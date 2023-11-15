use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{error::ConnectionError, CosmosBuilder};

use super::{node_chooser::NodeChooser, CosmosInner};

#[derive(Clone)]
pub(super) struct Pool {
    pub(super) builder: Arc<CosmosBuilder>,
    pub(super) node_chooser: NodeChooser,
    semaphore: Arc<Semaphore>,
    idle: Arc<Mutex<Vec<IdleConn>>>,
    idle_cleanup: IdleCleanup,
}

struct IdleConn {
    conn: CosmosInner,
    idle_start: Instant,
}

pub(super) struct CosmosInnerGuard {
    /// Only switches to None on drop
    pub(super) inner: Option<CosmosInner>,
    _permit: OwnedSemaphorePermit,
    idle: Arc<Mutex<Vec<IdleConn>>>,
    idle_cleanup: IdleCleanup,
}

impl CosmosInnerGuard {
    pub(crate) fn get_inner_mut(&mut self) -> &mut CosmosInner {
        self.inner
            .as_mut()
            .expect("CosmosInnerGuard::get_inner_mut: inner is None")
    }
}

impl CosmosInner {
    fn is_expired(&self) -> bool {
        self.expires
            .map_or(false, |expires| expires <= tokio::time::Instant::now())
    }
}

impl Drop for CosmosInnerGuard {
    fn drop(&mut self) {
        let inner = self
            .inner
            .take()
            .expect("CosmosInnerGuard::drop: inner is None");
        if !inner.is_expired() && !inner.is_broken {
            self.idle.lock().push(IdleConn {
                conn: inner,
                idle_start: Instant::now(),
            });
            self.idle_cleanup.trigger();
        }
    }
}

impl Pool {
    pub(super) async fn new(builder: Arc<CosmosBuilder>) -> Self {
        let node_chooser = NodeChooser::new(&builder);
        let semaphore = Arc::new(Semaphore::new(builder.connection_count()));
        let idle = Arc::new(Mutex::new(Vec::new()));
        let idle_cleanup = IdleCleanup::new(&builder, idle.clone()).await;
        Pool {
            builder,
            node_chooser,
            semaphore,
            idle,
            idle_cleanup,
        }
    }

    pub(super) async fn get(&self) -> Result<CosmosInnerGuard, ConnectionError> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("Pool::get: semaphore has been closed");
        while let Some(idle) = self.idle.lock().pop() {
            if !idle.conn.is_expired() {
                return Ok(CosmosInnerGuard {
                    inner: Some(idle.conn),
                    _permit: permit,
                    idle: self.idle.clone(),
                    idle_cleanup: self.idle_cleanup.clone(),
                });
            }
        }

        let inner = self.fresh().await?;
        Ok(CosmosInnerGuard {
            inner: Some(inner),
            _permit: permit,
            idle: self.idle.clone(),
            idle_cleanup: self.idle_cleanup.clone(),
        })
    }

    async fn fresh(&self) -> Result<CosmosInner, ConnectionError> {
        let node = self.node_chooser.choose_node();

        let build = self.builder.build_inner(node, &self.builder);
        let build = tokio::time::timeout(self.builder.connection_timeout(), build);

        match build.await {
            Ok(Ok(cosmos)) => Ok(cosmos),
            Ok(Err(e)) => {
                node.log_connection_error(e.clone());
                Err(e)
            }
            // Timeout case
            Err(_) => {
                let err = ConnectionError::TimeoutConnecting {
                    grpc_url: node.grpc_url.clone(),
                };
                node.log_connection_error(err.clone());
                Err(err)
            }
        }
    }
}

#[derive(Clone)]
struct IdleCleanup {
    send: tokio::sync::mpsc::Sender<()>,
}

impl IdleCleanup {
    fn trigger(&self) {
        match self.send.try_send(()) {
            Ok(()) => (),
            Err(e) => match e {
                // It's OK if we're full...
                tokio::sync::mpsc::error::TrySendError::Full(_) => (),
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    unreachable!("IdleCleanup::trigger: channel is closed")
                }
            },
        }
    }

    async fn new(builder: &CosmosBuilder, idle: Arc<Mutex<Vec<IdleConn>>>) -> Self {
        let idle_timeout = Duration::from_secs(builder.idle_timeout_seconds().into());
        let (send, recv) = tokio::sync::mpsc::channel(1);
        tokio::task::spawn(idle_reaper(idle_timeout, idle, recv));
        IdleCleanup { send }
    }
}

async fn idle_reaper(
    idle_timeout: Duration,
    idle: Arc<Mutex<Vec<IdleConn>>>,
    mut recv: tokio::sync::mpsc::Receiver<()>,
) {
    loop {
        let is_empty = {
            let mut guard = idle.lock();
            let old_idle = std::mem::take(&mut *guard);
            let now = Instant::now();
            for idle in old_idle {
                let expires = idle.idle_start + idle_timeout;
                if expires > now {
                    guard.push(idle);
                }
            }
            guard.is_empty()
        };

        if is_empty {
            // Nothing left to be reaped, so wait for a message on the channel.
            match recv.recv().await {
                // New idle connections available, sleep and then loop again
                Some(()) => (),
                // Channel has been closed, so we can exit
                None => break,
            }
        }

        // Sleep for the idle timeout period
        tokio::time::sleep(idle_timeout).await;
    }
}
