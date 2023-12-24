use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    error::{BuilderError, ConnectionError},
    CosmosBuilder,
};

use super::{node::Node, node_chooser::NodeChooser};

#[derive(Clone)]
pub(super) struct Pool {
    pub(super) builder: Arc<CosmosBuilder>,
    pub(super) node_chooser: NodeChooser,
    /// Permits for enforcing global concurrent request count.
    semaphore: Arc<Semaphore>,
}

pub(super) struct NodeGuard {
    pub(super) inner: Node,
    _permit: OwnedSemaphorePermit,
}

impl NodeGuard {
    pub(crate) fn get_inner_mut(&mut self) -> &mut Node {
        &mut self.inner
    }
}

impl Pool {
    pub(super) fn new(builder: Arc<CosmosBuilder>) -> Result<Self, BuilderError> {
        let node_chooser = NodeChooser::new(&builder)?;
        let semaphore = Arc::new(Semaphore::new(builder.request_count()));
        Ok(Pool {
            builder,
            node_chooser,
            semaphore,
        })
    }

    pub(super) async fn get(&self) -> Result<NodeGuard, ConnectionError> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("Pool::get: semaphore has been closed");

        let node = self.node_chooser.choose_node();
        Ok(NodeGuard {
            inner: node.clone(),
            _permit: permit,
        })
    }

    pub(crate) async fn get_with_node(&self, node: &Node) -> Result<NodeGuard, ConnectionError> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("Pool::get_with_node: semaphore has been closed");

        Ok(NodeGuard {
            inner: node.clone(),
            _permit: permit,
        })
    }
}
