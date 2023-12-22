use std::{sync::Arc, time::Instant};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rand::seq::SliceRandom;

use crate::{
    error::{
        Action, ConnectionError, LastNodeError, NodeHealthReport, QueryErrorDetails,
        SingleNodeHealthReport,
    },
    CosmosBuilder,
};

#[derive(Clone)]
pub(super) struct NodeChooser {
    primary: Node,
    fallbacks: Arc<Vec<Node>>,
    /// How many errors in a row are allowed before we call a node unhealthy?
    allowed_error_count: usize,
}

impl NodeChooser {
    pub(super) fn new(builder: &CosmosBuilder) -> Self {
        NodeChooser {
            primary: Node {
                grpc_url: builder.grpc_url_arc().clone(),
                is_fallback: false,
                last_error: Arc::new(RwLock::new(None)),
            },
            fallbacks: builder
                .grpc_fallback_urls()
                .iter()
                .map(|fallback| Node {
                    grpc_url: fallback.clone(),
                    is_fallback: true,
                    last_error: Arc::new(RwLock::new(None)),
                })
                .collect::<Vec<_>>()
                .into(),
            allowed_error_count: builder.get_allowed_error_count(),
        }
    }

    pub(super) fn choose_node(&self) -> &Node {
        if self.primary.is_healthy(self.allowed_error_count) {
            &self.primary
        } else {
            let fallbacks = self
                .fallbacks
                .iter()
                .filter(|node| node.is_healthy(self.allowed_error_count))
                .collect::<Vec<_>>();
            let mut rng = rand::thread_rng();
            fallbacks
                .as_slice()
                .choose(&mut rng)
                .copied()
                .unwrap_or(&self.primary)
        }
    }

    pub(super) fn health_report(&self) -> NodeHealthReport {
        NodeHealthReport {
            nodes: std::iter::once(self.primary.health_report(self.allowed_error_count))
                .chain(
                    self.fallbacks
                        .iter()
                        .map(|node| node.health_report(self.allowed_error_count)),
                )
                .collect(),
        }
    }

    pub(super) fn all_nodes(&self) -> impl Iterator<Item = &Node> {
        std::iter::once(&self.primary).chain(self.fallbacks.iter())
    }
}

#[derive(Clone)]
pub(super) struct Node {
    pub(super) grpc_url: Arc<String>,
    pub(super) is_fallback: bool,
    last_error: Arc<RwLock<Option<LastError>>>,
}

#[derive(Debug)]
struct LastError {
    error: Arc<String>,
    instant: Instant,
    timestamp: DateTime<Utc>,
    action: Option<Action>,
    /// How many network errors in a row have occurred?
    ///
    /// Gets reset each time there's a successful query, or a query that fails with a non-network reason.
    error_count: usize,
}

const NODE_ERROR_TIMEOUT: u64 = 30;

pub(crate) enum QueryResult {
    Success,
    NetworkError {
        err: QueryErrorDetails,
        action: Action,
    },
    OtherError,
}

impl Node {
    pub(super) fn log_connection_error(&self, error: ConnectionError) {
        *self.last_error.write() = Some(LastError {
            error: error.to_string().into(),
            instant: Instant::now(),
            timestamp: Utc::now(),
            action: None,
            error_count: 1,
        });
    }

    pub(super) fn log_query_result(&self, res: QueryResult) {
        let mut guard = self.last_error.write();
        match res {
            QueryResult::Success | QueryResult::OtherError => {
                if let Some(error) = guard.as_mut() {
                    error.error_count = 0;
                }
            }
            QueryResult::NetworkError { err, action } => {
                let old_error_count = guard.as_ref().map_or(0, |x| x.error_count);
                *guard = Some(LastError {
                    error: err.to_string().into(),
                    instant: Instant::now(),
                    timestamp: Utc::now(),
                    action: Some(action),
                    error_count: old_error_count + 1,
                });
            }
        }
    }

    fn is_healthy(&self, allowed_error_count: usize) -> bool {
        match &*self.last_error.read() {
            None => true,
            Some(last_error) => {
                last_error.instant.elapsed().as_secs() > NODE_ERROR_TIMEOUT
                    || last_error.error_count <= allowed_error_count
            }
        }
    }

    fn health_report(&self, allowed_error_count: usize) -> SingleNodeHealthReport {
        let guard = self.last_error.read();
        let last_error = guard.as_ref();
        SingleNodeHealthReport {
            grpc_url: self.grpc_url.clone(),
            is_fallback: self.is_fallback,
            is_healthy: self.is_healthy(allowed_error_count),
            error_count: last_error.map_or(0, |last_error| last_error.error_count),
            last_error: last_error.map(|last_error| {
                let error = match &last_error.action {
                    Some(action) => Arc::new(format!(
                        "{} during action {}",
                        last_error.error.clone(),
                        action
                    )),
                    None => last_error.error.clone(),
                };
                LastNodeError {
                    timestamp: last_error.timestamp,
                    age: last_error.instant.elapsed(),
                    error,
                }
            }),
        }
    }
}
