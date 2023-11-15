use std::{sync::Arc, time::Instant};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rand::seq::SliceRandom;

use crate::{
    error::{
        ConnectionError, LastNodeError, NodeHealthReport, QueryErrorDetails, SingleNodeHealthReport,
    },
    CosmosBuilder,
};

#[derive(Clone)]
pub(super) struct NodeChooser {
    primary: Node,
    fallbacks: Arc<Vec<Node>>,
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
        }
    }

    pub(super) fn choose_node(&self) -> &Node {
        if self.primary.is_healthy() {
            &self.primary
        } else {
            let fallbacks = self
                .fallbacks
                .iter()
                .filter(|node| node.is_healthy())
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
            nodes: std::iter::once(self.primary.health_report())
                .chain(self.fallbacks.iter().map(|node| node.health_report()))
                .collect(),
        }
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
}

const NODE_ERROR_TIMEOUT: u64 = 30;

impl Node {
    pub(super) fn log_connection_error(&self, error: ConnectionError) {
        *self.last_error.write() = Some(LastError {
            error: error.to_string().into(),
            instant: Instant::now(),
            timestamp: Utc::now(),
        });
    }

    pub(super) fn log_query_error(&self, error: QueryErrorDetails) {
        *self.last_error.write() = Some(LastError {
            error: error.to_string().into(),
            instant: Instant::now(),
            timestamp: Utc::now(),
        });
    }

    fn is_healthy(&self) -> bool {
        match &*self.last_error.read() {
            None => true,
            Some(last_error) => last_error.instant.elapsed().as_secs() > NODE_ERROR_TIMEOUT,
        }
    }

    fn health_report(&self) -> SingleNodeHealthReport {
        SingleNodeHealthReport {
            grpc_url: self.grpc_url.clone(),
            is_fallback: self.is_fallback,
            is_healthy: self.is_healthy(),
            last_error: self
                .last_error
                .read()
                .as_ref()
                .map(|last_error| LastNodeError {
                    timestamp: last_error.timestamp,
                    age: last_error.instant.elapsed(),
                    error: last_error.error.clone(),
                }),
        }
    }
}
