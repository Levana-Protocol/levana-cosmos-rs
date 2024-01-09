use std::{
    ops::Deref,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use tonic::{
    codegen::InterceptedService,
    transport::{Channel, ClientTlsConfig, Endpoint, Uri},
};

use crate::{
    error::{Action, BuilderError, ConnectionError, LastNodeError, SingleNodeHealthReport},
    CosmosBuilder,
};

use super::{node_chooser::QueryResult, CosmosInterceptor};

/// Internal data structure containing gRPC clients.
#[derive(Clone)]
pub(crate) struct Node {
    node_inner: Arc<NodeInner>,
}

struct NodeInner {
    grpc_url: Arc<String>,
    is_fallback: bool,
    last_error: RwLock<Option<LastError>>,
    channel: InterceptedService<Channel, CosmosInterceptor>,
}

#[derive(Debug, Clone)]
struct LastError {
    error: Arc<String>,
    instant: Instant,
    timestamp: DateTime<Utc>,
    action: Option<Arc<Action>>,
    /// How many network errors in a row have occurred?
    ///
    /// Gets reset each time there's a successful query, or a query that fails with a non-network reason.
    error_count: usize,
}

impl CosmosBuilder {
    pub(crate) fn make_node(
        &self,
        grpc_url: &Arc<String>,
        is_fallback: bool,
    ) -> Result<Node, BuilderError> {
        let grpc_endpoint =
            grpc_url
                .parse::<Endpoint>()
                .map_err(|source| BuilderError::InvalidGrpcUrl {
                    grpc_url: grpc_url.clone(),
                    source: source.into(),
                })?;

        let uri =
            Uri::try_from(grpc_url.clone().deref()).map_err(|op| BuilderError::InvalidUri {
                gprc_url: grpc_url.clone(),
                source: op,
            })?;
        // https://github.com/hyperium/tonic/issues/1033#issuecomment-1537239811
        let grpc_endpoint = grpc_endpoint.origin(uri);

        let grpc_endpoint = if let Some(rate_limit) = self.rate_limit() {
            grpc_endpoint.rate_limit(rate_limit, Duration::from_secs(rate_limit))
        } else {
            grpc_endpoint
        };

        let grpc_endpoint = if grpc_url.starts_with("https://") {
            grpc_endpoint
                .tls_config(ClientTlsConfig::new())
                .map_err(|source| BuilderError::TlsConfig {
                    grpc_url: grpc_url.clone(),
                    source: source.into(),
                })?
        } else {
            grpc_endpoint
        };

        let grpc_channel = grpc_endpoint.connect_lazy();

        let referer_header = self.referer_header().map(|x| x.to_owned());

        let interceptor = CosmosInterceptor(referer_header.map(Arc::new));
        let channel = InterceptedService::new(grpc_channel, interceptor);

        Ok(Node {
            node_inner: Arc::new(NodeInner {
                is_fallback,
                channel,
                grpc_url: grpc_url.clone(),
                last_error: RwLock::new(None),
            }),
        })
    }
}

pub(crate) type CosmosChannel = InterceptedService<Channel, CosmosInterceptor>;

impl Node {
    pub(crate) fn grpc_url(&self) -> &Arc<String> {
        &self.node_inner.grpc_url
    }

    pub(crate) fn set_broken(&mut self, err: impl FnOnce(Arc<String>) -> ConnectionError) {
        let err = err(self.node_inner.grpc_url.clone());
        self.log_connection_error(err);
    }

    pub(super) fn log_connection_error(&self, error: ConnectionError) {
        let last_error = Some(LastError {
            error: error.to_string().into(),
            instant: Instant::now(),
            timestamp: Utc::now(),
            action: None,
            error_count: 1,
        });
        *self.node_inner.last_error.write() = last_error;
    }

    pub(super) fn log_query_result(&self, res: QueryResult) {
        match res {
            QueryResult::Success | QueryResult::OtherError => {
                if let Some(error) = self.node_inner.last_error.write().as_mut() {
                    error.error_count = 0;
                }
            }
            QueryResult::NetworkError { err, action } => {
                let error = err.to_string().into();
                let instant = Instant::now();
                let timestamp = Utc::now();

                let mut guard = self.node_inner.last_error.write();
                let old_error_count = guard.as_ref().map_or(0, |x| x.error_count);
                *guard = Some(LastError {
                    error,
                    instant,
                    timestamp,
                    action: Some(Arc::new(action)),
                    error_count: old_error_count + 1,
                });
            }
        }
    }

    pub(crate) fn is_healthy(&self, allowed_error_count: usize) -> bool {
        let (instant, error_count) = match &*self.node_inner.last_error.read() {
            None => return true,
            Some(last_error) => (last_error.instant, last_error.error_count),
        };
        self.is_healthy_inner(allowed_error_count, instant, error_count)
    }

    fn is_healthy_inner(
        &self,
        allowed_error_count: usize,
        instant: Instant,
        error_count: usize,
    ) -> bool {
        const NODE_ERROR_TIMEOUT: u64 = 30;
        instant.elapsed().as_secs() > NODE_ERROR_TIMEOUT || error_count <= allowed_error_count
    }

    pub(crate) fn health_report(&self, allowed_error_count: usize) -> SingleNodeHealthReport {
        let last_error = self.node_inner.last_error.read().clone();
        SingleNodeHealthReport {
            grpc_url: self.node_inner.grpc_url.clone(),
            is_fallback: self.node_inner.is_fallback,
            is_healthy: match &last_error {
                None => true,
                Some(last_error) => self.is_healthy_inner(
                    allowed_error_count,
                    last_error.instant,
                    last_error.error_count,
                ),
            },
            error_count: last_error
                .as_ref()
                .map_or(0, |last_error| last_error.error_count),
            last_error: last_error.map(|last_error| {
                let error = match &last_error.action {
                    Some(action) => {
                        Arc::new(format!("{} during action {}", last_error.error, action))
                    }
                    None => last_error.error,
                };
                LastNodeError {
                    timestamp: last_error.timestamp,
                    age: last_error.instant.elapsed(),
                    error,
                }
            }),
        }
    }

    pub(crate) fn auth_query_client(
        &self,
    ) -> cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient<CosmosChannel> {
        cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient::new(
            self.node_inner.channel.clone(),
        )
    }

    pub(crate) fn bank_query_client(
        &self,
    ) -> cosmos_sdk_proto::cosmos::bank::v1beta1::query_client::QueryClient<CosmosChannel> {
        cosmos_sdk_proto::cosmos::bank::v1beta1::query_client::QueryClient::new(
            self.node_inner.channel.clone(),
        )
    }

    pub(crate) fn wasm_query_client(
        &self,
    ) -> cosmos_sdk_proto::cosmwasm::wasm::v1::query_client::QueryClient<CosmosChannel> {
        cosmos_sdk_proto::cosmwasm::wasm::v1::query_client::QueryClient::new(
            self.node_inner.channel.clone(),
        )
    }

    pub(crate) fn tx_service_client(
        &self,
    ) -> cosmos_sdk_proto::cosmos::tx::v1beta1::service_client::ServiceClient<CosmosChannel> {
        cosmos_sdk_proto::cosmos::tx::v1beta1::service_client::ServiceClient::new(
            self.node_inner.channel.clone(),
        )
    }

    pub(crate) fn tendermint_client(
        &self,
    ) -> cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient<
        CosmosChannel,
    > {
        cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient::new(
            self.node_inner.channel.clone(),
        )
    }

    pub(crate) fn authz_query_client(
        &self,
    ) -> cosmos_sdk_proto::cosmos::authz::v1beta1::query_client::QueryClient<CosmosChannel> {
        cosmos_sdk_proto::cosmos::authz::v1beta1::query_client::QueryClient::new(
            self.node_inner.channel.clone(),
        )
    }

    pub(crate) fn epochs_query_client(
        &self,
    ) -> crate::osmosis::epochs::query_client::QueryClient<CosmosChannel> {
        crate::osmosis::epochs::query_client::QueryClient::new(self.node_inner.channel.clone())
    }
}
