mod node_chooser;
mod pool;
mod query;

use std::{
    str::FromStr,
    sync::{Arc, Weak},
};

use chrono::{DateTime, TimeZone, Utc};
use cosmos_sdk_proto::{
    cosmos::{
        auth::v1beta1::{BaseAccount, QueryAccountRequest},
        bank::v1beta1::QueryAllBalancesRequest,
        base::{
            abci::v1beta1::TxResponse,
            query::v1beta1::PageRequest,
            tendermint::v1beta1::{GetBlockByHeightRequest, GetLatestBlockRequest},
            v1beta1::Coin,
        },
        tx::v1beta1::{
            AuthInfo, BroadcastMode, BroadcastTxRequest, Fee, GetTxRequest, GetTxResponse,
            GetTxsEventRequest, ModeInfo, OrderBy, SignDoc, SignerInfo, SimulateRequest,
            SimulateResponse, Tx, TxBody,
        },
    },
    cosmwasm::wasm::v1::QueryCodeRequest,
    traits::Message,
};
use parking_lot::Mutex;
use tokio::time::Instant;
use tonic::{
    codegen::InterceptedService,
    service::Interceptor,
    transport::{Channel, ClientTlsConfig, Endpoint},
    Status,
};

use crate::{
    address::HasAddressHrp,
    error::{
        Action, BuilderError, ConnectionError, CosmosSdkError, NodeHealthReport, QueryError,
        QueryErrorCategory, QueryErrorDetails,
    },
    osmosis::ChainPausedStatus,
    wallet::WalletPublicKey,
    Address, CosmosBuilder, HasAddress, TxBuilder,
};

use self::{node_chooser::Node, pool::Pool, query::GrpcRequest};

use super::Wallet;

/// A connection to a gRPC endpoint to communicate with a Cosmos chain.
///
/// Behind the scenes, this uses a [Pool] of connections. Cloning this value is
/// cheap and recommended, it will encourage connection sharing.
///
/// See [CosmosBuilder] and [crate::CosmosNetwork] for common methods of
/// building a [Cosmos].
#[derive(Clone)]
pub struct Cosmos {
    pool: Pool,
    height: Option<u64>,
    block_height_tracking: Arc<Mutex<BlockHeightTracking>>,
    pub(crate) chain_paused_status: ChainPausedStatus,
}

pub(crate) struct WeakCosmos {
    pool: Pool,
    height: Option<u64>,
    block_height_tracking: Weak<Mutex<BlockHeightTracking>>,
    chain_paused_status: ChainPausedStatus,
}

impl From<&Cosmos> for WeakCosmos {
    fn from(
        Cosmos {
            pool,
            height,
            block_height_tracking,
            chain_paused_status,
        }: &Cosmos,
    ) -> Self {
        WeakCosmos {
            pool: pool.clone(),
            height: *height,
            block_height_tracking: Arc::downgrade(block_height_tracking),
            chain_paused_status: chain_paused_status.clone(),
        }
    }
}

impl WeakCosmos {
    pub(crate) fn upgrade(&self) -> Option<Cosmos> {
        let WeakCosmos {
            pool,
            height,
            block_height_tracking,
            chain_paused_status,
        } = self;
        block_height_tracking
            .upgrade()
            .map(|block_height_tracking| Cosmos {
                pool: pool.clone(),
                height: *height,
                block_height_tracking,
                chain_paused_status: chain_paused_status.clone(),
            })
    }
}

struct BlockHeightTracking {
    /// Local time when this block height was observed
    when: Instant,
    /// Height that was seen
    height: i64,
}

impl std::fmt::Debug for Cosmos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cosmos")
            .field("builder", &self.pool.builder)
            .field("height", &self.height)
            .finish()
    }
}

impl Cosmos {
    pub(crate) async fn perform_query<Request: GrpcRequest>(
        &self,
        req: Request,
        action: Action,
        should_retry: bool,
    ) -> Result<tonic::Response<Request::Response>, QueryError> {
        let mut attempt = 0;
        loop {
            let (err, can_retry, grpc_url) = match self.pool.get().await {
                Err(err) => (
                    QueryErrorDetails::ConnectionError(err),
                    true,
                    self.get_cosmos_builder().grpc_url_arc().clone(),
                ),
                Ok(mut guard) => {
                    let cosmos_inner = guard.get_inner_mut();
                    match self.perform_query_inner(req.clone(), cosmos_inner).await {
                        Ok(x) => break Ok(x),
                        Err((err, can_retry)) => {
                            if can_retry {
                                cosmos_inner.node.log_query_error(err.clone());
                            }
                            (err, can_retry, cosmos_inner.node.grpc_url.clone())
                        }
                    }
                }
            };
            if attempt >= self.pool.builder.query_retries() || !should_retry || !can_retry {
                break Err(QueryError {
                    action,
                    builder: self.pool.builder.clone(),
                    height: self.height,
                    query: err,
                    grpc_url,
                    node_health: self.pool.node_chooser.health_report(),
                });
            } else {
                attempt += 1;
                tracing::debug!(
                    "Error performing a query, retrying. Attempt {attempt} of {}. {err:?}",
                    self.pool.builder.query_retries()
                );
            }
        }
    }

    /// Error return: the details itself, and whether a retry can be attempted.
    async fn perform_query_inner<Request: GrpcRequest>(
        &self,
        req: Request,
        cosmos_inner: &mut CosmosInner,
    ) -> Result<tonic::Response<Request::Response>, (QueryErrorDetails, bool)> {
        let duration =
            tokio::time::Duration::from_secs(self.pool.builder.query_timeout_seconds().into());
        let mut req = tonic::Request::new(req.clone());
        if let Some(height) = self.height {
            // https://docs.cosmos.network/v0.47/run-node/interact-node#query-for-historical-state-using-rest
            let metadata = req.metadata_mut();
            metadata.insert("x-cosmos-block-height", height.into());
        }
        let res = tokio::time::timeout(duration, GrpcRequest::perform(req, cosmos_inner)).await;
        match res {
            Ok(Ok(res)) => {
                self.check_block_height(
                    res.metadata().get("x-cosmos-block-height"),
                    &cosmos_inner.node.grpc_url,
                )?;
                Ok(res)
            }
            Ok(Err(status)) => {
                let err = QueryErrorDetails::from_tonic_status(status);
                let can_retry = match err.error_category() {
                    QueryErrorCategory::NetworkIssue => {
                        cosmos_inner
                            .set_broken(|grpc_url| ConnectionError::QueryFailed { grpc_url });
                        true
                    }
                    QueryErrorCategory::ConnectionIsFine => false,
                    QueryErrorCategory::Unsure => {
                        // Not enough info from the error to determine what went
                        // wrong. Send a basic request that should always
                        // succeed to determine if it's a network issue or not.
                        match GrpcRequest::perform(
                            tonic::Request::new(GetLatestBlockRequest {}),
                            cosmos_inner,
                        )
                        .await
                        {
                            Ok(_) => {
                                // OK, connection looks fine, don't bother retrying
                                false
                            }
                            Err(status) => {
                                // Something went wrong. Don't even bother
                                // looking at _what_ went wrong, just kill this
                                // connection and retry.
                                cosmos_inner.set_broken(|grpc_url| {
                                    ConnectionError::SanityCheckFailed {
                                        grpc_url,
                                        source: status,
                                    }
                                });
                                true
                            }
                        }
                    }
                };

                Err((err, can_retry))
            }
            Err(_) => {
                cosmos_inner.set_broken(|grpc_url| ConnectionError::TimeoutQuery { grpc_url });
                Err((QueryErrorDetails::QueryTimeout, true))
            }
        }
    }

    /// Get the [CosmosBuilder] used to construct this connection.
    pub fn get_cosmos_builder(&self) -> &Arc<CosmosBuilder> {
        &self.pool.builder
    }

    fn check_block_height(
        &self,
        new_height: Option<&tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
        grpc_url: &Arc<String>,
    ) -> Result<(), (QueryErrorDetails, bool)> {
        if self.height.is_some() {
            // Don't do a height check, we're specifically querying historical data.
            return Ok(());
        }
        // If the chain is paused, don't do a block height check either
        if self.chain_paused_status.is_paused() {
            return Ok(());
        }

        let new_height = match new_height {
            Some(header_value) => header_value,
            None => {
                tracing::warn!(
                    "No x-cosmos-block-height response header found on request to {grpc_url}"
                );
                return Ok(());
            }
        };
        let new_height = match new_height.to_str() {
            Ok(new_height) => new_height,
            Err(err) => {
                tracing::warn!("x-cosmos-block-height response header from {grpc_url} does not contain textual data: {err}");
                return Ok(());
            }
        };
        let new_height: i64 = match new_height.parse() {
            Ok(new_height) => new_height,
            Err(err) => {
                tracing::warn!("x-cosmos-block-height response header from {grpc_url} is {new_height}, could not parse as i64: {err}");
                return Ok(());
            }
        };
        let now = Instant::now();

        let mut guard = self.block_height_tracking.lock();

        let BlockHeightTracking {
            when: prev,
            height: old_height,
        } = *guard;

        // We're moving forward so update the tracking and move on.
        if new_height > old_height {
            *guard = BlockHeightTracking {
                when: now,
                height: new_height,
            };
            return Ok(());
        }

        // Check if we're too many blocks lagging.
        if old_height - new_height > self.get_cosmos_builder().block_lag_allowed().into() {
            return Err((
                QueryErrorDetails::BlocksLagDetected {
                    old_height,
                    new_height,
                    block_lag_allowed: self.get_cosmos_builder().block_lag_allowed(),
                },
                true,
            ));
        }

        // And now see if it's been too long since we've seen any new blocks.
        let age = match now.checked_duration_since(prev) {
            Some(age) => age,
            None => {
                tracing::warn!("Error subtracting two Instants: {now:?} - {prev:?}");
                return Ok(());
            }
        };

        if age > self.get_cosmos_builder().latest_block_age_allowed() {
            return Err((
                QueryErrorDetails::NoNewBlockFound {
                    age,
                    age_allowed: self.get_cosmos_builder().latest_block_age_allowed(),
                    old_height,
                    new_height,
                },
                true,
            ));
        }

        Ok(())
    }
}

impl CosmosInner {
    fn set_broken(&mut self, err: impl FnOnce(Arc<String>) -> ConnectionError) {
        let err = err(self.node.grpc_url.clone());
        self.is_broken = true;
        self.node.log_connection_error(err);
    }
}

pub struct CosmosInterceptor(Option<String>);

impl Interceptor for CosmosInterceptor {
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        let req = request.metadata_mut();
        if let Some(value) = &self.0 {
            let value = FromStr::from_str(value);
            if let Ok(header_value) = value {
                req.insert("referer", header_value);
            }
        }
        Ok(request)
    }
}

/// Internal data structure containing gRPC clients.
pub struct CosmosInner {
    auth_query_client: cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient<
        InterceptedService<Channel, CosmosInterceptor>,
    >,
    bank_query_client: cosmos_sdk_proto::cosmos::bank::v1beta1::query_client::QueryClient<
        InterceptedService<Channel, CosmosInterceptor>,
    >,
    tx_service_client: cosmos_sdk_proto::cosmos::tx::v1beta1::service_client::ServiceClient<
        InterceptedService<Channel, CosmosInterceptor>,
    >,
    wasm_query_client: cosmos_sdk_proto::cosmwasm::wasm::v1::query_client::QueryClient<
        InterceptedService<Channel, CosmosInterceptor>,
    >,
    tendermint_client:
        cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient<
            InterceptedService<Channel, CosmosInterceptor>,
        >,
    authz_query_client: cosmos_sdk_proto::cosmos::authz::v1beta1::query_client::QueryClient<
        InterceptedService<Channel, CosmosInterceptor>,
    >,
    epochs_query_client: crate::osmosis::epochs::query_client::QueryClient<
        InterceptedService<Channel, CosmosInterceptor>,
    >,
    is_broken: bool,
    node: Node,
    expires: Option<Instant>,
}

impl CosmosBuilder {
    /// Create a new [Cosmos] and perform a sanity check to make sure the connection works.
    pub async fn build(self) -> Result<Cosmos, BuilderError> {
        let cosmos = self.build_lazy().await;

        let resp = cosmos
            .perform_query(GetLatestBlockRequest {}, Action::SanityCheck, false)
            .await
            .map_err(|source| BuilderError::SanityQueryFailed { source })?;

        let actual = resp
            .into_inner()
            .block
            .and_then(|block| block.header)
            .map(|header| header.chain_id);

        let expected = cosmos.get_cosmos_builder().chain_id();
        if actual.as_deref() == Some(expected) {
            Ok(cosmos)
        } else {
            Err(BuilderError::MismatchedChainIds {
                grpc_url: cosmos.get_cosmos_builder().grpc_url().to_owned(),
                expected: expected.to_owned(),
                actual,
            })
        }
    }

    /// Create a new [Cosmos] but do not perform any sanity checks.
    pub async fn build_lazy(self) -> Cosmos {
        let builder = Arc::new(self);
        let chain_paused_status = builder.chain_paused_method.into();
        let cosmos = Cosmos {
            pool: Pool::new(builder).await,
            height: None,
            block_height_tracking: Arc::new(Mutex::new(BlockHeightTracking {
                when: Instant::now(),
                height: 0,
            })),
            chain_paused_status,
        };
        cosmos.launch_chain_paused_tracker();
        cosmos
    }
}

impl CosmosBuilder {
    async fn build_inner(
        &self,
        node: &Node,
        builder: &CosmosBuilder,
    ) -> Result<CosmosInner, ConnectionError> {
        let grpc_url = &node.grpc_url;
        let grpc_endpoint =
            grpc_url
                .parse::<Endpoint>()
                .map_err(|source| ConnectionError::InvalidGrpcUrl {
                    grpc_url: grpc_url.clone(),
                    source: source.into(),
                })?;
        let grpc_endpoint = if grpc_url.starts_with("https://") {
            grpc_endpoint
                .tls_config(ClientTlsConfig::new())
                .map_err(|source| ConnectionError::TlsConfig {
                    grpc_url: grpc_url.clone(),
                    source: source.into(),
                })?
        } else {
            grpc_endpoint
        };
        let grpc_channel =
            tokio::time::timeout(tokio::time::Duration::from_secs(5), grpc_endpoint.connect())
                .await
                .map_err(|_| ConnectionError::TimeoutConnecting {
                    grpc_url: grpc_url.clone(),
                })?
                .map_err(|source| ConnectionError::CannotEstablishConnection {
                    grpc_url: grpc_url.clone(),
                    source: source.into(),
                })?;

        let referer_header = self.referer_header().map(|x| x.to_owned());

        let expires = if node.is_fallback {
            Some(Instant::now() + builder.fallback_timeout())
        } else {
            None
        };

        Ok(CosmosInner {
            auth_query_client:
                cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient::with_interceptor(
                    grpc_channel.clone(), CosmosInterceptor(referer_header.clone())
            ),
            bank_query_client:
                cosmos_sdk_proto::cosmos::bank::v1beta1::query_client::QueryClient::with_interceptor(
                    grpc_channel.clone(),CosmosInterceptor(referer_header.clone())
            ),
            tx_service_client:
                cosmos_sdk_proto::cosmos::tx::v1beta1::service_client::ServiceClient::with_interceptor(
                    grpc_channel.clone(),CosmosInterceptor(referer_header.clone())
            ),
            wasm_query_client: cosmos_sdk_proto::cosmwasm::wasm::v1::query_client::QueryClient::with_interceptor(grpc_channel.clone(), CosmosInterceptor(referer_header.clone())),
            tendermint_client: cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient::with_interceptor(grpc_channel.clone(), CosmosInterceptor(referer_header.clone())),
            authz_query_client: cosmos_sdk_proto::cosmos::authz::v1beta1::query_client::QueryClient::with_interceptor(grpc_channel.clone(), CosmosInterceptor(referer_header.clone())),
            epochs_query_client: crate::osmosis::epochs::query_client::QueryClient::with_interceptor(grpc_channel, CosmosInterceptor(referer_header)),
            is_broken: false,
            node: node.clone(),
            expires
        })
    }
}

impl Cosmos {
    /// Return a modified version of this [Cosmos] that queries at the given height.
    pub fn at_height(mut self, height: Option<u64>) -> Self {
        self.height = height;
        self
    }

    /// Get the base account information for the given address.
    pub async fn get_base_account(&self, address: Address) -> Result<BaseAccount, crate::Error> {
        let action = Action::GetBaseAccount(address);
        let res = self
            .perform_query(
                QueryAccountRequest {
                    address: address.get_address_string(),
                },
                action.clone(),
                true,
            )
            .await?
            .into_inner();

        let base_account = if self.get_address_hrp().as_str() == "inj" {
            let eth_account: crate::injective::EthAccount = prost::Message::decode(
                res.account
                    .ok_or_else(|| crate::Error::InvalidChainResponse {
                        message: "no eth account found".to_owned(),
                        action: action.clone(),
                    })?
                    .value
                    .as_ref(),
            )
            .map_err(|source| crate::Error::InvalidChainResponse {
                message: format!("Unable to parse eth_account: {source}"),
                action: action.clone(),
            })?;
            eth_account
                .base_account
                .ok_or_else(|| crate::Error::InvalidChainResponse {
                    message: "no base account found".to_owned(),
                    action: action.clone(),
                })?
        } else {
            prost::Message::decode(
                res.account
                    .ok_or_else(|| crate::Error::InvalidChainResponse {
                        message: "no account found".to_owned(),
                        action: action.clone(),
                    })?
                    .value
                    .as_ref(),
            )
            .map_err(|source| crate::Error::InvalidChainResponse {
                message: format!("Unable to parse account: {source}"),
                action,
            })?
        };
        Ok(base_account)
    }

    /// Get the coin balances for the given address.
    pub async fn all_balances(&self, address: Address) -> Result<Vec<Coin>, crate::Error> {
        let mut coins = Vec::new();
        let mut pagination = None;
        loop {
            let mut res = self
                .perform_query(
                    QueryAllBalancesRequest {
                        address: address.get_address_string(),
                        pagination: pagination.take(),
                    },
                    Action::QueryAllBalances(address),
                    true,
                )
                .await?
                .into_inner();
            coins.append(&mut res.balances);
            match res.pagination {
                Some(x) if !x.next_key.is_empty() => {
                    pagination = Some(PageRequest {
                        key: x.next_key,
                        offset: 0,
                        limit: 0,
                        count_total: false,
                        reverse: false,
                    })
                }
                _ => break Ok(coins),
            }
        }
    }

    pub(crate) async fn code_info(&self, code_id: u64) -> Result<Vec<u8>, crate::Error> {
        let res = self
            .perform_query(
                QueryCodeRequest { code_id },
                Action::CodeInfo(code_id),
                true,
            )
            .await?;
        Ok(res.into_inner().data)
    }

    fn txres_to_pair(
        txres: GetTxResponse,
        action: Action,
    ) -> Result<(TxBody, TxResponse), crate::Error> {
        let txbody = txres
            .tx
            .ok_or_else(|| crate::Error::InvalidChainResponse {
                message: "Missing tx field".to_owned(),
                action: action.clone(),
            })?
            .body
            .ok_or_else(|| crate::Error::InvalidChainResponse {
                message: "Missing tx.body field".to_owned(),
                action: action.clone(),
            })?;
        let txres = txres
            .tx_response
            .ok_or_else(|| crate::Error::InvalidChainResponse {
                message: "Missing tx_response field".to_owned(),
                action: action.clone(),
            })?;
        Ok((txbody, txres))
    }

    /// Get a transaction, failing immediately if not present
    ///
    /// This will follow normal fallback rules for other queries. You may want
    /// to try out [Self::get_transaction_with_fallbacks].
    pub async fn get_transaction_body(
        &self,
        txhash: impl Into<String>,
    ) -> Result<(TxBody, TxResponse), crate::Error> {
        let txhash = txhash.into();
        let action = Action::GetTransactionBody(txhash.clone());
        let txres = self
            .perform_query(
                GetTxRequest {
                    hash: txhash.clone(),
                },
                action.clone(),
                true,
            )
            .await?
            .into_inner();
        Self::txres_to_pair(txres, action)
    }

    /// Get a transaction with more aggressive fallback usage.
    ///
    /// This is intended to help indexers. A common failure mode in Cosmos is a
    /// single missing transaction on some nodes. This method will first try to
    /// get the transaction following normal fallback rules, and if that fails,
    /// will iterate through all fallbacks.
    pub async fn get_transaction_with_fallbacks(
        &self,
        txhash: impl Into<String>,
    ) -> Result<(TxBody, TxResponse), crate::Error> {
        let txhash = txhash.into();
        let action = Action::GetTransactionBody(txhash.clone());
        let res = self
            .perform_query(
                GetTxRequest {
                    hash: txhash.clone(),
                },
                action.clone(),
                true,
            )
            .await;
        match res {
            Ok(txres) => Self::txres_to_pair(txres.into_inner(), action),
            Err(e) => {
                if let QueryErrorDetails::NotFound(_) = &e.query {
                    for node in self.pool.node_chooser.all_nodes() {
                        let mut cosmos_inner = match self
                            .pool
                            .builder
                            .build_inner(node, &self.pool.builder)
                            .await
                        {
                            Ok(cosmos_inner) => cosmos_inner,
                            Err(_) => continue,
                        };
                        if let Ok(txres) = self
                            .perform_query_inner(
                                GetTxRequest {
                                    hash: txhash.clone(),
                                },
                                &mut cosmos_inner,
                            )
                            .await
                        {
                            return Self::txres_to_pair(txres.into_inner(), action);
                        }
                    }
                }
                Err(e.into())
            }
        }
    }

    /// Wait for a transaction to land on-chain using a busy loop.
    ///
    /// This is most useful after broadcasting a transaction to wait for it to land.
    pub async fn wait_for_transaction(
        &self,
        txhash: impl Into<String>,
    ) -> Result<(TxBody, TxResponse), crate::Error> {
        self.wait_for_transaction_with_action(txhash, None).await
    }

    async fn wait_for_transaction_with_action(
        &self,
        txhash: impl Into<String>,
        action: Option<Action>,
    ) -> Result<(TxBody, TxResponse), crate::Error> {
        const DELAY_SECONDS: u64 = 2;
        let txhash = txhash.into();
        for attempt in 1..=self.pool.builder.transaction_attempts() {
            let txres = self
                .perform_query(
                    GetTxRequest {
                        hash: txhash.clone(),
                    },
                    action
                        .clone()
                        .unwrap_or_else(|| Action::WaitForTransaction(txhash.clone())),
                    false,
                )
                .await;
            match txres {
                Ok(txres) => {
                    let txres = txres.into_inner();
                    return Self::txres_to_pair(
                        txres,
                        action
                            .clone()
                            .unwrap_or_else(|| Action::WaitForTransaction(txhash.clone())),
                    );
                }
                Err(QueryError {
                    query: QueryErrorDetails::NotFound(_),
                    ..
                }) => {
                    tracing::debug!(
                        "Transaction {txhash} not ready, attempt #{attempt}/{}",
                        self.pool.builder.transaction_attempts()
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(DELAY_SECONDS)).await;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
        Err(match action {
            None => crate::Error::WaitForTransactionTimedOut { txhash },
            Some(action) => crate::Error::WaitForTransactionTimedOutWhile { txhash, action },
        })
    }

    /// Get a list of txhashes for transactions send by the given address.
    pub async fn list_transactions_for(
        &self,
        address: Address,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> Result<Vec<String>, QueryError> {
        self.perform_query(
            GetTxsEventRequest {
                events: vec![format!("message.sender='{address}'")],
                pagination: Some(PageRequest {
                    key: vec![],
                    offset: offset.unwrap_or_default(),
                    limit: limit.unwrap_or(10),
                    count_total: false,
                    reverse: false,
                }),
                order_by: OrderBy::Asc as i32,
            },
            Action::ListTransactionsFor(address),
            true,
        )
        .await
        .map(|x| {
            x.into_inner()
                .tx_responses
                .into_iter()
                .map(|x| x.txhash)
                .collect()
        })
    }

    /// attempt_number starts at 0
    fn gas_to_coins(&self, gas: u64, attempt_number: u64) -> u64 {
        let (low, high) = self.pool.builder.gas_price();
        let attempts = self.pool.builder.gas_price_retry_attempts();

        let gas_price = if attempt_number >= attempts {
            high
        } else {
            assert!(attempts > 0);
            let step = (high - low) / attempts as f64;
            low + step * attempt_number as f64
        };

        (gas as f64 * gas_price) as u64
    }

    /// Get information on the given block height.
    pub async fn get_block_info(&self, height: i64) -> Result<BlockInfo, crate::Error> {
        let action = Action::GetBlock(height);
        let res = self
            .perform_query(GetBlockByHeightRequest { height }, action.clone(), true)
            .await?
            .into_inner();
        BlockInfo::new(action, res.block_id, res.block, Some(height))
    }

    /// Get information on the earliest block available from this node
    pub async fn get_earliest_block_info(&self) -> Result<BlockInfo, crate::Error> {
        match self.get_block_info(1).await {
            Err(crate::Error::Query(QueryError {
                query:
                    QueryErrorDetails::HeightNotAvailable {
                        lowest_height: Some(lowest_height),
                        ..
                    },
                ..
            })) => self.get_block_info(lowest_height).await,
            x => x,
        }
    }

    /// Get the latest block available
    pub async fn get_latest_block_info(&self) -> Result<BlockInfo, crate::Error> {
        let action = Action::GetLatestBlock;
        let res = self
            .perform_query(GetLatestBlockRequest {}, action.clone(), true)
            .await?
            .into_inner();
        BlockInfo::new(action, res.block_id, res.block, None)
    }

    /// Get the most recently seen block height.
    ///
    /// If no queries have been made, this will return 0.
    pub fn get_last_seen_block(&self) -> i64 {
        self.block_height_tracking.lock().height
    }

    /// Do we think that the chain is currently paused?
    ///
    /// At the moment, this only occurs on Osmosis Mainnet during the epoch.
    pub fn is_chain_paused(&self) -> bool {
        self.chain_paused_status.is_paused()
    }

    /// Get a node health report
    pub fn node_health_report(&self) -> NodeHealthReport {
        self.pool.node_chooser.health_report()
    }
}

/// Information on a block.
#[derive(Debug)]
pub struct BlockInfo {
    /// Block height
    pub height: i64,
    /// Hash of the block
    pub block_hash: String,
    /// Timestamp of the block
    pub timestamp: DateTime<Utc>,
    /// Transaction hashes contained in this block
    pub txhashes: Vec<String>,
    /// Chain ID this block is associated with
    pub chain_id: String,
}

impl BlockInfo {
    fn new(
        action: Action,
        block_id: Option<cosmos_sdk_proto::tendermint::types::BlockId>,
        block: Option<cosmos_sdk_proto::tendermint::types::Block>,
        height: Option<i64>,
    ) -> Result<BlockInfo, crate::Error> {
        (|| {
            let block_id = block_id.ok_or("get_block_info: block_id is None".to_owned())?;
            let block = block.ok_or("get_block_info: block is None".to_owned())?;
            let header = block
                .header
                .ok_or("get_block_info: header is None".to_owned())?;
            let time = header
                .time
                .ok_or("get_block_info: time is None".to_owned())?;
            let data = block
                .data
                .ok_or("get_block_info: data is None".to_owned())?;
            if let Some(height) = height {
                if height != header.height {
                    return Err(format!(
                        "Mismatched height from blockchain. Got {}, expected {height}",
                        header.height
                    ));
                }
            }
            let mut txhashes = vec![];
            for tx in data.txs {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(tx);
                let digest = hasher.finalize();
                txhashes.push(hex::encode_upper(digest));
            }
            Ok(BlockInfo {
                height: header.height,
                block_hash: hex::encode_upper(block_id.hash),
                timestamp: Utc
                    .timestamp_nanos(time.seconds * 1_000_000_000 + i64::from(time.nanos)),
                txhashes,
                chain_id: header.chain_id,
            })
        })()
        .map_err(|message| crate::Error::InvalidChainResponse { message, action })
    }
}

impl TxBuilder {
    /// Simulate the transaction with the given signer or signers.
    ///
    /// Note that for simulation purposes you do not need to provide valid
    /// signatures, so only the signer addresses are needed.
    pub async fn simulate(
        &self,
        cosmos: &Cosmos,
        wallets: &[Address],
    ) -> Result<FullSimulateResponse, crate::Error> {
        let mut sequences = vec![];
        for wallet in wallets {
            sequences.push(match cosmos.get_base_account(wallet.get_address()).await {
                Ok(account) => account.sequence,
                Err(err) => {
                    if err.to_string().contains("not found") {
                        tracing::warn!(
                            "Simulating with a non-existent wallet. Setting sequence number to 0"
                        );
                        0
                    } else {
                        return Err(err);
                    }
                }
            });
        }

        self.simulate_inner(cosmos, &sequences).await
    }

    /// Sign transaction, broadcast, wait for it to complete, confirm that it was successful
    /// the gas amount is determined automatically by running a simulation first and padding by a multiplier
    /// the multiplier can by adjusted by calling [CosmosBuilder::set_gas_estimate_multiplier]
    pub async fn sign_and_broadcast(
        &self,
        cosmos: &Cosmos,
        wallet: &Wallet,
    ) -> Result<TxResponse, crate::Error> {
        let simres = self.simulate(cosmos, &[wallet.get_address()]).await?;
        self.inner_sign_and_broadcast(
            cosmos,
            wallet,
            simres.body,
            // Gas estimation is not perfect, so we need to adjust it by a multiplier to account for drift
            // Since we're already estimating and padding, the loss of precision from f64 to u64 is negligible
            (simres.gas_used as f64 * cosmos.pool.builder.gas_estimate_multiplier()) as u64,
        )
        .await
    }

    /// Sign transaction, broadcast, wait for it to complete, confirm that it was successful
    /// unlike sign_and_broadcast(), the gas amount is explicit here and therefore no simulation is run
    pub async fn sign_and_broadcast_with_gas(
        &self,
        cosmos: &Cosmos,
        wallet: &Wallet,
        gas_to_request: u64,
    ) -> Result<TxResponse, crate::Error> {
        self.inner_sign_and_broadcast(cosmos, wallet, self.make_tx_body(), gas_to_request)
            .await
    }

    async fn inner_sign_and_broadcast(
        &self,
        cosmos: &Cosmos,
        wallet: &Wallet,
        body: TxBody,
        gas_to_request: u64,
    ) -> Result<TxResponse, crate::Error> {
        let base_account = cosmos.get_base_account(wallet.get_address()).await?;

        self.sign_and_broadcast_with(
            cosmos,
            wallet,
            &base_account,
            base_account.sequence,
            body.clone(),
            gas_to_request,
        )
        .await
    }

    fn make_signer_info(&self, sequence: u64, wallet: Option<&Wallet>) -> SignerInfo {
        SignerInfo {
            public_key: match wallet {
                // No wallet/base account. We're simulating. Fill in a dummy value.
                None => Some(cosmos_sdk_proto::Any {
                    type_url: "/cosmos.crypto.secp256k1.PubKey".to_owned(),
                    value: cosmos_sdk_proto::tendermint::crypto::PublicKey {
                        sum: Some(
                            cosmos_sdk_proto::tendermint::crypto::public_key::Sum::Ed25519(vec![]),
                        ),
                    }
                    .encode_to_vec(),
                }),
                Some(wallet) => {
                    match wallet.public_key {
                        // Use the Cosmos method of public key
                        WalletPublicKey::Cosmos(public_key) => Some(cosmos_sdk_proto::Any {
                            type_url: "/cosmos.crypto.secp256k1.PubKey".to_owned(),
                            value: cosmos_sdk_proto::tendermint::crypto::PublicKey {
                                sum: Some(
                                    cosmos_sdk_proto::tendermint::crypto::public_key::Sum::Ed25519(
                                        public_key.to_vec(),
                                    ),
                                ),
                            }
                            .encode_to_vec(),
                        }),
                        // Use the Injective method of public key
                        WalletPublicKey::Ethereum(public_key) => Some(cosmos_sdk_proto::Any {
                            type_url: "/injective.crypto.v1beta1.ethsecp256k1.PubKey".to_owned(),
                            value: cosmos_sdk_proto::tendermint::crypto::PublicKey {
                                sum: Some(
                                    cosmos_sdk_proto::tendermint::crypto::public_key::Sum::Ed25519(
                                        public_key.to_vec(),
                                    ),
                                ),
                            }
                            .encode_to_vec(),
                        }),
                    }
                }
            },
            mode_info: Some(ModeInfo {
                sum: Some(
                    cosmos_sdk_proto::cosmos::tx::v1beta1::mode_info::Sum::Single(
                        cosmos_sdk_proto::cosmos::tx::v1beta1::mode_info::Single { mode: 1 },
                    ),
                ),
            }),
            sequence,
        }
    }

    /// Make a [TxBody] for this builder
    fn make_tx_body(&self) -> TxBody {
        TxBody {
            messages: self.messages.iter().map(|msg| msg.get_protobuf()).collect(),
            memo: self.memo.as_deref().unwrap_or_default().to_owned(),
            timeout_height: 0,
            extension_options: vec![],
            non_critical_extension_options: vec![],
        }
    }

    /// Simulate to calculate the gas costs
    async fn simulate_inner(
        &self,
        cosmos: &Cosmos,
        sequences: &[u64],
    ) -> Result<FullSimulateResponse, crate::Error> {
        let body = self.make_tx_body();

        // First simulate the request with no signature and fake gas
        let simulate_tx = Tx {
            auth_info: Some(AuthInfo {
                fee: Some(Fee {
                    amount: vec![],
                    gas_limit: 0,
                    payer: "".to_owned(),
                    granter: "".to_owned(),
                }),
                signer_infos: sequences
                    .iter()
                    .map(|sequence| self.make_signer_info(*sequence, None))
                    .collect(),
            }),
            signatures: sequences.iter().map(|_| vec![]).collect(),
            body: Some(body.clone()),
        };

        #[allow(deprecated)]
        let simulate_req = SimulateRequest {
            tx: None,
            tx_bytes: simulate_tx.encode_to_vec(),
        };

        let action = Action::Simulate(self.clone());
        let simres = cosmos
            .perform_query(simulate_req, action.clone(), true)
            .await?
            .into_inner();

        let gas_used = simres
            .gas_info
            .as_ref()
            .ok_or_else(|| crate::Error::InvalidChainResponse {
                message: "Missing gas_info in SimulateResponse".to_owned(),
                action,
            })?
            .gas_used;

        Ok(FullSimulateResponse {
            body,
            simres,
            gas_used,
        })
    }

    async fn sign_and_broadcast_with(
        &self,
        cosmos: &Cosmos,
        wallet: &Wallet,
        base_account: &BaseAccount,
        sequence: u64,
        body: TxBody,
        gas_to_request: u64,
    ) -> Result<TxResponse, crate::Error> {
        // enum AttemptError {
        //     Inner(Infallible),
        //     InsufficientGas(Infallible),
        // }
        // impl From<anyhow::Error> for AttemptError {
        //     fn from(e: anyhow::Error) -> Self {
        //         AttemptError::Inner(e)
        //     }
        // }
        let body_ref = &body;
        let retry_with_price = |amount| async move {
            let auth_info = AuthInfo {
                signer_infos: vec![self.make_signer_info(sequence, Some(wallet))],
                fee: Some(Fee {
                    amount: vec![Coin {
                        denom: cosmos.pool.builder.gas_coin().to_owned(),
                        amount,
                    }],
                    gas_limit: gas_to_request,
                    payer: "".to_owned(),
                    granter: "".to_owned(),
                }),
            };

            let sign_doc = SignDoc {
                body_bytes: body_ref.encode_to_vec(),
                auth_info_bytes: auth_info.encode_to_vec(),
                chain_id: cosmos.pool.builder.chain_id().to_owned(),
                account_number: base_account.account_number,
            };
            let sign_doc_bytes = sign_doc.encode_to_vec();
            let signature = wallet.sign_bytes(&sign_doc_bytes);

            let tx = Tx {
                body: Some(body_ref.clone()),
                auth_info: Some(auth_info),
                signatures: vec![signature.serialize_compact().to_vec()],
            };

            let res = cosmos
                .perform_query(
                    BroadcastTxRequest {
                        tx_bytes: tx.encode_to_vec(),
                        mode: BroadcastMode::Sync as i32,
                    },
                    Action::Broadcast(self.clone()),
                    true,
                )
                .await?
                .into_inner()
                .tx_response
                .ok_or_else(|| crate::Error::InvalidChainResponse {
                    message: "Missing inner tx_response".to_owned(),
                    action: Action::Broadcast(self.clone()),
                })?;

            if !self.skip_code_check && res.code != 0 {
                return Err(crate::Error::TransactionFailed {
                    code: res.code.into(),
                    raw_log: res.raw_log,
                    action: Action::Broadcast(self.clone()),
                });
            };

            tracing::debug!("Initial BroadcastTxResponse: {res:?}");

            let (_, res) = cosmos
                .wait_for_transaction_with_action(res.txhash, Some(Action::Broadcast(self.clone())))
                .await?;
            if !self.skip_code_check && res.code != 0 {
                return Err(crate::Error::TransactionFailed {
                    code: res.code.into(),
                    raw_log: res.raw_log,
                    action: Action::Broadcast(self.clone()),
                });
            };

            tracing::debug!("TxResponse: {res:?}");

            Ok(res)
        };

        let attempts = cosmos.get_cosmos_builder().gas_price_retry_attempts();
        for attempt_number in 0..attempts {
            let amount = cosmos
                .gas_to_coins(gas_to_request, attempt_number)
                .to_string();
            match retry_with_price(amount).await {
                Err(crate::Error::TransactionFailed {
                    code: CosmosSdkError::InsufficientFee,
                    raw_log,
                    action: _,
                }) => {
                    tracing::debug!(
                        "Insufficient gas in attempt #{}, retrying. Raw log: {raw_log}",
                        attempt_number + 1
                    );
                }
                res => return res,
            }
        }

        let amount = cosmos.gas_to_coins(gas_to_request, attempts).to_string();
        retry_with_price(amount).await
    }

    /// Does this transaction have any messages already?
    pub fn has_messages(&self) -> bool {
        !self.messages.is_empty()
    }
}

/// Trait for any types that contain a [Cosmos] connection.
pub trait HasCosmos: HasAddressHrp {
    /// Get the underlying connection
    fn get_cosmos(&self) -> &Cosmos;
}

impl HasCosmos for Cosmos {
    fn get_cosmos(&self) -> &Cosmos {
        self
    }
}

impl<T: HasCosmos> HasCosmos for &T {
    fn get_cosmos(&self) -> &Cosmos {
        HasCosmos::get_cosmos(*self)
    }
}

#[cfg(test)]
mod tests {
    use crate::CosmosNetwork;

    use super::*;

    #[test]
    fn gas_estimate_multiplier() {
        let mut cosmos = CosmosNetwork::OsmosisTestnet.builder_local();

        // the same as sign_and_broadcast()
        let multiply_estimated_gas = |cosmos: &CosmosBuilder, gas_used: u64| -> u64 {
            (gas_used as f64 * cosmos.gas_estimate_multiplier()) as u64
        };

        assert_eq!(multiply_estimated_gas(&cosmos, 1234), 1604);
        cosmos.set_gas_estimate_multiplier(Some(4.2));
        assert_eq!(multiply_estimated_gas(&cosmos, 1234), 5182);
    }

    #[tokio::test]

    async fn lazy_load() {
        let mut builder = CosmosNetwork::OsmosisTestnet.builder().await.unwrap();
        builder.set_query_retries(Some(0));
        // something that clearly won't work
        builder.set_grpc_url("https://0.0.0.0:0".to_owned());

        builder.clone().build().await.unwrap_err();
        let cosmos = builder.build_lazy().await;
        cosmos.get_latest_block_info().await.unwrap_err();
    }

    #[tokio::test]
    async fn fallback() {
        let mut builder = CosmosNetwork::OsmosisTestnet.builder().await.unwrap();
        builder.add_grpc_fallback_url(builder.grpc_url().to_owned());
        builder.set_grpc_url("http://0.0.0.0:0");
        let cosmos = builder.build_lazy().await;
        cosmos.get_latest_block_info().await.unwrap();
    }
}

#[derive(Debug)]
pub struct FullSimulateResponse {
    pub body: TxBody,
    pub simres: SimulateResponse,
    pub gas_used: u64,
}
