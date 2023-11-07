mod query;

use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bb8::{ManageConnection, Pool};
use chrono::{DateTime, TimeZone, Utc};
use cosmos_sdk_proto::{
    cosmos::{
        auth::v1beta1::{BaseAccount, QueryAccountRequest},
        bank::v1beta1::{MsgSend, QueryAllBalancesRequest},
        base::{
            abci::v1beta1::TxResponse,
            query::v1beta1::PageRequest,
            tendermint::v1beta1::{GetBlockByHeightRequest, GetLatestBlockRequest},
            v1beta1::Coin,
        },
        tx::v1beta1::{
            AuthInfo, BroadcastMode, BroadcastTxRequest, Fee, GetTxRequest, GetTxsEventRequest,
            ModeInfo, OrderBy, SignDoc, SignerInfo, SimulateRequest, SimulateResponse, Tx, TxBody,
        },
    },
    cosmwasm::wasm::v1::{
        MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract, MsgStoreCode,
        MsgUpdateAdmin, QueryCodeRequest,
    },
    traits::Message,
};
use tonic::{
    async_trait,
    codegen::InterceptedService,
    service::Interceptor,
    transport::{Channel, ClientTlsConfig, Endpoint},
    Status,
};

use crate::{
    address::HasAddressHrp,
    error::{Action, BuilderError, ConnectionError, QueryError, QueryErrorDetails},
    txbuilder::TypedMessage,
    wallet::WalletPublicKey,
    Address, CosmosBuilder, HasAddress, TxBuilder,
};

use self::query::GrpcRequest;

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
    pool: Pool<FinalizedCosmosBuilder>,
    builder: Arc<CosmosBuilder>,
    height: Option<u64>,
}

struct FinalizedCosmosBuilder(Arc<CosmosBuilder>);

impl std::fmt::Debug for Cosmos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cosmos")
            .field("pool", &self.pool)
            .field("builder", &self.builder)
            .field("height", &self.height)
            .finish()
    }
}

#[async_trait]
impl ManageConnection for FinalizedCosmosBuilder {
    type Connection = CosmosInner;

    type Error = ConnectionError;

    async fn connect(&self) -> Result<Self::Connection, ConnectionError> {
        self.0.build_inner().await
    }

    async fn is_valid(&self, inner: &mut CosmosInner) -> Result<(), ConnectionError> {
        inner.is_broken.clone()
    }

    fn has_broken(&self, inner: &mut CosmosInner) -> bool {
        inner.is_broken.is_err()
    }
}

#[async_trait]
trait WithCosmosInner {
    type Output;
    async fn call(self, inner: &CosmosInner) -> Result<Self::Output>;
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
            let err = match self.perform_query_inner(req.clone()).await {
                Ok(x) => break Ok(x),
                Err(err) => err,
            };
            if attempt >= self.builder.query_retries() || !should_retry && err.should_be_retried() {
                return Err(QueryError {
                    action,
                    builder: self.builder.clone(),
                    height: self.height,
                    query: err,
                });
            } else {
                attempt += 1;
                log::debug!(
                    "Error performing a query, retrying. Attempt {attempt} of {}. {err:?}",
                    self.builder.query_retries()
                );
            }
        }
    }

    pub(crate) async fn perform_query_inner<Request: GrpcRequest>(
        &self,
        req: Request,
    ) -> Result<tonic::Response<Request::Response>, QueryErrorDetails> {
        let mut cosmos_inner = self.pool.get().await.map_err(|err| match err {
            bb8::RunError::User(e) => QueryErrorDetails::ConnectionError(e),
            bb8::RunError::TimedOut => QueryErrorDetails::ConnectionTimeout,
        })?;
        let duration =
            tokio::time::Duration::from_secs(self.builder.query_timeout_seconds().into());
        let mut req = tonic::Request::new(req.clone());
        if let Some(height) = self.height {
            // https://docs.cosmos.network/v0.47/run-node/interact-node#query-for-historical-state-using-rest
            let metadata = req.metadata_mut();
            metadata.insert("x-cosmos-block-height", height.into());
        }
        let res =
            tokio::time::timeout(duration, GrpcRequest::perform(req, &mut cosmos_inner)).await;
        match res {
            Ok(Ok(x)) => Ok(x),
            Ok(Err(err)) => {
                // Basic sanity check that we can still talk to the blockchain
                match GrpcRequest::perform(
                    tonic::Request::new(GetLatestBlockRequest {}),
                    &mut cosmos_inner,
                )
                .await
                {
                    Ok(_) => (),
                    Err(source) => {
                        cosmos_inner.is_broken = Err(ConnectionError::SanityCheckFailed {
                            grpc_url: self.get_cosmos_builder().grpc_url().to_owned(),
                            source,
                        });
                    }
                }
                Err(QueryErrorDetails::Tonic(err))
            }
            Err(_) => {
                cosmos_inner.is_broken = Err(ConnectionError::TimeoutQuery {
                    grpc_url: self.get_cosmos_builder().grpc_url().to_owned(),
                });
                Err(QueryErrorDetails::QueryTimeout)
            }
        }
    }

    /// Get the [CosmosBuilder] used to construct this connection.
    pub fn get_cosmos_builder(&self) -> &Arc<CosmosBuilder> {
        &self.builder
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
    pub(crate) authz_query_client:
        cosmos_sdk_proto::cosmos::authz::v1beta1::query_client::QueryClient<
            InterceptedService<Channel, CosmosInterceptor>,
        >,
    is_broken: Result<(), ConnectionError>,
}

impl CosmosBuilder {
    /// Create a new [Cosmos] and perform a sanity check to make sure the connection works.
    pub async fn build(self) -> Result<Cosmos, BuilderError> {
        let cosmos = self.build_lazy().await;

        let actual = cosmos
            .get_latest_block_info()
            .await
            .map_err(|source| BuilderError::SanityQueryFailed {
                grpc_url: cosmos.get_cosmos_builder().grpc_url().to_owned(),
                source,
            })?
            .chain_id;
        let expected = cosmos.get_cosmos_builder().chain_id();
        if actual == expected {
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
        let mut pool_builder = Pool::builder().idle_timeout(Some(Duration::from_secs(
            builder.idle_timeout_seconds().into(),
        )));
        if let Some(count) = builder.connection_count() {
            pool_builder = pool_builder.max_size(count);
        }
        pool_builder = pool_builder.connection_timeout(builder.connection_timeout());
        if let Some(retry_connection) = builder.retry_connection() {
            pool_builder = pool_builder.retry_connection(retry_connection);
        }
        let pool = pool_builder
            .build(FinalizedCosmosBuilder(builder.clone()))
            .await
            .expect("Unexpected pool build error");
        Cosmos {
            pool,
            builder,
            height: None,
        }
    }
}

impl CosmosBuilder {
    async fn build_inner(&self) -> Result<CosmosInner, ConnectionError> {
        let grpc_url = self.grpc_url();
        let grpc_endpoint =
            grpc_url
                .parse::<Endpoint>()
                .map_err(|source| ConnectionError::InvalidGrpcUrl {
                    grpc_url: grpc_url.to_owned(),
                    source: source.into(),
                })?;
        let grpc_endpoint = if grpc_url.starts_with("https://") {
            grpc_endpoint
                .tls_config(ClientTlsConfig::new())
                .map_err(|source| ConnectionError::TlsConfig {
                    grpc_url: grpc_url.to_owned(),
                    source: source.into(),
                })?
        } else {
            grpc_endpoint
        };
        let grpc_channel =
            tokio::time::timeout(tokio::time::Duration::from_secs(5), grpc_endpoint.connect())
                .await
                .map_err(|_| ConnectionError::TimeoutConnecting {
                    grpc_url: grpc_url.to_owned(),
                })?
                .map_err(|source| ConnectionError::CannotEstablishConnection {
                    grpc_url: grpc_url.to_owned(),
                    source: source.into(),
                })?;

        let referer_header = self.referer_header().map(|x| x.to_owned());

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
            authz_query_client: cosmos_sdk_proto::cosmos::authz::v1beta1::query_client::QueryClient::with_interceptor(grpc_channel, CosmosInterceptor(referer_header)),
            is_broken: Ok(()),
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
    pub async fn get_base_account(&self, address: Address) -> Result<BaseAccount> {
        let res = self
            .perform_query(
                QueryAccountRequest {
                    address: address.get_address_string(),
                },
                Action::GetBaseAccount(address),
                true,
            )
            .await?
            .into_inner();

        let base_account = if self.get_address_hrp().as_str() == "inj" {
            let eth_account: crate::injective::EthAccount = prost::Message::decode(
                res.account.context("no eth account found")?.value.as_ref(),
            )?;
            eth_account.base_account.context("no base account found")?
        } else {
            prost::Message::decode(res.account.context("no account found")?.value.as_ref())?
        };
        Ok(base_account)
    }

    /// Get the coin balances for the given address.
    pub async fn all_balances(&self, address: Address) -> Result<Vec<Coin>> {
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

    pub(crate) async fn code_info(&self, code_id: u64) -> Result<Vec<u8>> {
        let res = self
            .perform_query(
                QueryCodeRequest { code_id },
                Action::CodeInfo(code_id),
                true,
            )
            .await?;
        Ok(res.into_inner().data)
    }

    /// Get a transaction, failing immediately if not present
    pub async fn get_transaction_body(
        &self,
        txhash: impl Into<String>,
    ) -> Result<(TxBody, TxResponse)> {
        let txhash = txhash.into();
        let txres = self
            .perform_query(
                GetTxRequest {
                    hash: txhash.clone(),
                },
                Action::GetTransactionBody(txhash.clone()),
                true,
            )
            .await
            .with_context(|| format!("Unable to get transaction {txhash}"))?
            .into_inner();
        let txbody = txres
            .tx
            .with_context(|| format!("Missing tx for transaction {txhash}"))?
            .body
            .with_context(|| format!("Missing body for transaction {txhash}"))?;
        let txres = txres
            .tx_response
            .with_context(|| format!("Missing tx_response for transaction {txhash}"))?;
        Ok((txbody, txres))
    }

    /// Wait for a transaction to land on-chain using a busy loop.
    ///
    /// This is most useful after broadcasting a transaction to wait for it to land.
    pub async fn wait_for_transaction(
        &self,
        txhash: impl Into<String>,
    ) -> Result<(TxBody, TxResponse)> {
        const DELAY_SECONDS: u64 = 2;
        let txhash = txhash.into();
        for attempt in 1..=self.builder.transaction_attempts() {
            let txres = self
                .perform_query(
                    GetTxRequest {
                        hash: txhash.clone(),
                    },
                    Action::GetTransactionBody(txhash.clone()),
                    false,
                )
                .await;
            match txres {
                Ok(txres) => {
                    let txres = txres.into_inner();
                    return Ok((
                        txres
                            .tx
                            .with_context(|| format!("Missing tx for transaction {txhash}"))?
                            .body
                            .with_context(|| format!("Missing body for transaction {txhash}"))?,
                        txres.tx_response.with_context(|| {
                            format!("Missing tx_response for transaction {txhash}")
                        })?,
                    ));
                }
                // For some reason, it looks like Osmosis testnet isn't returning a NotFound. Ugly workaround...
                Err(QueryError {
                    query: QueryErrorDetails::Tonic(e),
                    ..
                }) if e.code() == tonic::Code::NotFound || e.message().contains("not found") => {
                    log::debug!(
                        "Transaction {txhash} not ready, attempt #{attempt}/{}",
                        self.builder.transaction_attempts()
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(DELAY_SECONDS)).await;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
        Err(anyhow::anyhow!(
            "Timed out waiting for {txhash} to be ready"
        ))
    }

    /// Get a list of txhashes for transactions send by the given address.
    pub async fn list_transactions_for(
        &self,
        address: Address,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> Result<Vec<String>> {
        let x = self
            .perform_query(
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
            .await?;
        Ok(x.into_inner()
            .tx_responses
            .into_iter()
            .map(|x| x.txhash)
            .collect())
    }

    /// attempt_number starts at 0
    fn gas_to_coins(&self, gas: u64, attempt_number: u64) -> u64 {
        let low = self.builder.gas_price_low();
        let high = self.builder.gas_price_high();
        let attempts = self.builder.gas_price_retry_attempts();

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
    pub async fn get_block_info(&self, height: i64) -> Result<BlockInfo> {
        let res = self
            .perform_query(
                GetBlockByHeightRequest { height },
                Action::GetBlock(height),
                true,
            )
            .await?
            .into_inner();
        let block_id = res.block_id.context("get_block_info: block_id is None")?;
        let block = res.block.context("get_block_info: block is None")?;
        let header = block.header.context("get_block_info: header is None")?;
        let time = header.time.context("get_block_info: time is None")?;
        let data = block.data.context("get_block_info: data is None")?;
        anyhow::ensure!(
            height == header.height,
            "Mismatched height from blockchain. Got {}, expected {height}",
            header.height
        );
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
            timestamp: Utc.timestamp_nanos(time.seconds * 1_000_000_000 + i64::from(time.nanos)),
            txhashes,
            chain_id: header.chain_id,
        })
    }

    /// Get information on the earliest block available from this node
    pub async fn get_earliest_block_info(&self) -> Result<BlockInfo> {
        // Really hacky, there must be a better way
        let err = match self.get_block_info(1).await {
            Ok(x) => return Ok(x),
            Err(err) => err,
        };
        if let Some(height) = err.downcast_ref::<tonic::Status>().and_then(|status| {
            let per_needle = |needle: &str| {
                let trimmed = status.message().split(needle).nth(1)?.trim();
                let stripped = trimmed.strip_suffix(')').unwrap_or(trimmed);
                stripped.parse().ok()
            };
            for needle in ["lowest height is", "base height: "] {
                if let Some(x) = per_needle(needle) {
                    return Some(x);
                }
            }
            None
        }) {
            self.get_block_info(height).await
        } else {
            Err(err)
        }
    }

    /// Get the latest block available
    pub async fn get_latest_block_info(&self) -> Result<BlockInfo> {
        let res = self
            .perform_query(GetLatestBlockRequest {}, Action::GetLatestBlock, true)
            .await?
            .into_inner();
        let block_id = res.block_id.context("get_block_info: block_id is None")?;
        let block = res.block.context("get_block_info: block is None")?;
        let header = block.header.context("get_block_info: header is None")?;
        let time = header.time.context("get_block_info: time is None")?;
        let data = block.data.context("get_block_info: data is None")?;
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
            timestamp: Utc.timestamp_nanos(time.seconds * 1_000_000_000 + i64::from(time.nanos)),
            txhashes,
            chain_id: header.chain_id,
        })
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

impl TxBuilder {
    /// Simulate the transaction with the given signer or signers.
    ///
    /// Note that for simulation purposes you do not need to provide valid
    /// signatures, so only the signer addresses are needed.
    pub async fn simulate(
        &self,
        cosmos: &Cosmos,
        wallets: &[Address],
    ) -> Result<FullSimulateResponse> {
        let mut sequences = vec![];
        for wallet in wallets {
            sequences.push(match cosmos.get_base_account(wallet.get_address()).await {
                Ok(account) => account.sequence,
                Err(err) => {
                    if err.to_string().contains("not found") {
                        log::warn!(
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
    pub async fn sign_and_broadcast(&self, cosmos: &Cosmos, wallet: &Wallet) -> Result<TxResponse> {
        let simres = self.simulate(cosmos, &[wallet.get_address()]).await?;
        self.inner_sign_and_broadcast(
            cosmos,
            wallet,
            simres.body,
            // Gas estimation is not perfect, so we need to adjust it by a multiplier to account for drift
            // Since we're already estimating and padding, the loss of precision from f64 to u64 is negligible
            (simres.gas_used as f64 * cosmos.builder.gas_estimate_multiplier()) as u64,
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
    ) -> Result<TxResponse> {
        self.inner_sign_and_broadcast(cosmos, wallet, self.make_tx_body(), gas_to_request)
            .await
    }

    async fn inner_sign_and_broadcast(
        &self,
        cosmos: &Cosmos,
        wallet: &Wallet,
        body: TxBody,
        gas_to_request: u64,
    ) -> Result<TxResponse> {
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
            messages: self.messages.clone(),
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
    ) -> Result<FullSimulateResponse> {
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

        let simres = cosmos
            .perform_query(simulate_req, Action::Simulate(self.clone()), true)
            .await
            .context("Unable to simulate transaction")?
            .into_inner();

        let gas_used = simres
            .gas_info
            .as_ref()
            .context("Missing gas_info in SimulateResponse")?
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
    ) -> Result<TxResponse> {
        enum AttemptError {
            Inner(anyhow::Error),
            InsufficientGas(anyhow::Error),
        }
        impl From<anyhow::Error> for AttemptError {
            fn from(e: anyhow::Error) -> Self {
                AttemptError::Inner(e)
            }
        }
        let body_ref = &body;
        let retry_with_price = |amount| async move {
            let auth_info = AuthInfo {
                signer_infos: vec![self.make_signer_info(sequence, Some(wallet))],
                fee: Some(Fee {
                    amount: vec![Coin {
                        denom: cosmos.builder.gas_coin().to_owned(),
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
                chain_id: cosmos.builder.chain_id().to_owned(),
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
                .await
                .context("Unable to broadcast transaction")?
                .into_inner()
                .tx_response
                .context("Missing inner tx_response")?;

            if !self.skip_code_check && res.code != 0 {
                let e = anyhow::anyhow!(
                    "Initial transaction broadcast failed with code {}. Raw log: {}",
                    res.code,
                    res.raw_log
                );
                if res.code == 13 {
                    return Err(AttemptError::InsufficientGas(e));
                }
                return Err(AttemptError::Inner(e));
            };

            log::debug!("Initial BroadcastTxResponse: {res:?}");

            let (_, res) = cosmos.wait_for_transaction(res.txhash).await?;
            if !self.skip_code_check && res.code != 0 {
                return Err(AttemptError::Inner(anyhow::anyhow!(
                    "Transaction failed with code {}. Raw log: {}",
                    res.code,
                    res.raw_log
                )));
            };

            log::debug!("TxResponse: {res:?}");

            Ok(res)
        };

        let attempts = cosmos.get_cosmos_builder().gas_price_retry_attempts();
        for attempt_number in 0..attempts {
            let amount = cosmos
                .gas_to_coins(gas_to_request, attempt_number)
                .to_string();
            match retry_with_price(amount).await {
                Ok(x) => return Ok(x),
                Err(AttemptError::InsufficientGas(e)) => {
                    log::debug!(
                        "Insufficient gas in attempt #{attempt_number}, retrying. Error: {e:?}"
                    );
                }
                Err(AttemptError::Inner(e)) => return Err(e),
            }
        }

        let amount = cosmos.gas_to_coins(gas_to_request, attempts).to_string();
        match retry_with_price(amount).await {
            Ok(x) => Ok(x),
            Err(AttemptError::InsufficientGas(e)) => Err(e),
            Err(AttemptError::Inner(e)) => Err(e),
        }
    }

    /// Does this transaction have any messages already?
    pub fn has_messages(&self) -> bool {
        !self.messages.is_empty()
    }
}

impl TypedMessage {
    /// Generate a new [TypedMessage] from a raw protocol value.
    pub fn new(inner: cosmos_sdk_proto::Any) -> Self {
        TypedMessage(inner)
    }

    /// Extract the underlying raw protocol value.
    pub fn into_inner(self) -> cosmos_sdk_proto::Any {
        self.0
    }
}

impl From<MsgStoreCode> for TypedMessage {
    fn from(msg: MsgStoreCode) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmwasm.wasm.v1.MsgStoreCode".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

impl From<MsgInstantiateContract> for TypedMessage {
    fn from(msg: MsgInstantiateContract) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmwasm.wasm.v1.MsgInstantiateContract".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

impl From<MsgMigrateContract> for TypedMessage {
    fn from(msg: MsgMigrateContract) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmwasm.wasm.v1.MsgMigrateContract".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

impl From<MsgExecuteContract> for TypedMessage {
    fn from(msg: MsgExecuteContract) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmwasm.wasm.v1.MsgExecuteContract".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

impl From<MsgUpdateAdmin> for TypedMessage {
    fn from(msg: MsgUpdateAdmin) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmwasm.wasm.v1.MsgUpdateAdmin".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

impl From<MsgSend> for TypedMessage {
    fn from(msg: MsgSend) -> Self {
        TypedMessage(cosmos_sdk_proto::Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_owned(),
            value: msg.encode_to_vec(),
        })
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
        builder.set_retry_connection(Some(false));
        // something that clearly won't work
        builder.set_grpc_url("https://0.0.0.0:0".to_owned());

        builder.clone().build().await.unwrap_err();
        let cosmos = builder.build_lazy().await;
        cosmos.get_latest_block_info().await.unwrap_err();
    }
}

#[derive(Debug)]
pub struct FullSimulateResponse {
    pub body: TxBody,
    pub simres: SimulateResponse,
    pub gas_used: u64,
}
