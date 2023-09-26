mod query;

use std::{fmt::Display, str::FromStr, sync::Arc, time::Duration};

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
        ContractInfo, MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract, MsgStoreCode,
        MsgUpdateAdmin, QueryCodeRequest, QueryContractHistoryRequest,
        QueryContractHistoryResponse, QueryContractInfoRequest, QueryRawContractStateRequest,
        QuerySmartContractStateRequest,
    },
    traits::Message,
};
use serde::{de::Visitor, Deserialize};
use tokio::time::error::Elapsed;
use tonic::{
    async_trait,
    codegen::InterceptedService,
    service::Interceptor,
    transport::{Channel, ClientTlsConfig, Endpoint},
    Status,
};

use crate::{address::HasAddressType, Address, AddressType, HasAddress};

use self::query::GrpcRequest;

use super::Wallet;

#[derive(Clone)]
pub struct Cosmos {
    pool: Pool<CosmosBuilders>,
    first_builder: Arc<CosmosBuilder>,
}

/// Multiple [CosmosBuilder]s to allow for automatically switching between nodes.
pub struct CosmosBuilders {
    builders: Vec<Arc<CosmosBuilder>>,
    next_index: parking_lot::Mutex<usize>,
}

impl CosmosBuilders {
    fn get_first_builder(&self) -> &Arc<CosmosBuilder> {
        self.builders
            .first()
            .expect("Cannot construct a CosmosBuilders with no CosmosBuilder")
    }

    pub fn add(&mut self, builder: impl Into<Arc<CosmosBuilder>>) {
        self.builders.push(builder.into());
    }
}

#[async_trait]
impl ManageConnection for CosmosBuilders {
    type Connection = CosmosInner;

    type Error = anyhow::Error;

    async fn connect(&self) -> Result<Self::Connection> {
        self.get_next_builder().build_inner().await
    }

    async fn is_valid(&self, inner: &mut CosmosInner) -> Result<()> {
        if inner.is_broken {
            Err(anyhow::anyhow!("Connection is marked as broken"))
        } else {
            Ok(())
        }
    }

    fn has_broken(&self, inner: &mut CosmosInner) -> bool {
        inner.is_broken
    }
}

impl CosmosBuilders {
    fn get_next_builder(&self) -> Arc<CosmosBuilder> {
        let mut guard = self.next_index.lock();
        let res = self
            .builders
            .get(*guard)
            .expect("Impossible. get_next_builders failed")
            .clone();

        *guard += 1;
        if *guard >= self.builders.len() {
            *guard = 0;
        }

        res
    }
}

#[async_trait]
trait WithCosmosInner {
    type Output;
    async fn call(self, inner: &CosmosInner) -> Result<Self::Output>;
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum PerformQueryError {
    #[error("Error getting a gRPC connection from the pool: {0:?}")]
    Pool(bb8::RunError<anyhow::Error>),
    #[error("Error response from gRPC endpoint: {0:?}")]
    Tonic(tonic::Status),
    #[error("Query timed out, total elapsed time: {0}")]
    Timeout(Elapsed),
}

impl Cosmos {
    pub(crate) async fn perform_query<Request: GrpcRequest>(
        &self,
        height: Option<u64>,
        req: Request,
    ) -> Result<tonic::Response<Request::Response>, PerformQueryError> {
        let mut attempt = 0;
        loop {
            let mut cosmos_inner = self.pool.get().await.map_err(PerformQueryError::Pool)?;
            let duration = tokio::time::Duration::from_secs(
                self.first_builder.config.query_timeout_seconds.into(),
            );
            let mut req = tonic::Request::new(req.clone());
            if let Some(height) = height {
                // https://docs.cosmos.network/v0.47/run-node/interact-node#query-for-historical-state-using-rest
                let metadata = req.metadata_mut();
                metadata.insert("x-cosmos-block-height", height.into());
            }
            let res =
                tokio::time::timeout(duration, GrpcRequest::perform(req, &mut cosmos_inner)).await;
            let e = match res {
                Ok(Ok(x)) => return Ok(x),
                Ok(Err(err)) => {
                    // Basic sanity check that we can still talk to the blockchain
                    match GrpcRequest::perform(
                        tonic::Request::new(GetLatestBlockRequest {}),
                        &mut cosmos_inner,
                    )
                    .await
                    {
                        Ok(_) => (),
                        Err(_) => {
                            cosmos_inner.is_broken = true;
                        }
                    }
                    PerformQueryError::Tonic(err)
                }
                Err(e) => {
                    cosmos_inner.is_broken = true;
                    PerformQueryError::Timeout(e)
                }
            };
            if attempt >= self.first_builder.config.query_retries {
                return Err(e);
            } else {
                attempt += 1;
                log::debug!(
                    "Error performing a query, retrying. Attempt {attempt} of {}. {e:?}",
                    self.first_builder.config.query_retries
                );
            }
        }
    }

    pub fn get_first_builder(&self) -> &Arc<CosmosBuilder> {
        &self.first_builder
    }

    pub fn get_network(&self) -> CosmosNetwork {
        self.get_first_builder().network
    }

    /// Sanity check the connection, ensuring that the chain ID we found matches what we expected.
    ///
    /// Called automatically by [Cosmos::build], but not by [Cosmos::build_lazy].
    pub async fn sanity_check(&self) -> Result<()> {
        let actual = &self.get_latest_block_info().await?.chain_id;
        let expected = &self.get_first_builder().chain_id;
        if actual == expected {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Mismatched chain IDs. Actual: {actual}. Expected: {expected}."
            ))
        }
    }
}

impl HasAddressType for Cosmos {
    fn get_address_type(&self) -> AddressType {
        self.get_first_builder().address_type
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
    is_broken: bool,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum CosmosNetwork {
    JunoTestnet,
    JunoMainnet,
    JunoLocal,
    OsmosisMainnet,
    OsmosisTestnet,
    OsmosisLocal,
    WasmdLocal,
    SeiMainnet,
    SeiTestnet,
    StargazeTestnet,
    StargazeMainnet,
    InjectiveTestnet,
    InjectiveMainnet,
}

/// Build a connection
#[derive(Clone)]
pub struct CosmosBuilder {
    pub grpc_url: String,
    pub chain_id: String,
    pub gas_coin: String,
    pub address_type: AddressType,
    pub config: CosmosConfig,
    pub network: CosmosNetwork,
}

/// Optional config values.
#[derive(Clone, Debug)]
pub struct CosmosConfig {
    // Add a multiplier to the gas estimate to account for any gas fluctuations
    pub gas_estimate_multiplier: f64,

    /// Amount of gas coin to send per unit of gas, at the low end.
    pub gas_price_low: f64,

    /// Amount of gas coin to send per unit of gas, at the high end.
    pub gas_price_high: f64,

    /// How many retries at different gas prices should we try before using high
    ///
    /// If this is 0, we'll always go straight to high. 1 means we'll try the
    /// low and the high. 2 means we'll try low, midpoint, and high. And so on
    /// from there.
    pub gas_price_retry_attempts: u64,

    /// How many attempts to give a transaction before giving up
    pub transaction_attempts: usize,

    /// Referrer header that can be set
    referer_header: Option<String>,

    /// Set the number of bb8 connections
    connection_count: Option<u32>,

    /// Sets the number of seconds before an idle connection is reaped
    ///
    /// Defaults to 20 seconds
    idle_timeout_seconds: u32,

    /// Sets the number of seconds before timing out a gRPC query
    ///
    /// Defaults to 5 seconds
    query_timeout_seconds: u32,

    /// Number of attempts to make at a query before giving up.
    ///
    /// Only retries if there is a tonic-level error.
    ///
    /// Defaults to 3
    query_retries: u32,
}

impl Default for CosmosConfig {
    fn default() -> Self {
        // same amount that CosmosJS uses:  https://github.com/cosmos/cosmjs/blob/e8e65aa0c145616ccb58625c32bffe08b46ff574/packages/cosmwasm-stargate/src/signingcosmwasmclient.ts#L550
        // and OsmoJS too: https://github.com/osmosis-labs/osmojs/blob/bacb2fc322abc3d438581f5dce049f5ae467059d/packages/osmojs/src/utils/gas/estimation.ts#L10
        const DEFAULT_GAS_ESTIMATE_MULTIPLIER: f64 = 1.3;
        Self {
            gas_estimate_multiplier: DEFAULT_GAS_ESTIMATE_MULTIPLIER,
            gas_price_low: 0.02,
            gas_price_high: 0.03,
            gas_price_retry_attempts: 3,
            transaction_attempts: 30,
            referer_header: None,
            connection_count: None,
            idle_timeout_seconds: 20,
            query_timeout_seconds: 5,
            query_retries: 3,
        }
    }
}

impl CosmosBuilder {
    pub async fn build(self) -> Result<Cosmos> {
        let cosmos = self.build_lazy().await;
        // Force strict connection
        cosmos.sanity_check().await?;
        Ok(cosmos)
    }

    pub async fn build_lazy(self) -> Cosmos {
        CosmosBuilders::from(self).build_lazy().await
    }
}

impl From<CosmosBuilder> for CosmosBuilders {
    fn from(c: CosmosBuilder) -> Self {
        CosmosBuilders {
            builders: vec![c.into()],
            next_index: parking_lot::Mutex::new(0),
        }
    }
}

impl CosmosBuilders {
    pub async fn build_lazy(self) -> Cosmos {
        let first_builder = self.get_first_builder().clone();
        let mut builder = Pool::builder().idle_timeout(Some(Duration::from_secs(
            first_builder.config.idle_timeout_seconds.into(),
        )));
        if let Some(count) = first_builder.config.connection_count {
            builder = builder.max_size(count);
        }
        let pool = builder
            .build(self)
            .await
            .expect("Unexpected pool build error");
        Cosmos {
            pool,
            first_builder,
        }
    }
}

impl serde::Serialize for CosmosNetwork {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CosmosNetwork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(CosmosNetworkVisitor)
    }
}

struct CosmosNetworkVisitor;

impl<'de> Visitor<'de> for CosmosNetworkVisitor {
    type Value = CosmosNetwork;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("CosmosNetwork")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        CosmosNetwork::from_str(v).map_err(E::custom)
    }
}

impl CosmosNetwork {
    fn as_str(self) -> &'static str {
        match self {
            CosmosNetwork::JunoTestnet => "juno-testnet",
            CosmosNetwork::JunoMainnet => "juno-mainnet",
            CosmosNetwork::JunoLocal => "juno-local",
            CosmosNetwork::OsmosisMainnet => "osmosis-mainnet",
            CosmosNetwork::OsmosisTestnet => "osmosis-testnet",
            CosmosNetwork::OsmosisLocal => "osmosis-local",
            CosmosNetwork::WasmdLocal => "wasmd-local",
            CosmosNetwork::SeiMainnet => "sei-mainnet",
            CosmosNetwork::SeiTestnet => "sei-testnet",
            CosmosNetwork::StargazeTestnet => "stargaze-testnet",
            CosmosNetwork::StargazeMainnet => "stargaze-mainnet",
            CosmosNetwork::InjectiveTestnet => "injective-testnet",
            CosmosNetwork::InjectiveMainnet => "injective-mainnet",
        }
    }
}

impl Display for CosmosNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CosmosNetwork {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "juno-testnet" => Ok(CosmosNetwork::JunoTestnet),
            "juno-mainnet" => Ok(CosmosNetwork::JunoMainnet),
            "juno-local" => Ok(CosmosNetwork::JunoLocal),
            "osmosis-mainnet" => Ok(CosmosNetwork::OsmosisMainnet),
            "osmosis-testnet" => Ok(CosmosNetwork::OsmosisTestnet),
            "osmosis-local" => Ok(CosmosNetwork::OsmosisLocal),
            "wasmd-local" => Ok(CosmosNetwork::WasmdLocal),
            "sei-mainnet" => Ok(CosmosNetwork::SeiMainnet),
            "sei-testnet" => Ok(CosmosNetwork::SeiTestnet),
            "stargaze-testnet" => Ok(CosmosNetwork::StargazeTestnet),
            "stargaze-mainnet" => Ok(CosmosNetwork::StargazeMainnet),
            "injective-testnet" => Ok(CosmosNetwork::InjectiveTestnet),
            "injective-mainnet" => Ok(CosmosNetwork::InjectiveMainnet),
            _ => Err(anyhow::anyhow!("Unknown network: {s}")),
        }
    }
}

impl CosmosNetwork {
    pub async fn connect(self) -> Result<Cosmos> {
        self.builder().await?.build().await
    }

    pub async fn builder(self) -> Result<CosmosBuilder> {
        Ok(match self {
            CosmosNetwork::JunoTestnet => CosmosBuilder::new_juno_testnet(),
            CosmosNetwork::JunoMainnet => CosmosBuilder::new_juno_mainnet(),
            CosmosNetwork::JunoLocal => CosmosBuilder::new_juno_local(),
            CosmosNetwork::OsmosisMainnet => CosmosBuilder::new_osmosis_mainnet(),
            CosmosNetwork::OsmosisTestnet => CosmosBuilder::new_osmosis_testnet(),
            CosmosNetwork::OsmosisLocal => CosmosBuilder::new_osmosis_local(),
            CosmosNetwork::WasmdLocal => CosmosBuilder::new_wasmd_local(),
            CosmosNetwork::SeiMainnet => CosmosBuilder::new_sei_mainnet().await?,
            CosmosNetwork::SeiTestnet => CosmosBuilder::new_sei_testnet().await?,
            CosmosNetwork::StargazeTestnet => CosmosBuilder::new_stargaze_testnet(),
            CosmosNetwork::StargazeMainnet => CosmosBuilder::new_stargaze_mainnet(),
            CosmosNetwork::InjectiveTestnet => CosmosBuilder::new_injective_testnet(),
            CosmosNetwork::InjectiveMainnet => CosmosBuilder::new_injective_mainnet(),
        })
    }
}

impl CosmosBuilder {
    async fn build_inner(self: Arc<Self>) -> Result<CosmosInner> {
        let grpc_url = &self.grpc_url;
        let grpc_endpoint = grpc_url.parse::<Endpoint>()?;
        let grpc_endpoint = if grpc_url.starts_with("https://") {
            grpc_endpoint.tls_config(ClientTlsConfig::new())?
        } else {
            grpc_endpoint
        };
        let grpc_channel = match tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            grpc_endpoint.connect(),
        )
        .await
        {
            Ok(grpc_channel) => grpc_channel
                .with_context(|| format!("Error establishing gRPC connection to {grpc_url}"))?,
            Err(_) => anyhow::bail!("Timed out while connecting to {grpc_url}"),
        };

        let referer_header = self.config.referer_header.clone();

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
            is_broken: false,
        })
    }
}

impl Cosmos {
    pub fn get_config(&self) -> &CosmosConfig {
        &self.first_builder.config
    }

    pub async fn get_base_account(&self, address: impl Into<String>) -> Result<BaseAccount> {
        let res = self
            .perform_query(
                None,
                QueryAccountRequest {
                    address: address.into(),
                },
            )
            .await?
            .into_inner();

        let base_account = if self.get_address_type() == AddressType::Injective {
            let eth_account: crate::injective::EthAccount = prost::Message::decode(
                res.account.context("no eth account found")?.value.as_ref(),
            )?;
            eth_account.base_account.context("no base account found")?
        } else {
            prost::Message::decode(res.account.context("no account found")?.value.as_ref())?
        };
        Ok(base_account)
    }

    pub async fn all_balances(&self, address: impl Into<String>) -> Result<Vec<Coin>> {
        self.all_balances_at(address, None).await
    }

    pub async fn all_balances_at(
        &self,
        address: impl Into<String>,
        height: Option<u64>,
    ) -> Result<Vec<Coin>> {
        let address = address.into();
        let mut coins = Vec::new();
        let mut pagination = None;
        loop {
            let mut res = self
                .perform_query(
                    height,
                    QueryAllBalancesRequest {
                        address: address.clone(),
                        pagination: pagination.take(),
                    },
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

    pub async fn wasm_query(
        &self,
        address: impl Into<String>,
        query_data: impl Into<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let res = self
            .perform_query(
                None,
                QuerySmartContractStateRequest {
                    address: address.into(),
                    query_data: query_data.into(),
                },
            )
            .await?
            .into_inner();
        Ok(res.data)
    }

    pub async fn wasm_query_at_height(
        &self,
        address: impl Into<String>,
        query_data: impl Into<Vec<u8>>,
        height: u64,
    ) -> Result<Vec<u8>> {
        Ok(self
            .perform_query(
                Some(height),
                QuerySmartContractStateRequest {
                    address: address.into(),
                    query_data: query_data.into(),
                },
            )
            .await?
            .into_inner()
            .data)
    }

    pub async fn wasm_raw_query(
        &self,
        address: impl Into<String>,
        key: impl Into<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        Ok(self
            .perform_query(
                None,
                QueryRawContractStateRequest {
                    address: address.into(),
                    query_data: key.into(),
                },
            )
            .await?
            .into_inner()
            .data)
    }

    pub async fn wasm_raw_query_at_height(
        &self,
        address: impl Into<String>,
        key: impl Into<Vec<u8>>,
        height: u64,
    ) -> Result<Vec<u8>> {
        Ok(self
            .perform_query(
                Some(height),
                QueryRawContractStateRequest {
                    address: address.into(),
                    query_data: key.into(),
                },
            )
            .await?
            .into_inner()
            .data)
    }

    pub(crate) async fn code_info(&self, code_id: u64) -> Result<Vec<u8>> {
        let res = self
            .perform_query(None, QueryCodeRequest { code_id })
            .await?;
        Ok(res.into_inner().data)
    }

    /// Implements a retry loop waiting for a transaction to be ready
    pub async fn wait_for_transaction(&self, txhash: impl Into<String>) -> Result<TxResponse> {
        self.wait_for_transaction_body(txhash).await.map(|x| x.1)
    }

    /// Get a transaction, failing immediately if not present
    pub async fn get_transaction_body(
        &self,
        txhash: impl Into<String>,
    ) -> Result<(TxBody, TxResponse)> {
        let txhash = txhash.into();
        let txres = self
            .perform_query(
                None,
                GetTxRequest {
                    hash: txhash.clone(),
                },
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

    pub async fn wait_for_transaction_body(
        &self,
        txhash: impl Into<String>,
    ) -> Result<(TxBody, TxResponse)> {
        const DELAY_SECONDS: u64 = 2;
        let txhash = txhash.into();
        for attempt in 1..=self.first_builder.config.transaction_attempts {
            let txres = self
                .perform_query(
                    None,
                    GetTxRequest {
                        hash: txhash.clone(),
                    },
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
                Err(PerformQueryError::Tonic(e))
                    if e.code() == tonic::Code::NotFound || e.message().contains("not found") =>
                {
                    log::debug!(
                        "Transaction {txhash} not ready, attempt #{attempt}/{}",
                        self.first_builder.config.transaction_attempts
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

    pub async fn list_transactions_for(
        &self,
        address: Address,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> Result<Vec<String>> {
        let x = self
            .perform_query(
                None,
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
            )
            .await?;
        Ok(x.into_inner()
            .tx_responses
            .into_iter()
            .map(|x| x.txhash)
            .collect())
    }

    pub fn get_gas_coin(&self) -> &String {
        &self.first_builder.gas_coin
    }

    /// attempt_number starts at 0
    fn gas_to_coins(&self, gas: u64, attempt_number: u64) -> u64 {
        let config = &self.first_builder.config;
        let low = config.gas_price_low;
        let high = config.gas_price_high;
        let attempts = config.gas_price_retry_attempts;

        let gas_price = if attempt_number >= attempts {
            high
        } else {
            assert!(attempts > 0);
            let step = (high - low) / attempts as f64;
            low + step * attempt_number as f64
        };

        (gas as f64 * gas_price) as u64
    }

    pub fn get_gas_multiplier(&self) -> f64 {
        self.first_builder.config.gas_estimate_multiplier
    }

    pub async fn contract_info(&self, address: impl Into<String>) -> Result<ContractInfo> {
        self.perform_query(
            None,
            QueryContractInfoRequest {
                address: address.into(),
            },
        )
        .await?
        .into_inner()
        .contract_info
        .context("contract_info: missing contract_info (ironic...)")
    }

    pub async fn contract_history(
        &self,
        address: impl Into<String>,
    ) -> Result<QueryContractHistoryResponse> {
        Ok(self
            .perform_query(
                None,
                QueryContractHistoryRequest {
                    address: address.into(),
                    pagination: None,
                },
            )
            .await?
            .into_inner())
    }

    pub async fn get_block_info(&self, height: i64) -> Result<BlockInfo> {
        let res = self
            .perform_query(None, GetBlockByHeightRequest { height })
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

    pub async fn get_latest_block_info(&self) -> Result<BlockInfo> {
        let res = self
            .perform_query(None, GetLatestBlockRequest {})
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

impl CosmosBuilder {
    pub fn set_referer_header(&mut self, value: String) {
        self.config.referer_header = Some(value);
    }

    pub fn set_connection_count(&mut self, count: u32) {
        self.config.connection_count = Some(count);
    }

    pub fn set_idle_timeout(&mut self, timeout_seconds: u32) {
        self.config.idle_timeout_seconds = timeout_seconds;
    }

    pub fn set_query_timeout(&mut self, timeout_seconds: u32) {
        self.config.query_timeout_seconds = timeout_seconds;
    }

    pub fn set_query_retries(&mut self, retries: u32) {
        self.config.query_retries = retries;
    }

    fn new_juno_testnet() -> CosmosBuilder {
        CosmosBuilder {
            grpc_url: "http://juno-testnet-grpc.polkachu.com:12690".to_owned(),
            chain_id: "uni-6".to_owned(),
            gas_coin: "ujunox".to_owned(),
            address_type: AddressType::Juno,
            config: CosmosConfig::default(),
            network: CosmosNetwork::JunoTestnet,
        }
    }

    fn new_juno_local() -> CosmosBuilder {
        CosmosBuilder {
            grpc_url: "http://localhost:9090".to_owned(),
            chain_id: "testing".to_owned(),
            gas_coin: "ujunox".to_owned(),
            address_type: AddressType::Juno,
            config: CosmosConfig {
                transaction_attempts: 3, // fail faster during testing
                ..CosmosConfig::default()
            },
            network: CosmosNetwork::JunoLocal,
        }
    }

    fn new_juno_mainnet() -> CosmosBuilder {
        // Found at: https://cosmos.directory/juno/nodes
        CosmosBuilder {
            grpc_url: "http://juno-grpc.polkachu.com:12690".to_owned(),
            chain_id: "juno-1".to_owned(),
            gas_coin: "ujuno".to_owned(),
            address_type: AddressType::Juno,
            config: CosmosConfig::default(),
            network: CosmosNetwork::JunoMainnet,
        }
    }

    fn new_osmosis_mainnet() -> CosmosBuilder {
        // Found at: https://docs.osmosis.zone/networks/
        CosmosBuilder {
            grpc_url: "http://grpc.osmosis.zone:9090".to_owned(),
            chain_id: "osmosis-1".to_owned(),
            gas_coin: "uosmo".to_owned(),
            address_type: AddressType::Osmo,
            config: CosmosConfig::default(),
            network: CosmosNetwork::OsmosisMainnet,
        }
    }

    fn new_osmosis_testnet() -> CosmosBuilder {
        // Others available at: https://docs.osmosis.zone/networks/
        CosmosBuilder {
            grpc_url: "https://grpc.osmotest5.osmosis.zone".to_owned(),
            chain_id: "osmo-test-5".to_owned(),
            gas_coin: "uosmo".to_owned(),
            address_type: AddressType::Osmo,
            config: CosmosConfig::default(),
            network: CosmosNetwork::OsmosisTestnet,
        }
    }

    fn new_osmosis_local() -> CosmosBuilder {
        CosmosBuilder {
            grpc_url: "http://localhost:9090".to_owned(),
            chain_id: "localosmosis".to_owned(),
            gas_coin: "uosmo".to_owned(),
            address_type: AddressType::Osmo,
            config: CosmosConfig::default(),
            network: CosmosNetwork::OsmosisLocal,
        }
    }

    fn new_wasmd_local() -> CosmosBuilder {
        CosmosBuilder {
            grpc_url: "http://localhost:9090".to_owned(),
            chain_id: "localwasmd".to_owned(),
            gas_coin: "uwasm".to_owned(),
            address_type: AddressType::Wasm,
            config: CosmosConfig::default(),
            network: CosmosNetwork::WasmdLocal,
        }
    }
    async fn new_sei_mainnet() -> Result<CosmosBuilder> {
        #[derive(Deserialize)]
        struct SeiGasConfig {
            #[serde(rename = "pacific-1")]
            pub pacific_1: SeiGasConfigItem,
        }
        #[derive(Deserialize)]
        struct SeiGasConfigItem {
            pub min_gas_price: f64,
        }

        let url = "https://raw.githubusercontent.com/sei-protocol/chain-registry/master/gas.json";
        let resp = reqwest::get(url).await?;
        let gas_config: SeiGasConfig = resp.json().await?;

        // https://github.com/chainapsis/keplr-chain-registry/blob/main/cosmos/pacific.json
        Ok(CosmosBuilder {
            grpc_url: "https://grpc.sei-apis.com".to_owned(),
            chain_id: "pacific-1".to_owned(),
            gas_coin: "usei".to_owned(),
            address_type: AddressType::Sei,
            config: CosmosConfig {
                gas_price_low: gas_config.pacific_1.min_gas_price,
                gas_price_high: gas_config.pacific_1.min_gas_price * 2.0,
                gas_price_retry_attempts: 6,
                ..CosmosConfig::default()
            },
            network: CosmosNetwork::SeiMainnet,
        })
    }
    async fn new_sei_testnet() -> Result<CosmosBuilder> {
        #[derive(Deserialize)]
        struct SeiGasConfig {
            #[serde(rename = "atlantic-2")]
            pub atlantic_2: SeiGasConfigItem,
        }
        #[derive(Deserialize)]
        struct SeiGasConfigItem {
            pub min_gas_price: f64,
        }

        let url = "https://raw.githubusercontent.com/sei-protocol/testnet-registry/master/gas.json";
        let resp = reqwest::get(url).await?;
        let gas_config: SeiGasConfig = resp.json().await?;

        Ok(CosmosBuilder {
            grpc_url: "https://test-sei-grpc.kingnodes.com".to_owned(),
            chain_id: "atlantic-2".to_owned(),
            gas_coin: "usei".to_owned(),
            address_type: AddressType::Sei,
            config: CosmosConfig {
                gas_price_low: gas_config.atlantic_2.min_gas_price,
                gas_price_high: gas_config.atlantic_2.min_gas_price * 2.0,
                gas_price_retry_attempts: 6,
                ..CosmosConfig::default()
            },
            network: CosmosNetwork::SeiTestnet,
        })
    }

    fn new_stargaze_testnet() -> CosmosBuilder {
        // https://github.com/cosmos/chain-registry/blob/master/testnets/stargazetestnet/chain.json
        CosmosBuilder {
            grpc_url: "http://grpc-1.elgafar-1.stargaze-apis.com:26660".to_owned(),
            chain_id: "elgafar-1".to_owned(),
            // https://github.com/cosmos/chain-registry/blob/master/testnets/stargazetestnet/assetlist.json
            gas_coin: "ustars".to_owned(),
            address_type: AddressType::Stargaze,
            config: CosmosConfig::default(),
            network: CosmosNetwork::StargazeTestnet,
        }
    }

    fn new_stargaze_mainnet() -> CosmosBuilder {
        // https://github.com/cosmos/chain-registry/blob/master/stargaze/chain.json
        CosmosBuilder {
            grpc_url: "http://stargaze-grpc.polkachu.com:13790".to_owned(),
            chain_id: "stargaze-1".to_owned(),
            // https://github.com/cosmos/chain-registry/blob/master/stargaze/assetlist.json
            gas_coin: "ustars".to_owned(),
            address_type: AddressType::Stargaze,
            config: CosmosConfig::default(),
            network: CosmosNetwork::StargazeMainnet,
        }
    }

    fn new_injective_testnet() -> CosmosBuilder {
        // https://github.com/cosmos/chain-registry/blob/master/testnets/injectivetestnet/chain.json
        // https://docs.injective.network/develop/public-endpoints/
        CosmosBuilder {
            grpc_url: "https://testnet.sentry.chain.grpc.injective.network:443".to_owned(),
            chain_id: "injective-888".to_owned(),
            gas_coin: "inj".to_owned(),
            address_type: AddressType::Injective,
            config: CosmosConfig {
                gas_price_low: 500000000.0,
                gas_price_high: 900000000.0,
                ..CosmosConfig::default()
            },
            network: CosmosNetwork::InjectiveTestnet,
        }
    }

    fn new_injective_mainnet() -> CosmosBuilder {
        // https://github.com/cosmos/chain-registry/blob/master/injective/chain.json
        // https://docs.injective.network/develop/public-endpoints/
        CosmosBuilder {
            grpc_url: "https://sentry.chain.grpc.injective.network:443".to_owned(),
            chain_id: "injective-1".to_owned(),
            gas_coin: "inj".to_owned(),
            address_type: AddressType::Injective,
            config: CosmosConfig {
                gas_price_low: 500000000.0,
                gas_price_high: 900000000.0,
                ..CosmosConfig::default()
            },
            network: CosmosNetwork::InjectiveMainnet,
        }
    }
}

#[derive(Debug)]
pub struct BlockInfo {
    pub height: i64,
    pub block_hash: String,
    pub timestamp: DateTime<Utc>,
    pub txhashes: Vec<String>,
    pub chain_id: String,
}

#[derive(Default)]
pub struct TxBuilder {
    messages: Vec<cosmos_sdk_proto::Any>,
    memo: Option<String>,
    skip_code_check: bool,
}

impl TxBuilder {
    pub fn add_message(mut self, msg: impl Into<TypedMessage>) -> Self {
        self.messages.push(msg.into().0);
        self
    }

    pub fn add_message_mut(&mut self, msg: impl Into<TypedMessage>) {
        self.messages.push(msg.into().0);
    }

    pub fn add_update_contract_admin(
        mut self,
        contract: impl HasAddress,
        wallet: impl HasAddress,
        new_admin: impl HasAddress,
    ) -> Self {
        self.add_update_contract_admin_mut(contract, wallet, new_admin);
        self
    }

    pub fn add_update_contract_admin_mut(
        &mut self,
        contract: impl HasAddress,
        wallet: impl HasAddress,
        new_admin: impl HasAddress,
    ) {
        self.add_message_mut(MsgUpdateAdmin {
            sender: wallet.get_address_string(),
            new_admin: new_admin.get_address_string(),
            contract: contract.get_address_string(),
        });
    }

    pub fn add_execute_message(
        mut self,
        contract: impl HasAddress,
        wallet: impl HasAddress,
        funds: Vec<Coin>,
        msg: impl serde::Serialize,
    ) -> Result<Self> {
        self.add_execute_message_mut(contract, wallet, funds, msg)?;
        Ok(self)
    }

    pub fn add_execute_message_mut(
        &mut self,
        contract: impl HasAddress,
        wallet: impl HasAddress,
        funds: Vec<Coin>,
        msg: impl serde::Serialize,
    ) -> Result<()> {
        self.add_message_mut(MsgExecuteContract {
            sender: wallet.get_address_string(),
            contract: contract.get_address_string(),
            msg: serde_json::to_vec(&msg)?,
            funds,
        });
        Ok(())
    }

    pub fn set_memo(mut self, memo: impl Into<String>) -> Self {
        self.memo = Some(memo.into());
        self
    }

    pub fn set_optional_memo(mut self, memo: impl Into<Option<String>>) -> Self {
        self.memo = memo.into();
        self
    }

    /// When calling [TxBuilder::sign_and_broadcast], skip the check of whether the code is 0
    pub fn skip_code_check(mut self, skip_code_check: bool) -> Self {
        self.skip_code_check = skip_code_check;
        self
    }

    /// Simulate the amount of gas needed to run a transaction.
    pub async fn simulate(
        &self,
        cosmos: &Cosmos,
        wallet: impl HasAddress,
    ) -> Result<FullSimulateResponse> {
        let sequence = match cosmos.get_base_account(wallet.get_address()).await {
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
        };

        // Deal with account sequence errors, overall relevant issue is: https://phobosfinance.atlassian.net/browse/PERP-283
        //
        // There may be a bug in Cosmos where simulating expects the wrong
        // sequence number. So: we simulate, trying out the suggested sequence
        // number if necessary, and then we broadcast, again trying the sequence
        // number they recommend if necessary.
        //
        // See: https://github.com/cosmos/cosmos-sdk/issues/11597

        Ok(match self.simulate_inner(cosmos, sequence).await {
            Ok(pair) => pair,
            Err(ExpectedSequenceError::RealError(e)) => return Err(e),
            Err(ExpectedSequenceError::NewNumber(x, e)) => {
                log::warn!("Received an account sequence error while simulating a transaction, retrying with new number {x}: {e:?}");
                self.simulate_inner(cosmos, x).await?
            }
        })
    }

    /// Sign transaction, broadcast, wait for it to complete, confirm that it was successful
    /// the gas amount is determined automatically by running a simulation first and padding by a multiplier
    /// the multiplier can by adjusted by calling [Cosmos::set_gas_multiplier]
    pub async fn sign_and_broadcast(&self, cosmos: &Cosmos, wallet: &Wallet) -> Result<TxResponse> {
        let simres = self.simulate(cosmos, wallet).await?;
        self.inner_sign_and_broadcast(
            cosmos,
            wallet,
            simres.body,
            // Gas estimation is not perfect, so we need to adjust it by a multiplier to account for drift
            // Since we're already estimating and padding, the loss of precision from f64 to u64 is negligible
            (simres.gas_used as f64 * cosmos.get_gas_multiplier()) as u64,
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
        let base_account = cosmos.get_base_account(wallet.address()).await?;

        match self
            .sign_and_broadcast_with(
                cosmos,
                wallet,
                base_account.account_number,
                base_account.sequence,
                body.clone(),
                gas_to_request,
            )
            .await
        {
            Ok(res) => Ok(res),
            Err(ExpectedSequenceError::RealError(e)) => Err(e),
            Err(ExpectedSequenceError::NewNumber(x, e)) => {
                log::warn!("Received an account sequence error while broadcasting a transaction, retrying with new number {x}: {e:?}");
                self.sign_and_broadcast_with(
                    cosmos,
                    wallet,
                    base_account.account_number,
                    x,
                    body,
                    gas_to_request,
                )
                .await
                .map_err(|x| x.into())
            }
        }
    }

    fn make_signer_infos(&self, sequence: u64, wallet: Option<&Wallet>) -> Vec<SignerInfo> {
        vec![SignerInfo {
            public_key: Some(cosmos_sdk_proto::Any {
                type_url: "/cosmos.crypto.secp256k1.PubKey".to_owned(),
                value: cosmos_sdk_proto::tendermint::crypto::PublicKey {
                    sum: Some(
                        cosmos_sdk_proto::tendermint::crypto::public_key::Sum::Ed25519(
                            match wallet {
                                None => vec![],
                                Some(wallet) => wallet.public_key_bytes().to_owned(),
                            },
                        ),
                    ),
                }
                .encode_to_vec(),
            }),
            mode_info: Some(ModeInfo {
                sum: Some(
                    cosmos_sdk_proto::cosmos::tx::v1beta1::mode_info::Sum::Single(
                        cosmos_sdk_proto::cosmos::tx::v1beta1::mode_info::Single { mode: 1 },
                    ),
                ),
            }),
            sequence,
        }]
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
        sequence: u64,
    ) -> Result<FullSimulateResponse, ExpectedSequenceError> {
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
                signer_infos: self.make_signer_infos(sequence, None),
            }),
            signatures: vec![vec![]],
            body: Some(body.clone()),
        };

        #[allow(deprecated)]
        let simulate_req = SimulateRequest {
            tx: None,
            tx_bytes: simulate_tx.encode_to_vec(),
        };

        let simres = cosmos.perform_query(None, simulate_req).await;
        // PERP-283: detect account sequence mismatches
        let simres = match simres {
            Ok(simres) => simres.into_inner(),
            Err(PerformQueryError::Tonic(e)) => {
                let is_sequence = get_expected_sequence(e.message());
                let e = anyhow::Error::from(e).context("Unable to simulate transaction");
                return match is_sequence {
                    None => Err(ExpectedSequenceError::RealError(e)),
                    Some(number) => Err(ExpectedSequenceError::NewNumber(number, e)),
                };
            }
            Err(e) => return Err(ExpectedSequenceError::RealError(e.into())),
        };

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
        account_number: u64,
        sequence: u64,
        body: TxBody,
        gas_to_request: u64,
    ) -> Result<TxResponse, ExpectedSequenceError> {
        enum AttemptError {
            Inner(ExpectedSequenceError),
            InsufficientGas(anyhow::Error),
        }
        impl From<anyhow::Error> for AttemptError {
            fn from(e: anyhow::Error) -> Self {
                AttemptError::Inner(e.into())
            }
        }
        let body_ref = &body;
        let retry_with_price = |amount| async move {
            let auth_info = AuthInfo {
                signer_infos: self.make_signer_infos(sequence, Some(wallet)),
                fee: Some(Fee {
                    amount: vec![Coin {
                        denom: cosmos.first_builder.gas_coin.clone(),
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
                chain_id: cosmos.first_builder.chain_id.clone(),
                account_number,
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
                    None,
                    BroadcastTxRequest {
                        tx_bytes: tx.encode_to_vec(),
                        mode: BroadcastMode::Sync as i32,
                    },
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
                let is_sequence = get_expected_sequence(&res.raw_log);
                return Err(AttemptError::Inner(match is_sequence {
                    None => ExpectedSequenceError::RealError(e),
                    Some(number) => ExpectedSequenceError::NewNumber(number, e),
                }));
            };

            log::debug!("Initial BroadcastTxResponse: {res:?}");

            let res = cosmos.wait_for_transaction(res.txhash).await?;
            if !self.skip_code_check && res.code != 0 {
                // We don't do the account sequence mismatch hack work here, once a
                // transaction actually lands on the chain we don't want to ever
                // automatically retry.
                return Err(AttemptError::Inner(ExpectedSequenceError::RealError(
                    anyhow::anyhow!(
                        "Transaction failed with code {}. Raw log: {}",
                        res.code,
                        res.raw_log
                    ),
                )));
            };

            log::debug!("TxResponse: {res:?}");

            Ok(res)
        };

        let attempts = cosmos.get_first_builder().config.gas_price_retry_attempts;
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
            Err(AttemptError::InsufficientGas(e)) => Err(e.into()),
            Err(AttemptError::Inner(e)) => Err(e),
        }
    }
}

pub struct TypedMessage(cosmos_sdk_proto::Any);

impl TypedMessage {
    pub fn new(inner: cosmos_sdk_proto::Any) -> Self {
        TypedMessage(inner)
    }

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

pub trait HasCosmos {
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

/// Returned the expected account sequence mismatch based on an error message, if present
fn get_expected_sequence(message: &str) -> Option<u64> {
    for line in message.lines() {
        if let Some(x) = get_expected_sequence_single(line) {
            return Some(x);
        }
    }
    None
}

fn get_expected_sequence_single(message: &str) -> Option<u64> {
    let s = message.strip_prefix("account sequence mismatch, expected ")?;
    let comma = s.find(',')?;
    s[..comma].parse().ok()
}

/// Either a real error that should be propagated, or a new account sequence number to try
enum ExpectedSequenceError {
    RealError(anyhow::Error),
    NewNumber(u64, anyhow::Error),
}

impl From<anyhow::Error> for ExpectedSequenceError {
    fn from(e: anyhow::Error) -> Self {
        ExpectedSequenceError::RealError(e)
    }
}

impl From<ExpectedSequenceError> for anyhow::Error {
    fn from(e: ExpectedSequenceError) -> Self {
        match e {
            ExpectedSequenceError::RealError(e) => e,
            ExpectedSequenceError::NewNumber(_, e) => e,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_expected_sequence_good() {
        assert_eq!(
            get_expected_sequence("account sequence mismatch, expected 5, got 0"),
            Some(5)
        );
        assert_eq!(
            get_expected_sequence("account sequence mismatch, expected 2, got 7"),
            Some(2)
        );
        assert_eq!(
            get_expected_sequence("account sequence mismatch, expected 20000001, got 7"),
            Some(20000001)
        );
    }

    #[test]
    fn get_expected_sequence_extra_prelude() {
        assert_eq!(
            get_expected_sequence("blah blah blah\n\naccount sequence mismatch, expected 5, got 0"),
            Some(5)
        );
        assert_eq!(
            get_expected_sequence(
                "foajodifjaolkdfjas aiodjfaof\n\n\naccount sequence mismatch, expected 2, got 7"
            ),
            Some(2)
        );
        assert_eq!(
            get_expected_sequence(
                "iiiiiiiiiiiiii\n\naccount sequence mismatch, expected 20000001, got 7"
            ),
            Some(20000001)
        );
    }

    #[test]
    fn get_expected_sequence_bad() {
        assert_eq!(
            get_expected_sequence("Totally different error message"),
            None
        );
        assert_eq!(
            get_expected_sequence("account sequence mismatch, expected XXXXX, got 7"),
            None
        );
    }

    #[test]
    fn gas_estimate_multiplier() {
        let mut cosmos = CosmosBuilder::new_osmosis_testnet();

        // the same as sign_and_broadcast()
        let multiply_estimated_gas = |cosmos: &CosmosBuilder, gas_used: u64| -> u64 {
            (gas_used as f64 * cosmos.config.gas_estimate_multiplier) as u64
        };

        assert_eq!(multiply_estimated_gas(&cosmos, 1234), 1604);
        cosmos.config.gas_estimate_multiplier = 4.2;
        assert_eq!(multiply_estimated_gas(&cosmos, 1234), 5182);
    }
}

pub struct FullSimulateResponse {
    pub body: TxBody,
    pub simres: SimulateResponse,
    pub gas_used: u64,
}
