use std::{sync::Arc, time::Duration};

use crate::{
    gas_price::{GasPriceMethod, DEFAULT_GAS_PRICE},
    AddressHrp,
};

/// Used to build a [crate::Cosmos].
#[derive(Clone, Debug)]
pub struct CosmosBuilder {
    grpc_url: Arc<String>,
    grpc_fallback_urls: Vec<Arc<String>>,
    chain_id: String,
    gas_coin: String,
    hrp: AddressHrp,

    // Values with defaults
    gas_estimate_multiplier: Option<f64>,
    gas_price_method: Option<GasPriceMethod>,
    gas_price_retry_attempts: Option<u64>,
    transaction_attempts: Option<usize>,
    referer_header: Option<String>,
    connection_count: Option<usize>,
    connection_timeout: Option<Duration>,
    idle_timeout_seconds: Option<u32>,
    query_timeout_seconds: Option<u32>,
    query_retries: Option<u32>,
    block_lag_allowed: Option<u32>,
    latest_block_age_allowed: Option<Duration>,
    fallback_timeout: Option<Duration>,
    pub(crate) chain_paused_method: ChainPausedMethod,
}

impl CosmosBuilder {
    /// Create a new [CosmosBuilder] with default options where possible.
    pub fn new(
        chain_id: impl Into<String>,
        gas_coin: impl Into<String>,
        hrp: AddressHrp,
        grpc_url: impl Into<String>,
    ) -> CosmosBuilder {
        Self {
            grpc_url: Arc::new(grpc_url.into()),
            grpc_fallback_urls: vec![],
            chain_id: chain_id.into(),
            gas_coin: gas_coin.into(),
            hrp,
            gas_estimate_multiplier: None,
            gas_price_method: None,
            gas_price_retry_attempts: None,
            transaction_attempts: None,
            referer_header: None,
            connection_count: None,
            connection_timeout: None,
            idle_timeout_seconds: None,
            query_timeout_seconds: None,
            query_retries: None,
            block_lag_allowed: None,
            latest_block_age_allowed: None,
            fallback_timeout: None,
            chain_paused_method: ChainPausedMethod::None,
        }
    }

    /// gRPC endpoint to connect to
    ///
    /// This is the primary endpoint, not any fallbacks provided
    pub fn grpc_url(&self) -> &str {
        self.grpc_url.as_ref()
    }

    pub(crate) fn grpc_url_arc(&self) -> &Arc<String> {
        &self.grpc_url
    }

    /// See [Self::grpc_url]
    pub fn set_grpc_url(&mut self, grpc_url: impl Into<String>) {
        self.grpc_url = grpc_url.into().into();
    }

    /// Add a fallback gRPC URL
    pub fn add_grpc_fallback_url(&mut self, url: impl Into<String>) {
        self.grpc_fallback_urls.push(url.into().into());
    }

    pub(crate) fn grpc_fallback_urls(&self) -> &Vec<Arc<String>> {
        &self.grpc_fallback_urls
    }

    /// Chain ID we want to communicate with
    pub fn chain_id(&self) -> &str {
        self.chain_id.as_ref()
    }

    /// See [Self::chain_id]
    pub fn set_chain_id(&mut self, chain_id: String) {
        self.chain_id = chain_id;
    }

    /// Native coin used for gas payments
    pub fn gas_coin(&self) -> &str {
        self.gas_coin.as_ref()
    }

    /// See [Self::gas_coin]
    pub fn set_gas_coin(&mut self, gas_coin: String) {
        self.gas_coin = gas_coin;
    }

    /// Human-readable part (HRP) of chain addresses
    pub fn hrp(&self) -> AddressHrp {
        self.hrp
    }

    /// See [Self::hrp]
    pub fn set_hrp(&mut self, hrp: AddressHrp) {
        self.hrp = hrp;
    }

    /// Add a multiplier to the gas estimate to account for any gas fluctuations
    ///
    /// Defaults to 1.3 following cosmjs and osmojs.
    pub fn gas_estimate_multiplier(&self) -> f64 {
        // same amount that CosmosJS uses: https://github.com/cosmos/cosmjs/blob/e8e65aa0c145616ccb58625c32bffe08b46ff574/packages/cosmwasm-stargate/src/signingcosmwasmclient.ts#L550
        // and OsmoJS too: https://github.com/osmosis-labs/osmojs/blob/bacb2fc322abc3d438581f5dce049f5ae467059d/packages/osmojs/src/utils/gas/estimation.ts#L10
        self.gas_estimate_multiplier.unwrap_or(1.3)
    }

    /// See [Self::gas_estimate_multiplier]
    pub fn set_gas_estimate_multiplier(&mut self, gas_estimate_multiplier: Option<f64>) {
        self.gas_estimate_multiplier = gas_estimate_multiplier;
    }

    /// Set the lower and upper bounds of gas price.
    pub fn set_gas_price(&mut self, low: f64, high: f64) {
        self.gas_price_method = Some(GasPriceMethod::new_static(low, high));
    }

    pub(crate) fn set_gas_price_method(&mut self, method: GasPriceMethod) {
        self.gas_price_method = Some(method);
    }

    pub(crate) fn gas_price(&self) -> (f64, f64) {
        self.gas_price_method
            .as_ref()
            .map_or(DEFAULT_GAS_PRICE, GasPriceMethod::pair)
    }

    /// How many retries at different gas prices should we try before using high
    ///
    /// Default: 3
    ///
    /// If this is 0, we'll always go straight to high. 1 means we'll try the
    /// low and the high. 2 means we'll try low, midpoint, and high. And so on
    /// from there.
    pub fn gas_price_retry_attempts(&self) -> u64 {
        self.gas_price_retry_attempts.unwrap_or(3)
    }

    /// See [Self::gas_price_retry_attempts]
    pub fn set_gas_price_retry_attempts(&mut self, gas_price_retry_attempts: Option<u64>) {
        self.gas_price_retry_attempts = gas_price_retry_attempts;
    }

    /// How many attempts to give a transaction before giving up
    ///
    /// Default: 30
    pub fn transaction_attempts(&self) -> usize {
        self.transaction_attempts.unwrap_or(30)
    }

    /// See [Self::transaction_attempts]
    pub fn set_transaction_attempts(&mut self, transaction_attempts: Option<usize>) {
        self.transaction_attempts = transaction_attempts;
    }

    /// Referrer header sent to the server
    pub fn referer_header(&self) -> Option<&str> {
        self.referer_header.as_deref()
    }

    /// See [Self::referer_header]
    pub fn set_referer_header(&mut self, referer_header: Option<String>) {
        self.referer_header = referer_header;
    }

    /// The maximum number of connections allowed
    ///
    /// Defaults to 10
    pub fn connection_count(&self) -> usize {
        self.connection_count.unwrap_or(10)
    }

    /// See [Self::connection_count]
    pub fn set_connection_count(&mut self, connection_count: Option<usize>) {
        self.connection_count = connection_count;
    }

    /// Sets the duration to wait for a connection.
    ///
    /// Defaults to 5 seconds
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
            .unwrap_or_else(|| Duration::from_secs(5))
    }

    /// See [Self::connection_timeout]
    pub fn set_connection_timeout(&mut self, connection_timeout: Option<Duration>) {
        self.connection_timeout = connection_timeout;
    }

    /// Sets the number of seconds before an idle connection is reaped
    ///
    /// Defaults to 20 seconds
    pub fn idle_timeout_seconds(&self) -> u32 {
        self.idle_timeout_seconds.unwrap_or(20)
    }

    /// See [Self::idle_timeout_seconds]
    pub fn set_idle_timeout_seconds(&mut self, idle_timeout_seconds: Option<u32>) {
        self.idle_timeout_seconds = idle_timeout_seconds;
    }

    /// Sets the number of seconds before timing out a gRPC query
    ///
    /// Defaults to 5 seconds
    pub fn query_timeout_seconds(&self) -> u32 {
        self.query_timeout_seconds.unwrap_or(5)
    }

    /// See [Self::query_timeout_seconds]
    pub fn set_query_timeout_seconds(&mut self, query_timeout_seconds: Option<u32>) {
        self.query_timeout_seconds = query_timeout_seconds;
    }

    /// Number of attempts to make at a query before giving up.
    ///
    /// Only retries if there is a tonic-level error.
    ///
    /// Defaults to 3
    pub fn query_retries(&self) -> u32 {
        self.query_retries.unwrap_or(3)
    }

    /// See [Self::query_retries]
    pub fn set_query_retries(&mut self, query_retries: Option<u32>) {
        self.query_retries = query_retries;
    }

    /// How many blocks a response is allowed to lag.
    ///
    /// Defaults to 10
    ///
    /// This is intended to detect when one of the nodes in a load balancer has
    /// stopped syncing while others are making progress.
    pub fn block_lag_allowed(&self) -> u32 {
        self.block_lag_allowed.unwrap_or(10)
    }

    /// See [Self::block_lag_allowed]
    pub fn set_block_lag_allowed(&mut self, block_lag_allowed: Option<u32>) {
        self.block_lag_allowed = block_lag_allowed;
    }

    /// How long before we expect to see a new block
    ///
    /// Defaults to 60 seconds
    ///
    /// If we go this amount of time without seeing a new block, queries will
    /// fail on the assumption that they are getting stale data.
    pub fn latest_block_age_allowed(&self) -> Duration {
        self.latest_block_age_allowed
            .unwrap_or_else(|| Duration::from_secs(60))
    }

    /// See [Self::latest_block_age_allowed]
    pub fn set_latest_block_age_allowed(&mut self, latest_block_age_allowed: Option<Duration>) {
        self.latest_block_age_allowed = latest_block_age_allowed;
    }

    /// How long we allow a fallback connection to last before timing out.
    ///
    /// Defaults to 5 minutes.
    ///
    /// This forces systems to try to go back to the primary endpoint regularly.
    pub fn fallback_timeout(&self) -> Duration {
        self.fallback_timeout
            .unwrap_or_else(|| Duration::from_secs(300))
    }

    /// See [Self::fallback_timeout]
    pub fn set_fallback_timeout(&mut self, fallback_timeout: Option<Duration>) {
        self.fallback_timeout = fallback_timeout;
    }

    pub(crate) fn set_osmosis_mainnet_chain_paused(&mut self) {
        self.chain_paused_method = ChainPausedMethod::OsmosisMainnet;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ChainPausedMethod {
    None,
    OsmosisMainnet,
}
