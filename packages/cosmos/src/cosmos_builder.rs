use std::time::Duration;

use crate::AddressHrp;

/// Used to build a [crate::Cosmos].
#[derive(Clone, Debug)]
pub struct CosmosBuilder {
    grpc_url: String,
    chain_id: String,
    gas_coin: String,
    hrp: AddressHrp,

    // Values with defaults
    gas_estimate_multiplier: Option<f64>,
    gas_price_low: Option<f64>,
    gas_price_high: Option<f64>,
    gas_price_retry_attempts: Option<u64>,
    transaction_attempts: Option<usize>,
    referer_header: Option<String>,
    connection_count: Option<u32>,
    connection_timeout: Option<Duration>,
    retry_connection: Option<bool>,
    idle_timeout_seconds: Option<u32>,
    query_timeout_seconds: Option<u32>,
    query_retries: Option<u32>,
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
            grpc_url: grpc_url.into(),
            chain_id: chain_id.into(),
            gas_coin: gas_coin.into(),
            hrp,
            gas_estimate_multiplier: None,
            gas_price_low: None,
            gas_price_high: None,
            gas_price_retry_attempts: None,
            transaction_attempts: None,
            referer_header: None,
            connection_count: None,
            connection_timeout: None,
            retry_connection: None,
            idle_timeout_seconds: None,
            query_timeout_seconds: None,
            query_retries: None,
        }
    }

    /// gRPC endpoint to connect to
    pub fn grpc_url(&self) -> &str {
        self.grpc_url.as_ref()
    }

    /// See [Self::grpc_url]
    pub fn set_grpc_url(&mut self, grpc_url: impl Into<String>) {
        self.grpc_url = grpc_url.into();
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

    /// Amount of gas coin to send per unit of gas, at the low end.
    ///
    /// Default: 0.02
    pub fn gas_price_low(&self) -> f64 {
        self.gas_price_low.unwrap_or(0.02)
    }

    /// See [Self::gas_price_low]
    pub fn set_gas_price_low(&mut self, gas_price_low: Option<f64>) {
        self.gas_price_low = gas_price_low;
    }

    /// Amount of gas coin to send per unit of gas, at the high end.
    ///
    /// Default: 0.03
    pub fn gas_price_high(&self) -> f64 {
        self.gas_price_high.unwrap_or(0.03)
    }

    /// See [Self::gas_price_high]
    pub fn set_gas_price_high(&mut self, gas_price_high: Option<f64>) {
        self.gas_price_high = gas_price_high;
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

    /// Set the number of bb8 connections
    pub fn connection_count(&self) -> Option<u32> {
        self.connection_count
    }

    /// See [Self::connection_count]
    pub fn set_connection_count(&mut self, connection_count: Option<u32>) {
        self.connection_count = connection_count;
    }

    /// Sets the duration to wait for a connection.
    ///
    /// Defaults to 5 seconds
    ///
    /// See [bb8::Builder::connection_timeout]
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
            .unwrap_or_else(|| Duration::from_secs(5))
    }

    /// See [Self::connection_timeout]
    pub fn set_connection_timeout(&mut self, connection_timeout: Option<Duration>) {
        self.connection_timeout = connection_timeout;
    }

    /// See [bb8::Builder::retry_connection]
    pub fn retry_connection(&self) -> Option<bool> {
        self.retry_connection
    }

    /// See [Self::retry_connection]
    pub fn set_retry_connection(&mut self, retry_connection: Option<bool>) {
        self.retry_connection = retry_connection;
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
}
