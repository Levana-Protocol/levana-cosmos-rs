#![allow(missing_docs)]
//! Error types exposed by this package.

use std::{fmt::Display, path::PathBuf, str::FromStr, sync::Arc};

use bip39::Mnemonic;
use bitcoin::util::bip32::DerivationPath;
use chrono::{DateTime, Utc};

use crate::{Address, AddressHrp, CosmosBuilder, TxBuilder};

/// Errors that can occur with token factory
#[derive(thiserror::Error, Debug, Clone)]
pub enum TokenFactoryError {
    #[error("cosmos-rs does not support tokenfactory for the given chain HRP: {hrp}")]
    Unsupported { hrp: AddressHrp },
}

/// Errors that can occur while working with [crate::Address].
#[derive(thiserror::Error, Debug, Clone)]
pub enum AddressError {
    #[error("Invalid bech32 encoding in {address:?}: {source:?}")]
    InvalidBech32 {
        address: String,
        source: bech32::Error,
    },
    #[error("Invalid bech32 variant {variant:?} used in {address:?}, must use regular Bech32")]
    InvalidVariant {
        address: String,
        variant: bech32::Variant,
    },
    #[error("Invalid base32 encoded data in {address:?}: {source:?}")]
    InvalidBase32 {
        address: String,
        source: bech32::Error,
    },
    #[error("Invalid byte count within {address:?}, expected 20 or 32 bytes, received {actual}")]
    InvalidByteCount { address: String, actual: usize },
    #[error("Invalid HRP provided: {hrp:?}")]
    InvalidHrp { hrp: String },
}

/// Errors that can occur while working with [crate::Wallet].

#[derive(thiserror::Error, Debug, Clone)]
pub enum WalletError {
    #[error("Could not get root private key from mnemonic: {source:?}")]
    CouldNotGetRootPrivateKey { source: bitcoin::util::bip32::Error },
    #[error("Could not derive private key using derivation path {derivation_path}: {source:?}")]
    CouldNotDerivePrivateKey {
        derivation_path: Arc<DerivationPath>,
        source: bitcoin::util::bip32::Error,
    },
    #[error("Invalid derivation path {path:?}: {source:?}")]
    InvalidDerivationPath {
        path: String,
        source: <DerivationPath as FromStr>::Err,
    },
    #[error("Invalid seed phrase: {source}")]
    InvalidPhrase { source: <Mnemonic as FromStr>::Err },
}

/// Errors that can occur while building a connection.
#[derive(thiserror::Error, Debug)]
pub enum BuilderError {
    #[error("Error downloading chain information from {url}: {source:?}")]
    DownloadChainInfo { url: String, source: reqwest::Error },
    #[error("Unknown Cosmos network value {network:?}")]
    UnknownCosmosNetwork { network: String },
    #[error("Mismatched chain IDs during sanity check of {grpc_url}. Expected: {expected}. Actual: {actual:?}.")]
    MismatchedChainIds {
        grpc_url: String,
        expected: String,
        actual: Option<String>,
    },
    #[error("Connection sanity check failed: {source:}")]
    SanityQueryFailed { source: QueryError },
}

/// Parse errors while interacting with chain data.
#[derive(thiserror::Error, Debug, Clone)]
pub enum ChainParseError {
    #[error("Could not parse timestamp {timestamp:?} from transaction {txhash}: {source:?}")]
    InvalidTimestamp {
        timestamp: String,
        txhash: String,
        source: <DateTime<Utc> as FromStr>::Err,
    },
    #[error(
        "Invalid instantiate contract address {address:?} from transaction {txhash}: {source}"
    )]
    InvalidInstantiatedContract {
        address: String,
        txhash: String,
        source: AddressError,
    },
    #[error("Invalid code ID {code_id:?} from transaction {txhash}: {source:?}")]
    InvalidCodeId {
        code_id: String,
        txhash: String,
        source: std::num::ParseIntError,
    },
    #[error("No code ID found when expecting a store code response in transaction {txhash}")]
    NoCodeIdFound { txhash: String },
    #[error("No instantiated contract found in transaction {txhash}")]
    NoInstantiatedContractFound { txhash: String },
}

/// An error that occurs while connecting to a Cosmos gRPC endpoint.
///
/// This could be the initial connection or sending a new query.
#[derive(thiserror::Error, Debug, Clone)]
pub enum ConnectionError {
    #[error("Invalid gRPC URL: {grpc_url}: {source:?}")]
    InvalidGrpcUrl {
        grpc_url: Arc<String>,
        source: Arc<tonic::transport::Error>,
    },
    #[error("Unable to configure TLS when connecting to {grpc_url}: {source:?}")]
    TlsConfig {
        grpc_url: Arc<String>,
        source: Arc<tonic::transport::Error>,
    },
    #[error("Sanity check on connection to {grpc_url} failed with gRPC status {source}")]
    SanityCheckFailed {
        grpc_url: Arc<String>,
        source: tonic::Status,
    },
    #[error("Network error occured while performing query to {grpc_url}")]
    QueryFailed { grpc_url: Arc<String> },
    #[error("Timeout hit when querying gRPC endpoint {grpc_url}")]
    TimeoutQuery { grpc_url: Arc<String> },
    #[error("Timeout hit when connecting to gRPC endpoint {grpc_url}")]
    TimeoutConnecting { grpc_url: Arc<String> },
    #[error("Cannot establish connection to {grpc_url}: {source:?}")]
    CannotEstablishConnection {
        grpc_url: Arc<String>,
        source: Arc<tonic::transport::Error>,
    },
}

/// Error while parsing a [crate::ContractAdmin].
#[derive(thiserror::Error, Debug, Clone)]
#[error(
    "Invalid contract admin. Must be 'no-admin', 'sender', or a valid address. Received: {input:?}"
)]
pub struct ContractAdminParseError {
    pub input: String,
}

/// Errors that occur while querying the chain.
#[derive(thiserror::Error, Debug, Clone)]
#[error("On connection to {}, while performing:\n{action}\n{query}\nHeight set to: {height:?}", builder.grpc_url())]
pub struct QueryError {
    pub action: Action,
    pub builder: Arc<CosmosBuilder>,
    pub height: Option<u64>,
    pub query: QueryErrorDetails,
}

/// General errors while interacting with the chain
///
/// This error type is used by the majority of the codebase. The idea is that
/// the other error types will represent "preparation" errors, and this will
/// represent errors during normal interaction.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unable to serialize value to JSON: {0}")]
    JsonSerialize(#[from] serde_json::Error),
    #[error(
        "Unable to deserialize value from JSON while performing: {action}. Parse error: {source}"
    )]
    JsonDeserialize {
        source: serde_json::Error,
        action: Action,
    },
    #[error(transparent)]
    Query(#[from] QueryError),
    #[error("Error parsing data returned from chain: {source}. While performing: {action}")]
    ChainParse {
        source: Box<crate::error::ChainParseError>,
        action: Action,
    },
    #[error("Invalid response from chain: {message}. While performing: {action}")]
    InvalidChainResponse { message: String, action: Action },
    #[error("Timed out waiting for transaction {txhash}")]
    WaitForTransactionTimedOut { txhash: String },
    #[error("Timed out waiting for transaction {txhash} during {action}")]
    WaitForTransactionTimedOutWhile { txhash: String, action: Action },
    #[error("Unable to load WASM code from {}: {source}", path.display())]
    LoadingWasmFromFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Transaction failed with code {code} and log: {raw_log}. Action: {action}.")]
    TransactionFailed {
        code: u32,
        raw_log: String,
        action: Action,
    },
}

/// The action being performed when an error occurred.
#[derive(Debug, Clone)]
pub enum Action {
    GetBaseAccount(Address),
    QueryAllBalances(Address),
    QueryGranterGrants(Address),
    CodeInfo(u64),
    GetTransactionBody(String),
    ListTransactionsFor(Address),
    GetBlock(i64),
    GetLatestBlock,
    Simulate(TxBuilder),
    Broadcast(TxBuilder),
    RawQuery {
        contract: Address,
        key: StringOrBytes,
    },
    SmartQuery {
        contract: Address,
        message: StringOrBytes,
    },
    ContractInfo(Address),
    ContractHistory(Address),
    GetEarliestBlock,
    WaitForTransaction(String),
}

impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Action::GetBaseAccount(address) => write!(f, "get base account {address}"),
            Action::QueryAllBalances(address) => write!(f, "query all balances for {address}"),
            Action::QueryGranterGrants(address) => write!(f, "query granter grants for {address}"),
            Action::CodeInfo(code_id) => write!(f, "get code info for code ID {code_id}"),
            Action::GetTransactionBody(txhash) => write!(f, "get transaction {txhash}"),
            Action::ListTransactionsFor(address) => write!(f, "list transactions for {address}"),
            Action::GetBlock(height) => write!(f, "get block {height}"),
            Action::GetLatestBlock => f.write_str("get latest block"),
            Action::Simulate(txbuilder) => write!(f, "simulating transaction: {txbuilder}"),
            Action::Broadcast(txbuilder) => write!(f, "broadcasting transaction: {txbuilder}"),
            Action::RawQuery { contract, key } => {
                write!(f, "raw query contract {contract} with key: {key}")
            }
            Action::SmartQuery { contract, message } => {
                write!(f, "smart query contract {contract} with message: {message}")
            }
            Action::ContractInfo(address) => write!(f, "contract info for {address}"),
            Action::ContractHistory(address) => write!(f, "contract history for {address}"),
            Action::GetEarliestBlock => f.write_str("get earliest block"),
            Action::WaitForTransaction(txhash) => write!(f, "wait for transaction {txhash}"),
        }
    }
}

/// A helper type to display either as UTF8 data or the underlying bytes
#[derive(Debug, Clone)]
pub struct StringOrBytes(pub Vec<u8>);

impl From<Vec<u8>> for StringOrBytes {
    fn from(value: Vec<u8>) -> Self {
        StringOrBytes(value)
    }
}

impl Display for StringOrBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match std::str::from_utf8(&self.0) {
            Ok(s) => f.write_str(s),
            Err(_) => write!(f, "{:?}", self.0),
        }
    }
}

/// The lower-level details of how a query failed.
///
/// This error type should generally be wrapped up in [QueryError] to provide
/// additional context.
#[derive(thiserror::Error, Debug, Clone)]
pub enum QueryErrorDetails {
    #[error("Unknown gRPC status returned: {0:?}")]
    Unknown(tonic::Status),
    #[error("Timed out getting new connection")]
    ConnectionTimeout,
    #[error("Query timed out")]
    QueryTimeout,
    #[error("{0}")]
    ConnectionError(ConnectionError),
    #[error("Not found returned from chain: {0}")]
    NotFound(String),
    #[error("Cosmos SDK error code {error_code} returned: {source:?}")]
    CosmosSdk {
        error_code: u32,
        source: tonic::Status,
    },
    #[error("Error parsing message into expected type: {0:?}")]
    JsonParseError(tonic::Status),
    #[error("{0:?}")]
    FailedToExecute(tonic::Status),
    #[error(
        "Requested height not available, lowest height reported: {lowest_height:?}. {source:?}"
    )]
    HeightNotAvailable {
        lowest_height: Option<i64>,
        source: tonic::Status,
    },
}

pub(crate) enum QueryErrorCategory {
    /// Should retry, kill the connection
    NetworkIssue,
    /// Don't retry, connection is fine
    ConnectionIsFine,
    /// No idea, make a test query and try again
    Unsure,
}

impl QueryErrorDetails {
    /// Indicates that the error may be transient and deserves a retry.
    pub(crate) fn error_category(&self) -> QueryErrorCategory {
        use QueryErrorCategory::*;
        match self {
            // Not sure, so give it a retry
            QueryErrorDetails::Unknown(_) => Unsure,
            // Yup, may as well try to connect again.
            QueryErrorDetails::ConnectionTimeout => NetworkIssue,
            // Same here, maybe it was a bad connection.
            QueryErrorDetails::QueryTimeout => NetworkIssue,
            // Also possibly a bad connection
            QueryErrorDetails::ConnectionError(_) => NetworkIssue,
            QueryErrorDetails::NotFound(_) => ConnectionIsFine,
            QueryErrorDetails::CosmosSdk { .. } => ConnectionIsFine,
            QueryErrorDetails::JsonParseError(_) => ConnectionIsFine,
            QueryErrorDetails::FailedToExecute(_) => ConnectionIsFine,
            // Interesting case here... maybe we need to treat it as a network
            // issue so we retry with a fallback node. Or maybe apps that need
            // that specific case handled should implement their own fallback
            // logic.
            QueryErrorDetails::HeightNotAvailable { .. } => ConnectionIsFine,
        }
    }

    pub(crate) fn from_tonic_status(err: tonic::Status) -> QueryErrorDetails {
        // For some reason, it looks like Osmosis testnet isn't returning a NotFound. Ugly workaround...
        if err.message().contains("not found") || err.code() == tonic::Code::NotFound {
            return QueryErrorDetails::NotFound(err.message().to_owned());
        }

        if let Some(error_code) = extract_cosmos_sdk_error_code(err.message()) {
            return QueryErrorDetails::CosmosSdk {
                error_code,
                source: err,
            };
        }

        if err.message().starts_with("Error parsing into type ") {
            return QueryErrorDetails::JsonParseError(err);
        }

        if err.message().starts_with("failed to execute message;") {
            return QueryErrorDetails::FailedToExecute(err);
        }

        if let Some(lowest_height) = get_lowest_height(err.message()) {
            return QueryErrorDetails::HeightNotAvailable {
                lowest_height: Some(lowest_height),
                source: err,
            };
        }

        QueryErrorDetails::Unknown(err)
    }
}

fn get_lowest_height(message: &str) -> Option<i64> {
    let per_needle = |needle: &str| {
        let trimmed = message.split(needle).nth(1)?.trim();
        let stripped = trimmed.strip_suffix(')').unwrap_or(trimmed);
        stripped.parse().ok()
    };
    for needle in ["lowest height is", "base height: "] {
        if let Some(x) = per_needle(needle) {
            return Some(x);
        }
    }
    None
}

fn extract_cosmos_sdk_error_code(message: &str) -> Option<u32> {
    message
        .strip_prefix("codespace wasm code ")?
        .split_once(':')?
        .0
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_success() {
        assert_eq!(
            extract_cosmos_sdk_error_code("codespace wasm code 9: query wasm contract failed: Error parsing into type levana_perpswap_cosmos_msg::contracts::market::entry::QueryMsg: unknown variant `{\"invalid_request\":{}}`, expected one of `version`, `status`, `spot_price`, `spot_price_history`, `oracle_price`, `positions`, `limit_order`, `limit_orders`, `closed_position_history`, `nft_proxy`, `liquidity_token_proxy`, `trade_history_summary`, `position_action_history`, `trader_action_history`, `lp_action_history`, `limit_order_history`, `lp_info`, `delta_neutrality_fee`, `price_would_trigger`"),
            Some(9)
        );
    }

    #[test]
    fn test_extract_fail() {
        assert_eq!(
            extract_cosmos_sdk_error_code("invalid Bech32 prefix; expected osmo, got inj"),
            None
        );
        assert_eq!(
            extract_cosmos_sdk_error_code("Error parsing into type levana_perpswap_cosmos_msg::contracts::factory::entry::QueryMsg: unknown variant `{\"invalid_request\":{}}`, expected one of `version`, `markets`, `market_info`, `addr_is_contract`, `factory_owner`, `shutdown_status`, `code_ids`: query wasm contract failed"),
            None

        );
    }
}
