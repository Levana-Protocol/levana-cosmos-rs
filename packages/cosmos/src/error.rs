#![allow(missing_docs)]
//! Error types exposed by this package.

use std::{fmt::Display, path::PathBuf, str::FromStr, sync::Arc, time::Duration};

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
    #[error(transparent)]
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
#[error(
    "On connection to {grpc_url}, while performing:\n{action}\n{query}\nHeight set to: {height:?}\n{node_health}"
)]
pub struct QueryError {
    pub action: Action,
    pub builder: Arc<CosmosBuilder>,
    pub height: Option<u64>,
    pub query: QueryErrorDetails,
    pub grpc_url: Arc<String>,
    pub node_health: NodeHealthReport,
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
    #[error("Transaction failed ({grpc_url}) during {stage} with {code} and log: {raw_log}. Action: {action}.")]
    TransactionFailed {
        code: CosmosSdkError,
        raw_log: String,
        action: Arc<Action>,
        grpc_url: Arc<String>,
        stage: TransactionStage,
    },
    #[error(transparent)]
    Connection(#[from] ConnectionError),
}

#[derive(Debug)]
pub enum TransactionStage {
    Broadcast,
    Wait,
}

impl Display for TransactionStage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            TransactionStage::Broadcast => "broadcast",
            TransactionStage::Wait => "wait",
        })
    }
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
    SanityCheck,
    OsmosisEpochsInfo,
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
            Action::SanityCheck => f.write_str("sanity check"),
            Action::OsmosisEpochsInfo => f.write_str("get Osmosis epochs info"),
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
    #[error("Query timed out")]
    QueryTimeout,
    #[error(transparent)]
    ConnectionError(ConnectionError),
    #[error("Not found returned from chain: {0}")]
    NotFound(String),
    #[error("Cosmos SDK error code {error_code} returned: {source:?}")]
    CosmosSdk {
        error_code: CosmosSdkError,
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
    #[error("Error querying server, received HTTP status code {status}. {source:?}")]
    Unavailable {
        source: tonic::Status,
        status: reqwest::StatusCode,
    },
    #[error("Server does not implement expected services, it may not be a Cosmos gRPC endpoint. {source}")]
    Unimplemented { source: tonic::Status },
    #[error("Transport error with gRPC endpoint. {source}")]
    TransportError { source: tonic::Status },
    #[error("Block lag detected. Previously saw {old_height}, but just received {new_height}. Allowed lag is {block_lag_allowed}.")]
    BlocksLagDetected {
        old_height: i64,
        new_height: i64,
        block_lag_allowed: u32,
    },
    #[error("No new block time found in {}s ({}s allowed). Old height: {old_height}. New height: {new_height}.", age.as_secs(), age_allowed.as_secs())]
    NoNewBlockFound {
        age: Duration,
        age_allowed: Duration,
        old_height: i64,
        new_height: i64,
    },
    #[error("Account sequence mismatch: {0}")]
    AccountSequenceMismatch(tonic::Status),
}

/// Different known Cosmos SDK error codes
///
/// We can expand this over time, just including the most common ones for now
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CosmosSdkError {
    /// Code 4
    Unauthorized,
    /// Code 5
    InsufficientFunds,
    /// Code 11
    OutOfGas,
    /// Code 13
    InsufficientFee,
    /// Code 19
    TxInMempool,
    /// Code 21
    TxTooLarge,
    /// Code 28
    InvalidChainId,
    /// Code 30
    TxTimeoutHeight,
    /// Code 32
    IncorrectAccountSequence,
    /// Some other error code
    Other(u32),
}

impl Display for CosmosSdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CosmosSdkError::Unauthorized => f.write_str("unauthorized (4)"),
            CosmosSdkError::InsufficientFunds => f.write_str("insufficient funds (5)"),
            CosmosSdkError::OutOfGas => f.write_str("out of gas (11)"),
            CosmosSdkError::InsufficientFee => f.write_str("insufficient fee (13)"),
            CosmosSdkError::TxInMempool => f.write_str("tx already in mempool (19)"),
            CosmosSdkError::TxTooLarge => f.write_str("tx too large (21)"),
            CosmosSdkError::InvalidChainId => f.write_str("invalid chain ID (28)"),
            CosmosSdkError::TxTimeoutHeight => f.write_str("tx timeout height (30)"),
            CosmosSdkError::IncorrectAccountSequence => {
                f.write_str("incorrect account sequence (32)")
            }
            CosmosSdkError::Other(code) => write!(f, "Cosmos SDK error {code}"),
        }
    }
}

impl From<u32> for CosmosSdkError {
    fn from(value: u32) -> Self {
        match value {
            4 => Self::Unauthorized,
            5 => Self::InsufficientFunds,
            11 => Self::OutOfGas,
            13 => Self::InsufficientFee,
            19 => Self::TxInMempool,
            21 => Self::TxTooLarge,
            28 => Self::InvalidChainId,
            30 => Self::TxTimeoutHeight,
            32 => Self::IncorrectAccountSequence,
            _ => Self::Other(value),
        }
    }
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
            // Same here, maybe it was a bad connection.
            QueryErrorDetails::QueryTimeout => NetworkIssue,
            // Also possibly a bad connection
            QueryErrorDetails::ConnectionError(_) => NetworkIssue,
            QueryErrorDetails::NotFound(_) => ConnectionIsFine,
            QueryErrorDetails::CosmosSdk { error_code, .. } => {
                match *error_code {
                    // tx already in mempool usually indicates some kind of a
                    // node sync issue is occurring, where the node isn't seeing
                    // new blocks already containing the transaction/sequence
                    // number.
                    CosmosSdkError::TxInMempool => NetworkIssue,
                    // Similar for account sequence errors
                    CosmosSdkError::IncorrectAccountSequence => NetworkIssue,
                    // Invalid chain ID, we should try a different node if possible
                    CosmosSdkError::InvalidChainId => NetworkIssue,
                    _ => ConnectionIsFine,
                }
            }
            QueryErrorDetails::JsonParseError(_) => ConnectionIsFine,
            QueryErrorDetails::FailedToExecute(_) => ConnectionIsFine,
            // Interesting case here... maybe we need to treat it as a network
            // issue so we retry with a fallback node. Or maybe apps that need
            // that specific case handled should implement their own fallback
            // logic.
            QueryErrorDetails::HeightNotAvailable { .. } => ConnectionIsFine,
            QueryErrorDetails::Unavailable { .. } => NetworkIssue,
            QueryErrorDetails::Unimplemented { .. } => NetworkIssue,
            QueryErrorDetails::TransportError { .. } => NetworkIssue,
            QueryErrorDetails::BlocksLagDetected { .. } => NetworkIssue,
            QueryErrorDetails::NoNewBlockFound { .. } => NetworkIssue,
            // Same logic as CosmosSdk IncorrectAccountSequence above
            QueryErrorDetails::AccountSequenceMismatch { .. } => NetworkIssue,
        }
    }

    pub(crate) fn from_tonic_status(err: tonic::Status) -> QueryErrorDetails {
        // For some reason, it looks like Osmosis testnet isn't returning a NotFound. Ugly workaround...
        if err.message().contains("not found") || err.code() == tonic::Code::NotFound {
            return QueryErrorDetails::NotFound(err.message().to_owned());
        }

        if err.code() == tonic::Code::Unavailable {
            let http = err.clone().to_http();
            return QueryErrorDetails::Unavailable {
                source: err,
                status: http.status(),
            };
        }

        if err.code() == tonic::Code::Unimplemented {
            return QueryErrorDetails::Unimplemented { source: err };
        }

        if let Some(source) = std::error::Error::source(&err) {
            if source.downcast_ref::<tonic::transport::Error>().is_some() {
                return QueryErrorDetails::TransportError { source: err };
            }
        }

        if let Some(error_code) = extract_cosmos_sdk_error_code(err.message()) {
            return QueryErrorDetails::CosmosSdk {
                error_code: CosmosSdkError::from(error_code),
                source: err,
            };
        }

        if err.message().starts_with("Error parsing into type ") {
            return QueryErrorDetails::JsonParseError(err);
        }

        if err.message().starts_with("failed to execute message;") {
            return QueryErrorDetails::FailedToExecute(err);
        }

        // This seems like a duplicate of Cosmos SDK error code 32. However,
        // this sometimes happens during the simulate step instead of broadcast,
        // in which case we don't get the error code. In theory, we could simply
        // generate a 32 error code value, but keeping it as a separate variant
        // just in case we need to distinguish the cases.
        if err.message().starts_with("account sequence mismatch") {
            return QueryErrorDetails::AccountSequenceMismatch(err);
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

#[derive(Clone, Debug)]
pub struct NodeHealthReport {
    pub nodes: Vec<SingleNodeHealthReport>,
}

#[derive(Clone, Debug)]
pub struct SingleNodeHealthReport {
    pub grpc_url: Arc<String>,
    pub is_fallback: bool,
    pub is_healthy: bool,
    pub last_error: Option<LastNodeError>,
}

#[derive(Clone, Debug)]
pub struct LastNodeError {
    pub timestamp: DateTime<Utc>,
    pub age: std::time::Duration,
    pub error: Arc<String>,
}

impl Display for NodeHealthReport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for node in &self.nodes {
            writeln!(f, "{node}")?;
        }
        Ok(())
    }
}

impl Display for SingleNodeHealthReport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Health report for {}. Fallback: {}. Healthy: {}. ",
            self.grpc_url, self.is_fallback, self.is_healthy
        )?;
        match &self.last_error {
            None => write!(f, "No errors")?,
            Some(LastNodeError {
                timestamp,
                age,
                error,
            }) => write!(f, "Last error: {timestamp} ({age:?}): {error}")?,
        }
        Ok(())
    }
}
