#![allow(missing_docs)]
//! Error types exposed by this package.

use std::{fmt::Display, str::FromStr, sync::Arc};

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
    #[error("Failed sanity check on Cosmos value:\n{cosmos:?}\n{source:?}")]
    FailedSanityCheck {
        cosmos: crate::Cosmos,
        source: anyhow::Error,
    },
    #[error("Unknown Cosmos network value {network:?}")]
    UnknownCosmosNetwork { network: String },
    #[error("Mismatched chain IDs during sanity check of {grpc_url}. Expected: {expected}. Actual: {actual}.")]
    MismatchedChainIds {
        grpc_url: String,
        expected: String,
        actual: String,
    },
    #[error("Basic query to {grpc_url} failed during sanity check: {source:?}")]
    SanityQueryFailed {
        grpc_url: String,
        source: anyhow::Error,
    },
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
        grpc_url: String,
        source: Arc<tonic::transport::Error>,
    },
    #[error("Unable to configure TLS when connecting to {grpc_url}: {source:?}")]
    TlsConfig {
        grpc_url: String,
        source: Arc<tonic::transport::Error>,
    },
    #[error("Sanity check on connection to {grpc_url} failed with gRPC status {source}")]
    SanityCheckFailed {
        grpc_url: String,
        source: tonic::Status,
    },
    #[error("Timeout hit when querying gRPC endpoint {grpc_url}")]
    TimeoutQuery { grpc_url: String },
    #[error("Timeout hit when connecting to gRPC endpoint {grpc_url}")]
    TimeoutConnecting { grpc_url: String },
    #[error("Cannot establish connection to {grpc_url}: {source:?}")]
    CannotEstablishConnection {
        grpc_url: String,
        source: Arc<tonic::transport::Error>,
    },
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
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {}

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
    #[error("Error response from gRPC endpoint: {0:?}")]
    Tonic(tonic::Status),
    #[error("Timed out getting new connection")]
    ConnectionTimeout,
    #[error("Query timed out")]
    QueryTimeout,
    #[error("{0}")]
    ConnectionError(ConnectionError),
}

impl QueryErrorDetails {
    /// Indicates that the error may be transient and deserves a retry.
    pub(crate) fn should_be_retried(&self) -> bool {
        todo!()
    }
}
