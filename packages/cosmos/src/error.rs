#![allow(missing_docs)]
//! Error types exposed by this package.

use std::{str::FromStr, sync::Arc};

use bip39::Mnemonic;
use bitcoin::util::bip32::DerivationPath;
use chrono::{DateTime, Utc};

use crate::AddressHrp;

/// Errors that can occur with token factory
#[derive(thiserror::Error, Debug)]
pub enum TokenFactoryError {
    #[error("cosmos-rs does not support tokenfactory for the given chain HRP: {hrp}")]
    Unsupported { hrp: AddressHrp },
}

/// Errors that can occur while working with [crate::Address].
#[derive(thiserror::Error, Debug)]
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

#[derive(thiserror::Error, Debug)]
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
pub enum CosmosBuilderError {
    #[error("Error downloading chain information from {url}: {source:?}")]
    DownloadChainInfo { url: String, source: reqwest::Error },
    #[error("Failed sanity check on Cosmos value:\n{cosmos:?}\n{source:?}")]
    FailedSanityCheck {
        cosmos: crate::Cosmos,
        source: anyhow::Error,
    },
    #[error("Unknown Cosmos network value {network:?}")]
    UnknownCosmosNetwork { network: String },
}

/// Parse errors while interacting with chain data.
#[derive(thiserror::Error, Debug)]
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
