#![allow(missing_docs)]
//! Error types exposed by this package.

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
