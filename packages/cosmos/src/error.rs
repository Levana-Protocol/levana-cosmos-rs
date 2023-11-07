#![allow(missing_docs)]
//! Error types exposed by this package.

use crate::AddressHrp;

/// Errors that can occur with token factory
#[derive(thiserror::Error, Debug)]
pub enum TokenFactoryError {
    #[error("cosmos-rs does not support tokenfactory for the given chain HRP: {hrp}")]
    Unsupported { hrp: AddressHrp },
}
