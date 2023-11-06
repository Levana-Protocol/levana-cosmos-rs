use std::{fmt::Display, num::TryFromIntError};

use chrono::{DateTime, Utc};

use crate::Address;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Address(crate::AddressError),
    #[error("{0}")]
    Wallet(crate::WalletError),
    #[error("{0}")]
    WasmCode(crate::WasmCodeError),
    #[error("{0}")]
    Client(crate::ClientError),
    #[error("{0}")]
    Conversion(ConversionError),
}

/// A description of an action, mostly for user-friendly error messages.
#[derive(Debug)]
pub enum Action {
    Instantiate {
        code_id: u64,
    },
    Migrate {
        code_id: u64,
        contract: Address,
    },
    QueryContract {
        contract: Address,
        msg: Option<String>,
    },
}

impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Action::Instantiate { code_id } => write!(f, "instantiate code ID {code_id}"),
            Action::Migrate { code_id, contract } => {
                write!(f, "migration contract {contract} to code ID {code_id}")
            }
            Action::QueryContract {
                contract,
                msg: None,
            } => write!(f, "query contract {contract}"),
            Action::QueryContract {
                contract,
                msg: Some(msg),
            } => write!(f, "query contract {contract}: {msg:?}"),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug)]
pub enum ConversionError {
    #[error("Unable to render JSON while performing {action}. {source:?}")]
    RenderJson {
        action: Action,
        source: serde_json::Error,
    },
    #[error("Invalid timestamp in transaction {txhash}. {source:?}")]
    InvalidTimestamp {
        txhash: String,
        source: chrono::ParseError,
    },
    #[error("Invalid nanos in datetime {datetime}. {source:?}")]
    InvalidNanos {
        datetime: DateTime<Utc>,
        source: TryFromIntError,
    },
    #[error("Unable to parse JSON while performing {action}. {source:?}")]
    ParseJson {
        action: Action,
        source: serde_json::Error,
    },
}

impl From<ConversionError> for Error {
    fn from(e: ConversionError) -> Self {
        Error::Conversion(e)
    }
}
