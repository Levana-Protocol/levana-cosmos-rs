use chrono::{DateTime, Utc};
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;

use crate::{codeid::strip_quotes, error::ChainParseError, Address};

/// Extension trait to add some helper methods to [TxResponse].
pub trait TxResponseExt {
    /// Parse the timestamp of this transaction.
    fn parse_timestamp(&self) -> Result<DateTime<Utc>, ChainParseError>;

    /// Return the addresses of all instantiated contracts in this transaction.
    fn parse_instantiated_contracts(&self) -> Result<Vec<Address>, ChainParseError>;

    /// Return the instantiated contract address in this transaction
    fn parse_first_instantiated_contract(&self) -> Result<Address, ChainParseError>;

    /// Return the code IDs of any stored code in this transaction
    fn parse_stored_code_ids(&self) -> Result<Vec<u64>, ChainParseError>;

    /// Return the first code ID stored in this transaction
    fn parse_first_stored_code_id(&self) -> Result<u64, ChainParseError>;
}

impl TxResponseExt for TxResponse {
    fn parse_timestamp(&self) -> Result<DateTime<Utc>, ChainParseError> {
        self.timestamp
            .parse()
            .map_err(|source| ChainParseError::InvalidTimestamp {
                timestamp: self.timestamp.clone(),
                txhash: self.txhash.clone(),
                source,
            })
    }

    fn parse_instantiated_contracts(&self) -> Result<Vec<Address>, ChainParseError> {
        let mut addrs = vec![];

        for log in &self.logs {
            for event in &log.events {
                if event.r#type == "instantiate"
                    || event.r#type == "cosmwasm.wasm.v1.EventContractInstantiated"
                {
                    for attr in &event.attributes {
                        if attr.key == "_contract_address" || attr.key == "contract_address" {
                            let address = strip_quotes(&attr.value);
                            let address: Address = address.parse().map_err(|source| {
                                ChainParseError::InvalidInstantiatedContract {
                                    address: address.to_owned(),
                                    txhash: self.txhash.clone(),
                                    source,
                                }
                            })?;
                            addrs.push(address);
                        }
                    }
                }
            }
        }

        Ok(addrs)
    }

    fn parse_first_instantiated_contract(&self) -> Result<Address, ChainParseError> {
        self.parse_instantiated_contracts()?
            .into_iter()
            .next()
            .ok_or_else(|| ChainParseError::NoInstantiatedContractFound {
                txhash: self.txhash.clone(),
            })
    }

    fn parse_stored_code_ids(&self) -> Result<Vec<u64>, ChainParseError> {
        let mut res = vec![];

        for log in &self.logs {
            for event in &log.events {
                for attr in &event.attributes {
                    if attr.key == "code_id" {
                        let value = strip_quotes(&attr.value);
                        let value = value.parse::<u64>().map_err(|source| {
                            ChainParseError::InvalidCodeId {
                                code_id: value.to_owned(),
                                txhash: self.txhash.clone(),
                                source,
                            }
                        })?;
                        res.push(value);
                    }
                }
            }
        }

        Ok(res)
    }

    fn parse_first_stored_code_id(&self) -> Result<u64, ChainParseError> {
        self.parse_stored_code_ids()?
            .into_iter()
            .next()
            .ok_or_else(|| ChainParseError::NoCodeIdFound {
                txhash: self.txhash.clone(),
            })
    }
}
