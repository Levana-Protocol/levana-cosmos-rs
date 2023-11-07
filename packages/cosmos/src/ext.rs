use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;

use crate::{codeid::strip_quotes, Address};

/// Extension trait to add some helper methods to [TxResponse].
pub trait TxResponseExt {
    /// Parse the timestamp of this transaction.
    fn parse_timestamp(&self) -> Result<DateTime<Utc>>;

    /// Return the addresses of all instantiated contracts in this transaction.
    fn parse_instantiated_contracts(&self) -> Result<Vec<Address>>;

    /// Return the code IDs of any stored code in this transaction
    fn parse_stored_code_ids(&self) -> Result<Vec<u64>>;

    /// Return the first code ID stored in this transaction
    fn parse_first_stored_code_id(&self) -> Result<u64>;
}

impl TxResponseExt for TxResponse {
    fn parse_timestamp(&self) -> Result<DateTime<Utc>> {
        self.timestamp.parse().with_context(|| {
            format!(
                "Could not parse timestamp from TxResponse: {}",
                self.timestamp
            )
        })
    }

    fn parse_instantiated_contracts(&self) -> Result<Vec<Address>> {
        let mut addrs = vec![];

        for log in &self.logs {
            for event in &log.events {
                if event.r#type == "instantiate"
                    || event.r#type == "cosmwasm.wasm.v1.EventContractInstantiated"
                {
                    for attr in &event.attributes {
                        if attr.key == "_contract_address" || attr.key == "contract_address" {
                            let address: Address = strip_quotes(&attr.value).parse()?;
                            addrs.push(address);
                        }
                    }
                }
            }
        }

        Ok(addrs)
    }

    fn parse_stored_code_ids(&self) -> Result<Vec<u64>> {
        let mut res = vec![];

        for log in &self.logs {
            for event in &log.events {
                for attr in &event.attributes {
                    if attr.key == "code_id" {
                        let value = strip_quotes(&attr.value);
                        let value = value
                            .parse()
                            .with_context(|| format!("Unable to parse code ID: {}", attr.value))?;
                        res.push(value);
                    }
                }
            }
        }

        Ok(res)
    }

    fn parse_first_stored_code_id(&self) -> Result<u64> {
        self.parse_stored_code_ids()?
            .into_iter()
            .next()
            .with_context(|| {
                format!(
                    "Missing code_id in store_code response {}: {:?}",
                    self.txhash, self.logs
                )
            })
    }
}
