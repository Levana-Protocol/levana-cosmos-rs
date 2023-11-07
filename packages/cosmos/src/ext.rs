use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;

use crate::{codeid::strip_quotes, Address};

pub trait TxResponseExt {
    /// Parse the timestamp of this transaction.
    fn parse_timestamp(&self) -> Result<DateTime<Utc>>;

    /// Return the addresses of all instantiated contracts in this transaction.
    fn parse_instantiated_contracts(&self) -> Result<Vec<Address>>;
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
}
