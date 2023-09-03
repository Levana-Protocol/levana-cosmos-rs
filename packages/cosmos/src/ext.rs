use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;

pub trait TxResponseExt {
    fn parse_timestamp(&self) -> Result<DateTime<Utc>>;
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
}
