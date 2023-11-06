use chrono::{DateTime, Utc};
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;

pub trait TxResponseExt {
    fn parse_timestamp(&self) -> Result<DateTime<Utc>, crate::ConversionError>;
}

impl TxResponseExt for TxResponse {
    fn parse_timestamp(&self) -> Result<DateTime<Utc>, crate::ConversionError> {
        self.timestamp
            .parse()
            .map_err(|source| crate::ConversionError::InvalidTimestamp {
                txhash: self.txhash.clone(),
                source,
            })
    }
}
