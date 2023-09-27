use anyhow::Result;
use chrono::{DateTime, Utc};
use cosmos_sdk_proto::cosmos::{
    authz::v1beta1::{
        GenericAuthorization, Grant, GrantAuthorization, MsgExec, MsgGrant,
        QueryGranterGrantsRequest, QueryGranterGrantsResponse,
    },
    base::query::v1beta1::{PageRequest, PageResponse},
};
use prost::Message;
use prost_types::Timestamp;

use crate::{Address, Cosmos, HasAddress, TypedMessage};

impl From<MsgGrant> for TypedMessage {
    fn from(msg: MsgGrant) -> Self {
        TypedMessage::new(cosmos_sdk_proto::Any {
            type_url: "/cosmos.authz.v1beta1.MsgGrant".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

impl From<MsgExec> for TypedMessage {
    fn from(msg: MsgExec) -> Self {
        TypedMessage::new(cosmos_sdk_proto::Any {
            type_url: "/cosmos.authz.v1beta1.MsgExec".to_owned(),
            value: msg.encode_to_vec(),
        })
    }
}

pub struct MsgGrantHelper {
    pub granter: Address,
    pub grantee: Address,
    pub authorization: String,
    pub expiration: Option<DateTime<Utc>>,
}

impl MsgGrantHelper {
    pub fn try_into_msg_grant(self) -> Result<MsgGrant> {
        let MsgGrantHelper {
            granter,
            grantee,
            authorization,
            expiration,
        } = self;
        let authorization = GenericAuthorization { msg: authorization };
        let authorization = prost_types::Any {
            type_url: "/cosmos.authz.v1beta1.GenericAuthorization".to_owned(),
            value: authorization.encode_to_vec(),
        };
        Ok(MsgGrant {
            granter: granter.get_address_string(),
            grantee: grantee.get_address_string(),
            grant: Some(Grant {
                authorization: Some(authorization),
                expiration: expiration.map(datetime_to_timestamp).transpose()?,
            }),
        })
    }
}

fn datetime_to_timestamp(x: DateTime<Utc>) -> Result<Timestamp> {
    Ok(prost_types::Timestamp {
        seconds: x.timestamp(),
        nanos: x.timestamp_subsec_nanos().try_into()?,
    })
}

impl Cosmos {
    pub async fn query_granter_grants(
        &self,
        granter: impl HasAddress,
    ) -> Result<Vec<GrantAuthorization>> {
        let mut res = vec![];
        let mut pagination = None;

        loop {
            let req = QueryGranterGrantsRequest {
                granter: granter.get_address_string(),
                pagination: pagination.take(),
            };

            let QueryGranterGrantsResponse {
                mut grants,
                pagination: pag_res,
            } = self.perform_query(None, req, true).await?.into_inner();
            println!("{grants:?}");
            if grants.is_empty() {
                break Ok(res);
            }

            res.append(&mut grants);

            pagination = match pag_res {
                Some(PageResponse { next_key, total: _ }) => Some(PageRequest {
                    key: next_key,
                    // Ideally we'd just leave this out so we use next_key
                    // instead, but the Rust types don't allow this
                    offset: res.len().try_into()?,
                    limit: 10,
                    count_total: false,
                    reverse: false,
                }),
                None => None,
            };
        }
    }
}
