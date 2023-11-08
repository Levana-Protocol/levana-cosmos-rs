use cosmos_sdk_proto::cosmos::{
    authz::v1beta1::{
        GrantAuthorization, MsgGrant, QueryGranterGrantsRequest, QueryGranterGrantsResponse,
    },
    base::query::v1beta1::{PageRequest, PageResponse},
};
use prost::Message;

use crate::{error::Action, Cosmos, HasAddress, TxMessage};

impl From<MsgGrant> for TxMessage {
    fn from(msg: MsgGrant) -> Self {
        TxMessage::new(
            "/cosmos.authz.v1beta1.MsgGrant",
            msg.encode_to_vec(),
            format!(
                "{} grants {} access to {:?}",
                msg.granter, msg.grantee, msg.grant
            ),
        )
    }
}

impl Cosmos {
    /// Check which grants the given address has authorized.
    pub async fn query_granter_grants(
        &self,
        granter: impl HasAddress,
    ) -> Result<Vec<GrantAuthorization>, crate::Error> {
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
            } = self
                .perform_query(req, Action::QueryGranterGrants(granter.get_address()), true)
                .await?
                .into_inner();
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
                    offset: res.len().try_into().unwrap_or(u64::MAX),
                    limit: 10,
                    count_total: false,
                    reverse: false,
                }),
                None => None,
            };
        }
    }
}
