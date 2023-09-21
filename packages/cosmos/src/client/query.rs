use cosmos_sdk_proto::cosmos::{
    auth::v1beta1::{QueryAccountRequest, QueryAccountResponse},
    bank::v1beta1::{QueryAllBalancesRequest, QueryAllBalancesResponse},
};
use tonic::async_trait;

use super::CosmosInner;

#[async_trait]
pub(crate) trait GrpcRequest {
    type Response;

    async fn perform(
        self,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status>;
}

#[async_trait]
impl GrpcRequest for QueryAccountRequest {
    type Response = QueryAccountResponse;
    async fn perform(
        self,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner.auth_query_client.lock().await.account(self).await
    }
}

#[async_trait]
impl GrpcRequest for QueryAllBalancesRequest {
    type Response = QueryAllBalancesResponse;
    async fn perform(
        self,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .bank_query_client
            .lock()
            .await
            .all_balances(self)
            .await
    }
}

#[async_trait]
impl GrpcRequest for tonic::Request<QueryAllBalancesRequest> {
    type Response = QueryAllBalancesResponse;
    async fn perform(
        self,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .bank_query_client
            .lock()
            .await
            .all_balances(self)
            .await
    }
}
