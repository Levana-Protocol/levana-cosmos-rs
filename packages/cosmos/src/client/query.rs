use cosmos_sdk_proto::{
    cosmos::{
        auth::v1beta1::{QueryAccountRequest, QueryAccountResponse},
        authz::v1beta1::{
            QueryGranteeGrantsRequest, QueryGranteeGrantsResponse, QueryGranterGrantsRequest,
            QueryGranterGrantsResponse,
        },
        bank::v1beta1::{QueryAllBalancesRequest, QueryAllBalancesResponse},
        base::tendermint::v1beta1::{
            GetBlockByHeightRequest, GetBlockByHeightResponse, GetLatestBlockRequest,
            GetLatestBlockResponse,
        },
        tx::v1beta1::{
            BroadcastTxRequest, BroadcastTxResponse, GetTxRequest, GetTxResponse,
            GetTxsEventRequest, GetTxsEventResponse, SimulateRequest, SimulateResponse,
        },
    },
    cosmwasm::wasm::v1::{
        QueryCodeRequest, QueryCodeResponse, QueryContractHistoryRequest,
        QueryContractHistoryResponse, QueryContractInfoRequest, QueryContractInfoResponse,
        QueryRawContractStateRequest, QueryRawContractStateResponse,
        QuerySmartContractStateRequest, QuerySmartContractStateResponse,
    },
};
use tonic::async_trait;

use super::CosmosInner;

#[async_trait]
pub(crate) trait GrpcRequest: Sized {
    type Response;

    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status>;
}

#[async_trait]
impl GrpcRequest for QueryAccountRequest {
    type Response = QueryAccountResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner.auth_query_client.lock().await.account(req).await
    }
}

#[async_trait]
impl GrpcRequest for QueryAllBalancesRequest {
    type Response = QueryAllBalancesResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner.bank_query_client.lock().await.all_balances(req).await
    }
}

#[async_trait]
impl GrpcRequest for QuerySmartContractStateRequest {
    type Response = QuerySmartContractStateResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .wasm_query_client
            .lock()
            .await
            .smart_contract_state(req)
            .await
    }
}

#[async_trait]
impl GrpcRequest for QueryRawContractStateRequest {
    type Response = QueryRawContractStateResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .wasm_query_client
            .lock()
            .await
            .raw_contract_state(req)
            .await
    }
}

#[async_trait]
impl GrpcRequest for QueryCodeRequest {
    type Response = QueryCodeResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner.wasm_query_client.lock().await.code(req).await
    }
}

#[async_trait]
impl GrpcRequest for GetTxRequest {
    type Response = GetTxResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner.tx_service_client.lock().await.get_tx(req).await
    }
}

#[async_trait]
impl GrpcRequest for GetTxsEventRequest {
    type Response = GetTxsEventResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .tx_service_client
            .lock()
            .await
            .get_txs_event(req)
            .await
    }
}

#[async_trait]
impl GrpcRequest for QueryContractInfoRequest {
    type Response = QueryContractInfoResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .wasm_query_client
            .lock()
            .await
            .contract_info(req)
            .await
    }
}

#[async_trait]
impl GrpcRequest for QueryContractHistoryRequest {
    type Response = QueryContractHistoryResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .wasm_query_client
            .lock()
            .await
            .contract_history(req)
            .await
    }
}

#[async_trait]
impl GrpcRequest for GetBlockByHeightRequest {
    type Response = GetBlockByHeightResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .tendermint_client
            .lock()
            .await
            .get_block_by_height(req)
            .await
    }
}

#[async_trait]
impl GrpcRequest for GetLatestBlockRequest {
    type Response = GetLatestBlockResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .tendermint_client
            .lock()
            .await
            .get_latest_block(req)
            .await
    }
}

#[async_trait]
impl GrpcRequest for SimulateRequest {
    type Response = SimulateResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner.tx_service_client.lock().await.simulate(req).await
    }
}

#[async_trait]
impl GrpcRequest for BroadcastTxRequest {
    type Response = BroadcastTxResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner.tx_service_client.lock().await.broadcast_tx(req).await
    }
}

#[async_trait]
impl GrpcRequest for QueryGranterGrantsRequest {
    type Response = QueryGranterGrantsResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .authz_query_client
            .lock()
            .await
            .granter_grants(req)
            .await
    }
}

#[async_trait]
impl GrpcRequest for QueryGranteeGrantsRequest {
    type Response = QueryGranteeGrantsResponse;
    async fn perform(
        req: tonic::Request<Self>,
        inner: &CosmosInner,
    ) -> Result<tonic::Response<Self::Response>, tonic::Status> {
        inner
            .authz_query_client
            .lock()
            .await
            .grantee_grants(req)
            .await
    }
}
