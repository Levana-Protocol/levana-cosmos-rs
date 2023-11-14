/// EpochInfo is a struct that describes the data going into
/// a timer defined by the x/epochs module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EpochInfo {
    /// identifier is a unique reference to this particular timer.
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    /// start_time is the time at which the timer first ever ticks.
    /// If start_time is in the future, the epoch will not begin until the start
    /// time.
    #[prost(message, optional, tag = "2")]
    pub start_time: ::core::option::Option<::prost_types::Timestamp>,
    /// duration is the time in between epoch ticks.
    /// In order for intended behavior to be met, duration should
    /// be greater than the chains expected block time.
    /// Duration must be non-zero.
    #[prost(message, optional, tag = "3")]
    pub duration: ::core::option::Option<::prost_types::Duration>,
    /// current_epoch is the current epoch number, or in other words,
    /// how many times has the timer 'ticked'.
    /// The first tick (current_epoch=1) is defined as
    /// the first block whose blocktime is greater than the EpochInfo start_time.
    #[prost(int64, tag = "4")]
    pub current_epoch: i64,
    /// current_epoch_start_time describes the start time of the current timer
    /// interval. The interval is (current_epoch_start_time,
    /// current_epoch_start_time + duration] When the timer ticks, this is set to
    /// current_epoch_start_time = last_epoch_start_time + duration only one timer
    /// tick for a given identifier can occur per block.
    ///
    /// NOTE! The current_epoch_start_time may diverge significantly from the
    /// wall-clock time the epoch began at. Wall-clock time of epoch start may be
    /// >> current_epoch_start_time. Suppose current_epoch_start_time = 10,
    /// duration = 5. Suppose the chain goes offline at t=14, and comes back online
    /// at t=30, and produces blocks at every successive time. (t=31, 32, etc.)
    /// * The t=30 block will start the epoch for (10, 15]
    /// * The t=31 block will start the epoch for (15, 20]
    /// * The t=32 block will start the epoch for (20, 25]
    /// * The t=33 block will start the epoch for (25, 30]
    /// * The t=34 block will start the epoch for (30, 35]
    /// * The **t=36** block will start the epoch for (35, 40]
    #[prost(message, optional, tag = "5")]
    pub current_epoch_start_time: ::core::option::Option<::prost_types::Timestamp>,
    /// epoch_counting_started is a boolean, that indicates whether this
    /// epoch timer has began yet.
    #[prost(bool, tag = "6")]
    pub epoch_counting_started: bool,
    /// current_epoch_start_height is the block height at which the current epoch
    /// started. (The block height at which the timer last ticked)
    #[prost(int64, tag = "8")]
    pub current_epoch_start_height: i64,
}
/// GenesisState defines the epochs module's genesis state.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GenesisState {
    #[prost(message, repeated, tag = "1")]
    pub epochs: ::prost::alloc::vec::Vec<EpochInfo>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryEpochsInfoRequest {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryEpochsInfoResponse {
    #[prost(message, repeated, tag = "1")]
    pub epochs: ::prost::alloc::vec::Vec<EpochInfo>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryCurrentEpochRequest {
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryCurrentEpochResponse {
    #[prost(int64, tag = "1")]
    pub current_epoch: i64,
}
/// Generated client implementations.
pub mod query_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::http::Uri;
    use tonic::codegen::*;
    /// Query defines the gRPC querier service.
    #[derive(Debug, Clone)]
    pub struct QueryClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl QueryClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> QueryClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> QueryClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            QueryClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// EpochInfos provide running epochInfos
        pub async fn epoch_infos(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryEpochsInfoRequest>,
        ) -> Result<tonic::Response<super::QueryEpochsInfoResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/osmosis.epochs.v1beta1.Query/EpochInfos");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// CurrentEpoch provide current epoch of specified identifier
        pub async fn current_epoch(
            &mut self,
            request: impl tonic::IntoRequest<super::QueryCurrentEpochRequest>,
        ) -> Result<tonic::Response<super::QueryCurrentEpochResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/osmosis.epochs.v1beta1.Query/CurrentEpoch");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
