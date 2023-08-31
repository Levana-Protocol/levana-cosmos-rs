#![allow(non_snake_case)]
use cosmos_sdk_proto::cosmos::auth::v1beta1::BaseAccount;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthAccount {
    #[prost(message, optional, tag = "1")]
    pub base_account: ::core::option::Option<BaseAccount>,
    #[prost(bytes = "vec", tag = "2")]
    pub code_hash: ::prost::alloc::vec::Vec<u8>,
}
