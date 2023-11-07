#![deny(missing_docs)]
//! Library for communicating with Cosmos blockchains over gRPC
pub use address::{Address, AddressHrp, HasAddress, HasAddressHrp, PublicKeyMethod, RawAddress};
pub use authz::MsgGrantHelper;
pub use client::{BlockInfo, Cosmos, HasCosmos, TxBuilder, TypedMessage};
pub use codeid::CodeId;
pub use contract::{Contract, ContractAdmin, HasContract};
pub use cosmos_builder::CosmosBuilder;
pub use cosmos_network::CosmosNetwork;
pub use cosmos_sdk_proto as proto;
pub use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
pub use error::Error;
pub use ext::TxResponseExt;
pub use tokenfactory::TokenFactory;
pub use wallet::{SeedPhrase, Wallet};

mod address;
mod authz;
mod client;
mod codeid;
mod contract;
mod cosmos_builder;
mod cosmos_network;
mod ext;
mod injective;
mod tokenfactory;
mod wallet;

#[cfg(feature = "clap")]
pub mod clap;

pub mod error;
