use crate::{
    address::{AddressHrp, HasAddressHrp},
    Cosmos, TypedMessage, Wallet,
};
use anyhow::{Context, Result};
use cosmos_sdk_proto::cosmos::{
    bank::v1beta1::Metadata,
    base::{abci::v1beta1::TxResponse, v1beta1::Coin},
};

/// TokenFactory interface
pub struct TokenFactory {
    client: Cosmos,
    wallet: Wallet,
}

impl TokenFactory {
    pub fn new(client: Cosmos, wallet: Wallet) -> Self {
        Self { client, wallet }
    }

    pub async fn create(&self, subdenom: String) -> Result<(TxResponse, String)> {
        let msg = MsgCreateDenom {
            sender: self.wallet.address().to_string(),
            subdenom,
        }
        .into_typed_message(self.client.get_address_hrp())?;

        let res = self.wallet.broadcast_message(&self.client, msg).await?;

        let denom = res
            .events
            .iter()
            .find_map(|evt| {
                if evt.r#type == "create_denom" {
                    evt.attributes.iter().find_map(|attr| {
                        if attr.key == "new_token_denom" {
                            Some(std::str::from_utf8(&attr.value).unwrap().to_string())
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
            .context("Failed to get denom from tx events")?;

        Ok((res, denom))
    }

    pub async fn mint(&self, denom: String, amount: u128) -> Result<TxResponse> {
        let msg = MsgMint {
            sender: self.wallet.address().to_string(),
            amount: Some(Coin {
                denom,
                amount: amount.to_string(),
            }),
        }
        .into_typed_message(self.client.get_address_hrp())?;
        self.wallet.broadcast_message(&self.client, msg).await
    }

    pub async fn burn(&self, denom: String, amount: u128) -> Result<TxResponse> {
        let msg = MsgBurn {
            sender: self.wallet.address().to_string(),
            burn_from_address: self.wallet.address().to_string(),
            amount: Some(Coin {
                denom,
                amount: amount.to_string(),
            }),
        }
        .into_typed_message(self.client.get_address_hrp())?;
        self.wallet.broadcast_message(&self.client, msg).await
    }

    pub async fn change_admin(&self, denom: String, addr: String) -> Result<TxResponse> {
        let msg = MsgChangeAdmin {
            sender: self.wallet.address().to_string(),
            denom: denom.clone(),
            new_admin: addr,
        }
        .into_typed_message(self.client.get_address_hrp())?;
        self.wallet.broadcast_message(&self.client, msg).await
    }
}

fn type_url(hrp: AddressHrp, s: &str) -> Result<String> {
    match &*hrp.as_str() {
        "osmo" => Ok(format!("/osmosis.tokenfactory.v1beta1.{s}")),
        "sei" => Ok(format!("/seiprotocol.seichain.tokenfactory.{s}")),
        _ => Err(anyhow::anyhow!(
            "cosmos-rs does not support tokenfactory for address type {hrp}"
        )),
    }
}

fn into_typed_message<T: prost::Message>(
    address_type: AddressHrp,
    type_url_suffix: &str,
    msg: T,
) -> Result<TypedMessage> {
    Ok(TypedMessage::new(cosmos_sdk_proto::Any {
        type_url: type_url(address_type, type_url_suffix)?,
        value: msg.encode_to_vec(),
    }))
}

impl MsgCreateDenom {
    pub(crate) fn into_typed_message(self, address_type: AddressHrp) -> Result<TypedMessage> {
        into_typed_message(address_type, "MsgCreateDenom", self)
    }
}

impl MsgMint {
    pub(crate) fn into_typed_message(self, address_type: AddressHrp) -> Result<TypedMessage> {
        into_typed_message(address_type, "MsgMint", self)
    }
}

impl MsgBurn {
    pub(crate) fn into_typed_message(self, address_type: AddressHrp) -> Result<TypedMessage> {
        into_typed_message(address_type, "MsgBurn", self)
    }
}

impl MsgChangeAdmin {
    pub(crate) fn into_typed_message(self, address_type: AddressHrp) -> Result<TypedMessage> {
        into_typed_message(address_type, "MsgChangeAdmin", self)
    }
}

//////////// GENERATED, COPY/PASTED, AND PATCHED FROM PROST-BUILD ////////////////

/// MsgCreateDenom defines the message structure for the CreateDenom gRPC service
/// method. It allows an account to create a new denom. It requires a sender
/// address and a sub denomination. The (sender_address, sub_denomination) tuple
/// must be unique and cannot be re-used.
///
/// The resulting denom created is defined as
/// <factory/{creatorAddress}/{subdenom}>. The resulting denom's admin is
/// originally set to be the creator, but this can be changed later. The token
/// denom does not indicate the current admin.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateDenom {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    /// subdenom can be up to 44 "alphanumeric" characters long.
    #[prost(string, tag = "2")]
    pub subdenom: ::prost::alloc::string::String,
}
/// MsgCreateDenomResponse is the return value of MsgCreateDenom
/// It returns the full string of the newly created denom
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateDenomResponse {
    #[prost(string, tag = "1")]
    pub new_token_denom: ::prost::alloc::string::String,
}
/// MsgMint is the sdk.Msg type for allowing an admin account to mint
/// more of a token.  For now, we only support minting to the sender account
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgMint {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub amount: ::core::option::Option<Coin>,
    // not yet available in testnet
    // #[prost(string, tag = "3")]
    // pub mint_to_address: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgMintResponse {}
/// MsgBurn is the sdk.Msg type for allowing an admin account to burn
/// a token.  For now, we only support burning from the sender account.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgBurn {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub amount: ::core::option::Option<Coin>,
    #[prost(string, tag = "3")]
    pub burn_from_address: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgBurnResponse {}
/// MsgChangeAdmin is the sdk.Msg type for allowing an admin account to reassign
/// adminship of a denom to a new account
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgChangeAdmin {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub denom: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub new_admin: ::prost::alloc::string::String,
}
/// MsgChangeAdminResponse defines the response structure for an executed
/// MsgChangeAdmin message.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgChangeAdminResponse {}
/// MsgSetBeforeSendHook is the sdk.Msg type for allowing an admin account to
/// assign a CosmWasm contract to call with a BeforeSend hook
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSetBeforeSendHook {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub denom: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub cosmwasm_address: ::prost::alloc::string::String,
}
/// MsgSetBeforeSendHookResponse defines the response structure for an executed
/// MsgSetBeforeSendHook message.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSetBeforeSendHookResponse {}
/// MsgSetDenomMetadata is the sdk.Msg type for allowing an admin account to set
/// the denom's bank metadata
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSetDenomMetadata {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub metadata: ::core::option::Option<Metadata>,
}
/// MsgSetDenomMetadataResponse defines the response structure for an executed
/// MsgSetDenomMetadata message.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgSetDenomMetadataResponse {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgForceTransfer {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub amount: ::core::option::Option<Coin>,
    #[prost(string, tag = "3")]
    pub transfer_from_address: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub transfer_to_address: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgForceTransferResponse {}
