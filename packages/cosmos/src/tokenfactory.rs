use crate::{
    address::{AddressHrp, HasAddressHrp},
    error::TokenFactoryError,
    Cosmos, HasAddress, TxMessage, Wallet,
};
use anyhow::{Context, Result};
use cosmos_sdk_proto::cosmos::{
    bank::v1beta1::Metadata,
    base::{abci::v1beta1::TxResponse, v1beta1::Coin},
};

/// TokenFactory interface
#[derive(Clone, Debug)]
pub struct TokenFactory {
    client: Cosmos,
    kind: TokenFactoryKind,
}

#[derive(Clone, Copy, Debug)]
enum TokenFactoryKind {
    Osmosis,
    Sei,
}

impl TryFrom<AddressHrp> for TokenFactoryKind {
    type Error = TokenFactoryError;

    fn try_from(hrp: AddressHrp) -> Result<Self, TokenFactoryError> {
        match hrp.as_str() {
            "osmo" => Ok(TokenFactoryKind::Osmosis),
            "sei" => Ok(TokenFactoryKind::Sei),
            _ => Err(TokenFactoryError::Unsupported { hrp }),
        }
    }
}

impl Cosmos {
    /// Generate a new [TokenFactory] for this connection, if supported for this chain.
    pub fn token_factory(self) -> Result<TokenFactory, TokenFactoryError> {
        self.get_address_hrp()
            .try_into()
            .map(|kind| TokenFactory { client: self, kind })
    }
}

impl TokenFactory {
    /// Create a new token with the given subdenom.
    pub async fn create(&self, wallet: &Wallet, subdenom: String) -> Result<(TxResponse, String)> {
        let msg = MsgCreateDenom {
            sender: wallet.get_address_string(),
            subdenom,
        }
        .into_typed_message(self.kind);

        let res = wallet.broadcast_message(&self.client, msg).await?;

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

    /// Mint some tokens for the given denom.
    pub async fn mint(&self, wallet: &Wallet, denom: String, amount: u128) -> Result<TxResponse> {
        let msg = MsgMint {
            sender: wallet.get_address_string(),
            amount: Some(Coin {
                denom,
                amount: amount.to_string(),
            }),
        }
        .into_typed_message(self.kind);
        wallet.broadcast_message(&self.client, msg).await
    }

    /// Burn tokens for the given denom
    pub async fn burn(&self, wallet: &Wallet, denom: String, amount: u128) -> Result<TxResponse> {
        let msg = MsgBurn {
            sender: wallet.get_address_string(),
            burn_from_address: wallet.get_address_string(),
            amount: Some(Coin {
                denom,
                amount: amount.to_string(),
            }),
        }
        .into_typed_message(self.kind);
        wallet.broadcast_message(&self.client, msg).await
    }

    /// Change the admin for the given token.
    pub async fn change_admin(
        &self,
        wallet: &Wallet,
        denom: String,
        addr: String,
    ) -> Result<TxResponse> {
        let msg = MsgChangeAdmin {
            sender: wallet.get_address_string(),
            denom: denom.clone(),
            new_admin: addr,
        }
        .into_typed_message(self.kind);
        wallet.broadcast_message(&self.client, msg).await
    }
}

fn type_url(kind: TokenFactoryKind, s: &str) -> String {
    match kind {
        TokenFactoryKind::Osmosis => format!("/osmosis.tokenfactory.v1beta1.{s}"),
        TokenFactoryKind::Sei => format!("/seiprotocol.seichain.tokenfactory.{s}"),
    }
}

fn into_typed_message<T: prost::Message>(
    kind: TokenFactoryKind,
    type_url_suffix: &str,
    msg: T,
) -> TxMessage {
    TxMessage::new(cosmos_sdk_proto::Any {
        type_url: type_url(kind, type_url_suffix),
        value: msg.encode_to_vec(),
    })
}

impl MsgCreateDenom {
    fn into_typed_message(self, kind: TokenFactoryKind) -> TxMessage {
        into_typed_message(kind, "MsgCreateDenom", self)
    }
}

impl MsgMint {
    fn into_typed_message(self, kind: TokenFactoryKind) -> TxMessage {
        into_typed_message(kind, "MsgMint", self)
    }
}

impl MsgBurn {
    fn into_typed_message(self, kind: TokenFactoryKind) -> TxMessage {
        into_typed_message(kind, "MsgBurn", self)
    }
}

impl MsgChangeAdmin {
    fn into_typed_message(self, kind: TokenFactoryKind) -> TxMessage {
        into_typed_message(kind, "MsgChangeAdmin", self)
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
