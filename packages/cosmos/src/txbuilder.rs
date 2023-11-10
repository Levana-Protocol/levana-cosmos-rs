use std::{fmt::Display, sync::Arc};

use cosmos_sdk_proto::{
    cosmos::base::v1beta1::Coin,
    cosmwasm::wasm::v1::{MsgExecuteContract, MsgMigrateContract, MsgUpdateAdmin},
};

use crate::HasAddress;

/// Transaction builder
///
/// This is the core interface for producing, simulating, and broadcasting transactions.
#[derive(Default, Clone, Debug)]
pub struct TxBuilder {
    pub(crate) messages: Vec<Arc<TxMessage>>,
    pub(crate) memo: Option<String>,
    pub(crate) skip_code_check: bool,
}

impl Display for TxBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(memo) = &self.memo {
            writeln!(f, "Memo: {memo}")?;
        }
        for (idx, msg) in self.messages.iter().enumerate() {
            write!(f, "Message {idx}: {}", msg.description)?;
            if idx + 1 < self.messages.len() {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

impl TxBuilder {
    /// Add a message to this transaction.
    pub fn add_message(&mut self, msg: impl Into<TxMessage>) -> &mut Self {
        self.messages.push(msg.into().into());
        self
    }

    /// Try adding a message to this transaction.
    ///
    /// This is for types which may fail during conversion to [TypedMessage].
    pub fn try_add_message<T>(&mut self, msg: T) -> Result<&mut Self, T::Error>
    where
        T: TryInto<TxMessage>,
    {
        self.messages.push(msg.try_into()?.into());
        Ok(self)
    }

    /// Add a message to update a contract admin.
    pub fn add_update_contract_admin(
        &mut self,
        contract: impl HasAddress,
        wallet: impl HasAddress,
        new_admin: impl HasAddress,
    ) -> &mut Self {
        self.add_message(MsgUpdateAdmin {
            sender: wallet.get_address_string(),
            new_admin: new_admin.get_address_string(),
            contract: contract.get_address_string(),
        });
        self
    }

    /// Add an execute message on a contract.
    pub fn add_execute_message(
        &mut self,
        contract: impl HasAddress,
        wallet: impl HasAddress,
        funds: Vec<Coin>,
        msg: impl serde::Serialize,
    ) -> Result<&mut Self, serde_json::Error> {
        Ok(self.add_message(MsgExecuteContract {
            sender: wallet.get_address_string(),
            contract: contract.get_address_string(),
            msg: serde_json::to_vec(&msg)?,
            funds,
        }))
    }

    /// Add a contract migration message.
    pub fn add_migrate_message(
        &mut self,
        contract: impl HasAddress,
        wallet: impl HasAddress,
        code_id: u64,
        msg: impl serde::Serialize,
    ) -> Result<&mut Self, serde_json::Error> {
        Ok(self.add_message(MsgMigrateContract {
            sender: wallet.get_address_string(),
            contract: contract.get_address_string(),
            code_id,
            msg: serde_json::to_vec(&msg)?,
        }))
    }

    /// Set the memo field.
    pub fn set_memo(&mut self, memo: impl Into<String>) -> &mut Self {
        self.memo = Some(memo.into());
        self
    }

    /// Clear the memo field
    pub fn clear_memo(&mut self) -> &mut Self {
        self.memo = None;
        self
    }

    /// Either set or clear the memo field.
    pub fn set_optional_memo(&mut self, memo: impl Into<Option<String>>) -> &mut Self {
        self.memo = memo.into();
        self
    }

    /// When calling [TxBuilder::sign_and_broadcast], skip the check of whether the code is 0
    pub fn set_skip_code_check(&mut self, skip_code_check: bool) -> &mut Self {
        self.skip_code_check = skip_code_check;
        self
    }
}

/// A message to include in a transaction.
#[derive(Debug)]
pub struct TxMessage {
    type_url: String,
    value: Vec<u8>,
    description: String,
}

impl TxMessage {
    /// Generate a new [TxMessage].
    pub fn new(
        type_url: impl Into<String>,
        value: Vec<u8>,
        description: impl Into<String>,
    ) -> Self {
        TxMessage {
            type_url: type_url.into(),
            value,
            description: description.into(),
        }
    }

    /// Get an [cosmos_sdk_proto::Any] value for including in a protobuf message.
    pub fn get_protobuf(&self) -> cosmos_sdk_proto::Any {
        cosmos_sdk_proto::Any {
            type_url: self.type_url.clone(),
            value: self.value.clone(),
        }
    }

    /// Convert into an [cosmos_sdk_proto::Any] value for including in a protobuf message.
    ///
    /// Provides the description value as well.
    pub fn into_protobuf(self) -> (cosmos_sdk_proto::Any, String) {
        (
            cosmos_sdk_proto::Any {
                type_url: self.type_url,
                value: self.value,
            },
            self.description,
        )
    }
}
