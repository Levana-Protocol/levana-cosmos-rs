use std::fmt::Display;

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
    pub(crate) messages: Vec<cosmos_sdk_proto::Any>,
    pub(crate) memo: Option<String>,
    pub(crate) skip_code_check: bool,
}

impl Display for TxBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("FIXME need to implement a real Display for TxBuilder")
    }
}

impl TxBuilder {
    /// Add a message to this transaction.
    pub fn add_message(&mut self, msg: impl Into<TypedMessage>) -> &mut Self {
        self.messages.push(msg.into().0);
        self
    }

    /// Try adding a message to this transaction.
    ///
    /// This is for types which may fail during conversion to [TypedMessage].
    pub fn try_add_message<T>(&mut self, msg: T) -> Result<&mut Self, T::Error>
    where
        T: TryInto<TypedMessage>,
    {
        self.messages.push(msg.try_into()?.0);
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
    ) -> anyhow::Result<&mut Self> {
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
        // FIXME remove anyhow
    ) -> anyhow::Result<&mut Self> {
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

/// A message to include in a transaction, including the type URL string.
pub struct TypedMessage(pub(crate) cosmos_sdk_proto::Any);
