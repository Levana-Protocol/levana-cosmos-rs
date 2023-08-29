use std::{fmt::Display, path::Path};

use anyhow::{Context, Result};
use cosmos_sdk_proto::{
    cosmos::{authz::v1beta1::MsgExec, base::abci::v1beta1::TxResponse},
    cosmwasm::wasm::v1::MsgStoreCode,
};

use crate::{Address, Cosmos, HasAddress, HasCosmos, TxBuilder, TypedMessage, Wallet};

/// Represents the uploaded code on a specific blockchain connection.
#[derive(Clone)]
pub struct CodeId {
    pub(crate) code_id: u64,
    pub(crate) client: Cosmos,
}

impl CodeId {
    pub fn new(client: Cosmos, code_id: u64) -> Self {
        CodeId { code_id, client }
    }

    pub fn get_code_id(&self) -> u64 {
        self.code_id
    }

    pub async fn download(&self) -> Result<Vec<u8>> {
        self.client.code_info(self.code_id).await
    }
}

/// Get the code ID from a TxResponse
fn parse_code_id(res: &TxResponse) -> Result<u64> {
    for log in &res.logs {
        for event in &log.events {
            for attr in &event.attributes {
                if attr.key == "code_id" {
                    let value = strip_quotes(&attr.value);
                    return value
                        .parse()
                        .with_context(|| format!("Unable to parse code ID: {}", attr.value));
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Missing code_id in store_code response {}: {:?}",
        res.txhash,
        res.logs
    ))
}

pub(crate) fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('\"')
        .and_then(|s| s.strip_suffix('\"'))
        .unwrap_or(s)
}

impl Cosmos {
    /// Convenience helper for uploading code to the blockchain
    pub async fn store_code(&self, wallet: &Wallet, wasm_byte_code: Vec<u8>) -> Result<CodeId> {
        let msg = MsgStoreCode {
            sender: wallet.address().to_string(),
            wasm_byte_code,
            instantiate_permission: None,
        };
        let res = wallet
            .broadcast_message(self, msg)
            .await
            .context("Storing WASM contract")?;
        let code_id = parse_code_id(&res)?;
        Ok(CodeId {
            code_id,
            client: self.clone(),
        })
    }

    /// Convenience wrapper for [Cosmos::store_code] that works on file paths
    pub async fn store_code_path(&self, wallet: &Wallet, path: impl AsRef<Path>) -> Result<CodeId> {
        let path = path.as_ref();
        let wasm_byte_code = fs_err::read(path)?;
        self.store_code(wallet, wasm_byte_code)
            .await
            .with_context(|| format!("Storing code in file {}", path.display()))
    }

    /// Like store_code_path, but uses the authz grant mechanism
    pub async fn store_code_path_authz(
        &self,
        wallet: &Wallet,
        path: impl AsRef<Path>,
        granter: Address,
    ) -> Result<(TxResponse, CodeId)> {
        let wasm_byte_code = fs_err::read(path)?;
        let store_code = MsgStoreCode {
            sender: granter.get_address_string(),
            wasm_byte_code,
            instantiate_permission: None,
        };

        let mut txbuilder = TxBuilder::default();
        let msg = MsgExec {
            grantee: wallet.get_address_string(),
            msgs: vec![TypedMessage::from(store_code).into_inner()],
        };
        txbuilder.add_message_mut(msg);
        let res = txbuilder.sign_and_broadcast(self, wallet).await?;
        let code_id = parse_code_id(&res)?;
        Ok((res, self.make_code_id(code_id)))
    }

    /// Get the code ID from a transaction hash
    pub async fn code_id_from_tx(&self, txhash: impl Into<String>) -> Result<CodeId> {
        let (_, txres) = self.wait_for_transaction_body(txhash).await?;
        let code_id = parse_code_id(&txres)?;
        Ok(self.make_code_id(code_id))
    }

    /// Get the contract address from a transaction hash
    pub async fn contract_address_from_tx(&self, txhash: impl Into<String>) -> Result<CodeId> {
        let (_, txres) = self.wait_for_transaction_body(txhash).await?;
        let code_id = parse_code_id(&txres)?;
        Ok(self.make_code_id(code_id))
    }
}

impl Display for CodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.code_id)
    }
}

impl HasCosmos for CodeId {
    fn get_cosmos(&self) -> &Cosmos {
        &self.client
    }
}
