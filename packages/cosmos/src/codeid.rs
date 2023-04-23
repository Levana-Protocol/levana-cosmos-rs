use std::{fmt::Display, path::Path};

use anyhow::{Context, Result};
use cosmos_sdk_proto::cosmwasm::wasm::v1::MsgStoreCode;

use crate::{Cosmos, HasCosmos, Wallet};

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
        for log in &res.logs {
            for event in &log.events {
                if event.r#type == "store_code" {
                    for attr in &event.attributes {
                        if attr.key == "code_id" {
                            return Ok(CodeId {
                                code_id: attr.value.parse()?,
                                client: self.clone(),
                            });
                        }
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "Missing code_id in store_code response: {res:?}"
        ))
    }

    /// Convenience wrapper for [Cosmos::store_code] that works on file paths
    pub async fn store_code_path(&self, wallet: &Wallet, path: impl AsRef<Path>) -> Result<CodeId> {
        let path = path.as_ref();
        let wasm_byte_code = fs_err::read(path)?;
        self.store_code(wallet, wasm_byte_code)
            .await
            .with_context(|| format!("Storing code in file {}", path.display()))
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
