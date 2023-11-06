use std::{convert::Infallible, fmt::Display, path::Path};

use cosmos_sdk_proto::{
    cosmos::{
        authz::v1beta1::MsgExec,
        base::abci::v1beta1::{AbciMessageLog, TxResponse},
    },
    cosmwasm::wasm::v1::MsgStoreCode,
};

use crate::{Address, Cosmos, HasAddress, HasCosmos, TxBuilder, TypedMessage, Wallet};

#[derive(thiserror::Error, Debug)]
pub enum WasmCodeError {
    #[error("Missing code_id in store_code response {txhash}: {logs:?}")]
    MissingCodeId {
        txhash: String,
        logs: Vec<AbciMessageLog>,
    },
    #[error("Invalid code ID {value} in store_code response {txhash}: {logs:?}")]
    InvalidCodeId {
        txhash: String,
        logs: Vec<AbciMessageLog>,
        value: String,
    },
    #[error("Unable to load file {} containing WASM code: {source:?}", path.display())]
    LoadFileError {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}

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

    pub async fn download(&self) -> Result<Vec<u8>, Infallible> {
        self.client.code_info(self.code_id).await
    }
}

/// Get the code ID from a TxResponse
fn parse_code_id(res: &TxResponse) -> Result<u64, WasmCodeError> {
    for log in &res.logs {
        for event in &log.events {
            for attr in &event.attributes {
                if attr.key == "code_id" {
                    let value = strip_quotes(&attr.value);
                    return value.parse().map_err(|_| WasmCodeError::InvalidCodeId {
                        txhash: res.txhash,
                        logs: res.logs,
                        value: value.to_owned(),
                    });
                }
            }
        }
    }

    Err(WasmCodeError::MissingCodeId {
        txhash: res.txhash,
        logs: res.logs,
    })
}

pub(crate) fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('\"')
        .and_then(|s| s.strip_suffix('\"'))
        .unwrap_or(s)
}

impl Cosmos {
    /// Convenience helper for uploading code to the blockchain
    pub async fn store_code(
        &self,
        wallet: &Wallet,
        wasm_byte_code: Vec<u8>,
    ) -> Result<CodeId, WasmCodeError> {
        let msg = MsgStoreCode {
            sender: wallet.address().to_string(),
            wasm_byte_code,
            instantiate_permission: None,
        };
        let res = wallet.broadcast_message(self, msg).await?;
        let code_id = parse_code_id(&res)?;
        Ok(CodeId {
            code_id,
            client: self.clone(),
        })
    }

    /// Convenience wrapper for [Cosmos::store_code] that works on file paths
    pub async fn store_code_path(
        &self,
        wallet: &Wallet,
        path: impl AsRef<Path>,
    ) -> Result<CodeId, Infallible> {
        let path = path.as_ref();
        let wasm_byte_code = fs_err::read(path).map_err(|source| WasmCodeError::LoadFileError {
            path: path.to_owned(),
            source,
        })?;
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
    ) -> Result<(TxResponse, CodeId), Infallible> {
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
    pub async fn code_id_from_tx(&self, txhash: impl Into<String>) -> Result<CodeId, Infallible> {
        let (_, txres) = self.wait_for_transaction_body(txhash).await?;
        let code_id = parse_code_id(&txres)?;
        Ok(self.make_code_id(code_id))
    }

    /// Get the contract address from a transaction hash
    pub async fn contract_address_from_tx(
        &self,
        txhash: impl Into<String>,
    ) -> Result<CodeId, Infallible> {
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
