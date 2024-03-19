use std::{
    fmt::Display,
    io::Write,
    path::{Path, PathBuf},
};

use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
use flate2::{write::GzEncoder, Compression};

use crate::{
    error::Action,
    messages::{MsgExecHelper, MsgStoreCodeHelper},
    Address, AddressHrp, Cosmos, HasAddress, HasAddressHrp, HasCosmos, TxBuilder, TxMessage,
    TxResponseExt, Wallet,
};

/// Represents the uploaded code on a specific blockchain connection.
#[derive(Clone)]
pub struct CodeId {
    pub(crate) code_id: u64,
    pub(crate) client: Cosmos,
}

impl CodeId {
    /// Get the underlying numeric code ID.
    pub fn get_code_id(&self) -> u64 {
        self.code_id
    }

    /// Download the WASM content of this code ID.
    pub async fn download(&self) -> Result<Vec<u8>, crate::Error> {
        self.client.code_info(self.code_id).await
    }
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
        source: Option<PathBuf>,
    ) -> Result<CodeId, crate::Error> {
        // https://github.com/cosmos/cosmjs/blob/f944892fd337af1ae8b5b269d2b2f68cdf2ad6cb/packages/cosmwasm-stargate/src/signingcosmwasmclient.ts#L67
        let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::new(9));
        gzip_encoder
            .write_all(&wasm_byte_code)
            .map_err(|err| crate::Error::WasmGzipFailed { source: err })?;
        let wasm_byte_code = gzip_encoder
            .finish()
            .map_err(|err| crate::Error::WasmGzipFailed { source: err })?;

        let msg = MsgStoreCodeHelper {
            sender: wallet.get_address(),
            wasm_byte_code,
            source,
        };
        let mut txbuilder = TxBuilder::default();
        txbuilder.add_message(msg);
        let res = txbuilder.sign_and_broadcast(self, wallet).await?;

        Ok(
            self.make_code_id(res.parse_first_stored_code_id().map_err(|source| {
                crate::Error::ChainParse {
                    source: source.into(),
                    action: Action::Broadcast(txbuilder),
                }
            })?),
        )
    }

    /// Convenience wrapper for [Cosmos::store_code] that works on file paths
    pub async fn store_code_path(
        &self,
        wallet: &Wallet,
        path: impl AsRef<Path>,
    ) -> Result<CodeId, crate::Error> {
        let path = path.as_ref();
        let wasm_byte_code =
            fs_err::read(path).map_err(|source| crate::Error::LoadingWasmFromFile {
                path: path.to_owned(),
                source,
            })?;
        self.store_code(wallet, wasm_byte_code, Some(path.to_owned()))
            .await
    }

    /// Like [Self::store_code_path], but uses the authz grant mechanism
    pub async fn store_code_path_authz(
        &self,
        wallet: &Wallet,
        path: impl AsRef<Path>,
        granter: Address,
    ) -> Result<(TxResponse, CodeId), crate::Error> {
        let path = path.as_ref();
        let wasm_byte_code =
            fs_err::read(path).map_err(|source| crate::Error::LoadingWasmFromFile {
                path: path.to_owned(),
                source,
            })?;
        let store_code = MsgStoreCodeHelper {
            sender: granter.get_address(),
            wasm_byte_code,
            source: Some(path.to_owned()),
        };

        let mut txbuilder = TxBuilder::default();
        let msg = MsgExecHelper {
            grantee: wallet.get_address(),
            msgs: vec![TxMessage::from(store_code)],
        };
        txbuilder.add_message(msg);
        let res = txbuilder.sign_and_broadcast(self, wallet).await?;
        let code_id = self.make_code_id(res.parse_first_stored_code_id().map_err(|source| {
            crate::Error::ChainParse {
                source: source.into(),
                action: Action::Broadcast(txbuilder),
            }
        })?);
        Ok((res, code_id))
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

impl HasAddressHrp for CodeId {
    fn get_address_hrp(&self) -> AddressHrp {
        self.client.get_address_hrp()
    }
}
