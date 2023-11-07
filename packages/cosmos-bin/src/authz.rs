use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Result;
use base64::Engine;
use chrono::{DateTime, Utc};
use cosmos::{
    proto::{
        cosmos::authz::v1beta1::MsgExec, cosmwasm::wasm::v1::MsgExecuteContract, traits::Message,
    },
    Address, Cosmos, HasAddress, HasAddressHrp, MsgGrantHelper, TxBuilder, TypedMessage,
};

use crate::{my_duration::MyDuration, parsed_coin::ParsedCoin, TxOpt};

#[derive(clap::Parser)]
pub(crate) struct Opt {
    #[clap(subcommand)]
    sub: Subcommand,
}

#[derive(clap::Parser)]
enum Subcommand {
    /// Give the grantee permissions
    Grant {
        grantee: Address,
        /// Type of grant to allow
        grant_type: GrantType,
        #[clap(flatten)]
        tx_opt: TxOpt,
        /// How long the grant lasts
        #[clap(long)]
        duration: MyDuration,
    },
    /// Print a CW3-compatible version of a grant
    Cw3Grant {
        /// CW3 smart contract address
        #[clap(long)]
        granter: Address,
        /// Address allowed to perform actions
        #[clap(long)]
        grantee: Address,
        /// Type of grant to allow
        grant_type: GrantType,
        /// How long, in seconds, the grant lasts
        #[clap(long)]
        duration: MyDuration,
    },
    /// Query grants by the granter
    GranterGrants { granter: Address },
    /// Exec a store-code via a grant
    StoreCode {
        /// Filepath containing the code
        path: PathBuf,
        /// Who granted store-code permissions
        granter: Address,
        #[clap(flatten)]
        tx_opt: TxOpt,
    },
    /// Exec a MsgExecuteContract via a grant
    ExecuteContract {
        #[clap(flatten)]
        tx_opt: TxOpt,
        /// Contract address
        address: Address,
        /// Execute message (JSON)
        msg: String,
        /// Funds. Example 100ujunox
        #[clap(long)]
        funds: Option<String>,
        /// Who we're executing this on behalf of
        #[clap(long)]
        granter: Address,
    },
}

pub(crate) async fn go(cosmos: Cosmos, Opt { sub }: Opt) -> Result<()> {
    match sub {
        Subcommand::Grant {
            grantee,
            tx_opt,
            duration,
            grant_type,
        } => {
            let expiration = Utc::now() + duration.into_chrono_duration()?;
            grant(cosmos, grantee, tx_opt, expiration, grant_type).await?;
        }
        Subcommand::Cw3Grant {
            granter,
            grantee,
            grant_type,
            duration,
        } => {
            let expiration = Utc::now() + duration.into_chrono_duration()?;
            log::debug!("Setting expiration to {expiration}");
            cw3_grant(granter, grantee, expiration, grant_type)?;
        }
        Subcommand::GranterGrants { granter } => granter_grants(cosmos, granter).await?,
        Subcommand::StoreCode {
            path,
            granter,
            tx_opt,
        } => store_code(cosmos, tx_opt, &path, granter).await?,
        Subcommand::ExecuteContract {
            tx_opt,
            address,
            msg,
            funds,
            granter,
        } => execute_contract(cosmos, tx_opt, address, msg, funds, granter).await?,
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum GrantType {
    Send,
    ExecuteContract,
    StoreCode,
}

impl FromStr for GrantType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "send" => Ok(Self::Send),
            "execute-contract" => Ok(Self::ExecuteContract),
            "store-code" => Ok(Self::StoreCode),
            _ => Err(anyhow::anyhow!(
                "Invalid grant type, use one of: send, execute-contract, store-code"
            )),
        }
    }
}

impl GrantType {
    fn as_url(self) -> &'static str {
        match self {
            GrantType::Send => "/cosmos.bank.v1beta1.MsgSend",
            GrantType::ExecuteContract => "/cosmwasm.wasm.v1.MsgExecuteContract",
            GrantType::StoreCode => "/cosmwasm.wasm.v1.MsgStoreCode",
        }
    }
}

async fn grant(
    cosmos: Cosmos,
    grantee: Address,
    tx_opt: TxOpt,
    expiration: DateTime<Utc>,
    grant_type: GrantType,
) -> Result<()> {
    let wallet = tx_opt.get_wallet(cosmos.get_address_hrp())?;
    let mut txbuilder = TxBuilder::default();
    txbuilder.add_message_mut(
        MsgGrantHelper {
            granter: wallet.get_address(),
            grantee,
            authorization: grant_type.as_url().to_owned(),
            expiration: Some(expiration),
        }
        .try_into_msg_grant()?,
    );
    let res = txbuilder.sign_and_broadcast(&cosmos, &wallet).await?;
    log::info!("Granted in {}", res.txhash);
    Ok(())
}

fn cw3_grant(
    granter: Address,
    grantee: Address,
    expiration: DateTime<Utc>,
    grant_type: GrantType,
) -> Result<()> {
    let msg = MsgGrantHelper {
        granter,
        grantee,
        authorization: grant_type.as_url().to_owned(),
        expiration: Some(expiration),
    }
    .try_into_msg_grant()?;
    let msg = msg.encode_to_vec();

    #[derive(serde::Serialize)]
    #[serde(rename_all = "snake_case")]
    enum Msg {
        Stargate { type_url: String, value: String },
    }

    let stargate = Msg::Stargate {
        type_url: "/cosmos.authz.v1beta1.MsgGrant".to_owned(),
        value: into_base64(&msg),
    };

    let mut stdout = std::io::stdout();
    serde_json::to_writer_pretty(&mut stdout, &stargate)?;

    Ok(())
}

fn into_base64(msg: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(msg)
}

async fn granter_grants(cosmos: Cosmos, granter: Address) -> Result<()> {
    for x in cosmos.query_granter_grants(granter).await? {
        log::info!("{x:?}");
    }
    Ok(())
}

async fn store_code(cosmos: Cosmos, tx_opt: TxOpt, path: &Path, granter: Address) -> Result<()> {
    let wallet = tx_opt.get_wallet(cosmos.get_address_hrp())?;
    let (res, code_id) = cosmos.store_code_path_authz(&wallet, path, granter).await?;
    log::info!("Executed in {}", res.txhash);
    log::info!("Code ID: {}", code_id);
    Ok(())
}

async fn execute_contract(
    cosmos: Cosmos,
    tx_opt: TxOpt,
    address: Address,
    msg: String,
    funds: Option<String>,
    granter: Address,
) -> Result<()> {
    let contract = cosmos.make_contract(address);
    let amount = match funds {
        Some(funds) => {
            let coin = ParsedCoin::from_str(&funds)?.into();
            vec![coin]
        }
        None => vec![],
    };
    let wallet = tx_opt.get_wallet(cosmos.get_address_hrp())?;

    let msg_exec_contract = MsgExecuteContract {
        sender: granter.get_address_string(),
        contract: contract.get_address_string(),
        msg: msg.into_bytes(),
        funds: amount,
    };

    let mut txbuilder = TxBuilder::default();
    let msg = MsgExec {
        grantee: wallet.get_address_string(),
        msgs: vec![TypedMessage::from(msg_exec_contract).into_inner()],
    };
    txbuilder.add_message_mut(msg);
    let res = txbuilder.sign_and_broadcast(&cosmos, &wallet).await?;
    log::info!("Executed in {}", res.txhash);
    Ok(())
}
