use std::{fmt::Display, str::FromStr};

use anyhow::{anyhow, Context, Result};
use cosmos_sdk_proto::{
    cosmos::{
        base::{abci::v1beta1::TxResponse, v1beta1::Coin},
        tx::v1beta1::SimulateResponse,
    },
    cosmwasm::wasm::v1::{
        ContractInfo, MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract,
        QueryContractHistoryResponse,
    },
};

use crate::address::HasAddressType;
use crate::{Address, CodeId, Cosmos, HasAddress, HasCosmos, TxBuilder, Wallet};

/// A Cosmos smart contract
#[derive(Clone)]
pub struct Contract {
    address: Address,
    client: Cosmos,
}

impl Contract {
    pub fn new(client: Cosmos, address: Address) -> Self {
        Contract { address, client }
    }
}

pub trait HasContract: HasAddress + HasCosmos {
    fn get_contract(&self) -> &Contract;
}

impl HasContract for Contract {
    fn get_contract(&self) -> &Contract {
        self
    }
}

impl<T: HasContract> HasContract for &T {
    fn get_contract(&self) -> &Contract {
        HasContract::get_contract(*self)
    }
}

impl Cosmos {
    pub fn make_contract(&self, address: Address) -> Contract {
        Contract {
            address,
            client: self.clone(),
        }
    }

    pub fn make_code_id(&self, code_id: u64) -> CodeId {
        CodeId {
            client: self.clone(),
            code_id,
        }
    }
}

impl CodeId {
    pub async fn instantiate(
        &self,
        wallet: &Wallet,
        label: impl Into<String>,
        funds: Vec<Coin>,
        msg: impl serde::Serialize,
        admin: ContractAdmin,
    ) -> Result<Contract> {
        self.instantiate_binary(wallet, label, funds, serde_json::to_vec(&msg)?, admin)
            .await
    }

    /// Same as [CodeId::instantiate] but the message is already in binary.
    pub async fn instantiate_binary(
        &self,
        wallet: &Wallet,
        label: impl Into<String>,
        funds: Vec<Coin>,
        msg: impl Into<Vec<u8>>,
        admin: ContractAdmin,
    ) -> Result<Contract> {
        let msg = MsgInstantiateContract {
            sender: wallet.address().to_string(),
            admin: match admin {
                ContractAdmin::NoAdmin => "".to_owned(),
                ContractAdmin::Sender => wallet.get_address_string(),
                ContractAdmin::Addr(addr) => addr.get_address_string(),
            },
            code_id: self.code_id,
            label: label.into(),
            msg: msg.into(),
            funds,
        };
        let res = wallet.broadcast_message(&self.client, msg).await?;

        for log in &res.logs {
            for event in &log.events {
                if event.r#type == "instantiate" {
                    for attr in &event.attributes {
                        if attr.key == "_contract_address" {
                            let address: Address = attr.value.parse()?;
                            anyhow::ensure!(
                                address.get_address_type() == self.client.get_address_type()
                            );
                            return Ok(Contract {
                                address,
                                client: self.client.clone(),
                            });
                        }
                    }
                }
            }
        }

        Err(anyhow!(
            "Missing _contract_address in instantiate_contract response: {res:?}"
        ))
    }
}

impl Contract {
    pub async fn execute(
        &self,
        wallet: &Wallet,
        funds: Vec<Coin>,
        msg: impl serde::Serialize,
    ) -> Result<TxResponse> {
        self.execute_binary(wallet, funds, serde_json::to_vec(&msg)?)
            .await
    }

    pub fn add_message(
        &self,
        txbuilder: &mut TxBuilder,
        wallet: &Wallet,
        funds: Vec<Coin>,
        msg: impl serde::Serialize,
    ) -> Result<()> {
        txbuilder.add_message_mut(MsgExecuteContract {
            sender: wallet.get_address_string(),
            contract: self.get_address_string(),
            msg: serde_json::to_vec(&msg)?,
            funds,
        });
        Ok(())
    }

    pub async fn simulate(
        &self,
        wallet: &Wallet,
        funds: Vec<Coin>,
        msg: impl serde::Serialize,
    ) -> Result<SimulateResponse> {
        self.simulate_binary(wallet, funds, serde_json::to_vec(&msg)?)
            .await
    }

    /// Same as [Contract::execute] but the msg is serialized
    pub async fn execute_binary(
        &self,
        wallet: &Wallet,
        funds: Vec<Coin>,
        msg: impl Into<Vec<u8>>,
    ) -> Result<TxResponse> {
        let msg = MsgExecuteContract {
            sender: wallet.address().to_string(),
            contract: self.address.to_string(),
            msg: msg.into(),
            funds,
        };
        wallet.broadcast_message(&self.client, msg).await
    }

    /// Same as [Contract::simulate] but the msg is serialized
    pub async fn simulate_binary(
        &self,
        wallet: &Wallet,
        funds: Vec<Coin>,
        msg: impl Into<Vec<u8>>,
    ) -> Result<SimulateResponse> {
        let msg = MsgExecuteContract {
            sender: wallet.address().to_string(),
            contract: self.address.to_string(),
            msg: msg.into(),
            funds,
        };
        TxBuilder::default()
            .add_message(msg)
            .simulate(&self.client, wallet)
            .await
            .map(|x| x.simres)
    }

    /// Perform a query and return the raw unparsed JSON bytes.
    pub async fn query_raw(&self, msg: impl serde::Serialize) -> Result<Vec<u8>> {
        self.client
            .wasm_query(self.address, serde_json::to_vec(&msg)?)
            .await
    }

    /// Perform a query and return the raw unparsed JSON bytes.
    pub async fn query_raw_at_height(
        &self,
        msg: impl serde::Serialize,
        height: u64,
    ) -> Result<Vec<u8>> {
        self.client
            .wasm_query_at_height(self.address, serde_json::to_vec(&msg)?, height)
            .await
    }

    pub async fn query<T: serde::de::DeserializeOwned>(
        &self,
        msg: impl serde::Serialize,
    ) -> Result<T> {
        serde_json::from_slice(&self.query_raw(msg).await?)
            .context("Invalid JSON response from smart contract query")
    }

    pub async fn query_at_height<T: serde::de::DeserializeOwned>(
        &self,
        msg: impl serde::Serialize,
        height: u64,
    ) -> Result<T> {
        serde_json::from_slice(&self.query_raw_at_height(msg, height).await?)
            .context("Invalid JSON response from smart contract query")
    }

    pub async fn migrate(
        &self,
        wallet: &Wallet,
        code_id: u64,
        msg: impl serde::Serialize,
    ) -> Result<()> {
        self.migrate_binary(wallet, code_id, serde_json::to_vec(&msg)?)
            .await
    }

    /// Same as [Contract::migrate] but the msg is serialized
    pub async fn migrate_binary(
        &self,
        wallet: &Wallet,
        code_id: u64,
        msg: impl Into<Vec<u8>>,
    ) -> Result<()> {
        let msg = MsgMigrateContract {
            sender: wallet.address().to_string(),
            contract: self.address.to_string(),
            msg: msg.into(),
            code_id,
        };
        wallet.broadcast_message(&self.client, msg).await?;
        Ok(())
    }

    /// Get the contract info metadata
    pub async fn info(&self) -> Result<ContractInfo> {
        self.client.contract_info(&self.address).await
    }

    /// Get the contract history
    pub async fn history(&self) -> Result<QueryContractHistoryResponse> {
        self.client.contract_history(&self.address).await
    }
}

impl Display for Contract {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl HasAddress for Contract {
    fn get_address(&self) -> Address {
        self.address
    }
}

impl HasCosmos for Contract {
    fn get_cosmos(&self) -> &Cosmos {
        &self.client
    }
}

/// The on-chain admin for a contract set during instantiation
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ContractAdmin {
    NoAdmin,
    Sender,
    Addr(Address),
}

impl FromStr for ContractAdmin {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "no-admin" => Ok(ContractAdmin::NoAdmin),
            "sender" => Ok(ContractAdmin::Sender),
            _ => s.parse().map(ContractAdmin::Addr).map_err(|_| anyhow::anyhow!("Invalid contract admin. Must be 'no-admin', 'sender', or a valid address. Received: {s:?}"))
        }
    }
}
