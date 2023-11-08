use std::{fmt::Display, str::FromStr};

use cosmos_sdk_proto::{
    cosmos::{
        base::{abci::v1beta1::TxResponse, v1beta1::Coin},
        tx::v1beta1::SimulateResponse,
    },
    cosmwasm::wasm::v1::{
        ContractInfo, MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract,
        QueryContractHistoryRequest, QueryContractHistoryResponse, QueryContractInfoRequest,
        QueryRawContractStateRequest, QuerySmartContractStateRequest,
    },
};

use crate::{
    address::{AddressHrp, HasAddressHrp},
    error::{Action, ContractAdminParseError, QueryError},
    TxResponseExt,
};
use crate::{Address, CodeId, Cosmos, HasAddress, HasCosmos, TxBuilder, Wallet};

/// A Cosmos smart contract
#[derive(Clone)]
pub struct Contract {
    address: Address,
    client: Cosmos,
}

/// Trait for anything which has an underlying contract
///
/// This is intended for use with helper newtype wrappers which provide a higher
/// level interface for specific contracts.
pub trait HasContract: HasAddress + HasCosmos {
    /// Get the underlying [Contract].
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
    /// Make a new [Contract] for the given smart contract address.
    pub fn make_contract(&self, address: Address) -> Contract {
        Contract {
            address,
            client: self.clone(),
        }
    }

    /// Make a new [CodeId] for the given numeric ID.
    pub fn make_code_id(&self, code_id: u64) -> CodeId {
        CodeId {
            client: self.clone(),
            code_id,
        }
    }
}

impl CodeId {
    /// Instantiate a new contract with the given parameters.
    pub async fn instantiate(
        &self,
        wallet: &Wallet,
        label: impl Into<String>,
        funds: Vec<Coin>,
        msg: impl serde::Serialize,
        admin: ContractAdmin,
    ) -> Result<Contract, crate::Error> {
        self.instantiate_rendered(wallet, label, funds, serde_json::to_string(&msg)?, admin)
            .await
    }

    /// Same as [CodeId::instantiate] but the message is already rendered to text.
    pub async fn instantiate_rendered(
        &self,
        wallet: &Wallet,
        label: impl Into<String>,
        funds: Vec<Coin>,
        msg: impl Into<String>,
        admin: ContractAdmin,
    ) -> Result<Contract, crate::Error> {
        let msg = msg.into();
        let msg = MsgInstantiateContract {
            sender: wallet.get_address().to_string(),
            admin: match admin {
                ContractAdmin::NoAdmin => "".to_owned(),
                ContractAdmin::Sender => wallet.get_address_string(),
                ContractAdmin::Addr(addr) => addr.get_address_string(),
            },
            code_id: self.code_id,
            label: label.into(),
            msg: msg.into_bytes(),
            funds,
        };
        let mut txbuilder = TxBuilder::default();
        txbuilder.add_message(msg);
        let res = txbuilder.sign_and_broadcast(&self.client, wallet).await?;

        let addr =
            res.parse_first_instantiated_contract()
                .map_err(|source| crate::Error::ChainParse {
                    source,
                    action: Action::Broadcast(txbuilder.clone()),
                })?;

        if addr.get_address_hrp() == self.get_address_hrp() {
            Ok(self.client.make_contract(addr))
        } else {
            Err(crate::Error::InvalidChainResponse {
                message: format!(
                    "Network has address HRP {}, but new contract {} has HRP {}",
                    self.get_address_hrp(),
                    addr,
                    addr.get_address_hrp()
                ),
                action: Action::Broadcast(txbuilder),
            })
        }
    }
}

impl Contract {
    /// Execute a message against the smart contract.
    pub async fn execute(
        &self,
        wallet: &Wallet,
        funds: Vec<Coin>,
        msg: impl serde::Serialize,
    ) -> Result<TxResponse, crate::Error> {
        self.execute_rendered(
            wallet,
            funds,
            serde_json::to_string(&msg).map_err(crate::Error::JsonSerialize)?,
        )
        .await
    }

    /// Simulate executing a message against this contract.
    pub async fn simulate(
        &self,
        wallet: &Wallet,
        funds: Vec<Coin>,
        msg: impl serde::Serialize,
        memo: Option<String>,
    ) -> Result<SimulateResponse, crate::Error> {
        self.simulate_binary(
            wallet,
            funds,
            serde_json::to_vec(&msg).map_err(crate::Error::JsonSerialize)?,
            memo,
        )
        .await
    }

    /// Same as [Contract::execute] but the msg is serialized
    pub async fn execute_rendered(
        &self,
        wallet: &Wallet,
        funds: Vec<Coin>,
        msg: impl Into<Vec<u8>>,
    ) -> Result<TxResponse, crate::Error> {
        let msg = MsgExecuteContract {
            sender: wallet.get_address_string(),
            contract: self.address.to_string(),
            msg: msg.into(),
            funds,
        };
        wallet.broadcast_message(&self.client, msg).await
    }

    /// Same as [Contract::simulate] but the msg is serialized
    pub async fn simulate_binary(
        &self,
        wallet: impl HasAddress,
        funds: Vec<Coin>,
        msg: impl Into<Vec<u8>>,
        memo: Option<String>,
    ) -> Result<SimulateResponse, crate::Error> {
        let msg = MsgExecuteContract {
            sender: wallet.get_address().to_string(),
            contract: self.address.to_string(),
            msg: msg.into(),
            funds,
        };
        let mut builder = TxBuilder::default();
        builder.add_message(msg);
        if let Some(memo) = memo {
            builder.set_memo(memo);
        }
        builder
            .simulate(&self.client, &[wallet.get_address()])
            .await
            .map(|x| x.simres)
    }

    /// Perform a raw query
    pub async fn query_raw(&self, key: impl Into<Vec<u8>>) -> Result<Vec<u8>, crate::Error> {
        let key = key.into();
        Ok(self
            .client
            .perform_query(
                QueryRawContractStateRequest {
                    address: self.address.into(),
                    query_data: key.clone(),
                },
                Action::RawQuery {
                    contract: self.address,
                    key: key.into(),
                },
                true,
            )
            .await?
            .into_inner()
            .data)
    }

    /// Return a modified [Contract] that queries at the given height.
    pub fn at_height(mut self, height: Option<u64>) -> Self {
        self.client = self.client.at_height(height);
        self
    }

    /// Perform a query and return the raw unparsed JSON bytes.
    pub async fn query_bytes(&self, msg: impl serde::Serialize) -> Result<Vec<u8>, crate::Error> {
        self.query_rendered_bytes(serde_json::to_vec(&msg).map_err(crate::Error::JsonSerialize)?)
            .await
            .map_err(|e| e.into())
    }

    /// Like [Self::query_bytes], but the provided message is already serialized.
    pub async fn query_rendered_bytes(
        &self,
        msg: impl Into<Vec<u8>>,
    ) -> Result<Vec<u8>, QueryError> {
        let msg = msg.into();
        let res = self
            .client
            .perform_query(
                QuerySmartContractStateRequest {
                    address: self.address.into(),
                    query_data: msg.clone(),
                },
                Action::SmartQuery {
                    contract: self.address,
                    message: msg.into(),
                },
                true,
            )
            .await?
            .into_inner();
        Ok(res.data)
    }

    /// Perform a smart contract query and parse the resulting response as JSON.
    pub async fn query<T: serde::de::DeserializeOwned>(
        &self,
        msg: impl serde::Serialize,
    ) -> Result<T, crate::Error> {
        self.query_rendered(serde_json::to_vec(&msg)?).await
    }

    /// Like [Self::query], but the provided message is already serialized.
    pub async fn query_rendered<T: serde::de::DeserializeOwned>(
        &self,
        msg: impl Into<Vec<u8>>,
    ) -> Result<T, crate::Error> {
        let msg = msg.into();
        let action = Action::SmartQuery {
            contract: self.address,
            message: msg.clone().into(),
        };
        let res = self
            .client
            .perform_query(
                QuerySmartContractStateRequest {
                    address: self.address.into(),
                    query_data: msg,
                },
                action.clone(),
                true,
            )
            .await?
            .into_inner();
        serde_json::from_slice(&res.data)
            .map_err(|source| crate::Error::JsonDeserialize { source, action })
    }

    /// Perform a contract migration with the given message
    pub async fn migrate(
        &self,
        wallet: &Wallet,
        code_id: u64,
        msg: impl serde::Serialize,
    ) -> Result<(), crate::Error> {
        self.migrate_binary(wallet, code_id, serde_json::to_vec(&msg)?)
            .await
    }

    /// Same as [Contract::migrate] but the msg is serialized
    pub async fn migrate_binary(
        &self,
        wallet: &Wallet,
        code_id: u64,
        msg: impl Into<Vec<u8>>,
    ) -> Result<(), crate::Error> {
        let msg = MsgMigrateContract {
            sender: wallet.get_address_string(),
            contract: self.get_address_string(),
            msg: msg.into(),
            code_id,
        };
        wallet.broadcast_message(&self.client, msg).await?;
        Ok(())
    }

    /// Get the contract info metadata
    pub async fn info(&self) -> Result<ContractInfo, crate::Error> {
        let action = Action::ContractInfo(self.address);
        self.client
            .perform_query(
                QueryContractInfoRequest {
                    address: self.address.into(),
                },
                action.clone(),
                true,
            )
            .await?
            .into_inner()
            .contract_info
            .ok_or_else(|| crate::Error::InvalidChainResponse {
                message: "Missing contract_info field".to_string(),
                action,
            })
    }

    /// Get the contract history
    pub async fn history(&self) -> Result<QueryContractHistoryResponse, crate::Error> {
        Ok(self
            .client
            .perform_query(
                QueryContractHistoryRequest {
                    address: self.address.into(),
                    pagination: None,
                },
                Action::ContractHistory(self.address),
                true,
            )
            .await?
            .into_inner())
    }
}

impl Display for Contract {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl HasAddressHrp for Contract {
    fn get_address_hrp(&self) -> AddressHrp {
        self.get_address().get_address_hrp()
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
    /// No admin set, the contract will never be able to be migrated
    NoAdmin,
    /// Set the admin to the sender of the instantiate message
    Sender,
    /// Set the admin to the given address
    Addr(Address),
}

impl FromStr for ContractAdmin {
    type Err = ContractAdminParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "no-admin" => Ok(ContractAdmin::NoAdmin),
            "sender" => Ok(ContractAdmin::Sender),
            _ => s
                .parse()
                .map(ContractAdmin::Addr)
                .map_err(|_| ContractAdminParseError {
                    input: s.to_owned(),
                }),
        }
    }
}
