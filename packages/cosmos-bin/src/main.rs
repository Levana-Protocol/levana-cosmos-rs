mod authz;
mod chain;
mod contract;
mod nft;
mod parsed_coin;
mod tokenfactory;

use std::{io::Write, path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::{CommandFactory, Parser};
use cosmos::{
    proto::{
        cosmos::base::abci::v1beta1::TxResponse,
        cosmwasm::wasm::v1::{
            ContractCodeHistoryEntry, ContractInfo, MsgExecuteContract,
            QueryContractHistoryResponse,
        },
    },
    Address, AddressAnyHrp, AddressType, BlockInfo, CodeId, Coin, CosmosNetwork, HasAddress,
    HasAddressType, RawAddress, RawWallet, TxBuilder, Wallet,
};
use parsed_coin::ParsedCoin;

/// Command line tool for common Levana NFT activities
#[derive(clap::Parser)]
struct Cmd {
    #[clap(flatten)]
    opt: Opt,
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Parser)]
struct Opt {
    /// Network to use, either mainnet or testnet
    #[clap(
        long,
        default_value_t = CosmosNetwork::OsmosisTestnet,
        env = "COSMOS_NETWORK",
        global = true
    )]
    network: CosmosNetwork,
    /// Override gRPC endpoint
    #[clap(long, env = "COSMOS_GRPC", global = true)]
    cosmos_grpc: Option<String>,
    /// Turn on verbose output
    #[clap(long, short, global = true)]
    verbose: bool,

    /// Gas multiplier for simulated transactions
    #[clap(
        long,
        short,
        global = true,
        default_value = None,
        env = "COSMOS_GAS_MULTIPLIER"
    )]
    gas_multiplier: Option<f64>,
}

impl Opt {
    fn init_logger(&self) {
        let env = env_logger::Env::default().default_filter_or(if self.verbose {
            format!("{}=debug,cosmos=debug,info", env!("CARGO_CRATE_NAME"))
        } else {
            "info".to_owned()
        });
        env_logger::Builder::from_env(env).init();
    }
}

#[derive(clap::Parser)]
struct TxOpt {
    /// Mnemonic phrase
    #[clap(long, env = "COSMOS_WALLET")]
    wallet: RawWallet,
    /// Memo to put on transaction
    #[clap(long)]
    memo: Option<String>,
}

impl TxOpt {
    pub(crate) fn get_wallet(&self, address_type: AddressType) -> Wallet {
        self.wallet.for_chain(address_type)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cmd = Cmd::parse();
    cmd.opt.init_logger();

    cmd.subcommand.go(cmd.opt).await
}

#[derive(clap::Parser)]
enum Subcommand {
    /// Upload contract
    StoreCode {
        #[clap(flatten)]
        tx_opt: TxOpt,
        file: PathBuf,
    },
    /// Instantiate contract
    InstantiateContract {
        #[clap(flatten)]
        tx_opt: TxOpt,
        /// Code to deploy
        code_id: u64,
        /// Label to display
        label: String,
        /// Instantiate message (JSON)
        msg: String,
    },
    /// Print balances
    PrintBalances {
        /// Address on COSMOS blockchain
        address: String,
    },
    /// Query contract
    QueryContract {
        /// Contract address
        address: String,
        /// Query (in JSON)
        query: String,
        /// Optional Height. Use latest if not passed.
        height: Option<u64>,
    },
    /// Look up a raw value in the contract's storage
    RawQueryContract {
        /// Contract address
        address: String,
        /// Key
        key: String,
        /// Optional Height. Use latest if not passed.
        height: Option<u64>,
    },
    /// Migrate contract
    MigrateContract {
        #[clap(flatten)]
        tx_opt: TxOpt,
        /// Contract address
        address: Address,
        /// New code ID
        code_id: u64,
        /// Migrate message (JSON)
        msg: String,
    },
    /// Execute contract
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
        /// Skip the simulate phase and hard-code the given gas request instead
        #[clap(long)]
        skip_simulate: Option<u64>,
    },
    /// Simulate executing a message, but don't actually do it
    SimulateContract {
        #[clap(flatten)]
        tx_opt: TxOpt,
        /// Contract address
        address: Address,
        /// Execute message (JSON)
        msg: String,
        /// Funds. Example 100ujunox
        funds: Option<String>,
    },
    /// Generate wallet
    GenWallet {
        /// Address type, supports any valid Human Readable Part like cosmos, osmo, or juno
        address_type: String,
    },
    /// Print the address for the given phrase
    PrintAddress {
        /// Address type: One of cosmos, juno, osmo or levana
        address_type: AddressType,
        /// Phrase
        phrase: RawWallet,
    },
    /// Send coins to the given address
    SendCoins {
        #[clap(flatten)]
        tx_opt: TxOpt,
        /// Destination address
        dest: Address,
        /// Coins to send
        coins: Vec<ParsedCoin>,
    },
    /// Get contract metadata
    ContractInfo { contract: Address },
    /// Show transaction details
    ShowTx {
        txhash: String,
        /// Show all the data in the transaction?
        #[clap(long)]
        complete: bool,
        /// Pretty-print JSON output?
        #[clap(long)]
        pretty: bool,
    },
    /// List transactions for a given wallet
    ListTxsFor {
        address: Address,
        /// Maximum number of transactions to return
        #[clap(long)]
        limit: Option<u64>,
        /// Offset
        #[clap(long)]
        offset: Option<u64>,
    },
    /// Get the contract history
    ContractHistory { contract: Address },
    /// Generate bash shell completion script
    GenerateShellCompletions {
        /// Which shell to generate for
        #[clap(default_value_t = clap_complete::Shell::Bash)]
        shell: clap_complete::Shell,
    },
    /// Show block metadata and transaction hashes within the block
    ShowBlock {
        /// Height of the block to show
        height: i64,
    },
    /// Print the address for a different chain
    ChangeAddressType {
        /// Original address
        orig: RawAddress,
        /// Destination address type
        address_type: AddressType,
    },
    /// NFT focused subcommands
    Nft {
        #[clap(flatten)]
        opt: nft::Opt,
        #[clap(subcommand)]
        subcommand: nft::Subcommand,
    },
    /// Smart contract subcommands
    Contract {
        #[clap(flatten)]
        opt: contract::Opt,
    },
    /// Information about the chain
    Chain {
        #[clap(flatten)]
        opt: chain::Opt,
    },

    /// Tokenfactory operations
    TokenFactory {
        /// Mnemonic phrase
        #[clap(long, env = "COSMOS_WALLET")]
        wallet: RawWallet,

        #[clap(subcommand)]
        cmd: tokenfactory::Command,
    },
    /// Authz operations
    Authz {
        #[clap(flatten)]
        opt: authz::Opt,
    },
}

impl Subcommand {
    pub(crate) async fn go(self, opt: Opt) -> Result<()> {
        let mut builder = opt.network.builder();
        if let Some(grpc) = opt.cosmos_grpc {
            builder.grpc_url = grpc;
        }
        let cosmos = builder.build_lazy();
        let address_type = cosmos.get_address_type();

        if let Some(gas_multiplier) = opt.gas_multiplier {
            cosmos.set_gas_multiplier(gas_multiplier);
        }

        match self {
            Subcommand::StoreCode { tx_opt, file } => {
                let wallet = tx_opt.get_wallet(address_type);
                let codeid = cosmos.store_code_path(&wallet, &file).await?;
                println!("Code ID: {codeid}");
            }
            Subcommand::InstantiateContract {
                tx_opt,
                code_id,
                label,
                msg,
            } => {
                let contract = CodeId::new(cosmos, code_id)
                    .instantiate_binary(&tx_opt.get_wallet(address_type), label, vec![], msg)
                    .await?;
                println!("Contract: {contract}");
            }
            Subcommand::PrintBalances { address } => {
                let balances = cosmos.all_balances(address).await?;
                for Coin { denom, amount } in &balances {
                    println!("{amount}{denom}");
                }
                if balances.is_empty() {
                    println!("0");
                }
            }
            Subcommand::QueryContract {
                address,
                query,
                height,
            } => {
                let x = match height {
                    Some(height) => cosmos.wasm_query_at_height(address, query, height).await?,
                    None => cosmos.wasm_query(address, query).await?,
                };
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                stdout.write_all(&x)?;
                stdout.write_all(b"\n")?;
            }
            Subcommand::RawQueryContract {
                address,
                key,
                height,
            } => {
                let x = match height {
                    Some(height) => {
                        cosmos
                            .wasm_raw_query_at_height(address, key, height)
                            .await?
                    }
                    None => cosmos.wasm_raw_query(address, key).await?,
                };
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                stdout.write_all(&x)?;
                stdout.write_all(b"\n")?;
            }
            Subcommand::MigrateContract {
                tx_opt,
                address,
                code_id,
                msg,
            } => {
                let contract = cosmos::Contract::new(cosmos, address);
                contract
                    .migrate_binary(&tx_opt.get_wallet(address_type), code_id, msg)
                    .await?;
            }
            Subcommand::ExecuteContract {
                tx_opt,
                address,
                msg,
                funds: amount,
                skip_simulate,
            } => {
                let contract = cosmos::Contract::new(cosmos.clone(), address);
                let amount = match amount {
                    Some(funds) => {
                        let coin = ParsedCoin::from_str(&funds)?.into();
                        vec![coin]
                    }
                    None => vec![],
                };
                let wallet = tx_opt.get_wallet(address_type);

                let mut tx_builder = TxBuilder::default();
                tx_builder.add_message_mut(MsgExecuteContract {
                    sender: wallet.get_address_string(),
                    contract: contract.get_address_string(),
                    msg: msg.into_bytes(),
                    funds: amount,
                });

                let tx = match skip_simulate {
                    Some(gas_to_request) => {
                        tx_builder
                            .sign_and_broadcast_with_gas(&cosmos, &wallet, gas_to_request)
                            .await?
                    }
                    None => tx_builder.sign_and_broadcast(&cosmos, &wallet).await?,
                };

                println!("Transaction hash: {}", tx.txhash);
                println!("Raw log: {}", tx.raw_log);
                log::debug!("{tx:?}");
            }
            Subcommand::GenWallet { address_type } => gen_wallet(&address_type)?,
            Subcommand::PrintAddress {
                address_type,
                phrase,
            } => {
                println!("{}", phrase.for_chain(address_type));
            }
            Subcommand::SendCoins {
                tx_opt,
                dest,
                coins,
            } => {
                let txres = tx_opt
                    .get_wallet(address_type)
                    .send_coins(&cosmos, dest, coins.into_iter().map(|x| x.into()).collect())
                    .await?;

                println!("{}", txres.txhash);
            }
            Subcommand::ContractInfo { contract } => {
                let ContractInfo {
                    code_id,
                    creator,
                    admin,
                    label,
                    created: _,
                    ibc_port_id: _,
                    extension: _,
                } = cosmos.make_contract(contract).info().await?;
                println!("code_id: {code_id}");
                println!("creator: {creator}");
                println!("admin: {admin}");
                println!("label: {label}");
            }
            Subcommand::ShowTx {
                txhash,
                complete,
                pretty,
            } => {
                let TxResponse {
                    height,
                    txhash: _,
                    codespace,
                    code,
                    data,
                    raw_log,
                    logs,
                    info,
                    gas_wanted,
                    gas_used,
                    tx: _,
                    timestamp,
                    events,
                } = cosmos.wait_for_transaction(txhash).await?;
                println!("Height: {height}");
                println!("Code: {code}");
                println!("Codespace: {codespace}");
                if pretty {
                    match serde_json::from_str::<serde_json::Value>(&raw_log) {
                        Err(_) => println!("Raw log is not JSON: {raw_log}"),
                        Ok(raw_log) => serde_json::to_writer_pretty(std::io::stdout(), &raw_log)?,
                    }
                } else {
                    println!("Raw log: {raw_log}");
                }
                println!("Info: {info}");
                println!("Gas wanted: {gas_wanted}");
                println!("Gas used: {gas_used}");
                println!("Timestamp: {timestamp}");
                if complete {
                    println!("Data: {data}");
                    for (idx, log) in logs.into_iter().enumerate() {
                        println!("Log #{idx}: {log:?}");
                    }
                    for (idx, event) in events.into_iter().enumerate() {
                        println!("Event #{idx}: {event:?}");
                    }
                }
            }
            Subcommand::ListTxsFor {
                address,
                limit,
                offset,
            } => {
                for txhash in cosmos.list_transactions_for(address, limit, offset).await? {
                    println!("{txhash}");
                }
            }
            Subcommand::ContractHistory { contract } => {
                let QueryContractHistoryResponse {
                    entries,
                    pagination: _,
                } = cosmos.make_contract(contract).history().await?;
                for ContractCodeHistoryEntry {
                    operation,
                    code_id,
                    updated,
                    msg,
                } in entries
                {
                    println!("Operation: {operation}. Code ID: {code_id}. Updated: {updated:?}. Message: {:?}", String::from_utf8(msg))
                }
            }
            Subcommand::GenerateShellCompletions { shell } => {
                clap_complete::generate(
                    shell,
                    &mut Subcommand::command(),
                    "levana",
                    &mut std::io::stdout(),
                );
            }
            Subcommand::SimulateContract {
                tx_opt,
                address,
                msg,
                funds,
            } => {
                let contract = cosmos::Contract::new(cosmos.clone(), address);
                let amount = match funds {
                    Some(funds) => {
                        let coin = ParsedCoin::from_str(&funds)?.into();
                        vec![coin]
                    }
                    None => vec![],
                };
                let simres = contract
                    .simulate_binary(&tx_opt.get_wallet(address_type), amount, msg)
                    .await?;
                println!("{simres:?}");
            }
            Subcommand::ShowBlock { height } => {
                let BlockInfo {
                    height,
                    timestamp,
                    txhashes,
                    block_hash,
                } = cosmos.get_block_info(height).await?;
                println!("Height: {height}");
                println!("Timestamp: {timestamp}");
                println!("Block hash: {block_hash}");
                for (idx, txhash) in txhashes.into_iter().enumerate() {
                    println!("Transaction #{}: {txhash}", idx + 1);
                }
            }
            Subcommand::ChangeAddressType { orig, address_type } => {
                println!("{}", orig.for_chain(address_type));
            }
            Subcommand::Nft { opt, subcommand } => {
                nft::go(subcommand, opt, cosmos).await?;
            }
            Subcommand::Contract { opt } => {
                contract::go(opt, cosmos).await?;
            }
            Subcommand::Chain { opt } => chain::go(opt, cosmos).await?,
            Subcommand::TokenFactory { cmd, wallet } => {
                tokenfactory::go(cosmos, wallet, cmd).await?
            }
            Subcommand::Authz { opt } => authz::go(cosmos, opt).await?,
        }

        Ok(())
    }
}

fn gen_wallet(address_type: &str) -> Result<()> {
    let phrase = cosmos::Wallet::generate_phrase();
    let wallet = cosmos::Wallet::from_phrase(&phrase, AddressType::Cosmos)?;
    println!("Mnemonic: {phrase}");
    let address = AddressAnyHrp {
        raw_address: *wallet.address().raw(),
        hrp: address_type,
    };
    println!("Address: {address}");
    Ok(())
}
