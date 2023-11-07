use anyhow::{Context, Result};
use cosmos::{Address, ContractAdmin, Cosmos, HasAddress, HasAddressHrp, TxBuilder};
use cosmwasm_std::{to_binary, CosmosMsg, Decimal, Empty, WasmMsg};
use cw3::{ProposalListResponse, ProposalResponse};
use cw4::Member;
use cw_utils::Threshold;

use crate::{my_duration::MyDuration, TxOpt};

#[derive(Clone, Copy, Debug)]
enum ContractType {
    Cw3Flex,
    Cw4Group,
}

fn get_code_id(chain_id: &str, contract_type: ContractType) -> Result<u64> {
    match (chain_id, contract_type) {
        ("osmo-test-5", ContractType::Cw3Flex) => Ok(1519),
        ("osmo-test-5", ContractType::Cw4Group) => Ok(1521),
        ("osmosis-1", ContractType::Cw3Flex) => Ok(100),
        ("osmosis-1", ContractType::Cw4Group) => Ok(101),
        ("pacific-1", ContractType::Cw3Flex) => Ok(46),
        ("pacific-1", ContractType::Cw4Group) => Ok(47),
        ("injective-1", ContractType::Cw3Flex) => Ok(124),
        ("injective-1", ContractType::Cw4Group) => Ok(125),
        _ => Err(anyhow::anyhow!(
            "No code ID found for combo {chain_id}/{contract_type:?}"
        )),
    }
}

#[derive(clap::Parser)]
pub(crate) struct Opt {
    #[clap(subcommand)]
    sub: Subcommand,
}

#[derive(clap::Parser)]
enum Subcommand {
    /// Create a new CW3 flex with a CW4 group behind it. The CW3 becomes the admin for the CW4.
    NewFlex {
        #[clap(flatten)]
        inner: NewFlexOpt,
    },
    /// Print out the JSON command to update the members in a group
    UpdateMembersMessage {
        #[clap(flatten)]
        inner: AddMemberMessageOpt,
    },
    /// Make a new proposal
    Propose {
        #[clap(flatten)]
        inner: ProposeOpt,
    },
    /// List proposals
    List {
        #[clap(flatten)]
        inner: ListOpt,
    },
    /// Vote on an open proposal
    Vote {
        #[clap(flatten)]
        inner: VoteOpt,
    },
    /// Execute a passed proposal
    Execute {
        #[clap(flatten)]
        inner: ExecuteOpt,
    },
    /// Generate a message for a CW3 from a contract execute message
    WasmExecuteMessage {
        #[clap(flatten)]
        inner: WasmExecuteMessageOpt,
    },
    /// Generate a message for a CW3 to migrate a contract
    MigrateContractMessage {
        #[clap(flatten)]
        inner: MigrateContractOpt,
    },
}

pub(crate) async fn go(cosmos: Cosmos, Opt { sub }: Opt) -> Result<()> {
    match sub {
        Subcommand::NewFlex { inner } => new_flex(cosmos, inner).await,
        Subcommand::UpdateMembersMessage { inner } => update_members_message(inner).await,
        Subcommand::Propose { inner } => propose(cosmos, inner).await,
        Subcommand::List { inner } => list(cosmos, inner).await,
        Subcommand::Vote { inner } => vote(cosmos, inner).await,
        Subcommand::Execute { inner } => execute(cosmos, inner).await,
        Subcommand::WasmExecuteMessage { inner } => wasm_execute_message(inner),
        Subcommand::MigrateContractMessage { inner } => migrate_contract_message(inner),
    }
}

#[derive(clap::Parser)]
struct NewFlexOpt {
    /// Equal-weighted voting members of the group
    #[clap(long)]
    member: Vec<Address>,
    #[clap(flatten)]
    tx_opt: TxOpt,
    /// On-chain label used for the CW3
    #[clap(long)]
    label: String,
    /// On-chain label used for the CW4, will be derived from the CW3 label if omitted
    #[clap(long)]
    cw4_label: Option<String>,
    /// Percentage of total weight needed to pass the proposal
    #[clap(long)]
    weight_needed: Decimal,
    /// Duration. Accepts s, m, h, and d suffixes for seconds, minutes, hours, and days
    #[clap(long)]
    duration: MyDuration,
}

async fn new_flex(
    cosmos: Cosmos,
    NewFlexOpt {
        member: members,
        tx_opt,
        label,
        cw4_label,
        weight_needed,
        duration,
    }: NewFlexOpt,
) -> Result<()> {
    let chain_id = &cosmos.get_cosmos_builder().chain_id;
    let wallet = tx_opt.get_wallet(cosmos.get_address_hrp())?;
    let cw3 = cosmos.make_code_id(get_code_id(chain_id, ContractType::Cw3Flex)?);
    let cw4 = cosmos.make_code_id(get_code_id(chain_id, ContractType::Cw4Group)?);

    anyhow::ensure!(!members.is_empty(), "Must provide at least one member");

    // Set up the CW4 with the current wallet as the admin
    let cw4_label = cw4_label.unwrap_or_else(|| format!("{label} - CW4 group"));
    let cw4 = cw4
        .instantiate(
            &wallet,
            cw4_label,
            vec![],
            cw4_group::msg::InstantiateMsg {
                admin: Some(wallet.get_address_string()),
                members: members
                    .into_iter()
                    .map(|addr| Member {
                        addr: addr.get_address_string(),
                        weight: 1,
                    })
                    .collect(),
            },
            ContractAdmin::Sender,
        )
        .await?;
    log::info!("Created new CW4-group contract: {cw4}");

    // Now create the CW3 using this CW4 as its backing group
    let cw3 = cw3
        .instantiate(
            &wallet,
            label,
            vec![],
            cw3_flex_multisig::msg::InstantiateMsg {
                group_addr: cw4.get_address_string(),
                threshold: Threshold::AbsolutePercentage {
                    percentage: weight_needed,
                },
                max_voting_period: duration.into_cw_duration(),
                executor: None,
                proposal_deposit: None,
            },
            ContractAdmin::Sender,
        )
        .await?;
    log::info!("Created new CW3-flex contract: {cw3}");

    // Fix permissions
    log::info!("Fixing permissions on the contracts to make the CW3 the admin");
    let mut builder = TxBuilder::default();
    builder.add_update_contract_admin_mut(&cw3, &wallet, &cw3);
    builder.add_update_contract_admin_mut(&cw4, &wallet, &cw3);
    builder.add_execute_message_mut(
        &cw4,
        &wallet,
        vec![],
        cw4_group::msg::ExecuteMsg::UpdateAdmin {
            admin: Some(cw3.get_address_string()),
        },
    )?;
    let res = builder.sign_and_broadcast(&cosmos, &wallet).await?;
    log::info!("Admin permissions updated in {}", res.txhash);

    Ok(())
}

#[derive(clap::Parser)]
struct AddMemberMessageOpt {
    /// Members to add
    #[clap(long)]
    add: Vec<Address>,
    /// Members to remove
    #[clap(long)]
    remove: Vec<Address>,
    /// CW4 group contract address
    #[clap(long)]
    group: Address,
}

async fn update_members_message(
    AddMemberMessageOpt { add, remove, group }: AddMemberMessageOpt,
) -> Result<()> {
    let msg = cw4_group::msg::ExecuteMsg::UpdateMembers {
        add: add
            .into_iter()
            .map(|x| Member {
                addr: x.get_address_string(),
                weight: 1,
            })
            .collect(),
        remove: remove.into_iter().map(|x| x.get_address_string()).collect(),
    };
    let msg = CosmosMsg::<Empty>::Wasm(WasmMsg::Execute {
        contract_addr: group.get_address_string(),
        msg: to_binary(&msg)?,
        funds: vec![],
    });
    println!("{}", serde_json::to_string(&msg)?);
    Ok(())
}

#[derive(clap::Parser)]
struct ProposeOpt {
    /// CW3 group contract address
    #[clap(long)]
    cw3: Address,
    #[clap(flatten)]
    tx_opt: TxOpt,
    /// Title
    #[clap(long)]
    title: String,
    /// Description, defaults to title
    #[clap(long)]
    description: Option<String>,
    /// Messages, in JSON format
    #[clap(long)]
    msg: Vec<String>,
}

async fn propose(
    cosmos: Cosmos,
    ProposeOpt {
        cw3,
        tx_opt,
        title,
        description,
        msg,
    }: ProposeOpt,
) -> Result<()> {
    let wallet = tx_opt.get_wallet(cosmos.get_address_hrp())?;
    let cw3 = cosmos.make_contract(cw3);
    let res = cw3
        .execute(
            &wallet,
            vec![],
            cw3_flex_multisig::msg::ExecuteMsg::Propose {
                description: description.unwrap_or_else(|| title.clone()),
                title,
                msgs: msg
                    .into_iter()
                    .map(|x| {
                        serde_json::from_str::<CosmosMsg<Empty>>(&x)
                            .context("Invalid CosmosMsg provided")
                    })
                    .collect::<Result<_>>()?,
                latest: None,
            },
        )
        .await?;
    log::info!("Added in {}", res.txhash);
    Ok(())
}

#[derive(clap::Parser)]
struct ListOpt {
    /// CW3 group contract address
    #[clap(long)]
    cw3: Address,
}

async fn list(cosmos: Cosmos, ListOpt { cw3 }: ListOpt) -> Result<()> {
    let cw3 = cosmos.make_contract(cw3);
    let mut start_after = None;
    loop {
        let ProposalListResponse::<Empty> { proposals } = cw3
            .query(cw3_flex_multisig::msg::QueryMsg::ListProposals {
                start_after,
                limit: None,
            })
            .await?;
        match proposals.last() {
            None => break Ok(()),
            Some(proposal) => start_after = Some(proposal.id),
        }
        for ProposalResponse {
            id,
            title,
            description: _,
            msgs: _,
            status,
            expires: _,
            threshold: _,
            proposer: _,
            deposit: _,
        } in proposals
        {
            println!("{id}: {title}. {status:?}");
        }
    }
}

#[derive(clap::Parser)]
struct VoteOpt {
    #[clap(flatten)]
    tx_opt: TxOpt,
    /// CW3 group contract address
    #[clap(long)]
    cw3: Address,
    /// Proposal ID to execute
    #[clap(long)]
    proposal: u64,
    /// How to vote
    #[clap(long)]
    vote: String,
}

async fn vote(
    cosmos: Cosmos,
    VoteOpt {
        tx_opt,
        cw3,
        proposal,
        vote,
    }: VoteOpt,
) -> Result<()> {
    let wallet = tx_opt.get_wallet(cosmos.get_address_hrp())?;
    let cw3 = cosmos.make_contract(cw3);
    let res = cw3
        .execute(
            &wallet,
            vec![],
            cw3_flex_multisig::msg::ExecuteMsg::Vote {
                proposal_id: proposal,
                vote: serde_json::from_value(serde_json::Value::String(vote))?,
            },
        )
        .await?;
    println!("Executed in {}", res.txhash);
    Ok(())
}

#[derive(clap::Parser)]
struct ExecuteOpt {
    #[clap(flatten)]
    tx_opt: TxOpt,
    /// CW3 group contract address
    #[clap(long)]
    cw3: Address,
    /// Proposal ID to execute
    #[clap(long)]
    proposal: u64,
}

async fn execute(
    cosmos: Cosmos,
    ExecuteOpt {
        tx_opt,
        cw3,
        proposal,
    }: ExecuteOpt,
) -> Result<()> {
    let wallet = tx_opt.get_wallet(cosmos.get_address_hrp())?;
    let cw3 = cosmos.make_contract(cw3);
    let res = cw3
        .execute(
            &wallet,
            vec![],
            cw3_flex_multisig::msg::ExecuteMsg::Execute {
                proposal_id: proposal,
            },
        )
        .await?;
    println!("Executed in {}", res.txhash);
    Ok(())
}

#[derive(clap::Parser)]
struct WasmExecuteMessageOpt {
    /// Destination contract address
    #[clap(long)]
    contract: Address,
    /// Message to submit
    #[clap(long)]
    message: String,
}

fn wasm_execute_message(
    WasmExecuteMessageOpt { contract, message }: WasmExecuteMessageOpt,
) -> Result<()> {
    let msg = serde_json::from_str::<serde_json::Value>(&message)?;
    let msg = CosmosMsg::<Empty>::Wasm(WasmMsg::Execute {
        contract_addr: contract.get_address_string(),
        msg: to_binary(&msg)?,
        funds: vec![],
    });
    println!("{}", serde_json::to_string(&msg)?);
    Ok(())
}

#[derive(clap::Parser)]
struct MigrateContractOpt {
    /// Destination contract address
    #[clap(long)]
    contract: Address,
    /// New code ID
    #[clap(long)]
    code_id: u64,
    /// Message to submit
    #[clap(long)]
    message: String,
}

fn migrate_contract_message(
    MigrateContractOpt {
        contract,
        code_id,
        message,
    }: MigrateContractOpt,
) -> Result<()> {
    let message = serde_json::from_str::<serde_json::Value>(&message)?;
    let msg = CosmosMsg::<Empty>::Wasm(WasmMsg::Migrate {
        contract_addr: contract.get_address_string(),
        new_code_id: code_id,
        msg: to_binary(&message)?,
    });
    println!("{}", serde_json::to_string(&msg)?);
    Ok(())
}
