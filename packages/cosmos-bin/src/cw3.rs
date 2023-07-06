use std::str::FromStr;

use anyhow::{Context, Result};
use cosmos::{
    Address, ContractAdmin, Cosmos, CosmosNetwork, HasAddress, HasAddressType, TxBuilder,
};
use cosmwasm_std::Decimal;
use cw4::Member;
use cw_utils::Threshold;

use crate::TxOpt;

#[derive(Clone, Copy, Debug)]
enum ContractType {
    Cw3Flex,
    Cw4Group,
}

fn get_code_id(network: CosmosNetwork, contract_type: ContractType) -> Result<u64> {
    match (network, contract_type) {
        (CosmosNetwork::OsmosisTestnet, ContractType::Cw3Flex) => Ok(1519),
        (CosmosNetwork::OsmosisTestnet, ContractType::Cw4Group) => Ok(1521),
        (CosmosNetwork::OsmosisMainnet, ContractType::Cw3Flex) => Ok(100),
        (CosmosNetwork::OsmosisMainnet, ContractType::Cw4Group) => Ok(101),
        (CosmosNetwork::Dragonfire, ContractType::Cw3Flex) => Ok(600),
        (CosmosNetwork::Dragonfire, ContractType::Cw4Group) => Ok(601),
        _ => Err(anyhow::anyhow!(
            "No code ID found for combo {network}/{contract_type:?}"
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
}

pub(crate) async fn go(network: CosmosNetwork, cosmos: Cosmos, Opt { sub }: Opt) -> Result<()> {
    match sub {
        Subcommand::NewFlex { inner } => new_flex(network, cosmos, inner).await,
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

#[derive(Clone, Copy)]
struct MyDuration(cw_utils::Duration);

async fn new_flex(
    network: CosmosNetwork,
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
    let wallet = tx_opt.get_wallet(network.get_address_type());
    let cw3 = cosmos.make_code_id(get_code_id(network, ContractType::Cw3Flex)?);
    let cw4 = cosmos.make_code_id(get_code_id(network, ContractType::Cw4Group)?);

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
                max_voting_period: duration.0,
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

impl FromStr for MyDuration {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let multiplier = match s.as_bytes().last().context("Duration cannot be empty")? {
            b's' => 1,
            b'm' => 60,
            b'h' => 60 * 60,
            b'd' => 60 * 60 * 24,
            _ => anyhow::bail!("Final character in duration must be s, m, h, or d."),
        };
        let s = &s[0..s.len() - 1];
        let num: u64 = s
            .parse()
            .with_context(|| format!("Could not parse duration value {s}"))?;
        Ok(MyDuration(cw_utils::Duration::Time(num * multiplier)))
    }
}
