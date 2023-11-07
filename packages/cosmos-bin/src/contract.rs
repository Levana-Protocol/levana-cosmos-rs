use anyhow::Result;
use cosmos::{Address, Cosmos, HasAddressHrp, TxBuilder};

use crate::TxOpt;

#[derive(clap::Parser)]
pub(crate) struct Opt {
    /// Smart contract address
    #[clap(long, env = "CONTRACT")]
    contract: Address,
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Parser)]
enum Subcommand {
    /// Update the administrator on a contract
    UpdateAdmin {
        #[clap(long)]
        new_admin: Address,
        #[clap(flatten)]
        tx_opt: TxOpt,
    },
    /// Simulate migrating a contract, but don't actually do it
    SimulateMigrate {
        #[clap(long, env = "COSMOS_SENDER")]
        sender: Address,
        /// Memo to put on transaction
        #[clap(long)]
        memo: Option<String>,
        /// Migration message (JSON)
        msg: String,
        /// New code ID
        #[clap(long)]
        code_id: u64,
    },
}

pub(crate) async fn go(
    Opt {
        contract,
        subcommand,
    }: Opt,
    cosmos: Cosmos,
) -> Result<()> {
    match subcommand {
        Subcommand::UpdateAdmin { new_admin, tx_opt } => {
            let wallet = tx_opt.get_wallet(cosmos.get_address_hrp())?;
            TxBuilder::default()
                .add_update_contract_admin(contract, &wallet, new_admin)
                .sign_and_broadcast(&cosmos, &wallet)
                .await?;
        }
        Subcommand::SimulateMigrate {
            sender,
            memo,
            msg,
            code_id,
        } => {
            let mut txbuilder = TxBuilder::default();
            if let Some(memo) = memo {
                txbuilder = txbuilder.set_memo(memo);
            }
            let msg: serde_json::Value = serde_json::from_str(&msg)?;
            txbuilder.add_migrate_message_mut(contract, sender, code_id, msg)?;
            let simres = txbuilder.simulate(&cosmos, &[sender]).await?;
            println!("{simres:?}");
        }
    }
    Ok(())
}
