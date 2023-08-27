use anyhow::Result;
use cosmos::{Address, Cosmos, HasAddressType, TxBuilder};

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
            let wallet = tx_opt.get_wallet(cosmos.get_address_type())?;
            TxBuilder::default()
                .add_update_contract_admin(contract, &wallet, new_admin)
                .sign_and_broadcast(&cosmos, &wallet)
                .await?;
        }
    }
    Ok(())
}
