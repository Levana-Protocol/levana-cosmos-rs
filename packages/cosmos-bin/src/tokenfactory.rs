use anyhow::Result;
use cosmos::{Cosmos, HasAddressHrp, SeedPhrase, TokenFactory};

#[derive(clap::Parser)]
pub enum Command {
    Create { subdenom: String },

    Mint { denom: String, amount: u128 },

    Burn { denom: String, amount: u128 },

    ChangeAdmin { denom: String, addr: String },
}

pub(crate) async fn go(cosmos: Cosmos, raw_wallet: SeedPhrase, cmd: Command) -> Result<()> {
    let wallet = raw_wallet.with_hrp(cosmos.get_address_hrp(), None)?;
    let tokenfactory = TokenFactory::new(cosmos, wallet);

    match cmd {
        Command::Create { subdenom } => {
            let (resp, denom) = tokenfactory.create(subdenom).await?;
            log::info!("CREATED {denom}, tx hash: {}", resp.txhash);
        }

        Command::Mint { denom, amount } => {
            let resp = tokenfactory.mint(denom.clone(), amount).await?;
            log::info!("MINTED {amount} {denom}, tx hash: {}", resp.txhash);
        }

        Command::Burn { denom, amount } => {
            let resp = tokenfactory.burn(denom.clone(), amount).await?;
            log::info!("BURNED {amount} {denom}, tx hash: {}", resp.txhash);
        }

        Command::ChangeAdmin { denom, addr } => {
            let resp = tokenfactory
                .change_admin(denom.clone(), addr.clone())
                .await?;
            log::info!(
                "CHANGED ADMIN FOR {denom} to {addr}, tx hash: {}",
                resp.txhash
            );
        }
    }
    Ok(())
}
