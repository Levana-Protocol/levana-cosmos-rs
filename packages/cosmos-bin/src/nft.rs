use cosmos::{Address, Cosmos, HasAddressType, TxBuilder};

use crate::TxOpt;

#[derive(clap::Parser)]
pub(crate) struct Opt {
    /// NFT contract address
    #[clap(long, env = "NFT_CONTRACT")]
    nft_contract: Address,
}

#[derive(clap::Parser)]
pub(crate) enum Subcommand {
    /// Transfer all NFTs to the given destination wallet
    TransferAll {
        #[clap(long)]
        dest: Address,
        #[clap(flatten)]
        tx_opt: TxOpt,
    },
}

pub(super) async fn go(sub: Subcommand, opt: Opt, cosmos: Cosmos) -> anyhow::Result<()> {
    let contract = cosmos.make_contract(opt.nft_contract);
    match sub {
        Subcommand::TransferAll { dest, tx_opt } => {
            let wallet = tx_opt.get_wallet(cosmos.get_address_type())?;
            loop {
                let Tokens { tokens } = contract
                    .query(&NftQuery::Tokens {
                        owner: *wallet.address(),
                        limit: 30,
                    })
                    .await?;
                if tokens.is_empty() {
                    log::info!("No more tokens remaining");
                    break;
                }
                let count = tokens.len();

                let mut builder = TxBuilder::default();
                for token_id in tokens {
                    builder.add_execute_message_mut(
                        &contract,
                        &wallet,
                        vec![],
                        NftExec::TransferNft {
                            token_id,
                            recipient: dest,
                        },
                    )?;
                }
                let res = builder.sign_and_broadcast(&cosmos, &wallet).await?;
                log::info!(
                    "Transferred {count} {} in {}",
                    if count == 1 { "NFT" } else { "NFTs" },
                    res.txhash
                );
            }
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum NftQuery {
    Tokens { owner: Address, limit: u32 },
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum NftExec {
    TransferNft {
        token_id: String,
        recipient: Address,
    },
}

#[derive(serde::Deserialize)]
struct Tokens {
    tokens: Vec<String>,
}
