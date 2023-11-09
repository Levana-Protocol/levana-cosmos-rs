use std::path::PathBuf;

use anyhow::Result;
use chrono::{DateTime, Utc};
use cosmos::{Address, Cosmos, TxResponseExt};

#[derive(clap::Parser)]
pub(crate) struct Opt {
    #[clap(subcommand)]
    sub: Subcommand,
}

#[derive(clap::Parser)]
pub(crate) enum Subcommand {
    /// Find the first block after the given timestamp
    FirstBlockAfter {
        #[clap(long)]
        timestamp: DateTime<Utc>,
        #[clap(long)]
        earliest: Option<i64>,
    },
    /// Get account number and sequence number for the given address
    AccountInfo { address: Address },
    /// Get the code ID from the given transaction
    CodeIdFromTx { txhash: String },
    /// Get the contract address instantiated in a given transaction
    ContractAddressFromTx { txhash: String },
    /// Check that all transaction data is available on an archive node
    ArchiveCheck {
        #[clap(long)]
        start_block: i64,
        #[clap(long)]
        end_block: Option<i64>,
    },
    /// Print a CSV file with gas usage in a range of blocks
    BlockGasReport {
        #[clap(long)]
        start_block: i64,
        #[clap(long)]
        end_block: i64,
        #[clap(long)]
        dest: PathBuf,
    },
}

pub(crate) async fn go(Opt { sub }: Opt, cosmos: Cosmos) -> Result<()> {
    match sub {
        Subcommand::FirstBlockAfter {
            timestamp,
            earliest,
        } => first_block_after(cosmos, timestamp, earliest).await,
        Subcommand::AccountInfo { address } => account_info(cosmos, address).await,
        Subcommand::CodeIdFromTx { txhash } => code_id_from_tx(cosmos, txhash).await,
        Subcommand::ContractAddressFromTx { txhash } => {
            contract_address_from_tx(cosmos, txhash).await
        }
        Subcommand::ArchiveCheck {
            start_block,
            end_block,
        } => archive_check(cosmos, start_block, end_block).await,
        Subcommand::BlockGasReport {
            start_block,
            end_block,
            dest,
        } => block_gas_report(cosmos, start_block, end_block, &dest).await,
    }
}

async fn first_block_after(
    cosmos: Cosmos,
    timestamp: DateTime<Utc>,
    earliest: Option<i64>,
) -> Result<()> {
    let earliest = match earliest {
        None => cosmos.get_earliest_block_info().await?,
        Some(height) => cosmos.get_block_info(height).await?,
    };
    let latest = cosmos.get_latest_block_info().await?;
    anyhow::ensure!(
        earliest.timestamp < timestamp,
        "No blocks exist before {timestamp}, earliest is {} @ {}",
        earliest.height,
        earliest.timestamp
    );
    anyhow::ensure!(
        latest.timestamp > timestamp,
        "No blocks exist after {timestamp}, latest block is {}@{}",
        latest.height,
        latest.timestamp
    );
    let mut low = earliest.height;
    let mut high = latest.height;
    log::debug!("Earliest height {low} at {}", earliest.timestamp);
    log::debug!("Latest height {high} at {}", latest.timestamp);
    loop {
        if low == high || low + 1 == high {
            println!("{high}");
            break Ok(());
        }
        assert!(low < high);
        let mid = (high + low) / 2;
        let info = cosmos.get_block_info(mid).await?;
        log::debug!(
            "Block #{} occurred at timestamp {}",
            info.height,
            info.timestamp
        );
        if info.timestamp < timestamp {
            low = mid;
        } else {
            high = mid;
        }
    }
}

async fn account_info(cosmos: Cosmos, address: Address) -> Result<()> {
    let base_account = cosmos.get_base_account(address).await?;
    log::info!("Account number: {}", base_account.account_number);
    log::info!("Sequence number: {}", base_account.sequence);
    Ok(())
}

async fn code_id_from_tx(cosmos: Cosmos, txhash: String) -> Result<()> {
    let (_, txres) = cosmos.get_transaction_body(txhash).await?;
    let code_id = txres.parse_first_stored_code_id()?;
    log::info!("Code ID: {code_id}");
    Ok(())
}

async fn contract_address_from_tx(cosmos: Cosmos, txhash: String) -> Result<()> {
    let (_, tx) = cosmos.wait_for_transaction(&txhash).await?;
    let addrs = tx.parse_instantiated_contracts()?;

    anyhow::ensure!(
        !addrs.is_empty(),
        "No contract addresses found in transaction {txhash}"
    );
    addrs
        .into_iter()
        .for_each(|contract| log::info!("Contract address: {contract}"));
    Ok(())
}

async fn archive_check(cosmos: Cosmos, start_block: i64, end_block: Option<i64>) -> Result<()> {
    let end_block = match end_block {
        Some(end_block) => end_block,
        None => {
            let end_block = cosmos.get_latest_block_info().await?.height;
            log::info!("Checking until block height {end_block}");
            end_block
        }
    };
    anyhow::ensure!(end_block >= start_block);
    for block_height in start_block..=end_block {
        log::info!("Checking block {block_height}");
        match cosmos.get_block_info(block_height).await {
            Ok(block) => {
                for txhash in block.txhashes {
                    if let Err(e) = cosmos.get_transaction_body(&txhash).await {
                        log::error!("Error while getting transaction {txhash}: {e:?}");
                        println!("Missing transaction: {txhash} in block: {block_height}");
                    }
                }
            }
            Err(e) => {
                log::error!("Error while processing block {block_height}: {e:?}");
                println!("Missing block: {block_height}");
            }
        };
    }
    Ok(())
}

async fn block_gas_report(
    cosmos: Cosmos,
    start_block: i64,
    end_block: i64,
    dest: &PathBuf,
) -> Result<()> {
    let mut csv = csv::Writer::from_path(dest)?;
    #[derive(serde::Serialize)]
    struct Record {
        block: i64,
        timestamp: DateTime<Utc>,
        gas_used: i64,
        gas_wanted: i64,
        txcount: usize,
    }
    for height in start_block..=end_block {
        let block = cosmos.get_block_info(height).await?;
        let mut gas_used = 0;
        let mut gas_wanted = 0;
        let txcount = block.txhashes.len();
        for txhash in block.txhashes {
            let (_, tx) = cosmos.get_transaction_body(txhash).await?;
            gas_used += tx.gas_used;
            gas_wanted += tx.gas_wanted;
        }
        csv.serialize(Record {
            block: block.height,
            timestamp: block.timestamp,
            gas_used,
            gas_wanted,
            txcount,
        })?;
        csv.flush()?;
    }
    csv.flush()?;
    Ok(())
}
