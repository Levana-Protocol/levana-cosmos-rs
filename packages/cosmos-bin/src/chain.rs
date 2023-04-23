use anyhow::Result;
use chrono::{DateTime, Utc};
use cosmos::Cosmos;

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
    },
}

pub(crate) async fn go(
    Opt {
        sub: Subcommand::FirstBlockAfter { timestamp },
    }: Opt,
    cosmos: Cosmos,
) -> Result<()> {
    let earliest = cosmos.get_earliest_block_info().await?;
    let latest = cosmos.get_latest_block_info().await?;
    anyhow::ensure!(
        earliest.timestamp < timestamp,
        "No blocks exist before {timestamp}, earliest is {} @ {}",
        earliest.height,
        earliest.timestamp
    );
    anyhow::ensure!(
        latest.timestamp > timestamp,
        "No blocks exist after {timestamp}"
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
