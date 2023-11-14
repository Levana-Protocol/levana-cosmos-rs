//! Osmosis-specific functionality.
use std::sync::Arc;

use crate::{
    client::WeakCosmos,
    cosmos_builder::ChainPausedMethod,
    error::{Action, QueryError},
    Cosmos,
};

pub(crate) mod epochs;

use chrono::{DateTime, Utc};
pub use epochs::EpochInfo;
use parking_lot::RwLock;
use prost_types::Timestamp;

impl Cosmos {
    /// Get the Osmosis epoch information.
    ///
    /// Note that this query will fail if called on chains besides Osmosis Mainnet.
    pub async fn get_osmosis_epoch_info(&self) -> Result<EpochsInfo, QueryError> {
        self.perform_query(
            epochs::QueryEpochsInfoRequest {},
            Action::OsmosisEpochsInfo,
            true,
        )
        .await
        .map(|res| EpochsInfo {
            epochs: res.into_inner().epochs,
        })
    }
}

/// Information on epochs from an Osmosis chain.
#[derive(Debug)]
pub struct EpochsInfo {
    /// Epochs available
    pub epochs: Vec<EpochInfo>,
}

impl EpochsInfo {
    /// Provide a summarized version based on the current timestamp
    pub fn summarize(&self) -> SummarizedEpochInfo {
        self.summarize_at(Utc::now())
    }

    /// Provide a summ
    pub fn summarize_at(&self, now: DateTime<Utc>) -> SummarizedEpochInfo {
        let next_epoch_starts = self.epochs.iter().flat_map(EpochInfo::start_time).min();
        let current = match next_epoch_starts {
            None => CurrentEpochStatus::NoEpochs,
            Some(next_epoch_starts) => {
                if next_epoch_starts > now {
                    CurrentEpochStatus::Inactive {
                        starts: next_epoch_starts - now,
                    }
                } else {
                    CurrentEpochStatus::Active {
                        started: now - next_epoch_starts,
                    }
                }
            }
        };
        SummarizedEpochInfo {
            next_epoch_starts,
            current,
        }
    }
}

impl EpochInfo {
    /// When will this epoch next run?
    pub fn start_time(&self) -> Option<DateTime<Utc>> {
        // Ignore nanos, that level of granularity isn't needed
        let Timestamp { seconds, nanos } = self.current_epoch_start_time.as_ref()?;
        let duration = self.duration.as_ref()?;
        DateTime::from_timestamp(
            seconds + duration.seconds,
            // Ignoring additional nanos from duration, since it's never
            // actually used and can cause unnecessary failures from overflow
            u32::try_from(*nanos).ok().unwrap_or_default(),
        )
    }
}

/// Summarized version of the epoch info, providing commonly needed data.
#[derive(Debug)]
pub struct SummarizedEpochInfo {
    /// When does the next epoch start (may be in the past if currently active).
    pub next_epoch_starts: Option<DateTime<Utc>>,
    /// Are we currently in an epoch?
    pub current: CurrentEpochStatus,
}

/// Are we currently in an epoch?
#[derive(Debug)]
pub enum CurrentEpochStatus {
    /// No epochs are configured at all
    NoEpochs,
    /// No epoch active right now
    Inactive {
        /// Time until it starts
        starts: chrono::Duration,
    },
    /// Epoch is currently active
    Active {
        /// How long ago did it start?
        started: chrono::Duration,
    },
}

#[derive(Clone)]
pub(crate) enum ChainPausedStatus {
    NoPauseSupport,
    Osmosis {
        next_start: Arc<RwLock<Option<DateTime<Utc>>>>,
    },
}

impl ChainPausedStatus {
    pub(crate) fn is_paused(&self) -> bool {
        match self {
            ChainPausedStatus::NoPauseSupport => false,
            ChainPausedStatus::Osmosis { next_start } => match *next_start.read() {
                Some(start) => start <= Utc::now(),
                None => false,
            },
        }
    }
}

impl From<ChainPausedMethod> for ChainPausedStatus {
    fn from(method: ChainPausedMethod) -> Self {
        match method {
            ChainPausedMethod::None => ChainPausedStatus::NoPauseSupport,
            ChainPausedMethod::OsmosisMainnet => ChainPausedStatus::Osmosis {
                next_start: Arc::new(RwLock::new(None)),
            },
        }
    }
}

impl Cosmos {
    pub(crate) fn launch_chain_paused_tracker(&self) {
        match &self.chain_paused_status {
            ChainPausedStatus::NoPauseSupport => (),
            ChainPausedStatus::Osmosis { next_start } => {
                let weak = WeakCosmos::from(self);
                tokio::task::spawn(weak.update_osmosis_paused(next_start.clone()));
            }
        }
    }

    async fn single_osmosis_update(
        &self,
        next_start: &RwLock<Option<DateTime<Utc>>>,
    ) -> Result<tokio::time::Duration, QueryError> {
        let summarize = self.get_osmosis_epoch_info().await?.summarize();
        let (duration, new_next_start) = match summarize.next_epoch_starts {
            None => (tokio::time::Duration::from_secs(300), None),
            Some(next_epoch_starts) => {
                let now = Utc::now();
                let duration = if next_epoch_starts <= now {
                    tokio::time::Duration::from_secs(10)
                } else {
                    let duration = next_epoch_starts - now;
                    tokio::time::Duration::from_secs(
                        u64::try_from(duration.num_seconds())
                            .ok()
                            .map_or(300, |secs| secs.min(300)),
                    )
                };
                (duration, Some(next_epoch_starts))
            }
        };
        *next_start.write() = new_next_start;
        Ok(duration)
    }
}

impl WeakCosmos {
    async fn update_osmosis_paused(self, next_start: Arc<RwLock<Option<DateTime<Utc>>>>) {
        while let Some(cosmos) = self.upgrade() {
            match cosmos.single_osmosis_update(&next_start).await {
                Ok(to_sleep) => {
                    tokio::time::sleep(to_sleep).await;
                }
                Err(err) => {
                    log::warn!("Error while updating Osmosis epoch information: {err:?}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;
                }
            }
        }
    }
}
