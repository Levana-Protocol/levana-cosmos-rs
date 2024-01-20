//! Gas price query for osmosis mainnet from lcd endpoint /osmosis/txfees/v1beta1/cur_eip_base_fee

use std::{num::ParseFloatError, sync::Arc, time::Instant};

use parking_lot::RwLock;

use crate::{
    cosmos_builder::OsmosisGasParams, error::BuilderError, osmosis::TxFeesInfo, Cosmos,
    CosmosBuilder,
};

/// Mechanism used for determining the gas price
#[derive(Clone, Debug)]
pub(crate) struct GasPriceMethod {
    inner: GasPriceMethodInner,
}

impl GasPriceMethod {
    // see comment on `cosmos` field of `GasPriceMethodInner::OsmosisMainnet`
    pub(crate) fn set_cosmos(&self, cosmos: Cosmos) {
        match &self.inner {
            GasPriceMethodInner::Static { .. } => {}
            GasPriceMethodInner::OsmosisMainnet {
                cosmos: cosmos_lock,
                ..
            } => {
                *cosmos_lock.write() = Some(cosmos);
            }
        }
    }
}

pub(crate) const DEFAULT_GAS_PRICE: CurrentGasPrice = CurrentGasPrice {
    low: 0.02,
    high: 0.03,
    base: 0.02,
};

#[derive(Clone, Debug)]
enum GasPriceMethodInner {
    Static {
        low: f64,
        high: f64,
    },
    /// Reloads from EIP values regularly, starting with the values below.
    OsmosisMainnet {
        // This Cosmos instance is optional due to a circular dependency:
        // builder depends on gas price method -> gas price method depends on cosmos -> cosmos depends on builder
        // Therefore, we fallback to a default until the cosmos instance has been set
        // In practice, it's set almost right away via the builder completing
        // i.e. this is ultimately just a typesafe way to complete the circular dependency
        cosmos: Arc<RwLock<Option<Cosmos>>>,
        price: Arc<RwLock<OsmosisGasPrice>>,
        params: OsmosisGasParams,
    },
}

pub(crate) struct CurrentGasPrice {
    pub(crate) low: f64,
    pub(crate) high: f64,
    pub(crate) base: f64,
}

impl GasPriceMethod {
    pub(crate) fn current(&self, builder: &CosmosBuilder, max_price: f64) -> CurrentGasPrice {
        match &self.inner {
            GasPriceMethodInner::Static { low, high } => CurrentGasPrice {
                low: *low,
                high: *high,
                base: *low,
            },
            GasPriceMethodInner::OsmosisMainnet {
                cosmos,
                price,
                params:
                    OsmosisGasParams {
                        low_multiplier,
                        high_multiplier,
                    },
            } => {
                // To avoid a race condition, we lock, check the last triggered
                // time, and then immediately update last_triggered if we're
                // going to reload. This prevents multiple tasks from being
                // spawned simultaneously. We don't worry about the case of a
                // single task running longer than the next one, HTTP timeouts
                // will prevent that.
                //
                // Do this all in its own block to make sure we don't hold the
                // write guard for too long.
                let (reported, should_trigger) = {
                    let now = Instant::now();

                    // Locking optimization. First take a read lock and, if we
                    // don't need to trigger, no need for a write lock.
                    let orig = *price.read();
                    if osmosis_too_old(
                        orig.last_triggered,
                        now,
                        builder.get_osmosis_gas_price_too_old_seconds(),
                    ) {
                        // OK, we think we need to trigger. Now take a write
                        // lock and check again to see if another task was
                        // already triggered.
                        let mut guard = price.write();
                        let should_trigger = osmosis_too_old(
                            guard.last_triggered,
                            now,
                            builder.get_osmosis_gas_price_too_old_seconds(),
                        );
                        if should_trigger {
                            guard.last_triggered = now;
                        }
                        (guard.reported, should_trigger)
                    } else {
                        (orig.reported, false)
                    }
                };
                if should_trigger {
                    let cosmos = cosmos.clone();
                    let price = price.clone();
                    tokio::task::spawn(async move {
                        // no real need for the extra scope here, lock will be dropped, but better safe than sorry!
                        let cosmos: Option<Cosmos> =
                            { cosmos.try_read().as_deref().cloned().flatten() };
                        let reported = match cosmos {
                            None => OsmosisGasPrice::DEFAULT_REPORTED,
                            Some(cosmos) => load_osmosis_gas_base_fee(&cosmos).await?,
                        };
                        let mut guard = price.write();
                        guard.reported = reported;
                        Ok::<_, LoadOsmosisGasPriceError>(())
                    });
                }
                CurrentGasPrice {
                    base: reported,
                    low: (reported * low_multiplier).min(max_price),
                    high: (reported * high_multiplier).min(max_price),
                }
            }
        }
    }

    pub(crate) async fn new_osmosis_mainnet(
        params: OsmosisGasParams,
    ) -> Result<Self, BuilderError> {
        Ok(GasPriceMethod {
            inner: GasPriceMethodInner::OsmosisMainnet {
                cosmos: Arc::new(RwLock::new(None)),
                price: Arc::new(RwLock::new(OsmosisGasPrice {
                    reported: OsmosisGasPrice::DEFAULT_REPORTED,
                    last_triggered: Instant::now(),
                })),
                params,
            },
        })
    }

    pub(crate) fn new_static(low: f64, high: f64) -> GasPriceMethod {
        GasPriceMethod {
            inner: GasPriceMethodInner::Static { low, high },
        }
    }
}

fn osmosis_too_old(last_triggered: Instant, now: Instant, too_old_seconds: u64) -> bool {
    match now.checked_duration_since(last_triggered) {
        Some(age) => age.as_secs() > too_old_seconds,
        None => {
            tracing::warn!("now.checked_duration_since(last_triggered) returned None");
            false
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct OsmosisGasPrice {
    reported: f64,
    last_triggered: Instant,
}

impl OsmosisGasPrice {
    pub const DEFAULT_REPORTED: f64 = 0.0025;
}

/// Loads current eip base fee from Osmosis txfees module
pub async fn load_osmosis_gas_base_fee(cosmos: &Cosmos) -> Result<f64, LoadOsmosisGasPriceError> {
    let TxFeesInfo { eip_base_fee } = cosmos.get_osmosis_txfees_info().await?;
    let base_fee: f64 = eip_base_fee.to_string().parse()?;

    // There seems to be a bug where this endpoint occassionally returns 0. Just
    // set a minimum.
    let base_fee = base_fee.max(0.0025);

    Ok(base_fee)
}

#[derive(thiserror::Error, Debug)]
/// Verbose error for the gas price base fee request
pub enum LoadOsmosisGasPriceError {
    #[error(transparent)]
    /// TxFees error
    TxFees(#[from] crate::Error),
    #[error(transparent)]
    /// Parse error
    Parse(#[from] ParseFloatError),
    #[error(transparent)]
    /// Builder error
    Builder(#[from] BuilderError),
}
