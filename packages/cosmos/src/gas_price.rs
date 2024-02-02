//! Gas price query for osmosis mainnet from lcd endpoint /osmosis/txfees/v1beta1/cur_eip_base_fee

use std::{num::ParseFloatError, sync::Arc, time::Instant};

use crate::{cosmos_builder::OsmosisGasParams, error::BuilderError, osmosis::TxFeesInfo, Cosmos};

/// Mechanism used for determining the gas price
#[derive(Clone, Debug)]
pub(crate) struct GasPriceMethod {
    inner: GasPriceMethodInner,
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
        price: Arc<tokio::sync::RwLock<OsmosisGasPrice>>,
        params: OsmosisGasParams,
    },
}

pub(crate) struct CurrentGasPrice {
    pub(crate) low: f64,
    pub(crate) high: f64,
    pub(crate) base: f64,
}

impl GasPriceMethod {
    pub(crate) async fn current(&self, cosmos: &Cosmos) -> CurrentGasPrice {
        match &self.inner {
            GasPriceMethodInner::Static { low, high } => CurrentGasPrice {
                low: *low,
                high: *high,
                base: *low,
            },
            GasPriceMethodInner::OsmosisMainnet {
                price,
                params:
                    OsmosisGasParams {
                        low_multiplier,
                        high_multiplier,
                    },
            } => {
                // We're going to check if we have a recent enough value, so get
                // the current timestamp for use below.
                let now = Instant::now();
                let too_old_seconds = cosmos
                    .get_cosmos_builder()
                    .get_osmosis_gas_price_too_old_seconds();

                // Locking optimization. First take a read lock and, if we
                // don't need to reload the price, no need for a write lock.
                let orig = *price.read().await;
                let reported = if osmosis_too_old(orig.last_loaded, now, too_old_seconds) {
                    // OK, we think we need to reload. Now take a write lock.
                    // We'll end up waiting if another task is already in the process of reloading,
                    // which is exactly what we want (to avoid two concurrent loads).
                    let mut guard = price.write().await;
                    if osmosis_too_old(guard.last_loaded, now, too_old_seconds) {
                        // No other task updated this, so we'll do it. We're
                        // still holding the write lock, so all other tasks will wait on us. We rely
                        // on existing timeouts in the rest of the system to ensure this completes in
                        // a reasonable amount of time. This is considered acceptable, since any other
                        // actions we'd want to take would have the same latency from slow gRPC queries.
                        match load_osmosis_gas_base_fee(cosmos).await {
                            Ok(reported) => {
                                guard.reported = reported;
                                guard.last_loaded = Some(now);
                                reported
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Unable to load Osmosis gas price (aka base fee): {e}"
                                );
                                guard.reported
                            }
                        }
                    } else {
                        guard.reported
                    }
                } else {
                    orig.reported
                };

                CurrentGasPrice {
                    base: reported,
                    low: (reported * low_multiplier).min(cosmos.max_price),
                    high: (reported * high_multiplier).min(cosmos.max_price),
                }
            }
        }
    }

    pub(crate) async fn new_osmosis_mainnet(
        params: OsmosisGasParams,
    ) -> Result<Self, BuilderError> {
        Ok(GasPriceMethod {
            inner: GasPriceMethodInner::OsmosisMainnet {
                price: Arc::new(tokio::sync::RwLock::new(OsmosisGasPrice {
                    reported: OsmosisGasPrice::DEFAULT_REPORTED,
                    last_loaded: None,
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

fn osmosis_too_old(last_loaded: Option<Instant>, now: Instant, too_old_seconds: u64) -> bool {
    let last_loaded = match last_loaded {
        Some(last_loaded) => last_loaded,
        None => return true,
    };
    match now.checked_duration_since(last_loaded) {
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
    last_loaded: Option<Instant>,
}

impl OsmosisGasPrice {
    pub(crate) const DEFAULT_REPORTED: f64 = 0.0025;
}

/// Loads current eip base fee from Osmosis txfees module
async fn load_osmosis_gas_base_fee(cosmos: &Cosmos) -> Result<f64, LoadOsmosisGasPriceError> {
    let TxFeesInfo { eip_base_fee } = cosmos.get_osmosis_txfees_info().await?;
    let base_fee: f64 = eip_base_fee.to_string().parse()?;

    // There seems to be a bug where this endpoint occassionally returns 0. Just
    // set a minimum.
    let base_fee = base_fee.max(OsmosisGasPrice::DEFAULT_REPORTED);

    Ok(base_fee)
}

#[derive(thiserror::Error, Debug)]
/// Verbose error for the gas price base fee request
enum LoadOsmosisGasPriceError {
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
