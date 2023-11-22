//! Gas price query for osmosis mainnet from lcd endpoint /osmosis/txfees/v1beta1/cur_eip_base_fee

use std::{num::ParseFloatError, sync::Arc, time::Instant};

use parking_lot::RwLock;

use crate::error::BuilderError;

/// Mechanism used for determining the gas price
#[derive(Clone, Debug)]
pub(crate) struct GasPriceMethod {
    inner: GasPriceMethodInner,
}

pub(crate) const DEFAULT_GAS_PRICE: (f64, f64) = (0.02, 0.03);

#[derive(Clone, Debug)]
enum GasPriceMethodInner {
    Static {
        low: f64,
        high: f64,
    },
    /// Reloads from EIP values regularly, starting with the values below.
    OsmosisMainnet {
        client: reqwest::Client,
        price: Arc<RwLock<OsmosisGasPrice>>,
    },
}

impl GasPriceMethod {
    pub(crate) fn pair(&self) -> (f64, f64) {
        match &self.inner {
            GasPriceMethodInner::Static { low, high } => (*low, *high),
            GasPriceMethodInner::OsmosisMainnet { client, price } => {
                // To avoid a race condition, we lock, check the last triggered
                // time, and then immediately update last_triggered if we're
                // going to reload. This prevents multiple tasks from being
                // spawned simultaneously. We don't worry about the case of a
                // single task running longer than the next one, HTTP timeouts
                // will prevent that.
                //
                // Do this all in its own block to make sure we don't hold the
                // write guard for too long.
                let (low, high, should_trigger) = {
                    let now = Instant::now();

                    // Locking optimization. First take a read lock and, if we
                    // don't need to trigger, no need for a write lock.
                    let orig = *price.read();
                    if osmosis_too_old(orig.last_triggered, now) {
                        // OK, we think we need to trigger. Now take a write
                        // lock and check again to see if another task was
                        // already triggered.
                        let mut guard = price.write();
                        let should_trigger = osmosis_too_old(guard.last_triggered, now);
                        if should_trigger {
                            guard.last_triggered = now;
                        }
                        (guard.low, guard.high, should_trigger)
                    } else {
                        (orig.low, orig.high, false)
                    }
                };
                if should_trigger {
                    let client = client.clone();
                    let price = price.clone();
                    tokio::task::spawn(async move {
                        let (low, high) = load_osmosis_gas_price(&client).await?;
                        let mut guard = price.write();
                        guard.low = low;
                        guard.high = high;
                        Ok::<_, LoadOsmosisGasPriceError>(())
                    });
                }
                (low, high)
            }
        }
    }

    pub(crate) async fn new_osmosis_mainnet(
        client: &reqwest::Client,
    ) -> Result<Self, BuilderError> {
        // Do not kill this process if the query fails. We don't want services
        // to crash just because Osmosis's LCD stops responding.
        let (low, high) = match load_osmosis_gas_price(client).await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(
                    "Unable to load variable Osmosis mainnet gas price, using defaults: {e}"
                );
                DEFAULT_GAS_PRICE
            }
        };
        let price = OsmosisGasPrice {
            low,
            high,
            last_triggered: Instant::now(),
        };
        Ok(GasPriceMethod {
            inner: GasPriceMethodInner::OsmosisMainnet {
                client: client.clone(),
                price: Arc::new(RwLock::new(price)),
            },
        })
    }

    pub(crate) fn new_static(low: f64, high: f64) -> GasPriceMethod {
        GasPriceMethod {
            inner: GasPriceMethodInner::Static { low, high },
        }
    }
}

const OSMOSIS_TOO_OLD_SECONDS: u64 = 60;

fn osmosis_too_old(last_triggered: Instant, now: Instant) -> bool {
    match now.checked_duration_since(last_triggered) {
        Some(age) => age.as_secs() > OSMOSIS_TOO_OLD_SECONDS,
        None => {
            tracing::warn!("now.checked_duration_since(last_triggered) returned None");
            false
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct OsmosisGasPrice {
    low: f64,
    high: f64,
    last_triggered: Instant,
}

pub(crate) async fn load_osmosis_gas_price(
    client: &reqwest::Client,
) -> Result<(f64, f64), LoadOsmosisGasPriceError> {
    let base_fee = load_osmosis_gas_base_fee(client).await?;
    // Wide range to try and deal with potential bugs in the EIP gas price
    // mechanism.
    Ok((base_fee * 2.5, base_fee * 12.0))
}

/// Loads current eip base fee from a v1beta1 lcd endpoint
pub async fn load_osmosis_gas_base_fee(
    client: &reqwest::Client,
) -> Result<f64, LoadOsmosisGasPriceError> {
    #[derive(serde::Deserialize)]
    struct BaseFee {
        base_fee: String,
    }
    let BaseFee { base_fee } = client
        .get("https://lcd.osmosis.zone/osmosis/txfees/v1beta1/cur_eip_base_fee")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let base_fee: f64 = base_fee.parse()?;

    // There seems to be a bug where this endpoint occassionally returns 0. Just
    // set a minimum.
    let base_fee = base_fee.max(0.0025);

    Ok(base_fee)
}

#[derive(thiserror::Error, Debug)]
/// Verbose error for the gas price base fee request
pub enum LoadOsmosisGasPriceError {
    #[error(transparent)]
    /// Reqwest error
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    /// Parse error
    Parse(#[from] ParseFloatError),
}
