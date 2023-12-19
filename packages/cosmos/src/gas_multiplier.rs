use std::sync::Arc;

use parking_lot::RwLock;

use crate::{CosmosTxResponse, Error};

#[derive(Clone, Debug)]
pub(crate) enum GasMultiplierConfig {
    Default,
    Static(f64),
    Dynamic(DynamicGasMultiplier),
}

impl GasMultiplierConfig {
    pub(crate) fn build(&self) -> GasMultiplier {
        match self {
            GasMultiplierConfig::Default => GasMultiplier::Static(1.3),
            GasMultiplierConfig::Static(x) => GasMultiplier::Static(*x),
            GasMultiplierConfig::Dynamic(DynamicGasMultiplier {
                low,
                high,
                initial,
                step,
                too_high_ratio,
            }) => GasMultiplier::Dynamic(Arc::new(Dynamic {
                current: RwLock::new(*initial),
                low: *low,
                high: *high,
                step: *step,
                too_high_ratio: *too_high_ratio,
            })),
        }
    }
}

#[derive(Clone)]
pub(crate) enum GasMultiplier {
    Static(f64),
    Dynamic(Arc<Dynamic>),
}
impl GasMultiplier {
    pub(crate) fn get_current(&self) -> f64 {
        match self {
            GasMultiplier::Static(x) => *x,
            GasMultiplier::Dynamic(d) => *d.current.read(),
        }
    }

    pub(crate) fn update(&self, res: &Result<CosmosTxResponse, Error>) {
        let Dynamic {
            current,
            low,
            high,
            step,
            too_high_ratio,
        } = match self {
            GasMultiplier::Static(_) => return,
            GasMultiplier::Dynamic(d) => &**d,
        };
        match res {
            Ok(res) => {
                let ratio = res.response.gas_used as f64 / res.response.gas_wanted as f64;
                if ratio < *too_high_ratio {
                    let mut guard = current.write();
                    let old = *guard;
                    let new = (*guard - step).max(*low);
                    *guard = new;
                    std::mem::drop(guard);
                    tracing::info!("Dynamic gas: Too much gas used, reducing multiplier. Used: {} of {}. Used ratio {ratio} < too high ratio {too_high_ratio}. Old: {old}. New: {new}.", res.response.gas_used, res.response.gas_wanted);
                }
            }
            Err(e) => {
                if let Error::TransactionFailed {
                    code: crate::error::CosmosSdkError::OutOfGas,
                    ..
                } = e
                {
                    let mut guard = current.write();
                    let old = *guard;
                    let new = (*guard + step).min(*high);
                    *guard = new;
                    std::mem::drop(guard);
                    tracing::info!("Dynamic gas: Got an out of gas response, increasing multiplier. Old: {old}. New: {new}.");
                }
            }
        }
    }
}

pub(crate) struct Dynamic {
    current: RwLock<f64>,
    low: f64,
    high: f64,
    step: f64,
    too_high_ratio: f64,
}

/// Config parameters for dynamically modified gas multiplier.
///
/// Simulated gas can be very incorrect, this is a known bug in Cosmos SDK. The v21 upgrade of Osmosis exacerbated this further. The idea here is to allow the library to automatically adapt the gas multiplier value based on previous activities, specifically:
///
/// * Increase automatically when we get an "out of gas" error.
///
/// * Decrease automatically when our gas estimate was too high.
///
/// See comments on the field below for more details.
#[derive(Clone, Debug)]
pub struct DynamicGasMultiplier {
    /// The lowest the gas multiplier is allowed to go. Default: `1.2`.
    pub low: f64,
    /// The highest the gas multiplier is allowed to go. Default: `10.0`.
    pub high: f64,
    /// The initial gas multiplier value. Default: `1.3`.
    pub initial: f64,
    /// How much to increase or decrease the multiplier. Default: 0.01.
    pub step: f64,
    /// The usage ratio on a successful transaction which is considered "too high". Default: 0.7.
    ///
    /// Each time a transaction completes successfully using simulated gas, we check the requested versus actual gas on the transaction. If the ratio is below this value, we decrease the gas multiplier.
    pub too_high_ratio: f64,
}

impl Default for DynamicGasMultiplier {
    fn default() -> Self {
        DynamicGasMultiplier {
            low: 1.2,
            high: 10.0,
            initial: 1.3,
            step: 0.01,
            too_high_ratio: 0.7,
        }
    }
}
