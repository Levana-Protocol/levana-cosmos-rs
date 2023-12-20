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
                step_up,
                step_down,
                overpay_ratio: too_high_ratio,
                underpay_ratio: too_low_ratio,
            }) => GasMultiplier::Dynamic(Arc::new(Dynamic {
                current: RwLock::new(*initial),
                low: *low,
                high: *high,
                step_up: *step_up,
                step_down: *step_down,
                overpay_ratio: *too_high_ratio,
                underpay_ratio: *too_low_ratio,
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

    /// Returns true if any change was made, false otherwise.
    pub(crate) fn update(&self, res: &Result<CosmosTxResponse, Error>) -> bool {
        let Dynamic {
            current,
            low,
            high,
            step_up,
            step_down,
            overpay_ratio,
            underpay_ratio,
        } = match self {
            GasMultiplier::Static(_) => return false,
            GasMultiplier::Dynamic(d) => &**d,
        };

        enum IncreaseReason {
            Failed,
            RatioTooHigh { actual: f64, used: i64, wanted: i64 },
        }
        enum Action {
            Increase(IncreaseReason),
            Decrease { actual: f64, used: i64, wanted: i64 },
        }
        let action = match res {
            Ok(res) => {
                let ratio = res.response.gas_used as f64 / res.response.gas_wanted as f64;
                if ratio < *overpay_ratio {
                    Some(Action::Decrease {
                        actual: ratio,
                        used: res.response.gas_used,
                        wanted: res.response.gas_wanted,
                    })
                } else if ratio > *underpay_ratio {
                    Some(Action::Increase(IncreaseReason::RatioTooHigh {
                        actual: ratio,
                        used: res.response.gas_used,
                        wanted: res.response.gas_wanted,
                    }))
                } else {
                    None
                }
            }
            Err(e) => {
                if let Error::TransactionFailed {
                    code: crate::error::CosmosSdkError::OutOfGas,
                    ..
                } = e
                {
                    Some(Action::Increase(IncreaseReason::Failed))
                } else {
                    None
                }
            }
        };

        match action {
            None => false,
            Some(action) => match action {
                Action::Increase(reason) => {
                    let mut guard = current.write();
                    let old = *guard;
                    let new = (*guard + step_up).min(*high);
                    *guard = new;
                    std::mem::drop(guard);
                    match reason {
                        IncreaseReason::Failed => tracing::info!("Dynamic gas: Got an out of gas response, increasing multiplier. Old: {old}. New: {new}."),
                        IncreaseReason::RatioTooHigh { actual, used, wanted } => tracing::info!("Dynamic gas: underpaid gas, increasing multiplier. Used: {used} of {wanted}. Used ratio {actual} > underpay ratio {underpay_ratio}. Old: {old}. New: {new}."),
                    }
                    old != new
                }
                Action::Decrease {
                    actual,
                    used,
                    wanted,
                } => {
                    let mut guard = current.write();
                    let old = *guard;
                    let new = (*guard - step_down).max(*low);
                    *guard = new;
                    std::mem::drop(guard);
                    tracing::info!("Dynamic gas: overpaid gas, reducing multiplier. Used: {used} of {wanted}. Used ratio {actual} < overpay ratio {overpay_ratio}. Old: {old}. New: {new}.");
                    old != new
                }
            },
        }
    }
}

pub(crate) struct Dynamic {
    current: RwLock<f64>,
    low: f64,
    high: f64,
    step_up: f64,
    step_down: f64,
    overpay_ratio: f64,
    underpay_ratio: f64,
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
    /// How much to increase the multiplier when we hit out of gas. Default: 0.2.
    pub step_up: f64,
    /// How much to decrease the multiplier when we overpay. Default: 0.01.
    pub step_down: f64,
    /// The usage ratio on a successful transaction which is considered "overpaying". Default: 0.7.
    ///
    /// Each time a transaction completes successfully using simulated gas, we check the requested versus actual gas on the transaction. If the ratio is below this value, we decrease the gas multiplier.
    pub overpay_ratio: f64,
    /// The usage ratio on a successful transaction which is considered "underpaying". Default: 0.85.
    ///
    /// Each time a transaction completes successfully using simulated gas, we check the requested versus actual gas on the transaction. If the ratio is above this value, we increase the gas multiplier. The purpose of this is to preemptively avoid running out of gas.
    pub underpay_ratio: f64,
}

impl Default for DynamicGasMultiplier {
    fn default() -> Self {
        DynamicGasMultiplier {
            low: 1.2,
            high: 10.0,
            initial: 1.3,
            step_up: 0.2,
            step_down: 0.01,
            overpay_ratio: 0.7,
            underpay_ratio: 0.85,
        }
    }
}
