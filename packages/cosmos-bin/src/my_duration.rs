use std::str::FromStr;

use anyhow::{Context, Result};

#[derive(Clone, Copy)]
pub(crate) struct MyDuration(u64);

impl MyDuration {
    pub(crate) fn into_cw_duration(self) -> cw_utils::Duration {
        cw_utils::Duration::Time(self.0)
    }

    pub(crate) fn into_chrono_duration(self) -> Result<chrono::Duration> {
        Ok(chrono::Duration::seconds(self.0.try_into()?))
    }
}

impl FromStr for MyDuration {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let multiplier = match s.as_bytes().last().context("Duration cannot be empty")? {
            b's' => 1,
            b'm' => 60,
            b'h' => 60 * 60,
            b'd' => 60 * 60 * 24,
            _ => anyhow::bail!("Final character in duration must be s, m, h, or d."),
        };
        let s = &s[0..s.len() - 1];
        let num: u64 = s
            .parse()
            .with_context(|| format!("Could not parse duration value {s}"))?;
        Ok(MyDuration(num * multiplier))
    }
}
