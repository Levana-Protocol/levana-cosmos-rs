use std::str::FromStr;

use anyhow::Context;
use cosmos::Coin;

#[derive(PartialEq, Eq, Debug, Clone)]
pub(super) struct ParsedCoin {
    denom: String,
    amount: u128,
}

impl From<ParsedCoin> for Coin {
    fn from(ParsedCoin { denom, amount }: ParsedCoin) -> Self {
        Coin {
            denom,
            amount: amount.to_string(),
        }
    }
}

impl FromStr for ParsedCoin {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        (|| {
            anyhow::ensure!(!s.is_empty(), "Cannot parse empty string");
            let idx = s
                .find(|c: char| !c.is_ascii_digit())
                .context("All characters are ASCII digits")?;
            let (amount, denom) = s.split_at(idx);
            anyhow::ensure!(!amount.is_empty(), "Must not have an empty amount");
            anyhow::ensure!(!denom.is_empty(), "Must not have an empty denom");
            anyhow::ensure!(
                denom.bytes().all(|b| b.is_ascii_lowercase()),
                "Denom must be ASCII lowercase"
            );
            Ok(ParsedCoin {
                denom: denom.to_owned(),
                amount: amount.parse()?,
            })
        })()
        .with_context(|| format!("Could not parse coin value {s:?}"))
    }
}

#[cfg(test)]
mod tests {
    use quickcheck::Arbitrary;

    use super::*;

    fn parse_coin(s: &str) -> anyhow::Result<ParsedCoin> {
        s.parse()
    }

    fn make_coin(amount: u128, denom: &str) -> ParsedCoin {
        ParsedCoin {
            denom: denom.to_owned(),
            amount,
        }
    }

    #[test]
    fn sanity() {
        assert_eq!(parse_coin("1ujunox").unwrap(), make_coin(1, "ujunox"));
        parse_coin("1.523ujunox").unwrap_err();
        parse_coin("foobar").unwrap_err();
        parse_coin("123ujunox456").unwrap_err();
        assert_eq!(
            parse_coin("123456uwbtc").unwrap(),
            make_coin(123456, "uwbtc")
        );
    }

    #[derive(Clone, Debug)]
    struct DenomString(String);

    impl Arbitrary for DenomString {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            // See https://github.com/BurntSushi/quickcheck/issues/279
            let sizes = (3..20).collect::<Vec<_>>();
            let letters = ('a'..='z').collect::<Vec<_>>();
            DenomString(
                (1..*g.choose(&sizes).unwrap())
                    .map(|_| *g.choose(&letters).unwrap())
                    .collect(),
            )
        }
    }

    quickcheck::quickcheck! {
        fn roundtrip(amount: u128, denom: DenomString) -> bool {
            let denom = denom.0;
            let expected = make_coin(amount, &denom);
            let actual = parse_coin(&format!("{amount}{denom}")).unwrap();
            assert_eq!(expected, actual);
            true
        }
    }
}
