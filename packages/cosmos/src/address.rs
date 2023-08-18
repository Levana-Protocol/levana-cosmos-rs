use std::{
    convert::TryFrom,
    fmt::{Debug, Display},
    str::FromStr,
};

use anyhow::{Context, Result};
use bech32::{FromBase32, ToBase32};
use serde::de::Visitor;

use crate::CosmosNetwork;

/// A raw address value not connected to a specific blockchain. You usually want [Address].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum RawAddress {
    Twenty { raw_address: [u8; 20] },
    ThirtyTwo { raw_address: [u8; 32] },
}

/// Parse a raw address and its HRP from a string. Supports any Cosmos-compatible blockchain.
pub fn parse_raw_address(s: &str) -> Result<(String, RawAddress)> {
    let (hrp, data, variant) = bech32::decode(s).context("Invalid bech32 data")?;
    match variant {
        bech32::Variant::Bech32 => (),
        bech32::Variant::Bech32m => anyhow::bail!("Must use Bech32 variant"),
    }
    let data = Vec::<u8>::from_base32(&data)?;
    let raw_address = data
        .as_slice()
        .try_into()
        .with_context(|| format!("Total bytes found: {}", data.len()))?;
    Ok((hrp, raw_address))
}

/// Note that using this instance throws away the Human Readable Parse (HRP) of the address!
impl FromStr for RawAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_raw_address(s).map(|x| x.1)
    }
}

/// Note that using this instance throws away the Human Readable Parse (HRP) of the address!
impl<'de> serde::Deserialize<'de> for RawAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(RawAddressVisitor)
    }
}

struct RawAddressVisitor;

impl<'de> Visitor<'de> for RawAddressVisitor {
    type Value = RawAddress;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("RawAddress")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        parse_raw_address(s).map(|x| x.1).map_err(E::custom)
    }
}

impl AsRef<[u8]> for RawAddress {
    fn as_ref(&self) -> &[u8] {
        match self {
            RawAddress::Twenty { raw_address } => raw_address,
            RawAddress::ThirtyTwo { raw_address } => raw_address,
        }
    }
}

impl From<[u8; 20]> for RawAddress {
    fn from(raw_address: [u8; 20]) -> Self {
        RawAddress::Twenty { raw_address }
    }
}

impl From<[u8; 32]> for RawAddress {
    fn from(raw_address: [u8; 32]) -> Self {
        RawAddress::ThirtyTwo { raw_address }
    }
}

impl TryFrom<&[u8]> for RawAddress {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.try_into().ok() {
            Some(raw_address) => Ok(RawAddress::Twenty { raw_address }),
            None => value
                .try_into()
                .map(|raw_address| RawAddress::ThirtyTwo { raw_address })
                .context("Invalid data size for a RawAddress, need either 20 or 32 bytes"),
        }
    }
}

impl RawAddress {
    pub fn for_chain(self, type_: AddressType) -> Address {
        Address {
            raw_address: self,
            type_,
        }
    }
}

/// An address on a Cosmos blockchain
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    raw_address: RawAddress,
    type_: AddressType,
}

impl Address {
    pub fn raw(&self) -> &RawAddress {
        &self.raw_address
    }

    pub fn for_chain(&self, type_: AddressType) -> Self {
        Address {
            raw_address: self.raw_address,
            type_,
        }
    }
}

/// The type of address
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum AddressType {
    Cosmos,
    Juno,
    Osmo,
    Wasm,
    Sei,
    Stargaze,
}

impl AddressType {
    pub fn all() -> [AddressType; 6] {
        [
            AddressType::Cosmos,
            AddressType::Juno,
            AddressType::Osmo,
            AddressType::Wasm,
            AddressType::Sei,
            AddressType::Stargaze,
        ]
    }

    pub fn hrp(self) -> &'static str {
        match self {
            AddressType::Cosmos => "cosmos",
            AddressType::Juno => "juno",
            AddressType::Osmo => "osmo",
            AddressType::Wasm => "wasm",
            AddressType::Sei => "sei",
            // https://github.com/cosmos/chain-registry/blob/e20cc7896cc203dada0f6a197d8f52ccafb4f7c7/stargaze/chain.json#L9
            AddressType::Stargaze => "stars",
        }
    }
}

impl FromStr for AddressType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cosmos" => Ok(AddressType::Cosmos),
            "juno" => Ok(AddressType::Juno),
            "osmo" => Ok(AddressType::Osmo),
            "wasm" => Ok(AddressType::Wasm),
            "sei" => Ok(AddressType::Sei),
            // https://github.com/cosmos/chain-registry/blob/e20cc7896cc203dada0f6a197d8f52ccafb4f7c7/stargaze/chain.json#L9
            "stars" => Ok(AddressType::Stargaze),
            _ => Err(anyhow::anyhow!("Invalid address type {s:?}")),
        }
    }
}

impl Display for Address {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        AddressAnyHrp {
            raw_address: self.raw_address,
            hrp: self.type_.hrp(),
        }
        .fmt(fmt)
    }
}

pub struct AddressAnyHrp<'a> {
    pub raw_address: RawAddress,
    pub hrp: &'a str,
}

impl<'a> Display for AddressAnyHrp<'a> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        bech32::encode_to_fmt(
            fmt,
            self.hrp,
            self.raw_address.to_base32(),
            bech32::Variant::Bech32,
        )
        .expect("Invalid HRP")
    }
}

impl From<Address> for String {
    fn from(address: Address) -> Self {
        address.to_string()
    }
}

impl From<&Address> for String {
    fn from(address: &Address) -> Self {
        address.to_string()
    }
}

impl FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        (|| {
            let (hrp, raw_address) = parse_raw_address(s)?;
            hrp.parse().map(|type_| Address { raw_address, type_ })
        })()
        .with_context(|| format!("Unable to parse Cosmos address {s}"))
    }
}

pub trait HasAddress {
    fn get_address(&self) -> Address;

    fn get_address_string(&self) -> String {
        self.get_address().to_string()
    }

    fn get_address_type(&self) -> AddressType {
        self.get_address().type_
    }
}

impl HasAddress for Address {
    fn get_address(&self) -> Address {
        *self
    }
}

impl<T: HasAddress> HasAddress for &T {
    fn get_address(&self) -> Address {
        HasAddress::get_address(*self)
    }
}

pub trait HasAddressType {
    fn get_address_type(&self) -> AddressType;
}

impl HasAddressType for AddressType {
    fn get_address_type(&self) -> AddressType {
        *self
    }
}

impl HasAddressType for CosmosNetwork {
    fn get_address_type(&self) -> AddressType {
        match self {
            CosmosNetwork::JunoTestnet => AddressType::Juno,
            CosmosNetwork::JunoMainnet => AddressType::Juno,
            CosmosNetwork::JunoLocal => AddressType::Juno,
            CosmosNetwork::OsmosisMainnet => AddressType::Osmo,
            CosmosNetwork::OsmosisTestnet => AddressType::Osmo,
            CosmosNetwork::OsmosisLocal => AddressType::Osmo,
            CosmosNetwork::WasmdLocal => AddressType::Wasm,
            CosmosNetwork::SeiMainnet => AddressType::Sei,
            CosmosNetwork::SeiTestnet => AddressType::Sei,
            CosmosNetwork::StargazeTestnet => AddressType::Stargaze,
            CosmosNetwork::StargazeMainnet => AddressType::Stargaze,
        }
    }
}

#[cfg(test)]
mod tests {
    use quickcheck::Arbitrary;

    use super::*;

    impl Arbitrary for AddressType {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            *g.choose(&AddressType::all()).unwrap()
        }
    }

    impl Arbitrary for RawAddress {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            if bool::arbitrary(g) {
                let mut raw_address = [0; 20];
                for byte in &mut raw_address {
                    *byte = u8::arbitrary(g);
                }
                RawAddress::Twenty { raw_address }
            } else {
                let mut raw_address = [0; 32];
                for byte in &mut raw_address {
                    *byte = u8::arbitrary(g);
                }
                RawAddress::ThirtyTwo { raw_address }
            }
        }
    }

    quickcheck::quickcheck! {
        fn roundtrip_address(address_type: AddressType, raw_address: RawAddress) -> bool {
            let address1 = raw_address.for_chain(address_type);
            let s1 = address1.to_string();
            let address2: Address = s1.parse().unwrap();
            let s2 = address2.to_string();
            assert_eq!(s1, s2);
            assert_eq!(address1, address2);
            true
        }
    }

    #[test]
    fn spot_roundtrip_osmo() {
        const S: &str = "osmo168gdk6r58jdwfv49kuesq2rs747jawnn4ryvyk";
        let address: Address = S.parse().unwrap();
        assert_eq!(S, &address.to_string());
    }

    #[test]
    fn spot_roundtrip_juno() {
        const S: &str = "juno168gdk6r58jdwfv49kuesq2rs747jawnnt2584c";
        let address: Address = S.parse().unwrap();
        assert_eq!(S, &address.to_string());
    }
}

impl serde::Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(AddressVisitor)
    }
}

struct AddressVisitor;

impl<'de> Visitor<'de> for AddressVisitor {
    type Value = Address;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Cosmos address")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        v.parse().map_err(|e| E::custom(e))
    }
}

/// An address where the [AddressType] is known to be Juno.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct JunoAddress {
    raw_address: RawAddress,
}

impl From<JunoAddress> for Address {
    fn from(JunoAddress { raw_address }: JunoAddress) -> Self {
        raw_address.for_chain(AddressType::Juno)
    }
}

impl From<RawAddress> for JunoAddress {
    fn from(raw_address: RawAddress) -> Self {
        JunoAddress { raw_address }
    }
}

impl TryFrom<Address> for JunoAddress {
    type Error = anyhow::Error;

    fn try_from(Address { raw_address, type_ }: Address) -> Result<Self, Self::Error> {
        if let AddressType::Juno = type_ {
            Ok(JunoAddress { raw_address })
        } else {
            Err(anyhow::anyhow!(
                "Cannot convert to JunoAddress from {type_:?}"
            ))
        }
    }
}

impl Display for JunoAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            Address {
                raw_address: self.raw_address,
                type_: AddressType::Juno
            }
        )
    }
}

impl FromStr for JunoAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse()? {
            Address {
                raw_address,
                type_: AddressType::Juno,
            } => Ok(JunoAddress { raw_address }),
            _ => Err(anyhow::anyhow!("Expected a Juno address")),
        }
    }
}

impl serde::Serialize for JunoAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for JunoAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let Address { raw_address, type_ } = Address::deserialize(deserializer)?;
        match type_ {
            AddressType::Juno => Ok(JunoAddress { raw_address }),
            _ => Err(D::Error::custom("Expecting a Juno address")),
        }
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{self}\"")
    }
}

impl Debug for JunoAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{self}\"")
    }
}
