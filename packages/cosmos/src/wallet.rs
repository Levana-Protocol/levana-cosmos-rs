use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bitcoin::hashes::{ripemd160, sha256, Hash};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use cosmos_sdk_proto::cosmos::bank::v1beta1::MsgSend;
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
use hkd32::mnemonic::Phrase;
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::Mutex;
use rand::Rng;

use crate::address::RawAddress;
use crate::{Address, AddressType, Cosmos, HasAddress, TxBuilder, TypedMessage};

/// A seed phrase for a wallet
#[derive(Clone)]
pub struct SeedPhrase {
    mnemonic: bip39::Mnemonic,
}
impl SeedPhrase {
    fn random() -> SeedPhrase {
        let mut rng = rand::thread_rng();
        let mut entropy: [u8; 64] = [0; 64];
        for b in &mut entropy {
            *b = rng.gen();
        }
        SeedPhrase {
            mnemonic: bip39::Mnemonic::from_entropy(&entropy).unwrap(),
        }
    }
}

impl From<bip39::Mnemonic> for SeedPhrase {
    fn from(mnemonic: bip39::Mnemonic) -> Self {
        SeedPhrase { mnemonic }
    }
}

impl FromStr for SeedPhrase {
    type Err = anyhow::Error;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        match s {
            "juno-local" => s = JUNO_LOCAL_PHRASE,
            "osmosis-local" | "osmo-local" => s = OSMO_LOCAL_PHRASE,
            _ => (),
        }

        // Create mnemonic and generate seed from it
        let mnemonic = s
            .parse()
            .ok()
            .context("Unable to parse mnemonic from phrase")?;

        Ok(SeedPhrase { mnemonic })
    }
}

/// A private key for a wallet, without specifying the [AddressType].
#[derive(Clone)]
pub struct RawWallet {
    seed_phrase: SeedPhrase,
    derivation_path: Option<Arc<DerivationPath>>,
}

impl FromStr for RawWallet {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RawWallet::from_phrase(s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DerivationPathConfig {
    Three([DerivationPathComponent; 3]),
    Four([DerivationPathComponent; 4]),
    Vec(Vec<DerivationPathComponent>),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DerivationPathComponent {
    pub value: u64,
    pub hardened: bool,
}

impl DerivationPathConfig {
    pub const fn cosmos_numbered(index: u64) -> Self {
        DerivationPathConfig::Four([
            DerivationPathComponent {
                value: 118,
                hardened: true,
            },
            DerivationPathComponent {
                value: 0,
                hardened: true,
            },
            DerivationPathComponent {
                value: 0,
                hardened: false,
            },
            DerivationPathComponent {
                value: index,
                hardened: false,
            },
        ])
    }

    pub const fn ethereum_numbered(index: u64) -> Self {
        DerivationPathConfig::Three([
            DerivationPathComponent {
                value: 60,
                hardened: true,
            },
            DerivationPathComponent {
                value: 0,
                hardened: true,
            },
            DerivationPathComponent {
                value: index,
                hardened: false,
            },
        ])
    }

    pub fn as_derivation_path(&self) -> Arc<DerivationPath> {
        static PATHS: Lazy<Arc<Mutex<HashMap<DerivationPathConfig, Arc<DerivationPath>>>>> =
            Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));
        let mut guard = PATHS.lock();
        match guard.get(self) {
            Some(s) => s.clone(),
            None => {
                let path_str = self.to_string();
                guard.insert(
                    self.clone(),
                    Arc::new(
                        path_str
                            .parse()
                            .with_context(|| {
                                format!("Generated an invalid derivation path: {path_str}")
                            })
                            .unwrap(),
                    ),
                );
                guard.get(self).unwrap().clone()
            }
        }
    }
}

impl Display for &DerivationPathConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "m/44'")?;
        let slice = match self {
            DerivationPathConfig::Three(x) => x.as_slice(),
            DerivationPathConfig::Four(x) => x.as_slice(),
            DerivationPathConfig::Vec(x) => x.as_slice(),
        };
        for component in slice {
            write!(f, "/{component}")?
        }
        Ok(())
    }
}

impl Display for DerivationPathComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.hardened {
            write!(f, "{}'", self.value)
        } else {
            write!(f, "{}", self.value)
        }
    }
}

const JUNO_LOCAL_PHRASE: &str = "clip hire initial neck maid actor venue client foam budget lock catalog sweet steak waste crater broccoli pipe steak sister coyote moment obvious choose";
const OSMO_LOCAL_PHRASE: &str = "notice oak worry limit wrap speak medal online prefer cluster roof addict wrist behave treat actual wasp year salad speed social layer crew genius";

// fn make_derivation_path()

impl RawWallet {
    /// Generate the special Juno Local wallet
    pub fn juno_local() -> Self {
        Self::from_phrase(JUNO_LOCAL_PHRASE).unwrap()
    }

    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let (derivation_path, phrase) = if phrase.starts_with("m/44") {
            match phrase.split_once(' ') {
                Some((path, phrase)) => {
                    let path = Arc::new(path.parse()?);
                    (Some(path), phrase)
                }
                None => (None, phrase),
            }
        } else {
            (None, phrase)
        };

        let seed_phrase = SeedPhrase::from_str(phrase)?;
        Ok(RawWallet {
            seed_phrase,
            derivation_path,
        })
    }

    pub fn for_chain(&self, type_: AddressType) -> Result<Wallet> {
        let secp = global_secp();
        let derivation_path = self
            .derivation_path
            .clone()
            .unwrap_or_else(|| type_.default_derivation_path());

        let root_private_key = bitcoin::util::bip32::ExtendedPrivKey::new_master(
            bitcoin::Network::Bitcoin,
            &self.seed_phrase.mnemonic.to_seed(""),
        )?;
        let privkey = root_private_key.derive_priv(secp, &*derivation_path)?;
        let public_key = ExtendedPubKey::from_priv(secp, &privkey);

        let public_key_bytes = public_key.public_key.serialize();
        let raw_address = address_from_public_key(&public_key_bytes);
        let address = RawAddress::from(raw_address).for_chain(type_);

        Ok(Wallet {
            address,
            privkey,
            // pubkey: public_key,
            public_key_bytes,
        })
    }
}

/// A wallet capable of signing on a specific blockchain
#[derive(Clone)]
// Not deriving Copy since this is a pretty large data structure.
pub struct Wallet {
    address: Address,
    privkey: ExtendedPrivKey,
    // pubkey: ExtendedPubKey,
    public_key_bytes: [u8; 33],
}

fn global_secp() -> &'static Secp256k1<All> {
    static CELL: OnceCell<Secp256k1<All>> = OnceCell::new();
    CELL.get_or_init(Secp256k1::new)
}

impl Wallet {
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Generate a random mnemonic phrase
    pub fn generate_phrase() -> String {
        let mut rng = rand::thread_rng();
        Phrase::random(&mut rng, Default::default())
            .phrase()
            .to_owned()
    }

    /// Generate a random wallet
    pub fn generate(type_: AddressType) -> Result<Self> {
        RawWallet {
            seed_phrase: SeedPhrase::random(),
            derivation_path: None,
        }
        .for_chain(type_)
    }

    /// Generate the special Juno Local wallet
    pub fn juno_local() -> Self {
        RawWallet::juno_local()
            .for_chain(AddressType::Juno)
            .unwrap()
    }

    pub fn from_phrase(phrase: &str, type_: AddressType) -> Result<Self> {
        RawWallet::from_phrase(phrase)
            .map(|raw| raw.for_chain(type_))
            .unwrap()
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }

    pub fn sign_bytes(&self, msg: &[u8]) -> Signature {
        let msg = sha256::Hash::hash(msg);
        let msg = Message::from_slice(msg.as_ref()).unwrap();
        global_secp().sign_ecdsa(&msg, &self.privkey.private_key)
    }

    /// A simple helper function for signing and broadcasting a single message and waiting for a response.
    ///
    /// Generates an error if the transaction failed.
    pub async fn broadcast_message(
        &self,
        cosmos: &Cosmos,
        msg: impl Into<TypedMessage>,
    ) -> Result<TxResponse> {
        TxBuilder::default()
            .add_message(msg.into())
            .sign_and_broadcast(cosmos, self)
            .await
    }

    /// Send coins to the given wallet
    pub async fn send_coins(
        &self,
        cosmos: &Cosmos,
        dest: Address,
        amount: Vec<Coin>,
    ) -> Result<TxResponse> {
        self.broadcast_message(
            cosmos,
            MsgSend {
                from_address: self.to_string(),
                to_address: dest.to_string(),
                amount,
            },
        )
        .await
    }

    /// Send a given amount of gas coin
    pub async fn send_gas_coin(
        &self,
        cosmos: &Cosmos,
        dest: &impl HasAddress,
        amount: u128,
    ) -> Result<TxResponse> {
        self.broadcast_message(
            cosmos,
            MsgSend {
                from_address: self.to_string(),
                to_address: dest.get_address_string(),
                amount: vec![Coin {
                    denom: cosmos.get_gas_coin().clone(),
                    amount: amount.to_string(),
                }],
            },
        )
        .await
    }
}

fn address_from_public_key(public_key: &[u8]) -> [u8; 20] {
    let sha = sha256::Hash::hash(public_key);
    ripemd160::Hash::hash(sha.as_ref()).into_inner()
}

impl Display for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl HasAddress for Wallet {
    fn get_address(&self) -> Address {
        self.address
    }
}
