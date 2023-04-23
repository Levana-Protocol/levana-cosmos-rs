use std::fmt::Display;
use std::str::FromStr;

use anyhow::{Context, Result};
use bitcoin::hashes::{ripemd160, sha256, Hash};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, IntoDerivationPath};
use cosmos_sdk_proto::cosmos::bank::v1beta1::MsgSend;
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
use hkd32::mnemonic::{Phrase, Seed};
use once_cell::sync::OnceCell;

use crate::address::RawAddress;
use crate::{Address, AddressType, Cosmos, HasAddress, TxBuilder, TypedMessage};

/// A seed phrase for a wallet
pub struct SeedPhrase {
    seed: Seed,
}

impl From<Seed> for SeedPhrase {
    fn from(seed: Seed) -> Self {
        SeedPhrase { seed }
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
        let phrase = hkd32::mnemonic::Phrase::new(s, hkd32::mnemonic::Language::English)
            .ok()
            .context("Unable to parse mnemonic from phrase")?;

        Ok(SeedPhrase {
            seed: phrase.to_seed(""),
        })
    }
}

impl SeedPhrase {
    /// Derive a [RawWallet] from this seed phrase and a given derivation path
    pub fn derive(&self, derivation_path: &str) -> Result<RawWallet> {
        let root_private_key = bitcoin::util::bip32::ExtendedPrivKey::new_master(
            bitcoin::Network::Bitcoin,
            self.seed.as_bytes(),
        )?;

        let derivation_path = derivation_path.into_derivation_path()?;
        let secp = global_secp();

        Ok(RawWallet {
            privkey: root_private_key.derive_priv(secp, &derivation_path)?,
        })
    }

    /// Use the default Cosmos derivation path
    pub fn derive_cosmos(&self) -> Result<RawWallet> {
        self.derive(DEFAULT_DERIVATION_PATH)
    }

    /// Use a numbered account on the default Cosmos derivation path
    pub fn derive_cosmos_numbered(&self, idx: u32) -> Result<RawWallet> {
        self.derive(&format!("m/44'/118'/0'/0/{idx}"))
    }
}

/// A private key for a wallet, without specifying the [AddressType].
#[derive(Clone, Copy)]
pub struct RawWallet {
    privkey: ExtendedPrivKey,
}

impl FromStr for RawWallet {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RawWallet::from_phrase(s)
    }
}

const DEFAULT_DERIVATION_PATH: &str = "m/44'/118'/0'/0/0";
const JUNO_LOCAL_PHRASE: &str = "clip hire initial neck maid actor venue client foam budget lock catalog sweet steak waste crater broccoli pipe steak sister coyote moment obvious choose";
const OSMO_LOCAL_PHRASE: &str = "notice oak worry limit wrap speak medal online prefer cluster roof addict wrist behave treat actual wasp year salad speed social layer crew genius";

impl RawWallet {
    /// Generate the special Juno Local wallet
    pub fn juno_local() -> Self {
        Self::from_phrase(JUNO_LOCAL_PHRASE).unwrap()
    }

    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let (derivation_path, phrase) = if phrase.starts_with("m/44") {
            match phrase.split_once(' ') {
                Some(x) => x,
                None => (DEFAULT_DERIVATION_PATH, phrase),
            }
        } else {
            (DEFAULT_DERIVATION_PATH, phrase)
        };

        let seed_phrase = SeedPhrase::from_str(phrase)?;
        seed_phrase.derive(derivation_path)
    }

    pub fn for_chain(self, type_: AddressType) -> Wallet {
        let secp = global_secp();
        let public_key = ExtendedPubKey::from_priv(secp, &self.privkey);

        let public_key_bytes = public_key.public_key.serialize();
        let raw_address = address_from_public_key(&public_key_bytes);
        let address = RawAddress::from(raw_address).for_chain(type_);

        Wallet {
            address,
            privkey: self.privkey,
            // pubkey: public_key,
            public_key_bytes,
        }
    }
}

/// A wallet capable of signing on a specific blockchain
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
        let mut bytes = [0; Seed::SIZE];
        for byte in &mut bytes {
            *byte = rand::random();
        }
        Self::from_seed(Seed::new(bytes), DEFAULT_DERIVATION_PATH, type_)
    }

    /// Generate the special Juno Local wallet
    pub fn juno_local() -> Self {
        RawWallet::juno_local().for_chain(AddressType::Juno)
    }

    pub fn from_phrase(phrase: &str, type_: AddressType) -> Result<Self> {
        RawWallet::from_phrase(phrase).map(|raw| raw.for_chain(type_))
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

    fn from_seed(seed: Seed, derivation_path: &str, type_: AddressType) -> Result<Self> {
        SeedPhrase::from(seed)
            .derive(derivation_path)
            .map(|raw| raw.for_chain(type_))
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
