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
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::Mutex;
use rand::Rng;
use tiny_keccak::{Hasher, Keccak};

use crate::address::{AddressHrp, HasAddressHrp, PublicKeyMethod, RawAddress};
use crate::{Address, Cosmos, HasAddress, TxBuilder, TypedMessage};

/// A seed phrase for a wallet, together with an optional derivation path.
///
/// The derivation path can be provided before the seed phrase to override the default derivation path.
#[derive(Clone)]
pub struct SeedPhrase {
    /// The mnemonic seed phrase itself, used for deriving private keys.
    pub mnemonic: bip39::Mnemonic,
    /// The override derivation path to use when deriving private keys.
    pub derivation_path: Option<Arc<DerivationPath>>,
    /// The override method for converting the public key into bytes.
    pub public_key_method: Option<PublicKeyMethod>,
}

impl SeedPhrase {
    /// Generate a random [SeedPhrase].
    pub fn random() -> SeedPhrase {
        let mut rng = rand::thread_rng();
        let mut entropy: [u8; 32] = [0; 32];
        for b in &mut entropy {
            *b = rng.gen();
        }
        SeedPhrase {
            mnemonic: bip39::Mnemonic::from_entropy(&entropy).unwrap(),
            derivation_path: None,
            public_key_method: None,
        }
    }

    /// Generate the seed phrase itself.
    ///
    /// Note that this should be considered security-sensitive content.
    pub fn phrase(&self) -> String {
        let mut phrase = String::new();
        for (idx, word) in self.mnemonic.word_iter().enumerate() {
            if idx != 0 {
                phrase.push(' ');
            }
            phrase.push_str(word);
        }
        phrase
    }

    /// Make a new [SeedPhrase] using the given derivation path.
    fn with_derivation_path(mut self, derivation_path: Option<Arc<DerivationPath>>) -> Self {
        self.derivation_path = derivation_path;
        self
    }

    /// Make a new [SeedPhrase] using a Cosmos derivation path and the given index.
    pub fn with_cosmos_numbered(self, index: u64) -> Self {
        self.with_derivation_path(Some(
            DerivationPathConfig::cosmos_numbered(index).as_derivation_path(),
        ))
    }

    /// Make a new [SeedPhrase] using an Ethereum derivation path and the given index.
    pub fn with_ethereum_numbered(self, index: u64) -> Self {
        self.with_derivation_path(Some(
            DerivationPathConfig::ethereum_numbered(index).as_derivation_path(),
        ))
    }

    /// Generate a new [Wallet] with the given HRP.
    ///
    /// If no public key method is provided, the default for the given HRP is
    /// used. Similarly, if `self` does not include a derivation path, the
    /// default for the HRP is used.
    pub fn with_hrp(&self, hrp: AddressHrp) -> Result<Wallet> {
        let secp = global_secp();
        let derivation_path = self
            .derivation_path
            .clone()
            .unwrap_or_else(|| hrp.default_derivation_path());

        let root_private_key = bitcoin::util::bip32::ExtendedPrivKey::new_master(
            bitcoin::Network::Bitcoin,
            &self.mnemonic.to_seed(""),
        )?;
        let privkey = root_private_key.derive_priv(secp, &*derivation_path)?;
        let public_key = ExtendedPubKey::from_priv(secp, &privkey);
        let public_key_bytes = public_key.public_key.serialize();
        let public_key_bytes_uncompressed = public_key.public_key.serialize_uncompressed();

        let public_key_method = self
            .public_key_method
            .unwrap_or_else(|| hrp.default_public_key_method());
        let (raw_address, public_key) = match public_key_method {
            crate::address::PublicKeyMethod::Cosmos => (
                cosmos_address_from_public_key(&public_key_bytes),
                WalletPublicKey::Cosmos(public_key_bytes),
            ),
            crate::address::PublicKeyMethod::Ethereum => (
                eth_address_from_public_key(&public_key_bytes_uncompressed),
                WalletPublicKey::Ethereum(public_key_bytes_uncompressed),
            ),
        };
        let address = RawAddress::from(raw_address).with_hrp(hrp);

        Ok(Wallet {
            address,
            privkey,
            public_key,
        })
    }
}

impl From<bip39::Mnemonic> for SeedPhrase {
    fn from(mnemonic: bip39::Mnemonic) -> Self {
        SeedPhrase {
            mnemonic,
            derivation_path: None,
            public_key_method: None,
        }
    }
}

impl FromStr for SeedPhrase {
    type Err = anyhow::Error;

    fn from_str(mut phrase: &str) -> Result<Self, Self::Err> {
        match phrase {
            "juno-local" => phrase = JUNO_LOCAL_PHRASE,
            "osmosis-local" | "osmo-local" => phrase = OSMO_LOCAL_PHRASE,
            _ => (),
        }

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

        let mnemonic = phrase
            .parse()
            .ok()
            .context("Unable to parse mnemonic from phrase")?;

        Ok(SeedPhrase {
            derivation_path,
            mnemonic,
            public_key_method: None,
        })
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
        DerivationPathConfig::Four([
            DerivationPathComponent {
                value: 60,
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

    pub fn as_derivation_path(&self) -> Arc<DerivationPath> {
        type DerivationPathMap = HashMap<DerivationPathConfig, Arc<DerivationPath>>;
        static PATHS: Lazy<Arc<Mutex<DerivationPathMap>>> =
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

/// A wallet capable of signing on a specific blockchain
#[derive(Clone)]
// Not deriving Copy since this is a pretty large data structure.
pub struct Wallet {
    address: Address,
    privkey: ExtendedPrivKey,
    pub(crate) public_key: WalletPublicKey,
}

#[derive(Clone)]
pub(crate) enum WalletPublicKey {
    Cosmos([u8; 33]),
    Ethereum([u8; 65]),
}

fn global_secp() -> &'static Secp256k1<All> {
    static CELL: OnceCell<Secp256k1<All>> = OnceCell::new();
    CELL.get_or_init(Secp256k1::new)
}

impl Wallet {
    /// Generate a random wallet
    ///
    /// If you want more control over the derivation settings, use [SeedPhrase::random] instead.
    pub fn generate(hrp: AddressHrp) -> Result<Self> {
        SeedPhrase::random().with_hrp(hrp)
    }

    /// Get the byte representation of the public key used on chain.
    pub fn public_key_bytes(&self) -> &[u8] {
        match &self.public_key {
            WalletPublicKey::Cosmos(public_key) => public_key,
            WalletPublicKey::Ethereum(public_key) => public_key,
        }
    }

    /// Sign the given bytes with this wallet
    ///
    /// Note that the signature will depend on the [PublicKeyMethod] used when
    /// deriving this wallet.
    pub fn sign_bytes(&self, msg: &[u8]) -> Signature {
        let msg = match self.public_key {
            WalletPublicKey::Cosmos(_) => sha256::Hash::hash(msg).into_inner(),
            WalletPublicKey::Ethereum(_) => keccak(msg),
        };
        let msg = Message::from_slice(msg.as_ref()).unwrap();
        global_secp().sign_ecdsa(&msg, &self.privkey.private_key)
    }

    // Technically these functions are redundant, but keeping them as
    // convenient/ergonomic helpers.

    /// A simple helper function for signing and broadcasting a single message and waiting for a response.
    ///
    /// Generates an error if the transaction failed.
    ///
    /// Note: this is just a helper around the more general [TxBuilder] interface.
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
    ///
    /// Note: this is just a helper around the more general [TxBuilder] interface.
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
    ///
    /// Note: this is just a helper around the more general [TxBuilder] interface.
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
                    denom: cosmos.get_cosmos_builder().gas_coin().to_owned(),
                    amount: amount.to_string(),
                }],
            },
        )
        .await
    }
}

fn cosmos_address_from_public_key(public_key: &[u8]) -> [u8; 20] {
    let sha = sha256::Hash::hash(public_key);
    ripemd160::Hash::hash(sha.as_ref()).into_inner()
}

fn eth_address_from_public_key(public_key: &[u8; 65]) -> [u8; 20] {
    assert_eq!(public_key[0], 4);
    let hash = keccak(&public_key[1..]);
    let mut output = [0u8; 20];
    output.copy_from_slice(&hash[12..]);
    output
}

impl Display for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl HasAddressHrp for Wallet {
    fn get_address_hrp(&self) -> AddressHrp {
        self.address.get_address_hrp()
    }
}

impl HasAddress for Wallet {
    fn get_address(&self) -> Address {
        self.address
    }
}

fn keccak(input: &[u8]) -> [u8; 32] {
    let mut sha3 = Keccak::v256();
    sha3.update(input);
    let mut output = [0; 32];
    sha3.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::SecretKey;

    use super::*;

    #[test]
    fn test_ethereum_from_seed_phrase() {
        const PHRASE: &str =
            "entire clap mystery embrace blame doll volcano face trust mom cruel load";
        const ADDRESS: &str = "0x00980adc74d3d2053c011cb0528fbe1fa91a352c";
        let address = ADDRESS.chars().skip(2).collect::<String>();
        let phrase = SeedPhrase::from_str(PHRASE).unwrap();
        let wallet = phrase.with_hrp(AddressHrp::from_static("inj")).unwrap();
        let eth_address = eth_address_from_public_key(match &wallet.public_key {
            WalletPublicKey::Cosmos(_) => panic!("Should not be Cosmos"),
            WalletPublicKey::Ethereum(public_key) => public_key,
        });
        assert_eq!(address, hex::encode(eth_address));
    }

    #[test]
    fn test_osmosis_and_injective_addresses() {
        const PHRASE: &str =
            "dilemma flavor noise circle voyage vacant amateur mass morning tunnel unhappy entire";
        let expected_osmosis: Address = "osmo1t3mvqjxvfxlstyzfskl37zqgu5ftq0rttpqqc5"
            .parse()
            .unwrap();
        let expected_injective: Address = "inj15sws48vv977kmgawqfegptw0pqs7cfeq7mpr4c"
            .parse()
            .unwrap();
        let seed_phrase = SeedPhrase::from_str(PHRASE).unwrap();
        let osmosis = seed_phrase
            .with_hrp(AddressHrp::from_static("osmo"))
            .unwrap();
        let injective = seed_phrase
            .with_hrp(AddressHrp::from_static("inj"))
            .unwrap();
        assert_eq!(expected_osmosis, osmosis.get_address());
        assert_eq!(expected_injective, injective.get_address());
    }

    // https://www.geeksforgeeks.org/how-to-create-an-ethereum-wallet-address-from-a-private-key/
    #[test]
    fn test_ethereum_address() {
        const PRIVATE_KEY: &str =
            "4f3edf983ac986a65a342ce7c78d9ac076d3b113bce9c46f30d7d25171b32b1d";
        const PUBLIC_KEY: &str = "04c1573f1528638ae14cbe04a74e6583c5562d59214223762c1a11121e24619cbc09d27a7a1cb989dd801cc028dd8225f8e2d2fd57d852b5bf697112f69b6229d1";
        const ADDRESS: &str = "0xAf3CD5c36B97E9c28c263dC4639c6d7d53303A13";

        let public_key_from_str = hex::decode(PUBLIC_KEY).unwrap();

        let secret_key = SecretKey::from_str(PRIVATE_KEY).unwrap();
        let secp = global_secp();
        let public_key = secret_key.public_key(secp);
        let public_key_bytes = public_key.serialize_uncompressed();

        assert_eq!(public_key_from_str.as_slice(), &public_key_bytes);

        // https://tms-dev-blog.com/build-a-crypto-wallet-using-rust/#A_Simple_Rust_wallet
        let eth_address = eth_address_from_public_key(&public_key_bytes);
        assert_eq!(
            ADDRESS
                .chars()
                .skip(2)
                .map(|mut c| {
                    c.make_ascii_lowercase();
                    c
                })
                .collect::<String>(),
            hex::encode(eth_address)
        );
    }

    #[test]
    fn test_ethereum_hashing() {
        // https://github.com/ethereumbook/ethereumbook/blob/develop/04keys-addresses.asciidoc?ref=tms-dev-blog.com#ethereum-addresses
        const PRIVATE_KEY_STR: &str =
            "f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315";
        const PUBLIC_KEY_STR: &str = "046e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0";
        const PUBLIC_KEY_HASHED_STR: &str =
            "2a5bc342ed616b5ba5732269001d3f1ef827552ae1114027bd3ecf1f086ba0f9";

        let private_key = hex::decode(PRIVATE_KEY_STR).unwrap();
        let private_key1 = SecretKey::from_str(PRIVATE_KEY_STR).unwrap();
        let private_key2 = SecretKey::from_slice(&private_key).unwrap();
        assert_eq!(private_key1, private_key2);

        let secp = global_secp();
        let public_key = private_key1.public_key(secp);
        let public_key_bytes = public_key.serialize_uncompressed();

        assert_eq!(PUBLIC_KEY_STR, &hex::encode(public_key_bytes));
        assert_eq!(
            PUBLIC_KEY_HASHED_STR,
            hex::encode(keccak(&public_key_bytes[1..]))
        );
    }

    #[test]
    fn test_keccak() {
        // https://github.com/ethereumbook/ethereumbook/blob/develop/04keys-addresses.asciidoc?ref=tms-dev-blog.com#which-hash-function-am-i-using
        let hash = keccak(&[]);
        assert_eq!(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            hex::encode(hash)
        );
    }
}
