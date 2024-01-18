use std::{fmt::Display, str::FromStr};

use serde::de::Visitor;

use crate::{error::BuilderError, gas_price::GasPriceMethod, Cosmos, CosmosBuilder, HasAddressHrp};

/// A set of known networks.
///
/// This library is designed to work with arbitrary other chains too, but
/// providing this built-in list is intended to provide convenience for users of
/// the library.
///
/// Generally you'll want to use either [CosmosNetwork::builder] or [CosmosNetwork::connect].
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[allow(missing_docs)]
pub enum CosmosNetwork {
    JunoTestnet,
    JunoMainnet,
    JunoLocal,
    OsmosisMainnet,
    OsmosisTestnet,
    OsmosisLocal,
    WasmdLocal,
    SeiMainnet,
    SeiTestnet,
    StargazeTestnet,
    StargazeMainnet,
    InjectiveTestnet,
    InjectiveMainnet,
}

impl CosmosNetwork {
    /// Convenience method to make a [Self::builder] and then [CosmosBuilder::build] it.
    pub async fn connect(self) -> Result<Cosmos, BuilderError> {
        self.builder().await?.build().await
    }

    /// Construct a [CosmosBuilder] for this network with default values.
    ///
    /// Combines [Self::builder_local] and [Self::load_settings].
    ///
    /// If you have an existing [reqwest::Client], consider using [Self::builder_with].
    pub async fn builder(self) -> Result<CosmosBuilder, BuilderError> {
        self.builder_with(&reqwest::Client::new()).await
    }

    /// Same as [Self::builder] but takes an existing [reqwest::Client]
    pub async fn builder_with(
        self,
        client: &reqwest::Client,
    ) -> Result<CosmosBuilder, BuilderError> {
        let mut builder = self.builder_local();
        self.load_settings(client, &mut builder).await?;
        Ok(builder)
    }

    /// Construct a [CosmosBuilder] without loading settings from the internet.
    pub fn builder_local(self) -> CosmosBuilder {
        let mut builder = CosmosBuilder::new(
            self.chain_id(),
            self.gas_coin(),
            self.get_address_hrp(),
            self.grpc_url(),
        );
        self.local_settings(&mut builder);
        builder
    }

    /// Chain ID for the network
    pub fn chain_id(self) -> &'static str {
        match self {
            CosmosNetwork::JunoTestnet => "uni-6",
            CosmosNetwork::JunoMainnet => "juno-1",
            CosmosNetwork::JunoLocal => "testing",
            CosmosNetwork::OsmosisMainnet => "osmosis-1",
            CosmosNetwork::OsmosisTestnet => "osmo-test-5",
            CosmosNetwork::OsmosisLocal => "localosmosis",
            CosmosNetwork::WasmdLocal => "localwasmd",
            CosmosNetwork::SeiMainnet => "pacific-1",
            CosmosNetwork::SeiTestnet => "atlantic-2",
            CosmosNetwork::StargazeTestnet => "elgafar-1",
            CosmosNetwork::StargazeMainnet => "stargaze-1",
            CosmosNetwork::InjectiveTestnet => "injective-888",
            CosmosNetwork::InjectiveMainnet => "injective-1",
        }
    }

    /// Gas coin for the network
    pub fn gas_coin(self) -> &'static str {
        match self {
            CosmosNetwork::JunoTestnet | CosmosNetwork::JunoLocal => "ujunox",
            CosmosNetwork::JunoMainnet => "ujuno",
            CosmosNetwork::OsmosisMainnet
            | CosmosNetwork::OsmosisTestnet
            | CosmosNetwork::OsmosisLocal => "uosmo",
            CosmosNetwork::WasmdLocal => "uwasm",
            CosmosNetwork::SeiMainnet | CosmosNetwork::SeiTestnet => "usei",
            CosmosNetwork::StargazeTestnet | CosmosNetwork::StargazeMainnet => "ustars",
            CosmosNetwork::InjectiveTestnet | CosmosNetwork::InjectiveMainnet => "inj",
        }
    }

    /// Default gRPC URL for the network
    pub fn grpc_url(self) -> &'static str {
        match self {
            CosmosNetwork::JunoTestnet => "http://juno-testnet-grpc.polkachu.com:12690",
            // Found at: https://cosmos.directory/juno/nodes
            CosmosNetwork::JunoMainnet => "http://juno-grpc.polkachu.com:12690",
            CosmosNetwork::JunoLocal => "http://localhost:9090",
            // Found at: https://docs.osmosis.zone/networks/
            CosmosNetwork::OsmosisMainnet => "http://grpc.osmosis.zone:9090",
            // Others available at: https://docs.osmosis.zone/networks/
            CosmosNetwork::OsmosisTestnet => "https://grpc.osmotest5.osmosis.zone",
            CosmosNetwork::OsmosisLocal => "http://localhost:9090",
            CosmosNetwork::WasmdLocal => "http://localhost:9090",
            CosmosNetwork::SeiMainnet => "https://grpc.sei-apis.com",
            CosmosNetwork::SeiTestnet => "https://grpc-testnet.sei-apis.com",
            // https://github.com/cosmos/chain-registry/blob/master/testnets/stargazetestnet/chain.json
            CosmosNetwork::StargazeTestnet => "http://grpc-1.elgafar-1.stargaze-apis.com:26660",
            // https://github.com/cosmos/chain-registry/blob/master/stargaze/chain.json
            CosmosNetwork::StargazeMainnet => "http://stargaze-grpc.polkachu.com:13790",
            // https://docs.injective.network/develop/public-endpoints/
            CosmosNetwork::InjectiveTestnet => {
                "https://testnet.sentry.chain.grpc.injective.network"
            }
            // https://docs.injective.network/develop/public-endpoints/
            CosmosNetwork::InjectiveMainnet => "https://sentry.chain.grpc.injective.network",
        }
    }

    /// Override other settings based on chain.
    pub fn local_settings(self, builder: &mut CosmosBuilder) {
        match self {
            CosmosNetwork::JunoTestnet
            | CosmosNetwork::JunoMainnet
            | CosmosNetwork::OsmosisTestnet
            | CosmosNetwork::StargazeTestnet
            | CosmosNetwork::StargazeMainnet => (),
            CosmosNetwork::OsmosisMainnet => {
                builder.set_osmosis_mainnet_chain_paused();
                // We need a very wide band on Osmosis gas prices due to bugs in
                // the EIP fee market mechanism. Do lots of smaller attempts to
                // avoid overpaying by too much.
                builder.set_gas_price_retry_attempts(Some(12));
            }
            CosmosNetwork::SeiMainnet => {
                // https://raw.githubusercontent.com/sei-protocol/chain-registry/master/gas.json
                builder.set_gas_price(0.1, 0.2);
                builder.set_gas_price_retry_attempts(Some(6));
            }
            CosmosNetwork::SeiTestnet => {
                // https://raw.githubusercontent.com/sei-protocol/testnet-registry/master/gas.json
                builder.set_gas_price(0.1, 0.2);
                builder.set_gas_price_retry_attempts(Some(6));
            }
            CosmosNetwork::JunoLocal | CosmosNetwork::WasmdLocal | CosmosNetwork::OsmosisLocal => {
                // fail faster during testing
                builder.set_transaction_attempts(Some(3));
            }
            CosmosNetwork::InjectiveTestnet => {
                // https://github.com/cosmos/chain-registry/blob/master/testnets/injectivetestnet/chain.json
                builder.set_gas_price(500000000.0, 900000000.0);
            }
            CosmosNetwork::InjectiveMainnet => {
                // https://github.com/cosmos/chain-registry/blob/master/injective/chain.json
                builder.set_gas_price(500000000.0, 900000000.0);
            }
        }
    }

    /// Load settings, like gas fees, from the internet.
    pub async fn load_settings(
        self,
        client: &reqwest::Client,
        builder: &mut CosmosBuilder,
    ) -> Result<(), BuilderError> {
        match self {
            CosmosNetwork::JunoTestnet
            | CosmosNetwork::JunoMainnet
            | CosmosNetwork::JunoLocal
            | CosmosNetwork::OsmosisTestnet
            | CosmosNetwork::OsmosisLocal
            | CosmosNetwork::WasmdLocal
            | CosmosNetwork::StargazeTestnet
            | CosmosNetwork::StargazeMainnet
            | CosmosNetwork::InjectiveTestnet
            | CosmosNetwork::InjectiveMainnet => Ok(()),
            CosmosNetwork::OsmosisMainnet => {
                builder.set_gas_price_method(GasPriceMethod::new_osmosis_mainnet(builder).await?);
                Ok(())
            }
            CosmosNetwork::SeiMainnet => {
                #[derive(serde::Deserialize)]
                struct SeiGasConfig {
                    #[serde(rename = "pacific-1")]
                    pub pacific_1: SeiGasConfigItem,
                }
                #[derive(serde::Deserialize)]
                struct SeiGasConfigItem {
                    pub min_gas_price: f64,
                }

                let gas_config = load_json::<SeiGasConfig>(
                    "https://raw.githubusercontent.com/sei-protocol/chain-registry/master/gas.json",
                    client,
                )
                .await?;

                builder.set_gas_price(
                    gas_config.pacific_1.min_gas_price,
                    gas_config.pacific_1.min_gas_price * 2.0,
                );
                Ok(())
            }
            CosmosNetwork::SeiTestnet => {
                #[derive(serde::Deserialize)]
                struct SeiGasConfig {
                    #[serde(rename = "atlantic-2")]
                    pub atlantic_2: SeiGasConfigItem,
                }
                #[derive(serde::Deserialize)]
                struct SeiGasConfigItem {
                    pub min_gas_price: f64,
                }

                let gas_config = load_json::<SeiGasConfig>(
                "https://raw.githubusercontent.com/sei-protocol/testnet-registry/master/gas.json",
                    client,
                )
                .await?;

                builder.set_gas_price(
                    gas_config.atlantic_2.min_gas_price,
                    gas_config.atlantic_2.min_gas_price * 2.0,
                );
                Ok(())
            }
        }
    }
}

async fn load_json<T>(url: &str, client: &reqwest::Client) -> Result<T, BuilderError>
where
    T: serde::de::DeserializeOwned,
{
    async {
        client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }
    .await
    .map_err(|source| BuilderError::DownloadChainInfo {
        url: url.to_owned(),
        source,
    })
}

impl serde::Serialize for CosmosNetwork {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CosmosNetwork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(CosmosNetworkVisitor)
    }
}

struct CosmosNetworkVisitor;

impl<'de> Visitor<'de> for CosmosNetworkVisitor {
    type Value = CosmosNetwork;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("CosmosNetwork")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        CosmosNetwork::from_str(v).map_err(E::custom)
    }
}

impl CosmosNetwork {
    fn as_str(self) -> &'static str {
        match self {
            CosmosNetwork::JunoTestnet => "juno-testnet",
            CosmosNetwork::JunoMainnet => "juno-mainnet",
            CosmosNetwork::JunoLocal => "juno-local",
            CosmosNetwork::OsmosisMainnet => "osmosis-mainnet",
            CosmosNetwork::OsmosisTestnet => "osmosis-testnet",
            CosmosNetwork::OsmosisLocal => "osmosis-local",
            CosmosNetwork::WasmdLocal => "wasmd-local",
            CosmosNetwork::SeiMainnet => "sei-mainnet",
            CosmosNetwork::SeiTestnet => "sei-testnet",
            CosmosNetwork::StargazeTestnet => "stargaze-testnet",
            CosmosNetwork::StargazeMainnet => "stargaze-mainnet",
            CosmosNetwork::InjectiveTestnet => "injective-testnet",
            CosmosNetwork::InjectiveMainnet => "injective-mainnet",
        }
    }
}

impl Display for CosmosNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CosmosNetwork {
    type Err = BuilderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "juno-testnet" => Ok(CosmosNetwork::JunoTestnet),
            "juno-mainnet" => Ok(CosmosNetwork::JunoMainnet),
            "juno-local" => Ok(CosmosNetwork::JunoLocal),
            "osmosis-mainnet" => Ok(CosmosNetwork::OsmosisMainnet),
            "osmosis-testnet" => Ok(CosmosNetwork::OsmosisTestnet),
            "osmosis-local" => Ok(CosmosNetwork::OsmosisLocal),
            "wasmd-local" => Ok(CosmosNetwork::WasmdLocal),
            "sei-mainnet" => Ok(CosmosNetwork::SeiMainnet),
            "sei-testnet" => Ok(CosmosNetwork::SeiTestnet),
            "stargaze-testnet" => Ok(CosmosNetwork::StargazeTestnet),
            "stargaze-mainnet" => Ok(CosmosNetwork::StargazeMainnet),
            "injective-testnet" => Ok(CosmosNetwork::InjectiveTestnet),
            "injective-mainnet" => Ok(CosmosNetwork::InjectiveMainnet),
            _ => Err(BuilderError::UnknownCosmosNetwork {
                network: s.to_owned(),
            }),
        }
    }
}
