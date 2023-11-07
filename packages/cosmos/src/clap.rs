//! Provides helpers for generating Cosmos values from command line parameters.

use crate::{error::BuilderError, Cosmos, CosmosBuilder, CosmosNetwork};

/// Command line options for connecting to a Cosmos network
#[derive(clap::Parser, Clone, Debug)]
pub struct CosmosOpt {
    /// Which blockchain to connect to for grabbing blocks
    #[clap(long, env = "COSMOS_NETWORK", global = true)]
    pub network: Option<CosmosNetwork>,
    /// Optional gRPC endpoint override
    #[clap(long, env = "COSMOS_GRPC", global = true)]
    pub cosmos_grpc: Option<String>,
    /// Optional chain ID override
    #[clap(long, env = "COSMOS_CHAIN_ID", global = true)]
    pub chain_id: Option<String>,
    /// Optional gas multiplier override
    #[clap(long, env = "COSMOS_GAS_MULTIPLIER", global = true)]
    pub gas_multiplier: Option<f64>,
    /// Referer header
    #[clap(long, short, global = true, env = "COSMOS_REFERER_HEADER")]
    referer_header: Option<String>,
}

/// Errors for working with [CosmosOpt]
#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
pub enum CosmosOptError {
    #[error("No network specified, either provide the COSMOS_NETWORK env var or --network option")]
    NoNetworkProvided,
    #[error("{source}")]
    CosmosBuilderError { source: BuilderError },
}

impl CosmosOpt {
    /// Convert these options into a new [CosmosBuilder].
    pub async fn into_builder(self) -> Result<CosmosBuilder, CosmosOptError> {
        let CosmosOpt {
            network,
            cosmos_grpc,
            chain_id,
            gas_multiplier,
            referer_header,
        } = self;

        // Do the error checking here instead of in clap so that the field can
        // be global.
        let network = network.ok_or(CosmosOptError::NoNetworkProvided)?;
        let mut builder = network
            .builder()
            .await
            .map_err(|source| CosmosOptError::CosmosBuilderError { source })?;
        if let Some(grpc) = cosmos_grpc {
            builder.set_grpc_url(grpc);
        }
        if let Some(chain_id) = chain_id {
            builder.set_chain_id(chain_id);
        }

        builder.set_gas_estimate_multiplier(gas_multiplier);
        builder.set_referer_header(referer_header);

        Ok(builder)
    }

    /// Convenient for calling [CosmosOpt::into_builder] and then [CosmosBuilder::build].
    pub async fn build(self) -> Result<Cosmos, CosmosOptError> {
        self.into_builder()
            .await?
            .build()
            .await
            .map_err(|source| CosmosOptError::CosmosBuilderError { source })
    }
}
