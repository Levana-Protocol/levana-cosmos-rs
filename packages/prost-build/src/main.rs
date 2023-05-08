#![allow(clippy::useless_format)]
use anyhow::Result;
use std::io::prelude::*;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    let paths = Paths::new();
    download_proto(&paths).await?;
    compile_proto(&paths)?;

    println!("\n--------");
    println!("all prost files written to '{}'.", paths.output);
    println!("--------\n");

    Ok(())
}

async fn download_proto(paths: &Paths) -> Result<()> {
    for p in Proto::all() {
        let url = p.url();
        let dest = Path::new(&paths.proto).join(p.dest());
        std::fs::create_dir_all(dest.parent().unwrap())?;
        println!(
            "Downloading from '{}' to '{}'.",
            url,
            dest.to_string_lossy()
        );

        let response = reqwest::get(&url).await?;
        let bytes = response.bytes().await?;
        let mut file = std::fs::File::create(&dest)?;
        file.write_all(&bytes)?;
        println!("Data from '{}' saved to '{}'.", url, dest.to_string_lossy());
    }
    Ok(())
}

fn compile_proto(paths: &Paths) -> Result<()> {
    std::fs::create_dir_all(&paths.output)?;
    std::env::set_var("OUT_DIR", &paths.output);

    let proto_files = Proto::all()
        .into_iter()
        .map(|p| format!("{}/{}", paths.proto, p.dest()))
        .collect::<Vec<_>>();

    prost_build::compile_protos(&proto_files, &[&paths.proto])?;

    Ok(())
}

#[derive(Debug)]
struct Paths {
    proto: String,
    output: String,
}

impl Paths {
    pub fn new() -> Self {
        let cargo_dir_string = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let temp_path = Path::new(&cargo_dir_string).join("temp");
        let proto_path = Path::new(&temp_path).join("proto");
        let output_path = Path::new(&temp_path).join("output");

        Self {
            proto: proto_path.to_string_lossy().to_string(),
            output: output_path.to_string_lossy().to_string(),
        }
    }
}

const COSMOS_SDK_VERSION: &str = "v0.47.1";
const COSMOS_PROTO_VERSION: &str = "v1.0.0-beta.3";
const OSMOSIS_VERSION: &str = "v15.0.0"; // testnet is behind master
const REGEN_VERSION: &str = "v1.3.3-alpha.regen.1";
const GOOGLE_VERSION: &str = "master";

const COSMOS_SDK_BASE: &str = "cosmos/base/v1beta1";
const COSMOS_SDK_QUERY: &str = "cosmos/base/query/v1beta1";
const COSMOS_SDK_BANK: &str = "cosmos/bank/v1beta1";
const COSMOS_SDK_AMINO: &str = "amino";
const COSMOS_SDK_MSG: &str = "cosmos/msg/v1";

impl Proto {
    pub fn url(&self) -> String {
        match self {
            Proto::Cosmos => format!("https://raw.githubusercontent.com/cosmos/cosmos-proto/{COSMOS_PROTO_VERSION}/proto/cosmos_proto/cosmos.proto"),
            Proto::CosmosSdk(p) => match p {
                ProtoCosmosSdk::Coin => format!("https://raw.githubusercontent.com/cosmos/cosmos-sdk/{COSMOS_SDK_VERSION}/proto/{COSMOS_SDK_BASE}/coin.proto"), 
                ProtoCosmosSdk::Pagination => format!("https://raw.githubusercontent.com/cosmos/cosmos-sdk/{COSMOS_SDK_VERSION}/proto/{COSMOS_SDK_QUERY}/pagination.proto"), 
                ProtoCosmosSdk::Bank => format!("https://raw.githubusercontent.com/cosmos/cosmos-sdk/{COSMOS_SDK_VERSION}/proto/{COSMOS_SDK_BANK}/bank.proto"), 
                ProtoCosmosSdk::Amino => format!("https://raw.githubusercontent.com/cosmos/cosmos-sdk/{COSMOS_SDK_VERSION}/proto/{COSMOS_SDK_AMINO}/amino.proto"), 
                ProtoCosmosSdk::Msg => format!("https://raw.githubusercontent.com/cosmos/cosmos-sdk/{COSMOS_SDK_VERSION}/proto/{COSMOS_SDK_MSG}/msg.proto"), 
            },
            // actually download from regen, see https://github.com/cosmos/cosmos-sdk/issues/12984#issuecomment-1275674526
            Proto::Gogo => format!("https://raw.githubusercontent.com/regen-network/protobuf/{REGEN_VERSION}/gogoproto/gogo.proto"),
            Proto::Google(p) => match p {
                ProtoGoogle::Annotations => format!("https://raw.githubusercontent.com/googleapis/googleapis/{GOOGLE_VERSION}/google/api/annotations.proto"),
                ProtoGoogle::Http => format!("https://raw.githubusercontent.com/googleapis/googleapis/{GOOGLE_VERSION}/google/api/http.proto"),
            },
            Proto::Osmosis(p) => match p {
                ProtoOsmosis::TokenFactory(p) => match p {
                    ProtoTokenFactory::AuthorityMetadata => format!("https://raw.githubusercontent.com/osmosis-labs/osmosis/{OSMOSIS_VERSION}/proto/osmosis/tokenfactory/v1beta1/authorityMetadata.proto"),
                    ProtoTokenFactory::Genesis => format!("https://raw.githubusercontent.com/osmosis-labs/osmosis/{OSMOSIS_VERSION}/proto/osmosis/tokenfactory/v1beta1/genesis.proto"),
                    ProtoTokenFactory::Params => format!("https://raw.githubusercontent.com/osmosis-labs/osmosis/{OSMOSIS_VERSION}/proto/osmosis/tokenfactory/v1beta1/params.proto"),
                    ProtoTokenFactory::Query => format!("https://raw.githubusercontent.com/osmosis-labs/osmosis/{OSMOSIS_VERSION}/proto/osmosis/tokenfactory/v1beta1/query.proto"),
                    ProtoTokenFactory::Tx => format!("https://raw.githubusercontent.com/osmosis-labs/osmosis/{OSMOSIS_VERSION}/proto/osmosis/tokenfactory/v1beta1/tx.proto"),
                }
            }
        }
    }

    pub fn dest(&self) -> String {
        match self {
            Proto::Cosmos => "cosmos_proto/cosmos.proto".to_string(),
            Proto::CosmosSdk(p) => match p {
                ProtoCosmosSdk::Coin => format!("{COSMOS_SDK_BASE}/coin.proto"),
                ProtoCosmosSdk::Pagination => format!("{COSMOS_SDK_QUERY}/pagination.proto"),
                ProtoCosmosSdk::Bank => format!("{COSMOS_SDK_BANK}/bank.proto"),
                ProtoCosmosSdk::Amino => format!("{COSMOS_SDK_AMINO}/amino.proto"),
                ProtoCosmosSdk::Msg => format!("{COSMOS_SDK_MSG}/msg.proto"),
            },
            // actually download from regen, see https://github.com/cosmos/cosmos-sdk/issues/12984#issuecomment-1275674526
            Proto::Gogo => format!("gogoproto/gogo.proto"),
            Proto::Google(p) => match p {
                ProtoGoogle::Annotations => format!("google/api/annotations.proto"),
                ProtoGoogle::Http => format!("google/api/http.proto"),
            },
            Proto::Osmosis(p) => match p {
                ProtoOsmosis::TokenFactory(p) => match p {
                    ProtoTokenFactory::AuthorityMetadata => {
                        format!("osmosis/tokenfactory/v1beta1/authorityMetadata.proto")
                    }
                    ProtoTokenFactory::Genesis => {
                        format!("osmosis/tokenfactory/v1beta1/genesis.proto")
                    }
                    ProtoTokenFactory::Params => {
                        format!("osmosis/tokenfactory/v1beta1/params.proto")
                    }
                    ProtoTokenFactory::Query => format!("osmosis/tokenfactory/v1beta1/query.proto"),
                    ProtoTokenFactory::Tx => format!("osmosis/tokenfactory/v1beta1/tx.proto"),
                },
            },
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Proto::Cosmos,
            Proto::CosmosSdk(ProtoCosmosSdk::Coin),
            Proto::CosmosSdk(ProtoCosmosSdk::Pagination),
            Proto::CosmosSdk(ProtoCosmosSdk::Bank),
            Proto::CosmosSdk(ProtoCosmosSdk::Amino),
            Proto::CosmosSdk(ProtoCosmosSdk::Msg),
            Proto::Gogo,
            Proto::Google(ProtoGoogle::Annotations),
            Proto::Google(ProtoGoogle::Http),
            Proto::Osmosis(ProtoOsmosis::TokenFactory(
                ProtoTokenFactory::AuthorityMetadata,
            )),
            Proto::Osmosis(ProtoOsmosis::TokenFactory(ProtoTokenFactory::Genesis)),
            Proto::Osmosis(ProtoOsmosis::TokenFactory(ProtoTokenFactory::Params)),
            Proto::Osmosis(ProtoOsmosis::TokenFactory(ProtoTokenFactory::Query)),
            Proto::Osmosis(ProtoOsmosis::TokenFactory(ProtoTokenFactory::Tx)),
        ]
    }
}

enum Proto {
    Cosmos,
    CosmosSdk(ProtoCosmosSdk),
    Gogo,
    Google(ProtoGoogle),
    Osmosis(ProtoOsmosis),
}

enum ProtoCosmosSdk {
    Coin,
    Pagination,
    Bank,
    Amino,
    Msg,
}

enum ProtoGoogle {
    Annotations,
    Http,
}

enum ProtoOsmosis {
    TokenFactory(ProtoTokenFactory),
}

enum ProtoTokenFactory {
    AuthorityMetadata,
    Genesis,
    Params,
    Query,
    Tx,
}
