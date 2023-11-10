use clap::Parser;
use cosmos::{clap::CosmosOpt, HasAddress, HasAddressHrp, SeedPhrase};
use tokio::task::JoinSet;

#[derive(clap::Parser)]
struct Opt {
    #[clap(flatten)]
    cosmos: CosmosOpt,
    #[clap(long, env = "COSMOS_WALLET")]
    wallet: SeedPhrase,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let Opt { cosmos, wallet } = Opt::parse();
    let cosmos = cosmos.build().await.unwrap();
    let wallet = wallet.with_hrp(cosmos.get_address_hrp()).unwrap();
    let dest = wallet.get_address();
    let mut set = JoinSet::new();
    for amount in 1..10 {
        for _ in 0..5 {
            let cosmos = cosmos.clone();
            let wallet = wallet.clone();
            set.spawn(async move { wallet.send_gas_coin(&cosmos, dest, amount).await });
        }
    }

    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(txres)) => println!("Success: {}", txres.txhash),
            Ok(Err(e)) => println!("Error: {e}"),
            Err(e) => println!("Panic: {e}"),
        }
    }
}
