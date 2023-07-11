use std::path::PathBuf;

use anyhow::Result;
use cosmos::Cosmos;

#[derive(clap::Parser)]
pub(crate) struct Opt {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Parser)]
enum Subcommand {
    /// Download the code for a given code ID
    Download {
        #[clap(long)]
        code_id: u64,
        #[clap(long)]
        dest: PathBuf,
    },
}

pub(crate) async fn go(cosmos: Cosmos, opt: Opt) -> Result<()> {
    match opt.subcommand {
        Subcommand::Download { code_id, dest } => {
            let code = cosmos.make_code_id(code_id);
            let bytes = code.download().await?;
            fs_err::write(&dest, &bytes)?;
            Ok(())
        }
    }
}
