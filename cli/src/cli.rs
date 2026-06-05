use clap::Parser;

use crate::commands::Cmd;

#[derive(Parser)]
#[command(
    name        = "openlake",
    version,
    about       = "openlake: distributed object storage CLI",
    long_about  = "Multi node cluster operations against an openlake \
                   deployment.\n\n\
                   Each subcommand that talks to a cluster takes \
                   `--config <T.toml>`. One TOML describes exactly one \
                   cluster.\n\n\
                   Run `openlake <SUBCOMMAND> --help` for command details.",
    propagate_version = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}
