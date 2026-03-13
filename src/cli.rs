use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "storecold",
    version,
    about = "Linux-first encrypted cold-storage backup daemon for S3 and Azure Blob"
)]
pub struct Cli {
    /// Path to the YAML config file. Defaults to ~/.storecold.yaml.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Path to the local state directory. Overrides config.state_dir when set.
    #[arg(long, global = true, value_name = "DIR")]
    pub state_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the local state directory and a starter config.
    Init {
        /// Overwrite an existing config file.
        #[arg(long)]
        force: bool,
    },
    /// Show the resolved config and state paths.
    Status,
    /// Run one reconciliation cycle immediately.
    Sync {
        /// Restrict the sync to a single configured root path.
        #[arg(long)]
        path: Option<String>,
    },
    /// Run the long-lived daemon loop with filesystem notifications and periodic rescans.
    Daemon,
}
