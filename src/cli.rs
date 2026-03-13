use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "storecold",
    version,
    about = "Linux-first encrypted cold-storage backup daemon for S3 and Azure Blob"
)]
pub struct Cli {
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
    /// Create the local state directory and a starter config in the home directory.
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
