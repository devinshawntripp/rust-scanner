mod binary;
mod container;
mod license;
mod vuln;
mod redhat;
mod utils;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "scanner")]
#[command(about = "A Rust-powered security scanner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a binary file
    Bin {
        /// Path to binary
        #[arg(short, long)]
        path: String,
    },
    /// Scan a container image (from saved tar)
    Container {
        #[arg(short, long)]
        tar: String,
    },
    /// Detect license in a file
    License {
        #[arg(short, long)]
        path: String,
    },
    /// Match CVE from component/version
    Vuln {
        #[arg(short, long)]
        component: String,
        #[arg(short, long)]
        version: String,
    },
    /// Check Red Hat OVAL XML for CVE
    Redhat {
        #[arg(short, long)]
        cve: String,
        #[arg(short, long)]
        oval: String,
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Bin { path } => {
            binary::scan_binary(&path);
        }
        Commands::Container { tar } => {
            container::extract_tar(&tar);
        }
        Commands::License { path } => {
            license::detect_license(&path);
        }
        Commands::Vuln { component, version } => {
            vuln::match_vuln(&component, &version);
        }
        Commands::Redhat { cve, oval } => {
            redhat::check_redhat_cve(&cve, &oval);
        }
    }
}
