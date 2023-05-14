use std::{env, fs};

use clap::{Parser, Subcommand};
use log::{error, info};

use crate::workload::WorkloadConfiguration;

pub mod workload;
pub mod ycsb;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        /// The address of the database.
        address: String,
        /// The port of the database.
        port: u16,
        /// The workload file path.
        workload: String,
    },
}

fn init_logger() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }

    env_logger::init();
}

fn main() {
    init_logger();

    let args = Args::parse();

    match args.command {
        Commands::Run {
            address,
            port,
            workload,
        } => {
            info!("Trying to read workload file from `{workload}`");

            let content = match fs::read(&workload) {
                Ok(content) => content,
                Err(err) => {
                    error!("Failed to read the workload: {err}");
                    return;
                }
            };

            let config = match toml::from_str::<WorkloadConfiguration>(
                std::str::from_utf8(&content).unwrap(),
            ) {
                Ok(config) => config,
                Err(err) => {
                    error!("Failed to parse] the workload: {err}");
                    return;
                }
            };

            ycsb::ycsb_entry(&config);
        }
    }
}
