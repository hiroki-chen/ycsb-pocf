use std::{env, fs};

use clap::{Parser, ValueEnum};
use log::{error, info};

use crate::workload::WorkloadConfiguration;

#[cfg(not(any(feature = "sgx", feature = "sev")))]
compile_error!("Must specify tee type.");

#[cfg(feature = "sgx")]
pub mod ffi;
#[cfg(feature = "sgx")]
pub mod sgx_attestation;
#[cfg(feature = "sgx")]
pub mod sgx_networking;

#[cfg(feature = "sev")]
pub mod sev_attestation;

pub mod db;

pub mod generator;
pub mod workload;
pub mod ycsb;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunType {
    /// Generates some random data.
    Load,
    Run,
    /// Currently not sure what this should do...
    Warmup,
    /// Generates test data and dumps to the disk (for our convenience).
    Dump
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Args {
    /// Operation type: load / run.
    #[clap(value_parser)]
    run_type: RunType,
    /// The address of the database.
    #[clap(value_parser, short, long, default_value_t = String::from("127.0.0.1"))]
    address: String,
    /// The port of the database.
    #[clap(value_parser, short, long, default_value_t = 1234)]
    port: u16,
    /// The workload file path.
    #[clap(value_parser, short, long, default_value_t = String::from("./workloads/workloada.toml"))]
    workload: String,
    /// The thread number (1 for single-threaded client).
    #[clap(value_parser, short, long, default_value_t = 1)]
    thread_number: u8,
    // Add load/dump => tests the disk performance?
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

    info!("Arguments are\n{:#?}", args);
    let content = match fs::read(&args.workload) {
        Ok(content) => content,
        Err(err) => {
            error!("Failed to read the workload: {err}");
            return;
        }
    };
    let config =
        match toml::from_str::<WorkloadConfiguration>(std::str::from_utf8(&content).unwrap()) {
            Ok(config) => config,
            Err(err) => {
                error!("Failed to parse] the workload: {err}");
                return;
            }
        };

    match ycsb::ycsb_entry(
        args.run_type,
        &config,
        args.thread_number,
        &format!("{}:{}", args.address, args.port),
    ) {
        Ok(summary) => info!("\n{summary}"),
        Err(err) => error!("YCSB returned {err}"),
    }
}
