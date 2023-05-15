use std::{
    error::Error,
    fmt::{Debug, Display},
    io::{BufReader, BufWriter},
    net::TcpStream,
    thread,
};

use pobf_crypto::init_keypair;

use crate::{db::get_database, workload::WorkloadConfiguration, RunType};

#[cfg(feature = "sev")]
use crate::sev_attestation::attest_and_perform_task;
#[cfg(feature = "sgx")]
use crate::sgx_attestation::attest_and_perform_task;

pub type YcsbResult<T> = std::result::Result<T, YcsbError>;

const MAX_THREAD_NUM: usize = 8;

#[derive(Debug)]
pub enum YcsbError {
    /// A very generic error type indicating the remote database has some errors.
    DbError,
    /// Unsupported operations/types.
    Unsupported,
    /// Too many threads!
    TooManyThreads,
    /// Io error.
    IoError,
    /// Cryptographic error.
    BadCrypto,
    /// Unknown error.
    Unknown,
}

impl Error for YcsbError {}

impl Display for YcsbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

/// The summary.
#[derive(Debug, Clone)]
pub struct BenchSummary {}

/// Entry for the YCSB benchmark. Should return a summary.
pub fn ycsb_entry(
    run_type: RunType,
    config: &WorkloadConfiguration,
    thread_number: u8,
    address: &str,
) -> YcsbResult<BenchSummary> {
    if thread_number > MAX_THREAD_NUM as u8 {
        return Err(YcsbError::TooManyThreads);
    }

    let mut threads = Vec::new();
    (0..thread_number).for_each(|_| {
        let cloned_address = address.to_string();
        let cloned_config = config.clone();
        threads.push(thread::spawn(move || {
            ycsb_task(run_type, cloned_address, cloned_config)
        }));
    });

    let intermediate_result = threads
        .into_iter()
        .map(|join_handle| join_handle.join().expect("The thread crashed"))
        .collect::<Vec<_>>();

    println!("{intermediate_result:?}");

    unimplemented!("coming soon");
}

/// The task for each thread.
fn ycsb_task(run_type: RunType, address: String, config: WorkloadConfiguration) -> YcsbResult<()> {
    let socket = TcpStream::connect(address).map_err(|_| YcsbError::DbError)?;
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    let mut writer = BufWriter::new(socket);

    let data = match run_type {
        RunType::Load => vec![1, 2, 3],
        RunType::Run => vec![1, 2, 3],
    };

    let mut key_pair = init_keypair().map_err(|_| YcsbError::BadCrypto)?;
    attest_and_perform_task(&mut reader, &mut writer, &mut key_pair, &data)
        .map_err(|_| YcsbError::IoError)?;

    Ok(())
}
