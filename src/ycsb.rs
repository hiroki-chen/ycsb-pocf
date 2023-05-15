use std::{
    error::Error,
    fmt::{Debug, Display},
    io::{BufReader, BufWriter},
    net::TcpStream,
    thread,
    time::{Duration, Instant},
};

use pobf_crypto::init_keypair;

use crate::{
    db::{get_database, DatabaseType},
    workload::{CoreWorkload, WorkloadConfiguration},
    RunType,
};

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
#[derive(Clone)]
pub struct BenchSummary {
    thread_count: usize,
    run_time: Duration,
    /// Operation per **second**.
    throughput: f64,
}

impl Debug for BenchSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[OVERALL] ThreadCount {}", &self.thread_count)?;
        writeln!(
            f,
            "[OVERALL] RunTime(ms) {}",
            self.run_time.as_micros() as f64 / 1000.0
        )?;
        writeln!(f, "[OVERALL] Throughput(ops/sec) {}", self.throughput)
    }
}

impl Display for BenchSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

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

    let timer = Instant::now();
    let thread_operation_count = config.operation_count / thread_number as u64;
    let mut threads = Vec::new();
    (0..thread_number).for_each(|_| {
        let cloned_address = address.to_string();
        let cloned_config = config.clone();
        threads.push(thread::spawn(move || {
            ycsb_task(
                run_type,
                cloned_address,
                cloned_config,
                thread_operation_count,
            )
        }));
    });

    let intermediate_result = threads
        .into_iter()
        .map(|join_handle| join_handle.join().expect("The thread crashed"))
        .collect::<Vec<_>>();

    Ok(BenchSummary {
        thread_count: thread_number as _,
        run_time: timer.elapsed(),
        throughput: config.operation_count as f64 / timer.elapsed().as_secs_f64(),
    })
}

/// The task for each thread.
fn ycsb_task(
    run_type: RunType,
    address: String,
    config: WorkloadConfiguration,
    thread_operation_count: u64,
) -> YcsbResult<()> {
    let data = match run_type {
        RunType::Load => ycsb_generate_load(&config, thread_operation_count),
        RunType::Run => ycsb_generate_run(&config, thread_operation_count),
        RunType::Warmup => todo!(),
    }?;

    let socket = TcpStream::connect(address).map_err(|_| YcsbError::DbError)?;
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    let mut writer = BufWriter::new(socket);

    let mut key_pair = init_keypair().map_err(|_| YcsbError::BadCrypto)?;
    attest_and_perform_task(&mut reader, &mut writer, &mut key_pair, &data)
        .map_err(|_| YcsbError::IoError)?;

    Ok(())
}

/// Generates the dataset for `load`; this generally does the insert operation.
fn ycsb_generate_load(
    config: &WorkloadConfiguration,
    thread_operation_count: u64,
) -> YcsbResult<Vec<u8>> {
    let mut db = get_database(DatabaseType::PocfDatabase)?;
    let workload = CoreWorkload::new(config);
    workload.insert(&mut db);

    db.do_transaction()
}

/// Generates the workload for `run`.
fn ycsb_generate_run(
    config: &WorkloadConfiguration,
    thread_operation_count: u64,
) -> YcsbResult<Vec<u8>> {
    let db = get_database(DatabaseType::PocfDatabase)?;
    todo!()
}
