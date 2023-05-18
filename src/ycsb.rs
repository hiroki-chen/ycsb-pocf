use std::{
    error::Error,
    fmt::{Debug, Display},
    io::{BufReader, BufWriter},
    net::TcpStream,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use log::info;
use pobf_crypto::init_keypair;

use crate::{
    db::{get_database, DatabaseType},
    workload::{CoreWorkload, WorkloadConfiguration},
    RunType,
};

#[cfg(feature = "libos")]
use crate::none_attestation::attest_and_perform_task;
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
    disk_dump: bool,
) -> YcsbResult<BenchSummary> {
    #[cfg(feature = "sgx")]
    crate::sgx_attestation::init_verification_library();

    if run_type == RunType::Load {
        ycsb_prepare_load(&address)?;
    }

    if thread_number > MAX_THREAD_NUM as u8 {
        return Err(YcsbError::TooManyThreads);
    }

    // Create workload.
    let workload = Arc::new(CoreWorkload::new(config));

    let timer = Instant::now();
    let thread_operation_count = config.operation_count / thread_number as u64;
    let mut threads = Vec::new();
    info!("Each thread is given {thread_operation_count} operations");

    (0..thread_number).for_each(|_| {
        let cloned_address = address.to_string();
        let cloned_config = config.clone();
        let wl = workload.clone();

        threads.push(thread::spawn(move || {
            ycsb_task(
                wl,
                run_type,
                cloned_address,
                cloned_config,
                thread_operation_count,
            )
        }));
    });

    let _intermediate_result = threads
        .into_iter()
        .map(|join_handle| join_handle.join().unwrap_or(Ok(())))
        .collect::<Vec<_>>();
    let runtime = timer.elapsed();

    if disk_dump {
        let mut db = get_database(DatabaseType::PocfDatabase)?;
        db.dump()?;
        let data = db
            .do_transaction()?
            .into_iter()
            .map(|s| s.into_bytes())
            .flatten()
            .collect::<Vec<_>>();
        ycsb_send_requests(address, data.as_slice())?;
    }

    Ok(BenchSummary {
        thread_count: thread_number as _,
        run_time: runtime,
        throughput: config.operation_count as f64 / runtime.as_secs_f64(),
    })
}

/// The task for each thread.
fn ycsb_task(
    wl: Arc<CoreWorkload>,
    run_type: RunType,
    address: String,
    config: WorkloadConfiguration,
    thread_operation_count: u64,
) -> YcsbResult<()> {
    if run_type == RunType::Dump {
        let data = ycsb_generate_load(wl.clone(), thread_operation_count)?;
        let data = data
            .into_iter()
            .map(|s| s.into_bytes())
            .flatten()
            .collect::<Vec<_>>();
        std::fs::write("./data_load.bin", data).map_err(|_| YcsbError::IoError)?;

        let data = ycsb_generate_run(wl, thread_operation_count)?;
        let data = data
            .into_iter()
            .map(|s| s.into_bytes())
            .flatten()
            .collect::<Vec<_>>();
        std::fs::write("./data_run.bin", data).map_err(|_| YcsbError::IoError)?;

        return Ok(());
    }

    let data = match run_type {
        RunType::Load => ycsb_generate_load(wl, thread_operation_count),
        RunType::Run => ycsb_generate_run(wl, thread_operation_count),
        _ => todo!(),
    }?;

    // Due to the limitation of SGX, we need to send them in "batches".
    if (cfg!(feature = "sgx") || cfg!(feature = "libos")) && run_type == RunType::Load {
        const BATCH_SIZE: usize = 4096;

        let batch_num = (data.len() as f64 / BATCH_SIZE as f64).ceil() as usize;
        for i in 0..batch_num {
            let start = i * BATCH_SIZE;
            let end = (start + BATCH_SIZE).min(data.len());

            let bytes = data[start..end]
                .into_iter()
                .cloned()
                .map(|s| s.into_bytes())
                .flatten()
                .collect::<Vec<u8>>();
            ycsb_send_requests(&address, bytes.as_slice())?;
        }
    } else {
        let bytes = data
            .into_iter()
            .map(|s| s.into_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        ycsb_send_requests(&address, bytes.as_slice())?;
    }

    Ok(())
}

/// Prepares the schema.
fn ycsb_prepare_load(address: &str) -> YcsbResult<()> {
    let socket = TcpStream::connect(address).map_err(|_| YcsbError::DbError)?;
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    let mut writer = BufWriter::new(socket);

    let data = b"[114514, make_schema, usertable]";
    let mut key_pair = init_keypair().map_err(|_| YcsbError::BadCrypto)?;
    let res = attest_and_perform_task(&mut reader, &mut writer, &mut key_pair, data)
        .map_err(|_| YcsbError::IoError)?;
    let response = String::from_utf8(res).map_err(|_| YcsbError::IoError)?;

    log::info!("Database replied: {response}");

    Ok(())
}

fn ycsb_send_requests(address: &str, data: &[u8]) -> YcsbResult<Vec<u8>> {
    let socket = TcpStream::connect(address).map_err(|_| YcsbError::DbError)?;
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    let mut writer = BufWriter::new(socket);

    // Retry 0x20 times.
    let mut retry = 0x20;
    loop {
        if retry == 0 {
            return Err(YcsbError::DbError);
        }

        retry -= 1;

        let mut key_pair = init_keypair().map_err(|_| YcsbError::BadCrypto)?;
        if let Ok(buf) = attest_and_perform_task(&mut reader, &mut writer, &mut key_pair, &data) {
            return Ok(buf);
        }
    }
}

/// Generates the dataset for `load`; this generally does the insert operation.
fn ycsb_generate_load(
    wl: Arc<CoreWorkload>,
    thread_operation_count: u64,
) -> YcsbResult<Vec<String>> {
    let mut db = get_database(DatabaseType::PocfDatabase)?;
    wl.insert(&mut db, thread_operation_count as _);

    db.do_transaction()
}

/// Generates the workload for `run`.
fn ycsb_generate_run(
    wl: Arc<CoreWorkload>,
    thread_operation_count: u64,
) -> YcsbResult<Vec<String>> {
    let mut db = get_database(DatabaseType::PocfDatabase)?;
    wl.run(&mut db, thread_operation_count as _);

    db.do_transaction()
}
