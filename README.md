# YCSB Client for PoCF

Inspired by [this repo](https://github.com/penberg/ycsb-rs). Many thanks to Pekka and Alex Chi for releasing it. This client is used to generate the YCSB workloads from a template file (.toml) and evaluate the performance of the remote database supported by Proof-of-being-forgotten Compliant Framework (PoCF) which runs inside a secure TEE (e.g., SGX, SEV, etc.). 

The author(s) do not (and will not) make any other efforts to support other database types as this is not our major focus for the time being. If you are interested in benchmarking database using Rust, consider contacting Yahoo or other experienced personnel.

## For USENIX Artifact Evaluation

AE committee members are always welcomed :)

## Build for Different TEEs.

* Build SGX:

```sh
TEE_TYPE=SGX cargo build -r --features=sgx
```

* Build SEV:

```sh
TEE_TYPE=SEV cargo build -r --features=sev
```

## Run This Benchmark

```sh
$ TEE_TYPE=[tee_type] cargo run -r --features=[tee_type] -h

Usage: ycsb-pocf [OPTIONS] <RUN_TYPE>

Arguments:
  <RUN_TYPE>  Operation type: load / run [possible values: load, run]

Options:
  -a, --address <ADDRESS>              The address of the database [default: 127.0.0.1]
  -p, --port <PORT>                    The port of the database [default: 1234]
  -w, --workload <WORKLOAD>            The workload file path [default: ./workloads/workloada.toml]
  -t, --thread-number <THREAD_NUMBER>  The thread number (1 for single-threaded client) [default: 1]
  -h, --help                           Print help
  -V, --version                        Print version
```
