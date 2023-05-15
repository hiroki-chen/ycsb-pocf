use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    sync::Mutex,
};

use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::SmallRng,
    SeedableRng,
};
use serde::Deserialize;

use crate::{
    db::Database,
    generator::{
        ConstantGenerator, CounterGenerator, DiscreteGenerator, Generator, UniformLongGenerator,
        WeightPair, ZipfianGenerator,
    },
};

#[derive(Copy, Clone, Debug)]
pub enum CoreOperation {
    Read,
    Update,
    Insert,
    Scan,
    ReadModifyWrite,
}

impl Display for CoreOperation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn zero_u64() -> u64 {
    0
}

fn thread_count_default() -> u64 {
    200
}

fn field_length_distribution_default() -> String {
    "constant".to_string()
}

fn request_distribution_default() -> String {
    "uniform".to_string()
}

fn field_length_default() -> u64 {
    100
}

fn read_proportion_default() -> f64 {
    0.95
}

fn update_proportion_default() -> f64 {
    0.95
}

fn insert_proportion_default() -> f64 {
    0.0
}

fn scan_proportion_default() -> f64 {
    0.0
}

fn read_modify_write_proportion_default() -> f64 {
    0.0
}

#[derive(Deserialize, Debug, Clone)]
pub struct WorkloadConfiguration {
    #[serde(default = "zero_u64", rename = "insertstart")]
    pub insert_start: u64,
    #[serde(default = "zero_u64", rename = "insertcount")]
    pub insert_count: u64,
    #[serde(rename = "operationcount")]
    pub operation_count: u64,
    #[serde(default = "zero_u64", rename = "recordcount")]
    pub record_count: u64,
    #[serde(default = "thread_count_default", rename = "threacount")]
    pub thread_count: u64,
    #[serde(rename = "maxexecutiontime")]
    pub max_execution_time: Option<u64>,
    #[serde(rename = "warmuptime")]
    pub warmup_time: Option<u64>,
    // field length
    #[serde(
        default = "field_length_distribution_default",
        rename = "fieldlengthdistribution"
    )]
    pub field_length_distribution: String,
    #[serde(
        default = "request_distribution_default",
        rename = "requestdistribution"
    )]
    pub request_distribution: String,
    #[serde(default = "field_length_default", rename = "fieldlength")]
    pub field_length: u64,

    // read, update, insert, scan, read-modify-write
    #[serde(default = "read_proportion_default", rename = "readproportion")]
    pub read_proportion: f64,
    #[serde(default = "update_proportion_default", rename = "updateproportion")]
    pub update_proportion: f64,
    #[serde(default = "insert_proportion_default", rename = "insertproportion")]
    pub insert_proportion: f64,
    #[serde(default = "scan_proportion_default", rename = "scanproportion")]
    pub scan_proportion: f64,
    #[serde(
        default = "read_modify_write_proportion_default",
        rename = "readmodifywriteproportion"
    )]
    pub read_modify_write_proportion: f64,
}

#[allow(dead_code)]
pub struct CoreWorkload {
    rng: Mutex<SmallRng>,
    record_count: usize,
    key_sequence: Mutex<Box<dyn Generator<u64> + Send>>,
    table: String,
    field_count: u64,
    field_names: Vec<String>,
    field_length_generator: Mutex<Box<dyn Generator<u64> + Send>>,
    operation_chooser: Mutex<DiscreteGenerator<CoreOperation>>,
    key_chooser: Mutex<Box<dyn Generator<u64> + Send>>,
}

impl CoreWorkload {
    pub fn new(config: &WorkloadConfiguration) -> Self {
        let rng = SmallRng::from_entropy();
        let field_name_prefix = "field";
        let field_count = 1;

        let field_names = (0..field_count)
            .map(|idx| format!("{field_name_prefix}{idx}"))
            .collect::<Vec<_>>();

        Self {
            rng: Mutex::new(rng),
            field_length_generator: Mutex::new(get_field_length_generator(config)),
            record_count: config.record_count as _,
            key_sequence: Mutex::new(Box::new(CounterGenerator::new(config.insert_start))),
            table: "usertable".into(),
            field_count,
            field_names,
            operation_chooser: Mutex::new(create_operation_generator(config)),
            key_chooser: Mutex::new(get_key_chooser_generator(config)),
        }
    }

    /// Execute the operation.
    pub fn run(&self, db: &mut Box<dyn Database>) {
        let op = self
            .operation_chooser
            .lock()
            .unwrap()
            .next_value(&mut self.rng.lock().unwrap());
        match op {
            CoreOperation::Read => {
                let key_num = self.next_key_num();
                let db_key = format!("{}", fnvhash64(key_num));
                db.read("user_table", &db_key).unwrap();
            }
            CoreOperation::Update => {
                let key_num = self.next_key_num();
                let db_key = format!("{}", fnvhash64(key_num));
                todo!()
            }

            _ => todo!(),
        }
    }

    pub fn insert(&self, db: &mut Box<dyn Database>) {
        let db_key = self
            .key_sequence
            .lock()
            .unwrap()
            .next_value(&mut self.rng.lock().unwrap());
        let db_key = format!("{}", fnvhash64(db_key));

        let field_len = self
            .field_length_generator
            .lock()
            .unwrap()
            .next_value(&mut self.rng.lock().unwrap());
        let value = Alphanumeric
            .sample_string::<SmallRng>(&mut self.rng.lock().unwrap(), field_len as usize);

        // We currently insert into only one fields, but the length is 1KB.
        db.insert(&self.table, &db_key, &value);
    }

    fn next_key_num(&self) -> u64 {
        self.key_chooser
            .lock()
            .unwrap()
            .next_value(&mut self.rng.lock().unwrap())
    }
}

fn get_field_length_generator(config: &WorkloadConfiguration) -> Box<dyn Generator<u64> + Send> {
    match config.field_length_distribution.to_lowercase().as_str() {
        "constant" => Box::new(ConstantGenerator::new(config.field_length)),
        "uniform" => Box::new(UniformLongGenerator::new(1, config.field_length)),
        "zipfian" => Box::new(ZipfianGenerator::from_range(1, config.field_length)),
        "histogram" => unimplemented!(),
        _ => panic!(
            "unknown field length distribution {}",
            config.field_length_distribution
        ),
    }
}

fn get_key_chooser_generator(config: &WorkloadConfiguration) -> Box<dyn Generator<u64> + Send> {
    let insert_count = if config.insert_count > 1 {
        config.insert_count
    } else {
        config.record_count - config.insert_start
    };
    assert!(insert_count > 1);
    match config.request_distribution.to_lowercase().as_str() {
        "uniform" => Box::new(UniformLongGenerator::new(
            config.insert_start,
            config.insert_start + insert_count - 1,
        )),
        "zipfian" => Box::new(ZipfianGenerator::from_range(
            config.insert_start,
            config.insert_start + insert_count - 1,
        )),
        _ => todo!(),
    }
}

fn create_operation_generator(config: &WorkloadConfiguration) -> DiscreteGenerator<CoreOperation> {
    let mut pairs = vec![];
    if config.read_proportion > 0.0 {
        pairs.push(WeightPair::new(config.read_proportion, CoreOperation::Read));
    }
    if config.update_proportion > 0.0 {
        pairs.push(WeightPair::new(
            config.update_proportion,
            CoreOperation::Update,
        ));
    }
    if config.insert_proportion > 0.0 {
        pairs.push(WeightPair::new(
            config.insert_proportion,
            CoreOperation::Insert,
        ));
    }
    if config.scan_proportion > 0.0 {
        pairs.push(WeightPair::new(config.scan_proportion, CoreOperation::Scan));
    }
    if config.read_modify_write_proportion > 0.0 {
        pairs.push(WeightPair::new(
            config.read_modify_write_proportion,
            CoreOperation::ReadModifyWrite,
        ));
    }

    DiscreteGenerator::new(pairs)
}

/// http://en.wikipedia.org/wiki/Fowler_Noll_Vo_hash
fn fnvhash64(val: u64) -> u64 {
    let mut val = val;
    let prime = 0xcbf29ce484222325;
    let mut hash_val = prime;
    for _ in 0..8 {
        let octet = val & 0x00ff;
        val >>= 8;
        hash_val ^= octet;
        hash_val = hash_val.wrapping_mul(prime);
    }
    hash_val
}
