use log::error;

use crate::ycsb::{YcsbError, YcsbResult};

/// An abstract database representation.
pub trait Database {
    /// Initializes this database.
    fn init(&mut self, address: &str) -> YcsbResult<()>;

    /// Inserts into the database.
    fn insert(&mut self, collection: &str, key: &str, value: &str) -> YcsbResult<()>;

    /// Updates the database.
    fn update(&mut self, collection: &str, key: &str, value: &str) -> YcsbResult<()>;

    /// Reads from the database.
    fn read(&mut self, collection: &str, key: &str) -> YcsbResult<()>;

    /// Dumps the database.
    fn dump(&mut self) -> YcsbResult<()>;

    /// Loads the database.
    fn load(&mut self) -> YcsbResult<()>;

    /// Do the transaction which returns a raw response from the remote database.
    fn do_transaction(&self) -> YcsbResult<Vec<String>>;
}

#[derive(Default)]
pub struct PocfDatabase {
    /// Stores a bunch of database commands to be executed.
    commands: Vec<String>,
}

impl PocfDatabase {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Database for PocfDatabase {
    fn init(&mut self, _: &str) -> YcsbResult<()> {
        Ok(())
    }

    fn insert(&mut self, collection: &str, key: &str, value: &str) -> YcsbResult<()> {
        self.commands.push(format!(
            "[{}, insert, {collection}, {key}, {value}];",
            self.commands.len()
        ));

        Ok(())
    }

    fn read(&mut self, collection: &str, key: &str) -> YcsbResult<()> {
        self.commands.push(format!(
            "[{}, read, {collection}, {key}];",
            self.commands.len()
        ));

        Ok(())
    }

    fn update(&mut self, collection: &str, key: &str, value: &str) -> YcsbResult<()> {
        self.commands.push(format!(
            "[{}, update, {collection}, {key}, {value}];",
            self.commands.len()
        ));

        Ok(())
    }

    fn dump(&mut self) -> YcsbResult<()> {
        self.commands.push(format!(
            "[{}, dump, ./pocf_database.db];",
            self.commands.len()
        ));

        Ok(())
    }

    fn load(&mut self) -> YcsbResult<()> {
        self.commands.push(format!(
            "[{}, load, ./pocf_database.db];",
            self.commands.len()
        ));

        Ok(())
    }

    fn do_transaction(&self) -> YcsbResult<Vec<String>> {
        Ok(self.commands.clone())
    }
}

#[derive(Debug)]
pub enum DatabaseType {
    /// The in-memory database supported by the PoCF framework.
    PocfDatabase,
    Unspecified,
}

pub fn get_database(ty: DatabaseType) -> YcsbResult<Box<dyn Database>> {
    match ty {
        DatabaseType::PocfDatabase => Ok(Box::new(PocfDatabase::default())),
        _ => {
            error!("Unsupported database type: {ty:?}");
            Err(YcsbError::Unsupported)
        }
    }
}
