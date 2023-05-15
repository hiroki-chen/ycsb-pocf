use std::rc::Rc;

use log::error;

use crate::ycsb::{YcsbError, YcsbResult};

/// An abstract database representation.
pub trait Database {
    /// Initializes this database.
    fn init(&self, address: &str) -> YcsbResult<()>;

    /// Inserts into the database.
    fn insert(&self, collection: &str, key: &str, value: &str) -> YcsbResult<()>;

    /// Updates the database.
    fn update(&self, collection: &str, key: &str, value: &str) -> YcsbResult<()>;

    /// Dumps the database.
    fn dump(&self) -> YcsbResult<()>;

    /// Loads the database.
    fn load(&self) -> YcsbResult<()>;

    /// Do the transaction which returns a raw response from the remote database.
    fn do_transaction(&self) -> YcsbResult<Vec<u8>>;
}

#[derive(Debug)]
pub enum DatabaseType {
    /// The in-memory database supported by the PoCF framework.
    PocfDatabase,
    Unspecified,
}

pub fn get_database(ty: DatabaseType) -> YcsbResult<Rc<dyn Database>> {
    match ty {
        DatabaseType::PocfDatabase => {
            todo!()
        }
        _ => {
            error!("Unsupported database type: {ty:?}");
            Err(YcsbError::Unsupported)
        }
    }
}
