//! Bounded canonical logical snapshots; database pages are never state hashes.
use crate::{Error, MAX_ACCOUNTS, MAX_OPERATIONS, disk};
use prost::Message;
use rusqlite::{
    Connection, params_from_iter,
    types::{Value, ValueRef},
};
use volparossa_protocol::encode_canonical;

const TABLES: [(&str, &str, usize); 4] = [
    (
        "SELECT singleton,ledger,unit,supply FROM meta ORDER BY singleton",
        "INSERT INTO meta VALUES(?1,?2,?3,?4)",
        1,
    ),
    (
        "SELECT owner,available,reserved FROM accounts ORDER BY owner",
        "INSERT INTO accounts VALUES(?1,?2,?3)",
        MAX_ACCOUNTS,
    ),
    (
        "SELECT id,payer,recipient,units,state FROM reservations ORDER BY id",
        "INSERT INTO reservations VALUES(?1,?2,?3,?4,?5)",
        MAX_OPERATIONS as usize,
    ),
    (
        "SELECT sequence,id,signer,nonce,signed,hash,reservation,state FROM operations ORDER BY sequence",
        "INSERT INTO operations VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        MAX_OPERATIONS as usize,
    ),
];

#[derive(Clone, PartialEq, Message)]
pub(super) struct Snapshot {
    #[prost(message, repeated, tag = "1")]
    tables: Vec<Table>,
}
#[derive(Clone, PartialEq, Message)]
struct Table {
    #[prost(message, repeated, tag = "1")]
    rows: Vec<Row>,
}
#[derive(Clone, PartialEq, Message)]
struct Row {
    #[prost(message, repeated, tag = "1")]
    cells: Vec<Cell>,
}
#[derive(Clone, PartialEq, Message)]
struct Cell {
    #[prost(oneof = "Scalar", tags = "1,2,3")]
    value: Option<Scalar>,
}
#[derive(Clone, PartialEq, prost::Oneof)]
enum Scalar {
    #[prost(uint64, tag = "1")]
    Integer(u64),
    #[prost(bytes, tag = "2")]
    Blob(Vec<u8>),
    #[prost(string, tag = "3")]
    Text(String),
}

impl Snapshot {
    pub(super) fn capture(db: &Connection) -> Result<Self, Error> {
        disk::validate_accounting(db)?;
        let mut tables = Vec::new();
        for (select, _, bound) in TABLES {
            let mut statement = db.prepare(select)?;
            let columns = statement.column_count();
            let mut cursor = statement.query([])?;
            let mut rows = Vec::new();
            while let Some(row) = cursor.next()? {
                if rows.len() == bound {
                    return Err(Error::Store);
                }
                let mut cells = Vec::new();
                for column in 0..columns {
                    let value = match row.get_ref(column)? {
                        ValueRef::Integer(value) if value >= 0 => {
                            Scalar::Integer(value.unsigned_abs())
                        }
                        ValueRef::Blob(value) if value.len() <= 4096 => {
                            Scalar::Blob(value.to_vec())
                        }
                        ValueRef::Text(value) if value.len() <= 128 => Scalar::Text(
                            std::str::from_utf8(value)
                                .map_err(|_| Error::Store)?
                                .to_owned(),
                        ),
                        _ => return Err(Error::Store),
                    };
                    cells.push(Cell { value: Some(value) });
                }
                rows.push(Row { cells });
            }
            tables.push(Table { rows });
        }
        Ok(Self { tables })
    }

    pub(super) fn bytes(&self) -> Result<Vec<u8>, Error> {
        encode_canonical(self, 6 * 1024 * 1024).map_err(|_| Error::Store)
    }

    pub(super) fn memory_copy(&self) -> Result<Connection, Error> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;",
        )?;
        disk::schema(&db)?;
        for (table, (_, insert, _)) in self.tables.iter().zip(TABLES) {
            for row in &table.rows {
                let values = row
                    .cells
                    .iter()
                    .map(|cell| match &cell.value {
                        Some(Scalar::Integer(value)) => i64::try_from(*value)
                            .map(Value::Integer)
                            .map_err(|_| Error::Store),
                        Some(Scalar::Blob(value)) => Ok(Value::Blob(value.clone())),
                        Some(Scalar::Text(value)) => Ok(Value::Text(value.clone())),
                        None => Err(Error::Store),
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                db.execute(insert, params_from_iter(values))?;
            }
        }
        disk::validate_accounting(&db)?;
        Ok(db)
    }
}
