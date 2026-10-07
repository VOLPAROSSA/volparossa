//! Private files and `SQLite` atomicity, following private-storage's existing patterns.
use crate::{
    Error, GenesisAccount, LedgerId, MAX_ACCOUNTS, MAX_OPERATIONS, MAX_UNITS, Mode, Store,
    TEST_UNIT,
};
use ed25519_dalek::VerifyingKey;
use rusqlite::{Connection, OpenFlags, params};
use rustix::fs::{Mode as FileMode, OFlags};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::Path,
    time::Duration,
};

const FILE: &str = "test-transactions.sqlite3";
const APP: i32 = 0x5650_5431;
const ORDERED_APP: i32 = 0x5650_5432;

fn directory(path: &Path) -> Result<File, Error> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 || path.canonicalize()? != path {
        return Err(Error::Store);
    }
    let file = File::from(
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            FileMode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    let info = file.metadata()?;
    if info.uid() != rustix::process::geteuid().as_raw() || info.mode() & 0o777 != 0o700 {
        return Err(Error::Store);
    }
    Ok(file)
}

fn private_file(path: &Path) -> Result<File, Error> {
    let file = File::from(
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            FileMode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != rustix::process::geteuid().as_raw()
        || info.nlink() != 1
        || info.mode() & 0o777 != 0o600
    {
        return Err(Error::Store);
    }
    Ok(file)
}

fn same_file(file: &File, path: &Path) -> Result<(), Error> {
    let before = file.metadata()?;
    let after = fs::symlink_metadata(path)?;
    if after.file_type().is_symlink()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
    {
        return Err(Error::Store);
    }
    Ok(())
}

fn connection(path: &Path, root: &File) -> Result<Connection, Error> {
    same_file(root, path)?;
    let file = private_file(&path.join(FILE))?;
    // Any existing hot journal must be private too; SQLite owns recovery.
    let journal = path.join(format!("{FILE}-journal"));
    match fs::symlink_metadata(&journal) {
        Ok(_) => {
            private_file(&journal)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for suffix in ["-wal", "-shm"] {
        match fs::symlink_metadata(path.join(format!("{FILE}{suffix}"))) {
            Ok(_) => return Err(Error::Store),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let db = Connection::open_with_flags(
        path.join(FILE),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    same_file(root, path)?;
    same_file(&file, &path.join(FILE))?;
    db.busy_timeout(Duration::ZERO)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048;")?;
    Ok(db)
}

pub(super) fn create(
    path: &Path,
    ledger: LedgerId,
    accounts: &[GenesisAccount],
) -> Result<Store, Error> {
    create_mode(path, ledger, accounts, Mode::Local, |_| Ok(()))
}

pub(super) fn create_mode(
    path: &Path,
    ledger: LedgerId,
    accounts: &[GenesisAccount],
    mode: Mode,
    initialize: impl FnOnce(&Connection) -> Result<(), Error>,
) -> Result<Store, Error> {
    if !path.is_absolute()
        || ledger == [0; 32]
        || accounts.is_empty()
        || accounts.len() > MAX_ACCOUNTS
    {
        return Err(Error::Invalid);
    }
    let mut keys = BTreeSet::new();
    let mut supply = 0_u64;
    for account in accounts {
        if account.owner == [0; 32]
            || VerifyingKey::from_bytes(&account.owner).is_err()
            || !keys.insert(account.owner)
        {
            return Err(Error::Invalid);
        }
        supply = supply
            .checked_add(account.units)
            .filter(|n| *n <= MAX_UNITS)
            .ok_or(Error::Capacity)?;
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let root = directory(path)?;
    OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(FILE))?
        .sync_all()?;
    let mut db = connection(path, &root)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    schema(&tx)?;
    tx.pragma_update(
        None,
        "application_id",
        if mode == Mode::Local {
            APP
        } else {
            ORDERED_APP
        },
    )?;
    tx.pragma_update(None, "user_version", 1)?;
    tx.execute(
        "INSERT INTO meta VALUES(1,?1,?2,?3)",
        params![ledger.as_slice(), TEST_UNIT, supply],
    )?;
    for account in accounts {
        tx.execute(
            "INSERT INTO accounts VALUES(?1,?2,0)",
            params![account.owner.as_slice(), account.units],
        )?;
    }
    validate_accounting(&tx)?;
    initialize(&tx)?;
    tx.commit()?;
    root.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(Store {
        connection: db,
        _directory: root,
        ledger_id: ledger,
        mode,
    })
}

pub(super) fn open(path: &Path) -> Result<Store, Error> {
    open_mode(path, Mode::Local)
}

pub(super) fn open_mode(path: &Path, mode: Mode) -> Result<Store, Error> {
    let root = directory(path)?;
    let db = connection(path, &root)?;
    if db.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?
        != if mode == Mode::Local {
            APP
        } else {
            ORDERED_APP
        }
        || db.pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))? != 1
    {
        return Err(Error::Store);
    }
    let (ledger, unit): (Vec<u8>, String) = db.query_row(
        "SELECT ledger,unit FROM meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if unit != TEST_UNIT || ledger == [0; 32] {
        return Err(Error::Store);
    }
    validate_accounting(&db)?;
    Ok(Store {
        connection: db,
        _directory: root,
        ledger_id: ledger.try_into().map_err(|_| Error::Store)?,
        mode,
    })
}

pub(super) fn schema(db: &Connection) -> Result<(), Error> {
    db.execute_batch("CREATE TABLE meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),ledger BLOB NOT NULL CHECK(length(ledger)=32),unit TEXT NOT NULL,supply INTEGER NOT NULL CHECK(supply>=0)) STRICT;
        CREATE TABLE accounts(owner BLOB PRIMARY KEY CHECK(length(owner)=32),available INTEGER NOT NULL CHECK(available>=0),reserved INTEGER NOT NULL CHECK(reserved>=0)) STRICT;
        CREATE TABLE reservations(id BLOB PRIMARY KEY CHECK(length(id)=32),payer BLOB NOT NULL REFERENCES accounts(owner),recipient BLOB NOT NULL REFERENCES accounts(owner),units INTEGER NOT NULL CHECK(units>0),state INTEGER NOT NULL CHECK(state IN (1,2,3))) STRICT;
        CREATE TABLE operations(sequence INTEGER PRIMARY KEY CHECK(sequence>0),id BLOB UNIQUE NOT NULL CHECK(length(id)=32),signer BLOB NOT NULL REFERENCES accounts(owner),nonce BLOB NOT NULL CHECK(length(nonce)=32),signed BLOB NOT NULL CHECK(length(signed) BETWEEN 1 AND 4096),hash BLOB NOT NULL CHECK(length(hash)=32),reservation BLOB NOT NULL REFERENCES reservations(id),state INTEGER NOT NULL CHECK(state IN (1,2,3)),UNIQUE(signer,nonce)) STRICT;
        CREATE TRIGGER operations_no_update BEFORE UPDATE ON operations BEGIN SELECT RAISE(ABORT,'immutable receipt'); END;
        CREATE TRIGGER operations_no_delete BEFORE DELETE ON operations BEGIN SELECT RAISE(ABORT,'immutable receipt'); END;")?;
    Ok(())
}

pub(super) fn validate_accounting(db: &Connection) -> Result<(), Error> {
    let (supply, count): (u64, u64) = db.query_row(
        "SELECT supply,(SELECT count(*) FROM accounts) FROM meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if supply > MAX_UNITS || count == 0 || count > MAX_ACCOUNTS as u64 {
        return Err(Error::Store);
    }
    let total: u64 = db.query_row(
        "SELECT coalesce(sum(available),0)+coalesce(sum(reserved),0) FROM accounts",
        [],
        |row| row.get(0),
    )?;
    let mismatches:u64=db.query_row("SELECT count(*) FROM accounts WHERE reserved != (SELECT coalesce(sum(units),0) FROM reservations WHERE payer=owner AND state=1)",[],|row|row.get(0))?;
    let operations: u64 = db.query_row("SELECT count(*) FROM operations", [], |row| row.get(0))?;
    let pending: u64 = db.query_row(
        "SELECT count(*) FROM reservations WHERE state=1",
        [],
        |row| row.get(0),
    )?;
    if total != supply
        || mismatches != 0
        || operations
            .checked_add(pending)
            .is_none_or(|n| n > MAX_OPERATIONS)
    {
        return Err(Error::Store);
    }
    Ok(())
}
