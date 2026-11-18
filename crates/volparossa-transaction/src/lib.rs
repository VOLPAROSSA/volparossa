//! Durable accounting of fictitious TEST units with separate local/ordered modes.
//!
//! This is a reusable core store, not distributed settlement, money, securities,
//! a financial gateway or a daemon endpoint. Separate financial test keys sign
//! exact commands; network identity and model output provide no authorization.
//! `SQLite` serializes local transitions. Ordered execution stages whole blocks in
//! memory and persists only at Commit, with a separate signed-command domain.
//! Neither mode implements consensus. A future reviewed ordering protocol must
//! supply its own membership/finality proof rather than call this local order
//! distributed consensus. Owner-private files are not encrypted-at-rest storage.

#![forbid(unsafe_code)]

mod disk;
mod ordered;
mod wire;

use std::{fs::File, path::Path};

use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

pub use ordered::{
    Block, BlockOutcome, BlockReceipt, BlockTime, CommandFailure, MAX_BLOCK_BYTES,
    MAX_BLOCK_COMMANDS, OrderedStore, StagedBlock,
};
pub use wire::SignedCommand;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Local,
    Ordered,
}

/// Exact identifier of one independently initialized test ledger.
pub type LedgerId = [u8; 32];
/// Explicitly enrolled financial test public key, not a network peer identifier.
pub type AccountId = [u8; 32];
/// Permanent caller-chosen idempotency identifier within a ledger.
pub type OperationId = [u8; 32];
/// Only supported unit; this cannot be configured to a currency or security.
pub const TEST_UNIT: &str = "volparossa.test.unit.v1";
/// Exact integer/`SQLite` bound, including the entire initial supply.
pub const MAX_UNITS: u64 = i64::MAX.unsigned_abs();
/// Hard bound on explicitly initialized accounts.
pub const MAX_ACCOUNTS: usize = 64;
/// Accepted commands and their replay records are never evicted to make room.
/// Each admitted reserve also keeps one slot available for its commit or cancel.
pub const MAX_OPERATIONS: u64 = 1024;

/// Failure before a successful commit must not be interpreted as a debit receipt.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid encoding, version, bounds or command shape.
    #[error("invalid_transaction_command")]
    Invalid,
    /// The signature/payer or independently enrolled account does not match.
    #[error("transaction_unauthorized")]
    Unauthorized,
    /// The exact ledger domain does not match.
    #[error("transaction_wrong_ledger")]
    WrongLedger,
    /// A new mutation is outside its signed validity window.
    #[error("transaction_not_live")]
    NotLive,
    /// A previously accepted identifier binds different original bytes.
    #[error("transaction_operation_conflict")]
    Conflict,
    /// This financial signer already used the nonce on another accepted command.
    #[error("transaction_nonce_replay")]
    Replay,
    /// Insufficient available units; reserved units are not spendable.
    #[error("transaction_insufficient_units")]
    Insufficient,
    /// No requested account, reservation or accepted operation exists.
    #[error("transaction_not_found")]
    NotFound,
    /// This transition is not valid for the existing reservation state.
    #[error("transaction_invalid_state")]
    State,
    /// A fixed account/operation/unit bound would be exceeded.
    #[error("transaction_capacity")]
    Capacity,
    /// Store ownership, file shape, schema or conserved accounting is invalid.
    #[error("transaction_invalid_store")]
    Store,
    /// A concurrent local transaction owns the database; do not invent success.
    #[error("transaction_busy")]
    Busy,
    /// The operating system refused a local operation.
    #[error("transaction_io")]
    Io(#[from] std::io::Error),
    /// An unclassified database error; caller may inspect status after reopening.
    #[error("transaction_database")]
    Database(rusqlite::Error),
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Busy
            }
            _ => Self::Database(error),
        }
    }
}

/// Initial fictitious funding, recorded once; there is no subsequent mint API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisAccount {
    /// Independently supplied financial test verifying key.
    pub owner: AccountId,
    /// Nonnegative whole TEST units, never floating point.
    pub units: u64,
}

/// Immutable owner-authorized operation. Commit/cancel reference a prior reserve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Move available payer units into one exact recipient-bound reservation.
    Reserve {
        /// Existing recipient in this ledger.
        recipient: AccountId,
        /// Positive whole TEST units.
        units: u64,
    },
    /// Credit the original recipient once; cannot change the reserve terms.
    Commit {
        /// Operation id of the original reserve.
        reservation_id: OperationId,
    },
    /// Return only an uncommitted reservation to its original payer.
    Cancel {
        /// Operation id of the original reserve.
        reservation_id: OperationId,
    },
}

/// Signed command; a new id and nonce represent a new explicit authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Command {
    /// Permanent idempotency identity; conflicts fail without mutation.
    pub operation_id: OperationId,
    /// Must match the signer and independently enrolled payer.
    pub payer: AccountId,
    /// Exact operation and terms.
    pub action: Action,
}

/// Durable reservation state, with no external-settlement interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationState {
    /// Locally reserved, not spendable or credited.
    Reserved,
    /// Locally credited to the immutable recipient.
    Committed,
    /// Locally returned to the immutable payer.
    Cancelled,
}

/// Historical receipt for exactly one accepted command, unchanged on replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Store domain.
    pub ledger_id: LedgerId,
    /// Accepted command identity.
    pub operation_id: OperationId,
    /// SHA-256 of the exact original signed bytes.
    pub command_sha256: [u8; 32],
    /// Local commit order only, not distributed finality.
    pub sequence: u64,
    /// Original reserve identity.
    pub reservation_id: OperationId,
    /// State immediately after this command, not a fresh reservation query.
    pub state: ReservationState,
}

/// Current local account quantities; status access is owner-local, not remote auth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Balance {
    /// Available to a new explicitly signed reserve.
    pub available_units: u64,
    /// Pending reservations owned by this payer.
    pub reserved_units: u64,
}

/// A private `SQLite`-backed local transition executor. No background work occurs.
pub struct Store {
    connection: Connection,
    _directory: File,
    ledger_id: LedgerId,
    mode: Mode,
}

impl Store {
    /// Initialize a new, nonexisting private root with explicit fictitious funding.
    ///
    /// # Errors
    /// Rejects duplicate/invalid keys, bounds, existing roots or unsafe local files.
    pub fn create(
        path: &Path,
        ledger_id: LedgerId,
        accounts: &[GenesisAccount],
    ) -> Result<Self, Error> {
        disk::create(path, ledger_id, accounts)
    }

    /// Reopen exactly one private durable test ledger, without resetting replay state.
    ///
    /// # Errors
    /// Rejects unsafe files, wrong schema, corrupted accounting or database failure.
    pub fn open(path: &Path) -> Result<Self, Error> {
        disk::open(path)
    }

    /// Domain of this opened local ledger; not an account or execution authority.
    pub fn ledger_id(&self) -> LedgerId {
        self.ledger_id
    }

    /// Inspect signed terms without applying them or duplicating the wire parser.
    /// Verifies canonical encoding, signature, ledger domain and payer enrollment.
    /// This is not admission: validity at execution time, balances, replay and
    /// reservation state are checked independently by `apply`. Expired historical
    /// commands remain inspectable. No receipt is created and no nonce consumed.
    ///
    /// # Errors
    /// Rejects malformed, unauthenticated, cross-ledger or unenrolled commands.
    pub fn inspect(&self, bytes: &[u8]) -> Result<Command, Error> {
        let verified = wire::verify(bytes, self.ledger_id)?;
        account(&self.connection, &verified.command.payer)?;
        Ok(verified.command)
    }

    /// Apply one independently authenticated command and atomically store its receipt.
    /// `now` uses the same caller-supplied seconds timebase as the signed window;
    /// this local store does not establish a distributed clock or remote authority.
    /// Exact accepted replay returns the historical receipt even after expiry. New
    /// expired commands cannot mutate. No model, network or payment execution occurs.
    ///
    /// # Errors
    /// Rejects invalid authorization, replay/conflicts, overspending or invalid state.
    pub fn apply(&mut self, bytes: &[u8], now: u64) -> Result<Receipt, Error> {
        self.apply_inner(bytes, now, || {})
    }

    fn apply_inner(
        &mut self,
        bytes: &[u8],
        now: u64,
        before_commit: impl FnOnce(),
    ) -> Result<Receipt, Error> {
        if self.mode != Mode::Local {
            return Err(Error::Store);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = apply_command(&tx, self.ledger_id, Mode::Local, bytes, now)?;
        before_commit();
        tx.commit()?;
        Ok(result)
    }

    /// Read local current balances; never starts or authorizes an operation.
    ///
    /// # Errors
    /// Returns not-found for unknown owners and rejects invalid persisted accounting.
    pub fn status(&self, owner: AccountId) -> Result<Balance, Error> {
        account(&self.connection, &owner)
    }

    /// Read a historical command receipt without treating its state as current.
    ///
    /// # Errors
    /// Rejects database errors or malformed stored receipt fields.
    pub fn operation(&self, id: OperationId) -> Result<Option<Receipt>, Error> {
        receipt(&self.connection, self.ledger_id, id)
    }
}

// The caller owns the transaction/savepoint and its persistence boundary.
fn apply_command(
    db: &Connection,
    ledger: LedgerId,
    mode: Mode,
    bytes: &[u8],
    now: u64,
) -> Result<Receipt, Error> {
    let verified = wire::verify_mode(bytes, ledger, mode)?;
    let tx = db;
    let command = verified.command;
    account(tx, &command.payer)?;
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    if let Some(previous) = receipt(tx, ledger, command.operation_id)? {
        let original: Vec<u8> = tx.query_row(
            "SELECT signed FROM operations WHERE id=?1",
            [command.operation_id.as_slice()],
            |row| row.get(0),
        )?;
        return if original == bytes {
            Ok(previous)
        } else {
            Err(Error::Conflict)
        };
    }
    if now < verified.valid_from || now >= verified.expires {
        return Err(Error::NotLive);
    }
    let used: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM operations WHERE signer=?1 AND nonce=?2)",
        params![command.payer.as_slice(), verified.nonce.as_slice()],
        |row| row.get(0),
    )?;
    if used {
        return Err(Error::Replay);
    }
    let count: u64 = tx.query_row("SELECT count(*) FROM operations", [], |row| row.get(0))?;
    if count >= MAX_OPERATIONS {
        return Err(Error::Capacity);
    }
    if matches!(command.action, Action::Reserve { .. }) {
        let pending: u64 = tx.query_row(
            "SELECT count(*) FROM reservations WHERE state=1",
            [],
            |row| row.get(0),
        )?;
        // One durable record for this reserve and another for its eventual
        // completion, in addition to every already pending completion.
        if count
            .checked_add(pending)
            .and_then(|n| n.checked_add(2))
            .is_none_or(|n| n > MAX_OPERATIONS)
        {
            return Err(Error::Capacity);
        }
    }
    let (reservation_id, state) = transition(tx, command)?;
    let result = Receipt {
        ledger_id: ledger,
        operation_id: command.operation_id,
        command_sha256: hash,
        sequence: count + 1,
        reservation_id,
        state,
    };
    tx.execute("INSERT INTO operations(sequence,id,signer,nonce,signed,hash,reservation,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![result.sequence, command.operation_id.as_slice(), command.payer.as_slice(), verified.nonce.as_slice(), bytes, hash.as_slice(), reservation_id.as_slice(), state_number(state)])?;
    disk::validate_accounting(tx)?;
    Ok(result)
}

fn account(db: &Connection, owner: &AccountId) -> Result<Balance, Error> {
    db.query_row(
        "SELECT available,reserved FROM accounts WHERE owner=?1",
        [owner.as_slice()],
        |row| {
            Ok(Balance {
                available_units: row.get(0)?,
                reserved_units: row.get(1)?,
            })
        },
    )
    .optional()?
    .ok_or(Error::NotFound)
}

fn state_number(state: ReservationState) -> u8 {
    match state {
        ReservationState::Reserved => 1,
        ReservationState::Committed => 2,
        ReservationState::Cancelled => 3,
    }
}

fn parse_state(state: u8) -> Result<ReservationState, Error> {
    match state {
        1 => Ok(ReservationState::Reserved),
        2 => Ok(ReservationState::Committed),
        3 => Ok(ReservationState::Cancelled),
        _ => Err(Error::Store),
    }
}

fn receipt(db: &Connection, ledger: LedgerId, id: OperationId) -> Result<Option<Receipt>, Error> {
    let row: Option<(u64, Vec<u8>, Vec<u8>, u8)> = db
        .query_row(
            "SELECT sequence,hash,reservation,state FROM operations WHERE id=?1",
            [id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    row.map(|(sequence, hash, reservation, state)| {
        Ok(Receipt {
            ledger_id: ledger,
            operation_id: id,
            command_sha256: hash.try_into().map_err(|_| Error::Store)?,
            sequence,
            reservation_id: reservation.try_into().map_err(|_| Error::Store)?,
            state: parse_state(state)?,
        })
    })
    .transpose()
}

fn transition(db: &Connection, command: Command) -> Result<(OperationId, ReservationState), Error> {
    match command.action {
        Action::Reserve { recipient, units } => {
            let payer = account(db, &command.payer)?;
            account(db, &recipient)?;
            let available = payer
                .available_units
                .checked_sub(units)
                .ok_or(Error::Insufficient)?;
            let reserved = payer
                .reserved_units
                .checked_add(units)
                .filter(|n| *n <= MAX_UNITS)
                .ok_or(Error::Capacity)?;
            db.execute(
                "UPDATE accounts SET available=?1,reserved=?2 WHERE owner=?3",
                params![available, reserved, command.payer.as_slice()],
            )?;
            db.execute(
                "INSERT INTO reservations(id,payer,recipient,units,state) VALUES(?1,?2,?3,?4,1)",
                params![
                    command.operation_id.as_slice(),
                    command.payer.as_slice(),
                    recipient.as_slice(),
                    units
                ],
            )?;
            Ok((command.operation_id, ReservationState::Reserved))
        }
        Action::Commit { reservation_id } | Action::Cancel { reservation_id } => {
            let row: Option<(Vec<u8>, Vec<u8>, u64, u8)> = db
                .query_row(
                    "SELECT payer,recipient,units,state FROM reservations WHERE id=?1",
                    [reservation_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let (payer, recipient, units, state) = row.ok_or(Error::NotFound)?;
            if payer != command.payer {
                return Err(Error::Unauthorized);
            }
            if state != 1 {
                return Err(Error::State);
            }
            let paying = account(db, &command.payer)?;
            let reserved = paying
                .reserved_units
                .checked_sub(units)
                .ok_or(Error::Store)?;
            let commit = matches!(command.action, Action::Commit { .. });
            let beneficiary: AccountId = if commit {
                recipient.try_into().map_err(|_| Error::Store)?
            } else {
                command.payer
            };
            let available = account(db, &beneficiary)?
                .available_units
                .checked_add(units)
                .filter(|n| *n <= MAX_UNITS)
                .ok_or(Error::Capacity)?;
            db.execute(
                "UPDATE accounts SET reserved=?1 WHERE owner=?2",
                params![reserved, command.payer.as_slice()],
            )?;
            db.execute(
                "UPDATE accounts SET available=?1 WHERE owner=?2",
                params![available, beneficiary.as_slice()],
            )?;
            let state = if commit {
                ReservationState::Committed
            } else {
                ReservationState::Cancelled
            };
            db.execute(
                "UPDATE reservations SET state=?1 WHERE id=?2",
                params![state_number(state), reservation_id.as_slice()],
            )?;
            Ok((reservation_id, state))
        }
    }
}

#[cfg(test)]
mod tests;
