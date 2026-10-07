//! Staged deterministic execution, NOT a consensus engine or financial endpoint.
#[path = "ordered_snapshot.rs"]
mod snapshot;

use crate::{
    AccountId, Balance, Command, Error, GenesisAccount, LedgerId, MAX_ACCOUNTS, MAX_UNITS, Mode,
    OperationId, Receipt, Store, apply_command, disk, parse_state, state_number, wire,
};
use prost::Message;
use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use snapshot::Snapshot;
use std::path::Path;
use volparossa_protocol::{decode_canonical, encode_canonical};

/// Maximum signed commands, including rejected commands, in a staged block.
pub const MAX_BLOCK_COMMANDS: usize = 64;
/// Maximum aggregate command bytes in a staged block (each command <= 4096).
pub const MAX_BLOCK_BYTES: usize = 65_536;
const MAX_RECORD_BYTES: usize = 128 * 1024;

/// Agreed Unix timestamp. No local clock is consulted by ordered execution.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Message)]
pub struct BlockTime {
    /// Nonnegative Unix seconds, bounded by `i64::MAX`.
    #[prost(uint64, tag = "1")]
    pub seconds: u64,
    /// Nanoseconds within the second, strictly below one billion.
    #[prost(uint32, tag = "2")]
    pub nanos: u32,
}
impl BlockTime {
    /// Convert an agreed Protobuf timestamp without wrapping or rounding up.
    /// Signed command windows use seconds: start is inclusive, expiry exclusive.
    ///
    /// # Errors
    /// Rejects negative seconds, negative nanos or nanos outside one second.
    pub fn from_unix(seconds: i64, nanos: i32) -> Result<Self, Error> {
        let value = Self {
            seconds: u64::try_from(seconds).map_err(|_| Error::Invalid)?,
            nanos: u32::try_from(nanos).map_err(|_| Error::Invalid)?,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(self) -> Result<(), Error> {
        if self.seconds > MAX_UNITS || self.nanos >= 1_000_000_000 {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Ordered input from a future reviewed ordering adapter, not finality evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// Next consecutive height, beginning at one.
    pub height: u64,
    /// Exact nonzero identifier supplied by the ordering adapter.
    pub block_id: [u8; 32],
    /// Agreed timestamp; cannot go backwards relative to the committed block.
    pub time: BlockTime,
    /// Original signed bytes, applied in this exact order.
    pub commands: Vec<Vec<u8>>,
}

/// Stable transaction rejection codes; operating-system/database errors are NOT codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CommandFailure {
    /// Invalid canonical encoding, version or command shape.
    Invalid = 1,
    /// Signature or reservation owner does not authorize this command.
    Unauthorized = 2,
    /// The signed domain belongs to a different ordered ledger.
    WrongLedger = 3,
    /// Outside its signed validity interval at the agreed block timestamp.
    NotLive = 4,
    /// An accepted operation id already binds different signed bytes.
    Conflict = 5,
    /// An accepted operation by this signer already consumed this nonce.
    Replay = 6,
    /// Insufficient unreserved units.
    Insufficient = 7,
    /// Account or reservation does not exist.
    NotFound = 8,
    /// Reservation already completed or otherwise inapplicable transition.
    State = 9,
    /// The fixed operation/unit budget cannot admit the operation.
    Capacity = 10,
}
impl CommandFailure {
    fn classify(error: Error) -> Result<Self, Error> {
        match error {
            Error::Invalid => Ok(Self::Invalid),
            Error::Unauthorized => Ok(Self::Unauthorized),
            Error::WrongLedger => Ok(Self::WrongLedger),
            Error::NotLive => Ok(Self::NotLive),
            Error::Conflict => Ok(Self::Conflict),
            Error::Replay => Ok(Self::Replay),
            Error::Insufficient => Ok(Self::Insufficient),
            Error::NotFound => Ok(Self::NotFound),
            Error::State => Ok(Self::State),
            Error::Capacity => Ok(Self::Capacity),
            other => Err(other),
        }
    }
    fn number(value: u32) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Invalid),
            2 => Ok(Self::Unauthorized),
            3 => Ok(Self::WrongLedger),
            4 => Ok(Self::NotLive),
            5 => Ok(Self::Conflict),
            6 => Ok(Self::Replay),
            7 => Ok(Self::Insufficient),
            8 => Ok(Self::NotFound),
            9 => Ok(Self::State),
            10 => Ok(Self::Capacity),
            _ => Err(Error::Store),
        }
    }
}

/// One ordered command outcome. Staged outcomes are provisional until Commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockOutcome {
    /// Digest of the exact input, including rejected inputs.
    pub command_sha256: [u8; 32],
    /// Historical accepted receipt (including exact retries), or a stable rejection.
    pub result: Result<Receipt, CommandFailure>,
}
/// Provisional block calculation. This type does not certify persistence or finality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedBlock {
    /// Consecutive proposed height.
    pub height: u64,
    /// Exact proposed block identifier.
    pub block_id: [u8; 32],
    /// Expected logical state commitment after this block.
    pub app_hash: [u8; 32],
    /// Provisional outcomes in input order.
    pub outcomes: Vec<BlockOutcome>,
}
/// Durable local checkpoint of ordered execution; still NOT a consensus certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockReceipt {
    /// Latest locally committed height; zero means genesis.
    pub height: u64,
    /// Committed block identifier; all zero only for genesis.
    pub block_id: [u8; 32],
    /// Committed agreed time, not the host clock.
    pub time: BlockTime,
    /// Canonical logical state commitment, including replay/domain/checkpoint data.
    pub app_hash: [u8; 32],
    /// Latest block's outcomes, including rejections. Earlier receipts remain in the ledger.
    pub outcomes: Vec<BlockOutcome>,
}

/// One bounded, private ordered TEST ledger. Stage has no persistent side effects.
/// No networking, validator selection, finality validation or real settlement exists here.
pub struct OrderedStore {
    store: Store,
    staged: Option<Pending>,
}
struct Pending {
    base: Vec<u8>,
    record: Record,
}

impl OrderedStore {
    /// Initialize ordered-only state and derive its ledger id from the full genesis.
    /// `authority_id` must be the future adapter's binding of chain identity and
    /// validator authority. This library cannot verify that external authority.
    /// Account order does not affect the derived domain. Keys are never persisted.
    ///
    /// # Errors
    /// Rejects unsafe/existing paths, invalid authority/time/accounts or database failure.
    pub fn create(
        path: &Path,
        authority_id: [u8; 32],
        accounts: &[GenesisAccount],
        time: BlockTime,
    ) -> Result<Self, Error> {
        time.validate()?;
        if authority_id == [0; 32] || accounts.is_empty() || accounts.len() > MAX_ACCOUNTS {
            return Err(Error::Invalid);
        }
        let mut accounts = accounts.to_vec();
        accounts.sort_by_key(|account| account.owner);
        let genesis = Genesis {
            version: 1,
            authority: authority_id.to_vec(),
            time: Some(time),
            accounts: accounts
                .iter()
                .map(|a| InitialAccount {
                    owner: a.owner.to_vec(),
                    units: a.units,
                })
                .collect(),
        };
        let genesis_bytes = encode_canonical(&genesis, 8192).map_err(|_| Error::Invalid)?;
        let ledger = genesis_ledger(&genesis_bytes);
        let store = disk::create_mode(path, ledger, &accounts, Mode::Ordered, |db| {
            db.execute_batch("CREATE TABLE ordered_checkpoint(singleton INTEGER PRIMARY KEY CHECK(singleton=1),genesis BLOB NOT NULL CHECK(length(genesis) BETWEEN 1 AND 8192),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 131072)) STRICT;
                CREATE TRIGGER ordered_genesis_immutable BEFORE UPDATE OF genesis ON ordered_checkpoint BEGIN SELECT RAISE(ABORT,'immutable genesis'); END;")?;
            let mut record = Record {
                block: Some(BlockWire {
                    height: 0,
                    id: vec![0; 32],
                    time: Some(time),
                    commands: vec![],
                }),
                previous_hash: vec![0; 32],
                outcomes: vec![],
                app_hash: vec![],
            };
            record.app_hash = state_hash(db, &genesis_bytes, &record)?.to_vec();
            db.execute(
                "INSERT INTO ordered_checkpoint VALUES(1,?1,?2)",
                params![genesis_bytes, record_bytes(&record)?],
            )?;
            Ok(())
        })?;
        Ok(Self {
            store,
            staged: None,
        })
    }

    /// Reopen ordered-only state, validating its persisted logical commitment.
    ///
    /// # Errors
    /// Rejects owner-local mode, corrupt/mismatched checkpoints and unsafe files.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let value = Self {
            store: disk::open_mode(path, Mode::Ordered)?,
            staged: None,
        };
        value.info()?;
        Ok(value)
    }

    /// Genesis-derived domain for `SignedCommand::sign_ordered`.
    pub fn ledger_id(&self) -> LedgerId {
        self.store.ledger_id
    }

    /// Return only the durable checkpoint, never a staged calculation.
    ///
    /// # Errors
    /// Rejects corrupt state or database errors.
    pub fn info(&self) -> Result<BlockReceipt, Error> {
        let tx = self.store.connection.unchecked_transaction()?;
        let (_, record) = load(&tx, self.ledger_id())?;
        let result = public_receipt(&record, self.ledger_id())?;
        tx.commit()?;
        Ok(result)
    }

    /// Inspect ordered signature/domain/enrollment without consuming a nonce.
    ///
    /// # Errors
    /// Rejects malformed, local-mode, cross-domain or unauthorized input.
    pub fn inspect(&self, bytes: &[u8]) -> Result<Command, Error> {
        let verified = wire::verify_mode(bytes, self.ledger_id(), Mode::Ordered)?;
        crate::account(&self.store.connection, &verified.command.payer)?;
        Ok(verified.command)
    }

    /// Read committed balances. Staged changes remain invisible.
    ///
    /// # Errors
    /// Rejects unknown accounts or database failures.
    pub fn status(&self, owner: AccountId) -> Result<Balance, Error> {
        self.store.status(owner)
    }

    /// Read a committed historical command receipt, never a staged outcome.
    ///
    /// # Errors
    /// Rejects database errors and malformed receipts.
    pub fn operation(&self, id: OperationId) -> Result<Option<Receipt>, Error> {
        self.store.operation(id)
    }

    /// Calculate one block in bounded memory, with no disk mutations or journals.
    /// Repeating identical stage input returns identical output. A different block
    /// requires explicit discard. Only the latest committed block can be replayed.
    ///
    /// # Errors
    /// Rejects stale/conflicting heights, backward time, resource limits or fatal store errors.
    pub fn stage(&mut self, block: &Block) -> Result<StagedBlock, Error> {
        validate_block(block)?;
        let input = BlockWire::from(block);
        if let Some(pending) = &self.staged {
            if pending.record.block.as_ref() != Some(&input) {
                return Err(Error::Conflict);
            }
            return staged_receipt(&pending.record, self.ledger_id());
        }
        let tx = self.store.connection.unchecked_transaction()?;
        let (genesis, current) = load(&tx, self.ledger_id())?;
        let previous = current.block.as_ref().ok_or(Error::Store)?;
        if previous.height == block.height {
            if previous != &input {
                return Err(Error::Conflict);
            }
            return staged_receipt(&current, self.ledger_id());
        }
        if previous.height.checked_add(1) != Some(block.height)
            || previous.time.ok_or(Error::Store)? > block.time
            || previous.id == input.id
        {
            return Err(Error::State);
        }
        let snapshot = Snapshot::capture(&tx)?;
        tx.commit()?;
        let memory = snapshot.memory_copy()?;
        let outcomes = execute(&memory, self.ledger_id(), &input)?;
        let mut record = Record {
            block: Some(input),
            previous_hash: current.app_hash.clone(),
            outcomes,
            app_hash: vec![],
        };
        record.app_hash = state_hash(&memory, &genesis, &record)?.to_vec();
        let preview = staged_receipt(&record, self.ledger_id())?;
        self.staged = Some(Pending {
            base: record_bytes(&current)?,
            record,
        });
        Ok(preview)
    }

    /// Discard a memory-only calculation without changing durable state.
    pub fn discard_staged(&mut self) {
        self.staged = None;
    }

    /// Atomically persist the staged block and every accepted transition/receipt.
    /// A concurrent writer invalidates the staged base; no partial block is committed.
    /// Repeating the latest already committed block id returns its durable receipt.
    ///
    /// # Errors
    /// Rejects unstaged/conflicting blocks, changed bases, corruption or local storage errors.
    pub fn commit(&mut self, block_id: [u8; 32]) -> Result<BlockReceipt, Error> {
        self.commit_inner(block_id, || {})
    }

    fn commit_inner(
        &mut self,
        block_id: [u8; 32],
        before_commit: impl FnOnce(),
    ) -> Result<BlockReceipt, Error> {
        let ledger = self.ledger_id();
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (genesis, current) = load(&tx, ledger)?;
        let current_block = current.block.as_ref().ok_or(Error::Store)?;
        if current_block.height > 0 && current_block.id == block_id {
            if let Some(pending) = &self.staged {
                if pending.record != current {
                    return Err(Error::Conflict);
                }
            }
            let receipt = public_receipt(&current, ledger)?;
            tx.commit()?;
            self.staged = None;
            return Ok(receipt);
        }
        let pending = self.staged.as_ref().ok_or(Error::State)?;
        let block = pending.record.block.as_ref().ok_or(Error::Store)?;
        if block.id != block_id || pending.base != record_bytes(&current)? {
            return Err(Error::Conflict);
        }
        let outcomes = execute(&tx, ledger, block)?;
        if outcomes != pending.record.outcomes
            || state_hash(&tx, &genesis, &pending.record)?.as_slice() != pending.record.app_hash
        {
            return Err(Error::Store);
        }
        let receipt = public_receipt(&pending.record, ledger)?;
        tx.execute(
            "UPDATE ordered_checkpoint SET record=?1 WHERE singleton=1",
            [record_bytes(&pending.record)?],
        )?;
        before_commit();
        tx.commit()?;
        self.staged = None;
        Ok(receipt)
    }
}

fn validate_block(block: &Block) -> Result<(), Error> {
    block.time.validate()?;
    if block.height == 0 || block.height > MAX_UNITS || block.block_id == [0; 32] {
        return Err(Error::Invalid);
    }
    if block.commands.len() > MAX_BLOCK_COMMANDS
        || block.commands.iter().any(|c| c.len() > 4096)
        || block
            .commands
            .iter()
            .try_fold(0_usize, |size, c| size.checked_add(c.len()))
            .is_none_or(|size| size > MAX_BLOCK_BYTES)
    {
        return Err(Error::Capacity);
    }
    Ok(())
}

fn execute(
    db: &Connection,
    ledger: LedgerId,
    block: &BlockWire,
) -> Result<Vec<OutcomeWire>, Error> {
    let time = block.time.ok_or(Error::Store)?;
    let mut outcomes = Vec::new();
    for bytes in &block.commands {
        db.execute_batch("SAVEPOINT ordered_command;")?;
        let result = apply_command(db, ledger, Mode::Ordered, bytes, time.seconds);
        let outcome = match result {
            Ok(receipt) => OutcomeWire {
                hash: Sha256::digest(bytes).to_vec(),
                code: 0,
                receipt: Some(ReceiptWire {
                    operation: receipt.operation_id.to_vec(),
                    hash: receipt.command_sha256.to_vec(),
                    sequence: receipt.sequence,
                    reservation: receipt.reservation_id.to_vec(),
                    state: u32::from(state_number(receipt.state)),
                }),
            },
            Err(error) => {
                db.execute_batch("ROLLBACK TO ordered_command;")?;
                OutcomeWire {
                    hash: Sha256::digest(bytes).to_vec(),
                    code: CommandFailure::classify(error)? as u32,
                    receipt: None,
                }
            }
        };
        db.execute_batch("RELEASE ordered_command;")?;
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

fn genesis_ledger(genesis: &[u8]) -> LedgerId {
    let mut hash = Sha256::new();
    hash.update(b"volparossa/transaction/ordered-genesis/v1\0");
    hash.update(genesis);
    hash.finalize().into()
}
fn record_bytes(record: &Record) -> Result<Vec<u8>, Error> {
    encode_canonical(record, MAX_RECORD_BYTES).map_err(|_| Error::Store)
}
fn state_hash(db: &Connection, genesis: &[u8], record: &Record) -> Result<[u8; 32], Error> {
    let mut unhashed = record.clone();
    unhashed.app_hash.clear();
    let pieces = [
        genesis.to_vec(),
        record_bytes(&unhashed)?,
        Snapshot::capture(db)?.bytes()?,
    ];
    let mut hash = Sha256::new();
    hash.update(b"volparossa/transaction/ordered-state/v1\0");
    for piece in pieces {
        hash.update((piece.len() as u64).to_be_bytes());
        hash.update(piece);
    }
    Ok(hash.finalize().into())
}
fn load(db: &Connection, ledger: LedgerId) -> Result<(Vec<u8>, Record), Error> {
    let (genesis, bytes): (Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT genesis,record FROM ordered_checkpoint WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let decoded: Genesis = decode_canonical(&genesis, 8192).map_err(|_| Error::Store)?;
    if decoded.version != 1
        || decoded.authority.len() != 32
        || decoded.authority == [0; 32]
        || decoded.accounts.is_empty()
        || decoded.accounts.len() > MAX_ACCOUNTS
        || decoded
            .accounts
            .windows(2)
            .any(|a| a[0].owner >= a[1].owner)
        || genesis_ledger(&genesis) != ledger
    {
        return Err(Error::Store);
    }
    decoded
        .time
        .ok_or(Error::Store)?
        .validate()
        .map_err(|_| Error::Store)?;
    let record: Record = decode_canonical(&bytes, MAX_RECORD_BYTES).map_err(|_| Error::Store)?;
    let block = record.block.as_ref().ok_or(Error::Store)?;
    let public = public_receipt(&record, ledger)?;
    if record.previous_hash.len() != 32 || block.commands.len() != record.outcomes.len() {
        return Err(Error::Store);
    }
    if block.height == 0 {
        if block.id != [0; 32]
            || record.previous_hash != [0; 32]
            || !block.commands.is_empty()
            || block.time != decoded.time
        {
            return Err(Error::Store);
        }
    } else {
        validate_block(&Block {
            height: block.height,
            block_id: public.block_id,
            time: public.time,
            commands: block.commands.clone(),
        })
        .map_err(|_| Error::Store)?;
        if block.time < decoded.time {
            return Err(Error::Store);
        }
    }
    for (command, outcome) in block.commands.iter().zip(&record.outcomes) {
        if outcome.hash != Sha256::digest(command).as_slice() {
            return Err(Error::Store);
        }
    }
    if state_hash(db, &genesis, &record)?.as_slice() != record.app_hash {
        return Err(Error::Store);
    }
    Ok((genesis, record))
}
fn array(value: &[u8]) -> Result<[u8; 32], Error> {
    value.try_into().map_err(|_| Error::Store)
}
fn public_receipt(record: &Record, ledger: LedgerId) -> Result<BlockReceipt, Error> {
    let block = record.block.as_ref().ok_or(Error::Store)?;
    let outcomes = record
        .outcomes
        .iter()
        .map(|outcome| {
            let result = match (&outcome.receipt, outcome.code) {
                (Some(value), 0) => Ok(Receipt {
                    ledger_id: ledger,
                    operation_id: array(&value.operation)?,
                    command_sha256: array(&value.hash)?,
                    sequence: value.sequence,
                    reservation_id: array(&value.reservation)?,
                    state: parse_state(u8::try_from(value.state).map_err(|_| Error::Store)?)?,
                }),
                (None, code) => Err(CommandFailure::number(code)?),
                _ => return Err(Error::Store),
            };
            Ok(BlockOutcome {
                command_sha256: array(&outcome.hash)?,
                result,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(BlockReceipt {
        height: block.height,
        block_id: array(&block.id)?,
        time: block.time.ok_or(Error::Store)?,
        app_hash: array(&record.app_hash)?,
        outcomes,
    })
}
fn staged_receipt(record: &Record, ledger: LedgerId) -> Result<StagedBlock, Error> {
    let value = public_receipt(record, ledger)?;
    Ok(StagedBlock {
        height: value.height,
        block_id: value.block_id,
        app_hash: value.app_hash,
        outcomes: value.outcomes,
    })
}

#[derive(Clone, PartialEq, Message)]
struct Genesis {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    authority: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    time: Option<BlockTime>,
    #[prost(message, repeated, tag = "4")]
    accounts: Vec<InitialAccount>,
}
#[derive(Clone, PartialEq, Message)]
struct InitialAccount {
    #[prost(bytes = "vec", tag = "1")]
    owner: Vec<u8>,
    #[prost(uint64, tag = "2")]
    units: u64,
}
#[derive(Clone, PartialEq, Message)]
struct BlockWire {
    #[prost(uint64, tag = "1")]
    height: u64,
    #[prost(bytes = "vec", tag = "2")]
    id: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    time: Option<BlockTime>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    commands: Vec<Vec<u8>>,
}
impl From<&Block> for BlockWire {
    fn from(block: &Block) -> Self {
        Self {
            height: block.height,
            id: block.block_id.to_vec(),
            time: Some(block.time),
            commands: block.commands.clone(),
        }
    }
}
#[derive(Clone, PartialEq, Message)]
struct Record {
    #[prost(message, optional, tag = "1")]
    block: Option<BlockWire>,
    #[prost(bytes = "vec", tag = "2")]
    previous_hash: Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    outcomes: Vec<OutcomeWire>,
    #[prost(bytes = "vec", tag = "4")]
    app_hash: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
struct OutcomeWire {
    #[prost(bytes = "vec", tag = "1")]
    hash: Vec<u8>,
    #[prost(uint32, tag = "2")]
    code: u32,
    #[prost(message, optional, tag = "3")]
    receipt: Option<ReceiptWire>,
}
#[derive(Clone, PartialEq, Message)]
struct ReceiptWire {
    #[prost(bytes = "vec", tag = "1")]
    operation: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    hash: Vec<u8>,
    #[prost(uint64, tag = "3")]
    sequence: u64,
    #[prost(bytes = "vec", tag = "4")]
    reservation: Vec<u8>,
    #[prost(uint32, tag = "5")]
    state: u32,
}

#[cfg(test)]
#[path = "ordered_tests.rs"]
mod tests;
