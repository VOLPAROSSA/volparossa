//! Bounded local ordered-executor evidence, never described as consensus tests.
use super::*;
use crate::{Action, SignedCommand};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use std::{
    fs,
    io::{Read as _, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    process::{Command as Process, Stdio},
    thread,
    time::{Duration, Instant},
};

fn key(id: u8) -> SigningKey {
    SigningKey::from_bytes(&[id; 32])
}
fn owner(id: u8) -> AccountId {
    key(id).verifying_key().to_bytes()
}
fn time(seconds: u64) -> BlockTime {
    BlockTime { seconds, nanos: 0 }
}
fn accounts() -> Vec<GenesisAccount> {
    vec![
        GenesisAccount {
            owner: owner(1),
            units: 100,
        },
        GenesisAccount {
            owner: owner(2),
            units: 0,
        },
        GenesisAccount {
            owner: owner(3),
            units: 0,
        },
    ]
}
fn store(path: &Path) -> OrderedStore {
    OrderedStore::create(path, [7; 32], &accounts(), time(90)).unwrap()
}
fn random_nonce() -> [u8; 32] {
    std::array::from_fn(|_| OsRng.next_u32().to_le_bytes()[0])
}
fn signed(ledger: LedgerId, id: u8, nonce: [u8; 32], action: Action) -> Vec<u8> {
    SignedCommand::sign_ordered(
        ledger,
        &key(1),
        Command {
            operation_id: [id; 32],
            payer: owner(1),
            action,
        },
        100,
        200,
        nonce,
    )
    .unwrap()
    .encode()
}
fn reserve(ledger: LedgerId, id: u8, units: u64) -> Vec<u8> {
    signed(
        ledger,
        id,
        random_nonce(),
        Action::Reserve {
            recipient: owner(2),
            units,
        },
    )
}
fn block(height: u64, id: u8, seconds: u64, commands: Vec<Vec<u8>>) -> Block {
    Block {
        height,
        block_id: [id; 32],
        time: time(seconds),
        commands,
    }
}

#[test]
fn stage_is_memory_only_and_commit_reopen_replay_are_exact() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ordered");
    let mut store = store(&path);
    let initial = store.info().unwrap();
    let file = path.join("test-transactions.sqlite3");
    let original = fs::read(&file).unwrap();
    let bytes = reserve(store.ledger_id(), 1, 70);
    let input = block(1, 1, 110, vec![bytes]);
    let staged = store.stage(&input).unwrap();
    assert_eq!(store.stage(&input).unwrap(), staged);
    assert_eq!(fs::read(&file).unwrap(), original);
    assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
    assert_eq!(store.info().unwrap(), initial);
    assert_eq!(store.status(owner(1)).unwrap().available_units, 100);
    assert!(store.operation([1; 32]).unwrap().is_none());
    assert_eq!(OrderedStore::open(&path).unwrap().info().unwrap(), initial);
    let committed = store.commit([1; 32]).unwrap();
    assert_eq!(committed.app_hash, staged.app_hash);
    assert_eq!(committed.outcomes, staged.outcomes);
    assert_eq!(store.commit([1; 32]).unwrap(), committed);
    drop(store);
    let mut opened = OrderedStore::open(&path).unwrap();
    assert_eq!(opened.info().unwrap(), committed);
    assert_eq!(opened.stage(&input).unwrap(), staged);
    assert_eq!(opened.commit([1; 32]).unwrap(), committed);
    assert_eq!(
        opened.status(owner(1)).unwrap(),
        Balance {
            available_units: 30,
            reserved_units: 70
        }
    );
}

#[test]
fn independent_stores_same_order_conflicts_failures_and_hashes_match() {
    let temp = tempfile::tempdir().unwrap();
    let mut a = store(&temp.path().join("a"));
    let mut b = store(&temp.path().join("b"));
    let ledger = a.ledger_id();
    let original_nonce = random_nonce();
    let first = signed(
        ledger,
        1,
        original_nonce,
        Action::Reserve {
            recipient: owner(2),
            units: 70,
        },
    );
    let changed = signed(
        ledger,
        1,
        random_nonce(),
        Action::Reserve {
            recipient: owner(2),
            units: 71,
        },
    );
    let duplicate_nonce = signed(
        ledger,
        5,
        original_nonce,
        Action::Reserve {
            recipient: owner(2),
            units: 1,
        },
    );
    let input = block(
        1,
        8,
        110,
        vec![
            first.clone(),
            reserve(ledger, 2, 70),
            vec![],
            changed,
            duplicate_nonce,
            signed(
                ledger,
                3,
                random_nonce(),
                Action::Commit {
                    reservation_id: [1; 32],
                },
            ),
            first,
        ],
    );
    let calculated = a.stage(&input).unwrap();
    assert_eq!(b.stage(&input).unwrap(), calculated);
    assert_eq!(
        calculated.outcomes[1].result,
        Err(CommandFailure::Insufficient)
    );
    assert_eq!(calculated.outcomes[2].result, Err(CommandFailure::Invalid));
    assert_eq!(calculated.outcomes[3].result, Err(CommandFailure::Conflict));
    assert_eq!(calculated.outcomes[4].result, Err(CommandFailure::Replay));
    assert_eq!(calculated.outcomes[0], calculated.outcomes[6]);
    assert_eq!(a.commit([8; 32]).unwrap(), b.commit([8; 32]).unwrap());
    for s in [&a, &b] {
        assert_eq!(
            s.status(owner(1)).unwrap(),
            Balance {
                available_units: 30,
                reserved_units: 0
            }
        );
        assert_eq!(s.status(owner(2)).unwrap().available_units, 70);
        assert!(s.operation([2; 32]).unwrap().is_none());
        assert_eq!(s.operation([3; 32]).unwrap().unwrap().sequence, 2);
    }
}

#[test]
fn ordered_and_local_modes_and_signature_domains_cannot_be_bypassed() {
    let temp = tempfile::tempdir().unwrap();
    let ordered_path = temp.path().join("ordered");
    let mut ordered = store(&ordered_path);
    let ledger = ordered.ledger_id();
    let local_path = temp.path().join("local");
    let mut local = Store::create(&local_path, ledger, &accounts()).unwrap();
    assert!(Store::open(&ordered_path).is_err());
    assert!(OrderedStore::open(&local_path).is_err());
    let command = Command {
        operation_id: [1; 32],
        payer: owner(1),
        action: Action::Reserve {
            recipient: owner(2),
            units: 70,
        },
    };
    let local_bytes = SignedCommand::sign(ledger, &key(1), command, 100, 200, random_nonce())
        .unwrap()
        .encode();
    let ordered_bytes = reserve(ledger, 1, 70);
    assert!(matches!(
        local.apply(&ordered_bytes, 110),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        ordered.store.apply(&local_bytes, 110),
        Err(Error::Store)
    ));
    assert!(ordered.inspect(&local_bytes).is_err());
    let result = ordered.stage(&block(1, 1, 110, vec![local_bytes])).unwrap();
    assert_eq!(result.outcomes[0].result, Err(CommandFailure::Invalid));
    ordered.commit([1; 32]).unwrap();
    assert_eq!(ordered.status(owner(1)).unwrap().available_units, 100);
}

#[test]
fn canonical_genesis_binds_authority_accounts_and_time() {
    let temp = tempfile::tempdir().unwrap();
    let first = store(&temp.path().join("first"));
    let mut reversed = accounts();
    reversed.reverse();
    let same =
        OrderedStore::create(&temp.path().join("same"), [7; 32], &reversed, time(90)).unwrap();
    assert_eq!(first.ledger_id(), same.ledger_id());
    assert_eq!(first.info().unwrap(), same.info().unwrap());
    let changed_authority = OrderedStore::create(
        &temp.path().join("authority"),
        [8; 32],
        &accounts(),
        time(90),
    )
    .unwrap();
    let changed_time =
        OrderedStore::create(&temp.path().join("time"), [7; 32], &accounts(), time(91)).unwrap();
    let mut changed = accounts();
    changed[0].units = 99;
    changed[1].units = 1;
    let changed_accounts =
        OrderedStore::create(&temp.path().join("accounts"), [7; 32], &changed, time(90)).unwrap();
    for other in [&changed_authority, &changed_time, &changed_accounts] {
        assert_ne!(other.ledger_id(), first.ledger_id());
        assert!(matches!(
            other.inspect(&reserve(first.ledger_id(), 1, 70)),
            Err(Error::WrongLedger)
        ));
    }
}

#[test]
fn agreed_seconds_nanos_expiry_and_backwards_time_are_explicit() {
    assert!(BlockTime::from_unix(-1, 0).is_err());
    assert!(BlockTime::from_unix(1, -1).is_err());
    assert!(BlockTime::from_unix(1, 1_000_000_000).is_err());
    assert_eq!(
        BlockTime::from_unix(i64::MAX, 999_999_999).unwrap().seconds,
        MAX_UNITS
    );
    let temp = tempfile::tempdir().unwrap();
    let mut s = store(&temp.path().join("s"));
    let ledger = s.ledger_id();
    let bytes = reserve(ledger, 1, 70);
    let mut input = block(1, 1, 199, vec![bytes.clone()]);
    input.time.nanos = 999_999_999;
    assert!(s.stage(&input).unwrap().outcomes[0].result.is_ok());
    s.commit([1; 32]).unwrap();
    assert!(matches!(
        s.stage(&block(2, 2, 199, vec![])),
        Err(Error::State)
    ));
    let expired = block(2, 2, 200, vec![bytes, reserve(ledger, 2, 1)]);
    let result = s.stage(&expired).unwrap();
    assert!(result.outcomes[0].result.is_ok());
    assert_eq!(result.outcomes[1].result, Err(CommandFailure::NotLive));
    s.commit([2; 32]).unwrap();
    assert_eq!(s.status(owner(1)).unwrap().reserved_units, 70);
}

#[test]
fn conflicting_concurrent_commits_and_out_of_order_inputs_do_not_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("s");
    let mut a = store(&path);
    let mut b = OrderedStore::open(&path).unwrap();
    let ledger = a.ledger_id();
    let input = block(1, 1, 110, vec![reserve(ledger, 1, 70)]);
    let other = block(1, 2, 110, vec![reserve(ledger, 2, 70)]);
    a.stage(&input).unwrap();
    b.stage(&other).unwrap();
    a.commit([1; 32]).unwrap();
    assert!(matches!(b.commit([2; 32]), Err(Error::Conflict)));
    b.discard_staged();
    assert!(matches!(b.stage(&other), Err(Error::Conflict)));
    assert!(matches!(
        b.stage(&block(3, 3, 110, vec![])),
        Err(Error::State)
    ));
    assert_eq!(a.info().unwrap(), b.info().unwrap());
    assert_eq!(b.status(owner(1)).unwrap().reserved_units, 70);
    let next = block(2, 3, 120, vec![]);
    a.stage(&next).unwrap();
    b.stage(&next).unwrap();
    assert_eq!(a.commit([3; 32]).unwrap(), b.commit([3; 32]).unwrap());
}

#[test]
fn resource_limits_discard_and_unstaged_commit_preserve_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    let mut s = store(&temp.path().join("s"));
    let original = s.info().unwrap();
    assert!(matches!(
        s.stage(&block(1, 1, 110, vec![vec![]; MAX_BLOCK_COMMANDS + 1])),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        s.stage(&block(1, 1, 110, vec![vec![0; 4097]])),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        s.stage(&block(1, 1, 110, vec![vec![0; 4096]; 17])),
        Err(Error::Capacity)
    ));
    assert!(matches!(s.commit([1; 32]), Err(Error::State)));
    s.stage(&block(1, 1, 110, vec![])).unwrap();
    assert!(matches!(
        s.stage(&block(1, 2, 110, vec![])),
        Err(Error::Conflict)
    ));
    s.discard_staged();
    assert!(matches!(s.commit([1; 32]), Err(Error::State)));
    assert_eq!(s.info().unwrap(), original);
}

#[test]
fn database_failure_is_fatal_and_rolls_back_whole_commit() {
    let temp = tempfile::tempdir().unwrap();
    let mut s = store(&temp.path().join("s"));
    let original = s.info().unwrap();
    let input = block(
        1,
        1,
        110,
        vec![reserve(s.ledger_id(), 1, 70), reserve(s.ledger_id(), 2, 20)],
    );
    let staged = s.stage(&input).unwrap();
    assert!(staged.outcomes.iter().all(|outcome| outcome.result.is_ok()));
    // The first command has succeeded and released its savepoint when the
    // second command fails. The enclosing block transaction must undo both.
    s.store.connection.execute_batch("CREATE TRIGGER injected_failure BEFORE INSERT ON operations WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'injected second-command failure'); END;").unwrap();
    assert!(matches!(s.commit([1; 32]), Err(Error::Database(_))));
    assert_eq!(s.info().unwrap(), original);
    assert_eq!(
        s.status(owner(1)).unwrap(),
        Balance {
            available_units: 100,
            reserved_units: 0
        }
    );
    assert!(s.operation([1; 32]).unwrap().is_none());
    assert!(s.operation([2; 32]).unwrap().is_none());
    s.store
        .connection
        .execute_batch("DROP TRIGGER injected_failure;")
        .unwrap();
    let committed = s.commit([1; 32]).unwrap();
    assert_eq!(committed.app_hash, staged.app_hash);
    assert_eq!(committed.outcomes, staged.outcomes);
    assert_eq!(
        s.status(owner(1)).unwrap(),
        Balance {
            available_units: 10,
            reserved_units: 90
        }
    );
    assert_eq!(s.operation([1; 32]).unwrap().unwrap().sequence, 1);
    assert_eq!(s.operation([2; 32]).unwrap().unwrap().sequence, 2);
}

#[test]
fn state_hash_covers_replay_data_and_reopen_detects_balanced_corruption() {
    let temp = tempfile::tempdir().unwrap();
    let mut a = store(&temp.path().join("a"));
    let mut b = store(&temp.path().join("b"));
    let ledger = a.ledger_id();
    let action = Action::Reserve {
        recipient: owner(2),
        units: 70,
    };
    a.stage(&block(
        1,
        1,
        110,
        vec![signed(ledger, 1, random_nonce(), action)],
    ))
    .unwrap();
    a.commit([1; 32]).unwrap();
    b.stage(&block(
        1,
        1,
        110,
        vec![signed(ledger, 1, random_nonce(), action)],
    ))
    .unwrap();
    b.commit([1; 32]).unwrap();
    assert_eq!(a.status(owner(1)).unwrap(), b.status(owner(1)).unwrap());
    assert_ne!(a.info().unwrap().app_hash, b.info().unwrap().app_hash);
    a.store
        .connection
        .execute(
            "UPDATE accounts SET available=available-1 WHERE owner=?1",
            [owner(1).as_slice()],
        )
        .unwrap();
    a.store
        .connection
        .execute(
            "UPDATE accounts SET available=available+1 WHERE owner=?1",
            [owner(2).as_slice()],
        )
        .unwrap();
    drop(a);
    assert!(matches!(
        OrderedStore::open(&temp.path().join("a")),
        Err(Error::Store)
    ));
}

#[test]
fn canonical_hash_covers_old_nonce_signature_and_receipt_fields() {
    let temp = tempfile::tempdir().unwrap();
    let mut s = store(&temp.path().join("s"));
    let input = block(1, 1, 110, vec![reserve(s.ledger_id(), 1, 70)]);
    s.stage(&input).unwrap();
    s.commit([1; 32]).unwrap();
    // The latest block no longer contains the old command. Its replay state must
    // still be in the logical commitment, not just the most recent block bytes.
    s.stage(&block(2, 2, 120, vec![])).unwrap();
    s.commit([2; 32]).unwrap();
    let (genesis, record) = load(&s.store.connection, s.ledger_id()).unwrap();
    let snapshot = Snapshot::capture(&s.store.connection).unwrap();
    for mutation in [
        "UPDATE operations SET nonce=zeroblob(32)",
        "UPDATE operations SET signed=x'01'",
        "UPDATE operations SET hash=zeroblob(32)",
        "UPDATE operations SET sequence=2",
        "UPDATE operations SET state=2",
    ] {
        let memory = snapshot.memory_copy().unwrap();
        memory
            .execute_batch("DROP TRIGGER operations_no_update;")
            .unwrap();
        memory.execute_batch(mutation).unwrap();
        assert_ne!(
            state_hash(&memory, &genesis, &record).unwrap().as_slice(),
            record.app_hash
        );
    }
}

#[test]
fn tampered_checkpoint_is_not_adopted_on_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("s");
    let mut s = store(&path);
    s.stage(&block(1, 1, 110, vec![])).unwrap();
    s.commit([1; 32]).unwrap();
    let (_, mut record) = load(&s.store.connection, s.ledger_id()).unwrap();
    record.block.as_mut().unwrap().time.as_mut().unwrap().nanos = 1;
    s.store
        .connection
        .execute(
            "UPDATE ordered_checkpoint SET record=?1",
            [record_bytes(&record).unwrap()],
        )
        .unwrap();
    drop(s);
    assert!(matches!(OrderedStore::open(&path), Err(Error::Store)));
}

#[test]
#[ignore = "only the owned crash regression invokes this child"]
fn ordered_crash_child() {
    let Some(path) = std::env::var_os("VOLPAROSSA_ORDERED_CRASH_ROOT") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let phase = std::env::var("VOLPAROSSA_ORDERED_CRASH_PHASE").unwrap();
    let mut bytes = Vec::new();
    fs::File::open(path.join("block.pb"))
        .unwrap()
        .take(MAX_RECORD_BYTES as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    let input: BlockWire = decode_canonical(&bytes, MAX_RECORD_BYTES).unwrap();
    let block = Block {
        height: input.height,
        block_id: array(&input.id).unwrap(),
        time: input.time.unwrap(),
        commands: input.commands,
    };
    let mut s = OrderedStore::open(&path).unwrap();
    s.stage(&block).unwrap();
    let ready = || {
        fs::write(path.join("ready"), b"checkpoint").unwrap();
        thread::sleep(Duration::from_secs(30));
    };
    match phase.as_str() {
        "stage" => ready(),
        "before" => {
            s.commit_inner(block.block_id, ready).unwrap();
        }
        "after" => {
            s.commit(block.block_id).unwrap();
            ready();
        }
        _ => panic!("invalid phase"),
    }
}

#[test]
fn killed_process_stage_before_commit_and_after_commit_recover_exactly() {
    for phase in ["stage", "before", "after"] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("s");
        let s = store(&path);
        let initial = s.info().unwrap();
        let input = block(1, 1, 110, vec![reserve(s.ledger_id(), 1, 70)]);
        drop(s);
        let bytes = encode_canonical(&BlockWire::from(&input), MAX_RECORD_BYTES).unwrap();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("block.pb"))
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut child = Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ordered::tests::ordered_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("VOLPAROSSA_ORDERED_CRASH_ROOT", &path)
            .env("VOLPAROSSA_ORDERED_CRASH_PHASE", phase)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.join("ready").exists()
            && Instant::now() < deadline
            && child.try_wait().unwrap().is_none()
        {
            thread::sleep(Duration::from_millis(10));
        }
        let reached = path.join("ready").exists();
        child.kill().ok();
        child.wait().unwrap();
        assert!(reached, "child checkpoint {phase}");
        let mut s = OrderedStore::open(&path).unwrap();
        if phase == "after" {
            assert_eq!(s.info().unwrap().height, 1);
        } else {
            assert_eq!(s.info().unwrap(), initial);
        }
        assert_eq!(s.operation([1; 32]).unwrap().is_some(), phase == "after");
        let preview = s.stage(&input).unwrap();
        let committed = s.commit([1; 32]).unwrap();
        assert_eq!(preview.app_hash, committed.app_hash);
        assert_eq!(s.commit([1; 32]).unwrap(), committed);
        assert_eq!(
            s.status(owner(1)).unwrap(),
            Balance {
                available_units: 30,
                reserved_units: 70
            }
        );
    }
}
