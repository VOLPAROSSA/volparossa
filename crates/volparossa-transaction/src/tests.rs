//! Real `SQLite` and Ed25519 tests with fictional units and inert child processes.
use crate::*;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use std::{
    fs,
    io::{Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink},
    process::{Command as Process, Stdio},
    thread,
    time::{Duration, Instant},
};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}
fn owner(byte: u8) -> AccountId {
    key(byte).verifying_key().to_bytes()
}
fn store(root: &Path) -> Store {
    Store::create(
        root,
        [9; 32],
        &[
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
        ],
    )
    .unwrap()
}
fn signed(id: u8, action: Action) -> Vec<u8> {
    signed_with_nonce(id, action, random_nonce())
}
fn random_nonce() -> [u8; 32] {
    std::array::from_fn(|_| OsRng.next_u32().to_le_bytes()[0])
}
fn signed_with_nonce(id: u8, action: Action, nonce: [u8; 32]) -> Vec<u8> {
    SignedCommand::sign(
        [9; 32],
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
fn reserve(id: u8, units: u64) -> Vec<u8> {
    signed(
        id,
        Action::Reserve {
            recipient: owner(2),
            units,
        },
    )
}

#[test]
fn inspection_verifies_terms_without_admission_or_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = store(&temp.path().join("ledger"));
    assert_eq!(ledger.ledger_id(), [9; 32]);
    let input = reserve(1, 70);
    let terms = ledger.inspect(&input).unwrap();
    assert_eq!(terms.operation_id, [1; 32]);
    assert_eq!(terms.payer, owner(1));
    assert_eq!(
        terms.action,
        Action::Reserve {
            recipient: owner(2),
            units: 70
        }
    );
    // Inspection is deliberately not a quote, live authorization or reservation.
    assert!(ledger.inspect(&reserve(2, 101)).is_ok());
    assert!(matches!(ledger.apply(&input, 300), Err(Error::NotLive)));
    assert_eq!(ledger.inspect(&input).unwrap(), terms);
    assert_eq!(
        ledger.status(owner(1)).unwrap(),
        Balance {
            available_units: 100,
            reserved_units: 0
        }
    );
    assert!(ledger.operation([1; 32]).unwrap().is_none());
    assert!(ledger.operation([2; 32]).unwrap().is_none());
    let cross = SignedCommand::sign([8; 32], &key(1), terms, 100, 200, random_nonce())
        .unwrap()
        .encode();
    assert!(matches!(ledger.inspect(&cross), Err(Error::WrongLedger)));
    let foreign = SignedCommand::sign(
        [9; 32],
        &key(4),
        Command {
            payer: owner(4),
            ..terms
        },
        100,
        200,
        random_nonce(),
    )
    .unwrap()
    .encode();
    assert!(matches!(ledger.inspect(&foreign), Err(Error::NotFound)));
    let mut forged = input.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(ledger.inspect(&forged).is_err());
    assert_eq!(ledger.apply(&input, 110).unwrap().sequence, 1);
    assert_eq!(ledger.inspect(&input).unwrap(), terms);
}

#[test]
fn reopen_exact_expired_replay_and_commit_conserve_without_second_debit() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger");
    let mut ledger = store(&path);
    let input = reserve(1, 70);
    let first = ledger.apply(&input, 110).unwrap();
    assert_eq!(first.state, ReservationState::Reserved);
    drop(ledger);
    let mut ledger = Store::open(&path).unwrap();
    assert_eq!(ledger.apply(&input, 300).unwrap(), first);
    assert_eq!(
        ledger.status(owner(1)).unwrap(),
        Balance {
            available_units: 30,
            reserved_units: 70
        }
    );
    let commit = signed(
        2,
        Action::Commit {
            reservation_id: [1; 32],
        },
    );
    let receipt = ledger.apply(&commit, 120).unwrap();
    drop(ledger);
    let mut ledger = Store::open(&path).unwrap();
    assert_eq!(ledger.apply(&commit, 1000).unwrap(), receipt);
    assert_eq!(
        ledger.status(owner(1)).unwrap(),
        Balance {
            available_units: 30,
            reserved_units: 0
        }
    );
    assert_eq!(ledger.status(owner(2)).unwrap().available_units, 70);
    assert_eq!(ledger.operation([1; 32]).unwrap(), Some(first));
    assert_eq!(receipt.sequence, 2);
    assert!(matches!(
        ledger.apply(
            &signed(
                3,
                Action::Cancel {
                    reservation_id: [1; 32]
                }
            ),
            130
        ),
        Err(Error::State)
    ));
    assert!(ledger.operation([3; 32]).unwrap().is_none());
}

#[test]
fn cancel_returns_only_reserved_units_and_all_repeated_receipts_are_stable() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = store(&temp.path().join("ledger"));
    ledger.apply(&reserve(1, 80), 100).unwrap();
    let cancellation = signed(
        2,
        Action::Cancel {
            reservation_id: [1; 32],
        },
    );
    let receipt = ledger.apply(&cancellation, 101).unwrap();
    assert_eq!(receipt.state, ReservationState::Cancelled);
    assert_eq!(ledger.apply(&cancellation, 300).unwrap(), receipt);
    assert_eq!(
        ledger.status(owner(1)).unwrap(),
        Balance {
            available_units: 100,
            reserved_units: 0
        }
    );
    assert!(matches!(
        ledger.apply(
            &signed(
                3,
                Action::Commit {
                    reservation_id: [1; 32]
                }
            ),
            102
        ),
        Err(Error::State)
    ));
    assert!(matches!(
        ledger.apply(
            &signed(
                4,
                Action::Cancel {
                    reservation_id: [1; 32]
                }
            ),
            102
        ),
        Err(Error::State)
    ));
}

#[test]
fn forged_signer_wrong_domain_changed_bytes_and_unsupported_encoding_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = store(&temp.path().join("ledger"));
    let good = reserve(1, 50);
    let mut modified = good.clone();
    let last = modified.last_mut().unwrap();
    *last ^= 1;
    let mut unknown = good.clone();
    unknown.extend_from_slice(&[0xa0, 0x06, 1]);
    for bytes in [
        modified,
        unknown,
        wire::mutate_and_resign(&good, &key(2), "wrong-payer"),
        wire::mutate_and_resign(&good, &key(1), "version"),
        wire::mutate_and_resign(&good, &key(1), "real-asset"),
    ] {
        assert!(ledger.apply(&bytes, 110).is_err());
    }
    let cross = SignedCommand::sign(
        [8; 32],
        &key(1),
        Command {
            operation_id: [1; 32],
            payer: owner(1),
            action: Action::Reserve {
                recipient: owner(2),
                units: 50,
            },
        },
        100,
        200,
        random_nonce(),
    )
    .unwrap();
    assert!(matches!(
        ledger.apply(&cross.encode(), 110),
        Err(Error::WrongLedger)
    ));
    let stranger = SignedCommand::sign(
        [9; 32],
        &key(4),
        Command {
            operation_id: [1; 32],
            payer: owner(4),
            action: Action::Reserve {
                recipient: owner(2),
                units: 50,
            },
        },
        100,
        200,
        random_nonce(),
    )
    .unwrap();
    assert!(matches!(
        ledger.apply(&stranger.encode(), 110),
        Err(Error::NotFound)
    ));
    assert!(matches!(ledger.apply(&good, 99), Err(Error::NotLive)));
    assert!(matches!(ledger.apply(&good, 200), Err(Error::NotLive)));
    assert_eq!(ledger.status(owner(1)).unwrap().available_units, 100);
    assert!(ledger.operation([1; 32]).unwrap().is_none());
}

#[test]
fn durable_nonce_and_identifier_conflicts_do_not_change_balances() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger");
    let mut ledger = store(&path);
    let nonce = random_nonce();
    let original = signed_with_nonce(
        1,
        Action::Reserve {
            recipient: owner(2),
            units: 60,
        },
        nonce,
    );
    let receipt = ledger.apply(&original, 110).unwrap();
    drop(ledger);
    let mut ledger = Store::open(&path).unwrap();
    let changed = wire::mutate_and_resign(&original, &key(1), "amount");
    assert!(matches!(ledger.apply(&changed, 110), Err(Error::Conflict)));
    let reused = SignedCommand::sign(
        [9; 32],
        &key(1),
        Command {
            operation_id: [2; 32],
            payer: owner(1),
            action: Action::Reserve {
                recipient: owner(2),
                units: 1,
            },
        },
        100,
        200,
        nonce,
    )
    .unwrap();
    assert!(matches!(
        ledger.apply(&reused.encode(), 110),
        Err(Error::Replay)
    ));
    assert!(matches!(
        ledger.apply(&reserve(3, 41), 110),
        Err(Error::Insufficient)
    ));
    let stolen = SignedCommand::sign(
        [9; 32],
        &key(2),
        Command {
            operation_id: [4; 32],
            payer: owner(2),
            action: Action::Cancel {
                reservation_id: [1; 32],
            },
        },
        100,
        200,
        random_nonce(),
    )
    .unwrap();
    assert!(matches!(
        ledger.apply(&stolen.encode(), 110),
        Err(Error::Unauthorized)
    ));
    assert_eq!(ledger.operation([1; 32]).unwrap(), Some(receipt));
    assert_eq!(
        ledger.status(owner(1)).unwrap(),
        Balance {
            available_units: 40,
            reserved_units: 60
        }
    );
}

#[test]
fn exact_integer_supply_and_new_store_bounds_do_not_adopt_existing_data() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger");
    assert!(matches!(
        Store::create(
            &path,
            [9; 32],
            &[
                GenesisAccount {
                    owner: owner(1),
                    units: MAX_UNITS
                },
                GenesisAccount {
                    owner: owner(2),
                    units: 1
                }
            ]
        ),
        Err(Error::Capacity)
    ));
    assert!(!path.exists());
    let mut ledger = Store::create(
        &path,
        [9; 32],
        &[
            GenesisAccount {
                owner: owner(1),
                units: MAX_UNITS,
            },
            GenesisAccount {
                owner: owner(2),
                units: 0,
            },
        ],
    )
    .unwrap();
    ledger.apply(&reserve(1, MAX_UNITS), 110).unwrap();
    ledger
        .apply(
            &signed(
                2,
                Action::Commit {
                    reservation_id: [1; 32],
                },
            ),
            111,
        )
        .unwrap();
    assert_eq!(ledger.status(owner(2)).unwrap().available_units, MAX_UNITS);
    assert!(
        Store::create(
            &path,
            [8; 32],
            &[GenesisAccount {
                owner: owner(1),
                units: 1
            }]
        )
        .is_err()
    );
    assert!(
        SignedCommand::sign(
            [9; 32],
            &key(1),
            Command {
                operation_id: [1; 32],
                payer: owner(1),
                action: Action::Reserve {
                    recipient: owner(2),
                    units: MAX_UNITS + 1
                }
            },
            100,
            200,
            random_nonce()
        )
        .is_err()
    );
}

#[test]
fn private_modes_symlinks_and_corrupt_accounting_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger");
    drop(store(&path));
    let database = path.join("test-transactions.sqlite3");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Store::open(&path).is_err());
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = temp.path().join("alias");
    symlink(&path, &alias).unwrap();
    assert!(Store::open(&alias).is_err());
    let outside = temp.path().join("never-created");
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = path.join(format!("test-transactions.sqlite3{suffix}"));
        symlink(&outside, &sidecar).unwrap();
        assert!(Store::open(&path).is_err());
        assert!(!outside.exists());
        fs::remove_file(sidecar).unwrap();
    }
    let db = Connection::open(&database).unwrap();
    db.execute("UPDATE accounts SET available=101 WHERE available=100", [])
        .unwrap();
    drop(db);
    assert!(Store::open(&path).is_err());
}

#[test]
fn two_connections_serialize_conflicting_reservations_without_double_spend() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger");
    drop(store(&path));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut children = Vec::new();
    for id in [1, 2] {
        let mut ledger = Store::open(&path).unwrap();
        let barrier = barrier.clone();
        children.push(thread::spawn(move || {
            barrier.wait();
            ledger.apply(&reserve(id, 70), 110)
        }));
    }
    let results: Vec<_> = children
        .into_iter()
        .map(|child| child.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| matches!(e, Error::Busy | Error::Insufficient))
    );
    let ledger = Store::open(&path).unwrap();
    assert_eq!(
        ledger.status(owner(1)).unwrap(),
        Balance {
            available_units: 30,
            reserved_units: 70
        }
    );
}

#[test]
fn full_operation_budget_keeps_all_admitted_completions_and_expired_replays() {
    fn identifier(number: u64) -> OperationId {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&number.to_be_bytes());
        id
    }
    fn command(number: u64, action: Action) -> Vec<u8> {
        SignedCommand::sign(
            [9; 32],
            &key(1),
            Command {
                operation_id: identifier(number),
                payer: owner(1),
                action,
            },
            100,
            200,
            random_nonce(),
        )
        .unwrap()
        .encode()
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger");
    let capacity = MAX_OPERATIONS / 2;
    let mut ledger = Store::create(
        &path,
        [9; 32],
        &[
            GenesisAccount {
                owner: owner(1),
                units: capacity + 1,
            },
            GenesisAccount {
                owner: owner(2),
                units: 0,
            },
        ],
    )
    .unwrap();
    let reserve = |id| {
        command(
            id,
            Action::Reserve {
                recipient: owner(2),
                units: 1,
            },
        )
    };
    let first_bytes = reserve(1);
    ledger.apply(&first_bytes, 110).unwrap();
    for id in 2..=capacity {
        ledger.apply(&reserve(id), 110).unwrap();
    }
    assert!(matches!(
        ledger.apply(&reserve(capacity + 1), 110),
        Err(Error::Capacity)
    ));
    drop(ledger);
    let mut ledger = Store::open(&path).unwrap();
    for id in 1..=capacity {
        let action = if id % 2 == 0 {
            Action::Commit {
                reservation_id: identifier(id),
            }
        } else {
            Action::Cancel {
                reservation_id: identifier(id),
            }
        };
        ledger.apply(&command(capacity + id, action), 120).unwrap();
    }
    drop(ledger);
    let mut ledger = Store::open(&path).unwrap();
    assert_eq!(
        ledger.status(owner(1)).unwrap(),
        Balance {
            available_units: capacity / 2 + 1,
            reserved_units: 0
        }
    );
    assert_eq!(
        ledger.status(owner(2)).unwrap(),
        Balance {
            available_units: capacity / 2,
            reserved_units: 0
        }
    );
    assert_eq!(ledger.apply(&first_bytes, 300).unwrap().sequence, 1);
    assert_eq!(
        ledger
            .operation(identifier(MAX_OPERATIONS))
            .unwrap()
            .unwrap()
            .sequence,
        MAX_OPERATIONS
    );
    assert!(matches!(
        ledger.apply(&reserve(MAX_OPERATIONS + 1), 110),
        Err(Error::Capacity)
    ));
}

// Same real apply transaction as production, with a test-only precommit checkpoint.
// No test hook is exported by the public library/API.
#[test]
#[ignore = "invoked only by the owned crash regression child"]
fn crash_child() {
    let Some(path) = std::env::var_os("VOLPAROSSA_TEST_TRANSACTION_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(path);
    let mut ledger = Store::open(&root).unwrap();
    let phase = std::env::var("VOLPAROSSA_TEST_TRANSACTION_CRASH_PHASE").unwrap();
    let mut original = Vec::new();
    File::open(root.join("original-command.pb"))
        .unwrap()
        .take(4097)
        .read_to_end(&mut original)
        .unwrap();
    assert!(!original.is_empty() && original.len() <= 4096);
    if phase == "before" {
        ledger
            .apply_inner(&original, 110, || {
                fs::write(root.join("ready"), b"before").unwrap();
                thread::sleep(Duration::from_secs(30));
            })
            .unwrap();
    } else {
        ledger.apply(&original, 110).unwrap();
        fs::write(root.join("ready"), b"after").unwrap();
        thread::sleep(Duration::from_secs(30));
    }
}

#[test]
fn killed_process_before_and_after_commit_reopens_without_partial_debit_or_duplicate() {
    for phase in ["before", "after"] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ledger");
        drop(store(&path));
        let original = reserve(1, 70);
        let mut command_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("original-command.pb"))
            .unwrap();
        command_file.write_all(&original).unwrap();
        command_file.sync_all().unwrap();
        drop(command_file);
        let mut child = Process::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::crash_child", "--ignored", "--nocapture"])
            .env("VOLPAROSSA_TEST_TRANSACTION_CRASH_ROOT", &path)
            .env("VOLPAROSSA_TEST_TRANSACTION_CRASH_PHASE", phase)
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
        let ready = path.join("ready").exists();
        child.kill().ok();
        child.wait().unwrap();
        assert!(ready, "child reached exact transaction checkpoint");
        let mut ledger = Store::open(&path).unwrap();
        assert_eq!(
            ledger.operation([1; 32]).unwrap().is_some(),
            phase == "after"
        );
        let expected = if phase == "before" {
            Balance {
                available_units: 100,
                reserved_units: 0,
            }
        } else {
            Balance {
                available_units: 30,
                reserved_units: 70,
            }
        };
        assert_eq!(ledger.status(owner(1)).unwrap(), expected);
        assert_eq!(
            fs::read(path.join("original-command.pb")).unwrap(),
            original
        );
        let accepted = ledger.apply(&original, 110).unwrap();
        assert_eq!(accepted.sequence, 1);
        assert_eq!(ledger.apply(&original, 300).unwrap(), accepted);
        assert_eq!(
            ledger.status(owner(1)).unwrap(),
            Balance {
                available_units: 30,
                reserved_units: 70
            }
        );
    }
}
