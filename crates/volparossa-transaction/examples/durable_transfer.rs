//! Offline test-unit transfer through the real signed, durable core API.
//! No daemon, network, financial account, real asset or persisted private key.

use std::{error::Error, path::PathBuf};

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use volparossa_transaction::{
    Action, Balance, Command, Error as TransactionError, GenesisAccount, LedgerId,
    ReservationState, SignedCommand, Store, TEST_UNIT,
};

fn random_id() -> [u8; 32] {
    std::array::from_fn(|_| OsRng.next_u32().to_le_bytes()[0])
}

fn signed(
    ledger_id: LedgerId,
    key: &SigningKey,
    action: Action,
    now: u64,
) -> Result<(Command, Vec<u8>), TransactionError> {
    let command = Command {
        operation_id: random_id(),
        payer: key.verifying_key().to_bytes(),
        action,
    };
    // Explicit fixture clock, not an assertion about real-world settlement time.
    let bytes = SignedCommand::sign(ledger_id, key, command, now, now + 100, random_id())?.encode();
    Ok((command, bytes))
}

fn balances(store: &Store, payer: [u8; 32], recipient: [u8; 32]) -> Result<(), TransactionError> {
    assert_eq!(
        store.status(payer)?,
        Balance {
            available_units: 30,
            reserved_units: 0
        }
    );
    assert_eq!(
        store.status(recipient)?,
        Balance {
            available_units: 70,
            reserved_units: 0
        }
    );
    Ok(())
}

// Keep this short sequential demonstration in the same order as the transcript.
#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(
        args.next()
            .ok_or("usage: durable_transfer NEW_ABSOLUTE_STORE_DIR")?,
    );
    if args.next().is_some() || !path.is_absolute() {
        return Err("provide exactly one new absolute store directory".into());
    }
    let payer = SigningKey::generate(&mut OsRng);
    let recipient = SigningKey::generate(&mut OsRng);
    let payer_id = payer.verifying_key().to_bytes();
    let recipient_id = recipient.verifying_key().to_bytes();
    let ledger_id = random_id();
    // create refuses an existing directory; this example never adopts a store.
    let mut store = Store::create(
        &path,
        ledger_id,
        &[
            GenesisAccount {
                owner: payer_id,
                units: 100,
            },
            GenesisAccount {
                owner: recipient_id,
                units: 0,
            },
        ],
    )?;
    let (reserve, reserve_bytes) = signed(
        ledger_id,
        &payer,
        Action::Reserve {
            recipient: recipient_id,
            units: 70,
        },
        100,
    )?;
    let original = store.apply(&reserve_bytes, 101)?;
    assert_eq!(original.state, ReservationState::Reserved);
    assert_eq!(
        store.status(payer_id)?,
        Balance {
            available_units: 30,
            reserved_units: 70
        }
    );
    drop(store);

    let mut store = Store::open(&path)?;
    // An expired *accepted* request only retrieves its identical old receipt.
    assert_eq!(store.apply(&reserve_bytes, 201)?, original);
    assert_eq!(
        store.status(payer_id)?,
        Balance {
            available_units: 30,
            reserved_units: 70
        }
    );
    let (_, commit_bytes) = signed(
        ledger_id,
        &payer,
        Action::Commit {
            reservation_id: reserve.operation_id,
        },
        201,
    )?;
    let committed = store.apply(&commit_bytes, 202)?;
    assert_eq!(committed.state, ReservationState::Committed);
    drop(store);

    let mut store = Store::open(&path)?;
    assert_eq!(store.apply(&commit_bytes, 302)?, committed);
    // The old reserve receipt stays historical; it is not a current status reply.
    assert_eq!(store.apply(&reserve_bytes, 302)?, original);
    let (_, invalid_cancel) = signed(
        ledger_id,
        &payer,
        Action::Cancel {
            reservation_id: reserve.operation_id,
        },
        303,
    )?;
    assert!(matches!(
        store.apply(&invalid_cancel, 303),
        Err(TransactionError::State)
    ));

    let (second, second_bytes) = signed(
        ledger_id,
        &payer,
        Action::Reserve {
            recipient: recipient_id,
            units: 10,
        },
        304,
    )?;
    store.apply(&second_bytes, 304)?;
    let (_, cancel_bytes) = signed(
        ledger_id,
        &payer,
        Action::Cancel {
            reservation_id: second.operation_id,
        },
        305,
    )?;
    let cancelled = store.apply(&cancel_bytes, 305)?;
    assert_eq!(cancelled.state, ReservationState::Cancelled);
    assert_eq!(store.apply(&cancel_bytes, 406)?, cancelled);
    balances(&store, payer_id, recipient_id)?;

    println!("PASS: signed reserve/commit/cancel, reopen and exact replay; unit={TEST_UNIT}");
    println!("Payer: 30 available, 0 reserved; recipient: 70 available, 0 reserved.");
    println!("Only fictitious value. No distributed settlement or real payment occurred.");
    println!(
        "Private test store retained at {}; ephemeral test keys were not saved.",
        path.display()
    );
    Ok(())
}
