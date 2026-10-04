// SPDX-License-Identifier: GPL-3.0-only
use volparossa_transaction_simulation::*;

const A: SimulationAccount = SimulationAccount(1);
const B: SimulationAccount = SimulationAccount(2);
const C: SimulationAccount = SimulationAccount(3);
const D: SimulationAccount = SimulationAccount(4);

fn id(value: u64) -> SimulationOperationId {
    SimulationOperationId(value)
}
fn transfer(from: SimulationAccount, to: SimulationAccount, units: u64) -> SimulationTransfer {
    SimulationTransfer {
        from,
        to: SimulationDestination::Account(to),
        units,
    }
}
fn ledger(units: u64) -> SimulationLedger {
    SimulationLedger::new(&[(A, units), (B, 0), (C, 0), (D, 0)]).unwrap()
}
fn committed(
    ledger: &mut SimulationLedger,
    operation: u64,
    from: SimulationAccount,
    to: SimulationAccount,
    units: u64,
) {
    ledger
        .authorise(
            id(operation),
            transfer(from, to, units),
            SimulationAuthority::Debit(from),
        )
        .unwrap();
    assert!(ledger.conservation_holds());
    ledger.reserve(id(operation)).unwrap();
    assert!(ledger.conservation_holds());
    ledger.commit(id(operation)).unwrap();
    assert!(ledger.conservation_holds());
}

#[test]
fn internal_commit_and_compensation_append_without_rewriting_original() {
    let mut ledger = ledger(100);
    committed(&mut ledger, 1, A, B, 70);
    let original = ledger.events().to_vec();
    assert_eq!((ledger.available(A), ledger.available(B)), (Ok(30), Ok(70)));
    let correction = ledger
        .correct(id(2), id(1), SimulationAuthority::Correct(id(1)))
        .unwrap();
    assert_eq!(
        correction,
        SimulationCorrection {
            recovered_units: 70,
            shortfall_units: 0,
            outcome: SimulationRecovery::FullyCompensated
        }
    );
    assert_eq!(ledger.events()[..original.len()], original);
    assert_eq!(ledger.events().len(), original.len() + 1);
    assert_eq!(
        ledger.transfer(id(1)).unwrap().1,
        SimulationState::Committed
    );
    assert_eq!((ledger.available(A), ledger.available(B)), (Ok(100), Ok(0)));
    assert!(ledger.conservation_holds());
}

#[test]
fn matching_ids_are_idempotent_and_conflicting_ids_never_debit_again() {
    let mut ledger = ledger(100);
    let details = transfer(A, B, 60);
    committed(&mut ledger, 1, A, B, 60);
    let before = ledger.clone();
    assert_eq!(
        ledger.authorise(id(1), details, SimulationAuthority::Debit(A)),
        Ok(SimulationState::Committed)
    );
    assert_eq!(ledger.reserve(id(1)), Ok(SimulationState::Committed));
    assert_eq!(ledger.commit(id(1)), Ok(()));
    assert_eq!(ledger, before);
    assert_eq!(
        ledger.authorise(id(1), transfer(A, B, 61), SimulationAuthority::Debit(A)),
        Err(SimulationError::OperationIdConflict)
    );
    assert_eq!(
        ledger.correct(id(1), id(1), SimulationAuthority::Correct(id(1))),
        Err(SimulationError::OperationIdConflict)
    );
    assert_eq!(ledger, before);
}

#[test]
fn scoped_authority_ordering_and_overdraw_refuse_without_mutation() {
    let mut ledger = ledger(10);
    let before = ledger.clone();
    assert_eq!(
        ledger.authorise(id(1), transfer(A, B, 11), SimulationAuthority::Debit(B)),
        Err(SimulationError::AuthorityMismatch)
    );
    assert_eq!(ledger, before);
    ledger
        .authorise(id(1), transfer(A, B, 11), SimulationAuthority::Debit(A))
        .unwrap();
    let before = ledger.clone();
    assert_eq!(
        ledger.reserve(id(1)),
        Err(SimulationError::InsufficientAvailableUnits)
    );
    assert_eq!(ledger.commit(id(1)), Err(SimulationError::InvalidState));
    assert_eq!(
        ledger.observe_external_final(id(1), SimulationAuthority::ObserveExternal(id(1))),
        Err(SimulationError::InvalidState)
    );
    assert_eq!(
        ledger.correct(id(2), id(1), SimulationAuthority::Correct(id(3))),
        Err(SimulationError::AuthorityMismatch)
    );
    assert_eq!(ledger, before);
    assert!(ledger.conservation_holds());
}

#[test]
fn unknown_outbound_keeps_reservation_no_implicit_retry_or_fake_recovery() {
    let mut ledger = ledger(100);
    let details = SimulationTransfer {
        from: A,
        to: SimulationDestination::External(9),
        units: 80,
    };
    ledger
        .authorise(id(1), details, SimulationAuthority::Debit(A))
        .unwrap();
    ledger.reserve(id(1)).unwrap();
    assert_eq!(ledger.commit(id(1)), Err(SimulationError::InvalidState));
    assert_eq!(
        ledger.submit_outbound(id(1)),
        Ok(SimulationSubmission::FirstRecorded)
    );
    ledger.outbound_unknown(id(1)).unwrap();
    let before = ledger.clone();
    ledger.outbound_unknown(id(1)).unwrap();
    assert_eq!(
        ledger.submit_outbound(id(1)),
        Ok(SimulationSubmission::AlreadyRecordedDoNotRetry)
    );
    assert_eq!(
        ledger.correct(id(2), id(1), SimulationAuthority::Correct(id(1))),
        Err(SimulationError::ExternalOutcomeUncertain)
    );
    assert_eq!(
        ledger.observe_external_final(id(1), SimulationAuthority::ObserveExternal(id(3))),
        Err(SimulationError::AuthorityMismatch)
    );
    assert_eq!(ledger, before);
    assert_eq!(ledger.available(A), Ok(20));
    assert!(ledger.conservation_holds());
    ledger
        .observe_external_final(id(1), SimulationAuthority::ObserveExternal(id(1)))
        .unwrap();
    let finalized = ledger.clone();
    ledger
        .observe_external_final(id(1), SimulationAuthority::ObserveExternal(id(1)))
        .unwrap();
    assert_eq!(
        ledger.outbound_unknown(id(1)),
        Err(SimulationError::InvalidState)
    );
    assert_eq!(
        ledger.submit_outbound(id(1)),
        Ok(SimulationSubmission::AlreadyRecordedDoNotRetry)
    );
    assert_eq!(ledger, finalized);
    let correction = ledger
        .correct(id(2), id(1), SimulationAuthority::Correct(id(1)))
        .unwrap();
    assert_eq!(
        correction,
        SimulationCorrection {
            recovered_units: 0,
            shortfall_units: 80,
            outcome: SimulationRecovery::ExternalFinalNotRecoverable
        }
    );
    assert_eq!(ledger.available(A), Ok(20));
    assert!(ledger.conservation_holds());
}

#[test]
fn forwarding_and_splitting_expose_shortfall_without_seizing_downstream_units() {
    let mut ledger = ledger(100);
    committed(&mut ledger, 1, A, B, 100);
    committed(&mut ledger, 2, B, C, 60);
    committed(&mut ledger, 3, B, D, 20);
    let result = ledger
        .correct(id(4), id(1), SimulationAuthority::Correct(id(1)))
        .unwrap();
    assert_eq!(
        result,
        SimulationCorrection {
            recovered_units: 20,
            shortfall_units: 80,
            outcome: SimulationRecovery::RecipientShortfall
        }
    );
    assert_eq!(
        (
            ledger.available(A),
            ledger.available(B),
            ledger.available(C),
            ledger.available(D)
        ),
        (Ok(20), Ok(0), Ok(60), Ok(20))
    );
    // Later incoming units must not be silently debited by a repeated correction.
    committed(&mut ledger, 5, C, B, 10);
    let before = ledger.clone();
    assert_eq!(
        ledger.correct(id(4), id(1), SimulationAuthority::Correct(id(1))),
        Ok(result)
    );
    assert_eq!(
        ledger.correct(id(6), id(1), SimulationAuthority::Correct(id(1))),
        Err(SimulationError::AlreadyCorrected)
    );
    assert_eq!(
        ledger.authorise(id(4), transfer(B, A, 10), SimulationAuthority::Debit(B)),
        Err(SimulationError::OperationIdConflict)
    );
    assert_eq!(ledger, before);
    assert!(ledger.conservation_holds());
}

#[test]
fn correction_cannot_spend_another_operations_reserved_units() {
    let mut ledger = ledger(100);
    committed(&mut ledger, 1, A, B, 100);
    ledger
        .authorise(id(2), transfer(B, C, 80), SimulationAuthority::Debit(B))
        .unwrap();
    ledger.reserve(id(2)).unwrap();
    let correction = ledger
        .correct(id(3), id(1), SimulationAuthority::Correct(id(1)))
        .unwrap();
    assert_eq!(
        (correction.recovered_units, correction.shortfall_units),
        (20, 80)
    );
    ledger.commit(id(2)).unwrap();
    assert_eq!(
        (
            ledger.available(A),
            ledger.available(B),
            ledger.available(C)
        ),
        (Ok(20), Ok(0), Ok(80))
    );
    assert!(ledger.conservation_holds());
}

#[test]
fn checked_integer_genesis_and_exact_maximum_supply_do_not_wrap_or_mint() {
    assert_eq!(
        SimulationLedger::new(&[(A, u64::MAX), (B, 1)]),
        Err(SimulationError::ArithmeticOverflow)
    );
    assert_eq!(
        SimulationLedger::new(&[(A, 1), (A, 2)]),
        Err(SimulationError::DuplicateAccount)
    );
    assert_eq!(
        SimulationLedger::new(&[]),
        Err(SimulationError::BoundExceeded)
    );
    let mut ledger = ledger(u64::MAX);
    let before = ledger.clone();
    for invalid in [transfer(A, B, 0), transfer(A, A, 1)] {
        assert_eq!(
            ledger.authorise(id(1), invalid, SimulationAuthority::Debit(A)),
            Err(SimulationError::InvalidTransfer)
        );
    }
    assert_eq!(
        ledger.authorise(
            id(1),
            transfer(A, SimulationAccount(99), 1),
            SimulationAuthority::Debit(A)
        ),
        Err(SimulationError::UnknownAccount)
    );
    assert_eq!(ledger, before);
    committed(&mut ledger, 1, A, B, u64::MAX);
    ledger
        .correct(id(2), id(1), SimulationAuthority::Correct(id(1)))
        .unwrap();
    assert_eq!(ledger.available(A), Ok(u64::MAX));
    assert!(ledger.conservation_holds());
}

#[test]
fn small_balance_exhaustion_preserves_conservation_on_every_transition() {
    for initial in 0..=12 {
        for amount in 1..=14 {
            let mut ledger = ledger(initial);
            ledger
                .authorise(id(1), transfer(A, B, amount), SimulationAuthority::Debit(A))
                .unwrap();
            let before = ledger.clone();
            if amount > initial {
                assert_eq!(
                    ledger.reserve(id(1)),
                    Err(SimulationError::InsufficientAvailableUnits)
                );
                assert_eq!(ledger, before);
            } else {
                ledger.reserve(id(1)).unwrap();
                assert!(ledger.conservation_holds());
                ledger.commit(id(1)).unwrap();
                assert!(ledger.conservation_holds());
                ledger
                    .correct(id(2), id(1), SimulationAuthority::Correct(id(1)))
                    .unwrap();
                assert_eq!(ledger.available(A), Ok(initial));
            }
            assert!(ledger.conservation_holds());
        }
    }
}

#[test]
fn operation_and_journal_bounds_refuse_atomically() {
    let mut ledger = ledger(300);
    for operation in 0..MAX_OPERATIONS as u64 {
        ledger
            .authorise(
                id(operation),
                transfer(A, B, 1),
                SimulationAuthority::Debit(A),
            )
            .unwrap();
    }
    let before = ledger.clone();
    assert_eq!(
        ledger.authorise(id(999), transfer(A, B, 1), SimulationAuthority::Debit(A)),
        Err(SimulationError::BoundExceeded)
    );
    assert_eq!(ledger, before);
    let mut ledger = SimulationLedger::new(&[(A, 300)]).unwrap();
    for operation in 0..204 {
        let details = SimulationTransfer {
            from: A,
            to: SimulationDestination::External(9),
            units: 1,
        };
        ledger
            .authorise(id(operation), details, SimulationAuthority::Debit(A))
            .unwrap();
        ledger.reserve(id(operation)).unwrap();
        ledger.submit_outbound(id(operation)).unwrap();
        ledger.outbound_unknown(id(operation)).unwrap();
        ledger
            .observe_external_final(
                id(operation),
                SimulationAuthority::ObserveExternal(id(operation)),
            )
            .unwrap();
    }
    let details = SimulationTransfer {
        from: A,
        to: SimulationDestination::External(9),
        units: 1,
    };
    ledger
        .authorise(id(204), details, SimulationAuthority::Debit(A))
        .unwrap();
    ledger.reserve(id(204)).unwrap();
    ledger.submit_outbound(id(204)).unwrap();
    ledger.outbound_unknown(id(204)).unwrap();
    assert_eq!(ledger.events().len(), MAX_EVENTS);
    let before = ledger.clone();
    assert_eq!(
        ledger.observe_external_final(id(204), SimulationAuthority::ObserveExternal(id(204))),
        Err(SimulationError::BoundExceeded)
    );
    assert_eq!(ledger, before);
    assert!(ledger.conservation_holds());
}
