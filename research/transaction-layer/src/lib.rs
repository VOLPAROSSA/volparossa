// SPDX-License-Identifier: GPL-3.0-only
//! RESEARCH ONLY. These integer units are not money, securities, or legal rights.
//!
//! There is no persistence, consensus, signature, transport, gateway, key, daemon
//! integration or actual settlement. Authority is explicit TEST INPUT, not proof
//! of permission. The scoped-rights pattern follows the core's private-storage
//! grants; no grant, cryptography, or product permission is reused or invented.
//! Every successful mutation appends an event. Failed mutations leave the state
//! unchanged. A process crash loses this entire simulation, including its IDs;
//! production-grade durable idempotency is therefore NOT demonstrated.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

pub const MAX_ACCOUNTS: usize = 64;
pub const MAX_OPERATIONS: usize = 256;
pub const MAX_EVENTS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SimulationAccount(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SimulationOperationId(pub u64);

/// Deliberately constructible simulation input, NEVER authentication evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationAuthority {
    Debit(SimulationAccount),
    Correct(SimulationOperationId),
    ObserveExternal(SimulationOperationId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationDestination {
    Account(SimulationAccount),
    /// Opaque test label, not an address or executable gateway instruction.
    External(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimulationTransfer {
    pub from: SimulationAccount,
    pub to: SimulationDestination,
    pub units: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationState {
    Authorised,
    Reserved,
    Committed,
    OutboundSubmitted,
    OutboundUnknownPending,
    OutboundFinal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationSubmission {
    /// The first in-memory recording only: no external send has occurred.
    FirstRecorded,
    /// Not permission to send again, even when the remote outcome is unknown.
    AlreadyRecordedDoNotRetry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationRecovery {
    FullyCompensated,
    /// Only the original recipient's AVAILABLE units were recoverable. No
    /// downstream tracing, legal claim enforcement or later collection exists.
    RecipientShortfall,
    /// An accounting finding, not a recall or recovery of external funds.
    ExternalFinalNotRecoverable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimulationCorrection {
    pub recovered_units: u64,
    pub shortfall_units: u64,
    pub outcome: SimulationRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationEvent {
    Authorised(SimulationOperationId, SimulationTransfer),
    Reserved(SimulationOperationId),
    Committed(SimulationOperationId),
    OutboundSubmitted(SimulationOperationId),
    OutboundUnknownPending(SimulationOperationId),
    OutboundFinal(SimulationOperationId),
    CompensatingCorrection {
        id: SimulationOperationId,
        original: SimulationOperationId,
        result: SimulationCorrection,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationError {
    BoundExceeded,
    ArithmeticOverflow,
    DuplicateAccount,
    UnknownAccount,
    InvalidTransfer,
    AuthorityMismatch,
    OperationIdConflict,
    UnknownTransfer,
    InvalidState,
    InsufficientAvailableUnits,
    AlreadyCorrected,
    ExternalOutcomeUncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Transfer(SimulationTransfer, SimulationState),
    Correction(SimulationOperationId, SimulationCorrection),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationLedger {
    available: BTreeMap<SimulationAccount, u64>,
    operations: BTreeMap<SimulationOperationId, Operation>,
    events: Vec<SimulationEvent>,
    genesis_units: u64,
    external_final_units: u64,
}

impl SimulationLedger {
    /// The only supply allocation. There is no subsequent mint, deposit,
    /// overdraft, fee, interest, rounding or external-funding operation.
    pub fn new(accounts: &[(SimulationAccount, u64)]) -> Result<Self, SimulationError> {
        if accounts.is_empty() || accounts.len() > MAX_ACCOUNTS {
            return Err(SimulationError::BoundExceeded);
        }
        let mut available = BTreeMap::new();
        let mut genesis_units = 0_u64;
        for &(account, units) in accounts {
            if available.insert(account, units).is_some() {
                return Err(SimulationError::DuplicateAccount);
            }
            genesis_units = genesis_units
                .checked_add(units)
                .ok_or(SimulationError::ArithmeticOverflow)?;
        }
        Ok(Self {
            available,
            operations: BTreeMap::new(),
            events: Vec::new(),
            genesis_units,
            external_final_units: 0,
        })
    }

    pub fn available(&self, account: SimulationAccount) -> Result<u64, SimulationError> {
        self.available
            .get(&account)
            .copied()
            .ok_or(SimulationError::UnknownAccount)
    }

    pub fn events(&self) -> &[SimulationEvent] {
        &self.events
    }

    pub fn transfer(
        &self,
        id: SimulationOperationId,
    ) -> Result<(SimulationTransfer, SimulationState), SimulationError> {
        match self.operations.get(&id) {
            Some(Operation::Transfer(transfer, state)) => Ok((*transfer, *state)),
            _ => Err(SimulationError::UnknownTransfer),
        }
    }

    pub fn authorise(
        &mut self,
        id: SimulationOperationId,
        transfer: SimulationTransfer,
        authority: SimulationAuthority,
    ) -> Result<SimulationState, SimulationError> {
        if authority != SimulationAuthority::Debit(transfer.from) {
            return Err(SimulationError::AuthorityMismatch);
        }
        if let Some(previous) = self.operations.get(&id) {
            return match previous {
                Operation::Transfer(details, state) if *details == transfer => Ok(*state),
                _ => Err(SimulationError::OperationIdConflict),
            };
        }
        self.available(transfer.from)?;
        if transfer.units == 0 || transfer.to == SimulationDestination::Account(transfer.from) {
            return Err(SimulationError::InvalidTransfer);
        }
        if let SimulationDestination::Account(recipient) = transfer.to {
            self.available(recipient)?;
        }
        self.admit_new()?;
        self.operations.insert(
            id,
            Operation::Transfer(transfer, SimulationState::Authorised),
        );
        self.events.push(SimulationEvent::Authorised(id, transfer));
        Ok(SimulationState::Authorised)
    }

    pub fn reserve(
        &mut self,
        id: SimulationOperationId,
    ) -> Result<SimulationState, SimulationError> {
        let (transfer, state) = self.transfer(id)?;
        if state != SimulationState::Authorised {
            // This exact operation has already reserved once, possibly advanced.
            return Ok(state);
        }
        let available = self
            .available(transfer.from)?
            .checked_sub(transfer.units)
            .ok_or(SimulationError::InsufficientAvailableUnits)?;
        self.admit_event()?;
        self.available.insert(transfer.from, available);
        self.advance(
            id,
            transfer,
            SimulationState::Reserved,
            SimulationEvent::Reserved(id),
        );
        Ok(SimulationState::Reserved)
    }

    pub fn commit(&mut self, id: SimulationOperationId) -> Result<(), SimulationError> {
        let (transfer, state) = self.transfer(id)?;
        let SimulationDestination::Account(recipient) = transfer.to else {
            return Err(SimulationError::InvalidState);
        };
        if state == SimulationState::Committed {
            return Ok(());
        }
        if state != SimulationState::Reserved {
            return Err(SimulationError::InvalidState);
        }
        let available = self
            .available(recipient)?
            .checked_add(transfer.units)
            .ok_or(SimulationError::ArithmeticOverflow)?;
        self.admit_event()?;
        self.available.insert(recipient, available);
        self.advance(
            id,
            transfer,
            SimulationState::Committed,
            SimulationEvent::Committed(id),
        );
        Ok(())
    }

    pub fn submit_outbound(
        &mut self,
        id: SimulationOperationId,
    ) -> Result<SimulationSubmission, SimulationError> {
        let (transfer, state) = self.transfer(id)?;
        if !matches!(transfer.to, SimulationDestination::External(_)) {
            return Err(SimulationError::InvalidState);
        }
        match state {
            SimulationState::OutboundSubmitted
            | SimulationState::OutboundUnknownPending
            | SimulationState::OutboundFinal => {
                return Ok(SimulationSubmission::AlreadyRecordedDoNotRetry);
            }
            SimulationState::Reserved => (),
            _ => return Err(SimulationError::InvalidState),
        }
        self.admit_event()?;
        self.advance(
            id,
            transfer,
            SimulationState::OutboundSubmitted,
            SimulationEvent::OutboundSubmitted(id),
        );
        Ok(SimulationSubmission::FirstRecorded)
    }

    /// A timeout says nothing about external success. Keep the reservation.
    pub fn outbound_unknown(&mut self, id: SimulationOperationId) -> Result<(), SimulationError> {
        let (transfer, state) = self.transfer(id)?;
        if state == SimulationState::OutboundUnknownPending {
            return Ok(());
        }
        if state != SimulationState::OutboundSubmitted {
            return Err(SimulationError::InvalidState);
        }
        self.admit_event()?;
        self.advance(
            id,
            transfer,
            SimulationState::OutboundUnknownPending,
            SimulationEvent::OutboundUnknownPending(id),
        );
        Ok(())
    }

    /// An explicitly scoped TEST observation, not externally verified settlement.
    pub fn observe_external_final(
        &mut self,
        id: SimulationOperationId,
        authority: SimulationAuthority,
    ) -> Result<(), SimulationError> {
        if authority != SimulationAuthority::ObserveExternal(id) {
            return Err(SimulationError::AuthorityMismatch);
        }
        let (transfer, state) = self.transfer(id)?;
        if state == SimulationState::OutboundFinal {
            return Ok(());
        }
        if !matches!(
            state,
            SimulationState::OutboundSubmitted | SimulationState::OutboundUnknownPending
        ) {
            return Err(SimulationError::InvalidState);
        }
        let total = self
            .external_final_units
            .checked_add(transfer.units)
            .ok_or(SimulationError::ArithmeticOverflow)?;
        self.admit_event()?;
        self.external_final_units = total;
        self.advance(
            id,
            transfer,
            SimulationState::OutboundFinal,
            SimulationEvent::OutboundFinal(id),
        );
        Ok(())
    }

    /// One scoped correction per original committed transfer. The original
    /// event/state is retained, never rewritten. This simulation does not trace
    /// downstream payments or create transferable/enforceable recovery claims.
    pub fn correct(
        &mut self,
        id: SimulationOperationId,
        original: SimulationOperationId,
        authority: SimulationAuthority,
    ) -> Result<SimulationCorrection, SimulationError> {
        if authority != SimulationAuthority::Correct(original) {
            return Err(SimulationError::AuthorityMismatch);
        }
        if let Some(previous) = self.operations.get(&id) {
            return match previous {
                Operation::Correction(previous, result) if *previous == original => Ok(*result),
                _ => Err(SimulationError::OperationIdConflict),
            };
        }
        if self
            .operations
            .values()
            .any(|op| matches!(op, Operation::Correction(old, _) if *old == original))
        {
            return Err(SimulationError::AlreadyCorrected);
        }
        let (transfer, state) = self.transfer(original)?;
        let (result, changes) = match (transfer.to, state) {
            (SimulationDestination::Account(recipient), SimulationState::Committed) => {
                let available = self.available(recipient)?;
                let recovered = available.min(transfer.units);
                let recipient_after = available
                    .checked_sub(recovered)
                    .ok_or(SimulationError::ArithmeticOverflow)?;
                let sender_after = self
                    .available(transfer.from)?
                    .checked_add(recovered)
                    .ok_or(SimulationError::ArithmeticOverflow)?;
                let shortfall = transfer
                    .units
                    .checked_sub(recovered)
                    .ok_or(SimulationError::ArithmeticOverflow)?;
                (
                    SimulationCorrection {
                        recovered_units: recovered,
                        shortfall_units: shortfall,
                        outcome: if shortfall == 0 {
                            SimulationRecovery::FullyCompensated
                        } else {
                            SimulationRecovery::RecipientShortfall
                        },
                    },
                    Some((recipient, recipient_after, sender_after)),
                )
            }
            (SimulationDestination::External(_), SimulationState::OutboundFinal) => (
                SimulationCorrection {
                    recovered_units: 0,
                    shortfall_units: transfer.units,
                    outcome: SimulationRecovery::ExternalFinalNotRecoverable,
                },
                None,
            ),
            (_, SimulationState::OutboundSubmitted | SimulationState::OutboundUnknownPending) => {
                return Err(SimulationError::ExternalOutcomeUncertain);
            }
            _ => return Err(SimulationError::InvalidState),
        };
        self.admit_new()?;
        if let Some((recipient, recipient_after, sender_after)) = changes {
            self.available.insert(recipient, recipient_after);
            self.available.insert(transfer.from, sender_after);
        }
        self.operations
            .insert(id, Operation::Correction(original, result));
        self.events.push(SimulationEvent::CompensatingCorrection {
            id,
            original,
            result,
        });
        Ok(result)
    }

    /// Available + reserved/uncertain + externally final = immutable genesis.
    /// External units are a separate accounting sink, not locally spendable.
    pub fn conservation_holds(&self) -> bool {
        let reserved = self.operations.values().filter_map(|op| match op {
            Operation::Transfer(
                transfer,
                SimulationState::Reserved
                | SimulationState::OutboundSubmitted
                | SimulationState::OutboundUnknownPending,
            ) => Some(transfer.units),
            _ => None,
        });
        self.available
            .values()
            .copied()
            .chain(reserved)
            .chain([self.external_final_units])
            .try_fold(0_u64, u64::checked_add)
            == Some(self.genesis_units)
    }

    fn admit_event(&self) -> Result<(), SimulationError> {
        if self.events.len() >= MAX_EVENTS {
            Err(SimulationError::BoundExceeded)
        } else {
            Ok(())
        }
    }

    fn admit_new(&self) -> Result<(), SimulationError> {
        self.admit_event()?;
        if self.operations.len() >= MAX_OPERATIONS {
            Err(SimulationError::BoundExceeded)
        } else {
            Ok(())
        }
    }

    fn advance(
        &mut self,
        id: SimulationOperationId,
        transfer: SimulationTransfer,
        state: SimulationState,
        event: SimulationEvent,
    ) {
        self.operations
            .insert(id, Operation::Transfer(transfer, state));
        self.events.push(event);
    }
}
