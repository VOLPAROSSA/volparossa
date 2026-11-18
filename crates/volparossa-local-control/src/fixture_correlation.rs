//! Explicit development-fixture correlation, private to the protected local socket.

use prost::Message;
use serde::{Deserialize, Serialize};

use crate::ControlProtocolError;

/// Maximum exact fingerprints in one provider lookup.
pub const MAX_FIXTURE_FINGERPRINTS: usize = 8;
/// Maximum records in one private response.
pub const MAX_FIXTURE_RECORDS: usize = 64;
/// Maximum encoded correlation message, within the unchanged outer frame limit.
pub const MAX_FIXTURE_MESSAGE: usize = 8 * 1024;

/// Explicit local action; never a remote or production tracing capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum StorageFixtureCorrelationAction {
    /// Reserved and rejected.
    Unspecified = 0,
    /// Arm one caller-owned fixture epoch.
    Arm = 1,
    /// Read that epoch's client records.
    Clients = 2,
    /// Look up only the specified provider-side fingerprints.
    Providers = 3,
    /// Clear and disarm that caller-owned epoch.
    Disarm = 4,
}

/// Availability and lifecycle of a private fixture observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum StorageFixtureCorrelationState {
    /// Reserved and rejected.
    Unspecified = 0,
    /// The requested epoch was armed, not an operation success.
    Armed = 1,
    /// A bounded snapshot, possibly incomplete.
    Observed = 2,
    /// The requested epoch was cleared.
    Disarmed = 3,
    /// No trustworthy snapshot; never interpreted as zero sessions.
    Unavailable = 4,
}

/// Side of the existing application TLS connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum StorageFixtureCorrelationRole {
    /// Reserved and rejected.
    Unspecified = 0,
    /// Outgoing private-storage exchange.
    Client = 1,
    /// Incoming content-provider exchange.
    Provider = 2,
}

/// Finite existing boundary, without addresses, payloads or request identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum StorageFixtureCorrelationPhase {
    /// Reserved and rejected.
    Unspecified = 0,
    /// Client flow preparation or acquisition.
    FlowAcquire = 1,
    /// Application TLS handshake.
    TlsHandshake = 2,
    /// Provider registry snapshot.
    RegistrySnapshot = 3,
    /// Provider selector read.
    SelectorRead = 4,
    /// Provider storage grant verification.
    StorageGrantReadVerify = 5,
    /// Provider signed challenge write and flush.
    StorageChallengeWriteFlush = 6,
    /// Provider signed request verification.
    StorageRequestReadVerify = 7,
    /// Provider operation and receipt processing.
    StorageOperation = 8,
    /// Client selector/grant exchange and challenge verification.
    ClientChallenge = 9,
    /// Client operation and receipt exchange.
    ClientExchange = 10,
    /// Provider selected another protocol.
    OtherProtocol = 11,
    /// Local close or terminal handling, not successful custody evidence.
    Closing = 12,
}

/// Finite local completion observation, never a remote-cause assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum StorageFixtureCorrelationTerminal {
    /// Reserved and rejected.
    Unspecified = 0,
    /// No terminal event observed yet.
    Active = 1,
    /// Local exchange completed; not acceptance evidence.
    Complete = 2,
    /// The existing application TLS timeout elapsed.
    TlsTimeout = 3,
    /// Application TLS returned an error.
    TlsError = 4,
    /// Another operation failed or exhausted its existing deadline.
    OperationError = 5,
    /// The local observer was dropped before another terminal observation.
    Cancelled = 6,
}

/// Closed projection of an authenticated Acquire rejection, never its raw token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum StorageFixtureHelperDiagnostic {
    /// A validated rejection carried another token; not an absent observation.
    Unknown = 0,
    /// Ambiguous backend result, not necessarily a deadline.
    BackendResultAmbiguous = 1,
    /// Backend completion no longer matched the live context.
    StaleBackendResult = 2,
    /// No valid flow identity could be issued.
    FlowIdentityUnavailable = 3,
    /// Transport acquisition was unavailable; not a syscall diagnosis.
    TransportUnavailable = 4,
    /// The helper reported incomplete cleanup; not a remote cleanup receipt.
    CleanupIncomplete = 5,
    /// Transport replay state could not be committed consistently.
    ReplayCommitInconsistent = 6,
    /// A global expired-context reap was incomplete, not necessarily this route.
    ExpiredContextCleanupIncomplete = 7,
    /// A global expired-extension reap was incomplete, not necessarily this route.
    ExpiredExtensionCleanupIncomplete = 8,
    /// The connected MPTCP poll elapsed without readiness; no kernel errno was reported.
    MptcpConnectPollTimedOut = 9,
}

/// One request's first/last acquisition failure, not a provider or copy binding.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct StorageFixtureAcquireFailure {
    /// Existing closed failure stage/reason, unchanged in production diagnostics.
    #[prost(message, optional, tag = "1")]
    pub failure: Option<crate::PrivateStorageFlowAcquireFailure>,
    /// Absent without a validated helper rejection; zero is explicitly unknown.
    #[prost(enumeration = "StorageFixtureHelperDiagnostic", optional, tag = "2")]
    pub helper_diagnostic: Option<i32>,
}

/// Bounded request-local history exposed only in fixture schema two.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct StorageFixtureAcquireSummary {
    /// Original loop rounds, one through eight, not extra helper requests.
    #[prost(uint32, tag = "1")]
    pub rounds: u32,
    /// First returned failure.
    #[prost(message, optional, tag = "2")]
    pub first: Option<StorageFixtureAcquireFailure>,
    /// Last returned failure.
    #[prost(message, optional, tag = "3")]
    pub last: Option<StorageFixtureAcquireFailure>,
}

impl StorageFixtureAcquireSummary {
    fn validate(&self) -> Result<(), ControlProtocolError> {
        use crate::{
            PrivateStorageFlowAcquireReason as Reason, PrivateStorageFlowAcquireStage as Stage,
        };
        let first = self.first.ok_or_else(invalid)?;
        let last = self.last.ok_or_else(invalid)?;
        crate::PrivateStorageFlowAcquireDetail {
            rounds: self.rounds,
            first: first.failure,
            last: last.failure,
        }
        .validate()?;
        if self.rounds == 1 && first != last {
            return Err(invalid());
        }
        for value in [first, last] {
            if let Some(code) = value.helper_diagnostic {
                let code = StorageFixtureHelperDiagnostic::try_from(code).map_err(|_| invalid())?;
                let failure = value.failure.ok_or_else(invalid)?;
                if failure.stage != Stage::HelperAcquire as i32
                    || (code == StorageFixtureHelperDiagnostic::MptcpConnectPollTimedOut
                        && failure.reason != Reason::HelperKernel as i32)
                    || !matches!(
                        Reason::try_from(failure.reason),
                        Ok(Reason::HelperKernel
                            | Reason::HelperCapacity
                            | Reason::HelperUnavailable
                            | Reason::HelperNotFound
                            | Reason::HelperCleanupIncomplete
                            | Reason::HelperOtherRejection)
                    )
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

/// Closed verified storage operation, never a request supplied by a peer without verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum StorageFixtureOperation {
    /// No verified request observed.
    Unobserved = 0,
    /// Reserve one exact copy.
    Reserve = 1,
    /// Append one bounded chunk.
    Append = 2,
    /// Inspect a retained prefix.
    Progress = 3,
    /// Commit one complete copy.
    Finalize = 4,
    /// Read an authorized range.
    ReadRange = 5,
    /// Renew one existing lease.
    Renew = 6,
    /// Delete one existing copy.
    Delete = 7,
}

/// Private schema-three selector. Never retain or publish these fields.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct StorageFixtureTarget {
    /// Exact per-copy journal archive identifier, not its parent archive identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub archive_id: Vec<u8>,
    /// Pinned provider verification key from that same journal.
    #[prost(bytes = "vec", tag = "2")]
    pub provider_key: Vec<u8>,
    /// Exact requested operation; multiple attempts remain ambiguous.
    #[prost(enumeration = "StorageFixtureOperation", tag = "3")]
    pub operation: i32,
}

/// Last receiving-side request boundary actually observed, not client delivery proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum StorageFixtureProviderStage {
    /// No verified provider request observed.
    Unobserved = 0,
    /// Provider verified the signed request.
    RequestVerified = 1,
    /// Blocking worker entered the actual backend call.
    BackendEntered = 2,
    /// Actual backend call returned; receipt can still fail.
    BackendReturned = 3,
    /// Provider entered signed receipt write and flush.
    ReceiptWriteEntered = 4,
    /// Provider receipt write and flush returned successfully.
    ReceiptFlushReturned = 5,
}

/// Blocking backend state independent of connection cancellation/timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum StorageFixtureWorkerState {
    /// No backend entry observed; absence does not prove no work.
    Unobserved = 0,
    /// Actual backend call entered, with no return observed yet.
    Entered = 1,
    /// Actual backend call returned success.
    ReturnedOk = 2,
    /// Actual backend call returned error.
    ReturnedError = 3,
}

/// Coarse RESERVE timing from the original operation clock; no timestamps.
#[derive(Clone, Copy, PartialEq, Eq, Message)]
pub struct StorageFixtureReserveTiming {
    /// Operation budget spent on entry to request write/flush.
    #[prost(enumeration = "crate::PrivateStorageElapsedBucket", tag = "1")]
    pub before_request_flush_elapsed: i32,
    /// Original operation budget remaining at that same boundary (zero saturates).
    #[prost(enumeration = "crate::PrivateStorageElapsedBucket", tag = "2")]
    pub before_request_flush_remaining: i32,
    /// Receipt-read time; stops at successful read return or first terminal on failure.
    #[prost(
        enumeration = "crate::PrivateStorageElapsedBucket",
        optional,
        tag = "3"
    )]
    pub receipt_wait_elapsed: Option<i32>,
    /// Original operation budget remaining at receipt-read entry.
    #[prost(
        enumeration = "crate::PrivateStorageElapsedBucket",
        optional,
        tag = "4"
    )]
    pub receipt_wait_remaining: Option<i32>,
}

/// Private request-local detail. Digests are epoch-scoped and never public evidence.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct StorageFixtureRequestObservation {
    /// Client: only after actual signed frame flush; provider: only after signature verification.
    #[prost(bytes = "vec", optional, tag = "1")]
    pub request_digest: Option<Vec<u8>>,
    /// Verified operation, or zero before provider request verification.
    #[prost(enumeration = "StorageFixtureOperation", tag = "2")]
    pub operation: i32,
    /// Receiving-side boundary, zero on client records.
    #[prost(enumeration = "StorageFixtureProviderStage", tag = "3")]
    pub provider_stage: i32,
    /// Receiving backend state, zero on client records.
    #[prost(enumeration = "StorageFixtureWorkerState", tag = "4")]
    pub worker_state: i32,
    /// Backend return observed after this provider connection's terminal event.
    #[prost(bool, tag = "5")]
    pub worker_returned_after_terminal: bool,
    /// Client RESERVE only; absent without the original clock/request boundary.
    #[prost(message, optional, tag = "6")]
    pub reserve_timing: Option<StorageFixtureReserveTiming>,
}

impl StorageFixtureRequestObservation {
    fn validate(&self, role: StorageFixtureCorrelationRole) -> Result<(), ControlProtocolError> {
        use StorageFixtureOperation as Op;
        use StorageFixtureProviderStage as Stage;
        use StorageFixtureWorkerState as Worker;
        let op = Op::try_from(self.operation).map_err(|_| invalid())?;
        let stage = Stage::try_from(self.provider_stage).map_err(|_| invalid())?;
        let worker = Worker::try_from(self.worker_state).map_err(|_| invalid())?;
        if self.request_digest.as_ref().is_some_and(|v| v.len() != 32)
            || (self.request_digest.is_some() && op == Op::Unobserved)
            || (self.worker_returned_after_terminal
                && !matches!(worker, Worker::ReturnedOk | Worker::ReturnedError))
        {
            return Err(invalid());
        }
        match role {
            StorageFixtureCorrelationRole::Client
                if stage == Stage::Unobserved
                    && worker == Worker::Unobserved
                    && !self.worker_returned_after_terminal
                    && op != Op::Unobserved => {}
            StorageFixtureCorrelationRole::Provider
                if self.reserve_timing.is_none()
                    && ((stage == Stage::Unobserved
                        && op == Op::Unobserved
                        && self.request_digest.is_none()
                        && worker == Worker::Unobserved)
                        || (stage != Stage::Unobserved
                            && op != Op::Unobserved
                            && self.request_digest.is_some())) => {}
            _ => return Err(invalid()),
        }
        if stage as i32 >= Stage::BackendEntered as i32 && worker == Worker::Unobserved
            || stage as i32 >= Stage::BackendReturned as i32
                && !matches!(worker, Worker::ReturnedOk | Worker::ReturnedError)
            || stage as i32 >= Stage::ReceiptWriteEntered as i32 && worker != Worker::ReturnedOk
        {
            return Err(invalid());
        }
        if let Some(timing) = self.reserve_timing {
            if op != Op::Reserve
                || (timing.receipt_wait_elapsed.is_some() && self.request_digest.is_none())
                || timing.receipt_wait_elapsed.is_some() != timing.receipt_wait_remaining.is_some()
            {
                return Err(invalid());
            }
            for value in [
                Some(timing.before_request_flush_elapsed),
                Some(timing.before_request_flush_remaining),
                timing.receipt_wait_elapsed,
                timing.receipt_wait_remaining,
            ]
            .into_iter()
            .flatten()
            {
                if crate::PrivateStorageElapsedBucket::try_from(value).map_err(|_| invalid())?
                    == crate::PrivateStorageElapsedBucket::Unobserved
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

/// Bounded private command, subject to an additional agent-side development/UID gate.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct StorageFixtureCorrelationRequest {
    /// One: legacy; two: closed Acquire details; three: exact private request observations.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// One explicit action.
    #[prost(enumeration = "StorageFixtureCorrelationAction", tag = "2")]
    pub action: i32,
    /// Private caller-owned epoch, exactly 16 bytes; never returned in public evidence.
    #[prost(bytes = "vec", tag = "3")]
    pub epoch: Vec<u8>,
    /// One through eight unique 32-byte fingerprints only for provider lookup.
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub fingerprints: Vec<Vec<u8>>,
    /// Schema-three Arm/Clients exact target. Private input only; never echoed.
    #[prost(message, optional, tag = "5")]
    pub target: Option<StorageFixtureTarget>,
}

impl StorageFixtureCorrelationRequest {
    /// Validate the finite action and its bounded private arguments.
    ///
    /// # Errors
    /// Returns a fixed error without reflecting any private input.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        if !matches!(self.version, 1..=3)
            || self.epoch.len() != 16
            || self.encoded_len() > MAX_FIXTURE_MESSAGE
        {
            return Err(invalid());
        }
        if let Some(target) = &self.target {
            if self.version != 3
                || !matches!(
                    StorageFixtureCorrelationAction::try_from(self.action),
                    Ok(StorageFixtureCorrelationAction::Arm
                        | StorageFixtureCorrelationAction::Clients)
                )
                || target.archive_id.len() != 32
                || target.provider_key.len() != 32
                || StorageFixtureOperation::try_from(target.operation).map_err(|_| invalid())?
                    == StorageFixtureOperation::Unobserved
            {
                return Err(invalid());
            }
        } else if self.version == 3
            && matches!(
                StorageFixtureCorrelationAction::try_from(self.action),
                Ok(StorageFixtureCorrelationAction::Arm | StorageFixtureCorrelationAction::Clients)
            )
        {
            return Err(invalid());
        }
        match StorageFixtureCorrelationAction::try_from(self.action) {
            Ok(StorageFixtureCorrelationAction::Providers) => {
                if !(1..=MAX_FIXTURE_FINGERPRINTS).contains(&self.fingerprints.len()) {
                    return Err(invalid());
                }
                for (index, fingerprint) in self.fingerprints.iter().enumerate() {
                    if fingerprint.len() != 32 || self.fingerprints[..index].contains(fingerprint) {
                        return Err(invalid());
                    }
                }
            }
            Ok(
                StorageFixtureCorrelationAction::Arm
                | StorageFixtureCorrelationAction::Clients
                | StorageFixtureCorrelationAction::Disarm,
            ) if self.fingerprints.is_empty() => {}
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

/// Private connection observation; no durable or public trace identifier.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct StorageFixtureCorrelationRecord {
    /// Existing client or provider side.
    #[prost(enumeration = "StorageFixtureCorrelationRole", tag = "1")]
    pub role: i32,
    /// Exact fixture-derived fingerprint, absent only for an incomplete client observation.
    #[prost(bytes = "vec", optional, tag = "2")]
    pub fingerprint: Option<Vec<u8>>,
    /// Finite current or terminal boundary.
    #[prost(enumeration = "StorageFixtureCorrelationPhase", tag = "3")]
    pub phase: i32,
    /// Finite local terminal observation.
    #[prost(enumeration = "StorageFixtureCorrelationTerminal", tag = "4")]
    pub terminal: i32,
    /// Schema-two client-only returned acquisition failure; never a raw helper token.
    #[prost(message, optional, tag = "5")]
    pub flow_acquire: Option<StorageFixtureAcquireSummary>,
    /// Private schema-three request observations, never a public trace identifier.
    #[prost(message, optional, tag = "6")]
    pub request_observation: Option<StorageFixtureRequestObservation>,
}

impl StorageFixtureCorrelationRecord {
    fn validate(&self) -> Result<(), ControlProtocolError> {
        use StorageFixtureCorrelationPhase as Phase;
        use StorageFixtureCorrelationRole as Role;
        use StorageFixtureCorrelationTerminal as Terminal;

        let role = Role::try_from(self.role).map_err(|_| invalid())?;
        let phase = Phase::try_from(self.phase).map_err(|_| invalid())?;
        let terminal = Terminal::try_from(self.terminal).map_err(|_| invalid())?;
        let allowed = match role {
            Role::Client => matches!(
                phase,
                Phase::FlowAcquire
                    | Phase::TlsHandshake
                    | Phase::ClientChallenge
                    | Phase::ClientExchange
                    | Phase::Closing
            ),
            Role::Provider => matches!(
                phase,
                Phase::TlsHandshake
                    | Phase::RegistrySnapshot
                    | Phase::SelectorRead
                    | Phase::StorageGrantReadVerify
                    | Phase::StorageChallengeWriteFlush
                    | Phase::StorageRequestReadVerify
                    | Phase::StorageOperation
                    | Phase::OtherProtocol
                    | Phase::Closing
            ),
            Role::Unspecified => false,
        };
        if !allowed
            || terminal == Terminal::Unspecified
            || (matches!(terminal, Terminal::TlsTimeout | Terminal::TlsError)
                && phase != Phase::TlsHandshake)
            || self
                .fingerprint
                .as_ref()
                .is_some_and(|value| value.len() != 32)
            || (role == Role::Provider && self.fingerprint.is_none())
        {
            return Err(invalid());
        }
        if let Some(detail) = &self.request_observation {
            detail.validate(role)?;
            if detail.worker_returned_after_terminal
                && !matches!(terminal, Terminal::OperationError | Terminal::Cancelled)
            {
                return Err(invalid());
            }
            if role == Role::Provider {
                if detail.worker_state != StorageFixtureWorkerState::Unobserved as i32
                    && detail.provider_stage < StorageFixtureProviderStage::BackendEntered as i32
                    && terminal == Terminal::Active
                {
                    return Err(invalid());
                }
                if matches!(
                    StorageFixtureWorkerState::try_from(detail.worker_state),
                    Ok(StorageFixtureWorkerState::ReturnedOk
                        | StorageFixtureWorkerState::ReturnedError)
                ) && detail.provider_stage < StorageFixtureProviderStage::BackendReturned as i32
                    && !detail.worker_returned_after_terminal
                {
                    return Err(invalid());
                }
            }
        }

        if let Some(summary) = &self.flow_acquire {
            if role != Role::Client
                || phase != Phase::FlowAcquire
                || terminal != Terminal::OperationError
                || self.fingerprint.is_some()
            {
                return Err(invalid());
            }
            summary.validate()?;
        }
        Ok(())
    }
}

/// Bounded private response; no acceptance or absence proof.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct StorageFixtureCorrelationResponse {
    /// Matches the requesting private fixture schema (one, two or three).
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// Finite availability/lifecycle state.
    #[prost(enumeration = "StorageFixtureCorrelationState", tag = "2")]
    pub state: i32,
    /// Observation loss, including an unavailable snapshot.
    #[prost(bool, tag = "3")]
    pub incomplete: bool,
    /// At most 64 locally observed records.
    #[prost(message, repeated, tag = "4")]
    pub records: Vec<StorageFixtureCorrelationRecord>,
}

impl StorageFixtureCorrelationResponse {
    /// Unavailable is unknown rather than an empty successful observation.
    pub fn unavailable() -> Self {
        Self {
            version: 1,
            state: StorageFixtureCorrelationState::Unavailable as i32,
            incomplete: true,
            records: Vec::new(),
        }
    }

    /// Validate all closed fields before using or encoding the observation.
    ///
    /// # Errors
    /// Returns a fixed error on an invalid state, record, or size.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        use StorageFixtureCorrelationState as State;

        if !matches!(self.version, 1..=3)
            || self.records.len() > MAX_FIXTURE_RECORDS
            || self.encoded_len() > MAX_FIXTURE_MESSAGE
        {
            return Err(invalid());
        }
        match State::try_from(self.state) {
            Ok(State::Armed | State::Disarmed) if !self.incomplete && self.records.is_empty() => {}
            Ok(State::Unavailable) if self.incomplete && self.records.is_empty() => {}
            Ok(State::Observed) if self.version != 3 || !self.incomplete => {}
            _ => return Err(invalid()),
        }
        for record in &self.records {
            if self.version == 1 && record.flow_acquire.is_some()
                || self.version != 3 && record.request_observation.is_some()
                || self.version == 3 && record.request_observation.is_none()
            {
                return Err(invalid());
            }
            record.validate()?;
        }
        Ok(())
    }

    /// Bind a valid response to this exact local action and provider lookup set.
    ///
    /// # Errors
    /// Returns a fixed error for any cross-action, role or fingerprint mismatch.
    pub fn validate_for(
        &self,
        request: &StorageFixtureCorrelationRequest,
    ) -> Result<(), ControlProtocolError> {
        use StorageFixtureCorrelationAction as Action;
        use StorageFixtureCorrelationRole as Role;
        use StorageFixtureCorrelationState as State;

        request.validate()?;
        self.validate()?;
        if self.version != request.version {
            return Err(invalid());
        }
        if self.state == State::Unavailable as i32 {
            return Ok(());
        }
        let (state, role) = match Action::try_from(request.action).map_err(|_| invalid())? {
            Action::Arm => (State::Armed, None),
            Action::Clients => (State::Observed, Some(Role::Client)),
            Action::Providers => (State::Observed, Some(Role::Provider)),
            Action::Disarm => (State::Disarmed, None),
            Action::Unspecified => return Err(invalid()),
        };
        if self.state != state as i32 {
            return Err(invalid());
        }
        if request.version == 3 && self.state == State::Observed as i32 {
            let unique = match role {
                Some(Role::Client) => {
                    self.records.len() == 1
                        && self.records[0].fingerprint.is_some()
                        && self.records[0]
                            .request_observation
                            .as_ref()
                            .is_some_and(|detail| {
                                request
                                    .target
                                    .as_ref()
                                    .is_some_and(|target| target.operation == detail.operation)
                            })
                }
                Some(Role::Provider) => request.fingerprints.iter().all(|fingerprint| {
                    self.records
                        .iter()
                        .filter(|record| record.fingerprint.as_ref() == Some(fingerprint))
                        .count()
                        <= 1
                }),
                _ => true,
            };
            if !unique {
                return Err(invalid());
            }
        }
        for record in &self.records {
            if Some(record.role) != role.map(|value| value as i32)
                || (role == Some(Role::Provider)
                    && !record
                        .fingerprint
                        .as_ref()
                        .is_some_and(|fingerprint| request.fingerprints.contains(fingerprint)))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

fn invalid() -> ControlProtocolError {
    ControlProtocolError::Invalid("storage fixture correlation")
}

#[cfg(test)]
mod tests;
