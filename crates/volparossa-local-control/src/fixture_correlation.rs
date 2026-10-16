//! Explicit development-fixture correlation, private to the protected local socket.

use prost::Message;
use serde::Serialize;

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

/// Bounded private command, subject to an additional agent-side development/UID gate.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct StorageFixtureCorrelationRequest {
    /// Exactly one.
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
}

impl StorageFixtureCorrelationRequest {
    /// Validate the finite action and its bounded private arguments.
    ///
    /// # Errors
    /// Returns a fixed error without reflecting any private input.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.version != 1 || self.epoch.len() != 16 || self.encoded_len() > MAX_FIXTURE_MESSAGE {
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
        Ok(())
    }
}

/// Bounded private response; no acceptance or absence proof.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct StorageFixtureCorrelationResponse {
    /// Exactly one.
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

        if self.version != 1
            || self.records.len() > MAX_FIXTURE_RECORDS
            || self.encoded_len() > MAX_FIXTURE_MESSAGE
        {
            return Err(invalid());
        }
        match State::try_from(self.state) {
            Ok(State::Armed | State::Disarmed) if !self.incomplete && self.records.is_empty() => {}
            Ok(State::Unavailable) if self.incomplete && self.records.is_empty() => {}
            Ok(State::Observed) => {}
            _ => return Err(invalid()),
        }
        for record in &self.records {
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
