//! Provider-local observations, not wire replies, custody proof or client correlation.

#[cfg(test)]
mod tests;

use super::WireError;
use crate::private_storage::{
    StorageError,
    protocol::{ProtocolError, StorageOperation},
    provider::ProviderError,
};

/// Only the operation of a successfully verified owner request, without its fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Reserve an exact copy.
    Reserve,
    /// Append one chunk.
    Append,
    /// Inspect the durable prefix.
    Progress,
    /// Verify and commit the complete copy.
    Finalize,
    /// Read an authorized range.
    ReadRange,
    /// Renew the existing lease.
    Renew,
    /// Delete the existing copy.
    Delete,
}

impl From<StorageOperation> for Operation {
    fn from(value: StorageOperation) -> Self {
        match value {
            StorageOperation::Reserve { .. } => Self::Reserve,
            StorageOperation::Append { .. } => Self::Append,
            StorageOperation::Progress => Self::Progress,
            StorageOperation::Finalize => Self::Finalize,
            StorageOperation::ReadRange { .. } => Self::ReadRange,
            StorageOperation::Renew { .. } => Self::Renew,
            StorageOperation::Delete => Self::Delete,
        }
    }
}

/// Last boundary actually entered on this provider's owned exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Read and verify the grant.
    Grant,
    /// Issue and write its challenge.
    Challenge,
    /// Read and verify the owner request; its operation is not trusted yet.
    Request,
    /// Read/check the append payload and current request authorization.
    Payload,
    /// Acquire the existing non-queuing disk permit.
    DiskAdmission,
    /// Execute the existing authorized backend operation.
    Backend,
    /// After backend success: check/sign/write the receipt, without undoing any commit.
    Receipt,
    /// Write the authorized read-range payload after the receipt.
    ResponsePayload,
}

/// Closed error families; never formats a nested database, I/O or peer-supplied error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Category {
    /// Stream or filesystem I/O.
    Io,
    /// Signed message authorization failed.
    Auth,
    /// Invalid frame, input or state transition.
    Invalid,
    /// Existing disk admission refused the request.
    Busy,
    /// Invalid store, mutex or worker failure; outcome may be unknown.
    Store,
    /// Existing timeout; an in-flight blocking operation may still complete.
    Timeout,
    /// Database operation failed, without disclosing its error text.
    Database,
    /// Stored chunk, prefix or complete archive integrity failed.
    Integrity,
    /// Signed authorization or stored lease expired.
    Expired,
    /// Persistent provider/grant/owner/lease binding did not authorize the request.
    Ownership,
    /// Immutable archive identity conflicted.
    Conflict,
    /// Existing deletion tombstone denied the operation.
    Deleted,
    /// Payload or metadata quota rejected the operation.
    Quota,
    /// Existing lease was not found.
    NotFound,
    /// The requested archive was not committed.
    NotCommitted,
    /// Operating-system randomness was unavailable.
    Entropy,
}

impl Category {
    fn protocol(error: ProtocolError) -> Self {
        match error {
            ProtocolError::Invalid => Self::Invalid,
            ProtocolError::Unauthorized => Self::Auth,
            ProtocolError::Expired => Self::Expired,
            ProtocolError::Entropy => Self::Entropy,
        }
    }

    pub(super) fn wire(error: &WireError) -> Self {
        match error {
            WireError::Io(_) => Self::Io,
            WireError::Protocol(error) => Self::protocol(*error),
            WireError::Invalid => Self::Invalid,
            WireError::Busy => Self::Busy,
            WireError::Store => Self::Store,
            WireError::Timeout => Self::Timeout,
        }
    }

    pub(super) fn backend(error: &ProviderError) -> Self {
        match error {
            ProviderError::Protocol(error) => Self::protocol(*error),
            ProviderError::Unauthorized => Self::Ownership,
            ProviderError::Conflict => Self::Conflict,
            ProviderError::Deleted => Self::Deleted,
            ProviderError::MetadataQuota => Self::Quota,
            ProviderError::Storage(error) => match error {
                StorageError::Io(_) => Self::Io,
                StorageError::Database(_) => Self::Database,
                StorageError::InvalidStore => Self::Store,
                StorageError::InvalidInput | StorageError::AlreadyCommitted => Self::Invalid,
                StorageError::Busy => Self::Busy,
                StorageError::Quota => Self::Quota,
                StorageError::Expired => Self::Expired,
                StorageError::NotFound => Self::NotFound,
                StorageError::NotCommitted => Self::NotCommitted,
                StorageError::Integrity => Self::Integrity,
                StorageError::Entropy => Self::Entropy,
            },
        }
    }
}

/// One closed tuple. Absence of a tuple is not evidence of success or event absence.
/// Private fields prevent callers from inventing an operation before verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    operation: Option<Operation>,
    phase: Phase,
    category: Category,
    payload_io: Option<PayloadIo>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PayloadBoundary {
    Header,
    Body,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadIoKind {
    UnexpectedEof,
    TimedOut,
    ConnectionReset,
    BrokenPipe,
    InvalidData,
    Interrupted,
    Other,
}

impl From<std::io::ErrorKind> for PayloadIoKind {
    fn from(value: std::io::ErrorKind) -> Self {
        match value {
            std::io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            std::io::ErrorKind::TimedOut => Self::TimedOut,
            std::io::ErrorKind::ConnectionReset => Self::ConnectionReset,
            std::io::ErrorKind::BrokenPipe => Self::BrokenPipe,
            std::io::ErrorKind::InvalidData => Self::InvalidData,
            std::io::ErrorKind::Interrupted => Self::Interrupted,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PayloadIo {
    boundary: PayloadBoundary,
    kind: PayloadIoKind,
}

macro_rules! payload_io_code {
    ($boundary:literal, $kind:expr) => {
        match $kind {
            PayloadIoKind::UnexpectedEof => concat!(
                "CONTENT_PROVIDER_STORAGE_V2_APPEND__",
                $boundary,
                "__UNEXPECTED_EOF"
            ),
            PayloadIoKind::TimedOut => concat!(
                "CONTENT_PROVIDER_STORAGE_V2_APPEND__",
                $boundary,
                "__TIMED_OUT"
            ),
            PayloadIoKind::ConnectionReset => concat!(
                "CONTENT_PROVIDER_STORAGE_V2_APPEND__",
                $boundary,
                "__CONNECTION_RESET"
            ),
            PayloadIoKind::BrokenPipe => concat!(
                "CONTENT_PROVIDER_STORAGE_V2_APPEND__",
                $boundary,
                "__BROKEN_PIPE"
            ),
            PayloadIoKind::InvalidData => concat!(
                "CONTENT_PROVIDER_STORAGE_V2_APPEND__",
                $boundary,
                "__INVALID_DATA"
            ),
            PayloadIoKind::Interrupted => concat!(
                "CONTENT_PROVIDER_STORAGE_V2_APPEND__",
                $boundary,
                "__INTERRUPTED"
            ),
            PayloadIoKind::Other => {
                concat!("CONTENT_PROVIDER_STORAGE_V2_APPEND__", $boundary, "__OTHER")
            }
        }
    };
}

// Every returned code is a static literal accepted by the existing code-only log ring.
// There is no formatting of runtime strings, error contents or request identifiers.
macro_rules! category_code {
    ($op:literal, $phase:literal, $category:expr) => {
        match $category {
            Category::Io => concat!("CONTENT_PROVIDER_STORAGE_V1_", $op, "__", $phase, "__IO"),
            Category::Auth => concat!("CONTENT_PROVIDER_STORAGE_V1_", $op, "__", $phase, "__AUTH"),
            Category::Invalid => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__INVALID"
            ),
            Category::Busy => concat!("CONTENT_PROVIDER_STORAGE_V1_", $op, "__", $phase, "__BUSY"),
            Category::Store => {
                concat!("CONTENT_PROVIDER_STORAGE_V1_", $op, "__", $phase, "__STORE")
            }
            Category::Timeout => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__TIMEOUT"
            ),
            Category::Database => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__DATABASE"
            ),
            Category::Integrity => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__INTEGRITY"
            ),
            Category::Expired => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__EXPIRED"
            ),
            Category::Ownership => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__OWNERSHIP"
            ),
            Category::Conflict => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__CONFLICT"
            ),
            Category::Deleted => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__DELETED"
            ),
            Category::Quota => {
                concat!("CONTENT_PROVIDER_STORAGE_V1_", $op, "__", $phase, "__QUOTA")
            }
            Category::NotFound => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__NOT_FOUND"
            ),
            Category::NotCommitted => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__NOT_COMMITTED"
            ),
            Category::Entropy => concat!(
                "CONTENT_PROVIDER_STORAGE_V1_",
                $op,
                "__",
                $phase,
                "__ENTROPY"
            ),
        }
    };
}

macro_rules! phase_code {
    ($op:literal, $value:expr) => {
        match $value.phase {
            Phase::Grant => category_code!($op, "GRANT", $value.category),
            Phase::Challenge => category_code!($op, "CHALLENGE", $value.category),
            Phase::Request => category_code!($op, "REQUEST", $value.category),
            Phase::Payload => category_code!($op, "PAYLOAD", $value.category),
            Phase::DiskAdmission => category_code!($op, "DISK_ADMISSION", $value.category),
            Phase::Backend => category_code!($op, "BACKEND", $value.category),
            Phase::Receipt => category_code!($op, "RECEIPT", $value.category),
            Phase::ResponsePayload => category_code!($op, "RESPONSE_PAYLOAD", $value.category),
        }
    };
}

impl Failure {
    /// Additional APPEND read boundary and original I/O kind, never a cause or receipt.
    /// Existing timeout cancellation, invalid frames and other operations have no code.
    #[must_use]
    pub fn payload_io_event_code(self) -> Option<&'static str> {
        if self.operation != Some(Operation::Append)
            || self.phase != Phase::Payload
            || self.category != Category::Io
        {
            return None;
        }
        let payload = self.payload_io?;
        Some(match payload.boundary {
            PayloadBoundary::Header => payload_io_code!("PAYLOAD_HEADER", payload.kind),
            PayloadBoundary::Body => payload_io_code!("PAYLOAD_BODY", payload.kind),
        })
    }

    /// Bounded static tuple, suitable only for the existing provider-local log ring.
    #[must_use]
    pub fn event_code(self) -> &'static str {
        match self.operation {
            None => phase_code!("UNKNOWN", self),
            Some(Operation::Reserve) => phase_code!("RESERVE", self),
            Some(Operation::Append) => phase_code!("APPEND", self),
            Some(Operation::Progress) => phase_code!("PROGRESS", self),
            Some(Operation::Finalize) => phase_code!("FINALIZE", self),
            Some(Operation::ReadRange) => phase_code!("READ_RANGE", self),
            Some(Operation::Renew) => phase_code!("RENEW", self),
            Some(Operation::Delete) => phase_code!("DELETE", self),
        }
    }
}

/// Caller-owned progress survives cancellation by the enclosing selector deadline.
/// Never shared with a blocking worker: a late backend cannot rewrite an emitted tuple.
pub(crate) struct Observation {
    operation: Option<Operation>,
    pub(super) phase: Phase,
    pub(super) backend_category: Option<Category>,
    payload_io: Option<PayloadIo>,
    active: bool,
    failure: Option<Failure>,
}

impl Default for Observation {
    fn default() -> Self {
        Self {
            operation: None,
            phase: Phase::Grant,
            backend_category: None,
            payload_io: None,
            active: false,
            failure: None,
        }
    }
}

impl Observation {
    pub(super) fn begin(&mut self) {
        *self = Self {
            active: true,
            ..Self::default()
        };
    }

    pub(super) fn verified(&mut self, operation: StorageOperation) {
        self.operation = Some(operation.into());
        self.phase = Phase::Payload;
    }

    pub(super) fn payload_read_error(
        &mut self,
        boundary: PayloadBoundary,
        kind: std::io::ErrorKind,
    ) {
        if self.operation == Some(Operation::Append) && self.phase == Phase::Payload {
            self.payload_io = Some(PayloadIo {
                boundary,
                kind: kind.into(),
            });
        }
    }

    pub(super) fn finish(&mut self, result: &Result<(), WireError>) {
        self.failure = result.as_ref().err().map(|error| Failure {
            operation: self.operation,
            phase: self.phase,
            category: self
                .backend_category
                .unwrap_or_else(|| Category::wire(error)),
            payload_io: self.payload_io,
        });
        self.active = false;
    }

    pub(crate) fn failure(&self, outer_timeout: bool) -> Option<Failure> {
        if outer_timeout && self.active {
            Some(Failure {
                operation: self.operation,
                phase: self.phase,
                category: Category::Timeout,
                payload_io: None,
            })
        } else {
            self.failure
        }
    }
}
