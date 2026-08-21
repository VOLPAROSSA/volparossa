use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;

const MAX_IDENTIFIER_BYTES: usize = 128;

/// Failure to construct a bounded opaque identifier.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentifierError {
    /// The identifier was empty.
    #[error("identifier must not be empty")]
    Empty,
    /// The identifier exceeded the protocol allocation bound.
    #[error("identifier exceeds {MAX_IDENTIFIER_BYTES} bytes")]
    TooLong,
    /// The identifier contained a character outside the canonical safe set.
    #[error("identifier contains a non-canonical character")]
    InvalidCharacter,
}

fn validate_identifier(value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(IdentifierError::TooLong);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(IdentifierError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! define_text_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates and constructs the identifier.
            ///
            /// # Errors
            ///
            /// Returns an error when the text is empty, too long, or contains a forbidden byte.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            /// Returns the canonical textual representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentifierError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

define_text_id!(
    /// A permanent VOLPAROSSA node identity.
    NodeId
);
define_text_id!(
    /// A libp2p peer identity derived from the permanent node identity.
    PeerId
);
define_text_id!(
    /// A locally asserted operator identity used as an anti-Sybil signal.
    OperatorId
);
define_text_id!(
    /// A short-lived route context identity.
    RouteContextId
);
define_text_id!(
    /// A short-lived signed reservation identity.
    ReservationId
);
define_text_id!(
    /// An ephemeral identity used for one client route context.
    ClientEphemeralId
);
define_text_id!(
    /// An application-flow identity that is never a durable browsing identity.
    FlowId
);
define_text_id!(
    /// A local profile partition used when deriving an in-memory route scope.
    LocalProfileId
);
define_text_id!(
    /// An opaque, caller-derived origin partition key.
    ///
    /// It is deliberately not a hostname type.  Callers should derive a
    /// session-local opaque key from the registrable domain or application
    /// origin, and must not write that association to the peerstore.
    OriginKey
);

/// A path number unique within a route context.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct PathId(u16);

impl PathId {
    /// Constructs a non-zero path identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is zero.
    pub fn new(value: u16) -> Result<Self, IdentifierError> {
        if value == 0 {
            return Err(IdentifierError::Empty);
        }
        Ok(Self(value))
    }

    /// Returns the numeric identifier.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for PathId {
    type Error = IdentifierError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PathId> for u16 {
    fn from(value: PathId) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_bounded_and_canonical() {
        assert_eq!(NodeId::new("node-1").expect("valid").as_str(), "node-1");
        assert_eq!(NodeId::new(""), Err(IdentifierError::Empty));
        assert_eq!(
            NodeId::new("contains/slash"),
            Err(IdentifierError::InvalidCharacter)
        );
        assert_eq!(NodeId::new("x".repeat(129)), Err(IdentifierError::TooLong));
    }

    #[test]
    fn path_zero_is_rejected() {
        assert_eq!(PathId::new(0), Err(IdentifierError::Empty));
        assert_eq!(PathId::new(7).expect("valid").get(), 7);
    }
}
