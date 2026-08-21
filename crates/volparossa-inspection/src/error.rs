use thiserror::Error;

/// A fail-closed parsing, authentication, or resource-limit failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InspectionError {
    /// An externally controlled input exceeded a fixed resource limit.
    #[error("inspection resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    /// The stream ended before a complete `ClientHello` was available.
    #[error("truncated TLS ClientHello")]
    TruncatedClientHello,
    /// A TLS record was structurally invalid or inappropriate here.
    #[error("invalid TLS record: {0}")]
    InvalidTlsRecord(&'static str),
    /// A `ClientHello` was structurally invalid.
    #[error("invalid TLS ClientHello: {0}")]
    InvalidClientHello(&'static str),
    /// A TLS extension type occurred more than once.
    #[error("duplicate TLS extension type {0}")]
    DuplicateTlsExtension(u16),
    /// Visible-name policy cannot safely inspect an encrypted `ClientHello`.
    #[error("encrypted ClientHello extension {0} is not permitted")]
    EncryptedClientHello(u16),
    /// No visible server-name extension was present.
    #[error("visible SNI is required")]
    MissingServerName,
    /// More than one server-name value was present.
    #[error("exactly one visible SNI name is required")]
    MultipleServerNames,
    /// The only accepted SNI name type is DNS `host_name`.
    #[error("unsupported TLS server-name type {0}")]
    UnsupportedServerNameType(u8),
    /// Policy normalization rejected the visible server name.
    #[error("visible SNI is not a valid policy domain")]
    InvalidServerName,
    /// The packet is not an unambiguous QUIC v1 client Initial datagram.
    #[error("invalid QUIC Initial packet: {0}")]
    InvalidQuicInitial(&'static str),
    /// Only IETF QUIC version 1 is inspected by this implementation.
    #[error("unsupported QUIC version {0:#010x}")]
    UnsupportedQuicVersion(u32),
    /// QUIC packet protection authentication failed.
    #[error("QUIC Initial authentication failed")]
    QuicAuthentication,
    /// A frame not permitted at Initial encryption level was encountered.
    #[error("QUIC frame type {0} is not permitted in a client Initial")]
    ForbiddenQuicFrame(u64),
    /// Two CRYPTO fragments assigned different bytes to the same offset.
    #[error("conflicting overlapping QUIC CRYPTO data")]
    ConflictingCryptoData,
    /// The connection closed before a complete visible `ClientHello` arrived.
    #[error("QUIC connection closed before ClientHello inspection completed")]
    ClosedBeforeClientHello,
    /// A method was called after the inspector had completed.
    #[error("inspection has already completed")]
    AlreadyComplete,
}
