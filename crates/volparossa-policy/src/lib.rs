//! Canonical, threshold-signed VOLPAROSSA egress whitelist manifests.
//!
//! The verifier treats the manifest, its embedded maintainer list, and every
//! destination as untrusted. Trust is anchored in a separately configured
//! [`TrustStore`]; keys listed by a manifest cannot make themselves trusted.
//! Accepted manifests use one canonical protobuf representation, carry a
//! SHA-256 policy hash, meet an Ed25519 signature threshold, and remain subject
//! to time checks for every authorization decision.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod domain;
mod wire;

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use domain::NormalizedRequest;
pub use domain::{DestinationRule, ProtocolPort, TransportProtocol, normalize_domain};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use wire::destination_rule_proto;
use wire::{
    DestinationRuleProto, MaintainerProto, ManifestBodyProto, ManifestSignatureProto,
    ProtocolPortProto, SignedManifestProto, decode_canonical, encode_canonical,
};

/// The only whitelist-manifest protobuf schema implemented by this release.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// The VOLPAROSSA policy protocol version implemented by this release.
pub const POLICY_PROTOCOL_VERSION: u32 = 2;

/// Standard number of independently trusted policy maintainers.
pub const DEFAULT_MAINTAINER_COUNT: usize = 5;

/// Standard minimum number of valid maintainer signatures.
pub const DEFAULT_MINIMUM_SIGNATURES: usize = 3;

/// Maximum encoded size accepted for a signed manifest.
pub const MAX_SIGNED_MANIFEST_BYTES: usize = 512 * 1024;

/// Maximum encoded size accepted for the canonical signed body.
pub const MAX_MANIFEST_BODY_BYTES: usize = 448 * 1024;

/// Maximum number of trusted maintainer keys in a custom deployment.
pub const MAX_MAINTAINERS: usize = 32;

/// Maximum number of signatures carried by a manifest.
pub const MAX_SIGNATURES: usize = MAX_MAINTAINERS;

/// Maximum number of destination rules in one manifest.
pub const MAX_DESTINATION_RULES: usize = 4_096;

/// Maximum permissions attached to one destination selector.
pub const MAX_PERMISSIONS_PER_DESTINATION: usize = 64;

/// Maximum total protocol/port permissions in one manifest.
pub const MAX_TOTAL_PERMISSIONS: usize = 16_384;

/// Maximum UTF-8 input length accepted before IDNA processing.
pub const MAX_DOMAIN_INPUT_BYTES: usize = 1_024;

/// Maximum canonical ASCII DNS-name length, excluding a root dot.
pub const MAX_DOMAIN_NAME_BYTES: usize = 253;

/// Default maximum validity duration of an accepted manifest.
pub const DEFAULT_MAXIMUM_MANIFEST_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// Default maximum tolerated future timestamp skew.
pub const DEFAULT_MAXIMUM_CLOCK_SKEW_MS: u64 = 60 * 1_000;

const HASH_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const SIGNATURE_DOMAIN: &[u8] = b"volparossa/whitelist-manifest/signature/v1\0";
const MAINTAINER_ID_DOMAIN: &[u8] = b"volparossa/whitelist-maintainer/id/v1\0";

/// Whether policy verification is running with production or explicit local
/// development trust roots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyMode {
    /// Reject every maintainer marked as a development key.
    Production,
    /// Permit explicitly marked development keys for local testing.
    Development,
}

/// The environment in which a maintainer key is permitted.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaintainerEnvironment {
    /// A separately provisioned production maintainer key.
    Production,
    /// A conspicuously development-only key for local testing.
    Development,
}

impl MaintainerEnvironment {
    const fn wire_value(self) -> i32 {
        match self {
            Self::Production => 1,
            Self::Development => 2,
        }
    }

    fn from_wire(value: i32) -> Result<Self, PolicyError> {
        match value {
            1 => Ok(Self::Production),
            2 => Ok(Self::Development),
            _ => Err(PolicyError::InvalidField("maintainer environment")),
        }
    }
}

/// One locally trusted Ed25519 whitelist maintainer.
#[derive(Clone)]
pub struct TrustedMaintainer {
    key_id: [u8; HASH_BYTES],
    verifying_key: VerifyingKey,
    environment: MaintainerEnvironment,
}

impl TrustedMaintainer {
    /// Register a verifying key with an explicit production/development label.
    #[must_use]
    pub fn new(verifying_key: VerifyingKey, environment: MaintainerEnvironment) -> Self {
        let key_id = maintainer_id(&verifying_key.to_bytes());
        Self {
            key_id,
            verifying_key,
            environment,
        }
    }

    /// Register a production maintainer key.
    #[must_use]
    pub fn production(verifying_key: VerifyingKey) -> Self {
        Self::new(verifying_key, MaintainerEnvironment::Production)
    }

    /// Register a conspicuously development-only maintainer key.
    #[must_use]
    pub fn development(verifying_key: VerifyingKey) -> Self {
        Self::new(verifying_key, MaintainerEnvironment::Development)
    }

    /// Return the domain-separated identifier derived from the public key.
    #[must_use]
    pub const fn key_id(&self) -> &[u8; HASH_BYTES] {
        &self.key_id
    }

    /// Return the trusted Ed25519 verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Return the key's permitted environment.
    #[must_use]
    pub const fn environment(&self) -> MaintainerEnvironment {
        self.environment
    }
}

/// A sorted local trust root for whitelist maintainers.
///
/// This store is configured independently of a downloaded manifest. During
/// verification, the manifest's complete maintainer list must exactly match
/// this store.
#[derive(Clone)]
pub struct TrustStore {
    mode: PolicyMode,
    maintainers: Vec<TrustedMaintainer>,
}

impl TrustStore {
    /// Build a bounded trust store and reject duplicate or disallowed keys.
    ///
    /// # Errors
    ///
    /// An empty or oversized key set, duplicate public key, or development key
    /// in production mode is rejected.
    pub fn new(
        mode: PolicyMode,
        mut maintainers: Vec<TrustedMaintainer>,
    ) -> Result<Self, PolicyError> {
        if maintainers.is_empty() {
            return Err(PolicyError::InvalidField("empty maintainer trust store"));
        }
        if maintainers.len() > MAX_MAINTAINERS {
            return Err(PolicyError::TooManyItems {
                what: "trusted maintainers",
                maximum: MAX_MAINTAINERS,
            });
        }
        if mode == PolicyMode::Production
            && maintainers
                .iter()
                .any(|key| key.environment == MaintainerEnvironment::Development)
        {
            return Err(PolicyError::DevelopmentKeyRejected);
        }

        maintainers.sort_unstable_by_key(|key| key.key_id);
        if maintainers
            .windows(2)
            .any(|pair| pair[0].key_id == pair[1].key_id)
        {
            return Err(PolicyError::DuplicateItem("trusted maintainer key"));
        }
        Ok(Self { mode, maintainers })
    }

    /// Return the verification mode fixed for this trust root.
    #[must_use]
    pub const fn mode(&self) -> PolicyMode {
        self.mode
    }

    /// Return the sorted trusted maintainers.
    #[must_use]
    pub fn maintainers(&self) -> &[TrustedMaintainer] {
        &self.maintainers
    }

    fn find_key(&self, key_id: &[u8; HASH_BYTES]) -> Option<&TrustedMaintainer> {
        self.maintainers
            .binary_search_by_key(key_id, |key| key.key_id)
            .ok()
            .map(|index| &self.maintainers[index])
    }
}

/// Local limits and signature requirements applied during verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    minimum_signatures: usize,
    expected_maintainers: usize,
    maximum_lifetime_ms: u64,
    maximum_clock_skew_ms: u64,
}

impl VerificationPolicy {
    /// Construct an explicit verification policy.
    ///
    /// # Errors
    ///
    /// Zero limits, a threshold above the expected key count, or a key count
    /// above [`MAX_MAINTAINERS`] are rejected.
    pub fn new(
        minimum_signatures: usize,
        expected_maintainers: usize,
        maximum_lifetime_ms: u64,
        maximum_clock_skew_ms: u64,
    ) -> Result<Self, PolicyError> {
        if minimum_signatures == 0
            || expected_maintainers == 0
            || minimum_signatures > expected_maintainers
            || expected_maintainers > MAX_MAINTAINERS
            || maximum_lifetime_ms == 0
        {
            return Err(PolicyError::InvalidField("verification policy limits"));
        }
        Ok(Self {
            minimum_signatures,
            expected_maintainers,
            maximum_lifetime_ms,
            maximum_clock_skew_ms,
        })
    }

    /// Return the local minimum valid-signature threshold.
    #[must_use]
    pub const fn minimum_signatures(self) -> usize {
        self.minimum_signatures
    }

    /// Return the exact number of trusted maintainers expected by this node.
    #[must_use]
    pub const fn expected_maintainers(self) -> usize {
        self.expected_maintainers
    }

    /// Return the longest accepted activation-to-expiry duration.
    #[must_use]
    pub const fn maximum_lifetime_ms(self) -> u64 {
        self.maximum_lifetime_ms
    }

    /// Return the tolerated future skew for the signed issuance timestamp.
    #[must_use]
    pub const fn maximum_clock_skew_ms(self) -> u64 {
        self.maximum_clock_skew_ms
    }
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            minimum_signatures: DEFAULT_MINIMUM_SIGNATURES,
            expected_maintainers: DEFAULT_MAINTAINER_COUNT,
            maximum_lifetime_ms: DEFAULT_MAXIMUM_MANIFEST_LIFETIME_MS,
            maximum_clock_skew_ms: DEFAULT_MAXIMUM_CLOCK_SKEW_MS,
        }
    }
}

/// The unsigned semantic contents from which a canonical manifest is built.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestSpec {
    manifest_version: u64,
    minimum_protocol_version: u32,
    issued_at_ms: u64,
    valid_from_ms: u64,
    expires_at_ms: u64,
    required_signatures: usize,
    rules: Vec<DestinationRule>,
}

impl ManifestSpec {
    /// Construct an empty fail-closed manifest specification.
    ///
    /// The manifest initially authorizes no destination and uses the standard
    /// three-signature threshold. Rules must be added explicitly.
    ///
    /// # Errors
    ///
    /// Zero versions/timestamps and invalid time ordering are rejected.
    pub fn new(
        manifest_version: u64,
        minimum_protocol_version: u32,
        issued_at_ms: u64,
        valid_from_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, PolicyError> {
        if manifest_version == 0 || minimum_protocol_version == 0 {
            return Err(PolicyError::InvalidField("manifest or protocol version"));
        }
        validate_time_order(issued_at_ms, valid_from_ms, expires_at_ms)?;
        Ok(Self {
            manifest_version,
            minimum_protocol_version,
            issued_at_ms,
            valid_from_ms,
            expires_at_ms,
            required_signatures: DEFAULT_MINIMUM_SIGNATURES,
            rules: Vec::new(),
        })
    }

    /// Set the signature threshold committed by the manifest body.
    ///
    /// Local verification policy can require a higher threshold but never a
    /// lower one.
    ///
    /// # Errors
    ///
    /// Zero and values above [`MAX_MAINTAINERS`] are rejected.
    pub fn with_required_signatures(
        mut self,
        required_signatures: usize,
    ) -> Result<Self, PolicyError> {
        if required_signatures == 0 || required_signatures > MAX_MAINTAINERS {
            return Err(PolicyError::InvalidField("manifest signature threshold"));
        }
        self.required_signatures = required_signatures;
        Ok(self)
    }

    /// Add one unique destination selector.
    ///
    /// # Errors
    ///
    /// Duplicate destination selectors and manifests exceeding the fixed rule
    /// or total-permission limits are rejected.
    pub fn add_rule(&mut self, rule: DestinationRule) -> Result<(), PolicyError> {
        if self.rules.len() == MAX_DESTINATION_RULES {
            return Err(PolicyError::TooManyItems {
                what: "destination rules",
                maximum: MAX_DESTINATION_RULES,
            });
        }
        if self
            .rules
            .iter()
            .any(|existing| existing.destination_cmp(&rule) == Ordering::Equal)
        {
            return Err(PolicyError::DuplicateItem("destination rule"));
        }
        let current_permissions = self
            .rules
            .iter()
            .try_fold(0_usize, |total, existing| {
                total.checked_add(existing.permissions().len())
            })
            .ok_or(PolicyError::ResourceLimit("total manifest permissions"))?;
        if current_permissions
            .checked_add(rule.permissions().len())
            .is_none_or(|total| total > MAX_TOTAL_PERMISSIONS)
        {
            return Err(PolicyError::TooManyItems {
                what: "total protocol/port permissions",
                maximum: MAX_TOTAL_PERMISSIONS,
            });
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Return the monotonically assigned manifest version.
    #[must_use]
    pub const fn manifest_version(&self) -> u64 {
        self.manifest_version
    }

    /// Return the oldest VOLPAROSSA policy protocol accepted by the manifest.
    #[must_use]
    pub const fn minimum_protocol_version(&self) -> u32 {
        self.minimum_protocol_version
    }

    /// Return the signed issuance time in Unix milliseconds.
    #[must_use]
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Return the activation time in Unix milliseconds.
    #[must_use]
    pub const fn valid_from_ms(&self) -> u64 {
        self.valid_from_ms
    }

    /// Return the exclusive expiry time in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Return the threshold committed by this manifest.
    #[must_use]
    pub const fn required_signatures(&self) -> usize {
        self.required_signatures
    }

    /// Return all destination rules in insertion order.
    #[must_use]
    pub fn rules(&self) -> &[DestinationRule] {
        &self.rules
    }
}

/// A fully verified, active-at-load-time whitelist manifest.
///
/// Authorization methods require the current time again so a cached manifest
/// cannot silently continue authorizing new flows after expiry.
#[derive(Clone, Debug)]
pub struct VerifiedManifest {
    manifest_version: u64,
    minimum_protocol_version: u32,
    issued_at_ms: u64,
    valid_from_ms: u64,
    expires_at_ms: u64,
    required_signatures: usize,
    verified_signatures: usize,
    policy_hash: [u8; HASH_BYTES],
    rules: Vec<DestinationRule>,
}

impl VerifiedManifest {
    /// Return the manifest version.
    #[must_use]
    pub const fn manifest_version(&self) -> u64 {
        self.manifest_version
    }

    /// Return the minimum policy protocol version committed by the manifest.
    #[must_use]
    pub const fn minimum_protocol_version(&self) -> u32 {
        self.minimum_protocol_version
    }

    /// Return the signed issuance time in Unix milliseconds.
    #[must_use]
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Return the activation time in Unix milliseconds.
    #[must_use]
    pub const fn valid_from_ms(&self) -> u64 {
        self.valid_from_ms
    }

    /// Return the exclusive expiry time in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Return the signature threshold committed by the manifest.
    #[must_use]
    pub const fn required_signatures(&self) -> usize {
        self.required_signatures
    }

    /// Return the number of distinct valid trusted signatures verified.
    #[must_use]
    pub const fn verified_signatures(&self) -> usize {
        self.verified_signatures
    }

    /// Return the SHA-256 digest of the canonical manifest body.
    ///
    /// This stable policy hash commits rules, validity, protocol requirements,
    /// threshold, and the maintainer set, but not the detachable signatures.
    #[must_use]
    pub const fn policy_hash(&self) -> &[u8; HASH_BYTES] {
        &self.policy_hash
    }

    /// Return the canonical, sorted destination rules.
    #[must_use]
    pub fn rules(&self) -> &[DestinationRule] {
        &self.rules
    }

    /// Fail closed unless this manifest is active at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::NotYetValid`] or [`PolicyError::Expired`] outside
    /// the signed activation window.
    pub fn ensure_active_at(&self, now_ms: u64) -> Result<(), PolicyError> {
        if now_ms < self.valid_from_ms {
            return Err(PolicyError::NotYetValid);
        }
        if now_ms >= self.expires_at_ms {
            return Err(PolicyError::Expired);
        }
        Ok(())
    }

    /// Authorize an IDNA-normalized hostname and exact protocol/port tuple.
    ///
    /// Raw-IP spellings are rejected here and must use [`Self::authorize_ip`].
    ///
    /// # Errors
    ///
    /// Returns an input-validation or time error, or [`PolicyError::Denied`]
    /// when no exact/wildcard rule authorizes the tuple.
    pub fn authorize_domain(
        &self,
        now_ms: u64,
        domain: &str,
        protocol: TransportProtocol,
        port: u16,
    ) -> Result<(), PolicyError> {
        self.ensure_active_at(now_ms)?;
        let request = NormalizedRequest::domain(domain, protocol, port)?;
        self.authorize_normalized(&request)
    }

    /// Authorize one exact raw IP and protocol/port tuple.
    ///
    /// Domain and wildcard rules can never authorize this request.
    ///
    /// # Errors
    ///
    /// Returns a port or time error, or [`PolicyError::Denied`] unless the exact
    /// address and tuple are present in one manifest rule.
    pub fn authorize_ip(
        &self,
        now_ms: u64,
        address: IpAddr,
        protocol: TransportProtocol,
        port: u16,
    ) -> Result<(), PolicyError> {
        self.ensure_active_at(now_ms)?;
        let request = NormalizedRequest::ip(address, protocol, port)?;
        self.authorize_normalized(&request)
    }

    fn authorize_normalized(&self, request: &NormalizedRequest) -> Result<(), PolicyError> {
        if self.rules.iter().any(|rule| rule.is_allowed(request)) {
            Ok(())
        } else {
            Err(PolicyError::Denied)
        }
    }
}

/// Build and threshold-sign a canonical manifest.
///
/// Every signing key must belong to `trust_store`. Duplicate and untrusted
/// signers are rejected, and at least the manifest-committed threshold must be
/// present. The standard [`VerificationPolicy`] additionally requires three of
/// exactly five trusted maintainers when the result is loaded.
///
/// # Errors
///
/// Returns an error for invalid structure, trust mismatch, insufficient or
/// duplicate signing keys, or an oversized encoded manifest.
pub fn sign_manifest(
    specification: &ManifestSpec,
    trust_store: &TrustStore,
    signing_keys: &[&SigningKey],
) -> Result<Vec<u8>, PolicyError> {
    validate_spec_for_signing(specification, trust_store)?;
    if signing_keys.len() > MAX_SIGNATURES {
        return Err(PolicyError::TooManyItems {
            what: "manifest signatures",
            maximum: MAX_SIGNATURES,
        });
    }

    let body = body_from_spec(specification, trust_store)?;
    let body_bytes = encode_canonical(&body, MAX_MANIFEST_BODY_BYTES)?;
    let policy_hash: [u8; HASH_BYTES] = Sha256::digest(&body_bytes).into();
    let signed_input = signature_input(&body_bytes, &policy_hash);

    let mut signatures = Vec::with_capacity(signing_keys.len());
    for signing_key in signing_keys {
        let verifying_key = signing_key.verifying_key();
        let key_id = maintainer_id(&verifying_key.to_bytes());
        let trusted = trust_store
            .find_key(&key_id)
            .ok_or(PolicyError::UntrustedSigner)?;
        if trusted.verifying_key.to_bytes() != verifying_key.to_bytes() {
            return Err(PolicyError::UntrustedSigner);
        }
        signatures.push(ManifestSignatureProto {
            key_id: key_id.to_vec(),
            signature: signing_key.sign(&signed_input).to_bytes().to_vec(),
        });
    }
    signatures.sort_unstable_by(|left, right| left.key_id.cmp(&right.key_id));
    if signatures
        .windows(2)
        .any(|pair| pair[0].key_id == pair[1].key_id)
    {
        return Err(PolicyError::DuplicateItem("manifest signature"));
    }
    if signatures.len() < specification.required_signatures {
        return Err(PolicyError::InsufficientSignatures {
            required: specification.required_signatures,
            valid: signatures.len(),
        });
    }

    encode_canonical(
        &SignedManifestProto {
            body: Some(body),
            body_hash: policy_hash.to_vec(),
            signatures,
        },
        MAX_SIGNED_MANIFEST_BYTES,
    )
}

/// Decode and verify a canonical threshold-signed manifest.
///
/// Verification includes canonical protobuf round-tripping, all resource
/// bounds, schema and protocol versions, time ordering and expiry, body hash,
/// exact trust-root equality, production-key policy, sorted set invariants,
/// strict Ed25519 signatures, and the local/manifest signature thresholds.
///
/// # Errors
///
/// Any ambiguity or failed check returns [`PolicyError`] and no usable policy.
pub fn verify_manifest(
    encoded: &[u8],
    now_ms: u64,
    trust_store: &TrustStore,
    verification_policy: VerificationPolicy,
) -> Result<VerifiedManifest, PolicyError> {
    validate_verification_context(trust_store, verification_policy)?;
    let signed: SignedManifestProto = decode_canonical(encoded, MAX_SIGNED_MANIFEST_BYTES)?;
    let body = signed
        .body
        .as_ref()
        .ok_or(PolicyError::InvalidField("missing manifest body"))?;
    validate_body_header(body, now_ms, verification_policy)?;
    validate_embedded_trust(body, trust_store, verification_policy)?;
    let rules = rules_from_body(body)?;

    let body_bytes = encode_canonical(body, MAX_MANIFEST_BODY_BYTES)?;
    let computed_hash: [u8; HASH_BYTES] = Sha256::digest(&body_bytes).into();
    if signed.body_hash.len() != HASH_BYTES
        || signed
            .body_hash
            .as_slice()
            .ct_eq(computed_hash.as_slice())
            .unwrap_u8()
            != 1
    {
        return Err(PolicyError::ManifestHashMismatch);
    }

    let verified_signatures =
        verify_signatures(&signed.signatures, &body_bytes, &computed_hash, trust_store)?;
    let body_threshold = usize::try_from(body.required_signatures)
        .map_err(|_| PolicyError::InvalidField("manifest signature threshold"))?;
    let required = body_threshold.max(verification_policy.minimum_signatures);
    if verified_signatures < required {
        return Err(PolicyError::InsufficientSignatures {
            required,
            valid: verified_signatures,
        });
    }

    Ok(VerifiedManifest {
        manifest_version: body.manifest_version,
        minimum_protocol_version: body.minimum_protocol_version,
        issued_at_ms: body.issued_at_ms,
        valid_from_ms: body.valid_from_ms,
        expires_at_ms: body.expires_at_ms,
        required_signatures: body_threshold,
        verified_signatures,
        policy_hash: computed_hash,
        rules,
    })
}

/// Errors returned while constructing, signing, verifying, or applying a
/// whitelist manifest.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// An encoded or repeated value exceeds a hard resource bound.
    #[error("{what} exceeds the maximum of {maximum}")]
    Oversized {
        /// Name of the oversized value.
        what: &'static str,
        /// Maximum accepted size or count.
        maximum: usize,
    },

    /// A repeated set contains too many entries.
    #[error("{what} exceeds the maximum count of {maximum}")]
    TooManyItems {
        /// Name of the bounded collection.
        what: &'static str,
        /// Maximum accepted entry count.
        maximum: usize,
    },

    /// A checked resource-count calculation overflowed.
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(&'static str),

    /// Protobuf encoding failed.
    #[error("policy protobuf encoding failed: {0}")]
    Encode(#[from] prost::EncodeError),

    /// Protobuf decoding failed.
    #[error("policy protobuf decoding failed: {0}")]
    Decode(#[from] prost::DecodeError),

    /// The bytes decode as protobuf but are not the unique accepted encoding.
    #[error("non-canonical policy protobuf")]
    NonCanonicalProtobuf,

    /// A normalized set-like field was not in its canonical semantic form.
    #[error("non-canonical policy field: {0}")]
    NonCanonicalSemantic(&'static str),

    /// The manifest uses an unsupported protobuf schema version.
    #[error("unsupported manifest schema version {0}")]
    UnsupportedSchemaVersion(u32),

    /// The manifest requires a newer policy protocol implementation.
    #[error("manifest requires policy protocol {minimum}, but this node supports {supported}")]
    UnsupportedProtocolVersion {
        /// Minimum version required by the manifest.
        minimum: u32,
        /// Version implemented by this node.
        supported: u32,
    },

    /// A structural field is absent, unknown, or semantically invalid.
    #[error("invalid policy field: {0}")]
    InvalidField(&'static str),

    /// A DNS name failed bounded URL-host/IDNA and DNS label validation.
    #[error("invalid destination domain")]
    InvalidDomain,

    /// An input accepted only for domain authorization was an IP spelling.
    #[error("raw IP destination must use an exact IP policy rule")]
    RawIpAsDomain,

    /// A wildcard was malformed or broader than the supported label pattern.
    #[error("invalid wildcard domain pattern")]
    InvalidWildcard,

    /// A destination port is zero or outside the 16-bit range.
    #[error("invalid destination port {0}")]
    InvalidPort(u32),

    /// A set-like field contains a duplicate entry.
    #[error("duplicate policy item: {0}")]
    DuplicateItem(&'static str),

    /// Signed time fields do not form a positive, bounded validity window.
    #[error("invalid manifest validity window")]
    InvalidTimeWindow,

    /// The manifest is not active yet.
    #[error("policy manifest is not yet valid")]
    NotYetValid,

    /// The manifest has reached its exclusive expiry time.
    #[error("policy manifest has expired")]
    Expired,

    /// The canonical manifest body does not match its committed SHA-256 hash.
    #[error("policy manifest body hash mismatch")]
    ManifestHashMismatch,

    /// The local trust store or embedded maintainer count is not the expected size.
    #[error("expected {expected} policy maintainers, received {actual}")]
    MaintainerCount {
        /// Exact count required by local verification policy.
        expected: usize,
        /// Count found in the relevant key set.
        actual: usize,
    },

    /// The manifest's embedded trust metadata differs from local trusted keys.
    #[error("manifest maintainer set does not match the local trust root")]
    TrustRootMismatch,

    /// Production mode encountered a development maintainer key.
    #[error("development policy maintainer keys are forbidden in production mode")]
    DevelopmentKeyRejected,

    /// A signature identifies no key in the independently configured trust root.
    #[error("policy manifest contains an untrusted signer")]
    UntrustedSigner,

    /// An Ed25519 signature is malformed or fails strict verification.
    #[error("invalid policy manifest Ed25519 signature")]
    InvalidSignature,

    /// Fewer distinct trusted signatures were valid than required.
    #[error("insufficient policy signatures: required {required}, valid {valid}")]
    InsufficientSignatures {
        /// Effective local/manifest threshold.
        required: usize,
        /// Number of distinct valid signatures.
        valid: usize,
    },

    /// No rule authorizes the exact destination, protocol, and port tuple.
    #[error("destination denied by whitelist policy")]
    Denied,
}

fn maintainer_id(public_key: &[u8; PUBLIC_KEY_BYTES]) -> [u8; HASH_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(MAINTAINER_ID_DOMAIN);
    hasher.update(public_key);
    hasher.finalize().into()
}

fn signature_input(body: &[u8], policy_hash: &[u8; HASH_BYTES]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + HASH_BYTES + body.len());
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.extend_from_slice(policy_hash);
    input.extend_from_slice(body);
    input
}

fn validate_time_order(
    issued_at_ms: u64,
    valid_from_ms: u64,
    expires_at_ms: u64,
) -> Result<u64, PolicyError> {
    if issued_at_ms == 0 || valid_from_ms == 0 || expires_at_ms == 0 {
        return Err(PolicyError::InvalidTimeWindow);
    }
    if issued_at_ms > valid_from_ms {
        return Err(PolicyError::InvalidTimeWindow);
    }
    expires_at_ms
        .checked_sub(valid_from_ms)
        .filter(|lifetime| *lifetime > 0)
        .ok_or(PolicyError::InvalidTimeWindow)
}

fn validate_spec_for_signing(
    specification: &ManifestSpec,
    trust_store: &TrustStore,
) -> Result<(), PolicyError> {
    if specification.manifest_version == 0 || specification.minimum_protocol_version == 0 {
        return Err(PolicyError::InvalidField("manifest or protocol version"));
    }
    validate_time_order(
        specification.issued_at_ms,
        specification.valid_from_ms,
        specification.expires_at_ms,
    )?;
    if specification.required_signatures == 0
        || specification.required_signatures > trust_store.maintainers.len()
    {
        return Err(PolicyError::InvalidField("manifest signature threshold"));
    }
    validate_rules(&specification.rules)
}

fn validate_verification_context(
    trust_store: &TrustStore,
    policy: VerificationPolicy,
) -> Result<(), PolicyError> {
    VerificationPolicy::new(
        policy.minimum_signatures,
        policy.expected_maintainers,
        policy.maximum_lifetime_ms,
        policy.maximum_clock_skew_ms,
    )?;
    if trust_store.maintainers.len() != policy.expected_maintainers {
        return Err(PolicyError::MaintainerCount {
            expected: policy.expected_maintainers,
            actual: trust_store.maintainers.len(),
        });
    }
    if trust_store.mode == PolicyMode::Production
        && trust_store
            .maintainers
            .iter()
            .any(|key| key.environment == MaintainerEnvironment::Development)
    {
        return Err(PolicyError::DevelopmentKeyRejected);
    }
    Ok(())
}

fn validate_body_header(
    body: &ManifestBodyProto,
    now_ms: u64,
    policy: VerificationPolicy,
) -> Result<(), PolicyError> {
    if body.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(PolicyError::UnsupportedSchemaVersion(body.schema_version));
    }
    if body.manifest_version == 0 || body.minimum_protocol_version == 0 {
        return Err(PolicyError::InvalidField("manifest or protocol version"));
    }
    if body.minimum_protocol_version > POLICY_PROTOCOL_VERSION {
        return Err(PolicyError::UnsupportedProtocolVersion {
            minimum: body.minimum_protocol_version,
            supported: POLICY_PROTOCOL_VERSION,
        });
    }
    let lifetime = validate_time_order(body.issued_at_ms, body.valid_from_ms, body.expires_at_ms)?;
    if lifetime > policy.maximum_lifetime_ms {
        return Err(PolicyError::InvalidTimeWindow);
    }
    if body.issued_at_ms > now_ms.saturating_add(policy.maximum_clock_skew_ms)
        || body.valid_from_ms > now_ms
    {
        return Err(PolicyError::NotYetValid);
    }
    if body.expires_at_ms <= now_ms {
        return Err(PolicyError::Expired);
    }
    Ok(())
}

fn validate_embedded_trust(
    body: &ManifestBodyProto,
    trust_store: &TrustStore,
    policy: VerificationPolicy,
) -> Result<(), PolicyError> {
    if body.maintainers.len() != policy.expected_maintainers {
        return Err(PolicyError::MaintainerCount {
            expected: policy.expected_maintainers,
            actual: body.maintainers.len(),
        });
    }
    let threshold = usize::try_from(body.required_signatures)
        .map_err(|_| PolicyError::InvalidField("manifest signature threshold"))?;
    if threshold == 0 || threshold > body.maintainers.len() {
        return Err(PolicyError::InvalidField("manifest signature threshold"));
    }

    let mut previous_id: Option<[u8; HASH_BYTES]> = None;
    for (embedded, trusted) in body.maintainers.iter().zip(&trust_store.maintainers) {
        let key_id = fixed_bytes::<HASH_BYTES>(&embedded.key_id, "maintainer key ID")?;
        let public_key =
            fixed_bytes::<PUBLIC_KEY_BYTES>(&embedded.public_key, "maintainer public key")?;
        let environment = MaintainerEnvironment::from_wire(embedded.environment)?;
        if previous_id.is_some_and(|previous| previous >= key_id) {
            return Err(PolicyError::NonCanonicalSemantic("maintainer ordering"));
        }
        previous_id = Some(key_id);
        if maintainer_id(&public_key) != key_id {
            return Err(PolicyError::TrustRootMismatch);
        }
        if trust_store.mode == PolicyMode::Production
            && environment == MaintainerEnvironment::Development
        {
            return Err(PolicyError::DevelopmentKeyRejected);
        }
        if key_id != trusted.key_id
            || public_key != trusted.verifying_key.to_bytes()
            || environment != trusted.environment
        {
            return Err(PolicyError::TrustRootMismatch);
        }
    }
    Ok(())
}

fn verify_signatures(
    signatures: &[ManifestSignatureProto],
    body_bytes: &[u8],
    policy_hash: &[u8; HASH_BYTES],
    trust_store: &TrustStore,
) -> Result<usize, PolicyError> {
    if signatures.len() > MAX_SIGNATURES || signatures.len() > trust_store.maintainers.len() {
        return Err(PolicyError::TooManyItems {
            what: "manifest signatures",
            maximum: trust_store.maintainers.len().min(MAX_SIGNATURES),
        });
    }
    let input = signature_input(body_bytes, policy_hash);
    let mut previous_id: Option<[u8; HASH_BYTES]> = None;
    let mut valid = 0_usize;
    for signed in signatures {
        let key_id = fixed_bytes::<HASH_BYTES>(&signed.key_id, "signature key ID")?;
        if previous_id.is_some_and(|previous| previous >= key_id) {
            return Err(PolicyError::NonCanonicalSemantic("signature ordering"));
        }
        previous_id = Some(key_id);
        let trusted = trust_store
            .find_key(&key_id)
            .ok_or(PolicyError::UntrustedSigner)?;
        let signature_bytes = fixed_bytes::<SIGNATURE_BYTES>(&signed.signature, "signature")?;
        let signature = Signature::from_bytes(&signature_bytes);
        trusted
            .verifying_key
            .verify_strict(&input, &signature)
            .map_err(|_| PolicyError::InvalidSignature)?;
        valid = valid
            .checked_add(1)
            .ok_or(PolicyError::ResourceLimit("valid signature count"))?;
    }
    Ok(valid)
}

fn body_from_spec(
    specification: &ManifestSpec,
    trust_store: &TrustStore,
) -> Result<ManifestBodyProto, PolicyError> {
    let maintainers = trust_store
        .maintainers
        .iter()
        .map(|maintainer| MaintainerProto {
            key_id: maintainer.key_id.to_vec(),
            public_key: maintainer.verifying_key.to_bytes().to_vec(),
            environment: maintainer.environment.wire_value(),
        })
        .collect();
    let mut sorted_rules = specification.rules.clone();
    sorted_rules.sort_unstable_by(DestinationRule::destination_cmp);
    let rules = sorted_rules
        .iter()
        .map(rule_to_proto)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ManifestBodyProto {
        schema_version: MANIFEST_SCHEMA_VERSION,
        manifest_version: specification.manifest_version,
        minimum_protocol_version: specification.minimum_protocol_version,
        issued_at_ms: specification.issued_at_ms,
        valid_from_ms: specification.valid_from_ms,
        expires_at_ms: specification.expires_at_ms,
        required_signatures: u32::try_from(specification.required_signatures)
            .map_err(|_| PolicyError::InvalidField("manifest signature threshold"))?,
        maintainers,
        rules,
    })
}

fn rule_to_proto(rule: &DestinationRule) -> Result<DestinationRuleProto, PolicyError> {
    let destination = if let Some(domain) = rule.exact_domain_wire() {
        destination_rule_proto::Destination::ExactDomain(domain.to_owned())
    } else if let Some(pattern) = rule.wildcard_domain_wire() {
        destination_rule_proto::Destination::WildcardDomain(pattern)
    } else if let Some(address) = rule.ip_wire() {
        destination_rule_proto::Destination::ExactIp(match address {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        })
    } else {
        return Err(PolicyError::InvalidField("destination selector"));
    };
    let permissions = rule
        .permissions()
        .iter()
        .map(|permission| ProtocolPortProto {
            protocol: permission.protocol().wire_value(),
            port: u32::from(permission.port()),
        })
        .collect();
    Ok(DestinationRuleProto {
        destination: Some(destination),
        permissions,
    })
}

fn rules_from_body(body: &ManifestBodyProto) -> Result<Vec<DestinationRule>, PolicyError> {
    if body.rules.len() > MAX_DESTINATION_RULES {
        return Err(PolicyError::TooManyItems {
            what: "destination rules",
            maximum: MAX_DESTINATION_RULES,
        });
    }
    let mut rules = Vec::with_capacity(body.rules.len());
    let mut total_permissions = 0_usize;
    for wire_rule in &body.rules {
        if wire_rule.permissions.is_empty()
            || wire_rule.permissions.len() > MAX_PERMISSIONS_PER_DESTINATION
        {
            return Err(PolicyError::InvalidField("destination permission count"));
        }
        total_permissions = total_permissions
            .checked_add(wire_rule.permissions.len())
            .ok_or(PolicyError::ResourceLimit("total manifest permissions"))?;
        if total_permissions > MAX_TOTAL_PERMISSIONS {
            return Err(PolicyError::TooManyItems {
                what: "total protocol/port permissions",
                maximum: MAX_TOTAL_PERMISSIONS,
            });
        }
        let permissions = wire_rule
            .permissions
            .iter()
            .map(|permission| ProtocolPort::from_wire(permission.protocol, permission.port))
            .collect::<Result<Vec<_>, _>>()?;
        if !strictly_sorted(&permissions) {
            return Err(PolicyError::NonCanonicalSemantic(
                "protocol/port permission ordering",
            ));
        }
        let rule = match wire_rule
            .destination
            .clone()
            .ok_or(PolicyError::InvalidField("destination selector"))?
        {
            destination_rule_proto::Destination::ExactDomain(domain) => {
                DestinationRule::from_wire_exact_domain(&domain, permissions)?
            }
            destination_rule_proto::Destination::WildcardDomain(pattern) => {
                DestinationRule::from_wire_wildcard_domain(&pattern, permissions)?
            }
            destination_rule_proto::Destination::ExactIp(address) => {
                DestinationRule::from_wire_ip(ip_from_wire(&address)?, permissions)?
            }
        };
        if rules.last().is_some_and(|previous: &DestinationRule| {
            previous.destination_cmp(&rule) != Ordering::Less
        }) {
            return Err(PolicyError::NonCanonicalSemantic(
                "destination rule ordering",
            ));
        }
        rules.push(rule);
    }
    Ok(rules)
}

fn validate_rules(rules: &[DestinationRule]) -> Result<(), PolicyError> {
    if rules.len() > MAX_DESTINATION_RULES {
        return Err(PolicyError::TooManyItems {
            what: "destination rules",
            maximum: MAX_DESTINATION_RULES,
        });
    }
    let mut sorted = rules.iter().collect::<Vec<_>>();
    sorted.sort_unstable_by(|left, right| left.destination_cmp(right));
    if sorted
        .windows(2)
        .any(|pair| pair[0].destination_cmp(pair[1]) == Ordering::Equal)
    {
        return Err(PolicyError::DuplicateItem("destination rule"));
    }
    let total = rules.iter().try_fold(0_usize, |count, rule| {
        count.checked_add(rule.permissions().len())
    });
    if total.is_none_or(|count| count > MAX_TOTAL_PERMISSIONS) {
        return Err(PolicyError::TooManyItems {
            what: "total protocol/port permissions",
            maximum: MAX_TOTAL_PERMISSIONS,
        });
    }
    Ok(())
}

fn ip_from_wire(encoded: &[u8]) -> Result<IpAddr, PolicyError> {
    match encoded.len() {
        4 => {
            let octets = fixed_bytes::<4>(encoded, "IPv4 address")?;
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        16 => {
            let octets = fixed_bytes::<16>(encoded, "IPv6 address")?;
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(PolicyError::InvalidField("exact IP address")),
    }
}

fn fixed_bytes<const LENGTH: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; LENGTH], PolicyError> {
    bytes
        .try_into()
        .map_err(|_| PolicyError::InvalidField(field))
}

fn strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_keys() -> Vec<SigningKey> {
        (1_u8..=5)
            .map(|byte| SigningKey::from_bytes(&[byte; 32]))
            .collect()
    }

    fn production_store(keys: &[SigningKey]) -> TrustStore {
        TrustStore::new(
            PolicyMode::Production,
            keys.iter()
                .map(|key| TrustedMaintainer::production(key.verifying_key()))
                .collect(),
        )
        .unwrap()
    }

    fn manifest(keys: &[SigningKey]) -> Vec<u8> {
        let store = production_store(keys);
        let mut specification = ManifestSpec::new(7, 1, 1_000, 1_000, 20_000).unwrap();
        specification
            .add_rule(
                DestinationRule::exact_domain(
                    "example.com",
                    [ProtocolPort::new(TransportProtocol::Tcp, 443).unwrap()],
                )
                .unwrap(),
            )
            .unwrap();
        sign_manifest(&specification, &store, &[&keys[0], &keys[1], &keys[2]]).unwrap()
    }

    #[test]
    fn rejects_non_minimal_or_unknown_protobuf_fields() {
        let keys = signing_keys();
        let mut encoded = manifest(&keys);
        encoded.extend_from_slice(&[0x98, 0x06, 0x01]);
        let result = verify_manifest(
            &encoded,
            2_000,
            &production_store(&keys),
            VerificationPolicy::default(),
        );
        assert!(matches!(result, Err(PolicyError::NonCanonicalProtobuf)));
    }

    #[test]
    fn rejects_body_hash_tampering_before_use() {
        let keys = signing_keys();
        let encoded = manifest(&keys);
        let mut decoded: SignedManifestProto =
            decode_canonical(&encoded, MAX_SIGNED_MANIFEST_BYTES).unwrap();
        decoded.body_hash[0] ^= 1;
        let tampered = encode_canonical(&decoded, MAX_SIGNED_MANIFEST_BYTES).unwrap();
        let result = verify_manifest(
            &tampered,
            2_000,
            &production_store(&keys),
            VerificationPolicy::default(),
        );
        assert!(matches!(result, Err(PolicyError::ManifestHashMismatch)));
    }

    #[test]
    fn rejects_invalid_signature_even_when_threshold_otherwise_remains() {
        let keys = signing_keys();
        let store = production_store(&keys);
        let mut specification = ManifestSpec::new(7, 1, 1_000, 1_000, 20_000).unwrap();
        specification
            .add_rule(
                DestinationRule::exact_domain(
                    "example.com",
                    [ProtocolPort::new(TransportProtocol::Tcp, 443).unwrap()],
                )
                .unwrap(),
            )
            .unwrap();
        let encoded = sign_manifest(
            &specification,
            &store,
            &[&keys[0], &keys[1], &keys[2], &keys[3]],
        )
        .unwrap();
        let mut decoded: SignedManifestProto =
            decode_canonical(&encoded, MAX_SIGNED_MANIFEST_BYTES).unwrap();
        decoded.signatures[0].signature[0] ^= 1;
        let tampered = encode_canonical(&decoded, MAX_SIGNED_MANIFEST_BYTES).unwrap();
        assert!(matches!(
            verify_manifest(&tampered, 2_000, &store, VerificationPolicy::default()),
            Err(PolicyError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_semantically_unsorted_signatures() {
        let keys = signing_keys();
        let encoded = manifest(&keys);
        let mut decoded: SignedManifestProto =
            decode_canonical(&encoded, MAX_SIGNED_MANIFEST_BYTES).unwrap();
        decoded.signatures.swap(0, 1);
        let reordered = encode_canonical(&decoded, MAX_SIGNED_MANIFEST_BYTES).unwrap();
        assert!(matches!(
            verify_manifest(
                &reordered,
                2_000,
                &production_store(&keys),
                VerificationPolicy::default()
            ),
            Err(PolicyError::NonCanonicalSemantic("signature ordering"))
        ));
    }
}
