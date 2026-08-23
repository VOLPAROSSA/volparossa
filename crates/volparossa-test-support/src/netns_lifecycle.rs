//! Strict, bounded control protocol for the disposable network-namespace lifecycle.
//!
//! The protocol deliberately uses a small canonical line format rather than a
//! general-purpose serializer. Every accepted frame has one representation, so
//! a `FINISHED` frame can bind the exact `TOPOLOGY_READY` bytes observed by the
//! outer supervisor.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashSet;

use sha2::{Digest, Sha256 as Sha256Hasher};
use thiserror::Error;

/// Maximum encoded size of any lifecycle frame, including its final line feed.
pub const MAX_LIFECYCLE_FRAME_BYTES: usize = 16 * 1024;
/// Exact and maximum named-network-namespace count in the V1 lifecycle topology.
pub const MAX_LIFECYCLE_NAMESPACES: usize = 2;
/// Maximum byte length of a lifecycle-owned namespace name.
pub const MAX_LIFECYCLE_NAME_BYTES: usize = 63;
/// Maximum byte length of a non-`NONE` completion error code.
pub const MAX_LIFECYCLE_ERROR_CODE_BYTES: usize = 64;

/// Canonical specification hashed by [`LIFECYCLE_TOPOLOGY_SPEC_SHA256`].
///
/// This is intentionally narrow: the first executable slice will measure
/// containment, ownership, probing, and cleanup, but will not claim an
/// A01-A15 datapath.
pub const LIFECYCLE_TOPOLOGY_SPEC: &str = "version=1\n\
parent_network_namespace=anonymous\n\
private_run_mount=true\n\
private_proc_mount=true\n\
named_network_namespaces=2\n\
namespace_names=vpl-{run_id}-a,vpl-{run_id}-b\n\
veth_pairs=2\n\
underlay_interfaces=vpa{run_id[0:8]},vpb{run_id[0:8]}\n\
node_interfaces=eth0,eth0\n\
endpoint_a_ipv4=10.241.1.2/30\n\
underlay_a_ipv4=10.241.1.1/30\n\
endpoint_b_ipv4=10.241.2.2/30\n\
underlay_b_ipv4=10.241.2.1/30\n\
host_links=0\n\
default_routes=0\n\
endpoint_a_route=10.241.2.2/32_via_10.241.1.1\n\
endpoint_b_route=10.241.1.2/32_via_10.241.2.1\n\
underlay_ipv4_forwarding=true\n\
forward_policy=drop\n\
nft_family=inet\n\
nft_table=vpl_{run_id}\n\
nft_chain=forward\n\
nft_allow_a_to_b=ipv4_echo_request_exact_tuple\n\
nft_allow_b_to_a=ipv4_echo_reply_exact_tuple\n\
probe=one_ipv4_icmp_echo_request_and_reply\n\
ownership=namespace_mount_device_and_inode\n\
teardown=reverse_journal_order\n";

/// Lowercase SHA-256 of [`LIFECYCLE_TOPOLOGY_SPEC`].
pub const LIFECYCLE_TOPOLOGY_SPEC_SHA256: &str =
    "0eb82db0f377ab973c1fb26c4dedd153c1694b28b4817f82f56e84a2aaaf0783";

const BOOTSTRAP_READY_HEADER: &str = "VOLPAROSSA_NETNS_LIFECYCLE_V1 BOOTSTRAP_READY";
const GO_HEADER: &str = "VOLPAROSSA_NETNS_LIFECYCLE_V1 GO";
const TOPOLOGY_READY_HEADER: &str = "VOLPAROSSA_NETNS_LIFECYCLE_V1 TOPOLOGY_READY";
const STOP_HEADER: &str = "VOLPAROSSA_NETNS_LIFECYCLE_V1 STOP";
const FINISHED_HEADER: &str = "VOLPAROSSA_NETNS_LIFECYCLE_V1 FINISHED";

/// Validation or sequencing failure in the network-namespace lifecycle protocol.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NetnsLifecycleError {
    /// The encoded frame exceeded the fixed 16-KiB bound.
    #[error("lifecycle frame exceeds its size bound")]
    FrameTooLarge,
    /// The frame was empty or did not end in exactly one line feed.
    #[error("lifecycle frame must end in a line feed")]
    MissingFinalLineFeed,
    /// A carriage return appeared anywhere in the frame.
    #[error("carriage returns are forbidden in lifecycle frames")]
    CarriageReturn,
    /// The frame was not valid UTF-8.
    #[error("lifecycle frame is not UTF-8")]
    Utf8,
    /// The header, field order, field count, or line shape was not canonical.
    #[error("lifecycle frame shape is not canonical")]
    FrameShape,
    /// A run identifier was not exactly 32 lowercase hexadecimal characters.
    #[error("invalid lifecycle run identifier")]
    RunId,
    /// A digest was not exactly 64 lowercase hexadecimal characters.
    #[error("invalid lifecycle SHA-256 digest")]
    Sha256,
    /// A namespace device or inode was zero or not canonical decimal notation.
    #[error("invalid namespace identity")]
    NamespaceIdentity,
    /// A namespace name was empty, too long, or contained unsafe characters.
    #[error("invalid lifecycle namespace name")]
    NamespaceName,
    /// The namespace count did not match the fixed two-endpoint topology.
    #[error("invalid lifecycle namespace count")]
    NamespaceCount,
    /// Namespace names or device/inode identities were not unique.
    #[error("duplicate lifecycle namespace ownership record")]
    DuplicateNamespace,
    /// Bootstrap network, mount, and PID namespace identities were not distinct.
    #[error("bootstrap namespace identities must differ")]
    BootstrapNamespacesNotDistinct,
    /// An inner namespace identity still matched the corresponding original host namespace.
    #[error("bootstrap remained in an original host namespace")]
    BootstrapMatchesHost,
    /// A required bootstrap, handler, or probe assertion was not exactly `true`.
    #[error("required lifecycle assertion was not true")]
    RequiredAssertion,
    /// A decimal integer was non-canonical or outside its permitted bound.
    #[error("invalid bounded lifecycle integer")]
    BoundedInteger,
    /// A stop reason was outside the fixed allowlist.
    #[error("invalid lifecycle stop reason")]
    StopReason,
    /// A completion error code was malformed or used the reserved `NONE` code.
    #[error("invalid lifecycle completion error code")]
    CompletionErrorCode,
    /// Cleanup booleans, remaining count, and completion error contradicted each other.
    #[error("inconsistent lifecycle cleanup result")]
    CleanupConsistency,
    /// A state transition was attempted in the wrong order or more than once.
    #[error("invalid lifecycle state transition")]
    StateTransition,
    /// A frame or authorization carried a different run identifier.
    #[error("lifecycle run identifier mismatch")]
    RunIdMismatch,
    /// A frame did not carry the fixed topology specification digest.
    #[error("lifecycle topology specification digest mismatch")]
    TopologySpecificationMismatch,
    /// `FINISHED` did not bind the exact `TOPOLOGY_READY` frame bytes.
    #[error("finished frame does not bind the observed topology frame")]
    TopologyFrameDigestMismatch,
}

/// Canonical per-run nonce used by every frame in one lifecycle exchange.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RunId(String);

impl RunId {
    /// Parse exactly 32 lowercase hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::RunId`] for every non-canonical value.
    pub fn parse(value: &str) -> Result<Self, NetnsLifecycleError> {
        if !is_lower_hex(value, 32) {
            return Err(NetnsLifecycleError::RunId);
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the canonical hexadecimal representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical lowercase SHA-256 value carried by the lifecycle protocol.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LifecycleSha256(String);

impl LifecycleSha256 {
    /// Parse exactly 64 lowercase hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::Sha256`] for every non-canonical value.
    pub fn parse(value: &str) -> Result<Self, NetnsLifecycleError> {
        if !is_lower_hex(value, 64) {
            return Err(NetnsLifecycleError::Sha256);
        }
        Ok(Self(value.to_owned()))
    }

    /// Hash exact bytes with SHA-256.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256Hasher::digest(bytes)))
    }

    /// Return the canonical hexadecimal representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable device/inode identity of a Linux namespace object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NamespaceIdentity {
    device: u64,
    inode: u64,
}

impl NamespaceIdentity {
    /// Construct a nonzero device/inode identity.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::NamespaceIdentity`] when either value is zero.
    pub const fn new(device: u64, inode: u64) -> Result<Self, NetnsLifecycleError> {
        if device == 0 || inode == 0 {
            return Err(NetnsLifecycleError::NamespaceIdentity);
        }
        Ok(Self { device, inode })
    }

    /// Namespace backing-device number.
    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    /// Namespace inode number.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }
}

/// One named network namespace owned by the disposable topology.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedNamespace {
    name: String,
    identity: NamespaceIdentity,
}

impl OwnedNamespace {
    /// Construct a safe named-namespace ownership record.
    ///
    /// Names are ASCII, begin with an alphanumeric character, and may then use
    /// alphanumerics, `-`, `_`, or `.` up to 63 bytes. Slashes and traversal
    /// components therefore cannot enter `/run/netns` operations.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::NamespaceName`] for an unsafe name.
    pub fn new(name: String, identity: NamespaceIdentity) -> Result<Self, NetnsLifecycleError> {
        if !is_safe_name(&name) {
            return Err(NetnsLifecycleError::NamespaceName);
        }
        Ok(Self { name, identity })
    }

    /// Safe namespace name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Device/inode identity captured immediately after namespace creation.
    #[must_use]
    pub const fn identity(&self) -> NamespaceIdentity {
        self.identity
    }
}

/// Fixed reason carried in an outer-supervisor `STOP` frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// Normal completion of the lifecycle probe.
    Normal,
    /// Supervisor received `SIGHUP`.
    Hup,
    /// Supervisor received `SIGINT`.
    Int,
    /// Supervisor received `SIGTERM`.
    Term,
    /// Supervisor's bounded execution deadline expired.
    Timeout,
}

impl StopReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Hup => "HUP",
            Self::Int => "INT",
            Self::Term => "TERM",
            Self::Timeout => "TIMEOUT",
        }
    }

    fn parse(value: &str) -> Result<Self, NetnsLifecycleError> {
        match value {
            "NORMAL" => Ok(Self::Normal),
            "HUP" => Ok(Self::Hup),
            "INT" => Ok(Self::Int),
            "TERM" => Ok(Self::Term),
            "TIMEOUT" => Ok(Self::Timeout),
            _ => Err(NetnsLifecycleError::StopReason),
        }
    }
}

/// Completion error field from a `FINISHED` frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompletionError {
    /// No lifecycle or cleanup error occurred.
    None,
    /// A bounded uppercase machine error code.
    Code(String),
}

impl CompletionError {
    /// Construct an uppercase machine error code other than the reserved `NONE`.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::CompletionErrorCode`] for a malformed code.
    pub fn code(value: String) -> Result<Self, NetnsLifecycleError> {
        if !is_error_code(&value) || value == "NONE" {
            return Err(NetnsLifecycleError::CompletionErrorCode);
        }
        Ok(Self::Code(value))
    }

    /// Return `NONE` or the validated uppercase code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "NONE",
            Self::Code(code) => code,
        }
    }

    fn parse(value: &str) -> Result<Self, NetnsLifecycleError> {
        if value == "NONE" {
            return Ok(Self::None);
        }
        Self::code(value.to_owned())
    }
}

/// Inner sandbox attestation emitted before the outer supervisor may authorize mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapReady {
    run_id: RunId,
    network_namespace: NamespaceIdentity,
    mount_namespace: NamespaceIdentity,
    pid_namespace: NamespaceIdentity,
}

impl BootstrapReady {
    /// Construct an attestation with distinct network, mount, and PID namespace identities.
    ///
    /// The fixed inner worker must measure every assertion immediately before
    /// construction. The encoded frame always asserts PID-1 placement, private
    /// `/run` and `/proc`, private mount propagation, pristine loopback-only
    /// networking, installed handlers, and the parent-death chain as `true`;
    /// callers cannot construct a weaker frame.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::BootstrapNamespacesNotDistinct`] when any
    /// two namespace identities are equal.
    pub fn new(
        run_id: RunId,
        network_namespace: NamespaceIdentity,
        mount_namespace: NamespaceIdentity,
        pid_namespace: NamespaceIdentity,
    ) -> Result<Self, NetnsLifecycleError> {
        if network_namespace == mount_namespace
            || network_namespace == pid_namespace
            || mount_namespace == pid_namespace
        {
            return Err(NetnsLifecycleError::BootstrapNamespacesNotDistinct);
        }
        Ok(Self {
            run_id,
            network_namespace,
            mount_namespace,
            pid_namespace,
        })
    }

    /// Run identifier bound to this attestation.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Anonymous network namespace identity.
    #[must_use]
    pub const fn network_namespace(&self) -> NamespaceIdentity {
        self.network_namespace
    }

    /// Private mount namespace identity.
    #[must_use]
    pub const fn mount_namespace(&self) -> NamespaceIdentity {
        self.mount_namespace
    }

    /// Inner PID namespace identity.
    #[must_use]
    pub const fn pid_namespace(&self) -> NamespaceIdentity {
        self.pid_namespace
    }

    /// Encode the canonical frame.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::FrameTooLarge`] if the protocol bound is
    /// violated by a future format change.
    pub fn encode(&self) -> Result<String, NetnsLifecycleError> {
        encode_lines(&[
            BOOTSTRAP_READY_HEADER.to_owned(),
            format!("run_id={}", self.run_id.as_str()),
            format!("net_ns_dev={}", self.network_namespace.device()),
            format!("net_ns_inode={}", self.network_namespace.inode()),
            format!("mount_ns_dev={}", self.mount_namespace.device()),
            format!("mount_ns_inode={}", self.mount_namespace.inode()),
            format!("pid_ns_dev={}", self.pid_namespace.device()),
            format!("pid_ns_inode={}", self.pid_namespace.inode()),
            "pid_one=true".to_owned(),
            "private_run=true".to_owned(),
            "private_proc=true".to_owned(),
            "mount_propagation_private=true".to_owned(),
            "network_pristine=true".to_owned(),
            "handlers_installed=true".to_owned(),
            "parent_death_chain=true".to_owned(),
        ])
    }

    /// Parse one exact canonical `BOOTSTRAP_READY` frame.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for malformed, reordered, duplicated, weakened,
    /// oversized, or non-canonical input.
    pub fn parse(bytes: &[u8]) -> Result<Self, NetnsLifecycleError> {
        let lines = decode_lines(bytes)?;
        if lines.len() != 15 || lines[0] != BOOTSTRAP_READY_HEADER {
            return Err(NetnsLifecycleError::FrameShape);
        }
        let run_id = RunId::parse(field(&lines, 1, "run_id")?)?;
        let network_namespace = NamespaceIdentity::new(
            parse_nonzero_decimal(field(&lines, 2, "net_ns_dev")?)?,
            parse_nonzero_decimal(field(&lines, 3, "net_ns_inode")?)?,
        )?;
        let mount_namespace = NamespaceIdentity::new(
            parse_nonzero_decimal(field(&lines, 4, "mount_ns_dev")?)?,
            parse_nonzero_decimal(field(&lines, 5, "mount_ns_inode")?)?,
        )?;
        let pid_namespace = NamespaceIdentity::new(
            parse_nonzero_decimal(field(&lines, 6, "pid_ns_dev")?)?,
            parse_nonzero_decimal(field(&lines, 7, "pid_ns_inode")?)?,
        )?;
        require_true(field(&lines, 8, "pid_one")?)?;
        require_true(field(&lines, 9, "private_run")?)?;
        require_true(field(&lines, 10, "private_proc")?)?;
        require_true(field(&lines, 11, "mount_propagation_private")?)?;
        require_true(field(&lines, 12, "network_pristine")?)?;
        require_true(field(&lines, 13, "handlers_installed")?)?;
        require_true(field(&lines, 14, "parent_death_chain")?)?;
        let frame = Self::new(run_id, network_namespace, mount_namespace, pid_namespace)?;
        require_canonical(bytes, &frame.encode()?)?;
        Ok(frame)
    }
}

/// Outer mutation authorization sent only after a valid bootstrap attestation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Go {
    run_id: RunId,
}

impl Go {
    /// Construct a `GO` frame for one lifecycle run.
    #[must_use]
    pub const fn new(run_id: RunId) -> Self {
        Self { run_id }
    }

    /// Run identifier authorized by this frame.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Encode the canonical frame.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::FrameTooLarge`] if the protocol bound is
    /// violated by a future format change.
    pub fn encode(&self) -> Result<String, NetnsLifecycleError> {
        encode_lines(&[
            GO_HEADER.to_owned(),
            format!("run_id={}", self.run_id.as_str()),
        ])
    }

    /// Parse one exact canonical `GO` frame.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for malformed, reordered, duplicated, oversized,
    /// or non-canonical input.
    pub fn parse(bytes: &[u8]) -> Result<Self, NetnsLifecycleError> {
        let lines = decode_lines(bytes)?;
        if lines.len() != 2 || lines[0] != GO_HEADER {
            return Err(NetnsLifecycleError::FrameShape);
        }
        let frame = Self::new(RunId::parse(field(&lines, 1, "run_id")?)?);
        require_canonical(bytes, &frame.encode()?)?;
        Ok(frame)
    }
}

/// Inner attestation that the fixed isolated topology exists and its exact probe passed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyReady {
    run_id: RunId,
    namespaces: Vec<OwnedNamespace>,
}

impl TopologyReady {
    /// Construct the fixed topology attestation with its exact two run-bound ownership records.
    ///
    /// The fixed inner worker must observe the namespace identities and completed
    /// probe immediately before construction. The encoder always binds
    /// [`LIFECYCLE_TOPOLOGY_SPEC_SHA256`] and emits `probe=true`. Names and
    /// device/inode pairs must each be unique.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for an invalid count or duplicate ownership.
    pub fn new(
        run_id: RunId,
        namespaces: Vec<OwnedNamespace>,
    ) -> Result<Self, NetnsLifecycleError> {
        validate_owned_namespaces(&run_id, &namespaces)?;
        Ok(Self { run_id, namespaces })
    }

    /// Run identifier bound to the topology.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Canonically ordered ownership records.
    #[must_use]
    pub fn namespaces(&self) -> &[OwnedNamespace] {
        &self.namespaces
    }

    /// Fixed topology specification digest.
    #[must_use]
    pub const fn specification_sha256(&self) -> &'static str {
        LIFECYCLE_TOPOLOGY_SPEC_SHA256
    }

    /// Encode the canonical frame.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::FrameTooLarge`] if the encoded frame
    /// exceeds 16 KiB.
    pub fn encode(&self) -> Result<String, NetnsLifecycleError> {
        let mut lines = Vec::with_capacity(5 + (3 * self.namespaces.len()));
        lines.push(TOPOLOGY_READY_HEADER.to_owned());
        lines.push(format!("run_id={}", self.run_id.as_str()));
        lines.push(format!("spec_sha256={LIFECYCLE_TOPOLOGY_SPEC_SHA256}"));
        lines.push(format!("namespace_count={}", self.namespaces.len()));
        for (index, namespace) in self.namespaces.iter().enumerate() {
            lines.push(format!("namespace.{index}.name={}", namespace.name()));
            lines.push(format!(
                "namespace.{index}.dev={}",
                namespace.identity().device()
            ));
            lines.push(format!(
                "namespace.{index}.inode={}",
                namespace.identity().inode()
            ));
        }
        lines.push("probe=true".to_owned());
        encode_lines(&lines)
    }

    /// Parse one exact canonical `TOPOLOGY_READY` frame.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for malformed, reordered, duplicated, weakened,
    /// oversized, non-canonical, or wrong-specification input.
    pub fn parse(bytes: &[u8]) -> Result<Self, NetnsLifecycleError> {
        let lines = decode_lines(bytes)?;
        if lines.len() < 8 || lines[0] != TOPOLOGY_READY_HEADER {
            return Err(NetnsLifecycleError::FrameShape);
        }
        let run_id = RunId::parse(field(&lines, 1, "run_id")?)?;
        let spec = field(&lines, 2, "spec_sha256")?;
        let _ = LifecycleSha256::parse(spec)?;
        if spec != LIFECYCLE_TOPOLOGY_SPEC_SHA256 {
            return Err(NetnsLifecycleError::TopologySpecificationMismatch);
        }
        let count = parse_namespace_count(field(&lines, 3, "namespace_count")?)?;
        if lines.len() != 5 + (3 * count) {
            return Err(NetnsLifecycleError::FrameShape);
        }
        let mut namespaces = Vec::with_capacity(count);
        for index in 0..count {
            let base = 4 + (3 * index);
            let name_key = format!("namespace.{index}.name");
            let device_key = format!("namespace.{index}.dev");
            let inode_key = format!("namespace.{index}.inode");
            let identity = NamespaceIdentity::new(
                parse_nonzero_decimal(field(&lines, base + 1, &device_key)?)?,
                parse_nonzero_decimal(field(&lines, base + 2, &inode_key)?)?,
            )?;
            namespaces.push(OwnedNamespace::new(
                field(&lines, base, &name_key)?.to_owned(),
                identity,
            )?);
        }
        require_true(field(&lines, lines.len() - 1, "probe")?)?;
        let frame = Self::new(run_id, namespaces)?;
        require_canonical(bytes, &frame.encode()?)?;
        Ok(frame)
    }
}

/// Outer request that the inner sandbox stop mutating and perform cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stop {
    run_id: RunId,
    reason: StopReason,
}

impl Stop {
    /// Construct a bounded stop request.
    #[must_use]
    pub const fn new(run_id: RunId, reason: StopReason) -> Self {
        Self { run_id, reason }
    }

    /// Run identifier bound to this stop request.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Fixed reason for stopping.
    #[must_use]
    pub const fn reason(&self) -> StopReason {
        self.reason
    }

    /// Encode the canonical frame.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::FrameTooLarge`] if the protocol bound is
    /// violated by a future format change.
    pub fn encode(&self) -> Result<String, NetnsLifecycleError> {
        encode_lines(&[
            STOP_HEADER.to_owned(),
            format!("run_id={}", self.run_id.as_str()),
            format!("reason={}", self.reason.as_str()),
        ])
    }

    /// Parse one exact canonical `STOP` frame.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for malformed, reordered, duplicated, oversized,
    /// or non-canonical input.
    pub fn parse(bytes: &[u8]) -> Result<Self, NetnsLifecycleError> {
        let lines = decode_lines(bytes)?;
        if lines.len() != 3 || lines[0] != STOP_HEADER {
            return Err(NetnsLifecycleError::FrameShape);
        }
        let frame = Self::new(
            RunId::parse(field(&lines, 1, "run_id")?)?,
            StopReason::parse(field(&lines, 2, "reason")?)?,
        );
        require_canonical(bytes, &frame.encode()?)?;
        Ok(frame)
    }
}

/// Inner terminal result binding cleanup to the exact topology-attestation bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finished {
    run_id: RunId,
    topology_ready_sha256: LifecycleSha256,
    cleanup_attempted: bool,
    cleanup_complete: bool,
    remaining: usize,
    error: CompletionError,
}

impl Finished {
    /// Construct a semantically consistent terminal result.
    ///
    /// Successful cleanup requires `attempted=true`, `complete=true`, zero
    /// remaining objects, and `error=NONE`. Every incomplete result requires a
    /// non-`NONE` error code. Remaining namespace objects are bounded by the
    /// fixed topology's declared ownership count.
    ///
    /// # Errors
    ///
    /// Returns a protocol error when the cleanup fields contradict each other.
    pub fn new(
        run_id: RunId,
        topology_ready_sha256: LifecycleSha256,
        cleanup_attempted: bool,
        cleanup_complete: bool,
        remaining: usize,
        error: CompletionError,
    ) -> Result<Self, NetnsLifecycleError> {
        if !cleanup_attempted
            || remaining > MAX_LIFECYCLE_NAMESPACES
            || cleanup_complete != matches!(error, CompletionError::None)
            || (cleanup_complete && remaining != 0)
        {
            return Err(NetnsLifecycleError::CleanupConsistency);
        }
        Ok(Self {
            run_id,
            topology_ready_sha256,
            cleanup_attempted,
            cleanup_complete,
            remaining,
            error,
        })
    }

    /// Run identifier bound to the result.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// SHA-256 of the exact canonical `TOPOLOGY_READY` bytes.
    #[must_use]
    pub const fn topology_ready_sha256(&self) -> &LifecycleSha256 {
        &self.topology_ready_sha256
    }

    /// Whether cleanup was attempted.
    #[must_use]
    pub const fn cleanup_attempted(&self) -> bool {
        self.cleanup_attempted
    }

    /// Whether cleanup completed without an error.
    #[must_use]
    pub const fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
    }

    /// Count of lifecycle-owned namespaces still present.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Machine-readable completion error.
    #[must_use]
    pub const fn error(&self) -> &CompletionError {
        &self.error
    }

    /// Encode the canonical frame.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::FrameTooLarge`] if the protocol bound is
    /// violated by a future format change.
    pub fn encode(&self) -> Result<String, NetnsLifecycleError> {
        encode_lines(&[
            FINISHED_HEADER.to_owned(),
            format!("run_id={}", self.run_id.as_str()),
            format!(
                "topology_ready_sha256={}",
                self.topology_ready_sha256.as_str()
            ),
            format!("cleanup_attempted={}", self.cleanup_attempted),
            format!("cleanup_complete={}", self.cleanup_complete),
            format!("remaining={}", self.remaining),
            format!("error={}", self.error.as_str()),
        ])
    }

    /// Parse one exact canonical `FINISHED` frame.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for malformed, reordered, duplicated, inconsistent,
    /// oversized, or non-canonical input.
    pub fn parse(bytes: &[u8]) -> Result<Self, NetnsLifecycleError> {
        let lines = decode_lines(bytes)?;
        if lines.len() != 7 || lines[0] != FINISHED_HEADER {
            return Err(NetnsLifecycleError::FrameShape);
        }
        let frame = Self::new(
            RunId::parse(field(&lines, 1, "run_id")?)?,
            LifecycleSha256::parse(field(&lines, 2, "topology_ready_sha256")?)?,
            parse_bool(field(&lines, 3, "cleanup_attempted")?)?,
            parse_bool(field(&lines, 4, "cleanup_complete")?)?,
            parse_remaining(field(&lines, 5, "remaining")?)?,
            CompletionError::parse(field(&lines, 6, "error")?)?,
        )?;
        require_canonical(bytes, &frame.encode()?)?;
        Ok(frame)
    }
}

/// Frame sent from the inner sandbox to the outer supervisor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InnerLifecycleFrame {
    /// Isolation attestation sent before mutation authorization.
    BootstrapReady(BootstrapReady),
    /// Ownership and probe attestation sent after authorized topology creation.
    TopologyReady(TopologyReady),
    /// Terminal cleanup result.
    Finished(Finished),
}

impl InnerLifecycleFrame {
    /// Parse exactly one direction-correct inner frame.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for malformed input or an outer-only frame.
    pub fn parse(bytes: &[u8]) -> Result<Self, NetnsLifecycleError> {
        match first_line(bytes)? {
            BOOTSTRAP_READY_HEADER => BootstrapReady::parse(bytes).map(Self::BootstrapReady),
            TOPOLOGY_READY_HEADER => TopologyReady::parse(bytes).map(Self::TopologyReady),
            FINISHED_HEADER => Finished::parse(bytes).map(Self::Finished),
            _ => Err(NetnsLifecycleError::FrameShape),
        }
    }

    /// Encode the contained frame canonically.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::FrameTooLarge`] if the 16-KiB bound is
    /// violated by a future format change.
    pub fn encode(&self) -> Result<String, NetnsLifecycleError> {
        match self {
            Self::BootstrapReady(frame) => frame.encode(),
            Self::TopologyReady(frame) => frame.encode(),
            Self::Finished(frame) => frame.encode(),
        }
    }
}

/// Frame sent from the outer supervisor to the inner sandbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OuterLifecycleFrame {
    /// Mutation authorization after a valid bootstrap attestation.
    Go(Go),
    /// Request to stop and clean up.
    Stop(Stop),
}

impl OuterLifecycleFrame {
    /// Parse exactly one direction-correct outer frame.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for malformed input or an inner-only frame.
    pub fn parse(bytes: &[u8]) -> Result<Self, NetnsLifecycleError> {
        match first_line(bytes)? {
            GO_HEADER => Go::parse(bytes).map(Self::Go),
            STOP_HEADER => Stop::parse(bytes).map(Self::Stop),
            _ => Err(NetnsLifecycleError::FrameShape),
        }
    }

    /// Encode the contained frame canonically.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::FrameTooLarge`] if the 16-KiB bound is
    /// violated by a future format change.
    pub fn encode(&self) -> Result<String, NetnsLifecycleError> {
        match self {
            Self::Go(frame) => frame.encode(),
            Self::Stop(frame) => frame.encode(),
        }
    }
}

/// Observable phase of the outer supervisor's lifecycle state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OuterLifecyclePhase {
    /// Waiting for the inner isolation attestation.
    AwaitingBootstrap,
    /// A valid bootstrap attestation was received; `GO` has not been issued.
    BootstrapReady,
    /// `GO` was issued and the topology attestation is outstanding.
    GoSent,
    /// A valid topology attestation was received; `STOP` has not been issued.
    TopologyReady,
    /// `STOP` was issued and `FINISHED` is outstanding.
    StopSent,
    /// A valid terminal result was received.
    Finished,
    /// The peer closed before `GO`, so mutation was never authorized.
    PeerClosedBeforeGo,
    /// The peer closed after `GO`, so cleanup remains required.
    PeerClosedAfterGo,
}

/// Observable phase of the inner sandbox's lifecycle state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InnerLifecyclePhase {
    /// The bootstrap attestation has not yet been emitted.
    Bootstrapping,
    /// Bootstrap is proven and the sandbox is waiting for `GO`.
    AwaitingGo,
    /// A valid `GO` was consumed; topology mutation is authorized once.
    GoReceived,
    /// The topology attestation was emitted and `STOP` is outstanding.
    TopologyReady,
    /// A valid `STOP` was consumed and cleanup is underway.
    StopReceived,
    /// The terminal result was emitted.
    Finished,
    /// The outer peer closed before `GO`; mutation was never authorized.
    PeerClosedBeforeGo,
    /// The outer peer closed after `GO`; cleanup remains required.
    PeerClosedAfterGo,
}

/// Meaning of EOF for either side of the lifecycle exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleEofDisposition {
    /// EOF happened before `GO`; no mutation authorization exists.
    NoMutationAuthorized,
    /// EOF happened after `GO`; owned objects must be cleaned up.
    CleanupRequired,
}

/// Affine proof that a valid, same-run `GO` was consumed by the inner sandbox.
///
/// The token is intentionally neither `Clone` nor publicly constructible. It is
/// consumed by [`InnerLifecycleState::topology_ready`], preventing a second
/// topology mutation from the same authorization.
#[derive(Debug)]
pub struct MutationAuthorization {
    run_id: RunId,
}

impl MutationAuthorization {
    /// Run identifier authorized by this affine token.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }
}

/// Strict outer-supervisor lifecycle state.
#[derive(Debug)]
pub struct OuterLifecycleState {
    run_id: RunId,
    host_network_namespace: NamespaceIdentity,
    host_mount_namespace: NamespaceIdentity,
    host_pid_namespace: NamespaceIdentity,
    phase: OuterLifecyclePhase,
    topology_ready_sha256: Option<LifecycleSha256>,
}

impl OuterLifecycleState {
    /// Begin an outer exchange bound to the three original host namespace identities.
    #[must_use]
    pub const fn new(
        run_id: RunId,
        host_network_namespace: NamespaceIdentity,
        host_mount_namespace: NamespaceIdentity,
        host_pid_namespace: NamespaceIdentity,
    ) -> Self {
        Self {
            run_id,
            host_network_namespace,
            host_mount_namespace,
            host_pid_namespace,
            phase: OuterLifecyclePhase::AwaitingBootstrap,
            topology_ready_sha256: None,
        }
    }

    /// Current protocol phase.
    #[must_use]
    pub const fn phase(&self) -> OuterLifecyclePhase {
        self.phase
    }

    /// Run identifier expected on every frame.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Accept the exact inner bootstrap bytes without authorizing mutation yet.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, a nonce mismatch, or wrong order.
    /// The state is unchanged on error.
    pub fn accept_bootstrap_ready(
        &mut self,
        bytes: &[u8],
    ) -> Result<BootstrapReady, NetnsLifecycleError> {
        if self.phase != OuterLifecyclePhase::AwaitingBootstrap {
            return Err(NetnsLifecycleError::StateTransition);
        }
        let frame = BootstrapReady::parse(bytes)?;
        ensure_run_id(&self.run_id, frame.run_id())?;
        ensure_isolated_from_host(
            &frame,
            self.host_network_namespace,
            self.host_mount_namespace,
            self.host_pid_namespace,
        )?;
        self.phase = OuterLifecyclePhase::BootstrapReady;
        Ok(frame)
    }

    /// Issue the sole `GO` mutation authorization after bootstrap attestation.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::StateTransition`] unless bootstrap was
    /// accepted and no prior `GO` was issued.
    pub fn go(&mut self) -> Result<Go, NetnsLifecycleError> {
        if self.phase != OuterLifecyclePhase::BootstrapReady {
            return Err(NetnsLifecycleError::StateTransition);
        }
        let frame = Go::new(self.run_id.clone());
        self.phase = OuterLifecyclePhase::GoSent;
        Ok(frame)
    }

    /// Accept and hash the exact received `TOPOLOGY_READY` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, a nonce mismatch, or wrong order.
    /// The state is unchanged on error.
    pub fn accept_topology_ready(
        &mut self,
        bytes: &[u8],
    ) -> Result<TopologyReady, NetnsLifecycleError> {
        if self.phase != OuterLifecyclePhase::GoSent {
            return Err(NetnsLifecycleError::StateTransition);
        }
        let frame = TopologyReady::parse(bytes)?;
        ensure_run_id(&self.run_id, frame.run_id())?;
        let digest = LifecycleSha256::digest(bytes);
        self.topology_ready_sha256 = Some(digest);
        self.phase = OuterLifecyclePhase::TopologyReady;
        Ok(frame)
    }

    /// Issue one stop request after a valid topology attestation.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::StateTransition`] in every other phase.
    pub fn stop(&mut self, reason: StopReason) -> Result<Stop, NetnsLifecycleError> {
        if self.phase != OuterLifecyclePhase::TopologyReady {
            return Err(NetnsLifecycleError::StateTransition);
        }
        let frame = Stop::new(self.run_id.clone(), reason);
        self.phase = OuterLifecyclePhase::StopSent;
        Ok(frame)
    }

    /// Accept a terminal result and verify its exact topology-frame binding.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, wrong order/run/digest, or a
    /// remaining count exceeding the topology's ownership records. The state is
    /// unchanged on error.
    pub fn accept_finished(&mut self, bytes: &[u8]) -> Result<Finished, NetnsLifecycleError> {
        if self.phase != OuterLifecyclePhase::StopSent {
            return Err(NetnsLifecycleError::StateTransition);
        }
        let frame = Finished::parse(bytes)?;
        ensure_run_id(&self.run_id, frame.run_id())?;
        let Some(expected_digest) = &self.topology_ready_sha256 else {
            return Err(NetnsLifecycleError::StateTransition);
        };
        if frame.topology_ready_sha256() != expected_digest {
            return Err(NetnsLifecycleError::TopologyFrameDigestMismatch);
        }
        self.phase = OuterLifecyclePhase::Finished;
        Ok(frame)
    }

    /// Record inner EOF and make pre-`GO` non-authorization explicit.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::StateTransition`] after a terminal or
    /// previously recorded EOF state.
    pub fn observe_inner_eof(&mut self) -> Result<LifecycleEofDisposition, NetnsLifecycleError> {
        match self.phase {
            OuterLifecyclePhase::AwaitingBootstrap | OuterLifecyclePhase::BootstrapReady => {
                self.phase = OuterLifecyclePhase::PeerClosedBeforeGo;
                Ok(LifecycleEofDisposition::NoMutationAuthorized)
            }
            OuterLifecyclePhase::GoSent
            | OuterLifecyclePhase::TopologyReady
            | OuterLifecyclePhase::StopSent => {
                self.phase = OuterLifecyclePhase::PeerClosedAfterGo;
                Ok(LifecycleEofDisposition::CleanupRequired)
            }
            OuterLifecyclePhase::Finished
            | OuterLifecyclePhase::PeerClosedBeforeGo
            | OuterLifecyclePhase::PeerClosedAfterGo => Err(NetnsLifecycleError::StateTransition),
        }
    }
}

/// Strict inner-sandbox lifecycle state.
#[derive(Debug)]
pub struct InnerLifecycleState {
    run_id: RunId,
    host_network_namespace: NamespaceIdentity,
    host_mount_namespace: NamespaceIdentity,
    host_pid_namespace: NamespaceIdentity,
    phase: InnerLifecyclePhase,
    topology_ready_sha256: Option<LifecycleSha256>,
}

impl InnerLifecycleState {
    /// Begin an inner exchange bound to the outer-supplied host namespace identities.
    #[must_use]
    pub const fn new(
        run_id: RunId,
        host_network_namespace: NamespaceIdentity,
        host_mount_namespace: NamespaceIdentity,
        host_pid_namespace: NamespaceIdentity,
    ) -> Self {
        Self {
            run_id,
            host_network_namespace,
            host_mount_namespace,
            host_pid_namespace,
            phase: InnerLifecyclePhase::Bootstrapping,
            topology_ready_sha256: None,
        }
    }

    /// Current protocol phase.
    #[must_use]
    pub const fn phase(&self) -> InnerLifecyclePhase {
        self.phase
    }

    /// Run identifier expected on every frame.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Emit the sole bootstrap attestation and begin waiting for `GO`.
    ///
    /// # Errors
    ///
    /// Returns an error for a nonce mismatch, wrong order, or encoding failure.
    /// The state is unchanged on error.
    pub fn bootstrap_ready(
        &mut self,
        frame: &BootstrapReady,
    ) -> Result<String, NetnsLifecycleError> {
        if self.phase != InnerLifecyclePhase::Bootstrapping {
            return Err(NetnsLifecycleError::StateTransition);
        }
        ensure_run_id(&self.run_id, frame.run_id())?;
        ensure_isolated_from_host(
            frame,
            self.host_network_namespace,
            self.host_mount_namespace,
            self.host_pid_namespace,
        )?;
        let encoded = frame.encode()?;
        self.phase = InnerLifecyclePhase::AwaitingGo;
        Ok(encoded)
    }

    /// Consume one valid `GO` and return an affine mutation authorization.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, wrong order, or a nonce mismatch.
    /// No authorization is produced and state is unchanged on error.
    pub fn accept_go(
        &mut self,
        bytes: &[u8],
    ) -> Result<MutationAuthorization, NetnsLifecycleError> {
        if self.phase != InnerLifecyclePhase::AwaitingGo {
            return Err(NetnsLifecycleError::StateTransition);
        }
        let frame = Go::parse(bytes)?;
        ensure_run_id(&self.run_id, frame.run_id())?;
        self.phase = InnerLifecyclePhase::GoReceived;
        Ok(MutationAuthorization {
            run_id: frame.run_id,
        })
    }

    /// Consume authorization and emit the sole canonical topology attestation.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong order, a nonce mismatch, or encoding failure.
    /// The state is unchanged on error.
    pub fn topology_ready(
        &mut self,
        authorization: MutationAuthorization,
        frame: &TopologyReady,
    ) -> Result<String, NetnsLifecycleError> {
        if self.phase != InnerLifecyclePhase::GoReceived {
            return Err(NetnsLifecycleError::StateTransition);
        }
        ensure_run_id(&self.run_id, &authorization.run_id)?;
        drop(authorization);
        ensure_run_id(&self.run_id, frame.run_id())?;
        let encoded = frame.encode()?;
        self.topology_ready_sha256 = Some(LifecycleSha256::digest(encoded.as_bytes()));
        self.phase = InnerLifecyclePhase::TopologyReady;
        Ok(encoded)
    }

    /// Consume one valid stop request.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, wrong order, or a nonce mismatch.
    /// The state is unchanged on error.
    pub fn accept_stop(&mut self, bytes: &[u8]) -> Result<Stop, NetnsLifecycleError> {
        if self.phase != InnerLifecyclePhase::TopologyReady {
            return Err(NetnsLifecycleError::StateTransition);
        }
        let frame = Stop::parse(bytes)?;
        ensure_run_id(&self.run_id, frame.run_id())?;
        self.phase = InnerLifecyclePhase::StopReceived;
        Ok(frame)
    }

    /// Emit a terminal result bound to the emitted topology attestation.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong order/run/digest, an excessive remaining
    /// count, or encoding failure. The state is unchanged on error.
    pub fn finished(&mut self, frame: &Finished) -> Result<String, NetnsLifecycleError> {
        if self.phase != InnerLifecyclePhase::StopReceived {
            return Err(NetnsLifecycleError::StateTransition);
        }
        ensure_run_id(&self.run_id, frame.run_id())?;
        let Some(expected_digest) = &self.topology_ready_sha256 else {
            return Err(NetnsLifecycleError::StateTransition);
        };
        if frame.topology_ready_sha256() != expected_digest {
            return Err(NetnsLifecycleError::TopologyFrameDigestMismatch);
        }
        let encoded = frame.encode()?;
        self.phase = InnerLifecyclePhase::Finished;
        Ok(encoded)
    }

    /// Record outer EOF and make pre-`GO` non-authorization explicit.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsLifecycleError::StateTransition`] after a terminal or
    /// previously recorded EOF state.
    pub fn observe_outer_eof(&mut self) -> Result<LifecycleEofDisposition, NetnsLifecycleError> {
        match self.phase {
            InnerLifecyclePhase::Bootstrapping | InnerLifecyclePhase::AwaitingGo => {
                self.phase = InnerLifecyclePhase::PeerClosedBeforeGo;
                Ok(LifecycleEofDisposition::NoMutationAuthorized)
            }
            InnerLifecyclePhase::GoReceived
            | InnerLifecyclePhase::TopologyReady
            | InnerLifecyclePhase::StopReceived => {
                self.phase = InnerLifecyclePhase::PeerClosedAfterGo;
                Ok(LifecycleEofDisposition::CleanupRequired)
            }
            InnerLifecyclePhase::Finished
            | InnerLifecyclePhase::PeerClosedBeforeGo
            | InnerLifecyclePhase::PeerClosedAfterGo => Err(NetnsLifecycleError::StateTransition),
        }
    }
}

fn encode_lines(lines: &[String]) -> Result<String, NetnsLifecycleError> {
    if lines.is_empty()
        || lines
            .iter()
            .any(|line| line.is_empty() || line.contains(['\n', '\r']))
    {
        return Err(NetnsLifecycleError::FrameShape);
    }
    let mut encoded = lines.join("\n");
    encoded.push('\n');
    if encoded.len() > MAX_LIFECYCLE_FRAME_BYTES {
        return Err(NetnsLifecycleError::FrameTooLarge);
    }
    Ok(encoded)
}

fn decode_lines(bytes: &[u8]) -> Result<Vec<&str>, NetnsLifecycleError> {
    if bytes.len() > MAX_LIFECYCLE_FRAME_BYTES {
        return Err(NetnsLifecycleError::FrameTooLarge);
    }
    if bytes.last() != Some(&b'\n') {
        return Err(NetnsLifecycleError::MissingFinalLineFeed);
    }
    if bytes.contains(&b'\r') {
        return Err(NetnsLifecycleError::CarriageReturn);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| NetnsLifecycleError::Utf8)?;
    let body = text
        .strip_suffix('\n')
        .ok_or(NetnsLifecycleError::MissingFinalLineFeed)?;
    if body.is_empty() || body.ends_with('\n') {
        return Err(NetnsLifecycleError::FrameShape);
    }
    let lines = body.split('\n').collect::<Vec<_>>();
    if lines.iter().any(|line| line.is_empty()) {
        return Err(NetnsLifecycleError::FrameShape);
    }
    Ok(lines)
}

fn first_line(bytes: &[u8]) -> Result<&str, NetnsLifecycleError> {
    let lines = decode_lines(bytes)?;
    lines
        .first()
        .copied()
        .ok_or(NetnsLifecycleError::FrameShape)
}

fn field<'a>(
    lines: &'a [&str],
    index: usize,
    expected_name: &str,
) -> Result<&'a str, NetnsLifecycleError> {
    let line = lines.get(index).ok_or(NetnsLifecycleError::FrameShape)?;
    let (name, value) = line
        .split_once('=')
        .ok_or(NetnsLifecycleError::FrameShape)?;
    if name != expected_name || value.contains('=') {
        return Err(NetnsLifecycleError::FrameShape);
    }
    Ok(value)
}

fn require_canonical(bytes: &[u8], encoded: &str) -> Result<(), NetnsLifecycleError> {
    if bytes != encoded.as_bytes() {
        return Err(NetnsLifecycleError::FrameShape);
    }
    Ok(())
}

fn require_true(value: &str) -> Result<(), NetnsLifecycleError> {
    if value != "true" {
        return Err(NetnsLifecycleError::RequiredAssertion);
    }
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool, NetnsLifecycleError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(NetnsLifecycleError::FrameShape),
    }
}

fn parse_nonzero_decimal(value: &str) -> Result<u64, NetnsLifecycleError> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(NetnsLifecycleError::NamespaceIdentity);
    }
    value
        .parse::<u64>()
        .map_err(|_| NetnsLifecycleError::NamespaceIdentity)
        .and_then(|number| {
            if number == 0 {
                Err(NetnsLifecycleError::NamespaceIdentity)
            } else {
                Ok(number)
            }
        })
}

fn parse_canonical_usize(value: &str) -> Result<usize, NetnsLifecycleError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(NetnsLifecycleError::BoundedInteger);
    }
    value
        .parse::<usize>()
        .map_err(|_| NetnsLifecycleError::BoundedInteger)
}

fn parse_namespace_count(value: &str) -> Result<usize, NetnsLifecycleError> {
    let count = parse_canonical_usize(value)?;
    if !(1..=MAX_LIFECYCLE_NAMESPACES).contains(&count) {
        return Err(NetnsLifecycleError::NamespaceCount);
    }
    Ok(count)
}

fn parse_remaining(value: &str) -> Result<usize, NetnsLifecycleError> {
    let remaining = parse_canonical_usize(value)?;
    if remaining > MAX_LIFECYCLE_NAMESPACES {
        return Err(NetnsLifecycleError::CleanupConsistency);
    }
    Ok(remaining)
}

fn validate_owned_namespaces(
    run_id: &RunId,
    namespaces: &[OwnedNamespace],
) -> Result<(), NetnsLifecycleError> {
    if namespaces.len() != MAX_LIFECYCLE_NAMESPACES {
        return Err(NetnsLifecycleError::NamespaceCount);
    }
    let expected_names = [
        format!("vpl-{}-a", run_id.as_str()),
        format!("vpl-{}-b", run_id.as_str()),
    ];
    let mut names = HashSet::with_capacity(namespaces.len());
    let mut identities = HashSet::with_capacity(namespaces.len());
    for (namespace, expected_name) in namespaces.iter().zip(expected_names) {
        if namespace.name() != expected_name {
            return Err(NetnsLifecycleError::NamespaceName);
        }
        if !names.insert(namespace.name()) || !identities.insert(namespace.identity()) {
            return Err(NetnsLifecycleError::DuplicateNamespace);
        }
    }
    Ok(())
}

fn ensure_run_id(expected: &RunId, actual: &RunId) -> Result<(), NetnsLifecycleError> {
    if expected != actual {
        return Err(NetnsLifecycleError::RunIdMismatch);
    }
    Ok(())
}

fn ensure_isolated_from_host(
    bootstrap: &BootstrapReady,
    host_network_namespace: NamespaceIdentity,
    host_mount_namespace: NamespaceIdentity,
    host_pid_namespace: NamespaceIdentity,
) -> Result<(), NetnsLifecycleError> {
    if bootstrap.network_namespace() == host_network_namespace
        || bootstrap.mount_namespace() == host_mount_namespace
        || bootstrap.pid_namespace() == host_pid_namespace
    {
        return Err(NetnsLifecycleError::BootstrapMatchesHost);
    }
    Ok(())
}

fn is_lower_hex(value: &str, exact_length: usize) -> bool {
    value.len() == exact_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_safe_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    bytes.len() <= MAX_LIFECYCLE_NAME_BYTES
        && first.is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_error_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    bytes.len() <= MAX_LIFECYCLE_ERROR_CODE_BYTES
        && first.is_ascii_uppercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_id(byte: char) -> RunId {
        RunId::parse(&byte.to_string().repeat(32)).expect("valid run id")
    }

    fn identity(device: u64, inode: u64) -> NamespaceIdentity {
        NamespaceIdentity::new(device, inode).expect("valid namespace identity")
    }

    fn bootstrap(run_id: RunId) -> BootstrapReady {
        BootstrapReady::new(run_id, identity(7, 101), identity(7, 102), identity(7, 103))
            .expect("valid bootstrap")
    }

    fn host_namespaces() -> (NamespaceIdentity, NamespaceIdentity, NamespaceIdentity) {
        (identity(7, 1), identity(7, 2), identity(7, 3))
    }

    fn outer_state(run_id: RunId) -> OuterLifecycleState {
        let (network, mount, pid) = host_namespaces();
        OuterLifecycleState::new(run_id, network, mount, pid)
    }

    fn inner_state(run_id: RunId) -> InnerLifecycleState {
        let (network, mount, pid) = host_namespaces();
        InnerLifecycleState::new(run_id, network, mount, pid)
    }

    fn owned(name: &str, inode: u64) -> OwnedNamespace {
        OwnedNamespace::new(name.to_owned(), identity(11, inode)).expect("valid ownership")
    }

    fn topology(run_id: RunId) -> TopologyReady {
        let left = format!("vpl-{}-a", run_id.as_str());
        let right = format!("vpl-{}-b", run_id.as_str());
        TopologyReady::new(run_id, vec![owned(&left, 201), owned(&right, 202)])
            .expect("valid topology")
    }

    fn successful_finished(run_id: RunId, topology_bytes: &[u8]) -> Finished {
        Finished::new(
            run_id,
            LifecycleSha256::digest(topology_bytes),
            true,
            true,
            0,
            CompletionError::None,
        )
        .expect("valid finished")
    }

    #[test]
    fn primitive_values_are_canonical_and_bounded() {
        assert_eq!(run_id('a').as_str(), "a".repeat(32));
        assert_eq!(
            RunId::parse("A0000000000000000000000000000000"),
            Err(NetnsLifecycleError::RunId)
        );
        assert_eq!(
            RunId::parse("0000000000000000000000000000000"),
            Err(NetnsLifecycleError::RunId)
        );
        assert_eq!(
            LifecycleSha256::parse(&"A".repeat(64)),
            Err(NetnsLifecycleError::Sha256)
        );
        assert_eq!(
            NamespaceIdentity::new(0, 1),
            Err(NetnsLifecycleError::NamespaceIdentity)
        );
        assert_eq!(
            NamespaceIdentity::new(1, 0),
            Err(NetnsLifecycleError::NamespaceIdentity)
        );
        for invalid in ["", ".", "..", "-vp", "vp/name", "vp:name", "vp name"] {
            assert_eq!(
                OwnedNamespace::new(invalid.to_owned(), identity(1, 1)),
                Err(NetnsLifecycleError::NamespaceName)
            );
        }
        assert_eq!(
            OwnedNamespace::new("a".repeat(MAX_LIFECYCLE_NAME_BYTES + 1), identity(1, 1)),
            Err(NetnsLifecycleError::NamespaceName)
        );
        assert!(OwnedNamespace::new("A0._-z".to_owned(), identity(1, 1)).is_ok());
    }

    #[test]
    fn fixed_topology_digest_matches_exact_specification_bytes() {
        assert_eq!(
            LifecycleSha256::digest(LIFECYCLE_TOPOLOGY_SPEC.as_bytes()).as_str(),
            LIFECYCLE_TOPOLOGY_SPEC_SHA256
        );
    }

    #[test]
    fn bootstrap_round_trip_has_exact_order_and_required_assertions() {
        let frame = bootstrap(run_id('1'));
        let encoded = frame.encode().expect("encode");
        assert_eq!(
            encoded,
            concat!(
                "VOLPAROSSA_NETNS_LIFECYCLE_V1 BOOTSTRAP_READY\n",
                "run_id=11111111111111111111111111111111\n",
                "net_ns_dev=7\n",
                "net_ns_inode=101\n",
                "mount_ns_dev=7\n",
                "mount_ns_inode=102\n",
                "pid_ns_dev=7\n",
                "pid_ns_inode=103\n",
                "pid_one=true\n",
                "private_run=true\n",
                "private_proc=true\n",
                "mount_propagation_private=true\n",
                "network_pristine=true\n",
                "handlers_installed=true\n",
                "parent_death_chain=true\n"
            )
        );
        assert_eq!(BootstrapReady::parse(encoded.as_bytes()), Ok(frame));
    }

    #[test]
    fn bootstrap_rejects_weak_duplicate_and_noncanonical_proofs() {
        let run = run_id('2');
        assert_eq!(
            BootstrapReady::new(run, identity(1, 1), identity(1, 1), identity(1, 2)),
            Err(NetnsLifecycleError::BootstrapNamespacesNotDistinct)
        );

        let valid = bootstrap(run_id('2')).encode().expect("encode");
        for assertion in [
            "pid_one",
            "private_run",
            "private_proc",
            "mount_propagation_private",
            "network_pristine",
            "handlers_installed",
            "parent_death_chain",
        ] {
            let weakened =
                valid.replace(&format!("{assertion}=true"), &format!("{assertion}=false"));
            assert_eq!(
                BootstrapReady::parse(weakened.as_bytes()),
                Err(NetnsLifecycleError::RequiredAssertion)
            );
        }
        assert_eq!(
            BootstrapReady::parse(valid.replace("net_ns_dev=7", "net_ns_dev=07").as_bytes()),
            Err(NetnsLifecycleError::NamespaceIdentity)
        );
        assert_eq!(
            BootstrapReady::parse(
                valid
                    .replace(
                        "net_ns_dev=7\nnet_ns_inode=101",
                        "net_ns_inode=101\nnet_ns_dev=7"
                    )
                    .as_bytes()
            ),
            Err(NetnsLifecycleError::FrameShape)
        );
        let extra = valid.replace("private_run=true\n", "private_run=true\nprivate_run=true\n");
        assert_eq!(
            BootstrapReady::parse(extra.as_bytes()),
            Err(NetnsLifecycleError::FrameShape)
        );
    }

    #[test]
    fn state_machines_reject_a_bootstrap_still_in_any_original_host_namespace() {
        let run = run_id('2');
        let (host_network, host_mount, host_pid) = host_namespaces();
        for frame in [
            BootstrapReady::new(
                run.clone(),
                host_network,
                identity(7, 102),
                identity(7, 103),
            )
            .expect("frame"),
            BootstrapReady::new(run.clone(), identity(7, 101), host_mount, identity(7, 103))
                .expect("frame"),
            BootstrapReady::new(run.clone(), identity(7, 101), identity(7, 102), host_pid)
                .expect("frame"),
        ] {
            let bytes = frame.encode().expect("encode");
            let mut outer = outer_state(run.clone());
            assert_eq!(
                outer.accept_bootstrap_ready(bytes.as_bytes()),
                Err(NetnsLifecycleError::BootstrapMatchesHost)
            );
            assert_eq!(outer.phase(), OuterLifecyclePhase::AwaitingBootstrap);

            let mut inner = inner_state(run.clone());
            assert_eq!(
                inner.bootstrap_ready(&frame),
                Err(NetnsLifecycleError::BootstrapMatchesHost)
            );
            assert_eq!(inner.phase(), InnerLifecyclePhase::Bootstrapping);
        }
    }

    #[test]
    fn outer_frames_round_trip_for_every_fixed_stop_reason() {
        let run = run_id('3');
        let go = Go::new(run.clone());
        assert_eq!(Go::parse(go.encode().expect("encode").as_bytes()), Ok(go));

        for reason in [
            StopReason::Normal,
            StopReason::Hup,
            StopReason::Int,
            StopReason::Term,
            StopReason::Timeout,
        ] {
            let stop = Stop::new(run.clone(), reason);
            assert_eq!(
                Stop::parse(stop.encode().expect("encode").as_bytes()),
                Ok(stop)
            );
        }
        let invalid = Stop::new(run, StopReason::Normal)
            .encode()
            .expect("encode")
            .replace("reason=NORMAL", "reason=KILL");
        assert_eq!(
            Stop::parse(invalid.as_bytes()),
            Err(NetnsLifecycleError::StopReason)
        );
    }

    #[test]
    fn topology_round_trip_requires_the_exact_run_bound_pair_and_unique_ownership() {
        let run = run_id('4');
        let frame = topology(run.clone());
        let encoded = frame.encode().expect("encode");
        assert!(encoded.contains(&format!("spec_sha256={LIFECYCLE_TOPOLOGY_SPEC_SHA256}\n")));
        assert!(encoded.ends_with("probe=true\n"));
        assert_eq!(TopologyReady::parse(encoded.as_bytes()), Ok(frame));

        let left = format!("vpl-{}-a", run.as_str());
        let right = format!("vpl-{}-b", run.as_str());
        let wrong_name = vec![owned(&left, 1), owned("foreign", 2)];
        assert_eq!(
            TopologyReady::new(run.clone(), wrong_name),
            Err(NetnsLifecycleError::NamespaceName)
        );
        let reversed = vec![owned(&right, 2), owned(&left, 1)];
        assert_eq!(
            TopologyReady::new(run.clone(), reversed),
            Err(NetnsLifecycleError::NamespaceName)
        );
        let same_identity = vec![owned(&left, 1), owned(&right, 1)];
        assert_eq!(
            TopologyReady::new(run.clone(), same_identity),
            Err(NetnsLifecycleError::DuplicateNamespace)
        );
        assert_eq!(
            TopologyReady::new(run, Vec::new()),
            Err(NetnsLifecycleError::NamespaceCount)
        );
    }

    #[test]
    fn topology_rejects_wrong_spec_probe_count_order_and_decimal_notation() {
        let valid = topology(run_id('5')).encode().expect("encode");
        let wrong_spec = valid.replace(LIFECYCLE_TOPOLOGY_SPEC_SHA256, &"0".repeat(64));
        assert_eq!(
            TopologyReady::parse(wrong_spec.as_bytes()),
            Err(NetnsLifecycleError::TopologySpecificationMismatch)
        );
        assert_eq!(
            TopologyReady::parse(valid.replace("probe=true", "probe=false").as_bytes()),
            Err(NetnsLifecycleError::RequiredAssertion)
        );
        assert_eq!(
            TopologyReady::parse(
                valid
                    .replace("namespace_count=2", "namespace_count=02")
                    .as_bytes()
            ),
            Err(NetnsLifecycleError::BoundedInteger)
        );
        assert_eq!(
            TopologyReady::parse(
                valid
                    .replace("namespace_count=2", "namespace_count=0")
                    .as_bytes()
            ),
            Err(NetnsLifecycleError::NamespaceCount)
        );
        assert_eq!(
            TopologyReady::parse(
                valid
                    .replace(
                        "namespace.0.dev=11\nnamespace.0.inode=201",
                        "namespace.0.inode=201\nnamespace.0.dev=11"
                    )
                    .as_bytes()
            ),
            Err(NetnsLifecycleError::FrameShape)
        );
        assert_eq!(
            TopologyReady::parse(
                valid
                    .replace("namespace.0.inode=201", "namespace.0.inode=0201")
                    .as_bytes()
            ),
            Err(NetnsLifecycleError::NamespaceIdentity)
        );
    }

    #[test]
    fn topology_enforces_fixed_record_count_and_frame_bound() {
        let run = run_id('6');
        let frame = topology(run.clone());
        assert!(frame.encode().expect("encode").len() <= MAX_LIFECYCLE_FRAME_BYTES);
        let excessive = vec![
            owned(&format!("vpl-{}-a", run.as_str()), 1),
            owned(&format!("vpl-{}-b", run.as_str()), 2),
            owned(&format!("vpl-{}-c", run.as_str()), 3),
        ];
        assert_eq!(
            TopologyReady::new(run, excessive),
            Err(NetnsLifecycleError::NamespaceCount)
        );
    }

    #[test]
    fn finished_round_trips_success_and_failure() {
        let run = run_id('7');
        let topology_bytes = topology(run.clone()).encode().expect("encode");
        let success = successful_finished(run.clone(), topology_bytes.as_bytes());
        assert_eq!(
            Finished::parse(success.encode().expect("encode").as_bytes()),
            Ok(success)
        );

        let failure = Finished::new(
            run,
            LifecycleSha256::digest(topology_bytes.as_bytes()),
            true,
            false,
            1,
            CompletionError::code("OWNERSHIP_MISMATCH".to_owned()).expect("error code"),
        )
        .expect("valid failure");
        assert_eq!(
            Finished::parse(failure.encode().expect("encode").as_bytes()),
            Ok(failure)
        );
    }

    #[test]
    fn finished_rejects_inconsistent_cleanup_and_unsafe_error_codes() {
        let run = run_id('8');
        let digest = LifecycleSha256::digest(b"topology");
        assert_eq!(
            Finished::new(
                run.clone(),
                digest.clone(),
                false,
                true,
                0,
                CompletionError::None
            ),
            Err(NetnsLifecycleError::CleanupConsistency)
        );
        assert_eq!(
            Finished::new(
                run.clone(),
                digest.clone(),
                false,
                false,
                1,
                CompletionError::code("NOT_ATTEMPTED".to_owned()).expect("error code")
            ),
            Err(NetnsLifecycleError::CleanupConsistency)
        );
        assert_eq!(
            Finished::new(
                run.clone(),
                digest.clone(),
                true,
                true,
                1,
                CompletionError::None
            ),
            Err(NetnsLifecycleError::CleanupConsistency)
        );
        assert_eq!(
            Finished::new(
                run.clone(),
                digest.clone(),
                true,
                false,
                0,
                CompletionError::None
            ),
            Err(NetnsLifecycleError::CleanupConsistency)
        );
        for invalid in ["NONE", "", "lower", "HAS-DASH", "_PREFIX"] {
            assert_eq!(
                CompletionError::code(invalid.to_owned()),
                Err(NetnsLifecycleError::CompletionErrorCode)
            );
        }
        assert_eq!(
            CompletionError::code("A".repeat(MAX_LIFECYCLE_ERROR_CODE_BYTES + 1)),
            Err(NetnsLifecycleError::CompletionErrorCode)
        );
    }

    #[test]
    fn framing_rejects_missing_lf_cr_blank_lines_utf8_and_oversize() {
        let valid = Go::new(run_id('9')).encode().expect("encode");
        assert_eq!(
            Go::parse(valid.trim_end_matches('\n').as_bytes()),
            Err(NetnsLifecycleError::MissingFinalLineFeed)
        );
        assert_eq!(
            Go::parse(valid.replace('\n', "\r\n").as_bytes()),
            Err(NetnsLifecycleError::CarriageReturn)
        );
        assert_eq!(
            Go::parse(format!("{valid}\n").as_bytes()),
            Err(NetnsLifecycleError::FrameShape)
        );
        assert_eq!(
            Go::parse(valid.replace("\nrun_id", "\n\nrun_id").as_bytes()),
            Err(NetnsLifecycleError::FrameShape)
        );
        assert_eq!(Go::parse(&[0xff, b'\n']), Err(NetnsLifecycleError::Utf8));
        let oversized = vec![b'a'; MAX_LIFECYCLE_FRAME_BYTES + 1];
        assert_eq!(
            Go::parse(&oversized),
            Err(NetnsLifecycleError::FrameTooLarge)
        );
    }

    #[test]
    fn exact_fields_reject_extras_duplicates_reordering_and_extra_equals() {
        let valid = Go::new(run_id('a')).encode().expect("encode");
        assert_eq!(
            Go::parse(format!("{valid}run_id={}\n", "a".repeat(32)).as_bytes()),
            Err(NetnsLifecycleError::FrameShape)
        );
        assert_eq!(
            Go::parse(valid.replace("run_id=", "nonce=").as_bytes()),
            Err(NetnsLifecycleError::FrameShape)
        );
        assert_eq!(
            Go::parse(valid.replace("run_id=", "run_id==").as_bytes()),
            Err(NetnsLifecycleError::FrameShape)
        );
        let reordered = format!("run_id={}\n{GO_HEADER}\n", "a".repeat(32));
        assert_eq!(
            Go::parse(reordered.as_bytes()),
            Err(NetnsLifecycleError::FrameShape)
        );
    }

    #[test]
    fn directional_frame_enums_reject_frames_from_the_other_side() {
        let run = run_id('b');
        let inner = bootstrap(run.clone()).encode().expect("encode");
        let outer = Go::new(run).encode().expect("encode");
        assert!(matches!(
            InnerLifecycleFrame::parse(inner.as_bytes()),
            Ok(InnerLifecycleFrame::BootstrapReady(_))
        ));
        assert!(matches!(
            OuterLifecycleFrame::parse(outer.as_bytes()),
            Ok(OuterLifecycleFrame::Go(_))
        ));
        assert_eq!(
            InnerLifecycleFrame::parse(outer.as_bytes()),
            Err(NetnsLifecycleError::FrameShape)
        );
        assert_eq!(
            OuterLifecycleFrame::parse(inner.as_bytes()),
            Err(NetnsLifecycleError::FrameShape)
        );
    }

    #[test]
    fn outer_state_machine_accepts_one_complete_bound_exchange() {
        let run = run_id('c');
        let mut outer = outer_state(run.clone());
        let bootstrap_bytes = bootstrap(run.clone()).encode().expect("encode");
        outer
            .accept_bootstrap_ready(bootstrap_bytes.as_bytes())
            .expect("bootstrap");
        assert_eq!(outer.phase(), OuterLifecyclePhase::BootstrapReady);
        let go = outer.go().expect("go");
        assert_eq!(go.run_id(), &run);
        assert_eq!(outer.phase(), OuterLifecyclePhase::GoSent);

        let topology_bytes = topology(run.clone()).encode().expect("encode");
        outer
            .accept_topology_ready(topology_bytes.as_bytes())
            .expect("topology");
        let stop = outer.stop(StopReason::Normal).expect("stop");
        assert_eq!(stop.reason(), StopReason::Normal);
        let finished = successful_finished(run, topology_bytes.as_bytes());
        outer
            .accept_finished(finished.encode().expect("encode").as_bytes())
            .expect("finished");
        assert_eq!(outer.phase(), OuterLifecyclePhase::Finished);
    }

    #[test]
    fn inner_state_machine_requires_affine_go_authorization() {
        let run = run_id('d');
        let mut inner = inner_state(run.clone());
        inner
            .bootstrap_ready(&bootstrap(run.clone()))
            .expect("bootstrap");
        let authorization = inner
            .accept_go(Go::new(run.clone()).encode().expect("encode").as_bytes())
            .expect("go");
        assert_eq!(authorization.run_id(), &run);
        let topology_bytes = inner
            .topology_ready(authorization, &topology(run.clone()))
            .expect("topology");
        inner
            .accept_stop(
                Stop::new(run.clone(), StopReason::Term)
                    .encode()
                    .expect("encode")
                    .as_bytes(),
            )
            .expect("stop");
        let finished = successful_finished(run, topology_bytes.as_bytes());
        inner.finished(&finished).expect("finished");
        assert_eq!(inner.phase(), InnerLifecyclePhase::Finished);
    }

    #[test]
    fn state_machines_reject_wrong_order_nonce_and_duplicates_without_advancing() {
        let run = run_id('e');
        let other = run_id('f');
        let mut outer = outer_state(run.clone());
        assert_eq!(outer.go(), Err(NetnsLifecycleError::StateTransition));
        assert_eq!(
            outer.accept_bootstrap_ready(
                bootstrap(other.clone())
                    .encode()
                    .expect("encode")
                    .as_bytes()
            ),
            Err(NetnsLifecycleError::RunIdMismatch)
        );
        assert_eq!(outer.phase(), OuterLifecyclePhase::AwaitingBootstrap);
        let bootstrap_bytes = bootstrap(run.clone()).encode().expect("encode");
        outer
            .accept_bootstrap_ready(bootstrap_bytes.as_bytes())
            .expect("bootstrap");
        assert_eq!(
            outer.accept_bootstrap_ready(bootstrap_bytes.as_bytes()),
            Err(NetnsLifecycleError::StateTransition)
        );
        outer.go().expect("go");
        assert_eq!(outer.go(), Err(NetnsLifecycleError::StateTransition));

        let mut inner = inner_state(run.clone());
        let go = Go::new(run.clone()).encode().expect("encode");
        assert!(matches!(
            inner.accept_go(go.as_bytes()),
            Err(NetnsLifecycleError::StateTransition)
        ));
        inner
            .bootstrap_ready(&bootstrap(run.clone()))
            .expect("bootstrap");
        assert!(matches!(
            inner.accept_go(Go::new(other).encode().expect("encode").as_bytes()),
            Err(NetnsLifecycleError::RunIdMismatch)
        ));
        assert_eq!(inner.phase(), InnerLifecyclePhase::AwaitingGo);
        let _authorization = inner.accept_go(go.as_bytes()).expect("go");
        assert!(matches!(
            inner.accept_go(go.as_bytes()),
            Err(NetnsLifecycleError::StateTransition)
        ));
    }

    #[test]
    fn eof_before_go_never_authorizes_mutation_and_eof_after_go_requires_cleanup() {
        let run = run_id('1');
        let mut outer = outer_state(run.clone());
        outer
            .accept_bootstrap_ready(bootstrap(run.clone()).encode().expect("encode").as_bytes())
            .expect("bootstrap");
        assert_eq!(
            outer.observe_inner_eof(),
            Ok(LifecycleEofDisposition::NoMutationAuthorized)
        );
        assert_eq!(outer.phase(), OuterLifecyclePhase::PeerClosedBeforeGo);
        assert_eq!(outer.go(), Err(NetnsLifecycleError::StateTransition));

        let mut inner = inner_state(run.clone());
        inner
            .bootstrap_ready(&bootstrap(run.clone()))
            .expect("bootstrap");
        assert_eq!(
            inner.observe_outer_eof(),
            Ok(LifecycleEofDisposition::NoMutationAuthorized)
        );
        assert_eq!(inner.phase(), InnerLifecyclePhase::PeerClosedBeforeGo);

        let mut after_go = inner_state(run.clone());
        after_go
            .bootstrap_ready(&bootstrap(run.clone()))
            .expect("bootstrap");
        let _authorization = after_go
            .accept_go(Go::new(run).encode().expect("encode").as_bytes())
            .expect("go");
        assert_eq!(
            after_go.observe_outer_eof(),
            Ok(LifecycleEofDisposition::CleanupRequired)
        );
        assert_eq!(after_go.phase(), InnerLifecyclePhase::PeerClosedAfterGo);
    }

    #[test]
    fn finished_must_bind_exact_topology_bytes_on_both_sides() {
        let run = run_id('2');
        let topology_bytes = topology(run.clone()).encode().expect("encode");
        let wrong_finished = Finished::new(
            run.clone(),
            LifecycleSha256::digest(b"different exact bytes\n"),
            true,
            true,
            0,
            CompletionError::None,
        )
        .expect("syntactically valid finished");

        let mut outer = outer_state(run.clone());
        outer
            .accept_bootstrap_ready(bootstrap(run.clone()).encode().expect("encode").as_bytes())
            .expect("bootstrap");
        outer.go().expect("go");
        outer
            .accept_topology_ready(topology_bytes.as_bytes())
            .expect("topology");
        outer.stop(StopReason::Normal).expect("stop");
        assert_eq!(
            outer.accept_finished(wrong_finished.encode().expect("encode").as_bytes()),
            Err(NetnsLifecycleError::TopologyFrameDigestMismatch)
        );
        assert_eq!(outer.phase(), OuterLifecyclePhase::StopSent);

        let mut inner = inner_state(run.clone());
        inner
            .bootstrap_ready(&bootstrap(run.clone()))
            .expect("bootstrap");
        let authorization = inner
            .accept_go(Go::new(run.clone()).encode().expect("encode").as_bytes())
            .expect("go");
        inner
            .topology_ready(authorization, &topology(run.clone()))
            .expect("topology");
        inner
            .accept_stop(
                Stop::new(run, StopReason::Normal)
                    .encode()
                    .expect("encode")
                    .as_bytes(),
            )
            .expect("stop");
        assert_eq!(
            inner.finished(&wrong_finished),
            Err(NetnsLifecycleError::TopologyFrameDigestMismatch)
        );
        assert_eq!(inner.phase(), InnerLifecyclePhase::StopReceived);
    }

    #[test]
    fn finished_bounds_remaining_objects_by_the_fixed_topology() {
        let run = run_id('3');
        assert_eq!(
            Finished::new(
                run,
                LifecycleSha256::digest(b"topology"),
                true,
                false,
                MAX_LIFECYCLE_NAMESPACES + 1,
                CompletionError::code("CLEANUP_INCOMPLETE".to_owned()).expect("error code"),
            ),
            Err(NetnsLifecycleError::CleanupConsistency)
        );
    }
}
