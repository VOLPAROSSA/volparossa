//! Fail-closed migration interlock for the retired helper ownership journal.
//!
//! Helper v3 never parses or executes cleanup from the former v1 journal. If that journal exists,
//! production startup stops and an operator must inspect the host explicitly. Those read-only
//! production interlocks cover the retired path and the exact v3 main/lock/next paths; they perform
//! no route, link, firewall, namespace or file mutation. The v3 store below is
//! a dormant, boot-scoped substrate and is not called by production yet.

#![allow(dead_code)] // Dormant v3 store; production uses only read-only ownership interlocks.

mod actor;

// This affine surface is intentionally exported before its production composition is installed.
#[allow(unused_imports)]
pub(crate) use actor::{
    DurableArmOutcome, DurableIntentRegistration, DurableMayOwnPrepare, DurableOwnershipActor,
    DurableOwnershipError, DurableOwnershipKey, DurablePrepareAnchor, DurablePrepareAnchorParts,
    DurableRegistrationOutcome,
};

use crate::{deadline::HardDeadline, lease_spec::WireguardLeaseSpec};

/// Constructs one journal anchor without exposing actor-internal failure types outside this module.
pub(crate) fn durable_prepare_anchor_from_parts(
    parts: DurablePrepareAnchorParts,
) -> Option<DurablePrepareAnchor> {
    DurablePrepareAnchor::try_from_parts(parts).ok()
}

use rand_core::{OsRng, RngCore};
use rustix::{
    fs::{
        AtFlags, FlockOperation, Gid, Mode, OFlags, Uid, fchmod, fchown, flock, openat, renameat,
        statat, unlinkat,
    },
    io::Errno,
    process::getegid,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    num::{NonZeroU32, NonZeroU64},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

/// Starts the dormant actor against a caller-owned temporary directory for cross-module tests.
///
/// The fixture never opens production paths and deliberately accepts one absolute outer deadline.
/// Its recovery executor is a typed exact echo suitable only for deterministic unit tests.
#[cfg(test)]
pub(crate) fn spawn_test_durable_ownership_actor_until(
    parent: &Path,
    deadline: HardDeadline,
) -> Result<DurableOwnershipActor, DurableOwnershipError> {
    let metadata = fs::metadata(parent).map_err(|_| DurableOwnershipError::Unavailable)?;
    let config = JournalConfig::for_test(
        parent,
        metadata.mode() & 0o7777,
        metadata.uid(),
        metadata.gid(),
    );
    DurableOwnershipActor::spawn_with_executor_factory_until(
        config,
        || ExactTestRecoveryExecutor,
        deadline,
    )
}

#[cfg(test)]
struct ExactTestRecoveryExecutor;

#[cfg(test)]
impl RecoveryExecutor for ExactTestRecoveryExecutor {
    type Error = std::convert::Infallible;

    fn confirm_absent(
        &mut self,
        target: &RecoveryTarget,
        _deadline: HardDeadline,
    ) -> Result<ConfirmedAbsentProof, Self::Error> {
        Ok(target.confirmed_absent())
    }
}

const LEGACY_JOURNAL_PATH: &str = "/run/volparossa/helper.ownership-v1";
const OWNERSHIP_JOURNAL_PATH: &str = "/run/volparossa/helper.ownership-v3";
const OWNERSHIP_LOCK_PATH: &str = "/run/volparossa/helper.ownership-v3.lock";
const OWNERSHIP_NEXT_PATH: &str = "/run/volparossa/helper.ownership-v3.next";
const PRODUCTION_PARENT_MODE: u32 = 0o750;
const JOURNAL_FILE_MODE: u32 = 0o600;
const MAX_RECORDS: usize = 1_024;
const MAX_JOURNAL_BYTES: usize = 256 * 1_024;
const MAX_PATHS: usize = 8;
const MAX_PATH_ID: u8 = 8;
const MAX_LEASE_IDENTITIES: usize = 16;
const JOURNAL_MAGIC: [u8; 8] = *b"VOLJRN3\0";
const JOURNAL_VERSION: u16 = 3;
const DIGEST_BYTES: usize = 32;
const DURABLE_WIREGUARD_ALIAS_PREFIX: &str = "volparossa:wireguard:ownership-v1:";
const DURABLE_WIREGUARD_MARKER_DOMAIN: &str =
    "VOLPAROSSA helper durable WireGuard resource marker v1";
const DERIVED_WIREGUARD_INTERFACE_BYTES: usize = 12;

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Id16([u8; 16]);

impl Id16 {
    fn new(value: [u8; 16]) -> Result<Self, JournalError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for Id16 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Id16(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RuntimeId([u8; 32]);

impl RuntimeId {
    fn new(value: [u8; 32]) -> Result<Self, JournalError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct JournalEpochId([u8; 32]);

impl JournalEpochId {
    fn new(value: [u8; 32]) -> Result<Self, JournalError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for JournalEpochId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalEpochId(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct OwnershipId([u8; 32]);

impl OwnershipId {
    fn new(value: [u8; 32]) -> Result<Self, JournalError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for OwnershipId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnershipId(<redacted>)")
    }
}

impl fmt::Debug for RuntimeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeId(<redacted>)")
    }
}

/// Secret-free kernel metadata derived from one exact durable ownership record.
///
/// The alias is public evidence used to reject stale same-name links. It is neither proof of the
/// journal's current phase nor authority to create, adopt, mutate or delete a kernel resource.
/// Construction stays private to this module so callers cannot supply raw ownership coordinates or
/// a free-form alias. The value is deliberately non-`Clone` and its debug form reveals no marker.
#[derive(Eq, PartialEq)]
pub(crate) struct DurableWireguardResource {
    specification: WireguardLeaseSpec,
    ownership_alias: String,
}

impl DurableWireguardResource {
    /// Context-local path and endpoint role committed by the durable record.
    pub(crate) const fn key(&self) -> (u8, i32) {
        self.specification.key()
    }

    /// Exact topology-derived kernel interface name committed by the marker.
    pub(crate) fn interface(&self) -> &str {
        self.specification.interface()
    }

    /// Public fixed-format ownership marker; this is evidence, not authority.
    pub(crate) fn ownership_alias(&self) -> &str {
        &self.ownership_alias
    }

    /// Exact topology-derived local overlay address committed by the marker.
    pub(crate) const fn local_address(&self) -> std::net::Ipv6Addr {
        self.specification.local_address()
    }
}

impl fmt::Debug for DurableWireguardResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableWireguardResource(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ContextRole {
    Client = 1,
    Relay = 2,
    Exit = 3,
}

impl TryFrom<u8> for ContextRole {
    type Error = JournalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Client),
            2 => Ok(Self::Relay),
            3 => Ok(Self::Exit),
            _ => Err(JournalError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
enum WireguardRole {
    Client = 1,
    RelayClient = 2,
    RelayExit = 3,
    Exit = 4,
}

impl WireguardRole {
    fn belongs_to(self, context: ContextRole) -> bool {
        matches!(
            (context, self),
            (ContextRole::Client, Self::Client)
                | (ContextRole::Relay, Self::RelayClient | Self::RelayExit)
                | (ContextRole::Exit, Self::Exit)
        )
    }
}

impl TryFrom<u8> for WireguardRole {
    type Error = JournalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Client),
            2 => Ok(Self::RelayClient),
            3 => Ok(Self::RelayExit),
            4 => Ok(Self::Exit),
            _ => Err(JournalError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PathPlan {
    path_id: u8,
    role: WireguardRole,
}

#[derive(Clone, Eq, PartialEq)]
struct ClosedPlan {
    context_role: ContextRole,
    paths: Vec<PathPlan>,
}

impl ClosedPlan {
    fn new(context_role: ContextRole, paths: Vec<PathPlan>) -> Result<Self, JournalError> {
        if paths.is_empty() || paths.len() > MAX_LEASE_IDENTITIES {
            return Err(JournalError::InvalidRecord);
        }
        let mut seen = BTreeSet::new();
        let mut roles_by_path = BTreeMap::<u8, BTreeSet<WireguardRole>>::new();
        for path in &paths {
            if !(1..=MAX_PATH_ID).contains(&path.path_id)
                || !path.role.belongs_to(context_role)
                || !seen.insert(*path)
            {
                return Err(JournalError::InvalidRecord);
            }
            roles_by_path
                .entry(path.path_id)
                .or_default()
                .insert(path.role);
        }
        if roles_by_path.len() > MAX_PATHS
            || roles_by_path.values().any(|roles| {
                let expected = match context_role {
                    ContextRole::Client => BTreeSet::from([WireguardRole::Client]),
                    ContextRole::Relay => {
                        BTreeSet::from([WireguardRole::RelayClient, WireguardRole::RelayExit])
                    }
                    ContextRole::Exit => BTreeSet::from([WireguardRole::Exit]),
                };
                *roles != expected
            })
        {
            return Err(JournalError::InvalidRecord);
        }
        let mut paths = paths;
        paths.sort_unstable();
        Ok(Self {
            context_role,
            paths,
        })
    }

    /// Convert the externally validated recovery plan without silently canonicalising it.
    ///
    /// The durable intent must commit the same canonical identity order that appeared on tag 35.
    /// Accepting a permutation here and sorting it would give the journal a different semantic
    /// boundary from the helper protocol.
    fn try_from_wire(value: &volparossa_routing::ClosedPreparePlan) -> Result<Self, JournalError> {
        if !(1..=MAX_LEASE_IDENTITIES).contains(&value.leases.len()) {
            return Err(JournalError::InvalidRecord);
        }
        let context_role = match volparossa_routing::ContextRole::try_from(value.context_role)
            .map_err(|_| JournalError::InvalidRecord)?
        {
            volparossa_routing::ContextRole::Client => ContextRole::Client,
            volparossa_routing::ContextRole::Relay => ContextRole::Relay,
            volparossa_routing::ContextRole::Exit => ContextRole::Exit,
            volparossa_routing::ContextRole::Unspecified => {
                return Err(JournalError::InvalidRecord);
            }
        };
        let mut paths = Vec::with_capacity(value.leases.len());
        for lease in &value.leases {
            let path_id = u8::try_from(lease.path_id).map_err(|_| JournalError::InvalidRecord)?;
            let role = match volparossa_routing::WireguardRole::try_from(lease.role)
                .map_err(|_| JournalError::InvalidRecord)?
            {
                volparossa_routing::WireguardRole::Client => WireguardRole::Client,
                volparossa_routing::WireguardRole::RelayClient => WireguardRole::RelayClient,
                volparossa_routing::WireguardRole::RelayExit => WireguardRole::RelayExit,
                volparossa_routing::WireguardRole::Exit => WireguardRole::Exit,
                volparossa_routing::WireguardRole::Unspecified => {
                    return Err(JournalError::InvalidRecord);
                }
            };
            paths.push(PathPlan { path_id, role });
        }
        if paths.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(JournalError::InvalidRecord);
        }
        Self::new(context_role, paths)
    }
}

impl fmt::Debug for ClosedPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedPlan")
            .field("context_role", &self.context_role)
            .field("path_count", &self.paths.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum OwnershipPhase {
    Intent = 1,
    MayOwnPrepare = 2,
    Absent = 3,
}

impl TryFrom<u8> for OwnershipPhase {
    type Error = JournalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Intent),
            2 => Ok(Self::MayOwnPrepare),
            3 => Ok(Self::Absent),
            _ => Err(JournalError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum AbsentOrigin {
    NeverDispatched = 1,
    RecoveredMayOwn = 2,
}

impl TryFrom<u8> for AbsentOrigin {
    type Error = JournalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::NeverDispatched),
            2 => Ok(Self::RecoveredMayOwn),
            _ => Err(JournalError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ReconcileBinding {
    request_id: Id16,
    operation_digest: [u8; DIGEST_BYTES],
}

impl fmt::Debug for ReconcileBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReconcileBinding(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PrepareRecoveryAnchorV1 {
    boot_id: Id16,
    pid: NonZeroU32,
    process_start_ticks: NonZeroU64,
    network_namespace_device: NonZeroU64,
    network_namespace_inode: NonZeroU64,
    executable_device: NonZeroU64,
    executable_inode: NonZeroU64,
    service_cgroup_inode: NonZeroU64,
}

impl fmt::Debug for PrepareRecoveryAnchorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrepareRecoveryAnchorV1(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct OwnershipRecord {
    journal_epoch_id: JournalEpochId,
    origin_runtime_id: RuntimeId,
    ownership_id: OwnershipId,
    context_id: Id16,
    prepare_request_id: Id16,
    prepare_operation_digest: [u8; DIGEST_BYTES],
    generation: NonZeroU64,
    setup_expires_at_unix: NonZeroU64,
    hard_expires_at_unix: NonZeroU64,
    plan: ClosedPlan,
    phase: OwnershipPhase,
    absent_origin: Option<AbsentOrigin>,
    reconcile: Option<ReconcileBinding>,
    recovery_anchor: Option<PrepareRecoveryAnchorV1>,
}

impl OwnershipRecord {
    fn validate(&self) -> Result<(), JournalError> {
        let phase_evidence_is_valid = matches!(
            (self.phase, self.absent_origin, self.recovery_anchor),
            (OwnershipPhase::Intent, None, None)
                | (OwnershipPhase::MayOwnPrepare, None, Some(_))
                | (
                    OwnershipPhase::Absent,
                    Some(AbsentOrigin::NeverDispatched | AbsentOrigin::RecoveredMayOwn),
                    None
                )
        );
        if self.hard_expires_at_unix < self.setup_expires_at_unix || !phase_evidence_is_valid {
            return Err(JournalError::InvalidRecord);
        }
        let canonical = ClosedPlan::new(self.plan.context_role, self.plan.paths.clone())?;
        if canonical != self.plan {
            return Err(JournalError::InvalidRecord);
        }
        Ok(())
    }

    /// Project the immutable durable identity into exact per-link public kernel markers.
    ///
    /// Validation precedes every construction. Mutable lifecycle and reconciliation evidence is
    /// intentionally excluded so the marker remains stable until exact cleanup is proved.
    fn durable_wireguard_resources(&self) -> Result<Vec<DurableWireguardResource>, JournalError> {
        self.validate()?;
        let path_count =
            u8::try_from(self.plan.paths.len()).map_err(|_| JournalError::InvalidRecord)?;
        let mut resources = Vec::with_capacity(self.plan.paths.len());
        for resource_path in &self.plan.paths {
            let specification = WireguardLeaseSpec::derive(
                self.context_id.0,
                routing_context_role(self.plan.context_role),
                u32::from(resource_path.path_id),
                routing_wireguard_role(resource_path.role) as i32,
            )
            .map_err(|_| JournalError::InvalidRecord)?;
            if specification.interface().len() != DERIVED_WIREGUARD_INTERFACE_BYTES
                || specification.key()
                    != (
                        resource_path.path_id,
                        routing_wireguard_role(resource_path.role) as i32,
                    )
            {
                return Err(JournalError::InvalidRecord);
            }

            let mut marker = blake3::Hasher::new_derive_key(DURABLE_WIREGUARD_MARKER_DOMAIN);
            marker.update(&self.journal_epoch_id.0);
            marker.update(&self.origin_runtime_id.0);
            marker.update(&self.ownership_id.0);
            marker.update(&self.context_id.0);
            marker.update(&self.prepare_request_id.0);
            marker.update(&self.prepare_operation_digest);
            marker.update(&self.generation.get().to_be_bytes());
            marker.update(&self.setup_expires_at_unix.get().to_be_bytes());
            marker.update(&self.hard_expires_at_unix.get().to_be_bytes());
            marker.update(&[self.plan.context_role as u8, path_count]);
            for path in &self.plan.paths {
                marker.update(&[path.path_id, path.role as u8]);
            }
            marker.update(&[resource_path.path_id, resource_path.role as u8]);
            marker.update(specification.interface().as_bytes());
            marker.update(&specification.local_address().octets());
            let digest = marker.finalize();
            let ownership_alias = format!(
                "{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:{}",
                specification.interface(),
                digest.to_hex()
            );
            resources.push(DurableWireguardResource {
                specification,
                ownership_alias,
            });
        }
        Ok(resources)
    }

    fn advance(
        &mut self,
        next: OwnershipPhase,
        recovery_anchor: Option<PrepareRecoveryAnchorV1>,
        absent_origin: Option<AbsentOrigin>,
    ) -> Result<(), JournalError> {
        let transition_is_valid = matches!(
            (self.phase, next, absent_origin, recovery_anchor),
            (
                OwnershipPhase::Intent,
                OwnershipPhase::MayOwnPrepare,
                None,
                Some(_)
            ) | (
                OwnershipPhase::Intent,
                OwnershipPhase::Absent,
                Some(AbsentOrigin::NeverDispatched),
                None
            ) | (
                OwnershipPhase::MayOwnPrepare,
                OwnershipPhase::Absent,
                Some(AbsentOrigin::RecoveredMayOwn),
                None
            )
        );
        if !transition_is_valid {
            return Err(JournalError::InvalidTransition);
        }
        let mut candidate = self.clone();
        candidate.phase = next;
        candidate.absent_origin = absent_origin;
        candidate.recovery_anchor = recovery_anchor;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }
}

const fn routing_context_role(role: ContextRole) -> volparossa_routing::ContextRole {
    match role {
        ContextRole::Client => volparossa_routing::ContextRole::Client,
        ContextRole::Relay => volparossa_routing::ContextRole::Relay,
        ContextRole::Exit => volparossa_routing::ContextRole::Exit,
    }
}

const fn routing_wireguard_role(role: WireguardRole) -> volparossa_routing::WireguardRole {
    match role {
        WireguardRole::Client => volparossa_routing::WireguardRole::Client,
        WireguardRole::RelayClient => volparossa_routing::WireguardRole::RelayClient,
        WireguardRole::RelayExit => volparossa_routing::WireguardRole::RelayExit,
        WireguardRole::Exit => volparossa_routing::WireguardRole::Exit,
    }
}

/// Build one deterministic marker fixture without adding a production raw-marker constructor.
#[cfg(test)]
pub(crate) fn durable_wireguard_resource_for_test(
    route_context_id: [u8; 16],
    context_role: volparossa_routing::ContextRole,
    path_id: u8,
    role: volparossa_routing::WireguardRole,
    ownership_seed: u8,
) -> Option<DurableWireguardResource> {
    if route_context_id.iter().all(|byte| *byte == 0)
        || !(1..=MAX_PATH_ID).contains(&path_id)
        || !(1..=240).contains(&ownership_seed)
    {
        return None;
    }
    let context_role = match context_role {
        volparossa_routing::ContextRole::Client => ContextRole::Client,
        volparossa_routing::ContextRole::Relay => ContextRole::Relay,
        volparossa_routing::ContextRole::Exit => ContextRole::Exit,
        volparossa_routing::ContextRole::Unspecified => return None,
    };
    let requested_role = match role {
        volparossa_routing::WireguardRole::Client => WireguardRole::Client,
        volparossa_routing::WireguardRole::RelayClient => WireguardRole::RelayClient,
        volparossa_routing::WireguardRole::RelayExit => WireguardRole::RelayExit,
        volparossa_routing::WireguardRole::Exit => WireguardRole::Exit,
        volparossa_routing::WireguardRole::Unspecified => return None,
    };
    if !requested_role.belongs_to(context_role) {
        return None;
    }
    let paths = match context_role {
        ContextRole::Client => vec![PathPlan {
            path_id,
            role: WireguardRole::Client,
        }],
        ContextRole::Relay => vec![
            PathPlan {
                path_id,
                role: WireguardRole::RelayClient,
            },
            PathPlan {
                path_id,
                role: WireguardRole::RelayExit,
            },
        ],
        ContextRole::Exit => vec![PathPlan {
            path_id,
            role: WireguardRole::Exit,
        }],
    };
    let origin_seed = ownership_seed.checked_add(1)?;
    let owner_seed = ownership_seed.checked_add(2)?;
    let request_seed = ownership_seed.checked_add(3)?;
    let digest_seed = ownership_seed.checked_add(4)?;
    let generation = NonZeroU64::new(u64::from(ownership_seed))?;
    let record = OwnershipRecord {
        journal_epoch_id: JournalEpochId::new([ownership_seed; 32]).ok()?,
        origin_runtime_id: RuntimeId::new([origin_seed; 32]).ok()?,
        ownership_id: OwnershipId::new([owner_seed; 32]).ok()?,
        context_id: Id16::new(route_context_id).ok()?,
        prepare_request_id: Id16::new([request_seed; 16]).ok()?,
        prepare_operation_digest: [digest_seed; DIGEST_BYTES],
        generation,
        setup_expires_at_unix: NonZeroU64::new(1_000 + u64::from(ownership_seed))?,
        hard_expires_at_unix: NonZeroU64::new(2_000 + u64::from(ownership_seed))?,
        plan: ClosedPlan::new(context_role, paths).ok()?,
        phase: OwnershipPhase::Intent,
        absent_origin: None,
        reconcile: None,
        recovery_anchor: None,
    };
    record
        .durable_wireguard_resources()
        .ok()?
        .into_iter()
        .find(|resource| resource.key() == (path_id, role as i32))
}

impl fmt::Debug for OwnershipRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnershipRecord")
            .field("journal_epoch_id", &"<redacted>")
            .field("origin_runtime_id", &"<redacted>")
            .field("ownership_id", &"<redacted>")
            .field("context_id", &"<redacted>")
            .field("prepare_request_id", &"<redacted>")
            .field("prepare_operation_digest", &"<redacted>")
            .field("generation", &"<redacted>")
            .field("setup_expires_at_unix", &"<redacted>")
            .field("hard_expires_at_unix", &"<redacted>")
            .field("plan", &self.plan)
            .field("phase", &self.phase)
            .field("absent_origin", &self.absent_origin)
            .field("reconcile", &self.reconcile)
            .field("recovery_anchor", &self.recovery_anchor)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
enum JournalError {
    #[error("journal I/O failed")]
    Io(#[from] io::Error),
    #[error("journal record is invalid")]
    InvalidRecord,
    #[error("journal transition is invalid")]
    InvalidTransition,
    #[error("journal encoding is corrupt")]
    Corrupt,
    #[error("journal capacity is exhausted")]
    Capacity,
    #[error("journal revision conflict")]
    RevisionConflict,
    #[error("journal persistence is uncertain")]
    PersistUncertain,
    #[error("journal store is poisoned")]
    Poisoned,
    #[error("journal runtime lock is already held")]
    LockHeld,
    #[error("journal filesystem metadata is unsafe")]
    UnsafeMetadata,
    #[error("secure random generation failed")]
    Random,
    #[error("recovery proof does not match the exact ownership record")]
    ProofMismatch,
}

#[derive(Clone, Eq, PartialEq)]
struct JournalSnapshot {
    journal_epoch_id: JournalEpochId,
    revision: u64,
    next_generation: u64,
    records: BTreeMap<OwnershipId, OwnershipRecord>,
}

impl JournalSnapshot {
    fn empty(journal_epoch_id: JournalEpochId) -> Self {
        Self {
            journal_epoch_id,
            revision: 0,
            next_generation: 1,
            records: BTreeMap::new(),
        }
    }

    fn validate(&self) -> Result<(), JournalError> {
        if self.records.len() > MAX_RECORDS || self.next_generation == 0 {
            return Err(JournalError::Capacity);
        }
        let mut generations = BTreeSet::new();
        let mut context_ids = BTreeSet::new();
        let mut prepare_request_ids = BTreeSet::new();
        let mut reconcile_request_ids = BTreeSet::new();
        for (key, record) in &self.records {
            if *key != record.ownership_id
                || record.journal_epoch_id != self.journal_epoch_id
                || record.generation.get() >= self.next_generation
                || !generations.insert(record.generation)
                || !context_ids.insert(record.context_id)
                || !prepare_request_ids.insert(record.prepare_request_id)
                || record.reconcile.is_some_and(|binding| {
                    !reconcile_request_ids.insert(binding.request_id)
                        || prepare_request_ids.contains(&binding.request_id)
                })
            {
                return Err(JournalError::InvalidRecord);
            }
            record.validate()?;
        }
        if prepare_request_ids
            .iter()
            .any(|request_id| reconcile_request_ids.contains(request_id))
        {
            return Err(JournalError::InvalidRecord);
        }
        Ok(())
    }

    fn mint_generation(&mut self) -> Result<NonZeroU64, JournalError> {
        let generation = NonZeroU64::new(self.next_generation).ok_or(JournalError::Capacity)?;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(JournalError::Capacity)?;
        Ok(generation)
    }

    fn encode(&self) -> Result<Vec<u8>, JournalError> {
        self.validate()?;
        let mut encoded = Vec::with_capacity(128 + self.records.len() * 192);
        encoded.extend_from_slice(&JOURNAL_MAGIC);
        put_u16(&mut encoded, JOURNAL_VERSION);
        encoded.extend_from_slice(&self.journal_epoch_id.0);
        put_u64(&mut encoded, self.revision);
        put_u64(&mut encoded, self.next_generation);
        put_u32(
            &mut encoded,
            u32::try_from(self.records.len()).map_err(|_| JournalError::Capacity)?,
        );
        for record in self.records.values() {
            encode_record(&mut encoded, record);
            if encoded.len() + DIGEST_BYTES > MAX_JOURNAL_BYTES {
                return Err(JournalError::Capacity);
            }
        }
        let checksum = blake3::hash(&encoded);
        encoded.extend_from_slice(checksum.as_bytes());
        if encoded.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::Capacity);
        }
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, JournalError> {
        const PREFIX_BYTES: usize = 8 + 2 + 32 + 8 + 8 + 4;
        if encoded.len() < PREFIX_BYTES + DIGEST_BYTES || encoded.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::Corrupt);
        }
        let payload_len = encoded.len() - DIGEST_BYTES;
        let (payload, checksum) = encoded.split_at(payload_len);
        let expected = blake3::hash(payload);
        if expected.as_bytes().ct_eq(checksum).unwrap_u8() != 1 {
            return Err(JournalError::Corrupt);
        }

        let mut decoder = Decoder::new(payload);
        if decoder.take::<8>()? != JOURNAL_MAGIC || decoder.u16()? != JOURNAL_VERSION {
            return Err(JournalError::Corrupt);
        }
        let journal_epoch_id =
            JournalEpochId::new(decoder.take::<32>()?).map_err(|_| JournalError::Corrupt)?;
        let revision = decoder.u64()?;
        let next_generation = decoder.u64()?;
        let record_count = usize::try_from(decoder.u32()?).map_err(|_| JournalError::Corrupt)?;
        if record_count > MAX_RECORDS {
            return Err(JournalError::Corrupt);
        }
        let mut records = BTreeMap::new();
        let mut previous = None;
        for _ in 0..record_count {
            let record = decode_record(&mut decoder)?;
            if previous.is_some_and(|value| value >= record.ownership_id) {
                return Err(JournalError::Corrupt);
            }
            previous = Some(record.ownership_id);
            records.insert(record.ownership_id, record);
        }
        if !decoder.is_empty() {
            return Err(JournalError::Corrupt);
        }
        let snapshot = Self {
            journal_epoch_id,
            revision,
            next_generation,
            records,
        };
        snapshot.validate().map_err(|_| JournalError::Corrupt)?;
        Ok(snapshot)
    }
}

impl fmt::Debug for JournalSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalSnapshot")
            .field("journal_epoch_id", &"<redacted>")
            .field("revision", &self.revision)
            .field("next_generation", &self.next_generation)
            .field("record_count", &self.records.len())
            .finish()
    }
}

fn encode_record(encoded: &mut Vec<u8>, record: &OwnershipRecord) {
    encoded.extend_from_slice(&record.journal_epoch_id.0);
    encoded.extend_from_slice(&record.origin_runtime_id.0);
    encoded.extend_from_slice(&record.ownership_id.0);
    encoded.extend_from_slice(&record.context_id.0);
    encoded.extend_from_slice(&record.prepare_request_id.0);
    encoded.extend_from_slice(&record.prepare_operation_digest);
    put_u64(encoded, record.generation.get());
    put_u64(encoded, record.setup_expires_at_unix.get());
    put_u64(encoded, record.hard_expires_at_unix.get());
    encoded.push(record.plan.context_role as u8);
    encoded.push(u8::try_from(record.plan.paths.len()).expect("closed plan length"));
    for path in &record.plan.paths {
        encoded.push(path.path_id);
        encoded.push(path.role as u8);
    }
    encoded.push(record.phase as u8);
    match record.absent_origin {
        None => encoded.push(0),
        Some(origin) => {
            encoded.push(1);
            encoded.push(origin as u8);
        }
    }
    match record.reconcile {
        None => encoded.push(0),
        Some(binding) => {
            encoded.push(1);
            encoded.extend_from_slice(&binding.request_id.0);
            encoded.extend_from_slice(&binding.operation_digest);
        }
    }
    match record.recovery_anchor {
        None => encoded.push(0),
        Some(anchor) => {
            encoded.push(1);
            encoded.extend_from_slice(&anchor.boot_id.0);
            put_u32(encoded, anchor.pid.get());
            put_u64(encoded, anchor.process_start_ticks.get());
            put_u64(encoded, anchor.network_namespace_device.get());
            put_u64(encoded, anchor.network_namespace_inode.get());
            put_u64(encoded, anchor.executable_device.get());
            put_u64(encoded, anchor.executable_inode.get());
            put_u64(encoded, anchor.service_cgroup_inode.get());
        }
    }
}

fn decode_record(decoder: &mut Decoder<'_>) -> Result<OwnershipRecord, JournalError> {
    let journal_epoch_id =
        JournalEpochId::new(decoder.take::<32>()?).map_err(|_| JournalError::Corrupt)?;
    let origin_runtime_id =
        RuntimeId::new(decoder.take::<32>()?).map_err(|_| JournalError::Corrupt)?;
    let ownership_id =
        OwnershipId::new(decoder.take::<32>()?).map_err(|_| JournalError::Corrupt)?;
    let context_id = Id16::new(decoder.take::<16>()?).map_err(|_| JournalError::Corrupt)?;
    let prepare_request_id = Id16::new(decoder.take::<16>()?).map_err(|_| JournalError::Corrupt)?;
    let prepare_operation_digest = decoder.take::<DIGEST_BYTES>()?;
    let generation = nonzero(decoder.u64()?)?;
    let setup_expires_at_unix = nonzero(decoder.u64()?)?;
    let hard_expires_at_unix = nonzero(decoder.u64()?)?;
    let context_role = ContextRole::try_from(decoder.u8()?).map_err(|_| JournalError::Corrupt)?;
    let path_count = usize::from(decoder.u8()?);
    if !(1..=MAX_LEASE_IDENTITIES).contains(&path_count) {
        return Err(JournalError::Corrupt);
    }
    let mut paths = Vec::with_capacity(path_count);
    for _ in 0..path_count {
        paths.push(PathPlan {
            path_id: decoder.u8()?,
            role: WireguardRole::try_from(decoder.u8()?).map_err(|_| JournalError::Corrupt)?,
        });
    }
    if paths.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(JournalError::Corrupt);
    }
    let plan = ClosedPlan::new(context_role, paths).map_err(|_| JournalError::Corrupt)?;
    let phase = OwnershipPhase::try_from(decoder.u8()?).map_err(|_| JournalError::Corrupt)?;
    let absent_origin = match decoder.u8()? {
        0 => None,
        1 => Some(AbsentOrigin::try_from(decoder.u8()?).map_err(|_| JournalError::Corrupt)?),
        _ => return Err(JournalError::Corrupt),
    };
    let reconcile = match decoder.u8()? {
        0 => None,
        1 => Some(ReconcileBinding {
            request_id: Id16::new(decoder.take::<16>()?).map_err(|_| JournalError::Corrupt)?,
            operation_digest: decoder.take::<DIGEST_BYTES>()?,
        }),
        _ => return Err(JournalError::Corrupt),
    };
    let recovery_anchor = match decoder.u8()? {
        0 => None,
        1 => Some(PrepareRecoveryAnchorV1 {
            boot_id: Id16::new(decoder.take::<16>()?).map_err(|_| JournalError::Corrupt)?,
            pid: nonzero_u32(decoder.u32()?)?,
            process_start_ticks: nonzero(decoder.u64()?)?,
            network_namespace_device: nonzero(decoder.u64()?)?,
            network_namespace_inode: nonzero(decoder.u64()?)?,
            executable_device: nonzero(decoder.u64()?)?,
            executable_inode: nonzero(decoder.u64()?)?,
            service_cgroup_inode: nonzero(decoder.u64()?)?,
        }),
        _ => return Err(JournalError::Corrupt),
    };
    let record = OwnershipRecord {
        journal_epoch_id,
        origin_runtime_id,
        ownership_id,
        context_id,
        prepare_request_id,
        prepare_operation_digest,
        generation,
        setup_expires_at_unix,
        hard_expires_at_unix,
        plan,
        phase,
        absent_origin,
        reconcile,
        recovery_anchor,
    };
    record.validate().map_err(|_| JournalError::Corrupt)?;
    Ok(record)
}

fn nonzero(value: u64) -> Result<NonZeroU64, JournalError> {
    NonZeroU64::new(value).ok_or(JournalError::Corrupt)
}

fn nonzero_u32(value: u32) -> Result<NonZeroU32, JournalError> {
    NonZeroU32::new(value).ok_or(JournalError::Corrupt)
}

fn put_u16(encoded: &mut Vec<u8>, value: u16) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(encoded: &mut Vec<u8>, value: u32) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(encoded: &mut Vec<u8>, value: u64) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

struct Decoder<'a> {
    encoded: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self {
            encoded,
            position: 0,
        }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], JournalError> {
        let end = self.position.checked_add(N).ok_or(JournalError::Corrupt)?;
        let bytes = self
            .encoded
            .get(self.position..end)
            .ok_or(JournalError::Corrupt)?;
        self.position = end;
        bytes.try_into().map_err(|_| JournalError::Corrupt)
    }

    fn u8(&mut self) -> Result<u8, JournalError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, JournalError> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, JournalError> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, JournalError> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    fn is_empty(&self) -> bool {
        self.position == self.encoded.len()
    }
}

#[derive(Clone)]
struct JournalConfig {
    parent_path: PathBuf,
    journal_path: PathBuf,
    lock_path: PathBuf,
    next_path: PathBuf,
    expected_parent_mode: u32,
    expected_owner_uid: u32,
    expected_owner_gid: u32,
}

impl JournalConfig {
    fn production() -> Self {
        Self {
            parent_path: PathBuf::from("/run/volparossa"),
            journal_path: PathBuf::from(OWNERSHIP_JOURNAL_PATH),
            lock_path: PathBuf::from(OWNERSHIP_LOCK_PATH),
            next_path: PathBuf::from(OWNERSHIP_NEXT_PATH),
            expected_parent_mode: PRODUCTION_PARENT_MODE,
            expected_owner_uid: 0,
            expected_owner_gid: getegid().as_raw(),
        }
    }

    fn validate(&self) -> Result<(), JournalError> {
        if self.journal_path.parent() != Some(self.parent_path.as_path())
            || self.lock_path.parent() != Some(self.parent_path.as_path())
            || self.next_path.parent() != Some(self.parent_path.as_path())
            || self.journal_path == self.lock_path
            || self.journal_path == self.next_path
            || self.lock_path == self.next_path
            || self.journal_path.file_name() != Some(std::ffi::OsStr::new("helper.ownership-v3"))
            || self.lock_path.file_name() != Some(std::ffi::OsStr::new("helper.ownership-v3.lock"))
            || self.next_path.file_name() != Some(std::ffi::OsStr::new("helper.ownership-v3.next"))
            || self.expected_parent_mode & !0o7777 != 0
        {
            return Err(JournalError::UnsafeMetadata);
        }
        Ok(())
    }

    #[cfg(test)]
    #[allow(clippy::similar_names)]
    fn for_test(
        parent_path: &Path,
        expected_parent_mode: u32,
        expected_owner_uid: u32,
        expected_owner_gid: u32,
    ) -> Self {
        Self {
            parent_path: parent_path.to_path_buf(),
            journal_path: parent_path.join("helper.ownership-v3"),
            lock_path: parent_path.join("helper.ownership-v3.lock"),
            next_path: parent_path.join("helper.ownership-v3.next"),
            expected_parent_mode,
            expected_owner_uid,
            expected_owner_gid,
        }
    }
}

impl fmt::Debug for JournalConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalConfig")
            .field("paths", &"<fixed-or-test-scoped>")
            .field("expected_parent_mode", &self.expected_parent_mode)
            .field("expected_owner_uid", &self.expected_owner_uid)
            .field("expected_owner_gid", &self.expected_owner_gid)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct NewOwnershipIntent {
    origin_runtime_id: RuntimeId,
    ownership_id: OwnershipId,
    context_id: Id16,
    prepare_request_id: Id16,
    prepare_operation_digest: [u8; DIGEST_BYTES],
    setup_expires_at_unix: NonZeroU64,
    hard_expires_at_unix: NonZeroU64,
    plan: ClosedPlan,
}

impl fmt::Debug for NewOwnershipIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewOwnershipIntent")
            .field("identities", &"<redacted>")
            .field("deadlines", &"<redacted>")
            .field("plan", &self.plan)
            .finish_non_exhaustive()
    }
}

fn record_matches_intent(record: &OwnershipRecord, intent: &NewOwnershipIntent) -> bool {
    record.origin_runtime_id == intent.origin_runtime_id
        && record.ownership_id == intent.ownership_id
        && record.context_id == intent.context_id
        && record.prepare_request_id == intent.prepare_request_id
        && record.prepare_operation_digest == intent.prepare_operation_digest
        && record.setup_expires_at_unix == intent.setup_expires_at_unix
        && record.hard_expires_at_unix == intent.hard_expires_at_unix
        && record.plan == intent.plan
}

fn record_is_exact_post_insert(record: &OwnershipRecord, intent: &NewOwnershipIntent) -> bool {
    record_matches_intent(record, intent)
        && record.phase == OwnershipPhase::Intent
        && record.absent_origin.is_none()
        && record.reconcile.is_none()
        && record.recovery_anchor.is_none()
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct InsertedOwnership {
    ownership_id: OwnershipId,
    generation: NonZeroU64,
    revision: u64,
}

impl fmt::Debug for InsertedOwnership {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InsertedOwnership(<redacted>)")
    }
}

/// Result of durably crossing the point after which Prepare may have created resources.
///
/// The descriptors are projected from the exact validated ownership record before persistence,
/// but this value is constructed only after the transition is known durable. That ordering keeps
/// callers from observing cleanup authority for a merely in-memory candidate.
struct MarkedMayOwnPrepare {
    revision: u64,
    resources: Vec<DurableWireguardResource>,
}

impl fmt::Debug for MarkedMayOwnPrepare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MarkedMayOwnPrepare(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct RecoveryTarget {
    exact_record: OwnershipRecord,
}

impl RecoveryTarget {
    /// Re-derive the exact public kernel markers committed by this validated durable record.
    ///
    /// These descriptors let a future trusted recovery backend inventory exact resources. They do
    /// not themselves prove absence or grant cleanup authority.
    fn durable_wireguard_resources(&self) -> Result<Vec<DurableWireguardResource>, JournalError> {
        self.exact_record.durable_wireguard_resources()
    }

    /// Constructs only a typed echo, not cryptographic or kernel evidence. A trusted executor may
    /// call this only after a complete exact-owner inventory has proved absence. This dormant
    /// slice deliberately provides no production executor.
    fn confirmed_absent(&self) -> ConfirmedAbsentProof {
        ConfirmedAbsentProof {
            exact_record: self.exact_record.clone(),
        }
    }
}

impl fmt::Debug for RecoveryTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryTarget(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ConfirmedAbsentProof {
    exact_record: OwnershipRecord,
}

impl fmt::Debug for ConfirmedAbsentProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmedAbsentProof(<redacted>)")
    }
}

/// Trusted recovery boundary; implementations must prove absence before returning the exact echo.
/// The test fake below is the only implementation until production recovery is separately wired.
trait RecoveryExecutor {
    type Error;

    fn confirm_absent(
        &mut self,
        target: &RecoveryTarget,
        deadline: HardDeadline,
    ) -> Result<ConfirmedAbsentProof, Self::Error>;
}

#[derive(Debug)]
enum RecoveryAttemptError<ExecutorError> {
    Journal(JournalError),
    Executor(ExecutorError),
    Deadline,
}

struct OwnershipJournal {
    config: JournalConfig,
    parent_directory: File,
    runtime_lock: File,
    snapshot: JournalSnapshot,
    poisoned: bool,
}

impl OwnershipJournal {
    fn open_production() -> Result<Self, JournalError> {
        Self::open(JournalConfig::production())
    }

    fn open(config: JournalConfig) -> Result<Self, JournalError> {
        config.validate()?;
        let parent_directory = open_verified_parent(&config)?;
        Self::open_with_verified_parent(config, parent_directory)
    }

    /// Completes journal startup through one already verified directory object. Callers that need
    /// to latch that object before any lock creation or stale-next cleanup must never reopen the
    /// parent path between verification and this constructor.
    fn open_with_verified_parent(
        config: JournalConfig,
        parent_directory: File,
    ) -> Result<Self, JournalError> {
        config.validate()?;
        verify_parent_descriptor(&config, &parent_directory)?;
        let runtime_lock = open_runtime_lock(&config, &parent_directory)?;
        cleanup_stale_next(&config, &parent_directory)?;
        let snapshot = match load_snapshot(&config, &parent_directory)? {
            Some(snapshot) => snapshot,
            None => JournalSnapshot::empty(random_journal_epoch_id()?),
        };
        Ok(Self {
            config,
            parent_directory,
            runtime_lock,
            snapshot,
            poisoned: false,
        })
    }

    fn snapshot(&self) -> Result<&JournalSnapshot, JournalError> {
        self.ensure_usable()?;
        Ok(&self.snapshot)
    }

    fn ensure_usable(&self) -> Result<(), JournalError> {
        if self.poisoned {
            Err(JournalError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn ensure_expected_revision(&self, expected_revision: u64) -> Result<(), JournalError> {
        self.ensure_usable()?;
        if self.snapshot.revision != expected_revision {
            return Err(JournalError::RevisionConflict);
        }
        Ok(())
    }

    fn ensure_durable_matches(&self) -> Result<(), JournalError> {
        self.ensure_usable()?;
        let durable = load_snapshot(&self.config, &self.parent_directory)?;
        let exact = if self.snapshot.revision == 0 {
            durable.is_none()
        } else {
            durable.as_ref() == Some(&self.snapshot)
        };
        if !exact {
            return Err(JournalError::RevisionConflict);
        }
        Ok(())
    }

    /// Re-establishes that a persistence failure classified as pre-rename left this runtime's
    /// complete authority boundary unchanged before another mutation may be attempted.
    ///
    /// This is deliberately stricter than `ensure_durable_matches`: the retained parent and lock
    /// descriptors must still name the exact secure directory entries, this runtime must still
    /// own the exclusive lock, no temporary journal entry may exist, and the durable main entry
    /// must decode to the exact in-memory snapshot. The check never repairs or removes anything.
    /// Any inability to prove the complete state poisons this journal permanently.
    fn confirm_retry_safe_after_definite_failure(&mut self) -> Result<(), JournalError> {
        self.ensure_usable()?;
        let verified = (|| {
            verify_parent_descriptor(&self.config, &self.parent_directory)?;
            verify_runtime_lock_held(&self.config, &self.parent_directory, &self.runtime_lock)?;
            verify_next_absent(&self.config, &self.parent_directory)?;
            self.ensure_durable_matches()?;

            // Bracket the durable read so a replaced parent or lock entry is not accepted merely
            // because the retained directory descriptor still points at the former directory.
            verify_parent_descriptor(&self.config, &self.parent_directory)?;
            verify_runtime_lock_entry(&self.config, &self.parent_directory, &self.runtime_lock)?;
            verify_next_absent(&self.config, &self.parent_directory)
        })();
        if verified.is_err() {
            self.poisoned = true;
            return Err(JournalError::Poisoned);
        }
        Ok(())
    }

    fn insert_intent(
        &mut self,
        expected_revision: u64,
        intent: NewOwnershipIntent,
    ) -> Result<InsertedOwnership, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        // A durable insert may have completed after its reply was lost. Only the complete immutable
        // intent is an idempotency key; every partial match remains a conflicting new insert.
        if let Some(record) = self.snapshot.records.get(&intent.ownership_id) {
            if !record_matches_intent(record, &intent) {
                return Err(JournalError::InvalidRecord);
            }
            if !record_is_exact_post_insert(record, &intent) {
                return Err(JournalError::InvalidTransition);
            }
            let inserted = InsertedOwnership {
                ownership_id: record.ownership_id,
                generation: record.generation,
                revision: self.snapshot.revision,
            };
            self.ensure_durable_matches()?;
            return Ok(inserted);
        }
        if self.snapshot.records.len() >= MAX_RECORDS
            || self
                .snapshot
                .records
                .values()
                .any(|record| record.context_id == intent.context_id)
            || request_id_in_use(&self.snapshot, intent.prepare_request_id)
            || intent.hard_expires_at_unix < intent.setup_expires_at_unix
        {
            return Err(JournalError::InvalidRecord);
        }
        let ownership_id = intent.ownership_id;
        let mut next = self.snapshot.clone();
        let generation = next.mint_generation()?;
        let record = OwnershipRecord {
            journal_epoch_id: next.journal_epoch_id,
            origin_runtime_id: intent.origin_runtime_id,
            ownership_id,
            context_id: intent.context_id,
            prepare_request_id: intent.prepare_request_id,
            prepare_operation_digest: intent.prepare_operation_digest,
            generation,
            setup_expires_at_unix: intent.setup_expires_at_unix,
            hard_expires_at_unix: intent.hard_expires_at_unix,
            plan: intent.plan,
            phase: OwnershipPhase::Intent,
            absent_origin: None,
            reconcile: None,
            recovery_anchor: None,
        };
        record.validate()?;
        next.records.insert(ownership_id, record);
        let revision = self.compare_and_swap(expected_revision, next)?;
        Ok(InsertedOwnership {
            ownership_id,
            generation,
            revision,
        })
    }

    fn bind_reconcile(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        binding: ReconcileBinding,
    ) -> Result<u64, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        let record = self
            .snapshot
            .records
            .get(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation {
            return Err(JournalError::InvalidRecord);
        }
        if let Some(existing) = record.reconcile {
            if existing != binding {
                return Err(JournalError::InvalidTransition);
            }
            self.ensure_durable_matches()?;
            return Ok(expected_revision);
        }
        if request_id_in_use(&self.snapshot, binding.request_id) {
            return Err(JournalError::InvalidRecord);
        }
        let mut next = self.snapshot.clone();
        next.records
            .get_mut(&ownership_id)
            .expect("checked ownership")
            .reconcile = Some(binding);
        self.compare_and_swap(expected_revision, next)
    }

    fn mark_may_own_prepare(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        anchor: PrepareRecoveryAnchorV1,
    ) -> Result<MarkedMayOwnPrepare, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        let record = self
            .snapshot
            .records
            .get(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation {
            return Err(JournalError::InvalidRecord);
        }
        if record.phase == OwnershipPhase::MayOwnPrepare {
            // At the exact current revision, acknowledge only the durable transition already made.
            if record.recovery_anchor != Some(anchor)
                || record.absent_origin.is_some()
                || record.reconcile.is_some()
            {
                return Err(JournalError::InvalidTransition);
            }
            let resources = record.durable_wireguard_resources()?;
            self.ensure_durable_matches()?;
            return Ok(MarkedMayOwnPrepare {
                revision: self.snapshot.revision,
                resources,
            });
        }
        let mut next = self.snapshot.clone();
        let record = next
            .records
            .get_mut(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation {
            return Err(JournalError::InvalidRecord);
        }
        if record.reconcile.is_some() {
            return Err(JournalError::InvalidTransition);
        }
        record.advance(OwnershipPhase::MayOwnPrepare, Some(anchor), None)?;
        let resources = record.durable_wireguard_resources()?;
        let revision = self.compare_and_swap(expected_revision, next)?;
        Ok(MarkedMayOwnPrepare {
            revision,
            resources,
        })
    }

    fn mark_intent_absent(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
    ) -> Result<u64, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        let record = self
            .snapshot
            .records
            .get(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation {
            return Err(JournalError::InvalidRecord);
        }
        if record.phase == OwnershipPhase::Absent {
            // Only the exact never-dispatched transition may be acknowledged without another write.
            if record.absent_origin != Some(AbsentOrigin::NeverDispatched) {
                return Err(JournalError::InvalidTransition);
            }
            self.ensure_durable_matches()?;
            return Ok(self.snapshot.revision);
        }
        let mut next = self.snapshot.clone();
        let record = next
            .records
            .get_mut(&ownership_id)
            .ok_or(JournalError::InvalidRecord)?;
        if record.generation != generation {
            return Err(JournalError::InvalidRecord);
        }
        if record.phase != OwnershipPhase::Intent || record.recovery_anchor.is_some() {
            return Err(JournalError::InvalidTransition);
        }
        record.advance(
            OwnershipPhase::Absent,
            None,
            Some(AbsentOrigin::NeverDispatched),
        )?;
        self.compare_and_swap(expected_revision, next)
    }

    fn recover_may_own_prepare<Executor: RecoveryExecutor>(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        executor: &mut Executor,
        deadline: HardDeadline,
    ) -> Result<u64, RecoveryAttemptError<Executor::Error>> {
        self.recover_may_own_prepare_observed(
            expected_revision,
            ownership_id,
            generation,
            executor,
            deadline,
            &mut NoFailPersistObserver,
        )
    }

    fn recover_may_own_prepare_observed<Executor: RecoveryExecutor>(
        &mut self,
        expected_revision: u64,
        ownership_id: OwnershipId,
        generation: NonZeroU64,
        executor: &mut Executor,
        deadline: HardDeadline,
        observer: &mut impl PersistObserver,
    ) -> Result<u64, RecoveryAttemptError<Executor::Error>> {
        self.ensure_expected_revision(expected_revision)
            .map_err(RecoveryAttemptError::Journal)?;
        let record = self
            .snapshot
            .records
            .get(&ownership_id)
            .filter(|record| record.generation == generation)
            .cloned()
            .ok_or(RecoveryAttemptError::Journal(JournalError::InvalidRecord))?;
        if record.phase == OwnershipPhase::Absent {
            // Only a recovery-produced tombstone may suppress the trusted executor on retry.
            if record.absent_origin != Some(AbsentOrigin::RecoveredMayOwn) {
                return Err(RecoveryAttemptError::Journal(
                    JournalError::InvalidTransition,
                ));
            }
            self.ensure_durable_matches()
                .map_err(RecoveryAttemptError::Journal)?;
            return Ok(self.snapshot.revision);
        }
        if record.phase != OwnershipPhase::MayOwnPrepare || record.recovery_anchor.is_none() {
            return Err(RecoveryAttemptError::Journal(
                JournalError::InvalidTransition,
            ));
        }
        self.ensure_durable_matches()
            .map_err(RecoveryAttemptError::Journal)?;
        let target = RecoveryTarget {
            exact_record: record,
        };
        deadline
            .ensure_remaining()
            .map_err(|_| RecoveryAttemptError::Deadline)?;
        let proof = executor
            .confirm_absent(&target, deadline)
            .map_err(RecoveryAttemptError::Executor)?;
        if proof.exact_record != target.exact_record {
            return Err(RecoveryAttemptError::Journal(JournalError::ProofMismatch));
        }
        let mut next = self.snapshot.clone();
        next.records
            .get_mut(&ownership_id)
            .expect("checked ownership")
            .advance(
                OwnershipPhase::Absent,
                None,
                Some(AbsentOrigin::RecoveredMayOwn),
            )
            .map_err(RecoveryAttemptError::Journal)?;
        deadline
            .ensure_remaining()
            .map_err(|_| RecoveryAttemptError::Deadline)?;
        match self.compare_and_swap_observed_with_deadline(
            expected_revision,
            next,
            observer,
            Some(deadline),
        ) {
            Ok(revision) => Ok(revision),
            Err(JournalError::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
                    && deadline.ensure_remaining().is_err() =>
            {
                Err(RecoveryAttemptError::Deadline)
            }
            Err(error) => Err(RecoveryAttemptError::Journal(error)),
        }
    }

    fn compare_and_swap(
        &mut self,
        expected_revision: u64,
        next: JournalSnapshot,
    ) -> Result<u64, JournalError> {
        self.compare_and_swap_observed(expected_revision, next, &mut NoFailPersistObserver)
    }

    fn compare_and_swap_observed(
        &mut self,
        expected_revision: u64,
        next: JournalSnapshot,
        observer: &mut impl PersistObserver,
    ) -> Result<u64, JournalError> {
        self.compare_and_swap_observed_with_deadline(expected_revision, next, observer, None)
    }

    fn compare_and_swap_observed_with_deadline(
        &mut self,
        expected_revision: u64,
        mut next: JournalSnapshot,
        observer: &mut impl PersistObserver,
        mutation_deadline: Option<HardDeadline>,
    ) -> Result<u64, JournalError> {
        self.ensure_expected_revision(expected_revision)?;
        if next.revision != expected_revision
            || next.journal_epoch_id != self.snapshot.journal_epoch_id
            || next.next_generation < self.snapshot.next_generation
        {
            return Err(JournalError::RevisionConflict);
        }
        self.ensure_durable_matches()?;
        next.revision = expected_revision
            .checked_add(1)
            .ok_or(JournalError::Capacity)?;
        next.validate()?;
        let encoded = next.encode()?;
        match persist_atomic(
            &self.config,
            &self.parent_directory,
            &self.snapshot,
            &encoded,
            observer,
            mutation_deadline,
        ) {
            Ok(()) => {
                self.snapshot = next;
                Ok(self.snapshot.revision)
            }
            Err(failure) if failure.uncertain => {
                self.poisoned = true;
                Err(JournalError::PersistUncertain)
            }
            Err(failure) if is_revision_conflict_io(&failure.error) => {
                Err(JournalError::RevisionConflict)
            }
            Err(failure) => Err(JournalError::Io(failure.error)),
        }
    }
}

fn open_verified_parent(config: &JournalConfig) -> Result<File, JournalError> {
    let path_metadata = fs::symlink_metadata(&config.parent_path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || path_metadata.uid() != config.expected_owner_uid
        || path_metadata.gid() != config.expected_owner_gid
        || path_metadata.mode() & 0o7777 != config.expected_parent_mode
    {
        return Err(JournalError::UnsafeMetadata);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&config.parent_path)
        .map_err(JournalError::Io)?;
    let descriptor_metadata = directory.metadata()?;
    if !descriptor_metadata.is_dir()
        || descriptor_metadata.dev() != path_metadata.dev()
        || descriptor_metadata.ino() != path_metadata.ino()
        || descriptor_metadata.uid() != config.expected_owner_uid
        || descriptor_metadata.gid() != config.expected_owner_gid
        || descriptor_metadata.mode() & 0o7777 != config.expected_parent_mode
    {
        return Err(JournalError::UnsafeMetadata);
    }
    Ok(directory)
}

fn open_runtime_lock(
    config: &JournalConfig,
    parent_directory: &File,
) -> Result<File, JournalError> {
    let lock_name = child_name(&config.lock_path)?;
    let lock = open_or_create_secure_file(config, parent_directory, lock_name)?;
    match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(Errno::WOULDBLOCK) => return Err(JournalError::LockHeld),
        Err(error) => return Err(JournalError::Io(rustix_io(error))),
    }
    Ok(lock)
}

fn verify_runtime_lock_entry(
    config: &JournalConfig,
    parent_directory: &File,
    runtime_lock: &File,
) -> Result<(), JournalError> {
    let lock_name = child_name(&config.lock_path)?;
    verify_open_regular_file(runtime_lock, config)?;
    verify_child_entry(parent_directory, lock_name, runtime_lock)
}

fn verify_runtime_lock_held(
    config: &JournalConfig,
    parent_directory: &File,
    runtime_lock: &File,
) -> Result<(), JournalError> {
    verify_runtime_lock_entry(config, parent_directory, runtime_lock)?;
    let lock_name = child_name(&config.lock_path)?;
    let contender_descriptor = match openat(
        parent_directory,
        lock_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::LOOP) => return Err(JournalError::UnsafeMetadata),
        Err(error) => return Err(JournalError::Io(rustix_io(error))),
    };
    let contender = File::from(contender_descriptor);
    verify_open_regular_file(&contender, config)?;
    verify_child_entry(parent_directory, lock_name, &contender)?;

    match flock(&contender, FlockOperation::NonBlockingLockShared) {
        Err(Errno::WOULDBLOCK) => {}
        Err(error) => return Err(JournalError::Io(rustix_io(error))),
        Ok(()) => {
            // A shared contender can succeed only if the retained descriptor lost or downgraded
            // its exclusive lock. Release the diagnostic lock immediately; the caller poisons the
            // journal and must never try to repair or continue this runtime.
            flock(&contender, FlockOperation::Unlock)
                .map_err(|error| JournalError::Io(rustix_io(error)))?;
            return Err(JournalError::LockHeld);
        }
    }

    // Distinguish our retained exclusive lock from a conflicting lock acquired through a
    // different open-file description. Reasserting the same exclusive lock is idempotent.
    flock(runtime_lock, FlockOperation::NonBlockingLockExclusive)
        .map_err(|error| JournalError::Io(rustix_io(error)))
}

fn verify_next_absent(config: &JournalConfig, parent_directory: &File) -> Result<(), JournalError> {
    let next_name = child_name(&config.next_path)?;
    match statat(parent_directory, next_name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(JournalError::Io(rustix_io(error))),
        Ok(_) => Err(JournalError::RevisionConflict),
    }
}

fn load_snapshot(
    config: &JournalConfig,
    parent_directory: &File,
) -> Result<Option<JournalSnapshot>, JournalError> {
    let journal_name = child_name(&config.journal_path)?;
    let descriptor = match openat(
        parent_directory,
        journal_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => return Err(JournalError::UnsafeMetadata),
        Err(error) => return Err(JournalError::Io(rustix_io(error))),
    };
    let mut journal = File::from(descriptor);
    let metadata = verify_open_regular_file(&journal, config)?;
    verify_child_entry(parent_directory, journal_name, &journal)?;
    if metadata.len() > MAX_JOURNAL_BYTES as u64 {
        return Err(JournalError::Corrupt);
    }
    let mut encoded =
        Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| JournalError::Corrupt)?);
    Read::by_ref(&mut journal)
        .take((MAX_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::Corrupt);
    }
    let snapshot = JournalSnapshot::decode(&encoded)?;
    if snapshot.revision == 0 {
        return Err(JournalError::Corrupt);
    }
    Ok(Some(snapshot))
}

fn cleanup_stale_next(config: &JournalConfig, parent_directory: &File) -> Result<(), JournalError> {
    let next_name = child_name(&config.next_path)?;
    let descriptor = match openat(
        parent_directory,
        next_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(()),
        Err(Errno::LOOP) => return Err(JournalError::UnsafeMetadata),
        Err(error) => return Err(JournalError::Io(rustix_io(error))),
    };
    let stale = File::from(descriptor);
    verify_open_regular_file(&stale, config)?;
    verify_child_entry(parent_directory, next_name, &stale)?;
    unlinkat(parent_directory, next_name, AtFlags::empty())
        .map_err(|error| JournalError::Io(rustix_io(error)))?;
    parent_directory.sync_all()?;
    Ok(())
}

fn verify_open_regular_file(
    file: &File,
    config: &JournalConfig,
) -> Result<fs::Metadata, JournalError> {
    let descriptor_metadata = file.metadata()?;
    if !descriptor_metadata.is_file()
        || descriptor_metadata.uid() != config.expected_owner_uid
        || descriptor_metadata.gid() != config.expected_owner_gid
        || descriptor_metadata.mode() & 0o7777 != JOURNAL_FILE_MODE
        || descriptor_metadata.nlink() != 1
    {
        return Err(JournalError::UnsafeMetadata);
    }
    Ok(descriptor_metadata)
}

fn open_or_create_secure_file(
    config: &JournalConfig,
    parent_directory: &File,
    name: &std::ffi::OsStr,
) -> Result<File, JournalError> {
    let flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    match openat(parent_directory, name, flags, Mode::empty()) {
        Ok(descriptor) => {
            let file = File::from(descriptor);
            verify_open_regular_file(&file, config)?;
            verify_child_entry(parent_directory, name, &file)?;
            Ok(file)
        }
        Err(Errno::NOENT) => {
            let descriptor = openat(
                parent_directory,
                name,
                flags | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(JOURNAL_FILE_MODE),
            )
            .map_err(|error| JournalError::Io(rustix_io(error)))?;
            let file = File::from(descriptor);
            fchmod(&file, Mode::from_raw_mode(JOURNAL_FILE_MODE))
                .map_err(|error| JournalError::Io(rustix_io(error)))?;
            let metadata = file.metadata()?;
            if metadata.uid() != config.expected_owner_uid
                || metadata.gid() != config.expected_owner_gid
            {
                fchown(
                    &file,
                    Some(Uid::from_raw(config.expected_owner_uid)),
                    Some(Gid::from_raw(config.expected_owner_gid)),
                )
                .map_err(|error| JournalError::Io(rustix_io(error)))?;
            }
            verify_open_regular_file(&file, config)?;
            verify_child_entry(parent_directory, name, &file)?;
            Ok(file)
        }
        Err(Errno::LOOP) => Err(JournalError::UnsafeMetadata),
        Err(error) => Err(JournalError::Io(rustix_io(error))),
    }
}

fn child_name(path: &Path) -> Result<&std::ffi::OsStr, JournalError> {
    path.file_name().ok_or(JournalError::UnsafeMetadata)
}

fn verify_child_entry(
    parent_directory: &File,
    name: &std::ffi::OsStr,
    file: &File,
) -> Result<(), JournalError> {
    let entry = statat(parent_directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| JournalError::Io(rustix_io(error)))?;
    let descriptor = file.metadata()?;
    if entry.st_dev != descriptor.dev()
        || entry.st_ino != descriptor.ino()
        || entry.st_uid != descriptor.uid()
        || entry.st_gid != descriptor.gid()
        || entry.st_nlink != descriptor.nlink()
        || entry.st_mode != descriptor.mode()
    {
        return Err(JournalError::UnsafeMetadata);
    }
    Ok(())
}

fn random_journal_epoch_id() -> Result<JournalEpochId, JournalError> {
    for _ in 0..16 {
        let mut bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| JournalError::Random)?;
        if let Ok(epoch) = JournalEpochId::new(bytes) {
            return Ok(epoch);
        }
    }
    Err(JournalError::Random)
}

fn random_ownership_id() -> Result<OwnershipId, JournalError> {
    for _ in 0..16 {
        let mut bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| JournalError::Random)?;
        if let Ok(ownership_id) = OwnershipId::new(bytes) {
            return Ok(ownership_id);
        }
    }
    Err(JournalError::Random)
}

fn request_id_in_use(snapshot: &JournalSnapshot, request_id: Id16) -> bool {
    snapshot.records.values().any(|record| {
        record.prepare_request_id == request_id
            || record
                .reconcile
                .is_some_and(|binding| binding.request_id == request_id)
    })
}

fn rustix_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistStep {
    BeforeCreate,
    AfterCreate,
    AfterWrite,
    AfterFileSync,
    BeforeRename,
    BeforeCleanupUnlink,
    BeforeCleanupDirectorySync,
    AfterRename,
    AfterDirectorySync,
}

trait PersistObserver {
    fn observe(&mut self, step: PersistStep) -> io::Result<()>;
}

struct NoFailPersistObserver;

impl PersistObserver for NoFailPersistObserver {
    fn observe(&mut self, _step: PersistStep) -> io::Result<()> {
        Ok(())
    }
}

struct PersistFailure {
    error: io::Error,
    uncertain: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "atomic ordering, failpoints, identity checks and uncertainty form one audit unit"
)]
fn persist_atomic(
    config: &JournalConfig,
    parent_directory: &File,
    expected_snapshot: &JournalSnapshot,
    encoded: &[u8],
    observer: &mut impl PersistObserver,
    mutation_deadline: Option<HardDeadline>,
) -> Result<(), PersistFailure> {
    observer
        .observe(PersistStep::BeforeCreate)
        .map_err(|error| PersistFailure {
            error,
            uncertain: false,
        })?;
    verify_parent_descriptor(config, parent_directory).map_err(|error| PersistFailure {
        error: journal_error_as_io(error),
        uncertain: false,
    })?;
    let next_name = child_name(&config.next_path).map_err(|error| PersistFailure {
        error: journal_error_as_io(error),
        uncertain: false,
    })?;
    if let Some(deadline) = mutation_deadline {
        deadline
            .ensure_remaining()
            .map_err(|error| PersistFailure {
                error,
                uncertain: false,
            })?;
    }
    let mut temporary = match create_next_file(config, parent_directory) {
        Ok(file) => file,
        Err(error) => {
            let uncertain = statat(parent_directory, next_name, AtFlags::SYMLINK_NOFOLLOW)
                .map_or_else(|status| status != Errno::NOENT, |_| true);
            return Err(PersistFailure { error, uncertain });
        }
    };

    let before_rename = (|| -> io::Result<()> {
        observer.observe(PersistStep::AfterCreate)?;
        temporary.write_all(encoded)?;
        observer.observe(PersistStep::AfterWrite)?;
        temporary.sync_all()?;
        observer.observe(PersistStep::AfterFileSync)?;
        verify_open_regular_file(&temporary, config).map_err(journal_error_as_io)?;
        verify_parent_descriptor(config, parent_directory).map_err(journal_error_as_io)?;
        verify_destination_if_present(config, parent_directory).map_err(journal_error_as_io)?;
        Ok(())
    })();
    if let Err(error) = before_rename {
        return Err(
            match cleanup_failed_next(parent_directory, next_name, observer) {
                Ok(()) => PersistFailure {
                    error,
                    uncertain: false,
                },
                Err(cleanup_error) => PersistFailure {
                    error: cleanup_error,
                    uncertain: true,
                },
            },
        );
    }

    let durable = load_snapshot(config, parent_directory);
    let exact = durable.as_ref().is_ok_and(|durable| {
        if expected_snapshot.revision == 0 {
            durable.is_none()
        } else {
            durable.as_ref() == Some(expected_snapshot)
        }
    });
    if !exact {
        let durable_error = durable
            .err()
            .map_or_else(revision_conflict_io, journal_error_as_io);
        return Err(
            match cleanup_failed_next(parent_directory, next_name, observer) {
                Ok(()) => PersistFailure {
                    error: durable_error,
                    uncertain: false,
                },
                Err(cleanup_error) => PersistFailure {
                    error: cleanup_error,
                    uncertain: true,
                },
            },
        );
    }

    let journal_name = child_name(&config.journal_path).map_err(|error| PersistFailure {
        error: journal_error_as_io(error),
        uncertain: false,
    })?;
    if let Err(error) = observer.observe(PersistStep::BeforeRename) {
        return Err(
            match cleanup_failed_next(parent_directory, next_name, observer) {
                Ok(()) => PersistFailure {
                    error,
                    uncertain: false,
                },
                Err(cleanup_error) => PersistFailure {
                    error: cleanup_error,
                    uncertain: true,
                },
            },
        );
    }
    if let Err(error) = renameat(parent_directory, next_name, parent_directory, journal_name) {
        let cleanup = cleanup_failed_next(parent_directory, next_name, observer);
        return Err(PersistFailure {
            error: cleanup.err().unwrap_or_else(|| rustix_io(error)),
            uncertain: true,
        });
    }
    observer
        .observe(PersistStep::AfterRename)
        .map_err(|error| PersistFailure {
            error,
            uncertain: true,
        })?;
    let destination = openat(
        parent_directory,
        journal_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| PersistFailure {
        error: rustix_io(error),
        uncertain: true,
    })?;
    verify_open_regular_file(&destination, config).map_err(|error| PersistFailure {
        error: journal_error_as_io(error),
        uncertain: true,
    })?;
    verify_child_entry(parent_directory, journal_name, &destination).map_err(|error| {
        PersistFailure {
            error: journal_error_as_io(error),
            uncertain: true,
        }
    })?;
    let temporary_metadata = temporary.metadata().map_err(|error| PersistFailure {
        error,
        uncertain: true,
    })?;
    let destination_metadata = destination.metadata().map_err(|error| PersistFailure {
        error,
        uncertain: true,
    })?;
    if temporary_metadata.dev() != destination_metadata.dev()
        || temporary_metadata.ino() != destination_metadata.ino()
    {
        return Err(PersistFailure {
            error: io::Error::other("journal destination identity changed after rename"),
            uncertain: true,
        });
    }
    parent_directory
        .sync_all()
        .map_err(|error| PersistFailure {
            error,
            uncertain: true,
        })?;
    observer
        .observe(PersistStep::AfterDirectorySync)
        .map_err(|error| PersistFailure {
            error,
            uncertain: true,
        })?;
    Ok(())
}

fn cleanup_failed_next(
    parent_directory: &File,
    next_name: &std::ffi::OsStr,
    observer: &mut impl PersistObserver,
) -> io::Result<()> {
    observer.observe(PersistStep::BeforeCleanupUnlink)?;
    unlinkat(parent_directory, next_name, AtFlags::empty()).map_err(rustix_io)?;
    observer.observe(PersistStep::BeforeCleanupDirectorySync)?;
    parent_directory.sync_all()
}

fn create_next_file(config: &JournalConfig, parent_directory: &File) -> io::Result<File> {
    let next_name = child_name(&config.next_path).map_err(journal_error_as_io)?;
    let descriptor = openat(
        parent_directory,
        next_name,
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::from_raw_mode(JOURNAL_FILE_MODE),
    )
    .map_err(rustix_io)?;
    let file = File::from(descriptor);
    let setup = (|| -> Result<(), JournalError> {
        fchmod(&file, Mode::from_raw_mode(JOURNAL_FILE_MODE))
            .map_err(|error| JournalError::Io(rustix_io(error)))?;
        let metadata = file.metadata()?;
        if metadata.uid() != config.expected_owner_uid
            || metadata.gid() != config.expected_owner_gid
        {
            fchown(
                &file,
                Some(Uid::from_raw(config.expected_owner_uid)),
                Some(Gid::from_raw(config.expected_owner_gid)),
            )
            .map_err(|error| JournalError::Io(rustix_io(error)))?;
        }
        verify_open_regular_file(&file, config)?;
        verify_child_entry(parent_directory, next_name, &file)
    })();
    if let Err(error) = setup {
        let cleanup = unlinkat(parent_directory, next_name, AtFlags::empty())
            .map_err(rustix_io)
            .and_then(|()| parent_directory.sync_all());
        return Err(cleanup.err().unwrap_or_else(|| journal_error_as_io(error)));
    }
    Ok(file)
}

fn verify_destination_if_present(
    config: &JournalConfig,
    parent_directory: &File,
) -> Result<(), JournalError> {
    let journal_name = child_name(&config.journal_path)?;
    match openat(
        parent_directory,
        journal_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => {
            let destination = File::from(descriptor);
            verify_open_regular_file(&destination, config)?;
            verify_child_entry(parent_directory, journal_name, &destination)
        }
        Err(Errno::NOENT) => Ok(()),
        Err(Errno::LOOP) => Err(JournalError::UnsafeMetadata),
        Err(error) => Err(JournalError::Io(rustix_io(error))),
    }
}

fn verify_parent_descriptor(
    config: &JournalConfig,
    parent_directory: &File,
) -> Result<(), JournalError> {
    let path_metadata = fs::symlink_metadata(&config.parent_path)?;
    let descriptor_metadata = parent_directory.metadata()?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || !descriptor_metadata.is_dir()
        || path_metadata.dev() != descriptor_metadata.dev()
        || path_metadata.ino() != descriptor_metadata.ino()
        || path_metadata.uid() != config.expected_owner_uid
        || descriptor_metadata.uid() != config.expected_owner_uid
        || path_metadata.gid() != config.expected_owner_gid
        || descriptor_metadata.gid() != config.expected_owner_gid
        || path_metadata.mode() & 0o7777 != config.expected_parent_mode
        || descriptor_metadata.mode() & 0o7777 != config.expected_parent_mode
    {
        return Err(JournalError::UnsafeMetadata);
    }
    Ok(())
}

fn journal_error_as_io(error: JournalError) -> io::Error {
    match error {
        JournalError::Io(error) => error,
        other => io::Error::other(other.to_string()),
    }
}

#[derive(Debug)]
struct RevisionConflictMarker;

impl fmt::Display for RevisionConflictMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("journal revision conflict")
    }
}

impl std::error::Error for RevisionConflictMarker {}

fn revision_conflict_io() -> io::Error {
    io::Error::other(RevisionConflictMarker)
}

fn is_revision_conflict_io(error: &io::Error) -> bool {
    matches!(
        error.get_ref(),
        Some(source) if source.is::<RevisionConflictMarker>()
    )
}

/// Reject startup whenever any filesystem object occupies the retired journal path.
pub(crate) fn ensure_legacy_journal_absent() -> io::Result<()> {
    ensure_absent(Path::new(LEGACY_JOURNAL_PATH))
}

/// Reject startup while any boot-scoped v3 ownership-store object awaits a real reaper.
///
/// This read-only interlock neither opens the dormant store nor parses, locks, creates, repairs or
/// removes any object. A future production reaper must replace it atomically with recovery.
pub(crate) fn ensure_unreaped_v3_journal_absent() -> io::Result<()> {
    ensure_v3_journal_objects_absent(
        Path::new(OWNERSHIP_JOURNAL_PATH),
        Path::new(OWNERSHIP_LOCK_PATH),
        Path::new(OWNERSHIP_NEXT_PATH),
    )
}

fn ensure_v3_journal_objects_absent(
    journal_path: &Path,
    lock_path: &Path,
    next_path: &Path,
) -> io::Result<()> {
    for path in [journal_path, lock_path, next_path] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "unreaped helper v3 ownership journal requires recovery",
                ));
            }
        }
    }
    Ok(())
}

fn ensure_absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "retired helper ownership journal requires manual inspection",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        num::{NonZeroU32, NonZeroU64},
        os::unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink},
            net::UnixListener,
        },
        path::Path,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use tempfile::tempdir;

    use super::*;

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("non-zero fixture")
    }

    fn id16(byte: u8) -> Id16 {
        Id16::new([byte; 16]).expect("non-zero ID fixture")
    }

    fn runtime(byte: u8) -> RuntimeId {
        RuntimeId::new([byte; 32]).expect("non-zero runtime fixture")
    }

    fn epoch(byte: u8) -> JournalEpochId {
        JournalEpochId::new([byte; 32]).expect("non-zero epoch fixture")
    }

    fn ownership(byte: u8) -> OwnershipId {
        OwnershipId::new([byte; 32]).expect("non-zero ownership fixture")
    }

    fn recovery_deadline() -> HardDeadline {
        HardDeadline::after(Duration::from_secs(1)).expect("live recovery deadline")
    }

    fn recover_fixture<Executor: RecoveryExecutor>(
        journal: &mut OwnershipJournal,
        expected_revision: u64,
        inserted: InsertedOwnership,
        executor: &mut Executor,
    ) -> Result<u64, RecoveryAttemptError<Executor::Error>> {
        journal.recover_may_own_prepare(
            expected_revision,
            inserted.ownership_id,
            inserted.generation,
            executor,
            recovery_deadline(),
        )
    }

    fn client_plan(path_ids: &[u8]) -> ClosedPlan {
        ClosedPlan::new(
            ContextRole::Client,
            path_ids
                .iter()
                .map(|path_id| PathPlan {
                    path_id: *path_id,
                    role: WireguardRole::Client,
                })
                .collect(),
        )
        .expect("client plan fixture")
    }

    fn anchor(seed: u64) -> PrepareRecoveryAnchorV1 {
        PrepareRecoveryAnchorV1 {
            boot_id: id16(u8::try_from(seed).expect("small fixture seed")),
            pid: NonZeroU32::new(u32::try_from(seed).expect("small fixture seed"))
                .expect("non-zero pid"),
            process_start_ticks: nz(seed + 10),
            network_namespace_device: nz(seed + 20),
            network_namespace_inode: nz(seed + 30),
            executable_device: nz(seed + 40),
            executable_inode: nz(seed + 50),
            service_cgroup_inode: nz(seed + 60),
        }
    }

    fn record(
        journal_epoch_id: JournalEpochId,
        ownership_seed: u8,
        context_seed: u8,
        prepare_seed: u8,
        generation: u64,
        phase: OwnershipPhase,
    ) -> OwnershipRecord {
        OwnershipRecord {
            journal_epoch_id,
            origin_runtime_id: runtime(9),
            ownership_id: ownership(ownership_seed),
            context_id: id16(context_seed),
            prepare_request_id: id16(prepare_seed),
            prepare_operation_digest: [0; DIGEST_BYTES],
            generation: nz(generation),
            setup_expires_at_unix: nz(100),
            hard_expires_at_unix: nz(200),
            plan: client_plan(&[1, 2]),
            phase,
            absent_origin: (phase == OwnershipPhase::Absent)
                .then_some(AbsentOrigin::NeverDispatched),
            reconcile: None,
            recovery_anchor: (phase == OwnershipPhase::MayOwnPrepare).then(|| anchor(7)),
        }
    }

    fn snapshot_with(records: Vec<OwnershipRecord>) -> JournalSnapshot {
        let journal_epoch_id = records
            .first()
            .map_or_else(|| epoch(1), |record| record.journal_epoch_id);
        let next_generation = records
            .iter()
            .map(|record| record.generation.get())
            .max()
            .unwrap_or(0)
            + 1;
        JournalSnapshot {
            journal_epoch_id,
            revision: 1,
            next_generation,
            records: records
                .into_iter()
                .map(|record| (record.ownership_id, record))
                .collect(),
        }
    }

    fn test_config(parent: &Path) -> JournalConfig {
        let metadata = fs::metadata(parent).expect("temporary parent metadata");
        JournalConfig::for_test(
            parent,
            metadata.mode() & 0o7777,
            metadata.uid(),
            metadata.gid(),
        )
    }

    fn open_fifo_with_deadline(
        config: JournalConfig,
        fifo_path: PathBuf,
    ) -> Result<OwnershipJournal, JournalError> {
        let (sender, receiver) = mpsc::channel();
        let opener = thread::spawn(move || {
            let _ = sender.send(OwnershipJournal::open(config));
        });
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => {
                opener.join().expect("FIFO opener thread");
                result
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let writer = OpenOptions::new()
                    .write(true)
                    .open(fifo_path)
                    .expect("unblock regressed FIFO reader");
                drop(writer);
                let _ = receiver.recv_timeout(Duration::from_secs(1));
                opener.join().expect("unblocked FIFO opener thread");
                panic!("journal FIFO open exceeded its bounded deadline");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                opener.join().expect("FIFO opener thread");
                panic!("journal FIFO opener disconnected")
            }
        }
    }

    fn intent(context_seed: u8, request_seed: u8) -> NewOwnershipIntent {
        NewOwnershipIntent {
            origin_runtime_id: runtime(8),
            ownership_id: ownership(context_seed.wrapping_add(32)),
            context_id: id16(context_seed),
            prepare_request_id: id16(request_seed),
            prepare_operation_digest: [0; DIGEST_BYTES],
            setup_expires_at_unix: nz(100),
            hard_expires_at_unix: nz(200),
            plan: client_plan(&[1, 2]),
        }
    }

    fn binding(seed: u8) -> ReconcileBinding {
        ReconcileBinding {
            request_id: id16(seed),
            operation_digest: [seed; DIGEST_BYTES],
        }
    }

    fn marker_aliases(record: &OwnershipRecord) -> Vec<String> {
        record
            .durable_wireguard_resources()
            .expect("valid durable resource projection")
            .into_iter()
            .map(|resource| resource.ownership_alias().to_owned())
            .collect()
    }

    fn marker_digest(alias: &str) -> &str {
        alias
            .rsplit_once(':')
            .map(|(_, digest)| digest)
            .expect("fixed marker separator")
    }

    #[test]
    fn durable_wireguard_marker_has_fixed_golden_grammar_and_redacts_coordinates() {
        let exact = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Intent);
        let resources = exact
            .durable_wireguard_resources()
            .expect("valid resource projection");
        assert_eq!(resources.len(), 2);
        let first = &resources[0];
        assert_eq!(first.key(), (1, WireguardRole::Client as i32));
        assert_eq!(first.interface().len(), DERIVED_WIREGUARD_INTERFACE_BYTES);
        assert_eq!(first.local_address().octets()[14..], [0, 1]);
        assert_eq!(
            first.ownership_alias(),
            "volparossa:wireguard:ownership-v1:vpc123799507:\
             badfee16fe6577b6ea576dca60b0db2ed40adce2bf94d4571ae6fe95265f502b"
        );
        let expected_prefix = format!("{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:", first.interface());
        assert!(first.ownership_alias().starts_with(&expected_prefix));
        assert_eq!(
            first.ownership_alias().len(),
            DURABLE_WIREGUARD_ALIAS_PREFIX.len()
                + DERIVED_WIREGUARD_INTERFACE_BYTES
                + 1
                + DIGEST_BYTES * 2
        );
        let digest = marker_digest(first.ownership_alias());
        assert_eq!(digest.len(), DIGEST_BYTES * 2);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        );
        assert!(!first.ownership_alias().contains(&"01".repeat(32)));
        assert!(!first.ownership_alias().contains(&"02".repeat(32)));
        assert_eq!(format!("{first:?}"), "DurableWireguardResource(<redacted>)");

        let target = RecoveryTarget {
            exact_record: exact.clone(),
        };
        assert_eq!(
            target
                .durable_wireguard_resources()
                .expect("recovery resource projection")[0]
                .ownership_alias(),
            first.ownership_alias()
        );
        let snapshot = snapshot_with(vec![exact]);
        let decoded = JournalSnapshot::decode(&snapshot.encode().expect("encoded marker record"))
            .expect("decoded marker record");
        assert_eq!(
            marker_aliases(decoded.records.values().next().expect("decoded record")),
            resources
                .iter()
                .map(|resource| resource.ownership_alias().to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn durable_wireguard_marker_commits_every_immutable_record_class_and_exact_resource() {
        let base = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Intent);
        let base_digest = marker_digest(&marker_aliases(&base)[0]).to_owned();
        let assert_changes = |candidate: OwnershipRecord, field: &str| {
            candidate.validate().expect("valid immutable mutation");
            assert_ne!(
                marker_digest(&marker_aliases(&candidate)[0]),
                base_digest,
                "immutable field did not change marker: {field}"
            );
        };

        let mut candidate = base.clone();
        candidate.journal_epoch_id = epoch(5);
        assert_changes(candidate, "journal epoch");
        let mut candidate = base.clone();
        candidate.origin_runtime_id = runtime(5);
        assert_changes(candidate, "origin runtime");
        let mut candidate = base.clone();
        candidate.ownership_id = ownership(5);
        assert_changes(candidate, "ownership ID");
        let mut candidate = base.clone();
        candidate.context_id = id16(5);
        assert_changes(candidate, "context ID");
        let mut candidate = base.clone();
        candidate.prepare_request_id = id16(5);
        assert_changes(candidate, "prepare request ID");
        let mut candidate = base.clone();
        candidate.prepare_operation_digest = [5; DIGEST_BYTES];
        assert_changes(candidate, "prepare operation digest");
        let mut candidate = base.clone();
        candidate.generation = nz(5);
        assert_changes(candidate, "generation");
        let mut candidate = base.clone();
        candidate.setup_expires_at_unix = nz(101);
        assert_changes(candidate, "setup expiry");
        let mut candidate = base.clone();
        candidate.hard_expires_at_unix = nz(201);
        assert_changes(candidate, "hard expiry");
        let mut candidate = base.clone();
        candidate.plan = client_plan(&[1]);
        assert_changes(candidate, "canonical path list");
        let mut candidate = base.clone();
        candidate.plan = ClosedPlan::new(
            ContextRole::Exit,
            vec![
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::Exit,
                },
                PathPlan {
                    path_id: 2,
                    role: WireguardRole::Exit,
                },
            ],
        )
        .expect("exit plan");
        assert_changes(candidate, "canonical context role");

        let client_resources = base
            .durable_wireguard_resources()
            .expect("client resources");
        assert_ne!(
            marker_digest(client_resources[0].ownership_alias()),
            marker_digest(client_resources[1].ownership_alias()),
            "different path/name/address must have a distinct marker"
        );
        let mut relay = base;
        relay.plan = ClosedPlan::new(
            ContextRole::Relay,
            vec![
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayClient,
                },
                PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayExit,
                },
            ],
        )
        .expect("relay plan");
        let relay_resources = relay
            .durable_wireguard_resources()
            .expect("relay resources");
        assert_ne!(
            relay_resources[0].interface(),
            relay_resources[1].interface()
        );
        assert_ne!(
            relay_resources[0].local_address(),
            relay_resources[1].local_address()
        );
        assert_ne!(
            marker_digest(relay_resources[0].ownership_alias()),
            marker_digest(relay_resources[1].ownership_alias()),
            "different role/name/address must have a distinct marker"
        );
    }

    #[test]
    fn durable_wireguard_marker_excludes_every_mutable_record_field() {
        let intent = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Intent);
        let expected = marker_aliases(&intent);

        let mut reconciled = intent.clone();
        reconciled.reconcile = Some(binding(8));
        assert_eq!(marker_aliases(&reconciled), expected);

        let may_own = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::MayOwnPrepare);
        assert_eq!(marker_aliases(&may_own), expected);
        let mut different_anchor = may_own;
        different_anchor.recovery_anchor = Some(anchor(8));
        assert_eq!(marker_aliases(&different_anchor), expected);

        let absent = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Absent);
        assert_eq!(marker_aliases(&absent), expected);
        let mut different_absent_origin = absent;
        different_absent_origin.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        assert_eq!(marker_aliases(&different_absent_origin), expected);
    }

    #[test]
    fn canonical_codec_round_trips_byte_exact_and_detects_every_truncation_and_corruption() {
        let mut first = record(epoch(1), 2, 3, 4, 1, OwnershipPhase::MayOwnPrepare);
        first.reconcile = Some(binding(5));
        let snapshot = snapshot_with(vec![first]);
        let encoded = snapshot.encode().expect("canonical encoding");
        assert!(encoded.len() <= MAX_JOURNAL_BYTES);
        let decoded = JournalSnapshot::decode(&encoded).expect("canonical decoding");
        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.encode().expect("canonical re-encoding"), encoded);

        for length in 0..encoded.len() {
            assert!(JournalSnapshot::decode(&encoded[..length]).is_err());
        }
        let mut flipped = encoded.clone();
        let flipped_index = flipped.len() / 2;
        flipped[flipped_index] ^= 0x80;
        assert!(matches!(
            JournalSnapshot::decode(&flipped),
            Err(JournalError::Corrupt)
        ));

        let mut trailing_payload = encoded[..encoded.len() - DIGEST_BYTES].to_vec();
        trailing_payload.push(0);
        let checksum = blake3::hash(&trailing_payload);
        trailing_payload.extend_from_slice(checksum.as_bytes());
        assert!(matches!(
            JournalSnapshot::decode(&trailing_payload),
            Err(JournalError::Corrupt)
        ));
        assert!(!format!("{snapshot:?}").contains("03030303"));
    }

    #[test]
    fn absent_origin_is_persisted_and_phase_exact() {
        let journal_epoch = epoch(1);
        let never_dispatched = record(journal_epoch, 2, 3, 4, 1, OwnershipPhase::Absent);
        let mut recovered = record(journal_epoch, 5, 6, 7, 2, OwnershipPhase::Absent);
        recovered.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        let snapshot = snapshot_with(vec![never_dispatched.clone(), recovered.clone()]);
        let decoded =
            JournalSnapshot::decode(&snapshot.encode().expect("encoded typed tombstones"))
                .expect("decoded typed tombstones");
        assert_eq!(decoded, snapshot);
        assert_eq!(
            decoded
                .records
                .get(&never_dispatched.ownership_id)
                .expect("never-dispatched tombstone")
                .absent_origin,
            Some(AbsentOrigin::NeverDispatched)
        );
        assert_eq!(
            decoded
                .records
                .get(&recovered.ownership_id)
                .expect("recovered tombstone")
                .absent_origin,
            Some(AbsentOrigin::RecoveredMayOwn)
        );

        let mut intent_with_origin = record(journal_epoch, 8, 9, 10, 3, OwnershipPhase::Intent);
        intent_with_origin.absent_origin = Some(AbsentOrigin::NeverDispatched);
        assert!(matches!(
            intent_with_origin.validate(),
            Err(JournalError::InvalidRecord)
        ));
        let mut may_own_with_origin =
            record(journal_epoch, 11, 12, 13, 4, OwnershipPhase::MayOwnPrepare);
        may_own_with_origin.absent_origin = Some(AbsentOrigin::RecoveredMayOwn);
        assert!(matches!(
            may_own_with_origin.validate(),
            Err(JournalError::InvalidRecord)
        ));
        let mut absent_without_origin = never_dispatched;
        absent_without_origin.absent_origin = None;
        assert!(matches!(
            absent_without_origin.validate(),
            Err(JournalError::InvalidRecord)
        ));

        let mut never_dispatched_with_recovery_origin =
            record(journal_epoch, 14, 15, 16, 5, OwnershipPhase::Intent);
        assert!(matches!(
            never_dispatched_with_recovery_origin.advance(
                OwnershipPhase::Absent,
                None,
                Some(AbsentOrigin::RecoveredMayOwn),
            ),
            Err(JournalError::InvalidTransition)
        ));
        let mut recovered_with_never_dispatched_origin =
            record(journal_epoch, 17, 18, 19, 6, OwnershipPhase::MayOwnPrepare);
        assert!(matches!(
            recovered_with_never_dispatched_origin.advance(
                OwnershipPhase::Absent,
                None,
                Some(AbsentOrigin::NeverDispatched),
            ),
            Err(JournalError::InvalidTransition)
        ));
    }

    #[test]
    fn codec_rejects_raw_absent_origin_ambiguity_with_a_valid_checksum() {
        const HEADER_BYTES: usize = 8 + 2 + 32 + 8 + 8 + 4;
        const RECORD_PREFIX_TO_PATHS: usize = 32 + 32 + 32 + 16 + 16 + 32 + 8 + 8 + 8 + 1 + 1;
        const CLIENT_PATH_BYTES: usize = 4;
        const PHASE_OFFSET: usize = HEADER_BYTES + RECORD_PREFIX_TO_PATHS + CLIENT_PATH_BYTES;
        const ABSENT_ORIGIN_PRESENCE_OFFSET: usize = PHASE_OFFSET + 1;
        const ABSENT_ORIGIN_VALUE_OFFSET: usize = ABSENT_ORIGIN_PRESENCE_OFFSET + 1;

        fn replace_checksum(encoded: &mut [u8]) {
            let payload_len = encoded
                .len()
                .checked_sub(DIGEST_BYTES)
                .expect("encoded journal checksum");
            let checksum = *blake3::hash(&encoded[..payload_len]).as_bytes();
            encoded[payload_len..].copy_from_slice(&checksum);
        }

        let intent_snapshot =
            snapshot_with(vec![record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Intent)]);
        let mut invalid_presence = intent_snapshot.encode().expect("encoded Intent record");
        assert_eq!(invalid_presence[PHASE_OFFSET], OwnershipPhase::Intent as u8);
        assert_eq!(invalid_presence[ABSENT_ORIGIN_PRESENCE_OFFSET], 0);
        invalid_presence[ABSENT_ORIGIN_PRESENCE_OFFSET] = 2;
        replace_checksum(&mut invalid_presence);
        assert!(matches!(
            JournalSnapshot::decode(&invalid_presence),
            Err(JournalError::Corrupt)
        ));

        let absent_snapshot =
            snapshot_with(vec![record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Absent)]);
        let valid_absent = absent_snapshot.encode().expect("encoded Absent record");
        assert_eq!(valid_absent[PHASE_OFFSET], OwnershipPhase::Absent as u8);
        assert_eq!(valid_absent[ABSENT_ORIGIN_PRESENCE_OFFSET], 1);
        assert_eq!(
            valid_absent[ABSENT_ORIGIN_VALUE_OFFSET],
            AbsentOrigin::NeverDispatched as u8
        );

        let mut invalid_value = valid_absent.clone();
        invalid_value[ABSENT_ORIGIN_VALUE_OFFSET] = 99;
        replace_checksum(&mut invalid_value);
        assert!(matches!(
            JournalSnapshot::decode(&invalid_value),
            Err(JournalError::Corrupt)
        ));

        let mut mismatched_phase = valid_absent;
        mismatched_phase[PHASE_OFFSET] = OwnershipPhase::Intent as u8;
        replace_checksum(&mut mismatched_phase);
        assert!(matches!(
            JournalSnapshot::decode(&mismatched_phase),
            Err(JournalError::Corrupt)
        ));
    }

    #[test]
    fn codec_rejects_noncanonical_path_order_even_with_a_recomputed_checksum() {
        const HEADER_BYTES: usize = 8 + 2 + 32 + 8 + 8 + 4;
        const RECORD_PREFIX_TO_PATHS: usize = 32 + 32 + 32 + 16 + 16 + 32 + 8 + 8 + 8 + 1 + 1;
        let snapshot = snapshot_with(vec![record(epoch(1), 2, 3, 4, 1, OwnershipPhase::Intent)]);
        let encoded = snapshot.encode().expect("canonical encoding");
        let mut payload = encoded[..encoded.len() - DIGEST_BYTES].to_vec();
        let paths = HEADER_BYTES + RECORD_PREFIX_TO_PATHS;
        assert_eq!(&payload[paths..paths + 4], &[1, 1, 2, 1]);
        payload.swap(paths, paths + 2);
        payload.swap(paths + 1, paths + 3);
        assert_eq!(&payload[paths..paths + 4], &[2, 1, 1, 1]);
        let checksum = blake3::hash(&payload);
        payload.extend_from_slice(checksum.as_bytes());
        assert!(matches!(
            JournalSnapshot::decode(&payload),
            Err(JournalError::Corrupt)
        ));

        let mut noncanonical = snapshot;
        noncanonical
            .records
            .values_mut()
            .next()
            .expect("record fixture")
            .plan
            .paths
            .swap(0, 1);
        assert!(matches!(
            noncanonical.validate(),
            Err(JournalError::InvalidRecord)
        ));
        assert!(matches!(
            noncanonical.encode(),
            Err(JournalError::InvalidRecord)
        ));
    }

    #[test]
    fn closed_plan_enforces_exact_wire_roles_and_full_per_path_cardinality() {
        let relay = ClosedPlan::new(
            ContextRole::Relay,
            (1..=8)
                .flat_map(|path_id| {
                    [WireguardRole::RelayClient, WireguardRole::RelayExit]
                        .into_iter()
                        .map(move |role| PathPlan { path_id, role })
                })
                .collect(),
        )
        .expect("eight complete relay paths");
        assert_eq!(relay.paths.len(), MAX_LEASE_IDENTITIES);

        assert!(
            ClosedPlan::new(
                ContextRole::Relay,
                vec![PathPlan {
                    path_id: 1,
                    role: WireguardRole::RelayClient,
                }],
            )
            .is_err()
        );
        assert!(
            ClosedPlan::new(
                ContextRole::Client,
                vec![PathPlan {
                    path_id: 1,
                    role: WireguardRole::Exit,
                }],
            )
            .is_err()
        );
        assert!(
            ClosedPlan::new(
                ContextRole::Client,
                (1..=9)
                    .map(|path_id| PathPlan {
                        path_id,
                        role: WireguardRole::Client,
                    })
                    .collect(),
            )
            .is_err()
        );
    }

    #[test]
    fn wire_closed_plan_converts_exactly_without_normalising_a_permutation() {
        let wire = volparossa_routing::ClosedPreparePlan {
            context_role: volparossa_routing::ContextRole::Relay as i32,
            leases: vec![
                volparossa_routing::LeasePlan {
                    path_id: 1,
                    role: volparossa_routing::WireguardRole::RelayClient as i32,
                },
                volparossa_routing::LeasePlan {
                    path_id: 1,
                    role: volparossa_routing::WireguardRole::RelayExit as i32,
                },
                volparossa_routing::LeasePlan {
                    path_id: 2,
                    role: volparossa_routing::WireguardRole::RelayClient as i32,
                },
                volparossa_routing::LeasePlan {
                    path_id: 2,
                    role: volparossa_routing::WireguardRole::RelayExit as i32,
                },
            ],
        };
        let converted = ClosedPlan::try_from_wire(&wire).expect("canonical wire plan");
        assert_eq!(converted.context_role, ContextRole::Relay);
        assert_eq!(converted.paths.len(), wire.leases.len());
        for (path, lease) in converted.paths.iter().zip(&wire.leases) {
            assert_eq!(u32::from(path.path_id), lease.path_id);
            assert_eq!(i32::from(path.role as u8), lease.role);
        }

        let mut permuted = wire;
        permuted.leases.swap(0, 1);
        assert!(matches!(
            ClosedPlan::try_from_wire(&permuted),
            Err(JournalError::InvalidRecord)
        ));

        let invalid_cases = [
            volparossa_routing::ClosedPreparePlan {
                context_role: volparossa_routing::ContextRole::Client as i32,
                leases: Vec::new(),
            },
            volparossa_routing::ClosedPreparePlan {
                context_role: volparossa_routing::ContextRole::Client as i32,
                leases: (1..=17)
                    .map(|path_id| volparossa_routing::LeasePlan {
                        path_id,
                        role: volparossa_routing::WireguardRole::Client as i32,
                    })
                    .collect(),
            },
            volparossa_routing::ClosedPreparePlan {
                context_role: volparossa_routing::ContextRole::Client as i32,
                leases: vec![volparossa_routing::LeasePlan {
                    path_id: 256,
                    role: volparossa_routing::WireguardRole::Client as i32,
                }],
            },
            volparossa_routing::ClosedPreparePlan {
                context_role: volparossa_routing::ContextRole::Client as i32,
                leases: vec![volparossa_routing::LeasePlan {
                    path_id: 1,
                    role: 99,
                }],
            },
            volparossa_routing::ClosedPreparePlan {
                context_role: volparossa_routing::ContextRole::Client as i32,
                leases: vec![volparossa_routing::LeasePlan {
                    path_id: 1,
                    role: volparossa_routing::WireguardRole::Exit as i32,
                }],
            },
        ];
        for invalid in invalid_cases {
            assert!(matches!(
                ClosedPlan::try_from_wire(&invalid),
                Err(JournalError::InvalidRecord)
            ));
        }
    }

    #[test]
    fn snapshot_rejects_cross_lineage_context_generation_and_request_id_collisions() {
        let journal_epoch = epoch(1);
        let first = record(journal_epoch, 2, 3, 4, 1, OwnershipPhase::Intent);
        let mut second = record(journal_epoch, 5, 6, 7, 2, OwnershipPhase::Intent);

        second.context_id = first.context_id;
        assert!(
            snapshot_with(vec![first.clone(), second.clone()])
                .validate()
                .is_err()
        );
        second.context_id = id16(6);
        second.generation = first.generation;
        assert!(
            snapshot_with(vec![first.clone(), second.clone()])
                .validate()
                .is_err()
        );
        second.generation = nz(2);
        second.prepare_request_id = first.prepare_request_id;
        assert!(
            snapshot_with(vec![first.clone(), second.clone()])
                .validate()
                .is_err()
        );
        second.prepare_request_id = id16(7);
        second.reconcile = Some(ReconcileBinding {
            request_id: first.prepare_request_id,
            operation_digest: [0; DIGEST_BYTES],
        });
        assert!(snapshot_with(vec![first, second]).validate().is_err());
    }

    #[test]
    fn generation_mint_is_checked_and_does_not_wrap_or_mutate_on_failure() {
        let mut snapshot = JournalSnapshot {
            journal_epoch_id: epoch(1),
            revision: 1,
            next_generation: u64::MAX,
            records: BTreeMap::new(),
        };
        let before = snapshot.clone();
        assert!(matches!(
            snapshot.mint_generation(),
            Err(JournalError::Capacity)
        ));
        assert_eq!(snapshot, before);
    }

    struct FakeRecoveryExecutor {
        exact: bool,
        calls: usize,
    }

    impl RecoveryExecutor for FakeRecoveryExecutor {
        type Error = ();

        fn confirm_absent(
            &mut self,
            target: &RecoveryTarget,
            _deadline: HardDeadline,
        ) -> Result<ConfirmedAbsentProof, Self::Error> {
            self.calls += 1;
            let mut proof = target.confirmed_absent();
            if !self.exact {
                proof.exact_record.context_id = id16(99);
            }
            Ok(proof)
        }
    }

    struct ErrorRecoveryExecutor;

    impl RecoveryExecutor for ErrorRecoveryExecutor {
        type Error = &'static str;

        fn confirm_absent(
            &mut self,
            _target: &RecoveryTarget,
            _deadline: HardDeadline,
        ) -> Result<ConfirmedAbsentProof, Self::Error> {
            Err("injected recovery failure")
        }
    }

    struct ExpiringRecoveryExecutor {
        calls: usize,
        observed_deadline: Option<HardDeadline>,
    }

    impl RecoveryExecutor for ExpiringRecoveryExecutor {
        type Error = ();

        fn confirm_absent(
            &mut self,
            target: &RecoveryTarget,
            deadline: HardDeadline,
        ) -> Result<ConfirmedAbsentProof, Self::Error> {
            self.calls += 1;
            self.observed_deadline = Some(deadline);
            while let Ok(remaining) = deadline.remaining() {
                thread::sleep(remaining.min(Duration::from_millis(2)));
            }
            Ok(target.confirmed_absent())
        }
    }

    struct FailingObserver {
        steps: Vec<PersistStep>,
    }

    impl PersistObserver for FailingObserver {
        fn observe(&mut self, step: PersistStep) -> io::Result<()> {
            if self.steps.contains(&step) {
                Err(io::Error::other("injected persistence failure"))
            } else {
                Ok(())
            }
        }
    }

    struct ExpireBeforeCreateObserver {
        deadline: HardDeadline,
        steps: Vec<PersistStep>,
    }

    impl PersistObserver for ExpireBeforeCreateObserver {
        fn observe(&mut self, step: PersistStep) -> io::Result<()> {
            self.steps.push(step);
            if step == PersistStep::BeforeCreate {
                while let Ok(remaining) = self.deadline.remaining() {
                    thread::sleep(remaining.min(Duration::from_millis(2)));
                }
            }
            Ok(())
        }
    }

    fn next_with_binding(
        journal: &OwnershipJournal,
        inserted: InsertedOwnership,
        reconcile: ReconcileBinding,
    ) -> JournalSnapshot {
        let mut next = journal.snapshot().expect("usable journal").clone();
        next.records
            .get_mut(&inserted.ownership_id)
            .expect("inserted record")
            .reconcile = Some(reconcile);
        next
    }

    fn assert_retry_healthcheck_poisoned(journal: &mut OwnershipJournal) {
        assert!(matches!(
            journal.confirm_retry_safe_after_definite_failure(),
            Err(JournalError::Poisoned)
        ));
        assert!(matches!(journal.snapshot(), Err(JournalError::Poisoned)));
        assert!(matches!(
            journal.confirm_retry_safe_after_definite_failure(),
            Err(JournalError::Poisoned)
        ));
    }

    #[test]
    fn secure_metadata_runtime_lock_and_stale_next_are_enforced() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        fs::write(&config.next_path, b"stale next").expect("stale next fixture");
        fs::set_permissions(
            &config.next_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("secure stale next mode");

        let mut first = OwnershipJournal::open(config.clone()).expect("first runtime lock");
        first
            .insert_intent(0, intent(2, 3))
            .expect("journal metadata fixture");
        assert!(!config.next_path.exists());
        let lock_metadata = fs::metadata(&config.lock_path).expect("lock metadata");
        assert_eq!(lock_metadata.mode() & 0o7777, JOURNAL_FILE_MODE);
        assert_eq!(lock_metadata.nlink(), 1);
        let journal_metadata = fs::metadata(&config.journal_path).expect("journal metadata");
        assert_eq!(journal_metadata.mode() & 0o7777, JOURNAL_FILE_MODE);
        assert_eq!(journal_metadata.uid(), config.expected_owner_uid);
        assert_eq!(journal_metadata.gid(), config.expected_owner_gid);
        assert_eq!(journal_metadata.nlink(), 1);
        assert!(matches!(
            OwnershipJournal::open(config.clone()),
            Err(JournalError::LockHeld)
        ));
        drop(first);
        drop(OwnershipJournal::open(config).expect("lock released with descriptor drop"));

        let unsafe_directory = tempdir().expect("unsafe fixture directory");
        let unsafe_config = test_config(unsafe_directory.path());
        symlink("missing", &unsafe_config.next_path).expect("next symlink fixture");
        assert!(matches!(
            OwnershipJournal::open(unsafe_config.clone()),
            Err(JournalError::UnsafeMetadata)
        ));
        assert!(
            fs::symlink_metadata(&unsafe_config.next_path)
                .expect("unsafe next remains")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn insecure_or_hardlinked_lock_is_rejected_without_repair() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        fs::write(&config.lock_path, b"lock").expect("lock fixture");
        fs::set_permissions(&config.lock_path, fs::Permissions::from_mode(0o640))
            .expect("insecure mode fixture");
        assert!(matches!(
            OwnershipJournal::open(config.clone()),
            Err(JournalError::UnsafeMetadata)
        ));
        assert_eq!(
            fs::metadata(&config.lock_path)
                .expect("lock remains")
                .mode()
                & 0o7777,
            0o640
        );

        fs::set_permissions(
            &config.lock_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("secure mode for hardlink fixture");
        fs::hard_link(&config.lock_path, directory.path().join("alias")).expect("hardlink fixture");
        assert!(matches!(
            OwnershipJournal::open(config),
            Err(JournalError::UnsafeMetadata)
        ));
    }

    #[test]
    fn intent_restart_absence_and_late_exact_reconcile_binding_are_durable() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        assert_eq!(inserted.revision, 1);
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart journal");
        let absent_revision = journal
            .mark_intent_absent(1, inserted.ownership_id, inserted.generation)
            .expect("never-dispatched intent is absent");
        assert_eq!(absent_revision, 2);
        let exact = binding(4);
        let bound_revision = journal
            .bind_reconcile(2, inserted.ownership_id, inserted.generation, exact)
            .expect("late exact binding on tombstone");
        assert_eq!(bound_revision, 3);
        assert_eq!(
            journal
                .bind_reconcile(3, inserted.ownership_id, inserted.generation, exact)
                .expect("idempotent exact binding"),
            3
        );
        let before = fs::read(&config.journal_path).expect("durable bytes before conflict");
        assert!(matches!(
            journal.bind_reconcile(3, inserted.ownership_id, inserted.generation, binding(5)),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(
            fs::read(&config.journal_path).expect("durable bytes after conflict"),
            before
        );
    }

    #[test]
    fn lost_insert_reply_restarts_to_the_same_exact_ownership_identity() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let exact_intent = intent(2, 3);
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        journal
            .insert_intent(0, exact_intent.clone())
            .expect("durable insert whose reply is discarded");
        let marker_before_restart = marker_aliases(
            journal
                .snapshot()
                .expect("inserted snapshot")
                .records
                .values()
                .next()
                .expect("inserted record"),
        );
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart journal");
        let existing = journal
            .snapshot()
            .expect("usable restarted snapshot")
            .records
            .values()
            .next()
            .expect("durable ownership")
            .clone();
        assert_eq!(marker_aliases(&existing), marker_before_restart);
        let before = fs::read(&config.journal_path).expect("durable insert bytes");
        for wrong_revision in [0, 2] {
            assert!(matches!(
                journal.insert_intent(wrong_revision, exact_intent.clone()),
                Err(JournalError::RevisionConflict)
            ));
        }
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after stale insert retry"),
            before
        );
        let retried = journal
            .insert_intent(1, exact_intent.clone())
            .expect("exact retry at the current revision");
        assert_eq!(retried.ownership_id, existing.ownership_id);
        assert_eq!(retried.generation, existing.generation);
        assert_eq!(retried.revision, 1);
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact retry"),
            before
        );

        let mut conflicts = Vec::new();
        let mut changed = exact_intent.clone();
        changed.ownership_id = ownership(99);
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.origin_runtime_id = runtime(9);
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.context_id = id16(4);
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.prepare_request_id = id16(5);
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.prepare_operation_digest = [1; DIGEST_BYTES];
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.setup_expires_at_unix = nz(101);
        conflicts.push(changed);
        let mut changed = exact_intent.clone();
        changed.hard_expires_at_unix = nz(201);
        conflicts.push(changed);
        let mut changed = exact_intent;
        changed.plan = client_plan(&[1]);
        conflicts.push(changed);

        for conflict in conflicts {
            assert!(matches!(
                journal.insert_intent(1, conflict),
                Err(JournalError::InvalidRecord)
            ));
            assert_eq!(
                fs::read(&config.journal_path).expect("bytes after conflicting retry"),
                before
            );
        }
    }

    #[test]
    fn lost_arm_reply_restarts_to_exact_same_anchor_success() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let exact_anchor = anchor(7);
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let first_projection = journal
            .mark_may_own_prepare(1, inserted.ownership_id, inserted.generation, exact_anchor)
            .expect("durable arm whose reply is discarded");
        let first_aliases = first_projection
            .resources
            .iter()
            .map(|resource| resource.ownership_alias().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(first_projection.revision, 2);
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart journal");
        let before = fs::read(&config.journal_path).expect("durable arm bytes");
        for wrong_revision in [1, 3] {
            assert!(matches!(
                journal.mark_may_own_prepare(
                    wrong_revision,
                    inserted.ownership_id,
                    inserted.generation,
                    exact_anchor,
                ),
                Err(JournalError::RevisionConflict)
            ));
        }
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after stale arm retry"),
            before
        );
        let retried = journal
            .mark_may_own_prepare(2, inserted.ownership_id, inserted.generation, exact_anchor)
            .expect("exact arm retry at the current revision");
        assert_eq!(retried.revision, 2);
        assert_eq!(
            retried
                .resources
                .iter()
                .map(|resource| resource.ownership_alias().to_owned())
                .collect::<Vec<_>>(),
            first_aliases,
            "an exact durable retry must return the identical ordered resource projection"
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact arm retry"),
            before
        );
        assert!(matches!(
            journal.mark_may_own_prepare(2, inserted.ownership_id, inserted.generation, anchor(8),),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after conflicting arm retry"),
            before
        );
    }

    #[test]
    fn interposed_transitions_are_never_misreported_as_insert_or_arm_retries() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let exact_intent = intent(2, 3);
        let exact_anchor = anchor(7);
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, exact_intent.clone())
            .expect("durable intent");
        journal
            .mark_may_own_prepare(1, inserted.ownership_id, inserted.generation, exact_anchor)
            .expect("interposed durable arm");
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart after arm");
        let before_insert_retry =
            fs::read(&config.journal_path).expect("durable armed journal bytes");
        let revision_before_insert_retry =
            journal.snapshot().expect("usable armed snapshot").revision;
        assert_eq!(revision_before_insert_retry, 2);
        assert!(matches!(
            journal.insert_intent(2, exact_intent),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(
            journal
                .snapshot()
                .expect("insert retry leaves snapshot usable")
                .revision,
            revision_before_insert_retry
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after interposed insert retry"),
            before_insert_retry
        );

        journal
            .bind_reconcile(2, inserted.ownership_id, inserted.generation, binding(4))
            .expect("interposed reconcile binding");
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart after binding");
        let before_arm_retry = fs::read(&config.journal_path).expect("durable bound journal bytes");
        let revision_before_arm_retry = journal.snapshot().expect("usable bound snapshot").revision;
        assert_eq!(revision_before_arm_retry, 3);
        assert!(matches!(
            journal.mark_may_own_prepare(
                3,
                inserted.ownership_id,
                inserted.generation,
                exact_anchor,
            ),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(
            journal
                .snapshot()
                .expect("arm retry leaves snapshot usable")
                .revision,
            revision_before_arm_retry
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after interposed arm retry"),
            before_arm_retry
        );

        let bound_intent_directory = tempdir().expect("bound Intent temporary directory");
        let bound_intent_config = test_config(bound_intent_directory.path());
        let bound_intent = intent(5, 6);
        let mut journal =
            OwnershipJournal::open(bound_intent_config.clone()).expect("new bound-Intent journal");
        let inserted = journal
            .insert_intent(0, bound_intent.clone())
            .expect("durable bound-Intent fixture");
        journal
            .bind_reconcile(1, inserted.ownership_id, inserted.generation, binding(7))
            .expect("interposed Intent reconcile binding");
        drop(journal);

        let mut journal = OwnershipJournal::open(bound_intent_config.clone())
            .expect("restart after Intent binding");
        let before_bound_insert_retry =
            fs::read(&bound_intent_config.journal_path).expect("durable bound-Intent bytes");
        assert_eq!(
            journal
                .snapshot()
                .expect("usable bound-Intent snapshot")
                .revision,
            2
        );
        assert!(matches!(
            journal.insert_intent(2, bound_intent),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(
            journal
                .snapshot()
                .expect("bound insert retry leaves snapshot usable")
                .revision,
            2
        );
        assert_eq!(
            fs::read(&bound_intent_config.journal_path).expect("bytes after bound insert retry"),
            before_bound_insert_retry
        );
    }

    #[test]
    fn lost_never_dispatched_reply_restarts_to_exact_absent_success() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        journal
            .mark_intent_absent(1, inserted.ownership_id, inserted.generation)
            .expect("durable retirement whose reply is discarded");
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart journal");
        let before = fs::read(&config.journal_path).expect("durable absent bytes");
        for wrong_revision in [1, 3] {
            assert!(matches!(
                journal.mark_intent_absent(
                    wrong_revision,
                    inserted.ownership_id,
                    inserted.generation,
                ),
                Err(JournalError::RevisionConflict)
            ));
        }
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after stale absent retry"),
            before
        );
        assert_eq!(
            journal
                .mark_intent_absent(2, inserted.ownership_id, inserted.generation)
                .expect("exact absent retry at the current revision"),
            2
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact absent retry"),
            before
        );
        assert!(matches!(
            journal.recover_may_own_prepare(
                2,
                inserted.ownership_id,
                inserted.generation,
                &mut PanicIfRecoveryRuns,
                recovery_deadline(),
            ),
            Err(RecoveryAttemptError::Journal(
                JournalError::InvalidTransition
            ))
        ));
    }

    struct PanicIfRecoveryRuns;

    impl RecoveryExecutor for PanicIfRecoveryRuns {
        type Error = ();

        fn confirm_absent(
            &mut self,
            _target: &RecoveryTarget,
            _deadline: HardDeadline,
        ) -> Result<ConfirmedAbsentProof, Self::Error> {
            panic!("an already-Absent retry must not run recovery again")
        }
    }

    #[test]
    fn lost_recovery_reply_restarts_to_absent_without_rerunning_executor() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        journal
            .mark_may_own_prepare(1, inserted.ownership_id, inserted.generation, anchor(7))
            .expect("durable MayOwnPrepare");
        journal
            .recover_may_own_prepare(
                2,
                inserted.ownership_id,
                inserted.generation,
                &mut FakeRecoveryExecutor {
                    exact: true,
                    calls: 0,
                },
                recovery_deadline(),
            )
            .expect("durable recovery whose reply is discarded");
        drop(journal);

        let mut journal = OwnershipJournal::open(config.clone()).expect("restart journal");
        let before = fs::read(&config.journal_path).expect("durable recovered bytes");
        for wrong_revision in [2, 4] {
            assert!(matches!(
                journal.recover_may_own_prepare(
                    wrong_revision,
                    inserted.ownership_id,
                    inserted.generation,
                    &mut PanicIfRecoveryRuns,
                    recovery_deadline(),
                ),
                Err(RecoveryAttemptError::Journal(
                    JournalError::RevisionConflict
                ))
            ));
        }
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after stale recovered retry"),
            before
        );
        assert_eq!(
            journal
                .recover_may_own_prepare(
                    3,
                    inserted.ownership_id,
                    inserted.generation,
                    &mut PanicIfRecoveryRuns,
                    recovery_deadline(),
                )
                .expect("exact recovered retry at current revision skips executor"),
            3
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact recovered retry"),
            before
        );
        assert!(matches!(
            journal.mark_intent_absent(3, inserted.ownership_id, inserted.generation),
            Err(JournalError::InvalidTransition)
        ));
    }

    #[test]
    fn may_own_requires_exact_typed_proof_and_no_dispatch_api_cannot_bypass_it() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let may_own_revision = journal
            .mark_may_own_prepare(1, inserted.ownership_id, inserted.generation, anchor(7))
            .expect("durable MayOwnPrepare")
            .revision;
        assert_eq!(may_own_revision, 2);
        let before_snapshot = journal.snapshot().expect("usable snapshot").clone();
        let before_bytes = fs::read(&config.journal_path).expect("durable MayOwn bytes");

        let mut stale = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };
        assert!(matches!(
            recover_fixture(&mut journal, 1, inserted, &mut stale),
            Err(RecoveryAttemptError::Journal(
                JournalError::RevisionConflict
            ))
        ));
        assert_eq!(stale.calls, 0);
        assert_eq!(
            journal.snapshot().expect("stale recovery is inert"),
            &before_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("stale recovery leaves bytes unchanged"),
            before_bytes
        );

        assert!(matches!(
            journal.mark_intent_absent(2, inserted.ownership_id, inserted.generation),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(journal.snapshot().expect("still usable"), &before_snapshot);
        assert_eq!(
            fs::read(&config.journal_path).expect("unchanged bytes"),
            before_bytes
        );

        let mut wrong = FakeRecoveryExecutor {
            exact: false,
            calls: 0,
        };
        assert!(matches!(
            recover_fixture(&mut journal, 2, inserted, &mut wrong),
            Err(RecoveryAttemptError::Journal(JournalError::ProofMismatch))
        ));
        assert_eq!(wrong.calls, 1);
        assert_eq!(journal.snapshot().expect("still usable"), &before_snapshot);
        assert_eq!(
            fs::read(&config.journal_path).expect("unchanged bytes"),
            before_bytes
        );

        assert!(matches!(
            recover_fixture(&mut journal, 2, inserted, &mut ErrorRecoveryExecutor),
            Err(RecoveryAttemptError::Executor("injected recovery failure"))
        ));
        assert_eq!(
            journal.snapshot().expect("executor error is retryable"),
            &before_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("executor error leaves bytes unchanged"),
            before_bytes
        );

        let mut exact = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };
        assert_eq!(
            recover_fixture(&mut journal, 2, inserted, &mut exact).expect("exact typed proof"),
            3
        );
        let recovered = journal
            .snapshot()
            .expect("usable recovered journal")
            .records
            .get(&inserted.ownership_id)
            .expect("recovered tombstone");
        assert_eq!(recovered.phase, OwnershipPhase::Absent);
        assert_eq!(recovered.absent_origin, Some(AbsentOrigin::RecoveredMayOwn));
        assert!(recovered.recovery_anchor.is_none());
    }

    #[test]
    fn expired_recovery_and_late_exact_proof_leave_snapshot_and_bytes_unchanged() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        journal
            .mark_may_own_prepare(1, inserted.ownership_id, inserted.generation, anchor(7))
            .expect("durable MayOwnPrepare");
        let before_snapshot = journal.snapshot().expect("usable snapshot").clone();
        let before_bytes = fs::read(&config.journal_path).expect("durable MayOwn bytes");

        let mut never_started = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };
        let expired_before_executor =
            HardDeadline::after(Duration::from_millis(1)).expect("short deadline");
        while expired_before_executor.ensure_remaining().is_ok() {
            thread::yield_now();
        }
        assert!(matches!(
            journal.recover_may_own_prepare(
                2,
                inserted.ownership_id,
                inserted.generation,
                &mut never_started,
                expired_before_executor,
            ),
            Err(RecoveryAttemptError::Deadline)
        ));
        assert_eq!(never_started.calls, 0);
        assert_eq!(
            journal.snapshot().expect("expired recovery is inert"),
            &before_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after pre-executor expiry"),
            before_bytes
        );

        let deadline =
            HardDeadline::after(Duration::from_millis(100)).expect("blocking executor deadline");
        let mut blocked = ExpiringRecoveryExecutor {
            calls: 0,
            observed_deadline: None,
        };
        assert!(matches!(
            journal.recover_may_own_prepare(
                2,
                inserted.ownership_id,
                inserted.generation,
                &mut blocked,
                deadline,
            ),
            Err(RecoveryAttemptError::Deadline)
        ));
        assert_eq!(blocked.calls, 1);
        assert_eq!(blocked.observed_deadline, Some(deadline));
        assert_eq!(
            journal.snapshot().expect("late proof is inert"),
            &before_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after late exact proof"),
            before_bytes
        );
    }

    #[test]
    fn recovery_expiry_after_encoding_stops_before_creating_the_next_file() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        journal
            .mark_may_own_prepare(1, inserted.ownership_id, inserted.generation, anchor(7))
            .expect("durable MayOwnPrepare");
        let before_snapshot = journal.snapshot().expect("usable snapshot").clone();
        let before_bytes = fs::read(&config.journal_path).expect("durable MayOwn bytes");
        let deadline =
            HardDeadline::after(Duration::from_millis(30)).expect("persist boundary deadline");
        let mut observer = ExpireBeforeCreateObserver {
            deadline,
            steps: Vec::new(),
        };
        let mut exact = FakeRecoveryExecutor {
            exact: true,
            calls: 0,
        };

        assert!(matches!(
            journal.recover_may_own_prepare_observed(
                2,
                inserted.ownership_id,
                inserted.generation,
                &mut exact,
                deadline,
                &mut observer,
            ),
            Err(RecoveryAttemptError::Deadline)
        ));
        assert_eq!(exact.calls, 1);
        assert_eq!(observer.steps, vec![PersistStep::BeforeCreate]);
        assert_eq!(
            journal.snapshot().expect("persist expiry is inert"),
            &before_snapshot
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after persist-boundary expiry"),
            before_bytes
        );
        assert!(!config.next_path.exists());
    }

    #[test]
    fn reconcile_bound_intent_can_retire_but_can_never_be_dispatched_later() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        journal
            .bind_reconcile(1, inserted.ownership_id, inserted.generation, binding(4))
            .expect("durable reconcile lineage");
        let before = journal.snapshot().expect("usable snapshot").clone();
        assert!(matches!(
            journal.mark_may_own_prepare(2, inserted.ownership_id, inserted.generation, anchor(7),),
            Err(JournalError::InvalidTransition)
        ));
        assert_eq!(journal.snapshot().expect("unchanged snapshot"), &before);
        assert_eq!(
            journal
                .mark_intent_absent(2, inserted.ownership_id, inserted.generation)
                .expect("retirement-only transition"),
            3
        );
    }

    #[test]
    fn pre_rename_failpoints_preserve_authoritative_state_and_durable_bytes() {
        for step in [
            PersistStep::BeforeCreate,
            PersistStep::AfterCreate,
            PersistStep::AfterWrite,
            PersistStep::AfterFileSync,
            PersistStep::BeforeRename,
        ] {
            let directory = tempdir().expect("temporary directory");
            let config = test_config(directory.path());
            let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
            let inserted = journal
                .insert_intent(0, intent(2, 3))
                .expect("durable intent");
            let before_snapshot = journal.snapshot().expect("usable snapshot").clone();
            let before_bytes = fs::read(&config.journal_path).expect("durable bytes");
            let next = next_with_binding(&journal, inserted, binding(4));
            let mut observer = FailingObserver { steps: vec![step] };
            assert!(matches!(
                journal.compare_and_swap_observed(1, next, &mut observer),
                Err(JournalError::Io(_))
            ));
            assert_eq!(
                journal.snapshot().expect("retryable journal"),
                &before_snapshot
            );
            assert_eq!(
                fs::read(&config.journal_path).expect("unchanged journal bytes"),
                before_bytes
            );
            assert!(!config.next_path.exists());
        }
    }

    #[test]
    fn clean_pre_rename_failure_is_confirmed_retry_safe_and_retry_writes_once() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let before = fs::read(&config.journal_path).expect("durable bytes before failure");
        let next = next_with_binding(&journal, inserted, binding(4));
        let mut observer = FailingObserver {
            steps: vec![PersistStep::AfterWrite],
        };
        assert!(matches!(
            journal.compare_and_swap_observed(1, next, &mut observer),
            Err(JournalError::Io(_))
        ));

        journal
            .confirm_retry_safe_after_definite_failure()
            .expect("complete authority boundary remains retry-safe");
        assert_eq!(
            journal
                .bind_reconcile(1, inserted.ownership_id, inserted.generation, binding(4))
                .expect("single retry commits"),
            2
        );
        let committed = fs::read(&config.journal_path).expect("committed retry bytes");
        assert_ne!(committed, before);
        assert_eq!(
            journal
                .bind_reconcile(2, inserted.ownership_id, inserted.generation, binding(4))
                .expect("exact retry is read-only"),
            2
        );
        assert_eq!(
            fs::read(&config.journal_path).expect("bytes after exact retry"),
            committed
        );
        assert!(!config.next_path.exists());
    }

    #[test]
    fn retry_healthcheck_rejects_next_entry_without_removing_it_and_poison_is_sticky() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        fs::write(&config.next_path, b"foreign next entry").expect("next fixture");
        fs::set_permissions(
            &config.next_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("next fixture mode");

        assert_retry_healthcheck_poisoned(&mut journal);
        assert_eq!(
            fs::read(&config.next_path).expect("healthcheck leaves next untouched"),
            b"foreign next entry"
        );
    }

    #[test]
    fn retry_healthcheck_rejects_parent_substitution_without_creating_entries() {
        let directory = tempdir().expect("temporary directory");
        let parent = directory.path().join("runtime");
        let moved_parent = directory.path().join("retained-runtime");
        fs::create_dir(&parent).expect("runtime parent");
        let config = test_config(&parent);
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        fs::rename(&parent, &moved_parent).expect("move retained parent");
        fs::create_dir(&parent).expect("substituted parent");
        fs::set_permissions(
            &parent,
            fs::Permissions::from_mode(config.expected_parent_mode),
        )
        .expect("substituted parent mode");

        assert_retry_healthcheck_poisoned(&mut journal);
        assert_eq!(
            fs::read_dir(&parent)
                .expect("substituted parent remains readable")
                .count(),
            0
        );
        assert!(moved_parent.join("helper.ownership-v3").exists());
        assert!(moved_parent.join("helper.ownership-v3.lock").exists());
    }

    #[test]
    fn retry_healthcheck_rejects_lock_substitution_or_lost_exclusive_lock() {
        let substituted_directory = tempdir().expect("substitution directory");
        let substituted_config = test_config(substituted_directory.path());
        let mut substituted =
            OwnershipJournal::open(substituted_config.clone()).expect("new journal");
        let retained_lock = substituted_directory.path().join("retained-lock");
        fs::rename(&substituted_config.lock_path, &retained_lock)
            .expect("move retained lock entry");
        fs::write(&substituted_config.lock_path, b"").expect("replacement lock entry");
        fs::set_permissions(
            &substituted_config.lock_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("replacement lock mode");

        assert_retry_healthcheck_poisoned(&mut substituted);
        assert!(retained_lock.exists());
        assert!(substituted_config.lock_path.exists());

        let unlocked_directory = tempdir().expect("unlocked directory");
        let unlocked_config = test_config(unlocked_directory.path());
        let mut unlocked = OwnershipJournal::open(unlocked_config).expect("new journal");
        flock(&unlocked.runtime_lock, FlockOperation::Unlock).expect("release fixture lock");
        assert_retry_healthcheck_poisoned(&mut unlocked);
    }

    #[test]
    fn retry_healthcheck_rejects_main_substitution_or_readability_loss_without_repair() {
        let substituted_directory = tempdir().expect("substitution directory");
        let substituted_config = test_config(substituted_directory.path());
        let mut substituted =
            OwnershipJournal::open(substituted_config.clone()).expect("new journal");
        substituted
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let mut replacement = substituted.snapshot().expect("snapshot").clone();
        replacement.revision = 2;
        let replacement_path = substituted_directory.path().join("replacement-main");
        let replacement_bytes = replacement.encode().expect("replacement encoding");
        fs::write(&replacement_path, &replacement_bytes).expect("replacement main");
        fs::set_permissions(
            &replacement_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("replacement main mode");
        fs::rename(&replacement_path, &substituted_config.journal_path)
            .expect("substitute main entry");

        assert_retry_healthcheck_poisoned(&mut substituted);
        assert_eq!(
            fs::read(&substituted_config.journal_path)
                .expect("healthcheck leaves substituted main untouched"),
            replacement_bytes
        );

        let unreadable_directory = tempdir().expect("unreadable directory");
        let unreadable_config = test_config(unreadable_directory.path());
        let mut unreadable =
            OwnershipJournal::open(unreadable_config.clone()).expect("new journal");
        unreadable
            .insert_intent(0, intent(5, 6))
            .expect("durable intent");
        fs::set_permissions(
            &unreadable_config.journal_path,
            fs::Permissions::from_mode(0o000),
        )
        .expect("remove main readability");

        assert_retry_healthcheck_poisoned(&mut unreadable);
        assert_eq!(
            fs::metadata(&unreadable_config.journal_path)
                .expect("unreadable main remains")
                .mode()
                & 0o7777,
            0
        );
    }

    #[test]
    fn post_rename_and_cleanup_uncertainty_poison_all_authoritative_access() {
        for steps in [
            vec![PersistStep::AfterRename],
            vec![PersistStep::AfterDirectorySync],
            vec![PersistStep::AfterWrite, PersistStep::BeforeCleanupUnlink],
            vec![
                PersistStep::AfterWrite,
                PersistStep::BeforeCleanupDirectorySync,
            ],
        ] {
            let directory = tempdir().expect("temporary directory");
            let config = test_config(directory.path());
            let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
            let inserted = journal
                .insert_intent(0, intent(2, 3))
                .expect("durable intent");
            let next = next_with_binding(&journal, inserted, binding(4));
            let expected_after_restart = if steps.contains(&PersistStep::AfterRename)
                || steps.contains(&PersistStep::AfterDirectorySync)
            {
                let mut committed = next.clone();
                committed.revision = 2;
                committed
            } else {
                journal.snapshot().expect("old complete snapshot").clone()
            };
            let mut observer = FailingObserver { steps };
            assert!(matches!(
                journal.compare_and_swap_observed(1, next, &mut observer),
                Err(JournalError::PersistUncertain)
            ));
            assert!(matches!(journal.snapshot(), Err(JournalError::Poisoned)));
            assert!(matches!(
                journal.mark_intent_absent(1, inserted.ownership_id, inserted.generation),
                Err(JournalError::Poisoned)
            ));
            drop(journal);
            let reopened = OwnershipJournal::open(config.clone()).expect("restart after ambiguity");
            assert_eq!(
                reopened.snapshot().expect("complete restarted snapshot"),
                &expected_after_restart
            );
            assert!(!config.next_path.exists());
        }
    }

    #[test]
    fn stale_cas_and_revision_overflow_leave_bytes_and_memory_unchanged() {
        let directory = tempdir().expect("temporary directory");
        let config = test_config(directory.path());
        let mut journal = OwnershipJournal::open(config.clone()).expect("new journal");
        let inserted = journal
            .insert_intent(0, intent(2, 3))
            .expect("durable intent");
        let before = fs::read(&config.journal_path).expect("durable bytes");
        assert!(matches!(
            journal.bind_reconcile(0, inserted.ownership_id, inserted.generation, binding(4)),
            Err(JournalError::RevisionConflict)
        ));
        assert_eq!(
            fs::read(&config.journal_path).expect("unchanged bytes"),
            before
        );

        drop(journal);
        let overflow_snapshot = JournalSnapshot {
            journal_epoch_id: epoch(1),
            revision: u64::MAX,
            next_generation: 1,
            records: BTreeMap::new(),
        };
        fs::write(
            &config.journal_path,
            overflow_snapshot
                .encode()
                .expect("overflow fixture encoding"),
        )
        .expect("overflow journal fixture");
        fs::set_permissions(
            &config.journal_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("overflow fixture mode");
        let mut journal = OwnershipJournal::open(config.clone()).expect("overflow journal");
        let before = fs::read(&config.journal_path).expect("overflow bytes");
        assert!(matches!(
            journal.insert_intent(u64::MAX, intent(5, 6)),
            Err(JournalError::Capacity)
        ));
        assert_eq!(
            fs::read(&config.journal_path).expect("unchanged overflow bytes"),
            before
        );
        assert_eq!(
            journal.snapshot().expect("usable snapshot"),
            &overflow_snapshot
        );
    }

    #[test]
    fn fifo_entries_fail_closed_with_a_bounded_open_and_no_mutation() {
        let fifo_directory = tempdir().expect("FIFO fixture directory");
        let fifo_config = test_config(fifo_directory.path());
        let fifo_parent = File::open(fifo_directory.path()).expect("FIFO parent descriptor");
        rustix::fs::mkfifoat(
            &fifo_parent,
            "helper.ownership-v3",
            Mode::from_raw_mode(JOURNAL_FILE_MODE),
        )
        .expect("FIFO fixture");
        assert!(matches!(
            open_fifo_with_deadline(fifo_config.clone(), fifo_config.journal_path.clone()),
            Err(JournalError::UnsafeMetadata)
        ));
        assert!(
            fs::symlink_metadata(fifo_directory.path().join("helper.ownership-v3"))
                .expect("FIFO remains")
                .file_type()
                .is_fifo()
        );

        let next_fifo_directory = tempdir().expect("next FIFO fixture directory");
        let next_fifo_config = test_config(next_fifo_directory.path());
        let next_fifo_parent =
            File::open(next_fifo_directory.path()).expect("next FIFO parent descriptor");
        rustix::fs::mkfifoat(
            &next_fifo_parent,
            "helper.ownership-v3.next",
            Mode::from_raw_mode(JOURNAL_FILE_MODE),
        )
        .expect("next FIFO fixture");
        assert!(matches!(
            open_fifo_with_deadline(next_fifo_config.clone(), next_fifo_config.next_path.clone()),
            Err(JournalError::UnsafeMetadata)
        ));
        assert!(
            fs::symlink_metadata(&next_fifo_config.next_path)
                .expect("unsafe next FIFO remains")
                .file_type()
                .is_fifo()
        );
    }

    #[test]
    fn socket_directory_symlink_and_hardlink_journals_fail_closed_without_mutation() {
        let socket_directory = tempdir().expect("socket fixture parent");
        let socket_config = test_config(socket_directory.path());
        let _socket = UnixListener::bind(&socket_config.journal_path).expect("socket fixture");
        assert!(OwnershipJournal::open(socket_config.clone()).is_err());
        assert!(
            fs::symlink_metadata(&socket_config.journal_path)
                .expect("socket remains")
                .file_type()
                .is_socket()
        );

        let directory_fixture = tempdir().expect("directory fixture parent");
        let directory_config = test_config(directory_fixture.path());
        fs::create_dir(&directory_config.journal_path).expect("directory journal fixture");
        assert!(matches!(
            OwnershipJournal::open(directory_config),
            Err(JournalError::UnsafeMetadata)
        ));

        let symlink_directory = tempdir().expect("symlink fixture parent");
        let symlink_config = test_config(symlink_directory.path());
        symlink("missing", &symlink_config.journal_path).expect("journal symlink fixture");
        assert!(matches!(
            OwnershipJournal::open(symlink_config),
            Err(JournalError::UnsafeMetadata)
        ));

        let hardlink_directory = tempdir().expect("hardlink fixture parent");
        let hardlink_config = test_config(hardlink_directory.path());
        fs::write(&hardlink_config.journal_path, b"journal").expect("hardlink journal fixture");
        fs::set_permissions(
            &hardlink_config.journal_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("hardlink fixture mode");
        fs::hard_link(
            &hardlink_config.journal_path,
            hardlink_directory.path().join("journal-alias"),
        )
        .expect("journal hardlink fixture");
        assert!(matches!(
            OwnershipJournal::open(hardlink_config.clone()),
            Err(JournalError::UnsafeMetadata)
        ));
        assert_eq!(
            fs::metadata(&hardlink_config.journal_path)
                .expect("hardlinked journal remains")
                .nlink(),
            2
        );
    }

    #[test]
    fn oversized_journal_input_is_rejected_before_unbounded_read_or_decode() {
        let oversized_directory = tempdir().expect("oversized fixture parent");
        let oversized_config = test_config(oversized_directory.path());
        fs::write(
            &oversized_config.journal_path,
            vec![0; MAX_JOURNAL_BYTES + 1],
        )
        .expect("oversized journal fixture");
        fs::set_permissions(
            &oversized_config.journal_path,
            fs::Permissions::from_mode(JOURNAL_FILE_MODE),
        )
        .expect("oversized fixture mode");
        assert!(matches!(
            OwnershipJournal::open(oversized_config),
            Err(JournalError::Corrupt)
        ));
    }

    #[test]
    fn record_count_capacity_is_enforced_before_encoding_allocation_growth() {
        let journal_epoch = epoch(1);
        let template = record(journal_epoch, 1, 2, 3, 1, OwnershipPhase::Intent);
        let mut records = BTreeMap::new();
        for index in 1..=MAX_RECORDS + 1 {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(
                &u64::try_from(index)
                    .expect("bounded record index")
                    .to_be_bytes(),
            );
            let ownership_id = OwnershipId::new(bytes).expect("unique ownership fixture");
            let mut entry = template.clone();
            entry.ownership_id = ownership_id;
            records.insert(ownership_id, entry);
        }
        let oversized = JournalSnapshot {
            journal_epoch_id: journal_epoch,
            revision: 1,
            next_generation: 2,
            records,
        };
        assert!(matches!(oversized.validate(), Err(JournalError::Capacity)));
        assert!(matches!(oversized.encode(), Err(JournalError::Capacity)));
    }

    #[test]
    fn v3_store_remains_dormant_in_known_production_entrypoints() {
        for production_source in [
            include_str!("lib.rs"),
            include_str!("engine_v3.rs"),
            include_str!("runtime.rs"),
            include_str!("server.rs"),
            include_str!("main.rs"),
        ] {
            assert!(!production_source.contains("open_production"));
        }
    }

    #[test]
    fn absent_is_accepted_but_every_existing_object_fails_closed_without_mutation() {
        let directory = tempdir().expect("temporary directory");
        let candidate = directory.path().join("journal");
        ensure_absent(&candidate).expect("absent journal");

        fs::write(&candidate, b"legacy").expect("legacy fixture");
        assert_eq!(
            ensure_absent(&candidate)
                .expect_err("file must block")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&candidate).expect("fixture remains"), b"legacy");

        fs::remove_file(&candidate).expect("remove fixture");
        symlink("missing-target", &candidate).expect("symlink fixture");
        assert_eq!(
            ensure_absent(&candidate)
                .expect_err("symlink must block")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(fs::symlink_metadata(&candidate).is_ok());
    }

    #[test]
    fn v3_interlock_checks_exactly_main_lock_and_next_without_mutation() {
        let directory = tempdir().expect("temporary directory");
        let journal = directory.path().join("helper.ownership-v3");
        let lock = directory.path().join("helper.ownership-v3.lock");
        let next = directory.path().join("helper.ownership-v3.next");
        let exact = [&journal, &lock, &next];
        let near_misses = [
            "helper.ownership-v3.backup",
            "helper.ownership-v3.lock.extra",
            "helper.ownership-v3.next.extra",
            ".helper.ownership-v3.tmp-deadbeef",
        ];

        ensure_v3_journal_objects_absent(&journal, &lock, &next).expect("all absent");
        for name in near_misses {
            fs::write(directory.path().join(name), b"near miss").expect("near-miss fixture");
        }
        ensure_v3_journal_objects_absent(&journal, &lock, &next)
            .expect("near misses are outside the closed object set");

        for path in exact {
            fs::write(path, b"owned bytes").expect("file fixture");
            assert_eq!(
                ensure_v3_journal_objects_absent(&journal, &lock, &next)
                    .expect_err("file must block")
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_eq!(fs::read(path).expect("file remains"), b"owned bytes");
            fs::remove_file(path).expect("remove file fixture");

            fs::create_dir(path).expect("directory fixture");
            assert_eq!(
                ensure_v3_journal_objects_absent(&journal, &lock, &next)
                    .expect_err("directory must block")
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            assert!(
                fs::symlink_metadata(path)
                    .expect("directory remains")
                    .is_dir()
            );
            fs::remove_dir(path).expect("remove directory fixture");

            symlink("missing-target", path).expect("symlink fixture");
            assert_eq!(
                ensure_v3_journal_objects_absent(&journal, &lock, &next)
                    .expect_err("symlink must block")
                    .kind(),
                io::ErrorKind::AlreadyExists
            );
            assert!(
                fs::symlink_metadata(path)
                    .expect("symlink remains")
                    .file_type()
                    .is_symlink()
            );
            fs::remove_file(path).expect("remove symlink fixture");
        }

        for name in near_misses {
            assert_eq!(
                fs::read(directory.path().join(name)).expect("near miss remains"),
                b"near miss"
            );
        }
    }

    #[test]
    fn production_server_checks_journals_before_token_socket_and_listener_mutation() {
        let source = include_str!("server.rs");
        let start = source
            .find("pub fn bind_production_socket")
            .expect("production bind function");
        let end = source[start..]
            .find("pub async fn run_server")
            .map(|offset| start + offset)
            .expect("end of production bind function");
        let bind = &source[start..end];
        let legacy = bind
            .find("ensure_legacy_journal_absent()?")
            .expect("legacy interlock");
        let v3 = bind
            .find("ensure_unreaped_v3_journal_absent()?")
            .expect("v3 interlock");
        let runtime = bind
            .find("prepare_production_runtime()?")
            .expect("runtime and cleanup-token preparation");
        let stale_socket = bind
            .find("remove_stale_socket")
            .expect("stale-socket removal");
        let listener = bind.find("UnixListener::bind").expect("listener bind");

        assert!(legacy < v3);
        assert!(v3 < runtime);
        assert!(runtime < stale_socket);
        assert!(stale_socket < listener);
    }
}
