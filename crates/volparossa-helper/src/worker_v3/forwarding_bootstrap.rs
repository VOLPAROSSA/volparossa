//! Root-only IPv6-forwarding bootstrap for one already-unshared worker namespace.
//!
//! Linux does not expose an IPv6-forwarding setter through rtnetlink. The only
//! production mutation here is therefore one bounded write to the fixed procfs
//! `conf/all/forwarding` knob while the worker is still root. Linux applies that
//! global write to both the existing interfaces and `conf/default/forwarding`;
//! both values are read back before this affine bootstrap returns.

use std::{io, os::fd::OwnedFd};

use nix::unistd::geteuid;
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, fstatfs, open, openat2};
use thiserror::Error;

use crate::{deadline::HardDeadline, worker_sandbox::NetworkNamespaceIdentity};

const PROC_ROOT: &str = "/proc";
const ALL_FORWARDING: &str = "sys/net/ipv6/conf/all/forwarding";
const DEFAULT_FORWARDING: &str = "sys/net/ipv6/conf/default/forwarding";
const PROC_SUPER_MAGIC: i128 = 0x0000_9fa0;
const FORWARDING_DISABLED: &[u8; 2] = b"0\n";
const FORWARDING_ENABLED: &[u8; 2] = b"1\n";
const FORWARDING_READ_BOUND: usize = 3;

/// Failure to enable and prove the exact worker-local IPv6 forwarding state.
#[derive(Debug, Error)]
pub(super) enum Ipv6ForwardingBootstrapError {
    /// The caller-supplied monotonic operation deadline elapsed.
    #[error("IPv6 forwarding bootstrap deadline elapsed")]
    Deadline,
    /// The operation was not executed by the exact root pre-drop worker phase.
    #[error("IPv6 forwarding bootstrap requires the root pre-drop phase")]
    Authentication,
    /// The worker was not proven to be outside the captured parent namespace.
    #[error("IPv6 forwarding bootstrap namespace evidence is invalid")]
    NamespaceEvidence,
    /// A descriptor did not identify the fixed, protected procfs object.
    #[error("IPv6 forwarding bootstrap procfs evidence is invalid")]
    ProcfsEvidence,
    /// A procfs boolean was not encoded as exactly `0\n` or `1\n`.
    #[error("IPv6 forwarding bootstrap state is non-canonical")]
    NonCanonical,
    /// The sole bounded write failed or could not be proven complete.
    #[error("IPv6 forwarding bootstrap mutation is ambiguous")]
    MutationAmbiguous,
    /// A fixed kernel/filesystem observation failed.
    #[error("IPv6 forwarding bootstrap kernel operation failed")]
    Io(#[source] io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForwardingKnob {
    All,
    Default,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorEvidence {
    file_type: FileType,
    device: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
}

trait ForwardingBootstrapKernel {
    type Descriptor;

    fn checkpoint(&mut self, deadline: HardDeadline) -> Result<(), Ipv6ForwardingBootstrapError>;
    fn effective_uid(&mut self) -> u32;
    fn current_network_namespace(&mut self) -> io::Result<NetworkNamespaceIdentity>;
    fn open_proc_root(&mut self) -> io::Result<Self::Descriptor>;
    fn open_forwarding(
        &mut self,
        proc_root: &Self::Descriptor,
        knob: ForwardingKnob,
    ) -> io::Result<Self::Descriptor>;
    fn filesystem_magic(&mut self, descriptor: &Self::Descriptor) -> io::Result<i128>;
    fn descriptor_evidence(
        &mut self,
        descriptor: &Self::Descriptor,
    ) -> io::Result<DescriptorEvidence>;
    fn read_at_zero(
        &mut self,
        descriptor: &Self::Descriptor,
        bytes: &mut [u8; FORWARDING_READ_BOUND],
    ) -> io::Result<usize>;
    fn write_enabled(&mut self, descriptor: &Self::Descriptor) -> io::Result<usize>;
    fn close_descriptor(&mut self, descriptor: Self::Descriptor);
}

struct ProductionForwardingBootstrapKernel;

impl ForwardingBootstrapKernel for ProductionForwardingBootstrapKernel {
    type Descriptor = OwnedFd;

    fn checkpoint(&mut self, deadline: HardDeadline) -> Result<(), Ipv6ForwardingBootstrapError> {
        deadline
            .ensure_remaining()
            .map_err(|error| match error.kind() {
                io::ErrorKind::TimedOut => Ipv6ForwardingBootstrapError::Deadline,
                _ => Ipv6ForwardingBootstrapError::Io(error),
            })
    }

    fn effective_uid(&mut self) -> u32 {
        geteuid().as_raw()
    }

    fn current_network_namespace(&mut self) -> io::Result<NetworkNamespaceIdentity> {
        crate::worker_sandbox::current_network_namespace_identity()
            .map_err(|_| io::Error::other("worker network namespace observation failed"))
    }

    fn open_proc_root(&mut self) -> io::Result<Self::Descriptor> {
        open(
            PROC_ROOT,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(rustix_io)
    }

    fn open_forwarding(
        &mut self,
        proc_root: &Self::Descriptor,
        knob: ForwardingKnob,
    ) -> io::Result<Self::Descriptor> {
        let (path, access) = match knob {
            ForwardingKnob::All => (ALL_FORWARDING, OFlags::RDWR),
            ForwardingKnob::Default => (DEFAULT_FORWARDING, OFlags::RDONLY),
        };
        openat2(
            proc_root,
            path,
            access | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_XDEV
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(rustix_io)
    }

    fn filesystem_magic(&mut self, descriptor: &Self::Descriptor) -> io::Result<i128> {
        fstatfs(descriptor)
            .map(|metadata| i128::from(metadata.f_type))
            .map_err(rustix_io)
    }

    fn descriptor_evidence(
        &mut self,
        descriptor: &Self::Descriptor,
    ) -> io::Result<DescriptorEvidence> {
        let metadata = fstat(descriptor).map_err(rustix_io)?;
        Ok(DescriptorEvidence {
            file_type: FileType::from_raw_mode(metadata.st_mode),
            device: metadata.st_dev,
            inode: metadata.st_ino,
            owner_uid: metadata.st_uid,
            mode: metadata.st_mode,
        })
    }

    fn read_at_zero(
        &mut self,
        descriptor: &Self::Descriptor,
        bytes: &mut [u8; FORWARDING_READ_BOUND],
    ) -> io::Result<usize> {
        rustix::io::pread(descriptor, bytes, 0).map_err(rustix_io)
    }

    fn write_enabled(&mut self, descriptor: &Self::Descriptor) -> io::Result<usize> {
        rustix::io::write(descriptor, FORWARDING_ENABLED).map_err(rustix_io)
    }

    fn close_descriptor(&mut self, descriptor: Self::Descriptor) {
        drop(descriptor);
    }
}

/// Enable IPv6 forwarding inside one exact, already-unshared root worker.
///
/// The function does not retain or return a procfs descriptor. Any failure after
/// the sole write is fail-closed at the surrounding worker-bootstrap boundary:
/// the unauthenticated child must exit and its private namespace is destroyed.
pub(super) fn enable_ipv6_forwarding_before_identity_drop(
    parent_network_namespace: NetworkNamespaceIdentity,
    worker_network_namespace: NetworkNamespaceIdentity,
    deadline: HardDeadline,
) -> Result<(), Ipv6ForwardingBootstrapError> {
    enable_ipv6_forwarding_with_kernel(
        &mut ProductionForwardingBootstrapKernel,
        parent_network_namespace,
        worker_network_namespace,
        deadline,
    )
}

fn enable_ipv6_forwarding_with_kernel<K: ForwardingBootstrapKernel>(
    kernel: &mut K,
    parent_network_namespace: NetworkNamespaceIdentity,
    worker_network_namespace: NetworkNamespaceIdentity,
    deadline: HardDeadline,
) -> Result<(), Ipv6ForwardingBootstrapError> {
    let mut proc_root = None;
    let mut all = None;
    let mut default = None;
    let operation = bootstrap_operation(
        kernel,
        parent_network_namespace,
        worker_network_namespace,
        deadline,
        &mut proc_root,
        &mut all,
        &mut default,
    );

    let mut first_error = operation.err();
    close_if_open(kernel, &mut default, deadline, &mut first_error);
    close_if_open(kernel, &mut all, deadline, &mut first_error);
    close_if_open(kernel, &mut proc_root, deadline, &mut first_error);
    if let Err(error) = kernel.checkpoint(deadline) {
        first_error.get_or_insert(error);
    }
    first_error.map_or(Ok(()), Err)
}

fn bootstrap_operation<K: ForwardingBootstrapKernel>(
    kernel: &mut K,
    parent_network_namespace: NetworkNamespaceIdentity,
    worker_network_namespace: NetworkNamespaceIdentity,
    deadline: HardDeadline,
    proc_root: &mut Option<K::Descriptor>,
    all: &mut Option<K::Descriptor>,
    default: &mut Option<K::Descriptor>,
) -> Result<(), Ipv6ForwardingBootstrapError> {
    authenticate_private_root_worker(
        kernel,
        parent_network_namespace,
        worker_network_namespace,
        deadline,
    )?;
    let root_evidence = open_and_prove_proc_root(kernel, proc_root, deadline)?;
    let all_evidence = open_and_prove_forwarding(
        kernel,
        opened_descriptor(proc_root.as_ref())?,
        ForwardingKnob::All,
        all,
        deadline,
    )?;
    let default_evidence = open_and_prove_forwarding(
        kernel,
        opened_descriptor(proc_root.as_ref())?,
        ForwardingKnob::Default,
        default,
        deadline,
    )?;
    if all_evidence.device != root_evidence.device
        || default_evidence.device != root_evidence.device
        || (all_evidence.device, all_evidence.inode)
            == (default_evidence.device, default_evidence.inode)
    {
        return Err(Ipv6ForwardingBootstrapError::ProcfsEvidence);
    }
    configure_forwarding(
        kernel,
        opened_descriptor(all.as_ref())?,
        opened_descriptor(default.as_ref())?,
        deadline,
    )
}

fn authenticate_private_root_worker<K: ForwardingBootstrapKernel>(
    kernel: &mut K,
    parent_network_namespace: NetworkNamespaceIdentity,
    worker_network_namespace: NetworkNamespaceIdentity,
    deadline: HardDeadline,
) -> Result<(), Ipv6ForwardingBootstrapError> {
    checkpoint(kernel, deadline)?;
    if kernel.effective_uid() != 0 {
        return Err(Ipv6ForwardingBootstrapError::Authentication);
    }
    checkpoint(kernel, deadline)?;
    let current = kernel
        .current_network_namespace()
        .map_err(Ipv6ForwardingBootstrapError::Io)?;
    if parent_network_namespace == worker_network_namespace || current != worker_network_namespace {
        return Err(Ipv6ForwardingBootstrapError::NamespaceEvidence);
    }
    Ok(())
}

fn open_and_prove_proc_root<K: ForwardingBootstrapKernel>(
    kernel: &mut K,
    descriptor: &mut Option<K::Descriptor>,
    deadline: HardDeadline,
) -> Result<DescriptorEvidence, Ipv6ForwardingBootstrapError> {
    checkpoint(kernel, deadline)?;
    *descriptor = Some(
        kernel
            .open_proc_root()
            .map_err(Ipv6ForwardingBootstrapError::Io)?,
    );
    prove_descriptor(
        kernel,
        opened_descriptor(descriptor.as_ref())?,
        FileType::Directory,
        deadline,
    )
}

fn open_and_prove_forwarding<K: ForwardingBootstrapKernel>(
    kernel: &mut K,
    proc_root: &K::Descriptor,
    knob: ForwardingKnob,
    descriptor: &mut Option<K::Descriptor>,
    deadline: HardDeadline,
) -> Result<DescriptorEvidence, Ipv6ForwardingBootstrapError> {
    checkpoint(kernel, deadline)?;
    *descriptor = Some(
        kernel
            .open_forwarding(proc_root, knob)
            .map_err(Ipv6ForwardingBootstrapError::Io)?,
    );
    prove_descriptor(
        kernel,
        opened_descriptor(descriptor.as_ref())?,
        FileType::RegularFile,
        deadline,
    )
}

fn configure_forwarding<K: ForwardingBootstrapKernel>(
    kernel: &mut K,
    all: &K::Descriptor,
    default: &K::Descriptor,
    deadline: HardDeadline,
) -> Result<(), Ipv6ForwardingBootstrapError> {
    let all_state = read_forwarding(kernel, all, deadline)?;
    let default_state = read_forwarding(kernel, default, deadline)?;
    if all_state != ForwardingState::Enabled || default_state != ForwardingState::Enabled {
        checkpoint(kernel, deadline)?;
        let written = kernel
            .write_enabled(all)
            .map_err(|_| Ipv6ForwardingBootstrapError::MutationAmbiguous)?;
        if written != FORWARDING_ENABLED.len() {
            return Err(Ipv6ForwardingBootstrapError::MutationAmbiguous);
        }
    }
    if read_forwarding(kernel, all, deadline)? != ForwardingState::Enabled
        || read_forwarding(kernel, default, deadline)? != ForwardingState::Enabled
    {
        return Err(Ipv6ForwardingBootstrapError::MutationAmbiguous);
    }
    Ok(())
}

fn opened_descriptor<D>(descriptor: Option<&D>) -> Result<&D, Ipv6ForwardingBootstrapError> {
    descriptor.ok_or(Ipv6ForwardingBootstrapError::ProcfsEvidence)
}

fn checkpoint<K: ForwardingBootstrapKernel>(
    kernel: &mut K,
    deadline: HardDeadline,
) -> Result<(), Ipv6ForwardingBootstrapError> {
    kernel.checkpoint(deadline)
}

fn prove_descriptor<K: ForwardingBootstrapKernel>(
    kernel: &mut K,
    descriptor: &K::Descriptor,
    expected_type: FileType,
    deadline: HardDeadline,
) -> Result<DescriptorEvidence, Ipv6ForwardingBootstrapError> {
    checkpoint(kernel, deadline)?;
    if kernel
        .filesystem_magic(descriptor)
        .map_err(Ipv6ForwardingBootstrapError::Io)?
        != PROC_SUPER_MAGIC
    {
        return Err(Ipv6ForwardingBootstrapError::ProcfsEvidence);
    }
    checkpoint(kernel, deadline)?;
    let evidence = kernel
        .descriptor_evidence(descriptor)
        .map_err(Ipv6ForwardingBootstrapError::Io)?;
    if evidence.file_type != expected_type
        || evidence.device == 0
        || evidence.inode == 0
        || evidence.owner_uid != 0
        || evidence.mode & 0o022 != 0
    {
        return Err(Ipv6ForwardingBootstrapError::ProcfsEvidence);
    }
    Ok(evidence)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForwardingState {
    Disabled,
    Enabled,
}

fn read_forwarding<K: ForwardingBootstrapKernel>(
    kernel: &mut K,
    descriptor: &K::Descriptor,
    deadline: HardDeadline,
) -> Result<ForwardingState, Ipv6ForwardingBootstrapError> {
    checkpoint(kernel, deadline)?;
    let mut bytes = [0_u8; FORWARDING_READ_BOUND];
    let length = kernel
        .read_at_zero(descriptor, &mut bytes)
        .map_err(Ipv6ForwardingBootstrapError::Io)?;
    match &bytes[..length.min(bytes.len())] {
        value if length == FORWARDING_DISABLED.len() && value == FORWARDING_DISABLED => {
            Ok(ForwardingState::Disabled)
        }
        value if length == FORWARDING_ENABLED.len() && value == FORWARDING_ENABLED => {
            Ok(ForwardingState::Enabled)
        }
        _ => Err(Ipv6ForwardingBootstrapError::NonCanonical),
    }
}

fn close_if_open<K: ForwardingBootstrapKernel>(
    kernel: &mut K,
    descriptor: &mut Option<K::Descriptor>,
    deadline: HardDeadline,
    first_error: &mut Option<Ipv6ForwardingBootstrapError>,
) {
    if let Some(descriptor) = descriptor.take() {
        if let Err(error) = kernel.checkpoint(deadline) {
            first_error.get_or_insert(error);
        }
        kernel.close_descriptor(descriptor);
    }
}

fn rustix_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque, rc::Rc, time::Duration};

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DescriptorKind {
        ProcRoot,
        All,
        Default,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Checkpoint,
        EffectiveUid,
        CurrentNamespace,
        Open(DescriptorKind),
        FilesystemMagic(DescriptorKind),
        Evidence(DescriptorKind),
        Read(DescriptorKind),
        Write,
        Close(DescriptorKind),
    }

    struct MockDescriptor {
        kind: DescriptorKind,
    }

    struct MockKernel {
        events: Rc<RefCell<Vec<Event>>>,
        uid: u32,
        current_namespace: NetworkNamespaceIdentity,
        checkpoint_count: usize,
        fail_checkpoint: Option<usize>,
        fail_operation: Option<Event>,
        all_reads: VecDeque<Vec<u8>>,
        default_reads: VecDeque<Vec<u8>>,
        write_result: io::Result<usize>,
        writes: usize,
        opened: usize,
        closed: usize,
        magic_override: Option<(DescriptorKind, i128)>,
        evidence_override: Option<(DescriptorKind, DescriptorEvidence)>,
    }

    impl MockKernel {
        fn successful(all: &[u8], default: &[u8]) -> Self {
            Self {
                events: Rc::new(RefCell::new(Vec::new())),
                uid: 0,
                current_namespace: NetworkNamespaceIdentity::fixture(7, 8),
                checkpoint_count: 0,
                fail_checkpoint: None,
                fail_operation: None,
                all_reads: VecDeque::from([all.to_vec(), FORWARDING_ENABLED.to_vec()]),
                default_reads: VecDeque::from([default.to_vec(), FORWARDING_ENABLED.to_vec()]),
                write_result: Ok(FORWARDING_ENABLED.len()),
                writes: 0,
                opened: 0,
                closed: 0,
                magic_override: None,
                evidence_override: None,
            }
        }

        fn push(&self, event: Event) {
            self.events.borrow_mut().push(event);
        }

        fn maybe_fail(&self, event: &Event) -> io::Result<()> {
            if self.fail_operation.as_ref() == Some(event) {
                Err(io::Error::other("injected operation failure"))
            } else {
                Ok(())
            }
        }

        fn evidence(kind: DescriptorKind) -> DescriptorEvidence {
            let (file_type, inode, mode) = match kind {
                DescriptorKind::ProcRoot => (FileType::Directory, 10, 0o040_555),
                DescriptorKind::All => (FileType::RegularFile, 11, 0o100_644),
                DescriptorKind::Default => (FileType::RegularFile, 12, 0o100_644),
            };
            DescriptorEvidence {
                file_type,
                device: 9,
                inode,
                owner_uid: 0,
                mode,
            }
        }

        fn assert_closed(&self) {
            assert_eq!(self.opened, self.closed, "every mock descriptor must close");
        }
    }

    impl ForwardingBootstrapKernel for MockKernel {
        type Descriptor = MockDescriptor;

        fn checkpoint(
            &mut self,
            _deadline: HardDeadline,
        ) -> Result<(), Ipv6ForwardingBootstrapError> {
            self.push(Event::Checkpoint);
            self.checkpoint_count += 1;
            if self.fail_checkpoint == Some(self.checkpoint_count) {
                Err(Ipv6ForwardingBootstrapError::Deadline)
            } else {
                Ok(())
            }
        }

        fn effective_uid(&mut self) -> u32 {
            self.push(Event::EffectiveUid);
            self.uid
        }

        fn current_network_namespace(&mut self) -> io::Result<NetworkNamespaceIdentity> {
            let event = Event::CurrentNamespace;
            self.push(event.clone());
            self.maybe_fail(&event)?;
            Ok(self.current_namespace)
        }

        fn open_proc_root(&mut self) -> io::Result<Self::Descriptor> {
            self.open(DescriptorKind::ProcRoot)
        }

        fn open_forwarding(
            &mut self,
            _proc_root: &Self::Descriptor,
            knob: ForwardingKnob,
        ) -> io::Result<Self::Descriptor> {
            self.open(match knob {
                ForwardingKnob::All => DescriptorKind::All,
                ForwardingKnob::Default => DescriptorKind::Default,
            })
        }

        fn filesystem_magic(&mut self, descriptor: &Self::Descriptor) -> io::Result<i128> {
            let event = Event::FilesystemMagic(descriptor.kind);
            self.push(event.clone());
            self.maybe_fail(&event)?;
            Ok(self
                .magic_override
                .filter(|(kind, _)| *kind == descriptor.kind)
                .map_or(PROC_SUPER_MAGIC, |(_, magic)| magic))
        }

        fn descriptor_evidence(
            &mut self,
            descriptor: &Self::Descriptor,
        ) -> io::Result<DescriptorEvidence> {
            let event = Event::Evidence(descriptor.kind);
            self.push(event.clone());
            self.maybe_fail(&event)?;
            Ok(self
                .evidence_override
                .filter(|(kind, _)| *kind == descriptor.kind)
                .map_or_else(|| Self::evidence(descriptor.kind), |(_, evidence)| evidence))
        }

        fn read_at_zero(
            &mut self,
            descriptor: &Self::Descriptor,
            bytes: &mut [u8; FORWARDING_READ_BOUND],
        ) -> io::Result<usize> {
            let event = Event::Read(descriptor.kind);
            self.push(event.clone());
            self.maybe_fail(&event)?;
            let value = match descriptor.kind {
                DescriptorKind::All => self.all_reads.pop_front(),
                DescriptorKind::Default => self.default_reads.pop_front(),
                DescriptorKind::ProcRoot => None,
            }
            .ok_or_else(|| io::Error::other("missing mock read"))?;
            let length = value.len().min(bytes.len());
            bytes[..length].copy_from_slice(&value[..length]);
            Ok(value.len())
        }

        fn write_enabled(&mut self, _descriptor: &Self::Descriptor) -> io::Result<usize> {
            self.push(Event::Write);
            self.writes += 1;
            self.write_result.as_ref().map_or_else(
                |error| Err(io::Error::new(error.kind(), "injected write")),
                |n| Ok(*n),
            )
        }

        fn close_descriptor(&mut self, descriptor: Self::Descriptor) {
            self.push(Event::Close(descriptor.kind));
            self.closed += 1;
        }
    }

    impl MockKernel {
        fn open(&mut self, kind: DescriptorKind) -> io::Result<MockDescriptor> {
            let event = Event::Open(kind);
            self.push(event.clone());
            self.maybe_fail(&event)?;
            self.opened += 1;
            Ok(MockDescriptor { kind })
        }
    }

    fn deadline() -> HardDeadline {
        HardDeadline::after(Duration::from_secs(30)).expect("test deadline")
    }

    fn parent_namespace() -> NetworkNamespaceIdentity {
        NetworkNamespaceIdentity::fixture(5, 6)
    }

    fn worker_namespace() -> NetworkNamespaceIdentity {
        NetworkNamespaceIdentity::fixture(7, 8)
    }

    fn enable_with_mock(
        kernel: &mut MockKernel,
        deadline: HardDeadline,
    ) -> Result<(), Ipv6ForwardingBootstrapError> {
        enable_ipv6_forwarding_with_kernel(kernel, parent_namespace(), worker_namespace(), deadline)
    }

    #[test]
    fn disabled_state_gets_one_global_write_and_exact_dual_readback() {
        let mut kernel = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
        assert!(enable_with_mock(&mut kernel, deadline()).is_ok());
        assert_eq!(kernel.writes, 1);
        assert_eq!(
            kernel
                .events
                .borrow()
                .iter()
                .filter(|event| **event == Event::Write)
                .count(),
            1
        );
        assert_eq!(
            kernel
                .events
                .borrow()
                .iter()
                .rev()
                .take(7)
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                Event::Checkpoint,
                Event::Close(DescriptorKind::ProcRoot),
                Event::Checkpoint,
                Event::Close(DescriptorKind::All),
                Event::Checkpoint,
                Event::Close(DescriptorKind::Default),
                Event::Checkpoint,
            ]
        );
        kernel.assert_closed();
    }

    #[test]
    fn fully_enabled_state_is_read_only_while_inconsistent_state_is_reconciled_once() {
        for (all, default, expected_writes) in [
            (
                FORWARDING_ENABLED.as_slice(),
                FORWARDING_ENABLED.as_slice(),
                0,
            ),
            (
                FORWARDING_ENABLED.as_slice(),
                FORWARDING_DISABLED.as_slice(),
                1,
            ),
            (
                FORWARDING_DISABLED.as_slice(),
                FORWARDING_ENABLED.as_slice(),
                1,
            ),
        ] {
            let mut kernel = MockKernel::successful(all, default);
            assert!(enable_with_mock(&mut kernel, deadline()).is_ok());
            assert_eq!(kernel.writes, expected_writes);
            kernel.assert_closed();
        }
    }

    #[test]
    fn identity_and_namespace_checks_precede_every_procfs_operation() {
        let mut non_root = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
        non_root.uid = 1_000;
        assert!(matches!(
            enable_with_mock(&mut non_root, deadline()),
            Err(Ipv6ForwardingBootstrapError::Authentication)
        ));
        assert!(
            !non_root
                .events
                .borrow()
                .iter()
                .any(|event| matches!(event, Event::Open(_)))
        );

        let mut parent = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
        parent.current_namespace = parent_namespace();
        assert!(matches!(
            enable_with_mock(&mut parent, deadline()),
            Err(Ipv6ForwardingBootstrapError::NamespaceEvidence)
        ));
        assert!(
            !parent
                .events
                .borrow()
                .iter()
                .any(|event| matches!(event, Event::Open(_)))
        );

        let mut third = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
        third.current_namespace = NetworkNamespaceIdentity::fixture(9, 10);
        assert!(matches!(
            enable_with_mock(&mut third, deadline()),
            Err(Ipv6ForwardingBootstrapError::NamespaceEvidence)
        ));
        assert!(
            !third
                .events
                .borrow()
                .iter()
                .any(|event| matches!(event, Event::Open(_)))
        );
    }

    #[test]
    fn every_noncanonical_initial_or_readback_value_fails_closed() {
        for invalid in [
            b"".as_slice(),
            b"1".as_slice(),
            b"2\n".as_slice(),
            b"1\nx".as_slice(),
        ] {
            let mut invalid_all = MockKernel::successful(invalid, FORWARDING_DISABLED);
            assert!(matches!(
                enable_with_mock(&mut invalid_all, deadline()),
                Err(Ipv6ForwardingBootstrapError::NonCanonical)
            ));
            assert_eq!(invalid_all.writes, 0);
            invalid_all.assert_closed();

            let mut invalid_default = MockKernel::successful(FORWARDING_DISABLED, invalid);
            assert!(matches!(
                enable_with_mock(&mut invalid_default, deadline()),
                Err(Ipv6ForwardingBootstrapError::NonCanonical)
            ));
            assert_eq!(invalid_default.writes, 0);
            invalid_default.assert_closed();
        }

        for kind in [DescriptorKind::All, DescriptorKind::Default] {
            let mut kernel = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
            let reads = if kind == DescriptorKind::All {
                &mut kernel.all_reads
            } else {
                &mut kernel.default_reads
            };
            reads.pop_back();
            reads.push_back(FORWARDING_DISABLED.to_vec());
            assert!(matches!(
                enable_with_mock(&mut kernel, deadline()),
                Err(Ipv6ForwardingBootstrapError::MutationAmbiguous)
            ));
            assert_eq!(kernel.writes, 1);
            kernel.assert_closed();
        }
    }

    #[test]
    fn unsafe_procfs_evidence_is_rejected_before_any_write() {
        for kind in [
            DescriptorKind::ProcRoot,
            DescriptorKind::All,
            DescriptorKind::Default,
        ] {
            let mut wrong_magic = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
            wrong_magic.magic_override = Some((kind, 0));
            assert!(matches!(
                enable_with_mock(&mut wrong_magic, deadline()),
                Err(Ipv6ForwardingBootstrapError::ProcfsEvidence)
            ));
            assert_eq!(wrong_magic.writes, 0);
            wrong_magic.assert_closed();

            for evidence in [
                DescriptorEvidence {
                    owner_uid: 1,
                    ..MockKernel::evidence(kind)
                },
                DescriptorEvidence {
                    inode: 0,
                    ..MockKernel::evidence(kind)
                },
                DescriptorEvidence {
                    mode: MockKernel::evidence(kind).mode | 0o022,
                    ..MockKernel::evidence(kind)
                },
            ] {
                let mut kernel = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
                kernel.evidence_override = Some((kind, evidence));
                assert!(matches!(
                    enable_with_mock(&mut kernel, deadline()),
                    Err(Ipv6ForwardingBootstrapError::ProcfsEvidence)
                ));
                assert_eq!(kernel.writes, 0);
                kernel.assert_closed();
            }
        }
    }

    #[test]
    fn every_filesystem_operation_failure_closes_prior_descriptors_without_writing_twice() {
        let operations = [
            Event::CurrentNamespace,
            Event::Open(DescriptorKind::ProcRoot),
            Event::FilesystemMagic(DescriptorKind::ProcRoot),
            Event::Evidence(DescriptorKind::ProcRoot),
            Event::Open(DescriptorKind::All),
            Event::FilesystemMagic(DescriptorKind::All),
            Event::Evidence(DescriptorKind::All),
            Event::Open(DescriptorKind::Default),
            Event::FilesystemMagic(DescriptorKind::Default),
            Event::Evidence(DescriptorKind::Default),
            Event::Read(DescriptorKind::All),
            Event::Read(DescriptorKind::Default),
        ];
        for operation in operations {
            let mut kernel = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
            kernel.fail_operation = Some(operation);
            assert!(enable_with_mock(&mut kernel, deadline()).is_err());
            assert!(kernel.writes <= 1);
            kernel.assert_closed();
        }
    }

    #[test]
    fn partial_or_failed_sole_write_is_ambiguous_and_never_retried() {
        for result in [Ok(0), Ok(1), Err(io::Error::other("write failure"))] {
            let mut kernel = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
            kernel.write_result = result;
            assert!(matches!(
                enable_with_mock(&mut kernel, deadline()),
                Err(Ipv6ForwardingBootstrapError::MutationAmbiguous)
            ));
            assert_eq!(kernel.writes, 1);
            kernel.assert_closed();
        }
    }

    #[test]
    fn every_deadline_checkpoint_fails_without_leaking_or_repeating_mutation() {
        let mut baseline = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
        assert!(enable_with_mock(&mut baseline, deadline()).is_ok());
        let checkpoints = baseline.checkpoint_count;
        assert!(checkpoints > 0);

        for failed in 1..=checkpoints {
            let mut kernel = MockKernel::successful(FORWARDING_DISABLED, FORWARDING_DISABLED);
            kernel.fail_checkpoint = Some(failed);
            assert!(matches!(
                enable_with_mock(&mut kernel, deadline()),
                Err(Ipv6ForwardingBootstrapError::Deadline)
            ));
            assert!(kernel.writes <= 1);
            kernel.assert_closed();
        }
    }
}
