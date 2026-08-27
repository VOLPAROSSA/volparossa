//! Fail-closed systemd descriptor-store startup boundary.
//!
//! Debian 13 systemd may return descriptor-store entries to the service on restart. The current
//! production recovery executor cannot consume those entries yet, so the executable bootstrap
//! transfers one affine snapshot of the exact inherited descriptor range before any thread or
//! worker can be created. This module consumes that snapshot, canonicalises each pair into typed
//! pidfd/network-namespace ownership, validates identity separation and the exact bounded naming
//! shape, and then refuses to publish the helper socket while any bundle exists.
//! This prevents inherited recovery capability from being silently ignored or leaked into a
//! child. A later slice must additionally prove durable-journal binding and exact cleanup before it
//! may replace the final refusal with recovery.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fmt, io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};

use crate::systemd_fdstore::{BorrowedCustodyPair, CustodyDescriptorBinding, CustodyFdName};

const DESCRIPTORS_PER_CUSTODY_BUNDLE: usize = 2;
const MAX_WORKER_CUSTODY_BUNDLES: usize = 64;
const MAX_INHERITED_CUSTODY_DESCRIPTORS: usize =
    DESCRIPTORS_PER_CUSTODY_BUNDLE * MAX_WORKER_CUSTODY_BUNDLES;
const PID_FS_MAGIC: libc::c_long = 0x5049_4446;
pub(super) const CUSTODY_FD_NAME_PREFIX: &str = "volparossa-custody-v1-";
const CUSTODY_FD_NAME_DIGEST_BYTES: usize = 32;
pub(super) const CUSTODY_FD_NAME_BYTES: usize =
    CUSTODY_FD_NAME_PREFIX.len() + CUSTODY_FD_NAME_DIGEST_BYTES * 2;

#[must_use = "dropping inherited custody releases its exact typed descriptor owners"]
struct InheritedCustodyBundle {
    pidfd: OwnedFd,
    network_namespace: OwnedFd,
    binding: CustodyDescriptorBinding,
}

impl fmt::Debug for InheritedCustodyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InheritedCustodyBundle(<redacted>)")
    }
}

#[must_use = "dropping inherited custody releases every captured descriptor owner"]
struct InheritedCustody {
    bundles: BTreeMap<CustodyFdName, InheritedCustodyBundle>,
}

impl InheritedCustody {
    fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }
}

/// Consume the complete affine systemd startup snapshot into typed custody bundles.
///
/// The audited Linux-UAPI boundary has already taken exact ownership of systemd's raw descriptor
/// range. This crate keeps `unsafe_code = "forbid"`; it only consumes the resulting affine
/// `OwnedFd` set and never reopens or duplicates a descriptor by number.
fn capture_inherited_custody(
    inherited: volparossa_linux_uapi::SystemdListenFdSet,
) -> Result<InheritedCustody, io::Error> {
    let expected_count = inherited.len();
    let (fd_names, received) = inherited.into_parts();
    if received.len() != expected_count {
        return Err(invalid_data("inherited descriptor count changed"));
    }
    if expected_count == 0 {
        if fd_names.is_some() {
            return Err(invalid_data("absent descriptor names are inconsistent"));
        }
        return Ok(InheritedCustody {
            bundles: BTreeMap::new(),
        });
    }

    let fd_names = fd_names
        .as_deref()
        .ok_or_else(|| invalid_data("inherited descriptor names are absent"))?;
    let names = advertised_descriptor_names_from(fd_names, expected_count)?;
    let entries = names
        .into_iter()
        .zip(received)
        .map(|(name, descriptor)| (Some(name), descriptor))
        .collect::<Vec<_>>();
    validate_inherited_custody(entries.len(), entries)
}

/// Refuse inherited custody until the production restart reaper can consume it exactly.
pub(crate) fn refuse_unrecoverable_inherited_custody(
    inherited: volparossa_linux_uapi::SystemdListenFdSet,
) -> Result<(), io::Error> {
    let custody = capture_inherited_custody(inherited)?;
    refuse_unrecoverable_custody(&custody)
}

fn refuse_unrecoverable_custody(custody: &InheritedCustody) -> Result<(), io::Error> {
    if custody.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restart custody exists but no production recovery executor is installed",
        ))
    }
}

#[cfg(test)]
pub(crate) fn refuse_empty_inherited_custody_for_test() -> Result<(), io::Error> {
    refuse_unrecoverable_custody(&InheritedCustody {
        bundles: BTreeMap::new(),
    })
}

fn advertised_descriptor_names_from(
    fd_names: &OsStr,
    count: usize,
) -> Result<Vec<CustodyFdName>, io::Error> {
    if count == 0
        || count > MAX_INHERITED_CUSTODY_DESCRIPTORS
        || count % DESCRIPTORS_PER_CUSTODY_BUNDLE != 0
    {
        return Err(invalid_data("systemd descriptor count is invalid"));
    }
    let names = fd_names
        .to_str()
        .ok_or_else(|| invalid_data("systemd descriptor names are not UTF-8"))?;
    let expected_name_bytes = count
        .checked_mul(CUSTODY_FD_NAME_BYTES)
        .and_then(|bytes| bytes.checked_add(count - 1))
        .ok_or_else(|| invalid_data("systemd descriptor names are invalid"))?;
    if names.len() != expected_name_bytes {
        return Err(invalid_data("systemd descriptor names are invalid"));
    }
    let mut parsed = Vec::with_capacity(count);
    for name in names.split(':') {
        if parsed.len() == count {
            return Err(invalid_data("systemd descriptor names are invalid"));
        }
        parsed.push(
            CustodyFdName::parse(name)
                .map_err(|_| invalid_data("systemd descriptor names are invalid"))?,
        );
    }
    if parsed.len() != count {
        return Err(invalid_data("systemd descriptor names are invalid"));
    }
    Ok(parsed)
}

fn validate_inherited_custody(
    expected_count: usize,
    entries: Vec<(Option<CustodyFdName>, OwnedFd)>,
) -> Result<InheritedCustody, io::Error> {
    if expected_count == 0
        || expected_count > MAX_INHERITED_CUSTODY_DESCRIPTORS
        || entries.len() != expected_count
    {
        return Err(invalid_data("inherited descriptor count changed"));
    }
    let mut grouped = BTreeMap::<CustodyFdName, Vec<OwnedFd>>::new();
    for (name, descriptor) in entries {
        fcntl(&descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|_| invalid_data("inherited descriptor flags could not be sealed"))?;
        let name = name.ok_or_else(|| invalid_data("inherited descriptor name is invalid"))?;
        grouped.entry(name).or_default().push(descriptor);
    }
    let mut bundles = BTreeMap::new();
    let mut observed_bindings = Vec::<CustodyDescriptorBinding>::new();
    for (name, descriptors) in grouped {
        let descriptors: [OwnedFd; DESCRIPTORS_PER_CUSTODY_BUNDLE] = descriptors
            .try_into()
            .map_err(|_| invalid_data("inherited custody bundle is incomplete"))?;
        let bundle = InheritedCustodyBundle::from_unordered(descriptors)?;
        bundle.verify_retained_binding()?;
        if observed_bindings
            .iter()
            .any(|binding| binding.overlaps(&bundle.binding))
        {
            return Err(invalid_data(
                "inherited custody descriptor identity is reused",
            ));
        }
        observed_bindings.push(bundle.binding.clone());
        bundles.insert(name, bundle);
    }
    if bundles.len() > MAX_WORKER_CUSTODY_BUNDLES
        || bundles.len() * DESCRIPTORS_PER_CUSTODY_BUNDLE != expected_count
    {
        return Err(invalid_data("inherited custody bundle count is invalid"));
    }
    Ok(InheritedCustody { bundles })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InheritedDescriptorRole {
    Pidfd,
    NetworkNamespace,
}

impl InheritedCustodyBundle {
    fn from_unordered(
        descriptors: [OwnedFd; DESCRIPTORS_PER_CUSTODY_BUNDLE],
    ) -> Result<Self, io::Error> {
        let [first, second] = descriptors;
        let first_role = inherited_descriptor_role(first.as_fd())?;
        let second_role = inherited_descriptor_role(second.as_fd())?;
        let (pidfd, network_namespace) = match (first_role, second_role) {
            (InheritedDescriptorRole::Pidfd, InheritedDescriptorRole::NetworkNamespace) => {
                (first, second)
            }
            (InheritedDescriptorRole::NetworkNamespace, InheritedDescriptorRole::Pidfd) => {
                (second, first)
            }
            _ => {
                return Err(invalid_data(
                    "inherited custody roles are incomplete or ambiguous",
                ));
            }
        };
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .map_err(|_| invalid_data("inherited custody descriptors are duplicated"))?;
        let binding = CustodyDescriptorBinding::from_custody(custody)
            .map_err(|_| invalid_data("inherited custody descriptor identity is invalid"))?;
        Ok(Self {
            pidfd,
            network_namespace,
            binding,
        })
    }

    fn verify_retained_binding(&self) -> Result<(), io::Error> {
        let custody = BorrowedCustodyPair::new(self.pidfd.as_fd(), self.network_namespace.as_fd())
            .map_err(|_| invalid_data("inherited custody descriptors are duplicated"))?;
        let observed = CustodyDescriptorBinding::from_custody(custody)
            .map_err(|_| invalid_data("inherited custody descriptor identity is invalid"))?;
        if observed == self.binding {
            Ok(())
        } else {
            Err(invalid_data(
                "inherited custody descriptor identity changed",
            ))
        }
    }
}

fn inherited_descriptor_role(
    descriptor: BorrowedFd<'_>,
) -> Result<InheritedDescriptorRole, io::Error> {
    let pidfd = rustix::fs::fstatfs(descriptor).map_err(rustix_io)?.f_type == PID_FS_MAGIC;
    if pidfd {
        return Ok(InheritedDescriptorRole::Pidfd);
    }
    match volparossa_linux_uapi::namespace_type(&descriptor) {
        Ok(namespace_type) if namespace_type == libc::CLONE_NEWNET => {
            Ok(InheritedDescriptorRole::NetworkNamespace)
        }
        Ok(_) | Err(_) => Err(invalid_data(
            "inherited descriptor has no unique custody role",
        )),
    }
}

pub(super) fn custody_fd_name_is_valid(value: &str) -> bool {
    value.len() == CUSTODY_FD_NAME_BYTES
        && value
            .strip_prefix(CUSTODY_FD_NAME_PREFIX)
            .is_some_and(|digest| {
                digest
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn rustix_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        fs::File,
        os::fd::{AsRawFd, OwnedFd},
        os::unix::ffi::OsStringExt,
        process::Command,
    };

    use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
    use rustix::process::{PidfdFlags, getpid, pidfd_open};
    use tempfile::tempfile;

    use super::*;

    fn descriptor() -> OwnedFd {
        tempfile().expect("create descriptor fixture").into()
    }

    fn pidfd() -> OwnedFd {
        pidfd_open(getpid(), PidfdFlags::empty()).expect("open current-process pidfd")
    }

    fn network_namespace() -> OwnedFd {
        File::open("/proc/self/ns/net")
            .expect("open current network namespace")
            .into()
    }

    fn custody_name(seed: u8) -> String {
        format!("{CUSTODY_FD_NAME_PREFIX}{seed:064x}")
    }

    fn typed_custody_name(seed: u8) -> CustodyFdName {
        CustodyFdName::parse(&custody_name(seed)).expect("valid typed custody name")
    }

    #[test]
    fn descriptor_names_require_an_even_bounded_exact_shape() {
        for (names, count) in [
            (OsString::new(), 0),
            (custody_name(1).into(), 1),
            (custody_name(1).into(), 2),
            (
                format!(
                    "{}:{}:{}",
                    custody_name(1),
                    custody_name(1),
                    custody_name(1)
                )
                .into(),
                2,
            ),
            ("x".repeat(16 * 1_024).into(), 2),
            (
                std::iter::repeat_n(custody_name(2), 129)
                    .collect::<Vec<_>>()
                    .join(":")
                    .into(),
                129,
            ),
        ] {
            assert!(advertised_descriptor_names_from(&names, count).is_err());
        }
        let non_utf8 = OsString::from_vec(vec![0xff; CUSTODY_FD_NAME_BYTES * 2 + 1]);
        assert!(advertised_descriptor_names_from(&non_utf8, 2).is_err());
    }

    #[test]
    fn custody_names_are_fixed_lowercase_opaque_digests() {
        assert!(custody_fd_name_is_valid(&custody_name(1)));
        assert!(!custody_fd_name_is_valid("volparossa-custody-v1-secret"));
        assert!(!custody_fd_name_is_valid(&format!(
            "{CUSTODY_FD_NAME_PREFIX}{}",
            "A".repeat(64)
        )));
        assert!(!custody_fd_name_is_valid(&format!(
            "{CUSTODY_FD_NAME_PREFIX}{}",
            "0".repeat(63)
        )));
        let names = format!("{}:{}", custody_name(1), custody_name(1));
        let parsed = advertised_descriptor_names_from(OsStr::new(&names), 2)
            .expect("parse exact fixed names");
        assert_eq!(parsed, vec![typed_custody_name(1); 2]);
        assert_eq!(format!("{:?}", parsed[0]), "CustodyFdName(<redacted>)");
    }

    #[test]
    fn descriptor_advertisement_bounds_are_exact() {
        let one_name = custody_name(1);
        assert!(advertised_descriptor_names_from(OsStr::new(&one_name), 1).is_err());

        let maximum_names = std::iter::repeat_n(custody_name(2), 128)
            .collect::<Vec<_>>()
            .join(":");
        let parsed = advertised_descriptor_names_from(OsStr::new(&maximum_names), 128)
            .expect("parse maximum descriptor count");
        assert_eq!(parsed.len(), 128);

        let excessive_names = std::iter::repeat_n(custody_name(3), 129)
            .collect::<Vec<_>>()
            .join(":");
        assert!(advertised_descriptor_names_from(OsStr::new(&excessive_names), 129).is_err());
    }

    #[test]
    fn exact_pidfd_and_network_namespace_are_canonicalised_and_sealed() {
        let network_namespace = network_namespace();
        let pidfd = pidfd();
        fcntl(&network_namespace, FcntlArg::F_SETFD(FdFlag::empty()))
            .expect("clear namespace CLOEXEC");
        fcntl(&pidfd, FcntlArg::F_SETFD(FdFlag::empty())).expect("clear pidfd CLOEXEC");
        let custody = validate_inherited_custody(
            2,
            vec![
                (Some(typed_custody_name(1)), network_namespace),
                (Some(typed_custody_name(1)), pidfd),
            ],
        )
        .expect("adopt exact custody bundle");
        assert_eq!(custody.bundles.len(), 1);
        let bundle = custody.bundles.values().next().expect("custody pair");
        assert_eq!(
            inherited_descriptor_role(bundle.pidfd.as_fd()).expect("pidfd role"),
            InheritedDescriptorRole::Pidfd
        );
        assert_eq!(
            inherited_descriptor_role(bundle.network_namespace.as_fd()).expect("namespace role"),
            InheritedDescriptorRole::NetworkNamespace
        );
        assert_eq!(format!("{bundle:?}"), "InheritedCustodyBundle(<redacted>)");
        assert_eq!(
            format!("{:?}", &bundle.binding),
            "CustodyDescriptorBinding(<redacted>)"
        );
        let reread = CustodyDescriptorBinding::from_custody(
            BorrowedCustodyPair::new(bundle.pidfd.as_fd(), bundle.network_namespace.as_fd())
                .expect("role-ordered custody"),
        )
        .expect("re-read retained descriptor identities");
        assert_eq!(bundle.binding, reread);
        for descriptor in [&bundle.pidfd, &bundle.network_namespace] {
            let flags = FdFlag::from_bits_truncate(
                fcntl(descriptor.as_fd(), FcntlArg::F_GETFD).expect("read descriptor flags"),
            );
            assert_eq!(flags, FdFlag::FD_CLOEXEC);
        }
    }

    #[test]
    fn bundle_retains_exact_owner_numbers_in_both_orders() {
        for reversed in [false, true] {
            let pidfd = pidfd();
            let network_namespace = network_namespace();
            let source_numbers = [pidfd.as_raw_fd(), network_namespace.as_raw_fd()];
            let entries = if reversed {
                vec![network_namespace, pidfd]
            } else {
                vec![pidfd, network_namespace]
            };
            let custody = validate_inherited_custody(
                2,
                entries
                    .into_iter()
                    .map(|descriptor| (Some(typed_custody_name(7)), descriptor))
                    .collect(),
            )
            .expect("adopt exact source owners");
            let bundle = custody.bundles.values().next().expect("captured pair");
            let mut retained_numbers = [
                bundle.pidfd.as_raw_fd(),
                bundle.network_namespace.as_raw_fd(),
            ];
            let mut expected_numbers = source_numbers;
            retained_numbers.sort_unstable();
            expected_numbers.sort_unstable();
            assert_eq!(retained_numbers, expected_numbers);
            bundle
                .verify_retained_binding()
                .expect("captured role binding remains exact");

            let error = refuse_unrecoverable_custody(&custody)
                .expect_err("non-empty inherited custody must block startup");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn descriptor_roles_are_kernel_typed_and_ambiguous_pairs_fail_closed() {
        assert_eq!(
            inherited_descriptor_role(pidfd().as_fd()).expect("pidfd type"),
            InheritedDescriptorRole::Pidfd
        );
        assert_eq!(
            inherited_descriptor_role(network_namespace().as_fd()).expect("netns type"),
            InheritedDescriptorRole::NetworkNamespace
        );
        assert!(inherited_descriptor_role(descriptor().as_fd()).is_err());
        assert!(
            inherited_descriptor_role(
                File::open("/proc/self/ns/user")
                    .expect("open wrong namespace type")
                    .as_fd()
            )
            .is_err()
        );

        for entries in [
            vec![pidfd(), pidfd()],
            vec![network_namespace(), network_namespace()],
            vec![pidfd(), descriptor()],
            vec![descriptor(), network_namespace()],
        ] {
            assert!(
                validate_inherited_custody(
                    2,
                    entries
                        .into_iter()
                        .map(|descriptor| (Some(typed_custody_name(1)), descriptor))
                        .collect(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn exited_process_descriptor_remains_typed_as_pidfd() {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn short-lived child");
        let pidfd = pidfd_open(
            rustix::process::Pid::from_child(&child),
            PidfdFlags::empty(),
        )
        .expect("pin short-lived child");
        assert!(child.wait().expect("reap child").success());
        assert_eq!(
            inherited_descriptor_role(pidfd.as_fd()).expect("exited pidfd type"),
            InheritedDescriptorRole::Pidfd
        );
    }

    #[test]
    fn descriptor_identity_cannot_be_reused_across_custody_names() {
        let first_pidfd = pidfd();
        let first_namespace = network_namespace();
        let second_pidfd = pidfd();
        let second_namespace = network_namespace();
        for alias in [&second_pidfd, &second_namespace] {
            let flags = OFlag::from_bits_truncate(
                fcntl(alias, FcntlArg::F_GETFL).expect("read alias status flags"),
            );
            fcntl(alias, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
                .expect("set different alias status flags");
        }
        let result = validate_inherited_custody(
            4,
            vec![
                (Some(typed_custody_name(1)), first_pidfd),
                (Some(typed_custody_name(1)), first_namespace),
                (Some(typed_custody_name(2)), second_pidfd),
                (Some(typed_custody_name(2)), second_namespace),
            ],
        );
        let Err(error) = result else {
            panic!("cross-name descriptor identity reuse was accepted");
        };
        assert_eq!(
            error.to_string(),
            "inherited custody descriptor identity is reused"
        );
    }

    #[test]
    fn partial_duplicate_and_unnamed_bundles_fail_closed() {
        assert!(
            validate_inherited_custody(1, vec![(Some(typed_custody_name(1)), descriptor())])
                .is_err()
        );
        assert!(
            validate_inherited_custody(
                4,
                vec![
                    (Some(typed_custody_name(1)), descriptor()),
                    (Some(typed_custody_name(1)), descriptor()),
                    (Some(typed_custody_name(1)), descriptor()),
                    (Some(typed_custody_name(2)), descriptor()),
                ],
            )
            .is_err()
        );
        assert!(
            validate_inherited_custody(2, vec![(None, descriptor()), (None, descriptor())],)
                .is_err()
        );
    }
}
