//! Fail-closed systemd descriptor-store startup boundary.
//!
//! Debian 13 systemd may return descriptor-store entries to the service on restart. The current
//! production recovery executor cannot consume those entries yet, so startup adopts them before
//! any thread or worker can be created, marks every descriptor close-on-exec, validates the exact
//! bounded naming shape, and then refuses to publish the helper socket while any bundle exists.
//! This prevents inherited recovery capability from being silently ignored or leaked into a
//! child. A later slice must additionally prove exact pidfd/netns roles, kernel identity and
//! durable-journal binding before it may replace the final refusal with recovery.

use std::{collections::BTreeMap, env, io, os::fd::OwnedFd};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};

const SYSTEMD_DESCRIPTOR_START: usize = 3;
const DESCRIPTORS_PER_CUSTODY_BUNDLE: usize = 2;
const MAX_WORKER_CUSTODY_BUNDLES: usize = 64;
const MAX_INHERITED_CUSTODY_DESCRIPTORS: usize =
    DESCRIPTORS_PER_CUSTODY_BUNDLE * MAX_WORKER_CUSTODY_BUNDLES;
const CUSTODY_FD_NAME_PREFIX: &str = "volparossa-custody-v1-";
const CUSTODY_FD_NAME_DIGEST_BYTES: usize = 32;
const CUSTODY_FD_NAME_BYTES: usize =
    CUSTODY_FD_NAME_PREFIX.len() + CUSTODY_FD_NAME_DIGEST_BYTES * 2;

struct InheritedCustody {
    bundles: BTreeMap<Box<str>, [OwnedFd; DESCRIPTORS_PER_CUSTODY_BUNDLE]>,
}

impl InheritedCustody {
    fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }
}

/// Adopt all systemd-owned startup descriptors before any production thread can exist.
///
/// The audited Linux-UAPI boundary contains the unavoidable one-shot raw-FD adoption. This crate
/// keeps `unsafe_code = "forbid"`; all validation and ownership after adoption uses `OwnedFd`.
fn capture_inherited_custody() -> Result<InheritedCustody, io::Error> {
    let Some(names) = advertised_descriptor_count()? else {
        return Ok(InheritedCustody {
            bundles: BTreeMap::new(),
        });
    };
    let received = volparossa_linux_uapi::duplicate_systemd_listen_descriptors(names.len())?;
    let entries = names
        .into_iter()
        .zip(received)
        .map(|(name, descriptor)| (Some(name), descriptor))
        .collect::<Vec<_>>();
    validate_inherited_custody(entries.len(), entries)
}

/// Refuse inherited custody until the production restart reaper can consume it exactly.
pub(crate) fn refuse_unrecoverable_inherited_custody() -> Result<(), io::Error> {
    let custody = capture_inherited_custody()?;
    if custody.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restart custody exists but no production recovery executor is installed",
        ))
    }
}

fn advertised_descriptor_count() -> Result<Option<Vec<String>>, io::Error> {
    advertised_descriptor_count_from(
        env::var_os("LISTEN_PID"),
        env::var_os("LISTEN_FDS"),
        env::var_os("LISTEN_FDNAMES"),
        std::process::id(),
    )
}

fn advertised_descriptor_count_from(
    listen_pid: Option<std::ffi::OsString>,
    listen_fds: Option<std::ffi::OsString>,
    listen_fd_names: Option<std::ffi::OsString>,
    current_pid: u32,
) -> Result<Option<Vec<String>>, io::Error> {
    match (listen_pid, listen_fds, listen_fd_names) {
        (None, None, None) => Ok(None),
        (Some(pid), Some(count), Some(names)) => {
            pid.to_str()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| *value == current_pid)
                .ok_or_else(|| invalid_data("systemd descriptor PID binding is invalid"))?;
            let count = count
                .to_str()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|value| {
                    *value > 0
                        && *value <= MAX_INHERITED_CUSTODY_DESCRIPTORS
                        && value.checked_add(SYSTEMD_DESCRIPTOR_START).is_some()
                })
                .ok_or_else(|| invalid_data("systemd descriptor count is invalid"))?;
            let names = names
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
                if parsed.len() == count || !custody_fd_name_is_valid(name) {
                    return Err(invalid_data("systemd descriptor names are invalid"));
                }
                parsed.push(name.to_owned());
            }
            if parsed.len() != count {
                return Err(invalid_data("systemd descriptor names are invalid"));
            }
            Ok(Some(parsed))
        }
        _ => Err(invalid_data("systemd descriptor environment is incomplete")),
    }
}

fn validate_inherited_custody(
    expected_count: usize,
    entries: Vec<(Option<String>, OwnedFd)>,
) -> Result<InheritedCustody, io::Error> {
    if expected_count == 0
        || expected_count > MAX_INHERITED_CUSTODY_DESCRIPTORS
        || entries.len() != expected_count
    {
        return Err(invalid_data("inherited descriptor count changed"));
    }
    let mut grouped = BTreeMap::<String, Vec<OwnedFd>>::new();
    for (name, descriptor) in entries {
        fcntl(&descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|_| invalid_data("inherited descriptor flags could not be sealed"))?;
        let name = name
            .filter(|value| custody_fd_name_is_valid(value))
            .ok_or_else(|| invalid_data("inherited descriptor name is invalid"))?;
        grouped.entry(name).or_default().push(descriptor);
    }
    let mut bundles = BTreeMap::new();
    for (name, descriptors) in grouped {
        let descriptors: [OwnedFd; DESCRIPTORS_PER_CUSTODY_BUNDLE] = descriptors
            .try_into()
            .map_err(|_| invalid_data("inherited custody bundle is incomplete"))?;
        bundles.insert(name.into_boxed_str(), descriptors);
    }
    if bundles.len() > MAX_WORKER_CUSTODY_BUNDLES
        || bundles.len() * DESCRIPTORS_PER_CUSTODY_BUNDLE != expected_count
    {
        return Err(invalid_data("inherited custody bundle count is invalid"));
    }
    Ok(InheritedCustody { bundles })
}

fn custody_fd_name_is_valid(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd, OwnedFd};

    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use tempfile::tempfile;

    use super::*;

    fn descriptor() -> OwnedFd {
        tempfile().expect("create descriptor fixture").into()
    }

    fn custody_name(seed: u8) -> String {
        format!("{CUSTODY_FD_NAME_PREFIX}{seed:064x}")
    }

    #[test]
    fn absent_environment_is_the_only_unmanaged_shape() {
        assert_eq!(
            advertised_descriptor_count_from(None, None, None, 7).expect("absent environment"),
            None
        );
        for malformed in [
            (Some("7".into()), None, None),
            (None, Some("2".into()), Some(custody_name(1).into())),
            (
                Some("8".into()),
                Some("2".into()),
                Some(custody_name(1).into()),
            ),
            (
                Some("7".into()),
                Some("0".into()),
                Some(custody_name(1).into()),
            ),
            (Some("7".into()), Some("2".into()), Some("".into())),
            (
                Some("7".into()),
                Some("2".into()),
                Some(
                    format!(
                        "{}:{}:{}",
                        custody_name(1),
                        custody_name(1),
                        custody_name(1)
                    )
                    .into(),
                ),
            ),
            (
                Some("7".into()),
                Some("1".into()),
                Some("x".repeat(16 * 1_024).into()),
            ),
        ] {
            assert!(
                advertised_descriptor_count_from(malformed.0, malformed.1, malformed.2, 7).is_err()
            );
        }
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
    }

    #[test]
    fn exact_two_descriptor_groups_are_validated_and_sealed() {
        let first = descriptor();
        let second = descriptor();
        fcntl(&first, FcntlArg::F_SETFD(FdFlag::empty())).expect("clear first CLOEXEC");
        fcntl(&second, FcntlArg::F_SETFD(FdFlag::empty())).expect("clear second CLOEXEC");
        let custody = validate_inherited_custody(
            2,
            vec![
                (Some(custody_name(1)), first),
                (Some(custody_name(1)), second),
            ],
        )
        .expect("adopt exact custody bundle");
        assert_eq!(custody.bundles.len(), 1);
        for descriptor in custody.bundles.values().next().expect("custody pair") {
            let flags = FdFlag::from_bits_truncate(
                fcntl(descriptor.as_fd(), FcntlArg::F_GETFD).expect("read descriptor flags"),
            );
            assert_eq!(flags, FdFlag::FD_CLOEXEC);
        }
    }

    #[test]
    fn partial_duplicate_and_unnamed_bundles_fail_closed() {
        assert!(
            validate_inherited_custody(1, vec![(Some(custody_name(1)), descriptor())]).is_err()
        );
        assert!(
            validate_inherited_custody(
                4,
                vec![
                    (Some(custody_name(1)), descriptor()),
                    (Some(custody_name(1)), descriptor()),
                    (Some(custody_name(1)), descriptor()),
                    (Some(custody_name(2)), descriptor()),
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
