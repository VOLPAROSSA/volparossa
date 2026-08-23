use std::{
    fs::File,
    io::{self, Read as _},
    os::fd::OwnedFd,
    process::Child,
};

use nix::poll::{PollFd, PollFlags, poll};
use rustix::{
    fd::AsFd,
    fs::{Mode, OFlags, open, openat},
    process::{Pid, PidfdFlags, pidfd_open},
};
use thiserror::Error;

use crate::namespace::{NamespacePins, NamespaceSnapshot};

const MAXIMUM_PROC_RECORD_BYTES: usize = 16 * 1024;

pub(crate) struct LauncherKernelPins {
    pidfd: OwnedFd,
    process_directory: OwnedFd,
    namespaces: Option<NamespacePins>,
    process_id: u32,
    expected_parent: Option<u32>,
}

#[derive(Debug, Error)]
pub(crate) enum MappingInstallError {
    #[error("launcher liveness preflight failed: {0}")]
    Preflight(#[source] io::Error),
    #[error("setgroups policy installation failed: {0}")]
    Setgroups(#[source] io::Error),
    #[error("UID namespace mapping installation failed: {0}")]
    UserMap(#[source] io::Error),
    #[error("GID namespace mapping installation failed: {0}")]
    GroupMap(#[source] io::Error),
    #[error("namespace mapping readback failed: {0}")]
    Readback(#[source] io::Error),
}

impl MappingInstallError {
    pub(crate) fn is_policy_denial(&self) -> bool {
        matches!(
            self,
            Self::Setgroups(error) | Self::UserMap(error) | Self::GroupMap(error)
                if error.kind() == io::ErrorKind::PermissionDenied
        )
    }

    pub(crate) fn into_io(self) -> io::Error {
        let kind = match &self {
            Self::Preflight(error)
            | Self::Setgroups(error)
            | Self::UserMap(error)
            | Self::GroupMap(error)
            | Self::Readback(error) => error.kind(),
        };
        io::Error::new(kind, self)
    }
}

impl LauncherKernelPins {
    pub(crate) fn pin_child(child: &Child) -> io::Result<Self> {
        let process_id = child.id();
        let pidfd = pidfd_open(Pid::from_child(child), PidfdFlags::empty()).map_err(rustix_io)?;
        let process_directory = open(
            format!("/proc/{process_id}"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(rustix_io)?;
        Ok(Self {
            pidfd,
            process_directory,
            namespaces: None,
            process_id,
            expected_parent: None,
        })
    }

    pub(crate) fn ensure_alive(&self) -> io::Result<()> {
        let mut descriptors = [PollFd::new(self.pidfd.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut descriptors, 0_u8).map_err(errno_io)?;
        if ready == 0
            && descriptors[0]
                .revents()
                .is_none_or(|events| events.is_empty())
        {
            Ok(())
        } else {
            Err(invalid_data("fixed launcher is no longer alive"))
        }
    }

    pub(crate) fn pin_isolated_namespaces(
        &mut self,
        host: NamespaceSnapshot,
        expected_parent: u32,
    ) -> io::Result<NamespaceSnapshot> {
        if self.namespaces.is_some() {
            return Err(invalid_data("launcher namespaces were already pinned"));
        }
        self.ensure_alive()?;
        verify_process_status(
            &read_proc_file(&self.process_directory, "status")?,
            self.process_id,
            expected_parent,
        )?;
        let namespaces = NamespacePins::pin_process(&self.process_directory)?;
        let snapshot = namespaces.snapshot();
        if !snapshot.is_isolated_launcher_from(host)
            || !namespaces.matches_process_membership(&self.process_directory)?
        {
            return Err(invalid_data(
                "launcher namespace identities do not match isolated bootstrap",
            ));
        }
        self.ensure_alive()?;
        self.namespaces = Some(namespaces);
        self.expected_parent = Some(expected_parent);
        Ok(snapshot)
    }

    pub(crate) fn write_single_extent_mappings(
        &self,
        outer_user_id: u32,
        outer_group_id: u32,
    ) -> Result<(), MappingInstallError> {
        self.ensure_alive()
            .map_err(MappingInstallError::Preflight)?;
        write_proc_file_once(&self.process_directory, "setgroups", b"deny\n")
            .map_err(MappingInstallError::Setgroups)?;
        write_proc_file_once(
            &self.process_directory,
            "uid_map",
            format!("0 {outer_user_id} 1\n").as_bytes(),
        )
        .map_err(MappingInstallError::UserMap)?;
        write_proc_file_once(
            &self.process_directory,
            "gid_map",
            format!("0 {outer_group_id} 1\n").as_bytes(),
        )
        .map_err(MappingInstallError::GroupMap)?;
        self.verify_mapping_records(outer_user_id, outer_group_id)
            .map_err(MappingInstallError::Readback)
    }

    pub(crate) fn verify_single_extent_mappings(
        &self,
        outer_user_id: u32,
        outer_group_id: u32,
    ) -> io::Result<()> {
        self.ensure_alive()?;
        self.verify_mapping_records(outer_user_id, outer_group_id)?;
        let Some(namespaces) = &self.namespaces else {
            return Err(invalid_data("launcher namespaces were not pinned"));
        };
        let Some(expected_parent) = self.expected_parent else {
            return Err(invalid_data("launcher parent identity was not pinned"));
        };
        verify_process_status(
            &read_proc_file(&self.process_directory, "status")?,
            self.process_id,
            expected_parent,
        )?;
        if !namespaces.matches_process_membership(&self.process_directory)? {
            return Err(invalid_data("launcher namespace membership changed"));
        }
        self.ensure_alive()
    }

    fn verify_mapping_records(&self, outer_user_id: u32, outer_group_id: u32) -> io::Result<()> {
        if read_proc_file(&self.process_directory, "setgroups")? != b"deny\n"
            || parse_single_extent_map(&read_proc_file(&self.process_directory, "uid_map")?)?
                != (0, outer_user_id, 1)
            || parse_single_extent_map(&read_proc_file(&self.process_directory, "gid_map")?)?
                != (0, outer_group_id, 1)
        {
            return Err(invalid_data(
                "launcher user or group namespace mapping is not canonical",
            ));
        }
        Ok(())
    }
}

pub(crate) fn verify_current_single_extent_mappings(
    outer_user_id: u32,
    outer_group_id: u32,
) -> io::Result<()> {
    let setgroups = read_bounded(File::open("/proc/thread-self/setgroups")?)?;
    let user_map = read_bounded(File::open("/proc/thread-self/uid_map")?)?;
    let group_map = read_bounded(File::open("/proc/thread-self/gid_map")?)?;
    if setgroups != b"deny\n"
        || parse_single_extent_map(&user_map)? != (0, outer_user_id, 1)
        || parse_single_extent_map(&group_map)? != (0, outer_group_id, 1)
    {
        return Err(invalid_data(
            "current user or group namespace mapping is not canonical",
        ));
    }
    Ok(())
}

fn write_proc_file_once<Fd: AsFd>(
    process_directory: Fd,
    name: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let descriptor = openat(
        process_directory,
        name,
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    let written = rustix::io::write(&descriptor, bytes).map_err(rustix_io)?;
    if written == bytes.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "kernel did not consume one complete namespace mapping record",
        ))
    }
}

fn read_proc_file<Fd: AsFd>(process_directory: Fd, name: &str) -> io::Result<Vec<u8>> {
    let descriptor = openat(
        process_directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    read_bounded(File::from(descriptor))
}

fn read_bounded(mut file: File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(MAXIMUM_PROC_RECORD_BYTES.saturating_add(1));
    file.by_ref()
        .take(
            u64::try_from(MAXIMUM_PROC_RECORD_BYTES.saturating_add(1))
                .map_err(|_| invalid_data("proc record read bound does not fit the platform"))?,
        )
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAXIMUM_PROC_RECORD_BYTES {
        return Err(invalid_data("proc record is empty or oversized"));
    }
    Ok(bytes)
}

fn parse_single_extent_map(bytes: &[u8]) -> io::Result<(u32, u32, u32)> {
    if !bytes.ends_with(b"\n") || bytes.contains(&b'\r') || bytes.contains(&0) {
        return Err(invalid_data("namespace mapping framing is invalid"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid_data("namespace mapping is not UTF-8"))?;
    if text.lines().count() != 1 {
        return Err(invalid_data(
            "namespace mapping must contain exactly one extent",
        ));
    }
    let mut fields = text.split_ascii_whitespace();
    let inside = parse_decimal(fields.next())?;
    let outside = parse_decimal(fields.next())?;
    let length = parse_decimal(fields.next())?;
    if fields.next().is_some() {
        return Err(invalid_data("namespace mapping has extra fields"));
    }
    Ok((inside, outside, length))
}

fn parse_decimal(value: Option<&str>) -> io::Result<u32> {
    let Some(value) = value else {
        return Err(invalid_data("namespace mapping field is missing"));
    };
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid_data("namespace mapping decimal is not canonical"));
    }
    value
        .parse()
        .map_err(|_| invalid_data("namespace mapping decimal is out of range"))
}

fn verify_process_status(bytes: &[u8], expected_pid: u32, expected_parent: u32) -> io::Result<()> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid_data("process status is not UTF-8"))?;
    let mut pid = None;
    let mut parent = None;
    let mut threads = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Pid:\t") {
            set_once(&mut pid, parse_decimal(Some(value))?)?;
        } else if let Some(value) = line.strip_prefix("PPid:\t") {
            set_once(&mut parent, parse_decimal(Some(value))?)?;
        } else if let Some(value) = line.strip_prefix("Threads:\t") {
            set_once(&mut threads, parse_decimal(Some(value))?)?;
        }
    }
    if pid == Some(expected_pid) && parent == Some(expected_parent) && threads == Some(1) {
        Ok(())
    } else {
        Err(invalid_data(
            "launcher process identity or task count is invalid",
        ))
    }
}

fn set_once(slot: &mut Option<u32>, value: u32) -> io::Result<()> {
    if slot.replace(value).is_none() {
        Ok(())
    } else {
        Err(invalid_data("proc record duplicated a required field"))
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn rustix_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_parser_accepts_kernel_padding_and_one_canonical_extent() {
        assert_eq!(
            parse_single_extent_map(b"         0       1000          1\n").expect("mapping"),
            (0, 1000, 1)
        );
        assert_eq!(
            parse_single_extent_map(b"0 0 1\n").expect("root mapping"),
            (0, 0, 1)
        );
    }

    #[test]
    fn mapping_parser_rejects_malformed_or_multiple_extents() {
        for value in [
            b"".as_slice(),
            b"0 1000 1",
            b"0 1000 1\r\n",
            b"00 1000 1\n",
            b"0 01000 1\n",
            b"0 1000 01\n",
            b"0 1000 1 extra\n",
            b"0 1000 1\n1 1001 1\n",
            b"0 4294967296 1\n",
            b"\xff\n",
        ] {
            assert!(
                parse_single_extent_map(value).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn process_status_requires_exact_pid_parent_and_single_task() {
        let valid = b"Name:\tfixture\nPid:\t42\nPPid:\t7\nThreads:\t1\n";
        verify_process_status(valid, 42, 7).expect("status");
        assert!(verify_process_status(valid, 41, 7).is_err());
        assert!(verify_process_status(valid, 42, 8).is_err());
        assert!(verify_process_status(b"Pid:\t42\nPPid:\t7\nThreads:\t2\n", 42, 7).is_err());
        assert!(
            verify_process_status(b"Pid:\t42\nPid:\t42\nPPid:\t7\nThreads:\t1\n", 42, 7).is_err()
        );
    }

    #[test]
    fn only_write_stage_permission_denials_are_environmental() {
        for error in [
            MappingInstallError::Setgroups(io::ErrorKind::PermissionDenied.into()),
            MappingInstallError::UserMap(io::ErrorKind::PermissionDenied.into()),
            MappingInstallError::GroupMap(io::ErrorKind::PermissionDenied.into()),
        ] {
            assert!(error.is_policy_denial());
        }
        for error in [
            MappingInstallError::Setgroups(io::Error::from_raw_os_error(
                nix::errno::Errno::EINVAL as i32,
            )),
            MappingInstallError::UserMap(io::ErrorKind::Unsupported.into()),
            MappingInstallError::GroupMap(io::Error::from_raw_os_error(
                nix::errno::Errno::ENOSPC as i32,
            )),
            MappingInstallError::Readback(io::ErrorKind::PermissionDenied.into()),
            MappingInstallError::Preflight(io::ErrorKind::PermissionDenied.into()),
        ] {
            assert!(!error.is_policy_denial());
        }
    }
}
