use std::{
    fs::File,
    io::{self, Read as _},
    os::fd::OwnedFd,
    process::Child,
};

use nix::poll::{PollFd, PollFlags, poll};
use rustix::{
    fd::AsFd,
    fs::{
        AtFlags, Dir, FileType, Mode, OFlags, PROC_SUPER_MAGIC, ResolveFlags, StatxFlags, fstat,
        fstatfs, open, openat, openat2, statx,
    },
    process::{Pid, PidfdFlags, pidfd_open},
};
use thiserror::Error;

use crate::{
    mounts::{
        MAX_PRIVATE_MOUNTINFO_BYTES, PRIVATE_RUN_INODES, PRIVATE_RUN_MODE, PRIVATE_RUN_SIZE_BYTES,
    },
    namespace::{
        LauncherNamespaceMembership, LauncherNamespacePins, NamespacePins, NamespaceSnapshot,
    },
};

const MAXIMUM_PROC_RECORD_BYTES: usize = 16 * 1024;
const MAXIMUM_DIRECTORY_ENTRIES: usize = 4096;
const TMPFS_SUPER_MAGIC: i128 = 0x0102_1994;

pub(crate) struct LauncherKernelPins {
    pidfd: OwnedFd,
    process_directory: OwnedFd,
    launcher_namespaces: Option<LauncherNamespacePins>,
    namespaces: Option<NamespacePins>,
    process_id: u32,
    expected_parent: Option<u32>,
    host: Option<NamespaceSnapshot>,
}

pub(crate) struct PidOneKernelPins {
    pidfd: OwnedFd,
    process_directory: OwnedFd,
    root_directory: OwnedFd,
    namespaces: NamespacePins,
    process_id: u32,
    launcher_process_id: u32,
    launcher_pid_depth: usize,
}

struct ProcessStatus {
    pid: u32,
    parent: u32,
    threads: u32,
    namespace_pids: Vec<u32>,
}

#[derive(Debug, Error)]
pub(crate) enum MappingInstallError {
    #[error("launcher pre-mapping preflight failed: {0}")]
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
            launcher_namespaces: None,
            namespaces: None,
            process_id,
            expected_parent: None,
            host: None,
        })
    }

    pub(crate) fn ensure_alive(&self) -> io::Result<()> {
        ensure_pidfd_alive(&self.pidfd, "fixed launcher is no longer alive")
    }

    pub(crate) fn pin_launcher_before_pid_one(
        &mut self,
        host: NamespaceSnapshot,
        expected_parent: u32,
    ) -> io::Result<LauncherNamespaceMembership> {
        if self.launcher_namespaces.is_some()
            || self.namespaces.is_some()
            || self.expected_parent.is_some()
            || self.host.is_some()
        {
            return Err(invalid_data(
                "pre-PID-one launcher namespaces were already pinned",
            ));
        }
        self.ensure_alive()?;
        verify_process_status(
            &read_proc_file(&self.process_directory, "status")?,
            self.process_id,
            expected_parent,
        )?;
        let child_record = read_proc_file_allow_empty(
            &self.process_directory,
            &format!("task/{}/children", self.process_id),
        )?;
        verify_launcher_children(&child_record, None)?;
        let launcher_namespaces = LauncherNamespacePins::pin_process(&self.process_directory)?;
        let membership = launcher_namespaces.membership();
        if !membership.is_isolated_launcher_from(host)
            || !launcher_namespaces.matches_process_membership(&self.process_directory)?
        {
            return Err(invalid_data(
                "pre-PID-one launcher namespace identities do not match isolated bootstrap",
            ));
        }
        self.ensure_alive()?;
        self.launcher_namespaces = Some(launcher_namespaces);
        self.expected_parent = Some(expected_parent);
        self.host = Some(host);
        Ok(membership)
    }

    pub(crate) fn write_single_extent_mappings(
        &self,
        outer_user_id: u32,
        outer_group_id: u32,
    ) -> Result<(), MappingInstallError> {
        self.verify_launcher_before_pid_one_state()
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
            .and_then(|()| self.verify_launcher_before_pid_one_state())
            .map_err(MappingInstallError::Readback)
    }

    pub(crate) fn verify_single_extent_mappings(
        &self,
        outer_user_id: u32,
        outer_group_id: u32,
    ) -> io::Result<()> {
        self.ensure_alive()?;
        self.verify_mapping_records(outer_user_id, outer_group_id)?;
        self.ensure_alive()
    }

    pub(crate) fn pin_pid_one(
        &mut self,
        reported_process_id: u32,
        expected_selector: &str,
        outer_user_id: u32,
        outer_group_id: u32,
    ) -> io::Result<PidOneKernelPins> {
        let (launcher_snapshot, launcher_pid_depth) =
            self.upgrade_launcher_namespaces(outer_user_id, outer_group_id, reported_process_id)?;
        let pid_one = PidOneKernelPins::pin_and_verify(
            reported_process_id,
            self.process_id,
            launcher_pid_depth,
            launcher_snapshot,
            expected_selector,
            outer_user_id,
            outer_group_id,
        )?;
        self.verify_launcher_state(outer_user_id, outer_group_id, Some(reported_process_id))?;
        pid_one.ensure_alive()?;
        Ok(pid_one)
    }

    pub(crate) fn verify_pid_one_reaped(
        &self,
        pid_one: &PidOneKernelPins,
        outer_user_id: u32,
        outer_group_id: u32,
    ) -> io::Result<()> {
        self.verify_launcher_state(outer_user_id, outer_group_id, None)?;
        pid_one.verify_reaped()?;
        self.verify_launcher_state(outer_user_id, outer_group_id, None)?;
        Ok(())
    }

    fn verify_launcher_state(
        &self,
        outer_user_id: u32,
        outer_group_id: u32,
        expected_child: Option<u32>,
    ) -> io::Result<(NamespaceSnapshot, usize)> {
        self.ensure_alive()?;
        self.verify_mapping_records(outer_user_id, outer_group_id)?;
        let Some(launcher_namespaces) = &self.launcher_namespaces else {
            return Err(invalid_data(
                "pre-PID-one launcher namespaces were not pinned",
            ));
        };
        let Some(namespaces) = &self.namespaces else {
            return Err(invalid_data("full launcher namespaces were not pinned"));
        };
        let Some(expected_parent) = self.expected_parent else {
            return Err(invalid_data("launcher parent identity was not pinned"));
        };
        let Some(host) = self.host else {
            return Err(invalid_data("launcher host namespaces were not retained"));
        };
        let status = verify_process_status(
            &read_proc_file(&self.process_directory, "status")?,
            self.process_id,
            expected_parent,
        )?;
        let child_record = read_proc_file_allow_empty(
            &self.process_directory,
            &format!("task/{}/children", self.process_id),
        )?;
        verify_launcher_children(&child_record, expected_child)?;
        let snapshot = namespaces.snapshot();
        if !snapshot.is_isolated_launcher_from(host)
            || !launcher_namespaces
                .matches_resolved_process_membership(&self.process_directory, snapshot)?
            || !namespaces.matches_process_membership(&self.process_directory)?
        {
            return Err(invalid_data("launcher namespace membership changed"));
        }
        self.ensure_alive()?;
        Ok((snapshot, status.namespace_pids.len()))
    }

    fn verify_launcher_before_pid_one_state(&self) -> io::Result<()> {
        self.ensure_alive()?;
        let Some(launcher_namespaces) = &self.launcher_namespaces else {
            return Err(invalid_data(
                "pre-PID-one launcher namespaces were not pinned",
            ));
        };
        if self.namespaces.is_some() {
            return Err(invalid_data(
                "full launcher namespaces appeared before PID one",
            ));
        }
        let Some(expected_parent) = self.expected_parent else {
            return Err(invalid_data("launcher parent identity was not pinned"));
        };
        let Some(host) = self.host else {
            return Err(invalid_data("launcher host namespaces were not retained"));
        };
        verify_process_status(
            &read_proc_file(&self.process_directory, "status")?,
            self.process_id,
            expected_parent,
        )?;
        let child_record = read_proc_file_allow_empty(
            &self.process_directory,
            &format!("task/{}/children", self.process_id),
        )?;
        verify_launcher_children(&child_record, None)?;
        if !launcher_namespaces
            .membership()
            .is_isolated_launcher_from(host)
            || !launcher_namespaces.matches_process_membership(&self.process_directory)?
        {
            return Err(invalid_data(
                "pre-PID-one launcher namespace membership changed",
            ));
        }
        self.ensure_alive()
    }

    fn upgrade_launcher_namespaces(
        &mut self,
        outer_user_id: u32,
        outer_group_id: u32,
        reported_process_id: u32,
    ) -> io::Result<(NamespaceSnapshot, usize)> {
        if self.namespaces.is_some() {
            return Err(invalid_data("full launcher namespaces were already pinned"));
        }
        self.ensure_alive()?;
        self.verify_mapping_records(outer_user_id, outer_group_id)?;
        let Some(launcher_namespaces) = &self.launcher_namespaces else {
            return Err(invalid_data(
                "pre-PID-one launcher namespaces were not pinned",
            ));
        };
        let Some(expected_parent) = self.expected_parent else {
            return Err(invalid_data("launcher parent identity was not pinned"));
        };
        let Some(host) = self.host else {
            return Err(invalid_data("launcher host namespaces were not retained"));
        };
        let status = verify_process_status(
            &read_proc_file(&self.process_directory, "status")?,
            self.process_id,
            expected_parent,
        )?;
        let child_record = read_proc_file_allow_empty(
            &self.process_directory,
            &format!("task/{}/children", self.process_id),
        )?;
        verify_launcher_children(&child_record, Some(reported_process_id))?;
        let namespaces = NamespacePins::pin_process(&self.process_directory)?;
        let snapshot = namespaces.snapshot();
        if !snapshot.is_isolated_launcher_from(host)
            || !launcher_namespaces
                .matches_resolved_process_membership(&self.process_directory, snapshot)?
            || !namespaces.matches_process_membership(&self.process_directory)?
        {
            return Err(invalid_data(
                "launcher namespace upgrade did not match its retained pre-child pins",
            ));
        }
        self.ensure_alive()?;
        self.namespaces = Some(namespaces);
        let (verified_snapshot, verified_depth) =
            self.verify_launcher_state(outer_user_id, outer_group_id, Some(reported_process_id))?;
        if verified_snapshot != snapshot || verified_depth != status.namespace_pids.len() {
            return Err(invalid_data(
                "launcher namespace upgrade changed during verification",
            ));
        }
        Ok((verified_snapshot, verified_depth))
    }

    fn verify_mapping_records(&self, outer_user_id: u32, outer_group_id: u32) -> io::Result<()> {
        verify_mapping_records_at(&self.process_directory, outer_user_id, outer_group_id)
    }
}

impl PidOneKernelPins {
    fn pin_and_verify(
        process_id: u32,
        launcher_process_id: u32,
        launcher_pid_depth: usize,
        launcher_snapshot: NamespaceSnapshot,
        expected_selector: &str,
        outer_user_id: u32,
        outer_group_id: u32,
    ) -> io::Result<Self> {
        let raw_process_id = i32::try_from(process_id)
            .map_err(|_| invalid_data("reported PID-1 process ID is out of range"))?;
        let pid = Pid::from_raw(raw_process_id)
            .ok_or_else(|| invalid_data("reported PID-1 process ID is zero"))?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(rustix_io)?;
        ensure_pidfd_alive(&pidfd, "reported PID-1 process is no longer alive")?;
        let process_directory = open(
            format!("/proc/{process_id}"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(rustix_io)?;
        ensure_pidfd_alive(&pidfd, "reported PID-1 process is no longer alive")?;
        verify_pid_one_status(
            &read_proc_file(&process_directory, "status")?,
            process_id,
            launcher_process_id,
            launcher_pid_depth,
        )?;
        verify_pid_one_children(&read_proc_file_allow_empty(
            &process_directory,
            &format!("task/{process_id}/children"),
        )?)?;
        verify_exact_self_executable(&process_directory)?;
        verify_exact_command_line(
            &read_proc_file(&process_directory, "cmdline")?,
            expected_selector,
        )?;
        verify_mapping_records_at(&process_directory, outer_user_id, outer_group_id)?;
        let root_directory = openat(
            &process_directory,
            "root",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_io)?;
        let root_metadata = fstat(&root_directory).map_err(rustix_io)?;
        if !FileType::from_raw_mode(root_metadata.st_mode).is_dir() {
            return Err(invalid_data("reported PID-1 root is not a directory"));
        }
        let namespaces = NamespacePins::pin_process(&process_directory)?;
        if !namespaces.snapshot().is_pid_one_child_of(launcher_snapshot)
            || !namespaces.matches_process_membership(&process_directory)?
        {
            return Err(invalid_data(
                "reported PID-1 namespace identities do not match the launcher",
            ));
        }
        verify_pid_one_children(&read_proc_file_allow_empty(
            &process_directory,
            &format!("task/{process_id}/children"),
        )?)?;
        ensure_pidfd_alive(&pidfd, "reported PID-1 process is no longer alive")?;
        Ok(Self {
            pidfd,
            process_directory,
            root_directory,
            namespaces,
            process_id,
            launcher_process_id,
            launcher_pid_depth,
        })
    }

    pub(crate) fn ensure_alive(&self) -> io::Result<()> {
        ensure_pidfd_alive(&self.pidfd, "reported PID-1 process is no longer alive")
    }

    pub(crate) fn verify_private_mounts(
        &self,
        outer_user_id: u32,
        outer_group_id: u32,
    ) -> io::Result<()> {
        self.verify_live_identity(outer_user_id, outer_group_id)?;
        let mountinfo = read_proc_file_with_limit(
            &self.process_directory,
            "mountinfo",
            MAX_PRIVATE_MOUNTINFO_BYTES,
            false,
        )?;
        let run_directory = open_isolated_root_directory(&self.root_directory, "run")?;
        let proc_directory = open_isolated_root_directory(&self.root_directory, "proc")?;
        let run_mount_id = descriptor_mount_id(&run_directory)?;
        let proc_mount_id = descriptor_mount_id(&proc_directory)?;
        crate::mounts::verify_private_mountinfo(&mountinfo, run_mount_id, proc_mount_id)?;
        verify_private_run(&run_directory, outer_user_id, outer_group_id)?;
        verify_private_proc(&proc_directory, self.namespaces.snapshot().pid)?;
        self.verify_live_identity(outer_user_id, outer_group_id)
    }

    fn verify_live_identity(&self, outer_user_id: u32, outer_group_id: u32) -> io::Result<()> {
        self.ensure_alive()?;
        verify_pid_one_status(
            &read_proc_file(&self.process_directory, "status")?,
            self.process_id,
            self.launcher_process_id,
            self.launcher_pid_depth,
        )?;
        verify_pid_one_children(&read_proc_file_allow_empty(
            &self.process_directory,
            &format!("task/{}/children", self.process_id),
        )?)?;
        verify_mapping_records_at(&self.process_directory, outer_user_id, outer_group_id)?;
        if !self.namespaces.still_matches()?
            || !self
                .namespaces
                .matches_process_membership(&self.process_directory)?
        {
            return Err(invalid_data(
                "reported PID-1 namespace membership changed during mount proof",
            ));
        }
        let current_root = openat(
            &self.process_directory,
            "root",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_io)?;
        let expected_root = fstat(&self.root_directory).map_err(rustix_io)?;
        let observed_root = fstat(current_root).map_err(rustix_io)?;
        if expected_root.st_dev != observed_root.st_dev
            || expected_root.st_ino != observed_root.st_ino
        {
            return Err(invalid_data(
                "reported PID-1 root changed during mount proof",
            ));
        }
        self.ensure_alive()
    }

    fn verify_reaped(&self) -> io::Result<()> {
        ensure_pidfd_exited(&self.pidfd)?;
        if !self.namespaces.still_matches()? {
            return Err(invalid_data(
                "PID-1 namespace pins changed before reap proof",
            ));
        }
        match read_proc_file(&self.process_directory, "status") {
            Ok(_) => return Err(invalid_data("PID-1 process has exited but was not reaped")),
            Err(error) if is_reaped_proc_record(&error) => {}
            Err(error) => return Err(error),
        }
        ensure_pidfd_exited(&self.pidfd)
    }
}

fn open_isolated_root_directory<Fd: AsFd>(root: Fd, name: &str) -> io::Result<OwnedFd> {
    openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(rustix_io)
}

fn descriptor_mount_id<Fd: AsFd>(descriptor: Fd) -> io::Result<u64> {
    let status =
        statx(descriptor, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID).map_err(rustix_io)?;
    if StatxFlags::from_bits_retain(status.stx_mask).contains(StatxFlags::MNT_ID)
        && status.stx_mnt_id != 0
    {
        Ok(status.stx_mnt_id)
    } else {
        Err(invalid_data("kernel did not report a nonzero mount ID"))
    }
}

fn verify_private_run<Fd: AsFd>(
    directory: Fd,
    outer_user_id: u32,
    outer_group_id: u32,
) -> io::Result<()> {
    let metadata = fstat(&directory).map_err(rustix_io)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_mode & 0o7777 != PRIVATE_RUN_MODE
        || metadata.st_uid != outer_user_id
        || metadata.st_gid != outer_group_id
    {
        return Err(invalid_data(
            "private /run root type, mode, or ownership is not exact",
        ));
    }
    let filesystem = fstatfs(&directory).map_err(rustix_io)?;
    let block_size = u128::try_from(filesystem.f_bsize)
        .map_err(|_| invalid_data("private /run block size is invalid"))?;
    let capacity = u128::from(filesystem.f_blocks)
        .checked_mul(block_size)
        .ok_or_else(|| invalid_data("private /run capacity overflow"))?;
    if i128::from(filesystem.f_type) != TMPFS_SUPER_MAGIC
        || capacity == 0
        || capacity > u128::from(PRIVATE_RUN_SIZE_BYTES)
        || filesystem.f_files == 0
        || filesystem.f_files > PRIVATE_RUN_INODES
    {
        return Err(invalid_data("private /run is not the fixed bounded tmpfs"));
    }
    if !directory_names(directory)?.is_empty() {
        return Err(invalid_data("private /run is not initially empty"));
    }
    Ok(())
}

fn verify_private_proc<Fd: AsFd>(
    directory: Fd,
    expected_pid_namespace: volparossa_test_support::NamespaceIdentity,
) -> io::Result<()> {
    let metadata = fstat(&directory).map_err(rustix_io)?;
    let filesystem = fstatfs(&directory).map_err(rustix_io)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_dir() || filesystem.f_type != PROC_SUPER_MAGIC
    {
        return Err(invalid_data("private /proc is not procfs"));
    }
    let names = directory_names(&directory)?;
    let mut process_ids = Vec::new();
    for name in names {
        if name.first().is_some_and(u8::is_ascii_digit) {
            if name.len() > 1 && name.first() == Some(&b'0') || !name.iter().all(u8::is_ascii_digit)
            {
                return Err(invalid_data("private /proc PID entry is not canonical"));
            }
            process_ids.push(
                std::str::from_utf8(&name)
                    .ok()
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|pid| *pid != 0)
                    .ok_or_else(|| invalid_data("private /proc PID entry is invalid"))?,
            );
        }
    }
    process_ids.sort_unstable();
    if process_ids != [1] {
        return Err(invalid_data(
            "private /proc does not expose exactly namespace PID 1",
        ));
    }
    let namespace = openat(
        &directory,
        "1/ns/pid",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    let namespace_metadata = fstat(namespace).map_err(rustix_io)?;
    if namespace_metadata.st_dev != expected_pid_namespace.device()
        || namespace_metadata.st_ino != expected_pid_namespace.inode()
    {
        return Err(invalid_data(
            "private /proc is not bound to the retained PID namespace",
        ));
    }
    let status = parse_process_status(&read_proc_file_at(&directory, "1/status", false)?)?;
    if status.pid != 1 || status.parent != 0 || status.threads != 1 || status.namespace_pids != [1]
    {
        return Err(invalid_data("private /proc PID-1 status is not exact"));
    }
    verify_pid_one_children(&read_proc_file_at(directory, "1/task/1/children", true)?)
}

fn directory_names<Fd: AsFd>(directory: Fd) -> io::Result<Vec<Vec<u8>>> {
    let mut entries = Dir::read_from(directory).map_err(rustix_io)?;
    let mut names = Vec::new();
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(rustix_io)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() == MAXIMUM_DIRECTORY_ENTRIES {
            return Err(invalid_data("directory proof exceeded its entry bound"));
        }
        names.push(name.to_vec());
    }
    Ok(names)
}

fn read_proc_file_at<Fd: AsFd>(
    directory: Fd,
    name: &str,
    allow_empty: bool,
) -> io::Result<Vec<u8>> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    read_bounded_inner(File::from(descriptor), allow_empty)
}

fn ensure_pidfd_alive<Fd: AsFd>(pidfd: Fd, message: &'static str) -> io::Result<()> {
    let mut descriptors = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
    let ready = poll(&mut descriptors, 0_u8).map_err(errno_io)?;
    if ready == 0
        && descriptors[0]
            .revents()
            .is_none_or(|events| events.is_empty())
    {
        Ok(())
    } else {
        Err(invalid_data(message))
    }
}

fn ensure_pidfd_exited<Fd: AsFd>(pidfd: Fd) -> io::Result<()> {
    let mut descriptors = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
    let ready = poll(&mut descriptors, 0_u8).map_err(errno_io)?;
    let events = descriptors[0].revents().unwrap_or_else(PollFlags::empty);
    if ready == 1
        && events.contains(PollFlags::POLLIN)
        && !events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL)
    {
        Ok(())
    } else {
        Err(invalid_data("PID-1 pidfd does not prove process exit"))
    }
}

fn verify_mapping_records_at<Fd: AsFd>(
    process_directory: Fd,
    outer_user_id: u32,
    outer_group_id: u32,
) -> io::Result<()> {
    if read_proc_file(&process_directory, "setgroups")? != b"deny\n"
        || parse_single_extent_map(&read_proc_file(&process_directory, "uid_map")?)?
            != (0, outer_user_id, 1)
        || parse_single_extent_map(&read_proc_file(&process_directory, "gid_map")?)?
            != (0, outer_group_id, 1)
    {
        return Err(invalid_data(
            "process user or group namespace mapping is not canonical",
        ));
    }
    Ok(())
}

fn verify_exact_self_executable<Fd: AsFd>(process_directory: Fd) -> io::Result<()> {
    let expected = open(
        "/proc/self/exe",
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    let observed = openat(
        process_directory,
        "exe",
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    let expected_metadata = fstat(expected).map_err(rustix_io)?;
    let observed_metadata = fstat(observed).map_err(rustix_io)?;
    if expected_metadata.st_dev == observed_metadata.st_dev
        && expected_metadata.st_ino == observed_metadata.st_ino
    {
        Ok(())
    } else {
        Err(invalid_data(
            "reported PID-1 executable does not match the outer runner",
        ))
    }
}

fn verify_exact_command_line(bytes: &[u8], expected_selector: &str) -> io::Result<()> {
    if expected_selector.is_empty() || expected_selector.as_bytes().contains(&0) {
        return Err(invalid_data("expected PID-1 selector is invalid"));
    }
    let mut fields = bytes.split(|byte| *byte == 0);
    if fields.next() == Some(b"/proc/self/exe")
        && fields.next() == Some(expected_selector.as_bytes())
        && fields.next() == Some(b"")
        && fields.next().is_none()
    {
        Ok(())
    } else {
        Err(invalid_data("reported PID-1 command line is not exact"))
    }
}

fn is_reaped_proc_record(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == nix::errno::Errno::ENOENT as i32
            || code == nix::errno::Errno::ESRCH as i32
    )
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
    read_proc_file_with_limit(process_directory, name, MAXIMUM_PROC_RECORD_BYTES, false)
}

fn read_proc_file_allow_empty<Fd: AsFd>(process_directory: Fd, name: &str) -> io::Result<Vec<u8>> {
    read_proc_file_with_limit(process_directory, name, MAXIMUM_PROC_RECORD_BYTES, true)
}

fn read_proc_file_with_limit<Fd: AsFd>(
    process_directory: Fd,
    name: &str,
    maximum_bytes: usize,
    allow_empty: bool,
) -> io::Result<Vec<u8>> {
    let descriptor = openat(
        process_directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    read_bounded_inner_with_limit(File::from(descriptor), allow_empty, maximum_bytes)
}

fn read_bounded(file: File) -> io::Result<Vec<u8>> {
    read_bounded_inner(file, false)
}

fn read_bounded_inner(file: File, allow_empty: bool) -> io::Result<Vec<u8>> {
    read_bounded_inner_with_limit(file, allow_empty, MAXIMUM_PROC_RECORD_BYTES)
}

fn read_bounded_inner_with_limit(
    mut file: File,
    allow_empty: bool,
    maximum_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(maximum_bytes.saturating_add(1));
    file.by_ref()
        .take(
            u64::try_from(maximum_bytes.saturating_add(1))
                .map_err(|_| invalid_data("proc record read bound does not fit the platform"))?,
        )
        .read_to_end(&mut bytes)?;
    if (!allow_empty && bytes.is_empty()) || bytes.len() > maximum_bytes {
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

fn parse_process_status(bytes: &[u8]) -> io::Result<ProcessStatus> {
    if !bytes.ends_with(b"\n") || bytes.contains(&b'\r') || bytes.contains(&0) {
        return Err(invalid_data("process status framing is invalid"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid_data("process status is not UTF-8"))?;
    let mut pid = None;
    let mut parent = None;
    let mut threads = None;
    let mut namespace_pids = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Pid:\t") {
            set_once(&mut pid, parse_decimal(Some(value))?)?;
        } else if let Some(value) = line.strip_prefix("PPid:\t") {
            set_once(&mut parent, parse_decimal(Some(value))?)?;
        } else if let Some(value) = line.strip_prefix("Threads:\t") {
            set_once(&mut threads, parse_decimal(Some(value))?)?;
        } else if let Some(value) = line.strip_prefix("NSpid:\t") {
            let parsed = parse_namespace_pid_list(value)?;
            if namespace_pids.replace(parsed).is_some() {
                return Err(invalid_data("proc record duplicated a required field"));
            }
        }
    }
    let Some(pid) = pid else {
        return Err(invalid_data("process status is missing Pid"));
    };
    let Some(parent) = parent else {
        return Err(invalid_data("process status is missing PPid"));
    };
    let Some(threads) = threads else {
        return Err(invalid_data("process status is missing Threads"));
    };
    let Some(namespace_pids) = namespace_pids else {
        return Err(invalid_data("process status is missing NSpid"));
    };
    if namespace_pids.first() != Some(&pid) {
        return Err(invalid_data(
            "process status PID does not match its first namespace PID",
        ));
    }
    Ok(ProcessStatus {
        pid,
        parent,
        threads,
        namespace_pids,
    })
}

fn parse_namespace_pid_list(value: &str) -> io::Result<Vec<u32>> {
    if value.is_empty() {
        return Err(invalid_data("process namespace PID list is empty"));
    }
    let mut parsed = Vec::new();
    for field in value.split('\t') {
        parsed.push(parse_decimal(Some(field))?);
    }
    if parsed.is_empty() {
        Err(invalid_data("process namespace PID list is empty"))
    } else {
        Ok(parsed)
    }
}

fn verify_process_status(
    bytes: &[u8],
    expected_pid: u32,
    expected_parent: u32,
) -> io::Result<ProcessStatus> {
    let status = parse_process_status(bytes)?;
    if status.pid == expected_pid && status.parent == expected_parent && status.threads == 1 {
        Ok(status)
    } else {
        Err(invalid_data(
            "launcher process identity or task count is invalid",
        ))
    }
}

fn verify_pid_one_status(
    bytes: &[u8],
    expected_pid: u32,
    expected_parent: u32,
    launcher_pid_depth: usize,
) -> io::Result<ProcessStatus> {
    let status = parse_process_status(bytes)?;
    let expected_depth = launcher_pid_depth
        .checked_add(1)
        .ok_or_else(|| invalid_data("PID namespace depth overflow"))?;
    if status.pid == expected_pid
        && status.parent == expected_parent
        && status.threads == 1
        && status.namespace_pids.len() == expected_depth
        && status.namespace_pids.last() == Some(&1)
    {
        Ok(status)
    } else {
        Err(invalid_data(
            "reported PID-1 process identity, task count, or nesting is invalid",
        ))
    }
}

fn verify_launcher_children(bytes: &[u8], expected_child: Option<u32>) -> io::Result<()> {
    let expected =
        expected_child.map_or_else(Vec::new, |process_id| format!("{process_id} ").into_bytes());
    if bytes == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "launcher child process set is not exact: expected={expected:?} observed={bytes:?}"
            ),
        ))
    }
}

fn verify_pid_one_children(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(invalid_data("PID-one child process set is not empty"))
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
        let valid = b"Name:\tfixture\nPid:\t42\nPPid:\t7\nNSpid:\t42\nThreads:\t1\n";
        verify_process_status(valid, 42, 7).expect("status");
        assert!(verify_process_status(valid, 41, 7).is_err());
        assert!(verify_process_status(valid, 42, 8).is_err());
        assert!(
            verify_process_status(b"Pid:\t42\nPPid:\t7\nNSpid:\t42\nThreads:\t2\n", 42, 7).is_err()
        );
        assert!(
            verify_process_status(
                b"Pid:\t42\nPid:\t42\nPPid:\t7\nNSpid:\t42\nThreads:\t1\n",
                42,
                7
            )
            .is_err()
        );
    }

    #[test]
    fn process_status_requires_one_canonical_namespace_pid_record() {
        let valid = b"Pid:\t42\nPPid:\t7\nNSpid:\t42\t12\t1\nThreads:\t1\n";
        let status = parse_process_status(valid).expect("nested status");
        assert_eq!(status.namespace_pids, [42, 12, 1]);

        for rejected in [
            b"Pid:\t42\nPPid:\t7\nThreads:\t1\n".as_slice(),
            b"Pid:\t42\nPPid:\t7\nNSpid:\t41\t1\nThreads:\t1\n",
            b"Pid:\t42\nPPid:\t7\nNSpid:\t42 1\nThreads:\t1\n",
            b"Pid:\t42\nPPid:\t7\nNSpid:\t42\t01\nThreads:\t1\n",
            b"Pid:\t42\nPPid:\t7\nNSpid:\t42\t1\nNSpid:\t42\t1\nThreads:\t1\n",
            b"Pid:\t42\nPPid:\t7\nNSpid:\t42\t1\nThreads:\t1",
            b"Pid:\t42\r\nPPid:\t7\nNSpid:\t42\t1\nThreads:\t1\n",
        ] {
            assert!(
                parse_process_status(rejected).is_err(),
                "accepted {rejected:?}"
            );
        }
    }

    #[test]
    fn pid_one_status_requires_exactly_one_deeper_level_ending_in_one() {
        let valid = b"Pid:\t42\nPPid:\t7\nNSpid:\t42\t1\nThreads:\t1\n";
        verify_pid_one_status(valid, 42, 7, 1).expect("PID-1 status");

        for (record, launcher_depth) in [
            (
                b"Pid:\t42\nPPid:\t7\nNSpid:\t42\nThreads:\t1\n".as_slice(),
                1,
            ),
            (b"Pid:\t42\nPPid:\t7\nNSpid:\t42\t2\nThreads:\t1\n", 1),
            (b"Pid:\t42\nPPid:\t7\nNSpid:\t42\t9\t1\nThreads:\t1\n", 1),
        ] {
            assert!(verify_pid_one_status(record, 42, 7, launcher_depth).is_err());
        }
        assert!(verify_pid_one_status(valid, 41, 7, 1).is_err());
        assert!(verify_pid_one_status(valid, 42, 8, 1).is_err());
    }

    #[test]
    fn pid_one_command_line_requires_fixed_self_exec_and_one_selector() {
        let selector = "--internal-netns-pid-one-v1";
        verify_exact_command_line(b"/proc/self/exe\0--internal-netns-pid-one-v1\0", selector)
            .expect("exact command line");

        for rejected in [
            b"/other/exe\0--internal-netns-pid-one-v1\0".as_slice(),
            b"/proc/self/exe\0--wrong\0",
            b"/proc/self/exe\0--internal-netns-pid-one-v1",
            b"/proc/self/exe\0--internal-netns-pid-one-v1\0extra\0",
            b"\0--internal-netns-pid-one-v1\0",
        ] {
            assert!(
                verify_exact_command_line(rejected, selector).is_err(),
                "accepted {rejected:?}"
            );
        }
        assert!(verify_exact_command_line(b"/proc/self/exe\0x\0", "").is_err());
        assert!(verify_exact_command_line(b"/proc/self/exe\0x\0", "x\0y").is_err());
    }

    #[test]
    fn launcher_children_record_is_exactly_empty_or_one_kernel_pid() {
        verify_launcher_children(b"", None).expect("no child");
        verify_launcher_children(b"42 ", Some(42)).expect("one child");
        for (record, expected) in [
            (b"42".as_slice(), Some(42)),
            (b"42\n", Some(42)),
            (b"042 ", Some(42)),
            (b"42 43 ", Some(42)),
            (b"43 ", Some(42)),
            (b"42 ", None),
        ] {
            assert!(verify_launcher_children(record, expected).is_err());
        }
    }

    #[test]
    fn pid_one_children_record_must_be_exactly_empty() {
        verify_pid_one_children(b"").expect("no PID-one descendants");
        for record in [b"1".as_slice(), b"42 ", b"42\n", b"0 ", b"42 43 ", b" \t"] {
            assert!(
                verify_pid_one_children(record).is_err(),
                "accepted {record:?}"
            );
        }
    }

    #[test]
    fn only_disappeared_anchored_proc_records_are_reap_evidence() {
        for error in [
            io::Error::from_raw_os_error(nix::errno::Errno::ENOENT as i32),
            io::Error::from_raw_os_error(nix::errno::Errno::ESRCH as i32),
        ] {
            assert!(is_reaped_proc_record(&error));
        }
        for error in [
            io::Error::from_raw_os_error(nix::errno::Errno::EACCES as i32),
            io::Error::from_raw_os_error(nix::errno::Errno::EIO as i32),
        ] {
            assert!(!is_reaped_proc_record(&error));
        }
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
