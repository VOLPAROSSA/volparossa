use std::{
    collections::HashSet,
    fs::File,
    io::{self, Read as _},
    mem::MaybeUninit,
    os::fd::OwnedFd,
};

use nix::unistd::{getpid, getppid};
use rustix::{
    fd::AsFd,
    fs::{
        ABS, AtFlags, FileType, FsWord, Mode, OFlags, PROC_SUPER_MAGIC, RawDir, ResolveFlags,
        Statx, StatxFlags, fstatfs, openat2, readlinkat, statx,
    },
    io::Errno,
    mount::{
        FsMountFlags, FsOpenFlags, MountAttrFlags, MountPropagationFlags, MoveMountFlags,
        fsconfig_create, fsconfig_set_string, fsmount, fsopen, mount_change, move_mount,
    },
};
use thiserror::Error;

/// Exact byte ceiling for one kernel mount-table observation.
pub(crate) const MAX_PRIVATE_MOUNTINFO_BYTES: usize = 1024 * 1024;
/// Exact byte capacity of the private runner `/run` tmpfs.
pub(crate) const PRIVATE_RUN_SIZE_BYTES: u64 = 16 * 1024 * 1024;
/// Exact inode capacity of the private runner `/run` tmpfs.
pub(crate) const PRIVATE_RUN_INODES: u64 = 4096;
/// Exact root-directory mode of the private runner `/run` tmpfs.
pub(crate) const PRIVATE_RUN_MODE: u32 = 0o700;

const MAX_PRIVATE_MOUNTINFO_RECORDS: usize = 4096;
const MAX_PROC_PROOF_BYTES: usize = 4096;
const DIRECTORY_BUFFER_BYTES: usize = 4096;
const TMPFS_SUPER_MAGIC: FsWord = 0x0102_1994;
const RUN_MOUNT_POINT: &[u8] = b"/run";
const PROC_MOUNT_POINT: &[u8] = b"/proc";

/// Visible mount identities proven for the private runtime filesystems.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrivateMountIds {
    run_mount_id: u64,
    proc_mount_id: u64,
}

/// Failure of the fixed PID-1 private-mount setup or its kernel readback.
#[derive(Debug, Error)]
pub(crate) enum PrivateMountSetupError {
    /// An exact mount UAPI operation was denied by kernel policy.
    #[error("kernel policy denied private-mount operation {operation}: {source}")]
    PolicyDenied {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    /// A setup precondition, mount operation, or proof failed for any other reason.
    #[error("private-mount operation {operation} failed: {source}")]
    HardFailure {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

impl PrivateMountSetupError {
    /// Whether this error is the narrow EPERM/EACCES policy-denial outcome.
    pub(crate) const fn is_policy_denial(&self) -> bool {
        matches!(self, Self::PolicyDenied { .. })
    }
}

/// Affine owner of the exact private mounts installed by namespace PID 1.
///
/// The retained root and visible mount descriptors pin the measured objects.
/// Reverification reopens both fixed paths below the pinned root and requires
/// their visible mount IDs to remain unchanged.
pub(crate) struct PrivateMounts {
    root: OwnedFd,
    run_pin: OwnedFd,
    proc_pin: OwnedFd,
    root_mount_id: u64,
    ids: PrivateMountIds,
}

impl PrivateMounts {
    /// Repeat the complete local mount-table and procfs proof.
    pub(crate) fn verify(&self) -> Result<(), PrivateMountSetupError> {
        let root_stat = hard_rustix(
            "re-read pinned root mount identity",
            statx_fd(&self.root, StatxFlags::TYPE | StatxFlags::MNT_ID),
        )?;
        require_directory_and_mount_id(&root_stat, self.root_mount_id)
            .map_err(|source| hard_error("re-read pinned root mount identity", source))?;

        let pinned_run_id = hard_io(
            "re-read pinned /run mount identity",
            mount_id_for_fd(&self.run_pin),
        )?;
        let pinned_proc_id = hard_io(
            "re-read pinned /proc mount identity",
            mount_id_for_fd(&self.proc_pin),
        )?;
        if pinned_run_id != self.ids.run_mount_id || pinned_proc_id != self.ids.proc_mount_id {
            return Err(hard_error(
                "re-read pinned private mount identities",
                invalid_data("pinned private mount identity changed"),
            ));
        }

        verify_visible_private_mounts(&self.root, self.root_mount_id, self.ids)
    }
}

struct MountTargets {
    root: OwnedFd,
    run: OwnedFd,
    proc: OwnedFd,
    root_mount_id: u64,
    run_mount_id: u64,
    proc_mount_id: u64,
}

impl MountTargets {
    fn pin() -> Result<Self, PrivateMountSetupError> {
        let root = hard_rustix(
            "pin root mount target",
            openat2(
                ABS,
                "/",
                path_directory_flags(),
                Mode::empty(),
                ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
            ),
        )?;
        let run = hard_rustix(
            "pin /run mount target",
            open_beneath(&root, "run", path_directory_flags()),
        )?;
        let proc = hard_rustix(
            "pin /proc mount target",
            open_beneath(&root, "proc", path_directory_flags()),
        )?;
        let root_mount_id = hard_io("measure root mount target", mount_id_for_fd(&root))?;
        let run_mount_id = hard_io("measure /run mount target", mount_id_for_fd(&run))?;
        let proc_mount_id = hard_io("measure /proc mount target", mount_id_for_fd(&proc))?;
        Ok(Self {
            root,
            run,
            proc,
            root_mount_id,
            run_mount_id,
            proc_mount_id,
        })
    }
}

/// Install and prove the fixed private mounts from the real namespace PID 1.
///
/// The function has no caller-selected paths or options. It pins all targets
/// before mutation, recursively makes the inherited tree private, attaches a
/// bounded hardened tmpfs over `/run`, and attaches procfs over `/proc` last.
pub(crate) fn setup_and_verify_private_mounts() -> Result<PrivateMounts, PrivateMountSetupError> {
    if getpid().as_raw() != 1 || getppid().as_raw() != 0 {
        return Err(hard_error(
            "verify namespace PID one",
            invalid_data("private mounts may be installed only by namespace PID 1"),
        ));
    }

    let targets = MountTargets::pin()?;
    mount_uapi(
        "make inherited mount tree recursively private",
        mount_change(
            "/",
            MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
        ),
    )?;
    install_private_run(&targets.run)?;
    install_private_proc(&targets.proc)?;

    let visible_run = hard_rustix(
        "pin visible private /run",
        open_beneath(&targets.root, "run", path_directory_flags()),
    )?;
    let visible_proc = hard_rustix(
        "pin visible private /proc",
        open_beneath(&targets.root, "proc", path_directory_flags()),
    )?;
    let ids = PrivateMountIds {
        run_mount_id: hard_io(
            "measure visible private /run",
            mount_id_for_fd(&visible_run),
        )?,
        proc_mount_id: hard_io(
            "measure visible private /proc",
            mount_id_for_fd(&visible_proc),
        )?,
    };
    if ids.run_mount_id == targets.run_mount_id
        || ids.proc_mount_id == targets.proc_mount_id
        || ids.run_mount_id == ids.proc_mount_id
    {
        return Err(hard_error(
            "measure newly attached private mounts",
            invalid_data("private mounts did not replace both inherited visible mounts"),
        ));
    }

    let mounts = PrivateMounts {
        root: targets.root,
        run_pin: visible_run,
        proc_pin: visible_proc,
        root_mount_id: targets.root_mount_id,
        ids,
    };
    mounts.verify()?;
    Ok(mounts)
}

fn install_private_run(target: &OwnedFd) -> Result<(), PrivateMountSetupError> {
    let context = mount_uapi(
        "create private /run tmpfs context",
        fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC),
    )?;
    mount_uapi(
        "set private /run size",
        fsconfig_set_string(&context, "size", PRIVATE_RUN_SIZE_BYTES.to_string()),
    )?;
    mount_uapi(
        "set private /run inode bound",
        fsconfig_set_string(&context, "nr_inodes", PRIVATE_RUN_INODES.to_string()),
    )?;
    mount_uapi(
        "set private /run mode",
        fsconfig_set_string(&context, "mode", "0700"),
    )?;
    mount_uapi(
        "set private /run owner",
        fsconfig_set_string(&context, "uid", "0"),
    )?;
    mount_uapi(
        "set private /run group",
        fsconfig_set_string(&context, "gid", "0"),
    )?;
    mount_uapi("create private /run tmpfs", fsconfig_create(&context))?;
    let mount = mount_uapi(
        "instantiate private /run tmpfs",
        fsmount(
            &context,
            FsMountFlags::FSMOUNT_CLOEXEC,
            hardened_mount_attributes(),
        ),
    )?;
    mount_uapi(
        "attach private /run tmpfs",
        move_mount(
            &mount,
            "",
            target,
            "",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
        ),
    )
}

fn install_private_proc(target: &OwnedFd) -> Result<(), PrivateMountSetupError> {
    let context = mount_uapi(
        "create private /proc context",
        fsopen("proc", FsOpenFlags::FSOPEN_CLOEXEC),
    )?;
    mount_uapi("create private /proc filesystem", fsconfig_create(&context))?;
    let mount = mount_uapi(
        "instantiate private /proc filesystem",
        fsmount(
            &context,
            FsMountFlags::FSMOUNT_CLOEXEC,
            hardened_mount_attributes(),
        ),
    )?;
    mount_uapi(
        "attach private /proc filesystem",
        move_mount(
            &mount,
            "",
            target,
            "",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
        ),
    )
}

fn hardened_mount_attributes() -> MountAttrFlags {
    MountAttrFlags::MOUNT_ATTR_NOSUID
        | MountAttrFlags::MOUNT_ATTR_NODEV
        | MountAttrFlags::MOUNT_ATTR_NOEXEC
}

fn path_directory_flags() -> OFlags {
    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC
}

fn readable_directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC
}

fn open_beneath<Fd: AsFd>(directory: Fd, name: &str, flags: OFlags) -> rustix::io::Result<OwnedFd> {
    openat2(
        directory,
        name,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
}

fn statx_fd<Fd: AsFd>(fd: Fd, requested: StatxFlags) -> rustix::io::Result<Statx> {
    statx(
        fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        requested,
    )
}

fn mount_id_for_fd<Fd: AsFd>(fd: Fd) -> io::Result<u64> {
    let observed = statx_fd(fd, StatxFlags::TYPE | StatxFlags::MNT_ID).map_err(errno_io)?;
    require_directory_and_mount_id(&observed, observed.stx_mnt_id)?;
    Ok(observed.stx_mnt_id)
}

fn require_directory_and_mount_id(observed: &Statx, expected_mount_id: u64) -> io::Result<()> {
    let mask = StatxFlags::from_bits_retain(observed.stx_mask);
    if !mask.contains(StatxFlags::TYPE | StatxFlags::MNT_ID)
        || !FileType::from_raw_mode(u32::from(observed.stx_mode)).is_dir()
        || observed.stx_mnt_id == 0
        || observed.stx_mnt_id != expected_mount_id
    {
        return Err(invalid_data(
            "kernel did not return the expected directory mount identity",
        ));
    }
    Ok(())
}

fn verify_visible_private_mounts(
    root: &OwnedFd,
    expected_root_mount_id: u64,
    expected_ids: PrivateMountIds,
) -> Result<(), PrivateMountSetupError> {
    let run = hard_rustix(
        "open visible private /run",
        open_beneath(root, "run", readable_directory_flags()),
    )?;
    let proc_before = hard_rustix(
        "open visible private /proc",
        open_beneath(root, "proc", readable_directory_flags()),
    )?;
    let root_mount_id = hard_io("re-measure root mount", mount_id_for_fd(root))?;
    let run_mount_id = hard_io("re-measure private /run", mount_id_for_fd(&run))?;
    let proc_mount_id = hard_io("re-measure private /proc", mount_id_for_fd(&proc_before))?;
    if root_mount_id != expected_root_mount_id
        || run_mount_id != expected_ids.run_mount_id
        || proc_mount_id != expected_ids.proc_mount_id
    {
        return Err(hard_error(
            "re-measure visible private mounts",
            invalid_data("visible private mount identity changed"),
        ));
    }

    verify_run_filesystem(&run)?;
    verify_proc_filesystem(&proc_before)?;
    verify_exact_proc_state(&proc_before)?;
    let mountinfo = read_proc_record(&proc_before, "1/mountinfo", MAX_PRIVATE_MOUNTINFO_BYTES)?;
    verify_private_mountinfo(
        &mountinfo,
        expected_ids.run_mount_id,
        expected_ids.proc_mount_id,
    )
    .map_err(|source| hard_error("verify private mount table", source))?;

    let proc_after = hard_rustix(
        "reopen visible private /proc",
        open_beneath(root, "proc", readable_directory_flags()),
    )?;
    let proc_after_mount_id = hard_io(
        "re-measure private /proc after proof",
        mount_id_for_fd(&proc_after),
    )?;
    if proc_after_mount_id != expected_ids.proc_mount_id {
        return Err(hard_error(
            "re-measure private /proc after proof",
            invalid_data("visible private /proc changed during verification"),
        ));
    }
    verify_exact_proc_state(&proc_after)
}

fn verify_run_filesystem(run: &OwnedFd) -> Result<(), PrivateMountSetupError> {
    let filesystem = hard_rustix("read private /run filesystem type", fstatfs(run))?;
    let metadata = hard_rustix(
        "read private /run metadata",
        statx_fd(
            run,
            StatxFlags::TYPE
                | StatxFlags::MODE
                | StatxFlags::UID
                | StatxFlags::GID
                | StatxFlags::MNT_ID,
        ),
    )?;
    let mask = StatxFlags::from_bits_retain(metadata.stx_mask);
    if filesystem.f_type != TMPFS_SUPER_MAGIC
        || !mask.contains(
            StatxFlags::TYPE
                | StatxFlags::MODE
                | StatxFlags::UID
                | StatxFlags::GID
                | StatxFlags::MNT_ID,
        )
        || !FileType::from_raw_mode(u32::from(metadata.stx_mode)).is_dir()
        || Mode::from_raw_mode(u32::from(metadata.stx_mode)) != Mode::RWXU
        || metadata.stx_uid != 0
        || metadata.stx_gid != 0
    {
        return Err(hard_error(
            "verify private /run filesystem",
            invalid_data("private /run filesystem or root metadata is not exact"),
        ));
    }
    hard_io("verify private /run is empty", verify_empty_directory(run))
}

fn verify_proc_filesystem(proc: &OwnedFd) -> Result<(), PrivateMountSetupError> {
    let filesystem = hard_rustix("read private /proc filesystem type", fstatfs(proc))?;
    if filesystem.f_type != PROC_SUPER_MAGIC {
        return Err(hard_error(
            "verify private /proc filesystem",
            invalid_data("private /proc is not procfs"),
        ));
    }
    Ok(())
}

fn verify_exact_proc_state(proc: &OwnedFd) -> Result<(), PrivateMountSetupError> {
    let self_link = hard_rustix(
        "read private /proc/self",
        readlinkat(proc, "self", Vec::with_capacity(16)),
    )?;
    let thread_self_link = hard_rustix(
        "read private /proc/thread-self",
        readlinkat(proc, "thread-self", Vec::with_capacity(32)),
    )?;
    if self_link.as_bytes() != b"1" || thread_self_link.as_bytes() != b"1/task/1" {
        return Err(hard_error(
            "verify private procfs PID view",
            invalid_data("private procfs is not bound to the namespace PID-1 view"),
        ));
    }
    verify_exact_numeric_directory(proc, b"1", "verify private procfs process set")?;
    let task = hard_rustix(
        "open private procfs PID-1 task directory",
        open_beneath(proc, "1/task", readable_directory_flags()),
    )?;
    verify_exact_numeric_directory(&task, b"1", "verify private procfs task set")?;
    let children = read_proc_record(proc, "1/task/1/children", MAX_PROC_PROOF_BYTES)?;
    if !children.is_empty() {
        return Err(hard_error(
            "verify private procfs PID-1 child set",
            invalid_data("namespace PID 1 has an unexpected child"),
        ));
    }
    Ok(())
}

fn verify_exact_numeric_directory<Fd: AsFd>(
    directory: Fd,
    expected: &[u8],
    operation: &'static str,
) -> Result<(), PrivateMountSetupError> {
    let mut buffer = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
    let mut entries = RawDir::new(directory, &mut buffer);
    let mut found = false;
    while let Some(entry) = entries.next() {
        let entry = hard_rustix(operation, entry)?;
        let name = entry.file_name().to_bytes();
        if !name.is_empty() && name.iter().all(u8::is_ascii_digit) {
            if found || name != expected {
                return Err(hard_error(
                    operation,
                    invalid_data("procfs numeric directory set is not exact"),
                ));
            }
            found = true;
        }
    }
    if !found {
        return Err(hard_error(
            operation,
            invalid_data("procfs numeric directory set is empty"),
        ));
    }
    Ok(())
}

fn verify_empty_directory<Fd: AsFd>(directory: Fd) -> io::Result<()> {
    let reopened = openat2(
        directory,
        ".",
        readable_directory_flags(),
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(errno_io)?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); DIRECTORY_BUFFER_BYTES];
    let mut entries = RawDir::new(reopened, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(errno_io)?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Err(invalid_data("private /run contains an unexpected entry"));
        }
    }
    Ok(())
}

fn read_proc_record(
    proc: &OwnedFd,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, PrivateMountSetupError> {
    let descriptor = hard_rustix(
        "open private procfs proof record",
        open_beneath(proc, name, OFlags::RDONLY | OFlags::CLOEXEC),
    )?;
    read_bounded(File::from(descriptor), maximum)
        .map_err(|source| hard_error("read private procfs proof record", source))
}

fn read_bounded(mut file: File, maximum: usize) -> io::Result<Vec<u8>> {
    let limit = maximum
        .checked_add(1)
        .ok_or_else(|| invalid_data("proof record read bound overflowed"))?;
    let mut bytes = Vec::with_capacity(limit);
    file.by_ref()
        .take(
            u64::try_from(limit)
                .map_err(|_| invalid_data("proof record read bound does not fit u64"))?,
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid_data("proof record exceeded its fixed byte bound"));
    }
    Ok(bytes)
}

/// Verify one bounded mountinfo snapshot against the visible private mount IDs.
///
/// Covered inherited `/run` and `/proc` records are permitted. The caller must
/// obtain `visible_run_mount_id` and `visible_proc_mount_id` from descriptor-
/// anchored `statx(STATX_MNT_ID)` observations of the currently visible paths.
pub(crate) fn verify_private_mountinfo(
    bytes: &[u8],
    visible_run_mount_id: u64,
    visible_proc_mount_id: u64,
) -> io::Result<PrivateMountIds> {
    if bytes.is_empty()
        || bytes.len() > MAX_PRIVATE_MOUNTINFO_BYTES
        || !bytes.ends_with(b"\n")
        || bytes.contains(&b'\r')
        || bytes.contains(&0)
        || visible_run_mount_id == 0
        || visible_proc_mount_id == 0
        || visible_run_mount_id == visible_proc_mount_id
    {
        return Err(invalid_data(
            "private mountinfo framing or visible IDs are invalid",
        ));
    }

    let mut mount_ids = HashSet::new();
    let mut run_verified = false;
    let mut proc_verified = false;
    let mut record_count = 0_usize;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        record_count = record_count
            .checked_add(1)
            .ok_or_else(|| invalid_data("private mountinfo record count overflowed"))?;
        if line.is_empty() || record_count > MAX_PRIVATE_MOUNTINFO_RECORDS {
            return Err(invalid_data("private mountinfo record count is invalid"));
        }
        let record = MountInfoRecord::parse(line)?;
        if !mount_ids.insert(record.mount_id) {
            return Err(invalid_data(
                "private mountinfo contains a duplicate mount ID",
            ));
        }
        if record.has_optional_field() {
            return Err(invalid_data("mount propagation is not recursively private"));
        }
        if record.mount_id == visible_run_mount_id {
            verify_run_record(&record)?;
            run_verified = true;
        }
        if record.mount_id == visible_proc_mount_id {
            verify_proc_record(&record)?;
            proc_verified = true;
        }
    }
    if !run_verified || !proc_verified {
        return Err(invalid_data(
            "visible private /run or /proc mount record is missing",
        ));
    }
    Ok(PrivateMountIds {
        run_mount_id: visible_run_mount_id,
        proc_mount_id: visible_proc_mount_id,
    })
}

struct MountInfoRecord<'a> {
    mount_id: u64,
    root: &'a [u8],
    mount_point: &'a [u8],
    mount_options: &'a [u8],
    has_optional_field: bool,
    file_system_type: &'a [u8],
    super_options: &'a [u8],
}

impl<'a> MountInfoRecord<'a> {
    fn parse(line: &'a [u8]) -> io::Result<Self> {
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        if fields.len() < 10 || fields.iter().any(|field| field.is_empty()) {
            return Err(invalid_data("private mountinfo record shape is invalid"));
        }
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or_else(|| invalid_data("private mountinfo separator is missing"))?;
        if separator < 6 || separator.checked_add(4) != Some(fields.len()) {
            return Err(invalid_data(
                "private mountinfo separator position is invalid",
            ));
        }
        let mount_id = parse_canonical_decimal(fields[0])?;
        let parent_id = parse_canonical_decimal(fields[1])?;
        if mount_id == 0 || parent_id == 0 || !is_major_minor(fields[2]) {
            return Err(invalid_data(
                "private mountinfo identity fields are invalid",
            ));
        }
        Ok(Self {
            mount_id,
            root: fields[3],
            mount_point: fields[4],
            mount_options: fields[5],
            has_optional_field: separator != 6,
            file_system_type: fields[separator + 1],
            super_options: fields[separator + 3],
        })
    }

    fn has_optional_field(&self) -> bool {
        self.has_optional_field
    }
}

fn verify_run_record(record: &MountInfoRecord<'_>) -> io::Result<()> {
    if record.root != b"/"
        || record.mount_point != RUN_MOUNT_POINT
        || record.file_system_type != b"tmpfs"
    {
        return Err(invalid_data(
            "visible private /run mount record is not exact",
        ));
    }
    verify_hardened_mount_options(record.mount_options)?;
    require_flag(record.super_options, b"rw")?;
    let size = parse_quantity(require_value(record.super_options, b"size")?)?;
    let inodes = parse_quantity(require_value(record.super_options, b"nr_inodes")?)?;
    let mode = require_value(record.super_options, b"mode")?;
    if size != PRIVATE_RUN_SIZE_BYTES || inodes != PRIVATE_RUN_INODES || mode != b"700" {
        return Err(invalid_data(
            "private /run tmpfs bounds or mode are not exact",
        ));
    }
    Ok(())
}

fn verify_proc_record(record: &MountInfoRecord<'_>) -> io::Result<()> {
    if record.root != b"/"
        || record.mount_point != PROC_MOUNT_POINT
        || record.file_system_type != b"proc"
    {
        return Err(invalid_data(
            "visible private /proc mount record is not exact",
        ));
    }
    verify_hardened_mount_options(record.mount_options)?;
    require_flag(record.super_options, b"rw")
}

fn verify_hardened_mount_options(options: &[u8]) -> io::Result<()> {
    for required in [b"rw".as_slice(), b"nosuid", b"nodev", b"noexec"] {
        require_flag(options, required)?;
    }
    for forbidden in [b"ro".as_slice(), b"suid", b"dev", b"exec"] {
        if option_count(options, forbidden, false)? != 0 {
            return Err(invalid_data("private mount has a conflicting mount option"));
        }
    }
    Ok(())
}

fn require_flag(options: &[u8], name: &[u8]) -> io::Result<()> {
    if option_count(options, name, false)? == 1 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "required private mount flag {} is missing or duplicated",
                String::from_utf8_lossy(name)
            ),
        ))
    }
}

fn require_value<'a>(options: &'a [u8], name: &[u8]) -> io::Result<&'a [u8]> {
    let mut found = None;
    for option in options.split(|byte| *byte == b',') {
        if option.is_empty() {
            return Err(invalid_data(
                "private mount option list contains an empty field",
            ));
        }
        let Some((key, value)) = split_byte_once(option, b'=') else {
            continue;
        };
        if key != name {
            continue;
        }
        if value.is_empty() || found.replace(value).is_some() {
            return Err(invalid_data(
                "private mount option value is missing or duplicated",
            ));
        }
    }
    found.ok_or_else(|| invalid_data("required private mount option value is missing"))
}

fn option_count(options: &[u8], name: &[u8], accept_value: bool) -> io::Result<usize> {
    let mut count = 0_usize;
    for option in options.split(|byte| *byte == b',') {
        if option.is_empty() {
            return Err(invalid_data(
                "private mount option list contains an empty field",
            ));
        }
        let (key, has_value) =
            split_byte_once(option, b'=').map_or((option, false), |(key, _)| (key, true));
        if key == name && (accept_value || !has_value) {
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid_data("private mount option count overflowed"))?;
        }
    }
    Ok(count)
}

fn parse_quantity(value: &[u8]) -> io::Result<u64> {
    let (digits, multiplier) = match value.last().copied() {
        Some(b'k') => (&value[..value.len() - 1], 1024_u64),
        Some(b'm') => (&value[..value.len() - 1], 1024_u64 * 1024),
        Some(b'g') => (&value[..value.len() - 1], 1024_u64 * 1024 * 1024),
        _ => (value, 1_u64),
    };
    parse_canonical_decimal(digits)?
        .checked_mul(multiplier)
        .ok_or_else(|| invalid_data("private mount quantity overflowed"))
}

fn parse_canonical_decimal(value: &[u8]) -> io::Result<u64> {
    if value.is_empty()
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value.starts_with(b"0"))
    {
        return Err(invalid_data("private mount decimal is not canonical"));
    }
    let mut parsed = 0_u64;
    for digit in value {
        parsed = parsed
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(digit - b'0')))
            .ok_or_else(|| invalid_data("private mount decimal overflowed"))?;
    }
    Ok(parsed)
}

fn is_major_minor(value: &[u8]) -> bool {
    let Some((major, minor)) = split_byte_once(value, b':') else {
        return false;
    };
    parse_canonical_decimal(major).is_ok() && parse_canonical_decimal(minor).is_ok()
}

fn split_byte_once(value: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = value.iter().position(|byte| *byte == delimiter)?;
    Some((&value[..index], &value[index + 1..]))
}

fn mount_uapi<T>(
    operation: &'static str,
    result: rustix::io::Result<T>,
) -> Result<T, PrivateMountSetupError> {
    result.map_err(|error| classify_mount_error(operation, error))
}

fn hard_rustix<T>(
    operation: &'static str,
    result: rustix::io::Result<T>,
) -> Result<T, PrivateMountSetupError> {
    result.map_err(|error| {
        hard_error(
            operation,
            io::Error::from_raw_os_error(error.raw_os_error()),
        )
    })
}

fn hard_io<T>(operation: &'static str, result: io::Result<T>) -> Result<T, PrivateMountSetupError> {
    result.map_err(|source| hard_error(operation, source))
}

fn classify_mount_error(operation: &'static str, error: Errno) -> PrivateMountSetupError {
    let source = io::Error::from_raw_os_error(error.raw_os_error());
    if matches!(error, Errno::PERM | Errno::ACCESS) {
        PrivateMountSetupError::PolicyDenied { operation, source }
    } else {
        PrivateMountSetupError::HardFailure { operation, source }
    }
}

fn hard_error(operation: &'static str, source: io::Error) -> PrivateMountSetupError {
    PrivateMountSetupError::HardFailure { operation, source }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn errno_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_MOUNTINFO: &[u8] = b"10 10 8:1 / / rw,relatime - ext4 /dev/root rw\n\
20 10 0:20 / /run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=1024k,mode=755,inode64\n\
21 20 0:21 / /run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=16384k,nr_inodes=4096,mode=700,inode64\n\
30 10 0:30 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n\
31 30 0:31 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";

    #[test]
    fn visible_private_mounts_accept_covered_inherited_records() {
        let ids = verify_private_mountinfo(VALID_MOUNTINFO, 21, 31).expect("private mounts");
        assert_eq!(ids.run_mount_id, 21);
        assert_eq!(ids.proc_mount_id, 31);
    }

    #[test]
    fn every_propagation_relationship_is_rejected() {
        for field in [
            "shared:7",
            "master:7",
            "propagate_from:7",
            "unbindable",
            "future_kernel_field:7",
        ] {
            let changed = String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replacen(
                    "rw,relatime - ext4",
                    &format!("rw,relatime {field} - ext4"),
                    1,
                );
            assert!(verify_private_mountinfo(changed.as_bytes(), 21, 31).is_err());
        }
    }

    #[test]
    fn visible_ids_select_exact_top_records() {
        assert!(verify_private_mountinfo(VALID_MOUNTINFO, 20, 31).is_err());
        assert!(verify_private_mountinfo(VALID_MOUNTINFO, 21, 30).is_ok());
        assert!(verify_private_mountinfo(VALID_MOUNTINFO, 21, 999).is_err());
        assert!(verify_private_mountinfo(VALID_MOUNTINFO, 21, 21).is_err());
    }

    #[test]
    fn duplicate_mount_ids_and_malformed_records_are_rejected() {
        let duplicate = String::from_utf8(VALID_MOUNTINFO.to_vec())
            .expect("fixture")
            .replace("31 30 0:31", "21 30 0:31");
        assert!(verify_private_mountinfo(duplicate.as_bytes(), 21, 31).is_err());
        for malformed in [
            b"".as_slice(),
            b"1 1 0:1 / / rw - proc proc rw",
            b"1 1 bad / / rw - proc proc rw\n",
            b"1 1 0:1 / / rw shared:1 proc proc rw\n",
            b"1 1 0:1 / / rw - proc proc rw\n\n",
        ] {
            assert!(verify_private_mountinfo(malformed, 21, 31).is_err());
        }
    }

    #[test]
    fn mount_types_hardening_and_tmpfs_bounds_are_exact() {
        for changed in [
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace("- tmpfs tmpfs", "- ramfs ramfs"),
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace("- proc proc", "- sysfs sysfs"),
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace(
                    "rw,nosuid,nodev,noexec,relatime",
                    "rw,nosuid,nodev,relatime",
                ),
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace("size=16384k", "size=32768k"),
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace("nr_inodes=4096", "nr_inodes=8192"),
            String::from_utf8(VALID_MOUNTINFO.to_vec())
                .expect("fixture")
                .replace("mode=700", "mode=755"),
        ] {
            assert!(verify_private_mountinfo(changed.as_bytes(), 21, 31).is_err());
        }
    }

    #[test]
    fn mountinfo_is_strictly_bounded() {
        let mut oversized = vec![b'x'; MAX_PRIVATE_MOUNTINFO_BYTES];
        oversized.push(b'\n');
        assert!(verify_private_mountinfo(&oversized, 21, 31).is_err());
    }

    #[test]
    fn local_run_guard_rejects_every_non_dot_entry() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let empty = File::open(directory.path()).expect("open empty directory");
        verify_empty_directory(&empty).expect("empty directory");
        std::fs::write(directory.path().join("owned-object"), b"x").expect("write entry");
        assert!(verify_empty_directory(&empty).is_err());
    }

    #[test]
    fn quantities_are_canonical_bounded_and_binary_scaled() {
        assert_eq!(
            parse_quantity(b"16384k").expect("kilobytes"),
            16 * 1024 * 1024
        );
        assert_eq!(parse_quantity(b"16m").expect("megabytes"), 16 * 1024 * 1024);
        assert!(parse_quantity(b"016m").is_err());
        assert!(parse_quantity(b"1t").is_err());
        assert!(parse_quantity(b"18446744073709551615g").is_err());
    }

    #[test]
    fn only_mount_uapi_permission_errors_are_policy_denials() {
        for error in [Errno::PERM, Errno::ACCESS] {
            assert!(classify_mount_error("test", error).is_policy_denial());
        }
        for error in [
            Errno::NOENT,
            Errno::INVAL,
            Errno::NOSYS,
            Errno::NODEV,
            Errno::NOMEM,
            Errno::NOSPC,
            Errno::BUSY,
        ] {
            assert!(!classify_mount_error("test", error).is_policy_denial());
        }
    }
}
