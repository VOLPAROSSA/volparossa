//! Fixed root-owned runtime files; no path is accepted from an agent request.

use std::{
    ffi::CString,
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Read, Write},
    os::fd::OwnedFd,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream},
    },
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use nix::poll::PollFlags;
use nix::unistd::{Gid, Group, Uid, User, getegid, geteuid, getgrouplist};
use rand_core::{OsRng, RngCore};
use socket2::{Domain, SockAddr, Socket, Type};
use zeroize::Zeroizing;

use crate::deadline::{HardDeadline, wait_for_fd, wait_for_readable_fd};

/// Dedicated unprivileged system account allowed to call the helper.
pub const AGENT_ACCOUNT: &str = "volparossa";
const OPERATOR_GROUP: &str = "volparossa-users";
/// Dedicated non-login account used only by isolated route workers.
pub const WORKER_ACCOUNT: &str = "volparossa-worker";
/// Root-owned runtime directory, normally created by systemd `RuntimeDirectory=`.
pub const RUNTIME_DIRECTORY: &str = "/run/volparossa";
/// Fixed local helper endpoint.
pub const SOCKET_PATH: &str = "/run/volparossa/helper.sock";
/// Fixed short-lived cleanup capability file readable only by the agent group.
pub const TOKEN_PATH: &str = "/run/volparossa/helper.cleanup-token";

const SHADOW_PATH: &str = "/etc/shadow";
const PASSWD_PATH: &str = "/etc/passwd";
const GROUP_PATH: &str = "/etc/group";
const NSSWITCH_PATH: &str = "/etc/nsswitch.conf";
const SHADOW_GROUP: &str = "shadow";
const MAX_PUBLIC_ACCOUNT_DATABASE_BYTES: usize = 1024 * 1024;
const MAX_NSSWITCH_BYTES: usize = 64 * 1024;
const MAX_ACCOUNT_DATABASE_LINE_BYTES: usize = 4096;
const MAX_SHADOW_BYTES: usize = 1024 * 1024;
const SYSTEMD_RESERVED_ID: u32 = 65_535;
const POSIX_ACCESS_ACL_XATTR: &str = "system.posix_acl_access";
const SOCKET_IDENTITY_PROBE_BYTES: usize = 32;
const SOCKET_IDENTITY_MAX_ACCEPTS: usize = 8;
const SOCKET_IDENTITY_PROBE_TIMEOUT: Duration = Duration::from_millis(250);
const SOCKET_LISTEN_BACKLOG: i32 = 32;

const fn service_identity_id_is_valid(id: u32) -> bool {
    id != 0 && id != SYSTEMD_RESERVED_ID && id != u32::MAX
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalPasswdIdentity<'a> {
    name: &'a [u8],
    password: &'a [u8],
    uid: u32,
    gid: u32,
    gecos: &'a [u8],
    directory: &'a [u8],
    shell: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalGroupIdentity<'a> {
    name: &'a [u8],
    password: &'a [u8],
    gid: u32,
    members: &'a [u8],
}

static PRODUCTION_WORKER_IDENTITY: OnceLock<WorkerAccountIdentity> = OnceLock::new();

/// Numeric identity pinned from the dedicated worker account at helper startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkerAccountIdentity {
    uid: u32,
    gid: u32,
}

impl WorkerAccountIdentity {
    fn new(uid: u32, gid: u32, agent_identity: (u32, u32)) -> Result<Self, io::Error> {
        if !service_identity_id_is_valid(uid)
            || !service_identity_id_is_valid(gid)
            || !service_identity_id_is_valid(agent_identity.0)
            || !service_identity_id_is_valid(agent_identity.1)
            || uid == agent_identity.0
            || gid == agent_identity.1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "worker account must be distinct and unprivileged",
            ));
        }
        Ok(Self { uid, gid })
    }

    pub(crate) const fn uid(self) -> u32 {
        self.uid
    }

    pub(crate) const fn gid(self) -> u32 {
        self.gid
    }
}

pub(crate) struct ProductionRuntime {
    pub(crate) agent_uid: u32,
    pub(crate) agent_gid: u32,
    pub(crate) cleanup_token: Zeroizing<[u8; 32]>,
}

/// Validated production identity and runtime-directory boundary before capability publication.
///
/// Constructing this value may create the fixed systemd runtime directory when it is absent, but
/// it neither creates nor replaces the cleanup token or helper socket. The server deliberately
/// retains this boundary while durable ownership startup either reaches Ready or fails closed.
pub(crate) struct PreparedProductionRuntime {
    agent_uid: u32,
    agent_gid: u32,
}

impl PreparedProductionRuntime {
    /// Publish a fresh cleanup capability only after durable ownership startup is complete.
    pub(crate) fn publish_cleanup_token(self) -> Result<ProductionRuntime, io::Error> {
        let mut cleanup_token = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(cleanup_token.as_mut());
        write_token(
            Path::new(TOKEN_PATH),
            &cleanup_token,
            Uid::from_raw(0),
            Gid::from_raw(self.agent_gid),
        )?;
        Ok(ProductionRuntime {
            agent_uid: self.agent_uid,
            agent_gid: self.agent_gid,
            cleanup_token,
        })
    }
}

struct LocalAccountFiles {
    passwd: Vec<u8>,
    groups: Vec<u8>,
}

struct BoundProductionAccounts {
    agent: User,
    agent_group: Group,
    worker_identity: WorkerAccountIdentity,
}

/// Returns the exact worker identity pinned during production runtime setup.
pub(crate) fn pinned_production_worker_identity() -> Result<WorkerAccountIdentity, io::Error> {
    PRODUCTION_WORKER_IDENTITY.get().copied().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "worker identity was not pinned at helper startup",
        )
    })
}

/// Validate and pin the fixed production identities and runtime directory without publishing a
/// cleanup token or socket.
pub(crate) fn prepare_production_runtime_identity() -> Result<PreparedProductionRuntime, io::Error>
{
    if !geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "volparossa-helper must run as root",
        ));
    }
    let accounts = resolve_bound_production_accounts()?;
    let user = accounts.agent;
    let group = accounts.agent_group;
    let worker_identity = accounts.worker_identity;
    validate_service_group(getegid().as_raw(), group.gid.as_raw())?;
    match PRODUCTION_WORKER_IDENTITY.get() {
        Some(existing) if *existing != worker_identity => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "worker account identity changed during helper startup",
            ));
        }
        Some(_) => {}
        None => PRODUCTION_WORKER_IDENTITY
            .set(worker_identity)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "worker account identity could not be pinned",
                )
            })?,
    }

    let directory = Path::new(RUNTIME_DIRECTORY);
    if !directory.exists() {
        DirBuilder::new().mode(0o750).create(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o750))?;
    }
    validate_directory(directory, 0, group.gid.as_raw())?;

    Ok(PreparedProductionRuntime {
        agent_uid: user.uid.as_raw(),
        agent_gid: group.gid.as_raw(),
    })
}

/// Complete the fixed production runtime setup in one call for the isolated live-proof entry.
pub(crate) fn prepare_production_runtime() -> Result<ProductionRuntime, io::Error> {
    prepare_production_runtime_identity()?.publish_cleanup_token()
}

fn read_validated_local_account_files() -> Result<LocalAccountFiles, io::Error> {
    let nsswitch = read_public_account_database(Path::new(NSSWITCH_PATH), MAX_NSSWITCH_BYTES)?;
    if !nss_files_are_authoritative(&nsswitch) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "account NSS databases must use only the reviewed local files/systemd order",
        ));
    }
    let passwd =
        read_public_account_database(Path::new(PASSWD_PATH), MAX_PUBLIC_ACCOUNT_DATABASE_BYTES)?;
    let groups =
        read_public_account_database(Path::new(GROUP_PATH), MAX_PUBLIC_ACCOUNT_DATABASE_BYTES)?;
    let agent = required_local_passwd(&passwd, AGENT_ACCOUNT)?;
    let worker = required_local_passwd(&passwd, WORKER_ACCOUNT)?;
    let agent_group = required_local_group(&groups, AGENT_ACCOUNT)?;
    let operator_group = required_local_group(&groups, OPERATOR_GROUP)?;
    let worker_group = required_local_group(&groups, WORKER_ACCOUNT)?;
    let shadow_group = required_local_group(&groups, SHADOW_GROUP)?;
    if !local_account_contract_matches(
        agent,
        worker,
        agent_group,
        operator_group,
        worker_group,
        shadow_group,
        &groups,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local service account files do not match the isolated package contract",
        ));
    }
    Ok(LocalAccountFiles { passwd, groups })
}

fn resolve_bound_production_accounts() -> Result<BoundProductionAccounts, io::Error> {
    let files = read_validated_local_account_files()?;
    let local_agent = required_local_passwd(&files.passwd, AGENT_ACCOUNT)?;
    let local_worker = required_local_passwd(&files.passwd, WORKER_ACCOUNT)?;
    let local_agent_group = required_local_group(&files.groups, AGENT_ACCOUNT)?;
    let local_operator_group = required_local_group(&files.groups, OPERATOR_GROUP)?;
    let local_worker_group = required_local_group(&files.groups, WORKER_ACCOUNT)?;
    let local_shadow_group = required_local_group(&files.groups, SHADOW_GROUP)?;
    let agent = resolve_bound_user(AGENT_ACCOUNT, local_agent)?;
    let agent_group = resolve_bound_group(AGENT_ACCOUNT, local_agent_group)?;
    let operator_group = resolve_bound_group(OPERATOR_GROUP, local_operator_group)?;
    let worker = resolve_bound_user(WORKER_ACCOUNT, local_worker)?;
    let worker_group = resolve_bound_group(WORKER_ACCOUNT, local_worker_group)?;
    let shadow_group = resolve_bound_group(SHADOW_GROUP, local_shadow_group)?;
    if agent.gid != agent_group.gid || worker.gid != worker_group.gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service account primary group binding changed during startup",
        ));
    }
    if !account_groups_match(
        AGENT_ACCOUNT,
        agent.gid,
        &[agent_group.gid, operator_group.gid],
    ) || !account_groups_match(WORKER_ACCOUNT, worker.gid, &[worker_group.gid])
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service supplementary groups do not match the isolated local contract",
        ));
    }
    let worker_identity = validate_worker_identity(
        &worker,
        &worker_group,
        (agent.uid.as_raw(), agent_group.gid.as_raw()),
        shadow_group.gid.as_raw(),
    )?;
    validate_locked_shadow_accounts(Path::new(SHADOW_PATH), shadow_group.gid.as_raw())?;
    Ok(BoundProductionAccounts {
        agent,
        agent_group,
        worker_identity,
    })
}

fn required_local_passwd<'a>(
    bytes: &'a [u8],
    account: &str,
) -> Result<LocalPasswdIdentity<'a>, io::Error> {
    local_passwd_identity(bytes, account).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local passwd identity is absent, malformed, duplicated, or aliased",
        )
    })
}

fn required_local_group<'a>(
    bytes: &'a [u8],
    account: &str,
) -> Result<LocalGroupIdentity<'a>, io::Error> {
    local_group_identity(bytes, account).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local group identity is absent, malformed, duplicated, or aliased",
        )
    })
}

fn validate_worker_identity(
    user: &User,
    group: &Group,
    agent_identity: (u32, u32),
    shadow_gid: u32,
) -> Result<WorkerAccountIdentity, io::Error> {
    let identity =
        WorkerAccountIdentity::new(user.uid.as_raw(), group.gid.as_raw(), agent_identity)?;
    if identity.gid() == shadow_gid
        || user.gid != group.gid
        || user.dir != Path::new("/nonexistent")
        || user.shell != Path::new("/usr/sbin/nologin")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "worker account metadata is not the fixed non-login contract",
        ));
    }
    Ok(identity)
}

fn account_groups(account: &str, primary_gid: Gid) -> Result<Vec<Gid>, io::Error> {
    let name = CString::new(account)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "account name is invalid"))?;
    getgrouplist(&name, primary_gid).map_err(errno_io)
}

fn account_groups_match(account: &str, primary_gid: Gid, expected: &[Gid]) -> bool {
    let Ok(mut observed) = account_groups(account, primary_gid) else {
        return false;
    };
    observed.sort_unstable_by_key(|gid| gid.as_raw());
    if observed
        .windows(2)
        .any(|pair| pair[0].as_raw() == pair[1].as_raw())
    {
        return false;
    }
    let mut expected = expected.to_vec();
    expected.sort_unstable_by_key(|gid| gid.as_raw());
    observed == expected
}

fn read_public_account_database(path: &Path, maximum: usize) -> Result<Vec<u8>, io::Error> {
    if maximum == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "account database bound must be nonzero",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || !public_account_database_permissions_are_safe(before.mode())
        || before.len() == 0
        || before.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local account database is not safely readable",
        ));
    }
    let mut bytes = Vec::with_capacity(maximum.saturating_add(1));
    let mut limited = file.take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    let after = limited.into_inner().metadata()?;
    if bytes.len() > maximum
        || u64::try_from(bytes.len()).ok() != Some(before.len())
        || !same_database_snapshot(&before, &after)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local account database is oversized or changed while read",
        ));
    }
    Ok(bytes)
}

fn public_account_database_permissions_are_safe(mode: u32) -> bool {
    let permissions = mode & 0o7777;
    permissions & 0o400 != 0 && permissions & !0o644 == 0
}

fn same_database_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn nss_files_are_authoritative(bytes: &[u8]) -> bool {
    if !database_has_safe_physical_lines(bytes, true) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut seen = [false; 4];
    for raw_line in text.lines() {
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(before, _)| before);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((database, sources)) = line.split_once(':') else {
            continue;
        };
        let index = match database.trim() {
            "passwd" => 0,
            "group" => 1,
            "shadow" => 2,
            "initgroups" => 3,
            _ => continue,
        };
        let mut sources = sources.split_ascii_whitespace();
        let first = sources.next();
        let second = sources.next();
        if seen[index]
            || first != Some("files")
            || !matches!(second, None | Some("systemd"))
            || sources.next().is_some()
        {
            return false;
        }
        seen[index] = true;
    }
    seen[..3].iter().all(|entry| *entry)
}

fn database_has_safe_physical_lines(bytes: &[u8], allow_empty: bool) -> bool {
    if bytes.is_empty() || !bytes.ends_with(b"\n") || bytes.contains(&0) || bytes.contains(&b'\r') {
        return false;
    }
    bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .all(|line| {
            line.len() <= MAX_ACCOUNT_DATABASE_LINE_BYTES && (allow_empty || !line.is_empty())
        })
}

fn parse_canonical_account_id(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || (bytes.len() > 1 && bytes.first() == Some(&b'0')) {
        return None;
    }
    let mut value = 0_u32;
    for byte in bytes {
        let digit = byte.checked_sub(b'0')?;
        if digit > 9 {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(digit))?;
    }
    (value != u32::MAX).then_some(value)
}

fn local_passwd_identity<'a>(bytes: &'a [u8], account: &str) -> Option<LocalPasswdIdentity<'a>> {
    if !database_has_safe_physical_lines(bytes, false) {
        return None;
    }
    let mut found = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        let name = fields.next()?;
        let password = fields.next()?;
        let uid = parse_canonical_account_id(fields.next()?)?;
        let gid = parse_canonical_account_id(fields.next()?)?;
        let gecos = fields.next()?;
        let directory = fields.next()?;
        let shell = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        if name == account.as_bytes() {
            if found.is_some() {
                return None;
            }
            found = Some(LocalPasswdIdentity {
                name,
                password,
                uid,
                gid,
                gecos,
                directory,
                shell,
            });
        }
    }
    let found = found?;
    let mut uid_uses = 0_usize;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        fields.next()?;
        fields.next()?;
        let uid = parse_canonical_account_id(fields.next()?)?;
        if uid == found.uid {
            uid_uses = uid_uses.checked_add(1)?;
        }
    }
    (uid_uses == 1).then_some(found)
}

fn local_group_identity<'a>(bytes: &'a [u8], account: &str) -> Option<LocalGroupIdentity<'a>> {
    if !database_has_safe_physical_lines(bytes, false) {
        return None;
    }
    let mut found = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        let name = fields.next()?;
        let password = fields.next()?;
        let gid = parse_canonical_account_id(fields.next()?)?;
        let members = fields.next()?;
        if fields.next().is_some() || !local_group_member_list_is_canonical(members) {
            return None;
        }
        if name == account.as_bytes() {
            if found.is_some() {
                return None;
            }
            found = Some(LocalGroupIdentity {
                name,
                password,
                gid,
                members,
            });
        }
    }
    let found = found?;
    let mut gid_uses = 0_usize;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        fields.next()?;
        fields.next()?;
        let gid = parse_canonical_account_id(fields.next()?)?;
        if gid == found.gid {
            gid_uses = gid_uses.checked_add(1)?;
        }
    }
    (gid_uses == 1).then_some(found)
}

fn local_group_member_list_is_canonical(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let members = bytes.split(|byte| *byte == b',').collect::<Vec<_>>();
    members.iter().enumerate().all(|(index, member)| {
        !member.is_empty() && !members[..index].iter().any(|earlier| earlier == member)
    })
}

fn local_account_contract_matches(
    agent: LocalPasswdIdentity<'_>,
    worker: LocalPasswdIdentity<'_>,
    agent_group: LocalGroupIdentity<'_>,
    operator_group: LocalGroupIdentity<'_>,
    worker_group: LocalGroupIdentity<'_>,
    shadow_group: LocalGroupIdentity<'_>,
    groups: &[u8],
) -> bool {
    let group_ids = [
        agent_group.gid,
        operator_group.gid,
        worker_group.gid,
        shadow_group.gid,
    ];
    agent.name == AGENT_ACCOUNT.as_bytes()
        && worker.name == WORKER_ACCOUNT.as_bytes()
        && agent.password == b"x"
        && worker.password == b"x"
        && service_identity_id_is_valid(agent.uid)
        && service_identity_id_is_valid(worker.uid)
        && agent.uid != worker.uid
        && agent.gid == agent_group.gid
        && worker.gid == worker_group.gid
        && agent.directory == b"/var/lib/volparossa"
        && worker.directory == b"/nonexistent"
        && agent.shell == b"/usr/sbin/nologin"
        && worker.shell == b"/usr/sbin/nologin"
        && agent_group.name == AGENT_ACCOUNT.as_bytes()
        && operator_group.name == OPERATOR_GROUP.as_bytes()
        && worker_group.name == WORKER_ACCOUNT.as_bytes()
        && shadow_group.name == SHADOW_GROUP.as_bytes()
        && [
            agent_group.password,
            operator_group.password,
            worker_group.password,
            shadow_group.password,
        ]
        .into_iter()
        .all(|password| password == b"x")
        && group_ids.into_iter().all(service_identity_id_is_valid)
        && group_ids
            .iter()
            .enumerate()
            .all(|(index, gid)| !group_ids[..index].contains(gid))
        && agent_group.members.is_empty()
        && worker_group.members.is_empty()
        && group_members_contain(operator_group.members, AGENT_ACCOUNT)
        && !group_members_contain(operator_group.members, WORKER_ACCOUNT)
        && !group_members_contain(shadow_group.members, AGENT_ACCOUNT)
        && !group_members_contain(shadow_group.members, WORKER_ACCOUNT)
        && local_group_ids_match(
            groups,
            AGENT_ACCOUNT,
            agent.gid,
            &[agent_group.gid, operator_group.gid],
        )
        && local_group_ids_match(groups, WORKER_ACCOUNT, worker.gid, &[worker_group.gid])
}

fn local_group_ids_match(bytes: &[u8], account: &str, primary_gid: u32, expected: &[u32]) -> bool {
    let Some(observed) = local_group_ids_for_account(bytes, account, primary_gid) else {
        return false;
    };
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    observed == expected
}

fn local_group_ids_for_account(bytes: &[u8], account: &str, primary_gid: u32) -> Option<Vec<u32>> {
    if !database_has_safe_physical_lines(bytes, false) {
        return None;
    }
    let mut groups = vec![primary_gid];
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        fields.next()?;
        fields.next()?;
        let gid = parse_canonical_account_id(fields.next()?)?;
        let members = fields.next()?;
        if fields.next().is_some() || !local_group_member_list_is_canonical(members) {
            return None;
        }
        if group_members_contain(members, account) {
            groups.push(gid);
        }
    }
    groups.sort_unstable();
    groups.dedup();
    Some(groups)
}

fn group_members_contain(bytes: &[u8], account: &str) -> bool {
    !bytes.is_empty()
        && bytes
            .split(|byte| *byte == b',')
            .any(|member| member == account.as_bytes())
}

fn resolve_bound_user(account: &str, local: LocalPasswdIdentity<'_>) -> Result<User, io::Error> {
    let by_name = User::from_name(account)
        .map_err(errno_io)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "service account missing"))?;
    let by_uid = User::from_uid(Uid::from_raw(local.uid))
        .map_err(errno_io)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "service UID missing"))?;
    if by_name != by_uid || !local_passwd_identity_matches(local, account, &by_name) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "NSS user does not match the unique local account identity",
        ));
    }
    Ok(by_name)
}

fn resolve_bound_group(account: &str, local: LocalGroupIdentity<'_>) -> Result<Group, io::Error> {
    let by_name = Group::from_name(account)
        .map_err(errno_io)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "service group missing"))?;
    let by_gid = Group::from_gid(Gid::from_raw(local.gid))
        .map_err(errno_io)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "service GID missing"))?;
    if by_name != by_gid || !local_group_identity_matches(local, account, &by_name) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "NSS group does not match the unique local group identity",
        ));
    }
    Ok(by_name)
}

fn local_passwd_identity_matches(
    local: LocalPasswdIdentity<'_>,
    account: &str,
    user: &User,
) -> bool {
    user.name == account
        && user.passwd.as_bytes() == local.password
        && user.uid.as_raw() == local.uid
        && user.gid.as_raw() == local.gid
        && user.gecos.as_bytes() == local.gecos
        && user.dir.as_os_str().as_bytes() == local.directory
        && user.shell.as_os_str().as_bytes() == local.shell
}

fn local_group_identity_matches(
    local: LocalGroupIdentity<'_>,
    account: &str,
    group: &Group,
) -> bool {
    group.name == account
        && group.passwd.as_bytes() == local.password
        && group.gid.as_raw() == local.gid
        && local_group_members_match(local.members, &group.mem)
}

fn local_group_members_match(bytes: &[u8], members: &[String]) -> bool {
    if bytes.is_empty() {
        return members.is_empty();
    }
    let mut expected = bytes.split(|byte| *byte == b',');
    for member in members {
        if expected.next() != Some(member.as_bytes()) {
            return false;
        }
    }
    expected.next().is_none()
}

fn validate_posix_access_acl_probe(
    result: Result<usize, rustix::io::Errno>,
) -> Result<(), io::Error> {
    match result {
        Err(error) if error == rustix::io::Errno::NODATA => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadow account database has a POSIX access ACL",
        )),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("shadow POSIX access ACL probe failed: {error}"),
        )),
    }
}

fn validate_no_posix_access_acl(file: &fs::File) -> Result<(), io::Error> {
    // One byte is enough for an existence probe without unsafe code. A present POSIX ACL is larger
    // and returns ERANGE; even a zero/one-byte value returns success. Both paths are rejected. Only
    // explicit absence is accepted; an unsupported ACL query cannot prove exclusivity and fails.
    let mut probe = [0_u8; 1];
    let result = rustix::fs::fgetxattr(file, POSIX_ACCESS_ACL_XATTR, &mut probe[..]);
    validate_posix_access_acl_probe(result)
}

fn validate_locked_shadow_accounts(path: &Path, shadow_gid: u32) -> Result<(), io::Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || !shadow_permissions_are_safe(before.mode(), before.gid(), shadow_gid)
        || before.len() == 0
        || before.len() > u64::try_from(MAX_SHADOW_BYTES).unwrap_or(u64::MAX)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "shadow account database is not safely readable",
        ));
    }
    validate_no_posix_access_acl(&file)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SHADOW_BYTES.saturating_add(1)));
    let mut limited = file.take(
        u64::try_from(MAX_SHADOW_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    );
    limited.read_to_end(&mut bytes)?;
    let after = limited.into_inner().metadata()?;
    if bytes.len() > MAX_SHADOW_BYTES
        || u64::try_from(bytes.len()).ok() != Some(before.len())
        || !same_database_snapshot(&before, &after)
        || !shadow_accounts_match_contract(&bytes)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service shadow accounts are absent, malformed, duplicated, or unlocked",
        ));
    }
    Ok(())
}

fn shadow_permissions_are_safe(mode: u32, gid: u32, shadow_gid: u32) -> bool {
    let permissions = mode & 0o7777;
    permissions & 0o400 != 0
        && permissions & !0o640 == 0
        && (permissions & 0o040 == 0 || gid == shadow_gid)
}

fn shadow_accounts_match_contract(bytes: &[u8]) -> bool {
    if !database_has_safe_physical_lines(bytes, false) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut agent_locked = None;
    let mut worker_locked = None;
    for line in text.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next() else {
            return false;
        };
        let Some(password) = fields.next() else {
            return false;
        };
        let Some(_last_change) = fields.next() else {
            return false;
        };
        let Some(_minimum_age) = fields.next() else {
            return false;
        };
        let Some(_maximum_age) = fields.next() else {
            return false;
        };
        let Some(_warning_period) = fields.next() else {
            return false;
        };
        let Some(_inactivity_period) = fields.next() else {
            return false;
        };
        let Some(account_expiry) = fields.next() else {
            return false;
        };
        let Some(_reserved) = fields.next() else {
            return false;
        };
        if fields.next().is_some() {
            return false;
        }
        if name == AGENT_ACCOUNT {
            if agent_locked.is_some() {
                return false;
            }
            agent_locked = Some(password.starts_with('!'));
        } else if name == WORKER_ACCOUNT {
            if worker_locked.is_some() {
                return false;
            }
            worker_locked = Some(password.starts_with('!') && account_expiry == "1");
        }
    }
    agent_locked == Some(true) && worker_locked == Some(true)
}

pub(crate) fn remove_stale_socket(path: &Path, expected_gid: u32) -> Result<(), io::Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o777 != 0o660
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe pre-existing helper socket",
        ));
    }
    fs::remove_file(path)
}

pub(crate) fn secure_socket(path: &Path, expected_gid: Gid) -> Result<(), io::Error> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != expected_gid.as_raw()
        || metadata.mode() & 0o777 != 0o660
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper socket ownership validation failed",
        ));
    }
    Ok(())
}

fn validate_directory(path: &Path, uid: u32, gid: u32) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != 0o750
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe helper runtime directory",
        ));
    }
    Ok(())
}

fn write_token(path: &Path, token: &[u8; 32], owner: Uid, group: Gid) -> Result<(), io::Error> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_file()
            || metadata.uid() != owner.as_raw()
            || metadata.gid() != group.as_raw()
            || metadata.mode() & 0o777 != 0o640
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe cleanup token file",
            ));
        }
    }
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o640))?;
    file.write_all(token)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if metadata.uid() != owner.as_raw()
        || metadata.gid() != group.as_raw()
        || metadata.mode() & 0o777 != 0o640
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cleanup token ownership validation failed",
        ));
    }
    Ok(())
}

pub(crate) struct SocketPathGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

/// Create the fixed filesystem listener as non-blocking/CLOEXEC and return its exact inode guard.
///
/// Non-blocking mode is selected before `bind`, so no post-bind mode switch can strand an
/// unguarded pathname. The active challenge proves the newly listening descriptor is reachable
/// through the same unchanged filesystem inode before the pair is returned.
pub(crate) fn bind_guarded_nonblocking_socket(
    path: &Path,
    required_owner: u32,
    required_group: u32,
) -> io::Result<(StdUnixListener, SocketPathGuard)> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM.nonblocking().cloexec(), None)?;
    socket.bind(&SockAddr::unix(path)?)?;
    let guard = SocketPathGuard::capture_created(path, required_owner, required_group)?;
    socket.listen(SOCKET_LISTEN_BACKLOG)?;
    let descriptor: OwnedFd = socket.into();
    let listener = StdUnixListener::from(descriptor);
    guard.verify_listener(&listener)?;
    Ok((listener, guard))
}

impl SocketPathGuard {
    fn capture_created(path: &Path, required_owner: u32, required_group: u32) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != required_owner
            || metadata.gid() != required_group
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bound helper socket identity is unsafe",
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn verify_listener(&self, listener: &StdUnixListener) -> io::Result<()> {
        let identity = exact_bound_socket_identity(listener, &self.path)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bound helper socket pathname does not identify its listener",
            )
        })?;
        if identity.device != self.device || identity.inode != self.inode {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bound helper socket inode changed during listener proof",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundSocketIdentity {
    device: u64,
    inode: u64,
}

fn exact_bound_socket_identity(
    listener: &StdUnixListener,
    path: &Path,
) -> io::Result<Option<BoundSocketIdentity>> {
    if listener.local_addr()?.as_pathname() != Some(path) {
        return Ok(None);
    }
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_socket() {
        return Ok(None);
    }
    let deadline = HardDeadline::after(SOCKET_IDENTITY_PROBE_TIMEOUT)?;
    let mut challenge = Zeroizing::new([0_u8; SOCKET_IDENTITY_PROBE_BYTES]);
    OsRng.fill_bytes(challenge.as_mut());
    let mut probe = connect_socket_probe(path, deadline)?;
    write_all_until(&mut probe, challenge.as_ref(), deadline)?;
    let mut matched = false;
    for _ in 0..SOCKET_IDENTITY_MAX_ACCEPTS {
        deadline.ensure_remaining()?;
        let (mut accepted, _) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        };
        accepted.set_nonblocking(true)?;
        let mut observed = Zeroizing::new([0_u8; SOCKET_IDENTITY_PROBE_BYTES]);
        read_exact_until(&mut accepted, observed.as_mut(), deadline)?;
        if observed.as_ref() == challenge.as_ref() {
            matched = true;
            break;
        }
    }
    if !matched {
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.dev() != before.dev()
        || metadata.ino() != before.ino()
    {
        return Ok(None);
    }
    Ok(Some(BoundSocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }))
}

fn connect_socket_probe(path: &Path, deadline: HardDeadline) -> io::Result<StdUnixStream> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM.nonblocking().cloexec(), None)?;
    let address = SockAddr::unix(path)?;
    match socket.connect(&address) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(code) if code == libc::EINPROGRESS || code == libc::EALREADY
            ) =>
        {
            wait_for_fd(&socket, PollFlags::POLLOUT, deadline)?;
        }
        Err(error) => return Err(error),
    }
    if let Some(error) = socket.take_error()? {
        return Err(error);
    }
    deadline.ensure_remaining()?;
    let descriptor: OwnedFd = socket.into();
    Ok(StdUnixStream::from(descriptor))
}

fn write_all_until(
    stream: &mut StdUnixStream,
    mut bytes: &[u8],
    deadline: HardDeadline,
) -> io::Result<()> {
    while !bytes.is_empty() {
        wait_for_fd(stream, PollFlags::POLLOUT, deadline)?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket probe closed",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    deadline.ensure_remaining()
}

fn read_exact_until(
    stream: &mut StdUnixStream,
    mut bytes: &mut [u8],
    deadline: HardDeadline,
) -> io::Result<()> {
    while !bytes.is_empty() {
        wait_for_readable_fd(stream, deadline)?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    deadline.ensure_remaining()
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validate_service_group(effective_gid: u32, agent_gid: u32) -> Result<(), io::Error> {
    if effective_gid != agent_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper effective group must be the dedicated agent group",
        ));
    }
    Ok(())
}

fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{getegid, geteuid};
    use std::fs::File;

    fn valid_posix_access_acl() -> [u8; 36] {
        let mut acl = [0_u8; 36];
        acl[0..4].copy_from_slice(&2_u32.to_le_bytes());
        for (index, (tag, permission)) in [(1_u16, 0o6_u16), (4, 0o6), (16, 0o4), (32, 0)]
            .into_iter()
            .enumerate()
        {
            let offset = 4 + index * 8;
            acl[offset..offset + 2].copy_from_slice(&tag.to_le_bytes());
            acl[offset + 2..offset + 4].copy_from_slice(&permission.to_le_bytes());
            acl[offset + 4..offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        acl
    }

    #[test]
    fn runtime_directory_validation_rejects_world_access() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
            .expect("permissions");
        validate_directory(directory.path(), geteuid().as_raw(), getegid().as_raw())
            .expect("secure directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))
            .expect("permissions");
        assert!(
            validate_directory(directory.path(), geteuid().as_raw(), getegid().as_raw(),).is_err()
        );
    }

    #[test]
    fn service_group_must_match_the_agent_group_without_chown_capability() {
        let agent_gid = getegid().as_raw();
        validate_service_group(agent_gid, agent_gid).expect("matching service group");
        assert!(validate_service_group(agent_gid.wrapping_add(1), agent_gid).is_err());
    }

    #[test]
    fn worker_identity_is_nonroot_and_distinct_from_the_agent() {
        let identity = WorkerAccountIdentity::new(20_001, 20_002, (20_003, 20_004))
            .expect("dedicated worker identity");
        assert_eq!(identity.uid(), 20_001);
        assert_eq!(identity.gid(), 20_002);
        for (uid, gid, agent_identity) in [
            (0, 20_002, (20_003, 20_004)),
            (20_001, 0, (20_003, 20_004)),
            (SYSTEMD_RESERVED_ID, 20_002, (20_003, 20_004)),
            (20_001, SYSTEMD_RESERVED_ID, (20_003, 20_004)),
            (u32::MAX, 20_002, (20_003, 20_004)),
            (20_001, u32::MAX, (20_003, 20_004)),
            (20_001, 20_002, (SYSTEMD_RESERVED_ID, 20_004)),
            (20_001, 20_002, (20_003, SYSTEMD_RESERVED_ID)),
            (20_003, 20_002, (20_003, 20_004)),
            (20_001, 20_004, (20_003, 20_004)),
        ] {
            assert!(WorkerAccountIdentity::new(uid, gid, agent_identity).is_err());
        }
    }

    #[test]
    fn shadow_permissions_exclude_mutation_execution_world_access_and_wrong_groups() {
        let shadow_gid = 42;
        for mode in [0o400, 0o440, 0o600, 0o640] {
            assert!(shadow_permissions_are_safe(mode, shadow_gid, shadow_gid));
        }
        assert!(shadow_permissions_are_safe(0o600, 12_345, shadow_gid));
        for mode in [0o000, 0o200, 0o660, 0o700, 0o644, 0o4640] {
            assert!(!shadow_permissions_are_safe(mode, shadow_gid, shadow_gid));
        }
        assert!(!shadow_permissions_are_safe(0o640, 12_345, shadow_gid));
    }

    #[test]
    fn shadow_posix_access_acl_probe_is_explicit_and_fail_closed() {
        validate_posix_access_acl_probe(Err(rustix::io::Errno::NODATA))
            .expect("explicitly absent access ACL");
        for result in [
            Ok(0),
            Ok(1),
            Ok(36),
            Err(rustix::io::Errno::RANGE),
            Err(rustix::io::Errno::NOTSUP),
            Err(rustix::io::Errno::OPNOTSUPP),
            Err(rustix::io::Errno::ACCESS),
            Err(rustix::io::Errno::PERM),
            Err(rustix::io::Errno::IO),
            Err(rustix::io::Errno::NOSYS),
        ] {
            assert!(validate_posix_access_acl_probe(result).is_err());
        }

        let directory = tempfile::tempdir().expect("temporary directory");
        let file = File::create(directory.path().join("shadow")).expect("temporary shadow file");
        match rustix::fs::fsetxattr(
            &file,
            POSIX_ACCESS_ACL_XATTR,
            &valid_posix_access_acl(),
            rustix::fs::XattrFlags::empty(),
        ) {
            Ok(()) => {
                let error = validate_no_posix_access_acl(&file)
                    .expect_err("an installed access ACL must be rejected");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
            Err(error)
                if error == rustix::io::Errno::NOTSUP || error == rustix::io::Errno::OPNOTSUPP =>
            {
                let error = validate_no_posix_access_acl(&file)
                    .expect_err("unsupported ACL inspection must fail closed");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
            Err(error) => panic!("valid access ACL fixture failed: {error}"),
        }
    }

    #[test]
    fn public_account_database_modes_are_root_mutable_but_never_broadly_writable() {
        for mode in [0o400, 0o404, 0o440, 0o444, 0o600, 0o604, 0o640, 0o644] {
            assert!(public_account_database_permissions_are_safe(mode));
        }
        for mode in [0o000, 0o200, 0o666, 0o700, 0o4644] {
            assert!(!public_account_database_permissions_are_safe(mode));
        }
    }

    #[test]
    fn nss_account_databases_allow_only_the_reviewed_local_source_order() {
        for valid in [
            b"passwd: files systemd\ngroup: files systemd\nshadow: files systemd\n".as_slice(),
            b"# local only\npasswd: files\ngroup: files\nshadow: files\ninitgroups: files\n",
        ] {
            assert!(nss_files_are_authoritative(valid));
        }
        for invalid in [
            b"passwd: sss files\ngroup: files systemd\nshadow: files systemd\n".as_slice(),
            b"passwd: files [SUCCESS=continue] sss\ngroup: files\nshadow: files\n",
            b"passwd: files\ngroup: files\n",
            b"passwd: files\npasswd: files\ngroup: files\nshadow: files\n",
            b"passwd: files\ngroup: ldap files\nshadow: files\n",
            b"passwd: files sss\ngroup: files\nshadow: files\n",
            b"passwd: files\ngroup: files\nshadow: files\ninitgroups: sss files\n",
            b"passwd: files\ngroup: files\nshadow: files",
            &[0xff],
        ] {
            assert!(!nss_files_are_authoritative(invalid));
        }
    }

    #[test]
    fn local_account_parsers_require_unique_canonical_exact_records() {
        let passwd = concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "volparossa-worker:x:20001:20002:worker:/nonexistent:/usr/sbin/nologin\n",
        );
        assert_eq!(
            local_passwd_identity(passwd.as_bytes(), WORKER_ACCOUNT),
            Some(LocalPasswdIdentity {
                name: b"volparossa-worker",
                password: b"x",
                uid: 20_001,
                gid: 20_002,
                gecos: b"worker",
                directory: b"/nonexistent",
                shell: b"/usr/sbin/nologin",
            })
        );
        let group = "volparossa-worker:x:20002:\n";
        assert_eq!(
            local_group_identity(group.as_bytes(), WORKER_ACCOUNT),
            Some(LocalGroupIdentity {
                name: b"volparossa-worker",
                password: b"x",
                gid: 20_002,
                members: b"",
            })
        );
        for invalid in [
            "volparossa-worker:x:020001:20002:worker:/nonexistent:/usr/sbin/nologin\n",
            "volparossa-worker:x:20001:20002:worker:/nonexistent:/usr/sbin/nologin\nvolparossa-worker:x:20001:20002:worker:/nonexistent:/usr/sbin/nologin\n",
            "volparossa-worker:x:4294967295:20002:worker:/nonexistent:/usr/sbin/nologin\n",
            "volparossa-worker:x:20001:20002:worker:/nonexistent\n",
            "alias:x:20001:30000:alias:/nonexistent:/usr/sbin/nologin\nvolparossa-worker:x:20001:20002:worker:/nonexistent:/usr/sbin/nologin\n",
            "volparossa-worker:x:20001:20002:worker:/nonexistent:/usr/sbin/nologin",
            "volparossa-worker:x:20001:20002:worker:/nonexistent:/usr/sbin/nologin\n\n",
        ] {
            assert!(local_passwd_identity(invalid.as_bytes(), WORKER_ACCOUNT).is_none());
        }
        for invalid in [
            "volparossa-worker:x:020002:\n",
            "volparossa-worker:x:20002:\nvolparossa-worker:x:20002:\n",
            "volparossa-worker:x:4294967295:\n",
            "volparossa-worker:x:20002\n",
            "alias:x:20002:\nvolparossa-worker:x:20002:\n",
            "volparossa-worker:x:20002:member,member\n",
        ] {
            assert!(local_group_identity(invalid.as_bytes(), WORKER_ACCOUNT).is_none());
        }
    }

    #[test]
    fn local_identity_contract_is_role_exact_and_group_isolated() {
        let passwd = concat!(
            "volparossa:x:20001:20011:agent:/var/lib/volparossa:/usr/sbin/nologin\n",
            "volparossa-worker:x:20002:20012:worker:/nonexistent:/usr/sbin/nologin\n",
        );
        let groups = concat!(
            "volparossa:x:20011:\n",
            "volparossa-users:x:20013:volparossa\n",
            "volparossa-worker:x:20012:\n",
            "shadow:x:42:\n",
        );
        let contract = |group_bytes: &[u8]| {
            let Some(agent_group) = local_group_identity(group_bytes, AGENT_ACCOUNT) else {
                return false;
            };
            let Some(operator_group) = local_group_identity(group_bytes, OPERATOR_GROUP) else {
                return false;
            };
            let Some(worker_group) = local_group_identity(group_bytes, WORKER_ACCOUNT) else {
                return false;
            };
            let Some(shadow_group) = local_group_identity(group_bytes, SHADOW_GROUP) else {
                return false;
            };
            local_account_contract_matches(
                local_passwd_identity(passwd.as_bytes(), AGENT_ACCOUNT).expect("agent"),
                local_passwd_identity(passwd.as_bytes(), WORKER_ACCOUNT).expect("worker"),
                agent_group,
                operator_group,
                worker_group,
                shadow_group,
                group_bytes,
            )
        };
        assert!(contract(groups.as_bytes()));
        assert!(contract(
            groups
                .replace(
                    "volparossa-users:x:20013:volparossa",
                    "volparossa-users:x:20013:volparossa,alice",
                )
                .as_bytes()
        ));
        for reserved_passwd in [
            passwd.replace("volparossa:x:20001:", "volparossa:x:65535:"),
            passwd.replace("volparossa-worker:x:20002:", "volparossa-worker:x:65535:"),
        ] {
            assert!(!local_account_contract_matches(
                local_passwd_identity(reserved_passwd.as_bytes(), AGENT_ACCOUNT).expect("agent"),
                local_passwd_identity(reserved_passwd.as_bytes(), WORKER_ACCOUNT).expect("worker"),
                local_group_identity(groups.as_bytes(), AGENT_ACCOUNT).expect("agent group"),
                local_group_identity(groups.as_bytes(), OPERATOR_GROUP).expect("operator group"),
                local_group_identity(groups.as_bytes(), WORKER_ACCOUNT).expect("worker group"),
                local_group_identity(groups.as_bytes(), SHADOW_GROUP).expect("shadow group"),
                groups.as_bytes(),
            ));
        }
        for reserved_group in [
            groups.replace("volparossa:x:20011:", "volparossa:x:65535:"),
            groups.replace("volparossa-users:x:20013:", "volparossa-users:x:65535:"),
            groups.replace("volparossa-worker:x:20012:", "volparossa-worker:x:65535:"),
            groups.replace("shadow:x:42:", "shadow:x:65535:"),
        ] {
            assert!(!contract(reserved_group.as_bytes()));
        }
        for unsafe_groups in [
            groups.replace("shadow:x:42:", "shadow:x:42:volparossa-worker"),
            groups.replace("shadow:x:42:", "shadow:x:42:volparossa"),
            groups.replace(
                "volparossa-worker:x:20012:",
                "volparossa-worker:x:20012:alias",
            ),
            format!("{groups}extra:x:20014:volparossa-worker\n"),
            groups.replace(
                "volparossa-users:x:20013:volparossa",
                "volparossa-users:x:20013:",
            ),
            groups.replace(
                "volparossa-users:x:20013:volparossa",
                "volparossa-users:x:20013:volparossa,volparossa-worker",
            ),
            groups.replace(
                "volparossa-users:x:20013:volparossa",
                "volparossa-users:x:20013:volparossa,volparossa",
            ),
        ] {
            assert!(!contract(unsafe_groups.as_bytes()));
        }
    }

    #[test]
    fn service_shadow_entries_bind_locked_agent_and_account_locked_worker() {
        let shadow = |agent_password: &str, worker_password: &str| {
            format!(
                "root:*:20000:0:99999:7:::\n{AGENT_ACCOUNT}:{agent_password}:20000::::::\n{WORKER_ACCOUNT}:{worker_password}:20000:::::1:\n"
            )
        };
        for agent_password in ["!", "!!", "!$y$j9T$disabled", "!*"] {
            for worker_password in ["!", "!!", "!$y$j9T$disabled", "!*"] {
                assert!(shadow_accounts_match_contract(
                    shadow(agent_password, worker_password).as_bytes()
                ));
            }
        }
        for shadow in [
            shadow("$6$live", "!*"),
            shadow("*", "!*"),
            shadow("", "!*"),
            shadow("!*", "$6$live"),
            shadow("!*", "*"),
            shadow("!*", ""),
            format!("{AGENT_ACCOUNT}:!*:20000::::::\n{WORKER_ACCOUNT}:!*:20000::::::\n"),
            format!("{AGENT_ACCOUNT}:!*:20000::::::\n"),
            format!("{WORKER_ACCOUNT}:!*:20000:::::1:\n"),
            format!(
                "{AGENT_ACCOUNT}:!*:20000::::::\n{AGENT_ACCOUNT}:!:20000::::::\n{WORKER_ACCOUNT}:!*:20000:::::1:\n"
            ),
            format!(
                "{AGENT_ACCOUNT}:!*:20000::::::\n{WORKER_ACCOUNT}:!*:20000:::::1:\n{WORKER_ACCOUNT}:!:20000:::::1:\n"
            ),
            format!("{AGENT_ACCOUNT}:!*:20000::::::\n{WORKER_ACCOUNT}:!:20000:::::1"),
            "root:*:20000:0:99999:7:::\n".to_owned(),
        ] {
            assert!(!shadow_accounts_match_contract(shadow.as_bytes()));
        }
        assert!(!shadow_accounts_match_contract(&[0xff]));
    }

    #[test]
    fn token_creation_restores_exact_mode_without_chown() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("helper.cleanup-token");
        write_token(&path, &[7; 32], geteuid(), getegid()).expect("token");
        let metadata = fs::symlink_metadata(path).expect("metadata");
        assert_eq!(metadata.uid(), geteuid().as_raw());
        assert_eq!(metadata.gid(), getegid().as_raw());
        assert_eq!(metadata.mode() & 0o777, 0o640);
    }

    #[test]
    fn identity_preparation_cannot_publish_the_cleanup_capability() {
        let source = include_str!("runtime.rs");
        let start = source
            .find("pub(crate) fn prepare_production_runtime_identity")
            .expect("identity preparation");
        let end = source[start..]
            .find("/// Complete the fixed production runtime setup")
            .map(|offset| start + offset)
            .expect("publication boundary");
        let identity_phase = &source[start..end];
        assert!(!identity_phase.contains("write_token"));
        assert!(!identity_phase.contains("OsRng.fill_bytes"));

        let publication = source
            .split("impl PreparedProductionRuntime")
            .nth(1)
            .expect("prepared-runtime consumer");
        assert!(publication.contains("pub(crate) fn publish_cleanup_token(self)"));
        assert!(publication.contains("write_token"));
    }

    #[test]
    fn stale_cleanup_refuses_regular_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("helper.sock");
        File::create(&path).expect("file");
        assert!(remove_stale_socket(&path, getegid().as_raw()).is_err());
        assert!(path.exists());
    }

    #[test]
    fn socket_guard_removes_only_the_exact_captured_inode() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("helper.sock");
        let (original, guard) =
            bind_guarded_nonblocking_socket(&path, geteuid().as_raw(), getegid().as_raw())
                .expect("guarded original socket");
        assert_eq!(
            original
                .accept()
                .expect_err("listener must already be non-blocking")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        fs::remove_file(&path).expect("unlink original pathname");
        let (replacement, replacement_guard) =
            bind_guarded_nonblocking_socket(&path, geteuid().as_raw(), getegid().as_raw())
                .expect("guarded replacement socket");
        drop(guard);
        assert!(path.exists(), "a substituted inode must never be removed");
        drop(replacement_guard);
        drop(replacement);
        assert!(!path.exists());
        drop(original);

        let (owned, guard) =
            bind_guarded_nonblocking_socket(&path, geteuid().as_raw(), getegid().as_raw())
                .expect("guarded owned socket");
        drop(guard);
        assert!(!path.exists(), "the exact captured inode must be removed");
        drop(owned);
    }

    #[test]
    fn socket_guard_rejects_and_never_unlinks_a_pre_capture_substitution() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("helper.sock");
        let original = StdUnixListener::bind(&path).expect("original socket");
        original
            .set_nonblocking(true)
            .expect("non-blocking original");
        let original_guard =
            SocketPathGuard::capture_created(&path, geteuid().as_raw(), getegid().as_raw())
                .expect("capture created original inode");
        let mut queued_original = StdUnixStream::connect(&path).expect("queued original client");
        queued_original
            .write_all(&[0xa5_u8; SOCKET_IDENTITY_PROBE_BYTES])
            .expect("queued mismatched proof");
        fs::remove_file(&path).expect("unlink original pathname");
        let replacement = StdUnixListener::bind(&path).expect("replacement socket");
        replacement
            .set_nonblocking(true)
            .expect("non-blocking replacement");

        assert!(original_guard.verify_listener(&original).is_err());
        drop(original_guard);
        assert!(path.exists(), "the replacement pathname must remain");

        let guard = SocketPathGuard::capture_created(&path, geteuid().as_raw(), getegid().as_raw())
            .expect("capture replacement inode");
        guard
            .verify_listener(&replacement)
            .expect("prove replacement listener");
        drop(guard);
        assert!(!path.exists());
        drop(queued_original);
        drop(replacement);
        drop(original);
    }
}
