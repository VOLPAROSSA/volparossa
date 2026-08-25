//! Minimal safe wrappers around Linux UAPI calls not exposed by the standard library.
//!
//! The only unsafe operations are the audited `getsockopt(2)` call in [`mptcp_info`], the fixed
//! nsfs `ioctl(2)` calls in [`namespace_type`] and [`owning_user_namespace`], taking immediate
//! RAII ownership of descriptors installed by the bounded receive helpers, the
//! [`install_close_range_on_exec`] process hook, the read-only
//! [`ensure_waitable_sigchld_disposition`] and
//! [`ensure_default_lifecycle_signal_dispositions`] queries, the fixed
//! [`install_pid_one_lifecycle_signal_handlers`] and
//! [`verify_pid_one_lifecycle_signal_handlers`] signal-action calls, and
//! [`install_worker_confinement_filter`].
//! The process hook performs exactly one async-signal-safe `close_range(2)` syscall between
//! `fork` and `exec`. The seccomp wrapper installs one fixed amd64 classic-BPF program and accepts
//! no caller-controlled filter, action, syscall number, flag, or pointer.
//! The PID-1 signal wrapper installs and reads back only the fixed `SIGHUP`, `SIGINT`, and
//! `SIGTERM` emergency dispositions; its handler can only call `_exit(2)`.
//! The nsfs wrappers use the exact Debian 13 `<linux/nsfs.h>` request values and expose no
//! caller-controlled ioctl request or argument. A returned owning-user-namespace descriptor is
//! placed in [`OwnedFd`] immediately, then required to be read-only, close-on-exec, and a user
//! namespace before it is returned.
//! The MPTCP buffer uses the exact Debian 13 `/usr/include/linux/mptcp.h`
//! `struct mptcp_info` layout, is fully initialized before FFI, and its returned
//! length is checked before any field is trusted.

#![cfg(target_os = "linux")]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    io::{self, IoSlice, IoSliceMut},
    mem,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::process::CommandExt,
    },
    process::Command,
};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockType, SockaddrIn, SockaddrIn6,
    SockaddrStorage, getsockopt, recvmsg, sendmsg, sockopt,
};

use socket2::{Domain, Protocol, SockRef, Type};
/// `SOL_MPTCP` from the Linux socket UAPI.
const SOL_MPTCP: libc::c_int = 284;
/// `MPTCP_INFO` from `<linux/mptcp.h>`.
const MPTCP_INFO: libc::c_int = 1;
/// `NS_GET_USERNS` from the Debian 13 `<linux/nsfs.h>` UAPI.
const NS_GET_USERNS: libc::c_ulong = 0xb701;
/// `NS_GET_NSTYPE` from the Debian 13 `<linux/nsfs.h>` UAPI.
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const MPTCP_INFO_FLAG_FALLBACK: u32 = 1 << 0;
const MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED: u32 = 1 << 1;
const MAX_HANDOFF_FDS: usize = 2;
const MAX_HANDOFF_BINDING_BYTES: usize = 256;
const MAX_SEQPACKET_BYTES: usize = 1024 * 1024;
const CLOSE_RANGE_UNSHARE_AND_CLOEXEC: libc::c_uint =
    libc::CLOSE_RANGE_UNSHARE | libc::CLOSE_RANGE_CLOEXEC;
const PID_ONE_LIFECYCLE_SIGNALS: [libc::c_int; 3] = [libc::SIGHUP, libc::SIGINT, libc::SIGTERM];
const PID_ONE_LIFECYCLE_MASK_BITS: u64 = signal_bit(libc::SIGHUP)
    | signal_bit(libc::SIGINT)
    | signal_bit(libc::SIGTERM)
    | signal_bit(libc::SIGCHLD);

// glibc's amd64 `sigaction(2)` trampoline adds this Linux-internal flag to the action returned by
// an exact readback. It is not caller selectable through this API and does not alter delivery.
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const LIBC_SIGACTION_READBACK_FLAGS: libc::c_int = libc::SA_RESTART | 0x0400_0000;
#[cfg(not(all(target_arch = "x86_64", target_pointer_width = "64")))]
const LIBC_SIGACTION_READBACK_FLAGS: libc::c_int = libc::SA_RESTART;

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const SECCOMP_DATA_SYSCALL_OFFSET: u32 = 0;
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const WORKER_CONFINEMENT_FILTER_LENGTH: usize = 14;

/// Returns the Linux clone flag identifying an nsfs namespace descriptor.
///
/// The fixed `NS_GET_NSTYPE` ioctl accepts no argument and cannot be selected by the caller.
/// Known results include `CLONE_NEWNET`, `CLONE_NEWUSER`, and the other namespace flags defined
/// by the Linux clone UAPI. The borrowed descriptor remains owned by the caller.
///
/// # Errors
///
/// Returns the kernel error, including `ENOTTY` when the descriptor is not an nsfs namespace.
pub fn namespace_type<Fd: AsFd>(namespace: &Fd) -> io::Result<libc::c_int> {
    // SAFETY: the descriptor remains borrowed and live for the duration of the call. The ioctl
    // request is the fixed, argument-free Debian 13 `NS_GET_NSTYPE` value; no request, pointer,
    // length, or argument is caller controlled.
    let result = unsafe { libc::ioctl(namespace.as_fd().as_raw_fd(), NS_GET_NSTYPE) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

/// Opens and validates the user namespace that owns an nsfs namespace descriptor.
///
/// The fixed `NS_GET_USERNS` ioctl accepts no argument. On success, ownership of its returned
/// descriptor moves immediately into [`OwnedFd`], so every later validation failure closes it.
/// The descriptor is returned only when kernel readback proves `FD_CLOEXEC`, read-only access,
/// and namespace type `CLONE_NEWUSER`.
///
/// # Errors
///
/// Returns the kernel error when the owner cannot be opened or descriptor flags cannot be read,
/// and `InvalidData` when the returned descriptor lacks any required invariant.
pub fn owning_user_namespace<Fd: AsFd>(namespace: &Fd) -> io::Result<OwnedFd> {
    // SAFETY: the input descriptor remains borrowed and live for the duration of the call. The
    // ioctl request is the fixed, argument-free Debian 13 `NS_GET_USERNS` value; no request,
    // pointer, length, or argument is caller controlled.
    let result = unsafe { libc::ioctl(namespace.as_fd().as_raw_fd(), NS_GET_USERNS) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: successful `NS_GET_USERNS` returns a new descriptor owned by the caller. This is
    // deliberately the first operation after the success check, before any fallible validation.
    let owner = unsafe { OwnedFd::from_raw_fd(result) };
    let descriptor_flags =
        FdFlag::from_bits_truncate(fcntl(&owner, FcntlArg::F_GETFD).map_err(errno_io)?);
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC) {
        return Err(invalid_data(
            "owning user namespace descriptor is not close-on-exec",
        ));
    }
    let status_flags =
        OFlag::from_bits_truncate(fcntl(&owner, FcntlArg::F_GETFL).map_err(errno_io)?);
    if status_flags & OFlag::O_ACCMODE != OFlag::O_RDONLY {
        return Err(invalid_data(
            "owning user namespace descriptor is not read-only",
        ));
    }
    if namespace_type(&owner)? != libc::CLONE_NEWUSER {
        return Err(invalid_data(
            "owning user namespace descriptor has the wrong namespace type",
        ));
    }

    Ok(owner)
}

/// Installs an exec-time inherited-descriptor fence on a child command.
///
/// Immediately before `execve(2)`, the child makes exactly one
/// `close_range(3, UINT_MAX, CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC)` syscall.
/// `UNSHARE` gives the child a private descriptor table before applying `CLOEXEC`, closing the
/// cross-thread inheritance race without closing the standard library's pre-exec error channel.
/// The kernel must support both flags; any syscall error aborts `Command::spawn` fail closed.
/// This must be the last user-installed pre-exec hook on the command; callers must not append a
/// hook that can open or duplicate another descriptor after this fence.
///
/// A kernel error is returned by the later `Command::spawn` call.
pub fn install_close_range_on_exec(command: &mut Command) {
    // SAFETY: `pre_exec` is confined to this audited UAPI crate. The closure captures no state and
    // performs exactly one raw Linux syscall, followed only by errno conversion on failure. It
    // allocates nothing, takes no lock, and touches no inherited Rust state.
    unsafe {
        command.pre_exec(move || {
            let result = libc::syscall(
                libc::SYS_close_range,
                3_u32,
                libc::c_uint::MAX,
                CLOSE_RANGE_UNSHARE_AND_CLOEXEC,
            );
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
}

/// Require the current process to retain ordinary waitable child exit status.
///
/// A fixed child owner cannot prove exact reaping when `SIGCHLD` is ignored, a
/// handler can concurrently call `waitpid(2)`, or `SA_NOCLDWAIT` discards exit
/// status. This read-only query therefore accepts only the default `SIGCHLD`
/// disposition without `SA_NOCLDWAIT`. Callers must separately guarantee that
/// no concurrent thread can change the disposition after this check.
///
/// # Errors
///
/// Returns the kernel error when the action cannot be queried, or
/// `PermissionDenied` when the disposition cannot support exclusive reaping.
pub fn ensure_waitable_sigchld_disposition() -> io::Result<()> {
    let mut action = mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: a null `act` makes this a read-only query. `action` points to
    // writable storage of the exact libc type and is read only after the
    // kernel reports success and has initialized it.
    let result = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `sigaction` initialized the complete output object.
    let action = unsafe { action.assume_init() };
    classify_sigchld_action(action.sa_sigaction, action.sa_flags)
}

fn classify_sigchld_action(handler: libc::sighandler_t, flags: libc::c_int) -> io::Result<()> {
    if handler != libc::SIG_DFL || flags & libc::SA_NOCLDWAIT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "inherited SIGCHLD disposition prevents exact child reaping",
        ));
    }
    Ok(())
}

/// Require exact default dispositions for the fixed lifecycle signals.
///
/// An ignored disposition survives `execve(2)` and causes Linux to discard that signal instead
/// of making it pending for a later `signalfd(2)` read. This read-only admission check therefore
/// requires `SIGHUP`, `SIGINT`, and `SIGTERM` to each have the exact kernel default handler, an
/// empty action mask, and zero action flags. Custom handlers and otherwise inert extra action
/// state are rejected so the synchronous supervisor starts from one canonical process state.
///
/// Callers must remain single-threaded (or otherwise exclude concurrent disposition changes),
/// perform this check before changing their signal mask, and fail closed if it returns an error.
///
/// # Errors
///
/// Returns the first kernel query error, an `InvalidData` error for an invalid signal-set
/// readback, or `PermissionDenied` when any fixed lifecycle action is not exactly default.
pub fn ensure_default_lifecycle_signal_dispositions() -> io::Result<()> {
    for signal in PID_ONE_LIFECYCLE_SIGNALS {
        classify_default_lifecycle_action(read_signal_action(signal)?)?;
    }
    Ok(())
}

/// Installs the fixed emergency dispositions required by a PID-namespace init process.
///
/// Linux gives namespace PID 1 special default signal semantics, so `SIGHUP`, `SIGINT`, and
/// `SIGTERM` need real handlers even while the normal lifecycle path consumes blocked signals
/// synchronously. Each fixed action uses `SA_RESTART` and blocks exactly `SIGHUP`, `SIGINT`,
/// `SIGTERM`, and `SIGCHLD` while its handler runs. The emergency handler performs only the
/// async-signal-safe `_exit(128 + signal)` operation. Thus an accidentally unblocked managed
/// signal cannot leave PID 1 alive outside the supervised lifecycle path.
///
/// This API accepts no signal number, handler, mask, or action flags. The caller must block the
/// three lifecycle signals before installation, remain single-threaded (or otherwise exclude
/// concurrent disposition changes), and fail closed if this function returns an error. A
/// successful installation includes an exact kernel readback through
/// [`verify_pid_one_lifecycle_signal_handlers`].
///
/// # Errors
///
/// Returns the first kernel error while constructing or installing the fixed actions, or the
/// verification error if their immediate kernel readback is not exact.
pub fn install_pid_one_lifecycle_signal_handlers() -> io::Result<()> {
    let action = fixed_pid_one_lifecycle_action()?;
    for signal in PID_ONE_LIFECYCLE_SIGNALS {
        // SAFETY: `signal` comes only from the fixed array above and `action` is a fully
        // initialized fixed action whose function pointer, mask, and flags are not caller
        // controlled. A null old-action pointer requests no inherited pointer back from libc.
        let result = unsafe { libc::sigaction(signal, &raw const action, std::ptr::null_mut()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    verify_pid_one_lifecycle_signal_handlers()
}

/// Verifies the exact fixed PID-1 lifecycle dispositions by kernel readback.
///
/// The handler identity, `SA_RESTART` flags, and complete valid-signal mask must match for each of
/// `SIGHUP`, `SIGINT`, and `SIGTERM`. On Debian 13 amd64, the verifier also requires the fixed
/// libc-provided `SA_RESTORER` trampoline flag. Any extra or missing action property fails closed.
/// Callers must exclude concurrent signal-disposition changes for the duration of the query.
///
/// # Errors
///
/// Returns the first kernel query error, an `InvalidData` error for an invalid signal-set
/// readback, or `PermissionDenied` when any fixed action property differs.
pub fn verify_pid_one_lifecycle_signal_handlers() -> io::Result<()> {
    for signal in PID_ONE_LIFECYCLE_SIGNALS {
        let snapshot = read_signal_action(signal)?;
        classify_pid_one_lifecycle_action(snapshot)?;
    }
    Ok(())
}

extern "C" fn pid_one_lifecycle_emergency_exit(signal: libc::c_int) {
    // SAFETY: `_exit(2)` is async-signal-safe and never returns. The kernel invokes this private
    // handler only for one of the three fixed managed signals, whose `128 + signal` status fits
    // in the process exit-status byte.
    unsafe { libc::_exit(128 + signal) }
}

fn fixed_pid_one_lifecycle_action() -> io::Result<libc::sigaction> {
    // SAFETY: an all-zero Linux `sigaction` is a valid baseline: the integer handler slot is
    // overwritten below, the signal set is initialized by `sigemptyset`, flags are overwritten,
    // and the optional restorer remains `None` for libc to supply internally where required.
    let mut action = unsafe { mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = pid_one_lifecycle_emergency_exit as libc::sighandler_t;
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: `action.sa_mask` is writable storage of the exact libc signal-set type. Only the
    // fixed mask is constructed; no caller-provided signal number reaches libc.
    if unsafe { libc::sigemptyset(&raw mut action.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM, libc::SIGCHLD] {
        // SAFETY: the mask remains initialized and `signal` is one of four fixed valid signals.
        if unsafe { libc::sigaddset(&raw mut action.sa_mask, signal) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(action)
}

#[derive(Clone, Copy)]
struct SignalActionSnapshot {
    handler: libc::sighandler_t,
    flags: libc::c_int,
    mask_bits: u64,
}

fn read_signal_action(signal: libc::c_int) -> io::Result<SignalActionSnapshot> {
    let mut action = mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: this private helper is called only with one of the three fixed lifecycle signals. A
    // null input action makes the operation read-only, while `action` provides correctly aligned
    // writable output storage and is inspected only after libc reports success.
    let result = unsafe { libc::sigaction(signal, std::ptr::null(), action.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `sigaction` query initialized every field read below.
    let action = unsafe { action.assume_init() };
    Ok(SignalActionSnapshot {
        handler: action.sa_sigaction,
        flags: action.sa_flags,
        mask_bits: read_signal_set_bits(&action.sa_mask)?,
    })
}

fn read_signal_set_bits(mask: &libc::sigset_t) -> io::Result<u64> {
    let maximum = libc::SIGRTMAX();
    if !(1..=64).contains(&maximum) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux valid-signal range does not fit fixed signal snapshot",
        ));
    }
    let mut bits = 0_u64;
    for signal in 1..=maximum {
        // SAFETY: `mask` is an initialized libc signal set and every queried number is within the
        // runtime valid-signal range reported by libc.
        match unsafe { libc::sigismember(mask, signal) } {
            0 => {}
            1 => bits |= signal_bit(signal),
            _ => return Err(io::Error::last_os_error()),
        }
    }
    Ok(bits)
}

fn classify_pid_one_lifecycle_action(snapshot: SignalActionSnapshot) -> io::Result<()> {
    if snapshot.handler != pid_one_lifecycle_emergency_exit as libc::sighandler_t
        || snapshot.flags != LIBC_SIGACTION_READBACK_FLAGS
        || snapshot.mask_bits != PID_ONE_LIFECYCLE_MASK_BITS
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PID-1 lifecycle signal disposition is not the fixed emergency action",
        ));
    }
    Ok(())
}

fn classify_default_lifecycle_action(snapshot: SignalActionSnapshot) -> io::Result<()> {
    if snapshot.handler != libc::SIG_DFL || snapshot.flags != 0 || snapshot.mask_bits != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "inherited lifecycle signal disposition is not exactly default",
        ));
    }
    Ok(())
}

const fn signal_bit(signal: libc::c_int) -> u64 {
    1_u64 << ((signal as u32) - 1)
}

/// Installs the fixed amd64 worker filter that prevents descendants and namespace changes.
///
/// The caller must already have installed `PR_SET_NO_NEW_PRIVS`. One filter is applied to every
/// current thread with `SECCOMP_FILTER_FLAG_TSYNC`; the only denied cases are an unexpected audit
/// architecture, the x32 syscall ABI, `clone(2)`, `clone3(2)`, `fork(2)`, `vfork(2)`, `setns(2)`,
/// or `unshare(2)`. Those cases return `EPERM`; all other syscalls are allowed. The fixed filter
/// remains active across an `execve(2)`.
///
/// This API intentionally exposes no way to supply filter instructions or installation flags.
/// It is supported only on the Debian 13 amd64 production target and fails closed elsewhere.
///
/// # Errors
///
/// Returns the kernel error when seccomp installation fails. A positive thread ID returned by a
/// failed `TSYNC` operation is also an error, because that means the filter did not reach every
/// current thread.
pub fn install_worker_confinement_filter() -> io::Result<()> {
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    {
        let mut instructions = worker_confinement_filter();
        let mut program = libc::sock_fprog {
            len: u16::try_from(instructions.len()).expect("fixed seccomp program length fits u16"),
            filter: instructions.as_mut_ptr(),
        };

        // SAFETY: `program` points to the initialized, fixed instruction array above for the
        // duration of the syscall. No pointer, instruction, action, syscall number, or flag comes
        // from the caller. `SECCOMP_FILTER_FLAG_TSYNC` is required so an unexpected current thread
        // cannot remain outside the filter; zero is the only successful return value.
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                &raw mut program,
            )
        };
        classify_seccomp_tsync_result(result)
    }

    #[cfg(not(all(target_arch = "x86_64", target_pointer_width = "64")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "worker seccomp filter requires amd64",
        ))
    }
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
fn worker_confinement_filter() -> [libc::sock_filter; WORKER_CONFINEMENT_FILTER_LENGTH] {
    let load_word_absolute = classic_bpf_code(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS);
    let jump_equal = classic_bpf_code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K);
    let jump_bits_set = classic_bpf_code(libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K);
    let return_constant = classic_bpf_code(libc::BPF_RET | libc::BPF_K);
    let denied = libc::SECCOMP_RET_ERRNO
        | (u32::try_from(libc::EPERM).expect("Linux EPERM is positive") & libc::SECCOMP_RET_DATA);

    [
        bpf_statement(load_word_absolute, SECCOMP_DATA_ARCH_OFFSET),
        bpf_jump(jump_equal, AUDIT_ARCH_X86_64, 1, 0),
        bpf_statement(return_constant, denied),
        bpf_statement(load_word_absolute, SECCOMP_DATA_SYSCALL_OFFSET),
        bpf_jump(jump_bits_set, X32_SYSCALL_BIT, 0, 1),
        bpf_statement(return_constant, denied),
        bpf_jump(jump_equal, syscall_number(libc::SYS_clone), 6, 0),
        bpf_jump(jump_equal, syscall_number(libc::SYS_clone3), 5, 0),
        bpf_jump(jump_equal, syscall_number(libc::SYS_fork), 4, 0),
        bpf_jump(jump_equal, syscall_number(libc::SYS_vfork), 3, 0),
        bpf_jump(jump_equal, syscall_number(libc::SYS_setns), 2, 0),
        bpf_jump(jump_equal, syscall_number(libc::SYS_unshare), 1, 0),
        bpf_statement(return_constant, libc::SECCOMP_RET_ALLOW),
        bpf_statement(return_constant, denied),
    ]
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
fn classic_bpf_code(code: u32) -> u16 {
    u16::try_from(code).expect("classic-BPF opcode fits u16")
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
fn syscall_number(number: libc::c_long) -> u32 {
    u32::try_from(number).expect("amd64 syscall number fits u32")
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const fn bpf_statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const fn bpf_jump(code: u16, value: u32, jump_true: u8, jump_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: jump_true,
        jf: jump_false,
        k: value,
    }
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
fn classify_seccomp_tsync_result(result: libc::c_long) -> io::Result<()> {
    match result {
        0 => Ok(()),
        -1 => Err(io::Error::last_os_error()),
        thread_id if thread_id > 0 => Err(io::Error::other(format!(
            "seccomp TSYNC rejected thread {thread_id}"
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid seccomp TSYNC result",
        )),
    }
}

/// Safe snapshot of negotiation and aggregate transfer evidence for one MPTCP socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MptcpInfo {
    /// Kernel reported ordinary-TCP fallback; callers must reject this.
    pub fallback: bool,
    /// Peer MP_CAPABLE key was received, proving MPTCP negotiation.
    pub remote_key_received: bool,
    /// Additional subflows beyond the initial subflow.
    pub additional_subflows: u8,
    /// Total real subflow count reported by the kernel.
    pub total_subflows: u8,
    /// Aggregate application bytes sent by this MPTCP socket.
    pub bytes_sent: u64,
    /// Aggregate application bytes received by this MPTCP socket.
    pub bytes_received: u64,
    /// Aggregate retransmitted bytes.
    pub bytes_retransmitted: u64,
}

impl MptcpInfo {
    /// Returns true only when the kernel proves MP_CAPABLE negotiation without fallback.
    #[must_use]
    pub const fn is_negotiated(self) -> bool {
        !self.fallback && self.remote_key_received && self.total_subflows >= 1
    }
}

/// Reads `MPTCP_INFO` from an existing Linux socket.
///
/// # Errors
///
/// Returns the kernel error for a non-MPTCP or unavailable socket option, and
/// fails with `InvalidData` if the kernel returns a structure shorter than the
/// Debian 13 UAPI layout. No partially initialized fields are exposed.
pub fn mptcp_info<F: AsFd>(socket: &F) -> io::Result<MptcpInfo> {
    let mut raw = RawMptcpInfo::default();
    let mut length = libc::socklen_t::try_from(mem::size_of::<RawMptcpInfo>())
        .expect("mptcp_info size fits socklen_t");
    let expected = length;

    // SAFETY: `raw` is a fully initialized `repr(C)` value matching the Linux
    // UAPI. Its pointer is valid and writable for `length` bytes, `length`
    // itself is valid, and the borrowed file descriptor remains live for the
    // call. The kernel-returned length is checked before fields are read.
    let result = unsafe {
        libc::getsockopt(
            socket.as_fd().as_raw_fd(),
            SOL_MPTCP,
            MPTCP_INFO,
            std::ptr::from_mut(&mut raw).cast::<libc::c_void>(),
            std::ptr::from_mut(&mut length),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length < expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned truncated MPTCP_INFO",
        ));
    }

    Ok(MptcpInfo {
        fallback: raw.mptcpi_flags & MPTCP_INFO_FLAG_FALLBACK != 0,
        remote_key_received: raw.mptcpi_flags & MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED != 0,
        additional_subflows: raw.mptcpi_subflows,
        total_subflows: raw.mptcpi_subflows_total,
        bytes_sent: raw.mptcpi_bytes_sent,
        bytes_received: raw.mptcpi_bytes_received,
        bytes_retransmitted: raw.mptcpi_bytes_retrans,
    })
}

/// Exact Internet address family expected for an ingress capability.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IngressSocketFamily {
    /// IPv4-only socket.
    Ipv4,
    /// IPv6-only socket.
    Ipv6,
}

/// Closed purpose of a helper-owned client-ingress socket.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IngressSocketKind {
    /// Transparent TCP listener for non-DNS flows.
    TransparentTcpListener,
    /// Transparent UDP ingress for non-DNS datagrams.
    TransparentUdp,
    /// Dedicated transparent TCP listener for DNS.
    DnsTcpListener,
    /// Dedicated transparent UDP ingress for DNS.
    DnsUdp,
}

impl IngressSocketKind {
    const fn is_tcp(self) -> bool {
        matches!(self, Self::TransparentTcpListener | Self::DnsTcpListener)
    }

    const fn is_udp(self) -> bool {
        matches!(self, Self::TransparentUdp | Self::DnsUdp)
    }
}

/// Kernel-revalidated metadata for one helper-provided ingress descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedIngressSocket {
    family: IngressSocketFamily,
    kind: IngressSocketKind,
    local: SocketAddr,
}

impl ValidatedIngressSocket {
    /// Return the exact validated address family.
    #[must_use]
    pub const fn family(self) -> IngressSocketFamily {
        self.family
    }

    /// Return the exact validated semantic kind.
    #[must_use]
    pub const fn kind(self) -> IngressSocketKind {
        self.kind
    }

    /// Return the kernel-reported wildcard bind address and non-zero port.
    #[must_use]
    pub const fn local(self) -> SocketAddr {
        self.local
    }
}

/// One UDP payload paired with kernel-provided source and original destination evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedUdpDatagram {
    bytes: usize,
    source: SocketAddr,
    original_destination: SocketAddr,
}

impl ReceivedUdpDatagram {
    /// Number of initialized payload bytes in the caller's buffer.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }

    /// Kernel-reported sender tuple.
    #[must_use]
    pub const fn source(self) -> SocketAddr {
        self.source
    }

    /// Exact destination tuple recovered from one matching ORIGDST ancillary record.
    #[must_use]
    pub const fn original_destination(self) -> SocketAddr {
        self.original_destination
    }
}

#[derive(Clone, Copy)]
struct KernelIngressSnapshot {
    family: IngressSocketFamily,
    socket_type: Type,
    protocol: Option<Protocol>,
    transparent: bool,
    listening: bool,
    local: SocketAddr,
    nonblocking: bool,
    close_on_exec: bool,
    ipv6_only: Option<bool>,
    receives_original_destination: bool,
}

/// Revalidate every security-relevant property of one helper-provided ingress descriptor.
///
/// The kernel is queried again for domain, type, protocol, transparent mode, listener state,
/// wildcard bind tuple, nonblocking and close-on-exec flags. IPv6 sockets must be IPv6-only and
/// UDP ingress sockets must have original-destination ancillary reception enabled.
///
/// # Errors
///
/// Returns an error unless the descriptor exactly matches the requested closed kind, family and
/// helper-announced non-zero local port.
pub fn validate_ingress_socket<F: AsFd>(
    socket: &F,
    kind: IngressSocketKind,
    family: IngressSocketFamily,
    expected_local_port: u16,
) -> io::Result<ValidatedIngressSocket> {
    if expected_local_port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ingress local port is zero",
        ));
    }
    let snapshot = inspect_ingress_socket(socket)?;
    validate_ingress_snapshot(snapshot, kind, family, expected_local_port)
}

fn inspect_ingress_socket<F: AsFd>(socket: &F) -> io::Result<KernelIngressSnapshot> {
    let reference = SockRef::from(socket);
    let family = match reference.domain()? {
        value if value == Domain::IPV4 => IngressSocketFamily::Ipv4,
        value if value == Domain::IPV6 => IngressSocketFamily::Ipv6,
        _ => return Err(invalid_data("ingress socket is not AF_INET/AF_INET6")),
    };
    let socket_type = reference.r#type()?;
    let protocol = reference.protocol()?;
    let local = reference
        .local_addr()?
        .as_socket()
        .ok_or_else(|| invalid_data("ingress socket has no Internet local address"))?;
    let descriptor_flags =
        FdFlag::from_bits_truncate(fcntl(socket, FcntlArg::F_GETFD).map_err(errno_io)?);
    let status_flags =
        OFlag::from_bits_truncate(fcntl(socket, FcntlArg::F_GETFL).map_err(errno_io)?);
    let transparent = getsockopt(socket, sockopt::IpTransparent).map_err(errno_io)?;
    let listening = reference.is_listener()?;
    let ipv6_only = match family {
        IngressSocketFamily::Ipv4 => None,
        IngressSocketFamily::Ipv6 => {
            Some(getsockopt(socket, sockopt::Ipv6V6Only).map_err(errno_io)?)
        }
    };
    let receives_original_destination = if socket_type == Type::DGRAM {
        match family {
            IngressSocketFamily::Ipv4 => {
                getsockopt(socket, sockopt::Ipv4OrigDstAddr).map_err(errno_io)?
            }
            IngressSocketFamily::Ipv6 => {
                getsockopt(socket, sockopt::Ipv6OrigDstAddr).map_err(errno_io)?
            }
        }
    } else {
        false
    };
    Ok(KernelIngressSnapshot {
        family,
        socket_type,
        protocol,
        transparent,
        listening,
        local,
        nonblocking: status_flags.contains(OFlag::O_NONBLOCK),
        close_on_exec: descriptor_flags.contains(FdFlag::FD_CLOEXEC),
        ipv6_only,
        receives_original_destination,
    })
}

fn validate_ingress_snapshot(
    snapshot: KernelIngressSnapshot,
    kind: IngressSocketKind,
    family: IngressSocketFamily,
    expected_local_port: u16,
) -> io::Result<ValidatedIngressSocket> {
    let expected_type = if kind.is_tcp() {
        Type::STREAM
    } else {
        Type::DGRAM
    };
    let expected_protocol = if kind.is_tcp() {
        Some(Protocol::TCP)
    } else {
        Some(Protocol::UDP)
    };
    let local_matches = match (family, snapshot.local) {
        (IngressSocketFamily::Ipv4, SocketAddr::V4(value)) => {
            value.ip().is_unspecified() && value.port() == expected_local_port
        }
        (IngressSocketFamily::Ipv6, SocketAddr::V6(value)) => {
            value.ip().is_unspecified() && value.port() == expected_local_port
        }
        _ => false,
    };
    if snapshot.family != family
        || snapshot.socket_type != expected_type
        || snapshot.protocol != expected_protocol
        || !snapshot.transparent
        || snapshot.listening != kind.is_tcp()
        || !local_matches
        || !snapshot.nonblocking
        || !snapshot.close_on_exec
        || matches!(family, IngressSocketFamily::Ipv6) && snapshot.ipv6_only != Some(true)
        || kind.is_udp() && !snapshot.receives_original_destination
    {
        return Err(invalid_data("ingress socket properties do not match"));
    }
    Ok(ValidatedIngressSocket {
        family,
        kind,
        local: snapshot.local,
    })
}

/// Recover the original destination of one accepted transparent TCP connection.
///
/// The accepted descriptor must still be transparent, nonblocking, close-on-exec, connected and
/// non-listening. The netfilter original destination must exactly equal the concrete local tuple
/// preserved by TPROXY; disagreement is rejected rather than guessed.
///
/// # Errors
///
/// Returns an error for a wrong socket shape, missing kernel evidence, ambiguous address family,
/// wildcard/multicast tuple, zero port, or disagreeing destination evidence.
pub fn tcp_original_destination<F: AsFd>(
    socket: &F,
    family: IngressSocketFamily,
) -> io::Result<SocketAddr> {
    let snapshot = inspect_ingress_socket(socket)?;
    if snapshot.family != family
        || snapshot.socket_type != Type::STREAM
        || snapshot.protocol != Some(Protocol::TCP)
        || !snapshot.transparent
        || snapshot.listening
        || !snapshot.nonblocking
        || !snapshot.close_on_exec
        || matches!(family, IngressSocketFamily::Ipv6) && snapshot.ipv6_only != Some(true)
    {
        return Err(invalid_data(
            "accepted ingress TCP socket properties do not match",
        ));
    }
    let local = validate_concrete_address(snapshot.local, family)?;
    let peer = SockRef::from(socket)
        .peer_addr()?
        .as_socket()
        .ok_or_else(|| invalid_data("accepted ingress TCP socket has no Internet peer"))?;
    validate_concrete_address(peer, family)?;

    let destination = match family {
        IngressSocketFamily::Ipv4 => {
            let raw = getsockopt(socket, sockopt::OriginalDst).map_err(errno_io)?;
            SocketAddr::V4(ipv4_original_destination(raw)?)
        }
        IngressSocketFamily::Ipv6 => {
            let raw = getsockopt(socket, sockopt::Ip6tOriginalDst).map_err(errno_io)?;
            SocketAddr::V6(ipv6_original_destination(raw)?)
        }
    };
    let destination = validate_concrete_address(destination, family)?;
    if destination != local {
        return Err(invalid_data(
            "TPROXY local tuple and original destination disagree",
        ));
    }
    Ok(destination)
}

/// Receive one UDP datagram and require exactly one matching original-destination ancillary value.
///
/// The descriptor is fully revalidated before recvmsg. Missing, duplicate, wrong-family, extra,
/// truncated or malformed ancillary data fails closed. Any received SCM_RIGHTS descriptors become
/// RAII-owned immediately and are closed before error return. Payload bytes written by a rejected
/// datagram are zeroed before returning.
///
/// # Errors
///
/// Returns an error unless one complete datagram, one concrete matching-family source tuple and
/// exactly one concrete matching-family original destination are present.
pub fn receive_udp_with_original_destination<F: AsFd>(
    socket: &F,
    kind: IngressSocketKind,
    family: IngressSocketFamily,
    expected_local_port: u16,
    payload: &mut [u8],
) -> io::Result<ReceivedUdpDatagram> {
    if !kind.is_udp() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ingress socket kind is not UDP",
        ));
    }
    validate_ingress_socket(socket, kind, family, expected_local_port)?;
    receive_udp_record(socket, family, payload)
}

fn receive_udp_record<F: AsFd>(
    socket: &F,
    family: IngressSocketFamily,
    payload: &mut [u8],
) -> io::Result<ReceivedUdpDatagram> {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP receive buffer bound is invalid",
        ));
    }
    let mut vectors = [IoSliceMut::new(payload)];
    let mut control_space = nix::cmsg_space!(
        libc::sockaddr_in,
        libc::sockaddr_in6,
        [RawFd; MAX_HANDOFF_FDS]
    );
    let (bytes, flags, source, accumulator, descriptors, control_parse_failed) = {
        let message = recvmsg::<SockaddrStorage>(
            socket.as_fd().as_raw_fd(),
            &mut vectors,
            Some(&mut control_space),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )
        .map_err(errno_io)?;
        let mut accumulator = OriginalDestinationAccumulator::new(family);
        let mut descriptors = Vec::new();
        let mut control_parse_failed = false;
        match message.cmsgs() {
            Ok(controls) => {
                for control in controls {
                    match control {
                        ControlMessageOwned::Ipv4OrigDstAddr(value) => {
                            match ipv4_original_destination(value) {
                                Ok(value) => accumulator.observe_ipv4(value),
                                Err(_) => accumulator.observe_extra(),
                            }
                        }
                        ControlMessageOwned::Ipv6OrigDstAddr(value) => {
                            match ipv6_original_destination(value) {
                                Ok(value) => accumulator.observe_ipv6(value),
                                Err(_) => accumulator.observe_extra(),
                            }
                        }
                        ControlMessageOwned::ScmRights(received) => {
                            accumulator.observe_extra();
                            for raw in received {
                                // SAFETY: recvmsg freshly installed each descriptor and this loop
                                // consumes every reported raw value exactly once into RAII ownership.
                                descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                            }
                        }
                        _ => accumulator.observe_extra(),
                    }
                }
            }
            Err(_) => control_parse_failed = true,
        }
        let source = message.address.as_ref().and_then(storage_socket_address);
        (
            message.bytes,
            message.flags,
            source,
            accumulator,
            descriptors,
            control_parse_failed,
        )
    };

    let destination = accumulator.finish();
    let source = source
        .ok_or_else(|| invalid_data("UDP datagram has no Internet source"))
        .and_then(|value| validate_concrete_address(value, family));
    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        || control_parse_failed
        || !descriptors.is_empty()
        || destination.is_err()
        || source.is_err()
    {
        let initialized = bytes.min(payload.len());
        payload[..initialized].fill(0);
        return Err(invalid_data(
            "UDP original-destination evidence is incomplete or ambiguous",
        ));
    }
    Ok(ReceivedUdpDatagram {
        bytes,
        source: source.expect("checked source result"),
        original_destination: destination.expect("checked destination result"),
    })
}

struct OriginalDestinationAccumulator {
    family: IngressSocketFamily,
    destination: Option<SocketAddr>,
    invalid: bool,
}

impl OriginalDestinationAccumulator {
    const fn new(family: IngressSocketFamily) -> Self {
        Self {
            family,
            destination: None,
            invalid: false,
        }
    }

    fn observe_ipv4(&mut self, value: SocketAddrV4) {
        self.observe(IngressSocketFamily::Ipv4, SocketAddr::V4(value));
    }

    fn observe_ipv6(&mut self, value: SocketAddrV6) {
        self.observe(IngressSocketFamily::Ipv6, SocketAddr::V6(value));
    }

    fn observe(&mut self, family: IngressSocketFamily, value: SocketAddr) {
        if family != self.family || self.destination.replace(value).is_some() {
            self.invalid = true;
        }
    }

    const fn observe_extra(&mut self) {
        self.invalid = true;
    }

    fn finish(self) -> io::Result<SocketAddr> {
        if self.invalid {
            return Err(invalid_data(
                "ambiguous original-destination ancillary data",
            ));
        }
        let destination = self
            .destination
            .ok_or_else(|| invalid_data("missing original-destination ancillary data"))?;
        validate_concrete_address(destination, self.family)
    }
}

fn ipv4_original_destination(value: libc::sockaddr_in) -> io::Result<SocketAddrV4> {
    if i32::from(value.sin_family) != libc::AF_INET {
        return Err(invalid_data("invalid IPv4 original-destination family"));
    }
    Ok(SocketAddrV4::from(SockaddrIn::from(value)))
}

fn ipv6_original_destination(value: libc::sockaddr_in6) -> io::Result<SocketAddrV6> {
    if i32::from(value.sin6_family) != libc::AF_INET6 {
        return Err(invalid_data("invalid IPv6 original-destination family"));
    }
    Ok(SocketAddrV6::from(SockaddrIn6::from(value)))
}

fn storage_socket_address(value: &SockaddrStorage) -> Option<SocketAddr> {
    value
        .as_sockaddr_in()
        .copied()
        .map(SocketAddr::from)
        .or_else(|| value.as_sockaddr_in6().copied().map(SocketAddr::from))
}

fn validate_concrete_address(
    value: SocketAddr,
    family: IngressSocketFamily,
) -> io::Result<SocketAddr> {
    let valid = match (family, value) {
        (IngressSocketFamily::Ipv4, SocketAddr::V4(value)) => {
            !value.ip().is_unspecified() && !value.ip().is_multicast() && value.port() != 0
        }
        (IngressSocketFamily::Ipv6, SocketAddr::V6(value)) => {
            !value.ip().is_unspecified() && !value.ip().is_multicast() && value.port() != 0
        }
        _ => false,
    };
    if valid {
        Ok(value)
    } else {
        Err(invalid_data("invalid concrete Internet socket address"))
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Sends one complete descriptor-free record over a SOCK_SEQPACKET channel.
///
/// The record is bounded to one mebibyte. Its channel type is revalidated before transmission;
/// stream sockets are rejected so a reader cannot mistake a partial byte stream for one record.
///
/// # Errors
///
/// Returns an I/O error for an empty or oversized record, a non-seqpacket channel, a kernel error,
/// or a short send.
pub fn send_seqpacket_without_fd<S: AsFd>(channel: &S, record: &[u8]) -> io::Result<()> {
    validate_seqpacket(channel)?;
    validate_seqpacket_length(record.len())?;
    let vectors = [IoSlice::new(record)];
    let control: [ControlMessage<'_>; 0] = [];
    let written = sendmsg::<()>(
        channel.as_fd().as_raw_fd(),
        &vectors,
        &control,
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(errno_io)?;
    if written != record.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "kernel did not send complete seqpacket record",
        ));
    }
    Ok(())
}

/// Receives one complete descriptor-free record from a SOCK_SEQPACKET channel.
///
/// Any received descriptor is immediately owned and closed before an error is returned. Record or
/// ancillary truncation, unexpected ancillary data, EOF, and a record above the caller's bound all
/// fail closed.
///
/// # Errors
///
/// Returns an I/O error unless exactly one non-empty descriptor-free record within maximum_bytes
/// is received.
pub fn receive_seqpacket_without_fd<S: AsFd>(
    channel: &S,
    maximum_bytes: usize,
) -> io::Result<Vec<u8>> {
    validate_seqpacket(channel)?;
    if maximum_bytes == 0 || maximum_bytes > MAX_SEQPACKET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seqpacket receive bound is invalid",
        ));
    }
    let mut record = vec![0_u8; maximum_bytes];
    let mut vectors = [IoSliceMut::new(&mut record)];
    let mut control_space = nix::cmsg_space!([RawFd; MAX_HANDOFF_FDS]);
    let (bytes, flags, unexpected, descriptors) = {
        let message = recvmsg::<()>(
            channel.as_fd().as_raw_fd(),
            &mut vectors,
            Some(&mut control_space),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )
        .map_err(errno_io)?;
        let mut unexpected = false;
        let mut descriptors = Vec::new();
        for control in message.cmsgs().map_err(errno_io)? {
            match control {
                ControlMessageOwned::ScmRights(received) => {
                    for raw in received {
                        // SAFETY: every raw value was freshly installed by this recvmsg call and
                        // is consumed exactly once into immediate RAII ownership.
                        descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
                _ => unexpected = true,
            }
        }
        (message.bytes, message.flags, unexpected, descriptors)
    };
    if bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "seqpacket peer closed",
        ));
    }
    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        || unexpected
        || !descriptors.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid descriptor-free seqpacket record",
        ));
    }
    record.truncate(bytes);
    Ok(record)
}

/// Sends exactly one descriptor plus one non-ancillary marker byte over an AF_UNIX socket.
///
/// This compatibility helper delegates to [`send_fd_with_binding`]. New typed helper operations
/// should bind the operation, request identifier, and response digest rather than one marker.
///
/// # Errors
///
/// Returns an I/O error when Linux rejects the ancillary message or does not consume the marker.
pub fn send_fd_with_marker<S: AsFd, F: AsFd>(
    channel: &S,
    descriptor: &F,
    marker: u8,
) -> io::Result<()> {
    send_fd_with_binding(channel, descriptor, &[marker])
}

/// Sends exactly one descriptor with one bounded correlation binding.
///
/// The binding should commit the typed operation, request identifier, and response digest. It is
/// transmitted with the descriptor in one `sendmsg(2)` call. Empty bindings and bindings above
/// 256 bytes are rejected.
///
/// # Errors
///
/// Returns an I/O error when the binding length is invalid, Linux rejects the ancillary message,
/// or the complete binding is not consumed by the single call.
pub fn send_fd_with_binding<S: AsFd, F: AsFd>(
    channel: &S,
    descriptor: &F,
    binding: &[u8],
) -> io::Result<()> {
    if binding.is_empty() || binding.len() > MAX_HANDOFF_BINDING_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor binding length is invalid",
        ));
    }
    let vectors = [IoSlice::new(binding)];
    let descriptors = [descriptor.as_fd().as_raw_fd()];
    let control = [ControlMessage::ScmRights(&descriptors)];
    let written = sendmsg::<()>(
        channel.as_fd().as_raw_fd(),
        &vectors,
        &control,
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(errno_io)?;
    if written != binding.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "kernel did not send complete descriptor binding",
        ));
    }
    Ok(())
}

/// Sends one bounded correlation binding without an ancillary descriptor.
///
/// Private worker protocols can use this as the completion record for a typed error response.
/// The receiver can then prove that no unexpected descriptor accompanied the response instead of
/// relying on a racy nonblocking peek.
///
/// # Errors
///
/// Returns an I/O error when the binding length is invalid, Linux rejects the message, or the
/// complete binding is not consumed by the single call.
pub fn send_binding_without_fd<S: AsFd>(channel: &S, binding: &[u8]) -> io::Result<()> {
    validate_binding_length(binding)?;
    let vectors = [IoSlice::new(binding)];
    let control: [ControlMessage<'_>; 0] = [];
    let written = sendmsg::<()>(
        channel.as_fd().as_raw_fd(),
        &vectors,
        &control,
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(errno_io)?;
    if written != binding.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "kernel did not send complete descriptor-free binding",
        ));
    }
    Ok(())
}

/// Receives exactly one close-on-exec descriptor and validates its marker byte.
///
/// This compatibility helper delegates to [`receive_fd_with_binding`].
///
/// # Errors
///
/// Returns an I/O error unless one complete marker and exactly one descriptor arrive.
pub fn receive_fd_with_marker<S: AsFd>(channel: &S, expected_marker: u8) -> io::Result<OwnedFd> {
    receive_fd_with_binding(channel, &[expected_marker])
}

/// Receives exactly one close-on-exec descriptor bound to exact expected bytes.
///
/// Every installed descriptor is immediately owned and therefore closed on any mismatch. The
/// binding must be non-empty and at most 256 bytes. Truncation, unexpected ancillary data,
/// duplicate descriptors, or a binding mismatch fail closed. The caller must impose a deadline on
/// the dedicated channel when its peer is not already locally trusted.
///
/// # Errors
///
/// Returns an I/O error unless exactly the expected binding and exactly one descriptor arrive in
/// one complete `recvmsg(2)` operation.
pub fn receive_fd_with_binding<S: AsFd>(
    channel: &S,
    expected_binding: &[u8],
) -> io::Result<OwnedFd> {
    let mut descriptors = receive_descriptors_with_binding(channel, expected_binding)?;
    if descriptors.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid descriptor handoff binding",
        ));
    }
    descriptors
        .pop()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "descriptor missing"))
}

/// Receives one exact completion binding and proves that it carried no descriptor.
///
/// Any installed descriptor is immediately owned and closed before this function returns an
/// error. This is intended for typed worker error responses, where accepting an unexpected
/// `SCM_RIGHTS` descriptor would make the response ambiguous.
///
/// # Errors
///
/// Returns an I/O error unless one complete matching binding and no descriptors arrive in one
/// `recvmsg(2)` operation.
pub fn receive_binding_without_fd<S: AsFd>(channel: &S, expected_binding: &[u8]) -> io::Result<()> {
    let descriptors = receive_descriptors_with_binding(channel, expected_binding)?;
    if descriptors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected descriptor on descriptor-free binding",
        ))
    }
}

fn receive_descriptors_with_binding<S: AsFd>(
    channel: &S,
    expected_binding: &[u8],
) -> io::Result<Vec<OwnedFd>> {
    validate_binding_length(expected_binding)?;
    let mut binding = [0_u8; MAX_HANDOFF_BINDING_BYTES];
    let mut vectors = [IoSliceMut::new(&mut binding[..expected_binding.len()])];
    let mut control_space = nix::cmsg_space!([RawFd; MAX_HANDOFF_FDS]);
    let (bytes, flags, unexpected, descriptors) = {
        let message = recvmsg::<()>(
            channel.as_fd().as_raw_fd(),
            &mut vectors,
            Some(&mut control_space),
            MsgFlags::MSG_CMSG_CLOEXEC | MsgFlags::MSG_WAITALL,
        )
        .map_err(errno_io)?;
        let mut unexpected = false;
        let mut descriptors = Vec::with_capacity(1);
        for control in message.cmsgs().map_err(errno_io)? {
            match control {
                ControlMessageOwned::ScmRights(received) => {
                    for raw in received {
                        // SAFETY: every raw value was freshly installed by this recvmsg call and
                        // is consumed exactly once into immediate RAII ownership.
                        descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
                _ => unexpected = true,
            }
        }
        (message.bytes, message.flags, unexpected, descriptors)
    };
    if bytes != expected_binding.len()
        || binding[..expected_binding.len()] != *expected_binding
        || flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        || unexpected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid descriptor handoff binding",
        ));
    }
    Ok(descriptors)
}

fn validate_seqpacket<S: AsFd>(channel: &S) -> io::Result<()> {
    if getsockopt(channel, sockopt::SockType).map_err(errno_io)? != SockType::SeqPacket {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "channel is not SOCK_SEQPACKET",
        ));
    }
    Ok(())
}

fn validate_seqpacket_length(length: usize) -> io::Result<()> {
    if length == 0 || length > MAX_SEQPACKET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seqpacket record length is invalid",
        ));
    }
    Ok(())
}

fn validate_binding_length(binding: &[u8]) -> io::Result<()> {
    if binding.is_empty() || binding.len() > MAX_HANDOFF_BINDING_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor binding length is invalid",
        ));
    }
    Ok(())
}

fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct RawMptcpInfo {
    mptcpi_subflows: u8,
    mptcpi_add_addr_signal: u8,
    mptcpi_add_addr_accepted: u8,
    mptcpi_subflows_max: u8,
    mptcpi_add_addr_signal_max: u8,
    mptcpi_add_addr_accepted_max: u8,
    mptcpi_flags: u32,
    mptcpi_token: u32,
    mptcpi_write_seq: u64,
    mptcpi_snd_una: u64,
    mptcpi_rcv_nxt: u64,
    mptcpi_local_addr_used: u8,
    mptcpi_local_addr_max: u8,
    mptcpi_csum_enabled: u8,
    mptcpi_retransmits: u32,
    mptcpi_bytes_retrans: u64,
    mptcpi_bytes_sent: u64,
    mptcpi_bytes_received: u64,
    mptcpi_bytes_acked: u64,
    mptcpi_subflows_total: u8,
    reserved: [u8; 3],
    mptcpi_last_data_sent: u32,
    mptcpi_last_data_recv: u32,
    mptcpi_last_ack_recv: u32,
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        fs::{self, File},
        io::{Read as _, Write as _},
        os::{fd::AsRawFd as _, unix::net::UnixStream},
        process::{Command, Stdio},
    };

    use nix::fcntl::{FcntlArg, FdFlag, fcntl};

    use super::*;

    const CLOSE_RANGE_CHILD_ENV: &str = "VOLPAROSSA_UAPI_CLOSE_RANGE_CHILD";
    const DEFAULT_LIFECYCLE_ACTION_CHILD_ENV: &str =
        "VOLPAROSSA_UAPI_DEFAULT_LIFECYCLE_ACTION_CHILD";
    const PID_ONE_SIGNALS_CHILD_ENV: &str = "VOLPAROSSA_UAPI_PID_ONE_SIGNALS_CHILD";
    const SIGCHLD_ACTION_CHILD_ENV: &str = "VOLPAROSSA_UAPI_SIGCHLD_ACTION_CHILD";
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    const SECCOMP_CHILD_ENV: &str = "VOLPAROSSA_UAPI_SECCOMP_CHILD";

    #[test]
    fn nsfs_namespace_type_is_exact_and_rejects_non_namespace_descriptors() {
        let network_namespace = File::open("/proc/self/ns/net").expect("open current netns");
        assert_eq!(
            namespace_type(&network_namespace).expect("query current netns type"),
            libc::CLONE_NEWNET
        );

        let (pipe_read, _pipe_write) = nix::unistd::pipe().expect("open non-namespace pipe");
        assert_eq!(
            namespace_type(&pipe_read)
                .expect_err("pipe must not pass as nsfs")
                .raw_os_error(),
            Some(libc::ENOTTY)
        );
    }

    #[test]
    fn owning_user_namespace_is_owned_read_only_cloexec_and_typed() {
        let network_namespace = File::open("/proc/self/ns/net").expect("open current netns");
        let owner = owning_user_namespace(&network_namespace).expect("open owning userns");

        let descriptor_flags = FdFlag::from_bits_truncate(
            fcntl(&owner, FcntlArg::F_GETFD).expect("read owner descriptor flags"),
        );
        assert!(descriptor_flags.contains(FdFlag::FD_CLOEXEC));
        let status_flags = OFlag::from_bits_truncate(
            fcntl(&owner, FcntlArg::F_GETFL).expect("read owner status flags"),
        );
        assert_eq!(status_flags & OFlag::O_ACCMODE, OFlag::O_RDONLY);
        assert_eq!(
            namespace_type(&owner).expect("query owner namespace type"),
            libc::CLONE_NEWUSER
        );
    }

    #[test]
    fn child_reaping_requires_default_sigchld_without_nocldwait() {
        assert!(classify_sigchld_action(libc::SIG_DFL, 0).is_ok());
        for (handler, flags) in [
            (libc::SIG_IGN, 0),
            (libc::SIG_DFL, libc::SA_NOCLDWAIT),
            (libc::SIG_IGN, libc::SA_NOCLDWAIT),
        ] {
            assert_eq!(
                classify_sigchld_action(handler, flags)
                    .expect_err("nonwaitable SIGCHLD action")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    extern "C" fn sigchld_test_handler(_: libc::c_int) {}

    #[test]
    fn sigchld_query_rejects_nonwaitable_kernel_actions() {
        if let Some(mode) = env::var_os(SIGCHLD_ACTION_CHILD_ENV) {
            let mut action = unsafe { mem::zeroed::<libc::sigaction>() };
            action.sa_sigaction = match mode.to_str() {
                Some("ignore") => libc::SIG_IGN,
                Some("nocldwait") => libc::SIG_DFL,
                Some("handler") => sigchld_test_handler as libc::sighandler_t,
                _ => panic!("unexpected SIGCHLD test mode"),
            };
            action.sa_flags = if mode == "nocldwait" {
                libc::SA_NOCLDWAIT
            } else {
                0
            };
            // SAFETY: this is an isolated one-test subprocess which creates
            // no children. The initialized action has an empty mask and
            // either a valid fixed handler or a libc sentinel.
            unsafe {
                assert_eq!(libc::sigemptyset(&raw mut action.sa_mask), 0);
                assert_eq!(
                    libc::sigaction(libc::SIGCHLD, &raw const action, std::ptr::null_mut()),
                    0
                );
            }
            assert_eq!(
                ensure_waitable_sigchld_disposition()
                    .expect_err("nonwaitable kernel action")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            return;
        }

        let current_executable = env::current_exe().expect("current test executable");
        for mode in ["ignore", "nocldwait", "handler"] {
            let status = Command::new(&current_executable)
                .arg("--exact")
                .arg("tests::sigchld_query_rejects_nonwaitable_kernel_actions")
                .arg("--test-threads=1")
                .env(SIGCHLD_ACTION_CHILD_ENV, mode)
                .status()
                .expect("spawn isolated SIGCHLD query test");
            assert!(status.success(), "SIGCHLD mode {mode} was not rejected");
        }
    }

    #[test]
    fn default_lifecycle_action_classifier_is_exact() {
        let exact = SignalActionSnapshot {
            handler: libc::SIG_DFL,
            flags: 0,
            mask_bits: 0,
        };
        assert!(classify_default_lifecycle_action(exact).is_ok());

        for handler in [libc::SIG_IGN, sigchld_test_handler as libc::sighandler_t] {
            assert_eq!(
                classify_default_lifecycle_action(SignalActionSnapshot { handler, ..exact })
                    .expect_err("non-default lifecycle handler")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        for flags in [libc::SA_RESTART, libc::SA_NODEFER, libc::SA_RESETHAND] {
            assert_eq!(
                classify_default_lifecycle_action(SignalActionSnapshot { flags, ..exact })
                    .expect_err("lifecycle action flags")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        for mask_bits in [signal_bit(libc::SIGUSR1), signal_bit(libc::SIGCHLD)] {
            assert_eq!(
                classify_default_lifecycle_action(SignalActionSnapshot { mask_bits, ..exact })
                    .expect_err("lifecycle action mask")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn default_lifecycle_actions_are_verified_in_isolated_processes() {
        if let Some(mode) = env::var_os(DEFAULT_LIFECYCLE_ACTION_CHILD_ENV) {
            let mode = mode.to_str().expect("ASCII lifecycle-action mode");
            if mode == "default" {
                ensure_default_lifecycle_signal_dispositions()
                    .expect("exec supplied exact default lifecycle actions");
                return;
            }

            let (property, signal_name) = mode.split_once('-').expect("structured test mode");
            let signal = match signal_name {
                "hup" => libc::SIGHUP,
                "int" => libc::SIGINT,
                "term" => libc::SIGTERM,
                _ => panic!("unexpected lifecycle signal test mode"),
            };
            // SAFETY: this branch runs in a disposable, single-test subprocess. Every field in
            // the action is initialized before installing it for one fixed lifecycle signal.
            let mut action = unsafe { mem::zeroed::<libc::sigaction>() };
            action.sa_sigaction = match property {
                "ignore" => libc::SIG_IGN,
                "handler" => sigchld_test_handler as libc::sighandler_t,
                "flags" | "mask" => libc::SIG_DFL,
                _ => panic!("unexpected lifecycle action test mode"),
            };
            action.sa_flags = if property == "flags" {
                libc::SA_RESTART
            } else {
                0
            };
            // SAFETY: the action mask is valid writable storage; only a fixed valid test signal
            // is added, and the process exits immediately after the read-only admission query.
            unsafe {
                assert_eq!(libc::sigemptyset(&raw mut action.sa_mask), 0);
                if property == "mask" {
                    assert_eq!(libc::sigaddset(&raw mut action.sa_mask, libc::SIGUSR1), 0);
                }
                assert_eq!(
                    libc::sigaction(signal, &raw const action, std::ptr::null_mut()),
                    0
                );
            }
            assert_eq!(
                ensure_default_lifecycle_signal_dispositions()
                    .expect_err("non-default lifecycle kernel action")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            return;
        }

        let current_executable = env::current_exe().expect("current test executable");
        for mode in [
            "default",
            "ignore-hup",
            "ignore-int",
            "ignore-term",
            "handler-hup",
            "handler-int",
            "handler-term",
            "flags-hup",
            "flags-int",
            "flags-term",
            "mask-hup",
            "mask-int",
            "mask-term",
        ] {
            let status = Command::new(&current_executable)
                .arg("--exact")
                .arg("tests::default_lifecycle_actions_are_verified_in_isolated_processes")
                .arg("--test-threads=1")
                .env(DEFAULT_LIFECYCLE_ACTION_CHILD_ENV, mode)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("spawn isolated lifecycle-action test");
            assert!(status.success(), "lifecycle-action mode {mode}");
        }
    }

    #[test]
    fn pid_one_lifecycle_action_classifier_is_exact() {
        let exact = SignalActionSnapshot {
            handler: pid_one_lifecycle_emergency_exit as libc::sighandler_t,
            flags: LIBC_SIGACTION_READBACK_FLAGS,
            mask_bits: PID_ONE_LIFECYCLE_MASK_BITS,
        };
        assert!(classify_pid_one_lifecycle_action(exact).is_ok());

        for handler in [
            libc::SIG_DFL,
            libc::SIG_IGN,
            sigchld_test_handler as libc::sighandler_t,
        ] {
            assert_eq!(
                classify_pid_one_lifecycle_action(SignalActionSnapshot { handler, ..exact })
                    .expect_err("caller-selected handler must fail")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }

        for flags in [
            LIBC_SIGACTION_READBACK_FLAGS ^ libc::SA_RESTART,
            LIBC_SIGACTION_READBACK_FLAGS | libc::SA_NODEFER,
            LIBC_SIGACTION_READBACK_FLAGS | libc::SA_RESETHAND,
            LIBC_SIGACTION_READBACK_FLAGS | libc::SA_NOCLDWAIT,
        ] {
            assert_eq!(
                classify_pid_one_lifecycle_action(SignalActionSnapshot { flags, ..exact })
                    .expect_err("extra or missing action flag must fail")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }

        for mask_bits in [
            PID_ONE_LIFECYCLE_MASK_BITS & !signal_bit(libc::SIGHUP),
            PID_ONE_LIFECYCLE_MASK_BITS & !signal_bit(libc::SIGCHLD),
            PID_ONE_LIFECYCLE_MASK_BITS | signal_bit(libc::SIGUSR1),
        ] {
            assert_eq!(
                classify_pid_one_lifecycle_action(SignalActionSnapshot { mask_bits, ..exact })
                    .expect_err("extra or missing action-mask signal must fail")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn pid_one_lifecycle_actions_install_and_read_back_in_isolated_processes() {
        if let Some(mode) = env::var_os(PID_ONE_SIGNALS_CHILD_ENV) {
            let mut managed = unsafe { mem::zeroed::<libc::sigset_t>() };
            // SAFETY: this branch runs only in a disposable subprocess. `managed` is writable
            // signal-set storage and only the three fixed valid lifecycle signals are added. The
            // resulting set is blocked on this test thread before the processwide actions change.
            unsafe {
                assert_eq!(libc::sigemptyset(&raw mut managed), 0);
                for signal in PID_ONE_LIFECYCLE_SIGNALS {
                    assert_eq!(libc::sigaddset(&raw mut managed, signal), 0);
                }
                assert_eq!(
                    libc::pthread_sigmask(
                        libc::SIG_BLOCK,
                        &raw const managed,
                        std::ptr::null_mut()
                    ),
                    0
                );
            }

            install_pid_one_lifecycle_signal_handlers().expect("install fixed PID-1 actions");
            verify_pid_one_lifecycle_signal_handlers().expect("verify fixed PID-1 actions");
            if mode == "readback" {
                return;
            }

            let signal = match mode.to_str() {
                Some("hup") => libc::SIGHUP,
                Some("int") => libc::SIGINT,
                Some("term") => libc::SIGTERM,
                _ => panic!("unexpected PID-1 signal test mode"),
            };
            let mut selected = unsafe { mem::zeroed::<libc::sigset_t>() };
            // SAFETY: this disposable child constructs a set containing exactly one fixed valid
            // managed signal and unblocks it only after the emergency action was exactly verified.
            unsafe {
                assert_eq!(libc::sigemptyset(&raw mut selected), 0);
                assert_eq!(libc::sigaddset(&raw mut selected, signal), 0);
                assert_eq!(
                    libc::pthread_sigmask(
                        libc::SIG_UNBLOCK,
                        &raw const selected,
                        std::ptr::null_mut(),
                    ),
                    0
                );
                assert_eq!(libc::raise(signal), 0);
            }
            panic!("emergency lifecycle handler returned");
        }

        let current_executable = env::current_exe().expect("current test executable");
        for (mode, expected_code) in [
            ("readback", 0),
            ("hup", 128 + libc::SIGHUP),
            ("int", 128 + libc::SIGINT),
            ("term", 128 + libc::SIGTERM),
        ] {
            let status = Command::new(&current_executable)
                .arg("--exact")
                .arg("tests::pid_one_lifecycle_actions_install_and_read_back_in_isolated_processes")
                .arg("--test-threads=1")
                .arg("--nocapture")
                .env(PID_ONE_SIGNALS_CHILD_ENV, mode)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("spawn isolated PID-1 signal-action test");
            assert_eq!(
                status.code(),
                Some(expected_code),
                "PID-1 signal mode {mode}"
            );
        }
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn worker_confinement_filter_has_exact_fixed_program() {
        let load_word_absolute = classic_bpf_code(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS);
        let jump_equal = classic_bpf_code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K);
        let jump_bits_set = classic_bpf_code(libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K);
        let return_constant = classic_bpf_code(libc::BPF_RET | libc::BPF_K);
        let denied = libc::SECCOMP_RET_ERRNO
            | (u32::try_from(libc::EPERM).expect("Linux EPERM is positive")
                & libc::SECCOMP_RET_DATA);
        let actual = worker_confinement_filter().map(|instruction| {
            (
                instruction.code,
                instruction.jt,
                instruction.jf,
                instruction.k,
            )
        });

        assert_eq!(
            actual,
            [
                (load_word_absolute, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
                (jump_equal, 1, 0, AUDIT_ARCH_X86_64),
                (return_constant, 0, 0, denied),
                (load_word_absolute, 0, 0, SECCOMP_DATA_SYSCALL_OFFSET),
                (jump_bits_set, 0, 1, X32_SYSCALL_BIT),
                (return_constant, 0, 0, denied),
                (jump_equal, 6, 0, syscall_number(libc::SYS_clone)),
                (jump_equal, 5, 0, syscall_number(libc::SYS_clone3)),
                (jump_equal, 4, 0, syscall_number(libc::SYS_fork)),
                (jump_equal, 3, 0, syscall_number(libc::SYS_vfork)),
                (jump_equal, 2, 0, syscall_number(libc::SYS_setns)),
                (jump_equal, 1, 0, syscall_number(libc::SYS_unshare)),
                (return_constant, 0, 0, libc::SECCOMP_RET_ALLOW),
                (return_constant, 0, 0, denied),
            ]
        );
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn worker_seccomp_uapi_layout_matches_debian_13_amd64() {
        assert_eq!(mem::size_of::<libc::sock_filter>(), 8);
        assert_eq!(mem::offset_of!(libc::sock_filter, code), 0);
        assert_eq!(mem::offset_of!(libc::sock_filter, jt), 2);
        assert_eq!(mem::offset_of!(libc::sock_filter, jf), 3);
        assert_eq!(mem::offset_of!(libc::sock_filter, k), 4);
        assert_eq!(mem::size_of::<libc::sock_fprog>(), 16);
        assert_eq!(mem::offset_of!(libc::sock_fprog, len), 0);
        assert_eq!(mem::offset_of!(libc::sock_fprog, filter), 8);
        assert_eq!(mem::offset_of!(libc::seccomp_data, nr), 0);
        assert_eq!(mem::offset_of!(libc::seccomp_data, arch), 4);
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn worker_confinement_filter_denies_every_fixed_branch() {
        let denied = libc::SECCOMP_RET_ERRNO
            | (u32::try_from(libc::EPERM).expect("Linux EPERM is positive")
                & libc::SECCOMP_RET_DATA);
        for syscall in [
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_setns,
            libc::SYS_unshare,
        ] {
            assert_eq!(
                evaluate_worker_filter(AUDIT_ARCH_X86_64, syscall_number(syscall)),
                denied
            );
        }
        assert_eq!(
            evaluate_worker_filter(AUDIT_ARCH_X86_64 ^ 1, syscall_number(libc::SYS_getpid)),
            denied
        );
        assert_eq!(
            evaluate_worker_filter(
                AUDIT_ARCH_X86_64,
                syscall_number(libc::SYS_getpid) | X32_SYSCALL_BIT,
            ),
            denied
        );
        assert_eq!(
            evaluate_worker_filter(AUDIT_ARCH_X86_64, syscall_number(libc::SYS_getpid)),
            libc::SECCOMP_RET_ALLOW
        );
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn seccomp_tsync_result_classification_is_exact() {
        assert!(classify_seccomp_tsync_result(0).is_ok());
        assert!(classify_seccomp_tsync_result(-1).is_err());
        let positive = classify_seccomp_tsync_result(42).expect_err("positive TID must fail");
        assert_eq!(positive.kind(), io::ErrorKind::Other);
        assert!(positive.to_string().contains("42"));
        assert_eq!(
            classify_seccomp_tsync_result(-2)
                .expect_err("invalid negative result must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn worker_confinement_filter_is_unprivileged_and_enforced() {
        if env::var_os(SECCOMP_CHILD_ENV).is_some() {
            // SAFETY: this isolated subprocess sets the monotonic no-new-privileges bit on itself;
            // all arguments are the fixed values required by prctl(2).
            let no_new_privileges = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            assert_eq!(no_new_privileges, 0, "set no-new-privileges");
            let (before_mode, before_filters) = current_seccomp_state();

            install_worker_confinement_filter().expect("install fixed worker seccomp filter");

            let (after_mode, after_filters) = current_seccomp_state();
            assert!(matches!(before_mode, 0 | libc::SECCOMP_MODE_FILTER));
            assert_eq!(after_mode, libc::SECCOMP_MODE_FILTER);
            assert_eq!(
                after_filters,
                before_filters.checked_add(1).expect("filter count")
            );
            for syscall in [
                libc::SYS_clone,
                libc::SYS_clone3,
                libc::SYS_fork,
                libc::SYS_setns,
                libc::SYS_unshare,
            ] {
                assert_raw_syscall_is_eperm(syscall);
            }
            assert_raw_syscall_is_eperm(libc::c_long::from(
                syscall_number(libc::SYS_getpid) | X32_SYSCALL_BIT,
            ));
            // SAFETY: getpid(2) has no arguments and is deliberately allowed by the fixed filter.
            let allowed_pid = unsafe { libc::syscall(libc::SYS_getpid) };
            assert!(
                allowed_pid > 0,
                "ordinary getpid syscall must remain allowed"
            );
            return;
        }

        let mut command = Command::new("/proc/self/exe");
        command
            .arg("--exact")
            .arg("tests::worker_confinement_filter_is_unprivileged_and_enforced")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(SECCOMP_CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        assert!(command.status().expect("spawn seccomp child").success());
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    fn evaluate_worker_filter(arch: u32, syscall: u32) -> u32 {
        let instructions = worker_confinement_filter();
        let load_word_absolute = classic_bpf_code(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS);
        let jump_equal = classic_bpf_code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K);
        let jump_bits_set = classic_bpf_code(libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K);
        let return_constant = classic_bpf_code(libc::BPF_RET | libc::BPF_K);
        let mut accumulator = 0_u32;
        let mut program_counter = 0_usize;

        while let Some(instruction) = instructions.get(program_counter) {
            if instruction.code == load_word_absolute {
                accumulator = match instruction.k {
                    SECCOMP_DATA_ARCH_OFFSET => arch,
                    SECCOMP_DATA_SYSCALL_OFFSET => syscall,
                    _ => panic!("unexpected seccomp_data offset"),
                };
                program_counter += 1;
            } else if instruction.code == jump_equal || instruction.code == jump_bits_set {
                let condition = if instruction.code == jump_equal {
                    accumulator == instruction.k
                } else {
                    accumulator & instruction.k != 0
                };
                let jump = if condition {
                    instruction.jt
                } else {
                    instruction.jf
                };
                program_counter = program_counter
                    .checked_add(1 + usize::from(jump))
                    .expect("fixed filter jump does not overflow");
            } else if instruction.code == return_constant {
                return instruction.k;
            } else {
                panic!("unexpected classic-BPF opcode");
            }
        }
        panic!("fixed seccomp filter did not return an action");
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    fn current_seccomp_state() -> (u32, u32) {
        let status = fs::read_to_string("/proc/thread-self/status").expect("thread status");
        let mut mode = None;
        let mut filters = None;
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("Seccomp:") {
                assert!(mode.is_none(), "duplicate Seccomp field");
                mode = Some(value.trim().parse().expect("decimal Seccomp mode"));
            }
            if let Some(value) = line.strip_prefix("Seccomp_filters:") {
                assert!(filters.is_none(), "duplicate Seccomp_filters field");
                filters = Some(value.trim().parse().expect("decimal Seccomp filter count"));
            }
        }
        (
            mode.expect("Seccomp field"),
            filters.expect("Seccomp_filters field"),
        )
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    fn assert_raw_syscall_is_eperm(syscall: libc::c_long) {
        // SAFETY: the fixed filter is already installed. Supplying zero arguments is sufficient
        // because seccomp rejects these syscall numbers before the kernel dispatches them. If a
        // regression permits a fork-like call, the child immediately uses `_exit` and the parent
        // reaps it before failing the test.
        let result = unsafe {
            libc::syscall(
                syscall,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if result == 0 {
            // SAFETY: this is reachable only in an erroneously created fork-like child and exits
            // immediately without touching inherited Rust state.
            unsafe { libc::_exit(97) };
        }
        if result > 0 {
            let child = libc::pid_t::try_from(result).expect("returned child PID fits pid_t");
            let mut status = 0;
            // SAFETY: `child` is the positive PID returned by the immediately preceding syscall;
            // `status` is valid for one wait status and no other thread can consume this child.
            let waited = unsafe { libc::waitpid(child, &raw mut status, 0) };
            assert_eq!(waited, child, "reap unexpectedly permitted child");
            panic!("worker seccomp filter permitted syscall {syscall}");
        }
        assert_eq!(result, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn close_range_on_exec_is_unprivileged_and_removes_inheritable_descriptors() {
        if env::var_os(CLOSE_RANGE_CHILD_ENV).is_some() {
            let inherited =
                env::var("VOLPAROSSA_UAPI_INHERITED_FD").expect("inherited descriptor number");
            assert!(
                fs::read_link(format!("/proc/self/fd/{inherited}")).is_err(),
                "close_range must remove the deliberately inheritable descriptor at exec"
            );
            return;
        }

        let sentinel = File::open("/dev/null").expect("sentinel descriptor");
        fcntl(&sentinel, FcntlArg::F_SETFD(FdFlag::empty()))
            .expect("make sentinel deliberately inheritable");
        let mut command = Command::new("/proc/self/exe");
        command
            .arg("--exact")
            .arg("tests::close_range_on_exec_is_unprivileged_and_removes_inheritable_descriptors")
            .arg("--nocapture")
            .env(CLOSE_RANGE_CHILD_ENV, "1")
            .env(
                "VOLPAROSSA_UAPI_INHERITED_FD",
                sentinel.as_raw_fd().to_string(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        install_close_range_on_exec(&mut command);
        assert!(command.status().expect("spawn close-range child").success());
        assert_eq!(
            FdFlag::from_bits_truncate(
                fcntl(&sentinel, FcntlArg::F_GETFD).expect("parent sentinel flags")
            ),
            FdFlag::empty(),
            "CLOSE_RANGE_UNSHARE must not mutate the parent descriptor table"
        );
    }

    #[test]
    fn rust_layout_matches_debian_13_linux_uapi() {
        assert_eq!(mem::size_of::<RawMptcpInfo>(), 96);
        assert_eq!(mem::offset_of!(RawMptcpInfo, mptcpi_flags), 8);
        assert_eq!(mem::offset_of!(RawMptcpInfo, mptcpi_bytes_sent), 56);
        assert_eq!(mem::offset_of!(RawMptcpInfo, mptcpi_subflows_total), 80);
        assert_eq!(mem::offset_of!(RawMptcpInfo, mptcpi_last_ack_recv), 92);
    }

    #[test]
    fn negotiation_requires_remote_key_and_rejects_fallback() {
        let valid = MptcpInfo {
            fallback: false,
            remote_key_received: true,
            additional_subflows: 0,
            total_subflows: 1,
            bytes_sent: 0,
            bytes_received: 0,
            bytes_retransmitted: 0,
        };
        assert!(valid.is_negotiated());
        assert!(
            !MptcpInfo {
                fallback: true,
                ..valid
            }
            .is_negotiated()
        );
        assert!(
            !MptcpInfo {
                remote_key_received: false,
                ..valid
            }
            .is_negotiated()
        );
        assert!(
            !MptcpInfo {
                total_subflows: 0,
                ..valid
            }
            .is_negotiated()
        );
    }

    #[test]
    fn one_descriptor_round_trips_and_is_close_on_exec() {
        let (sender, receiver) = UnixStream::pair().expect("socket pair");
        let (read_end, write_end) = nix::unistd::pipe().expect("pipe");
        send_fd_with_marker(&sender, &read_end, 0xa5).expect("send descriptor");
        drop(read_end);

        let received = receive_fd_with_marker(&receiver, 0xa5).expect("receive exact descriptor");
        let flags = FdFlag::from_bits_truncate(
            fcntl(&received, FcntlArg::F_GETFD).expect("descriptor flags"),
        );
        assert!(flags.contains(FdFlag::FD_CLOEXEC));

        let mut writer = File::from(write_end);
        let mut reader = File::from(received);
        writer.write_all(b"route").expect("write through pipe");
        let mut payload = [0_u8; 5];
        reader.read_exact(&mut payload).expect("read handed fd");
        assert_eq!(&payload, b"route");
    }

    #[test]
    fn missing_or_wrong_marker_handoff_is_rejected() {
        let (mut sender, receiver) = UnixStream::pair().expect("socket pair");
        sender.write_all(&[0x31]).expect("plain marker");
        assert_eq!(
            receive_fd_with_marker(&receiver, 0x31)
                .expect_err("missing descriptor must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let (sender, receiver) = UnixStream::pair().expect("socket pair");
        let (read_end, _write_end) = nix::unistd::pipe().expect("pipe");
        send_fd_with_marker(&sender, &read_end, 0x41).expect("send descriptor");
        assert_eq!(
            receive_fd_with_marker(&receiver, 0x42)
                .expect_err("wrong marker must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn multi_byte_binding_round_trips_and_mismatch_fails_closed() {
        let binding = [0x21_u8; 49];
        let (sender, receiver) = UnixStream::pair().expect("socket pair");
        let (read_end, write_end) = nix::unistd::pipe().expect("pipe");
        send_fd_with_binding(&sender, &read_end, &binding).expect("send bound descriptor");
        drop(read_end);
        let received =
            receive_fd_with_binding(&receiver, &binding).expect("receive bound descriptor");
        let flags = FdFlag::from_bits_truncate(
            fcntl(&received, FcntlArg::F_GETFD).expect("descriptor flags"),
        );
        assert!(flags.contains(FdFlag::FD_CLOEXEC));
        let mut writer = File::from(write_end);
        let mut reader = File::from(received);
        writer.write_all(b"bound").expect("write through pipe");
        let mut payload = [0_u8; 5];
        reader.read_exact(&mut payload).expect("read handed fd");
        assert_eq!(&payload, b"bound");

        let (sender, receiver) = UnixStream::pair().expect("socket pair");
        let (read_end, _write_end) = nix::unistd::pipe().expect("pipe");
        send_fd_with_binding(&sender, &read_end, &binding).expect("send bound descriptor");
        let mut wrong = binding;
        wrong[48] ^= 1;
        assert_eq!(
            receive_fd_with_binding(&receiver, &wrong)
                .expect_err("binding mismatch must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn empty_and_oversized_bindings_are_rejected_before_io() {
        let (channel, _peer) = UnixStream::pair().expect("socket pair");
        let (read_end, _write_end) = nix::unistd::pipe().expect("pipe");
        assert_eq!(
            send_fd_with_binding(&channel, &read_end, &[])
                .expect_err("empty binding")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            receive_fd_with_binding(&channel, &[0_u8; 257])
                .expect_err("oversized binding")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn duplicate_descriptors_are_all_owned_then_rejected() {
        let (sender, receiver) = UnixStream::pair().expect("socket pair");
        let (read_end, _write_end) = nix::unistd::pipe().expect("pipe");
        let marker = [0x51];
        let vectors = [IoSlice::new(&marker)];
        let raw = [read_end.as_raw_fd(), read_end.as_raw_fd()];
        let control = [ControlMessage::ScmRights(&raw)];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &vectors,
                &control,
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .expect("send duplicate descriptors"),
            marker.len()
        );
        assert_eq!(
            receive_fd_with_marker(&receiver, marker[0])
                .expect_err("duplicate descriptors must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn truncated_ancillary_and_short_binding_are_rejected() {
        let (sender, receiver) = UnixStream::pair().expect("socket pair");
        let (read_end, _write_end) = nix::unistd::pipe().expect("pipe");
        let binding = [0x61_u8; 32];
        let vectors = [IoSlice::new(&binding)];
        let raw = [
            read_end.as_raw_fd(),
            read_end.as_raw_fd(),
            read_end.as_raw_fd(),
        ];
        let control = [ControlMessage::ScmRights(&raw)];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &vectors,
                &control,
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .expect("send oversized ancillary"),
            binding.len()
        );
        assert!(
            receive_fd_with_binding(&receiver, &binding).is_err(),
            "truncated ancillary must fail closed even when recvmsg reports the kernel errno"
        );

        let (sender, receiver) = UnixStream::pair().expect("socket pair");
        let (read_end, _write_end) = nix::unistd::pipe().expect("pipe");
        send_fd_with_binding(&sender, &read_end, &binding[..8]).expect("short binding");
        drop(sender);
        assert_eq!(
            receive_fd_with_binding(&receiver, &binding)
                .expect_err("short binding must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn seqpacket_records_reject_streams_and_close_unexpected_descriptors() {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

        let (sender, receiver) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("seqpacket pair");
        send_seqpacket_without_fd(&sender, b"worker request").expect("send record");
        assert_eq!(
            receive_seqpacket_without_fd(&receiver, 64).expect("receive record"),
            b"worker request"
        );

        let (stream, _peer) = UnixStream::pair().expect("stream pair");
        assert_eq!(
            send_seqpacket_without_fd(&stream, b"not a packet")
                .expect_err("stream must be rejected")
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let (sender, receiver) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("seqpacket pair");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let binding = b"unexpected capability";
        send_fd_with_binding(&sender, &descriptor, binding).expect("send unexpected descriptor");
        drop(descriptor);
        assert_eq!(
            receive_seqpacket_without_fd(&receiver, 64)
                .expect_err("descriptor-free record must reject SCM_RIGHTS")
                .kind(),
            io::ErrorKind::InvalidData
        );
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("rejected FD closed"), 0);
    }

    fn ingress_snapshot(
        kind: IngressSocketKind,
        family: IngressSocketFamily,
    ) -> KernelIngressSnapshot {
        let local = match family {
            IngressSocketFamily::Ipv4 => "0.0.0.0:42000".parse().expect("IPv4 wildcard"),
            IngressSocketFamily::Ipv6 => "[::]:42000".parse().expect("IPv6 wildcard"),
        };
        KernelIngressSnapshot {
            family,
            socket_type: if kind.is_tcp() {
                Type::STREAM
            } else {
                Type::DGRAM
            },
            protocol: if kind.is_tcp() {
                Some(Protocol::TCP)
            } else {
                Some(Protocol::UDP)
            },
            transparent: true,
            listening: kind.is_tcp(),
            local,
            nonblocking: true,
            close_on_exec: true,
            ipv6_only: matches!(family, IngressSocketFamily::Ipv6).then_some(true),
            receives_original_destination: kind.is_udp(),
        }
    }

    #[test]
    fn ingress_snapshot_validation_covers_all_eight_closed_identities() {
        for kind in [
            IngressSocketKind::TransparentTcpListener,
            IngressSocketKind::TransparentUdp,
            IngressSocketKind::DnsTcpListener,
            IngressSocketKind::DnsUdp,
        ] {
            for family in [IngressSocketFamily::Ipv4, IngressSocketFamily::Ipv6] {
                let snapshot = ingress_snapshot(kind, family);
                let validated =
                    validate_ingress_snapshot(snapshot, kind, family, 42_000).expect("valid shape");
                assert_eq!(validated.family(), family);
                assert_eq!(validated.kind(), kind);
                assert_eq!(validated.local(), snapshot.local);

                let mut missing_cloexec = snapshot;
                missing_cloexec.close_on_exec = false;
                assert!(validate_ingress_snapshot(missing_cloexec, kind, family, 42_000).is_err());
                let mut blocking = snapshot;
                blocking.nonblocking = false;
                assert!(validate_ingress_snapshot(blocking, kind, family, 42_000).is_err());
                let mut not_transparent = snapshot;
                not_transparent.transparent = false;
                assert!(validate_ingress_snapshot(not_transparent, kind, family, 42_000).is_err());
                let mut wrong_listener_state = snapshot;
                wrong_listener_state.listening = !kind.is_tcp();
                assert!(
                    validate_ingress_snapshot(wrong_listener_state, kind, family, 42_000).is_err()
                );
                let mut wrong_port = snapshot;
                wrong_port.local.set_port(42_001);
                assert!(validate_ingress_snapshot(wrong_port, kind, family, 42_000).is_err());

                if kind.is_udp() {
                    let mut no_original_destination = snapshot;
                    no_original_destination.receives_original_destination = false;
                    assert!(
                        validate_ingress_snapshot(no_original_destination, kind, family, 42_000)
                            .is_err()
                    );
                }
                if family == IngressSocketFamily::Ipv6 {
                    let mut dual_stack = snapshot;
                    dual_stack.ipv6_only = Some(false);
                    assert!(validate_ingress_snapshot(dual_stack, kind, family, 42_000).is_err());
                }
            }
        }
    }

    #[test]
    fn ingress_snapshot_rejects_wrong_type_protocol_family_and_bind_address() {
        let kind = IngressSocketKind::TransparentUdp;
        let family = IngressSocketFamily::Ipv4;
        let snapshot = ingress_snapshot(kind, family);

        let mut wrong_type = snapshot;
        wrong_type.socket_type = Type::STREAM;
        assert!(validate_ingress_snapshot(wrong_type, kind, family, 42_000).is_err());

        let mut wrong_protocol = snapshot;
        wrong_protocol.protocol = Some(Protocol::TCP);
        assert!(validate_ingress_snapshot(wrong_protocol, kind, family, 42_000).is_err());

        let mut wrong_family = snapshot;
        wrong_family.family = IngressSocketFamily::Ipv6;
        assert!(validate_ingress_snapshot(wrong_family, kind, family, 42_000).is_err());

        let mut concrete_bind = snapshot;
        concrete_bind.local = "127.0.0.1:42000".parse().expect("concrete bind");
        assert!(validate_ingress_snapshot(concrete_bind, kind, family, 42_000).is_err());

        assert!(validate_ingress_snapshot(snapshot, kind, family, 0).is_err());
    }

    #[test]
    fn original_destination_accumulator_requires_one_matching_family_and_no_extras() {
        let ipv4: SocketAddrV4 = "8.8.8.8:53".parse().expect("IPv4 destination");
        let ipv6: SocketAddrV6 = "[2001:4860:4860::8888]:53"
            .parse()
            .expect("IPv6 destination");

        let mut exact = OriginalDestinationAccumulator::new(IngressSocketFamily::Ipv4);
        exact.observe_ipv4(ipv4);
        assert_eq!(exact.finish().expect("exact IPv4"), SocketAddr::V4(ipv4));

        assert!(
            OriginalDestinationAccumulator::new(IngressSocketFamily::Ipv4)
                .finish()
                .is_err()
        );

        let mut duplicate = OriginalDestinationAccumulator::new(IngressSocketFamily::Ipv4);
        duplicate.observe_ipv4(ipv4);
        duplicate.observe_ipv4(ipv4);
        assert!(duplicate.finish().is_err());

        let mut wrong_family = OriginalDestinationAccumulator::new(IngressSocketFamily::Ipv4);
        wrong_family.observe_ipv6(ipv6);
        assert!(wrong_family.finish().is_err());

        let mut extra = OriginalDestinationAccumulator::new(IngressSocketFamily::Ipv6);
        extra.observe_ipv6(ipv6);
        extra.observe_extra();
        assert!(extra.finish().is_err());

        let mut zero_port = OriginalDestinationAccumulator::new(IngressSocketFamily::Ipv4);
        zero_port.observe_ipv4(SocketAddrV4::new(*ipv4.ip(), 0));
        assert!(zero_port.finish().is_err());
    }

    #[test]
    fn udp_socketpair_extra_fd_is_closed_and_rejected_payload_is_zeroed() {
        use nix::sys::socket::{AddressFamily, SockFlag, socketpair};

        let (sender, receiver) = socketpair(
            AddressFamily::Unix,
            SockType::Datagram,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .expect("datagram pair");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let payload = b"secret";
        let vectors = [IoSlice::new(payload)];
        let raw = [descriptor.as_raw_fd()];
        let control = [ControlMessage::ScmRights(&raw)];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &vectors,
                &control,
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .expect("send datagram and FD"),
            payload.len()
        );
        drop(descriptor);

        let mut received = [0xa5_u8; 16];
        assert_eq!(
            receive_udp_record(&receiver, IngressSocketFamily::Ipv4, &mut received)
                .expect_err("SCM_RIGHTS must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(received[..payload.len()].iter().all(|byte| *byte == 0));
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("rejected descriptor closed"), 0);
    }

    #[test]
    fn udp_socketpair_missing_and_truncated_ancillary_evidence_fail_closed() {
        use nix::sys::socket::{AddressFamily, SockFlag, socketpair};

        let (sender, receiver) = socketpair(
            AddressFamily::Unix,
            SockType::Datagram,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .expect("datagram pair");
        let payload = b"plain";
        let vectors = [IoSlice::new(payload)];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &vectors,
                &[],
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .expect("send plain datagram"),
            payload.len()
        );
        let mut received = [0xa5_u8; 16];
        assert!(receive_udp_record(&receiver, IngressSocketFamily::Ipv4, &mut received).is_err());
        assert!(received[..payload.len()].iter().all(|byte| *byte == 0));

        let oversized = [0x5a_u8; 32];
        let vectors = [IoSlice::new(&oversized)];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &vectors,
                &[],
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .expect("send oversized datagram"),
            oversized.len()
        );
        let mut short = [0xa5_u8; 4];
        assert!(receive_udp_record(&receiver, IngressSocketFamily::Ipv4, &mut short).is_err());
        assert_eq!(short, [0_u8; 4]);
    }

    #[test]
    fn public_ingress_validation_rejects_unix_socketpair_before_receive() {
        use nix::sys::socket::{AddressFamily, SockFlag, socketpair};

        let (_sender, receiver) = socketpair(
            AddressFamily::Unix,
            SockType::Datagram,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .expect("datagram pair");
        assert!(
            validate_ingress_socket(
                &receiver,
                IngressSocketKind::TransparentUdp,
                IngressSocketFamily::Ipv4,
                42_000,
            )
            .is_err()
        );
    }
}
