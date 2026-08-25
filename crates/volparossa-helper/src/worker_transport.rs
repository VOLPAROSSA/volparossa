//! Phase-3a private worker transport channel and closed socket factories.
//!
//! This module is deliberately not selected by the production engine yet. It provides the
//! blocking code that must run inside the route namespace worker once v3 Prepare owns the worker
//! lifecycle. The production engine remains fail-closed until that lifecycle is connected.

use std::{
    io::{self, IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsFd, AsRawFd as _, OwnedFd, RawFd},
    time::Duration,
};

use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    poll::{PollFd, PollFlags, poll},
    sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, SockType, UnixCredentials, getsockopt,
        recvmsg, sendmsg, setsockopt, sockopt,
    },
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;
use volparossa_linux_uapi::{
    duplicate_descriptor_cloexec, mptcp_info, receive_binding_without_fd, receive_fd_with_binding,
    receive_seqpacket_without_fd, send_binding_without_fd, send_fd_with_binding,
    send_seqpacket_without_fd, socket_network_namespace,
};

use crate::{
    deadline::{HardDeadline, wait_for_fd, wait_for_readable_fd},
    internal_protocol::{
        AcquireTransportSocket, InternalEndpointRole, InternalProtocolError, InternalSocketAddress,
        InternalTransportSocketKind, InternalWorkerRequest, InternalWorkerResponse,
        InternalWorkerResult, MAX_INTERNAL_WORKER_FRAME, decode_request, decode_response,
        encode_request, encode_response, internal_worker_request, transport_descriptor_binding,
        transport_descriptor_source_released_binding, validate_response_for_request,
    },
    worker_sandbox::PinnedWorkerNetworkNamespace,
};

const WORKER_IPC_TIMEOUT: Duration = Duration::from_secs(5);
const MPTCP_CONNECT_TIMEOUT_MILLISECONDS: u16 = 5_000;
const MPTCP_LISTEN_BACKLOG: i32 = 128;
const MAX_CREDENTIAL_BINDING_BYTES: usize = 256;
// Linux rejects SCM_RIGHTS messages above SCM_MAX_FD (253). Reserving the complete maximum plus
// one kernel credential record means a peer cannot make descriptor ancillary data truncate.
const MAX_SCM_RIGHTS_FDS: usize = 253;

/// Exact process identity expected on one kernel-generated `SCM_CREDENTIALS` record.
///
/// This is deliberately independent of `SO_PEERCRED`: a socketpair created before an exec would
/// otherwise report the creator rather than prove which process sent each individual record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedUnixCredentials {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

impl ExpectedUnixCredentials {
    /// Constructs an exact expected process identity from externally proven numeric IDs.
    ///
    /// # Errors
    ///
    /// Rejects PID zero and values which do not fit Linux `pid_t`.
    pub(crate) fn new(pid: u32, uid: u32, gid: u32) -> io::Result<Self> {
        let pid = libc::pid_t::try_from(pid)
            .ok()
            .filter(|pid| *pid > 0)
            .ok_or_else(|| invalid_input("expected credential PID is invalid"))?;
        Ok(Self { pid, uid, gid })
    }

    fn matches(self, credentials: UnixCredentials) -> bool {
        credentials.pid() == self.pid
            && credentials.uid() == self.uid
            && credentials.gid() == self.gid
    }
}

/// One descriptor freshly installed by a credentialed `recvmsg` call.
///
/// The helper crate forbids local unsafe code, so this private affine wrapper owns the raw
/// descriptor and closes it on every rejection or drop. Only [`Self::into_owned`] can consume a
/// fully validated instance: it duplicates through the audited Linux-UAPI boundary and closes this
/// original before ordinary [`OwnedFd`] ownership escapes. The kernel also installs this original
/// close-on-exec because every receive uses `MSG_CMSG_CLOEXEC`.
#[derive(Debug)]
#[must_use = "dropping the received worker descriptor closes it"]
struct CredentialedWorkerFd {
    raw: RawFd,
}

impl CredentialedWorkerFd {
    fn from_recvmsg(raw: RawFd) -> Self {
        debug_assert!(raw >= 0);
        Self { raw }
    }

    fn into_owned(self) -> io::Result<OwnedFd> {
        self.into_owned_with(duplicate_descriptor_cloexec)
    }

    fn into_owned_with<F>(self, duplicate: F) -> io::Result<OwnedFd>
    where
        F: FnOnce(&Self) -> io::Result<OwnedFd>,
    {
        let duplicate = duplicate(&self);
        drop(self);
        duplicate
    }
}

impl std::os::fd::AsRawFd for CredentialedWorkerFd {
    fn as_raw_fd(&self) -> RawFd {
        self.raw
    }
}

impl Drop for CredentialedWorkerFd {
    fn drop(&mut self) {
        let _ = nix::unistd::close(self.raw);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DescriptorRequirement {
    None,
    ExactlyOne,
}

#[derive(Default)]
struct CredentialAncillary {
    credential: Option<UnixCredentials>,
    credential_count: usize,
    descriptors: Vec<CredentialedWorkerFd>,
    unexpected: bool,
}

impl CredentialAncillary {
    fn observe(&mut self, control: ControlMessageOwned) {
        match control {
            ControlMessageOwned::ScmCredentials(credentials) => {
                self.credential_count = self.credential_count.saturating_add(1);
                if self.credential.is_none() {
                    self.credential = Some(credentials);
                }
            }
            ControlMessageOwned::ScmRights(received) => {
                self.descriptors
                    .extend(received.into_iter().map(CredentialedWorkerFd::from_recvmsg));
            }
            _ => self.unexpected = true,
        }
    }

    fn finish(
        mut self,
        expected: ExpectedUnixCredentials,
        descriptor_requirement: DescriptorRequirement,
    ) -> io::Result<Vec<CredentialedWorkerFd>> {
        let credential_matches = self.credential_count == 1
            && self
                .credential
                .is_some_and(|credentials| expected.matches(credentials));
        let descriptor_count_matches = match descriptor_requirement {
            DescriptorRequirement::None => self.descriptors.is_empty(),
            DescriptorRequirement::ExactlyOne => self.descriptors.len() == 1,
        };
        if self.unexpected || !credential_matches || !descriptor_count_matches {
            return Err(invalid_data("invalid credentialed worker record"));
        }
        Ok(std::mem::take(&mut self.descriptors))
    }
}

/// Kernel-committed worker state required before a transport socket can be created.
///
/// The overlay address is derived during Prepare and retained by the worker. It never comes from
/// the later Acquire request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommittedSocketLease {
    pub(crate) route_context_id: [u8; 16],
    pub(crate) path_id: u32,
    pub(crate) role: InternalEndpointRole,
    pub(crate) overlay_address: IpAddr,
}

/// One credential-authenticated response and its optional RAII-owned descriptor.
pub(crate) struct CredentialedWorkerExecution {
    pub(crate) response: InternalWorkerResponse,
    pub(crate) descriptor: Option<OwnedFd>,
}

/// One correlated internal response and its optional transferred descriptor.
pub(crate) struct InternalWorkerExecution {
    pub(crate) response: InternalWorkerResponse,
    pub(crate) descriptor: Option<OwnedFd>,
}

#[derive(Debug, Error)]
pub(crate) enum WorkerTransportError {
    #[error("invalid committed transport request")]
    Invalid,
    #[error("private worker protocol rejected")]
    Protocol,
    #[error("MPTCP connection timed out")]
    Timeout,
    #[error("worker IPC or kernel socket operation failed")]
    Io(#[from] io::Error),
    #[error("worker network-namespace proof failed")]
    Sandbox(#[from] crate::worker_sandbox::WorkerSandboxError),
}

/// Creates a private, bounded blocking `SOCK_SEQPACKET` channel.
///
/// Both endpoints are close-on-exec. A later process launcher must explicitly map only the worker
/// endpoint to child stdin/stdout; all unrelated child processes keep neither endpoint.
///
/// # Errors
///
/// Returns an I/O error when the socketpair or fixed deadlines cannot be configured.
pub(crate) fn private_worker_channel() -> io::Result<(Socket, Socket)> {
    let (parent, worker) = private_seqpacket_channel()?;
    for endpoint in [&parent, &worker] {
        endpoint.set_read_timeout(Some(WORKER_IPC_TIMEOUT))?;
        endpoint.set_write_timeout(Some(WORKER_IPC_TIMEOUT))?;
    }
    Ok((parent, worker))
}

/// Creates a bidirectional credential-receiving worker channel.
///
/// `SO_PASSCRED` is enabled on both endpoints before either endpoint is exposed, so each side can
/// require the kernel-selected sender PID, UID and GID on every later record.
///
/// # Errors
///
/// Returns an I/O error when channel creation or credential reception cannot be proven.
pub(crate) fn private_credential_worker_channel() -> io::Result<(Socket, Socket)> {
    // Credentialed traffic is driven by explicit nonblocking operations and one caller-owned
    // absolute deadline. In particular, do not install SO_RCVTIMEO/SO_SNDTIMEO here: either
    // option would restart a relative kernel timeout for every record in a multi-record Acquire.
    let (parent, worker) = private_seqpacket_channel()?;
    enable_passcred_receiver(&parent)?;
    enable_passcred_receiver(&worker)?;
    Ok((parent, worker))
}

fn private_seqpacket_channel() -> io::Result<(Socket, Socket)> {
    Socket::pair(Domain::UNIX, Type::SEQPACKET.cloexec(), None::<Protocol>)
}

/// Enables and revalidates per-record kernel credentials on one receiving endpoint.
///
/// This must happen before its peer can queue a record. Enabling it only immediately before
/// `recvmsg` would not prove credentials for a record which was already queued.
///
/// # Errors
///
/// Returns an I/O error unless the endpoint is `SOCK_SEQPACKET` and `SO_PASSCRED` reads back true.
pub(crate) fn enable_passcred_receiver<S: AsFd>(receiver: &S) -> io::Result<()> {
    validate_credential_seqpacket(receiver)?;
    setsockopt(receiver, sockopt::PassCred, &true).map_err(errno_io)?;
    if !getsockopt(receiver, sockopt::PassCred).map_err(errno_io)? {
        return Err(io::Error::other("SO_PASSCRED did not remain enabled"));
    }
    Ok(())
}

/// Sends one bounded credential-only worker record.
///
/// No caller-supplied `SCM_CREDENTIALS` is transmitted. A receiving endpoint on which
/// `SO_PASSCRED` was enabled before this send receives credentials selected by the kernel.
///
/// # Errors
///
/// Returns an I/O error for invalid bounds, a non-seqpacket channel, kernel failure or short send.
pub(crate) fn send_credential_record<S: AsFd>(channel: &S, record: &[u8]) -> io::Result<()> {
    let deadline = HardDeadline::after(WORKER_IPC_TIMEOUT)?;
    send_credential_record_with_deadline(channel, record, deadline)
}

/// Sends one credential-only record before one caller-owned absolute deadline.
///
/// The syscall is always nonblocking. Readiness races, interrupts and backpressure reuse the same
/// deadline; successful kernel consumption at or after expiry is reported as ambiguous timeout.
pub(crate) fn send_credential_record_with_deadline<S: AsFd>(
    channel: &S,
    record: &[u8],
    deadline: HardDeadline,
) -> io::Result<()> {
    deadline.ensure_remaining()?;
    validate_credential_record_length(record.len(), MAX_INTERNAL_WORKER_FRAME)?;
    validate_credential_seqpacket(channel)?;
    let vectors = [IoSlice::new(record)];
    let control: [ControlMessage<'_>; 0] = [];
    send_credential_message_with_deadline(channel, &vectors, &control, record.len(), deadline)
}

/// Receives one bounded worker record carrying exactly the expected kernel credentials and no FD.
///
/// # Errors
///
/// EOF, bounds violations, payload or ancillary truncation, missing/duplicate/wrong credentials,
/// any descriptor and any other ancillary message fail closed.
pub(crate) fn receive_credential_record<S: AsFd>(
    channel: &S,
    maximum_bytes: usize,
    expected: ExpectedUnixCredentials,
) -> io::Result<Vec<u8>> {
    let deadline = HardDeadline::after(WORKER_IPC_TIMEOUT)?;
    receive_credential_record_with_deadline(channel, maximum_bytes, expected, deadline)
}

/// Receives one credential-only record before one caller-owned absolute deadline.
pub(crate) fn receive_credential_record_with_deadline<S: AsFd>(
    channel: &S,
    maximum_bytes: usize,
    expected: ExpectedUnixCredentials,
    deadline: HardDeadline,
) -> io::Result<Vec<u8>> {
    deadline.ensure_remaining()?;
    let (record, descriptors) = receive_credential_record_inner(
        channel,
        maximum_bytes,
        expected,
        DescriptorRequirement::None,
        deadline,
    )?;
    debug_assert!(descriptors.is_empty());
    deadline.complete(record)
}

/// Sends one bounded binding together with exactly one descriptor.
///
/// Credentials are still kernel-selected by the receiving endpoint's prior `SO_PASSCRED` setting;
/// this function supplies only `SCM_RIGHTS`.
///
/// # Errors
///
/// Returns an I/O error for an invalid binding, non-seqpacket channel, kernel failure or short send.
pub(crate) fn send_credential_fd_record<S: AsFd, F: AsFd>(
    channel: &S,
    descriptor: &F,
    binding: &[u8],
) -> io::Result<()> {
    let deadline = HardDeadline::after(WORKER_IPC_TIMEOUT)?;
    send_credential_fd_record_with_deadline(channel, descriptor, binding, deadline)
}

/// Sends one credentialed descriptor binding before one caller-owned absolute deadline.
pub(crate) fn send_credential_fd_record_with_deadline<S: AsFd, F: AsFd>(
    channel: &S,
    descriptor: &F,
    binding: &[u8],
    deadline: HardDeadline,
) -> io::Result<()> {
    deadline.ensure_remaining()?;
    validate_credential_binding(binding)?;
    validate_credential_seqpacket(channel)?;
    let vectors = [IoSlice::new(binding)];
    let descriptors = [descriptor.as_fd().as_raw_fd()];
    let control = [ControlMessage::ScmRights(&descriptors)];
    send_credential_message_with_deadline(channel, &vectors, &control, binding.len(), deadline)
}

/// Receives one exact binding, one exact kernel credential and one close-on-exec descriptor.
///
/// # Errors
///
/// Any binding mismatch, EOF, truncation, missing/duplicate/wrong credential, descriptor count
/// other than one, or other ancillary data fails closed.
pub(crate) fn receive_credential_fd_record<S: AsFd>(
    channel: &S,
    expected_binding: &[u8],
    expected: ExpectedUnixCredentials,
) -> io::Result<OwnedFd> {
    let deadline = HardDeadline::after(WORKER_IPC_TIMEOUT)?;
    receive_credential_fd_record_with_deadline(channel, expected_binding, expected, deadline)
}

/// Receives one exact credentialed descriptor binding before an absolute deadline.
pub(crate) fn receive_credential_fd_record_with_deadline<S: AsFd>(
    channel: &S,
    expected_binding: &[u8],
    expected: ExpectedUnixCredentials,
    deadline: HardDeadline,
) -> io::Result<OwnedFd> {
    deadline.ensure_remaining()?;
    validate_credential_binding(expected_binding)?;
    let (binding, mut descriptors) = receive_credential_record_inner(
        channel,
        expected_binding.len(),
        expected,
        DescriptorRequirement::ExactlyOne,
        deadline,
    )?;
    if binding != expected_binding {
        return Err(invalid_data("credentialed descriptor binding mismatch"));
    }
    let descriptor = descriptors
        .pop()
        .ok_or_else(|| invalid_data("credentialed descriptor missing"))?;
    deadline.ensure_remaining()?;
    let descriptor = descriptor.into_owned()?;
    deadline.complete(descriptor)
}

fn receive_credential_record_inner<S: AsFd>(
    channel: &S,
    maximum_bytes: usize,
    expected: ExpectedUnixCredentials,
    descriptor_requirement: DescriptorRequirement,
    deadline: HardDeadline,
) -> io::Result<(Vec<u8>, Vec<CredentialedWorkerFd>)> {
    deadline.ensure_remaining()?;
    validate_credential_record_length(maximum_bytes, MAX_INTERNAL_WORKER_FRAME)?;
    validate_credential_seqpacket(channel)?;
    if !getsockopt(channel, sockopt::PassCred).map_err(errno_io)? {
        return Err(invalid_input(
            "SO_PASSCRED was not enabled before receiving worker records",
        ));
    }

    let (mut record, bytes, flags, ancillary) = loop {
        deadline.ensure_remaining()?;
        wait_for_credential_record(channel, deadline)?;
        let mut record = vec![0_u8; maximum_bytes];
        let mut vectors = [IoSliceMut::new(&mut record)];
        // Linux permits at most SCM_MAX_FD descriptors in one SCM_RIGHTS message. Together with
        // the one SO_PASSCRED credential, this captures every capability the peer can attach.
        let mut control_space = nix::cmsg_space!(UnixCredentials, [RawFd; MAX_SCM_RIGHTS_FDS]);
        let (bytes, flags, ancillary) = {
            let received = recvmsg::<()>(
                channel.as_fd().as_raw_fd(),
                &mut vectors,
                Some(&mut control_space),
                MsgFlags::MSG_CMSG_CLOEXEC | MsgFlags::MSG_DONTWAIT,
            );
            let message = match received {
                Ok(message) => message,
                Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => continue,
                Err(error) => return Err(errno_io(error)),
            };
            let mut ancillary = CredentialAncillary::default();
            let controls = message
                .cmsgs()
                .map_err(|_| invalid_data("credential ancillary data truncated"))?;
            for control in controls {
                ancillary.observe(control);
            }
            (message.bytes, message.flags, ancillary)
        };
        deadline.ensure_remaining()?;
        break (record, bytes, flags, ancillary);
    };

    if bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "credentialed seqpacket peer closed",
        ));
    }
    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        return Err(invalid_data("credentialed worker record truncated"));
    }
    record.truncate(bytes);
    let descriptors = ancillary.finish(expected, descriptor_requirement)?;
    Ok((record, descriptors))
}

fn wait_for_credential_record<S: AsFd>(channel: &S, deadline: HardDeadline) -> io::Result<()> {
    wait_for_readable_fd(channel, deadline).map_err(|error| {
        if error.kind() == io::ErrorKind::Other {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "credentialed seqpacket peer became unavailable",
            )
        } else {
            error
        }
    })
}

fn send_credential_message_with_deadline<S: AsFd>(
    channel: &S,
    vectors: &[IoSlice<'_>],
    control: &[ControlMessage<'_>],
    expected_bytes: usize,
    deadline: HardDeadline,
) -> io::Result<()> {
    loop {
        deadline.ensure_remaining()?;
        wait_for_fd(channel, PollFlags::POLLOUT, deadline)?;
        match sendmsg::<()>(
            channel.as_fd().as_raw_fd(),
            vectors,
            control,
            MsgFlags::MSG_NOSIGNAL | MsgFlags::MSG_DONTWAIT,
            None,
        ) {
            Ok(written) => {
                validate_complete_send(written, expected_bytes)?;
                return deadline.complete(());
            }
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => continue,
            Err(error) => return Err(errno_io(error)),
        }
    }
}

fn validate_credential_seqpacket<S: AsFd>(channel: &S) -> io::Result<()> {
    if getsockopt(channel, sockopt::SockType).map_err(errno_io)? != SockType::SeqPacket {
        return Err(invalid_input(
            "credentialed worker channel is not SOCK_SEQPACKET",
        ));
    }
    Ok(())
}

fn validate_credential_record_length(length: usize, maximum_bytes: usize) -> io::Result<()> {
    if maximum_bytes == 0
        || maximum_bytes > MAX_INTERNAL_WORKER_FRAME
        || length == 0
        || length > maximum_bytes
    {
        return Err(invalid_input(
            "credentialed worker record length is invalid",
        ));
    }
    Ok(())
}

fn validate_credential_binding(binding: &[u8]) -> io::Result<()> {
    validate_credential_record_length(binding.len(), MAX_CREDENTIAL_BINDING_BYTES)
}

fn validate_complete_send(written: usize, expected: usize) -> io::Result<()> {
    if written != expected {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "kernel did not send complete credentialed worker record",
        ));
    }
    Ok(())
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Returns two owned references to the exact worker channel for stdin/stdout exec mapping.
///
/// The caller can pass these values through `Stdio::from` without an unsafe pre-exec hook. No other
/// descriptor should be inherited by the child.
///
/// # Errors
///
/// Returns an I/O error when the kernel cannot duplicate the worker endpoint.
pub(crate) fn worker_stdio_descriptors(worker: Socket) -> io::Result<(OwnedFd, OwnedFd)> {
    let input: OwnedFd = worker.try_clone()?.into();
    let output: OwnedFd = worker.into();
    Ok((input, output))
}

/// Sends one canonical internal request with kernel-selected per-record credentials.
///
/// # Errors
///
/// Returns a protocol or channel error.
pub(crate) fn send_credential_worker_request<S: AsFd>(
    channel: &S,
    request: &InternalWorkerRequest,
) -> Result<(), WorkerTransportError> {
    let deadline = HardDeadline::after(WORKER_IPC_TIMEOUT)?;
    send_credential_worker_request_with_deadline(channel, request, deadline)
}

/// Sends one canonical request before the caller's absolute transaction deadline.
pub(crate) fn send_credential_worker_request_with_deadline<S: AsFd>(
    channel: &S,
    request: &InternalWorkerRequest,
    deadline: HardDeadline,
) -> Result<(), WorkerTransportError> {
    deadline.ensure_remaining()?;
    let encoded = encode_request(request).map_err(protocol_error)?;
    send_credential_record_with_deadline(channel, encoded.as_slice(), deadline)?;
    Ok(())
}

/// Receives one canonical request with exactly the expected PID, UID and GID.
///
/// # Errors
///
/// Returns a protocol or channel error for invalid credentials, ancillary state or encoding.
pub(crate) fn receive_credential_worker_request<S: AsFd>(
    channel: &S,
    expected: ExpectedUnixCredentials,
) -> Result<InternalWorkerRequest, WorkerTransportError> {
    let deadline = HardDeadline::after(WORKER_IPC_TIMEOUT)?;
    receive_credential_worker_request_with_deadline(channel, expected, deadline)
}

/// Receives one canonical request before the caller's absolute transaction deadline.
pub(crate) fn receive_credential_worker_request_with_deadline<S: AsFd>(
    channel: &S,
    expected: ExpectedUnixCredentials,
    deadline: HardDeadline,
) -> Result<InternalWorkerRequest, WorkerTransportError> {
    deadline.ensure_remaining()?;
    let encoded = receive_credential_record_with_deadline(
        channel,
        MAX_INTERNAL_WORKER_FRAME,
        expected,
        deadline,
    )?;
    let request = decode_request(&encoded).map_err(protocol_error)?;
    deadline.complete(request).map_err(Into::into)
}

/// Sends one canonical response and every required completion record with kernel credentials.
///
/// Acquire success carries exactly one descriptor in its bound second record. This function owns
/// and drops the worker's source descriptor before sending a distinct descriptor-free release
/// record. Acquire failure carries the same exact completion binding without a descriptor or
/// release record. Any partial failure makes the channel ambiguous and must cause worker
/// termination rather than a retry.
///
/// # Errors
///
/// Returns a protocol or channel error for any correlation, outcome, descriptor or I/O mismatch.
pub(crate) fn send_credential_worker_response<S: AsFd>(
    channel: &S,
    request: &InternalWorkerRequest,
    response: &InternalWorkerResponse,
    descriptor: Option<OwnedFd>,
) -> Result<(), WorkerTransportError> {
    let deadline = HardDeadline::after(WORKER_IPC_TIMEOUT)?;
    send_credential_worker_response_with_deadline(channel, request, response, descriptor, deadline)
}

/// Sends one response and all required completion records under one absolute deadline.
pub(crate) fn send_credential_worker_response_with_deadline<S: AsFd>(
    channel: &S,
    request: &InternalWorkerRequest,
    response: &InternalWorkerResponse,
    descriptor: Option<OwnedFd>,
    deadline: HardDeadline,
) -> Result<(), WorkerTransportError> {
    deadline.ensure_remaining()?;
    validate_response_for_request(request, response).map_err(protocol_error)?;
    let acquire = matches!(
        request.operation,
        Some(internal_worker_request::Operation::AcquireTransportSocket(
            _
        ))
    );
    let success = response.result == InternalWorkerResult::Ok as i32;
    if descriptor.is_some() != (acquire && success) {
        return Err(WorkerTransportError::Invalid);
    }
    let binding = acquire
        .then(|| transport_descriptor_binding(request, response).map_err(protocol_error))
        .transpose()?;
    let released = (acquire && success)
        .then(|| {
            transport_descriptor_source_released_binding(request, response).map_err(protocol_error)
        })
        .transpose()?;
    let encoded = encode_response(response).map_err(protocol_error)?;
    send_credential_record_with_deadline(channel, encoded.as_slice(), deadline)?;
    if let Some(binding) = binding {
        if let Some(descriptor) = descriptor {
            send_credential_fd_record_with_deadline(channel, &descriptor, &binding, deadline)?;
            drop(descriptor);
            let released = released.ok_or(WorkerTransportError::Invalid)?;
            validate_credential_binding(&released)?;
            send_credential_record_with_deadline(channel, &released, deadline)?;
        } else {
            validate_credential_binding(&binding)?;
            send_credential_record_with_deadline(channel, &binding, deadline)?;
        }
    }
    deadline.complete(()).map_err(Into::into)
}

/// Receives one canonical response and its exact credential-authenticated descriptor state.
///
/// Every installed descriptor is RAII-owned before binding, credential or semantic validation.
/// Any error makes the channel ambiguous and requires worker termination rather than a retry.
///
/// # Errors
///
/// Returns a protocol or channel error for any correlation, credentials, descriptor or I/O mismatch.
pub(crate) fn receive_credential_worker_response<S: AsFd>(
    channel: &S,
    request: &InternalWorkerRequest,
    expected: ExpectedUnixCredentials,
) -> Result<CredentialedWorkerExecution, WorkerTransportError> {
    let deadline = HardDeadline::after(WORKER_IPC_TIMEOUT)?;
    receive_credential_worker_response_with_deadline(channel, request, expected, deadline)
}

/// Receives one response and all required FD/binding records under one absolute deadline.
///
/// The same copied deadline is used for every record. Any descriptor installed after the deadline
/// is immediately owned and closed before this function reports timeout. Acquire success is not
/// returned until an exact descriptor-free release record proves that the correct worker program
/// dropped the source descriptor after its `SCM_RIGHTS` send.
pub(crate) fn receive_credential_worker_response_with_deadline<S: AsFd>(
    channel: &S,
    request: &InternalWorkerRequest,
    expected: ExpectedUnixCredentials,
    deadline: HardDeadline,
) -> Result<CredentialedWorkerExecution, WorkerTransportError> {
    deadline.ensure_remaining()?;
    let encoded = receive_credential_record_with_deadline(
        channel,
        MAX_INTERNAL_WORKER_FRAME,
        expected,
        deadline,
    )?;
    let response = decode_response(&encoded).map_err(protocol_error)?;
    validate_response_for_request(request, &response).map_err(protocol_error)?;
    let acquire = matches!(
        request.operation,
        Some(internal_worker_request::Operation::AcquireTransportSocket(
            _
        ))
    );
    let success = response.result == InternalWorkerResult::Ok as i32;
    let released = (acquire && success)
        .then(|| {
            transport_descriptor_source_released_binding(request, &response).map_err(protocol_error)
        })
        .transpose()?;
    let descriptor = if acquire {
        let binding = transport_descriptor_binding(request, &response).map_err(protocol_error)?;
        if success {
            let descriptor =
                receive_credential_fd_record_with_deadline(channel, &binding, expected, deadline)?;
            let released = released.ok_or(WorkerTransportError::Invalid)?;
            let received = receive_credential_record_with_deadline(
                channel,
                released.len(),
                expected,
                deadline,
            )?;
            if received.as_slice() != released {
                return Err(
                    invalid_data("credentialed descriptor release binding mismatch").into(),
                );
            }
            Some(descriptor)
        } else {
            let received = receive_credential_record_with_deadline(
                channel,
                binding.len(),
                expected,
                deadline,
            )?;
            if received.as_slice() != binding {
                return Err(invalid_data("credentialed descriptor binding mismatch").into());
            }
            None
        }
    } else {
        None
    };
    deadline
        .complete(CredentialedWorkerExecution {
            response,
            descriptor,
        })
        .map_err(Into::into)
}

/// Sends one canonical internal request record without ancillary data.
///
/// # Errors
///
/// Returns a protocol or channel error.
pub(crate) fn send_worker_request<S: AsFd>(
    channel: &S,
    request: &InternalWorkerRequest,
) -> Result<(), WorkerTransportError> {
    let encoded = encode_request(request).map_err(protocol_error)?;
    send_seqpacket_without_fd(channel, encoded.as_slice())?;
    Ok(())
}

/// Receives and canonically decodes one descriptor-free internal request record.
///
/// # Errors
///
/// Returns a protocol or channel error, including worker death and unexpected descriptors.
pub(crate) fn receive_worker_request<S: AsFd>(
    channel: &S,
) -> Result<InternalWorkerRequest, WorkerTransportError> {
    let encoded = receive_seqpacket_without_fd(channel, MAX_INTERNAL_WORKER_FRAME)?;
    decode_request(&encoded).map_err(protocol_error)
}

/// Sends one correlated response and the exact transport completion record when applicable.
///
/// An Acquire success requires exactly one owned descriptor. The source is dropped after the
/// descriptor send and before a distinct release record. An Acquire failure requires none and
/// emits a descriptor-free binding record, proving that no hidden capability accompanied the
/// error. Any error from this function makes the channel ambiguous; the caller must terminate the
/// worker and quarantine the context instead of retrying.
///
/// # Errors
///
/// Returns a protocol or channel error for any correlation, outcome, descriptor or I/O mismatch.
pub(crate) fn send_worker_response<S: AsFd>(
    channel: &S,
    request: &InternalWorkerRequest,
    response: &InternalWorkerResponse,
    descriptor: Option<OwnedFd>,
) -> Result<(), WorkerTransportError> {
    validate_response_for_request(request, response).map_err(protocol_error)?;
    let acquire = matches!(
        request.operation,
        Some(internal_worker_request::Operation::AcquireTransportSocket(
            _
        ))
    );
    let success = response.result == InternalWorkerResult::Ok as i32;
    if descriptor.is_some() != (acquire && success) {
        return Err(WorkerTransportError::Invalid);
    }
    let binding = acquire
        .then(|| transport_descriptor_binding(request, response).map_err(protocol_error))
        .transpose()?;
    let released = (acquire && success)
        .then(|| {
            transport_descriptor_source_released_binding(request, response).map_err(protocol_error)
        })
        .transpose()?;
    let encoded = encode_response(response).map_err(protocol_error)?;
    send_seqpacket_without_fd(channel, encoded.as_slice())?;
    if let Some(binding) = binding {
        if let Some(descriptor) = descriptor {
            send_fd_with_binding(channel, &descriptor, &binding)?;
            drop(descriptor);
            let released = released.ok_or(WorkerTransportError::Invalid)?;
            send_binding_without_fd(channel, &released)?;
        } else {
            send_binding_without_fd(channel, &binding)?;
        }
    }
    Ok(())
}

/// Receives one correlated response plus exactly the descriptor state its outcome requires.
///
/// All installed descriptors are RAII-owned before any semantic check. Wrong bindings, extra or
/// missing descriptors and worker death therefore fail closed without leaking a capability.
///
/// # Errors
///
/// Returns a protocol or channel error for any correlation, outcome, descriptor or I/O mismatch.
pub(crate) fn receive_worker_response<S: AsFd>(
    channel: &S,
    request: &InternalWorkerRequest,
) -> Result<InternalWorkerExecution, WorkerTransportError> {
    let encoded = receive_seqpacket_without_fd(channel, MAX_INTERNAL_WORKER_FRAME)?;
    let response = decode_response(&encoded).map_err(protocol_error)?;
    validate_response_for_request(request, &response).map_err(protocol_error)?;
    let acquire = matches!(
        request.operation,
        Some(internal_worker_request::Operation::AcquireTransportSocket(
            _
        ))
    );
    let success = response.result == InternalWorkerResult::Ok as i32;
    let released = (acquire && success)
        .then(|| {
            transport_descriptor_source_released_binding(request, &response).map_err(protocol_error)
        })
        .transpose()?;
    let descriptor = if acquire {
        let binding = transport_descriptor_binding(request, &response).map_err(protocol_error)?;
        if success {
            let descriptor = receive_fd_with_binding(channel, &binding)?;
            let released = released.ok_or(WorkerTransportError::Invalid)?;
            receive_binding_without_fd(channel, &released)?;
            Some(descriptor)
        } else {
            receive_binding_without_fd(channel, &binding)?;
            None
        }
    } else {
        None
    };
    Ok(InternalWorkerExecution {
        response,
        descriptor,
    })
}

/// Creates and fully revalidates one transport socket inside a committed route namespace.
///
/// # Errors
///
/// Returns Invalid unless the request matches the exact committed context, path, role and overlay
/// host address. Kernel errors and failure to prove genuine MPTCP negotiation fail closed.
pub(crate) fn create_transport_socket(
    lease: CommittedSocketLease,
    request: &AcquireTransportSocket,
) -> Result<OwnedFd, WorkerTransportError> {
    validate_committed_request(lease, request)?;
    match transport_socket_expectation(request)? {
        TransportSocketExpectation::MptcpConnected { local, remote } => {
            create_connected_mptcp(local, remote)
        }
        TransportSocketExpectation::MptcpListener { local } => create_mptcp_listener(local),
        TransportSocketExpectation::UdpUnconnected { local } => create_bound_udp(local),
    }
}

/// Consumes and revalidates one descriptor received for a canonical Acquire request.
///
/// The descriptor cannot escape on rejection: converting it to [`Socket`] preserves its affine
/// ownership, and every error drops that owner. This proves the parent-observed kernel socket
/// shape and uses `SIOCGSKNS` to prove its exact still-pinned worker network namespace. The
/// credentialed receive path separately requires the worker's source-release barrier before this
/// validation may run.
///
/// # Errors
///
/// Returns Invalid unless the request has one closed transport shape and the kernel reports the
/// exact domain, type, protocol, local/peer tuples, flags, listener state and error state. A
/// connected MPTCP descriptor must additionally prove genuine negotiation without TCP fallback.
pub(crate) fn validate_adopted_transport_socket(
    expected_namespace: &PinnedWorkerNetworkNamespace,
    request: &AcquireTransportSocket,
    descriptor: OwnedFd,
) -> Result<OwnedFd, WorkerTransportError> {
    let expectation = transport_socket_expectation(request)?;
    let socket = Socket::from(descriptor);
    let observed_namespace = socket_network_namespace(&socket)?;
    if !expected_namespace.matches_descriptor(&observed_namespace)? {
        return Err(WorkerTransportError::Invalid);
    }
    validate_transport_socket(&socket, expectation)?;
    Ok(socket.into())
}

#[cfg(test)]
fn validate_adopted_transport_socket_shape(
    descriptor: OwnedFd,
    request: &AcquireTransportSocket,
) -> Result<OwnedFd, WorkerTransportError> {
    let expectation = transport_socket_expectation(request)?;
    let socket = Socket::from(descriptor);
    validate_transport_socket(&socket, expectation)?;
    Ok(socket.into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportSocketExpectation {
    MptcpConnected {
        local: SocketAddr,
        remote: SocketAddr,
    },
    MptcpListener {
        local: SocketAddr,
    },
    UdpUnconnected {
        local: SocketAddr,
    },
}

fn transport_socket_expectation(
    request: &AcquireTransportSocket,
) -> Result<TransportSocketExpectation, WorkerTransportError> {
    let role =
        InternalEndpointRole::try_from(request.role).map_err(|_| WorkerTransportError::Invalid)?;
    let kind = InternalTransportSocketKind::try_from(request.descriptor_kind)
        .map_err(|_| WorkerTransportError::Invalid)?;
    if !role_allows_socket(role, kind) {
        return Err(WorkerTransportError::Invalid);
    }
    let local = socket_address(
        request
            .expected_local
            .as_ref()
            .ok_or(WorkerTransportError::Invalid)?,
    )?;
    match (kind, request.expected_remote.as_ref()) {
        (InternalTransportSocketKind::MptcpConnected, Some(remote)) => {
            let remote = socket_address(remote)?;
            if std::mem::discriminant(&local) != std::mem::discriminant(&remote) || local == remote
            {
                return Err(WorkerTransportError::Invalid);
            }
            Ok(TransportSocketExpectation::MptcpConnected { local, remote })
        }
        (InternalTransportSocketKind::MptcpListener, None) => {
            Ok(TransportSocketExpectation::MptcpListener { local })
        }
        (InternalTransportSocketKind::QuicUdpUnconnected, None) => {
            Ok(TransportSocketExpectation::UdpUnconnected { local })
        }
        _ => Err(WorkerTransportError::Invalid),
    }
}

fn validate_transport_socket(
    socket: &Socket,
    expectation: TransportSocketExpectation,
) -> Result<(), WorkerTransportError> {
    match expectation {
        TransportSocketExpectation::MptcpConnected { local, remote } => {
            validate_connected_mptcp(socket, local, remote)
        }
        TransportSocketExpectation::MptcpListener { local } => {
            validate_mptcp_listener(socket, local)
        }
        TransportSocketExpectation::UdpUnconnected { local } => validate_bound_udp(socket, local),
    }
}

fn validate_committed_request(
    lease: CommittedSocketLease,
    request: &AcquireTransportSocket,
) -> Result<(), WorkerTransportError> {
    let route_context_id: [u8; 16] = request
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| WorkerTransportError::Invalid)?;
    let role =
        InternalEndpointRole::try_from(request.role).map_err(|_| WorkerTransportError::Invalid)?;
    let kind = InternalTransportSocketKind::try_from(request.descriptor_kind)
        .map_err(|_| WorkerTransportError::Invalid)?;
    let local = socket_address(
        request
            .expected_local
            .as_ref()
            .ok_or(WorkerTransportError::Invalid)?,
    )?;
    if route_context_id != lease.route_context_id
        || request.path_id != lease.path_id
        || role != lease.role
        || local.ip() != lease.overlay_address
        || !role_allows_socket(role, kind)
    {
        return Err(WorkerTransportError::Invalid);
    }
    match (kind, request.expected_remote.as_ref()) {
        (InternalTransportSocketKind::MptcpConnected, Some(remote)) => {
            let remote = socket_address(remote)?;
            if std::mem::discriminant(&local) != std::mem::discriminant(&remote) || local == remote
            {
                return Err(WorkerTransportError::Invalid);
            }
        }
        (
            InternalTransportSocketKind::MptcpListener
            | InternalTransportSocketKind::QuicUdpUnconnected,
            None,
        ) => {}
        _ => return Err(WorkerTransportError::Invalid),
    }
    Ok(())
}

fn role_allows_socket(role: InternalEndpointRole, kind: InternalTransportSocketKind) -> bool {
    matches!(
        (role, kind),
        (
            InternalEndpointRole::Client,
            InternalTransportSocketKind::MptcpConnected
                | InternalTransportSocketKind::QuicUdpUnconnected
        ) | (
            InternalEndpointRole::Exit,
            InternalTransportSocketKind::MptcpListener
                | InternalTransportSocketKind::QuicUdpUnconnected
        )
    )
}

fn create_connected_mptcp(
    local: SocketAddr,
    remote: SocketAddr,
) -> Result<OwnedFd, WorkerTransportError> {
    let socket = Socket::new(
        Domain::for_address(local),
        Type::STREAM.nonblocking().cloexec(),
        Some(Protocol::MPTCP),
    )?;
    configure_exact_address_family(&socket, local)?;
    socket.bind(&SockAddr::from(local))?;
    match socket.connect(&SockAddr::from(remote)) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(code)
                    if code == libc::EINPROGRESS
                        || code == libc::EALREADY
                        || code == libc::EWOULDBLOCK
            ) => {}
        Err(error) => return Err(error.into()),
    }
    wait_for_connect(&socket)?;
    validate_connected_mptcp(&socket, local, remote)?;
    Ok(socket.into())
}

fn create_mptcp_listener(local: SocketAddr) -> Result<OwnedFd, WorkerTransportError> {
    let socket = Socket::new(
        Domain::for_address(local),
        Type::STREAM.nonblocking().cloexec(),
        Some(Protocol::MPTCP),
    )?;
    configure_exact_address_family(&socket, local)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(local))?;
    socket.listen(MPTCP_LISTEN_BACKLOG)?;
    validate_mptcp_listener(&socket, local)?;
    Ok(socket.into())
}

fn create_bound_udp(local: SocketAddr) -> Result<OwnedFd, WorkerTransportError> {
    let socket = Socket::new(
        Domain::for_address(local),
        Type::DGRAM.nonblocking().cloexec(),
        Some(Protocol::UDP),
    )?;
    configure_exact_address_family(&socket, local)?;
    socket.bind(&SockAddr::from(local))?;
    validate_bound_udp(&socket, local)?;
    Ok(socket.into())
}

fn wait_for_connect(socket: &Socket) -> Result<(), WorkerTransportError> {
    let mut descriptors = [PollFd::new(socket.as_fd(), PollFlags::POLLOUT)];
    if poll(&mut descriptors, MPTCP_CONNECT_TIMEOUT_MILLISECONDS).map_err(errno_io)? == 0 {
        return Err(WorkerTransportError::Timeout);
    }
    let events = descriptors[0]
        .revents()
        .ok_or_else(|| io::Error::other("poll returned no MPTCP events"))?;
    if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
        || !events.contains(PollFlags::POLLOUT)
    {
        if let Some(error) = socket.take_error()? {
            return Err(error.into());
        }
        return Err(io::Error::other("MPTCP connect readiness is ambiguous").into());
    }
    if let Some(error) = socket.take_error()? {
        return Err(error.into());
    }
    Ok(())
}

fn validate_connected_mptcp(
    socket: &Socket,
    local: SocketAddr,
    remote: SocketAddr,
) -> Result<(), WorkerTransportError> {
    validate_common(socket, Type::STREAM, Protocol::MPTCP, local, false)?;
    if socket.peer_addr()?.as_socket() != Some(remote) {
        return Err(WorkerTransportError::Invalid);
    }
    if !mptcp_info(socket)?.is_negotiated() {
        return Err(WorkerTransportError::Invalid);
    }
    Ok(())
}

fn validate_mptcp_listener(socket: &Socket, local: SocketAddr) -> Result<(), WorkerTransportError> {
    validate_common(socket, Type::STREAM, Protocol::MPTCP, local, true)?;
    if peer_is_connected(socket)? {
        return Err(WorkerTransportError::Invalid);
    }
    Ok(())
}

fn validate_bound_udp(socket: &Socket, local: SocketAddr) -> Result<(), WorkerTransportError> {
    validate_common(socket, Type::DGRAM, Protocol::UDP, local, false)?;
    if peer_is_connected(socket)? {
        return Err(WorkerTransportError::Invalid);
    }
    Ok(())
}

fn validate_common(
    socket: &Socket,
    expected_type: Type,
    expected_protocol: Protocol,
    expected_local: SocketAddr,
    expected_listener: bool,
) -> Result<(), WorkerTransportError> {
    if socket.domain()? != Domain::for_address(expected_local)
        || socket.r#type()? != expected_type
        || socket.protocol()? != Some(expected_protocol)
        || socket.local_addr()?.as_socket() != Some(expected_local)
        || socket.is_listener()? != expected_listener
        || socket.take_error()?.is_some()
        || (expected_local.is_ipv6() && !socket.only_v6()?)
    {
        return Err(WorkerTransportError::Invalid);
    }
    let descriptor_flags =
        FdFlag::from_bits_truncate(fcntl(socket, FcntlArg::F_GETFD).map_err(errno_io)?);
    let status_flags =
        OFlag::from_bits_truncate(fcntl(socket, FcntlArg::F_GETFL).map_err(errno_io)?);
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC) || !status_flags.contains(OFlag::O_NONBLOCK) {
        return Err(WorkerTransportError::Invalid);
    }
    Ok(())
}

fn configure_exact_address_family(
    socket: &Socket,
    local: SocketAddr,
) -> Result<(), WorkerTransportError> {
    if local.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    Ok(())
}

fn peer_is_connected(socket: &Socket) -> Result<bool, WorkerTransportError> {
    match socket.peer_addr() {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn socket_address(value: &InternalSocketAddress) -> Result<SocketAddr, WorkerTransportError> {
    let port = u16::try_from(value.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(WorkerTransportError::Invalid)?;
    let address = match value.address.as_slice() {
        bytes if bytes.len() == 4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| WorkerTransportError::Invalid)?,
        )),
        bytes if bytes.len() == 16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| WorkerTransportError::Invalid)?,
        )),
        _ => return Err(WorkerTransportError::Invalid),
    };
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || matches!(address, IpAddr::V4(value) if value == Ipv4Addr::BROADCAST)
        || matches!(
            address,
            IpAddr::V6(value)
                if value.is_unicast_link_local() || value.to_ipv4_mapped().is_some()
        )
    {
        return Err(WorkerTransportError::Invalid);
    }
    Ok(SocketAddr::new(address, port))
}

fn protocol_error(_error: InternalProtocolError) -> WorkerTransportError {
    WorkerTransportError::Protocol
}

fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        io::{IoSlice, Read as _, Write as _},
        net::UdpSocket,
        os::fd::{AsRawFd as _, IntoRawFd as _, OwnedFd},
        os::unix::net::UnixStream,
        process::{Command, Stdio},
        thread,
        time::Instant,
    };

    use nix::sched::{CloneFlags, unshare};
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    use prost::Message as _;
    use volparossa_linux_uapi::{
        send_binding_without_fd, send_fd_with_binding, send_seqpacket_without_fd,
    };

    use super::*;
    use crate::internal_protocol::{
        INTERNAL_WORKER_MAGIC, INTERNAL_WORKER_PROTOCOL_VERSION, InternalSocketAddress,
        TransportSocketReady, encode_request, internal_worker_response,
    };
    use crate::worker_sandbox::WorkerKernelPins;

    const ADOPTED_SOCKET_NAMESPACE_CHILD_ENV: &str =
        "VOLPAROSSA_ADOPTED_SOCKET_NAMESPACE_TEST_CHILD";

    fn address(octets: [u8; 4], port: u32) -> InternalSocketAddress {
        InternalSocketAddress {
            address: octets.to_vec(),
            port,
        }
    }

    fn internal_address(value: SocketAddr) -> InternalSocketAddress {
        InternalSocketAddress {
            address: match value.ip() {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            },
            port: u32::from(value.port()),
        }
    }

    fn acquire_operation_mut(request: &mut InternalWorkerRequest) -> &mut AcquireTransportSocket {
        match request.operation.as_mut() {
            Some(internal_worker_request::Operation::AcquireTransportSocket(operation)) => {
                operation
            }
            _ => panic!("Acquire request"),
        }
    }

    fn acquire_operation(request: &InternalWorkerRequest) -> &AcquireTransportSocket {
        match request.operation.as_ref() {
            Some(internal_worker_request::Operation::AcquireTransportSocket(operation)) => {
                operation
            }
            _ => panic!("Acquire request"),
        }
    }

    fn acquire_request_for_local(
        kind: InternalTransportSocketKind,
        local: SocketAddr,
    ) -> InternalWorkerRequest {
        let mut request = acquire_request(kind);
        acquire_operation_mut(&mut request).expected_local = Some(internal_address(local));
        request
    }

    fn freebound_udp() -> (Socket, SocketAddr) {
        let socket = Socket::new(
            Domain::IPV4,
            Type::DGRAM.nonblocking().cloexec(),
            Some(Protocol::UDP),
        )
        .expect("UDP socket");
        socket.set_freebind_v4(true).expect("IP_FREEBIND");
        socket
            .bind(&SockAddr::from(SocketAddr::from((
                Ipv4Addr::new(192, 0, 2, 10),
                0,
            ))))
            .expect("freebind UDP");
        let local = socket
            .local_addr()
            .expect("local UDP")
            .as_socket()
            .expect("IP UDP");
        (socket, local)
    }

    fn freebound_ipv4_mapped_udp() -> (Socket, SocketAddr) {
        let socket = Socket::new(
            Domain::IPV6,
            Type::DGRAM.nonblocking().cloexec(),
            Some(Protocol::UDP),
        )
        .expect("IPv6 UDP socket");
        socket.set_freebind_v4(true).expect("mapped IPv4 FREEBIND");
        socket.set_only_v6(false).expect("allow mapped IPv4");
        socket
            .bind(&SockAddr::from(SocketAddr::from((
                Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 10]),
                0,
            ))))
            .expect("freebind mapped IPv4 UDP");
        let local = socket
            .local_addr()
            .expect("local IPv6 UDP")
            .as_socket()
            .expect("IP UDP");
        (socket, local)
    }

    fn descriptor_target(raw: RawFd) -> std::path::PathBuf {
        std::fs::read_link(format!("/proc/self/fd/{raw}")).expect("open descriptor target")
    }

    fn assert_descriptor_closed(raw: RawFd, original: &std::path::Path) {
        let target = std::fs::read_link(format!("/proc/self/fd/{raw}"));
        assert!(
            !target.as_deref().is_ok_and(|current| current == original),
            "rejected descriptor {raw} retained its original target {original:?}"
        );
    }

    fn unprivileged_user_namespace_policy_denied(
        status_code: Option<i32>,
        stdout: &[u8],
        stderr: &[u8],
    ) -> bool {
        status_code == Some(1)
            && stdout.is_empty()
            && matches!(
                stderr,
                b"unshare: unshare failed: Operation not permitted\n"
                    | b"unshare: write failed /proc/self/uid_map: Operation not permitted\n"
                    | b"unshare: write failed /proc/self/gid_map: Operation not permitted\n"
            )
    }

    fn current_expected_credentials() -> ExpectedUnixCredentials {
        let credentials = UnixCredentials::new();
        ExpectedUnixCredentials::new(
            u32::try_from(credentials.pid()).expect("positive process ID"),
            credentials.uid(),
            credentials.gid(),
        )
        .expect("valid current credentials")
    }

    fn proc_descriptor_flags(raw: RawFd) -> u32 {
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{raw}"))
            .expect("read descriptor metadata");
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:\t"))
            .expect("descriptor flags");
        u32::from_str_radix(flags, 8).expect("octal descriptor flags")
    }

    fn acquire_request(kind: InternalTransportSocketKind) -> InternalWorkerRequest {
        InternalWorkerRequest {
            protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
            magic: INTERNAL_WORKER_MAGIC.to_vec(),
            request_id: vec![7; 16],
            operation: Some(internal_worker_request::Operation::AcquireTransportSocket(
                AcquireTransportSocket {
                    route_context_id: vec![9; 16],
                    path_id: 1,
                    role: if kind == InternalTransportSocketKind::MptcpListener {
                        InternalEndpointRole::Exit as i32
                    } else {
                        InternalEndpointRole::Client as i32
                    },
                    descriptor_kind: kind as i32,
                    expected_local: Some(address([10, 77, 0, 2], 42_000)),
                    expected_remote: (kind == InternalTransportSocketKind::MptcpConnected)
                        .then(|| address([10, 77, 0, 3], 443)),
                },
            )),
        }
    }

    fn response(
        request: &InternalWorkerRequest,
        result: InternalWorkerResult,
    ) -> InternalWorkerResponse {
        let encoded = encode_request(request).expect("valid request");
        let outcome = if result == InternalWorkerResult::Ok {
            let Some(internal_worker_request::Operation::AcquireTransportSocket(operation)) =
                request.operation.as_ref()
            else {
                panic!("Acquire request");
            };
            Some(internal_worker_response::Outcome::TransportSocketReady(
                TransportSocketReady {
                    path_id: operation.path_id,
                    role: operation.role,
                    descriptor_kind: operation.descriptor_kind,
                    local: operation.expected_local.clone(),
                    remote: operation.expected_remote.clone(),
                },
            ))
        } else {
            None
        };
        InternalWorkerResponse {
            protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
            magic: INTERNAL_WORKER_MAGIC.to_vec(),
            request_id: request.request_id.clone(),
            result: result as i32,
            request_digest: blake3::hash(encoded.as_slice()).as_bytes().to_vec(),
            outcome,
        }
    }

    #[test]
    fn credentialed_typed_protocol_round_trips_success_and_failure() {
        let expected = current_expected_credentials();
        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        let (parent, worker) =
            private_credential_worker_channel().expect("credentialed private channel");

        send_credential_worker_request(&parent, &request).expect("typed request send");
        assert_eq!(
            receive_credential_worker_request(&worker, expected).expect("typed request receive"),
            request
        );

        let success = response(&request, InternalWorkerResult::Ok);
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let descriptor = OwnedFd::from(descriptor);
        let source_raw = descriptor.as_raw_fd();
        let source_target = descriptor_target(source_raw);
        send_credential_worker_response(&worker, &request, &success, Some(descriptor))
            .expect("typed success response");
        assert_descriptor_closed(source_raw, &source_target);
        let execution = receive_credential_worker_response(&parent, &request, expected)
            .expect("typed success receive");
        assert_eq!(execution.response, success);
        let received = execution.descriptor.expect("typed response FD");
        assert_ne!(
            proc_descriptor_flags(received.as_raw_fd())
                & u32::try_from(libc::O_CLOEXEC).expect("positive O_CLOEXEC"),
            0
        );
        drop(received);
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("typed response FD closed"), 0);

        let (parent, worker) =
            private_credential_worker_channel().expect("credentialed private channel");
        send_credential_worker_request(&parent, &request).expect("typed request send");
        receive_credential_worker_request(&worker, expected).expect("typed request receive");
        let failure = response(&request, InternalWorkerResult::Kernel);
        send_credential_worker_response(&worker, &request, &failure, None)
            .expect("typed failure response and descriptor-free binding");
        let execution = receive_credential_worker_response(&parent, &request, expected)
            .expect("typed failure receive");
        assert_eq!(execution.response, failure);
        assert!(execution.descriptor.is_none());

        assert!(matches!(
            send_credential_worker_response(&worker, &request, &success, None),
            Err(WorkerTransportError::Invalid)
        ));
    }

    #[test]
    fn credentialed_success_requires_exact_source_release_and_closes_adopted_fd() {
        let expected = current_expected_credentials();
        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        let response = response(&request, InternalWorkerResult::Ok);
        let encoded = encode_response(&response).expect("response encoding");
        let binding = transport_descriptor_binding(&request, &response).expect("FD binding");
        let mut wrong_release = transport_descriptor_source_released_binding(&request, &response)
            .expect("source release binding");
        wrong_release[0] ^= 1;

        let (parent, worker) =
            private_credential_worker_channel().expect("credentialed private channel");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        send_credential_record(&worker, &encoded).expect("response record");
        send_credential_fd_record(&worker, &descriptor, &binding).expect("descriptor record");
        drop(descriptor);
        send_credential_record(&worker, &wrong_release).expect("wrong release record");
        assert!(receive_credential_worker_response(&parent, &request, expected).is_err());
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("peer read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("wrong-release FD closed"), 0);

        let released = transport_descriptor_source_released_binding(&request, &response)
            .expect("source release binding");
        let (parent, worker) =
            private_credential_worker_channel().expect("credentialed private channel");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let (unexpected, mut unexpected_peer) =
            UnixStream::pair().expect("unexpected descriptor pair");
        send_credential_record(&worker, &encoded).expect("response record");
        send_credential_fd_record(&worker, &descriptor, &binding).expect("descriptor record");
        drop(descriptor);
        send_credential_fd_record(&worker, &unexpected, &released)
            .expect("release record with forbidden descriptor");
        drop(unexpected);
        assert!(receive_credential_worker_response(&parent, &request, expected).is_err());
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("peer read timeout");
        unexpected_peer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("unexpected peer read timeout");
        assert_eq!(peer.read(&mut byte).expect("release-FD owner closed"), 0);
        assert_eq!(
            unexpected_peer
                .read(&mut byte)
                .expect("forbidden release FD closed"),
            0
        );

        let (parent, worker) =
            private_credential_worker_channel().expect("credentialed private channel");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        send_credential_record(&worker, &encoded).expect("response record");
        send_credential_fd_record(&worker, &descriptor, &binding).expect("descriptor record");
        drop(descriptor);
        drop(worker);
        assert!(matches!(
            receive_credential_worker_response(&parent, &request, expected),
            Err(WorkerTransportError::Io(error))
                if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("peer read timeout");
        assert_eq!(peer.read(&mut byte).expect("missing-release FD closed"), 0);
    }

    #[test]
    fn credentialed_source_release_uses_the_original_absolute_deadline() {
        let expected = current_expected_credentials();
        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        let response = response(&request, InternalWorkerResult::Ok);
        let encoded = encode_response(&response).expect("response encoding");
        let binding = transport_descriptor_binding(&request, &response).expect("FD binding");
        let released = transport_descriptor_source_released_binding(&request, &response)
            .expect("source release binding");
        let (parent, worker) =
            private_credential_worker_channel().expect("credentialed private channel");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        send_credential_record(&worker, &encoded).expect("response record");
        send_credential_fd_record(&worker, &descriptor, &binding).expect("descriptor record");
        drop(descriptor);

        let sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(260));
            send_credential_record(&worker, &released).expect("late release remains queueable");
        });
        let deadline = HardDeadline::after(Duration::from_millis(180)).expect("shared deadline");
        let started = Instant::now();
        assert!(matches!(
            receive_credential_worker_response_with_deadline(
                &parent, &request, expected, deadline,
            ),
            Err(WorkerTransportError::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
        ));
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(150));
        assert!(elapsed < Duration::from_millis(500));
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("peer read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("late-release FD closed"), 0);
        sender.join().expect("late release sender");
    }

    #[test]
    fn acquire_response_and_late_fd_share_one_absolute_deadline_and_close_queued_fd() {
        let expected = current_expected_credentials();
        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        let response = response(&request, InternalWorkerResult::Ok);
        let encoded = encode_response(&response).expect("response encoding");
        let binding = transport_descriptor_binding(&request, &response).expect("FD binding");
        let (parent, worker) =
            private_credential_worker_channel().expect("credentialed private channel");
        assert_eq!(parent.read_timeout().expect("parent read timeout"), None);
        assert_eq!(parent.write_timeout().expect("parent write timeout"), None);

        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        send_credential_record(&worker, &encoded).expect("primary response record");
        let deadline = HardDeadline::after(Duration::from_millis(180)).expect("shared deadline");
        let started = Instant::now();
        let sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(260));
            send_credential_fd_record(&worker, &descriptor, &binding)
                .expect("late descriptor record remains queueable");
            drop(descriptor);
        });

        // Model time already consumed by the credentialed request send and worker execution. The
        // primary response is ready, but record two must receive only the original remainder.
        thread::sleep(Duration::from_millis(120));
        assert!(matches!(
            receive_credential_worker_response_with_deadline(
                &parent, &request, expected, deadline,
            ),
            Err(WorkerTransportError::Io(error))
                if error.kind() == io::ErrorKind::TimedOut
        ));
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(150),
            "second record did not wait on the original budget: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "record two reset the original deadline: {elapsed:?}"
        );

        sender.join().expect("late descriptor sender");
        peer.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("peer read timeout");
        let mut byte = [0_u8; 1];
        assert!(matches!(
            peer.read(&mut byte),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                )
        ));
        drop(parent);
        assert_eq!(
            peer.read(&mut byte)
                .expect("queued FD closed on channel drop"),
            0
        );
    }

    #[test]
    fn queued_terminal_response_and_fd_survive_simultaneous_peer_hangup() {
        let expected = current_expected_credentials();
        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        let response = response(&request, InternalWorkerResult::Ok);
        let (parent, worker) =
            private_credential_worker_channel().expect("credentialed private channel");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let descriptor = OwnedFd::from(descriptor);

        send_credential_worker_response(&worker, &request, &response, Some(descriptor))
            .expect("queue complete terminal response");
        drop(worker);

        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("receive deadline");
        let execution =
            receive_credential_worker_response_with_deadline(&parent, &request, expected, deadline)
                .expect("POLLIN with POLLHUP retains queued authenticated records");
        assert_eq!(execution.response, response);
        drop(execution.descriptor.expect("queued close-on-exec FD"));

        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("peer read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("received FD closed"), 0);
    }

    #[test]
    fn credentialed_raw_owner_adoption_is_consuming_and_exact() {
        let (source, mut peer) = UnixStream::pair().expect("descriptor pair");
        let original = source.as_raw_fd();
        let received = CredentialedWorkerFd::from_recvmsg(source.into_raw_fd());
        let adopted = received
            .into_owned()
            .expect("adopt credentialed descriptor");

        assert_ne!(adopted.as_raw_fd(), original);
        let mut adopted = UnixStream::from(adopted);
        peer.write_all(b"a").expect("write through peer");
        let mut byte = [0_u8; 1];
        adopted
            .read_exact(&mut byte)
            .expect("adopted descriptor remains live");
        assert_eq!(byte, *b"a");

        drop(adopted);
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("peer read timeout");
        assert_eq!(peer.read(&mut byte).expect("exact final owner closes"), 0);
    }

    #[test]
    fn credentialed_raw_owner_closes_when_adoption_fails() {
        let (source, mut peer) = UnixStream::pair().expect("descriptor pair");
        let received = CredentialedWorkerFd::from_recvmsg(source.into_raw_fd());
        let error = received
            .into_owned_with(|_| Err(io::Error::other("injected duplication failure")))
            .expect_err("adoption failure");
        assert_eq!(error.kind(), io::ErrorKind::Other);

        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("peer read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(
            peer.read(&mut byte).expect("failed adoption closes source"),
            0
        );
    }

    #[test]
    fn passcred_records_round_trip_exact_credentials_and_one_cloexec_fd() {
        let expected = current_expected_credentials();
        let (parent, worker) =
            private_credential_worker_channel().expect("credentialed private channel");
        assert!(getsockopt(&parent, sockopt::PassCred).expect("parent PASSCRED"));
        assert!(getsockopt(&worker, sockopt::PassCred).expect("worker PASSCRED"));

        send_credential_record(&parent, b"authenticated request").expect("credentialed send");
        assert_eq!(
            receive_credential_record(&worker, 64, expected).expect("credentialed receive"),
            b"authenticated request"
        );

        let binding = b"namespace-fd-binding";
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        send_credential_fd_record(&worker, &descriptor, binding).expect("credentialed FD send");
        drop(descriptor);
        let received =
            receive_credential_fd_record(&parent, binding, expected).expect("exact FD receive");
        assert!(received.as_raw_fd() >= 0);
        assert_ne!(
            proc_descriptor_flags(received.as_raw_fd())
                & u32::try_from(libc::O_CLOEXEC).expect("positive O_CLOEXEC"),
            0
        );
        drop(received);
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("received FD closed"), 0);
    }

    #[test]
    fn missing_duplicate_and_wrong_credentials_fail_closed() {
        let expected = current_expected_credentials();
        assert_eq!(
            CredentialAncillary::default()
                .finish(expected, DescriptorRequirement::None)
                .expect_err("missing credential")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let credentials = UnixCredentials::new();
        let mut duplicate = CredentialAncillary::default();
        duplicate.observe(ControlMessageOwned::ScmCredentials(credentials));
        duplicate.observe(ControlMessageOwned::ScmCredentials(credentials));
        assert_eq!(
            duplicate
                .finish(expected, DescriptorRequirement::None)
                .expect_err("duplicate credential")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let wrong = ExpectedUnixCredentials {
            pid: credentials.pid().checked_add(1).expect("PID below maximum"),
            uid: credentials.uid(),
            gid: credentials.gid(),
        };
        let mut wrong_accumulator = CredentialAncillary::default();
        wrong_accumulator.observe(ControlMessageOwned::ScmCredentials(credentials));
        assert_eq!(
            wrong_accumulator
                .finish(wrong, DescriptorRequirement::None)
                .expect_err("wrong credential")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let (sender, receiver) = private_worker_channel().expect("plain private channel");
        send_credential_record(&sender, b"queued before PASSCRED").expect("queue record");
        enable_passcred_receiver(&receiver).expect("late PASSCRED");
        assert_eq!(
            receive_credential_record(&receiver, 64, expected)
                .expect_err("queued record has no credential")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let (sender, receiver) =
            private_credential_worker_channel().expect("credentialed private channel");
        send_credential_record(&sender, b"wrong expected PID").expect("credentialed send");
        assert_eq!(
            receive_credential_record(&receiver, 64, wrong)
                .expect_err("wrong per-record PID")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn credential_only_record_rejects_and_closes_extra_fd() {
        let expected = current_expected_credentials();
        let (sender, receiver) =
            private_credential_worker_channel().expect("credentialed private channel");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let payload = b"must not carry an fd";
        let vectors = [IoSlice::new(payload)];
        let descriptors = [descriptor.as_raw_fd()];
        let control = [ControlMessage::ScmRights(&descriptors)];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &vectors,
                &control,
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .expect("send extra descriptor"),
            payload.len()
        );
        drop(descriptor);
        assert_eq!(
            receive_credential_record(&receiver, 64, expected)
                .expect_err("credential-only record rejects FD")
                .kind(),
            io::ErrorKind::InvalidData
        );
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("extra FD closed"), 0);
    }

    #[test]
    fn credentialed_fd_record_rejects_duplicate_or_missing_fd() {
        let expected = current_expected_credentials();
        let binding = b"bound namespace descriptor";
        let (sender, receiver) =
            private_credential_worker_channel().expect("credentialed private channel");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let vectors = [IoSlice::new(binding)];
        let descriptors = [descriptor.as_raw_fd(), descriptor.as_raw_fd()];
        let control = [ControlMessage::ScmRights(&descriptors)];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &vectors,
                &control,
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .expect("send duplicate descriptors"),
            binding.len()
        );
        drop(descriptor);
        assert_eq!(
            receive_credential_fd_record(&receiver, binding, expected)
                .expect_err("duplicate descriptors")
                .kind(),
            io::ErrorKind::InvalidData
        );
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("duplicate FDs closed"), 0);

        let (sender, receiver) =
            private_credential_worker_channel().expect("credentialed private channel");
        send_credential_record(&sender, binding).expect("descriptor-free binding");
        assert_eq!(
            receive_credential_fd_record(&receiver, binding, expected)
                .expect_err("missing descriptor")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn credentialed_fd_record_rejects_wrong_binding_before_adoption() {
        let expected = current_expected_credentials();
        let (sender, receiver) =
            private_credential_worker_channel().expect("credentialed private channel");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        send_credential_fd_record(&sender, &descriptor, b"wrong binding")
            .expect("send wrong bound descriptor");
        drop(descriptor);

        assert_eq!(
            receive_credential_fd_record(&receiver, b"expected binding", expected)
                .expect_err("wrong binding rejected")
                .kind(),
            io::ErrorKind::InvalidData
        );
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("peer read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(
            peer.read(&mut byte)
                .expect("wrong-bound descriptor closed before adoption"),
            0
        );
    }

    #[test]
    fn credentialed_records_reject_payload_truncation_bounds_and_eof() {
        let expected = current_expected_credentials();
        let (sender, receiver) =
            private_credential_worker_channel().expect("credentialed private channel");
        send_credential_record(&sender, &[0x5a; 32]).expect("oversized-for-receiver record");
        assert_eq!(
            receive_credential_record(&receiver, 16, expected)
                .expect_err("MSG_TRUNC")
                .kind(),
            io::ErrorKind::InvalidData
        );

        assert_eq!(
            send_credential_record(&sender, &[])
                .expect_err("empty record")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            receive_credential_record(&receiver, MAX_INTERNAL_WORKER_FRAME + 1, expected)
                .expect_err("oversized receive bound")
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let (sender, receiver) =
            private_credential_worker_channel().expect("credentialed private channel");
        drop(sender);
        assert_eq!(
            receive_credential_record(&receiver, 16, expected)
                .expect_err("peer EOF")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn private_seqpacket_round_trips_request_and_exact_fd() {
        let (parent, worker) = private_worker_channel().expect("private channel");
        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        send_worker_request(&parent, &request).expect("send request");
        assert_eq!(
            receive_worker_request(&worker).expect("receive request"),
            request
        );

        let response = response(&request, InternalWorkerResult::Ok);
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let descriptor = OwnedFd::from(descriptor);
        send_worker_response(&worker, &request, &response, Some(descriptor))
            .expect("send response and descriptor");
        let execution = receive_worker_response(&parent, &request).expect("receive exact response");
        assert_eq!(execution.response, response);
        let mut received = UnixStream::from(execution.descriptor.expect("descriptor"));
        peer.write_all(b"route").expect("write peer");
        let mut bytes = [0_u8; 5];
        received.read_exact(&mut bytes).expect("read received FD");
        assert_eq!(&bytes, b"route");
    }

    #[test]
    fn wrong_or_missing_binding_fails_closed_and_closes_received_fd() {
        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        let response = response(&request, InternalWorkerResult::Ok);
        let encoded = encode_response(&response).expect("response encoding");
        let expected = transport_descriptor_binding(&request, &response).expect("binding");

        let (parent, worker) = private_worker_channel().expect("private channel");
        send_seqpacket_without_fd(&worker, encoded.as_slice()).expect("response packet");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let descriptor = OwnedFd::from(descriptor);
        let mut wrong = expected;
        wrong[0] ^= 1;
        send_fd_with_binding(&worker, &descriptor, &wrong).expect("wrong bound descriptor");
        drop(descriptor);
        assert!(receive_worker_response(&parent, &request).is_err());
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("closed rejected FD"), 0);

        let (parent, worker) = private_worker_channel().expect("private channel");
        send_seqpacket_without_fd(&worker, encoded.as_slice()).expect("response packet");
        send_binding_without_fd(&worker, &expected).expect("missing descriptor record");
        assert!(receive_worker_response(&parent, &request).is_err());
    }

    #[test]
    fn duplicate_descriptors_on_success_are_rejected_and_closed() {
        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        let response = response(&request, InternalWorkerResult::Ok);
        let encoded = encode_response(&response).expect("response encoding");
        let binding = transport_descriptor_binding(&request, &response).expect("binding");
        let (parent, worker) = private_worker_channel().expect("private channel");
        send_seqpacket_without_fd(&worker, encoded.as_slice()).expect("response packet");

        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let descriptor = OwnedFd::from(descriptor);
        let vectors = [IoSlice::new(&binding)];
        let descriptors = [descriptor.as_raw_fd(), descriptor.as_raw_fd()];
        let control = [ControlMessage::ScmRights(&descriptors)];
        assert_eq!(
            sendmsg::<()>(
                worker.as_raw_fd(),
                &vectors,
                &control,
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .expect("send duplicate descriptors"),
            binding.len()
        );
        drop(descriptor);
        assert!(receive_worker_response(&parent, &request).is_err());
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("duplicate FDs closed"), 0);
    }

    #[test]
    fn descriptor_on_error_is_rejected_and_closed() {
        let request = acquire_request(InternalTransportSocketKind::MptcpConnected);
        let response = response(&request, InternalWorkerResult::Kernel);
        let encoded = encode_response(&response).expect("response encoding");
        let binding = transport_descriptor_binding(&request, &response).expect("binding");
        let (parent, worker) = private_worker_channel().expect("private channel");
        send_seqpacket_without_fd(&worker, encoded.as_slice()).expect("response packet");
        let (descriptor, mut peer) = UnixStream::pair().expect("descriptor pair");
        let descriptor = OwnedFd::from(descriptor);
        send_fd_with_binding(&worker, &descriptor, &binding).expect("unexpected descriptor");
        drop(descriptor);
        assert!(receive_worker_response(&parent, &request).is_err());
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("closed unexpected FD"), 0);
    }

    #[test]
    fn worker_death_is_not_a_retryable_empty_response() {
        let (parent, worker) = private_worker_channel().expect("private channel");
        drop(worker);
        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        assert!(matches!(
            receive_worker_response(&parent, &request),
            Err(WorkerTransportError::Io(error))
                if error.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn role_and_committed_overlay_binding_are_closed() {
        let request = acquire_request(InternalTransportSocketKind::MptcpConnected);
        let lease = CommittedSocketLease {
            route_context_id: [9; 16],
            path_id: 1,
            role: InternalEndpointRole::Client,
            overlay_address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
        };
        assert!(
            validate_committed_request(
                lease,
                match request.operation.as_ref() {
                    Some(internal_worker_request::Operation::AcquireTransportSocket(value)) =>
                        value,
                    _ => panic!("Acquire"),
                }
            )
            .is_ok()
        );

        let wrong_overlay = CommittedSocketLease {
            overlay_address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 9)),
            ..lease
        };
        let Some(internal_worker_request::Operation::AcquireTransportSocket(operation)) =
            request.operation.as_ref()
        else {
            panic!("Acquire");
        };
        assert!(validate_committed_request(wrong_overlay, operation).is_err());

        for role in [
            InternalEndpointRole::RelayClient,
            InternalEndpointRole::RelayExit,
        ] {
            assert!(!role_allows_socket(
                role,
                InternalTransportSocketKind::QuicUdpUnconnected
            ));
        }
        assert!(!role_allows_socket(
            InternalEndpointRole::Exit,
            InternalTransportSocketKind::MptcpConnected
        ));
        assert!(!role_allows_socket(
            InternalEndpointRole::Client,
            InternalTransportSocketKind::MptcpListener
        ));
    }

    #[test]
    fn kernel_revalidation_accepts_only_unconnected_udp_and_rejects_tcp_as_mptcp() {
        let udp = Socket::new(
            Domain::IPV4,
            Type::DGRAM.nonblocking().cloexec(),
            Some(Protocol::UDP),
        )
        .expect("UDP socket");
        udp.bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
            .expect("bind UDP");
        let local = udp
            .local_addr()
            .expect("local UDP")
            .as_socket()
            .expect("IP UDP");
        validate_bound_udp(&udp, local).expect("exact unconnected UDP");

        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP peer");
        udp.connect(&SockAddr::from(
            peer.local_addr().expect("UDP peer address"),
        ))
        .expect("connect UDP");
        assert!(validate_bound_udp(&udp, local).is_err());

        let tcp = Socket::new(
            Domain::IPV4,
            Type::STREAM.nonblocking().cloexec(),
            Some(Protocol::TCP),
        )
        .expect("TCP socket");
        tcp.bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
            .expect("bind TCP");
        tcp.listen(1).expect("listen TCP");
        let local = tcp
            .local_addr()
            .expect("local TCP")
            .as_socket()
            .expect("IP TCP");
        assert!(validate_mptcp_listener(&tcp, local).is_err());
    }

    #[test]
    fn adopted_socket_namespace_proof_requires_exact_live_netns() {
        if env::var_os(ADOPTED_SOCKET_NAMESPACE_CHILD_ENV).is_some() {
            let original_pins = WorkerKernelPins::fixture();
            let original_namespace = original_pins
                .duplicate_network_namespace_pin()
                .expect("pin first live network namespace");
            let (socket, local) = freebound_udp();
            let request =
                acquire_request_for_local(InternalTransportSocketKind::QuicUdpUnconnected, local);
            let descriptor = validate_adopted_transport_socket(
                &original_namespace,
                acquire_operation(&request),
                socket.into(),
            )
            .expect("adopt socket from exact first namespace");
            drop(descriptor);

            unshare(CloneFlags::CLONE_NEWNET).expect("enter second live network namespace");
            let (wrong_namespace_socket, local) = freebound_udp();
            let request =
                acquire_request_for_local(InternalTransportSocketKind::QuicUdpUnconnected, local);
            let raw = wrong_namespace_socket.as_raw_fd();
            let target = descriptor_target(raw);
            assert!(matches!(
                validate_adopted_transport_socket(
                    &original_namespace,
                    acquire_operation(&request),
                    wrong_namespace_socket.into(),
                ),
                Err(WorkerTransportError::Invalid)
            ));
            assert_descriptor_closed(raw, &target);

            let second_pins = WorkerKernelPins::fixture();
            let second_namespace = second_pins
                .duplicate_network_namespace_pin()
                .expect("pin second live network namespace");
            assert_ne!(
                original_namespace.identity_for_test(),
                second_namespace.identity_for_test()
            );
            let (socket, local) = freebound_udp();
            let request =
                acquire_request_for_local(InternalTransportSocketKind::QuicUdpUnconnected, local);
            drop(
                validate_adopted_transport_socket(
                    &second_namespace,
                    acquire_operation(&request),
                    socket.into(),
                )
                .expect("adopt socket from exact second namespace"),
            );
            return;
        }

        let executable = env::current_exe().expect("current helper test executable");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(executable)
            .arg("--exact")
            .arg(
                "worker_transport::tests::adopted_socket_namespace_proof_requires_exact_live_netns",
            )
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(ADOPTED_SOCKET_NAMESPACE_CHILD_ENV, "1")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()
            .expect("spawn isolated adopted-socket namespace test");
        if unprivileged_user_namespace_policy_denied(
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ) {
            eprintln!("skipped live adopted-socket proof: user namespaces denied by policy");
            return;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "isolated adopted-socket proof failed\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    #[test]
    fn adopted_udp_is_consumed_and_returned_only_for_the_exact_request_shape() {
        let (socket, local) = freebound_udp();
        let request =
            acquire_request_for_local(InternalTransportSocketKind::QuicUdpUnconnected, local);
        let descriptor =
            validate_adopted_transport_socket_shape(socket.into(), acquire_operation(&request))
                .expect("exact adopted UDP");
        let adopted = Socket::from(descriptor);
        assert_eq!(
            adopted.local_addr().expect("adopted local").as_socket(),
            Some(local)
        );
        assert!(!peer_is_connected(&adopted).expect("unconnected adopted UDP"));

        let (socket, local) = freebound_udp();
        let wrong_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), local.port());
        let request =
            acquire_request_for_local(InternalTransportSocketKind::QuicUdpUnconnected, wrong_local);
        let raw = socket.as_raw_fd();
        let target = descriptor_target(raw);
        assert!(
            validate_adopted_transport_socket_shape(socket.into(), acquire_operation(&request))
                .is_err()
        );
        assert_descriptor_closed(raw, &target);
    }

    #[test]
    fn adopted_udp_rejects_missing_nonblocking_and_cloexec_flags() {
        let (socket, local) = freebound_udp();
        socket
            .set_nonblocking(false)
            .expect("clear nonblocking flag");
        let request =
            acquire_request_for_local(InternalTransportSocketKind::QuicUdpUnconnected, local);
        let raw = socket.as_raw_fd();
        let target = descriptor_target(raw);
        assert!(
            validate_adopted_transport_socket_shape(socket.into(), acquire_operation(&request))
                .is_err()
        );
        assert_descriptor_closed(raw, &target);

        let (socket, local) = freebound_udp();
        fcntl(&socket, FcntlArg::F_SETFD(FdFlag::empty())).expect("clear close-on-exec flag");
        let request =
            acquire_request_for_local(InternalTransportSocketKind::QuicUdpUnconnected, local);
        let raw = socket.as_raw_fd();
        let target = descriptor_target(raw);
        assert!(
            validate_adopted_transport_socket_shape(socket.into(), acquire_operation(&request))
                .is_err()
        );
        assert_descriptor_closed(raw, &target);
    }

    #[test]
    fn adopted_ipv6_udp_rejects_mapped_ipv4_family_ambiguity() {
        let (socket, local) = freebound_ipv4_mapped_udp();
        let request =
            acquire_request_for_local(InternalTransportSocketKind::QuicUdpUnconnected, local);
        let raw = socket.as_raw_fd();
        let target = descriptor_target(raw);
        assert!(
            validate_adopted_transport_socket_shape(socket.into(), acquire_operation(&request))
                .is_err()
        );
        assert_descriptor_closed(raw, &target);
    }

    #[test]
    fn adopted_socket_rejects_wrong_protocol_listener_and_request_peer_shape() {
        let tcp = Socket::new(
            Domain::IPV4,
            Type::STREAM.nonblocking().cloexec(),
            Some(Protocol::TCP),
        )
        .expect("TCP socket");
        tcp.set_freebind_v4(true).expect("IP_FREEBIND");
        tcp.bind(&SockAddr::from(SocketAddr::from((
            Ipv4Addr::new(192, 0, 2, 10),
            0,
        ))))
        .expect("freebind TCP");
        tcp.listen(1).expect("listen TCP");
        let local = tcp
            .local_addr()
            .expect("local TCP")
            .as_socket()
            .expect("IP TCP");
        validate_common(&tcp, Type::STREAM, Protocol::TCP, local, true)
            .expect("SO_ACCEPTCONN true");
        assert!(validate_common(&tcp, Type::STREAM, Protocol::TCP, local, false).is_err());
        let request = acquire_request_for_local(InternalTransportSocketKind::MptcpListener, local);
        let raw = tcp.as_raw_fd();
        let target = descriptor_target(raw);
        assert!(
            validate_adopted_transport_socket_shape(tcp.into(), acquire_operation(&request))
                .is_err()
        );
        assert_descriptor_closed(raw, &target);

        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        let (wrong_type, mut peer) = UnixStream::pair().expect("wrong-type descriptor pair");
        assert!(
            validate_adopted_transport_socket_shape(
                OwnedFd::from(wrong_type),
                acquire_operation(&request),
            )
            .is_err()
        );
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("wrong-type peer timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(
            peer.read(&mut byte)
                .expect("wrong-type adopted owner closed"),
            0
        );

        let (socket, local) = freebound_udp();
        let mut request =
            acquire_request_for_local(InternalTransportSocketKind::QuicUdpUnconnected, local);
        acquire_operation_mut(&mut request).expected_remote = Some(address([192, 0, 2, 20], 443));
        let raw = socket.as_raw_fd();
        let target = descriptor_target(raw);
        assert!(
            validate_adopted_transport_socket_shape(socket.into(), acquire_operation(&request))
                .is_err()
        );
        assert_descriptor_closed(raw, &target);
    }

    #[test]
    fn stdio_mapping_keeps_two_references_to_one_seqpacket_endpoint() {
        let (_parent, worker) = private_worker_channel().expect("private channel");
        let (input, output) = worker_stdio_descriptors(worker).expect("stdio descriptors");
        assert_eq!(
            getsockopt(&input, sockopt::SockType).expect("input type"),
            SockType::SeqPacket
        );
        assert_eq!(
            getsockopt(&output, sockopt::SockType).expect("output type"),
            SockType::SeqPacket
        );
    }

    #[test]
    fn worker_protocol_identity_is_not_supplied_by_an_agent() {
        let request = acquire_request(InternalTransportSocketKind::QuicUdpUnconnected);
        assert_eq!(request.protocol_version, INTERNAL_WORKER_PROTOCOL_VERSION);
        assert_eq!(request.magic, INTERNAL_WORKER_MAGIC);
        assert!(request.encode_to_vec().len() <= MAX_INTERNAL_WORKER_FRAME);
    }
}
