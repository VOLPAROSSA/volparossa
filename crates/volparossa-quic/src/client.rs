//! Authenticated, bounded client for the isolated native MPQUIC process.

use std::{
    fs,
    io::IoSlice,
    net::{IpAddr, SocketAddr},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt},
        },
    },
    path::{Component, Path, PathBuf},
    time::Duration,
};

use nix::{
    errno::Errno,
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    sys::socket::{ControlMessage, MsgFlags, getsockopt, sendmsg, sockopt},
    unistd::geteuid,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::UnixStream, time::timeout};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AddPath, GetStatus, NATIVE_API_VERSION, NativePathStatus, NativeRequest, NativeResponse,
    NativeResultCode, ReceiveDatagram, ReceivedDatagram, RemovePath, SendDatagram,
    StartExitSession, StartSession, StopSession,
    control::{validate_add_path, validate_start_exit},
    encode_request, native_request, read_response,
};

const FD_BINDING_LEN: usize = 32;
const ADD_PATH_FD_DOMAIN: &[u8] = b"VOLPAROSSA-MPQUIC-ADD-PATH-FD-V5\0";
const START_EXIT_FD_DOMAIN: &[u8] = b"VOLPAROSSA-MPQUIC-START-EXIT-FD-V5\0";
const NATIVE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SOCKET_PATH_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DescriptorPurpose {
    None,
    AddPath,
    StartExit,
}

/// Strict client for the unprivileged native process boundary.
#[derive(Clone, Debug)]
pub struct NativeClient {
    socket: PathBuf,
    expected_uid: u32,
    operation_timeout: Duration,
}

impl NativeClient {
    /// Constructs a client for one packaging-controlled absolute socket path.
    ///
    /// # Errors
    ///
    /// Relative, root, oversized and traversal-containing paths are rejected.
    pub fn new(socket: PathBuf) -> Result<Self, NativeClientError> {
        validate_path(&socket)?;
        Ok(Self {
            socket,
            expected_uid: geteuid().as_raw(),
            operation_timeout: NATIVE_TIMEOUT,
        })
    }

    /// Starts one pre-authorised genuine-multipath session.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket, timeout, framing/correlation failure, or a native
    /// rejection.
    pub async fn start_session(&self, value: StartSession) -> Result<(), NativeClientError> {
        self.execute_ok(native_request::Operation::StartSession(value), None)
            .await
    }

    /// Submits one short-lived route authorization to an explicitly enabled exit.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket, timeout, framing/correlation failure, or a native
    /// rejection. The descriptor is consumed on every success and failure path. It must be the
    /// exact unconnected, bound, nonblocking UDP listener named by the canonical request, with
    /// close-on-exec set and address/port reuse disabled. These current socket checks do not prove
    /// helper origin, assigned-address state, or network-namespace identity. The current native
    /// implementation still fails closed after consuming the listener until a descriptor-consuming
    /// exit transport factory is implemented.
    pub async fn start_exit_session(
        &self,
        value: StartExitSession,
        listener: OwnedFd,
    ) -> Result<(), NativeClientError> {
        let listener = validate_exit_listener_descriptor(&value, listener)?;
        self.execute_ok(
            native_request::Operation::StartExitSession(value),
            Some(listener),
        )
        .await
    }

    /// Adds one candidate route-namespace path socket.
    ///
    /// # Errors
    ///
    /// The descriptor is consumed on every success and failure path. It must be an unconnected,
    /// bound, nonblocking UDP socket with close-on-exec set and a local tuple exactly matching the
    /// canonical request metadata. The metadata must name the IPv6 VOLPAROSSA client-to-exit
    /// overlayshape; IPv4 and public-underlay tuples fail closed.
    ///
    /// `SCM_RIGHTS` transfer and the request hash prove correlation, not privileged-helper origin.
    /// Production orchestration remains blocked until helper provenance is independently bound.
    pub async fn add_path(
        &self,
        value: AddPath,
        descriptor: OwnedFd,
    ) -> Result<(), NativeClientError> {
        let descriptor = validate_path_descriptor(&value, descriptor)?;
        self.execute_ok(native_request::Operation::AddPath(value), Some(descriptor))
            .await
    }

    /// Removes one exact context-local path.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket, timeout, framing/correlation failure, or a native
    /// rejection.
    pub async fn remove_path(&self, value: RemovePath) -> Result<(), NativeClientError> {
        self.execute_ok(native_request::Operation::RemovePath(value), None)
            .await
    }

    /// Sends one already-authorised inner IP datagram.
    ///
    /// Both the request payload and encoded local-control frame are zeroized after use.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket, timeout, framing/correlation failure, or a native
    /// rejection.
    pub async fn send_datagram(&self, value: SendDatagram) -> Result<(), NativeClientError> {
        self.execute_ok(native_request::Operation::SendDatagram(value), None)
            .await
    }

    /// Polls one reverse inner IP datagram without an asynchronous push channel.
    ///
    /// The returned datagram wipes its packet and correlation fields on drop.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket, timeout, queue overflow, wrong correlation, framing
    /// failure, or another native rejection.
    pub async fn receive_datagram(
        &self,
        value: ReceiveDatagram,
    ) -> Result<Option<ReceivedDatagram>, NativeClientError> {
        let expected_route_context = value.route_context_id.clone();
        let expected_masque_context = value.masque_context_id;
        let mut response = self
            .exchange(native_request::Operation::ReceiveDatagram(value), None)
            .await?;
        let result = response_result(&response)?;
        if result == NativeResultCode::NoDatagram {
            if response.received_datagram.is_some() || !response.paths.is_empty() {
                return Err(NativeClientError::Correlation);
            }
            return Ok(None);
        }
        if result != NativeResultCode::Ok {
            return Err(rejected(response, result));
        }
        if !response.paths.is_empty() {
            return Err(NativeClientError::Correlation);
        }
        let mut datagram = response
            .received_datagram
            .take()
            .ok_or(NativeClientError::Correlation)?;
        if datagram.route_context_id != expected_route_context
            || datagram.masque_context_id != expected_masque_context
        {
            datagram.wipe();
            return Err(NativeClientError::Correlation);
        }
        Ok(Some(datagram))
    }

    /// Returns bounded genuine per-path native telemetry.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket, timeout, framing/correlation failure, or a native
    /// rejection.
    pub async fn status(
        &self,
        value: GetStatus,
    ) -> Result<Vec<NativePathStatus>, NativeClientError> {
        let response = self
            .exchange(native_request::Operation::GetStatus(value), None)
            .await?;
        let result = response_result(&response)?;
        if result != NativeResultCode::Ok {
            return Err(rejected(response, result));
        }
        if response.received_datagram.is_some() {
            return Err(NativeClientError::Correlation);
        }
        Ok(response.paths)
    }

    /// Stops and wipes one exact native session.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket, timeout, framing/correlation failure, or a native
    /// rejection.
    pub async fn stop_session(&self, value: StopSession) -> Result<(), NativeClientError> {
        self.execute_ok(native_request::Operation::StopSession(value), None)
            .await
    }

    async fn execute_ok(
        &self,
        operation: native_request::Operation,
        descriptor: Option<Socket>,
    ) -> Result<(), NativeClientError> {
        let response = self.exchange(operation, descriptor).await?;
        let result = response_result(&response)?;
        if result != NativeResultCode::Ok {
            return Err(rejected(response, result));
        }
        if response.received_datagram.is_some() || !response.paths.is_empty() {
            return Err(NativeClientError::Correlation);
        }
        Ok(())
    }

    async fn exchange(
        &self,
        operation: native_request::Operation,
        descriptor: Option<Socket>,
    ) -> Result<NativeResponse, NativeClientError> {
        validate_socket(&self.socket, self.expected_uid)?;
        let mut nonce = Zeroizing::new([0_u8; 16]);
        let descriptor_purpose = match &operation {
            native_request::Operation::AddPath(_) => DescriptorPurpose::AddPath,
            native_request::Operation::StartExitSession(_) => DescriptorPurpose::StartExit,
            _ => DescriptorPurpose::None,
        };
        if (descriptor_purpose != DescriptorPurpose::None) != descriptor.is_some() {
            return Err(NativeClientError::InvalidDescriptorBundle);
        }

        OsRng.fill_bytes(nonce.as_mut());
        let mut request = NativeRequest {
            api_version: NATIVE_API_VERSION,
            request_nonce: nonce.to_vec(),
            operation: Some(operation),
        };
        let mut frame = Zeroizing::new(encode_request(&request)?);
        let binding = request_binding(frame.as_slice(), descriptor_purpose)?;
        zeroize_sensitive_request(&mut request);
        let response = timeout(self.operation_timeout, async {
            let mut stream = UnixStream::connect(&self.socket).await?;
            let peer = stream.peer_cred()?;
            if peer.uid() != self.expected_uid {
                return Err(NativeClientError::PeerCredentials);
            }
            send_control_binding(&stream, &binding, descriptor.as_ref()).await?;
            stream.write_all(frame.as_slice()).await?;
            stream.flush().await?;
            stream.shutdown().await?;
            let response = read_response(&mut stream).await?;
            Ok::<NativeResponse, NativeClientError>(response)
        })
        .await
        .map_err(|_| NativeClientError::Timeout)??;
        frame.zeroize();
        if response.request_nonce.as_slice() != nonce.as_slice() {
            return Err(NativeClientError::Correlation);
        }
        Ok(response)
    }
}

fn response_result(response: &NativeResponse) -> Result<NativeResultCode, NativeClientError> {
    NativeResultCode::try_from(response.result).map_err(|_| NativeClientError::Correlation)
}
fn request_binding(
    frame: &[u8],
    purpose: DescriptorPurpose,
) -> Result<[u8; FD_BINDING_LEN], NativeClientError> {
    let domain = match purpose {
        DescriptorPurpose::None => return Ok([0_u8; FD_BINDING_LEN]),
        DescriptorPurpose::AddPath => ADD_PATH_FD_DOMAIN,
        DescriptorPurpose::StartExit => START_EXIT_FD_DOMAIN,
    };
    let payload = frame.get(4..).ok_or(crate::ControlError::Invalid(
        "missing canonical request payload",
    ))?;
    if payload.is_empty() {
        return Err(crate::ControlError::Invalid("empty canonical request payload").into());
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| crate::ControlError::TooLarge)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload_len.to_be_bytes());
    hasher.update(payload);
    Ok(hasher.finalize().into())
}

async fn send_control_binding(
    stream: &UnixStream,
    binding: &[u8; FD_BINDING_LEN],
    descriptor: Option<&Socket>,
) -> Result<(), NativeClientError> {
    loop {
        stream.writable().await?;
        let iov = [IoSlice::new(binding)];
        let result = if let Some(socket) = descriptor {
            let descriptors = [socket.as_raw_fd()];
            let ancillary = [ControlMessage::ScmRights(&descriptors)];
            sendmsg::<()>(
                stream.as_raw_fd(),
                &iov,
                &ancillary,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                None,
            )
        } else {
            sendmsg::<()>(
                stream.as_raw_fd(),
                &iov,
                &[],
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                None,
            )
        };
        match result {
            Ok(FD_BINDING_LEN) => return Ok(()),
            Ok(_) => {
                return Err(NativeClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "native descriptor binding was only partially sent",
                )));
            }
            Err(Errno::EAGAIN) => continue,
            Err(error) => return Err(NativeClientError::Io(error.into())),
        }
    }
}

fn validate_path_descriptor(
    path: &AddPath,
    descriptor: OwnedFd,
) -> Result<Socket, NativeClientError> {
    let socket = Socket::from(descriptor);
    validate_add_path(path).map_err(|_| NativeClientError::InvalidPathDescriptor)?;
    let local_ip = decode_ip(&path.local_ip).ok_or(NativeClientError::InvalidPathDescriptor)?;
    let remote_ip = decode_ip(&path.remote_ip).ok_or(NativeClientError::InvalidPathDescriptor)?;
    let local_port = u16::try_from(path.local_port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(NativeClientError::InvalidPathDescriptor)?;
    let remote_port = u16::try_from(path.remote_port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(NativeClientError::InvalidPathDescriptor)?;
    if local_ip.is_unspecified()
        || remote_ip.is_unspecified()
        || local_ip == remote_ip
        || local_ip.is_ipv4() != remote_ip.is_ipv4()
        || socket.r#type()? != Type::DGRAM
        || socket.protocol()? != Some(Protocol::UDP)
        || getsockopt(&socket, sockopt::AcceptConn)
            .map_err(|error| NativeClientError::Io(error.into()))?
        || socket.take_error()?.is_some()
        || socket.local_addr()?.as_socket() != Some(SocketAddr::new(local_ip, local_port))
    {
        return Err(NativeClientError::InvalidPathDescriptor);
    }
    match socket.peer_addr() {
        Err(error) if error.raw_os_error() == Some(nix::libc::ENOTCONN) => {}
        _ => return Err(NativeClientError::InvalidPathDescriptor),
    }
    let descriptor_flags = FdFlag::from_bits_truncate(
        fcntl(&socket, FcntlArg::F_GETFD).map_err(|error| NativeClientError::Io(error.into()))?,
    );
    let status_flags = OFlag::from_bits_truncate(
        fcntl(&socket, FcntlArg::F_GETFL).map_err(|error| NativeClientError::Io(error.into()))?,
    );
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC) || !status_flags.contains(OFlag::O_NONBLOCK) {
        return Err(NativeClientError::InvalidPathDescriptor);
    }
    let _validated_remote = SocketAddr::new(remote_ip, remote_port);
    Ok(socket)
}

fn validate_exit_listener_descriptor(
    start: &StartExitSession,
    descriptor: OwnedFd,
) -> Result<Socket, NativeClientError> {
    let socket = Socket::from(descriptor);
    validate_start_exit(start).map_err(|_| NativeClientError::InvalidExitListenerDescriptor)?;
    let listener_ip =
        decode_ip(&start.listener_ip).ok_or(NativeClientError::InvalidExitListenerDescriptor)?;
    let listener_port = u16::try_from(start.listener_port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(NativeClientError::InvalidExitListenerDescriptor)?;
    if listener_ip.is_unspecified()
        || !listener_ip.is_ipv6()
        || socket.domain()? != Domain::IPV6
        || socket.r#type()? != Type::DGRAM
        || socket.protocol()? != Some(Protocol::UDP)
        || getsockopt(&socket, sockopt::AcceptConn)
            .map_err(|error| NativeClientError::Io(error.into()))?
        || socket.take_error()?.is_some()
        || !socket.only_v6()?
        || socket.reuse_address()?
        || socket.reuse_port()?
        || socket.local_addr()?.as_socket() != Some(SocketAddr::new(listener_ip, listener_port))
    {
        return Err(NativeClientError::InvalidExitListenerDescriptor);
    }
    match socket.peer_addr() {
        Err(error) if error.raw_os_error() == Some(nix::libc::ENOTCONN) => {}
        _ => return Err(NativeClientError::InvalidExitListenerDescriptor),
    }
    let descriptor_flags = FdFlag::from_bits_truncate(
        fcntl(&socket, FcntlArg::F_GETFD).map_err(|error| NativeClientError::Io(error.into()))?,
    );
    let status_flags = OFlag::from_bits_truncate(
        fcntl(&socket, FcntlArg::F_GETFL).map_err(|error| NativeClientError::Io(error.into()))?,
    );
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC) || !status_flags.contains(OFlag::O_NONBLOCK) {
        return Err(NativeClientError::InvalidExitListenerDescriptor);
    }
    Ok(socket)
}

fn decode_ip(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes).ok().map(IpAddr::from),
        16 => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
        _ => None,
    }
}

fn rejected(response: NativeResponse, result: NativeResultCode) -> NativeClientError {
    NativeClientError::Rejected {
        result,
        diagnostic_code: response.diagnostic_code,
    }
}

fn zeroize_sensitive_request(request: &mut NativeRequest) {
    match request.operation.as_mut() {
        Some(native_request::Operation::StartSession(value)) => {
            value.auth_secret.zeroize();
            value.tls_server_name.zeroize();
        }
        Some(native_request::Operation::StartExitSession(value)) => {
            value.zeroize();
        }
        Some(native_request::Operation::SendDatagram(value)) => {
            value.inner_ip_packet.zeroize();
        }
        _ => {}
    }
}

fn validate_path(path: &Path) -> Result<(), NativeClientError> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(NativeClientError::InvalidPath);
    }
    Ok(())
}

fn validate_socket(path: &Path, expected_uid: u32) -> Result<(), NativeClientError> {
    let parent = path.parent().ok_or(NativeClientError::InvalidPath)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != expected_uid
        || parent_metadata.mode() & 0o777 != 0o700
    {
        return Err(NativeClientError::UnsafeSocket);
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(NativeClientError::UnsafeSocket);
    }
    Ok(())
}

/// Stable native-client failure categories.
#[derive(Debug, Error)]
pub enum NativeClientError {
    /// The packaging-controlled path was not a bounded absolute normal path.
    #[error("native socket path is invalid")]
    InvalidPath,
    /// Socket or parent metadata did not match the protected service boundary.
    #[error("native control socket metadata is unsafe")]
    UnsafeSocket,
    /// The connected process did not run under the expected service UID.
    #[error("native control peer credentials do not match")]
    PeerCredentials,
    /// The supplied path socket failed strict local validation.
    #[error("path socket is invalid")]
    InvalidPathDescriptor,
    /// The supplied exit-listener socket failed strict local validation.
    #[error("exit listener socket is invalid")]
    InvalidExitListenerDescriptor,
    /// The operation and exact descriptor bundle did not match.
    #[error("native descriptor bundle is invalid")]
    InvalidDescriptorBundle,
    /// Local socket I/O failed.
    #[error("native client I/O failed")]
    Io(#[from] std::io::Error),
    /// The bounded versioned native protocol failed validation.
    #[error("native client protocol failed")]
    Protocol(#[from] crate::control::ControlError),
    /// The complete connect/write/read exchange exceeded its fixed deadline.
    #[error("native client operation timed out")]
    Timeout,
    /// The response did not bind to the generated request nonce.
    #[error("native response correlation failed")]
    Correlation,
    /// The native process safely rejected the typed operation.
    #[error("native operation rejected with {result:?}: {diagnostic_code}")]
    Rejected {
        /// Stable result class.
        result: NativeResultCode,
        /// Bounded protocol-safe diagnostic code.
        diagnostic_code: String,
    },
}

#[cfg(test)]
mod tests {
    use std::{
        fs::Permissions,
        io::IoSliceMut,
        net::{Ipv4Addr, Ipv6Addr},
        os::{fd::RawFd, unix::fs::PermissionsExt},
        time::Instant,
    };

    use nix::sys::socket::{ControlMessageOwned, recvmsg};
    use nix::unistd::{close, dup};
    use socket2::{Domain, SockAddr};
    use tempfile::tempdir;
    use tokio::{io::AsyncReadExt, net::UnixListener};

    use super::*;
    use crate::{NativeResponse, read_request};

    fn secure_listener() -> (tempfile::TempDir, PathBuf, UnixListener) {
        let directory = tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).expect("dir mode");
        let path = directory.path().join("native.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        fs::set_permissions(&path, Permissions::from_mode(0o600)).expect("socket mode");
        (directory, path, listener)
    }
    async fn read_regular_request(stream: &mut UnixStream) -> NativeRequest {
        let mut binding = [0_u8; FD_BINDING_LEN];
        stream.read_exact(&mut binding).await.expect("binding");
        assert_eq!(binding, [0_u8; FD_BINDING_LEN]);
        let request = read_request(stream).await.expect("request");
        let mut trailing = [0_u8; 1];
        assert_eq!(stream.read(&mut trailing).await.expect("EOF"), 0);
        request
    }

    async fn read_descriptor_request(
        stream: &mut UnixStream,
        purpose: DescriptorPurpose,
    ) -> NativeRequest {
        let mut binding = [0_u8; FD_BINDING_LEN];
        let descriptors = loop {
            stream.readable().await.expect("readable");
            let attempt = {
                let mut iov = [IoSliceMut::new(&mut binding)];
                let mut control = nix::cmsg_space!([RawFd; 2]);
                match recvmsg::<()>(
                    stream.as_raw_fd(),
                    &mut iov,
                    Some(&mut control),
                    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_CMSG_CLOEXEC,
                ) {
                    Ok(message) => {
                        assert_eq!(message.bytes, FD_BINDING_LEN);
                        assert!(
                            !message
                                .flags
                                .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
                        );
                        let mut received = Vec::new();
                        for ancillary in message.cmsgs().expect("ancillary") {
                            match ancillary {
                                ControlMessageOwned::ScmRights(values) => {
                                    received.extend(values);
                                }
                                _ => panic!("unexpected ancillary"),
                            }
                        }
                        Some(received)
                    }
                    Err(Errno::EAGAIN) => None,
                    Err(error) => panic!("recvmsg: {error}"),
                }
            };
            if let Some(received) = attempt {
                break received;
            }
        };
        assert_eq!(descriptors.len(), 1);
        let request = read_request(stream).await.expect("request");
        let mut trailing = [0_u8; 1];
        assert_eq!(stream.read(&mut trailing).await.expect("EOF"), 0);
        let frame = encode_request(&request).expect("canonical request");
        assert_eq!(
            binding,
            request_binding(&frame, purpose).expect("request binding")
        );
        close(descriptors[0]).expect("close received descriptor");
        request
    }

    fn overlay_address(path_id: u16, host: u16) -> Ipv6Addr {
        Ipv6Addr::new(
            0xfd76, 0x6f6c, 0x7061, 0x1111, 0x2222, path_id, 0x3333, host,
        )
    }

    fn bound_overlay_socket(
        socket_type: Type,
        protocol: Protocol,
        nonblocking: bool,
    ) -> (Socket, SocketAddr) {
        let socket =
            Socket::new(Domain::IPV6, socket_type.cloexec(), Some(protocol)).expect("IPv6 socket");
        socket.set_freebind_v6(true).expect("IPv6 FREEBIND");
        socket
            .bind(&SockAddr::from(SocketAddr::new(
                IpAddr::V6(overlay_address(1, 1)),
                0,
            )))
            .expect("overlay bind");
        socket
            .set_nonblocking(nonblocking)
            .expect("nonblocking state");
        let local = socket
            .local_addr()
            .expect("local address")
            .as_socket()
            .expect("IP socket");
        (socket, local)
    }

    fn bound_exit_listener_socket(
        nonblocking: bool,
        reuse_address: bool,
        reuse_port: bool,
    ) -> (Socket, SocketAddr) {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM.cloexec(), Some(Protocol::UDP))
            .expect("IPv6 socket");
        socket.set_only_v6(true).expect("IPv6-only state");
        socket
            .set_reuse_address(reuse_address)
            .expect("address-reuse state");
        socket.set_reuse_port(reuse_port).expect("port-reuse state");
        socket.set_freebind_v6(true).expect("IPv6 FREEBIND");
        socket
            .bind(&SockAddr::from(SocketAddr::new(
                IpAddr::V6(overlay_address(1, 4)),
                0,
            )))
            .expect("exit overlay bind");
        socket
            .set_nonblocking(nonblocking)
            .expect("nonblocking state");
        let local = socket
            .local_addr()
            .expect("local address")
            .as_socket()
            .expect("IP socket");
        (socket, local)
    }

    fn add_path_for(local: SocketAddr) -> AddPath {
        assert_eq!(local.ip(), IpAddr::V6(overlay_address(1, 1)));
        AddPath {
            route_context_id: vec![1; 16],
            path_id: 1,
            local_ip: overlay_address(1, 1).octets().to_vec(),
            remote_ip: overlay_address(1, 4).octets().to_vec(),
            remote_port: 443,
            reservation_hash: vec![2; 32],
            local_port: u32::from(local.port()),
        }
    }

    fn start_exit_for(local: SocketAddr) -> StartExitSession {
        assert_eq!(local.ip(), IpAddr::V6(overlay_address(1, 4)));
        StartExitSession {
            route_context_id: vec![1; 16],
            auth_secret: b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
            expires_at_ms: 1_060_000,
            minimum_paths: 1,
            masque_context_id: 19,
            transport_mode: crate::TransportMode::SinglePathGeneralUdp as i32,
            exit_spki_sha256: vec![2; 32],
            tls_server_name: b"exit.example".to_vec(),
            path_id: 1,
            listener_ip: overlay_address(1, 4).octets().to_vec(),
            listener_port: u32::from(local.port()),
            expected_client_ip: overlay_address(1, 1).octets().to_vec(),
            expected_client_port: 51_820,
            reservation_hash: vec![3; 32],
            tls_certificate_pem: b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
                .to_vec(),
            tls_private_key_pem: b"-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n"
                .to_vec(),
        }
    }

    async fn assert_exit_listener_rejected(
        client: &NativeClient,
        request: StartExitSession,
        socket: Socket,
    ) {
        let descriptor: OwnedFd = socket.into();
        let probe = DescriptorProbe::new(&descriptor);
        let result = client.start_exit_session(request, descriptor).await;
        assert!(
            matches!(
                result,
                Err(NativeClientError::InvalidExitListenerDescriptor)
            ),
            "unexpected listener-validation result"
        );
        probe.assert_consumed();
    }

    fn public_underlay_path(local: SocketAddr) -> AddPath {
        let IpAddr::V4(local_ip) = local.ip() else {
            panic!("IPv4 fixture");
        };
        AddPath {
            route_context_id: vec![1; 16],
            path_id: 1,
            local_ip: local_ip.octets().to_vec(),
            remote_ip: [192, 0, 2, 4].to_vec(),
            remote_port: 443,
            reservation_hash: vec![2; 32],
            local_port: u32::from(local.port()),
        }
    }

    struct DescriptorProbe {
        original: RawFd,
        duplicate: OwnedFd,
    }

    impl DescriptorProbe {
        fn new(descriptor: &OwnedFd) -> Self {
            Self {
                original: descriptor.as_raw_fd(),
                duplicate: dup(descriptor).expect("duplicate test descriptor"),
            }
        }

        fn assert_consumed(self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let replacement = fcntl(&self.duplicate, FcntlArg::F_DUPFD_CLOEXEC(self.original))
                    .expect("probe closed descriptor slot");
                if replacement == self.original {
                    close(replacement).expect("close probe replacement");
                    return;
                }
                close(replacement).expect("close contended probe replacement");
                assert!(
                    Instant::now() < deadline,
                    "consumed descriptor slot remained occupied by parallel test activity"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn ipv4_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet
    }
    #[tokio::test]
    async fn status_exchange_checks_peer_and_nonce() {
        let (_directory, path, listener) = secure_listener();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = read_regular_request(&mut stream).await;
            assert!(matches!(
                request.operation,
                Some(native_request::Operation::GetStatus(_))
            ));
            let response = NativeResponse {
                api_version: NATIVE_API_VERSION,
                request_nonce: request.request_nonce,
                result: NativeResultCode::Ok as i32,
                diagnostic_code: "OK".to_owned(),
                paths: vec![NativePathStatus {
                    path_id: 1,
                    smoothed_rtt_us: 1_000,
                    packets_lost: 0,
                    delivered_bytes: 4_096,
                    congestion_window_bytes: 64_000,
                    bytes_in_flight: 512,
                    delivery_rate_bps: 8_000_000,
                    data_carrying: true,
                }],
                received_datagram: None,
            };
            stream
                .write_all(&crate::encode_response(&response).expect("response"))
                .await
                .expect("write");
        });
        let statuses = NativeClient::new(path)
            .expect("client")
            .status(GetStatus {
                route_context_id: vec![1; 16],
            })
            .await
            .expect("status");
        assert_eq!(statuses.len(), 1);
        assert!(statuses[0].data_carrying);
        server.await.expect("server");
    }

    #[tokio::test]
    async fn mismatched_nonce_fails_closed() {
        let (_directory, path, listener) = secure_listener();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _request = read_regular_request(&mut stream).await;
            let response = NativeResponse {
                api_version: NATIVE_API_VERSION,
                request_nonce: vec![9; 16],
                result: NativeResultCode::Ok as i32,
                diagnostic_code: "OK".to_owned(),
                paths: Vec::new(),
                received_datagram: None,
            };
            stream
                .write_all(&crate::encode_response(&response).expect("response"))
                .await
                .expect("write");
        });
        let error = NativeClient::new(path)
            .expect("client")
            .status(GetStatus {
                route_context_id: vec![1; 16],
            })
            .await
            .expect_err("nonce mismatch");
        assert!(matches!(error, NativeClientError::Correlation));
        server.await.expect("server");
    }

    #[tokio::test]
    async fn reverse_datagram_is_correlated_and_delivered() {
        let (_directory, path, listener) = secure_listener();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = read_regular_request(&mut stream).await;
            let Some(native_request::Operation::ReceiveDatagram(value)) = request.operation else {
                panic!("receive request");
            };
            let response = NativeResponse {
                api_version: NATIVE_API_VERSION,
                request_nonce: request.request_nonce,
                result: NativeResultCode::Ok as i32,
                diagnostic_code: "datagram".to_owned(),
                paths: Vec::new(),
                received_datagram: Some(ReceivedDatagram {
                    route_context_id: value.route_context_id,
                    masque_context_id: value.masque_context_id,
                    inner_ip_packet: ipv4_packet(),
                }),
            };
            stream
                .write_all(&crate::encode_response(&response).expect("response"))
                .await
                .expect("write");
        });
        let datagram = NativeClient::new(path)
            .expect("client")
            .receive_datagram(ReceiveDatagram {
                route_context_id: vec![1; 16],
                masque_context_id: 17,
            })
            .await
            .expect("receive")
            .expect("queued datagram");
        assert_eq!(datagram.masque_context_id, 17);
        assert_eq!(datagram.inner_ip_packet, ipv4_packet());
        server.await.expect("server");
    }

    #[tokio::test]
    async fn empty_and_overflow_receive_results_are_distinct() {
        for expected_result in [
            NativeResultCode::NoDatagram,
            NativeResultCode::QueueOverflow,
        ] {
            let (_directory, path, listener) = secure_listener();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let request = read_regular_request(&mut stream).await;
                assert!(matches!(
                    request.operation,
                    Some(native_request::Operation::ReceiveDatagram(_))
                ));
                let response = NativeResponse {
                    api_version: NATIVE_API_VERSION,
                    request_nonce: request.request_nonce,
                    result: expected_result as i32,
                    diagnostic_code: if expected_result == NativeResultCode::NoDatagram {
                        "no_datagram"
                    } else {
                        "reverse_queue_overflow"
                    }
                    .to_owned(),
                    paths: Vec::new(),
                    received_datagram: None,
                };
                stream
                    .write_all(&crate::encode_response(&response).expect("response"))
                    .await
                    .expect("write");
            });
            let result = NativeClient::new(path)
                .expect("client")
                .receive_datagram(ReceiveDatagram {
                    route_context_id: vec![1; 16],
                    masque_context_id: 17,
                })
                .await;
            if expected_result == NativeResultCode::NoDatagram {
                assert!(result.expect("empty receive").is_none());
            } else {
                assert!(matches!(
                    result,
                    Err(NativeClientError::Rejected {
                        result: NativeResultCode::QueueOverflow,
                        ..
                    })
                ));
            }
            server.await.expect("server");
        }
    }

    #[tokio::test]
    async fn wrong_reverse_context_fails_closed() {
        let (_directory, path, listener) = secure_listener();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = read_regular_request(&mut stream).await;
            let response = NativeResponse {
                api_version: NATIVE_API_VERSION,
                request_nonce: request.request_nonce,
                result: NativeResultCode::Ok as i32,
                diagnostic_code: "datagram".to_owned(),
                paths: Vec::new(),
                received_datagram: Some(ReceivedDatagram {
                    route_context_id: vec![2; 16],
                    masque_context_id: 18,
                    inner_ip_packet: ipv4_packet(),
                }),
            };
            stream
                .write_all(&crate::encode_response(&response).expect("response"))
                .await
                .expect("write");
        });
        let error = NativeClient::new(path)
            .expect("client")
            .receive_datagram(ReceiveDatagram {
                route_context_id: vec![1; 16],
                masque_context_id: 17,
            })
            .await
            .expect_err("wrong context");
        assert!(matches!(error, NativeClientError::Correlation));
        server.await.expect("server");
    }

    #[tokio::test]
    async fn add_path_sends_exact_descriptor_and_canonical_binding() {
        let (_directory, path, listener) = secure_listener();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = read_descriptor_request(&mut stream, DescriptorPurpose::AddPath).await;
            assert!(matches!(
                request.operation,
                Some(native_request::Operation::AddPath(_))
            ));
            let response = NativeResponse {
                api_version: NATIVE_API_VERSION,
                request_nonce: request.request_nonce,
                result: NativeResultCode::Ok as i32,
                diagnostic_code: "path_registered".to_owned(),
                paths: Vec::new(),
                received_datagram: None,
            };
            stream
                .write_all(&crate::encode_response(&response).expect("response"))
                .await
                .expect("write");
        });

        let (socket, local) = bound_overlay_socket(Type::DGRAM, Protocol::UDP, true);
        let descriptor: OwnedFd = socket.into();
        let probe = DescriptorProbe::new(&descriptor);
        NativeClient::new(path)
            .expect("client")
            .add_path(add_path_for(local), descriptor)
            .await
            .expect("add path");
        probe.assert_consumed();
        server.await.expect("server");
    }

    #[tokio::test]
    async fn start_exit_sends_one_listener_shaped_fd_with_distinct_canonical_binding() {
        let (_directory, path, listener) = secure_listener();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = read_descriptor_request(&mut stream, DescriptorPurpose::StartExit).await;
            assert!(matches!(
                request.operation,
                Some(native_request::Operation::StartExitSession(_))
            ));
            let response = NativeResponse {
                api_version: NATIVE_API_VERSION,
                request_nonce: request.request_nonce,
                result: NativeResultCode::Transport as i32,
                diagnostic_code: "exit_listener_orchestration_unavailable".to_owned(),
                paths: Vec::new(),
                received_datagram: None,
            };
            stream
                .write_all(&crate::encode_response(&response).expect("response"))
                .await
                .expect("write");
        });

        let (socket, local) = bound_exit_listener_socket(true, false, false);
        let descriptor: OwnedFd = socket.into();
        let probe = DescriptorProbe::new(&descriptor);
        let error = NativeClient::new(path)
            .expect("client")
            .start_exit_session(start_exit_for(local), descriptor)
            .await
            .expect_err("runtime remains unavailable");
        assert!(matches!(
            error,
            NativeClientError::Rejected {
                result: NativeResultCode::Transport,
                ..
            }
        ));
        probe.assert_consumed();
        server.await.expect("server");
    }

    #[test]
    fn descriptor_binding_domains_do_not_cross_correlate() {
        let request = NativeRequest {
            api_version: NATIVE_API_VERSION,
            request_nonce: vec![7; 16],
            operation: Some(native_request::Operation::GetStatus(GetStatus {
                route_context_id: vec![1; 16],
            })),
        };
        let frame = encode_request(&request).expect("canonical request");
        assert_ne!(
            request_binding(&frame, DescriptorPurpose::AddPath).expect("AddPath binding"),
            request_binding(&frame, DescriptorPurpose::StartExit).expect("StartExit binding")
        );
        assert_eq!(
            request_binding(&frame, DescriptorPurpose::None).expect("unbound operation"),
            [0; FD_BINDING_LEN]
        );
    }

    #[tokio::test]
    async fn add_path_consumes_descriptor_on_native_rejection() {
        let (_directory, path, listener) = secure_listener();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = read_descriptor_request(&mut stream, DescriptorPurpose::AddPath).await;
            let response = NativeResponse {
                api_version: NATIVE_API_VERSION,
                request_nonce: request.request_nonce,
                result: NativeResultCode::Transport as i32,
                diagnostic_code: "path_rejected".to_owned(),
                paths: Vec::new(),
                received_datagram: None,
            };
            stream
                .write_all(&crate::encode_response(&response).expect("response"))
                .await
                .expect("write");
        });

        let (socket, local) = bound_overlay_socket(Type::DGRAM, Protocol::UDP, true);
        let descriptor: OwnedFd = socket.into();
        let probe = DescriptorProbe::new(&descriptor);
        let error = NativeClient::new(path)
            .expect("client")
            .add_path(add_path_for(local), descriptor)
            .await
            .expect_err("native rejection");
        assert!(matches!(
            error,
            NativeClientError::Rejected {
                result: NativeResultCode::Transport,
                ..
            }
        ));
        probe.assert_consumed();
        server.await.expect("server");
    }

    #[tokio::test]
    async fn add_path_consumes_descriptor_on_timeout() {
        let (_directory, path, listener) = secure_listener();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = read_descriptor_request(&mut stream, DescriptorPurpose::AddPath).await;
            assert!(matches!(
                request.operation,
                Some(native_request::Operation::AddPath(_))
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let (socket, local) = bound_overlay_socket(Type::DGRAM, Protocol::UDP, true);
        let descriptor: OwnedFd = socket.into();
        let probe = DescriptorProbe::new(&descriptor);
        let mut client = NativeClient::new(path).expect("client");
        client.operation_timeout = Duration::from_millis(20);
        assert!(matches!(
            client.add_path(add_path_for(local), descriptor).await,
            Err(NativeClientError::Timeout)
        ));
        probe.assert_consumed();
        server.await.expect("server");
    }

    #[tokio::test]
    async fn local_path_descriptor_validation_fails_closed() {
        let (_directory, path, _listener) = secure_listener();
        let client = NativeClient::new(path).expect("client");

        let (blocking, local) = bound_overlay_socket(Type::DGRAM, Protocol::UDP, false);
        let descriptor: OwnedFd = blocking.into();
        let probe = DescriptorProbe::new(&descriptor);
        assert!(matches!(
            client.add_path(add_path_for(local), descriptor).await,
            Err(NativeClientError::InvalidPathDescriptor)
        ));
        probe.assert_consumed();

        let (wrong_tuple, local) = bound_overlay_socket(Type::DGRAM, Protocol::UDP, true);
        let mut request = add_path_for(local);
        request.local_port = request.local_port.saturating_add(1);
        let descriptor: OwnedFd = wrong_tuple.into();
        let probe = DescriptorProbe::new(&descriptor);
        assert!(matches!(
            client.add_path(request, descriptor).await,
            Err(NativeClientError::InvalidPathDescriptor)
        ));
        probe.assert_consumed();

        let (connected, local) = bound_overlay_socket(Type::DGRAM, Protocol::UDP, true);
        connected
            .connect(&SockAddr::from(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                9,
            )))
            .expect("UDP connect");
        let descriptor: OwnedFd = connected.into();
        let probe = DescriptorProbe::new(&descriptor);
        assert!(matches!(
            client.add_path(add_path_for(local), descriptor).await,
            Err(NativeClientError::InvalidPathDescriptor)
        ));
        probe.assert_consumed();

        let (listener, local) = bound_overlay_socket(Type::STREAM, Protocol::TCP, true);
        listener.listen(1).expect("TCP listen");
        let descriptor: OwnedFd = listener.into();
        let probe = DescriptorProbe::new(&descriptor);
        assert!(matches!(
            client.add_path(add_path_for(local), descriptor).await,
            Err(NativeClientError::InvalidPathDescriptor)
        ));
        probe.assert_consumed();

        let public = Socket::new(
            Domain::IPV4,
            Type::DGRAM.cloexec().nonblocking(),
            Some(Protocol::UDP),
        )
        .expect("public UDP socket");
        public
            .bind(&SockAddr::from(
                "127.0.0.1:0".parse::<SocketAddr>().expect("tuple"),
            ))
            .expect("public bind");
        let local = public
            .local_addr()
            .expect("public local address")
            .as_socket()
            .expect("IP socket");
        let descriptor: OwnedFd = public.into();
        let probe = DescriptorProbe::new(&descriptor);
        assert!(matches!(
            client
                .add_path(public_underlay_path(local), descriptor)
                .await,
            Err(NativeClientError::InvalidPathDescriptor)
        ));
        probe.assert_consumed();
    }

    #[tokio::test]
    async fn local_exit_listener_validation_fails_closed_and_consumes_descriptor() {
        let (_directory, path, _listener) = secure_listener();
        let client = NativeClient::new(path).expect("client");

        let (blocking, local) = bound_exit_listener_socket(false, false, false);
        assert_exit_listener_rejected(&client, start_exit_for(local), blocking).await;

        let (wrong_tuple, local) = bound_exit_listener_socket(true, false, false);
        let mut request = start_exit_for(local);
        request.listener_port = request.listener_port.saturating_add(1);
        assert_exit_listener_rejected(&client, request, wrong_tuple).await;

        let (connected, local) = bound_exit_listener_socket(true, false, false);
        connected
            .connect(&SockAddr::from(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                9,
            )))
            .expect("UDP connect");
        assert_exit_listener_rejected(&client, start_exit_for(local), connected).await;

        let (reusable, local) = bound_exit_listener_socket(true, true, false);
        assert_exit_listener_rejected(&client, start_exit_for(local), reusable).await;

        let expected = SocketAddr::new(IpAddr::V6(overlay_address(1, 4)), 45_443);

        let wrong_family = Socket::new(Domain::IPV4, Type::DGRAM.cloexec(), Some(Protocol::UDP))
            .expect("IPv4 UDP socket");
        wrong_family
            .bind(&SockAddr::from(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                0,
            )))
            .expect("IPv4 bind");
        wrong_family
            .set_nonblocking(true)
            .expect("IPv4 nonblocking");
        assert_exit_listener_rejected(&client, start_exit_for(expected), wrong_family).await;

        let wrong_type = Socket::new(Domain::IPV6, Type::STREAM.cloexec(), Some(Protocol::TCP))
            .expect("IPv6 TCP socket");
        wrong_type.set_nonblocking(true).expect("TCP nonblocking");
        assert_exit_listener_rejected(&client, start_exit_for(expected), wrong_type).await;

        let wrong_protocol =
            Socket::new(Domain::UNIX, Type::DGRAM.cloexec(), None).expect("Unix datagram socket");
        wrong_protocol
            .set_nonblocking(true)
            .expect("Unix nonblocking");
        assert_exit_listener_rejected(&client, start_exit_for(expected), wrong_protocol).await;

        let dual_stack = Socket::new(Domain::IPV6, Type::DGRAM.cloexec(), Some(Protocol::UDP))
            .expect("dual-stack UDP socket");
        dual_stack.set_only_v6(false).expect("dual-stack state");
        dual_stack
            .set_nonblocking(true)
            .expect("dual-stack nonblocking");
        assert_exit_listener_rejected(&client, start_exit_for(expected), dual_stack).await;

        let (reusable_port, local) = bound_exit_listener_socket(true, false, true);
        assert_exit_listener_rejected(&client, start_exit_for(local), reusable_port).await;

        let (without_cloexec, local) = bound_exit_listener_socket(true, false, false);
        fcntl(&without_cloexec, FcntlArg::F_SETFD(FdFlag::empty())).expect("clear close-on-exec");
        assert_exit_listener_rejected(&client, start_exit_for(local), without_cloexec).await;

        let (wrong_address, local) = bound_exit_listener_socket(true, false, false);
        let mut request = start_exit_for(local);
        request.path_id = 2;
        request.listener_ip = overlay_address(2, 4).octets().to_vec();
        request.expected_client_ip = overlay_address(2, 1).octets().to_vec();
        assert_exit_listener_rejected(&client, request, wrong_address).await;
    }

    #[tokio::test]
    async fn unsafe_socket_mode_is_rejected_before_exchange() {
        let (_directory, path, _listener) = secure_listener();
        fs::set_permissions(&path, Permissions::from_mode(0o660)).expect("unsafe mode");
        let error = NativeClient::new(path)
            .expect("client")
            .status(GetStatus {
                route_context_id: vec![1; 16],
            })
            .await
            .expect_err("unsafe socket");
        assert!(matches!(error, NativeClientError::UnsafeSocket));
    }
}
