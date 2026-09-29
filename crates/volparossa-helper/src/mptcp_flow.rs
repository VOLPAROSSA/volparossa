//! Descriptor-backed identity for one issued Client MPTCP flow capability.
//!
//! This record contains no descriptor and cannot keep a data stream alive. Every mutation must
//! supply a transient actual meta descriptor and retain it until the worker operation completes.

use std::{io, net::SocketAddr, os::fd::OwnedFd};

use socket2::{Domain, Protocol, SockRef, Type};
use volparossa_linux_uapi::{mptcp_local_token, socket_network_namespace};

/// Kernel identity captured after the existing affine worker descriptor validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MptcpFlowIdentity {
    pub(crate) cookie: u64,
    pub(crate) token: u32,
    pub(crate) local: SocketAddr,
    pub(crate) remote: SocketAddr,
    namespace_device: u64,
    namespace_inode: u64,
}

impl MptcpFlowIdentity {
    pub(crate) fn capture(descriptor: &OwnedFd) -> io::Result<Self> {
        let socket = SockRef::from(descriptor);
        if socket.domain()? != Domain::IPV6
            || socket.r#type()? != Type::STREAM
            || socket.protocol()? != Some(Protocol::MPTCP)
            || socket.is_listener()?
        {
            return Err(invalid());
        }
        let local = socket.local_addr()?.as_socket().ok_or_else(invalid)?;
        let remote = socket.peer_addr()?.as_socket().ok_or_else(invalid)?;
        let cookie = socket.cookie()?;
        if cookie == 0
            || !local.is_ipv6()
            || !remote.is_ipv6()
            || local.port() == 0
            || remote.port() == 0
        {
            return Err(invalid());
        }
        let token = mptcp_local_token(descriptor)?;
        let namespace = socket_network_namespace(descriptor)?;
        let stat = rustix::fs::fstat(&namespace)?;
        Ok(Self {
            cookie,
            token,
            local,
            remote,
            namespace_device: stat.st_dev,
            namespace_inode: stat.st_ino,
        })
    }

    pub(crate) fn verify(self, descriptor: &OwnedFd) -> io::Result<()> {
        if Self::capture(descriptor)? != self {
            return Err(invalid());
        }
        Ok(())
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "MPTCP flow descriptor identity mismatch",
    )
}
