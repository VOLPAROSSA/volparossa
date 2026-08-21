use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::UdpSocket;

use crate::{PinnedUdpFlow, QuicUdpAssociation, UdpError};

/// Fixed datagram-size and count bounds for one association bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramLimits {
    maximum_payload_bytes: usize,
    maximum_tunnel_to_destination_datagrams: u64,
    maximum_destination_to_tunnel_datagrams: u64,
}

impl DatagramLimits {
    /// Construct explicit datagram resource limits.
    ///
    /// # Errors
    ///
    /// Zero values and payload limits above the UDP maximum are rejected.
    pub fn new(
        maximum_payload_bytes: usize,
        maximum_tunnel_to_destination_datagrams: u64,
        maximum_destination_to_tunnel_datagrams: u64,
    ) -> Result<Self, UdpError> {
        if maximum_payload_bytes == 0
            || maximum_payload_bytes > crate::MAX_UDP_PAYLOAD_BYTES
            || maximum_tunnel_to_destination_datagrams == 0
            || maximum_destination_to_tunnel_datagrams == 0
        {
            return Err(UdpError::ResourceLimit);
        }
        Ok(Self {
            maximum_payload_bytes,
            maximum_tunnel_to_destination_datagrams,
            maximum_destination_to_tunnel_datagrams,
        })
    }

    /// Return the receive-allocation and payload-size limit.
    #[must_use]
    pub const fn maximum_payload_bytes(self) -> usize {
        self.maximum_payload_bytes
    }
}

/// Counts complete datagrams forwarded without reliability semantics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UdpBridgeStats {
    /// Datagrams sent from the protected tunnel to the pinned destination.
    pub tunnel_to_destination_datagrams: u64,
    /// Datagrams returned from the pinned destination into the tunnel.
    pub destination_to_tunnel_datagrams: u64,
    /// Payload bytes sent toward the pinned destination.
    pub tunnel_to_destination_bytes: u64,
    /// Payload bytes returned toward the client.
    pub destination_to_tunnel_bytes: u64,
}

/// Exit-side bridge between one QUIC association and one connected UDP socket.
///
/// `UdpSocket::connect` pins the only permitted destination and filters source
/// tuples in the kernel. The bridge exposes no destination-changing operation.
pub struct ExitUdpBridge {
    association: QuicUdpAssociation,
    destination_socket: UdpSocket,
    limits: DatagramLimits,
}

impl ExitUdpBridge {
    /// Create and connect an ephemeral ordinary UDP socket to the policy-pinned
    /// destination. The caller must run the exit inside its isolated namespace.
    ///
    /// # Errors
    ///
    /// Fails for a flow-ID mismatch, stale pin, or socket bind/connect error.
    pub async fn connect(
        association: QuicUdpAssociation,
        pinned: PinnedUdpFlow,
        now_ms: u64,
        limits: DatagramLimits,
    ) -> Result<Self, UdpError> {
        if now_ms >= pinned.expires_at_ms() {
            return Err(UdpError::Expired);
        }
        if association.flow_id() != pinned.flow_id() {
            return Err(UdpError::InvalidBinding("pinned flow id"));
        }
        let bind_address = match pinned.destination().ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind_address).await?;
        socket.connect(pinned.destination()).await?;
        Ok(Self {
            association,
            destination_socket: socket,
            limits,
        })
    }

    /// Forward complete datagrams in both directions until QUIC closes, the
    /// immutable idle guard expires, or a count/size limit is reached.
    ///
    /// No acknowledgements, retransmission, in-order delivery, segmentation,
    /// duplication, FEC, or batching are introduced.
    ///
    /// # Errors
    ///
    /// Returns an association, socket, size, or datagram-count error and closes
    /// the QUIC association fail closed.
    pub async fn run(self) -> Result<UdpBridgeStats, UdpError> {
        let mut buffer = vec![0_u8; self.limits.maximum_payload_bytes];
        let mut statistics = UdpBridgeStats::default();

        let result = loop {
            tokio::select! {
                tunneled = self.association.receive_payload() => {
                    let payload = tunneled?;
                    if payload.len() > self.limits.maximum_payload_bytes {
                        break Err(UdpError::ResourceLimit);
                    }
                    increment(
                        &mut statistics.tunnel_to_destination_datagrams,
                        self.limits.maximum_tunnel_to_destination_datagrams,
                    )?;
                    self.destination_socket.send(&payload).await?;
                    add_bytes(&mut statistics.tunnel_to_destination_bytes, payload.len())?;
                }
                received = self.destination_socket.recv(&mut buffer) => {
                    let length = received?;
                    increment(
                        &mut statistics.destination_to_tunnel_datagrams,
                        self.limits.maximum_destination_to_tunnel_datagrams,
                    )?;
                    self.association.send_payload(&buffer[..length])?;
                    add_bytes(&mut statistics.destination_to_tunnel_bytes, length)?;
                }
            }
        };
        self.association.close();
        result.map(|()| statistics)
    }
}

fn increment(value: &mut u64, maximum: u64) -> Result<(), UdpError> {
    *value = value.checked_add(1).ok_or(UdpError::ResourceLimit)?;
    if *value > maximum {
        return Err(UdpError::ResourceLimit);
    }
    Ok(())
}

fn add_bytes(value: &mut u64, length: usize) -> Result<(), UdpError> {
    let length = u64::try_from(length).map_err(|_| UdpError::ResourceLimit)?;
    *value = value.checked_add(length).ok_or(UdpError::ResourceLimit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DatagramLimits;

    #[test]
    fn bridge_limits_reject_unbounded_inputs() {
        assert!(DatagramLimits::new(0, 1, 1).is_err());
        assert!(DatagramLimits::new(65_508, 1, 1).is_err());
        assert!(DatagramLimits::new(1, 0, 1).is_err());
    }
}
