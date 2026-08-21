use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{self, Instant},
};

use crate::{AuthorizedUdpFlow, UdpError, VerifiedSingleRelayPath};

const DATAGRAM_VERSION: u8 = 1;
const FLOW_ID_BYTES: usize = 16;
const DATAGRAM_HEADER_BYTES: usize = 1 + FLOW_ID_BYTES;
const STATE_ACTIVE: u8 = 1;
const STATE_EXPIRED: u8 = 2;
const STATE_CLOSED: u8 = 3;
const CLOSE_IDLE_TIMEOUT: u32 = 0x100;
const CLOSE_PROTOCOL: u32 = 0x101;
const CLOSE_NORMAL: u32 = 0;

/// Largest legal IPv4 UDP payload. The negotiated QUIC DATAGRAM limit normally
/// imposes a smaller per-connection bound.
pub const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;

/// Observable lifecycle state without destination or peer metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpAssociationState {
    /// Authorization is live and valid datagrams may be exchanged.
    Active,
    /// The immutable idle or signed-expiry deadline elapsed.
    Expired,
    /// The association was explicitly closed or failed closed.
    Closed,
}

/// One dedicated, authenticated QUIC DATAGRAM connection for one signed UDP
/// flow over one verified relay path.
///
/// Datagram frames carry only a version, opaque flow ID, and original payload.
/// They contain no mutable destination field. The idle guard runs independently
/// of send/receive calls and closes QUIC after inactivity.
pub struct QuicUdpAssociation {
    connection: quinn::Connection,
    path: VerifiedSingleRelayPath,
    flow_id: [u8; FLOW_ID_BYTES],
    activity: watch::Sender<Instant>,
    state: Arc<AtomicU8>,
    idle_task: JoinHandle<()>,
}

impl QuicUdpAssociation {
    /// Bind a dedicated QUIC connection to one verified path and authorized
    /// flow. QUIC DATAGRAM negotiation is mandatory.
    ///
    /// # Errors
    ///
    /// Fails for stale or inconsistent route/flow binding, missing QUIC
    /// DATAGRAM support, invalid wall-clock lifetime, or missing Tokio runtime.
    pub fn new(
        connection: quinn::Connection,
        path: VerifiedSingleRelayPath,
        flow: &AuthorizedUdpFlow,
        now_ms: u64,
    ) -> Result<Self, UdpError> {
        path.ensure_active_at(now_ms)?;
        flow.ensure_active_at(now_ms)?;
        same(
            flow.route_context_id(),
            path.route_context_id(),
            "route context",
        )?;
        same(
            flow.client_ephemeral_id(),
            path.client_ephemeral_id(),
            "client session identity",
        )?;
        let maximum = connection
            .max_datagram_size()
            .ok_or(UdpError::DatagramUnsupported)?;
        if maximum <= DATAGRAM_HEADER_BYTES {
            return Err(UdpError::DatagramUnsupported);
        }
        let remaining_ms = flow
            .expires_at_ms()
            .min(path.expires_at_ms())
            .checked_sub(now_ms)
            .ok_or(UdpError::Expired)?;
        if remaining_ms == 0 {
            return Err(UdpError::Expired);
        }
        let absolute_lifetime = Duration::from_millis(remaining_ms);
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| UdpError::RuntimeUnavailable)?;
        let created_at = Instant::now();
        let (activity, activity_receiver) = watch::channel(created_at);
        let state = Arc::new(AtomicU8::new(STATE_ACTIVE));
        let idle_task = runtime.spawn(idle_guard(
            connection.clone(),
            activity_receiver,
            Arc::clone(&state),
            flow.idle_timeout(),
            created_at + absolute_lifetime,
        ));

        Ok(Self {
            connection,
            path,
            flow_id: *flow.flow_id(),
            activity,
            state,
            idle_task,
        })
    }

    /// Return the immutable relay-path proof.
    #[must_use]
    pub const fn path(&self) -> &VerifiedSingleRelayPath {
        &self.path
    }

    /// Return the opaque short-lived flow identifier.
    #[must_use]
    pub const fn flow_id(&self) -> &[u8; FLOW_ID_BYTES] {
        &self.flow_id
    }

    /// Return the association lifecycle without peer or destination metadata.
    #[must_use]
    pub fn state(&self) -> UdpAssociationState {
        match self.state.load(Ordering::Acquire) {
            STATE_ACTIVE => UdpAssociationState::Active,
            STATE_EXPIRED => UdpAssociationState::Expired,
            _ => UdpAssociationState::Closed,
        }
    }

    /// Send one original UDP datagram without retransmission, segmentation,
    /// duplication, FEC, or stream fallback.
    ///
    /// # Errors
    ///
    /// Fails if inactive, oversized for UDP or negotiated QUIC DATAGRAM, or if
    /// QUIC rejects the authenticated datagram.
    pub fn send_payload(&self, payload: &[u8]) -> Result<(), UdpError> {
        self.ensure_active()?;
        let frame = encode_datagram(&self.flow_id, payload)?;
        let maximum = self
            .connection
            .max_datagram_size()
            .ok_or(UdpError::DatagramUnsupported)?;
        if frame.len() > maximum {
            return Err(UdpError::ResourceLimit);
        }
        self.connection.send_datagram(frame)?;
        self.touch()?;
        Ok(())
    }

    /// Receive one complete authenticated QUIC DATAGRAM and return its original
    /// UDP payload. A wrong version or flow ID closes the association.
    ///
    /// # Errors
    ///
    /// Fails for expiry/closure, QUIC termination, malformed framing, or a
    /// datagram for another flow.
    pub async fn receive_payload(&self) -> Result<Bytes, UdpError> {
        self.ensure_active()?;
        let frame = match self.connection.read_datagram().await {
            Ok(frame) => frame,
            Err(_error) if self.state() == UdpAssociationState::Expired => {
                return Err(UdpError::IdleTimeout);
            }
            Err(error) => return Err(error.into()),
        };
        match decode_datagram(&frame, &self.flow_id) {
            Ok(payload) => {
                self.touch()?;
                Ok(payload)
            }
            Err(error) => {
                self.fail_closed(CLOSE_PROTOCOL, b"invalid-datagram");
                Err(error)
            }
        }
    }

    /// Explicitly close the association and stop its idle guard.
    pub fn close(&self) {
        if self.state.swap(STATE_CLOSED, Ordering::AcqRel) != STATE_CLOSED {
            self.connection
                .close(quinn::VarInt::from_u32(CLOSE_NORMAL), b"closed");
        }
        self.idle_task.abort();
    }

    fn ensure_active(&self) -> Result<(), UdpError> {
        match self.state() {
            UdpAssociationState::Active => Ok(()),
            UdpAssociationState::Expired => Err(UdpError::IdleTimeout),
            UdpAssociationState::Closed => Err(UdpError::InvalidBinding("closed association")),
        }
    }

    fn touch(&self) -> Result<(), UdpError> {
        self.ensure_active()?;
        self.activity
            .send(Instant::now())
            .map_err(|_| UdpError::InvalidBinding("idle guard stopped"))
    }

    fn fail_closed(&self, code: u32, reason: &'static [u8]) {
        self.state.store(STATE_CLOSED, Ordering::Release);
        self.connection.close(quinn::VarInt::from_u32(code), reason);
        self.idle_task.abort();
    }
}

impl Drop for QuicUdpAssociation {
    fn drop(&mut self) {
        self.state.store(STATE_CLOSED, Ordering::Release);
        self.idle_task.abort();
        self.connection
            .close(quinn::VarInt::from_u32(CLOSE_NORMAL), b"dropped");
    }
}

async fn idle_guard(
    connection: quinn::Connection,
    mut activity: watch::Receiver<Instant>,
    state: Arc<AtomicU8>,
    idle_timeout: Duration,
    absolute_deadline: Instant,
) {
    loop {
        let last_activity = *activity.borrow_and_update();
        let deadline = (last_activity + idle_timeout).min(absolute_deadline);
        tokio::select! {
            () = time::sleep_until(deadline) => {
                let current_last_activity = *activity.borrow();
                if Instant::now() >= (current_last_activity + idle_timeout).min(absolute_deadline) {
                    state.store(STATE_EXPIRED, Ordering::Release);
                    connection.close(
                        quinn::VarInt::from_u32(CLOSE_IDLE_TIMEOUT),
                        b"association-expired",
                    );
                    return;
                }
            }
            changed = activity.changed() => {
                if changed.is_err() || state.load(Ordering::Acquire) != STATE_ACTIVE {
                    return;
                }
            }
        }
    }
}

fn encode_datagram(flow_id: &[u8; FLOW_ID_BYTES], payload: &[u8]) -> Result<Bytes, UdpError> {
    if payload.len() > MAX_UDP_PAYLOAD_BYTES {
        return Err(UdpError::ResourceLimit);
    }
    let length = DATAGRAM_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(UdpError::ResourceLimit)?;
    let mut frame = Vec::with_capacity(length);
    frame.push(DATAGRAM_VERSION);
    frame.extend_from_slice(flow_id);
    frame.extend_from_slice(payload);
    Ok(Bytes::from(frame))
}

fn decode_datagram(frame: &Bytes, flow_id: &[u8; FLOW_ID_BYTES]) -> Result<Bytes, UdpError> {
    if frame.len() < DATAGRAM_HEADER_BYTES
        || frame.len() > DATAGRAM_HEADER_BYTES + MAX_UDP_PAYLOAD_BYTES
    {
        return Err(UdpError::InvalidBinding("datagram length"));
    }
    if frame[0] != DATAGRAM_VERSION {
        return Err(UdpError::InvalidBinding("datagram version"));
    }
    same(
        &frame[1..DATAGRAM_HEADER_BYTES],
        flow_id,
        "datagram flow id",
    )?;
    Ok(frame.slice(DATAGRAM_HEADER_BYTES..))
}

fn same(left: &[u8], right: &[u8], field: &'static str) -> Result<(), UdpError> {
    use subtle::ConstantTimeEq;

    if left.len() != right.len() || left.ct_eq(right).unwrap_u8() != 1 {
        return Err(UdpError::InvalidBinding(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls_pki_types::PrivatePkcs8KeyDer;

    use super::{UdpAssociationState, decode_datagram, encode_datagram};
    use crate::{AuthorizedUdpFlow, QuicUdpAssociation, UdpError, VerifiedSingleRelayPath};

    #[test]
    fn datagram_framing_preserves_one_payload() {
        let flow = [7_u8; 16];
        let encoded = encode_datagram(&flow, b"one datagram").unwrap();
        assert_eq!(
            decode_datagram(&encoded, &flow).unwrap(),
            b"one datagram"[..]
        );
    }

    #[test]
    fn datagram_framing_rejects_flow_change_and_preserves_empty_payload() {
        let encoded = encode_datagram(&[7_u8; 16], b"payload").unwrap();
        assert!(matches!(
            decode_datagram(&encoded, &[8_u8; 16]),
            Err(UdpError::InvalidBinding("datagram flow id"))
        ));
        let empty = encode_datagram(&[7_u8; 16], b"").unwrap();
        assert!(decode_datagram(&empty, &[7_u8; 16]).unwrap().is_empty());
    }

    #[tokio::test]
    async fn real_quic_datagrams_preserve_boundaries_and_idle_expiry() {
        let _installation = rustls::crypto::ring::default_provider().install_default();
        let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into())
                .unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let server_address = server_endpoint.local_addr().unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client_endpoint.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let (client_connection, server_connection) = tokio::join!(
            async {
                client_endpoint
                    .connect(server_address, "localhost")
                    .unwrap()
                    .await
                    .unwrap()
            },
            async { server_endpoint.accept().await.unwrap().await.unwrap() },
        );

        let now_ms = 1_700_000_000_000;
        let flow = AuthorizedUdpFlow::test_flow(Duration::from_millis(100), now_ms + 5_000);
        let client = QuicUdpAssociation::new(
            client_connection,
            VerifiedSingleRelayPath::test_path(now_ms + 5_000),
            &flow,
            now_ms,
        )
        .unwrap();
        let server = QuicUdpAssociation::new(
            server_connection,
            VerifiedSingleRelayPath::test_path(now_ms + 5_000),
            &flow,
            now_ms,
        )
        .unwrap();

        client.send_payload(b"first datagram").unwrap();
        assert_eq!(
            server.receive_payload().await.unwrap(),
            b"first datagram"[..]
        );
        server.send_payload(b"second").unwrap();
        assert_eq!(client.receive_payload().await.unwrap(), b"second"[..]);

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(client.state(), UdpAssociationState::Expired);
        assert_eq!(server.state(), UdpAssociationState::Expired);
    }
}
