//! Bounded production MPTCP session-activation frames.

use prost::Message;
use thiserror::Error;
use volparossa_protocol::{
    ControlMessageType, ExitConfirmationReceipt, ExitReservation, ExitReservationConfirmation,
    MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, PROTOCOL_VERSION, RelayReservation,
    SignedEnvelope, Transport, decode_canonical,
};

const ID_BYTES: usize = 16;
const NODE_ID_BYTES: usize = 32;
const MIN_MPTCP_PATHS: usize = 2;
const MAX_MPTCP_PATHS: usize = 8;
const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1_024;

/// One exact Relay acceptance, Client confirmation, and Exit receipt tuple.
#[derive(Clone, PartialEq, Message)]
pub struct MptcpSessionPathProof {
    #[prost(bytes = "vec", tag = "1")]
    signed_relay_reservation: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signed_confirmation: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    signed_confirmation_receipt: Vec<u8>,
}

impl MptcpSessionPathProof {
    /// Construct one path proof tuple.
    #[must_use]
    pub fn new(
        signed_relay_reservation: Vec<u8>,
        signed_confirmation: Vec<u8>,
        signed_confirmation_receipt: Vec<u8>,
    ) -> Self {
        Self {
            signed_relay_reservation,
            signed_confirmation,
            signed_confirmation_receipt,
        }
    }

    /// Data-Relay-signed acceptance for this exact path.
    #[must_use]
    pub fn signed_relay_reservation(&self) -> &[u8] {
        &self.signed_relay_reservation
    }

    /// Client-session-signed return of the exact Relay acceptance.
    #[must_use]
    pub fn signed_confirmation(&self) -> &[u8] {
        &self.signed_confirmation
    }

    /// Exit-signed receipt for the exact confirmation.
    #[must_use]
    pub fn signed_confirmation_receipt(&self) -> &[u8] {
        &self.signed_confirmation_receipt
    }
}

/// Exact signed multipath proof set sent Client -> data Relay -> Exit after helper Commit.
#[derive(Clone, PartialEq, Message)]
pub struct MptcpSessionStartRequest {
    #[prost(bytes = "vec", tag = "1")]
    signed_exit_reservation: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    paths: Vec<MptcpSessionPathProof>,
}

impl MptcpSessionStartRequest {
    /// Construct one canonical, complete MPTCP path proof set.
    ///
    /// # Errors
    ///
    /// Rejects wrong signed types, fewer than two paths, missing or duplicate path IDs, and
    /// cross-scoped reservations, confirmations, or receipts.
    pub fn new(
        signed_exit_reservation: Vec<u8>,
        paths: Vec<MptcpSessionPathProof>,
    ) -> Result<Self, MptcpSessionFrameError> {
        let value = Self {
            signed_exit_reservation,
            paths,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate canonical signed types and the exact selected path set.
    ///
    /// This is framing validation only. Each endpoint independently verifies signatures, expiry,
    /// replay, authenticated peer lineage, helper ownership, and actual MPTCP subflows.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, wrong-type, non-MPTCP, incomplete, or cross-scoped frames.
    pub fn validate(&self) -> Result<(), MptcpSessionFrameError> {
        let exit = signed_payload::<ExitReservation>(
            &self.signed_exit_reservation,
            ControlMessageType::ExitReservation,
        )?;
        let expected_paths =
            usize::try_from(exit.maximum_paths).map_err(|_| MptcpSessionFrameError::Invalid)?;
        if fixed_nonzero::<ID_BYTES>(&exit.reservation_id).is_none()
            || fixed_nonzero::<ID_BYTES>(&exit.route_context_id).is_none()
            || fixed_nonzero::<NODE_ID_BYTES>(&exit.exit_node_id).is_none()
            || !(MIN_MPTCP_PATHS..=MAX_MPTCP_PATHS).contains(&expected_paths)
            || self.paths.len() != expected_paths
            || !exit
                .allowed_transports
                .contains(&(Transport::TcpMptcp as i32))
        {
            return Err(MptcpSessionFrameError::Invalid);
        }

        let mut previous_path_id = 0;
        for proof in &self.paths {
            let relay = signed_payload::<RelayReservation>(
                &proof.signed_relay_reservation,
                ControlMessageType::RelayReservation,
            )?;
            let confirmation = signed_payload::<ExitReservationConfirmation>(
                &proof.signed_confirmation,
                ControlMessageType::ExitReservationConfirmation,
            )?;
            let receipt = signed_payload::<ExitConfirmationReceipt>(
                &proof.signed_confirmation_receipt,
                ControlMessageType::ExitConfirmationReceipt,
            )?;
            if !(1..=u32::try_from(MAX_MPTCP_PATHS).unwrap_or(u32::MAX)).contains(&relay.path_id)
                || relay.path_id <= previous_path_id
                || !relay_matches_exit(&relay, &exit)
                || !confirmation_matches_path(
                    &confirmation,
                    &relay,
                    &exit,
                    &proof.signed_relay_reservation,
                )
                || !receipt_matches_path(&receipt, &relay, &exit)
            {
                return Err(MptcpSessionFrameError::Invalid);
            }
            previous_path_id = relay.path_id;
        }
        Ok(())
    }

    /// Exit-signed reservation authorizing the exact MPTCP route.
    #[must_use]
    pub fn signed_exit_reservation(&self) -> &[u8] {
        &self.signed_exit_reservation
    }

    /// Canonically path-ID-ordered exact proof set.
    #[must_use]
    pub fn paths(&self) -> &[MptcpSessionPathProof] {
        &self.paths
    }
}

/// Exit readiness for one exact committed MPTCP listener and selected path set.
///
/// This frame does not claim that the listener accepted a connection or that any MPTCP subflow
/// carried traffic. Those are separate runtime and acceptance proofs.
#[derive(Clone, PartialEq, Message)]
pub struct ExitMptcpSessionSignal {
    #[prost(bytes = "vec", tag = "1")]
    reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    route_context_id: Vec<u8>,
    #[prost(uint32, tag = "3")]
    listener_port: u32,
    #[prost(uint32, repeated, tag = "4")]
    selected_path_ids: Vec<u32>,
    #[prost(bytes = "vec", tag = "5")]
    certificate_der: Vec<u8>,
}

impl ExitMptcpSessionSignal {
    /// Construct one bounded Exit MPTCP readiness frame.
    ///
    /// # Errors
    ///
    /// Rejects zero route identifiers/port, a non-canonical path set, or an unsafe certificate.
    pub fn new(
        reservation_id: [u8; ID_BYTES],
        route_context_id: [u8; ID_BYTES],
        listener_port: u16,
        selected_path_ids: Vec<u32>,
        certificate_der: Vec<u8>,
    ) -> Result<Self, MptcpSessionFrameError> {
        let value = Self {
            reservation_id: reservation_id.to_vec(),
            route_context_id: route_context_id.to_vec(),
            listener_port: u32::from(listener_port),
            selected_path_ids,
            certificate_der,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate exact fixed bounds and canonical selected-path ordering.
    ///
    /// # Errors
    ///
    /// Rejects malformed IDs, an invalid TCP port, fewer than two paths, duplicates, path zero, or
    /// an empty/oversized public certificate.
    pub fn validate(&self) -> Result<(), MptcpSessionFrameError> {
        if fixed_nonzero::<ID_BYTES>(&self.reservation_id).is_none()
            || fixed_nonzero::<ID_BYTES>(&self.route_context_id).is_none()
            || u16::try_from(self.listener_port)
                .ok()
                .is_none_or(|port| port == 0)
            || !(MIN_MPTCP_PATHS..=MAX_MPTCP_PATHS).contains(&self.selected_path_ids.len())
            || self.certificate_der.is_empty()
            || self.certificate_der.len() > MAX_CERTIFICATE_DER_BYTES
        {
            return Err(MptcpSessionFrameError::Invalid);
        }
        let mut previous_path_id = 0;
        for path_id in &self.selected_path_ids {
            if !(1..=u32::try_from(MAX_MPTCP_PATHS).unwrap_or(u32::MAX)).contains(path_id)
                || *path_id <= previous_path_id
            {
                return Err(MptcpSessionFrameError::Invalid);
            }
            previous_path_id = *path_id;
        }
        Ok(())
    }

    /// Exact reservation identifier.
    #[must_use]
    pub fn reservation_id(&self) -> &[u8] {
        &self.reservation_id
    }

    /// Exact helper route context.
    #[must_use]
    pub fn route_context_id(&self) -> &[u8] {
        &self.route_context_id
    }

    /// Exact committed Exit TCP listener port.
    #[must_use]
    pub const fn listener_port(&self) -> u32 {
        self.listener_port
    }

    /// Canonically ordered selected path IDs.
    #[must_use]
    pub fn selected_path_ids(&self) -> &[u32] {
        &self.selected_path_ids
    }

    /// Public route certificate whose SHA-256 digest is committed by the Exit reservation.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }
}

/// Bounded MPTCP activation-frame error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MptcpSessionFrameError {
    /// The frame is malformed, oversized, wrong-type, incomplete, or cross-scoped.
    #[error("invalid MPTCP session activation frame")]
    Invalid,
}

fn signed_payload<T: Message + Default>(
    encoded: &[u8],
    expected: ControlMessageType,
) -> Result<T, MptcpSessionFrameError> {
    if encoded.is_empty() || encoded.len() > MAX_CONTROL_MESSAGE_SIZE {
        return Err(MptcpSessionFrameError::Invalid);
    }
    let envelope = decode_canonical::<SignedEnvelope>(encoded, MAX_CONTROL_MESSAGE_SIZE)
        .map_err(|_| MptcpSessionFrameError::Invalid)?;
    if envelope.protocol_version != PROTOCOL_VERSION || envelope.message_type != expected as i32 {
        return Err(MptcpSessionFrameError::Invalid);
    }
    decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
        .map_err(|_| MptcpSessionFrameError::Invalid)
}

fn relay_matches_exit(relay: &RelayReservation, exit: &ExitReservation) -> bool {
    relay.reservation_id == exit.reservation_id
        && relay.route_context_id == exit.route_context_id
        && relay.exit_node_id == exit.exit_node_id
        && relay.client_session_id == exit.client_session_id
        && relay.allowed_transports == exit.allowed_transports
        && relay
            .allowed_transports
            .contains(&(Transport::TcpMptcp as i32))
        && relay.maximum_up_mbps == exit.reserved_up_mbps
        && relay.maximum_down_mbps == exit.reserved_down_mbps
        && relay.policy_hash == exit.policy_hash
        && relay.created_at_ms == exit.created_at_ms
        && relay.expires_at_ms == exit.expires_at_ms
        && relay.capability_id == exit.capability_id
        && relay.client_session_public_key == exit.client_session_public_key
        && relay.exit_boot_id == exit.exit_boot_id
        && relay.hold_id == exit.hold_id
        && relay.finalize_id == exit.finalize_id
        && relay.control_relay_node_id == exit.control_relay_node_id
        && relay.control_relay_peer_id == exit.control_relay_peer_id
        && relay.exit_peer_id == exit.exit_peer_id
}

fn confirmation_matches_path(
    confirmation: &ExitReservationConfirmation,
    relay: &RelayReservation,
    exit: &ExitReservation,
    signed_relay: &[u8],
) -> bool {
    confirmation.relay_reservation == signed_relay
        && confirmation.reservation_id == exit.reservation_id
        && confirmation.route_context_id == exit.route_context_id
        && confirmation.path_id == relay.path_id
        && confirmation.relay_node_id == relay.relay_node_id
        && confirmation.exit_node_id == exit.exit_node_id
        && confirmation.client_session_id == exit.client_session_id
        && confirmation.policy_hash == exit.policy_hash
        && confirmation.capability_id == exit.capability_id
        && confirmation.client_session_public_key == exit.client_session_public_key
        && confirmation.exit_boot_id == exit.exit_boot_id
        && confirmation.hold_id == exit.hold_id
        && confirmation.finalize_id == exit.finalize_id
        && confirmation.control_relay_node_id == exit.control_relay_node_id
        && confirmation.control_relay_peer_id == exit.control_relay_peer_id
        && confirmation.exit_peer_id == exit.exit_peer_id
}

fn receipt_matches_path(
    receipt: &ExitConfirmationReceipt,
    relay: &RelayReservation,
    exit: &ExitReservation,
) -> bool {
    receipt.reservation_id == exit.reservation_id
        && receipt.route_context_id == exit.route_context_id
        && receipt.path_id == relay.path_id
        && receipt.exit_node_id == exit.exit_node_id
        && receipt.client_session_id == exit.client_session_id
        && receipt.capability_id == exit.capability_id
        && receipt.exit_boot_id == exit.exit_boot_id
        && receipt.hold_id == exit.hold_id
        && receipt.finalize_id == exit.finalize_id
        && receipt.control_relay_node_id == exit.control_relay_node_id
        && receipt.control_relay_peer_id == exit.control_relay_peer_id
        && receipt.exit_peer_id == exit.exit_peer_id
}

fn fixed_nonzero<const N: usize>(value: &[u8]) -> Option<[u8; N]> {
    let value: [u8; N] = value.try_into().ok()?;
    value.iter().any(|byte| *byte != 0).then_some(value)
}

#[cfg(test)]
mod tests {
    use libp2p::identity;
    use volparossa_protocol::encode_canonical;

    use super::*;
    use crate::{
        DatapathRelayOperation, DatapathRelayRequest, DatapathRelayResponse, ExitForwardOperation,
        ExitForwardRequest, ExitForwardResponse,
    };

    const DEADLINE: u64 = 1_700_000_012_000;

    fn signed<T: Message>(message_type: ControlMessageType, payload: &T) -> Vec<u8> {
        encode_canonical(
            &SignedEnvelope {
                protocol_version: PROTOCOL_VERSION,
                message_type: message_type as i32,
                payload: encode_canonical(payload, MAX_CONTROL_PAYLOAD_SIZE).expect("payload"),
                ..SignedEnvelope::default()
            },
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("envelope")
    }

    fn exit_reservation(maximum_paths: u32) -> ExitReservation {
        ExitReservation {
            reservation_id: vec![1; ID_BYTES],
            route_context_id: vec![2; ID_BYTES],
            exit_node_id: vec![3; NODE_ID_BYTES],
            client_session_id: vec![4; ID_BYTES],
            allowed_transports: vec![Transport::TcpMptcp as i32],
            maximum_paths,
            ..ExitReservation::default()
        }
    }

    fn path_proof(exit: &ExitReservation, path_id: u32) -> MptcpSessionPathProof {
        let relay = RelayReservation {
            reservation_id: exit.reservation_id.clone(),
            route_context_id: exit.route_context_id.clone(),
            path_id,
            relay_node_id: vec![u8::try_from(path_id).expect("small path"); NODE_ID_BYTES],
            exit_node_id: exit.exit_node_id.clone(),
            client_session_id: exit.client_session_id.clone(),
            allowed_transports: exit.allowed_transports.clone(),
            ..RelayReservation::default()
        };
        let signed_relay = signed(ControlMessageType::RelayReservation, &relay);
        MptcpSessionPathProof::new(
            signed_relay.clone(),
            signed(
                ControlMessageType::ExitReservationConfirmation,
                &ExitReservationConfirmation {
                    reservation_id: exit.reservation_id.clone(),
                    route_context_id: exit.route_context_id.clone(),
                    path_id,
                    relay_node_id: relay.relay_node_id,
                    exit_node_id: exit.exit_node_id.clone(),
                    client_session_id: exit.client_session_id.clone(),
                    relay_reservation: signed_relay,
                    ..ExitReservationConfirmation::default()
                },
            ),
            signed(
                ControlMessageType::ExitConfirmationReceipt,
                &ExitConfirmationReceipt {
                    reservation_id: exit.reservation_id.clone(),
                    route_context_id: exit.route_context_id.clone(),
                    client_session_id: exit.client_session_id.clone(),
                    path_id,
                    exit_node_id: exit.exit_node_id.clone(),
                    ..ExitConfirmationReceipt::default()
                },
            ),
        )
    }

    fn correlated_start(path_ids: &[u32]) -> MptcpSessionStartRequest {
        let exit = exit_reservation(u32::try_from(path_ids.len()).expect("bounded paths"));
        let paths = path_ids
            .iter()
            .map(|path_id| path_proof(&exit, *path_id))
            .collect();
        MptcpSessionStartRequest::new(signed(ControlMessageType::ExitReservation, &exit), paths)
            .expect("correlated MPTCP activation proof")
    }

    #[test]
    fn exact_start_and_exit_signal_round_trip_canonically() {
        let start = correlated_start(&[1, 2]);
        let encoded = encode_canonical(&start, MAX_CONTROL_MESSAGE_SIZE).expect("start encode");
        let decoded =
            decode_canonical::<MptcpSessionStartRequest>(&encoded, MAX_CONTROL_MESSAGE_SIZE)
                .expect("start decode");
        decoded.validate().expect("exact start scope");
        assert_eq!(decoded.paths().len(), 2);

        let signal = ExitMptcpSessionSignal::new([1; 16], [2; 16], 443, vec![1, 2], vec![0x30, 1])
            .expect("bounded signal");
        let encoded = encode_canonical(&signal, MAX_CONTROL_MESSAGE_SIZE).expect("signal encode");
        let decoded =
            decode_canonical::<ExitMptcpSessionSignal>(&encoded, MAX_CONTROL_MESSAGE_SIZE)
                .expect("signal decode");
        decoded.validate().expect("exact signal scope");
        assert_eq!(decoded.listener_port(), 443);
        assert_eq!(decoded.selected_path_ids(), [1, 2]);
    }

    #[test]
    fn start_requires_the_complete_exit_authorized_multipath_set() {
        let exit = exit_reservation(2);
        assert_eq!(
            MptcpSessionStartRequest::new(
                signed(ControlMessageType::ExitReservation, &exit),
                vec![path_proof(&exit, 1)],
            ),
            Err(MptcpSessionFrameError::Invalid)
        );
        assert_eq!(
            MptcpSessionStartRequest::new(
                signed(
                    ControlMessageType::ExitReservation,
                    &ExitReservation {
                        allowed_transports: vec![Transport::UdpSinglePath as i32],
                        ..exit.clone()
                    },
                ),
                vec![path_proof(&exit, 1), path_proof(&exit, 2)],
            ),
            Err(MptcpSessionFrameError::Invalid)
        );
    }

    #[test]
    fn start_rejects_duplicate_reordered_and_cross_scoped_paths() {
        for path_ids in [&[1, 1][..], &[2, 1][..]] {
            let exit = exit_reservation(2);
            assert_eq!(
                MptcpSessionStartRequest::new(
                    signed(ControlMessageType::ExitReservation, &exit),
                    path_ids
                        .iter()
                        .map(|path_id| path_proof(&exit, *path_id))
                        .collect(),
                ),
                Err(MptcpSessionFrameError::Invalid)
            );
        }

        let mut start = correlated_start(&[1, 2]);
        let receipt = ExitConfirmationReceipt {
            reservation_id: vec![9; ID_BYTES],
            route_context_id: vec![2; ID_BYTES],
            client_session_id: vec![4; ID_BYTES],
            path_id: 2,
            exit_node_id: vec![3; NODE_ID_BYTES],
            ..ExitConfirmationReceipt::default()
        };
        start.paths[1].signed_confirmation_receipt =
            signed(ControlMessageType::ExitConfirmationReceipt, &receipt);
        assert_eq!(start.validate(), Err(MptcpSessionFrameError::Invalid));
    }

    #[test]
    fn signal_rejects_non_multipath_or_noncanonical_selected_sets() {
        for paths in [vec![1], vec![1, 1], vec![2, 1], vec![0, 1]] {
            assert_eq!(
                ExitMptcpSessionSignal::new([1; 16], [2; 16], 443, paths, vec![0x30, 1],),
                Err(MptcpSessionFrameError::Invalid)
            );
        }
        assert!(
            ExitMptcpSessionSignal::new([1; 16], [2; 16], 443, vec![1, 2], Vec::new()).is_err()
        );
    }

    #[test]
    fn dedicated_rpc_discriminants_carry_only_validated_mptcp_frames() {
        let start = encode_canonical(&correlated_start(&[1, 2]), MAX_CONTROL_MESSAGE_SIZE)
            .expect("start frame");
        let signal = encode_canonical(
            &ExitMptcpSessionSignal::new([1; 16], [2; 16], 443, vec![1, 2], vec![0x30, 1])
                .expect("signal"),
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("signal frame");

        let data_relay = identity::Keypair::generate_ed25519();
        let relay_peer = data_relay.public().to_peer_id().to_bytes();
        let datapath_request = DatapathRelayRequest::new(
            vec![8; ID_BYTES],
            vec![9; NODE_ID_BYTES],
            relay_peer.clone(),
            DEADLINE,
            DatapathRelayOperation::MptcpSessionStart,
            start.clone(),
            Vec::new(),
        )
        .expect("MPTCP datapath request");
        assert_eq!(DatapathRelayOperation::MptcpSessionStart as i32, 7);
        assert_eq!(
            datapath_request.validated_operation().expect("operation"),
            DatapathRelayOperation::MptcpSessionStart
        );
        DatapathRelayResponse::granted(
            vec![8; ID_BYTES],
            DatapathRelayOperation::MptcpSessionStart,
            vec![9; NODE_ID_BYTES],
            relay_peer,
            signal.clone(),
        )
        .expect("MPTCP datapath response");

        let control = identity::Keypair::generate_ed25519();
        let control_public = control
            .clone()
            .try_into_ed25519()
            .expect("Ed25519")
            .public()
            .to_bytes();
        let control_node = volparossa_protocol::node_id_from_public_key(&control_public);
        let exit = identity::Keypair::generate_ed25519();
        let exit_peer = exit.public().to_peer_id().to_bytes();
        let exit_node = vec![3; NODE_ID_BYTES];
        let forward_request = ExitForwardRequest::new(
            vec![10; ID_BYTES],
            control_node.to_vec(),
            control.public().to_peer_id().to_bytes(),
            control_public.to_vec(),
            exit_peer.clone(),
            exit_node.clone(),
            DEADLINE,
            ExitForwardOperation::MptcpSessionStart,
            start,
        )
        .expect("MPTCP forward request");
        assert_eq!(ExitForwardOperation::MptcpSessionStart as i32, 11);
        assert_eq!(
            forward_request.validated_operation().expect("operation"),
            ExitForwardOperation::MptcpSessionStart
        );
        ExitForwardResponse::granted(
            vec![10; ID_BYTES],
            ExitForwardOperation::MptcpSessionStart,
            exit_node,
            exit_peer,
            vec![signal],
        )
        .expect("MPTCP forward response");
    }
}
