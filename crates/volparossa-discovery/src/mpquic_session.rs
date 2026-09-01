//! Bounded production MPQUIC/MASQUE session-activation frames.

use prost::Message;
use thiserror::Error;
use volparossa_protocol::{
    ControlMessageType, ExitConfirmationReceipt, ExitReservation, ExitReservationConfirmation,
    MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, PROTOCOL_VERSION, RelayReservation,
    SignedEnvelope, Transport, decode_canonical,
};

const ID_BYTES: usize = 16;
const NODE_ID_BYTES: usize = 32;
const NATIVE_INSTANCE_BYTES: usize = 32;
const MIN_MPQUIC_PATHS: usize = 2;
const MAX_MPQUIC_PATHS: usize = 8;

/// One exact Relay acceptance, Client confirmation, and Exit receipt tuple.
#[derive(Clone, PartialEq, Message)]
pub struct MpquicSessionPathProof {
    #[prost(bytes = "vec", tag = "1")]
    signed_relay_reservation: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signed_confirmation: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    signed_confirmation_receipt: Vec<u8>,
}

impl MpquicSessionPathProof {
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
pub struct MpquicSessionStartRequest {
    #[prost(bytes = "vec", tag = "1")]
    signed_exit_reservation: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    paths: Vec<MpquicSessionPathProof>,
}

impl MpquicSessionStartRequest {
    /// Construct one canonical, complete MPQUIC path proof set.
    ///
    /// # Errors
    ///
    /// Rejects wrong signed types, fewer than two paths, missing or duplicate path IDs, and
    /// cross-scoped reservations, confirmations, or receipts.
    pub fn new(
        signed_exit_reservation: Vec<u8>,
        paths: Vec<MpquicSessionPathProof>,
    ) -> Result<Self, MpquicSessionFrameError> {
        let value = Self {
            signed_exit_reservation,
            paths,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate canonical signed types and the exact selected MPQUIC path set.
    ///
    /// Signature, expiry, replay, authenticated-peer, helper and native listener checks remain
    /// mandatory at the production endpoints; this method only closes the framing scope.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, non-MPQUIC, incomplete, or cross-scoped frames.
    pub fn validate(&self) -> Result<(), MpquicSessionFrameError> {
        let exit = signed_payload::<ExitReservation>(
            &self.signed_exit_reservation,
            ControlMessageType::ExitReservation,
        )?;
        let expected_paths =
            usize::try_from(exit.maximum_paths).map_err(|_| MpquicSessionFrameError::Invalid)?;
        let native = exit
            .native_route_identity
            .as_ref()
            .ok_or(MpquicSessionFrameError::Invalid)?;
        if fixed_nonzero::<ID_BYTES>(&exit.reservation_id).is_none()
            || fixed_nonzero::<ID_BYTES>(&exit.route_context_id).is_none()
            || fixed_nonzero::<NODE_ID_BYTES>(&exit.exit_node_id).is_none()
            || fixed_nonzero::<NATIVE_INSTANCE_BYTES>(&native.client_native_instance_id).is_none()
            || fixed_nonzero::<NATIVE_INSTANCE_BYTES>(&native.exit_native_instance_id).is_none()
            || !(MIN_MPQUIC_PATHS..=MAX_MPQUIC_PATHS).contains(&expected_paths)
            || self.paths.len() != expected_paths
            || !exit
                .allowed_transports
                .contains(&(Transport::MultipathQuic as i32))
        {
            return Err(MpquicSessionFrameError::Invalid);
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
            if !(1..=u32::try_from(MAX_MPQUIC_PATHS).unwrap_or(u32::MAX)).contains(&relay.path_id)
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
                return Err(MpquicSessionFrameError::Invalid);
            }
            previous_path_id = relay.path_id;
        }
        Ok(())
    }

    /// Exit-signed reservation authorizing the exact MPQUIC route.
    #[must_use]
    pub fn signed_exit_reservation(&self) -> &[u8] {
        &self.signed_exit_reservation
    }

    /// Canonically path-ID-ordered exact proof set.
    #[must_use]
    pub fn paths(&self) -> &[MpquicSessionPathProof] {
        &self.paths
    }
}

/// Exit readiness emitted only after its native process owns the complete listener set.
///
/// Listener and Client ports are deliberately absent: both endpoints derive the fixed route-local
/// ports and overlay addresses from the signed reservation and path IDs, leaving no unsigned
/// arbitrary target in the signal.
#[derive(Clone, PartialEq, Message)]
pub struct ExitMpquicSessionSignal {
    #[prost(bytes = "vec", tag = "1")]
    reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    exit_native_instance_id: Vec<u8>,
    #[prost(uint32, repeated, tag = "4")]
    selected_path_ids: Vec<u32>,
}

impl ExitMpquicSessionSignal {
    /// Construct one complete native Exit readiness signal.
    ///
    /// # Errors
    ///
    /// Rejects zero identifiers or a non-canonical 2--8 path set.
    pub fn new(
        reservation_id: [u8; ID_BYTES],
        route_context_id: [u8; ID_BYTES],
        exit_native_instance_id: [u8; NATIVE_INSTANCE_BYTES],
        selected_path_ids: Vec<u32>,
    ) -> Result<Self, MpquicSessionFrameError> {
        let value = Self {
            reservation_id: reservation_id.to_vec(),
            route_context_id: route_context_id.to_vec(),
            exit_native_instance_id: exit_native_instance_id.to_vec(),
            selected_path_ids,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate bounded identifiers and canonical path ordering.
    ///
    /// # Errors
    ///
    /// Rejects malformed IDs, fewer than two paths, duplicates, reordering, or path zero.
    pub fn validate(&self) -> Result<(), MpquicSessionFrameError> {
        if fixed_nonzero::<ID_BYTES>(&self.reservation_id).is_none()
            || fixed_nonzero::<ID_BYTES>(&self.route_context_id).is_none()
            || fixed_nonzero::<NATIVE_INSTANCE_BYTES>(&self.exit_native_instance_id).is_none()
            || !(MIN_MPQUIC_PATHS..=MAX_MPQUIC_PATHS).contains(&self.selected_path_ids.len())
        {
            return Err(MpquicSessionFrameError::Invalid);
        }
        let mut previous_path_id = 0;
        for path_id in &self.selected_path_ids {
            if !(1..=u32::try_from(MAX_MPQUIC_PATHS).unwrap_or(u32::MAX)).contains(path_id)
                || *path_id <= previous_path_id
            {
                return Err(MpquicSessionFrameError::Invalid);
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

    /// Exact preflighted native Exit process incarnation.
    #[must_use]
    pub fn exit_native_instance_id(&self) -> &[u8] {
        &self.exit_native_instance_id
    }

    /// Canonically ordered selected path IDs whose listeners are all ready.
    #[must_use]
    pub fn selected_path_ids(&self) -> &[u32] {
        &self.selected_path_ids
    }
}

/// Bounded MPQUIC activation-frame error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MpquicSessionFrameError {
    /// The frame is malformed, oversized, wrong-type, incomplete, or cross-scoped.
    #[error("invalid MPQUIC session activation frame")]
    Invalid,
}

fn signed_payload<T: Message + Default>(
    encoded: &[u8],
    expected: ControlMessageType,
) -> Result<T, MpquicSessionFrameError> {
    if encoded.is_empty() || encoded.len() > MAX_CONTROL_MESSAGE_SIZE {
        return Err(MpquicSessionFrameError::Invalid);
    }
    let envelope = decode_canonical::<SignedEnvelope>(encoded, MAX_CONTROL_MESSAGE_SIZE)
        .map_err(|_| MpquicSessionFrameError::Invalid)?;
    if envelope.protocol_version != PROTOCOL_VERSION || envelope.message_type != expected as i32 {
        return Err(MpquicSessionFrameError::Invalid);
    }
    decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
        .map_err(|_| MpquicSessionFrameError::Invalid)
}

fn relay_matches_exit(relay: &RelayReservation, exit: &ExitReservation) -> bool {
    relay.reservation_id == exit.reservation_id
        && relay.route_context_id == exit.route_context_id
        && relay.exit_node_id == exit.exit_node_id
        && relay.client_session_id == exit.client_session_id
        && relay.allowed_transports == exit.allowed_transports
        && relay
            .allowed_transports
            .contains(&(Transport::MultipathQuic as i32))
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
    use volparossa_protocol::encode_canonical;

    use super::*;

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

    fn exit_reservation() -> ExitReservation {
        ExitReservation {
            reservation_id: vec![1; ID_BYTES],
            route_context_id: vec![2; ID_BYTES],
            exit_node_id: vec![3; NODE_ID_BYTES],
            client_session_id: vec![4; ID_BYTES],
            allowed_transports: vec![Transport::MultipathQuic as i32],
            maximum_paths: 2,
            native_route_identity: Some(volparossa_protocol::NativeRouteIdentity {
                client_native_instance_id: vec![5; NATIVE_INSTANCE_BYTES],
                exit_native_instance_id: vec![6; NATIVE_INSTANCE_BYTES],
                ..volparossa_protocol::NativeRouteIdentity::default()
            }),
            ..ExitReservation::default()
        }
    }

    fn proof(exit: &ExitReservation, path_id: u32) -> MpquicSessionPathProof {
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
        MpquicSessionPathProof::new(
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

    #[test]
    fn exact_two_path_start_and_native_ready_signal_round_trip() {
        let exit = exit_reservation();
        let start = MpquicSessionStartRequest::new(
            signed(ControlMessageType::ExitReservation, &exit),
            vec![proof(&exit, 1), proof(&exit, 2)],
        )
        .expect("complete MPQUIC proof set");
        let encoded = encode_canonical(&start, MAX_CONTROL_MESSAGE_SIZE).expect("start encode");
        decode_canonical::<MpquicSessionStartRequest>(&encoded, MAX_CONTROL_MESSAGE_SIZE)
            .expect("start decode")
            .validate()
            .expect("start validate");

        let signal = ExitMpquicSessionSignal::new([1; 16], [2; 16], [6; 32], vec![1, 2])
            .expect("native ready signal");
        let encoded = encode_canonical(&signal, MAX_CONTROL_MESSAGE_SIZE).expect("signal encode");
        let decoded =
            decode_canonical::<ExitMpquicSessionSignal>(&encoded, MAX_CONTROL_MESSAGE_SIZE)
                .expect("signal decode");
        decoded.validate().expect("signal validate");
        assert_eq!(decoded.selected_path_ids(), [1, 2]);
    }

    #[test]
    fn ordinary_quic_and_incomplete_or_reordered_sets_fail_closed() {
        let exit = exit_reservation();
        for paths in [
            vec![proof(&exit, 1)],
            vec![proof(&exit, 2), proof(&exit, 1)],
        ] {
            assert_eq!(
                MpquicSessionStartRequest::new(
                    signed(ControlMessageType::ExitReservation, &exit),
                    paths,
                ),
                Err(MpquicSessionFrameError::Invalid)
            );
        }
        let ordinary = ExitReservation {
            allowed_transports: vec![Transport::UdpSinglePath as i32],
            ..exit.clone()
        };
        assert_eq!(
            MpquicSessionStartRequest::new(
                signed(ControlMessageType::ExitReservation, &ordinary),
                vec![proof(&exit, 1), proof(&exit, 2)],
            ),
            Err(MpquicSessionFrameError::Invalid)
        );
    }
}
