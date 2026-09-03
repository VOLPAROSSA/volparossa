//! Bounded production single-relay UDP session activation frames.

use prost::Message;
use thiserror::Error;
use volparossa_protocol::{
    ControlMessageType, ControlPayload, ExitConfirmationReceipt, ExitReservation,
    ExitReservationConfirmation, MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE,
    NativeRouteCredentialDelivery, PROTOCOL_VERSION, RelayReservation, SignedEnvelope,
    decode_canonical,
};

const ID_BYTES: usize = 16;
const NATIVE_INSTANCE_BYTES: usize = 32;
const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1_024;

/// Exact signed route proof sent Client -> data Relay -> Exit after the Client helper Commit.
#[derive(Clone, PartialEq, Message)]
pub struct UdpSessionStartRequest {
    #[prost(bytes = "vec", tag = "1")]
    signed_exit_reservation: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signed_relay_reservation: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    signed_confirmation: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    signed_confirmation_receipt: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    signed_credential_delivery: Vec<u8>,
}

impl UdpSessionStartRequest {
    /// Construct one exact proof set.
    ///
    /// # Errors
    ///
    /// Rejects wrong signed message types, duplicate substitutions, or inconsistent route IDs.
    pub fn new(
        signed_exit_reservation: Vec<u8>,
        signed_relay_reservation: Vec<u8>,
        signed_confirmation: Vec<u8>,
        signed_confirmation_receipt: Vec<u8>,
        signed_credential_delivery: Vec<u8>,
    ) -> Result<Self, UdpSessionFrameError> {
        let value = Self {
            signed_exit_reservation,
            signed_relay_reservation,
            signed_confirmation,
            signed_confirmation_receipt,
            signed_credential_delivery,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate canonical signed types and their exact route/path correlation.
    ///
    /// This is framing validation only. Each endpoint independently verifies signatures, expiry,
    /// replay, authenticated peer lineage, helper ownership, and the committed TLS digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, wrong-type, or cross-scoped signed frames.
    pub fn validate(&self) -> Result<(), UdpSessionFrameError> {
        let exit = signed_payload::<ExitReservation>(
            &self.signed_exit_reservation,
            ControlMessageType::ExitReservation,
        )?;
        let relay = signed_payload::<RelayReservation>(
            &self.signed_relay_reservation,
            ControlMessageType::RelayReservation,
        )?;
        let confirmation = signed_payload::<ExitReservationConfirmation>(
            &self.signed_confirmation,
            ControlMessageType::ExitReservationConfirmation,
        )?;
        let receipt = signed_payload::<ExitConfirmationReceipt>(
            &self.signed_confirmation_receipt,
            ControlMessageType::ExitConfirmationReceipt,
        )?;
        let credential_matches = if self.signed_credential_delivery.is_empty() {
            true
        } else {
            let native = exit
                .native_route_identity
                .as_ref()
                .ok_or(UdpSessionFrameError::Invalid)?;
            let credential = signed_control_payload::<NativeRouteCredentialDelivery>(
                &self.signed_credential_delivery,
                ControlMessageType::NativeRouteCredentialDelivery,
            )?;
            credential
                .scope
                .as_ref()
                .is_some_and(|scope| credential_matches_exit(scope, &exit, native))
        };
        if confirmation.relay_reservation != self.signed_relay_reservation
            || exit.reservation_id != relay.reservation_id
            || exit.reservation_id != confirmation.reservation_id
            || exit.reservation_id != receipt.reservation_id
            || exit.route_context_id != relay.route_context_id
            || exit.route_context_id != confirmation.route_context_id
            || exit.route_context_id != receipt.route_context_id
            || relay.path_id != confirmation.path_id
            || relay.path_id != receipt.path_id
            || relay.exit_node_id != exit.exit_node_id
            || receipt.exit_node_id != exit.exit_node_id
            || exit.maximum_paths != 1
            || (self.uses_native_connect_ip()
                && !exit
                    .allowed_transports
                    .contains(&(volparossa_protocol::Transport::UdpSinglePath as i32)))
            || !credential_matches
        {
            return Err(UdpSessionFrameError::Invalid);
        }
        Ok(())
    }

    /// Exit-signed exact one-path reservation.
    #[must_use]
    pub fn signed_exit_reservation(&self) -> &[u8] {
        &self.signed_exit_reservation
    }

    /// Data-Relay-signed exact path reservation.
    #[must_use]
    pub fn signed_relay_reservation(&self) -> &[u8] {
        &self.signed_relay_reservation
    }

    /// Client-session-signed return of that Relay reservation to the Exit.
    #[must_use]
    pub fn signed_confirmation(&self) -> &[u8] {
        &self.signed_confirmation
    }

    /// Exit-signed receipt for the exact confirmation bytes.
    #[must_use]
    pub fn signed_confirmation_receipt(&self) -> &[u8] {
        &self.signed_confirmation_receipt
    }

    /// Client-session-signed HPKE delivery of the route-local native bearer.
    #[must_use]
    pub fn signed_credential_delivery(&self) -> &[u8] {
        &self.signed_credential_delivery
    }

    /// Whether this request selects the native single-path CONNECT-IP runtime.
    ///
    /// Legacy protected-DNS associations deliberately omit the native bearer and remain on the
    /// separately authenticated DNS-only transport. General UDP must carry it.
    #[must_use]
    pub fn uses_native_connect_ip(&self) -> bool {
        !self.signed_credential_delivery.is_empty()
    }
}

/// Exit readiness returned only after its helper Commit and responder start.
///
/// The certificate is public. Its authentication comes from the SHA-256 commitment inside the
/// already verified Exit reservation; neither Relay is trusted to substitute these bytes.
#[derive(Clone, PartialEq, Message)]
pub struct UdpExitSessionSignal {
    #[prost(bytes = "vec", tag = "1")]
    reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    route_context_id: Vec<u8>,
    #[prost(uint32, tag = "3")]
    path_id: u32,
    #[prost(bytes = "vec", tag = "4")]
    certificate_der: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    exit_native_instance_id: Vec<u8>,
}

impl UdpExitSessionSignal {
    /// Construct one bounded committed-Exit signal.
    ///
    /// # Errors
    ///
    /// Rejects zero route identifiers/path or an empty/oversized certificate.
    pub fn new(
        reservation_id: [u8; ID_BYTES],
        route_context_id: [u8; ID_BYTES],
        path_id: u32,
        certificate_der: Vec<u8>,
        exit_native_instance_id: [u8; NATIVE_INSTANCE_BYTES],
    ) -> Result<Self, UdpSessionFrameError> {
        let value = Self {
            reservation_id: reservation_id.to_vec(),
            route_context_id: route_context_id.to_vec(),
            path_id,
            certificate_der,
            exit_native_instance_id: exit_native_instance_id.to_vec(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate fixed bounds without claiming the certificate matches the signed reservation.
    ///
    /// # Errors
    ///
    /// Rejects malformed route identifiers, path zero, or empty/oversized DER.
    pub fn validate(&self) -> Result<(), UdpSessionFrameError> {
        if fixed_nonzero::<ID_BYTES>(&self.reservation_id).is_none()
            || fixed_nonzero::<ID_BYTES>(&self.route_context_id).is_none()
            || self.path_id == 0
            || self.certificate_der.is_empty()
            || self.certificate_der.len() > MAX_CERTIFICATE_DER_BYTES
            || fixed_nonzero::<NATIVE_INSTANCE_BYTES>(&self.exit_native_instance_id).is_none()
        {
            return Err(UdpSessionFrameError::Invalid);
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

    /// Exact single path identifier.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.path_id
    }

    /// Public DER certificate whose digest is Exit-signed in the reservation.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Exact preflighted native Exit process incarnation which owns the listener.
    #[must_use]
    pub fn exit_native_instance_id(&self) -> &[u8] {
        &self.exit_native_instance_id
    }
}

/// Bounded UDP activation frame error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum UdpSessionFrameError {
    /// The frame is malformed, oversized, wrong-type, or cross-scoped.
    #[error("invalid UDP session activation frame")]
    Invalid,
}

fn signed_payload<T: Message + Default>(
    encoded: &[u8],
    expected: ControlMessageType,
) -> Result<T, UdpSessionFrameError> {
    if encoded.is_empty() || encoded.len() > MAX_CONTROL_MESSAGE_SIZE {
        return Err(UdpSessionFrameError::Invalid);
    }
    let envelope = decode_canonical::<SignedEnvelope>(encoded, MAX_CONTROL_MESSAGE_SIZE)
        .map_err(|_| UdpSessionFrameError::Invalid)?;
    if envelope.message_type != expected as i32 {
        return Err(UdpSessionFrameError::Invalid);
    }
    decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
        .map_err(|_| UdpSessionFrameError::Invalid)
}

fn signed_control_payload<T: ControlPayload>(
    encoded: &[u8],
    expected: ControlMessageType,
) -> Result<T, UdpSessionFrameError> {
    if encoded.is_empty() || encoded.len() > MAX_CONTROL_MESSAGE_SIZE {
        return Err(UdpSessionFrameError::Invalid);
    }
    let envelope = decode_canonical::<SignedEnvelope>(encoded, MAX_CONTROL_MESSAGE_SIZE)
        .map_err(|_| UdpSessionFrameError::Invalid)?;
    if envelope.protocol_version != PROTOCOL_VERSION || envelope.message_type != expected as i32 {
        return Err(UdpSessionFrameError::Invalid);
    }
    let payload = decode_canonical::<T>(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)
        .map_err(|_| UdpSessionFrameError::Invalid)?;
    payload
        .validate()
        .and_then(|()| payload.validate_envelope(&envelope))
        .map_err(|_| UdpSessionFrameError::Invalid)?;
    Ok(payload)
}

fn credential_matches_exit(
    credential: &volparossa_protocol::NativeRouteCredentialScope,
    exit: &ExitReservation,
    native: &volparossa_protocol::NativeRouteIdentity,
) -> bool {
    credential.reservation_id == exit.reservation_id
        && credential.route_context_id == exit.route_context_id
        && credential.finalize_id == exit.finalize_id
        && credential.exit_node_id == exit.exit_node_id
        && credential.client_session_id == exit.client_session_id
        && credential.client_session_public_key == exit.client_session_public_key
        && credential.auth_commitment == native.auth_commitment
        && credential.certificate_sha256 == native.certificate_sha256
        && credential.spki_sha256 == native.spki_sha256
        && credential.masque_context_id == native.masque_context_id
        && credential.client_native_instance_id == native.client_native_instance_id
        && credential.exit_native_instance_id == native.exit_native_instance_id
        && credential.credential_hpke_public_key == native.credential_hpke_public_key
        && credential.created_at_ms >= exit.created_at_ms
        && credential.created_at_ms < credential.expires_at_ms
        && credential.expires_at_ms == exit.expires_at_ms
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
                message_type: message_type as i32,
                payload: encode_canonical(payload, MAX_CONTROL_PAYLOAD_SIZE).expect("payload"),
                ..SignedEnvelope::default()
            },
            MAX_CONTROL_MESSAGE_SIZE,
        )
        .expect("envelope")
    }

    fn correlated_start(path_id: u32) -> UdpSessionStartRequest {
        let reservation_id = vec![1; ID_BYTES];
        let route_context_id = vec![2; ID_BYTES];
        let exit_node_id = vec![3; 32];
        let relay = RelayReservation {
            reservation_id: reservation_id.clone(),
            route_context_id: route_context_id.clone(),
            path_id,
            exit_node_id: exit_node_id.clone(),
            ..RelayReservation::default()
        };
        let signed_relay = signed(ControlMessageType::RelayReservation, &relay);
        UdpSessionStartRequest::new(
            signed(
                ControlMessageType::ExitReservation,
                &ExitReservation {
                    reservation_id: reservation_id.clone(),
                    route_context_id: route_context_id.clone(),
                    exit_node_id: exit_node_id.clone(),
                    maximum_paths: 1,
                    ..ExitReservation::default()
                },
            ),
            signed_relay.clone(),
            signed(
                ControlMessageType::ExitReservationConfirmation,
                &ExitReservationConfirmation {
                    reservation_id: reservation_id.clone(),
                    route_context_id: route_context_id.clone(),
                    path_id,
                    relay_reservation: signed_relay,
                    ..ExitReservationConfirmation::default()
                },
            ),
            signed(
                ControlMessageType::ExitConfirmationReceipt,
                &ExitConfirmationReceipt {
                    reservation_id,
                    route_context_id,
                    path_id,
                    exit_node_id,
                    ..ExitConfirmationReceipt::default()
                },
            ),
            Vec::new(),
        )
        .expect("correlated activation proof")
    }

    #[test]
    fn exact_start_and_exit_signal_round_trip_canonically() {
        let start = correlated_start(1);
        let encoded = encode_canonical(&start, MAX_CONTROL_MESSAGE_SIZE).expect("start encode");
        let decoded =
            decode_canonical::<UdpSessionStartRequest>(&encoded, MAX_CONTROL_MESSAGE_SIZE)
                .expect("start decode");
        decoded.validate().expect("exact start scope");

        let signal = UdpExitSessionSignal::new([1; 16], [2; 16], 1, vec![0x30, 1, 2], [9; 32])
            .expect("bounded signal");
        let encoded = encode_canonical(&signal, MAX_CONTROL_MESSAGE_SIZE).expect("signal encode");
        let decoded = decode_canonical::<UdpExitSessionSignal>(&encoded, MAX_CONTROL_MESSAGE_SIZE)
            .expect("signal decode");
        decoded.validate().expect("exact signal scope");
        assert_eq!(decoded.route_context_id(), [2; 16]);
    }

    #[test]
    fn start_rejects_confirmation_for_a_different_path() {
        let mut start = correlated_start(1);
        let confirmation = ExitReservationConfirmation {
            reservation_id: vec![1; ID_BYTES],
            route_context_id: vec![2; ID_BYTES],
            path_id: 2,
            relay_reservation: start.signed_relay_reservation.clone(),
            ..ExitReservationConfirmation::default()
        };
        start.signed_confirmation = signed(
            ControlMessageType::ExitReservationConfirmation,
            &confirmation,
        );
        assert_eq!(start.validate(), Err(UdpSessionFrameError::Invalid));
    }
}
