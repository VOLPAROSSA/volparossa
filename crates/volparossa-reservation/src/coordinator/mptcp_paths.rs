//! Same-session, original-reservation-bound live endpoint state.

#[allow(clippy::wildcard_imports, reason = "private coordinator phase")]
use super::*;
use volparossa_protocol::{MptcpPathsRequest, MptcpPathsState, mptcp_paths_request_hash};

impl ReservationCoordinator {
    /// Sign a fresh read-only query using the established route's original session.
    ///
    /// # Errors
    /// Rejects another session or a deadline outside the retained reservation.
    pub fn sign_mptcp_paths_request(
        &self,
        original: &VerifiedFinalizedExitBundle,
        now: u64,
        expiry: u64,
    ) -> Result<Vec<u8>, CoordinatorError> {
        let request = MptcpPathsRequest {
            signed_exit_reservation: original.signed_exit_reservation.clone(),
        };
        let parent = request.parent()?;
        if parent.client_session_id.as_slice() != self.client_session_id
            || parent.client_session_public_key.as_slice() != self.client_session_public_key()
        {
            return Err(CoordinatorError::Scope("MPTCP path-state session"));
        }
        Ok(sign_control_message(
            &request,
            &self.session_key,
            now,
            expiry,
            generate_nonce(),
            TimePolicy::default(),
        )?)
    }

    /// Verify an Exit snapshot for the exact fresh query and retained original authority.
    ///
    /// # Errors
    /// Rejects replay, changed session/Exit/context/reservation/lifetime or request substitution.
    pub fn verify_mptcp_paths_state(
        &mut self,
        original: &VerifiedFinalizedExitBundle,
        signed_request: &[u8],
        encoded: &[u8],
        now: u64,
    ) -> Result<MptcpPathsState, CoordinatorError> {
        let mut replay = ReplayCache::new(1)?;
        let query = verify_control_message::<MptcpPathsRequest>(
            signed_request,
            now,
            TimePolicy::default(),
            &mut replay,
        )?;
        let parent = query.message().parent()?;
        if query.message().signed_exit_reservation != original.signed_exit_reservation
            || query.sender_id() != &self.client_session_id
        {
            return Err(CoordinatorError::Scope(
                "MPTCP path-state original authority",
            ));
        }
        let state = verify_control_message::<MptcpPathsState>(
            encoded,
            now,
            TimePolicy::default(),
            &mut self.exit_replay,
        )?;
        let value = state.message();
        if value.request_sha256.as_slice() != mptcp_paths_request_hash(signed_request)
            || state.sender_id().as_slice() != parent.exit_node_id
            || value.exit_node_id != parent.exit_node_id
            || value.route_context_id != parent.route_context_id
            || value.reservation_id != parent.reservation_id
            || value.hard_expires_at_ms != parent.expires_at_ms
            || state.expires_at_ms() > query.expires_at_ms()
        {
            return Err(CoordinatorError::Scope("MPTCP path-state response"));
        }
        Ok(value.clone())
    }
}
