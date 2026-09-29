//! Fresh, endpoint-free snapshots from the exact live Exit runtime through its control relay.

#[allow(clippy::wildcard_imports, reason = "private discovery actor phase")]
use super::*;
use volparossa_protocol::{
    MptcpPathsRequest, MptcpPathsState, generate_nonce, mptcp_paths_request_hash,
};

pub(super) fn forward_scope_matches(request: &ExitForwardRequest, now: u64) -> bool {
    let Ok(mut replay) = ReplayCache::new(1) else {
        return false;
    };
    let Ok(query) = verify_control_message::<MptcpPathsRequest>(
        request.canonical_request(),
        now,
        TimePolicy::default(),
        &mut replay,
    ) else {
        return false;
    };
    let Ok(parent) = query.message().parent() else {
        return false;
    };
    inner_forward_scope_matches(
        request,
        query.nonce(),
        query.expires_at_ms(),
        &parent.control_relay_node_id,
        &parent.control_relay_peer_id,
        &parent.exit_node_id,
        &parent.exit_peer_id,
    )
}

impl DiscoveryRuntime {
    pub(super) async fn answer_mptcp_paths(
        &mut self,
        peer: Libp2pPeerId,
        connection: ConnectionId,
        request: ExitForwardRequest,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
    ) {
        let Ok(bound_connection) = self
            .service
            .bind_native_probe_control_connection(peer, connection)
        else {
            return;
        };
        let response = self.mptcp_paths_response(peer, &request).await;
        let response = if let Some(encoded) = response {
            ExitForwardResponse::granted(
                request.forward_id().to_vec(),
                ExitForwardOperation::MptcpPaths,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
                vec![encoded],
            )
        } else {
            ExitForwardResponse::unavailable(
                request.forward_id().to_vec(),
                ExitForwardOperation::MptcpPaths,
                self.local_node_id.to_vec(),
                self.service.local_peer_id().to_bytes(),
            )
        };
        if let Ok(response) = response {
            let _ = self.service.send_mptcp_paths_response(
                bound_connection,
                peer,
                channel,
                response.into(),
            );
        }
    }

    async fn mptcp_paths_response(
        &mut self,
        peer: Libp2pPeerId,
        request: &ExitForwardRequest,
    ) -> Option<Vec<u8>> {
        let untrusted = decoded_signed_payload::<MptcpPathsRequest>(request.canonical_request())?;
        let parent = untrusted.parent().ok()?;
        let context = fixed_bytes::<16>(&parent.route_context_id)?;
        let route = self.active_production_mptcp_exit_routes.get_mut(&context)?;
        let now = unix_millis();
        let start: MptcpSessionStartRequest = decode_canonical(
            &route.canonical_start,
            usize::try_from(MAX_FORWARDING_FRAME_BYTES).ok()?,
        )
        .ok()?;
        // Nested shape is not an Exit signature verification. Match the exact already verified
        // original grant before admitting any sender's nonce into this route's replay cache.
        if !route.runtime_started
            || route.expires_at_ms <= now
            || untrusted.signed_exit_reservation != start.signed_exit_reservation()
        {
            return None;
        }
        let query = verify_control_message::<MptcpPathsRequest>(
            request.canonical_request(),
            now,
            TimePolicy::default(),
            &mut route.path_state_replay,
        )
        .ok()?;
        if parent.exit_node_id.as_slice() != self.local_node_id
            || parent.exit_peer_id != self.service.local_peer_id().to_bytes()
            || parent.control_relay_peer_id != peer.to_bytes()
            || parent.control_relay_node_id != request.control_relay_node_id()
            || parent.reservation_id.as_slice() != route.reservation_id
            || parent.expires_at_ms != route.expires_at_ms
        {
            return None;
        }
        let control = route.path_control.clone()?;
        let state = control.snapshot().await.ok()?;
        let now = unix_millis();
        let expiry = query
            .expires_at_ms()
            .min(request.deadline_unix_ms())
            .min(parent.expires_at_ms)
            .min(now.saturating_add(5_000));
        let payload = MptcpPathsState {
            request_sha256: mptcp_paths_request_hash(request.canonical_request()).to_vec(),
            route_context_id: parent.route_context_id,
            reservation_id: parent.reservation_id,
            exit_node_id: parent.exit_node_id,
            hard_expires_at_ms: parent.expires_at_ms,
            revision: state.revision,
            active_path_ids: state.active,
            retired_path_ids: state.retired,
        };
        sign_control_message_with(
            &payload,
            self.local_public_key,
            now,
            expiry,
            generate_nonce(),
            TimePolicy::default(),
            |bytes| self.identity.sign(bytes).ok(),
        )
        .ok()
    }
}
