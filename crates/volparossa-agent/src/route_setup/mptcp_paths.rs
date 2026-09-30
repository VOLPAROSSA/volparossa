//! Same-control-relay read-only endpoint state; no direct Client-to-Exit connection.

#[allow(clippy::wildcard_imports, reason = "private route maintenance phase")]
use super::*;

impl ProductionRoute {
    pub(super) async fn mptcp_path_state(
        &mut self,
        discovery: &DiscoveryControlHandle,
    ) -> Option<volparossa_protocol::MptcpPathsState> {
        // A unavailable read does not replace or disconnect an otherwise healthy route.
        // Every actual subflow change still requires a new verified signed snapshot.
        timeout(Duration::from_secs(5), async {
            let route = &mut self.established;
            let authority = extension::authorities(route, discovery).await.ok()?;
            let now = crate::unix_millis();
            let expiry = now
                .saturating_add(5_000)
                .min(route.request.parameters.expires_at_ms);
            let original = route.exit_bundle.clone();
            let signed = extension::session(route)
                .ok()?
                .sign_mptcp_paths_request(&original, now, expiry)
                .ok()?;
            let rpc = exit_forward_request(
                &authority,
                ExitForwardOperation::MptcpPaths,
                signed.clone(),
                expiry,
            )
            .ok()?;
            let response = discovery
                .request_exit_forward(authority.control.peer_id, rpc.clone())
                .await
                .ok()?;
            let values = accepted_exit_response(
                &rpc,
                &response,
                &authority.exit,
                RouteSetupPhase::Finalizing,
            )
            .ok()?;
            let [encoded]: [Vec<u8>; 1] = values.try_into().ok()?;
            extension::session(route)
                .ok()?
                .verify_mptcp_paths_state(&original, &signed, &encoded, crate::unix_millis())
                .ok()
        })
        .await
        .ok()
        .flatten()
    }
}
