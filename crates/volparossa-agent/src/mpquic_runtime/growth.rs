//! Consume one existing authorized warm descriptor without retiring a useful active path.

use super::{
    Instant, MAXIMUM_MULTIPATH_PATHS, ProductionMpquicError, ProductionMpquicSession,
    TransportMode, await_reconfigured_session, start_request, validate_committed_path,
    validate_reconfiguration_wait,
};
use std::time::Duration;

impl ProductionMpquicSession {
    /// Activate an already committed warm path for an explicitly justified failover probe.
    ///
    /// The descriptor, Relay grant and Exit listener were retained by this exact session. This
    /// never replaces the signed minimum or fabricates payload readiness: subsequent native
    /// status must still demonstrate that the added path actually carries useful traffic.
    pub(crate) async fn activate_warm_path(
        &mut self,
        warm_path_id: u32,
        now_ms: u64,
        ready_wait: Duration,
    ) -> Result<(), ProductionMpquicError> {
        validate_reconfiguration_wait(ready_wait)?;
        if self.transport_mode != TransportMode::MultipathQuic
            || self.active_path_ids.len() >= MAXIMUM_MULTIPATH_PATHS
            || self.active_path_ids.contains(&warm_path_id)
        {
            return Err(ProductionMpquicError::Invalid("MPQUIC warm growth state"));
        }
        let start = start_request(
            &self.authorization,
            self.minimum_paths,
            self.transport_mode,
            now_ms,
        )?;
        let warm = self
            .warm_paths
            .get(&warm_path_id)
            .ok_or(ProductionMpquicError::Invalid("MPQUIC committed warm path"))?;
        validate_committed_path(&start, warm, now_ms)?;
        let remaining = Duration::from_millis(
            warm.expires_at_ms.min(self.authorization.expires_at_ms()) - now_ms,
        );
        let deadline = Instant::now() + ready_wait.min(remaining);
        let warm = self
            .warm_paths
            .remove(&warm_path_id)
            .ok_or(ProductionMpquicError::Invalid("MPQUIC owned warm path"))?;
        let assignment = tokio::time::timeout_at(deadline, async {
            self.client.add_path(warm.add, warm.descriptor).await?;
            await_reconfigured_session(
                &self.client,
                &start,
                deadline.saturating_duration_since(Instant::now()),
            )
            .await
        })
        .await
        .map_err(|_| ProductionMpquicError::ReadyTimeout)??;
        self.assignment = assignment;
        self.active_path_ids.push(warm_path_id);
        self.active_path_ids.sort_unstable();
        Ok(())
    }
}
