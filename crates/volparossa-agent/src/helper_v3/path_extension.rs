//! Same-runtime, additive lease ownership for a route which is already committed.
//!
//! Register the attempted extension before any RPC is polled. A lost response never loses its
//! abort identity; original-context destruction remains authoritative for all helper resources.

use volparossa_routing::{
    AbortPathExtension, ActivatePathExtension, ActivatedPathExtension, CommitPathExtension,
    CommittedPathExtension, ContextRole, Empty, PreparePathExtension, PreparedLease,
    PreparedPathExtension, WireguardRole, helper_request, helper_response,
};
use zeroize::Zeroize;

use super::{HelperClient, HelperClientError, RuntimeBoundPreparedLeaseBatch, RuntimeLeasePhase};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    PrepareDispatched,
    Prepared,
    ActivationDispatched,
    Activated,
    CommitDispatched,
    Committed,
    AbortDispatched,
    Aborted,
}

pub(super) struct PathExtensionState {
    request: PreparePathExtension,
    prepared: Option<PreparedLease>,
    phase: Phase,
}

impl PathExtensionState {
    fn pending(&self) -> bool {
        !matches!(self.phase, Phase::Committed | Phase::Aborted)
    }

    fn lease_matches(&self, handle: &[u8], path: u32, role: i32) -> bool {
        self.prepared.as_ref().is_some_and(|lease| {
            lease.lease_handle == handle && lease.path_id == path && lease.role == role
        })
    }
}

impl Drop for PathExtensionState {
    fn drop(&mut self) {
        self.request.context_handle.zeroize();
        if let Some(lease) = &mut self.prepared {
            lease.lease_handle.zeroize();
        }
    }
}

impl RuntimeBoundPreparedLeaseBatch {
    /// The full owner stays affine; callers may derive only a queue-update capability from
    /// a settled activated lease. Ambiguous in-flight mutation and aborted ownership fail closed.
    pub(super) fn activated_extension_lease(&self, id: [u8; 16]) -> Option<&PreparedLease> {
        let state = self.extensions.get(&id)?;
        (self.phase == RuntimeLeasePhase::Committed
            && matches!(state.phase, Phase::Activated | Phase::Committed))
        .then_some(state.prepared.as_ref())
        .flatten()
    }

    pub(crate) fn committed_extension_path(&self, id: [u8; 16]) -> Option<u32> {
        let state = self.extensions.get(&id)?;
        (self.phase == RuntimeLeasePhase::Committed && state.phase == Phase::Committed)
            .then(|| state.prepared.as_ref().map(|lease| lease.path_id))
            .flatten()
    }

    fn begin_path_extension(
        &mut self,
        request: PreparePathExtension,
    ) -> Result<[u8; 16], HelperClientError> {
        let id: [u8; 16] = request
            .extension_id
            .as_slice()
            .try_into()
            .map_err(|_| HelperClientError::Correlation)?;
        let lease = request
            .lease
            .as_ref()
            .ok_or(HelperClientError::Correlation)?;
        let expected_role = match ContextRole::try_from(self.prepare.role) {
            Ok(ContextRole::Client) => WireguardRole::Client,
            Ok(ContextRole::Exit) => WireguardRole::Exit,
            _ => return Err(HelperClientError::Correlation),
        };
        if self.phase != RuntimeLeasePhase::Committed
            || id == [0; 16]
            || self.extensions.contains_key(&id)
            || request.route_context_id != self.prepare.route_context_id
            || request.context_handle != self.prepared.context_handle
            || request.setup_expires_at_unix == 0
            || request.setup_expires_at_unix > self.prepare.hard_expires_at_unix
            || lease.role != expected_role as i32
            || !(1..=8).contains(&lease.path_id)
            || self.prepare.leases.len() + self.extensions.len() >= 8
            || self
                .prepare
                .leases
                .iter()
                .any(|old| old.path_id == lease.path_id)
            || self.extensions.values().any(|old| {
                old.pending()
                    || old
                        .request
                        .lease
                        .as_ref()
                        .is_some_and(|old| old.path_id == lease.path_id)
            })
        {
            return Err(HelperClientError::Correlation);
        }
        self.extensions.insert(
            id,
            PathExtensionState {
                request,
                prepared: None,
                phase: Phase::PrepareDispatched,
            },
        );
        Ok(id)
    }

    fn extension_mut(
        &mut self,
        context: &[u8],
        handle: &[u8],
        id: &[u8],
    ) -> Result<&mut PathExtensionState, HelperClientError> {
        let id: [u8; 16] = id.try_into().map_err(|_| HelperClientError::Correlation)?;
        if self.phase != RuntimeLeasePhase::Committed
            || context != self.prepare.route_context_id
            || handle != self.prepared.context_handle
        {
            return Err(HelperClientError::Correlation);
        }
        self.extensions
            .get_mut(&id)
            .ok_or(HelperClientError::Correlation)
    }

    fn finish_path_prepare(
        &mut self,
        id: [u8; 16],
        response: &PreparedPathExtension,
    ) -> Result<(), HelperClientError> {
        let state = self
            .extensions
            .get_mut(&id)
            .ok_or(HelperClientError::Correlation)?;
        let plan = state
            .request
            .lease
            .as_ref()
            .ok_or(HelperClientError::Correlation)?;
        let lease = response
            .lease
            .as_ref()
            .ok_or(HelperClientError::Correlation)?;
        if state.phase != Phase::PrepareDispatched
            || response.extension_id != id
            || response.context_handle != self.prepared.context_handle
            || lease.path_id != plan.path_id
            || lease.role != plan.role
            || lease.lease_handle.len() != 32
            || lease.lease_handle.iter().all(|byte| *byte == 0)
            || self
                .prepared
                .leases
                .iter()
                .any(|old| old.lease_handle == lease.lease_handle)
        {
            return Err(HelperClientError::Correlation);
        }
        state.prepared = Some(lease.clone());
        state.phase = Phase::Prepared;
        Ok(())
    }
}

impl HelperClient {
    pub(crate) async fn prepare_path_extension(
        &self,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        value: PreparePathExtension,
    ) -> Result<PreparedPathExtension, HelperClientError> {
        let id = owner.begin_path_extension(value.clone())?;
        let outcome = self
            .execute_expected_runtime(
                &owner.helper_runtime_id,
                helper_request::Operation::PreparePathExtension(value),
            )
            .await?;
        let helper_response::Outcome::PreparedPathExtension(response) = outcome else {
            return Err(HelperClientError::Correlation);
        };
        owner.finish_path_prepare(id, &response)?;
        Ok(response)
    }

    pub(crate) async fn activate_path_extension(
        &self,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        value: ActivatePathExtension,
    ) -> Result<ActivatedPathExtension, HelperClientError> {
        let state = owner.extension_mut(
            &value.route_context_id,
            &value.context_handle,
            &value.extension_id,
        )?;
        let lease = value.lease.as_ref().ok_or(HelperClientError::Correlation)?;
        if state.phase != Phase::Prepared
            || value.signed_route_extension.is_empty()
            || !state.lease_matches(&lease.lease_handle, lease.path_id, lease.role)
        {
            return Err(HelperClientError::Correlation);
        }
        state.phase = Phase::ActivationDispatched;
        let outcome = self
            .execute_expected_runtime(
                &owner.helper_runtime_id,
                helper_request::Operation::ActivatePathExtension(value.clone()),
            )
            .await?;
        let helper_response::Outcome::ActivatedPathExtension(response) = outcome else {
            return Err(HelperClientError::Correlation);
        };
        if response.context_handle != value.context_handle
            || response.extension_id != value.extension_id
            || response.lease_handle != lease.lease_handle
        {
            return Err(HelperClientError::Correlation);
        }
        owner
            .extension_mut(
                &value.route_context_id,
                &value.context_handle,
                &value.extension_id,
            )?
            .phase = Phase::Activated;
        Ok(response)
    }

    pub(crate) async fn commit_path_extension(
        &self,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        value: CommitPathExtension,
    ) -> Result<CommittedPathExtension, HelperClientError> {
        let state = owner.extension_mut(
            &value.route_context_id,
            &value.context_handle,
            &value.extension_id,
        )?;
        let lease = value.lease.as_ref().ok_or(HelperClientError::Correlation)?;
        if state.phase != Phase::Activated
            || !state.lease_matches(&lease.lease_handle, lease.path_id, lease.role)
        {
            return Err(HelperClientError::Correlation);
        }
        state.phase = Phase::CommitDispatched;
        let outcome = self
            .execute_expected_runtime(
                &owner.helper_runtime_id,
                helper_request::Operation::CommitPathExtension(value.clone()),
            )
            .await?;
        let helper_response::Outcome::CommittedPathExtension(response) = outcome else {
            return Err(HelperClientError::Correlation);
        };
        let proof = response
            .lease
            .as_ref()
            .ok_or(HelperClientError::Correlation)?;
        if response.context_handle != value.context_handle
            || response.extension_id != value.extension_id
            || proof.lease_handle != lease.lease_handle
            || proof.latest_handshake_unix == 0
            || proof.received_bytes == 0
            || proof.transmitted_bytes == 0
        {
            return Err(HelperClientError::Correlation);
        }
        owner
            .extension_mut(
                &value.route_context_id,
                &value.context_handle,
                &value.extension_id,
            )?
            .phase = Phase::Committed;
        Ok(response)
    }

    pub(crate) async fn abort_path_extension(
        &self,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        extension_id: [u8; 16],
    ) -> Result<(), HelperClientError> {
        let state = owner
            .extensions
            .get_mut(&extension_id)
            .ok_or(HelperClientError::Correlation)?;
        if state.phase == Phase::Aborted {
            return Ok(());
        }
        state.phase = Phase::AbortDispatched;
        let request = AbortPathExtension {
            route_context_id: state.request.route_context_id.clone(),
            context_handle: state.request.context_handle.clone(),
            extension_id: extension_id.to_vec(),
        };
        let outcome = self
            .execute_expected_runtime(
                &owner.helper_runtime_id,
                helper_request::Operation::AbortPathExtension(request),
            )
            .await?;
        if !matches!(outcome, helper_response::Outcome::Empty(Empty {})) {
            return Err(HelperClientError::Correlation);
        }
        let state = owner
            .extensions
            .get_mut(&extension_id)
            .ok_or(HelperClientError::Correlation)?;
        state.phase = Phase::Aborted;
        if let Some(mut lease) = state.prepared.take() {
            lease.lease_handle.zeroize();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_routing::{
        LeasePlan, PrepareLeaseBatch, PreparedLeaseBatch, PublicUdpEndpoint, UnderlayEvidence,
    };

    fn owner() -> RuntimeBoundPreparedLeaseBatch {
        let prepare = PrepareLeaseBatch {
            route_context_id: vec![1; 16],
            role: ContextRole::Exit as i32,
            leases: (1..=2)
                .map(|path_id| LeasePlan {
                    path_id,
                    role: WireguardRole::Exit as i32,
                })
                .collect(),
            setup_expires_at_unix: 20,
            hard_expires_at_unix: 100,
            mptcp_accepted_addrs: 2,
            mptcp_subflows: 2,
            traversal_hints: Vec::new(),
        };
        let prepared = PreparedLeaseBatch {
            context_handle: vec![2; 32],
            leases: (1..=2).map(prepared_lease).collect(),
        };
        let mut owner = RuntimeBoundPreparedLeaseBatch::for_test(prepare, prepared);
        owner.phase = RuntimeLeasePhase::Committed;
        owner
    }

    fn prepared_lease(path: u32) -> PreparedLease {
        PreparedLease {
            lease_handle: vec![u8::try_from(path).unwrap() + 2; 32],
            path_id: path,
            role: WireguardRole::Exit as i32,
            public_key: vec![7; 32],
            public_endpoint: Some(PublicUdpEndpoint {
                address: vec![192, 0, 2, 4],
                port: 4000 + path,
            }),
            underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
        }
    }

    fn request(path_id: u32) -> PreparePathExtension {
        PreparePathExtension {
            route_context_id: vec![1; 16],
            context_handle: vec![2; 32],
            extension_id: vec![u8::try_from(path_id).unwrap(); 16],
            lease: Some(LeasePlan {
                path_id,
                role: WireguardRole::Exit as i32,
            }),
            setup_expires_at_unix: 40,
            traversal_hints: Vec::new(),
        }
    }

    #[test]
    fn extension_downlink_target_requires_settled_activation_and_exact_owner() {
        let mut owner = owner();
        let id = owner.begin_path_extension(request(3)).unwrap();
        assert!(owner.extension_downlink_budget_target(id).is_err());
        owner
            .finish_path_prepare(
                id,
                &PreparedPathExtension {
                    context_handle: vec![2; 32],
                    extension_id: id.to_vec(),
                    lease: Some(prepared_lease(3)),
                },
            )
            .unwrap();
        assert!(owner.extension_downlink_budget_target(id).is_err());
        owner.extensions.get_mut(&id).unwrap().phase = Phase::Activated;
        let target = owner.extension_downlink_budget_target(id).unwrap();
        assert!(target.matches_route_path(&[1; 16], 3));
        assert!(!target.matches_route_path(&[1; 16], 2));
        assert!(!target.matches_route_path(&[2; 16], 3));
        assert!(target.same_owner(&owner.extension_downlink_budget_target(id).unwrap()));
        for phase in [
            Phase::ActivationDispatched,
            Phase::CommitDispatched,
            Phase::AbortDispatched,
            Phase::Aborted,
        ] {
            owner.extensions.get_mut(&id).unwrap().phase = phase;
            assert!(owner.extension_downlink_budget_target(id).is_err());
        }
        owner.extensions.get_mut(&id).unwrap().phase = Phase::Committed;
        assert!(target.same_owner(&owner.extension_downlink_budget_target(id).unwrap()));
        owner
            .extensions
            .get_mut(&id)
            .unwrap()
            .prepared
            .as_mut()
            .unwrap()
            .role = WireguardRole::Client as i32;
        assert!(owner.extension_downlink_budget_target(id).is_err());
    }

    #[test]
    fn attempted_extension_retains_abort_identity_without_rewriting_original_prepare() {
        let mut owner = owner();
        let original_prepare = owner.prepare.clone();
        let original_proof = owner.prepared.clone();
        let id = owner.begin_path_extension(request(3)).unwrap();
        assert_eq!(owner.prepare, original_prepare);
        assert_eq!(owner.prepared, original_proof);
        assert_eq!(owner.extensions[&id].request.extension_id, id);
        assert!(owner.extensions[&id].pending());
        assert!(owner.begin_path_extension(request(4)).is_err());
        assert!(owner.committed_extension_path(id).is_none());
        assert_eq!(
            owner.destroy_request().context_handle,
            original_proof.context_handle
        );
    }

    #[test]
    fn extension_response_must_match_exact_new_lease_and_keeps_original_deadline() {
        let mut owner = owner();
        let id = owner.begin_path_extension(request(3)).unwrap();
        let mut response = PreparedPathExtension {
            context_handle: vec![2; 32],
            extension_id: id.to_vec(),
            lease: Some(prepared_lease(4)),
        };
        assert!(owner.finish_path_prepare(id, &response).is_err());
        response.lease = Some(prepared_lease(3));
        owner.finish_path_prepare(id, &response).unwrap();
        assert_eq!(owner.prepare.hard_expires_at_unix, 100);
        assert_eq!(owner.prepare.setup_expires_at_unix, 20);
        assert_eq!(owner.prepared.leases.len(), 2);
        assert!(owner.extensions[&id].lease_matches(&[5; 32], 3, WireguardRole::Exit as i32));
        assert!(owner.committed_extension_path(id).is_none());
    }

    #[test]
    fn extension_cannot_reuse_original_or_aborted_path_or_extend_authority() {
        let mut owner = owner();
        assert!(owner.begin_path_extension(request(1)).is_err());
        let mut wrong = request(3);
        wrong.setup_expires_at_unix = 101;
        assert!(owner.begin_path_extension(wrong).is_err());
        let mut wrong = request(3);
        wrong.context_handle = vec![99; 32];
        assert!(owner.begin_path_extension(wrong).is_err());
        let id = owner.begin_path_extension(request(3)).unwrap();
        owner.extensions.get_mut(&id).unwrap().phase = Phase::Aborted;
        let mut replay = request(3);
        replay.extension_id = vec![9; 16];
        assert!(owner.begin_path_extension(replay).is_err());
        assert!(owner.begin_path_extension(request(4)).is_ok());
    }
}
