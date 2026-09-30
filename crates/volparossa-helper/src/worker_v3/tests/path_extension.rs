use super::*;
use crate::internal_protocol::path_extension::{Action, PathExtension};

#[test]
fn additive_prepare_abort_preserves_original_committed_worker() {
    let (mut worker, transport, _) = committed_quic_udp_worker_fixture(
        73,
        RoutingContextRole::Client,
        InternalEndpointRole::Client,
    );
    let Some(WorkerLeaseLifecycle::Committed(original)) = worker.lease.as_ref() else {
        panic!("committed fixture");
    };
    let original_plan = original[0]
        .resource
        .internal_lease_plan_v3()
        .expect("original exact plan");
    worker.staged_resources = validate_worker_prepare(
        &PrepareLeases {
            route_context_id: worker.route_context_id.to_vec(),
            leases: vec![original_plan.clone()],
        },
        worker.route_context_id,
        RoutingContextRole::Client,
    );
    let resource = crate::ownership_journal::durable_wireguard_resource_for_test(
        worker.route_context_id,
        RoutingContextRole::Client,
        2,
        volparossa_routing::WireguardRole::Client,
        19,
    )
    .expect("new exact resource");
    let mut plan = resource.internal_lease_plan_v3().expect("new lease plan");
    plan.setup_expires_at_unix = current_unix_seconds().expect("clock") + 20;
    plan.hard_expires_at_unix = original_plan.hard_expires_at_unix;
    let prepare = PrepareLeases {
        route_context_id: worker.route_context_id.to_vec(),
        leases: vec![plan],
    };
    let id = [31; 16];
    let mut keys = OsWorkerKeySource;
    let invoke =
        |worker: &mut WorkerContext<FakeWorkerKernel>, keys: &mut OsWorkerKeySource, action| {
            worker
                .extension_operation(
                    &PathExtension {
                        extension_id: id.to_vec(),
                        action: Some(action),
                    },
                    keys,
                    worker_deadline(),
                )
                .expect("typed extension call")
        };
    assert_eq!(
        invoke(&mut worker, &mut keys, Action::Stage(prepare.clone())).0,
        InternalWorkerResult::Ok
    );
    assert_eq!(
        invoke(&mut worker, &mut keys, Action::Prepare(prepare.clone())).0,
        InternalWorkerResult::Ok
    );
    assert!(worker.transport_lease(&transport).is_ok());
    worker.kernel.cleanup_calls.clear();
    let abort = Action::Abort(DestroyContext {
        route_context_id: worker.route_context_id.to_vec(),
    });
    assert_eq!(
        invoke(&mut worker, &mut keys, abort.clone()).0,
        InternalWorkerResult::Ok
    );
    assert!(
        worker
            .kernel
            .cleanup_calls
            .iter()
            .all(|(_, identity)| identity.0 == 2)
    );
    assert!(worker.transport_lease(&transport).is_ok());
    assert_eq!(
        worker
            .staged_resources
            .as_ref()
            .expect("original resources")
            .iter()
            .map(|resource| resource.internal_lease_plan_v3().expect("original plan"))
            .collect::<Vec<_>>(),
        vec![original_plan]
    );
    assert_eq!(
        invoke(&mut worker, &mut keys, abort).0,
        InternalWorkerResult::Ok
    );
    assert_eq!(
        invoke(&mut worker, &mut keys, Action::Stage(prepare)).0,
        InternalWorkerResult::Conflict
    );
}
