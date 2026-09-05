//! Real namespace-local Relay lifecycle regression, without a daemon or host network changes.

use super::{
    Command, Duration, HardDeadline, Instant, NamespaceKernel, NetworkNamespaceIdentity,
    OsWorkerKeySource, RoutingContextRole, WorkerActivateOutcome, WorkerContext,
    WorkerDestroyOutcome, WorkerMptcpPathManager, WorkerNetworkBootstrap, WorkerPrepareOutcome,
    current_unix_seconds, env, functional_backend, relay_fence, validate_worker_prepare,
    worker_relay_activate, worker_relay_prepare,
};

fn deadline() -> HardDeadline {
    HardDeadline::after(Duration::from_secs(2)).expect("bounded kernel operation")
}

fn ip(arguments: &[&str]) {
    let output = Command::new("ip")
        .args(arguments)
        .output()
        .expect("namespace ip tool");
    assert!(
        output.status.success(),
        "namespace setup: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn prepare_disposable_namespace() -> NetworkNamespaceIdentity {
    let parent = NetworkNamespaceIdentity::fixture(
        env::var("VOLPAROSSA_TEST_PARENT_NETNS_DEVICE")
            .unwrap()
            .parse()
            .unwrap(),
        env::var("VOLPAROSSA_TEST_PARENT_NETNS_INODE")
            .unwrap()
            .parse()
            .unwrap(),
    );
    assert_ne!(
        parent,
        crate::worker_sandbox::current_network_namespace_identity().unwrap()
    );
    ip(&["link", "set", "lo", "up"]);
    // Fixture-only setup inside the proven new netns. The production pre-drop bootstrap also
    // validates root-owned procfs metadata, which a one-UID user namespace deliberately lacks.
    let forwarding = Command::new("/usr/sbin/sysctl")
        .args(["-q", "-w", "net.ipv6.conf.all.forwarding=1"])
        .output()
        .expect("namespace forwarding setup");
    assert!(
        forwarding.status.success(),
        "namespace forwarding: {}",
        String::from_utf8_lossy(&forwarding.stderr)
    );
    parent
}

fn report_cleanup_state(context: &mut WorkerContext<NamespaceKernel>) {
    let fence = match context.relay_fence.as_ref() {
        Some(super::WorkerRelayFence::Active { .. }) => "ACTIVE",
        Some(super::WorkerRelayFence::Restricted(_)) => "RESTRICTED",
        Some(_) => "OTHER",
        None => "NONE",
    };
    eprintln!(
        "RELAY_CLEANUP_STATE mptcp_retained={} fence={fence}",
        context.mptcp.is_some()
    );
    for resource in context.staged_resources.as_ref().unwrap() {
        eprintln!(
            "RELAY_CLEANUP_LINK absent={}",
            context
                .kernel
                .prove_wireguard_absent_v3(resource, deadline())
                .is_ok()
        );
    }
}

#[test]
fn repeated_real_relay_pair_prepare_activate_destroy() {
    if !functional_backend::tests::run_inside_disposable_user_network_namespace(
        "worker_v3::tests::live_relay_cleanup::repeated_real_relay_pair_prepare_activate_destroy",
        "VOLPAROSSA_TEST_RELAY_CLEANUP_NETNS",
    ) {
        return;
    }
    let parent = prepare_disposable_namespace();
    for iteration in 1_u8..=8 {
        let mut context_id = [0x93; 16];
        context_id[15] = iteration;
        let now = current_unix_seconds().unwrap();
        let mut prepare = worker_relay_prepare(context_id, iteration);
        for lease in &mut prepare.leases {
            lease.setup_expires_at_unix = now + 30;
            lease.hard_expires_at_unix = now + 60;
        }
        let resources = validate_worker_prepare(&prepare, context_id, RoutingContextRole::Relay)
            .expect("canonical owned Relay pair");
        for resource in &resources {
            ip(&["link", "add", resource.interface(), "type", "wireguard"]);
            ip(&[
                "link",
                "set",
                "dev",
                resource.interface(),
                "alias",
                resource.ownership_alias(),
            ]);
        }
        let namespace = relay_fence::RelayFenceNamespaceAuthority::new(
            parent,
            crate::worker_sandbox::current_network_namespace_identity().unwrap(),
        )
        .unwrap();
        let pristine = relay_fence::observe_pristine_relay_fence(namespace, deadline())
            .expect("real empty namespace ruleset");
        let identity = relay_fence::RelayFenceIdentity::derive(context_id, 1).unwrap();
        let restricted = relay_fence::create_relay_fence_baseline(pristine, identity, deadline())
            .expect("real restrictive Relay bootstrap");
        let bootstrap = WorkerNetworkBootstrap::RelayRestricted(restricted);
        let kernel = NamespaceKernel::connect(deadline()).expect("real namespace kernel");
        let manager =
            WorkerMptcpPathManager::prepare(context_id, 1, 1).expect("real MPTCP manager");
        let mut context = WorkerContext::new_bound(
            context_id,
            RoutingContextRole::Relay,
            1,
            bootstrap,
            kernel,
            resources,
            manager,
        )
        .expect("exact worker binding");
        let mut keys = OsWorkerKeySource;
        assert!(matches!(
            context.prepare(&prepare, &mut keys, deadline()),
            WorkerPrepareOutcome::Prepared(_)
        ));
        let mut activate = worker_relay_activate(context_id);
        for lease in &mut activate.leases {
            lease.hard_expires_at_unix = now + 60;
            lease.persistent_keepalive_seconds = 0;
        }
        assert!(matches!(
            context.activate(&activate, deadline()),
            WorkerActivateOutcome::Activated(_)
        ));
        let started = Instant::now();
        let outcome = context.destroy(deadline());
        if outcome != WorkerDestroyOutcome::Destroyed {
            report_cleanup_state(&mut context);
        }
        assert_eq!(
            outcome,
            WorkerDestroyOutcome::Destroyed,
            "iteration {iteration}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        for resource in context.staged_resources.as_ref().unwrap() {
            context
                .kernel
                .prove_wireguard_absent_v3(resource, deadline())
                .expect("both exact links absent");
        }
        eprintln!("RELAY_DESTROY_PROVEN iteration={iteration}");
    }
}
