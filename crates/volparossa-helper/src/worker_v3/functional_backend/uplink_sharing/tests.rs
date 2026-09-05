use std::{env, fs, process::Command, sync::Arc};

use volparossa_routing::{
    CleanupOwned, CleanupScope, DestroyUplinkSharing, HELPER_PROTOCOL_VERSION, HelperRequest,
    HelperResult, InspectUplinkSharing, InstallUplinkSharing, helper_request, helper_response,
};
use zeroize::Zeroizing;

use super::super::tests::backend_with_state;
use crate::engine::HelperEngine;

const CHILD_NAMESPACE: &str = "VOLPAROSSA_SHARING_BACKEND_PARENT_NETNS";
const TEST_NAME: &str = "worker_v3::functional_backend::uplink_sharing::tests::uplink_sharing_disposable_engine_to_kernel_lifecycle";

#[test]
fn uplink_sharing_disposable_engine_to_kernel_lifecycle() {
    let namespace = fs::read_link("/proc/thread-self/ns/net").expect("current namespace");
    if let Some(parent) = env::var_os(CHILD_NAMESPACE) {
        assert_ne!(
            namespace.as_os_str(),
            parent,
            "never modify the host network"
        );
        eprintln!(
            "Disposable sharing test: add only veth shareapi0/shareapi1, install owned upload qdiscs, inspect and remove them, then delete the veth pair."
        );
        ip(&[
            "link",
            "add",
            "shareapi0",
            "type",
            "veth",
            "peer",
            "name",
            "shareapi1",
        ]);
        let _veth = VethCleanup;
        ip(&["link", "set", "shareapi0", "up"]);
        ip(&["link", "set", "shareapi1", "up"]);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(engine_lifecycle());
        return;
    }
    let output = Command::new("/usr/bin/timeout")
        .args([
            "--signal=TERM",
            "--kill-after=2s",
            "20s",
            "/usr/bin/unshare",
            "--user",
            "--map-root-user",
            "--net",
        ])
        .arg(env::current_exe().expect("test executable"))
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD_NAMESPACE, namespace.as_os_str())
        .env("LC_ALL", "C")
        .output()
        .expect("disposable backend process");
    assert_eq!(
        fs::read_link("/proc/thread-self/ns/net").unwrap(),
        namespace
    );
    if output.status.code() == Some(1)
        && output.stdout.is_empty()
        && matches!(
            output.stderr.as_slice(),
            b"unshare: unshare failed: Operation not permitted\n"
                | b"unshare: write failed /proc/self/uid_map: Operation not permitted\n"
                | b"unshare: write failed /proc/self/gid_map: Operation not permitted\n"
        )
    {
        eprintln!("SKIP sharing backend live proof: unprivileged namespaces unavailable");
        return;
    }
    assert!(
        output.status.success(),
        "backend live failure\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

async fn engine_lifecycle() {
    let backend = Arc::new(backend_with_state(None));
    let engine = HelperEngine::new_with_backend(Zeroizing::new([9; 32]), 1000, backend.clone());
    let install = request(
        1,
        helper_request::Operation::InstallUplinkSharing(InstallUplinkSharing {
            sharing_runtime_id: vec![7; 16],
            interface: "shareapi0".to_owned(),
            total_upload_mbps: 2,
            contribution_upload_ceiling_mbps: 1,
        }),
    );
    let installed = engine.execute(install.clone()).await;
    assert_eq!(installed.result, HelperResult::Ok as i32, "{installed:?}");
    let Some(helper_response::Outcome::InstalledUplinkSharing(owner)) = installed.outcome else {
        panic!("typed installed owner");
    };
    assert!(owner.egress_ifindex > 1);
    let inspect = request(
        2,
        helper_request::Operation::InspectUplinkSharing(InspectUplinkSharing {
            sharing_runtime_id: owner.sharing_runtime_id.clone(),
            sharing_handle: owner.sharing_handle.clone(),
        }),
    );
    let counters = engine.execute(inspect).await;
    assert_eq!(counters.result, HelperResult::Ok as i32, "{counters:?}");
    assert!(matches!(
        counters.outcome,
        Some(helper_response::Outcome::SharingCounters(_))
    ));
    let cleanup = |id, scope| {
        request(
            id,
            helper_request::Operation::CleanupOwned(CleanupOwned {
                cleanup_token: vec![9; 32],
                scope: scope as i32,
            }),
        )
    };
    assert_eq!(
        engine
            .execute(cleanup(3, CleanupScope::RouteContextsOnly))
            .await
            .result,
        HelperResult::Ok as i32
    );
    assert!(
        backend.sharing_state.lock().unwrap().is_some(),
        "route cleanup preserves real queues"
    );
    let destroyed = engine
        .execute(request(
            4,
            helper_request::Operation::DestroyUplinkSharing(DestroyUplinkSharing {
                sharing_runtime_id: owner.sharing_runtime_id,
                sharing_handle: owner.sharing_handle,
            }),
        ))
        .await;
    assert_eq!(destroyed.result, HelperResult::Ok as i32, "{destroyed:?}");
    assert!(backend.sharing_state.lock().unwrap().is_none());
    // A new installation can only succeed when exact default-qdisc restoration was real.
    assert_eq!(
        engine.execute(install.clone()).await.result,
        HelperResult::Ok as i32
    );
    assert_eq!(
        engine
            .execute(cleanup(5, CleanupScope::AllOwnedResources))
            .await
            .result,
        HelperResult::Ok as i32
    );
    assert!(backend.sharing_state.lock().unwrap().is_none());
    assert_eq!(
        engine.execute(install).await.result,
        HelperResult::Ok as i32
    );
    assert!(engine.shutdown_cleanup().await);
    assert!(backend.sharing_state.lock().unwrap().is_none());
    println!(
        "SHARING_BACKEND_PROOF real typed Install/Inspect/Destroy; route-only preserved; AllOwned/shutdown restored exact baseline"
    );
}

fn request(id: u8, operation: helper_request::Operation) -> HelperRequest {
    HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: vec![id; 16],
        operation: Some(operation),
    }
}

fn ip(args: &[&str]) {
    assert_ne!(
        fs::read_link("/proc/thread-self/ns/net")
            .unwrap()
            .as_os_str(),
        env::var_os(CHILD_NAMESPACE).expect("parent namespace")
    );
    let output = Command::new("/usr/bin/ip")
        .args(args)
        .output()
        .expect("disposable ip");
    assert!(
        output.status.success(),
        "disposable ip failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct VethCleanup;
impl Drop for VethCleanup {
    fn drop(&mut self) {
        ip(&["link", "delete", "shareapi0"]);
    }
}
