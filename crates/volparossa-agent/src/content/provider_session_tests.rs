//! Actual provider-session rejection over loopback TCP and authenticated provider TLS.
//! This is connection-lifetime evidence, not MPTCP, relay routing or consumer acceptance.

use super::*;
use std::{env, fs, io};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{Instant, sleep, timeout_at},
};
use volparossa_config::Config;
use volparossa_local_control::ProviderActivityStage;
use volparossa_metrics::MetricsRegistry;

fn require_isolation() {
    let parent = env::var_os("VOLPAROSSA_EXACT_CONTENT_PARENT_NETNS")
        .expect("run only through the disposable namespace harness");
    let number = parent
        .to_str()
        .and_then(|value| value.strip_prefix("net:["))
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<u64>().ok());
    assert!(number.is_some_and(|value| value > 0));
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
        parent
    );
}

async fn entered(activity: &provider_activity::Activity, stage: ProviderActivityStage) -> bool {
    timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = activity.snapshot();
            if snapshot.active_sessions == Some(1)
                && snapshot.groups.len() == 1
                && snapshot.groups[0].stage == stage as i32
            {
                break;
            }
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .is_ok()
}

struct AuthenticatedSession {
    client: tokio_rustls::client::TlsStream<TcpStream>,
    tasks: JoinSet<Option<provider_events::Batch>>,
    server: tokio::task::AbortHandle,
    before_handshake: Instant,
}

async fn authenticated_session(
    registry: &Arc<Mutex<PublicationRegistry>>,
    activity: &Arc<provider_activity::Activity>,
) -> AuthenticatedSession {
    let session = activity.begin();
    let identity = Identity::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = ProviderEndpoint::new("provider.volparossa.test", address.port()).unwrap();
    let signer = ContentRuntime::new(&identity).unwrap().signer;
    let offer = make_offer(&signer, endpoint.clone())
        .unwrap()
        .verify(&signer.verifying_key(), now())
        .unwrap();
    let tls = tls::ContentTlsServer::new(identity.keypair(), endpoint.hostname()).unwrap();
    let mut tasks = JoinSet::new();
    let server_registry = Arc::clone(registry);
    // JoinSet aborts the owned task if setup or an assertion panics.
    let server = tasks.spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(listener);
        serve_provider_session(
            stream,
            tls,
            server_registry,
            session,
            fixture_correlation::Guard::default(),
        )
        .await
    });
    let socket = timeout(Duration::from_secs(5), TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
    let before_handshake = Instant::now();
    let client = tls::connect(socket, *identity.peer_id(), &offer)
        .await
        .expect("real TLS must authenticate the signed provider identity");
    AuthenticatedSession {
        client,
        tasks,
        server,
        before_handshake,
    }
}

async fn rejected_session_closes_before_event_lock(hold_registry: bool) {
    // Do not open even a loopback socket in the calling host namespace.
    require_isolation();
    assert_eq!(
        TransferLimits::default().exchange_timeout,
        Duration::from_secs(15)
    );
    assert_eq!(REGISTRY_SNAPSHOT_TIMEOUT, Duration::from_secs(2));
    let config = Config::default();
    let state = Arc::new(RwLock::new(
        AgentState::new(&config, config.roles, None, MetricsRegistry::new()).unwrap(),
    ));
    // Diagnostics cannot acquire this lock before the rejected session releases its slot.
    let state_guard = state.write().await;
    let registry = Arc::new(Mutex::new(PublicationRegistry::default()));
    let registry_guard = if hold_registry {
        Some(registry.lock().await)
    } else {
        None
    };
    let activity = Arc::new(provider_activity::Activity::default());
    let AuthenticatedSession {
        mut client,
        mut tasks,
        server,
        before_handshake,
    } = authenticated_session(&registry, &activity).await;
    let close_deadline = Instant::now() + Duration::from_secs(if hold_registry { 8 } else { 25 });
    let expected_stage = if hold_registry {
        ProviderActivityStage::RegistrySnapshot
    } else {
        ProviderActivityStage::SelectorRead
    };
    let stage_observed = entered(&activity, expected_stage).await;

    // Keep the authenticated client open and send no selector or close_notify.
    // A read timeout cancels only the read future; it does not close this stream.
    let mut byte = [0; 1];
    let closure = timeout_at(close_deadline, client.read(&mut byte)).await;
    let elapsed = before_handshake.elapsed();
    let peer_closed = match &closure {
        Ok(Ok(0)) => true,
        Ok(Err(error)) => matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ),
        _ => false,
    };
    // Join the production network session before releasing the held log lock.
    let joined = timeout(Duration::from_secs(5), tasks.join_next()).await;
    if joined.is_err() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    let released = server.is_finished();
    let active_before_release = activity.snapshot().active_sessions;
    let logs_before_release = state_guard.logs(10).records;
    drop(state_guard);
    drop(registry_guard);
    drop(client);
    let mut drain = provider_events::Drain::default();
    if let Ok(Some(Ok(Some(batch)))) = joined {
        drain.enqueue(batch);
    } else {
        panic!(
            "PROVIDER_SESSION_RETAINED_BEHIND_EVENT_LOCK: rejected network task did not return its closed diagnostic batch"
        );
    }
    drain.flush(Some(&state)).await;
    let logs = state.read().await.logs(10).records;

    assert!(
        stage_observed,
        "authenticated server did not enter the expected stage"
    );
    assert!(
        released,
        "rejected network task must release its admission slot"
    );
    assert!(logs_before_release.is_empty());
    assert!(tasks.is_empty());
    assert_eq!(active_before_release, Some(0));
    assert_eq!(logs.len(), 1);
    assert_eq!(
        logs[0].event_code,
        if hold_registry {
            "CONTENT_PROVIDER_REGISTRY_TIMEOUT"
        } else {
            "CONTENT_PROVIDER_SELECTOR_TIMEOUT"
        }
    );
    assert!(logs[0].session_id.is_empty());
    assert!(
        elapsed >= Duration::from_secs(if hold_registry { 2 } else { 15 }),
        "the existing production deadline must elapse before rejecting the session"
    );
    assert!(
        peer_closed,
        "PROVIDER_STREAM_RETAINED_BEHIND_EVENT_LOCK: peer did not observe EOF/I/O before releasing the event lock: {closure:?}"
    );
}

#[tokio::test]
#[ignore = "requires explicit disposable loopback namespace; retains real 15-second selector deadline"]
async fn selector_timeout_closes_before_event_lock() {
    rejected_session_closes_before_event_lock(false).await;
}

#[tokio::test]
#[ignore = "requires explicit disposable loopback namespace; retains real 2-second registry deadline"]
async fn registry_timeout_closes_before_event_lock() {
    rejected_session_closes_before_event_lock(true).await;
}
