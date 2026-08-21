//! Privacy-preserving, process-local VOLPAROSSA metrics.
//!
//! The registry deliberately has no free-form labels. In particular, peer
//! identities, route identifiers, hostnames, destination addresses, and URLs
//! cannot enter the exported metric model. The HTTP endpoint refuses every
//! non-loopback bind address and has no push or external telemetry path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{
    fmt::Write as _,
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time,
};

const MAX_PEERS: usize = 100_000;
const MAX_CANDIDATES: usize = 10_000;
const MAX_ROUTE_CONTEXTS: usize = 4_096;
const MAX_PATHS: usize = 65_536;
const MAX_RESERVATIONS: usize = 100_000;
const MAX_RTT: Duration = Duration::from_secs(600);
const PARTS_PER_MILLION: u32 = 1_000_000;
const MAX_CONCURRENT_SCRAPES: usize = 16;
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HTTP_REQUEST_BYTES: usize = 1_024;

#[derive(Debug, Default)]
struct Inner {
    active_peers: AtomicUsize,
    candidate_pool: AtomicUsize,
    active_route_contexts: AtomicUsize,
    mptcp_subflows: AtomicUsize,
    mpquic_paths: AtomicUsize,
    relay_reservations: AtomicUsize,
    exit_reservations: AtomicUsize,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    rtt_microseconds: AtomicU64,
    loss_parts_per_million: AtomicU32,
    policy_denials: AtomicU64,
}

/// A cheap, thread-safe handle to a bounded aggregate registry.
#[derive(Clone, Debug, Default)]
pub struct MetricsRegistry {
    inner: Arc<Inner>,
}

impl MetricsRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of currently connected control-plane peers.
    ///
    /// # Errors
    ///
    /// Values above the defensive process bound are rejected.
    pub fn set_active_peers(&self, value: usize) -> Result<(), MetricsError> {
        set_bounded(&self.inner.active_peers, value, MAX_PEERS, "active peers")
    }

    /// Set the number of discovery candidates held in memory.
    ///
    /// # Errors
    ///
    /// Values above the defensive process bound are rejected.
    pub fn set_candidate_pool(&self, value: usize) -> Result<(), MetricsError> {
        set_bounded(
            &self.inner.candidate_pool,
            value,
            MAX_CANDIDATES,
            "candidate pool",
        )
    }

    /// Set the number of active local route contexts.
    ///
    /// # Errors
    ///
    /// Values above the defensive process bound are rejected.
    pub fn set_active_route_contexts(&self, value: usize) -> Result<(), MetricsError> {
        set_bounded(
            &self.inner.active_route_contexts,
            value,
            MAX_ROUTE_CONTEXTS,
            "active route contexts",
        )
    }

    /// Set the number of kernel-confirmed MPTCP subflows.
    ///
    /// # Errors
    ///
    /// Values above the defensive process bound are rejected.
    pub fn set_mptcp_subflows(&self, value: usize) -> Result<(), MetricsError> {
        set_bounded(
            &self.inner.mptcp_subflows,
            value,
            MAX_PATHS,
            "MPTCP subflows",
        )
    }

    /// Set the number of native-engine-confirmed Multipath QUIC paths.
    ///
    /// # Errors
    ///
    /// Values above the defensive process bound are rejected.
    pub fn set_mpquic_paths(&self, value: usize) -> Result<(), MetricsError> {
        set_bounded(
            &self.inner.mpquic_paths,
            value,
            MAX_PATHS,
            "Multipath QUIC paths",
        )
    }

    /// Set active relay allocations without exposing their identifiers.
    ///
    /// # Errors
    ///
    /// Values above the defensive process bound are rejected.
    pub fn set_relay_reservations(&self, value: usize) -> Result<(), MetricsError> {
        set_bounded(
            &self.inner.relay_reservations,
            value,
            MAX_RESERVATIONS,
            "relay reservations",
        )
    }

    /// Set active exit allocations without exposing their identifiers.
    ///
    /// # Errors
    ///
    /// Values above the defensive process bound are rejected.
    pub fn set_exit_reservations(&self, value: usize) -> Result<(), MetricsError> {
        set_bounded(
            &self.inner.exit_reservations,
            value,
            MAX_RESERVATIONS,
            "exit reservations",
        )
    }

    /// Add aggregate payload byte counts using saturating counters.
    pub fn record_throughput(&self, bytes_up: u64, bytes_down: u64) {
        saturating_add(&self.inner.bytes_up, bytes_up);
        saturating_add(&self.inner.bytes_down, bytes_down);
    }

    /// Store an aggregate path RTT sample.
    ///
    /// # Errors
    ///
    /// Samples above ten minutes are rejected as invalid telemetry.
    pub fn record_rtt(&self, rtt: Duration) -> Result<(), MetricsError> {
        if rtt > MAX_RTT {
            return Err(MetricsError::OutOfRange("RTT"));
        }
        let microseconds =
            u64::try_from(rtt.as_micros()).map_err(|_| MetricsError::OutOfRange("RTT"))?;
        self.inner
            .rtt_microseconds
            .store(microseconds, Ordering::Relaxed);
        Ok(())
    }

    /// Store aggregate packet loss in integer parts per million.
    ///
    /// # Errors
    ///
    /// Values above one million are rejected.
    pub fn record_loss_parts_per_million(&self, value: u32) -> Result<(), MetricsError> {
        if value > PARTS_PER_MILLION {
            return Err(MetricsError::OutOfRange("packet loss"));
        }
        self.inner
            .loss_parts_per_million
            .store(value, Ordering::Relaxed);
        Ok(())
    }

    /// Increment the aggregate policy-denial counter without recording a name.
    pub fn record_policy_denial(&self) {
        saturating_add(&self.inner.policy_denials, 1);
    }

    /// Read one internally consistent-enough aggregate snapshot.
    ///
    /// Metrics are observational only, so a concurrent update may appear in
    /// either adjacent scrape without affecting authorization or routing.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        let relay_reservations = self.inner.relay_reservations.load(Ordering::Relaxed);
        let exit_reservations = self.inner.exit_reservations.load(Ordering::Relaxed);
        MetricsSnapshot {
            active_peers: self.inner.active_peers.load(Ordering::Relaxed),
            candidate_pool: self.inner.candidate_pool.load(Ordering::Relaxed),
            active_route_contexts: self.inner.active_route_contexts.load(Ordering::Relaxed),
            mptcp_subflows: self.inner.mptcp_subflows.load(Ordering::Relaxed),
            mpquic_paths: self.inner.mpquic_paths.load(Ordering::Relaxed),
            active_reservations: relay_reservations.saturating_add(exit_reservations),
            bytes_up: self.inner.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.inner.bytes_down.load(Ordering::Relaxed),
            rtt_microseconds: self.inner.rtt_microseconds.load(Ordering::Relaxed),
            loss_parts_per_million: self.inner.loss_parts_per_million.load(Ordering::Relaxed),
            policy_denials: self.inner.policy_denials.load(Ordering::Relaxed),
        }
    }

    /// Render the fixed, label-free Prometheus text exposition.
    #[must_use]
    pub fn render(&self) -> String {
        self.snapshot().render()
    }
}

/// A label-free aggregate snapshot safe for local status display.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetricsSnapshot {
    /// Connected control-plane peers.
    pub active_peers: usize,
    /// Candidates retained by selection.
    pub candidate_pool: usize,
    /// Active route contexts.
    pub active_route_contexts: usize,
    /// Kernel-confirmed MPTCP subflows.
    pub mptcp_subflows: usize,
    /// Native-engine-confirmed Multipath QUIC paths.
    pub mpquic_paths: usize,
    /// Active relay and exit allocations.
    pub active_reservations: usize,
    /// Aggregate payload bytes sent toward exits or destinations.
    pub bytes_up: u64,
    /// Aggregate payload bytes returned toward clients.
    pub bytes_down: u64,
    /// Latest aggregate path RTT sample in microseconds.
    pub rtt_microseconds: u64,
    /// Latest aggregate packet-loss sample in parts per million.
    pub loss_parts_per_million: u32,
    /// Total policy requests denied without destination labels.
    pub policy_denials: u64,
}

impl MetricsSnapshot {
    fn render(self) -> String {
        let mut output = String::with_capacity(1_024);
        append_gauge(&mut output, "volparossa_active_peers", self.active_peers);
        append_gauge(
            &mut output,
            "volparossa_candidate_pool",
            self.candidate_pool,
        );
        append_gauge(
            &mut output,
            "volparossa_active_route_contexts",
            self.active_route_contexts,
        );
        append_gauge(
            &mut output,
            "volparossa_mptcp_subflows",
            self.mptcp_subflows,
        );
        append_gauge(&mut output, "volparossa_mpquic_paths", self.mpquic_paths);
        append_gauge(
            &mut output,
            "volparossa_active_reservations",
            self.active_reservations,
        );
        append_counter(
            &mut output,
            "volparossa_payload_bytes_up_total",
            self.bytes_up,
        );
        append_counter(
            &mut output,
            "volparossa_payload_bytes_down_total",
            self.bytes_down,
        );
        append_gauge(
            &mut output,
            "volparossa_path_rtt_microseconds",
            self.rtt_microseconds,
        );
        append_gauge(
            &mut output,
            "volparossa_path_loss_parts_per_million",
            self.loss_parts_per_million,
        );
        append_counter(
            &mut output,
            "volparossa_policy_denials_total",
            self.policy_denials,
        );
        output
    }
}

fn append_gauge(output: &mut String, name: &str, value: impl std::fmt::Display) {
    append_typed_metric(output, name, value, "gauge");
}

fn append_counter(output: &mut String, name: &str, value: impl std::fmt::Display) {
    append_typed_metric(output, name, value, "counter");
}

fn append_typed_metric(
    output: &mut String,
    name: &str,
    value: impl std::fmt::Display,
    metric_type: &str,
) {
    writeln!(output, "# TYPE {name} {metric_type}").expect("writing to String cannot fail");
    writeln!(output, "{name} {value}").expect("writing to String cannot fail");
}

fn set_bounded(
    metric: &AtomicUsize,
    value: usize,
    maximum: usize,
    name: &'static str,
) -> Result<(), MetricsError> {
    if value > maximum {
        return Err(MetricsError::OutOfRange(name));
    }
    metric.store(value, Ordering::Relaxed);
    Ok(())
}

fn saturating_add(metric: &AtomicU64, increment: u64) {
    let _result = metric.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(increment))
    });
}

/// A bound local HTTP listener for the label-free metrics endpoint.
pub struct LocalMetricsEndpoint {
    listener: TcpListener,
    registry: MetricsRegistry,
}

impl LocalMetricsEndpoint {
    /// Bind a metrics listener only when the requested address is loopback.
    ///
    /// Port zero is allowed so systemd or tests can request an ephemeral port.
    ///
    /// # Errors
    ///
    /// Non-loopback addresses are rejected before binding. Socket errors are
    /// returned unchanged.
    pub async fn bind(
        address: SocketAddr,
        registry: MetricsRegistry,
    ) -> Result<Self, MetricsError> {
        if !address.ip().is_loopback() {
            return Err(MetricsError::NonLocalBind);
        }
        let listener = TcpListener::bind(address).await?;
        Ok(Self { listener, registry })
    }

    /// Return the effective local address, including an assigned ephemeral port.
    ///
    /// # Errors
    ///
    /// Returns the listener's socket error when its address cannot be queried.
    pub fn local_addr(&self) -> Result<SocketAddr, MetricsError> {
        Ok(self.listener.local_addr()?)
    }

    /// Serve `/metrics` until the supplied shutdown future resolves.
    ///
    /// All other paths return HTTP 404. The response is fixed-format and never
    /// interpolates caller-controlled labels or strings.
    ///
    /// # Errors
    ///
    /// Returns a listener or HTTP server I/O error.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), MetricsError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_SCRAPES));
        let mut tasks = JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let (stream, _peer_address) = accepted?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let registry = self.registry.clone();
                    tasks.spawn(async move {
                        let outcome = time::timeout(
                            SCRAPE_TIMEOUT,
                            serve_one_scrape(stream, registry),
                        )
                        .await;
                        match outcome {
                            Ok(Ok(()) | Err(_)) | Err(_) => {}
                        }
                        drop(permit);
                    });
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        return Err(error.into());
                    }
                }
            }
        }
        while let Some(completed) = tasks.join_next().await {
            completed?;
        }
        Ok(())
    }
}

async fn serve_one_scrape(
    mut stream: TcpStream,
    registry: MetricsRegistry,
) -> Result<(), std::io::Error> {
    let mut request = Vec::with_capacity(256);
    let mut chunk = [0_u8; 256];
    loop {
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() == MAX_HTTP_REQUEST_BYTES {
            write_response(&mut stream, 400, "Bad Request", "").await?;
            return Ok(());
        }
        let remaining = MAX_HTTP_REQUEST_BYTES - request.len();
        let read_length = remaining.min(chunk.len());
        let count = stream.read(&mut chunk[..read_length]).await?;
        if count == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..count]);
    }

    let first_line_end = request
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(request.len());
    match &request[..first_line_end] {
        b"GET /metrics HTTP/1.1" | b"GET /metrics HTTP/1.0" => {
            let body = registry.render();
            write_response(&mut stream, 200, "OK", &body).await?;
        }
        _ => write_response(&mut stream, 404, "Not Found", "").await?,
    }
    stream.shutdown().await
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<(), std::io::Error> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await
}

/// Metrics validation and local endpoint errors.
#[derive(Debug, Error)]
pub enum MetricsError {
    /// A metric sample exceeded its fixed defensive bound.
    #[error("metric sample is out of range: {0}")]
    OutOfRange(&'static str),
    /// The endpoint was asked to listen beyond the local host.
    #[error("metrics endpoint may bind only to a loopback address")]
    NonLocalBind,
    /// A local socket operation failed.
    #[error("metrics endpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A bounded local connection task panicked or was cancelled.
    #[error("metrics endpoint task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        sync::oneshot,
    };

    use super::{LocalMetricsEndpoint, MetricsError, MetricsRegistry};

    #[test]
    fn registry_is_bounded_and_export_has_no_labels() {
        let registry = MetricsRegistry::new();
        registry.set_active_peers(7).unwrap();
        registry.set_candidate_pool(19).unwrap();
        registry.set_relay_reservations(2).unwrap();
        registry.set_exit_reservations(3).unwrap();
        registry.record_throughput(1_000, 2_000);
        registry.record_rtt(Duration::from_millis(12)).unwrap();
        registry.record_loss_parts_per_million(2_500).unwrap();
        registry.record_policy_denial();

        let rendered = registry.render();
        assert!(rendered.contains("volparossa_active_reservations 5\n"));
        assert!(rendered.contains("volparossa_payload_bytes_up_total 1000\n"));
        assert!(rendered.contains("# TYPE volparossa_payload_bytes_up_total counter\n"));
        assert!(rendered.contains("# TYPE volparossa_active_peers gauge\n"));
        assert!(!rendered.contains('{'));
        assert!(!rendered.contains("hostname"));
        assert!(registry.set_candidate_pool(10_001).is_err());
        assert!(registry.record_loss_parts_per_million(1_000_001).is_err());
    }

    #[tokio::test]
    async fn endpoint_refuses_external_bind_and_serves_loopback() {
        let registry = MetricsRegistry::new();
        registry.set_active_peers(3).unwrap();
        let external = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        assert!(matches!(
            LocalMetricsEndpoint::bind(external, registry.clone()).await,
            Err(MetricsError::NonLocalBind)
        ));

        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint = LocalMetricsEndpoint::bind(local, registry).await.unwrap();
        let address = endpoint.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(endpoint.serve(async move {
            let _ignored = shutdown_rx.await;
        }));

        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("volparossa_active_peers 3\n"));

        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
