//! Private inherited-pipe adapter; authorization remains with the existing Exit callers.
//! One owned child retains its native context for bounded, related proof queries.
//! No listener, OS fallback, persistent query store or new UID exception exists.

mod session;

use std::{
    fs,
    os::unix::fs::MetadataExt,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    process::{Child, Command},
    sync::{Semaphore, oneshot},
    time::{Instant, timeout_at},
};

use super::{DnsAnswerSource, DnsQuestion, DnsResolverError, ValidatedDnsAnswer, proof};
use session::Session;

const EXECUTABLE: &str = "/usr/libexec/volparossa-dns-worker";
const CLEANUP_RESERVE: Duration = Duration::from_millis(500);

pub(super) fn assets_installed() -> bool {
    [
        (EXECUTABLE, true),
        ("/usr/share/dns/root.key", false),
        ("/usr/share/dns/root.hints", false),
    ]
    .into_iter()
    .all(|(path, executable)| {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && if executable {
                    metadata.mode() & 0o111 != 0
                } else {
                    metadata.mode() & 0o444 != 0
                }
        })
    })
}

pub(super) struct PrivateResolution {
    pub fallback: ValidatedDnsAnswer,
    pub proof: Option<proof::ValidatedProof>,
}

type Answer = Result<PrivateResolution, DnsResolverError>;

struct State {
    permits: Arc<Semaphore>,
    quarantined: AtomicBool,
}

/// Shared process bound; native caches do not survive this one resolution operation.
#[derive(Clone)]
pub(super) struct PrivateUnbound(Arc<State>);

impl PrivateUnbound {
    pub(super) fn new() -> Self {
        Self(Arc::new(State {
            permits: Arc::new(Semaphore::new(2)),
            quarantined: AtomicBool::new(false),
        }))
    }

    pub(super) async fn resolve(
        &self,
        question: &DnsQuestion,
        deadline: Instant,
        collect_proof: bool,
    ) -> Answer {
        if self.0.quarantined.load(Ordering::Acquire) {
            return Err(DnsResolverError::CleanupUnconfirmed);
        }
        if deadline.saturating_duration_since(Instant::now()) <= CLEANUP_RESERVE {
            return Err(DnsResolverError::Unavailable);
        }
        let permit = Arc::clone(&self.0.permits)
            .try_acquire_owned()
            .map_err(|_| DnsResolverError::Unavailable)?;
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| DnsResolverError::Unavailable)?;
        let question = question.clone();
        let state = Arc::clone(&self.0);
        let (mut reply, result) = oneshot::channel();
        // This affine owner outlives caller cancellation and retains the exact
        // Child plus slot until reaped, including all supplemental proof queries.
        tokio::spawn(async move {
            let mut command = Command::new(EXECUTABLE);
            command
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            let answer = match command.spawn() {
                Ok(mut child) => {
                    match supervise(
                        &mut child,
                        &question,
                        nonce,
                        deadline,
                        collect_proof,
                        &mut reply,
                    )
                    .await
                    {
                        Err(DnsResolverError::CleanupUnconfirmed) => {
                            state.quarantined.store(true, Ordering::Release);
                            let _ = reply.send(Err(DnsResolverError::CleanupUnconfirmed));
                            while child.wait().await.is_err() {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                            drop(permit);
                            return;
                        }
                        result => result,
                    }
                }
                Err(_) => Err(DnsResolverError::Unavailable),
            };
            drop(permit);
            let _ = reply.send(answer);
        });
        result.await.map_err(|_| DnsResolverError::Unavailable)?
    }
}

async fn supervise(
    child: &mut Child,
    question: &DnsQuestion,
    nonce: [u8; 16],
    deadline: Instant,
    collect_proof: bool,
    reply: &mut oneshot::Sender<Answer>,
) -> Answer {
    let session = match Session::new(child, question.clone(), nonce) {
        Ok(session) => Arc::new(session),
        Err(error) => {
            reap(child, deadline).await?;
            return Err(error);
        }
    };
    let mut fallback = None;
    let mut proof_timed_out = false;
    let (result, timed_out) = {
        let exchange = async {
            let primary = session.request(question.query()?).await?;
            let answer = primary.answer.ok_or(DnsResolverError::InvalidProof)?;
            fallback = Some(answer.clone());
            let proof = if collect_proof
                && answer.source()
                    == (DnsAnswerSource::PrivateUnbound {
                        dnssec_secure: true,
                    }) {
                if let Some(raw) = primary.raw {
                    let source: Arc<dyn proof::EvidenceSource> = session.clone();
                    let bound =
                        (deadline - CLEANUP_RESERVE).min(Instant::now() + super::COLLECT_TIMEOUT);
                    if let Ok(result) =
                        timeout_at(bound, proof::collect_private(question, source, raw)).await
                    {
                        result.ok()
                    } else {
                        proof_timed_out = true;
                        return Err(DnsResolverError::Unavailable);
                    }
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(error) = session.integrity_error() {
                return Err(error);
            }
            session.finish().await?;
            let status = child
                .wait()
                .await
                .map_err(|_| DnsResolverError::Unavailable)?;
            if !status.success() {
                return Err(DnsResolverError::Unavailable);
            }
            Ok(PrivateResolution {
                fallback: answer,
                proof,
            })
        };
        tokio::select! {
            () = reply.closed() => (Err(DnsResolverError::Unavailable), false),
            result = timeout_at(deadline - CLEANUP_RESERVE, exchange) => {
                match result {
                    Ok(answer) => (answer, false),
                    Err(_) => (Err(DnsResolverError::Unavailable), true),
                }
            }
        }
    };
    if result.is_ok() {
        return result;
    }
    reap(child, deadline).await?;
    // Optional collection must not replace an already usable native answer with
    // a new timeout. Only a deadline (never malformed protocol/bogus data) can
    // recover it, and only after the exact child has been confirmed reaped.
    if (timed_out || proof_timed_out) && session.integrity_error().is_none() && !reply.is_closed() {
        if let Some(fallback) = fallback.filter(|answer| answer.ttl_seconds() > 0) {
            return Ok(PrivateResolution {
                fallback,
                proof: None,
            });
        }
    }
    result
}

async fn reap(child: &mut Child, deadline: Instant) -> Result<(), DnsResolverError> {
    let _ = child.start_kill();
    if matches!(timeout_at(deadline, child.wait()).await, Ok(Ok(_))) {
        Ok(())
    } else {
        Err(DnsResolverError::CleanupUnconfirmed)
    }
}

#[cfg(test)]
mod tests;
