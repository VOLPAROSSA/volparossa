//! Explicitly authorized guest evidence exchange, never private worker admission.
//!
//! A separate signed purpose reuses the protected provider framing without
//! interpreting public job RPCs as device authority. Reports identify hardware:
//! neither this service nor its local framing offers transcript/log export.

pub mod confirmation;
mod outcome;
mod transport;

pub use outcome::QuoteOutcome;
pub use transport::{
    QuoteChallenge, begin, exchange, exchange_outcome, read_outcome, read_request, read_response,
    write_outcome, write_request, write_response,
};

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, sleep_until, timeout, timeout_at},
};

use super::{
    ComputeError, EXCHANGE_SECONDS, FRAME_OVERHEAD,
    guest::{
        self, GuestCancellation, GuestError, GuestLimits, GuestQuoteSession, GuestSession,
        GuestSessionOwner, QuoteRequest,
    },
    protocol::{self, Kind, Purpose, Record},
};

/// Additive selector, independent of public compute selector five.
pub const SELECTOR_VERSION: u32 = 1;
/// Quote-only evidence on the same protected listener; no new destination authority.
pub const SELECTOR_OPERATION: u32 = 7;

/// Closed exchange failures, never firmware details, identifiers or raw I/O text.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum QuoteError {
    /// Unsupported or noncanonical message or configuration.
    #[error("invalid guest quote exchange")]
    Invalid,
    /// Signature, exact requester grant or current local authority failed.
    #[error("guest quote exchange not authorized")]
    Unauthorized,
    /// Original finite authority or challenge expired.
    #[error("guest quote exchange expired")]
    Expired,
    /// The process firmware permit or single owner slot is occupied/exhausted.
    #[error("guest quote exchange busy")]
    Busy,
    /// Fixed firmware collection or local lifecycle is unavailable.
    #[error("guest quote exchange unavailable")]
    Unavailable,
    /// The already supplied protected stream failed.
    #[error("guest quote exchange stream failed")]
    Io,
}

impl From<ComputeError> for QuoteError {
    fn from(value: ComputeError) -> Self {
        match value {
            ComputeError::Io(_) => Self::Io,
            ComputeError::Invalid => Self::Invalid,
            ComputeError::Authentication => Self::Unauthorized,
            ComputeError::Expired => Self::Expired,
            ComputeError::Entropy | ComputeError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<GuestError> for QuoteError {
    fn from(value: GuestError) -> Self {
        match value {
            GuestError::Configuration
            | GuestError::Encoding
            | GuestError::ReportBinding
            | GuestError::UnsupportedReport(_) => Self::Invalid,
            GuestError::Budget => Self::Busy,
            GuestError::Replay | GuestError::Cancelled => Self::Unauthorized,
            GuestError::Expired => Self::Expired,
            GuestError::Unavailable | GuestError::DeviceUnavailable | GuestError::Firmware => {
                Self::Unavailable
            }
        }
    }
}

/// Explicit owner-local device permission for one signing identity only.
/// No public challenge, signed peer identity or dataset implicitly creates this grant.
#[derive(Clone, Copy)]
pub struct QuoteGrant {
    /// Exact authenticated node key allowed to obtain identifying quote evidence.
    pub requester_key: [u8; 32],
    /// Finite owner lifetime/attempt budget; never an extension of a challenge.
    pub limits: GuestLimits,
}

/// Bounded local policy/liveness check; it must not open another network route.
pub type QuoteAuthorityFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), QuoteError>> + Send + 'a>>;

/// Required current runtime authority, without a permissive implementation/default.
pub trait QuoteAuthority: Send + Sync {
    /// Recheck the live service, explicit requester and current local policy.
    fn check(&self, requester: [u8; 32]) -> QuoteAuthorityFuture<'_>;
}

struct RetainedQuote {
    requester: [u8; 32],
    challenge: [u8; 32],
    quote: GuestQuoteSession,
}

#[allow(
    clippy::large_enum_variant,
    reason = "One bounded owned session; do not add a heap allocation to quote collection"
)]
enum Collection {
    Evidence(GuestQuoteSession),
    DeviceUnavailable(Instant),
}

struct Work {
    session: GuestSession,
    permit: OwnedSemaphorePermit,
    reply: oneshot::Sender<Result<GuestQuoteSession, GuestError>>,
    #[cfg(test)]
    source: Option<guest::TestReportSource>,
}

impl Work {
    fn collect(self) {
        let Self {
            session,
            permit,
            reply,
            #[cfg(test)]
            source,
        } = self;
        // The real worker owns this permit through actual return/unwind. Async
        // cancellation is not ioctl interruption, rollback or released capacity.
        #[cfg(test)]
        let result = match source {
            Some(source) => session.collect_source(guest::ReportSource::Fake(source)),
            None => session.collect_quote(),
        };
        #[cfg(not(test))]
        let result = session.collect_quote();
        drop(permit);
        // If the requester left, dropping the undelivered result erases its key.
        let _ = reply.send(result);
    }
}

/// One explicit quote attachment, coexisting with the public compute service.
/// No key access, task submission, lease renewal or private-input method exists.
pub struct QuoteService {
    confirmation: bool,
    signer: Arc<SigningKey>,
    requester: [u8; 32],
    owner: GuestSessionOwner,
    firmware: Arc<Semaphore>,
    authority: Arc<dyn QuoteAuthority>,
    // 0 constructed, 1 supervised, 2 permanently deactivated.
    lifecycle: AtomicU8,
    retained: Mutex<Option<RetainedQuote>>,
    changed: Notify,
    work: mpsc::Sender<Work>,
    receiver: Mutex<Option<mpsc::Receiver<Work>>>,
    #[cfg(test)]
    source: Mutex<Option<guest::TestReportSource>>,
}

impl QuoteService {
    /// Construct an inactive attachment, without opening firmware or spawning work.
    /// The caller supplies its process-long one-permit semaphore, shared across
    /// detach/reattach, not a fresh semaphore for each request or attachment.
    ///
    /// # Errors
    /// Rejects invalid requester identity, limits or an obviously unbounded gate.
    pub fn new(
        signer: Arc<SigningKey>,
        grant: QuoteGrant,
        firmware: Arc<Semaphore>,
        authority: Arc<dyn QuoteAuthority>,
    ) -> Result<Arc<Self>, QuoteError> {
        Self::construct(signer, grant, firmware, authority, false)
    }

    /// Explicitly authorize the separate quote/key-confirmation profile.
    /// This admits only one random probe, never private input or execution.
    /// The original quote-only constructor does not enable this profile.
    ///
    /// # Errors
    /// Uses the same exact requester, finite grant and process firmware permit.
    pub fn new_confirmation(
        signer: Arc<SigningKey>,
        grant: QuoteGrant,
        firmware: Arc<Semaphore>,
        authority: Arc<dyn QuoteAuthority>,
    ) -> Result<Arc<Self>, QuoteError> {
        Self::construct(signer, grant, firmware, authority, true)
    }

    fn construct(
        signer: Arc<SigningKey>,
        grant: QuoteGrant,
        firmware: Arc<Semaphore>,
        authority: Arc<dyn QuoteAuthority>,
        confirmation: bool,
    ) -> Result<Arc<Self>, QuoteError> {
        if grant.requester_key == [0; 32]
            || VerifyingKey::from_bytes(&grant.requester_key).is_err()
            || firmware.available_permits() > 1
        {
            return Err(QuoteError::Invalid);
        }
        let owner = GuestSessionOwner::new(grant.limits)?;
        let (work, receiver) = mpsc::channel(1);
        Ok(Arc::new(Self {
            confirmation,
            signer,
            requester: grant.requester_key,
            owner,
            firmware,
            authority,
            lifecycle: AtomicU8::new(0),
            retained: Mutex::new(None),
            changed: Notify::new(),
            work,
            receiver: Mutex::new(Some(receiver)),
            #[cfg(test)]
            source: Mutex::new(None),
        }))
    }

    /// Whether the finite attachment is supervised and locally unexpired.
    /// This does not replace the asynchronous authority check before each quote.
    pub fn is_active(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) == 1 && self.owner.check_live().is_ok()
    }

    /// Revoke current/future collection and erase retained/in-flight keys now.
    /// A still-running blocking ioctl retains its real process permit until return.
    pub fn deactivate(&self) {
        self.lifecycle.store(2, Ordering::Release);
        self.owner.cancel();
        drop(
            self.retained
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
        self.changed.notify_one();
    }

    /// Arm exactly one caller-owned, joinable expiry/worker supervisor.
    /// Even dropping this returned future before its first poll revokes the service.
    /// The owner must retain its task handle and stop it on attachment shutdown.
    ///
    /// # Errors
    /// Rejects repeated activation, deactivated state or poisoned internal state.
    pub fn supervise(
        self: Arc<Self>,
    ) -> Result<impl Future<Output = ()> + Send + 'static, QuoteError> {
        let receiver = self
            .receiver
            .lock()
            .map_err(|_| QuoteError::Unavailable)?
            .take()
            .ok_or(QuoteError::Unavailable)?;
        self.lifecycle
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| QuoteError::Unavailable)?;
        let guard = ServiceGuard(self);
        Ok(async move {
            guard.0.run(receiver).await;
        })
    }

    async fn run(&self, mut receiver: mpsc::Receiver<Work>) {
        let mut worker: Option<JoinHandle<()>> = None;
        let mut policy_due = Instant::now();
        while self.is_active() {
            let lease_deadline = {
                let Ok(mut retained) = self.retained.lock() else {
                    break;
                };
                if retained.as_ref().is_some_and(|lease| {
                    lease.requester != self.requester
                        || lease.challenge != lease.quote.challenge_binding()
                        || lease.quote.response().is_err()
                        || Instant::now() >= Instant::from_std(lease.quote.deadline())
                }) {
                    drop(retained.take());
                }
                retained.as_ref().map_or_else(
                    || Instant::from_std(self.owner.deadline()),
                    |lease| Instant::from_std(lease.quote.deadline()),
                )
            };
            let checking = Instant::now() >= policy_due;
            // Policy-lock contention must not delay original expiry or shutdown.
            let wake = lease_deadline.min(Instant::from_std(self.owner.deadline()));
            let wake = if checking { wake } else { wake.min(policy_due) };
            tokio::select! {
                biased;
                () = sleep_until(wake) => {}
                () = self.changed.notified() => {}
                result = self.authority.check(self.requester), if checking => {
                    if result.is_err() { break; }
                    policy_due = Instant::now() + Duration::from_secs(1);
                }
                Some(work) = receiver.recv(), if worker.is_none() => {
                    if self.is_active() && !work.reply.is_closed() {
                        worker = Some(tokio::task::spawn_blocking(move || work.collect()));
                    }
                }
                () = async { if let Some(task) = worker.as_mut() { let _ = task.await; } }, if worker.is_some() => {
                    worker = None;
                }
            }
        }
        self.deactivate();
        receiver.close();
        while let Ok(work) = receiver.try_recv() {
            drop(work);
        }
        // A graceful supervisor shutdown observes actual worker completion. An
        // aborted supervisor still cannot free the worker-owned permit/session.
        if let Some(worker) = worker {
            let _ = worker.await;
        }
    }

    async fn authorize(&self, requester: [u8; 32]) -> Result<(), QuoteError> {
        if requester != self.requester {
            return Err(QuoteError::Unauthorized);
        }
        if !self.is_active() {
            return Err(QuoteError::Unavailable);
        }
        self.authority.check(requester).await?;
        if !self.is_active() {
            return Err(QuoteError::Unavailable);
        }
        Ok(())
    }

    #[cfg(test)]
    async fn collect(
        &self,
        request: QuoteRequest,
    ) -> Result<(GuestQuoteSession, CancelGuard), QuoteError> {
        match self.collect_outcome(request).await? {
            (Collection::Evidence(quote), guard) => Ok((quote, guard)),
            (Collection::DeviceUnavailable(_), _) => Err(QuoteError::Unavailable),
        }
    }

    async fn collect_outcome(
        &self,
        request: QuoteRequest,
    ) -> Result<(Collection, CancelGuard), QuoteError> {
        let permit = Arc::clone(&self.firmware)
            .try_acquire_owned()
            .map_err(|_| QuoteError::Busy)?;
        let session = self.owner.begin(request)?;
        // Construct cancellation before any asynchronous handoff or spawn.
        let guard = CancelGuard(Some(session.cancellation()));
        let deadline = Instant::from_std(session.deadline());
        let (reply, response) = oneshot::channel();
        let work = Work {
            session,
            permit,
            reply,
            #[cfg(test)]
            source: self
                .source
                .lock()
                .map_err(|_| QuoteError::Unavailable)?
                .take(),
        };
        self.work.try_send(work).map_err(|_| QuoteError::Busy)?;
        let result = timeout_at(deadline, response)
            .await
            .map_err(|_| QuoteError::Expired)?
            .map_err(|_| QuoteError::Unavailable)?;
        match result {
            Ok(quote) => {
                quote.response()?;
                Ok((Collection::Evidence(quote), guard))
            }
            Err(GuestError::DeviceUnavailable) => {
                self.owner.check_live()?;
                if Instant::now() >= deadline {
                    return Err(QuoteError::Expired);
                }
                Ok((Collection::DeviceUnavailable(deadline), guard))
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn device_unavailable<S>(
        &self,
        stream: &mut S,
        challenge: &Record,
        signed_request: &Record,
        request: &QuoteRequest,
        deadline: Instant,
    ) -> Result<(), QuoteError>
    where
        S: AsyncWrite + Unpin,
    {
        // This path exists only after the real worker returned DeviceUnavailable.
        // Recheck authority and both original clocks; no key/session is retained.
        self.authorize(signed_request.sender()).await?;
        request.check_time(protocol::now()?)?;
        if Instant::now() >= deadline {
            return Err(QuoteError::Expired);
        }
        let reply = Record::reply(
            &self.signer,
            challenge,
            Sha256::digest(signed_request.encode()).into(),
            outcome::encode(&QuoteOutcome::DeviceUnavailable, request)?,
            protocol::now()?,
        )?;
        timeout_at(
            deadline,
            protocol::write(
                stream,
                &reply.encode(),
                guest::MAX_QUOTE_RESPONSE_BYTES + FRAME_OVERHEAD,
            ),
        )
        .await
        .map_err(|_| QuoteError::Expired)??;
        self.authorize(signed_request.sender()).await?;
        request.check_time(protocol::now()?)?;
        if Instant::now() >= deadline {
            return Err(QuoteError::Expired);
        }
        Ok(())
    }

    /// Serve one caller-authenticated quote on an already protected stream.
    /// Successful delivery retains its real key only until its original deadline.
    ///
    /// # Errors
    /// Rejects wrong purpose/requester, stale authority, occupied capacity, invalid
    /// firmware binding or stream failure. No response implies task admission.
    pub async fn serve<S>(&self, stream: &mut S) -> Result<(), QuoteError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if self.confirmation {
            return Err(QuoteError::Unauthorized);
        }
        timeout(Duration::from_secs(EXCHANGE_SECONDS), async {
            if !self.is_active() {
                return Err(QuoteError::Unavailable);
            }
            let challenge =
                Record::challenge_for(&self.signer, protocol::now()?, Purpose::QuoteV1)?;
            protocol::write(stream, &challenge.encode(), FRAME_OVERHEAD).await?;
            let bytes =
                protocol::read(stream, guest::MAX_QUOTE_REQUEST_BYTES + FRAME_OVERHEAD).await?;
            let request =
                Record::decode_for(&bytes, Kind::Request, protocol::now()?, Purpose::QuoteV1)?;
            request.matches_challenge(&challenge)?;
            let requester = request.sender();
            self.authorize(requester).await?;
            if protocol::now()? >= request.expires() {
                return Err(QuoteError::Expired);
            }
            let payload = QuoteRequest::decode(request.payload())?;
            let (collected, mut guard) = self
                .collect_outcome(QuoteRequest::decode(request.payload())?)
                .await?;
            let quote = match collected {
                Collection::Evidence(quote) => quote,
                Collection::DeviceUnavailable(deadline) => {
                    return self
                        .device_unavailable(stream, &challenge, &request, &payload, deadline)
                        .await;
                }
            };
            self.authorize(requester).await?;
            let response = quote.response()?.encode();
            let reply = Record::reply(
                &self.signer,
                &challenge,
                Sha256::digest(&bytes).into(),
                response,
                protocol::now()?,
            )?;
            // Keep both the real session and cancellation guard through the write.
            timeout_at(
                Instant::from_std(quote.deadline()),
                protocol::write(
                    stream,
                    &reply.encode(),
                    guest::MAX_QUOTE_RESPONSE_BYTES + FRAME_OVERHEAD,
                ),
            )
            .await
            .map_err(|_| QuoteError::Expired)??;
            self.authorize(requester).await?;
            quote.response()?;
            let mut retained = self.retained.lock().map_err(|_| QuoteError::Unavailable)?;
            if !self.is_active() || retained.is_some() {
                return Err(QuoteError::Unavailable);
            }
            *retained = Some(RetainedQuote {
                requester,
                challenge: quote.challenge_binding(),
                quote,
            });
            drop(guard.0.take());
            self.changed.notify_one();
            Ok(())
        })
        .await
        .map_err(|_| QuoteError::Expired)?
    }
}

impl Drop for QuoteService {
    fn drop(&mut self) {
        self.deactivate();
    }
}

struct ServiceGuard(Arc<QuoteService>);
impl Drop for ServiceGuard {
    fn drop(&mut self) {
        self.0.deactivate();
    }
}

struct CancelGuard(Option<GuestCancellation>);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Some(cancellation) = self.0.take() {
            cancellation.cancel();
        }
    }
}

#[cfg(test)]
mod outcome_tests;

#[cfg(test)]
mod tests;
