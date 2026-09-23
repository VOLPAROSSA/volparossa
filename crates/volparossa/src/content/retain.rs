//! Explicit owner maintenance of one original public publication. Discovery is a
//! hint; only fresh, signed custody exchanges establish observed remote copies.

mod state;
#[cfg(test)]
mod tests;

use std::{
    collections::BTreeSet,
    io::Read as _,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::signal::unix::{Signal, SignalKind, signal};
use volparossa_content::{
    MAX_MANIFEST_BYTES,
    provider::custody::{CustodyOperation, CustodyReceipt, CustodyState},
};
use volparossa_local_control::{
    ContentCustodyDiscoverRequest, control_request::Operation, control_response::Payload,
};

use super::{Limits, custody, now_seconds, open_regular, private_message::Unlock};
use state::{Observation, State, Store};

// Bounded evidence retained by this one owner, not a global network/connection cap.
const MAX_PROVIDERS: usize = 64;
const DISCOVERY_PROVIDERS: u32 = 16;
const OPERATION_SECONDS: u64 = 600;

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Exact existing public manifest signed by this node's own publisher identity.
    #[arg(long)]
    manifest: PathBuf,
    /// Existing complete source cache; not sent to the agent or any peer as a path.
    #[arg(long)]
    cache: PathBuf,
    /// Existing encrypted identity belonging to the original publication's publisher.
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    passphrase_file: PathBuf,
    /// Desired observed remote copies for this object, within one discovery batch.
    #[arg(long, default_value_t=2, value_parser=clap::value_parser!(u16).range(1..=16))]
    copies: u16,
    /// New private owner directory; use --resume only with exactly the same enrollment.
    #[arg(long)]
    directory: PathBuf,
    /// Finite owner lifetime, also capped by the original signed publication expiry.
    #[arg(long, default_value_t=3600, value_parser=clap::value_parser!(u32).range(1..=604_800))]
    max_seconds: u32,
    #[arg(long, default_value_t=30, value_parser=clap::value_parser!(u16).range(1..=3600))]
    poll_seconds: u16,
    /// Full object bytes reserved before every deposit attempt, including failed uploads.
    #[arg(long, value_parser=clap::value_parser!(u64).range(1..))]
    max_upload_bytes: u64,
    #[arg(long)]
    execute: bool,
    #[arg(long, requires = "execute")]
    resume: bool,
    #[command(flatten)]
    limits: Limits,
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn selection(args: &Options, socket: &Path) -> Result<Value> {
    let absolute = |path: &Path| -> Result<PathBuf> { Ok(std::path::absolute(path)?) };
    Ok(
        json!({"version":1,"scope":"one_original_public_object_owner",
        "manifest":absolute(&args.manifest)?,"cache":absolute(&args.cache)?,
        "identity":absolute(&args.identity)?,"passphrase_file":absolute(&args.passphrase_file)?,
        "directory":absolute(&args.directory)?,"socket":absolute(socket)?,
        "copies":args.copies,"max_seconds":args.max_seconds,"poll_seconds":args.poll_seconds,
        "max_upload_bytes":args.max_upload_bytes,"limits":args.limits.configuration(),
        "discovery_batch":DISCOVERY_PROVIDERS,"operation_seconds":OPERATION_SECONDS,
        "future_availability_guaranteed":false,"maintenance_while_owner_offline":false}),
    )
}

struct Controller<'a> {
    args: &'a Options,
    socket: &'a Path,
    original: Vec<u8>,
    owner: custody::RetentionOwner,
    store: Store,
    state: State,
    recheck: Vec<String>,
    interrupt: Signal,
    terminate: Signal,
    stopped: bool,
}

pub(crate) async fn run(args: &Options, socket: &Path) -> Result<()> {
    let selected = selection(args, socket)?;
    if !args.execute {
        println!(
            "{}",
            json!({"operation":"content_retain_preview","selection":selected,
            "network_io":false,"keys_unlocked":false,"automatic_provider_selection":true})
        );
        return Ok(());
    }
    let root = std::path::absolute(&args.directory)?;
    let cache = std::fs::canonicalize(&args.cache)?;
    ensure!(
        cache != root && !cache.starts_with(&root) && !root.starts_with(&cache),
        "content_retain_cache_state_overlap"
    );
    let store = Store::open(&root, args.resume)?;
    let enrollment = serde_json::to_vec(&selected)?;
    let mut original = Vec::new();
    open_regular(&args.manifest, MAX_MANIFEST_BYTES as u64)?
        .take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut original)?;
    ensure!(
        original.len() <= MAX_MANIFEST_BYTES,
        "content_retain_manifest_bound"
    );
    let signer = Unlock::explicit(args.identity.clone(), args.passphrase_file.clone()).signer()?;
    let at = now_seconds()?;
    let existing = if args.resume {
        ensure!(
            store.read("enrollment.json", 16 * 1024)? == enrollment
                && store.read("original.manifest", MAX_MANIFEST_BYTES)? == original,
            "content_retain_enrollment_changed"
        );
        Some(store.load()?)
    } else {
        None
    };
    // Historical verification permits an honest expired resume summary, never a new lease.
    let owner = custody::RetentionOwner::new(
        signer,
        &original,
        existing.as_ref().map_or(at, |state| state.started_at),
    )?;
    let expires = owner.manifest().validity().expires;
    let mut state = existing.unwrap_or(State::new(&enrollment, at, args.max_seconds, expires)?);
    state.validate(
        &enrollment,
        args.max_seconds,
        expires,
        args.max_upload_bytes,
    )?;
    verify_history(&state, &original)?;
    if !args.resume {
        store.write("enrollment.json", &enrollment, false)?;
        store.write("original.manifest", &original, false)?;
    }
    if let Some(pending) = state.pending.take() {
        state.observations.insert(
            pending.provider_key,
            Observation {
                sequence: pending.sequence,
                operation: pending.operation,
                checked_at: at,
                outcome: "interrupted".into(),
                original: None,
            },
        );
    }
    let recheck = recheck_candidates(&state);
    state.confirmed_holders.clear();
    state.last_observed = at;
    let mut controller = Controller {
        args,
        socket,
        original,
        owner,
        store,
        state,
        recheck,
        interrupt: signal(SignalKind::interrupt())?,
        terminate: signal(SignalKind::terminate())?,
        stopped: false,
    };
    controller.checkpoint()?;
    controller.drive().await?;
    println!(
        "{}",
        json!({"operation":"content_retain","directory":root,
        "manifest_id":hex::encode(controller.owner.manifest().manifest_id()),
        "completed_polls":controller.state.completed_polls,"last_outcome":controller.state.last_outcome,
        "confirmed_holders":controller.state.confirmed_holders,
        "uploads_reserved_bytes":controller.state.uploads_reserved_bytes,
        "deadline_unix_seconds":controller.state.deadline,
        "future_availability_guaranteed":false,"maintenance_while_owner_offline":false})
    );
    Ok(())
}

fn verify_history(state: &State, original: &[u8]) -> Result<()> {
    for (key, observation) in &state.observations {
        let provider = super::parse_publisher_key(key).map_err(anyhow::Error::msg)?;
        if let Some(exchange) = &observation.original {
            ensure!(
                exchange.verified_at <= observation.checked_at,
                "content_retain_observation_time"
            );
            let operation = if observation.operation == "inspect" {
                CustodyOperation::Inspect
            } else {
                CustodyOperation::Deposit
            };
            let receipt = exchange.verify(&provider, original, operation)?;
            ensure!(
                observation.outcome != "complete"
                    || exchange.handoff_complete && receipt.state() == CustodyState::Complete,
                "content_retain_false_confirmation"
            );
        } else {
            ensure!(
                observation.outcome != "complete",
                "content_retain_missing_receipt"
            );
        }
    }
    Ok(())
}

// Original observations only select where to ask again. Bounded discovery may
// omit an existing holder; absence from that batch is not a custody response.
fn recheck_candidates(state: &State) -> Vec<String> {
    state
        .observations
        .iter()
        .filter(|(_, observation)| {
            matches!(observation.outcome.as_str(), "complete" | "interrupted")
        })
        .map(|(provider, _)| provider.clone())
        .collect()
}

impl Controller<'_> {
    fn checkpoint(&self) -> Result<()> {
        self.store.checkpoint(
            &self.state,
            &hex::encode(self.owner.manifest().manifest_id()),
            self.owner.manifest().validity().expires,
        )
    }

    fn remaining(&self) -> Result<Duration> {
        Ok(Duration::from_secs(
            self.state
                .deadline
                .saturating_sub(now_seconds()?)
                .min(OPERATION_SECONDS),
        ))
    }

    async fn discover(&mut self) -> Result<Vec<String>> {
        let request = ContentCustodyDiscoverRequest {
            manifest: self.original.clone(),
            publisher_key: self.owner.manifest().publisher().to_vec(),
            max_providers: DISCOVERY_PROVIDERS,
        };
        let remaining = self.remaining()?;
        let response = tokio::select! {
            () = tokio::time::sleep(remaining) => return Ok(Vec::new()),
            _ = self.interrupt.recv() => {self.stopped=true; return Ok(Vec::new())},
            _ = self.terminate.recv() => {self.stopped=true; return Ok(Vec::new())},
            result = crate::control::request(self.socket, Operation::ContentCustodyDiscover(request)) => result,
        };
        let Ok(response) = response else {
            return Ok(Vec::new());
        };
        let Some(Payload::ContentCustodyDiscovered(found)) = response.payload else {
            anyhow::bail!("content_retain_discovery_payload");
        };
        ensure!(
            found.providers.len() <= DISCOVERY_PROVIDERS as usize,
            "content_retain_discovery_bound"
        );
        let at = now_seconds()?;
        let mut candidates = BTreeSet::new();
        for provider in found.providers {
            let key: [u8; 32] = provider
                .provider_key
                .try_into()
                .map_err(|_| anyhow::anyhow!("content_retain_provider_key"))?;
            VerifyingKey::from_bytes(&key)?;
            if key != *self.owner.manifest().publisher() && provider.offer_expires_unix_seconds > at
            {
                candidates.insert(hex::encode(key));
            }
        }
        let mut candidates: Vec<_> = candidates.into_iter().collect();
        // Explore candidates not recently attempted before reusing failed/missing ones.
        candidates.sort_by_key(|key| {
            self.state
                .observations
                .get(key)
                .map_or(0, |record| record.sequence)
        });
        Ok(candidates)
    }

    async fn attempt(&mut self, key: &str, deposit: bool) -> Result<Option<CustodyState>> {
        let started = now_seconds()?;
        if started >= self.state.deadline {
            return Ok(None);
        }
        let operation = if deposit { "deposit" } else { "inspect" };
        let bytes = if deposit {
            self.owner.manifest().length()
        } else {
            0
        };
        self.make_room(key)?;
        if !self.state.reserve(
            key.into(),
            operation,
            bytes,
            self.args.max_upload_bytes,
            started,
        )? {
            self.state.last_outcome = "budget_exhausted".into();
            self.checkpoint()?;
            return Ok(None);
        }
        self.checkpoint()?; // Durable upload reservation and pending intent precede any I/O.
        let provider = super::parse_publisher_key(key).map_err(anyhow::Error::msg)?;
        let source = if deposit {
            Some((self.args.cache.as_path(), self.args.limits.cache_limits()?))
        } else {
            None
        };
        let mut original = None;
        let remaining = self.remaining()?;
        let result = tokio::select! {
            () = tokio::time::sleep(remaining) => Err(anyhow::anyhow!("content_retain_attempt_timeout")),
            _ = self.interrupt.recv() => {self.stopped=true; Err(anyhow::anyhow!("content_retain_cancelled"))},
            _ = self.terminate.recv() => {self.stopped=true; Err(anyhow::anyhow!("content_retain_cancelled"))},
            result = self.owner.exchange(self.socket, &provider, source, &mut original) => result,
        };
        self.owner.release_source();
        let at = now_seconds()?;
        let observed = original
            .as_ref()
            .map(|exchange| {
                exchange.verify(
                    &provider,
                    &self.original,
                    if deposit {
                        CustodyOperation::Deposit
                    } else {
                        CustodyOperation::Inspect
                    },
                )
            })
            .transpose()?;
        let current = if result.is_ok() {
            observed.as_ref().map(CustodyReceipt::state)
        } else {
            None
        };
        let outcome = match current {
            Some(CustodyState::Complete) => "complete",
            Some(CustodyState::Missing) => "missing",
            None => "unavailable",
        };
        self.state.observations.insert(
            key.into(),
            Observation {
                sequence: self.state.attempt_sequence,
                operation: operation.into(),
                checked_at: at,
                outcome: outcome.into(),
                original,
            },
        );
        self.state.pending = None;
        self.state.last_observed = at;
        if current == Some(CustodyState::Complete) {
            self.state.confirmed_holders.push(key.into());
        }
        self.checkpoint()?;
        Ok(current)
    }

    fn make_room(&mut self, key: &str) -> Result<()> {
        if !self.state.observations.contains_key(key)
            && self.state.observations.len() == MAX_PROVIDERS
        {
            let oldest = self
                .state
                .observations
                .iter()
                .filter(|(key, _)| !self.state.confirmed_holders.contains(key))
                .min_by_key(|(_, record)| record.sequence)
                .map(|(key, _)| key.clone())
                .context("content_retain_observation_limit")?;
            self.state.observations.remove(&oldest);
        }
        Ok(())
    }

    async fn poll(&mut self) -> Result<()> {
        let mut previous = std::mem::take(&mut self.recheck);
        previous.extend(self.state.confirmed_holders.clone());
        self.state.confirmed_holders.clear();
        self.state.last_outcome = "polling".into();
        self.checkpoint()?;
        let candidates = self.discover().await?;
        let mut visited = BTreeSet::new();
        for key in previous.into_iter().chain(candidates) {
            if self.stopped
                || now_seconds()? >= self.state.deadline
                || self.state.confirmed_holders.len() >= usize::from(self.args.copies)
            {
                break;
            }
            if !visited.insert(key.clone()) {
                continue;
            }
            if self.attempt(&key, false).await? == Some(CustodyState::Missing)
                && !self.stopped
                && now_seconds()? < self.state.deadline
            {
                self.attempt(&key, true).await?;
            }
        }
        if self.stopped || now_seconds()? >= self.state.deadline {
            return Ok(());
        }
        self.state.completed_polls = self
            .state
            .completed_polls
            .checked_add(1)
            .context("content_retain_poll_counter")?;
        self.state.last_observed = now_seconds()?;
        self.state.last_outcome =
            if self.state.confirmed_holders.len() >= usize::from(self.args.copies) {
                "maintained"
            } else if self.state.last_outcome == "budget_exhausted" {
                "budget_exhausted"
            } else {
                "degraded"
            }
            .into();
        self.checkpoint()
    }

    async fn drive(&mut self) -> Result<()> {
        while !self.stopped && now_seconds()? < self.state.deadline {
            self.poll().await?;
            if self.stopped {
                break;
            }
            let seconds = u64::from(self.args.poll_seconds)
                .min(self.state.deadline.saturating_sub(now_seconds()?));
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(seconds)) => {},
                _ = self.interrupt.recv() => {self.stopped=true},
                _ = self.terminate.recv() => {self.stopped=true},
            }
        }
        self.state.last_observed = now_seconds()?;
        self.state.last_outcome = if self.stopped {
            "stopped"
        } else if self.state.last_observed >= self.owner.manifest().validity().expires {
            "expired"
        } else {
            "deadline_reached"
        }
        .into();
        self.checkpoint()
    }
}
