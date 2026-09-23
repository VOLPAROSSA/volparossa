//! One explicitly enrolled feed owner. This is not a globally complete policy feed.

mod state;
#[cfg(test)]
mod tests;

use std::{
    fs::{File, OpenOptions},
    io::Read as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use tokio::signal::unix::{Signal, SignalKind, signal};
use volparossa_content::ChunkStore;
use volparossa_policy::{MAX_SIGNED_MANIFEST_BYTES, verify_manifest};

use super::{milliseconds, parse_key, parse_manifest, request_apply_decision, sha, storage, task};
use crate::{content, doctor::PolicyContext};
use state::{Phase, Record, State};

#[derive(Debug, Args)]
pub(crate) struct Options {
    #[arg(long)]
    policy_config: PathBuf,
    /// Selected native publication channel, not a policy authority.
    #[arg(long, value_parser=parse_key)]
    publisher_key: VerifyingKey,
    #[arg(long, value_parser=content::parse_content_name)]
    name: String,
    #[arg(long, default_value_t=1, value_parser=clap::value_parser!(u64).range(1..))]
    min_revision: u64,
    #[arg(long, value_parser=parse_key)]
    subject_publisher_key: VerifyingKey,
    #[arg(long, value_parser=parse_manifest)]
    subject_manifest_id: [u8; 32],
    #[arg(long, value_parser=parse_manifest)]
    subject_sha256: [u8; 32],
    #[arg(long, value_parser=parse_manifest)]
    framework_sha256: [u8; 32],
    /// Private owner state; one instance follows one selected subject/channel.
    #[arg(long)]
    directory: PathBuf,
    /// New owned cache, reopened only with the same enrolled --resume selection.
    #[arg(long)]
    cache: PathBuf,
    #[arg(long, default_value_t=60, value_parser=clap::value_parser!(u16).range(1..=3600))]
    poll_seconds: u16,
    #[arg(long)]
    execute: bool,
    #[arg(long, requires = "execute")]
    resume: bool,
    #[command(flatten)]
    limits: content::Limits,
}

fn enrollment(args: &Options) -> Value {
    json!({"version":1,"scope":"selected_channel_exact_object","policy_config":args.policy_config,
        "feed":{"publisher_key":hex::encode(args.publisher_key.as_bytes()),"name":args.name,
            "min_revision":args.min_revision},
        "subject":{"publisher_key":hex::encode(args.subject_publisher_key.as_bytes()),
            "manifest_id":hex::encode(args.subject_manifest_id),"object_sha256":hex::encode(args.subject_sha256)},
        "framework_sha256":hex::encode(args.framework_sha256),"cache":args.cache,
        "poll_seconds":args.poll_seconds,"limits":args.limits.configuration()})
}

fn checkpoint(args: &Options, state: &State) -> Result<()> {
    let bytes = serde_json::to_vec(state)?;
    ensure!(
        bytes.len() <= state::MAX_STATE_BYTES,
        "policy_follow_state_bound"
    );
    task::write_bytes(&args.directory.join("state.json"), &bytes, true)?;
    task::write_bytes(
        &args.directory.join("status.json"),
        &serde_json::to_vec(&state.status(&bytes)?)?,
        true,
    )
}

fn load(args: &Options) -> Result<State> {
    let expected = serde_json::to_vec(&enrollment(args))?;
    if args.resume {
        ensure!(
            storage::read(&args.directory.join("enrollment.json"), 16 * 1024)? == expected,
            "policy_follow_enrollment_changed"
        );
        let saved = serde_json::from_slice(&storage::read(
            &args.directory.join("state.json"),
            state::MAX_STATE_BYTES as u64,
        )?)?;
        let _cache = ChunkStore::open(&args.cache, args.limits.cache_limits()?)?;
        Ok(saved)
    } else {
        task::write_bytes(&args.directory.join("enrollment.json"), &expected, false)?;
        let _cache = ChunkStore::create(&args.cache, args.limits.cache_limits()?)?;
        let fresh = State::default();
        checkpoint(args, &fresh)?;
        Ok(fresh)
    }
}

fn context(args: &Options, at: u64) -> Result<(PolicyContext, Vec<u8>)> {
    let config = volparossa_config::Config::from_path(&args.policy_config)?;
    let checked = crate::doctor::load_policy_context(&config, &args.policy_config, at)?;
    // Preserve the exact original epoch, while retaining the existing independent trust loader.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&config.policy.manifest_path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= MAX_SIGNED_MANIFEST_BYTES as u64,
        "policy_follow_epoch_bound"
    );
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_SIGNED_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_SIGNED_MANIFEST_BYTES,
        "policy_follow_epoch_bound"
    );
    let original = verify_manifest(&bytes, at, &checked.trust, checked.verification)?;
    ensure!(
        original.policy_hash() == checked.manifest.policy_hash(),
        "policy_follow_epoch_changed"
    );
    Ok((checked, bytes))
}

struct Signals {
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    fn new() -> Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }
    async fn cancelled(&mut self) {
        tokio::select! { _=self.interrupt.recv()=>{}, _=self.terminate.recv()=>{} }
    }
}

pub(in crate::compute::peer) async fn run(args: &Options, socket: &Path) -> Result<()> {
    ensure!(
        args.policy_config.is_absolute()
            && args.directory.is_absolute()
            && args.cache.is_absolute()
            && args.cache != args.directory,
        "policy_follow_absolute_distinct_paths"
    );
    if !args.execute {
        println!(
            "{}",
            json!({"operation":"compute_policy_follow","execute":false,
            "enrollment":enrollment(args),"network_policy_activation":false,"model_execution":false})
        );
        return Ok(());
    }
    let mut signals = Signals::new()?;
    let _lock = task::open_directory(&args.directory, args.resume)?;
    if !args.resume {
        File::open(args.directory.parent().context("policy_follow_parent")?)?.sync_all()?;
    }
    let mut state = load(args)?;
    let (authority, _) = context(args, milliseconds()?)?;
    state.validate(args, &authority)?;
    checkpoint(args, &state)?;
    loop {
        tokio::select! {
            biased;
            ()=signals.cancelled()=>break,
            result=tick(args,socket,&mut state)=>result?,
        }
        tokio::select! {
            ()=signals.cancelled()=>break,
            ()=tokio::time::sleep(Duration::from_secs(u64::from(args.poll_seconds)))=>{},
        }
    }
    // A dropped in-flight apply leaves the exact pending envelope durable for idempotent resume.
    checkpoint(args, &state)?;
    println!(
        "{}",
        json!({"operation":"compute_policy_follow","stopped":true,
        "network_policy_activation":false,"model_execution":false,
        "status":state.status(&serde_json::to_vec(&state)?)?})
    );
    Ok(())
}

async fn tick(args: &Options, socket: &Path, state: &mut State) -> Result<()> {
    if state
        .latest
        .as_ref()
        .is_some_and(|record| record.phase == Phase::Pending)
    {
        return finish_pending(args, socket, state).await;
    }
    let minimum = state
        .latest
        .as_ref()
        .map(Record::wrapper_revision)
        .transpose()?
        .unwrap_or(args.min_revision);
    let feed = content::policy_decision::Feed {
        publisher: args.publisher_key,
        name: args.name.clone(),
        min_revision: minimum.max(args.min_revision),
        cache: args.cache.clone(),
        limits: args.limits.clone(),
    };
    let downloaded = content::policy_decision::refresh(&feed, socket, &args.directory).await;
    let at = milliseconds()?;
    let download = match downloaded {
        Ok(download) => download,
        Err(error) => {
            eprintln!("policy_follow event=fetch_failed reason={error:#}");
            state.poll_completed(at, "fetch_failed")?;
            return checkpoint(args, state);
        }
    };
    let accepted = accept(args, state, download, at);
    let record = match accepted {
        Ok(Some(record)) => record,
        Ok(None) => {
            state.poll_completed(at, "unchanged")?;
            return checkpoint(args, state);
        }
        Err(error) => {
            eprintln!("policy_follow event=rejected reason={error:#}");
            state.poll_completed(at, "rejected")?;
            return checkpoint(args, state);
        }
    };
    state.latest = Some(record);
    state.poll_completed(at, "pending")?;
    checkpoint(args, state)?;
    finish_pending(args, socket, state).await
}

fn accept(
    args: &Options,
    state: &State,
    download: content::policy_decision::Download,
    at: u64,
) -> Result<Option<Record>> {
    let (authority, epoch) = context(args, at)?;
    let record = Record {
        phase: Phase::Pending,
        observed_at_ms: at,
        manifest_hex: hex::encode(download.signed_manifest),
        decision_hex: hex::encode(download.bytes),
        epoch_manifest_hex: hex::encode(epoch),
        download_receipt: download.receipt,
        apply_receipt: None,
    };
    record.verify_live(args, &authority, at)?;
    state
        .accepts(args, &authority, &record)
        .map(|changed| changed.then_some(record))
}

async fn finish_pending(args: &Options, socket: &Path, state: &mut State) -> Result<()> {
    let Some(pending) = state.latest.as_ref() else {
        return Ok(());
    };
    let at = milliseconds()?;
    if pending.expired(at)? {
        state
            .latest
            .as_mut()
            .context("policy_follow_pending")?
            .phase = Phase::Expired;
        return checkpoint(args, state);
    }
    let (authority, _) = match context(args, at) {
        Ok(context) => context,
        Err(error) => {
            eprintln!("policy_follow event=authority_unavailable reason={error:#}");
            return Ok(());
        }
    };
    let original = pending.original_decision()?;
    if original.body().policy_hash != *authority.manifest.policy_hash() {
        state
            .latest
            .as_mut()
            .context("policy_follow_pending")?
            .phase = Phase::StaleEpoch;
        return checkpoint(args, state);
    }
    let verified = pending.verify_live(args, &authority, at)?;
    let envelope = state::decode(
        &pending.decision_hex,
        volparossa_policy::object::MAX_OBJECT_DECISION_BYTES,
    )?;
    let applied = tokio::time::timeout(
        Duration::from_secs(30),
        request_apply_decision(&envelope, &verified, socket),
    )
    .await;
    let receipt = match applied {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(error)) => {
            eprintln!("policy_follow event=apply_deferred reason={error:#}");
            return Ok(());
        }
        Err(_) => {
            eprintln!("policy_follow event=apply_deferred reason=deadline");
            return Ok(());
        }
    };
    state.applied(serde_json::to_value(receipt)?)?;
    checkpoint(args, state)
}
