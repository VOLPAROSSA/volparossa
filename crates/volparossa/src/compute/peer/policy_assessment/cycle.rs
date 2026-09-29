//! One owner-enrolled public source -> four original judgments -> authority round.
//! Resumption keeps the original tasks, selections and finite wall-clock window.

use std::{
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;
use volparossa_content::model_profile::ModelProfile;

use super::{
    Cancellation, Enrollment, IncompleteAssessment,
    object_policy::{Selection, round},
    parse_key, parse_manifest, sha, storage, task, transfer,
};
use crate::content;

const ASSESSMENT_CLEANUP_GRACE_SECONDS: u64 = 30;
const MAX_STATE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Fresh private cycle directory, or the exact original with --resume.
    #[arg(long)]
    directory: PathBuf,
    /// Repeat the original selections. Existing jobs are never replaced or resubmitted.
    #[arg(long, requires = "execute")]
    resume: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long, value_parser = parse_key)]
    source_publisher_key: VerifyingKey,
    #[arg(long, value_parser = content::parse_content_name)]
    source_name: String,
    #[arg(long, value_parser = parse_manifest)]
    source_manifest_id: [u8; 32],
    #[arg(long)]
    cache: PathBuf,
    #[arg(long)]
    reuse_cache: bool,
    /// Original local agent identity, selected independently of the content publisher.
    #[arg(long, value_parser = parse_key)]
    requester_key: VerifyingKey,
    /// Content identity for contexts, requests and the final wrapper; not a policy authority.
    #[arg(long, value_parser = parse_key)]
    publication_key: VerifyingKey,
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    passphrase_file: PathBuf,
    /// Exactly two selected compute peers, in assessment order.
    #[arg(long, required = true, value_parser = parse_key)]
    provider_key: Vec<VerifyingKey>,
    #[arg(long, default_value = "smollm2-360m-v1")]
    model_profile: ModelProfile,
    #[arg(long, value_parser = ["GPL-3.0-only", "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0"])]
    license: String,
    #[arg(long)]
    policy_config: PathBuf,
    #[arg(long, required = true, value_parser = round::parse_authority)]
    authority: Vec<round::Authority>,
    #[arg(long, value_parser = content::parse_content_name)]
    request_name: String,
    #[arg(long, value_parser = content::parse_content_name)]
    publish_name: String,
    #[arg(long, value_parser = parse_key)]
    publication_provider_key: Vec<VerifyingKey>,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    decision_revision: u64,
    /// Each original model job's budget; there are two assessments and two cross-reviews.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    worker_seconds: u16,
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=3600))]
    round_seconds: u16,
    /// Whole-cycle window, including source retrieval and the authority round; never renewed.
    #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(u32).range(1..=86400))]
    total_seconds: u32,
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u16).range(1..=3600))]
    poll_seconds: u16,
    #[command(flatten)]
    limits: content::Limits,
}

fn assessment_options(args: &Options, resume: bool) -> super::Options {
    super::Options {
        output: args.directory.join("assessment"),
        resume,
        portable_receipts: !resume,
        source_publisher_key: (!resume).then_some(args.source_publisher_key),
        source_name: (!resume).then(|| args.source_name.clone()),
        source_manifest_id: (!resume).then_some(args.source_manifest_id),
        cache: (!resume).then(|| args.cache.clone()),
        reuse_cache: !resume && args.reuse_cache,
        publisher_key: (!resume).then_some(args.publication_key),
        identity: Some(args.identity.clone()),
        passphrase_file: Some(args.passphrase_file.clone()),
        provider_key: if resume {
            Vec::new()
        } else {
            args.provider_key.clone()
        },
        model_profile: (!resume).then_some(args.model_profile),
        license: (!resume).then(|| args.license.clone()),
        max_seconds: args.worker_seconds,
        limits: args.limits.clone(),
        execute: args.execute,
    }
}

fn round_options(args: &Options, resume: bool) -> round::Options {
    round::Options {
        selection: Selection {
            assessment_bundle: args.directory.join("assessment.bundle"),
            policy_config: args.policy_config.clone(),
            requester_key: args.requester_key,
            source_publisher_key: args.source_publisher_key,
            source_manifest_id: args.source_manifest_id,
            provider_key: args.provider_key.clone(),
            model_profile: args.model_profile,
        },
        authority: args.authority.clone(),
        publication_key: args.publication_key,
        identity: args.identity.clone(),
        passphrase_file: args.passphrase_file.clone(),
        request_name: args.request_name.clone(),
        publish_name: args.publish_name.clone(),
        publication_provider_key: args.publication_provider_key.clone(),
        decision_revision: args.decision_revision,
        directory: args.directory.join("round"),
        max_seconds: args.round_seconds,
        poll_seconds: args.poll_seconds,
        execute: args.execute,
        resume,
        limits: args.limits.clone(),
    }
}

fn absolute_normal(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}

fn paths(args: &Options, socket: &Path) -> Result<()> {
    let files = [&args.identity, &args.passphrase_file, &args.policy_config];
    ensure!(
        files
            .iter()
            .map(|path| path.as_path())
            .chain([args.directory.as_path(), args.cache.as_path(), socket])
            .all(absolute_normal),
        "policy_cycle_absolute_unaliased_paths"
    );
    ensure!(
        !args.directory.starts_with(&args.cache)
            && !args.cache.starts_with(&args.directory)
            && files
                .iter()
                .all(|path| !path.starts_with(&args.directory) && !path.starts_with(&args.cache))
            && args.identity != args.passphrase_file
            && args.identity != args.policy_config
            && args.passphrase_file != args.policy_config,
        "policy_cycle_separate_stores_and_inputs"
    );
    Ok(())
}

async fn preview(args: &Options, socket: &Path) -> Result<Value> {
    paths(args, socket)?;
    ensure!(
        (1..=600).contains(&args.worker_seconds)
            && (1..=3600).contains(&args.round_seconds)
            && (1..=86400).contains(&args.total_seconds)
            && (1..=3600).contains(&args.poll_seconds)
            && args.decision_revision > 0,
        "policy_cycle_budget"
    );
    super::preview(&assessment_options(args, false))?;
    let mut round = round_options(args, false);
    round.execute = false;
    round::run_value(&round, socket).await?;
    Ok(
        json!({"operation":"compute_policy_cycle","execute":false,"resume":args.resume,
        "source":"explicit_selected_public_native_object","planned_jobs":4,
        "portable_receipts":true,"requires_prebuilt_assessment_bundle":false,
        "worker_seconds":args.worker_seconds,"round_seconds":args.round_seconds,
        "total_seconds":args.total_seconds,"cancellation_cleanup_grace_seconds":ASSESSMENT_CLEANUP_GRACE_SECONDS,
        "selected_authorities":args.authority.len(),"network_policy_activation":false,
        "framework":crate::compute::policy_assessment::framework(),
        "framework_sha256":sha(&serde_json::to_vec(&crate::compute::policy_assessment::framework())?),
        "model_execution":false,"authority_private_keys_loaded":false,
        "semantic_correctness_proven":false,"private_data_supported":false}),
    )
}

fn enrollment(args: &Options, socket: &Path, config_sha256: &str) -> Value {
    json!({"version":1,"directory":args.directory,"socket":socket,
        "source_publisher_key":hex::encode(args.source_publisher_key.as_bytes()),
        "source_name":args.source_name,"source_manifest_id":hex::encode(args.source_manifest_id),
        "cache":args.cache,"reuse_cache":args.reuse_cache,
        "requester_key":hex::encode(args.requester_key.as_bytes()),
        "publication_key":hex::encode(args.publication_key.as_bytes()),
        "identity":args.identity,"passphrase_file":args.passphrase_file,
        "provider_keys":args.provider_key.iter().map(|key|hex::encode(key.as_bytes())).collect::<Vec<_>>(),
        "model_profile":args.model_profile,"license":args.license,
        "policy_config":args.policy_config,"policy_config_sha256":config_sha256,
        "authorities":args.authority.iter().map(|selected|json!({
            "policy_key":hex::encode(selected.key.as_bytes()),
            "transport_publisher":hex::encode(selected.publisher.as_bytes()),
            "reply_name":selected.reply_name})).collect::<Vec<_>>(),
        "request_name":args.request_name,"publish_name":args.publish_name,
        "publication_provider_keys":args.publication_provider_key.iter().map(|key|hex::encode(key.as_bytes())).collect::<Vec<_>>(),
        "decision_revision":args.decision_revision,"worker_seconds":args.worker_seconds,
        "round_seconds":args.round_seconds,"total_seconds":args.total_seconds,"poll_seconds":args.poll_seconds,
        "limits":args.limits.configuration(),"portable_receipts":true,
        "cancellation_cleanup_grace_seconds":ASSESSMENT_CLEANUP_GRACE_SECONDS})
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Assessment,
    Round,
    Complete,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    enrollment_sha256: String,
    started_at_ms: u64,
    deadline_ms: u64,
    phase: Phase,
    assessment_sha256: Option<String>,
    bundle_sha256: Option<String>,
    round_sha256: Option<String>,
}

fn milliseconds() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn retain(path: &Path, bytes: &[u8]) -> Result<()> {
    if storage::exists(path)? {
        ensure!(
            storage::read(path, bytes.len() as u64)? == bytes,
            "policy_cycle_original_changed"
        );
        Ok(())
    } else {
        task::write_bytes(path, bytes, false)
    }
}

impl State {
    fn new(enrollment_sha256: String, started_at_ms: u64, seconds: u32) -> Result<Self> {
        Ok(Self {
            version: 1,
            enrollment_sha256,
            started_at_ms,
            deadline_ms: started_at_ms
                .checked_add(u64::from(seconds) * 1000)
                .context("policy_cycle_deadline")?,
            phase: Phase::Assessment,
            assessment_sha256: None,
            bundle_sha256: None,
            round_sha256: None,
        })
    }

    fn check(&self, enrollment_sha256: &str, seconds: u32) -> Result<()> {
        ensure!(
            self.version == 1
                && self.enrollment_sha256 == enrollment_sha256
                && self.deadline_ms.checked_sub(self.started_at_ms)
                    == Some(u64::from(seconds) * 1000),
            "policy_cycle_original_enrollment_or_deadline_changed"
        );
        let paired = self.assessment_sha256.is_some() && self.bundle_sha256.is_some();
        ensure!(
            match self.phase {
                Phase::Assessment =>
                    self.assessment_sha256.is_none()
                        && self.bundle_sha256.is_none()
                        && self.round_sha256.is_none(),
                Phase::Round => paired && self.round_sha256.is_none(),
                Phase::Complete => paired && self.round_sha256.is_some(),
            },
            "policy_cycle_phase_binding"
        );
        ensure!(
            [
                &self.assessment_sha256,
                &self.bundle_sha256,
                &self.round_sha256
            ]
            .into_iter()
            .flatten()
            .all(|value| crate::compute::is_hex(value, 64)),
            "policy_cycle_original_hash"
        );
        Ok(())
    }

    fn save(&self, args: &Options) -> Result<()> {
        task::write_bytes(
            &args.directory.join("state.json"),
            &serde_json::to_vec(self)?,
            true,
        )
    }
}

struct Owner {
    _signals: Cancellation,
    bridge: tokio::task::JoinHandle<()>,
    activity: watch::Receiver<bool>,
}

async fn stopped(activity: &mut watch::Receiver<bool>) {
    while !*activity.borrow() {
        if activity.changed().await.is_err() {
            break;
        }
    }
}

impl Owner {
    fn new(deadline_ms: u64) -> Result<Self> {
        let signals = Cancellation::new()?;
        let mut interrupted = signals.activity.clone();
        let remaining = deadline_ms.saturating_sub(milliseconds()?);
        let (sender, activity) = watch::channel(remaining == 0);
        let bridge = tokio::spawn(async move {
            tokio::select! {
                () = stopped(&mut interrupted) => {},
                () = tokio::time::sleep(Duration::from_millis(remaining)) => {},
            }
            let _ = sender.send(true);
        });
        Ok(Self {
            _signals: signals,
            bridge,
            activity,
        })
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.bridge.abort();
    }
}

#[derive(Debug)]
struct Incomplete {
    report: Value,
    cause: Option<anyhow::Error>,
}
impl std::fmt::Display for Incomplete {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("compute_policy_cycle_incomplete_retained")
    }
}
impl std::error::Error for Incomplete {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(AsRef::as_ref)
    }
}

fn incomplete<T>(
    args: &Options,
    state: &State,
    reason: &str,
    assessment: Option<&Value>,
) -> Result<T> {
    incomplete_with_cause(args, state, reason, assessment, None)
}

fn incomplete_with_cause<T>(
    args: &Options,
    state: &State,
    reason: &str,
    assessment: Option<&Value>,
    cause: Option<anyhow::Error>,
) -> Result<T> {
    let report = json!({"operation":"compute_policy_cycle","complete":false,
        "phase":state.phase,"reason":reason,"started_at_ms":state.started_at_ms,"deadline_ms":state.deadline_ms,
        "assessment":assessment,"original_jobs_retained":true,
        "remote_cancellation_confirmed":false,"network_policy_activation":false,
        "authority_private_keys_loaded":false,"semantic_correctness_proven":false,
        "cancellation_cleanup_grace_seconds":ASSESSMENT_CLEANUP_GRACE_SECONDS});
    task::write_bytes(
        &args.directory.join("status.json"),
        &serde_json::to_vec(&report)?,
        true,
    )?;
    // Keep the original executor error in the CLI error chain. The durable
    // status contains only the fixed phase/reason and any original typed result.
    Err(Incomplete { report, cause }.into())
}

fn check_assessment(args: &Options, enrolled: &Enrollment) -> Result<()> {
    ensure!(
        enrolled.portable_receipts
            && enrolled.source_name == args.source_name
            && enrolled.scope.source_publisher_key
                == hex::encode(args.source_publisher_key.as_bytes())
            && enrolled.scope.source_manifest_id == hex::encode(args.source_manifest_id)
            && enrolled.publisher_key == hex::encode(args.publication_key.as_bytes())
            && enrolled.providers.iter().eq(args
                .provider_key
                .iter()
                .map(|key| hex::encode(key.as_bytes()))
                .collect::<Vec<_>>()
                .iter())
            && enrolled.profile()? == args.model_profile
            && enrolled.license == args.license
            && enrolled.max_seconds == args.worker_seconds,
        "policy_cycle_original_assessment_selection"
    );
    Ok(())
}

fn execution_paths(args: &Options, socket: &Path) -> Result<String> {
    for file in [&args.identity, &args.passphrase_file, &args.policy_config] {
        ensure!(
            std::fs::canonicalize(file)?.as_os_str() == file.as_os_str(),
            "policy_cycle_input_alias"
        );
    }
    ensure!(
        std::fs::canonicalize(socket)?.as_os_str() == socket.as_os_str(),
        "policy_cycle_socket_alias"
    );
    for directory in [&args.directory, &args.cache] {
        if storage::exists(directory)? {
            crate::compute::private_directory(directory)?;
        } else {
            crate::compute::private_directory(directory.parent().context("policy_cycle_parent")?)?;
        }
    }
    config_hash(&args.policy_config)
}

fn config_hash(path: &Path) -> Result<String> {
    // Normal node configuration may be root-owned and readable by this owner;
    // unlike private cycle records it need not be owned by the CLI's uid.
    Ok(sha(&super::super::read_file(path, 64 * 1024)?))
}

pub(in crate::compute::peer) async fn run(args: &Options, socket: &Path) -> Result<()> {
    match run_value(args, socket).await {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Err(error) => {
            if let Some(incomplete) = error.downcast_ref::<Incomplete>() {
                println!("{}", serde_json::to_string_pretty(&incomplete.report)?);
            }
            Err(error)
        }
    }
}

async fn run_value(args: &Options, socket: &Path) -> Result<Value> {
    let planned = preview(args, socket).await?;
    if !args.execute {
        return Ok(planned);
    }
    let config_sha256 = execution_paths(args, socket)?;
    let selected = serde_json::to_vec(&enrollment(args, socket, &config_sha256))?;
    let _lock = task::open_directory(&args.directory, args.resume)?;
    let mut state = if args.resume {
        ensure!(
            storage::read(&args.directory.join("enrollment.json"), MAX_STATE_BYTES)? == selected,
            "policy_cycle_original_enrollment_changed"
        );
        serde_json::from_slice::<State>(&storage::read(
            &args.directory.join("state.json"),
            MAX_STATE_BYTES,
        )?)?
    } else {
        retain(&args.directory.join("enrollment.json"), &selected)?;
        let state = State::new(sha(&selected), milliseconds()?, args.total_seconds)?;
        state.save(args)?;
        state
    };
    state.check(&sha(&selected), args.total_seconds)?;
    if milliseconds()? >= state.deadline_ms {
        return incomplete(args, &state, "original_deadline_expired", None);
    }
    let owner = Owner::new(state.deadline_ms)?;
    round::preflight_authorities(&round_options(args, false))?;
    advance(args, socket, &owner, &config_sha256, &mut state).await
}

async fn assess_selected(
    args: &Options,
    socket: &Path,
    owner: &Owner,
    state: &State,
) -> Result<()> {
    let assessment_root = args.directory.join("assessment");
    if state.phase == Phase::Assessment {
        let resume = storage::exists(&assessment_root)?;
        if resume {
            check_assessment(args, &storage::load(&assessment_root)?.0)?;
        }
        let options = assessment_options(args, resume);
        let future = super::run_value_with_activity(&options, socket, &owner.activity);
        tokio::pin!(future);
        let mut stop = owner.activity.clone();
        let assessed = tokio::select! { biased;
            ()=stopped(&mut stop)=>tokio::time::timeout(Duration::from_secs(ASSESSMENT_CLEANUP_GRACE_SECONDS), &mut future).await,
            result=&mut future=>Ok(result),
        };
        match assessed {
            Err(_) => return incomplete(args, state, "assessment_cleanup_unconfirmed", None),
            Ok(Err(error)) => {
                let original = error
                    .downcast_ref::<IncompleteAssessment>()
                    .map(|value| value.result.clone());
                return incomplete_with_cause(
                    args,
                    state,
                    "assessment_incomplete",
                    original.as_ref(),
                    Some(error),
                );
            }
            Ok(Ok(result)) => ensure!(
                result["complete"] == true,
                "policy_cycle_complete_assessment_required"
            ),
        }
    }
    Ok(())
}

async fn advance(
    args: &Options,
    socket: &Path,
    owner: &Owner,
    config_sha256: &str,
    state: &mut State,
) -> Result<Value> {
    assess_selected(args, socket, owner, state).await?;
    let assessment_root = args.directory.join("assessment");
    if *owner.activity.borrow() || milliseconds()? >= state.deadline_ms {
        return incomplete(args, state, "owner_stopped_before_round", None);
    }
    let bytes = transfer::verified_bundle(&assessment_root, &args.requester_key)?;
    let (enrolled, assessed) =
        transfer::replay_bundle(&bytes, &args.requester_key, &args.directory)?;
    check_assessment(args, &enrolled)?;
    ensure!(
        assessed["complete"] == true,
        "policy_cycle_complete_assessment_required"
    );
    let original_assessment = storage::read(&assessment_root.join("result.json"), 256 * 1024)?;
    ensure!(
        serde_json::from_slice::<Value>(&original_assessment)? == assessed,
        "policy_cycle_assessment_replay_changed"
    );
    if state.phase == Phase::Assessment {
        retain(&args.directory.join("assessment.bundle"), &bytes)?;
        state.assessment_sha256 = Some(sha(&original_assessment));
        state.bundle_sha256 = Some(sha(&bytes));
        state.phase = Phase::Round;
        state.save(args)?;
    } else {
        ensure!(
            state.assessment_sha256.as_deref() == Some(sha(&original_assessment).as_str())
                && state.bundle_sha256.as_deref() == Some(sha(&bytes).as_str())
                && storage::read(
                    &args.directory.join("assessment.bundle"),
                    content::policy_bundle::MAX_BYTES
                )? == bytes,
            "policy_cycle_original_bundle_changed"
        );
    }
    ensure!(
        config_hash(&args.policy_config)? == config_sha256,
        "policy_cycle_config_changed"
    );
    let round_root = args.directory.join("round");
    let resume = storage::exists(&round_root)?;
    ensure!(
        state.phase != Phase::Complete || resume,
        "policy_cycle_completed_round_missing"
    );
    let round = round_options(args, resume);
    let mut stop = owner.activity.clone();
    let result = tokio::select! { biased;
        ()=stopped(&mut stop)=>return incomplete(args,state,"round_interrupted_retained",None),
        result=round::run_value(&round,socket)=>match result {
            Ok(result)=>result,
            Err(error)=>return incomplete_with_cause(args,state,"round_incomplete_retained",None,Some(error)),
        },
    };
    ensure!(
        result["complete"] == true && result["provider_signed_claims_replayed"] == 4,
        "policy_cycle_complete_round_required"
    );
    let original_round = storage::read(&round_root.join("result.json"), 512 * 1024)?;
    ensure!(
        serde_json::from_slice::<Value>(&original_round)? == result,
        "policy_cycle_original_round_result_changed"
    );
    if let Some(hash) = &state.round_sha256 {
        ensure!(
            *hash == sha(&original_round),
            "policy_cycle_completed_round_changed"
        );
    }
    let report = json!({"operation":"compute_policy_cycle","complete":true,
        "started_at_ms":state.started_at_ms,"deadline_ms":state.deadline_ms,
        "assessment":assessed,"assessment_sha256":state.assessment_sha256,
        "assessment_bundle_sha256":state.bundle_sha256,"round":result,"round_sha256":sha(&original_round),
        "planned_jobs":4,"portable_receipts":true,"provider_signed_claims_replayed":4,
        "original_jobs_never_replaced":true,"publication_receipts_are_historical":true,
        "current_availability_proven":false,"network_policy_activation":false,
        "local_object_policy_applied":false,"authority_private_keys_loaded":false,
        "private_keys_transferred":false,"semantic_correctness_proven":false,"legal_status":"not_determined"});
    retain(
        &args.directory.join("result.json"),
        &serde_json::to_vec(&report)?,
    )?;
    state.round_sha256 = Some(sha(&original_round));
    state.phase = Phase::Complete;
    state.save(args)?;
    task::write_bytes(
        &args.directory.join("status.json"),
        &serde_json::to_vec(&json!({
        "operation":"compute_policy_cycle","complete":true,"phase":"complete",
        "result_sha256":sha(&serde_json::to_vec(&report)?),"deadline_ms":state.deadline_ms}))?,
        true,
    )?;
    Ok(report)
}

#[cfg(test)]
mod tests;
