//! Owner-authorized public documents, split by the real tokenizer and resumed from full receipts.

mod storage;
mod synthesis;
#[cfg(test)]
mod tests;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use tokio::sync::watch;

use super::super::{
    Mode,
    document_plan::{Input, MAX_DOCUMENT_BYTES, Plan},
    private_directory,
};
use super::{Cancellation, discovery, now, parse_key, read_file, rpc, task, workflow};

const MAX_SAVED_BYTES: usize = 16 * 1024 * 1024;
// Up to MAX_PARTS independently checked 1024-byte answers, including worst-case
// JSON escaping and per-answer provenance. Metadata retains its smaller bound.
const MAX_RESULT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent explicit CLI permission and execution switches"
)]
pub(crate) struct Options {
    /// New private task directory; existing exact source/results are used with --resume.
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    resume: bool,
    /// Opt into legacy grouped batches when enrolling; resume keeps the recorded mode.
    #[arg(long, conflicts_with = "resume")]
    batch_barrier: bool,
    /// Combine all fragment answers through further peer inference; retains every intermediate receipt.
    #[arg(long, conflicts_with = "resume")]
    synthesize: bool,
    /// UTF-8 text that you are authorized to publish, not automatic browsing/private-file ingestion.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    input: Option<PathBuf>,
    /// Explicit permission to disclose this document and question to the selected peers.
    #[arg(long, conflicts_with = "resume")]
    public_content: bool,
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    public_question: Option<String>,
    /// Explicit content license; no license is silently assigned to your document.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume",
          value_parser = ["GPL-3.0-only", "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0"])]
    license: Option<String>,
    /// Already provisioned local tokenizer runtime. No automatic installation/download.
    #[arg(long, required_unless_present = "resume")]
    runtime_root: Option<PathBuf>,
    #[arg(long, required_unless_present = "resume")]
    model_root: Option<PathBuf>,
    /// Existing encrypted publisher identity; must match --publisher-key.
    #[arg(long, required_unless_present = "resume")]
    identity: Option<PathBuf>,
    #[arg(long, required_unless_present = "resume")]
    passphrase_file: Option<PathBuf>,
    #[arg(long, value_parser = parse_key, required_unless_present = "resume", conflicts_with = "resume")]
    publisher_key: Option<VerifyingKey>,
    /// Independently selected peers, already configured to trust this publisher.
    #[arg(long, value_parser = parse_key, required_unless_present_any = ["resume", "discover_peers"], conflicts_with_all = ["resume", "discover_peers"])]
    provider_key: Vec<VerifyingKey>,
    #[command(flatten)]
    discovery: discovery::Options,
    #[arg(long, default_value_t = 86400, value_parser = clap::value_parser!(u64).range(1..=2678400))]
    lifetime_seconds: u64,
    /// Package rounds per invocation, or per continuation window with --follow.
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=32))]
    max_batches: u16,
    #[command(flatten)]
    follow: super::follow::Options,
    /// Unchanged bounded lease for each tokenizer/peer worker.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=2))]
    threads: u16,
    #[arg(long)]
    execute: bool,
    /// Prepare the public source, tokenizer plan and immutable peer selection without submitting jobs.
    #[arg(long, requires = "execute", conflicts_with = "resume")]
    enroll_only: bool,
}

pub(super) fn save(
    root: &Path,
    name: &str,
    value: &impl serde::Serialize,
    replace: bool,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    let limit = if name == "result.json" {
        MAX_RESULT_BYTES
    } else {
        MAX_SAVED_BYTES
    };
    ensure!(bytes.len() <= limit, "compute_document_saved_size");
    task::write_bytes(&root.join(name), &bytes, replace)
}

pub(super) async fn run(args: &Options, socket: &Path) -> Result<()> {
    if !args.execute {
        println!(
            "{}",
            json!({"operation":"compute_document_plan", "execute":false,
            "input":args.input,"directory":args.directory,"resume":args.resume,
            "synthesize":args.synthesize,
            "discover_peers":args.discovery.discover_peers,
            "replace_peers":args.discovery.replace_peers,
            "max_batches":args.max_batches,"maximum_seconds_per_worker":args.max_seconds,"follow":args.follow.follow,
            "maximum_document_bytes":MAX_DOCUMENT_BYTES,"private_data_supported":false,
            "tokenizer_execution":false,"network_execution":false})
        );
        return Ok(());
    }
    let cancellation = Cancellation::new()?;
    ensure!(
        args.directory.is_absolute(),
        "compute_document_absolute_directory"
    );
    ensure!(
        args.resume || args.public_content,
        "compute_document_public_permission_required"
    );
    let _lock = task::open_directory(&args.directory, args.resume)?;
    if !args.resume {
        prepare(args, socket, &cancellation.activity).await?;
    }
    if args.enroll_only {
        let (enrollment, _, _) = storage::load(&args.directory)?;
        println!(
            "{}",
            json!({"operation":"compute_document_enrolled", "execution_started":false,
            "task_complete":false, "source_manifest_id":enrollment.source_manifest_id,
            "provider_keys":enrollment.provider_keys, "model_fingerprint":enrollment.model_fingerprint,
            "package_count":enrollment.packages.len(), "private_data_supported":false})
        );
        return Ok(());
    }
    let mut result = advance(args, socket, &cancellation.activity).await?;
    if result["synthesis_requested"] == true {
        if result["complete"] == true {
            synthesis::advance(args, socket, &cancellation.activity, &mut result).await?;
        } else {
            result["joining"] = "awaiting_fragments_before_peer_synthesis".into();
        }
    }
    save(&args.directory, "result.json", &result, true)?;
    println!("{}", serde_json::to_string(&result)?);
    ensure!(
        result["complete"] == true,
        "compute_document_partial_results_retained"
    );
    Ok(())
}

async fn prepare(args: &Options, socket: &Path, cancelled: &watch::Receiver<bool>) -> Result<()> {
    ensure!(
        args.public_content,
        "compute_document_public_permission_required"
    );
    let input = Input {
        version: 1,
        synthesis: false,
        visibility: "public".into(),
        license: args.license.clone().context("compute_document_license")?,
        document: String::from_utf8(super::super::read_file(
            args.input.as_ref().context("compute_document_input")?,
            MAX_DOCUMENT_BYTES as u64,
        )?)?,
        question: args
            .public_question
            .clone()
            .context("compute_document_question")?,
    };
    input.validate()?;
    let selected = if args.discovery.discover_peers {
        ensure!(
            args.provider_key.is_empty(),
            "compute_discovery_conflicting_providers"
        );
        let publisher = args.publisher_key.context("compute_document_publisher")?;
        let query = args.discovery.query(
            [hex::encode(publisher.as_bytes())],
            true,
            true,
            args.synthesize,
        )?;
        Some(args.discovery.select(socket, query, cancelled).await?)
    } else {
        None
    };
    let providers = selected
        .as_ref()
        .map_or(&args.provider_key, |selected| &selected.providers);
    ensure!(
        (2..=4).contains(&providers.len())
            && providers
                .iter()
                .map(VerifyingKey::to_bytes)
                .collect::<BTreeSet<_>>()
                .len()
                == providers.len(),
        "compute_document_independent_peers"
    );
    ensure!(
        !*cancelled.borrow(),
        "compute_document_cancelled_before_planning"
    );
    task::write_bytes(
        &args.directory.join("source.txt"),
        input.document.as_bytes(),
        false,
    )?;
    save(&args.directory, "planner-input.json", &input, false)?;
    let plan = tokenize(args, &args.directory, &input, cancelled).await?;
    ensure!(
        !*cancelled.borrow(),
        "compute_document_cancelled_before_publication"
    );
    let signer =
        crate::content::unlock_signer(args.identity.as_deref(), args.passphrase_file.as_deref())?;
    ensure!(
        Some(signer.verifying_key()) == args.publisher_key,
        "compute_document_publisher_identity"
    );
    let mut enrollment = storage::publish(
        &args.directory,
        &input,
        &plan,
        &signer,
        providers,
        now()?,
        args.lifetime_seconds,
        cancelled,
        args.synthesize,
    )?;
    enrollment.model_fingerprint = selected.map(|selected| selected.model_fingerprint);
    enrollment.replace_peers = args.discovery.replace_peers;
    enrollment.scheduling = workflow::Scheduling::from_batch_barrier(args.batch_barrier);
    drop(signer); // No identity/private key is retained during any peer exchange.
    save(&args.directory, "document.json", &enrollment, false)
}

async fn tokenize(
    args: &Options,
    directory: &Path,
    input: &Input,
    cancelled: &watch::Receiver<bool>,
) -> Result<Plan> {
    // A stopped tokenizer leaves its work intact. Only a complete plan is reused; a
    // new bounded worker gets a new directory, never overwrites an interrupted one.
    let mut output = directory.join("tokenizer");
    for attempt in 0..32 {
        if output.join("document-plan.json").try_exists()? {
            let plan: Plan = serde_json::from_slice(&read_file(
                &output.join("document-plan.json"),
                MAX_SAVED_BYTES,
            )?)?;
            plan.validate(input)?;
            return Ok(plan);
        }
        if !storage::present(&output)? {
            break;
        }
        ensure!(attempt < 31, "compute_document_tokenizer_attempt_limit");
        output = directory.join(format!("tokenizer-attempt-{:04}", attempt + 1));
    }
    ensure!(
        !*cancelled.borrow(),
        "compute_document_cancelled_before_planning"
    );
    let options = super::super::Options {
        mode: Mode::PlanDocument,
        runtime_root: args
            .runtime_root
            .clone()
            .context("compute_document_runtime")?,
        model_root: args.model_root.clone().context("compute_document_model")?,
        adapter_root: None,
        dataset: directory.join("planner-input.json"),
        output: output.clone(),
        steps: 1,
        threads: args.threads,
        max_seconds: args.max_seconds,
        spare_capacity: true,
        execute: true,
    };
    options.validate()?;
    let (owner, idle) = watch::channel(!*cancelled.borrow());
    let mut receiver = cancelled.clone();
    let bridge = tokio::spawn(async move {
        while !*receiver.borrow() {
            if receiver.changed().await.is_err() {
                break;
            }
        }
        let _ = owner.send(false);
    });
    let report = super::super::execute(&options, idle).await;
    bridge.abort();
    let report = report?;
    save(directory, "tokenizer-report.json", &report, true)?;
    let plan: Plan = serde_json::from_slice(&read_file(
        &output.join("document-plan.json"),
        MAX_SAVED_BYTES,
    )?)?;
    plan.validate(input)?;
    Ok(plan)
}

async fn advance(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
) -> Result<Value> {
    let (enrollment, input, plan) = storage::load(&args.directory)?;
    let providers = enrollment
        .provider_keys
        .iter()
        .map(|key| parse_key(key).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    let mut packages = Vec::new();
    let mut answers = Vec::new();
    let mut rounds = 0_u64;
    let mut stopped = false;
    for (index, package) in enrollment.packages.iter().enumerate() {
        let root = args.directory.join(format!("package-{index:04}"));
        private_directory(&root)?;
        let expected = storage::expected(&root, &enrollment, package, &input, &plan)?;
        let work = root.join("work");
        let established = storage::present(&work)?;
        let mut snapshot = if established {
            Some(workflow::task_snapshot(&work, &expected)?)
        } else {
            None
        };
        if snapshot.as_ref().is_none_or(|s| s["complete"] != true)
            && (args.follow.follow || rounds < u64::from(args.max_batches))
            && !stopped
            && !*cancelled.borrow()
        {
            let options = workflow::Options::task(
                (!established).then(|| root.join("workflow-plan.json")),
                work.clone(),
                providers.clone(),
                if args.follow.follow {
                    args.max_batches
                } else {
                    args.max_batches - u16::try_from(rounds)?
                },
                args.max_seconds,
                true,
            )
            .expect_task(expected.clone())
            .with_follow(args.follow.clone());
            let report = workflow::report_with_activity(&options, socket, cancelled).await?;
            let used = report["rounds_this_invocation"]
                .as_u64()
                .context("compute_document_rounds")?;
            rounds = rounds
                .checked_add(used)
                .context("compute_document_round_overflow")?;
            ensure!(
                args.follow.follow || rounds <= u64::from(args.max_batches),
                "compute_document_invocation_budget"
            );
            snapshot = Some(workflow::task_snapshot(&work, &expected)?);
            stopped = report["complete"] != true;
        }
        let complete = snapshot.as_ref().is_some_and(|s| s["complete"] == true);
        if let Some(snapshot) = snapshot {
            storage::join_answers(&snapshot, package, &input, &plan, &mut answers)?;
        }
        packages.push(
            json!({"package_index":index,"manifest_id":package.manifest_id,"complete":complete,
            "first_part":package.first_part,"parts":package.rows}),
        );
    }
    let complete =
        packages.iter().all(|p| p["complete"] == true) && answers.len() == plan.parts.len();
    Ok(
        json!({"version":1,"operation":"compute_public_document","complete":complete,
        "source_manifest_id":enrollment.source_manifest_id,"source_sha256":plan.source_sha256,
        "source_bytes":plan.source_bytes,"public_question":input.question,"license":input.license,
        "total_parts":plan.parts.len(),"packages":packages,"answers":answers,"rounds_this_invocation":rounds,
        "interrupted":*cancelled.borrow(),"follow":args.follow.follow,
        "joining":"ordered_source_ranges_not_neural_synthesis",
        "synthesis_requested":enrollment.synthesize,
        "source_selection_uses_cache_inventory":false,"private_data_supported":false,
        "content_cache":"local_native_signed_publications_not_automatic_network_contribution",
        "model_answer_correctness_proven":false,"full_b03_claimed":false}),
    )
}
