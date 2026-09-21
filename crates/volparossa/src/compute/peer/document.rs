//! Owner-authorized public documents, split by the real tokenizer and resumed from full receipts.

mod collection;
mod graph;
mod storage;
mod synthesis;
#[cfg(test)]
mod tests;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::compute::ModelProfile;
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
use super::batch::output;
use super::{Cancellation, discovery, now, parse_key, read_file, rpc, task, workflow};

const MAX_SAVED_BYTES: usize = 16 * 1024 * 1024;
// Up to MAX_PARTS independently checked answers (at most 4096 escaped bytes each),
// including per-answer provenance. Metadata retains its smaller bound.
const MAX_RESULT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, Args)]
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
    /// Explicit public question/dependency graph over the selected sources; not an autonomous planner.
    #[arg(long, conflicts_with_all = ["resume", "public_question", "synthesize", "batch_barrier"])]
    task_plan: Option<PathBuf>,
    /// Ask the pinned model for bounded public subquestions; preserves the exact question in the final join.
    #[arg(long, requires = "public_question", conflicts_with_all = ["resume", "task_plan", "plan_task_graph", "synthesize", "batch_barrier"])]
    plan_tasks: bool,
    /// Let the pinned model choose bounded public subtasks and dependencies; keeps the exact final question.
    #[arg(long, requires = "public_question", conflicts_with_all = ["resume", "task_plan", "plan_tasks", "synthesize", "batch_barrier"])]
    plan_task_graph: bool,
    /// Require a model-selected dependent analysis, not just independent source questions.
    #[arg(
        long,
        value_enum,
        requires = "plan_task_graph",
        conflicts_with_all = ["resume", "plan_tasks", "task_plan", "synthesize", "batch_barrier"]
    )]
    plan_structure: Option<crate::compute::task_plan::PlanRequirement>,
    /// UTF-8 text that you are authorized to publish, not automatic browsing/private-file ingestion.
    #[arg(long, required_unless_present_any = ["resume", "source_plan"], conflicts_with_all = ["resume", "source_plan"])]
    input: Option<PathBuf>,
    /// Plan of 2–32 explicitly public documents: v1 local files, v2 local or exact native publications.
    /// Their exact bytes and labels form an owner-published compilation, not third-party attestations.
    #[arg(long, conflicts_with_all = ["input", "resume"])]
    source_plan: Option<PathBuf>,
    /// Agent-owned source cache for v2 native publications; cache misses fetch the same selected source.
    #[arg(long, requires = "source_plan", conflicts_with = "resume")]
    source_cache: Option<PathBuf>,
    #[arg(long, requires = "source_cache", conflicts_with = "resume")]
    reuse_source_cache: bool,
    #[command(flatten)]
    source_limits: crate::content::Limits,
    /// Explicit permission to disclose this document and question to the selected peers.
    #[arg(long, conflicts_with = "resume")]
    public_content: bool,
    #[arg(long, required_unless_present_any = ["resume", "task_plan"], conflicts_with_all = ["resume", "task_plan"])]
    public_question: Option<String>,
    /// Explicit content license; no license is silently assigned to your document.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume",
          value_parser = ["GPL-3.0-only", "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0"])]
    license: Option<String>,
    /// Already provisioned local tokenizer/planner runtime. No automatic installation/download.
    #[arg(long, required_unless_present = "resume")]
    runtime_root: Option<PathBuf>,
    #[arg(long, required_unless_present = "resume")]
    model_root: Option<PathBuf>,
    /// Explicit pinned profile for new planning and the exact peer cohort; resume retains it.
    #[arg(long, default_value_t = ModelProfile::default(), conflicts_with = "resume")]
    model_profile: ModelProfile,
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
    /// Run local planning/tokenization and pin source/peers without submitting peer jobs.
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
    ensure!(
        args.plan_structure.is_none()
            || (args.plan_task_graph
                && !args.plan_tasks
                && !args.resume
                && args.task_plan.is_none()
                && !args.synthesize
                && !args.batch_barrier),
        "compute_task_plan_requirement_mode"
    );
    if !args.execute {
        println!(
            "{}",
            json!({"operation":"compute_document_plan", "execute":false,
            "input":args.input,"source_plan":args.source_plan,"source_cache":args.source_cache,
            "directory":args.directory,"resume":args.resume,
            "synthesize":args.synthesize,
            "task_plan":args.task_plan,"plan_tasks":args.plan_tasks,"plan_task_graph":args.plan_task_graph,"model_profile":args.model_profile,
            "plan_structure":args.plan_structure,
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
    if args.task_plan.is_some()
        || args.plan_tasks
        || args.plan_task_graph
        || (args.resume && args.directory.join("graph.json").try_exists()?)
    {
        return graph::run(args, socket, &cancellation.activity).await;
    }
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
            result["joining"] = if result["execution_complete"] == true {
                "incomplete_fragment_answers"
            } else {
                "awaiting_fragments_before_peer_synthesis"
            }
            .into();
        }
    }
    attach_collection(&args.directory, &mut result)?;
    if !output::preserve_legacy_result(
        &args.directory.join("result.json"),
        MAX_RESULT_BYTES as u64,
        result["rounds_this_invocation"]
            .as_u64()
            .context("compute_document_rounds")?,
        &result,
    )? {
        save(&args.directory, "result.json", &result, true)?;
    }
    println!("{}", serde_json::to_string(&result)?);
    ensure!(
        result["complete"] == true,
        "compute_document_partial_results_retained"
    );
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "One enrollment boundary binds acquired sources, tokenizer results and original signed validity before dispatch"
)]
async fn prepare(args: &Options, socket: &Path, cancelled: &watch::Receiver<bool>) -> Result<()> {
    ensure!(
        args.model_profile.is_default() || !args.batch_barrier,
        "compute_profile_requires_ready_rows"
    );
    ensure!(
        args.public_content,
        "compute_document_public_permission_required"
    );
    let (document, collection, network) = selected_input(args, socket, cancelled).await?;
    let input = Input {
        version: 1,
        model_profile: args.model_profile,
        synthesis: false,
        visibility: "public".into(),
        license: args.license.clone().context("compute_document_license")?,
        document,
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
        let mut query = args.discovery.query(
            [hex::encode(publisher.as_bytes())],
            true,
            true,
            args.synthesize,
        )?;
        bind_profile_query(&mut query, args.model_profile)?;
        Some(args.discovery.select(socket, query, cancelled).await?)
    } else {
        None
    };
    let model_fingerprint = match &selected {
        Some(selected) => selected.model_fingerprint.clone(),
        None => manual_fingerprint(args, socket, cancelled).await?,
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
    retain_selected_sources(
        &args.directory,
        &input,
        collection.as_ref(),
        network.as_ref(),
    )?;
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
    let at = now()?;
    let lifetime = source_lifetime(args.lifetime_seconds, at, network.as_ref())?;
    if let Some(proofs) = &network {
        proofs.validate(
            collection
                .as_ref()
                .context("compute_collection_missing_ledger")?,
            &input.document,
            at,
            at + lifetime,
        )?;
    }
    let mut enrollment = storage::publish(
        &args.directory,
        &input,
        &plan,
        &signer,
        providers,
        at,
        lifetime,
        cancelled,
        args.synthesize,
    )?;
    enrollment.model_fingerprint = Some(model_fingerprint);
    enrollment.replace_peers = args.discovery.replace_peers;
    enrollment.scheduling = workflow::Scheduling::from_batch_barrier(args.batch_barrier);
    enrollment.collection_sha256 = collection
        .as_ref()
        .map(collection::Ledger::sha256)
        .transpose()?;
    enrollment.native_source_proofs_sha256 = network
        .as_ref()
        .map(collection::network::Proofs::sha256)
        .transpose()?;
    drop(signer); // No identity/private key is retained during any peer exchange.
    save(&args.directory, "document.json", &enrollment, false)
}

fn required_fingerprint(profile: ModelProfile) -> Result<Option<String>> {
    if profile.is_default() {
        return Ok(None); // Existing default cohorts may use an explicitly approved adapter.
    }
    let spec = profile.spec();
    let model = rpc::ModelIdentity {
        model_id: spec.model_id.into(),
        model_revision: spec.revision.into(),
        base_weights: rpc::FileIdentity {
            bytes: spec.weights_bytes,
            sha256: spec.weights_sha256.into(),
        },
        adapter_files: None,
    };
    Ok(Some(super::sha(&serde_json::to_vec(&model)?)))
}

fn bind_profile_query(query: &mut rpc::EligibilityQuery, profile: ModelProfile) -> Result<()> {
    query.model_profile = Some(profile.to_string());
    if let Some(required) = required_fingerprint(profile)? {
        ensure!(
            query
                .model_fingerprint
                .as_ref()
                .is_none_or(|selected| selected == &required),
            "compute_discovery_profile_conflict"
        );
        query.model_fingerprint = Some(required);
    }
    Ok(())
}

async fn manual_fingerprint(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
) -> Result<String> {
    let mut fingerprint: Option<String> = None;
    for provider in &args.provider_key {
        ensure!(!*cancelled.borrow(), "compute_document_cancelled");
        let caps = super::capabilities(socket, provider).await?;
        ensure!(
            crate::compute::broker::profile_for_model(&caps.model)? == args.model_profile,
            "compute_document_peer_model_profile"
        );
        ensure!(
            fingerprint
                .as_ref()
                .is_none_or(|value| value == &caps.model_fingerprint),
            "compute_document_mixed_peer_models"
        );
        fingerprint = Some(caps.model_fingerprint);
    }
    fingerprint.context("compute_document_missing_peer_model")
}

fn retain_selected_sources(
    directory: &Path,
    input: &Input,
    collection: Option<&collection::Ledger>,
    network: Option<&collection::network::Proofs>,
) -> Result<()> {
    task::write_bytes(
        &directory.join("source.txt"),
        input.document.as_bytes(),
        false,
    )?;
    if let Some(collection) = collection {
        save(directory, "collection.json", collection, false)?;
    }
    if let Some(network) = network {
        ensure!(
            serde_json::to_vec(network)?.len() <= 128 * 1024,
            "compute_collection_source_proofs_size"
        );
        save(directory, "native-source-proofs.json", network, false)?;
    }
    save(directory, "planner-input.json", input, false)
}

type SelectedInput = (
    String,
    Option<collection::Ledger>,
    Option<collection::network::Proofs>,
);

async fn selected_input(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
) -> Result<SelectedInput> {
    match (&args.input, &args.source_plan) {
        (Some(path), None) => Ok((
            String::from_utf8(super::super::read_file(path, MAX_DOCUMENT_BYTES as u64)?)?,
            None,
            None,
        )),
        (None, Some(path)) => {
            let prepared = collection::acquire(
                path,
                collection::Acquisition {
                    socket,
                    directory: &args.directory,
                    cache: args.source_cache.as_deref(),
                    reuse_cache: args.reuse_source_cache,
                    limits: &args.source_limits,
                    cancelled,
                },
            )
            .await?;
            Ok((prepared.document, Some(prepared.ledger), prepared.network))
        }
        _ => anyhow::bail!("compute_document_exactly_one_source_selection"),
    }
}

fn source_lifetime(
    requested: u64,
    at: u64,
    sources: Option<&collection::network::Proofs>,
) -> Result<u64> {
    let expiry = sources.and_then(|proofs| proofs.sources.iter().map(|proof| proof.expires).min());
    let remaining = expiry
        .map(|expiry| {
            expiry
                .checked_sub(at)
                .filter(|left| *left > 0)
                .context("compute_collection_source_expired")
        })
        .transpose()?;
    Ok(remaining.map_or(requested, |remaining| requested.min(remaining)))
}

/// Citations here are deterministic input-byte lineage, never a claim that generated
/// statements are supported by a particular source or that every source was understood.
fn attach_collection(root: &Path, result: &mut Value) -> Result<()> {
    let (enrollment, input, _) = storage::load(root)?;
    let Some(ledger) = storage::load_collection(root, &enrollment, &input)? else {
        return Ok(());
    };
    result["source_collection"] = json!({
        "ledger":ledger,"ledger_sha256":enrollment.collection_sha256,
        "publication_scope":"owner_authorized_public_compilation",
        "original_publishers_authenticated":false,"common_license":input.license,
        "source_files_needed_for_resume":false,"semantic_citations_proven":false
    });
    if let Some(proofs) = storage::load_native_sources(root, &enrollment, &input, &ledger)? {
        result["source_collection"]["native_publications"] = serde_json::to_value(&proofs)?;
        result["source_collection"]["publication_signatures_verified"] = true.into();
        result["source_collection"]["source_selection_uses_cache_inventory"] = false.into();
        result["source_collection"]["source_proofs_sha256"] =
            enrollment.native_source_proofs_sha256.clone().into();
        result["source_collection"]["compilation_expires_unix_seconds"] =
            enrollment.expires_at_unix_seconds.into();
    }
    for answer in result["answers"]
        .as_array_mut()
        .context("compute_document_answers")?
    {
        let start = answer["start"]
            .as_u64()
            .context("compute_collection_answer_start")?;
        let end = answer["end"]
            .as_u64()
            .context("compute_collection_answer_end")?;
        answer["source_provenance"] = ledger.provenance(start, end)?;
    }
    if let Some(answer) = result.get_mut("synthesized_answer") {
        let start = answer["source_start"]
            .as_u64()
            .context("compute_collection_answer_start")?;
        let end = answer["source_end"]
            .as_u64()
            .context("compute_collection_answer_end")?;
        answer["source_provenance"] = ledger.provenance(start, end)?;
    }
    Ok(())
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
        model_profile: input.model_profile,
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
    let grouped = enrollment.scheduling == workflow::Scheduling::ReadyRowsV1;
    let mut rounds = if grouped {
        advance_groups(
            args,
            socket,
            cancelled,
            &enrollment,
            &input,
            &plan,
            &providers,
        )
        .await?
    } else {
        0
    };
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
            && !grouped
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
    let execution_complete =
        packages.iter().all(|p| p["complete"] == true) && answers.len() == plan.parts.len();
    let complete = execution_complete && output::all_complete(&answers)?;
    Ok(
        json!({"version":2,"operation":"compute_public_document","complete":complete,
        "execution_complete":execution_complete,"answer_complete":complete,"semantic_completeness_proven":false,
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

/// A bounded set of signed packages shares one provider registry rather than each
/// starting an independent coordinator that races for the same broker slots.
async fn advance_groups(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    enrollment: &storage::Enrollment,
    input: &Input,
    plan: &Plan,
    providers: &[VerifyingKey],
) -> Result<u64> {
    let mut rounds = 0_u64;
    for (group, packages) in enrollment.packages.chunks(32).enumerate() {
        if *cancelled.borrow() || (!args.follow.follow && rounds >= u64::from(args.max_batches)) {
            break;
        }
        let budget = if args.follow.follow {
            args.max_batches
        } else {
            args.max_batches - u16::try_from(rounds)?
        };
        let options = packages
            .iter()
            .enumerate()
            .map(|(offset, package)| {
                let root = args
                    .directory
                    .join(format!("package-{:04}", group * 32 + offset));
                private_directory(&root)?;
                let expected = storage::expected(&root, enrollment, package, input, plan)?;
                let work = root.join("work");
                let established = storage::present(&work)?;
                Ok(workflow::Options::task(
                    (!established).then(|| root.join("workflow-plan.json")),
                    work,
                    providers.to_vec(),
                    budget,
                    args.max_seconds,
                    true,
                )
                .expect_task(expected)
                .with_follow(args.follow.clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        let report =
            workflow::report_group_with_activity(&options, budget, &args.follow, socket, cancelled)
                .await?;
        rounds = rounds
            .checked_add(
                report["rounds_this_invocation"]
                    .as_u64()
                    .context("compute_document_rounds")?,
            )
            .context("compute_document_round_overflow")?;
        ensure!(
            args.follow.follow || rounds <= u64::from(args.max_batches),
            "compute_document_invocation_budget"
        );
        if report["complete"] != true {
            break;
        }
    }
    Ok(rounds)
}
