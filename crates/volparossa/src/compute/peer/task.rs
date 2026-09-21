//! Source-bound public user tasks over the existing protected, resumable peer executor.
//! A requester-authored question is never presented as a statement by the source publisher.

use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
};

use anyhow::Context as _;
use nix::fcntl::{Flock, FlockArg};
use serde_json::{Value, json};
use volparossa_content::{SignedManifest, provider::compute::dataset::VerifiedPublicDataset};

use super::batch::output;
use super::{
    Args, Cancellation, Deserialize, Path, PathBuf, Result, Serialize, VerifyingKey, discovery,
    ensure, fs, now, parse_key, read_file, rpc, sha, workflow,
};
use crate::{
    compute::private_directory,
    content::{self, Limits, agent_artifact},
};

#[derive(Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent explicit CLI enrollment and execution switches"
)]
pub(crate) struct Options {
    /// Independently trusted publisher of the original public dataset, not of your question.
    #[arg(long, value_parser=parse_key, required_unless_present="resume", conflicts_with="resume")]
    publisher_key: Option<VerifyingKey>,
    /// Exact original publisher-local dataset name.
    #[arg(long, value_parser=content::parse_content_name, required_unless_present="resume", conflicts_with="resume")]
    dataset_name: Option<String>,
    #[arg(long, value_parser=parse_manifest, conflicts_with="resume")]
    dataset_manifest_id: Option<[u8; 32]>,
    #[arg(long, value_parser=clap::value_parser!(u64).range(1..), conflicts_with="resume")]
    min_revision: Option<u64>,
    /// Agent-owned native source cache, with the same source requested on a miss.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    cache: Option<PathBuf>,
    #[arg(long, conflicts_with = "resume")]
    reuse_cache: bool,
    /// Explicit PUBLIC question exported to the selected workers; never use private text here.
    /// Omit to request a fixed section-by-section summary of the public source contexts.
    #[arg(long, conflicts_with = "resume")]
    public_question: Option<String>,
    /// Two to four explicit independently known workers, retained unchanged on resume.
    #[arg(long, value_parser=parse_key, required_unless_present_any=["resume", "discover_peers"], conflicts_with_all=["resume", "discover_peers"])]
    provider_key: Vec<VerifyingKey>,
    #[command(flatten)]
    discovery: discovery::Options,
    /// New private task directory, or the exact existing directory with --resume.
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    resume: bool,
    /// Opt into legacy grouped batches when enrolling; resume keeps the recorded mode.
    #[arg(long, conflicts_with = "resume")]
    batch_barrier: bool,
    /// Worker rounds per invocation, or per continuation window with --follow.
    #[arg(long, default_value_t=8, value_parser=clap::value_parser!(u16).range(1..=32))]
    max_batches: u16,
    #[command(flatten)]
    follow: super::follow::Options,
    #[arg(long, default_value_t=600, value_parser=clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// Default is a preview without output creation, network traffic or remote execution.
    #[arg(long)]
    execute: bool,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u32,
    #[serde(default, skip_serializing_if = "workflow::Scheduling::is_legacy")]
    scheduling: workflow::Scheduling,
    selected_at_unix_seconds: u64,
    publisher_key: String,
    dataset_name: String,
    expected_manifest_id: Option<String>,
    minimum_revision: Option<u64>,
    task: rpc::PublicTask,
    provider_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    replace_peers: bool,
}

fn selection(args: &Options) -> Result<Enrollment> {
    let publisher = args.publisher_key.context("compute_task_publisher")?;
    let task = match &args.public_question {
        Some(question) => rpc::PublicTask::AnswerPublicQuestionV1 {
            question: question.clone(),
        },
        None => rpc::PublicTask::SummarizeContextsV1 {},
    };
    let selected = Enrollment {
        version: 1,
        scheduling: workflow::Scheduling::from_batch_barrier(args.batch_barrier),
        selected_at_unix_seconds: now()?,
        publisher_key: hex::encode(publisher.as_bytes()),
        dataset_name: args.dataset_name.clone().context("compute_task_name")?,
        expected_manifest_id: args.dataset_manifest_id.map(hex::encode),
        minimum_revision: args.min_revision,
        task,
        provider_keys: args
            .provider_key
            .iter()
            .map(|key| hex::encode(key.as_bytes()))
            .collect(),
        model_fingerprint: None,
        replace_peers: args.discovery.replace_peers,
    };
    if args.discovery.discover_peers {
        ensure!(
            args.provider_key.is_empty(),
            "compute_discovery_conflicting_providers"
        );
        validate_source_selection(&selected)?;
    } else {
        validate_selection(&selected)?;
    }
    Ok(selected)
}

fn validate_selection(selected: &Enrollment) -> Result<()> {
    ensure!(
        !selected.replace_peers || selected.model_fingerprint.is_some(),
        "compute_executor_replacement_requires_pinned_model"
    );
    ensure!(
        selected.version == 1
            && selected.selected_at_unix_seconds > 0
            && selected.selected_at_unix_seconds <= now()?
            && selected.minimum_revision != Some(0)
            && (2..=4).contains(&selected.provider_keys.len()),
        "compute_task_selection"
    );
    if let Some(fingerprint) = &selected.model_fingerprint {
        discovery::parse_fingerprint(fingerprint).map_err(anyhow::Error::msg)?;
    }
    let mut peers = BTreeSet::new();
    for key in &selected.provider_keys {
        let key = parse_key(key).map_err(anyhow::Error::msg)?;
        ensure!(peers.insert(key.to_bytes()), "compute_task_duplicate_peer");
    }
    validate_source_selection(selected)
}

fn validate_source_selection(selected: &Enrollment) -> Result<()> {
    parse_key(&selected.publisher_key).map_err(anyhow::Error::msg)?;
    content::parse_content_name(&selected.dataset_name).map_err(anyhow::Error::msg)?;
    selected.task.question()?;
    if let Some(id) = &selected.expected_manifest_id {
        parse_manifest(id).map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

pub(super) async fn run(args: &Options, socket: &Path) -> Result<()> {
    ensure!(
        args.directory.is_absolute(),
        "compute_task_absolute_directory"
    );
    let mut selected = if args.resume {
        private_directory(&args.directory)?;
        serde_json::from_slice(&read_file(&args.directory.join("task.json"), 64 * 1024)?)?
    } else {
        selection(args)?
    };
    if args.resume || !args.discovery.discover_peers {
        validate_selection(&selected)?;
    }
    if !args.execute {
        println!(
            "{}",
            json!({"operation":"compute_public_task_plan","execute":false,"selection":selected,
            "resume":args.resume,"new_directory":args.directory,"network_retrieval":false,
            "discover_peers":args.discovery.discover_peers,
            "remote_execution":false,"private_data_supported":false,"follow":args.follow.follow,
            "source_choice_uses_cache_inventory":false,"question_authored_by_requester":true})
        );
        return Ok(());
    }
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    let cancellation = Cancellation::new()?;
    if !args.resume && args.discovery.discover_peers {
        let query = args
            .discovery
            .query([selected.publisher_key.clone()], true, false, false)?;
        let peers = args
            .discovery
            .select(socket, query, &cancellation.activity)
            .await?;
        selected.provider_keys = peers
            .providers
            .iter()
            .map(|key| hex::encode(key.as_bytes()))
            .collect();
        selected.model_fingerprint = Some(peers.model_fingerprint);
        validate_selection(&selected)?;
    }
    let _lock = open_directory(&args.directory, args.resume)?;
    if !args.resume {
        write_json(&args.directory.join("task.json"), &selected, false)?;
        fetch_source(args, socket, &selected, &cancellation).await?;
        let plan = expected_plan(&args.directory, &selected);
        write_json(&args.directory.join("workflow-plan.json"), &plan, false)?;
    }
    validate_plan(&args.directory, &selected)?;
    let verified = source_for_run(&args.directory, &selected, args.resume, now()?)?;
    let expected = expected_work(&args.directory, &selected, &verified)?;
    ensure!(
        !*cancellation.activity.borrow(),
        "compute_task_cancelled_before_dispatch"
    );
    let directory = args.directory.join("work");
    let workflow_resume = directory.try_exists()?;
    let options = workflow::Options::task(
        (!workflow_resume).then(|| args.directory.join("workflow-plan.json")),
        directory,
        if workflow_resume {
            Vec::new()
        } else {
            selected
                .provider_keys
                .iter()
                .map(|key| parse_key(key).map_err(anyhow::Error::msg))
                .collect::<Result<_>>()?
        },
        args.max_batches,
        args.max_seconds,
        true,
    )
    .expect_task(expected.clone())
    .with_follow(args.follow.clone());
    // Await the real executor and its cancellation/reconciliation. Never drop a live
    // remote execution future and pretend its worker has stopped.
    let work = workflow::report_with_activity(&options, socket, &cancellation.activity).await?;
    let result = joined_result(&args.directory, &selected, &verified, &expected, &work)?;
    let path = args.directory.join("result.json");
    if !output::preserve_legacy_result(
        &path,
        rpc::MAX_DATASET_BYTES as u64,
        work["rounds_this_invocation"]
            .as_u64()
            .context("compute_task_rounds")?,
        &result,
    )? {
        write_json(&path, &result, true)?;
    }
    println!("{}", serde_json::to_string(&result)?);
    ensure!(
        result["complete"] == true,
        "compute_task_partial_results_retained"
    );
    Ok(())
}

async fn fetch_source(
    args: &Options,
    socket: &Path,
    selected: &Enrollment,
    cancelled: &Cancellation,
) -> Result<()> {
    let cache = args.cache.as_ref().context("compute_task_cache")?;
    ensure!(
        cache.is_absolute()
            && !cache.starts_with(&args.directory)
            && !args.directory.starts_with(cache),
        "compute_task_cache_overlap"
    );
    ensure!(
        !*cancelled.activity.borrow(),
        "compute_task_cancelled_before_fetch"
    );
    let query = agent_artifact::TrainingSource {
        publisher_key: parse_key(&selected.publisher_key).map_err(anyhow::Error::msg)?,
        name: selected.dataset_name.clone(),
        manifest_id: args.dataset_manifest_id,
        min_revision: selected.minimum_revision,
        cache: cache.clone(),
        reuse_cache: args.reuse_cache,
        limits: args.limits.clone(),
    };
    let mut activity = cancelled.activity.clone();
    let received = tokio::select! { biased;
        _=activity.changed()=>anyhow::bail!("compute_task_cancelled_during_fetch"),
        response=agent_artifact::fetch_training_source(&query,socket,&args.directory)=>response?
    };
    write_bytes(
        &args.directory.join("dataset.json"),
        &received.dataset,
        false,
    )?;
    write_bytes(
        &args.directory.join("dataset.manifest"),
        &received.signed_manifest,
        false,
    )?;
    verified_source(&args.directory, selected)?;
    write_json(
        &args.directory.join("source-receipt.json"),
        &json!({"publisher_key":selected.publisher_key,"dataset_name":selected.dataset_name,
            "manifest_id":sha(&received.signed_manifest),"dataset_sha256":sha(&received.dataset),
            "expires_unix_seconds":received.expires,"receipt":received.receipt,
            "source_choice_uses_cache_inventory":false,"private_data_supported":false}),
        false,
    )
}

fn verified_source(root: &Path, selected: &Enrollment) -> Result<VerifiedPublicDataset> {
    verified_source_at(root, selected, now()?)
}

fn verified_source_at(
    root: &Path,
    selected: &Enrollment,
    at: u64,
) -> Result<VerifiedPublicDataset> {
    let publisher = parse_key(&selected.publisher_key).map_err(anyhow::Error::msg)?;
    let bytes = read_file(&root.join("dataset.manifest"), 64 * 1024)?;
    // Keep the native expiry error distinct from invalid source bytes/signatures.
    let manifest = SignedManifest::decode(&bytes)?.verify(&publisher, at)?;
    let data = read_file(&root.join("dataset.json"), rpc::MAX_DATASET_BYTES)?;
    let verified = volparossa_content::provider::compute::dataset::verify_source(
        &bytes,
        &publisher,
        std::str::from_utf8(&data)?,
        at,
    )?;
    ensure!(
        manifest.metadata().name == selected.dataset_name
            && selected
                .minimum_revision
                .is_none_or(|minimum| manifest.metadata().revision >= minimum)
            && selected
                .expected_manifest_id
                .as_ref()
                .is_none_or(|id| id == &hex::encode(verified.manifest_id()))
            && (2..=4).contains(&verified.row_count()),
        "compute_task_selected_source"
    );
    Ok(verified)
}

fn source_for_run(
    root: &Path,
    selected: &Enrollment,
    resume: bool,
    current: u64,
) -> Result<VerifiedPublicDataset> {
    match verified_source_at(root, selected, current) {
        Ok(verified) => Ok(verified),
        Err(error)
            if resume
                && matches!(
                    error.downcast_ref::<volparossa_content::Error>(),
                    Some(volparossa_content::Error::Expired)
                ) =>
        {
            let work = root.join("work");
            private_directory(&work)?;
            let enrollment: Value =
                serde_json::from_slice(&read_file(&work.join("workflow.json"), 64 * 1024)?)?;
            let at = enrollment["verified_at_unix_seconds"]
                .as_u64()
                .context("compute_task_historical_verification_time")?;
            ensure!(
                at >= selected.selected_at_unix_seconds && at <= current && at > 0,
                "compute_task_historical_verification_time"
            );
            let verified = verified_source_at(root, selected, at)?;
            let expected = expected_work(root, selected, &verified)?;
            // This revalidates the complete enrollment, source copies, exact handles,
            // full reports and report hashes. A cached 'complete' boolean is insufficient.
            let retained = workflow::task_snapshot(&work, &expected)?;
            ensure!(
                retained["complete"] == true,
                "compute_task_expired_source_has_unfinished_work"
            );
            // Only reading already-completed receipts is authorized. The workflow's
            // real-time source-expiry guard still prohibits any new admission.
            Ok(verified)
        }
        Err(error) => Err(error),
    }
}

fn joined_result(
    root: &Path,
    selected: &Enrollment,
    verified: &VerifiedPublicDataset,
    expected: &workflow::ExpectedTask,
    work: &Value,
) -> Result<Value> {
    let packages = work["packages"]
        .as_array()
        .context("compute_task_workflow_report")?;
    ensure!(packages.len() == 1, "compute_task_package_count");
    let package = &packages[0];
    let stored = workflow::task_snapshot(&root.join("work"), expected)?;
    ensure!(
        work["operation"] == "compute_workflow"
            && package["package_index"] == 0
            && package["dataset_manifest_id"] == hex::encode(verified.manifest_id())
            && package["task"] == serde_json::to_value(&selected.task)?
            && package["task"] == stored["task"]
            && package["complete"] == stored["complete"]
            && package["outputs"] == stored["outputs"],
        "compute_task_result_source"
    );
    let original: Value = serde_json::from_slice(&read_file(
        &root.join("dataset.json"),
        rpc::MAX_DATASET_BYTES,
    )?)?;
    let outputs = package["outputs"]
        .as_array()
        .context("compute_task_result_outputs")?;
    let mut rows = BTreeSet::new();
    let mut answers = Vec::new();
    for output in outputs {
        let index = output["sample_index"]
            .as_u64()
            .context("compute_task_result_row")?;
        let index = usize::try_from(index)?;
        ensure!(
            index < verified.row_count() && rows.insert(index),
            "compute_task_result_rows"
        );
        let context = original["inference"][index]["context"]
            .as_str()
            .context("compute_task_source_context")?;
        ensure!(
            output["text"].is_string()
                && output["report_sha256"]
                    .as_str()
                    .is_some_and(|hash| rpc::nonzero_hex(hash, 64))
                && output["provider_key"].as_str().is_some_and(|key| selected
                    .provider_keys
                    .iter()
                    .any(|provider| provider == key)),
            "compute_task_result_provider"
        );
        let mut answer = json!({"source_row":index,"context_sha256":sha(context.as_bytes()),
            "text":output["text"],"provider_key":output["provider_key"],"job_id":output["job_id"],
            "report_sha256":output["report_sha256"]});
        output::retain(output, &mut answer)?;
        output::annotate(&mut answer)?;
        answers.push(answer);
    }
    let execution_complete = work["complete"] == true
        && package["complete"] == true
        && work["pending_failure"] != true
        && rows.len() == verified.row_count();
    let complete = execution_complete && output::all_complete(&answers)?;
    Ok(
        json!({"version":2,"operation":"compute_public_task","complete":complete,
        "execution_complete":execution_complete,"answer_complete":complete,"semantic_completeness_proven":false,
        "task":selected.task,"publisher_key":selected.publisher_key,"dataset_name":selected.dataset_name,
        "dataset_manifest_id":hex::encode(verified.manifest_id()),"answers":answers,
        "joining":"ordered_per_context_answers_not_neural_synthesis","workflow":work,
        "question_authored_by_requester":true,"publisher_signature_covers_original_source_not_question":true,
        "private_data_supported":false,"automatic_source_discovery":false,
        "arbitrary_document_splitting":false,"model_answer_correctness_proven":false,
        "full_b03_claimed":false}),
    )
}

fn expected_plan(root: &Path, selected: &Enrollment) -> Value {
    json!({"version":1,"packages":[{
        "dataset":root.join("dataset.json"),
        "dataset_manifest":root.join("dataset.manifest"),
        "publisher_key":selected.publisher_key,"task":selected.task}]})
}

fn validate_plan(root: &Path, selected: &Enrollment) -> Result<()> {
    let plan: Value =
        serde_json::from_slice(&read_file(&root.join("workflow-plan.json"), 64 * 1024)?)?;
    ensure!(
        plan == expected_plan(root, selected),
        "compute_task_workflow_plan_changed"
    );
    Ok(())
}

fn expected_work(
    root: &Path,
    selected: &Enrollment,
    verified: &VerifiedPublicDataset,
) -> Result<workflow::ExpectedTask> {
    Ok(workflow::ExpectedTask {
        publisher_key: selected.publisher_key.clone(),
        manifest_id: hex::encode(verified.manifest_id()),
        dataset_sha256: sha(&read_file(
            &root.join("dataset.json"),
            rpc::MAX_DATASET_BYTES,
        )?),
        rows: verified.row_count(),
        task: selected.task.clone(),
        provider_keys: selected.provider_keys.clone(),
        model_fingerprint: selected.model_fingerprint.clone(),
        replace_peers: selected.replace_peers,
        scheduling: selected.scheduling,
        selected_at_unix_seconds: selected.selected_at_unix_seconds,
    })
}

pub(super) fn open_directory(root: &Path, resume: bool) -> Result<Flock<File>> {
    if !resume {
        private_directory(root.parent().context("compute_task_parent")?)?;
        fs::DirBuilder::new().mode(0o700).create(root)?;
    }
    private_directory(root)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(!resume)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join(".task.lock"))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() == 0
            && metadata.nlink() == 1
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode().trailing_zeros() >= 6,
        "compute_task_lock_owner"
    );
    Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|_| anyhow::anyhow!("compute_task_already_running"))
}

fn write_json(path: &Path, value: &impl Serialize, replace: bool) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= rpc::MAX_DATASET_BYTES,
        "compute_task_saved_report_bound"
    );
    write_bytes(path, &bytes, replace)
}

pub(super) fn write_bytes(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    use std::io::Write as _;
    let parent = path.parent().context("compute_task_file_parent")?;
    private_directory(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            replace
                && metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == nix::unistd::geteuid().as_raw(),
            "compute_task_existing_output"
        );
    }
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    if replace {
        file.persist(path).map_err(|error| error.error)?;
    } else {
        file.persist_noclobber(path).map_err(|error| error.error)?;
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn parse_manifest(value: &str) -> Result<[u8; 32], String> {
    let mut bytes = [0; 32];
    if !crate::compute::is_hex(value, 64) {
        return Err("compute_task_manifest_id".into());
    }
    hex::decode_to_slice(value, &mut bytes).map_err(|_| "compute_task_manifest_id")?;
    if bytes == [0; 32] {
        return Err("compute_task_manifest_id".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::{JobHandle, batch, binding, derive};
    use super::*;
    use ed25519_dalek::SigningKey;
    use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};

    struct Fixture {
        root: tempfile::TempDir,
        selected: Enrollment,
        expected: workflow::ExpectedTask,
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let publisher = SigningKey::from_bytes(&[61; 32]);
        let peers = [
            SigningKey::from_bytes(&[62; 32]),
            SigningKey::from_bytes(&[63; 32]),
        ];
        let at = now().unwrap();
        let json = json!({"version":1,"visibility":"public","license":"GPL-3.0-only",
            "source_revision":"a".repeat(40),"train":[],
            "heldout":[{"question":"What is this?","context":"Public protocol fixture.","answer":"A test."}],
            "inference":[{"question":"First?","context":"First public context."},
                {"question":"Second?","context":"Second public context."}]}).to_string();
        let mut cache = ChunkStore::create(
            &root.path().join("cache"),
            CacheLimits {
                max_bytes: 1024 * 1024,
                max_entries: 8,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let signed = publish(
            &mut json.as_bytes(),
            Publication {
                metadata: Metadata {
                    name: "selected".into(),
                    revision: 1,
                    content_type: volparossa_content::provider::compute::dataset::CONTENT_TYPE
                        .into(),
                },
                length: json.len() as u64,
                validity: Validity {
                    created: at,
                    expires: at + 1200,
                },
            },
            &publisher,
            &mut cache,
        )
        .unwrap();
        let selected = Enrollment {
            version: 1,
            scheduling: workflow::Scheduling::BatchBarrierV1,
            selected_at_unix_seconds: at,
            publisher_key: hex::encode(publisher.verifying_key().as_bytes()),
            dataset_name: "selected".into(),
            expected_manifest_id: None,
            minimum_revision: Some(1),
            task: rpc::PublicTask::SummarizeContextsV1 {},
            provider_keys: peers
                .iter()
                .map(|key| hex::encode(key.verifying_key().as_bytes()))
                .collect(),
            model_fingerprint: None,
            replace_peers: false,
        };
        write_bytes(&root.path().join("dataset.json"), json.as_bytes(), false).unwrap();
        write_bytes(
            &root.path().join("dataset.manifest"),
            &signed.encode(),
            false,
        )
        .unwrap();
        write_json(
            &root.path().join("workflow-plan.json"),
            &expected_plan(root.path(), &selected),
            false,
        )
        .unwrap();
        let verified = verified_source(root.path(), &selected).unwrap();
        let expected = expected_work(root.path(), &selected, &verified).unwrap();
        let work = root.path().join("work");
        fs::DirBuilder::new().mode(0o700).create(&work).unwrap();
        let package = work.join("package-0000");
        fs::DirBuilder::new().mode(0o700).create(&package).unwrap();
        write_bytes(&package.join("dataset.json"), json.as_bytes(), false).unwrap();
        write_bytes(&package.join("manifest.bin"), &signed.encode(), false).unwrap();
        write_json(&work.join("workflow.json"),&json!({
            "version":1,"verified_at_unix_seconds":at,"provider_keys":selected.provider_keys,
            "packages":[{"publisher_key":selected.publisher_key,"manifest_id":expected.manifest_id,
                "dataset_sha256":expected.dataset_sha256,"rows":2,"task":selected.task}],
        }),false).unwrap();
        Fixture {
            root,
            selected,
            expected,
        }
    }

    // Full local receipt fixtures exercise parser/hash binding, never successful remote ML.
    fn retained_receipts(fixture: &Fixture) -> Value {
        let source = verified_source(fixture.root.path(), &fixture.selected).unwrap();
        let profile = crate::compute::ModelProfile::Default135.spec();
        let model = rpc::ModelIdentity {
            model_id: profile.model_id.into(),
            model_revision: profile.revision.into(),
            base_weights: rpc::FileIdentity {
                bytes: profile.weights_bytes,
                sha256: profile.weights_sha256.into(),
            },
            adapter_files: None,
        };
        let caps = rpc::Capabilities {
            model_fingerprint: sha(&serde_json::to_vec(&model).unwrap()),
            model,
            accepting_work: true,
            public_inference_only: true,
            runtime_slots: 1,
            max_threads: 2,
            max_job_seconds: 600,
            max_dataset_bytes: 1024 * 1024,
            max_rows: 4,
            task_derivation_v1: true,
            document_inference_v2: false,
            principle_inference_v4: false,
            derived_inference_v3: false,
            successor_activation_v1: false,
        };
        let attempt = fixture.root.path().join("work/package-0000/attempt-0000");
        fs::DirBuilder::new().mode(0o700).create(&attempt).unwrap();
        for index in 0..2_u16 {
            let data = derive(&source, &[index], Some(&fixture.selected.task)).unwrap();
            let handle = JobHandle {
                version: 1,
                provider_key: fixture.selected.provider_keys[usize::from(index)].clone(),
                binding: binding(
                    &source,
                    vec![index],
                    &data,
                    &caps,
                    600,
                    Some(fixture.selected.task.clone()),
                )
                .unwrap(),
                capabilities: caps.clone(),
            };
            write_json(&attempt.join(format!("job-{index}.json")), &handle, false).unwrap();
            let report = json!({"mode":"infer","status":"ok","updates_completed":0,
                "dataset":{"sha256":handle.binding.dataset_sha256,"visibility":"public","inference_examples":1},
                "model":{"id":caps.model.model_id,"revision":caps.model.model_revision,
                    "files":{"model.safetensors":caps.model.base_weights}},
                "supervisor":{"child_reaped":true,"network_access":false},
                "outputs":[{"sample_index":0,"text":"Synthetic receipt fixture, not model output."}]}).to_string();
            let status = rpc::JobStatus {
                binding: handle.binding.clone(),
                state: rpc::JobState::Complete,
                cancellation_requested: false,
                report_sha256: Some(sha(report.as_bytes())),
                report_json: Some(report),
                error: None,
            };
            batch::save_status(&attempt, &handle, &status).unwrap();
        }
        let snapshot =
            workflow::task_snapshot(&fixture.root.path().join("work"), &fixture.expected).unwrap();
        json!({"operation":"compute_workflow","complete":true,"pending_failure":false,
            "packages":[{"package_index":0,"dataset_manifest_id":snapshot["dataset_manifest_id"],
                "task":snapshot["task"],"complete":snapshot["complete"],"outputs":snapshot["outputs"]}]})
    }

    #[test]
    fn expired_source_resume_recovers_only_original_complete_receipts_without_renewal() {
        let fixture = fixture();
        let work = retained_receipts(&fixture);
        let original = read_file(&fixture.root.path().join("dataset.manifest"), 64 * 1024).unwrap();
        let source = verified_source(fixture.root.path(), &fixture.selected).unwrap();
        let after_expiry = source.expires() + 1;
        assert!(verified_source_at(fixture.root.path(), &fixture.selected, after_expiry).is_err());
        let resumed =
            source_for_run(fixture.root.path(), &fixture.selected, true, after_expiry).unwrap();
        assert_eq!(resumed.manifest_id(), source.manifest_id());
        assert_eq!(resumed.expires(), source.expires());
        let joined = joined_result(
            fixture.root.path(),
            &fixture.selected,
            &resumed,
            &fixture.expected,
            &work,
        )
        .unwrap();
        assert_eq!(joined["execution_complete"], true);
        assert_eq!(joined["complete"], false);
        assert_eq!(joined["answers"][0]["answer_status"], "legacy_unknown");
        assert_eq!(
            read_file(&fixture.root.path().join("dataset.manifest"), 64 * 1024).unwrap(),
            original
        );
        assert!(
            source_for_run(fixture.root.path(), &fixture.selected, false, after_expiry).is_err()
        );
    }

    #[test]
    fn historical_source_never_admits_incomplete_or_relabelled_work() {
        let fixture = fixture();
        let expires = verified_source(fixture.root.path(), &fixture.selected)
            .unwrap()
            .expires();
        let error = source_for_run(fixture.root.path(), &fixture.selected, true, expires)
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("expired_source_has_unfinished_work")
        );
        retained_receipts(&fixture);
        let mut changed = fixture.selected.clone();
        changed.task = rpc::PublicTask::AnswerPublicQuestionV1 {
            question: "A newly selected public question?".into(),
        };
        assert!(source_for_run(fixture.root.path(), &changed, true, expires).is_err());
        let path = fixture.root.path().join("work/workflow.json");
        let mut enrollment: Value =
            serde_json::from_slice(&read_file(&path, 64 * 1024).unwrap()).unwrap();
        enrollment["verified_at_unix_seconds"] = (expires + 1).into();
        write_json(&path, &enrollment, true).unwrap();
        assert!(source_for_run(fixture.root.path(), &fixture.selected, true, expires).is_err());
    }

    #[test]
    fn exact_source_paths_publisher_and_public_task_are_required_in_plan() {
        let fixture = fixture();
        validate_plan(fixture.root.path(), &fixture.selected).unwrap();
        for field in ["dataset", "dataset_manifest", "publisher_key", "task"] {
            let mut changed = expected_plan(fixture.root.path(), &fixture.selected);
            changed["packages"][0][field] = Value::Null;
            write_json(
                &fixture.root.path().join("workflow-plan.json"),
                &changed,
                true,
            )
            .unwrap();
            assert!(
                validate_plan(fixture.root.path(), &fixture.selected).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn resumed_work_cannot_change_source_question_workers_or_row_count() {
        let fixture = fixture();
        let work = fixture.root.path().join("work");
        workflow::task_snapshot(&work, &fixture.expected).unwrap();
        let original: Value =
            serde_json::from_slice(&read_file(&work.join("workflow.json"), 64 * 1024).unwrap())
                .unwrap();
        for field in [
            "publisher_key",
            "manifest_id",
            "dataset_sha256",
            "rows",
            "task",
        ] {
            let mut changed = original.clone();
            changed["packages"][0][field] = match field {
                "rows" => json!(3),
                "task" => serde_json::to_value(rpc::PublicTask::AnswerPublicQuestionV1 {
                    question: "A different public question?".into(),
                })
                .unwrap(),
                _ => json!("b".repeat(64)),
            };
            write_json(&work.join("workflow.json"), &changed, true).unwrap();
            assert!(
                workflow::task_snapshot(&work, &fixture.expected).is_err(),
                "{field}"
            );
        }
        let mut changed = original;
        changed["provider_keys"].as_array_mut().unwrap().reverse();
        write_json(&work.join("workflow.json"), &changed, true).unwrap();
        assert!(workflow::task_snapshot(&work, &fixture.expected).is_err());
    }

    #[test]
    fn joined_answers_require_actual_retained_report_hash_and_exact_task() {
        let fixture = fixture();
        let work = retained_receipts(&fixture);
        let verified = verified_source(fixture.root.path(), &fixture.selected).unwrap();
        let joined = joined_result(
            fixture.root.path(),
            &fixture.selected,
            &verified,
            &fixture.expected,
            &work,
        )
        .unwrap();
        assert_eq!(joined["execution_complete"], true);
        assert_eq!(joined["complete"], false);
        assert_eq!(joined["answers"][0]["answer_status"], "legacy_unknown");
        assert_eq!(joined["answers"].as_array().unwrap().len(), 2);
        assert_eq!(
            joined["answers"][0]["report_sha256"],
            work["packages"][0]["outputs"][0]["report_sha256"]
        );
        for replacement in [Value::Null, json!("b".repeat(64))] {
            let mut changed = work.clone();
            changed["packages"][0]["outputs"][0]["report_sha256"] = replacement;
            assert!(
                joined_result(
                    fixture.root.path(),
                    &fixture.selected,
                    &verified,
                    &fixture.expected,
                    &changed
                )
                .is_err()
            );
        }
        let mut changed = work;
        changed["packages"][0]["task"] = Value::Null;
        assert!(
            joined_result(
                fixture.root.path(),
                &fixture.selected,
                &verified,
                &fixture.expected,
                &changed
            )
            .is_err()
        );
    }
}
