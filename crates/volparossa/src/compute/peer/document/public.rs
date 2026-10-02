//! Fixed operator configuration for the real public-document browser backend.

mod diagnostic;
mod reconciliation;

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use tokio::sync::watch;

use super::{Options, Phase, parse_key, private_directory, rpc, task};
use crate::compute::ModelProfile;
use diagnostic::{ReceiptObservation, ReceiptPhase};

#[derive(Clone, Debug, Args)]
pub(in crate::compute) struct Config {
    #[arg(long)]
    pub runtime_root: PathBuf,
    #[arg(long)]
    pub model_root: PathBuf,
    #[arg(long, default_value_t = ModelProfile::default())]
    pub model_profile: ModelProfile,
    /// Existing encrypted publisher identity, never supplied by an IPC request.
    #[arg(long)]
    pub identity: PathBuf,
    #[arg(long)]
    pub passphrase_file: PathBuf,
    #[arg(long, value_parser = parse_key)]
    pub publisher_key: VerifyingKey,
    /// Two to four fixed compatible workers; alternatively use authenticated discovery.
    #[arg(long, required_unless_present = "discover_peers", conflicts_with = "discover_peers", value_parser = parse_key)]
    pub provider_key: Vec<VerifyingKey>,
    /// Select two to four eligible peers in the operator-selected model cohort for each new task.
    #[arg(long, conflicts_with = "provider_key")]
    discover_peers: bool,
    /// Optional exact base/adapter fingerprint within the selected discovery profile.
    #[arg(long, requires = "discover_peers", conflicts_with = "provider_key", value_parser = super::discovery::parse_fingerprint)]
    model_fingerprint: Option<String>,
    /// Authorize a bounded pass of smaller source jobs when a leaf reaches its output limit.
    #[arg(long)]
    refine_incomplete: bool,
    /// Explicit owner permission for up to four source-refinement levels, sharing one budget.
    #[arg(long, default_value_t = 1, requires = "refine_incomplete", value_parser = clap::value_parser!(u8).range(1..=4))]
    refinement_levels: u8,
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    pub max_seconds: u16,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=2))]
    pub threads: u16,
    #[command(flatten)]
    source_limits: crate::content::Limits,
}

impl Config {
    fn validate_selection(&self) -> Result<()> {
        let fixed = (2..=4).contains(&self.provider_key.len())
            && self
                .provider_key
                .iter()
                .map(VerifyingKey::to_bytes)
                .collect::<BTreeSet<_>>()
                .len()
                == self.provider_key.len();
        ensure!(
            (if self.discover_peers {
                self.provider_key.is_empty()
            } else {
                fixed && self.model_fingerprint.is_none()
            }) && (1..=600).contains(&self.max_seconds)
                && (1..=2).contains(&self.threads),
            "compute_public_fixed_configuration"
        );
        ensure!(
            (1..=4).contains(&self.refinement_levels)
                && (self.refinement_levels == 1 || self.refine_incomplete),
            "compute_public_refinement_levels"
        );
        ensure!(
            self.model_profile != ModelProfile::Qwen600,
            "compute_profile_private_conversation_only"
        );
        if let Some(fingerprint) = &self.model_fingerprint {
            super::discovery::parse_fingerprint(fingerprint).map_err(anyhow::Error::msg)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_selection()?;
        private_directory(&self.runtime_root)?;
        private_directory(&self.model_root)?;
        ensure!(
            self.runtime_root.join("bin/python3").is_file()
                && self.model_root.join("model.safetensors").is_file(),
            "compute_public_runtime_missing"
        );
        for path in [&self.identity, &self.passphrase_file] {
            ensure!(
                path.is_absolute() && fs::canonicalize(path)? == *path,
                "compute_public_signer_path"
            );
        }
        let signer =
            crate::content::unlock_signer(Some(&self.identity), Some(&self.passphrase_file))?;
        ensure!(
            signer.verifying_key() == self.publisher_key,
            "compute_document_publisher_identity"
        );
        Ok(())
    }

    fn options(&self, root: &Path, question: String, license: String) -> Options {
        // Reuse the existing selector, without its CLI-only --resume conflicts.
        // Replacement discovery stays disabled: this service reports one enrolled cohort.
        let mut discovery = super::discovery::Options::default();
        discovery.discover_peers = self.discover_peers;
        discovery
            .model_fingerprint
            .clone_from(&self.model_fingerprint);
        Options {
            directory: root.join("document"),
            resume: false,
            batch_barrier: false,
            synthesize: true,
            refine_incomplete: self.refine_incomplete,
            refinement_levels: self.refinement_levels,
            task_plan: None,
            plan_tasks: false,
            plan_task_graph: false,
            grounded_synthesis: false,
            plan_structure: None,
            input: Some(root.join("input.txt")),
            source_plan: None,
            source_cache: None,
            reuse_source_cache: false,
            source_limits: self.source_limits.clone(),
            public_content: true,
            public_question: Some(question),
            license: Some(license),
            runtime_root: Some(self.runtime_root.clone()),
            model_root: Some(self.model_root.clone()),
            model_profile: self.model_profile,
            identity: Some(self.identity.clone()),
            passphrase_file: Some(self.passphrase_file.clone()),
            publisher_key: Some(self.publisher_key),
            provider_key: self.provider_key.clone(),
            discovery,
            lifetime_seconds: 86_400,
            max_batches: 32,
            follow: super::super::follow::Options::default(),
            max_seconds: self.max_seconds,
            threads: self.threads,
            execute: true,
            enroll_only: false,
        }
    }
}

pub(in crate::compute) struct Execution {
    pub result: Result<Value>,
    pub cleanup_confirmed: bool,
}

pub(in crate::compute) async fn execute(
    config: &Config,
    root: &Path,
    socket: &Path,
    question: String,
    context: String,
    license: String,
    cancelled: &watch::Receiver<bool>,
) -> Execution {
    let options = config.options(root, question, license);
    let mut phase = Phase::Input;
    let result = async {
        private_directory(root)?;
        ensure!(
            !*cancelled.borrow(),
            "compute_document_cancelled_before_planning"
        );
        task::write_bytes(&root.join("input.txt"), context.as_bytes(), false)?;
        super::report_with_phase(&options, socket, cancelled, &mut phase).await
    }
    .await;
    let execution_complete = result
        .as_ref()
        .ok()
        .and_then(|value| value["execution_complete"].as_bool());
    let answer_complete = result
        .as_ref()
        .ok()
        .and_then(|value| value["answer_complete"].as_bool());
    // Failed/ambiguous execution must never free the admission slot just because the
    // coordinator future returned. Reconcile every original handle, including abandoned
    // retries, without creating or renewing work; then recheck durable terminal receipts.
    let reconciliation = reconciliation::run(root, socket).await;
    let mut receipts = ReceiptObservation::default();
    let remote_cleanup = terminal_receipts(root, &mut receipts).unwrap_or_else(|error| {
        receipts.error = diagnostic::classify(&error);
        false
    });
    receipts.confirmed = remote_cleanup;
    let local_cleanup = result.is_ok()
        // This phase contains capability/discovery RPCs only. No tokenizer or peer
        // job has started, and the separate exact-receipt check still gates cleanup.
        || matches!(phase, Phase::ProviderSelection)
        || result.as_ref().is_err_and(|error| {
            matches!(
                error.to_string().as_str(),
                "compute_document_cancelled_before_planning"
                    | "compute_document_cancelled_before_publication"
                    | "compute_document_cancelled"
                    | "compute_owner_busy"
            ) || error
                .downcast_ref::<crate::compute::supervise::WorkerFailure>()
                .is_some()
        });
    let cleanup_confirmed = local_cleanup && remote_cleanup;
    let result = result.and_then(|report| {
        phase = Phase::Compaction;
        let selected = selected_provider_keys(&root.join("document"), &report, config)?;
        let compact = compact(&report, config, &selected, cleanup_confirmed)?;
        phase = Phase::Complete;
        Ok(compact)
    });
    let mut observation =
        diagnostic::report(phase, &result, local_cleanup, &receipts, cleanup_confirmed);
    observation["version"] = 2.into();
    observation["execution_complete"] = execution_complete.into();
    observation["answer_complete"] = answer_complete.into();
    observation["reconciliation"] =
        serde_json::to_value(&reconciliation).expect("closed reconciliation fields");
    // Diagnostic write failure does not change execution/cleanup truth or reopen a gate.
    // The fixture reports this file as absent/invalid, never exports raw coordinator state.
    let _ = task::write_bytes(
        &root.join("execution-diagnostic.json"),
        observation.to_string().as_bytes(),
        false,
    );
    Execution {
        result,
        cleanup_confirmed,
    }
}

fn selected_provider_keys(root: &Path, report: &Value, config: &Config) -> Result<Vec<String>> {
    let (enrollment, input, plan) = super::storage::load(root)?;
    ensure!(
        enrollment.synthesize
            && enrollment.refine_incomplete == config.refine_incomplete
            && enrollment.refinement_levels == config.refinement_levels
            && !enrollment.replace_peers
            && enrollment.publisher_key == hex::encode(config.publisher_key.as_bytes())
            && input.model_profile == config.model_profile
            && enrollment.model_fingerprint.is_some()
            && config
                .model_fingerprint
                .as_ref()
                .is_none_or(|expected| enrollment.model_fingerprint.as_ref() == Some(expected))
            && report["source_manifest_id"] == enrollment.source_manifest_id
            && report["source_sha256"] == plan.source_sha256
            && report["source_bytes"] == plan.source_bytes
            && report["public_question"] == input.question
            && report["license"] == input.license,
        "compute_public_retained_selection_binding"
    );
    ensure!(
        config.discover_peers
            || enrollment.provider_keys
                == config
                    .provider_key
                    .iter()
                    .map(|key| hex::encode(key.as_bytes()))
                    .collect::<Vec<_>>(),
        "compute_public_fixed_selection_changed"
    );
    Ok(enrollment.provider_keys)
}

fn compact(report: &Value, config: &Config, selected: &[String], cleanup: bool) -> Result<Value> {
    ensure!(
        report["operation"] == "compute_public_document"
            && report["complete"].is_boolean()
            && report["execution_complete"].is_boolean(),
        "compute_public_report_shape"
    );
    let mut providers = BTreeSet::new();
    let mut collect = |answers: &Value| -> Result<()> {
        if let Some(answers) = answers.as_array() {
            for answer in answers {
                let key = answer["provider_key"]
                    .as_str()
                    .context("compute_public_answer_provider")?;
                parse_key(key).map_err(anyhow::Error::msg)?;
                providers.insert(key.to_owned());
            }
        }
        Ok(())
    };
    collect(&report["answers"])?;
    collect(&report["refinement"]["answers"])?;
    if let Some(levels) = report["synthesis"]["levels"].as_array() {
        for level in levels {
            collect(&level["answers"])?;
        }
    }
    ensure!(
        providers.iter().all(|provider| selected.contains(provider)),
        "compute_public_result_provider_not_selected"
    );
    let text = report["synthesized_answer"]["text"].as_str().unwrap_or("");
    ensure!(
        text.len() <= config.model_profile.spec().max_output_bytes,
        "compute_public_answer_bound"
    );
    let complete = report["complete"] == true;
    ensure!(
        !complete || (!text.trim().is_empty() && report["answer_complete"] == true),
        "compute_public_complete_answer"
    );
    Ok(
        json!({"answer_complete":complete,"answer_status":if complete {"complete"} else {"incomplete"},
        "output":{"text":text},"provider_keys":providers,
        "selected_provider_keys":selected,
        "joining":report["joining"],"execution_complete":report["execution_complete"],
        "package_count":report["packages"].as_array().context("compute_public_packages")?.len(),
        "total_parts":report["total_parts"],
        "synthesis_levels":report["synthesis"]["levels"].as_array().map_or(0, Vec::len),
        "source_manifest_id":report["source_manifest_id"],
        "remote_cleanup_confirmed":cleanup,"cleanup":{"complete":cleanup},
        "retained_public_receipts":true,"model_answer_correctness_proven":false,
        "semantic_completeness_proven":false}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    handle: super::super::JobHandle,
    status: rpc::JobStatus,
    verified_at_unix_seconds: u64,
}

/// Recheck coordinator-retained, exact authenticated RPC observations. This does not
/// upgrade them into independently portable execution attestations or remote erasure.
fn retained_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut directories = vec![(root.to_path_buf(), 0)];
    let mut paths = Vec::new();
    let mut entries = 0;
    while let Some((directory, depth)) = directories.pop() {
        private_directory(&directory)?;
        ensure!(depth <= 20, "compute_public_retained_depth");
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            entries += 1;
            ensure!(entries <= 16_384, "compute_public_retained_entries");
            let kind = entry.file_type()?;
            ensure!(
                kind.is_dir() || kind.is_file(),
                "compute_public_retained_type"
            );
            if kind.is_dir() {
                directories.push((entry.path(), depth + 1));
            } else {
                paths.push(entry.path());
            }
        }
    }
    Ok(paths)
}

fn terminal_receipts(root: &Path, observed: &mut ReceiptObservation) -> Result<bool> {
    let (handles, terminal) = scan_receipts(root, observed)?;
    let confirmed = handles.keys().all(|id| terminal.contains(id));
    observed.phase = if confirmed {
        ReceiptPhase::Complete
    } else {
        ReceiptPhase::MissingTerminal
    };
    Ok(confirmed)
}

fn scan_receipts(
    root: &Path,
    observed: &mut ReceiptObservation,
) -> Result<(BTreeMap<String, super::super::JobHandle>, BTreeSet<String>)> {
    let paths = retained_paths(root)?;
    let mut handles = BTreeMap::new();
    for path in &paths {
        if matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("job-0.json" | "job-1.json" | "job-2.json" | "job-3.json")
        ) {
            observed.phase = ReceiptPhase::ReadHandle;
            let bytes = super::read_file(path, 65_536)?;
            observed.phase = ReceiptPhase::DecodeHandle;
            let handle: super::super::JobHandle = serde_json::from_slice(&bytes)?;
            observed.phase = ReceiptPhase::DuplicateHandle;
            ensure!(
                handles
                    .insert(handle.binding.job_id.clone(), handle)
                    .is_none(),
                "compute_public_duplicate_handle"
            );
            observed.handles = handles.len();
        }
    }
    let mut terminal = BTreeSet::new();
    for path in &paths {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("receipt-")
            || path.extension().is_none_or(|extension| extension != "json")
        {
            continue;
        }
        observed.phase = ReceiptPhase::ReadReceipt;
        let bytes = super::read_file(path, rpc::MAX_RESPONSE_BYTES + 32768)?;
        observed.phase = ReceiptPhase::DecodeReceipt;
        let receipt: Receipt = serde_json::from_slice(&bytes)?;
        observed.receipts += 1;
        let id = &receipt.handle.binding.job_id;
        observed.phase = ReceiptPhase::HandleLookup;
        let handle = handles
            .get(id)
            .context("compute_public_receipt_without_handle")?;
        observed.phase = ReceiptPhase::Binding;
        ensure!(
            receipt.version == 1
                && name == format!("receipt-{id}.json")
                && receipt.verified_at_unix_seconds <= super::now()?
                && serde_json::to_vec(handle)? == serde_json::to_vec(&receipt.handle)?,
            "compute_public_retained_receipt_binding"
        );
        observed.phase = ReceiptPhase::StatusValidation;
        let status = super::super::job(rpc::Outcome::Job(receipt.status), handle)?;
        if matches!(
            status.state,
            rpc::JobState::Complete | rpc::JobState::Failed | rpc::JobState::Cancelled
        ) {
            terminal.insert(id.clone());
            observed.terminal = terminal.len();
        }
    }
    Ok((handles, terminal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::os::unix::fs::PermissionsExt as _;

    fn arguments(extra: &[&str]) -> std::result::Result<Config, clap::Error> {
        #[derive(Parser)]
        struct Command {
            #[command(flatten)]
            config: Config,
        }
        let key = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                .verifying_key()
                .as_bytes(),
        );
        let mut words = vec![
            "public-service",
            "--runtime-root",
            "/unused/runtime",
            "--model-root",
            "/unused/model",
            "--identity",
            "/unused/identity",
            "--passphrase-file",
            "/unused/passphrase",
            "--publisher-key",
            &key,
        ];
        words.extend_from_slice(extra);
        Command::try_parse_from(words).map(|value| value.config)
    }

    #[test]
    fn public_service_can_explicitly_select_authenticated_peers_without_fixed_keys() {
        let discovered =
            arguments(&["--discover-peers", "--model-fingerprint", &"a".repeat(64)]).unwrap();
        discovered.validate_selection().unwrap();
        let options = discovered.options(
            Path::new("/unused/task"),
            "Question?".into(),
            "CC0-1.0".into(),
        );
        assert!(options.discovery.discover_peers);
        assert!(!options.discovery.replace_peers);
        assert_eq!(options.discovery.model_fingerprint, Some("a".repeat(64)));
        assert_eq!(options.model_profile, ModelProfile::default());
        assert!(options.provider_key.is_empty());
        assert!(!options.refine_incomplete);
        let recovering = arguments(&["--discover-peers", "--refine-incomplete"]).unwrap();
        recovering.validate_selection().unwrap();
        let recovery_options = recovering.options(
            Path::new("/unused/recovery"),
            "Question?".into(),
            "CC0-1.0".into(),
        );
        assert!(recovery_options.refine_incomplete && recovery_options.synthesize);
        assert_eq!(recovery_options.refinement_levels, 1);
        let deeper = arguments(&[
            "--discover-peers",
            "--refine-incomplete",
            "--refinement-levels",
            "4",
        ])
        .unwrap();
        deeper.validate_selection().unwrap();
        assert_eq!(
            deeper
                .options(
                    Path::new("/unused/deeper"),
                    "Question?".into(),
                    "CC0-1.0".into()
                )
                .refinement_levels,
            4
        );
        for extra in [
            vec!["--discover-peers", "--refinement-levels", "2"],
            vec![
                "--discover-peers",
                "--refine-incomplete",
                "--refinement-levels",
                "0",
            ],
            vec![
                "--discover-peers",
                "--refine-incomplete",
                "--refinement-levels",
                "5",
            ],
        ] {
            assert!(arguments(&extra).is_err());
        }
        assert_eq!(recovery_options.max_batches, options.max_batches);
        assert_eq!(recovery_options.max_seconds, options.max_seconds);
        let first = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[2; 32])
                .verifying_key()
                .as_bytes(),
        );
        let second = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .as_bytes(),
        );
        let fixed = arguments(&["--provider-key", &first, "--provider-key", &second]).unwrap();
        fixed.validate_selection().unwrap();
        assert!(!fixed.discover_peers);
        for invalid in [
            vec![],
            vec!["--discover-peers", "--provider-key", &first],
            vec![
                "--provider-key",
                &first,
                "--model-fingerprint",
                &"a".repeat(64),
            ],
            vec!["--discover-peers", "--model-fingerprint", "bad"],
            vec!["--discover-peers", "--replace-peers"],
            vec!["--discover-peers", "--resume"],
        ] {
            assert!(arguments(&invalid).is_err(), "accepted {invalid:?}");
        }
        for invalid in [
            vec!["--provider-key", &first],
            vec!["--provider-key", &first, "--provider-key", &first],
            vec!["--discover-peers", "--model-profile", "qwen3-0.6b-v1"],
        ] {
            assert!(arguments(&invalid).unwrap().validate_selection().is_err());
        }
    }

    #[tokio::test]
    async fn unavailable_discovery_before_any_execution_does_not_quarantine_cleanup() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = arguments(&["--discover-peers"]).unwrap();
        let (_owner, cancelled) = watch::channel(false);
        let result = execute(
            &config,
            root.path(),
            &root.path().join("absent-agent.sock"),
            "Public question?".into(),
            "Public context.".into(),
            "CC0-1.0".into(),
            &cancelled,
        )
        .await;
        assert!(result.result.is_err());
        assert!(result.cleanup_confirmed);
        let diagnostic: Value = serde_json::from_slice(
            &fs::read(root.path().join("execution-diagnostic.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(diagnostic["phase"], "provider_selection");
        assert_eq!(diagnostic["receipts"]["handles"], 0);
        assert_eq!(diagnostic["receipts"]["confirmed"], true);
        assert!(!root.path().join("document/document.json").exists());
    }

    fn discovery_fixture() -> (String, volparossa_local_control::ComputeDiscovered) {
        use volparossa_local_control::{ComputeDiscovered, ComputeDiscoveredProvider};
        let spec = ModelProfile::default().spec();
        let model = rpc::ModelIdentity {
            model_id: spec.model_id.into(),
            model_revision: spec.revision.into(),
            base_weights: rpc::FileIdentity {
                bytes: spec.weights_bytes,
                sha256: spec.weights_sha256.into(),
            },
            adapter_files: None,
        };
        let fingerprint = super::super::super::sha(&serde_json::to_vec(&model).unwrap());
        let caps = rpc::Capabilities {
            model,
            model_fingerprint: fingerprint.clone(),
            accepting_work: true,
            public_inference_only: true,
            runtime_slots: 1,
            max_threads: 2,
            max_job_seconds: 600,
            max_dataset_bytes: 1_048_576,
            max_rows: 4,
            task_derivation_v1: true,
            document_inference_v2: true,
            derived_inference_v3: true,
            principle_inference_v4: false,
            successor_activation_v1: false,
        };
        let found = ComputeDiscovered {
            providers: [2, 3]
                .into_iter()
                .map(|byte| ComputeDiscoveredProvider {
                    provider_key: ed25519_dalek::SigningKey::from_bytes(&[byte; 32])
                        .verifying_key()
                        .as_bytes()
                        .to_vec(),
                    capabilities_json: serde_json::to_string(&caps).unwrap(),
                })
                .collect(),
        };
        (fingerprint, found)
    }

    #[tokio::test]
    async fn public_execution_joins_existing_discovery_and_rejects_or_cancels_before_enrollment() {
        use tokio::io::AsyncReadExt as _;
        use volparossa_local_control::{
            CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, control_request::Operation,
            control_response::Payload, read_request, write_response,
        };
        // Real public backend/framed IPC, controlled offers. No model or remote execution.
        for outcome in ["eligible", "insufficient", "wrong_model", "cancel"] {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let sockets = tempfile::tempdir().unwrap();
            let socket = sockets.path().join("agent.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let (fingerprint, mut found) = discovery_fixture();
            let selected = if outcome == "wrong_model" {
                "a".repeat(64)
            } else {
                fingerprint
            };
            let config =
                arguments(&["--discover-peers", "--model-fingerprint", &selected]).unwrap();
            let publisher = config.publisher_key.as_bytes().to_vec();
            let (owner, cancelled) = watch::channel(false);
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await.unwrap();
                let Some(Operation::ComputeDiscover(query)) = request.operation else {
                    panic!("only discovery is permitted before eligibility validation");
                };
                assert_eq!(
                    query.model_profile,
                    Some(ModelProfile::default().to_string())
                );
                assert_eq!(query.model_fingerprint, Some(selected));
                assert_eq!(query.publisher_keys, vec![publisher]);
                assert_eq!((query.maximum, query.effective_minimum()), (4, 2));
                assert!(query.require_task_derivation_v1 && query.require_document_inference_v2);
                assert!(
                    query.require_derived_inference_v3 && !query.require_principle_inference_v4
                );
                if outcome == "cancel" {
                    owner.send(true).unwrap();
                    return;
                }
                if outcome == "insufficient" {
                    found.providers.pop();
                }
                write_response(
                    &mut stream,
                    &ControlResponse {
                        protocol_version: CONTROL_PROTOCOL_VERSION,
                        request_id: request.request_id,
                        result: ControlResult::Ok.into(),
                        diagnostic_code: "COMPUTE_DISCOVERED".into(),
                        payload: Some(Payload::ComputeDiscovered(found)),
                    },
                )
                .await
                .unwrap();
                // Retain cancellation authority until the request consumer closes its stream.
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
            });
            let execution = execute(
                &config,
                root.path(),
                &socket,
                "Public question?".into(),
                "Public context.".into(),
                "CC0-1.0".into(),
                &cancelled,
            )
            .await;
            server.await.unwrap();
            assert!(execution.result.is_err());
            let diagnostic: Value = serde_json::from_slice(
                &fs::read(root.path().join("execution-diagnostic.json")).unwrap(),
            )
            .unwrap();
            if outcome == "eligible" {
                // Valid offers reach tokenization, which intentionally lacks an installed runtime.
                // This later failure is NOT included in the new pre-execution cleanup exception.
                assert_eq!(diagnostic["phase"], "tokenization");
                assert!(!execution.cleanup_confirmed);
            } else {
                assert_eq!(diagnostic["phase"], "provider_selection");
                assert!(execution.cleanup_confirmed);
                let expected = match outcome {
                    "insufficient" => "compute_discovery_insufficient_peers",
                    "wrong_model" => "compute_discovery_ineligible_profile",
                    _ => "compute_discovery_cancelled",
                };
                assert_eq!(execution.result.unwrap_err().to_string(), expected);
            }
            assert_eq!(diagnostic["receipts"]["handles"], 0);
            assert!(!root.path().join("document/document.json").exists());
        }
    }

    fn retained_selection_fixture() -> (tempfile::TempDir, Config, Value) {
        use crate::compute::document_plan::{Input, Plan};
        use ed25519_dalek::SigningKey;
        use sha2::{Digest as _, Sha256};
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let input: Input = serde_json::from_value(json!({"version":1,"visibility":"public",
            "license":"CC0-1.0","document":"Public fixture.","question":"What is stated?"}))
        .unwrap();
        let hash = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
        let profile = ModelProfile::default().spec();
        // Synthetic tokenizer count; signatures/storage are real, model/peer execution is not.
        let plan: Plan = serde_json::from_value(json!({"version":1,
            "source_sha256":hash(input.document.as_bytes()),"source_bytes":input.document.len(),
            "question_sha256":hash(input.question.as_bytes()),"model_id":profile.model_id,
            "model_revision":profile.revision,"prompt_limit":profile.prompt_tokens,
            "tokenizer_sha256":"9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c",
            "parts":[{"start":0,"end":input.document.len(),"prompt_tokens":80}]}))
        .unwrap();
        task::write_bytes(
            &root.path().join("source.txt"),
            input.document.as_bytes(),
            false,
        )
        .unwrap();
        super::super::save(root.path(), "planner-input.json", &input, false).unwrap();
        let providers = [
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            SigningKey::from_bytes(&[3; 32]).verifying_key(),
        ];
        let (_owner, cancelled) = watch::channel(false);
        let mut enrollment = super::super::storage::publish(
            root.path(),
            &input,
            &plan,
            &SigningKey::from_bytes(&[1; 32]),
            &providers,
            super::super::now().unwrap(),
            600,
            &cancelled,
            true,
        )
        .unwrap();
        enrollment.model_fingerprint = Some("a".repeat(64));
        super::super::save(root.path(), "document.json", &enrollment, false).unwrap();
        let report = json!({"operation":"compute_public_document","complete":true,"answer_complete":true,
            "execution_complete":true,"source_manifest_id":enrollment.source_manifest_id,
            "source_sha256":plan.source_sha256,"source_bytes":plan.source_bytes,
            "public_question":input.question,"license":input.license,
            "answers":[{"provider_key":hex::encode(providers[0].as_bytes())}],
            "packages":[{}],"total_parts":1,"synthesized_answer":{"text":"Public fixture."},
            "joining":"single_source_answer"});
        (root, arguments(&["--discover-peers"]).unwrap(), report)
    }

    #[test]
    fn compact_discovery_uses_actual_retained_cohort_and_never_invents_execution() {
        let (root, mut config, report) = retained_selection_fixture();
        let selected = selected_provider_keys(root.path(), &report, &config).unwrap();
        assert!(config.provider_key.is_empty());
        assert_eq!(selected.len(), 2);
        let value = compact(&report, &config, &selected, true).unwrap();
        assert_eq!(value["selected_provider_keys"], json!(selected));
        // A small task may use one of two eligible peers; selected does not mean executed.
        assert_eq!(value["provider_keys"].as_array().unwrap().len(), 1);
        assert_eq!(value["answer_complete"], true);
        let mut recovered = report.clone();
        recovered["refinement"] = json!({"answers":[{"provider_key":selected[1]}]});
        assert_eq!(
            compact(&recovered, &config, &selected, true).unwrap()["provider_keys"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        recovered["refinement"]["answers"][0]["provider_key"] = "f".repeat(64).into();
        assert!(compact(&recovered, &config, &selected, true).is_err());
        config.refine_incomplete = true;
        assert!(selected_provider_keys(root.path(), &report, &config).is_err());
        config.refine_incomplete = false;
        let mut foreign = report.clone();
        foreign["answers"][0]["provider_key"] = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[4; 32])
                .verifying_key()
                .as_bytes(),
        )
        .into();
        assert!(compact(&foreign, &config, &selected, true).is_err());
        for name in [
            "source_manifest_id",
            "source_sha256",
            "public_question",
            "license",
        ] {
            let mut changed = report.clone();
            changed[name] = "changed".into();
            assert!(selected_provider_keys(root.path(), &changed, &config).is_err());
        }
        config.model_fingerprint = Some("b".repeat(64));
        assert!(selected_provider_keys(root.path(), &report, &config).is_err());
        config.model_fingerprint = None;
        config.discover_peers = false;
        config.provider_key = selected.iter().map(|key| parse_key(key).unwrap()).collect();
        assert_eq!(
            selected_provider_keys(root.path(), &report, &config).unwrap(),
            selected
        );
        config.provider_key.reverse();
        assert!(selected_provider_keys(root.path(), &report, &config).is_err());
    }

    #[test]
    fn absent_jobs_are_quiescent_but_unknown_retained_objects_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut observed = ReceiptObservation::default();
        assert!(terminal_receipts(root.path(), &mut observed).unwrap());
        assert_eq!(observed.phase, ReceiptPhase::Complete);
        std::os::unix::fs::symlink("/unused", root.path().join("untrusted")).unwrap();
        assert!(terminal_receipts(root.path(), &mut ReceiptObservation::default()).is_err());
    }

    #[test]
    fn malformed_handle_preserves_decode_stage_without_private_json() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        task::write_bytes(&root.path().join("job-0.json"), b"{\"PRIVATE_PROMPT", false).unwrap();
        let mut observed = ReceiptObservation::default();
        let error = terminal_receipts(root.path(), &mut observed).unwrap_err();
        assert_eq!(observed.phase, ReceiptPhase::DecodeHandle);
        assert_eq!(
            diagnostic::classify(&error),
            diagnostic::ErrorClass::JsonEof
        );
        assert_eq!(observed.handles, 0);
    }
}
