//! Signed publication and real framed local IPC tests, not tokenizer/model execution proof.

use super::super::{rpc, task};
use super::*;
use crate::compute::{ModelProfile, document_plan::Plan, inference_output::Generation};
use ed25519_dalek::SigningKey;
use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

#[path = "frontier_tests.rs"]
mod frontier_tests;

fn parent(text: &str) -> synthesis::Answer {
    synthesis::Answer {
        text: "Protocol fixture partial answer".into(),
        provider_key: hex::encode(SigningKey::from_bytes(&[44; 32]).verifying_key().as_bytes()),
        job_id: "1".repeat(32),
        report_sha256: "2".repeat(64),
        package_manifest_id: "3".repeat(64),
        model_fingerprint: "4".repeat(64),
        output_index: 0,
        source_start: 0,
        source_end: text.len() as u64,
        generated_tokens: 64,
        text_truncated: false,
        generation: Some(Generation {
            version: 1,
            model_profile: ModelProfile::default(),
            output_contract: None,
            stop_reason: StopReason::TokenLimit,
            max_new_tokens: 64,
        }),
    }
}

fn input(text: &str) -> Input {
    Input {
        version: 1,
        model_profile: ModelProfile::default(),
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        document: text.into(),
        question: "Summarize the public text.".into(),
        synthesis: false,
        original_source: None,
    }
}

fn parser_plan(input: &Input, parts: &[(u64, u64)]) -> Plan {
    // Explicit synthetic parser counts only. Production calls the pinned real tokenizer.
    let profile = input.model_profile.spec();
    serde_json::from_value(json!({"version":1,"source_sha256":storage::sha(input.document.as_bytes()),
        "source_bytes":input.document.len(),"question_sha256":storage::sha(input.question.as_bytes()),
        "model_id":profile.model_id,"model_revision":profile.revision,"prompt_limit":profile.prompt_tokens,
        "tokenizer_sha256":"9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c",
        "parts":parts.iter().map(|(start,end)| json!({"start":start,"end":end,"prompt_tokens":80})).collect::<Vec<_>>()})).unwrap()
}

fn options(root: &Path) -> Options {
    #[derive(clap::Parser)]
    struct Command {
        #[command(flatten)]
        options: Options,
    }
    <Command as clap::Parser>::parse_from([
        "document",
        "--directory",
        root.to_str().unwrap(),
        "--resume",
        "--max-batches",
        "4",
        "--execute",
    ])
    .options
}

struct Fixture {
    root: tempfile::TempDir,
    input: Input,
    plan: Plan,
    enrollment: super::super::storage::Enrollment,
    signer: SigningKey,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let input = input("alpha beta gamma delta. Other original answer.");
    let split = 23;
    let plan = parser_plan(&input, &[(0, split), (split, input.document.len() as u64)]);
    task::write_bytes(
        &root.path().join("source.txt"),
        input.document.as_bytes(),
        false,
    )
    .unwrap();
    super::super::save(root.path(), "planner-input.json", &input, false).unwrap();
    let signer = SigningKey::from_bytes(&[42; 32]);
    let providers = [
        SigningKey::from_bytes(&[44; 32]).verifying_key(),
        SigningKey::from_bytes(&[45; 32]).verifying_key(),
    ];
    let (_, cancel) = watch::channel(false);
    let mut enrollment = super::super::storage::publish(
        root.path(),
        &input,
        &plan,
        &signer,
        &providers,
        super::super::now().unwrap() - 1,
        1200,
        &cancel,
        true,
    )
    .unwrap();
    enrollment.scheduling = workflow::Scheduling::ReadyRowsV1;
    enrollment.refine_incomplete = true;
    super::super::save(root.path(), "document.json", &enrollment, false).unwrap();
    Fixture {
        root,
        input,
        plan,
        enrollment,
        signer,
    }
}

#[test]
fn only_untruncated_token_limit_is_eligible_and_utf8_ranges_cover_exact_original() {
    for text in ["alpha beta gamma", "één東京三", "A💡B", "  left   right "] {
        let original = input(text);
        let mut answer = parent(text);
        assert!(eligible(&answer));
        let [(start, middle), (again, end)] = halves(&original, &answer).unwrap().unwrap();
        assert_eq!((start, again, end), (0, middle, text.len() as u64));
        let middle = usize::try_from(middle).unwrap();
        assert!(text.is_char_boundary(middle));
        assert!(!text[..middle].trim().is_empty());
        assert!(!text[middle..].trim().is_empty());
        answer.text_truncated = true;
        assert!(!eligible(&answer));
        answer.text_truncated = false;
        answer.generation = None;
        assert!(!eligible(&answer));
        assert!(!complete(&answer));
        answer.generation = parent(text).generation;
        answer.generation.as_mut().unwrap().stop_reason = StopReason::Eos;
        assert!(!eligible(&answer));
        assert!(complete(&answer));
        answer.text.clear();
        assert!(!complete(&answer) && !eligible(&answer));
    }
    assert!(halves(&input("é"), &parent("é")).unwrap().is_none());
}

#[test]
fn intent_replay_is_byte_identical_and_rejects_changed_parent_or_authority() {
    let mut fixture = fixture();
    let mut answer = parent(&fixture.input.document);
    let ranges = halves(&fixture.input, &answer).unwrap().unwrap();
    let root = fixture.root.path().join("refinement/leaf-0000");
    let first = storage::intent(
        &root,
        &fixture.enrollment,
        &fixture.input,
        &answer,
        0,
        ranges,
    )
    .unwrap();
    let bytes = fs::read(root.join("intent.json")).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&first).unwrap());
    storage::intent(
        &root,
        &fixture.enrollment,
        &fixture.input,
        &answer,
        0,
        ranges,
    )
    .unwrap();
    assert_eq!(fs::read(root.join("intent.json")).unwrap(), bytes);
    answer.report_sha256 = "a".repeat(64);
    assert!(
        storage::intent(
            &root,
            &fixture.enrollment,
            &fixture.input,
            &answer,
            0,
            ranges
        )
        .is_err()
    );
    answer = parent(&fixture.input.document);
    fixture.enrollment.expires_at_unix_seconds += 1;
    assert!(
        storage::intent(
            &root,
            &fixture.enrollment,
            &fixture.input,
            &answer,
            0,
            ranges
        )
        .is_err()
    );
    fixture.enrollment.expires_at_unix_seconds -= 1;
    fixture.enrollment.provider_keys.reverse();
    assert!(
        storage::intent(
            &root,
            &fixture.enrollment,
            &fixture.input,
            &answer,
            0,
            ranges
        )
        .is_err()
    );
    assert_eq!(fs::read(root.join("intent.json")).unwrap(), bytes);
}

// Retain synthetic tokenizer plans and genuine signed child publications, so the
// following tests exercise peer admission/receipt replay without executing a model.
fn retain_children(fixture: &Fixture, answer: &synthesis::Answer) -> Vec<PathBuf> {
    retain_children_at(
        fixture,
        answer,
        &fixture.root.path().join("refinement/leaf-0000"),
    )
}

fn retain_children_at(fixture: &Fixture, answer: &synthesis::Answer, root: &Path) -> Vec<PathBuf> {
    use volparossa_content::provider::compute::dataset::{
        DOCUMENT_CONTENT_TYPE, DocumentDataset, DocumentQuestion,
    };
    use volparossa_content::{CacheLimits, ChunkStore, Validity};
    let ranges = halves(&fixture.input, answer).unwrap().unwrap();
    storage::intent(root, &fixture.enrollment, &fixture.input, answer, 0, ranges).unwrap();
    let mut cache = ChunkStore::create(
        &root.join("test-publication-cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 32,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    ranges
        .into_iter()
        .enumerate()
        .map(|(child, (start, end))| {
            let directory = root.join(format!("child-{child}"));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let child_input = input(
                &fixture.input.document
                    [usize::try_from(start).unwrap()..usize::try_from(end).unwrap()],
            );
            super::super::save(&directory, "planner-input.json", &child_input, false).unwrap();
            super::super::save(
                &directory,
                "document-plan.json",
                &parser_plan(&child_input, &[(0, end - start)]),
                false,
            )
            .unwrap();
            let dataset = DocumentDataset {
                version: 2,
                visibility: "public".into(),
                license: fixture.input.license.clone(),
                source_manifest_hex: hex::encode(
                    fs::read(fixture.root.path().join("source.manifest")).unwrap(),
                ),
                inference: vec![DocumentQuestion {
                    question: fixture.input.question.clone(),
                    context: child_input.document,
                    start,
                    end,
                }],
            };
            let bytes = serde_json::to_vec(&dataset).unwrap();
            let manifest = super::super::storage::publish_object(
                &bytes,
                format!("refined-leaf-0000-child-{child}"),
                DOCUMENT_CONTENT_TYPE,
                Validity {
                    created: fixture.enrollment.selected_at_unix_seconds,
                    expires: fixture.enrollment.expires_at_unix_seconds,
                },
                &fixture.signer,
                &mut cache,
            )
            .unwrap();
            task::write_bytes(
                &directory.join("dataset.manifest"),
                &manifest.encode(),
                false,
            )
            .unwrap();
            directory
        })
        .collect()
}

fn capabilities() -> rpc::Capabilities {
    use volparossa_content::agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION};
    let model = rpc::ModelIdentity {
        model_id: MODEL_ID.into(),
        model_revision: MODEL_REVISION.into(),
        base_weights: rpc::FileIdentity {
            bytes: 269_060_552,
            sha256: hex::encode(BASE_MODEL_SHA256),
        },
        adapter_files: None,
    };
    rpc::Capabilities {
        model_fingerprint: storage::sha(&serde_json::to_vec(&model).unwrap()),
        model,
        accepting_work: true,
        public_inference_only: true,
        runtime_slots: 1,
        max_threads: 2,
        max_job_seconds: 600,
        max_dataset_bytes: 1024 * 1024,
        max_rows: 4,
        task_derivation_v1: true,
        document_inference_v2: true,
        derived_inference_v3: true,
        principle_inference_v4: false,
        successor_activation_v1: false,
    }
}

async fn serve_protocol_fixture(
    listener: tokio::net::UnixListener,
    original_manifest: String,
    submissions: std::sync::Arc<std::sync::Mutex<Vec<rpc::JobBinding>>>,
    limit_first_child: bool,
) {
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ComputeReady, ControlResponse, ControlResult, Empty,
        control_request::Operation, control_response::Payload,
    };
    let caps = capabilities();
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let control = volparossa_local_control::read_request(&mut stream)
            .await
            .unwrap();
        let Some(Operation::ComputeRemote(remote)) = control.operation else {
            panic!("not compute");
        };
        assert!(!remote.retain_transcript);
        let mut response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: control.request_id,
            result: ControlResult::Ok as i32,
            diagnostic_code: "COMPUTE_RPC_READY".into(),
            payload: Some(Payload::ComputeReady(ComputeReady {
                provider_key: remote.provider_key,
                requester_key: vec![42; 32],
            })),
        };
        volparossa_local_control::write_response(&mut stream, &response)
            .await
            .unwrap();
        let request = rpc::read_request(&mut stream).await.unwrap();
        request.validate(super::super::now().unwrap()).unwrap();
        let outcome = match request.operation {
            rpc::Operation::Capabilities => rpc::Outcome::Capabilities(caps.clone()),
            rpc::Operation::Submit(submit) => {
                assert_eq!(
                    storage::sha(submit.dataset_json.as_bytes()),
                    submit.binding.dataset_sha256
                );
                assert_eq!(submit.binding.model_fingerprint, caps.model_fingerprint);
                // Synthetic answers only; the real protocol, signed datasets, durable
                // handles and receipt validation are under test, not ML inference.
                let original = submit.binding.dataset_manifest_id == original_manifest;
                let source: volparossa_content::provider::compute::dataset::DocumentDataset =
                    serde_json::from_str(&submit.dataset_json).unwrap();
                let row = &source.inference[0];
                let limited = (original && submit.binding.row_indices == [0])
                    || (limit_first_child && !original && row.start == 0 && row.end > 6);
                let report=json!({"mode":"infer","status":"ok","updates_completed":0,
                    "dataset":{"sha256":submit.binding.dataset_sha256,"visibility":"public","inference_examples":1},
                    "model":{"id":caps.model.model_id,"revision":caps.model.model_revision,
                        "files":{"model.safetensors":caps.model.base_weights}},
                    "supervisor":{"child_reaped":true,"network_access":false},
                    "outputs":[{"sample_index":0,"text":"Synthetic protocol fixture answer; no model execution.",
                        "generated_tokens":if limited {64}else{12},"text_truncated":false,
                        "generation":{"version":1,"stop_reason":if limited {"token_limit"}else{"eos"},"max_new_tokens":64}}]}).to_string();
                submissions.lock().unwrap().push(submit.binding.clone());
                rpc::Outcome::Job(rpc::JobStatus {
                    binding: submit.binding,
                    state: rpc::JobState::Complete,
                    cancellation_requested: false,
                    report_sha256: Some(storage::sha(report.as_bytes())),
                    report_json: Some(report),
                    error: None,
                })
            }
            unexpected => panic!("unexpected fixture operation: {unexpected:?}"),
        };
        rpc::write_response(
            &mut stream,
            &rpc::Response {
                version: rpc::VERSION,
                request_id: request.request_id,
                outcome,
            },
        )
        .await
        .unwrap();
        response.diagnostic_code = "COMPUTE_RPC_OK".into();
        response.payload = Some(Payload::Ack(Empty {}));
        volparossa_local_control::write_response(&mut stream, &response)
            .await
            .unwrap();
    }
}

fn retained_receipts(directory: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut receipts = Vec::new();
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            receipts.extend(retained_receipts(&path));
        } else if path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("receipt-")
        {
            receipts.push((path.clone(), fs::read(path).unwrap()));
        }
    }
    receipts
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One real IPC lifecycle retains original and child receipts across cancellation and resume"
)]
async fn bounded_real_ipc_refinement_preserves_originals_and_resumes_only_unfinished_children() {
    let fixture = fixture();
    let sockets = tempfile::tempdir().unwrap();
    let socket = sockets.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let submissions = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let server = tokio::spawn(serve_protocol_fixture(
        listener,
        fixture.enrollment.packages[0].manifest_id.clone(),
        submissions.clone(),
        false,
    ));
    let (owner, cancelled) = watch::channel(false);
    let mut args = options(fixture.root.path());
    let providers = fixture
        .enrollment
        .provider_keys
        .iter()
        .map(|key| parse_key(key).unwrap())
        .collect::<Vec<_>>();
    let original_root = fixture.root.path().join("package-0000");
    let expected = super::super::storage::expected(
        &original_root,
        &fixture.enrollment,
        &fixture.enrollment.packages[0],
        &fixture.input,
        &fixture.plan,
    )
    .unwrap();
    let original = workflow::Options::task(
        Some(original_root.join("workflow-plan.json")),
        original_root.join("work"),
        providers,
        4,
        600,
        true,
    )
    .expect_task(expected);
    let report = workflow::report_group_with_activity(
        &[original],
        4,
        &super::super::super::follow::Options::default(),
        &socket,
        &cancelled,
    )
    .await
    .unwrap();
    assert_eq!(report["complete"], true);
    let originals = synthesis::leaf_answers(
        fixture.root.path(),
        &fixture.enrollment,
        &fixture.input,
        &fixture.plan,
    )
    .unwrap();
    assert_eq!(originals.len(), 2);
    assert!(eligible(&originals[0]) && complete(&originals[1]));
    let original_receipts = retained_receipts(&original_root);
    assert_eq!(original_receipts.len(), 2);
    assert_eq!(submissions.lock().unwrap().len(), 2);

    let original_view = json!({"execution_complete":true,"complete":false,"rounds_this_invocation":0,
        "answers":["Original public projection remains unchanged."]});
    let mut result = original_view.clone();
    args.max_batches = 0;
    assert!(
        advance(&args, &socket, &cancelled, &mut result)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(result["execution_complete"], false);
    assert!(!fixture.root.path().join("refinement").exists());

    let children = retain_children(&fixture, &originals[0]);
    // Cancellation before dispatch preserves enrollment without claiming the child jobs ran.
    args.max_batches = 1;
    owner.send(true).unwrap();
    result = original_view.clone();
    assert!(
        advance(&args, &socket, &cancelled, &mut result)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(result["interrupted"], true);
    assert_eq!(result["execution_complete"], false);
    assert!(children.iter().all(|path| !path.join("work").exists()));
    owner.send(false).unwrap();

    // One shared round admits at most one new child workflow, not a separate
    // max_batches allowance for every child. The following invocation resumes it.
    result = original_view.clone();
    let first = advance(&args, &socket, &cancelled, &mut result)
        .await
        .unwrap();
    assert!(first.is_none());
    assert_eq!(result["rounds_this_invocation"], 1);
    assert_eq!(result["execution_complete"], false);
    assert_eq!(result["answers"], original_view["answers"]);
    assert_eq!(submissions.lock().unwrap().len(), 3);
    let first_child = retained_receipts(&fixture.root.path().join("refinement"));
    assert_eq!(first_child.len(), 1);
    result = original_view.clone();
    let frontier = advance(&args, &socket, &cancelled, &mut result)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(submissions.lock().unwrap().len(), 4);
    assert_eq!(result["rounds_this_invocation"], 1);
    assert_eq!(result["refinement"]["complete"], true);
    assert_eq!(result["execution_complete"], true);
    assert_eq!(frontier.len(), 3);
    assert_eq!(frontier[2], originals[1]);
    assert!(frontier.iter().all(complete));
    assert_eq!(frontier[0].source_start, 0);
    assert_eq!(frontier[0].source_end, frontier[1].source_start);
    assert_eq!(frontier[1].source_end, frontier[2].source_start);
    assert_eq!(frontier[2].source_end, fixture.input.document.len() as u64);
    for (path, bytes) in original_receipts.iter().chain(&first_child) {
        assert_eq!(fs::read(path).unwrap(), *bytes);
    }
    let repaired_receipts = retained_receipts(&fixture.root.path().join("refinement"));
    assert_eq!(repaired_receipts.len(), 2);
    server.abort();
    let _ = server.await;
    result = original_view.clone();
    args.max_batches = 0;
    let replay = advance(
        &args,
        &sockets.path().join("no-agent.sock"),
        &cancelled,
        &mut result,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(replay, frontier);
    assert_eq!(result["rounds_this_invocation"], 0);
    assert_eq!(result["answers"], original_view["answers"]);

    // A forged aggregate does not stand in for one missing full child receipt.
    let (receipt, bytes) = &repaired_receipts[0];
    fs::remove_file(receipt).unwrap();
    result = original_view.clone();
    assert!(
        advance(
            &args,
            &sockets.path().join("no-agent.sock"),
            &cancelled,
            &mut result
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(result["refinement"]["complete"], false);
    assert_eq!(result["execution_complete"], false);
    task::write_bytes(receipt, bytes, false).unwrap();
    for (path, bytes) in original_receipts {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
