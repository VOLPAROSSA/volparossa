use super::*;
use crate::compute::document_plan::Part;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn retained_file_presence_distinguishes_missing_files_and_rejects_other_types() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let file = root.path().join("retained.json");
    assert!(!file_present(&file).unwrap());
    task::write_bytes(&file, b"{}", false).unwrap();
    assert!(file_present(&file).unwrap());
    assert!(file_present(root.path()).is_err());
    assert!(document_storage::present(&file).is_err());
    assert!(document_storage::present(root.path()).unwrap());
    let link = root.path().join("link.json");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(file_present(&link).is_err());
    let dangling = root.path().join("dangling.json");
    std::os::unix::fs::symlink(root.path().join("absent.json"), &dangling).unwrap();
    assert!(file_present(&dangling).is_err());
}

fn parent(text: &str, index: u16) -> Answer {
    Answer {
        text: text.into(),
        provider_key: hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[17; 32])
                .verifying_key()
                .as_bytes(),
        ),
        job_id: format!("{:032x}", index + 1),
        report_sha256: "1".repeat(64),
        package_manifest_id: "2".repeat(64),
        model_fingerprint: "3".repeat(64),
        output_index: index,
        source_start: u64::from(index) * 100,
        source_end: u64::from(index + 1) * 100,
        generated_tokens: 15,
        text_truncated: false,
    }
}

#[test]
fn every_virtual_parent_byte_survives_unicode_and_cross_answer_tokenizer_cuts() {
    let parents = vec![parent("één", 0), parent("second", 1), parent("三", 2)];
    let input = Input {
        version: 1,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        question: "Combine the answers.".into(),
        document: combined(&parents),
        synthesis: true,
    };
    let mut contexts = String::new();
    // Includes a cut on the newline between answers and a cut inside ASCII text.
    let ends = [2, 5, 9, input.document.len()];
    let mut start = 0;
    for end in ends {
        let part = Part {
            start: start as u64,
            end: end as u64,
            prompt_tokens: 80,
        };
        let question = row(&input, &part, &parents, 64).unwrap();
        let reconstructed: String = question
            .inputs
            .iter()
            .map(|i| {
                assert!((64..=66).contains(&i.parent_index));
                assert_eq!(i.text, parents[(i.parent_index - 64) as usize].text);
                format!("{}\n", i.text)
                    [usize::try_from(i.piece_start).unwrap()..usize::try_from(i.piece_end).unwrap()]
                    .to_owned()
            })
            .collect();
        assert_eq!(reconstructed, question.context);
        contexts.push_str(&question.context);
        start = end;
    }
    assert_eq!(contexts, input.document);
    let bad = Part {
        start: 0,
        end: 1,
        prompt_tokens: 80,
    };
    assert!(row(&input, &bad, &parents, 64).is_err());
}

#[test]
fn resumed_intermediate_inputs_are_never_silently_replaced() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let value = json!({"parents":["original model output"],"level":1});
    retain_json(temp.path(), "parents.json", &value).unwrap();
    let before = read(&temp.path().join("parents.json"), MAX_SAVED_BYTES).unwrap();
    retain_json(temp.path(), "parents.json", &value).unwrap();
    assert!(retain_json(temp.path(), "parents.json", &json!({"parents":["changed"]})).is_err());
    assert_eq!(
        before,
        read(&temp.path().join("parents.json"), MAX_SAVED_BYTES).unwrap()
    );
}

// These token counts and parent report hashes are parser fixtures, not model-run evidence.
fn parser_only_plan(input: &Input) -> Plan {
    use volparossa_content::agent_artifact::{MODEL_ID, MODEL_REVISION};
    serde_json::from_value(
        json!({"version":1,"source_sha256":sha(input.document.as_bytes()),
        "source_bytes":input.document.len(),"question_sha256":sha(input.question.as_bytes()),
        "model_id":MODEL_ID,"model_revision":MODEL_REVISION,
        "tokenizer_sha256":"9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c",
        "prompt_limit":192,"synthesis":input.synthesis,
        "parts":[{"start":0,"end":input.document.len(),"prompt_tokens":80}]}),
    )
    .unwrap()
}

fn replay_options(root: &Path) -> Options {
    #[derive(clap::Parser)]
    struct Defaults {
        #[command(flatten)]
        limits: crate::content::Limits,
    }
    Options {
        discovery: crate::compute::peer::discovery::Options::default(),
        directory: root.into(),
        resume: true,
        batch_barrier: false,
        synthesize: false,
        task_plan: None,
        plan_tasks: false,
        input: None,
        source_plan: None,
        source_cache: None,
        reuse_source_cache: false,
        source_limits: <Defaults as clap::Parser>::parse_from(["limits"]).limits,
        public_content: false,
        public_question: None,
        license: None,
        runtime_root: None,
        model_root: None,
        identity: None,
        passphrase_file: None,
        publisher_key: None,
        provider_key: Vec::new(),
        lifetime_seconds: 600,
        max_batches: 1,
        follow: crate::compute::peer::follow::Options::default(),
        max_seconds: 600,
        threads: 2,
        execute: true,
        enroll_only: false,
    }
}

fn historical_original(
    root: &Path,
    signer: &ed25519_dalek::SigningKey,
    cancelled: &watch::Receiver<bool>,
) -> (document_storage::Enrollment, Input) {
    let input = Input {
        version: 1,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        document: "Original public source. ".repeat(20),
        question: "Combine these public answers.".into(),
        synthesis: false,
    };
    task::write_bytes(&root.join("source.txt"), input.document.as_bytes(), false).unwrap();
    retain_json(root, "planner-input.json", &input).unwrap();
    let providers = [
        ed25519_dalek::SigningKey::from_bytes(&[24; 32]).verifying_key(),
        ed25519_dalek::SigningKey::from_bytes(&[25; 32]).verifying_key(),
    ];
    let enrollment = document_storage::publish(
        root,
        &input,
        &parser_only_plan(&input),
        signer,
        &providers,
        now().unwrap() - 1000,
        600,
        cancelled,
        true,
    )
    .unwrap();
    retain_json(root, "document.json", &enrollment).unwrap();
    document_storage::load(root).unwrap(); // Actual original source bytes, chunks and signatures.
    (enrollment, input)
}

fn historical_reduction(
    root: &Path,
    enrollment: &document_storage::Enrollment,
    original: &Input,
    signer: &ed25519_dalek::SigningKey,
    parents: &[Answer],
) -> (std::path::PathBuf, DerivedDataset) {
    historical_reduction_at(root, enrollment, original, signer, parents, 0)
}

fn historical_reduction_at(
    root: &Path,
    enrollment: &document_storage::Enrollment,
    original: &Input,
    signer: &ed25519_dalek::SigningKey,
    parents: &[Answer],
    offset: usize,
) -> (std::path::PathBuf, DerivedDataset) {
    let directory_root = root.join("synthesis");
    directory(&directory_root).unwrap();
    let group_root = directory_root.join(format!(
        "level-01-group-{:04}",
        offset / super::super::PARENTS_PER_GROUP
    ));
    directory(&group_root).unwrap();
    let input = Input {
        version: 1,
        visibility: "public".into(),
        license: original.license.clone(),
        document: combined(parents),
        question: original.question.clone(),
        synthesis: true,
    };
    let plan = parser_only_plan(&input);
    plan.validate(&input).unwrap();
    retain_json(&group_root, "document-plan.json", &plan).unwrap();
    let group = Group {
        version: 1,
        level: 1,
        parent_offset: offset,
        parents_sha256: sha(&serde_json::to_vec(parents).unwrap()),
        source_manifest_id: enrollment.source_manifest_id.clone(),
        created_at_unix_seconds: enrollment.selected_at_unix_seconds + 100,
    };
    retain_json(&group_root, "group.json", &group).unwrap();
    let dataset = DerivedDataset {
        version: 3,
        visibility: "public".into(),
        license: input.license.clone(),
        source_manifest_hex: hex::encode(
            read(&root.join("source.manifest"), MAX_MANIFEST_BYTES).unwrap(),
        ),
        level: 1,
        claim_scope: DERIVED_CLAIM_SCOPE.into(),
        inference: vec![row(&input, &plan.parts[0], parents, offset).unwrap()],
    };
    dataset.validate_shape().unwrap();
    let prepared = Prepared {
        datasets: vec![dataset.clone()],
        input_sha256: plan.source_sha256,
        parts: 1,
        group,
    };
    let package = group_root.join("package-0000");
    directory(&package).unwrap();
    let bytes = serde_json::to_vec(&dataset).unwrap();
    retain_bytes(
        &package.join("dataset.json"),
        &bytes,
        rpc::MAX_DATASET_BYTES,
    )
    .unwrap();
    retain_json(
        &package,
        "workflow-plan.json",
        &workflow_plan(&package, &enrollment.publisher_key, &input.question),
    )
    .unwrap();
    let mut cache = ChunkStore::create(
        &group_root.join("publication-cache"),
        CacheLimits {
            max_bytes: 64 * 1024 * 1024,
            max_entries: 65_536,
            min_free_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap();
    let publication = document_storage::publish_object(
        &bytes,
        publication_name(&prepared, 0),
        DERIVED_CONTENT_TYPE,
        Validity {
            created: prepared.group.created_at_unix_seconds,
            expires: enrollment.expires_at_unix_seconds,
        },
        signer,
        &mut cache,
    )
    .unwrap();
    retain_bytes(
        &package.join("dataset.manifest"),
        &publication.encode(),
        MAX_MANIFEST_BYTES,
    )
    .unwrap();
    (group_root, dataset)
}

#[tokio::test]
async fn zero_budget_restore_does_not_finish_partially_prepared_groups() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
    let (_owner, cancelled) = watch::channel(false);
    let (mut enrollment, original) = historical_original(temp.path(), &signer, &cancelled);
    enrollment.scheduling = workflow::Scheduling::ReadyRowsV1;
    let parents = vec![parent("First answer.", 0)];
    let (root, _) = historical_reduction(temp.path(), &enrollment, &original, &signer, &parents);
    let mut args = replay_options(temp.path());
    args.max_batches = 0;
    assert!(
        restore(&args, &root, &enrollment, &original, &parents, 0, 1)
            .unwrap()
            .is_none()
    );
    let mut result = json!({"complete":false,"rounds_this_invocation":0});
    let ready = super::super::prepare_frontier(
        &args,
        &cancelled,
        &mut result,
        &enrollment,
        &original,
        parents,
        true,
        &|_, _| panic!("No peer workflow exists in this parser fixture"),
    )
    .await
    .unwrap();
    assert!(ready.is_empty());
    assert_eq!(result["complete"], false);
    assert_eq!(result["synthesis"]["reason"], "invocation_round_budget");
    assert!(!root.join("parents.json").exists());
    assert!(!root.join("planner-input.json").exists());
    assert!(!root.join("tokenizer").exists());
    assert!(!root.join("package-0000/work").exists());
}

#[tokio::test]
async fn external_frontier_keeps_one_parent_instruction_and_uses_owned_snapshot() {
    use std::cell::Cell;
    use std::os::unix::fs::MetadataExt as _;
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
    let (_owner, cancelled) = watch::channel(false);
    let (mut enrollment, original) = historical_original(temp.path(), &signer, &cancelled);
    enrollment.scheduling = workflow::Scheduling::ReadyRowsV1;
    let parents = vec![parent("First answer.", 0)];
    let (root, _) = historical_reduction(temp.path(), &enrollment, &original, &signer, &parents);
    let mut args = replay_options(temp.path());
    prepare(
        &args,
        &root,
        &enrollment,
        &original,
        &parents,
        0,
        1,
        &cancelled,
    )
    .await
    .unwrap();
    args.max_batches = 0;
    let file = root.join("package-0000/dataset.manifest");
    let original_bytes = fs::read(&file).unwrap();
    let inode = fs::metadata(&file).unwrap().ino();
    let mut result = json!({"complete":false,"rounds_this_invocation":0});
    let ready = super::super::prepare_frontier(
        &args,
        &cancelled,
        &mut result,
        &enrollment,
        &original,
        parents.clone(),
        true,
        &|_, _| panic!("Preparation must not dispatch or create a workflow"),
    )
    .await
    .unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(result["complete"], false);
    assert!(result.get("synthesized_answer").is_none());
    assert!(!root.join("package-0000/work").exists());

    // Synthetic receipt callback proves collector control flow, not actual model work.
    // Its directory intentionally has no workflow metadata: only the external owner's
    // typed snapshot callback is used, never a second local workflow lock/read.
    let work = root.join("package-0000/work");
    directory(&work).unwrap();
    let calls = Cell::new(0);
    let output = json!({"complete":true,"outputs":[{
        "sample_index":0,"text":"A distinct instructed answer.",
        "provider_key":enrollment.provider_keys[0],"job_id":"7".repeat(32),
        "report_sha256":"8".repeat(64),"model_fingerprint":"3".repeat(64),
        "output_index":0,"generated_tokens":19,"text_truncated":false}]});
    let snapshot = |path: &Path, expected: &workflow::ExpectedTask| {
        calls.set(calls.get() + 1);
        assert_eq!(path, work);
        assert_eq!(expected.task.question().unwrap(), original.question);
        assert_eq!(expected.manifest_id, sha(&original_bytes));
        Ok(output.clone())
    };
    let ready = super::super::prepare_frontier(
        &args,
        &cancelled,
        &mut result,
        &enrollment,
        &original,
        parents.clone(),
        true,
        &snapshot,
    )
    .await
    .unwrap();
    assert!(ready.is_empty());
    assert_eq!(calls.get(), 1);
    assert_eq!(result["complete"], true);
    assert_eq!(result["synthesized_answer"]["job_id"], "7".repeat(32));
    assert_ne!(result["synthesized_answer"]["job_id"], parents[0].job_id);
    assert_eq!(result["rounds_this_invocation"], 0);
    assert!(!root.parent().unwrap().join("level-01-result.json").exists());
    assert_eq!(fs::read(&file).unwrap(), original_bytes);
    assert_eq!(fs::metadata(&file).unwrap().ino(), inode);
    let mut changed = parents;
    changed[0].report_sha256 = "9".repeat(64);
    assert!(
        super::super::prepare_frontier(
            &args,
            &cancelled,
            &mut result,
            &enrollment,
            &original,
            changed,
            true,
            &snapshot,
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn external_frontier_enumerates_independent_pending_groups_without_early_break() {
    use std::cell::Cell;
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
    let (_owner, cancelled) = watch::channel(false);
    let (mut enrollment, original) = historical_original(temp.path(), &signer, &cancelled);
    enrollment.scheduling = workflow::Scheduling::ReadyRowsV1;
    let parents = (0..65)
        .map(|index| {
            let mut answer = parent("Answer.", index);
            answer.source_start = 0;
            answer.source_end = 100;
            answer
        })
        .collect::<Vec<_>>();
    let mut args = replay_options(temp.path());
    for (index, group) in parents.chunks(super::super::PARENTS_PER_GROUP).enumerate() {
        let offset = index * super::super::PARENTS_PER_GROUP;
        let (root, _) =
            historical_reduction_at(temp.path(), &enrollment, &original, &signer, group, offset);
        prepare(
            &args,
            &root,
            &enrollment,
            &original,
            group,
            offset,
            1,
            &cancelled,
        )
        .await
        .unwrap();
        directory(&root.join("package-0000/work")).unwrap();
    }
    args.max_batches = 0;
    let calls = Cell::new(0);
    let snapshot = |_: &Path, _: &workflow::ExpectedTask| {
        calls.set(calls.get() + 1);
        Ok(json!({"complete":false,"outputs":[]}))
    };
    let mut result = json!({"complete":false,"rounds_this_invocation":0});
    let ready = super::super::prepare_frontier(
        &args,
        &cancelled,
        &mut result,
        &enrollment,
        &original,
        parents,
        false,
        &snapshot,
    )
    .await
    .unwrap();
    assert_eq!(ready.len(), 2);
    assert_eq!(calls.get(), 2);
    assert_eq!(
        result["synthesis"]["levels"][0]["groups"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(result["rounds_this_invocation"], 0);
    assert_eq!(result["complete"], false);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One retained signed-source fixture checks historical resume without keys or runtime"
)]
async fn native_synthesis_replay_preserves_parent_bindings_and_original_expiry_without_keys_or_runtime()
 {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
    let (_owner, cancelled) = watch::channel(false);
    let (enrollment, original) = historical_original(temp.path(), &signer, &cancelled);
    let parents = vec![
        parent("één public answer", 0),
        parent("Second model answer.", 1),
    ];
    let (root, dataset) =
        historical_reduction(temp.path(), &enrollment, &original, &signer, &parents);
    let publisher = signer.verifying_key();
    drop(signer);
    let args = replay_options(temp.path());
    let package = root.join("package-0000");
    let file = package.join("dataset.manifest");
    let before = read(&file, MAX_MANIFEST_BYTES).unwrap();
    let inode = fs::metadata(&file).unwrap().ino();
    assert!(enrollment.expires_at_unix_seconds < now().unwrap());
    assert!(
        SignedManifest::decode(&before)
            .unwrap()
            .verify(&publisher, now().unwrap())
            .is_err()
    );

    let prepared = prepare(
        &args,
        &root,
        &enrollment,
        &original,
        &parents,
        0,
        1,
        &cancelled,
    )
    .await
    .unwrap();
    assert_eq!(prepared.datasets, vec![dataset.clone()]);
    let selected = expected(&package, &enrollment, &prepared, &dataset, 0).unwrap();
    assert_eq!(selected.manifest_id, sha(&before));
    assert_eq!(selected.rows, 1);
    assert_eq!(selected.provider_keys, enrollment.provider_keys);
    assert_eq!(selected.task.question().unwrap(), original.question);
    let native = SignedManifest::decode(&before)
        .unwrap()
        .verify(&publisher, selected.selected_at_unix_seconds)
        .unwrap();
    assert_eq!(
        native.validity().expires,
        enrollment.expires_at_unix_seconds
    );
    assert_eq!(dataset.inference[0].context, combined(&parents));
    assert_eq!(dataset.inference[0].inputs.len(), parents.len());
    for (input, parent) in dataset.inference[0].inputs.iter().zip(&parents) {
        assert_eq!(input.text, parent.text);
        assert_eq!(input.report_sha256, parent.report_sha256);
        assert_eq!(input.piece_start, 0);
        assert_eq!(input.piece_end, parent.text.len() as u64 + 1);
    }
    let mut changed_dataset = dataset.clone();
    changed_dataset.inference[0].inputs[0].report_sha256 = "9".repeat(64);
    assert!(expected(&package, &enrollment, &prepared, &changed_dataset, 0).is_err());
    let mut changed_enrollment: document_storage::Enrollment =
        serde_json::from_value(serde_json::to_value(&enrollment).unwrap()).unwrap();
    changed_enrollment.expires_at_unix_seconds -= 1;
    assert!(expected(&package, &changed_enrollment, &prepared, &dataset, 0).is_err());
    let mut changed = parents.clone();
    changed[0].text.push('!');
    assert!(
        prepare(
            &args,
            &root,
            &enrollment,
            &original,
            &changed,
            0,
            1,
            &cancelled
        )
        .await
        .is_err()
    );
    let new_group = root.parent().unwrap().join("level-02-group-0000");
    assert!(
        prepare(
            &args,
            &new_group,
            &enrollment,
            &original,
            &parents,
            0,
            2,
            &cancelled
        )
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("original_source_expired")
    );
    assert_eq!(read(&file, MAX_MANIFEST_BYTES).unwrap(), before);
    assert_eq!(fs::metadata(&file).unwrap().ino(), inode);
    assert!(!root.join("tokenizer").exists());
    assert!(!package.join("work").exists());
}
