//! Inert metadata/advice tests. Tiny fixtures do not prove real model execution.

use std::{
    cell::Cell,
    os::unix::fs::{PermissionsExt as _, symlink},
    time::{Duration, SystemTime},
};

use nix::fcntl::{FcntlArg, fcntl};

use super::super::tests::fixture as native_fixture;
use super::*;

fn specs() -> [ModelFileSpec; 3] {
    let fixed: &[ModelFileSpec; 3] = PROFILE.sharded_weight_files().unwrap()[1..]
        .try_into()
        .unwrap();
    fixed.map(|spec| ModelFileSpec { bytes: 1, ..spec })
}

fn fixture() -> (tempfile::TempDir, Binding) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for spec in specs() {
        fs::write(root.path().join(spec.name), b"x").unwrap();
        fs::set_permissions(
            root.path().join(spec.name),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let hints = Hints::bind(root.path(), &specs()).unwrap();
    (
        root,
        Binding {
            hints: Some(hints),
            reason: "bound",
        },
    )
}

fn model_result() -> Value {
    let files = PROFILE.sharded_weight_files().unwrap();
    let model_files: serde_json::Map<String, Value> = files
        .iter()
        .map(|file| {
            (
                file.name.to_owned(),
                json!({"bytes":file.bytes,"sha256":file.sha256}),
            )
        })
        .collect();
    json!({"model":{"files":model_files,"weights":{
        "layout":"safetensors_shards_concat_v1",
        "bytes":PROFILE.spec().weights_bytes,"sha256":PROFILE.spec().weights_sha256,
        "files":files[1..].iter().map(|file|file.name).collect::<Vec<_>>()
    }}})
}

fn observe(binding: Binding, result: &Result<Value>) -> Value {
    binding.observe_with(
        result,
        true,
        |_| memory::Sample::for_test(Some(0)),
        |_, _| Ok(()),
    )
}

#[test]
fn source_binding_is_native_owner_authorized_and_exactly_three_fixed_shards() {
    let (_native, mut options) = native_fixture();
    let request = options.request(PROFILE).unwrap();
    let (root, _small) = fixture();
    // Sparse length metadata only; no allocation/read of model bytes or model claim.
    for spec in &PROFILE.sharded_weight_files().unwrap()[1..] {
        OpenOptions::new()
            .write(true)
            .open(root.path().join(spec.name))
            .unwrap()
            .set_len(spec.bytes)
            .unwrap();
    }
    let binding = Binding::bind(&request, &options, PROFILE, root.path());
    let hints = binding.hints.unwrap();
    assert_eq!(hints.shards.len(), 3);
    for (shard, spec) in hints
        .shards
        .iter()
        .zip(&PROFILE.sharded_weight_files().unwrap()[1..])
    {
        assert_eq!(shard.name, spec.name);
        assert_eq!(shard.identity.bytes, spec.bytes);
    }
    assert!(!root.path().join("model.safetensors.index.json").exists());
    assert!(
        Binding::bind(&request, &options, ModelProfile::Qwen600, root.path())
            .hints
            .is_none()
    );
    assert!(
        Binding::bind(&request, &Options::default(), PROFILE, root.path())
            .hints
            .is_none()
    );
    options.native_backend_sha256 = Some("0".repeat(64));
    assert!(
        Binding::bind(&request, &options, PROFILE, root.path())
            .hints
            .is_none()
    );
    let legacy = Options::default().request(PROFILE).unwrap();
    assert!(
        Binding::bind(&legacy, &options, PROFILE, root.path())
            .hints
            .is_none()
    );
}

#[test]
fn source_descriptors_are_readonly_cloexec_nonblocking_and_exact() {
    let (root, binding) = fixture();
    let hints = binding.hints.unwrap();
    assert!(hints.parent_unchanged());
    for shard in hints.shards {
        assert!(shard.unchanged(root.path()));
        assert_ne!(
            fcntl(&shard.file, FcntlArg::F_GETFD).unwrap() & libc::FD_CLOEXEC,
            0
        );
        let flags = fcntl(&shard.file, FcntlArg::F_GETFL).unwrap();
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
        assert_ne!(flags & libc::O_NONBLOCK, 0);
        assert_ne!(flags & libc::O_NOFOLLOW, 0);
    }
}

#[test]
fn source_identity_rejects_foreign_owner_permissions_links_type_and_size() {
    let (_root, binding) = fixture();
    let identity = binding.hints.unwrap().shards[0].identity;
    assert!(identity.valid(1));
    assert!(!identity.valid(2));
    for changed in [
        Identity {
            owner: identity.owner.wrapping_add(1),
            ..identity
        },
        Identity {
            mode: identity.mode | 0o040,
            ..identity
        },
        Identity {
            mode: identity.mode | 0o004,
            ..identity
        },
        Identity {
            mode: libc::S_IFDIR | 0o600,
            ..identity
        },
        Identity {
            links: 2,
            ..identity
        },
        Identity {
            bytes: 0,
            ..identity
        },
        Identity {
            bytes: 5 * 1024 * 1024 * 1024,
            ..identity
        },
    ] {
        assert!(!changed.valid(changed.bytes));
    }
}

#[test]
fn source_bind_rejects_symlink_hardlink_nonregular_and_unprivate_root() {
    for change in 0..6 {
        let (root, _binding) = fixture();
        let path = root.path().join(specs()[1].name);
        let original = root.path().join("original");
        match change {
            0 => {
                fs::rename(&path, &original).unwrap();
                symlink("original", &path).unwrap();
            }
            1 => fs::hard_link(&path, &original).unwrap(),
            2 => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            3 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            4 => fs::write(&path, b"xx").unwrap(),
            _ => fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap(),
        }
        assert!(Hints::bind(root.path(), &specs()).is_err());
    }
    let (root, _binding) = fixture();
    let alias = root.path().join("alias");
    symlink(root.path(), &alias).unwrap();
    assert!(Hints::bind(&alias, &specs()).is_err());
}

#[test]
fn source_changes_after_binding_skip_every_advice() {
    for change in 0..6 {
        let (root, binding) = fixture();
        let path = root.path().join(specs()[0].name);
        match change {
            0 => {
                fs::rename(&path, root.path().join("old")).unwrap();
                fs::write(&path, b"x").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            1 => fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap(),
            2 => fs::hard_link(&path, root.path().join("other-link")).unwrap(),
            3 => fs::write(&path, b"xx").unwrap(),
            4 => binding.hints.as_ref().unwrap().shards[0]
                .file
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
                .unwrap(),
            _ => fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap(),
        }
        let record = binding.observe_with(
            &Ok(model_result()),
            true,
            |_| memory::Sample::for_test(Some(0)),
            |_, _| panic!("changed source advised"),
        );
        assert_eq!(record["outcome"], "identity_changed");
        assert_eq!(record["shards"], json!([]));
        assert!(record["after"].is_null());
    }
}

#[test]
fn source_parent_replacement_cannot_rebind_retained_descriptors() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("model");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for spec in specs() {
        fs::write(root.join(spec.name), b"x").unwrap();
        fs::set_permissions(root.join(spec.name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let hints = Hints::bind(&root, &specs()).unwrap();
    let saved = directory.path().join("saved");
    fs::rename(&root, &saved).unwrap();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    // Same retained files at the original lexical names, but a different parent.
    for spec in specs() {
        fs::rename(saved.join(spec.name), root.join(spec.name)).unwrap();
    }
    assert!(!hints.parent_unchanged());
    let record = Binding {
        hints: Some(hints),
        reason: "bound",
    }
    .observe_with(
        &Ok(model_result()),
        true,
        |_| memory::Sample::for_test(Some(0)),
        |_, _| panic!("replaced parent advised"),
    );
    assert_eq!(record["outcome"], "identity_changed");
}

#[test]
fn source_unbound_files_do_not_sample_or_advise() {
    let record = Binding {
        hints: None,
        reason: "file_invalid",
    }
    .observe_with(
        &Ok(model_result()),
        true,
        |_| panic!("unbound sample"),
        |_, _| panic!("unbound advice"),
    );
    assert_eq!(record["outcome"], "not_bound");
    assert_eq!(record["binding"], "file_invalid");
    assert_eq!(record["shards"], json!([]));
    assert!(record["before"].is_null());
    assert!(record["after"].is_null());
}

#[test]
fn source_parent_change_during_advice_skips_remaining_descriptors() {
    let (root, binding) = fixture();
    let calls = Cell::new(0);
    let record = binding.observe_with(
        &Ok(model_result()),
        true,
        |_| memory::Sample::for_test(Some(0)),
        |_, _| {
            calls.set(calls.get() + 1);
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
            Ok(())
        },
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(record["shards"][0]["outcome"], "advised");
    assert_eq!(record["shards"][1]["outcome"], "identity_changed");
    assert_eq!(record["shards"][2]["outcome"], "identity_changed");
}

#[test]
fn source_sufficient_after_gguf_never_uses_previous_shortage() {
    let (_root, binding) = fixture();
    let required = resources::limits(PROFILE).admission_headroom.unwrap();
    let record = binding.observe_with(
        &Ok(model_result()),
        true,
        |_| memory::Sample::for_test(Some(required)),
        |_, _| panic!("stale shortage used"),
    );
    assert_eq!(record["outcome"], "headroom_sufficient");
    assert_eq!(record["shards"], json!([]));
    assert!(record["after"].is_null());
    assert!(resources::admits(PROFILE, Some(required)));
}

#[test]
fn source_corrupted_report_pin_cannot_authorize_advice() {
    let (_root, binding) = fixture();
    let mut report = model_result();
    report["model"]["files"][specs()[0].name]["sha256"] = json!("0".repeat(64));
    let record = binding.observe_with(
        &Ok(report),
        true,
        |_| panic!("corrupted provenance sample"),
        |_, _| panic!("corrupted provenance advice"),
    );
    assert_eq!(record["outcome"], "provenance_unconfirmed");
    assert_eq!(record["shards"], json!([]));
}

#[test]
fn source_binding_failure_keeps_finite_nonprivate_reason() {
    let record = observe(
        Binding {
            hints: None,
            reason: "open_failed",
        },
        &Ok(model_result()),
    );
    assert_eq!(record["binding"], "open_failed");
    assert_eq!(record["outcome"], "not_bound");
}

#[test]
fn source_advice_requires_successful_supervisor_and_checked_provenance() {
    for outcome in ["supervisor_error", "provenance_unconfirmed"] {
        let (_root, binding) = fixture();
        let result = if outcome == "supervisor_error" {
            Err(private_task::CleanupUnconfirmed.into())
        } else {
            Ok(json!({"model":{"files":{},"weights":{}}}))
        };
        let record = binding.observe_with(
            &result,
            true,
            |_| panic!("unverified sample"),
            |_, _| panic!("unverified advice"),
        );
        assert_eq!(record["outcome"], outcome);
        assert!(record["before"].is_null());
        assert!(record["after"].is_null());
        assert_eq!(record["shards"], json!([]));
    }
}

#[test]
fn source_advice_requires_known_low_headroom_with_unchanged_admission() {
    let required = resources::limits(PROFILE).admission_headroom.unwrap();
    assert_eq!(required, 11_274_289_152);
    for (headroom, outcome) in [
        (None, "headroom_unknown"),
        (Some(required), "headroom_sufficient"),
        (Some(u64::MAX), "headroom_sufficient"),
    ] {
        let (_root, binding) = fixture();
        let samples = Cell::new(0);
        let record = binding.observe_with(
            &Ok(model_result()),
            true,
            |_| {
                samples.set(samples.get() + 1);
                memory::Sample::for_test(headroom)
            },
            |_, _| panic!("no known shortage"),
        );
        assert_eq!(record["outcome"], outcome);
        assert_eq!(samples.get(), 1);
        assert!(record["after"].is_null());
        assert_eq!(record["shards"], json!([]));
        assert_eq!(resources::admits(PROFILE, headroom), headroom.is_some());
    }
}

#[test]
fn source_one_shot_advises_exact_three_without_changing_original_result() {
    let (_root, binding) = fixture();
    let identities = binding
        .hints
        .as_ref()
        .unwrap()
        .shards
        .each_ref()
        .map(|shard| shard.identity);
    let result = Ok(model_result());
    let original = result.as_ref().unwrap().clone();
    let mut calls = 0;
    let mut samples = 0;
    let record = binding.observe_with(
        &result,
        true,
        |stats| {
            assert!(stats);
            samples += 1;
            memory::Sample::for_test(Some(0))
        },
        |file, bytes| {
            assert_eq!(bytes, 1);
            assert_eq!(Identity::read(&file.metadata().unwrap()), identities[calls]);
            calls += 1;
            Ok(())
        },
    );
    assert_eq!(calls, 3);
    assert_eq!(samples, 2);
    assert_eq!(record["outcome"], "shards_checked");
    assert_eq!(
        record["shards"],
        json!([
            {"ordinal":1,"outcome":"advised","syscall_error":null},
            {"ordinal":2,"outcome":"advised","syscall_error":null},
            {"ordinal":3,"outcome":"advised","syscall_error":null}
        ])
    );
    assert_eq!(result.as_ref().ok(), Some(&original));
    assert!(!resources::admits(PROFILE, Some(0)));
}

#[test]
fn source_syscall_failure_is_finite_without_retry_or_result_override() {
    let (_root, binding) = fixture();
    let result = Ok(model_result());
    let original = result.as_ref().unwrap().clone();
    let calls = Cell::new(0);
    let record = binding.observe_with(
        &result,
        true,
        |_| memory::Sample::for_test(Some(0)),
        |_, _| {
            calls.set(calls.get() + 1);
            Err(nix::errno::Errno::EINTR)
        },
    );
    assert_eq!(calls.get(), 3);
    for item in record["shards"].as_array().unwrap() {
        assert_eq!(item["outcome"], "error");
        assert_eq!(item["syscall_error"], "interrupted");
    }
    assert_eq!(result.as_ref().ok(), Some(&original));
    for (error, expected) in [
        (nix::errno::Errno::EBADF, "bad_fd"),
        (nix::errno::Errno::EINVAL, "invalid"),
        (nix::errno::Errno::ENOSYS, "unsupported"),
        (nix::errno::Errno::EOPNOTSUPP, "unsupported"),
        (nix::errno::Errno::EACCES, "other"),
    ] {
        assert_eq!(syscall_kind(error), expected);
    }
}

#[test]
fn source_rechecks_remaining_files_between_advisory_calls() {
    let (root, binding) = fixture();
    let calls = Cell::new(0);
    let record = binding.observe_with(
        &Ok(model_result()),
        true,
        |_| memory::Sample::for_test(Some(0)),
        |_, _| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                fs::set_permissions(
                    root.path().join(specs()[1].name),
                    fs::Permissions::from_mode(0o400),
                )
                .unwrap();
            }
            Ok(())
        },
    );
    assert_eq!(calls.get(), 2);
    assert_eq!(record["shards"][0]["outcome"], "advised");
    assert_eq!(record["shards"][1]["outcome"], "identity_changed");
    assert_eq!(record["shards"][2]["outcome"], "advised");
}

#[test]
fn source_observation_is_bounded_and_does_not_export_private_identities() {
    let (root, binding) = fixture();
    let record = observe(binding, &Ok(model_result()));
    let raw = serde_json::to_string(&record).unwrap();
    assert!("private_source_weight_cache_diagnostic ".len() + raw.len() < 4096);
    assert!(!raw.contains(root.path().to_str().unwrap()));
    for forbidden in [
        "safetensors",
        "sha256",
        "inode",
        "owner",
        "reclaimed",
        "admitted",
    ] {
        assert!(!raw.contains(forbidden));
    }
    assert_eq!(record.as_object().unwrap().len(), 8);
    assert_eq!(record["version"], 1);
    assert_eq!(record["phase"], "source_weights");
    assert_eq!(record["binding"], "bound");
    assert_eq!(record["supervisor_ok"], true);
}

#[test]
fn source_disabled_observation_preserves_advice_but_no_extra_sampling() {
    let (_root, binding) = fixture();
    let samples = Cell::new(0);
    let record = binding.observe_with(
        &Ok(model_result()),
        false,
        |stats| {
            assert!(!stats);
            samples.set(samples.get() + 1);
            memory::Sample::for_test(Some(0))
        },
        |_, _| Ok(()),
    );
    assert_eq!(samples.get(), 1);
    assert!(record["before"].is_null());
    assert!(record["after"].is_null());
}

#[derive(Clone)]
struct Log(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Log {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn source_logging_requires_scope_and_its_own_explicit_debug_opt_in() {
    for diagnostic in [false, true] {
        for filter in [
            "off",
            "off,volparossa::compute::private_diagnostic=debug",
            "off,volparossa::compute::private_source_weight_cache_diagnostic=debug",
        ] {
            let log = Log(std::sync::Arc::default());
            let writer = log.clone();
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_target(false)
                .with_level(false)
                .with_env_filter(filter)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                let binding = Binding {
                    hints: None,
                    reason: "not_applicable",
                };
                // Never invokes a real advisory or sampler in this logging test.
                binding.after_supervisor(&Err(anyhow::anyhow!("PRIVATE_CANARY")), diagnostic);
            });
            let raw = log.0.lock().unwrap();
            if diagnostic && filter.contains("private_source_weight_cache_diagnostic=") {
                let text = std::str::from_utf8(&raw).unwrap();
                let record: Value = serde_json::from_str(
                    text.trim()
                        .strip_prefix("private_source_weight_cache_diagnostic ")
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(record["outcome"], "supervisor_error");
                assert_eq!(record["supervisor_ok"], false);
                assert!(!text.contains("PRIVATE_CANARY"));
            } else {
                assert!(raw.is_empty());
            }
        }
    }
}

#[test]
fn source_advice_stays_after_gguf_and_successful_join_inside_runtime_lease() {
    let source = include_str!("../../../compute.rs");
    let lease = source.find("let _lease = runtime_lease").unwrap();
    let admission = source
        .find("resources::admission(options.model_profile")
        .unwrap();
    let binding = source.find("let source_weight_cache = ").unwrap();
    let spawn = source[binding..]
        .find("let child = sandbox::command")
        .unwrap()
        + binding;
    let join = source.find("let result = supervise::run(child").unwrap();
    let gguf = source.find("cache_hint.after_supervisor(&result").unwrap();
    let advice = source
        .find("source_weight_cache.after_supervisor(&result")
        .unwrap();
    assert!(lease < admission && admission < binding && binding < spawn);
    assert!(spawn < join && join < gguf && gguf < advice);
    assert!(source[advice..].starts_with(
        "source_weight_cache.after_supervisor(&result, memory_diagnostic);\n    result\n}"
    ));
}
