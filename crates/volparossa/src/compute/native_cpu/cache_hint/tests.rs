//! Tiny inert files and injected advice only; no model, native code, or cache syscall.

use std::{
    cell::Cell,
    os::unix::fs::{PermissionsExt as _, symlink},
    time::{Duration, SystemTime},
};

use nix::fcntl::{FcntlArg, fcntl};

use super::super::{Options, tests::fixture};
use super::*;

const PROFILE: ModelProfile = ModelProfile::Qwen4bInstruct2507;

fn bound(options: &Options) -> CacheHint {
    options
        .request(PROFILE)
        .unwrap()
        .cache_hint(options, PROFILE)
        .unwrap()
}

#[test]
fn hint_requires_known_shortage_without_changing_admission() {
    let required = 10 * 1024 * 1024 * 1024 + 512 * 1024 * 1024;
    assert_eq!(
        resources::limits(PROFILE).admission_headroom,
        Some(required)
    );
    for (available, hint, admitted) in [
        (None, false, false),
        (Some(0), true, false),
        (Some(required - 1), true, false),
        (Some(required), false, true),
        (Some(required + 1), false, true),
    ] {
        assert_eq!(needs_hint(PROFILE, available), hint);
        assert_eq!(resources::admits(PROFILE, available), admitted);
    }
    for profile in [
        ModelProfile::Default135,
        ModelProfile::Smol360,
        ModelProfile::Smol1700,
        ModelProfile::Qwen600,
    ] {
        assert!(!needs_hint(profile, Some(0)));
    }
}

#[test]
fn hint_binding_requires_the_same_owner_authorized_native_request() {
    let (_root, mut options) = fixture();
    let request = options.request(PROFILE).unwrap();
    assert!(request.cache_hint(&options, PROFILE).is_some());
    assert!(
        request
            .cache_hint(&options, ModelProfile::Qwen600)
            .is_none()
    );
    assert!(request.cache_hint(&Options::default(), PROFILE).is_none());
    options.native_backend_sha256 = Some("0".repeat(64));
    assert!(request.cache_hint(&options, PROFILE).is_none());
    assert!(options.request(PROFILE).is_err());
    assert!(
        Options::default()
            .request(PROFILE)
            .unwrap()
            .cache_hint(&options, PROFILE)
            .is_none()
    );
}

#[test]
fn bound_descriptor_is_read_only_cloexec_and_matches_exact_file() {
    let (_root, options) = fixture();
    let hint = bound(&options);
    assert!(hint.unchanged());
    assert_eq!(hint.identity.bytes, 1);
    assert_ne!(
        fcntl(&hint.file, FcntlArg::F_GETFD).unwrap() & libc::FD_CLOEXEC,
        0
    );
    assert_eq!(
        fcntl(&hint.file, FcntlArg::F_GETFL).unwrap() & libc::O_ACCMODE,
        libc::O_RDONLY
    );
}

#[test]
fn file_identity_requires_regular_private_single_link_owned_exact_size() {
    let (_root, options) = fixture();
    let identity = bound(&options).identity;
    assert!(identity.valid(1));
    assert!(!identity.valid(2));
    for changed in [
        Identity {
            mode: libc::S_IFDIR | 0o600,
            ..identity
        },
        Identity {
            mode: identity.mode | 0o004,
            ..identity
        },
        Identity {
            owner: identity.owner.wrapping_add(1),
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
            bytes: 10 * 1024 * 1024 * 1024,
            ..identity
        },
    ] {
        assert!(!changed.valid(changed.bytes));
    }
    for changed in [
        Identity {
            device: identity.device.wrapping_add(1),
            ..identity
        },
        Identity {
            inode: identity.inode.wrapping_add(1),
            ..identity
        },
        Identity {
            modified: (identity.modified.0 + 1, 0),
            ..identity
        },
        Identity {
            changed: (identity.changed.0 + 1, 0),
            ..identity
        },
    ] {
        assert_ne!(changed, identity);
    }
}

#[test]
fn optional_binding_rejects_symlink_hardlink_nonregular_and_unprivate_parent() {
    let (root, _options) = fixture();
    let model = root.path().join("model.gguf");
    fs::rename(&model, root.path().join("original")).unwrap();
    symlink("original", &model).unwrap();
    assert!(CacheHint::bind(root.path(), 1).is_none());
    fs::remove_file(&model).unwrap();
    fs::hard_link(root.path().join("original"), &model).unwrap();
    assert!(CacheHint::bind(root.path(), 1).is_none());
    fs::remove_file(&model).unwrap();
    fs::create_dir(&model).unwrap();
    assert!(CacheHint::bind(root.path(), 1).is_none());
    fs::remove_dir(&model).unwrap();
    fs::rename(root.path().join("original"), &model).unwrap();
    assert!(CacheHint::bind(root.path(), 2).is_none());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(CacheHint::bind(root.path(), 1).is_none());
}

#[test]
fn replaced_same_size_file_is_never_advised() {
    let (root, options) = fixture();
    let hint = bound(&options);
    let model = root.path().join("model.gguf");
    fs::rename(&model, root.path().join("original")).unwrap();
    fs::write(&model, b"x").unwrap();
    fs::set_permissions(&model, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!hint.unchanged());
    hint.after_supervisor_with(&Ok(()), PROFILE, || Some(0), |_, _| panic!("replacement"));
}

#[test]
fn changed_metadata_and_parent_identity_are_never_advised() {
    for change in 0..4 {
        let (root, options) = fixture();
        let hint = bound(&options);
        let model = root.path().join("model.gguf");
        match change {
            0 => fs::set_permissions(&model, fs::Permissions::from_mode(0o400)).unwrap(),
            1 => fs::write(&model, b"xx").unwrap(),
            2 => hint
                .file
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
                .unwrap(),
            _ => fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap(),
        }
        assert!(!hint.unchanged());
        hint.after_supervisor_with(&Ok(()), PROFILE, || Some(0), |_, _| panic!("changed"));
    }
    let (_root, options) = fixture();
    let mut hint = bound(&options);
    hint.root_identity.1 = hint.root_identity.1.wrapping_add(1);
    assert!(!hint.unchanged());
}

#[test]
fn successful_supervisor_allows_one_exact_range_hint_without_reading_model() {
    let (_root, options) = fixture();
    let hint = bound(&options);
    let expected = hint.identity;
    let calls = Cell::new(0);
    let result = Ok("original result");
    hint.after_supervisor_with(
        &result,
        PROFILE,
        || Some(0),
        |file, bytes| {
            calls.set(calls.get() + 1);
            assert_eq!(bytes, 1);
            assert_eq!(Identity::read(&file.metadata().unwrap()), expected);
            Ok(())
        },
    );
    assert_eq!(calls.get(), 1);
    assert!(matches!(result, Ok("original result")));
}

#[test]
fn hint_failure_does_not_change_success_or_claim_reclaimed_memory() {
    let (_root, options) = fixture();
    let result = Ok("original result");
    bound(&options).after_supervisor_with(
        &result,
        PROFILE,
        || Some(0),
        |_, _| Err(nix::errno::Errno::EIO),
    );
    assert!(matches!(result, Ok("original result")));
}

#[test]
fn errors_including_unconfirmed_cleanup_never_sample_or_hint() {
    let (_root, options) = fixture();
    for error in [
        anyhow::Error::new(crate::compute::private_task::CleanupUnconfirmed),
        anyhow::anyhow!("compute_cancelled"),
        anyhow::anyhow!("PRIVATE_ERROR_CANARY /private/path"),
    ] {
        let original = error.to_string();
        let uncertain_cleanup = error.is::<crate::compute::private_task::CleanupUnconfirmed>();
        let result: Result<()> = Err(error);
        bound(&options).after_supervisor_with(
            &result,
            PROFILE,
            || panic!("error sample"),
            |_, _| panic!("error hint"),
        );
        let Err(error) = &result else {
            panic!("original error replaced");
        };
        assert_eq!(error.to_string(), original);
        assert_eq!(
            error.is::<crate::compute::private_task::CleanupUnconfirmed>(),
            uncertain_cleanup
        );
    }
}

#[test]
fn missing_or_sufficient_headroom_never_hints() {
    let (_root, options) = fixture();
    for available in [
        None,
        resources::limits(PROFILE).admission_headroom,
        Some(u64::MAX),
    ] {
        bound(&options).after_supervisor_with(
            &Ok(()),
            PROFILE,
            || available,
            |_, _| panic!("no measured shortage"),
        );
    }
}

fn observed(options: &Options) -> Binding {
    options
        .request(PROFILE)
        .unwrap()
        .cache_hint_observed(options, PROFILE)
}

fn collect(records: &[Value]) {
    use std::io::Write as _;
    let mut log = tempfile::NamedTempFile::new().unwrap();
    for record in records {
        let line = format!("private_memory_diagnostic {record}\n");
        assert!(line.len() <= 4096);
        assert!(!line.contains("CANARY"));
        log.write_all(line.as_bytes()).unwrap();
    }
    let script = r"
import json, runpy, sys
from pathlib import Path
module = runpy.run_path(sys.argv[1])
path = Path(sys.argv[2])
original = [json.loads(line.split(' ', 1)[1]) for line in path.read_text().splitlines()]
legacy = module['service_diagnostic'](path)
assert legacy == dict(version=1, truncated=False, unrecognized_record=False, events=[])
current = module['service_diagnostic'](path, memory_enabled=True)
assert current == dict(version=2, truncated=False, unrecognized_record=False,
                       events=[], memory=original)
";
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/agent-private-conversation.py");
    let parsed = std::process::Command::new("python3")
        .args(["-B", "-c", script])
        .arg(fixture)
        .arg(log.path())
        .output()
        .unwrap();
    assert!(parsed.status.success());
    assert!(parsed.stdout.is_empty() && parsed.stderr.is_empty());
}

#[test]
fn cache_observation_preserves_cleanup_and_cancel_priority_without_private_error_text() {
    let (_root, options) = fixture();
    let mut records = Vec::new();
    for error in [
        anyhow::Error::new(crate::compute::private_task::CleanupUnconfirmed),
        anyhow::anyhow!("compute_cancelled"),
        anyhow::anyhow!("PRIVATE_CACHE_CANARY /private/path"),
    ] {
        let original = error.to_string();
        let result: Result<()> = Err(error);
        let record = observed(&options).observe_with(
            &result,
            PROFILE,
            true,
            |_| panic!("sample before confirmed cleanup"),
            |_, _| panic!("hint before confirmed cleanup"),
        );
        let Err(preserved_error) = result else {
            panic!("supervisor failure was replaced by success");
        };
        assert_eq!(preserved_error.to_string(), original);
        assert_eq!(record["outcome"], "supervisor_error");
        assert_eq!(record["supervisor_ok"], false);
        records.push(record);
    }
    collect(&records);
}

#[test]
fn unavailable_hint_and_unknown_or_sufficient_headroom_remain_non_authoritative() {
    let (_root, options) = fixture();
    let mut records = Vec::new();
    for reason in [
        "not_applicable",
        "root_invalid",
        "open_failed",
        "file_invalid",
        "path_changed",
    ] {
        let record = Binding::unavailable(reason).observe_with(
            &Ok(()),
            PROFILE,
            true,
            |_| panic!("unbound sample"),
            |_, _| panic!("unbound advice"),
        );
        assert_eq!(record["outcome"], "not_bound");
        records.push(record);
    }
    for (available, outcome) in [
        (None, "headroom_unknown"),
        (
            resources::limits(PROFILE).admission_headroom,
            "headroom_sufficient",
        ),
        (Some(u64::MAX), "headroom_sufficient"),
    ] {
        let calls = Cell::new(0);
        let record = observed(&options).observe_with(
            &Ok(()),
            PROFILE,
            true,
            |stats| {
                assert!(stats);
                calls.set(calls.get() + 1);
                memory::Sample::for_test(available)
            },
            |_, _| panic!("unproven shortage"),
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(record["outcome"], outcome);
        records.push(record);
    }
    collect(&records);
}

#[test]
fn advice_observation_reports_one_syscall_and_closed_errno_without_reclaim_claim() {
    let (_root, options) = fixture();
    let mut records = Vec::new();
    for (advice, expected) in [
        (Ok(()), None),
        (Err(nix::errno::Errno::EBADF), Some("bad_fd")),
        (Err(nix::errno::Errno::EINVAL), Some("invalid")),
        (Err(nix::errno::Errno::ENOSYS), Some("unsupported")),
        (Err(nix::errno::Errno::EOPNOTSUPP), Some("unsupported")),
        (Err(nix::errno::Errno::EINTR), Some("interrupted")),
        (Err(nix::errno::Errno::EIO), Some("other")),
    ] {
        let samples = Cell::new(0);
        let calls = Cell::new(0);
        let original = Ok("original result");
        let record = observed(&options).observe_with(
            &original,
            PROFILE,
            true,
            |stats| {
                assert!(stats);
                samples.set(samples.get() + 1);
                memory::Sample::for_test(if samples.get() == 1 { Some(0) } else { None })
            },
            |_, bytes| {
                assert_eq!(bytes, 1);
                assert_eq!(samples.get(), 1);
                calls.set(calls.get() + 1);
                advice
            },
        );
        assert_eq!(samples.get(), 2);
        assert_eq!(calls.get(), 1);
        assert!(matches!(original, Ok("original result")));
        assert_eq!(
            record["outcome"],
            if expected.is_some() {
                "error"
            } else {
                "advised"
            }
        );
        assert_eq!(record["syscall_error"], json!(expected));
        assert_eq!(record["after"]["missing_stage"], "meminfo");
        records.push(record);
    }
    collect(&records);
}

#[test]
fn changed_hint_identity_is_observed_without_advice_or_second_sample() {
    let (root, options) = fixture();
    let binding = observed(&options);
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let calls = Cell::new(0);
    let record = binding.observe_with(
        &Ok(()),
        PROFILE,
        true,
        |_| {
            calls.set(calls.get() + 1);
            memory::Sample::for_test(Some(0))
        },
        |_, _| panic!("changed identity"),
    );
    assert_eq!(record["outcome"], "identity_changed");
    assert_eq!(calls.get(), 1);
    collect(&[record]);
}

#[test]
fn opt_out_does_not_read_stats_or_add_an_after_hint_sample() {
    let (_root, options) = fixture();
    let samples = Cell::new(0);
    let record = observed(&options).observe_with(
        &Ok(()),
        PROFILE,
        false,
        |stats| {
            assert!(!stats);
            samples.set(samples.get() + 1);
            memory::Sample::for_test(Some(0))
        },
        |_, _| Ok(()),
    );
    assert_eq!(samples.get(), 1);
    assert!(record["before"].is_null() && record["after"].is_null());
}
