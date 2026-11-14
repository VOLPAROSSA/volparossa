// SPDX-License-Identifier: GPL-3.0-only
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

use super::*;

fn counts() -> Counts {
    Counts {
        cli_started: 8,
        cli_joined: 8,
        daemon_started: 2,
        crash_joined: 1,
        graceful_joined: 1,
        failure_joined: 0,
        cli_rejections: 4,
        agent_rejections: 1,
        verified_bytes: 262_281,
        verified_chunks: 2,
    }
}

fn output(report: &ChildReport) -> String {
    let completion = if report.success {
        format!("{COMPLETE}\n")
    } else {
        String::new()
    };
    let summary = if report.success {
        "ok. 1 passed; 0 failed; 0 ignored; 0 measured;"
    } else {
        "FAILED. 0 passed; 1 failed; 0 ignored; 0 measured;"
    };
    format!(
        "running 1 test\n{CHILD_RECEIPT}{}\n{completion}test result: {summary} 0 filtered out;\n",
        serde_json::to_string(report).unwrap()
    )
}

#[test]
fn success_requires_exact_counts_stage_cleanup_and_one_actual_execution() {
    let report = ChildReport {
        version: 1,
        success: true,
        stage: Stage::Complete,
        cleanup: Cleanup::NormalJoinedSocketAndFixtureRemoved,
        counts: counts(),
    };
    let valid = output(&report);
    assert!(parse_child_output(true, valid.as_bytes()).unwrap().success);
    for invalid in [
        valid.replace(COMPLETE, ""),
        format!("{valid}{COMPLETE}\n"),
        valid.replace("running 1 test", "running 0 tests"),
        valid.replace("1 passed; 0 failed", "0 passed; 0 failed"),
        valid.replace("\"version\":1", "\"version\":2"),
        valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
        valid.replace("\"stage\":\"complete\"", "\"stage\":\"import\""),
        valid.replace("normal_joined_socket_and_fixture_removed", "unconfirmed"),
        valid.replace("\"cli_joined\":8", "\"cli_joined\":7"),
        valid.replace("\"crash_joined\":1", "\"crash_joined\":0"),
        valid.replace("\"agent_rejections\":1", "\"agent_rejections\":0"),
        valid.replace("\"verified_bytes\":262281", "\"verified_bytes\":true"),
        valid.replace("\"version\":1", "\"private_payload\":0,\"version\":1"),
        format!(
            "{valid}{CHILD_RECEIPT}{}\n",
            serde_json::to_string(&report).unwrap()
        ),
    ] {
        assert!(parse_child_output(true, invalid.as_bytes()).is_err());
    }
    assert!(parse_child_output(false, valid.as_bytes()).is_err());
}

#[test]
fn failure_keeps_observed_partial_counts_without_inventing_completion() {
    let report = ChildReport {
        version: 1,
        success: false,
        stage: Stage::Import,
        cleanup: Cleanup::FailureJoined,
        counts: Counts {
            cli_started: 6,
            cli_joined: 6,
            daemon_started: 1,
            failure_joined: 1,
            ..Counts::default()
        },
    };
    let raw = output(&report);
    let parsed = parse_child_output(false, raw.as_bytes()).unwrap();
    assert!(!parsed.success);
    assert_eq!(parsed.counts, report.counts);
    assert!(parse_child_output(true, raw.as_bytes()).is_err());
    assert!(parse_child_output(false, format!("{raw}{COMPLETE}\n").as_bytes()).is_err());
    assert!(
        parse_child_output(
            false,
            raw.replace("\"stage\":\"import\"", "\"stage\":\"complete\"")
                .as_bytes()
        )
        .is_err()
    );
}

#[test]
fn missing_hosted_or_explicit_opt_in_never_authorizes_the_proof() {
    let valid = [Some("1"), Some("true"), Some("github-hosted")];
    assert!(hosted_authority(valid));
    for index in 0..3 {
        for invalid in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("self-hosted"),
        ] {
            let mut gates = valid;
            gates[index] = invalid;
            assert!(!hosted_authority(gates));
        }
    }
}

#[test]
fn namespace_route_keeps_real_wrapper_and_only_fixed_hosted_opt_in() {
    let command = namespace_command(
        Path::new("/not-executed/wrapper"),
        Path::new("/not-executed/test-binary"),
    );
    assert_eq!(command.as_std().get_program(), "/not-executed/wrapper");
    let args = command.as_std().get_args().collect::<Vec<_>>();
    assert_eq!(
        args,
        [
            "--command",
            "/usr/bin/env",
            TEST,
            MARKER,
            "loopback",
            "VOLPAROSSA_REQUIRE_PUBLIC_CONTENT_DAEMON_PROOF=1",
            "GITHUB_ACTIONS=true",
            "RUNNER_ENVIRONMENT=github-hosted",
            "/not-executed/test-binary",
            "--ignored",
            "--exact",
            TEST,
            "--nocapture",
            "--test-threads=1"
        ]
        .map(std::ffi::OsStr::new)
    );
}

#[test]
fn fixed_binary_metadata_refuses_symlinks_non_executables_and_unsafe_modes() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("public-inert-file");
    fixture::private_file(&file, b"public inert bytes, never executed").unwrap();
    assert!(fixture::executable_stamp(&file).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(fixture::executable_stamp(&file).is_ok());
    let link = root.path().join("symlink");
    symlink(&file, &link).unwrap();
    assert!(fixture::executable_stamp(&link).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(fixture::executable_stamp(&file).is_err());
    assert!(fixture::executable_stamp(root.path()).is_err());
}

#[test]
fn private_read_refuses_bounds_symlinks_aliases_and_wide_modes() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("public-source");
    fixture::private_file(&file, b"public").unwrap();
    assert_eq!(fixture::read_private(&file, 6).unwrap(), b"public");
    assert!(fixture::read_private(&file, 5).is_err());
    let alias = root.path().join("alias");
    fs::hard_link(&file, &alias).unwrap();
    assert!(fixture::read_private(&file, 6).is_err());
    fs::remove_file(alias).unwrap();
    let link = root.path().join("link");
    symlink(&file, &link).unwrap();
    assert!(fixture::read_private(&link, 6).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(fixture::read_private(&file, 6).is_err());
}

#[test]
fn expected_cli_rejection_cannot_mask_success_output_or_unrelated_failure() {
    let expected = b"fixed public refusal";
    let result = process::CliResult {
        success: false,
        stdout: vec![],
        stderr: expected.to_vec(),
    };
    assert!(result.rejection(expected).is_ok());
    assert!(
        process::CliResult {
            success: true,
            stdout: vec![],
            stderr: expected.to_vec()
        }
        .rejection(expected)
        .is_err()
    );
    assert!(
        process::CliResult {
            success: false,
            stdout: b"unexpected output".to_vec(),
            stderr: expected.to_vec()
        }
        .rejection(expected)
        .is_err()
    );
    assert!(
        process::CliResult {
            success: false,
            stdout: vec![],
            stderr: b"unrelated failure".to_vec()
        }
        .rejection(expected)
        .is_err()
    );
}
