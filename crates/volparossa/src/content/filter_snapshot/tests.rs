//! Inert signed-data/CLI tests only: no agent socket, browser or network delivery.

use clap::{CommandFactory as _, Parser as _};
use ed25519_dalek::SigningKey;
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

use super::*;

const FILTERS: &str = "[Adblock Plus 2.0]\r\n||ads.fixture.test^\r\n\r\n||metrics.fixture.test^\n";

struct Fixture {
    root: tempfile::TempDir,
    args: Options,
    download: public_text::TextDownload,
    now: u64,
}

fn fixture(text: &str) -> Fixture {
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let key = SigningKey::from_bytes(&[91; 32]);
    let now = now_seconds().unwrap();
    let cache = root.path().join("source-cache");
    let mut store = ChunkStore::create(
        &cache,
        CacheLimits {
            max_bytes: 2 * MAX_BYTES as u64,
            max_entries: 16,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let signed = volparossa_content::publish(
        &mut text.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "filters.synthetic.1".into(),
                revision: 1,
                content_type: "text/plain".into(),
            },
            length: text.len() as u64,
            validity: Validity {
                created: now,
                expires: now + 600,
            },
        },
        &key,
        &mut store,
    )
    .unwrap();
    let manifest = signed.verify(&key.verifying_key(), now).unwrap();
    let args = Options {
        publisher_key: key.verifying_key(),
        name: "filters.synthetic.1".into(),
        manifest_id: *manifest.manifest_id(),
        authorize_filter_publisher: true,
        public_content: true,
        cache,
        reuse_cache: true,
        output: root.path().join("snapshot"),
        limits: Limits {
            quota_bytes: 2 * MAX_BYTES as u64,
            max_entries: 16,
            min_free_bytes: 0,
        },
    };
    Fixture {
        root,
        args,
        now,
        download: public_text::TextDownload {
            signed_manifest: signed.encode(),
            text: text.into(),
            expires: now + 600,
            verified_at: now,
            receipt: serde_json::json!({"inert_unit_fixture": true, "network_delivery_proven": false}),
        },
    }
}

#[test]
fn filter_grammar_accepts_only_explicit_domain_blocks_without_rewriting() {
    assert_eq!(rule_count(FILTERS).unwrap(), 2);
    assert_eq!(rule_count("||ads.fixture.test^").unwrap(), 1);
    assert_eq!(rule_count("\n||x-1.fixture.test^\r\n").unwrap(), 1);
    for text in [
        "",
        "\n",
        HEADER,
        "! comment\n",
        "!#include https://peer.test/list.txt\n",
        "!#if true\n||ads.test^\n!#endif",
        "!#trusted on\n||ads.test^",
        "@@||ads.test^",
        "||ads.test^$important",
        "||ads.test^$redirect=noopjs",
        "||ads.test^$removeparam",
        "test##.cmp",
        "test##+js(set, cookie, true)",
        "0.0.0.0 ads.test",
        "/ads/",
        "*",
        "||Ads.test^",
        "||localhost^",
        "||127.0.0.1^",
        "||a..test^",
        "||-a.test^",
        "||a-.test^",
        "||a.test.^",
        "||a.t^",
        "||a.te_st^",
        "||é.test^",
        " ||a.test^",
        "||a.test^ ",
        "||a.test^\0",
        "||a.test^\r||b.test^",
        "||a.test^\n[Adblock Plus 2.0]",
    ] {
        assert!(
            rule_count(text).is_err(),
            "accepted unsupported grammar: {text:?}"
        );
    }
}

#[test]
fn filter_grammar_bounds_bytes_lines_labels_and_rule_count() {
    assert!(rule_count(&"x".repeat(MAX_BYTES + 1)).is_err());
    assert!(rule_count(&format!("{}||a.test^", "\n".repeat(MAX_LINES))).is_err());
    assert!(rule_count(&"||a.test^\n".repeat(MAX_RULES + 1)).is_err());
    assert!(rule_count(&format!("||{}.test^", "a".repeat(64))).is_err());
    assert!(rule_count(&format!("||{}^", "a.".repeat(129))).is_err());
    assert_eq!(
        rule_count(&"||a.test^\n".repeat(MAX_RULES)).unwrap(),
        MAX_RULES
    );
}

#[test]
fn signed_selection_rejects_tamper_wrong_publisher_name_id_and_expiry() {
    let mut fixture = fixture(FILTERS);
    let (manifest, count) = check_download(&fixture.args, &fixture.download, fixture.now).unwrap();
    assert_eq!(count, 2);
    assert_eq!(manifest.metadata().revision, 1);
    for at in [
        fixture.now - 1,
        fixture.download.expires,
        fixture.download.expires + 1,
    ] {
        assert!(check_download(&fixture.args, &fixture.download, at).is_err());
    }
    fixture.args.publisher_key = SigningKey::from_bytes(&[92; 32]).verifying_key();
    assert!(check_download(&fixture.args, &fixture.download, fixture.now).is_err());
    fixture.args.publisher_key = SigningKey::from_bytes(&[91; 32]).verifying_key();
    fixture.args.name.push('x');
    assert!(check_download(&fixture.args, &fixture.download, fixture.now).is_err());
    fixture.args.name.pop();
    fixture.args.manifest_id[0] ^= 1;
    assert!(check_download(&fixture.args, &fixture.download, fixture.now).is_err());
    fixture.args.manifest_id[0] ^= 1;
    fixture.download.text.push('\n');
    assert!(check_download(&fixture.args, &fixture.download, fixture.now).is_err());
    fixture.download.text.pop();
    fixture.download.text = fixture.download.text.replace("ads.fixture", "bad.fixture");
    assert!(check_download(&fixture.args, &fixture.download, fixture.now).is_err());
    fixture.download.text = FILTERS.into();
    let last = fixture.download.signed_manifest.last_mut().unwrap();
    *last ^= 1;
    assert!(check_download(&fixture.args, &fixture.download, fixture.now).is_err());
}

#[test]
fn valid_signatures_do_not_authorize_oversize_or_directives() {
    for text in [
        "x".repeat(MAX_BYTES + 1),
        "!#include https://peer.test/x\n".into(),
        "@@||ads.fixture.test^\n".into(),
        "fixture.test##+js(foo)\n".into(),
    ] {
        let fixture = fixture(&text);
        assert!(check_download(&fixture.args, &fixture.download, fixture.now).is_err());
        assert!(!fixture.args.output.exists());
    }
}

#[test]
fn selected_cache_identity_and_validity_are_not_changed() {
    let fixture = fixture(FILTERS);
    let selection = fixture.args.selection();
    assert_eq!(selection.publisher_key, fixture.args.publisher_key);
    assert_eq!(selection.name, fixture.args.name);
    assert_eq!(selection.manifest_id, fixture.args.manifest_id);
    assert_eq!(selection.cache, fixture.args.cache);
    assert!(selection.reuse_cache);
    assert_eq!(
        selection.limits.configuration(),
        fixture.args.limits.configuration()
    );
}

#[test]
fn exact_signed_data_exports_atomically_as_private_files_without_browser_activation() {
    let fixture = fixture(FILTERS);
    validate_output(&fixture.args.output).unwrap();
    let pending = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(fixture.root.path())
        .unwrap();
    let report = persist(&fixture.args, &fixture.download, pending).unwrap();
    let root = &fixture.args.output;
    assert_eq!(fs::metadata(root).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::read(root.join("filters.txt")).unwrap(),
        FILTERS.as_bytes()
    );
    assert_eq!(
        fs::read(root.join("manifest.pb")).unwrap(),
        fixture.download.signed_manifest
    );
    let receipt: Value =
        serde_json::from_slice(&fs::read(root.join("delivery-receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt, fixture.download.receipt);
    let retained: Value =
        serde_json::from_slice(&fs::read(root.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(retained, report);
    assert_eq!(report["expires_unix_seconds"], fixture.download.expires);
    assert_eq!(report["rules"], 2);
    for field in [
        "globally_latest",
        "browser_configuration_changed",
        "subscription_installed",
        "delivery_receipt_is_signed_attestation",
    ] {
        assert_eq!(report[field], false);
    }
    let entries: Vec<_> = fs::read_dir(root).unwrap().collect();
    assert_eq!(entries.len(), 4);
    for entry in entries {
        assert_eq!(entry.unwrap().metadata().unwrap().mode() & 0o777, 0o600);
    }
    assert!(validate_output(root).is_err());
}

#[test]
fn output_collision_and_symlinks_never_overwrite_existing_state() {
    let fixture = fixture(FILTERS);
    fs::create_dir(&fixture.args.output).unwrap();
    let sentinel = fixture.args.output.join("unchanged");
    fs::write(&sentinel, "owned data").unwrap();
    let pending = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(fixture.root.path())
        .unwrap();
    assert!(persist(&fixture.args, &fixture.download, pending).is_err());
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "owned data");
    assert_eq!(fs::read_dir(&fixture.args.output).unwrap().count(), 1);
    let link = fixture.root.path().join("link");
    std::os::unix::fs::symlink(&fixture.args.output, &link).unwrap();
    assert!(validate_output(&link).is_err());
    assert!(validate_output(&link.join("new")).is_err());
    assert!(validate_output(Path::new("relative")).is_err());
}

#[test]
fn empty_output_collision_and_partial_staging_failure_are_cleaned_without_publication() {
    let fixture = fixture(FILTERS);
    fs::create_dir(&fixture.args.output).unwrap();
    let pending = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(fixture.root.path())
        .unwrap();
    let pending_path = pending.path().to_path_buf();
    assert!(persist(&fixture.args, &fixture.download, pending).is_err());
    assert!(!pending_path.exists());
    assert_eq!(fs::read_dir(&fixture.args.output).unwrap().count(), 0);

    let mut fixture = self::fixture(FILTERS);
    let pending = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(fixture.root.path())
        .unwrap();
    let pending_path = pending.path().to_path_buf();
    // Force the second staged file to collide after filters.txt has been written.
    write_new(
        &pending.path().join("manifest.pb"),
        b"fixture-owned collision",
    )
    .unwrap();
    assert!(persist(&fixture.args, &fixture.download, pending).is_err());
    assert!(!pending_path.exists());
    assert!(!fixture.args.output.exists());
    fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(validate_output(&fixture.args.output).is_err());
    fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fixture.args.output = fixture.root.path().join("safe-output");
    validate_output(&fixture.args.output).unwrap();
}

#[test]
fn complete_cli_tree_and_filter_help_remain_consistent() {
    crate::Cli::command().debug_assert();
    let error = crate::Cli::try_parse_from(["volparossa", "content", "filter-snapshot", "--help"])
        .err()
        .unwrap();
    assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    let help = error.to_string();
    for flag in [
        "--publisher-key",
        "--manifest-id",
        "--authorize-filter-publisher",
        "--public-content",
    ] {
        assert!(help.contains(flag));
    }
}

#[test]
fn cli_requires_exact_independent_authority_and_explicit_public_acknowledgments() {
    let fixture = fixture(FILTERS);
    let arguments = vec![
        "volparossa".into(),
        "content".into(),
        "filter-snapshot".into(),
        "--publisher-key".into(),
        hex::encode(fixture.args.publisher_key.as_bytes()),
        "--name".into(),
        fixture.args.name.clone(),
        "--manifest-id".into(),
        hex::encode(fixture.args.manifest_id),
        "--cache".into(),
        fixture.args.cache.to_string_lossy().into_owned(),
        "--output".into(),
        fixture.args.output.to_string_lossy().into_owned(),
        "--authorize-filter-publisher".into(),
        "--public-content".into(),
    ];
    let parsed = crate::Cli::try_parse_from(&arguments).unwrap();
    let crate::CliCommand::Content { command } = parsed.command else {
        panic!("content")
    };
    let super::super::Command::FilterSnapshot(args) = *command else {
        panic!("filter snapshot")
    };
    assert_eq!(args.manifest_id, fixture.args.manifest_id);
    assert!(args.public_content && args.authorize_filter_publisher);
    for flag in ["--authorize-filter-publisher", "--public-content"] {
        assert!(crate::Cli::try_parse_from(arguments.iter().filter(|arg| *arg != flag)).is_err());
    }
    assert!(parse_manifest_id(&"00".repeat(32)).is_err());
    assert!(parse_manifest_id("abc").is_err());
}

#[tokio::test]
async fn absent_acknowledgment_and_existing_output_fail_before_any_agent_access() {
    let mut fixture = fixture(FILTERS);
    let absent_socket = fixture.root.path().join("no-agent.sock");
    fixture.args.public_content = false;
    assert!(
        run(&fixture.args, &absent_socket)
            .await
            .unwrap_err()
            .to_string()
            .contains("authority_required")
    );
    fixture.args.public_content = true;
    fixture.args.authorize_filter_publisher = false;
    assert!(
        run(&fixture.args, &absent_socket)
            .await
            .unwrap_err()
            .to_string()
            .contains("authority_required")
    );
    fixture.args.authorize_filter_publisher = true;
    fs::create_dir(&fixture.args.output).unwrap();
    assert!(
        run(&fixture.args, &absent_socket)
            .await
            .unwrap_err()
            .to_string()
            .contains("already exists")
    );
}
