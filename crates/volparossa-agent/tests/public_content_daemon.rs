// SPDX-License-Identifier: GPL-3.0-only
//! Hosted-only actual public-content CLI/agent process-crash persistence proof.
//! Same-owner local storage only; no overlay/provider, named-site or power-loss claim.

#[path = "public_content_daemon/fixture.rs"]
mod fixture;
#[path = "dps_daemon/host_state.rs"]
mod host_state;
#[path = "public_content_daemon/process.rs"]
mod process;
#[path = "public_content_daemon/scenario.rs"]
mod scenario;
#[cfg(test)]
#[path = "public_content_daemon/tests.rs"]
mod tests;

use std::{cell::Cell, fs, path::Path};

use tokio::process::Command;

const TEST: &str = "public_content_daemon_import_crash_reopen_export_and_joined_cleanup";
const MARKER: &str = "VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS";
const OPT_IN: &str = "VOLPAROSSA_REQUIRE_PUBLIC_CONTENT_DAEMON_PROOF";
const CHILD_RECEIPT: &str = "PUBLIC_CONTENT_DAEMON_CHILD_RESULT ";
const RECEIPT: &str = "PUBLIC_CONTENT_DAEMON_HOST_PROOF ";
const COMPLETE: &str = "PUBLIC_CONTENT_DAEMON_CHILD_COMPLETE_V1";

type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Fixture,
    Binary,
    NegativePublication,
    Publish,
    Spawn,
    Readiness,
    DormantRoles,
    AgentRejection,
    NegativeImport,
    Import,
    CrashJoin,
    Restart,
    Export,
    Assemble,
    Shutdown,
    SocketCleanup,
    FixtureCleanup,
    Complete,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Cleanup {
    #[default]
    NotStarted,
    Unconfirmed,
    FailureJoined,
    CrashJoined,
    GracefulJoined,
    NormalJoinedSocketAndFixtureRemoved,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Counts {
    cli_started: u8,
    cli_joined: u8,
    daemon_started: u8,
    crash_joined: u8,
    graceful_joined: u8,
    failure_joined: u8,
    cli_rejections: u8,
    agent_rejections: u8,
    verified_bytes: u64,
    verified_chunks: u32,
}

impl Counts {
    fn complete(self) -> bool {
        self == Self {
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
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildReport {
    version: u8,
    success: bool,
    stage: Stage,
    cleanup: Cleanup,
    counts: Counts,
}

struct Progress {
    stage: Cell<Stage>,
    cleanup: Cell<Cleanup>,
    counts: Cell<Counts>,
}

impl Progress {
    fn new() -> Self {
        Self {
            stage: Cell::new(Stage::Fixture),
            cleanup: Cell::new(Cleanup::NotStarted),
            counts: Cell::new(Counts::default()),
        }
    }
    fn count(&self, update: impl FnOnce(&mut Counts)) {
        let mut counts = self.counts.get();
        update(&mut counts);
        self.counts.set(counts);
    }
}

#[test]
#[ignore = "requires explicit disposable GitHub-hosted public content daemon proof"]
fn public_content_daemon_import_crash_reopen_export_and_joined_cleanup() {
    let gates = [OPT_IN, "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT"].map(|key| std::env::var(key).ok());
    assert!(hosted_authority(gates.each_ref().map(Option::as_deref)));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    if let Some(parent) = std::env::var_os(MARKER) {
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
            parent
        );
        let progress = Progress::new();
        let result = runtime.block_on(scenario::run(&progress));
        let report = ChildReport {
            version: 1,
            success: result.is_ok(),
            stage: progress.stage.get(),
            cleanup: progress.cleanup.get(),
            counts: progress.counts.get(),
        };
        println!(
            "\n{CHILD_RECEIPT}{}",
            serde_json::to_string(&report).unwrap()
        );
        assert!(result.is_ok(), "public_content_scenario_failed");
        println!("\n{COMPLETE}");
    } else {
        runtime.block_on(hosted_scenario());
    }
}

fn hosted_authority(gates: [Option<&str>; 3]) -> bool {
    gates == [Some("1"), Some("true"), Some("github-hosted")]
}

async fn hosted_scenario() {
    let before = host_state::HostState::capture().await;
    let proof = if before.is_ok() {
        namespace_proof().await
    } else {
        Err("before_capture")
    };
    let after = host_state::HostState::capture().await;
    let (routes, dns, firewall, sysctls, namespace) = match (&before, &after) {
        (Ok(first), Ok(last)) => (
            first.routes == last.routes,
            first.dns == last.dns,
            first.firewall == last.firewall,
            first.sysctls == last.sysctls,
            first.namespace == last.namespace,
        ),
        _ => (false, false, false, false, false),
    };
    let completed = proof.as_ref().is_ok_and(|report| report.success);
    let success = completed && routes && dns && firewall && sysctls && namespace;
    let status = if before.is_err() {
        "before_capture_failed"
    } else if after.is_err() {
        "after_capture_failed"
    } else if !completed {
        "daemon_proof_failed"
    } else if !success {
        "host_configuration_changed"
    } else {
        "passed"
    };
    // Only fixed enums, booleans and actual counts cross the capture boundary.
    let receipt = serde_json::json!({
        "version":1,"status":status,"success":success,
        "before_captured":before.is_ok(),"after_captured":after.is_ok(),
        "routes_unchanged":routes,"dns_unchanged":dns,"firewall_unchanged":firewall,
        "sysctls_unchanged":sysctls,"parent_namespace_unchanged":namespace,
        "child_stage":proof.as_ref().ok().map(|report|report.stage),
        "cleanup":proof.as_ref().ok().map(|report|report.cleanup),
        "counts":proof.as_ref().ok().map(|report|report.counts),
        "public_synthetic_only":true,"overlay_storage_proven":false,
        "named_site_open_proven":false,"power_loss_recovery_proven":false,
    });
    println!("\n{RECEIPT}{receipt}");
    assert!(success, "{status}");
}

async fn namespace_proof() -> Result<ChildReport> {
    let executable = std::env::current_exe().map_err(|_| "test_executable")?;
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let (success, output) =
        host_state::capture_command(&mut namespace_command(&runner, &executable), 135).await?;
    parse_child_output(success, &output)
}

fn namespace_command(runner: &Path, executable: &Path) -> Command {
    let mut command = Command::new(runner);
    command.arg("--command").arg("/usr/bin/env").args([
        TEST,
        MARKER,
        "loopback",
        "VOLPAROSSA_REQUIRE_PUBLIC_CONTENT_DAEMON_PROOF=1",
        "GITHUB_ACTIONS=true",
        "RUNNER_ENVIRONMENT=github-hosted",
    ]);
    command.arg(executable).args([
        "--ignored",
        "--exact",
        TEST,
        "--nocapture",
        "--test-threads=1",
    ]);
    command
}

fn parse_child_output(success: bool, output: &[u8]) -> Result<ChildReport> {
    let output = std::str::from_utf8(output).map_err(|_| "child_encoding")?;
    let reports = output
        .lines()
        .filter_map(|line| line.strip_prefix(CHILD_RECEIPT))
        .collect::<Vec<_>>();
    if reports.len() != 1 {
        return Err("child_report_count");
    }
    let report: ChildReport = serde_json::from_str(reports[0]).map_err(|_| "child_report_shape")?;
    let expected = if report.success {
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;"
    } else {
        "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured;"
    };
    let summaries = output
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect::<Vec<_>>();
    if report.version != 1
        || success != report.success
        || (report.stage == Stage::Complete) != report.success
        || (report.cleanup == Cleanup::NormalJoinedSocketAndFixtureRemoved) != report.success
        || (report.success && !report.counts.complete())
        || output.lines().filter(|line| *line == COMPLETE).count() != usize::from(report.success)
        || output
            .lines()
            .filter(|line| *line == "running 1 test")
            .count()
            != 1
        || summaries.len() != 1
        || !summaries[0].starts_with(expected)
    {
        return Err("exact_child_execution");
    }
    Ok(report)
}
