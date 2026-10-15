//! Closed service-boundary observations, not actual model or sandbox evidence.

use super::*;

const CHILD: &str = "VOLPAROSSA_TASK_DIAGNOSTIC_CHILD";
const INPUT: &[u8] = br#"{
    "version":1,"visibility":"private_local","question":"Hello?","context":"PRIVATE_TASK_CANARY"
}"#;

fn result_binding_failure() -> anyhow::Error {
    // The real validator rejects this synthetic worker report. No model runs.
    private_task::validate_mode_report(
        &json!({"status":"ok","outputs":[{"text":"PRIVATE_TASK_CANARY"}]}),
        INPUT,
        ModelProfile::Smol360,
        super::super::super::Mode::PrivateInfer,
    )
    .unwrap_err()
}

const PARSER_CHECK: &str = r"
import json, runpy, sys
from pathlib import Path
fixture = runpy.run_path(sys.argv[1])
value = fixture['service_diagnostic'](Path(sys.argv[2]))
codes = ['compute_private_budget', 'compute_private_result_scope', 'unclassified'] if sys.argv[3] == '1' else []
assert value == dict(version=1, truncated=False, unrecognized_record=False, events=[dict(
    version=1, phase='task', detail=dict(code=code, io_kind='none', exit_code=None,
    signal=None, stderr_class=None)) for code in codes])
assert 'PRIVATE_TASK_CANARY' not in json.dumps(value)
";

#[test]
fn service_task_failures_cover_pre_supervisor_and_result_binding_only_when_opted_in() {
    if std::env::var_os(CHILD).is_some() {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap())
            .with_ansi(false)
            .with_target(false)
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let root = tempfile::tempdir().unwrap();
                let mut config = config(root.path());
                config.threads = 0;
                let gate = Arc::new(Semaphore::new(1));
                let slot = ExecutionSlot::admit(&gate).unwrap();
                let mut task = Active::start(FIRST.into(), Arc::new(config), INPUT.to_vec(), slot);
                let result = task.reap().await;
                assert_eq!(
                    result.as_ref().unwrap_err().to_string(),
                    "compute_private_budget"
                );
                assert_eq!(
                    terminal_response(&task, Ok(result), &gate),
                    wire::error(Some(FIRST), "execution_failed")
                );
                assert_eq!(gate.available_permits(), 1);
                assert!(!root.path().join("work").exists());

                for error in [
                    result_binding_failure(),
                    anyhow::anyhow!("PRIVATE_TASK_CANARY /private/task"),
                ] {
                    let mut slot = ExecutionSlot::admit(&gate).unwrap();
                    let result = finish_execution(&mut slot, Err(error));
                    assert!(slot.cleanup_confirmed);
                    drop(slot);
                    assert_eq!(
                        terminal_response(&task, Ok(result), &gate),
                        wire::error(Some(FIRST), "execution_failed")
                    );
                }
            });
        return;
    }
    for enabled in [false, true] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "compute::private_serve::tests::task_diagnostic::service_task_failures_cover_pre_supervisor_and_result_binding_only_when_opted_in",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .env(
                "RUST_LOG",
                if enabled {
                    "off,volparossa::compute::private_diagnostic=debug"
                } else {
                    "off"
                },
            )
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = std::str::from_utf8(&output.stdout).unwrap();
        assert!(!text.contains("PRIVATE_TASK_CANARY") && !text.contains("/private/task"));
        let mut log = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut log, &output.stdout).unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/integration/agent-private-conversation.py");
        let parsed = std::process::Command::new("python3")
            .args(["-B", "-c", PARSER_CHECK])
            .arg(fixture)
            .arg(log.path())
            .arg(if enabled { "1" } else { "0" })
            .output()
            .unwrap();
        assert!(parsed.status.success());
        assert!(parsed.stdout.is_empty() && parsed.stderr.is_empty());
    }
}

#[test]
fn task_diagnostic_cannot_override_cleanup_cancel_or_success() {
    let (activity, _signal) = watch::channel(true);
    let mut task = Active {
        id: FIRST.into(),
        activity,
        execution: None,
        cancelled: false,
        budget_error: true,
    };
    for cancelled in [false, true] {
        task.cancelled = cancelled;
        let gate = Arc::new(Semaphore::new(1));
        let mut slot = ExecutionSlot::admit(&gate).unwrap();
        let result = finish_execution(&mut slot, Err(result_binding_failure()));
        drop(slot);
        let expected = if cancelled {
            "cancelled"
        } else {
            "execution_failed"
        };
        assert_eq!(
            terminal_response(&task, Ok(result), &gate),
            wire::error(Some(FIRST), expected)
        );
        let mut slot = ExecutionSlot::admit(&gate).unwrap();
        let result = finish_execution(&mut slot, Err(private_task::CleanupUnconfirmed.into()));
        assert!(!slot.cleanup_confirmed);
        drop(slot);
        assert!(gate.is_closed());
        assert_eq!(
            terminal_response(&task, Ok(result), &gate),
            wire::error(Some(FIRST), "cleanup_unconfirmed")
        );
    }
    task.cancelled = false;
    let gate = Arc::new(Semaphore::new(1));
    let mut slot = ExecutionSlot::admit(&gate).unwrap();
    let answer = json!({"synthetic":"unchanged"});
    let result = finish_execution(&mut slot, Ok(answer.clone()));
    drop(slot);
    assert_eq!(
        terminal_response(&task, Ok(result), &gate)["result"],
        answer
    );
}
