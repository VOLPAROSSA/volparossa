//! Opt-in, closed local lifecycle facts. Never a prompt, request ID, path or raw error.
//! These observations do not assert cleanup, successful inference or trusted peer evidence.

use anyhow::Error;
use serde::Serialize;

const FIXED_CODES: &[&str] = &[
    "compute_deadline",
    "compute_owner_busy",
    "compute_memory_budget",
    "compute_storage_budget",
    "compute_process_bound",
    "compute_thread_bound",
    "compute_process_observation",
    "compute_observation_size",
    "compute_private_process_observation",
    "compute_private_process_missing",
    "compute_private_process_bound",
    "compute_private_process_stat",
    "compute_private_process_stat_open",
    "compute_private_process_stat_read",
    "compute_private_process_stat_bound",
    "compute_private_process_children",
    "compute_private_process_cleanup_deadline",
    "compute_private_storage_cleanup_failed",
    "compute_reap_deadline",
    "compute_reap",
    "compute_request_write_deadline",
    "compute_request_write",
    "compute_control_write_deadline",
    "compute_control_write",
    "compute_memory_pressure",
    "compute_device_reserve",
    "compute_owner_pressure",
    "compute_pressure_observation",
    "compute_worker_json",
    "compute_worker_correlation",
    "compute_worker_phase",
    "compute_worker_status",
    "compute_worker_kind",
    "compute_worker_line_size",
    "compute_worker_unterminated_line",
    "compute_stdout_size",
    "compute_stderr_size",
    "compute_stderr_read",
    "compute_wait",
    "compute_worker_exit",
];

const WORKER_CODES: &[&str] = &[
    "JOB_INPUT_NOT_FOUND",
    "JOB_PATH_PERMISSION_DENIED",
    "JOB_MEMORY_EXHAUSTED",
    "BACKEND_IMPORT_FAILED",
    "BACKEND_EXECUTION_FAILED",
    "BACKEND_NOT_INSTALLED",
    "BACKEND_VERSION_MISMATCH",
    "CPU_BACKEND_REQUIRED",
    "MODEL_PARAMETER_DTYPE_MISMATCH",
    "MODEL_WEIGHTS_CHANGED_ON_DISK",
    "CONVERSATION_TOKENIZER_SHAPE",
    "CONVERSATION_TOKEN_LIMIT",
    "RESULT_TOO_LARGE",
    "CANCELLED",
    "DEADLINE_EXCEEDED",
];

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct Detail {
    code: &'static str,
    io_kind: &'static str,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stderr_class: Option<&'static str>,
}

pub(super) fn describe(error: &Error) -> Detail {
    let io_kind = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .map_or("none", |error| match error.kind() {
            std::io::ErrorKind::NotFound => "not_found",
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::UnexpectedEof => "unexpected_eof",
            std::io::ErrorKind::BrokenPipe => "broken_pipe",
            std::io::ErrorKind::Interrupted => "interrupted",
            std::io::ErrorKind::InvalidData => "invalid_data",
            _ => "other",
        });
    let mut detail = Detail {
        code: "unclassified",
        io_kind,
        exit_code: None,
        signal: None,
        stderr_class: None,
    };
    if let Some(startup) = error.downcast_ref::<super::StartupFailure>() {
        detail.code = "startup_missing_result";
        detail.exit_code = Some(startup.exit_code);
        detail.signal = Some(startup.signal);
        detail.stderr_class = Some(startup.stderr_class);
    } else if let Some(worker) = error.downcast_ref::<super::PendingWorkerFailure>() {
        detail.code = WORKER_CODES
            .iter()
            .copied()
            .find(|code| *code == worker.code)
            .unwrap_or("worker_other");
    } else {
        for cause in error.chain() {
            let message = cause.to_string();
            if let Some(code) = FIXED_CODES.iter().copied().find(|code| *code == message) {
                detail.code = code;
                break;
            }
        }
    }
    detail
}

pub(in crate::compute) fn failure(phase: &'static str, error: &Error) {
    emit(phase, &describe(error));
}

pub(in crate::compute) fn event(phase: &'static str, code: &'static str) {
    emit(
        phase,
        &Detail {
            code,
            io_kind: "none",
            exit_code: None,
            signal: None,
            stderr_class: None,
        },
    );
}

fn emit(phase: &'static str, detail: &Detail) {
    // A dedicated target is off by default. Its fixture log is private and removed;
    // only a second independently closed parser can populate exported diagnostics.
    let record = serde_json::json!({"version": 1, "phase": phase, "detail": detail});
    tracing::debug!(target: "volparossa::compute::private_diagnostic",
        "private_execution_diagnostic {record}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_subscriber_output_passes_the_private_fixture_parser() {
        const CHILD: &str = "VOLPAROSSA_DIAGNOSTIC_BRIDGE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            // Exactly the production formatter, including its default ANSI decision;
            // NO_COLOR is supplied to this isolated test process, never mutated globally.
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap())
                .with_target(false)
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                failure(
                    "refresh",
                    &Error::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "PRIVATE_BRIDGE_CANARY /private/path",
                    ))
                    .context("compute_private_process_children"),
                );
            });
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "compute::supervise::diagnostic::tests::actual_subscriber_output_passes_the_private_fixture_parser",
                "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("NO_COLOR", "1")
            .env("RUST_LOG", "off,volparossa::compute::private_diagnostic=debug")
            .output().unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = std::str::from_utf8(&output.stdout).unwrap();
        assert!(
            !text.contains("PRIVATE_BRIDGE_CANARY")
                && !text.contains("/private/path")
                && !text.contains('\u{1b}')
        );
        let mut log = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut log, &output.stdout).unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/integration/agent-private-conversation.py");
        let result = std::process::Command::new("python3")
            .args([
                "-B",
                "-c",
                r"
import runpy, sys
from pathlib import Path
fixture = runpy.run_path(sys.argv[1])
result = fixture['service_diagnostic'](Path(sys.argv[2]))
assert result == dict(version=1, truncated=False, unrecognized_record=False, events=[dict(
    version=1, phase='refresh', detail=dict(code='compute_private_process_children',
    io_kind='permission_denied', exit_code=None, signal=None, stderr_class=None))])
",
            ])
            .arg(fixture)
            .arg(log.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "closed diagnostic parser rejected actual subscriber output"
        );
        assert!(result.stdout.is_empty() && result.stderr.is_empty());
    }

    #[test]
    fn diagnostics_keep_operation_and_errno_but_never_arbitrary_error_text() {
        let error = Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private canary /home/owner/photo.jpg",
        ))
        .context("compute_private_process_children");
        let detail = describe(&error);
        assert_eq!(detail.code, "compute_private_process_children");
        assert_eq!(detail.io_kind, "permission_denied");
        let raw = serde_json::to_string(&detail).unwrap();
        assert!(!raw.contains("canary") && !raw.contains("photo") && !raw.contains("/home"));
        assert_eq!(
            describe(&anyhow::anyhow!("private dynamic failure")).code,
            "unclassified"
        );
    }

    #[test]
    fn diagnostics_do_not_export_unknown_uppercase_worker_codes_as_safe_text() {
        let failure = |code: &str| {
            Error::new(super::super::PendingWorkerFailure {
                request_id: "private-request-canary".into(),
                code: code.into(),
                planner_diagnostic: None,
            })
        };
        assert_eq!(
            describe(&failure("BACKEND_IMPORT_FAILED")).code,
            "BACKEND_IMPORT_FAILED"
        );
        let raw = serde_json::to_string(&describe(&failure("PRIVATE_CANARY"))).unwrap();
        assert!(raw.contains("worker_other"));
        assert!(!raw.contains("CANARY") && !raw.contains("request"));
    }
}
