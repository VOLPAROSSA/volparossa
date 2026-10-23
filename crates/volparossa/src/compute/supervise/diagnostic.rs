//! Opt-in, closed local lifecycle facts. Never a prompt, request ID, path or raw error.
//! These observations do not assert cleanup, successful inference or trusted peer evidence.

use anyhow::Error;
use serde::Serialize;
use serde_json::Value;
use std::sync::Mutex;

mod generation;

const FIXED_CODES: &[&str] = &[
    // Private-service setup/result boundaries outside the worker supervisor.
    // Exact equality only: prefixes and path-bearing messages remain unknown.
    "compute_private_budget",
    "compute_model_memory_headroom",
    "compute_runtime_busy",
    "compute_lock_invalid",
    "compute_output_create",
    "compute_sandbox_spawn",
    "compute_sandbox_prerequisite",
    "compute_runtime_missing",
    "compute_native_backend_authorization",
    "compute_native_backend_manifest_hash",
    "compute_native_backend_manifest_schema",
    "compute_native_backend_identity",
    "compute_native_backend_artifacts",
    "compute_native_backend_conversion",
    "compute_native_backend_file",
    "compute_native_backend_scope",
    "compute_native_backend_policy",
    "compute_native_backend_output_constraint",
    "compute_private_result_scope",
    "compute_private_result_input",
    "compute_private_result_model",
    "compute_private_result_model_weights",
    "compute_private_result_outputs",
    "compute_private_result_output",
    "compute_native_backend_result_binding",
    "compute_native_backend_result_precision",
    "compute_native_backend_output_constraint_binding",
    "conversation_generation_policy_binding",
    "conversation_output_constraint_binding",
    "conversation_report_binding",
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
    "compute_control_ack_deadline",
    "compute_private_progress",
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
    "conversation_request_id",
    "conversation_native_marker",
    "conversation_native_call",
    "conversation_native_preface",
    // Retained for original receipts; new JSON rejections use closed categories.
    "conversation_native_json",
    "conversation_native_json_syntax",
    "conversation_native_json_data",
    "conversation_native_json_eof",
    "conversation_native_json_io",
    "conversation_unknown_tool",
    "conversation_custom_input",
    "conversation_arguments",
    "conversation_call_id",
    "conversation_empty_answer",
    "conversation_native_output_other",
];

const PRIVATE_STAGES: &[&str] = &[
    "owner_gate",
    "verify_files",
    "backend_import",
    "tokenizer_load",
    "prompt_encode",
    "model_load",
    "generation",
    "verify_after",
    "result",
];
const PROGRESS_PHASES: &[&str] = &[
    "preparing",
    "baseline",
    "training",
    "checkpoint",
    "reload",
    "complete",
    "paused",
    "resumed",
];

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
struct Substage {
    stage: &'static str,
    state: &'static str,
    elapsed_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct ProgressState {
    last_phase: Option<&'static str>,
    substage: Option<Substage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<generation::Observation>,
}

#[derive(Default)]
pub(super) struct Progress(Mutex<ProgressState>, bool);

impl Progress {
    pub(super) fn with_generation(enabled: bool) -> Self {
        Self(Mutex::default(), enabled)
    }
    /// Called only after framing/correlation and owner ACK validation. Retain
    /// closed labels, not the worker's Value or any private request material.
    pub(super) fn observe(&self, value: &Value) -> anyhow::Result<()> {
        use anyhow::{Context, ensure};
        let phase = PROGRESS_PHASES
            .iter()
            .copied()
            .find(|phase| value["phase"].as_str() == Some(*phase))
            .context("compute_private_progress")?;
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("compute_private_progress"))?;
        if let Some(progress) = value.get("private_generation") {
            ensure!(
                self.1
                    && phase == "baseline"
                    && value.as_object().is_some_and(|v| v.len() == 7)
                    && value.get("control_sequence").is_none()
                    && value.get("planner").is_none()
                    && value.get("private_execution").is_none()
                    && value["step"].as_u64() == Some(0)
                    && state
                        .substage
                        .is_some_and(|stage| stage.stage == "generation" && stage.state == "begin"),
                "compute_private_progress"
            );
            let elapsed = value["elapsed_ms"]
                .as_u64()
                .context("compute_private_progress")?;
            ensure!(
                state
                    .substage
                    .is_some_and(|stage| elapsed >= stage.elapsed_ms),
                "compute_private_progress"
            );
            state.generation = Some(generation::Observation::observe(
                state.generation,
                progress,
                elapsed,
            )?);
        }
        if let Some(progress) = value.get("private_execution") {
            ensure!(
                progress.as_object().is_some_and(|object| object.len() == 2)
                    && value.get("control_sequence").is_none()
                    && value.get("planner").is_none()
                    && value["step"].as_u64() == Some(0),
                "compute_private_progress"
            );
            let index = PRIVATE_STAGES
                .iter()
                .position(|stage| progress["stage"].as_str() == Some(*stage))
                .context("compute_private_progress")?;
            let next = ["begin", "complete"]
                .into_iter()
                .find(|stage| progress["state"].as_str() == Some(*stage))
                .context("compute_private_progress")?;
            let elapsed_ms = value["elapsed_ms"]
                .as_u64()
                .filter(|elapsed| *elapsed < 600_000)
                .context("compute_private_progress")?;
            ensure!(
                phase == if index < 6 { "preparing" } else { "baseline" },
                "compute_private_progress"
            );
            let expected = match state.substage {
                None => index == 0 && next == "begin",
                Some(previous) => {
                    let previous_index = PRIVATE_STAGES
                        .iter()
                        .position(|stage| *stage == previous.stage)
                        .context("compute_private_progress")?;
                    elapsed_ms >= previous.elapsed_ms
                        && ((previous.state == "begin"
                            && next == "complete"
                            && index == previous_index)
                            || (previous.state == "complete"
                                && next == "begin"
                                && index == previous_index + 1))
                }
            };
            ensure!(expected, "compute_private_progress");
            state.substage = Some(Substage {
                stage: PRIVATE_STAGES[index],
                state: next,
                elapsed_ms,
            });
        }
        state.last_phase = Some(phase);
        Ok(())
    }
}

/// Terminal execution observation, before cleanup. This proves neither cleanup
/// nor successful model loading/inference; an entered stage can wait at a gate.
pub(super) fn terminal_state(
    progress: &Progress,
    budget: &super::Budget,
    controls: Option<&super::Controls>,
    peak_rss: u64,
) {
    let state = progress.0.lock().map(|state| *state).unwrap_or_default();
    let observation = budget.observation();
    let mut record = serde_json::json!({"version":1,
        "last_phase":state.last_phase,"substage":state.substage,
        "capacity":{"decision":budget.current(),"constraint":budget.constraint(),
            "cpu_some_avg10":observation.cpu_some_avg10,"io_some_avg10":observation.io_some_avg10,
            "memory_bytes":observation.memory_bytes},
        "controls":controls.and_then(super::Controls::observation),"peak_rss_bytes":peak_rss});
    if let Some(generation) = state.generation {
        record["generation"] = serde_json::to_value(generation.snapshot)
            .expect("closed scalar generation observation");
    }
    tracing::debug!(target: "volparossa::compute::private_diagnostic",
        "private_execution_state {record}");
}

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
    "JOB_CANCELLED",
    "JOB_DEADLINE_EXCEEDED",
    "NATIVE_ABI_MISMATCH",
    "NATIVE_BUILD_PATCH_BINDING",
    "NATIVE_OPEN_DIAGNOSTIC_INVALID",
    "NATIVE_OPEN_INVALID_ARGUMENT",
    "NATIVE_CPU_UNSUPPORTED",
    "NATIVE_BACKEND_INITIALIZATION_FAILED",
    "NATIVE_MODEL_INITIALIZATION_FAILED",
    "NATIVE_VOCABULARY_MISMATCH",
    "NATIVE_CONTEXT_INITIALIZATION_FAILED",
    "NATIVE_SAMPLER_INITIALIZATION_FAILED",
    "NATIVE_MODEL_LOAD_FAILED",
    "NATIVE_OWNER_CONTROL_FAILED",
    "INVALID_NATIVE_CONTROL",
];

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(super) struct Detail {
    code: &'static str,
    io_kind: &'static str,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stderr_class: Option<&'static str>,
}

impl Detail {
    // Only the sealed public-fixture accessor uses this copy. Ordinary Detail
    // serialization, StartupClass and StartupFailure remain unchanged.
    pub(super) fn with_public_bubblewrap_stage(
        mut self,
        stage: Option<super::BubblewrapStage>,
    ) -> Self {
        if let Some(stage) = stage.filter(|_| {
            self.code == "compute_native_session_stdout_closed"
                && self.stderr_class == Some("bubblewrap")
        }) {
            self.stderr_class = Some(stage.label());
        }
        self
    }

    pub(super) fn with_native_stdout_close(
        mut self,
        status_before_cleanup: Option<std::process::ExitStatus>,
        stderr_class: &'static str,
    ) -> Self {
        use std::os::unix::process::ExitStatusExt as _;

        // Preserve the primary failure and every other code's existing shape.
        // These are observations, not successful execution or causal attribution.
        if self.code == "compute_native_session_stdout_closed" {
            if let Some(status) = status_before_cleanup {
                self.exit_code = Some(status.code().unwrap_or(-1));
                self.signal = Some(status.signal().unwrap_or(0));
            }
            self.stderr_class = Some(stderr_class);
        }
        self
    }
}

/// Exact closed vocabulary shared by the public-fixture writer and reader.
/// This validates a projection, never constructs cleanup or execution authority.
pub(in crate::compute) fn public_fixture_detail(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 5
        || !["code", "io_kind", "exit_code", "signal", "stderr_class"]
            .iter()
            .all(|key| object.contains_key(*key))
    {
        return false;
    }
    let code = value["code"].as_str().unwrap_or("");
    let known = FIXED_CODES
        .iter()
        .chain(WORKER_CODES)
        .chain(SESSION_CODES)
        .chain(SESSION_WORKER_CODES)
        .copied()
        .any(|known| code == known)
        || ["unclassified", "worker_other", "startup_missing_result"].contains(&code);
    let io = value["io_kind"].as_str().is_some_and(|kind| {
        [
            "none",
            "not_found",
            "permission_denied",
            "unexpected_eof",
            "broken_pipe",
            "interrupted",
            "invalid_data",
            "other",
        ]
        .contains(&kind)
    });
    let no_status = value["exit_code"].is_null()
        && value["signal"].is_null()
        && value["stderr_class"].is_null();
    let status = value["exit_code"]
        .as_i64()
        .zip(value["signal"].as_i64())
        .is_some_and(|(exit, signal)| {
            ((0..=255).contains(&exit) && signal == 0) || (exit == -1 && (1..=64).contains(&signal))
        });
    let stderr_class = value["stderr_class"].as_str().is_some_and(|class| {
        [
            "none",
            "bubblewrap",
            "user_namespace",
            "proc_mount",
            "exec_denied",
            "python_startup",
            "other",
        ]
        .contains(&class)
    });
    let public_stage = value["stderr_class"].as_str().is_some_and(|class| {
        [
            "bubblewrap_namespace_setup",
            "bubblewrap_root_setup",
            "bubblewrap_source_setup",
            "bubblewrap_destination_setup",
            "bubblewrap_bind_mount",
        ]
        .contains(&class)
    });
    let no_exit = value["exit_code"].is_null() && value["signal"].is_null();
    known
        && io
        && if code == "startup_missing_result" {
            status && stderr_class
        } else if code == "compute_native_session_stdout_closed" {
            // Old all-null messages remain exact. New observations require the
            // updated Rust/controller readers; older readers reject this shape.
            no_status || ((stderr_class || public_stage) && (no_exit || status))
        } else {
            no_status
        }
}

pub(super) fn describe(error: &Error) -> Detail {
    if let Some(detail) = super::native_session::diagnostic(error) {
        return detail;
    }
    if let Some(error) = error.downcast_ref::<ReceivedNativeWorkerFailure>() {
        return error.0;
    }
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

// Selected-session diagnostics only. Legacy FIXED_CODES/WORKER_CODES and their
// historical projections remain unchanged. Exact literals, never a code prefix
// or arbitrary uppercase text, are the complete additional export authority.
const SESSION_CODES: &[&str] = &[
    "compute_native_session_child_exited",
    "compute_native_session_cpu_backwards",
    "compute_native_session_cpu_bound",
    "compute_native_session_cpu_budget",
    "compute_native_session_cpu_clock",
    "compute_native_session_cpu_identity",
    "compute_native_session_cpu_stat",
    "compute_native_session_receiver",
    "compute_native_session_report",
    "compute_native_session_request_bound",
    "compute_native_session_root",
    "compute_native_session_stderr",
    "compute_native_session_stderr_closed",
    "compute_native_session_stdout_closed",
    "compute_native_session_turn_root",
    "compute_native_session_unrequested_idle",
    "compute_native_session_unsupported",
    "compute_native_session_worker",
    "compute_worker_invalid_json",
    "compute_output_after_result",
    "compute_result_missing",
];
const SESSION_WORKER_CODES: &[&str] = &[
    "NATIVE_DECODE_FAILED",
    "NATIVE_SAMPLE_FAILED",
    "NATIVE_SESSION_PREFIX_RESET_FAILED",
    "NATIVE_SESSION_CPU_OBSERVATION",
    "NATIVE_SESSION_CPU_BOUND",
    "NATIVE_SESSION_DEADLINE",
    "NATIVE_SESSION_MODEL_CHANGED",
    "NATIVE_SESSION_PREFIX_BOUND",
    "INVALID_NATIVE_SESSION_FINISH",
    "INVALID_NATIVE_SESSION_SEQUENCE",
];

pub(super) fn native_session_detail(error: &Error) -> Detail {
    let mut detail = describe(error);
    if detail.code == "unclassified" {
        for cause in error.chain() {
            let message = cause.to_string();
            if let Some(code) = SESSION_CODES.iter().copied().find(|code| *code == message) {
                detail.code = code;
                break;
            }
        }
    }
    detail
}

// Unlike WorkerFailure, this has no exit-status, adapter-quarantine, request-ID
// or cleanup authority. It retains only the independently closed projection.
#[derive(Debug)]
struct ReceivedNativeWorkerFailure(Detail);

impl std::fmt::Display for ReceivedNativeWorkerFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("compute_native_worker_error")
    }
}

impl std::error::Error for ReceivedNativeWorkerFailure {}

pub(super) fn native_worker_failure(value: &Value, id: &str) -> Option<Error> {
    if value.get("version") != Some(&Value::from(1))
        || value.get("id").and_then(Value::as_str) != Some(id)
        || value.get("kind").and_then(Value::as_str) != Some("result")
        || value.get("status").and_then(Value::as_str) != Some("error")
    {
        return None;
    }
    let code = WORKER_CODES
        .iter()
        .chain(SESSION_WORKER_CODES)
        .copied()
        .find(|code| value.get("code").and_then(Value::as_str) == Some(*code))
        .unwrap_or("worker_other");
    Some(Error::new(ReceivedNativeWorkerFailure(Detail {
        code,
        io_kind: "none",
        exit_code: None,
        signal: None,
        stderr_class: None,
    })))
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
    fn session_codes_are_exact_and_do_not_change_legacy_error_projection() {
        for code in SESSION_CODES {
            let original = anyhow::anyhow!("PRIVATE_CANARY /private/prompt").context(*code);
            assert_eq!(describe(&original).code, "unclassified");
            let detail = native_session_detail(&original);
            assert_eq!(detail.code, *code);
            let raw = serde_json::to_string(&detail).unwrap();
            assert!(!raw.contains("PRIVATE_CANARY") && !raw.contains("/private/"));
            let altered = anyhow::anyhow!("{code} PRIVATE_CANARY");
            assert_eq!(native_session_detail(&altered).code, "unclassified");
        }
    }

    #[test]
    fn received_native_codes_require_exact_correlation_and_never_invent_exit_facts() {
        let base = serde_json::json!({"version":1,"id":"PRIVATE_REQUEST_CANARY",
            "kind":"result","status":"error","code":"NATIVE_DECODE_FAILED"});
        for code in WORKER_CODES.iter().chain(SESSION_WORKER_CODES) {
            let mut value = base.clone();
            value["code"] = (*code).into();
            let error = native_worker_failure(&value, "PRIVATE_REQUEST_CANARY").unwrap();
            assert_eq!(
                describe(&error),
                Detail {
                    code,
                    io_kind: "none",
                    exit_code: None,
                    signal: None,
                    stderr_class: None,
                }
            );
            assert_eq!(error.chain().count(), 1);
            assert!(super::super::adapter_violation(&error).is_none());
            assert!(super::super::native_session::cleanup(&error).is_none());
        }
        for (key, changed) in [
            ("version", serde_json::json!(true)),
            ("version", serde_json::json!(2)),
            ("id", serde_json::json!("OTHER_PRIVATE_REQUEST")),
            ("kind", serde_json::json!("progress")),
            ("status", serde_json::json!("ok")),
        ] {
            let mut value = base.clone();
            value[key] = changed;
            assert!(native_worker_failure(&value, "PRIVATE_REQUEST_CANARY").is_none());
        }
    }

    #[test]
    fn native_worker_unknown_codes_and_extra_private_fields_never_escape_projection() {
        for code in [
            serde_json::json!("PRIVATE_CANARY"),
            serde_json::json!("NATIVE_DECODE_FAILED /private/PRIVATE_CANARY"),
            serde_json::json!("NATIVE_DECODE_FAILED\nPRIVATE_CANARY"),
            serde_json::json!(true),
            serde_json::json!({"private":"PRIVATE_CANARY"}),
            Value::Null,
        ] {
            let value = serde_json::json!({"version":1,"id":"PRIVATE_REQUEST_CANARY",
                "kind":"result","status":"error","code":code,
                "message":"PRIVATE_CANARY /private/input", "exit_code":42, "signal":9,
                "cleanup":{"child_reaped":true}});
            let error = native_worker_failure(&value, "PRIVATE_REQUEST_CANARY").unwrap();
            let detail = describe(&error);
            assert_eq!(detail.code, "worker_other");
            assert_eq!(detail.exit_code, None);
            assert_eq!(detail.signal, None);
            let raw = serde_json::to_string(&detail).unwrap();
            assert!(!raw.contains("CANARY") && !raw.contains("/private/") && !raw.contains("42"));
        }
    }

    fn progress(stage: &str, observation: &str, elapsed_ms: u64) -> Value {
        let index = PRIVATE_STAGES
            .iter()
            .position(|candidate| *candidate == stage)
            .unwrap_or(0);
        serde_json::json!({"phase":if index < 6 {"preparing"} else {"baseline"}, "step":0,
            "elapsed_ms":elapsed_ms,"private_execution":{"stage":stage,"state":observation}})
    }

    fn generation_frame() -> Value {
        serde_json::json!({"version":1,"id":"private-request-canary","kind":"progress",
            "phase":"baseline","step":0,"elapsed_ms":20,"private_generation":{
                "prompt_tokens":100,"threads":2,"interop_threads":1,
                "cpu":{"isa":null,"avx2":null,"avx512_bf16":null,"amx_bf16":null,
                    "amx_tile":null,"mkldnn_available":null,"mkldnn_enabled":null},
                "first_forward_started_ms":null,"first_forward_completed_ms":null,"first_token_ms":null,
                "generated_tokens":0,"complete":false,"elapsed_ms":20}})
    }

    fn enter_generation(observed: &Progress) {
        for (index, stage) in PRIVATE_STAGES.iter().take(7).enumerate() {
            observed
                .observe(&progress(stage, "begin", index as u64 * 2))
                .unwrap();
            if *stage != "generation" {
                observed
                    .observe(&progress(stage, "complete", index as u64 * 2 + 1))
                    .unwrap();
            }
        }
    }

    #[test]
    fn generation_requires_explicit_opt_in_correct_phase_and_closed_frames() {
        let frame = generation_frame();
        assert!(Progress::with_generation(true).observe(&frame).is_err());
        let disabled = Progress::default();
        enter_generation(&disabled);
        assert!(disabled.observe(&frame).is_err());
        for (key, value) in [
            ("control_sequence", serde_json::json!(1)),
            (
                "private_execution",
                serde_json::json!({"stage":"generation","state":"begin"}),
            ),
            ("payload", serde_json::json!("PRIVATE_CANARY")),
            ("phase", serde_json::json!("paused")),
        ] {
            let enabled = Progress::with_generation(true);
            enter_generation(&enabled);
            let mut changed = frame.clone();
            changed[key] = value;
            assert!(enabled.observe(&changed).is_err());
            assert!(enabled.0.lock().unwrap().generation.is_none());
        }
        let enabled = Progress::with_generation(true);
        enter_generation(&enabled);
        enabled.observe(&frame).unwrap();
        assert!(enabled.0.lock().unwrap().generation.is_some());
    }

    #[test]
    fn private_stages_are_closed_ordered_observations_not_model_proof() {
        let observed = Progress::default();
        for (index, stage) in PRIVATE_STAGES.iter().enumerate() {
            observed
                .observe(&progress(stage, "begin", index as u64 * 2))
                .unwrap();
            observed
                .observe(&serde_json::json!({"phase":"paused"}))
                .unwrap();
            assert_eq!(observed.0.lock().unwrap().substage.unwrap().state, "begin");
            observed
                .observe(&progress(stage, "complete", index as u64 * 2 + 1))
                .unwrap();
        }
        let value = serde_json::to_value(*observed.0.lock().unwrap()).unwrap();
        assert_eq!(
            value["substage"],
            serde_json::json!({"stage":"result","state":"complete","elapsed_ms":17})
        );
        assert!(
            observed
                .observe(&progress("owner_gate", "begin", 18))
                .is_err()
        );
        for invalid in [
            progress("private-canary", "begin", 0),
            progress("owner_gate", "private-canary", 0),
            progress("owner_gate", "complete", 0),
            progress("model_load", "begin", 0),
            progress("owner_gate", "begin", 600_000),
        ] {
            let observed = Progress::default();
            assert!(observed.observe(&invalid).is_err());
            assert!(observed.0.lock().unwrap().substage.is_none());
        }
        for (field, value) in [
            ("step", serde_json::json!(true)),
            ("elapsed_ms", serde_json::json!(-1)),
            ("phase", serde_json::json!("paused")),
            ("control_sequence", serde_json::json!(1)),
        ] {
            let mut invalid = progress("owner_gate", "begin", 0);
            invalid[field] = value;
            assert!(Progress::default().observe(&invalid).is_err());
        }
        let mut invalid = progress("owner_gate", "begin", 0);
        invalid["private_execution"]["payload"] = serde_json::json!("PRIVATE_CANARY");
        assert!(Progress::default().observe(&invalid).is_err());
        assert_eq!(
            describe(&anyhow::anyhow!("compute_control_ack_deadline")).code,
            "compute_control_ack_deadline"
        );
    }

    const SUBSCRIBER_PARSER_CHECK: &str = r"
import runpy, sys
from pathlib import Path
fixture = runpy.run_path(sys.argv[1])
result = fixture['service_diagnostic'](Path(sys.argv[2]))
generation = result['states'].pop()
assert generation['last_phase'] == 'baseline'
assert generation['substage'] == dict(stage='generation',state='begin',elapsed_ms=12)
assert generation['generation'] == dict(prompt_tokens=100, threads=2, interop_threads=1,
    cpu=dict(isa=None,avx2=None,avx512_bf16=None,amx_bf16=None,amx_tile=None,mkldnn_available=None,mkldnn_enabled=None),
    first_forward_started_ms=20, first_forward_completed_ms=20, first_token_ms=20,
    generated_tokens=1, complete=False, elapsed_ms=20)
assert result == dict(version=1, truncated=False, unrecognized_record=False, states=[dict(
    version=1,last_phase='paused',substage=dict(stage='owner_gate',state='begin',elapsed_ms=0),
    capacity=dict(decision='pause',constraint='memory',cpu_some_avg10=None,io_some_avg10=None,memory_bytes=None),
    controls=dict(issued=1,acknowledged=1,last_issued='pause',last_acknowledged='pause'),peak_rss_bytes=1234)], events=[dict(
    version=1, phase='refresh', detail=dict(code='compute_private_process_children',
    io_kind='permission_denied', exit_code=None, signal=None, stderr_class=None))])
";

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
                let observed = Progress::default();
                observed
                    .observe(&progress("owner_gate", "begin", 0))
                    .unwrap();
                observed
                    .observe(&serde_json::json!({"phase":"paused"}))
                    .unwrap();
                let controls = super::super::Controls::default();
                controls
                    .issue(super::super::Action::Pause, "PRIVATE_REQUEST_ID")
                    .unwrap();
                controls
                    .acknowledge(&serde_json::json!({"phase":"paused","control_sequence":1}))
                    .unwrap();
                terminal_state(
                    &observed,
                    &super::super::Budget::new(),
                    Some(&controls),
                    1234,
                );
                failure(
                    "refresh",
                    &Error::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "PRIVATE_BRIDGE_CANARY /private/path",
                    ))
                    .context("compute_private_process_children"),
                );
                let observed = Progress::with_generation(true);
                enter_generation(&observed);
                let mut frame = generation_frame();
                observed.observe(&frame).unwrap();
                frame["private_generation"]["first_forward_started_ms"] = 20.into();
                observed.observe(&frame).unwrap();
                frame["private_generation"]["first_forward_completed_ms"] = 20.into();
                observed.observe(&frame).unwrap();
                frame["private_generation"]["first_token_ms"] = 20.into();
                frame["private_generation"]["generated_tokens"] = 1.into();
                observed.observe(&frame).unwrap();
                terminal_state(&observed, &super::super::Budget::new(), None, 456);
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
                && !text.contains("PRIVATE_REQUEST_ID")
                && !text.contains('\u{1b}')
        );
        let mut log = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut log, &output.stdout).unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/integration/agent-private-conversation.py");
        let result = std::process::Command::new("python3")
            .args(["-B", "-c", SUBSCRIBER_PARSER_CHECK])
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
    fn fixed_task_codes_require_exact_equality_and_do_not_disclose_context() {
        for code in FIXED_CODES {
            let error = anyhow::anyhow!("PRIVATE_TASK_CANARY /private/input").context(*code);
            let detail = describe(&error);
            assert_eq!(detail.code, *code);
            let raw = serde_json::to_string(&detail).unwrap();
            assert!(!raw.contains("PRIVATE_TASK_CANARY") && !raw.contains("/private/input"));
            let altered = anyhow::anyhow!("{code} PRIVATE_TASK_CANARY");
            assert_eq!(describe(&altered).code, "unclassified");
        }
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
        assert_eq!(describe(&failure("JOB_CANCELLED")).code, "JOB_CANCELLED");
        for code in WORKER_CODES.iter().filter(|code| code.contains("NATIVE")) {
            assert_eq!(describe(&failure(code)).code, *code);
        }
        assert_eq!(
            describe(&failure("JOB_DEADLINE_EXCEEDED")).code,
            "JOB_DEADLINE_EXCEEDED"
        );
        let raw = serde_json::to_string(&describe(&failure("PRIVATE_CANARY"))).unwrap();
        assert!(raw.contains("worker_other"));
        assert!(!raw.contains("CANARY") && !raw.contains("request"));
    }
}
