//! Fixed owner-side pause/resume records and acknowledgements, never peer commands.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use tokio::time::{Duration, Instant};

const MAX_CONTROLS: usize = 128;
const ACK_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Action {
    Pause,
    Resume,
}

#[derive(Clone, Default)]
pub(super) struct Controls(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    issued: Vec<Action>,
    acknowledged: usize,
    issued_at: Option<Instant>,
    terminal: bool,
}

impl Controls {
    /// Reserve a bounded record before writing it, so a fast acknowledgement cannot race
    /// ahead of the owner's issuance ledger. Only one unacknowledged command is allowed.
    pub(super) fn issue(&self, action: Action, id: &str) -> Result<Option<Vec<u8>>> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("compute_control_lock"))?;
        if state.terminal {
            return Ok(None);
        }
        if state.acknowledged != state.issued.len() {
            ensure!(
                state
                    .issued_at
                    .is_some_and(|at| at.elapsed() < ACK_DEADLINE),
                "compute_control_ack_deadline"
            );
            return Ok(None);
        }
        if state.issued.last() == Some(&action) {
            return Ok(None);
        }
        ensure!(state.issued.len() < MAX_CONTROLS, "compute_control_budget");
        state.issued.push(action);
        state.issued_at = Some(Instant::now());
        let mut bytes = serde_json::to_vec(&serde_json::json!({
            "version":1,"id":id,"sequence":state.issued.len(),"action":action
        }))?;
        ensure!(bytes.len() < 1024, "compute_control_size");
        bytes.push(b'\n');
        Ok(Some(bytes))
    }

    /// A correlated result ends control issuance, not result/EOF/exit validation.
    pub(super) fn terminal(&self) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("compute_control_lock"))?
            .terminal = true;
        Ok(())
    }

    pub(super) fn acknowledge(&self, value: &Value) -> Result<()> {
        let sequence = value["control_sequence"]
            .as_u64()
            .context("compute_control_sequence")?;
        let action = match value["phase"].as_str() {
            Some("paused") => Action::Pause,
            Some("resumed") => Action::Resume,
            _ => anyhow::bail!("compute_control_phase"),
        };
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("compute_control_lock"))?;
        ensure!(
            sequence == state.acknowledged as u64 + 1
                && state.issued.get(state.acknowledged) == Some(&action),
            "compute_unissued_control_ack"
        );
        state.acknowledged += 1;
        Ok(())
    }

    pub(super) fn check_report(&self, report: &Value) -> Result<()> {
        let state = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("compute_control_lock"))?;
        let control = &report["owner_control"];
        let pauses = state.issued[..state.acknowledged]
            .iter()
            .filter(|action| **action == Action::Pause)
            .count();
        ensure!(
            state.acknowledged > 0
                && control["enabled"] == true
                && control["records_received"].as_u64() == Some(state.acknowledged as u64)
                && control["last_sequence"].as_u64() == Some(state.acknowledged as u64)
                && control["pause_count"].as_u64() == Some(pauses as u64)
                && control["resume_count"].as_u64() == Some((state.acknowledged - pauses) as u64)
                && control["paused_ms"].as_u64().is_some(),
            "compute_owner_control_report"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn terminal_result_stops_commands_without_approving_a_report() {
        let controls = Controls::default();
        controls.issue(Action::Resume, "a").unwrap();
        controls.terminal().unwrap();
        assert!(controls.issue(Action::Pause, "a").unwrap().is_none());
        assert!(controls.check_report(&serde_json::json!({})).is_err());
    }

    #[tokio::test]
    async fn pause_records_are_real_bounded_pipe_bytes_and_acks_cannot_be_invented() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let controls = Controls::default();
        let pause = controls.issue(Action::Pause, "a").unwrap().unwrap();
        let (mut sender, receiver) = tokio::io::duplex(1024);
        sender.write_all(&pause).await.unwrap();
        let mut line = String::new();
        BufReader::new(receiver).read_line(&mut line).await.unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["action"], "pause");
        assert_eq!(value["sequence"], 1);
        assert!(controls.issue(Action::Resume, "a").unwrap().is_none());
        assert!(
            controls
                .acknowledge(&serde_json::json!({"phase":"resumed","control_sequence":1}))
                .is_err()
        );
        controls
            .acknowledge(&serde_json::json!({"phase":"paused","control_sequence":1}))
            .unwrap();
        assert!(
            controls
                .acknowledge(&serde_json::json!({"phase":"paused","control_sequence":1}))
                .is_err()
        );
        assert!(controls.issue(Action::Pause, "a").unwrap().is_none());
        assert!(controls.issue(Action::Resume, "a").unwrap().is_some());
        controls
            .acknowledge(&serde_json::json!({"phase":"resumed","control_sequence":2}))
            .unwrap();
        controls.check_report(&serde_json::json!({"owner_control":{
            "enabled":true,"records_received":2,"last_sequence":2,"pause_count":1,"resume_count":1,"paused_ms":50
        }})).unwrap();
    }
}
