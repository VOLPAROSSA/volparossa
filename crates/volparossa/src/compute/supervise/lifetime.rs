//! Exact private sandbox lifetimes, retained across launcher exit/reparenting.
//!
//! Observation never signals a process. Only the existing owned `Child` is killed/reaped.
//! A PID reused by another lifetime is neither followed nor treated as a live old worker.

use std::{collections::BTreeSet, fs::File, io::Read as _, path::Path};

use anyhow::{Context as _, Result, ensure};
use tokio::time::{Duration, Instant};

use super::{MAX_OBSERVED_PROCESSES, process_children};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Identity {
    pid: u32,
    start_ticks: u64,
}

struct Record {
    identity: Identity,
    parent: u32,
}

pub(super) struct OwnedLifetimes {
    members: BTreeSet<Identity>,
    observation_failed: bool,
}

impl OwnedLifetimes {
    pub(super) fn capture(pid: u32) -> Result<Self> {
        let root = record(pid)?.context("compute_private_process_missing")?;
        let mut result = Self {
            members: BTreeSet::from([root.identity]),
            observation_failed: false,
        };
        result.refresh()?;
        Ok(result)
    }

    pub(super) fn refresh(&mut self) -> Result<()> {
        let result = self.refresh_inner();
        self.observation_failed |= result.is_err();
        result
    }

    fn refresh_inner(&mut self) -> Result<()> {
        let mut pending: Vec<_> = self.members.iter().copied().collect();
        let mut visited = BTreeSet::new();
        while let Some(expected) = pending.pop() {
            if !visited.insert(expected) || !same_lifetime(expected)? {
                continue;
            }
            let root = Path::new("/proc").join(expected.pid.to_string());
            let children = match process_children(&root) {
                Ok(children) => children,
                Err(_) if !same_lifetime(expected)? => continue,
                Err(error) => return Err(error),
            };
            if !same_lifetime(expected)? {
                continue;
            }
            for child in children {
                let Some(child) = record(child)? else {
                    continue;
                };
                if child.parent != expected.pid || !same_lifetime(expected)? {
                    continue;
                }
                if !self.members.contains(&child.identity) {
                    ensure!(
                        self.members.len() < MAX_OBSERVED_PROCESSES,
                        "compute_private_process_bound"
                    );
                    self.members.insert(child.identity);
                    pending.push(child.identity);
                }
            }
        }
        Ok(())
    }

    pub(super) async fn wait_closed(self, deadline: Instant) -> Result<()> {
        ensure!(
            !self.observation_failed,
            "compute_private_process_observation"
        );
        loop {
            let mut remaining = false;
            for member in &self.members {
                remaining |= same_lifetime(*member)?;
            }
            if !remaining {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "compute_private_process_cleanup_deadline"
            );
            tokio::time::sleep_until((Instant::now() + Duration::from_millis(10)).min(deadline))
                .await;
        }
    }
}

fn same_lifetime(expected: Identity) -> Result<bool> {
    Ok(record(expected.pid)?.is_some_and(|value| value.identity == expected))
}

fn record(pid: u32) -> Result<Option<Record>> {
    let file = match File::open(Path::new("/proc").join(pid.to_string()).join("stat")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut raw = String::new();
    file.take(8193).read_to_string(&mut raw)?;
    ensure!(raw.len() <= 8192, "compute_private_process_stat_bound");
    parse_record(pid, &raw).map(Some)
}

fn parse_record(pid: u32, raw: &str) -> Result<Record> {
    let (head, fields) = raw
        .rsplit_once(") ")
        .context("compute_private_process_stat")?;
    let (observed_pid, _) = head
        .split_once(" (")
        .context("compute_private_process_stat")?;
    ensure!(
        pid > 0 && observed_pid.parse::<u32>()? == pid,
        "compute_private_process_stat"
    );
    let fields: Vec<_> = fields.split_whitespace().collect();
    ensure!(fields.len() >= 20, "compute_private_process_stat");
    let parent = fields[1].parse().context("compute_private_process_stat")?;
    let start_ticks = fields[19].parse().context("compute_private_process_stat")?;
    Ok(Record {
        identity: Identity { pid, start_ticks },
        parent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_identity_uses_pid_and_start_ticks_without_interpreting_command_text() {
        let mut fields = vec!["0"; 20];
        fields[0] = "Z";
        fields[1] = "11";
        fields[19] = "12345";
        let raw = format!("77 (arbitrary ) private command) {}", fields.join(" "));
        let observed = parse_record(77, &raw).unwrap();
        assert_eq!(
            observed.identity,
            Identity {
                pid: 77,
                start_ticks: 12345
            }
        );
        assert_eq!(observed.parent, 11);
        assert!(parse_record(78, &raw).is_err());
        assert!(parse_record(77, "77 (incomplete) S 11").is_err());
    }

    #[tokio::test]
    async fn owned_process_must_end_but_a_reused_pid_is_not_followed_or_signalled() {
        // One ordinary owned process, no model, network, namespaces or privileged operation.
        let mut child = tokio::process::Command::new("/usr/bin/sleep")
            .arg("10")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let tracker = OwnedLifetimes::capture(pid).unwrap();
        let expected = *tracker.members.first().unwrap();
        let old_lifetime = OwnedLifetimes {
            members: BTreeSet::from([Identity {
                start_ticks: expected.start_ticks + 1,
                ..expected
            }]),
            observation_failed: false,
        };
        old_lifetime
            .wait_closed(Instant::now() + Duration::from_millis(20))
            .await
            .unwrap();
        assert!(child.try_wait().unwrap().is_none());
        let timed_out = tracker
            .wait_closed(Instant::now() + Duration::from_millis(20))
            .await;
        let tracker = OwnedLifetimes::capture(pid).unwrap();
        child.kill().await.unwrap();
        assert!(timed_out.is_err());
        tracker
            .wait_closed(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_incomplete_observation_cannot_confirm_cleanup() {
        let tracker = OwnedLifetimes {
            members: BTreeSet::new(),
            observation_failed: true,
        };
        assert!(tracker.wait_closed(Instant::now()).await.is_err());
    }
}
