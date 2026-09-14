//! Read-only CPU/I/O/memory budget for explicitly authorized background work.
//!
//! These kernel samples do not observe all owner activity, battery state or thermal
//! limits. A quiet sample is capacity evidence, not proof that the user is absent.

use std::{
    fs::File,
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde::Serialize;

const MAX_FILE_BYTES: u64 = 16 * 1024;
const MAX_CGROUP_DEPTH: usize = 64;
const MIN_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
const QUIET_TIME: Duration = Duration::from_secs(5);
const MAX_SAMPLE_GAP: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Decision {
    Run,
    Pause,
    Cancel,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub(super) struct Observation {
    pub(super) cpu_some_avg10: Option<f64>,
    pub(super) io_some_avg10: Option<f64>,
    /// Minimum of host availability and every observed unified-cgroup parent cap.
    pub(super) memory_bytes: Option<u64>,
}

pub(super) struct Budget {
    observation: Observation,
    decision: Decision,
    quiet_since: Option<Instant>,
    last_sample: Option<Instant>,
    #[cfg(test)]
    fixed: Option<Decision>,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            observation: Observation::default(),
            decision: Decision::Pause,
            quiet_since: None,
            last_sample: None,
            #[cfg(test)]
            fixed: None,
        }
    }
}

impl Budget {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn sample(&mut self) -> Decision {
        #[cfg(test)]
        if let Some(decision) = self.fixed {
            return decision;
        }
        let observation = Observation {
            cpu_some_avg10: system_text(Path::new("/proc/pressure/cpu"))
                .ok()
                .and_then(|text| pressure_average(&text)),
            io_some_avg10: system_text(Path::new("/proc/pressure/io"))
                .ok()
                .and_then(|text| pressure_average(&text)),
            memory_bytes: memory_headroom(),
        };
        self.update(observation, Instant::now())
    }

    /// Pure broker fixtures can choose admission without sampling development-host
    /// load. This constructor does not exist in production or produce telemetry.
    #[cfg(test)]
    pub(super) fn fixed_for_test(decision: Decision) -> Self {
        Self {
            decision,
            fixed: Some(decision),
            ..Self::default()
        }
    }

    pub(super) const fn current(&self) -> Decision {
        self.decision
    }

    pub(super) const fn observation(&self) -> Observation {
        self.observation
    }

    fn update(&mut self, observation: Observation, now: Instant) -> Decision {
        let previous_sample = self.last_sample.replace(now);
        self.observation = observation;
        self.decision = if observation
            .memory_bytes
            .is_none_or(|bytes| bytes < MIN_MEMORY_BYTES)
        {
            self.quiet_since = None;
            Decision::Cancel
        } else if observation.cpu_some_avg10.is_none_or(|value| value >= 20.0)
            || observation.io_some_avg10.is_none_or(|value| value >= 10.0)
        {
            self.quiet_since = None;
            Decision::Pause
        } else if previous_sample.is_none() || self.decision == Decision::Run {
            self.quiet_since = None;
            Decision::Run
        } else {
            // A stalled sampler does not establish five seconds of known quiet.
            if previous_sample
                .is_some_and(|previous| now.saturating_duration_since(previous) > MAX_SAMPLE_GAP)
            {
                self.quiet_since = None;
            }
            let quiet_since = self.quiet_since.get_or_insert(now);
            if now.saturating_duration_since(*quiet_since) >= QUIET_TIME {
                Decision::Run
            } else {
                Decision::Pause
            }
        };
        self.decision
    }
}

fn system_text(path: &Path) -> Result<String, ErrorKind> {
    let mut text = String::new();
    File::open(path)
        .map_err(|error| error.kind())?
        .take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| error.kind())?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(ErrorKind::InvalidData);
    }
    Ok(text)
}

fn unsigned(text: &str) -> Option<u64> {
    (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

fn available_memory(text: &str) -> Option<u64> {
    let mut lines = text
        .lines()
        .filter(|line| line.starts_with("MemAvailable:"));
    let mut fields = lines.next()?.split_whitespace();
    if lines.next().is_some() || fields.next()? != "MemAvailable:" {
        return None;
    }
    let kibibytes = unsigned(fields.next()?)?;
    (fields.next()? == "kB" && fields.next().is_none())
        .then(|| kibibytes.checked_mul(1024))
        .flatten()
}

fn pressure_average(text: &str) -> Option<f64> {
    let mut some = text
        .lines()
        .map(str::split_whitespace)
        .filter(|fields| fields.clone().next() == Some("some"));
    let line = some.next()?;
    if some.next().is_some() {
        return None;
    }
    let mut averages = line.filter_map(|field| field.strip_prefix("avg10="));
    let value = averages.next()?.parse::<f64>().ok()?;
    (averages.next().is_none() && value.is_finite() && (0.0..=100.0).contains(&value))
        .then_some(value)
}

fn unified_path(text: &str) -> Option<PathBuf> {
    let mut groups = text.lines().filter_map(|line| line.strip_prefix("0::"));
    let group = groups.next()?;
    if groups.next().is_some() || !group.starts_with('/') {
        return None;
    }
    let relative = &group[1..];
    if relative.is_empty() {
        return Some(PathBuf::new());
    }
    let mut count = 0;
    for part in relative.split('/') {
        count += 1;
        if count > MAX_CGROUP_DEPTH
            || part.is_empty()
            || matches!(part, "." | "..")
            || part.chars().any(char::is_control)
        {
            return None;
        }
    }
    Some(PathBuf::from(relative))
}

fn capped_memory(available: u64, limit: &str, current: Option<&str>) -> Option<u64> {
    if limit.trim() == "max" {
        return Some(available);
    }
    let limit = unsigned(limit.trim())?;
    let used = unsigned(current?.trim())?;
    Some(available.min(limit.saturating_sub(used)))
}

fn memory_headroom() -> Option<u64> {
    let host = available_memory(&system_text(Path::new("/proc/meminfo")).ok()?)?;
    let relative = unified_path(&system_text(Path::new("/proc/self/cgroup")).ok()?)?;
    cgroup_headroom(host, &relative, system_text)
}

fn cgroup_headroom(
    mut available: u64,
    relative: &Path,
    read: impl Fn(&Path) -> Result<String, ErrorKind>,
) -> Option<u64> {
    let root = Path::new("/sys/fs/cgroup");
    let mut path = root.join(relative);
    loop {
        match read(&path.join("memory.max")) {
            Ok(limit) => {
                let current = if limit.trim() == "max" {
                    None
                } else {
                    Some(read(&path.join("memory.current")).ok()?)
                };
                available = capped_memory(available, &limit, current.as_deref())?;
            }
            Err(ErrorKind::NotFound) if path == root => {
                // The actual unified hierarchy root has no memory.max. Its
                // supported controllers distinguish that case from absent data.
                let controllers = read(&path.join("cgroup.controllers")).ok()?;
                if !controllers.split_whitespace().any(|name| name == "memory") {
                    return None;
                }
            }
            Err(ErrorKind::NotFound) => {
                // With memory disabled on the parent this child has no own cap;
                // continue upward, where an ancestor can still impose one.
                let parent = path.parent().filter(|parent| parent.starts_with(root))?;
                let controllers = read(&parent.join("cgroup.subtree_control")).ok()?;
                if controllers.split_whitespace().any(|name| name == "memory") {
                    return None;
                }
            }
            Err(_) => return None,
        }
        if path == root {
            return Some(available);
        }
        if !path.pop() || !path.starts_with(root) {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() -> Observation {
        Observation {
            cpu_some_avg10: Some(0.0),
            io_some_avg10: Some(0.0),
            memory_bytes: Some(MIN_MEMORY_BYTES),
        }
    }

    #[test]
    fn exact_thresholds_and_unknown_telemetry_never_claim_spare_capacity() {
        let now = Instant::now();
        assert_eq!(Budget::new().update(quiet(), now), Decision::Run);
        for observation in [
            Observation {
                cpu_some_avg10: Some(20.0),
                ..quiet()
            },
            Observation {
                io_some_avg10: Some(10.0),
                ..quiet()
            },
            Observation {
                cpu_some_avg10: None,
                ..quiet()
            },
            Observation {
                io_some_avg10: None,
                ..quiet()
            },
        ] {
            assert_eq!(Budget::new().update(observation, now), Decision::Pause);
        }
        for memory_bytes in [None, Some(0), Some(MIN_MEMORY_BYTES - 1)] {
            assert_eq!(
                Budget::new().update(
                    Observation {
                        memory_bytes,
                        ..quiet()
                    },
                    now
                ),
                Decision::Cancel
            );
        }
    }

    #[test]
    fn pause_requires_five_seconds_of_known_quiet_and_gap_resets_hysteresis() {
        let now = Instant::now();
        let mut budget = Budget::new();
        assert_eq!(budget.update(quiet(), now), Decision::Run);
        assert_eq!(
            budget.update(
                Observation {
                    io_some_avg10: None,
                    ..quiet()
                },
                now
            ),
            Decision::Pause
        );
        for tick in 1..=20 {
            assert_eq!(
                budget.update(quiet(), now + Duration::from_millis(tick * 250)),
                Decision::Pause
            );
        }
        assert_eq!(
            budget.update(quiet(), now + Duration::from_millis(5250)),
            Decision::Run
        );
        assert_eq!(budget.observation(), quiet());
        assert_eq!(budget.current(), Decision::Run);
        assert_eq!(
            budget.update(
                Observation {
                    memory_bytes: None,
                    ..quiet()
                },
                now + Duration::from_secs(6)
            ),
            Decision::Cancel
        );
        assert_eq!(
            budget.update(quiet(), now + Duration::from_secs(7)),
            Decision::Pause
        );
        assert_eq!(
            budget.update(quiet(), now + Duration::from_secs(12)),
            Decision::Pause
        );
    }

    #[test]
    fn memory_and_pressure_parsing_rejects_unknown_units_duplicates_and_nonfinite_values() {
        assert_eq!(
            available_memory("MemAvailable: 524288 kB\n"),
            Some(MIN_MEMORY_BYTES)
        );
        for invalid in [
            "MemFree: 100 kB",
            "MemAvailable: 12 MB",
            "MemAvailable: +12 kB",
            "MemAvailable: 1 kB\nMemAvailable: 2 kB",
            "MemAvailable: 18446744073709551615 kB",
        ] {
            assert_eq!(available_memory(invalid), None);
        }
        assert_eq!(
            pressure_average("some avg10=19.99 avg60=2.00 avg300=1.00 total=42\n"),
            Some(19.99)
        );
        for invalid in [
            "full avg10=0",
            "some avg10=NaN",
            "some avg10=inf",
            "some avg10=-1",
            "some avg10=100.1",
            "some avg10=1 avg10=2",
            "some avg10=1\nsome avg10=2",
        ] {
            assert_eq!(pressure_average(invalid), None);
        }
    }

    #[test]
    fn unified_paths_and_parent_caps_are_bounded_and_fail_closed() {
        assert_eq!(unified_path("0::/\n"), Some(PathBuf::new()));
        assert_eq!(
            unified_path("0::/user.slice/session.scope\n"),
            Some(PathBuf::from("user.slice/session.scope"))
        );
        for invalid in [
            "1:memory:/scope",
            "0::relative",
            "0::/a/../b",
            "0::/a/./b",
            "0::/a//b",
            "0::/a\n0::/b",
        ] {
            assert_eq!(unified_path(invalid), None);
        }
        assert!(
            unified_path(&format!(
                "0::/{}",
                vec!["a"; MAX_CGROUP_DEPTH + 1].join("/")
            ))
            .is_none()
        );
        assert_eq!(capped_memory(100, "max\n", None), Some(100));
        assert_eq!(capped_memory(100, "80", Some("30")), Some(50));
        assert_eq!(capped_memory(100, "80", Some("90")), Some(0));
        assert_eq!(capped_memory(100, "80", None), None);
        assert_eq!(capped_memory(100, "unknown", Some("0")), None);
        let reader = |path: &Path| match path.to_str().unwrap() {
            "/sys/fs/cgroup/parent/child/memory.max" => Ok("max".to_owned()),
            "/sys/fs/cgroup/parent/memory.max" => Ok("800".to_owned()),
            "/sys/fs/cgroup/parent/memory.current" => Ok("300".to_owned()),
            "/sys/fs/cgroup/cgroup.controllers" => Ok("cpu memory io".to_owned()),
            _ => Err(ErrorKind::NotFound),
        };
        assert_eq!(
            cgroup_headroom(900, Path::new("parent/child"), reader),
            Some(500)
        );
        assert_eq!(
            cgroup_headroom(900, Path::new("parent/child"), |_| Err(
                ErrorKind::PermissionDenied
            )),
            None
        );
    }
}
