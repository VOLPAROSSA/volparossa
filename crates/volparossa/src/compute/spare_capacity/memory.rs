//! The original admission sample, with opt-in closed observations of its inputs.
//! Reads are sequential, not an atomic snapshot, reservation or reclaim proof.

use std::{io::ErrorKind, path::Path};

use serde_json::{Value, json};

const JSON_MAX: u64 = (1 << 53) - 1;
const STAT_KEYS: [&str; 6] = [
    "anon",
    "file",
    "shmem",
    "inactive_file",
    "active_file",
    "kernel",
];

#[derive(Clone, Debug)]
struct Stat {
    state: &'static str,
    values: [Option<u64>; 6],
}

impl Default for Stat {
    fn default() -> Self {
        Self {
            state: "unobserved",
            values: [None; 6],
        }
    }
}

impl Stat {
    fn observe(path: &Path, read: &impl Fn(&Path) -> Result<String, ErrorKind>) -> Self {
        let Ok(raw) = read(&path.join("memory.stat")) else {
            return Self {
                state: "unavailable",
                ..Self::default()
            };
        };
        let mut result = Self {
            state: "observed",
            ..Self::default()
        };
        for line in raw.lines() {
            let mut fields = line.split_whitespace();
            let Some(key) = fields.next() else { continue };
            let Some(index) = STAT_KEYS.iter().position(|candidate| *candidate == key) else {
                continue;
            };
            let value = fields.next().and_then(super::unsigned);
            if result.values[index].is_some() || value.is_none() || fields.next().is_some() {
                return Self {
                    state: "invalid",
                    ..Self::default()
                };
            }
            result.values[index] = value;
        }
        if result.values.iter().any(Option::is_none) {
            return Self {
                state: "invalid",
                ..Self::default()
            };
        }
        result
    }

    fn overflow(&self) -> bool {
        self.values.iter().flatten().any(|value| *value > JSON_MAX)
    }

    fn snapshot(&self) -> Value {
        let overflow = self.overflow();
        let values = if overflow { [None; 6] } else { self.values };
        json!({"state":if overflow { "unrepresentable" } else { self.state },
            "anon_bytes":values[0],"file_bytes":values[1],"shmem_bytes":values[2],
            "inactive_file_bytes":values[3],"active_file_bytes":values[4],"kernel_bytes":values[5]})
    }
}

#[derive(Clone, Debug)]
pub(in crate::compute) struct Sample {
    pub(in crate::compute) headroom: Option<u64>,
    host: Option<u64>,
    own: Option<u64>,
    ancestor: Option<u64>,
    own_current: Option<u64>,
    own_max: Option<u64>,
    ancestor_current: Option<u64>,
    ancestor_max: Option<u64>,
    missing: &'static str,
    io_kind: &'static str,
    own_stat: Stat,
    ancestor_stat: Stat,
}

impl Default for Sample {
    fn default() -> Self {
        Self {
            headroom: None,
            host: None,
            own: None,
            ancestor: None,
            own_current: None,
            own_max: None,
            ancestor_current: None,
            ancestor_max: None,
            missing: "none",
            io_kind: "none",
            own_stat: Stat::default(),
            ancestor_stat: Stat::default(),
        }
    }
}

impl Sample {
    #[cfg(test)]
    pub(in crate::compute) fn for_test(headroom: Option<u64>) -> Self {
        Self {
            headroom,
            host: headroom,
            missing: if headroom.is_some() {
                "none"
            } else {
                "meminfo"
            },
            io_kind: if headroom.is_some() {
                "none"
            } else {
                "invalid_data"
            },
            ..Self::default()
        }
    }

    fn failed(mut self, stage: &'static str, error: ErrorKind) -> Self {
        self.headroom = None;
        self.missing = stage;
        self.io_kind = match error {
            ErrorKind::NotFound => "not_found",
            ErrorKind::PermissionDenied => "permission",
            ErrorKind::InvalidData => "invalid_data",
            _ => "other",
        };
        self
    }

    fn record_cap(&mut self, limit: &str, current: Option<&str>, own: bool) -> bool {
        // capped_memory already validated these strings. This records that
        // decision's inputs; optional statistics never participate in it.
        let maximum = super::unsigned(limit.trim());
        let used = current.and_then(|raw| super::unsigned(raw.trim()));
        if let (Some(maximum), Some(used)) = (maximum, used) {
            let free = maximum.saturating_sub(used);
            if own {
                self.own = Some(free);
                self.own_current = Some(used);
                self.own_max = Some(maximum);
            } else if self.ancestor.is_none_or(|previous| free < previous) {
                self.ancestor = Some(free);
                self.ancestor_current = Some(used);
                self.ancestor_max = Some(maximum);
                return true;
            }
        }
        false
    }

    pub(in crate::compute) fn snapshot(&self) -> Value {
        let values = [
            self.headroom,
            self.host,
            self.own,
            self.ancestor,
            self.own_current,
            self.own_max,
            self.ancestor_current,
            self.ancestor_max,
        ];
        let overflow = values.iter().flatten().any(|value| *value > JSON_MAX)
            || self.own_stat.overflow()
            || self.ancestor_stat.overflow();
        let values = values.map(|value| value.filter(|number| *number <= JSON_MAX));
        let limiting = self.headroom.map_or("unknown", |minimum| {
            let scopes = [
                (self.host, "host"),
                (self.own, "self"),
                (self.ancestor, "ancestor"),
            ];
            let mut matching = scopes
                .into_iter()
                .filter(|(value, _)| *value == Some(minimum));
            let first = matching.next().map_or("unknown", |(_, scope)| scope);
            if matching.next().is_some() {
                "multiple"
            } else {
                first
            }
        });
        json!({"headroom_bytes":values[0],"host_available_bytes":values[1],
            "self_headroom_bytes":values[2],"ancestor_headroom_bytes":values[3],
            "self_current_bytes":values[4],"self_max_bytes":values[5],
            "ancestor_current_bytes":values[6],"ancestor_max_bytes":values[7],
            "limiting_scope":limiting,"missing_stage":self.missing,"io_kind":self.io_kind,
            "numeric_overflow":overflow,"self_stat":self.own_stat.snapshot(),
            "ancestor_stat":self.ancestor_stat.snapshot()})
    }
}

pub(in crate::compute) fn enabled() -> bool {
    tracing::enabled!(target: "volparossa::compute::private_diagnostic", tracing::Level::DEBUG)
}

pub(in crate::compute) fn emit(record: &Value) {
    tracing::debug!(target: "volparossa::compute::private_diagnostic",
        "private_memory_diagnostic {record}");
}

pub(in crate::compute) fn sample(stats: bool) -> Sample {
    sample_with(stats, &super::system_text)
}

fn sample_with(stats: bool, read: &impl Fn(&Path) -> Result<String, ErrorKind>) -> Sample {
    let host = match read(Path::new("/proc/meminfo")) {
        Ok(raw) => match super::available_memory(&raw) {
            Some(value) => value,
            None => return Sample::default().failed("meminfo", ErrorKind::InvalidData),
        },
        Err(error) => return Sample::default().failed("meminfo", error),
    };
    let partial = Sample {
        host: Some(host),
        ..Sample::default()
    };
    let relative = match read(Path::new("/proc/self/cgroup")) {
        Ok(raw) => match super::unified_path(&raw) {
            Some(value) => value,
            None => return partial.failed("cgroup_path", ErrorKind::InvalidData),
        },
        Err(error) => return partial.failed("cgroup_path", error),
    };
    cgroup_sample(host, &relative, read, stats)
}

pub(super) fn cgroup_sample(
    host: u64,
    relative: &Path,
    read: &impl Fn(&Path) -> Result<String, ErrorKind>,
    stats: bool,
) -> Sample {
    let root = Path::new("/sys/fs/cgroup");
    let own_path = root.join(relative);
    let mut path = own_path.clone();
    let mut ancestor_path = None;
    let mut available = host;
    let mut observed = Sample {
        host: Some(host),
        ..Sample::default()
    };
    loop {
        match read(&path.join("memory.max")) {
            Ok(limit) => {
                let current = if limit.trim() == "max" {
                    None
                } else {
                    match read(&path.join("memory.current")) {
                        Ok(raw) => Some(raw),
                        Err(error) => return observed.failed("current", error),
                    }
                };
                let Some(next) = super::capped_memory(available, &limit, current.as_deref()) else {
                    let stage = if super::unsigned(limit.trim()).is_none() {
                        "max"
                    } else {
                        "current"
                    };
                    return observed.failed(stage, ErrorKind::InvalidData);
                };
                available = next;
                if observed.record_cap(&limit, current.as_deref(), path == own_path) {
                    ancestor_path = Some(path.clone());
                }
            }
            Err(ErrorKind::NotFound) => {
                let control = if path == root {
                    path.join("cgroup.controllers")
                } else {
                    let Some(parent) = path.parent().filter(|parent| parent.starts_with(root))
                    else {
                        return observed.failed("cgroup_path", ErrorKind::InvalidData);
                    };
                    parent.join("cgroup.subtree_control")
                };
                let controllers = match read(&control) {
                    Ok(raw) => raw,
                    Err(error) => return observed.failed("controller", error),
                };
                let memory = controllers.split_whitespace().any(|name| name == "memory");
                if memory != (path == root) {
                    return observed.failed("controller", ErrorKind::InvalidData);
                }
            }
            Err(error) => return observed.failed("max", error),
        }
        if path == root {
            observed.headroom = Some(available);
            if stats {
                observed.own_stat = Stat::observe(&own_path, read);
                if let Some(ancestor) = ancestor_path {
                    observed.ancestor_stat = Stat::observe(&ancestor, read);
                }
            }
            return observed;
        }
        if !path.pop() || !path.starts_with(root) {
            return observed.failed("cgroup_path", ErrorKind::InvalidData);
        }
    }
}

#[cfg(test)]
mod tests;
