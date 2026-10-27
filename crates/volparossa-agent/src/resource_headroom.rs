//! Read-only, bounded kernel resource observations shared by admission budgets.
//!
//! This captures available resources and pressure, not admission policy or reservations.
//! Callers retain their own sampling cache and resource-unit accounting.

use std::{
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};

const MAX_SYSTEM_FILE_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct ResourceHeadroom {
    pub(crate) memory_bytes: u64,
    pub(crate) available_fds: u64,
    pub(crate) pressured: bool,
}

/// Closed observations, not raw PSI text, device/process identities or policy overrides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum PressureState {
    BelowThreshold,
    AtOrAboveThreshold,
    /// Missing, unreadable and malformed PSI all retain the existing pressured policy.
    #[default]
    Unavailable,
}

impl PressureState {
    fn from_average(value: Option<f64>, threshold: f64) -> Self {
        match value {
            Some(value) if value >= threshold => Self::AtOrAboveThreshold,
            Some(_) => Self::BelowThreshold,
            None => Self::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PressureObservation {
    pub(crate) cpu: PressureState,
    pub(crate) memory: PressureState,
    pub(crate) io: PressureState,
}

impl PressureObservation {
    fn sample(mut observe: impl FnMut(&str) -> Option<f64>) -> Self {
        // Observe each bounded source once, even when an earlier one is pressured,
        // so diagnostics and the admission decision describe the same sample.
        Self {
            cpu: PressureState::from_average(observe("cpu"), 20.0),
            memory: PressureState::from_average(observe("memory"), 1.0),
            io: PressureState::from_average(observe("io"), 10.0),
        }
    }

    pub(crate) fn pressured(self) -> bool {
        [self.cpu, self.memory, self.io]
            .into_iter()
            .any(|state| state != PressureState::BelowThreshold)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ObservedHeadroom {
    pub(crate) headroom: ResourceHeadroom,
    pub(crate) pressure: PressureObservation,
}

pub(crate) fn capture() -> Option<ResourceHeadroom> {
    capture_with_pressure().map(|observation| observation.headroom)
}

pub(crate) fn capture_with_pressure() -> Option<ObservedHeadroom> {
    let memory = available_memory(&system_text(Path::new("/proc/meminfo"))?)?;
    let memory = cgroup_headroom(memory)?;
    let limit = descriptor_limit(&system_text(Path::new("/proc/self/limits"))?)?;
    let open = fs::read_dir("/proc/self/fd")
        .ok()?
        .try_fold(0_u64, |count, entry| {
            entry.ok()?;
            count.checked_add(1)
        })?;
    let pressure = PressureObservation::sample(pressure);
    Some(ObservedHeadroom {
        headroom: ResourceHeadroom {
            memory_bytes: memory,
            available_fds: limit.saturating_sub(open),
            pressured: pressure.pressured(),
        },
        pressure,
    })
}

fn system_text(path: &Path) -> Option<String> {
    let mut text = String::new();
    File::open(path)
        .ok()?
        .take(MAX_SYSTEM_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() as u64 <= MAX_SYSTEM_FILE_BYTES).then_some(text)
}

fn available_memory(text: &str) -> Option<u64> {
    let mut fields = text
        .lines()
        .find(|line| line.starts_with("MemAvailable:"))?
        .split_whitespace();
    (fields.next()? == "MemAvailable:").then_some(())?;
    let kibibytes = fields.next()?.parse::<u64>().ok()?;
    (fields.next()? == "kB" && fields.next().is_none()).then_some(())?;
    kibibytes.checked_mul(1024)
}

fn descriptor_limit(text: &str) -> Option<u64> {
    let line = text
        .lines()
        .find(|line| line.starts_with("Max open files"))?;
    let value = line.split_whitespace().nth(3)?;
    if value == "unlimited" {
        Some(u64::MAX)
    } else {
        value.parse().ok()
    }
}

fn pressure(kind: &str) -> Option<f64> {
    let path = PathBuf::from("/proc/pressure").join(kind);
    pressure_average(&system_text(&path)?)
}

fn pressure_average(text: &str) -> Option<f64> {
    let line = text.lines().find(|line| line.starts_with("some "))?;
    let value = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("avg10="))?
        .parse::<f64>()
        .ok()?;
    (value.is_finite() && (0.0..=100.0).contains(&value)).then_some(value)
}

fn cgroup_headroom(mut memory: u64) -> Option<u64> {
    let text = system_text(Path::new("/proc/self/cgroup"))?;
    let Some(group) = text.lines().find_map(|line| line.strip_prefix("0::")) else {
        // Older non-unified systems still have the independently read host headroom.
        return Some(memory);
    };
    let relative = Path::new(group.strip_prefix('/')?);
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }
    let root = Path::new("/sys/fs/cgroup");
    let mut path = root.join(relative);
    loop {
        // A limit on a parent slice applies even when the service's own limit is "max".
        if let Some(limit) = system_text(&path.join("memory.max"))
            && limit.trim() != "max" {
                let limit = limit.trim().parse::<u64>().ok()?;
                let used = system_text(&path.join("memory.current"))?
                    .trim()
                    .parse::<u64>()
                    .ok()?;
                memory = memory.min(limit.saturating_sub(used));
            }
        if path == root {
            break;
        }
        if !path.pop() || !path.starts_with(root) {
            return None;
        }
    }
    Some(memory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_headroom_reads_bounded_kernel_units_without_treating_missing_data_as_idle() {
        assert_eq!(
            available_memory("MemFree: 12 kB\nMemAvailable: 2048 kB\n"),
            Some(2 * 1024 * 1024)
        );
        assert_eq!(available_memory("MemAvailable: 2048 MB\n"), None);
        assert_eq!(available_memory("MemFree: 2048 kB\n"), None);
        assert_eq!(
            descriptor_limit("Max open files            1024           4096            files\n"),
            Some(1024)
        );
        assert_eq!(
            descriptor_limit("Max open files            unlimited      unlimited       files\n"),
            Some(u64::MAX)
        );
        assert_eq!(
            pressure_average("some avg10=1.25 avg60=0.50 total=200\n"),
            Some(1.25)
        );
        assert_eq!(pressure_average("some avg10=NaN\n"), None);
        assert_eq!(pressure_average("full avg10=0.00\n"), None);
    }

    #[test]
    fn pressure_observations_preserve_thresholds_and_all_causes_from_one_sample() {
        use PressureState::{AtOrAboveThreshold as High, BelowThreshold as Low, Unavailable};

        let mut sampled = Vec::new();
        let pressure = PressureObservation::sample(|kind| {
            sampled.push(kind.to_owned());
            Some(match kind {
                "cpu" => 20.0,
                "memory" => 1.0,
                "io" => 10.0,
                _ => panic!("only the three fixed PSI sources may be sampled"),
            })
        });
        assert_eq!(sampled, ["cpu", "memory", "io"]);
        assert_eq!(
            pressure,
            PressureObservation {
                cpu: High,
                memory: High,
                io: High
            }
        );
        assert!(pressure.pressured());

        for cpu in [Some(0.0), Some(19.999), Some(20.0), Some(100.0), None] {
            for memory in [Some(0.0), Some(0.999), Some(1.0), Some(100.0), None] {
                for io in [Some(0.0), Some(9.999), Some(10.0), Some(100.0), None] {
                    let pressure = PressureObservation::sample(|kind| match kind {
                        "cpu" => cpu,
                        "memory" => memory,
                        "io" => io,
                        _ => unreachable!(),
                    });
                    let expected = cpu.is_none_or(|value| value >= 20.0)
                        || memory.is_none_or(|value| value >= 1.0)
                        || io.is_none_or(|value| value >= 10.0);
                    assert_eq!(pressure.pressured(), expected);
                    for (value, threshold, state) in [
                        (cpu, 20.0, pressure.cpu),
                        (memory, 1.0, pressure.memory),
                        (io, 10.0, pressure.io),
                    ] {
                        assert_eq!(
                            state,
                            match value {
                                None => Unavailable,
                                Some(value) if value >= threshold => High,
                                Some(_) => Low,
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn missing_or_invalid_psi_is_unavailable_not_an_idle_sample() {
        use PressureState::{AtOrAboveThreshold as High, BelowThreshold as Low, Unavailable};

        assert_eq!(
            PressureObservation::default(),
            PressureObservation {
                cpu: Unavailable,
                memory: Unavailable,
                io: Unavailable,
            }
        );
        assert!(PressureObservation::default().pressured());
        for invalid in [
            "",
            "full avg10=0.00\n",
            "some avg60=0.00\n",
            "some avg10=NaN\n",
            "some avg10=inf\n",
            "some avg10=-0.01\n",
            "some avg10=100.01\n",
            "some avg10=invalid\n",
        ] {
            let pressure = PressureObservation::sample(|kind| {
                pressure_average(match kind {
                    "cpu" => invalid,
                    "memory" => "some avg10=0.00\n",
                    "io" => "some avg10=10.00\n",
                    _ => unreachable!(),
                })
            });
            assert_eq!(
                pressure,
                PressureObservation {
                    cpu: Unavailable,
                    memory: Low,
                    io: High
                }
            );
            assert!(pressure.pressured());
        }
        let idle = PressureObservation::sample(|_| pressure_average("some avg10=0.00\n"));
        assert_eq!(
            idle,
            PressureObservation {
                cpu: Low,
                memory: Low,
                io: Low
            }
        );
        assert!(!idle.pressured());
    }
}
