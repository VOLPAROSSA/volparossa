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

pub(crate) fn capture() -> Option<ResourceHeadroom> {
    let memory = available_memory(&system_text(Path::new("/proc/meminfo"))?)?;
    let memory = cgroup_headroom(memory)?;
    let limit = descriptor_limit(&system_text(Path::new("/proc/self/limits"))?)?;
    let open = fs::read_dir("/proc/self/fd")
        .ok()?
        .try_fold(0_u64, |count, entry| {
            entry.ok()?;
            count.checked_add(1)
        })?;
    // Missing telemetry selects the caller's pressured policy, never a claim of an idle host.
    let pressured = pressure("cpu").is_none_or(|value| value >= 20.0)
        || pressure("memory").is_none_or(|value| value >= 1.0)
        || pressure("io").is_none_or(|value| value >= 10.0);
    Some(ResourceHeadroom {
        memory_bytes: memory,
        available_fds: limit.saturating_sub(open),
        pressured,
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
        if let Some(limit) = system_text(&path.join("memory.max")) {
            if limit.trim() != "max" {
                let limit = limit.trim().parse::<u64>().ok()?;
                let used = system_text(&path.join("memory.current"))?
                    .trim()
                    .parse::<u64>()
                    .ok()?;
                memory = memory.min(limit.saturating_sub(used));
            }
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
}
