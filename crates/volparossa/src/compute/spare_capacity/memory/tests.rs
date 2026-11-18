//! Injected kernel text only: no host pressure, cgroup writes or model execution.

use std::{cell::RefCell, collections::BTreeMap, path::PathBuf};

use super::*;

type Files = BTreeMap<PathBuf, Result<String, ErrorKind>>;

const ROOT: &str = "/sys/fs/cgroup";
const GROUP: &str = "PRIVATE_CGROUP_CANARY/child";
const STAT: &str = "anon 40\nfile 50\nshmem 3\ninactive_file 20\nactive_file 30\nkernel 10\n";

fn files() -> Files {
    BTreeMap::from([
        (
            PathBuf::from("/proc/meminfo"),
            Ok("MemAvailable: 1 kB\n".into()),
        ),
        (
            PathBuf::from("/proc/self/cgroup"),
            Ok(format!("0::/{GROUP}\n")),
        ),
        (
            Path::new(ROOT).join(GROUP).join("memory.max"),
            Ok("900".into()),
        ),
        (
            Path::new(ROOT).join(GROUP).join("memory.current"),
            Ok("100".into()),
        ),
        (
            Path::new(ROOT).join("PRIVATE_CGROUP_CANARY/memory.max"),
            Ok("700".into()),
        ),
        (
            Path::new(ROOT).join("PRIVATE_CGROUP_CANARY/memory.current"),
            Ok("200".into()),
        ),
        (
            Path::new(ROOT).join("cgroup.controllers"),
            Ok("cpu memory io".into()),
        ),
    ])
}

fn read(files: &Files, path: &Path) -> Result<String, ErrorKind> {
    files.get(path).cloned().unwrap_or(Err(ErrorKind::NotFound))
}

// Frozen decision algorithm from 3630ff79, independent of the new observer.
fn original(files: &Files, calls: &RefCell<Vec<PathBuf>>) -> Option<u64> {
    let read = |path: &Path| {
        calls.borrow_mut().push(path.to_owned());
        read(files, path)
    };
    let mut available = super::super::available_memory(&read(Path::new("/proc/meminfo")).ok()?)?;
    let relative = super::super::unified_path(&read(Path::new("/proc/self/cgroup")).ok()?)?;
    let root = Path::new(ROOT);
    let mut path = root.join(relative);
    loop {
        match read(&path.join("memory.max")) {
            Ok(limit) => {
                let current = if limit.trim() == "max" {
                    None
                } else {
                    Some(read(&path.join("memory.current")).ok()?)
                };
                available = super::super::capped_memory(available, &limit, current.as_deref())?;
            }
            Err(ErrorKind::NotFound) if path == root => {
                let controllers = read(&path.join("cgroup.controllers")).ok()?;
                if !controllers.split_whitespace().any(|name| name == "memory") {
                    return None;
                }
            }
            Err(ErrorKind::NotFound) => {
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

fn differential(files: &Files) {
    let original_calls = RefCell::new(Vec::new());
    let expected = original(files, &original_calls);
    for stats in [false, true] {
        let calls = RefCell::new(Vec::new());
        let observed = sample_with(stats, &|path| {
            calls.borrow_mut().push(path.to_owned());
            read(files, path)
        });
        assert_eq!(observed.headroom, expected);
        let calls = calls.into_inner();
        if stats && expected.is_some() {
            assert!(calls.starts_with(&original_calls.borrow()));
            assert!(
                calls[original_calls.borrow().len()..]
                    .iter()
                    .all(|path| path.file_name().unwrap() == "memory.stat")
            );
        } else {
            assert_eq!(calls, *original_calls.borrow());
        }
    }
}

#[test]
fn admission_sampler_preserves_original_decisions_and_read_order() {
    let variants = [
        Ok("max".into()),
        Ok("0".into()),
        Ok("100".into()),
        Ok(u64::MAX.to_string()),
        Ok("+1".into()),
        Ok("PRIVATE_VALUE_CANARY".into()),
        Err(ErrorKind::NotFound),
        Err(ErrorKind::PermissionDenied),
    ];
    for own in &variants {
        for used in &variants {
            for parent in &variants {
                let mut files = files();
                files.insert(Path::new(ROOT).join(GROUP).join("memory.max"), own.clone());
                files.insert(
                    Path::new(ROOT).join(GROUP).join("memory.current"),
                    used.clone(),
                );
                files.insert(
                    Path::new(ROOT).join("PRIVATE_CGROUP_CANARY/memory.max"),
                    parent.clone(),
                );
                differential(&files);
            }
        }
    }
}

#[test]
fn admission_sampler_keeps_original_text_and_controller_rejections() {
    for (path, variants) in [
        (
            "/proc/meminfo",
            vec![
                "",
                "MemAvailable: +1 kB",
                "MemAvailable: 1 MB",
                "MemAvailable: 1 kB extra",
                "MemAvailable: 1 kB\nMemAvailable: 2 kB",
                "MemAvailable: 18446744073709551615 kB",
            ],
        ),
        (
            "/proc/self/cgroup",
            vec![
                "",
                "0::relative",
                "0::/a/../b",
                "0::/a/./b",
                "0::/a//b",
                "0::/a\n0::/b",
                "1:memory:/scope",
                "0::/",
            ],
        ),
        (
            "/sys/fs/cgroup/cgroup.controllers",
            vec!["", "cpu", "memory", "cpu memory io"],
        ),
    ] {
        for raw in variants {
            let mut files = files();
            files.insert(PathBuf::from(path), Ok(raw.into()));
            differential(&files);
        }
    }
    for controller in ["", "cpu io", "memory", "cpu memory io"] {
        let mut files = files();
        files.remove(&Path::new(ROOT).join(GROUP).join("memory.max"));
        files.insert(
            Path::new(ROOT).join("PRIVATE_CGROUP_CANARY/cgroup.subtree_control"),
            Ok(controller.into()),
        );
        differential(&files);
    }
    let mut deep = files();
    deep.insert(
        PathBuf::from("/proc/self/cgroup"),
        Ok(format!("0::/{}", vec!["a"; 65].join("/"))),
    );
    differential(&deep);
    let files = files();
    for path in files.keys().cloned().collect::<Vec<_>>() {
        for error in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidData,
            ErrorKind::Other,
        ] {
            let mut changed = files.clone();
            changed.insert(path.clone(), Err(error));
            differential(&changed);
        }
    }
}

#[test]
fn closed_snapshot_identifies_minimum_and_ties_without_cgroup_names() {
    for (host, own, parent, scope) in [
        (100, 800, 500, "host"),
        (900, 100, 500, "self"),
        (900, 800, 100, "ancestor"),
        (100, 100, 500, "multiple"),
    ] {
        let sample = Sample {
            headroom: Some(host.min(own).min(parent)),
            host: Some(host),
            own: Some(own),
            ancestor: Some(parent),
            ..Sample::default()
        };
        assert_eq!(sample.snapshot()["limiting_scope"], scope);
    }
    let sample = sample_with(true, &|path| read(&files(), path));
    let value = sample.snapshot();
    assert_eq!(value["headroom_bytes"], 500);
    assert_eq!(value["self_current_bytes"], 100);
    assert_eq!(value["self_max_bytes"], 900);
    assert_eq!(value["ancestor_current_bytes"], 200);
    assert_eq!(value["ancestor_max_bytes"], 700);
    assert_eq!(value["limiting_scope"], "ancestor");
    assert!(!value.to_string().contains("CANARY"));
}

#[test]
fn missing_samples_preserve_only_closed_failure_stage_and_io_kind() {
    for (path, stage) in [
        ("/proc/meminfo", "meminfo"),
        ("/proc/self/cgroup", "cgroup_path"),
        (
            "/sys/fs/cgroup/PRIVATE_CGROUP_CANARY/child/memory.max",
            "max",
        ),
        (
            "/sys/fs/cgroup/PRIVATE_CGROUP_CANARY/child/memory.current",
            "current",
        ),
        ("/sys/fs/cgroup/cgroup.controllers", "controller"),
    ] {
        let mut files = files();
        files.insert(PathBuf::from(path), Err(ErrorKind::PermissionDenied));
        let sample = sample_with(true, &|path| read(&files, path));
        let value = sample.snapshot();
        assert_eq!(sample.headroom, None);
        assert_eq!(value["missing_stage"], stage);
        assert_eq!(value["io_kind"], "permission");
        assert_eq!(value["limiting_scope"], "unknown");
        assert!(value["headroom_bytes"].is_null());
        assert!(!value.to_string().contains("CANARY"));
    }
}

#[test]
fn optional_stat_reads_only_self_and_selected_ancestor_after_the_decision_sample() {
    let mut files = files();
    let own = Path::new(ROOT).join(GROUP).join("memory.stat");
    let ancestor = Path::new(ROOT).join("PRIVATE_CGROUP_CANARY/memory.stat");
    files.insert(own.clone(), Ok(format!("{STAT}PRIVATE_STAT_CANARY 999\n")));
    files.insert(ancestor.clone(), Ok(STAT.into()));
    let calls = RefCell::new(Vec::new());
    let sample = sample_with(true, &|path| {
        calls.borrow_mut().push(path.to_owned());
        read(&files, path)
    });
    let calls = calls.into_inner();
    assert_eq!(&calls[calls.len() - 2..], &[own, ancestor]);
    assert_eq!(sample.headroom, Some(500));
    assert_eq!(sample.snapshot()["self_stat"]["file_bytes"], 50);
    assert_eq!(sample.snapshot()["ancestor_stat"]["anon_bytes"], 40);
    assert!(!sample.snapshot().to_string().contains("CANARY"));
    differential(&files);
}

#[test]
fn absent_invalid_or_overflowing_stats_never_change_headroom() {
    for (raw, state) in [
        (Err(ErrorKind::PermissionDenied), "unavailable"),
        (Ok(String::new()), "invalid"),
        (Ok(format!("{STAT}anon 1\n")), "invalid"),
        (Ok(STAT.replace("anon 40", "anon +40")), "invalid"),
        (Ok(STAT.replace("file 50", "file 50 extra")), "invalid"),
        (
            Ok(STAT.replace("file 50", &format!("file {}", u64::MAX))),
            "unrepresentable",
        ),
    ] {
        let mut files = files();
        files.insert(Path::new(ROOT).join(GROUP).join("memory.stat"), raw);
        let sample = sample_with(true, &|path| read(&files, path));
        assert_eq!(sample.headroom, Some(500));
        let snapshot = sample.snapshot();
        let stat = &snapshot["self_stat"];
        assert_eq!(stat["state"], state);
        assert!(
            stat.as_object()
                .unwrap()
                .iter()
                .all(|(key, value)| key == "state" || value.is_null())
        );
        assert_eq!(snapshot["numeric_overflow"], state == "unrepresentable");
    }
}

#[test]
fn json_bound_does_not_change_internal_u64_admission_value() {
    for value in [JSON_MAX, JSON_MAX + 1, u64::MAX] {
        let sample = Sample::for_test(Some(value));
        let snapshot = sample.snapshot();
        assert_eq!(sample.headroom, Some(value));
        assert_eq!(snapshot["numeric_overflow"], value > JSON_MAX);
        assert_eq!(snapshot["headroom_bytes"].is_null(), value > JSON_MAX);
        assert_eq!(snapshot["missing_stage"], "none");
        assert!(crate::compute::resources::admits(
            crate::compute::ModelProfile::Qwen4bInstruct2507,
            sample.headroom
        ));
    }
}
