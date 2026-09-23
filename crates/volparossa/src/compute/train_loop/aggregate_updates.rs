//! Owner-enrolled automatic aggregation. Combining peers is not a local training cycle.
//! Original cohorts are processed once; only a real comparison can replace the active adapter.

use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::sync::watch;

use super::{
    CurrentAdapter, Options, State, Store, active as running, aggregate, now, private_directory,
    read_file,
    storage::{FileSnapshot, Snapshot},
};

const RETAINED: usize = 8;
const MAX_TREE_BYTES: u64 = 48 * 1024 * 1024;
const MAX_ENTRIES: usize = 256;

#[cfg(test)]
#[path = "aggregate_updates/tests.rs"]
mod lifecycle_tests;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Cohort {
    manifest_ids: [String; 3],
    revisions: [u64; 3],
}

impl Cohort {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.manifest_ids
                .iter()
                .all(|id| super::super::is_hex(id, 64))
                && self.revisions.iter().all(|revision| *revision > 0),
            "aggregate_updates_cohort"
        );
        Ok(())
    }

    fn advances(&self, previous: Option<&Self>) -> Result<bool> {
        self.validate()?;
        let Some(previous) = previous else {
            return Ok(true);
        };
        previous.validate()?;
        for index in 0..3 {
            ensure!(
                self.revisions[index] >= previous.revisions[index]
                    && (self.revisions[index] != previous.revisions[index]
                        || self.manifest_ids[index] == previous.manifest_ids[index]),
                "aggregate_updates_revision_rollback_or_fork"
            );
        }
        Ok(self != previous)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Running,
    Approved,
    Rejected,
    Failed,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Round {
    sequence: u64,
    cohort: Cohort,
    phase: Phase,
    observed_at: u64,
    expires: u64,
    local_predecessor: Option<u64>,
    baseline_origin: Value,
    baseline_files: Option<Value>,
    baseline_expires: Option<u64>,
    approval: Option<Value>,
    snapshot: Option<Snapshot>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Registry {
    version: u32,
    selection: Value,
    next_sequence: u64,
    next_poll: u64,
    verified_cohort_polls: u64,
    seen: Option<Cohort>,
    active: Option<u64>,
    rounds: Vec<Round>,
    garbage: Vec<u64>,
}

pub(super) fn active_sequence(registry: &Registry) -> Option<u64> {
    registry.active
}
pub(super) fn clear_active(registry: &mut Registry) {
    registry.active = None;
}

fn root(args: &Options, sequence: u64) -> Result<PathBuf> {
    ensure!(sequence > 0, "aggregate_updates_sequence");
    private_directory(&args.directory)?;
    Ok(args
        .directory
        .join(format!("aggregate-update-{sequence:016x}")))
}

fn checkpoint(registry: &Registry, store: &Store, state: &mut State) -> Result<()> {
    state.aggregate_updates = Some(registry.clone());
    store.save_state(&serde_json::to_value(&*state)?)
}

fn validate(registry: &Registry, selection: &Value) -> Result<()> {
    ensure!(
        registry.version == 1
            && &registry.selection == selection
            && registry.next_sequence > 0
            && registry.rounds.len() <= RETAINED
            && registry.garbage.len() <= 1,
        "aggregate_updates_state"
    );
    if let Some(cohort) = &registry.seen {
        cohort.validate()?;
    }
    let mut sequences = BTreeSet::new();
    let mut pending = 0;
    for round in &registry.rounds {
        round.cohort.validate()?;
        ensure!(
            round.sequence > 0
                && round.sequence < registry.next_sequence
                && sequences.insert(round.sequence)
                && round.expires > round.observed_at
                && (round.phase == Phase::Running || round.snapshot.is_some())
                && (round.phase != Phase::Approved || round.approval.is_some()),
            "aggregate_updates_round"
        );
        if round.phase == Phase::Running {
            pending += 1;
            ensure!(
                Some(&round.cohort) == registry.seen.as_ref()
                    && round.sequence.checked_add(1) == Some(registry.next_sequence),
                "aggregate_updates_pending_cohort"
            );
        }
    }
    ensure!(pending <= 1, "aggregate_updates_pending_count");
    for sequence in &registry.garbage {
        ensure!(
            *sequence > 0
                && *sequence < registry.next_sequence
                && sequences.insert(*sequence)
                && Some(*sequence) != registry.active,
            "aggregate_updates_garbage"
        );
    }
    if let Some(sequence) = registry.active {
        ensure!(
            registry
                .rounds
                .iter()
                .any(|r| r.sequence == sequence && r.phase == Phase::Approved),
            "aggregate_updates_active_round"
        );
    }
    Ok(())
}

pub(super) fn restore(
    args: &Options,
    store: &Store,
    state: &mut State,
    enrollment: &Value,
) -> Result<()> {
    let Some(selection) = enrollment.get("aggregate_updates") else {
        ensure!(
            args.aggregate_plan.is_none() && state.aggregate_updates.is_none(),
            "aggregate_updates_unrequested_state"
        );
        return Ok(());
    };
    ensure!(
        state.peer_updates.is_none(),
        "aggregate_updates_conflicting_adoption_modes"
    );
    let mut registry = if let Some(registry) = &state.aggregate_updates {
        registry.clone()
    } else {
        ensure!(!args.resume, "aggregate_updates_missing_state");
        Registry {
            version: 1,
            selection: selection.clone(),
            next_sequence: 1,
            next_poll: 0,
            verified_cohort_polls: 0,
            seen: None,
            active: None,
            rounds: Vec::new(),
            garbage: Vec::new(),
        }
    };
    validate(&registry, selection)?;
    for sequence in &registry.garbage {
        prune(&root(args, *sequence)?)?;
    }
    registry.garbage.clear();
    for round in &registry.rounds {
        if let Some(expected) = &round.snapshot {
            ensure!(
                &snapshot(&root(args, round.sequence)?)? == expected,
                "aggregate_updates_retained_bytes_changed"
            );
        }
    }
    if let Some(index) = registry
        .rounds
        .iter()
        .position(|round| round.phase == Phase::Running)
    {
        // A complete immutable result can be reopened. An interrupted worker is not rerun,
        // nor are its original inputs or elapsed authority silently refreshed.
        finish(args, &mut registry, index, state.latest)?;
    }
    checkpoint(&registry, store, state)?;
    reconcile(args, store, state)
}

pub(super) fn reconcile(args: &Options, store: &Store, state: &mut State) -> Result<()> {
    let Some(registry) = &state.aggregate_updates else {
        return Ok(());
    };
    let Some(sequence) = registry.active else {
        return Ok(());
    };
    let round = registry
        .rounds
        .iter()
        .find(|round| round.sequence == sequence)
        .context("aggregate_updates_active_missing")?;
    if now()? >= round.expires || round.local_predecessor != state.latest {
        let mut registry = registry.clone();
        registry.active = None;
        checkpoint(&registry, store, state)?;
        eprintln!("compute loop_event=aggregate_selection_expired_or_superseded");
        return Ok(());
    }
    // Local corruption is an execution failure, not an allegation against publishers.
    let _ = active(args, registry, state.latest)?;
    Ok(())
}

pub(super) fn active(
    args: &Options,
    registry: &Registry,
    local: Option<u64>,
) -> Result<Option<CurrentAdapter>> {
    let Some(sequence) = registry.active else {
        return Ok(None);
    };
    let round = registry
        .rounds
        .iter()
        .find(|round| round.sequence == sequence)
        .context("aggregate_updates_active_missing")?;
    if round.local_predecessor != local || now()? >= round.expires {
        return Ok(None);
    }
    let directory = root(args, sequence)?;
    ensure!(
        round.phase == Phase::Approved && round.snapshot.as_ref() == Some(&snapshot(&directory)?),
        "aggregate_updates_active_bytes"
    );
    let approved = aggregate::reopen_approved(&directory, &args.limits, now()?)?;
    ensure!(
        round.approval.as_ref() == Some(&approved.identity) && approved.expires == round.expires,
        "aggregate_updates_original_approval"
    );
    let origin = json!({"kind":"aggregate_update","aggregate_sequence":sequence,
        "local_predecessor":round.local_predecessor,"manifest_ids":round.cohort.manifest_ids,
        "dataset_manifest_id":approved.identity["dataset_manifest_id"],
        "cohort_sha256":approved.identity["cohort_sha256"],
        "comparison_sha256":approved.identity["comparison_sha256"],
        "result_sha256":approved.identity["result_sha256"],
        "adapter_files":approved.identity["adapter_files"],"expires_unix_seconds":round.expires});
    Ok(Some(CurrentAdapter {
        adapter_root: Some(directory.join("candidate/import/adapter")),
        authority_expires: Some(round.expires),
        origin,
    }))
}

pub(super) fn serving_candidate(
    args: &Options,
    registry: &Registry,
    local: Option<u64>,
) -> Result<Option<(PathBuf, u64, Value)>> {
    active(args, registry, local)?.map(|current| {
        let expires = current.authority_expires.context("aggregate_updates_serving_expiry")?;
        let proof = json!({"kind":"approved_aggregate","approved":true,
            "adapter_files":current.origin["adapter_files"],"expires_unix_seconds":expires,
            "origin":current.origin,"general_quality_proven":false,"network_authority_claimed":false});
        Ok((current.adapter_root.context("aggregate_updates_serving_adapter")?, expires, proof))
    }).transpose()
}

pub(super) async fn tick(
    args: &Options,
    socket: &Path,
    store: &Store,
    state: &mut State,
    activity: &watch::Receiver<bool>,
) -> Result<()> {
    let Some(mut registry) = state.aggregate_updates.clone() else {
        return Ok(());
    };
    if !running(activity) || now()? < registry.next_poll {
        return Ok(());
    }
    registry.next_poll = now()?.saturating_add(u64::from(args.poll_seconds));
    checkpoint(&registry, store, state)?;
    let staging = tempfile::Builder::new()
        .prefix(".aggregate-discovery-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&args.directory)?;
    let fetched =
        aggregate::discover_loop(args, &registry.selection, socket, staging.path(), activity).await;
    let Ok(cohort) = fetched else {
        eprintln!("compute loop_event=aggregate_sources_unavailable");
        return Ok(());
    };
    let stamp = Cohort {
        manifest_ids: cohort.manifest_ids.clone(),
        revisions: cohort.revisions,
    };
    let Ok(advances) = stamp.advances(registry.seen.as_ref()) else {
        eprintln!("compute loop_event=aggregate_source_rollback_or_fork_rejected");
        return Ok(());
    };
    // Scheduling the next attempt is not proof that the original sources were observed.
    // This checkpoint records only a completed, authenticated and monotone cohort poll.
    registry.verified_cohort_polls = registry
        .verified_cohort_polls
        .checked_add(1)
        .context("aggregate_updates_poll_count_exhausted")?;
    checkpoint(&registry, store, state)?;
    if !advances {
        return Ok(());
    }
    if !make_room(args, store, state, &mut registry)? {
        return Ok(());
    }
    let current = super::current_adapter(args, store, state)?;
    let baseline_files = current
        .adapter_root
        .as_ref()
        .map(|path| {
            super::peer_evaluation::adapter_files(path)
                .and_then(|files| Ok(serde_json::to_value(files)?))
        })
        .transpose()?;
    let time = now()?;
    let expires = current
        .authority_expires
        .map_or(cohort.expires, |until| cohort.expires.min(until));
    if !running(activity) || expires <= time {
        return Ok(());
    }
    let sequence = registry.next_sequence;
    registry.next_sequence = sequence
        .checked_add(1)
        .context("aggregate_updates_sequence_exhausted")?;
    registry.seen = Some(stamp.clone());
    registry.rounds.push(Round {
        sequence,
        cohort: stamp,
        phase: Phase::Running,
        observed_at: time,
        expires,
        local_predecessor: state.latest,
        baseline_origin: current.origin,
        baseline_files,
        baseline_expires: current.authority_expires,
        approval: None,
        snapshot: None,
    });
    checkpoint(&registry, store, state)?;
    // Do not drop a running worker future. Its existing supervisor must reap on cancellation.
    let result = Box::pin(aggregate::execute_loop(
        args,
        &registry.selection,
        &root(args, sequence)?,
        current.adapter_root.as_deref(),
        current.authority_expires,
        cohort,
        socket,
        activity,
    ))
    .await;
    if result.is_err() {
        eprintln!("compute loop_event=aggregate_execution_failed");
    }
    let index = registry.rounds.len() - 1;
    finish(args, &mut registry, index, state.latest)?;
    checkpoint(&registry, store, state)?;
    println!(
        "{}",
        json!({"operation":"compute_train_loop_aggregate","sequence":sequence,
        "approved":registry.rounds[index].phase == Phase::Approved,"active_sequence":registry.active,
        "optimizer_steps":0,"general_quality_proven":false,"network_publication":false})
    );
    Ok(())
}

fn finish(args: &Options, registry: &mut Registry, index: usize, local: Option<u64>) -> Result<()> {
    let round = &mut registry.rounds[index];
    let directory = root(args, round.sequence)?;
    let result_path = directory.join("result.json");
    round.phase = Phase::Failed;
    if result_path.try_exists()? {
        let result: Value = serde_json::from_slice(&read_file(&result_path, 512 * 1024)?)?;
        ensure!(
            result["operation"] == "compute_aggregate_adapters" && result["optimizer_steps"] == 0,
            "aggregate_updates_result_kind"
        );
        let effective = result["cohort"]["expires_unix_seconds"]
            .as_u64()
            .context("aggregate_updates_result_expiry")?;
        ensure!(
            round.observed_at < effective && effective <= round.expires,
            "aggregate_updates_result_renewed_authority"
        );
        round.expires = effective;
        if result["approved"] == true && now()? < round.expires {
            let approved = aggregate::reopen_approved(&directory, &args.limits, now()?)?;
            let selection: Value =
                serde_json::from_slice(&read_file(&directory.join("selection.json"), 64 * 1024)?)?;
            ensure!(
                selection["plan"] == registry.selection["plan"]
                    && selection["validation_source"] == registry.selection["validation_source"]
                    && result["cohort"]["baseline"]["adapter_files"]
                        == serde_json::to_value(&round.baseline_files)?
                    && selection
                        .get("baseline_expires_unix_seconds")
                        .and_then(Value::as_u64)
                        == round.baseline_expires
                    && approved.expires <= round.expires
                    && round.local_predecessor == local,
                "aggregate_updates_frozen_selection"
            );
            for index in 0..3 {
                let signed = read_file(
                    &directory.join(format!("peers/{index}/import/adapter.manifest")),
                    64 * 1024,
                )?;
                ensure!(
                    hex::encode(Sha256::digest(signed)) == round.cohort.manifest_ids[index],
                    "aggregate_updates_frozen_cohort"
                );
            }
            round.expires = approved.expires;
            round.approval = Some(approved.identity);
            round.phase = Phase::Approved;
            registry.active = Some(round.sequence);
        } else if now()? >= round.expires {
            round.phase = Phase::Expired;
        } else {
            ensure!(
                result["approved"] == false,
                "aggregate_updates_approval_flag"
            );
            round.phase = Phase::Rejected;
        }
    }
    round.snapshot = Some(snapshot(&directory)?);
    Ok(())
}

fn make_room(
    args: &Options,
    store: &Store,
    state: &mut State,
    registry: &mut Registry,
) -> Result<bool> {
    if registry.rounds.len() < RETAINED {
        return Ok(true);
    }
    let Some(index) = registry
        .rounds
        .iter()
        .position(|round| Some(round.sequence) != registry.active && round.phase != Phase::Running)
    else {
        return Ok(false);
    };
    let obsolete = registry.rounds.remove(index);
    registry.garbage.push(obsolete.sequence);
    checkpoint(registry, store, state)?;
    prune(&root(args, obsolete.sequence)?)?;
    registry.garbage.clear();
    checkpoint(registry, store, state)?;
    Ok(true)
}

fn tree(root: &Path) -> Result<Vec<(PathBuf, bool)>> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        other => {
            other?;
        }
    }
    private_directory(root)?;
    let mut todo = vec![(PathBuf::new(), 0)];
    let mut entries = Vec::new();
    let mut bytes = 0_u64;
    while let Some((relative, depth)) = todo.pop() {
        ensure!(depth <= 5, "aggregate_updates_tree_depth");
        for entry in fs::read_dir(root.join(&relative))? {
            let entry = entry?;
            let path = relative.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(
                entries.len() < MAX_ENTRIES
                    && metadata.uid() == nix::unistd::geteuid().as_raw()
                    && allowed(&path, metadata.is_dir())
                    && (metadata.is_dir() || (metadata.is_file() && metadata.nlink() == 1)),
                "aggregate_updates_tree_owner_type"
            );
            if metadata.is_dir() {
                private_directory(&entry.path())?;
                todo.push((path.clone(), depth + 1));
            } else {
                ensure!(
                    metadata.len() <= 4 * 1024 * 1024,
                    "aggregate_updates_file_bound"
                );
                bytes = bytes
                    .checked_add(metadata.len())
                    .context("aggregate_updates_tree_bound")?;
                ensure!(bytes <= MAX_TREE_BYTES, "aggregate_updates_tree_bound");
            }
            entries.push((path, metadata.is_dir()));
        }
    }
    Ok(entries)
}

#[allow(
    clippy::too_many_lines,
    reason = "One exact owned-output allowlist shared by snapshot and pruning"
)]
fn allowed(path: &Path, directory: bool) -> bool {
    let Some(name) = path.to_str() else {
        return false;
    };
    let adapter_file = |name: &str| {
        matches!(
            name,
            "README.md" | "adapter_config.json" | "adapter_model.safetensors"
        )
    };
    if directory {
        return matches!(
            name,
            "baseline"
                | "validation-input"
                | "cohort"
                | "peers"
                | "candidate"
                | "candidate/import"
                | "candidate/import/adapter"
                | "candidate/comparison"
                | "candidate/comparison/baseline"
                | "candidate/comparison/candidate"
                | "job"
                | "job/adapter"
        ) || (0..3).any(|index| {
            name == format!("cohort/{index}")
                || name == format!("peers/{index}")
                || ["pending", "import", "import/adapter"]
                    .iter()
                    .any(|suffix| name == format!("peers/{index}/{suffix}"))
        });
    }
    if matches!(
        name,
        "selection.json"
            | "validation-source.json"
            | "dataset.json"
            | "cohort.json"
            | "aggregate-report.json"
            | "adapter.bundle"
            | "result.json"
            | "job/report.json"
            | "candidate/import/dataset.json"
            | "candidate/import/provenance.json"
    ) {
        return true;
    }
    for prefix in [
        "baseline/",
        "job/adapter/",
        "candidate/import/adapter/",
        "cohort/0/",
        "cohort/1/",
        "cohort/2/",
    ] {
        if name.strip_prefix(prefix).is_some_and(adapter_file) {
            return true;
        }
    }
    if name.strip_prefix("validation-input/").is_some_and(|name| {
        matches!(
            name,
            "dataset.json" | "dataset.manifest" | "provenance.json"
        )
    }) {
        return true;
    }
    if name
        .strip_prefix("candidate/comparison/")
        .is_some_and(|name| {
            matches!(
                name,
                "selection.json"
                    | "dataset.json"
                    | "dataset.manifest"
                    | "provenance.json"
                    | "baseline-report.json"
                    | "candidate-report.json"
                    | "decision.json"
                    | "quarantine.json"
                    | "baseline/report.json"
                    | "candidate/report.json"
            )
        })
    {
        return true;
    }
    (0..3).any(|index| {
        name.strip_prefix(&format!("peers/{index}/"))
            .is_some_and(|tail| {
                tail.strip_prefix("import/adapter/")
                    .is_some_and(adapter_file)
                    || tail.strip_prefix("pending/").is_some_and(|file| {
                        matches!(
                            file,
                            "adapter.bundle" | "adapter.manifest" | "provenance.json"
                        )
                    })
                    || tail.strip_prefix("import/").is_some_and(|file| {
                        matches!(
                            file,
                            "adapter.bundle"
                                | "adapter.manifest"
                                | "provenance.json"
                                | "dataset.json"
                                | "dataset.manifest"
                        )
                    })
            })
    })
}

fn snapshot(root: &Path) -> Result<Snapshot> {
    let mut result = Snapshot::new();
    for (path, directory) in tree(root)? {
        if !directory {
            let raw = read_file(&root.join(&path), 4 * 1024 * 1024)?;
            result.insert(
                path.to_str()
                    .context("aggregate_updates_file_encoding")?
                    .into(),
                FileSnapshot {
                    bytes: raw.len() as u64,
                    sha256: hex::encode(Sha256::digest(raw)),
                },
            );
        }
    }
    Ok(result)
}

fn prune(root: &Path) -> Result<()> {
    let mut entries = tree(root)?;
    entries.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, directory) in entries {
        if directory {
            fs::remove_dir(root.join(path))?;
        } else {
            fs::remove_file(root.join(path))?;
        }
    }
    if root.try_exists()? {
        fs::remove_dir(root)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cohort() -> Cohort {
        Cohort {
            manifest_ids: ["a".repeat(64), "b".repeat(64), "c".repeat(64)],
            revisions: [1, 2, 3],
        }
    }

    #[test]
    fn unchanged_cohort_does_not_repeat_and_one_new_publisher_advances() {
        let previous = cohort();
        assert!(previous.advances(None).unwrap());
        assert!(!previous.advances(Some(&previous)).unwrap());
        let mut next = previous.clone();
        next.revisions[1] += 1;
        next.manifest_ids[1] = "d".repeat(64);
        assert!(next.advances(Some(&previous)).unwrap());
        next.revisions[0] = 0;
        assert!(next.advances(Some(&previous)).is_err());
    }

    #[test]
    fn same_revision_fork_and_mixed_rollback_are_not_new_training() {
        let previous = cohort();
        let mut next = previous.clone();
        next.manifest_ids[1] = "d".repeat(64);
        assert!(next.advances(Some(&previous)).is_err());
        next.revisions = [2, 1, 3];
        assert!(next.advances(Some(&previous)).is_err());
    }

    #[test]
    fn registry_requires_original_enrollment_and_exact_pending_cohort() {
        let selection = json!({"version":1,"fixture":"inert"});
        let mut registry = Registry {
            version: 1,
            selection: selection.clone(),
            next_sequence: 2,
            next_poll: 0,
            verified_cohort_polls: 0,
            seen: Some(cohort()),
            active: None,
            garbage: Vec::new(),
            rounds: vec![Round {
                sequence: 1,
                cohort: cohort(),
                phase: Phase::Running,
                observed_at: 1,
                expires: 2,
                local_predecessor: None,
                baseline_origin: json!({"kind":"pinned_base"}),
                baseline_files: None,
                baseline_expires: None,
                approval: None,
                snapshot: None,
            }],
        };
        validate(&registry, &selection).unwrap();
        assert!(validate(&registry, &json!({"version":2})).is_err());
        registry.active = Some(1);
        assert!(validate(&registry, &selection).is_err());
        registry.active = None;
        registry.seen = None;
        assert!(validate(&registry, &selection).is_err());
    }
}
