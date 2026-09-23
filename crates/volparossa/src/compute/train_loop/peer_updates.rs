//! Owner-enrolled peer adapters, independent source resolution and local adoption.
//! A peer publication is never counted as a locally trained cycle. The fixed
//! worker, not a publisher's quality claim, decides the local comparison.

mod retirement;

pub(super) use retirement::{recover_active, recovery_blocked};

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::sync::watch;

use super::{
    Options, Plan, Source, State, Store, active as running, now, private_directory, read_file,
};
use crate::content::{
    self,
    peer_update::{self, DatasetSource, Fetch, ImportedUpdate, VerifiedUpdate},
};

const MAX_CHANNELS: usize = 16;
const RETAINED: usize = 8;
const MAX_TREE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 64;
type Snapshot = BTreeMap<String, super::storage::FileSnapshot>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Channel {
    publisher_key: String,
    name: String,
    #[serde(default)]
    min_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u32,
    channels: Vec<Channel>,
}

impl Enrollment {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && (1..=MAX_CHANNELS).contains(&self.channels.len()),
            "peer_updates_enrollment"
        );
        let mut unique = BTreeSet::new();
        for channel in &self.channels {
            let key =
                content::parse_publisher_key(&channel.publisher_key).map_err(anyhow::Error::msg)?;
            content::parse_content_name(&channel.name).map_err(anyhow::Error::msg)?;
            ensure!(
                channel.publisher_key == hex::encode(key.as_bytes())
                    && channel.min_revision != Some(0)
                    && unique.insert((key.to_bytes(), channel.name.clone())),
                "peer_updates_channel"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Feed {
    channel: Channel,
    revision: Option<u64>,
    manifest_id: Option<String>,
    processed_manifest: Option<String>,
    next_poll: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Staging,
    AwaitingSource,
    Importing,
    Evaluating,
    Approved,
    Rejected,
    Quarantined,
    Failed,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    adapter_root: Option<PathBuf>,
    origin: Value,
    local_predecessor: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Round {
    sequence: u64,
    channel: usize,
    revision: u64,
    manifest_id: String,
    dataset_manifest_id: String,
    observed_at: u64,
    expires: u64,
    next_attempt: u64,
    phase: Phase,
    source: Option<Source>,
    imported_at: Option<u64>,
    baseline: Option<Baseline>,
    snapshot: Option<Snapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retirement: Option<retirement::Record>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Registry {
    version: u32,
    next_sequence: u64,
    cursor: usize,
    feeds: Vec<Feed>,
    pending: Option<Round>,
    completed: Vec<Round>,
    active: Option<u64>,
    garbage: Vec<u64>,
}

pub(super) struct Active {
    pub(super) adapter_root: PathBuf,
    pub(super) origin: Value,
}

pub(super) fn selection(args: &Options) -> Result<Option<Value>> {
    args.peer_updates
        .as_ref()
        .map(|path| {
            ensure!(
                args.validation_source.is_some(),
                "peer_updates_validation_required"
            );
            let selected: Enrollment = serde_json::from_slice(&read_file(path, 64 * 1024)?)?;
            selected.validate()?;
            Ok(serde_json::to_value(selected)?)
        })
        .transpose()
}

pub(super) fn restore(
    args: &Options,
    store: &Store,
    state: &mut State,
    enrollment: &Value,
) -> Result<()> {
    let Some(selected) = enrollment.get("peer_updates").filter(|v| !v.is_null()) else {
        ensure!(
            state.peer_updates.is_none() && args.peer_updates.is_none(),
            "peer_updates_unrequested_state"
        );
        return Ok(());
    };
    let selected: Enrollment = serde_json::from_value(selected.clone())?;
    selected.validate()?;
    if state.peer_updates.is_none() {
        ensure!(!args.resume, "peer_updates_missing_state");
        state.peer_updates = Some(Registry {
            version: 1,
            next_sequence: 1,
            cursor: 0,
            feeds: selected
                .channels
                .iter()
                .cloned()
                .map(|channel| Feed {
                    channel,
                    revision: None,
                    manifest_id: None,
                    processed_manifest: None,
                    next_poll: 0,
                })
                .collect(),
            pending: None,
            completed: Vec::new(),
            active: None,
            garbage: Vec::new(),
        });
    }
    let mut registry = state
        .peer_updates
        .as_ref()
        .context("peer_updates_state")?
        .clone();
    registry.validate(&selected, now()?)?;
    for sequence in registry.garbage.clone() {
        prune(&round_root(args, sequence)?)?;
    }
    registry.garbage.clear();
    checkpoint(&registry, store, state)?;
    // An interruption may leave a previously accepted local extraction damaged.
    // Recover only from attributable bytes, never from a generic restore error.
    recover_active(args, store, state)?;
    registry = state
        .peer_updates
        .as_ref()
        .context("peer_updates_state")?
        .clone();
    for round in &registry.completed {
        if round.retirement.is_some() {
            retirement::verify(args, &registry, round)?;
            continue;
        }
        ensure!(
            round.snapshot.as_ref() == Some(&snapshot(&round_root(args, round.sequence)?)?),
            "peer_updates_retained_files_changed"
        );
        if matches!(round.phase, Phase::Approved | Phase::Rejected) {
            verify_round(args, &registry, round)?;
        } else if round.phase == Phase::Quarantined {
            verify_quarantine_round(args, &registry, round)?;
        }
    }
    if registry
        .pending
        .as_ref()
        .is_some_and(|round| round.phase == Phase::Staging)
    {
        // No confirmed local admission was committed before interruption.
        finish(args, &mut registry, Phase::Failed)?;
    }
    if let Some(round) = registry
        .pending
        .clone()
        .filter(|round| round.phase == Phase::Evaluating)
    {
        if round_root(args, round.sequence)?
            .join("comparison/quarantine.json")
            .try_exists()?
        {
            // The immutable observation may have reached disk just before the
            // coordinator checkpoint. Restore it without executing the artifact
            // again or renewing its original source/worker admission.
            verify_quarantine_round(args, &registry, &round)?;
            finish(args, &mut registry, Phase::Quarantined)?;
        }
    }
    if registry.active.is_some() {
        active(args, &registry, state.latest)?;
    }
    checkpoint(&registry, store, state)
}

impl Registry {
    fn validate(&self, selected: &Enrollment, time: u64) -> Result<()> {
        ensure!(
            self.version == 1
                && self.next_sequence > 0
                && self.cursor < self.feeds.len()
                && self
                    .feeds
                    .iter()
                    .map(|f| &f.channel)
                    .eq(selected.channels.iter())
                && self.completed.len() <= RETAINED
                && self.garbage.len() <= 1,
            "peer_updates_registry"
        );
        for feed in &self.feeds {
            ensure!(
                feed.revision.is_some() == feed.manifest_id.is_some()
                    && feed.revision != Some(0)
                    && feed.manifest_id.as_deref().is_none_or(hash)
                    && feed.processed_manifest.as_deref().is_none_or(hash),
                "peer_updates_channel_floor"
            );
        }
        let mut sequences = BTreeSet::new();
        for round in self.completed.iter().chain(self.pending.iter()) {
            ensure!(
                round.sequence > 0
                    && round.sequence < self.next_sequence
                    && sequences.insert(round.sequence)
                    && round.channel < self.feeds.len()
                    && round.revision > 0
                    && hash(&round.manifest_id)
                    && hash(&round.dataset_manifest_id)
                    && round.observed_at > 0
                    && round.observed_at <= time
                    && round.expires > round.observed_at,
                "peer_updates_round"
            );
            let terminal = matches!(
                round.phase,
                Phase::Approved
                    | Phase::Rejected
                    | Phase::Quarantined
                    | Phase::Failed
                    | Phase::Expired
            );
            ensure!(
                terminal == self.completed.iter().any(|r| r.sequence == round.sequence)
                    && (!terminal || round.snapshot.is_some())
                    && (round.retirement.is_none() || round.phase == Phase::Approved),
                "peer_updates_round_phase"
            );
        }
        ensure!(
            self.active
                .is_none_or(|id| self.completed.iter().any(|r| r.sequence == id
                    && r.phase == Phase::Approved
                    && r.retirement.is_none())),
            "peer_updates_active_missing"
        );
        for id in &self.garbage {
            ensure!(
                *id > 0
                    && *id < self.next_sequence
                    && !sequences.contains(id)
                    && Some(*id) != self.active,
                "peer_updates_garbage_identity"
            );
        }
        Ok(())
    }
}

pub(super) fn clear_active(registry: &mut Registry) {
    registry.active = None;
}

pub(super) fn active_sequence(registry: &Registry) -> Option<u64> {
    registry.active
}

pub(super) fn serving_candidate(
    args: &Options,
    registry: &Registry,
    local_latest: Option<u64>,
) -> Result<Option<(PathBuf, u64, Value)>> {
    let Some(accepted) = active(args, registry, local_latest)? else {
        return Ok(None);
    };
    let sequence = registry.active.context("serving_peer_active_missing")?;
    let root = round_root(args, sequence)?;
    // active() rechecks the immutable round/import and both actual comparison reports.
    // Its original selection expires at min(import publication, dataset, validation).
    let raw = read_file(&root.join("comparison/selection.json"), 512 * 1024)?;
    let selection: Value = serde_json::from_slice(&raw)?;
    let expires = selection["expires"]
        .as_u64()
        .context("serving_peer_expiry")?;
    let provenance = json!({"kind":"approved_peer_update","approved":true,
        "selection_sha256":hex::encode(Sha256::digest(raw)),"origin":accepted.origin,
        "adapter_files":accepted.origin["adapter_files"],"expires_unix_seconds":expires,
        "general_quality_proven":false,"network_authority_claimed":false});
    Ok(Some((accepted.adapter_root, expires, provenance)))
}

pub(super) fn active(
    args: &Options,
    registry: &Registry,
    local_latest: Option<u64>,
) -> Result<Option<Active>> {
    let Some(id) = registry.active else {
        return Ok(None);
    };
    let round = registry
        .completed
        .iter()
        .find(|r| r.sequence == id)
        .context("peer_updates_active_missing")?;
    let baseline = round
        .baseline
        .as_ref()
        .context("peer_updates_baseline_missing")?;
    ensure!(
        round.phase == Phase::Approved
            && round.retirement.is_none()
            && baseline.local_predecessor == local_latest,
        "peer_updates_active_local_history"
    );
    let comparison = verify_round(args, registry, round)?;
    ensure!(comparison.approved, "peer_updates_active_unapproved");
    let root = round_root(args, id)?;
    let raw = read_file(&root.join("comparison/decision.json"), 512 * 1024)?;
    let value = serde_json::to_value(comparison)?;
    Ok(Some(Active {
        adapter_root: root.join("import/adapter"),
        origin: json!({
            "kind":"peer_update", "import_sequence":id, "adapter_manifest_id":round.manifest_id,
            "dataset_manifest_id":round.dataset_manifest_id,"publisher_key":registry.feeds[round.channel].channel.publisher_key,
            "revision":round.revision,"local_predecessor":baseline.local_predecessor,
            "comparison_sha256":hex::encode(Sha256::digest(raw)),"adapter_files":value["candidate_files"]
        }),
    }))
}

fn verify_round(
    args: &Options,
    registry: &Registry,
    round: &Round,
) -> Result<super::peer_evaluation::Comparison> {
    let root = round_root(args, round.sequence)?;
    ensure!(
        round.snapshot.as_ref() == Some(&snapshot(&root)?),
        "peer_updates_round_snapshot_changed"
    );
    let query = request(args, &registry.feeds[round.channel], Some(round.revision))?;
    let source = dataset_source(
        round
            .source
            .as_ref()
            .context("peer_updates_source_missing")?,
    )?;
    let imported = peer_update::reopen(
        &root.join("import"),
        &query,
        &source,
        round.imported_at.context("peer_updates_import_time")?,
    )?;
    bind_import(&imported, round)?;
    let comparison = super::peer_evaluation::verify(&root)?;
    let baseline = round
        .baseline
        .as_ref()
        .context("peer_updates_baseline_missing")?;
    let value = serde_json::to_value(&comparison)?;
    ensure!(
        comparison.baseline_origin == baseline.origin
            && value["import_proof"] == *imported.provenance()
            && comparison.approved == (round.phase == Phase::Approved),
        "peer_updates_comparison_changed"
    );
    Ok(comparison)
}

fn verify_quarantine_round(args: &Options, registry: &Registry, round: &Round) -> Result<()> {
    let root = round_root(args, round.sequence)?;
    let query = request(args, &registry.feeds[round.channel], Some(round.revision))?;
    let source = dataset_source(
        round
            .source
            .as_ref()
            .context("peer_updates_source_missing")?,
    )?;
    let imported = peer_update::reopen(
        &root.join("import"),
        &query,
        &source,
        round.imported_at.context("peer_updates_import_time")?,
    )?;
    bind_import(&imported, round)?;
    let baseline = round
        .baseline
        .as_ref()
        .context("peer_updates_baseline_missing")?;
    super::peer_evaluation::verify_quarantine(&root, &baseline.origin, imported.provenance())
}

/// Called only while the normal owner budget admits work. At most one candidate
/// is progressed; all model futures retain the supervisor's cancellation/reap path.
#[allow(clippy::too_many_lines)] // One serial durable admission/import/comparison transaction.
pub(super) async fn tick(
    args: &Options,
    socket: &Path,
    pool: &Plan,
    store: &Store,
    state: &mut State,
    activity: &watch::Receiver<bool>,
) -> Result<bool> {
    let Some(mut registry) = state.peer_updates.clone() else {
        return Ok(false);
    };
    if !running(activity) {
        return Ok(false);
    }
    if registry.pending.is_none() {
        let changed = discover(args, socket, store, state, &mut registry, activity).await?;
        if registry.pending.is_none() || !running(activity) {
            return Ok(changed);
        }
    }
    let mut round = registry
        .pending
        .clone()
        .context("peer_updates_candidate_missing")?;
    let time = now()?;
    if round.next_attempt > time {
        return Ok(false);
    }
    if round.expires <= time {
        finish(args, &mut registry, Phase::Expired)?;
        checkpoint(&registry, store, state)?;
        return Ok(true);
    }
    let root = round_root(args, round.sequence)?;
    if round.phase == Phase::AwaitingSource {
        let source = resolve_source(pool, state, &round.dataset_manifest_id, time)?;
        let Some(source) = source else {
            round.next_attempt = time.saturating_add(u64::from(args.poll_seconds));
            registry.pending = Some(round);
            checkpoint(&registry, store, state)?;
            return Ok(true);
        };
        round.source = Some(source);
        round.phase = Phase::Importing;
        registry.pending = Some(round.clone());
        checkpoint(&registry, store, state)?;
    }
    if round.phase == Phase::Importing {
        let query = request(args, &registry.feeds[round.channel], Some(round.revision))?;
        let source = dataset_source(
            round
                .source
                .as_ref()
                .context("peer_updates_source_missing")?,
        )?;
        let imported = if root.join("import").try_exists()? {
            peer_update::reopen(&root.join("import"), &query, &source, time)
        } else {
            let update = peer_update::open_pending(&root.join("pending"), &query, time)?;
            bind_update(&update, &round)?;
            let mut changed = activity.clone();
            let output = root.join("import");
            tokio::select! {biased;
                _=changed.changed()=>return Ok(false),
                result=peer_update::import(&query,&update,&source,socket,&output)=>result,
            }
        };
        let Ok(imported) = imported else {
            registry
                .pending
                .as_mut()
                .context("peer_updates_pending")?
                .next_attempt = now()?.saturating_add(u64::from(args.poll_seconds));
            eprintln!("compute loop_event=peer_import_deferred");
            checkpoint(&registry, store, state)?;
            return Ok(true);
        };
        bind_import(&imported, &round)?;
        let baseline = super::current_adapter(args, store, state)?;
        round.imported_at = Some(now()?);
        round.baseline = Some(Baseline {
            adapter_root: baseline.adapter_root,
            origin: baseline.origin,
            local_predecessor: state.latest,
        });
        round.phase = Phase::Evaluating;
        round.snapshot = Some(snapshot(&root)?);
        registry.pending = Some(round.clone());
        checkpoint(&registry, store, state)?;
    }
    ensure!(
        round.phase == Phase::Evaluating,
        "peer_updates_pending_phase"
    );
    let baseline = round
        .baseline
        .as_ref()
        .context("peer_updates_baseline_missing")?;
    ensure!(
        state.latest == baseline.local_predecessor,
        "peer_updates_baseline_local_history_changed"
    );
    let current = super::current_adapter(args, store, state)?;
    ensure!(
        current.origin == baseline.origin && current.adapter_root == baseline.adapter_root,
        "peer_updates_baseline_changed"
    );
    super::validation::data(args, state)?.context("peer_updates_validation_required")?;
    let query = request(args, &registry.feeds[round.channel], Some(round.revision))?;
    let source = dataset_source(
        round
            .source
            .as_ref()
            .context("peer_updates_source_missing")?,
    )?;
    let imported = peer_update::reopen(&root.join("import"), &query, &source, now()?)?;
    bind_import(&imported, &round)?;
    let compared = super::peer_evaluation::assess(
        args,
        &root,
        &args.directory.join("validation-input"),
        baseline.adapter_root.as_deref(),
        &baseline.origin,
        imported.provenance(),
        activity,
    )
    .await;
    match compared {
        Ok(super::peer_evaluation::Outcome::Compared(comparison)) => {
            ensure!(
                comparison.baseline_origin == baseline.origin,
                "peer_updates_comparison_baseline"
            );
            if !running(activity) {
                return Ok(false);
            }
            let phase = if comparison.approved {
                Phase::Approved
            } else {
                Phase::Rejected
            };
            finish(args, &mut registry, phase)?;
            if phase == Phase::Approved {
                registry.active = Some(round.sequence);
                eprintln!("compute loop_event=peer_update_adopted");
            } else {
                eprintln!("compute loop_event=peer_update_rejected");
            }
        }
        Ok(super::peer_evaluation::Outcome::Quarantined) => {
            if !running(activity) {
                return Ok(false);
            }
            verify_quarantine_round(args, &registry, &round)?;
            // Never change the accepted warmstart or ban this publisher. Only
            // this exact manifest is consumed; subsequent revisions remain eligible.
            finish(args, &mut registry, Phase::Quarantined)?;
            eprintln!("compute loop_event=peer_update_quarantined");
        }
        Err(_) if !running(activity) => return Ok(false),
        Err(_) => {
            finish(args, &mut registry, Phase::Failed)?;
            eprintln!("compute loop_event=peer_comparison_failed");
        }
    }
    checkpoint(&registry, store, state)?;
    Ok(true)
}

async fn discover(
    args: &Options,
    socket: &Path,
    store: &Store,
    state: &mut State,
    registry: &mut Registry,
    activity: &watch::Receiver<bool>,
) -> Result<bool> {
    let time = now()?;
    let Some(index) = (0..registry.feeds.len())
        .map(|n| (registry.cursor + n) % registry.feeds.len())
        .find(|index| registry.feeds[*index].next_poll <= time)
    else {
        return Ok(false);
    };
    if !make_room(args, store, state, registry)? {
        return Ok(false);
    }
    let query = request(args, &registry.feeds[index], registry.feeds[index].revision)?;
    registry.feeds[index].next_poll = time.saturating_add(u64::from(args.poll_seconds));
    registry.cursor = (index + 1) % registry.feeds.len();
    checkpoint(registry, store, state)?;
    let mut changed = activity.clone();
    let fetched = tokio::select! {biased;
        _=changed.changed()=>return Ok(true),
        result=peer_update::fetch(&query,socket,&args.directory)=>result,
    };
    let Ok(update) = fetched else {
        eprintln!("compute loop_event=peer_discovery_deferred");
        return Ok(true);
    };
    let manifest = hex::encode(update.manifest_id());
    let feed = &mut registry.feeds[index];
    if admit_revision(feed, update.revision(), &manifest).is_err() {
        eprintln!("compute loop_event=peer_revision_rejected");
        return Ok(true);
    }
    if feed.processed_manifest.as_ref() == Some(&manifest) {
        checkpoint(registry, store, state)?;
        return Ok(true);
    }
    let sequence = registry.next_sequence;
    registry.next_sequence = sequence
        .checked_add(1)
        .context("peer_updates_sequence_exhausted")?;
    registry.pending = Some(Round {
        sequence,
        channel: index,
        revision: update.revision(),
        manifest_id: manifest,
        dataset_manifest_id: hex::encode(update.dataset_manifest_id()),
        observed_at: now()?,
        expires: update.expires(),
        next_attempt: 0,
        phase: Phase::Staging,
        source: None,
        imported_at: None,
        baseline: None,
        snapshot: None,
        retirement: None,
    });
    checkpoint(registry, store, state)?;
    let root = round_root(args, sequence)?;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    File::open(&args.directory)?.sync_all()?;
    peer_update::save_pending(&update, &root.join("pending"))?;
    registry
        .pending
        .as_mut()
        .context("peer_updates_pending")?
        .phase = Phase::AwaitingSource;
    checkpoint(registry, store, state)?;
    Ok(true)
}

fn admit_revision(feed: &mut Feed, revision: u64, manifest: &str) -> Result<()> {
    ensure!(
        revision > 0
            && hash(manifest)
            && feed
                .channel
                .min_revision
                .is_none_or(|floor| revision >= floor)
            && feed.revision.is_none_or(|old| revision >= old)
            && (feed.revision != Some(revision) || feed.manifest_id.as_deref() == Some(manifest)),
        "peer_updates_revision_conflict"
    );
    feed.revision = Some(revision);
    feed.manifest_id = Some(manifest.to_owned());
    Ok(())
}

fn request(args: &Options, feed: &Feed, floor: Option<u64>) -> Result<Fetch> {
    Ok(Fetch {
        publisher_key: content::parse_publisher_key(&feed.channel.publisher_key)
            .map_err(anyhow::Error::msg)?,
        name: feed.channel.name.clone(),
        min_revision: floor.max(feed.channel.min_revision),
        cache: args.cache.clone(),
        limits: args.limits.clone(),
    })
}

fn resolve_source(pool: &Plan, state: &State, manifest: &str, time: u64) -> Result<Option<Source>> {
    let mut selected = None;
    for (index, source) in pool.sources.iter().enumerate() {
        if source.manifest_id.as_deref() != Some(manifest)
            || source.min_revision.is_none()
            || state
                .catalog
                .as_ref()
                .is_some_and(|r| !r.eligible(r.static_count(), index, time))
        {
            continue;
        }
        dataset_source(source)?;
        ensure!(
            selected.is_none(),
            "peer_updates_ambiguous_dataset_authority"
        );
        selected = Some(source.clone());
    }
    Ok(selected)
}

fn dataset_source(source: &Source) -> Result<DatasetSource> {
    Ok(DatasetSource {
        publisher_key: source.key()?,
        name: source.name.clone(),
        revision: source
            .min_revision
            .filter(|n| *n > 0)
            .context("peer_updates_exact_dataset_revision")?,
        manifest_id: source
            .manifest()?
            .context("peer_updates_exact_dataset_manifest")?,
    })
}

fn bind_update(update: &VerifiedUpdate, round: &Round) -> Result<()> {
    ensure!(
        hex::encode(update.manifest_id()) == round.manifest_id
            && hex::encode(update.dataset_manifest_id()) == round.dataset_manifest_id
            && update.revision() == round.revision
            && update.expires() == round.expires,
        "peer_updates_pending_changed"
    );
    Ok(())
}

fn bind_import(imported: &ImportedUpdate, round: &Round) -> Result<()> {
    ensure!(
        hex::encode(imported.manifest_id()) == round.manifest_id
            && hex::encode(imported.dataset_manifest_id()) == round.dataset_manifest_id
            && imported.revision() == round.revision
            && imported.expires() <= round.expires,
        "peer_updates_import_changed"
    );
    Ok(())
}

fn finish(args: &Options, registry: &mut Registry, phase: Phase) -> Result<()> {
    ensure!(
        matches!(
            phase,
            Phase::Approved | Phase::Rejected | Phase::Quarantined | Phase::Failed | Phase::Expired
        ),
        "peer_updates_finish_phase"
    );
    let mut round = registry.pending.take().context("peer_updates_pending")?;
    round.phase = phase;
    round.snapshot = Some(snapshot(&round_root(args, round.sequence)?)?);
    registry.feeds[round.channel].processed_manifest = Some(round.manifest_id.clone());
    registry.completed.push(round);
    Ok(())
}

fn checkpoint(registry: &Registry, store: &Store, state: &mut State) -> Result<()> {
    state.peer_updates = Some(registry.clone());
    store.save_state(&serde_json::to_value(state)?)
}

fn make_room(
    args: &Options,
    store: &Store,
    state: &mut State,
    registry: &mut Registry,
) -> Result<bool> {
    if registry.completed.len() < RETAINED {
        return Ok(true);
    }
    let predecessor = retirement::predecessor_sequence(registry);
    let Some(index) = registry.completed.iter().position(|round| {
        Some(round.sequence) != registry.active && Some(round.sequence) != predecessor
    }) else {
        return Ok(false);
    };
    let obsolete = registry.completed.remove(index);
    registry.garbage.push(obsolete.sequence);
    checkpoint(registry, store, state)?;
    prune(&round_root(args, obsolete.sequence)?)?;
    registry.garbage.clear();
    checkpoint(registry, store, state)?;
    Ok(true)
}

fn round_root(args: &Options, sequence: u64) -> Result<PathBuf> {
    ensure!(sequence > 0, "peer_updates_round_sequence");
    private_directory(&args.directory)?;
    Ok(args.directory.join(format!("peer-update-{sequence:016x}")))
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn allowed(path: &Path, directory: bool) -> bool {
    let Some(name) = path.to_str() else {
        return false;
    };
    if directory {
        return matches!(
            name,
            "pending"
                | "import"
                | "import/adapter"
                | "comparison"
                | "comparison/baseline"
                | "comparison/candidate"
        );
    }
    matches!(
        name,
        "pending/adapter.bundle"
            | "pending/adapter.manifest"
            | "pending/provenance.json"
            | "import/adapter.bundle"
            | "import/adapter.manifest"
            | "import/provenance.json"
            | "import/dataset.json"
            | "import/dataset.manifest"
            | "import/adapter/README.md"
            | "import/adapter/adapter_config.json"
            | "import/adapter/adapter_model.safetensors"
            | "comparison/selection.json"
            | "comparison/dataset.json"
            | "comparison/dataset.manifest"
            | "comparison/provenance.json"
            | "comparison/baseline-report.json"
            | "comparison/candidate-report.json"
            | "comparison/decision.json"
            | "comparison/quarantine.json"
            | "comparison/baseline/report.json"
            | "comparison/candidate/report.json"
    )
}

fn tree(root: &Path) -> Result<Vec<(PathBuf, bool)>> {
    if !root.try_exists()? {
        return Ok(Vec::new());
    }
    private_directory(root)?;
    let mut todo = vec![(PathBuf::new(), 0)];
    let mut result = Vec::new();
    let mut bytes = 0_u64;
    while let Some((relative, depth)) = todo.pop() {
        ensure!(depth <= 4, "peer_updates_tree_depth");
        for entry in fs::read_dir(root.join(&relative))? {
            let entry = entry?;
            let path = relative.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(
                result.len() < MAX_TREE_ENTRIES
                    && metadata.uid() == nix::unistd::geteuid().as_raw()
                    && allowed(&path, metadata.is_dir()),
                "peer_updates_tree_owner_or_name"
            );
            if metadata.is_dir() {
                private_directory(&entry.path())?;
                todo.push((path.clone(), depth + 1));
            } else {
                ensure!(
                    metadata.is_file()
                        && metadata.nlink() == 1
                        && metadata.permissions().mode() & 0o777 == 0o600,
                    "peer_updates_tree_file"
                );
                bytes = bytes
                    .checked_add(metadata.len())
                    .context("peer_updates_tree_size")?;
                ensure!(bytes <= MAX_TREE_BYTES, "peer_updates_tree_size");
            }
            result.push((path, metadata.is_dir()));
        }
    }
    Ok(result)
}

fn snapshot(root: &Path) -> Result<Snapshot> {
    let mut result = Snapshot::new();
    for (path, directory) in tree(root)? {
        if directory {
            continue;
        }
        let raw = read_file(&root.join(&path), MAX_TREE_BYTES)?;
        result.insert(
            path.to_str().context("peer_updates_file_encoding")?.into(),
            super::storage::FileSnapshot {
                bytes: raw.len() as u64,
                sha256: hex::encode(Sha256::digest(raw)),
            },
        );
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
mod tests;
