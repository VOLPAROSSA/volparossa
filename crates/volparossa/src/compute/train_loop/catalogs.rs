//! Owner-selected signed catalog snapshots and stable, bounded source slots.
//! Cache availability never enrolls a publisher or changes the selected source.

use std::{collections::BTreeSet, path::Path};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;
use volparossa_content::SignedManifest;

use super::{MAX_SOURCES, Options, Plan, Source, active, now, storage::Store};
use crate::content::source_catalog::{self, Entry, Fetch, VerifiedCatalog};

const MAX_CATALOGS: usize = 16;
const MAX_REGISTRY_BYTES: usize = 3 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Registry {
    version: u32,
    static_count: usize,
    cursor: usize,
    feeds: Vec<Feed>,
    slots: Vec<Slot>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Feed {
    enrolled: Source,
    snapshot: Option<Snapshot>,
    next_refresh: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    revision: u64,
    manifest_id: String,
    expires: u64,
    verified_at: u64,
    signed_manifest_hex: String,
    body: String,
    receipt: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    feed: usize,
    source: Source,
    active: bool,
    expires: u64,
    last_seen_catalog_revision: u64,
}

impl Snapshot {
    fn received(catalog: &VerifiedCatalog, time: u64) -> Result<Self> {
        Ok(Self {
            revision: catalog.revision(),
            manifest_id: hex::encode(catalog.manifest_id()),
            expires: catalog.expires(),
            verified_at: time,
            signed_manifest_hex: hex::encode(catalog.signed_manifest()),
            body: std::str::from_utf8(catalog.body())?.to_owned(),
            receipt: catalog.receipt().clone(),
        })
    }

    fn verify(&self, enrolled: &Source, time: u64) -> Result<Vec<Entry>> {
        ensure!(
            self.verified_at > 0
                && self.verified_at <= time
                && self.signed_manifest_hex.len() <= 2 * volparossa_content::MAX_MANIFEST_BYTES
                && self.body.len() <= source_catalog::MAX_BYTES
                && serde_json::to_vec(&self.receipt)?.len() <= MAX_RECEIPT_BYTES,
            "train_catalog_snapshot_bounds"
        );
        let key = enrolled.key()?;
        let bytes = hex::decode(&self.signed_manifest_hex)?;
        ensure!(
            hex::encode(&bytes) == self.signed_manifest_hex,
            "train_catalog_manifest_encoding"
        );
        let signed = SignedManifest::decode(&bytes)?;
        let manifest = signed.verify(&key, self.verified_at)?;
        ensure!(
            manifest.metadata().name == enrolled.name
                && manifest.metadata().revision == self.revision
                && self.revision >= enrolled.min_revision.unwrap_or(1)
                && hex::encode(manifest.manifest_id()) == self.manifest_id
                && enrolled
                    .manifest()?
                    .is_none_or(|id| &id == manifest.manifest_id())
                && manifest.validity().expires == self.expires,
            "train_catalog_enrolled_snapshot"
        );
        source_catalog::verify(&bytes, self.body.as_bytes(), &key, self.verified_at)
    }
}

impl Registry {
    pub(super) fn new(base: &Plan) -> Result<Self> {
        ensure!(
            base.sources.len() <= MAX_SOURCES && (1..=MAX_CATALOGS).contains(&base.catalogs.len()),
            "train_catalog_enrollment_bounds"
        );
        let registry = Self {
            version: 1,
            static_count: base.sources.len(),
            cursor: 0,
            feeds: base
                .catalogs
                .iter()
                .cloned()
                .map(|enrolled| Feed {
                    enrolled,
                    snapshot: None,
                    next_refresh: 0,
                })
                .collect(),
            slots: Vec::new(),
        };
        registry.validate(base, now()?)?;
        Ok(registry)
    }

    pub(super) const fn static_count(&self) -> usize {
        self.static_count
    }

    pub(super) fn sources(&self, base: &Plan) -> Vec<Source> {
        base.sources
            .iter()
            .take(self.static_count)
            .cloned()
            .chain(self.slots.iter().map(|slot| slot.source.clone()))
            .collect()
    }

    pub(super) fn eligible(&self, static_count: usize, index: usize, time: u64) -> bool {
        if static_count != self.static_count {
            return false;
        }
        if index < self.static_count {
            return true;
        }
        self.slots
            .get(index - self.static_count)
            .is_some_and(|slot| slot.active && slot.expires > time)
    }

    // One cross-check of the bounded enrolled feeds, signed snapshots and stable source slots.
    #[allow(clippy::too_many_lines)]
    pub(super) fn validate(&self, base: &Plan, time: u64) -> Result<()> {
        ensure!(
            self.version == 1
                && self.static_count == base.sources.len()
                && self.static_count <= MAX_SOURCES
                && self.slots.len() <= MAX_SOURCES - self.static_count
                && (1..=MAX_CATALOGS).contains(&self.feeds.len())
                && self.feeds.len() == base.catalogs.len()
                && self.cursor < self.feeds.len(),
            "train_catalog_registry_bounds"
        );
        let mut source_keys = BTreeSet::new();
        for source in &base.sources {
            source_fields(source)?;
            ensure!(
                source_keys.insert(identity(source)?),
                "train_catalog_static_duplicate"
            );
        }
        let mut feed_keys = BTreeSet::new();
        let mut rows = Vec::with_capacity(self.feeds.len());
        for (feed, enrolled) in self.feeds.iter().zip(&base.catalogs) {
            source_fields(enrolled)?;
            ensure!(
                &feed.enrolled == enrolled && feed_keys.insert(identity(enrolled)?),
                "train_catalog_enrollment_changed"
            );
            rows.push(
                feed.snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.verify(enrolled, time))
                    .transpose()?,
            );
        }
        for slot in &self.slots {
            source_fields(&slot.source)?;
            ensure!(
                slot.feed < self.feeds.len()
                    && slot.source.min_revision.is_some()
                    && slot.source.manifest_id.is_some()
                    && source_keys.insert(identity(&slot.source)?),
                "train_catalog_slot_identity"
            );
            let feed = &self.feeds[slot.feed];
            let snapshot = feed
                .snapshot
                .as_ref()
                .context("train_catalog_slot_without_snapshot")?;
            ensure!(
                slot.source.key()? == feed.enrolled.key()?
                    && slot.last_seen_catalog_revision > 0
                    && slot.last_seen_catalog_revision <= snapshot.revision,
                "train_catalog_slot_authority"
            );
            let row = rows[slot.feed]
                .as_ref()
                .and_then(|rows| rows.iter().find(|row| row.name == slot.source.name));
            if let Some(row) = row {
                ensure!(
                    slot.active
                        && slot.expires == snapshot.expires
                        && slot.last_seen_catalog_revision == snapshot.revision
                        && slot.source == row_source(&feed.enrolled, row),
                    "train_catalog_active_row_changed"
                );
            } else {
                // Retired slots are local progress tombstones, not independent signed proofs.
                ensure!(
                    !slot.active && slot.expires == 0,
                    "train_catalog_withdrawn_row_active"
                );
            }
        }
        for (index, rows) in rows.iter().enumerate() {
            if let Some(rows) = rows {
                ensure!(
                    rows.iter().all(|row| self.slots.iter().any(|slot| {
                        slot.feed == index && slot.source.name == row.name && slot.active
                    })),
                    "train_catalog_snapshot_row_missing"
                );
            }
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_REGISTRY_BYTES,
            "train_catalog_registry_capacity"
        );
        Ok(())
    }

    /// The caller may supply its full runtime pool; offsets always use the immutable static count.
    pub(super) fn proof_for(&self, _base: &Plan, index: usize) -> Option<Value> {
        let slot = self.slots.get(index.checked_sub(self.static_count)?)?;
        if !slot.active {
            return None;
        }
        let feed = self.feeds.get(slot.feed)?;
        let snapshot = feed.snapshot.as_ref()?;
        Some(
            json!({"version":1,"catalog_publisher_key":feed.enrolled.publisher_key.to_ascii_lowercase(),
            "catalog_name":feed.enrolled.name,"catalog_manifest_id":snapshot.manifest_id,
            "catalog_revision":snapshot.revision,"catalog_expires_unix_seconds":snapshot.expires,
            "verified_at_unix_seconds":snapshot.verified_at,"signed_manifest_hex":snapshot.signed_manifest_hex,
            "catalog_body":snapshot.body,"selected_source":slot.source}),
        )
    }

    /// One bounded attempt; true includes failed attempts whose durable retry deadline changed.
    pub(super) async fn refresh_one(
        &mut self,
        args: &Options,
        socket: &Path,
        base: &Plan,
        _store: &Store,
        activity: &watch::Receiver<bool>,
    ) -> Result<bool> {
        if !active(activity) {
            return Ok(false);
        }
        let time = now()?;
        let Some(index) = (0..self.feeds.len())
            .map(|offset| (self.cursor + offset) % self.feeds.len())
            .find(|index| self.feeds[*index].next_refresh <= time)
        else {
            return Ok(false);
        };
        let feed = &self.feeds[index];
        let fetch = Fetch {
            publisher_key: feed.enrolled.key()?,
            name: feed.enrolled.name.clone(),
            min_revision: Some(
                feed.enrolled.min_revision.unwrap_or(1).max(
                    feed.snapshot
                        .as_ref()
                        .map_or(1, |snapshot| snapshot.revision),
                ),
            ),
            manifest_id: feed.enrolled.manifest()?,
            cache: args.cache.clone(),
            limits: args.limits.clone(),
        };
        let validation = super::validation::selection(args)?;
        let mut receiver = activity.clone();
        let result = tokio::select! {
            biased;
            () = cancelled(&mut receiver) => None,
            result = source_catalog::fetch(&fetch, socket, &args.directory) => Some(result),
        };
        self.feeds[index].next_refresh = now()?.saturating_add(u64::from(args.poll_seconds));
        self.cursor = (index + 1) % self.feeds.len();
        match result {
            Some(Ok(catalog)) if active(activity) => {
                let candidate_snapshot = Snapshot::received(&catalog, now()?)?;
                match self.accept(base, index, candidate_snapshot, validation.as_ref(), now()?) {
                    Ok(()) => eprintln!(
                        "compute loop_event=catalog_refreshed source_count={}",
                        catalog.rows().len()
                    ),
                    Err(error) if error.to_string() == "train_catalog_registry_capacity" => {
                        eprintln!("compute loop_event=catalog_capacity_refused");
                    }
                    Err(_) => eprintln!("compute loop_event=catalog_update_rejected"),
                }
            }
            Some(_) => eprintln!("compute loop_event=catalog_refresh_failed"),
            None => eprintln!("compute loop_event=catalog_refresh_cancelled"),
        }
        Ok(true)
    }

    fn accept(
        &mut self,
        base: &Plan,
        index: usize,
        snapshot: Snapshot,
        validation: Option<&Source>,
        time: u64,
    ) -> Result<()> {
        let feed = self.feeds.get(index).context("train_catalog_feed_index")?;
        let rows = snapshot.verify(&feed.enrolled, time)?;
        ensure!(
            snapshot.expires > time,
            "train_catalog_expired_before_admission"
        );
        if let Some(previous) = &feed.snapshot {
            ensure!(
                snapshot.revision >= previous.revision
                    && (snapshot.revision != previous.revision
                        || snapshot.manifest_id == previous.manifest_id),
                "train_catalog_revision_conflict"
            );
        }
        let mut candidate = self.clone();
        for slot in candidate.slots.iter_mut().filter(|slot| slot.feed == index) {
            slot.active = false;
            slot.expires = 0;
        }
        for row in rows {
            let source = row_source(&feed.enrolled, &row);
            let key = identity(&source)?;
            ensure!(
                !base
                    .sources
                    .iter()
                    .any(|item| identity(item).is_ok_and(|item| item == key)),
                "train_catalog_static_source_collision"
            );
            if let Some(validation) = validation {
                ensure!(
                    identity(validation)? != key && validation.manifest()? != source.manifest()?,
                    "train_catalog_validation_source_collision"
                );
            }
            if let Some(slot) = candidate
                .slots
                .iter_mut()
                .find(|slot| identity(&slot.source).is_ok_and(|item| item == key))
            {
                ensure!(slot.feed == index, "train_catalog_other_feed_collision");
                let old_revision = slot
                    .source
                    .min_revision
                    .context("train_catalog_row_revision")?;
                ensure!(
                    row.revision >= old_revision
                        && (row.revision != old_revision
                            || source.manifest_id == slot.source.manifest_id),
                    "train_catalog_source_revision_conflict"
                );
                slot.source = source;
                slot.active = true;
                slot.expires = snapshot.expires;
                slot.last_seen_catalog_revision = snapshot.revision;
            } else {
                ensure!(
                    candidate.slots.len() + self.static_count < MAX_SOURCES,
                    "train_catalog_registry_capacity"
                );
                candidate.slots.push(Slot {
                    feed: index,
                    source,
                    active: true,
                    expires: snapshot.expires,
                    last_seen_catalog_revision: snapshot.revision,
                });
            }
        }
        candidate.feeds[index].snapshot = Some(snapshot);
        candidate.validate(base, time)?;
        *self = candidate;
        Ok(())
    }
}

fn identity(source: &Source) -> Result<([u8; 32], String)> {
    Ok((source.key()?.to_bytes(), source.name.clone()))
}

fn source_fields(source: &Source) -> Result<()> {
    source.key()?;
    source.manifest()?;
    crate::content::parse_content_name(&source.name).map_err(anyhow::Error::msg)?;
    ensure!(
        source.min_revision != Some(0),
        "train_catalog_source_revision"
    );
    Ok(())
}

fn row_source(enrolled: &Source, row: &Entry) -> Source {
    Source {
        publisher_key: enrolled.publisher_key.to_ascii_lowercase(),
        name: row.name.clone(),
        min_revision: Some(row.revision),
        manifest_id: Some(hex::encode(row.manifest_id)),
    }
}

async fn cancelled(activity: &mut watch::Receiver<bool>) {
    while active(activity) {
        if activity.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests;
