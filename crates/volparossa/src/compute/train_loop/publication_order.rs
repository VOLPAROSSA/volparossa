//! One retained publication order for local and aggregate adapters on one channel.
//!
//! The coordinator must persist the updated ledger before signing. This pure
//! allocator does not infer revisions from remote state or perform filesystem IO.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};

const MAX_ENTRIES: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    tag = "kind",
    content = "sequence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum Target {
    Local(u64),
    Aggregate(u64),
}

impl Target {
    fn validate(self) -> Result<()> {
        let (Self::Local(sequence) | Self::Aggregate(sequence)) = self;
        ensure!(sequence > 0, "train_publication_order_target");
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    target: Target,
    revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ledger {
    version: u32,
    first: u64,
    // Explicit null means u64::MAX was consumed, not an absent/legacy cursor.
    #[serde(deserialize_with = "required_next")]
    next_revision: Option<u64>,
    entries: Vec<Entry>,
}

fn required_next<'de, D: Deserializer<'de>>(value: D) -> Result<Option<u64>, D::Error> {
    Option::deserialize(value)
}

impl Ledger {
    pub(super) fn new(first: u64) -> Result<Self> {
        ensure!(first > 0, "train_publication_order_first");
        Ok(Self {
            version: 1,
            first,
            next_revision: Some(first),
            entries: Vec::new(),
        })
    }

    /// Idempotent for each retained target, including after counter exhaustion.
    /// Persist the resulting state before constructing any signed publication.
    pub(super) fn allocate(&mut self, target: Target) -> Result<u64> {
        self.validate(self.first)?;
        target.validate()?;
        if let Some(revision) = self.get(target) {
            return Ok(revision);
        }
        let revision = self
            .next_revision
            .context("train_publication_order_exhausted")?;
        ensure!(
            self.entries.len() < MAX_ENTRIES,
            "train_publication_order_full"
        );
        self.entries.push(Entry { target, revision });
        self.next_revision = revision.checked_add(1);
        Ok(revision)
    }

    pub(super) fn get(&self, target: Target) -> Option<u64> {
        self.entries
            .iter()
            .find(|entry| entry.target == target)
            .map(|entry| entry.revision)
    }

    pub(super) fn validate(&self, first: u64) -> Result<()> {
        ensure!(
            self.version == 1 && self.first == first && first > 0,
            "train_publication_order_enrollment"
        );
        ensure!(
            self.entries.len() <= MAX_ENTRIES,
            "train_publication_order_full"
        );
        if let Some(next) = self.next_revision {
            ensure!(next >= first, "train_publication_order_cursor");
        }
        let mut targets = BTreeSet::new();
        let mut previous = None;
        for entry in &self.entries {
            entry.target.validate()?;
            ensure!(
                targets.insert(entry.target),
                "train_publication_order_duplicate_target"
            );
            ensure!(
                entry.revision >= first
                    && previous.is_none_or(|old| old < entry.revision)
                    && self.next_revision.is_none_or(|next| entry.revision < next),
                "train_publication_order_revision"
            );
            previous = Some(entry.revision);
        }
        Ok(())
    }

    /// Drop only mappings whose cycles/rounds the coordinator has pruned. Never
    /// rewind the cursor. Pruned targets must not be resurrected by the caller;
    /// bounded retention is not an unbounded historical target registry.
    pub(super) fn retain(&mut self, retained: &BTreeSet<Target>) -> Result<()> {
        self.validate(self.first)?;
        for target in retained {
            target.validate()?;
        }
        self.entries
            .retain(|entry| retained.contains(&entry.target));
        Ok(())
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (Target, u64)> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.target, entry.revision))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn interleaved_targets_keep_exact_revisions_across_checkpoint_roundtrip() {
        let mut ledger = Ledger::new(41).unwrap();
        let ordered = [
            (Target::Local(1), 41),
            (Target::Aggregate(1), 42),
            (Target::Local(2), 43),
        ];
        for (target, revision) in ordered {
            assert_eq!(ledger.allocate(target).unwrap(), revision);
        }
        let bytes = serde_json::to_vec(&ledger).unwrap();
        let mut reopened: Ledger = serde_json::from_slice(&bytes).unwrap();
        reopened.validate(41).unwrap();
        for (target, revision) in ordered.into_iter().rev() {
            assert_eq!(reopened.allocate(target).unwrap(), revision);
        }
        assert_eq!(reopened.iter().collect::<Vec<_>>(), ordered);
        assert_eq!(serde_json::to_vec(&reopened).unwrap(), bytes);
        assert_eq!(reopened.allocate(Target::Aggregate(2)).unwrap(), 44);
        assert_eq!(reopened.get(Target::Local(99)), None);
    }

    #[test]
    fn strict_checkpoint_rejects_duplicate_reordered_or_rolled_back_entries() {
        let mut ledger = Ledger::new(7).unwrap();
        ledger.allocate(Target::Local(1)).unwrap();
        ledger.allocate(Target::Aggregate(1)).unwrap();
        let valid = serde_json::to_value(&ledger).unwrap();
        assert!(ledger.validate(8).is_err());
        for altered in [
            json!({"version":2}),
            json!({"first":0}),
            json!({"next_revision":0}),
            json!({"next_revision":8}),
            json!({"entries":[valid["entries"][0].clone(), valid["entries"][0].clone()]}),
            json!({"entries":[valid["entries"][1].clone(), valid["entries"][0].clone()]}),
            json!({"entries":[{"target":{"kind":"local","sequence":0},"revision":7}]}),
            json!({"entries":[{"target":{"kind":"local","sequence":1},"revision":6}]}),
            json!({"entries":[{"target":{"kind":"local","sequence":1},"revision":7},
                {"target":{"kind":"aggregate","sequence":1},"revision":7}]}),
        ] {
            let mut invalid = valid.clone();
            for (name, value) in altered.as_object().unwrap() {
                invalid[name] = value.clone();
            }
            assert!(
                serde_json::from_value::<Ledger>(invalid)
                    .unwrap()
                    .validate(7)
                    .is_err()
            );
        }
        for field in ["version", "first", "next_revision", "entries"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Ledger>(missing).is_err());
        }
        let mut extra = valid;
        extra["unrecognized"] = true.into();
        assert!(serde_json::from_value::<Ledger>(extra).is_err());
        for invalid in [
            json!({"kind":"other","sequence":1}),
            json!({"kind":"local","sequence":1,"unrecognized":true}),
            json!({"kind":"local"}),
        ] {
            assert!(serde_json::from_value::<Target>(invalid).is_err());
        }
        assert!(Ledger::new(0).is_err());
    }

    #[test]
    fn final_revision_is_allocated_once_and_exhaustion_survives_full_pruning() {
        let mut ledger = Ledger::new(u64::MAX - 1).unwrap();
        assert_eq!(ledger.allocate(Target::Local(1)).unwrap(), u64::MAX - 1);
        assert_eq!(ledger.allocate(Target::Aggregate(1)).unwrap(), u64::MAX);
        assert_eq!(ledger.allocate(Target::Aggregate(1)).unwrap(), u64::MAX);
        let before = ledger.clone();
        assert_eq!(
            ledger.allocate(Target::Local(2)).unwrap_err().to_string(),
            "train_publication_order_exhausted"
        );
        assert_eq!(ledger, before);
        ledger.retain(&BTreeSet::new()).unwrap();
        let mut reopened: Ledger =
            serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
        reopened.validate(u64::MAX - 1).unwrap();
        assert!(reopened.allocate(Target::Aggregate(2)).is_err());
        let mut final_only = Ledger::new(u64::MAX).unwrap();
        assert_eq!(final_only.allocate(Target::Local(1)).unwrap(), u64::MAX);
        assert!(final_only.allocate(Target::Local(2)).is_err());
    }

    #[test]
    fn retention_preserves_live_targets_and_never_reuses_forgotten_revisions() {
        let mut ledger = Ledger::new(100).unwrap();
        ledger.allocate(Target::Local(1)).unwrap();
        ledger.allocate(Target::Aggregate(1)).unwrap();
        ledger.allocate(Target::Local(2)).unwrap();
        // An unallocated retained target is allowed: it has not been signed yet.
        ledger
            .retain(&BTreeSet::from([
                Target::Aggregate(1),
                Target::Local(2),
                Target::Aggregate(2),
            ]))
            .unwrap();
        assert_eq!(ledger.get(Target::Local(1)), None);
        assert_eq!(ledger.allocate(Target::Aggregate(1)).unwrap(), 101);
        assert_eq!(ledger.allocate(Target::Aggregate(2)).unwrap(), 103);
        ledger.retain(&BTreeSet::new()).unwrap();
        ledger.validate(100).unwrap();
        assert_eq!(ledger.allocate(Target::Local(3)).unwrap(), 104);
        let before = ledger.clone();
        assert!(ledger.retain(&BTreeSet::from([Target::Local(0)])).is_err());
        assert_eq!(ledger, before);
    }

    #[test]
    fn bounded_retention_full_or_invalid_allocation_does_not_advance_cursor() {
        let mut ledger = Ledger::new(1).unwrap();
        for sequence in 1..=MAX_ENTRIES as u64 {
            assert_eq!(ledger.allocate(Target::Local(sequence)).unwrap(), sequence);
        }
        let before = ledger.clone();
        assert!(ledger.allocate(Target::Aggregate(1)).is_err());
        assert!(ledger.allocate(Target::Local(0)).is_err());
        assert_eq!(ledger, before);
        assert_eq!(ledger.allocate(Target::Local(1)).unwrap(), 1);
        ledger.retain(&BTreeSet::from([Target::Local(1)])).unwrap();
        assert_eq!(ledger.allocate(Target::Aggregate(1)).unwrap(), 33);
        let mut oversized: Value = serde_json::to_value(before).unwrap();
        oversized["entries"].as_array_mut().unwrap().push(json!({
            "target":{"kind":"aggregate","sequence":1},"revision":33}));
        oversized["next_revision"] = 34.into();
        assert!(
            serde_json::from_value::<Ledger>(oversized)
                .unwrap()
                .validate(1)
                .is_err()
        );
    }
}
