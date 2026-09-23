//! Opt-in export of the loop's selected approved adapter, never every completed candidate.

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Options, State, Store, evaluation, now, peer_updates, read_file};
use crate::compute::serving_snapshot::Publisher;

pub(super) struct Serving {
    publisher: Publisher,
    last: Option<(Option<u64>, Option<u64>)>,
}

impl Serving {
    pub(super) fn open(args: &Options, enrollment: &Value) -> Result<Option<Self>> {
        args.serving_directory
            .as_ref()
            .map(|root| {
                let mut identity = serde_json::to_vec(enrollment)?;
                // Equal configurations in distinct loop directories do not share writer authority.
                identity.extend(serde_json::to_vec(&args.directory)?);
                Ok(Self {
                    publisher: Publisher::open(
                        root,
                        &args.runtime_root,
                        &hex::encode(Sha256::digest(identity)),
                    )?,
                    last: None,
                })
            })
            .transpose()
    }

    pub(super) fn reconcile(&mut self, args: &Options, store: &Store, state: &State) -> Result<()> {
        let peer = state
            .peer_updates
            .as_ref()
            .and_then(peer_updates::active_sequence);
        let key = (state.latest, peer);
        if self.last == Some(key) {
            return Ok(());
        }
        let candidate = if let Some(registry) = &state.peer_updates {
            peer_updates::serving_candidate(args, registry, state.latest)?
        } else {
            None
        };
        let candidate = match candidate {
            Some(candidate) => Some(candidate),
            None => local_candidate(store, state)?,
        };
        if let Some((adapter, expires, provenance)) = candidate {
            let at = now()?;
            if expires > at {
                self.publisher.publish(&adapter, expires, &provenance, at)?;
                eprintln!("compute loop_event=approved_serving_snapshot_published");
            }
        }
        // An expired selection is never republished with a renewed deadline.
        self.last = Some(key);
        Ok(())
    }

    /// Called only after typed, proven active-adapter corruption without a valid
    /// approved predecessor. Busy, I/O uncertainty and quality differences do not revoke.
    pub(super) fn withdraw(&mut self) -> Result<()> {
        self.publisher.withdraw_current()?;
        self.last = None;
        Ok(())
    }
}

pub(super) fn local_candidate(
    store: &Store,
    state: &State,
) -> Result<Option<(std::path::PathBuf, u64, Value)>> {
    let Some(sequence) = state.latest else {
        return Ok(None);
    };
    let cycle = state
        .cycles
        .iter()
        .find(|cycle| cycle.sequence == sequence)
        .context("serving_loop_latest_missing")?;
    store.validate_snapshot(
        sequence,
        cycle
            .snapshot
            .as_ref()
            .context("serving_loop_snapshot_missing")?,
    )?;
    let decision = evaluation::verify(store, sequence)?;
    ensure!(decision.approved, "serving_loop_unapproved_successor");
    let record = serde_json::to_value(&decision)?;
    let result = store.read_cycle_json(sequence, "result.json")?;
    let selection = store.read_cycle_json(sequence, "selection.json")?;
    let mut expires = result["source_expires_unix_seconds"]
        .as_u64()
        .context("serving_loop_source_expiry")?;
    if let Some(catalog) = selection
        .get("source_catalog")
        .filter(|value| !value.is_null())
    {
        expires = expires.min(
            catalog["catalog_expires_unix_seconds"]
                .as_u64()
                .context("serving_loop_catalog_expiry")?,
        );
    }
    if let Some(validation) = record.get("validation").filter(|value| !value.is_null()) {
        expires = expires.min(
            validation["source_expires_unix_seconds"]
                .as_u64()
                .context("serving_loop_validation_expiry")?,
        );
    }
    let root = store.cycle_path(sequence)?;
    let bytes = read_file(&root.join("evaluation.json"), 64 * 1024)?;
    let provenance = json!({"kind":"approved_local_successor","approved":true,"sequence":sequence,
        "evaluation_sha256":hex::encode(Sha256::digest(bytes)),"quality_policy":record["policy"],
        "source_manifest_id":record["source_manifest_id"],"source_publisher_key":record["source_publisher_key"],
        "adapter_files":record["candidate_adapter"],"expires_unix_seconds":expires,
        "general_quality_proven":false,"network_authority_claimed":false});
    Ok(Some((root.join("training/adapter"), expires, provenance)))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;
    use crate::compute::train_loop::{Cycle, Phase};

    #[test]
    fn only_selected_approved_local_cycle_is_exportable_with_original_source_expiry() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(&directory.path().join("loop"), &json!({}), false).unwrap();
        let mut state = State::new(1);
        assert!(local_candidate(&store, &state).unwrap().is_none());
        for (sequence, approved) in [(1, true), (2, false)] {
            evaluation::fixture(&store, sequence, approved);
            state.cycles.push(Cycle {
                sequence,
                source: 0,
                phase: if approved {
                    Phase::Complete
                } else {
                    Phase::Rejected
                },
                snapshot: Some(store.snapshot_cycle(sequence).unwrap()),
                training: None,
                publication: None,
                next_publication_attempt: 0,
            });
        }
        // A later rejected cycle cannot supersede the selected predecessor.
        state.latest = Some(1);
        let (adapter, expires, proof) = local_candidate(&store, &state).unwrap().unwrap();
        assert_eq!(
            adapter,
            store.cycle_path(1).unwrap().join("training/adapter")
        );
        assert_eq!(proof["sequence"], 1);
        assert_eq!(proof["approved"], true);
        assert_eq!(
            expires,
            store.read_cycle_json(1, "result.json").unwrap()["source_expires_unix_seconds"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            proof["adapter_files"],
            store.read_cycle_json(1, "evaluation.json").unwrap()["candidate_adapter"]
        );
        // Even a corrupted local pointer cannot turn a rejection into authority.
        state.latest = Some(2);
        assert!(local_candidate(&store, &state).is_err());
    }
}
