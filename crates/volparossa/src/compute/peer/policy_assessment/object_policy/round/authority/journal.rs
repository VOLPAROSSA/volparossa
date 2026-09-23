//! Fsynced reservation before signing; retries may reuse a body but not replace its revision.
//! This protects automatic owners of one configured identity, not malicious key duplication.

use super::{open_output, sha, storage, task};
use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::path::Path;
use volparossa_policy::object::SignedObjectDecision;

const MAX_RECORDS: usize = 256;
const MAX_BYTES: u64 = 256 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    authority_key: String,
    records: Vec<Record>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    epoch: String,
    subject: String,
    revision: u64,
    proposal_sha256: String,
    expires_at_ms: u64,
    retire_after_ms: u64,
}

impl State {
    fn record(&mut self, proposal: &SignedObjectDecision, at: u64) -> Result<()> {
        ensure!(
            self.version == 1 && self.records.len() <= MAX_RECORDS,
            "policy_authority_journal_bound"
        );
        let body = proposal.body();
        ensure!(
            body.issued_at_ms <= at && at < body.expires_at_ms,
            "policy_authority_journal_expiry"
        );
        let unsigned = SignedObjectDecision::new(body.clone())?.encode()?;
        ensure!(
            proposal.encode()? == unsigned,
            "policy_authority_journal_requires_unsigned"
        );
        let epoch = hex::encode(body.policy_hash);
        let subject = sha(&[
            body.subject.publisher_key,
            body.subject.manifest_id,
            body.subject.object_sha256,
        ]
        .concat());
        let proposal_sha256 = sha(&unsigned);
        self.records.retain(|record| record.retire_after_ms > at);
        if let Some(previous) = self
            .records
            .iter_mut()
            .find(|record| record.epoch == epoch && record.subject == subject)
        {
            ensure!(
                body.decision_revision >= previous.revision,
                "policy_authority_revision_rollback"
            );
            if body.decision_revision == previous.revision {
                ensure!(
                    previous.proposal_sha256 == proposal_sha256
                        && previous.expires_at_ms == body.expires_at_ms,
                    "policy_authority_equivocation_refused"
                );
                return Ok(());
            }
            let retire_after_ms = previous.retire_after_ms.max(body.expires_at_ms);
            *previous = Record {
                epoch,
                subject,
                revision: body.decision_revision,
                proposal_sha256,
                expires_at_ms: body.expires_at_ms,
                retire_after_ms,
            };
        } else {
            ensure!(
                self.records.len() < MAX_RECORDS,
                "policy_authority_journal_full"
            );
            self.records.push(Record {
                epoch,
                subject,
                revision: body.decision_revision,
                proposal_sha256,
                expires_at_ms: body.expires_at_ms,
                retire_after_ms: body.expires_at_ms,
            });
        }
        Ok(())
    }
}

pub(super) fn reserve(
    identity: &Path,
    key: &VerifyingKey,
    proposal: &SignedObjectDecision,
    at: u64,
) -> Result<()> {
    let filename = identity
        .file_name()
        .context("policy_authority_identity_filename")?;
    let mut journal_name = filename.to_os_string();
    journal_name.push(".policy-round-journal");
    let root = identity.with_file_name(journal_name);
    let _lock = open_output(&root)?;
    let path = root.join("journal.json");
    let authority_key = hex::encode(key.as_bytes());
    let mut state: State = if storage::exists(&path)? {
        serde_json::from_slice(&storage::read(&path, MAX_BYTES)?)?
    } else {
        State {
            version: 1,
            authority_key: authority_key.clone(),
            records: Vec::new(),
        }
    };
    ensure!(
        state.authority_key == authority_key,
        "policy_authority_journal_identity_changed"
    );
    state.record(proposal, at)?;
    let bytes = serde_json::to_vec(&state)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "policy_authority_journal_bound"
    );
    task::write_bytes(&path, &bytes, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_policy::object::{ObjectDecision, ObjectOutcome, ObjectSubject};

    fn proposal(revision: u64, nonce: u8) -> SignedObjectDecision {
        SignedObjectDecision::new(ObjectDecision {
            policy_hash: [1; 32],
            policy_version: 1,
            decision_revision: revision,
            subject: ObjectSubject {
                publisher_key: ed25519_dalek::SigningKey::from_bytes(&[2; 32])
                    .verifying_key()
                    .to_bytes(),
                manifest_id: [3; 32],
                object_sha256: [4; 32],
            },
            framework_sha256: [5; 32],
            evidence_sha256: [6; 32],
            outcome: ObjectOutcome::Undetermined,
            issued_at_ms: 1000,
            expires_at_ms: 2000,
            nonce: [nonce; 32],
        })
        .unwrap()
    }

    #[test]
    fn same_body_retries_but_conflict_and_rollback_are_refused() {
        let mut state = State {
            version: 1,
            authority_key: String::new(),
            records: vec![],
        };
        state.record(&proposal(1, 1), 1500).unwrap();
        state.record(&proposal(1, 1), 1500).unwrap();
        assert_eq!(state.records.len(), 1);
        assert!(state.record(&proposal(1, 2), 1500).is_err());
        state.record(&proposal(2, 2), 1500).unwrap();
        assert!(state.record(&proposal(1, 1), 1500).is_err());
        assert!(state.record(&proposal(2, 2), 2000).is_err());
    }

    #[test]
    fn separately_enrolled_owners_of_same_identity_share_durable_reservation() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity = root.path().join("authority.key");
        let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]).verifying_key();
        reserve(&identity, &key, &proposal(1, 1), 1500).unwrap();
        reserve(&identity, &key, &proposal(1, 1), 1500).unwrap();
        assert!(reserve(&identity, &key, &proposal(1, 2), 1500).is_err());
        let different = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key();
        assert!(reserve(&identity, &different, &proposal(1, 1), 1500).is_err());
    }

    #[test]
    fn shorter_new_revision_keeps_floor_while_an_old_signature_is_still_live() {
        let mut state = State {
            version: 1,
            authority_key: String::new(),
            records: vec![],
        };
        state.record(&proposal(1, 1), 1500).unwrap();
        let mut body = proposal(2, 2).body().clone();
        body.expires_at_ms = 1700;
        state
            .record(&SignedObjectDecision::new(body).unwrap(), 1500)
            .unwrap();
        assert!(state.record(&proposal(1, 1), 1800).is_err());
    }
}
