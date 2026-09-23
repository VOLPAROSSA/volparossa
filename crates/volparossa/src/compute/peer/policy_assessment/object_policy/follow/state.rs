//! Bounded original authority and one durable pending handoff; no lease renewal on restart.

use serde::{Deserialize, Serialize};
use volparossa_content::{ChunkId, SignedManifest};
use volparossa_policy::{
    object::{
        MAX_OBJECT_DECISION_BYTES, SignedObjectDecision, VerifiedObjectDecision,
        verify_object_decision,
    },
    verify_manifest,
};

use super::{Options, PolicyContext, Result, Value, content, ensure, json, sha};

pub(super) const MAX_STATE_BYTES: usize = 3 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Pending,
    Applied,
    Expired,
    StaleEpoch,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub(super) phase: Phase,
    pub(super) observed_at_ms: u64,
    pub(super) manifest_hex: String,
    pub(super) decision_hex: String,
    pub(super) epoch_manifest_hex: String,
    pub(super) download_receipt: Value,
    pub(super) apply_receipt: Option<Value>,
}

pub(super) fn decode(text: &str, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        !text.is_empty() && text.len() <= maximum * 2 && text.len() % 2 == 0,
        "policy_follow_original_bound"
    );
    Ok(hex::decode(text)?)
}

impl Record {
    fn manifest(&self) -> Result<SignedManifest> {
        Ok(SignedManifest::decode(&decode(
            &self.manifest_hex,
            volparossa_content::MAX_MANIFEST_BYTES,
        )?)?)
    }
    pub(super) fn original_decision(&self) -> Result<SignedObjectDecision> {
        Ok(SignedObjectDecision::decode(&decode(
            &self.decision_hex,
            MAX_OBJECT_DECISION_BYTES,
        )?)?)
    }
    pub(super) fn wrapper_revision(&self) -> Result<u64> {
        // Decode does not authorize; historical/live callers verify the original first.
        let original = self.manifest()?;
        let publisher = ed25519_dalek::VerifyingKey::from_bytes(&original.publisher_key_hint())?;
        Ok(original
            .verify(&publisher, self.observed_at_ms / 1000)?
            .metadata()
            .revision)
    }
    pub(super) fn expired(&self, at: u64) -> Result<bool> {
        let original = self.manifest()?;
        let publisher = ed25519_dalek::VerifyingKey::from_bytes(&original.publisher_key_hint())?;
        let manifest = original.verify(&publisher, self.observed_at_ms / 1000)?;
        Ok(at / 1000 >= manifest.validity().expires
            || at >= self.original_decision()?.body().expires_at_ms)
    }
    pub(super) fn verify_live(
        &self,
        args: &Options,
        authority: &PolicyContext,
        at: u64,
    ) -> Result<VerifiedObjectDecision> {
        let raw = decode(&self.decision_hex, MAX_OBJECT_DECISION_BYTES)?;
        let decision = verify_object_decision(
            &raw,
            at,
            &authority.trust,
            authority.verification,
            &authority.manifest,
        )?;
        self.bind(args, &raw, &decision, at)?;
        Ok(decision)
    }
    fn historical(
        &self,
        args: &Options,
        authority: &PolicyContext,
    ) -> Result<VerifiedObjectDecision> {
        let epoch = verify_manifest(
            &decode(
                &self.epoch_manifest_hex,
                volparossa_policy::MAX_SIGNED_MANIFEST_BYTES,
            )?,
            self.observed_at_ms,
            &authority.trust,
            authority.verification,
        )?;
        let raw = decode(&self.decision_hex, MAX_OBJECT_DECISION_BYTES)?;
        let decision = verify_object_decision(
            &raw,
            self.observed_at_ms,
            &authority.trust,
            authority.verification,
            &epoch,
        )?;
        self.bind(args, &raw, &decision, self.observed_at_ms)?;
        let expected = receipt(&decision);
        ensure!(
            match self.phase {
                Phase::Applied => self.apply_receipt.as_ref() == Some(&expected),
                _ => self.apply_receipt.is_none(),
            },
            "policy_follow_original_receipt_changed"
        );
        Ok(decision)
    }
    fn bind(
        &self,
        args: &Options,
        raw: &[u8],
        decision: &VerifiedObjectDecision,
        at: u64,
    ) -> Result<()> {
        let manifest = self.manifest()?.verify(&args.publisher_key, at / 1000)?;
        let subject = &decision.body().subject;
        let chunks = manifest.chunks();
        ensure!(
            manifest.metadata().name == args.name
                && manifest.metadata().revision >= args.min_revision
                && manifest.metadata().content_type == content::POLICY_DECISION_CONTENT_TYPE
                && manifest.length() == raw.len() as u64
                && hex::encode(manifest.object_sha256()) == sha(raw)
                && chunks.len() == 1
                && chunks[0].id() == &ChunkId::digest(raw)
                && chunks[0].length() as usize == raw.len()
                && manifest.validity().expires <= decision.body().expires_at_ms / 1000
                && subject.publisher_key == args.subject_publisher_key.to_bytes()
                && subject.manifest_id == args.subject_manifest_id
                && subject.object_sha256 == args.subject_sha256
                && decision.body().framework_sha256 == args.framework_sha256,
            "policy_follow_original_binding_changed"
        );
        ensure!(
            self.download_receipt["operation"] == "named_content_download"
                && self.download_receipt["publisher_key"]
                    == hex::encode(args.publisher_key.as_bytes())
                && self.download_receipt["name"] == args.name
                && self.download_receipt["manifest_id"] == hex::encode(manifest.manifest_id())
                && self.download_receipt["bytes"] == raw.len() as u64
                && self.download_receipt["sha256"] == sha(raw)
                && self.download_receipt["cache_only"] == false,
            "policy_follow_original_download_changed"
        );
        Ok(())
    }
}

fn receipt(decision: &VerifiedObjectDecision) -> Value {
    let body = decision.body();
    json!({"version":1,"manifest_id":body.subject.manifest_id.to_vec(),
        "decision_hash":decision.decision_hash().to_vec(),"decision_revision":body.decision_revision,
        "policy_hash":body.policy_hash.to_vec(),"outcome":body.outcome as i32})
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Poll {
    completed_at_ms: u64,
    outcome: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    version: u32,
    completed_polls: u64,
    confirmed_applications: u64,
    last_poll: Option<Poll>,
    pub(super) latest: Option<Record>,
    applied: Option<Record>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            completed_polls: 0,
            confirmed_applications: 0,
            last_poll: None,
            latest: None,
            applied: None,
        }
    }
}
impl State {
    pub(super) fn validate(&self, args: &Options, authority: &PolicyContext) -> Result<()> {
        ensure!(
            self.version == 1
                && (self.completed_polls == 0) == self.last_poll.is_none()
                && (self.confirmed_applications == 0) == self.applied.is_none(),
            "policy_follow_state_invalid"
        );
        if let Some(poll) = &self.last_poll {
            ensure!(
                poll.completed_at_ms > 0
                    && matches!(
                        poll.outcome.as_str(),
                        "fetch_failed" | "rejected" | "unchanged" | "pending"
                    ),
                "policy_follow_poll_invalid"
            );
        }
        if let Some(current) = &self.latest {
            current.historical(args, authority)?;
        }
        if let Some(applied) = &self.applied {
            ensure!(
                applied.phase == Phase::Applied,
                "policy_follow_applied_phase"
            );
            applied.historical(args, authority)?;
            let latest = self
                .latest
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("policy_follow_latest_missing"))?;
            monotone(applied, latest)?;
        }
        if self
            .latest
            .as_ref()
            .is_some_and(|record| record.phase == Phase::Applied)
        {
            ensure!(
                self.latest == self.applied,
                "policy_follow_applied_checkpoint_changed"
            );
        }
        Ok(())
    }
    pub(super) fn accepts(
        &self,
        args: &Options,
        authority: &PolicyContext,
        new: &Record,
    ) -> Result<bool> {
        new.historical(args, authority)?;
        if let Some(previous) = &self.latest {
            previous.historical(args, authority)?;
            monotone(previous, new)?;
            if previous.manifest_hex == new.manifest_hex {
                ensure!(
                    previous.decision_hex == new.decision_hex,
                    "policy_follow_original_bytes_changed"
                );
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub(super) fn poll_completed(&mut self, at: u64, outcome: &str) -> Result<()> {
        self.completed_polls = self
            .completed_polls
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("policy_follow_poll_overflow"))?;
        self.last_poll = Some(Poll {
            completed_at_ms: at,
            outcome: outcome.into(),
        });
        Ok(())
    }
    pub(super) fn applied(&mut self, receipt: Value) -> Result<()> {
        let original = self
            .latest
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("policy_follow_pending_missing"))?;
        ensure!(
            original.phase == Phase::Pending,
            "policy_follow_pending_phase"
        );
        original.phase = Phase::Applied;
        original.apply_receipt = Some(receipt);
        self.applied = Some(original.clone());
        self.confirmed_applications = self
            .confirmed_applications
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("policy_follow_apply_overflow"))?;
        Ok(())
    }
    pub(super) fn status(&self, raw: &[u8]) -> Result<Value> {
        let mut value = json!({"version":1,"scope":"selected_channel_exact_object","state_sha256":sha(raw),
            "completed_polls":self.completed_polls,"confirmed_applications":self.confirmed_applications,
            "last_poll":self.last_poll,"pending":self.latest.as_ref().is_some_and(|record| record.phase == Phase::Pending),
            "applied":self.applied.is_some(),"applied_is_historical_receipt":true});
        if let Some(applied) = &self.applied {
            let decision = applied.original_decision()?;
            value["applied_manifest_id"] = sha(&decode(
                &applied.manifest_hex,
                volparossa_content::MAX_MANIFEST_BYTES,
            )?)
            .into();
            let decision_hash: [u8; 32] = serde_json::from_value(
                applied
                    .apply_receipt
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("policy_follow_receipt_missing"))?["decision_hash"]
                    .clone(),
            )?;
            value["decision_hash"] = hex::encode(decision_hash).into();
            value["decision_revision"] = decision.body().decision_revision.into();
            value["expires_at_ms"] = decision.body().expires_at_ms.into();
        }
        Ok(value)
    }
}

fn monotone(old: &Record, new: &Record) -> Result<()> {
    let old_revision = old.wrapper_revision()?;
    let new_revision = new.wrapper_revision()?;
    let old_decision = old.original_decision()?;
    let new_decision = new.original_decision()?;
    ensure!(
        new_revision >= old_revision
            && (new_revision != old_revision || new.manifest_hex == old.manifest_hex)
            && new_decision.body().decision_revision >= old_decision.body().decision_revision
            && (new_decision.body().decision_revision != old_decision.body().decision_revision
                || new_decision.body() == old_decision.body()),
        "policy_follow_revision_conflict_or_rollback"
    );
    Ok(())
}
