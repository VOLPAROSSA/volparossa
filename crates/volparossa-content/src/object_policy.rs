//! Shared live enforcement for independently verified, exact-object decisions.
//!
//! This is the enforcement layer, not a signature verifier or content classifier.
//! Its owner must durably verify a decision against its independently configured
//! authority before installing a rule. An absent rule does not constitute approval:
//! the object remains subject to the caller's existing publication authorization.
//! Known objects remain withheld after expiry or policy-epoch change. Registries and
//! in-flight transfers share this state instead of copying an obsolete decision.

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::watch;

use crate::VerifiedManifest;

/// Maximum exact object decisions retained by one live gate; saturation never evicts a denial.
pub const MAX_OBJECT_POLICY_RULES: usize = 1024;

/// Exact publication identity, not a domain, URL, publisher-wide ban or chunk blacklist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectSubject {
    /// Independently verified original publisher.
    pub publisher_key: [u8; 32],
    /// Exact signed native-manifest identity.
    pub manifest_id: [u8; 32],
    /// Complete reconstructed object digest.
    pub object_sha256: [u8; 32],
}

impl ObjectSubject {
    /// Bind all identity fields to an independently verified native manifest.
    pub fn from_manifest(manifest: &VerifiedManifest) -> Self {
        Self {
            publisher_key: *manifest.publisher(),
            manifest_id: *manifest.manifest_id(),
            object_sha256: *manifest.object_sha256(),
        }
    }
}

/// A verified caller's current exact-object rule. `allow=false` includes contested decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectRule {
    /// Exact original publication.
    pub subject: ObjectSubject,
    /// Current threshold-verified destination-policy epoch, not a newly trusted key set.
    pub policy_hash: [u8; 32],
    /// Whether the original quorum authorizes access to this exact object.
    pub allow: bool,
    /// Original decision deadline in Unix milliseconds; reads never extend it.
    pub expires_at_ms: u64,
}

#[derive(Default)]
struct State {
    epoch: Option<[u8; 32]>,
    rules: BTreeMap<[u8; 32], ObjectRule>,
}

/// Cloneable live gate shared by registry snapshots, downloads and active serving sessions.
#[derive(Clone)]
pub struct ObjectPolicyGate {
    state: Arc<RwLock<State>>,
    changed: Arc<watch::Sender<u64>>,
}

impl Default for ObjectPolicyGate {
    fn default() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            state: Arc::new(RwLock::new(State::default())),
            changed: Arc::new(changed),
        }
    }
}

impl ObjectPolicyGate {
    /// Currently installed independently verified epoch; absent or poisoned means unavailable.
    pub fn epoch(&self) -> Option<[u8; 32]> {
        self.state.read().ok().and_then(|state| state.epoch)
    }

    /// Set the independently verified active epoch, or withdraw it without forgetting objects.
    pub fn set_epoch(&self, epoch: Option<[u8; 32]>) {
        if let Ok(mut state) = self.state.write() {
            state.epoch = epoch;
        }
        self.notify();
    }

    /// Install a decision only after the owning service has durably checked its authority/floor.
    ///
    /// # Errors
    /// Rejects saturation or poisoned state. An existing entry is never silently evicted.
    pub fn install(&self, rule: ObjectRule) -> Result<(), ObjectPolicyError> {
        let mut state = self.state.write().map_err(|_| ObjectPolicyError)?;
        if state.rules.len() >= MAX_OBJECT_POLICY_RULES
            && !state.rules.contains_key(&rule.subject.manifest_id)
        {
            return Err(ObjectPolicyError);
        }
        state.rules.insert(rule.subject.manifest_id, rule);
        drop(state);
        self.notify();
        Ok(())
    }

    /// Whether this exact native publication is not withheld by the current gate.
    /// This does not replace its signature, expiry, destination or source-eligibility checks.
    pub fn allows(&self, manifest: &VerifiedManifest, now_ms: u64) -> bool {
        self.allows_subject(ObjectSubject::from_manifest(manifest), now_ms)
    }

    /// Check at the current wall time, failing closed if a valid time is unavailable.
    pub fn allows_now(&self, manifest: &VerifiedManifest) -> bool {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_millis()).ok())
            .is_some_and(|now| self.allows(manifest, now))
    }

    fn allows_subject(&self, subject: ObjectSubject, now_ms: u64) -> bool {
        let Ok(state) = self.state.read() else {
            return false;
        };
        let Some(rule) = state.rules.get(&subject.manifest_id) else {
            return true;
        };
        rule.subject == subject
            && rule.allow
            && state.epoch == Some(rule.policy_hash)
            && now_ms < rule.expires_at_ms
    }

    /// Resolve as soon as this object is withheld, including by expiry or epoch withdrawal.
    /// Use as the cancellation branch around an actual transfer, not just before registration.
    pub async fn wait_until_withheld(&self, manifest: &VerifiedManifest) {
        let subject = ObjectSubject::from_manifest(manifest);
        let mut changed = self.changed.subscribe();
        loop {
            let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
                return;
            };
            let Ok(now_ms) = u64::try_from(now.as_millis()) else {
                return;
            };
            if !self.allows_subject(subject, now_ms) {
                return;
            }
            let expiry = match self.state.read() {
                Ok(state) => state
                    .rules
                    .get(&subject.manifest_id)
                    .map(|rule| rule.expires_at_ms),
                Err(_) => return,
            };
            if let Some(expires) = expiry {
                // Recheck wall time at least once per second, including clock adjustments.
                let wait = Duration::from_millis(expires.saturating_sub(now_ms).clamp(1, 1000));
                tokio::select! {
                    () = tokio::time::sleep(wait) => {},
                    result = changed.changed() => if result.is_err() { return; },
                }
            } else if changed.changed().await.is_err() {
                return;
            }
        }
    }

    fn notify(&self) {
        self.changed
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

/// The bounded gate could not install a rule; callers must not claim it was enforced.
#[derive(Debug, thiserror::Error)]
#[error("object policy state unavailable or full")]
pub struct ObjectPolicyError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_rules_retain_withholding_on_expiry_epoch_change_and_identity_mismatch() {
        let gate = ObjectPolicyGate::default();
        let old_snapshot = gate.clone();
        let subject = ObjectSubject {
            publisher_key: [1; 32],
            manifest_id: [2; 32],
            object_sha256: [3; 32],
        };
        let rule = ObjectRule {
            subject,
            policy_hash: [4; 32],
            allow: true,
            expires_at_ms: 100,
        };
        assert!(gate.allows_subject(subject, 1)); // Unmanaged is not a policy approval.
        gate.set_epoch(Some([4; 32]));
        gate.install(rule).unwrap();
        assert!(old_snapshot.allows_subject(subject, 99));
        assert!(!old_snapshot.allows_subject(subject, 100));
        gate.set_epoch(Some([5; 32]));
        assert!(!old_snapshot.allows_subject(subject, 99));
        gate.set_epoch(Some([4; 32]));
        assert!(!gate.allows_subject(
            ObjectSubject {
                object_sha256: [6; 32],
                ..subject
            },
            99
        ));
        gate.install(ObjectRule {
            allow: false,
            ..rule
        })
        .unwrap();
        assert!(!old_snapshot.allows_subject(subject, 1));
        assert!(!old_snapshot.allows_subject(subject, 1000));
        gate.set_epoch(None);
        assert!(!old_snapshot.allows_subject(subject, 1));
    }
}
