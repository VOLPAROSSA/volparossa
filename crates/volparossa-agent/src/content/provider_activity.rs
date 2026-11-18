//! Four nonblocking, process-local activity slots. Never a protocol admission gate.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering::SeqCst},
    },
    time::{Duration, Instant},
};

use volparossa_content::provider::activity::{Observer, Stage};
use volparossa_local_control::{
    ContentProviderActivity, MAX_PROVIDER_SESSIONS, ProviderActivityElapsedBucket as Bucket,
    ProviderActivityGroup, ProviderActivityStage as WireStage, ProviderActivityState,
};

#[derive(Default)]
struct Slot {
    // Zero: free. One: being changed. Other values: unique stable revisions.
    revision: AtomicU64,
    entered_ns: AtomicU64,
    stage: AtomicI32,
}

pub(super) struct Activity {
    origin: Instant,
    revision: AtomicU64,
    writers: AtomicUsize,
    unavailable: AtomicBool,
    slots: [Slot; MAX_PROVIDER_SESSIONS],
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            revision: AtomicU64::new(2),
            writers: AtomicUsize::new(0),
            unavailable: AtomicBool::new(false),
            slots: std::array::from_fn(|_| Slot::default()),
        }
    }
}

impl Activity {
    /// Allocate before spawning the session, so even an unpolled future owns its guard.
    pub(super) fn begin(self: &Arc<Self>) -> Session {
        self.writers.fetch_add(1, SeqCst);
        let index = self
            .slots
            .iter()
            .position(|slot| slot.revision.compare_exchange(0, 1, SeqCst, SeqCst).is_ok());
        if let Some(index) = index {
            self.write(index, Stage::TlsHandshake);
        } else {
            // Unexpected overlap beyond the existing cap must not masquerade as four
            // complete observations, nor refuse an otherwise authorized protocol session.
            self.unavailable.store(true, SeqCst);
        }
        self.writers.fetch_sub(1, SeqCst);
        Session {
            activity: Arc::clone(self),
            index,
        }
    }

    fn write(&self, index: usize, stage: Stage) {
        let slot = &self.slots[index];
        slot.revision.store(1, SeqCst);
        let revision = self.revision.fetch_add(1, SeqCst);
        let Ok(elapsed) = u64::try_from(self.origin.elapsed().as_nanos()) else {
            self.unavailable.store(true, SeqCst);
            return;
        };
        if revision < 2 || revision == u64::MAX {
            // Wraparound cannot reuse a seemingly current revision. Unavailability is
            // sticky; even this unreachable lifetime limit never affects serving.
            self.unavailable.store(true, SeqCst);
            return;
        }
        slot.entered_ns.store(elapsed, SeqCst);
        slot.stage.store(wire_stage(stage) as i32, SeqCst);
        slot.revision.store(revision, SeqCst);
    }

    pub(super) fn snapshot(&self) -> ContentProviderActivity {
        let Ok(now) = u64::try_from(self.origin.elapsed().as_nanos()) else {
            return ContentProviderActivity::unavailable();
        };
        self.snapshot_at(now)
    }

    fn snapshot_at(&self, now: u64) -> ContentProviderActivity {
        if self.unavailable.load(SeqCst) || self.writers.load(SeqCst) != 0 {
            return ContentProviderActivity::unavailable();
        }
        let revision = self.revision.load(SeqCst);
        let mut groups: Vec<ProviderActivityGroup> = Vec::with_capacity(MAX_PROVIDER_SESSIONS);
        let mut active = 0;
        for slot in &self.slots {
            let before = slot.revision.load(SeqCst);
            if before == 0 {
                continue;
            }
            if before == 1 {
                return ContentProviderActivity::unavailable();
            }
            let stage = slot.stage.load(SeqCst);
            let Some(elapsed) = now.checked_sub(slot.entered_ns.load(SeqCst)) else {
                return ContentProviderActivity::unavailable();
            };
            let elapsed_bucket = bucket(Duration::from_nanos(elapsed)) as i32;
            if before != slot.revision.load(SeqCst) {
                return ContentProviderActivity::unavailable();
            }
            active += 1;
            if let Some(group) = groups
                .iter_mut()
                .find(|group| group.stage == stage && group.elapsed_bucket == elapsed_bucket)
            {
                group.count += 1;
            } else {
                groups.push(ProviderActivityGroup {
                    stage,
                    elapsed_bucket,
                    count: 1,
                });
            }
        }
        if self.revision.load(SeqCst) != revision
            || self.writers.load(SeqCst) != 0
            || self.unavailable.load(SeqCst)
        {
            return ContentProviderActivity::unavailable();
        }
        groups.sort_unstable_by_key(|group| (group.stage, group.elapsed_bucket));
        let snapshot = ContentProviderActivity {
            version: 1,
            state: ProviderActivityState::Observed as i32,
            active_sessions: Some(active),
            groups,
        };
        if snapshot.validate().is_err() {
            return ContentProviderActivity::unavailable();
        }
        snapshot
    }
}

/// Move-only ownership; dropping a cancelled future clears precisely its own slot.
pub(super) struct Session {
    activity: Arc<Activity>,
    index: Option<usize>,
}

impl Observer for Session {
    fn enter(&self, stage: Stage) {
        if let Some(index) = self.index {
            self.activity.writers.fetch_add(1, SeqCst);
            self.activity.write(index, stage);
            self.activity.writers.fetch_sub(1, SeqCst);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(index) = self.index {
            self.activity.writers.fetch_add(1, SeqCst);
            let revision = self.activity.revision.fetch_add(1, SeqCst);
            if revision < 2 || revision == u64::MAX {
                self.activity.unavailable.store(true, SeqCst);
            }
            self.activity.slots[index].revision.store(0, SeqCst);
            self.activity.writers.fetch_sub(1, SeqCst);
        }
    }
}

fn wire_stage(stage: Stage) -> WireStage {
    match stage {
        Stage::TlsHandshake => WireStage::TlsHandshake,
        Stage::RegistrySnapshot => WireStage::RegistrySnapshot,
        Stage::SelectorRead => WireStage::SelectorRead,
        Stage::StorageGrantReadVerify => WireStage::StorageGrantReadVerify,
        Stage::StorageChallengeWriteFlush => WireStage::StorageChallengeWriteFlush,
        Stage::StorageRequestReadVerify => WireStage::StorageRequestReadVerify,
        Stage::StorageOperation => WireStage::StorageOperation,
        Stage::OtherProtocol => WireStage::OtherProtocol,
        Stage::Closing => WireStage::Closing,
    }
}

fn bucket(elapsed: Duration) -> Bucket {
    match elapsed.as_secs() {
        0 => Bucket::Under1s,
        1..=4 => Bucket::From1To5s,
        5..=14 => Bucket::From5To15s,
        15..=29 => Bucket::From15To30s,
        30..=59 => Bucket::From30To60s,
        60..=89 => Bucket::From60To90s,
        90..=119 => Bucket::From90To120s,
        _ => Bucket::AtLeast120s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grouped_snapshot(activity: &Activity) -> ContentProviderActivity {
        // This single-threaded fixture controls age; grouping must not depend on scheduling.
        for slot in &activity.slots {
            slot.entered_ns.store(0, SeqCst);
        }
        activity.snapshot_at(0)
    }

    #[test]
    fn four_slots_aggregate_and_drop_only_their_own_session() {
        let activity = Arc::new(Activity::default());
        let mut sessions: Vec<_> = (0..MAX_PROVIDER_SESSIONS)
            .map(|_| activity.begin())
            .collect();
        let observed = grouped_snapshot(&activity);
        observed.validate().unwrap();
        assert_eq!(observed.active_sessions, Some(4));
        assert_eq!(observed.groups.len(), 1);
        assert_eq!(observed.groups[0].count, 4);
        sessions[0].enter(Stage::StorageGrantReadVerify);
        assert_eq!(grouped_snapshot(&activity).groups.len(), 2);
        drop(sessions.pop());
        assert_eq!(activity.snapshot().active_sessions, Some(3));
        let replacement = activity.begin();
        replacement.enter(Stage::StorageRequestReadVerify);
        drop(sessions);
        assert_eq!(activity.snapshot().active_sessions, Some(1));
        assert_eq!(
            activity.snapshot().groups[0].stage,
            WireStage::StorageRequestReadVerify as i32
        );
        drop(replacement);
        assert_eq!(activity.snapshot().active_sessions, Some(0));
    }

    #[test]
    fn unexpected_capacity_overlap_is_unavailable_not_a_protocol_rejection() {
        let activity = Arc::new(Activity::default());
        let sessions: Vec<_> = (0..=MAX_PROVIDER_SESSIONS)
            .map(|_| activity.begin())
            .collect();
        assert!(sessions.last().unwrap().index.is_none());
        assert_eq!(activity.snapshot(), ContentProviderActivity::unavailable());
        for session in &sessions {
            session.enter(Stage::StorageOperation);
        }
        drop(sessions);
        assert!(
            activity
                .slots
                .iter()
                .all(|slot| slot.revision.load(SeqCst) == 0)
        );
    }

    #[tokio::test]
    async fn unpolled_future_drop_and_joined_task_abort_clear_slots() {
        let activity = Arc::new(Activity::default());
        let session = activity.begin();
        let unpolled = async move {
            let _session = session;
            std::future::pending::<()>().await;
        };
        assert_eq!(activity.snapshot().active_sessions, Some(1));
        drop(unpolled);
        assert_eq!(activity.snapshot().active_sessions, Some(0));
        let session = activity.begin();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _session = session;
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(activity.snapshot().active_sessions, Some(0));
    }

    #[tokio::test]
    async fn snapshot_does_not_acquire_runtime_service_or_retrieval_locks() {
        let runtime =
            super::super::ContentRuntime::new(&volparossa_identity::Identity::generate()).unwrap();
        let _service = runtime.service.lock().await;
        let _retrieval = runtime.retrieval.lock().await;
        let _recent = runtime.recent.lock().await;
        let session = runtime.provider_activity.begin();
        session.enter(Stage::StorageChallengeWriteFlush);
        let observed = runtime.provider_activity();
        assert_eq!(observed.active_sessions, Some(1));
        assert_eq!(
            observed.groups[0].stage,
            WireStage::StorageChallengeWriteFlush as i32
        );
    }

    #[test]
    fn coarse_stage_age_boundaries_and_phase_reset_are_exact() {
        for (seconds, expected) in [
            (0, Bucket::Under1s),
            (1, Bucket::From1To5s),
            (5, Bucket::From5To15s),
            (15, Bucket::From15To30s),
            (30, Bucket::From30To60s),
            (60, Bucket::From60To90s),
            (90, Bucket::From90To120s),
            (120, Bucket::AtLeast120s),
        ] {
            assert_eq!(bucket(Duration::from_secs(seconds)), expected);
            if seconds != 0 {
                assert_ne!(
                    bucket(Duration::from_nanos(seconds * 1_000_000_000 - 1)),
                    expected
                );
            }
        }
        let activity = Arc::new(Activity::default());
        let session = activity.begin();
        let index = session.index.unwrap();
        let start = activity.slots[index].entered_ns.load(SeqCst);
        assert_eq!(
            activity.snapshot_at(start + 120_000_000_000).groups[0].elapsed_bucket,
            Bucket::AtLeast120s as i32
        );
        session.enter(Stage::StorageGrantReadVerify);
        let start = activity.slots[index].entered_ns.load(SeqCst);
        assert_eq!(
            activity.snapshot_at(start).groups[0].elapsed_bucket,
            Bucket::Under1s as i32
        );
    }

    #[test]
    fn changing_or_invalid_slots_are_unavailable_not_silent_zero() {
        let activity = Arc::new(Activity::default());
        let session = activity.begin();
        activity.writers.fetch_add(1, SeqCst);
        assert_eq!(activity.snapshot(), ContentProviderActivity::unavailable());
        activity.writers.fetch_sub(1, SeqCst);
        activity.slots[session.index.unwrap()]
            .stage
            .store(99, SeqCst);
        assert_eq!(activity.snapshot(), ContentProviderActivity::unavailable());
        session.enter(Stage::SelectorRead);
        activity.revision.store(u64::MAX, SeqCst);
        session.enter(Stage::StorageGrantReadVerify);
        assert_eq!(activity.snapshot(), ContentProviderActivity::unavailable());
        drop(session);
        assert_eq!(activity.slots[0].revision.load(SeqCst), 0);
    }
}
