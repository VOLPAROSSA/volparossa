//! Bounded caller-bound RAM observations. No log, disk, peer identity or custody assertion.

mod timing;

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI32, Ordering},
    },
    time::Duration,
};

use tokio::time::Instant;
use volparossa_content::private_storage::{
    protocol::ProtocolError,
    wire::{
        WireError,
        bridge_observation::{self, Observer},
    },
};
use volparossa_local_control::{
    PrivateStorageDeadlineScope, PrivateStorageOutcome, PrivateStorageOutcomeCategory as Category,
    PrivateStorageOutcomeDeadline as Deadline, PrivateStorageOutcomePhase as Phase,
    PrivateStorageOutcomeStatus as Status,
};

use super::ContentError;

const CAPACITY: usize = 64;
const RETENTION: Duration = Duration::from_secs(120);
type Key = (u32, [u8; 16]);

enum Entry {
    Pending,
    Failed {
        expires: Instant,
        outcome: PrivateStorageOutcome,
    },
}

#[derive(Default)]
pub(crate) struct Outcomes(Mutex<BTreeMap<Key, Entry>>);

impl Outcomes {
    pub(super) fn begin(self: &Arc<Self>, uid: u32, id: &[u8]) -> Result<Guard, ContentError> {
        let key = (uid, id.try_into().map_err(|_| ContentError::Invalid)?);
        let mut entries = self.0.lock().map_err(|_| ContentError::Unavailable)?;
        let now = Instant::now();
        entries
            .retain(|_, entry| !matches!(entry, Entry::Failed { expires, .. } if *expires <= now));
        if entries.contains_key(&key) {
            return Err(ContentError::Busy);
        }
        // Never evict active or unexpired observations, or make this best-effort
        // diagnostic cache a new storage-admission gate for older callers.
        let tracked = entries.len() < CAPACITY;
        if tracked {
            entries.insert(key, Entry::Pending);
        }
        Ok(Guard {
            owner: Arc::clone(self),
            key,
            tracked,
            phase: AtomicI32::new(Phase::Unobserved as i32),
            deadline: AtomicI32::new(Deadline::None as i32),
            category: AtomicI32::new(Category::Unobserved as i32),
            succeeded: false,
            finished: false,
            timing: timing::Progress::default(),
        })
    }

    pub(super) fn take(&self, uid: u32, id: &[u8]) -> Result<PrivateStorageOutcome, ContentError> {
        let key = (uid, id.try_into().map_err(|_| ContentError::Invalid)?);
        let mut entries = self.0.lock().map_err(|_| ContentError::Unavailable)?;
        match entries.get(&key) {
            None => Ok(status(Status::Missing)),
            Some(Entry::Pending) => Ok(status(Status::Pending)),
            Some(Entry::Failed { .. }) => {
                let Some(Entry::Failed { expires, outcome }) = entries.remove(&key) else {
                    unreachable!("same owned synchronous map entry")
                };
                Ok(if expires <= Instant::now() {
                    status(Status::Expired)
                } else {
                    outcome
                })
            }
        }
    }
}

fn status(status: Status) -> PrivateStorageOutcome {
    PrivateStorageOutcome {
        status: status as i32,
        phase: 0,
        category: 0,
        deadline: 0,
        append_timing: None,
    }
}

/// Lives outside every operation timeout. Drop records task cancellation before socket drop.
pub(super) struct Guard {
    owner: Arc<Outcomes>,
    key: Key,
    tracked: bool,
    phase: AtomicI32,
    deadline: AtomicI32,
    category: AtomicI32,
    succeeded: bool,
    finished: bool,
    timing: timing::Progress,
}

impl Guard {
    pub(super) fn start_operation(&self, started: Option<Instant>) {
        self.timing.start_operation(started);
    }

    pub(super) fn enter(&self, phase: Phase) {
        self.timing.phase(phase);
        self.phase.store(phase as i32, Ordering::Relaxed);
    }

    pub(super) fn wire_error(&self, error: &WireError) {
        self.timing.fail();
        let category = match error {
            WireError::Io(_) => Category::Io,
            WireError::Protocol(ProtocolError::Unauthorized) => Category::Auth,
            WireError::Protocol(ProtocolError::Invalid) | WireError::Invalid => Category::Invalid,
            WireError::Protocol(ProtocolError::Expired) => Category::Expired,
            WireError::Protocol(ProtocolError::Entropy) => Category::Entropy,
            WireError::Busy => Category::Busy,
            WireError::Store => Category::Store,
            WireError::Timeout => Category::Timeout,
        };
        self.category.store(category as i32, Ordering::Relaxed);
    }

    pub(super) fn cancelled(&self) {
        self.timing.fail();
        self.category
            .store(Category::Cancelled as i32, Ordering::Relaxed);
        self.deadline
            .store(Deadline::None as i32, Ordering::Relaxed);
    }

    pub(super) fn finish(
        mut self,
        result: &Result<(), ContentError>,
        outer: PrivateStorageDeadlineScope,
    ) {
        if result.is_err() {
            self.timing.fail();
        }
        self.finished = true;
        self.succeeded = result.is_ok();
        if self.succeeded {
            return;
        }
        if outer != PrivateStorageDeadlineScope::None {
            let deadline = match outer {
                PrivateStorageDeadlineScope::Operation => Deadline::Operation,
                PrivateStorageDeadlineScope::Exchange => Deadline::Exchange,
                PrivateStorageDeadlineScope::None => unreachable!(),
            };
            self.deadline.store(deadline as i32, Ordering::Relaxed);
            self.category
                .store(Category::Timeout as i32, Ordering::Relaxed);
        } else if self.category.load(Ordering::Relaxed) == Category::Unobserved as i32 {
            let category = match result {
                Err(ContentError::Invalid) => Category::Invalid,
                Err(ContentError::Busy) => Category::Busy,
                Err(
                    ContentError::Policy | ContentError::NameConflict | ContentError::NameRollback,
                ) => Category::Policy,
                _ => Category::Unavailable,
            };
            self.category.store(category as i32, Ordering::Relaxed);
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.timing.fail();
        // Its key may have been admitted later after another query freed capacity.
        // An untracked operation must never touch that newer operation's entry.
        if !self.tracked {
            return;
        }
        let Ok(mut entries) = self.owner.0.lock() else {
            return;
        };
        let phase = self.phase.load(Ordering::Relaxed);
        if self.succeeded || phase == Phase::Unobserved as i32 {
            entries.remove(&self.key);
            return;
        }
        let category = if self.finished {
            self.category.load(Ordering::Relaxed)
        } else {
            Category::Cancelled as i32
        };
        let deadline = if self.finished {
            self.deadline.load(Ordering::Relaxed)
        } else {
            Deadline::None as i32
        };
        entries.insert(
            self.key,
            Entry::Failed {
                expires: Instant::now() + RETENTION,
                outcome: PrivateStorageOutcome {
                    status: Status::Observed as i32,
                    phase,
                    category,
                    deadline,
                    append_timing: self.timing.detail(phase),
                },
            },
        );
    }
}

impl Observer for Guard {
    fn phase(&self, phase: bridge_observation::Phase) {
        use bridge_observation::Phase as Wire;
        self.enter(match phase {
            Wire::LocalRequestRead => Phase::LocalRequestRead,
            Wire::LocalRequestVerify => Phase::LocalRequestVerify,
            Wire::LocalPayloadRead => Phase::LocalPayloadRead,
            Wire::LocalPayloadVerify => Phase::LocalPayloadVerify,
            Wire::Admission => Phase::Admission,
            Wire::RemoteRequestVerify => Phase::RemoteRequestVerify,
            Wire::RemoteRequestWrite => Phase::RemoteRequestWrite,
            Wire::RemotePayloadWrite => Phase::RemotePayloadWrite,
            Wire::RemoteReceiptRead => Phase::RemoteReceiptRead,
            Wire::RemoteReceiptVerify => Phase::RemoteReceiptVerify,
            Wire::RemotePayloadRead => Phase::RemotePayloadRead,
            Wire::RemotePayloadVerify => Phase::RemotePayloadVerify,
            Wire::LocalReceiptWrite => Phase::LocalReceiptWrite,
            Wire::LocalPayloadWrite => Phase::LocalPayloadWrite,
        });
    }

    fn deadline(&self, deadline: bridge_observation::Deadline) {
        self.timing.fail();
        let deadline = match deadline {
            bridge_observation::Deadline::Bridge => Deadline::Bridge,
            bridge_observation::Deadline::RemoteWire => Deadline::RemoteWire,
        };
        self.deadline.store(deadline as i32, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests;
