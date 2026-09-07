//! Conservative admission for optional cache work, not proof of spare ISP/radio capacity.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::watch;
use volparossa_config::Config;
use volparossa_linux_uapi::{InterfaceTraffic, observe_interface_traffic};

pub(super) struct Foreground {
    active: AtomicUsize,
    changed: watch::Sender<u64>,
}

pub(super) struct ForegroundLease(Arc<Foreground>);

impl Default for Foreground {
    fn default() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            active: AtomicUsize::new(0),
            changed,
        }
    }
}

impl Foreground {
    pub(super) fn enter(self: &Arc<Self>) -> ForegroundLease {
        self.active.fetch_add(1, Ordering::AcqRel);
        self.changed
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        ForegroundLease(Arc::clone(self))
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub(super) fn active(&self) -> bool {
        self.active.load(Ordering::Acquire) != 0
    }
}

impl Drop for ForegroundLease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0
            .changed
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

/// Explicitly configured link capacities bound a small average budget; they are not
/// discovered throughput. Unknown accounting, drops or meaningful activity close admission.
pub(super) struct IdleBudget {
    interfaces: Vec<String>,
    receive_rate: u64,
    transmit_rate: u64,
}

impl IdleBudget {
    pub(super) fn new(config: &Config) -> Option<Self> {
        if !config.sharing.enabled || !config.download_sharing.enabled {
            return None;
        }
        let mut interfaces = vec![
            config.sharing.interface.clone(),
            config.download_sharing.interface.clone(),
        ];
        interfaces.sort_unstable();
        interfaces.dedup();
        let receive_rate = u64::from(config.download_sharing.total_download_mbps) * 125_000;
        let transmit_rate = u64::from(config.sharing.total_upload_mbps) * 125_000;
        if receive_rate == 0 || transmit_rate == 0 {
            return None;
        }
        Some(Self {
            interfaces,
            receive_rate,
            transmit_rate,
        })
    }

    pub(super) fn cooldown(&self, wire_bytes: u64) -> Duration {
        let rate = (self.receive_rate.min(self.transmit_rate) / 100).max(1);
        // Include a conservative transport-overhead allowance. A configured average ceiling
        // and a quiet sample still do not establish an absolute no-interference guarantee.
        Duration::from_secs(wire_bytes.saturating_mul(2).div_ceil(rate).max(5))
    }

    async fn sample(&self) -> Option<Vec<InterfaceTraffic>> {
        let interfaces = self.interfaces.clone();
        tokio::task::spawn_blocking(move || {
            interfaces
                .iter()
                .map(|name| observe_interface_traffic(name).ok().flatten())
                .collect::<Option<Vec<_>>>()
        })
        .await
        .ok()
        .flatten()
    }

    pub(super) async fn quiet(&self) -> bool {
        let Some(before) = self.sample().await else {
            return false;
        };
        let started = std::time::Instant::now();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let Some(after) = self.sample().await else {
            return false;
        };
        quiet_delta(
            &before,
            &after,
            started.elapsed(),
            self.receive_rate,
            self.transmit_rate,
        )
    }

    /// The caller supplies the job deadline and foreground cancellation. A busy sample
    /// pauses optional work; it must not permanently consume a just-finished contact.
    pub(super) async fn wait_until_quiet(&self) {
        while !self.quiet().await {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

fn quiet_delta(
    before: &[InterfaceTraffic],
    after: &[InterfaceTraffic],
    elapsed: Duration,
    receive_rate: u64,
    transmit_rate: u64,
) -> bool {
    if before.is_empty()
        || before.len() != after.len()
        || elapsed < Duration::from_millis(200)
        || elapsed > Duration::from_secs(2)
    {
        return false;
    }
    before.iter().zip(after).all(|(a, b)| {
        if a.ifindex != b.ifindex
            || a.receive_drops != b.receive_drops
            || a.transmit_drops != b.transmit_drops
        {
            return false;
        }
        let (Some(rx), Some(tx)) = (
            b.received.checked_sub(a.received),
            b.transmitted.checked_sub(a.transmitted),
        ) else {
            return false;
        };
        let threshold =
            |rate: u64| (u128::from(rate / 100) * elapsed.as_nanos() / 1_000_000_000).max(2048);
        u128::from(rx) <= threshold(receive_rate) && u128::from(tx) <= threshold(transmit_rate)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_copy_requires_fresh_quiet_non_dropping_same_interface_samples() {
        let first = InterfaceTraffic {
            ifindex: 7,
            received: 1000,
            transmitted: 2000,
            receive_drops: 0,
            transmit_drops: 0,
        };
        let quiet = InterfaceTraffic {
            received: 2000,
            transmitted: 3000,
            ..first
        };
        let elapsed = Duration::from_millis(500);
        assert!(quiet_delta(
            &[first],
            &[quiet],
            elapsed,
            12_500_000,
            12_500_000
        ));
        for bad in [
            InterfaceTraffic {
                received: 1_000_000,
                ..quiet
            },
            InterfaceTraffic {
                ifindex: 8,
                ..quiet
            },
            InterfaceTraffic {
                receive_drops: 1,
                ..quiet
            },
            InterfaceTraffic {
                transmitted: 0,
                ..quiet
            },
        ] {
            assert!(!quiet_delta(
                &[first],
                &[bad],
                elapsed,
                12_500_000,
                12_500_000
            ));
        }
        assert!(!quiet_delta(
            &[first],
            &[quiet],
            Duration::from_secs(3),
            12_500_000,
            12_500_000
        ));
    }

    #[tokio::test]
    async fn owner_activity_interrupts_even_if_owner_finishes_before_background_poll() {
        let state = Arc::new(Foreground::default());
        let mut background = state.subscribe();
        let first = state.enter();
        let second = state.enter();
        drop(first);
        assert!(state.active());
        drop(second);
        assert!(!state.active());
        background.changed().await.unwrap();
    }
}
