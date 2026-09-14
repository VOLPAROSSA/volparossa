//! Receiver-wide owner priority for cooperative Exit-to-Relay downloads.
//!
//! One explicitly configured interface and operator-known capacity, not an ISP speed estimate.
//! Only controlled `RelayExit` receive traffic is subtracted. Own Client traffic and unsupported
//! receive directions remain owner/unmanaged load. There is no ingress policing here.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use rand_core::{OsRng, RngCore as _};
use volparossa_config::{DownloadSharingConfig, RolesConfig};
use volparossa_routing::{InstallReceiveAccounting, ReceiveAccountingSnapshot, WireguardRole};

use crate::helper::{HelperClient, HelperClientError, RuntimeBoundReceiveAccounting};

pub(crate) const DOWNLINK_SAMPLE_INTERVAL: Duration = Duration::from_millis(500);
const OWNER_IDLE_HOLD: Duration = Duration::from_secs(1);
const MAXIMUM_SAMPLE_GAP: Duration = Duration::from_secs(3);
const MAXIMUM_AGGREGATE_BURST_BYTES: u32 = 262_144;

pub(crate) struct DownlinkSharingRuntime {
    helper: HelperClient,
    owner: RuntimeBoundReceiveAccounting,
    controller: ReceiveBudgetController,
}

pub(crate) struct ReceiveBudgetWindow {
    pub(crate) available_bytes_per_second: u64,
    /// Current exact controlled receive legs on the configured interface, not arbitrary peers.
    pub(crate) paths: BTreeSet<(Vec<u8>, u32)>,
}

impl DownlinkSharingRuntime {
    pub(crate) async fn start(
        helper: HelperClient,
        config: &DownloadSharingConfig,
        roles: RolesConfig,
    ) -> Result<Option<Self>, HelperClientError> {
        if !config.enabled || !roles.relay {
            return Ok(None);
        }
        let mut runtime_id = [0; 16];
        OsRng.fill_bytes(&mut runtime_id);
        let owner = helper
            .install_receive_accounting(InstallReceiveAccounting {
                accounting_runtime_id: runtime_id.to_vec(),
                interface: config.interface.clone(),
            })
            .await?;
        let mut runtime = Self {
            helper,
            owner,
            controller: ReceiveBudgetController::new(config),
        };
        if let Err(error) = runtime.sample(&BTreeSet::new()).await {
            let _ = runtime.shutdown().await;
            return Err(error);
        }
        Ok(Some(runtime))
    }

    pub(crate) async fn sample(
        &mut self,
        controlled: &BTreeSet<(Vec<u8>, u32)>,
    ) -> Result<ReceiveBudgetWindow, HelperClientError> {
        let mut snapshot = self.helper.inspect_receive_accounting(&self.owner).await?;
        retain_controlled_rows(&mut snapshot, controlled)?;
        self.controller.observe(snapshot, Instant::now())
    }

    pub(crate) async fn shutdown(self) -> Result<(), HelperClientError> {
        self.helper.destroy_receive_accounting(&self.owner).await
    }
}

fn retain_controlled_rows(
    snapshot: &mut ReceiveAccountingSnapshot,
    controlled: &BTreeSet<(Vec<u8>, u32)>,
) -> Result<(), HelperClientError> {
    if controlled.len() > 128 {
        return Err(HelperClientError::Correlation);
    }
    snapshot.managed.retain(|row| {
        row.role != WireguardRole::RelayExit as i32
            || controlled.contains(&(row.route_context_id.clone(), row.path_id))
    });
    Ok(())
}

type ReceiveHistory = (Instant, u64, BTreeMap<(Vec<u8>, u32), u64>);

struct ReceiveBudgetController {
    capacity: u64,
    ceiling: u64,
    previous: Option<ReceiveHistory>,
    owner_busy_until: Option<Instant>,
}

impl ReceiveBudgetController {
    fn new(config: &DownloadSharingConfig) -> Self {
        Self {
            capacity: u64::from(config.total_download_mbps) * 125_000,
            ceiling: u64::from(config.contribution_download_ceiling_mbps) * 125_000,
            previous: None,
            owner_busy_until: None,
        }
    }

    fn observe(
        &mut self,
        snapshot: ReceiveAccountingSnapshot,
        now: Instant,
    ) -> Result<ReceiveBudgetWindow, HelperClientError> {
        let total = snapshot.total.ok_or(HelperClientError::Correlation)?.bytes;
        let mut controlled = BTreeMap::new();
        for row in snapshot.managed {
            if row.role == WireguardRole::RelayExit as i32 {
                let bytes = row.counters.ok_or(HelperClientError::Correlation)?.bytes;
                controlled.insert((row.route_context_id, row.path_id), bytes);
            }
        }
        let mut window = ReceiveBudgetWindow {
            available_bytes_per_second: 0,
            paths: controlled.keys().cloned().collect(),
        };
        let old = self.previous.replace((now, total, controlled.clone()));
        let Some((previous_time, previous_total, previous_controlled)) = old else {
            return Ok(window);
        };
        let Some(elapsed) = now.checked_duration_since(previous_time) else {
            return Ok(window);
        };
        if elapsed.is_zero() || elapsed > MAXIMUM_SAMPLE_GAP {
            return Ok(window);
        }
        let Some(total_delta) = total.checked_sub(previous_total) else {
            return Ok(window);
        };
        let mut controlled_delta = 0_u64;
        for (key, bytes) in controlled {
            if let Some(previous) = previous_controlled.get(&key) {
                let Some(delta) = bytes.checked_sub(*previous) else {
                    return Ok(window);
                };
                controlled_delta = controlled_delta.saturating_add(delta);
            }
        }
        // NETDEV counters share a byte basis, but a multi-counter read is not an atomic packet
        // snapshot. A small read skew cannot create negative owner demand. New/removed tuples
        // are conservatively unclassified for this interval instead of fabricating history.
        let owner_delta = total_delta.saturating_sub(controlled_delta);
        let owner_rate =
            u64::try_from(u128::from(owner_delta) * 1_000_000_000 / elapsed.as_nanos())
                .unwrap_or(u64::MAX);
        // Subtracting owner throughput alone can freeze a saturated link at a shared equilibrium.
        // Substantial owner activity therefore yields entirely, then resumes after a quiet hold.
        if owner_delta >= 2048 && owner_rate >= (self.capacity / 100).max(16_384) {
            self.owner_busy_until = now.checked_add(OWNER_IDLE_HOLD);
        }
        if self.owner_busy_until.is_some_and(|until| now < until) {
            return Ok(window);
        }
        window.available_bytes_per_second =
            self.ceiling.min(self.capacity.saturating_sub(owner_rate));
        Ok(window)
    }
}

/// Divide one receiver budget without multiplying capacity or burst allowance by the path count.
pub(crate) fn allocate_receive_budget(total: u64, caps: &[u64]) -> Vec<(u64, u32)> {
    let mut rates = vec![0_u64; caps.len()];
    if caps.is_empty() || caps.len() > 128 {
        return rates.into_iter().map(|rate| (rate, 0)).collect();
    }
    let mut remaining = total;
    while remaining > 0 {
        let eligible = rates
            .iter()
            .zip(caps)
            .filter(|(rate, cap)| rate < cap)
            .count();
        if eligible == 0 {
            break;
        }
        let share = (remaining / u64::try_from(eligible).unwrap_or(u64::MAX)).max(1);
        for (rate, cap) in rates.iter_mut().zip(caps) {
            let added = share.min(cap.saturating_sub(*rate)).min(remaining);
            *rate += added;
            remaining -= added;
        }
    }
    let burst = (MAXIMUM_AGGREGATE_BURST_BYTES / u32::try_from(caps.len()).unwrap_or(128))
        .clamp(2048, 65_536);
    // A closed rate still carries a finite valid queue geometry; it admits no payload.
    rates.into_iter().map(|rate| (rate, burst)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_routing::{ManagedReceiveCounter, ReceiveByteCounters};

    fn sample(total: u64, controlled: u64, own_client: u64) -> ReceiveAccountingSnapshot {
        ReceiveAccountingSnapshot {
            total: Some(ReceiveByteCounters {
                bytes: total,
                packets: 0,
            }),
            managed: vec![
                ManagedReceiveCounter {
                    route_context_id: vec![1; 16],
                    path_id: 1,
                    role: WireguardRole::RelayExit as i32,
                    counters: Some(ReceiveByteCounters {
                        bytes: controlled,
                        packets: 0,
                    }),
                },
                ManagedReceiveCounter {
                    route_context_id: vec![2; 16],
                    path_id: 1,
                    role: WireguardRole::Client as i32,
                    counters: Some(ReceiveByteCounters {
                        bytes: own_client,
                        packets: 0,
                    }),
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn downlink_owner_yields_to_own_client_and_recovers_one_shared_budget() {
        let config = DownloadSharingConfig {
            enabled: true,
            interface: "eth0".into(),
            total_download_mbps: 12,
            contribution_download_ceiling_mbps: 8,
        };
        let mut controller = ReceiveBudgetController::new(&config);
        let now = Instant::now();
        assert_eq!(
            controller
                .observe(sample(0, 0, 0), now)
                .unwrap()
                .available_bytes_per_second,
            0
        );
        let idle = controller
            .observe(
                sample(500_000, 500_000, 0),
                now + Duration::from_millis(500),
            )
            .unwrap();
        assert_eq!(idle.available_bytes_per_second, 1_000_000);
        let owner = controller
            .observe(
                sample(1_000_000, 750_000, 250_000),
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(owner.available_bytes_per_second, 0);
        assert_eq!(
            owner.paths.len(),
            1,
            "own Client is not a controlled contribution leg"
        );
        assert_eq!(
            controller
                .observe(
                    sample(1_000_000, 750_000, 250_000),
                    now + Duration::from_millis(1500)
                )
                .unwrap()
                .available_bytes_per_second,
            0
        );
        assert_eq!(
            controller
                .observe(
                    sample(1_000_000, 750_000, 250_000),
                    now + Duration::from_secs(2)
                )
                .unwrap()
                .available_bytes_per_second,
            1_000_000
        );
        assert_eq!(
            controller
                .observe(sample(1, 0, 0), now + Duration::from_millis(2500))
                .unwrap()
                .available_bytes_per_second,
            0
        );
        assert_eq!(
            controller
                .observe(sample(2, 0, 0), now + Duration::from_secs(8))
                .unwrap()
                .available_bytes_per_second,
            0
        );
    }

    #[test]
    fn downlink_uncontrolled_relay_exit_remains_owner_load() {
        let config = DownloadSharingConfig {
            enabled: true,
            interface: "eth0".into(),
            total_download_mbps: 12,
            contribution_download_ceiling_mbps: 8,
        };
        let mut controller = ReceiveBudgetController::new(&config);
        let now = Instant::now();
        let exact_grants = BTreeSet::from([(vec![9; 16], 1)]);
        let mut first = sample(0, 0, 0);
        retain_controlled_rows(&mut first, &exact_grants).unwrap();
        controller.observe(first, now).unwrap();
        let mut next = sample(500_000, 500_000, 0);
        retain_controlled_rows(&mut next, &exact_grants).unwrap();
        let observed = controller
            .observe(next, now + Duration::from_millis(500))
            .unwrap();
        assert_eq!(observed.available_bytes_per_second, 0);
        assert!(
            observed.paths.is_empty(),
            "unbudgeted/native-probe RelayExit is not controlled"
        );
    }

    #[test]
    fn downlink_allocation_respects_aggregate_and_individual_caps() {
        let shares = allocate_receive_budget(1000, &[100, 1000, 1000]);
        assert_eq!(shares.iter().map(|item| item.0).sum::<u64>(), 1000);
        assert_eq!(shares[0].0, 100);
        for count in [1, 2, 8, 128] {
            let shares = allocate_receive_budget(1_000_000, &vec![1_000_000; count]);
            assert_eq!(shares.iter().map(|item| item.0).sum::<u64>(), 1_000_000);
            assert!(shares.iter().map(|item| item.1).sum::<u32>() <= MAXIMUM_AGGREGATE_BURST_BYTES);
        }
        assert_eq!(
            allocate_receive_budget(0, &[1000, 1000]),
            vec![(0, 65_536), (0, 65_536)]
        );
    }
}
