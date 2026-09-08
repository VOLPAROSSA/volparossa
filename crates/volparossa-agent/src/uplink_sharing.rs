//! Runtime-long owner-priority upload scheduling, started before advertising participation.

use std::{sync::Arc, time::Duration};

use rand_core::{OsRng, RngCore as _};
use tokio::sync::watch;
use volparossa_config::{RolesConfig, SharingConfig};
use volparossa_routing::InstallUplinkSharing;

use crate::helper::{HelperClient, HelperClientError, RuntimeBoundUplinkSharing};

pub(crate) struct UplinkSharingRuntime {
    helper: HelperClient,
    owner: RuntimeBoundUplinkSharing,
}

impl UplinkSharingRuntime {
    pub(crate) async fn start(
        helper: HelperClient,
        config: &SharingConfig,
        roles: RolesConfig,
    ) -> Result<Option<Arc<Self>>, HelperClientError> {
        if !config.enabled || !(roles.relay || roles.exit) {
            return Ok(None);
        }
        let mut runtime_id = [0_u8; 16];
        OsRng.fill_bytes(&mut runtime_id);
        let owner = helper
            .install_uplink_sharing(InstallUplinkSharing {
                sharing_runtime_id: runtime_id.to_vec(),
                interface: config.interface.clone(),
                total_upload_mbps: config.total_upload_mbps,
                contribution_upload_ceiling_mbps: config.contribution_upload_ceiling_mbps,
            })
            .await?;
        let runtime = Self { helper, owner };
        // Verify the actual queues before discovery can announce contribution capacity.
        if let Err(error) = runtime.helper.inspect_uplink_sharing(&runtime.owner).await {
            let _ = runtime.shutdown().await;
            return Err(error);
        }
        Ok(Some(Arc::new(runtime)))
    }

    pub(crate) async fn shutdown(&self) -> Result<(), HelperClientError> {
        self.helper.destroy_uplink_sharing(&self.owner).await
    }

    pub(crate) async fn monitor(
        runtime: Option<Arc<Self>>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), HelperClientError> {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() { return Ok(()); }
                }
                _ = interval.tick(), if runtime.is_some() => {
                    if let Some(runtime) = &runtime {
                        runtime.helper.inspect_uplink_sharing(&runtime.owner).await?;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn uplink_sharing_is_inert_without_explicit_configuration_and_participation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let helper = HelperClient::new(
            directory.path().join("missing.sock"),
            directory.path().join("missing-token"),
        );
        assert!(
            UplinkSharingRuntime::start(
                helper.clone(),
                &SharingConfig::default(),
                RolesConfig {
                    client: true,
                    relay: true,
                    exit: true
                },
            )
            .await
            .expect("disabled sharing has no IPC")
            .is_none()
        );
        let config = SharingConfig {
            enabled: true,
            interface: "uplink0".to_owned(),
            total_upload_mbps: 10,
            contribution_upload_ceiling_mbps: 8,
        };
        assert!(
            UplinkSharingRuntime::start(
                helper,
                &config,
                RolesConfig {
                    client: false,
                    relay: false,
                    exit: false
                },
            )
            .await
            .expect("inactive node has no IPC")
            .is_none()
        );
    }
}
