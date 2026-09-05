//! Explicit radio adjacency lifetime, independent of any overlay route context.

use crate::helper::{HelperClient, HelperClientError, RuntimeBoundWifiMesh};
use rand_core::{OsRng, RngCore as _};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::watch;
use volparossa_config::{RolesConfig, WifiMeshConfig};
use volparossa_routing::InstallWifiMesh;

pub(crate) struct WifiMeshRuntime {
    helper: HelperClient,
    owner: RuntimeBoundWifiMesh,
}

impl WifiMeshRuntime {
    pub(crate) async fn start(
        helper: HelperClient,
        config: &WifiMeshConfig,
        roles: RolesConfig,
    ) -> Result<Option<Arc<Self>>, HelperClientError> {
        if !config.enabled || !(roles.client || roles.relay || roles.exit) {
            return Ok(None);
        }
        let local: IpAddr = config
            .local_address
            .parse()
            .map_err(|_| HelperClientError::Correlation)?;
        let mut runtime_id = [0_u8; 16];
        OsRng.fill_bytes(&mut runtime_id);
        let owner = helper
            .install_wifi_mesh(InstallWifiMesh {
                mesh_runtime_id: runtime_id.to_vec(),
                parent_interface: config.parent_interface.clone(),
                mesh_id: config.mesh_id.as_bytes().to_vec(),
                frequency_mhz: config.frequency_mhz,
                local_address: match local {
                    IpAddr::V4(ip) => ip.octets().to_vec(),
                    IpAddr::V6(ip) => ip.octets().to_vec(),
                },
                prefix_len: config.prefix_len.into(),
                maximum_peers: config.maximum_peers.into(),
            })
            .await?;
        let runtime = Self { helper, owner };
        if let Err(error) = runtime.helper.inspect_wifi_mesh(&runtime.owner).await {
            let _ = runtime.shutdown().await;
            return Err(error);
        }
        Ok(Some(Arc::new(runtime)))
    }

    pub(crate) async fn shutdown(&self) -> Result<(), HelperClientError> {
        self.helper.destroy_wifi_mesh(&self.owner).await
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
                changed = shutdown.changed() => { if changed.is_err() { return Ok(()); } }
                _ = interval.tick(), if runtime.is_some() => {
                    if let Some(runtime) = &runtime {
                        runtime.helper.inspect_wifi_mesh(&runtime.owner).await?;
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
    async fn wifi_mesh_is_inert_without_configuration_or_participation() {
        let directory = tempfile::tempdir().unwrap();
        let helper = HelperClient::new(
            directory.path().join("absent.sock"),
            directory.path().join("absent-token"),
        );
        let roles = RolesConfig {
            client: true,
            relay: true,
            exit: false,
        };
        assert!(
            WifiMeshRuntime::start(helper.clone(), &WifiMeshConfig::default(), roles)
                .await
                .unwrap()
                .is_none()
        );
        let enabled = WifiMeshConfig {
            enabled: true,
            ..WifiMeshConfig::default()
        };
        let roles = RolesConfig {
            client: false,
            relay: false,
            exit: false,
        };
        assert!(
            WifiMeshRuntime::start(helper, &enabled, roles)
                .await
                .unwrap()
                .is_none()
        );
    }
}
