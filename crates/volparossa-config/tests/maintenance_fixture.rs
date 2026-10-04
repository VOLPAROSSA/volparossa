// SPDX-License-Identifier: GPL-3.0-only
//! Compose the actual guest client configuration, without a VM, services or networking.

use std::{fs, path::Path, process::Command};
use volparossa_config::Config;

#[test]
fn complete_custody_client_config_uses_one_strict_sharing_configuration() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let integration = repository.join("tests/integration");
    let source = fs::read_to_string(integration.join("kvm-alpha-topology.sh")).unwrap();
    let function = source
        .split_once("\nwrite_config() {\n")
        .unwrap()
        .1
        .split_once("\n}\n\nwrite_config client")
        .unwrap()
        .0;
    let script = format!(
        r#"
. "$1/content-custody-smoke.sh"
WORK=$2
private_storage_maintenance=$3
AGENT_UID=$(id -u)
AGENT_GID=$(id -g)
RUN_ID=maintenance-config-regression
scenario=content-custody
agent_successor_serving=no
agent_active_recovery=no
agent_adapter_aggregation=no
agent_autonomous_aggregation=no
agent_train_loop=no
download_sharing=no
wifi_link=no
uplink_link=no
reciprocal_private_dns=no
write_config() {{
{function}
}}
write_config client null false false 43.159.1.1 \
    /ip4/40.156.1.1/udp/41000/quic-v1 \
    /ip4/41.157.2.1/udp/41000/quic-v1 none
"#
    );
    for (maintenance, receive_interface, ceiling) in [("no", "cr2", 1), ("yes", "cr0", 10)] {
        let work = tempfile::tempdir().unwrap();
        let output = Command::new("sh")
            .args(["-eu", "-c", &script, "maintenance-config-regression"])
            .arg(&integration)
            .arg(work.path())
            .arg(maintenance)
            .output()
            .unwrap();
        assert!(output.status.success(), "configuration emitter failed");
        let yaml = fs::read_to_string(work.path().join("config-client.yaml")).unwrap();
        let config = Config::from_yaml(&yaml).expect("the full composed client YAML must parse");
        assert!(config.roles.client && config.sharing.enabled && config.download_sharing.enabled);
        assert_eq!(config.sharing.interface, "cr0");
        assert_eq!(config.sharing.total_upload_mbps, 100);
        assert_eq!(config.sharing.contribution_upload_ceiling_mbps, ceiling);
        assert_eq!(config.download_sharing.interface, receive_interface);
        assert_eq!(config.download_sharing.total_download_mbps, 100);
        assert_eq!(
            config.download_sharing.contribution_download_ceiling_mbps,
            ceiling
        );
        // The original first-VM failure emitted a second sharing section. The
        // actual parser must reject that composition, not silently choose one.
        let duplicate = format!("{yaml}\nsharing:\n  enabled: false\n");
        assert!(
            Config::from_yaml(&duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate field")
        );
    }
}
