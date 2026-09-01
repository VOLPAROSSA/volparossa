//! Generate one short-lived, threshold-signed development policy for the disposable acceptance
//! topology. It permits only the topology's exact A02 TCP and A05 UDP echo tuples. The fixed keys
//! are test material and are never accepted in production.

use std::{
    env, fs,
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use volparossa_policy::{
    DestinationRule, MaintainerEnvironment, ManifestSpec, POLICY_PROTOCOL_VERSION, PolicyMode,
    ProtocolPort, TransportProtocol, TrustStore, TrustedMaintainer, sign_manifest,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let directory = arguments.next().ok_or("missing fixture directory")?;
    if arguments.next().is_some() || !Path::new(&directory).is_absolute() {
        return Err("invalid fixture directory".into());
    }
    let keys = [
        SigningKey::from_bytes(&[0x41; 32]),
        SigningKey::from_bytes(&[0x42; 32]),
        SigningKey::from_bytes(&[0x43; 32]),
    ];
    let trust = TrustStore::new(
        PolicyMode::Development,
        keys.iter()
            .map(|key| {
                TrustedMaintainer::new(key.verifying_key(), MaintainerEnvironment::Development)
            })
            .collect(),
    )?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let mut specification = ManifestSpec::new(
        1,
        POLICY_PROTOCOL_VERSION,
        now.saturating_sub(1_000),
        now.saturating_sub(1_000),
        now.saturating_add(600_000),
    )?;
    specification.add_rule(DestinationRule::exact_ip(
        IpAddr::V4(Ipv4Addr::new(10, 241, 31, 2)),
        [ProtocolPort::new(TransportProtocol::Udp, 18_081)?],
    )?)?;
    specification.add_rule(DestinationRule::exact_ip(
        IpAddr::V4(Ipv4Addr::new(47, 163, 4, 2)),
        [ProtocolPort::new(TransportProtocol::Tcp, 18_080)?],
    )?)?;
    let signers = keys.iter().collect::<Vec<_>>();
    let manifest = sign_manifest(&specification, &trust, &signers)?;
    write_private(
        Path::new(&directory).join("development-policy.manifest"),
        &manifest,
    )?;
    let entries = keys
        .iter()
        .map(|key| {
            format!(
                "{{\"public_key_hex\":\"{}\",\"environment\":\"development\"}}",
                encode_hex(&key.verifying_key().to_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    write_private(
        Path::new(&directory).join("policy-maintainers.json"),
        format!("{{\"schema_version\":1,\"maintainers\":[{entries}]}}").as_bytes(),
    )?;
    Ok(())
}

fn write_private(path: impl AsRef<Path>, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
