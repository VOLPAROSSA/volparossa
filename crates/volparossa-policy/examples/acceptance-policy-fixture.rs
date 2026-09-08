//! Generate one short-lived, threshold-signed development policy for the disposable acceptance
//! topology. It permits only the topology's exact A02 TCP, A05 UDP echo, A06/A07 HTTP/3 and
//! A08 visible-name TLS destinations. The explicit `--content-providers` option additionally
//! permits three exact provider names on TCP 18080. `--dns-cache` permits the exact public DNSSEC
//! fixture name for the ordinary protected DNS route, without replacing its public answers.
//! The fixed keys are test material and are never
//! accepted in production.

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

// The disposable VM runner has a forty-minute outer budget and creates its manifest before
// discovery/bootstrap acceptance starts. Keep this development-only policy bounded, but valid for
// the complete run instead of silently losing all ingress policy during the later A08-A10 phases.
const ACCEPTANCE_POLICY_LIFETIME_MS: u64 = 60 * 60 * 1_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let directory = arguments.next().ok_or("missing fixture directory")?;
    let (content_providers, dns_cache) = fixture_flags(arguments)?;
    if !Path::new(&directory).is_absolute() {
        return Err("fixture directory must be absolute".into());
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
        now.saturating_add(ACCEPTANCE_POLICY_LIFETIME_MS),
    )?;
    specification.add_rule(DestinationRule::exact_ip(
        IpAddr::V4(Ipv4Addr::new(10, 241, 31, 2)),
        [ProtocolPort::new(TransportProtocol::Udp, 18_081)?],
    )?)?;
    specification.add_rule(DestinationRule::exact_ip(
        IpAddr::V4(Ipv4Addr::new(47, 163, 4, 2)),
        [ProtocolPort::new(TransportProtocol::Tcp, 18_080)?],
    )?)?;
    specification.add_rule(DestinationRule::exact_domain(
        "destination.volparossa.test",
        [
            ProtocolPort::new(TransportProtocol::Tcp, 18_443)?,
            ProtocolPort::new(TransportProtocol::Udp, 443)?,
        ],
    )?)?;
    if content_providers {
        for hostname in [
            "provider-a.volparossa.test",
            "provider-b.volparossa.test",
            "provider-c.volparossa.test",
        ] {
            specification.add_rule(DestinationRule::exact_domain(
                hostname,
                [ProtocolPort::new(TransportProtocol::Tcp, 18_080)?],
            )?)?;
        }
    }
    if dns_cache {
        specification.add_rule(DestinationRule::exact_domain(
            "iana.org",
            [ProtocolPort::new(TransportProtocol::Tcp, 443)?],
        )?)?;
    }
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

fn fixture_flags(
    arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(bool, bool), &'static str> {
    let (mut content, mut dns) = (false, false);
    for option in arguments {
        if option == "--content-providers" && !content {
            content = true;
        } else if option == "--dns-cache" && !dns {
            dns = true;
        } else {
            return Err(
                "usage: acceptance-policy-fixture ROOT [--content-providers] [--dns-cache]",
            );
        }
    }
    Ok((content, dns))
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

#[test]
fn explicit_fixture_flags_are_exact_and_composable() {
    let flags = |args: &[&str]| fixture_flags(args.iter().map(std::ffi::OsString::from));
    assert_eq!(flags(&[]).unwrap(), (false, false));
    assert_eq!(flags(&["--dns-cache"]).unwrap(), (false, true));
    assert_eq!(
        flags(&["--content-providers", "--dns-cache"]).unwrap(),
        (true, true)
    );
    assert!(flags(&["--dns-cache", "--dns-cache"]).is_err());
    assert!(flags(&["--dns-cache", "--unknown"]).is_err());
}
