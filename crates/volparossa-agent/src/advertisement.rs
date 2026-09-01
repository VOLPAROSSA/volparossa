//! Truthful, short-lived local node advertisements.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use libp2p::{Multiaddr, multiaddr::Protocol};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use volparossa_config::RolesConfig;
use volparossa_core::OperatorId;
use volparossa_discovery::capability;
use volparossa_identity::{Identity, IdentityError};
use volparossa_protocol::{
    AdvertisementCapabilities, AdvertisementCapacity, AdvertisementNetwork, AdvertisementPolicy,
    AdvertisementQuality, AdvertisementRoles, NodeAdvertisement, ProtocolError, TimePolicy,
    generate_nonce, node_id_from_public_key, sign_control_message_with,
};

const MAX_WIRE_TTL_SECONDS: u64 = 15 * 60;
const MAX_CONTROL_ADDRESSES: usize = 16;
const MAX_SEQUENCE_FILE_BYTES: u64 = 32;

#[derive(Clone, Debug)]
pub(crate) struct LocalAdvertisementInput {
    pub(crate) roles: RolesConfig,
    pub(crate) operator_id: String,
    pub(crate) capabilities: AdvertisementCapabilities,
    pub(crate) capacity: AdvertisementCapacity,
    pub(crate) origin: AdvertisementNetwork,
    pub(crate) policy_version: u64,
    pub(crate) policy_hash: [u8; 32],
    pub(crate) policy_expires_at_ms: u64,
    pub(crate) control_addresses: BTreeSet<String>,
}

#[derive(Debug)]
pub(crate) struct SignedLocalAdvertisement {
    pub(crate) envelope: Vec<u8>,
    pub(crate) provider_keys: BTreeSet<String>,
}

pub(crate) struct AdvertisementPublisher {
    sequence_store: AdvertisementSequenceStore,
    started_at: Instant,
    ttl: Duration,
    refresh_interval: Duration,
}

impl AdvertisementPublisher {
    pub(crate) fn new(sequence_path: PathBuf, ttl_seconds: u64) -> Self {
        let ttl_seconds = ttl_seconds.clamp(1, MAX_WIRE_TTL_SECONDS);
        let refresh_seconds = (ttl_seconds / 3).clamp(1, 60);
        Self {
            sequence_store: AdvertisementSequenceStore::new(sequence_path),
            started_at: Instant::now(),
            ttl: Duration::from_secs(ttl_seconds),
            refresh_interval: Duration::from_secs(refresh_seconds),
        }
    }

    pub(crate) const fn refresh_interval(&self) -> Duration {
        self.refresh_interval
    }

    pub(crate) fn sign(
        &self,
        signer: &Identity,
        input: &LocalAdvertisementInput,
        now_ms: u64,
    ) -> Result<SignedLocalAdvertisement, AdvertisementError> {
        if !(input.roles.relay || input.roles.exit) {
            return Err(AdvertisementError::UnavailableServiceRole);
        }
        if input.control_addresses.is_empty()
            || input.control_addresses.len() > MAX_CONTROL_ADDRESSES
            || OperatorId::new(input.operator_id.clone()).is_err()
            || input.policy_version == 0
            || input.policy_hash == [0; 32]
            || input.policy_expires_at_ms <= now_ms
            || !service_claims_are_consistent(input)
        {
            return Err(AdvertisementError::InvalidInput);
        }

        let (ipv4, ipv6) = address_families(&input.control_addresses)?;
        if !(ipv4 || ipv6) {
            return Err(AdvertisementError::InvalidInput);
        }
        let expires_at_ms = now_ms
            .checked_add(
                u64::try_from(self.ttl.as_millis())
                    .map_err(|_| AdvertisementError::InvalidInput)?,
            )
            .ok_or(AdvertisementError::InvalidInput)?
            .min(input.policy_expires_at_ms);
        if expires_at_ms <= now_ms {
            return Err(AdvertisementError::InvalidInput);
        }

        let public_key = signer.ed25519_public_key_bytes()?;
        let sequence_number = self.sequence_store.next()?;
        let sample_window_seconds = u32::try_from(self.refresh_interval.as_secs().clamp(1, 300))
            .map_err(|_| AdvertisementError::InvalidInput)?;
        let message = NodeAdvertisement {
            node_id: node_id_from_public_key(&public_key).to_vec(),
            peer_id: signer.peer_id().to_bytes(),
            sequence_number,
            roles: Some(AdvertisementRoles {
                client: input.roles.client,
                relay: input.roles.relay,
                exit: input.roles.exit,
            }),
            capabilities: Some(AdvertisementCapabilities {
                ipv4,
                ipv6,
                ..input.capabilities.clone()
            }),
            control_addresses: input.control_addresses.iter().cloned().collect(),
            capacity: Some(AdvertisementCapacity {
                sample_window_seconds,
                ..input.capacity.clone()
            }),
            network: Some(AdvertisementNetwork {
                operator_id: input.operator_id.clone(),
                ..input.origin.clone()
            }),
            quality: Some(AdvertisementQuality {
                local_uptime_seconds: self.started_at.elapsed().as_secs(),
                historical_uptime_ppm: 0,
                historical_delivery_ratio_p25_ppm: 0,
            }),
            policy: Some(AdvertisementPolicy {
                whitelist_version: input.policy_version,
                whitelist_hash: input.policy_hash.to_vec(),
            }),
            measured_at_ms: now_ms,
            expires_at_ms,
        };
        let provider_keys = provider_keys(&message);
        let envelope = sign_control_message_with(
            &message,
            public_key,
            now_ms,
            expires_at_ms,
            generate_nonce(),
            TimePolicy::default(),
            |bytes| signer.sign(bytes).ok(),
        )?;
        Ok(SignedLocalAdvertisement {
            envelope,
            provider_keys,
        })
    }
}

fn service_claims_are_consistent(input: &LocalAdvertisementInput) -> bool {
    let transport = input.capabilities.tcp_mptcp
        || input.capabilities.udp_single_path
        || input.capabilities.multipath_quic;
    let relay_capacity = !input.roles.relay
        || (input.capacity.operator_relay_limit_up_mbps > 0
            && input.capacity.operator_relay_limit_down_mbps > 0);
    let exit_capacity = !input.roles.exit
        || (input.capacity.operator_exit_limit_up_mbps > 0
            && input.capacity.operator_exit_limit_down_mbps > 0);
    input.origin.asn != 0
        && !input.origin.region.is_empty()
        && input.origin.country_code.len() == 2
        && transport
        && relay_capacity
        && exit_capacity
}

fn address_families(addresses: &BTreeSet<String>) -> Result<(bool, bool), AdvertisementError> {
    let mut ipv4 = false;
    let mut ipv6 = false;
    for text in addresses {
        let address: Multiaddr = text.parse().map_err(|_| AdvertisementError::InvalidInput)?;
        for protocol in &address {
            match protocol {
                Protocol::Ip4(_) => ipv4 = true,
                Protocol::Ip6(_) => ipv6 = true,
                _ => {}
            }
        }
    }
    Ok((ipv4, ipv6))
}

fn provider_keys(advertisement: &NodeAdvertisement) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let Some(roles) = advertisement.roles.as_ref() else {
        return keys;
    };
    let Some(capabilities) = advertisement.capabilities.as_ref() else {
        return keys;
    };
    if !(roles.relay || roles.exit) {
        return keys;
    }

    if roles.relay {
        keys.insert(capability::RELAY.to_owned());
    }
    if roles.exit {
        keys.insert(capability::EXIT.to_owned());
    }
    if capabilities.tcp_mptcp {
        keys.insert(capability::MPTCP.to_owned());
    }
    if capabilities.multipath_quic {
        keys.insert(capability::MPQUIC.to_owned());
    }
    if let Some(network) = advertisement.network.as_ref() {
        if network.region != "unknown" {
            for role in [roles.relay.then_some("relay"), roles.exit.then_some("exit")]
                .into_iter()
                .flatten()
            {
                if let Some(key) = capability::region(role, &network.region) {
                    keys.insert(key);
                }
            }
        }
    }
    if let Some(policy) = advertisement.policy.as_ref() {
        if let Ok(hash) = <[u8; 32]>::try_from(policy.whitelist_hash.as_slice()) {
            keys.insert(capability::policy(&hash));
        }
    }
    keys
}

#[derive(Clone, Debug)]
struct AdvertisementSequenceStore {
    path: PathBuf,
}

impl AdvertisementSequenceStore {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn next(&self) -> Result<u64, AdvertisementError> {
        let previous = self.load()?.unwrap_or(0);
        let next = previous
            .checked_add(1)
            .ok_or(AdvertisementError::SequenceExhausted)?;
        self.persist(next)?;
        Ok(next)
    }

    fn load(&self) -> Result<Option<u64>, AdvertisementError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(AdvertisementError::Io(error)),
        };
        validate_sequence_metadata(&metadata)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(AdvertisementError::Io)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len()).map_err(|_| AdvertisementError::UnsafeSequence)?,
        );
        Read::by_ref(&mut file)
            .take(MAX_SEQUENCE_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(AdvertisementError::Io)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| AdvertisementError::UnsafeSequence)?;
        let value = text
            .strip_suffix('\n')
            .ok_or(AdvertisementError::UnsafeSequence)?
            .parse::<u64>()
            .map_err(|_| AdvertisementError::UnsafeSequence)?;
        if value == 0 || format!("{value}\n").as_bytes() != bytes {
            return Err(AdvertisementError::UnsafeSequence);
        }
        Ok(Some(value))
    }

    fn persist(&self, sequence: u64) -> Result<(), AdvertisementError> {
        let parent = self
            .path
            .parent()
            .ok_or(AdvertisementError::UnsafeSequence)?;
        validate_private_directory(parent)?;
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            validate_sequence_metadata(&metadata)?;
        }
        let mut nonce = [0_u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let temporary = parent.join(format!(
            ".advertisement-sequence-{}.tmp",
            hex::encode(nonce)
        ));
        let bytes = format!("{sequence}\n");
        let result = write_sequence(&temporary, &self.path, bytes.as_bytes());
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(parent)
            .map_err(AdvertisementError::Io)?;
        directory.sync_all().map_err(AdvertisementError::Io)
    }
}

fn write_sequence(
    temporary: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), AdvertisementError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(temporary)
        .map_err(AdvertisementError::Io)?;
    file.write_all(bytes).map_err(AdvertisementError::Io)?;
    file.sync_all().map_err(AdvertisementError::Io)?;
    fs::rename(temporary, destination).map_err(AdvertisementError::Io)?;
    let metadata = fs::symlink_metadata(destination).map_err(AdvertisementError::Io)?;
    validate_sequence_metadata(&metadata)
}

fn validate_private_directory(path: &Path) -> Result<(), AdvertisementError> {
    let metadata = fs::symlink_metadata(path).map_err(AdvertisementError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(AdvertisementError::UnsafeSequence);
    }
    Ok(())
}

fn validate_sequence_metadata(metadata: &fs::Metadata) -> Result<(), AdvertisementError> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.len() == 0
        || metadata.len() > MAX_SEQUENCE_FILE_BYTES
    {
        return Err(AdvertisementError::UnsafeSequence);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum AdvertisementError {
    #[error("local advertisement input is invalid")]
    InvalidInput,
    #[error("relay and exit advertisement is unavailable without its service dataplane")]
    UnavailableServiceRole,
    #[error("advertisement sequence state is unsafe")]
    UnsafeSequence,
    #[error("advertisement sequence is exhausted")]
    SequenceExhausted,
    #[error("advertisement sequence persistence failed")]
    Io(#[source] std::io::Error),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;
    use volparossa_protocol::{ReplayCache, verify_control_message};

    use super::*;

    const NOW_MS: u64 = 1_900_000_000_000;

    fn input() -> LocalAdvertisementInput {
        LocalAdvertisementInput {
            roles: RolesConfig {
                client: true,
                relay: true,
                exit: false,
            },
            operator_id: "operator-test".to_owned(),
            capabilities: AdvertisementCapabilities {
                tcp_mptcp: true,
                udp_single_path: true,
                multipath_quic: true,
                ipv4: false,
                ipv6: false,
                udp_hole_punching: false,
            },
            capacity: AdvertisementCapacity {
                operator_relay_limit_up_mbps: 100,
                operator_relay_limit_down_mbps: 100,
                operator_exit_limit_up_mbps: 0,
                operator_exit_limit_down_mbps: 0,
                currently_reserved_up_mbps: 0,
                currently_reserved_down_mbps: 0,
                estimated_free_up_mbps: 100,
                estimated_free_down_mbps: 100,
                active_relay_sessions: 0,
                active_exit_sessions: 0,
                free_relay_slots: 4,
                free_exit_slots: 0,
                sample_window_seconds: 0,
            },
            origin: AdvertisementNetwork {
                region: "test".to_owned(),
                country_code: "NL".to_owned(),
                asn: 64_512,
                ipv4_prefix_hint: "44.12.34.0/24".to_owned(),
                ipv6_prefix_hint: "2606:4700:100::/48".to_owned(),
                operator_id: String::new(),
            },
            policy_version: 7,
            policy_hash: [7; 32],
            policy_expires_at_ms: NOW_MS + 1_000_000,
            control_addresses: BTreeSet::from([
                "/ip4/127.0.0.1/udp/42000/quic-v1".to_owned(),
                "/ip6/::1/tcp/42001".to_owned(),
            ]),
        }
    }

    #[test]
    fn signed_service_refresh_is_truthful_monotonic_and_short_lived() {
        let directory = tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let identity = Identity::generate();
        let publisher =
            AdvertisementPublisher::new(directory.path().join("advertisement.sequence"), 300);
        let first = publisher
            .sign(&identity, &input(), NOW_MS)
            .expect("first signed ad");
        assert!(first.provider_keys.contains(capability::RELAY));
        let mut replay = ReplayCache::new(4).expect("replay cache");
        let first_verified = verify_control_message::<NodeAdvertisement>(
            &first.envelope,
            NOW_MS + 1,
            TimePolicy::default(),
            &mut replay,
        )
        .expect("verified first ad");
        let first_message = first_verified.message();
        assert_eq!(first_message.sequence_number, 1);
        assert_eq!(first_message.expires_at_ms, NOW_MS + 300_000);
        assert_eq!(
            first_message.roles,
            Some(AdvertisementRoles {
                client: true,
                relay: true,
                exit: false,
            })
        );
        assert_eq!(
            first_message
                .network
                .as_ref()
                .map(|network| network.operator_id.as_str()),
            Some("operator-test")
        );
        assert!(
            first_message
                .capabilities
                .as_ref()
                .is_some_and(|capabilities| {
                    capabilities.ipv4
                        && capabilities.ipv6
                        && capabilities.tcp_mptcp
                        && capabilities.udp_single_path
                        && capabilities.multipath_quic
                })
        );

        let second = publisher
            .sign(&identity, &input(), NOW_MS + 1_000)
            .expect("refreshed signed ad");
        let second_verified = verify_control_message::<NodeAdvertisement>(
            &second.envelope,
            NOW_MS + 1_001,
            TimePolicy::default(),
            &mut replay,
        )
        .expect("verified refreshed ad");
        assert_eq!(second_verified.message().sequence_number, 2);
        assert_eq!(second_verified.message().expires_at_ms, NOW_MS + 301_000);
    }

    #[test]
    fn sequence_survives_reopen_and_file_is_private() {
        let directory = tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let path = directory.path().join("advertisement.sequence");
        let store = AdvertisementSequenceStore::new(path.clone());
        assert_eq!(store.next().expect("one"), 1);
        assert_eq!(store.next().expect("two"), 2);
        drop(store);
        assert_eq!(
            AdvertisementSequenceStore::new(path.clone())
                .next()
                .expect("three"),
            3
        );
        assert_eq!(
            fs::symlink_metadata(path).expect("metadata").mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn unavailable_service_roles_never_create_claims_or_sequence_state() {
        let directory = tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let sequence_path = directory.path().join("advertisement.sequence");
        let identity = Identity::generate();
        let publisher = AdvertisementPublisher::new(sequence_path.clone(), 300);
        let mut invalid_operator = input();
        invalid_operator.operator_id.clear();
        assert!(matches!(
            publisher.sign(&identity, &invalid_operator, NOW_MS),
            Err(AdvertisementError::InvalidInput)
        ));
        assert!(!sequence_path.exists());
        let mut unavailable = input();
        unavailable.roles.relay = false;
        assert!(matches!(
            publisher.sign(&identity, &unavailable, NOW_MS),
            Err(AdvertisementError::UnavailableServiceRole)
        ));
        assert!(!sequence_path.exists());
    }
}
