//! Integration tests for the privacy-minimizing `SQLite` peerstore.

use std::net::{IpAddr, Ipv4Addr};
#[cfg(unix)]
use std::os::unix::fs::symlink;
use tempfile::tempdir;
use volparossa_core::{
    Bandwidth, CapacitySnapshot, NetworkMetadata, NodeAdvertisement, NodeCapabilities, NodeId,
    NodeQuality, NodeRoles, OperatorId, PROTOCOL_VERSION, PeerId, PolicyHash, UnixTime,
};
use volparossa_peerstore::{
    MAX_SIGNED_ADVERTISEMENT_ENVELOPE_BYTES, PeerMeasurement, PeerStore, PeerStoreError,
};

const SIGNED_ENVELOPE: &[u8] = b"canonical-signed-advertisement-envelope";

fn bandwidth(value: u32) -> Bandwidth {
    Bandwidth::new(value, value).expect("bounded")
}

fn advertisement(sequence: u64, expiry: u64) -> NodeAdvertisement {
    NodeAdvertisement {
        protocol_version: PROTOCOL_VERSION,
        node_id: NodeId::new("node-a").expect("valid"),
        peer_id: PeerId::new("peer-a").expect("valid"),
        sequence_number: sequence,
        roles: NodeRoles {
            client: false,
            relay: true,
            exit: false,
        },
        capabilities: NodeCapabilities {
            tcp_mptcp: true,
            udp_single_path: true,
            multipath_quic: true,
            ipv4: true,
            ipv6: true,
            udp_hole_punching: true,
        },
        capacity: CapacitySnapshot {
            relay_limit: bandwidth(200),
            exit_limit: Bandwidth::default(),
            currently_reserved: bandwidth(20),
            estimated_free: bandwidth(150),
            active_relay_sessions: 1,
            active_exit_sessions: 0,
            free_relay_slots: 8,
            free_exit_slots: 0,
            sample_window_seconds: 15,
        },
        network: NetworkMetadata {
            operator_id: OperatorId::new("operator-a").expect("valid"),
            region: "eu-west".to_owned(),
            country_code: "NL".to_owned(),
            asn: Some(64_500),
            ipv4_prefix_hint: Some("192.0.2.0/24".to_owned()),
            ipv6_prefix_hint: None,
        },
        quality: NodeQuality {
            local_uptime_seconds: 10_000,
            historical_uptime_score: 0.9,
            historical_delivery_ratio_p25: 0.8,
        },
        policy_hash: PolicyHash::from_bytes([7; 32]),
        control_endpoints: vec!["/ip4/192.0.2.10/udp/443/quic-v1".to_owned()],
        measured_at: UnixTime::from_secs(1_000),
        expires_at: UnixTime::from_secs(expiry),
    }
}

#[test]
fn rejects_missing_provenance_and_replayed_advertisements() {
    let mut store = PeerStore::open_in_memory().expect("store");
    let value = advertisement(1, 1_300);
    assert!(matches!(
        store.upsert_advertisement(&value, &[], UnixTime::from_secs(1_100)),
        Err(PeerStoreError::MissingAdvertisementProvenance)
    ));
    store
        .upsert_advertisement(&value, SIGNED_ENVELOPE, UnixTime::from_secs(1_100))
        .expect("verified");
    assert!(matches!(
        store.upsert_advertisement(&value, SIGNED_ENVELOPE, UnixTime::from_secs(1_101)),
        Err(PeerStoreError::StaleAdvertisement)
    ));
}

#[test]
fn retains_bounded_samples_and_computes_local_p25() {
    let mut store = PeerStore::open_in_memory().expect("store");
    let value = advertisement(1, 1_300);
    store
        .upsert_advertisement(&value, SIGNED_ENVELOPE, UnixTime::from_secs(1_050))
        .expect("advertisement");
    for index in 0..80_u32 {
        let reachable = index % 4 != 0;
        store
            .record_measurement(
                &value.node_id,
                PeerMeasurement {
                    observed_at: UnixTime::from_secs(1_060 + u64::from(index)),
                    reachable,
                    rtt_ms: reachable.then_some(20.0 + f64::from(index)),
                    jitter_ms: reachable.then_some(2.0),
                    loss_ratio: 0.01,
                    delivery_rate: if reachable {
                        bandwidth(index + 1)
                    } else {
                        bandwidth(0)
                    },
                },
            )
            .expect("measurement");
    }
    let peers = store
        .load_candidates(UnixTime::from_secs(1_200), 200)
        .expect("load");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].evidence.measurement_count, 64);
    assert_eq!(peers[0].evidence.delivery_p25, Some(bandwidth(0)));
    assert_eq!(peers[0].evidence.uptime_score, Some(0.75));
}

#[test]
fn persists_only_peer_endpoint_and_aggregate_events() {
    let temporary = tempdir().expect("temporary directory");
    let path = temporary.path().join("peers.sqlite3");
    let value = advertisement(1, 1_300);
    {
        let mut store = PeerStore::open(&path).expect("open");
        store
            .upsert_advertisement(&value, SIGNED_ENVELOPE, UnixTime::from_secs(1_050))
            .expect("advertisement");
        store
            .record_endpoint(
                &value.node_id,
                "/ip4/192.0.2.10/udp/443/quic-v1",
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                true,
                UnixTime::from_secs(1_060),
            )
            .expect("endpoint");
        store
            .record_reservation_failure(&value.node_id)
            .expect("event");
        store
            .record_protocol_fault(&value.node_id, Some(UnixTime::from_secs(1_180)))
            .expect("fault");
        store.audit_privacy_schema().expect("privacy schema");
    }
    let store = PeerStore::open(&path).expect("reopen");
    let peers = store
        .load_candidates(UnixTime::from_secs(1_100), 200)
        .expect("load");
    assert_eq!(peers[0].evidence.reservation_failures, 1);
    assert_eq!(peers[0].evidence.protocol_faults, 1);
    assert_eq!(
        peers[0].evidence.serious_protocol_fault_until,
        Some(UnixTime::from_secs(1_180))
    );
    assert_eq!(
        peers[0]
            .latest_endpoint
            .as_ref()
            .expect("endpoint")
            .observed_ip,
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    );
}

#[test]
fn pruning_expired_advertisement_cascades_all_peer_history() {
    let mut store = PeerStore::open_in_memory().expect("store");
    let value = advertisement(1, 1_200);
    store
        .upsert_advertisement(&value, SIGNED_ENVELOPE, UnixTime::from_secs(1_050))
        .expect("advertisement");
    store
        .record_measurement(
            &value.node_id,
            PeerMeasurement {
                observed_at: UnixTime::from_secs(1_100),
                reachable: true,
                rtt_ms: Some(20.0),
                jitter_ms: Some(1.0),
                loss_ratio: 0.0,
                delivery_rate: bandwidth(50),
            },
        )
        .expect("measurement");
    assert_eq!(
        store
            .prune_expired(UnixTime::from_secs(1_260), 30)
            .expect("prune"),
        1
    );
    assert!(
        store
            .load_candidates(UnixTime::from_secs(1_260), 200)
            .expect("load")
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn file_store_opens_real_path_and_rejects_symbolic_link() {
    let temporary = tempdir().expect("temporary directory");
    let database_path = temporary.path().join("peers.sqlite3");
    drop(PeerStore::open(&database_path).expect("open real database path"));

    let symbolic_link_path = temporary.path().join("peerstore-link.sqlite3");
    symlink(&database_path, &symbolic_link_path).expect("create database symbolic link");

    let error = PeerStore::open(&symbolic_link_path)
        .expect_err("SQLite must reject a symbolic-link database path");
    match error {
        PeerStoreError::Sqlite(error) => {
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::CannotOpen),
                "SQLITE_OPEN_NOFOLLOW must reject the symbolic link"
            );
        }
        other => panic!("expected an SQLite open error, got {other}"),
    }
}

#[test]
fn oversized_provenance_is_rejected_before_any_database_write() {
    let mut store = PeerStore::open_in_memory().expect("store");
    let value = advertisement(1, 1_300);
    let oversized = vec![0; MAX_SIGNED_ADVERTISEMENT_ENVELOPE_BYTES + 1];
    assert!(matches!(
        store.upsert_advertisement(&value, &oversized, UnixTime::from_secs(1_100)),
        Err(PeerStoreError::AdvertisementEnvelopeTooLarge)
    ));
    assert!(
        store
            .load_candidates(UnixTime::from_secs(1_100), 1)
            .expect("bounded load")
            .is_empty()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the complete legacy schema and atomic migration assertions form one regression"
)]
fn version_one_rows_are_atomically_quarantined_until_real_provenance_replaces_them() {
    let temporary = tempdir().expect("temporary directory");
    let path = temporary.path().join("legacy.sqlite3");
    let value = advertisement(1, 1_300);
    let serialized = serde_json::to_vec(&value).expect("serialize advertisement");
    let connection = rusqlite::Connection::open(&path).expect("legacy database");
    connection
        .execute_batch(
            r"
            PRAGMA foreign_keys = ON;
            CREATE TABLE advertisements (
                node_id TEXT PRIMARY KEY NOT NULL,
                peer_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                protocol_version INTEGER NOT NULL,
                policy_hash BLOB NOT NULL,
                advertisement_json BLOB NOT NULL,
                measured_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                stored_at INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE endpoints (
                node_id TEXT NOT NULL REFERENCES advertisements(node_id) ON DELETE CASCADE,
                endpoint TEXT NOT NULL,
                observed_ip TEXT,
                reachable INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                last_reachable_at INTEGER,
                PRIMARY KEY (node_id, endpoint)
            ) STRICT;
            CREATE TABLE measurements (
                sample_id INTEGER PRIMARY KEY,
                node_id TEXT NOT NULL REFERENCES advertisements(node_id) ON DELETE CASCADE,
                observed_at INTEGER NOT NULL,
                reachable INTEGER NOT NULL,
                rtt_ms REAL,
                jitter_ms REAL,
                loss_ratio REAL NOT NULL,
                delivery_up_mbps INTEGER NOT NULL,
                delivery_down_mbps INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE peer_reputation (
                node_id TEXT PRIMARY KEY NOT NULL
                    REFERENCES advertisements(node_id) ON DELETE CASCADE,
                reservation_failures INTEGER NOT NULL DEFAULT 0,
                protocol_faults INTEGER NOT NULL DEFAULT 0,
                severe_protocol_faults INTEGER NOT NULL DEFAULT 0,
                severe_fault_until INTEGER,
                last_successful_session_at INTEGER
            ) STRICT;
            PRAGMA user_version = 1;
            ",
        )
        .expect("legacy schema");
    connection
        .execute(
            "INSERT INTO advertisements VALUES (?1, ?2, 1, ?3, ?4, ?5, 1000, 1300, 1050)",
            rusqlite::params![
                value.node_id.as_str(),
                value.peer_id.as_str(),
                i64::from(value.protocol_version),
                value.policy_hash.as_bytes().as_slice(),
                serialized,
            ],
        )
        .expect("legacy advertisement");
    connection
        .execute(
            "INSERT INTO endpoints VALUES (?1, ?2, ?3, 1, 1060, 1060)",
            rusqlite::params![
                value.node_id.as_str(),
                "/ip4/192.0.2.10/udp/443/quic-v1",
                "192.0.2.10",
            ],
        )
        .expect("legacy endpoint");
    connection
        .execute(
            "INSERT INTO measurements(
                node_id, observed_at, reachable, rtt_ms, jitter_ms, loss_ratio,
                delivery_up_mbps, delivery_down_mbps
             ) VALUES (?1, 1060, 1, 20.0, 1.0, 0.0, 50, 50)",
            [value.node_id.as_str()],
        )
        .expect("legacy measurement");
    connection
        .execute(
            "INSERT INTO peer_reputation(node_id, reservation_failures) VALUES (?1, 1)",
            [value.node_id.as_str()],
        )
        .expect("legacy reputation");
    drop(connection);

    let mut migrated = PeerStore::open(&path).expect("atomic migration");
    assert!(
        migrated
            .load_candidates(UnixTime::from_secs(1_100), 10)
            .expect("quarantined load")
            .is_empty()
    );
    assert!(matches!(
        migrated.record_reservation_failure(&value.node_id),
        Err(PeerStoreError::UnknownPeer)
    ));
    drop(migrated);

    let connection = rusqlite::Connection::open(&path).expect("inspect migrated database");
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("schema version");
    assert_eq!(version, 2);
    for table in [
        "advertisements",
        "endpoints",
        "measurements",
        "peer_reputation",
    ] {
        let query = format!("SELECT count(*) FROM {table}");
        let count: i64 = connection
            .query_row(&query, [], |row| row.get(0))
            .expect("preserved privacy-safe row");
        assert_eq!(count, 1);
    }
    let proof_is_null: bool = connection
        .query_row(
            "SELECT signed_advertisement_envelope IS NULL FROM advertisements",
            [],
            |row| row.get(0),
        )
        .expect("quarantined proof");
    assert!(proof_is_null);
    drop(connection);

    let mut upgraded = PeerStore::open(&path).expect("reopen migrated store");
    upgraded
        .upsert_advertisement(&value, SIGNED_ENVELOPE, UnixTime::from_secs(1_100))
        .expect("same-sequence signed replacement");
    let peers = upgraded
        .load_candidates(UnixTime::from_secs(1_100), 10)
        .expect("proven candidate");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].signed_advertisement_envelope(), SIGNED_ENVELOPE);
    assert_eq!(peers[0].evidence.measurement_count, 1);
    assert_eq!(peers[0].evidence.reservation_failures, 1);
    assert!(peers[0].latest_endpoint.is_some());
}

#[test]
fn oversized_persisted_provenance_corruption_fails_the_open_audit() {
    let temporary = tempdir().expect("temporary directory");
    let path = temporary.path().join("corrupt.sqlite3");
    let value = advertisement(1, 1_300);
    let mut store = PeerStore::open(&path).expect("store");
    store
        .upsert_advertisement(&value, SIGNED_ENVELOPE, UnixTime::from_secs(1_100))
        .expect("advertisement");
    drop(store);

    let connection = rusqlite::Connection::open(&path).expect("tamper connection");
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .expect("test-only constraint override");
    connection
        .execute(
            "UPDATE advertisements
             SET signed_advertisement_envelope = zeroblob(?1)",
            [i64::try_from(MAX_SIGNED_ADVERTISEMENT_ENVELOPE_BYTES + 1).expect("SQLite size")],
        )
        .expect("inject oversized corruption");
    drop(connection);

    assert!(matches!(
        PeerStore::open(&path),
        Err(PeerStoreError::SchemaAudit)
    ));
}
