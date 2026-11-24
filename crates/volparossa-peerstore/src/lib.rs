//! Bounded local peer evidence stored in `SQLite`.
//!
//! The schema has no route-context, origin, hostname, DNS, URL, destination,
//! payload, flow or secret-key fields.  Browsing policy and route selection
//! must remain in memory or in their dedicated short-lived protocol state.

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::Path, time::Duration};
use thiserror::Error;
use volparossa_core::{AdvertisementError, Bandwidth, NodeAdvertisement, NodeId, UnixTime};

const SCHEMA_VERSION: i64 = 2;
const MAX_SERIALIZED_ADVERTISEMENT_BYTES: usize = 64 * 1024;
/// Maximum signed advertisement envelope accepted by the discovery RPC.
///
/// This intentionally mirrors the stable control-envelope bound without making
/// the persistence crate depend on the networking stack.
pub const MAX_SIGNED_ADVERTISEMENT_ENVELOPE_BYTES: usize = 256 * 1024;
const MAX_ENDPOINT_BYTES: usize = 512;
const MAX_ENDPOINTS_PER_PEER: usize = 16;
const MAX_MEASUREMENTS_PER_PEER: usize = 64;
const MAX_LOAD_LIMIT: usize = 1_000;
const MAX_COUNTER: u32 = 1_000_000;

type EndpointRow = (String, Option<String>, bool, i64, Option<i64>);
type MeasurementRow = (bool, Option<f64>, Option<f64>, f64, u32, u32);

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS advertisements (
    node_id TEXT PRIMARY KEY NOT NULL,
    peer_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL CHECK (sequence_number >= 0),
    protocol_version INTEGER NOT NULL,
    policy_hash BLOB NOT NULL CHECK (length(policy_hash) = 32),
    advertisement_json BLOB NOT NULL CHECK (length(advertisement_json) <= 65536),
    signed_advertisement_envelope BLOB CHECK (
        signed_advertisement_envelope IS NULL OR
        length(signed_advertisement_envelope) BETWEEN 1 AND 262144
    ),
    measured_at INTEGER NOT NULL CHECK (measured_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > measured_at),
    stored_at INTEGER NOT NULL CHECK (stored_at >= 0)
) STRICT;

CREATE TABLE IF NOT EXISTS endpoints (
    node_id TEXT NOT NULL REFERENCES advertisements(node_id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL CHECK (length(endpoint) BETWEEN 1 AND 512),
    observed_ip TEXT,
    reachable INTEGER NOT NULL CHECK (reachable IN (0, 1)),
    last_seen_at INTEGER NOT NULL CHECK (last_seen_at >= 0),
    last_reachable_at INTEGER CHECK (last_reachable_at >= 0),
    PRIMARY KEY (node_id, endpoint)
) STRICT;

CREATE TABLE IF NOT EXISTS measurements (
    sample_id INTEGER PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES advertisements(node_id) ON DELETE CASCADE,
    observed_at INTEGER NOT NULL CHECK (observed_at >= 0),
    reachable INTEGER NOT NULL CHECK (reachable IN (0, 1)),
    rtt_ms REAL,
    jitter_ms REAL,
    loss_ratio REAL NOT NULL CHECK (loss_ratio >= 0.0 AND loss_ratio <= 1.0),
    delivery_up_mbps INTEGER NOT NULL CHECK (delivery_up_mbps >= 0),
    delivery_down_mbps INTEGER NOT NULL CHECK (delivery_down_mbps >= 0)
) STRICT;

CREATE INDEX IF NOT EXISTS measurements_peer_time
ON measurements(node_id, observed_at DESC, sample_id DESC);

CREATE TABLE IF NOT EXISTS peer_reputation (
    node_id TEXT PRIMARY KEY NOT NULL REFERENCES advertisements(node_id) ON DELETE CASCADE,
    reservation_failures INTEGER NOT NULL DEFAULT 0 CHECK (reservation_failures >= 0),
    protocol_faults INTEGER NOT NULL DEFAULT 0 CHECK (protocol_faults >= 0),
    severe_protocol_faults INTEGER NOT NULL DEFAULT 0 CHECK (severe_protocol_faults >= 0),
    severe_fault_until INTEGER CHECK (severe_fault_until >= 0),
    last_successful_session_at INTEGER CHECK (last_successful_session_at >= 0)
) STRICT;

PRAGMA user_version = 2;
";

const MIGRATE_V1_TO_V2: &str = r"
BEGIN IMMEDIATE;
ALTER TABLE advertisements ADD COLUMN signed_advertisement_envelope BLOB CHECK (
    signed_advertisement_envelope IS NULL OR
    length(signed_advertisement_envelope) BETWEEN 1 AND 262144
);
PRAGMA user_version = 2;
COMMIT;
";

/// One local reachability and delivery-rate observation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PeerMeasurement {
    /// Observation timestamp.
    pub observed_at: UnixTime,
    /// Whether the peer was reachable during this sample.
    pub reachable: bool,
    /// RTT when reachable.
    pub rtt_ms: Option<f64>,
    /// Jitter when reachable.
    pub jitter_ms: Option<f64>,
    /// Packet-loss ratio from 0 through 1.
    pub loss_ratio: f64,
    /// Short, controlled delivery-rate sample.
    pub delivery_rate: Bandwidth,
}

impl PeerMeasurement {
    fn validate(self) -> Result<(), PeerStoreError> {
        self.delivery_rate
            .validate()
            .map_err(|_| PeerStoreError::InvalidMeasurement)?;
        if !self.loss_ratio.is_finite() || !(0.0..=1.0).contains(&self.loss_ratio) {
            return Err(PeerStoreError::InvalidMeasurement);
        }
        for value in [self.rtt_ms, self.jitter_ms].into_iter().flatten() {
            if !value.is_finite() || !(0.0..=120_000.0).contains(&value) {
                return Err(PeerStoreError::InvalidMeasurement);
            }
        }
        if self.reachable && self.rtt_ms.is_none() {
            return Err(PeerStoreError::InvalidMeasurement);
        }
        if (!self.reachable && self.rtt_ms.is_some())
            || (self.rtt_ms.is_none() && self.jitter_ms.is_some())
            || (!self.reachable && !self.delivery_rate.is_zero())
        {
            return Err(PeerStoreError::InvalidMeasurement);
        }
        Ok(())
    }
}

/// Most recently observed control/dataplane endpoint for a peer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EndpointObservation {
    /// Bounded peer multiaddress or endpoint text.
    pub endpoint: String,
    /// Locally observed public address when available.
    pub observed_ip: Option<IpAddr>,
    /// Result of the most recent light reachability probe.
    pub reachable: bool,
    /// Most recent observation time.
    pub last_seen_at: UnixTime,
    /// Most recent successful reachability time.
    pub last_reachable_at: Option<UnixTime>,
}

/// Bounded local reputation evidence, independent of browsing activity.
#[derive(Clone, Debug, PartialEq)]
pub struct LocalPeerEvidence {
    /// Most recent RTT.
    pub latest_rtt_ms: Option<f64>,
    /// Most recent jitter.
    pub latest_jitter_ms: Option<f64>,
    /// Most recent packet-loss ratio.
    pub latest_loss_ratio: Option<f64>,
    /// Component-wise p25 of bounded local delivery samples.
    pub delivery_p25: Option<Bandwidth>,
    /// Fraction of retained samples that were reachable.
    pub uptime_score: Option<f64>,
    /// Number of retained samples.
    pub measurement_count: usize,
    /// Saturating count of locally failed reservations.
    pub reservation_failures: u32,
    /// Saturating count of protocol faults.
    pub protocol_faults: u32,
    /// Saturating count of severe protocol faults.
    pub severe_protocol_faults: u32,
    /// Active serious-fault cool-down.
    pub serious_protocol_fault_until: Option<UnixTime>,
    /// Most recent successful route session with this peer.
    pub last_successful_session_at: Option<UnixTime>,
}

impl LocalPeerEvidence {
    /// Computes a transparent local-only reputation score from counters and
    /// retained reachability.  It is never advertised as universal truth.
    #[must_use]
    pub fn reputation_score(&self) -> f64 {
        let uptime = self.uptime_score.unwrap_or(0.5);
        let penalty = f64::from(self.reservation_failures.min(20)) * 0.015
            + f64::from(self.protocol_faults.min(10)) * 0.05
            + f64::from(self.severe_protocol_faults.min(5)) * 0.15;
        (0.25 + uptime * 0.75 - penalty).clamp(0.0, 1.0)
    }
}

/// Advertisement, last endpoint and locally retained performance evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredPeer {
    /// Most recent valid signed advertisement body supplied by the protocol layer.
    pub advertisement: NodeAdvertisement,
    /// Exact canonical signed envelope accepted from the authenticated provider peer.
    signed_advertisement_envelope: Vec<u8>,
    /// Most recently observed endpoint.
    pub latest_endpoint: Option<EndpointObservation>,
    /// Local performance and reputation evidence.
    pub evidence: LocalPeerEvidence,
}

impl StoredPeer {
    /// Borrows the exact bounded envelope retained as cryptographic provenance.
    #[must_use]
    pub fn signed_advertisement_envelope(&self) -> &[u8] {
        &self.signed_advertisement_envelope
    }
}

/// SQLite-backed local peer observations.
#[derive(Debug)]
pub struct PeerStore {
    connection: Connection,
}

impl PeerStore {
    /// Opens or creates a store and applies the bounded version-two schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened, configured, migrated, or audited, or
    /// when its schema version is unsupported.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PeerStoreError> {
        let flags = OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(path, flags)?;
        Self::from_connection(connection)
    }

    /// Creates an isolated in-memory store, primarily useful for short-lived
    /// agents and unit tests.
    ///
    /// # Errors
    ///
    /// Returns an error when the in-memory database cannot be opened, configured, initialised, or
    /// privacy-audited.
    pub fn open_in_memory() -> Result<Self, PeerStoreError> {
        let connection = Connection::open_in_memory()?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, PeerStoreError> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF; PRAGMA synchronous = FULL; PRAGMA journal_mode = WAL;",
        )?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        match version {
            0 => connection.execute_batch(SCHEMA)?,
            1 => {
                // Version one has no signed proof. Its rows and privacy-safe observations remain
                // recoverable, but the new nullable proof column leaves them quarantined: every
                // candidate query below requires a non-null envelope.
                connection.execute_batch(MIGRATE_V1_TO_V2)?;
            }
            SCHEMA_VERSION => {}
            other => return Err(PeerStoreError::UnsupportedSchemaVersion(other)),
        }
        let store = Self { connection };
        store.audit_schema()?;
        store.audit_privacy_schema()?;
        Ok(store)
    }

    /// Atomically stores a strictly newer, currently valid advertisement and
    /// the exact signed envelope already verified against its authenticated peer.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized envelope, invalid, stale, oversized, or
    /// unrepresentable advertisement, JSON encoding failure, or an `SQLite` transaction failure.
    /// No partial update is committed. The protocol consumer must perform canonical decoding,
    /// signature verification and authenticated-peer binding before calling this persistence API;
    /// readers must repeat those checks before granting a peer capability.
    pub fn upsert_advertisement(
        &mut self,
        advertisement: &NodeAdvertisement,
        signed_advertisement_envelope: &[u8],
        now: UnixTime,
    ) -> Result<(), PeerStoreError> {
        validate_signed_advertisement_envelope(signed_advertisement_envelope)?;
        advertisement.validate_at(now)?;
        let sequence_number = to_sql_integer(advertisement.sequence_number)?;
        let measured_at = to_sql_time(advertisement.measured_at)?;
        let expires_at = to_sql_time(advertisement.expires_at)?;
        let stored_at = to_sql_time(now)?;
        let serialized = serde_json::to_vec(advertisement)?;
        if serialized.len() > MAX_SERIALIZED_ADVERTISEMENT_BYTES {
            return Err(PeerStoreError::AdvertisementTooLarge);
        }

        let transaction = self.connection.transaction()?;
        let existing: Option<i64> = transaction
            .query_row(
                "SELECT sequence_number FROM advertisements
                 WHERE node_id = ?1
                   AND signed_advertisement_envelope IS NOT NULL",
                params![advertisement.node_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_some_and(|sequence| sequence >= sequence_number) {
            return Err(PeerStoreError::StaleAdvertisement);
        }
        transaction.execute(
            "INSERT INTO advertisements (
                node_id, peer_id, sequence_number, protocol_version, policy_hash,
                advertisement_json, signed_advertisement_envelope,
                measured_at, expires_at, stored_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(node_id) DO UPDATE SET
                peer_id = excluded.peer_id,
                sequence_number = excluded.sequence_number,
                protocol_version = excluded.protocol_version,
                policy_hash = excluded.policy_hash,
                advertisement_json = excluded.advertisement_json,
                signed_advertisement_envelope = excluded.signed_advertisement_envelope,
                measured_at = excluded.measured_at,
                expires_at = excluded.expires_at,
                stored_at = excluded.stored_at",
            params![
                advertisement.node_id.as_str(),
                advertisement.peer_id.as_str(),
                sequence_number,
                i64::from(advertisement.protocol_version),
                advertisement.policy_hash.as_bytes().as_slice(),
                serialized,
                signed_advertisement_envelope,
                measured_at,
                expires_at,
                stored_at,
            ],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO peer_reputation(node_id) VALUES (?1)",
            params![advertisement.node_id.as_str()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Records a bounded endpoint observation and retains at most sixteen per peer.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid endpoint, unknown peer, unrepresentable timestamp, or an
    /// `SQLite` transaction failure. No partial update is committed.
    pub fn record_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: &str,
        observed_ip: Option<IpAddr>,
        reachable: bool,
        now: UnixTime,
    ) -> Result<(), PeerStoreError> {
        validate_endpoint(endpoint)?;
        let now = to_sql_time(now)?;
        let transaction = self.connection.transaction()?;
        ensure_peer_exists(&transaction, node_id)?;
        let previous_reachable: Option<i64> = transaction
            .query_row(
                "SELECT last_reachable_at FROM endpoints WHERE node_id = ?1 AND endpoint = ?2",
                params![node_id.as_str(), endpoint],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        let last_reachable = if reachable {
            Some(now)
        } else {
            previous_reachable
        };
        let observed_ip = observed_ip.map(|address| address.to_string());
        transaction.execute(
            "INSERT INTO endpoints(
                node_id, endpoint, observed_ip, reachable, last_seen_at, last_reachable_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(node_id, endpoint) DO UPDATE SET
                observed_ip = excluded.observed_ip,
                reachable = excluded.reachable,
                last_seen_at = excluded.last_seen_at,
                last_reachable_at = excluded.last_reachable_at",
            params![
                node_id.as_str(),
                endpoint,
                observed_ip,
                i64::from(reachable),
                now,
                last_reachable,
            ],
        )?;
        transaction.execute(
            "DELETE FROM endpoints
             WHERE node_id = ?1 AND endpoint NOT IN (
                SELECT endpoint FROM endpoints WHERE node_id = ?1
                ORDER BY last_seen_at DESC, endpoint ASC LIMIT ?2
             )",
            params![node_id.as_str(), usize_to_i64(MAX_ENDPOINTS_PER_PEER)?],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Records one controlled local measurement and trims the peer's history.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid measurement fields, an unknown peer, unrepresentable values,
    /// or an `SQLite` transaction failure. No partial update is committed.
    pub fn record_measurement(
        &mut self,
        node_id: &NodeId,
        measurement: PeerMeasurement,
    ) -> Result<(), PeerStoreError> {
        measurement.validate()?;
        let observed_at = to_sql_time(measurement.observed_at)?;
        let transaction = self.connection.transaction()?;
        ensure_peer_exists(&transaction, node_id)?;
        transaction.execute(
            "INSERT INTO measurements(
                node_id, observed_at, reachable, rtt_ms, jitter_ms, loss_ratio,
                delivery_up_mbps, delivery_down_mbps
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                node_id.as_str(),
                observed_at,
                i64::from(measurement.reachable),
                measurement.rtt_ms,
                measurement.jitter_ms,
                measurement.loss_ratio,
                i64::from(measurement.delivery_rate.up_mbps),
                i64::from(measurement.delivery_rate.down_mbps),
            ],
        )?;
        transaction.execute(
            "DELETE FROM measurements
             WHERE node_id = ?1 AND sample_id NOT IN (
                SELECT sample_id FROM measurements WHERE node_id = ?1
                ORDER BY observed_at DESC, sample_id DESC LIMIT ?2
             )",
            params![node_id.as_str(), usize_to_i64(MAX_MEASUREMENTS_PER_PEER)?],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Increments the local failed-reservation counter with saturation.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer is unknown or the `SQLite` update fails.
    pub fn record_reservation_failure(&mut self, node_id: &NodeId) -> Result<(), PeerStoreError> {
        self.increment_counter(node_id, "reservation_failures")
    }

    /// Records a protocol fault and optional severe-fault cool-down.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer is unknown, the cool-down timestamp cannot be represented,
    /// or the `SQLite` transaction fails.
    pub fn record_protocol_fault(
        &mut self,
        node_id: &NodeId,
        severe_until: Option<UnixTime>,
    ) -> Result<(), PeerStoreError> {
        let severe_until = severe_until.map(to_sql_time).transpose()?;
        let transaction = self.connection.transaction()?;
        ensure_peer_exists(&transaction, node_id)?;
        transaction.execute(
            "UPDATE peer_reputation SET
                protocol_faults = MIN(protocol_faults + 1, ?2),
                severe_protocol_faults = MIN(
                    severe_protocol_faults + CASE WHEN ?3 IS NULL THEN 0 ELSE 1 END,
                    ?2
                ),
                severe_fault_until = CASE
                    WHEN ?3 IS NULL THEN severe_fault_until
                    WHEN severe_fault_until IS NULL OR severe_fault_until < ?3 THEN ?3
                    ELSE severe_fault_until
                END
             WHERE node_id = ?1",
            params![node_id.as_str(), i64::from(MAX_COUNTER), severe_until],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Records only the time of a successful peer session, with no flow or origin.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer is unknown, the timestamp cannot be represented, or the
    /// `SQLite` update fails.
    pub fn record_successful_session(
        &mut self,
        node_id: &NodeId,
        now: UnixTime,
    ) -> Result<(), PeerStoreError> {
        let changed = self.connection.execute(
            "UPDATE peer_reputation SET last_successful_session_at = ?2
             WHERE node_id = ?1 AND EXISTS (
                SELECT 1 FROM advertisements
                WHERE advertisements.node_id = peer_reputation.node_id
                  AND signed_advertisement_envelope IS NOT NULL)",
            params![node_id.as_str(), to_sql_time(now)?],
        )?;
        if changed == 0 {
            return Err(PeerStoreError::UnknownPeer);
        }
        Ok(())
    }

    /// Loads up to the bounded candidate-pool limit, excluding expired entries.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit, `SQLite` or JSON failure, or persisted
    /// advertisements, endpoints, measurements, counters, addresses, or timestamps that violate
    /// their defensive bounds.
    pub fn load_candidates(
        &self,
        now: UnixTime,
        limit: usize,
    ) -> Result<Vec<StoredPeer>, PeerStoreError> {
        if limit == 0 || limit > MAX_LOAD_LIMIT {
            return Err(PeerStoreError::InvalidLoadLimit);
        }
        let mut statement = self.connection.prepare(
            "SELECT advertisement_json, signed_advertisement_envelope FROM advertisements
             WHERE expires_at > ?1
               AND signed_advertisement_envelope IS NOT NULL
               AND length(signed_advertisement_envelope) BETWEEN 1 AND 262144
             ORDER BY stored_at DESC, node_id ASC LIMIT ?2",
        )?;
        let serialized: Vec<(Vec<u8>, Vec<u8>)> = statement
            .query_map(params![to_sql_time(now)?, usize_to_i64(limit)?], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<Result<_, _>>()?;
        drop(statement);
        let mut peers = Vec::with_capacity(serialized.len());
        for (bytes, signed_advertisement_envelope) in serialized {
            if bytes.len() > MAX_SERIALIZED_ADVERTISEMENT_BYTES {
                return Err(PeerStoreError::AdvertisementTooLarge);
            }
            validate_signed_advertisement_envelope(&signed_advertisement_envelope)?;
            let advertisement: NodeAdvertisement = serde_json::from_slice(&bytes)?;
            advertisement.validate_at(now)?;
            let latest_endpoint = self.load_latest_endpoint(&advertisement.node_id)?;
            let evidence = self.load_evidence(&advertisement.node_id)?;
            peers.push(StoredPeer {
                advertisement,
                signed_advertisement_envelope,
                latest_endpoint,
                evidence,
            });
        }
        Ok(peers)
    }

    /// Deletes advertisements expired for at least `retention_seconds`; foreign
    /// keys cascade to endpoints, measurements and counters.
    ///
    /// # Errors
    ///
    /// Returns an error when the calculated threshold cannot be represented by `SQLite` or the
    /// deletion fails.
    pub fn prune_expired(
        &mut self,
        now: UnixTime,
        retention_seconds: u64,
    ) -> Result<usize, PeerStoreError> {
        let threshold = now.as_secs().saturating_sub(retention_seconds);
        let deleted = self.connection.execute(
            "DELETE FROM advertisements WHERE expires_at <= ?1",
            params![to_sql_integer(threshold)?],
        )?;
        Ok(deleted)
    }

    /// Verifies that the actual `SQLite` schema has no browsing-history or secret fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema cannot be queried or contains a forbidden field name.
    pub fn audit_privacy_schema(&self) -> Result<(), PeerStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT lower(sql) FROM sqlite_schema
             WHERE sql IS NOT NULL AND type IN ('table', 'index')",
        )?;
        let definitions: Vec<String> = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        let forbidden = [
            "hostname",
            "url_history",
            "dns_query",
            "destination_ip",
            "browse",
            "origin_key",
            "route_context",
            "flow_id",
            "private_key",
            "payload",
        ];
        if definitions
            .iter()
            .any(|definition| forbidden.iter().any(|term| definition.contains(term)))
        {
            return Err(PeerStoreError::PrivacySchemaViolation);
        }
        Ok(())
    }

    fn audit_schema(&self) -> Result<(), PeerStoreError> {
        let version: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(PeerStoreError::SchemaAudit);
        }
        let table_sql: String = self.connection.query_row(
            "SELECT lower(sql) FROM sqlite_schema
             WHERE type = 'table' AND name = 'advertisements'",
            [],
            |row| row.get(0),
        )?;
        let normalized = table_sql.split_whitespace().collect::<Vec<_>>().join(" ");
        if !normalized.contains("signed_advertisement_envelope blob check")
            || !normalized.contains("signed_advertisement_envelope is null or")
            || !normalized.contains("length(signed_advertisement_envelope) between 1 and 262144")
        {
            return Err(PeerStoreError::SchemaAudit);
        }
        let integrity: String = self
            .connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(PeerStoreError::SchemaAudit);
        }
        let foreign_key_violation: Option<String> = self
            .connection
            .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
            .optional()?;
        if foreign_key_violation.is_some() {
            return Err(PeerStoreError::SchemaAudit);
        }
        Ok(())
    }

    fn increment_counter(
        &mut self,
        node_id: &NodeId,
        column: &'static str,
    ) -> Result<(), PeerStoreError> {
        let sql = match column {
            "reservation_failures" => {
                "UPDATE peer_reputation SET reservation_failures =
                 MIN(reservation_failures + 1, ?2)
                 WHERE node_id = ?1 AND EXISTS (
                    SELECT 1 FROM advertisements
                    WHERE advertisements.node_id = peer_reputation.node_id
                      AND signed_advertisement_envelope IS NOT NULL)"
            }
            _ => return Err(PeerStoreError::InvalidCounter),
        };
        let changed = self
            .connection
            .execute(sql, params![node_id.as_str(), i64::from(MAX_COUNTER)])?;
        if changed == 0 {
            return Err(PeerStoreError::UnknownPeer);
        }
        Ok(())
    }

    fn load_latest_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<EndpointObservation>, PeerStoreError> {
        let row: Option<EndpointRow> = self
            .connection
            .query_row(
                "SELECT endpoint, observed_ip, reachable, last_seen_at, last_reachable_at
                 FROM endpoints WHERE node_id = ?1
                 ORDER BY last_seen_at DESC, endpoint ASC LIMIT 1",
                params![node_id.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(endpoint, observed_ip, reachable, seen, reached)| {
            let observed_ip = observed_ip
                .map(|value| value.parse())
                .transpose()
                .map_err(|_| PeerStoreError::CorruptObservedAddress)?;
            Ok(EndpointObservation {
                endpoint,
                observed_ip,
                reachable,
                last_seen_at: from_sql_time(seen)?,
                last_reachable_at: reached.map(from_sql_time).transpose()?,
            })
        })
        .transpose()
    }

    fn load_evidence(&self, node_id: &NodeId) -> Result<LocalPeerEvidence, PeerStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT reachable, rtt_ms, jitter_ms, loss_ratio,
                    delivery_up_mbps, delivery_down_mbps
             FROM measurements WHERE node_id = ?1
             ORDER BY observed_at DESC, sample_id DESC",
        )?;
        let samples: Vec<MeasurementRow> = statement
            .query_map(params![node_id.as_str()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        let latest = samples.first();
        let mut upload: Vec<u32> = samples.iter().map(|sample| sample.4).collect();
        let mut download: Vec<u32> = samples.iter().map(|sample| sample.5).collect();
        upload.sort_unstable();
        download.sort_unstable();
        let delivery_p25 = if upload.is_empty() {
            None
        } else {
            let index = (upload.len() - 1) / 4;
            Some(
                Bandwidth::new(upload[index], download[index])
                    .map_err(|_| PeerStoreError::CorruptMeasurement)?,
            )
        };
        let reachable_count = u32::try_from(samples.iter().filter(|sample| sample.0).count())
            .map_err(|_| PeerStoreError::CorruptMeasurement)?;
        let sample_count =
            u32::try_from(samples.len()).map_err(|_| PeerStoreError::CorruptMeasurement)?;
        let uptime_score =
            (sample_count != 0).then(|| f64::from(reachable_count) / f64::from(sample_count));
        let counters: (u32, u32, u32, Option<i64>, Option<i64>) = self.connection.query_row(
            "SELECT reservation_failures, protocol_faults, severe_protocol_faults,
                    severe_fault_until, last_successful_session_at
             FROM peer_reputation WHERE node_id = ?1",
            params![node_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        Ok(LocalPeerEvidence {
            latest_rtt_ms: latest.and_then(|sample| sample.1),
            latest_jitter_ms: latest.and_then(|sample| sample.2),
            latest_loss_ratio: latest.map(|sample| sample.3),
            delivery_p25,
            uptime_score,
            measurement_count: samples.len(),
            reservation_failures: counters.0,
            protocol_faults: counters.1,
            severe_protocol_faults: counters.2,
            serious_protocol_fault_until: counters.3.map(from_sql_time).transpose()?,
            last_successful_session_at: counters.4.map(from_sql_time).transpose()?,
        })
    }
}

fn ensure_peer_exists(
    transaction: &Transaction<'_>,
    node_id: &NodeId,
) -> Result<(), PeerStoreError> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM advertisements
            WHERE node_id = ?1 AND signed_advertisement_envelope IS NOT NULL)",
        params![node_id.as_str()],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(PeerStoreError::UnknownPeer);
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<(), PeerStoreError> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_ENDPOINT_BYTES
        || endpoint.bytes().any(|byte| byte == 0 || !byte.is_ascii())
    {
        return Err(PeerStoreError::InvalidEndpoint);
    }
    Ok(())
}

fn validate_signed_advertisement_envelope(envelope: &[u8]) -> Result<(), PeerStoreError> {
    if envelope.is_empty() {
        return Err(PeerStoreError::MissingAdvertisementProvenance);
    }
    if envelope.len() > MAX_SIGNED_ADVERTISEMENT_ENVELOPE_BYTES {
        return Err(PeerStoreError::AdvertisementEnvelopeTooLarge);
    }
    Ok(())
}

fn to_sql_time(value: UnixTime) -> Result<i64, PeerStoreError> {
    to_sql_integer(value.as_secs())
}

fn to_sql_integer(value: u64) -> Result<i64, PeerStoreError> {
    i64::try_from(value).map_err(|_| PeerStoreError::IntegerOutOfRange)
}

fn usize_to_i64(value: usize) -> Result<i64, PeerStoreError> {
    i64::try_from(value).map_err(|_| PeerStoreError::IntegerOutOfRange)
}

fn from_sql_time(value: i64) -> Result<UnixTime, PeerStoreError> {
    let value = u64::try_from(value).map_err(|_| PeerStoreError::CorruptTimestamp)?;
    Ok(UnixTime::from_secs(value))
}

/// Persistence, validation or privacy-schema failure.
#[derive(Debug, Error)]
pub enum PeerStoreError {
    /// `SQLite` operation failed.
    #[error("SQLite peerstore error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Advertisement JSON encoding or decoding failed.
    #[error("peer advertisement encoding error: {0}")]
    Json(#[from] serde_json::Error),
    /// Advertisement validation failed.
    #[error("invalid advertisement: {0}")]
    Advertisement(#[from] AdvertisementError),
    /// Cryptographic advertisement provenance is absent.
    #[error("signed advertisement provenance is empty")]
    MissingAdvertisementProvenance,
    /// The signed advertisement envelope exceeds the fixed protocol allocation bound.
    #[error("signed advertisement envelope exceeds the peerstore bound")]
    AdvertisementEnvelopeTooLarge,
    /// The advertisement sequence is replayed or older than the stored value.
    #[error("stale advertisement sequence")]
    StaleAdvertisement,
    /// The bounded serialized advertisement is too large.
    #[error("serialized advertisement exceeds the peerstore bound")]
    AdvertisementTooLarge,
    /// A measurement is non-finite, inconsistent or outside defensive bounds.
    #[error("invalid peer measurement")]
    InvalidMeasurement,
    /// A control endpoint is empty, unsafe or too large.
    #[error("invalid peer endpoint")]
    InvalidEndpoint,
    /// A referenced peer has no accepted advertisement.
    #[error("unknown peer")]
    UnknownPeer,
    /// Candidate load limit is zero or above the defensive maximum.
    #[error("invalid peer load limit")]
    InvalidLoadLimit,
    /// `SQLite` schema version is newer or otherwise unsupported.
    #[error("unsupported peerstore schema version {0}")]
    UnsupportedSchemaVersion(i64),
    /// The claimed schema version or required provenance constraint failed its audit.
    #[error("peerstore schema audit failed")]
    SchemaAudit,
    /// An unsigned integer cannot be represented safely in `SQLite`.
    #[error("integer is outside SQLite's signed range")]
    IntegerOutOfRange,
    /// A stored timestamp is negative or corrupt.
    #[error("corrupt timestamp in peerstore")]
    CorruptTimestamp,
    /// A stored observed IP address cannot be parsed.
    #[error("corrupt observed address in peerstore")]
    CorruptObservedAddress,
    /// A stored measurement violates the domain bounds.
    #[error("corrupt measurement in peerstore")]
    CorruptMeasurement,
    /// Internal counter dispatch received an unknown field.
    #[error("invalid reputation counter")]
    InvalidCounter,
    /// The actual `SQLite` schema contains a forbidden browsing/secret field.
    #[error("peerstore schema violates privacy boundary")]
    PrivacySchemaViolation,
}
