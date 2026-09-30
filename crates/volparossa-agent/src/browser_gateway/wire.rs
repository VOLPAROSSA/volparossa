//! Tiny independent app bootstrap: 4-byte BE length plus strict bounded UTF-8 JSON.

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

use super::{Attachment, GatewayError, Scope};

const MAX_BOOTSTRAP_FRAME: usize = 4096;
const DIRECT_DECISION_LIFETIME_MS: u64 = 5_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    version: u32,
    capability: String,
    partition: String,
}

#[derive(Serialize)]
struct Ready<'a> {
    version: u32,
    proxy_host: &'static str,
    proxy_port: u16,
    proxy_authorization: String,
    hostname: &'a str,
    port: u16,
    partition: String,
    expires_at_ms: u64,
    overlay_only: bool,
}

#[derive(Serialize)]
struct Failure<'a> {
    version: u32,
    status: &'static str,
    reason: &'static str,
    hostname: &'a str,
    port: u16,
    partition: String,
    expires_at_ms: u64,
    direct_until_ms: u64,
}

/// This authorizes only a browser decision outside the overlay with its killswitch off.
/// It never relaxes the exit policy or permits a client-to-exit dataplane connection.
pub(super) fn direct_deadline(
    error: GatewayError,
    retired: bool,
    running: bool,
    scope: &Scope,
    current_policy_expiry: Option<u64>,
) -> u64 {
    if !matches!(error, GatewayError::NoEligiblePaths) || !retired || !running || !scope.live() {
        return 0;
    }
    let Some(policy_expiry) = current_policy_expiry else {
        return 0;
    };
    let now = crate::unix_millis();
    let remaining = scope
        .deadline
        .saturating_duration_since(tokio::time::Instant::now());
    let remaining_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
    let until = now
        .saturating_add(DIRECT_DECISION_LIFETIME_MS.min(remaining_ms))
        .min(scope.expires_at_ms)
        .min(policy_expiry);
    if until > now { until } else { 0 }
}

pub(super) async fn write_failure(
    stream: &mut UnixStream,
    attachment: &Attachment,
    direct_until_ms: u64,
) -> Result<(), GatewayError> {
    let permitted = direct_until_ms > crate::unix_millis();
    let response = Failure {
        version: 1,
        status: if permitted { "unavailable" } else { "denied" },
        reason: if permitted {
            "no_eligible_paths"
        } else {
            "blocked"
        },
        hostname: &attachment.scope.hostname,
        port: attachment.scope.port,
        partition: hex::encode(attachment.scope.partition),
        expires_at_ms: attachment.scope.expires_at_ms,
        direct_until_ms: if permitted { direct_until_ms } else { 0 },
    };
    write_response(stream, &response).await
}

pub(super) async fn read_bootstrap(
    stream: &mut UnixStream,
) -> Result<([u8; 32], [u8; 32]), GatewayError> {
    let length = stream.read_u32().await.map_err(|_| GatewayError::Invalid)? as usize;
    if length == 0 || length > MAX_BOOTSTRAP_FRAME {
        return Err(GatewayError::Invalid);
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| GatewayError::Invalid)?;
    decode(&bytes)
}

fn decode(bytes: &[u8]) -> Result<([u8; 32], [u8; 32]), GatewayError> {
    if bytes.len() > MAX_BOOTSTRAP_FRAME {
        return Err(GatewayError::Invalid);
    }
    let request: Bootstrap = serde_json::from_slice(bytes).map_err(|_| GatewayError::Invalid)?;
    if request.version != 1 {
        return Err(GatewayError::Invalid);
    }
    Ok((
        fixed_hex(&request.capability)?,
        fixed_hex(&request.partition)?,
    ))
}

fn fixed_hex(value: &str) -> Result<[u8; 32], GatewayError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayError::Invalid);
    }
    let mut result = [0; 32];
    hex::decode_to_slice(value, &mut result).map_err(|_| GatewayError::Invalid)?;
    Ok(result)
}

pub(super) async fn write_ready(
    stream: &mut UnixStream,
    attachment: &Attachment,
    port: u16,
) -> Result<(), GatewayError> {
    let response = Ready {
        version: 1,
        proxy_host: "127.0.0.1",
        proxy_port: port,
        proxy_authorization: format!("Bearer {}", hex::encode(attachment.proxy_secret)),
        hostname: &attachment.scope.hostname,
        port: attachment.scope.port,
        partition: hex::encode(attachment.scope.partition),
        expires_at_ms: attachment.scope.expires_at_ms,
        overlay_only: true,
    };
    write_response(stream, &response).await
}

async fn write_response(
    stream: &mut UnixStream,
    response: &impl Serialize,
) -> Result<(), GatewayError> {
    let bytes = serde_json::to_vec(response).map_err(|_| GatewayError::Unavailable)?;
    let length = u32::try_from(bytes.len()).map_err(|_| GatewayError::Unavailable)?;
    if bytes.len() > MAX_BOOTSTRAP_FRAME {
        return Err(GatewayError::Unavailable);
    }
    stream
        .write_u32(length)
        .await
        .map_err(|_| GatewayError::Unavailable)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| GatewayError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_confirmed_clean_live_candidate_shortage_can_authorize_short_direct_decision() {
        let mut scope = super::super::tests::scope(1);
        let deadline = direct_deadline(
            GatewayError::NoEligiblePaths,
            true,
            true,
            &scope,
            Some(scope.expires_at_ms),
        );
        assert!(deadline > crate::unix_millis());
        assert!(deadline <= crate::unix_millis() + DIRECT_DECISION_LIFETIME_MS);
        for (error, retired, running, expiry) in [
            (
                GatewayError::Unavailable,
                true,
                true,
                Some(scope.expires_at_ms),
            ),
            (GatewayError::Policy, true, true, Some(scope.expires_at_ms)),
            (GatewayError::Invalid, true, true, Some(scope.expires_at_ms)),
            (GatewayError::Busy, true, true, Some(scope.expires_at_ms)),
            (
                GatewayError::NoEligiblePaths,
                false,
                true,
                Some(scope.expires_at_ms),
            ),
            (
                GatewayError::NoEligiblePaths,
                true,
                false,
                Some(scope.expires_at_ms),
            ),
            (GatewayError::NoEligiblePaths, true, true, None),
            (GatewayError::NoEligiblePaths, true, true, Some(0)),
        ] {
            assert_eq!(direct_deadline(error, retired, running, &scope, expiry), 0);
        }
        scope.deadline = tokio::time::Instant::now();
        assert_eq!(
            direct_deadline(
                GatewayError::NoEligiblePaths,
                true,
                true,
                &scope,
                Some(scope.expires_at_ms)
            ),
            0
        );
    }

    #[tokio::test]
    async fn scoped_terminal_frame_has_no_proxy_capability_and_never_extends_grant() {
        let scope = std::sync::Arc::new(super::super::tests::scope(3));
        let attachment = Attachment {
            key: [1; 32],
            scope,
            routes: crate::route_setup::ClientRouteControl::new("/absent/mpquic.sock".into()),
            proxy_secret: [4; 32],
        };
        let (mut server, mut client) = UnixStream::pair().unwrap();
        for allowed in [false, true] {
            let until = if allowed {
                direct_deadline(
                    GatewayError::NoEligiblePaths,
                    true,
                    true,
                    &attachment.scope,
                    Some(attachment.scope.expires_at_ms),
                )
            } else {
                0
            };
            write_failure(&mut server, &attachment, until)
                .await
                .unwrap_or_else(|_| panic!("frame"));
            let length = client.read_u32().await.unwrap() as usize;
            assert!(length <= MAX_BOOTSTRAP_FRAME);
            let mut bytes = vec![0; length];
            client.read_exact(&mut bytes).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value.as_object().unwrap().len(), 8);
            assert_eq!(
                value["status"],
                if allowed { "unavailable" } else { "denied" }
            );
            assert_eq!(
                value["reason"],
                if allowed {
                    "no_eligible_paths"
                } else {
                    "blocked"
                }
            );
            assert_eq!(value["hostname"], attachment.scope.hostname);
            assert_eq!(value["partition"], hex::encode(attachment.scope.partition));
            assert_eq!(value["expires_at_ms"], attachment.scope.expires_at_ms);
            assert_eq!(value["direct_until_ms"], until);
        }
    }

    #[test]
    fn bootstrap_is_not_an_admin_request_and_rejects_ambiguous_scope() {
        let request = serde_json::json!({"version":1,"capability":"ab".repeat(32),"partition":"cd".repeat(32)});
        assert!(decode(&serde_json::to_vec(&request).unwrap()).is_ok());
        for bad in [
            serde_json::json!({"version":1,"capability":"AB".repeat(32),"partition":"cd".repeat(32)}),
            serde_json::json!({"version":1,"capability":"ab".repeat(32),"partition":"cd".repeat(31)}),
            serde_json::json!({"version":1,"capability":"ab".repeat(32),"partition":"cd".repeat(32),"operation":"disconnect"}),
            serde_json::json!({"version":2,"capability":"ab".repeat(32),"partition":"cd".repeat(32)}),
        ] {
            assert!(decode(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        assert!(decode(b"{\"version\":1,\"version\":1}").is_err());
        assert!(decode(&[0; MAX_BOOTSTRAP_FRAME + 1]).is_err());
    }
}
