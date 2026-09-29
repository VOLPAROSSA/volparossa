//! Tiny independent app bootstrap: 4-byte BE length plus strict bounded UTF-8 JSON.

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

use super::{Attachment, GatewayError};

const MAX_BOOTSTRAP_FRAME: usize = 4096;

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
    let bytes = serde_json::to_vec(&response).map_err(|_| GatewayError::Unavailable)?;
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
