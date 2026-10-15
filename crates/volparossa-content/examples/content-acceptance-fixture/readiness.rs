//! One normal guarded discovery request. The fixture never supplies desired providers.
use std::{fs::OpenOptions, io::Read as _, os::unix::fs::OpenOptionsExt as _, path::Path};

use rand_core::RngCore as _;
use serde_json::json;
use tokio::net::UnixStream;
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentCustodyDiscoverRequest, ControlRequest, ControlResult,
    control_request::Operation, control_response::Payload, read_response, write_request,
};

pub(super) async fn discover(socket: &Path, manifest: &Path, publisher: &str) -> super::Result<()> {
    let publisher_key = hex::decode(publisher)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits(),
        )?)
        .open(manifest)?;
    let info = file.metadata()?;
    if !info.is_file() || info.len() == 0 || info.len() > 65536 {
        return Err("invalid readiness manifest".into());
    }
    let mut manifest = Vec::new();
    file.by_ref().take(65537).read_to_end(&mut manifest)?;
    let mut request_id = [0; 16];
    rand_core::OsRng.fill_bytes(&mut request_id);
    let request = ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: request_id.to_vec(),
        operation: Some(Operation::ContentCustodyDiscover(
            ContentCustodyDiscoverRequest {
                manifest,
                publisher_key,
                max_providers: 16,
            },
        )),
    };
    println!("{}", query(socket, &request).await?);
    Ok(())
}

async fn query(socket: &Path, request: &ControlRequest) -> super::Result<serde_json::Value> {
    // The owner supervises one absolute preparation deadline and closes this socket
    // on termination. No retry, data fetch, cache path or provider selector exists here.
    let mut stream = UnixStream::connect(socket).await?;
    write_request(&mut stream, request).await?;
    let response = read_response(&mut stream).await?;
    if response.request_id != request.request_id || response.result != ControlResult::Ok as i32 {
        return Err("readiness request rejected".into());
    }
    let Some(Payload::ContentCustodyDiscovered(found)) = response.payload else {
        return Err("unexpected readiness response".into());
    };
    let mut providers = Vec::new();
    for offer in found.providers {
        let key = libp2p_identity::ed25519::PublicKey::try_from_bytes(&offer.provider_key)?;
        let key = libp2p_identity::PublicKey::from(key);
        providers.push(json!({"peer_id": key.to_peer_id().to_string(),
            "offer_expires_unix_seconds": offer.offer_expires_unix_seconds}));
    }
    Ok(
        json!({"schema_version": 1, "kind": "content-provider-discovery-readiness",
        "control_relay_peer_id": found.control_relay_peer_id, "providers": providers}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::AsyncReadExt as _,
        net::UnixListener,
        sync::oneshot,
        time::{Duration, timeout},
    };
    use volparossa_local_control::{
        ContentCustodyDiscovered, ContentCustodyProvider, ControlResponse, read_request,
        write_response,
    };

    fn request() -> ControlRequest {
        ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![7; 16],
            operation: Some(Operation::ContentCustodyDiscover(
                ContentCustodyDiscoverRequest {
                    manifest: vec![1, 2, 3],
                    publisher_key: vec![8; 32],
                    max_providers: 16,
                },
            )),
        }
    }

    #[tokio::test]
    async fn one_typed_request_correlates_and_converts_only_authenticated_reply_keys() {
        for mode in ["ok", "wrong-id", "denied"] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("agent.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                .verifying_key()
                .to_bytes();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await.unwrap();
                let Some(Operation::ContentCustodyDiscover(discover)) = request.operation else {
                    panic!("unexpected operation")
                };
                assert_eq!(discover.manifest, [1, 2, 3]);
                assert_eq!(discover.publisher_key, [8; 32]);
                assert_eq!(discover.max_providers, 16);
                let response = ControlResponse {
                    protocol_version: CONTROL_PROTOCOL_VERSION,
                    request_id: if mode == "wrong-id" {
                        vec![0; 16]
                    } else {
                        request.request_id
                    },
                    result: if mode == "denied" {
                        ControlResult::Policy
                    } else {
                        ControlResult::Ok
                    } as i32,
                    diagnostic_code: "CONTENT_CUSTODY_DISCOVERED".into(),
                    private_storage_remote_detail: None,
                    payload: Some(Payload::ContentCustodyDiscovered(
                        ContentCustodyDiscovered {
                            control_relay_peer_id: "broker".into(),
                            providers: vec![ContentCustodyProvider {
                                provider_key: key.to_vec(),
                                offer_expires_unix_seconds: 12345,
                            }],
                        },
                    )),
                };
                write_response(&mut stream, &response).await.unwrap();
                let mut byte = [0];
                assert_eq!(
                    stream.read(&mut byte).await.unwrap(),
                    0,
                    "no second request or payload stream"
                );
            });
            let result = timeout(Duration::from_secs(2), query(&socket, &request()))
                .await
                .unwrap();
            if mode == "ok" {
                let key = libp2p_identity::PublicKey::from(
                    libp2p_identity::ed25519::PublicKey::try_from_bytes(&key).unwrap(),
                );
                assert_eq!(
                    result.unwrap(),
                    json!({"schema_version":1,"kind":"content-provider-discovery-readiness",
                    "control_relay_peer_id":"broker","providers":[{"peer_id":key.to_peer_id().to_string(),"offer_expires_unix_seconds":12345}]})
                );
            } else {
                assert!(result.is_err());
            }
            timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn dropping_pending_query_closes_exact_socket_without_another_request() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (ready, received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await.unwrap();
            ready.send(()).unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        });
        let request = request();
        let mut query = Box::pin(query(&socket, &request));
        tokio::select! { _ = &mut query => panic!("unexpected reply"), _ = received => {} }
        drop(query);
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
