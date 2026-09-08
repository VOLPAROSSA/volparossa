use super::*;
use ed25519_dalek::SigningKey;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
use volparossa_content::{
    CHUNK_BYTES, Metadata, Publication, Validity,
    private_message::{RecipientKeyPair, open_private_message, publish_private_message},
    publish,
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentExportRequest, ContentImportRequest, read_request,
    read_response, write_request,
};

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 8 * 1024 * 1024,
        max_entries: 32,
        min_free_bytes: 0,
    }
}

#[tokio::test]
async fn public_publication_handoff_echoes_mode_without_private_or_missing_service_success() {
    let fixture = Fixture::new();
    let request = ContentImportRequest {
        manifest: fixture.signed.encode(),
        publisher_key: fixture.sender.verifying_key().to_bytes().to_vec(),
        cache: String::new(),
        limits: None,
        allow_public_content: true,
        contribute: true,
    };
    assert!(
        publication_manifest(&request).is_err(),
        "private sentinel cannot publish"
    );
    let mut source =
        ChunkStore::create(&fixture.root.path().join("public-source"), limits()).unwrap();
    let signed = publish(
        &mut b"a complete ordinary public publication".as_slice(),
        Publication {
            length: 38,
            metadata: Metadata {
                name: "public-publish".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            validity: Validity {
                created: now(),
                expires: now() + 60,
            },
        },
        &fixture.sender,
        &mut source,
    )
    .unwrap();
    let request = ContentImportRequest {
        manifest: signed.encode(),
        ..request
    };
    let (_, manifest) = publication_manifest(&request).unwrap();
    let control = ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![9; 16],
        operation: Some(Operation::ContentImport(request)),
    };
    let (mut client, task) = begin(&control).await;
    assert_ne!(
        read_response(&mut client).await.unwrap().result,
        ControlResult::Ok as i32,
        "no configured service cannot become a legacy import success"
    );
    task.await.unwrap().unwrap();
    let mut destination =
        ChunkStore::create(&fixture.root.path().join("private-staging"), limits()).unwrap();
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let checked = manifest.clone();
    let task = tokio::spawn(async move {
        assert!(
            exchange(
                &mut server,
                &[9; 16],
                &checked,
                &mut destination,
                true,
                true
            )
            .await
            .unwrap()
        );
    });
    ready_mode(&mut client, &manifest, true).await;
    serve_peer(
        &mut client,
        &manifest,
        &mut source,
        transfer_limits(&manifest),
    )
    .await
    .unwrap();
    task.await.unwrap();
    // Chunk completion alone emits no network-publication final receipt; that is the separate
    // configured service owner's durable commit/registration/advertisement responsibility.
    assert!(read_response(&mut client).await.is_err());
}
fn wire_limits() -> ContentCacheLimits {
    ContentCacheLimits {
        quota_bytes: limits().max_bytes,
        max_entries: 32,
        min_free_bytes: 0,
    }
}

struct Fixture {
    root: tempfile::TempDir,
    source: PathBuf,
    signed: SignedManifest,
    sender: SigningKey,
    recipient: RecipientKeyPair,
    plaintext: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("root");
        let source = root.path().join("user-source");
        let mut store = ChunkStore::create(&source, limits()).expect("source cache");
        let sender = SigningKey::generate(&mut rand_core::OsRng);
        let recipient = RecipientKeyPair::generate().expect("recipient");
        let plaintext = vec![0x71; CHUNK_BYTES * 2 + 73];
        let signed = publish_private_message(
            &plaintext,
            recipient.public_key(),
            &sender,
            Validity {
                created: now(),
                expires: now() + 300,
            },
            &mut store,
        )
        .expect("ciphertext");
        Self {
            root,
            source,
            signed,
            sender,
            recipient,
            plaintext,
        }
    }

    fn request(&self, importing: bool, cache: &Path) -> ControlRequest {
        let manifest = self.signed.encode();
        let publisher_key = self.sender.verifying_key().to_bytes().to_vec();
        let cache = cache.to_str().expect("path").to_owned();
        let operation = if importing {
            Operation::ContentImport(ContentImportRequest {
                manifest,
                publisher_key,
                cache,
                limits: Some(wire_limits()),
                allow_public_content: false,
                contribute: false,
            })
        } else {
            Operation::ContentExport(ContentExportRequest {
                manifest,
                publisher_key,
                cache,
                limits: Some(wire_limits()),
                allow_public_content: false,
            })
        };
        ControlRequest {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![9; 16],
            operation: Some(operation),
        }
    }

    fn verified(&self) -> VerifiedManifest {
        self.signed
            .verify(&self.sender.verifying_key(), now())
            .expect("trusted sender")
    }
}

async fn begin(
    request: &ControlRequest,
) -> (
    UnixStream,
    tokio::task::JoinHandle<Result<(), ControlServerError>>,
) {
    let (mut client, mut server) = UnixStream::pair().expect("real local socket pair");
    let task = tokio::spawn(async move {
        let request = read_request(&mut server)
            .await
            .expect("bounded initial control request");
        process(server, request, None).await
    });
    write_request(&mut client, request).await.expect("request");
    (client, task)
}

fn allow_public(mut request: ControlRequest) -> ControlRequest {
    match request.operation.as_mut() {
        Some(Operation::ContentImport(value)) => value.allow_public_content = true,
        Some(Operation::ContentExport(value)) => value.allow_public_content = true,
        _ => panic!("handoff operation"),
    }
    request
}

async fn ready(stream: &mut UnixStream, manifest: &VerifiedManifest) {
    ready_mode(stream, manifest, false).await;
}

async fn ready_mode(stream: &mut UnixStream, manifest: &VerifiedManifest, contribute: bool) {
    let response = read_response(stream).await.expect("Ready response");
    assert_eq!(response.request_id, vec![9; 16]);
    assert_eq!(response.result, ControlResult::Ok as i32);
    assert_eq!(response.diagnostic_code, "CONTENT_TRANSFER_READY");
    let Some(Payload::ContentTransferReady(value)) = response.payload else {
        panic!("distinct Ready payload")
    };
    assert_eq!(value.manifest_id, manifest.manifest_id());
    assert_eq!(value.bytes, manifest.length());
    assert_eq!(value.contribute, contribute);
    assert_eq!(
        usize::try_from(value.chunks).expect("chunks"),
        manifest.chunks().len()
    );
}

async fn final_receipt(stream: &mut UnixStream, manifest: &VerifiedManifest) {
    let response = read_response(stream).await.expect("final response");
    assert_eq!(response.request_id, vec![9; 16]);
    assert_eq!(response.result, ControlResult::Ok as i32);
    let Some(Payload::Content(value)) = response.payload else {
        panic!("final receipt")
    };
    assert_eq!(value.bytes, manifest.length());
    assert_eq!(
        usize::try_from(value.chunks).expect("chunks"),
        manifest.chunks().len()
    );
    assert!(!value.serving);
    assert!(!value.network_publication);
}

#[tokio::test]
async fn ciphertext_import_export_uses_one_unix_stream_without_changing_cache_permissions() {
    let fixture = Fixture::new();
    let manifest = fixture.verified();
    let agent_cache = fixture.root.path().join("agent-cache");
    let destination = fixture.root.path().join("user-received");
    let (mut socket, server) = begin(&fixture.request(true, &agent_cache)).await;
    ready(&mut socket, &manifest).await;
    let mut source = ChunkStore::open(&fixture.source, limits()).expect("user opens own cache");
    serve_peer(
        &mut socket,
        &manifest,
        &mut source,
        transfer_limits(&manifest),
    )
    .await
    .expect("import chunks");
    final_receipt(&mut socket, &manifest).await;
    server.await.expect("server").expect("complete import");
    drop(source);
    let (mut socket, server) = begin(&fixture.request(false, &agent_cache)).await;
    ready(&mut socket, &manifest).await;
    let mut received =
        ChunkStore::create(&destination, limits()).expect("new user cache after Ready");
    pull_from_peer(
        &mut socket,
        &manifest,
        &mut received,
        transfer_limits(&manifest),
    )
    .await
    .expect("export chunks");
    final_receipt(&mut socket, &manifest).await;
    server.await.expect("server").expect("complete export");
    let plaintext =
        open_private_message(&manifest, &mut [&mut received], now(), &fixture.recipient)
            .expect("local recipient decrypts");
    assert_eq!(*plaintext, fixture.plaintext);
    for path in [&fixture.source, &agent_cache, &destination] {
        assert_eq!(
            fs::metadata(path)
                .expect("cache metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let (mut socket, server) = begin(&fixture.request(true, &agent_cache)).await;
    let rejected = read_response(&mut socket)
        .await
        .expect("existing cache rejected");
    assert_ne!(rejected.result, ControlResult::Ok as i32);
    server.await.expect("server").expect("bounded rejection");
}

#[tokio::test]
async fn handoff_rejects_invalid_sender_before_ready_and_malformed_ciphertext_before_success() {
    let mut fixture = Fixture::new();
    let agent_cache = fixture.root.path().join("agent-cache");
    let mut invalid = fixture.request(true, &agent_cache);
    let Some(Operation::ContentImport(value)) = invalid.operation.as_mut() else {
        unreachable!()
    };
    value.publisher_key[0] ^= 1;
    let (mut socket, server) = begin(&invalid).await;
    assert_ne!(
        read_response(&mut socket)
            .await
            .expect("invalid sender")
            .result,
        ControlResult::Ok as i32
    );
    server.await.expect("server").expect("rejection");
    assert!(!agent_cache.exists());

    let bad_source = fixture.root.path().join("bad-source");
    let mut source = ChunkStore::create(&bad_source, limits()).expect("bad source");
    let bytes = [0x71; 80];
    fixture.signed = publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: Metadata {
                name: "a".repeat(64),
                revision: 1,
                content_type: PRIVATE_MESSAGE_CONTENT_TYPE.into(),
            },
            length: 80,
            validity: Validity {
                created: now(),
                expires: now() + 300,
            },
        },
        &fixture.sender,
        &mut source,
    )
    .expect("self-consistent signature does not prove HPKE envelope");
    let manifest = fixture.verified();
    // Opting into public content must not bypass the exact private-message envelope checks.
    let (mut socket, server) = begin(&allow_public(fixture.request(true, &agent_cache))).await;
    ready(&mut socket, &manifest).await;
    serve_peer(
        &mut socket,
        &manifest,
        &mut source,
        transfer_limits(&manifest),
    )
    .await
    .expect("bad envelope chunks");
    let rejected = read_response(&mut socket)
        .await
        .expect("final invalid-envelope response");
    assert_eq!(rejected.request_id, vec![9; 16]);
    assert_ne!(rejected.result, ControlResult::Ok as i32);
    server
        .await
        .expect("server")
        .expect("explicit final failure");
    assert_eq!(
        ChunkStore::open(&agent_cache, limits())
            .expect("retained verified chunks")
            .usage()
            .bytes,
        80
    );
    let (mut socket, server) = begin(&allow_public(fixture.request(false, &agent_cache))).await;
    assert_ne!(
        read_response(&mut socket)
            .await
            .expect("export rejects before Ready")
            .result,
        ControlResult::Ok as i32
    );
    server.await.expect("server").expect("export rejection");
}

#[tokio::test]
async fn public_handoff_requires_explicit_opt_in_and_transfers_large_and_empty_objects() {
    for length in [MAX_PRIVATE_MESSAGE_BYTES + 123, 0] {
        public_roundtrip(length).await;
    }
}

async fn public_roundtrip(length: usize) {
    let mut fixture = Fixture::new();
    let mut bytes = vec![0_u8; length];
    for (index, chunk) in bytes.chunks_mut(CHUNK_BYTES).enumerate() {
        chunk.fill(u8::try_from(index).expect("bounded distinct fixture chunk"));
    }
    let public_source = fixture.root.path().join("public-source");
    let mut source = ChunkStore::create(&public_source, limits()).expect("source");
    fixture.signed = publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: Metadata {
                name: "explicit-native-object".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: u64::try_from(bytes.len()).expect("length"),
            validity: Validity {
                created: now(),
                expires: now() + 300,
            },
        },
        &fixture.sender,
        &mut source,
    )
    .expect("explicit public publication");
    let manifest = fixture.verified();
    let agent_cache = fixture.root.path().join("agent-public");
    let (mut socket, server) = begin(&fixture.request(true, &agent_cache)).await;
    assert_ne!(
        read_response(&mut socket)
            .await
            .expect("public disabled")
            .result,
        ControlResult::Ok as i32
    );
    server.await.expect("server").expect("default rejection");
    assert!(
        !agent_cache.exists(),
        "default rejection does not create agent state"
    );

    let (mut socket, server) = begin(&allow_public(fixture.request(true, &agent_cache))).await;
    ready(&mut socket, &manifest).await;
    let progress = serve_peer(
        &mut socket,
        &manifest,
        &mut source,
        transfer_limits(&manifest),
    )
    .await
    .expect("complete public import");
    assert_eq!(
        progress.bytes,
        manifest.length(),
        "distinct chunks carry the full object"
    );
    final_receipt(&mut socket, &manifest).await;
    server.await.expect("server").expect("import success");
    drop(source);
    let (mut socket, server) = begin(&fixture.request(false, &agent_cache)).await;
    assert_ne!(
        read_response(&mut socket)
            .await
            .expect("public export disabled")
            .result,
        ControlResult::Ok as i32
    );
    server
        .await
        .expect("server")
        .expect("export default rejection");

    let (mut socket, server) = begin(&allow_public(fixture.request(false, &agent_cache))).await;
    ready(&mut socket, &manifest).await;
    let mut destination = ChunkStore::create(&fixture.root.path().join("public-return"), limits())
        .expect("new user cache");
    let progress = pull_from_peer(
        &mut socket,
        &manifest,
        &mut destination,
        transfer_limits(&manifest),
    )
    .await
    .expect("complete public export");
    assert_eq!(progress.bytes, manifest.length());
    assert_eq!(progress.chunks, manifest.chunks().len());
    final_receipt(&mut socket, &manifest).await;
    server.await.expect("server").expect("export success");
    let mut reconstructed = Vec::new();
    reassemble(
        &manifest,
        &mut [&mut destination],
        now(),
        &mut reconstructed,
    )
    .expect("complete signed object hash");
    assert_eq!(reconstructed, bytes);
}
