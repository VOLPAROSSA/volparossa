//! Real publish CLI plus local chunk protocol; final serving receipts are a simulated agent.
//! This does not prove an actual provider advertisement, separate UID or overlay transfer.

use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Output, time::Duration};

use ed25519_dalek::VerifyingKey;
use tokio::{io::AsyncReadExt as _, net::UnixListener};
use volparossa_content::{
    CHUNK_BYTES, ChunkStore, SignedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
    reassemble,
    transfer::{TransferLimits, pull_from_peer},
};
use volparossa_identity::{IdentityStore, Passphrase};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ContentTransferReady, ControlResponse, ControlResult,
    control_request::Operation, control_response::Payload, read_request, write_response,
};

use super::{cache_limits, invoke, now, successful};

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    OldReady,
    FinalNotPublished,
    FinalNotServing,
}

fn arguments(identity: &Path, contribute: bool) -> Vec<String> {
    let mut args = [
        "publish",
        "--input",
        "input.bin",
        "--cache",
        "user-cache",
        "--manifest",
        "manifest.pb",
        "--name",
        "public-file",
        "--revision",
        "1",
        "--min-free-bytes",
        "0",
    ]
    .map(str::to_owned)
    .to_vec();
    args.extend([
        "--identity".into(),
        identity.join("identity.key").to_string_lossy().into_owned(),
        "--passphrase-file".into(),
        identity.join("passphrase").to_string_lossy().into_owned(),
    ]);
    if contribute {
        args.push("--contribute".into());
    }
    args
}

pub(super) async fn scenario() {
    let temporary = tempfile::tempdir().expect("private user fixture");
    let identity = temporary.path();
    let password = b"explicit public contribution process fixture";
    fs::write(identity.join("passphrase"), password).unwrap();
    fs::set_permissions(
        identity.join("passphrase"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let created = IdentityStore::new(identity.join("identity.key"))
        .create(&Passphrase::new(password).unwrap())
        .unwrap();
    let key = VerifyingKey::from_bytes(&created.ed25519_public_key_bytes().unwrap()).unwrap();
    drop(created);
    let encrypted_identity = fs::read(identity.join("identity.key")).unwrap();
    // Absence of --contribute remains completely offline even with no control listener.
    let offline = tempfile::tempdir_in(identity).unwrap();
    fs::write(offline.path().join("input.bin"), b"offline remains local").unwrap();
    let report = successful(&invoke(offline.path(), arguments(identity, false)).await);
    assert_eq!(report["network_publication"], false);
    assert_eq!(report["operation"], "offline_content_publish");
    for (length, fault) in [
        (CHUNK_BYTES + 123, Fault::None),
        (0, Fault::None),
        (123, Fault::OldReady),
        (123, Fault::FinalNotPublished),
        (123, Fault::FinalNotServing),
    ] {
        let case = tempfile::tempdir_in(identity).unwrap();
        let bytes = vec![0x41; length];
        fs::write(case.path().join("input.bin"), &bytes).unwrap();
        let output = exchange(case.path(), arguments(identity, true), &key, fault).await;
        if matches!(fault, Fault::None) {
            let report = successful(&output);
            assert_eq!(report["network_publication"], true);
            assert_eq!(report["operation"], "content_publish");
            assert_eq!(report["serving"], true);
            assert_eq!(report["publications"], 1);
            assert_eq!(report["bytes"], length);
            for field in [
                "private_keys_transferred",
                "ownership_changed",
                "origin_authenticated",
            ] {
                assert_eq!(report[field], false);
            }
        } else {
            assert!(!output.status.success() && output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("local publication retained"));
        }
        let encoded =
            fs::read(case.path().join("manifest.pb")).expect("original manifest retained");
        let manifest = SignedManifest::decode(&encoded)
            .unwrap()
            .verify(&key, now())
            .unwrap();
        let mut source = ChunkStore::open(&case.path().join("user-cache"), cache_limits()).unwrap();
        let mut retained = Vec::new();
        reassemble(&manifest, &mut [&mut source], now(), &mut retained).unwrap();
        assert_eq!(retained, bytes);
        assert_eq!(
            fs::metadata(case.path().join("user-cache"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(case.path().join("manifest.pb"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let private = tempfile::tempdir_in(identity).unwrap();
    fs::write(
        private.path().join("input.bin"),
        b"not an admissible public message",
    )
    .unwrap();
    let mut args = arguments(identity, true);
    args.extend(["--content-type".into(), PRIVATE_MESSAGE_CONTENT_TYPE.into()]);
    let rejected = invoke(private.path(), args).await;
    assert!(!rejected.status.success() && rejected.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("never private messages"));
    assert!(
        !private.path().join("user-cache").exists() && !private.path().join("manifest.pb").exists()
    );
    assert_eq!(
        fs::read(identity.join("identity.key")).unwrap(),
        encrypted_identity
    );
}

async fn exchange(root: &Path, args: Vec<String>, key: &VerifyingKey, fault: Fault) -> Output {
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    let serve = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(Operation::ContentImport(import)) = request.operation else {
            panic!("typed import required")
        };
        assert!(
            import.contribute
                && import.allow_public_content
                && import.cache.is_empty()
                && import.limits.is_none()
        );
        assert_eq!(import.publisher_key, key.to_bytes());
        assert_eq!(import.manifest, fs::read(root.join("manifest.pb")).unwrap());
        let manifest = SignedManifest::decode(&import.manifest)
            .unwrap()
            .verify(key, now())
            .unwrap();
        let ready = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: ControlResult::Ok as i32,
            diagnostic_code: "CONTENT_TRANSFER_READY".into(),
            payload: Some(Payload::ContentTransferReady(ContentTransferReady {
                manifest_id: manifest.manifest_id().to_vec(),
                bytes: manifest.length(),
                chunks: u32::try_from(manifest.chunks().len()).unwrap(),
                contribute: !matches!(fault, Fault::OldReady),
            })),
        };
        write_response(&mut stream, &ready).await.unwrap();
        if matches!(fault, Fault::OldReady) {
            assert_eq!(
                stream.read(&mut [0; 1]).await.unwrap(),
                0,
                "legacy absent/false echo admits no chunks"
            );
            return;
        }
        let mut destination =
            ChunkStore::create(&root.join("configured-agent-cache"), cache_limits()).unwrap();
        let progress = pull_from_peer(
            &mut stream,
            &manifest,
            &mut destination,
            TransferLimits {
                max_requests: manifest.chunks().len().max(1),
                max_bytes: manifest.length().max(1),
                ..TransferLimits::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(progress.bytes, manifest.length());
        assert_eq!(progress.chunks, manifest.chunks().len());
        assert_eq!(progress.missing, 0);
        reassemble(
            &manifest,
            &mut [&mut destination],
            now(),
            &mut std::io::sink(),
        )
        .unwrap();
        write_response(
            &mut stream,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: ControlResult::Ok as i32,
                diagnostic_code: "CONTENT_OK".into(),
                payload: Some(Payload::Content(ContentReceipt {
                    bytes: manifest.length(),
                    chunks: u32::try_from(manifest.chunks().len()).unwrap(),
                    serving: !matches!(fault, Fault::FinalNotServing),
                    publications: 1,
                    network_publication: !matches!(fault, Fault::FinalNotPublished),
                    ..ContentReceipt::default()
                })),
            },
        )
        .await
        .unwrap();
    };
    let ((), output) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(serve, invoke(root, args))
    })
    .await
    .unwrap();
    output
}
