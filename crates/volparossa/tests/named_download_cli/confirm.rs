//! Real publisher CLI against a local control fixture with independently chosen replies.

use std::time::Duration;

use tokio::{io::AsyncReadExt as _, net::UnixListener, process::Command};
use volparossa_content::{SignedManifest, VerifiedManifest, site::SITE_CONTENT_TYPE};
use volparossa_local_control::{ControlResult, NamedContentTransferReady};

use super::site_fixture;
use crate::{
    Fault, Fixture, NAME, Operation, Payload, TransferLimits, directory_names, fs, isolated,
    read_request, response, serve_peer, transfer_receipt, write_response,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reply {
    Complete,
    Changed,
    Expired,
    Interrupted,
    Withheld,
    RemoteReceipt,
}

#[test]
fn confirmation_requires_the_exact_complete_local_site_and_receipt() {
    isolated(
        "site::confirm::confirmation_requires_the_exact_complete_local_site_and_receipt",
        exercise(),
    );
}

async fn exercise() {
    let mut fixture = site_fixture();
    let root = fixture.directory.path().to_owned();
    let (expected, manifest) = fixture.publication(Fault::None);
    fs::write(root.join("original.pb"), expected.encode()).unwrap();
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    for reply in [
        Reply::Changed,
        Reply::Expired,
        Reply::Interrupted,
        Reply::Withheld,
        Reply::RemoteReceipt,
        Reply::Complete,
    ] {
        let (selected, selected_manifest) = match reply {
            Reply::Changed => {
                fixture.bytes[0] ^= 1;
                let different = fixture.publication(Fault::None);
                fixture.bytes[0] ^= 1;
                different
            }
            Reply::Expired => fixture.publication(Fault::Expired),
            _ => (expected.clone(), manifest.clone()),
        };
        let key = fixture.key.verifying_key().to_bytes();
        let mut cli = Command::new(env!("CARGO_BIN_EXE_volparossa"));
        cli.current_dir(&root)
            .env("TMPDIR", root.join("no-such-directory"))
            .arg("--control-socket")
            .arg(root.join("control.sock"))
            .args([
                "content",
                "site",
                "confirm",
                "--manifest",
                "original.pb",
                "--publisher-key",
            ])
            .arg(hex::encode(key))
            .kill_on_drop(true);
        let server = answer(
            &mut fixture,
            &listener,
            reply,
            &manifest,
            &selected,
            &selected_manifest,
        );
        let (result, ()) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(cli.output(), server)
        })
        .await
        .unwrap();
        let output = result.unwrap();
        if reply == Reply::Complete {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let checked: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(checked["local_registry_read_verified"], true);
            assert_eq!(checked["name"], NAME);
            assert_eq!(checked["revision"], manifest.metadata().revision);
            assert_eq!(checked["manifest_id"], hex::encode(manifest.manifest_id()));
            assert_eq!(checked["bytes"], manifest.length());
        } else {
            assert!(!output.status.success(), "accepted {reply:?}");
            assert!(output.stdout.is_empty());
        }
    }
    assert_eq!(
        fs::read(root.join("original.pb")).unwrap(),
        expected.encode()
    );
    assert_eq!(
        directory_names(&root),
        ["control.sock", "original.pb", "served-store"]
    );
}

async fn answer(
    fixture: &mut Fixture,
    listener: &UnixListener,
    reply: Reply,
    manifest: &VerifiedManifest,
    selected: &SignedManifest,
    selected_manifest: &VerifiedManifest,
) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let request = read_request(&mut stream).await.unwrap();
    let Some(Operation::ContentLocalFetchName(local)) = request.operation else {
        panic!("expected only an owner-local registry read");
    };
    assert_eq!(local.publisher_key, fixture.key.verifying_key().to_bytes());
    assert_eq!(local.name, NAME);
    assert_eq!(local.min_revision, manifest.metadata().revision);
    assert_eq!(local.expected_content_type, SITE_CONTENT_TYPE);
    assert_eq!(local.max_object_bytes, manifest.length());
    write_response(
        &mut stream,
        &response(
            request.request_id.clone(),
            "LOCAL_NAMED_CONTENT_TRANSFER_READY",
            Payload::NamedContentTransferReady(NamedContentTransferReady {
                manifest: selected.encode(),
                cache_only: true,
            }),
        ),
    )
    .await
    .unwrap();
    if matches!(reply, Reply::Changed | Reply::Expired) {
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        return;
    }
    if reply == Reply::Interrupted {
        return;
    }
    let progress = serve_peer(
        &mut stream,
        selected_manifest,
        &mut fixture.store,
        TransferLimits {
            exchange_timeout: Duration::from_secs(3),
            session_timeout: Duration::from_secs(5),
            max_requests: manifest.chunks().len(),
            max_bytes: manifest.length(),
        },
    )
    .await
    .unwrap();
    assert_eq!(progress.bytes, manifest.length());
    let mut final_response = response(
        request.request_id,
        "CONTENT_OK",
        Payload::Content(transfer_receipt(
            selected_manifest,
            reply == Reply::RemoteReceipt,
        )),
    );
    if reply == Reply::Withheld {
        final_response.result = ControlResult::Policy as i32;
        final_response.diagnostic_code = "CONTENT_POLICY".into();
        final_response.payload = None;
    }
    write_response(&mut stream, &final_response).await.unwrap();
}
