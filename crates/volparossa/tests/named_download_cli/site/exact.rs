// SPDX-License-Identifier: GPL-3.0-only
//! Pin the signed envelope independently of the authenticated site payload.
use std::time::Duration;

use tokio::{net::UnixListener, time::timeout};
use volparossa_content::{MAX_OBJECT_BYTES, site::SITE_CONTENT_TYPE};
use volparossa_local_control::ContentFetchNameRequest;

use super::{site_command, site_fixture, successful_site};
use crate::{Fault, directory_names, fs, isolated_network};

pub(super) fn assert_query(
    query: &ContentFetchNameRequest,
    pin: Option<&[u8; 32]>,
    minimum: Option<u64>,
) {
    assert_eq!(query.min_revision, minimum);
    assert_eq!(
        query.expected_manifest_id.as_deref(),
        pin.map(<[u8; 32]>::as_slice)
    );
    assert_eq!(
        query.expected_content_type.as_deref(),
        Some(SITE_CONTENT_TYPE)
    );
    assert_eq!(query.max_object_bytes, Some(MAX_OBJECT_BYTES));
    assert!(!query.prefer_cached);
}

#[test]
fn site_open_requires_the_selected_signed_manifest_before_transfer_and_http() {
    isolated_network(
        "site::exact::site_open_requires_the_selected_signed_manifest_before_transfer_and_http",
        async {
            rejected_releases().await;
            // Pin alone via the protected-peer receipt, then pin and minimum via the owned cache.
            successful_site(false, true).await;
            successful_site(true, true).await;
        },
        "loopback",
    );
}

async fn rejected_releases() {
    let mut fixture = site_fixture();
    let root = fixture.directory.path().to_owned();
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    let older = fixture.publication(Fault::OldRevision);
    let selected = fixture.publication(Fault::None);
    let other_equal = fixture.publication(Fault::None);
    // All envelopes authenticate the same site payload under the same publisher/name.
    assert_eq!(older.1.object_sha256(), selected.1.object_sha256());
    assert_eq!(selected.1.object_sha256(), other_equal.1.object_sha256());
    assert_ne!(selected.1.manifest_id(), other_equal.1.manifest_id());
    let reject = Fault::UnselectedEnvelope;
    for (expected, presented, minimum, fault) in [
        (&selected.1, &older, None, reject),
        (&older.1, &selected, None, reject),
        (&selected.1, &other_equal, Some(3), reject),
        (&selected.1, &selected, Some(4), reject),
        (&selected.1, &selected, None, Fault::Disconnect),
    ] {
        fixture.retained = Some(presented.clone());
        let mut cli = site_command(&fixture, "30");
        cli.arg("--expected-manifest-id")
            .arg(hex::encode(expected.manifest_id()));
        if let Some(minimum) = minimum {
            cli.arg("--min-revision").arg(minimum.to_string());
        }
        let server = fixture.serve_checked(&listener, fault, false, |query| {
            assert_query(query, Some(expected.manifest_id()), minimum);
        });
        let (output, ()) = timeout(Duration::from_secs(15), async {
            tokio::join!(cli.output(), server)
        })
        .await
        .unwrap();
        let output = output.unwrap();
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "unverified site emitted a ready URL"
        );
        assert_eq!(directory_names(&root), ["control.sock", "served-store"]);
    }
    drop(listener);
    fs::remove_file(root.join("control.sock")).unwrap();
}
