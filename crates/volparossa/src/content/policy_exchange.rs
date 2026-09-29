//! Original, inert policy-round objects carried by the existing public cache transport.
//! Transport publishers never become policy authorities by serving these objects.

use std::{io::Read as _, os::unix::fs::FileExt as _, path::Path};

use anyhow::{Result, ensure};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use volparossa_content::{ChunkStore, SignedManifest, VerifiedManifest};
use volparossa_policy::object::{MAX_OBJECT_DECISION_BYTES, exchange::MAX_DECISION_REQUEST_BYTES};

use super::{FetchName, PolicyDecisionPublication, Publish, named_download, policy_decision::Feed};

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Request,
    Endorsement,
}

impl Kind {
    pub(crate) const fn content_type(self) -> &'static str {
        match self {
            Self::Request => "application/vnd.volparossa.object-policy-request.v1",
            Self::Endorsement => "application/vnd.volparossa.object-policy-endorsement.v1",
        }
    }
    pub(crate) const fn maximum_bytes(self) -> u64 {
        match self {
            Self::Request => MAX_DECISION_REQUEST_BYTES as u64,
            Self::Endorsement => MAX_OBJECT_DECISION_BYTES as u64,
        }
    }
    fn requirement(self) -> named_download::Requirement {
        named_download::Requirement {
            content_type: self.content_type(),
            maximum_bytes: self.maximum_bytes(),
            manifest_id: None,
        }
    }
}

pub(crate) struct Download {
    pub(crate) bytes: Vec<u8>,
    pub(crate) signed_manifest: Vec<u8>,
    pub(crate) manifest: VerifiedManifest,
    pub(crate) receipt: Value,
}

fn complete(download: &named_download::VerifiedNamedDownload, kind: Kind) -> Result<Download> {
    let length = download.as_file().metadata()?.len();
    ensure!(
        (1..=kind.maximum_bytes()).contains(&length) && length == download.manifest().length(),
        "policy_exchange_download_bound"
    );
    let mut bytes = vec![0; usize::try_from(length)?];
    download.as_file().read_exact_at(&mut bytes, 0)?;
    download.check_live()?;
    Ok(Download {
        bytes,
        signed_manifest: download.signed_manifest().encode(),
        manifest: download.manifest().clone(),
        receipt: download.report(),
    })
}

pub(crate) async fn local_request(
    publisher: &VerifyingKey,
    name: &str,
    min_revision: u64,
    socket: &Path,
    parent: &Path,
) -> Result<Download> {
    local(publisher, name, min_revision, socket, parent, Kind::Request).await
}

pub(crate) async fn local_endorsement(
    publisher: &VerifyingKey,
    name: &str,
    min_revision: u64,
    socket: &Path,
    parent: &Path,
) -> Result<Download> {
    local(
        publisher,
        name,
        min_revision,
        socket,
        parent,
        Kind::Endorsement,
    )
    .await
}

async fn local(
    publisher: &VerifyingKey,
    name: &str,
    min_revision: u64,
    socket: &Path,
    parent: &Path,
    kind: Kind,
) -> Result<Download> {
    let result = named_download::prepare_local(
        publisher,
        name,
        min_revision,
        socket,
        parent,
        &kind.requirement(),
    )
    .await?;
    complete(&result, kind)
}

pub(crate) async fn endorsement(feed: &Feed, socket: &Path, parent: &Path) -> Result<Download> {
    let query = FetchName {
        publisher_key: feed.publisher,
        name: feed.name.clone(),
        min_revision: Some(feed.min_revision),
        cache: feed.cache.clone(),
        reuse_cache: true,
        cache_only: false,
        local_output: parent.join("unused-policy-endorsement"),
        limits: feed.limits.clone(),
    };
    let result = named_download::prepare_bounded_refresh(
        &query,
        socket,
        parent,
        &Kind::Endorsement.requirement(),
    )
    .await?;
    complete(&result, Kind::Endorsement)
}

/// Reopens the exact previous wrapper on resume, including its original expiry.
pub(crate) async fn publish(
    args: PolicyDecisionPublication,
    publisher: &VerifyingKey,
    kind: Kind,
    socket: &Path,
) -> Result<VerifiedManifest> {
    let mut bytes = Vec::new();
    super::open_regular(&args.input, kind.maximum_bytes())?
        .take(kind.maximum_bytes() + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= kind.maximum_bytes(),
        "policy_exchange_publication_bound"
    );
    if !args.manifest.try_exists()? {
        let signer = super::unlock_signer(Some(&args.identity), Some(&args.passphrase_file))?;
        ensure!(
            &signer.verifying_key() == publisher,
            "policy_exchange_publisher_changed"
        );
        drop(signer);
        super::publish_command(
            &Publish::policy_object(
                PolicyDecisionPublication {
                    input: args.input.clone(),
                    cache: args.cache.clone(),
                    reuse_cache: args.reuse_cache,
                    manifest: args.manifest.clone(),
                    name: args.name.clone(),
                    revision: args.revision,
                    expires_not_after: args.expires_not_after,
                    identity: args.identity.clone(),
                    passphrase_file: args.passphrase_file.clone(),
                    limits: args.limits.clone(),
                },
                kind.content_type(),
            ),
            socket,
        )
        .await?;
    }
    let original = super::verified_manifest_bytes(&args.manifest, publisher)?;
    let manifest = SignedManifest::decode(&original)?.verify(publisher, super::now_seconds()?)?;
    ensure!(
        manifest.metadata().name == args.name
            && manifest.metadata().revision == args.revision
            && manifest.metadata().content_type == kind.content_type()
            && manifest.validity().expires == args.expires_not_after
            && manifest.length() == bytes.len() as u64,
        "policy_exchange_original_wrapper_changed"
    );
    let mut cache = ChunkStore::open(&args.cache, args.limits.cache_limits()?)?;
    let mut reconstructed = Vec::with_capacity(bytes.len());
    volparossa_content::reassemble(
        &manifest,
        &mut [&mut cache],
        super::now_seconds()?,
        &mut reconstructed,
    )?;
    ensure!(
        reconstructed == bytes,
        "policy_exchange_original_bytes_changed"
    );
    Ok(manifest)
}

pub(crate) async fn deposit(
    args: &PolicyDecisionPublication,
    providers: Vec<VerifyingKey>,
    socket: &Path,
) -> Result<Value> {
    super::custody::deposit_existing(args, providers, socket).await
}
