//! Fresh, bounded named retrieval of inert quorum bytes, not publisher-derived authority.

use std::{
    os::unix::fs::FileExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use ed25519_dalek::VerifyingKey;

use super::{FetchName, Limits, POLICY_DECISION_CONTENT_TYPE, named_download};

pub(crate) struct Feed {
    pub(crate) publisher: VerifyingKey,
    pub(crate) name: String,
    pub(crate) min_revision: u64,
    pub(crate) cache: PathBuf,
    pub(crate) limits: Limits,
}

pub(crate) struct Download {
    pub(crate) bytes: Vec<u8>,
    pub(crate) signed_manifest: Vec<u8>,
    pub(crate) receipt: serde_json::Value,
}

pub(crate) async fn refresh(feed: &Feed, socket: &Path, parent: &Path) -> Result<Download> {
    let query = FetchName {
        publisher_key: feed.publisher,
        name: feed.name.clone(),
        min_revision: Some(feed.min_revision),
        cache: feed.cache.clone(),
        reuse_cache: true,
        cache_only: false,
        local_output: parent.join("unused-policy-output"),
        limits: feed.limits.clone(),
    };
    let download = named_download::prepare_bounded_refresh(
        &query,
        socket,
        parent,
        &named_download::Requirement {
            content_type: POLICY_DECISION_CONTENT_TYPE,
            maximum_bytes: volparossa_policy::object::MAX_OBJECT_DECISION_BYTES as u64,
            manifest_id: None,
        },
    )
    .await?;
    let length = download.as_file().metadata()?.len();
    ensure!(
        (1..=volparossa_policy::object::MAX_OBJECT_DECISION_BYTES as u64).contains(&length)
            && length == download.manifest().length(),
        "policy_follow_download_bound"
    );
    let mut bytes = vec![0; usize::try_from(length)?];
    download.as_file().read_exact_at(&mut bytes, 0)?;
    download.check_live()?;
    Ok(Download {
        bytes,
        signed_manifest: download.signed_manifest().encode(),
        receipt: download.report(),
    })
}
