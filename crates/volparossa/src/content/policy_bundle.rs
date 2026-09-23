//! Bounded inert assessment data, not a policy activation or trust-anchor import.

use super::{FetchName, Limits, named_download};
use anyhow::{Result, ensure};
use ed25519_dalek::VerifyingKey;
use std::{
    os::unix::fs::FileExt as _,
    path::{Path, PathBuf},
};

pub(crate) const CONTENT_TYPE: &str = "application/vnd.volparossa.principle-assessment+json";
pub(crate) const MAX_BYTES: u64 = 2 * 1024 * 1024;

pub(crate) struct Selection {
    pub(crate) publisher: VerifyingKey,
    pub(crate) name: String,
    pub(crate) manifest_id: [u8; 32],
    pub(crate) cache: PathBuf,
    pub(crate) reuse_cache: bool,
    pub(crate) limits: Limits,
}

pub(crate) struct Download {
    pub(crate) bytes: Vec<u8>,
    pub(crate) signed_manifest: Vec<u8>,
    pub(crate) expires: u64,
    pub(crate) receipt: serde_json::Value,
}

pub(crate) async fn fetch(args: &Selection, socket: &Path, parent: &Path) -> Result<Download> {
    let query = FetchName {
        publisher_key: args.publisher,
        name: args.name.clone(),
        min_revision: None,
        cache: args.cache.clone(),
        reuse_cache: args.reuse_cache,
        cache_only: false,
        local_output: parent.join("unused-output"),
        limits: args.limits.clone(),
    };
    let download = named_download::prepare_bounded(
        &query,
        socket,
        parent,
        &named_download::Requirement {
            content_type: CONTENT_TYPE,
            maximum_bytes: MAX_BYTES,
            manifest_id: Some(args.manifest_id),
        },
    )
    .await?;
    let length = download.as_file().metadata()?.len();
    ensure!(
        (1..=MAX_BYTES).contains(&length) && length == download.manifest().length(),
        "compute_policy_bundle_download_bound"
    );
    let mut bytes = vec![0; usize::try_from(length)?];
    download.as_file().read_exact_at(&mut bytes, 0)?;
    download.check_live()?;
    Ok(Download {
        bytes,
        signed_manifest: download.signed_manifest().encode(),
        expires: download.expires(),
        receipt: download.report(),
    })
}
