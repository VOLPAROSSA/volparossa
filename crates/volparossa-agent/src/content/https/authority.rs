//! Two own-origin authorization paths, never a peer key promoted to HTTPS authority.

use std::path::{Path, PathBuf};

use volparossa_content::origin_https::{
    OriginAuthorizedDigest, OriginAuthorizedManifest, OriginError,
};
use volparossa_content::{CacheLimits, ChunkStore, SignedManifest, VerifiedManifest};

use super::super::{ContentRuntime, now};

pub(super) enum Authorization {
    Cooperative(OriginAuthorizedManifest),
    Digest {
        authority: OriginAuthorizedDigest,
        signed: SignedManifest,
        manifest: VerifiedManifest,
    },
}

impl Authorization {
    pub(super) fn verified_digest(
        authority: OriginAuthorizedDigest,
        signed: SignedManifest,
        store: &mut ChunkStore,
    ) -> Result<Self, OriginError> {
        let manifest = authority.verify_candidate(&signed, now())?;
        authority.verify_cached(&manifest, store, now())?;
        Ok(Self::Digest {
            authority,
            signed,
            manifest,
        })
    }

    pub(super) fn manifest(&self) -> &VerifiedManifest {
        match self {
            Self::Cooperative(value) => value.manifest(),
            Self::Digest { manifest, .. } => manifest,
        }
    }

    pub(super) fn native_manifest_bytes(&self) -> Vec<u8> {
        match self {
            Self::Cooperative(value) => value.native_manifest_bytes().to_vec(),
            Self::Digest { signed, .. } => signed.encode(),
        }
    }

    pub(super) fn origin_digest(&self) -> bool {
        matches!(self, Self::Digest { .. })
    }

    pub(super) fn check_validity(&self, at: u64) -> Result<u64, OriginError> {
        match self {
            Self::Cooperative(value) => value.check_validity(at),
            Self::Digest {
                authority,
                manifest,
                signed,
            } => {
                let expiry = authority.check_validity(at)?;
                authority.verify_candidate(signed, at)?;
                Ok(expiry.min(manifest.validity().expires))
            }
        }
    }

    pub(super) fn verify_cached(
        &self,
        store: &mut ChunkStore,
        at: u64,
    ) -> Result<u64, OriginError> {
        match self {
            Self::Cooperative(value) => value.verify_cached(store, at),
            Self::Digest {
                authority,
                manifest,
                ..
            } => authority.verify_cached(manifest, store, at),
        }
    }

    pub(super) fn reassemble_to_file(
        &self,
        stores: &mut [&mut ChunkStore],
        at: u64,
        path: &Path,
    ) -> Result<u64, OriginError> {
        match self {
            Self::Cooperative(value) => value.reassemble_to_file(stores, at, path),
            Self::Digest {
                authority,
                manifest,
                ..
            } => authority.reassemble_to_file(manifest, stores, at, path),
        }
    }

    /// Called only after complete verification. HTTPS admission keeps the original HTTP clock;
    /// converting the transport manifest into ordinary native consent would lose that boundary.
    pub(super) async fn contribute(
        &self,
        runtime: &ContentRuntime,
        root: PathBuf,
        limits: CacheLimits,
    ) {
        match self {
            Self::Cooperative(value) => runtime.contribute_https(value, root, limits).await,
            Self::Digest {
                authority,
                signed,
                manifest,
            } => {
                runtime
                    .contribute_https_digest(
                        authority,
                        signed.clone(),
                        manifest.clone(),
                        root,
                        limits,
                    )
                    .await;
            }
        }
    }
}
