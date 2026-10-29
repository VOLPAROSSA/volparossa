// SPDX-License-Identifier: GPL-3.0-only
//! Explicit local signed-bundle preview: no signing, daemon, cache or name lookup.

#[cfg(test)]
mod tests;

use std::{
    fmt,
    fs::{File, Metadata},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use clap::Args;
use ed25519_dalek::VerifyingKey;
use nix::unistd::geteuid;
use rustix::fs::{Mode, OFlags, open};
use sha2::{Digest, Sha256};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::Instant,
};
use volparossa_content::{
    ChunkId, MAX_MANIFEST_BYTES, MAX_OBJECT_BYTES, SignedManifest, VerifiedManifest,
    site::{SITE_CONTENT_TYPE, SiteBundle},
};

use crate::content::now_seconds;

#[derive(Debug, Args)]
pub(crate) struct Preview {
    /// Exact owned 0600 bundle file; only one immutable in-memory snapshot is served.
    #[arg(long)]
    input: PathBuf,
    /// Original signed native manifest, never replaced, re-signed or granted name authority.
    #[arg(long)]
    manifest: PathBuf,
    /// Independently trusted publisher key; never selected from the supplied manifest.
    #[arg(long,value_parser=super::super::parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// Exact reviewed bundle bytes; this digest grants no publication or origin authority.
    #[arg(long,value_parser=super::super::parse_input_sha256)]
    expected_input_sha256: [u8; 32],
    /// Maximum preparation plus preview lifetime, also capped by original signed expiry.
    #[arg(long,default_value_t=60,value_parser=clap::value_parser!(u64).range(1..=86_400))]
    lifetime_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    File,
    Profile,
    Changed,
    Bounds,
    Manifest,
    Publisher,
    Expired,
    ContentType,
    Digest,
    Length,
    Chunk,
    Bundle,
    Cancelled,
    Deadline,
    Worker,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::File => "local site input unavailable",
            Self::Profile => "local site requires owned regular single-link 0600 inputs",
            Self::Changed => "local site input changed while reading",
            Self::Bounds => "local site input bound exceeded",
            Self::Manifest => "local site signed manifest rejected",
            Self::Publisher => "local site publisher differs from the selected key",
            Self::Expired => "local site original publication expired",
            Self::ContentType => "local site manifest is not a site bundle",
            Self::Digest => "local site reviewed input digest differs",
            Self::Length => "local site signed payload length differs",
            Self::Chunk => "local site signed chunk binding differs",
            Self::Bundle => "local site bundle encoding rejected",
            Self::Cancelled => "local site preparation cancelled",
            Self::Deadline => "local site lifetime expired",
            Self::Worker => "local site preparation worker failed",
        })
    }
}
impl std::error::Error for Failure {}
type Result<T> = std::result::Result<T, Failure>;

struct Control {
    cancel: Arc<AtomicBool>,
    deadline: Instant,
}
impl Control {
    fn check(&self) -> Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(Failure::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Failure::Deadline);
        }
        Ok(())
    }
}
struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Holds only verified local publication authority, never a named-download receipt.
pub(super) struct LocalAuthority {
    manifest: VerifiedManifest,
    deadline: Instant,
    expires: u64,
}
impl LocalAuthority {
    pub(super) fn check_live(&self) -> anyhow::Result<()> {
        if Instant::now() >= self.deadline
            || now_seconds().map_err(|_| Failure::Expired)? >= self.expires
        {
            return Err(Failure::Expired.into());
        }
        Ok(())
    }
    pub(super) fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "source":"local_signed_bundle","bytes":self.manifest.length(),"chunks":self.manifest.chunks().len(),
            "publisher_key":hex::encode(self.manifest.publisher()),"manifest_id":hex::encode(self.manifest.manifest_id()),
            "publication_expires_unix_seconds":self.manifest.validity().expires,
            "sha256":hex::encode(self.manifest.object_sha256()),
            "reviewed_input_sha256_matched":true,"publisher_signature_verified":true,"original_signed_manifest_verified":true,
            "name":self.manifest.metadata().name,"revision":self.manifest.metadata().revision,
            "named_lookup_performed":false,"network_retrieval_performed":false,
            "https_origin_authenticated":false,"origin_authenticated":false,"globally_latest":false,
            "publisher_name_authority_verified":false,"internet_policy_permission_granted":false,
            "private_spool_created":false,"input_files_modified":false,
        })
    }
}

pub(super) struct Prepared {
    pub(super) authority: LocalAuthority,
    pub(super) bundle: SiteBundle,
    pub(super) deadline: Instant,
    pub(super) expires: u64,
}

pub(super) async fn run(args: Preview) -> anyhow::Result<()> {
    let started = Instant::now();
    let wall = now_seconds().map_err(|_| Failure::Expired)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| Failure::Worker)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| Failure::Worker)?;
    let prepared = prepare(args, started, wall, &mut interrupt, &mut terminate).await?;
    super::viewer::run_local(prepared, interrupt, terminate).await
}

async fn prepare(
    args: Preview,
    started: Instant,
    wall: u64,
    interrupt: &mut Signal,
    terminate: &mut Signal,
) -> Result<Prepared> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel = Cancel(Arc::clone(&cancelled));
    let mut worker =
        tokio::task::spawn_blocking(move || prepare_blocking(&args, started, wall, cancelled));
    tokio::select! {
        result=&mut worker=>result.map_err(|_|Failure::Worker)?,
        _=interrupt.recv()=> { cancel.0.store(true,Ordering::Relaxed); let _=worker.await; Err(Failure::Cancelled) },
        _=terminate.recv()=> { cancel.0.store(true,Ordering::Relaxed); let _=worker.await; Err(Failure::Cancelled) },
    }
    // Caller Drop sets cancellation too. Kernel-stalled regular-file I/O cannot
    // be interrupted here; no listener/success report exists until the join.
}

pub(super) fn prepare_blocking(
    args: &Preview,
    started: Instant,
    wall: u64,
    cancel: Arc<AtomicBool>,
) -> Result<Prepared> {
    if !(1..=86_400).contains(&args.lifetime_seconds) {
        return Err(Failure::Bounds);
    }
    let mut control = Control {
        cancel,
        deadline: started + Duration::from_secs(args.lifetime_seconds),
    };
    control.check()?;
    let encoded = Opened::open(
        &args.manifest,
        u64::try_from(MAX_MANIFEST_BYTES).map_err(|_| Failure::Bounds)?,
        &control,
    )?
    .read(&control)?;
    let signed = SignedManifest::decode(&encoded.bytes).map_err(|_| Failure::Manifest)?;
    let manifest = signed
        .verify(
            &args.publisher_key,
            now_seconds().map_err(|_| Failure::Expired)?,
        )
        .map_err(|error| match error {
            volparossa_content::Error::WrongPublisher => Failure::Publisher,
            volparossa_content::Error::Expired => Failure::Expired,
            _ => Failure::Manifest,
        })?;
    if manifest.metadata().content_type != SITE_CONTENT_TYPE {
        return Err(Failure::ContentType);
    }
    if manifest.length() > MAX_OBJECT_BYTES {
        return Err(Failure::Bounds);
    }
    let expires = manifest
        .validity()
        .expires
        .min(wall.saturating_add(args.lifetime_seconds));
    control.deadline = control
        .deadline
        .min(started + Duration::from_secs(manifest.validity().expires.saturating_sub(wall)));
    control.check()?;
    let snapshot = Opened::open(&args.input, MAX_OBJECT_BYTES, &control)?.read(&control)?;
    if u64::try_from(snapshot.bytes.len()).map_err(|_| Failure::Bounds)? != manifest.length() {
        return Err(Failure::Length);
    }
    if snapshot.sha256 != args.expected_input_sha256 || &snapshot.sha256 != manifest.object_sha256()
    {
        return Err(Failure::Digest);
    }
    verify_chunks(&snapshot.bytes, &manifest, &control)?;
    let bundle = SiteBundle::decode(snapshot.bytes).map_err(|_| Failure::Bundle)?;
    let authority = LocalAuthority {
        manifest,
        deadline: control.deadline,
        expires,
    };
    authority.check_live().map_err(|_| Failure::Expired)?;
    control.check()?;
    Ok(Prepared {
        deadline: authority.deadline,
        expires: authority.expires,
        authority,
        bundle,
    })
}

fn verify_chunks(bytes: &[u8], manifest: &VerifiedManifest, control: &Control) -> Result<()> {
    let mut offset = 0_usize;
    for chunk in manifest.chunks() {
        control.check()?;
        let end = offset
            .checked_add(usize::try_from(chunk.length()).map_err(|_| Failure::Chunk)?)
            .ok_or(Failure::Chunk)?;
        let payload = bytes.get(offset..end).ok_or(Failure::Chunk)?;
        if &ChunkId::digest(payload) != chunk.id() {
            return Err(Failure::Chunk);
        }
        offset = end;
    }
    if offset != bytes.len() {
        return Err(Failure::Chunk);
    }
    Ok(())
}

#[derive(Eq, PartialEq)]
struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl From<&Metadata> for Stamp {
    fn from(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            nlink: m.nlink(),
            len: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
struct Opened {
    file: File,
    before: Stamp,
}
struct Snapshot {
    bytes: Vec<u8>,
    sha256: [u8; 32],
}
impl Opened {
    fn open(path: &Path, maximum: u64, control: &Control) -> Result<Self> {
        control.check()?;
        let file = File::from(
            open(
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Failure::File)?,
        );
        let metadata = file.metadata().map_err(|_| Failure::File)?;
        if !metadata.is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(Failure::Profile);
        }
        if metadata.len() > maximum {
            return Err(Failure::Bounds);
        }
        Ok(Self {
            file,
            before: Stamp::from(&metadata),
        })
    }
    fn read(mut self, control: &Control) -> Result<Snapshot> {
        control.check()?;
        let maximum = usize::try_from(self.before.len)
            .map_err(|_| Failure::Bounds)?
            .checked_add(1)
            .ok_or(Failure::Bounds)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(maximum)
            .map_err(|_| Failure::Bounds)?;
        let mut sha = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            control.check()?;
            let bound = buffer.len().min(maximum - bytes.len());
            if bound == 0 {
                return Err(Failure::Changed);
            }
            let count = self
                .file
                .read(&mut buffer[..bound])
                .map_err(|_| Failure::File)?;
            control.check()?;
            if count == 0 {
                break;
            }
            sha.update(&buffer[..count]);
            bytes.extend_from_slice(&buffer[..count]);
        }
        let after = self.file.metadata().map_err(|_| Failure::File)?;
        if Stamp::from(&after) != self.before
            || u64::try_from(bytes.len()).map_err(|_| Failure::Bounds)? != self.before.len
        {
            return Err(Failure::Changed);
        }
        Ok(Snapshot {
            bytes,
            sha256: sha.finalize().into(),
        })
    }
}
