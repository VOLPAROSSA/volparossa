// SPDX-License-Identifier: GPL-3.0-only
use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use volparossa_content::{MAX_MANIFEST_BYTES, SignedManifest, VerifiedManifest};
use volparossa_local_control::{
    ContentCacheLimits, ContentImportRequest, ControlResult, control_request::Operation,
    control_response::Payload,
};

use super::{
    Cleanup, Progress, Result, Stage,
    fixture::{Fixture, absent, cache_stamp, private_file, read_private},
    process::{Daemon, cli, request},
};

const QUOTA: u64 = 1_048_576;
const MIN_FREE_BYTES: u64 = 64 * 1024 * 1024;

pub(super) async fn run(progress: &Progress) -> Result<()> {
    let total = Instant::now() + Duration::from_secs(100);
    let work = total - Duration::from_secs(10);
    let fixture = Fixture::create()?;
    progress.stage.set(Stage::Binary);
    fixture.verify_identity_and_binary()?;
    let mut daemon = Daemon::new();
    let outcome = operations(&fixture, &mut daemon, progress, work, total).await;
    // No early return skips joining this exact currently owned agent. A prior
    // joined crash child is never signalled again; restart receives a new handle.
    daemon.failure_join(progress, total).await?;
    outcome?;
    progress.stage.set(Stage::FixtureCleanup);
    fixture.directory.close().map_err(|_| "fixture_cleanup")?;
    if Instant::now() >= total {
        return Err("total_deadline");
    }
    if !progress.counts.get().complete() {
        return Err("actual_counts_differ");
    }
    progress
        .cleanup
        .set(Cleanup::NormalJoinedSocketAndFixtureRemoved);
    progress.stage.set(Stage::Complete);
    Ok(())
}

async fn operations(
    fixture: &Fixture,
    daemon: &mut Daemon,
    progress: &Progress,
    work: Instant,
    total: Instant,
) -> Result<()> {
    let (encoded, verified) = offline(fixture, progress, work, total).await?;
    progress.stage.set(Stage::Spawn);
    daemon.spawn(fixture, progress, work)?;
    daemon.ready(fixture, progress, work).await?;
    let mut tampered = encoded.clone();
    *tampered.last_mut().ok_or("manifest_empty")? ^= 1;
    // Preserve canonical protobuf and publisher hint; change only the signature.
    if SignedManifest::decode(&tampered)
        .map_err(|_| "tamper_shape")?
        .verify(&fixture.publisher, now()?)
        .is_ok()
    {
        return Err("tamper_not_effective");
    }
    progress.stage.set(Stage::AgentRejection);
    agent_rejection(fixture, daemon, &tampered, progress, work).await?;
    progress.stage.set(Stage::NegativeImport);
    import_rejections(fixture, &tampered, &verified, progress, work, total).await?;
    progress.stage.set(Stage::Import);
    let value = cli(
        fixture,
        handoff_args(
            fixture,
            "import",
            "manifest.pb",
            "source-cache",
            "agent-cache",
        ),
        progress,
        work,
        total,
    )
    .await?
    .json()?;
    handoff(&value, "content_import", &verified)?;
    let cache_before = cache_stamp(&fixture.path("agent-cache"))?;
    progress.stage.set(Stage::CrashJoin);
    daemon.crash(progress, work).await?;
    if cache_stamp(&fixture.path("agent-cache"))? != cache_before {
        return Err("cache_changed_after_joined_crash");
    }
    progress.stage.set(Stage::Restart);
    daemon.spawn(fixture, progress, work)?;
    daemon.ready(fixture, progress, work).await?;
    progress.stage.set(Stage::Export);
    let value = cli(
        fixture,
        handoff_args(
            fixture,
            "export",
            "manifest.pb",
            "export-cache",
            "agent-cache",
        ),
        progress,
        work,
        total,
    )
    .await?
    .json()?;
    handoff(&value, "content_export", &verified)?;
    if cache_stamp(&fixture.path("agent-cache"))? != cache_before {
        return Err("reopened_cache_identity_changed");
    }
    progress.stage.set(Stage::Assemble);
    assemble(fixture, &verified, progress, work, total).await?;
    if read_private(
        &fixture.path("manifest.pb"),
        u64::try_from(MAX_MANIFEST_BYTES).map_err(|_| "manifest_bound")?,
    )? != encoded
    {
        return Err("original_manifest_changed");
    }
    fixture.verify_identity_and_binary()?;
    progress.stage.set(Stage::Shutdown);
    daemon.graceful(progress, work).await?;
    progress.stage.set(Stage::SocketCleanup);
    absent(&fixture.socket)?;
    absent(&fixture.socket.with_extension("sock.apps"))?;
    absent(&fixture.path("control/absent-helper.sock"))?;
    absent(&fixture.path("control/helper.cleanup-token"))?;
    absent(&fixture.path("control/absent-mpquic.sock"))?;
    Ok(())
}

async fn offline(
    fixture: &Fixture,
    progress: &Progress,
    work: Instant,
    total: Instant,
) -> Result<(Vec<u8>, VerifiedManifest)> {
    progress.stage.set(Stage::NegativePublication);
    publication_rejections(fixture, progress, work, total).await?;
    progress.stage.set(Stage::Publish);
    let report = cli(
        fixture,
        publish_args(
            fixture,
            "source-cache",
            "manifest.pb",
            &hex::encode(fixture.input_hash),
            &hex::encode(fixture.publisher.as_bytes()),
        ),
        progress,
        work,
        total,
    )
    .await?
    .json()?;
    let (encoded, verified) = publication(fixture, &report)?;
    absent(&fixture.socket)?; // The actual publication remained offline.
    Ok((encoded, verified))
}

fn publish_args(
    fixture: &Fixture,
    cache: &str,
    manifest: &str,
    input_hash: &str,
    publisher: &str,
) -> Vec<OsString> {
    let mut args = vec![
        "publish".into(),
        "--input".into(),
        fixture.path("public-synthetic.bin").into_os_string(),
        "--expected-input-sha256".into(),
        input_hash.into(),
        "--expected-publisher-key".into(),
        publisher.into(),
        "--cache".into(),
        fixture.path(cache).into_os_string(),
        "--manifest".into(),
        fixture.path(manifest).into_os_string(),
        "--name".into(),
        "public-synthetic-daemon-fixture".into(),
        "--revision".into(),
        "1".into(),
        "--lifetime-seconds".into(),
        "600".into(),
        "--identity".into(),
        fixture.path("state/identity.key").into_os_string(),
        "--passphrase-file".into(),
        fixture
            .path("credentials/identity-passphrase")
            .into_os_string(),
    ];
    limits(&mut args);
    args
}

fn handoff_args(
    fixture: &Fixture,
    operation: &str,
    manifest: &str,
    cache: &str,
    agent_cache: &str,
) -> Vec<OsString> {
    let mut args = vec![
        operation.into(),
        "--manifest".into(),
        fixture.path(manifest).into_os_string(),
        "--publisher-key".into(),
        hex::encode(fixture.publisher.as_bytes()).into(),
        "--cache".into(),
        fixture.path(cache).into_os_string(),
        "--agent-cache".into(),
        fixture.path(agent_cache).into_os_string(),
        "--public-content".into(),
    ];
    limits(&mut args);
    args
}

fn limits(args: &mut Vec<OsString>) {
    args.extend(["--quota-bytes", "1048576", "--max-entries", "8"].map(OsString::from));
}

async fn publication_rejections(
    fixture: &Fixture,
    progress: &Progress,
    work: Instant,
    total: Instant,
) -> Result<()> {
    let wrong_key = SigningKey::from_bytes(&[2; 32]).verifying_key();
    for (cache, manifest, hash, key, error) in [
        (
            "rejected-input-cache",
            "rejected-input.pb",
            hex::encode([0; 32]),
            hex::encode(fixture.publisher.as_bytes()),
            b"content input does not match the expected SHA-256".as_slice(),
        ),
        (
            "rejected-publisher-cache",
            "rejected-publisher.pb",
            hex::encode(fixture.input_hash),
            hex::encode(wrong_key.as_bytes()),
            b"content publisher does not match the expected publisher key".as_slice(),
        ),
    ] {
        let result = cli(
            fixture,
            publish_args(fixture, cache, manifest, &hash, &key),
            progress,
            work,
            total,
        )
        .await?;
        result.rejection(error)?;
        absent(&fixture.path(cache))?;
        absent(&fixture.path(manifest))?;
        absent(&fixture.socket)?;
        progress.count(|counts| counts.cli_rejections += 1);
    }
    Ok(())
}

fn publication(fixture: &Fixture, report: &Value) -> Result<(Vec<u8>, VerifiedManifest)> {
    let encoded = read_private(
        &fixture.path("manifest.pb"),
        u64::try_from(MAX_MANIFEST_BYTES).map_err(|_| "manifest_bound")?,
    )?;
    let signed = SignedManifest::decode(&encoded).map_err(|_| "manifest_shape")?;
    let verified = signed
        .verify(&fixture.publisher, now()?)
        .map_err(|_| "manifest_signature")?;
    if verified.length() != u64::try_from(fixture.bytes.len()).map_err(|_| "input_length")?
        || verified.object_sha256() != &fixture.input_hash
        || verified.chunks().len() != 2
        || verified.metadata().name != "public-synthetic-daemon-fixture"
        || verified.metadata().revision != 1
        || verified.metadata().content_type != "application/octet-stream"
        || verified
            .validity()
            .expires
            .checked_sub(verified.validity().created)
            != Some(600)
        || report["operation"] != "offline_content_publish"
        || report["network_publication"] != false
        || report["publisher_key_hex"] != hex::encode(fixture.publisher.as_bytes())
        || report["manifest_id"] != hex::encode(verified.manifest_id())
        || report["bytes"].as_u64() != Some(verified.length())
        || report["chunks"].as_u64() != Some(2)
        || report["expires_unix_seconds"].as_u64() != Some(verified.validity().expires)
    {
        return Err("offline_publication_binding");
    }
    Ok((encoded, verified))
}

async fn agent_rejection(
    fixture: &Fixture,
    daemon: &Daemon,
    tampered: &[u8],
    progress: &Progress,
    deadline: Instant,
) -> Result<()> {
    let path = fixture.path("typed-rejected-cache");
    let operation = Operation::ContentImport(ContentImportRequest {
        manifest: tampered.to_vec(),
        publisher_key: fixture.publisher.as_bytes().to_vec(),
        cache: path.to_str().ok_or("fixture_path_encoding")?.into(),
        limits: Some(ContentCacheLimits {
            quota_bytes: QUOTA,
            max_entries: 8,
            min_free_bytes: MIN_FREE_BYTES,
        }),
        allow_public_content: true,
        contribute: false,
    });
    let reply = request(fixture, daemon.pid()?, operation, 3, deadline).await?;
    if reply.result != ControlResult::InvalidRequest as i32
        || reply.diagnostic_code != "CONTENT_INVALID"
        || !matches!(reply.payload, Some(Payload::Ack(_)))
    {
        return Err("typed_tamper_refusal");
    }
    absent(&path)?;
    progress.count(|counts| counts.agent_rejections += 1);
    Ok(())
}

async fn import_rejections(
    fixture: &Fixture,
    tampered: &[u8],
    verified: &VerifiedManifest,
    progress: &Progress,
    work: Instant,
    total: Instant,
) -> Result<()> {
    private_file(&fixture.path("tampered.pb"), tampered)?;
    let result = cli(
        fixture,
        handoff_args(
            fixture,
            "import",
            "tampered.pb",
            "source-cache",
            "bad-manifest-agent-cache",
        ),
        progress,
        work,
        total,
    )
    .await?;
    result.rejection(b"invalid native content publisher signature")?;
    absent(&fixture.path("bad-manifest-agent-cache"))?;
    progress.count(|counts| counts.cli_rejections += 1);
    let path = fixture
        .path("source-cache")
        .join(verified.chunks()[0].id().to_string());
    let original = read_private(
        &path,
        u64::try_from(volparossa_content::CHUNK_BYTES).map_err(|_| "chunk_bound")?,
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| "chunk_tamper_open")?;
    file.write_all(&[original[0] ^ 1])
        .map_err(|_| "chunk_tamper")?;
    let result = cli(
        fixture,
        handoff_args(
            fixture,
            "import",
            "manifest.pb",
            "source-cache",
            "bad-chunk-agent-cache",
        ),
        progress,
        work,
        total,
    )
    .await;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "chunk_restore_seek")?;
    file.write_all(&original[..1])
        .map_err(|_| "chunk_restore")?;
    result?.rejection(b"native source is incomplete or fails the signed whole-object hash")?;
    absent(&fixture.path("bad-chunk-agent-cache"))?;
    progress.count(|counts| counts.cli_rejections += 1);
    Ok(())
}

fn handoff(value: &Value, operation: &str, manifest: &VerifiedManifest) -> Result<()> {
    if value["operation"] != operation
        || value["manifest_id"] != hex::encode(manifest.manifest_id())
        || value["content_bytes"].as_u64() != Some(manifest.length())
        || value["chunks"].as_u64() != u64::try_from(manifest.chunks().len()).ok()
        || value["complete"] != true
        || value["public_content"] != true
        || value["network_transfer"] != false
        || value["ownership_changed"] != false
        || value["private_keys_transferred"] != false
        || value["origin_authenticated"] != false
    {
        return Err("actual_handoff_receipt");
    }
    Ok(())
}

async fn assemble(
    fixture: &Fixture,
    manifest: &VerifiedManifest,
    progress: &Progress,
    work: Instant,
    total: Instant,
) -> Result<()> {
    let output = fixture.path("reconstructed-public.bin");
    let mut args = vec![
        "assemble".into(),
        "--manifest".into(),
        fixture.path("manifest.pb").into_os_string(),
        "--publisher-key".into(),
        hex::encode(fixture.publisher.as_bytes()).into(),
        "--cache".into(),
        fixture.path("export-cache").into_os_string(),
        "--output".into(),
        output.clone().into_os_string(),
    ];
    limits(&mut args);
    let value = cli(fixture, args, progress, work, total).await?.json()?;
    let recovered = read_private(&output, QUOTA)?;
    if value["operation"] != "offline_content_assemble"
        || value["network_retrieval"] != false
        || value["bytes"].as_u64() != Some(manifest.length())
        || value["chunks"].as_u64() != Some(2)
        || recovered != fixture.bytes
        || <[u8; 32]>::from(Sha256::digest(&recovered)) != fixture.input_hash
    {
        return Err("reconstruction_binding");
    }
    let chunks = u32::try_from(manifest.chunks().len()).map_err(|_| "verified_chunks_bound")?;
    progress.count(|counts| {
        counts.verified_bytes = manifest.length();
        counts.verified_chunks = chunks;
    });
    Ok(())
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| "fixture_clock")
}
