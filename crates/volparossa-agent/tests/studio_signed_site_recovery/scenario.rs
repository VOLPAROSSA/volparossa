// SPDX-License-Identifier: GPL-3.0-only
use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::Instant;
use volparossa_content::{MAX_MANIFEST_BYTES, VerifiedManifest};

use super::{
    Progress, Result,
    browser::{Browser, Preview, refusals},
    fixture::{Fixture, absent, cache_stamp, read_private},
    process::Daemon,
    site::{self, Packed},
    stage,
};

struct Observed {
    bindings: Value,
    browser: Value,
}

pub(super) async fn run() -> Result<Value> {
    // The paired controller owns an 80-second child wait; reserve its final
    // five seconds and ten more here for unconditional owned-child joins.
    let total = Instant::now() + Duration::from_secs(75);
    let work = total - Duration::from_secs(10);
    let fixture = Fixture::create()?;
    fixture.verify_identity_and_binary()?;
    let progress = Progress::new();
    let mut daemon = Daemon::new();
    let mut preview = Preview::new();
    let mut browser = Browser::new();
    let outcome = operations(
        &fixture,
        &progress,
        &mut daemon,
        &mut preview,
        &mut browser,
        work,
        total,
    )
    .await;
    // Run every owner even when an earlier cleanup fails. A proof never survives
    // an unconfirmed join, and directories still used by children are retained.
    let browser_join = browser.force_join(total).await;
    let preview_join = preview.force_join(total).await;
    let daemon_join = daemon.failure_join(&progress, total).await;
    if browser_join.is_err() || preview_join.is_err() || daemon_join.is_err() {
        let _retained = fixture.directory.keep();
        return Err(outcome.err().unwrap_or("owned_child_cleanup_unconfirmed"));
    }
    let observed = outcome?;
    if !progress.counts.get().complete() {
        return Err("observed_counts");
    }
    stage("cleanup");
    fixture
        .directory
        .close()
        .map_err(|_| "private_state_cleanup")?;
    if Instant::now() >= total {
        return Err("total_deadline");
    }
    stage("complete");
    Ok(proof(observed, &progress))
}

async fn operations(
    f: &Fixture,
    p: &Progress,
    daemon: &mut Daemon,
    preview: &mut Preview,
    browser: &mut Browser,
    work: Instant,
    total: Instant,
) -> Result<Observed> {
    stage("pack");
    let packed = site::pack(f, p, work, total).await?;
    stage("publish");
    let (original, manifest) = site::publish(f, p, &packed, work, total).await?;
    absent(&f.socket)?;
    let source_stamp = cache_stamp(&f.path("source-cache"))?;
    stage("agent_import");
    daemon.spawn(f, p, work)?;
    daemon.ready(f, p, work).await?;
    site::handoff(f, p, "import", &manifest, work, total).await?;
    let cache_before = cache_stamp(&f.path("agent-cache"))?;
    stage("crash_join");
    daemon.crash(p, work).await?;
    stage("reopen");
    daemon.spawn(f, p, work)?;
    daemon.ready(f, p, work).await?;
    stage("export");
    site::handoff(f, p, "export", &manifest, work, total).await?;
    if cache_stamp(&f.path("agent-cache"))? != cache_before
        || cache_stamp(&f.path("source-cache"))? != source_stamp
    {
        return Err("same_cache_identity");
    }
    stage("assemble");
    site::assemble(f, p, &packed, &manifest, work, total).await?;
    stage("preview");
    refusals(f, p, &packed, work, total).await?;
    let ready = preview.start(f, p, &packed, &manifest, work).await?;
    stage("browser_observation");
    let browser_receipt = browser.observe(f, &ready, &packed, work).await?;
    stage("shutdown");
    preview.shutdown(p, work).await?;
    daemon.graceful(p, work).await?;
    for path in [
        &f.socket,
        &f.socket.with_extension("sock.apps"),
        &f.path("control/absent-helper.sock"),
        &f.path("control/helper.cleanup-token"),
        &f.path("control/absent-mpquic.sock"),
    ] {
        absent(path)?;
    }
    f.verify_identity_and_binary()?;
    if read_private(
        &f.path("manifest.pb"),
        u64::try_from(MAX_MANIFEST_BYTES).map_err(|_| "manifest_limit")?,
    )? != original
        || read_private(&f.path("site.bundle"), site::MAX_BYTES)? != packed.bytes
    {
        return Err("original_publication_changed");
    }
    Ok(Observed {
        bindings: bindings(&packed, &manifest),
        browser: browser_receipt,
    })
}
fn bindings(packed: &Packed, manifest: &VerifiedManifest) -> Value {
    json!({"bundle_sha256":hex::encode(packed.sha),"bundle_bytes":manifest.length(),
        "asset_count":packed.assets.len(),"chunk_count":manifest.chunks().len(),
        "manifest_id":hex::encode(manifest.manifest_id()),"publisher_key":hex::encode(manifest.publisher()),
        "revision":manifest.metadata().revision,"publication_expires_unix_seconds":manifest.validity().expires})
}
fn proof(observed: Observed, progress: &Progress) -> Value {
    json!({"schema":1,"status":"passed","proof_mode":"signed-site-recovery",
        "bindings":observed.bindings,"counts":progress.counts.get(),
        "checks":{"actual_cli_pack":true,"original_signed_publication":true,"roles_off_agent_import":true,
            "crash_reopen_same_cache":true,"agent_export_assemble_equal":true,"local_signed_preview":true,"all_zip_assets_verified":true},
        "cleanup":{"cli_children_joined":true,"agent_children_joined":true,"browser_closed":true,"listener_closed":true,"private_state_removed":true},
        "scope":{"ephemeral_test_identity":true,"real_cli_test_key_signing":true,"mock_local_control_peer":false,
            "gui_native_publication_consent":false,"named_lookup_performed":false,"globally_latest":false,
            "https_origin_authenticated":false,"network_published":false,"protected_peer_retrieval":false,
            "independent_hosting":false,"full_studio_acceptance":false,"power_loss_recovery":false,"physical_node_participation":false},
        "browser":observed.browser})
}
