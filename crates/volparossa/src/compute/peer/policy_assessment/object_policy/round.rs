//! One finite, explicitly enrolled assessment-to-quorum publication round.
//! The coordinator holds a content identity, never the authorities' signing keys.

pub(in crate::compute::peer) mod authority;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::signal::unix::{SignalKind, signal};
use volparossa_content::{ChunkStore, SignedManifest};
use volparossa_policy::object::{
    SignedObjectDecision,
    exchange::{DecisionRequest, MAX_ASSESSMENT_BUNDLE_BYTES},
    verify_object_decision, verify_object_endorsement,
};

use super::{
    Combine, Propose, Selection, combine_value, distribution, milliseconds, parse_key,
    policy_context, propose_value, retain, sha, storage, task,
};
use crate::{
    content::{self, policy_exchange},
    doctor::PolicyContext,
};

#[derive(Clone, Debug)]
pub(in crate::compute::peer::policy_assessment) struct Authority {
    pub(in crate::compute::peer::policy_assessment) key: VerifyingKey,
    pub(in crate::compute::peer::policy_assessment) publisher: VerifyingKey,
    pub(in crate::compute::peer::policy_assessment) reply_name: String,
}

pub(in crate::compute::peer::policy_assessment) fn parse_authority(
    value: &str,
) -> Result<Authority, String> {
    let mut fields = value.split(':');
    let key = parse_key(fields.next().ok_or("policy_round_authority_binding")?)?;
    let publisher = parse_key(fields.next().ok_or("policy_round_authority_binding")?)?;
    let reply_name =
        content::parse_content_name(fields.next().ok_or("policy_round_authority_binding")?)?;
    if fields.next().is_some() || key == publisher {
        return Err("policy_round_separate_authority_transport_binding".into());
    }
    Ok(Authority {
        key,
        publisher,
        reply_name,
    })
}

#[derive(Debug, Args)]
pub(crate) struct Options {
    #[command(flatten)]
    pub(in crate::compute::peer::policy_assessment) selection: Selection,
    /// `POLICY_KEY:TRANSPORT_PUBLISHER:REPLY_NAME`, selected separately from content discovery.
    #[arg(long, required=true, value_parser=parse_authority)]
    pub(in crate::compute::peer::policy_assessment) authority: Vec<Authority>,
    /// Only the original request and completed quorum are signed with this content identity.
    #[arg(long, value_parser=parse_key)]
    pub(in crate::compute::peer::policy_assessment) publication_key: VerifyingKey,
    #[arg(long)]
    pub(in crate::compute::peer::policy_assessment) identity: PathBuf,
    #[arg(long)]
    pub(in crate::compute::peer::policy_assessment) passphrase_file: PathBuf,
    #[arg(long, value_parser=content::parse_content_name)]
    pub(in crate::compute::peer::policy_assessment) request_name: String,
    #[arg(long, value_parser=content::parse_content_name)]
    pub(in crate::compute::peer::policy_assessment) publish_name: String,
    /// Optional explicit peers to retain the original final wrapper instead of local serving.
    #[arg(long, value_parser=parse_key)]
    pub(in crate::compute::peer::policy_assessment) publication_provider_key: Vec<VerifyingKey>,
    #[arg(long, value_parser=clap::value_parser!(u64).range(1..))]
    pub(in crate::compute::peer::policy_assessment) decision_revision: u64,
    #[arg(long)]
    pub(in crate::compute::peer::policy_assessment) directory: PathBuf,
    /// Original finite round budget; resuming does not extend it or any signed expiry.
    #[arg(long, default_value_t=600, value_parser=clap::value_parser!(u16).range(1..=3600))]
    pub(in crate::compute::peer::policy_assessment) max_seconds: u16,
    #[arg(long, default_value_t=5, value_parser=clap::value_parser!(u16).range(1..=3600))]
    pub(in crate::compute::peer::policy_assessment) poll_seconds: u16,
    #[arg(long)]
    pub(in crate::compute::peer::policy_assessment) execute: bool,
    #[arg(long, requires = "execute")]
    pub(in crate::compute::peer::policy_assessment) resume: bool,
    #[command(flatten)]
    pub(in crate::compute::peer::policy_assessment) limits: content::Limits,
}

fn bindings(authorities: &[Authority]) -> Result<()> {
    ensure!(
        (1..=volparossa_policy::MAX_MAINTAINERS).contains(&authorities.len()),
        "policy_round_authority_count"
    );
    let mut keys = BTreeSet::new();
    let mut channels = BTreeSet::new();
    for authority in authorities {
        ensure!(
            authority.key != authority.publisher
                && keys.insert(authority.key.to_bytes())
                && channels.insert((authority.publisher.to_bytes(), authority.reply_name.clone())),
            "policy_round_distinct_authorities_and_channels"
        );
    }
    Ok(())
}

fn threshold(args: &Options, context: &PolicyContext) -> Result<usize> {
    let required = context
        .verification
        .minimum_signatures()
        .max(context.manifest.required_signatures());
    ensure!(
        args.authority.len() >= required
            && args.authority.iter().all(|selected| context
                .trust
                .maintainers()
                .iter()
                .any(|trusted| trusted.verifying_key() == &selected.key)),
        "policy_round_independently_configured_quorum"
    );
    ensure!(
        !context
            .trust
            .maintainers()
            .iter()
            .any(|trusted| trusted.verifying_key() == &args.publication_key),
        "policy_round_separate_transport_identity"
    );
    Ok(required)
}

fn selection(args: &Options) -> Selection {
    Selection {
        assessment_bundle: args.directory.join("assessment.bundle"),
        policy_config: args.selection.policy_config.clone(),
        requester_key: args.selection.requester_key,
        source_publisher_key: args.selection.source_publisher_key,
        source_manifest_id: args.selection.source_manifest_id,
        provider_key: args.selection.provider_key.clone(),
        model_profile: args.selection.model_profile,
    }
}

fn enrollment(args: &Options, bytes: &[u8]) -> Value {
    json!({"version":1,"scope":"finite_selected_authority_round",
        "assessment_bundle":args.selection.assessment_bundle,"assessment_sha256":sha(bytes),
        "selection":super::selection_record(&args.selection),"policy_config":args.selection.policy_config,
        "authorities":args.authority.iter().map(|authority|json!({
            "policy_key":hex::encode(authority.key.as_bytes()),
            "transport_publisher":hex::encode(authority.publisher.as_bytes()),
            "reply_name":authority.reply_name})).collect::<Vec<_>>(),
        "publication_key":hex::encode(args.publication_key.as_bytes()),
        "identity":args.identity,"passphrase_file":args.passphrase_file,
        "request_name":args.request_name,"publish_name":args.publish_name,
        "publication_provider_keys":args.publication_provider_key.iter().map(|key|hex::encode(key.as_bytes())).collect::<Vec<_>>(),
        "decision_revision":args.decision_revision,"max_seconds":args.max_seconds,
        "poll_seconds":args.poll_seconds,"limits":args.limits.configuration()})
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    started_at_ms: u64,
    deadline_ms: u64,
}

fn window(args: &Options) -> Result<Window> {
    let path = args.directory.join("window.json");
    if args.resume {
        let original: Window = serde_json::from_slice(&storage::read(&path, 1024)?)?;
        ensure!(
            original.deadline_ms.checked_sub(original.started_at_ms)
                == Some(u64::from(args.max_seconds) * 1000),
            "policy_round_original_deadline_changed"
        );
        Ok(original)
    } else {
        let started_at_ms = milliseconds()?;
        let original = Window {
            started_at_ms,
            deadline_ms: started_at_ms
                .checked_add(u64::from(args.max_seconds) * 1000)
                .context("policy_round_deadline")?,
        };
        retain(&path, &serde_json::to_vec(&original)?)?;
        Ok(original)
    }
}

fn status(args: &Options, phase: &str, verified: usize) -> Result<()> {
    task::write_bytes(
        &args.directory.join("status.json"),
        &serde_json::to_vec(&json!({
        "operation":"compute_policy_round","phase":phase,"verified_endorsements":verified,
        "complete":phase=="complete","model_execution":false,"assessment_started":false,
        "authority_private_keys_loaded":false,"network_policy_activation":false}))?,
        true,
    )
}

pub(in crate::compute::peer) async fn run(args: &Options, socket: &Path) -> Result<()> {
    println!("{}", run_value(args, socket).await?);
    Ok(())
}

pub(in crate::compute::peer::policy_assessment) async fn run_value(
    args: &Options,
    socket: &Path,
) -> Result<Value> {
    bindings(&args.authority)?;
    ensure!(
        args.publication_provider_key.len() <= 32
            && args
                .publication_provider_key
                .iter()
                .all(|key| *key != args.publication_key)
            && args
                .publication_provider_key
                .iter()
                .map(VerifyingKey::to_bytes)
                .collect::<BTreeSet<_>>()
                .len()
                == args.publication_provider_key.len(),
        "policy_round_publication_provider_selection"
    );
    ensure!(
        [&args.identity, &args.passphrase_file, &args.directory]
            .iter()
            .all(|path| path.is_absolute())
            && args.request_name != args.publish_name,
        "policy_round_absolute_distinct_paths_names"
    );
    let preview = super::preview(
        &args.selection,
        &args.directory,
        "compute_policy_round",
        args.execute,
    )?;
    if let Some(mut planned) = preview {
        planned["assessment_started"] = false.into();
        planned["authority_private_keys_loaded"] = false.into();
        planned["selected_authorities"] = args.authority.len().into();
        return Ok(planned);
    }
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let _lock = task::open_directory(&args.directory, args.resume)?;
    let bytes = storage::read(
        &args.selection.assessment_bundle,
        MAX_ASSESSMENT_BUNDLE_BYTES as u64,
    )?;
    retain(
        &args.directory.join("enrollment.json"),
        &serde_json::to_vec(&enrollment(args, &bytes))?,
    )?;
    retain(&args.directory.join("assessment.bundle"), &bytes)?;
    let window = window(args)?;
    let remaining = window
        .deadline_ms
        .checked_sub(milliseconds()?)
        .filter(|remaining| *remaining > 0)
        .context("policy_round_original_deadline_expired")?;
    let result = tokio::select! { biased;
        _=interrupt.recv()=>Err(anyhow::anyhow!("policy_round_interrupted_retained")),
        _=terminate.recv()=>Err(anyhow::anyhow!("policy_round_interrupted_retained")),
        result=tokio::time::timeout(Duration::from_millis(remaining), execute(args,socket))=>
            result.context("policy_round_original_deadline_retained").and_then(std::convert::identity),
    };
    match result {
        Ok(result) => {
            retain(
                &args.directory.join("result.json"),
                &serde_json::to_vec(&result)?,
            )?;
            status(
                args,
                "complete",
                usize::try_from(
                    result["verified_endorsements"]
                        .as_u64()
                        .context("policy_round_result_count")?,
                )?,
            )?;
            Ok(result)
        }
        Err(error) => {
            status(args, "incomplete_retained", 0)?;
            Err(error)
        }
    }
}

fn request_publication(
    args: &Options,
    proposal: &SignedObjectDecision,
) -> Result<content::PolicyDecisionPublication> {
    let cache = args.directory.join("request-cache");
    Ok(content::PolicyDecisionPublication {
        input: args.directory.join("request.bin"),
        reuse_cache: storage::exists(&cache)?,
        cache,
        manifest: args.directory.join("request.manifest"),
        name: args.request_name.clone(),
        revision: args.decision_revision,
        expires_not_after: proposal.body().expires_at_ms / 1000,
        identity: args.identity.clone(),
        passphrase_file: args.passphrase_file.clone(),
        limits: args.limits.clone(),
    })
}

async fn contribution(
    args: &Options,
    manifest: PathBuf,
    cache: PathBuf,
    id: [u8; 32],
    record: &str,
    socket: &Path,
) -> Result<Value> {
    let path = args.directory.join(record);
    if storage::exists(&path)? {
        let original: Value = serde_json::from_slice(&storage::read(&path, 64 * 1024)?)?;
        ensure!(
            original["manifest_id"] == hex::encode(id)
                && original["serving"] == true
                && original["network_publication"] == true,
            "policy_round_original_contribution_changed"
        );
        return Ok(original);
    }
    let receipt = content::contribute_existing(
        &content::Contribute::existing(manifest, args.publication_key, cache, args.limits.clone())
            .expect_manifest_id(id),
        socket,
    )
    .await?;
    retain(&path, &serde_json::to_vec(&receipt)?)?;
    Ok(receipt)
}

async fn deliver(
    args: &Options,
    proposal: &SignedObjectDecision,
    id: [u8; 32],
    socket: &Path,
) -> Result<()> {
    if args
        .authority
        .iter()
        .any(|authority| authority.publisher == args.publication_key)
    {
        contribution(
            args,
            args.directory.join("request.manifest"),
            args.directory.join("request-cache"),
            id,
            "request-contribution.json",
            socket,
        )
        .await?;
    }
    let mut providers = Vec::new();
    for authority in &args.authority {
        if authority.publisher != args.publication_key && !providers.contains(&authority.publisher)
        {
            providers.push(authority.publisher);
        }
    }
    if providers.is_empty() {
        return Ok(());
    }
    // Keep every failed batch's original signed receipts, as well as a successful retry.
    for attempt in 0..64 {
        let path = args
            .directory
            .join(format!("request-deposit-{attempt:02}.json"));
        if storage::exists(&path)? {
            let prior: Value = serde_json::from_slice(&storage::read(&path, 1024 * 1024)?)?;
            ensure!(
                prior["manifest_id"] == hex::encode(id)
                    && prior["publisher_key_hex"] == hex::encode(args.publication_key.as_bytes())
                    && prior["original_expiry_unix_seconds"]
                        == proposal.body().expires_at_ms / 1000
                    && prior["requested_providers"] == providers.len(),
                "policy_round_original_deposit_changed"
            );
            if prior["complete"] == true {
                return Ok(());
            }
            continue;
        }
        let receipt = policy_exchange::deposit(
            &request_publication(args, proposal)?,
            providers.clone(),
            socket,
        )
        .await?;
        retain(&path, &serde_json::to_vec(&receipt)?)?;
        if receipt["complete"] == true {
            return Ok(());
        }
        // A parallel enrolled owner may currently hold the agent's retrieval slot.
        // Retry only this original object, within the unchanged outer round deadline.
        tokio::time::sleep(Duration::from_secs(u64::from(args.poll_seconds))).await;
    }
    anyhow::bail!("policy_round_request_custody_retry_bound")
}

fn verify_reply(
    authority: &Authority,
    proposal: &SignedObjectDecision,
    signed_manifest: &[u8],
    bytes: &[u8],
    context: &PolicyContext,
    at: u64,
) -> Result<()> {
    let manifest =
        SignedManifest::decode(signed_manifest)?.verify(&authority.publisher, at / 1000)?;
    ensure!(
        manifest.metadata().name == authority.reply_name
            && manifest.metadata().revision == proposal.body().decision_revision
            && manifest.metadata().content_type
                == policy_exchange::Kind::Endorsement.content_type()
            && manifest.length() == bytes.len() as u64
            && hex::encode(manifest.object_sha256()) == sha(bytes)
            && manifest.validity().expires <= proposal.body().expires_at_ms / 1000,
        "policy_round_reply_original_transport_binding"
    );
    let verified = verify_object_endorsement(
        bytes,
        at,
        &authority.key,
        &context.trust,
        context.verification,
        &context.manifest,
    )?;
    ensure!(
        verified.body() == proposal.body(),
        "policy_round_reply_original_proposal_changed"
    );
    Ok(())
}

async fn receive(
    args: &Options,
    authority: &Authority,
    proposal: &SignedObjectDecision,
    socket: &Path,
) -> Result<Option<PathBuf>> {
    let prefix = hex::encode(authority.key.as_bytes());
    let record_path = args.directory.join(format!("reply-{prefix}.json"));
    let endorsement_path = args.directory.join(format!("endorsement-{prefix}.bin"));
    let context = policy_context(&args.selection, milliseconds()?)?;
    if storage::exists(&record_path)? {
        let original: Value = serde_json::from_slice(&storage::read(&record_path, 256 * 1024)?)?;
        let bytes = hex::decode(
            original["endorsement_hex"]
                .as_str()
                .context("policy_round_original_reply")?,
        )?;
        let manifest = hex::decode(
            original["manifest_hex"]
                .as_str()
                .context("policy_round_original_reply")?,
        )?;
        verify_reply(
            authority,
            proposal,
            &manifest,
            &bytes,
            &context,
            milliseconds()?,
        )?;
        retain(&endorsement_path, &bytes)?;
        return Ok(Some(endorsement_path));
    }
    // One unavailable selected peer must not consume the entire finite round.
    let downloaded = tokio::time::timeout(Duration::from_secs(30), async {
        if authority.publisher == args.publication_key {
            policy_exchange::local_endorsement(
                &authority.publisher,
                &authority.reply_name,
                args.decision_revision,
                socket,
                &args.directory,
            )
            .await
        } else {
            policy_exchange::endorsement(
                &content::policy_decision::Feed {
                    publisher: authority.publisher,
                    name: authority.reply_name.clone(),
                    min_revision: args.decision_revision,
                    cache: args.directory.join("reply-cache"),
                    limits: args.limits.clone(),
                },
                socket,
                &args.directory,
            )
            .await
        }
    })
    .await;
    let Ok(Ok(download)) = downloaded else {
        return Ok(None);
    };
    let context = policy_context(&args.selection, milliseconds()?)?;
    if verify_reply(
        authority,
        proposal,
        &download.signed_manifest,
        &download.bytes,
        &context,
        milliseconds()?,
    )
    .is_err()
    {
        return Ok(None);
    }
    let record = json!({"endorsement_hex":hex::encode(&download.bytes),
        "manifest_hex":hex::encode(&download.signed_manifest),"download_receipt":download.receipt});
    retain(&record_path, &serde_json::to_vec(&record)?)?;
    retain(&endorsement_path, &download.bytes)?;
    Ok(Some(endorsement_path))
}

async fn quorum(
    args: &Options,
    proposal: &SignedObjectDecision,
    required: usize,
    socket: &Path,
) -> Result<Vec<PathBuf>> {
    let path = args.directory.join("quorum.json");
    if storage::exists(&path)? {
        let keys: Vec<String> = serde_json::from_slice(&storage::read(&path, 4096)?)?;
        let unique = keys.iter().collect::<BTreeSet<_>>();
        ensure!(
            keys.len() == required && unique.len() == keys.len(),
            "policy_round_original_quorum_changed"
        );
        let mut endorsements = Vec::new();
        for key in keys {
            let selected = args
                .authority
                .iter()
                .find(|authority| hex::encode(authority.key.as_bytes()) == key)
                .context("policy_round_original_quorum_changed")?;
            ensure!(
                storage::exists(&args.directory.join(format!("reply-{key}.json")))?,
                "policy_round_original_quorum_reply_missing"
            );
            endorsements.push(
                receive(args, selected, proposal, socket)
                    .await?
                    .context("policy_round_original_quorum_reply_missing")?,
            );
        }
        return Ok(endorsements);
    }
    loop {
        let mut keys = Vec::new();
        let mut found = Vec::new();
        for authority in &args.authority {
            if let Some(path) = receive(args, authority, proposal, socket).await? {
                keys.push(hex::encode(authority.key.as_bytes()));
                found.push(path);
            }
            if found.len() >= required {
                break;
            }
        }
        status(args, "awaiting_quorum", found.len())?;
        if found.len() >= required {
            retain(&path, &serde_json::to_vec(&keys)?)?;
            return Ok(found);
        }
        ensure!(
            milliseconds()? < proposal.body().expires_at_ms,
            "policy_round_original_proposal_expired"
        );
        tokio::time::sleep(Duration::from_secs(u64::from(args.poll_seconds))).await;
    }
}

/// Reject an unusable locally configured quorum before a composing caller starts model work.
/// No assessment file, private authority key or remote service is read here.
pub(in crate::compute::peer::policy_assessment) fn preflight_authorities(
    args: &Options,
) -> Result<usize> {
    bindings(&args.authority)?;
    threshold(args, &policy_context(&args.selection, milliseconds()?)?)
}

async fn execute(args: &Options, socket: &Path) -> Result<Value> {
    let required = preflight_authorities(args)?;
    status(args, "preparing_request", 0)?;
    propose_value(&Propose {
        selection: selection(args),
        output: args.directory.join("proposal"),
        decision_revision: args.decision_revision,
        execute: true,
    })?;
    let proposal_path = args.directory.join("proposal/proposal.bin");
    let proposal_bytes = storage::read(&proposal_path, super::MAX_DECISION_BYTES)?;
    let proposal = SignedObjectDecision::decode(&proposal_bytes)?;
    let request = DecisionRequest::new(
        storage::read(
            &args.directory.join("assessment.bundle"),
            MAX_ASSESSMENT_BUNDLE_BYTES as u64,
        )?,
        proposal_bytes,
    )?;
    retain(&args.directory.join("request.bin"), &request.encode()?)?;
    let remaining = proposal
        .body()
        .expires_at_ms
        .checked_sub(milliseconds()?)
        .filter(|remaining| *remaining > 0)
        .context("policy_round_original_proposal_expired")?;
    tokio::time::timeout(
        Duration::from_millis(remaining),
        complete_round(args, socket, &proposal, required),
    )
    .await
    .context("policy_round_original_proposal_expired")?
}

async fn complete_round(
    args: &Options,
    socket: &Path,
    proposal: &SignedObjectDecision,
    required: usize,
) -> Result<Value> {
    let request_manifest = policy_exchange::publish(
        request_publication(args, proposal)?,
        &args.publication_key,
        policy_exchange::Kind::Request,
        socket,
    )
    .await?;
    deliver(args, proposal, *request_manifest.manifest_id(), socket).await?;
    let cache = args.directory.join("reply-cache");
    let reply_cache = if storage::exists(&cache)? {
        ChunkStore::open(&cache, args.limits.cache_limits()?)?
    } else {
        ChunkStore::create(&cache, args.limits.cache_limits()?)?
    };
    drop(reply_cache);
    let endorsements = quorum(args, proposal, required, socket).await?;
    let verified_count = endorsements.len();
    let combined = combine_value(
        &Combine {
            selection: selection(args),
            proposal: args.directory.join("proposal/proposal.bin"),
            endorsement: endorsements,
            output: args.directory.join("combined"),
            execute: true,
            apply: false,
        },
        socket,
    )
    .await?;
    publish_completed(
        args,
        socket,
        *request_manifest.manifest_id(),
        required,
        verified_count,
        combined,
    )
    .await
}

async fn publish_completed(
    args: &Options,
    socket: &Path,
    request_id: [u8; 32],
    required: usize,
    verified_count: usize,
    combined: Value,
) -> Result<Value> {
    let decision_path = args.directory.join("combined/decision.bin");
    let decision = storage::read(&decision_path, super::MAX_DECISION_BYTES)?;
    let context = policy_context(&args.selection, milliseconds()?)?;
    let verified = verify_object_decision(
        &decision,
        milliseconds()?,
        &context.trust,
        context.verification,
        &context.manifest,
    )?;
    let publication = distribution::publish_value(
        &distribution::Publish {
            selection: distribution::Selection {
                decision: decision_path,
                policy_config: args.selection.policy_config.clone(),
                subject_publisher_key: args.selection.source_publisher_key,
                subject_manifest_id: args.selection.source_manifest_id,
                subject_sha256: verified.body().subject.object_sha256,
                decision_hash: *verified.decision_hash(),
                evidence_sha256: verified.body().evidence_sha256,
            },
            publication_key: args.publication_key,
            name: args.publish_name.clone(),
            revision: args.decision_revision,
            identity: args.identity.clone(),
            passphrase_file: args.passphrase_file.clone(),
            output: args.directory.join("publication"),
            execute: true,
            limits: args.limits.clone(),
        },
        socket,
    )
    .await?;
    let manifest = SignedManifest::decode(&storage::read(
        &args.directory.join("publication/publication.manifest"),
        64 * 1024,
    )?)?
    .verify(&args.publication_key, milliseconds()? / 1000)?;
    let (contribution, custody) = deliver_completed(
        args,
        socket,
        &manifest,
        verified.body().expires_at_ms / 1000,
    )
    .await?;
    Ok(json!({"operation":"compute_policy_round","complete":true,
        "request_manifest_id":hex::encode(request_id),
        "decision_hash":hex::encode(verified.decision_hash()),"decision_revision":args.decision_revision,
        "verified_endorsements":verified_count,"required_endorsements":required,
        "combined":combined,"publication":publication,"contribution":contribution,"custody":custody,
        "network_publication":true,"network_policy_activation":false,"local_object_policy_applied":false,
        "publication_receipts_are_historical":true,"current_availability_proven":false,
        "assessment_started":false,"model_execution":false,"provider_signed_claims_replayed":4,
        "authority_private_keys_loaded":false,"private_keys_transferred":false,
        "semantic_correctness_proven":false,"legal_status":"not_determined"}))
}

async fn deliver_completed(
    args: &Options,
    socket: &Path,
    manifest: &volparossa_content::VerifiedManifest,
    expires: u64,
) -> Result<(Value, Value)> {
    Ok(if args.publication_provider_key.is_empty() {
        (
            contribution(
                args,
                args.directory.join("publication/publication.manifest"),
                args.directory.join("publication/cache"),
                *manifest.manifest_id(),
                "publication-contribution.json",
                socket,
            )
            .await?,
            Value::Null,
        )
    } else {
        let parameters = content::PolicyDecisionPublication {
            input: args.directory.join("publication/decision.bin"),
            cache: args.directory.join("publication/cache"),
            reuse_cache: true,
            manifest: args.directory.join("publication/publication.manifest"),
            name: args.publish_name.clone(),
            revision: args.decision_revision,
            expires_not_after: expires,
            identity: args.identity.clone(),
            passphrase_file: args.passphrase_file.clone(),
            limits: args.limits.clone(),
        };
        let mut delivered = None;
        for attempt in 0..64 {
            let path = args
                .directory
                .join(format!("publication-deposit-{attempt:02}.json"));
            if storage::exists(&path)? {
                let previous: Value = serde_json::from_slice(&storage::read(&path, 1024 * 1024)?)?;
                ensure!(
                    previous["manifest_id"] == hex::encode(manifest.manifest_id()),
                    "policy_round_original_publication_custody_changed"
                );
                if previous["complete"] == true {
                    delivered = Some(previous);
                    break;
                }
                continue;
            }
            let receipt = policy_exchange::deposit(
                &parameters,
                args.publication_provider_key.clone(),
                socket,
            )
            .await?;
            retain(&path, &serde_json::to_vec(&receipt)?)?;
            if receipt["complete"] == true {
                delivered = Some(receipt);
                break;
            }
            tokio::time::sleep(Duration::from_secs(u64::from(args.poll_seconds))).await;
        }
        (
            Value::Null,
            delivered.context("policy_round_publication_custody_retry_bound")?,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn binding(seed: u8, publisher: u8, name: &str) -> String {
        format!(
            "{}:{}:{name}",
            hex::encode(
                SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .as_bytes()
            ),
            hex::encode(
                SigningKey::from_bytes(&[publisher; 32])
                    .verifying_key()
                    .as_bytes()
            )
        )
    }

    #[test]
    fn authority_parser_keeps_policy_and_transport_separate() {
        let selected = parse_authority(&binding(61, 62, "reply-one")).unwrap();
        assert_ne!(selected.key, selected.publisher);
        assert_eq!(selected.reply_name, "reply-one");
        assert!(parse_authority(&binding(61, 61, "reply-one")).is_err());
        assert!(parse_authority(&(binding(61, 62, "reply-one") + ":extra")).is_err());
        assert!(parse_authority(&binding(61, 62, "bad\nreply")).is_err());
    }

    #[test]
    fn duplicate_authorities_or_reply_channels_cannot_supply_a_quorum() {
        let first = parse_authority(&binding(61, 62, "reply-one")).unwrap();
        assert!(
            bindings(&[
                first.clone(),
                parse_authority(&binding(63, 64, "reply-two")).unwrap()
            ])
            .is_ok()
        );
        assert!(
            bindings(&[
                first.clone(),
                parse_authority(&binding(61, 64, "reply-two")).unwrap()
            ])
            .is_err()
        );
        assert!(
            bindings(&[
                first,
                parse_authority(&binding(63, 62, "reply-one")).unwrap()
            ])
            .is_err()
        );
        assert!(bindings(&[]).is_err());
    }
}
