//! One source acquisition and one signed authority shared by all initial questions.

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::VerifyingKey;
use tokio::sync::watch;
use volparossa_content::SignedManifest;

use super::super::{
    MAX_SAVED_BYTES, collection, discovery, now, read_file, retain_selected_sources,
    selected_input, source_lifetime, task, tokenize, workflow,
};
use super::{
    DocumentPlan, Enrollment, Input, Leaf, Options, Path, digest, node_root, plan, save, storage,
};

async fn providers(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
) -> Result<Option<discovery::Selected>> {
    if !args.discovery.discover_peers {
        return Ok(None);
    }
    ensure!(
        args.provider_key.is_empty(),
        "compute_discovery_conflicting_providers"
    );
    let publisher = args.publisher_key.context("compute_document_publisher")?;
    let query = args
        .discovery
        .query([hex::encode(publisher.as_bytes())], true, true, true)?;
    Ok(Some(args.discovery.select(socket, query, cancelled).await?))
}

struct Prepared {
    index: usize,
    input: Input,
    plan: DocumentPlan,
}

#[allow(
    clippy::too_many_lines,
    reason = "One graph enrollment separates all tokenizer awaits from the single synchronous shared-source signing boundary"
)]
pub(super) async fn prepare(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    plan: &plan::Plan,
) -> Result<()> {
    ensure!(
        args.public_content && !args.batch_barrier && !args.synthesize,
        "compute_graph_explicit_public_plan_required"
    );
    plan.validate()?;
    let selected = providers(args, socket, cancelled).await?;
    let provider_keys = selected
        .as_ref()
        .map_or(&args.provider_key, |selected| &selected.providers);
    ensure!(
        (2..=4).contains(&provider_keys.len())
            && provider_keys
                .iter()
                .map(VerifyingKey::to_bytes)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == provider_keys.len(),
        "compute_document_independent_peers"
    );
    let (document, collection, network) = selected_input(args, socket, cancelled).await?;
    save(&args.directory, "graph-plan.json", plan, false)?;
    let mut prepared = Vec::new();
    // Finish the real tokenization first. No unlocked publication key crosses an await.
    for (index, node) in plan
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.depends_on.is_empty())
    {
        let root = node_root(&args.directory, index);
        let _lock = task::open_directory(&root, false)?;
        let input = Input {
            version: 1,
            synthesis: false,
            visibility: "public".into(),
            license: args.license.clone().context("compute_document_license")?,
            document: document.clone(),
            question: node.question.clone(),
        };
        input.validate()?;
        retain_selected_sources(&root, &input, collection.as_ref(), network.as_ref())?;
        let tokenized = tokenize(args, &root, &input, cancelled).await?;
        prepared.push(Prepared {
            index,
            input,
            plan: tokenized,
        });
    }
    let signer =
        crate::content::unlock_signer(args.identity.as_deref(), args.passphrase_file.as_deref())?;
    ensure!(
        Some(signer.verifying_key()) == args.publisher_key,
        "compute_document_publisher_identity"
    );
    let at = now()?;
    let lifetime = source_lifetime(args.lifetime_seconds, at, network.as_ref())?;
    if let Some(proofs) = &network {
        proofs.validate(
            collection
                .as_ref()
                .context("compute_collection_missing_ledger")?,
            &document,
            at,
            at + lifetime,
        )?;
    }
    let mut source = None::<SignedManifest>;
    let mut leaves = Vec::new();
    for prepared in prepared {
        let root = node_root(&args.directory, prepared.index);
        let mut enrollment = if let Some(source) = &source {
            storage::publish_with_source(
                &root,
                &prepared.input,
                &prepared.plan,
                &signer,
                provider_keys,
                at,
                lifetime,
                cancelled,
                true,
                source,
            )?
        } else {
            storage::publish(
                &root,
                &prepared.input,
                &prepared.plan,
                &signer,
                provider_keys,
                at,
                lifetime,
                cancelled,
                true,
            )?
        };
        if source.is_none() {
            source = Some(SignedManifest::decode(&read_file(
                &root.join("source.manifest"),
                volparossa_content::MAX_MANIFEST_BYTES,
            )?)?);
        }
        enrollment.model_fingerprint = selected
            .as_ref()
            .map(|selected| selected.model_fingerprint.clone());
        enrollment.replace_peers = args.discovery.replace_peers;
        enrollment.scheduling = workflow::Scheduling::ReadyRowsV1;
        enrollment.collection_sha256 = collection
            .as_ref()
            .map(collection::Ledger::sha256)
            .transpose()?;
        enrollment.native_source_proofs_sha256 = network
            .as_ref()
            .map(collection::network::Proofs::sha256)
            .transpose()?;
        save(&root, "document.json", &enrollment, false)?;
        leaves.push(Leaf {
            node: prepared.index,
            enrollment_sha256: digest(&read_file(&root.join("document.json"), MAX_SAVED_BYTES)?),
        });
    }
    drop(signer);
    save(
        &args.directory,
        "graph.json",
        &Enrollment {
            version: 1,
            plan_sha256: plan.fingerprint()?,
            leaves,
        },
        false,
    )
}
