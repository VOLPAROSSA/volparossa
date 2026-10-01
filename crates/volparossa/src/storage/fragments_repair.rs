//! Bounded owner repair, with independently retained retirement obligations.
//! Reuse real handoff transfers; never infer lost custody from provider silence.

use std::{collections::BTreeSet, path::Path};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use volparossa_content::private_storage::protocol::VerifiedStorageGrant;

use super::{
    super::retained::{Charge, HandoffPhase},
    drain, placement,
    retained::LockedFragments,
};

#[derive(Clone, Copy)]
enum Work {
    Resume(usize),
    New(usize),
}

/// Conservative additional payload for the first actual attempt, not another charge ledger.
pub(super) fn next_additional_charge(set: &LockedFragments, from: &VerifyingKey) -> Result<u64> {
    additional_charge(set, work(set, from)?.first())
}

fn additional_charge(set: &LockedFragments, work: Option<&Work>) -> Result<u64> {
    Ok(match work {
        Some(Work::New(index)) => set.data.fragments[*index].length,
        Some(Work::Resume(index)) => {
            let copies = set.fragment(*index)?;
            let intent = copies
                .data
                .handoff
                .as_ref()
                .context("pending handoff missing")?;
            if copies.data.copies[intent.to].charge == Charge::Unattempted {
                set.data.fragments[*index].length
            } else {
                0
            }
        }
        None => 0,
    })
}

/// Maintenance's adaptive mode may repair only the exact observed failed copy,
/// not every healthy copy belonging to the same provider earlier in the archive.
fn selected_work(set: &LockedFragments, index: usize, from: &VerifyingKey) -> Result<Work> {
    let copies = set.fragment(index)?;
    if let Some(intent) = &copies.data.handoff {
        if intent.phase != HandoffPhase::Complete {
            ensure!(
                copies.data.copies[intent.from].provider_key == from.to_bytes(),
                "selected pending source changed"
            );
            return Ok(Work::Resume(index));
        }
    }
    let retired = placement::retired(set, index);
    ensure!(
        copies
            .data
            .copies
            .iter()
            .enumerate()
            .any(|(copy_index, copy)| !retired.contains(&copy_index)
                && copy.provider_key == from.to_bytes()
                && copy.charge == Charge::Uncertain),
        "selected effective copy is not uncertain"
    );
    Ok(Work::New(index))
}

pub(super) fn selected_additional_charge(
    set: &LockedFragments,
    index: usize,
    from: &VerifyingKey,
) -> Result<u64> {
    additional_charge(set, Some(&selected_work(set, index, from)?))
}

struct Plan {
    tasks: Vec<Work>,
    maximum: usize,
}

pub(super) async fn repair_selected(
    set: &mut LockedFragments,
    socket: &Path,
    signer: &SigningKey,
    target: (usize, VerifyingKey),
    grants: &[VerifiedStorageGrant],
    lifetime: u64,
) -> Result<serde_json::Value> {
    let (index, from) = target;
    let plan = Plan {
        tasks: vec![selected_work(set, index, &from)?],
        maximum: 1,
    };
    execute(set, socket, signer, from, grants, lifetime, plan).await
}

/// Copying intents retain priority. Already verified retirements stay charged,
/// but do not repeatedly consume the entire repair budget ahead of new copies.
fn work(set: &LockedFragments, from: &VerifyingKey) -> Result<Vec<Work>> {
    let mut copying = Vec::new();
    let mut missing = Vec::new();
    let mut retiring = Vec::new();
    for index in 0..set.data.fragments.len() {
        let copies = set.fragment(index)?;
        match copies.data.handoff.as_ref().map(|intent| intent.phase) {
            Some(HandoffPhase::Copying) => copying.push(Work::Resume(index)),
            Some(HandoffPhase::DeletePending) => retiring.push(Work::Resume(index)),
            _ => {
                if copies.data.copies.iter().any(|copy| {
                    copy.provider_key == from.to_bytes() && copy.charge != Charge::Deleted
                }) {
                    missing.push(Work::New(index));
                }
            }
        }
    }
    copying.extend(missing);
    copying.extend(retiring);
    Ok(copying)
}

fn report(
    set: &LockedFragments,
    from: &VerifyingKey,
    stage: &str,
    outcomes: Vec<serde_json::Value>,
) -> Result<serde_json::Value> {
    let mut remaining = 0;
    let mut unrepaired = 0;
    let mut pending = 0;
    for index in 0..set.data.fragments.len() {
        let copies = set.fragment(index)?;
        let source_remains = copies
            .data
            .copies
            .iter()
            .any(|copy| copy.provider_key == from.to_bytes() && copy.charge != Charge::Deleted);
        remaining += usize::from(source_remains);
        unrepaired += usize::from(
            source_remains
                && !copies.data.handoff.as_ref().is_some_and(|intent| {
                    intent.phase == HandoffPhase::DeletePending
                        && copies.data.copies[intent.from].provider_key == from.to_bytes()
                }),
        );
        pending += usize::from(
            copies
                .data
                .handoff
                .as_ref()
                .is_some_and(|intent| intent.phase != HandoffPhase::Complete),
        );
    }
    let complete = remaining == 0 && pending == 0;
    let freshly_verified = outcomes
        .iter()
        .filter(|outcome| outcome["replacement_verified_this_pass"] == true)
        .count();
    let mut result = set.report("repair")?;
    result["operation_complete"] = complete.into();
    result["repair_stage"] = if complete {
        "complete"
    } else if stage == "retirement_pending" && unrepaired != 0 {
        "repair_pending"
    } else {
        stage
    }
    .into();
    result["repairing_provider_key"] = hex::encode(from.as_bytes()).into();
    result["remaining_provider_fragments"] = remaining.into();
    result["remaining_provider_fragments_without_retained_replacement"] = unrepaired.into();
    result["pending_retirements"] = pending.into();
    result["attempted_handoffs"] = outcomes.len().into();
    result["freshly_verified_replacements"] = freshly_verified.into();
    result["fragment_outcomes"] = outcomes.into();
    result["owner_driven_bounded_pass"] = true.into();
    result["candidate_scope"] = "explicit_verified_grants".into();
    result["placement_score_scope"] = "this_archive_retained_charges".into();
    result["automatic_contribution_resize"] = false.into();
    result["background_completion"] = false.into();
    result["replacement_readback_required_before_source_delete"] = true.into();
    result["unconfirmed_retirements_block_other_repairs"] = false.into();
    Ok(result)
}

/// An existing phase alone is not a new readback proof: only this invocation's
/// actual handoff result can permit continuation after an incomplete operation.
fn verified_retirement(
    set: &LockedFragments,
    index: usize,
    result: &serde_json::Value,
) -> Result<bool> {
    if result["handoff_stage"] != "source_delete_unconfirmed" {
        return Ok(false);
    }
    let copies = set.fragment(index)?;
    ensure!(
        copies.data.handoff.as_ref().is_some_and(|intent| {
            intent.phase == HandoffPhase::DeletePending
                && copies.data.copies[intent.to].charge == Charge::Committed
                && copies.data.copies[intent.from].charge != Charge::Deleted
        }),
        "unconfirmed retirement lacks its verified retained handoff"
    );
    Ok(true)
}

/// Repair only the explicitly selected owner's provider copies. Existing grants,
/// immutable root, signed placement intents and charge journals remain authoritative.
pub(super) async fn repair(
    set: &mut LockedFragments,
    socket: &Path,
    signer: &SigningKey,
    from: VerifyingKey,
    grants: &[VerifiedStorageGrant],
    lifetime: u64,
    maximum: usize,
) -> Result<serde_json::Value> {
    let plan = Plan {
        tasks: work(set, &from)?,
        maximum,
    };
    execute(set, socket, signer, from, grants, lifetime, plan).await
}

async fn execute(
    set: &mut LockedFragments,
    socket: &Path,
    signer: &SigningKey,
    from: VerifyingKey,
    grants: &[VerifiedStorageGrant],
    lifetime: u64,
    plan: Plan,
) -> Result<serde_json::Value> {
    set.check_owner(signer)?;
    ensure!(
        (1..=256).contains(&plan.maximum),
        "repair pass must attempt 1..256 handoffs"
    );
    ensure!(
        (1..=8).contains(&grants.len()),
        "repair needs 1..8 explicit candidate grants"
    );
    ensure!(
        placement::providers(set).contains(&from.to_bytes()),
        "unknown repair source provider"
    );
    let mut keys = BTreeSet::new();
    for grant in grants {
        ensure!(
            grant.owner_key() == &signer.verifying_key()
                && grant.provider_key() != grant.owner_key()
                && grant.provider_key() != &from
                && keys.insert(grant.provider_key().to_bytes()),
            "invalid or duplicate repair candidate authority"
        );
    }
    let mut outcomes = Vec::new();
    for task in plan.tasks {
        if outcomes.len() == plan.maximum {
            return report(set, &from, "pass_limit", outcomes);
        }
        let (index, original, grant, resumed) = match task {
            Work::Resume(index) => {
                let copies = set.fragment(index)?;
                let intent = copies
                    .data
                    .handoff
                    .as_ref()
                    .context("planned pending handoff missing")?;
                let original =
                    VerifyingKey::from_bytes(&copies.data.copies[intent.from].provider_key)?;
                let provider = VerifyingKey::from_bytes(&intent.initial_journal.provider_key)?;
                let retained_grant = intent
                    .initial_journal
                    .grant(&provider, &signer.verifying_key());
                drop(copies);
                let Ok(grant) = retained_grant else {
                    return report(set, &from, "pending_grant_unavailable", outcomes);
                };
                (index, original, grant, true)
            }
            Work::New(index) => {
                let Some(grant) = drain::select(set, index, &from, grants, lifetime)? else {
                    return report(set, &from, "no_eligible_candidate", outcomes);
                };
                (index, from, grant.clone(), false)
            }
        };
        let result =
            placement::replace(set, socket, signer, index, original, &grant, lifetime).await?;
        let complete = result["operation_complete"] == true;
        let verified = verified_retirement(set, index, &result)?;
        outcomes.push(
            serde_json::json!({"index": index, "resumed_signed_intent": resumed,
            "operation_complete": complete, "handoff_stage": result["handoff_stage"],
            "replacement_verified_this_pass": complete || verified}),
        );
        if !complete && !verified {
            return report(set, &from, "pending_handoff", outcomes);
        }
    }
    report(set, &from, "retirement_pending", outcomes)
}

#[cfg(test)]
#[path = "fragments_repair_tests.rs"]
mod tests;
