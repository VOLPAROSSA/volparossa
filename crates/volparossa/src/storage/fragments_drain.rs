//! One owner-driven archive drain pass. Existing signed intents own every retry;
//! this controller selects candidates but neither changes redundancy nor grants trust.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Result, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use volparossa_content::private_storage::protocol::{StorageRights, VerifiedStorageGrant};

use super::{
    super::retained::{Charge, HandoffPhase},
    placement,
    retained::LockedFragments,
};

#[derive(Default)]
struct Usage {
    charged: u64,
    allocated: u64,
    leases: u32,
}

fn usage(set: &LockedFragments) -> Result<BTreeMap<[u8; 32], Usage>> {
    let mut result: BTreeMap<_, Usage> = BTreeMap::new();
    for (index, fragment) in set.data.fragments.iter().enumerate() {
        let copies = set.fragment(index)?;
        for copy in &copies.data.copies {
            if copy.charge == Charge::Deleted {
                continue;
            }
            let entry = result.entry(copy.provider_key).or_default();
            // Include unattempted original allocations for candidate quota admission;
            // only actually attempted copies contribute to the placement score.
            entry.allocated += fragment.length;
            entry.leases += 1;
            if copy.charge != Charge::Unattempted {
                entry.charged += fragment.length;
            }
        }
    }
    Ok(result)
}

fn required_rights(grant: &VerifiedStorageGrant) -> bool {
    let rights = StorageRights::RESERVE
        .union(StorageRights::APPEND)
        .union(StorageRights::PROGRESS)
        .union(StorageRights::FINALIZE)
        .union(StorageRights::READ_RANGE);
    grant.limits().rights.bits() & rights.bits() == rights.bits()
}

pub(super) fn select<'a>(
    set: &LockedFragments,
    index: usize,
    from: &VerifyingKey,
    grants: &'a [VerifiedStorageGrant],
    lifetime: u64,
) -> Result<Option<&'a VerifiedStorageGrant>> {
    let charged = usage(set)?;
    let copies = set.fragment(index)?;
    let mut candidates = Vec::new();
    for grant in grants {
        let key = grant.provider_key().to_bytes();
        let empty = Usage::default();
        let current = charged.get(&key).unwrap_or(&empty);
        if key == from.to_bytes()
            || !required_rights(grant)
            || current.allocated + copies.data.ciphertext_bytes > grant.limits().max_payload_bytes
            || current.leases >= grant.limits().max_leases
            || copies.plan_handoff(from, grant, lifetime).is_err()
        {
            continue;
        }
        candidates.push((current.charged, key, grant));
    }
    candidates.sort_by_key(|(bytes, key, _)| (*bytes, *key));
    Ok(candidates.first().map(|(_, _, grant)| *grant))
}

fn report(
    set: &LockedFragments,
    from: &VerifyingKey,
    stage: &str,
    outcomes: Vec<serde_json::Value>,
) -> Result<serde_json::Value> {
    let mut remaining = 0;
    let mut pending = 0;
    for index in 0..set.data.fragments.len() {
        let copies = set.fragment(index)?;
        remaining +=
            usize::from(copies.data.copies.iter().any(|copy| {
                copy.provider_key == from.to_bytes() && copy.charge != Charge::Deleted
            }));
        pending += usize::from(
            copies
                .data
                .handoff
                .as_ref()
                .is_some_and(|intent| intent.phase != HandoffPhase::Complete),
        );
    }
    let mut result = set.report("drain")?;
    result["operation_complete"] = (remaining == 0 && pending == 0).into();
    result["drain_stage"] = stage.into();
    result["draining_provider_key"] = hex::encode(from.as_bytes()).into();
    result["remaining_provider_fragments"] = remaining.into();
    result["pending_retirements"] = pending.into();
    result["attempted_handoffs"] = outcomes.len().into();
    result["fragment_outcomes"] = outcomes.into();
    result["owner_driven_bounded_pass"] = true.into();
    result["candidate_scope"] = "explicit_verified_grants".into();
    result["placement_score_scope"] = "this_archive_retained_charges".into();
    result["automatic_contribution_resize"] = false.into();
    result["background_completion"] = false.into();
    result["replacement_readback_required_before_source_delete"] = true.into();
    Ok(result)
}

fn outcome(index: usize, resumed: bool, result: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"index": index, "resumed_signed_intent": resumed,
        "operation_complete": result["operation_complete"], "handoff_stage": result["handoff_stage"]})
}

/// Resume all prior owner-signed handoffs before allocating any new placement. A
/// failed remote step stops this pass; retries keep the original target/expiry/grant.
pub(super) async fn drain(
    set: &mut LockedFragments,
    socket: &Path,
    signer: &SigningKey,
    from: VerifyingKey,
    grants: &[VerifiedStorageGrant],
    lifetime: u64,
    maximum: usize,
) -> Result<serde_json::Value> {
    set.check_owner(signer)?;
    ensure!(
        (1..=256).contains(&maximum),
        "drain pass must attempt 1..256 handoffs"
    );
    ensure!(
        (1..=8).contains(&grants.len()),
        "drain needs 1..8 explicit candidate grants"
    );
    ensure!(
        placement::providers(set).contains(&from.to_bytes()),
        "unknown draining provider"
    );
    let mut keys = BTreeSet::new();
    for grant in grants {
        ensure!(
            grant.owner_key() == &signer.verifying_key()
                && grant.provider_key() != grant.owner_key()
                && grant.provider_key() != &from
                && keys.insert(grant.provider_key().to_bytes()),
            "invalid or duplicate drain candidate authority"
        );
    }
    let mut outcomes = Vec::new();
    // Opening a fragment first authenticates and recovers its child from the exact
    // durable signed parent intent. Candidate ordering cannot redirect a pending copy.
    for index in 0..set.data.fragments.len() {
        let copies = set.fragment(index)?;
        let Some(intent) = copies
            .data
            .handoff
            .as_ref()
            .filter(|intent| intent.phase != HandoffPhase::Complete)
        else {
            continue;
        };
        if outcomes.len() == maximum {
            drop(copies);
            return report(set, &from, "pass_limit", outcomes);
        }
        let original = VerifyingKey::from_bytes(&copies.data.copies[intent.from].provider_key)?;
        let provider = VerifyingKey::from_bytes(&intent.initial_journal.provider_key)?;
        let grant = intent
            .initial_journal
            .grant(&provider, &signer.verifying_key());
        drop(copies);
        let Ok(grant) = grant else {
            return report(set, &from, "pending_grant_unavailable", outcomes);
        };
        let result =
            placement::replace(set, socket, signer, index, original, &grant, lifetime).await?;
        outcomes.push(outcome(index, true, &result));
        if result["operation_complete"] != true {
            return report(set, &from, "pending_handoff", outcomes);
        }
    }
    for index in 0..set.data.fragments.len() {
        let copies = set.fragment(index)?;
        let remains = copies
            .data
            .copies
            .iter()
            .any(|copy| copy.provider_key == from.to_bytes() && copy.charge != Charge::Deleted);
        drop(copies);
        if !remains {
            continue;
        }
        if outcomes.len() == maximum {
            return report(set, &from, "pass_limit", outcomes);
        }
        let Some(grant) = select(set, index, &from, grants, lifetime)? else {
            return report(set, &from, "no_eligible_candidate", outcomes);
        };
        let result = placement::replace(set, socket, signer, index, from, grant, lifetime).await?;
        outcomes.push(outcome(index, false, &result));
        if result["operation_complete"] != true {
            return report(set, &from, "pending_handoff", outcomes);
        }
    }
    report(set, &from, "complete", outcomes)
}

#[cfg(test)]
#[path = "fragments_drain_tests.rs"]
mod tests;
