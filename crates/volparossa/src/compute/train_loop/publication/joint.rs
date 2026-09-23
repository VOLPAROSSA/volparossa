//! Ordered sharing of combined and locally trained updates under one enrollment.

use std::collections::BTreeSet;

use super::{
    Context, Instant, Options, Path, Phase, Result, State, Store, Value, active, deliver, ensure,
    now, prepare, retry_due, watch,
};
use crate::compute::train_loop::{
    aggregate_updates,
    publication_order::{Ledger, Target},
};

#[cfg(test)]
mod tests;

fn retained(state: &State) -> BTreeSet<Target> {
    state
        .cycles
        .iter()
        .map(|cycle| Target::Local(cycle.sequence))
        .chain(
            state
                .aggregate_updates
                .as_ref()
                .into_iter()
                .flat_map(aggregate_updates::retained_sequences)
                .map(Target::Aggregate),
        )
        .collect()
}

pub(in crate::compute::train_loop) fn restore_order(
    args: &Options,
    store: &Store,
    state: &mut State,
    enrollment: &Value,
) -> Result<()> {
    if enrollment.get("aggregate_publication").is_none() {
        ensure!(
            state.publication_order.is_none(),
            "train_publication_order_unrequested"
        );
        return Ok(());
    }
    ensure!(
        args.aggregate_plan.is_some()
            && args.publish_name.is_some()
            && state.aggregate_updates.is_some(),
        "train_publication_order_mode"
    );
    let mut order = if let Some(order) = &state.publication_order {
        order.clone()
    } else {
        ensure!(!args.resume, "train_publication_order_missing");
        Ledger::new(args.first_publication_revision)?
    };
    order.validate(args.first_publication_revision)?;
    order.retain(&retained(state))?;
    state.publication_order = Some(order);
    store.save_state(&serde_json::to_value(&*state)?)
}

fn assign(args: &Options, store: &Store, state: &mut State) -> Result<Vec<(Target, u64)>> {
    let mut order = state
        .publication_order
        .clone()
        .context("train_publication_order_missing")?;
    order.validate(args.first_publication_revision)?;
    order.retain(&retained(state))?;
    // An aggregation precedes the local cycle warm-started from it. Earlier assigned
    // revisions stay ahead; no remote revision is guessed and no pending item is skipped.
    if let Some(registry) = &state.aggregate_updates {
        for sequence in aggregate_updates::publication::pending_sequences(registry) {
            order.allocate(Target::Aggregate(sequence))?;
        }
    }
    for cycle in &state.cycles {
        if cycle.retirement.is_none()
            && matches!(cycle.phase, Phase::Trained | Phase::PublishPending)
        {
            order.allocate(Target::Local(cycle.sequence))?;
        }
    }
    let assigned = order.iter().collect();
    if state.publication_order.as_ref() != Some(&order) {
        // This checkpoint must precede even offline signing into the cache.
        let mut persisted = serde_json::to_value(&*state)?;
        persisted["publication_order"] = serde_json::to_value(&order)?;
        store.save_state(&persisted)?;
        state.publication_order = Some(order);
    }
    Ok(assigned)
}

pub(super) async fn pending(
    args: &Options,
    socket: &Path,
    store: &Store,
    state: &mut State,
    activity: &watch::Receiver<bool>,
    deadline: Option<Instant>,
) -> Result<()> {
    let assigned = assign(args, store, state)?;
    for (target, revision) in assigned {
        if !active(activity) || deadline.is_some_and(|until| Instant::now() >= until) {
            break;
        }
        let terminal = match target {
            Target::Aggregate(sequence) => {
                aggregate_updates::publication::publish(
                    args, socket, store, state, sequence, revision, activity, deadline,
                )
                .await?
            }
            Target::Local(sequence) => {
                local(
                    args, socket, store, state, sequence, revision, activity, deadline,
                )
                .await?
            }
        };
        if !terminal {
            break;
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "Process one durably assigned channel revision under one owner deadline"
)]
async fn local(
    args: &Options,
    socket: &Path,
    store: &Store,
    state: &mut State,
    sequence: u64,
    revision: u64,
    activity: &watch::Receiver<bool>,
    deadline: Option<Instant>,
) -> Result<bool> {
    let index = state
        .cycles
        .iter()
        .position(|cycle| cycle.sequence == sequence)
        .context("train_publication_order_local_missing")?;
    let cycle = &mut state.cycles[index];
    // A retired target keeps its already allocated revision forever until normal
    // bounded pruning. Never hand it off again or recycle that revision.
    if cycle.retirement.is_some() || !matches!(cycle.phase, Phase::Trained | Phase::PublishPending)
    {
        return Ok(true);
    }
    if !retry_due(cycle, store, now()?)? {
        return Ok(false);
    }
    let verified = prepare(
        args,
        socket,
        store,
        cycle,
        args.publish_name
            .as_deref()
            .context("train_loop_publish_name")?,
        Some(revision),
    )
    .await?;
    store.save_state(&serde_json::to_value(&*state)?)?;
    if let Some(verified) = verified {
        deliver(
            args,
            socket,
            store,
            &mut state.cycles[index],
            &verified,
            activity,
            deadline,
        )
        .await?;
        store.save_state(&serde_json::to_value(&*state)?)?;
    }
    Ok(!matches!(
        state.cycles[index].phase,
        Phase::Trained | Phase::PublishPending
    ))
}
