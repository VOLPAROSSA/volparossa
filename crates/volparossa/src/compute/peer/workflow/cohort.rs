//! One owner window shares executor capacity across independently authenticated packages.
//! Per-package storage and the stopped/expired retry authority remain unchanged.

use super::{
    BTreeSet, Enrollment, MAX_ATTEMPTS, MAX_PACKAGES, MAX_PLAN_BYTES, Options, Path, PathBuf,
    Progress, Result, Scheduling, Source, VerifiedPublicDataset, batch, discovery, ensure,
    executors, follow, load_progress, lock_directory, now, parse_key, persist_enrollment, prepare,
    read_file, replacement_authorization, resume, round_failure, rpc, stored_source,
    validate_enrollment, validate_expected_task,
};

struct PackageState {
    owner: usize,
    index: usize,
    directory: PathBuf,
    source: Source,
    verified: VerifiedPublicDataset,
    progress: Progress,
    authorization: Option<executors::Authorization>,
    failure: Option<&'static str>,
    attempted: bool,
}

fn held(pending: &batch::ReadyPending, at: u64) -> bool {
    pending.handle.binding.expires_unix_seconds > at
        && pending
            .verified_status
            .as_ref()
            .is_none_or(|status| status.state == rpc::JobState::Running)
}

fn reservations(
    states: &[PackageState],
    excluded: &BTreeSet<usize>,
    at: u64,
) -> Vec<batch::ReadyPending> {
    states
        .iter()
        .enumerate()
        .filter(|(index, _)| !excluded.contains(index))
        .flat_map(|(_, state)| state.progress.ready_pending())
        .filter(|pending| held(pending, at))
        .collect()
}

fn load(owners: &[(&Options, &Enrollment)]) -> Result<Vec<PackageState>> {
    let mut states = Vec::new();
    for (owner, (args, enrollment)) in owners.iter().enumerate() {
        ensure!(
            args.execute && enrollment.scheduling == Scheduling::ReadyRowsV1,
            "compute_cohort_ready_execution_required"
        );
        for (index, package) in enrollment.packages.iter().enumerate() {
            let directory = args.directory.join(format!("package-{index:04}"));
            let (source, verified) =
                stored_source(&directory, package, enrollment.verified_at_unix_seconds)?;
            let progress = load_progress(&directory, &source, &verified, enrollment)?;
            let authorization = replacement_authorization(enrollment, package, &verified)?;
            states.push(PackageState {
                owner,
                index,
                directory,
                source,
                verified,
                progress,
                authorization,
                failure: None,
                attempted: false,
            });
        }
    }
    Ok(states)
}

fn executable(state: &PackageState, at: u64) -> bool {
    !state.progress.complete()
        && state.verified.expires() > at
        && state.progress.attempts < MAX_ATTEMPTS
}

fn ready_model_fingerprint(
    pinned: Option<&String>,
    selected: Option<&discovery::Selected>,
) -> Option<String> {
    pinned
        .or_else(|| selected.map(|selected| &selected.model_fingerprint))
        .cloned()
}

async fn ready_options(
    state: &PackageState,
    owners: &[(&Options, &Enrollment)],
    socket: &Path,
    cancelled: &tokio::sync::watch::Receiver<bool>,
) -> Result<batch::ReadyOptions> {
    let (args, enrollment) = owners[state.owner];
    let mut providers = enrollment
        .provider_keys
        .iter()
        .map(|key| parse_key(key).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    // Discovery remains read-only and source-authorized. Its result is recorded in the
    // attempt before any handle; already leased rows are never retargeted here.
    let admission = if let Some(authorization) = &state.authorization {
        match executors::discover(authorization, socket, cancelled).await {
            Ok(selected) => {
                providers.clone_from(&selected.providers);
                Some((authorization.clone(), selected))
            }
            Err(_) => None,
        }
    } else {
        None
    };
    Ok(batch::ReadyOptions {
        source: state.source.clone(),
        providers,
        output: state
            .directory
            .join(format!("attempt-{:04}", state.progress.attempts)),
        max_seconds: args.max_seconds,
        task: enrollment.packages[state.index].task.clone(),
        model_fingerprint: ready_model_fingerprint(
            state.progress.model_fingerprint.as_ref(),
            admission.as_ref().map(|(_, selected)| selected),
        ),
        ready_rows: state.progress.ready_rows()?,
        pending: state.progress.ready_pending(),
        executor_admission: admission,
    })
}

fn reconcile(
    state: &mut PackageState,
    enrollment: &Enrollment,
    result: &Result<serde_json::Value>,
) -> Result<()> {
    state.progress = load_progress(&state.directory, &state.source, &state.verified, enrollment)?;
    state.failure = round_failure(result);
    Ok(())
}

/// Each admitted package attempt consumes one round; work from other packages is
/// never permission to grow the explicit window. Their retained live leases still reserve slots.
#[allow(
    clippy::too_many_lines,
    reason = "One owner window retains exact package attempts and reconciles their shared lease boundary before retry"
)]
pub(super) async fn advance(
    owners: &[(&Options, &Enrollment)],
    max_batches: u16,
    socket: &Path,
    cancelled: &tokio::sync::watch::Receiver<bool>,
) -> Result<Vec<serde_json::Value>> {
    ensure!(
        !owners.is_empty() && owners.len() <= MAX_PACKAGES && (1..=32).contains(&max_batches),
        "compute_cohort_bound"
    );
    let mut states = load(owners)?;
    let mut rounds = vec![0_u16; owners.len()];
    let at = now()?;
    let selected = if *cancelled.borrow() {
        Vec::new()
    } else {
        states
            .iter()
            .enumerate()
            .filter(|(_, state)| executable(state, at))
            .filter_map(|(index, state)| match state.progress.ready_rows() {
                Ok(rows) if rows.is_empty() => None,
                rows => Some(rows.map(|_| index)),
            })
            .take(usize::from(max_batches))
            .collect::<Result<Vec<_>>>()?
    };
    let mut options = Vec::new();
    for index in &selected {
        options.push(ready_options(&states[*index], owners, socket, cancelled).await?);
        states[*index].attempted = true;
        rounds[states[*index].owner] += 1;
    }
    let mut failure = None;
    if !options.is_empty() {
        let excluded = selected.iter().copied().collect();
        let reservations = reservations(&states, &excluded, now()?);
        let results =
            batch::report_ready_many_with_activity(&options, &reservations, socket, cancelled)
                .await?;
        ensure!(
            results.len() == selected.len(),
            "compute_cohort_result_count"
        );
        for (index, result) in selected.into_iter().zip(results) {
            let state = &mut states[index];
            reconcile(state, owners[state.owner].1, &result)?;
            if let Err(error) = result {
                if !follow::transient_preflight(&error)
                    && !*cancelled.borrow()
                    && state.verified.expires() > now()?
                {
                    failure.get_or_insert(error);
                }
            }
        }
    }
    // Existing retry admission already proves stopped/expired authority. Run it only
    // after the shared first-submission loop drains, and exclude every other still-held
    // provider, including peers discovered by another package in earlier windows.
    for index in 0..states.len() {
        if failure.is_some() || *cancelled.borrow() || rounds.iter().sum::<u16>() >= max_batches {
            break;
        }
        let state = &states[index];
        if state.attempted || !executable(state, now()?) || !state.progress.ready_rows()?.is_empty()
        {
            continue;
        }
        let held = reservations(&states, &BTreeSet::from([index]), now()?)
            .into_iter()
            .map(|pending| pending.handle.provider_key)
            .collect();
        let (args, enrollment) = owners[state.owner];
        let providers = enrollment
            .provider_keys
            .iter()
            .map(|key| parse_key(key).map_err(anyhow::Error::msg))
            .collect::<Result<_>>()?;
        let mut retry = resume::Options::workflow(
            state.source.clone(),
            state.progress.pending(),
            providers,
            state
                .directory
                .join(format!("attempt-{:04}", state.progress.attempts)),
            args.max_seconds,
        )
        .prefer_other_provider(args.follow.follow)
        .with_verified_stopped_receipts(state.progress.stopped_receipts())
        .exclude_held_providers(held);
        if let Some(authorization) = &state.authorization {
            retry = retry.discover_replacements(authorization.clone());
        }
        rounds[state.owner] += 1;
        let result = resume::report_with_activity(&retry, socket, cancelled).await;
        let state = &mut states[index];
        state.attempted = true;
        reconcile(state, enrollment, &result)?;
        if let Err(error) = result {
            if !follow::transient_preflight(&error)
                && !*cancelled.borrow()
                && state.verified.expires() > now()?
            {
                failure.get_or_insert(error);
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    owners
        .iter()
        .enumerate()
        .map(|(owner, (args, enrollment))| {
            report(
                args,
                enrollment,
                states.iter().filter(|state| state.owner == owner),
                rounds[owner],
                *cancelled.borrow(),
            )
        })
        .collect()
}

fn report<'a>(
    args: &Options,
    enrollment: &Enrollment,
    states: impl Iterator<Item = &'a PackageState>,
    rounds: u16,
    cancelled: bool,
) -> Result<serde_json::Value> {
    let mut packages = Vec::new();
    let mut completed = 0;
    let mut expiry = None;
    let mut pending_failure = false;
    let mut stopped = "invocation_budget";
    for state in states {
        let complete = state.progress.complete();
        completed += usize::from(complete);
        if !complete {
            expiry = Some(expiry.map_or(state.verified.expires(), |previous: u64| {
                previous.min(state.verified.expires())
            }));
            if state.verified.expires() <= now()? {
                stopped = "source_expired_new_signed_package_required";
                pending_failure = true;
            } else if state.progress.attempts >= MAX_ATTEMPTS {
                stopped = "attempt_storage_bound";
                pending_failure = true;
            } else if state.attempted {
                pending_failure = true;
                if stopped == "invocation_budget" {
                    stopped = "pending_handles_retained_no_busy_retry_loop";
                }
            }
        }
        let package = &enrollment.packages[state.index];
        let mut value = serde_json::json!({"package_index":state.index,"dataset_manifest_id":package.manifest_id,
            "complete":complete,"attempts":state.progress.attempts,"outputs":state.progress.outputs()?,
            "pending_handles":state.progress.pending(),"task":package.task,"ready_rows":state.progress.ready_rows()?});
        if let Some(failure) = state.failure {
            value["failure_code"] = failure.into();
        }
        packages.push(value);
    }
    let complete = completed == enrollment.packages.len();
    if complete {
        stopped = "complete";
    } else if cancelled {
        stopped = "interrupted_handles_retained";
        pending_failure = true;
    }
    Ok(
        serde_json::json!({"version":1,"operation":"compute_workflow","execute":true,
        "scheduling":enrollment.scheduling,"package_scheduling":"shared_provider_round_robin_v1",
        "complete":complete,"completed_packages":completed,"package_count":enrollment.packages.len(),
        "rounds_this_invocation":rounds,"maximum_seconds_per_worker":args.max_seconds,"maximum_rounds_per_window":args.max_batches,
        "stopped":stopped,"packages":packages,"pending_failure":pending_failure,
        "source_admission_expires_unix_seconds":expiry,"receipt_scope":"locally_retained_authenticated_rpc_status",
        "private_data_supported":false,"automatic_source_discovery":false,"general_task_planning":false,
        "exactly_once_execution_guaranteed":false,"result_truthfulness_guaranteed":false}),
    )
}

/// The document owner already holds its outer directory lock. Keep each admitted
/// workflow's own lock as well; no source, task or selection check is bypassed.
pub(crate) async fn report_group_with_activity(
    args: &[Options],
    max_batches: u16,
    follow: &follow::Options,
    socket: &Path,
    cancelled: &tokio::sync::watch::Receiver<bool>,
) -> Result<serde_json::Value> {
    ensure!(
        !args.is_empty() && args.len() <= MAX_PACKAGES,
        "compute_cohort_bound"
    );
    let mut owners = Vec::new();
    let mut locks = Vec::new();
    for options in args {
        ensure!(
            options.execute && options.expected_task.is_some() && !options.discovery.discover_peers,
            "compute_cohort_frontend_selection_required"
        );
        let exists = options.directory.try_exists()?;
        let enrollment = if exists {
            super::super::super::private_directory(&options.directory)?;
            locks.push(lock_directory(&options.directory)?);
            serde_json::from_slice(&read_file(
                &options.directory.join("workflow.json"),
                MAX_PLAN_BYTES,
            )?)?
        } else {
            let (enrollment, sources) = prepare(options)?;
            validate_expected_task(
                &enrollment,
                options.expected_task.as_ref().expect("checked selection"),
            )?;
            persist_enrollment(&options.directory, &enrollment, &sources)?;
            locks.push(lock_directory(&options.directory)?);
            enrollment
        };
        validate_enrollment(&enrollment)?;
        validate_expected_task(
            &enrollment,
            options.expected_task.as_ref().expect("checked selection"),
        )?;
        ensure!(
            enrollment.scheduling == Scheduling::ReadyRowsV1,
            "compute_cohort_legacy_selection"
        );
        owners.push(enrollment);
    }
    let references: Vec<_> = args.iter().zip(&owners).collect();
    let result = follow::run(follow, cancelled, || async {
        let reports = advance(&references, max_batches, socket, cancelled).await?;
        let complete = reports.iter().all(|value| value["complete"] == true);
        let expiry = reports.iter().filter_map(|value| value["source_admission_expires_unix_seconds"].as_u64()).min();
        let rounds = reports.iter().filter_map(|value| value["rounds_this_invocation"].as_u64()).sum::<u64>();
        let stopped = if complete { "complete" } else if *cancelled.borrow() { "interrupted_handles_retained" }
            else if reports.iter().any(|value| value["stopped"] == "source_expired_new_signed_package_required") { "source_expired_new_signed_package_required" }
            else if reports.iter().any(|value| value["stopped"] == "attempt_storage_bound") { "attempt_storage_bound" }
            else { "pending_handles_retained_no_busy_retry_loop" };
        Ok(serde_json::json!({"operation":"compute_workflow_group","execute":true,"complete":complete,
            "rounds_this_invocation":rounds,"workflows":reports,"source_admission_expires_unix_seconds":expiry,
            "stopped":stopped,"pending_failure":!complete}))
    }).await;
    drop(locks);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_pins_first_model_but_never_overrides_an_existing_model() {
        let selected = discovery::Selected {
            providers: Vec::new(),
            model_fingerprint: "a".repeat(64),
        };
        assert_eq!(
            ready_model_fingerprint(None, Some(&selected)),
            Some(selected.model_fingerprint.clone())
        );
        let original = "b".repeat(64);
        assert_eq!(
            ready_model_fingerprint(Some(&original), Some(&selected)),
            Some(original.clone())
        );
        assert_eq!(
            ready_model_fingerprint(Some(&original), None),
            Some(original)
        );
        assert_eq!(ready_model_fingerprint(None, None), None);
    }
}
