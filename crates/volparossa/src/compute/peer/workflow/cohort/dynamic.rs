//! One locked frontend-selected package enrolled into an external shared slot owner.

#[allow(
    clippy::wildcard_imports,
    reason = "Private incremental workflow adapter reuses the parent's admission checks"
)]
use super::*;
use anyhow::Context as _;
use tokio::sync::watch;

pub(crate) struct ReadyWork {
    args: Options,
    enrollment: Enrollment,
    state: PackageState,
    _lock: nix::fcntl::Flock<std::fs::File>,
    rounds: u16,
}

impl ReadyWork {
    /// Only graph/frontend-selected single-package workflows use this incremental API.
    /// The original source, task, model and provider checks still precede dispatch.
    pub(crate) fn open(mut args: Options, window_budget: u16) -> Result<Self> {
        ensure!(
            (1..=32).contains(&window_budget),
            "compute_graph_invocation_budget"
        );
        args.max_batches = window_budget;
        ensure!(
            args.execute && args.expected_task.is_some() && !args.discovery.discover_peers,
            "compute_cohort_frontend_selection_required"
        );
        let (enrollment, lock) = if args.directory.try_exists()? {
            super::super::super::super::private_directory(&args.directory)?;
            let lock = lock_directory(&args.directory)?;
            let enrollment = serde_json::from_slice(&read_file(
                &args.directory.join("workflow.json"),
                MAX_PLAN_BYTES,
            )?)?;
            (enrollment, lock)
        } else {
            let (enrollment, sources) = prepare(&args)?;
            validate_expected_task(
                &enrollment,
                args.expected_task.as_ref().expect("checked task"),
            )?;
            persist_enrollment(&args.directory, &enrollment, &sources)?;
            let lock = lock_directory(&args.directory)?;
            (enrollment, lock)
        };
        validate_enrollment(&enrollment)?;
        validate_expected_task(
            &enrollment,
            args.expected_task.as_ref().expect("checked task"),
        )?;
        ensure!(
            enrollment.scheduling == Scheduling::ReadyRowsV1 && enrollment.packages.len() == 1,
            "compute_graph_single_ready_package_required"
        );
        let state = load(&[(&args, &enrollment)])?
            .pop()
            .context("compute_graph_package_missing")?;
        Ok(Self {
            args,
            enrollment,
            state,
            _lock: lock,
            rounds: 0,
        })
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.args.directory
    }

    pub(crate) fn verify_selection(&self, args: &Options) -> Result<()> {
        ensure!(
            self.args.directory == args.directory,
            "compute_graph_workflow_changed"
        );
        validate_expected_task(
            &self.enrollment,
            args.expected_task
                .as_ref()
                .context("compute_graph_task_missing")?,
        )
    }

    pub(crate) fn reservations(&self) -> Vec<batch::ReadyPending> {
        // Include terminal observations too: they release an earlier external lease
        // only after its corresponding receipt has been validated and made durable.
        self.state
            .progress
            .parts
            .values()
            .map(|part| batch::ReadyPending {
                handle: part.handle.clone(),
                verified_status: part.status.clone(),
            })
            .collect()
    }

    /// The same checked snapshot as `task_snapshot_detailed`, under this owner's lock.
    pub(crate) fn snapshot(
        &self,
        expected: &super::super::ExpectedTask,
    ) -> Result<serde_json::Value> {
        validate_expected_task(&self.enrollment, expected)?;
        let state = &self.state;
        let progress = load_progress(
            &state.directory,
            &state.source,
            &state.verified,
            &self.enrollment,
        )?;
        let package = &self.enrollment.packages[0];
        Ok(
            serde_json::json!({"dataset_manifest_id":package.manifest_id,"task":package.task,
            "complete":progress.complete(),"outputs":progress.output_rows(true)?}),
        )
    }

    pub(crate) fn rounds(&self) -> u16 {
        self.rounds
    }

    /// At most one attempt per owner window, just like the existing cohort path.
    pub(crate) async fn ready(
        &mut self,
        socket: &Path,
        cancelled: &watch::Receiver<bool>,
    ) -> Result<Option<batch::ReadyOptions>> {
        if self.state.attempted
            || !executable(&self.state, now()?)
            || self.state.progress.ready_rows()?.is_empty()
            || *cancelled.borrow()
        {
            return Ok(None);
        }
        let options = ready_options(
            &self.state,
            &[(&self.args, &self.enrollment)],
            socket,
            cancelled,
        )
        .await?;
        self.state.attempted = true;
        self.rounds += 1;
        Ok(Some(options))
    }

    pub(crate) fn completed(
        &mut self,
        result: Result<serde_json::Value>,
        cancelled: bool,
    ) -> Result<()> {
        reconcile(&mut self.state, &self.enrollment, &result)?;
        if let Err(error) = result {
            if !follow::transient_preflight(&error)
                && !cancelled
                && self.state.verified.expires() > now()?
            {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Called only after the shared driver has no active futures. Reuse the existing
    /// stopped/expired retry admission, excluding every other workflow's held lease.
    pub(crate) async fn recover(
        &mut self,
        external: &[batch::ReadyPending],
        socket: &Path,
        cancelled: &watch::Receiver<bool>,
    ) -> Result<bool> {
        if self.state.attempted
            || !executable(&self.state, now()?)
            || !self.state.progress.ready_rows()?.is_empty()
            || *cancelled.borrow()
        {
            return Ok(false);
        }
        let result = advance_reserved(
            &[(&self.args, &self.enrollment)],
            1,
            external,
            socket,
            cancelled,
        )
        .await;
        self.state.attempted = true;
        self.rounds += 1;
        self.state.progress = load_progress(
            &self.state.directory,
            &self.state.source,
            &self.state.verified,
            &self.enrollment,
        )?;
        result?;
        Ok(true)
    }

    pub(crate) fn report(&self, cancelled: bool) -> Result<serde_json::Value> {
        report(
            &self.args,
            &self.enrollment,
            std::iter::once(&self.state),
            self.rounds,
            cancelled,
        )
    }
}
