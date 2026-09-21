//! Incremental ownership of one bounded cohort, including leases outside its ready frontier.

use super::*;

type Completion = (usize, Result<serde_json::Value>);

/// Keep this owner and the caller's workflow locks alive until `cancel_and_drain` returns.
/// Dropping is only a conservative interruption fallback: exact handles remain durable,
/// but remote cancellation and receipt collection must normally be explicitly awaited.
#[must_use]
pub(in crate::compute::peer) struct ReadyCohort {
    socket: PathBuf,
    owner: watch::Receiver<bool>,
    leases: Leases,
    packages: Vec<Option<Package>>,
    results: Vec<Option<Result<serde_json::Value>>>,
    outputs: BTreeSet<PathBuf>,
    providers: BTreeMap<String, VerifyingKey>,
    tasks: JoinSet<GroupEvent>,
    cursor: usize,
    stopped: bool,
    fatal: Option<anyhow::Error>,
}

impl ReadyCohort {
    pub(in crate::compute::peer) fn new(
        reservations: &[ReadyPending],
        socket: &Path,
        activity: &watch::Receiver<bool>,
    ) -> Result<Self> {
        let mut driver = Self {
            socket: socket.to_owned(),
            owner: activity.clone(),
            leases: Leases::default(),
            packages: Vec::new(),
            results: Vec::new(),
            outputs: BTreeSet::new(),
            providers: BTreeMap::new(),
            tasks: JoinSet::new(),
            cursor: 0,
            stopped: false,
            fatal: None,
        };
        driver.reserve(reservations)?;
        Ok(driver)
    }

    /// Seed all previously leased work, including workflows outside this 32-package window.
    /// A matching terminal receipt can release only its original lease; none are renewed.
    pub(in crate::compute::peer) fn reserve(&mut self, pending: &[ReadyPending]) -> Result<()> {
        let time = now()?;
        for pending in pending {
            self.leases
                .observe(&pending.handle, pending.verified_status.as_ref(), time)?;
        }
        Ok(())
    }

    fn cancelled(&self) -> bool {
        self.stopped || *self.owner.borrow() || self.owner.has_changed().is_err()
    }

    fn cancel(&mut self) {
        self.stopped = true;
        stop_all(&mut self.packages);
    }

    fn fail(&mut self, error: anyhow::Error) {
        self.fatal.get_or_insert(error);
        self.cancel();
    }

    fn cancel_candidates(&mut self, first: usize) {
        let results = self.results[first..].iter_mut().map(Option::take).collect();
        for (slot, result) in self.results[first..]
            .iter_mut()
            .zip(cancelled_packages(results))
        {
            *slot = Some(result);
        }
        self.cancel();
    }

    /// Append owned sources; indices are stable and at most 32 may ever enter this window.
    /// Source/profile failures are returned by `next_completed`, not as a cohort failure.
    /// Metadata is read-only; existing worker tasks continue during these bounded probes.
    pub(in crate::compute::peer) async fn append(
        &mut self,
        args: Vec<ReadyOptions>,
    ) -> Result<Vec<usize>> {
        let first = self.packages.len();
        ensure!(
            !args.is_empty() && args.len() <= MAX_PACKAGES.saturating_sub(first),
            "compute_cohort_package_bound"
        );
        let mut outputs = self.outputs.clone();
        ensure!(
            args.iter().all(|args| outputs.insert(args.output.clone())),
            "compute_cohort_duplicate_output"
        );
        // All original leases precede all new metadata, plans and submissions, even
        // when a source later fails validation. Reserve does not create a second observer.
        for options in &args {
            self.reserve(&options.pending)?;
        }
        self.outputs = outputs;
        let indices: Vec<_> = (first..first + args.len()).collect();
        let mut candidates = Vec::new();
        let mut providers = BTreeMap::new();
        for (index, options) in indices.iter().copied().zip(args) {
            self.packages.push(None);
            self.results.push(None);
            match prepare(options) {
                Ok(candidate) => {
                    for provider in &candidate.args.providers {
                        providers.insert(hex::encode(provider.as_bytes()), *provider);
                    }
                    candidates.push((index, candidate));
                }
                Err(error) => self.results[index] = Some(Err(error)),
            }
        }
        if self.cancelled() {
            self.cancel_candidates(first);
            return Ok(indices);
        }
        let mut probes = JoinSet::new();
        for (key, provider) in &providers {
            let (key, provider) = (key.clone(), *provider);
            let (socket, activity) = (self.socket.clone(), self.owner.clone());
            probes.spawn(async move { (key, metadata(socket, provider, activity).await) });
        }
        let mut capabilities = BTreeMap::new();
        let mut probe_error = None;
        while let Some(result) = probes.join_next().await {
            match result {
                Ok((key, Ok(caps))) => {
                    capabilities.insert(key, caps);
                }
                Ok((_, Err(_))) => {}
                Err(error) => {
                    probe_error.get_or_insert(anyhow::Error::from(error));
                }
            }
        }
        if let Some(error) = probe_error {
            self.fail(error);
        }
        if self.cancelled() {
            self.cancel_candidates(first);
            return Ok(indices);
        }
        self.providers.extend(providers);
        for (index, candidate) in candidates {
            // Cancellation cannot admit a late source after another candidate's I/O.
            if self.cancelled() {
                self.results[index] = Some(Err(anyhow::anyhow!(
                    "compute_distribute_cancelled_before_submit"
                )));
                self.cancel();
                continue;
            }
            match initialize(candidate, &capabilities) {
                Ok(mut package) => {
                    for pending in
                        package.args.pending.iter().filter(|pending| {
                            !pending.verified_status.as_ref().is_some_and(terminal)
                        })
                    {
                        self.tasks.spawn(observe_pending(
                            index,
                            pending.clone(),
                            self.socket.clone(),
                            package.activity.clone(),
                        ));
                        package.inflight += 1;
                    }
                    self.packages[index] = Some(package);
                }
                Err(error) => self.results[index] = Some(Err(error)),
            }
        }
        Ok(indices)
    }

    fn take_completed(&mut self, exhausted: bool) -> Option<Completion> {
        for (index, package) in self.packages.iter_mut().enumerate() {
            let ready = package.as_ref().is_some_and(|package| {
                (package.inflight == 0 || (exhausted && self.tasks.is_empty()))
                    && (exhausted
                        || self.stopped
                        || package.error.is_some()
                        || package.rows.is_empty())
            });
            if ready {
                self.results[index] = Some(package.take().expect("checked package").report());
            }
            if let Some(result) = self.results[index].take() {
                return Some((index, result));
            }
        }
        None
    }

    fn handle_event(&mut self, event: GroupEvent) -> Result<()> {
        let index = match &event {
            GroupEvent::Profile { package, .. } | GroupEvent::Finished { package, .. } => *package,
        };
        let package = self
            .packages
            .get_mut(index)
            .and_then(Option::as_mut)
            .context("compute_cohort_package_missing")?;
        package.inflight = package
            .inflight
            .checked_sub(1)
            .context("compute_cohort_inflight_missing")?;
        match event {
            GroupEvent::Profile {
                package,
                row,
                provider,
                result,
            } => accept_profile(
                package,
                row,
                &provider,
                result,
                &mut self.packages,
                &mut self.leases,
                &self.socket,
                &mut self.tasks,
            ),
            GroupEvent::Finished {
                package,
                handle,
                result,
                new_submission,
            } => accept_finished(
                package,
                &handle,
                &result,
                new_submission,
                &mut self.packages,
                &mut self.leases,
            ),
        }
    }

    /// Yield a durable package report immediately, before refilling another package.
    /// Other exact-handle tasks keep running. `None` leaves outside-window leases intact
    /// and permits another append, but never invents a free slot from an uncertain job.
    pub(in crate::compute::peer) async fn next_completed(&mut self) -> Result<Option<Completion>> {
        loop {
            if self.cancelled() {
                self.cancel();
            }
            if let Some(result) = self.take_completed(false) {
                return Ok(Some(result));
            }
            let time = match now() {
                Ok(time) => time,
                Err(error) => {
                    self.fail(error);
                    0
                }
            };
            self.leases.expire(time);
            for package in self.packages.iter_mut().flatten() {
                if package.error.is_none() && time >= package.source.expires() {
                    package.fail(anyhow::anyhow!("compute_peer_source_expired"));
                }
            }
            if !self.stopped {
                if let Err(error) = start_probes(
                    &mut self.packages,
                    &self.providers,
                    &mut self.leases,
                    &mut self.cursor,
                    &self.socket,
                    &mut self.tasks,
                ) {
                    self.fail(error);
                }
            }
            let unlock = self.leases.next_expiry(|provider| {
                self.packages
                    .iter()
                    .flatten()
                    .any(|package| package.eligible(provider))
            });
            if self.tasks.is_empty() && (self.stopped || unlock.is_none()) {
                if let Some(result) = self.take_completed(true) {
                    return Ok(Some(result));
                }
                if let Some(error) = self.fatal.take() {
                    return Err(error);
                }
                return Ok(None);
            }
            let source_expiry = self
                .packages
                .iter()
                .flatten()
                .filter(|package| package.error.is_none())
                .map(|package| package.source.expires())
                .min();
            let wake = unlock.into_iter().chain(source_expiry).min();
            let delay = Duration::from_secs(wake.map_or(600, |at| at.saturating_sub(time).max(1)));
            let event = tokio::select! {
                biased;
                changed = self.owner.changed(), if !self.stopped => {
                    if changed.is_err() || *self.owner.borrow() { self.cancel(); }
                    continue;
                },
                () = sleep(delay), if !self.stopped => continue,
                event = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    let Some(event) = event else { continue }; event
                },
            };
            let result = event
                .map_err(anyhow::Error::from)
                .and_then(|event| self.handle_event(event));
            if let Err(error) = result {
                self.fail(error);
            }
        }
    }

    /// Stop admitting work and await all owned cancellation/receipt futures before the
    /// caller releases any workflow lock. Unconfirmed original leases remain retained.
    pub(in crate::compute::peer) async fn cancel_and_drain(&mut self) -> Result<Vec<Completion>> {
        self.cancel();
        let mut completions = Vec::new();
        let mut failure = None;
        loop {
            match self.next_completed().await {
                Ok(Some(completion)) => completions.push(completion),
                Ok(None) => break,
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(completions)
    }
}

impl Drop for ReadyCohort {
    fn drop(&mut self) {
        // No detached owner outlives the caller's locks. Durable handles conservatively
        // cover interruption; normal callers await cancel_and_drain before this point.
        self.cancel();
    }
}

#[cfg(test)]
mod tests;
