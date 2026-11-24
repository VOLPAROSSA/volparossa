//! Execute a foreground audio task with the shared bounded IPC and descendant cleanup.

use super::{
    Context as _, Duration, ExecutionDeadline, Path, Result, Value, collect_completion,
    confirm_cleanup, ensure, lifetime::OwnedLifetimes, observe,
};
use tokio::{
    io::AsyncWriteExt as _, process::Child, signal::unix::Signal, time::MissedTickBehavior,
};

pub(in crate::compute) async fn run(
    mut child: Child,
    request: &Value,
    stage: &Path,
    seconds: u16,
    mut interrupt: Signal,
) -> Result<(Value, u64)> {
    let pid = child.id().context("compute_speech_pid")?;
    let mut lifetimes = OwnedLifetimes::capture(pid);
    let mut peak_rss = 0;
    let result = async {
        let mut stdin = child.stdin.take().context("compute_speech_stdin")?;
        let stdout = child.stdout.take().context("compute_speech_stdout")?;
        let stderr = child.stderr.take().context("compute_speech_stderr")?;
        let id = request["id"].as_str().context("compute_speech_id")?;
        let mut input = serde_json::to_vec(request)?;
        input.push(b'\n');
        stdin.write_all(&input).await?;
        drop(stdin);
        let completion = collect_completion(&mut child, stdout, stderr, id, None, None);
        tokio::pin!(completion);
        let deadline = tokio::time::sleep(Duration::from_secs(u64::from(seconds)));
        tokio::pin!(deadline);
        let mut ticks = tokio::time::interval(Duration::from_millis(250));
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = interrupt.recv() => anyhow::bail!("compute_owner_cancelled"),
                () = &mut deadline => return Err(ExecutionDeadline.into()),
                result = &mut completion => {
                    let (value, status) = result?;
                    ensure!(status.success() && value["status"] == "ok", "compute_speech_failed");
                    return Ok(value);
                },
                _ = ticks.tick() => {
                    lifetimes.as_mut().map_err(|_| anyhow::anyhow!("compute_private_process_observation"))?.refresh()?;
                    peak_rss = peak_rss.max(observe(pid, stage, true, super::super::resources::SMALL_CPU.observed_rss)?);
                }
            }
        }
    }
    .await;
    let value = confirm_cleanup(&mut child, true, result, Some(lifetimes)).await?;
    Ok((value, peak_rss))
}
