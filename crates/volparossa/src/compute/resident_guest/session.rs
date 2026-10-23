//! One accepted channel owns one retained worker and awaits its real cleanup.

use super::wire;
use crate::compute::{
    private_conversation, private_task,
    supervise::native_session::{self, Command, Event, SessionBudget},
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
    time::sleep_until,
};
use volparossa_content::provider::compute::resident_task::GrantAllowance;

struct CancelOnDrop(watch::Sender<bool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(false);
    }
}

// The CLI awaits this top-level owner to completion. Do not wrap it in a timeout
// or abort it: cancellation is an input to the loop, not cancellation of the
// cleanup future. The reader owns no worker and is explicitly aborted and joined.
pub(super) async fn execute<S, F, Fut>(
    stream: S,
    config: Arc<private_task::ExecutionConfig>,
    mut allowance: GrantAllowance,
    budget: SessionBudget,
    run: F,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(
        Arc<private_task::ExecutionConfig>,
        mpsc::Receiver<Command>,
        mpsc::Sender<Event>,
        watch::Receiver<bool>,
        SessionBudget,
    ) -> Fut,
    Fut: Future<Output = Result<Value>> + Send + 'static,
{
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let deadline = allowance.deadline();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (incoming, mut frames) = mpsc::channel(1);
    let reader_task = tokio::spawn(async move {
        loop {
            let frame = wire::read(&mut reader, deadline).await;
            let failed = frame.is_err();
            if incoming.send(frame).await.is_err() || failed {
                break;
            }
        }
    });
    let (commands, receive) = mpsc::channel(1);
    let (send, mut events) = mpsc::channel(1);
    let (activity, signal) = watch::channel(true);
    let activity = CancelOnDrop(activity);
    let execution = tokio::spawn(run(config.clone(), receive, send, signal, budget));
    let mut opened = false;
    let mut closing = false;
    let mut sequence = 1_u32;
    let mut pending: Option<String> = None;
    let mut native_ended = false;
    let result: Result<()> = async {
        loop {
            tokio::select! {
                biased;
                _ = terminate.recv() => anyhow::bail!("resident_stopped"),
                _ = interrupt.recv() => anyhow::bail!("resident_stopped"),
                () = sleep_until(deadline) => anyhow::bail!("resident_session_deadline"),
                frame = frames.recv(), if opened && !closing => {
                    let frame = frame.ok_or_else(|| anyhow::anyhow!("resident_channel_closed"))??;
                    ensure!(pending.is_none() && frame.sequence == sequence, "resident_request_order");
                    match frame.kind {
                        wire::SUBMIT => {
                            allowance.consume_input(&Sha256::digest(&frame.body).into())?;
                            let input = private_conversation::Input::decode_profile(&frame.body, config.model_profile)?;
                            ensure!(input.requires_generation_policy_handshake(), "resident_generation_policy");
                            allowance.check()?;
                            let id = format!("{sequence:032x}");
                            commands.try_send(Command::Submit { id: id.clone(), input: frame.body }).map_err(|_| anyhow::anyhow!("resident_worker_channel"))?;
                            pending = Some(id);
                            wire::write(&mut writer, wire::frame(wire::ADMITTED, sequence, vec![]), deadline).await?;
                        }
                        wire::CLOSE => {
                            ensure!(frame.body.is_empty(), "resident_close_payload");
                            commands.try_send(Command::Close).map_err(|_| anyhow::anyhow!("resident_worker_channel"))?;
                            closing = true;
                        }
                        _ => anyhow::bail!("resident_operation"),
                    }
                }
                event = events.recv() => match event {
                    Some(Event::Opened) if !opened => opened = true,
                    Some(Event::Result { id, value }) if pending.as_ref() == Some(&id) => {
                        ensure!(value["version"] == 2 && value["cleanup"] == json!({"version":2,"request_files_removed":true,"session_closed":false,"session_private_state_retained":true}), "resident_turn_receipt");
                        wire::write(&mut writer, wire::frame(wire::RESULT, sequence, serde_json::to_vec(&value)?), deadline).await?;
                        pending = None;
                        sequence += 1;
                    }
                    None => { native_ended = true; ensure!(closing && pending.is_none(), "resident_worker_stopped"); break Ok(()); }
                    _ => anyhow::bail!("resident_worker_event"),
                }
            }
        }
    }.await;
    // Reader cancellation never cancels the retained worker's mandatory join.
    reader_task.abort();
    let _ = reader_task.await;
    drop(activity);
    drop(commands);
    drop(events);
    let execution = execution
        .await
        .map_err(|_| anyhow::anyhow!("resident_cleanup_unconfirmed"))?;
    let cleanup = match &execution {
        Ok(value) => Some(value.clone()),
        Err(error) => native_session::cleanup(error),
    };
    ensure!(
        cleanup == Some(json!({"version":1,"child_reaped":true,"private_state_removed":true})),
        "resident_cleanup_unconfirmed"
    );
    // Only spontaneous native sender closure during an admitted turn can export
    // its sealed diagnostic. Cancellation/read/write/signal failures cannot.
    if native_ended && pending.is_some() {
        if let Err(error) = &execution {
            observe_native_failure(&mut writer, error, sequence, deadline).await;
        }
    }
    execution?;
    result?;
    wire::write(
        &mut writer,
        wire::frame(wire::CLOSED, sequence, serde_json::to_vec(&cleanup)?),
        deadline,
    )
    .await
}

// The caller has already checked loop origin and the exact owner cleanup receipt.
// The sealed accessor independently denies ordinary/unconfirmed errors.
pub(super) async fn observe_native_failure(
    writer: &mut (impl AsyncWrite + Unpin),
    error: &anyhow::Error,
    sequence: u32,
    deadline: tokio::time::Instant,
) {
    if let Some(detail) = native_session::public_fixture_failure(error) {
        if let Ok(frame) = wire::failure(sequence, &detail) {
            // No fresh execution budget, retry, or error-precedence change.
            let _ = wire::write(writer, frame, deadline).await;
        }
    }
}
