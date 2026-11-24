//! Transcribe an already held local recording without a microphone or a network client.

use std::{
    fs,
    future::Future,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use serde_json::{Value, json};
use tokio::signal::unix::{SignalKind, signal};

const MAX_SAMPLES: usize = 16_000 * 30;
const MAX_WAVE_BYTES: u64 = (MAX_SAMPLES * 2 + 65_536) as u64;

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Owned mode-0600 mono PCM16 WAV, 16 kHz, at most 30 seconds.
    #[arg(long)]
    input: PathBuf,
    /// Explicitly provisioned private CPU runtime.
    #[arg(long)]
    runtime_root: PathBuf,
    /// Read-only source-pinned Whisper tiny model directory.
    #[arg(long)]
    model_root: PathBuf,
    /// Existing private mode-0700 parent for the ephemeral input snapshot.
    #[arg(long)]
    work_parent: PathBuf,
    /// Spoken language code supported by Whisper, for example en or nl.
    #[arg(long)]
    language: String,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=2))]
    threads: u16,
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// Permit this one local execution and return the transcript on stdout.
    #[arg(long)]
    execute: bool,
}

/// Admit bounded RIFF chunks, including ordinary ancillary metadata, and one PCM payload.
fn samples(bytes: &[u8]) -> Result<usize> {
    inspect_wave(bytes, None)
}

pub(super) fn inspect_wave(bytes: &[u8], marker: Option<&[u8]>) -> Result<usize> {
    fn word(bytes: &[u8]) -> Result<usize> {
        Ok(u32::from_le_bytes(bytes.try_into()?) as usize)
    }
    ensure!(
        bytes.len() >= 12
            && &bytes[..4] == b"RIFF"
            && &bytes[8..12] == b"WAVE"
            && word(&bytes[4..8])? == bytes.len() - 8,
        "compute_speech_wave"
    );
    let mut chunks = &bytes[12..];
    let mut marker_seen = false;
    let mut format = false;
    let mut count = None;
    while !chunks.is_empty() {
        ensure!(chunks.len() >= 8, "compute_speech_chunk");
        let size = word(&chunks[4..8])?;
        let padded = size.checked_add(size % 2).context("compute_speech_chunk")?;
        ensure!(padded <= chunks.len() - 8, "compute_speech_chunk");
        let payload = &chunks[8..8 + size];
        match (&chunks[..4], marker) {
            (b"fmt ", _) => {
                ensure!(
                    !format
                        && payload.len() >= 16
                        && payload[..16] == [1, 0, 1, 0, 128, 62, 0, 0, 0, 125, 0, 0, 2, 0, 16, 0],
                    "compute_speech_pcm16_mono_16000_required"
                );
                format = true;
            }
            (b"data", _) => {
                ensure!(
                    format
                        && count.is_none()
                        && size.is_multiple_of(2)
                        && (1..=MAX_SAMPLES).contains(&(size / 2)),
                    "compute_speech_duration"
                );
                ensure!(
                    payload
                        .chunks_exact(2)
                        .any(|sample| sample != &payload[..2]),
                    "compute_speech_no_signal"
                );
                count = Some(size / 2);
            }
            (b"LIST", Some(text)) => {
                ensure!(
                    !marker_seen
                        && payload.starts_with(b"INFOICMT")
                        && payload.len() >= 12
                        && word(&payload[8..12])? == text.len()
                        && payload[12..].strip_prefix(text) == Some(&[0_u8][..text.len() % 2]),
                    "compute_synthesis_voice_marker"
                );
                marker_seen = true;
            }
            _ => ensure!(marker.is_none(), "compute_synthesis_metadata"),
        }
        chunks = &chunks[8 + padded..];
    }
    ensure!(
        marker.is_none() || marker_seen,
        "compute_synthesis_voice_marker"
    );
    count.context("compute_speech_data")
}

pub(super) async fn run(args: &Options) -> Result<()> {
    ensure!(
        (2..=3).contains(&args.language.len())
            && args.language.bytes().all(|b| b.is_ascii_lowercase()),
        "compute_speech_language"
    );
    if !args.execute {
        println!(
            "{}",
            json!({"version":1,"operation":"compute_transcribe","execute":false,
            "model_profile":"whisper-tiny-v1","language":args.language,"max_audio_seconds":30,
            "threads":args.threads,"max_seconds":args.max_seconds,"network_access":false})
        );
        return Ok(());
    }
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    for directory in [&args.runtime_root, &args.model_root, &args.work_parent] {
        super::private_directory(directory)?;
    }
    for root in [&args.model_root, &args.runtime_root] {
        ensure!(
            !args.work_parent.starts_with(root) && !root.starts_with(&args.work_parent),
            "compute_speech_directory_overlap"
        );
    }
    // Register both termination paths before any private data is read or staged.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let cancelled = async move {
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
    };
    let _lease = super::runtime_lease(&args.runtime_root)?;
    super::supervise::headroom()?;
    let bytes = super::private_task::read_owned_file(&args.input, MAX_WAVE_BYTES)?;
    let count = samples(&bytes)?;
    let staging = tempfile::Builder::new()
        .prefix("private-speech-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&args.work_parent)?;
    let started = Instant::now();
    let result = recognize(args, staging.path(), bytes, cancelled).await;
    let (reply, peak_rss) = super::private_task::finish_owned(staging, result)?;
    let text = reply["transcript"]
        .as_str()
        .context("compute_speech_reply")?;
    ensure!(
        reply["model_profile"] == "whisper-tiny-v1"
            && reply["language"] == args.language
            && reply["audio_samples"].as_u64() == Some(count as u64)
            && !text.trim().is_empty()
            && text.len() <= 4096
            && !text.chars().any(char::is_control),
        "compute_speech_reply"
    );
    let summary: Value = json!({"version":1,"operation":"compute_transcribe","model_profile":"whisper-tiny-v1",
        "language":args.language,"transcript":text,"audio_samples":count,"elapsed_ms":started.elapsed().as_millis(),
        "max_observed_rss_bytes":peak_rss,"cleanup":{"complete":true}});
    println!("{summary}");
    Ok(())
}

async fn recognize(
    args: &Options,
    stage: &Path,
    bytes: Vec<u8>,
    cancelled: impl Future<Output = ()>,
) -> Result<(Value, u64)> {
    let audio = stage.join("input.wav");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&audio)?;
    file.write_all(&bytes)?;
    drop(file);
    drop(bytes);
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| anyhow::anyhow!("compute_randomness"))?;
    let request =
        json!({"version":1,"id":hex::encode(id),"threads":args.threads,"language":args.language});
    let child = super::sandbox::speech_command(
        &args.runtime_root,
        &args.model_root,
        &audio,
        args.threads,
        args.max_seconds,
    )
    .spawn()
    .context("compute_speech_spawn")?;
    super::supervise::speech::run(child, &request, stage, args.max_seconds, cancelled).await
}

#[cfg(test)]
mod tests {
    use super::{MAX_SAMPLES, samples};

    fn wave(count: usize) -> Vec<u8> {
        let mut data =
            b"RIFF\0\0\0\0WAVEfmt \x10\0\0\0\x01\0\x01\0\x80\x3e\0\0\0\x7d\0\0\x02\0\x10\0data"
                .to_vec();
        let len = u32::try_from(count * 2).unwrap();
        data.extend(len.to_le_bytes());
        data.resize(data.len() + count * 2, 0);
        data[4..8].copy_from_slice(&(len + 36).to_le_bytes());
        if count > 0 {
            data[44] = 1;
        }
        data
    }

    #[test]
    fn synthesis_requires_one_structural_voice_label() {
        let label = b"test";
        let mut data = wave(8);
        assert!(super::inspect_wave(&data, Some(label)).is_err());
        let chunk = b"LIST\x10\0\0\0INFOICMT\x04\0\0\0test";
        data.extend(chunk);
        let len = u32::try_from(data.len() - 8).unwrap();
        data[4..8].copy_from_slice(&len.to_le_bytes());
        assert_eq!(super::inspect_wave(&data, Some(label)).unwrap(), 8);
        assert!(super::inspect_wave(&data, Some(b"fake")).is_err());
        let tag = data.len() - 12;
        data[tag..tag + 4].copy_from_slice(b"JUNK");
        assert!(super::inspect_wave(&data, Some(label)).is_err());
    }

    #[test]
    fn only_one_bounded_mono_pcm16_recording_is_admitted() {
        assert_eq!(samples(&wave(2)).unwrap(), 2);
        let mut silent = wave(4);
        silent[44..].fill(0);
        assert!(samples(&silent).is_err());
        assert_eq!(samples(&wave(MAX_SAMPLES)).unwrap(), MAX_SAMPLES);
        assert!(samples(&wave(0)).is_err());
        assert!(samples(&wave(MAX_SAMPLES + 1)).is_err());
        for at in [0, 4, 8, 20, 22, 24, 32, 34, 40] {
            let mut malformed = wave(32);
            malformed[at] ^= 0xff;
            assert!(samples(&malformed).is_err());
        }
        let mut truncated = wave(4);
        truncated.pop();
        assert!(samples(&truncated).is_err());
    }
}
