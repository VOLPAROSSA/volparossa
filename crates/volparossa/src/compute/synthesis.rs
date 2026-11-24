//! Produce one marked synthetic recording, released only after worker cleanup.

use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context as _, Result, ensure};
use clap::{Args, ValueEnum};
use serde_json::json;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Voice {
    EnUs,
    Nl,
}

impl Voice {
    fn name(self) -> &'static str {
        match self {
            Self::EnUs => "en-us",
            Self::Nl => "nl",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Absolute path to private UTF-8 text, mode 0600, at most 512 bytes.
    #[arg(long)]
    input: PathBuf,
    /// New WAV file in an existing private directory, mono PCM16 at 16 kHz.
    #[arg(long)]
    output: PathBuf,
    /// An explicitly synthetic eSpeak NG voice.
    #[arg(long, value_enum)]
    voice: Voice,
    /// Allow this one local synthesis. The default previews its limits.
    #[arg(long)]
    execute: bool,
}

const SECONDS: u16 = 15;
const MAX_WAVE_BYTES: u64 = 30 * 16_000 * 2 + 1024;

pub(super) async fn run(args: &Options) -> Result<()> {
    let voice = args.voice.name();
    if !args.execute {
        println!(
            "{}",
            json!({"version":1,"operation":"compute_synthesize","execute":false,
            "voice":voice,"engine":"espeak-ng","synthetic":true,"network_access":false,
            "max_text_bytes":512,"max_audio_seconds":30})
        );
        return Ok(());
    }
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    let directory = args.output.parent().context("compute_synthesis_output")?;
    super::private_directory(directory)?;
    ensure!(
        args.output.file_name().is_some() && !args.output.try_exists()?,
        "compute_synthesis_output_exists"
    );
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let cancelled = async move {
        tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
    };
    let text = String::from_utf8(super::private_task::read_owned_file(&args.input, 512)?)?;
    ensure!(
        !text.trim().is_empty()
            && text
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r')),
        "compute_synthesis_text"
    );
    super::supervise::headroom()?;
    let stage = tempfile::Builder::new()
        .prefix(".volparossa-speech-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(directory)?;
    let started = Instant::now();
    let result = render(stage.path(), voice, text, cancelled).await;
    let (wave, samples, rss) = super::private_task::finish_owned(stage, result)?;
    let mut output = tempfile::NamedTempFile::new_in(directory)?;
    output.write_all(&wave)?;
    output.as_file().sync_all()?;
    output
        .persist_noclobber(&args.output)
        .context("compute_synthesis_publish")?;
    println!(
        "{}",
        json!({"version":1,"operation":"compute_synthesize","execute":true,"engine":"espeak-ng",
        "voice":voice,"synthetic":true,"audio_samples":samples,"sample_rate":16000,
        "elapsed_ms":started.elapsed().as_millis(),"max_observed_rss_bytes":rss,"cleanup":{"complete":true}})
    );
    Ok(())
}

async fn render(
    stage: &Path,
    voice: &str,
    text: String,
    cancelled: impl std::future::Future<Output = ()>,
) -> Result<(Vec<u8>, usize, u64)> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| anyhow::anyhow!("compute_randomness"))?;
    let request = json!({"version":1,"id":hex::encode(id),"voice":voice,"text":text});
    let child = super::sandbox::synthesis_command(stage, SECONDS)
        .spawn()
        .context("compute_synthesis_spawn")?;
    let (reply, rss) =
        super::supervise::speech::run(child, &request, stage, SECONDS, cancelled).await?;
    let wave = super::private_task::read_owned_file(&stage.join("audio.wav"), MAX_WAVE_BYTES)?;
    let samples = super::speech::samples(&wave)?;
    ensure!(
        reply["voice"] == voice && reply["audio_samples"].as_u64() == Some(samples as u64),
        "compute_synthesis_result"
    );
    Ok((wave, samples, rss))
}
