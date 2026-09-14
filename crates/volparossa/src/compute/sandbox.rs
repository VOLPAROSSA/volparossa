//! Fixed Debian sandbox, never a remotely supplied executable or shell command.

use std::process::Stdio;

use tokio::process::Command;

use super::Options;

pub(super) const ADDRESS_SPACE_BYTES: u64 = 6 * 1024 * 1024 * 1024;
pub(super) const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const TMPFS_BYTES: u64 = 16 * 1024 * 1024;

// Keep the complete fixed sandbox argument vector reviewable in one place.
#[allow(clippy::too_many_lines)]
pub(super) fn command(options: &Options) -> Command {
    let mut command = Command::new("/usr/bin/bwrap");
    command
        .env_clear()
        .args([
            "--unshare-user",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
            &TMPFS_BYTES.to_string(),
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(&options.runtime_root)
        .arg("/runtime")
        .arg("--ro-bind")
        .arg(&options.model_root)
        .arg("/model")
        .arg("--ro-bind")
        .arg(&options.dataset)
        .arg("/dataset.json")
        .arg("--bind")
        .arg(&options.output)
        .arg("/output")
        .args([
            "--chdir",
            "/output",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "CUDA_VISIBLE_DEVICES",
            "",
            "--setenv",
            "OMP_NUM_THREADS",
            &options.threads.to_string(),
            "--setenv",
            "MKL_NUM_THREADS",
            &options.threads.to_string(),
            "--setenv",
            "OPENBLAS_NUM_THREADS",
            &options.threads.to_string(),
            "--setenv",
            "TOKENIZERS_PARALLELISM",
            "false",
            "--setenv",
            "HF_HUB_OFFLINE",
            "1",
            "--setenv",
            "TRANSFORMERS_OFFLINE",
            "1",
            "--",
            "/usr/bin/prlimit",
            "--core=0",
            "--nofile=128",
            "--nproc=128",
            &format!("--as={ADDRESS_SPACE_BYTES}"),
            &format!("--fsize={MAX_FILE_BYTES}"),
            &format!("--cpu={}", options.max_seconds),
            "/usr/bin/nice",
            "-n",
            "19",
            "/usr/bin/ionice",
            "-c",
            "3",
            "/runtime/bin/python3",
            "-I",
            "-c",
            include_str!("../../../../workers/volparossa-ml/worker.py"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}
