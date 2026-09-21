//! Fixed Debian sandbox, never a remotely supplied executable or shell command.

use std::process::Stdio;

use tokio::process::Command;

use super::Options;

pub(super) const ADDRESS_SPACE_BYTES: u64 = 6 * 1024 * 1024 * 1024;
pub(super) const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const TMPFS_BYTES: u64 = 16 * 1024 * 1024;

fn worker_source() -> String {
    // Both modules are fixed build inputs, not files supplied by a task or peer.
    // -I deliberately excludes cwd/PYTHONPATH; install this bundled module only
    // in this interpreter's module table, without creating a disk import path.
    let decoder = serde_json::json!(include_str!(
        "../../../../workers/volparossa-ml/task_graph_decoder.py"
    ));
    format!(
        "import sys as _vp_sys, types as _vp_types\n\
         _vp_decoder = _vp_types.ModuleType('volparossa_task_graph_decoder')\n\
         exec({decoder}, _vp_decoder.__dict__)\n\
         _vp_sys.modules['volparossa_task_graph_decoder'] = _vp_decoder\n{}",
        include_str!("../../../../workers/volparossa-ml/worker.py")
    )
}

// Keep the complete fixed sandbox argument vector reviewable in one place.
#[allow(clippy::too_many_lines)]
pub(super) fn command(options: &Options) -> Command {
    let mut command = Command::new("/usr/bin/bwrap");
    if let Some(adapter) = &options.adapter_root {
        command.arg("--ro-bind").arg(adapter).arg("/adapter");
    }
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
            &worker_source(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixed_worker_bundles_decoder_without_a_filesystem_import_or_oversized_argument() {
        let source = super::worker_source();
        assert!(source.len() < 128 * 1024 - 1);
        assert!(source.contains("_vp_sys.modules['volparossa_task_graph_decoder'] = _vp_decoder"));
        assert!(source.ends_with(include_str!("../../../../workers/volparossa-ml/worker.py")));
        assert!(
            source.contains(
                &serde_json::json!(include_str!(
                    "../../../../workers/volparossa-ml/task_graph_decoder.py"
                ))
                .to_string()
            )
        );
    }
}
