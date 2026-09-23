//! Fixed Debian sandbox, never a remotely supplied executable or shell command.

use std::process::Stdio;

use tokio::process::Command;

use super::Options;

pub(super) const ADDRESS_SPACE_BYTES: u64 = 6 * 1024 * 1024 * 1024;
pub(super) const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const TMPFS_BYTES: u64 = 16 * 1024 * 1024;

// Linux bounds each individual argv string independently of ARG_MAX. Keep
// bundled code out of the single -c string as the fixed worker grows. These
// arguments are build inputs only, never prompts or peer-supplied source.
const SOURCE_ARGUMENT_BYTES: usize = 32 * 1024;
const WORKER_BOOTSTRAP: &str = "import sys as _vp_boot_sys\n\
    _vp_source = ''.join(_vp_boot_sys.argv[1:])\n\
    _vp_boot_sys.argv = ['-c']\n\
    exec(compile(_vp_source, '<volparossa-worker>', 'exec'))\n";

fn source_arguments(source: &str) -> Vec<String> {
    let mut remaining = source;
    let mut arguments = vec![WORKER_BOOTSTRAP.to_owned()];
    while !remaining.is_empty() {
        let mut end = remaining.len().min(SOURCE_ARGUMENT_BYTES);
        while !remaining.is_char_boundary(end) {
            end -= 1;
        }
        arguments.push(remaining[..end].to_owned());
        remaining = &remaining[end..];
    }
    arguments
}

fn worker_source() -> String {
    // These modules are fixed build inputs, not files supplied by a task or peer.
    // -I deliberately excludes cwd/PYTHONPATH; install this bundled module only
    // in this interpreter's module table, without creating a disk import path.
    let decoder = serde_json::json!(include_str!(
        "../../../../workers/volparossa-ml/task_graph_decoder.py"
    ));
    let aggregation = serde_json::json!(include_str!(
        "../../../../workers/volparossa-ml/adapter_aggregation.py"
    ));
    format!(
        "import sys as _vp_sys, types as _vp_types\n\
         _vp_decoder = _vp_types.ModuleType('volparossa_task_graph_decoder')\n\
         exec({decoder}, _vp_decoder.__dict__)\n\
         _vp_sys.modules['volparossa_task_graph_decoder'] = _vp_decoder\n\
         _vp_aggregation = _vp_types.ModuleType('volparossa_adapter_aggregation')\n\
         exec({aggregation}, _vp_aggregation.__dict__)\n\
         _vp_sys.modules['volparossa_adapter_aggregation'] = _vp_aggregation\n{}",
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
        ])
        .args(source_arguments(&worker_source()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

#[cfg(test)]
mod tests {
    use super::{SOURCE_ARGUMENT_BYTES, WORKER_BOOTSTRAP, source_arguments, worker_source};

    #[test]
    fn fixed_worker_bundles_decoder_without_a_filesystem_import_or_oversized_argument() {
        let source = worker_source();
        let arguments = source_arguments(&source);
        assert_eq!(arguments[0], WORKER_BOOTSTRAP);
        assert_eq!(arguments[1..].concat(), source);
        assert!(
            arguments
                .iter()
                .all(|part| part.len() <= SOURCE_ARGUMENT_BYTES)
        );
        // Also reserve ample room under Linux's total argv/environment bound.
        assert!(arguments.iter().map(|part| part.len() + 1).sum::<usize>() < 1024 * 1024);
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

    #[test]
    fn source_chunks_preserve_multibyte_boundaries_without_rewriting_code() {
        for width in 1..=4 {
            let source = "a".repeat(SOURCE_ARGUMENT_BYTES - width) + "é🙂漢字";
            let arguments = source_arguments(&source);
            assert_eq!(arguments[1..].concat(), source);
            assert!(
                arguments
                    .iter()
                    .all(|part| part.len() <= SOURCE_ARGUMENT_BYTES)
            );
        }
    }

    #[test]
    fn bootstrap_executes_only_the_inert_fixture_not_the_model_worker() {
        // Python's standard interpreter only: no model, decoder backend, third-party
        // import, sandbox/mount operation or network access is executed here.
        let source = format!(
            "# {}\nimport sys\nassert sys.argv == ['-c']\nassert __name__ == '__main__'\nprint('bundled source reassembled')\n",
            "é🙂".repeat(24 * 1024)
        );
        assert!(source.len() > 128 * 1024);
        let result = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-c"])
            .args(source_arguments(&source))
            .output()
            .unwrap();
        assert!(result.status.success(), "{:?}", result.stderr);
        assert_eq!(result.stdout, b"bundled source reassembled\n");
        assert!(result.stderr.is_empty());
    }
}
