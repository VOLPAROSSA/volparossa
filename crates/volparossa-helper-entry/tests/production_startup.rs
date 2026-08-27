//! End-to-end startup ownership checks for the privileged helper executable.

use std::{
    fs::File,
    process::{Command, Stdio},
};

use rustix::process::{PidfdFlags, getpid, pidfd_open};

#[test]
fn production_binary_takes_and_refuses_real_inherited_custody_in_both_orders() {
    let executable = env!("CARGO_BIN_EXE_volparossa-helper");
    let name = format!("volparossa-custody-v1-{}", "0".repeat(64));
    let names = format!("{name}:{name}");
    let script = r#"
exec 3<&0
exec 4>&1
exec 0</dev/null
exec 1>&2
exec env LISTEN_PID=$$ LISTEN_FDS=2 LISTEN_FDNAMES="$1" "$0"
"#;

    for reversed in [false, true] {
        let pidfd = Stdio::from(
            pidfd_open(getpid(), PidfdFlags::empty()).expect("open current-process pidfd fixture"),
        );
        let network_namespace =
            Stdio::from(File::open("/proc/self/ns/net").expect("open network namespace fixture"));
        let (stdin, stdout) = if reversed {
            (network_namespace, pidfd)
        } else {
            (pidfd, network_namespace)
        };
        let output = Command::new("/bin/sh")
            .arg("-eu")
            .arg("-c")
            .arg(script)
            .arg(executable)
            .arg(&names)
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::piped())
            .output()
            .expect("run production inherited-custody fixture");
        assert!(!output.status.success(), "custody must fail closed");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("HELPER_SHUTDOWN_FAILED"),
            "fixed shutdown diagnostic missing: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
