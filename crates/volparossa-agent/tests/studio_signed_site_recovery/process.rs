// SPDX-License-Identifier: GPL-3.0-only
use std::{
    ffi::OsString,
    fs,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        process::ExitStatusExt,
    },
    process::Stdio,
    time::Duration,
};

use super::{
    Cleanup, Progress, Result,
    fixture::{Fixture, absent},
};
use nix::{
    sys::signal::{Signal, kill},
    unistd::{Pid, getegid, geteuid},
};
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::UnixStream,
    process::{Child, Command},
    time::{Instant, sleep, timeout_at},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult, Empty,
    control_request::Operation, control_response::Payload, read_response, write_request,
};

const LIMIT: u64 = 65_536;

pub(super) struct Daemon {
    pub(super) child: Option<Child>,
}

impl Daemon {
    pub(super) fn new() -> Self {
        Self { child: None }
    }
    pub(super) fn spawn(
        &mut self,
        fixture: &Fixture,
        progress: &Progress,
        deadline: Instant,
    ) -> Result<()> {
        if Instant::now() >= deadline {
            return Err("operation_deadline");
        }
        if self.child.is_some() {
            return Err("daemon_already_owned");
        }
        let root = fixture.directory.path();
        let child = Command::new(env!("CARGO_BIN_EXE_volparossa-agent"))
            .env_clear()
            .env("VOLPAROSSA_CONFIG", root.join("config.yaml"))
            .env("VOLPAROSSA_STATE_DIRECTORY", root.join("state"))
            .env("VOLPAROSSA_CONTROL_SOCKET", &fixture.socket)
            .env(
                "VOLPAROSSA_HELPER_SOCKET",
                root.join("control/absent-helper.sock"),
            )
            .env(
                "VOLPAROSSA_MPQUIC_SOCKET",
                root.join("control/absent-mpquic.sock"),
            )
            .env("CREDENTIALS_DIRECTORY", root.join("credentials"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| "daemon_spawn")?;
        self.child = Some(child);
        progress.count(|counts| counts.daemon_started += 1);
        progress.cleanup.set(Cleanup::Unconfirmed);
        Ok(())
    }

    pub(super) fn pid(&self) -> Result<u32> {
        self.child.as_ref().and_then(Child::id).ok_or("daemon_pid")
    }

    pub(super) async fn ready(
        &mut self,
        fixture: &Fixture,
        progress: &Progress,
        deadline: Instant,
    ) -> Result<()> {
        let pid = self.pid()?;
        loop {
            if self
                .child
                .as_mut()
                .ok_or("daemon_missing")?
                .try_wait()
                .map_err(|_| "daemon_poll")?
                .is_some()
            {
                return Err("daemon_exited_before_ready");
            }
            if let Ok(Ok(mut stream)) =
                timeout_at(deadline, UnixStream::connect(&fixture.socket)).await
            {
                peer(&stream, pid)?;
                let reply = exchange(&mut stream, Operation::Status(Empty {}), 1, deadline).await?;
                if reply.result != ControlResult::Ok as i32
                    || !matches!(reply.payload, Some(Payload::Status(_)))
                {
                    return Err("daemon_status");
                }
                break;
            }
            timeout_at(deadline, sleep(Duration::from_millis(25)))
                .await
                .map_err(|_| "readiness_deadline")?;
        }
        socket_permissions(&fixture.socket)?;
        socket_permissions(&fixture.socket.with_extension("sock.apps"))?;
        let reply = request(fixture, pid, Operation::Roles(Empty {}), 2, deadline).await?;
        let Some(Payload::Roles(roles)) = reply.payload else {
            return Err("roles_payload");
        };
        if reply.result != ControlResult::Ok as i32 || roles.client || roles.relay || roles.exit {
            return Err("roles_not_dormant");
        }
        absent(&fixture.path("control/absent-helper.sock"))?;
        absent(&fixture.path("control/absent-mpquic.sock"))?;
        Ok(())
    }

    pub(super) async fn crash(&mut self, progress: &Progress, deadline: Instant) -> Result<()> {
        let child = self.child.as_mut().ok_or("daemon_missing")?;
        child.start_kill().map_err(|_| "daemon_crash_signal")?;
        let status = timeout_at(deadline, child.wait())
            .await
            .map_err(|_| "crash_join_deadline")?
            .map_err(|_| "crash_join")?;
        self.child = None;
        progress.count(|counts| counts.crash_joined += 1);
        progress.cleanup.set(Cleanup::CrashJoined);
        if status.signal() != Some(libc::SIGKILL) {
            return Err("crash_status");
        }
        Ok(())
    }

    pub(super) async fn graceful(&mut self, progress: &Progress, deadline: Instant) -> Result<()> {
        let pid = i32::try_from(self.pid()?).map_err(|_| "daemon_pid_bound")?;
        kill(Pid::from_raw(pid), Signal::SIGTERM).map_err(|_| "daemon_shutdown_signal")?;
        let status = timeout_at(
            deadline,
            self.child.as_mut().ok_or("daemon_missing")?.wait(),
        )
        .await
        .map_err(|_| "shutdown_deadline")?
        .map_err(|_| "shutdown_join")?;
        self.child = None;
        progress.count(|counts| counts.graceful_joined += 1);
        progress.cleanup.set(Cleanup::GracefulJoined);
        if !status.success() {
            return Err("shutdown_status");
        }
        Ok(())
    }

    pub(super) async fn failure_join(
        &mut self,
        progress: &Progress,
        deadline: Instant,
    ) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
            timeout_at(deadline, child.wait())
                .await
                .map_err(|_| "failure_join_deadline")?
                .map_err(|_| "failure_join")?;
            self.child = None;
            progress.count(|counts| counts.failure_joined += 1);
            progress.cleanup.set(Cleanup::FailureJoined);
        }
        Ok(())
    }
}

pub(super) async fn request(
    fixture: &Fixture,
    pid: u32,
    operation: Operation,
    id: u8,
    deadline: Instant,
) -> Result<ControlResponse> {
    let mut stream = timeout_at(deadline, UnixStream::connect(&fixture.socket))
        .await
        .map_err(|_| "connect_deadline")?
        .map_err(|_| "control_connect")?;
    peer(&stream, pid)?;
    exchange(&mut stream, operation, id, deadline).await
}

async fn exchange(
    stream: &mut UnixStream,
    operation: Operation,
    id: u8,
    deadline: Instant,
) -> Result<ControlResponse> {
    let request = ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![id; 16],
        operation: Some(operation),
    };
    timeout_at(deadline, write_request(stream, &request))
        .await
        .map_err(|_| "request_deadline")?
        .map_err(|_| "request_frame")?;
    let response = timeout_at(deadline, read_response(stream))
        .await
        .map_err(|_| "response_deadline")?
        .map_err(|_| "response_frame")?;
    if response.protocol_version != CONTROL_PROTOCOL_VERSION
        || response.request_id != request.request_id
    {
        return Err("response_correlation");
    }
    Ok(response)
}

fn peer(stream: &UnixStream, pid: u32) -> Result<()> {
    let peer = stream.peer_cred().map_err(|_| "socket_credentials")?;
    if peer.uid() != geteuid().as_raw()
        || peer.gid() != getegid().as_raw()
        || peer.pid() != i32::try_from(pid).ok()
    {
        return Err("socket_owner");
    }
    Ok(())
}

fn socket_permissions(path: &std::path::Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|_| "socket_metadata")?;
    let parent = fs::symlink_metadata(path.parent().ok_or("socket_parent")?)
        .map_err(|_| "socket_parent_metadata")?;
    if !meta.file_type().is_socket()
        || meta.mode() & 0o777 != 0o660
        || meta.uid() != geteuid().as_raw()
        || meta.gid() != parent.gid()
        || parent.uid() != geteuid().as_raw()
        || parent.mode() & 0o077 != 0
    {
        return Err("socket_permissions");
    }
    Ok(())
}

pub(super) async fn bounded(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| "cli_read")?;
    if u64::try_from(bytes.len()).map_err(|_| "cli_bound")? > LIMIT {
        return Err("cli_bound");
    }
    Ok(bytes)
}

pub(super) struct CliResult {
    pub(super) success: bool,
    pub(super) normal_exit: bool,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}
impl CliResult {
    pub(super) fn json(&self) -> Result<Value> {
        if !self.success {
            return Err("cli_failed");
        }
        serde_json::from_slice(&self.stdout).map_err(|_| "cli_json")
    }
    pub(super) fn rejection(&self, expected: &[u8]) -> Result<()> {
        if self.success
            || !self.normal_exit
            || !self.stdout.is_empty()
            || !self
                .stderr
                .windows(expected.len())
                .any(|window| window == expected)
        {
            return Err("cli_expected_refusal");
        }
        Ok(())
    }
}

pub(super) async fn cli(
    fixture: &Fixture,
    args: Vec<OsString>,
    progress: &Progress,
    work: Instant,
    total: Instant,
    negative: bool,
) -> Result<CliResult> {
    if Instant::now() >= work {
        return Err("operation_deadline");
    }
    let mut child = Command::new(&fixture.cli)
        .arg("--control-socket")
        .arg(&fixture.socket)
        .arg("content")
        .args(args)
        .current_dir(fixture.directory.path())
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "cli_spawn")?;
    progress.count(|counts| {
        if negative {
            counts.negative_cli_started += 1;
        } else {
            counts.positive_cli_started += 1;
        }
    });
    let captured = if let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take())
    {
        timeout_at(work, async {
            let (out, err) = tokio::join!(bounded(stdout), bounded(stderr));
            let status = child.wait().await.map_err(|_| "cli_wait")?;
            Ok(CliResult {
                success: status.success(),
                normal_exit: status.code().is_some(),
                stdout: out?,
                stderr: err?,
            })
        })
        .await
        .unwrap_or(Err("cli_deadline"))
    } else {
        Err("cli_streams")
    };
    if captured.is_err() {
        let _ = child.start_kill();
        timeout_at(total, child.wait())
            .await
            .map_err(|_| "cli_cleanup_deadline")?
            .map_err(|_| "cli_cleanup_join")?;
    }
    progress.count(|counts| {
        if negative {
            counts.negative_cli_joined += 1;
        } else {
            counts.positive_cli_joined += 1;
        }
    });
    captured
}
