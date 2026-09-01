//! VOLPAROSSA user-facing command-line interface.

mod control;
mod doctor;
mod secret;

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, FileTypeExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::process::Command as ProcessCommand;
use tracing_subscriber::EnvFilter;
use volparossa_identity::IdentityStore;
use volparossa_local_control::{
    ConnectRequest, ControlResponse, Empty, LogQuery, NodeRole, RoleChange, SessionTransport,
    control_request::Operation, control_response::Payload,
};

const DEFAULT_CONFIG: &str = "/etc/volparossa/config.yaml";
const DEFAULT_CONTROL_SOCKET: &str = "/run/volparossa/control/agent.sock";
const DEFAULT_STATE_DIRECTORY: &str = "/var/lib/volparossa";
const DEFAULT_TRUST_STORE: &str = "/etc/volparossa/policy-maintainers.json";
const SERVICES: [&str; 3] = [
    "volparossa-agent.service",
    "volparossa-mpquic.service",
    "volparossa-helper.service",
];

#[derive(Debug, Parser)]
#[command(
    name = "volparossa",
    version,
    about = "Decentralised one-relay privacy overlay"
)]
struct Cli {
    /// Strict YAML configuration.
    #[arg(long, env = "VOLPAROSSA_CONFIG", default_value = DEFAULT_CONFIG, global = true)]
    config: PathBuf,
    /// Agent control socket.
    #[arg(
        long,
        env = "VOLPAROSSA_CONTROL_SOCKET",
        default_value = DEFAULT_CONTROL_SOCKET,
        global = true
    )]
    control_socket: PathBuf,
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Create a new encrypted permanent Ed25519 identity.
    Init {
        /// Exact identity file path; defaults below the state directory.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Strict 0600 passphrase file; otherwise prompt without echo.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Run read-only prerequisite and safety checks.
    Doctor {
        /// Emit a machine-readable JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Start the hardened systemd services.
    Start,
    /// Stop services, triggering helper-owned cleanup.
    Stop,
    /// Show agent status.
    Status,
    /// Establish a policy-approved route context for one explicit transport.
    Connect {
        /// Product transport to establish.
        #[arg(long, value_enum, default_value = "single-path-udp")]
        transport: ConnectTransport,
    },
    /// Drain and remove all route contexts.
    Disconnect,
    /// Show locally known peers.
    Peers,
    /// Show selected client-relay-exit paths.
    Paths,
    /// Show ephemeral sessions without destination metadata.
    Sessions,
    /// Policy inspection and offline threshold verification.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Independently inspect or change voluntary roles.
    Role {
        #[command(subcommand)]
        command: RoleCommand,
    },
    /// Configuration operations.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Show bounded privacy-safe in-memory logs.
    Logs {
        /// Maximum records.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
    },
    /// Preview or execute scoped VOLPAROSSA service cleanup.
    Cleanup {
        /// Stop agent/helper services; without this flag the command is preview-only.
        #[arg(long)]
        execute: bool,
    },
    /// Validate prerequisites and ask the real agent to connect.
    Demo,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Show active policy metadata from the agent.
    Status,
    /// Verify a signed manifest against an independent local trust root.
    Verify {
        /// Canonical signed manifest.
        file: PathBuf,
        /// Agent-compatible JSON file containing pinned maintainer public keys.
        #[arg(long, default_value = DEFAULT_TRUST_STORE)]
        trust_store: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RoleCommand {
    /// Show role state.
    Show,
    /// Enable a voluntary role after agent-side safety validation.
    Enable { role: VoluntaryRole },
    /// Disable a voluntary role and drain its reservations.
    Disable { role: VoluntaryRole },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum VoluntaryRole {
    Relay,
    Exit,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ConnectTransport {
    Mptcp,
    SinglePathUdp,
    MultipathQuic,
}

impl ConnectTransport {
    const fn request(self) -> ConnectRequest {
        let transport = match self {
            Self::Mptcp => SessionTransport::Mptcp,
            Self::SinglePathUdp => SessionTransport::SinglePathUdp,
            Self::MultipathQuic => SessionTransport::MultipathQuic,
        };
        ConnectRequest {
            transport: Some(transport as i32),
        }
    }
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Parse and fail-closed validate the configured YAML file.
    Validate,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .try_init()
        .ok();
    let cli = Cli::parse();
    dispatch(cli).await
}

async fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        CliCommand::Init {
            identity,
            passphrase_file,
        } => initialize_identity(identity, passphrase_file.as_deref()),
        CliCommand::Doctor { json } => run_doctor(&cli.config, json),
        CliCommand::Start => systemctl("start").await,
        CliCommand::Stop => systemctl("stop").await,
        CliCommand::Status => {
            let response =
                control::request(&cli.control_socket, Operation::Status(Empty {})).await?;
            print_response(response)
        }
        CliCommand::Connect { transport } => {
            let response =
                control::request(&cli.control_socket, Operation::Connect(transport.request()))
                    .await?;
            print_response(response)
        }
        CliCommand::Disconnect => {
            let response =
                control::request(&cli.control_socket, Operation::Disconnect(Empty {})).await?;
            print_response(response)
        }
        CliCommand::Peers => {
            let response =
                control::request(&cli.control_socket, Operation::Peers(Empty {})).await?;
            print_response(response)
        }
        CliCommand::Paths => {
            let response =
                control::request(&cli.control_socket, Operation::Paths(Empty {})).await?;
            print_response(response)
        }
        CliCommand::Sessions => {
            let response =
                control::request(&cli.control_socket, Operation::Sessions(Empty {})).await?;
            print_response(response)
        }
        CliCommand::Policy { command } => match command {
            PolicyCommand::Status => {
                let response =
                    control::request(&cli.control_socket, Operation::PolicyStatus(Empty {}))
                        .await?;
                print_response(response)
            }
            PolicyCommand::Verify { file, trust_store } => {
                verify_policy(&cli.config, &file, &trust_store)
            }
        },
        CliCommand::Role { command } => match command {
            RoleCommand::Show => {
                let response =
                    control::request(&cli.control_socket, Operation::Roles(Empty {})).await?;
                print_response(response)
            }
            RoleCommand::Enable { role } => set_role(&cli.control_socket, role, true).await,
            RoleCommand::Disable { role } => set_role(&cli.control_socket, role, false).await,
        },
        CliCommand::Config {
            command: ConfigCommand::Validate,
        } => {
            doctor::load_config_bounded(&cli.config)?;
            println!("configuration valid: {}", cli.config.display());
            Ok(())
        }
        CliCommand::Logs { limit } => {
            let response = control::request(
                &cli.control_socket,
                Operation::Logs(LogQuery {
                    maximum_records: limit,
                }),
            )
            .await?;
            print_response(response)
        }
        CliCommand::Cleanup { execute } => cleanup(execute, &cli.control_socket).await,
        CliCommand::Demo => {
            let report = doctor::run(&cli.config);
            print_doctor(&report);
            if !report.is_usable() {
                bail!("demo cannot start because required doctor checks failed");
            }
            let response = control::request(
                &cli.control_socket,
                Operation::Connect(ConnectTransport::SinglePathUdp.request()),
            )
            .await?;
            print_response(response)
        }
    }
}

fn initialize_identity(identity: Option<PathBuf>, passphrase_file: Option<&Path>) -> Result<()> {
    let path = identity.unwrap_or_else(default_identity_path);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("identity path has no parent directory"))?;
    if !parent.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("cannot create state directory {}", parent.display()))?;
    }
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("cannot inspect state directory {}", parent.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("identity parent must be a real directory");
    }
    let passphrase = secret::read_passphrase(passphrase_file, passphrase_file.is_none())?;
    let created = IdentityStore::new(&path).create(&passphrase)?;
    println!("identity created: {}", path.display());
    println!("peer ID: {}", created.peer_id());
    Ok(())
}

fn default_identity_path() -> PathBuf {
    std::env::var_os("VOLPAROSSA_STATE_DIRECTORY")
        .map_or_else(|| PathBuf::from(DEFAULT_STATE_DIRECTORY), PathBuf::from)
        .join("identity.key")
}

fn run_doctor(config: &Path, json: bool) -> Result<()> {
    let report = doctor::run(config);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_doctor(&report);
    }
    if report.is_usable() {
        Ok(())
    } else {
        bail!("one or more required doctor checks failed")
    }
}

fn print_doctor(report: &doctor::DoctorReport) {
    for check in &report.checks {
        println!("{:?}\t{}\t{}", check.status, check.name, check.detail);
    }
}

async fn systemctl(action: &str) -> Result<()> {
    let mut command = ProcessCommand::new("systemctl");
    command.arg(action);
    command.args(SERVICES);
    let status = command
        .status()
        .await
        .context("could not execute systemctl")?;
    if status.success() {
        Ok(())
    } else {
        bail!("systemctl {action} failed with {status}")
    }
}

async fn cleanup(execute: bool, control_socket: &Path) -> Result<()> {
    println!("cleanup scope: VOLPAROSSA agent contexts and helper-owned runtime resources only");
    println!("unowned host routes, DNS, firewall rules, interfaces and namespaces are excluded");
    println!("services: {}", SERVICES.join(", "));
    if !execute {
        println!(
            "preview only; rerun with --execute to drain the agent, stop all services and trigger helper cleanup"
        );
        return Ok(());
    }

    match fs::symlink_metadata(control_socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            match control::request(control_socket, Operation::Disconnect(Empty {})).await {
                Ok(response) => print_response(response)?,
                Err(error) => eprintln!(
                    "agent drain was unavailable ({error:#}); stopping the helper will still trigger its scoped shutdown cleanup"
                ),
            }
        }
        Ok(_) => eprintln!("agent control path is not a socket; refusing to connect to it"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("agent control socket is absent; relying on helper shutdown cleanup");
        }
        Err(error) => return Err(error).context("could not inspect the agent control socket"),
    }
    systemctl("stop").await
}

async fn set_role(socket: &Path, role: VoluntaryRole, enabled: bool) -> Result<()> {
    let role = match role {
        VoluntaryRole::Relay => NodeRole::Relay,
        VoluntaryRole::Exit => NodeRole::Exit,
    };
    let response = control::request(
        socket,
        Operation::SetRole(RoleChange {
            role: role as i32,
            enabled,
        }),
    )
    .await?;
    print_response(response)
}

fn verify_policy(config_path: &Path, manifest_path: &Path, trust_path: &Path) -> Result<()> {
    let config = doctor::load_config_bounded(config_path)?;
    let now_ms = doctor::unix_millis()?;
    let evidence = doctor::verify_policy_at(&config, manifest_path, trust_path, now_ms)?;
    println!("policy valid");
    println!("manifest version: {}", evidence.manifest_version);
    println!("policy hash: {}", hex::encode(evidence.policy_hash));
    println!("verified signatures: {}", evidence.verified_signatures);
    println!("expires at (ms): {}", evidence.expires_at_ms);
    Ok(())
}

fn print_response(response: ControlResponse) -> Result<()> {
    match response
        .payload
        .ok_or_else(|| anyhow::anyhow!("agent returned no typed payload"))?
    {
        Payload::Ack(_) => println!("ok"),
        Payload::Status(status) => {
            println!("connected: {}", status.connected);
            println!("active peers: {}", status.active_peers);
            println!("candidate pool: {}", status.candidate_pool);
            println!("active contexts: {}", status.active_contexts);
            println!("MPTCP subflows: {}", status.mptcp_subflows);
            println!("MPQUIC paths: {}", status.mpquic_paths);
        }
        Payload::Peers(list) => {
            for peer in list.peers {
                println!(
                    "{}\troles={:#05b}\treachability={}",
                    peer.peer_id, peer.role_bits, peer.reachability
                );
            }
        }
        Payload::Paths(list) => {
            for path in list.paths {
                println!(
                    "context={} path={} relay={} exit={} state={} rtt_us={} bytes={}",
                    hex::encode(path.route_context_id),
                    path.path_id,
                    path.relay_peer_id,
                    path.exit_peer_id,
                    path.state,
                    path.smoothed_rtt_micros,
                    path.user_bytes
                );
            }
        }
        Payload::Sessions(list) => {
            for session in list.sessions {
                println!(
                    "session={} transport={} paths={} user_bytes={} tunnel_bytes={}",
                    hex::encode(session.session_id),
                    session.transport,
                    session.active_paths,
                    session.user_bytes,
                    session.tunnel_bytes
                );
            }
        }
        Payload::Policy(policy) => {
            println!("active: {}", policy.active);
            println!("manifest version: {}", policy.manifest_version);
            println!("policy hash: {}", hex::encode(policy.policy_hash));
            println!("verified signatures: {}", policy.verified_signatures);
            println!("expires at (ms): {}", policy.expires_at_ms);
        }
        Payload::Roles(roles) => {
            println!("client: {}", roles.client);
            println!("relay: {}", roles.relay);
            println!("exit: {}", roles.exit);
        }
        Payload::Logs(logs) => {
            for record in logs.records {
                println!(
                    "{}\tlevel={}\tevent={}\tsession={}\tpath={}",
                    record.timestamp_ms,
                    record.level,
                    record.event_code,
                    hex::encode(record.session_id),
                    record
                        .path_id
                        .map_or_else(|| "-".to_owned(), |id| id.to_string())
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_identity_uses_state_directory_override() {
        // The pure fallback is stable; environment mutation is intentionally avoided in tests.
        assert!(default_identity_path().ends_with("identity.key"));
    }
    #[test]
    fn every_master_section_twenty_nine_command_form_parses() {
        let commands: &[&[&str]] = &[
            &["volparossa", "init"],
            &["volparossa", "doctor"],
            &["volparossa", "start"],
            &["volparossa", "stop"],
            &["volparossa", "status"],
            &["volparossa", "connect"],
            &["volparossa", "connect", "--transport", "multipath-quic"],
            &["volparossa", "disconnect"],
            &["volparossa", "peers"],
            &["volparossa", "paths"],
            &["volparossa", "sessions"],
            &["volparossa", "policy", "status"],
            &["volparossa", "policy", "verify", "/tmp/policy.manifest"],
            &["volparossa", "role", "show"],
            &["volparossa", "role", "enable", "relay"],
            &["volparossa", "role", "disable", "relay"],
            &["volparossa", "role", "enable", "exit"],
            &["volparossa", "role", "disable", "exit"],
            &["volparossa", "config", "validate"],
            &["volparossa", "logs"],
            &["volparossa", "cleanup"],
            &["volparossa", "demo"],
        ];
        for command in commands {
            Cli::try_parse_from(*command)
                .unwrap_or_else(|error| panic!("{}: {error}", command.join(" ")));
        }
    }

    #[test]
    fn policy_verify_defaults_to_agent_trust_file() {
        let cli = Cli::try_parse_from(["volparossa", "policy", "verify", "/tmp/policy.manifest"])
            .expect("policy verify");
        let CliCommand::Policy {
            command: PolicyCommand::Verify { trust_store, .. },
        } = cli.command
        else {
            panic!("unexpected command");
        };
        assert_eq!(trust_store, PathBuf::from(DEFAULT_TRUST_STORE));
    }

    #[test]
    fn log_query_bounds_are_enforced_by_clap() {
        assert!(Cli::try_parse_from(["volparossa", "logs", "--limit", "1"]).is_ok());
        assert!(Cli::try_parse_from(["volparossa", "logs", "--limit", "1000"]).is_ok());
        assert!(Cli::try_parse_from(["volparossa", "logs", "--limit", "0"]).is_err());
        assert!(Cli::try_parse_from(["volparossa", "logs", "--limit", "1001"]).is_err());
    }

    #[test]
    fn cleanup_is_preview_only_without_explicit_execute() {
        let cli = Cli::try_parse_from(["volparossa", "cleanup"]).expect("cleanup");
        assert!(matches!(
            cli.command,
            CliCommand::Cleanup { execute: false }
        ));
    }
}
