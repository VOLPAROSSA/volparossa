//! VOLPAROSSA user-facing command-line interface.

mod control;
mod doctor;
mod policy_bootstrap;
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
    /// Offline permanent-identity maintenance.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
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
    /// Generate a local 3-of-5 production policy and its private maintainer keys.
    BootstrapLocal {
        /// New absolute directory to publish; it and all output files must not exist.
        #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
        output_directory: PathBuf,
        /// Repeatable exact-domain rule: DOMAIN=tcp:PORT[,udp:PORT...].
        #[arg(long = "allow-domain", value_name = "RULE")]
        allow_domains: Vec<String>,
        /// Repeatable exact-IP rule: IP=tcp:PORT[,udp:PORT...].
        #[arg(long = "allow-ip", value_name = "RULE")]
        allow_ips: Vec<String>,
        /// Manifest lifetime in hours (1 through 168).
        #[arg(long, default_value_t = 24, value_parser = clap::value_parser!(u16).range(1..=168))]
        lifetime_hours: u16,
    },
}

#[derive(Debug, Subcommand)]
enum RoleCommand {
    /// Show role state.
    Show,
    /// Request a role change; participation prerequisites and restart requirements apply.
    Enable { role: ConfigurableRole },
    /// Request a role disable; apply effective changes through configuration and restart.
    Disable { role: ConfigurableRole },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ConfigurableRole {
    Client,
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

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    /// Replace the permanent Ed25519 identity while all services are stopped.
    Rotate {
        /// Exact encrypted identity file path; defaults below the state directory.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Strict 0600 file containing the current passphrase; otherwise prompt without echo.
        #[arg(long, value_name = "FILE")]
        current_passphrase_file: Option<PathBuf>,
        /// Strict 0600 file containing the new passphrase; otherwise prompt twice without echo.
        #[arg(long, value_name = "FILE")]
        new_passphrase_file: Option<PathBuf>,
    },
    /// Re-encrypt the same permanent identity while all services are stopped.
    ChangePassphrase {
        /// Exact encrypted identity file path; defaults below the state directory.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Strict 0600 file containing the current passphrase; otherwise prompt without echo.
        #[arg(long, value_name = "FILE")]
        current_passphrase_file: Option<PathBuf>,
        /// Strict 0600 file containing the new passphrase; otherwise prompt twice without echo.
        #[arg(long, value_name = "FILE")]
        new_passphrase_file: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityMutation {
    Rotate,
    ChangePassphrase,
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
        CliCommand::Identity { command } => maintain_identity_command(command).await,
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
        CliCommand::Policy { command } => {
            run_policy_command(command, &cli.config, &cli.control_socket).await
        }
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

async fn run_policy_command(command: PolicyCommand, config: &Path, socket: &Path) -> Result<()> {
    match command {
        PolicyCommand::Status => {
            let response = control::request(socket, Operation::PolicyStatus(Empty {})).await?;
            print_response(response)
        }
        PolicyCommand::Verify { file, trust_store } => verify_policy(config, &file, &trust_store),
        PolicyCommand::BootstrapLocal {
            output_directory,
            allow_domains,
            allow_ips,
            lifetime_hours,
        } => {
            let output = policy_bootstrap::bootstrap_local(
                &output_directory,
                &allow_domains,
                &allow_ips,
                lifetime_hours,
            )?;
            println!("policy manifest: {}", output.manifest.display());
            println!("production trust store: {}", output.trust_store.display());
            println!("local maintainer keys: {}", output.keys_directory.display());
            println!(
                "warning: all five production-labeled maintainer keys are co-located for this personal alpha; separate them before operational use"
            );
            println!(
                "configuration: set runtime_mode: production, policy.manifest_path: \"{}\", and policy.minimum_signatures: 3",
                output.manifest.display()
            );
            println!(
                "trust placement: policy-maintainers.json must be beside the active config file; using {}/config.yaml satisfies that layout",
                output_directory.display()
            );
            Ok(())
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

async fn maintain_identity_command(command: IdentityCommand) -> Result<()> {
    let (mutation, identity, current_passphrase_file, new_passphrase_file) = match command {
        IdentityCommand::Rotate {
            identity,
            current_passphrase_file,
            new_passphrase_file,
        } => (
            IdentityMutation::Rotate,
            identity,
            current_passphrase_file,
            new_passphrase_file,
        ),
        IdentityCommand::ChangePassphrase {
            identity,
            current_passphrase_file,
            new_passphrase_file,
        } => (
            IdentityMutation::ChangePassphrase,
            identity,
            current_passphrase_file,
            new_passphrase_file,
        ),
    };
    maintain_identity(
        mutation,
        identity,
        current_passphrase_file.as_deref(),
        new_passphrase_file.as_deref(),
    )
    .await
}

async fn maintain_identity(
    mutation: IdentityMutation,
    identity: Option<PathBuf>,
    current_passphrase_file: Option<&Path>,
    new_passphrase_file: Option<&Path>,
) -> Result<()> {
    // Check both before and after interactive input so a service start while the
    // operator is at a prompt cannot silently produce a split-brain identity.
    ensure_identity_services_stopped().await?;
    let current_passphrase = secret::read_passphrase_with_prompts(
        current_passphrase_file,
        "Current VOLPAROSSA identity passphrase: ",
        None,
    )?;
    let new_passphrase = secret::read_passphrase_with_prompts(
        new_passphrase_file,
        "New VOLPAROSSA identity passphrase: ",
        Some("Repeat new VOLPAROSSA identity passphrase: "),
    )?;
    ensure_identity_services_stopped().await?;

    let path = identity.unwrap_or_else(default_identity_path);
    let maintained =
        apply_identity_mutation(mutation, &path, &current_passphrase, &new_passphrase)?;
    match mutation {
        IdentityMutation::Rotate => {
            println!("identity rotated atomically: {}", path.display());
            println!("new peer ID: {}", maintained.peer_id());
            println!(
                "services remain stopped; previously signed advertisements expire at their embedded TTL"
            );
            println!(
                "before restart, update the packaged identity-passphrase systemd credential to the new passphrase"
            );
        }
        IdentityMutation::ChangePassphrase => {
            println!("identity passphrase changed atomically: {}", path.display());
            println!("peer ID unchanged: {}", maintained.peer_id());
            println!("services remain stopped");
            println!(
                "before restart, update the packaged identity-passphrase systemd credential to the new passphrase"
            );
        }
    }
    Ok(())
}

fn apply_identity_mutation(
    mutation: IdentityMutation,
    path: &Path,
    current_passphrase: &volparossa_identity::Passphrase,
    new_passphrase: &volparossa_identity::Passphrase,
) -> Result<volparossa_identity::Identity> {
    let store = IdentityStore::new(path);
    match mutation {
        IdentityMutation::Rotate => store.rotate(current_passphrase, new_passphrase),
        IdentityMutation::ChangePassphrase => {
            store.change_passphrase(current_passphrase, new_passphrase)
        }
    }
    .context("identity maintenance failed")
}

async fn ensure_identity_services_stopped() -> Result<()> {
    for service in SERVICES {
        let output = ProcessCommand::new("systemctl")
            .args(["show", "--property=ActiveState", "--value", service])
            .output()
            .await
            .with_context(|| format!("cannot inspect {service}; identity maintenance refused"))?;
        if !output.status.success() {
            bail!(
                "cannot prove {service} is stopped; identity maintenance refused (run `volparossa stop` first)"
            );
        }
        let state = std::str::from_utf8(&output.stdout)
            .with_context(|| format!("{service} returned a non-UTF-8 active state"))?;
        require_stopped_service_state(service, state)?;
    }
    Ok(())
}

fn require_stopped_service_state(service: &str, state: &str) -> Result<()> {
    let mut states = state.lines();
    let state = states.next().unwrap_or_default().trim();
    if states.next().is_some() || state.is_empty() {
        bail!("cannot prove {service} is stopped; identity maintenance refused");
    }
    if matches!(state, "inactive" | "failed") {
        return Ok(());
    }
    bail!(
        "{service} is {state}; identity maintenance requires every VOLPAROSSA service to be stopped (run `volparossa stop` first)"
    )
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

async fn set_role(socket: &Path, role: ConfigurableRole, enabled: bool) -> Result<()> {
    let role = match role {
        ConfigurableRole::Client => NodeRole::Client,
        ConfigurableRole::Relay => NodeRole::Relay,
        ConfigurableRole::Exit => NodeRole::Exit,
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
    use std::{io::Write, os::unix::fs::OpenOptionsExt};

    #[test]
    fn default_identity_uses_state_directory_override() {
        // The pure fallback is stable; environment mutation is intentionally avoided in tests.
        assert!(default_identity_path().ends_with("identity.key"));
    }
    #[test]
    fn every_cli_command_form_parses() {
        let commands: &[&[&str]] = &[
            &["volparossa", "init"],
            &["volparossa", "identity", "rotate"],
            &["volparossa", "identity", "change-passphrase"],
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
            &[
                "volparossa",
                "policy",
                "bootstrap-local",
                "--output-directory",
                "/tmp/local-policy",
                "--allow-domain",
                "example.com=tcp:443,udp:443",
                "--allow-ip",
                "93.184.216.34=tcp:8443",
            ],
            &["volparossa", "role", "show"],
            &["volparossa", "role", "enable", "client"],
            &["volparossa", "role", "disable", "client"],
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
    fn policy_bootstrap_parses_repeatable_exact_rules_and_bounded_lifetime() {
        let cli = Cli::try_parse_from([
            "volparossa",
            "policy",
            "bootstrap-local",
            "--output-directory",
            "/etc/volparossa/local-policy",
            "--allow-domain",
            "example.com=tcp:443",
            "--allow-domain",
            "example.net=udp:443",
            "--lifetime-hours",
            "12",
        ])
        .expect("policy bootstrap");
        let CliCommand::Policy {
            command:
                PolicyCommand::BootstrapLocal {
                    output_directory,
                    allow_domains,
                    allow_ips,
                    lifetime_hours,
                },
        } = cli.command
        else {
            panic!("unexpected command");
        };
        assert_eq!(
            output_directory,
            PathBuf::from("/etc/volparossa/local-policy")
        );
        assert_eq!(allow_domains.len(), 2);
        assert!(allow_ips.is_empty());
        assert_eq!(lifetime_hours, 12);
        assert!(
            Cli::try_parse_from([
                "volparossa",
                "policy",
                "bootstrap-local",
                "--output-directory",
                "/tmp/policy",
                "--lifetime-hours",
                "169",
            ])
            .is_err()
        );
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

    #[test]
    fn identity_maintenance_parses_exact_paths_and_separate_secret_files() {
        let cli = Cli::try_parse_from([
            "volparossa",
            "identity",
            "rotate",
            "--identity",
            "/var/lib/volparossa/custom.key",
            "--current-passphrase-file",
            "/run/secrets/current",
            "--new-passphrase-file",
            "/run/secrets/new",
        ])
        .expect("identity rotate");
        let CliCommand::Identity {
            command:
                IdentityCommand::Rotate {
                    identity,
                    current_passphrase_file,
                    new_passphrase_file,
                },
        } = cli.command
        else {
            panic!("unexpected command");
        };
        assert_eq!(
            identity,
            Some(PathBuf::from("/var/lib/volparossa/custom.key"))
        );
        assert_eq!(
            current_passphrase_file,
            Some(PathBuf::from("/run/secrets/current"))
        );
        assert_eq!(new_passphrase_file, Some(PathBuf::from("/run/secrets/new")));
    }

    #[test]
    fn identity_maintenance_accepts_only_definitively_stopped_services() {
        assert!(require_stopped_service_state("agent", "inactive\n").is_ok());
        assert!(require_stopped_service_state("agent", "failed\n").is_ok());
        for unsafe_state in [
            "active\n",
            "activating\n",
            "deactivating\n",
            "reloading\n",
            "maintenance\n",
            "unknown\n",
            "",
            "inactive\nactive\n",
        ] {
            assert!(
                require_stopped_service_state("agent", unsafe_state).is_err(),
                "unexpectedly accepted {unsafe_state:?}"
            );
        }
    }

    #[test]
    fn identity_maintenance_changes_passphrase_and_rotates_via_strict_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let identity_path = directory.path().join("identity.key");
        let current = volparossa_identity::Passphrase::new("current-passphrase-123")
            .expect("current passphrase");
        let original = IdentityStore::new(&identity_path)
            .create(&current)
            .expect("initial identity");
        let original_peer_id = *original.peer_id();

        let current_path = private_secret(directory.path(), "current", b"current-passphrase-123\n");
        let changed_path = private_secret(directory.path(), "changed", b"changed-passphrase-456\n");
        let current_from_file =
            secret::read_passphrase_with_prompts(Some(&current_path), "unused", Some("unused"))
                .expect("current secret file");
        let changed_from_file =
            secret::read_passphrase_with_prompts(Some(&changed_path), "unused", Some("unused"))
                .expect("changed secret file");
        let unchanged = apply_identity_mutation(
            IdentityMutation::ChangePassphrase,
            &identity_path,
            &current_from_file,
            &changed_from_file,
        )
        .expect("change passphrase");
        assert_eq!(*unchanged.peer_id(), original_peer_id);
        assert!(IdentityStore::new(&identity_path).load(&current).is_err());
        assert_eq!(
            *IdentityStore::new(&identity_path)
                .load(&changed_from_file)
                .expect("changed passphrase loads")
                .peer_id(),
            original_peer_id
        );

        let rotated_path = private_secret(directory.path(), "rotated", b"rotated-passphrase-789\n");
        let rotated_from_file =
            secret::read_passphrase_with_prompts(Some(&rotated_path), "unused", Some("unused"))
                .expect("rotated secret file");
        let rotated = apply_identity_mutation(
            IdentityMutation::Rotate,
            &identity_path,
            &changed_from_file,
            &rotated_from_file,
        )
        .expect("rotate identity");
        assert_ne!(*rotated.peer_id(), original_peer_id);
        assert_eq!(
            *IdentityStore::new(&identity_path)
                .load(&rotated_from_file)
                .expect("rotated identity loads")
                .peer_id(),
            *rotated.peer_id()
        );
    }

    fn private_secret(directory: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = directory.join(name);
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .expect("create private secret");
        file.write_all(contents).expect("write private secret");
        file.sync_all().expect("sync private secret");
        path
    }
}
