//! Explicit quote attachment, reference verification and optional key confirmation.
//! No private task, raw quote export, workload approval, or worker permit.

mod confirmation;

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use volparossa_content::provider::compute::{
    attestation::{
        LocalPolicy, MAX_CRL_BYTES, MAX_VCEK_BYTES, MilanTcb, OutstandingAppraisal, SessionLimits,
        SessionOwner, SmtPolicy, TcbMinimums,
    },
    guest::QuoteRequest,
    quote as wire,
};
use volparossa_local_control::{
    Empty, QuoteAttachRequest, QuoteReady, QuoteRemoteRequest, control_request::Operation,
    control_response::Payload,
};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Authorize one exact requester for finite quote attempts; enables no private work.
    Attach(Attach),
    /// Cancel quote authority, retained keys and pending work; preserve public compute.
    Detach,
    /// Exchange one fresh quote and check supplied legacy Milan collateral/local expectations.
    Verify(Verify),
}

#[derive(Debug, Args)]
pub(crate) struct Attach {
    #[arg(long)]
    bind: std::net::SocketAddr,
    #[arg(long)]
    advertised_hostname: String,
    /// Exact operator-approved requester identity, not merely a discovery hint.
    #[arg(long, value_parser = parse_key)]
    requester_key: VerifyingKey,
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=64))]
    max_attempts: u16,
    /// Explicitly permit the separate one-probe key-confirmation profile; no private work.
    #[arg(long)]
    key_confirmation_v1: bool,
}

#[derive(Debug, Args)]
pub(crate) struct Verify {
    #[arg(long, value_parser = parse_key)]
    provider_key: VerifyingKey,
    /// Strict JSON containing explicitly public local expectations, not private task hashes.
    #[arg(long)]
    public_policy: PathBuf,
    /// Supplied DER VCEK certificate; no network retrieval or root override.
    #[arg(long)]
    vcek: PathBuf,
    /// Supplied complete DER ARK CRL for ASK scope, not general VCEK revocation proof.
    #[arg(long)]
    vendor_crl: PathBuf,
    /// Require same-connection key possession after verifying the original quote.
    #[arg(long)]
    key_confirmation_v1: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicExpectations {
    version: u32,
    public_policy_id: String,
    expected_measurement: String,
    minimum_guest_svn: u32,
    minimum_tcb: Minimums,
    smt: Smt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Minimums {
    current: Tcb,
    reported: Tcb,
    committed: Tcb,
    launch: Tcb,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tcb {
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

impl Tcb {
    const fn components(self) -> MilanTcb {
        MilanTcb {
            bootloader: self.bootloader,
            tee: self.tee,
            snp: self.snp,
            microcode: self.microcode,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Smt {
    Allow,
    RequireDisabled,
}

impl PublicExpectations {
    fn decode(bytes: &[u8]) -> Result<([u8; 32], LocalPolicy)> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= 4096,
            "quote_public_policy_bound"
        );
        let policy: Self = serde_json::from_slice(bytes).context("quote_public_policy_encoding")?;
        ensure!(policy.version == 1, "quote_public_policy_version");
        let id = public_hex(&policy.public_policy_id)?;
        let measurement = public_hex(&policy.expected_measurement)?;
        let minima = policy.minimum_tcb;
        Ok((
            id,
            LocalPolicy::new(
                measurement,
                policy.minimum_guest_svn,
                TcbMinimums {
                    current: minima.current.components(),
                    reported: minima.reported.components(),
                    committed: minima.committed.components(),
                    launch: minima.launch.components(),
                },
                match policy.smt {
                    Smt::Allow => SmtPolicy::Allow,
                    Smt::RequireDisabled => SmtPolicy::RequireDisabled,
                },
            )?,
        ))
    }
}

fn public_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    ensure!(
        text.len() == N * 2
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "quote_public_hex"
    );
    let bytes: [u8; N] = hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("quote_public_hex"))?;
    ensure!(bytes != [0; N], "quote_public_hex_zero");
    Ok(bytes)
}

fn parse_key(text: &str) -> Result<VerifyingKey, String> {
    let bytes = public_hex(text)
        .map_err(|_| "quote identity must be a nonzero lowercase Ed25519 key".to_owned())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid Ed25519 quote identity".to_owned())
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(crate) async fn run(command: Command, socket: &Path) -> Result<()> {
    match command {
        Command::Attach(args) => {
            let expires_at = now()?
                .checked_add(u64::from(args.max_seconds))
                .context("quote_expiry_overflow")?;
            crate::print_response(
                crate::control::request(
                    socket,
                    Operation::QuoteAttach(QuoteAttachRequest {
                        bind_address: args.bind.to_string(),
                        advertised_hostname: args.advertised_hostname,
                        requester_key: args.requester_key.to_bytes().to_vec(),
                        expires_at,
                        maximum_attempts: u32::from(args.max_attempts),
                        confirmation_version: args.key_confirmation_v1.then_some(1),
                    }),
                )
                .await?,
            )
        }
        Command::Detach => crate::print_response(
            crate::control::request(socket, Operation::QuoteDetach(Empty {})).await?,
        ),
        Command::Verify(args) => {
            // Register signal listeners before preparation; cancellation closes this exact socket.
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let report = tokio::select! {
                result = timeout(Duration::from_secs(150), verify(&args, socket)) => result.context("quote_exchange_deadline")??,
                _ = interrupt.recv() => return Err(anyhow::anyhow!("quote_exchange_cancelled")),
                _ = terminate.recv() => return Err(anyhow::anyhow!("quote_exchange_cancelled")),
            };
            println!("{}", serde_json::to_string(&report)?);
            report.require_evidence()
        }
    }
}

#[derive(Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent closed evidence and authority claims are never inferred from one success flag"
)]
struct Report {
    version: u32,
    quote_exchange: bool,
    bound_reference_evidence: bool,
    complete_appraisal: bool,
    worker_admission: bool,
    private_input_released: bool,
    outstanding_appraisal: Vec<&'static str>,
}

/// Local projection of the agent-verified provider claim, not hardware evidence.
/// The legacy path cannot independently authenticate this projection. The opt-in
/// path also verifies the original signature but keeps this conservative report:
/// a provider signature binds a claim, not its truth.
#[derive(Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "The closed refusal explicitly denies evidence and execution authority"
)]
struct RefusalReport {
    version: u32,
    provider_claim: &'static str,
    provider_assertion_verified_by: &'static str,
    quote_exchange: bool,
    bound_reference_evidence: bool,
    complete_appraisal: bool,
    worker_admission: bool,
    private_input_released: bool,
}

impl RefusalReport {
    const fn device_unavailable() -> Self {
        Self {
            version: 2,
            provider_claim: "fixed_quote_device_unavailable",
            provider_assertion_verified_by: "local_agent",
            quote_exchange: false,
            bound_reference_evidence: false,
            complete_appraisal: false,
            worker_admission: false,
            private_input_released: false,
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum VerifyReport {
    Evidence(Report),
    Confirmed(confirmation::Report),
    ProviderRefusal(RefusalReport),
}

impl VerifyReport {
    fn require_evidence(&self) -> Result<()> {
        ensure!(
            matches!(self, Self::Evidence(_) | Self::Confirmed(_)),
            "quote_provider_reported_device_unavailable"
        );
        Ok(())
    }
}

fn check_terminal(
    outcome: &wire::QuoteOutcome,
    finished: &volparossa_local_control::ControlResponse,
) -> Result<()> {
    let expected = match outcome {
        wire::QuoteOutcome::Evidence(_) => "QUOTE_EXCHANGE_OK",
        wire::QuoteOutcome::DeviceUnavailable => "QUOTE_DEVICE_UNAVAILABLE",
    };
    ensure!(
        finished.diagnostic_code == expected && matches!(finished.payload, Some(Payload::Ack(_))),
        "quote_final_handoff"
    );
    Ok(())
}

fn check_ready(ready: &QuoteReady, provider: &VerifyingKey, confirmation: bool) -> Result<()> {
    ensure!(
        ready.provider_key == provider.as_bytes(),
        "quote_ready_provider"
    );
    ensure!(
        ready.confirmation_version == confirmation.then_some(1),
        "quote_ready_confirmation_version"
    );
    Ok(())
}

async fn verify(args: &Verify, socket: &Path) -> Result<VerifyReport> {
    let (policy_id, policy) =
        PublicExpectations::decode(&super::read_file(&args.public_policy, 4096)?)?;
    let vcek = super::read_file(&args.vcek, MAX_VCEK_BYTES as u64)?;
    let crl = super::read_file(&args.vendor_crl, MAX_CRL_BYTES as u64)?;
    ensure!(
        !vcek.is_empty() && !crl.is_empty(),
        "quote_collateral_empty"
    );
    let (mut stream, id, response) = crate::control::begin_request(
        socket,
        Operation::QuoteRemote(QuoteRemoteRequest {
            provider_key: args.provider_key.to_bytes().to_vec(),
            confirmation_version: args.key_confirmation_v1.then_some(1),
        }),
    )
    .await?;
    ensure!(
        response.diagnostic_code == "QUOTE_READY",
        "quote_ready_code"
    );
    let Some(Payload::QuoteReady(ready)) = response.payload else {
        anyhow::bail!("quote_ready_missing");
    };
    check_ready(&ready, &args.provider_key, args.key_confirmation_v1)?;
    // Route/TLS and provider authentication are ready. No long setup consumes this challenge.
    let owner = SessionOwner::new(
        policy_id,
        policy,
        SessionLimits {
            expires_at: now()?.checked_add(30).context("quote_expiry_overflow")?,
            maximum_pending: 1,
            maximum_attempts: 1,
        },
    )?;
    let pending = owner.begin()?;
    if args.key_confirmation_v1 {
        return confirmation::verify(&ready, pending, &mut stream, &id, &vcek, &crl).await;
    }
    let request = QuoteRequest::from_challenge(pending.challenge_bytes())?;
    wire::write_request(&mut stream, &request).await?;
    let outcome = wire::read_outcome(&mut stream, &request).await?;
    let finished = crate::control::finish_request(&mut stream, &id).await?;
    check_terminal(&outcome, &finished)?;
    drop(stream);
    let response = match outcome {
        wire::QuoteOutcome::Evidence(response) => response,
        wire::QuoteOutcome::DeviceUnavailable => {
            // The local agent verified the signed provider claim; the CLI has no
            // portable signature proof and cannot independently authenticate it.
            // Consume the original live challenge after the final ACK, without
            // accepting evidence or a key. The command still exits unsuccessfully.
            pending.finish_without_evidence()?;
            return Ok(VerifyReport::ProviderRefusal(
                RefusalReport::device_unavailable(),
            ));
        }
    };
    // One foreground CLI verification, never on the async reactor. Its borrowed one-use
    // pending owner remains in scope; real pre/post crypto checks enforce the same deadline.
    let bound = tokio::task::block_in_place(|| {
        pending.verify_and_bind(response.report(), &vcek, &crl, *response.public_key())
    })
    .context("quote_reference_evidence_rejected")?;
    Ok(VerifyReport::Evidence(Report {
        version: 1,
        quote_exchange: true,
        bound_reference_evidence: true,
        complete_appraisal: false,
        worker_admission: false,
        private_input_released: false,
        outstanding_appraisal: bound
            .outstanding_appraisal()
            .iter()
            .copied()
            .map(obligation)
            .collect(),
    }))
}

fn obligation(value: OutstandingAppraisal) -> &'static str {
    match value {
        OutstandingAppraisal::ProductionRootAuthorization => "production_root_authorization",
        OutstandingAppraisal::EndorsementProfileAndChipBinding => {
            "endorsement_profile_and_chip_binding"
        }
        OutstandingAppraisal::CurrentVendorRevocation => "current_vendor_revocation",
        OutstandingAppraisal::VcekRevocationAndCollateralFreshness => {
            "vcek_revocation_and_collateral_freshness"
        }
        OutstandingAppraisal::VendorTcbAndLocalPolicy => "vendor_tcb_and_local_policy",
        OutstandingAppraisal::AuthorizedWorkloadAndKeyOrigin => {
            "authorized_workload_and_key_origin"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(clap::Parser)]
    struct QuoteOptions {
        #[command(subcommand)]
        command: Command,
    }

    #[test]
    fn quote_cli_confirmation_flag_is_opt_in_at_both_endpoints() {
        use clap::Parser as _;

        let key = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[19; 32])
                .verifying_key()
                .to_bytes(),
        );
        for enabled in [false, true] {
            let mut verify = vec![
                "quote",
                "verify",
                "--provider-key",
                &key,
                "--public-policy",
                "policy.json",
                "--vcek",
                "vcek.der",
                "--vendor-crl",
                "crl.der",
            ];
            let mut attach = vec![
                "quote",
                "attach",
                "--bind",
                "127.0.0.1:8443",
                "--advertised-hostname",
                "provider.example",
                "--requester-key",
                &key,
                "--max-seconds",
                "30",
                "--max-attempts",
                "1",
            ];
            if enabled {
                verify.push("--key-confirmation-v1");
                attach.push("--key-confirmation-v1");
            }
            let Command::Verify(parsed) = QuoteOptions::try_parse_from(verify).unwrap().command
            else {
                panic!("verify command");
            };
            assert_eq!(parsed.key_confirmation_v1, enabled);
            let Command::Attach(parsed) = QuoteOptions::try_parse_from(attach).unwrap().command
            else {
                panic!("attach command");
            };
            assert_eq!(parsed.key_confirmation_v1, enabled);
        }
    }

    #[test]
    fn quote_cli_readiness_rejects_mode_downgrade_unsolicited_upgrade_and_substitution() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]).verifying_key();
        let mut ready = QuoteReady {
            provider_key: key.to_bytes().to_vec(),
            requester_key: vec![2; 32],
            confirmation_version: None,
        };
        for enabled in [false, true] {
            for version in [None, Some(0), Some(1), Some(2), Some(u32::MAX)] {
                ready.confirmation_version = version;
                assert_eq!(
                    check_ready(&ready, &key, enabled).is_ok(),
                    version == enabled.then_some(1)
                );
            }
        }
        ready.confirmation_version = Some(1);
        ready.provider_key = vec![2; 32];
        assert!(check_ready(&ready, &key, true).is_err());
    }

    fn policy() -> serde_json::Value {
        let tcb = serde_json::json!({"bootloader": 1, "tee": 2, "snp": 3, "microcode": 4});
        serde_json::json!({"version": 1, "public_policy_id": "11".repeat(32),
            "expected_measurement": "22".repeat(48), "minimum_guest_svn": 0,
            "minimum_tcb": {"current": tcb, "reported": tcb, "committed": tcb, "launch": tcb},
            "smt": "require_disabled"})
    }

    #[test]
    fn quote_cli_public_policy_has_no_defaults_and_checks_every_floor() {
        assert!(PublicExpectations::decode(&serde_json::to_vec(&policy()).unwrap()).is_ok());
        for name in ["current", "reported", "committed", "launch"] {
            let mut value = policy();
            value["minimum_tcb"][name]["bootloader"] = serde_json::json!(128);
            assert!(PublicExpectations::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        for field in ["minimum_guest_svn", "smt", "public_policy_id"] {
            let mut value = policy();
            value.as_object_mut().unwrap().remove(field);
            assert!(PublicExpectations::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut value = policy();
        value["production_root_authorized"] = serde_json::json!(true);
        assert!(PublicExpectations::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(PublicExpectations::decode(&vec![b' '; 4097]).is_err());
    }

    #[test]
    fn quote_cli_output_preserves_obligations_without_hardware_identifiers() {
        let report = VerifyReport::Evidence(Report {
            version: 1,
            quote_exchange: true,
            bound_reference_evidence: true,
            complete_appraisal: false,
            worker_admission: false,
            private_input_released: false,
            outstanding_appraisal: [
                OutstandingAppraisal::ProductionRootAuthorization,
                OutstandingAppraisal::VcekRevocationAndCollateralFreshness,
                OutstandingAppraisal::VendorTcbAndLocalPolicy,
                OutstandingAppraisal::AuthorizedWorkloadAndKeyOrigin,
            ]
            .into_iter()
            .map(obligation)
            .collect(),
        });
        assert!(report.require_evidence().is_ok());
        let encoded = serde_json::to_value(report).unwrap();
        assert_eq!(encoded.as_object().unwrap().len(), 7);
        assert_eq!(
            encoded["outstanding_appraisal"].as_array().unwrap().len(),
            4
        );
        assert_eq!(encoded["private_input_released"], false);
        for field in [
            "report",
            "public_key",
            "chip_id",
            "measurement",
            "transcript",
        ] {
            assert!(encoded.get(field).is_none());
        }
    }

    #[test]
    fn quote_cli_device_refusal_is_closed_and_cannot_report_success() {
        let refusal = VerifyReport::ProviderRefusal(RefusalReport::device_unavailable());
        assert!(refusal.require_evidence().is_err());
        assert_eq!(
            serde_json::to_value(&refusal).unwrap(),
            serde_json::json!({
                "version": 2,
                "provider_claim": "fixed_quote_device_unavailable",
                "provider_assertion_verified_by": "local_agent",
                "quote_exchange": false,
                "bound_reference_evidence": false,
                "complete_appraisal": false,
                "worker_admission": false,
                "private_input_released": false,
            })
        );
    }

    #[test]
    fn quote_cli_refusal_rejects_success_or_mismatched_terminal_messages() {
        use volparossa_local_control::{CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult};

        let outcome = wire::QuoteOutcome::DeviceUnavailable;
        let mut finished = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: vec![1; 16],
            result: ControlResult::Ok.into(),
            diagnostic_code: "QUOTE_DEVICE_UNAVAILABLE".into(),
            private_storage_remote_detail: None,
            payload: Some(Payload::Ack(Empty {})),
        };
        assert!(check_terminal(&outcome, &finished).is_ok());
        for code in ["QUOTE_EXCHANGE_OK", "QUOTE_READY", "", "UNAVAILABLE"] {
            finished.diagnostic_code = code.into();
            assert!(check_terminal(&outcome, &finished).is_err());
        }
        finished.diagnostic_code = "QUOTE_DEVICE_UNAVAILABLE".into();
        finished.payload = None;
        assert!(check_terminal(&outcome, &finished).is_err());
    }
}
