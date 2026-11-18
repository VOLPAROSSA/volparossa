//! Strict framing before upstream RSA-PSS/P-384 signature verification.

use sev::{
    certs::snp::{Certificate, Chain, Verifiable, builtin::milan, ca},
    firmware::guest::AttestationReport,
    parser::ByteParser,
};
use sha2::{Digest as _, Sha256};

use super::{
    EvidenceError, MAX_VCEK_BYTES, MilanTcb, REPORT_BYTES, SignatureFacts, cert_profile,
    endorsement,
};

/// Verify exact raw SNP v2 report and certificate signatures against the pinned
/// upstream Milan reference roots. No caller-supplied root is accepted.
///
/// This synchronous, size-bounded operation performs real cryptography but no
/// I/O, device access, time/appraisal decision or task release. An async caller
/// must schedule it under its own bounded CPU executor; it is not preemptible.
/// [`super::PendingSession`] additionally limits owner attempts and checks time
/// before and after this work.
///
/// # Errors
/// Rejects noncanonical/unsupported input and any failed signature. A successful
/// return still has all [`super::OutstandingAppraisal`] obligations outstanding.
pub fn verify_milan_v2_signature_facts(
    received: &[u8],
    vcek_der: &[u8],
) -> Result<SignatureFacts, EvidenceError> {
    let report = exact_report(received)?;
    if vcek_der.is_empty() || vcek_der.len() > MAX_VCEK_BYTES {
        return Err(EvidenceError::Encoding);
    }
    let vek = Certificate::from_der(vcek_der).map_err(|_| EvidenceError::Encoding)?;
    if vek.to_der().map_err(|_| EvidenceError::Encoding)? != vcek_der {
        return Err(EvidenceError::Encoding);
    }
    let chain = Chain {
        ca: ca::Chain {
            ark: milan::ark().map_err(|_| EvidenceError::Encoding)?,
            ask: milan::ask().map_err(|_| EvidenceError::Encoding)?,
        },
        vek,
    };
    // Upstream hashes its re-encoding; exact_report already proved byte equality.
    (&chain, &report)
        .verify()
        .map_err(|_| EvidenceError::Signature)?;
    // The upstream verifier performs the actual cryptography. Separately bind
    // the declared algorithms to that exact supported scheme before any facts.
    let leaf_certificate = chain.vek.clone().into();
    cert_profile::check_chain(
        &chain.ca.ark.clone().into(),
        &chain.ca.ask.clone().into(),
        &leaf_certificate,
    )?;
    // A signature alone does not bind the leaf's chip/firmware claims to the
    // signed report. Use REPORTED_TCB, the version that derives this VCEK.
    endorsement::check_claims(
        &leaf_certificate,
        received.try_into().map_err(|_| EvidenceError::Encoding)?,
    )?;
    Ok(SignatureFacts {
        report_sha256: Sha256::digest(received).into(),
        vcek_sha256: Sha256::digest(vcek_der).into(),
        measurement: report.measurement,
        report_data: report.report_data,
        guest_svn: report.guest_svn,
        guest_policy: u64::from_le_bytes(
            received[8..16]
                .try_into()
                .map_err(|_| EvidenceError::Encoding)?,
        ),
        // AMD 56860 legacy Milan layout: current/reported/committed/launch,
        // not a packed integer ordering and not an assumption of stage equality.
        tcb: [
            MilanTcb::from_report(&received[0x38..0x40])?,
            MilanTcb::from_report(&received[0x180..0x188])?,
            MilanTcb::from_report(&received[0x1e0..0x1e8])?,
            MilanTcb::from_report(&received[0x1f0..0x1f8])?,
        ],
        platform_smt_enabled: received[0x40] & 1 != 0,
        validity: [
            validity(chain.ca.ark),
            validity(chain.ca.ask),
            validity(chain.vek),
        ],
    })
}

fn validity(cert: Certificate) -> (u64, u64) {
    let cert: x509_cert::Certificate = cert.into();
    let validity = cert.tbs_certificate.validity;
    (
        validity.not_before.to_unix_duration().as_secs(),
        validity.not_after.to_unix_duration().as_secs(),
    )
}

pub(super) fn exact_report(received: &[u8]) -> Result<AttestationReport, EvidenceError> {
    if received.len() != REPORT_BYTES || received[..4] != 2_u32.to_le_bytes() {
        return Err(EvidenceError::Encoding);
    }
    let report = AttestationReport::from_bytes(received).map_err(|_| EvidenceError::Encoding)?;
    let policy = u64::from_le_bytes(
        received[8..16]
            .try_into()
            .map_err(|_| EvidenceError::Encoding)?,
    );
    let platform = u64::from_le_bytes(
        received[0x40..0x48]
            .try_into()
            .map_err(|_| EvidenceError::Encoding)?,
    );
    let key = u32::from_le_bytes(
        received[0x48..0x4c]
            .try_into()
            .map_err(|_| EvidenceError::Encoding)?,
    );
    // Restrict to the legacy Milan layout and VCEK, not masked-chip/VLEK/unsigned.
    // Version 2 has no CPUID product field; do not invent a stepping comparison.
    if report.vmpl != 0
        || report.sig_algo != 1
        || key & !1 != 0
        || policy & (1 << 17) == 0
        || policy & !0x1f_ffff != 0
        || platform & !0x1f != 0
        || report.current_tcb.fmc.is_some()
        || report.reported_tcb.fmc.is_some()
        || report.committed_tcb.fmc.is_some()
        || report.launch_tcb.fmc.is_some()
        || report.signature.r()[48..].iter().any(|byte| *byte != 0)
        || report.signature.s()[48..].iter().any(|byte| *byte != 0)
    {
        return Err(EvidenceError::Encoding);
    }
    // Also covers skipped reserved ranges, TCB padding, signature padding and
    // version-specific omitted fields. No authenticated received byte is ignored.
    if report
        .to_bytes()
        .map_err(|_| EvidenceError::Encoding)?
        .as_slice()
        != received
    {
        return Err(EvidenceError::Encoding);
    }
    Ok(report)
}
