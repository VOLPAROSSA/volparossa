//! Offline legacy Milan certificate path and complete ARK-issued CRL appraisal.
//!
//! AMD 57230 §2 and RFC 5280 §5/6.3. The CRL covers certificates issued by
//! ARK-Milan, notably the fixed ASK. It does NOT list individual ASK-issued
//! VCEKs; firmware vulnerability/TCB appraisal remains independently required.
//! Validity proves a currently usable supplied CRL, not that none newer exists.
//! No fetching, trust-store changes, private-key operation or worker permission.

use std::collections::BTreeSet;

use rsa::{
    RsaPublicKey,
    pss::{Signature, VerifyingKey},
    signature::Verifier as _,
    traits::PublicKeyParts as _,
};
use sev::certs::snp::builtin::milan;
use sha2::{Digest as _, Sha256, Sha384};
use x509_cert::{
    Certificate, Version,
    crl::CertificateList,
    der::{Decode as _, Encode as _, referenced::OwnedToRef as _},
    ext::{
        Extension,
        pkix::{AuthorityKeyIdentifier, crl::CrlReason},
    },
    spki::ObjectIdentifier,
};

use super::{
    EvidenceError, MAX_CRL_BYTES, SignatureFacts, cert_path, cert_profile,
    verify_milan_v2_signature_facts,
};

const NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.20");
const REASON: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.21");
const MAX_REVOKED: usize = 1024;

/// Verified full ARK-Milan CRL observation, scoped to the pinned ASK path.
/// No public constructor, deserializer or private hardware identifier.
pub struct VendorCrlFacts {
    pub(super) sha256: [u8; 32],
    pub(super) number: u64,
    pub(super) this_update: u64,
    pub(super) next_update: u64,
}

impl VendorCrlFacts {
    /// Digest of the actual signature-verified canonical DER CRL.
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    /// Vendor CRL number, not proof that a newer list does not exist.
    pub const fn number(&self) -> u64 {
        self.number
    }
    /// Signed lower validity bound in Unix seconds.
    pub const fn this_update(&self) -> u64 {
        self.this_update
    }
    /// Signed exclusive upper bound; evidence must not extend past it.
    pub const fn next_update(&self) -> u64 {
        self.next_update
    }

    pub(super) fn check_time(&self, now: u64) -> Result<(), EvidenceError> {
        if self.this_update >= self.next_update || now < self.this_update || now >= self.next_update
        {
            return Err(EvidenceError::Revocation);
        }
        Ok(())
    }
}

pub(super) fn verify(
    report: &[u8],
    vcek_der: &[u8],
    crl_der: &[u8],
    now: u64,
) -> Result<(SignatureFacts, VendorCrlFacts), EvidenceError> {
    // Bound all attacker-controlled inputs before expensive verification.
    let crl = parse_crl(crl_der)?;
    let facts = verify_milan_v2_signature_facts(report, vcek_der)?;
    facts.check_time(now)?;
    let root: Certificate = milan::ark().map_err(|_| EvidenceError::Encoding)?.into();
    let intermediate: Certificate = milan::ask().map_err(|_| EvidenceError::Encoding)?.into();
    let leaf = Certificate::from_der(vcek_der).map_err(|_| EvidenceError::Encoding)?;
    cert_path::check(&root, &intermediate, &leaf)?;
    // Keep the fixed 4096-bit key profile explicit, independent of signature API.
    public_key(&intermediate)?;
    let key = public_key(&root)?;
    let collateral = verify_crl(&root, &intermediate, key, &crl, crl_der, now)?;
    Ok((facts, collateral))
}

fn parse_crl(raw: &[u8]) -> Result<CertificateList, EvidenceError> {
    if raw.is_empty() || raw.len() > MAX_CRL_BYTES {
        return Err(EvidenceError::Encoding);
    }
    let crl = CertificateList::from_der(raw).map_err(|_| EvidenceError::Encoding)?;
    if crl.to_der().map_err(|_| EvidenceError::Encoding)? != raw {
        return Err(EvidenceError::Encoding);
    }
    Ok(crl)
}

fn public_key(certificate: &Certificate) -> Result<RsaPublicKey, EvidenceError> {
    let key = RsaPublicKey::try_from(
        certificate
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref(),
    )
    .map_err(|_| EvidenceError::Endorsement)?;
    if key.n().bits() != 4096 || key.e().to_bytes_be() != [1, 0, 1] {
        return Err(EvidenceError::Endorsement);
    }
    Ok(key)
}

fn verify_crl(
    root: &Certificate,
    intermediate: &Certificate,
    key: RsaPublicKey,
    crl: &CertificateList,
    raw: &[u8],
    now: u64,
) -> Result<VendorCrlFacts, EvidenceError> {
    cert_profile::check_signature_algorithm(
        &crl.signature_algorithm,
        &crl.tbs_cert_list.signature,
    )?;
    let bytes = crl.signature.as_bytes().ok_or(EvidenceError::Encoding)?;
    if bytes.len() != 512 {
        return Err(EvidenceError::Encoding);
    }
    let signature = Signature::try_from(bytes).map_err(|_| EvidenceError::Signature)?;
    let message = crl
        .tbs_cert_list
        .to_der()
        .map_err(|_| EvidenceError::Encoding)?;
    // Public-key PSS/SHA-384 only; the salt is fixed to the digest length (48).
    VerifyingKey::<Sha384>::new(key)
        .verify(&message, &signature)
        .map_err(|_| EvidenceError::Signature)?;
    let number = check_scope(root, intermediate, crl)?;
    let body = &crl.tbs_cert_list;
    let facts = VendorCrlFacts {
        sha256: Sha256::digest(raw).into(),
        number,
        this_update: body.this_update.to_unix_duration().as_secs(),
        next_update: body
            .next_update
            .ok_or(EvidenceError::Revocation)?
            .to_unix_duration()
            .as_secs(),
    };
    facts.check_time(now)?;
    Ok(facts)
}

fn check_scope(
    root: &Certificate,
    intermediate: &Certificate,
    crl: &CertificateList,
) -> Result<u64, EvidenceError> {
    let body = &crl.tbs_cert_list;
    if body.version != Version::V2
        || body.issuer != root.tbs_certificate.subject
        || !cert_path::canonical_time(body.this_update)
        || body
            .next_update
            .is_none_or(|time| !cert_path::canonical_time(time))
    {
        return Err(EvidenceError::Revocation);
    }
    // Closed complete/direct profile: no delta, indirect issuer, distribution-
    // point limitation, reason subset, critical extension or optional ignore path.
    let extensions = body
        .crl_extensions
        .as_deref()
        .ok_or(EvidenceError::Revocation)?;
    if extensions.len() != 2 {
        return Err(EvidenceError::Revocation);
    }
    let authority: AuthorityKeyIdentifier =
        cert_path::decode(crl_extension(extensions, cert_path::AKI)?)?;
    cert_path::check_authority(&authority, &cert_path::root_identifier(root)?)?;
    let number: u64 = cert_path::decode(crl_extension(extensions, NUMBER)?)?;
    check_entries(intermediate, crl)?;
    Ok(number)
}

fn crl_extension(
    extensions: &[Extension],
    oid: ObjectIdentifier,
) -> Result<&Extension, EvidenceError> {
    let mut matching = extensions.iter().filter(|item| item.extn_id == oid);
    let found = matching.next().ok_or(EvidenceError::Revocation)?;
    if found.critical || matching.next().is_some() {
        return Err(EvidenceError::Revocation);
    }
    Ok(found)
}

fn check_entries(intermediate: &Certificate, crl: &CertificateList) -> Result<(), EvidenceError> {
    let body = &crl.tbs_cert_list;
    let entries = body.revoked_certificates.as_deref().unwrap_or_default();
    if entries.len() > MAX_REVOKED
        || body
            .revoked_certificates
            .as_ref()
            .is_some_and(Vec::is_empty)
    {
        return Err(EvidenceError::Revocation);
    }
    let mut serials = BTreeSet::new();
    for entry in entries {
        let serial = entry.serial_number.as_bytes();
        if serial == [0]
            || !serials.insert(serial)
            || !cert_path::canonical_time(entry.revocation_date)
            || entry.revocation_date.to_unix_duration() > body.this_update.to_unix_duration()
        {
            return Err(EvidenceError::Revocation);
        }
        if let Some(extensions) = &entry.crl_entry_extensions {
            if extensions.len() != 1 {
                return Err(EvidenceError::Revocation);
            }
            let reason: CrlReason = cert_path::decode(crl_extension(extensions, REASON)?)?;
            // removeFromCRL belongs to a delta; it cannot clear a full-list entry.
            if reason == CrlReason::RemoveFromCRL {
                return Err(EvidenceError::Revocation);
            }
        }
        if entry.serial_number == intermediate.tbs_certificate.serial_number {
            return Err(EvidenceError::Revocation);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "collateral_tests.rs"]
mod tests;
