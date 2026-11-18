//! Closed legacy Milan path profile, after actual signature verification.
//!
//! AMD 57230 tables 7–10 and RFC 5280 sections 4.2/6.1. This is not a
//! general-purpose PKIX builder: roots and intermediate are fixed, policies,
//! name constraints, alternate paths and unknown extensions are unsupported.

use x509_cert::{
    Certificate, Version,
    der::{Decode, Encode, asn1::OctetString},
    ext::{
        Extension,
        pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage},
    },
    name::Name,
    spki::ObjectIdentifier,
    time::Time,
};

use super::EvidenceError;

pub(super) const AKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const SKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const DISTRIBUTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
// DER of one complete, direct distribution point; not a URL to fetch at runtime.
const DISTRIBUTION_DER: &[u8] =
    b"\x30\x31\x30\x2f\xa0\x2d\xa0\x2b\x86\x29https://kdsintf.amd.com/vcek/v1/Milan/crl";

pub(super) fn check(
    root: &Certificate,
    intermediate: &Certificate,
    leaf: &Certificate,
) -> Result<(), EvidenceError> {
    for certificate in [root, intermediate, leaf] {
        let body = &certificate.tbs_certificate;
        if body.version != Version::V3
            || body.issuer_unique_id.is_some()
            || body.subject_unique_id.is_some()
            || body.subject.is_empty()
            || !canonical_time(body.validity.not_before)
            || !canonical_time(body.validity.not_after)
        {
            return Err(EvidenceError::Endorsement);
        }
    }
    if root.tbs_certificate.issuer != root.tbs_certificate.subject
        || intermediate.tbs_certificate.issuer != root.tbs_certificate.subject
        || leaf.tbs_certificate.issuer != intermediate.tbs_certificate.subject
        || leaf.tbs_certificate.serial_number.as_bytes() != [0]
        || leaf.tbs_certificate.subject
            != "CN=SEV-VCEK,O=Advanced Micro Devices,ST=CA,L=Santa Clara,C=US,OU=Engineering"
                .parse::<Name>()
                .map_err(|_| EvidenceError::Endorsement)?
    {
        return Err(EvidenceError::Endorsement);
    }
    let root_id = check_ca(root, false)?;
    check_ca(intermediate, true)?;
    let authority: AuthorityKeyIdentifier = decode(extension(intermediate, AKI, false)?)?;
    check_authority(&authority, &root_id)?;
    // The existing authenticated leaf-claim check admits exactly eleven AMD
    // extensions, all noncritical. In particular it cannot assert CA or certSign.
    // Later VCEK profiles with AKI/SKI require a separate reviewed extension.
    Ok(())
}

pub(super) fn canonical_time(time: Time) -> bool {
    match time {
        Time::UtcTime(_) => true,
        Time::GeneralTime(value) => value.to_date_time().year() >= 2050,
    }
}

fn check_ca(certificate: &Certificate, intermediate: bool) -> Result<Vec<u8>, EvidenceError> {
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(EvidenceError::Endorsement)?;
    let expected = if intermediate { 5 } else { 4 };
    if extensions.len() != expected || certificate.tbs_certificate.serial_number.as_bytes() == [0] {
        return Err(EvidenceError::Endorsement);
    }
    let constraints: BasicConstraints = decode(extension(certificate, CONSTRAINTS, true)?)?;
    if !constraints.ca
        || constraints.path_len_constraint != if intermediate { Some(0) } else { None }
    {
        return Err(EvidenceError::Endorsement);
    }
    let raw_usage = extension(certificate, USAGE, true)?.extn_value.as_bytes();
    // These are the exact signed encodings in the pinned legacy Milan CAs.
    // ASK retains a zero named bit: 03 02 01 04. KeyUsage re-encoding removes
    // it (03 02 02 04), so generic decode/re-encode equality rejects the vendor
    // certificate. Admit only its original bytes here, not arbitrary padding
    // or a normalized replacement. Other extensions retain canonical decoding.
    let expected_usage = if intermediate {
        [3, 2, 1, 4]
    } else {
        [3, 2, 1, 6]
    };
    if raw_usage != expected_usage {
        return Err(EvidenceError::Endorsement);
    }
    let usage = KeyUsage::from_der(raw_usage).map_err(|_| EvidenceError::Endorsement)?;
    let expected_bits = if intermediate {
        1 << 5
    } else {
        (1 << 5) | (1 << 6)
    };
    if usage.0.bits() != expected_bits {
        return Err(EvidenceError::Endorsement);
    }
    let identifier: OctetString = decode(extension(certificate, SKI, false)?)?;
    if identifier.as_bytes().len() != 20
        || extension(certificate, DISTRIBUTION, false)?
            .extn_value
            .as_bytes()
            != DISTRIBUTION_DER
    {
        return Err(EvidenceError::Endorsement);
    }
    // Required distinct extension count plus unique lookup rejects unknown and
    // duplicate extensions, including unhandled critical constraints.
    Ok(identifier.as_bytes().to_vec())
}

pub(super) fn root_identifier(root: &Certificate) -> Result<Vec<u8>, EvidenceError> {
    let identifier: OctetString = decode(extension(root, SKI, false)?)?;
    Ok(identifier.as_bytes().to_vec())
}

pub(super) fn check_authority(
    authority: &AuthorityKeyIdentifier,
    identifier: &[u8],
) -> Result<(), EvidenceError> {
    if authority.authority_cert_issuer.is_some()
        || authority.authority_cert_serial_number.is_some()
        || authority.key_identifier.as_ref().map(OctetString::as_bytes) != Some(identifier)
    {
        return Err(EvidenceError::Endorsement);
    }
    Ok(())
}

fn extension(
    certificate: &Certificate,
    oid: ObjectIdentifier,
    critical: bool,
) -> Result<&Extension, EvidenceError> {
    let mut matching = certificate
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|item| item.extn_id == oid);
    let found = matching.next().ok_or(EvidenceError::Endorsement)?;
    if found.critical != critical || matching.next().is_some() {
        return Err(EvidenceError::Endorsement);
    }
    Ok(found)
}

pub(super) fn decode<'a, T: Decode<'a> + Encode>(
    extension: &'a Extension,
) -> Result<T, EvidenceError> {
    let raw = extension.extn_value.as_bytes();
    let parsed = T::from_der(raw).map_err(|_| EvidenceError::Endorsement)?;
    if parsed.to_der().map_err(|_| EvidenceError::Endorsement)? != raw {
        return Err(EvidenceError::Endorsement);
    }
    Ok(parsed)
}
