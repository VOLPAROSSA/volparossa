//! Narrow algorithm profile for the fixed Milan reference chain, not path appraisal.
//!
//! AMD 57230 rev. 1.05 tables 7-9 require PSS/SHA-384 and a P-384 VCEK.
//! RFC 5280 sections 4.1.1.2/4.1.2.3 bind the two signature identifiers;
//! RFC 4055 section 3 defines their parameters; RFC 5480 section 2 defines SPKI.
//! The supported PSS profile is SHA-384, MGF1/SHA-384, salt 48, trailer 1.
//! No certificate-path, revocation, root-authorization or release decision is made.

use x509_cert::{
    Certificate,
    der::{
        Decode as _, Reader as _, TagNumber,
        asn1::{ContextSpecific, Null},
    },
    spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef, ObjectIdentifier},
};

use super::EvidenceError;

const PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Private consistency check: success cannot construct facts or bypass signatures.
pub(super) fn check_chain(
    root: &Certificate,
    intermediate: &Certificate,
    leaf: &Certificate,
) -> Result<(), EvidenceError> {
    for certificate in [root, intermediate, leaf] {
        check_signature(certificate)?;
    }
    let spki = &leaf.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != EC
        || spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|value| value.decode_as::<ObjectIdentifier>().ok())
            != Some(P384)
    {
        return Err(EvidenceError::Endorsement);
    }
    // Retain the supported uncompressed SEC1 form. The existing cryptographic
    // verifier, not this shape check, must verify that this is a valid curve point.
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or(EvidenceError::Endorsement)?;
    if point.len() != 97 || point.first() != Some(&4) {
        return Err(EvidenceError::Endorsement);
    }
    Ok(())
}

fn check_signature(certificate: &Certificate) -> Result<(), EvidenceError> {
    check_signature_algorithm(
        &certificate.signature_algorithm,
        &certificate.tbs_certificate.signature,
    )
}

/// Used for certificates and CRLs; parsing never replaces actual verification.
pub(super) fn check_signature_algorithm(
    algorithm: &AlgorithmIdentifierOwned,
    inner: &AlgorithmIdentifierOwned,
) -> Result<(), EvidenceError> {
    if algorithm != inner || algorithm.oid != PSS {
        return Err(EvidenceError::Endorsement);
    }
    let parameters = algorithm
        .parameters
        .as_ref()
        .ok_or(EvidenceError::Endorsement)?;
    // Decode each field in order rather than decode_explicit, whose extension
    // semantics would skip earlier unknown/duplicate context-specific fields.
    let (hash, mask, salt, trailer) = parameters
        .sequence(|reader| {
            let hash = ContextSpecific::<AlgorithmIdentifierRef<'_>>::decode(reader)?;
            let mask = ContextSpecific::<AlgorithmIdentifierRef<'_>>::decode(reader)?;
            let salt = ContextSpecific::<u8>::decode(reader)?;
            let trailer = if reader.is_finished() {
                None
            } else {
                Some(ContextSpecific::<u8>::decode(reader)?)
            };
            Ok((hash, mask, salt, trailer))
        })
        .map_err(|_| EvidenceError::Endorsement)?;
    if hash.tag_number != TagNumber::N0
        || mask.tag_number != TagNumber::N1
        || salt.tag_number != TagNumber::N2
        || !sha384(hash.value)
        || mask.value.oid != MGF1
        || !mask.value.parameters.and_then(|value| value.decode_as().ok()).is_some_and(sha384)
        || salt.value != 48
        // RFC 4055 gives trailerField a default of 1; the public AMD reference
        // certificates encode 1 explicitly. Support both forms, never another value.
        || trailer.is_some_and(|value| value.tag_number != TagNumber::N3 || value.value != 1)
    {
        return Err(EvidenceError::Endorsement);
    }
    Ok(())
}

fn sha384(algorithm: AlgorithmIdentifierRef<'_>) -> bool {
    // RFC 4055 section 2.1 permits absent or NULL SHA-2 parameters.
    algorithm.oid == SHA384
        && algorithm
            .parameters
            .is_none_or(|value| value.decode_as::<Null>().is_ok())
}
