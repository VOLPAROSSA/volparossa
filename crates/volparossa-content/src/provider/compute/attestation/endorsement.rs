//! Bind authenticated Milan VCEK claims to the exact report, not to a KDS URL.
//!
//! AMD 57230 revision 1.05, section 3.1/table 10 and section 4.1 define
//! these extension encodings and SPL ranges. Hardware ID is 64 raw octets in
//! extnValue, not a second DER OCTET STRING. Report v2 has no CPUID stepping;
//! the product claim is checked against the fixed Milan chain/profile only.
//! This is not full certificate-path, revocation or current-TCB appraisal.

use x509_cert::{
    Certificate,
    der::{Decode, asn1::Ia5StringRef},
    spki::ObjectIdentifier,
};

use super::{EvidenceError, REPORT_BYTES};

const VERSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.1");
const PRODUCT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.2");
const HWID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.4");
// Array order is report TCB byte order, NOT numeric extension suffix order.
const SPL: [ObjectIdentifier; 8] = [
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.1"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.2"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.4"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.5"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.6"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.7"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.3"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.8"),
];

/// Only the already signature-verified, size-bounded caller may produce facts.
/// Keeping this function private prevents parse-only checks becoming authority.
pub(super) fn check_claims(
    certificate: &Certificate,
    report: &[u8; REPORT_BYTES],
) -> Result<(), EvidenceError> {
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(EvidenceError::Endorsement)?;
    // Narrow supported leaf profile: exactly the eleven mandatory AMD claims.
    // Additional extensions need explicit profile review, never silent ignoring.
    if extensions.len() != 11 {
        return Err(EvidenceError::Endorsement);
    }
    let mut seen = [false; 11];
    for extension in extensions {
        let oid = extension.extn_id;
        let index = if oid == VERSION {
            0
        } else if oid == PRODUCT {
            1
        } else if oid == HWID {
            2
        } else {
            3 + SPL
                .iter()
                .position(|candidate| *candidate == oid)
                .ok_or(EvidenceError::Endorsement)?
        };
        if extension.critical || std::mem::replace(&mut seen[index], true) {
            return Err(EvidenceError::Endorsement);
        }
        let raw = extension.extn_value.as_bytes();
        let matches = match index {
            0 => u8::from_der(raw).map_err(|_| EvidenceError::Endorsement)? == 0,
            1 => {
                let product =
                    Ia5StringRef::from_der(raw).map_err(|_| EvidenceError::Endorsement)?;
                let bytes = product.as_bytes();
                bytes.len() == 8
                    && bytes.starts_with(b"Milan-")
                    && bytes[6].is_ascii_uppercase()
                    && bytes[7].is_ascii_digit()
            }
            2 => raw == &report[0x1a0..0x1e0],
            _ => {
                let position = index - 3;
                let value = u8::from_der(raw).map_err(|_| EvidenceError::Endorsement)?;
                let allowed = match position {
                    2..=5 => value == 0,
                    7 => true,
                    _ => value <= 127,
                };
                allowed && value == report[0x180 + position]
            }
        };
        if !matches {
            return Err(EvidenceError::Endorsement);
        }
    }
    if seen.iter().any(|present| !present) {
        return Err(EvidenceError::Endorsement);
    }
    Ok(())
}
