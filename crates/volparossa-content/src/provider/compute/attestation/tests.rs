//! Public signed fixtures test cryptography. Synthetic facts below test only
//! deterministic owner/binding state; they are never available to production.

use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use x509_cert::{
    Certificate as X509Certificate,
    der::{
        Decode as _, Encode as _, Tag, TagMode, TagNumber,
        asn1::{Any, BitString, ContextSpecific, OctetString},
    },
    ext::Extension,
    spki::{AlgorithmIdentifierOwned, ObjectIdentifier},
};

use super::{session::Stamp, *};

const REPORT_HEX: &[u8] = include_bytes!("../../../../tests/fixtures/snp/report_milan.hex");
const VCEK: &[u8] = include_bytes!("../../../../tests/fixtures/snp/vcek_milan.der");
const NOW: u64 = 1_800_000_000;

// Synthetic state-only collateral. This is not an AMD signature or revocation proof.
fn synthetic_collateral() -> VendorCrlFacts {
    VendorCrlFacts {
        sha256: [7; 32],
        number: 0,
        this_update: NOW - 1,
        next_update: NOW + 600,
    }
}

fn report() -> Vec<u8> {
    hex::decode(REPORT_HEX).unwrap()
}

fn limits(attempts: u16, pending: u8) -> SessionLimits {
    SessionLimits {
        expires_at: NOW + 120,
        maximum_pending: pending,
        maximum_attempts: attempts,
    }
}

fn stamp(at: Instant, seconds: u64) -> Stamp {
    Stamp {
        unix: NOW + seconds,
        monotonic: at + Duration::from_secs(seconds),
    }
}

fn owner(at: Instant, attempts: u16, pending: u8) -> SessionOwner {
    SessionOwner::new_at(
        [1; 32],
        test_policy([2; 48], 1),
        limits(attempts, pending),
        stamp(at, 0),
    )
    .unwrap()
}

// Test-only construction exercises binding without claiming a new signed report.
// There is no cfg(test) feature or constructor reachable from the public library.
fn synthetic_binding_facts(pending: &PendingSession<'_>, key: &[u8; 32]) -> SignatureFacts {
    SignatureFacts {
        report_sha256: [3; 32],
        vcek_sha256: [4; 32],
        measurement: [2; 48],
        report_data: session_report_data(pending.challenge_bytes(), key).unwrap(),
        guest_svn: 1,
        guest_policy: 1 << 17,
        tcb: [fixture_tcb(); 4],
        platform_smt_enabled: false,
        validity: [(NOW - 10, NOW + 1000); 3],
    }
}

#[test]
fn upstream_public_fixtures_and_reference_roots_match_source_pins() {
    use sev::certs::snp::builtin::milan;
    for (bytes, expected) in [
        (
            REPORT_HEX,
            "3d956e9104969a038031a6b63dd6c4b60000619d37702065994f7da76f88ae7d",
        ),
        (
            VCEK,
            "3bbfb6ee259f75a95d13168cfdf2e034181bb93c7c016825731cbe8ea16c95e1",
        ),
        (
            milan::ARK,
            "8c109952166431ffad8cb9a3d54f3d20ffbbb58164f0d54be3457bf0ece9e0d8",
        ),
        (
            milan::ASK,
            "8da3a65af1cb7cb90a21fac78431a2431a9ee7811f48c36569c53fb80ad31fee",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(bytes)), expected);
    }
}

#[test]
fn real_public_signatures_return_only_incomplete_facts() {
    let bytes = report();
    let facts = verify_milan_v2_signature_facts(&bytes, VCEK).unwrap();
    assert_eq!(
        facts.report_sha256(),
        &<[u8; 32]>::from(Sha256::digest(&bytes))
    );
    assert_eq!(facts.vcek_sha256(), &<[u8; 32]>::from(Sha256::digest(VCEK)));
    assert_eq!(facts.measurement(), &bytes[0x90..0xc0]);
    assert_eq!(facts.outstanding_appraisal(), &OUTSTANDING);
    assert!(
        facts
            .outstanding_appraisal()
            .contains(&OutstandingAppraisal::CurrentVendorRevocation)
    );
}

fn public_vcek() -> X509Certificate {
    X509Certificate::from_der(VCEK).unwrap()
}

fn certificate_profile(certificate: &X509Certificate) -> Result<(), EvidenceError> {
    use sev::certs::snp::builtin::milan;
    cert_profile::check_chain(
        &milan::ark().unwrap().into(),
        &milan::ask().unwrap().into(),
        certificate,
    )
}

// Synthetic ASN.1 structures below test only the private profile predicate.
// Their edited TBS bytes have NOT been signed and cannot authenticate anything.
fn public_pss_fields() -> Vec<ContextSpecific<Any>> {
    public_vcek()
        .signature_algorithm
        .parameters
        .unwrap()
        .sequence(|reader| {
            (0..4)
                .map(|_| ContextSpecific::<Any>::decode(reader))
                .collect()
        })
        .unwrap()
}

fn pss_parameters(fields: &[ContextSpecific<Any>]) -> Any {
    let bytes: Vec<u8> = fields
        .iter()
        .flat_map(|field| field.to_der().unwrap())
        .collect();
    Any::new(Tag::Sequence, bytes).unwrap()
}

fn encoded_any(value: &impl x509_cert::der::Encode) -> Any {
    Any::from_der(&value.to_der().unwrap()).unwrap()
}

fn synthetic_profile(parameters: Option<Any>) -> Result<(), EvidenceError> {
    let mut certificate = public_vcek();
    certificate.signature_algorithm.parameters = parameters;
    certificate.tbs_certificate.signature = certificate.signature_algorithm.clone();
    certificate_profile(&certificate)
}

#[test]
fn certificate_profile_public_chain_and_report_keep_incomplete_facts() {
    use sev::certs::snp::builtin::milan;
    let root = milan::ark().unwrap().into();
    let intermediate = milan::ask().unwrap().into();
    assert_eq!(
        cert_profile::check_chain(&root, &intermediate, &public_vcek()),
        Ok(())
    );
    let facts = verify_milan_v2_signature_facts(&report(), VCEK).unwrap();
    assert_eq!(facts.outstanding_appraisal(), &OUTSTANDING);
    assert_eq!(facts.outstanding_appraisal().len(), 5);
    // Apply the algorithm check to both fixed roots, not only the leaf.
    for position in 0..2 {
        let mut roots = [root.clone(), intermediate.clone()];
        roots[position].signature_algorithm.parameters = None;
        assert_eq!(
            cert_profile::check_chain(&roots[0], &roots[1], &public_vcek()),
            Err(EvidenceError::Endorsement)
        );
    }
}

#[test]
fn certificate_profile_outer_algorithm_mutations_are_rejected_with_signed_bytes_unchanged() {
    use sev::certs::snp::{Certificate, Chain, Verifiable, builtin::milan, ca};
    let original = public_vcek();
    let raw = report();
    for mutation in 0..5 {
        let mut certificate = original.clone();
        let mut fields = public_pss_fields();
        match mutation {
            0 => fields[2].value = encoded_any(&47_u8),
            1 => fields[3].value = encoded_any(&0_u8),
            2 => {
                let mut hash = fields[0]
                    .value
                    .decode_as::<AlgorithmIdentifierOwned>()
                    .unwrap();
                hash.oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
                fields[0].value = encoded_any(&hash);
            }
            3 => fields[1].value = fields[0].value.clone(),
            _ => {}
        }
        certificate.signature_algorithm.parameters =
            (mutation != 4).then(|| pss_parameters(&fields));
        assert!(
            certificate.tbs_certificate.to_der().unwrap()
                == original.tbs_certificate.to_der().unwrap()
        );
        assert!(certificate.signature == original.signature);
        let der = certificate.to_der().unwrap();
        let chain = Chain {
            ca: ca::Chain {
                ark: milan::ark().unwrap(),
                ask: milan::ask().unwrap(),
            },
            vek: Certificate::from_der(&der).unwrap(),
        };
        // Actual public signatures still verify: the pinned verifier uses its
        // fixed scheme without checking these outer parameter declarations.
        assert!((&chain, &snp::exact_report(&raw).unwrap()).verify().is_ok());
        assert_eq!(
            verify_milan_v2_signature_facts(&raw, &der).err(),
            Some(EvidenceError::Endorsement)
        );
    }
}

fn synthetic_pss_mutation(mutation: u8) -> Any {
    let mut changed = public_pss_fields();
    match mutation {
        0 => changed[0].tag_number = TagNumber::N1,
        1 => changed.swap(0, 1),
        2 => changed.insert(1, changed[0].clone()),
        3 => changed.push(changed[3].clone()),
        4 => {
            changed.pop();
            changed.pop();
        }
        5 => changed[2].value = encoded_any(&47_u8),
        6 => changed[2].value = encoded_any(&49_u8),
        7 => changed[2].value = encoded_any(&256_u16),
        8 => changed[3].value = encoded_any(&0_u8),
        9 => changed[3].value = encoded_any(&2_u8),
        10 => changed[3].tag_number = TagNumber::N4,
        11 => changed[2].value = encoded_any(&OctetString::new([48]).unwrap()),
        19 => changed[0].tag_mode = TagMode::Implicit,
        20 => changed[2].tag_mode = TagMode::Implicit,
        21 => {
            let mut extra = changed[3].clone();
            extra.tag_number = TagNumber::N4;
            changed.push(extra);
        }
        22 => changed[2].value = Any::new(Tag::Integer, [0, 48]).unwrap(),
        23 => changed[2].value = Any::new(Tag::Integer, [255]).unwrap(),
        index => {
            let target = usize::from(index >= 14);
            let mut algorithm = changed[target]
                .value
                .decode_as::<AlgorithmIdentifierOwned>()
                .unwrap();
            match index {
                12 | 14 => algorithm.oid = ObjectIdentifier::new_unwrap("1.2.3.4"),
                13 | 16 => algorithm.parameters = Some(encoded_any(&0_u8)),
                15 => algorithm.parameters = None,
                _ => {
                    let mut hash = algorithm
                        .parameters
                        .unwrap()
                        .decode_as::<AlgorithmIdentifierOwned>()
                        .unwrap();
                    if index == 17 {
                        hash.oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
                    } else {
                        hash.parameters = Some(encoded_any(&0_u8));
                    }
                    algorithm.parameters = Some(encoded_any(&hash));
                }
            }
            changed[target].value = encoded_any(&algorithm);
        }
    }
    pss_parameters(&changed)
}

#[test]
fn certificate_profile_synthetic_pss_parameters_are_closed() {
    let fields = public_pss_fields();
    assert_eq!(synthetic_profile(Some(pss_parameters(&fields))), Ok(()));
    // Explicit trailer 1 and the ASN.1 default 1 are the same supported profile.
    assert_eq!(
        synthetic_profile(Some(pss_parameters(&fields[..3]))),
        Ok(())
    );
    for target in 0..2 {
        let mut changed = fields.clone();
        let mut algorithm = changed[target]
            .value
            .decode_as::<AlgorithmIdentifierOwned>()
            .unwrap();
        if target == 0 {
            algorithm.parameters = None;
        } else {
            let mut hash = algorithm
                .parameters
                .unwrap()
                .decode_as::<AlgorithmIdentifierOwned>()
                .unwrap();
            hash.parameters = None;
            algorithm.parameters = Some(encoded_any(&hash));
        }
        changed[target].value = encoded_any(&algorithm);
        assert_eq!(synthetic_profile(Some(pss_parameters(&changed))), Ok(()));
    }
    for mutation in 0..24 {
        assert_eq!(
            synthetic_profile(Some(synthetic_pss_mutation(mutation))),
            Err(EvidenceError::Endorsement)
        );
    }
    for parameters in [None, Some(encoded_any(&0_u8)), Some(pss_parameters(&[]))] {
        assert_eq!(
            synthetic_profile(parameters),
            Err(EvidenceError::Endorsement)
        );
    }
    let mut trailing = pss_parameters(&fields).value().to_vec();
    trailing.extend_from_slice(&Any::null().to_der().unwrap());
    assert_eq!(
        synthetic_profile(Some(Any::new(Tag::Sequence, trailing).unwrap())),
        Err(EvidenceError::Endorsement)
    );
}

#[test]
fn certificate_profile_synthetic_inner_outer_mismatch_is_rejected() {
    for outer in [false, true] {
        let mut certificate = public_vcek();
        let algorithm = if outer {
            &mut certificate.signature_algorithm
        } else {
            &mut certificate.tbs_certificate.signature
        };
        algorithm.parameters = Some(pss_parameters(&public_pss_fields()[..3]));
        // Both individually name the supported scheme, but the identifiers differ.
        assert_eq!(
            certificate_profile(&certificate),
            Err(EvidenceError::Endorsement)
        );
    }
    let mut certificate = public_vcek();
    certificate.signature_algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    certificate.tbs_certificate.signature = certificate.signature_algorithm.clone();
    assert_eq!(
        certificate_profile(&certificate),
        Err(EvidenceError::Endorsement)
    );
}

#[test]
fn certificate_profile_synthetic_spki_requires_p384_byte_aligned_point() {
    for mutation in 0..10 {
        let mut certificate = public_vcek();
        let spki = &mut certificate.tbs_certificate.subject_public_key_info;
        match mutation {
            0 => spki.algorithm.oid = ObjectIdentifier::new_unwrap("1.2.3.4"),
            1 => spki.algorithm.parameters = None,
            2 => spki.algorithm.parameters = Some(encoded_any(&0_u8)),
            3 => {
                spki.algorithm.parameters = Some(encoded_any(&ObjectIdentifier::new_unwrap(
                    "1.2.840.10045.3.1.7",
                )));
            }
            9 => spki.algorithm.parameters = Some(Any::null()),
            _ => {
                let mut point = spki.subject_public_key.as_bytes().unwrap().to_vec();
                match mutation {
                    4 => {
                        point.pop();
                    }
                    5 => point.push(0),
                    6 => point[0] = 2,
                    7 => point.clear(),
                    _ => *point.last_mut().unwrap() = 0,
                }
                spki.subject_public_key = BitString::new(u8::from(mutation == 8), point).unwrap();
            }
        }
        assert_eq!(
            certificate_profile(&certificate),
            Err(EvidenceError::Endorsement)
        );
    }
}

#[test]
fn certificate_profile_preserves_signature_and_session_gates() {
    let mut certificate = public_vcek();
    // A synthetic declaration accepted in isolation is not an authentic certificate.
    let parameters = pss_parameters(&public_pss_fields()[..3]);
    certificate.signature_algorithm.parameters = Some(parameters.clone());
    certificate.tbs_certificate.signature.parameters = Some(parameters);
    assert_eq!(certificate_profile(&certificate), Ok(()));
    assert_eq!(
        verify_milan_v2_signature_facts(&report(), &certificate.to_der().unwrap()).err(),
        Some(EvidenceError::Signature)
    );
    let facts = verify_milan_v2_signature_facts(&report(), VCEK).unwrap();
    let at = Instant::now();
    let owner = SessionOwner::new_at(
        [1; 32],
        test_policy(*facts.measurement(), facts.guest_svn()),
        limits(1, 1),
        stamp(at, 0),
    )
    .unwrap();
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    assert_eq!(
        pending
            .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 1))
            .err(),
        Some(EvidenceError::Binding)
    );
    assert_eq!(
        owner.begin_at(stamp(at, 2)).err(),
        Some(EvidenceError::Budget)
    );
}

fn vcek_extension<'a>(certificate: &'a mut X509Certificate, suffix: &str) -> &'a mut Extension {
    let oid = ObjectIdentifier::new(&format!("1.3.6.1.4.1.3704.1.{suffix}")).unwrap();
    certificate
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|extension| extension.extn_id == oid)
        .unwrap()
}

fn extension_bytes(certificate: &mut X509Certificate, suffix: &str, raw: &[u8]) {
    vcek_extension(certificate, suffix).extn_value = OctetString::new(raw).unwrap();
}

fn claims(certificate: &X509Certificate, raw: &[u8]) -> Result<(), EvidenceError> {
    endorsement::check_claims(certificate, raw.try_into().unwrap())
}

#[test]
fn endorsement_public_fixture_binds_all_milan_claims() {
    let raw = report();
    assert_eq!(&raw[0x180..0x188], &[3, 0, 0, 0, 0, 0, 8, 115]);
    assert_eq!(claims(&public_vcek(), &raw), Ok(()));
    assert!(verify_milan_v2_signature_facts(&raw, VCEK).is_ok());
    // Extension order has no meaning; this is a parse-only consistency check.
    let mut reordered = public_vcek();
    reordered
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .reverse();
    assert_eq!(claims(&reordered, &raw), Ok(()));
}

#[test]
fn endorsement_requires_complete_unique_noncritical_known_extensions() {
    let raw = report();
    for index in 0..11 {
        for mutation in 0..4 {
            let mut cert = public_vcek();
            // Keep a failed fixture assumption free of certificate debug output.
            let Some(extensions) = cert.tbs_certificate.extensions.as_mut() else {
                panic!("public fixture requires certificate extensions");
            };
            assert_eq!(extensions.len(), 11);
            match mutation {
                0 => {
                    // Build the missing-claim fixture in the original order.
                    *extensions = extensions
                        .iter()
                        .enumerate()
                        .filter(|(position, _)| *position != index)
                        .map(|(_, extension)| extension.clone())
                        .collect();
                    assert_eq!(extensions.len(), 10);
                }
                1 => {
                    extensions[index] = extensions[(index + 1) % 11].clone();
                }
                2 => {
                    extensions[index].critical = true;
                }
                _ => {
                    extensions[index].extn_id = ObjectIdentifier::new_unwrap("1.2.3.4");
                }
            }
            assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
        }
    }
    let mut cert = public_vcek();
    cert.tbs_certificate.extensions = None;
    assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
    cert.tbs_certificate.extensions = Some(Vec::new());
    assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
    let mut cert = public_vcek();
    let extra = cert.tbs_certificate.extensions.as_ref().unwrap()[0].clone();
    cert.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extra);
    assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
}

#[test]
fn endorsement_integer_der_and_ranges_are_canonical() {
    let raw = report();
    let malformed: &[&[u8]] = &[
        &[],
        &[2, 0],
        &[2, 1, 255],
        &[2, 2, 0, 0],
        &[2, 1, 0, 0],
        &[4, 1, 0],
        &[2, 2, 1, 0],
        &[2, 0x81, 1, 0],
    ];
    for suffix in ["1", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8"] {
        for malformed in malformed {
            let mut cert = public_vcek();
            extension_bytes(&mut cert, suffix, malformed);
            assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
        }
    }
    // Even matching, canonical unsupported firmware components are refused.
    for (suffix, offset) in [("3.1", 0), ("3.2", 1), ("3.3", 6)] {
        for value in [128_u8, 255] {
            let mut cert = public_vcek();
            let mut raw = raw.clone();
            extension_bytes(&mut cert, suffix, &value.to_der().unwrap());
            raw[0x180 + offset] = value;
            assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
        }
    }
    // Microcode is allowed the full byte range, including canonical sign padding.
    for value in [0_u8, 127, 128, 255] {
        let mut cert = public_vcek();
        let mut raw = raw.clone();
        extension_bytes(&mut cert, "3.8", &value.to_der().unwrap());
        raw[0x187] = value;
        assert_eq!(claims(&cert, &raw), Ok(()));
    }
}

#[test]
fn endorsement_product_version_and_raw_hwid_are_not_interchangeable() {
    let raw = report();
    for version in [1_u8, 2, 255] {
        let mut cert = public_vcek();
        extension_bytes(&mut cert, "1", &version.to_der().unwrap());
        assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
    }
    for product in [
        "Milan",
        "Genoa-A0",
        "Milan-b0",
        "Milan-00",
        "Milan-B00",
        "Milan-B0\0",
    ] {
        let mut cert = public_vcek();
        let mut value = vec![0x16, u8::try_from(product.len()).unwrap()];
        value.extend_from_slice(product.as_bytes());
        extension_bytes(&mut cert, "2", &value);
        assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
    }
    let mut cert = public_vcek();
    extension_bytes(&mut cert, "2", b"\x0c\x08Milan-B0");
    assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
    let chip = &raw[0x1a0..0x1e0];
    let wrapped = OctetString::new(chip).unwrap().to_der().unwrap();
    for wrong in [&chip[..63], &wrapped, &[0; 64], &[0; 8]] {
        let mut cert = public_vcek();
        extension_bytes(&mut cert, "4", wrong);
        assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
    }
}

#[test]
fn endorsement_tcb_uses_exact_reported_component_order() {
    // Explicitly synthetic edits test consistency only, never authentication.
    let mut cert = public_vcek();
    let mut raw = report();
    for (suffix, offset, value) in [
        ("3.1", 0, 11_u8),
        ("3.2", 1, 22),
        ("3.3", 6, 33),
        ("3.8", 7, 144),
    ] {
        extension_bytes(&mut cert, suffix, &value.to_der().unwrap());
        raw[0x180 + offset] = value;
    }
    for range in [0x38..0x40, 0x1e0..0x1e8, 0x1f0..0x1f8] {
        raw[range].fill(99); // current, committed and launch cannot substitute.
    }
    assert_eq!(claims(&cert, &raw), Ok(()));
    for (suffix, offset) in [("3.4", 2), ("3.5", 3), ("3.6", 4), ("3.7", 5)] {
        let mut cert = cert.clone();
        let mut raw = raw.clone();
        extension_bytes(&mut cert, suffix, &1_u8.to_der().unwrap());
        raw[0x180 + offset] = 1;
        assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
    }
}

#[test]
fn endorsement_mismatched_chip_or_each_spl_is_rejected() {
    let cert = public_vcek();
    for offset in (0x1a0..0x1e0).chain(0x180..0x188) {
        let mut raw = report();
        raw[offset] ^= 1;
        assert_eq!(claims(&cert, &raw), Err(EvidenceError::Endorsement));
    }
}

#[test]
fn endorsement_mutation_cannot_bypass_signature_verification() {
    let raw = report();
    let mut cert = public_vcek();
    // The metadata predicate alone accepts this syntactically valid Milan claim.
    // Version-two reports cannot prove a stepping comparison. Changed signed
    // certificate bytes must still fail at the actual cryptographic entrypoint.
    extension_bytes(&mut cert, "2", b"\x16\x08Milan-B1");
    assert_eq!(claims(&cert, &raw), Ok(()));
    assert_eq!(
        verify_milan_v2_signature_facts(&raw, &cert.to_der().unwrap()).err(),
        Some(EvidenceError::Signature)
    );
    let mut raw = raw;
    raw[0x180] ^= 1;
    assert_eq!(
        verify_milan_v2_signature_facts(&raw, VCEK).err(),
        Some(EvidenceError::Signature)
    );
}

#[test]
fn endorsement_consistency_never_clears_remaining_appraisal() {
    let facts = verify_milan_v2_signature_facts(&report(), VCEK).unwrap();
    assert_eq!(facts.outstanding_appraisal(), &OUTSTANDING);
    assert_eq!(facts.outstanding_appraisal().len(), 5);
    assert_eq!(
        EvidenceError::Endorsement.to_string(),
        "attestation endorsement binding failed"
    );
    // No certificate/chip identifier is included in the closed error text.
    assert!(!EvidenceError::Endorsement.to_string().contains("Milan"));
}

#[test]
fn signed_report_or_certificate_tampering_is_rejected_by_actual_crypto() {
    for offset in [0x15, 0x50, 0x90, 0x1a0, 0x2a0] {
        let mut bytes = report();
        bytes[offset] ^= 0x80;
        assert_eq!(
            verify_milan_v2_signature_facts(&bytes, VCEK).err(),
            Some(EvidenceError::Signature)
        );
    }
    let mut cert = VCEK.to_vec();
    cert[40] ^= 0xff; // Same parseable mutation as the upstream invalid-chain test.
    assert_eq!(
        verify_milan_v2_signature_facts(&report(), &cert).err(),
        Some(EvidenceError::Signature)
    );
}

#[test]
fn exact_received_framing_version_and_reserved_bytes_are_required() {
    let original = report();
    for size in [0, 1, 1183, 1185, 8192] {
        let mut bytes = original.clone();
        bytes.resize(size, 0);
        assert_eq!(
            verify_milan_v2_signature_facts(&bytes, VCEK).err(),
            Some(EvidenceError::Encoding)
        );
    }
    for version in [0_u32, 1, 3, 4, 5, u32::MAX] {
        let mut bytes = original.clone();
        bytes[..4].copy_from_slice(&version.to_le_bytes());
        assert_eq!(
            snp::exact_report(&bytes).err(),
            Some(EvidenceError::Encoding)
        );
    }
    // Reserved report, TCB, pre-chip, version and tail bytes plus high R/S bytes.
    for offset in [
        0x3a,
        0x4c,
        0x188,
        0x1e2,
        0x1eb,
        0x1ef,
        0x1f2,
        0x1f8,
        0x2a0 + 48,
        0x2a0 + 72 + 48,
        0x2a0 + 144,
        1183,
    ] {
        let mut bytes = original.clone();
        bytes[offset] = 1;
        assert_eq!(
            snp::exact_report(&bytes).err(),
            Some(EvidenceError::Encoding),
            "offset {offset:x}"
        );
    }
}

#[test]
fn unsupported_key_policy_platform_and_certificate_shapes_fail_closed() {
    let original = report();
    for (offset, bit) in [
        (0x30, 1),
        (0x34, 2),
        (0x48, 2),
        (0x48, 4),
        (0x48, 0x20),
        (0x0a, 0x20),
        (0x40, 0x20),
    ] {
        let mut bytes = original.clone();
        bytes[offset] |= bit;
        assert_eq!(
            snp::exact_report(&bytes).err(),
            Some(EvidenceError::Encoding)
        );
    }
    let mut bytes = original;
    bytes[0x0a] &= !2; // Mandatory policy reserved bit must be one on the wire.
    assert_eq!(
        snp::exact_report(&bytes).err(),
        Some(EvidenceError::Encoding)
    );
    for cert in [
        Vec::new(),
        vec![0; MAX_VCEK_BYTES + 1],
        [VCEK, &[0]].concat(),
    ] {
        assert_eq!(
            verify_milan_v2_signature_facts(&report(), &cert).err(),
            Some(EvidenceError::Encoding)
        );
    }
}

#[test]
fn actual_public_report_cannot_bind_to_fresh_owner_even_with_matching_measurement() {
    let facts = verify_milan_v2_signature_facts(&report(), VCEK).unwrap();
    let at = Instant::now();
    let owner = SessionOwner::new_at(
        [1; 32],
        test_policy(*facts.measurement(), facts.guest_svn()),
        limits(1, 1),
        stamp(at, 0),
    )
    .unwrap();
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    assert_eq!(
        pending
            .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 1))
            .err(),
        Some(EvidenceError::Binding)
    );
    assert_eq!(
        owner.begin_at(stamp(at, 2)).err(),
        Some(EvidenceError::Budget)
    );
}

#[test]
fn synthetic_binding_positive_is_explicitly_not_full_appraisal_or_release() {
    let at = Instant::now();
    let owner = owner(at, 2, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let expected_hash: [u8; 32] = Sha256::digest(pending.challenge_bytes()).into();
    let facts = synthetic_binding_facts(&pending, &[5; 32]);
    let evidence = pending
        .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 1))
        .unwrap();
    assert_eq!(evidence.challenge_sha256(), &expected_hash);
    assert_eq!(evidence.proposed_session_key(), &[5; 32]);
    assert_eq!(evidence.expires_at(), NOW + 30);
    assert_eq!(evidence.observed_at(), NOW + 1);
    assert_eq!(evidence.outstanding_appraisal(), &BOUND_OUTSTANDING);
    assert_eq!(evidence.signature_facts().report_sha256(), &[3; 32]);
    let next = owner.begin_at(stamp(at, 2)).unwrap();
    assert_ne!(
        Sha256::digest(next.challenge_bytes()).as_slice(),
        &expected_hash
    );
}

#[test]
fn fresh_nonce_owner_policy_and_proposed_key_are_all_bound() {
    let at = Instant::now();
    let owner = owner(at, 4, 2);
    let first = owner.begin_at(stamp(at, 0)).unwrap();
    let second = owner.begin_at(stamp(at, 0)).unwrap();
    let facts = synthetic_binding_facts(&first, &[5; 32]);
    assert_ne!(first.challenge_bytes(), second.challenge_bytes());
    assert_eq!(
        second
            .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 1))
            .err(),
        Some(EvidenceError::Binding)
    );
    let facts = synthetic_binding_facts(&first, &[5; 32]);
    assert_eq!(
        first
            .bind_at(facts, synthetic_collateral(), [6; 32], stamp(at, 1))
            .err(),
        Some(EvidenceError::Binding)
    );
    let first = owner.begin_at(stamp(at, 2)).unwrap();
    let facts = synthetic_binding_facts(&first, &[5; 32]);
    let other =
        SessionOwner::new_at([9; 32], test_policy([2; 48], 1), limits(1, 1), stamp(at, 0)).unwrap();
    let second = other.begin_at(stamp(at, 2)).unwrap();
    assert_eq!(
        second
            .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 3))
            .err(),
        Some(EvidenceError::Binding)
    );
}

#[test]
fn measurement_svn_debug_migration_and_each_certificate_time_are_checked() {
    let at = Instant::now();
    let owner = owner(at, 16, 1);
    for mutation in 0..4 {
        let pending = owner.begin_at(stamp(at, 0)).unwrap();
        let mut facts = synthetic_binding_facts(&pending, &[5; 32]);
        match mutation {
            0 => facts.measurement[0] ^= 1,
            1 => facts.guest_svn = 0,
            2 => facts.guest_policy |= 1 << 18,
            _ => facts.guest_policy |= 1 << 19,
        }
        assert_eq!(
            pending
                .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 1))
                .err(),
            Some(EvidenceError::Policy)
        );
    }
    for index in 0..3 {
        for validity in [(NOW + 2, NOW + 10), (NOW - 10, NOW), (NOW + 2, NOW)] {
            let pending = owner.begin_at(stamp(at, 0)).unwrap();
            let mut facts = synthetic_binding_facts(&pending, &[5; 32]);
            facts.validity[index] = validity;
            assert_eq!(
                pending
                    .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 1))
                    .err(),
                Some(EvidenceError::CertificateTime)
            );
        }
    }
}

#[test]
fn delayed_expired_rollback_and_cancelled_bindings_cannot_succeed() {
    let at = Instant::now();
    let owner = owner(at, 8, 1);
    for now in [
        stamp(at, 30),
        stamp(at, 31),
        Stamp {
            unix: NOW - 1,
            monotonic: at + Duration::from_secs(1),
        },
        Stamp {
            unix: NOW + 1,
            monotonic: at + Duration::from_secs(31),
        },
    ] {
        let pending = owner.begin_at(stamp(at, 0)).unwrap();
        let facts = synthetic_binding_facts(&pending, &[5; 32]);
        assert_eq!(
            pending
                .bind_at(facts, synthetic_collateral(), [5; 32], now)
                .err(),
            Some(EvidenceError::Expired)
        );
    }
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let facts = synthetic_binding_facts(&pending, &[5; 32]);
    owner.cancel();
    assert_eq!(
        pending
            .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 1))
            .err(),
        Some(EvidenceError::Cancelled)
    );
    assert_eq!(
        owner.begin_at(stamp(at, 1)).err(),
        Some(EvidenceError::Cancelled)
    );
}

#[test]
fn pending_slots_release_but_attempts_never_refund_on_drop_cancel_or_failure() {
    let at = Instant::now();
    let owner = owner(at, 3, 1);
    let first = owner.begin_at(stamp(at, 0)).unwrap();
    assert_eq!(
        owner.begin_at(stamp(at, 0)).err(),
        Some(EvidenceError::Budget)
    );
    drop(first);
    owner.begin_at(stamp(at, 1)).unwrap().cancel();
    let final_attempt = owner.begin_at(stamp(at, 2)).unwrap();
    let facts = synthetic_binding_facts(&final_attempt, &[5; 32]);
    assert_eq!(
        final_attempt
            .bind_at(facts, synthetic_collateral(), [6; 32], stamp(at, 3))
            .err(),
        Some(EvidenceError::Binding)
    );
    assert_eq!(
        owner.begin_at(stamp(at, 4)).err(),
        Some(EvidenceError::Budget)
    );
}

#[test]
fn owner_bounds_expire_without_rebasing_challenge_or_attempt_budget() {
    let at = Instant::now();
    let owner = owner(at, 3, 1);
    let pending = owner.begin_at(stamp(at, 119)).unwrap();
    let facts = synthetic_binding_facts(&pending, &[5; 32]);
    assert_eq!(
        pending
            .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 120))
            .err(),
        Some(EvidenceError::Expired)
    );
    assert_eq!(
        owner.begin_at(stamp(at, 120)).err(),
        Some(EvidenceError::Expired)
    );
    for bad in [
        SessionLimits {
            expires_at: NOW,
            ..limits(1, 1)
        },
        SessionLimits {
            expires_at: NOW + 601,
            ..limits(1, 1)
        },
        SessionLimits {
            expires_at: u64::MAX,
            ..limits(1, 1)
        },
        limits(0, 1),
        limits(65, 1),
        limits(1, 0),
        limits(1, 9),
    ] {
        assert_eq!(
            SessionOwner::new_at([1; 32], test_policy([2; 48], 1), bad, stamp(at, 0)).err(),
            Some(EvidenceError::Configuration)
        );
    }
}

#[test]
fn public_binding_codec_rejects_unknown_duplicate_noncanonical_and_oversize() {
    let at = Instant::now();
    let owner = owner(at, 1, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let original = pending.challenge_bytes();
    let mut unknown = original.to_vec();
    unknown.extend([0x48, 1]);
    let mut duplicate = original.to_vec();
    duplicate.extend([8, 1]);
    let mut bad_version = original.to_vec();
    bad_version[1] = 1;
    for bytes in [Vec::new(), vec![0; 257], unknown, duplicate, bad_version] {
        assert_eq!(
            session_report_data(&bytes, &[5; 32]).err(),
            Some(EvidenceError::Encoding)
        );
    }
    assert_eq!(
        session_report_data(original, &[0; 32]).err(),
        Some(EvidenceError::Encoding)
    );
}

#[test]
fn public_signature_binding_entrypoint_consumes_its_attempt_without_release() {
    let facts = verify_milan_v2_signature_facts(&report(), VCEK).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let owner = SessionOwner::new(
        [1; 32],
        test_policy(*facts.measurement(), facts.guest_svn()),
        SessionLimits {
            expires_at: now + 60,
            maximum_pending: 1,
            maximum_attempts: 1,
        },
    )
    .unwrap();
    // The public fixture may itself eventually expire: neither outcome admits it.
    let failure = owner
        .begin()
        .unwrap()
        .verify_and_bind(
            &report(),
            VCEK,
            include_bytes!("../../../../tests/fixtures/snp/ark_milan_20260922.crl"),
            [5; 32],
        )
        .err()
        .unwrap();
    assert!(matches!(
        failure,
        EvidenceError::Binding | EvidenceError::CertificateTime | EvidenceError::Revocation
    ));
    assert_eq!(owner.begin().err(), Some(EvidenceError::Budget));
}

// Separate file, same historical test namespace for exact hosted receipts.
include!("policy_tests.rs");
