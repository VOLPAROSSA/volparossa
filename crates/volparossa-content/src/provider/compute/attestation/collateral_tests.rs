//! Public authentic collateral tests are separate from unsigned profile/state
//! mutations. Neither kind supplies a fresh hardware report or private execution.

use super::super::{
    BOUND_OUTSTANDING, SessionLimits, SessionOwner,
    session::{Stamp, session_report_data},
    tests::test_policy,
};
use super::*;
use std::time::{Duration, Instant};
use x509_cert::{
    crl::RevokedCert,
    der::asn1::{BitString, OctetString, UtcTime},
    serial_number::SerialNumber,
    time::Time,
};

// Public DER retrieved from https://kdsintf.amd.com/vcek/v1/Milan/crl on
// 2026-10-14. Real ARK-Milan signature, CRL 12, 2026-09-22..2026-11-09.
const CRL: &[u8] = include_bytes!("../../../../tests/fixtures/snp/ark_milan_20260922.crl");
const LEAF: &[u8] = include_bytes!("../../../../tests/fixtures/snp/vcek_milan.der");
const NOW: u64 = 1_791_979_200;
const START: u64 = 1_790_062_542;
const END: u64 = 1_794_186_000;

fn report() -> Vec<u8> {
    hex::decode(include_bytes!(
        "../../../../tests/fixtures/snp/report_milan.hex"
    ))
    .unwrap()
}

fn chain() -> (Certificate, Certificate, Certificate) {
    (
        milan::ark().unwrap().into(),
        milan::ask().unwrap().into(),
        Certificate::from_der(LEAF).unwrap(),
    )
}

fn time(seconds: u64) -> Time {
    Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(seconds)).unwrap())
}

fn stamp(at: Instant, seconds: u64) -> Stamp {
    Stamp {
        unix: NOW + seconds,
        monotonic: at + Duration::from_secs(seconds),
    }
}

fn owner(at: Instant) -> SessionOwner {
    SessionOwner::new_at(
        [1; 32],
        test_policy([2; 48], 1),
        SessionLimits {
            expires_at: NOW + 120,
            maximum_pending: 1,
            maximum_attempts: 1,
        },
        stamp(at, 0),
    )
    .unwrap()
}

fn extension(oid: &str, value: &[u8]) -> Extension {
    Extension {
        extn_id: ObjectIdentifier::new(oid).unwrap(),
        critical: false,
        extn_value: OctetString::new(value).unwrap(),
    }
}

fn synthetic_scope(crl: &CertificateList) -> Result<u64, EvidenceError> {
    let (root, intermediate, _) = chain();
    check_scope(&root, &intermediate, crl)
}

#[test]
fn public_signed_milan_crl_and_complete_path_are_actually_verified() {
    assert_eq!(CRL.len(), 866);
    assert_eq!(
        hex::encode(Sha256::digest(CRL)),
        "dd68e9e3feb97dd0e95135feeae47d9cc193c73239a6281ec9884c00d5e6a525"
    );
    let (signature, collateral) = verify(&report(), LEAF, CRL, NOW).unwrap();
    assert_eq!(signature.outstanding_appraisal().len(), 5);
    assert_eq!(collateral.number(), 12);
    assert_eq!(collateral.this_update(), START);
    assert_eq!(collateral.next_update(), END);
    assert_eq!(collateral.sha256(), &<[u8; 32]>::from(Sha256::digest(CRL)));
    assert!(
        parse_crl(CRL)
            .unwrap()
            .tbs_cert_list
            .revoked_certificates
            .is_none()
    );
}

#[test]
fn real_crl_signature_rejects_signed_body_signature_and_wrong_key_mutations() {
    let (root, intermediate, _) = chain();
    for change in 0..3 {
        let mut crl = parse_crl(CRL).unwrap();
        let key = if change == 2 {
            public_key(&intermediate).unwrap()
        } else {
            public_key(&root).unwrap()
        };
        if change == 0 {
            let mut bytes = crl.signature.as_bytes().unwrap().to_vec();
            bytes[0] ^= 1;
            crl.signature = BitString::from_bytes(&bytes).unwrap();
        } else if change == 1 {
            crl.tbs_cert_list.this_update = time(START + 1);
        }
        let raw = crl.to_der().unwrap();
        assert_eq!(
            verify_crl(&root, &intermediate, key, &crl, &raw, NOW).err(),
            Some(EvidenceError::Signature)
        );
    }
    let mut raw_report = report();
    raw_report[0x90] ^= 1;
    assert_eq!(
        verify(&raw_report, LEAF, CRL, NOW).err(),
        Some(EvidenceError::Signature)
    );
}

#[test]
fn crl_framing_is_bounded_canonical_and_byte_aligned() {
    for raw in [
        vec![],
        vec![0; MAX_CRL_BYTES + 1],
        [CRL, &[0]].concat(),
        CRL[..CRL.len() - 1].to_vec(),
    ] {
        assert_eq!(parse_crl(&raw).err(), Some(EvidenceError::Encoding));
    }
    let (root, intermediate, _) = chain();
    for unused in [0, 1] {
        let mut crl = parse_crl(CRL).unwrap();
        let mut signature = crl.signature.as_bytes().unwrap().to_vec();
        if unused == 0 {
            signature.pop();
        } else {
            *signature.last_mut().unwrap() = 0;
        }
        crl.signature = BitString::new(unused, signature).unwrap();
        assert_eq!(
            verify_crl(
                &root,
                &intermediate,
                public_key(&root).unwrap(),
                &crl,
                &crl.to_der().unwrap(),
                NOW
            )
            .err(),
            Some(EvidenceError::Encoding)
        );
    }
}

#[test]
fn authenticated_crl_validity_is_inclusive_start_exclusive_end() {
    for now in [START, NOW, END - 1] {
        assert!(verify(&report(), LEAF, CRL, now).is_ok());
    }
    for now in [START - 1, END, END + 1] {
        assert_eq!(
            verify(&report(), LEAF, CRL, now).err(),
            Some(EvidenceError::Revocation)
        );
    }
    assert_eq!(
        verify(&report(), LEAF, CRL, 0).err(),
        Some(EvidenceError::CertificateTime)
    );
}

#[test]
fn synthetic_path_issuer_versions_unique_ids_and_leaf_identity_are_closed() {
    for mutation in 0..9 {
        let (mut root, mut intermediate, mut leaf) = chain();
        match mutation {
            0 => root.tbs_certificate.issuer = leaf.tbs_certificate.subject.clone(),
            1 => intermediate.tbs_certificate.issuer = leaf.tbs_certificate.subject.clone(),
            2 => leaf.tbs_certificate.issuer = root.tbs_certificate.subject.clone(),
            3 => root.tbs_certificate.version = Version::V1,
            4 => intermediate.tbs_certificate.version = Version::V2,
            5 => leaf.tbs_certificate.version = Version::V2,
            6 => leaf.tbs_certificate.issuer_unique_id = Some(BitString::from_bytes(&[1]).unwrap()),
            7 => leaf.tbs_certificate.subject = root.tbs_certificate.subject.clone(),
            _ => leaf.tbs_certificate.serial_number = SerialNumber::from(1_u8),
        }
        assert_eq!(
            cert_path::check(&root, &intermediate, &leaf),
            Err(EvidenceError::Endorsement)
        );
    }
}

fn assert_pinned_ca_usage_and_path() {
    let (root, intermediate, leaf) = chain();
    for (certificate, original, normalized, bits) in [
        (&root, [3, 2, 1, 6], [3, 2, 1, 6], (1 << 5) | (1 << 6)),
        (&intermediate, [3, 2, 1, 4], [3, 2, 2, 4], 1 << 5),
    ] {
        let selected = certificate
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find(|item| item.extn_id.to_string() == "2.5.29.15")
            .unwrap();
        assert!(selected.critical);
        assert_eq!(selected.extn_value.as_bytes(), original);
        let usage = x509_cert::ext::pkix::KeyUsage::from_der(&original).unwrap();
        assert_eq!(usage.0.bits(), bits);
        assert_eq!(usage.to_der().unwrap(), normalized);
    }
    // The real pinned path must pass before any unsigned negative mutation.
    assert_eq!(cert_path::check(&root, &intermediate, &leaf), Ok(()));
}

#[test]
fn synthetic_ca_constraints_usage_identifiers_and_extensions_are_closed() {
    assert_pinned_ca_usage_and_path();
    for root_target in [false, true] {
        for mutation in 0..8 {
            let (mut root, mut intermediate, leaf) = chain();
            let target = if root_target {
                &mut root
            } else {
                &mut intermediate
            };
            let extensions = target.tbs_certificate.extensions.as_mut().unwrap();
            match mutation {
                0 => {
                    extensions.pop();
                }
                1 => extensions.push(extension("1.2.3.4", &[5, 0])),
                2 => extensions.push(extensions[0].clone()),
                3 => {
                    let selected = extensions
                        .iter_mut()
                        .find(|item| item.extn_id.to_string() == "2.5.29.19")
                        .unwrap();
                    selected.extn_value = OctetString::new([0x30, 0]).unwrap();
                }
                4 => {
                    let selected = extensions
                        .iter_mut()
                        .find(|item| item.extn_id.to_string() == "2.5.29.15")
                        .unwrap();
                    // digitalSignature alone does not authorize CA/CRL signing.
                    selected.extn_value = OctetString::new([3, 2, 7, 128]).unwrap();
                }
                5 => extensions[0].critical = !extensions[0].critical,
                6 => {
                    let selected = extensions
                        .iter_mut()
                        .find(|item| item.extn_id.to_string() == "2.5.29.31")
                        .unwrap();
                    selected.extn_value = OctetString::new([0x30, 0]).unwrap();
                }
                _ => {
                    let selected = extensions
                        .iter_mut()
                        .find(|item| item.extn_id.to_string() == "2.5.29.14")
                        .unwrap();
                    selected.extn_value = OctetString::new([4, 1, 0]).unwrap();
                }
            }
            assert_eq!(
                cert_path::check(&root, &intermediate, &leaf),
                Err(EvidenceError::Endorsement)
            );
        }
        // Even equivalent re-encodings are not the pinned vendor profile.
        // Also reject excess rights, unknown bits, nonzero unused bits, trailing
        // bytes, and long-form lengths instead of relying on flag truncation.
        let rights = if root_target { 6 } else { 4 };
        for raw in [
            vec![3, 2, 1, if root_target { 4 } else { 6 }],
            vec![3, 2, 0, rights],
            vec![3, 2, 2, rights],
            vec![3, 2, 1, rights | 128],
            vec![3, 2, 1, rights | 1],
            vec![3, 3, 0, rights, 1],
            vec![3, 2, 1, rights, 0],
            vec![3, 0x81, 2, 1, rights],
            vec![3, 2, 1],
        ] {
            let (mut root, mut intermediate, leaf) = chain();
            let target = if root_target {
                &mut root
            } else {
                &mut intermediate
            };
            target
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|item| item.extn_id.to_string() == "2.5.29.15")
                .unwrap()
                .extn_value = OctetString::new(raw).unwrap();
            assert_eq!(
                cert_path::check(&root, &intermediate, &leaf),
                Err(EvidenceError::Endorsement)
            );
        }
    }
}

#[test]
fn synthetic_crl_scope_issuer_authority_and_critical_extensions_fail_closed() {
    for mutation in 0..11 {
        let mut crl = parse_crl(CRL).unwrap();
        let body = &mut crl.tbs_cert_list;
        match mutation {
            0 => body.version = Version::V3,
            1 => body.issuer = chain().1.tbs_certificate.subject,
            2 => body.crl_extensions = None,
            index => {
                let extensions = body.crl_extensions.as_mut().unwrap();
                match index {
                    3 => extensions[0].critical = true,
                    4 => extensions.push(extensions[0].clone()),
                    5 => {
                        extensions.pop();
                    }
                    6 => extensions.push(extension("2.5.29.27", &[2, 1, 1])),
                    7 => extensions.push(extension("2.5.29.28", &[0x30, 0])),
                    8 => extensions.push(extension("1.2.3.4", &[5, 0])),
                    9 => {
                        let selected = extensions
                            .iter_mut()
                            .find(|item| item.extn_id == cert_path::AKI)
                            .unwrap();
                        selected.extn_value = OctetString::new([0x30, 3, 0x80, 1, 0]).unwrap();
                    }
                    _ => {
                        let selected = extensions
                            .iter_mut()
                            .find(|item| item.extn_id == NUMBER)
                            .unwrap();
                        selected.extn_value = OctetString::new([2, 2, 0, 12]).unwrap();
                    }
                }
            }
        }
        assert!(synthetic_scope(&crl).is_err());
    }
}

#[test]
fn synthetic_revocation_entries_cannot_hide_ask_or_change_issuer_scope() {
    let mut crl = parse_crl(CRL).unwrap();
    let mut entry = RevokedCert {
        serial_number: SerialNumber::from(7_u8),
        revocation_date: time(START),
        crl_entry_extensions: None,
    };
    crl.tbs_cert_list.revoked_certificates = Some(vec![entry.clone()]);
    assert_eq!(synthetic_scope(&crl), Ok(12));
    for mutation in 0..7 {
        let mut changed = crl.clone();
        match mutation {
            0 => changed.tbs_cert_list.revoked_certificates = Some(vec![]),
            1 => changed.tbs_cert_list.revoked_certificates = Some(vec![entry.clone(); 2]),
            2 => {
                changed.tbs_cert_list.revoked_certificates =
                    Some(vec![entry.clone(); MAX_REVOKED + 1]);
            }
            3 => {
                entry.serial_number = chain().1.tbs_certificate.serial_number;
                changed.tbs_cert_list.revoked_certificates = Some(vec![entry.clone()]);
            }
            index => {
                let selected = &mut changed.tbs_cert_list.revoked_certificates.as_mut().unwrap()[0];
                match index {
                    4 => selected.revocation_date = time(START + 1),
                    5 => {
                        selected.crl_entry_extensions =
                            Some(vec![extension("2.5.29.29", &[0x30, 0])]);
                    }
                    _ => {
                        selected.crl_entry_extensions =
                            Some(vec![extension("2.5.29.21", &[10, 1, 8])]);
                    }
                }
            }
        }
        assert_eq!(synthetic_scope(&changed), Err(EvidenceError::Revocation));
    }
}

#[test]
fn authentic_collateral_cannot_make_historical_report_fresh() {
    let (facts, collateral) = verify(&report(), LEAF, CRL, NOW).unwrap();
    let at = Instant::now();
    let owner = SessionOwner::new_at(
        [1; 32],
        test_policy(*facts.measurement(), facts.guest_svn()),
        SessionLimits {
            expires_at: NOW + 120,
            maximum_pending: 1,
            maximum_attempts: 1,
        },
        stamp(at, 0),
    )
    .unwrap();
    assert_eq!(
        owner
            .begin_at(stamp(at, 0))
            .unwrap()
            .bind_at(facts, collateral, [5; 32], stamp(at, 1))
            .err(),
        Some(EvidenceError::Binding)
    );
    assert_eq!(
        owner.begin_at(stamp(at, 2)).err(),
        Some(EvidenceError::Budget)
    );
}

#[test]
fn synthetic_bound_expiry_never_exceeds_crl_or_certificate() {
    for cert_end in [NOW + 5, NOW + 120] {
        let at = Instant::now();
        let owner = owner(at);
        let pending = owner.begin_at(stamp(at, 0)).unwrap();
        // Authenticated public fixtures are deliberately changed into synthetic
        // state inputs; these are NOT newly signed guest evidence or vendor data.
        let (mut facts, mut collateral) = verify(&report(), LEAF, CRL, NOW).unwrap();
        facts.measurement = [2; 48];
        facts.guest_svn = 1;
        facts.guest_policy = 1 << 17;
        facts.report_data = session_report_data(pending.challenge_bytes(), &[5; 32]).unwrap();
        facts.validity[2].1 = cert_end;
        collateral.next_update = NOW + 10;
        let evidence = pending
            .bind_at(facts, collateral, [5; 32], stamp(at, 1))
            .unwrap();
        assert_eq!(evidence.expires_at(), cert_end.min(NOW + 10));
        assert_eq!(evidence.vendor_crl().number(), 12);
        assert_eq!(evidence.outstanding_appraisal(), &BOUND_OUTSTANDING);
        assert_eq!(evidence.signature_facts().outstanding_appraisal().len(), 5);
    }
}

#[test]
fn synthetic_collateral_expiry_and_cancel_are_rechecked_before_binding() {
    for cancel in [false, true] {
        let at = Instant::now();
        let owner = owner(at);
        let pending = owner.begin_at(stamp(at, 0)).unwrap();
        let (facts, mut collateral) = verify(&report(), LEAF, CRL, NOW).unwrap();
        collateral.next_update = NOW + 1;
        if cancel {
            owner.cancel();
        }
        assert_eq!(
            pending
                .bind_at(facts, collateral, [5; 32], stamp(at, 1))
                .err(),
            Some(if cancel {
                EvidenceError::Cancelled
            } else {
                EvidenceError::Revocation
            })
        );
    }
}

#[test]
fn synthetic_profile_acceptance_never_substitutes_for_real_crl_signature() {
    let mut crl = parse_crl(CRL).unwrap();
    // A plausible unsigned replacement number passes the scope helper alone.
    let extensions = crl.tbs_cert_list.crl_extensions.as_mut().unwrap();
    extensions
        .iter_mut()
        .find(|item| item.extn_id == NUMBER)
        .unwrap()
        .extn_value = OctetString::new([2, 1, 13]).unwrap();
    assert_eq!(synthetic_scope(&crl), Ok(13));
    assert_eq!(
        verify(&report(), LEAF, &crl.to_der().unwrap(), NOW).err(),
        Some(EvidenceError::Signature)
    );
}
