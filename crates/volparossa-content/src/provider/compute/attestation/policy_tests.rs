// Included in the existing attestation test namespace. Only explicitly named
// public-fixture cases perform authentic report verification; state edits below
// are synthetic and cannot manufacture signed evidence in the public API.
use prost::Message as _;

fn fixture_tcb() -> MilanTcb {
    MilanTcb {
        bootloader: 3,
        tee: 0,
        snp: 8,
        microcode: 115,
    }
}

fn minima(stages: [MilanTcb; 4]) -> TcbMinimums {
    let [current, reported, committed, launch] = stages;
    TcbMinimums {
        current,
        reported,
        committed,
        launch,
    }
}

// Compatibility expectations solely for the historical fixture/state tests.
// Deliberately NOT production minima or a current AMD mitigation decision.
pub(super) fn test_policy(measurement: [u8; 48], svn: u32) -> LocalPolicy {
    LocalPolicy::new(
        measurement,
        svn,
        minima([fixture_tcb(); 4]),
        SmtPolicy::Allow,
    )
    .unwrap()
}

fn component(value: &mut MilanTcb, index: usize) -> &mut u8 {
    match index {
        0 => &mut value.bootloader,
        1 => &mut value.tee,
        2 => &mut value.snp,
        3 => &mut value.microcode,
        _ => panic!("test component index"),
    }
}

// Independent wire view used only to mutate public challenge fields in tests.
#[derive(Clone, PartialEq, prost::Message)]
struct PolicyChallenge {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    public_policy_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    expected_measurement: Vec<u8>,
    #[prost(uint32, tag = "5")]
    minimum_guest_svn: u32,
    #[prost(uint64, tag = "6")]
    created_at: u64,
    #[prost(uint64, tag = "7")]
    expires_at: u64,
    #[prost(bytes = "vec", tag = "8")]
    local_policy: Vec<u8>,
}

#[test]
fn local_policy_public_fixture_obeys_explicit_fixture_only_floor() {
    let facts = verify_milan_v2_signature_facts(&report(), VCEK).unwrap();
    assert!(facts.tcb.iter().all(|stage| *stage == fixture_tcb()));
    assert!(facts.platform_smt_enabled);
    assert_eq!(facts.guest_svn(), 0);
    assert_eq!(
        facts.check_local_policy(&test_policy(*facts.measurement(), 0)),
        Ok(())
    );
    let disabled = LocalPolicy::new(
        *facts.measurement(),
        0,
        minima([fixture_tcb(); 4]),
        SmtPolicy::RequireDisabled,
    )
    .unwrap();
    assert_eq!(
        facts.check_local_policy(&disabled),
        Err(EvidenceError::Policy)
    );
    assert_eq!(
        facts.check_local_policy(&test_policy(*facts.measurement(), 1)),
        Err(EvidenceError::Policy)
    );
    assert_eq!(facts.outstanding_appraisal(), &OUTSTANDING);
}

#[test]
fn local_policy_each_tcb_stage_and_component_enforces_its_floor() {
    let facts = verify_milan_v2_signature_facts(&report(), VCEK).unwrap();
    // Sixteen negative comparisons against unchanged, genuinely signed bytes.
    for stage in 0..4 {
        for index in 0..4 {
            let mut floors = [fixture_tcb(); 4];
            *component(&mut floors[stage], index) += 1;
            let policy =
                LocalPolicy::new(*facts.measurement(), 0, minima(floors), SmtPolicy::Allow)
                    .unwrap();
            assert_eq!(
                facts.check_local_policy(&policy),
                Err(EvidenceError::Policy)
            );
        }
    }
}

#[test]
fn local_policy_synthetic_component_order_is_not_lexicographic() {
    let at = Instant::now();
    let owner = owner(at, 1, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let floor = MilanTcb {
        bootloader: 5,
        tee: 5,
        snp: 5,
        microcode: 5,
    };
    let policy = LocalPolicy::new([2; 48], 1, minima([floor; 4]), SmtPolicy::Allow).unwrap();
    for stage in 0..4 {
        for index in 0..4 {
            let mut facts = synthetic_binding_facts(&pending, &[5; 32]);
            facts.tcb = [MilanTcb {
                bootloader: 6,
                tee: 6,
                snp: 6,
                microcode: 6,
            }; 4];
            *component(&mut facts.tcb[stage], index) = 4;
            assert_eq!(
                facts.check_local_policy(&policy),
                Err(EvidenceError::Policy)
            );
            *component(&mut facts.tcb[stage], index) = 5;
            assert_eq!(facts.check_local_policy(&policy), Ok(()));
        }
    }
    // Independent stages may differ; equality or current/launch ordering is not required.
    let mut facts = synthetic_binding_facts(&pending, &[5; 32]);
    facts.tcb = [floor; 4];
    facts.tcb[3].microcode = 255;
    assert_eq!(facts.check_local_policy(&policy), Ok(()));
}

#[test]
fn local_policy_synthetic_smt_permission_and_state_are_distinct() {
    let at = Instant::now();
    let owner = owner(at, 1, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let disabled = LocalPolicy::new(
        [2; 48],
        1,
        minima([fixture_tcb(); 4]),
        SmtPolicy::RequireDisabled,
    )
    .unwrap();
    for permission in [false, true] {
        for enabled in [false, true] {
            let mut facts = synthetic_binding_facts(&pending, &[5; 32]);
            facts.guest_policy |= u64::from(permission) << 16;
            facts.platform_smt_enabled = enabled;
            assert_eq!(facts.check_local_policy(&test_policy([2; 48], 1)), Ok(()));
            assert_eq!(
                facts.check_local_policy(&disabled),
                if permission || enabled {
                    Err(EvidenceError::Policy)
                } else {
                    Ok(())
                }
            );
        }
    }
}

#[test]
fn local_policy_synthetic_measurement_svn_debug_and_migration() {
    let at = Instant::now();
    let owner = owner(at, 1, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    for change in 0..4 {
        let mut facts = synthetic_binding_facts(&pending, &[5; 32]);
        match change {
            0 => facts.measurement[47] ^= 1,
            1 => facts.guest_svn = 0,
            2 => facts.guest_policy |= 1 << 18,
            _ => facts.guest_policy |= 1 << 19,
        }
        assert_eq!(
            facts.check_local_policy(&test_policy([2; 48], 1)),
            Err(EvidenceError::Policy)
        );
    }
}

#[test]
fn local_policy_invalid_configuration_is_rejected() {
    assert_eq!(
        LocalPolicy::new([0; 48], 0, minima([fixture_tcb(); 4]), SmtPolicy::Allow).err(),
        Some(EvidenceError::Configuration)
    );
    for stage in 0..4 {
        for index in 0..3 {
            for invalid in [128, 255] {
                let mut floors = [fixture_tcb(); 4];
                *component(&mut floors[stage], index) = invalid;
                assert_eq!(
                    LocalPolicy::new([2; 48], 1, minima(floors), SmtPolicy::Allow).err(),
                    Some(EvidenceError::Configuration)
                );
            }
        }
    }
    let maximum = MilanTcb {
        bootloader: 127,
        tee: 127,
        snp: 127,
        microcode: 255,
    };
    assert!(
        LocalPolicy::new(
            [2; 48],
            u32::MAX,
            minima([maximum; 4]),
            SmtPolicy::RequireDisabled
        )
        .is_ok()
    );
    for index in [0, 1, 6] {
        let mut raw = [0; 8];
        raw[index] = 128;
        assert_eq!(
            MilanTcb::from_report(&raw).err(),
            Some(EvidenceError::Encoding)
        );
    }
}

#[test]
fn local_policy_signed_mutation_cannot_bypass_crypto() {
    // Signed stage/state bytes remain under actual signature verification.
    for offset in [0x38, 0x180, 0x1e0, 0x1f0, 0x40, 10] {
        let mut bytes = report();
        bytes[offset] ^= 1;
        assert_eq!(
            verify_milan_v2_signature_facts(&bytes, VCEK).err(),
            Some(EvidenceError::Signature)
        );
    }
    // Do not broaden the historical v2 platform mask to claim alias mitigation.
    let mut bytes = report();
    bytes[0x40] |= 1 << 5;
    assert_eq!(
        verify_milan_v2_signature_facts(&bytes, VCEK).err(),
        Some(EvidenceError::Encoding)
    );
}

#[test]
fn local_policy_challenge_binds_every_policy_field() {
    let at = Instant::now();
    let owner = owner(at, 1, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let original = PolicyChallenge::decode(pending.challenge_bytes()).unwrap();
    assert_eq!(original.version, 2);
    assert_eq!(original.encode_to_vec(), pending.challenge_bytes());
    let bound = session_report_data(pending.challenge_bytes(), &[5; 32]).unwrap();
    // Same nonce, times and public policy ID: every independent local choice binds.
    for index in 0..19 {
        let mut changed = original.clone();
        match index {
            0 => changed.expected_measurement[0] ^= 1,
            1 => changed.minimum_guest_svn += 1,
            2..=17 => changed.local_policy[index - 1] += 1,
            _ => changed.local_policy[17] = 1,
        }
        assert_ne!(
            session_report_data(&changed.encode_to_vec(), &[5; 32]).unwrap(),
            bound
        );
    }
    // A policy does not move between owners under the same public identifier.
    let stricter =
        LocalPolicy::new([2; 48], 2, minima([fixture_tcb(); 4]), SmtPolicy::Allow).unwrap();
    let other = SessionOwner::new_at([1; 32], stricter, limits(1, 1), stamp(at, 0)).unwrap();
    let second = other.begin_at(stamp(at, 0)).unwrap();
    let mut facts = synthetic_binding_facts(&pending, &[5; 32]);
    facts.guest_svn = 2;
    assert_eq!(
        second
            .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 1))
            .err(),
        Some(EvidenceError::Binding)
    );
}

#[test]
fn local_policy_old_or_noncanonical_challenges_are_rejected() {
    let at = Instant::now();
    let owner = owner(at, 1, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let original = PolicyChallenge::decode(pending.challenge_bytes()).unwrap();
    for change in 0..9 {
        let mut value = original.clone();
        match change {
            0 => value.version = 1,
            1 => {
                value.version = 1;
                value.local_policy.clear();
            }
            2 => value.local_policy.clear(),
            3 => {
                value.local_policy.pop();
            }
            4 => value.local_policy.push(0),
            5 => value.local_policy[0] = 2,
            6 => value.local_policy[17] = 2,
            7 => value.local_policy[1] = 128,
            _ => value.local_policy[15] = 128,
        }
        assert_eq!(
            session_report_data(&value.encode_to_vec(), &[5; 32]).err(),
            Some(EvidenceError::Encoding)
        );
    }
    let mut duplicate = pending.challenge_bytes().to_vec();
    duplicate.extend([0x42, 18]);
    duplicate.extend(original.local_policy);
    assert_eq!(
        session_report_data(&duplicate, &[5; 32]).err(),
        Some(EvidenceError::Encoding)
    );
}

#[test]
fn local_policy_synthetic_rejection_consumes_one_attempt() {
    let at = Instant::now();
    let owner = owner(at, 2, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let mut facts = synthetic_binding_facts(&pending, &[5; 32]);
    facts.tcb[2].snp = 7;
    assert_eq!(
        pending
            .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 1))
            .err(),
        Some(EvidenceError::Policy)
    );
    let pending = owner.begin_at(stamp(at, 2)).unwrap();
    let facts = synthetic_binding_facts(&pending, &[5; 32]);
    assert!(
        pending
            .bind_at(facts, synthetic_collateral(), [5; 32], stamp(at, 3))
            .is_ok()
    );
    assert_eq!(
        owner.begin_at(stamp(at, 4)).err(),
        Some(EvidenceError::Budget)
    );
}

#[test]
fn local_policy_synthetic_owner_and_collateral_bounds() {
    for mode in 0..3 {
        let at = Instant::now();
        let owner = owner(at, 1, 1);
        let pending = owner.begin_at(stamp(at, 0)).unwrap();
        let facts = synthetic_binding_facts(&pending, &[5; 32]);
        let mut collateral = synthetic_collateral();
        if mode == 0 {
            owner.cancel();
        }
        if mode == 1 {
            collateral.next_update = NOW + 1;
        }
        let now = stamp(at, if mode == 2 { 30 } else { 1 });
        assert_eq!(
            pending.bind_at(facts, collateral, [5; 32], now).err(),
            Some(match mode {
                0 => EvidenceError::Cancelled,
                1 => EvidenceError::Revocation,
                _ => EvidenceError::Expired,
            })
        );
    }
}

#[test]
fn local_policy_synthetic_success_preserves_appraisal_obligations() {
    let at = Instant::now();
    let owner = owner(at, 1, 1);
    let pending = owner.begin_at(stamp(at, 0)).unwrap();
    let facts = synthetic_binding_facts(&pending, &[5; 32]);
    let mut collateral = synthetic_collateral();
    collateral.next_update = NOW + 7;
    let bound = pending
        .bind_at(facts, collateral, [5; 32], stamp(at, 1))
        .unwrap();
    assert_eq!(bound.expires_at(), NOW + 7);
    assert_eq!(bound.outstanding_appraisal(), &BOUND_OUTSTANDING);
    assert_eq!(bound.outstanding_appraisal().len(), 4);
    assert!(
        bound
            .outstanding_appraisal()
            .contains(&OutstandingAppraisal::VendorTcbAndLocalPolicy)
    );
    assert_eq!(
        bound.signature_facts().outstanding_appraisal(),
        &OUTSTANDING
    );
}
