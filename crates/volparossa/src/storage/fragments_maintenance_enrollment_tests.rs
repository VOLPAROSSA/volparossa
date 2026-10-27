//! Deterministic signing-time samples; no network or wall-clock sleeps.

use super::*;
use std::cell::Cell;

fn authority(created: u64, expires: u64, owner: &SigningKey) -> Enrollment {
    let (_, grant) = candidate(owner);
    Enrollment {
        version: 1,
        id: [4; 32],
        owner: owner.verifying_key().to_bytes(),
        root: [9; 32],
        archive: PathBuf::from("/private/original/archive"),
        source: [7; 32],
        providers: vec![grant.provider_key().to_bytes()],
        grants: vec![hex::encode(grant.signed().encode())],
        created,
        expires,
        lifetime: 900,
        renew_before: 1800,
        maximum_charged: 4096,
        maximum_turn: 134_217_728,
    }
}

#[test]
fn absolute_enrollment_expiry_only_tightens_original_relative_authority() {
    assert_eq!(enrollment_expiry(100, 60, None).unwrap(), 160);
    assert_eq!(enrollment_expiry(100, 60, Some(130)).unwrap(), 130);
    assert_eq!(enrollment_expiry(100, 60, Some(160)).unwrap(), 160);
    assert_eq!(enrollment_expiry(100, 60, Some(u64::MAX)).unwrap(), 160);
    for cap in [0, 99, 100] {
        assert!(enrollment_expiry(100, 60, Some(cap)).is_err());
    }
    for seconds in [0, MAX_LEASE_SECONDS + 1, u64::MAX] {
        assert!(enrollment_expiry(100, seconds, Some(101)).is_err());
    }
    for cap in [None, Some(u64::MAX)] {
        assert!(
            enrollment_expiry(u64::MAX - 1, 2, cap)
                .unwrap_err()
                .to_string()
                .contains("expiry overflow")
        );
    }
}

#[test]
fn delayed_enrollment_signing_preserves_absolute_cap_and_v1_signature() {
    let owner = SigningKey::from_bytes(&[3; 32]);
    let clock = Cell::new(100);
    let created = clock.get();
    let expires = enrollment_expiry(created, 60, Some(130)).unwrap();
    let enrollment = authority(created, expires, &owner);
    let original = serde_json::to_value(&enrollment).unwrap();
    // Model delay in preparation/grant validation. This is the same final
    // signing helper used by enroll, with a real signature and private reload.
    clock.set(129);
    let reads = Cell::new(0);
    let signed = sign_enrollment(enrollment, &owner, || {
        reads.set(reads.get() + 1);
        Ok(clock.get())
    })
    .unwrap();
    assert_eq!(reads.get(), 1);
    assert_eq!(serde_json::to_value(&signed.enrollment).unwrap(), original);
    owner
        .verifying_key()
        .verify_strict(
            &signing(&signed.enrollment).unwrap(),
            &Signature::from_slice(&hex::decode(&signed.signature).unwrap()).unwrap(),
        )
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("maintenance");
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let directory = state::directory(&path).unwrap();
    save(&directory, "enrollment.json", &signed).unwrap();
    assert_eq!(
        serde_json::to_value(load(&directory).unwrap()).unwrap(),
        original
    );
    assert_eq!(
        fs::metadata(path.join("enrollment.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let record = serde_json::to_value(&signed).unwrap();
    assert_eq!(record.as_object().unwrap().len(), 2);
    assert_eq!(record["enrollment"]["version"], 1);
    assert!(
        record["enrollment"]
            .get("authorization_expires_at")
            .is_none()
    );
}

#[test]
fn expired_or_backwards_clock_cannot_sign_enrollment() {
    let owner = SigningKey::from_bytes(&[3; 32]);
    for (cap, signing_at, expected) in [
        (Some(130), 130, "authority expired"),
        (Some(130), 131, "authority expired"),
        (Some(200), 160, "authority expired"),
        (None, 160, "authority expired"),
        (Some(130), 99, "clock moved backwards"),
        (None, 99, "clock moved backwards"),
    ] {
        let expires = enrollment_expiry(100, 60, cap).unwrap();
        let error = sign_enrollment(authority(100, expires, &owner), &owner, || Ok(signing_at))
            .err()
            .unwrap();
        assert!(error.to_string().contains(expected));
    }
    let error = sign_enrollment(authority(100, 160, &owner), &owner, || {
        anyhow::bail!("clock unavailable")
    })
    .err()
    .unwrap();
    assert!(error.to_string().contains("clock unavailable"));
}

#[test]
fn relative_only_enrollment_signing_keeps_original_bytes_and_expiry() {
    let owner = SigningKey::from_bytes(&[3; 32]);
    let enrollment = authority(100, enrollment_expiry(100, 60, None).unwrap(), &owner);
    let expected_signature = hex::encode(owner.sign(&signing(&enrollment).unwrap()).to_bytes());
    let original = serde_json::to_value(&enrollment).unwrap();
    let signed = sign_enrollment(enrollment, &owner, || Ok(129)).unwrap();
    assert_eq!(signed.signature, expected_signature);
    assert_eq!(serde_json::to_value(signed.enrollment).unwrap(), original);
}

#[test]
fn absolute_enrollment_cli_is_optional_and_never_replaces_relative_bound() {
    #[derive(clap::Parser)]
    struct EnrollmentCli {
        #[command(flatten)]
        args: Enroll,
    }
    let key = hex::encode(SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes());
    let base = vec![
        "enroll",
        "--enrollment",
        "/private/enrollment",
        "--state",
        "/private/archive",
        "--from-provider-key",
        &key,
        "--provider-key",
        &key,
        "--grant",
        "/private/grant",
        "--authorization-seconds",
        "60",
        "--lifetime-seconds",
        "60",
        "--maximum-charged-bytes",
        "4096",
    ];
    let legacy = <EnrollmentCli as clap::Parser>::try_parse_from(&base)
        .unwrap()
        .args;
    assert_eq!(legacy.authorization_seconds, 60);
    assert_eq!(legacy.authorization_expires_at, None);
    let mut capped = base.clone();
    capped.extend(["--authorization-expires-at", "130"]);
    let capped = <EnrollmentCli as clap::Parser>::try_parse_from(&capped)
        .unwrap()
        .args;
    assert_eq!(capped.authorization_seconds, 60);
    assert_eq!(capped.authorization_expires_at, Some(130));
    for invalid in ["0", "-1", "18446744073709551616", "invalid"] {
        let mut args = base.clone();
        args.extend(["--authorization-expires-at", invalid]);
        assert!(<EnrollmentCli as clap::Parser>::try_parse_from(args).is_err());
    }
    let mut duplicate = base.clone();
    duplicate.extend([
        "--authorization-expires-at",
        "130",
        "--authorization-expires-at",
        "140",
    ]);
    assert!(<EnrollmentCli as clap::Parser>::try_parse_from(duplicate).is_err());
    let mut absolute_only = base;
    let relative = absolute_only
        .iter()
        .position(|arg| *arg == "--authorization-seconds")
        .unwrap();
    absolute_only.drain(relative..=relative + 1);
    absolute_only.extend(["--authorization-expires-at", "130"]);
    assert!(<EnrollmentCli as clap::Parser>::try_parse_from(absolute_only).is_err());
}
