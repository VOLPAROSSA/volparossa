// SPDX-License-Identifier: GPL-3.0-only
//! Hosted-only unit tests; synthetic JSON and toy children establish no sensor accuracy.

use std::net::{Ipv4Addr, SocketAddrV4};

use chrono::Utc;
use serde_json::{Value, json};

use super::*;

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_750_000_000)
}

fn tpv(epoch: SystemTime) -> Value {
    json!({"class":"TPV", "device":"/private/gnss-test-source", "datum":"WGS84", "mode":3,
        "time":DateTime::<Utc>::from(epoch).to_rfc3339(), "lat":53.809_394_444_444_45,
        "lon":2.12955, "altHAE":73.0, "epx":0.001, "epy":0.001, "epv":0.001})
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn frames(current: SystemTime) -> Vec<u8> {
    [300, 200, 100]
        .into_iter()
        .flat_map(|millis| {
            let mut line = bytes(&tpv(current - Duration::from_millis(millis)));
            line.push(b'\n');
            line
        })
        .collect()
}

fn endpoint() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2948)
}

#[test]
fn complete_epochs_are_distinct_increasing_and_keep_only_latest() {
    let mut epochs = Epochs::default();
    for (index, age) in [300, 200, 100].into_iter().enumerate() {
        let epoch = now() - Duration::from_millis(age);
        assert_eq!(epochs.push(&bytes(&tpv(epoch)), now()), Ok(index == 2));
        assert_eq!(epochs.count, u8::try_from(index + 1).unwrap());
        assert_eq!(epochs.latest.as_ref().unwrap().epoch, epoch);
    }
    assert_eq!(epochs.device.as_deref(), Some("/private/gnss-test-source"));
}

#[test]
fn duplicate_epoch_does_not_count_and_changed_or_backward_epoch_is_rejected() {
    let mut epochs = Epochs::default();
    let value = tpv(now() - Duration::from_millis(100));
    assert_eq!(epochs.push(&bytes(&value), now()), Ok(false));
    assert_eq!(epochs.push(&bytes(&value), now()), Ok(false));
    assert_eq!(epochs.count, 1);
    let mut changed = value;
    changed["lat"] = json!(54.0);
    assert_eq!(epochs.push(&bytes(&changed), now()), Err(Failure::Epoch));
    assert_eq!(
        epochs.push(&bytes(&tpv(now() - Duration::from_millis(200))), now()),
        Err(Failure::Epoch)
    );
}

#[test]
fn partial_tpv_fields_never_merge_and_missing_datum_or_msl_never_substitutes() {
    for missing in ["datum", "lat", "lon", "altHAE", "time", "device"] {
        let mut epochs = Epochs::default();
        let mut partial = tpv(now());
        partial.as_object_mut().unwrap().remove(missing);
        partial["altMSL"] = json!(65.0);
        for _ in 0..3 {
            assert_eq!(epochs.push(&bytes(&partial), now()), Ok(false));
        }
        assert_eq!(epochs.count, 0);
        assert!(epochs.latest.is_none());
    }
    let mut epochs = Epochs::default();
    for missing in ["lat", "lon", "altHAE"] {
        let mut partial = tpv(now());
        partial.as_object_mut().unwrap().remove(missing);
        assert_eq!(epochs.push(&bytes(&partial), now()), Ok(false));
    }
    assert!(epochs.latest.is_none());
}

#[test]
fn explicit_unknown_datum_and_invalid_geometry_fail_closed() {
    for (key, value) in [
        ("datum", json!("UNKNOWN")),
        ("datum", json!("NAD83")),
        ("lat", json!(91)),
        ("lon", json!(-181)),
        ("altHAE", json!(1.0e9)),
    ] {
        let mut value_tpv = tpv(now());
        value_tpv[key] = value;
        assert_eq!(
            Epochs::default().push(&bytes(&value_tpv), now()),
            Err(Failure::Geometry)
        );
    }
    let mut negative_height = tpv(now());
    negative_height["altHAE"] = json!(-20.0);
    negative_height["altMSL"] = json!(-50.0);
    assert_eq!(
        Epochs::default().push(&bytes(&negative_height), now()),
        Ok(false)
    );
}

#[test]
fn malformed_nonfinite_duplicate_keys_and_ill_typed_frames_are_closed() {
    for raw in [
        b"not-json".as_slice(),
        b"\xff",
        b"[]",
        b"{\"class\":\"TPV\",\"mode\":3,\"mode\":2}",
        b"{\"class\":\"TPV\",\"class\":\"SKY\"}",
        b"{\"class\":\"TPV\",\"mode\":3,\"lat\":1e999}",
        b"{\"class\":\"TPV\",\"mode\":3,\"altHAE\":NaN}",
        b"{\"class\":\"ERROR\",\"message\":\"private\"}",
    ] {
        assert_eq!(Epochs::default().push(raw, now()), Err(Failure::Input));
    }
    for mode in [0, 1, 2] {
        let mut value = tpv(now());
        value["mode"] = json!(mode);
        assert_eq!(Epochs::default().push(&bytes(&value), now()), Ok(false));
    }
    assert_eq!(
        Epochs::default().push(b"{\"class\":\"SKY\",\"private\":\"ignored\"}", now()),
        Ok(false)
    );
}

#[test]
fn device_switch_and_unbounded_or_control_bindings_are_rejected_without_export() {
    let mut epochs = Epochs::default();
    epochs
        .push(&bytes(&tpv(now() - Duration::from_millis(100))), now())
        .unwrap();
    for device in [
        "/private/other".to_owned(),
        String::new(),
        "x".repeat(257),
        "private\npath".to_owned(),
    ] {
        let mut value = tpv(now());
        value["device"] = json!(device);
        assert_eq!(epochs.push(&bytes(&value), now()), Err(Failure::Device));
    }
}

#[test]
fn receiver_timestamp_validates_real_age_future_precision_and_rfc3339() {
    let text = |time| DateTime::<Utc>::from(time).to_rfc3339();
    assert!(receiver_time(&text(now() - MAX_AGE), now()).is_ok());
    for epoch in [
        now() - MAX_AGE - Duration::from_nanos(1),
        now() + Duration::from_nanos(1),
    ] {
        assert_eq!(receiver_time(&text(epoch), now()), Err(Failure::Time));
    }
    for invalid in [
        "",
        "private time",
        "2016-12-31T23:59:60Z",
        "1969-12-31T23:59:59Z",
    ] {
        assert_eq!(receiver_time(invalid, now()), Err(Failure::Time));
    }
    assert_eq!(receiver_time(&"x".repeat(65), now()), Err(Failure::Time));
}

#[test]
fn evaluation_clock_rejects_backward_steps_and_wall_monotonic_divergence() {
    let base = Instant::now();
    let mut clock = Clock {
        wall: now(),
        monotonic: base,
        last_wall: now(),
    };
    assert_eq!(
        clock.check(
            now() + Duration::from_secs(1),
            base + Duration::from_secs(1)
        ),
        Ok(now() + Duration::from_secs(1))
    );
    assert_eq!(
        clock.check(
            now() + Duration::from_millis(900),
            base + Duration::from_millis(1100)
        ),
        Err(Failure::Clock)
    );
    assert_eq!(
        clock.check(now() - Duration::from_nanos(1), base),
        Err(Failure::Clock)
    );
    assert_eq!(
        clock.check(
            now() + Duration::from_secs(2),
            base + Duration::from_secs(1)
        ),
        Err(Failure::Clock)
    );
    assert_eq!(
        clock.check(now(), base - Duration::from_nanos(1)),
        Err(Failure::Clock)
    );
}

#[test]
fn radius_endpoint_and_command_are_fixed_and_sanitized() {
    for radius in [
        f64::NAN,
        f64::INFINITY,
        0.0,
        -1.0,
        0.5,
        MAX_DPS_RADIUS_METRES + 1.0,
    ] {
        assert_eq!(options(endpoint(), radius), Err(Failure::Options));
    }
    for port in [0, 53, 1024] {
        assert_eq!(
            options(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), 10.0),
            Err(Failure::Options)
        );
    }
    assert_eq!(
        options(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 2948), 10.0),
        Err(Failure::Options)
    );
    for radius in [1.0, MAX_DPS_RADIUS_METRES] {
        assert_eq!(options(endpoint(), radius), Ok(()));
    }
    let command = gpspipe(endpoint()).unwrap();
    assert_eq!(command.as_std().get_program(), "gpspipe");
    assert_eq!(
        command.as_std().get_args().collect::<Vec<_>>(),
        ["-w", "-B", "-n", "32", "-x", "8", "127.0.0.1:2948"]
    );
    let environment = command
        .as_std()
        .get_envs()
        .map(|(key, _)| key.to_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(environment, ["LANG", "PATH"]);
}

#[tokio::test]
async fn stream_bounds_are_enforced_before_extending_allocations() {
    let exact = [vec![b' '; MAX_LINE_BYTES - 1], vec![b'\n']].concat();
    let mut reader = BufReader::new(exact.as_slice());
    let mut total = 0;
    assert_eq!(
        bounded_line(&mut reader, &mut total)
            .await
            .unwrap()
            .unwrap()
            .len(),
        MAX_LINE_BYTES
    );
    assert_eq!(total, MAX_LINE_BYTES);
    let oversized = [vec![b' '; MAX_LINE_BYTES], vec![b'\n']].concat();
    let mut reader = BufReader::new(oversized.as_slice());
    assert_eq!(
        bounded_line(&mut reader, &mut 0).await,
        Err(Failure::Bounds)
    );
    let mut reader = BufReader::new(b"x\n".as_slice());
    assert_eq!(
        bounded_line(&mut reader, &mut (MAX_TOTAL_BYTES - 1)).await,
        Err(Failure::Bounds)
    );
    let mut reader = BufReader::new(b"partial".as_slice());
    assert_eq!(bounded_line(&mut reader, &mut 0).await, Err(Failure::Input));
}

#[tokio::test]
async fn three_frames_feed_existing_assessment_without_exporting_position_or_history() {
    let input = frames(SystemTime::now());
    let claim = collect(BufReader::new(input.as_slice()), &mut Clock::new())
        .await
        .unwrap();
    let report = assessment(&claim, 10.0, SystemTime::now()).unwrap();
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["quality"], "SingleClaim");
    assert_eq!(value["eligible_claims"], 1);
    assert_eq!(value["declared_independence_groups"], 1);
    assert_eq!(value["limitations"].as_array().unwrap().len(), 7);
    assert_eq!(value["provenance"]["navigation_authentication"], "unknown");
    assert_eq!(value["provenance"]["uncertainty_confidence"], "unknown");
    assert_eq!(value["provenance"]["physical_datum_verified"], false);
    let text = serde_json::to_string(&value).unwrap();
    for private in [
        "53.809",
        "2.12955",
        "73.0",
        "/private/gnss",
        "observed_at",
        "source_id",
        "timestamp",
        "epx",
    ] {
        assert!(!text.contains(private));
    }
    let errors = [
        Failure::Input,
        Failure::Time,
        Failure::Device,
        Failure::Geometry,
    ];
    for error in errors {
        assert!(!format!("{error:?} {error}").contains("/private/gnss"));
    }
}

#[test]
fn request_uses_one_ephemeral_source_group_and_unknown_authentication_with_existing_frame() {
    let mut epochs = Epochs::default();
    epochs.push(&bytes(&tpv(now())), now()).unwrap();
    let claim = epochs.latest.unwrap();
    let first = request_for(&claim, 10.0).unwrap();
    let second = request_for(&claim, 10.0).unwrap();
    assert_eq!(first.dps_version, DPS_SERVICE_VERSION);
    assert_eq!(first.maximum_age_ms, 5000);
    assert_eq!(first.observations.len(), 1);
    let observation = &first.observations[0];
    assert_eq!(observation.source_kind, SourceKind::Gnss as i32);
    assert_eq!(
        observation.navigation_authentication,
        NavigationAuthentication::Unknown as i32
    );
    assert_eq!(
        observation.supplied_radius_metres.to_bits(),
        10.0_f64.to_bits()
    );
    assert_eq!(
        observation.frame.as_ref().unwrap().kind,
        FrameKind::Wgs84Ecef as i32
    );
    assert!(
        observation
            .frame
            .as_ref()
            .unwrap()
            .local_frame_id
            .is_empty()
    );
    assert_eq!(observation.frame, first.desired_frame);
    let actual = [
        observation.x_metres,
        observation.y_metres,
        observation.z_metres,
    ];
    for (actual, expected) in actual
        .into_iter()
        .zip(claim.position.to_ecef().unwrap().components_metres())
    {
        assert_eq!(actual.to_bits(), expected.to_bits());
    }
    for id in [
        &observation.observation_id,
        &observation.source_id,
        &observation.declared_independence_group,
    ] {
        assert_eq!(id.len(), 16);
    }
    assert_ne!(observation.source_id, second.observations[0].source_id);
    assert_ne!(
        observation.declared_independence_group,
        second.observations[0].declared_independence_group
    );
    let result = first.assess(unix_millis(now()).unwrap()).unwrap();
    assert_eq!(result.limitations, vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(result.status, AssessmentStatus::SingleClaim as i32);
}

#[tokio::test]
async fn eof_partial_and_line_count_cannot_produce_assessment() {
    assert!(matches!(
        collect(BufReader::new(b"".as_slice()), &mut Clock::new()).await,
        Err(Failure::Incomplete)
    ));
    let input = b"{\"class\":\"SKY\"}\n".repeat(MAX_LINES);
    assert!(matches!(
        collect(BufReader::new(input.as_slice()), &mut Clock::new()).await,
        Err(Failure::Bounds)
    ));
}

fn toy(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .kill_on_drop(true);
    command
}

#[tokio::test]
async fn owned_live_child_is_killed_and_reaped_without_signalling_any_server() {
    let mut command = toy("/bin/sleep");
    command.arg("60");
    let mut child = command.spawn().unwrap();
    finish_child(&mut child, Instant::now() + TOTAL_BUDGET)
        .await
        .unwrap();
    assert!(child.try_wait().unwrap().is_some());
}

#[tokio::test]
async fn cancellation_of_owned_collection_joins_child_before_returning() {
    let mut command = toy("/bin/sleep");
    command.arg("60");
    let child = command.spawn().unwrap();
    let (sender, receiver) = watch::channel(false);
    let cancellation = Cancel(sender);
    let owner = tokio::spawn(own_child(
        child,
        receiver,
        Instant::now() + TOTAL_BUDGET,
        10.0,
    ));
    drop(cancellation);
    assert!(matches!(owner.await.unwrap(), Err(Failure::Interrupted)));
}

#[tokio::test]
async fn child_failure_and_collection_timeout_never_release_success() {
    let child = toy("/bin/false").spawn().unwrap();
    let (_sender, receiver) = watch::channel(false);
    assert!(
        own_child(child, receiver, Instant::now() + TOTAL_BUDGET, 10.0)
            .await
            .is_err()
    );
    let mut command = toy("/bin/sleep");
    command.arg("60");
    let child = command.spawn().unwrap();
    let (_sender, receiver) = watch::channel(false);
    let deadline = Instant::now() + CLEANUP_RESERVE + Duration::from_millis(10);
    assert!(matches!(
        own_child(child, receiver, deadline, 10.0).await,
        Err(Failure::Deadline)
    ));
}

#[tokio::test]
async fn actual_owned_stdout_pipeline_succeeds_only_after_join() {
    let mut command = toy("/usr/bin/printf");
    command
        .arg("%s")
        .arg(String::from_utf8(frames(SystemTime::now())).unwrap());
    let child = command.spawn().unwrap();
    let (_sender, receiver) = watch::channel(false);
    let report = own_child(child, receiver, Instant::now() + TOTAL_BUDGET, 10.0)
        .await
        .unwrap();
    assert_eq!(report.quality, "SingleClaim");
}
