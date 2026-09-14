use super::*;
use std::os::unix::fs::symlink;

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("power_supply")).unwrap();
    fs::create_dir(root.path().join("thermal")).unwrap();
    root
}

fn attributes(root: &Path, name: &str, values: &[(&str, &str)]) -> PathBuf {
    let directory = root.join(name);
    fs::create_dir(&directory).unwrap();
    for (file, value) in values {
        fs::write(directory.join(file), value).unwrap();
    }
    directory
}

#[test]
fn battery_reserve_applies_on_ac_while_device_scope_and_absent_batteries_are_ignored() {
    let root = fixture();
    let supplies = root.path().join("power_supply");
    attributes(&supplies, "AC", &[("type", "Mains\n"), ("online", "1\n")]);
    attributes(
        &supplies,
        "peripheral",
        &[
            ("type", "Battery"),
            ("scope", "Device"),
            ("capacity", "malformed"),
        ],
    );
    attributes(
        &supplies,
        "empty_slot",
        &[("type", "Battery"), ("present", "0")],
    );
    assert_eq!(batteries(&supplies).state, State::NotPresent);
    let device = attributes(
        root.path(),
        "private-device-name",
        &[
            ("type", "Battery"),
            ("capacity", "50"),
            ("status", "Charging"),
        ],
    );
    symlink(&device, supplies.join("BAT0")).unwrap(); // The normal Linux class-link layout.
    for (percent, expected) in [
        (21, State::Healthy),
        (20, State::Pause),
        (6, State::Pause),
        (5, State::Cancel),
        (0, State::Cancel),
    ] {
        fs::write(device.join("capacity"), percent.to_string()).unwrap();
        let actual = batteries(&supplies);
        assert_eq!(actual.state, expected);
        assert_eq!(actual.present_system_batteries, 1);
        assert_eq!(actual.minimum_percent, Some(percent));
        assert!(!actual.incomplete);
        assert!(
            !serde_json::to_string(&actual)
                .unwrap()
                .contains("private-device-name")
        );
    }
    fs::write(device.join("scope"), "unknown").unwrap();
    assert_eq!(batteries(&supplies).state, State::Unknown);
    fs::write(device.join("scope"), "System").unwrap();
    fs::write(device.join("present"), "2").unwrap();
    assert_eq!(batteries(&supplies).state, State::Unknown);
}

#[test]
fn thermal_thresholds_use_each_actual_zone_and_its_passive_hot_or_critical_margin() {
    let root = fixture();
    let thermal_root = root.path().join("thermal");
    let first = attributes(
        &thermal_root,
        "thermal_zone0",
        &[
            ("temp", "70000"),
            ("trip_point_0_type", "passive"),
            ("trip_point_0_temp", "76000"),
        ],
    );
    attributes(&thermal_root, "thermal_zone1", &[("temp", "74000")]);
    assert_eq!(thermal(&thermal_root).state, State::Healthy); // Do not compare zone1 with zone0's lower trip.
    fs::write(first.join("temp"), "71000").unwrap();
    assert_eq!(thermal(&thermal_root).state, State::Pause);
    fs::write(first.join("trip_point_0_type"), "hot").unwrap();
    fs::write(first.join("trip_point_0_temp"), "60000").unwrap();
    fs::write(first.join("temp"), "55000").unwrap();
    assert_eq!(thermal(&thermal_root).state, State::Pause);
    fs::write(first.join("trip_point_0_type"), "critical").unwrap();
    fs::write(first.join("trip_point_0_temp"), "70000").unwrap();
    fs::write(first.join("temp"), "65000").unwrap();
    assert_eq!(thermal(&thermal_root).state, State::Cancel);
    fs::write(first.join("trip_point_0_type"), "active").unwrap();
    for (value, state) in [
        (79_999, State::Healthy),
        (80_000, State::Pause),
        (90_000, State::Cancel),
    ] {
        fs::write(first.join("temp"), value.to_string()).unwrap();
        assert_eq!(thermal(&thermal_root).state, state);
    }
    fs::write(first.join("temp"), "-1000").unwrap();
    assert_eq!(thermal(&thermal_root).state, State::Healthy);
    fs::write(first.join("temp"), "-274000").unwrap();
    assert_eq!(thermal(&thermal_root).state, State::Unknown);
    // A real temperature plus an inactive Linux trip slot still uses software
    // thresholds, unlike an unavailable current-temperature measurement above.
    fs::write(first.join("trip_point_0_type"), "passive").unwrap();
    fs::write(first.join("trip_point_0_temp"), "-274000").unwrap();
    for (value, state) in [
        (37_000, State::Healthy),
        (80_000, State::Pause),
        (90_000, State::Cancel),
    ] {
        fs::write(first.join("temp"), value.to_string()).unwrap();
        assert_eq!(thermal(&thermal_root).state, state);
    }
    fs::write(first.join("trip_point_0_temp"), "-274001").unwrap();
    fs::write(first.join("temp"), "37000").unwrap();
    assert_eq!(thermal(&thermal_root).state, State::Unknown);
}

#[test]
fn missing_classes_unknown_exposed_sensors_and_bounded_overflow_never_hide_observed_critical() {
    let missing = tempfile::tempdir().unwrap();
    let mut budget = DeviceBudget::default();
    let observation = budget.sample_from(missing.path(), Instant::now());
    assert_eq!(observation.battery.state, State::NotExposed);
    assert_eq!(observation.thermal.state, State::NotExposed);
    assert_eq!(DeviceObservation::default().decision(), Decision::Pause);
    let root = fixture();
    assert_eq!(
        thermal(&root.path().join("thermal")).state,
        State::NotPresent
    );
    let battery = attributes(
        &root.path().join("power_supply"),
        "BAT0",
        &[("type", "Battery"), ("capacity", "101")],
    );
    assert_eq!(
        batteries(&root.path().join("power_supply")).state,
        State::Unknown
    );
    fs::write(battery.join("capacity"), "9".repeat(4097)).unwrap();
    assert_eq!(
        batteries(&root.path().join("power_supply")).state,
        State::Unknown
    );
    attributes(
        &root.path().join("thermal"),
        "thermal_zone0",
        &[("temp", "bad")],
    );
    let hot = attributes(
        &root.path().join("thermal"),
        "thermal_zone1",
        &[("temp", "90000")],
    );
    let observation = DeviceBudget::default().sample_from(root.path(), Instant::now());
    assert_eq!(observation.decision(), Decision::Cancel);
    assert!(observation.thermal.incomplete);
    fs::write(hot.join("temp"), "50000").unwrap();
    for number in 0..=MAX_TRIPS {
        fs::write(hot.join(format!("trip_point_{number}_type")), "passive").unwrap();
        fs::write(hot.join(format!("trip_point_{number}_temp")), "90000").unwrap();
    }
    assert!(trip_limits(&hot).2);
    let crowded = fixture();
    for number in 0..=MAX_CLASS_ENTRIES {
        attributes(
            &crowded.path().join("power_supply"),
            &format!("BAT{number}"),
            &[("type", "Battery"), ("capacity", "50")],
        );
    }
    let observed = batteries(&crowded.path().join("power_supply"));
    assert_eq!(observed.state, State::Unknown);
    assert!(usize::from(observed.present_system_batteries) <= MAX_CLASS_ENTRIES);
}

#[test]
fn cached_measurement_expires_at_one_second_and_fresh_failure_replaces_old_health() {
    let root = fixture();
    let battery = attributes(
        &root.path().join("power_supply"),
        "BAT0",
        &[("type", "Battery"), ("capacity", "50")],
    );
    let start = Instant::now();
    let mut budget = DeviceBudget::default();
    assert_eq!(
        budget.sample_from(root.path(), start).decision(),
        Decision::Run
    );
    fs::write(battery.join("capacity"), "5").unwrap();
    assert_eq!(
        budget
            .sample_from(root.path(), start + Duration::from_millis(999))
            .decision(),
        Decision::Run
    );
    let critical = budget.sample_from(root.path(), start + Duration::from_secs(1));
    assert_eq!(critical.decision(), Decision::Cancel);
    fs::remove_file(battery.join("capacity")).unwrap(); // Only this test-owned temporary scalar.
    let unknown = budget.sample_from(root.path(), start + Duration::from_secs(2));
    assert_eq!(unknown.decision(), Decision::Pause);
    assert_eq!(unknown.battery.state, State::Unknown);
    assert_eq!(critical.stale().decision(), Decision::Cancel);
    assert_eq!(
        DeviceObservation::default().stale().decision(),
        Decision::Pause
    );
}
