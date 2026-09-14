//! Read-only software battery/thermal budgets, not a physical safety guarantee.
//!
//! Linux ABI references: <https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-power>
//! and <https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-thermal>.
//! Class symlinks are normal sysfs links. No device names, serials, models or history
//! are exposed. Missing classes mean not exposed, not evidence of absent hardware.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde::Serialize;

use super::spare_capacity::Decision;

const MAX_FILE_BYTES: u64 = 4096;
const MAX_CLASS_ENTRIES: usize = 32;
const MAX_TRIPS: usize = 32;
// Three attributes per bounded trip plus bounded ordinary zone attributes.
const MAX_ZONE_ENTRIES: usize = MAX_TRIPS * 3 + 32;
const CACHE_LIFETIME: Duration = Duration::from_secs(1);
const BATTERY_PAUSE: u8 = 20;
const BATTERY_CANCEL: u8 = 5;
const THERMAL_PAUSE: i64 = 80_000;
const THERMAL_CANCEL: i64 = 90_000;
const TRIP_MARGIN: i64 = 5000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    NotExposed,
    NotPresent,
    Healthy,
    Pause,
    Cancel,
    Unknown,
}

impl State {
    fn decision(self) -> Decision {
        match self {
            Self::Cancel => Decision::Cancel,
            Self::Pause | Self::Unknown => Decision::Pause,
            Self::NotExposed | Self::NotPresent | Self::Healthy => Decision::Run,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) struct BatteryObservation {
    pub(super) state: State,
    pub(super) present_system_batteries: u8,
    pub(super) minimum_percent: Option<u8>,
    pub(super) incomplete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) struct ThermalObservation {
    pub(super) state: State,
    pub(super) observed_zones: u8,
    pub(super) maximum_millicelsius: Option<i64>,
    pub(super) incomplete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) struct DeviceObservation {
    pub(super) battery: BatteryObservation,
    pub(super) thermal: ThermalObservation,
}

impl Default for DeviceObservation {
    fn default() -> Self {
        Self {
            battery: BatteryObservation {
                state: State::Unknown,
                present_system_batteries: 0,
                minimum_percent: None,
                incomplete: true,
            },
            thermal: ThermalObservation {
                state: State::Unknown,
                observed_zones: 0,
                maximum_millicelsius: None,
                incomplete: true,
            },
        }
    }
}

impl DeviceObservation {
    pub(super) fn decision(self) -> Decision {
        match (self.battery.state.decision(), self.thermal.state.decision()) {
            (Decision::Cancel, _) | (_, Decision::Cancel) => Decision::Cancel,
            (Decision::Pause, _) | (_, Decision::Pause) => Decision::Pause,
            _ => Decision::Run,
        }
    }

    fn stale(mut self) -> Self {
        self.battery.incomplete = true;
        self.thermal.incomplete = true;
        if self.battery.state != State::Cancel {
            self.battery.state = State::Unknown;
        }
        if self.thermal.state != State::Cancel {
            self.thermal.state = State::Unknown;
        }
        self
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct DeviceBudget {
    cached: Option<(Instant, DeviceObservation)>,
}

impl DeviceBudget {
    pub(super) fn sample(&mut self) -> DeviceObservation {
        self.sample_from(Path::new("/sys/class"), Instant::now())
    }

    fn sample_from(&mut self, root: &Path, now: Instant) -> DeviceObservation {
        if let Some((at, observation)) = self.cached {
            if now
                .checked_duration_since(at)
                .is_some_and(|age| age < CACHE_LIFETIME)
            {
                return observation;
            }
        }
        let started = Instant::now();
        let mut observation = DeviceObservation {
            battery: batteries(&root.join("power_supply")),
            thermal: thermal(&root.join("thermal")),
        };
        if started.elapsed() >= CACHE_LIFETIME {
            // A slow read cannot make a stale healthy value fresh by timestamping it last.
            observation = observation.stale();
        }
        self.cached = Some((now, observation));
        observation
    }
}

fn scalar(path: &Path) -> Result<String, ErrorKind> {
    let mut value = String::new();
    File::open(path)
        .map_err(|error| error.kind())?
        .take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut value)
        .map_err(|error| error.kind())?;
    if value.len() as u64 > MAX_FILE_BYTES || value.contains('\0') {
        return Err(ErrorKind::InvalidData);
    }
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ErrorKind::InvalidData);
    }
    Ok(value.into())
}

fn optional(path: &Path) -> Result<Option<String>, ErrorKind> {
    match scalar(path) {
        Ok(value) => Ok(Some(value)),
        Err(ErrorKind::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

fn unsigned(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn temperature(value: &str) -> Option<i64> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    // Impossible sub-absolute-zero values, including kernel invalid-temperature
    // sentinels, are unavailable measurements rather than abundant thermal headroom.
    value.parse().ok().filter(|value| *value >= -273_150)
}

fn entries(path: &Path, maximum: usize) -> Result<(Vec<PathBuf>, bool), ErrorKind> {
    let mut paths = Vec::new();
    let mut incomplete = false;
    for (index, entry) in fs::read_dir(path)
        .map_err(|error| error.kind())?
        .enumerate()
    {
        if index == maximum {
            incomplete = true;
            break;
        }
        match entry {
            Ok(entry) => paths.push(entry.path()),
            Err(_) => incomplete = true,
        }
    }
    paths.sort();
    Ok((paths, incomplete))
}

fn observed_state(count: u8, incomplete: bool, decision: Decision) -> State {
    if decision == Decision::Cancel {
        State::Cancel
    } else if incomplete {
        State::Unknown
    } else if decision == Decision::Pause {
        State::Pause
    } else if count == 0 {
        State::NotPresent
    } else {
        State::Healthy
    }
}

fn battery_percent(path: &Path) -> Result<Option<u8>, ErrorKind> {
    let kind = scalar(&path.join("type"))?;
    if kind.len() > 64
        || !kind
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ErrorKind::InvalidData);
    }
    if kind != "Battery" {
        return Ok(None);
    }
    match optional(&path.join("scope"))?.as_deref() {
        Some("Device") => return Ok(None),
        Some("System") | None => {}
        _ => return Err(ErrorKind::InvalidData),
    }
    match optional(&path.join("present"))?.as_deref() {
        Some("0") => return Ok(None),
        Some("1") | None => {} // The power-supply ABI makes this attribute optional.
        _ => return Err(ErrorKind::InvalidData),
    }
    let value = unsigned(&scalar(&path.join("capacity"))?).ok_or(ErrorKind::InvalidData)?;
    Ok(Some(
        u8::try_from(value)
            .ok()
            .filter(|value| *value <= 100)
            .ok_or(ErrorKind::InvalidData)?,
    ))
}

fn batteries(root: &Path) -> BatteryObservation {
    let mut observation = BatteryObservation {
        state: State::NotPresent,
        present_system_batteries: 0,
        minimum_percent: None,
        incomplete: false,
    };
    let paths = match entries(root, MAX_CLASS_ENTRIES) {
        Ok((paths, incomplete)) => {
            observation.incomplete = incomplete;
            paths
        }
        Err(ErrorKind::NotFound) => {
            observation.state = State::NotExposed;
            return observation;
        }
        Err(_) => {
            observation.state = State::Unknown;
            observation.incomplete = true;
            return observation;
        }
    };
    for path in paths {
        match battery_percent(&path) {
            Ok(Some(percent)) => {
                observation.present_system_batteries += 1;
                observation.minimum_percent = Some(
                    observation
                        .minimum_percent
                        .map_or(percent, |old| old.min(percent)),
                );
            }
            Ok(None) => {}
            Err(_) => observation.incomplete = true,
        }
    }
    let decision = match observation.minimum_percent {
        Some(value) if value <= BATTERY_CANCEL => Decision::Cancel,
        Some(value) if value <= BATTERY_PAUSE => Decision::Pause,
        _ => Decision::Run,
    };
    observation.state = observed_state(
        observation.present_system_batteries,
        observation.incomplete,
        decision,
    );
    observation
}

fn trip_limits(root: &Path) -> (i64, i64, bool) {
    let mut pause = THERMAL_PAUSE;
    let mut cancel = THERMAL_CANCEL;
    let Ok((paths, mut incomplete)) = entries(root, MAX_ZONE_ENTRIES) else {
        return (pause, cancel, true);
    };
    let mut trips = BTreeSet::new();
    for path in paths {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            incomplete = true;
            continue;
        };
        let Some(rest) = name.strip_prefix("trip_point_") else {
            continue;
        };
        let number = rest
            .strip_suffix("_type")
            .or_else(|| rest.strip_suffix("_temp"))
            .or_else(|| rest.strip_suffix("_hyst"));
        let Some(index) = number
            .and_then(unsigned)
            .filter(|index| *index < MAX_TRIPS as u64)
        else {
            incomplete = true;
            continue;
        };
        trips.insert(index);
    }
    for trip in trips {
        let kind = scalar(&root.join(format!("trip_point_{trip}_type")));
        let raw = scalar(&root.join(format!("trip_point_{trip}_temp")));
        // Linux v6.12 handle_thermal_trip() skips this exact inactive/uninitialized
        // trip value. It is not a sensor failure or a temperature threshold. Keep
        // our software limits; never apply this exception to the actual zone temp.
        // https://github.com/torvalds/linux/blob/v6.12/drivers/thermal/thermal_core.c
        if raw.as_deref() == Ok("-274000")
            && matches!(
                kind.as_deref(),
                Ok("passive" | "hot" | "critical" | "active")
            )
        {
            continue;
        }
        let value = raw.ok().and_then(|value| temperature(&value));
        match (
            kind.as_deref(),
            value.and_then(|value| value.checked_sub(TRIP_MARGIN)),
        ) {
            (Ok("passive" | "hot"), Some(value)) => pause = pause.min(value),
            (Ok("critical"), Some(value)) => cancel = cancel.min(value),
            (Ok("active"), Some(_)) => {}
            _ => incomplete = true,
        }
    }
    (pause, cancel, incomplete)
}

fn thermal(root: &Path) -> ThermalObservation {
    let mut observation = ThermalObservation {
        state: State::NotPresent,
        observed_zones: 0,
        maximum_millicelsius: None,
        incomplete: false,
    };
    let paths = match entries(root, MAX_CLASS_ENTRIES) {
        Ok((paths, incomplete)) => {
            observation.incomplete = incomplete;
            paths
        }
        Err(ErrorKind::NotFound) => {
            observation.state = State::NotExposed;
            return observation;
        }
        Err(_) => {
            observation.state = State::Unknown;
            observation.incomplete = true;
            return observation;
        }
    };
    let mut decision = Decision::Run;
    for path in paths {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            observation.incomplete = true;
            continue;
        };
        let Some(index) = name.strip_prefix("thermal_zone") else {
            continue;
        };
        if unsigned(index).is_none() {
            observation.incomplete = true;
            continue;
        }
        let Some(value) = scalar(&path.join("temp"))
            .ok()
            .and_then(|value| temperature(&value))
        else {
            observation.incomplete = true;
            continue;
        };
        observation.observed_zones += 1;
        observation.maximum_millicelsius = Some(
            observation
                .maximum_millicelsius
                .map_or(value, |old| old.max(value)),
        );
        let (pause, cancel, incomplete) = trip_limits(&path);
        observation.incomplete |= incomplete;
        if value >= cancel {
            decision = Decision::Cancel;
        } else if value >= pause && decision != Decision::Cancel {
            decision = Decision::Pause;
        }
    }
    observation.state =
        observed_state(observation.observed_zones, observation.incomplete, decision);
    observation
}

#[cfg(test)]
mod tests;
