//! Opt-in v10 projection; historical diagnostic DTOs remain closed and unchanged.

use serde::{Deserialize, Serialize};
use volparossa_local_control::{
    PrivateStorageChallengeReadDetail, PrivateStorageChallengeReadOutcome as Outcome,
    PrivateStorageChallengeReadStep as Step,
};

use super::{Failure, flow_acquire, tls_close};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Detail {
    step: Step,
    #[serde(deserialize_with = "Option::deserialize")]
    returned_outcome: Option<Outcome>,
}

impl Detail {
    pub(super) fn from_wire(value: PrivateStorageChallengeReadDetail) -> Option<Self> {
        Some(Self {
            step: Step::try_from(value.step).ok()?,
            returned_outcome: value
                .returned_outcome
                .map(Outcome::try_from)
                .transpose()
                .ok()?,
        })
    }

    fn wire(self) -> PrivateStorageChallengeReadDetail {
        PrivateStorageChallengeReadDetail {
            step: self.step as i32,
            returned_outcome: self.returned_outcome.map(|value| value as i32),
        }
    }

    fn valid_for(self, failure: &Failure) -> bool {
        let Some(detail) = &failure.agent_detail else {
            return false;
        };
        let Some(challenge) = &detail.challenge else {
            return false;
        };
        let mut wire = challenge.wire();
        wire.read = Some(self.wire());
        volparossa_local_control::PrivateStorageRemoteDetail {
            stage: detail.stage as i32,
            deadline_scope: detail.deadline_scope as i32,
            tls_failure: detail.tls_failure.map(|value| value as i32),
            stream_failure: detail.stream_failure.map(|value| value as i32),
            challenge: Some(wire),
            flow_acquire: None,
        }
        .validate_rejection(
            volparossa_local_control::ControlResult::Unavailable,
            "CONTENT_UNAVAILABLE",
        )
        .is_ok()
    }
}

pub(super) fn project(
    failure: &Failure,
    flow: Option<flow_acquire::Detail>,
    read: Option<Detail>,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut value = serde_json::to_value(tls_close::Failure::new(failure, flow))?;
    if let Some(challenge) = value
        .pointer_mut("/agent_detail/challenge")
        .and_then(serde_json::Value::as_object_mut)
    {
        challenge.insert("read".into(), serde_json::to_value(read)?);
    }
    Ok(value)
}

pub(super) type Decoded = (Failure, Option<flow_acquire::Detail>, Option<Detail>);

pub(super) fn decode(mut value: serde_json::Value) -> Result<Decoded, serde_json::Error> {
    let read = if let Some(challenge) = value
        .pointer_mut("/agent_detail/challenge")
        .and_then(serde_json::Value::as_object_mut)
    {
        let read = challenge.remove("read").ok_or_else(|| {
            <serde_json::Error as serde::de::Error>::custom("missing challenge read field")
        })?;
        serde_json::from_value::<Option<Detail>>(read)?
    } else {
        None
    };
    let (failure, flow) = tls_close::Failure::decode(value)?;
    if read.is_some_and(|read| !read.valid_for(&failure)) {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "challenge read scope",
        ));
    }
    Ok((failure, flow, read))
}
