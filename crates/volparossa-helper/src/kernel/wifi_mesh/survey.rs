//! Passive channel counters from nl80211; never trigger a scan, retune or synthetic load.

use super::super::{HardDeadline, KernelError, attributes};
use super::netlink::{
    GET_SURVEY, IFINDEX, NEW_SURVEY_RESULTS, SURVEY_INFO, Wireless, field, nested, number,
    number_field,
};
use super::{MeshSurvey, index_attributes};

pub(super) fn query(
    wireless: &mut Wireless,
    index: u32,
    frequency: u32,
    deadline: HardDeadline,
) -> Result<Option<MeshSurvey>, KernelError> {
    match wireless.dump(
        GET_SURVEY,
        NEW_SURVEY_RESULTS,
        &index_attributes(index)?,
        deadline,
    ) {
        Ok(records) => parse(&records, index, frequency),
        Err(error) if error.is_errno(libc::EOPNOTSUPP) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn parse(
    records: &[Vec<u8>],
    index: u32,
    frequency: u32,
) -> Result<Option<MeshSurvey>, KernelError> {
    if records.len() > volparossa_routing::MAX_WIFI_MESH_OBSERVATIONS {
        return Err(KernelError::Malformed);
    }
    let mut observed = false;
    let mut result = None;
    for record in records {
        let fields = attributes(record)?;
        if number_field(&fields, IFINDEX)? != index {
            return Err(KernelError::Malformed);
        }
        let survey = nested(&fields, SURVEY_INFO)?;
        let channel = number_field(&survey, 1)?; // NL80211_SURVEY_INFO_FREQUENCY
        let in_use = field(&survey, 3)?;
        if in_use.is_some_and(|value| !value.is_empty()) {
            return Err(KernelError::Malformed);
        }
        let active_ms = counter(&survey, 4)?; // NL80211_SURVEY_INFO_TIME, milliseconds
        let busy_ms = counter(&survey, 5)?; // NL80211_SURVEY_INFO_TIME_BUSY
        if matches!((active_ms, busy_ms), (Some(active), Some(busy)) if busy > active) {
            return Err(KernelError::Malformed);
        }
        let offset = field(&survey, 12)?.map(number).transpose()?;
        if in_use.is_none() {
            continue;
        }
        if observed || channel != frequency || offset.is_some_and(|value| value != 0) {
            return Err(KernelError::Invalid);
        }
        observed = true;
        // Drivers expose these filled flags independently. Absence is unavailable, never zero
        // occupancy; malformed present values above remain errors, even on another channel.
        result = active_ms
            .zip(busy_ms)
            .map(|(active_ms, busy_ms)| MeshSurvey { active_ms, busy_ms });
    }
    Ok(result)
}

fn counter(fields: &[(u16, &[u8])], kind: u16) -> Result<Option<u64>, KernelError> {
    field(fields, kind)?
        .map(|value| {
            value
                .try_into()
                .map(u64::from_ne_bytes)
                .map_err(|_| KernelError::Malformed)
        })
        .transpose()
}
