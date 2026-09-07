//! Count-only receiver observations and authenticated, lease-bound sender budgets.

use super::{
    HelperProtocolError, HelperRequest, HelperResponse, HelperResult, MAX_HELPER_PATHS,
    WireguardRole, context, handle, helper_request::Operation, helper_response::Outcome,
    operation_digest, validate_request, validate_response,
};
use prost::Message;
use std::collections::BTreeSet;

/// Refresh an already budget-required Exit lease, never select an arbitrary interface.
#[derive(Clone, PartialEq, Message)]
pub struct ApplyDownlinkBudget {
    /// Exact route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Helper-issued context capability.
    #[prost(bytes = "vec", tag = "2")]
    pub context_handle: Vec<u8>,
    /// Helper-issued Exit endpoint capability.
    #[prost(bytes = "vec", tag = "3")]
    pub lease_handle: Vec<u8>,
    /// Canonical original signed adjacent budget. The helper verifies its signature and grant.
    #[prost(bytes = "vec", tag = "4")]
    pub signed_budget: Vec<u8>,
}

/// Install one runtime-long count-only NETDEV ingress owner, with no policing or redirection.
#[derive(Clone, PartialEq, Message)]
pub struct InstallReceiveAccounting {
    /// Ephemeral node accounting runtime, not a browsing identity.
    #[prost(bytes = "vec", tag = "1")]
    pub accounting_runtime_id: Vec<u8>,
    /// One bounded physical netdevice name, resolved and pinned by the helper.
    #[prost(string, tag = "2")]
    pub interface: String,
}

/// Read one exact accounting owner.
#[derive(Clone, PartialEq, Message)]
pub struct InspectReceiveAccounting {
    /// Exact node accounting runtime.
    #[prost(bytes = "vec", tag = "1")]
    pub accounting_runtime_id: Vec<u8>,
    /// Helper-issued accounting capability.
    #[prost(bytes = "vec", tag = "2")]
    pub accounting_handle: Vec<u8>,
}

/// Remove one exact count-only owner; route-only cleanup does not remove it.
#[derive(Clone, PartialEq, Message)]
pub struct DestroyReceiveAccounting {
    /// Exact node accounting runtime.
    #[prost(bytes = "vec", tag = "1")]
    pub accounting_runtime_id: Vec<u8>,
    /// Helper-issued accounting capability.
    #[prost(bytes = "vec", tag = "2")]
    pub accounting_handle: Vec<u8>,
}

/// Kernel-accepted budget metadata, not a throughput or ISP capacity guarantee.
#[derive(Clone, PartialEq, Message)]
pub struct AppliedDownlinkBudget {
    /// Exact context and endpoint capability from the request.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Exact endpoint capability.
    #[prost(bytes = "vec", tag = "2")]
    pub lease_handle: Vec<u8>,
    /// Strictly increasing receiver-signed sequence.
    #[prost(uint64, tag = "3")]
    pub sequence: u64,
    /// Zero means closed. Expiry never changes this into unlimited traffic.
    #[prost(uint64, tag = "4")]
    pub rate_bytes_per_second: u64,
    /// Signed finite token burst.
    #[prost(uint32, tag = "5")]
    pub burst_bytes: u32,
    /// Signed wall-clock expiry; helper also pins a monotone kernel deadline.
    #[prost(uint64, tag = "6")]
    pub expires_at_ms: u64,
    /// Maximum queued inner payload tail; not already transmitted ISP bytes.
    #[prost(uint32, tag = "7")]
    pub maximum_queued_bytes: u32,
}

/// Exact kernel-resolved receive accounting identity.
#[derive(Clone, PartialEq, Message)]
pub struct InstalledReceiveAccounting {
    /// Exact runtime from the install request.
    #[prost(bytes = "vec", tag = "1")]
    pub accounting_runtime_id: Vec<u8>,
    /// New helper-issued owner capability.
    #[prost(bytes = "vec", tag = "2")]
    pub accounting_handle: Vec<u8>,
    /// Pinned physical ingress interface index.
    #[prost(uint32, tag = "3")]
    pub ingress_ifindex: u32,
}

/// Bytes and packets counted at the same NETDEV ingress hook.
#[derive(Clone, PartialEq, Message)]
pub struct ReceiveByteCounters {
    /// Cumulative skb bytes; not NIC/ISP wire-byte accounting.
    #[prost(uint64, tag = "1")]
    pub bytes: u64,
    /// Cumulative packets at this hook.
    #[prost(uint64, tag = "2")]
    pub packets: u64,
}

/// One helper-owned outer UDP tuple, with addresses omitted from the public helper response.
#[derive(Clone, PartialEq, Message)]
pub struct ManagedReceiveCounter {
    /// Existing ephemeral route context.
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    /// Existing path ordinal.
    #[prost(uint32, tag = "2")]
    pub path_id: u32,
    /// Client remains owner traffic; only Relay/Exit roles are contributed traffic.
    #[prost(enumeration = "WireguardRole", tag = "3")]
    pub role: i32,
    /// Same-hook counter for this exact owned tuple.
    #[prost(message, optional, tag = "4")]
    pub counters: Option<ReceiveByteCounters>,
}

/// Complete bounded same-hook snapshot. No bandwidth estimate or endpoint history is persisted.
#[derive(Clone, PartialEq, Message)]
pub struct ReceiveAccountingSnapshot {
    /// Exact accounting runtime.
    #[prost(bytes = "vec", tag = "1")]
    pub accounting_runtime_id: Vec<u8>,
    /// Exact owner capability.
    #[prost(bytes = "vec", tag = "2")]
    pub accounting_handle: Vec<u8>,
    /// Total ingress bytes, including owner and unmanaged traffic.
    #[prost(message, optional, tag = "3")]
    pub total: Option<ReceiveByteCounters>,
    /// Every live managed tuple on this interface, at most 128, canonically ordered.
    #[prost(message, repeated, tag = "4")]
    pub managed: Vec<ManagedReceiveCounter>,
}

/// Idempotent exact accounting-owner removal.
#[derive(Clone, PartialEq, Message)]
pub struct DestroyedReceiveAccounting {
    /// Exact accounting runtime.
    #[prost(bytes = "vec", tag = "1")]
    pub accounting_runtime_id: Vec<u8>,
    /// Exact owner capability.
    #[prost(bytes = "vec", tag = "2")]
    pub accounting_handle: Vec<u8>,
    /// Whether that exact owner existed before removal.
    #[prost(bool, tag = "3")]
    pub existed: bool,
}

pub(super) fn validate_apply(value: &ApplyDownlinkBudget) -> Result<(), HelperProtocolError> {
    context(&value.route_context_id)?;
    handle(&value.context_handle)?;
    handle(&value.lease_handle)?;
    if !(1..=2048).contains(&value.signed_budget.len()) {
        return Err(HelperProtocolError::Invalid("signed receive budget size"));
    }
    Ok(())
}

pub(super) fn validate_install(
    value: &InstallReceiveAccounting,
) -> Result<(), HelperProtocolError> {
    context(&value.accounting_runtime_id)?;
    let name = value.interface.as_bytes();
    if !(1..=15).contains(&name.len())
        || matches!(name, b"." | b"..")
        || !name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(HelperProtocolError::Invalid("receive accounting interface"));
    }
    Ok(())
}

pub(super) fn validate_applied(value: &AppliedDownlinkBudget) -> Result<(), HelperProtocolError> {
    context(&value.route_context_id)?;
    handle(&value.lease_handle)?;
    if value.sequence == 0
        || value.rate_bytes_per_second > 125_000_000_000
        || value.burst_bytes > 65_536
        || value.expires_at_ms == 0
        || value.maximum_queued_bytes == 0
        || value.maximum_queued_bytes > 262_144
    {
        return Err(HelperProtocolError::Invalid("applied receive budget"));
    }
    Ok(())
}

pub(super) fn validate_installed(
    value: &InstalledReceiveAccounting,
) -> Result<(), HelperProtocolError> {
    context(&value.accounting_runtime_id)?;
    handle(&value.accounting_handle)?;
    if !(2..=0x7fff_ffff).contains(&value.ingress_ifindex) {
        return Err(HelperProtocolError::Invalid("receive accounting ifindex"));
    }
    Ok(())
}

pub(super) fn validate_snapshot(
    value: &ReceiveAccountingSnapshot,
) -> Result<(), HelperProtocolError> {
    context(&value.accounting_runtime_id)?;
    handle(&value.accounting_handle)?;
    if value.total.is_none() || value.managed.len() > 128 {
        return Err(HelperProtocolError::Invalid("receive accounting counters"));
    }
    let mut identities = BTreeSet::new();
    for row in &value.managed {
        context(&row.route_context_id)?;
        if !(1..=MAX_HELPER_PATHS).contains(&row.path_id)
            || row.counters.is_none()
            || !matches!(
                WireguardRole::try_from(row.role),
                Ok(WireguardRole::Client
                    | WireguardRole::RelayClient
                    | WireguardRole::RelayExit
                    | WireguardRole::Exit)
            )
            || !identities.insert((&row.route_context_id, row.path_id, row.role))
        {
            return Err(HelperProtocolError::Invalid("managed receive identity"));
        }
    }
    if identities.iter().copied().ne(value
        .managed
        .iter()
        .map(|row| (&row.route_context_id, row.path_id, row.role)))
    {
        return Err(HelperProtocolError::Invalid("managed receive ordering"));
    }
    Ok(())
}

/// Verify response kind, canonical digest and exact owner/capability pairing.
///
/// # Errors
/// Rejects malformed, mismatched or substituted responses. Success does not replace same-socket
/// helper runtime authentication; no operation in this family transfers descriptors.
pub fn validate_downlink_response(
    request: &HelperRequest,
    response: &HelperResponse,
) -> Result<(), HelperProtocolError> {
    validate_request(request)?;
    validate_response(response)?;
    if request.request_id != response.request_id
        || response.operation_digest.as_slice() != operation_digest(request)?
    {
        return Err(HelperProtocolError::Invalid(
            "downlink response correlation",
        ));
    }
    let operation = request
        .operation
        .as_ref()
        .ok_or(HelperProtocolError::Invalid("downlink operation"))?;
    if !matches!(
        operation,
        Operation::ApplyDownlinkBudget(_)
            | Operation::InstallReceiveAccounting(_)
            | Operation::InspectReceiveAccounting(_)
            | Operation::DestroyReceiveAccounting(_)
    ) {
        return Err(HelperProtocolError::Invalid("downlink operation"));
    }
    if response.result != HelperResult::Ok as i32 {
        return Ok(());
    }
    let matched = match (operation, response.outcome.as_ref()) {
        (Operation::ApplyDownlinkBudget(request), Some(Outcome::AppliedDownlinkBudget(value))) => {
            request.route_context_id == value.route_context_id
                && request.lease_handle == value.lease_handle
        }
        (
            Operation::InstallReceiveAccounting(request),
            Some(Outcome::InstalledReceiveAccounting(value)),
        ) => request.accounting_runtime_id == value.accounting_runtime_id,
        (
            Operation::InspectReceiveAccounting(request),
            Some(Outcome::ReceiveAccountingSnapshot(value)),
        ) => {
            request.accounting_runtime_id == value.accounting_runtime_id
                && request.accounting_handle == value.accounting_handle
        }
        (
            Operation::DestroyReceiveAccounting(request),
            Some(Outcome::DestroyedReceiveAccounting(value)),
        ) => {
            request.accounting_runtime_id == value.accounting_runtime_id
                && request.accounting_handle == value.accounting_handle
        }
        _ => false,
    };
    if !matched {
        return Err(HelperProtocolError::Invalid("downlink response owner"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HELPER_PROTOCOL_VERSION, decode_request, decode_response, safe_preview};

    #[test]
    #[allow(clippy::too_many_lines)] // Four closed wire-operation pairs in one encoding/correlation contract.
    fn downlink_wire_exact_tags_correlation_and_bounded_inputs() {
        let operations = [
            Operation::ApplyDownlinkBudget(ApplyDownlinkBudget {
                route_context_id: vec![1; 16],
                context_handle: vec![2; 32],
                lease_handle: vec![3; 32],
                signed_budget: vec![4; 100],
            }),
            Operation::InstallReceiveAccounting(InstallReceiveAccounting {
                accounting_runtime_id: vec![5; 16],
                interface: "down0".into(),
            }),
            Operation::InspectReceiveAccounting(InspectReceiveAccounting {
                accounting_runtime_id: vec![5; 16],
                accounting_handle: vec![6; 32],
            }),
            Operation::DestroyReceiveAccounting(DestroyReceiveAccounting {
                accounting_runtime_id: vec![5; 16],
                accounting_handle: vec![6; 32],
            }),
        ];
        let outcomes = [
            Outcome::AppliedDownlinkBudget(AppliedDownlinkBudget {
                route_context_id: vec![1; 16],
                lease_handle: vec![3; 32],
                sequence: 1,
                rate_bytes_per_second: 0,
                burst_bytes: 2048,
                expires_at_ms: 1000,
                maximum_queued_bytes: 4096,
            }),
            Outcome::InstalledReceiveAccounting(InstalledReceiveAccounting {
                accounting_runtime_id: vec![5; 16],
                accounting_handle: vec![6; 32],
                ingress_ifindex: 2,
            }),
            Outcome::ReceiveAccountingSnapshot(ReceiveAccountingSnapshot {
                accounting_runtime_id: vec![5; 16],
                accounting_handle: vec![6; 32],
                total: Some(ReceiveByteCounters {
                    bytes: 42,
                    packets: 1,
                }),
                managed: Vec::new(),
            }),
            Outcome::DestroyedReceiveAccounting(DestroyedReceiveAccounting {
                accounting_runtime_id: vec![5; 16],
                accounting_handle: vec![6; 32],
                existed: true,
            }),
        ];
        for (index, (operation, outcome)) in operations.into_iter().zip(outcomes).enumerate() {
            let request = HelperRequest {
                protocol_version: HELPER_PROTOCOL_VERSION,
                request_id: vec![7; 16],
                operation: Some(operation),
            };
            let bytes = request.encode_to_vec();
            assert_eq!(decode_request(&bytes).unwrap(), request);
            // Common version/id occupy20bytes; new allowlisted operation tags are43..46.
            assert_eq!(
                &bytes[20..22],
                &[0xda + u8::try_from(index * 8).unwrap(), 2]
            );
            let response = HelperResponse {
                protocol_version: HELPER_PROTOCOL_VERSION,
                request_id: request.request_id.clone(),
                result: HelperResult::Ok as i32,
                diagnostic_code: "OK".into(),
                operation_digest: operation_digest(&request).unwrap().to_vec(),
                outcome: Some(outcome),
            };
            assert_eq!(
                decode_response(&response.encode_to_vec()).unwrap(),
                response
            );
            assert!(validate_downlink_response(&request, &response).is_ok());
            let mut changed = response.clone();
            changed.request_id[0] ^= 1;
            assert!(validate_downlink_response(&request, &changed).is_err());
            changed = response;
            changed.operation_digest[0] ^= 1;
            assert!(validate_downlink_response(&request, &changed).is_err());
            assert!(!safe_preview(&request).unwrap().contains("down0"));
            let mut unknown = bytes;
            unknown.extend([0xf8, 0x07, 1]);
            assert!(decode_request(&unknown).is_err());
        }
        assert!(
            validate_install(&InstallReceiveAccounting {
                accounting_runtime_id: vec![5; 16],
                interface: "../down0".into()
            })
            .is_err()
        );
        assert!(
            validate_apply(&ApplyDownlinkBudget {
                route_context_id: vec![1; 16],
                context_handle: vec![2; 32],
                lease_handle: vec![3; 32],
                signed_budget: vec![0; 2049]
            })
            .is_err()
        );
    }
}
