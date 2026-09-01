//! Fail-atomic conversion from helper-v3 prepare outcomes to local client endpoint capabilities.
//!
//! The signed reservation protocol receives only public endpoint tuples. Opaque helper handles
//! stay in this process-local boundary and are compared with the exact client prepare request
//! before any lease is made available to reservation code.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use thiserror::Error;
use volparossa_protocol::WireguardEndpoint;
use volparossa_routing::{
    ContextRole, HELPER_PROTOCOL_VERSION, HelperRequest, PrepareLeaseBatch, PreparedLease,
    PreparedLeaseBatch, UnderlayEvidence, WireguardRole, encode_request, helper_request,
};
use volparossa_wireguard::{
    ClientEndpointLease, EndpointRole, HelperContextHandle, HelperLeaseHandle, MAX_PATHS,
    PublicWireGuardEndpoint, WireGuardError, WireGuardPublicKey,
};

/// A helper-prepared, locally bound client route-context capability.
///
/// Every contained client lease retains its exact route-context, context-handle, lease-handle and
/// path binding. The batch intentionally has no serialization implementation.
pub struct LocalEndpointLeaseBatch {
    context_handle: HelperContextHandle,
    client_leases: Vec<ClientEndpointLease>,
}

impl LocalEndpointLeaseBatch {
    /// Return the opaque helper context capability for local lifecycle calls.
    #[must_use]
    pub const fn context_handle(&self) -> HelperContextHandle {
        self.context_handle
    }

    /// Borrow the complete, path-sorted set of client endpoint capabilities.
    #[must_use]
    pub fn client_leases(&self) -> &[ClientEndpointLease] {
        &self.client_leases
    }
}

/// Failure while binding a helper prepare outcome to its exact local client request.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum EndpointLeaseBindingError {
    /// The locally constructed prepare plan violated its closed client/cardinality contract.
    #[error("invalid local helper prepare plan")]
    InvalidPreparePlan,
    /// The helper outcome was malformed despite passing the outer response envelope.
    #[error("invalid helper prepared-lease outcome")]
    InvalidPreparedOutcome,
    /// The helper returned a different path/role identity set than was requested.
    #[error("helper prepared-lease identities do not match the request")]
    IdentityMismatch,
    /// A client-specific `WireGuard` lease invariant failed.
    #[error(transparent)]
    WireGuard(#[from] WireGuardError),
}

struct ParsedLease {
    handle: HelperLeaseHandle,
    endpoint: PublicWireGuardEndpoint,
}

/// Bind a validated helper prepare outcome to the exact client prepare plan.
///
/// Plan validation happens before any response field is read. The conversion is fail-atomic: all
/// response identities, evidence, opaque handles, public keys and ports are checked before a
/// result is returned. Output paths are sorted by `path_id`, independent of helper response order.
///
/// # Errors
///
/// Returns an error unless the request is exactly `ContextRole::Client` with one through eight
/// unique `WireguardRole::Client` paths. Also rejects malformed or substituted responses,
/// evidence other than `DirectAssigned`, duplicate capabilities/key material/ports, non-public
/// addresses and role-binding failures.
pub fn bind_prepared_endpoint_leases(
    request: &PrepareLeaseBatch,
    response: PreparedLeaseBatch,
) -> Result<LocalEndpointLeaseBatch, EndpointLeaseBindingError> {
    let expected = validate_prepare_plan(request)?;
    let route_context_id: [u8; 16] = request
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| EndpointLeaseBindingError::InvalidPreparePlan)?;
    if route_context_id.iter().all(|byte| *byte == 0) {
        return Err(EndpointLeaseBindingError::InvalidPreparePlan);
    }

    let context_handle = HelperContextHandle::try_from(response.context_handle.as_slice())?;
    let parsed = parse_response(response.leases, &expected, context_handle)?;
    let client_leases = parsed
        .into_iter()
        .map(|((path_id, _role), value)| {
            ClientEndpointLease::new(
                route_context_id,
                context_handle,
                value.handle,
                path_id,
                EndpointRole::Client,
                value.endpoint,
            )
            .map_err(Into::into)
        })
        .collect::<Result<Vec<_>, EndpointLeaseBindingError>>()?;

    Ok(LocalEndpointLeaseBatch {
        context_handle,
        client_leases,
    })
}

/// Convert one already validated helper endpoint into its canonical signed-control shape.
pub(crate) fn protocol_endpoint_for_native(endpoint: PublicWireGuardEndpoint) -> WireguardEndpoint {
    let underlay_ip = match endpoint.underlay_ip() {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    WireguardEndpoint {
        public_key: endpoint.public_key().as_bytes().to_vec(),
        underlay_ip,
        listen_port: u32::from(endpoint.listen_port()),
    }
}

fn validate_prepare_plan(
    request: &PrepareLeaseBatch,
) -> Result<BTreeSet<(u32, WireguardRole)>, EndpointLeaseBindingError> {
    let context_role = ContextRole::try_from(request.role)
        .map_err(|_| EndpointLeaseBindingError::InvalidPreparePlan)?;
    if context_role != ContextRole::Client {
        return Err(EndpointLeaseBindingError::InvalidPreparePlan);
    }
    let expected = expected_identities(request)?;
    encode_request(&HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: vec![1; 16],
        operation: Some(helper_request::Operation::PrepareLeaseBatch(
            request.clone(),
        )),
    })
    .map_err(|_| EndpointLeaseBindingError::InvalidPreparePlan)?;
    Ok(expected)
}

fn expected_identities(
    request: &PrepareLeaseBatch,
) -> Result<BTreeSet<(u32, WireguardRole)>, EndpointLeaseBindingError> {
    if request.leases.is_empty() || request.leases.len() > usize::from(MAX_PATHS) {
        return Err(EndpointLeaseBindingError::InvalidPreparePlan);
    }
    let mut identities = BTreeSet::new();
    for lease in &request.leases {
        let role = WireguardRole::try_from(lease.role)
            .map_err(|_| EndpointLeaseBindingError::InvalidPreparePlan)?;
        if !(1..=u32::from(MAX_PATHS)).contains(&lease.path_id)
            || role != WireguardRole::Client
            || !identities.insert((lease.path_id, role))
        {
            return Err(EndpointLeaseBindingError::InvalidPreparePlan);
        }
    }
    Ok(identities)
}

fn parse_response(
    leases: Vec<PreparedLease>,
    expected: &BTreeSet<(u32, WireguardRole)>,
    context_handle: HelperContextHandle,
) -> Result<BTreeMap<(u32, WireguardRole), ParsedLease>, EndpointLeaseBindingError> {
    if leases.len() != expected.len() {
        return Err(EndpointLeaseBindingError::IdentityMismatch);
    }
    let mut parsed = BTreeMap::new();
    let mut handles = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut listen_ports = BTreeSet::new();
    for lease in leases {
        let role = WireguardRole::try_from(lease.role)
            .map_err(|_| EndpointLeaseBindingError::InvalidPreparedOutcome)?;
        let identity = (lease.path_id, role);
        if !expected.contains(&identity) || parsed.contains_key(&identity) {
            return Err(EndpointLeaseBindingError::IdentityMismatch);
        }
        if UnderlayEvidence::try_from(lease.underlay_evidence)
            != Ok(UnderlayEvidence::DirectAssigned)
        {
            return Err(EndpointLeaseBindingError::InvalidPreparedOutcome);
        }
        let handle = HelperLeaseHandle::try_from(lease.lease_handle.as_slice())?;
        if handle.as_bytes() == context_handle.as_bytes() || !handles.insert(*handle.as_bytes()) {
            return Err(WireGuardError::DuplicateHelperHandle.into());
        }
        let public_key_bytes: [u8; 32] = lease
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| EndpointLeaseBindingError::InvalidPreparedOutcome)?;
        if !public_keys.insert(public_key_bytes) {
            return Err(WireGuardError::InvalidTopology.into());
        }
        let public = lease
            .public_endpoint
            .ok_or(EndpointLeaseBindingError::InvalidPreparedOutcome)?;
        let listen_port = u16::try_from(public.port)
            .map_err(|_| EndpointLeaseBindingError::InvalidPreparedOutcome)?;
        if !listen_ports.insert(listen_port) {
            return Err(WireGuardError::DuplicateListenPort.into());
        }
        let endpoint = PublicWireGuardEndpoint::new(
            WireGuardPublicKey::from_bytes(public_key_bytes),
            parse_ip(&public.address)?,
            listen_port,
        )?;
        parsed.insert(identity, ParsedLease { handle, endpoint });
    }
    Ok(parsed)
}

fn parse_ip(bytes: &[u8]) -> Result<IpAddr, EndpointLeaseBindingError> {
    match bytes {
        [a, b, c, d] => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| EndpointLeaseBindingError::InvalidPreparedOutcome)?;
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(EndpointLeaseBindingError::InvalidPreparedOutcome),
    }
}

#[cfg(test)]
mod tests {
    use volparossa_routing::{LeasePlan, PublicUdpEndpoint};
    use volparossa_wireguard::HELPER_HANDLE_BYTES;

    use super::*;

    fn request(role: ContextRole, leases: &[(u32, WireguardRole)]) -> PrepareLeaseBatch {
        PrepareLeaseBatch {
            route_context_id: vec![7; 16],
            role: role as i32,
            mptcp_accepted_addrs: 8,
            mptcp_subflows: 8,
            leases: leases
                .iter()
                .map(|(path_id, role)| LeasePlan {
                    path_id: *path_id,
                    role: *role as i32,
                })
                .collect(),
            setup_expires_at_unix: 10,
            hard_expires_at_unix: 20,
        }
    }

    fn prepared(path_id: u32, role: WireguardRole, seed: u8, port: u32) -> PreparedLease {
        PreparedLease {
            lease_handle: vec![seed; HELPER_HANDLE_BYTES],
            path_id,
            role: role as i32,
            public_key: vec![seed.wrapping_add(32); 32],
            public_endpoint: Some(PublicUdpEndpoint {
                address: vec![8, 8, 4, seed],
                port,
            }),
            underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
        }
    }

    fn response(leases: Vec<PreparedLease>) -> PreparedLeaseBatch {
        PreparedLeaseBatch {
            context_handle: vec![99; HELPER_HANDLE_BYTES],
            leases,
        }
    }

    #[test]
    fn client_outcome_is_exactly_bound_and_sorted() {
        let request = request(
            ContextRole::Client,
            &[(1, WireguardRole::Client), (2, WireguardRole::Client)],
        );
        let batch = bind_prepared_endpoint_leases(
            &request,
            response(vec![
                prepared(2, WireguardRole::Client, 2, 40_002),
                prepared(1, WireguardRole::Client, 1, 40_001),
            ]),
        )
        .expect("bound batch");

        assert_eq!(
            batch.context_handle().as_bytes(),
            &[99; HELPER_HANDLE_BYTES]
        );
        let leases = batch.client_leases();
        assert_eq!(
            leases
                .iter()
                .map(ClientEndpointLease::path_id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(
            leases
                .iter()
                .all(|lease| lease.route_context_id() == &[7; 16])
        );
        assert_eq!(leases[0].public_endpoint().listen_port(), 40_001);
    }

    #[test]
    fn every_non_client_plan_fails_before_response_is_read() {
        let plans = [
            request(
                ContextRole::Relay,
                &[
                    (1, WireguardRole::RelayClient),
                    (1, WireguardRole::RelayExit),
                ],
            ),
            request(ContextRole::Exit, &[(1, WireguardRole::Exit)]),
            request(ContextRole::Unspecified, &[(1, WireguardRole::Client)]),
            request(ContextRole::Client, &[(1, WireguardRole::RelayClient)]),
        ];
        for plan in plans {
            let unreadable_response = PreparedLeaseBatch {
                context_handle: Vec::new(),
                leases: vec![PreparedLease::default()],
            };
            assert_eq!(
                bind_prepared_endpoint_leases(&plan, unreadable_response).err(),
                Some(EndpointLeaseBindingError::InvalidPreparePlan)
            );
        }
    }

    #[test]
    fn empty_duplicate_and_out_of_range_client_plans_are_rejected() {
        let duplicate = request(
            ContextRole::Client,
            &[(1, WireguardRole::Client), (1, WireguardRole::Client)],
        );
        let nine_paths = (1..=9)
            .map(|path_id| (path_id, WireguardRole::Client))
            .collect::<Vec<_>>();
        for plan in [
            request(ContextRole::Client, &[]),
            duplicate,
            request(ContextRole::Client, &[(0, WireguardRole::Client)]),
            request(ContextRole::Client, &[(9, WireguardRole::Client)]),
            request(ContextRole::Client, &nine_paths),
            request(ContextRole::Client, &[(1, WireguardRole::Unspecified)]),
        ] {
            assert_eq!(
                bind_prepared_endpoint_leases(&plan, response(Vec::new())).err(),
                Some(EndpointLeaseBindingError::InvalidPreparePlan)
            );
        }
    }

    #[test]
    fn zero_context_and_incomplete_client_response_are_rejected() {
        let mut zero = request(ContextRole::Client, &[(1, WireguardRole::Client)]);
        zero.route_context_id.fill(0);
        assert_eq!(
            bind_prepared_endpoint_leases(
                &zero,
                response(vec![prepared(1, WireguardRole::Client, 1, 40_001)])
            )
            .err(),
            Some(EndpointLeaseBindingError::InvalidPreparePlan)
        );

        let two_paths = request(
            ContextRole::Client,
            &[(1, WireguardRole::Client), (2, WireguardRole::Client)],
        );
        assert_eq!(
            bind_prepared_endpoint_leases(
                &two_paths,
                response(vec![prepared(1, WireguardRole::Client, 1, 40_001)])
            )
            .err(),
            Some(EndpointLeaseBindingError::IdentityMismatch)
        );
    }

    #[test]
    fn identity_substitution_fails_before_exposing_a_lease() {
        let request = request(ContextRole::Client, &[(1, WireguardRole::Client)]);
        assert_eq!(
            bind_prepared_endpoint_leases(
                &request,
                response(vec![prepared(2, WireguardRole::Client, 1, 40_001)])
            )
            .err(),
            Some(EndpointLeaseBindingError::IdentityMismatch)
        );
    }

    #[test]
    fn non_direct_evidence_and_duplicate_material_fail_closed() {
        let client_request = request(
            ContextRole::Client,
            &[(1, WireguardRole::Client), (2, WireguardRole::Client)],
        );
        let mut wrong_evidence = prepared(1, WireguardRole::Client, 1, 40_001);
        wrong_evidence.underlay_evidence = UnderlayEvidence::Unspecified as i32;
        assert_eq!(
            bind_prepared_endpoint_leases(
                &request(ContextRole::Client, &[(1, WireguardRole::Client)]),
                response(vec![wrong_evidence])
            )
            .err(),
            Some(EndpointLeaseBindingError::InvalidPreparedOutcome)
        );

        let duplicate_handle = prepared(2, WireguardRole::Client, 1, 40_002);
        assert_eq!(
            bind_prepared_endpoint_leases(
                &client_request,
                response(vec![
                    prepared(1, WireguardRole::Client, 1, 40_001),
                    duplicate_handle,
                ])
            )
            .err(),
            Some(EndpointLeaseBindingError::WireGuard(
                WireGuardError::DuplicateHelperHandle
            ))
        );

        let mut duplicate_key = prepared(2, WireguardRole::Client, 2, 40_002);
        duplicate_key.public_key = vec![33; 32];
        assert_eq!(
            bind_prepared_endpoint_leases(
                &client_request,
                response(vec![
                    prepared(1, WireguardRole::Client, 1, 40_001),
                    duplicate_key,
                ])
            )
            .err(),
            Some(EndpointLeaseBindingError::WireGuard(
                WireGuardError::InvalidTopology
            ))
        );

        assert_eq!(
            bind_prepared_endpoint_leases(
                &client_request,
                response(vec![
                    prepared(1, WireguardRole::Client, 1, 40_001),
                    prepared(2, WireguardRole::Client, 2, 40_001),
                ])
            )
            .err(),
            Some(EndpointLeaseBindingError::WireGuard(
                WireGuardError::DuplicateListenPort
            ))
        );
    }

    #[test]
    fn public_address_key_and_port_validation_remains_fail_closed() {
        let request = request(ContextRole::Client, &[(1, WireguardRole::Client)]);

        let mut special_address = prepared(1, WireguardRole::Client, 1, 40_001);
        special_address
            .public_endpoint
            .as_mut()
            .expect("endpoint")
            .address = vec![127, 0, 0, 1];
        assert_eq!(
            bind_prepared_endpoint_leases(&request, response(vec![special_address])).err(),
            Some(EndpointLeaseBindingError::WireGuard(
                WireGuardError::InvalidUnderlayAddress
            ))
        );

        let mut zero_key = prepared(1, WireguardRole::Client, 1, 40_001);
        zero_key.public_key.fill(0);
        assert_eq!(
            bind_prepared_endpoint_leases(&request, response(vec![zero_key])).err(),
            Some(EndpointLeaseBindingError::WireGuard(
                WireGuardError::InvalidTopology
            ))
        );

        let zero_port = prepared(1, WireguardRole::Client, 1, 0);
        assert_eq!(
            bind_prepared_endpoint_leases(&request, response(vec![zero_port])).err(),
            Some(EndpointLeaseBindingError::WireGuard(
                WireGuardError::InvalidListenPort
            ))
        );
    }
}
