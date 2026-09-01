//! Affine client/upstream dispatch, response transport, and connection binding for A1c.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use libp2p::{PeerId, request_response::OutboundRequestId, swarm::ConnectionId};
use thiserror::Error;
use tokio::time::Instant;
use volparossa_core::IpFamily;
use volparossa_protocol::{
    ObservationAddressFamily, PreselectionObservationRequest, PreselectionObservationRole,
    decode_canonical, preselection_observation_request_hash,
};

use crate::{
    ClientPreselectionObservationRequest, ClientPreselectionObservationResponse, DiscoveryService,
    MAX_PRESELECTION_REQUEST_SIZE, PRESELECTION_OBSERVATION_REQUEST_TIMEOUT,
    UpstreamPreselectionObservationRequest, UpstreamPreselectionObservationResponse,
    connection_provenance::{BoundConnectionObservation, ConnectionWitness},
};

pub(super) struct PreselectionTransactionState {
    instance: Arc<()>,
    client_active: Option<OutboundRequestId>,
    upstream_active: Option<OutboundRequestId>,
}

impl PreselectionTransactionState {
    pub(super) fn new() -> Self {
        Self {
            instance: Arc::new(()),
            client_active: None,
            upstream_active: None,
        }
    }
}

/// Detail-free rejection at the affine preselection transport boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum PreselectionDispatchError {
    /// The immutable local roles do not permit the requested transport direction.
    #[error("preselection transport role is disabled")]
    Role,
    /// The canonical request cannot yield the required target and address family.
    #[error("invalid preselection transport request")]
    Request,
    /// No unique current authenticated connection proves the requested native family.
    #[error("preselection transport provenance is unavailable")]
    Provenance,
    /// A response arrival does not belong to this exact dispatch.
    #[error("preselection response correlation failed")]
    Correlation,
    /// Dispatch or response arrival falls outside the monotonic time window.
    #[error("preselection transport time window failed")]
    Time,
    /// The exact per-hop dispatch slot is already occupied.
    #[error("preselection dispatch slot is occupied")]
    Busy,
}

/// Affine owner of one exact sent client-hop request and its pre-send connection witness.
#[must_use = "a client preselection dispatch must be bound or cancelled through its originating DiscoveryService"]
pub struct ClientPreselectionDispatch {
    request_id: OutboundRequestId,
    request_hash: [u8; 32],
    expected_peer_id: PeerId,
    instance: Arc<()>,
    sent_at: Instant,
    deadline: Instant,
    witness: ConnectionWitness,
}

/// Affine client-hop dispatch carrying its exact caller-owned attempt context.
///
/// The context can be the owner that retains the original candidate snapshot and canonical
/// request. It is returned only after this exact dispatch binds or cancels through its originating
/// service, so a later A1c owner cannot accidentally pair a response with a sibling attempt.
#[must_use = "a context-bound client preselection transaction must be bound or cancelled through its originating DiscoveryService"]
pub struct ClientPreselectionTransaction<Context> {
    dispatch: ClientPreselectionDispatch,
    context: Context,
}

/// Service-sealed arrival of one outbound client-hop response.
///
/// All fields are private and this type has no constructor or inspection API. Only the
/// `DiscoveryService` instance whose private swarm observed the response can mint it, and only
/// that same instance can bind it to an affine dispatch.
#[must_use = "a client response arrival must be bound through its originating DiscoveryService"]
pub struct ClientPreselectionResponseArrival {
    peer: PeerId,
    connection_id: ConnectionId,
    request_id: OutboundRequestId,
    response: ClientPreselectionObservationResponse,
    instance: Arc<()>,
    arrived_at_mono: Instant,
    arrived_at_unix_ms: u64,
}

/// Affine transport observation bound to the exact sealed response and current connection lineage.
#[must_use = "a bound client preselection transport must remain with its A1c transaction"]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "opaque A1c3 proof awaits the single agent transaction owner"
    )
)]
pub struct BoundClientPreselectionTransport {
    observation: BoundConnectionObservation,
    request_hash: [u8; 32],
    request_id: OutboundRequestId,
    sent_at_mono: Instant,
    arrived_at_mono: Instant,
    arrived_at_unix_ms: u64,
    deadline_mono: Instant,
}

/// Affine owner of one exact relay-to-exit request and its pre-send connection witness.
#[must_use = "an upstream preselection dispatch must be bound or cancelled through its originating DiscoveryService"]
pub struct UpstreamPreselectionDispatch {
    request_id: OutboundRequestId,
    request_hash: [u8; 32],
    expected_peer_id: PeerId,
    instance: Arc<()>,
    sent_at: Instant,
    deadline: Instant,
    witness: ConnectionWitness,
}

/// Affine relay-to-exit dispatch carrying its exact caller-owned forwarding context.
///
/// A future service-owned upstream responder can retain its private originating request owner in
/// `Context`; the value is returned only after this exact upstream dispatch binds or cancels. No
/// public event pump yields the downstream response channel.
#[must_use = "a context-bound upstream preselection transaction must be bound or cancelled through its originating DiscoveryService"]
pub struct UpstreamPreselectionTransaction<Context> {
    dispatch: UpstreamPreselectionDispatch,
    context: Context,
}

/// Service-sealed arrival of one outbound relay-to-exit response.
///
/// The opaque value records its private behaviour instance and arrival clocks at the instant the
/// service-owned event pump observes the response. A sibling service or independent behaviour
/// cannot manufacture a bindable value even when its local request ID is numerically identical.
#[must_use = "an upstream response arrival must be bound through its originating DiscoveryService"]
pub struct UpstreamPreselectionResponseArrival {
    peer: PeerId,
    connection_id: ConnectionId,
    request_id: OutboundRequestId,
    response: UpstreamPreselectionObservationResponse,
    instance: Arc<()>,
    arrived_at_mono: Instant,
    arrived_at_unix_ms: u64,
}

/// Affine transport observation bound to one exact exit response and connection lineage.
#[must_use = "a bound upstream preselection transport must remain with its A1c transaction"]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "opaque A1c proof awaits the single agent transaction owner"
    )
)]
pub struct BoundUpstreamPreselectionTransport {
    observation: BoundConnectionObservation,
    request_hash: [u8; 32],
    request_id: OutboundRequestId,
    sent_at_mono: Instant,
    arrived_at_mono: Instant,
    arrived_at_unix_ms: u64,
    deadline_mono: Instant,
}

impl DiscoveryService {
    /// Send one client-hop request while retaining an exact affine caller context.
    ///
    /// This is the context-preserving entry point for a later A1c owner. The context is not cloned,
    /// exposed, or stored in the swarm and can return only through the matching bind/cancel API.
    ///
    /// # Errors
    ///
    /// Returns the same detail-free dispatch errors as [`Self::dispatch_preselection_observation`].
    pub fn dispatch_preselection_observation_with_context<Context>(
        &mut self,
        request: ClientPreselectionObservationRequest,
        absolute_deadline: Instant,
        context: Context,
    ) -> Result<ClientPreselectionTransaction<Context>, PreselectionDispatchError> {
        let dispatch = self.dispatch_preselection_observation(request, absolute_deadline)?;
        Ok(ClientPreselectionTransaction { dispatch, context })
    }

    /// Bind a matching client response and return its unchanged exact caller context.
    ///
    /// # Errors
    ///
    /// Returns the same detail-free binding errors as
    /// [`Self::bind_preselection_observation_response`].
    pub fn bind_preselection_observation_response_with_context<Context>(
        &mut self,
        transaction: ClientPreselectionTransaction<Context>,
        arrival: ClientPreselectionResponseArrival,
    ) -> Result<
        (
            Context,
            BoundClientPreselectionTransport,
            ClientPreselectionObservationResponse,
        ),
        PreselectionDispatchError,
    > {
        let ClientPreselectionTransaction { dispatch, context } = transaction;
        let (transport, response) =
            self.bind_preselection_observation_response(dispatch, arrival)?;
        Ok((context, transport, response))
    }

    /// Cancel a client-hop transaction and return its unchanged exact caller context.
    ///
    /// # Errors
    ///
    /// Returns the same correlation error as [`Self::cancel_preselection_observation_dispatch`].
    pub fn cancel_preselection_observation_transaction<Context>(
        &mut self,
        transaction: ClientPreselectionTransaction<Context>,
    ) -> Result<Context, PreselectionDispatchError> {
        let ClientPreselectionTransaction { dispatch, context } = transaction;
        self.cancel_preselection_observation_dispatch(dispatch)?;
        Ok(context)
    }

    /// Send one canonical preselection observation over its request-derived authenticated peer.
    ///
    /// The exact target and native family are decoded only from `request`. The connection witness
    /// is minted immediately before the synchronous libp2p send, with no suspension point.
    ///
    /// # Errors
    ///
    /// Returns a detail-free error for an occupied single-dispatch slot, disabled client role,
    /// invalid request binding, unavailable wall or monotonic time, an expired effective deadline,
    /// or unavailable unique direct connection provenance.
    pub fn dispatch_preselection_observation(
        &mut self,
        request: ClientPreselectionObservationRequest,
        absolute_deadline: Instant,
    ) -> Result<ClientPreselectionDispatch, PreselectionDispatchError> {
        if self.preselection_transaction.client_active.is_some() {
            return Err(PreselectionDispatchError::Busy);
        }
        if !self.protocol_roles.client() {
            return Err(PreselectionDispatchError::Role);
        }
        let request_hash = preselection_observation_request_hash(request.as_encoded())
            .map_err(|_| PreselectionDispatchError::Request)?;
        let typed_request: PreselectionObservationRequest =
            decode_canonical(request.as_encoded(), MAX_PRESELECTION_REQUEST_SIZE)
                .map_err(|_| PreselectionDispatchError::Request)?;
        typed_request
            .validate()
            .map_err(|_| PreselectionDispatchError::Request)?;
        let (expected_peer_id, actor_peer_id, family) = request_target_and_family(&typed_request)?;
        if expected_peer_id == *self.local_peer_id() || actor_peer_id == *self.local_peer_id() {
            return Err(PreselectionDispatchError::Request);
        }
        let sent_at = Instant::now();
        let sent_at_unix_ms = system_unix_millis()?;
        if typed_request.created_at_ms > sent_at_unix_ms
            || sent_at_unix_ms >= typed_request.expires_at_ms
        {
            return Err(PreselectionDispatchError::Time);
        }
        let request_remaining = Duration::from_millis(
            typed_request
                .expires_at_ms
                .checked_sub(sent_at_unix_ms)
                .ok_or(PreselectionDispatchError::Time)?,
        );
        let deadline = sent_at
            .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
            .ok_or(PreselectionDispatchError::Time)?
            .min(
                sent_at
                    .checked_add(request_remaining)
                    .ok_or(PreselectionDispatchError::Time)?,
            )
            .min(absolute_deadline);
        if sent_at >= deadline {
            return Err(PreselectionDispatchError::Time);
        }
        let witness = self
            .swarm
            .behaviour()
            .connection_provenance
            .unique_witness(expected_peer_id, family)
            .ok_or(PreselectionDispatchError::Provenance)?;
        let request_id = self
            .swarm
            .behaviour_mut()
            .preselection_observation
            .send_request(&expected_peer_id, request);
        self.preselection_transaction.client_active = Some(request_id);
        Ok(ClientPreselectionDispatch {
            request_id,
            request_hash,
            expected_peer_id,
            instance: Arc::clone(&self.preselection_transaction.instance),
            sent_at,
            deadline,
            witness,
        })
    }

    /// Bind one matching service-sealed response arrival to the exact connection lineage.
    ///
    /// # Errors
    ///
    /// Returns a detail-free error for a service-instance, peer, or request mismatch, an invalid
    /// monotonic arrival time, or a stale, ambiguous, closed, changed, or otherwise unavailable
    /// connection proof. Dropping either affine value or submitting a cross-service arrival
    /// deliberately leaves the originating slot occupied. After exact correlation the slot is
    /// consumed even when time or connection-provenance binding then fails closed.
    pub fn bind_preselection_observation_response(
        &mut self,
        dispatch: ClientPreselectionDispatch,
        arrival: ClientPreselectionResponseArrival,
    ) -> Result<
        (
            BoundClientPreselectionTransport,
            ClientPreselectionObservationResponse,
        ),
        PreselectionDispatchError,
    > {
        let ClientPreselectionResponseArrival {
            peer,
            connection_id,
            request_id,
            response,
            instance,
            arrived_at_mono,
            arrived_at_unix_ms,
        } = arrival;
        if !Arc::ptr_eq(&self.preselection_transaction.instance, &dispatch.instance)
            || !Arc::ptr_eq(&self.preselection_transaction.instance, &instance)
            || !Arc::ptr_eq(&dispatch.instance, &instance)
        {
            return Err(PreselectionDispatchError::Correlation);
        }
        let transport = self.bind_preselection_observation_response_at(
            dispatch,
            peer,
            connection_id,
            request_id,
            arrived_at_mono,
            arrived_at_unix_ms,
        )?;
        Ok((transport, response))
    }

    pub(super) fn seal_client_preselection_response(
        &self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: OutboundRequestId,
        response: ClientPreselectionObservationResponse,
    ) -> Result<ClientPreselectionResponseArrival, PreselectionDispatchError> {
        if self.preselection_transaction.client_active != Some(request_id) {
            return Err(PreselectionDispatchError::Correlation);
        }
        Ok(ClientPreselectionResponseArrival {
            peer,
            connection_id,
            request_id,
            response,
            instance: Arc::clone(&self.preselection_transaction.instance),
            arrived_at_mono: Instant::now(),
            arrived_at_unix_ms: system_unix_millis()?,
        })
    }

    fn bind_preselection_observation_response_at(
        &mut self,
        dispatch: ClientPreselectionDispatch,
        event_peer: PeerId,
        event_connection: ConnectionId,
        event_request: OutboundRequestId,
        arrived_at_mono: Instant,
        arrived_at_unix_ms: u64,
    ) -> Result<BoundClientPreselectionTransport, PreselectionDispatchError> {
        if !Arc::ptr_eq(&self.preselection_transaction.instance, &dispatch.instance)
            || self.preselection_transaction.client_active != Some(dispatch.request_id)
        {
            return Err(PreselectionDispatchError::Correlation);
        }
        let ClientPreselectionDispatch {
            request_id,
            request_hash,
            expected_peer_id,
            instance: _,
            sent_at,
            deadline,
            witness,
        } = dispatch;
        if expected_peer_id != event_peer || request_id != event_request {
            return Err(PreselectionDispatchError::Correlation);
        }
        self.preselection_transaction.client_active = None;
        if arrived_at_mono < sent_at || arrived_at_mono >= deadline {
            return Err(PreselectionDispatchError::Time);
        }
        let observation = self
            .swarm
            .behaviour()
            .connection_provenance
            .bind(witness, expected_peer_id, event_connection)
            .ok_or(PreselectionDispatchError::Provenance)?;
        Ok(BoundClientPreselectionTransport {
            observation,
            request_hash,
            request_id,
            sent_at_mono: sent_at,
            arrived_at_mono,
            arrived_at_unix_ms,
            deadline_mono: deadline,
        })
    }

    /// Consume and clear the exact active dispatch after a local timeout or shutdown. Typed
    /// outbound-failure events remain observable for diagnostics, but deliberately expose no
    /// dispatch-token equality oracle; the fixed local deadline remains the terminal authority.
    ///
    /// # Errors
    ///
    /// Returns a correlation error if the token belongs to another service or is no longer active.
    pub fn cancel_preselection_observation_dispatch(
        &mut self,
        dispatch: ClientPreselectionDispatch,
    ) -> Result<(), PreselectionDispatchError> {
        let ClientPreselectionDispatch {
            request_id,
            request_hash: _,
            expected_peer_id: _,
            instance,
            sent_at: _,
            deadline: _,
            witness: _,
        } = dispatch;
        if !Arc::ptr_eq(&self.preselection_transaction.instance, &instance)
            || self.preselection_transaction.client_active != Some(request_id)
        {
            return Err(PreselectionDispatchError::Correlation);
        }
        self.preselection_transaction.client_active = None;
        Ok(())
    }

    /// Send one unchanged forwarded Exit request over its request-derived authenticated exit.
    ///
    /// The exact exit target and native family are decoded only from `request`. The request must
    /// name this service as its forwarding control relay. A connection witness is minted
    /// immediately before the synchronous libp2p send, with no suspension point.
    ///
    /// # Errors
    ///
    /// Returns a detail-free error for an occupied upstream slot, disabled relay role, invalid
    /// request/local-control binding, unavailable wall or monotonic time, an expired effective
    /// deadline, or unavailable unique direct exit-connection provenance.
    pub fn dispatch_preselection_observation_upstream(
        &mut self,
        request: UpstreamPreselectionObservationRequest,
        absolute_deadline: Instant,
    ) -> Result<UpstreamPreselectionDispatch, PreselectionDispatchError> {
        if self.preselection_transaction.upstream_active.is_some() {
            return Err(PreselectionDispatchError::Busy);
        }
        if !self.protocol_roles.relay() {
            return Err(PreselectionDispatchError::Role);
        }
        let request_hash = preselection_observation_request_hash(request.as_encoded())
            .map_err(|_| PreselectionDispatchError::Request)?;
        let typed_request: PreselectionObservationRequest =
            decode_canonical(request.as_encoded(), MAX_PRESELECTION_REQUEST_SIZE)
                .map_err(|_| PreselectionDispatchError::Request)?;
        typed_request
            .validate()
            .map_err(|_| PreselectionDispatchError::Request)?;
        let (expected_peer_id, family) =
            upstream_target_and_family(&typed_request, *self.local_peer_id())?;
        let sent_at = Instant::now();
        let sent_at_unix_ms = system_unix_millis()?;
        if typed_request.created_at_ms > sent_at_unix_ms
            || sent_at_unix_ms >= typed_request.expires_at_ms
        {
            return Err(PreselectionDispatchError::Time);
        }
        let request_remaining = Duration::from_millis(
            typed_request
                .expires_at_ms
                .checked_sub(sent_at_unix_ms)
                .ok_or(PreselectionDispatchError::Time)?,
        );
        let deadline = sent_at
            .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
            .ok_or(PreselectionDispatchError::Time)?
            .min(
                sent_at
                    .checked_add(request_remaining)
                    .ok_or(PreselectionDispatchError::Time)?,
            )
            .min(absolute_deadline);
        if sent_at >= deadline {
            return Err(PreselectionDispatchError::Time);
        }
        let witness = self
            .swarm
            .behaviour()
            .connection_provenance
            .unique_witness(expected_peer_id, family)
            .ok_or(PreselectionDispatchError::Provenance)?;
        let request_id = self
            .swarm
            .behaviour_mut()
            .preselection_observation_upstream
            .send_request(&expected_peer_id, request);
        self.preselection_transaction.upstream_active = Some(request_id);
        Ok(UpstreamPreselectionDispatch {
            request_id,
            request_hash,
            expected_peer_id,
            instance: Arc::clone(&self.preselection_transaction.instance),
            sent_at,
            deadline,
            witness,
        })
    }

    /// Send one upstream request while retaining an exact affine caller context.
    ///
    /// The context can own future private responder state and is returned only by this exact
    /// upstream transaction's bind/cancel API. No public event pump supplies an inbound response
    /// channel to this method.
    ///
    /// # Errors
    ///
    /// Returns the same detail-free dispatch errors as
    /// [`Self::dispatch_preselection_observation_upstream`].
    pub fn dispatch_preselection_observation_upstream_with_context<Context>(
        &mut self,
        request: UpstreamPreselectionObservationRequest,
        absolute_deadline: Instant,
        context: Context,
    ) -> Result<UpstreamPreselectionTransaction<Context>, PreselectionDispatchError> {
        let dispatch =
            self.dispatch_preselection_observation_upstream(request, absolute_deadline)?;
        Ok(UpstreamPreselectionTransaction { dispatch, context })
    }

    /// Bind one matching sealed upstream response to the still-current exact exit connection.
    ///
    /// # Errors
    ///
    /// Returns a detail-free error for a service-instance, peer, or request mismatch, an invalid
    /// monotonic arrival time, or a stale, ambiguous, closed, changed, or otherwise unavailable
    /// exit-connection proof. Exact correlation consumes the upstream slot before later time or
    /// provenance checks.
    pub fn bind_preselection_observation_upstream_response(
        &mut self,
        dispatch: UpstreamPreselectionDispatch,
        arrival: UpstreamPreselectionResponseArrival,
    ) -> Result<
        (
            BoundUpstreamPreselectionTransport,
            UpstreamPreselectionObservationResponse,
        ),
        PreselectionDispatchError,
    > {
        let UpstreamPreselectionResponseArrival {
            peer,
            connection_id,
            request_id,
            response,
            instance,
            arrived_at_mono,
            arrived_at_unix_ms,
        } = arrival;
        if !Arc::ptr_eq(&self.preselection_transaction.instance, &dispatch.instance)
            || !Arc::ptr_eq(&self.preselection_transaction.instance, &instance)
            || !Arc::ptr_eq(&dispatch.instance, &instance)
        {
            return Err(PreselectionDispatchError::Correlation);
        }
        let transport = self.bind_preselection_observation_upstream_response_at(
            dispatch,
            peer,
            connection_id,
            request_id,
            arrived_at_mono,
            arrived_at_unix_ms,
        )?;
        Ok((transport, response))
    }

    pub(super) fn seal_upstream_preselection_response(
        &self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: OutboundRequestId,
        response: UpstreamPreselectionObservationResponse,
    ) -> Result<UpstreamPreselectionResponseArrival, PreselectionDispatchError> {
        if self.preselection_transaction.upstream_active != Some(request_id) {
            return Err(PreselectionDispatchError::Correlation);
        }
        Ok(UpstreamPreselectionResponseArrival {
            peer,
            connection_id,
            request_id,
            response,
            instance: Arc::clone(&self.preselection_transaction.instance),
            arrived_at_mono: Instant::now(),
            arrived_at_unix_ms: system_unix_millis()?,
        })
    }

    /// Bind a matching upstream response and return its unchanged exact forwarding context.
    ///
    /// # Errors
    ///
    /// Returns the same detail-free binding errors as
    /// [`Self::bind_preselection_observation_upstream_response`].
    pub fn bind_preselection_observation_upstream_response_with_context<Context>(
        &mut self,
        transaction: UpstreamPreselectionTransaction<Context>,
        arrival: UpstreamPreselectionResponseArrival,
    ) -> Result<
        (
            Context,
            BoundUpstreamPreselectionTransport,
            UpstreamPreselectionObservationResponse,
        ),
        PreselectionDispatchError,
    > {
        let UpstreamPreselectionTransaction { dispatch, context } = transaction;
        let (transport, response) =
            self.bind_preselection_observation_upstream_response(dispatch, arrival)?;
        Ok((context, transport, response))
    }

    fn bind_preselection_observation_upstream_response_at(
        &mut self,
        dispatch: UpstreamPreselectionDispatch,
        event_peer: PeerId,
        event_connection: ConnectionId,
        event_request: OutboundRequestId,
        arrived_at_mono: Instant,
        arrived_at_unix_ms: u64,
    ) -> Result<BoundUpstreamPreselectionTransport, PreselectionDispatchError> {
        if !Arc::ptr_eq(&self.preselection_transaction.instance, &dispatch.instance)
            || self.preselection_transaction.upstream_active != Some(dispatch.request_id)
        {
            return Err(PreselectionDispatchError::Correlation);
        }
        let UpstreamPreselectionDispatch {
            request_id,
            request_hash,
            expected_peer_id,
            instance: _,
            sent_at,
            deadline,
            witness,
        } = dispatch;
        if expected_peer_id != event_peer || request_id != event_request {
            return Err(PreselectionDispatchError::Correlation);
        }
        self.preselection_transaction.upstream_active = None;
        if arrived_at_mono < sent_at || arrived_at_mono >= deadline {
            return Err(PreselectionDispatchError::Time);
        }
        let observation = self
            .swarm
            .behaviour()
            .connection_provenance
            .bind(witness, expected_peer_id, event_connection)
            .ok_or(PreselectionDispatchError::Provenance)?;
        Ok(BoundUpstreamPreselectionTransport {
            observation,
            request_hash,
            request_id,
            sent_at_mono: sent_at,
            arrived_at_mono,
            arrived_at_unix_ms,
            deadline_mono: deadline,
        })
    }

    /// Consume and clear the exact active upstream dispatch after a local timeout or shutdown.
    /// Typed outbound failures remain diagnostic-only; the fixed local deadline is authoritative.
    ///
    /// # Errors
    ///
    /// Returns a correlation error if the token belongs to another service or is no longer active.
    pub fn cancel_preselection_observation_upstream_dispatch(
        &mut self,
        dispatch: UpstreamPreselectionDispatch,
    ) -> Result<(), PreselectionDispatchError> {
        let UpstreamPreselectionDispatch {
            request_id,
            request_hash: _,
            expected_peer_id: _,
            instance,
            sent_at: _,
            deadline: _,
            witness: _,
        } = dispatch;
        if !Arc::ptr_eq(&self.preselection_transaction.instance, &instance)
            || self.preselection_transaction.upstream_active != Some(request_id)
        {
            return Err(PreselectionDispatchError::Correlation);
        }
        self.preselection_transaction.upstream_active = None;
        Ok(())
    }

    /// Cancel an upstream transaction and return its unchanged exact forwarding context.
    ///
    /// # Errors
    ///
    /// Returns the same correlation error as
    /// [`Self::cancel_preselection_observation_upstream_dispatch`].
    pub fn cancel_preselection_observation_upstream_transaction<Context>(
        &mut self,
        transaction: UpstreamPreselectionTransaction<Context>,
    ) -> Result<Context, PreselectionDispatchError> {
        let UpstreamPreselectionTransaction { dispatch, context } = transaction;
        self.cancel_preselection_observation_upstream_dispatch(dispatch)?;
        Ok(context)
    }
}

fn system_unix_millis() -> Result<u64, PreselectionDispatchError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PreselectionDispatchError::Time)?
        .as_millis();
    u64::try_from(millis).map_err(|_| PreselectionDispatchError::Time)
}

/// Check only the authenticated transport facts available for an unsigned client-hop request.
///
/// A0 deliberately carries no requester identity, so this cannot bind the authenticated sender to
/// a request field. It requires the request target to be local and the remote sender to differ from
/// both the local target and challenged actor.
pub(super) fn client_request_has_local_target_from_distinct_sender(
    request: &ClientPreselectionObservationRequest,
    authenticated_sender: &PeerId,
    local_relay: &PeerId,
) -> bool {
    if authenticated_sender == local_relay {
        return false;
    }
    let Ok(typed_request) = decode_canonical::<PreselectionObservationRequest>(
        request.as_encoded(),
        MAX_PRESELECTION_REQUEST_SIZE,
    ) else {
        return false;
    };
    if typed_request.validate().is_err() || !request_is_current(&typed_request) {
        return false;
    }
    request_target_and_family(&typed_request)
        .is_ok_and(|(target, actor, _)| target == *local_relay && actor != *authenticated_sender)
}

pub(super) fn upstream_request_has_authenticated_target(
    request: &UpstreamPreselectionObservationRequest,
    authenticated_relay: &PeerId,
    local_exit: &PeerId,
) -> bool {
    if authenticated_relay == local_exit {
        return false;
    }
    let Ok(typed_request) = decode_canonical::<PreselectionObservationRequest>(
        request.as_encoded(),
        MAX_PRESELECTION_REQUEST_SIZE,
    ) else {
        return false;
    };
    typed_request.validate().is_ok()
        && request_is_current(&typed_request)
        && upstream_target_and_family(&typed_request, *authenticated_relay)
            .is_ok_and(|(target, _)| target == *local_exit)
}

fn request_is_current(request: &PreselectionObservationRequest) -> bool {
    system_unix_millis()
        .is_ok_and(|now_ms| request.created_at_ms <= now_ms && now_ms < request.expires_at_ms)
}

fn request_target_and_family(
    request: &PreselectionObservationRequest,
) -> Result<(PeerId, PeerId, IpFamily), PreselectionDispatchError> {
    let actor = request
        .actor
        .as_ref()
        .ok_or(PreselectionDispatchError::Request)?;
    let scope = request
        .scope
        .as_ref()
        .ok_or(PreselectionDispatchError::Request)?;
    let role = PreselectionObservationRole::try_from(scope.role)
        .map_err(|_| PreselectionDispatchError::Request)?;
    let family = match ObservationAddressFamily::try_from(scope.address_family)
        .map_err(|_| PreselectionDispatchError::Request)?
    {
        ObservationAddressFamily::Ipv4 => IpFamily::Ipv4,
        ObservationAddressFamily::Ipv6 => IpFamily::Ipv6,
        ObservationAddressFamily::Unspecified => return Err(PreselectionDispatchError::Request),
    };
    let actor_peer =
        PeerId::from_bytes(&actor.peer_id).map_err(|_| PreselectionDispatchError::Request)?;
    let target = match (role, request.forwarded_control.as_ref()) {
        (PreselectionObservationRole::Relay, None) => actor_peer,
        (PreselectionObservationRole::Exit, Some(control)) => {
            let control_peer = PeerId::from_bytes(&control.peer_id)
                .map_err(|_| PreselectionDispatchError::Request)?;
            if control_peer == actor_peer {
                return Err(PreselectionDispatchError::Request);
            }
            control_peer
        }
        (PreselectionObservationRole::Unspecified, _)
        | (PreselectionObservationRole::Relay, Some(_))
        | (PreselectionObservationRole::Exit, None) => {
            return Err(PreselectionDispatchError::Request);
        }
    };
    Ok((target, actor_peer, family))
}

fn upstream_target_and_family(
    request: &PreselectionObservationRequest,
    local_peer_id: PeerId,
) -> Result<(PeerId, IpFamily), PreselectionDispatchError> {
    let actor = request
        .actor
        .as_ref()
        .ok_or(PreselectionDispatchError::Request)?;
    let scope = request
        .scope
        .as_ref()
        .ok_or(PreselectionDispatchError::Request)?;
    let control = request
        .forwarded_control
        .as_ref()
        .ok_or(PreselectionDispatchError::Request)?;
    if PreselectionObservationRole::try_from(scope.role)
        .map_err(|_| PreselectionDispatchError::Request)?
        != PreselectionObservationRole::Exit
    {
        return Err(PreselectionDispatchError::Request);
    }
    let family = match ObservationAddressFamily::try_from(scope.address_family)
        .map_err(|_| PreselectionDispatchError::Request)?
    {
        ObservationAddressFamily::Ipv4 => IpFamily::Ipv4,
        ObservationAddressFamily::Ipv6 => IpFamily::Ipv6,
        ObservationAddressFamily::Unspecified => return Err(PreselectionDispatchError::Request),
    };
    let exit_peer =
        PeerId::from_bytes(&actor.peer_id).map_err(|_| PreselectionDispatchError::Request)?;
    let control_peer =
        PeerId::from_bytes(&control.peer_id).map_err(|_| PreselectionDispatchError::Request)?;
    if control_peer != local_peer_id || exit_peer == local_peer_id || exit_peer == control_peer {
        return Err(PreselectionDispatchError::Request);
    }
    Ok((exit_peer, family))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use libp2p::{
        Multiaddr, Swarm, Transport as _,
        core::{ConnectedPoint, Endpoint, transport::MemoryTransport, transport::PortUse, upgrade},
        identity, noise, request_response,
        swarm::{
            AddressChange, ConnectionClosed, FromSwarm, NetworkBehaviour, SwarmEvent,
            behaviour::ConnectionEstablished,
        },
        yamux,
    };
    use volparossa_protocol::{
        PROTOCOL_VERSION, PreselectionActorBinding, PreselectionObservationReceipt,
        PreselectionObservationScope, TimePolicy, Transport, encode_canonical, generate_nonce,
        node_id_from_public_key, sign_control_message_with,
    };

    use crate::{
        BehaviourEvent, DiscoveryEvent, DiscoveryProtocolRoles,
        preselection_wire::{
            ClientPreselectionObservationCodec, UpstreamPreselectionObservationCodec,
            client_preselection_observation_behaviour, upstream_preselection_observation_behaviour,
        },
    };

    const CONNECTION: usize = 41;

    struct ClientRequestFixture {
        request: ClientPreselectionObservationRequest,
        encoded: Vec<u8>,
        typed: PreselectionObservationRequest,
    }

    struct AttemptContext {
        candidate_snapshot_marker: Box<[u8]>,
    }

    fn now_ms() -> u64 {
        system_unix_millis().expect("test wall clock")
    }

    async fn next_other(service: &mut DiscoveryService) -> SwarmEvent<BehaviourEvent> {
        loop {
            if let DiscoveryEvent::Other(event) = service.next_event().await {
                return event;
            }
        }
    }

    fn custom_client_preselection_swarm(
        keypair: &identity::Keypair,
    ) -> Swarm<request_response::Behaviour<ClientPreselectionObservationCodec>> {
        let peer_id = keypair.public().to_peer_id();
        let transport = MemoryTransport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(keypair).expect("custom client noise"))
            .multiplex(yamux::Config::default())
            .boxed();
        Swarm::new(
            transport,
            client_preselection_observation_behaviour(Some(
                request_response::ProtocolSupport::Full,
            )),
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        )
    }

    fn custom_upstream_preselection_swarm(
        keypair: &identity::Keypair,
    ) -> Swarm<request_response::Behaviour<UpstreamPreselectionObservationCodec>> {
        let peer_id = keypair.public().to_peer_id();
        let transport = MemoryTransport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(keypair).expect("custom upstream noise"))
            .multiplex(yamux::Config::default())
            .boxed();
        Swarm::new(
            transport,
            upstream_preselection_observation_behaviour(Some(
                request_response::ProtocolSupport::Full,
            )),
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        )
    }

    async fn connect_custom_behaviour<B>(custom: &mut Swarm<B>, service: &mut DiscoveryService)
    where
        B: NetworkBehaviour,
    {
        service
            .listen_on("/memory/0".parse().expect("custom memory address"))
            .expect("custom memory listener");
        let address = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = next_other(service).await {
                    break address;
                }
            }
        })
        .await
        .expect("custom listener timeout");
        let service_peer = *service.local_peer_id();
        custom
            .dial(
                address
                    .with_p2p(service_peer)
                    .expect("peer-bound custom address"),
            )
            .expect("custom dial");
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut custom_connected = false;
            let mut service_connected = false;
            while !custom_connected || !service_connected {
                tokio::select! {
                    event = custom.select_next_some() => {
                        custom_connected |= matches!(
                            event,
                            SwarmEvent::ConnectionEstablished { peer_id, .. }
                                if peer_id == service_peer
                        );
                    }
                    event = next_other(service) => {
                        service_connected |= matches!(event, SwarmEvent::ConnectionEstablished { .. });
                    }
                }
            }
        })
        .await
        .expect("custom connection timeout");
    }

    fn raw_public_key(key: &identity::Keypair) -> [u8; 32] {
        key.clone()
            .try_into_ed25519()
            .expect("Ed25519 key")
            .public()
            .to_bytes()
    }

    fn actor(key: &identity::Keypair, marker: u8, created_at_ms: u64) -> PreselectionActorBinding {
        let public_key = raw_public_key(key);
        PreselectionActorBinding {
            node_id: node_id_from_public_key(&public_key).to_vec(),
            peer_id: key.public().to_peer_id().to_bytes(),
            public_key: public_key.to_vec(),
            advertisement_sequence: u64::from(marker),
            advertisement_expires_at_ms: created_at_ms + 60_000,
            advertisement_payload_hash: vec![marker; 32],
            capability_expires_at_ms: created_at_ms + 60_000,
        }
    }

    fn client_request(
        role: PreselectionObservationRole,
        actor: PreselectionActorBinding,
        forwarded_control: Option<PreselectionActorBinding>,
        family: ObservationAddressFamily,
        created_at_ms: u64,
    ) -> ClientRequestFixture {
        client_request_with_lifetime(role, actor, forwarded_control, family, created_at_ms, 4_000)
    }

    fn client_request_with_lifetime(
        role: PreselectionObservationRole,
        actor: PreselectionActorBinding,
        forwarded_control: Option<PreselectionActorBinding>,
        family: ObservationAddressFamily,
        created_at_ms: u64,
        lifetime_ms: u64,
    ) -> ClientRequestFixture {
        let typed = PreselectionObservationRequest {
            protocol_version: PROTOCOL_VERSION,
            challenge: generate_nonce().to_vec(),
            actor: Some(actor),
            scope: Some(PreselectionObservationScope {
                role: role as i32,
                transport: Transport::TcpMptcp as i32,
                address_family: family as i32,
                policy_version: 1,
                policy_hash: vec![9; 32],
                policy_expires_at_ms: created_at_ms + 60_000,
            }),
            forwarded_control,
            created_at_ms,
            expires_at_ms: created_at_ms
                .checked_add(lifetime_ms)
                .expect("bounded request lifetime"),
        };
        let encoded = encode_canonical(&typed, MAX_PRESELECTION_REQUEST_SIZE).expect("request");
        let request = ClientPreselectionObservationRequest::from_canonical(encoded.clone())
            .expect("valid client request");
        ClientRequestFixture {
            request,
            encoded,
            typed,
        }
    }

    fn signed_response(
        fixture: &ClientRequestFixture,
        key: &identity::Keypair,
        observed_at_ms: u64,
    ) -> ClientPreselectionObservationResponse {
        let nonce = generate_nonce();
        let receipt = PreselectionObservationReceipt {
            request_hash: preselection_observation_request_hash(&fixture.encoded)
                .expect("request hash")
                .to_vec(),
            challenge: fixture.typed.challenge.clone(),
            actor: fixture.typed.actor.clone(),
            scope: fixture.typed.scope.clone(),
            observed_at_ms,
            valid_until_ms: observed_at_ms + 2_000,
            nonce: nonce.to_vec(),
        };
        let encoded = sign_control_message_with(
            &receipt,
            raw_public_key(key),
            observed_at_ms,
            observed_at_ms + 2_000,
            nonce,
            TimePolicy::default(),
            |message| key.sign(message).ok()?.try_into().ok(),
        )
        .expect("signed receipt");
        ClientPreselectionObservationResponse::from_canonical(encoded)
            .expect("client response wrapper")
    }

    fn client_service(key: identity::Keypair) -> DiscoveryService {
        DiscoveryService::new_with_protocol_roles(
            key,
            DiscoveryProtocolRoles::new(true, false, false),
        )
        .expect("client discovery")
    }

    fn relay_service(key: identity::Keypair) -> DiscoveryService {
        DiscoveryService::new_with_protocol_roles(
            key,
            DiscoveryProtocolRoles::new(false, true, false),
        )
        .expect("relay discovery")
    }

    fn client_and_relay_service(key: identity::Keypair) -> DiscoveryService {
        DiscoveryService::new_with_protocol_roles(
            key,
            DiscoveryProtocolRoles::new(true, true, false),
        )
        .expect("client and relay discovery")
    }

    fn upstream_request(fixture: &ClientRequestFixture) -> UpstreamPreselectionObservationRequest {
        UpstreamPreselectionObservationRequest::from_canonical(fixture.encoded.clone())
            .expect("valid upstream request")
    }

    fn signed_upstream_response(
        fixture: &ClientRequestFixture,
        key: &identity::Keypair,
        observed_at_ms: u64,
    ) -> UpstreamPreselectionObservationResponse {
        let nonce = generate_nonce();
        let receipt = PreselectionObservationReceipt {
            request_hash: preselection_observation_request_hash(&fixture.encoded)
                .expect("request hash")
                .to_vec(),
            challenge: fixture.typed.challenge.clone(),
            actor: fixture.typed.actor.clone(),
            scope: fixture.typed.scope.clone(),
            observed_at_ms,
            valid_until_ms: observed_at_ms + 2_000,
            nonce: nonce.to_vec(),
        };
        let encoded = sign_control_message_with(
            &receipt,
            raw_public_key(key),
            observed_at_ms,
            observed_at_ms + 2_000,
            nonce,
            TimePolicy::default(),
            |message| key.sign(message).ok()?.try_into().ok(),
        )
        .expect("signed exit receipt");
        UpstreamPreselectionObservationResponse::from_canonical(encoded)
            .expect("upstream response wrapper")
    }

    fn dialer(value: &str) -> ConnectedPoint {
        ConnectedPoint::Dialer {
            address: value.parse::<Multiaddr>().expect("multiaddr"),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        }
    }

    fn established(
        service: &mut DiscoveryService,
        peer: PeerId,
        id: usize,
        endpoint: &ConnectedPoint,
        other_established: usize,
    ) {
        service
            .swarm
            .behaviour_mut()
            .connection_provenance
            .on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id: peer,
                connection_id: ConnectionId::new_unchecked(id),
                endpoint,
                failed_addresses: &[],
                other_established,
            }));
    }

    fn changed(
        service: &mut DiscoveryService,
        peer: PeerId,
        id: usize,
        old: &ConnectedPoint,
        new: &ConnectedPoint,
    ) {
        service
            .swarm
            .behaviour_mut()
            .connection_provenance
            .on_swarm_event(FromSwarm::AddressChange(AddressChange {
                peer_id: peer,
                connection_id: ConnectionId::new_unchecked(id),
                old,
                new,
            }));
    }

    fn closed(service: &mut DiscoveryService, peer: PeerId, id: usize, endpoint: &ConnectedPoint) {
        service
            .swarm
            .behaviour_mut()
            .connection_provenance
            .on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id: peer,
                connection_id: ConnectionId::new_unchecked(id),
                endpoint,
                cause: None,
                remaining_established: 0,
            }));
    }

    async fn connect_memory(dialing: &mut DiscoveryService, listening: &mut DiscoveryService) {
        const TEST_TIMEOUT: Duration = Duration::from_secs(10);
        listening
            .listen_on("/memory/0".parse().expect("memory address"))
            .expect("memory listener");
        let address = tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = next_other(listening).await {
                    break address;
                }
            }
        })
        .await
        .expect("memory listener timeout");
        let listening_peer = *listening.local_peer_id();
        let dialing_peer = *dialing.local_peer_id();
        dialing
            .dial_peerlink(&crate::PeerLink::new(listening_peer, address).expect("memory peerlink"))
            .expect("memory dial");
        tokio::time::timeout(TEST_TIMEOUT, async {
            let mut dialing_connected = false;
            let mut listening_connected = false;
            while !dialing_connected || !listening_connected {
                tokio::select! {
                    event = next_other(dialing) => {
                        dialing_connected |= matches!(
                            event,
                            SwarmEvent::ConnectionEstablished { peer_id, .. }
                                if peer_id == listening_peer
                        );
                    }
                    event = next_other(listening) => {
                        listening_connected |= matches!(
                            event,
                            SwarmEvent::ConnectionEstablished { peer_id, .. }
                                if peer_id == dialing_peer
                        );
                    }
                }
            }
        })
        .await
        .expect("memory connection timeout");
    }

    async fn connect_memory_and_capture_dialer_lineage(
        dialing: &mut DiscoveryService,
        listening: &mut DiscoveryService,
    ) -> (ConnectionId, ConnectedPoint) {
        const TEST_TIMEOUT: Duration = Duration::from_secs(10);
        listening
            .listen_on("/memory/0".parse().expect("memory address"))
            .expect("memory listener");
        let address = tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = next_other(listening).await {
                    break address;
                }
            }
        })
        .await
        .expect("memory listener timeout");
        let listening_peer = *listening.local_peer_id();
        let dialing_peer = *dialing.local_peer_id();
        dialing
            .dial_peerlink(&crate::PeerLink::new(listening_peer, address).expect("memory peerlink"))
            .expect("memory dial");
        tokio::time::timeout(TEST_TIMEOUT, async {
            let mut dialing_lineage = None;
            let mut listening_connected = false;
            while dialing_lineage.is_none() || !listening_connected {
                tokio::select! {
                    event = next_other(dialing) => {
                        if let SwarmEvent::ConnectionEstablished {
                            peer_id,
                            connection_id,
                            endpoint,
                            ..
                        } = event
                        {
                            if peer_id == listening_peer {
                                dialing_lineage = Some((connection_id, endpoint));
                            }
                        }
                    }
                    event = next_other(listening) => {
                        listening_connected |= matches!(
                            event,
                            SwarmEvent::ConnectionEstablished { peer_id, .. }
                                if peer_id == dialing_peer
                        );
                    }
                }
            }
            dialing_lineage.expect("dialer lineage")
        })
        .await
        .expect("memory connection timeout")
    }

    async fn exchange_client_response(
        client: &mut DiscoveryService,
        relay: &mut DiscoveryService,
        fixture: ClientRequestFixture,
        response: ClientPreselectionObservationResponse,
    ) {
        let relay_peer = *relay.local_peer_id();
        let client_peer = *client.local_peer_id();
        let expected_request = fixture.encoded;
        let expected_response = response.as_encoded().to_vec();
        let outbound = client
            .swarm
            .behaviour_mut()
            .preselection_observation
            .send_request(&relay_peer, fixture.request);
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut response = Some(response);
            loop {
                tokio::select! {
                    event = client.next_internal_event() => {
                        match event {
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                                request_response::Event::Message {
                                    peer,
                                    message: request_response::Message::Response {
                                        request_id,
                                        response,
                                    },
                                    ..
                                },
                            )) if request_id == outbound => {
                                assert_eq!(peer, relay_peer);
                                assert_eq!(response.as_encoded(), expected_response);
                                break;
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                                request_response::Event::OutboundFailure {
                                    request_id,
                                    error,
                                    ..
                                },
                            )) if request_id == outbound => panic!("client hop failed: {error}"),
                            _ => {}
                        }
                    }
                    event = relay.next_internal_event() => {
                        if let SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                            request_response::Event::Message {
                                peer,
                                message: request_response::Message::Request {
                                    request,
                                    channel,
                                    ..
                                },
                                ..
                            },
                        )) = event {
                            assert_eq!(peer, client_peer);
                            assert_eq!(request.as_encoded(), expected_request);
                            relay
                                .swarm
                                .behaviour_mut()
                                .preselection_observation
                                .send_response(channel, response.take().expect("one response"))
                                .expect("relay response");
                        }
                    }
                }
            }
        })
        .await
        .expect("client-hop exchange timeout");
    }

    async fn exchange_upstream_response(
        relay: &mut DiscoveryService,
        exit: &mut DiscoveryService,
        fixture: &ClientRequestFixture,
        response: UpstreamPreselectionObservationResponse,
    ) {
        let exit_peer = *exit.local_peer_id();
        let relay_peer = *relay.local_peer_id();
        let expected_request = fixture.encoded.clone();
        let expected_response = response.as_encoded().to_vec();
        let outbound = relay
            .swarm
            .behaviour_mut()
            .preselection_observation_upstream
            .send_request(&exit_peer, upstream_request(fixture));
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut response = Some(response);
            loop {
                tokio::select! {
                    event = relay.next_internal_event() => {
                        match event {
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservationUpstream(
                                request_response::Event::Message {
                                    peer,
                                    message: request_response::Message::Response {
                                        request_id,
                                        response,
                                    },
                                    ..
                                },
                            )) if request_id == outbound => {
                                assert_eq!(peer, exit_peer);
                                assert_eq!(response.as_encoded(), expected_response);
                                break;
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservationUpstream(
                                request_response::Event::OutboundFailure {
                                    request_id,
                                    error,
                                    ..
                                },
                            )) if request_id == outbound => panic!("upstream hop failed: {error}"),
                            _ => {}
                        }
                    }
                    event = exit.next_internal_event() => {
                        if let SwarmEvent::Behaviour(
                            BehaviourEvent::PreselectionObservationUpstream(
                                request_response::Event::Message {
                                    peer,
                                    message: request_response::Message::Request {
                                        request,
                                        channel,
                                        ..
                                    },
                                    ..
                                },
                            ),
                        ) = event {
                            assert_eq!(peer, relay_peer);
                            assert_eq!(request.as_encoded(), expected_request);
                            exit.swarm
                                .behaviour_mut()
                                .preselection_observation_upstream
                                .send_response(channel, response.take().expect("one response"))
                                .expect("exit response");
                        }
                    }
                }
            }
        })
        .await
        .expect("upstream exchange timeout");
    }

    fn direct_context() -> (
        DiscoveryService,
        identity::Keypair,
        PreselectionActorBinding,
        PeerId,
        ConnectedPoint,
    ) {
        let created_at_ms = now_ms();
        let relay_key = identity::Keypair::generate_ed25519();
        let relay = actor(&relay_key, 13, created_at_ms);
        let peer = relay_key.public().to_peer_id();
        let mut service = client_service(identity::Keypair::generate_ed25519());
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        established(&mut service, peer, CONNECTION, &endpoint, 0);
        (service, relay_key, relay, peer, endpoint)
    }

    fn dispatch_direct(
        service: &mut DiscoveryService,
        binding: PreselectionActorBinding,
    ) -> ClientPreselectionDispatch {
        let fixture = client_request(
            PreselectionObservationRole::Relay,
            binding,
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        service
            .dispatch_preselection_observation(
                fixture.request,
                Instant::now() + Duration::from_secs(30),
            )
            .expect("direct dispatch")
    }

    #[tokio::test]
    async fn direct_target_hash_id_timeout_cap_and_single_slot_are_exact() {
        let (mut service, _, relay, peer, _) = direct_context();
        let fixture = client_request(
            PreselectionObservationRole::Relay,
            relay.clone(),
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        let expected_hash =
            preselection_observation_request_hash(&fixture.encoded).expect("request hash");
        let dispatch = service
            .dispatch_preselection_observation(
                fixture.request,
                Instant::now() + Duration::from_secs(60),
            )
            .expect("dispatch");
        assert_eq!(dispatch.expected_peer_id, peer);
        assert_eq!(dispatch.request_hash, expected_hash);
        assert!(dispatch.deadline > dispatch.sent_at);
        assert!(
            dispatch.deadline
                <= dispatch
                    .sent_at
                    .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
                    .expect("wire timeout cap")
        );
        let busy = client_request(
            PreselectionObservationRole::Relay,
            relay.clone(),
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        assert!(matches!(
            service.dispatch_preselection_observation(
                busy.request,
                Instant::now() + Duration::from_secs(30)
            ),
            Err(PreselectionDispatchError::Busy)
        ));
        service
            .cancel_preselection_observation_dispatch(dispatch)
            .expect("exact cancellation");
        let replacement = dispatch_direct(&mut service, relay);
        service
            .cancel_preselection_observation_dispatch(replacement)
            .expect("replacement cancellation");
    }

    #[tokio::test]
    async fn request_ttl_is_a_real_deadline_minimum() {
        let (mut service, _, relay, _, _) = direct_context();
        let fixture = client_request_with_lifetime(
            PreselectionObservationRole::Relay,
            relay,
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
            1_000,
        );
        let dispatch = service
            .dispatch_preselection_observation(
                fixture.request,
                Instant::now() + Duration::from_secs(30),
            )
            .expect("short-lived dispatch");
        assert!(
            dispatch.deadline
                <= dispatch
                    .sent_at
                    .checked_add(Duration::from_secs(1))
                    .expect("request lifetime")
        );
        assert!(
            dispatch.deadline
                < dispatch
                    .sent_at
                    .checked_add(PRESELECTION_OBSERVATION_REQUEST_TIMEOUT)
                    .expect("wire timeout")
        );
        service
            .cancel_preselection_observation_dispatch(dispatch)
            .expect("short-lived cancellation");
    }

    #[tokio::test]
    async fn dropping_an_active_dispatch_permanently_leaves_the_slot_fail_closed() {
        let (mut service, _, relay, _, _) = direct_context();
        let dispatch = dispatch_direct(&mut service, relay.clone());
        drop(dispatch);
        let replacement = client_request(
            PreselectionObservationRole::Relay,
            relay,
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        assert!(matches!(
            service.dispatch_preselection_observation(
                replacement.request,
                Instant::now() + Duration::from_secs(30)
            ),
            Err(PreselectionDispatchError::Busy)
        ));
    }

    #[tokio::test]
    async fn forwarded_exit_targets_only_control_and_uses_shorter_deadline() {
        let created_at_ms = now_ms();
        let control_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let control = actor(&control_key, 2, created_at_ms);
        let exit = actor(&exit_key, 3, created_at_ms);
        let control_peer = control_key.public().to_peer_id();
        let exit_peer = exit_key.public().to_peer_id();
        let mut service = client_service(identity::Keypair::generate_ed25519());
        let endpoint = dialer("/ip6/2606:4700:4700::1111/udp/443/quic-v1");
        established(&mut service, control_peer, CONNECTION, &endpoint, 0);
        let fixture = client_request(
            PreselectionObservationRole::Exit,
            exit,
            Some(control),
            ObservationAddressFamily::Ipv6,
            created_at_ms,
        );
        let absolute_deadline = Instant::now() + Duration::from_secs(1);
        let dispatch = service
            .dispatch_preselection_observation(fixture.request, absolute_deadline)
            .expect("forwarded dispatch");
        assert_eq!(dispatch.expected_peer_id, control_peer);
        assert_ne!(dispatch.expected_peer_id, exit_peer);
        assert_eq!(dispatch.deadline, absolute_deadline);
    }

    #[tokio::test]
    async fn role_and_expired_request_fail_before_connection_provenance() {
        let created_at_ms = now_ms();
        let remote_key = identity::Keypair::generate_ed25519();
        let remote = actor(&remote_key, 4, created_at_ms);
        let request = client_request(
            PreselectionObservationRole::Relay,
            remote.clone(),
            None,
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let mut non_client = DiscoveryService::new_with_protocol_roles(
            identity::Keypair::generate_ed25519(),
            DiscoveryProtocolRoles::new(false, true, false),
        )
        .expect("relay discovery");
        assert!(matches!(
            non_client.dispatch_preselection_observation(
                request.request,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(PreselectionDispatchError::Role)
        ));

        let expired_at_ms = now_ms() - 5_000;
        let expired = client_request(
            PreselectionObservationRole::Relay,
            actor(&remote_key, 5, expired_at_ms),
            None,
            ObservationAddressFamily::Ipv4,
            expired_at_ms,
        );
        let mut service = client_service(identity::Keypair::generate_ed25519());
        assert!(matches!(
            service.dispatch_preselection_observation(
                expired.request,
                Instant::now() + Duration::from_secs(30)
            ),
            Err(PreselectionDispatchError::Time)
        ));
    }

    #[tokio::test]
    async fn every_local_actor_position_fails_closed() {
        let created_at_ms = now_ms();
        let local_direct_key = identity::Keypair::generate_ed25519();
        let direct = client_request(
            PreselectionObservationRole::Relay,
            actor(&local_direct_key, 6, created_at_ms),
            None,
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let mut direct_service = client_service(local_direct_key);
        assert!(matches!(
            direct_service.dispatch_preselection_observation(
                direct.request,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(PreselectionDispatchError::Request)
        ));

        let local_exit_key = identity::Keypair::generate_ed25519();
        let forwarded_exit = client_request(
            PreselectionObservationRole::Exit,
            actor(&local_exit_key, 7, created_at_ms),
            Some(actor(
                &identity::Keypair::generate_ed25519(),
                8,
                created_at_ms,
            )),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let mut exit_service = client_service(local_exit_key);
        assert!(matches!(
            exit_service.dispatch_preselection_observation(
                forwarded_exit.request,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(PreselectionDispatchError::Request)
        ));

        let local_control_key = identity::Keypair::generate_ed25519();
        let forwarded_control = client_request(
            PreselectionObservationRole::Exit,
            actor(&identity::Keypair::generate_ed25519(), 9, created_at_ms),
            Some(actor(&local_control_key, 10, created_at_ms)),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let mut control_service = client_service(local_control_key);
        assert!(matches!(
            control_service.dispatch_preselection_observation(
                forwarded_control.request,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(PreselectionDispatchError::Request)
        ));
    }

    #[tokio::test]
    async fn forwarded_request_never_uses_a_direct_exit_connection() {
        let created_at_ms = now_ms();
        let control = actor(&identity::Keypair::generate_ed25519(), 11, created_at_ms);
        let exit_key = identity::Keypair::generate_ed25519();
        let exit = actor(&exit_key, 12, created_at_ms);
        let exit_peer = exit_key.public().to_peer_id();
        let mut service = client_service(identity::Keypair::generate_ed25519());
        let endpoint = dialer("/ip4/8.8.8.8/tcp/443");
        established(&mut service, exit_peer, CONNECTION, &endpoint, 0);
        let fixture = client_request(
            PreselectionObservationRole::Exit,
            exit,
            Some(control),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        assert!(matches!(
            service.dispatch_preselection_observation(
                fixture.request,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(PreselectionDispatchError::Provenance)
        ));
    }

    #[tokio::test]
    async fn family_and_total_connection_count_gate_dispatch() {
        let created_at_ms = now_ms();
        let relay_key = identity::Keypair::generate_ed25519();
        let relay = actor(&relay_key, 14, created_at_ms);
        let peer = relay_key.public().to_peer_id();
        let ipv4 = dialer("/ip4/1.1.1.8/tcp/443");

        let mut wrong_family = client_service(identity::Keypair::generate_ed25519());
        established(&mut wrong_family, peer, CONNECTION, &ipv4, 0);
        let request = client_request(
            PreselectionObservationRole::Relay,
            relay.clone(),
            None,
            ObservationAddressFamily::Ipv6,
            created_at_ms,
        );
        assert!(matches!(
            wrong_family.dispatch_preselection_observation(
                request.request,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(PreselectionDispatchError::Provenance)
        ));

        let mut multiple = client_service(identity::Keypair::generate_ed25519());
        let second = dialer("/ip4/1.1.1.9/udp/443/quic-v1");
        established(&mut multiple, peer, CONNECTION, &ipv4, 0);
        established(&mut multiple, peer, CONNECTION + 1, &second, 1);
        let request = client_request(
            PreselectionObservationRole::Relay,
            relay,
            None,
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        assert!(matches!(
            multiple.dispatch_preselection_observation(
                request.request,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(PreselectionDispatchError::Provenance)
        ));
    }

    #[tokio::test]
    async fn request_id_and_peer_correlation_are_exact_and_mismatch_stays_busy() {
        let (mut wrong_id_service, _, relay, peer, _) = direct_context();
        let wrong_id = dispatch_direct(&mut wrong_id_service, relay.clone());
        let unrelated = client_request(
            PreselectionObservationRole::Relay,
            relay.clone(),
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        let unrelated_id = wrong_id_service
            .swarm
            .behaviour_mut()
            .preselection_observation
            .send_request(&peer, unrelated.request);
        let request_id = wrong_id.request_id;
        assert_eq!(wrong_id.request_id, request_id);
        assert_ne!(wrong_id.request_id, unrelated_id);
        let sent_at = wrong_id.sent_at;
        assert!(matches!(
            wrong_id_service.bind_preselection_observation_response_at(
                wrong_id,
                peer,
                ConnectionId::new_unchecked(CONNECTION),
                unrelated_id,
                sent_at,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Correlation)
        ));
        let blocked = client_request(
            PreselectionObservationRole::Relay,
            relay,
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        assert!(matches!(
            wrong_id_service.dispatch_preselection_observation(
                blocked.request,
                Instant::now() + Duration::from_secs(30)
            ),
            Err(PreselectionDispatchError::Busy)
        ));

        let (mut wrong_peer_service, _, relay, _, _) = direct_context();
        let wrong_peer = dispatch_direct(&mut wrong_peer_service, relay);
        let request_id = wrong_peer.request_id;
        let sent_at = wrong_peer.sent_at;
        assert!(matches!(
            wrong_peer_service.bind_preselection_observation_response_at(
                wrong_peer,
                PeerId::random(),
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                sent_at,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Correlation)
        ));
    }

    #[tokio::test]
    async fn wrong_connection_fails_provenance_and_consumes_the_exact_slot() {
        let (mut wrong_connection_service, _, relay, peer, _) = direct_context();
        let wrong_connection = dispatch_direct(&mut wrong_connection_service, relay.clone());
        let request_id = wrong_connection.request_id;
        let sent_at = wrong_connection.sent_at;
        assert!(matches!(
            wrong_connection_service.bind_preselection_observation_response_at(
                wrong_connection,
                peer,
                ConnectionId::new_unchecked(CONNECTION + 9),
                request_id,
                sent_at,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Provenance)
        ));
        let replacement = dispatch_direct(&mut wrong_connection_service, relay);
        wrong_connection_service
            .cancel_preselection_observation_dispatch(replacement)
            .expect("provenance failure clears the exact slot");
    }

    #[tokio::test]
    async fn arrival_time_window_is_half_open_and_terminal_failure_consumes_the_slot() {
        let (mut too_early_service, _, relay, peer, _) = direct_context();
        let too_early = dispatch_direct(&mut too_early_service, relay.clone());
        let request_id = too_early.request_id;
        let arrived_at = too_early
            .sent_at
            .checked_sub(Duration::from_nanos(1))
            .expect("earlier instant");
        assert!(matches!(
            too_early_service.bind_preselection_observation_response_at(
                too_early,
                peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                arrived_at,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Time)
        ));
        let replacement = dispatch_direct(&mut too_early_service, relay);
        too_early_service
            .cancel_preselection_observation_dispatch(replacement)
            .expect("time failure clears the exact slot");

        let (mut deadline_service, _, relay, peer, _) = direct_context();
        let at_deadline = dispatch_direct(&mut deadline_service, relay);
        let request_id = at_deadline.request_id;
        let deadline = at_deadline.deadline;
        assert!(matches!(
            deadline_service.bind_preselection_observation_response_at(
                at_deadline,
                peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                deadline,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Time)
        ));
    }

    #[tokio::test]
    async fn arrival_exactly_at_send_time_is_the_inclusive_lower_bound() {
        let (mut service, _, relay, peer, _) = direct_context();
        let dispatch = dispatch_direct(&mut service, relay);
        let request_id = dispatch.request_id;
        let sent_at = dispatch.sent_at;
        let bound = service
            .bind_preselection_observation_response_at(
                dispatch,
                peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                sent_at,
                now_ms(),
            )
            .expect("send time is the inclusive arrival lower bound");
        assert_eq!(bound.sent_at_mono, sent_at);
        assert_eq!(bound.arrived_at_mono, sent_at);
    }

    #[tokio::test]
    async fn typed_client_response_event_retains_one_exact_opaque_proof() {
        let (mut service, relay_key, relay, peer, _) = direct_context();
        let fixture = client_request(
            PreselectionObservationRole::Relay,
            relay.clone(),
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        let expected_hash =
            preselection_observation_request_hash(&fixture.encoded).expect("request hash");
        let response = signed_response(&fixture, &relay_key, now_ms());
        let expected_response = response.as_encoded().to_vec();
        let transaction = service
            .dispatch_preselection_observation_with_context(
                fixture.request,
                Instant::now() + Duration::from_secs(30),
                AttemptContext {
                    candidate_snapshot_marker: vec![41, 42, 43].into_boxed_slice(),
                },
            )
            .expect("dispatch");
        let dispatch = &transaction.dispatch;
        let request_id = dispatch.request_id;
        let sent_at = dispatch.sent_at;
        let arrival = service
            .seal_client_preselection_response(
                peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                response,
            )
            .expect("service-sealed arrival");
        let (context, bound, returned_response) = service
            .bind_preselection_observation_response_with_context(transaction, arrival)
            .expect("sealed arrival binding");
        assert_eq!(&*context.candidate_snapshot_marker, &[41, 42, 43]);
        assert_eq!(returned_response.as_encoded(), expected_response);
        assert_eq!(bound.request_hash, expected_hash);
        assert_eq!(bound.request_id, request_id);
        assert_eq!(bound.sent_at_mono, sent_at);
        assert!(bound.arrived_at_mono >= sent_at);
        assert!(bound.arrived_at_mono < bound.deadline_mono);
        assert!(bound.arrived_at_unix_ms > 0);
        assert!(size_of_val(&bound.observation) > 0);
        let replacement = dispatch_direct(&mut service, relay);
        service
            .cancel_preselection_observation_dispatch(replacement)
            .expect("successful bind clears the exact slot");
    }

    #[tokio::test]
    async fn cross_service_sealed_arrival_is_rejected_and_leaves_the_slot_fail_closed() {
        let (mut service, relay_key, relay, peer, _) = direct_context();
        let dispatch = dispatch_direct(&mut service, relay.clone());
        let request_id = dispatch.request_id;
        let fixture = client_request(
            PreselectionObservationRole::Relay,
            relay.clone(),
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        let response = signed_response(&fixture, &relay_key, now_ms());
        let mut sibling = client_service(identity::Keypair::generate_ed25519());
        established(
            &mut sibling,
            peer,
            CONNECTION,
            &dialer("/ip4/1.1.1.8/tcp/443"),
            0,
        );
        let sibling_dispatch = dispatch_direct(&mut sibling, relay.clone());
        assert_eq!(sibling_dispatch.request_id, request_id);
        let arrival = sibling
            .seal_client_preselection_response(
                peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                response,
            )
            .expect("sibling-sealed arrival");
        assert!(matches!(
            service.bind_preselection_observation_response(dispatch, arrival),
            Err(PreselectionDispatchError::Correlation)
        ));
        let blocked = client_request(
            PreselectionObservationRole::Relay,
            relay,
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        assert!(matches!(
            service.dispatch_preselection_observation(
                blocked.request,
                Instant::now() + Duration::from_secs(30)
            ),
            Err(PreselectionDispatchError::Busy)
        ));
    }

    #[tokio::test]
    async fn stale_responses_are_dropped_before_sealing_on_both_hops() {
        let (mut client, relay_key, relay_binding, peer, _) = direct_context();
        let first = dispatch_direct(&mut client, relay_binding.clone());
        let stale_request_id = first.request_id;
        client
            .cancel_preselection_observation_dispatch(first)
            .expect("cancel first client dispatch");
        let replacement = dispatch_direct(&mut client, relay_binding.clone());
        assert_ne!(replacement.request_id, stale_request_id);
        let fixture = client_request(
            PreselectionObservationRole::Relay,
            relay_binding,
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        let stale_response = signed_response(&fixture, &relay_key, now_ms());
        let stale_event = SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
            request_response::Event::Message {
                peer,
                connection_id: ConnectionId::new_unchecked(CONNECTION),
                message: request_response::Message::Response {
                    request_id: stale_request_id,
                    response: stale_response,
                },
            },
        ));
        assert!(client.sanitize_public_event(stale_event).is_none());
        client
            .cancel_preselection_observation_dispatch(replacement)
            .expect("replacement client dispatch remains active");

        let created_at_ms = now_ms();
        let control_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let exit_peer = exit_key.public().to_peer_id();
        let mut control = relay_service(control_key.clone());
        established(
            &mut control,
            exit_peer,
            CONNECTION,
            &dialer("/ip4/9.9.9.9/tcp/443"),
            0,
        );
        let forwarded = client_request(
            PreselectionObservationRole::Exit,
            actor(&exit_key, 70, created_at_ms),
            Some(actor(&control_key, 71, created_at_ms)),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let first = control
            .dispatch_preselection_observation_upstream(
                upstream_request(&forwarded),
                Instant::now() + Duration::from_secs(30),
            )
            .expect("first upstream dispatch");
        let stale_request_id = first.request_id;
        control
            .cancel_preselection_observation_upstream_dispatch(first)
            .expect("cancel first upstream dispatch");
        let replacement = control
            .dispatch_preselection_observation_upstream(
                upstream_request(&forwarded),
                Instant::now() + Duration::from_secs(30),
            )
            .expect("replacement upstream dispatch");
        assert_ne!(replacement.request_id, stale_request_id);
        let stale_response = signed_upstream_response(&forwarded, &exit_key, now_ms());
        let stale_event = SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservationUpstream(
            request_response::Event::Message {
                peer: exit_peer,
                connection_id: ConnectionId::new_unchecked(CONNECTION),
                message: request_response::Message::Response {
                    request_id: stale_request_id,
                    response: stale_response,
                },
            },
        ));
        assert!(control.sanitize_public_event(stale_event).is_none());
        control
            .cancel_preselection_observation_upstream_dispatch(replacement)
            .expect("replacement upstream dispatch remains active");
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one real independent client-behaviour collision and transplant proof"
    )]
    async fn independent_client_behaviour_same_id_response_cannot_be_transplanted() {
        let (mut origin, relay_key, relay_binding, relay_peer, _) = direct_context();
        let fixture = client_request(
            PreselectionObservationRole::Relay,
            relay_binding.clone(),
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        let custom_request =
            ClientPreselectionObservationRequest::from_canonical(fixture.encoded.clone())
                .expect("custom client request");
        let response = signed_response(&fixture, &relay_key, now_ms());
        let dispatch = origin
            .dispatch_preselection_observation(
                fixture.request,
                Instant::now() + Duration::from_secs(30),
            )
            .expect("origin client dispatch");

        let custom_key = identity::Keypair::generate_ed25519();
        let custom_peer = custom_key.public().to_peer_id();
        let mut custom = custom_client_preselection_swarm(&custom_key);
        let mut responder = relay_service(relay_key);
        connect_custom_behaviour(&mut custom, &mut responder).await;
        let custom_request_id = custom
            .behaviour_mut()
            .send_request(&relay_peer, custom_request);
        assert_eq!(
            custom_request_id, dispatch.request_id,
            "the independent behaviour deliberately collides in its local ID namespace"
        );

        let (peer, connection_id, request_id, response) =
            tokio::time::timeout(Duration::from_secs(10), async {
                let mut response = Some(response);
                loop {
                    tokio::select! {
                        event = custom.select_next_some() => {
                            match event {
                                SwarmEvent::Behaviour(request_response::Event::Message {
                                    peer,
                                    connection_id,
                                    message: request_response::Message::Response {
                                        request_id,
                                        response,
                                    },
                                }) if request_id == custom_request_id => {
                                    break (peer, connection_id, request_id, response);
                                }
                                SwarmEvent::Behaviour(request_response::Event::OutboundFailure {
                                    request_id,
                                    error,
                                    ..
                                }) if request_id == custom_request_id => {
                                    panic!("custom client response failed: {error}");
                                }
                                _ => {}
                            }
                        }
                        event = responder.next_internal_event() => {
                            if let SwarmEvent::Behaviour(
                                BehaviourEvent::PreselectionObservation(
                                    request_response::Event::Message {
                                        peer,
                                        message: request_response::Message::Request {
                                            channel,
                                            ..
                                        },
                                        ..
                                    },
                                ),
                            ) = event
                            {
                                assert_eq!(peer, custom_peer);
                                responder
                                    .swarm
                                    .behaviour_mut()
                                    .preselection_observation
                                    .send_response(channel, response.take().expect("one response"))
                                    .expect("custom client response");
                            }
                        }
                    }
                }
            })
            .await
            .expect("custom client exchange timeout");
        assert_eq!(peer, relay_peer);
        assert_eq!(request_id, dispatch.request_id);

        let mut foreign_service = client_service(identity::Keypair::generate_ed25519());
        established(
            &mut foreign_service,
            relay_peer,
            CONNECTION,
            &dialer("/ip4/1.1.1.8/tcp/443"),
            0,
        );
        let foreign_dispatch = dispatch_direct(&mut foreign_service, relay_binding.clone());
        assert_eq!(foreign_dispatch.request_id, request_id);
        let foreign_arrival = foreign_service
            .seal_client_preselection_response(peer, connection_id, request_id, response)
            .expect("foreign client arrival");
        assert!(matches!(
            origin.bind_preselection_observation_response(dispatch, foreign_arrival),
            Err(PreselectionDispatchError::Correlation)
        ));
        let blocked = client_request(
            PreselectionObservationRole::Relay,
            relay_binding,
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        assert!(matches!(
            origin.dispatch_preselection_observation(
                blocked.request,
                Instant::now() + Duration::from_secs(30),
            ),
            Err(PreselectionDispatchError::Busy)
        ));
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one real independent upstream-behaviour collision and transplant proof"
    )]
    async fn independent_upstream_behaviour_same_id_response_cannot_be_transplanted() {
        let created_at_ms = now_ms();
        let relay_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let exit_peer = exit_key.public().to_peer_id();
        let exit_binding = actor(&exit_key, 63, created_at_ms);
        let relay_binding = actor(&relay_key, 64, created_at_ms);
        let fixture = client_request(
            PreselectionObservationRole::Exit,
            exit_binding,
            Some(relay_binding),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let custom_request = upstream_request(&fixture);
        let response = signed_upstream_response(&fixture, &exit_key, now_ms());
        let mut origin = relay_service(relay_key.clone());
        established(
            &mut origin,
            exit_peer,
            CONNECTION,
            &dialer("/ip4/9.9.9.9/tcp/443"),
            0,
        );
        let dispatch = origin
            .dispatch_preselection_observation_upstream(
                upstream_request(&fixture),
                Instant::now() + Duration::from_secs(30),
            )
            .expect("origin upstream dispatch");

        let custom_peer = relay_key.public().to_peer_id();
        let mut custom = custom_upstream_preselection_swarm(&relay_key);
        let mut responder = DiscoveryService::new_with_protocol_roles(
            exit_key.clone(),
            DiscoveryProtocolRoles::new(false, false, true),
        )
        .expect("custom upstream responder");
        connect_custom_behaviour(&mut custom, &mut responder).await;
        let custom_request_id = custom
            .behaviour_mut()
            .send_request(&exit_peer, custom_request);
        assert_eq!(
            custom_request_id, dispatch.request_id,
            "the independent upstream behaviour deliberately collides in its local ID namespace"
        );

        let (peer, connection_id, request_id, response) =
            tokio::time::timeout(Duration::from_secs(10), async {
                let mut response = Some(response);
                loop {
                    tokio::select! {
                        event = custom.select_next_some() => {
                            match event {
                                SwarmEvent::Behaviour(request_response::Event::Message {
                                    peer,
                                    connection_id,
                                    message: request_response::Message::Response {
                                        request_id,
                                        response,
                                    },
                                }) if request_id == custom_request_id => {
                                    break (peer, connection_id, request_id, response);
                                }
                                SwarmEvent::Behaviour(request_response::Event::OutboundFailure {
                                    request_id,
                                    error,
                                    ..
                                }) if request_id == custom_request_id => {
                                    panic!("custom upstream response failed: {error}");
                                }
                                _ => {}
                            }
                        }
                        event = responder.next_internal_event() => {
                            if let SwarmEvent::Behaviour(
                                BehaviourEvent::PreselectionObservationUpstream(
                                    request_response::Event::Message {
                                        peer,
                                        message: request_response::Message::Request {
                                            channel,
                                            ..
                                        },
                                        ..
                                    },
                                ),
                            ) = event
                            {
                                assert_eq!(peer, custom_peer);
                                responder
                                    .swarm
                                    .behaviour_mut()
                                    .preselection_observation_upstream
                                    .send_response(channel, response.take().expect("one response"))
                                    .expect("custom upstream response");
                            }
                        }
                    }
                }
            })
            .await
            .expect("custom upstream exchange timeout");
        assert_eq!(peer, exit_peer);
        assert_eq!(request_id, dispatch.request_id);

        let foreign_key = identity::Keypair::generate_ed25519();
        let mut foreign_service = relay_service(foreign_key.clone());
        established(
            &mut foreign_service,
            exit_peer,
            CONNECTION,
            &dialer("/ip4/9.9.9.9/tcp/443"),
            0,
        );
        let foreign_fixture = client_request(
            PreselectionObservationRole::Exit,
            actor(&exit_key, 68, created_at_ms),
            Some(actor(&foreign_key, 69, created_at_ms)),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let foreign_dispatch = foreign_service
            .dispatch_preselection_observation_upstream(
                upstream_request(&foreign_fixture),
                Instant::now() + Duration::from_secs(30),
            )
            .expect("foreign upstream dispatch");
        assert_eq!(foreign_dispatch.request_id, request_id);
        let foreign_arrival = foreign_service
            .seal_upstream_preselection_response(peer, connection_id, request_id, response)
            .expect("foreign upstream arrival");
        assert!(matches!(
            origin.bind_preselection_observation_upstream_response(dispatch, foreign_arrival),
            Err(PreselectionDispatchError::Correlation)
        ));
        assert!(matches!(
            origin.dispatch_preselection_observation_upstream(
                upstream_request(&fixture),
                Instant::now() + Duration::from_secs(30),
            ),
            Err(PreselectionDispatchError::Busy)
        ));
    }

    #[tokio::test]
    async fn service_instance_binding_rejects_cross_service_token_substitution() {
        let created_at_ms = now_ms();
        let local = identity::Keypair::generate_ed25519();
        let relay_key = identity::Keypair::generate_ed25519();
        let relay = actor(&relay_key, 15, created_at_ms);
        let peer = relay_key.public().to_peer_id();
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        let mut first = client_service(local.clone());
        let mut second = client_service(local);
        established(&mut first, peer, CONNECTION, &endpoint, 0);
        established(&mut second, peer, CONNECTION, &endpoint, 0);
        let first_dispatch = dispatch_direct(&mut first, relay.clone());
        let second_dispatch = dispatch_direct(&mut second, relay);
        assert_eq!(first_dispatch.request_id, second_dispatch.request_id);
        let request_id = first_dispatch.request_id;
        let arrived_at = first_dispatch.sent_at;
        assert!(matches!(
            second.bind_preselection_observation_response_at(
                first_dispatch,
                peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                arrived_at,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Correlation)
        ));
        second
            .cancel_preselection_observation_dispatch(second_dispatch)
            .expect("second service remains independently active");
    }

    #[tokio::test]
    async fn connection_change_close_and_new_sibling_each_invalidate_dispatch() {
        let (mut changed_service, _, relay, peer, old) = direct_context();
        let dispatch = dispatch_direct(&mut changed_service, relay);
        let request_id = dispatch.request_id;
        let arrived_at = dispatch.sent_at;
        let new = dialer("/ip4/1.1.1.9/udp/443/quic-v1");
        changed(&mut changed_service, peer, CONNECTION, &old, &new);
        assert!(matches!(
            changed_service.bind_preselection_observation_response_at(
                dispatch,
                peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                arrived_at,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Provenance)
        ));

        let (mut closed_service, _, relay, peer, endpoint) = direct_context();
        let dispatch = dispatch_direct(&mut closed_service, relay);
        let request_id = dispatch.request_id;
        let arrived_at = dispatch.sent_at;
        closed(&mut closed_service, peer, CONNECTION, &endpoint);
        assert!(matches!(
            closed_service.bind_preselection_observation_response_at(
                dispatch,
                peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                arrived_at,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Provenance)
        ));

        let (mut sibling_service, _, relay, peer, _) = direct_context();
        let dispatch = dispatch_direct(&mut sibling_service, relay);
        let request_id = dispatch.request_id;
        let arrived_at = dispatch.sent_at;
        let sibling = dialer("/ip4/8.8.8.8/tcp/443");
        established(&mut sibling_service, peer, CONNECTION + 1, &sibling, 1);
        assert!(matches!(
            sibling_service.bind_preselection_observation_response_at(
                dispatch,
                peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                arrived_at,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Provenance)
        ));
    }

    #[tokio::test]
    async fn private_raw_transport_proof_completes_both_real_memory_hops() {
        let client_key = identity::Keypair::generate_ed25519();
        let relay_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let mut client = client_service(client_key);
        let mut relay = relay_service(relay_key.clone());
        let mut exit = DiscoveryService::new_with_protocol_roles(
            exit_key.clone(),
            DiscoveryProtocolRoles::new(false, false, true),
        )
        .expect("exit discovery");
        connect_memory(&mut client, &mut relay).await;
        connect_memory(&mut relay, &mut exit).await;

        let created_at_ms = now_ms();
        let direct = client_request(
            PreselectionObservationRole::Relay,
            actor(&relay_key, 55, created_at_ms),
            None,
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let direct_response = signed_response(&direct, &relay_key, now_ms());
        exchange_client_response(&mut client, &mut relay, direct, direct_response).await;

        let forwarded = client_request(
            PreselectionObservationRole::Exit,
            actor(&exit_key, 56, created_at_ms),
            Some(actor(&relay_key, 57, created_at_ms)),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let upstream_response = signed_upstream_response(&forwarded, &exit_key, now_ms());
        exchange_upstream_response(&mut relay, &mut exit, &forwarded, upstream_response).await;
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one real two-hop public sealing and affine binding proof"
    )]
    async fn public_pump_seals_and_binds_both_real_response_hops() {
        let client_key = identity::Keypair::generate_ed25519();
        let relay_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let mut client = client_service(client_key);
        let mut relay = relay_service(relay_key.clone());
        let (client_connection, client_old_endpoint) =
            connect_memory_and_capture_dialer_lineage(&mut client, &mut relay).await;
        let relay_peer = *relay.local_peer_id();
        let client_public_endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        client
            .swarm
            .behaviour_mut()
            .connection_provenance
            .on_swarm_event(FromSwarm::AddressChange(AddressChange {
                peer_id: relay_peer,
                connection_id: client_connection,
                old: &client_old_endpoint,
                new: &client_public_endpoint,
            }));

        let created_at_ms = now_ms();
        let direct = client_request(
            PreselectionObservationRole::Relay,
            actor(&relay_key, 65, created_at_ms),
            None,
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let direct_response = signed_response(&direct, &relay_key, now_ms());
        let direct_dispatch = client
            .dispatch_preselection_observation(
                direct.request,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("real direct dispatch");
        let direct_arrival = tokio::time::timeout(Duration::from_secs(10), async {
            let mut response = Some(direct_response);
            loop {
                tokio::select! {
                    event = client.next_event() => {
                        match event {
                            DiscoveryEvent::ClientPreselectionResponse(arrival) => break arrival,
                            DiscoveryEvent::Other(SwarmEvent::Behaviour(
                                BehaviourEvent::PreselectionObservation(
                                    request_response::Event::OutboundFailure { error, .. },
                                ),
                            )) => panic!("real direct response failed: {error}"),
                            _ => {}
                        }
                    }
                    event = relay.next_internal_event() => {
                        if let SwarmEvent::Behaviour(
                            BehaviourEvent::PreselectionObservation(
                                request_response::Event::Message {
                                    message: request_response::Message::Request { channel, .. },
                                    ..
                                },
                            ),
                        ) = event
                        {
                            relay
                                .swarm
                                .behaviour_mut()
                                .preselection_observation
                                .send_response(channel, response.take().expect("one direct response"))
                                .expect("direct response channel");
                        }
                    }
                }
            }
        })
        .await
        .expect("sealed direct arrival timeout");
        let (_direct_bound, _direct_response) = client
            .bind_preselection_observation_response(direct_dispatch, direct_arrival)
            .expect("bind sealed direct arrival");

        let mut exit = DiscoveryService::new_with_protocol_roles(
            exit_key.clone(),
            DiscoveryProtocolRoles::new(false, false, true),
        )
        .expect("exit discovery");
        let (relay_connection, relay_old_endpoint) =
            connect_memory_and_capture_dialer_lineage(&mut relay, &mut exit).await;
        let exit_peer = *exit.local_peer_id();
        let relay_public_endpoint = dialer("/ip4/9.9.9.9/tcp/443");
        relay
            .swarm
            .behaviour_mut()
            .connection_provenance
            .on_swarm_event(FromSwarm::AddressChange(AddressChange {
                peer_id: exit_peer,
                connection_id: relay_connection,
                old: &relay_old_endpoint,
                new: &relay_public_endpoint,
            }));
        let forwarded = client_request(
            PreselectionObservationRole::Exit,
            actor(&exit_key, 66, created_at_ms),
            Some(actor(&relay_key, 67, created_at_ms)),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let upstream_response = signed_upstream_response(&forwarded, &exit_key, now_ms());
        let upstream_dispatch = relay
            .dispatch_preselection_observation_upstream(
                upstream_request(&forwarded),
                Instant::now() + Duration::from_secs(10),
            )
            .expect("real upstream dispatch");
        let upstream_arrival = tokio::time::timeout(Duration::from_secs(10), async {
            let mut response = Some(upstream_response);
            loop {
                tokio::select! {
                    event = relay.next_event() => {
                        match event {
                            DiscoveryEvent::UpstreamPreselectionResponse(arrival) => break arrival,
                            DiscoveryEvent::Other(SwarmEvent::Behaviour(
                                BehaviourEvent::PreselectionObservationUpstream(
                                    request_response::Event::OutboundFailure { error, .. },
                                ),
                            )) => panic!("real upstream response failed: {error}"),
                            _ => {}
                        }
                    }
                    event = exit.next_internal_event() => {
                        if let SwarmEvent::Behaviour(
                            BehaviourEvent::PreselectionObservationUpstream(
                                request_response::Event::Message {
                                    message: request_response::Message::Request { channel, .. },
                                    ..
                                },
                            ),
                        ) = event
                        {
                            exit.swarm
                                .behaviour_mut()
                                .preselection_observation_upstream
                                .send_response(channel, response.take().expect("one upstream response"))
                                .expect("upstream response channel");
                        }
                    }
                }
            }
        })
        .await
        .expect("sealed upstream arrival timeout");
        let (_upstream_bound, _upstream_response) = relay
            .bind_preselection_observation_upstream_response(upstream_dispatch, upstream_arrival)
            .expect("bind sealed upstream arrival");
    }

    #[tokio::test]
    async fn public_event_pump_closes_direct_request_without_exposing_its_channel() {
        let client_key = identity::Keypair::generate_ed25519();
        let relay_key = identity::Keypair::generate_ed25519();
        let mut client = client_service(client_key);
        let mut relay = relay_service(relay_key.clone());
        connect_memory(&mut client, &mut relay).await;

        let created_at_ms = now_ms();
        let fixture = client_request(
            PreselectionObservationRole::Relay,
            actor(&relay_key, 58, created_at_ms),
            None,
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let relay_peer = *relay.local_peer_id();
        let outbound = client
            .swarm
            .behaviour_mut()
            .preselection_observation
            .send_request(&relay_peer, fixture.request);

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = relay.next_event() => {
                        assert!(matches!(event, DiscoveryEvent::Other(_)));
                    }
                    event = next_other(&mut client) => {
                        match event {
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                                request_response::Event::OutboundFailure {
                                    request_id,
                                    ..
                                },
                            )) if request_id == outbound => break,
                            SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                                request_response::Event::Message {
                                    message: request_response::Message::Response {
                                        request_id,
                                        ..
                                    },
                                    ..
                                },
                            )) if request_id == outbound => {
                                panic!("public pump unexpectedly permitted a direct response")
                            }
                            _ => {}
                        }
                    }
                }
            }
        })
        .await
        .expect("public direct-request omission timeout");
    }

    #[tokio::test]
    async fn responder_pump_closes_upstream_request_without_exact_exit_authority() {
        let relay_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let exit_public_key = raw_public_key(&exit_key);
        let mut relay = relay_service(relay_key.clone());
        let mut exit = DiscoveryService::new_with_protocol_roles(
            exit_key.clone(),
            DiscoveryProtocolRoles::new(false, false, true),
        )
        .expect("exit discovery");
        connect_memory(&mut relay, &mut exit).await;

        let created_at_ms = now_ms();
        let fixture = client_request(
            PreselectionObservationRole::Exit,
            actor(&exit_key, 59, created_at_ms),
            Some(actor(&relay_key, 60, created_at_ms)),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let exit_peer = *exit.local_peer_id();
        let outbound = relay
            .swarm
            .behaviour_mut()
            .preselection_observation_upstream
            .send_request(&exit_peer, upstream_request(&fixture));
        let policy = crate::LocalPreselectionPolicy::new(1, [9; 32], created_at_ms + 60_000)
            .expect("shaped policy");
        let mut signer = |message: &[u8]| exit_key.sign(message).ok()?.try_into().ok();

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = exit.next_event_with_preselection_responders(
                        policy,
                        exit_public_key,
                        &mut signer,
                    ) => {
                        assert!(matches!(event, DiscoveryEvent::Other(_)));
                    }
                    event = next_other(&mut relay) => {
                        match event {
                            SwarmEvent::Behaviour(
                                BehaviourEvent::PreselectionObservationUpstream(
                                    request_response::Event::OutboundFailure {
                                        request_id,
                                        ..
                                    },
                                ),
                            ) if request_id == outbound => break,
                            SwarmEvent::Behaviour(
                                BehaviourEvent::PreselectionObservationUpstream(
                                    request_response::Event::Message {
                                        message: request_response::Message::Response {
                                            request_id,
                                            ..
                                        },
                                        ..
                                    },
                                ),
                            ) if request_id == outbound => {
                                panic!("responder unexpectedly permitted an unauthorised upstream response")
                            }
                            _ => {}
                        }
                    }
                }
            }
        })
        .await
        .expect("public upstream-request omission timeout");
    }

    #[tokio::test]
    async fn upstream_target_hash_deadline_and_per_hop_slots_are_exact() {
        let created_at_ms = now_ms();
        let local_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let direct_key = identity::Keypair::generate_ed25519();
        let control = actor(&local_key, 31, created_at_ms);
        let exit = actor(&exit_key, 32, created_at_ms);
        let direct = actor(&direct_key, 33, created_at_ms);
        let exit_peer = exit_key.public().to_peer_id();
        let direct_peer = direct_key.public().to_peer_id();
        let mut service = client_and_relay_service(local_key);
        let exit_endpoint = dialer("/ip4/8.8.8.8/tcp/443");
        let direct_endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        established(&mut service, exit_peer, CONNECTION, &exit_endpoint, 0);
        established(
            &mut service,
            direct_peer,
            CONNECTION + 1,
            &direct_endpoint,
            0,
        );
        let fixture = client_request(
            PreselectionObservationRole::Exit,
            exit,
            Some(control),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let expected_hash =
            preselection_observation_request_hash(&fixture.encoded).expect("request hash");
        let absolute_deadline = Instant::now() + Duration::from_secs(1);
        let upstream = service
            .dispatch_preselection_observation_upstream(
                upstream_request(&fixture),
                absolute_deadline,
            )
            .expect("upstream dispatch");
        assert_eq!(upstream.expected_peer_id, exit_peer);
        assert_eq!(upstream.request_hash, expected_hash);
        assert_eq!(upstream.deadline, absolute_deadline);
        let busy = service.dispatch_preselection_observation_upstream(
            upstream_request(&fixture),
            Instant::now() + Duration::from_secs(1),
        );
        assert!(matches!(busy, Err(PreselectionDispatchError::Busy)));

        let direct_fixture = client_request(
            PreselectionObservationRole::Relay,
            direct,
            None,
            ObservationAddressFamily::Ipv4,
            now_ms(),
        );
        let client = service
            .dispatch_preselection_observation(
                direct_fixture.request,
                Instant::now() + Duration::from_secs(1),
            )
            .expect("independent client-hop slot");
        service
            .cancel_preselection_observation_dispatch(client)
            .expect("client cancellation");
        service
            .cancel_preselection_observation_upstream_dispatch(upstream)
            .expect("upstream cancellation");
    }

    #[tokio::test]
    async fn upstream_requires_local_control_relay_and_never_targets_control() {
        let created_at_ms = now_ms();
        let local_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let exit = actor(&exit_key, 34, created_at_ms);
        let exit_peer = exit_key.public().to_peer_id();
        let endpoint = dialer("/ip6/2606:4700:4700::1111/udp/443/quic-v1");
        let mut service = relay_service(local_key.clone());
        established(&mut service, exit_peer, CONNECTION, &endpoint, 0);

        let wrong_control = client_request(
            PreselectionObservationRole::Exit,
            exit.clone(),
            Some(actor(
                &identity::Keypair::generate_ed25519(),
                35,
                created_at_ms,
            )),
            ObservationAddressFamily::Ipv6,
            created_at_ms,
        );
        assert!(matches!(
            service.dispatch_preselection_observation_upstream(
                upstream_request(&wrong_control),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(PreselectionDispatchError::Request)
        ));

        let exact = client_request(
            PreselectionObservationRole::Exit,
            exit,
            Some(actor(&local_key, 36, created_at_ms)),
            ObservationAddressFamily::Ipv6,
            created_at_ms,
        );
        let dispatch = service
            .dispatch_preselection_observation_upstream(
                upstream_request(&exact),
                Instant::now() + Duration::from_secs(1),
            )
            .expect("local control dispatch");
        assert_eq!(dispatch.expected_peer_id, exit_peer);
        assert_ne!(dispatch.expected_peer_id, *service.local_peer_id());
        service
            .cancel_preselection_observation_upstream_dispatch(dispatch)
            .expect("exact upstream cancellation");

        let mut client_only = client_service(identity::Keypair::generate_ed25519());
        assert!(matches!(
            client_only.dispatch_preselection_observation_upstream(
                upstream_request(&exact),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(PreselectionDispatchError::Role)
        ));
    }

    #[tokio::test]
    async fn typed_upstream_response_retains_one_exact_opaque_exit_proof() {
        let created_at_ms = now_ms();
        let local_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let exit = actor(&exit_key, 37, created_at_ms);
        let exit_peer = exit_key.public().to_peer_id();
        let endpoint = dialer("/ip4/8.8.4.4/tcp/443");
        let mut service = relay_service(local_key.clone());
        established(&mut service, exit_peer, CONNECTION, &endpoint, 0);
        let fixture = client_request(
            PreselectionObservationRole::Exit,
            exit,
            Some(actor(&local_key, 38, created_at_ms)),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let expected_hash =
            preselection_observation_request_hash(&fixture.encoded).expect("request hash");
        let response = signed_upstream_response(&fixture, &exit_key, now_ms());
        let expected_response = response.as_encoded().to_vec();
        let transaction = service
            .dispatch_preselection_observation_upstream_with_context(
                upstream_request(&fixture),
                Instant::now() + Duration::from_secs(1),
                AttemptContext {
                    candidate_snapshot_marker: vec![51, 52, 53].into_boxed_slice(),
                },
            )
            .expect("upstream dispatch");
        let dispatch = &transaction.dispatch;
        let request_id = dispatch.request_id;
        let sent_at = dispatch.sent_at;
        let arrival = service
            .seal_upstream_preselection_response(
                exit_peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                response,
            )
            .expect("service-sealed upstream arrival");
        let (context, bound, returned_response) = service
            .bind_preselection_observation_upstream_response_with_context(transaction, arrival)
            .expect("sealed upstream binding");
        assert_eq!(&*context.candidate_snapshot_marker, &[51, 52, 53]);
        assert_eq!(returned_response.as_encoded(), expected_response);
        assert_eq!(bound.request_hash, expected_hash);
        assert_eq!(bound.request_id, request_id);
        assert_eq!(bound.sent_at_mono, sent_at);
        assert!(bound.arrived_at_mono >= sent_at);
        assert!(bound.arrived_at_mono < bound.deadline_mono);
        assert!(bound.arrived_at_unix_ms > 0);
        assert!(size_of_val(&bound.observation) > 0);
    }

    #[tokio::test]
    async fn upstream_exact_correlation_and_lineage_fail_closed_like_client_hop() {
        let created_at_ms = now_ms();
        let local_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let exit = actor(&exit_key, 39, created_at_ms);
        let exit_peer = exit_key.public().to_peer_id();
        let endpoint = dialer("/ip4/9.9.9.9/tcp/443");
        let mut mismatch_service = relay_service(local_key.clone());
        established(&mut mismatch_service, exit_peer, CONNECTION, &endpoint, 0);
        let fixture = client_request(
            PreselectionObservationRole::Exit,
            exit.clone(),
            Some(actor(&local_key, 40, created_at_ms)),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        let dispatch = mismatch_service
            .dispatch_preselection_observation_upstream(
                upstream_request(&fixture),
                Instant::now() + Duration::from_secs(1),
            )
            .expect("upstream dispatch");
        let unrelated_id = mismatch_service
            .swarm
            .behaviour_mut()
            .preselection_observation_upstream
            .send_request(&exit_peer, upstream_request(&fixture));
        let arrived_at = dispatch.sent_at;
        assert!(matches!(
            mismatch_service.bind_preselection_observation_upstream_response_at(
                dispatch,
                exit_peer,
                ConnectionId::new_unchecked(CONNECTION),
                unrelated_id,
                arrived_at,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Correlation)
        ));
        assert!(matches!(
            mismatch_service.dispatch_preselection_observation_upstream(
                upstream_request(&fixture),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(PreselectionDispatchError::Busy)
        ));

        let mut changed_service = relay_service(local_key);
        established(&mut changed_service, exit_peer, CONNECTION, &endpoint, 0);
        let changed_dispatch = changed_service
            .dispatch_preselection_observation_upstream(
                upstream_request(&fixture),
                Instant::now() + Duration::from_secs(1),
            )
            .expect("changed-lineage dispatch");
        let request_id = changed_dispatch.request_id;
        let arrived_at = changed_dispatch.sent_at;
        let changed_endpoint = dialer("/ip4/9.9.9.10/udp/443/quic-v1");
        changed(
            &mut changed_service,
            exit_peer,
            CONNECTION,
            &endpoint,
            &changed_endpoint,
        );
        assert!(matches!(
            changed_service.bind_preselection_observation_upstream_response_at(
                changed_dispatch,
                exit_peer,
                ConnectionId::new_unchecked(CONNECTION),
                request_id,
                arrived_at,
                now_ms(),
            ),
            Err(PreselectionDispatchError::Provenance)
        ));
        let replacement = changed_service
            .dispatch_preselection_observation_upstream(
                upstream_request(&fixture),
                Instant::now() + Duration::from_secs(1),
            )
            .expect("terminal provenance failure clears upstream slot");
        changed_service
            .cancel_preselection_observation_upstream_dispatch(replacement)
            .expect("replacement cancellation");
    }

    #[test]
    fn inbound_filters_enforce_each_hops_available_identity_bindings() {
        let created_at_ms = now_ms();
        let client_key = identity::Keypair::generate_ed25519();
        let other_client_key = identity::Keypair::generate_ed25519();
        let relay_key = identity::Keypair::generate_ed25519();
        let exit_key = identity::Keypair::generate_ed25519();
        let client_peer = client_key.public().to_peer_id();
        let other_client_peer = other_client_key.public().to_peer_id();
        let relay_peer = relay_key.public().to_peer_id();
        let exit_peer = exit_key.public().to_peer_id();

        let direct = client_request(
            PreselectionObservationRole::Relay,
            actor(&relay_key, 61, created_at_ms),
            None,
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        assert!(client_request_has_local_target_from_distinct_sender(
            &direct.request,
            &client_peer,
            &relay_peer,
        ));
        // A0 is intentionally requester-anonymous: any distinct authenticated remote may submit
        // the same still-current challenge to its exact local target.
        assert!(client_request_has_local_target_from_distinct_sender(
            &direct.request,
            &other_client_peer,
            &relay_peer,
        ));
        assert!(!client_request_has_local_target_from_distinct_sender(
            &direct.request,
            &relay_peer,
            &relay_peer,
        ));
        assert!(!client_request_has_local_target_from_distinct_sender(
            &direct.request,
            &client_peer,
            &exit_peer,
        ));

        let forwarded = client_request(
            PreselectionObservationRole::Exit,
            actor(&exit_key, 62, created_at_ms),
            Some(actor(&relay_key, 63, created_at_ms)),
            ObservationAddressFamily::Ipv4,
            created_at_ms,
        );
        assert!(client_request_has_local_target_from_distinct_sender(
            &forwarded.request,
            &client_peer,
            &relay_peer,
        ));
        assert!(!client_request_has_local_target_from_distinct_sender(
            &forwarded.request,
            &exit_peer,
            &relay_peer,
        ));
        let upstream = upstream_request(&forwarded);
        assert!(upstream_request_has_authenticated_target(
            &upstream,
            &relay_peer,
            &exit_peer,
        ));
        assert!(!upstream_request_has_authenticated_target(
            &upstream,
            &client_peer,
            &exit_peer,
        ));
        assert!(!upstream_request_has_authenticated_target(
            &upstream,
            &relay_peer,
            &relay_peer,
        ));

        let expired_at_ms = now_ms().saturating_sub(5_000);
        let expired = client_request(
            PreselectionObservationRole::Relay,
            actor(&relay_key, 64, expired_at_ms),
            None,
            ObservationAddressFamily::Ipv4,
            expired_at_ms,
        );
        assert!(!client_request_has_local_target_from_distinct_sender(
            &expired.request,
            &client_peer,
            &relay_peer,
        ));
    }

    fn item_body<'a>(source: &'a str, declaration: &str) -> &'a str {
        assert_eq!(source.matches(declaration).count(), 1, "{declaration}");
        source
            .split(declaration)
            .nth(1)
            .expect("declaration")
            .split('}')
            .next()
            .expect("body")
    }

    fn compact(value: &str) -> String {
        value.split_whitespace().collect()
    }

    fn assert_affine_token_fields(production: &str) {
        assert_eq!(
            compact(item_body(
                production,
                "pub(super) struct PreselectionTransactionState {"
            )),
            "instance:Arc<()>,client_active:Option<OutboundRequestId>,upstream_active:Option<OutboundRequestId>,"
        );
        assert_eq!(
            compact(item_body(
                production,
                "pub struct ClientPreselectionDispatch {"
            )),
            "request_id:OutboundRequestId,request_hash:[u8;32],expected_peer_id:PeerId,instance:Arc<()>,sent_at:Instant,deadline:Instant,witness:ConnectionWitness,"
        );
        assert_eq!(
            compact(item_body(
                production,
                "pub struct BoundClientPreselectionTransport {"
            )),
            "observation:BoundConnectionObservation,request_hash:[u8;32],request_id:OutboundRequestId,sent_at_mono:Instant,arrived_at_mono:Instant,arrived_at_unix_ms:u64,deadline_mono:Instant,"
        );
        assert_eq!(
            compact(item_body(
                production,
                "pub struct ClientPreselectionTransaction<Context> {"
            )),
            "dispatch:ClientPreselectionDispatch,context:Context,"
        );
        assert_eq!(
            compact(item_body(
                production,
                "pub struct ClientPreselectionResponseArrival {"
            )),
            "peer:PeerId,connection_id:ConnectionId,request_id:OutboundRequestId,response:ClientPreselectionObservationResponse,instance:Arc<()>,arrived_at_mono:Instant,arrived_at_unix_ms:u64,"
        );
        assert_eq!(
            compact(item_body(
                production,
                "pub struct UpstreamPreselectionDispatch {"
            )),
            "request_id:OutboundRequestId,request_hash:[u8;32],expected_peer_id:PeerId,instance:Arc<()>,sent_at:Instant,deadline:Instant,witness:ConnectionWitness,"
        );
        assert_eq!(
            compact(item_body(
                production,
                "pub struct BoundUpstreamPreselectionTransport {"
            )),
            "observation:BoundConnectionObservation,request_hash:[u8;32],request_id:OutboundRequestId,sent_at_mono:Instant,arrived_at_mono:Instant,arrived_at_unix_ms:u64,deadline_mono:Instant,"
        );
        assert_eq!(
            compact(item_body(
                production,
                "pub struct UpstreamPreselectionTransaction<Context> {"
            )),
            "dispatch:UpstreamPreselectionDispatch,context:Context,"
        );
        assert_eq!(
            compact(item_body(
                production,
                "pub struct UpstreamPreselectionResponseArrival {"
            )),
            "peer:PeerId,connection_id:ConnectionId,request_id:OutboundRequestId,response:UpstreamPreselectionObservationResponse,instance:Arc<()>,arrived_at_mono:Instant,arrived_at_unix_ms:u64,"
        );
    }

    fn assert_affine_token_surface(production: &str) {
        let affine = production
            .split("/// Affine owner")
            .nth(1)
            .expect("affine start")
            .split("impl DiscoveryService")
            .next()
            .expect("affine end");
        assert!(!affine.contains("#[derive"));
        for token in [
            "ClientPreselectionDispatch",
            "ClientPreselectionTransaction",
            "ClientPreselectionResponseArrival",
            "BoundClientPreselectionTransport",
            "UpstreamPreselectionDispatch",
            "UpstreamPreselectionTransaction",
            "UpstreamPreselectionResponseArrival",
            "BoundUpstreamPreselectionTransport",
        ] {
            for trait_name in ["Clone", "Copy", "Debug", "Serialize", "Deserialize"] {
                assert!(!production.contains(&format!("impl {trait_name} for {token}")));
            }
        }
        assert!(!production.contains("impl ClientPreselectionDispatch"));
        assert!(!production.contains("impl<Context> ClientPreselectionTransaction<Context>"));
        assert!(!production.contains("impl UpstreamPreselectionDispatch"));
        assert!(!production.contains("impl<Context> UpstreamPreselectionTransaction<Context>"));
        assert!(!production.contains("matches_request_id"));
        assert!(!production.contains("impl BoundClientPreselectionTransport"));
        assert!(!production.contains("impl BoundUpstreamPreselectionTransport"));
        for forbidden in [
            "Multiaddr",
            "IpAddr",
            "Ipv4Addr",
            "Ipv6Addr",
            "ObservedNetworkPrefix",
            "into_observed_prefix",
            "fn request_hash",
            "fn request_id",
            "fn expected_peer",
            "fn sent_at",
            "fn arrived_at",
            "fn deadline",
            "fn decompose",
            "fn into_parts",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface {forbidden}"
            );
        }
    }

    #[test]
    fn public_tokens_are_affine_exact_and_the_bound_proof_is_fully_opaque() {
        let production = include_str!("preselection_transaction.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production");
        assert_affine_token_fields(production);
        assert_affine_token_surface(production);
    }

    fn assert_client_dispatch_and_bind_contract(production: &str) {
        let dispatch = production
            .split("pub fn dispatch_preselection_observation(")
            .nth(1)
            .expect("dispatch")
            .split("/// Bind one matching")
            .next()
            .expect("dispatch end");
        let signature = dispatch.split('{').next().expect("signature");
        assert!(!signature.contains("PeerId"));
        assert!(!signature.contains("IpFamily"));
        let adjacent = concat!(
            "letwitness=self.swarm.behaviour().connection_provenance",
            ".unique_witness(expected_peer_id,family)",
            ".ok_or(PreselectionDispatchError::Provenance)?;",
            "letrequest_id=self.swarm.behaviour_mut().preselection_observation",
            ".send_request(&expected_peer_id,request);"
        );
        assert_eq!(compact(dispatch).matches(adjacent).count(), 1);
        let witness = dispatch.find(".unique_witness(").expect("witness");
        let send = dispatch.find(".send_request(").expect("send");
        for forbidden in [".await", "yield_now", "sleep(", "spawn("] {
            assert!(!dispatch[witness..send].contains(forbidden));
        }
        assert!(dispatch.contains("PRESELECTION_OBSERVATION_REQUEST_TIMEOUT"));
        assert!(dispatch.contains("typed_request.expires_at_ms"));
        assert!(
            dispatch.contains("self.preselection_transaction.client_active = Some(request_id);")
        );

        let public_bind = production
            .split("pub fn bind_preselection_observation_response(")
            .nth(1)
            .expect("public bind")
            .split("pub(super) fn seal_client_preselection_response")
            .next()
            .expect("public bind end");
        let bind_signature = compact(public_bind.split('{').next().expect("bind signature"));
        assert!(bind_signature.contains("arrival:ClientPreselectionResponseArrival"));
        assert!(!bind_signature.contains("request_response::Event"));
        for forbidden in [
            "event_peer:",
            "event_connection:",
            "event_request:",
            "arrived_at:",
        ] {
            assert!(!bind_signature.contains(forbidden));
        }
        assert_eq!(public_bind.matches("Arc::ptr_eq").count(), 3);
        assert_eq!(public_bind.matches("Instant::now()").count(), 0);
        assert_eq!(public_bind.matches("system_unix_millis()").count(), 0);
        let seal = production
            .split("pub(super) fn seal_client_preselection_response(")
            .nth(1)
            .expect("private client sealer")
            .split("fn bind_preselection_observation_response_at")
            .next()
            .expect("client sealer end");
        assert_eq!(seal.matches("Instant::now()").count(), 1);
        assert_eq!(seal.matches("system_unix_millis()?").count(), 1);
        assert_eq!(
            production
                .matches("fn bind_preselection_observation_response_at")
                .count(),
            1
        );
    }

    fn assert_upstream_dispatch_and_bind_contract(production: &str) {
        let upstream_dispatch = production
            .split("pub fn dispatch_preselection_observation_upstream(")
            .nth(1)
            .expect("upstream dispatch")
            .split("/// Bind one matching upstream response")
            .next()
            .expect("upstream dispatch end");
        let upstream_signature = upstream_dispatch.split('{').next().expect("signature");
        assert!(!upstream_signature.contains("PeerId"));
        assert!(!upstream_signature.contains("IpFamily"));
        let upstream_adjacent = concat!(
            "letwitness=self.swarm.behaviour().connection_provenance",
            ".unique_witness(expected_peer_id,family)",
            ".ok_or(PreselectionDispatchError::Provenance)?;",
            "letrequest_id=self.swarm.behaviour_mut().preselection_observation_upstream",
            ".send_request(&expected_peer_id,request);"
        );
        assert_eq!(
            compact(upstream_dispatch)
                .matches(upstream_adjacent)
                .count(),
            1
        );
        let upstream_witness = upstream_dispatch.find(".unique_witness(").expect("witness");
        let upstream_send = upstream_dispatch.find(".send_request(").expect("send");
        for forbidden in [".await", "yield_now", "sleep(", "spawn("] {
            assert!(!upstream_dispatch[upstream_witness..upstream_send].contains(forbidden));
        }
        assert!(upstream_dispatch.contains("PRESELECTION_OBSERVATION_REQUEST_TIMEOUT"));
        assert!(upstream_dispatch.contains("typed_request.expires_at_ms"));
        assert!(
            upstream_dispatch
                .contains("self.preselection_transaction.upstream_active = Some(request_id);")
        );

        let upstream_bind = production
            .split("pub fn bind_preselection_observation_upstream_response(")
            .nth(1)
            .expect("upstream bind")
            .split("pub(super) fn seal_upstream_preselection_response")
            .next()
            .expect("upstream public bind end");
        let upstream_bind_signature = compact(upstream_bind.split('{').next().expect("signature"));
        assert!(upstream_bind_signature.contains("arrival:UpstreamPreselectionResponseArrival"));
        assert!(!upstream_bind_signature.contains("request_response::Event"));
        for forbidden in [
            "event_peer:",
            "event_connection:",
            "event_request:",
            "arrived_at:",
        ] {
            assert!(!upstream_bind_signature.contains(forbidden));
        }
        assert_eq!(upstream_bind.matches("Arc::ptr_eq").count(), 3);
        assert_eq!(upstream_bind.matches("Instant::now()").count(), 0);
        assert_eq!(upstream_bind.matches("system_unix_millis()").count(), 0);
        let seal = production
            .split("pub(super) fn seal_upstream_preselection_response(")
            .nth(1)
            .expect("private upstream sealer")
            .split("/// Bind a matching upstream response")
            .next()
            .expect("upstream sealer end");
        assert_eq!(seal.matches("Instant::now()").count(), 1);
        assert_eq!(seal.matches("system_unix_millis()?").count(), 1);
    }

    fn assert_transaction_stops_before_application_owner(production: &str) {
        for forbidden in [
            "sign_control_message",
            "ReplayCache",
            "FreshEvidence",
            "CandidateEvidence",
            "BoundPreselectionTranscriptBatch",
            "HashMap",
            "VecDeque",
            "retry",
            "backoff",
            "spawn(",
        ] {
            assert!(
                !production.contains(forbidden),
                "transaction crossed its owner boundary: {forbidden}"
            );
        }
    }

    #[test]
    fn dispatch_and_bind_derive_every_authoritative_input_internally() {
        let production = include_str!("preselection_transaction.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production");
        assert_client_dispatch_and_bind_contract(production);
        assert_upstream_dispatch_and_bind_contract(production);
        assert!(!production.contains("send_preselection_observation_response"));
        assert!(!production.contains("send_preselection_observation_upstream_response"));
        assert!(!production.contains("ResponseChannel"));
        assert!(!production.contains(".send_response("));
        assert_transaction_stops_before_application_owner(production);
    }

    #[test]
    fn root_composition_has_one_private_state_and_no_second_transaction_module() {
        let root = include_str!("lib.rs");
        let production = root
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("root production");
        let compact = compact(production);
        assert_eq!(compact.matches("modpreselection_transaction;").count(), 1);
        assert!(!compact.contains("pubmodpreselection_transaction;"));
        assert_eq!(
            compact
                .matches("preselection_transaction:PreselectionTransactionState,")
                .count(),
            1
        );
        assert_eq!(
            compact
                .matches("preselection_transaction:PreselectionTransactionState::new(),")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("pub fn dispatch_preselection_observation(")
                .count(),
            0,
            "the implementation remains isolated in its private module"
        );
        assert_eq!(
            production
                .matches("client_request_has_local_target_from_distinct_sender(")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("upstream_request_has_authenticated_target(")
                .count(),
            1
        );
    }

    #[test]
    fn every_public_pump_seals_or_drops_preselection_messages() {
        let root = include_str!("lib.rs");
        let root_production = root
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("root production");
        let next_event = root_production
            .split("pub async fn next_event(")
            .nth(1)
            .expect("public event pump")
            .split("/// Private event pump")
            .next()
            .expect("public event pump end");
        assert!(compact(next_event).starts_with("&mutself)->DiscoveryEvent{"));
        assert_eq!(
            next_event
                .matches("seal_client_preselection_response(")
                .count(),
            1
        );
        assert_eq!(
            next_event
                .matches("seal_upstream_preselection_response(")
                .count(),
            1
        );
        assert!(next_event.contains("event if inbound_preselection_request(&event) => None"));
        assert!(next_event.contains("event => Some(DiscoveryEvent::Other(event))"));

        let responder = include_str!("preselection_responder.rs");
        let responder_production = responder
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("responder production");
        let responder_pump = responder_production
            .split("pub async fn next_event_with_preselection_responders")
            .nth(1)
            .expect("signed responder pump")
            .split("/// Validate, connection-bind")
            .next()
            .expect("signed responder pump end");
        assert!(responder_pump.contains(") -> crate::DiscoveryEvent"));
        assert!(responder_pump.contains("self.sanitize_public_event(event)"));

        let transaction = include_str!("preselection_transaction.rs");
        let transaction_production = transaction
            .split("#[cfg(test)]")
            .next()
            .expect("transaction production");
        for public_bind in [
            "pub fn bind_preselection_observation_response(",
            "pub fn bind_preselection_observation_response_with_context<",
            "pub fn bind_preselection_observation_upstream_response(",
            "pub fn bind_preselection_observation_upstream_response_with_context<",
        ] {
            let signature = transaction_production
                .split(public_bind)
                .nth(1)
                .expect("public sealed bind")
                .split('{')
                .next()
                .expect("public sealed bind signature");
            assert!(!signature.contains("request_response::Event"));
            assert!(signature.contains("ResponseArrival"));
        }
        assert!(!transaction_production.contains("matches_request_id"));
    }
}
