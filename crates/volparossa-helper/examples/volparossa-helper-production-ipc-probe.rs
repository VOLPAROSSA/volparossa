//! Narrow live probe for the packaged helper-v3 production IPC boundary.
//!
//! This example accepts no socket path, request bytes or privileged operation from its caller. It
//! requires one exact expected production PID/GID pair and connects only to the fixed production
//! socket. Its closed modes exercise read-only runtime binding, bounded fail-closed framing, or one
//! exact functional Client-lease cycle through Commit, one exact functional Exit-lease cycle, and
//! one atomic RelayClient+RelayExit pair cycle through Commit. The functional mode publishes a
//! fixed role-specific READY record only after each exact Activated receipt, accepts one fixed
//! release byte for each cycle on standard input, and never prints handles or endpoint material.

use std::{
    cell::Cell,
    ffi::OsString,
    io::{self, Write as _},
    os::{fd::AsFd as _, unix::ffi::OsStrExt},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use nix::{
    poll::{PollFd, PollFlags, poll},
    unistd::read,
};
use rand_core::{OsRng, RngCore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};
use volparossa_helper::SOCKET_PATH;
use volparossa_protocol::{
    ClientSessionCapability, ExitReservation, NativeRouteIdentity, RelayAuthorization,
    RelayReservation, RelayReservationRequest, TimePolicy, Transport, WireguardEndpoint,
    generate_nonce, node_id_from_public_key, relay_reservation_request_sha256,
    sign_control_message,
};
use volparossa_routing::{
    ActivateLeaseBatch, ActivatedLeaseBatch, BindHelperRuntime, ClosedPreparePlan,
    CommitLeaseBatch, CommittedLeaseBatch, ContextRole, DestroyContext, HELPER_PROTOCOL_VERSION,
    HelperRequest, HelperResponse, HelperResult, LeaseActivation, LeaseCommit, LeasePlan,
    PrepareIntent, PrepareLeaseBatch, PreparedLeaseBatch, PublicUdpEndpoint, UnderlayEvidence,
    WireguardRole, encode_request, encode_response, helper_request, helper_response,
    operation_digest, read_response,
};
use zeroize::Zeroizing;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const FUNCTIONAL_PROBE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_MODE_ARGUMENT_BYTES: usize = "expect-unauthorised-peer".len();
const MAX_DECIMAL_U32_BYTES: usize = 10;
const ROOT_UID: u32 = 0;
const HELPER_RUNTIME_DIAGNOSTIC: &str = "HELPER_RUNTIME";
const LEASES_PREPARED_DIAGNOSTIC: &str = "LEASES_PREPARED";
const LEASES_ACTIVATED_DIAGNOSTIC: &str = "LEASES_ACTIVATED";
const LEASES_COMMITTED_DIAGNOSTIC: &str = "LEASES_COMMITTED";
const CONTEXT_DESTROYED_DIAGNOSTIC: &str = "CONTEXT_DESTROYED";
const CONTEXT_ABSENT_DIAGNOSTIC: &str = "CONTEXT_ABSENT";
const FAILURE_RECORD: &str = "VOLPAROSSA_HELPER_V3_IPC_PROBE_V1=fail";
const USAGE_RECORD: &str = "VOLPAROSSA_HELPER_V3_IPC_PROBE_V1=usage";
const FUNCTIONAL_SETUP_TTL_SECONDS: u64 = 30;
const FUNCTIONAL_HARD_TTL_SECONDS: u64 = 300;
const FUNCTIONAL_MPTCP_LIMIT: u32 = 4;
const FUNCTIONAL_PATH_ID: u32 = 1;
const FUNCTIONAL_PUBLIC_IPV4: [u8; 4] = [192, 31, 195, 254];
// This exact test-only public peer tuple is shared with the public helper-protocol Activate fixture
// and the disposable KVM relay fixture. The Base64 public key is
// `MdSras7slhE3kXA3k25gcW+sVzr+lNnahKgCBEjfwRI=`. It is intentionally neither a local helper key
// nor the helper's prepared public endpoint.
const FUNCTIONAL_PEER_PUBLIC_KEY: [u8; 32] = [
    0x31, 0xd4, 0xab, 0x6a, 0xce, 0xec, 0x96, 0x11, 0x37, 0x91, 0x70, 0x37, 0x93, 0x6e, 0x60, 0x71,
    0x6f, 0xac, 0x57, 0x3a, 0xfe, 0x94, 0xd9, 0xda, 0x84, 0xa8, 0x02, 0x04, 0x48, 0xdf, 0xc1, 0x12,
];
const FUNCTIONAL_PEER_IPV4: [u8; 4] = FUNCTIONAL_PUBLIC_IPV4;
const FUNCTIONAL_PEER_PORT: u16 = 10_000;
// The public key for the second disposable relay-to-exit peer is derived from the deterministic
// test-only private fixture [11; 32]. The private key itself exists only in the KVM hook's pipe.
const FUNCTIONAL_EXIT_PEER_PUBLIC_KEY: [u8; 32] = [
    0x73, 0xb2, 0xd8, 0xb7, 0x6a, 0xa9, 0xb5, 0x36, 0x60, 0x03, 0x2b, 0xc8, 0xf5, 0xd8, 0xbe, 0xe3,
    0xa3, 0xae, 0x4e, 0x3b, 0x3a, 0x7f, 0xd4, 0x9a, 0xde, 0x81, 0xf7, 0x34, 0x7a, 0x34, 0xaa, 0x68,
];
const FUNCTIONAL_EXIT_PEER_IPV4: [u8; 4] = FUNCTIONAL_PUBLIC_IPV4;
const FUNCTIONAL_EXIT_PEER_PORT: u16 = 10_001;
const FUNCTIONAL_RELAY_EXIT_PUBLIC_KEY: [u8; 32] = [9; 32];
const FUNCTIONAL_RELAY_EXIT_IPV4: [u8; 4] = [8, 8, 8, 8];
const FUNCTIONAL_RELAY_EXIT_PORT: u16 = 51_821;
const FUNCTIONAL_EXIT_PUBLIC_KEY: [u8; 32] = [10; 32];
const FUNCTIONAL_EXIT_IPV4: [u8; 4] = [9, 9, 9, 9];
const FUNCTIONAL_EXIT_PORT: u16 = 51_822;
const FUNCTIONAL_SIGNED_RATE_MBPS: u64 = 1;
const FUNCTIONAL_RELEASE_TIMEOUT_MILLIS: u16 = 20_000;
const FUNCTIONAL_RELEASE_BYTE: u8 = b'G';
const FUNCTIONAL_READY_RECORD: &str = "VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready";
const FUNCTIONAL_EXIT_READY_RECORD: &str = "VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=ready";
const FUNCTIONAL_EXIT_PASS_RECORD: &str = "VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=pass";
const FUNCTIONAL_RELAY_PAIR_READY_RECORD: &str =
    "VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=ready";
const FUNCTIONAL_RELAY_PAIR_PASS_RECORD: &str =
    "VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=pass";
const FUNCTIONAL_FAILURE_RECORD_PREFIX: &str =
    "VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=";

const ZERO_LENGTH_FRAME: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
const EXCESSIVE_LENGTH_FRAME: [u8; 4] = [0x00, 0x02, 0x00, 0x01];

const RETIRED_TAG_24_FRAME: [u8; 27] = [
    0x00, 0x00, 0x00, 0x17, 0x08, 0x03, 0x12, 0x10, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24,
    0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0xc2, 0x01, 0x00,
];
const UNKNOWN_TAG_99_FRAME: [u8; 27] = [
    0x00, 0x00, 0x00, 0x17, 0x08, 0x03, 0x12, 0x10, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x9a, 0x06, 0x00,
];
const VERSION_TWO_FRAME: [u8; 27] = [
    0x00, 0x00, 0x00, 0x17, 0x08, 0x02, 0x12, 0x10, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x9a, 0x02, 0x00,
];
const NONCANONICAL_UNKNOWN_OUTER_FIELD_FRAME: [u8; 29] = [
    0x00, 0x00, 0x00, 0x19, 0x08, 0x03, 0x12, 0x10, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x9a, 0x02, 0x00, 0x20, 0x01,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    BindRuntime,
    FunctionalClientLease,
    RejectFrameBounds,
    RejectWireShapes,
    ExpectUnauthorisedPeer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpectedPeer {
    pid: i32,
    gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProbeInvocation {
    mode: Mode,
    expected_peer: ExpectedPeer,
}

impl Mode {
    const fn success_record(self) -> &'static str {
        match self {
            Self::BindRuntime => "VOLPAROSSA_HELPER_V3_IPC_BIND_RUNTIME_V1=pass",
            Self::FunctionalClientLease => "VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=pass",
            Self::RejectFrameBounds => "VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass",
            Self::RejectWireShapes => "VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass",
            Self::ExpectUnauthorisedPeer => "VOLPAROSSA_HELPER_V3_IPC_UNAUTHORISED_PEER_V1=pass",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeError {
    Random,
    Protocol,
    Io,
    Timeout,
    UntrustedServer,
    Correlation,
    UnexpectedResponse,
}

impl ProbeError {
    const fn diagnostic_class(self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::Protocol => "protocol",
            Self::Io => "io",
            Self::Timeout => "timeout",
            Self::UntrustedServer => "untrusted",
            Self::Correlation => "correlation",
            Self::UnexpectedResponse => "unexpected-response",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FunctionalPhase {
    Plan,
    Connect,
    Bind,
    Prepare,
    Activate,
    Shutdown,
    Ready,
    Release,
    Reconnect,
    Commit,
    Destroy,
    SecondCyclePlan,
    SecondCycleBind,
    SecondCyclePrepare,
    SecondCycleActivate,
    Reuse,
    SecondCycleShutdown,
    SecondCycleReady,
    SecondCycleRelease,
    SecondCycleReconnect,
    SecondCycleCommit,
    SecondCycleDestroy,
    RelayPairPlan,
    RelayPairBind,
    RelayPairPrepare,
    RelayPairActivate,
    RelayPairReuse,
    RelayPairShutdown,
    RelayPairReady,
    RelayPairRelease,
    RelayPairReconnect,
    RelayPairCommit,
    RelayPairDestroy,
    FinalShutdown,
}

impl FunctionalPhase {
    const fn diagnostic_name(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Connect => "connect",
            Self::Bind => "bind",
            Self::Prepare => "prepare",
            Self::Activate => "activate",
            Self::Shutdown => "shutdown",
            Self::Ready => "ready",
            Self::Release => "release",
            Self::Reconnect => "reconnect",
            Self::Commit => "commit",
            Self::Destroy => "destroy",
            Self::SecondCyclePlan => "second-cycle-plan",
            Self::SecondCycleBind => "second-cycle-bind",
            Self::SecondCyclePrepare => "second-cycle-prepare",
            Self::SecondCycleActivate => "second-cycle-activate",
            Self::Reuse => "reuse",
            Self::SecondCycleShutdown => "second-cycle-shutdown",
            Self::SecondCycleReady => "second-cycle-ready",
            Self::SecondCycleRelease => "second-cycle-release",
            Self::SecondCycleReconnect => "second-cycle-reconnect",
            Self::SecondCycleCommit => "second-cycle-commit",
            Self::SecondCycleDestroy => "second-cycle-destroy",
            Self::RelayPairPlan => "relay-pair-plan",
            Self::RelayPairBind => "relay-pair-bind",
            Self::RelayPairPrepare => "relay-pair-prepare",
            Self::RelayPairActivate => "relay-pair-activate",
            Self::RelayPairReuse => "relay-pair-reuse",
            Self::RelayPairShutdown => "relay-pair-shutdown",
            Self::RelayPairReady => "relay-pair-ready",
            Self::RelayPairRelease => "relay-pair-release",
            Self::RelayPairReconnect => "relay-pair-reconnect",
            Self::RelayPairCommit => "relay-pair-commit",
            Self::RelayPairDestroy => "relay-pair-destroy",
            Self::FinalShutdown => "final-shutdown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FunctionalLeaseRole {
    Client,
    Exit,
}

impl FunctionalLeaseRole {
    const fn context(self) -> ContextRole {
        match self {
            Self::Client => ContextRole::Client,
            Self::Exit => ContextRole::Exit,
        }
    }

    const fn wireguard(self) -> WireguardRole {
        match self {
            Self::Client => WireguardRole::Client,
            Self::Exit => WireguardRole::Exit,
        }
    }

    const fn peer_public_key(self) -> [u8; 32] {
        match self {
            Self::Client => FUNCTIONAL_PEER_PUBLIC_KEY,
            Self::Exit => FUNCTIONAL_EXIT_PEER_PUBLIC_KEY,
        }
    }

    const fn peer_endpoint(self) -> ([u8; 4], u16) {
        match self {
            Self::Client => (FUNCTIONAL_PEER_IPV4, FUNCTIONAL_PEER_PORT),
            Self::Exit => (FUNCTIONAL_EXIT_PEER_IPV4, FUNCTIONAL_EXIT_PEER_PORT),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct FunctionalProbeFailure {
    phase: FunctionalPhase,
    error: ProbeError,
}

impl FunctionalProbeFailure {
    const fn new(phase: FunctionalPhase, error: ProbeError) -> Self {
        Self { phase, error }
    }

    fn write_record(self, output: &mut impl io::Write) -> io::Result<()> {
        writeln!(
            output,
            "{FUNCTIONAL_FAILURE_RECORD_PREFIX}{},{}",
            self.phase.diagnostic_name(),
            self.error.diagnostic_class()
        )
    }
}

enum ProbeFailure {
    Generic,
    Functional(FunctionalProbeFailure),
}

struct BindExchange {
    request_id: [u8; 16],
    operation_digest: [u8; 32],
    frame: Zeroizing<Vec<u8>>,
}

impl BindExchange {
    fn random() -> Result<Self, ProbeError> {
        let mut source = OsRng;
        let mut request_id = [0_u8; 16];
        source
            .try_fill_bytes(&mut request_id)
            .map_err(|_| ProbeError::Random)?;
        Self::from_request_id(request_id)
    }

    fn from_request_id(request_id: [u8; 16]) -> Result<Self, ProbeError> {
        if request_id.iter().all(|byte| *byte == 0) {
            return Err(ProbeError::Protocol);
        }
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request_id.to_vec(),
            operation: Some(helper_request::Operation::BindHelperRuntime(
                BindHelperRuntime {
                    prepare_intent: None,
                },
            )),
        };
        let operation_digest = operation_digest(&request).map_err(|_| ProbeError::Protocol)?;
        let frame = Zeroizing::new(encode_request(&request).map_err(|_| ProbeError::Protocol)?);
        Ok(Self {
            request_id,
            operation_digest,
            frame,
        })
    }
}

struct FunctionalRequestExchange {
    request_id: [u8; 16],
    operation_digest: [u8; 32],
    frame: Zeroizing<Vec<u8>>,
}

impl FunctionalRequestExchange {
    fn from_request(request: &HelperRequest) -> Result<Self, ProbeError> {
        let request_id: [u8; 16] = request
            .request_id
            .as_slice()
            .try_into()
            .map_err(|_| ProbeError::Protocol)?;
        if request_id.iter().all(|byte| *byte == 0) {
            return Err(ProbeError::Protocol);
        }
        let operation_digest = operation_digest(request).map_err(|_| ProbeError::Protocol)?;
        let frame = Zeroizing::new(encode_request(request).map_err(|_| ProbeError::Protocol)?);
        Ok(Self {
            request_id,
            operation_digest,
            frame,
        })
    }
}

#[derive(Clone, Copy)]
struct FunctionalCycleIds {
    context: [u8; 16],
    bind_request: [u8; 16],
    prepare_request: [u8; 16],
    activate_request: [u8; 16],
    commit_request: [u8; 16],
    destroy_present_request: [u8; 16],
    destroy_absent_request: [u8; 16],
}

impl FunctionalCycleIds {
    const fn request_ids(self) -> [[u8; 16]; 6] {
        [
            self.bind_request,
            self.prepare_request,
            self.activate_request,
            self.commit_request,
            self.destroy_present_request,
            self.destroy_absent_request,
        ]
    }
}

struct FunctionalCyclePlan {
    ids: FunctionalCycleIds,
    role: FunctionalLeaseRole,
    bind: FunctionalRequestExchange,
    prepare: FunctionalRequestExchange,
    hard_expires_at_unix: u64,
}

impl FunctionalCyclePlan {
    fn random(
        excluded_contexts: &[[u8; 16]],
        excluded_request_ids: &[[u8; 16]],
        role: FunctionalLeaseRole,
    ) -> Result<Self, ProbeError> {
        let context_id = random_unique_id(excluded_contexts)?;
        let mut request_ids = excluded_request_ids.to_vec();
        let bind_request_id = random_unique_id(&request_ids)?;
        request_ids.push(bind_request_id);
        let prepare_request_id = random_unique_id(&request_ids)?;
        request_ids.push(prepare_request_id);
        let activate_request_id = random_unique_id(&request_ids)?;
        request_ids.push(activate_request_id);
        let commit_request_id = random_unique_id(&request_ids)?;
        request_ids.push(commit_request_id);
        let destroy_present_request_id = random_unique_id(&request_ids)?;
        request_ids.push(destroy_present_request_id);
        let destroy_absent_request_id = random_unique_id(&request_ids)?;
        Self::from_ids(
            FunctionalCycleIds {
                context: context_id,
                bind_request: bind_request_id,
                prepare_request: prepare_request_id,
                activate_request: activate_request_id,
                commit_request: commit_request_id,
                destroy_present_request: destroy_present_request_id,
                destroy_absent_request: destroy_absent_request_id,
            },
            unix_now()?,
            role,
        )
    }

    fn from_ids(
        ids: FunctionalCycleIds,
        now: u64,
        role: FunctionalLeaseRole,
    ) -> Result<Self, ProbeError> {
        if ids.context.iter().all(|byte| *byte == 0) {
            return Err(ProbeError::Protocol);
        }
        let request_ids = ids.request_ids();
        for (position, request_id) in request_ids.iter().enumerate() {
            if request_id.iter().all(|byte| *byte == 0)
                || request_ids[..position].contains(request_id)
            {
                return Err(ProbeError::Protocol);
            }
        }
        let setup_expires_at_unix = now
            .checked_add(FUNCTIONAL_SETUP_TTL_SECONDS)
            .ok_or(ProbeError::Protocol)?;
        let hard_expires_at_unix = now
            .checked_add(FUNCTIONAL_HARD_TTL_SECONDS)
            .ok_or(ProbeError::Protocol)?;
        let leases = vec![LeasePlan {
            path_id: FUNCTIONAL_PATH_ID,
            role: role.wireguard() as i32,
        }];
        let prepare_value = PrepareLeaseBatch {
            route_context_id: ids.context.to_vec(),
            role: role.context() as i32,
            mptcp_accepted_addrs: FUNCTIONAL_MPTCP_LIMIT,
            mptcp_subflows: FUNCTIONAL_MPTCP_LIMIT,
            leases: leases.clone(),
            setup_expires_at_unix,
            hard_expires_at_unix,
        };
        let prepare_request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: ids.prepare_request.to_vec(),
            operation: Some(helper_request::Operation::PrepareLeaseBatch(
                prepare_value.clone(),
            )),
        };
        let prepare = FunctionalRequestExchange::from_request(&prepare_request)?;
        let bind_request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: ids.bind_request.to_vec(),
            operation: Some(helper_request::Operation::BindHelperRuntime(
                BindHelperRuntime {
                    prepare_intent: Some(PrepareIntent {
                        route_context_id: ids.context.to_vec(),
                        prepare_request_id: ids.prepare_request.to_vec(),
                        prepare_operation_digest: prepare.operation_digest.to_vec(),
                        setup_expires_at_unix,
                        hard_expires_at_unix,
                        closed_plan: Some(ClosedPreparePlan {
                            context_role: role.context() as i32,
                            leases,
                        }),
                    }),
                },
            )),
        };
        let bind = FunctionalRequestExchange::from_request(&bind_request)?;
        Ok(Self {
            ids,
            role,
            bind,
            prepare,
            hard_expires_at_unix,
        })
    }
}

struct FunctionalRelayPairPlan {
    ids: FunctionalCycleIds,
    bind: FunctionalRequestExchange,
    prepare: FunctionalRequestExchange,
    hard_expires_at_unix: u64,
}

impl FunctionalRelayPairPlan {
    fn random(
        excluded_contexts: &[[u8; 16]],
        excluded_request_ids: &[[u8; 16]],
    ) -> Result<Self, ProbeError> {
        let context_id = random_unique_id(excluded_contexts)?;
        let mut request_ids = excluded_request_ids.to_vec();
        let bind_request_id = random_unique_id(&request_ids)?;
        request_ids.push(bind_request_id);
        let prepare_request_id = random_unique_id(&request_ids)?;
        request_ids.push(prepare_request_id);
        let activate_request_id = random_unique_id(&request_ids)?;
        request_ids.push(activate_request_id);
        let commit_request_id = random_unique_id(&request_ids)?;
        request_ids.push(commit_request_id);
        let destroy_present_request_id = random_unique_id(&request_ids)?;
        request_ids.push(destroy_present_request_id);
        let destroy_absent_request_id = random_unique_id(&request_ids)?;
        Self::from_ids(
            FunctionalCycleIds {
                context: context_id,
                bind_request: bind_request_id,
                prepare_request: prepare_request_id,
                activate_request: activate_request_id,
                commit_request: commit_request_id,
                destroy_present_request: destroy_present_request_id,
                destroy_absent_request: destroy_absent_request_id,
            },
            unix_now()?,
        )
    }

    fn from_ids(ids: FunctionalCycleIds, now: u64) -> Result<Self, ProbeError> {
        if ids.context.iter().all(|byte| *byte == 0) {
            return Err(ProbeError::Protocol);
        }
        let request_ids = ids.request_ids();
        for (position, request_id) in request_ids.iter().enumerate() {
            if request_id.iter().all(|byte| *byte == 0)
                || request_ids[..position].contains(request_id)
            {
                return Err(ProbeError::Protocol);
            }
        }
        let setup_expires_at_unix = now
            .checked_add(FUNCTIONAL_SETUP_TTL_SECONDS)
            .ok_or(ProbeError::Protocol)?;
        let hard_expires_at_unix = now
            .checked_add(FUNCTIONAL_HARD_TTL_SECONDS)
            .ok_or(ProbeError::Protocol)?;
        let leases = vec![
            LeasePlan {
                path_id: FUNCTIONAL_PATH_ID,
                role: WireguardRole::RelayClient as i32,
            },
            LeasePlan {
                path_id: FUNCTIONAL_PATH_ID,
                role: WireguardRole::RelayExit as i32,
            },
        ];
        let prepare_value = PrepareLeaseBatch {
            route_context_id: ids.context.to_vec(),
            role: ContextRole::Relay as i32,
            mptcp_accepted_addrs: FUNCTIONAL_MPTCP_LIMIT,
            mptcp_subflows: FUNCTIONAL_MPTCP_LIMIT,
            leases: leases.clone(),
            setup_expires_at_unix,
            hard_expires_at_unix,
        };
        let prepare_request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: ids.prepare_request.to_vec(),
            operation: Some(helper_request::Operation::PrepareLeaseBatch(prepare_value)),
        };
        let prepare = FunctionalRequestExchange::from_request(&prepare_request)?;
        let bind_request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: ids.bind_request.to_vec(),
            operation: Some(helper_request::Operation::BindHelperRuntime(
                BindHelperRuntime {
                    prepare_intent: Some(PrepareIntent {
                        route_context_id: ids.context.to_vec(),
                        prepare_request_id: ids.prepare_request.to_vec(),
                        prepare_operation_digest: prepare.operation_digest.to_vec(),
                        setup_expires_at_unix,
                        hard_expires_at_unix,
                        closed_plan: Some(ClosedPreparePlan {
                            context_role: ContextRole::Relay as i32,
                            leases,
                        }),
                    }),
                },
            )),
        };
        let bind = FunctionalRequestExchange::from_request(&bind_request)?;
        Ok(Self {
            ids,
            bind,
            prepare,
            hard_expires_at_unix,
        })
    }
}

#[derive(Clone)]
struct FunctionalPreparedReceipt {
    context_id: [u8; 16],
    context_handle: [u8; 32],
    lease_handle: [u8; 32],
    public_key: [u8; 32],
    listen_port: u16,
}

struct FunctionalCycleResult {
    helper_runtime_id: [u8; 32],
    prepared: FunctionalPreparedReceipt,
}

#[derive(Clone)]
struct FunctionalRelayPairLeaseReceipt {
    lease_handle: [u8; 32],
    public_key: [u8; 32],
    listen_port: u16,
}

#[derive(Clone)]
struct FunctionalRelayPairPreparedReceipt {
    context_id: [u8; 16],
    context_handle: [u8; 32],
    relay_client: FunctionalRelayPairLeaseReceipt,
    relay_exit: FunctionalRelayPairLeaseReceipt,
}

struct FunctionalRelayPairResult {
    helper_runtime_id: [u8; 32],
    prepared: FunctionalRelayPairPreparedReceipt,
}

struct FunctionalRelayPairAuthority {
    signed_relay_reservation: Vec<u8>,
    signed_client_relay_request: Vec<u8>,
    maximum_up_mbps: u32,
    maximum_down_mbps: u32,
}

struct FunctionalResponseReceipt {
    outcome: helper_response::Outcome,
    canonical_frame: Zeroizing<Vec<u8>>,
}

fn random_unique_id(excluded: &[[u8; 16]]) -> Result<[u8; 16], ProbeError> {
    let mut source = OsRng;
    for _ in 0..64 {
        let mut value = [0_u8; 16];
        source
            .try_fill_bytes(&mut value)
            .map_err(|_| ProbeError::Random)?;
        if value.iter().any(|byte| *byte != 0) && !excluded.contains(&value) {
            return Ok(value);
        }
    }
    Err(ProbeError::Random)
}

fn unix_now() -> Result<u64, ProbeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProbeError::Protocol)
        .map(|duration| duration.as_secs())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let Some(invocation) = parse_invocation(std::env::args_os().skip(1)) else {
        eprintln!("{USAGE_RECORD}");
        return ExitCode::from(2);
    };
    match run_mode(invocation).await {
        Ok(()) => {
            println!("{}", invocation.mode.success_record());
            ExitCode::SUCCESS
        }
        Err(ProbeFailure::Functional(failure)) => {
            let stderr = io::stderr();
            let mut stderr = stderr.lock();
            if failure.write_record(&mut stderr).is_err() || stderr.flush().is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::FAILURE
        }
        Err(ProbeFailure::Generic) => {
            eprintln!("{FAILURE_RECORD}");
            ExitCode::FAILURE
        }
    }
}

fn parse_invocation(arguments: impl IntoIterator<Item = OsString>) -> Option<ProbeInvocation> {
    let mut arguments = arguments.into_iter();
    let mode_argument = arguments.next()?;
    let pid_argument = arguments.next()?;
    let gid_argument = arguments.next()?;
    if arguments.next().is_some() {
        return None;
    }
    if mode_argument.as_os_str().as_bytes().len() > MAX_MODE_ARGUMENT_BYTES {
        return None;
    }
    let mode = match mode_argument.to_str()? {
        "bind-runtime" => Mode::BindRuntime,
        "functional-client-lease" => Mode::FunctionalClientLease,
        "reject-frame-bounds" => Mode::RejectFrameBounds,
        "reject-wire-shapes" => Mode::RejectWireShapes,
        "expect-unauthorised-peer" => Mode::ExpectUnauthorisedPeer,
        _ => return None,
    };
    let pid = i32::try_from(parse_nonzero_decimal_u32(&pid_argument)?).ok()?;
    let gid = parse_nonzero_decimal_u32(&gid_argument)?;
    Some(ProbeInvocation {
        mode,
        expected_peer: ExpectedPeer { pid, gid },
    })
}

fn parse_nonzero_decimal_u32(argument: &OsString) -> Option<u32> {
    let bytes = argument.as_os_str().as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_DECIMAL_U32_BYTES
        || bytes[0] == b'0'
        || bytes.iter().any(|byte| !byte.is_ascii_digit())
    {
        return None;
    }
    let mut value = 0_u32;
    for byte in bytes {
        value = value
            .checked_mul(10)?
            .checked_add(u32::from(*byte - b'0'))?;
    }
    (value != u32::MAX).then_some(value)
}

async fn run_mode(invocation: ProbeInvocation) -> Result<(), ProbeFailure> {
    match invocation.mode {
        Mode::BindRuntime => run_bind_runtime(invocation.expected_peer)
            .await
            .map_err(|_| ProbeFailure::Generic),
        Mode::FunctionalClientLease => run_functional_client_lease(invocation.expected_peer)
            .await
            .map_err(ProbeFailure::Functional),
        Mode::RejectFrameBounds => run_reject_frame_bounds(invocation.expected_peer)
            .await
            .map_err(|_| ProbeFailure::Generic),
        Mode::RejectWireShapes => run_reject_wire_shapes(invocation.expected_peer)
            .await
            .map_err(|_| ProbeFailure::Generic),
        Mode::ExpectUnauthorisedPeer => run_expect_unauthorised_peer(invocation.expected_peer)
            .await
            .map_err(|_| ProbeFailure::Generic),
    }
}

async fn run_bind_runtime(expected_peer: ExpectedPeer) -> Result<(), ProbeError> {
    let first = BindExchange::random()?;
    let second = BindExchange::random()?;
    if first.request_id == second.request_id {
        return Err(ProbeError::Random);
    }
    timeout(PROBE_TIMEOUT, async move {
        let mut stream = connect_trusted_helper(expected_peer).await?;
        let first_runtime = exchange_bind(&mut stream, &first).await?;
        let second_runtime = exchange_bind(&mut stream, &second).await?;
        if first_runtime.iter().all(|byte| *byte == 0) || first_runtime != second_runtime {
            return Err(ProbeError::Correlation);
        }
        stream.shutdown().await.map_err(|_| ProbeError::Io)
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

#[allow(
    clippy::too_many_lines,
    reason = "the explicit three-cycle lifecycle keeps every phase transition and fixed record ordered"
)]
async fn run_functional_client_lease(
    expected_peer: ExpectedPeer,
) -> Result<(), FunctionalProbeFailure> {
    let phase = Cell::new(FunctionalPhase::Connect);
    timeout(FUNCTIONAL_PROBE_TIMEOUT, async {
        let mut prepare_stream = connect_trusted_helper(expected_peer)
            .await
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        phase.set(FunctionalPhase::Plan);
        let first_plan = FunctionalCyclePlan::random(&[], &[], FunctionalLeaseRole::Client)
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        let first_context_id = first_plan.ids.context;
        let first_request_ids = first_plan.ids.request_ids();
        let first = activate_functional_cycle(
            &mut prepare_stream,
            &first_plan,
            &phase,
            FunctionalPhase::Bind,
            FunctionalPhase::Prepare,
            FunctionalPhase::Activate,
        )
        .await?;
        let mut stream = functional_barrier_and_reconnect(
            prepare_stream,
            expected_peer,
            &phase,
            FunctionalPhase::Shutdown,
            FunctionalPhase::Ready,
            FunctionalPhase::Release,
            FunctionalPhase::Reconnect,
            FUNCTIONAL_READY_RECORD,
        )
        .await?;
        phase.set(FunctionalPhase::Commit);
        commit_functional_cycle(&mut stream, &first_plan, &first.prepared)
            .await
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        phase.set(FunctionalPhase::Destroy);
        destroy_functional_cycle(&mut stream, &first_plan, &first.prepared)
            .await
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;

        phase.set(FunctionalPhase::SecondCyclePlan);
        let second_plan = FunctionalCyclePlan::random(
            &[first_context_id],
            &first_request_ids,
            FunctionalLeaseRole::Exit,
        )
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        let second_context_id = second_plan.ids.context;
        let second_request_ids = second_plan.ids.request_ids();
        let second = activate_functional_cycle(
            &mut stream,
            &second_plan,
            &phase,
            FunctionalPhase::SecondCycleBind,
            FunctionalPhase::SecondCyclePrepare,
            FunctionalPhase::SecondCycleActivate,
        )
        .await?;
        phase.set(FunctionalPhase::Reuse);
        if first.helper_runtime_id != second.helper_runtime_id {
            return Err(FunctionalProbeFailure::new(
                phase.get(),
                ProbeError::Correlation,
            ));
        }
        validate_functional_reuse(&first.prepared, &second.prepared)
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        let mut stream = functional_barrier_and_reconnect(
            stream,
            expected_peer,
            &phase,
            FunctionalPhase::SecondCycleShutdown,
            FunctionalPhase::SecondCycleReady,
            FunctionalPhase::SecondCycleRelease,
            FunctionalPhase::SecondCycleReconnect,
            FUNCTIONAL_EXIT_READY_RECORD,
        )
        .await?;
        phase.set(FunctionalPhase::SecondCycleCommit);
        commit_functional_cycle(&mut stream, &second_plan, &second.prepared)
            .await
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        phase.set(FunctionalPhase::SecondCycleDestroy);
        destroy_functional_cycle(&mut stream, &second_plan, &second.prepared)
            .await
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        publish_fixed_record(FUNCTIONAL_EXIT_PASS_RECORD)
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;

        phase.set(FunctionalPhase::RelayPairPlan);
        let mut prior_request_ids = first_request_ids.to_vec();
        prior_request_ids.extend(second_request_ids);
        let pair_plan = FunctionalRelayPairPlan::random(
            &[first_context_id, second_context_id],
            &prior_request_ids,
        )
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        let pair = activate_functional_relay_pair(&mut stream, &pair_plan, &phase).await?;
        phase.set(FunctionalPhase::RelayPairReuse);
        if first.helper_runtime_id != pair.helper_runtime_id {
            return Err(FunctionalProbeFailure::new(
                phase.get(),
                ProbeError::Correlation,
            ));
        }
        validate_functional_relay_pair_reuse(&first.prepared, &second.prepared, &pair.prepared)
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        let mut stream = functional_barrier_and_reconnect(
            stream,
            expected_peer,
            &phase,
            FunctionalPhase::RelayPairShutdown,
            FunctionalPhase::RelayPairReady,
            FunctionalPhase::RelayPairRelease,
            FunctionalPhase::RelayPairReconnect,
            FUNCTIONAL_RELAY_PAIR_READY_RECORD,
        )
        .await?;
        phase.set(FunctionalPhase::RelayPairCommit);
        commit_functional_relay_pair(&mut stream, &pair_plan, &pair.prepared)
            .await
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        phase.set(FunctionalPhase::RelayPairDestroy);
        destroy_functional_relay_pair(&mut stream, &pair_plan, &pair.prepared)
            .await
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        publish_fixed_record(FUNCTIONAL_RELAY_PAIR_PASS_RECORD)
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        phase.set(FunctionalPhase::FinalShutdown);
        stream
            .shutdown()
            .await
            .map_err(|_| FunctionalProbeFailure::new(phase.get(), ProbeError::Io))
    })
    .await
    .map_err(|_| FunctionalProbeFailure::new(phase.get(), ProbeError::Timeout))?
}

#[allow(
    clippy::too_many_arguments,
    reason = "the explicit role-specific phase sequence keeps every barrier failure diagnostic exact"
)]
async fn functional_barrier_and_reconnect(
    mut stream: UnixStream,
    expected_peer: ExpectedPeer,
    phase: &Cell<FunctionalPhase>,
    shutdown_phase: FunctionalPhase,
    ready_phase: FunctionalPhase,
    release_phase: FunctionalPhase,
    reconnect_phase: FunctionalPhase,
    ready_record: &str,
) -> Result<UnixStream, FunctionalProbeFailure> {
    phase.set(shutdown_phase);
    stream
        .shutdown()
        .await
        .map_err(|_| FunctionalProbeFailure::new(phase.get(), ProbeError::Io))?;
    drop(stream);
    phase.set(ready_phase);
    publish_fixed_record(ready_record)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    phase.set(release_phase);
    wait_for_functional_release()
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    phase.set(reconnect_phase);
    connect_trusted_helper(expected_peer)
        .await
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))
}

async fn activate_functional_cycle(
    stream: &mut UnixStream,
    plan: &FunctionalCyclePlan,
    phase: &Cell<FunctionalPhase>,
    bind_phase: FunctionalPhase,
    prepare_phase: FunctionalPhase,
    activate_phase: FunctionalPhase,
) -> Result<FunctionalCycleResult, FunctionalProbeFailure> {
    phase.set(bind_phase);
    let runtime_outcome = exchange_functional(stream, &plan.bind, HELPER_RUNTIME_DIAGNOSTIC)
        .await
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    let helper_runtime_id = validate_runtime_outcome(runtime_outcome)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    phase.set(prepare_phase);
    let prepared_outcome = exchange_functional(stream, &plan.prepare, LEASES_PREPARED_DIAGNOSTIC)
        .await
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    let prepared = validate_prepared_outcome(prepared_outcome, plan.ids.context, plan.role)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    phase.set(activate_phase);
    let activate = functional_activation_exchange(plan, &prepared)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    let activated_outcome = exchange_functional(stream, &activate, LEASES_ACTIVATED_DIAGNOSTIC)
        .await
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    validate_activated_outcome(activated_outcome, &prepared)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    let retried_outcome = exchange_functional(stream, &activate, LEASES_ACTIVATED_DIAGNOSTIC)
        .await
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    validate_activated_outcome(retried_outcome, &prepared)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    Ok(FunctionalCycleResult {
        helper_runtime_id,
        prepared,
    })
}

async fn activate_functional_relay_pair(
    stream: &mut UnixStream,
    plan: &FunctionalRelayPairPlan,
    phase: &Cell<FunctionalPhase>,
) -> Result<FunctionalRelayPairResult, FunctionalProbeFailure> {
    phase.set(FunctionalPhase::RelayPairBind);
    let runtime_outcome = exchange_functional(stream, &plan.bind, HELPER_RUNTIME_DIAGNOSTIC)
        .await
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    let helper_runtime_id = validate_runtime_outcome(runtime_outcome)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    phase.set(FunctionalPhase::RelayPairPrepare);
    let prepared_outcome = exchange_functional(stream, &plan.prepare, LEASES_PREPARED_DIAGNOSTIC)
        .await
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    let prepared = validate_relay_pair_prepared_outcome(prepared_outcome, plan.ids.context)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    phase.set(FunctionalPhase::RelayPairActivate);
    let activate = functional_relay_pair_activation_exchange(plan, &prepared)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    let activated_outcome = exchange_functional(stream, &activate, LEASES_ACTIVATED_DIAGNOSTIC)
        .await
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    validate_relay_pair_activated_outcome(activated_outcome, &prepared)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    let retried_outcome = exchange_functional(stream, &activate, LEASES_ACTIVATED_DIAGNOSTIC)
        .await
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    validate_relay_pair_activated_outcome(retried_outcome, &prepared)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    Ok(FunctionalRelayPairResult {
        helper_runtime_id,
        prepared,
    })
}

async fn commit_functional_relay_pair(
    stream: &mut UnixStream,
    plan: &FunctionalRelayPairPlan,
    prepared: &FunctionalRelayPairPreparedReceipt,
) -> Result<(), ProbeError> {
    let commit = functional_relay_pair_commit_exchange(plan, prepared)?;
    let committed =
        exchange_functional_receipt(stream, &commit, LEASES_COMMITTED_DIAGNOSTIC).await?;
    let retried = exchange_functional_receipt(stream, &commit, LEASES_COMMITTED_DIAGNOSTIC).await?;
    validate_relay_pair_committed_retry(
        &committed.outcome,
        &retried.outcome,
        &committed.canonical_frame,
        &retried.canonical_frame,
        prepared,
    )
}

fn functional_relay_pair_commit_exchange(
    plan: &FunctionalRelayPairPlan,
    prepared: &FunctionalRelayPairPreparedReceipt,
) -> Result<FunctionalRequestExchange, ProbeError> {
    if prepared.context_id != plan.ids.context {
        return Err(ProbeError::Correlation);
    }
    FunctionalRequestExchange::from_request(&HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: plan.ids.commit_request.to_vec(),
        operation: Some(helper_request::Operation::CommitLeaseBatch(
            CommitLeaseBatch {
                route_context_id: prepared.context_id.to_vec(),
                context_handle: prepared.context_handle.to_vec(),
                leases: vec![
                    LeaseCommit {
                        lease_handle: prepared.relay_client.lease_handle.to_vec(),
                        path_id: FUNCTIONAL_PATH_ID,
                        role: WireguardRole::RelayClient as i32,
                    },
                    LeaseCommit {
                        lease_handle: prepared.relay_exit.lease_handle.to_vec(),
                        path_id: FUNCTIONAL_PATH_ID,
                        role: WireguardRole::RelayExit as i32,
                    },
                ],
            },
        )),
    })
}

fn functional_relay_pair_activation_exchange(
    plan: &FunctionalRelayPairPlan,
    prepared: &FunctionalRelayPairPreparedReceipt,
) -> Result<FunctionalRequestExchange, ProbeError> {
    let client = &prepared.relay_client;
    let exit = &prepared.relay_exit;
    if prepared.context_id != plan.ids.context
        || client.public_key == exit.public_key
        || client.listen_port == exit.listen_port
        || [client.public_key, exit.public_key].iter().any(|key| {
            *key == FUNCTIONAL_PEER_PUBLIC_KEY || *key == FUNCTIONAL_EXIT_PEER_PUBLIC_KEY
        })
        || [client.listen_port, exit.listen_port].contains(&FUNCTIONAL_PEER_PORT)
        || [client.listen_port, exit.listen_port].contains(&FUNCTIONAL_EXIT_PEER_PORT)
    {
        return Err(ProbeError::Correlation);
    }
    let authority = functional_signed_relay_pair_authority(plan, prepared)?;
    FunctionalRequestExchange::from_request(&HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: plan.ids.activate_request.to_vec(),
        operation: Some(helper_request::Operation::ActivateLeaseBatch(
            ActivateLeaseBatch {
                route_context_id: prepared.context_id.to_vec(),
                context_handle: prepared.context_handle.to_vec(),
                leases: vec![
                    LeaseActivation {
                        lease_handle: client.lease_handle.to_vec(),
                        path_id: FUNCTIONAL_PATH_ID,
                        role: WireguardRole::RelayClient as i32,
                        peer_public_key: FUNCTIONAL_PEER_PUBLIC_KEY.to_vec(),
                        peer_endpoint: Some(PublicUdpEndpoint {
                            address: FUNCTIONAL_PEER_IPV4.to_vec(),
                            port: u32::from(FUNCTIONAL_PEER_PORT),
                        }),
                        maximum_up_mbps: authority.maximum_up_mbps,
                        maximum_down_mbps: authority.maximum_down_mbps,
                        signed_relay_reservation: authority.signed_relay_reservation.clone(),
                        signed_client_relay_request: authority.signed_client_relay_request,
                    },
                    LeaseActivation {
                        lease_handle: exit.lease_handle.to_vec(),
                        path_id: FUNCTIONAL_PATH_ID,
                        role: WireguardRole::RelayExit as i32,
                        peer_public_key: FUNCTIONAL_EXIT_PEER_PUBLIC_KEY.to_vec(),
                        peer_endpoint: Some(PublicUdpEndpoint {
                            address: FUNCTIONAL_EXIT_PEER_IPV4.to_vec(),
                            port: u32::from(FUNCTIONAL_EXIT_PEER_PORT),
                        }),
                        maximum_up_mbps: authority.maximum_up_mbps,
                        maximum_down_mbps: authority.maximum_down_mbps,
                        signed_relay_reservation: authority.signed_relay_reservation,
                        signed_client_relay_request: Vec::new(),
                    },
                ],
            },
        )),
    })
}

async fn commit_functional_cycle(
    stream: &mut UnixStream,
    plan: &FunctionalCyclePlan,
    prepared: &FunctionalPreparedReceipt,
) -> Result<(), ProbeError> {
    let commit = functional_commit_exchange(plan, prepared)?;
    let committed =
        exchange_functional_receipt(stream, &commit, LEASES_COMMITTED_DIAGNOSTIC).await?;
    let retried = exchange_functional_receipt(stream, &commit, LEASES_COMMITTED_DIAGNOSTIC).await?;
    validate_committed_retry(
        &committed.outcome,
        &retried.outcome,
        &committed.canonical_frame,
        &retried.canonical_frame,
        prepared,
    )
}

fn functional_commit_exchange(
    plan: &FunctionalCyclePlan,
    prepared: &FunctionalPreparedReceipt,
) -> Result<FunctionalRequestExchange, ProbeError> {
    if prepared.context_id != plan.ids.context {
        return Err(ProbeError::Correlation);
    }
    FunctionalRequestExchange::from_request(&HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: plan.ids.commit_request.to_vec(),
        operation: Some(helper_request::Operation::CommitLeaseBatch(
            CommitLeaseBatch {
                route_context_id: prepared.context_id.to_vec(),
                context_handle: prepared.context_handle.to_vec(),
                leases: vec![LeaseCommit {
                    lease_handle: prepared.lease_handle.to_vec(),
                    path_id: FUNCTIONAL_PATH_ID,
                    role: plan.role.wireguard() as i32,
                }],
            },
        )),
    })
}

fn functional_activation_exchange(
    plan: &FunctionalCyclePlan,
    prepared: &FunctionalPreparedReceipt,
) -> Result<FunctionalRequestExchange, ProbeError> {
    let peer_public_key = plan.role.peer_public_key();
    let (peer_address, peer_port) = plan.role.peer_endpoint();
    if prepared.context_id != plan.ids.context
        || prepared.public_key == peer_public_key
        || prepared.public_key == FUNCTIONAL_RELAY_EXIT_PUBLIC_KEY
        || prepared.public_key == FUNCTIONAL_EXIT_PUBLIC_KEY
        || (FUNCTIONAL_PUBLIC_IPV4, prepared.listen_port) == (peer_address, peer_port)
    {
        return Err(ProbeError::Correlation);
    }
    let signed_relay_reservation = functional_signed_relay_reservation(plan, prepared)?;
    FunctionalRequestExchange::from_request(&HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: plan.ids.activate_request.to_vec(),
        operation: Some(helper_request::Operation::ActivateLeaseBatch(
            ActivateLeaseBatch {
                route_context_id: prepared.context_id.to_vec(),
                context_handle: prepared.context_handle.to_vec(),
                leases: vec![LeaseActivation {
                    lease_handle: prepared.lease_handle.to_vec(),
                    path_id: FUNCTIONAL_PATH_ID,
                    role: plan.role.wireguard() as i32,
                    peer_public_key: peer_public_key.to_vec(),
                    peer_endpoint: Some(PublicUdpEndpoint {
                        address: peer_address.to_vec(),
                        port: u32::from(peer_port),
                    }),
                    maximum_up_mbps: 0,
                    maximum_down_mbps: 0,
                    signed_relay_reservation,
                    signed_client_relay_request: Vec::new(),
                }],
            },
        )),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one closed probe builder creates a single internally consistent two-signer grant graph"
)]
fn functional_signed_relay_reservation(
    plan: &FunctionalCyclePlan,
    prepared: &FunctionalPreparedReceipt,
) -> Result<Vec<u8>, ProbeError> {
    let created_at_ms = plan
        .hard_expires_at_unix
        .checked_sub(FUNCTIONAL_HARD_TTL_SECONDS)
        .and_then(|created| created.checked_mul(1_000))
        .ok_or(ProbeError::Protocol)?;
    let expires_at_ms = plan
        .hard_expires_at_unix
        .checked_mul(1_000)
        .ok_or(ProbeError::Protocol)?;
    let request_expires_at_ms = created_at_ms
        .checked_add(20_000)
        .filter(|request_expiry| *request_expiry <= expires_at_ms)
        .ok_or(ProbeError::Protocol)?;
    let relay_key = ephemeral_signing_key()?;
    let exit_key = ephemeral_signing_key()?;
    let client_session_key = ephemeral_signing_key()?;
    let control_relay_key = ephemeral_signing_key()?;
    let relay_public_key = relay_key.verifying_key().to_bytes();
    let exit_public_key = exit_key.verifying_key().to_bytes();
    let client_session_public_key = client_session_key.verifying_key().to_bytes();
    let control_relay_public_key = control_relay_key.verifying_key().to_bytes();
    let relay_node_id = node_id_from_public_key(&relay_public_key);
    let exit_node_id = node_id_from_public_key(&exit_public_key);
    let client_session_id = node_id_from_public_key(&client_session_public_key);
    let control_relay_node_id = node_id_from_public_key(&control_relay_public_key);
    let relay_peer_id = peer_id_from_ed25519(&relay_public_key)?;
    let exit_peer_id = peer_id_from_ed25519(&exit_public_key)?;
    let control_relay_peer_id = peer_id_from_ed25519(&control_relay_public_key)?;
    let reservation_id = random_unique_id(&[])?;
    let capability_id = random_unique_id(&[])?;
    let exit_boot_id = random_unique_id(&[])?;
    let hold_id = random_unique_id(&[])?;
    let finalize_id = random_unique_id(&[])?;
    let policy_hash = random_nonzero_32()?;
    let exit_nonce = generate_nonce();
    let relay_nonce = generate_nonce();
    let exit_endpoint = if plan.role == FunctionalLeaseRole::Exit {
        WireguardEndpoint {
            public_key: prepared.public_key.to_vec(),
            underlay_ip: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
            listen_port: u32::from(prepared.listen_port),
        }
    } else {
        WireguardEndpoint {
            public_key: FUNCTIONAL_EXIT_PUBLIC_KEY.to_vec(),
            underlay_ip: FUNCTIONAL_EXIT_IPV4.to_vec(),
            listen_port: u32::from(FUNCTIONAL_EXIT_PORT),
        }
    };
    let authorization = RelayAuthorization {
        reservation_id: reservation_id.to_vec(),
        route_context_id: prepared.context_id.to_vec(),
        path_id: FUNCTIONAL_PATH_ID,
        relay_node_id: relay_node_id.to_vec(),
        exit_node_id: exit_node_id.to_vec(),
        client_session_id: client_session_id.to_vec(),
        allowed_transports: vec![Transport::TcpMptcp as i32],
        maximum_up_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        maximum_down_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        client_wireguard_public_key: if plan.role == FunctionalLeaseRole::Client {
            prepared.public_key.to_vec()
        } else {
            FUNCTIONAL_RELAY_EXIT_PUBLIC_KEY.to_vec()
        },
        exit_wireguard_endpoint: Some(exit_endpoint.clone()),
        policy_hash: policy_hash.to_vec(),
        created_at_ms,
        expires_at_ms,
        nonce: exit_nonce.to_vec(),
        relay_peer_id: relay_peer_id.clone(),
        capability_id: capability_id.to_vec(),
        client_session_public_key: client_session_public_key.to_vec(),
        exit_boot_id: exit_boot_id.to_vec(),
        hold_id: hold_id.to_vec(),
        finalize_id: finalize_id.to_vec(),
        control_relay_node_id: control_relay_node_id.to_vec(),
        control_relay_peer_id: control_relay_peer_id.clone(),
        exit_peer_id: exit_peer_id.clone(),
    };
    let exit_authorization = sign_control_message(
        &authorization,
        &exit_key,
        created_at_ms,
        expires_at_ms,
        exit_nonce,
        TimePolicy::default(),
    )
    .map_err(|_| ProbeError::Protocol)?;
    let client_endpoint = if plan.role == FunctionalLeaseRole::Client {
        WireguardEndpoint {
            public_key: prepared.public_key.to_vec(),
            underlay_ip: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
            listen_port: u32::from(prepared.listen_port),
        }
    } else {
        WireguardEndpoint {
            public_key: FUNCTIONAL_RELAY_EXIT_PUBLIC_KEY.to_vec(),
            underlay_ip: FUNCTIONAL_RELAY_EXIT_IPV4.to_vec(),
            listen_port: u32::from(FUNCTIONAL_RELAY_EXIT_PORT),
        }
    };
    let capability_nonce = generate_nonce();
    let capability = ClientSessionCapability {
        capability_id: capability_id.to_vec(),
        reservation_id: reservation_id.to_vec(),
        route_context_id: prepared.context_id.to_vec(),
        client_session_id: client_session_id.to_vec(),
        client_session_public_key: client_session_public_key.to_vec(),
        exit_node_id: exit_node_id.to_vec(),
        exit_boot_id: exit_boot_id.to_vec(),
        control_relay_node_id: control_relay_node_id.to_vec(),
        control_relay_peer_id: control_relay_peer_id.clone(),
        policy_hash: policy_hash.to_vec(),
        allowed_transports: vec![Transport::TcpMptcp as i32],
        reserved_up_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        reserved_down_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        maximum_paths: 1,
        created_at_ms,
        expires_at_ms,
        nonce: capability_nonce.to_vec(),
        exit_peer_id: exit_peer_id.clone(),
        probe_permit_limit: 1,
    };
    let signed_capability = sign_control_message(
        &capability,
        &exit_key,
        created_at_ms,
        expires_at_ms,
        capability_nonce,
        TimePolicy::default(),
    )
    .map_err(|_| ProbeError::Protocol)?;
    let exit_reservation_nonce = generate_nonce();
    let exit_reservation = ExitReservation {
        reservation_id: reservation_id.to_vec(),
        route_context_id: prepared.context_id.to_vec(),
        exit_node_id: exit_node_id.to_vec(),
        client_session_id: client_session_id.to_vec(),
        allowed_transports: vec![Transport::TcpMptcp as i32],
        reserved_up_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        reserved_down_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        maximum_paths: 1,
        policy_hash: policy_hash.to_vec(),
        created_at_ms,
        expires_at_ms,
        nonce: exit_reservation_nonce.to_vec(),
        capability_id: capability_id.to_vec(),
        client_session_public_key: client_session_public_key.to_vec(),
        exit_boot_id: exit_boot_id.to_vec(),
        hold_id: hold_id.to_vec(),
        finalize_id: finalize_id.to_vec(),
        control_relay_node_id: control_relay_node_id.to_vec(),
        control_relay_peer_id: control_relay_peer_id.clone(),
        exit_peer_id: exit_peer_id.clone(),
        native_route_identity: Some(NativeRouteIdentity {
            auth_commitment: random_nonzero_32()?.to_vec(),
            certificate_sha256: random_nonzero_32()?.to_vec(),
            spki_sha256: random_nonzero_32()?.to_vec(),
            tls_server_name: "exit.volparossa.test".to_owned(),
            masque_context_id: 1,
            client_native_instance_id: random_nonzero_32()?.to_vec(),
            exit_native_instance_id: random_nonzero_32()?.to_vec(),
        }),
    };
    let signed_exit_reservation = sign_control_message(
        &exit_reservation,
        &exit_key,
        created_at_ms,
        expires_at_ms,
        exit_reservation_nonce,
        TimePolicy::default(),
    )
    .map_err(|_| ProbeError::Protocol)?;
    let request_nonce = generate_nonce();
    let request = RelayReservationRequest {
        client_session_id: client_session_id.to_vec(),
        exit_authorization: exit_authorization.clone(),
        created_at_ms,
        expires_at_ms: request_expires_at_ms,
        nonce: request_nonce.to_vec(),
        client_wireguard_endpoint: Some(client_endpoint),
        client_session_capability: signed_capability,
        exit_reservation: signed_exit_reservation,
    };
    let signed_client_relay_request = sign_control_message(
        &request,
        &client_session_key,
        created_at_ms,
        request_expires_at_ms,
        request_nonce,
        TimePolicy::default(),
    )
    .map_err(|_| ProbeError::Protocol)?;
    let signed_client_relay_request_sha256 =
        relay_reservation_request_sha256(&signed_client_relay_request)
            .map_err(|_| ProbeError::Protocol)?;
    let relay = RelayReservation {
        reservation_id: reservation_id.to_vec(),
        route_context_id: prepared.context_id.to_vec(),
        path_id: FUNCTIONAL_PATH_ID,
        relay_node_id: relay_node_id.to_vec(),
        exit_node_id: exit_node_id.to_vec(),
        client_session_id: client_session_id.to_vec(),
        allowed_transports: vec![Transport::TcpMptcp as i32],
        maximum_up_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        maximum_down_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        client_wireguard_public_key: if plan.role == FunctionalLeaseRole::Client {
            prepared.public_key.to_vec()
        } else {
            FUNCTIONAL_RELAY_EXIT_PUBLIC_KEY.to_vec()
        },
        relay_client_wireguard_endpoint: Some(WireguardEndpoint {
            public_key: FUNCTIONAL_PEER_PUBLIC_KEY.to_vec(),
            underlay_ip: FUNCTIONAL_PEER_IPV4.to_vec(),
            listen_port: u32::from(FUNCTIONAL_PEER_PORT),
        }),
        relay_exit_wireguard_endpoint: Some(if plan.role == FunctionalLeaseRole::Exit {
            WireguardEndpoint {
                public_key: FUNCTIONAL_EXIT_PEER_PUBLIC_KEY.to_vec(),
                underlay_ip: FUNCTIONAL_EXIT_PEER_IPV4.to_vec(),
                listen_port: u32::from(FUNCTIONAL_EXIT_PEER_PORT),
            }
        } else {
            WireguardEndpoint {
                public_key: FUNCTIONAL_RELAY_EXIT_PUBLIC_KEY.to_vec(),
                underlay_ip: FUNCTIONAL_RELAY_EXIT_IPV4.to_vec(),
                listen_port: u32::from(FUNCTIONAL_RELAY_EXIT_PORT),
            }
        }),
        exit_wireguard_endpoint: Some(exit_endpoint),
        policy_hash: policy_hash.to_vec(),
        created_at_ms,
        expires_at_ms,
        nonce: relay_nonce.to_vec(),
        exit_authorization,
        relay_peer_id,
        capability_id: capability_id.to_vec(),
        client_session_public_key: client_session_public_key.to_vec(),
        exit_boot_id: exit_boot_id.to_vec(),
        hold_id: hold_id.to_vec(),
        finalize_id: finalize_id.to_vec(),
        control_relay_node_id: control_relay_node_id.to_vec(),
        control_relay_peer_id,
        exit_peer_id,
        signed_client_relay_request_sha256: signed_client_relay_request_sha256.to_vec(),
    };
    sign_control_message(
        &relay,
        &relay_key,
        created_at_ms,
        expires_at_ms,
        relay_nonce,
        TimePolicy::default(),
    )
    .map_err(|_| ProbeError::Protocol)
}

#[allow(
    clippy::too_many_lines,
    reason = "one closed probe builder creates the complete client, exit, and relay authority graph"
)]
fn functional_signed_relay_pair_authority(
    plan: &FunctionalRelayPairPlan,
    prepared: &FunctionalRelayPairPreparedReceipt,
) -> Result<FunctionalRelayPairAuthority, ProbeError> {
    if prepared.context_id != plan.ids.context {
        return Err(ProbeError::Correlation);
    }
    let created_at_ms = plan
        .hard_expires_at_unix
        .checked_sub(FUNCTIONAL_HARD_TTL_SECONDS)
        .and_then(|created| created.checked_mul(1_000))
        .ok_or(ProbeError::Protocol)?;
    let expires_at_ms = plan
        .hard_expires_at_unix
        .checked_mul(1_000)
        .ok_or(ProbeError::Protocol)?;
    let request_expires_at_ms = created_at_ms
        .checked_add(20_000)
        .filter(|request_expiry| *request_expiry <= expires_at_ms)
        .ok_or(ProbeError::Protocol)?;
    let relay_key = ephemeral_signing_key()?;
    let exit_key = ephemeral_signing_key()?;
    let client_session_key = ephemeral_signing_key()?;
    let control_relay_key = ephemeral_signing_key()?;
    let relay_public_key = relay_key.verifying_key().to_bytes();
    let exit_public_key = exit_key.verifying_key().to_bytes();
    let client_session_public_key = client_session_key.verifying_key().to_bytes();
    let control_relay_public_key = control_relay_key.verifying_key().to_bytes();
    let relay_node_id = node_id_from_public_key(&relay_public_key);
    let exit_node_id = node_id_from_public_key(&exit_public_key);
    let client_session_id = node_id_from_public_key(&client_session_public_key);
    let control_relay_node_id = node_id_from_public_key(&control_relay_public_key);
    let relay_peer_id = peer_id_from_ed25519(&relay_public_key)?;
    let exit_peer_id = peer_id_from_ed25519(&exit_public_key)?;
    let control_relay_peer_id = peer_id_from_ed25519(&control_relay_public_key)?;
    let reservation_id = random_unique_id(&[])?;
    let capability_id = random_unique_id(&[reservation_id])?;
    let exit_boot_id = random_unique_id(&[reservation_id, capability_id])?;
    let hold_id = random_unique_id(&[reservation_id, capability_id, exit_boot_id])?;
    let finalize_id = random_unique_id(&[reservation_id, capability_id, exit_boot_id, hold_id])?;
    let policy_hash = random_nonzero_32()?;
    let allowed_transports = vec![Transport::TcpMptcp as i32];
    let exit_endpoint = WireguardEndpoint {
        public_key: FUNCTIONAL_EXIT_PEER_PUBLIC_KEY.to_vec(),
        underlay_ip: FUNCTIONAL_EXIT_PEER_IPV4.to_vec(),
        listen_port: u32::from(FUNCTIONAL_EXIT_PEER_PORT),
    };

    let capability_nonce = generate_nonce();
    let capability = ClientSessionCapability {
        capability_id: capability_id.to_vec(),
        reservation_id: reservation_id.to_vec(),
        route_context_id: prepared.context_id.to_vec(),
        client_session_id: client_session_id.to_vec(),
        client_session_public_key: client_session_public_key.to_vec(),
        exit_node_id: exit_node_id.to_vec(),
        exit_boot_id: exit_boot_id.to_vec(),
        control_relay_node_id: control_relay_node_id.to_vec(),
        control_relay_peer_id: control_relay_peer_id.clone(),
        policy_hash: policy_hash.to_vec(),
        allowed_transports: allowed_transports.clone(),
        reserved_up_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        reserved_down_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        maximum_paths: 1,
        created_at_ms,
        expires_at_ms,
        nonce: capability_nonce.to_vec(),
        exit_peer_id: exit_peer_id.clone(),
        probe_permit_limit: 1,
    };
    let signed_capability = sign_control_message(
        &capability,
        &exit_key,
        created_at_ms,
        expires_at_ms,
        capability_nonce,
        TimePolicy::default(),
    )
    .map_err(|_| ProbeError::Protocol)?;

    let exit_reservation_nonce = generate_nonce();
    let exit_reservation = ExitReservation {
        reservation_id: reservation_id.to_vec(),
        route_context_id: prepared.context_id.to_vec(),
        exit_node_id: exit_node_id.to_vec(),
        client_session_id: client_session_id.to_vec(),
        allowed_transports: allowed_transports.clone(),
        reserved_up_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        reserved_down_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        maximum_paths: 1,
        policy_hash: policy_hash.to_vec(),
        created_at_ms,
        expires_at_ms,
        nonce: exit_reservation_nonce.to_vec(),
        capability_id: capability_id.to_vec(),
        client_session_public_key: client_session_public_key.to_vec(),
        exit_boot_id: exit_boot_id.to_vec(),
        hold_id: hold_id.to_vec(),
        finalize_id: finalize_id.to_vec(),
        control_relay_node_id: control_relay_node_id.to_vec(),
        control_relay_peer_id: control_relay_peer_id.clone(),
        exit_peer_id: exit_peer_id.clone(),
        native_route_identity: Some(NativeRouteIdentity {
            auth_commitment: random_nonzero_32()?.to_vec(),
            certificate_sha256: random_nonzero_32()?.to_vec(),
            spki_sha256: random_nonzero_32()?.to_vec(),
            tls_server_name: "exit.volparossa.test".to_owned(),
            masque_context_id: 1,
            client_native_instance_id: random_nonzero_32()?.to_vec(),
            exit_native_instance_id: random_nonzero_32()?.to_vec(),
        }),
    };
    let signed_exit_reservation = sign_control_message(
        &exit_reservation,
        &exit_key,
        created_at_ms,
        expires_at_ms,
        exit_reservation_nonce,
        TimePolicy::default(),
    )
    .map_err(|_| ProbeError::Protocol)?;

    let authorization_nonce = generate_nonce();
    let authorization = RelayAuthorization {
        reservation_id: reservation_id.to_vec(),
        route_context_id: prepared.context_id.to_vec(),
        path_id: FUNCTIONAL_PATH_ID,
        relay_node_id: relay_node_id.to_vec(),
        exit_node_id: exit_node_id.to_vec(),
        client_session_id: client_session_id.to_vec(),
        allowed_transports: allowed_transports.clone(),
        maximum_up_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        maximum_down_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        client_wireguard_public_key: FUNCTIONAL_PEER_PUBLIC_KEY.to_vec(),
        exit_wireguard_endpoint: Some(exit_endpoint.clone()),
        policy_hash: policy_hash.to_vec(),
        created_at_ms,
        expires_at_ms,
        nonce: authorization_nonce.to_vec(),
        relay_peer_id: relay_peer_id.clone(),
        capability_id: capability_id.to_vec(),
        client_session_public_key: client_session_public_key.to_vec(),
        exit_boot_id: exit_boot_id.to_vec(),
        hold_id: hold_id.to_vec(),
        finalize_id: finalize_id.to_vec(),
        control_relay_node_id: control_relay_node_id.to_vec(),
        control_relay_peer_id: control_relay_peer_id.clone(),
        exit_peer_id: exit_peer_id.clone(),
    };
    let signed_authorization = sign_control_message(
        &authorization,
        &exit_key,
        created_at_ms,
        expires_at_ms,
        authorization_nonce,
        TimePolicy::default(),
    )
    .map_err(|_| ProbeError::Protocol)?;

    let request_nonce = generate_nonce();
    let request = RelayReservationRequest {
        client_session_id: client_session_id.to_vec(),
        exit_authorization: signed_authorization.clone(),
        created_at_ms,
        expires_at_ms: request_expires_at_ms,
        nonce: request_nonce.to_vec(),
        client_wireguard_endpoint: Some(WireguardEndpoint {
            public_key: FUNCTIONAL_PEER_PUBLIC_KEY.to_vec(),
            underlay_ip: FUNCTIONAL_PEER_IPV4.to_vec(),
            listen_port: u32::from(FUNCTIONAL_PEER_PORT),
        }),
        client_session_capability: signed_capability,
        exit_reservation: signed_exit_reservation,
    };
    let signed_client_relay_request = sign_control_message(
        &request,
        &client_session_key,
        created_at_ms,
        request_expires_at_ms,
        request_nonce,
        TimePolicy::default(),
    )
    .map_err(|_| ProbeError::Protocol)?;
    let signed_client_relay_request_sha256 =
        relay_reservation_request_sha256(&signed_client_relay_request)
            .map_err(|_| ProbeError::Protocol)?;

    let relay_nonce = generate_nonce();
    let relay = RelayReservation {
        reservation_id: reservation_id.to_vec(),
        route_context_id: prepared.context_id.to_vec(),
        path_id: FUNCTIONAL_PATH_ID,
        relay_node_id: relay_node_id.to_vec(),
        exit_node_id: exit_node_id.to_vec(),
        client_session_id: client_session_id.to_vec(),
        allowed_transports,
        maximum_up_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        maximum_down_mbps: FUNCTIONAL_SIGNED_RATE_MBPS,
        client_wireguard_public_key: FUNCTIONAL_PEER_PUBLIC_KEY.to_vec(),
        relay_client_wireguard_endpoint: Some(WireguardEndpoint {
            public_key: prepared.relay_client.public_key.to_vec(),
            underlay_ip: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
            listen_port: u32::from(prepared.relay_client.listen_port),
        }),
        relay_exit_wireguard_endpoint: Some(WireguardEndpoint {
            public_key: prepared.relay_exit.public_key.to_vec(),
            underlay_ip: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
            listen_port: u32::from(prepared.relay_exit.listen_port),
        }),
        exit_wireguard_endpoint: Some(exit_endpoint),
        policy_hash: policy_hash.to_vec(),
        created_at_ms,
        expires_at_ms,
        nonce: relay_nonce.to_vec(),
        exit_authorization: signed_authorization,
        relay_peer_id,
        capability_id: capability_id.to_vec(),
        client_session_public_key: client_session_public_key.to_vec(),
        exit_boot_id: exit_boot_id.to_vec(),
        hold_id: hold_id.to_vec(),
        finalize_id: finalize_id.to_vec(),
        control_relay_node_id: control_relay_node_id.to_vec(),
        control_relay_peer_id,
        exit_peer_id,
        signed_client_relay_request_sha256: signed_client_relay_request_sha256.to_vec(),
    };
    let maximum_up_mbps = u32::try_from(relay.maximum_up_mbps).map_err(|_| ProbeError::Protocol)?;
    let maximum_down_mbps =
        u32::try_from(relay.maximum_down_mbps).map_err(|_| ProbeError::Protocol)?;
    if maximum_up_mbps == 0 || maximum_down_mbps == 0 {
        return Err(ProbeError::Protocol);
    }
    let signed_relay_reservation = sign_control_message(
        &relay,
        &relay_key,
        created_at_ms,
        expires_at_ms,
        relay_nonce,
        TimePolicy::default(),
    )
    .map_err(|_| ProbeError::Protocol)?;
    Ok(FunctionalRelayPairAuthority {
        signed_relay_reservation,
        signed_client_relay_request,
        maximum_up_mbps,
        maximum_down_mbps,
    })
}

fn ephemeral_signing_key() -> Result<SigningKey, ProbeError> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ProbeError::Random)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn random_nonzero_32() -> Result<[u8; 32], ProbeError> {
    let mut bytes = [0_u8; 32];
    for _ in 0..64 {
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| ProbeError::Random)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(ProbeError::Random)
}

fn peer_id_from_ed25519(public_key: &[u8; 32]) -> Result<Vec<u8>, ProbeError> {
    let public_key = libp2p_identity::ed25519::PublicKey::try_from_bytes(public_key)
        .map_err(|_| ProbeError::Protocol)?;
    Ok(libp2p_identity::PublicKey::from(public_key)
        .to_peer_id()
        .to_bytes())
}

async fn destroy_functional_cycle(
    stream: &mut UnixStream,
    plan: &FunctionalCyclePlan,
    prepared: &FunctionalPreparedReceipt,
) -> Result<(), ProbeError> {
    if prepared.context_id != plan.ids.context {
        return Err(ProbeError::Correlation);
    }
    let value = DestroyContext {
        route_context_id: prepared.context_id.to_vec(),
        context_handle: prepared.context_handle.to_vec(),
    };
    let present_request = HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: plan.ids.destroy_present_request.to_vec(),
        operation: Some(helper_request::Operation::DestroyContext(value.clone())),
    };
    let present = FunctionalRequestExchange::from_request(&present_request)?;
    let present_outcome =
        exchange_functional(stream, &present, CONTEXT_DESTROYED_DIAGNOSTIC).await?;
    validate_destroyed_outcome(present_outcome, true)?;

    let absent_request = HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: plan.ids.destroy_absent_request.to_vec(),
        operation: Some(helper_request::Operation::DestroyContext(value)),
    };
    let absent = FunctionalRequestExchange::from_request(&absent_request)?;
    let absent_outcome = exchange_functional(stream, &absent, CONTEXT_ABSENT_DIAGNOSTIC).await?;
    validate_destroyed_outcome(absent_outcome, false)
}

async fn destroy_functional_relay_pair(
    stream: &mut UnixStream,
    plan: &FunctionalRelayPairPlan,
    prepared: &FunctionalRelayPairPreparedReceipt,
) -> Result<(), ProbeError> {
    if prepared.context_id != plan.ids.context {
        return Err(ProbeError::Correlation);
    }
    let value = DestroyContext {
        route_context_id: prepared.context_id.to_vec(),
        context_handle: prepared.context_handle.to_vec(),
    };
    let present = FunctionalRequestExchange::from_request(&HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: plan.ids.destroy_present_request.to_vec(),
        operation: Some(helper_request::Operation::DestroyContext(value.clone())),
    })?;
    let present_outcome =
        exchange_functional(stream, &present, CONTEXT_DESTROYED_DIAGNOSTIC).await?;
    validate_destroyed_outcome(present_outcome, true)?;

    let absent = FunctionalRequestExchange::from_request(&HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: plan.ids.destroy_absent_request.to_vec(),
        operation: Some(helper_request::Operation::DestroyContext(value)),
    })?;
    let absent_outcome = exchange_functional(stream, &absent, CONTEXT_ABSENT_DIAGNOSTIC).await?;
    validate_destroyed_outcome(absent_outcome, false)
}

async fn exchange_functional(
    stream: &mut UnixStream,
    exchange: &FunctionalRequestExchange,
    expected_diagnostic: &str,
) -> Result<helper_response::Outcome, ProbeError> {
    exchange_functional_receipt(stream, exchange, expected_diagnostic)
        .await
        .map(|receipt| receipt.outcome)
}

async fn exchange_functional_receipt(
    stream: &mut UnixStream,
    exchange: &FunctionalRequestExchange,
    expected_diagnostic: &str,
) -> Result<FunctionalResponseReceipt, ProbeError> {
    stream
        .write_all(exchange.frame.as_slice())
        .await
        .map_err(|_| ProbeError::Io)?;
    stream.flush().await.map_err(|_| ProbeError::Io)?;
    let response = read_response(stream)
        .await
        .map_err(|_| ProbeError::Protocol)?;
    let canonical_frame =
        Zeroizing::new(encode_response(&response).map_err(|_| ProbeError::Protocol)?);
    let outcome = validate_functional_response(response, exchange, expected_diagnostic)?;
    Ok(FunctionalResponseReceipt {
        outcome,
        canonical_frame,
    })
}

fn validate_functional_response(
    response: HelperResponse,
    exchange: &FunctionalRequestExchange,
    expected_diagnostic: &str,
) -> Result<helper_response::Outcome, ProbeError> {
    if response.protocol_version != HELPER_PROTOCOL_VERSION
        || response.request_id.as_slice() != exchange.request_id
        || response.operation_digest.as_slice() != exchange.operation_digest
    {
        return Err(ProbeError::Correlation);
    }
    if response.diagnostic_code != expected_diagnostic
        || HelperResult::try_from(response.result) != Ok(HelperResult::Ok)
    {
        return Err(ProbeError::UnexpectedResponse);
    }
    response.outcome.ok_or(ProbeError::UnexpectedResponse)
}

fn validate_runtime_outcome(outcome: helper_response::Outcome) -> Result<[u8; 32], ProbeError> {
    let helper_response::Outcome::HelperRuntime(runtime) = outcome else {
        return Err(ProbeError::Correlation);
    };
    let helper_runtime_id: [u8; 32] = runtime
        .helper_runtime_id
        .try_into()
        .map_err(|_| ProbeError::Correlation)?;
    if helper_runtime_id.iter().all(|byte| *byte == 0) {
        return Err(ProbeError::Correlation);
    }
    Ok(helper_runtime_id)
}

fn validate_prepared_outcome(
    outcome: helper_response::Outcome,
    context_id: [u8; 16],
    role: FunctionalLeaseRole,
) -> Result<FunctionalPreparedReceipt, ProbeError> {
    let helper_response::Outcome::PreparedLeaseBatch(PreparedLeaseBatch {
        context_handle,
        leases,
    }) = outcome
    else {
        return Err(ProbeError::Correlation);
    };
    let context_handle: [u8; 32] = context_handle
        .try_into()
        .map_err(|_| ProbeError::Correlation)?;
    let [lease] = leases.as_slice() else {
        return Err(ProbeError::Correlation);
    };
    let lease_handle: [u8; 32] = lease
        .lease_handle
        .as_slice()
        .try_into()
        .map_err(|_| ProbeError::Correlation)?;
    let public_key: [u8; 32] = lease
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| ProbeError::Correlation)?;
    let endpoint = lease
        .public_endpoint
        .as_ref()
        .ok_or(ProbeError::Correlation)?;
    let listen_port = u16::try_from(endpoint.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(ProbeError::Correlation)?;
    if context_id.iter().all(|byte| *byte == 0)
        || context_handle.iter().all(|byte| *byte == 0)
        || lease_handle.iter().all(|byte| *byte == 0)
        || context_handle == lease_handle
        || public_key.iter().all(|byte| *byte == 0)
        || lease.path_id != FUNCTIONAL_PATH_ID
        || lease.role != role.wireguard() as i32
        || endpoint.address.as_slice() != FUNCTIONAL_PUBLIC_IPV4
        || UnderlayEvidence::try_from(lease.underlay_evidence)
            != Ok(UnderlayEvidence::DirectAssigned)
    {
        return Err(ProbeError::Correlation);
    }
    Ok(FunctionalPreparedReceipt {
        context_id,
        context_handle,
        lease_handle,
        public_key,
        listen_port,
    })
}

fn relay_pair_lease_receipt(
    lease: &volparossa_routing::PreparedLease,
    role: WireguardRole,
) -> Result<FunctionalRelayPairLeaseReceipt, ProbeError> {
    let lease_handle: [u8; 32] = lease
        .lease_handle
        .as_slice()
        .try_into()
        .map_err(|_| ProbeError::Correlation)?;
    let public_key: [u8; 32] = lease
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| ProbeError::Correlation)?;
    let endpoint = lease
        .public_endpoint
        .as_ref()
        .ok_or(ProbeError::Correlation)?;
    let listen_port = u16::try_from(endpoint.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(ProbeError::Correlation)?;
    if lease_handle.iter().all(|byte| *byte == 0)
        || public_key.iter().all(|byte| *byte == 0)
        || lease.path_id != FUNCTIONAL_PATH_ID
        || lease.role != role as i32
        || endpoint.address.as_slice() != FUNCTIONAL_PUBLIC_IPV4
        || UnderlayEvidence::try_from(lease.underlay_evidence)
            != Ok(UnderlayEvidence::DirectAssigned)
    {
        return Err(ProbeError::Correlation);
    }
    Ok(FunctionalRelayPairLeaseReceipt {
        lease_handle,
        public_key,
        listen_port,
    })
}

fn validate_relay_pair_prepared_outcome(
    outcome: helper_response::Outcome,
    context_id: [u8; 16],
) -> Result<FunctionalRelayPairPreparedReceipt, ProbeError> {
    let helper_response::Outcome::PreparedLeaseBatch(PreparedLeaseBatch {
        context_handle,
        leases,
    }) = outcome
    else {
        return Err(ProbeError::Correlation);
    };
    let context_handle: [u8; 32] = context_handle
        .try_into()
        .map_err(|_| ProbeError::Correlation)?;
    let [client, exit] = leases.as_slice() else {
        return Err(ProbeError::Correlation);
    };
    let relay_client = relay_pair_lease_receipt(client, WireguardRole::RelayClient)?;
    let relay_exit = relay_pair_lease_receipt(exit, WireguardRole::RelayExit)?;
    if context_id.iter().all(|byte| *byte == 0)
        || context_handle.iter().all(|byte| *byte == 0)
        || relay_client.lease_handle == context_handle
        || relay_exit.lease_handle == context_handle
        || relay_client.lease_handle == relay_exit.lease_handle
        || relay_client.public_key == relay_exit.public_key
        || relay_client.listen_port == relay_exit.listen_port
    {
        return Err(ProbeError::Correlation);
    }
    Ok(FunctionalRelayPairPreparedReceipt {
        context_id,
        context_handle,
        relay_client,
        relay_exit,
    })
}

fn validate_activated_outcome(
    outcome: helper_response::Outcome,
    prepared: &FunctionalPreparedReceipt,
) -> Result<(), ProbeError> {
    let helper_response::Outcome::ActivatedLeaseBatch(ActivatedLeaseBatch {
        context_handle,
        lease_handles,
    }) = outcome
    else {
        return Err(ProbeError::Correlation);
    };
    let [lease_handle] = lease_handles.as_slice() else {
        return Err(ProbeError::Correlation);
    };
    if context_handle.as_slice() != prepared.context_handle
        || lease_handle.as_slice() != prepared.lease_handle
    {
        return Err(ProbeError::Correlation);
    }
    Ok(())
}

fn validate_relay_pair_activated_outcome(
    outcome: helper_response::Outcome,
    prepared: &FunctionalRelayPairPreparedReceipt,
) -> Result<(), ProbeError> {
    let helper_response::Outcome::ActivatedLeaseBatch(ActivatedLeaseBatch {
        context_handle,
        lease_handles,
    }) = outcome
    else {
        return Err(ProbeError::Correlation);
    };
    let [client, exit] = lease_handles.as_slice() else {
        return Err(ProbeError::Correlation);
    };
    if context_handle.as_slice() != prepared.context_handle
        || client.as_slice() != prepared.relay_client.lease_handle
        || exit.as_slice() != prepared.relay_exit.lease_handle
    {
        return Err(ProbeError::Correlation);
    }
    Ok(())
}

fn validate_committed_outcome(
    outcome: &helper_response::Outcome,
    prepared: &FunctionalPreparedReceipt,
) -> Result<(), ProbeError> {
    let helper_response::Outcome::CommittedLeaseBatch(CommittedLeaseBatch {
        context_handle,
        leases,
    }) = outcome
    else {
        return Err(ProbeError::Correlation);
    };
    let [lease] = leases.as_slice() else {
        return Err(ProbeError::Correlation);
    };
    if context_handle.as_slice() != prepared.context_handle
        || lease.lease_handle.as_slice() != prepared.lease_handle
        || lease.latest_handshake_unix == 0
        || lease.received_bytes == 0
        || lease.transmitted_bytes == 0
    {
        return Err(ProbeError::Correlation);
    }
    Ok(())
}

fn validate_committed_retry(
    committed: &helper_response::Outcome,
    retried: &helper_response::Outcome,
    committed_frame: &[u8],
    retried_frame: &[u8],
    prepared: &FunctionalPreparedReceipt,
) -> Result<(), ProbeError> {
    validate_committed_outcome(committed, prepared)?;
    validate_committed_outcome(retried, prepared)?;
    if committed != retried || committed_frame != retried_frame {
        return Err(ProbeError::Correlation);
    }
    Ok(())
}

fn validate_relay_pair_committed_outcome(
    outcome: &helper_response::Outcome,
    prepared: &FunctionalRelayPairPreparedReceipt,
) -> Result<(), ProbeError> {
    let helper_response::Outcome::CommittedLeaseBatch(CommittedLeaseBatch {
        context_handle,
        leases,
    }) = outcome
    else {
        return Err(ProbeError::Correlation);
    };
    let [client, exit] = leases.as_slice() else {
        return Err(ProbeError::Correlation);
    };
    if context_handle.as_slice() != prepared.context_handle
        || client.lease_handle.as_slice() != prepared.relay_client.lease_handle
        || exit.lease_handle.as_slice() != prepared.relay_exit.lease_handle
        || [client, exit].iter().any(|lease| {
            lease.latest_handshake_unix == 0
                || lease.received_bytes == 0
                || lease.transmitted_bytes == 0
        })
    {
        return Err(ProbeError::Correlation);
    }
    Ok(())
}

fn validate_relay_pair_committed_retry(
    committed: &helper_response::Outcome,
    retried: &helper_response::Outcome,
    committed_frame: &[u8],
    retried_frame: &[u8],
    prepared: &FunctionalRelayPairPreparedReceipt,
) -> Result<(), ProbeError> {
    validate_relay_pair_committed_outcome(committed, prepared)?;
    validate_relay_pair_committed_outcome(retried, prepared)?;
    if committed != retried || committed_frame != retried_frame {
        return Err(ProbeError::Correlation);
    }
    Ok(())
}

fn validate_destroyed_outcome(
    outcome: helper_response::Outcome,
    expected_existed: bool,
) -> Result<(), ProbeError> {
    match outcome {
        helper_response::Outcome::DestroyedContext(value) if value.existed == expected_existed => {
            Ok(())
        }
        _ => Err(ProbeError::Correlation),
    }
}

fn validate_functional_reuse(
    first: &FunctionalPreparedReceipt,
    second: &FunctionalPreparedReceipt,
) -> Result<(), ProbeError> {
    if first.context_id == second.context_id
        || first.context_handle == second.context_handle
        || first.lease_handle == second.lease_handle
        || first.public_key == second.public_key
        || first.listen_port == 0
        || second.listen_port == 0
    {
        return Err(ProbeError::Correlation);
    }
    Ok(())
}

fn validate_functional_relay_pair_reuse(
    first: &FunctionalPreparedReceipt,
    second: &FunctionalPreparedReceipt,
    pair: &FunctionalRelayPairPreparedReceipt,
) -> Result<(), ProbeError> {
    let context_ids = [first.context_id, second.context_id, pair.context_id];
    let context_handles = [
        first.context_handle,
        second.context_handle,
        pair.context_handle,
    ];
    let lease_handles = [
        first.lease_handle,
        second.lease_handle,
        pair.relay_client.lease_handle,
        pair.relay_exit.lease_handle,
    ];
    let public_keys = [
        first.public_key,
        second.public_key,
        pair.relay_client.public_key,
        pair.relay_exit.public_key,
    ];
    if !fixed_values_are_distinct(&context_ids)
        || !fixed_values_are_distinct(&context_handles)
        || !fixed_values_are_distinct(&lease_handles)
        || !fixed_values_are_distinct(&public_keys)
        || pair.relay_client.listen_port == 0
        || pair.relay_exit.listen_port == 0
        || pair.relay_client.listen_port == pair.relay_exit.listen_port
    {
        return Err(ProbeError::Correlation);
    }
    Ok(())
}

fn fixed_values_are_distinct<const WIDTH: usize>(values: &[[u8; WIDTH]]) -> bool {
    !values
        .iter()
        .enumerate()
        .any(|(index, value)| values[index + 1..].contains(value))
}

fn publish_fixed_record(record: &str) -> Result<(), ProbeError> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{record}").map_err(|_| ProbeError::Io)?;
    stdout.flush().map_err(|_| ProbeError::Io)
}

fn wait_for_functional_release() -> Result<(), ProbeError> {
    let stdin = io::stdin();
    let mut descriptors = [PollFd::new(stdin.as_fd(), PollFlags::POLLIN)];
    let ready =
        poll(&mut descriptors, FUNCTIONAL_RELEASE_TIMEOUT_MILLIS).map_err(|_| ProbeError::Io)?;
    let events = descriptors[0].revents().ok_or(ProbeError::Io)?;
    if ready != 1
        || !events.contains(PollFlags::POLLIN)
        || events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL)
    {
        return Err(ProbeError::Timeout);
    }
    let mut release = [0_u8; 2];
    let received = read(&stdin, &mut release).map_err(|_| ProbeError::Io)?;
    if received != 1 || release[0] != FUNCTIONAL_RELEASE_BYTE {
        return Err(ProbeError::Protocol);
    }
    Ok(())
}

async fn run_reject_frame_bounds(expected_peer: ExpectedPeer) -> Result<(), ProbeError> {
    let zero_bind = BindExchange::random()?;
    let excessive_bind = BindExchange::random()?;
    timeout(PROBE_TIMEOUT, async move {
        reject_after_authenticated_bind(expected_peer, &zero_bind, &ZERO_LENGTH_FRAME).await?;
        reject_after_authenticated_bind(expected_peer, &excessive_bind, &EXCESSIVE_LENGTH_FRAME)
            .await
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

async fn run_reject_wire_shapes(expected_peer: ExpectedPeer) -> Result<(), ProbeError> {
    let retired_bind = BindExchange::random()?;
    let unknown_bind = BindExchange::random()?;
    let version_bind = BindExchange::random()?;
    let noncanonical_bind = BindExchange::random()?;
    timeout(PROBE_TIMEOUT, async move {
        reject_after_authenticated_bind(expected_peer, &retired_bind, &RETIRED_TAG_24_FRAME)
            .await?;
        reject_after_authenticated_bind(expected_peer, &unknown_bind, &UNKNOWN_TAG_99_FRAME)
            .await?;
        reject_after_authenticated_bind(expected_peer, &version_bind, &VERSION_TWO_FRAME).await?;
        reject_after_authenticated_bind(
            expected_peer,
            &noncanonical_bind,
            &NONCANONICAL_UNKNOWN_OUTER_FIELD_FRAME,
        )
        .await
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

async fn run_expect_unauthorised_peer(expected_peer: ExpectedPeer) -> Result<(), ProbeError> {
    let bind = BindExchange::random()?;
    timeout(PROBE_TIMEOUT, async move {
        let mut stream = connect_trusted_helper(expected_peer).await?;
        match stream.write_all(bind.frame.as_slice()).await {
            Ok(()) => match stream.flush().await {
                Ok(()) => {}
                Err(error) if write_closed(&error) => {}
                Err(_) => return Err(ProbeError::Io),
            },
            Err(error) if write_closed(&error) => {}
            Err(_) => return Err(ProbeError::Io),
        }
        expect_eof_or_reset_without_response(&mut stream).await
    })
    .await
    .map_err(|_| ProbeError::Timeout)?
}

async fn connect_trusted_helper(expected_peer: ExpectedPeer) -> Result<UnixStream, ProbeError> {
    let stream = UnixStream::connect(SOCKET_PATH)
        .await
        .map_err(|_| ProbeError::Io)?;
    let credentials = stream.peer_cred().map_err(|_| ProbeError::Io)?;
    if !peer_identity_matches(
        credentials.uid(),
        credentials.gid(),
        credentials.pid(),
        expected_peer,
    ) {
        return Err(ProbeError::UntrustedServer);
    }
    Ok(stream)
}

fn peer_identity_matches(
    uid: u32,
    gid: u32,
    pid: Option<i32>,
    expected_peer: ExpectedPeer,
) -> bool {
    uid == ROOT_UID && gid == expected_peer.gid && pid == Some(expected_peer.pid)
}

async fn exchange_bind(
    stream: &mut UnixStream,
    exchange: &BindExchange,
) -> Result<[u8; 32], ProbeError> {
    stream
        .write_all(exchange.frame.as_slice())
        .await
        .map_err(|_| ProbeError::Io)?;
    stream.flush().await.map_err(|_| ProbeError::Io)?;
    let response = read_response(stream)
        .await
        .map_err(|_| ProbeError::Protocol)?;
    validate_bind_response(response, exchange)
}

fn validate_bind_response(
    response: HelperResponse,
    exchange: &BindExchange,
) -> Result<[u8; 32], ProbeError> {
    if response.protocol_version != HELPER_PROTOCOL_VERSION
        || response.request_id.as_slice() != exchange.request_id
        || response.operation_digest.as_slice() != exchange.operation_digest
        || response.diagnostic_code != HELPER_RUNTIME_DIAGNOSTIC
        || HelperResult::try_from(response.result) != Ok(HelperResult::Ok)
    {
        return Err(ProbeError::Correlation);
    }
    let Some(helper_response::Outcome::HelperRuntime(runtime)) = response.outcome else {
        return Err(ProbeError::Correlation);
    };
    let runtime_id: [u8; 32] = runtime
        .helper_runtime_id
        .try_into()
        .map_err(|_| ProbeError::Correlation)?;
    if runtime_id.iter().all(|byte| *byte == 0) {
        return Err(ProbeError::Correlation);
    }
    Ok(runtime_id)
}

async fn reject_after_authenticated_bind(
    expected_peer: ExpectedPeer,
    bind: &BindExchange,
    rejected_frame: &[u8],
) -> Result<(), ProbeError> {
    let mut stream = connect_trusted_helper(expected_peer).await?;
    let _runtime_id = exchange_bind(&mut stream, bind).await?;
    stream
        .write_all(rejected_frame)
        .await
        .map_err(|_| ProbeError::Io)?;
    stream.flush().await.map_err(|_| ProbeError::Io)?;
    expect_eof_or_reset_without_response(&mut stream).await
}

async fn expect_eof_or_reset_without_response(stream: &mut UnixStream) -> Result<(), ProbeError> {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => Ok(()),
        Ok(_) => Err(ProbeError::UnexpectedResponse),
        Err(_) => Err(ProbeError::Io),
    }
}

fn write_closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStringExt;

    use volparossa_routing::{
        CommittedLease, DestroyedContext, HelperRuntime, MAX_HELPER_FRAME, PreparedLease,
        decode_request,
    };

    use super::*;

    fn fixed_cycle_ids(seed: u8) -> FunctionalCycleIds {
        FunctionalCycleIds {
            context: [seed; 16],
            bind_request: [seed.wrapping_add(1); 16],
            prepare_request: [seed.wrapping_add(2); 16],
            activate_request: [seed.wrapping_add(3); 16],
            commit_request: [seed.wrapping_add(4); 16],
            destroy_present_request: [seed.wrapping_add(5); 16],
            destroy_absent_request: [seed.wrapping_add(6); 16],
        }
    }

    fn functional_response(
        exchange: &FunctionalRequestExchange,
        diagnostic_code: &str,
        outcome: helper_response::Outcome,
    ) -> HelperResponse {
        HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: exchange.request_id.to_vec(),
            result: HelperResult::Ok as i32,
            diagnostic_code: diagnostic_code.to_owned(),
            operation_digest: exchange.operation_digest.to_vec(),
            outcome: Some(outcome),
        }
    }

    fn valid_prepared_outcome(
        seed: u8,
        listen_port: u32,
        role: FunctionalLeaseRole,
    ) -> helper_response::Outcome {
        helper_response::Outcome::PreparedLeaseBatch(PreparedLeaseBatch {
            context_handle: vec![seed; 32],
            leases: vec![PreparedLease {
                lease_handle: vec![seed.wrapping_add(1); 32],
                path_id: FUNCTIONAL_PATH_ID,
                role: role.wireguard() as i32,
                public_key: vec![seed.wrapping_add(2); 32],
                public_endpoint: Some(PublicUdpEndpoint {
                    address: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
                    port: listen_port,
                }),
                underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
            }],
        })
    }

    fn valid_relay_pair_prepared_outcome(
        seed: u8,
        client_port: u32,
        exit_port: u32,
    ) -> helper_response::Outcome {
        helper_response::Outcome::PreparedLeaseBatch(PreparedLeaseBatch {
            context_handle: vec![seed; 32],
            leases: vec![
                PreparedLease {
                    lease_handle: vec![seed.wrapping_add(1); 32],
                    path_id: FUNCTIONAL_PATH_ID,
                    role: WireguardRole::RelayClient as i32,
                    public_key: vec![seed.wrapping_add(2); 32],
                    public_endpoint: Some(PublicUdpEndpoint {
                        address: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
                        port: client_port,
                    }),
                    underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
                },
                PreparedLease {
                    lease_handle: vec![seed.wrapping_add(3); 32],
                    path_id: FUNCTIONAL_PATH_ID,
                    role: WireguardRole::RelayExit as i32,
                    public_key: vec![seed.wrapping_add(4); 32],
                    public_endpoint: Some(PublicUdpEndpoint {
                        address: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
                        port: exit_port,
                    }),
                    underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
                },
            ],
        })
    }

    fn valid_activated_outcome(prepared: &FunctionalPreparedReceipt) -> helper_response::Outcome {
        helper_response::Outcome::ActivatedLeaseBatch(ActivatedLeaseBatch {
            context_handle: prepared.context_handle.to_vec(),
            lease_handles: vec![prepared.lease_handle.to_vec()],
        })
    }

    fn valid_committed_outcome(prepared: &FunctionalPreparedReceipt) -> helper_response::Outcome {
        helper_response::Outcome::CommittedLeaseBatch(CommittedLeaseBatch {
            context_handle: prepared.context_handle.to_vec(),
            leases: vec![CommittedLease {
                lease_handle: prepared.lease_handle.to_vec(),
                latest_handshake_unix: 1_234,
                received_bytes: 56,
                transmitted_bytes: 78,
            }],
        })
    }

    fn valid_relay_pair_activated_outcome(
        prepared: &FunctionalRelayPairPreparedReceipt,
    ) -> helper_response::Outcome {
        helper_response::Outcome::ActivatedLeaseBatch(ActivatedLeaseBatch {
            context_handle: prepared.context_handle.to_vec(),
            lease_handles: vec![
                prepared.relay_client.lease_handle.to_vec(),
                prepared.relay_exit.lease_handle.to_vec(),
            ],
        })
    }

    fn valid_relay_pair_committed_outcome(
        prepared: &FunctionalRelayPairPreparedReceipt,
    ) -> helper_response::Outcome {
        helper_response::Outcome::CommittedLeaseBatch(CommittedLeaseBatch {
            context_handle: prepared.context_handle.to_vec(),
            leases: vec![
                CommittedLease {
                    lease_handle: prepared.relay_client.lease_handle.to_vec(),
                    latest_handshake_unix: 1_234,
                    received_bytes: 56,
                    transmitted_bytes: 78,
                },
                CommittedLease {
                    lease_handle: prepared.relay_exit.lease_handle.to_vec(),
                    latest_handshake_unix: 1_235,
                    received_bytes: 65,
                    transmitted_bytes: 87,
                },
            ],
        })
    }

    #[test]
    fn parser_accepts_only_exact_mode_pid_and_gid_arguments() {
        let expected_peer = ExpectedPeer {
            pid: 1_234,
            gid: 61_000,
        };
        for (argument, expected) in [
            ("bind-runtime", Mode::BindRuntime),
            ("functional-client-lease", Mode::FunctionalClientLease),
            ("reject-frame-bounds", Mode::RejectFrameBounds),
            ("reject-wire-shapes", Mode::RejectWireShapes),
            ("expect-unauthorised-peer", Mode::ExpectUnauthorisedPeer),
        ] {
            assert_eq!(
                parse_invocation([
                    OsString::from(argument),
                    OsString::from("1234"),
                    OsString::from("61000"),
                ]),
                Some(ProbeInvocation {
                    mode: expected,
                    expected_peer,
                })
            );
        }
        assert_eq!(parse_invocation([]), None);
        assert_eq!(
            parse_invocation([
                OsString::from("unknown"),
                OsString::from("1234"),
                OsString::from("61000"),
            ]),
            None
        );
        assert_eq!(
            parse_invocation([
                OsString::from("bind-runtime"),
                OsString::from("1234"),
                OsString::from("61000"),
                OsString::from("extra"),
            ]),
            None
        );
        assert_eq!(
            parse_invocation([
                OsString::from_vec(vec![0xff]),
                OsString::from("1234"),
                OsString::from("61000"),
            ]),
            None
        );
        for (pid, gid) in [
            ("0", "61000"),
            ("01234", "61000"),
            ("2147483648", "61000"),
            ("1234", "0"),
            ("1234", "061000"),
            ("1234", "4294967295"),
            ("1234", "not-a-gid"),
        ] {
            assert_eq!(
                parse_invocation([
                    OsString::from("bind-runtime"),
                    OsString::from(pid),
                    OsString::from(gid),
                ]),
                None
            );
        }
        assert_eq!(
            parse_invocation([
                OsString::from_vec(vec![b'a'; MAX_MODE_ARGUMENT_BYTES + 1]),
                OsString::from("1234"),
                OsString::from("61000"),
            ]),
            None
        );
        assert_eq!(
            parse_invocation([
                OsString::from("bind-runtime"),
                OsString::from_vec(vec![b'9'; MAX_DECIMAL_U32_BYTES + 1]),
                OsString::from("61000"),
            ]),
            None
        );
    }

    #[test]
    fn success_records_are_fixed_and_contain_no_runtime_fields() {
        assert_eq!(
            Mode::BindRuntime.success_record(),
            "VOLPAROSSA_HELPER_V3_IPC_BIND_RUNTIME_V1=pass"
        );
        assert_eq!(
            Mode::FunctionalClientLease.success_record(),
            "VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=pass"
        );
        assert_eq!(
            FUNCTIONAL_READY_RECORD,
            "VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready"
        );
        assert_eq!(
            FUNCTIONAL_EXIT_READY_RECORD,
            "VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=ready"
        );
        assert_eq!(
            FUNCTIONAL_EXIT_PASS_RECORD,
            "VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=pass"
        );
        assert_eq!(
            FUNCTIONAL_RELAY_PAIR_READY_RECORD,
            "VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=ready"
        );
        assert_eq!(
            FUNCTIONAL_RELAY_PAIR_PASS_RECORD,
            "VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=pass"
        );
        assert_eq!(
            Mode::RejectFrameBounds.success_record(),
            "VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass"
        );
        assert_eq!(
            Mode::RejectWireShapes.success_record(),
            "VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass"
        );
        assert_eq!(
            Mode::ExpectUnauthorisedPeer.success_record(),
            "VOLPAROSSA_HELPER_V3_IPC_UNAUTHORISED_PEER_V1=pass"
        );
        for record in [
            Mode::BindRuntime.success_record(),
            Mode::FunctionalClientLease.success_record(),
            Mode::RejectFrameBounds.success_record(),
            Mode::RejectWireShapes.success_record(),
            Mode::ExpectUnauthorisedPeer.success_record(),
        ] {
            for forbidden in [
                "runtime_id",
                "MainPID",
                "InvocationID",
                SOCKET_PATH,
                "context_handle",
                "lease_handle",
                "public_key",
                "192.31.195.254",
                "1.1.1.1",
                "51820",
            ] {
                assert!(!record.contains(forbidden));
                assert!(!FUNCTIONAL_READY_RECORD.contains(forbidden));
                assert!(!FUNCTIONAL_EXIT_READY_RECORD.contains(forbidden));
                assert!(!FUNCTIONAL_EXIT_PASS_RECORD.contains(forbidden));
                assert!(!FUNCTIONAL_RELAY_PAIR_READY_RECORD.contains(forbidden));
                assert!(!FUNCTIONAL_RELAY_PAIR_PASS_RECORD.contains(forbidden));
            }
        }
        assert_eq!(FUNCTIONAL_RELEASE_BYTE, b'G');
        assert_eq!(
            FUNCTIONAL_PEER_PUBLIC_KEY,
            [
                0x31, 0xd4, 0xab, 0x6a, 0xce, 0xec, 0x96, 0x11, 0x37, 0x91, 0x70, 0x37, 0x93, 0x6e,
                0x60, 0x71, 0x6f, 0xac, 0x57, 0x3a, 0xfe, 0x94, 0xd9, 0xda, 0x84, 0xa8, 0x02, 0x04,
                0x48, 0xdf, 0xc1, 0x12,
            ]
        );
        assert_eq!(FUNCTIONAL_PEER_IPV4, [192, 31, 195, 254]);
        assert_eq!(FUNCTIONAL_PEER_PORT, 10_000);
        assert_eq!(
            FUNCTIONAL_EXIT_PEER_PUBLIC_KEY,
            [
                0x73, 0xb2, 0xd8, 0xb7, 0x6a, 0xa9, 0xb5, 0x36, 0x60, 0x03, 0x2b, 0xc8, 0xf5, 0xd8,
                0xbe, 0xe3, 0xa3, 0xae, 0x4e, 0x3b, 0x3a, 0x7f, 0xd4, 0x9a, 0xde, 0x81, 0xf7, 0x34,
                0x7a, 0x34, 0xaa, 0x68,
            ]
        );
        assert_eq!(FUNCTIONAL_EXIT_PEER_IPV4, [192, 31, 195, 254]);
        assert_eq!(FUNCTIONAL_EXIT_PEER_PORT, 10_001);
    }

    #[test]
    fn functional_failure_records_are_one_bounded_allowlisted_line() {
        let phases = [
            FunctionalPhase::Plan,
            FunctionalPhase::Connect,
            FunctionalPhase::Bind,
            FunctionalPhase::Prepare,
            FunctionalPhase::Activate,
            FunctionalPhase::Shutdown,
            FunctionalPhase::Ready,
            FunctionalPhase::Release,
            FunctionalPhase::Reconnect,
            FunctionalPhase::Commit,
            FunctionalPhase::Destroy,
            FunctionalPhase::SecondCyclePlan,
            FunctionalPhase::SecondCycleBind,
            FunctionalPhase::SecondCyclePrepare,
            FunctionalPhase::SecondCycleActivate,
            FunctionalPhase::Reuse,
            FunctionalPhase::SecondCycleShutdown,
            FunctionalPhase::SecondCycleReady,
            FunctionalPhase::SecondCycleRelease,
            FunctionalPhase::SecondCycleReconnect,
            FunctionalPhase::SecondCycleCommit,
            FunctionalPhase::SecondCycleDestroy,
            FunctionalPhase::RelayPairPlan,
            FunctionalPhase::RelayPairBind,
            FunctionalPhase::RelayPairPrepare,
            FunctionalPhase::RelayPairActivate,
            FunctionalPhase::RelayPairReuse,
            FunctionalPhase::RelayPairShutdown,
            FunctionalPhase::RelayPairReady,
            FunctionalPhase::RelayPairRelease,
            FunctionalPhase::RelayPairReconnect,
            FunctionalPhase::RelayPairCommit,
            FunctionalPhase::RelayPairDestroy,
            FunctionalPhase::FinalShutdown,
        ];
        let errors = [
            ProbeError::Random,
            ProbeError::Protocol,
            ProbeError::Io,
            ProbeError::Timeout,
            ProbeError::UntrustedServer,
            ProbeError::Correlation,
            ProbeError::UnexpectedResponse,
        ];
        for phase in phases {
            for error in errors {
                let mut record = Vec::new();
                FunctionalProbeFailure::new(phase, error)
                    .write_record(&mut record)
                    .expect("in-memory diagnostic record");
                let expected = format!(
                    "{FUNCTIONAL_FAILURE_RECORD_PREFIX}{},{}\n",
                    phase.diagnostic_name(),
                    error.diagnostic_class()
                );
                assert_eq!(record, expected.as_bytes());
                assert!(record.len() <= 128);
                assert_eq!(record.iter().filter(|byte| **byte == b'\n').count(), 1);
                assert!(record[..record.len() - 1].iter().all(u8::is_ascii));
                for forbidden in [
                    "runtime_id",
                    "MainPID",
                    "InvocationID",
                    SOCKET_PATH,
                    "context_handle",
                    "lease_handle",
                    "public_key",
                    "192.31.195.254",
                ] {
                    assert!(!expected.contains(forbidden));
                }
            }
        }
    }

    #[test]
    fn peer_identity_requires_exact_root_main_pid_and_primary_gid() {
        let expected = ExpectedPeer {
            pid: 1_234,
            gid: 61_000,
        };
        assert!(peer_identity_matches(0, 61_000, Some(1_234), expected));
        assert!(!peer_identity_matches(1, 61_000, Some(1_234), expected));
        assert!(!peer_identity_matches(0, 61_001, Some(1_234), expected));
        assert!(!peer_identity_matches(0, 61_000, Some(1_235), expected));
        assert!(!peer_identity_matches(0, 61_000, None, expected));
    }

    #[test]
    fn bind_runtime_query_frame_is_frozen() {
        let exchange = BindExchange::from_request_id([0x36; 16]).expect("fixed Bind query");
        assert_eq!(
            exchange.frame.as_slice(),
            [
                0x00, 0x00, 0x00, 0x17, 0x08, 0x03, 0x12, 0x10, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x9a, 0x02, 0x00,
            ]
        );
        assert_eq!(
            decode_request(&exchange.frame[4..]).expect("canonical Bind query"),
            HelperRequest {
                protocol_version: HELPER_PROTOCOL_VERSION,
                request_id: vec![0x36; 16],
                operation: Some(helper_request::Operation::BindHelperRuntime(
                    BindHelperRuntime {
                        prepare_intent: None,
                    },
                )),
            }
        );
    }

    #[test]
    fn functional_cycle_plan_binds_exact_prepare_and_fresh_lifecycle_ids() {
        let ids = fixed_cycle_ids(0x31);
        let plan = FunctionalCyclePlan::from_ids(ids, 1_000, FunctionalLeaseRole::Client)
            .expect("functional cycle");
        assert_eq!(plan.ids.request_ids(), ids.request_ids());
        assert!(
            ids.request_ids()
                .iter()
                .all(|request_id| request_id.iter().any(|byte| *byte != 0))
        );
        for (position, request_id) in ids.request_ids().iter().enumerate() {
            assert!(!ids.request_ids()[..position].contains(request_id));
        }

        let prepare = decode_request(&plan.prepare.frame[4..]).expect("canonical Prepare");
        let Some(helper_request::Operation::PrepareLeaseBatch(value)) = prepare.operation.as_ref()
        else {
            panic!("PrepareLeaseBatch");
        };
        assert_eq!(prepare.request_id, ids.prepare_request);
        assert_eq!(value.route_context_id, ids.context);
        assert_eq!(value.role, ContextRole::Client as i32);
        assert_eq!(value.mptcp_accepted_addrs, FUNCTIONAL_MPTCP_LIMIT);
        assert_eq!(value.mptcp_subflows, FUNCTIONAL_MPTCP_LIMIT);
        assert_eq!(
            value.leases,
            [LeasePlan {
                path_id: FUNCTIONAL_PATH_ID,
                role: WireguardRole::Client as i32,
            }]
        );
        assert_eq!(value.setup_expires_at_unix, 1_030);
        assert_eq!(value.hard_expires_at_unix, 1_300);
        assert_eq!(
            operation_digest(&prepare).expect("Prepare digest"),
            plan.prepare.operation_digest
        );

        let bind = decode_request(&plan.bind.frame[4..]).expect("canonical Bind intent");
        let Some(helper_request::Operation::BindHelperRuntime(BindHelperRuntime {
            prepare_intent: Some(intent),
        })) = bind.operation.as_ref()
        else {
            panic!("BindHelperRuntime(Some)");
        };
        assert_eq!(bind.request_id, ids.bind_request);
        assert_eq!(intent.route_context_id, value.route_context_id);
        assert_eq!(intent.prepare_request_id, prepare.request_id);
        assert_eq!(
            intent.prepare_operation_digest,
            plan.prepare.operation_digest
        );
        assert_eq!(intent.setup_expires_at_unix, value.setup_expires_at_unix);
        assert_eq!(intent.hard_expires_at_unix, value.hard_expires_at_unix);
        assert_eq!(
            intent.closed_plan.as_ref(),
            Some(&ClosedPreparePlan {
                context_role: value.role,
                leases: value.leases.clone(),
            })
        );

        let prepared = validate_prepared_outcome(
            valid_prepared_outcome(0x62, 41_234, FunctionalLeaseRole::Client),
            ids.context,
            FunctionalLeaseRole::Client,
        )
        .expect("prepared receipt");
        let activate_exchange =
            functional_activation_exchange(&plan, &prepared).expect("activation exchange");
        let activate = decode_request(&activate_exchange.frame[4..]).expect("canonical Activate");
        let Some(helper_request::Operation::ActivateLeaseBatch(value)) =
            activate.operation.as_ref()
        else {
            panic!("ActivateLeaseBatch");
        };
        assert_eq!(activate.request_id, ids.activate_request);
        assert_eq!(value.route_context_id, ids.context);
        assert_eq!(value.context_handle, prepared.context_handle);
        let [activation] = value.leases.as_slice() else {
            panic!("one activation");
        };
        assert_eq!(activation.lease_handle, prepared.lease_handle);
        assert_eq!(activation.path_id, FUNCTIONAL_PATH_ID);
        assert_eq!(activation.role, WireguardRole::Client as i32);
        assert_eq!(activation.peer_public_key, FUNCTIONAL_PEER_PUBLIC_KEY);
        assert_eq!(
            activation.peer_endpoint,
            Some(PublicUdpEndpoint {
                address: FUNCTIONAL_PEER_IPV4.to_vec(),
                port: u32::from(FUNCTIONAL_PEER_PORT),
            })
        );
        assert_eq!(activation.maximum_up_mbps, 0);
        assert_eq!(activation.maximum_down_mbps, 0);
        assert!(!activation.signed_relay_reservation.is_empty());
        let mut replay = volparossa_protocol::ReplayCache::new(8).expect("probe replay verifier");
        let (relay, exit) = volparossa_protocol::verify_relay_reservation(
            &activation.signed_relay_reservation,
            1_000_000,
            TimePolicy::default(),
            &mut replay,
        )
        .expect("cryptographically valid relay grant");
        assert_eq!(relay.message().route_context_id, ids.context);
        assert_eq!(relay.message().path_id, FUNCTIONAL_PATH_ID);
        assert_eq!(
            relay.message().client_wireguard_public_key,
            prepared.public_key
        );
        assert_eq!(
            relay.message().relay_peer_id,
            peer_id_from_ed25519(relay.sender_public_key()).expect("relay Peer ID")
        );
        assert_eq!(
            exit.message().exit_peer_id,
            peer_id_from_ed25519(exit.sender_public_key()).expect("exit Peer ID")
        );
        assert_eq!(replay.len(), 2);
        assert_eq!(
            operation_digest(&activate).expect("Activate digest"),
            activate_exchange.operation_digest
        );

        let commit_exchange =
            functional_commit_exchange(&plan, &prepared).expect("commit exchange");
        let commit = decode_request(&commit_exchange.frame[4..]).expect("canonical Commit");
        let Some(helper_request::Operation::CommitLeaseBatch(value)) = commit.operation.as_ref()
        else {
            panic!("CommitLeaseBatch");
        };
        assert_eq!(commit.request_id, ids.commit_request);
        assert_eq!(value.route_context_id, ids.context);
        assert_eq!(value.context_handle, prepared.context_handle);
        assert_eq!(
            value.leases,
            [LeaseCommit {
                lease_handle: prepared.lease_handle.to_vec(),
                path_id: FUNCTIONAL_PATH_ID,
                role: WireguardRole::Client as i32,
            }]
        );
        assert_eq!(
            operation_digest(&commit).expect("Commit digest"),
            commit_exchange.operation_digest
        );

        let mut duplicate = ids;
        duplicate.destroy_absent_request = duplicate.destroy_present_request;
        assert!(
            FunctionalCyclePlan::from_ids(duplicate, 1_000, FunctionalLeaseRole::Client).is_err()
        );
        let mut duplicate_activate = ids;
        duplicate_activate.activate_request = duplicate_activate.prepare_request;
        assert!(
            FunctionalCyclePlan::from_ids(duplicate_activate, 1_000, FunctionalLeaseRole::Client)
                .is_err()
        );
        let mut duplicate_commit = ids;
        duplicate_commit.commit_request = duplicate_commit.activate_request;
        assert!(
            FunctionalCyclePlan::from_ids(duplicate_commit, 1_000, FunctionalLeaseRole::Client)
                .is_err()
        );
        let mut zero_context = ids;
        zero_context.context = [0; 16];
        assert!(
            FunctionalCyclePlan::from_ids(zero_context, 1_000, FunctionalLeaseRole::Client)
                .is_err()
        );
        assert!(FunctionalCyclePlan::from_ids(ids, u64::MAX, FunctionalLeaseRole::Client).is_err());
    }

    #[test]
    fn functional_exit_cycle_binds_signed_local_and_relay_exit_endpoints() {
        let ids = fixed_cycle_ids(0x37);
        let plan = FunctionalCyclePlan::from_ids(ids, 1_000, FunctionalLeaseRole::Exit)
            .expect("functional Exit cycle");
        let prepare = decode_request(&plan.prepare.frame[4..]).expect("canonical Exit Prepare");
        let Some(helper_request::Operation::PrepareLeaseBatch(prepare_value)) =
            prepare.operation.as_ref()
        else {
            panic!("PrepareLeaseBatch");
        };
        assert_eq!(prepare_value.role, ContextRole::Exit as i32);
        assert_eq!(
            prepare_value.leases,
            [LeasePlan {
                path_id: FUNCTIONAL_PATH_ID,
                role: WireguardRole::Exit as i32,
            }]
        );

        let prepared = validate_prepared_outcome(
            valid_prepared_outcome(0x92, 41_235, FunctionalLeaseRole::Exit),
            ids.context,
            FunctionalLeaseRole::Exit,
        )
        .expect("Exit prepared receipt");
        let activation_exchange =
            functional_activation_exchange(&plan, &prepared).expect("Exit activation exchange");
        let activation_request =
            decode_request(&activation_exchange.frame[4..]).expect("canonical Exit Activate");
        let Some(helper_request::Operation::ActivateLeaseBatch(activation_batch)) =
            activation_request.operation.as_ref()
        else {
            panic!("ActivateLeaseBatch");
        };
        let [activation] = activation_batch.leases.as_slice() else {
            panic!("one Exit activation");
        };
        assert_eq!(activation.role, WireguardRole::Exit as i32);
        assert_eq!(activation.peer_public_key, FUNCTIONAL_EXIT_PEER_PUBLIC_KEY);
        assert_eq!(
            activation.peer_endpoint,
            Some(PublicUdpEndpoint {
                address: FUNCTIONAL_EXIT_PEER_IPV4.to_vec(),
                port: u32::from(FUNCTIONAL_EXIT_PEER_PORT),
            })
        );
        assert_eq!(
            (activation.maximum_up_mbps, activation.maximum_down_mbps),
            (0, 0)
        );

        let mut replay = volparossa_protocol::ReplayCache::new(8).expect("probe replay verifier");
        let (relay, exit) = volparossa_protocol::verify_relay_reservation(
            &activation.signed_relay_reservation,
            1_000_000,
            TimePolicy::default(),
            &mut replay,
        )
        .expect("cryptographically valid Exit relay grant");
        let expected_exit_endpoint = WireguardEndpoint {
            public_key: prepared.public_key.to_vec(),
            underlay_ip: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
            listen_port: u32::from(prepared.listen_port),
        };
        let expected_relay_exit_endpoint = WireguardEndpoint {
            public_key: FUNCTIONAL_EXIT_PEER_PUBLIC_KEY.to_vec(),
            underlay_ip: FUNCTIONAL_EXIT_PEER_IPV4.to_vec(),
            listen_port: u32::from(FUNCTIONAL_EXIT_PEER_PORT),
        };
        assert_eq!(
            relay.message().relay_exit_wireguard_endpoint,
            Some(expected_relay_exit_endpoint)
        );
        assert_eq!(
            relay.message().exit_wireguard_endpoint,
            Some(expected_exit_endpoint.clone())
        );
        assert_eq!(
            exit.message().exit_wireguard_endpoint,
            Some(expected_exit_endpoint)
        );
        assert_eq!(
            relay.message().client_wireguard_public_key,
            FUNCTIONAL_RELAY_EXIT_PUBLIC_KEY
        );

        let commit_exchange =
            functional_commit_exchange(&plan, &prepared).expect("Exit commit exchange");
        let commit = decode_request(&commit_exchange.frame[4..]).expect("canonical Exit Commit");
        let Some(helper_request::Operation::CommitLeaseBatch(commit_batch)) =
            commit.operation.as_ref()
        else {
            panic!("CommitLeaseBatch");
        };
        assert_eq!(
            commit_batch.leases,
            [LeaseCommit {
                lease_handle: prepared.lease_handle.to_vec(),
                path_id: FUNCTIONAL_PATH_ID,
                role: WireguardRole::Exit as i32,
            }]
        );
        assert!(
            validate_prepared_outcome(
                valid_prepared_outcome(0x92, 41_235, FunctionalLeaseRole::Exit),
                ids.context,
                FunctionalLeaseRole::Client,
            )
            .is_err()
        );
    }

    #[test]
    fn functional_relay_pair_cycle_binds_both_legs_to_one_signed_grant() {
        let ids = fixed_cycle_ids(0x3d);
        let plan =
            FunctionalRelayPairPlan::from_ids(ids, 1_000).expect("functional Relay pair cycle");
        let prepare = decode_request(&plan.prepare.frame[4..]).expect("canonical pair Prepare");
        let Some(helper_request::Operation::PrepareLeaseBatch(prepare_batch)) =
            prepare.operation.as_ref()
        else {
            panic!("PrepareLeaseBatch");
        };
        assert_eq!(prepare_batch.role, ContextRole::Relay as i32);
        assert_eq!(
            prepare_batch.leases,
            [
                LeasePlan {
                    path_id: FUNCTIONAL_PATH_ID,
                    role: WireguardRole::RelayClient as i32,
                },
                LeasePlan {
                    path_id: FUNCTIONAL_PATH_ID,
                    role: WireguardRole::RelayExit as i32,
                },
            ]
        );
        let bind = decode_request(&plan.bind.frame[4..]).expect("canonical pair Bind");
        let Some(helper_request::Operation::BindHelperRuntime(BindHelperRuntime {
            prepare_intent: Some(intent),
        })) = bind.operation.as_ref()
        else {
            panic!("BindHelperRuntime(Some)");
        };
        assert_eq!(
            intent.closed_plan.as_ref().map(|value| value.context_role),
            Some(ContextRole::Relay as i32)
        );
        assert_eq!(
            intent.closed_plan.as_ref().map(|value| &value.leases),
            Some(&prepare_batch.leases)
        );

        let prepared = validate_relay_pair_prepared_outcome(
            valid_relay_pair_prepared_outcome(0xa1, 41_236, 41_237),
            ids.context,
        )
        .expect("pair prepared receipt");
        let activation_exchange = functional_relay_pair_activation_exchange(&plan, &prepared)
            .expect("pair activation exchange");
        let activation_request =
            decode_request(&activation_exchange.frame[4..]).expect("canonical pair Activate");
        let Some(helper_request::Operation::ActivateLeaseBatch(activation_batch)) =
            activation_request.operation.as_ref()
        else {
            panic!("ActivateLeaseBatch");
        };
        let [client, exit_activation] = activation_batch.leases.as_slice() else {
            panic!("RelayClient and RelayExit activation");
        };
        assert_eq!(client.role, WireguardRole::RelayClient as i32);
        assert_eq!(exit_activation.role, WireguardRole::RelayExit as i32);
        assert_eq!(client.path_id, FUNCTIONAL_PATH_ID);
        assert_eq!(exit_activation.path_id, FUNCTIONAL_PATH_ID);
        assert_eq!(client.peer_public_key, FUNCTIONAL_PEER_PUBLIC_KEY);
        assert_eq!(
            exit_activation.peer_public_key,
            FUNCTIONAL_EXIT_PEER_PUBLIC_KEY
        );
        assert_eq!(
            client.peer_endpoint,
            Some(PublicUdpEndpoint {
                address: FUNCTIONAL_PEER_IPV4.to_vec(),
                port: u32::from(FUNCTIONAL_PEER_PORT),
            })
        );
        assert_eq!(
            exit_activation.peer_endpoint,
            Some(PublicUdpEndpoint {
                address: FUNCTIONAL_EXIT_PEER_IPV4.to_vec(),
                port: u32::from(FUNCTIONAL_EXIT_PEER_PORT),
            })
        );
        assert!(client.maximum_up_mbps > 0);
        assert!(client.maximum_down_mbps > 0);
        assert_eq!(client.maximum_up_mbps, exit_activation.maximum_up_mbps);
        assert_eq!(client.maximum_down_mbps, exit_activation.maximum_down_mbps);
        assert_eq!(
            client.signed_relay_reservation,
            exit_activation.signed_relay_reservation
        );
        assert!(!client.signed_client_relay_request.is_empty());
        assert!(exit_activation.signed_client_relay_request.is_empty());

        let mut grant_replay =
            volparossa_protocol::ReplayCache::new(8).expect("pair grant replay verifier");
        let (relay, exit) = volparossa_protocol::verify_relay_reservation(
            &client.signed_relay_reservation,
            1_000_000,
            TimePolicy::default(),
            &mut grant_replay,
        )
        .expect("cryptographically valid pair grant");
        let mut request_replay =
            volparossa_protocol::ReplayCache::new(8).expect("pair request replay verifier");
        let request = volparossa_protocol::verify_control_message::<RelayReservationRequest>(
            &client.signed_client_relay_request,
            1_000_000,
            TimePolicy::default(),
            &mut request_replay,
        )
        .expect("cryptographically valid client relay request");
        assert_eq!(
            client.maximum_up_mbps,
            u32::try_from(relay.message().maximum_up_mbps).expect("bounded signed rate")
        );
        assert_eq!(
            client.maximum_down_mbps,
            u32::try_from(relay.message().maximum_down_mbps).expect("bounded signed rate")
        );
        assert_eq!(
            relay.message().signed_client_relay_request_sha256,
            relay_reservation_request_sha256(&client.signed_client_relay_request)
                .expect("canonical request hash")
        );
        assert_eq!(
            request.sender_public_key().as_slice(),
            relay.message().client_session_public_key.as_slice()
        );
        assert_eq!(
            request.message().exit_authorization,
            relay.message().exit_authorization
        );
        assert_eq!(
            request.message().client_wireguard_endpoint,
            Some(WireguardEndpoint {
                public_key: FUNCTIONAL_PEER_PUBLIC_KEY.to_vec(),
                underlay_ip: FUNCTIONAL_PEER_IPV4.to_vec(),
                listen_port: u32::from(FUNCTIONAL_PEER_PORT),
            })
        );
        assert_eq!(
            relay.message().relay_client_wireguard_endpoint,
            Some(WireguardEndpoint {
                public_key: prepared.relay_client.public_key.to_vec(),
                underlay_ip: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
                listen_port: u32::from(prepared.relay_client.listen_port),
            })
        );
        assert_eq!(
            relay.message().relay_exit_wireguard_endpoint,
            Some(WireguardEndpoint {
                public_key: prepared.relay_exit.public_key.to_vec(),
                underlay_ip: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
                listen_port: u32::from(prepared.relay_exit.listen_port),
            })
        );
        assert_eq!(
            exit.message().exit_wireguard_endpoint,
            Some(WireguardEndpoint {
                public_key: FUNCTIONAL_EXIT_PEER_PUBLIC_KEY.to_vec(),
                underlay_ip: FUNCTIONAL_EXIT_PEER_IPV4.to_vec(),
                listen_port: u32::from(FUNCTIONAL_EXIT_PEER_PORT),
            })
        );

        let commit_exchange =
            functional_relay_pair_commit_exchange(&plan, &prepared).expect("pair Commit exchange");
        let commit = decode_request(&commit_exchange.frame[4..]).expect("canonical pair Commit");
        let Some(helper_request::Operation::CommitLeaseBatch(commit_batch)) =
            commit.operation.as_ref()
        else {
            panic!("CommitLeaseBatch");
        };
        assert_eq!(
            commit_batch.leases,
            [
                LeaseCommit {
                    lease_handle: prepared.relay_client.lease_handle.to_vec(),
                    path_id: FUNCTIONAL_PATH_ID,
                    role: WireguardRole::RelayClient as i32,
                },
                LeaseCommit {
                    lease_handle: prepared.relay_exit.lease_handle.to_vec(),
                    path_id: FUNCTIONAL_PATH_ID,
                    role: WireguardRole::RelayExit as i32,
                },
            ]
        );
    }

    #[test]
    fn functional_response_requires_exact_correlation_diagnostic_and_runtime() {
        let plan = FunctionalCyclePlan::from_ids(
            fixed_cycle_ids(0x41),
            1_000,
            FunctionalLeaseRole::Client,
        )
        .expect("functional cycle");
        let outcome = helper_response::Outcome::HelperRuntime(HelperRuntime {
            helper_runtime_id: vec![0xa5; 32],
        });
        let valid = functional_response(&plan.bind, HELPER_RUNTIME_DIAGNOSTIC, outcome);
        let validated =
            validate_functional_response(valid.clone(), &plan.bind, HELPER_RUNTIME_DIAGNOSTIC)
                .expect("correlated response");
        assert_eq!(
            validate_runtime_outcome(validated).expect("runtime"),
            [0xa5; 32]
        );

        let mut substitutions = Vec::new();
        let mut wrong_version = valid.clone();
        wrong_version.protocol_version += 1;
        substitutions.push(wrong_version);
        let mut wrong_request = valid.clone();
        wrong_request.request_id[0] ^= 0xff;
        substitutions.push(wrong_request);
        let mut wrong_digest = valid.clone();
        wrong_digest.operation_digest[0] ^= 0xff;
        substitutions.push(wrong_digest);
        let mut wrong_diagnostic = valid.clone();
        wrong_diagnostic.diagnostic_code = LEASES_PREPARED_DIAGNOSTIC.to_owned();
        assert_eq!(
            validate_functional_response(wrong_diagnostic, &plan.bind, HELPER_RUNTIME_DIAGNOSTIC,),
            Err(ProbeError::UnexpectedResponse)
        );
        let mut wrong_result = valid.clone();
        wrong_result.result = HelperResult::Unavailable as i32;
        assert_eq!(
            validate_functional_response(wrong_result, &plan.bind, HELPER_RUNTIME_DIAGNOSTIC),
            Err(ProbeError::UnexpectedResponse)
        );
        let mut absent_outcome = valid;
        absent_outcome.outcome = None;
        assert_eq!(
            validate_functional_response(absent_outcome, &plan.bind, HELPER_RUNTIME_DIAGNOSTIC),
            Err(ProbeError::UnexpectedResponse)
        );
        for response in substitutions {
            assert!(
                validate_functional_response(response, &plan.bind, HELPER_RUNTIME_DIAGNOSTIC,)
                    .is_err()
            );
        }
        assert!(
            validate_runtime_outcome(helper_response::Outcome::HelperRuntime(HelperRuntime {
                helper_runtime_id: vec![0; 32],
            }))
            .is_err()
        );
        assert!(
            validate_runtime_outcome(valid_prepared_outcome(
                0x51,
                41_234,
                FunctionalLeaseRole::Client,
            ))
            .is_err()
        );
    }

    #[test]
    fn functional_prepared_validation_rejects_every_endpoint_substitution() {
        let context_id = [0x61; 16];
        let valid = valid_prepared_outcome(0x62, 41_234, FunctionalLeaseRole::Client);
        let receipt =
            validate_prepared_outcome(valid.clone(), context_id, FunctionalLeaseRole::Client)
                .expect("prepared receipt");
        assert_eq!(receipt.context_id, context_id);
        assert_eq!(receipt.context_handle, [0x62; 32]);
        assert_eq!(receipt.lease_handle, [0x63; 32]);
        assert_eq!(receipt.public_key, [0x64; 32]);
        assert_eq!(receipt.listen_port, 41_234);

        let mut substitutions = Vec::new();
        let mut zero_context_handle = valid.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut zero_context_handle else {
            unreachable!();
        };
        batch.context_handle.fill(0);
        substitutions.push(zero_context_handle);

        let mut equal_handles = valid.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut equal_handles else {
            unreachable!();
        };
        batch.leases[0].lease_handle = batch.context_handle.clone();
        substitutions.push(equal_handles);

        let mut wrong_path = valid.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut wrong_path else {
            unreachable!();
        };
        batch.leases[0].path_id += 1;
        substitutions.push(wrong_path);

        let mut wrong_role = valid.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut wrong_role else {
            unreachable!();
        };
        batch.leases[0].role = WireguardRole::Exit as i32;
        substitutions.push(wrong_role);

        let mut zero_key = valid.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut zero_key else {
            unreachable!();
        };
        batch.leases[0].public_key.fill(0);
        substitutions.push(zero_key);

        let mut wrong_address = valid.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut wrong_address else {
            unreachable!();
        };
        batch.leases[0]
            .public_endpoint
            .as_mut()
            .expect("endpoint")
            .address[3] ^= 1;
        substitutions.push(wrong_address);

        let mut zero_port = valid.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut zero_port else {
            unreachable!();
        };
        batch.leases[0]
            .public_endpoint
            .as_mut()
            .expect("endpoint")
            .port = 0;
        substitutions.push(zero_port);

        let mut excessive_port = valid.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut excessive_port else {
            unreachable!();
        };
        batch.leases[0]
            .public_endpoint
            .as_mut()
            .expect("endpoint")
            .port = u32::from(u16::MAX) + 1;
        substitutions.push(excessive_port);

        let mut wrong_evidence = valid;
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut wrong_evidence else {
            unreachable!();
        };
        batch.leases[0].underlay_evidence = UnderlayEvidence::Unspecified as i32;
        substitutions.push(wrong_evidence);

        for outcome in substitutions {
            assert!(
                validate_prepared_outcome(outcome, context_id, FunctionalLeaseRole::Client)
                    .is_err()
            );
        }
        assert!(
            validate_prepared_outcome(
                valid_prepared_outcome(0x62, 41_234, FunctionalLeaseRole::Client),
                [0; 16],
                FunctionalLeaseRole::Client,
            )
            .is_err()
        );
    }

    #[test]
    fn functional_activation_requires_exact_prepared_lineage_and_receipt() {
        let ids = fixed_cycle_ids(0x69);
        let plan = FunctionalCyclePlan::from_ids(ids, 1_000, FunctionalLeaseRole::Client)
            .expect("functional cycle");
        let prepared = validate_prepared_outcome(
            valid_prepared_outcome(0x6a, 41_234, FunctionalLeaseRole::Client),
            ids.context,
            FunctionalLeaseRole::Client,
        )
        .expect("prepared receipt");
        let exchange =
            functional_activation_exchange(&plan, &prepared).expect("activation exchange");
        let activated = valid_activated_outcome(&prepared);
        let response =
            functional_response(&exchange, LEASES_ACTIVATED_DIAGNOSTIC, activated.clone());
        let outcome =
            validate_functional_response(response, &exchange, LEASES_ACTIVATED_DIAGNOSTIC)
                .expect("correlated activation response");
        validate_activated_outcome(outcome, &prepared).expect("exact activation receipt");

        let mut wrong_context = prepared.clone();
        wrong_context.context_id[0] ^= 1;
        assert!(functional_activation_exchange(&plan, &wrong_context).is_err());
        let mut self_peer = prepared.clone();
        self_peer.public_key = FUNCTIONAL_PEER_PUBLIC_KEY;
        assert!(functional_activation_exchange(&plan, &self_peer).is_err());

        let mut substitutions = Vec::new();
        let mut wrong_context_handle = activated.clone();
        let helper_response::Outcome::ActivatedLeaseBatch(batch) = &mut wrong_context_handle else {
            unreachable!();
        };
        batch.context_handle[0] ^= 1;
        substitutions.push(wrong_context_handle);
        let mut wrong_lease_handle = activated.clone();
        let helper_response::Outcome::ActivatedLeaseBatch(batch) = &mut wrong_lease_handle else {
            unreachable!();
        };
        batch.lease_handles[0][0] ^= 1;
        substitutions.push(wrong_lease_handle);
        let mut absent_lease = activated.clone();
        let helper_response::Outcome::ActivatedLeaseBatch(batch) = &mut absent_lease else {
            unreachable!();
        };
        batch.lease_handles.clear();
        substitutions.push(absent_lease);
        let mut extra_lease = activated;
        let helper_response::Outcome::ActivatedLeaseBatch(batch) = &mut extra_lease else {
            unreachable!();
        };
        batch.lease_handles.push(vec![0x7f; 32]);
        substitutions.push(extra_lease);
        substitutions.push(valid_prepared_outcome(
            0x6a,
            41_234,
            FunctionalLeaseRole::Client,
        ));
        for outcome in substitutions {
            assert!(validate_activated_outcome(outcome, &prepared).is_err());
        }
    }

    #[test]
    fn functional_relay_pair_receipts_fail_closed_on_partial_or_reordered_state() {
        let context_id = [0xb1; 16];
        let valid_prepared = valid_relay_pair_prepared_outcome(0xb2, 41_236, 41_237);
        let prepared = validate_relay_pair_prepared_outcome(valid_prepared.clone(), context_id)
            .expect("pair prepared receipt");

        let mut prepared_substitutions = Vec::new();
        let mut reordered = valid_prepared.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut reordered else {
            unreachable!();
        };
        batch.leases.swap(0, 1);
        prepared_substitutions.push(reordered);
        let mut duplicate_handle = valid_prepared.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut duplicate_handle else {
            unreachable!();
        };
        batch.leases[1].lease_handle = batch.leases[0].lease_handle.clone();
        prepared_substitutions.push(duplicate_handle);
        let mut duplicate_key = valid_prepared.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut duplicate_key else {
            unreachable!();
        };
        batch.leases[1].public_key = batch.leases[0].public_key.clone();
        prepared_substitutions.push(duplicate_key);
        let mut duplicate_port = valid_prepared.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut duplicate_port else {
            unreachable!();
        };
        let client_port = batch.leases[0]
            .public_endpoint
            .as_ref()
            .expect("client endpoint")
            .port;
        batch.leases[1]
            .public_endpoint
            .as_mut()
            .expect("exit endpoint")
            .port = client_port;
        prepared_substitutions.push(duplicate_port);
        let mut absent = valid_prepared.clone();
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut absent else {
            unreachable!();
        };
        batch.leases.pop();
        prepared_substitutions.push(absent);
        let mut extra = valid_prepared;
        let helper_response::Outcome::PreparedLeaseBatch(batch) = &mut extra else {
            unreachable!();
        };
        batch.leases.push(batch.leases[1].clone());
        prepared_substitutions.push(extra);
        for outcome in prepared_substitutions {
            assert!(validate_relay_pair_prepared_outcome(outcome, context_id).is_err());
        }

        let activated = valid_relay_pair_activated_outcome(&prepared);
        validate_relay_pair_activated_outcome(activated.clone(), &prepared)
            .expect("exact pair Activated receipt");
        let mut reordered_activation = activated.clone();
        let helper_response::Outcome::ActivatedLeaseBatch(batch) = &mut reordered_activation else {
            unreachable!();
        };
        batch.lease_handles.swap(0, 1);
        assert!(validate_relay_pair_activated_outcome(reordered_activation, &prepared).is_err());
        let mut partial_activation = activated;
        let helper_response::Outcome::ActivatedLeaseBatch(batch) = &mut partial_activation else {
            unreachable!();
        };
        batch.lease_handles.pop();
        assert!(validate_relay_pair_activated_outcome(partial_activation, &prepared).is_err());

        let committed = valid_relay_pair_committed_outcome(&prepared);
        let frame = [0_u8, 0, 0, 1, 0x55];
        validate_relay_pair_committed_retry(&committed, &committed, &frame, &frame, &prepared)
            .expect("byte-identical pair Commit retry");
        let mut partial_commit = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut partial_commit else {
            unreachable!();
        };
        batch.leases.pop();
        assert!(validate_relay_pair_committed_outcome(&partial_commit, &prepared).is_err());
        let mut zero_second_counter = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut zero_second_counter else {
            unreachable!();
        };
        batch.leases[1].received_bytes = 0;
        assert!(validate_relay_pair_committed_outcome(&zero_second_counter, &prepared).is_err());
        let mut reordered_commit = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut reordered_commit else {
            unreachable!();
        };
        batch.leases.swap(0, 1);
        assert!(validate_relay_pair_committed_outcome(&reordered_commit, &prepared).is_err());
        let mut changed_retry = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut changed_retry else {
            unreachable!();
        };
        batch.leases[1].transmitted_bytes += 1;
        assert!(
            validate_relay_pair_committed_retry(
                &committed,
                &changed_retry,
                &frame,
                &frame,
                &prepared,
            )
            .is_err()
        );
    }

    #[test]
    fn functional_commit_requires_exact_prepared_lineage_receipt_and_identical_retry() {
        let ids = fixed_cycle_ids(0x79);
        let plan = FunctionalCyclePlan::from_ids(ids, 1_000, FunctionalLeaseRole::Client)
            .expect("functional cycle");
        let prepared = validate_prepared_outcome(
            valid_prepared_outcome(0x7a, 41_234, FunctionalLeaseRole::Client),
            ids.context,
            FunctionalLeaseRole::Client,
        )
        .expect("prepared receipt");
        let exchange = functional_commit_exchange(&plan, &prepared).expect("commit exchange");
        let request = decode_request(&exchange.frame[4..]).expect("canonical Commit");
        assert_eq!(request.request_id, ids.commit_request);
        assert!(matches!(
            request.operation,
            Some(helper_request::Operation::CommitLeaseBatch(_))
        ));

        let committed = valid_committed_outcome(&prepared);
        validate_committed_outcome(&committed, &prepared).expect("exact committed receipt");
        let committed_frame = [0_u8, 0, 0, 1, 0x7f];
        validate_committed_retry(
            &committed,
            &committed,
            &committed_frame,
            &committed_frame,
            &prepared,
        )
        .expect("identical committed retry");
        let changed_frame = [0_u8, 0, 0, 1, 0x7e];
        assert!(
            validate_committed_retry(
                &committed,
                &committed,
                &committed_frame,
                &changed_frame,
                &prepared,
            )
            .is_err()
        );

        let mut wrong_context = prepared.clone();
        wrong_context.context_id[0] ^= 1;
        assert!(functional_commit_exchange(&plan, &wrong_context).is_err());

        let mut substitutions = Vec::new();
        let mut wrong_context_handle = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut wrong_context_handle else {
            unreachable!();
        };
        batch.context_handle[0] ^= 1;
        substitutions.push(wrong_context_handle);

        let mut wrong_lease_handle = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut wrong_lease_handle else {
            unreachable!();
        };
        batch.leases[0].lease_handle[0] ^= 1;
        substitutions.push(wrong_lease_handle);

        let mut zero_handshake = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut zero_handshake else {
            unreachable!();
        };
        batch.leases[0].latest_handshake_unix = 0;
        substitutions.push(zero_handshake);

        let mut zero_received = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut zero_received else {
            unreachable!();
        };
        batch.leases[0].received_bytes = 0;
        substitutions.push(zero_received);

        let mut zero_transmitted = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut zero_transmitted else {
            unreachable!();
        };
        batch.leases[0].transmitted_bytes = 0;
        substitutions.push(zero_transmitted);

        let mut absent_lease = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut absent_lease else {
            unreachable!();
        };
        batch.leases.clear();
        substitutions.push(absent_lease);

        let mut extra_lease = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut extra_lease else {
            unreachable!();
        };
        batch.leases.push(CommittedLease {
            lease_handle: vec![0x7f; 32],
            latest_handshake_unix: 1_234,
            received_bytes: 1,
            transmitted_bytes: 1,
        });
        substitutions.push(extra_lease);
        substitutions.push(valid_prepared_outcome(
            0x7a,
            41_234,
            FunctionalLeaseRole::Client,
        ));

        for outcome in substitutions {
            assert!(validate_committed_outcome(&outcome, &prepared).is_err());
        }

        let mut changed_retry = committed.clone();
        let helper_response::Outcome::CommittedLeaseBatch(batch) = &mut changed_retry else {
            unreachable!();
        };
        batch.leases[0].received_bytes += 1;
        validate_committed_outcome(&changed_retry, &prepared)
            .expect("individually valid changed receipt");
        assert!(
            validate_committed_retry(
                &committed,
                &changed_retry,
                &committed_frame,
                &committed_frame,
                &prepared,
            )
            .is_err()
        );
    }

    #[test]
    fn functional_destroy_and_reuse_validation_are_exact() {
        let destroyed =
            |existed| helper_response::Outcome::DestroyedContext(DestroyedContext { existed });
        assert!(validate_destroyed_outcome(destroyed(true), true).is_ok());
        assert!(validate_destroyed_outcome(destroyed(false), false).is_ok());
        assert!(validate_destroyed_outcome(destroyed(true), false).is_err());
        assert!(
            validate_destroyed_outcome(
                valid_prepared_outcome(0x71, 41_234, FunctionalLeaseRole::Client),
                true,
            )
            .is_err()
        );

        let first = validate_prepared_outcome(
            valid_prepared_outcome(0x72, 41_234, FunctionalLeaseRole::Client),
            [0x11; 16],
            FunctionalLeaseRole::Client,
        )
        .expect("first receipt");
        let second = validate_prepared_outcome(
            valid_prepared_outcome(0x82, 41_234, FunctionalLeaseRole::Exit),
            [0x12; 16],
            FunctionalLeaseRole::Exit,
        )
        .expect("second receipt");
        assert!(validate_functional_reuse(&first, &second).is_ok());

        let mut same_context = second.clone();
        same_context.context_id = first.context_id;
        assert!(validate_functional_reuse(&first, &same_context).is_err());
        let mut same_context_handle = second.clone();
        same_context_handle.context_handle = first.context_handle;
        assert!(validate_functional_reuse(&first, &same_context_handle).is_err());
        let mut same_lease_handle = second.clone();
        same_lease_handle.lease_handle = first.lease_handle;
        assert!(validate_functional_reuse(&first, &same_lease_handle).is_err());
        let mut same_public_key = second;
        same_public_key.public_key = first.public_key;
        assert!(validate_functional_reuse(&first, &same_public_key).is_err());
    }

    #[test]
    fn raw_rejection_wires_and_bounds_are_frozen() {
        assert_eq!(ZERO_LENGTH_FRAME, [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(EXCESSIVE_LENGTH_FRAME, [0x00, 0x02, 0x00, 0x01]);
        assert_eq!(
            u32::try_from(MAX_HELPER_FRAME + 1)
                .expect("bounded helper frame")
                .to_be_bytes(),
            EXCESSIVE_LENGTH_FRAME
        );
        assert_eq!(&RETIRED_TAG_24_FRAME[24..], [0xc2, 0x01, 0x00]);
        assert_eq!(&UNKNOWN_TAG_99_FRAME[24..], [0x9a, 0x06, 0x00]);
        assert_eq!(&VERSION_TWO_FRAME[4..6], [0x08, 0x02]);
        assert_eq!(&NONCANONICAL_UNKNOWN_OUTER_FIELD_FRAME[27..], [0x20, 0x01]);
        for frame in [
            RETIRED_TAG_24_FRAME.as_slice(),
            UNKNOWN_TAG_99_FRAME.as_slice(),
            VERSION_TWO_FRAME.as_slice(),
            NONCANONICAL_UNKNOWN_OUTER_FIELD_FRAME.as_slice(),
        ] {
            let advertised = usize::try_from(u32::from_be_bytes(
                frame[..4].try_into().expect("four-byte frame prefix"),
            ))
            .expect("bounded frame length");
            assert_eq!(advertised, frame.len() - 4);
            assert!(decode_request(&frame[4..]).is_err());
        }
    }

    #[test]
    fn bind_response_validation_rejects_every_correlation_substitution() {
        let exchange = BindExchange::from_request_id([0x36; 16]).expect("fixed Bind query");
        let valid = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: exchange.request_id.to_vec(),
            result: HelperResult::Ok as i32,
            diagnostic_code: HELPER_RUNTIME_DIAGNOSTIC.to_owned(),
            operation_digest: exchange.operation_digest.to_vec(),
            outcome: Some(helper_response::Outcome::HelperRuntime(HelperRuntime {
                helper_runtime_id: vec![0xa5; 32],
            })),
        };
        assert_eq!(
            validate_bind_response(valid.clone(), &exchange).expect("valid response"),
            [0xa5; 32]
        );

        let mut substitutions = Vec::new();
        let mut wrong_version = valid.clone();
        wrong_version.protocol_version += 1;
        substitutions.push(wrong_version);
        let mut wrong_request = valid.clone();
        wrong_request.request_id[0] ^= 0xff;
        substitutions.push(wrong_request);
        let mut wrong_digest = valid.clone();
        wrong_digest.operation_digest[0] ^= 0xff;
        substitutions.push(wrong_digest);
        let mut wrong_diagnostic = valid.clone();
        wrong_diagnostic.diagnostic_code = "OTHER".to_owned();
        substitutions.push(wrong_diagnostic);
        let mut wrong_result = valid.clone();
        wrong_result.result = i32::MAX;
        substitutions.push(wrong_result);
        let mut absent_outcome = valid.clone();
        absent_outcome.outcome = None;
        substitutions.push(absent_outcome);
        let mut zero_runtime = valid.clone();
        zero_runtime.outcome = Some(helper_response::Outcome::HelperRuntime(HelperRuntime {
            helper_runtime_id: vec![0; 32],
        }));
        substitutions.push(zero_runtime);
        let mut short_runtime = valid;
        short_runtime.outcome = Some(helper_response::Outcome::HelperRuntime(HelperRuntime {
            helper_runtime_id: vec![0xa5; 31],
        }));
        substitutions.push(short_runtime);

        for response in substitutions {
            assert!(validate_bind_response(response, &exchange).is_err());
        }
    }
}
