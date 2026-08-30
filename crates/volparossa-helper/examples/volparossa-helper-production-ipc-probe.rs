//! Narrow live probe for the packaged helper-v3 production IPC boundary.
//!
//! This example accepts no socket path, request bytes or privileged operation from its caller. It
//! requires one exact expected production PID/GID pair and connects only to the fixed production
//! socket. Its closed modes exercise read-only runtime binding, bounded fail-closed framing, or two
//! exact functional Client-lease cycles through Activate. The functional mode publishes one fixed
//! READY record only after the first exact Activated receipt, accepts one fixed release byte on
//! standard input, and never prints handles or endpoint material.

use std::{
    cell::Cell,
    ffi::OsString,
    io::{self, Write as _},
    os::{fd::AsFd as _, unix::ffi::OsStrExt},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
use volparossa_routing::{
    ActivateLeaseBatch, ActivatedLeaseBatch, BindHelperRuntime, ClosedPreparePlan, ContextRole,
    DestroyContext, HELPER_PROTOCOL_VERSION, HelperRequest, HelperResponse, HelperResult,
    LeaseActivation, LeasePlan, PrepareIntent, PrepareLeaseBatch, PreparedLeaseBatch,
    PublicUdpEndpoint, UnderlayEvidence, WireguardRole, encode_request, helper_request,
    helper_response, operation_digest, read_response,
};
use zeroize::Zeroizing;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const FUNCTIONAL_PROBE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_MODE_ARGUMENT_BYTES: usize = "expect-unauthorised-peer".len();
const MAX_DECIMAL_U32_BYTES: usize = 10;
const ROOT_UID: u32 = 0;
const HELPER_RUNTIME_DIAGNOSTIC: &str = "HELPER_RUNTIME";
const LEASES_PREPARED_DIAGNOSTIC: &str = "LEASES_PREPARED";
const LEASES_ACTIVATED_DIAGNOSTIC: &str = "LEASES_ACTIVATED";
const CONTEXT_DESTROYED_DIAGNOSTIC: &str = "CONTEXT_DESTROYED";
const CONTEXT_ABSENT_DIAGNOSTIC: &str = "CONTEXT_ABSENT";
const FAILURE_RECORD: &str = "VOLPAROSSA_HELPER_V3_IPC_PROBE_V1=fail";
const USAGE_RECORD: &str = "VOLPAROSSA_HELPER_V3_IPC_PROBE_V1=usage";
const FUNCTIONAL_SETUP_TTL_SECONDS: u64 = 30;
const FUNCTIONAL_HARD_TTL_SECONDS: u64 = 300;
const FUNCTIONAL_MPTCP_LIMIT: u32 = 4;
const FUNCTIONAL_PATH_ID: u32 = 1;
const FUNCTIONAL_PUBLIC_IPV4: [u8; 4] = [192, 31, 195, 254];
// This exact public peer tuple is shared with the public helper-protocol Activate fixture. It is
// intentionally neither a local helper key nor the helper's prepared public endpoint.
const FUNCTIONAL_PEER_PUBLIC_KEY: [u8; 32] = [8; 32];
const FUNCTIONAL_PEER_IPV4: [u8; 4] = [1, 1, 1, 1];
const FUNCTIONAL_PEER_PORT: u16 = 51_820;
const FUNCTIONAL_RELEASE_TIMEOUT_MILLIS: u16 = 10_000;
const FUNCTIONAL_RELEASE_BYTE: u8 = b'G';
const FUNCTIONAL_READY_RECORD: &str = "VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready";
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
    Destroy,
    SecondCyclePlan,
    SecondCycleBind,
    SecondCyclePrepare,
    SecondCycleActivate,
    Reuse,
    SecondCycleDestroy,
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
            Self::Destroy => "destroy",
            Self::SecondCyclePlan => "second-cycle-plan",
            Self::SecondCycleBind => "second-cycle-bind",
            Self::SecondCyclePrepare => "second-cycle-prepare",
            Self::SecondCycleActivate => "second-cycle-activate",
            Self::Reuse => "reuse",
            Self::SecondCycleDestroy => "second-cycle-destroy",
            Self::FinalShutdown => "final-shutdown",
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
    destroy_present_request: [u8; 16],
    destroy_absent_request: [u8; 16],
}

impl FunctionalCycleIds {
    const fn request_ids(self) -> [[u8; 16]; 5] {
        [
            self.bind_request,
            self.prepare_request,
            self.activate_request,
            self.destroy_present_request,
            self.destroy_absent_request,
        ]
    }
}

struct FunctionalCyclePlan {
    ids: FunctionalCycleIds,
    bind: FunctionalRequestExchange,
    prepare: FunctionalRequestExchange,
}

impl FunctionalCyclePlan {
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
        let destroy_present_request_id = random_unique_id(&request_ids)?;
        request_ids.push(destroy_present_request_id);
        let destroy_absent_request_id = random_unique_id(&request_ids)?;
        Self::from_ids(
            FunctionalCycleIds {
                context: context_id,
                bind_request: bind_request_id,
                prepare_request: prepare_request_id,
                activate_request: activate_request_id,
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
        let leases = vec![LeasePlan {
            path_id: FUNCTIONAL_PATH_ID,
            role: WireguardRole::Client as i32,
        }];
        let prepare_value = PrepareLeaseBatch {
            route_context_id: ids.context.to_vec(),
            role: ContextRole::Client as i32,
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
                            context_role: ContextRole::Client as i32,
                            leases,
                        }),
                    }),
                },
            )),
        };
        let bind = FunctionalRequestExchange::from_request(&bind_request)?;
        Ok(Self { ids, bind, prepare })
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

async fn run_functional_client_lease(
    expected_peer: ExpectedPeer,
) -> Result<(), FunctionalProbeFailure> {
    let phase = Cell::new(FunctionalPhase::Connect);
    timeout(FUNCTIONAL_PROBE_TIMEOUT, async {
        let mut prepare_stream = connect_trusted_helper(expected_peer)
            .await
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        phase.set(FunctionalPhase::Plan);
        let first_plan = FunctionalCyclePlan::random(&[], &[])
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
            FunctionalPhase::Activate,
        )
        .await?;
        phase.set(FunctionalPhase::Shutdown);
        prepare_stream
            .shutdown()
            .await
            .map_err(|_| FunctionalProbeFailure::new(phase.get(), ProbeError::Io))?;
        drop(prepare_stream);

        phase.set(FunctionalPhase::Ready);
        publish_functional_ready()
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        phase.set(FunctionalPhase::Release);
        wait_for_functional_release()
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        phase.set(FunctionalPhase::Reconnect);
        let mut stream = connect_trusted_helper(expected_peer)
            .await
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        phase.set(FunctionalPhase::Destroy);
        destroy_functional_cycle(&mut stream, &first_plan, &first.prepared)
            .await
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;

        phase.set(FunctionalPhase::SecondCyclePlan);
        let second_plan = FunctionalCyclePlan::random(&[first_context_id], &first_request_ids)
            .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
        let second = activate_functional_cycle(
            &mut stream,
            &second_plan,
            &phase,
            FunctionalPhase::SecondCycleBind,
            FunctionalPhase::SecondCyclePrepare,
            FunctionalPhase::SecondCycleActivate,
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
        phase.set(FunctionalPhase::SecondCycleDestroy);
        destroy_functional_cycle(&mut stream, &second_plan, &second.prepared)
            .await
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
    let prepared = validate_prepared_outcome(prepared_outcome, plan.ids.context)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    phase.set(activate_phase);
    let activate = functional_activation_exchange(plan, &prepared)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    let activated_outcome = exchange_functional(stream, &activate, LEASES_ACTIVATED_DIAGNOSTIC)
        .await
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    validate_activated_outcome(activated_outcome, &prepared)
        .map_err(|error| FunctionalProbeFailure::new(phase.get(), error))?;
    Ok(FunctionalCycleResult {
        helper_runtime_id,
        prepared,
    })
}

fn functional_activation_exchange(
    plan: &FunctionalCyclePlan,
    prepared: &FunctionalPreparedReceipt,
) -> Result<FunctionalRequestExchange, ProbeError> {
    if prepared.context_id != plan.ids.context
        || prepared.public_key == FUNCTIONAL_PEER_PUBLIC_KEY
        || (FUNCTIONAL_PUBLIC_IPV4, prepared.listen_port)
            == (FUNCTIONAL_PEER_IPV4, FUNCTIONAL_PEER_PORT)
    {
        return Err(ProbeError::Correlation);
    }
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
                    role: WireguardRole::Client as i32,
                    peer_public_key: FUNCTIONAL_PEER_PUBLIC_KEY.to_vec(),
                    peer_endpoint: Some(PublicUdpEndpoint {
                        address: FUNCTIONAL_PEER_IPV4.to_vec(),
                        port: u32::from(FUNCTIONAL_PEER_PORT),
                    }),
                    maximum_up_mbps: 0,
                    maximum_down_mbps: 0,
                    signed_relay_reservation: Vec::new(),
                }],
            },
        )),
    })
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

async fn exchange_functional(
    stream: &mut UnixStream,
    exchange: &FunctionalRequestExchange,
    expected_diagnostic: &str,
) -> Result<helper_response::Outcome, ProbeError> {
    stream
        .write_all(exchange.frame.as_slice())
        .await
        .map_err(|_| ProbeError::Io)?;
    stream.flush().await.map_err(|_| ProbeError::Io)?;
    let response = read_response(stream)
        .await
        .map_err(|_| ProbeError::Protocol)?;
    validate_functional_response(response, exchange, expected_diagnostic)
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
        || lease.role != WireguardRole::Client as i32
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

fn publish_functional_ready() -> Result<(), ProbeError> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{FUNCTIONAL_READY_RECORD}").map_err(|_| ProbeError::Io)?;
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
        DestroyedContext, HelperRuntime, MAX_HELPER_FRAME, PreparedLease, decode_request,
    };

    use super::*;

    fn fixed_cycle_ids(seed: u8) -> FunctionalCycleIds {
        FunctionalCycleIds {
            context: [seed; 16],
            bind_request: [seed.wrapping_add(1); 16],
            prepare_request: [seed.wrapping_add(2); 16],
            activate_request: [seed.wrapping_add(3); 16],
            destroy_present_request: [seed.wrapping_add(4); 16],
            destroy_absent_request: [seed.wrapping_add(5); 16],
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

    fn valid_prepared_outcome(seed: u8, listen_port: u32) -> helper_response::Outcome {
        helper_response::Outcome::PreparedLeaseBatch(PreparedLeaseBatch {
            context_handle: vec![seed; 32],
            leases: vec![PreparedLease {
                lease_handle: vec![seed.wrapping_add(1); 32],
                path_id: FUNCTIONAL_PATH_ID,
                role: WireguardRole::Client as i32,
                public_key: vec![seed.wrapping_add(2); 32],
                public_endpoint: Some(PublicUdpEndpoint {
                    address: FUNCTIONAL_PUBLIC_IPV4.to_vec(),
                    port: listen_port,
                }),
                underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
            }],
        })
    }

    fn valid_activated_outcome(prepared: &FunctionalPreparedReceipt) -> helper_response::Outcome {
        helper_response::Outcome::ActivatedLeaseBatch(ActivatedLeaseBatch {
            context_handle: prepared.context_handle.to_vec(),
            lease_handles: vec![prepared.lease_handle.to_vec()],
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
            }
        }
        assert_eq!(FUNCTIONAL_RELEASE_BYTE, b'G');
    }

    #[test]
    fn functional_failure_records_are_one_bounded_allowlisted_line() {
        let phases = [
            FunctionalPhase::Plan,
            FunctionalPhase::Connect,
            FunctionalPhase::Bind,
            FunctionalPhase::Prepare,
            FunctionalPhase::Shutdown,
            FunctionalPhase::Ready,
            FunctionalPhase::Release,
            FunctionalPhase::Reconnect,
            FunctionalPhase::Destroy,
            FunctionalPhase::SecondCyclePlan,
            FunctionalPhase::SecondCycleBind,
            FunctionalPhase::SecondCyclePrepare,
            FunctionalPhase::Reuse,
            FunctionalPhase::SecondCycleDestroy,
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
        let plan = FunctionalCyclePlan::from_ids(ids, 1_000).expect("functional cycle");
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

        let prepared = validate_prepared_outcome(valid_prepared_outcome(0x62, 41_234), ids.context)
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
        assert_eq!(
            value.leases,
            [LeaseActivation {
                lease_handle: prepared.lease_handle.to_vec(),
                path_id: FUNCTIONAL_PATH_ID,
                role: WireguardRole::Client as i32,
                peer_public_key: FUNCTIONAL_PEER_PUBLIC_KEY.to_vec(),
                peer_endpoint: Some(PublicUdpEndpoint {
                    address: FUNCTIONAL_PEER_IPV4.to_vec(),
                    port: u32::from(FUNCTIONAL_PEER_PORT),
                }),
                maximum_up_mbps: 0,
                maximum_down_mbps: 0,
                signed_relay_reservation: Vec::new(),
            }]
        );
        assert_eq!(
            operation_digest(&activate).expect("Activate digest"),
            activate_exchange.operation_digest
        );

        let mut duplicate = ids;
        duplicate.destroy_absent_request = duplicate.destroy_present_request;
        assert!(FunctionalCyclePlan::from_ids(duplicate, 1_000).is_err());
        let mut duplicate_activate = ids;
        duplicate_activate.activate_request = duplicate_activate.prepare_request;
        assert!(FunctionalCyclePlan::from_ids(duplicate_activate, 1_000).is_err());
        let mut zero_context = ids;
        zero_context.context = [0; 16];
        assert!(FunctionalCyclePlan::from_ids(zero_context, 1_000).is_err());
        assert!(FunctionalCyclePlan::from_ids(ids, u64::MAX).is_err());
    }

    #[test]
    fn functional_response_requires_exact_correlation_diagnostic_and_runtime() {
        let plan =
            FunctionalCyclePlan::from_ids(fixed_cycle_ids(0x41), 1_000).expect("functional cycle");
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
        assert!(validate_runtime_outcome(valid_prepared_outcome(0x51, 41_234)).is_err());
    }

    #[test]
    fn functional_prepared_validation_rejects_every_endpoint_substitution() {
        let context_id = [0x61; 16];
        let valid = valid_prepared_outcome(0x62, 41_234);
        let receipt =
            validate_prepared_outcome(valid.clone(), context_id).expect("prepared receipt");
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
            assert!(validate_prepared_outcome(outcome, context_id).is_err());
        }
        assert!(validate_prepared_outcome(valid_prepared_outcome(0x62, 41_234), [0; 16]).is_err());
    }

    #[test]
    fn functional_activation_requires_exact_prepared_lineage_and_receipt() {
        let ids = fixed_cycle_ids(0x69);
        let plan = FunctionalCyclePlan::from_ids(ids, 1_000).expect("functional cycle");
        let prepared = validate_prepared_outcome(valid_prepared_outcome(0x6a, 41_234), ids.context)
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
        substitutions.push(valid_prepared_outcome(0x6a, 41_234));
        for outcome in substitutions {
            assert!(validate_activated_outcome(outcome, &prepared).is_err());
        }
    }

    #[test]
    fn functional_destroy_and_reuse_validation_are_exact() {
        let destroyed =
            |existed| helper_response::Outcome::DestroyedContext(DestroyedContext { existed });
        assert!(validate_destroyed_outcome(destroyed(true), true).is_ok());
        assert!(validate_destroyed_outcome(destroyed(false), false).is_ok());
        assert!(validate_destroyed_outcome(destroyed(true), false).is_err());
        assert!(validate_destroyed_outcome(valid_prepared_outcome(0x71, 41_234), true).is_err());

        let first = validate_prepared_outcome(valid_prepared_outcome(0x72, 41_234), [0x11; 16])
            .expect("first receipt");
        let second = validate_prepared_outcome(valid_prepared_outcome(0x82, 41_234), [0x12; 16])
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
