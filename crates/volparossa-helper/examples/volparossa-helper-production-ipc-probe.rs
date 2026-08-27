//! Narrow live probe for the packaged helper-v3 production IPC boundary.
//!
//! This example accepts no socket path, request bytes or privileged operation from its caller. It
//! requires one exact expected production PID/GID pair, connects only to the fixed production
//! socket, and exercises the read-only `BindHelperRuntime(None)` operation plus bounded fail-closed
//! framing cases.

use std::{ffi::OsString, io, os::unix::ffi::OsStrExt, process::ExitCode, time::Duration};

use rand_core::{OsRng, RngCore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};
use volparossa_helper::SOCKET_PATH;
use volparossa_routing::{
    BindHelperRuntime, HELPER_PROTOCOL_VERSION, HelperRequest, HelperResponse, HelperResult,
    encode_request, helper_request, helper_response, operation_digest, read_response,
};
use zeroize::Zeroizing;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MODE_ARGUMENT_BYTES: usize = "expect-unauthorised-peer".len();
const MAX_DECIMAL_U32_BYTES: usize = 10;
const ROOT_UID: u32 = 0;
const HELPER_RUNTIME_DIAGNOSTIC: &str = "HELPER_RUNTIME";
const FAILURE_RECORD: &str = "VOLPAROSSA_HELPER_V3_IPC_PROBE_V1=fail";
const USAGE_RECORD: &str = "VOLPAROSSA_HELPER_V3_IPC_PROBE_V1=usage";

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
            Self::RejectFrameBounds => "VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass",
            Self::RejectWireShapes => "VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass",
            Self::ExpectUnauthorisedPeer => "VOLPAROSSA_HELPER_V3_IPC_UNAUTHORISED_PEER_V1=pass",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ProbeError {
    Random,
    Protocol,
    Io,
    Timeout,
    UntrustedServer,
    Correlation,
    UnexpectedResponse,
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let Some(invocation) = parse_invocation(std::env::args_os().skip(1)) else {
        eprintln!("{USAGE_RECORD}");
        return ExitCode::from(2);
    };
    if run_mode(invocation).await.is_ok() {
        println!("{}", invocation.mode.success_record());
        ExitCode::SUCCESS
    } else {
        eprintln!("{FAILURE_RECORD}");
        ExitCode::FAILURE
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

async fn run_mode(invocation: ProbeInvocation) -> Result<(), ProbeError> {
    match invocation.mode {
        Mode::BindRuntime => run_bind_runtime(invocation.expected_peer).await,
        Mode::RejectFrameBounds => run_reject_frame_bounds(invocation.expected_peer).await,
        Mode::RejectWireShapes => run_reject_wire_shapes(invocation.expected_peer).await,
        Mode::ExpectUnauthorisedPeer => {
            run_expect_unauthorised_peer(invocation.expected_peer).await
        }
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

    use volparossa_routing::{HelperRuntime, MAX_HELPER_FRAME, decode_request};

    use super::*;

    #[test]
    fn parser_accepts_only_exact_mode_pid_and_gid_arguments() {
        let expected_peer = ExpectedPeer {
            pid: 1_234,
            gid: 61_000,
        };
        for (argument, expected) in [
            ("bind-runtime", Mode::BindRuntime),
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
            Mode::RejectFrameBounds.success_record(),
            Mode::RejectWireShapes.success_record(),
            Mode::ExpectUnauthorisedPeer.success_record(),
        ] {
            for forbidden in ["runtime_id", "MainPID", "InvocationID", SOCKET_PATH] {
                assert!(!record.contains(forbidden));
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
