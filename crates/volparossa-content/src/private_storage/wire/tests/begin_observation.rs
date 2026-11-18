use super::*;
use crate::private_storage::wire::begin_observation::{self as observation, Observer, Phase};

#[derive(Default)]
struct Trace(
    Mutex<Vec<Phase>>,
    Mutex<Vec<observation::ReadStep>>,
    Mutex<Vec<observation::ReadFailure>>,
);

impl Observer for Trace {
    fn phase(&self, phase: Phase) {
        self.0.lock().unwrap().push(phase);
    }
    fn read_step(&self, step: observation::ReadStep) {
        self.1.lock().unwrap().push(step);
    }
    fn read_failure(&self, failure: observation::ReadFailure) {
        self.2.lock().unwrap().push(failure);
    }
}

#[tokio::test(start_paused = true)]
async fn challenge_read_steps_preserve_pending_timeout_eof_invalid_and_verification_errors() {
    use observation::{ReadFailure as Failure, ReadStep as Step};
    for (bytes, eof, step, failure) in [
        (vec![], false, Step::LengthRead, Failure::WireTimeout),
        (
            vec![0, 0, 0, 3, 1],
            false,
            Step::BodyRead,
            Failure::WireTimeout,
        ),
        (vec![0, 0], true, Step::LengthRead, Failure::IoEof),
        (vec![0, 0, 0, 3, 1], true, Step::BodyRead, Failure::IoEof),
        (vec![0, 0, 0, 0], false, Step::LengthRead, Failure::Invalid),
        (
            vec![0, 0, 0, 1, 255],
            false,
            Step::Verification,
            Failure::VerificationRejected,
        ),
    ] {
        let fixture = Fixture::new();
        let (mut client, mut server) = tokio::io::duplex(8192);
        server.write_all(&bytes).await.unwrap();
        if eof {
            server.shutdown().await.unwrap();
        }
        let trace = Trace::default();
        let result = begin_observed(&mut client, &fixture.grant, &trace).await;
        assert!(result.is_err());
        assert_eq!(trace.1.lock().unwrap().last(), Some(&step));
        assert_eq!(*trace.2.lock().unwrap(), [failure]);
        match failure {
            Failure::WireTimeout => assert!(matches!(result, Err(WireError::Timeout))),
            Failure::IoEof => assert!(
                matches!(result, Err(WireError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
            ),
            Failure::Invalid => assert!(matches!(result, Err(WireError::Invalid))),
            Failure::VerificationRejected => assert!(matches!(result, Err(WireError::Protocol(_)))),
            Failure::IoOther => unreachable!(),
        }
    }
}

#[derive(Default)]
struct PendingIo {
    bytes: Vec<u8>,
    flushes: usize,
    block_write_after_flushes: Option<usize>,
    block_flush: Option<usize>,
    fail_read: bool,
}

impl AsyncRead for PendingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.fail_read {
            Poll::Ready(Err(std::io::Error::other("private-read-canary")))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncWrite for PendingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.block_write_after_flushes == Some(this.flushes) {
            return Poll::Pending;
        }
        this.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.block_flush == Some(this.flushes) {
            return Poll::Pending;
        }
        this.flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn begin_progress_identifies_pending_writes_flushes_and_challenge_read() {
    let fixture = Fixture::new();
    for (write, flush, expected) in [
        (Some(0), None, Phase::SelectorWriteFlush),
        (None, Some(0), Phase::SelectorWriteFlush),
        (Some(1), None, Phase::GrantWriteFlush),
        (None, Some(1), Phase::GrantWriteFlush),
        (None, None, Phase::ChallengeReadVerify),
    ] {
        let mut stream = PendingIo {
            block_write_after_flushes: write,
            block_flush: flush,
            ..PendingIo::default()
        };
        let trace = Trace::default();
        let started = tokio::time::Instant::now();
        let result = begin_observed(&mut stream, &fixture.grant, &trace).await;
        assert!(matches!(result, Err(WireError::Timeout)));
        assert!(started.elapsed() >= IO_TIMEOUT);
        assert!(started.elapsed() < IO_TIMEOUT + Duration::from_secs(1));
        let phases = trace.0.lock().unwrap().clone();
        assert_eq!(phases.last(), Some(&expected));
        assert_eq!(phases[0], Phase::SelectorWriteFlush);
        assert!(phases.len() <= 3);
        if expected == Phase::ChallengeReadVerify {
            assert_eq!(stream.flushes, 2);
            let mut written = stream.bytes.as_slice();
            let selector =
                Selector::decode(read_frame(&mut written, 64).await.unwrap().as_slice()).unwrap();
            assert_eq!(selector.operation, SELECTOR_OPERATION);
            assert_eq!(selector.version, SELECTOR_VERSION);
            assert!(selector.manifest_id.is_empty());
            assert_eq!(
                read_frame(&mut written, MAX_GRANT_BYTES).await.unwrap(),
                fixture.grant.signed().encode()
            );
            assert!(written.is_empty());
        }
    }
}

#[tokio::test]
async fn begin_progress_preserves_original_authenticated_exchange_and_receipt() {
    let fixture = Fixture::new();
    let (mut client, server) = fixture.stream();
    let trace = Trace::default();
    let challenge = begin_observed(&mut client, &fixture.grant, &trace)
        .await
        .unwrap();
    assert_eq!(
        *trace.1.lock().unwrap(),
        [
            observation::ReadStep::LengthRead,
            observation::ReadStep::BodyRead,
            observation::ReadStep::Verification
        ]
    );
    assert!(trace.2.lock().unwrap().is_empty());
    assert_eq!(
        *trace.0.lock().unwrap(),
        [
            Phase::SelectorWriteFlush,
            Phase::GrantWriteFlush,
            Phase::ChallengeReadVerify,
        ]
    );
    let request = fixture.request(
        &challenge,
        target(b"opaque"),
        StorageOperation::Reserve {
            expires_at: unix_now().unwrap() + 60,
        },
    );
    finish(&mut client, &fixture.grant, &challenge, &request, &[])
        .await
        .unwrap();
    drop(client);
    server.await.unwrap().unwrap();
    assert_eq!(fixture.usage().leases, 1);
}

#[tokio::test]
async fn begin_progress_preserves_io_error_without_exposing_its_text() {
    let fixture = Fixture::new();
    let trace = Trace::default();
    let mut stream = PendingIo {
        fail_read: true,
        ..PendingIo::default()
    };
    let result = begin_observed(&mut stream, &fixture.grant, &trace).await;
    let Err(WireError::Io(error)) = result else {
        panic!("original I/O error was not preserved");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    let phases = trace.0.lock().unwrap();
    assert_eq!(phases.last(), Some(&Phase::ChallengeReadVerify));
    assert_eq!(phases.len(), 3);
    assert!(!format!("{phases:?}").contains("private-read-canary"));
    assert_eq!(
        *trace.2.lock().unwrap(),
        [observation::ReadFailure::IoOther]
    );
}
