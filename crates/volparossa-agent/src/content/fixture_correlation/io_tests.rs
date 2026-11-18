use std::{
    collections::VecDeque,
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::*;

enum Step {
    Pending,
    Error,
    Count(usize),
}

struct Scripted {
    steps: VecDeque<Step>,
    writes: usize,
    reads: usize,
    vectors: usize,
    flushes: usize,
    shutdowns: usize,
}

impl Scripted {
    fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            writes: 0,
            reads: 0,
            vectors: 0,
            flushes: 0,
            shutdowns: 0,
        }
    }

    fn next(&mut self) -> Poll<io::Result<usize>> {
        match self.steps.pop_front().expect("exact poll inventory") {
            Step::Pending => Poll::Pending,
            Step::Error => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Step::Count(count) => Poll::Ready(Ok(count)),
        }
    }
}

impl AsyncWrite for Scripted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes += 1;
        self.next()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _bytes: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.vectors += 1;
        self.next()
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes += 1;
        Poll::Pending
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdowns += 1;
        Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
    }
}

impl AsyncRead for Scripted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        match self.next() {
            Poll::Ready(Ok(count)) => {
                buf.put_slice(&[13; 64][..count]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[tokio::test]
async fn partial_pending_zero_and_error_writes_are_passed_through_once() {
    let state = armed().await;
    let guard = state.client(UID);
    let mut raw = Scripted::new([
        Step::Pending,
        Step::Error,
        Step::Count(0),
        Step::Count(13),
        Step::Count(51),
    ]);
    let mut stream = Observed::client(&mut raw, &guard);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        Pin::new(&mut stream)
            .poll_write(&mut cx, &[99; 64])
            .is_pending()
    );
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, &[99; 64]),
        Poll::Ready(Err(_))
    ));
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, &[99; 64]),
        Poll::Ready(Ok(0))
    ));
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, &[13; 64]),
        Poll::Ready(Ok(13))
    ));
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, &[13; 64]),
        Poll::Ready(Ok(51))
    ));
    assert!(stream.is_write_vectored());
    assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_pending());
    assert!(matches!(
        Pin::new(&mut stream).poll_shutdown(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert_eq!(
        (raw.writes, raw.flushes, raw.shutdowns, raw.reads),
        (5, 1, 1, 0)
    );
    assert!(raw.steps.is_empty());
    assert_eq!(
        clients(&state).await.records[0].fingerprint,
        Some(digest(&EPOCH, &[13; 64]))
    );
}

#[tokio::test]
async fn vectored_write_hashes_only_successful_prefix_across_slices() {
    let state = armed().await;
    let guard = state.client(UID);
    let mut raw = Scripted::new([Step::Pending, Step::Error, Step::Count(64)]);
    let mut stream = Observed::client(&mut raw, &guard);
    let mut cx = Context::from_waker(Waker::noop());
    let slices = [
        IoSlice::new(&[]),
        IoSlice::new(&[1; 20]),
        IoSlice::new(&[2; 80]),
    ];
    assert!(
        Pin::new(&mut stream)
            .poll_write_vectored(&mut cx, &slices)
            .is_pending()
    );
    assert!(matches!(
        Pin::new(&mut stream).poll_write_vectored(&mut cx, &slices),
        Poll::Ready(Err(_))
    ));
    assert!(matches!(
        Pin::new(&mut stream).poll_write_vectored(&mut cx, &slices),
        Poll::Ready(Ok(64))
    ));
    let mut accepted = [2; 64];
    accepted[..20].fill(1);
    assert_eq!(raw.vectors, 3);
    assert_eq!(raw.writes, 0);
    assert_eq!(
        clients(&state).await.records[0].fingerprint,
        Some(digest(&EPOCH, &accepted))
    );
}

#[tokio::test]
async fn provider_reads_ignore_prefilled_bytes_pending_error_and_eof() {
    let state = armed().await;
    let guard = state.provider();
    let mut raw = Scripted::new([Step::Pending, Step::Error, Step::Count(0), Step::Count(64)]);
    let mut stream = Observed::provider(&mut raw, &guard);
    let mut cx = Context::from_waker(Waker::noop());
    let mut bytes = [99; 80];
    let mut buf = ReadBuf::new(&mut bytes);
    buf.advance(7);
    assert!(
        Pin::new(&mut stream)
            .poll_read(&mut cx, &mut buf)
            .is_pending()
    );
    assert!(matches!(
        Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
        Poll::Ready(Err(_))
    ));
    assert!(matches!(
        Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(buf.filled(), &[99; 7]);
    assert!(matches!(
        Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(&buf.filled()[7..], &[13; 64]);
    assert_eq!(raw.reads, 4);
    assert_eq!(raw.writes, 0);
    assert_eq!(
        providers(&state, &digest(&EPOCH, &[13; 64]))
            .await
            .records
            .len(),
        1
    );
}

#[tokio::test]
async fn reverse_direction_and_disabled_wrapper_do_not_hash_or_change_io() {
    let state = armed().await;
    let client = state.client(UID);
    let provider = state.provider();
    let mut raw = Scripted::new([Step::Count(64), Step::Count(64)]);
    let mut bytes = [0; 64];
    Observed::client(&mut raw, &client)
        .read_exact(&mut bytes)
        .await
        .unwrap();
    Observed::provider(&mut raw, &provider)
        .write_all(&bytes)
        .await
        .unwrap();
    assert_eq!(bytes, [13; 64]);
    assert!(clients(&state).await.records[0].fingerprint.is_none());
    assert!(
        providers(&state, &digest(&EPOCH, &bytes))
            .await
            .records
            .is_empty()
    );
    let disabled = Guard::default();
    let mut raw = Scripted::new([Step::Count(64)]);
    Observed::client(&mut raw, &disabled)
        .write_all(&bytes)
        .await
        .unwrap();
    assert_eq!(raw.writes, 1);
}

#[tokio::test]
async fn real_duplex_partial_io_preserves_all_bytes_and_matches_endpoints() {
    let state = armed().await;
    let client = state.client(UID);
    let provider = state.provider();
    let (write, read) = tokio::io::duplex(7);
    let mut write = Observed::client(write, &client);
    let mut read = Observed::provider(read, &provider);
    let mut received = [0; 137];
    let (sent, got) = tokio::join!(write.write_all(&[42; 137]), read.read_exact(&mut received));
    sent.unwrap();
    got.unwrap();
    assert_eq!(received, [42; 137]);
    let expected = clients(&state).await.records[0]
        .fingerprint
        .clone()
        .unwrap();
    assert_eq!(expected, digest(&EPOCH, &received));
    assert_eq!(providers(&state, &expected).await.records.len(), 1);
}

#[tokio::test]
async fn real_inner_tls_uses_identical_ciphertext_prefix_without_protocol_changes() {
    use ed25519_dalek::SigningKey;
    use volparossa_content::{
        Validity,
        provider::{ProviderEndpoint, SignedProviderOffer},
    };

    let state = armed().await;
    let client_guard = state.client(UID);
    client_guard.enter(Phase::TlsHandshake);
    let provider_guard = state.provider();
    let identity = libp2p::identity::Keypair::generate_ed25519();
    let pair = identity.clone().try_into_ed25519().unwrap();
    let key = SigningKey::from_keypair_bytes(&pair.to_bytes()).unwrap();
    let now = crate::content::now();
    let offer = SignedProviderOffer::sign(
        &key,
        ProviderEndpoint::new("provider.test", 18080).unwrap(),
        Validity {
            created: now,
            expires: now + 300,
        },
    )
    .unwrap()
    .verify(&key.verifying_key(), now)
    .unwrap();
    let tls = crate::content::tls::ContentTlsServer::new(&identity, "provider.test").unwrap();
    let (client, provider) = tokio::io::duplex(4096);
    let client = Observed::client(client, &client_guard);
    let provider = Observed::provider(provider, &provider_guard);
    tokio::join!(
        Box::pin(async {
            let mut stream =
                crate::content::tls::connect(client, identity.public().to_peer_id(), &offer)
                    .await
                    .unwrap();
            stream.write_all(&[27; 20]).await.unwrap();
            stream.flush().await.unwrap();
            crate::content::tls::finish(&mut stream).await.unwrap();
        }),
        Box::pin(async {
            let mut stream = tls
                .accept_observed(provider, &provider_guard)
                .await
                .unwrap();
            let mut bytes = [0; 20];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, [27; 20]);
            crate::content::tls::finish(&mut stream).await.unwrap();
        }),
    );
    let expected = clients(&state).await.records[0]
        .fingerprint
        .clone()
        .unwrap();
    assert_eq!(providers(&state, &expected).await.records.len(), 1);
}
