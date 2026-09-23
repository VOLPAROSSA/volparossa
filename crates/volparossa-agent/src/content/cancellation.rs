//! Request-local cancellation before the named/HTTPS transfer-ready response.
//!
//! This phase permits no more requester bytes: chunk requests start only after readiness.
//! Once preparation completes, the reader is dropped and the ordinary transfer framing owns
//! the socket again. Cancelling preparation drops its locally owned streams/guards, not the
//! shared route controller's independently retained bootstrap or established route.

use std::future::Future;

use tokio::{io::AsyncReadExt, net::UnixStream};

use super::ContentError;

pub(super) async fn until_requester_closed<T>(
    stream: &mut UnixStream,
    preparation: impl Future<Output = Result<T, ContentError>>,
) -> Result<T, ContentError> {
    let mut unexpected = [0_u8; 1];
    tokio::select! {
        biased;
        received = stream.read(&mut unexpected) => {
            match received {
                Ok(0) | Err(_) => Err(ContentError::Unavailable),
                Ok(_) => Err(ContentError::Invalid),
            }
        }
        result = preparation => result,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use tokio::{
        io::AsyncWriteExt,
        sync::{Mutex, oneshot},
        time::timeout,
    };

    use super::*;
    use crate::content::replication_budget::Foreground;

    const WAIT: Duration = Duration::from_secs(2);

    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn requester_eof_drops_owned_preparation_streams_and_releases_outer_guards() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let (owned_first, mut remote_first) = UnixStream::pair().unwrap();
        let (owned_second, mut remote_second) = UnixStream::pair().unwrap();
        let foreground = Arc::new(Foreground::default());
        let retrieval = Arc::new(Mutex::new(()));
        let dropped = Arc::new(AtomicBool::new(false));
        let (started, running) = oneshot::channel();
        let request = {
            let foreground = Arc::clone(&foreground);
            let retrieval = Arc::clone(&retrieval);
            let dropped = Arc::clone(&dropped);
            tokio::spawn(async move {
                // Same lexical guard ownership as ContentRuntime::fetch_name/download_https.
                let _foreground = foreground.enter();
                let _retrieval = retrieval.try_lock().unwrap();
                until_requester_closed(&mut server, async move {
                    let _owned = (owned_first, owned_second, Dropped(dropped));
                    started.send(()).unwrap();
                    pending::<Result<(), ContentError>>().await
                })
                .await
            })
        };
        timeout(WAIT, running).await.unwrap().unwrap();
        assert!(foreground.active());
        assert!(retrieval.try_lock().is_err());
        drop(client);
        assert!(matches!(
            timeout(WAIT, request).await.unwrap().unwrap(),
            Err(ContentError::Unavailable)
        ));
        assert!(dropped.load(Ordering::Acquire));
        assert!(!foreground.active());
        assert!(retrieval.try_lock().is_ok());
        let mut byte = [0_u8; 1];
        assert_eq!(
            timeout(WAIT, remote_first.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(
            timeout(WAIT, remote_second.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn unexpected_requester_input_is_rejected_before_ready_work_is_polled() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(b"premature chunk request").await.unwrap();
        server.readable().await.unwrap();
        let mut polled = false;
        let result = until_requester_closed(&mut server, async {
            polled = true;
            Ok(())
        })
        .await;
        assert!(matches!(result, Err(ContentError::Invalid)));
        assert!(!polled);
    }

    #[tokio::test]
    async fn already_closed_requester_does_not_start_even_immediately_ready_preparation() {
        let (client, mut server) = UnixStream::pair().unwrap();
        drop(client);
        server.readable().await.unwrap();
        let mut polled = false;
        let result = until_requester_closed(&mut server, async {
            polled = true;
            Ok(())
        })
        .await;
        assert!(matches!(result, Err(ContentError::Unavailable)));
        assert!(!polled);
    }

    #[tokio::test]
    async fn successful_preparation_returns_socket_to_existing_transfer_framing() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        assert_eq!(
            until_requester_closed(&mut server, async { Ok(7_u8) })
                .await
                .unwrap(),
            7
        );
        server.write_all(b"ready").await.unwrap();
        let mut ready = [0_u8; 5];
        timeout(WAIT, client.read_exact(&mut ready))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ready, b"ready");
        client.write_all(b"chunk").await.unwrap();
        let mut chunk = [0_u8; 5];
        timeout(WAIT, server.read_exact(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&chunk, b"chunk");
    }

    #[tokio::test]
    async fn preparation_errors_keep_the_original_classification() {
        let (_client, mut server) = UnixStream::pair().unwrap();
        let result =
            until_requester_closed::<()>(&mut server, async { Err(ContentError::NameRollback) })
                .await;
        assert!(matches!(result, Err(ContentError::NameRollback)));
    }

    #[tokio::test]
    async fn cancellation_leaves_unrelated_consumer_stream_open() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let (mut sibling, mut sibling_peer) = UnixStream::pair().unwrap();
        drop(client);
        let result =
            until_requester_closed(&mut server, pending::<Result<(), ContentError>>()).await;
        assert!(matches!(result, Err(ContentError::Unavailable)));
        sibling.write_all(b"alive").await.unwrap();
        let mut bytes = [0_u8; 5];
        timeout(WAIT, sibling_peer.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"alive");
    }
}
