//! Named retrieval admission only; no network, model or policy quality claim.

use super::*;
use tokio::net::UnixStream;

const WAIT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn named_consumers_wait_in_order_for_the_original_retrieval_owner() {
    let retrieval = Mutex::new(());
    let original = retrieval.lock().await;
    let (_first_client, mut first_stream) = UnixStream::pair().unwrap();
    let (_second_client, mut second_stream) = UnixStream::pair().unwrap();
    let first = named_retrieval(&retrieval, &mut first_stream);
    tokio::pin!(first);
    tokio::select! {
        biased;
        _ = &mut first => panic!("occupied retrieval must queue, not reject or run"),
        () = tokio::task::yield_now() => {},
    }
    let second = named_retrieval(&retrieval, &mut second_stream);
    tokio::pin!(second);
    tokio::select! {
        biased;
        _ = &mut second => panic!("the next consumer must also remain queued"),
        () = tokio::task::yield_now() => {},
    }
    drop(original);
    let admitted = timeout(WAIT, first).await.unwrap().unwrap();
    tokio::select! {
        biased;
        _ = &mut second => panic!("queued consumers must not overlap retrieval"),
        () = tokio::task::yield_now() => {},
    }
    drop(admitted);
    drop(timeout(WAIT, second).await.unwrap().unwrap());
    assert!(retrieval.try_lock().is_ok());
}

#[tokio::test]
async fn requester_eof_and_original_deadline_remove_waiters_without_holding_retrieval() {
    let retrieval = Mutex::new(());
    let original = retrieval.lock().await;
    let (client, mut stream) = UnixStream::pair().unwrap();
    let waiting = named_retrieval(&retrieval, &mut stream);
    tokio::pin!(waiting);
    tokio::select! {
        biased;
        _ = &mut waiting => panic!("occupied retrieval must wait"),
        () = tokio::task::yield_now() => {},
    }
    drop(client);
    assert!(matches!(
        timeout(WAIT, waiting).await.unwrap(),
        Err(ContentError::Unavailable)
    ));
    assert!(
        retrieval.try_lock().is_err(),
        "the original owner stays intact"
    );

    let (_next_client, mut next_stream) = UnixStream::pair().unwrap();
    assert!(
        timeout(
            Duration::ZERO,
            named_retrieval(&retrieval, &mut next_stream)
        )
        .await
        .is_err()
    );
    drop(original);
    drop(
        timeout(WAIT, named_retrieval(&retrieval, &mut next_stream))
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(retrieval.try_lock().is_ok());
}
