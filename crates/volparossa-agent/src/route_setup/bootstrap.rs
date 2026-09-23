//! The controller, not an individual RPC waiter, owns an in-flight route bootstrap.

use std::future::Future;

use tokio::task::JoinHandle;

use super::{ClientRouteConnectError, ClientRouteProgress};

type BootstrapResult = Result<ClientRouteProgress, ClientRouteConnectError>;

/// Kept behind the controller's shared mutex, including while a caller waits. Dropping a
/// waiter releases that mutex but leaves the task here for the next caller or shutdown.
#[derive(Default)]
pub(super) struct BootstrapOwner {
    task: Option<JoinHandle<BootstrapResult>>,
    failed: bool,
    closed: bool,
}

impl BootstrapOwner {
    pub(super) fn is_closed(&self) -> bool {
        self.closed || self.failed
    }

    pub(super) fn start(
        &mut self,
        operation: impl Future<Output = BootstrapResult> + Send + 'static,
    ) {
        assert!(self.task.is_none() && !self.is_closed());
        self.task = Some(tokio::spawn(operation));
    }

    pub(super) async fn join(&mut self) -> Result<Option<BootstrapResult>, ()> {
        if self.failed {
            return Err(());
        }
        let Some(task) = self.task.as_mut() else {
            return Ok(None);
        };
        // Borrow, never take, the handle across await: RPC cancellation cannot detach ownership.
        let result = task.await;
        self.task = None;
        if let Ok(result) = result {
            Ok(Some(result))
        } else {
            // A panic/abort cannot prove that an affine helper operation was unwound.
            self.failed = true;
            Err(())
        }
    }

    pub(super) async fn close_and_drain(&mut self) -> Result<(), ()> {
        self.closed = true;
        self.join().await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::{Mutex, oneshot};

    use super::*;

    #[tokio::test]
    async fn cancelling_a_waiter_retains_the_same_bootstrap_for_the_next_waiter() {
        let owner = Arc::new(Mutex::new(BootstrapOwner::default()));
        let (complete, completion) = oneshot::channel();
        let (waiting, started) = oneshot::channel();
        let caller_owner = Arc::clone(&owner);
        let caller = tokio::spawn(async move {
            let mut owner = caller_owner.lock().await;
            owner.start(async move {
                completion.await.expect("same operation remains live");
                Ok(ClientRouteProgress::TransportActive)
            });
            waiting.send(()).expect("caller observed");
            owner.join().await
        });
        started.await.expect("retained task installed");
        caller.abort();
        assert!(caller.await.expect_err("waiter cancelled").is_cancelled());
        complete.send(()).expect("bootstrap was not cancelled");
        let mut owner = owner.lock().await;
        assert_eq!(
            owner.join().await,
            Ok(Some(Ok(ClientRouteProgress::TransportActive)))
        );
        assert_eq!(
            owner.join().await,
            Ok(None),
            "consumed handle never repolled"
        );
        assert!(!owner.is_closed());
    }

    #[tokio::test]
    async fn cancelled_shutdown_keeps_closed_owner_and_original_completion() {
        let mut owner = BootstrapOwner::default();
        let (complete, completion) = oneshot::channel();
        owner.start(async move {
            completion
                .await
                .expect("shutdown must drain the same operation");
            Err(ClientRouteConnectError::PreselectionUnavailable)
        });
        let mut drain = Box::pin(owner.close_and_drain());
        tokio::select! {
            result = &mut drain => panic!("incomplete operation returned {result:?}"),
            () = tokio::task::yield_now() => {}
        }
        drop(drain);
        assert!(owner.is_closed());
        complete
            .send(())
            .expect("retained bootstrap still owns completion");
        assert_eq!(owner.close_and_drain().await, Ok(()));
        assert_eq!(owner.close_and_drain().await, Ok(()));
    }

    #[tokio::test]
    async fn failed_owner_never_claims_a_successful_drain_or_repolls_join() {
        let mut owner = BootstrapOwner::default();
        owner.start(async { panic!("synthetic bootstrap failure") });
        assert_eq!(owner.join().await, Err(()));
        assert!(owner.is_closed());
        assert_eq!(owner.join().await, Err(()));
        assert_eq!(owner.close_and_drain().await, Err(()));
    }
}
