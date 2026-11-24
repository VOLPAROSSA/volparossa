// SPDX-License-Identifier: GPL-3.0-only
use super::{ClientRouteControl, ClientRouteExpiry, Instant, Libp2pPeerId};
use tokio::sync::watch;

/// Status can read the actual control peer while the TCP owner awaits its helper.
/// Every discovery or flow admission still has to acquire the route owner itself.
#[derive(Clone)]
pub(super) struct AcquiringTcpControl {
    sender: watch::Sender<Option<(Libp2pPeerId, ClientRouteExpiry)>>,
}

impl Default for AcquiringTcpControl {
    fn default() -> Self {
        Self {
            sender: watch::channel(None).0,
        }
    }
}

impl AcquiringTcpControl {
    /// The caller holds the exclusive route owner throughout this await. Drop clears the
    /// observation before that owner can retire, move or be released on cancellation.
    pub(super) async fn during<F: Future>(
        &self,
        peer: Libp2pPeerId,
        expiry: ClientRouteExpiry,
        work: F,
    ) -> F::Output {
        struct Clear<'a>(&'a AcquiringTcpControl);
        impl Drop for Clear<'_> {
            fn drop(&mut self) {
                self.0.sender.send_replace(None);
            }
        }
        self.sender.send_replace(Some((peer, expiry)));
        let _clear = Clear(self);
        work.await
    }
}

impl ClientRouteControl {
    pub(crate) async fn status_content_control(&self) -> Option<Libp2pPeerId> {
        let mut acquiring = self.acquiring_tcp_control.sender.subscribe();
        tokio::select! {
            biased;
            state = self.state.lock() => state.current_content_route().map(|route| route.request.control.identity.peer_id),
            value = acquiring.wait_for(Option::is_some) => {
                let (peer, expiry) = (*value.ok()?)?;
                (!expiry.is_expired(crate::unix_millis(), Instant::now())).then_some(peer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::pending, time::Duration};
    use tokio::time::timeout;

    #[tokio::test]
    async fn stalled_acquisition_exposes_only_live_status_until_cancelled() {
        let controller = ClientRouteControl::default();
        let owner = controller.state.lock().await;
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let now = Instant::now();
        let expiry = ClientRouteExpiry {
            hard_expires_at_ms: crate::unix_millis() + 60_000,
            monotonic_deadline: now + Duration::from_secs(60),
        };
        let admission = controller
            .acquiring_tcp_control
            .during(peer, expiry, pending::<()>());
        let mut admission = Box::pin(admission);
        tokio::select! {
            biased;
            () = &mut admission => panic!("stalled acquisition completed"),
            current = timeout(Duration::from_millis(100), controller.status_content_control()) => assert_eq!(current.expect("status blocked by helper"), Some(peer)),
        }
        assert!(
            timeout(
                Duration::from_millis(10),
                controller.content_discovery_control()
            )
            .await
            .is_err()
        );
        drop(admission);
        assert!(
            timeout(
                Duration::from_millis(10),
                controller.status_content_control()
            )
            .await
            .is_err()
        );
        for expired in [
            ClientRouteExpiry {
                hard_expires_at_ms: 0,
                ..expiry
            },
            ClientRouteExpiry {
                monotonic_deadline: now,
                ..expiry
            },
        ] {
            let result = controller
                .acquiring_tcp_control
                .during(peer, expired, controller.status_content_control())
                .await;
            assert_eq!(result, None);
        }
        drop(owner);
        assert_eq!(controller.status_content_control().await, None);
    }
}
