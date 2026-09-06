//! Owner-local timing for display-only native path observations, never packet authority.

use std::{future::Future, time::Duration};

use tokio::time::Instant;

const REFRESH_INTERVAL: Duration = Duration::from_millis(250);

/// Lives inside one affine route owner; a replacement route starts without a cached deadline.
#[derive(Default)]
pub(super) struct PathTelemetry {
    next_refresh: Option<Instant>,
}

impl PathTelemetry {
    /// Observe immediately when forced, otherwise at most once per monotonic interval.
    ///
    /// The caller has already authenticated its datagram independently. Only a successful
    /// observation advances this deadline; an observation error is returned unchanged.
    pub(super) async fn sample<T, E, F, S>(
        &mut self,
        now: Instant,
        force: bool,
        sample: F,
    ) -> Result<Option<T>, E>
    where
        F: FnOnce() -> S,
        S: Future<Output = Result<T, E>>,
    {
        if !force && self.next_refresh.is_some_and(|deadline| now < deadline) {
            return Ok(None);
        }
        let observed = sample().await?;
        self.next_refresh = Some(now + REFRESH_INTERVAL);
        Ok(Some(observed))
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, future::ready};

    use super::*;

    #[tokio::test]
    async fn path_telemetry_datagrams_do_not_issue_one_status_rpc_each() {
        let mut owner = PathTelemetry::default();
        let now = Instant::now();
        let events = RefCell::new(Vec::new());
        for offset in [0, 1, 249] {
            // This is the same order as the production receive callsite: authenticated native
            // receive and exact flow acceptance, optional status, then application delivery.
            events.borrow_mut().push("accepted_datagram");
            owner
                .sample(now + Duration::from_millis(offset), false, || {
                    events.borrow_mut().push("status_rpc");
                    ready(Ok::<_, ()>(()))
                })
                .await
                .unwrap();
            events.borrow_mut().push("delivered_datagram");
        }
        assert_eq!(
            *events.borrow(),
            [
                "accepted_datagram",
                "status_rpc",
                "delivered_datagram",
                "accepted_datagram",
                "delivered_datagram",
                "accepted_datagram",
                "delivered_datagram",
            ]
        );
        assert_eq!(
            owner
                .sample(now + REFRESH_INTERVAL, false, || ready(Ok::<_, ()>(7)))
                .await,
            Ok(Some(7)),
            "the exact 250-ms deadline permits one new observation"
        );
    }

    #[tokio::test]
    async fn path_telemetry_forced_refresh_and_new_owner_do_not_reuse_a_deadline() {
        let now = Instant::now();
        let mut old_owner = PathTelemetry::default();
        for force in [false, true, true] {
            assert_eq!(
                old_owner.sample(now, force, || ready(Ok::<_, ()>(1))).await,
                Ok(Some(1)),
                "initial, explicit query and maintenance must observe fresh status"
            );
        }
        let mut new_owner = PathTelemetry::default();
        assert_eq!(
            new_owner.sample(now, false, || ready(Ok::<_, ()>(2))).await,
            Ok(Some(2)),
            "a replaced route cannot inherit another native owner's observation"
        );
    }

    #[tokio::test]
    async fn path_telemetry_failed_observation_does_not_authorize_or_advance() {
        let now = Instant::now();
        let mut owner = PathTelemetry::default();
        assert_eq!(
            owner
                .sample(now, false, || ready(Err::<(), _>("stale_native_epoch")))
                .await,
            Err("stale_native_epoch")
        );
        assert_eq!(
            owner.sample(now, false, || ready(Ok::<_, &str>(()))).await,
            Ok(Some(())),
            "failed refresh leaves the owner due, not a fabricated successful snapshot"
        );
        assert_eq!(
            owner
                .sample(now, true, || ready(Err::<(), _>("invalid_correlation")))
                .await,
            Err("invalid_correlation"),
            "forced observations propagate native validation failures inside the interval"
        );
    }

    #[test]
    fn path_telemetry_gate_is_after_each_real_datagram_authorization() {
        let source = include_str!("../route_setup.rs");
        for (start, end, operations) in [
            (
                "pub(crate) async fn send_browser_quic_ingress(",
                "pub(crate) async fn receive_browser_quic_response(",
                [".send_browser_quic(", ".record_sent("],
            ),
            (
                "pub(crate) async fn receive_browser_quic_response(",
                "pub(crate) async fn refresh_mpquic_path_summaries(",
                [".receive_browser_quic(", ".accept_response("],
            ),
        ] {
            let body = source
                .split_once(start)
                .unwrap()
                .1
                .split_once(end)
                .unwrap()
                .0;
            let gate = body.find(".sample_path_summaries(false).await?").unwrap();
            for operation in operations {
                assert!(body.find(operation).unwrap() < gate);
            }
            assert!(!body.contains(".path_summaries().await?"));
            assert_eq!(body.matches(".sample_path_summaries(false)").count(), 1);
        }
    }
}
