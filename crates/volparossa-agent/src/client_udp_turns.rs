//! Bounded readiness turns for the single Client UDP actor, not packet buffering.

use std::{io, os::fd::OwnedFd};

use tokio::{
    io::unix::{AsyncFd, AsyncFdReadyGuard},
    time::Interval,
};

use crate::{MAXIMUM_BROWSER_QUIC_RESPONSES_PER_TICK, helper::ClientIngressSocketFamily};

pub(super) enum ClientUdpIoTurn<'a> {
    Ingress(ClientIngressSocketFamily, AsyncFdReadyGuard<'a, OwnedFd>),
    BrowserResponse,
}

/// Holds only a remaining operation count and family preference; it owns no datagram or FD.
#[derive(Default)]
pub(super) struct ClientUdpTurns {
    reverse_remaining: usize,
    ipv6_first: bool,
    ingress_first: bool,
}

impl ClientUdpTurns {
    /// Preserve a bounded drain across outer actor turns, without waiting a tick per packet.
    /// The outer actor retains shutdown/deadline selection and all datagram authorization.
    pub(super) async fn next<'a>(
        &mut self,
        ipv4: &'a AsyncFd<OwnedFd>,
        ipv6: &'a AsyncFd<OwnedFd>,
        reverse_poll: &mut Interval,
        browser_active: bool,
    ) -> io::Result<ClientUdpIoTurn<'a>> {
        if !browser_active {
            self.end_reverse_drain();
        }
        loop {
            // Once an ingress turn has run, the pending response gets the next turn even if
            // both input families remain ready. After a response, inspect readiness first.
            if self.reverse_remaining > 0 && !self.ingress_first {
                return Ok(self.reverse_turn());
            }
            let (first, first_family, second, second_family) = if self.ipv6_first {
                (
                    ipv6,
                    ClientIngressSocketFamily::Ipv6,
                    ipv4,
                    ClientIngressSocketFamily::Ipv4,
                )
            } else {
                (
                    ipv4,
                    ClientIngressSocketFamily::Ipv4,
                    ipv6,
                    ClientIngressSocketFamily::Ipv6,
                )
            };
            tokio::select! {
                biased;
                // Arm a due drain even under continuous ingress; this does not read a packet.
                _ = reverse_poll.tick(), if browser_active && self.reverse_remaining == 0 => {
                    self.reverse_remaining = MAXIMUM_BROWSER_QUIC_RESPONSES_PER_TICK;
                }
                ready = first.readable() => {
                    return Ok(self.ingress_turn(first_family, ready?));
                }
                ready = second.readable() => {
                    return Ok(self.ingress_turn(second_family, ready?));
                }
                () = std::future::ready(()), if self.reverse_remaining > 0 => {
                    return Ok(self.reverse_turn());
                }
            }
        }
    }

    pub(super) fn end_reverse_drain(&mut self) {
        self.reverse_remaining = 0;
    }

    fn reverse_turn(&mut self) -> ClientUdpIoTurn<'static> {
        self.reverse_remaining -= 1;
        self.ingress_first = true;
        ClientUdpIoTurn::BrowserResponse
    }

    fn ingress_turn<'a>(
        &mut self,
        family: ClientIngressSocketFamily,
        ready: AsyncFdReadyGuard<'a, OwnedFd>,
    ) -> ClientUdpIoTurn<'a> {
        self.ipv6_first = matches!(family, ClientIngressSocketFamily::Ipv4);
        self.ingress_first = false;
        ClientUdpIoTurn::Ingress(family, ready)
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::net::UnixDatagram, sync::Arc, time::Duration};

    use tokio::{
        sync::Notify,
        time::{interval, timeout},
    };

    use super::*;

    fn socket_pair() -> (AsyncFd<OwnedFd>, UnixDatagram, UnixDatagram) {
        let (receiver, sender) = UnixDatagram::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let poll = AsyncFd::new(receiver.try_clone().unwrap().into()).unwrap();
        (poll, receiver, sender)
    }

    #[tokio::test]
    async fn udp_turns_ready_ack_precedes_next_response_and_families_alternate() {
        let (ipv4, receiver4, sender4) = socket_pair();
        let (ipv6, receiver6, sender6) = socket_pair();
        let mut poll = interval(Duration::from_secs(3600));
        let mut turns = ClientUdpTurns::default();
        assert!(matches!(
            turns.next(&ipv4, &ipv6, &mut poll, true).await.unwrap(),
            ClientUdpIoTurn::BrowserResponse
        ));
        let released = Arc::new(Notify::new());
        let writer_ready = Arc::clone(&released);
        let writer = tokio::spawn(async move {
            writer_ready.notified().await;
            sender4.send(b"ack4").unwrap();
            sender6.send(b"ack6").unwrap();
        });
        released.notify_one();
        writer.await.unwrap();
        // Real kernel datagrams and AsyncFd readiness, not an invented ready flag. This tests
        // the production turn selector, not the helper-owned transparent ingress datapath.
        drop(
            timeout(Duration::from_secs(1), ipv4.readable())
                .await
                .unwrap()
                .unwrap(),
        );
        drop(
            timeout(Duration::from_secs(1), ipv6.readable())
                .await
                .unwrap()
                .unwrap(),
        );
        let mut payload = [0; 8];
        for (family, receiver) in [
            (ClientIngressSocketFamily::Ipv4, &receiver4),
            (ClientIngressSocketFamily::Ipv6, &receiver6),
        ] {
            let turn = turns.next(&ipv4, &ipv6, &mut poll, true).await.unwrap();
            let ClientUdpIoTurn::Ingress(observed_family, mut ready) = turn else {
                panic!("an already-readable ACK must run before another reverse operation");
            };
            assert_eq!(observed_family, family);
            assert_eq!(receiver.recv(&mut payload).unwrap(), 4);
            ready.clear_ready();
            assert!(
                matches!(
                    turns.next(&ipv4, &ipv6, &mut poll, true).await.unwrap(),
                    ClientUdpIoTurn::BrowserResponse
                ),
                "pending responses cannot be starved by the other ready ingress family"
            );
        }
    }

    #[tokio::test]
    async fn udp_turns_continue_all_64_without_waiting_for_another_tick() {
        let (ipv4, _receiver4, sender4) = socket_pair();
        let (ipv6, _receiver6, _sender6) = socket_pair();
        let mut poll = interval(Duration::from_secs(3600));
        let mut turns = ClientUdpTurns::default();
        timeout(Duration::from_secs(1), async {
            for _ in 0..MAXIMUM_BROWSER_QUIC_RESPONSES_PER_TICK {
                assert!(matches!(
                    turns.next(&ipv4, &ipv6, &mut poll, true).await.unwrap(),
                    ClientUdpIoTurn::BrowserResponse
                ));
            }
        })
        .await
        .expect("remaining work must be immediately eligible, not one packet per tick");
        assert_eq!(turns.reverse_remaining, 0);
        assert!(
            timeout(
                Duration::from_millis(10),
                turns.next(&ipv4, &ipv6, &mut poll, true)
            )
            .await
            .is_err()
        );
        sender4.send(b"ack").unwrap();
        drop(
            timeout(Duration::from_secs(1), ipv4.readable())
                .await
                .unwrap()
                .unwrap(),
        );
        // An overdue next tick must not start another 64-response burst ahead of ready ACKs.
        poll.reset_at(tokio::time::Instant::now() - Duration::from_secs(1));
        assert!(matches!(
            turns.next(&ipv4, &ipv6, &mut poll, true).await.unwrap(),
            ClientUdpIoTurn::Ingress(ClientIngressSocketFamily::Ipv4, _)
        ));
        assert!(matches!(
            turns.next(&ipv4, &ipv6, &mut poll, true).await.unwrap(),
            ClientUdpIoTurn::BrowserResponse
        ));
    }

    #[tokio::test]
    async fn udp_turns_empty_queue_and_inactive_owner_discard_pending_drain() {
        let (ipv4, _receiver4, sender4) = socket_pair();
        let (ipv6, _receiver6, _sender6) = socket_pair();
        let mut poll = interval(Duration::from_secs(3600));
        let mut turns = ClientUdpTurns::default();
        assert!(matches!(
            turns.next(&ipv4, &ipv6, &mut poll, true).await.unwrap(),
            ClientUdpIoTurn::BrowserResponse
        ));
        turns.end_reverse_drain();
        assert_eq!(turns.reverse_remaining, 0);
        assert!(
            timeout(
                Duration::from_millis(10),
                turns.next(&ipv4, &ipv6, &mut poll, true)
            )
            .await
            .is_err()
        );
        turns.reverse_remaining = 63;
        sender4.send(b"ack").unwrap();
        assert!(matches!(
            timeout(
                Duration::from_secs(1),
                turns.next(&ipv4, &ipv6, &mut poll, false)
            )
            .await
            .unwrap()
            .unwrap(),
            ClientUdpIoTurn::Ingress(ClientIngressSocketFamily::Ipv4, _)
        ));
        assert_eq!(turns.reverse_remaining, 0);
        assert_eq!(ClientUdpTurns::default().reverse_remaining, 0);
    }

    #[test]
    fn udp_turns_actor_keeps_per_packet_checks_and_outer_retirement() {
        let source = include_str!("lib.rs");
        let actor = source
            .split_once("async fn run_client_udp_ingress(")
            .unwrap()
            .1
            .split_once("async fn run_client_dns_ingress(")
            .unwrap()
            .0;
        assert!(actor.contains("result = io_turns.next("));
        assert!(!actor.contains("0..MAXIMUM_BROWSER_QUIC_RESPONSES_PER_TICK"));
        assert!(actor.contains("changed = shutdown.changed()"));
        assert!(actor.contains("routes.retire_expired().await"));
        let response = actor
            .split_once("Ok(ClientUdpIoTurn::BrowserResponse) => {")
            .unwrap()
            .1
            .split_once("let (family, mut ready) = ready;")
            .unwrap()
            .0;
        assert_eq!(
            response
                .matches("routes.receive_browser_quic_response(&policy, now_ms).await")
                .count(),
            1
        );
        assert!(
            response
                .find("state.read().await.active_policy(now_ms)")
                .unwrap()
                < response
                    .find("routes.receive_browser_quic_response(")
                    .unwrap()
        );
        assert!(response.contains("Ok(None) => io_turns.end_reverse_drain()"));
        assert_eq!(response.matches("io_turns.end_reverse_drain()").count(), 3);
    }
}
