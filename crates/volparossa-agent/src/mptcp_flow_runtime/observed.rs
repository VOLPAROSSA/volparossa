//! Weak read-only observation of the same TLS/MPTCP socket that the egress proxy owns.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use volparossa_mptcp::MptcpSubflowInfo;
use volparossa_tcp_proxy::Tls13MptcpStream;

pub(super) struct ObservedTls(Arc<Mutex<Tls13MptcpStream>>);

type SocketObservation = Mutex<Option<Weak<Mutex<Tls13MptcpStream>>>>;

// This guard belongs to one accepted flow even while TLS/OPEN_TCP is still pending. The route
// can therefore withhold retirement until every live flow has a trustworthy observation.
pub(super) struct ObservationSlot(Arc<SocketObservation>);

pub(super) struct FlowObserver(Weak<SocketObservation>);

impl ObservationSlot {
    pub(super) fn new() -> (Self, FlowObserver) {
        let slot = Arc::new(Mutex::new(None));
        let observer = FlowObserver(Arc::downgrade(&slot));
        (Self(slot), observer)
    }

    pub(super) fn attach(&self, stream: Tls13MptcpStream) -> io::Result<ObservedTls> {
        let shared = Arc::new(Mutex::new(stream));
        let mut slot = self
            .0
            .lock()
            .map_err(|_| io::Error::other("MPTCP observer poisoned"))?;
        if slot.is_some() {
            return Err(io::Error::other("MPTCP flow observer already attached"));
        }
        *slot = Some(Arc::downgrade(&shared));
        Ok(ObservedTls(shared))
    }
}

impl FlowObserver {
    pub(super) fn is_live(&self) -> bool {
        self.0.strong_count() > 0
    }

    pub(super) fn observe(
        &self,
        maximum_subflows: usize,
    ) -> io::Result<Option<Vec<MptcpSubflowInfo>>> {
        let Some(slot) = self.0.upgrade() else {
            return Ok(None);
        };
        let stream = slot
            .lock()
            .map_err(|_| io::Error::other("MPTCP observer poisoned"))?
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "MPTCP authenticated flow not observable",
                )
            })?;
        // Neither I/O polling nor this read-only syscall holds the lock across an await. This
        // observer owns no extra FD and cannot keep the flow alive between maintenance ticks.
        let stream = stream
            .lock()
            .map_err(|_| io::Error::other("MPTCP observer poisoned"))?;
        stream.subflow_info(maximum_subflows).map(Some)
    }
}

impl AsyncRead for ObservedTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut stream = self
            .0
            .lock()
            .map_err(|_| io::Error::other("MPTCP observer poisoned"))?;
        Pin::new(&mut *stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for ObservedTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut stream = self
            .0
            .lock()
            .map_err(|_| io::Error::other("MPTCP observer poisoned"))?;
        Pin::new(&mut *stream).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut stream = self
            .0
            .lock()
            .map_err(|_| io::Error::other("MPTCP observer poisoned"))?;
        Pin::new(&mut *stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut stream = self
            .0
            .lock()
            .map_err(|_| io::Error::other("MPTCP observer poisoned"))?;
        Pin::new(&mut *stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mptcp_warm_observer_pending_or_dropped_flow_cannot_supply_metrics() {
        let (slot, observer) = ObservationSlot::new();
        assert!(observer.is_live());
        assert_eq!(
            observer.observe(3).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(slot);
        assert!(!observer.is_live());
        assert_eq!(observer.observe(3).unwrap(), None);
    }
}
