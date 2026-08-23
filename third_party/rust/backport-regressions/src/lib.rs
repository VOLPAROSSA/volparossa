// SPDX-License-Identifier: GPL-3.0-only

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use futures::{
        io::{self, AsyncRead, AsyncWrite, Cursor},
        task::noop_waker_ref,
    };
    use hickory_proto::serialize::binary::BinEncoder;
    use libp2p_core::{
        muxing::StreamMuxer,
        upgrade::{InboundConnectionUpgrade, UpgradeInfo},
    };
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        pin::Pin,
        task::{Context, Poll},
    };
    use time::{format_description::well_known::Rfc2822, OffsetDateTime};
    use yamux::{Config, Connection, Mode};

    struct PendingAfterInput {
        input: Cursor<Vec<u8>>,
    }

    impl AsyncRead for PendingAfterInput {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            match Pin::new(&mut self.input).poll_read(context, output) {
                Poll::Ready(Ok(0)) => Poll::Pending,
                result => result,
            }
        }
    }

    impl AsyncWrite for PendingAfterInput {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(input.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn hickory_name_compression_candidates_are_bounded() {
        let mut buffer = Vec::new();
        let mut encoder = BinEncoder::new(&mut buffer);

        for candidate in 0_u8..=64 {
            let start = encoder.offset();
            encoder.emit(candidate).unwrap();
            let end = encoder.offset();
            encoder.store_label_pointer(start, end);
        }

        assert_eq!(encoder.get_label_pointer(63, 64), Some(63));
        assert_eq!(encoder.get_label_pointer(64, 65), None);
    }

    #[test]
    fn hickory_cross_zone_nsec3_proof_fails_closed() {
        assert!(hickory_proto::dnssec::volparossa_backport_nsec3_cross_zone_regression());
    }

    #[test]
    fn time_rfc2822_comment_recursion_is_bounded() {
        let accepted = rfc2822_with_nested_comment(31);
        assert!(OffsetDateTime::parse(&accepted, &Rfc2822).is_ok());

        let rejected = rfc2822_with_nested_comment(32);
        assert!(OffsetDateTime::parse(&rejected, &Rfc2822).is_err());
    }

    #[test]
    fn yamux_oversized_first_stream_frame_fails_closed_without_panicking() {
        const SYN: u16 = 1;
        const DATA: u8 = 0;
        const STREAM_ID: u32 = 1;

        let body_len = yamux::DEFAULT_CREDIT + 1;
        let mut input = Vec::with_capacity(12 + body_len as usize);
        input.push(0); // Yamux version.
        input.push(DATA);
        input.extend_from_slice(&SYN.to_be_bytes());
        input.extend_from_slice(&STREAM_ID.to_be_bytes());
        input.extend_from_slice(&body_len.to_be_bytes());
        input.resize(12 + body_len as usize, 0);

        let mut connection = Connection::new(Cursor::new(input), Config::default(), Mode::Server);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let waker = noop_waker_ref();
            let mut context = Context::from_waker(waker);

            for _ in 0..16 {
                if let Poll::Ready(result) = connection.poll_next_inbound(&mut context) {
                    return Some(result);
                }
            }
            None
        }));

        let ready = outcome.expect("oversized first-stream frame must not unwind");
        let result = ready.expect("in-memory malformed frame processing must terminate promptly");
        assert!(
            !matches!(result, Some(Ok(_))),
            "oversized first-stream frame must never open a stream",
        );
    }

    #[test]
    fn libp2p_yamux_default_stops_buffered_reads_after_connection_close() {
        const SYN: u16 = 1;
        const DATA: u8 = 0;
        const STREAM_ID: u32 = 1;
        const PAYLOAD: &[u8] = b"buffered";

        let mut input = Vec::with_capacity(12 + PAYLOAD.len());
        input.push(0); // Yamux version.
        input.push(DATA);
        input.extend_from_slice(&SYN.to_be_bytes());
        input.extend_from_slice(&STREAM_ID.to_be_bytes());
        input.extend_from_slice(&(PAYLOAD.len() as u32).to_be_bytes());
        input.extend_from_slice(PAYLOAD);

        let mut config = libp2p_yamux::Config::default();
        config.set_max_num_streams(1);
        let protocol = config
            .protocol_info()
            .next()
            .expect("libp2p Yamux protocol must be declared");
        let mut muxer = futures::executor::block_on(config.upgrade_inbound(
            PendingAfterInput {
                input: Cursor::new(input),
            },
            protocol,
        ))
        .expect("in-memory wrapper upgrade must succeed");
        let waker = noop_waker_ref();
        let mut context = Context::from_waker(waker);
        let mut stream = match Pin::new(&mut muxer).poll_inbound(&mut context) {
            Poll::Ready(Ok(stream)) => stream,
            Poll::Ready(Err(error)) => panic!("valid buffered stream failed: {error}"),
            Poll::Pending => panic!("in-memory buffered stream did not become ready"),
        };

        drop(muxer);
        let mut output = [0_u8; PAYLOAD.len()];
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut context, &mut output),
            Poll::Ready(Ok(0)),
        ));
        assert_eq!(output, [0_u8; PAYLOAD.len()]);
    }

    fn rfc2822_with_nested_comment(depth: usize) -> String {
        format!(
            "{}x{} Fri, 21 Nov 1997 09:55:06 -0600",
            "(".repeat(depth),
            ")".repeat(depth),
        )
    }
}
