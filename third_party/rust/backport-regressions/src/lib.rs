// SPDX-License-Identifier: GPL-3.0-only

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use hickory_proto::serialize::binary::BinEncoder;
    use time::{format_description::well_known::Rfc2822, OffsetDateTime};

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

    fn rfc2822_with_nested_comment(depth: usize) -> String {
        format!(
            "{}x{} Fri, 21 Nov 1997 09:55:06 -0600",
            "(".repeat(depth),
            ")".repeat(depth),
        )
    }
}
