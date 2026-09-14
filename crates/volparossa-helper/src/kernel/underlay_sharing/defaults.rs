//! Linux 6.12 kernel-default recognition, not arbitrary qdisc snapshot/replay.
//!
//! `qdisc_create()` allocates nonzero handles even for an explicit zero-handle request.
//! Deleting our nonzero root instead calls `dev_activate()/attach_default_qdiscs()`, which
//! restores handle-zero defaults. Only those recognizable defaults are admitted here.
//! Sources: Linux v6.12 `net/sched/{sch_api,sch_generic,sch_mq,sch_fq_codel}.c`.

use super::{
    HardDeadline, KernelError, MAX_OBJECTS, NetlinkClient, RTM_GETTFILTER, TC_ROOT, TcRecord,
    attributes, dump, exact_u32,
};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LinkGeometry {
    pub(super) mtu: u32,
    pub(super) hardware_type: u16,
    pub(super) tx_queues: u32,
    pub(super) tx_queue_length: u32,
}

#[derive(Clone, Debug)]
pub(super) struct DefaultTree {
    records: Vec<TcRecord>,
    filter_capable_root: bool,
}

impl DefaultTree {
    pub(super) fn from_records(
        records: &[TcRecord],
        geometry: LinkGeometry,
    ) -> Result<Self, KernelError> {
        if records.is_empty()
            || records.len() > MAX_OBJECTS
            || !(1..=4096).contains(&geometry.tx_queues)
            // sch_api's legacy IFF_NO_QUEUE/zero-length handling otherwise changes the link's
            // tx_queue_len when creating a qdisc. Reject rather than mutate unrelated geometry.
            || geometry.tx_queue_length == 0
            || records
                .iter()
                .any(|record| record.handle != 0 || record.extra_configuration)
        {
            return Err(KernelError::Invalid);
        }
        let roots: Vec<_> = records
            .iter()
            .filter(|record| record.parent == TC_ROOT)
            .collect();
        let [root] = roots.as_slice() else {
            return Err(KernelError::Invalid);
        };
        match root.kind.as_str() {
            "noqueue" | "noop" if records.len() == 1 && root.options.is_empty() => {}
            "fq_codel" if records.len() == 1 && geometry.tx_queues == 1 => {
                FqCodelDefaults::parse(&root.options, geometry)?;
            }
            "mq" if geometry.tx_queues > 1 && records.len() > 1 && root.options.is_empty() => {
                let mut parents = BTreeSet::new();
                for leaf in records.iter().filter(|record| record.parent != TC_ROOT) {
                    // Active queues are dumped; allocated-but-inactive MQ queues are kernel-only.
                    // Every visible default leaf has handle0, and its parent is its 1-based queue.
                    if leaf.kind != "fq_codel"
                        || leaf.parent == 0
                        || leaf.parent > geometry.tx_queues
                        || !parents.insert(leaf.parent)
                    {
                        return Err(KernelError::Invalid);
                    }
                    FqCodelDefaults::parse(&leaf.options, geometry)?;
                }
                if parents
                    .iter()
                    .copied()
                    .ne(1..=u32::try_from(parents.len()).map_err(|_| KernelError::Invalid)?)
                {
                    return Err(KernelError::Invalid);
                }
            }
            _ => return Err(KernelError::Invalid),
        }
        let mut records = records.to_vec();
        records.sort_by_key(|record| record.parent);
        Ok(Self {
            records,
            filter_capable_root: root.kind == "fq_codel",
        })
    }

    pub(super) fn matches(&self, records: &[TcRecord], geometry: LinkGeometry) -> bool {
        Self::from_records(records, geometry).is_ok_and(|other| {
            self.records.len() == other.records.len()
                && self
                    .records
                    .iter()
                    .zip(&other.records)
                    .all(|(left, right)| left.same_configuration(right))
        })
    }

    pub(super) fn verify_no_filters(
        &self,
        route: &mut NetlinkClient,
        ifindex: u32,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        // cls_api resolves parent0 to the root itself: a default fq_codel can contain filters.
        // Default MQ has no filter block, and its handle0 leaves cannot be separately addressed.
        if self.filter_capable_root
            && !dump(route, RTM_GETTFILTER, ifindex, 0, deadline)?.is_empty()
        {
            return Err(KernelError::Invalid);
        }
        Ok(())
    }
}

/// Exact eight-attribute default encoding from `fq_codel_init()/fq_codel_dump()`.
/// Additional CE thresholds, custom limits, unknown attributes and duplicates are rejected.
struct FqCodelDefaults;

impl FqCodelDefaults {
    fn parse(options: &[u8], geometry: LinkGeometry) -> Result<Self, KernelError> {
        // This bounded slice supports ordinary Ethernet/TAP headers. It does not guess a custom
        // hardware header length or reinterpret a non-Ethernet default quantum.
        if geometry.hardware_type != 1 {
            return Err(KernelError::Invalid);
        } // ARPHRD_ETHER.
        let fields = attributes(options)?;
        // CoDel stores 1024ns ticks, then truncates again when dumping integer microseconds.
        let default_us = |milliseconds: u32| (((milliseconds * 1_000_000) >> 10) << 10) / 1000;
        let expected = [
            (1, default_us(5)),
            (2, 10_240),
            (3, default_us(100)),
            (4, 1),
            (5, 1024),
            (6, geometry.mtu.checked_add(14).ok_or(KernelError::Invalid)?),
            (8, 64),
            (9, 32 << 20),
        ];
        if fields.len() != expected.len() {
            return Err(KernelError::Invalid);
        }
        for (kind, expected) in expected {
            if exact_u32(&fields, kind)? != expected {
                return Err(KernelError::Invalid);
            }
        }
        Ok(Self)
    }
}
