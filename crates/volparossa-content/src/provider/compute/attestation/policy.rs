//! Explicit owner-local comparisons, not current vendor security authorization.

use super::{EvidenceError, SignatureFacts};

/// Milan security-version components. There is deliberately no total ordering:
/// each component must independently meet its explicitly selected minimum.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MilanTcb {
    /// Bootloader SPL, in 0..=127.
    pub bootloader: u8,
    /// TEE SPL, in 0..=127.
    pub tee: u8,
    /// SNP SPL, in 0..=127.
    pub snp: u8,
    /// Microcode SPL, in 0..=255.
    pub microcode: u8,
}

impl MilanTcb {
    fn valid(self) -> bool {
        self.bootloader <= 127 && self.tee <= 127 && self.snp <= 127
    }

    fn meets(self, minimum: Self) -> bool {
        self.valid()
            && self.bootloader >= minimum.bootloader
            && self.tee >= minimum.tee
            && self.snp >= minimum.snp
            && self.microcode >= minimum.microcode
    }

    const fn bytes(self) -> [u8; 4] {
        [self.bootloader, self.tee, self.snp, self.microcode]
    }

    fn from_components(bytes: &[u8]) -> Result<Self, EvidenceError> {
        let [bootloader, tee, snp, microcode] =
            *<&[u8; 4]>::try_from(bytes).map_err(|_| EvidenceError::Encoding)?;
        let value = Self {
            bootloader,
            tee,
            snp,
            microcode,
        };
        if !value.valid() {
            return Err(EvidenceError::Encoding);
        }
        Ok(value)
    }

    pub(super) fn from_report(bytes: &[u8]) -> Result<Self, EvidenceError> {
        let bytes: &[u8; 8] = bytes.try_into().map_err(|_| EvidenceError::Encoding)?;
        if bytes[2..6] != [0; 4] {
            return Err(EvidenceError::Encoding);
        }
        Self::from_components(&[bytes[0], bytes[1], bytes[6], bytes[7]])
    }
}

/// Independently chosen minima; no implicit equality or ordering between stages.
/// There is no production default or conversion from a packed integer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcbMinimums {
    /// Running firmware's current TCB.
    pub current: MilanTcb,
    /// Reported TCB used to derive the VCEK.
    pub reported: MilanTcb,
    /// Committed firmware TCB, distinct from provisional current firmware.
    pub committed: MilanTcb,
    /// Signed launch/import TCB; not evidence of current workload behavior.
    pub launch: MilanTcb,
}

impl TcbMinimums {
    const fn stages(self) -> [MilanTcb; 4] {
        [self.current, self.reported, self.committed, self.launch]
    }
}

/// Explicit SMT choice. Guest permission and actual platform state are distinct.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SmtPolicy {
    /// Locally allow SMT; this is not a vendor mitigation appraisal.
    Allow,
    /// Reject either guest permission to use SMT or actual platform SMT enablement.
    RequireDisabled,
}

/// Immutable public owner expectations, with no inferred vendor-safe defaults.
/// Debug and migration-agent permission are always denied. No raw report/chip
/// bytes, serializer, deserializer or raw Debug representation are provided.
#[derive(Clone)]
pub struct LocalPolicy {
    pub(super) expected_measurement: [u8; 48],
    pub(super) minimum_guest_svn: u32,
    minimum_tcb: TcbMinimums,
    smt: SmtPolicy,
}

impl LocalPolicy {
    /// Construct explicit local expectations. SPL minima are not evidence that
    /// AMD advisories, operating-system mitigations or platform trust are satisfied.
    ///
    /// # Errors
    /// Rejects a zero measurement or a Milan SPL outside its component range.
    pub fn new(
        expected_measurement: [u8; 48],
        minimum_guest_svn: u32,
        minimum_tcb: TcbMinimums,
        smt: SmtPolicy,
    ) -> Result<Self, EvidenceError> {
        if expected_measurement == [0; 48]
            || minimum_tcb.stages().iter().any(|value| !value.valid())
        {
            return Err(EvidenceError::Configuration);
        }
        Ok(Self {
            expected_measurement,
            minimum_guest_svn,
            minimum_tcb,
            smt,
        })
    }

    // Measurement and guest SVN occupy separate canonical challenge fields.
    // This fixed encoding covers every other choice: encoding version, four
    // named stages in declared order, then the closed SMT discriminant.
    pub(super) fn restriction_bytes(&self) -> [u8; 18] {
        let mut bytes = [0; 18];
        bytes[0] = 1;
        for (chunk, stage) in bytes[1..17]
            .chunks_exact_mut(4)
            .zip(self.minimum_tcb.stages())
        {
            chunk.copy_from_slice(&stage.bytes());
        }
        bytes[17] = match self.smt {
            SmtPolicy::Allow => 0,
            SmtPolicy::RequireDisabled => 1,
        };
        bytes
    }

    pub(super) fn valid_restriction_bytes(bytes: &[u8]) -> bool {
        bytes.len() == 18
            && bytes[0] == 1
            && bytes[17] <= 1
            && bytes[1..17]
                .chunks_exact(4)
                .all(|value| MilanTcb::from_components(value).is_ok())
    }
}

impl SignatureFacts {
    /// Compare authentic signed claims against an explicit owner's local policy.
    /// Success does not change the remaining appraisal obligations, establish
    /// freshness, verify key origin or authorize a worker or private input.
    ///
    /// # Errors
    /// Returns only a closed policy error for any failed local comparison.
    pub fn check_local_policy(&self, policy: &LocalPolicy) -> Result<(), EvidenceError> {
        if self.measurement != policy.expected_measurement
            || self.guest_svn < policy.minimum_guest_svn
            || self.guest_policy & ((1 << 18) | (1 << 19)) != 0
            || self
                .tcb
                .iter()
                .zip(policy.minimum_tcb.stages())
                .any(|(actual, minimum)| !actual.meets(minimum))
            || (policy.smt == SmtPolicy::RequireDisabled
                && (self.guest_policy & (1 << 16) != 0 || self.platform_smt_enabled))
        {
            return Err(EvidenceError::Policy);
        }
        Ok(())
    }
}
