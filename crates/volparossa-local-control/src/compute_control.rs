//! Explicit broker attachment and same-socket protected compute handoff.

use prost::Message;

use crate::ControlProtocolError;

/// Local operator attachment; no remote peer chooses a path on this host.
#[derive(Clone, PartialEq, Message)]
pub struct ComputeAttachRequest {
    /// Existing protected same-UID broker socket.
    #[prost(string, tag = "1")]
    pub broker_socket: String,
    /// Explicit unprivileged provider listener address and port.
    #[prost(string, tag = "2")]
    pub bind_address: String,
    /// Policy-authorized hostname; no arbitrary destination fallback.
    #[prost(string, tag = "3")]
    pub advertised_hostname: String,
    /// Independently trusted publishers of public input datasets.
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub trusted_dataset_publishers: Vec<Vec<u8>>,
}

/// Select a provider before upgrading this exact local connection for a bounded job RPC.
#[derive(Clone, PartialEq, Message)]
pub struct ComputeRemoteRequest {
    /// Independently selected Ed25519 provider key.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
}

/// Readiness for a single request, not a successful job or completed network exchange.
#[derive(Clone, PartialEq, Message)]
pub struct ComputeReady {
    /// Exact selected remote provider.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Node key the agent will use to authenticate this caller's request.
    #[prost(bytes = "vec", tag = "2")]
    pub requester_key: Vec<u8>,
}

/// Explicit content-free discovery requirements; no task, source bytes or local paths.
#[derive(Clone, PartialEq, Message)]
pub struct ComputeDiscoverRequest {
    /// Independently selected public dataset publishers, not authorities inferred from discovery.
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub publisher_keys: Vec<Vec<u8>>,
    /// Optional exact frozen base/adapter fingerprint.
    #[prost(string, optional, tag = "2")]
    pub model_fingerprint: Option<String>,
    /// Require requester-authored public task derivation.
    #[prost(bool, tag = "3")]
    pub require_task_derivation_v1: bool,
    /// Require original signed document excerpts.
    #[prost(bool, tag = "4")]
    pub require_document_inference_v2: bool,
    /// Require signed model-generated synthesis inputs.
    #[prost(bool, tag = "5")]
    pub require_derived_inference_v3: bool,
    /// Maximum returned compatible pool, between two and four.
    #[prost(uint32, tag = "6")]
    pub maximum: u32,
}

/// One authenticated capability observation, not a reservation or successful worker job.
#[derive(Clone, PartialEq, Message)]
pub struct ComputeDiscoveredProvider {
    /// Provider identity authenticated on the existing protected route.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Bounded strict compute capabilities, containing no local paths or task data.
    #[prost(string, tag = "2")]
    pub capabilities_json: String,
}

/// One compatible observed pool; Submit still decides actual admission.
#[derive(Clone, PartialEq, Message)]
pub struct ComputeDiscovered {
    /// Between two and four distinct providers with the same model fingerprint.
    #[prost(message, repeated, tag = "1")]
    pub providers: Vec<ComputeDiscoveredProvider>,
}

impl ComputeDiscoverRequest {
    /// Convert bounded local requirements to the signed content-free eligibility query.
    ///
    /// # Errors
    /// Rejects invalid/duplicate publishers, fingerprints and pool bounds.
    pub fn eligibility(&self) -> Result<crate::compute::EligibilityQuery, ControlProtocolError> {
        use std::fmt::Write as _;

        if !(2..=4).contains(&self.maximum)
            || !(1..=32).contains(&self.publisher_keys.len())
            || self.publisher_keys.iter().any(|key| key.len() != 32)
        {
            return Err(ControlProtocolError::Invalid("compute discovery scope"));
        }
        let publisher_keys = self
            .publisher_keys
            .iter()
            .map(|key| {
                let mut encoded = String::with_capacity(64);
                for byte in key {
                    let _ = write!(encoded, "{byte:02x}");
                }
                encoded
            })
            .collect();
        let query = crate::compute::EligibilityQuery {
            publisher_keys,
            model_fingerprint: self.model_fingerprint.clone(),
            require_task_derivation_v1: self.require_task_derivation_v1,
            require_document_inference_v2: self.require_document_inference_v2,
            require_derived_inference_v3: self.require_derived_inference_v3,
        };
        query
            .validate()
            .map_err(|_| ControlProtocolError::Invalid("compute discovery requirements"))?;
        Ok(query)
    }
}

impl ComputeDiscovered {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        let mut keys = std::collections::BTreeSet::new();
        let mut fingerprint = None;
        if !(2..=4).contains(&self.providers.len()) {
            return Err(ControlProtocolError::Invalid("compute discovered pool"));
        }
        for provider in &self.providers {
            let key: [u8; 32] = provider
                .provider_key
                .as_slice()
                .try_into()
                .map_err(|_| ControlProtocolError::Invalid("compute discovered identity"))?;
            if key == [0; 32]
                || !keys.insert(key)
                || ed25519_dalek::VerifyingKey::from_bytes(&key).is_err()
                || provider.capabilities_json.is_empty()
                || provider.capabilities_json.len() > 16 * 1024
            {
                return Err(ControlProtocolError::Invalid("compute discovered provider"));
            }
            let caps: crate::compute::Capabilities =
                serde_json::from_str(&provider.capabilities_json).map_err(|_| {
                    ControlProtocolError::Invalid("compute discovered capabilities")
                })?;
            if !caps.accepting_work
                || !caps.public_inference_only
                || !crate::compute::nonzero_hex(&caps.model_fingerprint, 64)
                || fingerprint
                    .as_ref()
                    .is_some_and(|old| old != &caps.model_fingerprint)
            {
                return Err(ControlProtocolError::Invalid(
                    "compute discovered compatibility",
                ));
            }
            fingerprint = Some(caps.model_fingerprint);
        }
        Ok(())
    }
}

impl ComputeAttachRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if !self.broker_socket.starts_with('/')
            || self.broker_socket.len() > 107
            || self.broker_socket.contains('\0')
            || self.bind_address.parse::<std::net::SocketAddr>().is_err()
            || self.advertised_hostname.is_empty()
            || self.advertised_hostname.len() > 253
            || !(1..=64).contains(&self.trusted_dataset_publishers.len())
            || self
                .trusted_dataset_publishers
                .iter()
                .any(|key| key.len() != 32)
        {
            return Err(ControlProtocolError::Invalid("compute attachment scope"));
        }
        let unique: std::collections::BTreeSet<_> =
            self.trusted_dataset_publishers.iter().collect();
        if unique.len() != self.trusted_dataset_publishers.len() {
            return Err(ControlProtocolError::Invalid("duplicate compute publisher"));
        }
        Ok(())
    }
}

impl ComputeRemoteRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.provider_key.len() != 32 {
            return Err(ControlProtocolError::Invalid("compute provider"));
        }
        Ok(())
    }
}

impl ComputeReady {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.provider_key.len() != 32 || self.requester_key.len() != 32 {
            return Err(ControlProtocolError::Invalid("compute readiness"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
