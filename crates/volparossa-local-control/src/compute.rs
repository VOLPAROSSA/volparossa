//! Fixed public-inference broker RPC, not execution permission or publication provenance.
//!
//! A same-UID agent must authenticate the network requester before forwarding its key.
//! Dataset identifiers supplied here are bindings; the caller must separately verify their
//! original signed publications and explicit public-data authorization. No paths or commands
//! can be supplied. JSON is bounded and rejects unknown and duplicate typed fields.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Fixed broker protocol version.
pub const VERSION: u32 = 1;
/// Maximum framed request including the escaped public dataset JSON string.
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
/// Maximum framed response, including a bounded escaped worker report.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Maximum decoded explicitly public dataset bytes.
pub const MAX_DATASET_BYTES: usize = 1024 * 1024;
/// Maximum actual worker report bytes retained in one response.
pub const MAX_REPORT_BYTES: usize = 32 * 1024;
/// Longest admitted inference job lifetime, including loading and cleanup.
pub const MAX_JOB_SECONDS: u64 = 600;

/// Requester-selected operations on independently verified public contexts.
/// This instruction is not part of the original publisher's signed dataset.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicTask {
    /// Apply the fixed version-one summary instruction separately to selected public contexts.
    SummarizeContextsV1 {},
    /// Apply one explicitly public requester question to each selected public context.
    AnswerPublicQuestionV1 {
        /// Exact requester-authored UTF-8 text, at most 512 bytes; never a command or path.
        question: String,
    },
}

impl PublicTask {
    /// Exact versioned instruction used for deterministic public-dataset derivation.
    ///
    /// # Errors
    /// Rejects empty/whitespace-only questions, NUL and more than 512 UTF-8 bytes.
    pub fn question(&self) -> Result<&str, ProtocolError> {
        match self {
            Self::SummarizeContextsV1 {} => Ok("Summarize the provided public context."),
            Self::AnswerPublicQuestionV1 { question } => {
                if question.trim().is_empty() || question.len() > 512 || question.contains('\0') {
                    return Err(ProtocolError::Invalid);
                }
                Ok(question)
            }
        }
    }
}

/// A correlated request sent through the protected same-UID local broker socket.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Exact protocol version.
    pub version: u32,
    /// Fresh lowercase hexadecimal 16-byte exchange identifier.
    pub request_id: String,
    /// Independently authenticated requester Ed25519 key, not self-authorizing metadata.
    pub requester_key: String,
    /// One fixed operation.
    pub operation: Operation,
}

/// No arbitrary commands, scripts, model downloads or file paths are representable.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "operation",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Operation {
    /// Inspect this explicitly enabled broker's fixed model and current capacity.
    Capabilities,
    /// Ask the provider agent about selected public publishers and fixed execution profiles.
    /// Only the agent can answer publisher eligibility; this never admits a worker job.
    Eligibility(EligibilityQuery),
    /// Admit one real inference job, or report busy; there is no pending queue.
    Submit(Submit),
    /// Observe a job with its complete original binding and authenticated owner.
    Poll(JobBinding),
    /// Request actual worker cancellation with the complete original binding.
    Cancel(JobBinding),
}

/// Immutable task identity; job ID alone never authorizes reading or cancellation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobBinding {
    /// Lowercase hexadecimal 16-byte job identifier.
    pub job_id: String,
    /// Original independently verified signed public dataset manifest ID.
    pub dataset_manifest_id: String,
    /// SHA-256 of the exact derived public inference dataset JSON bytes.
    pub dataset_sha256: String,
    /// Exact model/base/optional adapter fingerprint from capabilities.
    pub model_fingerprint: String,
    /// Increasing original inference-row indices, mapped to local output order.
    pub row_indices: Vec<u16>,
    /// Original absolute expiry; retry cannot extend it.
    pub expires_unix_seconds: u64,
    /// Optional requester-authored derivation, never publisher-authored question provenance.
    /// Absence retains the original independent inference-row operation and encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<PublicTask>,
}

/// A bounded explicitly authorized public inference dataset, never private cache contents.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Submit {
    /// Complete immutable job binding.
    pub binding: JobBinding,
    /// Exact UTF-8 JSON text whose hash appears in the binding.
    pub dataset_json: String,
    /// Original signed, explicitly public source, independently checked by the network agent.
    pub publication: PublicDataset,
}

/// Publication evidence, not permission to export private data or execute publisher code.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicDataset {
    /// Publisher key; the receiver must independently allow this publisher.
    pub publisher_key: String,
    /// Original canonical signed content manifest as hexadecimal bytes.
    pub manifest_hex: String,
    /// Exact original object bytes before selecting the bound inference rows.
    pub dataset_json: String,
}

/// Public file identity without a local filename path.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    /// Actual file byte count.
    pub bytes: u64,
    /// Lowercase hexadecimal SHA-256.
    pub sha256: String,
}

/// Fixed provisioned model profile; it does not promise model answer quality.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentity {
    /// Recognized base-model ID.
    pub model_id: String,
    /// Exact pinned base-model revision.
    pub model_revision: String,
    /// Actual base-model weights file identity.
    pub base_weights: FileIdentity,
    /// Exactly three fixed adapter file identities, or no adapter.
    pub adapter_files: Option<BTreeMap<String, FileIdentity>>,
}

/// Resource bounds of the explicitly enabled local inference worker.
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent versioned wire capability flags preserve old peers' default-false encoding"
)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// Actual fixed base and optional adapter identity.
    pub model: ModelIdentity,
    /// SHA-256 of serialized `model`, binding the whole frozen profile.
    pub model_fingerprint: String,
    /// A slot may be taken after observing this hint; Submit decides admission.
    pub accepting_work: bool,
    /// Only independently authorized public inference is supported.
    pub public_inference_only: bool,
    /// Actual simultaneous runtime slots on this broker.
    pub runtime_slots: u16,
    /// Maximum worker CPU threads.
    pub max_threads: u16,
    /// Maximum requested whole-job lifetime.
    pub max_job_seconds: u64,
    /// Maximum decoded input dataset bytes.
    pub max_dataset_bytes: u64,
    /// Maximum independent Q/A rows in one task.
    pub max_rows: u16,
    /// Supports the explicit version-one requester instruction derivation.
    /// Older capability records default to false and cannot admit a derived task.
    #[serde(default, skip_serializing_if = "is_false")]
    pub task_derivation_v1: bool,
    /// Supports publisher-signed inference-only document excerpts (dataset version two).
    #[serde(default, skip_serializing_if = "is_false")]
    pub document_inference_v2: bool,
    /// Supports explicitly model-generated inference-only synthesis inputs (dataset version three).
    /// This is not an attestation of the parent workers or permission to train on their answers.
    #[serde(default, skip_serializing_if = "is_false")]
    pub derived_inference_v3: bool,
}

/// A content-free suitability query, not publisher authority or a capacity reservation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EligibilityQuery {
    /// One through 32 distinct, independently selected public-data publisher keys.
    pub publisher_keys: Vec<String>,
    /// Optional exact frozen model fingerprint; absence does not select a model by itself.
    pub model_fingerprint: Option<String>,
    /// Optional recognized base profile, independent of an approved adapter fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_profile: Option<String>,
    /// Require the existing explicit public-question derivation profile.
    pub require_task_derivation_v1: bool,
    /// Require signed original public-document inference.
    pub require_document_inference_v2: bool,
    /// Require signed generated-intermediate public inference.
    pub require_derived_inference_v3: bool,
}

impl EligibilityQuery {
    /// Check canonical, valid Ed25519 publisher identities and bounded profile requirements.
    ///
    /// # Errors
    /// Rejects empty, duplicate, excessive or invalid keys and invalid model fingerprints.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !(1..=32).contains(&self.publisher_keys.len())
            || self
                .model_fingerprint
                .as_ref()
                .is_some_and(|value| !nonzero_hex(value, 64))
            || self
                .model_profile
                .as_deref()
                .is_some_and(|profile| profile_model_id(profile).is_none())
        {
            return Err(ProtocolError::Invalid);
        }
        let mut seen = BTreeSet::new();
        for key in &self.publisher_keys {
            if !nonzero_hex(key, 64) || !seen.insert(key) {
                return Err(ProtocolError::Invalid);
            }
            let mut bytes = [0; 32];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&key[index * 2..index * 2 + 2], 16)
                    .map_err(|_| ProtocolError::Invalid)?;
            }
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| ProtocolError::Invalid)?;
        }
        Ok(())
    }

    /// Match this valid query against current capacity and the requested fixed profiles.
    /// The caller must authenticate/validate capabilities and independently check publisher trust.
    /// A positive result is only an observation; actual Submit still decides admission.
    pub fn matches(&self, capabilities: &Capabilities) -> bool {
        self.validate().is_ok()
            && capabilities.accepting_work
            && capabilities.public_inference_only
            && self
                .model_fingerprint
                .as_ref()
                .is_none_or(|expected| expected == &capabilities.model_fingerprint)
            && self.model_profile.as_deref().is_none_or(|profile| {
                profile_model_id(profile) == Some(capabilities.model.model_id.as_str())
            })
            && (!self.require_task_derivation_v1 || capabilities.task_derivation_v1)
            && (!self.require_document_inference_v2 || capabilities.document_inference_v2)
            && (!self.require_derived_inference_v3 || capabilities.derived_inference_v3)
    }
}

fn profile_model_id(profile: &str) -> Option<&'static str> {
    match profile {
        "smollm2-135m-v1" => Some("HuggingFaceTB/SmolLM2-135M-Instruct"),
        "smollm2-360m-v1" => Some("HuggingFaceTB/SmolLM2-360M-Instruct"),
        _ => None,
    }
}

/// Provider-checked suitability at one instant, never a lease or an execution receipt.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Eligibility {
    /// Actual owner-broker model/profile/capacity observation.
    pub capabilities: Capabilities,
    /// All requested publishers are locally trusted and all requested constraints currently match.
    pub eligible: bool,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "Serde skip predicate requires a reference"
)]
fn is_false(value: &bool) -> bool {
    !value
}

/// Correlated response; only Complete includes a validated actual worker report.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Exact protocol version.
    pub version: u32,
    /// Exact corresponding request identifier.
    pub request_id: String,
    /// One bounded typed outcome.
    pub outcome: Outcome,
}

/// Operation result, not a signed network receipt; the agent authenticates that envelope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "Single bounded RPC outcome retains its inline immutable job binding"
)]
#[serde(
    tag = "outcome",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Outcome {
    /// Supported provisioned identity and owner-constrained resource availability.
    Capabilities(Capabilities),
    /// Provider agent's publisher/profile suitability observation, not execution permission.
    Eligibility(Eligibility),
    /// Exact retained job state.
    Job(JobStatus),
    /// A fixed diagnostic without prompts, paths or backend exception details.
    Error(ErrorCode),
}

/// Live or terminal execution state; cancellation is terminal only after worker completion.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// The real execution task is still owned, possibly while cancellation is being reaped.
    Running,
    /// Real worker exited successfully and its report and exact inputs were verified.
    Complete,
    /// Cancellation requested and the actual execution task has returned.
    Cancelled,
    /// The actual execution or validation failed, never a synthetic successful response.
    Failed,
}

/// Pollable bounded report, retained only until the original task expiry.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobStatus {
    /// Exact original immutable binding.
    pub binding: JobBinding,
    /// Actual lifecycle state.
    pub state: JobState,
    /// A requested cancellation is not yet proof of worker termination.
    pub cancellation_requested: bool,
    /// Original validated worker/supervisor JSON, only when Complete.
    pub report_json: Option<String>,
    /// SHA-256 of exact report JSON bytes, only when Complete.
    pub report_sha256: Option<String>,
    /// Fixed failure code, never a backend exception or private local path.
    pub error: Option<ErrorCode>,
}

/// Fixed public broker errors.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Invalid framing, fields, input hash, public schema or unsupported operation.
    Invalid,
    /// No execution or retained-result capacity is available.
    Busy,
    /// Unknown job or requester/binding mismatch; no foreign job information is returned.
    Missing,
    /// The original job authorization expired.
    Expired,
    /// Requested frozen model does not match the configured worker.
    ModelMismatch,
    /// Real worker execution failed; no result is claimed.
    WorkerFailed,
    /// Actual worker result differs from its frozen request or configured model.
    ResultMismatch,
    /// Local runtime, cache, output or socket operation is unavailable.
    Unavailable,
}

/// Framing or strict DTO validation failure.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Underlying bounded local-stream I/O failure.
    #[error("compute_broker_io")]
    Io(#[from] std::io::Error),
    /// Malformed, excessive or noncorrelated protocol value.
    #[error("compute_broker_invalid")]
    Invalid,
}

impl Request {
    /// Check fixed types and bounds before admission; does not authenticate the sender.
    ///
    /// # Errors
    /// Rejects invalid identifiers, fields, resource sizes and excessive new-task lifetime.
    pub fn validate(&self, now: u64) -> Result<(), ProtocolError> {
        if self.version != VERSION
            || !nonzero_hex(&self.request_id, 32)
            || !nonzero_hex(&self.requester_key, 64)
        {
            return Err(ProtocolError::Invalid);
        }
        let binding = match &self.operation {
            Operation::Capabilities => return Ok(()),
            Operation::Eligibility(query) => return query.validate(),
            Operation::Submit(submit) => {
                if submit.dataset_json.is_empty()
                    || submit.dataset_json.len() > MAX_DATASET_BYTES
                    || !nonzero_hex(&submit.publication.publisher_key, 64)
                    || submit.publication.manifest_hex.is_empty()
                    || submit.publication.manifest_hex.len() > 128 * 1024
                    || submit.publication.manifest_hex.len() % 2 != 0
                    || !submit
                        .publication
                        .manifest_hex
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit())
                    || submit.publication.dataset_json.is_empty()
                    || submit.publication.dataset_json.len() > MAX_DATASET_BYTES
                    || submit.binding.expires_unix_seconds > now.saturating_add(MAX_JOB_SECONDS)
                {
                    return Err(ProtocolError::Invalid);
                }
                &submit.binding
            }
            Operation::Poll(binding) | Operation::Cancel(binding) => binding,
        };
        if !nonzero_hex(&binding.job_id, 32)
            || !nonzero_hex(&binding.dataset_manifest_id, 64)
            || !nonzero_hex(&binding.dataset_sha256, 64)
            || !nonzero_hex(&binding.model_fingerprint, 64)
            || !(1..=4).contains(&binding.row_indices.len())
            || binding.row_indices.iter().any(|index| *index >= 4)
            || binding
                .row_indices
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || binding.expires_unix_seconds == 0
            || binding
                .task
                .as_ref()
                .is_some_and(|task| task.question().is_err())
        {
            return Err(ProtocolError::Invalid);
        }
        Ok(())
    }
}

/// Whether a string is a nonzero, canonical lowercase hexadecimal value of exact width.
pub fn nonzero_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Read one bounded strict request. The caller imposes an exchange deadline.
///
/// # Errors
/// Rejects oversized, invalid JSON or unknown/duplicate fields and incomplete frames.
pub async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Request, ProtocolError> {
    read_frame(stream, MAX_REQUEST_BYTES).await
}

/// Write one bounded request. Authentication and semantic admission remain separate.
///
/// # Errors
/// Rejects oversized serialized data or failed stream writes.
pub async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &Request,
) -> Result<(), ProtocolError> {
    write_frame(stream, request, MAX_REQUEST_BYTES).await
}

/// Read one bounded response and require exact local exchange correlation.
///
/// # Errors
/// Rejects invalid JSON, framing, version or request correlation.
pub async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    request_id: &str,
) -> Result<Response, ProtocolError> {
    let response: Response = read_frame(stream, MAX_RESPONSE_BYTES).await?;
    if response.version != VERSION || response.request_id != request_id {
        return Err(ProtocolError::Invalid);
    }
    Ok(response)
}

/// Write one bounded strict response.
///
/// # Errors
/// Rejects excessive serialized data or failed stream writes.
pub async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: &Response,
) -> Result<(), ProtocolError> {
    write_frame(stream, response, MAX_RESPONSE_BYTES).await
}

async fn read_frame<S: AsyncRead + Unpin, T: DeserializeOwned>(
    stream: &mut S,
    maximum: usize,
) -> Result<T, ProtocolError> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > maximum {
        return Err(ProtocolError::Invalid);
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| ProtocolError::Invalid)
}

async fn write_frame<S: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut S,
    value: &T,
    maximum: usize,
) -> Result<(), ProtocolError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ProtocolError::Invalid)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ProtocolError::Invalid);
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| ProtocolError::Invalid)?)
        .await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut encoded = String::new();
        for byte in bytes {
            write!(encoded, "{byte:02x}").unwrap();
        }
        encoded
    }

    fn eligibility_query() -> EligibilityQuery {
        EligibilityQuery {
            publisher_keys: vec![key_hex(
                ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                    .verifying_key()
                    .as_bytes(),
            )],
            model_fingerprint: None,
            model_profile: None,
            require_task_derivation_v1: false,
            require_document_inference_v2: false,
            require_derived_inference_v3: false,
        }
    }

    #[test]
    fn eligibility_query_bounds_distinct_valid_publishers_and_optional_model() {
        let mut query = eligibility_query();
        query.validate().unwrap();
        query.publisher_keys = (1..=32)
            .map(|seed| {
                key_hex(
                    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                        .verifying_key()
                        .as_bytes(),
                )
            })
            .collect();
        query.model_fingerprint = Some("a".repeat(64));
        query.validate().unwrap();
        query.publisher_keys.push(key_hex(
            ed25519_dalek::SigningKey::from_bytes(&[33; 32])
                .verifying_key()
                .as_bytes(),
        ));
        assert!(query.validate().is_err());
        let original = eligibility_query();
        let invalid_point = (1..=255)
            .find(|byte| ed25519_dalek::VerifyingKey::from_bytes(&[*byte; 32]).is_err())
            .unwrap();
        for keys in [
            vec![],
            vec![original.publisher_keys[0].clone(); 2],
            vec![original.publisher_keys[0].to_uppercase()],
            vec!["0".repeat(64)],
            vec!["1".repeat(63)],
            vec![key_hex(&[invalid_point; 32])],
        ] {
            query = original.clone();
            query.publisher_keys = keys;
            assert!(query.validate().is_err());
        }
        for model in ["0".repeat(64), "A".repeat(64), "a".repeat(63)] {
            query = original.clone();
            query.model_fingerprint = Some(model);
            assert!(query.validate().is_err());
        }
    }

    #[test]
    fn eligibility_base_profile_is_optional_exact_and_legacy_encoding_stays_unchanged() {
        let original = eligibility_query();
        let encoded = serde_json::to_string(&original).unwrap();
        assert_eq!(
            encoded,
            format!(
                "{{\"publisher_keys\":[\"{}\"],\"model_fingerprint\":null,\"require_task_derivation_v1\":false,\"require_document_inference_v2\":false,\"require_derived_inference_v3\":false}}",
                original.publisher_keys[0]
            )
        );
        assert_eq!(
            serde_json::from_str::<EligibilityQuery>(&encoded).unwrap(),
            original
        );
        for profile in ["smollm2-135m-v1", "smollm2-360m-v1"] {
            let mut query = original.clone();
            query.model_profile = Some(profile.into());
            query.validate().unwrap();
            assert_eq!(
                serde_json::from_slice::<EligibilityQuery>(&serde_json::to_vec(&query).unwrap())
                    .unwrap(),
                query
            );
        }
        for profile in ["", "smollm2-360m", "SMOLLM2-135M-V1", "smollm2-360m-v1 "] {
            let mut query = original.clone();
            query.model_profile = Some(profile.into());
            assert!(query.validate().is_err());
        }
    }

    #[test]
    fn eligibility_matches_only_current_capacity_and_requested_profiles() {
        let mut query = eligibility_query();
        let mut caps = Capabilities {
            model: ModelIdentity {
                model_id: "fixture".into(),
                model_revision: "pinned".into(),
                base_weights: FileIdentity {
                    bytes: 1,
                    sha256: "a".repeat(64),
                },
                adapter_files: None,
            },
            model_fingerprint: "b".repeat(64),
            accepting_work: true,
            public_inference_only: true,
            runtime_slots: 1,
            max_threads: 2,
            max_job_seconds: 600,
            max_dataset_bytes: 1_048_576,
            max_rows: 4,
            task_derivation_v1: false,
            document_inference_v2: false,
            derived_inference_v3: false,
        };
        assert!(query.matches(&caps));
        query.require_task_derivation_v1 = true;
        assert!(!query.matches(&caps));
        caps.task_derivation_v1 = true;
        assert!(query.matches(&caps));
        query.require_document_inference_v2 = true;
        assert!(!query.matches(&caps));
        caps.document_inference_v2 = true;
        assert!(query.matches(&caps));
        query.require_derived_inference_v3 = true;
        assert!(!query.matches(&caps));
        caps.derived_inference_v3 = true;
        assert!(query.matches(&caps));
        query.model_fingerprint = Some("c".repeat(64));
        assert!(!query.matches(&caps));
        query.model_fingerprint = Some(caps.model_fingerprint.clone());
        assert!(query.matches(&caps));
        query.model_profile = Some("smollm2-135m-v1".into());
        assert!(!query.matches(&caps));
        caps.model.model_id = "HuggingFaceTB/SmolLM2-135M-Instruct".into();
        assert!(query.matches(&caps));
        query.model_profile = Some("smollm2-360m-v1".into());
        assert!(!query.matches(&caps));
        caps.model.model_id = "HuggingFaceTB/SmolLM2-360M-Instruct".into();
        assert!(query.matches(&caps));
        query.model_profile = Some("unrecognized".into());
        assert!(!query.matches(&caps));
        query.model_profile = None;
        assert!(query.matches(&caps));
        caps.accepting_work = false;
        assert!(!query.matches(&caps));
        caps.accepting_work = true;
        caps.public_inference_only = false;
        assert!(!query.matches(&caps));
        caps.public_inference_only = true;
        query.publisher_keys.clear();
        assert!(!query.matches(&caps));
    }

    #[test]
    fn eligibility_request_is_strict_and_has_no_task_or_path_fields() {
        let query = eligibility_query();
        let request = Request {
            version: VERSION,
            request_id: "a".repeat(32),
            requester_key: query.publisher_keys[0].clone(),
            operation: Operation::Eligibility(query.clone()),
        };
        request.validate(1000).unwrap();
        assert_eq!(
            serde_json::from_slice::<Request>(&serde_json::to_vec(&request).unwrap()).unwrap(),
            request
        );
        for field in ["dataset_json", "manifest_id", "url", "path", "command"] {
            let mut value = serde_json::to_value(&query).unwrap();
            value[field] = "not permitted".into();
            assert!(serde_json::from_value::<EligibilityQuery>(value).is_err());
        }
        let duplicate = serde_json::to_string(&query).unwrap().replacen(
            "\"publisher_keys\":",
            "\"publisher_keys\":[],\"publisher_keys\":",
            1,
        );
        assert!(serde_json::from_str::<EligibilityQuery>(&duplicate).is_err());
    }

    #[test]
    fn versioned_public_tasks_bound_exact_requester_questions_and_reject_unknown_types() {
        assert_eq!(
            PublicTask::SummarizeContextsV1 {}.question().unwrap(),
            "Summarize the provided public context."
        );
        for question in [
            "A public question?".to_owned(),
            "  Keep these spaces.  ".into(),
            "é".repeat(256),
        ] {
            let task = PublicTask::AnswerPublicQuestionV1 {
                question: question.clone(),
            };
            assert_eq!(task.question().unwrap(), question);
            let bytes = serde_json::to_vec(&task).unwrap();
            assert_eq!(serde_json::from_slice::<PublicTask>(&bytes).unwrap(), task);
        }
        for question in [
            String::new(),
            " \t\n".into(),
            "bad\0question".into(),
            "x".repeat(513),
            "é".repeat(257),
        ] {
            assert!(
                PublicTask::AnswerPublicQuestionV1 { question }
                    .question()
                    .is_err()
            );
        }
        for json in [
            r#"{"kind":"summarize_contexts_v2"}"#,
            r#"{"kind":"summarize_contexts_v1","question":"unknown override"}"#,
            r#"{"kind":"answer_public_question_v1","question":"a","question":"b"}"#,
        ] {
            assert!(serde_json::from_str::<PublicTask>(json).is_err());
        }
    }

    #[test]
    fn legacy_binding_bytes_are_unchanged_but_requester_task_changes_full_binding() {
        let legacy = format!(
            concat!(
                "{{\"job_id\":\"{}\",\"dataset_manifest_id\":\"{}\",\"dataset_sha256\":\"{}\",",
                "\"model_fingerprint\":\"{}\",\"row_indices\":[0,2],\"expires_unix_seconds\":1600}}"
            ),
            "1".repeat(32),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64)
        );
        let binding: JobBinding = serde_json::from_str(&legacy).unwrap();
        assert!(binding.task.is_none());
        assert_eq!(serde_json::to_string(&binding).unwrap(), legacy);
        let mut changed = binding.clone();
        changed.task = Some(PublicTask::SummarizeContextsV1 {});
        assert_ne!(changed, binding);
        assert_ne!(serde_json::to_string(&changed).unwrap(), legacy);
        let mut request = Request {
            version: VERSION,
            request_id: "a".repeat(32),
            requester_key: "b".repeat(64),
            operation: Operation::Poll(changed.clone()),
        };
        request.validate(1000).unwrap();
        changed.task = Some(PublicTask::AnswerPublicQuestionV1 {
            question: "\0".into(),
        });
        request.operation = Operation::Cancel(changed);
        assert!(request.validate(1000).is_err());
    }

    #[test]
    fn absent_derivation_capability_defaults_false_and_omits_the_new_field() {
        let original = serde_json::json!({
            "model": {"model_id":"public-model","model_revision":"pinned","base_weights":{"bytes":1,"sha256":"a".repeat(64)},"adapter_files":null},
            "model_fingerprint":"b".repeat(64),"accepting_work":true,"public_inference_only":true,
            "runtime_slots":1,"max_threads":2,"max_job_seconds":600,"max_dataset_bytes":1_048_576,"max_rows":4
        });
        let mut capabilities: Capabilities = serde_json::from_value(original.clone()).unwrap();
        assert!(!capabilities.task_derivation_v1);
        assert!(!capabilities.document_inference_v2);
        assert!(!capabilities.derived_inference_v3);
        assert_eq!(serde_json::to_value(&capabilities).unwrap(), original);
        capabilities.task_derivation_v1 = true;
        assert_eq!(
            serde_json::to_value(&capabilities).unwrap()["task_derivation_v1"],
            true
        );
        capabilities.document_inference_v2 = true;
        assert_eq!(
            serde_json::to_value(&capabilities).unwrap()["document_inference_v2"],
            true
        );
        capabilities.derived_inference_v3 = true;
        assert_eq!(
            serde_json::to_value(&capabilities).unwrap()["derived_inference_v3"],
            true
        );
    }
}
