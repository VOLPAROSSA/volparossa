//! Explicit owner authorization for the fixed, source-built CPU inference backend.
//! A cached model or a peer request cannot authorize loading executable code.

use std::{
    fs,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{Mode, ModelProfile};

mod cache_hint;
pub(super) mod source_weight_cache;
use cache_hint::{Binding, CacheHint};

pub(super) const KIND: &str = "llama_cpp_bf16_v1";
const SOURCE: &str = "7fe450e19305b828c199d602c23a8337aaa1f03b";
const WEIGHTS: &str = "79f6bbc34572c0063d12022f0f93074d90bbcd5dfd82134423bf892f7f8df3cf";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum OutputConstraint {
    QwenTaggedToolJsonV1,
}

#[derive(Clone, Debug, Default, Args)]
#[group(id = "NativeCpuBackendOptions")]
pub(super) struct Options {
    /// Private owner-provisioned CPU backend; never a path supplied by a peer.
    #[arg(long, requires = "native_backend_sha256")]
    pub native_backend_root: Option<PathBuf>,
    /// Explicit owner-authorized SHA-256 of backend.json, including executable identity.
    #[arg(long, requires = "native_backend_root")]
    pub native_backend_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Verification {
    tensor_count: u32,
    tensor_values_equal: bool,
    tokenizer_equal: bool,
    chat_template_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    kind: String,
    abi_version: u8,
    source_commit: String,
    model_profile: ModelProfile,
    source_weights_sha256: String,
    source_weights_bytes: u64,
    library: Artifact,
    gguf: Artifact,
    verification: Verification,
    build_manifest_sha256: String,
    #[serde(default, deserialize_with = "present_output_constraints")]
    output_constraints: Option<Vec<OutputConstraint>>,
    #[serde(default, deserialize_with = "present_native_sessions")]
    native_sessions: Option<Vec<String>>,
}

fn present_output_constraints<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Vec<OutputConstraint>>, D::Error> {
    Vec::<OutputConstraint>::deserialize(deserializer).map(Some)
}

fn present_native_sessions<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error> {
    Vec::<String>::deserialize(deserializer).map(Some)
}

impl Manifest {
    fn validate(&self) -> Result<()> {
        ensure!(
            ((self.version == 1 && self.output_constraints.is_none())
                || ((self.version == 2 || self.version == 3)
                    && self.output_constraints.as_deref()
                        == Some(&[OutputConstraint::QwenTaggedToolJsonV1])))
                && (if self.version == 3 {
                    self.native_sessions.as_deref() == Some(&["connection_bound_v1".to_owned()])
                } else {
                    self.native_sessions.is_none()
                })
                && self.kind == KIND
                && self.abi_version == 1
                && self.source_commit == SOURCE
                && self.model_profile == ModelProfile::Qwen4bInstruct2507
                && self.source_weights_sha256 == WEIGHTS
                && self.source_weights_bytes == 8_044_982_000,
            "compute_native_backend_identity"
        );
        ensure!(
            self.library.path == "libvolparossa_llama_cpu.so"
                && (1..=128 * 1024 * 1024).contains(&self.library.bytes)
                && self.gguf.path == "model.gguf"
                && (1..=9 * 1024 * 1024 * 1024).contains(&self.gguf.bytes)
                && [
                    &self.library.sha256,
                    &self.gguf.sha256,
                    &self.build_manifest_sha256,
                    &self.verification.chat_template_sha256
                ]
                .iter()
                .all(|hash| super::is_hex(hash, 64)),
            "compute_native_backend_artifacts"
        );
        ensure!(
            self.verification.tensor_count == 398
                && self.verification.tensor_values_equal
                && self.verification.tokenizer_equal,
            "compute_native_backend_conversion"
        );
        Ok(())
    }

    fn report(&self, hash: &str) -> Value {
        json!({"kind":KIND,"abi_version":1,"source_commit":SOURCE,
            "manifest_sha256":hash,"library_sha256":self.library.sha256,
            "gguf_sha256":self.gguf.sha256,"gguf_bytes":self.gguf.bytes,
            "source_weights_sha256":WEIGHTS,
            "verification_scope":{"version":1,
                "source_weights":"initial_complete_bytes_only",
                "execution_weights":"gguf_complete_bytes_before_and_after"}})
    }
}

impl Options {
    pub(super) fn enabled(&self) -> bool {
        self.native_backend_root.is_some() || self.native_backend_sha256.is_some()
    }

    pub(super) fn validate(&self, profile: ModelProfile) -> Result<()> {
        self.request(profile).map(|_| ())
    }

    pub(super) fn validate_input(
        &self,
        mode: Mode,
        raw: &[u8],
        profile: ModelProfile,
    ) -> Result<()> {
        if self.enabled() {
            ensure!(
                mode == Mode::PrivateConversation && profile == ModelProfile::Qwen4bInstruct2507,
                "compute_native_backend_scope"
            );
            let input = super::private_conversation::Input::decode_profile(raw, profile)?;
            ensure!(
                input.requires_generation_policy_handshake(),
                "compute_native_backend_policy"
            );
        }
        if mode == Mode::PrivateConversation {
            let input = super::private_conversation::Input::decode_profile(raw, profile)?;
            if input.output_constraint().is_some() {
                self.request(profile)?.select_constraint(&input)?;
            }
        }
        Ok(())
    }

    pub(super) fn supports_output_constraint(&self, profile: ModelProfile) -> bool {
        self.request(profile)
            .is_ok_and(|request| request.supported_output_constraint.is_some())
    }

    pub(super) fn supports_native_session(&self, profile: ModelProfile) -> bool {
        self.request(profile)
            .is_ok_and(|request| request.supported_native_session)
    }

    pub(super) fn request_for_dataset(
        &self,
        profile: ModelProfile,
        mode: Mode,
        dataset: &Path,
    ) -> Result<Request> {
        let mut request = self.request(profile)?;
        if mode == Mode::PrivateConversation {
            let raw = super::read_file(
                dataset,
                super::private_conversation::request_frame(profile) as u64,
            )?;
            let input = super::private_conversation::Input::decode_profile(&raw, profile)?;
            request.select_constraint(&input)?;
        }
        Ok(request)
    }

    pub(super) fn request(&self, profile: ModelProfile) -> Result<Request> {
        let (root, hash) = match (&self.native_backend_root, &self.native_backend_sha256) {
            (None, None) => return Ok(Request::default()),
            (Some(root), Some(hash)) => (root, hash),
            _ => anyhow::bail!("compute_native_backend_authorization"),
        };
        ensure!(
            profile == ModelProfile::Qwen4bInstruct2507 && super::is_hex(hash, 64),
            "compute_native_backend_authorization"
        );
        super::private_directory(root)?;
        let raw = super::read_file(&root.join("backend.json"), 16 * 1024)?;
        ensure!(
            hex::encode(Sha256::digest(&raw)) == *hash,
            "compute_native_backend_manifest_hash"
        );
        let manifest: Manifest = serde_json::from_slice(&raw)
            .map_err(|_| anyhow::anyhow!("compute_native_backend_manifest_schema"))?;
        manifest.validate()?;
        for artifact in [&manifest.library, &manifest.gguf] {
            let info = fs::symlink_metadata(root.join(&artifact.path))?;
            ensure!(
                info.is_file()
                    && info.uid() == nix::unistd::geteuid().as_raw()
                    && info.nlink() == 1
                    && info.mode().trailing_zeros() >= 6
                    && info.len() == artifact.bytes,
                "compute_native_backend_file"
            );
        }
        // The fixed isolated worker verifies both complete artifact hashes and
        // build provenance before dlopen. No native library is loaded by the core.
        Ok(Request {
            inference_backend: Some(KIND),
            native_backend_root: Some("/native-backend"),
            native_backend_sha256: Some(hash.clone()),
            expected_report: Some(manifest.report(hash)),
            supported_output_constraint: manifest
                .output_constraints
                .as_ref()
                .and_then(|values| values.first().copied()),
            output_constraint: None,
            output_constraint_tools: None,
            supported_native_session: manifest.version == 3,
        })
    }
}

#[derive(Default, Serialize)]
pub(super) struct Request {
    #[serde(skip_serializing_if = "Option::is_none")]
    inference_backend: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_backend_root: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_backend_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_constraint: Option<OutputConstraint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_constraint_tools: Option<Vec<String>>,
    #[serde(skip)]
    expected_report: Option<Value>,
    #[serde(skip)]
    supported_output_constraint: Option<OutputConstraint>,
    #[serde(skip)]
    supported_native_session: bool,
}

impl Request {
    #[cfg(test)]
    pub(super) fn cache_hint(&self, options: &Options, profile: ModelProfile) -> Option<CacheHint> {
        self.cache_hint_observed(options, profile).hint
    }

    pub(super) fn cache_hint_observed(&self, options: &Options, profile: ModelProfile) -> Binding {
        if profile != ModelProfile::Qwen4bInstruct2507
            || self.inference_backend != Some(KIND)
            || self.native_backend_sha256 != options.native_backend_sha256
        {
            return Binding::unavailable("not_applicable");
        }
        let Some(root) = options.native_backend_root.as_ref() else {
            return Binding::unavailable("not_applicable");
        };
        let Some(bytes) = self
            .expected_report
            .as_ref()
            .and_then(|report| report.get("gguf_bytes"))
            .and_then(Value::as_u64)
        else {
            return Binding::unavailable("not_applicable");
        };
        match CacheHint::bind_observed(root, bytes) {
            Ok(hint) => Binding {
                hint: Some(hint),
                reason: "bound",
            },
            Err(reason) => Binding::unavailable(reason),
        }
    }

    fn select_constraint(&mut self, input: &super::private_conversation::Input) -> Result<()> {
        if let Some(constraint) = input.output_constraint() {
            ensure!(
                self.enabled() && self.supported_output_constraint == Some(constraint),
                "compute_native_backend_output_constraint"
            );
        }
        self.output_constraint = input.output_constraint();
        self.output_constraint_tools = input.output_constraint_tools();
        Ok(())
    }

    pub(super) fn enabled(&self) -> bool {
        self.inference_backend.is_some()
    }

    pub(super) fn check_report(&self, value: &Value) -> Result<()> {
        ensure!(
            value.get("inference_backend") == self.expected_report.as_ref(),
            "compute_native_backend_result_binding"
        );
        let expected_constraint = self.output_constraint.map(|constraint| json!(constraint));
        ensure!(
            value.get("output_constraint") == expected_constraint.as_ref()
                && value.get("output_constraint_tools").is_none(),
            "compute_native_backend_output_constraint_binding"
        );
        if self.enabled() {
            ensure!(
                value["model_parameter_dtype"] == "bf16_with_exact_f32_norms"
                    && value["model_attention_backend"] == "llama_cpp_cpu",
                "compute_native_backend_result_precision"
            );
        }
        Ok(())
    }
}

/// Preserve the existing post-supervisor advisories, once after the whole
/// connection-owned process has joined, never after a still-resident turn.
pub(super) struct SessionHints {
    gguf: Binding,
    source: source_weight_cache::Binding,
    profile: ModelProfile,
    diagnostic: bool,
}

impl SessionHints {
    pub(super) fn bind(request: &Request, options: &super::Options) -> Self {
        Self {
            gguf: request.cache_hint_observed(&options.native_backend, options.model_profile),
            source: source_weight_cache::Binding::bind(
                request,
                &options.native_backend,
                options.model_profile,
                &options.model_root,
            ),
            profile: options.model_profile,
            diagnostic: true,
        }
    }

    pub(super) fn finish(self, result: &Result<Value>) {
        self.gguf
            .after_supervisor(result, self.profile, self.diagnostic);
        self.source.after_supervisor(result, self.diagnostic);
    }
}

#[cfg(test)]
mod tests;
