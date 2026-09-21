//! Exact, owner-selected inference profiles; never permission to download model code.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// Supported fixed model identities and their bounded public inference contracts.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub enum ModelProfile {
    /// Historical 135M profile; omitted selectors retain its exact existing encoding.
    #[default]
    #[serde(rename = "smollm2-135m-v1")]
    Default135,
    /// Explicit, inference-only 360M profile. Existing 135M adapters are incompatible.
    #[serde(rename = "smollm2-360m-v1")]
    Smol360,
}

/// Immutable identity and bounds, not values supplied by a remote model provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelSpec {
    /// Exact upstream model name.
    pub model_id: &'static str,
    /// Exact upstream source revision.
    pub revision: &'static str,
    /// Original encoded `model.safetensors` length.
    pub weights_bytes: u64,
    /// Lowercase SHA-256 of those complete original weight bytes.
    pub weights_sha256: &'static str,
    /// Maximum input tokens for ordinary inference under this profile.
    pub prompt_tokens: u16,
    /// Maximum generated tokens for each inference row.
    pub max_new_tokens: u16,
    /// Maximum bytes in one answer's ASCII-escaped JSON string, including quotes.
    pub max_output_bytes: usize,
    /// Maximum rows admitted to one executing job, not a signed package-size limit.
    pub max_rows: u16,
}

impl ModelProfile {
    /// Whether serializing this selector may omit the historical default field.
    pub const fn is_default(&self) -> bool {
        matches!(self, Self::Default135)
    }

    /// Return the fixed identity and execution bounds of this explicit profile.
    pub const fn spec(self) -> ModelSpec {
        match self {
            Self::Default135 => ModelSpec {
                model_id: crate::agent_artifact::MODEL_ID,
                revision: crate::agent_artifact::MODEL_REVISION,
                weights_bytes: 269_060_552,
                weights_sha256: "5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c",
                prompt_tokens: 192,
                max_new_tokens: 64,
                max_output_bytes: 1024,
                max_rows: 4,
            },
            Self::Smol360 => ModelSpec {
                model_id: "HuggingFaceTB/SmolLM2-360M-Instruct",
                revision: "a10cc1512eabd3dde888204e902eca88bddb4951",
                weights_bytes: 723_674_912,
                weights_sha256: "e6bffe7435d7ddc10fd3b9a9efd429dafbacb1cb17015fb5562664e7532bf86e",
                prompt_tokens: 1024,
                max_new_tokens: 256,
                max_output_bytes: 4096,
                max_rows: 1,
            },
        }
    }

    /// Recognize only a complete exact supported base identity, never a similar model name.
    pub fn from_identity(id: &str, revision: &str, bytes: u64, sha: &str) -> Option<Self> {
        [Self::Default135, Self::Smol360]
            .into_iter()
            .find(|profile| {
                let spec = profile.spec();
                id == spec.model_id
                    && revision == spec.revision
                    && bytes == spec.weights_bytes
                    && sha == spec.weights_sha256
            })
    }
}

impl fmt::Display for ModelProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Default135 => "smollm2-135m-v1",
            Self::Smol360 => "smollm2-360m-v1",
        })
    }
}

impl FromStr for ModelProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "smollm2-135m-v1" => Ok(Self::Default135),
            "smollm2-360m-v1" => Ok(Self::Smol360),
            _ => Err("unsupported model profile"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_and_historical_default_are_exact() {
        assert!(ModelProfile::default().is_default());
        for profile in [ModelProfile::Default135, ModelProfile::Smol360] {
            let name = profile.to_string();
            assert_eq!(name.parse::<ModelProfile>().unwrap(), profile);
            assert_eq!(
                serde_json::to_string(&profile).unwrap(),
                format!("\"{name}\"")
            );
            assert_eq!(
                serde_json::from_str::<ModelProfile>(&format!("\"{name}\"")).unwrap(),
                profile
            );
        }
        for invalid in ["", "smollm2-360m", "SMOLLM2-360M-V1", "smollm2-360m-v2"] {
            assert!(invalid.parse::<ModelProfile>().is_err());
            assert!(serde_json::from_str::<ModelProfile>(&format!("\"{invalid}\"")).is_err());
        }
        assert_eq!(
            ModelProfile::Default135.spec().weights_sha256,
            hex::encode(crate::agent_artifact::BASE_MODEL_SHA256)
        );
    }

    #[test]
    fn recognition_requires_all_identity_components_and_preserves_distinct_bounds() {
        for profile in [ModelProfile::Default135, ModelProfile::Smol360] {
            let spec = profile.spec();
            assert_eq!(
                ModelProfile::from_identity(
                    spec.model_id,
                    spec.revision,
                    spec.weights_bytes,
                    spec.weights_sha256
                ),
                Some(profile)
            );
            for (id, revision, bytes, sha) in [
                (
                    "different",
                    spec.revision,
                    spec.weights_bytes,
                    spec.weights_sha256,
                ),
                (
                    spec.model_id,
                    "different",
                    spec.weights_bytes,
                    spec.weights_sha256,
                ),
                (
                    spec.model_id,
                    spec.revision,
                    spec.weights_bytes + 1,
                    spec.weights_sha256,
                ),
                (
                    spec.model_id,
                    spec.revision,
                    spec.weights_bytes,
                    "different",
                ),
            ] {
                assert_eq!(ModelProfile::from_identity(id, revision, bytes, sha), None);
            }
        }
        let old = ModelProfile::Default135.spec();
        let new = ModelProfile::Smol360.spec();
        assert_eq!(
            (
                old.prompt_tokens,
                old.max_new_tokens,
                old.max_output_bytes,
                old.max_rows
            ),
            (192, 64, 1024, 4)
        );
        assert_eq!(
            (
                new.prompt_tokens,
                new.max_new_tokens,
                new.max_output_bytes,
                new.max_rows
            ),
            (1024, 256, 4096, 1)
        );
    }
}
