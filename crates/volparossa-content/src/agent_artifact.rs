//! Fixed, bounded data bundle for the initial CPU worker's compatible public adapter.
//!
//! The outer native signed manifest must independently authenticate the publisher, complete
//! object and validity. This codec verifies structure and hashes, not dataset eligibility,
//! tensor/configuration safety, training provenance, model quality or execution permission.
//! Only the separately isolated fixed worker may interpret the three data files. No archive
//! paths, operators, runtime code, filesystem extraction or model activation are accepted here.

use std::ops::Range;

use prost::Message;
use sha2::{Digest, Sha256};

/// Native content type for this fixed adapter object, not a website or executable package.
pub const ADAPTER_CONTENT_TYPE: &str = "application/vnd.volparossa.adapter.v1";
/// Maximum complete encoded adapter object; the general native object limit stays unchanged.
pub const MAX_ADAPTER_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encoded adapter weights, independent of the complete-object bound.
pub const MAX_ADAPTER_WEIGHT_BYTES: usize = 2 * 1024 * 1024;
/// Maximum bytes of either the original adapter config or README.
pub const MAX_ADAPTER_METADATA_BYTES: usize = 16 * 1024;
/// Exact supported base model; fetching a bundle never downloads its runtime or base weights.
pub const MODEL_ID: &str = "HuggingFaceTB/SmolLM2-135M-Instruct";
/// Exact upstream revision of the supported base model.
pub const MODEL_REVISION: &str = "83212e1e2b3cfd6958f3707877bb878945dea8ee";
/// SHA-256 of the original base model.safetensors, not a tensor or adapter hash.
pub const BASE_MODEL_SHA256: [u8; 32] = [
    0x5a, 0xf5, 0x71, 0xcb, 0xf0, 0x74, 0xe6, 0xd2, 0x1a, 0x03, 0x52, 0x8d, 0x23, 0x30, 0x79, 0x2e,
    0x53, 0x2c, 0xa6, 0x08, 0xf2, 0x4a, 0xc7, 0x0a, 0x14, 0x3f, 0x6b, 0x36, 0x99, 0x68, 0xab, 0x8c,
];
const VERSION: u32 = 1;
const RANK: u32 = 4;
const ALPHA: u32 = 8;
const TARGET_MODULES: [&str; 2] = ["q_proj", "v_proj"];
const MAX_INDEX_BYTES: usize = 4096;
const FILENAMES: [&str; 3] = [
    "README.md",
    "adapter_config.json",
    "adapter_model.safetensors",
];
const FILE_LIMITS: [usize; 3] = [
    MAX_ADAPTER_METADATA_BYTES,
    MAX_ADAPTER_METADATA_BYTES,
    MAX_ADAPTER_WEIGHT_BYTES,
];

/// Explicit bytes produced by the supported worker, not a directory to recursively publish.
pub struct AdapterFiles {
    /// Original `adapter_config.json`. Its semantic validation belongs to the fixed worker.
    pub config: Vec<u8>,
    /// Original `adapter_model.safetensors`. No pickle or operator code is interpreted here.
    pub weights: Vec<u8>,
    /// Original README.md, retained as uninterpreted model-card/provenance data.
    pub readme: Vec<u8>,
}

/// Fixed errors without caller-controlled filenames, model descriptions or data.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterError {
    /// Object, index or file length exceeds its independent limit.
    #[error("adapter object resource limit exceeded")]
    Limit,
    /// Noncanonical framing, unknown fields, file layout or required metadata is invalid.
    #[error("invalid adapter object encoding")]
    Encoding,
    /// The object does not describe the one supported base model and `LoRA` profile.
    #[error("unsupported adapter model profile")]
    Model,
    /// A required file's bytes do not match its indexed SHA-256.
    #[error("adapter object file integrity failure")]
    Integrity,
}

#[derive(Clone, PartialEq, Message)]
struct Index {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(string, tag = "2")]
    model_id: String,
    #[prost(string, tag = "3")]
    model_revision: String,
    #[prost(bytes = "vec", tag = "4")]
    base_sha256: Vec<u8>,
    #[prost(uint32, tag = "5")]
    rank: u32,
    #[prost(uint32, tag = "6")]
    alpha: u32,
    #[prost(string, repeated, tag = "7")]
    target_modules: Vec<String>,
    #[prost(bytes = "vec", tag = "8")]
    dataset_manifest_id: Vec<u8>,
    #[prost(message, repeated, tag = "9")]
    files: Vec<Entry>,
}

#[derive(Clone, PartialEq, Message)]
struct Entry {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(uint64, tag = "2")]
    offset: u64,
    #[prost(uint64, tag = "3")]
    length: u64,
    #[prost(bytes = "vec", tag = "4")]
    sha256: Vec<u8>,
}

/// Structurally checked immutable bytes; this type grants no publisher or model authority.
#[derive(Debug)]
pub struct AdapterBundle {
    encoded: Vec<u8>,
    dataset_manifest_id: [u8; 32],
    files: [Range<usize>; 3],
}

impl AdapterBundle {
    /// Encode exactly three sorted files, a fixed profile and an exact original dataset ID.
    ///
    /// Format: four-byte big-endian canonical protobuf-index length, Index, then consecutive
    /// file bytes. Offsets refer to the payload start. No caller-supplied filename is accepted.
    ///
    /// # Errors
    /// Rejects a zero dataset ID, empty/oversized files, index/object limits or allocation failure.
    pub fn encode(
        dataset_manifest_id: [u8; 32],
        files: AdapterFiles,
    ) -> Result<Vec<u8>, AdapterError> {
        if dataset_manifest_id == [0; 32] {
            return Err(AdapterError::Encoding);
        }
        let files = [files.readme, files.config, files.weights];
        let mut index = Index {
            version: VERSION,
            model_id: MODEL_ID.to_owned(),
            model_revision: MODEL_REVISION.to_owned(),
            base_sha256: BASE_MODEL_SHA256.to_vec(),
            rank: RANK,
            alpha: ALPHA,
            target_modules: TARGET_MODULES.map(str::to_owned).to_vec(),
            dataset_manifest_id: dataset_manifest_id.to_vec(),
            files: Vec::with_capacity(FILENAMES.len()),
        };
        let mut payload_length = 0_usize;
        for (position, file) in files.iter().enumerate() {
            check_file_length(file.len(), FILE_LIMITS[position])?;
            index.files.push(Entry {
                name: FILENAMES[position].to_owned(),
                offset: u64::try_from(payload_length).map_err(|_| AdapterError::Limit)?,
                length: u64::try_from(file.len()).map_err(|_| AdapterError::Limit)?,
                sha256: Sha256::digest(file).to_vec(),
            });
            payload_length = payload_length
                .checked_add(file.len())
                .ok_or(AdapterError::Limit)?;
        }
        let header = index.encode_to_vec();
        let length = 4_usize
            .checked_add(header.len())
            .and_then(|value| value.checked_add(payload_length))
            .filter(|value| *value <= MAX_ADAPTER_BYTES)
            .ok_or(AdapterError::Limit)?;
        if header.len() > MAX_INDEX_BYTES {
            return Err(AdapterError::Limit);
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(length)
            .map_err(|_| AdapterError::Limit)?;
        encoded.extend_from_slice(
            &u32::try_from(header.len())
                .map_err(|_| AdapterError::Limit)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&header);
        for file in files {
            encoded.extend_from_slice(&file);
        }
        Ok(encoded)
    }

    /// Verify canonical fixed metadata, exact file boundaries and every file hash.
    ///
    /// # Errors
    /// Rejects oversized/noncanonical data, unknown profile, zero dataset ID, missing/extra
    /// files, gaps/overlaps, trailing/truncated bytes and corrupted file payloads.
    pub fn decode(encoded: Vec<u8>) -> Result<Self, AdapterError> {
        if encoded.len() > MAX_ADAPTER_BYTES {
            return Err(AdapterError::Limit);
        }
        let length: [u8; 4] = encoded
            .get(..4)
            .ok_or(AdapterError::Encoding)?
            .try_into()
            .map_err(|_| AdapterError::Encoding)?;
        let index_length =
            usize::try_from(u32::from_be_bytes(length)).map_err(|_| AdapterError::Limit)?;
        if index_length == 0 || index_length > MAX_INDEX_BYTES {
            return Err(AdapterError::Limit);
        }
        let payload_start = 4 + index_length;
        let wire = encoded
            .get(4..payload_start)
            .ok_or(AdapterError::Encoding)?;
        let index = Index::decode(wire).map_err(|_| AdapterError::Encoding)?;
        if index.version != VERSION || index.encode_to_vec() != wire || index.files.len() != 3 {
            return Err(AdapterError::Encoding);
        }
        if index.model_id != MODEL_ID
            || index.model_revision != MODEL_REVISION
            || index.base_sha256 != BASE_MODEL_SHA256
            || index.rank != RANK
            || index.alpha != ALPHA
            || index.target_modules != TARGET_MODULES
        {
            return Err(AdapterError::Model);
        }
        let dataset_manifest_id: [u8; 32] = index
            .dataset_manifest_id
            .as_slice()
            .try_into()
            .map_err(|_| AdapterError::Encoding)?;
        if dataset_manifest_id == [0; 32] {
            return Err(AdapterError::Encoding);
        }
        let mut files = [0..0, 0..0, 0..0];
        let mut end = payload_start;
        for (position, entry) in index.files.iter().enumerate() {
            if entry.name != FILENAMES[position]
                || usize::try_from(entry.offset).map_err(|_| AdapterError::Limit)?
                    != end - payload_start
            {
                return Err(AdapterError::Encoding);
            }
            let size = usize::try_from(entry.length).map_err(|_| AdapterError::Limit)?;
            check_file_length(size, FILE_LIMITS[position])?;
            let start = end;
            end = start
                .checked_add(size)
                .filter(|end| *end <= encoded.len())
                .ok_or(AdapterError::Encoding)?;
            if entry.sha256.as_slice() != Sha256::digest(&encoded[start..end]).as_slice() {
                return Err(AdapterError::Integrity);
            }
            files[position] = start..end;
        }
        if end != encoded.len() {
            return Err(AdapterError::Encoding);
        }
        Ok(Self {
            encoded,
            dataset_manifest_id,
            files,
        })
    }

    /// Original signed public dataset manifest ID; callers separately verify its publisher/TTL.
    pub const fn dataset_manifest_id(&self) -> [u8; 32] {
        self.dataset_manifest_id
    }

    /// Original adapter config bytes; not authorization to interpret arbitrary PEFT settings.
    pub fn config(&self) -> &[u8] {
        &self.encoded[self.files[1].clone()]
    }

    /// Original safetensors bytes; fixed-worker shape/value validation remains required.
    pub fn weights(&self) -> &[u8] {
        &self.encoded[self.files[2].clone()]
    }

    /// Original README, retained without evaluating markup or its instructions.
    pub fn readme(&self) -> &[u8] {
        &self.encoded[self.files[0].clone()]
    }

    /// Exact canonical complete object, suitable for the existing native chunk protocol.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

fn check_file_length(length: usize, maximum: usize) -> Result<(), AdapterError> {
    if length == 0 || length > maximum {
        return Err(AdapterError::Limit);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
