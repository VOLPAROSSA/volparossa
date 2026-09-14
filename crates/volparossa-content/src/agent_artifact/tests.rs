use super::*;

fn files() -> AdapterFiles {
    AdapterFiles {
        config: br#"{"synthetic_codec_fixture":true}"#.to_vec(),
        // Codec fixtures are opaque bytes, not claimed to be trained/safe model weights.
        weights: vec![0x39; crate::CHUNK_BYTES + 73],
        readme: b"Synthetic adapter codec fixture; no model execution.\n".to_vec(),
    }
}

fn split(encoded: &[u8]) -> (Index, Vec<u8>) {
    let length = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize;
    (
        Index::decode(&encoded[4..4 + length]).unwrap(),
        encoded[4 + length..].to_vec(),
    )
}

fn join(index: &Index, payload: &[u8]) -> Vec<u8> {
    let index = index.encode_to_vec();
    let mut encoded = u32::try_from(index.len()).unwrap().to_be_bytes().to_vec();
    encoded.extend_from_slice(&index);
    encoded.extend_from_slice(payload);
    encoded
}

#[test]
fn roundtrip_preserves_exact_files_profile_and_dataset_binding() {
    let encoded = AdapterBundle::encode([7; 32], files()).unwrap();
    assert_eq!(encoded, AdapterBundle::encode([7; 32], files()).unwrap());
    let bundle = AdapterBundle::decode(encoded.clone()).unwrap();
    let original = files();
    assert_eq!(bundle.config(), original.config);
    assert_eq!(bundle.weights(), original.weights);
    assert_eq!(bundle.readme(), original.readme);
    assert_eq!(bundle.dataset_manifest_id(), [7; 32]);
    assert_eq!(bundle.encoded(), encoded);
    let (index, _) = split(&encoded);
    assert_eq!(
        index
            .files
            .iter()
            .map(|file| file.name.as_str())
            .collect::<Vec<_>>(),
        FILENAMES
    );
    assert_eq!(index.model_id, MODEL_ID);
    assert_eq!(index.model_revision, MODEL_REVISION);
    assert_eq!(index.target_modules, TARGET_MODULES);
    assert_eq!(
        hex::encode(index.base_sha256),
        "5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c"
    );
}

#[test]
fn native_signature_and_chunks_authenticate_the_complete_adapter_separately() {
    use crate::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

    let root = tempfile::tempdir().unwrap();
    let mut cache = ChunkStore::create(
        &root.path().join("cache"),
        CacheLimits {
            max_bytes: 2 * 1024 * 1024,
            max_entries: 16,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let encoded = AdapterBundle::encode([17; 32], files()).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
    let envelope = crate::publish(
        &mut encoded.as_slice(),
        Publication {
            metadata: Metadata {
                name: "public-doc-adapter".to_owned(),
                revision: 1,
                content_type: ADAPTER_CONTENT_TYPE.to_owned(),
            },
            length: u64::try_from(encoded.len()).unwrap(),
            validity: Validity {
                created: 100,
                expires: 200,
            },
        },
        &signer,
        &mut cache,
    )
    .unwrap();
    let manifest = envelope.verify(&signer.verifying_key(), 101).unwrap();
    assert_eq!(manifest.chunks().len(), 2);
    assert_eq!(manifest.metadata().content_type, ADAPTER_CONTENT_TYPE);
    let mut recovered = Vec::new();
    crate::reassemble(&manifest, &mut [&mut cache], 101, &mut recovered).unwrap();
    assert_eq!(recovered, encoded);
    assert_eq!(
        AdapterBundle::decode(recovered)
            .unwrap()
            .dataset_manifest_id(),
        [17; 32]
    );
    let other = ed25519_dalek::SigningKey::from_bytes(&[24; 32]);
    assert!(envelope.verify(&other.verifying_key(), 101).is_err());
    assert!(envelope.verify(&signer.verifying_key(), 200).is_err());
}

#[test]
fn rejects_changed_profile_paths_layout_hashes_and_noncanonical_index() {
    type Mutation = fn(&mut Index);
    let mutations: &[Mutation] = &[
        |index| index.version = 2,
        |index| index.model_id.push_str("-other"),
        |index| index.model_revision.replace_range(..1, "9"),
        |index| index.base_sha256[0] ^= 1,
        |index| index.rank = 8,
        |index| index.alpha = 16,
        |index| index.target_modules.reverse(),
        |index| index.target_modules.push("executable".to_owned()),
        |index| index.dataset_manifest_id.fill(0),
        |index| {
            index.dataset_manifest_id.pop();
        },
        |index| index.files[0].name = "../README.md".to_owned(),
        |index| index.files[1].name = "README.md".to_owned(),
        |index| index.files.swap(0, 1),
        |index| {
            index.files.pop();
        },
        |index| index.files.push(index.files[2].clone()),
        |index| index.files[0].offset = 1,
        |index| index.files[1].offset += 1,
        |index| index.files[1].offset -= 1,
        |index| index.files[2].length = u64::MAX,
        |index| index.files[2].sha256[0] ^= 1,
    ];
    let encoded = AdapterBundle::encode([7; 32], files()).unwrap();
    for mutation in mutations {
        let (mut index, payload) = split(&encoded);
        mutation(&mut index);
        assert!(AdapterBundle::decode(join(&index, &payload)).is_err());
    }
    let (index, payload) = split(&encoded);
    for unknown_or_duplicate in [vec![0x08, 0x01], vec![0x50, 0x01]] {
        let mut wire = index.encode_to_vec();
        wire.extend_from_slice(&unknown_or_duplicate);
        let mut noncanonical = u32::try_from(wire.len()).unwrap().to_be_bytes().to_vec();
        noncanonical.extend_from_slice(&wire);
        noncanonical.extend_from_slice(&payload);
        assert_eq!(
            AdapterBundle::decode(noncanonical).unwrap_err(),
            AdapterError::Encoding
        );
    }
    let mut corrupt = encoded.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(
        AdapterBundle::decode(corrupt).unwrap_err(),
        AdapterError::Integrity
    );
    let mut extra = encoded.clone();
    extra.push(0);
    assert_eq!(
        AdapterBundle::decode(extra).unwrap_err(),
        AdapterError::Encoding
    );
    assert!(AdapterBundle::decode(encoded[..encoded.len() - 1].to_vec()).is_err());
}

#[test]
fn rejects_empty_or_oversized_files_and_indexes_before_payload_parsing() {
    assert_eq!(
        AdapterBundle::encode([0; 32], files()).unwrap_err(),
        AdapterError::Encoding
    );
    for (position, maximum) in FILE_LIMITS.iter().enumerate() {
        for length in [0, maximum + 1] {
            let mut inputs = files();
            match position {
                0 => inputs.readme = vec![0; length],
                1 => inputs.config = vec![0; length],
                2 => inputs.weights = vec![0; length],
                _ => unreachable!(),
            }
            assert_eq!(
                AdapterBundle::encode([7; 32], inputs).unwrap_err(),
                AdapterError::Limit
            );
        }
    }
    assert_eq!(
        AdapterBundle::decode(vec![0; MAX_ADAPTER_BYTES + 1]).unwrap_err(),
        AdapterError::Limit
    );
    let oversized = u32::try_from(MAX_INDEX_BYTES + 1)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    assert_eq!(
        AdapterBundle::decode(oversized).unwrap_err(),
        AdapterError::Limit
    );
    assert_eq!(
        AdapterBundle::decode(vec![0; 4]).unwrap_err(),
        AdapterError::Limit
    );
    assert_eq!(
        AdapterBundle::decode(vec![0; 3]).unwrap_err(),
        AdapterError::Encoding
    );
}
