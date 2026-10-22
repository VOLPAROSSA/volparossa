//! Optional reviewed-byte binding before any publication credentials or mutable outputs.

use std::{
    fs::File,
    io::{self, Read},
};

use anyhow::{Result, bail};
use sha2::{Digest as _, Sha256};
use volparossa_content::MAX_OBJECT_BYTES;
use zeroize::Zeroizing;

pub(super) struct Input {
    source: Source,
}

enum Source {
    Streaming(File),
    Reviewed {
        bytes: Zeroizing<Vec<u8>>,
        offset: usize,
    },
}

impl Input {
    pub(super) fn new(mut file: File, length: u64, expected: Option<[u8; 32]>) -> Result<Self> {
        let Some(expected) = expected else {
            return Ok(Self {
                source: Source::Streaming(file),
            });
        };
        if length > MAX_OBJECT_BYTES {
            bail!("content input snapshot exceeds the object size limit");
        }
        let length = usize::try_from(length)
            .map_err(|_| anyhow::anyhow!("content input snapshot exceeds the object size limit"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| anyhow::anyhow!("cannot allocate bounded content input snapshot"))?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| anyhow::anyhow!("cannot read exact content input snapshot"))?;
        let mut extra = Zeroizing::new([0; 1]);
        if file
            .read(&mut *extra)
            .map_err(|_| anyhow::anyhow!("cannot read exact content input snapshot"))?
            != 0
        {
            bail!("content input snapshot exceeds its declared length");
        }
        if <[u8; 32]>::from(Sha256::digest(&*bytes)) != expected {
            bail!("content input does not match the expected SHA-256");
        }
        // Only the snapshot survives this branch: signing cannot reread a mutable source file.
        Ok(Self {
            source: Source::Reviewed { bytes, offset: 0 },
        })
    }
}

impl Read for Input {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match &mut self.source {
            Source::Streaming(file) => file.read(output),
            Source::Reviewed { bytes, offset } => {
                let count = (&bytes[*offset..]).read(output)?;
                *offset += count;
                Ok(count)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_snapshot_survives_original_file_mutation_and_signs_only_checked_bytes() {
        use volparossa_content::{
            CacheLimits, ChunkStore, Metadata, Publication, Validity, publish, reassemble,
        };
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("input");
        let original = b"reviewed bytes before the source changed";
        std::fs::write(&path, original).unwrap();
        let file = super::super::open_regular(&path, MAX_OBJECT_BYTES).unwrap();
        let expected: [u8; 32] = Sha256::digest(original).into();
        let mut input = Input::new(file, original.len() as u64, Some(expected)).unwrap();
        std::fs::write(
            &path,
            b"different longer bytes after review and before signing",
        )
        .unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[47; 32]);
        let mut store = ChunkStore::create(
            &root.path().join("cache"),
            CacheLimits {
                max_bytes: 1024,
                max_entries: 4,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let manifest = publish(
            &mut input,
            Publication {
                metadata: Metadata {
                    name: "snapshot".into(),
                    revision: 1,
                    content_type: "application/octet-stream".into(),
                },
                length: original.len() as u64,
                validity: Validity {
                    created: 1000,
                    expires: 1100,
                },
            },
            &signer,
            &mut store,
        )
        .unwrap();
        let verified = manifest.verify(&signer.verifying_key(), 1000).unwrap();
        assert_eq!(verified.object_sha256(), &expected);
        let mut output = Vec::new();
        reassemble(&verified, &mut [&mut store], 1000, &mut output).unwrap();
        assert_eq!(output, original);
    }

    #[test]
    fn unpinned_input_remains_streaming_without_a_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("input");
        std::fs::write(&path, b"before").unwrap();
        let file = super::super::open_regular(&path, MAX_OBJECT_BYTES).unwrap();
        let mut input = Input::new(file, 6, None).unwrap();
        assert!(matches!(input.source, Source::Streaming(_)));
        std::fs::write(&path, b"after!").unwrap();
        let mut output = Vec::new();
        input.read_to_end(&mut output).unwrap();
        assert_eq!(output, b"after!");
    }

    #[test]
    fn snapshot_rejects_oversize_before_reading_and_bounds_growing_input_to_one_extra_byte() {
        use std::io::Seek as _;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("input");
        std::fs::write(&path, b"abc").unwrap();
        let file = super::super::open_regular(&path, MAX_OBJECT_BYTES).unwrap();
        let mut position = file.try_clone().unwrap();
        let result = Input::new(file, MAX_OBJECT_BYTES + 1, Some([0; 32]));
        assert_eq!(
            result.err().unwrap().to_string(),
            "content input snapshot exceeds the object size limit"
        );
        assert_eq!(position.stream_position().unwrap(), 0);
        let file = super::super::open_regular(&path, MAX_OBJECT_BYTES).unwrap();
        let length = file.metadata().unwrap().len();
        let mut position = file.try_clone().unwrap();
        std::fs::write(&path, [0x41; 1024]).unwrap();
        let result = Input::new(file, length, Some(Sha256::digest(b"abc").into()));
        assert_eq!(
            result.err().unwrap().to_string(),
            "content input snapshot exceeds its declared length"
        );
        assert_eq!(position.stream_position().unwrap(), length + 1);
    }

    #[test]
    fn snapshot_rejects_truncation_after_metadata_and_empty_input_growth() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("input");
        for (before, after, message) in [
            (
                &b"abc"[..],
                &b"ab"[..],
                "cannot read exact content input snapshot",
            ),
            (
                &b""[..],
                &b"x"[..],
                "content input snapshot exceeds its declared length",
            ),
        ] {
            std::fs::write(&path, before).unwrap();
            let file = super::super::open_regular(&path, MAX_OBJECT_BYTES).unwrap();
            let length = file.metadata().unwrap().len();
            std::fs::write(&path, after).unwrap();
            let result = Input::new(file, length, Some(Sha256::digest(before).into()));
            assert_eq!(result.err().unwrap().to_string(), message);
        }
        let oversized = File::create(&path).unwrap();
        oversized.set_len(MAX_OBJECT_BYTES + 1).unwrap();
        assert!(super::super::open_regular(&path, MAX_OBJECT_BYTES).is_err());
    }
}
