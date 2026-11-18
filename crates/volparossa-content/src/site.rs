//! Canonical multi-asset static-site objects, authenticated only by an outer native manifest.
//!
//! Decoding checks structure, not a publisher identity, HTTPS origin, filesystem path or script
//! safety. Callers must independently authenticate the complete object before exposing assets.
//! The codec performs no filesystem operations and cannot authorize following a symlink.

use std::{
    io::{self, Cursor, Read, Write},
    ops::Range,
};

use prost::Message;

use crate::MAX_OBJECT_BYTES;

/// Content type for the complete native static-site bundle, not its individual assets.
pub const SITE_CONTENT_TYPE: &str = "application/vnd.volparossa.site.v1";
/// Maximum assets in one bundle, including the required HTML entry point.
pub const MAX_SITE_ASSETS: usize = 256;
/// Maximum encoded protobuf index, checked before parsing it.
pub const MAX_SITE_INDEX_BYTES: usize = 256 * 1024;
/// Maximum bytes in a decoded, absolute asset path.
pub const MAX_SITE_PATH_BYTES: usize = 1024;
const MAX_MEDIA_TYPE_BYTES: usize = 128;
const VERSION: u32 = 1;

/// An explicitly supplied asset. Filesystem selection and symlink refusal belong to the caller.
pub struct SiteAsset {
    /// Exact absolute UTF-8 path; no URL escapes, query, fragment, hidden or empty segments.
    pub path: String,
    /// Lowercase ASCII type/subtype, without parameters or whitespace.
    pub content_type: String,
    /// Complete asset bytes; the aggregate bundle must fit the native object bound.
    pub bytes: Vec<u8>,
}

/// Source for one asset in a streaming bundle. Its length must match the readable bytes exactly.
pub struct SiteAssetSource<R> {
    /// Exact absolute UTF-8 path under the same rules as [`SiteAsset`].
    pub path: String,
    /// Lowercase ASCII type/subtype used in the bundle index.
    pub content_type: String,
    /// Expected byte count from the reader's current position through EOF.
    pub length: u64,
    /// Already selected source. The encoder never opens a path.
    pub reader: R,
}

/// Borrowed immutable asset contents, valid for the lifetime of its checked bundle.
#[derive(Debug)]
pub struct SiteAssetRef<'a> {
    /// Checked MIME type, not permission to inherit a publisher or HTTPS origin.
    pub content_type: &'a str,
    /// Exactly the indexed asset bytes.
    pub bytes: &'a [u8],
}

/// Structural errors carry no caller-controlled path, media type or content.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum SiteError {
    /// Asset count, index, path, media type, allocation or full-object limit was exceeded.
    #[error("static-site resource limit exceeded")]
    Limit,
    /// A path is not in the supported unambiguous absolute-path profile.
    #[error("invalid static-site asset path")]
    Path,
    /// An asset's media type is not a bounded lowercase type/subtype.
    #[error("invalid static-site media type")]
    MediaType,
    /// The canonical entry point is absent or does not use text/html.
    #[error("static-site HTML entry point missing")]
    MissingIndex,
    /// Version, protobuf canonicality, uniqueness, ordering or payload boundaries are invalid.
    #[error("invalid static-site bundle encoding")]
    Encoding,
    /// A source ended early or contained bytes past its declared length.
    #[error("static-site asset length changed")]
    AssetLength,
    /// Reading a source or writing the destination failed.
    #[error("static-site stream I/O failed ({0})")]
    Io(io::ErrorKind),
}

impl From<io::Error> for SiteError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

#[derive(Clone, PartialEq, Message)]
struct Index {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(message, repeated, tag = "2")]
    assets: Vec<Entry>,
}

#[derive(Clone, PartialEq, Message)]
struct Entry {
    #[prost(string, tag = "1")]
    path: String,
    #[prost(string, tag = "2")]
    content_type: String,
    #[prost(uint64, tag = "3")]
    offset: u64,
    #[prost(uint64, tag = "4")]
    length: u64,
}

struct AssetRange {
    path: String,
    content_type: String,
    bytes: Range<usize>,
}

/// Structurally checked, immutable index and bytes. This type conveys no origin authority.
pub struct SiteBundle {
    encoded: Vec<u8>,
    assets: Vec<AssetRange>,
}

impl SiteBundle {
    /// Sort and pack supplied assets into one deterministic versioned bundle.
    ///
    /// Format: four-byte big-endian protobuf-index length, canonical Index, then consecutive
    /// asset bytes in index order. Offsets are relative to the start of that payload.
    ///
    /// # Errors
    /// Rejects limits, invalid or duplicate paths/media types, and a missing HTML entry point.
    pub fn encode(assets: Vec<SiteAsset>) -> Result<Vec<u8>, SiteError> {
        let layout = SiteEncoding::prepare(assets.into_iter().map(|asset| SiteAssetSource {
            path: asset.path,
            content_type: asset.content_type,
            length: asset.bytes.len() as u64,
            reader: Cursor::new(asset.bytes),
        }))?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(usize::try_from(layout.total).map_err(|_| SiteError::Limit)?)
            .map_err(|_| SiteError::Limit)?;
        layout.write_to(&mut encoded)?;
        Ok(encoded)
    }

    /// Write a canonical bundle in sorted path order and return its encoded length.
    ///
    /// All declared paths, types, lengths and the entire index are checked before I/O.
    /// Each source is copied through EOF with bounded memory. On a stream error the
    /// destination may contain a prefix; use a temporary output for atomic publication.
    ///
    /// # Errors
    /// Rejects invalid geometry, short or oversized input and read or write failures.
    pub fn write_to<R: Read, W: Write>(
        assets: Vec<SiteAssetSource<R>>,
        output: &mut W,
    ) -> Result<u64, SiteError> {
        SiteEncoding::prepare(assets.into_iter())?.write_to(output)
    }

    /// Validate canonical framing and retain exact immutable payload ranges without copying it.
    ///
    /// # Errors
    /// Rejects limits, noncanonical indexes, unsupported versions, invalid metadata, gaps,
    /// overlaps, trailing/truncated bytes, and a missing HTML entry point.
    pub fn decode(encoded: Vec<u8>) -> Result<Self, SiteError> {
        let assets = Self::asset_ranges(&encoded, encoded.len())?;
        Ok(Self { encoded, assets })
    }

    fn asset_ranges(prefix: &[u8], total: usize) -> Result<Vec<AssetRange>, SiteError> {
        if u64::try_from(total).map_err(|_| SiteError::Limit)? > MAX_OBJECT_BYTES {
            return Err(SiteError::Limit);
        }
        let header: [u8; 4] = prefix
            .get(..4)
            .ok_or(SiteError::Encoding)?
            .try_into()
            .map_err(|_| SiteError::Encoding)?;
        let index_bytes =
            usize::try_from(u32::from_be_bytes(header)).map_err(|_| SiteError::Limit)?;
        if index_bytes == 0 || index_bytes > MAX_SITE_INDEX_BYTES {
            return Err(SiteError::Limit);
        }
        let payload_start = 4 + index_bytes;
        let wire = prefix.get(4..payload_start).ok_or(SiteError::Encoding)?;
        let index = decode_index(wire)?;
        if index.version != VERSION || index.encode_to_vec() != wire {
            return Err(SiteError::Encoding);
        }
        if index.assets.is_empty() || index.assets.len() > MAX_SITE_ASSETS {
            return Err(SiteError::Limit);
        }
        require_html_index(&index)?;
        let mut assets = Vec::with_capacity(index.assets.len());
        let mut end = payload_start;
        for entry in index.assets {
            validate_path(&entry.path)?;
            validate_media_type(&entry.content_type)?;
            if assets
                .last()
                .is_some_and(|previous: &AssetRange| previous.path >= entry.path)
                || entry.offset
                    != u64::try_from(end - payload_start).map_err(|_| SiteError::Limit)?
            {
                return Err(SiteError::Encoding);
            }
            let start = end;
            end = end
                .checked_add(usize::try_from(entry.length).map_err(|_| SiteError::Limit)?)
                .filter(|end| *end <= total)
                .ok_or(SiteError::Encoding)?;
            assets.push(AssetRange {
                path: entry.path,
                content_type: entry.content_type,
                bytes: start..end,
            });
        }
        if end != total {
            return Err(SiteError::Encoding);
        }
        Ok(assets)
    }

    /// Exact path lookup; this does not URL-decode, normalize or access the filesystem.
    #[must_use]
    pub fn asset(&self, path: &str) -> Option<SiteAssetRef<'_>> {
        validate_path(path).ok()?;
        let index = self
            .assets
            .binary_search_by(|asset| asset.path.as_str().cmp(path))
            .ok()?;
        let asset = &self.assets[index];
        Some(SiteAssetRef {
            content_type: &asset.content_type,
            bytes: &self.encoded[asset.bytes.clone()],
        })
    }

    /// Number of checked assets, including the HTML entry point.
    #[must_use]
    pub fn asset_count(&self) -> usize {
        self.assets.len()
    }
}

/// Validate the layout of an authenticated stream without holding its asset payloads.
/// The native reassembler independently verifies chunk and complete object hashes.
#[derive(Default)]
pub struct SiteLayoutVerifier {
    prefix: Vec<u8>,
    total: usize,
}

impl SiteLayoutVerifier {
    /// Check the same canonical index and exact payload bounds as [`SiteBundle::decode`].
    ///
    /// # Errors
    /// Rejects malformed framing, index, asset metadata, and incorrect aggregate length.
    pub fn finish(self) -> Result<(), SiteError> {
        SiteBundle::asset_ranges(&self.prefix, self.total).map(|_| ())
    }
}

impl Write for SiteLayoutVerifier {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self
            .total
            .checked_add(bytes.len())
            .filter(|total| u64::try_from(*total).is_ok_and(|len| len <= MAX_OBJECT_BYTES))
            .ok_or(io::ErrorKind::InvalidData)?;
        let header = 4_usize.saturating_sub(self.prefix.len()).min(bytes.len());
        self.prefix.extend_from_slice(&bytes[..header]);
        if let Some(length) = self.prefix.first_chunk::<4>() {
            let size = u32::from_be_bytes(*length) as usize;
            // Invalid lengths are retained in the header for the canonical decoder.
            if size <= MAX_SITE_INDEX_BYTES {
                let remaining = (4 + size) - self.prefix.len();
                let take = remaining.min(bytes.len() - header);
                if take != 0 {
                    self.prefix
                        .try_reserve_exact(remaining)
                        .map_err(|_| io::ErrorKind::OutOfMemory)?;
                    self.prefix.extend_from_slice(&bytes[header..header + take]);
                }
            }
        }
        self.total = total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod layout_tests;

struct SiteEncoding<R> {
    index: Index,
    readers: Vec<R>,
    total: u64,
}

impl<R: Read> SiteEncoding<R> {
    fn prepare(
        assets: impl ExactSizeIterator<Item = SiteAssetSource<R>>,
    ) -> Result<Self, SiteError> {
        if !(1..=MAX_SITE_ASSETS).contains(&assets.len()) {
            return Err(SiteError::Limit);
        }
        let mut assets: Vec<_> = assets.collect();
        assets.sort_unstable_by(|left, right| left.path.cmp(&right.path));
        let mut index = Index {
            version: VERSION,
            assets: Vec::with_capacity(assets.len()),
        };
        let mut readers = Vec::with_capacity(assets.len());
        let mut payload_bytes = 0_u64;
        for asset in assets {
            validate_path(&asset.path)?;
            validate_media_type(&asset.content_type)?;
            if index
                .assets
                .last()
                .is_some_and(|entry| entry.path == asset.path)
            {
                return Err(SiteError::Encoding);
            }
            index.assets.push(Entry {
                path: asset.path,
                content_type: asset.content_type,
                offset: payload_bytes,
                length: asset.length,
            });
            readers.push(asset.reader);
            payload_bytes = payload_bytes
                .checked_add(asset.length)
                .filter(|length| *length <= MAX_OBJECT_BYTES)
                .ok_or(SiteError::Limit)?;
        }
        require_html_index(&index)?;
        let index_bytes = index.encoded_len();
        if index_bytes > MAX_SITE_INDEX_BYTES {
            return Err(SiteError::Limit);
        }
        let total = payload_bytes + index_bytes as u64 + 4;
        if total > MAX_OBJECT_BYTES {
            return Err(SiteError::Limit);
        }
        Ok(Self {
            index,
            readers,
            total,
        })
    }

    fn write_to<W: Write>(self, output: &mut W) -> Result<u64, SiteError> {
        let header = self.index.encode_to_vec();
        let index_length = u32::try_from(header.len()).map_err(|_| SiteError::Limit)?;
        output.write_all(&index_length.to_be_bytes())?;
        output.write_all(&header)?;
        for (mut reader, entry) in self.readers.into_iter().zip(self.index.assets) {
            if io::copy(&mut reader.by_ref().take(entry.length), output)? != entry.length
                || io::copy(&mut reader.take(1), &mut io::sink())? != 0
            {
                return Err(SiteError::AssetLength);
            }
        }
        Ok(self.total)
    }
}

fn decode_index(mut wire: &[u8]) -> Result<Index, SiteError> {
    let mut index = Index::default();
    while !wire.is_empty() {
        let (tag, kind) =
            prost::encoding::decode_key(&mut wire).map_err(|_| SiteError::Encoding)?;
        // Enforce the asset bound before prost can allocate another repeated entry.
        if tag == 2 && index.assets.len() == MAX_SITE_ASSETS {
            return Err(SiteError::Limit);
        }
        index
            .merge_field(
                tag,
                kind,
                &mut wire,
                prost::encoding::DecodeContext::default(),
            )
            .map_err(|_| SiteError::Encoding)?;
    }
    Ok(index)
}

fn require_html_index(index: &Index) -> Result<(), SiteError> {
    if index
        .assets
        .iter()
        .any(|asset| asset.path == "/index.html" && asset.content_type == "text/html")
    {
        Ok(())
    } else {
        Err(SiteError::MissingIndex)
    }
}

fn validate_path(path: &str) -> Result<(), SiteError> {
    if path.len() > MAX_SITE_PATH_BYTES {
        return Err(SiteError::Limit);
    }
    if !path.starts_with('/')
        || path.len() == 1
        || path.chars().any(|value| {
            value.is_control() || value.is_whitespace() || matches!(value, '\\' | '%' | '?' | '#')
        })
        || path[1..]
            .split('/')
            .any(|segment| segment.is_empty() || segment.starts_with('.'))
    {
        return Err(SiteError::Path);
    }
    Ok(())
}

fn validate_media_type(content_type: &str) -> Result<(), SiteError> {
    if content_type.len() > MAX_MEDIA_TYPE_BYTES {
        return Err(SiteError::Limit);
    }
    let Some((kind, subtype)) = content_type.split_once('/') else {
        return Err(SiteError::MediaType);
    };
    let token = |value: &str| {
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"!#$&^_.+-".contains(&byte)
            })
    };
    if token(kind) && token(subtype) {
        Ok(())
    } else {
        Err(SiteError::MediaType)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assets() -> Vec<SiteAsset> {
        [
            (
                "/index.html",
                "text/html",
                b"<link rel=stylesheet href=/style.css><script src=/app.js></script>".as_slice(),
            ),
            ("/style.css", "text/css", b"body{color:navy}".as_slice()),
            (
                "/app.js",
                "text/javascript",
                b"document.title='native';".as_slice(),
            ),
            ("/empty.txt", "text/plain", b"".as_slice()),
        ]
        .into_iter()
        .map(|(path, content_type, bytes)| SiteAsset {
            path: path.into(),
            content_type: content_type.into(),
            bytes: bytes.into(),
        })
        .collect()
    }

    fn pack(index: &Index, payload: &[u8]) -> Vec<u8> {
        let wire = index.encode_to_vec();
        let mut result = u32::try_from(wire.len()).unwrap().to_be_bytes().to_vec();
        result.extend_from_slice(&wire);
        result.extend_from_slice(payload);
        result
    }

    #[test]
    fn static_html_css_script_bundle_is_canonical_and_serves_exact_immutable_ranges() {
        let encoded = SiteBundle::encode(assets()).unwrap();
        let mut reversed = assets();
        reversed.reverse();
        assert_eq!(SiteBundle::encode(reversed).unwrap(), encoded);
        let bundle = SiteBundle::decode(encoded).unwrap();
        assert_eq!(bundle.asset_count(), 4);
        for original in assets() {
            let checked = bundle.asset(&original.path).unwrap();
            assert_eq!(checked.content_type, original.content_type);
            assert_eq!(checked.bytes, original.bytes);
        }
        assert!(bundle.asset("/missing").is_none());
        assert!(bundle.asset("/a/../index.html").is_none());
        assert!(bundle.asset("/%69ndex.html").is_none());
        assert_eq!(bundle.asset("/empty.txt").unwrap().bytes, b"");
    }

    fn index_source<R>(length: u64, reader: R) -> SiteAssetSource<R> {
        SiteAssetSource {
            path: "/index.html".into(),
            content_type: "text/html".into(),
            length,
            reader,
        }
    }

    #[test]
    fn streaming_bundle_matches_v1_wire_bytes_including_an_empty_asset() {
        let sources = vec![
            SiteAssetSource {
                path: "/z".into(),
                content_type: "text/plain".into(),
                length: 0,
                reader: &b""[..],
            },
            index_source(2, &b"ab"[..]),
        ];
        let mut output = Vec::new();
        let length = SiteBundle::write_to(sources, &mut output).unwrap();
        let expected = b"\0\0\0\x32\x08\x01\x12\x1a\x0a\x0b/index.html\x12\x09text/html\x20\x02\x12\x12\x0a\x02/z\x12\x0atext/plain\x18\x02ab";
        assert_eq!(output, expected.as_slice());
        assert_eq!(length, expected.len() as u64);
        let site = SiteBundle::decode(output).unwrap();
        assert_eq!(site.asset("/index.html").unwrap().bytes, b"ab");
        assert_eq!(site.asset("/z").unwrap().bytes, b"");
    }

    #[test]
    fn multi_megabyte_asset_is_copied_with_bounded_reads() {
        struct BoundedRead;
        impl Read for BoundedRead {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                assert!(buffer.len() <= 64 * 1024);
                buffer.fill(7);
                Ok(buffer.len())
            }
        }
        let length = 4 * 1024 * 1024;
        let source = index_source(length, BoundedRead.take(length));
        let written = SiteBundle::write_to(vec![source], &mut io::sink()).unwrap();
        assert!(written > length);
        assert!(written - length < 64);
    }

    #[test]
    fn all_geometry_is_checked_before_reading_sources_or_writing_output() {
        struct Unread;
        impl Read for Unread {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("invalid geometry must be rejected before reading");
            }
        }
        let mut output = Vec::new();
        let bad_path = SiteAssetSource {
            path: "/z/.private".into(),
            ..index_source(1, Unread)
        };
        assert_eq!(
            SiteBundle::write_to(vec![index_source(1, Unread), bad_path], &mut output),
            Err(SiteError::Path)
        );
        for length in [MAX_OBJECT_BYTES, u64::MAX] {
            assert_eq!(
                SiteBundle::write_to(vec![index_source(length, Unread)], &mut output),
                Err(SiteError::Limit)
            );
        }
        let mut oversized_index = vec![index_source(0, Unread)];
        for ordinal in 1..MAX_SITE_ASSETS {
            oversized_index.push(SiteAssetSource {
                path: format!("/{ordinal:03}{}", "z".repeat(MAX_SITE_PATH_BYTES - 4)),
                ..index_source(0, Unread)
            });
        }
        assert_eq!(
            SiteBundle::write_to(oversized_index, &mut output),
            Err(SiteError::Limit)
        );
        assert!(output.is_empty());
    }

    #[test]
    fn streaming_rejects_changed_lengths_and_preserves_io_errors() {
        struct FailedRead;
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        for (length, bytes) in [(2, &b"x"[..]), (1, &b"xy"[..]), (0, &b"x"[..])] {
            assert_eq!(
                SiteBundle::write_to(vec![index_source(length, bytes)], &mut io::sink()),
                Err(SiteError::AssetLength)
            );
        }
        for length in [0, 1] {
            assert_eq!(
                SiteBundle::write_to(vec![index_source(length, FailedRead)], &mut io::sink()),
                Err(SiteError::Io(io::ErrorKind::PermissionDenied))
            );
        }
        let mut short_destination = [0_u8; 5];
        assert_eq!(
            SiteBundle::write_to(
                vec![index_source(1, &b"x"[..])],
                &mut &mut short_destination[..]
            ),
            Err(SiteError::Io(io::ErrorKind::WriteZero))
        );
    }

    #[test]
    fn unsafe_paths_types_counts_and_noncanonical_or_noncontiguous_bundles_are_rejected() {
        for path in [
            "index.html",
            "/",
            "//x",
            "/x/",
            "/../x",
            "/a/./x",
            "/.env",
            "/a/.git/x",
            "/a\\x",
            "/a%2fb",
            "/a%2Fb",
            "/%2e%2e/x",
            "/a?b",
            "/a#b",
            "/a\r\nb",
            "/a b",
        ] {
            let mut input = assets();
            input[1].path = path.into();
            assert!(matches!(SiteBundle::encode(input), Err(SiteError::Path)));
        }
        for media in [
            "text/html\r\nx:y",
            "Text/HTML",
            "text",
            "text/",
            "/html",
            "text/html; charset=utf-8",
        ] {
            let mut input = assets();
            input[1].content_type = media.into();
            assert!(matches!(
                SiteBundle::encode(input),
                Err(SiteError::MediaType)
            ));
        }
        let mut input = assets();
        input[1].path = "/index.html".into();
        assert!(matches!(
            SiteBundle::encode(input),
            Err(SiteError::Encoding)
        ));
        let mut input = assets();
        input[0].content_type = "text/plain".into();
        assert!(matches!(
            SiteBundle::encode(input),
            Err(SiteError::MissingIndex)
        ));
        let mut input = assets();
        input[1].path = format!("/{}", "x".repeat(MAX_SITE_PATH_BYTES));
        assert!(matches!(SiteBundle::encode(input), Err(SiteError::Limit)));
        assert!(matches!(
            SiteBundle::decode(u32::MAX.to_be_bytes().to_vec()),
            Err(SiteError::Limit)
        ));

        let encoded = SiteBundle::encode(assets()).unwrap();
        let size = usize::try_from(u32::from_be_bytes(encoded[..4].try_into().unwrap())).unwrap();
        let index = Index::decode(&encoded[4..4 + size]).unwrap();
        let payload = &encoded[4 + size..];
        for mutate in [
            |value: &mut Index| value.version = 2,
            |value: &mut Index| value.assets[1].offset += 1,
            |value: &mut Index| value.assets[1].offset -= 1,
            |value: &mut Index| value.assets[0].length = u64::MAX,
            |value: &mut Index| value.assets.swap(0, 1),
            |value: &mut Index| value.assets[1].path = value.assets[0].path.clone(),
        ] {
            let mut changed = index.clone();
            mutate(&mut changed);
            assert!(SiteBundle::decode(pack(&changed, payload)).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            SiteBundle::decode(trailing),
            Err(SiteError::Encoding)
        ));
        assert!(SiteBundle::decode(encoded[..encoded.len() - 1].to_vec()).is_err());
        let mut noncanonical = index.encode_to_vec();
        noncanonical.extend_from_slice(&[0x78, 0x01]); // Unknown tag must not survive canonical decode.
        let mut wire = u32::try_from(noncanonical.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        wire.extend(noncanonical);
        wire.extend_from_slice(payload);
        assert!(matches!(SiteBundle::decode(wire), Err(SiteError::Encoding)));
        let mut oversized = index;
        oversized
            .assets
            .resize(MAX_SITE_ASSETS + 1, oversized.assets[0].clone());
        assert!(matches!(
            SiteBundle::decode(pack(&oversized, payload)),
            Err(SiteError::Limit)
        ));
    }
}
