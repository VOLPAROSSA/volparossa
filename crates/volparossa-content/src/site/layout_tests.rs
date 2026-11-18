// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn frame(wire: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut result = u32::try_from(wire.len()).unwrap().to_be_bytes().to_vec();
    result.extend_from_slice(wire);
    result.extend_from_slice(payload);
    result
}

fn index(length: u64) -> Index {
    Index {
        version: VERSION,
        assets: vec![Entry {
            path: "/index.html".into(),
            content_type: "text/html".into(),
            offset: 0,
            length,
        }],
    }
}

fn streamed(bytes: &[u8], fragment_size: usize) -> bool {
    let mut verifier = SiteLayoutVerifier::default();
    for fragment in bytes.chunks(fragment_size) {
        if verifier.write_all(fragment).is_err() {
            return false;
        }
    }
    verifier.finish().is_ok()
}

fn agree(bytes: &[u8], expected: bool) {
    assert_eq!(SiteBundle::decode(bytes.to_vec()).is_ok(), expected);
    for fragment in [1, 3, 4, 15, bytes.len().max(1)] {
        assert_eq!(
            streamed(bytes, fragment),
            expected,
            "fragment size {fragment}"
        );
    }
}

#[test]
fn layout_verification_accepts_empty_assets_and_every_split_of_header_index_and_payload() {
    let mut layout = index(0);
    layout.assets.push(Entry {
        path: "/sample.txt".into(),
        content_type: "text/plain".into(),
        offset: 0,
        length: 5,
    });
    let bytes = frame(&layout.encode_to_vec(), b"hello");
    agree(&bytes, true);
    agree(&frame(&index(0).encode_to_vec(), b""), true);
    for split in 0..=bytes.len() {
        let mut verifier = SiteLayoutVerifier::default();
        verifier.write_all(&bytes[..split]).unwrap();
        verifier.write_all(&[]).unwrap();
        verifier.write_all(&bytes[split..]).unwrap();
        verifier.finish().unwrap();
    }
    for end in 0..bytes.len() {
        agree(&bytes[..end], false);
    }
    let mut trailing = bytes;
    trailing.push(0);
    agree(&trailing, false);
}

#[test]
fn both_decoders_refuse_invalid_framing_and_index_geometry() {
    let mut layout = index(2);
    layout.assets.push(Entry {
        path: "/photo.png".into(),
        content_type: "image/png".into(),
        offset: 2,
        length: 1,
    });
    let payload = b"abc";
    let wire = layout.encode_to_vec();
    agree(&frame(&wire, payload), true);
    // Valid protobuf with an unknown field is an invalid canonical site index.
    let mut noncanonical = wire;
    noncanonical.extend_from_slice(&[0x78, 1]);
    agree(&frame(&noncanonical, payload), false);
    agree(&frame(&[0xff], payload), false);
    agree(&frame(&[], payload), false);
    agree(&u32::MAX.to_be_bytes(), false);
    for mutation in [
        |i: &mut Index| i.version += 1,
        |i: &mut Index| i.assets.clear(),
        |i: &mut Index| i.assets[0].path = "/main.html".into(),
        |i: &mut Index| i.assets[0].content_type = "text/plain".into(),
        |i: &mut Index| i.assets[1].path = "/../escape".into(),
        |i: &mut Index| i.assets[1].content_type = "Bad/Type".into(),
        |i: &mut Index| i.assets.swap(0, 1),
        |i: &mut Index| i.assets[1].path = i.assets[0].path.clone(),
        |i: &mut Index| i.assets[1].offset += 1,
        |i: &mut Index| i.assets[1].offset -= 1,
        |i: &mut Index| i.assets[1].length = u64::MAX,
        |i: &mut Index| i.assets.resize(MAX_SITE_ASSETS + 1, i.assets[0].clone()),
    ] {
        let mut changed = layout.clone();
        mutation(&mut changed);
        agree(&frame(&changed.encode_to_vec(), payload), false);
    }
}

#[test]
fn a_multi_megabyte_site_keeps_only_its_framing_in_the_streaming_verifier() {
    let bytes = SiteBundle::encode(vec![
        SiteAsset {
            path: "/index.html".into(),
            content_type: "text/html".into(),
            bytes: b"<a href='/sample.bin'>Sample</a>".to_vec(),
        },
        SiteAsset {
            path: "/sample.bin".into(),
            content_type: "application/octet-stream".into(),
            bytes: vec![0x95; 2 * 1024 * 1024 + 17],
        },
    ])
    .unwrap();
    assert!(SiteBundle::decode(bytes.clone()).is_ok());
    let prefix_len = 4 + u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let mut verifier = SiteLayoutVerifier::default();
    for fragment in bytes.chunks(8191) {
        verifier.write_all(fragment).unwrap();
    }
    assert_eq!(verifier.prefix, bytes[..prefix_len]);
    assert!(verifier.prefix.capacity() <= 4 + MAX_SITE_INDEX_BYTES);
    verifier.finish().unwrap();
}

#[test]
fn the_maximum_native_object_fits_through_one_reused_block() {
    // The index includes the payload length as a varint. Find the fixed header size
    // at the 256 MiB boundary without allocating either the payload or the full object.
    let mut length = MAX_OBJECT_BYTES;
    let prefix = loop {
        let candidate = frame(&index(length).encode_to_vec(), &[]);
        let available = MAX_OBJECT_BYTES - candidate.len() as u64;
        if length == available {
            break candidate;
        }
        length = available;
    };
    assert_eq!(prefix.len(), 37);
    let block = [0x61; 8192];
    let mut valid = SiteLayoutVerifier::default();
    let mut over = SiteLayoutVerifier::default();
    for verifier in [&mut valid, &mut over] {
        verifier.write_all(&prefix).unwrap();
        let mut remaining = length;
        while remaining > 0 {
            let count = remaining.min(block.len() as u64) as usize;
            verifier.write_all(&block[..count]).unwrap();
            remaining -= count as u64;
        }
        assert_eq!(verifier.prefix, prefix);
        assert!(verifier.prefix.capacity() <= 4 + MAX_SITE_INDEX_BYTES);
    }
    valid.finish().unwrap();
    assert!(over.write_all(&[0]).is_err() || over.finish().is_err());
}
