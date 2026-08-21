use ring::aead;

use super::*;

const TEST_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

fn encode_varint(value: u64) -> Vec<u8> {
    if value < (1 << 6) {
        vec![u8::try_from(value).expect("one-byte test varint")]
    } else if value < (1 << 14) {
        let encoded = u16::try_from(value).expect("two-byte test varint") | 0x4000;
        encoded.to_be_bytes().to_vec()
    } else if value < (1 << 30) {
        let encoded = u32::try_from(value).expect("four-byte test varint") | 0x8000_0000;
        encoded.to_be_bytes().to_vec()
    } else {
        (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec()
    }
}

fn extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
    let mut extension = Vec::new();
    extension.extend_from_slice(&extension_type.to_be_bytes());
    extension.extend_from_slice(
        &u16::try_from(data.len())
            .expect("test extension fits")
            .to_be_bytes(),
    );
    extension.extend_from_slice(data);
    extension
}

fn client_hello(name: &[u8], extra_extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut name_list = vec![0];
    name_list.extend_from_slice(
        &u16::try_from(name.len())
            .expect("test name fits")
            .to_be_bytes(),
    );
    name_list.extend_from_slice(name);
    let mut sni = Vec::new();
    sni.extend_from_slice(
        &u16::try_from(name_list.len())
            .expect("test name list fits")
            .to_be_bytes(),
    );
    sni.extend_from_slice(&name_list);
    let mut extensions = vec![extension(0, &sni)];
    extensions.extend_from_slice(extra_extensions);
    let extensions_len = extensions.iter().map(Vec::len).sum::<usize>();

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(&[0x24; 32]);
    body.push(0);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&0x1301_u16.to_be_bytes());
    body.push(1);
    body.push(0);
    body.extend_from_slice(
        &u16::try_from(extensions_len)
            .expect("test extensions fit")
            .to_be_bytes(),
    );
    for value in extensions {
        body.extend_from_slice(&value);
    }

    let mut hello = vec![1];
    let encoded_len = u32::try_from(body.len())
        .expect("test ClientHello fits")
        .to_be_bytes();
    hello.extend_from_slice(&encoded_len[1..]);
    hello.extend_from_slice(&body);
    hello
}

fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
    let mut frame = encode_varint(0x06);
    frame.extend_from_slice(&encode_varint(
        u64::try_from(offset).expect("test offset fits"),
    ));
    frame.extend_from_slice(&encode_varint(
        u64::try_from(data.len()).expect("test data length fits"),
    ));
    frame.extend_from_slice(data);
    frame
}

fn protected_packet(packet_number: u32, frames: &[u8]) -> Vec<u8> {
    let keys = InitialKeys::derive(&TEST_DCID).expect("derive test keys");
    let packet_number_len = 4_usize;
    let packet_number_offset = 18_usize;
    let protected_len = MIN_INITIAL_DATAGRAM_BYTES - packet_number_offset;
    let plaintext_len = protected_len - packet_number_len - aead::MAX_TAG_LEN;
    assert!(frames.len() <= plaintext_len);

    let mut header = vec![0xc3];
    header.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
    header.push(u8::try_from(TEST_DCID.len()).expect("test DCID length"));
    header.extend_from_slice(&TEST_DCID);
    header.push(0);
    header.push(0);
    header.extend_from_slice(&encode_varint(
        u64::try_from(protected_len).expect("test protected length"),
    ));
    assert_eq!(header.len(), packet_number_offset);
    header.extend_from_slice(&packet_number.to_be_bytes());

    let mut plaintext = frames.to_vec();
    plaintext.resize(plaintext_len, 0);
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &keys.key).expect("test AEAD key"),
    );
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(packet_nonce(&keys.iv, u64::from(packet_number))),
        aead::Aad::from(header.as_slice()),
        &mut plaintext,
    )
    .expect("protect test Initial");

    let mut packet = header;
    packet.extend_from_slice(&plaintext);
    let header_key =
        aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &keys.header_protection)
            .expect("test header key");
    let mask = header_key
        .new_mask(&packet[packet_number_offset + 4..packet_number_offset + 20])
        .expect("test header mask");
    packet[0] ^= mask[0] & 0x0f;
    for index in 0..packet_number_len {
        packet[packet_number_offset + index] ^= mask[index + 1];
    }
    assert_eq!(packet.len(), MIN_INITIAL_DATAGRAM_BYTES);
    packet
}

#[test]
fn rfc9001_appendix_a_client_keys_and_header_mask_match() {
    let keys = InitialKeys::derive(&TEST_DCID).expect("derive Appendix A keys");
    assert_eq!(
        keys.key,
        hex::decode("1f369613dd76d5467730efcbe3b1a22d")
            .expect("valid vector")
            .as_slice()
    );
    assert_eq!(
        keys.iv,
        hex::decode("fa044b2f42a3fd3b46fb255c")
            .expect("valid vector")
            .as_slice()
    );
    assert_eq!(
        keys.header_protection,
        hex::decode("9f50449e04a0e810283a1e9933adedd2")
            .expect("valid vector")
            .as_slice()
    );
    let header_key =
        aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &keys.header_protection)
            .expect("Appendix A header key");
    let sample = hex::decode("d1b1c98dd7689fb8ec11d242b123dc9b").expect("valid sample");
    assert_eq!(
        header_key.new_mask(&sample).expect("derive mask"),
        [0x43, 0x7b, 0x9a, 0xec, 0x36]
    );
}

#[test]
fn authenticates_synthetic_initial_and_reassembles_out_of_order_crypto() {
    let hello = client_hello(b"Quic.Example.COM", &[]);
    let first = crypto_frame(20, &hello[20..40]);
    let second = crypto_frame(0, &hello[..20]);
    let third = crypto_frame(40, &hello[40..]);
    let mut inspector = QuicInitialInspector::new(&TEST_DCID).expect("inspector");

    assert_eq!(
        inspector
            .inspect_datagram(&protected_packet(0, &first))
            .expect("first packet")
            .progress,
        InspectionProgress::NeedMore
    );
    assert_eq!(
        inspector
            .inspect_datagram(&protected_packet(1, &second))
            .expect("second packet")
            .progress,
        InspectionProgress::NeedMore
    );
    let result = inspector
        .inspect_datagram(&protected_packet(2, &third))
        .expect("third packet");
    assert_eq!(result.packet_number, 2);
    let InspectionProgress::Complete(name) = result.progress else {
        panic!("ClientHello should now be complete");
    };
    assert_eq!(name.as_str(), "quic.example.com");
}

#[test]
fn rejects_conflicting_crypto_overlap() {
    let hello = client_hello(b"example.com", &[]);
    let mut inspector = QuicInitialInspector::new(&TEST_DCID).expect("inspector");
    inspector
        .inspect_datagram(&protected_packet(0, &crypto_frame(10, &hello[10..20])))
        .expect("first fragment");
    let mut conflicting = hello[10..20].to_vec();
    conflicting[3] ^= 0xff;
    assert_eq!(
        inspector.inspect_datagram(&protected_packet(1, &crypto_frame(10, &conflicting))),
        Err(InspectionError::ConflictingCryptoData)
    );
}

#[test]
fn rejects_ech_after_authenticating_quic_initial() {
    let hello = client_hello(b"public.example", &[extension(0xfe0d, &[0])]);
    let mut inspector = QuicInitialInspector::new(&TEST_DCID).expect("inspector");
    assert_eq!(
        inspector.inspect_datagram(&protected_packet(0, &crypto_frame(0, &hello))),
        Err(InspectionError::EncryptedClientHello(0xfe0d))
    );
}

#[test]
fn rejects_coalesced_unsupported_and_forbidden_initials() {
    let hello = client_hello(b"example.com", &[]);
    let mut coalesced = protected_packet(0, &crypto_frame(0, &hello));
    coalesced.push(0);
    let mut inspector = QuicInitialInspector::new(&TEST_DCID).expect("inspector");
    assert_eq!(
        inspector.inspect_datagram(&coalesced),
        Err(InspectionError::InvalidQuicInitial(
            "coalesced or trailing packet data is ambiguous"
        ))
    );

    let mut unsupported = protected_packet(0, &crypto_frame(0, &hello));
    unsupported[1..5].copy_from_slice(&2_u32.to_be_bytes());
    let mut inspector = QuicInitialInspector::new(&TEST_DCID).expect("inspector");
    assert_eq!(
        inspector.inspect_datagram(&unsupported),
        Err(InspectionError::UnsupportedQuicVersion(2))
    );

    let mut inspector = QuicInitialInspector::new(&TEST_DCID).expect("inspector");
    assert_eq!(
        inspector.inspect_datagram(&protected_packet(0, &[0x08])),
        Err(InspectionError::ForbiddenQuicFrame(0x08))
    );
}

#[test]
fn reconstructs_packet_number_from_rfc9000_example() {
    assert_eq!(
        reconstruct_packet_number(0x9b32, 2, Some(0xa82f_30ea)).expect("packet number"),
        0xa82f_9b32
    );
}
