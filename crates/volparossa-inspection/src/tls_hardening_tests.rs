use super::*;

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

fn client_hello(name: &[u8], padding_bytes: usize) -> Vec<u8> {
    let mut name_entry = vec![0];
    name_entry.extend_from_slice(
        &u16::try_from(name.len())
            .expect("test name fits")
            .to_be_bytes(),
    );
    name_entry.extend_from_slice(name);
    let mut name_list = Vec::new();
    name_list.extend_from_slice(
        &u16::try_from(name_entry.len())
            .expect("test name list fits")
            .to_be_bytes(),
    );
    name_list.extend_from_slice(&name_entry);
    let extensions = [
        extension(SERVER_NAME_EXTENSION, &name_list),
        extension(42, &vec![0; padding_bytes]),
    ];
    let extensions_len = extensions.iter().map(Vec::len).sum::<usize>();

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&0x1301_u16.to_be_bytes());
    body.push(1);
    body.push(0);
    body.extend_from_slice(
        &u16::try_from(extensions_len)
            .expect("test extension vector fits")
            .to_be_bytes(),
    );
    for value in extensions {
        body.extend_from_slice(&value);
    }
    let mut hello = vec![CLIENT_HELLO_HANDSHAKE_TYPE];
    let body_len = u32::try_from(body.len())
        .expect("test ClientHello fits")
        .to_be_bytes();
    hello.extend_from_slice(&body_len[1..]);
    hello.extend_from_slice(&body);
    hello
}

fn record(payload: &[u8]) -> Vec<u8> {
    let mut record = vec![TLS_HANDSHAKE_CONTENT_TYPE, 3, 1];
    record.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("test record fits")
            .to_be_bytes(),
    );
    record.extend_from_slice(payload);
    record
}

#[test]
fn accepts_multiple_complete_records_in_one_input_chunk() {
    let hello = client_hello(b"bundled.example", 20_000);
    let wire = [
        record(&hello[..MAX_TLS_RECORD_PAYLOAD_BYTES]),
        record(&hello[MAX_TLS_RECORD_PAYLOAD_BYTES..]),
    ]
    .concat();
    assert!(wire.len() > MAX_TLS_RECORD_PAYLOAD_BYTES + 5);
    let mut inspector = TlsClientHelloInspector::new();
    let InspectionProgress::Complete(name) = inspector.push(&wire).expect("bundled records") else {
        panic!("the bundled ClientHello should complete");
    };
    assert_eq!(name.as_str(), "bundled.example");
}

#[test]
fn rejects_non_null_legacy_compression_method() {
    let mut hello = client_hello(b"compression.example", 0);
    hello[44] = 1;
    assert_eq!(
        inspect_client_hello(&hello),
        Err(InspectionError::InvalidClientHello(
            "legacy compression methods are not null-only"
        ))
    );
}

#[test]
fn rejects_trailing_tls_and_quic_handshake_bytes() {
    let mut hello = client_hello(b"trailing.example", 0);
    hello.push(2);
    let mut stream = TlsClientHelloInspector::new();
    assert_eq!(
        stream.push(&record(&hello)),
        Err(InspectionError::InvalidClientHello(
            "trailing handshake bytes"
        ))
    );
    assert_eq!(
        inspect_client_hello_prefix(&hello),
        Err(InspectionError::InvalidClientHello(
            "trailing handshake bytes"
        ))
    );
}
