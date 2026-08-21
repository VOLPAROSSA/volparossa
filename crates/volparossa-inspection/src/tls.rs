use std::collections::BTreeSet;

use volparossa_policy::normalize_domain;

use crate::InspectionError;

/// Maximum complete TLS `ClientHello` size, including its handshake header.
pub const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
/// Maximum plaintext bytes accepted in one TLS record.
pub const MAX_TLS_RECORD_PAYLOAD_BYTES: usize = 1 << 14;
/// Maximum number of TLS records used to assemble one `ClientHello`.
pub const MAX_TLS_CLIENT_HELLO_RECORDS: usize = 8;
const MAX_TLS_CLIENT_HELLO_WIRE_BYTES: usize =
    MAX_CLIENT_HELLO_BYTES + (5 * MAX_TLS_CLIENT_HELLO_RECORDS);
const MAX_TLS_EXTENSIONS: usize = 256;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
const CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 1;
const SERVER_NAME_EXTENSION: u16 = 0;
const ECH_STANDARD: u16 = 0xfe0d;
const ECH_DRAFT: u16 = 0xff02;
const ESNI_LEGACY: u16 = 0xffce;
const ECH_OUTER_EXTENSIONS: u16 = 0xfd00;

/// A visible DNS server name normalized by `volparossa-policy`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedServerName(String);

impl InspectedServerName {
    /// Return the canonical lower-case ASCII policy domain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the canonical policy domain.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Progress made by a streaming TLS or QUIC `ClientHello` inspector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InspectionProgress {
    /// More authenticated bytes are required.
    NeedMore,
    /// One complete, visible, normalized server name was found.
    Complete(InspectedServerName),
}

/// A bounded streaming TLS-record `ClientHello` reassembler.
#[derive(Debug, Default)]
pub struct TlsClientHelloInspector {
    record_buffer: Vec<u8>,
    handshake: Vec<u8>,
    records: usize,
    complete: bool,
}

impl TlsClientHelloInspector {
    /// Construct an empty fail-closed reassembler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            record_buffer: Vec::new(),
            handshake: Vec::new(),
            records: 0,
            complete: false,
        }
    }

    /// Add bytes from a TLS byte stream.
    ///
    /// Record headers and `ClientHello` bodies may be split across calls. Only
    /// handshake records are accepted until the visible name is available.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed records, an invalid `ClientHello`,
    /// encrypted or ambiguous SNI, or any fixed resource-limit violation.
    pub fn push(&mut self, input: &[u8]) -> Result<InspectionProgress, InspectionError> {
        if self.complete {
            return Err(InspectionError::AlreadyComplete);
        }
        let maximum_buffer = MAX_TLS_CLIENT_HELLO_WIRE_BYTES;
        if input.len() > maximum_buffer.saturating_sub(self.record_buffer.len()) {
            return Err(InspectionError::ResourceLimit("TLS record buffer"));
        }
        self.record_buffer.extend_from_slice(input);

        loop {
            if self.record_buffer.len() < 5 {
                return Ok(InspectionProgress::NeedMore);
            }
            if self.record_buffer[0] != TLS_HANDSHAKE_CONTENT_TYPE {
                return Err(InspectionError::InvalidTlsRecord(
                    "non-handshake record before ClientHello",
                ));
            }
            if self.record_buffer[1] != 3 || !(1..=3).contains(&self.record_buffer[2]) {
                return Err(InspectionError::InvalidTlsRecord(
                    "unsupported legacy record version",
                ));
            }
            let payload_len = usize::from(u16::from_be_bytes([
                self.record_buffer[3],
                self.record_buffer[4],
            ]));
            if payload_len == 0 || payload_len > MAX_TLS_RECORD_PAYLOAD_BYTES {
                return Err(InspectionError::InvalidTlsRecord(
                    "invalid plaintext record length",
                ));
            }
            let record_len = 5 + payload_len;
            if self.record_buffer.len() < record_len {
                return Ok(InspectionProgress::NeedMore);
            }
            self.records = self.records.saturating_add(1);
            if self.records > MAX_TLS_CLIENT_HELLO_RECORDS {
                return Err(InspectionError::ResourceLimit("TLS record count"));
            }
            if payload_len > MAX_CLIENT_HELLO_BYTES.saturating_sub(self.handshake.len()) {
                return Err(InspectionError::ResourceLimit("TLS ClientHello bytes"));
            }
            self.handshake
                .extend_from_slice(&self.record_buffer[5..record_len]);
            self.record_buffer.drain(..record_len);

            if let Some(required) = client_hello_wire_len(&self.handshake)? {
                if self.handshake.len() > required {
                    return Err(InspectionError::InvalidClientHello(
                        "trailing handshake bytes",
                    ));
                }
                if self.handshake.len() == required {
                    let server_name = inspect_client_hello(&self.handshake)?;
                    self.complete = true;
                    return Ok(InspectionProgress::Complete(server_name));
                }
            }
        }
    }

    /// Report a truncated `ClientHello` when the inspected stream ends.
    ///
    /// # Errors
    ///
    /// Always returns [`InspectionError::TruncatedClientHello`] unless a
    /// prior call had already completed, in which case it returns
    /// [`InspectionError::AlreadyComplete`].
    pub fn finish(self) -> Result<InspectedServerName, InspectionError> {
        if self.complete {
            Err(InspectionError::AlreadyComplete)
        } else {
            Err(InspectionError::TruncatedClientHello)
        }
    }
}

/// Inspect one complete, unframed TLS `ClientHello` handshake message.
///
/// The slice must contain exactly the four-byte TLS handshake header and its
/// declared `ClientHello` body, without TLS record framing.
///
/// # Errors
///
/// Returns an error for malformed or trailing bytes, duplicate extensions,
/// ECH/ESNI, missing or multiple names, raw IPs, or an invalid DNS name.
pub fn inspect_client_hello(input: &[u8]) -> Result<InspectedServerName, InspectionError> {
    let required = client_hello_wire_len(input)?.ok_or(InspectionError::TruncatedClientHello)?;
    if input.len() != required {
        return Err(InspectionError::InvalidClientHello(
            "trailing handshake bytes",
        ));
    }
    parse_client_hello_body(&input[4..])
}

pub(crate) fn inspect_client_hello_prefix(
    input: &[u8],
) -> Result<Option<InspectedServerName>, InspectionError> {
    let Some(required) = client_hello_wire_len(input)? else {
        return Ok(None);
    };
    if input.len() < required {
        return Ok(None);
    }
    if input.len() > required {
        return Err(InspectionError::InvalidClientHello(
            "trailing handshake bytes",
        ));
    }
    parse_client_hello_body(&input[4..required]).map(Some)
}

fn client_hello_wire_len(input: &[u8]) -> Result<Option<usize>, InspectionError> {
    if input.is_empty() {
        return Ok(None);
    }
    if input[0] != CLIENT_HELLO_HANDSHAKE_TYPE {
        return Err(InspectionError::InvalidClientHello(
            "first handshake message is not ClientHello",
        ));
    }
    if input.len() < 4 {
        return Ok(None);
    }
    let body_len =
        (usize::from(input[1]) << 16) | (usize::from(input[2]) << 8) | usize::from(input[3]);
    let total = body_len
        .checked_add(4)
        .ok_or(InspectionError::ResourceLimit("TLS ClientHello bytes"))?;
    if total > MAX_CLIENT_HELLO_BYTES {
        return Err(InspectionError::ResourceLimit("TLS ClientHello bytes"));
    }
    Ok(Some(total))
}

fn parse_client_hello_body(body: &[u8]) -> Result<InspectedServerName, InspectionError> {
    let mut reader = Reader::new(body);
    if reader.u16()? != 0x0303 {
        return Err(InspectionError::InvalidClientHello(
            "legacy_version is not TLS 1.2",
        ));
    }
    reader.take(32)?;
    let session_id_len = usize::from(reader.u8()?);
    if session_id_len > 32 {
        return Err(InspectionError::InvalidClientHello(
            "legacy session identifier is oversized",
        ));
    }
    reader.take(session_id_len)?;
    let cipher_suites_len = usize::from(reader.u16()?);
    if cipher_suites_len < 2 || cipher_suites_len % 2 != 0 {
        return Err(InspectionError::InvalidClientHello(
            "invalid cipher-suite vector",
        ));
    }
    reader.take(cipher_suites_len)?;
    let compression_len = usize::from(reader.u8()?);
    let compression_methods = reader.take(compression_len)?;
    if compression_methods != [0] {
        return Err(InspectionError::InvalidClientHello(
            "legacy compression methods are not null-only",
        ));
    }
    let extensions_len = usize::from(reader.u16()?);
    let extensions = reader.take(extensions_len)?;
    if !reader.is_empty() {
        return Err(InspectionError::InvalidClientHello(
            "extension vector length mismatch",
        ));
    }

    let mut extensions = Reader::new(extensions);
    let mut seen = BTreeSet::new();
    let mut server_name = None;
    while !extensions.is_empty() {
        if seen.len() == MAX_TLS_EXTENSIONS {
            return Err(InspectionError::ResourceLimit("TLS extension count"));
        }
        let extension_type = extensions.u16()?;
        let extension_data_len = usize::from(extensions.u16()?);
        let extension_data = extensions.take(extension_data_len)?;
        if !seen.insert(extension_type) {
            return Err(InspectionError::DuplicateTlsExtension(extension_type));
        }
        if matches!(
            extension_type,
            ECH_STANDARD | ECH_DRAFT | ESNI_LEGACY | ECH_OUTER_EXTENSIONS
        ) {
            return Err(InspectionError::EncryptedClientHello(extension_type));
        }
        if extension_type == SERVER_NAME_EXTENSION {
            server_name = Some(parse_server_name(extension_data)?);
        }
    }
    let visible_name = server_name.ok_or(InspectionError::MissingServerName)?;
    let visible_name =
        std::str::from_utf8(visible_name).map_err(|_| InspectionError::InvalidServerName)?;
    let normalized =
        normalize_domain(visible_name).map_err(|_| InspectionError::InvalidServerName)?;
    Ok(InspectedServerName(normalized))
}

fn parse_server_name(data: &[u8]) -> Result<&[u8], InspectionError> {
    let mut reader = Reader::new(data);
    let list_len = usize::from(reader.u16()?);
    if list_len == 0 || list_len != reader.remaining() {
        return Err(InspectionError::InvalidClientHello(
            "invalid server-name list length",
        ));
    }
    let name_type = reader.u8()?;
    if name_type != 0 {
        return Err(InspectionError::UnsupportedServerNameType(name_type));
    }
    let name_len = usize::from(reader.u16()?);
    if name_len == 0 {
        return Err(InspectionError::InvalidServerName);
    }
    let name = reader.take(name_len)?;
    if !reader.is_empty() {
        return Err(InspectionError::MultipleServerNames);
    }
    Ok(name)
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], InspectionError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(InspectionError::InvalidClientHello("length overflow"))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(InspectionError::InvalidClientHello("truncated vector"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, InspectionError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, InspectionError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| InspectionError::InvalidClientHello("truncated integer"))?;
        Ok(u16::from_be_bytes(bytes))
    }

    const fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
}

#[cfg(test)]
mod tests {
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

    fn name_entry(name_type: u8, name: &[u8]) -> Vec<u8> {
        let mut entry = vec![name_type];
        entry.extend_from_slice(
            &u16::try_from(name.len())
                .expect("test name fits")
                .to_be_bytes(),
        );
        entry.extend_from_slice(name);
        entry
    }

    fn server_name_data(entries: &[Vec<u8>]) -> Vec<u8> {
        let entries_len = entries.iter().map(Vec::len).sum::<usize>();
        let mut data = Vec::new();
        data.extend_from_slice(
            &u16::try_from(entries_len)
                .expect("test name list fits")
                .to_be_bytes(),
        );
        for entry in entries {
            data.extend_from_slice(entry);
        }
        data
    }

    fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
        let extensions_len = extensions.iter().map(Vec::len).sum::<usize>();
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0x42; 32]);
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
            body.extend_from_slice(value);
        }
        let mut handshake = vec![CLIENT_HELLO_HANDSHAKE_TYPE];
        let body_len = u32::try_from(body.len()).expect("test ClientHello fits");
        let encoded = body_len.to_be_bytes();
        handshake.extend_from_slice(&encoded[1..]);
        handshake.extend_from_slice(&body);
        handshake
    }

    fn hello_for(name: &[u8]) -> Vec<u8> {
        client_hello(&[extension(
            SERVER_NAME_EXTENSION,
            &server_name_data(&[name_entry(0, name)]),
        )])
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
    fn reassembles_fragmented_records_and_normalizes_sni() {
        let hello = hello_for(b"WWW.Example.COM.");
        let split = 11;
        let wire = [record(&hello[..split]), record(&hello[split..])].concat();
        let mut inspector = TlsClientHelloInspector::new();
        let mut result = InspectionProgress::NeedMore;
        for byte in wire {
            result = inspector.push(&[byte]).expect("fragment accepted");
        }
        assert_eq!(
            result,
            InspectionProgress::Complete(InspectedServerName("www.example.com".to_owned()))
        );
    }

    #[test]
    fn rejects_missing_and_duplicate_sni_extensions() {
        let no_sni = client_hello(&[extension(43, &[2, 3, 4])]);
        assert_eq!(
            inspect_client_hello(&no_sni),
            Err(InspectionError::MissingServerName)
        );

        let sni = extension(
            SERVER_NAME_EXTENSION,
            &server_name_data(&[name_entry(0, b"example.com")]),
        );
        let duplicate = client_hello(&[sni.clone(), sni]);
        assert_eq!(
            inspect_client_hello(&duplicate),
            Err(InspectionError::DuplicateTlsExtension(0))
        );
    }

    #[test]
    fn rejects_multiple_names_and_unknown_name_type() {
        let multiple = client_hello(&[extension(
            SERVER_NAME_EXTENSION,
            &server_name_data(&[
                name_entry(0, b"example.com"),
                name_entry(0, b"other.example"),
            ]),
        )]);
        assert_eq!(
            inspect_client_hello(&multiple),
            Err(InspectionError::MultipleServerNames)
        );

        let unknown = client_hello(&[extension(
            SERVER_NAME_EXTENSION,
            &server_name_data(&[name_entry(7, b"example.com")]),
        )]);
        assert_eq!(
            inspect_client_hello(&unknown),
            Err(InspectionError::UnsupportedServerNameType(7))
        );
    }

    #[test]
    fn rejects_every_recognized_ech_and_esni_codepoint() {
        for extension_type in [ECH_STANDARD, ECH_DRAFT, ESNI_LEGACY, ECH_OUTER_EXTENSIONS] {
            let hello = client_hello(&[
                extension(
                    SERVER_NAME_EXTENSION,
                    &server_name_data(&[name_entry(0, b"public.example")]),
                ),
                extension(extension_type, &[1, 2, 3]),
            ]);
            assert_eq!(
                inspect_client_hello(&hello),
                Err(InspectionError::EncryptedClientHello(extension_type))
            );
        }
    }

    #[test]
    fn rejects_raw_ip_and_non_utf8_visible_names() {
        assert_eq!(
            inspect_client_hello(&hello_for(b"192.0.2.1")),
            Err(InspectionError::InvalidServerName)
        );
        assert_eq!(
            inspect_client_hello(&hello_for(&[0xff, 0xfe])),
            Err(InspectionError::InvalidServerName)
        );
    }

    #[test]
    fn rejects_oversized_record_and_reports_truncation() {
        let mut inspector = TlsClientHelloInspector::new();
        assert_eq!(
            inspector.push(&[TLS_HANDSHAKE_CONTENT_TYPE, 3, 1, 0x40, 1]),
            Err(InspectionError::InvalidTlsRecord(
                "invalid plaintext record length"
            ))
        );
        assert_eq!(
            TlsClientHelloInspector::new().finish(),
            Err(InspectionError::TruncatedClientHello)
        );
    }
}

#[cfg(test)]
#[path = "tls_hardening_tests.rs"]
mod hardening_tests;
