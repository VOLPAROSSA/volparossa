use ring::{aead, hkdf};

use crate::tls::{InspectionProgress, MAX_CLIENT_HELLO_BYTES, inspect_client_hello_prefix};
use crate::{InspectedServerName, InspectionError};

const QUIC_VERSION_1: u32 = 1;
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const MIN_INITIAL_DATAGRAM_BYTES: usize = 1200;
const MAX_INITIAL_DATAGRAM_BYTES: usize = 65_527;
const MAX_CONNECTION_ID_BYTES: usize = 20;
const MIN_INITIAL_DCID_BYTES: usize = 8;
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_CRYPTO_FRAGMENTS: usize = 128;
const MAX_INITIAL_DATAGRAMS: usize = 128;
const MAX_ACK_RANGES: u64 = 64;
const MAX_CLOSE_REASON_BYTES: usize = 1024;
const MAX_PACKET_NUMBER: u64 = (1_u64 << 62) - 1;

/// Metadata authenticated from one QUIC v1 client Initial packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicInspection {
    /// The reconstructed full packet number.
    pub packet_number: u64,
    /// `ClientHello` inspection progress after applying this packet's CRYPTO data.
    pub progress: InspectionProgress,
}

/// Stateful QUIC v1 client-Initial decryptor and CRYPTO reassembler.
///
/// Initial keys are derived from the destination connection identifier in the
/// client's first Initial packet. The inspector keeps that key material across
/// later client Initial packets, as required by RFC 9001.
pub struct QuicInitialInspector {
    key: aead::LessSafeKey,
    iv: [u8; 12],
    header_key: aead::quic::HeaderProtectionKey,
    largest_packet_number: Option<u64>,
    crypto: CryptoReassembler,
    datagrams: usize,
    complete: bool,
}

impl QuicInitialInspector {
    /// Derive QUIC v1 client Initial keys from the original client DCID.
    ///
    /// # Errors
    ///
    /// Rejects connection identifiers outside the QUIC v1 initial bounds or
    /// an unexpected cryptographic setup failure.
    pub fn new(original_client_dcid: &[u8]) -> Result<Self, InspectionError> {
        if !(MIN_INITIAL_DCID_BYTES..=MAX_CONNECTION_ID_BYTES).contains(&original_client_dcid.len())
        {
            return Err(InspectionError::InvalidQuicInitial(
                "original destination connection identifier length",
            ));
        }
        let keys = InitialKeys::derive(original_client_dcid)?;
        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &keys.key)
            .map_err(|_| InspectionError::QuicAuthentication)?;
        let header_key =
            aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &keys.header_protection)
                .map_err(|_| InspectionError::QuicAuthentication)?;
        Ok(Self {
            key: aead::LessSafeKey::new(unbound),
            iv: keys.iv,
            header_key,
            largest_packet_number: None,
            crypto: CryptoReassembler::default(),
            datagrams: 0,
            complete: false,
        })
    }

    /// Authenticate one UDP datagram containing exactly one client Initial.
    ///
    /// Coalesced packets are intentionally rejected because this boundary is
    /// designed for an unambiguous, fail-closed policy decision. CRYPTO data
    /// can arrive out of order across successive calls.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, malformed protection,
    /// failed authentication, forbidden Initial frames, conflicting CRYPTO
    /// overlaps, or fixed resource-limit violations.
    pub fn inspect_datagram(&mut self, datagram: &[u8]) -> Result<QuicInspection, InspectionError> {
        if self.complete {
            return Err(InspectionError::AlreadyComplete);
        }
        self.datagrams = self.datagrams.saturating_add(1);
        if self.datagrams > MAX_INITIAL_DATAGRAMS {
            return Err(InspectionError::ResourceLimit(
                "QUIC Initial datagram count",
            ));
        }
        let opened = open_initial(
            datagram,
            &self.key,
            &self.iv,
            &self.header_key,
            self.largest_packet_number,
        )?;
        self.largest_packet_number = Some(
            self.largest_packet_number
                .map_or(opened.packet_number, |largest| {
                    largest.max(opened.packet_number)
                }),
        );
        parse_initial_frames(&opened.plaintext, &mut self.crypto)?;
        let progress = match self.crypto.client_hello()? {
            Some(name) => {
                self.complete = true;
                InspectionProgress::Complete(name)
            }
            None => InspectionProgress::NeedMore,
        };
        Ok(QuicInspection {
            packet_number: opened.packet_number,
            progress,
        })
    }
}

struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    header_protection: [u8; 16],
}

impl InitialKeys {
    fn derive(dcid: &[u8]) -> Result<Self, InspectionError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &QUIC_V1_INITIAL_SALT);
        let initial_secret = salt.extract(dcid);
        let mut client_secret = [0_u8; 32];
        expand_label(&initial_secret, b"client in", &mut client_secret)?;
        let client_secret = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_secret);
        let mut key = [0_u8; 16];
        let mut iv = [0_u8; 12];
        let mut header_protection = [0_u8; 16];
        expand_label(&client_secret, b"quic key", &mut key)?;
        expand_label(&client_secret, b"quic iv", &mut iv)?;
        expand_label(&client_secret, b"quic hp", &mut header_protection)?;
        Ok(Self {
            key,
            iv,
            header_protection,
        })
    }
}

struct OutputLength(usize);

impl hkdf::KeyType for OutputLength {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand_label(
    secret: &hkdf::Prk,
    label: &[u8],
    output: &mut [u8],
) -> Result<(), InspectionError> {
    let full_label_len = 6_usize
        .checked_add(label.len())
        .ok_or(InspectionError::QuicAuthentication)?;
    let label_len =
        u8::try_from(full_label_len).map_err(|_| InspectionError::QuicAuthentication)?;
    let output_len =
        u16::try_from(output.len()).map_err(|_| InspectionError::QuicAuthentication)?;
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    info.extend_from_slice(&output_len.to_be_bytes());
    info.push(label_len);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    let info_parts = [info.as_slice()];
    secret
        .expand(&info_parts, OutputLength(output.len()))
        .and_then(|okm| okm.fill(output))
        .map_err(|_| InspectionError::QuicAuthentication)
}

struct OpenedInitial {
    packet_number: u64,
    plaintext: Vec<u8>,
}

fn open_initial(
    datagram: &[u8],
    key: &aead::LessSafeKey,
    iv: &[u8; 12],
    header_key: &aead::quic::HeaderProtectionKey,
    largest_packet_number: Option<u64>,
) -> Result<OpenedInitial, InspectionError> {
    if datagram.len() < MIN_INITIAL_DATAGRAM_BYTES {
        return Err(InspectionError::InvalidQuicInitial(
            "datagram shorter than 1200 bytes",
        ));
    }
    if datagram.len() > MAX_INITIAL_DATAGRAM_BYTES {
        return Err(InspectionError::ResourceLimit("QUIC UDP datagram bytes"));
    }
    let parsed = parse_protected_header(datagram)?;
    let sample = datagram
        .get(parsed.packet_number_offset + 4..parsed.packet_number_offset + 4 + 16)
        .ok_or(InspectionError::InvalidQuicInitial(
            "header-protection sample is truncated",
        ))?;
    let mask = header_key
        .new_mask(sample)
        .map_err(|_| InspectionError::QuicAuthentication)?;
    let first = datagram[0] ^ (mask[0] & 0x0f);
    if first & 0x0c != 0 {
        return Err(InspectionError::InvalidQuicInitial(
            "non-zero protected reserved bits",
        ));
    }
    let packet_number_len = usize::from((first & 0x03) + 1);
    let header_len = parsed
        .packet_number_offset
        .checked_add(packet_number_len)
        .ok_or(InspectionError::InvalidQuicInitial(
            "header length overflow",
        ))?;
    if header_len + aead::MAX_TAG_LEN > parsed.packet_end {
        return Err(InspectionError::InvalidQuicInitial(
            "protected payload is too short",
        ));
    }
    let mut header = datagram[..header_len].to_vec();
    header[0] = first;
    let mut truncated = 0_u64;
    for (index, byte) in header[parsed.packet_number_offset..header_len]
        .iter_mut()
        .enumerate()
    {
        *byte ^= mask[index + 1];
        truncated = (truncated << 8) | u64::from(*byte);
    }
    let packet_number =
        reconstruct_packet_number(truncated, packet_number_len, largest_packet_number)?;
    let nonce = packet_nonce(iv, packet_number);
    let mut plaintext = datagram[header_len..parsed.packet_end].to_vec();
    let plaintext_len = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(header.as_slice()),
            &mut plaintext,
        )
        .map_err(|_| InspectionError::QuicAuthentication)?
        .len();
    plaintext.truncate(plaintext_len);
    Ok(OpenedInitial {
        packet_number,
        plaintext,
    })
}

struct ProtectedHeader {
    packet_number_offset: usize,
    packet_end: usize,
}

fn parse_protected_header(datagram: &[u8]) -> Result<ProtectedHeader, InspectionError> {
    let first = *datagram
        .first()
        .ok_or(InspectionError::InvalidQuicInitial("empty datagram"))?;
    if first & 0xc0 != 0xc0 {
        return Err(InspectionError::InvalidQuicInitial(
            "long-header and fixed bits are required",
        ));
    }
    if first & 0x30 != 0 {
        return Err(InspectionError::InvalidQuicInitial(
            "long-header packet is not Initial",
        ));
    }
    let version_bytes: [u8; 4] = datagram
        .get(1..5)
        .ok_or(InspectionError::InvalidQuicInitial("truncated version"))?
        .try_into()
        .map_err(|_| InspectionError::InvalidQuicInitial("truncated version"))?;
    let version = u32::from_be_bytes(version_bytes);
    if version != QUIC_VERSION_1 {
        return Err(InspectionError::UnsupportedQuicVersion(version));
    }
    let mut reader = QuicReader::at(datagram, 5);
    let dcid_len = usize::from(reader.u8()?);
    if dcid_len > MAX_CONNECTION_ID_BYTES {
        return Err(InspectionError::InvalidQuicInitial(
            "destination CID is oversized",
        ));
    }
    reader.take(dcid_len)?;
    let scid_len = usize::from(reader.u8()?);
    if scid_len > MAX_CONNECTION_ID_BYTES {
        return Err(InspectionError::InvalidQuicInitial(
            "source CID is oversized",
        ));
    }
    reader.take(scid_len)?;
    let token_len = usize::try_from(reader.varint()?)
        .map_err(|_| InspectionError::ResourceLimit("QUIC Initial token bytes"))?;
    if token_len > MAX_TOKEN_BYTES {
        return Err(InspectionError::ResourceLimit("QUIC Initial token bytes"));
    }
    reader.take(token_len)?;
    let protected_len = usize::try_from(reader.varint()?)
        .map_err(|_| InspectionError::InvalidQuicInitial("payload length overflow"))?;
    let packet_number_offset = reader.offset;
    let packet_end = packet_number_offset.checked_add(protected_len).ok_or(
        InspectionError::InvalidQuicInitial("packet length overflow"),
    )?;
    if packet_end != datagram.len() {
        return Err(InspectionError::InvalidQuicInitial(
            "coalesced or trailing packet data is ambiguous",
        ));
    }
    if protected_len < 1 + aead::MAX_TAG_LEN {
        return Err(InspectionError::InvalidQuicInitial(
            "protected payload is too short",
        ));
    }
    Ok(ProtectedHeader {
        packet_number_offset,
        packet_end,
    })
}

fn packet_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let encoded = packet_number.to_be_bytes();
    for (target, byte) in nonce[4..].iter_mut().zip(encoded) {
        *target ^= byte;
    }
    nonce
}

fn reconstruct_packet_number(
    truncated: u64,
    encoded_len: usize,
    largest: Option<u64>,
) -> Result<u64, InspectionError> {
    let expected = largest.map_or(0, |value| value.saturating_add(1));
    let packet_number_bits = encoded_len
        .checked_mul(8)
        .ok_or(InspectionError::InvalidQuicInitial("packet-number width"))?;
    let window = 1_u64
        .checked_shl(
            u32::try_from(packet_number_bits)
                .map_err(|_| InspectionError::InvalidQuicInitial("packet-number width"))?,
        )
        .ok_or(InspectionError::InvalidQuicInitial("packet-number width"))?;
    let half_window = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    let candidate = if candidate
        .checked_add(half_window)
        .is_some_and(|value| value <= expected)
        && candidate <= MAX_PACKET_NUMBER.saturating_sub(window)
    {
        candidate + window
    } else if candidate > expected.saturating_add(half_window) && candidate >= window {
        candidate - window
    } else {
        candidate
    };
    if candidate > MAX_PACKET_NUMBER {
        return Err(InspectionError::InvalidQuicInitial(
            "packet number exceeds QUIC limit",
        ));
    }
    Ok(candidate)
}

fn parse_initial_frames(
    plaintext: &[u8],
    crypto: &mut CryptoReassembler,
) -> Result<(), InspectionError> {
    let mut reader = QuicReader::new(plaintext);
    while !reader.is_empty() {
        let frame_type = reader.varint()?;
        match frame_type {
            0x00 | 0x01 => {}
            0x02 | 0x03 => parse_ack(&mut reader, frame_type == 0x03)?,
            0x06 => {
                let offset = usize::try_from(reader.varint()?)
                    .map_err(|_| InspectionError::ResourceLimit("QUIC CRYPTO offset"))?;
                let length = usize::try_from(reader.varint()?)
                    .map_err(|_| InspectionError::ResourceLimit("QUIC CRYPTO bytes"))?;
                let data = reader.take(length)?;
                crypto.insert(offset, data)?;
            }
            0x1c => {
                parse_transport_close(&mut reader)?;
                return Err(InspectionError::ClosedBeforeClientHello);
            }
            _ => return Err(InspectionError::ForbiddenQuicFrame(frame_type)),
        }
    }
    Ok(())
}

fn parse_ack(reader: &mut QuicReader<'_>, has_ecn: bool) -> Result<(), InspectionError> {
    let largest = reader.varint()?;
    let _delay = reader.varint()?;
    let range_count = reader.varint()?;
    if range_count > MAX_ACK_RANGES {
        return Err(InspectionError::ResourceLimit("QUIC ACK range count"));
    }
    let first_range = reader.varint()?;
    let mut smallest =
        largest
            .checked_sub(first_range)
            .ok_or(InspectionError::InvalidQuicInitial(
                "invalid first ACK range",
            ))?;
    for _ in 0..range_count {
        let gap = reader.varint()?;
        let range = reader.varint()?;
        let next_largest = smallest
            .checked_sub(gap.saturating_add(2))
            .ok_or(InspectionError::InvalidQuicInitial("invalid ACK gap"))?;
        smallest = next_largest
            .checked_sub(range)
            .ok_or(InspectionError::InvalidQuicInitial("invalid ACK range"))?;
    }
    if has_ecn {
        reader.varint()?;
        reader.varint()?;
        reader.varint()?;
    }
    Ok(())
}

fn parse_transport_close(reader: &mut QuicReader<'_>) -> Result<(), InspectionError> {
    reader.varint()?;
    reader.varint()?;
    let reason_len = usize::try_from(reader.varint()?)
        .map_err(|_| InspectionError::ResourceLimit("QUIC close reason bytes"))?;
    if reason_len > MAX_CLOSE_REASON_BYTES {
        return Err(InspectionError::ResourceLimit("QUIC close reason bytes"));
    }
    reader.take(reason_len)?;
    Ok(())
}

#[derive(Default)]
struct CryptoReassembler {
    bytes: Vec<u8>,
    present: Vec<bool>,
    contiguous: usize,
    fragments: usize,
}

impl CryptoReassembler {
    fn insert(&mut self, offset: usize, data: &[u8]) -> Result<(), InspectionError> {
        self.fragments = self.fragments.saturating_add(1);
        if self.fragments > MAX_CRYPTO_FRAGMENTS {
            return Err(InspectionError::ResourceLimit("QUIC CRYPTO fragment count"));
        }
        let end = offset
            .checked_add(data.len())
            .ok_or(InspectionError::ResourceLimit("QUIC CRYPTO bytes"))?;
        if end > MAX_CLIENT_HELLO_BYTES {
            return Err(InspectionError::ResourceLimit("QUIC CRYPTO bytes"));
        }
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
            self.present.resize(end, false);
        }
        for (index, &byte) in data.iter().enumerate() {
            let position = offset + index;
            if self.present[position] {
                if self.bytes[position] != byte {
                    return Err(InspectionError::ConflictingCryptoData);
                }
            } else {
                self.bytes[position] = byte;
                self.present[position] = true;
            }
        }
        while self.contiguous < self.present.len() && self.present[self.contiguous] {
            self.contiguous += 1;
        }
        Ok(())
    }

    fn client_hello(&self) -> Result<Option<InspectedServerName>, InspectionError> {
        inspect_client_hello_prefix(&self.bytes[..self.contiguous])
    }
}

struct QuicReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> QuicReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    const fn at(input: &'a [u8], offset: usize) -> Self {
        Self { input, offset }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], InspectionError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(InspectionError::InvalidQuicInitial("length overflow"))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(InspectionError::InvalidQuicInitial("truncated field"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, InspectionError> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> Result<u64, InspectionError> {
        let first = self.u8()?;
        let length = 1_usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for &byte in self.take(length - 1)? {
            value = (value << 8) | u64::from(byte);
        }
        Ok(value)
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.input.len()
    }
}

#[cfg(test)]
#[path = "quic_tests.rs"]
mod tests;
