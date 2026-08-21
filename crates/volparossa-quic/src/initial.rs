use thiserror::Error;

/// Maximum QUIC connection ID length from RFC 9000.
const MAX_CONNECTION_ID_LEN: usize = 20;
/// Local defensive bound on `retry/NEW_TOKEN` material carried into an Initial.
const MAX_INITIAL_TOKEN_LEN: usize = 4_096;
/// AEAD tag length for QUIC v1 Initial packets.
const QUIC_TAG_LEN: usize = 16;

/// Safely parsed public header of a QUIC Initial packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicInitial<'a> {
    /// QUIC version from the long header.
    pub version: u32,
    /// Destination connection ID used to derive v1 Initial keys.
    pub destination_connection_id: &'a [u8],
    /// Source connection ID.
    pub source_connection_id: &'a [u8],
    /// Retry token, empty for the first client Initial.
    pub token: &'a [u8],
    /// Offset at which the protected packet number begins.
    pub protected_payload_offset: usize,
    /// Declared length of packet number plus protected payload.
    pub protected_payload_len: usize,
}

/// Reasons a datagram cannot be treated as a valid QUIC Initial candidate.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum QuicInitialError {
    /// Input ended before a length-delimited field completed.
    #[error("truncated QUIC Initial")]
    Truncated,
    /// Fixed and long-header bits are not both set.
    #[error("not a QUIC long header with a fixed bit")]
    NotLongHeader,
    /// Long-header packet type is not Initial.
    #[error("QUIC long-header packet is not Initial")]
    NotInitial,
    /// Version negotiation (zero) is not an Initial packet.
    #[error("QUIC version negotiation is not an Initial")]
    VersionNegotiation,
    /// Connection ID exceeds the protocol limit.
    #[error("QUIC connection ID exceeds 20 bytes")]
    ConnectionIdTooLong,
    /// A QUIC variable integer was malformed or too large for this platform.
    #[error("invalid QUIC variable integer")]
    InvalidVarInt,
    /// Token exceeds the local defensive limit.
    #[error("QUIC Initial token exceeds local limit")]
    TokenTooLong,
    /// Declared protected payload cannot contain a packet number and AEAD tag.
    #[error("invalid QUIC Initial protected payload length")]
    InvalidPayloadLength,
    /// Datagram contains trailing or declared bytes outside its input boundary.
    #[error("QUIC Initial declared length exceeds datagram")]
    DeclaredLengthExceedsDatagram,
}

/// Parses only the public QUIC Initial header, applying strict allocation-free bounds.
///
/// Successful parsing is a classifier signal, not whitelist authorisation. The native endpoint
/// must remove header protection, authenticate/decrypt Initial CRYPTO data, reassemble TLS
/// `ClientHello` fragments, and prove a policy-approved SNI before forwarding UDP/443.
///
/// # Errors
///
/// Returns an error when the datagram is truncated, is not an Initial, or violates connection-ID,
/// token, variable-integer, or protected-payload bounds.
pub fn parse_initial(datagram: &[u8]) -> Result<QuicInitial<'_>, QuicInitialError> {
    let first = *datagram.first().ok_or(QuicInitialError::Truncated)?;
    if first & 0xc0 != 0xc0 {
        return Err(QuicInitialError::NotLongHeader);
    }
    // For QUIC v1/v2 this type encoding denotes Initial. Unsupported versions are rejected by
    // the session policy after parsing, before key derivation.
    if first & 0x30 != 0 {
        return Err(QuicInitialError::NotInitial);
    }

    let version = read_u32(datagram, 1)?;
    if version == 0 {
        return Err(QuicInitialError::VersionNegotiation);
    }
    let mut cursor = 5;

    let destination_len = usize::from(read_u8(datagram, &mut cursor)?);
    if destination_len > MAX_CONNECTION_ID_LEN {
        return Err(QuicInitialError::ConnectionIdTooLong);
    }
    let destination_connection_id = take(datagram, &mut cursor, destination_len)?;

    let source_len = usize::from(read_u8(datagram, &mut cursor)?);
    if source_len > MAX_CONNECTION_ID_LEN {
        return Err(QuicInitialError::ConnectionIdTooLong);
    }
    let source_connection_id = take(datagram, &mut cursor, source_len)?;

    let token_len = usize::try_from(read_varint(datagram, &mut cursor)?)
        .map_err(|_| QuicInitialError::InvalidVarInt)?;
    if token_len > MAX_INITIAL_TOKEN_LEN {
        return Err(QuicInitialError::TokenTooLong);
    }
    let token = take(datagram, &mut cursor, token_len)?;

    let protected_payload_len = usize::try_from(read_varint(datagram, &mut cursor)?)
        .map_err(|_| QuicInitialError::InvalidVarInt)?;
    // Packet number length is protected but is always 1..=4 bytes.
    if protected_payload_len < 1 + QUIC_TAG_LEN {
        return Err(QuicInitialError::InvalidPayloadLength);
    }
    if protected_payload_len > datagram.len().saturating_sub(cursor) {
        return Err(QuicInitialError::DeclaredLengthExceedsDatagram);
    }

    Ok(QuicInitial {
        version,
        destination_connection_id,
        source_connection_id,
        token,
        protected_payload_offset: cursor,
        protected_payload_len,
    })
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, QuicInitialError> {
    let value = *bytes.get(*cursor).ok_or(QuicInitialError::Truncated)?;
    *cursor = cursor
        .checked_add(1)
        .ok_or(QuicInitialError::InvalidVarInt)?;
    Ok(value)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, QuicInitialError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(QuicInitialError::Truncated)?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64, QuicInitialError> {
    let first = read_u8(bytes, cursor)?;
    let length = 1_usize << usize::from(first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..length {
        value = value
            .checked_shl(8)
            .ok_or(QuicInitialError::InvalidVarInt)?
            | u64::from(read_u8(bytes, cursor)?);
    }
    Ok(value)
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], QuicInitialError> {
    let end = cursor
        .checked_add(length)
        .ok_or(QuicInitialError::InvalidVarInt)?;
    let value = bytes.get(*cursor..end).ok_or(QuicInitialError::Truncated)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(payload_len: u8) -> Vec<u8> {
        let mut packet = vec![
            0xc0,
            0x00,
            0x00,
            0x00,
            0x01, // flags and version 1
            0x04,
            1,
            2,
            3,
            4, // DCID
            0x02,
            5,
            6,    // SCID
            0x00, // token length
            payload_len,
        ];
        packet.resize(packet.len() + usize::from(payload_len), 0);
        packet
    }

    #[test]
    fn parses_bounded_v1_initial_header() {
        let packet = candidate(32);
        let parsed = parse_initial(&packet).expect("valid public header");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.destination_connection_id, [1, 2, 3, 4]);
        assert_eq!(parsed.source_connection_id, [5, 6]);
        assert_eq!(parsed.protected_payload_len, 32);
    }

    #[test]
    fn rejects_short_or_non_initial_datagrams() {
        assert_eq!(parse_initial(&[]), Err(QuicInitialError::Truncated));
        assert_eq!(parse_initial(&[0x40]), Err(QuicInitialError::NotLongHeader));
        let mut handshake = candidate(32);
        handshake[0] = 0xe0;
        assert_eq!(parse_initial(&handshake), Err(QuicInitialError::NotInitial));
    }

    #[test]
    fn rejects_declared_length_outside_datagram() {
        let mut packet = candidate(32);
        packet.truncate(packet.len() - 1);
        assert_eq!(
            parse_initial(&packet),
            Err(QuicInitialError::DeclaredLengthExceedsDatagram)
        );
    }

    #[test]
    fn varint_lengths_are_bounded_before_slicing() {
        let mut packet = candidate(32);
        // Replace the one-byte token length with a 2-byte value of 4097.
        let token_offset = 13;
        packet.splice(token_offset..=token_offset, [0x50, 0x01]);
        assert_eq!(parse_initial(&packet), Err(QuicInitialError::TokenTooLong));
    }
}
