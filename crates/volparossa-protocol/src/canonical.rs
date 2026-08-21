use prost::Message;

use crate::ProtocolError;

/// Encode a protobuf message using the one accepted VOLPAROSSA representation.
///
/// Canonical schemas in this crate never contain protobuf maps. Callers must
/// additionally preserve the documented sorted order for repeated set-like
/// fields; message-specific validation enforces that invariant.
///
/// # Errors
///
/// Returns an oversized error when the encoded length exceeds the supplied
/// limit, or an encoding error when protobuf encoding fails.
pub fn encode_canonical<M: Message>(message: &M, maximum: usize) -> Result<Vec<u8>, ProtocolError> {
    if message.encoded_len() > maximum {
        return Err(ProtocolError::Oversized {
            what: "protobuf message",
            maximum,
        });
    }
    let mut encoded = Vec::with_capacity(message.encoded_len());
    message.encode(&mut encoded)?;
    Ok(encoded)
}

/// Decode a protobuf and reject alternate encodings, duplicate fields, and
/// unknown fields by requiring an exact decode/re-encode round trip.
///
/// # Errors
///
/// Returns an error for oversized, malformed, or non-canonical input.
pub fn decode_canonical<M: Message + Default>(
    encoded: &[u8],
    maximum: usize,
) -> Result<M, ProtocolError> {
    if encoded.len() > maximum {
        return Err(ProtocolError::Oversized {
            what: "protobuf message",
            maximum,
        });
    }
    let message = M::decode(encoded)?;
    let canonical = encode_canonical(&message, maximum)?;
    if canonical != encoded {
        return Err(ProtocolError::NonCanonical);
    }
    Ok(message)
}
