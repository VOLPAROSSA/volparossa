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

/// Decode a protobuf and reject alternate encodings, duplicate singular
/// fields, and unknown fields by requiring an exact decode/re-encode round
/// trip. Multiple occurrences of a repeated field are distinct semantic
/// elements and remain canonical when the round trip preserves them exactly.
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

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::decode_canonical;
    use crate::ProtocolError;

    #[derive(Clone, PartialEq, Message)]
    struct SingularBytes {
        #[prost(bytes = "vec", tag = "7")]
        value: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct RepeatedBytes {
        #[prost(bytes = "vec", repeated, tag = "7")]
        values: Vec<Vec<u8>>,
    }

    #[test]
    fn duplicate_singular_occurrence_is_noncanonical() {
        let duplicated = [0x3a, 0x01, 0x01, 0x3a, 0x01, 0x01];
        assert!(matches!(
            decode_canonical::<SingularBytes>(&duplicated, duplicated.len()),
            Err(ProtocolError::NonCanonical)
        ));
    }

    #[test]
    fn repeated_occurrences_are_distinct_canonical_elements() {
        let repeated = [0x3a, 0x00, 0x3a, 0x00];
        let decoded = decode_canonical::<RepeatedBytes>(&repeated, repeated.len())
            .expect("two repeated empty byte strings are an exact canonical message");
        assert_eq!(decoded.values, vec![Vec::<u8>::new(), Vec::<u8>::new()]);
    }
}
