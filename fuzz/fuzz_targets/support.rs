use prost::Message;
use volparossa_protocol::{decode_canonical, encode_canonical};

pub fn exercise_message<T, F>(data: &[u8], maximum: usize, validate: F)
where
    T: Message + Default + PartialEq,
    F: FnOnce(&T),
{
    let decoded = decode_canonical::<T>(data, maximum);
    if data.len() > maximum {
        assert!(decoded.is_err());
        return;
    }

    let Ok(message) = decoded else {
        return;
    };
    validate(&message);

    let canonical = encode_canonical(&message, maximum).expect("decoded message remains bounded");
    assert_eq!(canonical, data);
    exercise_noncanonical_forms::<T>(&message, &canonical, maximum);
}

fn exercise_noncanonical_forms<T>(message: &T, canonical: &[u8], maximum: usize)
where
    T: Message + Default + PartialEq,
{
    if canonical.len().saturating_add(3) <= maximum {
        let mut unknown_field = canonical.to_vec();
        unknown_field.extend_from_slice(&[0xfa, 0x7f, 0x00]);
        assert!(decode_canonical::<T>(&unknown_field, maximum).is_err());
    }

    let Some((first_tag, first_end)) = field_at(canonical, 0) else {
        return;
    };
    if canonical.len().saturating_add(first_end) <= maximum {
        let mut duplicate = canonical.to_vec();
        duplicate.extend_from_slice(&canonical[..first_end]);
        if let Ok(duplicated_message) = decode_canonical::<T>(&duplicate, maximum) {
            assert!(
                &duplicated_message != message,
                "an accepted repeated field occurrence must change message semantics",
            );
        }
    }

    if let Some((second_tag, second_end)) = field_at(canonical, first_end) {
        if first_tag != second_tag {
            let mut reordered = Vec::with_capacity(canonical.len());
            reordered.extend_from_slice(&canonical[first_end..second_end]);
            reordered.extend_from_slice(&canonical[..first_end]);
            reordered.extend_from_slice(&canonical[second_end..]);
            assert!(decode_canonical::<T>(&reordered, maximum).is_err());
        }
    }

    if let Some(overlong) = overlong_first_varint(canonical, maximum) {
        assert!(decode_canonical::<T>(&overlong, maximum).is_err());
    }
}

fn field_at(encoded: &[u8], start: usize) -> Option<(u64, usize)> {
    let (key, mut cursor) = read_varint(encoded, start)?;
    let tag = key >> 3;
    if tag == 0 {
        return None;
    }
    cursor = match key & 0x07 {
        0 => read_varint(encoded, cursor)?.1,
        1 => cursor.checked_add(8)?,
        2 => {
            let (length, payload_start) = read_varint(encoded, cursor)?;
            payload_start.checked_add(usize::try_from(length).ok()?)?
        }
        5 => cursor.checked_add(4)?,
        _ => return None,
    };
    (cursor <= encoded.len()).then_some((tag, cursor))
}

fn overlong_first_varint(encoded: &[u8], maximum: usize) -> Option<Vec<u8>> {
    let (key, value_start) = read_varint(encoded, 0)?;
    if key & 0x07 != 0 || encoded.len().saturating_add(1) > maximum {
        return None;
    }
    let (_, value_end) = read_varint(encoded, value_start)?;
    let mut overlong = Vec::with_capacity(encoded.len() + 1);
    overlong.extend_from_slice(&encoded[..value_end - 1]);
    overlong.push(encoded[value_end - 1] | 0x80);
    overlong.push(0);
    overlong.extend_from_slice(&encoded[value_end..]);
    Some(overlong)
}

fn read_varint(encoded: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *encoded.get(start.checked_add(shift / 7)?)?;
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, start + shift / 7 + 1));
        }
    }
    None
}
