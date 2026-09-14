//! Closed expression set: exact IPv4/IPv6 UDP tuple predicates and one counter.

use std::net::IpAddr;

use super::{
    KernelError, MASK, NESTED, ReceiveCounters, ReceiveTuple, attributes, attributes_map, number,
    push_attribute, push_string_attribute, string, u32_field, u64_field, value,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::kernel::receive_accounting) enum Expression {
    Meta(u32),
    Payload { base: u32, offset: u32, length: u32 },
    Compare(Vec<u8>),
    Counter,
}

pub(in crate::kernel::receive_accounting) fn expressions(
    tuple: Option<&ReceiveTuple>,
) -> Vec<Expression> {
    let mut output = Vec::new();
    if let Some(tuple) = tuple {
        // meta protocol is the EtherType; L4PROTO uses the kernel-validated transport offset.
        output.extend([
            Expression::Meta(1),
            Expression::Compare(if tuple.local.is_ipv4() {
                vec![8, 0]
            } else {
                vec![0x86, 0xdd]
            }),
            Expression::Meta(16),
            Expression::Compare(vec![17]),
        ]);
        for (remote, address) in [(true, tuple.remote.ip()), (false, tuple.local.ip())] {
            let (offset, bytes) = match address {
                IpAddr::V4(address) => (if remote { 12 } else { 16 }, address.octets().to_vec()),
                IpAddr::V6(address) => (if remote { 8 } else { 24 }, address.octets().to_vec()),
            };
            output.extend([
                Expression::Payload {
                    base: 1,
                    offset,
                    length: u32::try_from(bytes.len()).expect("IPv4/IPv6 address width"),
                },
                Expression::Compare(bytes),
            ]);
        }
        let mut ports = tuple.remote.port().to_be_bytes().to_vec();
        ports.extend(tuple.local.port().to_be_bytes());
        output.extend([
            Expression::Payload {
                base: 2,
                offset: 0,
                length: 4,
            },
            Expression::Compare(ports),
        ]);
    }
    output.push(Expression::Counter);
    output
}

pub(super) fn encode(expressions: &[Expression]) -> Result<Vec<u8>, KernelError> {
    let mut output = Vec::new();
    for expression in expressions {
        let mut data = Vec::new();
        let name = match expression {
            Expression::Meta(key) => {
                number(&mut data, 1, 1)?;
                number(&mut data, 2, *key)?;
                "meta"
            }
            Expression::Payload {
                base,
                offset,
                length,
            } => {
                number(&mut data, 1, 1)?;
                number(&mut data, 2, *base)?;
                number(&mut data, 3, *offset)?;
                number(&mut data, 4, *length)?;
                "payload"
            }
            Expression::Compare(bytes) => {
                number(&mut data, 1, 1)?;
                number(&mut data, 2, 0)?;
                let mut value = Vec::new();
                push_attribute(&mut value, 1, bytes)?;
                push_attribute(&mut data, 3 | NESTED, &value)?;
                "cmp"
            }
            Expression::Counter => "counter",
        };
        let mut element = Vec::new();
        push_string_attribute(&mut element, 1, name)?;
        push_attribute(&mut element, 2 | NESTED, &data)?;
        push_attribute(&mut output, 1 | NESTED, &element)?;
    }
    Ok(output)
}

pub(super) fn decode(bytes: &[u8]) -> Result<(Vec<Expression>, ReceiveCounters), KernelError> {
    let mut output = Vec::new();
    let mut counters = None;
    for (kind, element) in attributes(bytes)? {
        if kind & MASK != 1 || output.len() >= 11 {
            return Err(KernelError::Malformed);
        }
        let fields = attributes_map(element, &[1, 2], &[])?;
        let data = value(&fields, 2)?;
        let expression = match string(&fields, 1)? {
            "meta" => {
                let fields = attributes_map(data, &[1, 2], &[])?;
                if u32_field(&fields, 1)? != 1 {
                    return Err(KernelError::Invalid);
                }
                Expression::Meta(u32_field(&fields, 2)?)
            }
            "payload" => {
                let fields = attributes_map(data, &[1, 2, 3, 4], &[])?;
                if u32_field(&fields, 1)? != 1 {
                    return Err(KernelError::Invalid);
                }
                Expression::Payload {
                    base: u32_field(&fields, 2)?,
                    offset: u32_field(&fields, 3)?,
                    length: u32_field(&fields, 4)?,
                }
            }
            "cmp" => {
                let fields = attributes_map(data, &[1, 2, 3], &[])?;
                if u32_field(&fields, 1)? != 1 || u32_field(&fields, 2)? != 0 {
                    return Err(KernelError::Invalid);
                }
                let data = attributes_map(value(&fields, 3)?, &[1], &[])?;
                let bytes = value(&data, 1)?;
                if bytes.is_empty() || bytes.len() > 16 {
                    return Err(KernelError::Invalid);
                }
                Expression::Compare(bytes.to_vec())
            }
            "counter" => {
                let fields = attributes_map(data, &[1, 2, 3], &[3])?;
                if counters.is_some() {
                    return Err(KernelError::Invalid);
                }
                counters = Some(ReceiveCounters {
                    bytes: u64_field(&fields, 1)?,
                    packets: u64_field(&fields, 2)?,
                });
                Expression::Counter
            }
            _ => return Err(KernelError::Invalid),
        };
        output.push(expression);
    }
    Ok((output, counters.ok_or(KernelError::Malformed)?))
}

#[cfg(test)]
mod tests {
    use super::{
        NESTED, ReceiveCounters, ReceiveTuple, decode, encode, expressions, push_attribute,
        push_string_attribute,
    };
    use volparossa_routing::WireguardRole;

    #[test]
    fn receive_accounting_exact_v4_v6_dump_and_counter_padding() {
        for (local, remote) in [
            ("10.244.8.1:18081", "10.244.8.2:28081"),
            ("[fd44:8::1]:18081", "[fd44:8::2]:28081"),
        ] {
            let tuple = ReceiveTuple {
                context_id: [1; 16],
                path_id: 1,
                role: WireguardRole::RelayExit,
                local: local.parse().unwrap(),
                remote: remote.parse().unwrap(),
            };
            let expected = expressions(Some(&tuple));
            let mut encoded = encode(&expected[..expected.len() - 1]).unwrap();
            let mut counter = Vec::new();
            for (kind, value) in [(1, 2048_u64), (2, 2)] {
                push_attribute(&mut counter, 3, &[]).unwrap();
                push_attribute(&mut counter, kind, &value.to_be_bytes()).unwrap();
            }
            let mut element = Vec::new();
            push_string_attribute(&mut element, 1, "counter").unwrap();
            push_attribute(&mut element, 2 | NESTED, &counter).unwrap();
            push_attribute(&mut encoded, 1 | NESTED, &element).unwrap();
            assert_eq!(
                decode(&encoded).unwrap(),
                (
                    expected,
                    ReceiveCounters {
                        bytes: 2048,
                        packets: 2
                    }
                )
            );
            for length in 0..encoded.len() {
                assert!(decode(&encoded[..length]).is_err());
            }
            // A second counter must never double count or hide an extra expression.
            push_attribute(&mut encoded, 1 | NESTED, &element).unwrap();
            assert!(decode(&encoded).is_err());
        }
    }
}
