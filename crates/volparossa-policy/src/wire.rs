use prost::Message;

use crate::PolicyError;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SignedManifestProto {
    #[prost(message, optional, tag = "1")]
    pub body: Option<ManifestBodyProto>,
    #[prost(bytes = "vec", tag = "2")]
    pub body_hash: Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    pub signatures: Vec<ManifestSignatureProto>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ManifestBodyProto {
    #[prost(uint32, tag = "1")]
    pub schema_version: u32,
    #[prost(uint64, tag = "2")]
    pub manifest_version: u64,
    #[prost(uint32, tag = "3")]
    pub minimum_protocol_version: u32,
    #[prost(uint64, tag = "4")]
    pub issued_at_ms: u64,
    #[prost(uint64, tag = "5")]
    pub valid_from_ms: u64,
    #[prost(uint64, tag = "6")]
    pub expires_at_ms: u64,
    #[prost(uint32, tag = "7")]
    pub required_signatures: u32,
    #[prost(message, repeated, tag = "8")]
    pub maintainers: Vec<MaintainerProto>,
    #[prost(message, repeated, tag = "9")]
    pub rules: Vec<DestinationRuleProto>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct MaintainerProto {
    #[prost(bytes = "vec", tag = "1")]
    pub key_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: Vec<u8>,
    #[prost(int32, tag = "3")]
    pub environment: i32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DestinationRuleProto {
    #[prost(oneof = "destination_rule_proto::Destination", tags = "1, 2, 3")]
    pub destination: Option<destination_rule_proto::Destination>,
    #[prost(message, repeated, tag = "4")]
    pub permissions: Vec<ProtocolPortProto>,
}

pub(crate) mod destination_rule_proto {
    use prost::Oneof;

    #[derive(Clone, PartialEq, Oneof)]
    pub(crate) enum Destination {
        #[prost(string, tag = "1")]
        ExactDomain(String),
        #[prost(string, tag = "2")]
        WildcardDomain(String),
        #[prost(bytes, tag = "3")]
        ExactIp(Vec<u8>),
    }
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ProtocolPortProto {
    #[prost(int32, tag = "1")]
    pub protocol: i32,
    #[prost(uint32, tag = "2")]
    pub port: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ManifestSignatureProto {
    #[prost(bytes = "vec", tag = "1")]
    pub key_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
}

pub(crate) fn encode_canonical<M: Message>(
    message: &M,
    maximum: usize,
) -> Result<Vec<u8>, PolicyError> {
    if message.encoded_len() > maximum {
        return Err(PolicyError::Oversized {
            what: "canonical protobuf",
            maximum,
        });
    }
    let mut encoded = Vec::with_capacity(message.encoded_len());
    message.encode(&mut encoded)?;
    Ok(encoded)
}

pub(crate) fn decode_canonical<M: Message + Default>(
    encoded: &[u8],
    maximum: usize,
) -> Result<M, PolicyError> {
    if encoded.is_empty() || encoded.len() > maximum {
        return Err(PolicyError::Oversized {
            what: "signed policy manifest",
            maximum,
        });
    }
    let decoded = M::decode(encoded)?;
    if encode_canonical(&decoded, maximum)? != encoded {
        return Err(PolicyError::NonCanonicalProtobuf);
    }
    Ok(decoded)
}
