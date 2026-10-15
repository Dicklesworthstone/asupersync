//! Independent unary-consumer fixture for the owned protobuf derive.

use asupersync::grpc::codec::Codec;
use asupersync::grpc::protobuf::ProtoCodec;

#[derive(Clone, Debug, Default, Eq, PartialEq, asupersync::ProtoMessage)]
pub struct LookupRequest {
    #[proto(string, tag = 1)]
    pub account: String,
    #[proto(uint64, optional, tag = 2)]
    pub revision: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, asupersync::ProtoMessage)]
pub struct LookupResponse {
    #[proto(bytes, tag = 1)]
    pub document: Vec<u8>,
    #[proto(string, repeated, tag = 2)]
    pub warnings: Vec<String>,
}

pub fn unary_round_trip(
    response: &LookupResponse,
) -> Result<LookupResponse, asupersync::grpc::protobuf::ProtoCodecError> {
    let mut codec: ProtoCodec<LookupResponse, LookupResponse> = ProtoCodec::new();
    let wire = codec.encode(response)?;
    codec.decode(&wire)
}

#[cfg(test)]
mod tests {
    use super::{LookupResponse, unary_round_trip};

    #[test]
    fn realistic_unary_response_round_trips() {
        let expected = LookupResponse {
            document: b"owned-protobuf".to_vec(),
            warnings: vec!["stale replica".to_owned()],
        };
        assert_eq!(unary_round_trip(&expected).expect("round trip"), expected);
    }
}
