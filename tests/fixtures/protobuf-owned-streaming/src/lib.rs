//! Independent streaming-consumer fixture for the owned protobuf derive.

use std::collections::HashMap;

use asupersync::bytes::BytesMut;
use asupersync::grpc::codec::FramedCodec;
use asupersync::grpc::protobuf::SymmetricProtoCodec;

#[derive(Clone, Debug, Default, Eq, PartialEq, asupersync::ProtoMessage)]
pub struct Cursor {
    #[proto(uint64, tag = 1)]
    pub partition: u64,
    #[proto(uint64, tag = 2)]
    pub offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, asupersync::ProtoOneof)]
pub enum StreamEvent {
    #[proto(bytes, tag = 5)]
    Data(Vec<u8>),
    #[proto(message, tag = 6)]
    Checkpoint(Cursor),
    #[proto(string, tag = 7)]
    Warning(String),
}

#[derive(Clone, Debug, Default, Eq, PartialEq, asupersync::ProtoMessage)]
pub struct StreamEnvelope {
    #[proto(string, tag = 1)]
    pub stream_id: String,
    #[proto(uint64, repeated, packed, tag = 2)]
    pub acknowledgements: Vec<u64>,
    #[proto(map, key = "string", value = "string", tag = 3)]
    pub labels: HashMap<String, String>,
    #[proto(message, optional, tag = 4)]
    pub cursor: Option<Cursor>,
    #[proto(oneof, tags = "5, 6, 7")]
    pub event: Option<StreamEvent>,
}

pub fn framed_round_trip(
    messages: &[StreamEnvelope],
) -> Result<Vec<StreamEnvelope>, asupersync::grpc::GrpcError> {
    let mut codec = FramedCodec::new(SymmetricProtoCodec::<StreamEnvelope>::new());
    let mut wire = BytesMut::new();
    for message in messages {
        codec.encode_message(message, &mut wire)?;
    }

    let mut decoded = Vec::new();
    while let Some(message) = codec.decode_message(&mut wire)? {
        decoded.push(message);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{Cursor, StreamEnvelope, StreamEvent, framed_round_trip};

    #[test]
    fn realistic_stream_preserves_order_and_shapes() {
        let expected = vec![
            StreamEnvelope {
                stream_id: "orders".to_owned(),
                acknowledgements: vec![1, 2, 3],
                labels: HashMap::from([
                    ("region".to_owned(), "us-east".to_owned()),
                    ("tier".to_owned(), "gold".to_owned()),
                ]),
                cursor: Some(Cursor {
                    partition: 4,
                    offset: 99,
                }),
                event: Some(StreamEvent::Data(b"event".to_vec())),
            },
            StreamEnvelope {
                stream_id: "orders".to_owned(),
                event: Some(StreamEvent::Checkpoint(Cursor {
                    partition: 4,
                    offset: 100,
                })),
                ..StreamEnvelope::default()
            },
        ];
        assert_eq!(
            framed_round_trip(&expected).expect("framed round trip"),
            expected
        );
    }
}
