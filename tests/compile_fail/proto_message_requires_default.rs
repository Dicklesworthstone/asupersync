//! `ProtoMessage` requires `Default`, and that is a semantic requirement rather
//! than a convenience bound.
//!
//! Protocol Buffers decoding is a *merge* onto the default instance: every
//! field absent from the wire keeps its default value, which is why a
//! zero-length message decodes successfully instead of erroring. A message type
//! with no default has no well-defined starting point for that merge, so the
//! trait refuses it at the definition site rather than at the first decode.

use asupersync::grpc::protobuf::{
    ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError, ProtobufWireField,
};

struct NoDefault {
    value: u64,
}

impl ProtoMessage for NoDefault {
    fn encode_fields(&self, encoder: &mut ProtobufWireEncoder) -> Result<(), ProtobufWireError> {
        encoder.write_varint(1, self.value)
    }

    fn merge_field<'wire>(
        &mut self,
        field: &ProtobufWireField<'wire>,
        _decoder: &mut ProtobufWireDecoder<'wire, '_>,
    ) -> Result<bool, ProtobufWireError> {
        if field.field_number() == 1 {
            self.value = field.as_varint()?;
            return Ok(true);
        }
        Ok(false)
    }
}

fn main() {}
