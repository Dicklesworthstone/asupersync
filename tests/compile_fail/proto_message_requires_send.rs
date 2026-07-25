//! `ProtoMessage` requires `Send`, enforced where the message is *defined*
//! rather than where it is eventually streamed.
//!
//! The gRPC `Codec` trait is `Send + 'static` because unary and streaming call
//! sites move messages across worker threads. If the bound were only applied at
//! the codec, a downstream author could write a perfectly good-looking
//! `ProtoMessage` impl and only discover the problem much later, at an
//! unrelated call site, with a diagnostic pointing at the wrong place.

use std::rc::Rc;

use asupersync::grpc::protobuf::{
    ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError, ProtobufWireField,
};

#[derive(Default)]
struct NotSend {
    value: Rc<u64>,
}

impl ProtoMessage for NotSend {
    fn encode_fields(&self, encoder: &mut ProtobufWireEncoder) -> Result<(), ProtobufWireError> {
        encoder.write_varint(1, *self.value)
    }

    fn merge_field<'wire>(
        &mut self,
        field: &ProtobufWireField<'wire>,
        _decoder: &mut ProtobufWireDecoder<'wire, '_>,
    ) -> Result<bool, ProtobufWireError> {
        if field.field_number() == 1 {
            self.value = Rc::new(field.as_varint()?);
            return Ok(true);
        }
        Ok(false)
    }
}

fn main() {}
