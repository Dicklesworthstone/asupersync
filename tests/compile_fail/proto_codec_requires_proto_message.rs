//! `ProtoCodec` is genuinely gated on the owned message trait.
//!
//! Constructing the codec is deliberately unbounded — a caller may name the
//! type parameters before proving anything about them — but *using* it as a
//! `Codec` requires `ProtoMessage` on both directions. Without this contract
//! the codec would silently accept any type and fail somewhere deeper.

use asupersync::grpc::codec::Codec;
use asupersync::grpc::protobuf::ProtoCodec;

struct NotAMessage;

fn main() {
    let mut codec: ProtoCodec<NotAMessage, NotAMessage> = ProtoCodec::new();
    let _ = codec.encode(&NotAMessage);
}
