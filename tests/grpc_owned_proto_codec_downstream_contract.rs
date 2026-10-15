//! Downstream-consumer contract for the owned protobuf codec.
//!
//! Bead: asupersync-5z2scg.1.2 (Protobuf A2)
//!
//! This file is deliberately an *integration* test rather than an inline unit
//! test. Inline tests live inside the crate and can therefore reach private
//! items, so they cannot prove the claim this bead's acceptance criteria
//! actually make: that a downstream crate can define its own protobuf messages
//! against the owned trait with no in-tree registry, no derive macro, and no
//! `prost` dependency. Compiling this file at all is that proof — if
//! [`ProtoMessage`] ever grew a sealed method, a crate-private type in a
//! signature, or a required registration step, this stops building.
//!
//! Coverage:
//! - a downstream message type authored purely against the public API;
//! - unary use through [`ProtoCodec`];
//! - streaming use through [`FramedCodec`], including multi-message buffers and
//!   partial frames;
//! - message-size limits set by the framing layer actually reaching the codec;
//! - forward compatibility: an old consumer round-trips a newer peer's fields.

#![allow(missing_docs)]

use asupersync::bytes::BytesMut;
use asupersync::grpc::codec::{Codec, FramedCodec};
use asupersync::grpc::protobuf::{
    ProtoCodec, ProtoCodecError, ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder,
    ProtobufWireError, ProtobufWireField, ProtobufWireLimits, SymmetricProtoCodec, UnknownFields,
    WireType, merge_nested_message,
};

// ---------------------------------------------------------------------------
// A downstream schema, authored entirely against the public surface.
// ---------------------------------------------------------------------------

/// Protocol Buffers sign-extends `int32` into a 64-bit varint, so the
/// specified narrowing is "keep the low 32 bits, reinterpret as two's
/// complement". Going through the byte representation makes that a pure
/// reinterpretation rather than a lossy cast.
fn narrow_to_i32(value: u64) -> i32 {
    i32::from_le_bytes((value as u32).to_le_bytes())
}

/// `message Point { int32 x = 1; int32 y = 2; }`
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Point {
    x: i32,
    y: i32,
}

impl ProtoMessage for Point {
    fn encode_fields(&self, encoder: &mut ProtobufWireEncoder) -> Result<(), ProtobufWireError> {
        if self.x != 0 {
            encoder.write_int32(1, self.x)?;
        }
        if self.y != 0 {
            encoder.write_int32(2, self.y)?;
        }
        Ok(())
    }

    fn merge_field<'wire>(
        &mut self,
        field: &ProtobufWireField<'wire>,
        _decoder: &mut ProtobufWireDecoder<'wire, '_>,
    ) -> Result<bool, ProtobufWireError> {
        match field.field_number() {
            1 => {
                self.x = narrow_to_i32(field.as_varint()?);
                Ok(true)
            }
            2 => {
                self.y = narrow_to_i32(field.as_varint()?);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// `message Path { string label = 1; repeated Point points = 2; }`
///
/// Preserves unknown fields so a build of this schema can forward fields added
/// by a newer peer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Path {
    label: String,
    points: Vec<Point>,
    unknown: UnknownFields,
}

impl ProtoMessage for Path {
    fn encode_fields(&self, encoder: &mut ProtobufWireEncoder) -> Result<(), ProtobufWireError> {
        if !self.label.is_empty() {
            encoder.write_string(1, &self.label)?;
        }
        for point in &self.points {
            let nested = point.encode_to_bytes(ProtobufWireLimits::default())?;
            encoder.write_message(2, nested.as_ref())?;
        }
        self.unknown.encode(encoder)?;
        Ok(())
    }

    fn merge_field<'wire>(
        &mut self,
        field: &ProtobufWireField<'wire>,
        decoder: &mut ProtobufWireDecoder<'wire, '_>,
    ) -> Result<bool, ProtobufWireError> {
        match field.field_number() {
            1 => {
                field.as_str()?.clone_into(&mut self.label);
                Ok(true)
            }
            2 => {
                // Repeated message: each record appends a fresh element.
                let mut point = Point::default();
                merge_nested_message(&mut point, field, decoder)?;
                self.points.push(point);
                Ok(true)
            }
            _ => {
                // A group delimiter's `raw()` is only the delimiter key, so a
                // group has to be captured whole or the preserved bytes would
                // be a partial fragment that fails to re-encode.
                if field.wire_type() == WireType::StartGroup {
                    self.unknown.record_group(field, decoder)?;
                } else {
                    self.unknown.record(field);
                }
                Ok(true)
            }
        }
    }
}

fn sample_path() -> Path {
    Path {
        label: "route-66".to_string(),
        points: vec![Point { x: 1, y: -2 }, Point { x: 300, y: 400 }],
        unknown: UnknownFields::new(),
    }
}

// ---------------------------------------------------------------------------
// Unary
// ---------------------------------------------------------------------------

#[test]
fn downstream_message_round_trips_through_the_unary_codec() {
    let mut codec: SymmetricProtoCodec<Path> = SymmetricProtoCodec::new();

    let encoded = codec.encode(&sample_path()).expect("encode");
    let decoded = codec.decode(&encoded).expect("decode");

    assert_eq!(
        decoded,
        sample_path(),
        "a downstream-defined message must survive a unary round trip unchanged"
    );
}

#[test]
fn separate_encode_and_decode_types_are_supported() {
    // The two-parameter form is what lets one codec serve a method whose
    // request and response types differ, which is the common gRPC case.
    let mut codec: ProtoCodec<Point, Path> = ProtoCodec::new();

    let encoded = codec.encode(&Point { x: 7, y: 8 }).expect("encode Point");
    // Point's fields 1 and 2 are varints; Path's field 1 is a string and its
    // field 2 is a message, so decoding this as a Path must fail closed on the
    // wire-type mismatch rather than silently producing a wrong value.
    assert!(
        matches!(codec.decode(&encoded), Err(ProtoCodecError::Wire(_))),
        "a wire-type mismatch must be a typed error, not a silent misread"
    );
}

#[test]
fn empty_message_round_trips_as_the_default_value() {
    let mut codec: SymmetricProtoCodec<Path> = SymmetricProtoCodec::new();

    let encoded = codec.encode(&Path::default()).expect("encode");
    assert!(
        encoded.is_empty(),
        "an all-default proto3 message encodes to zero bytes"
    );
    assert_eq!(codec.decode(&encoded).expect("decode"), Path::default());
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

#[test]
fn streaming_round_trips_many_messages_through_one_framed_codec() {
    let mut framed = FramedCodec::new(SymmetricProtoCodec::<Path>::new());

    let stream: Vec<Path> = (0..8)
        .map(|index| Path {
            label: format!("segment-{index}"),
            points: vec![Point {
                x: index,
                y: -index,
            }],
            unknown: UnknownFields::new(),
        })
        .collect();

    // Encode the whole stream into a single buffer, exactly as a streaming
    // call would write successive frames onto one connection.
    let mut buffer = BytesMut::new();
    for message in &stream {
        framed
            .encode_message(message, &mut buffer)
            .expect("encode frame");
    }

    let mut received = Vec::new();
    while let Some(message) = framed.decode_message(&mut buffer).expect("decode frame") {
        received.push(message);
    }

    assert_eq!(
        received, stream,
        "every streamed message must be recovered, in order"
    );
    assert!(
        buffer.is_empty(),
        "a fully drained stream must leave no residual bytes"
    );
}

#[test]
fn a_partial_frame_yields_no_message_until_it_completes() {
    // The streaming contract that matters under cancellation: a half-arrived
    // frame must be "not yet", never a truncated decode.
    let mut framed = FramedCodec::new(SymmetricProtoCodec::<Path>::new());

    let mut complete = BytesMut::new();
    framed
        .encode_message(&sample_path(), &mut complete)
        .expect("encode");
    assert!(
        complete.len() > 6,
        "the fixture must be larger than a bare gRPC frame header"
    );

    let split_at = complete.len() - 3;
    let mut partial = BytesMut::from(&complete[..split_at]);

    assert!(
        framed
            .decode_message(&mut partial)
            .expect("partial decode")
            .is_none(),
        "an incomplete frame must decode to None, not an error or a partial value"
    );

    partial.extend_from_slice(&complete[split_at..]);
    let decoded = framed
        .decode_message(&mut partial)
        .expect("completed decode")
        .expect("a completed frame must yield its message");
    assert_eq!(decoded, sample_path());
}

#[test]
fn framing_layer_message_size_limits_reach_the_owned_codec() {
    // This is the parity point the migration notes call out: the framing layer
    // pushes limits down through Codec::set_max_*_message_size. A codec that
    // ignores those hooks silently runs unbounded, so assert propagation
    // rather than trusting it.
    let framed = FramedCodec::with_message_size_limits(SymmetricProtoCodec::<Path>::new(), 128, 64);

    assert_eq!(framed.inner().max_encode_message_size(), 128);
    assert_eq!(framed.inner().max_decode_message_size(), 64);
    assert!(
        framed.inner().wire_limits().max_message_len <= 64,
        "the structural decode budget must be tightened alongside the byte ceiling"
    );
}

#[test]
fn an_over_limit_streamed_message_fails_closed() {
    let mut framed =
        FramedCodec::with_message_size_limits(SymmetricProtoCodec::<Path>::new(), 32, 32);

    let oversized = Path {
        label: "x".repeat(4096),
        points: Vec::new(),
        unknown: UnknownFields::new(),
    };

    let mut buffer = BytesMut::new();
    assert!(
        framed.encode_message(&oversized, &mut buffer).is_err(),
        "a message above the negotiated ceiling must be refused, not truncated"
    );
}

// ---------------------------------------------------------------------------
// Forward compatibility
// ---------------------------------------------------------------------------

#[test]
fn an_older_consumer_forwards_a_newer_peers_fields_untouched() {
    // Simulate a newer peer: the same schema plus fields 5 and 6 that this
    // build has never heard of.
    let mut writer = ProtobufWireEncoder::new(ProtobufWireLimits::default());
    writer.write_string(1, "route-66").expect("label");
    let point = Point { x: 1, y: -2 }
        .encode_to_bytes(ProtobufWireLimits::default())
        .expect("encode point");
    writer.write_message(2, point.as_ref()).expect("point");
    writer.write_varint(5, 987_654).expect("future varint");
    writer
        .write_string(6, "field-from-the-future")
        .expect("future string");
    let newer_wire = writer.finish().expect("finish");

    let mut codec: SymmetricProtoCodec<Path> = SymmetricProtoCodec::new();
    let decoded = codec
        .decode(&newer_wire)
        .expect("unknown fields must never fail a decode");

    // Known fields are understood...
    assert_eq!(decoded.label, "route-66");
    assert_eq!(decoded.points, vec![Point { x: 1, y: -2 }]);
    // ...and the rest is carried, not dropped.
    assert!(!decoded.unknown.is_empty());

    let forwarded = codec.encode(&decoded).expect("re-encode");
    assert_eq!(
        forwarded.as_ref(),
        newer_wire.as_ref(),
        "an old build must forward a newer peer's message byte-for-byte"
    );
}

#[test]
fn unknown_field_preservation_is_opt_in_per_message() {
    // Point does not embed UnknownFields, so it drops what it does not know.
    // Proving both halves keeps the semantics a documented choice rather than
    // an accident of one type's layout.
    let mut writer = ProtobufWireEncoder::new(ProtobufWireLimits::default());
    writer.write_int32(1, 5).expect("known");
    writer.write_varint(9, 42).expect("unknown");
    let wire = writer.finish().expect("finish");

    let mut codec: SymmetricProtoCodec<Point> = SymmetricProtoCodec::new();
    let decoded = codec.decode(&wire).expect("decode");
    assert_eq!(decoded, Point { x: 5, y: 0 });

    let reencoded = codec.encode(&decoded).expect("re-encode");
    assert!(
        reencoded.len() < wire.len(),
        "a type that does not preserve unknown fields must re-encode without them"
    );
}
