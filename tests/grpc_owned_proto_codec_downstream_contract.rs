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

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::grpc::codec::{Codec, FramedCodec};
use asupersync::grpc::protobuf::{
    DEFAULT_MAX_MESSAGE_SIZE, ProtoCodec, ProtoCodecError, ProtoMessage, ProtobufWireDecoder,
    ProtobufWireEncoder, ProtobufWireError, ProtobufWireField, ProtobufWireLimits,
    ProtobufWireMessage, SymmetricProtoCodec, UnknownFields, WireType, merge_nested_message,
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
fn framing_layer_can_raise_the_default_inbound_limit() {
    // br-asupersync-fe1plr: an outer frame ceiling must also raise the
    // automatically selected message, field, and work budgets.
    let message = Path {
        label: "x".repeat(DEFAULT_MAX_MESSAGE_SIZE + 1),
        points: Vec::new(),
        unknown: UnknownFields::new(),
    };
    let limit = 2 * DEFAULT_MAX_MESSAGE_SIZE;
    let wire = message
        .encode_to_bytes(ProtobufWireLimits::for_message_size(limit))
        .expect("encode larger peer message");
    assert!(wire.len() > DEFAULT_MAX_MESSAGE_SIZE);

    // Build the uncompressed frame independently of the framing encoder.
    let mut buffer = BytesMut::new();
    buffer.extend_from_slice(&[0]);
    buffer.extend_from_slice(
        &u32::try_from(wire.len())
            .expect("frame length")
            .to_be_bytes(),
    );
    buffer.extend_from_slice(wire.as_ref());
    let mut framed =
        FramedCodec::with_message_size_limits(SymmetricProtoCodec::<Path>::new(), 64, limit);
    assert_eq!(
        framed.decode_message(&mut buffer).expect("decode frame"),
        Some(message),
    );
    assert!(buffer.is_empty());
    assert_eq!(framed.inner().max_encode_message_size(), 64);
    assert_eq!(
        framed.inner().wire_limits(),
        ProtobufWireLimits::for_message_size(limit),
    );
}

#[test]
fn automatic_decode_limits_recover_after_zero_and_small_channel_limits() {
    let message = Path {
        label: "resized".repeat(8),
        points: Vec::new(),
        unknown: UnknownFields::new(),
    };
    let wire = message
        .encode_to_bytes(ProtobufWireLimits::for_message_size(128))
        .expect("fixture");
    let mut codec = SymmetricProtoCodec::<Path>::with_max_size(16);
    for limit in [0, 8, 128, 4, 64] {
        codec.set_max_decode_message_size(limit);
        assert_eq!(
            codec.wire_limits(),
            ProtobufWireLimits::for_message_size(limit)
        );
        if wire.len() > limit {
            assert!(matches!(
                codec.decode(&wire),
                Err(ProtoCodecError::DecodeMessageTooLarge { size, limit: actual })
                    if size == wire.len() && actual == limit
            ));
        } else {
            assert_eq!(codec.decode(&wire).expect("raised limit"), message);
        }
        if limit == 0 {
            assert_eq!(codec.decode(&Bytes::new()).expect("empty"), Path::default());
        }
    }
    assert_eq!(codec.max_encode_message_size(), 16);
}

#[test]
fn resizing_and_cloning_preserve_all_explicit_wire_limits() {
    let limits = ProtobufWireLimits::for_message_size(128)
        .with_max_field_len(12)
        .with_max_fields(2)
        .with_max_depth(0)
        .with_max_work(24);
    let mut original = SymmetricProtoCodec::<Path>::new().with_wire_limits(limits);
    original.set_max_decode_message_size(2);
    let mut codec = original.clone();
    codec.set_max_decode_message_size(256);
    assert_eq!(codec.wire_limits(), limits);
    assert_eq!(original.wire_limits().max_message_len, 2);

    // Fixed, well-formed wire bytes exercise each preserved policy.
    let field_too_long = Bytes::from_static(b"\x0a\x0dabcdefghijklm");
    assert!(matches!(
        codec.decode(&field_too_long),
        Err(ProtoCodecError::Wire(
            ProtobufWireError::FieldLimitExceeded {
                length: 13,
                limit: 12,
                ..
            }
        ))
    ));
    let too_many_fields = Bytes::from_static(b"\x18\x01\x20\x01\x28\x01");
    assert!(matches!(
        codec.decode(&too_many_fields),
        Err(ProtoCodecError::Wire(
            ProtobufWireError::FieldCountExceeded {
                count: 3,
                limit: 2,
                ..
            }
        ))
    ));
    let nested = Bytes::from_static(b"\x12\x02\x08\x01");
    assert!(matches!(
        codec.decode(&nested),
        Err(ProtoCodecError::Wire(
            ProtobufWireError::RecursionLimitExceeded {
                depth: 1,
                limit: 0,
                ..
            }
        ))
    ));
    let too_much_work =
        Bytes::from_static(b"\x0a\x0cabcdefghijkl\x18\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01");
    assert!(matches!(
        codec.decode(&too_much_work),
        Err(ProtoCodecError::Wire(
            ProtobufWireError::WorkLimitExceeded { limit: 24, .. }
        ))
    ));
    assert!(matches!(
        codec.decode(&Bytes::from(vec![0; 129])),
        Err(ProtoCodecError::Wire(
            ProtobufWireError::MessageLimitExceeded {
                length: 129,
                limit: 128,
            }
        ))
    ));
    assert_eq!(
        codec
            .decode(&Bytes::from_static(b"\x0a\x02ok"))
            .expect("within policy")
            .label,
        "ok",
    );
}

#[test]
fn replacing_an_explicit_policy_after_resizing_uses_the_new_ceiling() {
    let mut codec = SymmetricProtoCodec::<Path>::with_max_size(128)
        .with_wire_limits(ProtobufWireLimits::for_message_size(32));
    codec.set_max_decode_message_size(4);
    let mut codec = codec.with_wire_limits(ProtobufWireLimits::for_message_size(64));
    codec.set_max_decode_message_size(128);
    assert_eq!(
        codec.wire_limits(),
        ProtobufWireLimits::for_message_size(64)
    );

    let message = Path {
        label: "x".repeat(40),
        points: Vec::new(),
        unknown: UnknownFields::new(),
    };
    let wire = message
        .encode_to_bytes(ProtobufWireLimits::for_message_size(64))
        .expect("fixture");
    assert_eq!(codec.decode(&wire).expect("replacement policy"), message);
}

/// `message NestedPayload { NestedPayload child = 1; bytes payload = 2; }`
#[derive(Debug, Default, Eq, PartialEq)]
struct NestedPayload {
    child: Option<Box<Self>>,
    payload: Vec<u8>,
}

impl ProtoMessage for NestedPayload {
    fn encode_fields(&self, encoder: &mut ProtobufWireEncoder) -> Result<(), ProtobufWireError> {
        if let Some(child) = &self.child {
            encoder.write_nested_message(1, |nested| child.encode_fields(nested))?;
        }
        if !self.payload.is_empty() {
            encoder.write_bytes(2, &self.payload)?;
        }
        Ok(())
    }

    fn merge_field<'wire>(
        &mut self,
        field: &ProtobufWireField<'wire>,
        decoder: &mut ProtobufWireDecoder<'wire, '_>,
    ) -> Result<bool, ProtobufWireError> {
        match field.field_number() {
            1 => {
                let child = self.child.get_or_insert_with(Box::default);
                merge_nested_message(child.as_mut(), field, decoder)?;
                Ok(true)
            }
            2 => {
                self.payload = field.as_bytes()?.to_vec();
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

fn nested_payload(payload_len: usize, depth: usize) -> NestedPayload {
    let mut message = NestedPayload {
        child: None,
        payload: vec![b'x'; payload_len],
    };
    for _ in 0..depth {
        message = NestedPayload {
            child: Some(Box::new(message)),
            payload: Vec::new(),
        };
    }
    message
}

// Independent wire fixture: no owned encoder or derive implementation is used
// to manufacture the bytes that must be accepted by the decoder.
fn nested_payload_wire(payload_len: usize, depth: usize) -> Bytes {
    fn wrap(key: u8, payload: &[u8]) -> Vec<u8> {
        let mut wire = vec![key];
        let mut length = u64::try_from(payload.len()).expect("wire length");
        while length >= 0x80 {
            wire.push((length as u8 & 0x7f) | 0x80);
            length >>= 7;
        }
        wire.push(length as u8);
        wire.extend_from_slice(payload);
        wire
    }

    let mut wire = wrap(0x12, &vec![b'x'; payload_len]);
    for _ in 0..depth {
        wire = wrap(0x0a, &wire);
    }
    Bytes::from(wire)
}

#[test]
fn automatic_work_limits_admit_nested_messages_within_byte_and_depth_limits() {
    // The small message is 90 wire bytes but needs 430 units of cumulative
    // work; the large message needs over 16 MiB. Both exceeded the former
    // four-times-message-ceiling budget despite obeying byte and depth limits.
    for (payload_len, ceiling) in [
        (80, 100),
        (7 * DEFAULT_MAX_MESSAGE_SIZE / 8, DEFAULT_MAX_MESSAGE_SIZE),
    ] {
        let message = nested_payload(payload_len, 4);
        let wire = nested_payload_wire(payload_len, 4);
        assert!(wire.len() < ceiling);
        let mut codec = SymmetricProtoCodec::<NestedPayload>::with_max_size(ceiling);
        assert_eq!(codec.decode(&wire).expect("admitted nested input"), message);
        assert_eq!(
            codec.encode(&message).expect("admitted nested output"),
            wire
        );
    }
}

#[test]
fn the_default_depth_limit_remains_effective_at_its_boundary() {
    let message = nested_payload(1, 100);
    let wire = nested_payload_wire(1, 100);
    let mut codec = SymmetricProtoCodec::<NestedPayload>::new();
    assert_eq!(codec.decode(&wire).expect("depth 100 input"), message);
    assert_eq!(codec.encode(&message).expect("depth 100 output"), wire);

    let message = nested_payload(1, 101);
    let wire = nested_payload_wire(1, 101);
    for result in [
        codec.decode(&wire).map(|_| ()),
        codec.encode(&message).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(ProtoCodecError::Wire(
                ProtobufWireError::RecursionLimitExceeded {
                    depth: 101,
                    limit: 100,
                    ..
                }
            ))
        ));
    }
}

#[test]
fn explicit_work_caps_still_reject_nested_input_and_output() {
    let message = nested_payload(80, 4);
    let wire = nested_payload_wire(80, 4);
    // Setter order must never turn an explicit CPU-work policy into an
    // automatically enlarged allowance.
    for limits in [
        ProtobufWireLimits::for_message_size(100)
            .with_max_work(400)
            .with_max_depth(4),
        ProtobufWireLimits::for_message_size(100)
            .with_max_depth(4)
            .with_max_work(400),
    ] {
        let mut codec =
            SymmetricProtoCodec::<NestedPayload>::with_max_size(100).with_wire_limits(limits);
        for result in [
            codec.decode(&wire).map(|_| ()),
            codec.encode(&message).map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(ProtoCodecError::Wire(
                    ProtobufWireError::WorkLimitExceeded { limit: 400, .. }
                ))
            ));
        }
    }
}

#[test]
fn configured_depth_sizes_work_without_relaxing_other_bounds() {
    let message = nested_payload(80, 4);
    let wire = nested_payload_wire(80, 4);
    let limits = ProtobufWireLimits::for_message_size_and_depth(100, 4);
    let mut codec =
        SymmetricProtoCodec::<NestedPayload>::with_max_size(100).with_wire_limits(limits);
    assert_eq!(codec.decode(&wire).expect("configured depth"), message);
    assert_eq!(codec.encode(&message).expect("configured depth"), wire);

    for limits in [
        limits.with_max_fields(4),
        limits.with_max_depth(3),
        limits.with_max_field_len(79),
    ] {
        let mut codec =
            SymmetricProtoCodec::<NestedPayload>::with_max_size(100).with_wire_limits(limits);
        assert!(
            codec.decode(&wire).is_err(),
            "other decoding limits still apply"
        );
        assert!(
            codec.encode(&message).is_err(),
            "other encoding limits still apply"
        );
    }
    let mut codec = SymmetricProtoCodec::<NestedPayload>::with_max_size(wire.len() - 1);
    assert!(codec.decode(&wire).is_err(), "wire ceiling still applies");
    assert!(
        codec.encode(&message).is_err(),
        "wire ceiling still applies"
    );
}

#[test]
fn repeated_root_and_nested_traversals_still_exhaust_shared_work() {
    let mut message = ProtobufWireMessage::new(
        &[0x08, 0x01],
        ProtobufWireLimits::for_message_size_and_depth(2, 0),
    )
    .expect("root fixture");
    for _ in 0..4 {
        let mut decoder = message.decoder();
        assert!(decoder.next_field().expect("admitted root pass").is_some());
        assert!(decoder.next_field().expect("end").is_none());
    }
    assert!(matches!(
        message.decoder().next_field(),
        Err(ProtobufWireError::WorkLimitExceeded { limit: 8, .. })
    ));
    assert_eq!(message.work_used(), 8);

    let mut message = ProtobufWireMessage::new(
        &[0x0a, 0x02, 0x10, 0x01],
        ProtobufWireLimits::for_message_size_and_depth(4, 1),
    )
    .expect("nested fixture");
    let mut decoder = message.decoder();
    let field = decoder.next_field().expect("wrapper").expect("field");
    for _ in 0..8 {
        let mut child = decoder.nested_message(&field).expect("child");
        assert!(child.next_field().expect("admitted child pass").is_some());
        assert!(child.next_field().expect("end").is_none());
    }
    assert!(matches!(
        decoder.nested_message(&field).expect("child").next_field(),
        Err(ProtobufWireError::WorkLimitExceeded { limit: 20, .. })
    ));
    assert_eq!(message.work_used(), 20);
}

#[test]
fn automatic_work_limit_arithmetic_handles_zero_and_overflow() {
    const ZERO: ProtobufWireLimits = ProtobufWireLimits::for_message_size_and_depth(0, usize::MAX);
    const LARGE: ProtobufWireLimits =
        ProtobufWireLimits::for_message_size_and_depth(usize::MAX, usize::MAX);
    assert_eq!(ZERO.max_work, 0);
    assert_eq!(LARGE.max_work, usize::MAX);
    assert_eq!(
        ProtobufWireLimits::for_message_size_and_depth(32, 0).max_work,
        128
    );
    assert_eq!(
        ProtobufWireLimits::for_message_size(32)
            .with_max_work(7)
            .with_max_depth(0)
            .max_work,
        7
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
