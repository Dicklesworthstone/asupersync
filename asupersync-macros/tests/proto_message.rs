//! Runtime contracts for the owned protobuf authoring derives.

use std::collections::HashMap;

use asupersync::grpc::protobuf::{
    ProtoMessage as OwnedProtoMessage, ProtoOneof as OwnedProtoOneof, ProtobufWireDecoder,
    ProtobufWireEncoder, ProtobufWireError, ProtobufWireField, ProtobufWireLimits, UnknownFields,
    merge_nested_message,
};
use asupersync_macros::{ProtoMessage, ProtoOneof};

#[derive(Clone, Copy, Debug)]
#[repr(i32)]
enum Mode {
    Unknown = 0,
    Active = 1,
}

#[derive(Clone, Debug, Default, PartialEq, ProtoMessage)]
struct ScalarMessage {
    #[proto(double, tag = 1)]
    double_value: f64,
    #[proto(float, tag = 2)]
    float_value: f32,
    #[proto(int32, tag = 3)]
    int32_value: i32,
    #[proto(int64, tag = 4)]
    int64_value: i64,
    #[proto(uint32, tag = 5)]
    uint32_value: u32,
    #[proto(uint64, tag = 6)]
    uint64_value: u64,
    #[proto(sint32, tag = 7)]
    sint32_value: i32,
    #[proto(sint64, tag = 8)]
    sint64_value: i64,
    #[proto(fixed32, tag = 9)]
    fixed32_value: u32,
    #[proto(fixed64, tag = 10)]
    fixed64_value: u64,
    #[proto(sfixed32, tag = 11)]
    sfixed32_value: i32,
    #[proto(sfixed64, tag = 12)]
    sfixed64_value: i64,
    #[proto(bool, tag = 13)]
    bool_value: bool,
    #[proto(string, tag = 14)]
    string_value: String,
    #[proto(bytes, tag = 15)]
    bytes_value: Vec<u8>,
    #[proto(enumeration = "Mode", tag = 16)]
    mode: i32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, ProtoMessage)]
struct Point {
    #[proto(sint32, tag = 1)]
    x: i32,
    #[proto(sint32, tag = 2)]
    y: i32,
}

#[derive(Clone, Debug, Eq, PartialEq, ProtoOneof)]
enum Payload {
    #[proto(string, tag = 8)]
    Text(String),
    #[proto(message, tag = 9)]
    Point(Point),
    #[proto(uint64, tag = 10)]
    Sequence(u64),
}

#[derive(Clone, Debug, Default, Eq, PartialEq, ProtoMessage)]
struct Envelope {
    #[proto(string, tag = 1)]
    name: String,
    #[proto(uint32, optional, tag = 2)]
    optional_count: Option<u32>,
    #[proto(sint64, repeated, packed, tag = 3)]
    packed_values: Vec<i64>,
    #[proto(string, repeated, tag = 4)]
    labels: Vec<String>,
    #[proto(map, key = "string", value = "uint64", tag = 5)]
    counters: HashMap<String, u64>,
    #[proto(message, optional, tag = 6)]
    point: Option<Point>,
    #[proto(enumeration = "Mode", tag = 7)]
    mode: i32,
    #[proto(oneof, tags = "8, 9, 10")]
    payload: Option<Payload>,
    #[proto(unknown_fields)]
    unknown: UnknownFields,
}

#[test]
fn scalar_grammar_round_trips_every_wire_kind() {
    let expected = ScalarMessage {
        double_value: -1.25,
        float_value: 2.5,
        int32_value: -3,
        int64_value: -4,
        uint32_value: 5,
        uint64_value: u64::MAX,
        sint32_value: -6,
        sint64_value: i64::MIN,
        fixed32_value: 7,
        fixed64_value: 8,
        sfixed32_value: -9,
        sfixed64_value: -10,
        bool_value: true,
        string_value: "derive".to_owned(),
        bytes_value: vec![0, 1, 2, 255],
        mode: Mode::Active as i32,
    };

    let wire = expected
        .encode_to_bytes(ProtobufWireLimits::default())
        .expect("encode every scalar");
    let actual = ScalarMessage::decode_from_bytes(&wire, ProtobufWireLimits::default())
        .expect("decode every scalar");
    assert_eq!(actual, expected);
    assert_eq!(Mode::Unknown as i32, 0);
}

fn sample_envelope() -> Envelope {
    Envelope {
        name: "route".to_owned(),
        optional_count: Some(0),
        packed_values: vec![0, -1, i64::MIN, i64::MAX],
        labels: vec!["alpha".to_owned(), "beta".to_owned()],
        counters: HashMap::from([
            ("z-last".to_owned(), 3),
            ("a-first".to_owned(), 1),
            ("middle".to_owned(), 2),
        ]),
        point: Some(Point { x: -7, y: 11 }),
        mode: Mode::Active as i32,
        payload: Some(Payload::Text(String::new())),
        unknown: UnknownFields::new(),
    }
}

#[test]
fn compound_grammar_is_deterministic_and_preserves_presence() {
    let limits = ProtobufWireLimits::default();
    let expected = sample_envelope();
    let first = expected.encode_to_bytes(limits).expect("first encode");

    let mut reordered = sample_envelope();
    reordered.counters.clear();
    reordered.counters.insert("middle".to_owned(), 2);
    reordered.counters.insert("a-first".to_owned(), 1);
    reordered.counters.insert("z-last".to_owned(), 3);
    let second = reordered.encode_to_bytes(limits).expect("second encode");

    assert_eq!(
        first, second,
        "map insertion order must not affect generated wire bytes"
    );
    let decoded = Envelope::decode_from_bytes(&first, limits).expect("decode compound message");
    assert_eq!(decoded, expected);
    assert_eq!(decoded.optional_count, Some(0));
    assert_eq!(decoded.payload, Some(Payload::Text(String::new())));
}

#[test]
fn repeated_numeric_decoder_accepts_packed_and_unpacked_records() {
    let limits = ProtobufWireLimits::default();
    let mut unpacked = ProtobufWireEncoder::new(limits);
    unpacked.write_sint64(3, -1).expect("first unpacked value");
    unpacked.write_sint64(3, 7).expect("second unpacked value");
    let unpacked = unpacked.finish().expect("finish unpacked message");

    let decoded = Envelope::decode_from_bytes(&unpacked, limits).expect("decode unpacked values");
    assert_eq!(decoded.packed_values, vec![-1, 7]);
}

#[test]
fn derived_unknown_field_member_round_trips_verbatim() {
    let limits = ProtobufWireLimits::default();
    let mut encoder = ProtobufWireEncoder::new(limits);
    encoder.write_string(1, "known").expect("known field");
    encoder.write_varint(99, 42).expect("future field");
    let future_wire = encoder.finish().expect("finish future wire");

    let decoded = Envelope::decode_from_bytes(&future_wire, limits).expect("old schema decode");
    assert!(!decoded.unknown.is_empty());
    assert_eq!(
        decoded
            .encode_to_bytes(limits)
            .expect("forward future field"),
        future_wire
    );
}

#[test]
fn all_oneof_variant_kinds_round_trip() {
    for payload in [
        Payload::Text("hello".to_owned()),
        Payload::Point(Point { x: 1, y: 2 }),
        Payload::Sequence(42),
    ] {
        let expected = Envelope {
            payload: Some(payload),
            ..Envelope::default()
        };
        let wire = expected
            .encode_to_bytes(ProtobufWireLimits::default())
            .expect("encode oneof");
        let actual = Envelope::decode_from_bytes(&wire, ProtobufWireLimits::default())
            .expect("decode oneof");
        assert_eq!(actual, expected);
    }
}

fn envelope_wire(payloads: &[Payload]) -> Vec<u8> {
    payloads
        .iter()
        .map(|payload| {
            Envelope {
                payload: Some(payload.clone()),
                ..Envelope::default()
            }
            .encode_to_bytes(ProtobufWireLimits::default())
            .expect("encode one member")
            .to_vec()
        })
        .collect::<Vec<_>>()
        .concat()
}

/// q6jo59 A1: protobuf merges a message member that appears again while it
/// is the oneof's current member, as prost does. The derive replaced it, so
/// `x` was lost: `4a 02 08 02 4a 02 10 04` decoded as `Point { x: 0, y: 2 }`.
#[test]
fn a_repeated_oneof_message_member_merges_into_the_current_member() {
    let limits = ProtobufWireLimits::default();
    let wire = [0x4a, 0x02, 0x08, 0x02, 0x4a, 0x02, 0x10, 0x04];
    let decoded = Envelope::decode_from_bytes(&wire, limits).expect("decode repeated member");
    assert_eq!(decoded.payload, Some(Payload::Point(Point { x: 1, y: 2 })));

    // Concatenated encodings decode as their merge.
    let wire = envelope_wire(&[
        Payload::Point(Point { x: 1, y: 0 }),
        Payload::Point(Point { x: 0, y: 2 }),
    ]);
    let decoded = Envelope::decode_from_bytes(&wire, limits).expect("decode concatenation");
    assert_eq!(decoded.payload, Some(Payload::Point(Point { x: 1, y: 2 })));
}

/// Only the current member merges. Another member in between replaces it,
/// so the next message member starts from its default, and a repeated
/// string or number keeps the last value (a string is not concatenated).
#[test]
fn other_oneof_members_still_replace_the_current_member() {
    let limits = ProtobufWireLimits::default();
    for (members, expected) in [
        (
            vec![
                Payload::Point(Point { x: 1, y: 0 }),
                Payload::Text("between".to_owned()),
                Payload::Point(Point { x: 0, y: 2 }),
            ],
            Payload::Point(Point { x: 0, y: 2 }),
        ),
        (
            vec![Payload::Point(Point { x: 1, y: 2 }), Payload::Sequence(7)],
            Payload::Sequence(7),
        ),
        (
            vec![
                Payload::Text("first".to_owned()),
                Payload::Text("last".to_owned()),
            ],
            Payload::Text("last".to_owned()),
        ),
        (
            vec![Payload::Sequence(1), Payload::Sequence(2)],
            Payload::Sequence(2),
        ),
    ] {
        let decoded =
            Envelope::decode_from_bytes(&envelope_wire(&members), limits).expect("decode members");
        assert_eq!(decoded.payload, Some(expected), "{members:?}");
    }
}

/// A hand-written `ProtoOneof`: the derive cannot see inside it.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ManualPayload {
    Point(Point),
}

impl OwnedProtoOneof for ManualPayload {
    const FIELD_NUMBERS: &'static [u32] = &[3];

    fn encode_oneof(&self, encoder: &mut ProtobufWireEncoder) -> Result<(), ProtobufWireError> {
        let Self::Point(point) = self;
        let nested = point.encode_to_bytes(ProtobufWireLimits::default())?;
        encoder.write_message(3, &nested)
    }

    fn decode_oneof<'wire>(
        field: &ProtobufWireField<'wire>,
        decoder: &mut ProtobufWireDecoder<'wire, '_>,
    ) -> Result<Option<Self>, ProtobufWireError> {
        if field.field_number() != 3 {
            return Ok(None);
        }
        let mut point = Point::default();
        merge_nested_message(&mut point, field, decoder)?;
        Ok(Some(Self::Point(point)))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, ProtoMessage)]
struct ManualEnvelope {
    #[proto(oneof, tags = "3")]
    payload: Option<ManualPayload>,
}

/// A derived message still accepts a hand-written `ProtoOneof`. Its own
/// `decode_oneof` cannot see the member already present, so a repeated
/// member replaces it, as every oneof did in v0.4.3.
#[test]
fn a_hand_written_oneof_in_a_derived_message_decodes_through_its_own_decode_oneof() {
    let limits = ProtobufWireLimits::default();
    let wire = [Point { x: 1, y: 0 }, Point { x: 0, y: 2 }]
        .into_iter()
        .map(|point| {
            ManualEnvelope {
                payload: Some(ManualPayload::Point(point)),
            }
            .encode_to_bytes(limits)
            .expect("encode manual member")
            .to_vec()
        })
        .collect::<Vec<_>>()
        .concat();
    let decoded = ManualEnvelope::decode_from_bytes(&wire, limits).expect("decode manual oneof");
    assert_eq!(
        decoded.payload,
        Some(ManualPayload::Point(Point { x: 0, y: 2 }))
    );
}
