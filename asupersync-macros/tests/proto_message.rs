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

#[derive(Clone, Debug, Default, Eq, PartialEq, ProtoMessage)]
struct Blob {
    #[proto(bytes, tag = 1)]
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, ProtoMessage)]
struct SingularBlob {
    #[proto(message, tag = 1)]
    child: Blob,
}

#[derive(Clone, Debug, Eq, PartialEq, ProtoOneof)]
enum BlobChoice {
    #[proto(message, tag = 4)]
    Child(Blob),
}

#[derive(Clone, Debug, Default, Eq, PartialEq, ProtoMessage)]
struct BlobContainers {
    #[proto(message, optional, tag = 1)]
    child: Option<Blob>,
    #[proto(message, repeated, tag = 2)]
    children: Vec<Blob>,
    #[proto(map, key = "string", value = "message", tag = 3)]
    entries: HashMap<String, Blob>,
    #[proto(oneof, tags = "4")]
    choice: Option<BlobChoice>,
}

fn assert_owned_round_trip<T>(value: &T, limits: ProtobufWireLimits)
where
    T: OwnedProtoMessage + std::fmt::Debug + PartialEq,
{
    let wire = value
        .encode_to_bytes(limits)
        .expect("encode within parent limits");
    assert_eq!(
        &T::decode_from_bytes(&wire, limits).expect("decode within parent limits"),
        value,
    );
}

/// br-asupersync-fe1plr: child messages previously restarted the default 4 MiB
/// encoder even when their parent explicitly admitted a larger message.
#[test]
fn parent_message_limits_reach_every_derived_nested_container() {
    let limits = ProtobufWireLimits::for_message_size(16 * 1024 * 1024);
    let blob = Blob {
        bytes: vec![0xa5; 5 * 1024 * 1024],
    };
    assert_owned_round_trip(
        &SingularBlob {
            child: blob.clone(),
        },
        limits,
    );
    for value in [
        BlobContainers {
            child: Some(blob.clone()),
            ..BlobContainers::default()
        },
        BlobContainers {
            children: vec![blob.clone()],
            ..BlobContainers::default()
        },
        BlobContainers {
            entries: HashMap::from([("key".to_owned(), blob.clone())]),
            ..BlobContainers::default()
        },
        BlobContainers {
            choice: Some(BlobChoice::Child(blob.clone())),
            ..BlobContainers::default()
        },
    ] {
        assert_owned_round_trip(&value, limits);
        assert!(
            value
                .encode_to_bytes(ProtobufWireLimits::default())
                .is_err(),
            "the default ceiling must still reject the oversized child",
        );
    }
}

#[test]
fn derived_children_share_the_parents_aggregate_field_budget() {
    let blob = Blob { bytes: vec![1] };
    let value = BlobContainers {
        child: Some(blob.clone()),
        children: vec![blob],
        ..BlobContainers::default()
    };
    let limits = ProtobufWireLimits::for_message_size(128).with_max_fields(4);
    assert_owned_round_trip(&value, limits);
    assert!(matches!(
        value.encode_to_bytes(limits.with_max_fields(3)),
        Err(ProtobufWireError::FieldCountExceeded {
            count: 4,
            limit: 3,
            ..
        }),
    ));
}

#[test]
fn derived_messages_and_map_wrappers_share_the_depth_budget() {
    let blob = Blob { bytes: vec![1] };
    let singular = SingularBlob {
        child: blob.clone(),
    };
    let limits = ProtobufWireLimits::for_message_size(128);
    assert!(matches!(
        singular.encode_to_bytes(limits.with_max_depth(0)),
        Err(ProtobufWireError::RecursionLimitExceeded {
            depth: 1,
            limit: 0,
            ..
        }),
    ));
    assert_owned_round_trip(&singular, limits.with_max_depth(1));

    let map = BlobContainers {
        entries: HashMap::from([("k".to_owned(), blob)]),
        ..BlobContainers::default()
    };
    assert!(matches!(
        map.encode_to_bytes(limits.with_max_depth(1)),
        Err(ProtobufWireError::RecursionLimitExceeded {
            depth: 2,
            limit: 1,
            ..
        }),
    ));
    assert_owned_round_trip(&map, limits.with_max_depth(2));
}

#[test]
fn derived_children_and_map_wrappers_honor_stricter_field_byte_limits() {
    let limits = ProtobufWireLimits::for_message_size(128);
    let singular = SingularBlob {
        child: Blob {
            bytes: vec![1, 2, 3],
        },
    };
    assert!(matches!(
        singular.encode_to_bytes(limits.with_max_field_len(4)),
        Err(ProtobufWireError::FieldLimitExceeded { limit: 4, .. }),
    ));
    assert_owned_round_trip(&singular, limits.with_max_field_len(5));

    let map = BlobContainers {
        entries: HashMap::from([("k".to_owned(), Blob { bytes: vec![7] })]),
        ..BlobContainers::default()
    };
    assert!(matches!(
        map.encode_to_bytes(limits.with_max_field_len(7)),
        Err(ProtobufWireError::FieldLimitExceeded { limit: 7, .. }),
    ));
    assert_owned_round_trip(&map, limits.with_max_field_len(8));
}

#[test]
fn nested_work_refusal_restores_the_prefix_and_allows_encoder_reuse() {
    let limits = ProtobufWireLimits::for_message_size(128);
    let message = SingularBlob {
        child: Blob { bytes: vec![7; 20] },
    };
    let mut encoder = ProtobufWireEncoder::new(limits.with_max_work(47));
    encoder.write_varint(9, 1).expect("existing prefix");
    let before = encoder.as_bytes().to_vec();
    assert!(matches!(
        message.encode_fields(&mut encoder),
        Err(ProtobufWireError::WorkLimitExceeded { limit: 47, .. }),
    ));
    assert_eq!(encoder.as_bytes(), before);
    assert_eq!(encoder.fields_written(), 1);
    assert_eq!(encoder.work_used(), 2);
    encoder
        .write_varint(10, 3)
        .expect("reuse after failed child");
    assert_eq!(
        encoder.finish().expect("finish prefix").as_ref(),
        &[0x48, 1, 0x50, 3]
    );

    let mut exact = ProtobufWireEncoder::new(limits.with_max_work(48));
    exact.write_varint(9, 1).expect("existing prefix");
    message
        .encode_fields(&mut exact)
        .expect("exact work budget");
    assert_eq!(exact.work_used(), 48);
    assert_eq!(exact.fields_written(), 3);
    let mut expected = vec![0x48, 1, 0x0a, 22, 0x0a, 20];
    expected.extend_from_slice(&[7; 20]);
    assert_eq!(exact.finish().expect("finish child").as_ref(), expected);
}

#[test]
fn derived_map_has_independent_wire_bytes_and_exact_shared_budgets() {
    let map = BlobContainers {
        entries: HashMap::from([("k".to_owned(), Blob { bytes: vec![7] })]),
        ..BlobContainers::default()
    };
    let limits = ProtobufWireLimits::for_message_size(10)
        .with_max_fields(4)
        .with_max_depth(2)
        .with_max_work(21);
    let mut encoder = ProtobufWireEncoder::new(limits);
    map.encode_fields(&mut encoder)
        .expect("exact aggregate budget");
    assert_eq!(encoder.fields_written(), 4);
    assert_eq!(encoder.work_used(), 21);
    let wire = encoder.finish().expect("finish map");
    assert_eq!(
        wire.as_ref(),
        &[0x1a, 8, 0x0a, 1, b'k', 0x12, 3, 0x0a, 1, 7]
    );
    assert_eq!(
        BlobContainers::decode_from_bytes(&wire, limits).unwrap(),
        map
    );
    assert!(matches!(
        map.encode_to_bytes(limits.with_max_work(20)),
        Err(ProtobufWireError::WorkLimitExceeded { limit: 20, .. }),
    ));
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ManualBlob(Blob);

impl OwnedProtoMessage for ManualBlob {
    fn encode_fields(&self, encoder: &mut ProtobufWireEncoder) -> Result<(), ProtobufWireError> {
        self.0.encode_fields(encoder)
    }

    fn merge_field<'wire>(
        &mut self,
        field: &ProtobufWireField<'wire>,
        decoder: &mut ProtobufWireDecoder<'wire, '_>,
    ) -> Result<bool, ProtobufWireError> {
        self.0.merge_field(field, decoder)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, ProtoMessage)]
struct ManualBlobEnvelope {
    #[proto(message, tag = 1)]
    child: ManualBlob,
}

#[test]
fn derived_parent_supports_hand_written_child_under_shared_limits() {
    let value = ManualBlobEnvelope {
        child: ManualBlob(Blob {
            bytes: vec![1, 2, 3],
        }),
    };
    let limits = ProtobufWireLimits::for_message_size(32)
        .with_max_fields(2)
        .with_max_depth(1);
    assert_owned_round_trip(&value, limits);
    assert!(matches!(
        value.encode_to_bytes(limits.with_max_fields(1)),
        Err(ProtobufWireError::FieldCountExceeded { limit: 1, .. }),
    ));
}

#[test]
fn nested_callback_unwind_restores_groups_counters_and_original_panic() {
    let limits = ProtobufWireLimits::for_message_size(128);
    let mut encoder = ProtobufWireEncoder::new(limits);
    encoder.start_group(1).expect("parent group");
    encoder.write_varint(9, 1).expect("parent prefix");
    let before = encoder.as_bytes().to_vec();
    let fields = encoder.fields_written();
    let work = encoder.work_used();
    let marker = std::sync::Arc::new(17_u8);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        encoder.write_nested_message(3, |nested| {
            nested.start_group(4)?;
            nested.write_varint(5, 9)?;
            std::panic::panic_any(marker.clone());
        })
    }))
    .expect_err("the callback panic must propagate");
    assert!(std::sync::Arc::ptr_eq(
        panic
            .downcast_ref::<std::sync::Arc<u8>>()
            .expect("original panic type"),
        &marker,
    ));
    assert_eq!(encoder.as_bytes(), before);
    assert_eq!(encoder.fields_written(), fields);
    assert_eq!(encoder.work_used(), work);
    encoder
        .write_nested_message(3, |nested| nested.write_varint(7, 11))
        .expect("reuse");
    encoder.end_group(1).expect("parent group floor restored");
    assert_eq!(
        encoder.finish().expect("finish restored encoder").as_ref(),
        &[0x0b, 0x48, 1, 0x1a, 2, 0x38, 11, 0x0c]
    );
}
