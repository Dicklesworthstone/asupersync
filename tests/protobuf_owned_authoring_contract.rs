//! Public-surface and documentation contract for Protobuf A6.

use asupersync::grpc::protobuf::{ProtoMessage as _, ProtobufWireLimits};

#[derive(Clone, Debug, Default, Eq, PartialEq, asupersync::ProtoMessage)]
struct PublicDerive {
    #[proto(string, tag = 1)]
    name: String,
    #[proto(uint64, repeated, packed, tag = 2)]
    values: Vec<u64>,
}

#[test]
fn root_reexport_derives_the_public_owned_trait() {
    let expected = PublicDerive {
        name: "public".to_owned(),
        values: vec![0, 1, u64::MAX],
    };
    let limits = ProtobufWireLimits::default();
    let wire = expected.encode_to_bytes(limits).expect("encode");
    assert_eq!(
        PublicDerive::decode_from_bytes(&wire, limits).expect("decode"),
        expected
    );
}

#[derive(Debug, Default, Eq, PartialEq, asupersync::ProtoMessage)]
struct Envelope {
    #[proto(message, optional, tag = 1)]
    child: Option<PublicDerive>,
}

#[test]
fn optional_message_survives_a_failed_incremental_merge() {
    let limits = ProtobufWireLimits::default();
    let child = PublicDerive {
        name: "retained".to_owned(),
        values: vec![1],
    };
    let mut envelope = Envelope { child: Some(child) };

    // The wrong wire type fails before reading any child fields.
    assert!(envelope.merge_from_bytes(&[0x08, 1], limits).is_err());
    let present = envelope.child.as_ref().expect("existing optional child");
    assert_eq!(present.name, "retained");
    assert_eq!(present.values, [1]);

    // A valid repeated item precedes a truncated string inside the child.
    let partial = [0x0a, 5, 0x10, 7, 0x0a, 2, b'x'];
    assert!(envelope.merge_from_bytes(&partial, limits).is_err());
    envelope
        .merge_from_bytes(&[0x0a, 2, 0x10, 3], limits)
        .expect("resume with a valid fragment");
    let present = envelope.child.unwrap();
    assert_eq!(present.name, "retained");
    assert_eq!(present.values, [1, 7, 3]);

    let mut empty = Envelope::default();
    assert!(empty.merge_from_bytes(&partial, limits).is_err());
    assert!(
        empty.child.is_none(),
        "failed first occurrence stays absent"
    );
}

#[test]
fn authoring_contract_pins_grammar_fixtures_and_keep_boundary() {
    let docs = include_str!("../docs/protobuf_owned_authoring.md");
    for required in [
        "scalar",
        "optional",
        "repeated",
        "packed",
        "map",
        "enumeration",
        "oneof",
        "nested message",
        "unknown_fields",
        "KEEP_UNTIL_PARITY",
        "KEEP_INCUMBENT",
        "tests/fixtures/protobuf-owned-unary",
        "tests/fixtures/protobuf-owned-streaming",
        "does not authorize removing `prost`",
    ] {
        assert!(
            docs.contains(required),
            "authoring contract must retain marker `{required}`"
        );
    }

    let unary = include_str!("fixtures/protobuf-owned-unary/Cargo.toml");
    let streaming = include_str!("fixtures/protobuf-owned-streaming/Cargo.toml");
    assert!(unary.contains("protobuf-owned-unary-consumer"));
    assert!(streaming.contains("protobuf-owned-streaming-consumer"));
    assert!(unary.contains("features = [\"proc-macros\"]"));
    assert!(streaming.contains("features = [\"proc-macros\"]"));
    assert!(!unary.contains("prost"));
    assert!(!streaming.contains("prost"));
}
