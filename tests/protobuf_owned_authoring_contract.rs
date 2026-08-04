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
