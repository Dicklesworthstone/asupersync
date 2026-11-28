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

mod recursive {
    use super::*;
    use asupersync::grpc::protobuf::{
        ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError,
        ProtobufWireField,
    };
    use std::collections::BTreeMap;

    type Link = Box<Node>;

    #[derive(Debug, Default, PartialEq, asupersync::ProtoMessage)]
    struct Node {
        #[proto(uint64, tag = 1)]
        id: u64,
        #[proto(message, optional, tag = 2)]
        next: Option<Link>,
        #[proto(oneof, tags = "3")]
        choice: Option<Branch>,
    }

    #[derive(Debug, PartialEq, asupersync::ProtoOneof)]
    enum Branch {
        #[proto(message, tag = 3)]
        Child(Link),
    }

    #[derive(Debug, Default, PartialEq, asupersync::ProtoMessage)]
    struct Forest {
        #[proto(message, tag = 1)]
        root: Link,
        #[proto(message, repeated, tag = 2)]
        nodes: Vec<Link>,
        #[proto(map, key = "uint32", value = "message", tag = 3)]
        index: BTreeMap<u32, Link>,
    }

    #[test]
    fn boxed_messages_merge_and_share_the_wire_depth_limit() {
        let limits = ProtobufWireLimits::for_message_size_and_depth(32, 2);
        // Two occurrences of the same oneof member merge a scalar and a nested child.
        let wire = [0x1a, 2, 0x08, 7, 0x1a, 4, 0x12, 2, 0x08, 9];
        let root = Node::decode_from_bytes(&wire, limits).unwrap();
        let Some(Branch::Child(child)) = &root.choice else {
            panic!("missing branch")
        };
        assert_eq!(child.id, 7);
        assert_eq!(child.next.as_ref().unwrap().id, 9);
        assert_eq!(
            root.encode_to_bytes(limits).unwrap().as_ref(),
            &[0x1a, 6, 0x08, 7, 0x12, 2, 0x08, 9]
        );

        let shallow = limits.with_max_depth(1);
        for rejected in [
            Node::decode_from_bytes(&wire, shallow).unwrap_err(),
            root.encode_to_bytes(shallow).unwrap_err(),
        ] {
            assert!(matches!(
                rejected,
                ProtobufWireError::RecursionLimitExceeded {
                    depth: 2,
                    limit: 1,
                    ..
                }
            ));
        }

        // The same recursive schema works as a singular field, a repeated
        // element and a map value, including through a downstream type alias.
        let forest_wire = [0x0a, 2, 8, 1, 0x12, 2, 8, 2, 0x1a, 6, 8, 3, 0x12, 2, 8, 4];
        let forest = Forest::decode_from_bytes(&forest_wire, limits).unwrap();
        assert_eq!(
            (forest.root.id, forest.nodes[0].id, forest.index[&3].id),
            (1, 2, 4)
        );
        assert_eq!(
            forest.encode_to_bytes(limits).unwrap().as_ref(),
            forest_wire
        );
    }

    #[derive(Debug, Default, asupersync::ProtoMessage)]
    struct Custom {
        #[proto(uint64, tag = 1)]
        id: u64,
    }

    // A downstream implementation on Box<Local> is legal and can have a
    // different schema from Local. Derive must continue selecting it first.
    impl ProtoMessage for Box<Custom> {
        fn encode_fields(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            encoder.write_varint(2, self.id)
        }

        fn merge_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            _: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            if field.field_number() != 2 {
                return Ok(false);
            }
            self.id = field.as_varint()?;
            Ok(true)
        }
    }

    #[test]
    fn explicit_box_message_implementation_remains_authoritative() {
        #[derive(Default, asupersync::ProtoMessage)]
        struct Holder {
            #[proto(message, optional, tag = 1)]
            child: Option<Box<Custom>>,
        }
        let wire = [0x0a, 2, 0x10, 13];
        let limits = ProtobufWireLimits::default();
        let holder = Holder::decode_from_bytes(&wire, limits).unwrap();
        assert_eq!(holder.child.as_ref().unwrap().id, 13);
        assert_eq!(holder.encode_to_bytes(limits).unwrap().as_ref(), wire);
    }
}
