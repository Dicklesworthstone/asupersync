//! Runnable proofs for three pure foundation modules shipped this session:
//! the SWIM membership wire codec (bead 8y37kz.4.4), the typed-computation
//! schema fingerprint (bead 8y37kz.7), and the erasure-channel block-layout
//! planner (bead 3bb2pl.1).
//!
//! These exercise the public APIs end to end so the round-trip/decision
//! behaviour is verified at runtime, not merely compiled. Run with:
//! `cargo test --test membership_codec_and_schema_proofs --features test-internals`.

use asupersync::channel::erasure::{EcConfig, EcError, MessageHeader};
use asupersync::distributed::membership::{
    DEFAULT_MTU, Packet, Payload, Rumor, WireError, decode_packet, encode_packet,
};
use asupersync::distributed::{HasSchema, SchemaDescriptor, SchemaMismatchKind};
use asupersync::remote::NodeId;

// ---- 8y37kz.4.4: membership wire codec -----------------------------------

fn node(s: &str) -> NodeId {
    NodeId::new(s)
}

#[test]
fn wire_codec_round_trips_payloads_and_gossip() {
    let packet = Packet {
        payload: Payload::PingReq {
            seq: 11,
            target: node("node-b"),
        },
        gossip: vec![
            Rumor::alive(node("a"), 3),
            Rumor::suspect(node("b"), 5, node("c")),
            Rumor::confirm(node("d"), 7, node("e")),
            Rumor::leave(node("f"), 9),
        ],
    };
    let encoded = encode_packet(&packet, DEFAULT_MTU).expect("encode");
    assert_eq!(encoded.gossip_dropped, 0);
    let decoded = decode_packet(&encoded.bytes).expect("decode");
    assert_eq!(decoded, packet);
}

#[test]
fn wire_codec_truncates_gossip_to_mtu_and_decodes_prefix() {
    let gossip: Vec<Rumor> = (0..40)
        .map(|i| Rumor::alive(node(&format!("node-{i}")), i))
        .collect();
    let packet = Packet {
        payload: Payload::Ping { seq: 1 },
        gossip,
    };
    let encoded = encode_packet(&packet, 64).expect("encode");
    assert!(encoded.bytes.len() <= 64);
    assert!(encoded.gossip_included < 40);
    assert_eq!(encoded.gossip_included + encoded.gossip_dropped, 40);
    let decoded = decode_packet(&encoded.bytes).expect("decode");
    assert_eq!(decoded.gossip.len(), encoded.gossip_included);
}

#[test]
fn wire_codec_rejects_malformed_input() {
    assert_eq!(decode_packet(&[]), Err(WireError::UnexpectedEof));
    assert_eq!(decode_packet(&[9, 0]), Err(WireError::UnknownVersion(9)));
}

// ---- 8y37kz.7: schema fingerprint ----------------------------------------

#[test]
fn schema_fingerprint_is_structural_and_distinct() {
    assert_eq!(u64::schema_fingerprint(), u64::schema_fingerprint());
    assert_ne!(u64::schema_fingerprint(), u32::schema_fingerprint());
    assert_ne!(
        <Vec<u8>>::schema_fingerprint(),
        <Vec<u16>>::schema_fingerprint()
    );
    // Two independently-built but identical descriptors agree (not TypeId-based).
    let a = SchemaDescriptor::structure("P", vec![("x", u8::schema())]);
    let b = SchemaDescriptor::structure("P", vec![("x", u8::schema())]);
    assert_eq!(a.fingerprint(), b.fingerprint());
}

#[test]
fn schema_diff_names_a_type_change() {
    let expected = SchemaDescriptor::structure(
        "Person",
        vec![("id", u64::schema()), ("name", String::schema())],
    );
    let actual = SchemaDescriptor::structure(
        "Person",
        vec![("id", u32::schema()), ("name", String::schema())],
    );
    let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
    assert_eq!(mismatch.path, "$.id");
    assert!(matches!(
        mismatch.kind,
        SchemaMismatchKind::PrimitiveChanged {
            expected: "u64",
            actual: "u32"
        }
    ));
}

// ---- 3bb2pl.1: erasure-channel block-layout planner ----------------------

#[test]
fn erasure_block_layout_plans_symbols_and_padding() {
    let cfg = EcConfig {
        symbol_size: 100,
        repair_overhead: 2,
        max_message_size: 1 << 20,
    };
    let small = cfg.plan(10).expect("plan");
    assert_eq!(small.source_symbols, 1);
    assert_eq!(small.total_symbols, 3);
    assert_eq!(small.padding, 90);

    let padded = cfg.plan(250).expect("plan");
    assert_eq!(padded.source_symbols, 3);
    assert_eq!(padded.padding, 50);

    assert_eq!(
        cfg.plan(usize::MAX),
        Err(EcError::MessageTooLarge {
            size: usize::MAX,
            max: 1 << 20
        })
    );
}

#[test]
fn erasure_message_header_round_trips() {
    let cfg = EcConfig::default();
    let layout = cfg.plan(5000).expect("plan");
    let header = MessageHeader::from_layout(7, &layout).expect("header");
    let bytes = header.encode();
    let decoded = MessageHeader::decode(&bytes).expect("decode");
    assert_eq!(decoded, header);
    assert_eq!(decoded.message_id, 7);
    assert_eq!(decoded.message_size, 5000);
}
