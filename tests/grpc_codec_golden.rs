//! Golden tests for gRPC frame encoding and decoding shapes.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::{FramedCodec, GrpcCodec, GrpcMessage, IdentityCodec};
use insta::assert_json_snapshot;
use serde_json::{Value, json};
use std::fmt::Write as _;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (idx, byte) in bytes.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn repeated_payload(seed: u8, len: usize) -> Bytes {
    Bytes::from(
        (0..len)
            .map(|idx| seed.wrapping_add((idx % 251) as u8))
            .collect::<Vec<_>>(),
    )
}

fn frame_fixture(name: &str, wire: &[u8]) -> Value {
    let declared_length = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize;
    json!({
        "name": name,
        "compressed": wire[0] == 1,
        "declared_length": declared_length,
        "wire_len": wire.len(),
        "wire_hex": hex(wire),
    })
}

#[test]
fn golden_grpc_codec_length_prefixed_messages() {
    let mut codec = GrpcCodec::new();
    let mut fixtures = Vec::new();

    for (name, payload) in [
        ("empty", Bytes::new()),
        ("small", Bytes::from_static(b"hello")),
        ("medium", repeated_payload(0x41, 64)),
        ("large", repeated_payload(0x7a, 256)),
    ] {
        let mut wire = BytesMut::new();
        codec
            .encode(GrpcMessage::new(payload), &mut wire)
            .expect("grpc framing encode must succeed");
        fixtures.push(frame_fixture(name, wire.as_ref()));
    }

    assert_json_snapshot!(
        "grpc_codec_length_prefixed_messages",
        json!({
            "spec": "Length-Prefixed-Message",
            "cases": fixtures,
        })
    );
}

#[test]
fn golden_grpc_codec_identity_compression_wire_layout() {
    let mut codec = FramedCodec::new(IdentityCodec).with_identity_frame_codec();
    let mut wire = BytesMut::new();
    let payload = Bytes::from_static(b"identity-codec");

    codec
        .encode_message(&payload, &mut wire)
        .expect("identity compression framing must succeed");

    assert_json_snapshot!(
        "grpc_codec_identity_compression_wire_layout",
        frame_fixture("identity", wire.as_ref())
    );
}

#[cfg(feature = "compression")]
#[test]
fn golden_grpc_codec_gzip_compression_wire_layout() {
    let mut codec = FramedCodec::new(IdentityCodec).with_gzip_frame_codec();
    let mut wire = BytesMut::new();
    let payload = Bytes::from_static(b"gzip-wire-layout");

    codec
        .encode_message(&payload, &mut wire)
        .expect("gzip framing must succeed");

    assert_json_snapshot!(
        "grpc_codec_gzip_compression_wire_layout",
        frame_fixture("gzip", wire.as_ref())
    );
}

#[test]
fn golden_grpc_codec_decode_edge_cases() {
    let mut decode_codec = GrpcCodec::new();
    let mut truncated = BytesMut::from(&b"\x00\x00\x00\x00\x04abc"[..]);
    let truncated_result = decode_codec
        .decode(&mut truncated)
        .expect("truncated frames should remain pending");

    let mut oversize_encode = BytesMut::new();
    let oversize_error = GrpcCodec::with_max_size(3)
        .encode(
            GrpcMessage::new(Bytes::from_static(b"four")),
            &mut oversize_encode,
        )
        .expect_err("oversize payload must be rejected");

    assert_json_snapshot!(
        "grpc_codec_decode_edge_cases",
        json!({
            "truncated_length_prefixed_message": {
                "decode_result": match truncated_result {
                    Some(_) => "decoded",
                    None => "pending",
                },
                "remaining_wire_hex": hex(truncated.as_ref()),
            },
            "max_size_rejection": {
                "error": oversize_error.to_string(),
            },
        })
    );
}
