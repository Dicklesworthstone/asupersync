use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::{FramedCodec, GrpcCodec, GrpcError, GrpcMessage, IdentityCodec};
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
        }),
        @r###"
        {
          "spec": "Length-Prefixed-Message",
          "cases": [
            {
              "compressed": false,
              "declared_length": 0,
              "name": "empty",
              "wire_hex": "00 00 00 00 00",
              "wire_len": 5
            },
            {
              "compressed": false,
              "declared_length": 5,
              "name": "small",
              "wire_hex": "00 00 00 00 05 68 65 6c 6c 6f",
              "wire_len": 10
            },
            {
              "compressed": false,
              "declared_length": 64,
              "name": "medium",
              "wire_hex": "00 00 00 00 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80",
              "wire_len": 69
            },
            {
              "compressed": false,
              "declared_length": 256,
              "name": "large",
              "wire_hex": "00 00 00 01 00 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79",
              "wire_len": 261
            }
          ]
        }
        "###
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
        frame_fixture("identity", wire.as_ref()),
        @r###"
        {
          "compressed": true,
          "declared_length": 14,
          "name": "identity",
          "wire_hex": "01 00 00 00 0e 69 64 65 6e 74 69 74 79 2d 63 6f 64 65 63",
          "wire_len": 19
        }
        "###
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
        frame_fixture("gzip", wire.as_ref()),
        @r###"
        {
          "compressed": true,
          "declared_length": 36,
          "name": "gzip",
          "wire_hex": "01 00 00 00 24 1f 8b 08 00 00 00 00 00 00 ff 4b af ca 2c 50 28 2f ca 4c 49 d5 49 cc 29 c8 48 04 00 26 86 4b a5 10 00 00 00",
          "wire_len": 41
        }
        "###
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
        }),
        @r###"
        {
          "max_size_rejection": {
            "error": "message too large"
          },
          "truncated_length_prefixed_message": {
            "decode_result": "pending",
            "remaining_wire_hex": "00 00 00 00 04 61 62 63"
          }
        }
        "###
    );
}
