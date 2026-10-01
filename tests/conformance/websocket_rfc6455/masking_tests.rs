#![allow(warnings)]
#![allow(clippy::all)]
//! Masking conformance tests (RFC 6455 §5.1, §5.3).
//!
//! Every case drives the production `FrameCodec` (in its client or server
//! role) or `apply_mask`. Wire expectations use the RFC 6455 §5.7 example
//! frames, so the masking algorithm is checked against known answers rather
//! than only against itself.

use super::*;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::net::websocket::{Frame, FrameCodec, Opcode, WsError, apply_mask};
use std::collections::HashSet;

/// RFC 6455 §5.7: masking key used by the masked example frames.
const RFC_MASK_KEY: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];
/// RFC 6455 §5.7: "Hello" masked with `RFC_MASK_KEY`.
const RFC_MASKED_HELLO_PAYLOAD: [u8; 5] = [0x7f, 0x9f, 0x4d, 0x51, 0x58];
/// RFC 6455 §5.7: a single-frame masked text message containing "Hello".
const RFC_MASKED_TEXT: [u8; 11] = [
    0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
];
/// RFC 6455 §5.7: a masked Pong whose body is "Hello".
const RFC_MASKED_PONG: [u8; 11] = [
    0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
];
/// RFC 6455 §5.7: a single-frame unmasked text message containing "Hello".
const RFC_UNMASKED_TEXT: [u8; 7] = [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];

/// Run all masking conformance tests.
#[allow(dead_code)]
pub fn run_masking_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();

    results.push(test_server_rejects_unmasked_client_frame());
    results.push(test_client_rejects_masked_server_frame());
    results.push(test_client_masking_requirement());
    results.push(test_server_frames_are_unmasked());
    results.push(test_fresh_mask_key_per_frame());
    results.push(test_mask_algorithm_known_answer());
    results.push(test_masked_client_frame_decodes());

    results
}

/// Encodes one frame with `codec` and returns the wire bytes.
fn encode_one(codec: &mut FrameCodec, frame: Frame) -> Result<Vec<u8>, String> {
    let opcode = frame.opcode;
    let mut buf = BytesMut::new();
    codec
        .encode(frame, &mut buf)
        .map_err(|e| format!("encode of {opcode:?} failed: {e}"))?;
    Ok(buf.to_vec())
}

/// Splits a client-encoded frame into (mask key, masked payload), checking the
/// MASK bit and the declared length.
fn masked_parts(wire: &[u8], payload_len: usize) -> Result<([u8; 4], Vec<u8>), String> {
    if wire.len() < 2 {
        return Err(format!("encoded frame too short: {wire:?}"));
    }
    if wire[1] & 0x80 == 0 {
        return Err(format!(
            "client frame must have the MASK bit set, second byte is 0x{:02X}",
            wire[1]
        ));
    }
    let header_len = match wire[1] & 0x7F {
        126 => 4,
        127 => 10,
        _ => 2,
    };
    let key_end = header_len + 4;
    if wire.len() != key_end + payload_len {
        return Err(format!(
            "masked frame must be {} bytes (header {header_len} + key 4 + payload {payload_len}), got {}",
            key_end + payload_len,
            wire.len()
        ));
    }
    let key = [
        wire[header_len],
        wire[header_len + 1],
        wire[header_len + 2],
        wire[header_len + 3],
    ];
    Ok((key, wire[key_end..].to_vec()))
}

/// RFC 6455 §5.1: "The server MUST close the connection upon receiving a
/// frame that is not masked."
#[allow(dead_code)]
fn test_server_rejects_unmasked_client_frame() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let unmasked_ping: &[u8] = &[0x89, 0x00];
        for (label, bytes) in [
            ("unmasked Text", &RFC_UNMASKED_TEXT[..]),
            ("unmasked Ping", unmasked_ping),
        ] {
            let mut buf = BytesMut::from(bytes);
            match FrameCodec::server().decode(&mut buf) {
                Err(WsError::UnmaskedClientFrame) => {}
                other => {
                    return Err(format!(
                        "server must reject an {label} frame from a client, got {other:?}"
                    ));
                }
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.1-SERVER-REJECTS-UNMASKED",
        "Server MUST fail the connection on an unmasked client frame",
        TestCategory::Masking,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.1: "A client MUST close a connection if it detects a masked
/// frame."
#[allow(dead_code)]
fn test_client_rejects_masked_server_frame() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        for (label, bytes) in [
            ("masked Text", &RFC_MASKED_TEXT[..]),
            ("masked Pong", &RFC_MASKED_PONG[..]),
        ] {
            let mut buf = BytesMut::from(bytes);
            match FrameCodec::client().decode(&mut buf) {
                Err(WsError::MaskedServerFrame) => {}
                other => {
                    return Err(format!(
                        "client must reject a {label} frame from a server, got {other:?}"
                    ));
                }
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.1-CLIENT-REJECTS-MASKED",
        "Client MUST fail the connection on a masked server frame",
        TestCategory::Masking,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.3: "a client MUST mask all frames that it sends to the server",
/// data and control frames alike and whatever the payload-length encoding.
/// Unmasking the wire payload with the wire key must give back the payload.
#[allow(dead_code)]
fn test_client_masking_requirement() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let long: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let cases: Vec<(&str, Frame, Vec<u8>)> = vec![
            ("Text \"Hello\"", Frame::text("Hello"), b"Hello".to_vec()),
            (
                "200-byte Binary (16-bit length)",
                Frame::binary(Bytes::from(long.clone())),
                long.clone(),
            ),
            (
                "Ping",
                Frame::ping(Bytes::from_static(b"ping")),
                b"ping".to_vec(),
            ),
        ];

        let mut codec = FrameCodec::client();
        for (label, frame, plain) in cases {
            if frame.masked {
                return Err(format!(
                    "{label}: precondition, input frame must be unmasked"
                ));
            }
            let wire = encode_one(&mut codec, frame)?;
            let (key, mut payload) =
                masked_parts(&wire, plain.len()).map_err(|e| format!("{label}: {e}"))?;
            apply_mask(&mut payload, key);
            if payload != plain {
                return Err(format!(
                    "{label}: unmasking the wire payload with the wire key must give the payload back"
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.3-MASKING",
        "Client MUST mask every frame it sends",
        TestCategory::Masking,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.1: "A server MUST NOT mask any frames that it sends to the
/// client." Even a frame value that claims a mask must go out unmasked.
#[allow(dead_code)]
fn test_server_frames_are_unmasked() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = FrameCodec::server();

        let wire = encode_one(&mut codec, Frame::text("Hello"))?;
        if wire[..] != RFC_UNMASKED_TEXT[..] {
            return Err(format!(
                "server Text(\"Hello\") must be the RFC 6455 §5.7 unmasked frame {RFC_UNMASKED_TEXT:02X?}, got {wire:02X?}"
            ));
        }

        let claims_mask = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: true,
            mask_key: Some(RFC_MASK_KEY),
            payload: Bytes::from_static(b"Hello"),
        };
        let wire = encode_one(&mut codec, claims_mask)?;
        if wire[..] != RFC_UNMASKED_TEXT[..] {
            return Err(format!(
                "server must not mask even when the frame value carries a key; expected {RFC_UNMASKED_TEXT:02X?}, got {wire:02X?}"
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.1-SERVER-UNMASKED",
        "Server MUST NOT mask frames it sends",
        TestCategory::Masking,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.3: "The masking key is a 32-bit value chosen at random by the
/// client ... the client MUST pick a fresh masking key from the set of allowed
/// 32-bit values" for each frame. Sixteen frames must not share a key (one
/// chance collision among sixteen random keys is tolerated).
#[allow(dead_code)]
fn test_fresh_mask_key_per_frame() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        const FRAMES: usize = 16;
        let mut codec = FrameCodec::client();
        let mut keys = HashSet::new();
        for _ in 0..FRAMES {
            let wire = encode_one(&mut codec, Frame::text("same payload"))?;
            let (key, _) = masked_parts(&wire, "same payload".len())?;
            keys.insert(key);
        }
        if keys.len() < FRAMES - 1 {
            return Err(format!(
                "each frame needs a fresh masking key; {FRAMES} frames used only {} distinct keys",
                keys.len()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.3-FRESH-MASK-KEY",
        "Client MUST use a fresh masking key for each frame",
        TestCategory::Masking,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.3: octet i of the masked data is octet i of the original data
/// XOR octet (i mod 4) of the masking key. Checked against the §5.7 vector;
/// applying the mask again restores the original.
#[allow(dead_code)]
fn test_mask_algorithm_known_answer() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut data = b"Hello".to_vec();
        apply_mask(&mut data, RFC_MASK_KEY);
        if data[..] != RFC_MASKED_HELLO_PAYLOAD[..] {
            return Err(format!(
                "apply_mask(\"Hello\", {RFC_MASK_KEY:02X?}) must be {RFC_MASKED_HELLO_PAYLOAD:02X?}, got {data:02X?}"
            ));
        }
        apply_mask(&mut data, RFC_MASK_KEY);
        if data[..] != b"Hello"[..] {
            return Err(format!(
                "applying the same mask twice must restore \"Hello\", got {data:02X?}"
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.3-MASK-ALGORITHM",
        "Masking transform matches the RFC 6455 §5.7 known answer",
        TestCategory::Masking,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.3/§5.7: a server-role decoder unmasks client frames back to
/// the original payload (RFC example masked Text and masked Pong).
#[allow(dead_code)]
fn test_masked_client_frame_decodes() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        for (label, bytes, opcode) in [
            ("masked Text", &RFC_MASKED_TEXT[..], Opcode::Text),
            ("masked Pong", &RFC_MASKED_PONG[..], Opcode::Pong),
        ] {
            let mut buf = BytesMut::from(bytes);
            let frame = FrameCodec::server()
                .decode(&mut buf)
                .map_err(|e| format!("{label}: server must accept it: {e}"))?
                .ok_or_else(|| format!("{label}: decoder returned no frame"))?;
            if frame.opcode != opcode || !frame.fin {
                return Err(format!(
                    "{label}: expected FIN {opcode:?}, got FIN={} {:?}",
                    frame.fin, frame.opcode
                ));
            }
            if &frame.payload[..] != b"Hello" {
                return Err(format!(
                    "{label}: must unmask to \"Hello\", got {:?}",
                    &frame.payload[..]
                ));
            }
            if !frame.masked || frame.mask_key != Some(RFC_MASK_KEY) {
                return Err(format!(
                    "{label}: decoded frame must report the wire masking key, got masked={} key={:?}",
                    frame.masked, frame.mask_key
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.3-MASKED-DECODE",
        "Masked client frame decodes to the original payload",
        TestCategory::Masking,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
