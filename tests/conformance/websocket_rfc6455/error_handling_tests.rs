#![allow(warnings)]
#![allow(clippy::all)]
//! Error handling conformance tests.
//!
//! RFC6455-5.6-002, RFC6455-ERROR-001 and RFC6455-ERROR-002 are ported from
//! the orphaned legacy close-frame harness and tightened so each rejection can
//! only pass for the stated reason. The remaining cases check that the
//! production codec and client fail the connection on invalid input
//! (RFC 6455 §8.1) and stop processing peer data afterwards (§7.1.7).

use super::fragmentation_tests::{client_receiving, data_frame, recv_once, server_wire};
use super::*;
use asupersync::Cx;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Decoder;
use asupersync::net::websocket::{
    CloseHandshake, CloseReason, CloseState, Frame, FrameCodec, Message, Opcode, WsError,
};

/// Run all error handling conformance tests.
#[allow(dead_code)]
pub fn run_error_handling_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();

    results.push(test_close_reason_invalid_utf8_rejection());
    results.push(test_invalid_opcode_rejection());
    results.push(test_malformed_payload_rejection());
    results.push(test_invalid_utf8_text_fails_connection());
    results.push(test_codec_stops_after_fatal_error());
    results.push(test_no_data_processed_after_failure());

    results
}

/// RFC 6455 §5.5.1/§8.1: a Close reason that is not valid UTF-8 must be
/// rejected by the payload parser, the wire decoder and the close handshake.
#[allow(dead_code)]
fn test_close_reason_invalid_utf8_rejection() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice(&[0xFF, 0xFE]); // Invalid UTF-8

        match CloseReason::parse(&payload) {
            Err(WsError::InvalidClosePayload) => {}
            other => {
                return Err(format!(
                    "CloseReason::parse must reject an invalid UTF-8 reason, got {other:?}"
                ));
            }
        }

        let mut buf = BytesMut::from(&[0x88u8, 0x04, 0x03, 0xE8, 0xFF, 0xFE][..]);
        match FrameCodec::client().decode(&mut buf) {
            Err(WsError::InvalidClosePayload) => {}
            other => {
                return Err(format!(
                    "wire decoder must reject a Close frame with an invalid UTF-8 reason, got {other:?}"
                ));
            }
        }

        let forged = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Close,
            masked: false,
            mask_key: None,
            payload: Bytes::from(payload),
        };
        let mut handshake = CloseHandshake::new();
        match handshake.receive_close(&forged) {
            Err(WsError::InvalidClosePayload) => {}
            other => {
                return Err(format!(
                    "close handshake must reject an invalid UTF-8 reason, got {other:?}"
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.6-002",
        "Close reason text MUST reject invalid UTF-8",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// The close handshake must refuse non-Close frames. The payload of each
/// probe is a valid Close body (code 1000), so only the opcode check can
/// reject it.
#[allow(dead_code)]
fn test_invalid_opcode_rejection() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let valid_close_body: &'static [u8] = &[0x03, 0xE8];
        let probes = [
            Frame::ping(Bytes::from_static(valid_close_body)),
            Frame::pong(Bytes::from_static(valid_close_body)),
            Frame::text(Bytes::from_static(valid_close_body)),
        ];

        for probe in &probes {
            let mut handshake = CloseHandshake::new();
            match handshake.receive_close(probe) {
                Err(WsError::InvalidOpcode(op)) if op == probe.opcode as u8 => {}
                other => {
                    return Err(format!(
                        "{:?} frame must be rejected by the close handshake as an invalid opcode, got {other:?}",
                        probe.opcode
                    ));
                }
            }
            if handshake.state() != CloseState::Open || handshake.peer_reason().is_some() {
                return Err(format!(
                    "a rejected {:?} frame must not advance the close handshake (state {:?})",
                    probe.opcode,
                    handshake.state()
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-ERROR-001",
        "Non-close frames MUST be rejected by close handshake",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §7.4: codes outside the valid ranges and the never-on-the-wire
/// codes must be rejected in a received Close frame.
#[allow(dead_code)]
fn test_malformed_payload_rejection() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        for code in [0u16, 999, 1004, 1005, 1006, 1015, 5000, 65535] {
            match CloseReason::parse(&code.to_be_bytes()) {
                Err(WsError::InvalidClosePayload) => {}
                other => {
                    return Err(format!(
                        "received close code {code} must be rejected, got {other:?}"
                    ));
                }
            }
        }

        // The same rule on the wire decoder (codes 999 and 1005).
        for (code, bytes) in [(999u16, [0x03u8, 0xE7]), (1005, [0x03, 0xED])] {
            let mut buf = BytesMut::from(&[0x88u8, 0x02, bytes[0], bytes[1]][..]);
            match FrameCodec::client().decode(&mut buf) {
                Err(WsError::InvalidClosePayload) => {}
                other => {
                    return Err(format!(
                        "wire decoder must reject a Close frame carrying {code}, got {other:?}"
                    ));
                }
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-ERROR-002",
        "Malformed close payloads MUST be rejected",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §8.1: "When an endpoint is to interpret a byte stream as UTF-8
/// but finds that the byte stream is not, in fact, a valid UTF-8 stream, that
/// endpoint MUST _Fail the WebSocket Connection_."
#[allow(dead_code)]
fn test_invalid_utf8_text_fails_connection() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let wire = server_wire(vec![Frame::text(Bytes::from_static(&[0xFF, 0xFE]))])?;
        let (mut ws, _peer) = client_receiving(&wire)?;
        let cx = Cx::for_testing();

        match recv_once(&mut ws, &cx) {
            Err(WsError::InvalidUtf8) => {}
            other => {
                return Err(format!(
                    "a Text message that is not valid UTF-8 must fail the connection, got {other:?}"
                ));
            }
        }
        if ws.is_open() {
            return Err("connection must be failed (not open) after invalid UTF-8".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-8.1-INVALID-UTF8-TEXT",
        "Invalid UTF-8 in a Text message MUST fail the connection",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §7.1.7: after a fatal protocol error the decoder must not produce
/// further frames, even from well-formed input.
#[allow(dead_code)]
fn test_codec_stops_after_fatal_error() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Each case: label, decoder, bytes that trigger a fatal error, and a
        // well-formed frame for that decoder's role.
        let unmasked_ok: &[u8] = &[0x81, 0x02, b'o', b'k'];
        let masked_ok: &[u8] = &[0x81, 0x82, 0x00, 0x00, 0x00, 0x00, b'o', b'k'];
        let cases: [(&str, FrameCodec, &[u8], &[u8]); 4] = [
            (
                "reserved opcode 0x3",
                FrameCodec::client(),
                &[0x83, 0x00],
                unmasked_ok,
            ),
            (
                "RSV1 without extension",
                FrameCodec::client(),
                &[0xC1, 0x00],
                unmasked_ok,
            ),
            (
                "unmasked client frame",
                FrameCodec::server(),
                &[0x81, 0x00],
                masked_ok,
            ),
            (
                "126-byte Ping",
                FrameCodec::client(),
                &[0x89, 0x7E, 0x00, 0x7E],
                unmasked_ok,
            ),
        ];

        for (label, mut codec, bad, good) in cases {
            let mut bad_buf = BytesMut::from(bad);
            if let Ok(frame) = codec.decode(&mut bad_buf) {
                return Err(format!("{label}: must fail decode, got {frame:?}"));
            }
            let mut good_buf = BytesMut::from(good);
            if let Ok(frame) = codec.decode(&mut good_buf) {
                return Err(format!(
                    "{label}: after the fatal error the decoder still processed peer data, got {frame:?}"
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.1.7-CODEC-STOPS-AFTER-FAIL",
        "Decoder MUST NOT process further data after a fatal protocol error",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §7.1.7: "An endpoint MUST NOT continue to attempt to process data
/// (including a responding Close frame) from the remote endpoint after being
/// instructed to _Fail the WebSocket Connection_." After `recv` reports a
/// violation, a later `recv` must not deliver the data message that followed
/// it on the wire.
#[allow(dead_code)]
fn test_no_data_processed_after_failure() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let trailer = server_wire(vec![Frame::text("after-failure")])?;
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "invalid UTF-8 text (RFC 6455 §8.1)",
                server_wire(vec![Frame::text(Bytes::from_static(&[0xFF, 0xFE]))])?,
            ),
            (
                "continuation without a started message (§5.4)",
                server_wire(vec![data_frame(Opcode::Continuation, true, b"x")])?,
            ),
            (
                "new data frame inside a fragmented message (§5.4)",
                server_wire(vec![
                    data_frame(Opcode::Text, false, b"a"),
                    data_frame(Opcode::Binary, true, b"b"),
                ])?,
            ),
            (
                "RSV1 without a negotiated extension (§5.2)",
                vec![0xC1, 0x00],
            ),
        ];

        let mut leaks = Vec::new();
        for (label, mut wire) in cases {
            wire.extend_from_slice(&trailer);
            let (mut ws, _peer) = client_receiving(&wire)?;
            let cx = Cx::for_testing();

            match recv_once(&mut ws, &cx) {
                Err(_) => {}
                other => {
                    return Err(format!(
                        "{label}: precondition failed, the violation was not reported: {other:?}"
                    ));
                }
            }
            match recv_once(&mut ws, &cx) {
                Ok(Some(message @ (Message::Text(_) | Message::Binary(_)))) => {
                    leaks.push(format!("{label}: then delivered {message:?}"));
                }
                _ => {}
            }
        }

        if leaks.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "data was processed after the connection was failed: {}",
                leaks.join("; ")
            ))
        }
    });

    create_test_result(
        "RFC6455-7.1.7-NO-DATA-AFTER-FAIL",
        "No peer data MUST be processed after the connection is failed",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
