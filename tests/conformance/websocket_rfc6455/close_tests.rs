#![allow(warnings)]
#![allow(clippy::all)]
//! Close frame conformance tests.
//!
//! Ported from the orphaned legacy close-frame harness
//! (`tests/conformance/websocket_rfc6455.rs`), keeping its test ids,
//! descriptions and requirement levels: close-frame payloads (RFC 6455
//! §5.5.1), status codes (§7.4), the close handshake (§7.1), close-reason
//! UTF-8 acceptance and the encode/parse round trip. Each legacy
//! `catch_unwind` + `assert!` body is a `Result` closure here, and most cases
//! also check the same rule on the production wire codec. Two live-connection
//! cases drive the production client over an in-memory transport.

use super::fragmentation_tests::{
    client_receiving, decode_client_frames, drain_peer, recv_once, server_wire,
};
use super::*;
use asupersync::Cx;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::net::websocket::{
    CloseCode, CloseHandshake, CloseReason, CloseState, Frame, FrameCodec, Message, Opcode, WsError,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Run all close conformance tests.
#[allow(dead_code)]
pub fn run_close_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();

    // RFC 6455 §5.5.1 - close frame payload format
    results.push(test_close_frame_empty_payload());
    results.push(test_close_frame_code_only());
    results.push(test_close_frame_code_and_reason());
    results.push(test_close_frame_invalid_single_byte());
    results.push(test_close_frame_oversized_payload());
    results.push(test_close_frame_answered_on_live_connection());
    results.push(test_no_data_after_close_on_live_connection());

    // RFC 6455 §7.4 - status code semantics
    results.push(test_status_code_normal_closure());
    results.push(test_status_code_going_away());
    results.push(test_status_code_protocol_error());
    results.push(test_status_code_unsupported_data());
    results.push(test_status_code_invalid_payload());
    results.push(test_status_code_policy_violation());
    results.push(test_status_code_message_too_big());
    results.push(test_status_code_mandatory_extension());
    results.push(test_status_code_internal_error());

    // RFC 6455 §7.4 - codes that must never be sent
    results.push(test_status_code_reserved_never_sent());
    results.push(test_status_code_no_status_received_never_sent());
    results.push(test_status_code_abnormal_never_sent());
    results.push(test_status_code_tls_handshake_never_sent());

    // RFC 6455 §7.4 - status code ranges
    results.push(test_status_code_range_validation());
    results.push(test_status_code_iana_registered());
    results.push(test_status_code_private_use());
    results.push(test_status_code_unassigned_acceptance());

    // RFC 6455 §7.1 - close handshake
    results.push(test_handshake_initiator_flow());
    results.push(test_handshake_receiver_flow());
    results.push(test_handshake_echo_status_code());
    results.push(test_handshake_empty_close_echo());
    results.push(test_handshake_custom_code_echo());

    // Close reason text and round trip
    results.push(test_close_reason_utf8_validation());
    results.push(test_close_frame_encode_decode_roundtrip());

    results
}

// ===== Helpers =====

/// Runs `f`; a panic becomes `Err` so a production regression is reported as a
/// failed verdict instead of aborting the suite.
fn no_panic<T>(what: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|_| format!("{what}: unexpected panic"))
}

/// Requires `f` to refuse its input by panicking (the documented behaviour of
/// the `Frame::close` constructor for RFC-invalid input).
fn expect_panic<T>(what: &str, f: impl FnOnce() -> T) -> Result<(), String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Err(_) => Ok(()),
        Ok(_) => Err(format!(
            "{what}: the call must refuse the input (panic), but it returned a value"
        )),
    }
}

/// Encodes `frame` with the production server-role encoder and decodes it
/// with the production client-role decoder.
fn wire_round_trip(frame: Frame) -> Result<Frame, String> {
    let opcode = frame.opcode;
    let mut buf = BytesMut::new();
    FrameCodec::server()
        .encode(frame, &mut buf)
        .map_err(|e| format!("server encode of {opcode:?} failed: {e}"))?;
    FrameCodec::client()
        .decode(&mut buf)
        .map_err(|e| format!("client decode of {opcode:?} failed: {e}"))?
        .ok_or_else(|| format!("client decode of {opcode:?} returned no frame"))
}

/// A Close frame built field by field, bypassing the panicking constructor.
fn raw_close_frame(payload: Vec<u8>) -> Frame {
    Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: Opcode::Close,
        masked: false,
        mask_key: None,
        payload: Bytes::from(payload),
    }
}

/// A sendable status code: right numeric value, accepted by every send and
/// receive path, and carried unchanged across the wire.
fn check_sendable_status(code: CloseCode, wire: u16) -> Result<(), String> {
    if u16::from(code) != wire {
        return Err(format!(
            "{code:?} must map to {wire}, got {}",
            u16::from(code)
        ));
    }
    if !code.is_sendable() {
        return Err(format!("{code:?} ({wire}) must be sendable"));
    }
    if !CloseCode::is_valid_code(wire) {
        return Err(format!("{wire} must be valid for sending"));
    }
    if CloseCode::from_u16(wire) != Some(code) {
        return Err(format!(
            "CloseCode::from_u16({wire}) must be {code:?}, got {:?}",
            CloseCode::from_u16(wire)
        ));
    }

    let parsed = CloseReason::parse(&wire.to_be_bytes())
        .map_err(|e| format!("received code {wire} must parse: {e}"))?;
    if parsed.code != Some(code) || parsed.raw_code != Some(wire) {
        return Err(format!(
            "received code {wire} must parse to {code:?}/{wire}, got {:?}/{:?}",
            parsed.code, parsed.raw_code
        ));
    }

    let frame = no_panic(&format!("Frame::close(Some({wire}), None)"), || {
        Frame::close(Some(wire), None)
    })?;
    if frame.payload[..] != wire.to_be_bytes()[..] {
        return Err(format!(
            "Close frame for {wire} must carry its big-endian code, got {:?}",
            &frame.payload[..]
        ));
    }

    let decoded = wire_round_trip(frame)?;
    if decoded.opcode != Opcode::Close || decoded.payload[..] != wire.to_be_bytes()[..] {
        return Err(format!(
            "Close({wire}) must survive the wire unchanged, got {:?} {:?}",
            decoded.opcode,
            &decoded.payload[..]
        ));
    }
    Ok(())
}

/// RFC 6455 §7.4.1: 1004, 1005, 1006 and 1015 MUST NOT be sent in a Close
/// frame. Checks the constructor, the non-panicking wire encoder and the
/// `CloseReason` send paths.
fn check_never_sent_status(code: CloseCode, wire: u16) -> Result<(), String> {
    if u16::from(code) != wire {
        return Err(format!(
            "{code:?} must map to {wire}, got {}",
            u16::from(code)
        ));
    }
    if code.is_sendable() {
        return Err(format!("{code:?} ({wire}) must not be sendable"));
    }
    if CloseCode::is_valid_code(wire) {
        return Err(format!("{wire} must not be valid for sending"));
    }

    expect_panic(&format!("Frame::close(Some({wire}), None)"), || {
        Frame::close(Some(wire), None)
    })?;

    let forged = raw_close_frame(wire.to_be_bytes().to_vec());
    match FrameCodec::server().encode(forged, &mut BytesMut::new()) {
        Err(WsError::InvalidClosePayload) => {}
        other => {
            return Err(format!(
                "wire encoder must refuse a Close frame carrying {wire}, got {other:?}"
            ));
        }
    }

    let encoded = CloseReason::new(code, None).encode();
    if encoded.len() >= 2 && encoded[..2] == wire.to_be_bytes()[..] {
        return Err(format!("CloseReason::encode put {wire} on the wire"));
    }
    let frame = no_panic(&format!("CloseReason::new({code:?}).to_frame()"), || {
        CloseReason::new(code, None).to_frame()
    })?;
    if frame.payload.len() >= 2 && frame.payload[..2] == wire.to_be_bytes()[..] {
        return Err(format!("CloseReason::to_frame put {wire} on the wire"));
    }
    Ok(())
}

// ===== RFC 6455 §5.5.1 - Close Frame Format Tests =====

#[allow(dead_code)]
fn test_close_frame_empty_payload() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let reason =
            CloseReason::parse(&[]).map_err(|e| format!("empty payload should parse: {e}"))?;
        if reason.code.is_some() || reason.raw_code.is_some() || reason.text.is_some() {
            return Err(format!(
                "empty payload must parse to no code/text, got {reason:?}"
            ));
        }
        if !reason.encode().is_empty() {
            return Err("empty close reason must encode to an empty payload".to_string());
        }

        let mut buf = BytesMut::from(&[0x88u8, 0x00][..]);
        let frame = FrameCodec::client()
            .decode(&mut buf)
            .map_err(|e| format!("empty Close frame must decode: {e}"))?
            .ok_or("empty Close frame: decoder returned no frame")?;
        if frame.opcode != Opcode::Close || !frame.payload.is_empty() {
            return Err(format!(
                "expected an empty Close frame, got {:?} with {} bytes",
                frame.opcode,
                frame.payload.len()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.5.1-001",
        "Close frame with empty payload MUST be accepted",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_close_frame_code_only() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let payload = 1000u16.to_be_bytes();
        let reason = CloseReason::parse(&payload)
            .map_err(|e| format!("code-only payload should parse: {e}"))?;
        if reason.code != Some(CloseCode::Normal)
            || reason.raw_code != Some(1000)
            || reason.text.is_some()
        {
            return Err(format!(
                "code-only payload must parse to Normal/1000, got {reason:?}"
            ));
        }
        let encoded = reason.encode();
        if encoded[..] != payload[..] {
            return Err(format!(
                "code-only reason must encode to {payload:?}, got {:?}",
                &encoded[..]
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.5.1-002",
        "Close frame with status code only MUST be accepted",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_close_frame_code_and_reason() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1001u16.to_be_bytes());
        payload.extend_from_slice(b"Going away");

        let reason =
            CloseReason::parse(&payload).map_err(|e| format!("code+reason should parse: {e}"))?;
        if reason.code != Some(CloseCode::GoingAway)
            || reason.raw_code != Some(1001)
            || reason.text.as_deref() != Some("Going away")
        {
            return Err(format!(
                "code+reason must parse to GoingAway/1001/\"Going away\", got {reason:?}"
            ));
        }
        let encoded = reason.encode();
        if encoded[..] != payload[..] {
            return Err(format!(
                "code+reason must encode back to {payload:?}, got {:?}",
                &encoded[..]
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.5.1-003",
        "Close frame with status code and reason text MUST be accepted",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_close_frame_invalid_single_byte() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        match CloseReason::parse(&[0x42]) {
            Err(WsError::InvalidClosePayload) => {}
            other => {
                return Err(format!(
                    "single-byte close payload must be rejected, got {other:?}"
                ));
            }
        }

        let mut buf = BytesMut::from(&[0x88u8, 0x01, 0x42][..]);
        match FrameCodec::client().decode(&mut buf) {
            Err(WsError::InvalidClosePayload) => {}
            other => {
                return Err(format!(
                    "Close frame with a 1-byte body must fail decode, got {other:?}"
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.5.1-004",
        "Close frame with single-byte payload MUST be rejected",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_close_frame_oversized_payload() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // RFC 6455 §5.5: control frame payloads MUST be <= 125 bytes.
        // 2 bytes code + 124 bytes text = 126 bytes.
        let reason_text = "a".repeat(124);
        expect_panic("Frame::close with a 126-byte payload", || {
            Frame::close(Some(1000), Some(reason_text.as_str()))
        })?;

        let mut oversized = Vec::with_capacity(126);
        oversized.extend_from_slice(&1000u16.to_be_bytes());
        oversized.extend_from_slice(reason_text.as_bytes());
        match CloseReason::parse(&oversized) {
            Err(WsError::InvalidClosePayload) => {}
            other => {
                return Err(format!(
                    "126-byte close payload must be rejected by CloseReason::parse, got {other:?}"
                ));
            }
        }
        match FrameCodec::server().encode(raw_close_frame(oversized), &mut BytesMut::new()) {
            Err(WsError::ControlFrameTooLarge(126)) => {}
            other => {
                return Err(format!(
                    "wire encoder must refuse a 126-byte Close payload, got {other:?}"
                ));
            }
        }

        // The CloseReason send path must never emit an oversized payload.
        let frame = no_panic("CloseReason::to_frame with an over-long reason", || {
            CloseReason::with_text(CloseCode::Normal, reason_text.as_str()).to_frame()
        })?;
        if frame.payload.len() > 125 {
            return Err(format!(
                "CloseReason::to_frame produced a {}-byte Close payload",
                frame.payload.len()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.5.1-005",
        "Close frame payload exceeding 125 bytes MUST be rejected",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.5.1: "If an endpoint receives a Close frame and did not
/// previously send a Close frame, the endpoint MUST send a Close frame in
/// response." Driven through the production client `recv` loop.
#[allow(dead_code)]
fn test_close_frame_answered_on_live_connection() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let peer_close = no_panic("Frame::close(Some(1000), Some(\"bye\"))", || {
            Frame::close(Some(1000), Some("bye"))
        })?;
        let wire = server_wire(vec![peer_close])?;
        let (mut ws, peer) = client_receiving(&wire)?;
        let cx = Cx::for_testing();

        match recv_once(&mut ws, &cx) {
            Ok(Some(Message::Close(Some(reason)))) if reason.wire_code() == Some(1000) => {}
            other => {
                return Err(format!(
                    "peer Close(1000) must surface as Message::Close with code 1000, got {other:?}"
                ));
            }
        }
        if !ws.is_closed() {
            return Err(format!(
                "after answering the peer's Close the handshake must be complete, state {:?}",
                ws.close_state()
            ));
        }

        let sent = decode_client_frames(&drain_peer(ws, peer)?)?;
        match sent.as_slice() {
            [reply] if reply.opcode == Opcode::Close => {
                CloseReason::parse(&reply.payload)
                    .map_err(|e| format!("the Close reply must carry a valid body: {e}"))?;
                Ok(())
            }
            _ => Err(format!(
                "client must answer with exactly one Close frame, sent {:?}",
                sent.iter().map(|f| f.opcode).collect::<Vec<_>>()
            )),
        }
    });

    create_test_result(
        "RFC6455-5.5.1-CLOSE",
        "Received Close frame MUST be answered with a Close frame",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.5.1: "The application MUST NOT send any more data frames after
/// sending a Close frame." The production client must refuse, and nothing but
/// the Close frame may reach the wire.
#[allow(dead_code)]
fn test_no_data_after_close_on_live_connection() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let (mut ws, peer) = client_receiving(&[])?;
        let cx = Cx::for_testing();

        futures_lite::future::block_on(ws.send(&cx, Message::Close(None)))
            .map_err(|e| format!("sending Close must succeed: {e}"))?;
        if futures_lite::future::block_on(ws.send(&cx, Message::text("late data"))).is_ok() {
            return Err(
                "a data message was accepted for sending after the Close frame".to_string(),
            );
        }

        let sent = decode_client_frames(&drain_peer(ws, peer)?)?;
        let opcodes: Vec<Opcode> = sent.iter().map(|f| f.opcode).collect();
        if opcodes != [Opcode::Close] {
            return Err(format!(
                "only the Close frame may reach the wire, client sent {opcodes:?}"
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.5.1-NO-DATA-AFTER-CLOSE",
        "Data frames MUST NOT be sent after a Close frame",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

// ===== RFC 6455 §7.4 - Status Code Semantics Tests =====

#[allow(dead_code)]
fn test_status_code_normal_closure() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_sendable_status(CloseCode::Normal, 1000)?;
        let reason = CloseReason::new(CloseCode::Normal, None);
        if !reason.is_normal() {
            return Err("1000 must be reported as a normal closure".to_string());
        }
        if reason.is_error() {
            return Err("1000 must not be reported as an error".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.4-001",
        "Status code 1000 (Normal) semantics MUST be correct",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_going_away() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_sendable_status(CloseCode::GoingAway, 1001)?;
        let reason = CloseReason::new(CloseCode::GoingAway, Some("Server shutdown"));
        if reason.is_normal() {
            return Err("1001 must not be reported as a normal closure".to_string());
        }
        if reason.is_error() {
            return Err("1001 must not be reported as an error".to_string());
        }
        if reason.wire_code() != Some(1001) {
            return Err(format!(
                "wire_code must be 1001, got {:?}",
                reason.wire_code()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.4-002",
        "Status code 1001 (Going Away) semantics MUST be correct",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_protocol_error() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_sendable_status(CloseCode::ProtocolError, 1002)?;
        let reason = CloseReason::new(CloseCode::ProtocolError, Some("Invalid frame"));
        if !reason.is_error() {
            return Err("1002 must be reported as an error".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.4-003",
        "Status code 1002 (Protocol Error) semantics MUST be correct",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_unsupported_data() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_sendable_status(CloseCode::Unsupported, 1003)
    });

    create_test_result(
        "RFC6455-7.4-004",
        "Status code 1003 (Unsupported Data) semantics MUST be correct",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_invalid_payload() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_sendable_status(CloseCode::InvalidPayload, 1007)?;
        let reason = CloseReason::new(CloseCode::InvalidPayload, Some("Non-UTF-8 data"));
        if !reason.is_error() {
            return Err("1007 must be reported as an error".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.4-005",
        "Status code 1007 (Invalid Payload) semantics MUST be correct",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_policy_violation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_sendable_status(CloseCode::PolicyViolation, 1008)?;
        let reason = CloseReason::new(CloseCode::PolicyViolation, Some("Rate limit exceeded"));
        if !reason.is_error() {
            return Err("1008 must be reported as an error".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.4-006",
        "Status code 1008 (Policy Violation) semantics MUST be correct",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_message_too_big() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_sendable_status(CloseCode::MessageTooBig, 1009)
    });

    create_test_result(
        "RFC6455-7.4-007",
        "Status code 1009 (Message Too Big) semantics MUST be correct",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_mandatory_extension() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_sendable_status(CloseCode::MandatoryExtension, 1010)
    });

    create_test_result(
        "RFC6455-7.4-008",
        "Status code 1010 (Mandatory Extension) semantics MUST be correct",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_internal_error() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_sendable_status(CloseCode::InternalError, 1011)?;
        let reason = CloseReason::new(CloseCode::InternalError, Some("Database error"));
        if !reason.is_error() {
            return Err("1011 must be reported as an error".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.4-009",
        "Status code 1011 (Internal Error) semantics MUST be correct",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

// ===== Reserved Status Code Tests =====

#[allow(dead_code)]
fn test_status_code_reserved_never_sent() -> WsConformanceResult {
    let (result, elapsed) =
        timed_test(|| -> Result<(), String> { check_never_sent_status(CloseCode::Reserved, 1004) });

    create_test_result(
        "RFC6455-7.4-010",
        "Status code 1004 (Reserved) MUST NOT be sent in close frame",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_no_status_received_never_sent() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_never_sent_status(CloseCode::NoStatusReceived, 1005)
    });

    create_test_result(
        "RFC6455-7.4-011",
        "Status code 1005 (No Status Received) MUST NOT be sent in close frame",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_abnormal_never_sent() -> WsConformanceResult {
    let (result, elapsed) =
        timed_test(|| -> Result<(), String> { check_never_sent_status(CloseCode::Abnormal, 1006) });

    create_test_result(
        "RFC6455-7.4-012",
        "Status code 1006 (Abnormal Closure) MUST NOT be sent in close frame",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_tls_handshake_never_sent() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_never_sent_status(CloseCode::TlsHandshake, 1015)
    });

    create_test_result(
        "RFC6455-7.4-013",
        "Status code 1015 (TLS Handshake) MUST NOT be sent in close frame",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

// ===== Status Code Range Validation =====

#[allow(dead_code)]
fn test_status_code_range_validation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let valid: [u16; 11] = [
            1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 4999,
        ];
        for code in valid {
            if !CloseCode::is_valid_code(code) {
                return Err(format!("{code} must be valid for sending"));
            }
        }

        // Below range, reserved, never-sent, above range.
        let invalid: [u16; 6] = [999, 1004, 1005, 1006, 1015, 5000];
        for code in invalid {
            if CloseCode::is_valid_code(code) {
                return Err(format!("{code} must not be valid for sending"));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.4-014",
        "Status code range validation MUST follow RFC 6455 specification",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_iana_registered() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        check_sendable_status(CloseCode::ServiceRestart, 1012)?;
        check_sendable_status(CloseCode::TryAgainLater, 1013)?;
        check_sendable_status(CloseCode::BadGateway, 1014)
    });

    create_test_result(
        "RFC6455-7.4-015",
        "IANA registered status codes MUST be accepted",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_private_use() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        for code in [4000u16, 4500, 4999] {
            if !CloseCode::is_valid_code(code) {
                return Err(format!("private-use code {code} must be valid for sending"));
            }
            let parsed = CloseReason::parse(&code.to_be_bytes())
                .map_err(|e| format!("private-use code {code} must parse: {e}"))?;
            if parsed.raw_code != Some(code) {
                return Err(format!(
                    "private-use code {code} must be kept verbatim, got {:?}",
                    parsed.raw_code
                ));
            }
            let frame = no_panic(&format!("Frame::close(Some({code}), None)"), || {
                Frame::close(Some(code), None)
            })?;
            let decoded = wire_round_trip(frame)?;
            if decoded.payload[..] != code.to_be_bytes()[..] {
                return Err(format!(
                    "private-use code {code} must survive the wire, got {:?}",
                    &decoded.payload[..]
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.4-016",
        "Private use status codes (4000-4999) MUST be accepted",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_status_code_unassigned_acceptance() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        for code in [1016u16, 2000, 2999] {
            if !CloseCode::is_valid_received_code(code) {
                return Err(format!("{code} must be accepted when received"));
            }
            let parsed = CloseReason::parse(&code.to_be_bytes())
                .map_err(|e| format!("received code {code} must parse: {e}"))?;
            if parsed.raw_code != Some(code) {
                return Err(format!(
                    "received code {code} must be kept verbatim, got {:?}",
                    parsed.raw_code
                ));
            }
        }
        // But not valid for sending.
        for code in [1016u16, 2000] {
            if CloseCode::is_valid_code(code) {
                return Err(format!("{code} must not be valid for sending"));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.4-017",
        "Unassigned status codes MUST be accepted when received per §7.4.2",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

// ===== Close Handshake Protocol Tests =====

#[allow(dead_code)]
fn test_handshake_initiator_flow() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut handshake = CloseHandshake::new();
        if handshake.state() != CloseState::Open {
            return Err(format!(
                "new handshake must be Open, got {:?}",
                handshake.state()
            ));
        }

        // 1. Initiate close.
        let close_frame = handshake
            .initiate(CloseReason::normal())
            .ok_or("initiate() from Open must return a Close frame to send")?;
        if close_frame.opcode != Opcode::Close {
            return Err(format!(
                "initiate() must return a Close frame, got {:?}",
                close_frame.opcode
            ));
        }
        if close_frame.payload[..] != 1000u16.to_be_bytes()[..] {
            return Err(format!(
                "initiate(normal) must carry code 1000, got {:?}",
                &close_frame.payload[..]
            ));
        }
        if handshake.state() != CloseState::CloseSent {
            return Err(format!(
                "after initiate() state must be CloseSent, got {:?}",
                handshake.state()
            ));
        }

        // 2. Receive the peer's Close response: handshake complete, nothing to send.
        let peer_response = no_panic("Frame::close(Some(1000), None)", || {
            Frame::close(Some(1000), None)
        })?;
        match handshake.receive_close(&peer_response) {
            Ok(None) => {}
            other => {
                return Err(format!(
                    "peer's Close reply must complete the handshake without a further frame, got {other:?}"
                ));
            }
        }
        if handshake.state() != CloseState::Closed || !handshake.is_closed() {
            return Err(format!(
                "handshake must be Closed, got {:?}",
                handshake.state()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.1.2-001",
        "Close handshake initiator flow MUST follow RFC 6455 protocol",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_handshake_receiver_flow() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut handshake = CloseHandshake::new();

        // 1. Receive the peer's Close.
        let peer_close = no_panic("Frame::close(Some(1001), Some(\"going away\"))", || {
            Frame::close(Some(1001), Some("going away"))
        })?;
        let response = match handshake.receive_close(&peer_close) {
            Ok(Some(frame)) => frame,
            other => {
                return Err(format!(
                    "peer-initiated Close must be answered with a Close frame, got {other:?}"
                ));
            }
        };
        if response.opcode != Opcode::Close {
            return Err(format!(
                "response must be a Close frame, got {:?}",
                response.opcode
            ));
        }
        if handshake.state() != CloseState::CloseReceived {
            return Err(format!(
                "state must be CloseReceived, got {:?}",
                handshake.state()
            ));
        }

        // 2. Our Close response has been sent: handshake complete.
        handshake.mark_response_sent();
        if handshake.state() != CloseState::Closed {
            return Err(format!(
                "after the response is sent the state must be Closed, got {:?}",
                handshake.state()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.1.2-002",
        "Close handshake receiver flow MUST follow RFC 6455 protocol",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_handshake_echo_status_code() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut handshake = CloseHandshake::new();

        let peer_close = no_panic(
            "Frame::close(Some(1001), Some(\"server shutdown\"))",
            || Frame::close(Some(1001), Some("server shutdown")),
        )?;
        let response = match handshake.receive_close(&peer_close) {
            Ok(Some(frame)) => frame,
            other => return Err(format!("expected a Close response, got {other:?}")),
        };

        if response.opcode != Opcode::Close {
            return Err(format!(
                "response must be a Close frame, got {:?}",
                response.opcode
            ));
        }
        if response.payload.get(..2) != Some(&1001u16.to_be_bytes()[..]) {
            return Err(format!(
                "response must echo status 1001, got payload {:?}",
                &response.payload[..]
            ));
        }

        let peer_reason = handshake
            .peer_reason()
            .ok_or("peer's close reason must be recorded")?;
        if peer_reason.wire_code() != Some(1001) {
            return Err(format!(
                "recorded peer code must be 1001, got {:?}",
                peer_reason.wire_code()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.1.6-001",
        "Close handshake MUST echo peer's status code",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_handshake_empty_close_echo() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut handshake = CloseHandshake::new();

        let peer_close = no_panic("Frame::close(None, None)", || Frame::close(None, None))?;
        let response = match handshake.receive_close(&peer_close) {
            Ok(Some(frame)) => frame,
            other => return Err(format!("expected a Close response, got {other:?}")),
        };

        if response.opcode != Opcode::Close {
            return Err(format!(
                "response must be a Close frame, got {:?}",
                response.opcode
            ));
        }
        if !response.payload.is_empty() {
            return Err(format!(
                "empty Close must be answered with an empty Close, got {:?}",
                &response.payload[..]
            ));
        }

        let empty = CloseReason::empty();
        if handshake.peer_reason() != Some(&empty) {
            return Err(format!(
                "recorded peer reason must be empty, got {:?}",
                handshake.peer_reason()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.1.6-002",
        "Empty close frame MUST be echoed as empty",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_handshake_custom_code_echo() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut handshake = CloseHandshake::new();

        let peer_close = no_panic("Frame::close(Some(4000), Some(\"custom\"))", || {
            Frame::close(Some(4000), Some("custom"))
        })?;
        let response = match handshake.receive_close(&peer_close) {
            Ok(Some(frame)) => frame,
            other => return Err(format!("expected a Close response, got {other:?}")),
        };

        if response.opcode != Opcode::Close {
            return Err(format!(
                "response must be a Close frame, got {:?}",
                response.opcode
            ));
        }
        if response.payload.get(..2) != Some(&4000u16.to_be_bytes()[..]) {
            return Err(format!(
                "response must echo custom code 4000 verbatim, got payload {:?}",
                &response.payload[..]
            ));
        }

        let peer_reason = handshake
            .peer_reason()
            .ok_or("peer's close reason must be recorded")?;
        if peer_reason.wire_code() != Some(4000) {
            return Err(format!(
                "recorded peer code must be 4000, got {:?}",
                peer_reason.wire_code()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-7.1.6-003",
        "Custom status codes MUST be echoed verbatim",
        TestCategory::ConnectionClose,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

// ===== Text Encoding and Round-trip Tests =====

#[allow(dead_code)]
fn test_close_reason_utf8_validation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let text = "Hello, \u{4e16}\u{754c}!"; // "Hello, 世界!"
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice(text.as_bytes());

        let reason =
            CloseReason::parse(&payload).map_err(|e| format!("valid UTF-8 should parse: {e}"))?;
        if reason.text.as_deref() != Some(text) {
            return Err(format!(
                "reason text must be {text:?}, got {:?}",
                reason.text
            ));
        }

        // The wire decoder validates the reason too and must accept it.
        let decoded = wire_round_trip(raw_close_frame(payload.clone()))?;
        if decoded.payload[..] != payload[..] {
            return Err("UTF-8 close reason must survive the wire unchanged".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.6-001",
        "Close reason text MUST accept valid UTF-8",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_close_frame_encode_decode_roundtrip() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let test_cases = vec![
            CloseReason::empty(),
            CloseReason::normal(),
            CloseReason::going_away(),
            CloseReason::with_text(CloseCode::Normal, "goodbye"),
            CloseReason::with_text(CloseCode::GoingAway, "Server restart"),
            CloseReason::with_text(CloseCode::ProtocolError, "Invalid frame received"),
        ];

        for original in test_cases {
            let encoded = original.encode();
            let decoded = CloseReason::parse(&encoded)
                .map_err(|e| format!("round-trip of {original:?} failed to parse: {e}"))?;
            if original.code != decoded.code
                || original.raw_code != decoded.raw_code
                || original.text != decoded.text
            {
                return Err(format!(
                    "close reason must round-trip: {original:?} became {decoded:?}"
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-ROUNDTRIP-001",
        "Close frame encoding/decoding MUST be symmetric",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
