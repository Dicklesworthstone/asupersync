#![allow(warnings)]
#![allow(clippy::all)]
//! Control frame conformance tests (RFC 6455 §5.5).
//!
//! The 125-byte limit and FIN rule are ported from the orphaned legacy
//! close-frame harness (ids RFC6455-5.5-001/002) and extended to Ping/Pong and
//! to the production wire encoder. Ping/Pong behaviour is driven through the
//! production client `recv` loop over an in-memory transport (see
//! `fragmentation_tests` for the shared helpers).

use super::fragmentation_tests::{
    client_receiving, decode_client_frames, drain_peer, recv_once, server_wire,
};
use super::*;
use asupersync::Cx;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::net::websocket::{Frame, FrameCodec, Message, Opcode, WsError};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Run all control frame conformance tests.
#[allow(dead_code)]
pub fn run_control_frame_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();

    results.push(test_control_frame_125_byte_limit());
    results.push(test_control_frame_fin_bit_required());
    results.push(test_ping_pong_frames());
    results.push(test_unsolicited_pong_ignored());

    results
}

/// Runs `f`; a panic becomes `Err` so a regression is reported as a failed
/// verdict instead of aborting the suite.
fn no_panic<T>(what: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|_| format!("{what}: unexpected panic"))
}

/// Requires `f` to refuse its input by panicking (the documented behaviour of
/// the `Frame::ping`/`pong`/`close` constructors for oversized payloads).
fn expect_panic<T>(what: &str, f: impl FnOnce() -> T) -> Result<(), String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Err(_) => Ok(()),
        Ok(_) => Err(format!(
            "{what}: the call must refuse the input (panic), but it returned a value"
        )),
    }
}

/// A control frame built field by field, bypassing the checking constructors.
fn raw_control_frame(opcode: Opcode, fin: bool, payload: Vec<u8>) -> Frame {
    Frame {
        fin,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode,
        masked: false,
        mask_key: None,
        payload: Bytes::from(payload),
    }
}

/// A Close body of `len` bytes: code 1000 followed by ASCII reason text.
fn close_body(len: usize) -> Vec<u8> {
    let mut body = 1000u16.to_be_bytes().to_vec();
    body.resize(len, b'a');
    body
}

/// RFC 6455 §5.5: "All control frames MUST have a payload length of 125 bytes
/// or less".
#[allow(dead_code)]
fn test_control_frame_125_byte_limit() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Legacy case: 2 bytes code + 123 bytes reason = 125 bytes is accepted,
        // one byte more is refused.
        let max_reason = "a".repeat(123);
        let frame = no_panic("Frame::close with a 125-byte payload", || {
            Frame::close(Some(1000), Some(max_reason.as_str()))
        })?;
        if frame.payload.len() != 125 {
            return Err(format!(
                "maximal Close frame must carry 125 bytes, got {}",
                frame.payload.len()
            ));
        }
        let over_reason = "a".repeat(124);
        expect_panic("Frame::close with a 126-byte payload", || {
            Frame::close(Some(1000), Some(over_reason.as_str()))
        })?;

        // Same boundary for the Ping/Pong constructors.
        no_panic("Frame::ping with 125 bytes", || {
            Frame::ping(Bytes::from(vec![0xA5u8; 125]))
        })?;
        no_panic("Frame::pong with 125 bytes", || {
            Frame::pong(Bytes::from(vec![0xA5u8; 125]))
        })?;
        expect_panic("Frame::ping with 126 bytes", || {
            Frame::ping(Bytes::from(vec![0xA5u8; 126]))
        })?;
        expect_panic("Frame::pong with 126 bytes", || {
            Frame::pong(Bytes::from(vec![0xA5u8; 126]))
        })?;

        // The wire encoder must refuse hand-built oversized control frames and
        // carry a maximal one intact.
        for opcode in [Opcode::Ping, Opcode::Pong, Opcode::Close] {
            let body = |len: usize| {
                if opcode == Opcode::Close {
                    close_body(len)
                } else {
                    vec![0x5Au8; len]
                }
            };

            let oversized = raw_control_frame(opcode, true, body(126));
            match FrameCodec::server().encode(oversized, &mut BytesMut::new()) {
                Err(WsError::ControlFrameTooLarge(126)) => {}
                other => {
                    return Err(format!(
                        "encoder must refuse a 126-byte {opcode:?}, got {other:?}"
                    ));
                }
            }

            let mut buf = BytesMut::new();
            FrameCodec::server()
                .encode(raw_control_frame(opcode, true, body(125)), &mut buf)
                .map_err(|e| format!("125-byte {opcode:?} must encode: {e}"))?;
            let decoded = FrameCodec::client()
                .decode(&mut buf)
                .map_err(|e| format!("125-byte {opcode:?} must decode: {e}"))?
                .ok_or_else(|| format!("125-byte {opcode:?}: decoder returned no frame"))?;
            if decoded.opcode != opcode || decoded.payload.len() != 125 {
                return Err(format!(
                    "125-byte {opcode:?} must survive the wire, got {:?} with {} bytes",
                    decoded.opcode,
                    decoded.payload.len()
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.5-001",
        "Control frames MUST NOT exceed 125-byte payload limit",
        TestCategory::ControlFrames,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.5: "All control frames ... MUST NOT be fragmented."
#[allow(dead_code)]
fn test_control_frame_fin_bit_required() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Legacy case, extended to all three constructors.
        let constructed = [
            no_panic("Frame::close(Some(1000), None)", || {
                Frame::close(Some(1000), None)
            })?,
            no_panic("Frame::ping", || Frame::ping(Bytes::from_static(b"p")))?,
            no_panic("Frame::pong", || Frame::pong(Bytes::from_static(b"p")))?,
        ];
        for frame in &constructed {
            if !frame.fin {
                return Err(format!(
                    "{:?} frame must have the FIN bit set",
                    frame.opcode
                ));
            }
        }

        // The wire encoder must refuse to emit a fragmented control frame.
        for opcode in [Opcode::Ping, Opcode::Pong, Opcode::Close] {
            let fragmented = raw_control_frame(opcode, false, Vec::new());
            match FrameCodec::server().encode(fragmented, &mut BytesMut::new()) {
                Err(WsError::FragmentedControlFrame) => {}
                other => {
                    return Err(format!(
                        "encoder must refuse {opcode:?} with FIN=0, got {other:?}"
                    ));
                }
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.5-002",
        "Control frames MUST have FIN bit set",
        TestCategory::ControlFrames,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.5.2: "Upon receipt of a Ping frame, an endpoint MUST send a Pong
/// frame in response"; §5.5.3: the Pong "must have identical Application
/// data" as the Ping. Two Pings (one with binary data, one at the 125-byte
/// limit) must each be answered, in order, with an identical Pong.
#[allow(dead_code)]
fn test_ping_pong_frames() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let first: &'static [u8] = b"app-data\x00\x7f\xff";
        let second: Vec<u8> = (0u8..125).collect();

        let wire = server_wire(vec![
            no_panic("Frame::ping(first)", || {
                Frame::ping(Bytes::from_static(first))
            })?,
            no_panic("Frame::ping(second)", || {
                Frame::ping(Bytes::from(second.clone()))
            })?,
            Frame::text("after-pings"),
        ])?;
        let (mut ws, peer) = client_receiving(&wire)?;
        let cx = Cx::for_testing();

        // Pings are answered inside recv; the next data message is "after-pings".
        let mut delivered = None;
        for _ in 0..4 {
            match recv_once(&mut ws, &cx) {
                Ok(Some(Message::Ping(_))) | Ok(Some(Message::Pong(_))) => continue,
                other => {
                    delivered = Some(other);
                    break;
                }
            }
        }
        match delivered {
            Some(Ok(Some(Message::Text(text)))) if text == "after-pings" => {}
            other => {
                return Err(format!(
                    "the text message after the Pings must be delivered, got {other:?}"
                ));
            }
        }

        let sent = decode_client_frames(&drain_peer(ws, peer)?)?;
        let pongs: Vec<&Frame> = sent.iter().filter(|f| f.opcode == Opcode::Pong).collect();
        if pongs.len() != 2 {
            return Err(format!(
                "each Ping must be answered by a Pong; client sent {:?}",
                sent.iter().map(|f| f.opcode).collect::<Vec<_>>()
            ));
        }
        if &pongs[0].payload[..] != first {
            return Err(format!(
                "first Pong must echo {first:?}, got {:?}",
                &pongs[0].payload[..]
            ));
        }
        if pongs[1].payload[..] != second[..] {
            return Err(format!(
                "second Pong must echo the 125-byte Ping data, got {} bytes {:?}",
                pongs[1].payload.len(),
                &pongs[1].payload[..]
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.5.2-PING-PONG",
        "Ping MUST be answered by a Pong carrying identical application data",
        TestCategory::ControlFrames,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.5.3: "A Pong frame MAY be sent unsolicited ... A response to an
/// unsolicited Pong frame is not expected." The receiver must keep the
/// connection open and must not answer it.
#[allow(dead_code)]
fn test_unsolicited_pong_ignored() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let wire = server_wire(vec![
            no_panic("Frame::pong", || {
                Frame::pong(Bytes::from_static(b"heartbeat"))
            })?,
            Frame::text("after-pong"),
        ])?;
        let (mut ws, peer) = client_receiving(&wire)?;
        let cx = Cx::for_testing();

        let mut delivered = None;
        for _ in 0..3 {
            match recv_once(&mut ws, &cx) {
                Ok(Some(Message::Pong(_))) => continue,
                other => {
                    delivered = Some(other);
                    break;
                }
            }
        }
        match delivered {
            Some(Ok(Some(Message::Text(text)))) if text == "after-pong" => {}
            other => {
                return Err(format!(
                    "an unsolicited Pong must not disturb the connection; expected \"after-pong\", got {other:?}"
                ));
            }
        }

        let sent = decode_client_frames(&drain_peer(ws, peer)?)?;
        if !sent.is_empty() {
            return Err(format!(
                "an unsolicited Pong must not be answered; client sent {:?}",
                sent.iter().map(|f| f.opcode).collect::<Vec<_>>()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.5.3-UNSOLICITED-PONG",
        "Unsolicited Pong is tolerated and not answered",
        TestCategory::ControlFrames,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}
