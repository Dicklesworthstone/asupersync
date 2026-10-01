#![allow(warnings)]
#![allow(clippy::all)]
//! Message fragmentation conformance tests (RFC 6455 §5.4, §5.6).
//!
//! Two levels are exercised, both against production code:
//!
//! - Codec level: `FrameCodec` decodes the RFC 6455 §5.7 fragmented-message
//!   vectors into frames with the right FIN bit and opcode, including a
//!   control frame between fragments.
//! - Message level: reassembly lives in the production `MessageAssembler`,
//!   which is crate-private. It is reached through the public
//!   `WebSocket::from_upgraded` + `WebSocket::recv` path over the production
//!   in-memory `VirtualTcpStream` transport (no OS socket, no mock). The peer
//!   writes its frames and then shuts down its write side before `recv` is
//!   polled, so every `recv` terminates: a regression shows up as a wrong
//!   result or end-of-stream, never as a hang.
//!
//! The `pub(super)` live-connection helpers below are shared with the
//! control-frame, close, error-handling and extension modules.

use super::*;
use asupersync::Cx;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::net::websocket::{
    Frame, FrameCodec, Message, Opcode, WebSocket, WebSocketConfig, WsError,
};
use std::net::SocketAddr;

/// Run all fragmentation conformance tests.
#[allow(dead_code)]
pub fn run_fragmentation_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();

    results.push(test_message_fragmentation());
    results.push(test_control_frame_between_fragments_codec());
    results.push(test_fragmented_message_reassembly());
    results.push(test_control_frame_between_fragments_live());
    results.push(test_orphan_continuation_rejected());
    results.push(test_interleaved_data_frame_rejected());
    results.push(test_utf8_split_across_fragments());

    results
}

// ===== Shared live-connection helpers =====

/// A production client connection over an in-memory transport.
pub(super) type LiveClient = WebSocket<VirtualTcpStream>;

/// Builds a data frame with explicit FIN bit and opcode (unmasked; the
/// encoder applies masking according to its role).
pub(super) fn data_frame(opcode: Opcode, fin: bool, payload: &'static [u8]) -> Frame {
    Frame {
        fin,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode,
        masked: false,
        mask_key: None,
        payload: Bytes::from_static(payload),
    }
}

/// Encodes `frames` as a server sends them (unmasked), using the production
/// server-role encoder.
pub(super) fn server_wire(frames: Vec<Frame>) -> Result<Vec<u8>, String> {
    let mut codec = FrameCodec::server();
    let mut buf = BytesMut::new();
    for frame in frames {
        let opcode = frame.opcode;
        codec
            .encode(frame, &mut buf)
            .map_err(|e| format!("server-side encode of {opcode:?} failed: {e}"))?;
    }
    Ok(buf.to_vec())
}

/// A connected pair of production `VirtualTcpStream`s: (client end, peer end).
pub(super) fn virtual_pair() -> Result<(VirtualTcpStream, VirtualTcpStream), String> {
    let client_addr: SocketAddr = "127.0.0.1:50000"
        .parse()
        .map_err(|e| format!("client address parse failed: {e}"))?;
    let server_addr: SocketAddr = "127.0.0.1:8080"
        .parse()
        .map_err(|e| format!("server address parse failed: {e}"))?;
    Ok(VirtualTcpStream::pair(client_addr, server_addr))
}

/// Writes `wire` from the peer end, then shuts down the peer's write side so
/// the client reads end-of-stream after the last byte.
pub(super) fn deliver_and_shutdown(peer: &mut VirtualTcpStream, wire: &[u8]) -> Result<(), String> {
    futures_lite::future::block_on(async {
        AsyncWriteExt::write_all(&mut *peer, wire).await?;
        AsyncWriteExt::shutdown(&mut *peer).await?;
        Ok::<(), std::io::Error>(())
    })
    .map_err(|e| format!("in-memory peer failed to deliver {} bytes: {e}", wire.len()))
}

/// A production client `WebSocket` (heartbeat disabled) whose peer has
/// already sent `wire` and closed its write side. Keep the returned peer
/// alive (bind it to a named variable) while the client may still write:
/// dropping it makes the client's writes fail with a broken pipe.
pub(super) fn client_receiving(wire: &[u8]) -> Result<(LiveClient, VirtualTcpStream), String> {
    let (client_io, mut peer) = virtual_pair()?;
    deliver_and_shutdown(&mut peer, wire)?;
    let config = WebSocketConfig::new().ping_interval(None);
    Ok((WebSocket::from_upgraded(client_io, config), peer))
}

/// Polls one production `WebSocket::recv` to completion.
pub(super) fn recv_once(ws: &mut LiveClient, cx: &Cx) -> Result<Option<Message>, WsError> {
    futures_lite::future::block_on(ws.recv(cx))
}

/// Drops the client (closing its write side) and returns every byte it sent.
pub(super) fn drain_peer(ws: LiveClient, mut peer: VirtualTcpStream) -> Result<Vec<u8>, String> {
    drop(ws);
    let mut sent = Vec::new();
    futures_lite::future::block_on(AsyncReadExt::read_to_end(&mut peer, &mut sent))
        .map_err(|e| format!("reading the bytes the client sent failed: {e}"))?;
    Ok(sent)
}

/// Decodes client-sent bytes with the production server-role decoder, which
/// also requires every client frame to be masked.
pub(super) fn decode_client_frames(wire: &[u8]) -> Result<Vec<Frame>, String> {
    let mut codec = FrameCodec::server();
    let mut buf = BytesMut::from(wire);
    let mut frames = Vec::new();
    while let Some(frame) = codec
        .decode(&mut buf)
        .map_err(|e| format!("client-sent bytes are not valid masked frames: {e}"))?
    {
        frames.push(frame);
    }
    if !buf.is_empty() {
        return Err(format!(
            "{} trailing bytes after the last complete client frame",
            buf.len()
        ));
    }
    Ok(frames)
}

/// Decodes the next frame or reports why there is none.
fn next_frame(codec: &mut FrameCodec, buf: &mut BytesMut, label: &str) -> Result<Frame, String> {
    codec
        .decode(buf)
        .map_err(|e| format!("{label}: decode failed: {e}"))?
        .ok_or_else(|| format!("{label}: decoder returned no frame"))
}

/// Checks one decoded frame's FIN bit, opcode and payload.
fn expect_frame(
    frame: &Frame,
    label: &str,
    fin: bool,
    opcode: Opcode,
    payload: &[u8],
) -> Result<(), String> {
    if frame.fin != fin {
        return Err(format!(
            "{label}: expected FIN={fin}, got FIN={}",
            frame.fin
        ));
    }
    if frame.opcode != opcode {
        return Err(format!(
            "{label}: expected {opcode:?}, got {:?}",
            frame.opcode
        ));
    }
    if &frame.payload[..] != payload {
        return Err(format!(
            "{label}: expected payload {payload:?}, got {:?}",
            &frame.payload[..]
        ));
    }
    Ok(())
}

// ===== Codec level =====

/// RFC 6455 §5.4/§5.7: a fragmented text message (first frame FIN=0 with the
/// Text opcode, final frame FIN=1 with the Continuation opcode) decodes as two
/// frames. Bytes are the RFC 6455 §5.7 "fragmented unmasked text message".
#[allow(dead_code)]
fn test_message_fragmentation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::from(&[0x01u8, 0x03, 0x48, 0x65, 0x6c, 0x80, 0x02, 0x6c, 0x6f][..]);

        let first = next_frame(&mut codec, &mut buf, "first fragment")?;
        expect_frame(&first, "first fragment", false, Opcode::Text, b"Hel")?;

        let last = next_frame(&mut codec, &mut buf, "final fragment")?;
        expect_frame(&last, "final fragment", true, Opcode::Continuation, b"lo")?;

        if !buf.is_empty() {
            return Err(format!("{} bytes left undecoded", buf.len()));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.4-FRAGMENTATION",
        "Fragmented message decodes as Text FIN=0 followed by Continuation FIN=1",
        TestCategory::Fragmentation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.4: control frames MAY be injected in the middle of a
/// fragmented message; the codec must decode the interleaved Ping.
#[allow(dead_code)]
fn test_control_frame_between_fragments_codec() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = FrameCodec::client();
        let mut buf = BytesMut::from(
            &[
                0x01u8, 0x03, 0x48, 0x65, 0x6c, // Text, FIN=0, "Hel"
                0x89, 0x01, 0x70, // Ping, FIN=1, "p"
                0x80, 0x02, 0x6c, 0x6f, // Continuation, FIN=1, "lo"
            ][..],
        );

        let first = next_frame(&mut codec, &mut buf, "first fragment")?;
        expect_frame(&first, "first fragment", false, Opcode::Text, b"Hel")?;

        let ping = next_frame(&mut codec, &mut buf, "interleaved ping")?;
        expect_frame(&ping, "interleaved ping", true, Opcode::Ping, b"p")?;

        let last = next_frame(&mut codec, &mut buf, "final fragment")?;
        expect_frame(&last, "final fragment", true, Opcode::Continuation, b"lo")?;

        if !buf.is_empty() {
            return Err(format!("{} bytes left undecoded", buf.len()));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.4-CONTROL-INTERLEAVE-CODEC",
        "Control frame between data fragments decodes in order",
        TestCategory::Fragmentation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

// ===== Message level (production assembler via WebSocket::recv) =====

/// RFC 6455 §5.4: the fragments of a message are reassembled in order into
/// one message (text and binary).
#[allow(dead_code)]
fn test_fragmented_message_reassembly() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let wire = server_wire(vec![
            data_frame(Opcode::Text, false, b"hel"),
            data_frame(Opcode::Continuation, false, b"l"),
            data_frame(Opcode::Continuation, true, b"o"),
            data_frame(Opcode::Binary, false, &[0x01, 0x02]),
            data_frame(Opcode::Continuation, true, &[0x03]),
        ])?;
        let (mut ws, _peer) = client_receiving(&wire)?;
        let cx = Cx::for_testing();

        match recv_once(&mut ws, &cx) {
            Ok(Some(Message::Text(text))) if text == "hello" => {}
            other => {
                return Err(format!(
                    "three text fragments must reassemble to \"hello\", got {other:?}"
                ));
            }
        }
        match recv_once(&mut ws, &cx) {
            Ok(Some(Message::Binary(data))) if &data[..] == &[0x01u8, 0x02, 0x03][..] => {}
            other => {
                return Err(format!(
                    "two binary fragments must reassemble to [1, 2, 3], got {other:?}"
                ));
            }
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.4-REASSEMBLY",
        "Fragmented text and binary messages are reassembled in order",
        TestCategory::Fragmentation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.4: "An endpoint MUST be capable of handling control frames in
/// the middle of a fragmented message." The message must still reassemble and
/// the Ping must still be answered.
#[allow(dead_code)]
fn test_control_frame_between_fragments_live() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let wire = server_wire(vec![
            data_frame(Opcode::Text, false, b"hel"),
            Frame::ping(Bytes::from_static(b"mid")),
            data_frame(Opcode::Continuation, true, b"lo"),
        ])?;
        let (mut ws, peer) = client_receiving(&wire)?;
        let cx = Cx::for_testing();

        match recv_once(&mut ws, &cx) {
            Ok(Some(Message::Text(text))) if text == "hello" => {}
            other => {
                return Err(format!(
                    "message with a Ping between its fragments must reassemble to \"hello\", got {other:?}"
                ));
            }
        }

        let sent = decode_client_frames(&drain_peer(ws, peer)?)?;
        let pongs: Vec<&Frame> = sent.iter().filter(|f| f.opcode == Opcode::Pong).collect();
        if pongs.len() != 1 || &pongs[0].payload[..] != b"mid" {
            return Err(format!(
                "the interleaved Ping(\"mid\") must be answered by one Pong(\"mid\"); client sent {:?}",
                sent.iter()
                    .map(|f| (f.opcode, f.payload.to_vec()))
                    .collect::<Vec<_>>()
            ));
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.4-CONTROL-INTERLEAVE",
        "Endpoint MUST handle control frames in the middle of a fragmented message",
        TestCategory::Fragmentation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.4: a Continuation frame is only valid after a non-final data
/// frame; one with no message in progress MUST fail the connection.
#[allow(dead_code)]
fn test_orphan_continuation_rejected() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let wire = server_wire(vec![data_frame(Opcode::Continuation, true, b"oops")])?;
        let (mut ws, _peer) = client_receiving(&wire)?;
        let cx = Cx::for_testing();

        match recv_once(&mut ws, &cx) {
            Err(WsError::ProtocolViolation(_)) => {}
            other => {
                return Err(format!(
                    "Continuation with no message in progress must fail with a protocol violation, got {other:?}"
                ));
            }
        }
        if ws.is_open() {
            return Err("connection must be failed (not open) after the violation".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.4-ORPHAN-CONTINUATION",
        "Continuation frame without a preceding fragment MUST be rejected",
        TestCategory::Fragmentation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.4: "the fragments of one message MUST NOT be interleaved
/// between the fragments of another message unless an extension has been
/// negotiated". A new Binary frame while a Text message is in progress must
/// fail the connection.
#[allow(dead_code)]
fn test_interleaved_data_frame_rejected() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let wire = server_wire(vec![
            data_frame(Opcode::Text, false, b"part1"),
            data_frame(Opcode::Binary, true, b"wrong"),
        ])?;
        let (mut ws, _peer) = client_receiving(&wire)?;
        let cx = Cx::for_testing();

        match recv_once(&mut ws, &cx) {
            Err(WsError::ProtocolViolation(_)) => {}
            other => {
                return Err(format!(
                    "new data frame inside a fragmented message must fail with a protocol violation, got {other:?}"
                ));
            }
        }
        if ws.is_open() {
            return Err("connection must be failed (not open) after the violation".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-5.4-NO-INTERLEAVED-MESSAGES",
        "New data frame in the middle of a fragmented message MUST be rejected",
        TestCategory::Fragmentation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 6455 §5.6: "a particular text frame might include a partial UTF-8
/// sequence; however, the whole message MUST contain valid UTF-8." A code
/// point split across fragments must be accepted.
#[allow(dead_code)]
fn test_utf8_split_across_fragments() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // U+20AC EURO SIGN is E2 82 AC; split after the first byte.
        let wire = server_wire(vec![
            data_frame(Opcode::Text, false, &[0xE2]),
            data_frame(Opcode::Continuation, true, &[0x82, 0xAC]),
        ])?;
        let (mut ws, _peer) = client_receiving(&wire)?;
        let cx = Cx::for_testing();

        match recv_once(&mut ws, &cx) {
            Ok(Some(Message::Text(text))) if text == "\u{20AC}" => Ok(()),
            other => Err(format!(
                "a UTF-8 sequence split across fragments must be accepted as \"\u{20AC}\", got {other:?}"
            )),
        }
    });

    create_test_result(
        "RFC6455-5.6-FRAGMENTED-UTF8",
        "UTF-8 sequence split across fragments MUST be accepted",
        TestCategory::Fragmentation,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
