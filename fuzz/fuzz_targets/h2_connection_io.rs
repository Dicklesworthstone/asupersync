//! Fuzz target for `asupersync::http::h2::connection::Connection`.
//!
//! Drives the connection-level HTTP/2 state machine with adversarial
//! frame sequences. Two surfaces under attack:
//!
//!   * **Wire-format**: random byte streams fed through `FrameCodec`,
//!     exercising every parser in `frame.rs` (header, length-prefix,
//!     padding, flags, stream-id, payload bounds).
//!   * **State-machine**: well-formed frames in arbitrary interleavings
//!     fed to `Connection::process_frame`, exercising HEADERS / DATA /
//!     SETTINGS / PING / RST_STREAM / GOAWAY / WINDOW_UPDATE /
//!     CONTINUATION / PRIORITY transitions including the corner cases
//!     RFC 9113 calls out (CONTINUATION not following HEADERS, DATA
//!     with stream_id=0, SETTINGS ack with payload, PING ack, GOAWAY
//!     followed by stream usage, WINDOW_UPDATE with delta=0, mid-stream
//!     RST_STREAM, PRIORITY before stream open).
//!
//! Both client and server connections are exercised — server- and
//! client-stream-id parity is one of the easier-to-break invariants.
//!
//! Crashes / panics / sanitizer hits are findings.
//!
//! ```bash
//! cargo +nightly fuzz run h2_connection_io -- -max_total_time=180
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Decoder;
use asupersync::http::h2::{
    Connection, Frame, FrameCodec, Settings,
};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{
    DataFrame, GoAwayFrame, HeadersFrame, PingFrame, RstStreamFrame, Setting, SettingsFrame,
    WindowUpdateFrame,
};
use libfuzzer_sys::fuzz_target;

/// Cap on the total wire-bytes / frame-count any single seed can drive.
/// Without this libfuzzer can spend the whole budget on one pathological
/// gigabyte seed.
const MAX_WIRE_BYTES: usize = 64 * 1024;
const MAX_FRAMES_PER_SCENARIO: usize = 64;

/// Top-level driver shape. Each variant feeds a different mix into the
/// connection state machine.
#[derive(Arbitrary, Debug)]
enum Scenario {
    /// Random wire bytes streamed through FrameCodec into Connection.
    /// Stresses the parser + the parser->process_frame plumbing.
    RawWireBytes {
        is_client: bool,
        bytes: Vec<u8>,
    },
    /// Sequence of well-formed (per individual-frame parser) frames in
    /// arbitrary order. Stresses the connection state machine, NOT the
    /// parser.
    StructuredFrameSequence {
        is_client: bool,
        ops: Vec<FuzzFrame>,
    },
    /// SETTINGS handshake variants. The connection starts in
    /// Handshaking; wrong/duplicate/early SETTINGS must be handled.
    SettingsHandshakeAdversarial {
        is_client: bool,
        first_frames: Vec<FuzzFrame>,
    },
    /// CONTINUATION-frame stream-id mismatch. RFC 9113 §6.10 says
    /// CONTINUATION must follow HEADERS/PUSH_PROMISE on the same
    /// stream and any deviation is PROTOCOL_ERROR.
    ContinuationOrderingViolation {
        is_client: bool,
        headers_stream_id: u32,
        continuation_stream_id: u32,
        intervening: Option<FuzzFrame>,
    },
    /// PING + RST_STREAM + GOAWAY rate-limit / mid-flight stress.
    /// Connection has an internal RST rate limiter — exercise its rim.
    ControlFrameBurst {
        is_client: bool,
        burst: Vec<ControlFrame>,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum FuzzFrame {
    Data {
        stream_id: u32,
        payload: Vec<u8>,
        end_stream: bool,
    },
    Headers {
        stream_id: u32,
        block: Vec<u8>,
        end_stream: bool,
        end_headers: bool,
    },
    Settings(Vec<(u16, u32)>),
    SettingsAck,
    Ping([u8; 8]),
    PingAck([u8; 8]),
    RstStream {
        stream_id: u32,
        error_code: u32,
    },
    GoAway {
        last_stream_id: u32,
        error_code: u32,
    },
    WindowUpdate {
        stream_id: u32,
        delta: u32,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum ControlFrame {
    Ping([u8; 8]),
    Rst { stream_id: u32, error_code: u32 },
    GoAway { last_stream_id: u32, error_code: u32 },
    WindowUpdate { stream_id: u32, delta: u32 },
}

fn make_connection(is_client: bool) -> Connection {
    let settings = Settings::default();
    if is_client {
        Connection::client(settings)
    } else {
        Connection::server(settings)
    }
}

/// Best-effort `ErrorCode::from_u16` shim — h2/error.rs has the discriminants
/// 0x0..=0xd; clamp to that range so we don't panic on out-of-range
/// fuzzer inputs.
fn arb_error_code(raw: u32) -> ErrorCode {
    match raw % 14 {
        0 => ErrorCode::NoError,
        1 => ErrorCode::ProtocolError,
        2 => ErrorCode::InternalError,
        3 => ErrorCode::FlowControlError,
        4 => ErrorCode::SettingsTimeout,
        5 => ErrorCode::StreamClosed,
        6 => ErrorCode::FrameSizeError,
        7 => ErrorCode::RefusedStream,
        8 => ErrorCode::Cancel,
        9 => ErrorCode::CompressionError,
        10 => ErrorCode::ConnectError,
        11 => ErrorCode::EnhanceYourCalm,
        12 => ErrorCode::InadequateSecurity,
        _ => ErrorCode::Http11Required,
    }
}

fn build_frame(ff: &FuzzFrame) -> Option<Frame> {
    match ff {
        FuzzFrame::Data { stream_id, payload, end_stream } => {
            let payload = if payload.len() > MAX_WIRE_BYTES { &payload[..MAX_WIRE_BYTES] } else { payload };
            Some(Frame::Data(DataFrame::new(
                *stream_id,
                Bytes::copy_from_slice(payload),
                *end_stream,
            )))
        }
        FuzzFrame::Headers { stream_id, block, end_stream, end_headers } => {
            let block = if block.len() > MAX_WIRE_BYTES { &block[..MAX_WIRE_BYTES] } else { block };
            Some(Frame::Headers(HeadersFrame::new(
                *stream_id,
                Bytes::copy_from_slice(block),
                *end_stream,
                *end_headers,
            )))
        }
        FuzzFrame::Settings(items) => {
            // Setting is an enum keyed by id 0x1..=0x6; unknown ids
            // map to None and are dropped (matches RFC 7540 §6.5.2).
            let take: Vec<Setting> = items
                .iter()
                .take(16)
                .filter_map(|(id, val)| Setting::from_id_value(*id, *val))
                .collect();
            Some(Frame::Settings(SettingsFrame::new(take)))
        }
        FuzzFrame::SettingsAck => Some(Frame::Settings(SettingsFrame::ack())),
        FuzzFrame::Ping(opaque) => Some(Frame::Ping(PingFrame::new(*opaque))),
        FuzzFrame::PingAck(opaque) => {
            // PingFrame uses a public `ack: bool` field; build then flip.
            let mut p = PingFrame::new(*opaque);
            p.ack = true;
            Some(Frame::Ping(p))
        }
        FuzzFrame::RstStream { stream_id, error_code } => Some(Frame::RstStream(
            RstStreamFrame::new(*stream_id, arb_error_code(*error_code)),
        )),
        FuzzFrame::GoAway { last_stream_id, error_code } => Some(Frame::GoAway(
            GoAwayFrame::new(*last_stream_id, arb_error_code(*error_code)),
        )),
        FuzzFrame::WindowUpdate { stream_id, delta } => Some(Frame::WindowUpdate(
            WindowUpdateFrame::new(*stream_id, *delta),
        )),
    }
}

fn build_control_frame(cf: &ControlFrame) -> Option<Frame> {
    match cf {
        ControlFrame::Ping(opaque) => Some(Frame::Ping(PingFrame::new(*opaque))),
        ControlFrame::Rst { stream_id, error_code } => Some(Frame::RstStream(
            RstStreamFrame::new(*stream_id, arb_error_code(*error_code)),
        )),
        ControlFrame::GoAway { last_stream_id, error_code } => Some(Frame::GoAway(
            GoAwayFrame::new(*last_stream_id, arb_error_code(*error_code)),
        )),
        ControlFrame::WindowUpdate { stream_id, delta } => {
            Some(Frame::WindowUpdate(WindowUpdateFrame::new(*stream_id, *delta)))
        }
    }
}

fn drive_frames(conn: &mut Connection, ops: &[FuzzFrame]) {
    for op in ops.iter().take(MAX_FRAMES_PER_SCENARIO) {
        if let Some(frame) = build_frame(op) {
            // process_frame is the load-bearing state-machine entry
            // point. We discard Ok/Err — the harness only cares that
            // it never panics or aborts.
            let _ = conn.process_frame(frame);
        }
    }
}

fuzz_target!(|s: Scenario| match s {
    Scenario::RawWireBytes { is_client, bytes } => {
        if bytes.len() > MAX_WIRE_BYTES {
            return;
        }
        let mut conn = make_connection(is_client);
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::from(bytes.as_slice());
        // Decode-loop: pull frames from the wire and push them into the
        // connection until the codec returns Ok(None) (need more bytes)
        // or Err (frame parse failure).
        let mut iters = 0;
        while iters < MAX_FRAMES_PER_SCENARIO {
            iters += 1;
            match codec.decode(&mut buf) {
                Ok(Some(frame)) => {
                    let _ = conn.process_frame(frame);
                }
                Ok(None) | Err(_) => break,
            }
        }
    }
    Scenario::StructuredFrameSequence { is_client, ops } => {
        let mut conn = make_connection(is_client);
        drive_frames(&mut conn, &ops);
    }
    Scenario::SettingsHandshakeAdversarial { is_client, first_frames } => {
        // Fresh Connection starts in Handshaking — feed it whatever the
        // fuzzer produced (including frames that would normally come
        // after the SETTINGS handshake). The state machine must surface
        // a clean Err(H2Error) for misordered frames, never panic.
        let mut conn = make_connection(is_client);
        drive_frames(&mut conn, &first_frames);
    }
    Scenario::ContinuationOrderingViolation { is_client, headers_stream_id, continuation_stream_id, intervening } => {
        let mut conn = make_connection(is_client);
        // First do a normal SETTINGS exchange so the connection leaves
        // Handshaking state — gives the CONTINUATION rule something to
        // bite on.
        let _ = conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())));
        // HEADERS without END_HEADERS: the connection must now expect
        // CONTINUATION on the SAME stream.
        let _ = conn.process_frame(Frame::Headers(HeadersFrame::new(
            headers_stream_id,
            Bytes::from_static(&[]),
            false,
            false,
        )));
        // Optionally inject an intervening frame (anything other than
        // a CONTINUATION on the right stream is a PROTOCOL_ERROR).
        if let Some(interv) = intervening.as_ref() {
            if let Some(frame) = build_frame(interv) {
                let _ = conn.process_frame(frame);
            }
        }
        // Now the (possibly mismatched) CONTINUATION.
        // We can't construct a ContinuationFrame directly via the
        // public surface, so emit one via SettingsAck-shaped placeholder
        // (HEADERS with END_HEADERS=true on the wrong stream still
        // exercises the "expected CONTINUATION on stream X, got HEADERS
        // on stream Y" branch).
        let _ = conn.process_frame(Frame::Headers(HeadersFrame::new(
            continuation_stream_id,
            Bytes::from_static(&[]),
            false,
            true,
        )));
    }
    Scenario::ControlFrameBurst { is_client, burst } => {
        let mut conn = make_connection(is_client);
        // Exit handshake first so the rate limiter is observable.
        let _ = conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())));
        for cf in burst.iter().take(MAX_FRAMES_PER_SCENARIO) {
            if let Some(frame) = build_control_frame(cf) {
                let _ = conn.process_frame(frame);
            }
        }
    }
});
