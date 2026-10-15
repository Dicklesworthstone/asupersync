//! HTTP/2 RFC 9113 must-reject conformance vectors.
//!
//! This file covers the specific h2spec-style scenarios where the
//! protocol REQUIRES the receiver to fail the connection (or stream)
//! with a PROTOCOL_ERROR. Each test asserts that asupersync's
//! `Connection::process_frame` returns an error for the cited vector,
//! never accepts it silently.
//!
//! Coverage map:
//!   - (a) HEADERS without END_HEADERS, then a non-CONTINUATION frame
//!         (RFC 9113 §6.2 / §4.3): see `headers_then_data_must_reject`
//!   - (b) PUSH_PROMISE on stream id 0 (RFC 9113 §6.6): see
//!         `push_promise_on_stream_zero_must_reject`
//!   - (c) WINDOW_UPDATE with increment 0 on connection (§6.9.1):
//!         already covered by tests/conformance/h2_window_update.rs
//!   - (d) RST_STREAM on idle stream (§5.1): see
//!         `rst_stream_on_idle_must_reject`
//!   - (e) GOAWAY with last_stream_id newer than highest received
//!         (§6.8): already covered by
//!         tests/conformance_h2_goaway_graceful_shutdown.rs
//!         (`receive_multiple_goaway_decreasing_only`)

use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{
    DataFrame, Frame, GoAwayFrame, HeadersFrame, PushPromiseFrame, RstStreamFrame, SettingsFrame,
    WindowUpdateFrame,
};
use asupersync::http::h2::settings::Settings;

/// Bring a freshly-constructed Connection out of Handshaking by
/// processing the peer's initial empty SETTINGS frame.
fn handshake(conn: &mut Connection) {
    let _ = conn
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("initial SETTINGS must be accepted");
}

/// (a) RFC 9113 §6.2 + §4.3: After a HEADERS frame WITHOUT END_HEADERS,
/// the next frame on the connection MUST be CONTINUATION on the same
/// stream. Any other frame type — even on a different stream — MUST
/// be treated as PROTOCOL_ERROR.
///
/// Asupersync code path: process_frame at src/http/h2/connection.rs:589
/// rejects with H2Error::protocol("expected CONTINUATION frame") when
/// `continuation_stream_id` is set and the next frame is not Continuation.
#[test]
fn headers_then_data_must_reject() {
    let mut conn = Connection::server(Settings::default());
    handshake(&mut conn);

    // HEADERS on stream 1, end_stream=false, end_headers=false (so we
    // expect CONTINUATION next).
    let headers = Frame::Headers(HeadersFrame::new(
        1,
        Bytes::new(),
        /* end_stream */ false,
        /* end_headers */ false,
    ));
    // Stream-state validation may fire first (depending on whether the
    // empty-payload header block decodes). Either way, the goal of this
    // test is: feeding a DATA frame between HEADERS-without-END_HEADERS
    // and the expected CONTINUATION must NOT silently succeed.
    let _ = conn.process_frame(headers);

    // Now interleave a DATA frame — must be rejected even if the prior
    // HEADERS was accepted (continuation_stream_id is set if it was).
    let data = Frame::Data(DataFrame::new(1, Bytes::from_static(b"x"), false));
    let result = conn.process_frame(data);
    assert!(
        result.is_err(),
        "DATA between HEADERS-without-END_HEADERS and CONTINUATION must be rejected; got {:?}",
        result.as_ref().map(|_| "Ok")
    );
}

/// (b) RFC 9113 §6.6: PUSH_PROMISE frames MUST NOT be sent on stream 0.
/// A receiver MUST treat a PUSH_PROMISE on stream 0 as a connection
/// error (PROTOCOL_ERROR).
///
/// Asupersync code path: process_push_promise at
/// src/http/h2/connection.rs:1150 currently rejects via the
/// "PUSH_PROMISE on unknown stream" branch (since stream 0 has no
/// Stream object). The exact error message differs from h2spec's
/// preferred phrasing, but the rejection itself satisfies RFC §6.6.
#[test]
fn push_promise_on_stream_zero_must_reject() {
    // Use a CLIENT connection — only clients receive PUSH_PROMISE.
    let mut conn = Connection::client(Settings::default());
    handshake(&mut conn);

    let push = Frame::PushPromise(PushPromiseFrame {
        stream_id: 0,
        promised_stream_id: 2,
        header_block: Bytes::new(),
        end_headers: true,
    });
    let result = conn.process_frame(push);
    assert!(
        result.is_err(),
        "PUSH_PROMISE on stream 0 must be rejected; got {:?}",
        result.as_ref().map(|_| "Ok")
    );
}

/// (d) RFC 9113 §5.1: Receiving RST_STREAM on a stream in the "idle"
/// state MUST be treated as a connection error (PROTOCOL_ERROR).
///
/// Asupersync code path: process_rst_stream at
/// src/http/h2/connection.rs:1024 line 1032-1034 explicitly rejects
/// idle streams with H2Error::protocol("RST_STREAM received on idle
/// stream").
#[test]
fn rst_stream_on_idle_must_reject() {
    let mut conn = Connection::server(Settings::default());
    handshake(&mut conn);

    // Stream 7 has never been opened — it's in idle state. RFC requires
    // PROTOCOL_ERROR here, not silent stream creation + reset.
    let rst = Frame::RstStream(RstStreamFrame::new(7, ErrorCode::Cancel));
    let result = conn.process_frame(rst);
    assert!(
        result.is_err(),
        "RST_STREAM on idle stream 7 must be rejected; got {:?}",
        result.as_ref().map(|_| "Ok")
    );
}

/// Cross-reference test for (c): WINDOW_UPDATE increment 0 on the
/// connection (stream 0) must be PROTOCOL_ERROR per RFC 9113 §6.9.1.
/// This duplicates the assertion already in
/// tests/conformance/h2_window_update.rs to give h2spec-style coverage
/// in one place.
#[test]
fn window_update_zero_increment_on_connection_must_reject() {
    let mut conn = Connection::server(Settings::default());
    handshake(&mut conn);

    let zero = Frame::WindowUpdate(WindowUpdateFrame::new(
        /* stream */ 0, /* incr */ 0,
    ));
    let result = conn.process_frame(zero);
    assert!(
        result.is_err(),
        "WINDOW_UPDATE with increment 0 on connection must be rejected; got {:?}",
        result.as_ref().map(|_| "Ok")
    );
}

/// Cross-reference test for (e): GOAWAY with last_stream_id GREATER
/// than the previously-received last_stream_id must NOT widen the
/// effective bound. Per RFC 9113 §6.8, the sender MUST NOT increase
/// the value; asupersync's receiver behavior is to clamp via
/// `previous.min(frame.last_stream_id)` (connection.rs:1245). This
/// duplicates an existing assertion in
/// tests/conformance_h2_goaway_graceful_shutdown.rs.
#[test]
fn goaway_increase_in_last_stream_id_must_not_widen_bound() {
    let mut conn = Connection::client(Settings::default());
    handshake(&mut conn);

    // First GOAWAY with last_stream_id=5 — accepted.
    let g1 = conn
        .process_frame(Frame::GoAway(GoAwayFrame::new(5, ErrorCode::NoError)))
        .expect("first GOAWAY parses")
        .expect("first GOAWAY emits a result");
    match g1 {
        asupersync::http::h2::connection::ReceivedFrame::GoAway { last_stream_id, .. } => {
            assert_eq!(last_stream_id, 5);
        }
        _ => panic!("expected GoAway result"),
    }

    // Second GOAWAY with last_stream_id=10 — must NOT widen the bound.
    // Asupersync clamps to min(prev, new) = 5.
    let g2 = conn
        .process_frame(Frame::GoAway(GoAwayFrame::new(10, ErrorCode::NoError)))
        .expect("second GOAWAY parses")
        .expect("second GOAWAY emits a result");
    match g2 {
        asupersync::http::h2::connection::ReceivedFrame::GoAway { last_stream_id, .. } => {
            assert_eq!(
                last_stream_id, 5,
                "second GOAWAY must not widen the effective last_stream_id beyond 5; got {}",
                last_stream_id
            );
        }
        _ => panic!("expected GoAway result"),
    }
}
