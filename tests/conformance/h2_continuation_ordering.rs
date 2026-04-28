#![allow(warnings)]
#![allow(clippy::all)]
//! HTTP/2 CONTINUATION ordering conformance tests (RFC 9113 §6.10).
//!
//! These vectors exercise the connection's real frame-sequencing state:
//! once a HEADERS or PUSH_PROMISE frame starts a fragmented header block,
//! the next frame on the connection must be CONTINUATION for the same stream.

use asupersync::bytes::Bytes;
use asupersync::http::h2::{
    connection::Connection,
    error::ErrorCode,
    frame::{
        ContinuationFrame, DataFrame, Frame, FrameHeader, FrameType, HeadersFrame,
        PushPromiseFrame, SettingsFrame, parse_frame,
    },
    hpack::Header,
    settings::Settings,
};

fn handshake(conn: &mut Connection) {
    conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("initial SETTINGS must be accepted");
}

fn request_headers() -> Vec<Header> {
    vec![
        Header::new(":method", "GET"),
        Header::new(":path", "/continuation"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.com"),
    ]
}

#[test]
fn headers_then_intervening_frame_must_reject() {
    let mut conn = Connection::server(Settings::default());
    handshake(&mut conn);

    conn.process_frame(Frame::Headers(HeadersFrame::new(
        1,
        Bytes::new(),
        false,
        false,
    )))
    .expect("fragmented HEADERS should begin a continuation sequence");

    assert!(conn.is_awaiting_continuation());
    assert_eq!(conn.continuation_stream_id(), Some(1));

    let err = conn
        .process_frame(Frame::Data(DataFrame::new(
            1,
            Bytes::from_static(b"x"),
            false,
        )))
        .expect_err("DATA between HEADERS and CONTINUATION must be rejected");

    assert_eq!(err.code, ErrorCode::ProtocolError);
    assert!(
        err.message.contains("expected CONTINUATION frame"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn push_promise_then_intervening_frame_must_reject() {
    let mut settings = Settings::client();
    settings.enable_push = true;

    let mut conn = Connection::client(settings);
    handshake(&mut conn);

    let stream_id = conn
        .open_stream(request_headers(), false)
        .expect("client should be able to open request stream");

    conn.process_frame(Frame::PushPromise(PushPromiseFrame {
        stream_id,
        promised_stream_id: 2,
        header_block: Bytes::new(),
        end_headers: false,
    }))
    .expect("fragmented PUSH_PROMISE should begin a continuation sequence");

    assert!(conn.is_awaiting_continuation());
    assert_eq!(conn.continuation_stream_id(), Some(stream_id));

    let err = conn
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect_err("SETTINGS between PUSH_PROMISE and CONTINUATION must be rejected");

    assert_eq!(err.code, ErrorCode::ProtocolError);
    assert!(
        err.message.contains("expected CONTINUATION frame"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn continuation_on_stream_zero_is_rejected() {
    let header = FrameHeader {
        length: 0,
        frame_type: FrameType::Continuation as u8,
        flags: 0x4,
        stream_id: 0,
    };

    let err = parse_frame(&header, Bytes::new())
        .expect_err("CONTINUATION on stream 0 must be rejected at parse time");

    assert_eq!(err.code, ErrorCode::ProtocolError);
    assert!(
        err.message.contains("CONTINUATION frame with stream ID 0"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn continuation_before_any_headers_is_rejected() {
    let mut conn = Connection::server(Settings::default());
    handshake(&mut conn);

    let err = conn
        .process_frame(Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: Bytes::new(),
            end_headers: true,
        }))
        .expect_err("orphaned CONTINUATION must be rejected");

    assert_eq!(err.code, ErrorCode::ProtocolError);
    assert!(
        err.message.contains("CONTINUATION for unknown stream"),
        "unexpected error: {err:?}"
    );
}
