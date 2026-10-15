//! HTTP/2 RST_STREAM race-condition vectors (RFC 9113 §6.4).
//!
//! These tests exercise the real `Connection::process_frame` path rather than
//! only validating frame parsing. That keeps the assertions on stream state,
//! SETTINGS side effects, and duplicate-reset handling aligned with the actual
//! runtime behavior.

use asupersync::bytes::Bytes;
use asupersync::http::h2::Header;
use asupersync::http::h2::connection::{Connection, ReceivedFrame};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{DataFrame, Frame, RstStreamFrame, Setting, SettingsFrame};
use asupersync::http::h2::settings::Settings;

fn open_client_connection() -> Connection {
    let mut conn = Connection::client(Settings::client());
    conn.process_frame(Frame::Settings(SettingsFrame::new(vec![])))
        .expect("initial SETTINGS handshake should succeed");
    conn
}

fn request_headers() -> Vec<Header> {
    vec![
        Header::new(":method", "GET"),
        Header::new(":path", "/rst-race"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.com"),
    ]
}

fn open_stream(conn: &mut Connection) -> u32 {
    conn.open_stream(request_headers(), false)
        .expect("open_stream should create a valid client-initiated stream")
}

fn assert_reset(result: Option<ReceivedFrame>, stream_id: u32, error_code: ErrorCode) {
    match result {
        Some(ReceivedFrame::Reset {
            stream_id: actual_stream_id,
            error_code: actual_error_code,
        }) => {
            assert_eq!(actual_stream_id, stream_id);
            assert_eq!(actual_error_code, error_code);
        }
        other => panic!("expected Reset({stream_id}, {error_code:?}), got {other:?}"),
    }
}

fn race_settings_frame() -> Frame {
    Frame::Settings(SettingsFrame::new(vec![
        Setting::MaxConcurrentStreams(10),
        Setting::InitialWindowSize(32_768),
    ]))
}

#[test]
fn multiple_rst_stream_on_same_stream_is_idempotent() {
    let mut conn = open_client_connection();
    let stream_id = open_stream(&mut conn);

    let first = conn
        .process_frame(Frame::RstStream(RstStreamFrame::new(
            stream_id,
            ErrorCode::Cancel,
        )))
        .expect("first RST_STREAM should succeed");
    assert_reset(first, stream_id, ErrorCode::Cancel);

    let second = conn
        .process_frame(Frame::RstStream(RstStreamFrame::new(
            stream_id,
            ErrorCode::StreamClosed,
        )))
        .expect("duplicate RST_STREAM on a closed stream should stay idempotent");
    assert_reset(second, stream_id, ErrorCode::StreamClosed);

    let err = conn
        .process_frame(Frame::Data(DataFrame::new(
            stream_id,
            Bytes::from_static(b"after-reset"),
            false,
        )))
        .expect_err("DATA after duplicate RST_STREAM must stay stream-scoped");
    assert_eq!(err.code, ErrorCode::StreamClosed);
    assert_eq!(err.stream_id, Some(stream_id));
}

#[test]
fn rst_stream_and_settings_interleavings_preserve_connection_consistency() {
    let mut settings_then_rst = open_client_connection();
    let stream_id = open_stream(&mut settings_then_rst);

    settings_then_rst
        .process_frame(race_settings_frame())
        .expect("SETTINGS before RST_STREAM should succeed");
    assert_eq!(
        settings_then_rst.remote_settings().max_concurrent_streams,
        10
    );
    assert_eq!(
        settings_then_rst.remote_settings().initial_window_size,
        32_768
    );

    let reset = settings_then_rst
        .process_frame(Frame::RstStream(RstStreamFrame::new(
            stream_id,
            ErrorCode::FlowControlError,
        )))
        .expect("RST_STREAM after SETTINGS should succeed");
    assert_reset(reset, stream_id, ErrorCode::FlowControlError);
    let next_stream_id = open_stream(&mut settings_then_rst);
    assert!(next_stream_id > stream_id);

    let mut rst_then_settings = open_client_connection();
    let stream_id = open_stream(&mut rst_then_settings);

    let reset = rst_then_settings
        .process_frame(Frame::RstStream(RstStreamFrame::new(
            stream_id,
            ErrorCode::FlowControlError,
        )))
        .expect("RST_STREAM before SETTINGS should succeed");
    assert_reset(reset, stream_id, ErrorCode::FlowControlError);

    rst_then_settings
        .process_frame(race_settings_frame())
        .expect("SETTINGS after RST_STREAM should still succeed");
    assert_eq!(
        rst_then_settings.remote_settings().max_concurrent_streams,
        10
    );
    assert_eq!(
        rst_then_settings.remote_settings().initial_window_size,
        32_768
    );
    let next_stream_id = open_stream(&mut rst_then_settings);
    assert!(next_stream_id > stream_id);
}

#[test]
fn server_initiated_invalid_stream_style_reset_uses_stream_closed() {
    let mut conn = open_client_connection();
    let stream_id = open_stream(&mut conn);

    // HTTP/2 does not define an INVALID_STREAM error code. The standardized
    // server-side reset for an invalid/closed stream state is STREAM_CLOSED.
    let reset = conn
        .process_frame(Frame::RstStream(RstStreamFrame::new(
            stream_id,
            ErrorCode::StreamClosed,
        )))
        .expect("STREAM_CLOSED reset should be delivered to the stream");
    assert_reset(reset, stream_id, ErrorCode::StreamClosed);

    let err = conn
        .process_frame(Frame::Data(DataFrame::new(
            stream_id,
            Bytes::from_static(b"late-data"),
            false,
        )))
        .expect_err("stream must remain closed after STREAM_CLOSED reset");
    assert_eq!(err.code, ErrorCode::StreamClosed);
    assert_eq!(err.stream_id, Some(stream_id));
}
