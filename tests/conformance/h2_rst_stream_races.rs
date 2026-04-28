//! HTTP/2 RST_STREAM race-condition vectors (RFC 9113 §6.4).
//!
//! These tests exercise the real `Connection::process_frame` path rather than
//! only validating frame parsing. That keeps the assertions on stream state,
//! SETTINGS side effects, and duplicate-reset handling aligned with the actual
//! runtime behavior.

use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::{Connection, ReceivedFrame};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{
    DataFrame, Frame, HeadersFrame, RstStreamFrame, Setting, SettingsFrame,
};
use asupersync::http::h2::settings::Settings;

fn open_server_connection() -> Connection {
    let mut conn = Connection::server(Settings::default());
    conn.process_frame(Frame::Settings(SettingsFrame::new(vec![])))
        .expect("initial SETTINGS handshake should succeed");
    conn
}

fn open_stream(conn: &mut Connection, stream_id: u32) {
    let received = conn
        .process_frame(Frame::Headers(HeadersFrame::new(
            stream_id,
            Bytes::new(),
            false,
            true,
        )))
        .expect("HEADERS should open the test stream");
    assert!(
        matches!(received, Some(ReceivedFrame::Headers { stream_id: id, .. }) if id == stream_id),
        "expected HEADERS for stream {stream_id}, got {received:?}"
    );
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
    let mut conn = open_server_connection();
    open_stream(&mut conn, 1);

    let first = conn
        .process_frame(Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel)))
        .expect("first RST_STREAM should succeed");
    assert_reset(first, 1, ErrorCode::Cancel);

    let second = conn
        .process_frame(Frame::RstStream(RstStreamFrame::new(
            1,
            ErrorCode::StreamClosed,
        )))
        .expect("duplicate RST_STREAM on a closed stream should stay idempotent");
    assert_reset(second, 1, ErrorCode::StreamClosed);

    let err = conn
        .process_frame(Frame::Data(DataFrame::new(
            1,
            Bytes::from_static(b"after-reset"),
            false,
        )))
        .expect_err("DATA after duplicate RST_STREAM must stay stream-scoped");
    assert_eq!(err.code, ErrorCode::StreamClosed);
    assert_eq!(err.stream_id, Some(1));
}

#[test]
fn rst_stream_and_settings_interleavings_preserve_connection_consistency() {
    let mut settings_then_rst = open_server_connection();
    open_stream(&mut settings_then_rst, 1);

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
            1,
            ErrorCode::FlowControlError,
        )))
        .expect("RST_STREAM after SETTINGS should succeed");
    assert_reset(reset, 1, ErrorCode::FlowControlError);
    open_stream(&mut settings_then_rst, 3);

    let mut rst_then_settings = open_server_connection();
    open_stream(&mut rst_then_settings, 1);

    let reset = rst_then_settings
        .process_frame(Frame::RstStream(RstStreamFrame::new(
            1,
            ErrorCode::FlowControlError,
        )))
        .expect("RST_STREAM before SETTINGS should succeed");
    assert_reset(reset, 1, ErrorCode::FlowControlError);

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
    open_stream(&mut rst_then_settings, 3);
}

#[test]
fn server_initiated_invalid_stream_style_reset_uses_stream_closed() {
    let mut conn = open_server_connection();
    open_stream(&mut conn, 1);

    // HTTP/2 does not define an INVALID_STREAM error code. The standardized
    // server-side reset for an invalid/closed stream state is STREAM_CLOSED.
    let reset = conn
        .process_frame(Frame::RstStream(RstStreamFrame::new(
            1,
            ErrorCode::StreamClosed,
        )))
        .expect("STREAM_CLOSED reset should be delivered to the stream");
    assert_reset(reset, 1, ErrorCode::StreamClosed);

    let err = conn
        .process_frame(Frame::Data(DataFrame::new(
            1,
            Bytes::from_static(b"late-data"),
            false,
        )))
        .expect_err("stream must remain closed after STREAM_CLOSED reset");
    assert_eq!(err.code, ErrorCode::StreamClosed);
    assert_eq!(err.stream_id, Some(1));
}
