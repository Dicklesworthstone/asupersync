//! Regression tests for HTTP/2 flow-control resume latency.

use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::frame::{Frame, SettingsFrame, WindowUpdateFrame};
use asupersync::http::h2::hpack::Header;
use asupersync::http::h2::settings::Settings;

fn open_connection() -> Connection {
    let mut conn = Connection::client(Settings::default());
    conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("peer SETTINGS should open the connection");

    match conn.next_frame() {
        Some(Frame::Settings(frame)) if frame.ack => {}
        other => panic!("expected SETTINGS ack, got {other:?}"),
    }

    conn
}

fn open_post_stream(conn: &mut Connection, path: &str) -> u32 {
    let headers = vec![
        Header::new(":method", "POST"),
        Header::new(":path", path),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.com"),
    ];
    let stream_id = conn
        .open_stream(headers, false)
        .expect("POST stream should open");

    match conn.next_frame() {
        Some(Frame::Headers(frame)) if frame.stream_id == stream_id => {}
        other => panic!("expected request HEADERS for stream {stream_id}, got {other:?}"),
    }

    stream_id
}

fn drain_data_until_blocked(conn: &mut Connection) -> usize {
    let mut sent = 0;

    loop {
        match conn.next_frame() {
            Some(Frame::Data(frame)) => sent += frame.data.len(),
            None => return sent,
            Some(other) => panic!("expected DATA or flow-control block, got {other:?}"),
        }
    }
}

#[test]
fn connection_window_update_resumes_blocked_data_immediately() {
    let mut conn = open_connection();
    let stream_id = open_post_stream(&mut conn, "/data");

    conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(
        stream_id, 65_535,
    )))
    .expect("stream WINDOW_UPDATE should leave stream window available");
    conn.send_data(stream_id, Bytes::from(vec![0xAB; 70_000]), false)
        .expect("DATA should queue");

    assert_eq!(drain_data_until_blocked(&mut conn), 65_535);
    assert_eq!(
        conn.send_window(),
        0,
        "connection window should be exhausted"
    );

    conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(0, 1_024)))
        .expect("connection WINDOW_UPDATE should succeed");

    match conn.next_frame() {
        Some(Frame::Data(frame)) => {
            assert_eq!(frame.stream_id, stream_id);
            assert_eq!(frame.data.len(), 1_024);
            assert!(!frame.end_stream);
        }
        other => panic!("expected immediate DATA after connection WINDOW_UPDATE, got {other:?}"),
    }
}

#[test]
fn stream_window_update_resumes_blocked_data_immediately() {
    let mut conn = open_connection();
    let stream_id = open_post_stream(&mut conn, "/stream-data");

    conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(0, 65_535)))
        .expect("connection WINDOW_UPDATE should leave connection window available");
    conn.send_data(stream_id, Bytes::from(vec![0xCD; 70_000]), false)
        .expect("DATA should queue");

    assert_eq!(drain_data_until_blocked(&mut conn), 65_535);
    assert_eq!(
        conn.stream(stream_id)
            .expect("stream should remain available")
            .send_window(),
        0,
        "stream window should be exhausted"
    );

    conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(
        stream_id, 1_024,
    )))
    .expect("stream WINDOW_UPDATE should succeed");

    match conn.next_frame() {
        Some(Frame::Data(frame)) => {
            assert_eq!(frame.stream_id, stream_id);
            assert_eq!(frame.data.len(), 1_024);
            assert!(!frame.end_stream);
        }
        other => panic!("expected immediate DATA after stream WINDOW_UPDATE, got {other:?}"),
    }
}
