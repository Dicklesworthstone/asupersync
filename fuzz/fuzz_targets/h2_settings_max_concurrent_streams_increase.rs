#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h2::Header;
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{Frame, Setting, SettingsFrame};
use asupersync::http::h2::settings::Settings;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct MaxConcurrentStreamsIncreaseInput {
    initial_limit: u8,
    blocked_attempts: u8,
    server_role: bool,
    end_stream: bool,
    path_suffix: Vec<u8>,
    authority_suffix: Vec<u8>,
}

fuzz_target!(|input: MaxConcurrentStreamsIncreaseInput| {
    let initial_limit = u32::from((input.initial_limit % 16) + 1);
    let increased_limit = initial_limit * 2;
    let blocked_attempts = u32::from((input.blocked_attempts % initial_limit as u8) + 1);

    let mut conn = if input.server_role {
        Connection::server(Settings::server())
    } else {
        Connection::client(Settings::client())
    };

    apply_peer_max_concurrent_streams(&mut conn, initial_limit);
    assert_eq!(conn.remote_settings().max_concurrent_streams, initial_limit);
    drain_pending_frames(&mut conn);

    let headers = headers_for_role(&input);
    let mut opened = Vec::new();
    for _ in 0..initial_limit {
        let stream_id = conn
            .open_stream(headers.clone(), input.end_stream)
            .expect("opening streams below SETTINGS_MAX_CONCURRENT_STREAMS must succeed");
        opened.push(stream_id);
    }

    let next_stream_id = next_stream_id_after(&opened, input.server_role);
    for _ in 0..blocked_attempts {
        let err = conn
            .open_stream(headers.clone(), input.end_stream)
            .expect_err("stream creation at SETTINGS_MAX_CONCURRENT_STREAMS must block");
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(
            err.message.contains("max concurrent streams exceeded"),
            "wrong refusal reason: {}",
            err.message
        );
    }
    assert!(
        conn.stream(next_stream_id).is_none(),
        "blocked stream creation must not allocate or burn the next stream ID"
    );

    apply_peer_max_concurrent_streams(&mut conn, increased_limit);
    assert_eq!(
        conn.remote_settings().max_concurrent_streams,
        increased_limit
    );
    drain_pending_frames(&mut conn);

    for attempt in 0..blocked_attempts {
        let expected_id = next_stream_id + (attempt * 2);
        let stream_id = conn
            .open_stream(headers.clone(), input.end_stream)
            .expect("stream creation blocked at N must resume after SETTINGS increases to 2N");
        assert_eq!(
            stream_id, expected_id,
            "resumed stream creation should reuse the first unallocated stream ID"
        );
        assert!(
            conn.stream(stream_id).is_some(),
            "resumed stream must be present in the connection stream store"
        );
    }
});

fn apply_peer_max_concurrent_streams(conn: &mut Connection, limit: u32) {
    conn.process_frame(Frame::Settings(SettingsFrame::new(vec![
        Setting::MaxConcurrentStreams(limit),
    ])))
    .expect("valid SETTINGS_MAX_CONCURRENT_STREAMS update must be accepted");
}

fn drain_pending_frames(conn: &mut Connection) {
    while conn.next_frame().is_some() {}
}

fn headers_for_role(input: &MaxConcurrentStreamsIncreaseInput) -> Vec<Header> {
    if input.server_role {
        vec![Header::new(":status", "200")]
    } else {
        vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":path", bounded_ascii("/", &input.path_suffix)),
            Header::new(
                ":authority",
                bounded_ascii("example.test", &input.authority_suffix),
            ),
        ]
    }
}

fn bounded_ascii(prefix: &str, bytes: &[u8]) -> String {
    let mut out = String::from(prefix);
    for byte in bytes.iter().take(16) {
        let ch = match byte % 38 {
            0..=25 => char::from(b'a' + (byte % 26)),
            26..=35 => char::from(b'0' + (byte % 10)),
            36 => '-',
            _ => '.',
        };
        out.push(ch);
    }
    out
}

fn next_stream_id_after(opened: &[u32], server_role: bool) -> u32 {
    opened
        .last()
        .map_or(if server_role { 2 } else { 1 }, |stream_id| stream_id + 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_creations_resume_after_limit_doubles() {
        libfuzzer_sys::test_input_wrap(MaxConcurrentStreamsIncreaseInput {
            initial_limit: 2,
            blocked_attempts: 1,
            server_role: false,
            end_stream: false,
            path_suffix: b"resume".to_vec(),
            authority_suffix: b"host".to_vec(),
        });
    }
}
