#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::Header;
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{Frame, Setting, SettingsFrame};
use asupersync::http::h2::settings::Settings;
use libfuzzer_sys::fuzz_target;

const INITIAL_LIMIT: u32 = 100;
const DECREASED_LIMIT: u32 = 10;
const MAX_ACTIVE_OVER_LIMIT: u8 = 32;
const MAX_BLOCKED_ATTEMPTS: u8 = 8;
const MAX_EXISTING_OPS: u8 = 8;
const MAX_DATA_LEN: usize = 32;

#[derive(Debug, Arbitrary)]
struct MaxConcurrentStreamsDecreaseInput {
    active_over_limit: u8,
    blocked_attempts: u8,
    existing_ops: u8,
    server_role: bool,
    end_existing_data: bool,
    path_suffix: Vec<u8>,
    authority_suffix: Vec<u8>,
    data_seed: Vec<u8>,
}

fuzz_target!(|input: MaxConcurrentStreamsDecreaseInput| {
    let active_streams =
        DECREASED_LIMIT + 1 + u32::from(input.active_over_limit.min(MAX_ACTIVE_OVER_LIMIT));
    assert!(active_streams > DECREASED_LIMIT);
    assert!(active_streams < INITIAL_LIMIT);

    let mut conn = if input.server_role {
        Connection::server(Settings::server())
    } else {
        Connection::client(Settings::client())
    };

    apply_peer_max_concurrent_streams(&mut conn, INITIAL_LIMIT);
    assert_eq!(conn.remote_settings().max_concurrent_streams, INITIAL_LIMIT);
    drain_pending_frames(&mut conn);

    let headers = headers_for_role(&input);
    let mut opened = Vec::with_capacity(active_streams as usize);
    for _ in 0..active_streams {
        let stream_id = conn
            .open_stream(headers.clone(), false)
            .expect("stream creation below the original SETTINGS limit must succeed");
        opened.push(stream_id);
    }
    drain_pending_frames(&mut conn);

    assert_eq!(
        active_count(&conn, &opened),
        active_streams,
        "opened streams must count as active before the SETTINGS decrease"
    );

    apply_peer_max_concurrent_streams(&mut conn, DECREASED_LIMIT);
    assert_eq!(
        conn.remote_settings().max_concurrent_streams,
        DECREASED_LIMIT
    );
    drain_pending_frames(&mut conn);

    assert_eq!(
        active_count(&conn, &opened),
        active_streams,
        "decreasing SETTINGS_MAX_CONCURRENT_STREAMS must not evict existing active streams"
    );

    let next_stream_id = next_stream_id_after(&opened, input.server_role);
    let blocked_attempts = input.blocked_attempts.min(MAX_BLOCKED_ATTEMPTS).max(1);
    for _ in 0..blocked_attempts {
        let err = conn
            .open_stream(headers.clone(), false)
            .expect_err("new streams must be rejected while active streams exceed the new limit");
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(
            err.message.contains("max concurrent streams exceeded"),
            "wrong stream refusal reason after decrease: {}",
            err.message
        );
        assert!(
            conn.stream(next_stream_id).is_none(),
            "rejected stream creation must not allocate or burn the next stream ID"
        );
    }

    let existing_ops = usize::from(input.existing_ops.min(MAX_EXISTING_OPS).max(1));
    for op_index in 0..existing_ops {
        let stream_id = opened[op_index % opened.len()];
        let payload = payload_for(&input.data_seed, op_index);
        conn.send_data(stream_id, Bytes::from(payload), input.end_existing_data)
            .expect("existing streams must continue after the peer decreases the limit");

        let stream = conn
            .stream(stream_id)
            .expect("existing stream must remain in the store after DATA");
        assert!(
            stream.state().is_active(),
            "existing stream became inactive after allowed DATA on decreased limit"
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

fn active_count(conn: &Connection, stream_ids: &[u32]) -> u32 {
    stream_ids
        .iter()
        .filter(|stream_id| {
            conn.stream(**stream_id)
                .is_some_and(|stream| stream.state().is_active())
        })
        .count() as u32
}

fn headers_for_role(input: &MaxConcurrentStreamsDecreaseInput) -> Vec<Header> {
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

fn payload_for(seed: &[u8], op_index: usize) -> Vec<u8> {
    let len = seed.len().min(MAX_DATA_LEN).max(1);
    let mut payload = Vec::with_capacity(len);
    for index in 0..len {
        payload.push(
            seed.get(index)
                .copied()
                .unwrap_or(0)
                .wrapping_add(op_index as u8),
        );
    }
    payload
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
    fn decrease_rejects_new_streams_but_keeps_existing_active() {
        libfuzzer_sys::test_input_wrap(MaxConcurrentStreamsDecreaseInput {
            active_over_limit: 4,
            blocked_attempts: 2,
            existing_ops: 3,
            server_role: false,
            end_existing_data: false,
            path_suffix: b"decrease".to_vec(),
            authority_suffix: b"host".to_vec(),
            data_seed: b"body".to_vec(),
        });
    }
}
