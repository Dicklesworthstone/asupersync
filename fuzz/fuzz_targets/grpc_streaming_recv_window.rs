#![no_main]

//! Structure-aware fuzz target for gRPC streaming receive flow-control.
//!
//! The client side models HTTP/2 send windows and only transmits DATA when both
//! connection and stream credit are available. The server side is the real
//! HTTP/2 `Connection` receive path. Delayed WINDOW_UPDATE delivery must stall
//! the sender, not drop bytes that already entered the HTTP/2 layer.

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::codec::{GrpcCodec, GrpcMessage};
use asupersync::http::h2::{
    Connection,
    connection::DEFAULT_CONNECTION_WINDOW_SIZE,
    frame::{DataFrame, Frame, HeadersFrame, SettingsFrame, WindowUpdateFrame},
    hpack::{Encoder as HpackEncoder, Header},
    settings,
};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;

const STREAM_ID: u32 = 1;
const MAX_MESSAGES: usize = 48;
const MAX_MESSAGE_LEN: usize = 4096;
const MAX_CHUNK_LEN: usize = 16 * 1024;
const MAX_STEPS: usize = 384;

#[derive(Arbitrary, Debug)]
struct Scenario {
    messages: Vec<Vec<u8>>,
    chunk_plan: Vec<u16>,
    update_delay_steps: u8,
}

#[derive(Debug, Clone, Copy)]
struct DelayedUpdate {
    due_step: usize,
    stream_id: u32,
    increment: u32,
}

fuzz_target!(|mut scenario: Scenario| {
    scenario.messages.truncate(MAX_MESSAGES);
    if scenario.messages.is_empty() {
        scenario.messages.push(Vec::new());
    }
    scenario.chunk_plan.truncate(MAX_STEPS);

    let messages = normalize_messages(scenario.messages);
    let wire = encode_grpc_stream(&messages);
    if wire.is_empty() {
        return;
    }

    let mut server = open_server_stream();
    let mut delayed_updates = VecDeque::new();
    let mut client_conn_window = DEFAULT_CONNECTION_WINDOW_SIZE;
    let mut client_stream_window =
        i32::try_from(settings::DEFAULT_INITIAL_WINDOW_SIZE).expect("default stream window fits");
    let update_delay = usize::from(scenario.update_delay_steps % 9);
    let mut cursor = 0usize;
    let mut received_wire = BytesMut::new();
    let mut stalled_steps = 0usize;
    let mut data_frames_accepted = 0usize;

    for step in 0..MAX_STEPS {
        apply_due_updates(
            step,
            &mut delayed_updates,
            &mut client_conn_window,
            &mut client_stream_window,
        );

        if cursor >= wire.len() {
            break;
        }

        let remaining = wire.len() - cursor;
        let planned = scenario
            .chunk_plan
            .get(step % scenario.chunk_plan.len().max(1))
            .copied()
            .unwrap_or(8192);
        let chunk_len = normalize_chunk_len(planned, remaining);
        let available = client_conn_window.min(client_stream_window);

        if available < i32::try_from(chunk_len).expect("chunk length fits i32") {
            stalled_steps = stalled_steps.saturating_add(1);
            continue;
        }

        let chunk = wire.slice(cursor..cursor + chunk_len);
        let result = server
            .process_frame(Frame::Data(DataFrame::new(STREAM_ID, chunk.clone(), false)))
            .expect("in-window DATA must be accepted by server receive path");

        match result {
            Some(asupersync::http::h2::connection::ReceivedFrame::Data {
                stream_id,
                data,
                end_stream,
            }) => {
                assert_eq!(stream_id, STREAM_ID);
                assert!(!end_stream);
                assert_eq!(
                    data, chunk,
                    "server receive path must surface exactly the DATA bytes sent"
                );
                received_wire.extend_from_slice(&data);
                data_frames_accepted = data_frames_accepted.saturating_add(1);
            }
            other => panic!("DATA frame did not surface as DATA: {other:?}"),
        }

        let chunk_i32 = i32::try_from(chunk_len).expect("chunk length fits i32");
        client_conn_window -= chunk_i32;
        client_stream_window -= chunk_i32;
        cursor += chunk_len;

        schedule_window_updates(&mut server, step, update_delay, &mut delayed_updates);
    }

    for step in MAX_STEPS..MAX_STEPS + 16 {
        apply_due_updates(
            step,
            &mut delayed_updates,
            &mut client_conn_window,
            &mut client_stream_window,
        );
    }

    assert_eq!(
        &received_wire[..],
        &wire[..cursor],
        "accepted gRPC DATA bytes must be delivered without truncation or reordering"
    );
    assert_decoded_prefix_matches(&messages, &received_wire, cursor == wire.len());

    if wire.len()
        > usize::try_from(DEFAULT_CONNECTION_WINDOW_SIZE).expect("default window positive")
        && update_delay > 0
    {
        assert!(
            stalled_steps > 0,
            "over-window sender with delayed WINDOW_UPDATE delivery should stall"
        );
    }
    assert!(
        data_frames_accepted > 0,
        "scenario must accept at least one DATA frame"
    );
});

fn normalize_messages(messages: Vec<Vec<u8>>) -> Vec<Bytes> {
    messages
        .into_iter()
        .map(|mut msg| {
            msg.truncate(MAX_MESSAGE_LEN);
            Bytes::from(msg)
        })
        .collect()
}

fn encode_grpc_stream(messages: &[Bytes]) -> Bytes {
    let mut codec = GrpcCodec::new();
    let mut wire = BytesMut::new();
    for payload in messages {
        codec
            .encode(GrpcMessage::new(payload.clone()), &mut wire)
            .expect("bounded fuzz message should encode");
    }
    wire.freeze()
}

fn open_server_stream() -> Connection {
    let mut server = Connection::server(settings::Settings::default());
    server
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("initial SETTINGS should be accepted");
    drain_non_update_frames(&mut server);

    let mut encoder = HpackEncoder::new();
    let mut header_block = BytesMut::new();
    encoder.encode(
        &[
            Header::new(":method", "POST"),
            Header::new(":scheme", "http"),
            Header::new(":path", "/fuzz.Stream/RecvWindow"),
            Header::new(":authority", "fuzz.local"),
            Header::new("content-type", "application/grpc"),
            Header::new("te", "trailers"),
        ],
        &mut header_block,
    );

    server
        .process_frame(Frame::Headers(HeadersFrame::new(
            STREAM_ID,
            header_block.freeze(),
            false,
            true,
        )))
        .expect("request HEADERS should open stream");
    drain_non_update_frames(&mut server);
    server
}

fn normalize_chunk_len(planned: u16, remaining: usize) -> usize {
    let planned = usize::from(planned).saturating_add(1);
    planned.min(MAX_CHUNK_LEN).min(remaining)
}

fn schedule_window_updates(
    server: &mut Connection,
    step: usize,
    delay: usize,
    delayed_updates: &mut VecDeque<DelayedUpdate>,
) {
    while let Some(frame) = server.next_frame() {
        if let Frame::WindowUpdate(update) = frame {
            assert!(
                update.increment > 0,
                "WINDOW_UPDATE increment must be nonzero"
            );
            delayed_updates.push_back(DelayedUpdate {
                due_step: step.saturating_add(delay),
                stream_id: update.stream_id,
                increment: update.increment,
            });
        }
    }
}

fn drain_non_update_frames(server: &mut Connection) {
    while let Some(frame) = server.next_frame() {
        assert!(
            !matches!(frame, Frame::WindowUpdate(_)),
            "setup should not emit WINDOW_UPDATE"
        );
    }
}

fn apply_due_updates(
    step: usize,
    delayed_updates: &mut VecDeque<DelayedUpdate>,
    client_conn_window: &mut i32,
    client_stream_window: &mut i32,
) {
    while delayed_updates
        .front()
        .is_some_and(|update| update.due_step <= step)
    {
        let update = delayed_updates.pop_front().expect("front checked above");
        apply_update(update, client_conn_window, client_stream_window);
    }
}

fn apply_update(
    update: DelayedUpdate,
    client_conn_window: &mut i32,
    client_stream_window: &mut i32,
) {
    let increment = i32::try_from(update.increment).expect("WINDOW_UPDATE increment fits i32");
    if update.stream_id == 0 {
        *client_conn_window = client_conn_window.saturating_add(increment);
    } else if update.stream_id == STREAM_ID {
        *client_stream_window = client_stream_window.saturating_add(increment);
    }
}

fn assert_decoded_prefix_matches(expected: &[Bytes], received_wire: &BytesMut, complete: bool) {
    let mut decoder = GrpcCodec::new();
    let mut buf = received_wire.clone();
    let mut decoded = Vec::new();

    while let Some(message) = decoder
        .decode(&mut buf)
        .expect("server-delivered bytes should remain valid gRPC framing")
    {
        decoded.push(message.data);
    }

    assert!(
        decoded.len() <= expected.len(),
        "decoded more gRPC messages than the client encoded"
    );
    for (idx, actual) in decoded.iter().enumerate() {
        assert_eq!(
            actual, &expected[idx],
            "decoded gRPC message {idx} differs from sent message"
        );
    }

    if complete {
        assert_eq!(
            decoded.len(),
            expected.len(),
            "complete DATA stream must decode every sent gRPC message"
        );
        assert!(
            buf.is_empty(),
            "complete DATA stream must not leave trailing undecoded bytes"
        );
    }
}
