#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::{
    Connection, ErrorCode, Frame, Settings,
};
use asupersync::http::h2::frame::{HeadersFrame, SettingsFrame, WindowUpdateFrame};
use libfuzzer_sys::fuzz_target;

const ACTIVE_STREAM_ID: u32 = 1;
const IDLE_STREAM_ID: u32 = 3;
const MISSING_STREAM_ID: u32 = 9;
const MAX_INBOUND_OPS: usize = 24;
const MAX_OUTBOUND_OPS: usize = 24;

#[derive(Arbitrary, Debug, Clone)]
struct H2ConnectionWindowUpdateFuzzInput {
    inbound_ops: Vec<InboundWindowUpdate>,
    outbound_ops: Vec<OutboundWindowUpdate>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum InboundTarget {
    Connection,
    ActiveStream,
    IdleStream,
}

#[derive(Arbitrary, Debug, Clone)]
struct InboundWindowUpdate {
    target: InboundTarget,
    increment: u32,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum OutboundTarget {
    Connection,
    ActiveStream,
    MissingStream,
}

#[derive(Arbitrary, Debug, Clone)]
struct OutboundWindowUpdate {
    target: OutboundTarget,
    increment: u32,
}

fn setup_connection() -> Connection {
    let mut connection = Connection::server(Settings::default());

    let _ = connection.process_frame(Frame::Settings(SettingsFrame::new(vec![])));
    drain_all_frames(&mut connection);

    let headers = Frame::Headers(HeadersFrame::new(
        ACTIVE_STREAM_ID,
        Bytes::new(),
        false,
        true,
    ));
    connection
        .process_frame(headers)
        .expect("opening active test stream should succeed");
    drain_all_frames(&mut connection);

    assert!(
        connection.stream(ACTIVE_STREAM_ID).is_some(),
        "active test stream must exist"
    );
    assert!(
        connection.stream(IDLE_STREAM_ID).is_none(),
        "idle test stream must stay unopened"
    );

    connection
}

fn drain_all_frames(connection: &mut Connection) {
    while connection.next_frame().is_some() {}
}

fn collect_window_update_frames(connection: &mut Connection) -> Vec<(u32, u32)> {
    let mut frames = Vec::new();
    while let Some(frame) = connection.next_frame() {
        match frame {
            Frame::WindowUpdate(update) => frames.push((update.stream_id, update.increment)),
            other => panic!("unexpected queued frame while draining WINDOW_UPDATEs: {other:?}"),
        }
    }
    frames
}

fn apply_inbound_update(connection: &mut Connection, op: &InboundWindowUpdate) {
    match op.target {
        InboundTarget::Connection => {
            let before = connection.send_window();
            let result = connection.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(
                0,
                op.increment,
            )));

            if op.increment == 0 {
                let err = result.expect_err("zero increment on connection must fail");
                assert_eq!(err.code, ErrorCode::ProtocolError);
                assert!(err.stream_id.is_none());
                assert_eq!(connection.send_window(), before);
                return;
            }

            if op.increment > i32::MAX as u32
                || i64::from(before) + i64::from(op.increment) > i64::from(i32::MAX)
            {
                let err = result.expect_err("overflowing connection update must fail");
                assert_eq!(err.code, ErrorCode::FlowControlError);
                assert!(err.stream_id.is_none());
                assert_eq!(connection.send_window(), before);
                return;
            }

            let received = result.expect("valid connection update should succeed");
            assert!(received.is_none());
            assert_eq!(connection.send_window(), before + op.increment as i32);
        }
        InboundTarget::ActiveStream => {
            let before = connection
                .stream(ACTIVE_STREAM_ID)
                .expect("active stream must exist")
                .send_window();

            let result = connection.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(
                ACTIVE_STREAM_ID,
                op.increment,
            )));

            if op.increment == 0 {
                let err = result.expect_err("zero increment on active stream must fail");
                assert_eq!(err.code, ErrorCode::ProtocolError);
                assert_eq!(err.stream_id, Some(ACTIVE_STREAM_ID));
                assert_eq!(
                    connection
                        .stream(ACTIVE_STREAM_ID)
                        .expect("active stream must still exist")
                        .send_window(),
                    before
                );
                return;
            }

            if op.increment > i32::MAX as u32 {
                let err = result.expect_err("oversized stream increment must fail");
                assert_eq!(err.code, ErrorCode::FlowControlError);
                assert!(err.stream_id.is_none());
                assert_eq!(
                    connection
                        .stream(ACTIVE_STREAM_ID)
                        .expect("active stream must still exist")
                        .send_window(),
                    before
                );
                return;
            }

            if i64::from(before) + i64::from(op.increment) > i64::from(i32::MAX) {
                let err = result.expect_err("overflowing stream update must fail");
                assert_eq!(err.code, ErrorCode::FlowControlError);
                assert_eq!(err.stream_id, Some(ACTIVE_STREAM_ID));
                assert_eq!(
                    connection
                        .stream(ACTIVE_STREAM_ID)
                        .expect("active stream must still exist")
                        .send_window(),
                    before
                );
                return;
            }

            let received = result.expect("valid active-stream update should succeed");
            assert!(received.is_none());
            assert_eq!(
                connection
                    .stream(ACTIVE_STREAM_ID)
                    .expect("active stream must still exist")
                    .send_window(),
                before + op.increment as i32
            );
        }
        InboundTarget::IdleStream => {
            let before = connection.send_window();
            let result = connection.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(
                IDLE_STREAM_ID,
                op.increment,
            )));

            if op.increment == 0 {
                let err = result.expect_err("zero increment on idle stream must fail");
                assert_eq!(err.code, ErrorCode::ProtocolError);
                assert_eq!(err.stream_id, Some(IDLE_STREAM_ID));
            } else if op.increment > i32::MAX as u32 {
                let err = result.expect_err("oversized idle-stream increment must fail");
                assert_eq!(err.code, ErrorCode::FlowControlError);
                assert!(err.stream_id.is_none());
            } else {
                let err = result.expect_err("idle-stream WINDOW_UPDATE must fail");
                assert_eq!(err.code, ErrorCode::ProtocolError);
                assert!(err.stream_id.is_none());
            }

            assert_eq!(
                connection.send_window(),
                before,
                "idle-stream WINDOW_UPDATE must not mutate the connection send window"
            );
        }
    }
}

fn apply_outbound_update(
    connection: &mut Connection,
    op: &OutboundWindowUpdate,
    expected_frames: &mut Vec<(u32, u32)>,
) {
    match op.target {
        OutboundTarget::Connection => {
            let before = connection.recv_window();
            let result = connection.send_connection_window_update(op.increment);

            if op.increment == 0 {
                let err = result.expect_err("zero outbound connection increment must fail");
                assert_eq!(err.code, ErrorCode::FlowControlError);
                assert!(err.stream_id.is_none());
                assert_eq!(connection.recv_window(), before);
                return;
            }

            if op.increment > i32::MAX as u32
                || i64::from(before) + i64::from(op.increment) > i64::from(i32::MAX)
            {
                let err = result.expect_err("overflowing outbound connection increment must fail");
                assert_eq!(err.code, ErrorCode::FlowControlError);
                assert!(err.stream_id.is_none());
                assert_eq!(connection.recv_window(), before);
                return;
            }

            result.expect("valid outbound connection increment should succeed");
            assert_eq!(connection.recv_window(), before + op.increment as i32);
            expected_frames.push((0, op.increment));
        }
        OutboundTarget::ActiveStream => {
            let before = connection
                .stream(ACTIVE_STREAM_ID)
                .expect("active stream must exist")
                .recv_window();
            let result = connection.send_stream_window_update(ACTIVE_STREAM_ID, op.increment);

            if op.increment == 0 {
                let err = result.expect_err("zero outbound stream increment must fail");
                assert_eq!(err.code, ErrorCode::FlowControlError);
                assert!(err.stream_id.is_none());
                assert_eq!(
                    connection
                        .stream(ACTIVE_STREAM_ID)
                        .expect("active stream must still exist")
                        .recv_window(),
                    before
                );
                return;
            }

            if op.increment > i32::MAX as u32 {
                let err = result.expect_err("oversized outbound stream increment must fail");
                assert_eq!(err.code, ErrorCode::FlowControlError);
                assert!(err.stream_id.is_none());
                assert_eq!(
                    connection
                        .stream(ACTIVE_STREAM_ID)
                        .expect("active stream must still exist")
                        .recv_window(),
                    before
                );
                return;
            }

            if i64::from(before) + i64::from(op.increment) > i64::from(i32::MAX) {
                let err = result.expect_err("overflowing outbound stream increment must fail");
                assert_eq!(err.code, ErrorCode::FlowControlError);
                assert_eq!(err.stream_id, Some(ACTIVE_STREAM_ID));
                assert_eq!(
                    connection
                        .stream(ACTIVE_STREAM_ID)
                        .expect("active stream must still exist")
                        .recv_window(),
                    before
                );
                return;
            }

            result.expect("valid outbound stream increment should succeed");
            assert_eq!(
                connection
                    .stream(ACTIVE_STREAM_ID)
                    .expect("active stream must still exist")
                    .recv_window(),
                before + op.increment as i32
            );
            expected_frames.push((ACTIVE_STREAM_ID, op.increment));
        }
        OutboundTarget::MissingStream => {
            let before = expected_frames.len();
            let result = connection.send_stream_window_update(MISSING_STREAM_ID, op.increment);

            if op.increment == 0 || op.increment > i32::MAX as u32 {
                let err = result.expect_err("invalid missing-stream increment must fail");
                assert_eq!(err.code, ErrorCode::FlowControlError);
                assert!(err.stream_id.is_none());
            } else {
                result.expect("missing-stream WINDOW_UPDATE should be skipped cleanly");
            }

            assert_eq!(
                expected_frames.len(),
                before,
                "missing-stream WINDOW_UPDATE must not queue a frame"
            );
            assert!(
                connection.stream(MISSING_STREAM_ID).is_none(),
                "missing stream should remain absent"
            );
        }
    }
}

fn fuzz_connection_window_updates(input: H2ConnectionWindowUpdateFuzzInput) {
    let mut connection = setup_connection();
    let mut expected_frames = Vec::new();

    for op in input.inbound_ops.iter().take(MAX_INBOUND_OPS) {
        apply_inbound_update(&mut connection, op);
    }

    for op in input.outbound_ops.iter().take(MAX_OUTBOUND_OPS) {
        apply_outbound_update(&mut connection, op, &mut expected_frames);
    }

    let actual_frames = collect_window_update_frames(&mut connection);
    assert_eq!(
        actual_frames, expected_frames,
        "queued WINDOW_UPDATE frames must preserve issue order"
    );
}

fuzz_target!(|input: H2ConnectionWindowUpdateFuzzInput| {
    fuzz_connection_window_updates(input);
});
