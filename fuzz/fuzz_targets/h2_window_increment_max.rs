#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::frame::{
    FrameHeader, FrameType, HeadersFrame, SettingsFrame, WindowUpdateFrame,
};
use asupersync::http::h2::{Connection, ErrorCode, Frame, Settings};
use libfuzzer_sys::fuzz_target;

const STREAM_ID: u32 = 1;
const DEFAULT_WINDOW: u32 = 65_535;
const MAX_INCREMENT: u32 = 0x7fff_ffff;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum MaxIncrementTarget {
    Connection,
    Stream,
    ConnectionThenStream,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct MaxIncrementInput {
    target: MaxIncrementTarget,
    consumed_before_update: u16,
}

fn open_server_connection() -> Connection {
    let mut connection = Connection::server(Settings::default());

    connection
        .process_frame(Frame::Settings(SettingsFrame::new(vec![])))
        .expect("initial peer SETTINGS should open the connection");
    drain_pending_frames(&mut connection);

    connection
        .process_frame(Frame::Headers(HeadersFrame::new(
            STREAM_ID,
            Bytes::new(),
            false,
            true,
        )))
        .expect("request HEADERS should open the test stream");

    connection
}

fn drain_pending_frames(connection: &mut Connection) {
    while connection.next_frame().is_some() {}
}

fn consume_send_window(connection: &mut Connection, amount: u32) {
    if amount == 0 {
        return;
    }

    connection
        .send_data(STREAM_ID, Bytes::from(vec![0; amount as usize]), false)
        .expect("test stream should accept outbound DATA");

    let mut consumed = 0u32;
    while consumed < amount {
        match connection.next_frame() {
            Some(Frame::Data(frame)) => {
                consumed += u32::try_from(frame.data.len()).expect("DATA frame length fits u32");
            }
            Some(other) => panic!("unexpected pending frame while consuming window: {other:?}"),
            None => panic!("queued DATA stopped before consuming requested send window"),
        }
    }
}

fn assert_max_increment_frame_round_trip(stream_id: u32) {
    let header = FrameHeader {
        length: 4,
        frame_type: FrameType::WindowUpdate as u8,
        flags: 0,
        stream_id,
    };
    let payload = Bytes::from_static(&[0x7f, 0xff, 0xff, 0xff]);
    let parsed = WindowUpdateFrame::parse(&header, &payload).expect("max increment parses");
    assert_eq!(parsed.stream_id, stream_id);
    assert_eq!(parsed.increment, MAX_INCREMENT);

    let mut encoded = BytesMut::new();
    parsed.encode(&mut encoded).expect("max increment encodes");
    assert_eq!(&encoded[9..13], &[0x7f, 0xff, 0xff, 0xff]);
}

fn apply_connection_max_increment(connection: &mut Connection, should_accept: bool) {
    let before_connection = connection.send_window();
    let before_stream = connection
        .stream(STREAM_ID)
        .expect("test stream should exist")
        .send_window();

    let result = connection.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(
        0,
        MAX_INCREMENT,
    )));

    if should_accept {
        result.expect("max connection WINDOW_UPDATE should fit from a zero send window");
        assert_eq!(connection.send_window(), i32::MAX);
    } else {
        let err = result.expect_err("max connection WINDOW_UPDATE should overflow positive window");
        assert_eq!(err.code, ErrorCode::FlowControlError);
        assert!(err.stream_id.is_none());
        assert_eq!(connection.send_window(), before_connection);
    }

    assert_eq!(
        connection
            .stream(STREAM_ID)
            .expect("test stream should still exist")
            .send_window(),
        before_stream,
        "connection-level WINDOW_UPDATE must not mutate stream send window"
    );
}

fn apply_stream_max_increment(connection: &mut Connection, should_accept: bool) {
    let before_connection = connection.send_window();
    let before_stream = connection
        .stream(STREAM_ID)
        .expect("test stream should exist")
        .send_window();

    let result = connection.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(
        STREAM_ID,
        MAX_INCREMENT,
    )));

    if should_accept {
        result.expect("max stream WINDOW_UPDATE should fit from a zero send window");
        assert_eq!(
            connection
                .stream(STREAM_ID)
                .expect("test stream should still exist")
                .send_window(),
            i32::MAX
        );
    } else {
        let err = result.expect_err("max stream WINDOW_UPDATE should overflow positive window");
        assert_eq!(err.code, ErrorCode::FlowControlError);
        assert_eq!(err.stream_id, Some(STREAM_ID));
        assert_eq!(
            connection
                .stream(STREAM_ID)
                .expect("test stream should still exist")
                .send_window(),
            before_stream
        );
    }

    assert_eq!(
        connection.send_window(),
        before_connection,
        "stream-level WINDOW_UPDATE must not mutate connection send window"
    );
}

fn fuzz_max_increment(input: MaxIncrementInput) {
    assert_max_increment_frame_round_trip(0);
    assert_max_increment_frame_round_trip(STREAM_ID);

    let consumed = u32::from(input.consumed_before_update).min(DEFAULT_WINDOW);
    let should_accept = consumed == DEFAULT_WINDOW;
    let mut connection = open_server_connection();
    consume_send_window(&mut connection, consumed);

    match input.target {
        MaxIncrementTarget::Connection => {
            apply_connection_max_increment(&mut connection, should_accept);
        }
        MaxIncrementTarget::Stream => {
            apply_stream_max_increment(&mut connection, should_accept);
        }
        MaxIncrementTarget::ConnectionThenStream => {
            apply_connection_max_increment(&mut connection, should_accept);
            apply_stream_max_increment(&mut connection, should_accept);
            if should_accept {
                assert_eq!(connection.send_window(), i32::MAX);
                assert_eq!(
                    connection
                        .stream(STREAM_ID)
                        .expect("test stream should still exist")
                        .send_window(),
                    i32::MAX
                );
            }
        }
    }
}

fuzz_target!(|input: MaxIncrementInput| {
    fuzz_max_increment(input);
});
