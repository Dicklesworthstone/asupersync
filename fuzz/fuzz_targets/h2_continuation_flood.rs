#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::{Connection, ConnectionState, ReceivedFrame};
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{
    ContinuationFrame, Frame, FrameHeader, FrameType, HeadersFrame, SettingsFrame,
    continuation_flags, parse_frame,
};
use asupersync::http::h2::settings::Settings;
use libfuzzer_sys::fuzz_target;

const MAX_INITIAL_BLOCK: usize = 4096;
const MAX_FRAGMENT: usize = 4096;
const MAX_CONTINUATIONS: usize = 256;
const MAX_RAW_PAYLOAD: usize = 8192;

fn observe_parse_frame(header: &FrameHeader, payload: Bytes) -> Result<Frame, H2Error> {
    let payload_len = payload.len();
    let result = parse_frame(header, payload);

    match &result {
        Ok(Frame::Continuation(frame)) => {
            assert!(
                payload_len <= MAX_RAW_PAYLOAD,
                "successful continuation parse exceeded raw fuzz payload bound"
            );
            assert_eq!(
                header.length as usize, payload_len,
                "successful continuation parse accepted a mismatched header length"
            );
            assert_eq!(
                header.frame_type,
                FrameType::Continuation as u8,
                "continuation parser probe used a non-continuation frame type"
            );
            assert_eq!(
                frame.stream_id, header.stream_id,
                "successful continuation parse changed the stream id"
            );
            assert!(
                frame.header_block.len() <= MAX_RAW_PAYLOAD,
                "successful continuation parse exceeded header block fuzz bound"
            );
        }
        Ok(_) => {
            panic!("continuation parser probe returned a non-continuation frame");
        }
        Err(err) => {
            assert!(
                !format!("{err:?}").is_empty(),
                "H2 continuation parser errors must remain observable"
            );
        }
    }

    result
}

fn assert_initial_settings_observed(
    result: Result<Option<ReceivedFrame>, H2Error>,
    conn: &Connection,
) {
    match result {
        Ok(None) => {
            assert_eq!(
                conn.state(),
                ConnectionState::Open,
                "empty initial SETTINGS must complete the H2 handshake"
            );
            assert!(
                !conn.is_awaiting_continuation(),
                "initial SETTINGS must not enter continuation state"
            );
        }
        Ok(Some(frame)) => {
            panic!("initial SETTINGS unexpectedly produced a received event: {frame:?}");
        }
        Err(err) => {
            panic!("empty initial SETTINGS must be accepted during handshake: {err:?}");
        }
    }
}

fn assert_connection_continuation_observed(
    result: Result<Option<ReceivedFrame>, H2Error>,
    conn: &Connection,
    expected_stream_id: u32,
    end_headers: bool,
) -> bool {
    match result {
        Ok(Some(ReceivedFrame::Headers { stream_id, .. })) => {
            assert_eq!(
                stream_id, expected_stream_id,
                "decoded continuation header event changed stream id"
            );
            assert!(
                end_headers,
                "continuation sequence produced headers before END_HEADERS"
            );
            assert!(
                !conn.is_awaiting_continuation(),
                "END_HEADERS continuation must clear continuation state"
            );
            true
        }
        Ok(Some(frame)) => {
            panic!("continuation sequence produced an unrelated received event: {frame:?}");
        }
        Ok(None) => {
            assert!(
                !end_headers,
                "END_HEADERS continuation was accepted without a decoded event"
            );
            assert_eq!(
                conn.continuation_stream_id(),
                Some(expected_stream_id),
                "non-terminal continuation must preserve the expected stream id"
            );
            false
        }
        Err(err) => {
            assert_ne!(
                err.code,
                ErrorCode::NoError,
                "rejected continuation must carry an error code"
            );
            assert!(
                !err.message.is_empty(),
                "rejected continuation must carry diagnostics"
            );
            if let Some(stream_id) = err.stream_id {
                assert_ne!(
                    stream_id, 0,
                    "stream-scoped continuation errors must name a nonzero stream"
                );
            }
            true
        }
    }
}

fn assert_parser_continuation_observed(result: Result<Frame, H2Error>) {
    match result {
        Ok(Frame::Continuation(frame)) => {
            assert_ne!(
                frame.stream_id, 0,
                "accepted parser-only CONTINUATION must name a stream"
            );
            assert!(
                frame.header_block.len() <= MAX_RAW_PAYLOAD,
                "accepted parser-only CONTINUATION exceeded payload bound"
            );
        }
        Ok(frame) => {
            panic!("parser-only CONTINUATION probe produced non-continuation frame: {frame:?}");
        }
        Err(err) => {
            assert_ne!(
                err.code,
                ErrorCode::NoError,
                "rejected parser-only CONTINUATION must carry an error code"
            );
            assert!(
                !err.message.is_empty(),
                "rejected parser-only CONTINUATION must carry diagnostics"
            );
        }
    }
}

#[derive(Arbitrary, Debug)]
struct ContinuationFloodInput {
    initial_stream_id: u32,
    initial_header_block: Vec<u8>,
    fragments: Vec<ContinuationFragment>,
    raw_payload: Vec<u8>,
    mode: FloodMode,
}

#[derive(Arbitrary, Debug)]
struct ContinuationFragment {
    stream_id: u32,
    payload: Vec<u8>,
    end_headers: bool,
    raw_flags: u8,
}

#[derive(Arbitrary, Debug)]
enum FloodMode {
    ConnectionSequence,
    ParserOnly,
    Mixed,
}

fuzz_target!(|input: ContinuationFloodInput| {
    match input.mode {
        FloodMode::ConnectionSequence => fuzz_connection_sequence(&input),
        FloodMode::ParserOnly => fuzz_parser_only(&input),
        FloodMode::Mixed => {
            fuzz_parser_only(&input);
            fuzz_connection_sequence(&input);
        }
    }
});

fn fuzz_connection_sequence(input: &ContinuationFloodInput) {
    let mut conn = Connection::server(Settings::default());
    let settings_result = conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())));
    assert_initial_settings_observed(settings_result, &conn);

    let stream_id = normalize_client_stream_id(input.initial_stream_id);
    let header_block = capped_bytes(&input.initial_header_block, MAX_INITIAL_BLOCK);
    let headers = HeadersFrame::new(stream_id, header_block, false, false);
    if conn.process_frame(Frame::Headers(headers)).is_err() {
        return;
    }

    for fragment in input.fragments.iter().take(MAX_CONTINUATIONS) {
        let continuation = Frame::Continuation(ContinuationFrame {
            stream_id: normalize_continuation_stream_id(fragment.stream_id, stream_id),
            header_block: capped_bytes(&fragment.payload, MAX_FRAGMENT),
            end_headers: fragment.end_headers,
        });

        let done = fragment.end_headers;
        let result = conn.process_frame(continuation);
        if assert_connection_continuation_observed(result, &conn, stream_id, done) {
            break;
        }
    }
}

fn fuzz_parser_only(input: &ContinuationFloodInput) {
    let raw_payload = capped_bytes(&input.raw_payload, MAX_RAW_PAYLOAD);
    let raw_header = FrameHeader {
        length: raw_payload.len() as u32,
        frame_type: FrameType::Continuation as u8,
        flags: continuation_flags::END_HEADERS,
        stream_id: normalize_client_stream_id(input.initial_stream_id),
    };
    assert_parser_continuation_observed(observe_parse_frame(&raw_header, raw_payload));

    for fragment in input.fragments.iter().take(MAX_CONTINUATIONS) {
        let payload = capped_bytes(&fragment.payload, MAX_RAW_PAYLOAD);
        let header = FrameHeader {
            length: payload.len() as u32,
            frame_type: FrameType::Continuation as u8,
            flags: fragment.raw_flags | continuation_flags::END_HEADERS,
            stream_id: fragment.stream_id & 0x7fff_ffff,
        };
        assert_parser_continuation_observed(observe_parse_frame(&header, payload));
    }
}

fn normalize_client_stream_id(raw: u32) -> u32 {
    let mut stream_id = raw & 0x7fff_ffff;
    if stream_id == 0 {
        stream_id = 1;
    }
    if stream_id.is_multiple_of(2) {
        stream_id = stream_id.saturating_add(1);
    }
    if stream_id == 0 { 1 } else { stream_id }
}

fn normalize_continuation_stream_id(raw: u32, expected: u32) -> u32 {
    if raw & 0b11 == 0 {
        expected
    } else {
        raw & 0x7fff_ffff
    }
}

fn capped_bytes(data: &[u8], max: usize) -> Bytes {
    Bytes::copy_from_slice(&data[..data.len().min(max)])
}
