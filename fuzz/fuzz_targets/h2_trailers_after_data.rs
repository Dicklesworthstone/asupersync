//! Fuzz HTTP/2 request body/trailer ordering through the production connection.
//!
//! The important seam is `Connection::process_frame`, not an independent model:
//! trailers are a second HEADERS block on an open request stream and are valid
//! even when the body is empty. The target asserts the hard failures that matter:
//! malformed trailers without END_STREAM, pseudo-headers in trailers, duplicate
//! trailers after the remote side closed, and DATA after trailers.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::connection::{Connection, ReceivedFrame};
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{DataFrame, Frame, HeadersFrame, SettingsFrame};
use asupersync::http::h2::hpack::{Encoder as HpackEncoder, Header};
use asupersync::http::h2::settings::Settings;
use libfuzzer_sys::fuzz_target;

/// Test scenarios for HTTP/2 trailer validation
#[derive(Debug, Arbitrary)]
struct TrailersAfterDataInput {
    /// Stream configurations to test
    streams: Vec<StreamScenario>,
    /// Frame sequences to send
    frame_sequences: Vec<FrameSequence>,
}

/// Configuration for a stream's trailer test scenario
#[derive(Debug, Arbitrary)]
struct StreamScenario {
    stream_id: u32,
    trailer_scenario: TrailerScenario,
}

/// Frame sequence to send for testing
#[derive(Debug, Arbitrary)]
struct FrameSequence {
    stream_id: u32,
    frames: Vec<TestFrame>,
}

/// Test frame for trailer sequences
#[derive(Debug, Arbitrary)]
enum TestFrame {
    /// Initial HEADERS frame
    InitialHeaders {
        content: HeaderContent,
        end_stream: bool,
    },
    /// DATA frame
    Data { size: u16, end_stream: bool },
    /// Trailer HEADERS frame
    TrailerHeaders {
        content: HeaderContent,
        end_stream: bool,
    },
    /// Invalid frame (for negative testing)
    InvalidFrame,
}

#[derive(Debug, Arbitrary)]
struct HeaderContent {
    /// Simulated header block (simplified)
    block_size: u8,
    /// Whether this represents trailers
    is_trailers: bool,
}

/// Different trailer test scenarios
#[derive(Debug, Clone, Copy, Arbitrary)]
enum TrailerScenario {
    /// Valid: DATA(end_stream=0) → HEADERS(end_stream=1, trailers)
    ValidTrailers,
    /// Valid: HEADERS(trailers) without prior DATA; HTTP/2 permits empty bodies.
    TrailersWithoutData,
    /// Invalid: DATA(end_stream=1) → HEADERS(trailers) (no DATA with end_stream=0)
    TrailersAfterEndStream,
    /// Invalid: Multiple trailing HEADERS
    MultipleTrailers,
    /// Invalid: Trailers with END_STREAM=0
    TrailersWithoutEndStream,
    /// Invalid: Trailers in middle of DATA stream
    TrailersInMiddle,
}

/// Normalize stream ID to valid range
fn normalize_stream_id(raw: u32) -> u32 {
    let mut id = raw & 0x7fff_ffff; // Ensure 31-bit
    if id == 0 {
        id = 1;
    }
    if id.is_multiple_of(2) {
        id = id.saturating_add(1);
    } // Make odd (client-initiated)
    id
}

fn new_server_connection() -> Connection {
    let mut conn = Connection::server(Settings::default());
    conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("initial peer SETTINGS should be accepted");
    conn
}

fn encode_headers(headers: &[Header]) -> Bytes {
    let mut encoder = HpackEncoder::new();
    encoder.set_use_huffman(false);

    let mut block = BytesMut::new();
    encoder.encode(headers, &mut block);
    block.freeze()
}

fn bounded_value(prefix: &str, size: u8, max: usize) -> String {
    let repeat = usize::from(size).min(max);
    format!("{prefix}{}", "x".repeat(repeat))
}

fn request_header_block(content: Option<&HeaderContent>) -> Bytes {
    let mut headers = vec![
        Header::new(":method", "POST"),
        Header::new(":scheme", "https"),
        Header::new(":path", "/fuzz"),
        Header::new(":authority", "example.test"),
    ];
    if let Some(content) = content {
        headers.push(Header::new(
            "x-fuzz-request",
            bounded_value("req-", content.block_size, 128),
        ));
    }
    encode_headers(&headers)
}

fn trailer_header_block(content: &HeaderContent) -> Bytes {
    let mut headers = Vec::new();
    if !content.is_trailers {
        headers.push(Header::new(":path", "/smuggled-after-initial-headers"));
    }
    headers.push(Header::new(
        "x-fuzz-trailer",
        bounded_value("trailer-", content.block_size, 128),
    ));
    encode_headers(&headers)
}

fn request_headers_frame(
    stream_id: u32,
    content: Option<&HeaderContent>,
    end_stream: bool,
) -> Frame {
    Frame::Headers(HeadersFrame::new(
        stream_id,
        request_header_block(content),
        end_stream,
        true,
    ))
}

fn trailer_headers_frame(stream_id: u32, content: &HeaderContent, end_stream: bool) -> Frame {
    Frame::Headers(HeadersFrame::new(
        stream_id,
        trailer_header_block(content),
        end_stream,
        true,
    ))
}

fn data_frame(stream_id: u32, size: u16, end_stream: bool) -> Frame {
    Frame::Data(DataFrame::new(
        stream_id,
        Bytes::from(vec![b'd'; usize::from(size).min(4096)]),
        end_stream,
    ))
}

fn assert_trailer_accepted(
    result: Result<Option<ReceivedFrame>, H2Error>,
    scenario: TrailerScenario,
) {
    match result.expect("valid request trailers should be accepted") {
        Some(ReceivedFrame::Headers {
            end_stream: true, ..
        }) => {}
        other => panic!("expected END_STREAM trailer headers for {scenario:?}, got {other:?}"),
    }
}

fn assert_h2_error(
    result: Result<Option<ReceivedFrame>, H2Error>,
    expected: ErrorCode,
    expected_stream_id: Option<u32>,
    expected_message: &str,
    context: &str,
) {
    let err = result.expect_err(context);
    assert_eq!(err.code, expected, "{context}: unexpected error {err:?}");
    assert_eq!(
        err.stream_id, expected_stream_id,
        "{context}: unexpected stream id for {err:?}"
    );
    assert_eq!(
        err.message, expected_message,
        "{context}: unexpected message for {err:?}"
    );
    assert_eq!(
        err.is_connection_error(),
        expected_stream_id.is_none(),
        "{context}: unexpected connection/stream classification for {err:?}"
    );

    let expected_display = match expected_stream_id {
        Some(stream_id) => {
            format!("HTTP/2 stream {stream_id} error ({expected}): {expected_message}")
        }
        None => format!("HTTP/2 connection error ({expected}): {expected_message}"),
    };
    assert_eq!(
        err.to_string(),
        expected_display,
        "{context}: unexpected display text for {err:?}"
    );
}

fn run_arbitrary_sequence(sequence: &FrameSequence) {
    let stream_id = normalize_stream_id(sequence.stream_id);
    let mut conn = new_server_connection();
    let mut opened = false;

    for test_frame in sequence.frames.iter().take(16) {
        let result = match test_frame {
            TestFrame::InitialHeaders {
                content,
                end_stream,
            } => {
                opened = true;
                conn.process_frame(request_headers_frame(stream_id, Some(content), *end_stream))
            }
            TestFrame::Data { size, end_stream } => {
                conn.process_frame(data_frame(stream_id, *size, *end_stream))
            }
            TestFrame::TrailerHeaders {
                content,
                end_stream,
            } => conn.process_frame(trailer_headers_frame(stream_id, content, *end_stream)),
            TestFrame::InvalidFrame => continue,
        };

        if opened
            && matches!(
                test_frame,
                TestFrame::TrailerHeaders {
                    end_stream: false,
                    ..
                }
            )
        {
            assert!(
                result.is_err(),
                "server-side trailers without END_STREAM must be rejected"
            );
            break;
        }

        if result.is_err() {
            break;
        }
    }
}

fn run_targeted_scenario(scenario: &StreamScenario) {
    let stream_id = normalize_stream_id(scenario.stream_id);
    let mut conn = new_server_connection();
    let valid_trailers = HeaderContent {
        block_size: 8,
        is_trailers: true,
    };
    let bad_trailers = HeaderContent {
        block_size: 8,
        is_trailers: false,
    };

    match scenario.trailer_scenario {
        TrailerScenario::ValidTrailers => {
            conn.process_frame(request_headers_frame(stream_id, None, false))
                .expect("initial request headers should be accepted");
            conn.process_frame(data_frame(stream_id, 8, false))
                .expect("request DATA should be accepted");
            assert_trailer_accepted(
                conn.process_frame(trailer_headers_frame(stream_id, &valid_trailers, true)),
                scenario.trailer_scenario,
            );
        }
        TrailerScenario::TrailersWithoutData => {
            conn.process_frame(request_headers_frame(stream_id, None, false))
                .expect("initial request headers should be accepted");
            assert_trailer_accepted(
                conn.process_frame(trailer_headers_frame(stream_id, &valid_trailers, true)),
                scenario.trailer_scenario,
            );
        }
        TrailerScenario::TrailersAfterEndStream => {
            conn.process_frame(request_headers_frame(stream_id, None, false))
                .expect("initial request headers should be accepted");
            conn.process_frame(data_frame(stream_id, 8, true))
                .expect("END_STREAM DATA should close the remote side");
            assert_h2_error(
                conn.process_frame(trailer_headers_frame(stream_id, &valid_trailers, true)),
                ErrorCode::StreamClosed,
                Some(stream_id),
                "cannot receive headers in current state",
                "trailers after END_STREAM DATA must be rejected",
            );
        }
        TrailerScenario::MultipleTrailers => {
            conn.process_frame(request_headers_frame(stream_id, None, false))
                .expect("initial request headers should be accepted");
            conn.process_frame(data_frame(stream_id, 8, false))
                .expect("request DATA should be accepted");
            assert_trailer_accepted(
                conn.process_frame(trailer_headers_frame(stream_id, &valid_trailers, true)),
                scenario.trailer_scenario,
            );
            assert_h2_error(
                conn.process_frame(trailer_headers_frame(stream_id, &valid_trailers, true)),
                ErrorCode::StreamClosed,
                Some(stream_id),
                "cannot receive headers in current state",
                "duplicate trailers after remote close must be rejected",
            );
        }
        TrailerScenario::TrailersWithoutEndStream => {
            conn.process_frame(request_headers_frame(stream_id, None, false))
                .expect("initial request headers should be accepted");
            conn.process_frame(data_frame(stream_id, 8, false))
                .expect("request DATA should be accepted");
            assert_h2_error(
                conn.process_frame(trailer_headers_frame(stream_id, &valid_trailers, false)),
                ErrorCode::ProtocolError,
                Some(stream_id),
                "trailers MUST have END_STREAM (RFC 9113 \u{00a7}8.1) \u{2014} server received second HEADERS without END_STREAM",
                "server-side trailers without END_STREAM must be rejected",
            );
        }
        TrailerScenario::TrailersInMiddle => {
            conn.process_frame(request_headers_frame(stream_id, None, false))
                .expect("initial request headers should be accepted");
            conn.process_frame(data_frame(stream_id, 8, false))
                .expect("request DATA should be accepted");
            assert_h2_error(
                conn.process_frame(trailer_headers_frame(stream_id, &bad_trailers, true)),
                ErrorCode::ProtocolError,
                Some(stream_id),
                "trailers section MUST NOT contain pseudo-header fields (RFC 9113 \u{00a7}8.1)",
                "trailers with pseudo-headers must be rejected",
            );
        }
    }
}

fuzz_target!(|input: TrailersAfterDataInput| {
    for sequence in input.frame_sequences.iter().take(20) {
        run_arbitrary_sequence(sequence);
    }

    for scenario in input.streams.iter().take(16) {
        run_targeted_scenario(scenario);
    }
});
