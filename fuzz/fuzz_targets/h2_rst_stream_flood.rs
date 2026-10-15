//! HTTP/2 RST_STREAM rapid-reset flood harness.
//!
//! Drives the production HTTP/2 connection path that enforces the
//! CVE-2023-44487 RST_STREAM rate limit. The target keeps the sequence small
//! enough for libFuzzer while checking the exact N allowed / N+1 rejected
//! contract across arbitrary limits and error-code mixes.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::{ReceivedFrame, RstStreamRateLimit};
use asupersync::http::h2::frame::{HeadersFrame, RstStreamFrame, SettingsFrame};
use asupersync::http::h2::{Connection, ErrorCode, Frame, Settings};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Scenario {
    max_rst_streams: u8,
    extra_resets: u8,
    error_codes: Vec<u8>,
    include_idle_probe: bool,
}

fuzz_target!(|scenario: Scenario| {
    let limit = u32::from(scenario.max_rst_streams % 16) + 1;
    let extra = usize::from(scenario.extra_resets % 4) + 1;
    let attempts = limit as usize + extra;

    let mut conn =
        Connection::server(Settings::default()).rst_stream_rate_limit(RstStreamRateLimit {
            max_rst_streams: limit,
            rst_window_ms: 30_000,
        });

    conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("peer SETTINGS should open the connection");

    if scenario.include_idle_probe {
        let idle = Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel));
        let err = conn
            .process_frame(idle)
            .expect_err("idle-stream RST_STREAM must be rejected before rate counting");
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.is_connection_error());
    }

    for idx in 0..attempts {
        let stream_id = (idx as u32).saturating_mul(2).saturating_add(1);
        let headers = Frame::Headers(HeadersFrame::new(stream_id, Bytes::new(), false, true));
        conn.process_frame(headers)
            .expect("opening a small odd client stream should succeed");

        let rst = Frame::RstStream(RstStreamFrame::new(
            stream_id,
            error_code_at(&scenario.error_codes, idx),
        ));
        let result = conn.process_frame(rst);

        if idx < limit as usize {
            match result.expect("RST_STREAM within the configured rate limit should pass") {
                Some(ReceivedFrame::Reset {
                    stream_id: reset_id,
                    ..
                }) => assert_eq!(reset_id, stream_id),
                other => panic!("expected Reset received frame, got {other:?}"),
            }
        } else {
            let err = result.expect_err("RST_STREAM above the configured limit must fail");
            assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
            assert!(err.is_connection_error());
            break;
        }
    }
});

fn error_code_at(codes: &[u8], idx: usize) -> ErrorCode {
    match codes.get(idx).copied().unwrap_or(8) % 14 {
        0 => ErrorCode::NoError,
        1 => ErrorCode::ProtocolError,
        2 => ErrorCode::InternalError,
        3 => ErrorCode::FlowControlError,
        4 => ErrorCode::SettingsTimeout,
        5 => ErrorCode::StreamClosed,
        6 => ErrorCode::FrameSizeError,
        7 => ErrorCode::RefusedStream,
        8 => ErrorCode::Cancel,
        9 => ErrorCode::CompressionError,
        10 => ErrorCode::ConnectError,
        11 => ErrorCode::EnhanceYourCalm,
        12 => ErrorCode::InadequateSecurity,
        _ => ErrorCode::Http11Required,
    }
}
