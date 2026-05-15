//! br-asupersync-001c14 — Fuzz `H2 FrameHeader::parse` against
//! adversarial 9-byte (and shorter / longer) buffers. Every HTTP/2
//! frame begins with this 9-octet header (length:24 + type:8 +
//! flags:8 + R:1 + stream_id:31), so a panic here is reachable from
//! every connection's first read.
//!
//! Invariants:
//!   * No panic on any byte input length, including <9 bytes.
//!   * Parser returns Result on length >= 9; on shorter input,
//!     returns the documented short-read error rather than panic.
//!   * On a successful parse, `length()` is in [0, 2^24-1] and
//!     `stream_id()` has the reserved high bit cleared.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::bytes::BytesMut;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{FRAME_HEADER_SIZE, FrameHeader};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let mut buf = BytesMut::with_capacity(data.len());
    buf.extend_from_slice(data);

    let r = catch_unwind(AssertUnwindSafe(|| FrameHeader::parse(&mut buf)));

    match r {
        Ok(Ok(header)) => {
            // length is a 24-bit field per RFC 9113 §4.1.
            assert!(
                header.length <= 0x00FF_FFFF,
                "FrameHeader::parse returned length > 2^24-1: {}",
                header.length
            );
            // stream_id MUST have the reserved high bit cleared.
            assert!(
                header.stream_id & 0x8000_0000 == 0,
                "FrameHeader::parse returned stream_id with reserved bit set: {:#x}",
                header.stream_id
            );
        }
        Ok(Err(error)) => {
            let diagnostic = error.to_string();
            assert!(
                !diagnostic.trim().is_empty(),
                "FrameHeader::parse error diagnostics must be non-empty"
            );
            if data.len() < FRAME_HEADER_SIZE {
                assert_eq!(
                    error.code,
                    ErrorCode::ProtocolError,
                    "short frame-header input should be a protocol error"
                );
                assert!(
                    error.is_connection_error(),
                    "short frame-header input should be a connection-level error"
                );
                assert_eq!(error.stream_id, None);
                assert_eq!(error.message, "insufficient bytes for frame header");
                assert_eq!(
                    diagnostic,
                    "HTTP/2 connection error (PROTOCOL_ERROR): insufficient bytes for frame header"
                );
            }
        }
        Err(_) => {
            panic!("FrameHeader::parse panicked on {} bytes", data.len());
        }
    }
});
