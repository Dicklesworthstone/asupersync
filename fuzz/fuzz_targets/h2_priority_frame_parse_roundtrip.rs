//! br-asupersync-u3xx8w — Narrow structure-aware fuzz target for
//! HTTP/2 [`PriorityFrame::parse`] (RFC 9113 §6.3).
//!
//! Existing fuzz coverage for PRIORITY frames is high-level (cycle
//! detection, idle streams, max weight). The parser itself has tight
//! invariants that deserve a dedicated narrow target, so a regression
//! is caught at the wire boundary rather than via downstream symptoms:
//!
//!   * payload MUST be exactly 5 bytes (else stream FRAME_SIZE_ERROR);
//!   * `stream_id == 0` is rejected as a connection PROTOCOL_ERROR;
//!   * the high bit of the first 4 payload bytes is the `exclusive`
//!     flag — the dependency field returned to callers MUST have it
//!     cleared (i.e. `dependency & 0x8000_0000 == 0`);
//!   * `dependency == header.stream_id` (self-dependency) is a stream
//!     PROTOCOL_ERROR;
//!   * encode → parse round-trip preserves `(stream_id, exclusive,
//!     dependency, weight)` exactly for any inputs that satisfy the
//!     invariants.
//!
//! The harness is structure-aware: an Arbitrary input picks
//! independently the frame header (length, stream_id with the reserved
//! high bit set/cleared, flags) and the 5 payload octets, including the
//! decision of whether to set the exclusive bit. Out-of-spec lengths,
//! stream IDs, and self-dependencies are deliberately reachable so the
//! parser's error classification is exercised.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{FrameHeader, FrameType, PriorityFrame};

const MAX_INPUT_LEN: usize = 256;

#[derive(Arbitrary, Debug)]
struct Input {
    /// Header.length we present to the parser. The parser relies on
    /// `payload.len()` rather than this field, so the two are
    /// intentionally independent — this catches any future drift.
    declared_length: u32,
    /// Header.stream_id, including the high reserved bit. The parser
    /// MUST reject stream_id == 0 outright.
    header_stream_id: u32,
    /// PRIORITY has no flags per RFC 9113 §6.3, but garbage flags must
    /// not affect the parse outcome.
    flags: u8,
    /// Whether to set the exclusive bit (high bit of payload[0]) on
    /// well-formed payloads. Out-of-spec payloads ignore this.
    exclusive_bit: bool,
    /// Lower 31 bits of the dependency stream id.
    dependency_low_31: u32,
    /// PRIORITY weight byte.
    weight: u8,
    /// What kind of payload to feed the parser.
    payload: PayloadShape,
}

#[derive(Arbitrary, Debug)]
enum PayloadShape {
    /// Strictly RFC-conforming 5-byte payload built from the typed
    /// fields above; expected to round-trip cleanly when the
    /// stream_id / dependency invariants hold.
    Conforming,
    /// Payload of an arbitrary length (other than 5) — the parser
    /// MUST return a stream FRAME_SIZE_ERROR.
    WrongLength { padding: Vec<u8> },
    /// Garbage 5-byte payload — every parse outcome is acceptable
    /// except a panic; round-trip is asserted only when no error.
    Arbitrary { bytes: [u8; 5] },
}

fn dependency_from_priority_payload(payload: &Bytes) -> u32 {
    assert_eq!(
        payload.len(),
        5,
        "PRIORITY dependency oracle only applies to 5-byte payloads"
    );
    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFF_FFFF
}

fuzz_target!(|input: Input| {
    if matches!(&input.payload, PayloadShape::WrongLength { padding } if padding.len() > MAX_INPUT_LEN)
    {
        return;
    }

    // The header.length field is mostly cosmetic for these unit-level
    // parsers (they read from the payload Bytes directly), but pinning
    // it stops a future refactor from quietly trusting it.
    let header = FrameHeader {
        length: input.declared_length & 0x00FF_FFFF,
        frame_type: FrameType::Priority as u8,
        flags: input.flags,
        stream_id: input.header_stream_id & 0x7FFF_FFFF,
    };

    let payload = match &input.payload {
        PayloadShape::Conforming => {
            let mut buf = [0u8; 5];
            let mut dep = input.dependency_low_31 & 0x7FFF_FFFF;
            if input.exclusive_bit {
                dep |= 0x8000_0000;
            }
            buf[0] = ((dep >> 24) & 0xFF) as u8;
            buf[1] = ((dep >> 16) & 0xFF) as u8;
            buf[2] = ((dep >> 8) & 0xFF) as u8;
            buf[3] = (dep & 0xFF) as u8;
            buf[4] = input.weight;
            Bytes::copy_from_slice(&buf)
        }
        PayloadShape::WrongLength { padding } => {
            let mut buf = BytesMut::with_capacity(padding.len());
            buf.extend_from_slice(padding);
            // Make sure we are not 5 bytes by accident.
            if buf.len() == 5 {
                buf.extend_from_slice(b"\x00");
            }
            buf.freeze()
        }
        PayloadShape::Arbitrary { bytes } => Bytes::copy_from_slice(bytes),
    };

    let result = PriorityFrame::parse(&header, &payload);

    // 1. stream_id == 0 → connection PROTOCOL_ERROR. Always.
    if header.stream_id == 0 {
        let err = result.expect_err("PRIORITY on stream 0 must error");
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(
            err.stream_id, None,
            "RFC 9113 §6.3: PRIORITY on stream 0 is a connection error"
        );
        assert_eq!(
            err.message, "PRIORITY frame with stream ID 0",
            "stream-0 PRIORITY diagnostic changed"
        );
        return;
    }

    match (&input.payload, result) {
        // 2. WrongLength → stream FRAME_SIZE_ERROR.
        (PayloadShape::WrongLength { .. }, Err(err)) => {
            assert_eq!(err.code, ErrorCode::FrameSizeError);
            assert_eq!(
                err.stream_id,
                Some(header.stream_id),
                "RFC 9113 §6.3: PRIORITY size violation is a stream error"
            );
            assert_eq!(
                err.message, "PRIORITY frame must be 5 bytes",
                "wrong-length PRIORITY diagnostic changed"
            );
        }
        (PayloadShape::WrongLength { .. }, Ok(_)) => {
            panic!("PRIORITY parser accepted non-5-byte payload");
        }
        // 3. Conforming or Arbitrary 5-byte payload — same path.
        (_, Ok(frame)) => {
            // RFC 9113 §6.3: dependency must NOT carry the exclusive bit
            // back to the caller.
            assert_eq!(
                frame.priority.dependency & 0x8000_0000,
                0,
                "PriorityFrame.parse leaked the exclusive bit into dependency: {:#x}",
                frame.priority.dependency
            );
            assert_eq!(frame.stream_id, header.stream_id);
            // 4. Round-trip: encode → parse must be a fixed point on
            //    well-formed inputs.
            let mut encoded = BytesMut::with_capacity(9 + 5);
            frame
                .encode(&mut encoded)
                .expect("encode of just-parsed frame must succeed");
            assert!(
                encoded.len() >= 9 + 5,
                "encoded PRIORITY frame must be at least header(9) + payload(5)"
            );
            let mut header_buf = BytesMut::from(&encoded[..]);
            let parsed_header =
                FrameHeader::parse(&mut header_buf).expect("re-parse of own header must succeed");
            assert_eq!(parsed_header.length, 5);
            assert_eq!(parsed_header.frame_type, FrameType::Priority as u8);
            assert_eq!(parsed_header.stream_id, frame.stream_id);
            let payload_again = header_buf.split_to(parsed_header.length as usize).freeze();
            let frame_again = PriorityFrame::parse(&parsed_header, &payload_again)
                .expect("round-trip parse must succeed");
            assert_eq!(frame_again.stream_id, frame.stream_id);
            assert_eq!(frame_again.priority.exclusive, frame.priority.exclusive);
            assert_eq!(frame_again.priority.dependency, frame.priority.dependency);
            assert_eq!(frame_again.priority.weight, frame.priority.weight);
        }
        (_, Err(err)) => {
            // Only legitimate error on a 5-byte payload is the
            // self-dependency check.
            let dependency = dependency_from_priority_payload(&payload);
            assert_eq!(
                dependency, header.stream_id,
                "PRIORITY parser rejected non-self-dependency payload: dependency={dependency}, stream_id={}",
                header.stream_id
            );
            assert_eq!(
                err.code,
                ErrorCode::ProtocolError,
                "non-self-dep error on 5-byte PRIORITY payload: {err:?}"
            );
            assert_eq!(
                err.stream_id,
                Some(header.stream_id),
                "RFC 9113 §6.3: self-dependency is a stream error, not connection"
            );
            assert_eq!(
                err.message, "stream cannot depend on itself",
                "self-dep error message changed"
            );
        }
    }
});
