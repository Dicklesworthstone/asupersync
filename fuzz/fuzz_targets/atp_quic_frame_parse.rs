//! Structure-aware crash/invariant fuzzer for the ATP QUIC frame receive parser.
//!
//! The target feeds adversarial packet payload bytes into `QuicFrame::decode`,
//! the parser used by the native QUIC receive path. Accepted frames must consume
//! input, produce non-empty diagnostics on typed errors, and re-encode into a
//! frame that the same parser can read again.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::bytes::BytesMut;
use asupersync::net::atp::protocol::quic_frames::{QuicFrame, QuicFrameError};
use libfuzzer_sys::fuzz_target;

const MAX_PACKET_BYTES: usize = 4096;
const MAX_FRAMES_PER_PACKET: usize = 256;
const MAX_REENCODE_BYTES: usize = 8192;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PACKET_BYTES {
        return;
    }

    let result = catch_unwind(AssertUnwindSafe(|| parse_packet_frames(data)));
    assert!(
        result.is_ok(),
        "QuicFrame::decode panicked while parsing {} packet bytes",
        data.len()
    );
});

fn parse_packet_frames(data: &[u8]) {
    let mut buf = data;
    let mut frames = 0usize;

    while !buf.is_empty() && frames < MAX_FRAMES_PER_PACKET {
        let before = buf.len();
        match QuicFrame::decode(&mut buf) {
            Ok(Some(frame)) => {
                frames += 1;
                assert!(
                    buf.len() < before,
                    "QuicFrame::decode accepted a frame without consuming bytes"
                );
                assert_accepted_frame_reencodes(&frame);
            }
            Ok(None) => {
                assert_eq!(
                    buf.len(),
                    before,
                    "QuicFrame::decode returned None after consuming bytes"
                );
                break;
            }
            Err(error) => {
                assert_typed_quic_error(&error);
                break;
            }
        }
    }
}

fn assert_accepted_frame_reencodes(frame: &QuicFrame) {
    let mut encoded = BytesMut::new();
    match frame.encode(&mut encoded) {
        Ok(()) => {}
        Err(error) => panic!("accepted QUIC frame failed to re-encode: {error:?}"),
    }

    assert!(
        encoded.len() <= MAX_REENCODE_BYTES,
        "accepted QUIC frame re-encoded to an unexpectedly large payload: {} bytes",
        encoded.len()
    );

    let mut encoded_slice = encoded.as_ref();
    let before = encoded_slice.len();
    match QuicFrame::decode(&mut encoded_slice) {
        Ok(Some(_)) => assert!(
            encoded_slice.len() < before,
            "re-encoded QUIC frame did not consume bytes on decode"
        ),
        Ok(None) => panic!("re-encoded QUIC frame decoded as incomplete"),
        Err(error) => panic!("re-encoded accepted QUIC frame failed to decode: {error:?}"),
    }
}

fn assert_typed_quic_error(error: &QuicFrameError) {
    let diagnostic = error.to_string();
    assert!(
        !diagnostic.trim().is_empty(),
        "QUIC frame parser error diagnostics must be non-empty"
    );

    match error {
        QuicFrameError::VarInt(_)
        | QuicFrameError::UnknownFrameType(_)
        | QuicFrameError::InvalidFormat(_)
        | QuicFrameError::UnexpectedEof
        | QuicFrameError::PayloadTooLarge { .. } => {}
    }
}
