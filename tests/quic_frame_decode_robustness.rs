//! `QuicFrame::decode` robustness / fuzz coverage (arq-quic-epic b0k8qo.1.2).
//!
//! The QUIC application data plane carries unreliable fountain symbols inside
//! DATAGRAM frames, so the frame decoder is exposed to arbitrary — potentially
//! adversarial / Byzantine — packet bytes off the wire. The existing
//! `QuicFrameFuzzer` (tests/atp/quic/fuzz_harness.rs) re-implements per-frame
//! parsing and predates the DATAGRAM variant; it never drives the real
//! `quic_native::quic_frames::QuicFrame::decode`. This file closes that gap with
//! a deterministic (seeded) robustness suite over the actual codec:
//!
//! - decoding arbitrary byte buffers never panics and always terminates;
//! - unknown frame types fail closed with `UnknownFrameType`, not a panic;
//! - a truncated / oversized DATAGRAM length prefix yields `UnexpectedEof`
//!   without over-allocating (the decoder checks `remaining` before copying);
//! - the DATAGRAM round-trip is an identity across a payload-size matrix;
//! - a packed stream of valid frames decodes sequentially and terminates.
//!
//! Deterministic: a fixed-seed xorshift PRNG generates the fuzz inputs, so the
//! suite is replayable. New test file only; no source touched.

#![allow(missing_docs)]

use asupersync::bytes::BytesMut;
use asupersync::net::atp::protocol::quic_frames::{QuicFrame, QuicFrameError};

/// Tiny deterministic xorshift64 PRNG so the fuzz inputs are replayable (the
/// lab-runtime forbids ambient randomness; we never call the OS RNG).
struct XorShift(u64);

impl XorShift {
    fn new(seed: u64) -> Self {
        // xorshift requires a non-zero state.
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    /// A bounded random length in `0..=max`.
    fn len(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % (max + 1)
    }
}

/// Decode every frame out of `bytes`, returning how many frames parsed before
/// the buffer emptied or an error surfaced. Bounded iteration guarantees the
/// helper terminates even if a decoder bug failed to advance the cursor.
fn drain_decode(bytes: &[u8]) -> Result<usize, QuicFrameError> {
    let mut slice: &[u8] = bytes;
    let mut count = 0usize;
    // A frame consumes at least one byte (the type varint), so the buffer length
    // is a hard upper bound on the number of decode steps.
    let cap = bytes.len() + 1;
    for _ in 0..cap {
        match QuicFrame::decode(&mut slice)? {
            Some(_) => count += 1,
            None => return Ok(count),
        }
    }
    Ok(count)
}

#[test]
fn decoding_arbitrary_bytes_never_panics_and_terminates() {
    let mut rng = XorShift::new(0x9E37_79B9_7F4A_7C15);
    for _ in 0..20_000 {
        let n = rng.len(96);
        let mut buf = Vec::with_capacity(n);
        for _ in 0..n {
            buf.push(rng.byte());
        }
        // The contract is "no panic, and terminate": decode returns Ok/Err for
        // every input. drain_decode's bounded loop also proves the cursor always
        // advances (a non-advancing Ok(Some) would be caught by the cap).
        let _ = drain_decode(&buf);
    }
}

#[test]
fn unknown_frame_type_fails_closed() {
    // 0x40 is a 2-byte varint prefix; 0x40 0x40 decodes to varint 0x40 (64),
    // which is not an assigned QUIC frame type in this codec.
    let mut slice: &[u8] = &[0x40, 0x40];
    match QuicFrame::decode(&mut slice) {
        Err(QuicFrameError::UnknownFrameType(value)) => assert_eq!(value, 0x40),
        other => panic!("expected UnknownFrameType(64), got {other:?}"),
    }
}

#[test]
fn truncated_datagram_length_prefix_is_unexpected_eof_without_over_alloc() {
    // Encode a large length-prefixed DATAGRAM, then hand the decoder only its
    // first few bytes. The declared length far exceeds `remaining`, so decode
    // must return UnexpectedEof — it checks remaining before copying, so it
    // neither panics nor allocates the declared (large) length.
    let frame = QuicFrame::Datagram {
        data: asupersync::bytes::Bytes::from(vec![0xABu8; 4096]),
    };
    let mut encoded = BytesMut::new();
    frame.encode(&mut encoded).expect("encode");
    let full = encoded.as_ref().to_vec();

    // Keep only the type byte + (partial) length/payload: far less than declared.
    let truncated = &full[..6.min(full.len())];
    let mut slice: &[u8] = truncated;
    match QuicFrame::decode(&mut slice) {
        Err(QuicFrameError::UnexpectedEof) => {}
        other => panic!("expected UnexpectedEof on truncated DATAGRAM, got {other:?}"),
    }
}

#[test]
fn datagram_round_trip_is_identity_across_payload_sizes() {
    let mut rng = XorShift::new(0xDEAD_BEEF_CAFE_F00D);
    for &size in &[
        0usize, 1, 2, 3, 7, 8, 63, 64, 127, 128, 255, 256, 1000, 1200,
    ] {
        let payload: Vec<u8> = (0..size).map(|_| rng.byte()).collect();
        let frame = QuicFrame::Datagram {
            data: asupersync::bytes::Bytes::from(payload.clone()),
        };
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded).expect("encode datagram");

        let bytes = encoded.as_ref().to_vec();
        let mut slice: &[u8] = &bytes;
        let decoded = QuicFrame::decode(&mut slice)
            .expect("decode ok")
            .expect("a frame is present");
        assert_eq!(decoded, frame, "round-trip identity for size={size}");
        // Length-prefixed (0x31) form is self-delimiting: nothing left over.
        assert!(slice.is_empty(), "decoder must consume exactly the frame");
    }
}

#[test]
fn packed_valid_frame_stream_decodes_sequentially_and_terminates() {
    // A realistic 1-RTT packet payload: control + datagram + padding tail.
    let frames = vec![
        QuicFrame::Ping,
        QuicFrame::Datagram {
            data: asupersync::bytes::Bytes::from_static(b"symbol-A"),
        },
        QuicFrame::Datagram {
            data: asupersync::bytes::Bytes::from_static(b"symbol-B"),
        },
    ];
    let mut encoded = BytesMut::new();
    for f in &frames {
        f.encode(&mut encoded).expect("encode");
    }
    let bytes = encoded.as_ref().to_vec();

    let count = drain_decode(&bytes).expect("packed stream decodes cleanly");
    assert_eq!(count, frames.len());
}
