#![no_main]

//! Cargo-fuzz target for `gzip_frame_decompress` — the gRPC
//! Content-Encoding=gzip decompression entry point in
//! `asupersync::grpc::codec`.
//!
//! gRPC peers can negotiate `gzip` per the registered compression
//! algorithms list, and any HEADERS+DATA stream that advertises
//! `grpc-encoding: gzip` flows the body through this function. The
//! body comes straight off the wire, so adversarial inputs are the
//! norm; a panic here is a remote DoS, an unbounded
//! decompression-bomb is a remote OOM, and a malformed-trailer
//! that returns Ok with a truncated payload silently corrupts the
//! peer's view of the message.
//!
//! Properties pinned per fuzz iteration:
//!
//!   1. **No panic.** Every input — well-formed gzip, raw garbage,
//!      half-trimmed trailers, byte-flipped magic — must produce
//!      either Ok(bytes) or Err(GrpcError). Never unwind.
//!
//!   2. **Bomb rejection.** When the decompressed output would
//!      exceed the supplied `max_size`, decompression MUST stop
//!      and return `GrpcError::MessageTooLarge` BEFORE the output
//!      buffer crosses that bound. The fuzzer asserts the invariant
//!      `output.len() <= max_size` on the success branch — a
//!      regression that lets the buffer grow past the cap before
//!      checking would surface as that bound being violated.
//!
//!   3. **Malformed trailer rejection.** A gzip stream missing or
//!      damaging its 8-byte trailer (CRC32 + ISIZE) MUST surface as
//!      Err — never as silent-truncation Ok. The fuzzer feeds the
//!      decompressor truncated-trailer streams (well-formed body
//!      with the last 1..=8 bytes lopped off) and asserts Err is
//!      returned.
//!
//!   4. **Round-trip identity on the well-formed lane.** Compressing
//!      a payload via `gzip_frame_compress` and immediately
//!      decompressing must reproduce the original bytes. Pins the
//!      "no information loss in the absence of adversarial input"
//!      contract that all the corner cases ride on.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_gzip_decompress -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::grpc::{gzip_frame_compress, gzip_frame_decompress};
use libfuzzer_sys::fuzz_target;

/// Per-iteration cap on raw input size. The decompression bomb
/// defense is the value-under-test; the harness still bounds input
/// so libFuzzer cannot hand us arbitrarily-large blobs and turn
/// the harness itself into a memory hog.
const MAX_INPUT_LEN: usize = 64 * 1024;

/// max_size handed to the decompressor. Tight enough that realistic
/// fuzz inputs reach the MessageTooLarge path on bomb-shaped streams.
const DECOMPRESS_MAX: usize = 32 * 1024;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    /// Raw bytes — exercises the magic-byte / header / inflater /
    /// trailer paths via libFuzzer's mutation hill-climb.
    RawGzipStream(Vec<u8>),

    /// A payload that the harness will compress on the FORWARD path
    /// and then feed back into the decompressor. The asserted
    /// property is round-trip identity within the cap.
    WellFormedRoundTrip(Vec<u8>),

    /// A well-formed compressed stream with the last 1..=8 bytes
    /// chopped off — that's the gzip trailer's CRC32 + ISIZE
    /// region. flate2 must surface a typed error rather than
    /// returning Ok with the partial payload.
    TruncatedTrailer { payload: Vec<u8>, chop_bytes: u8 },

    /// Header tweaks: flip the magic bytes (1F 8B at offsets 0..2)
    /// or the compression-method byte (0x08 at offset 2). The
    /// decompressor must reject these; never panic, never silently
    /// succeed.
    CorruptHeader {
        payload: Vec<u8>,
        offset: u8,
        xor: u8,
    },
}

fn truncated(bytes: &[u8], cap: usize) -> Vec<u8> {
    bytes.iter().take(cap).copied().collect()
}

fuzz_target!(|input: FuzzInput| {
    match input {
        FuzzInput::RawGzipStream(bytes) => {
            let bytes = truncated(&bytes, MAX_INPUT_LEN);
            let result = gzip_frame_decompress(Bytes::from(bytes), DECOMPRESS_MAX);
            // Property 1 + 2: no panic; Ok output is bounded by max_size.
            if let Ok(out) = result {
                assert!(
                    out.len() <= DECOMPRESS_MAX,
                    "bomb defense: gzip_frame_decompress returned {} bytes \
                     but max_size was {DECOMPRESS_MAX} — bomb-cap was crossed",
                    out.len(),
                );
            }
            // Err is allowed; it must be a typed GrpcError, which the
            // signature already guarantees.
        }
        FuzzInput::WellFormedRoundTrip(payload) => {
            let payload = truncated(&payload, DECOMPRESS_MAX / 2);
            let compressed = match gzip_frame_compress(Bytes::from(payload.clone())) {
                Ok(c) => c,
                // Compression itself can return Err on out-of-memory or
                // other wrap conditions — that's not a fuzz finding.
                Err(_) => return,
            };
            // The compressed output for a well-formed payload that fits
            // within DECOMPRESS_MAX must round-trip cleanly.
            let decompressed = gzip_frame_decompress(compressed, DECOMPRESS_MAX)
                .expect("well-formed gzip round-trip must succeed");
            assert_eq!(
                decompressed.as_ref(),
                payload.as_slice(),
                "round-trip identity broken: gzip(payload) → decompressed != payload",
            );
        }
        FuzzInput::TruncatedTrailer {
            payload,
            chop_bytes,
        } => {
            let payload = truncated(&payload, DECOMPRESS_MAX / 2);
            let compressed = match gzip_frame_compress(Bytes::from(payload.clone())) {
                Ok(c) => c,
                Err(_) => return,
            };
            // chop 1..=8 bytes off the end. The gzip trailer is exactly
            // 8 bytes (CRC32 + ISIZE), so 1..=8 lands inside it and
            // produces a structurally invalid stream.
            let chop = (chop_bytes % 8) as usize + 1;
            if compressed.len() <= chop {
                return;
            }
            let truncated_bytes = compressed[..compressed.len() - chop].to_vec();
            let result = gzip_frame_decompress(Bytes::from(truncated_bytes), DECOMPRESS_MAX);
            // Property 3: malformed trailer must NOT silently succeed.
            assert!(
                result.is_err(),
                "truncated-trailer (chop={chop}) gzip stream produced Ok — \
                 silent truncation would let an attacker tail-strip a real \
                 message and have the peer see a shortened payload",
            );
        }
        FuzzInput::CorruptHeader {
            payload,
            offset,
            xor,
        } => {
            let payload = truncated(&payload, DECOMPRESS_MAX / 2);
            let compressed = match gzip_frame_compress(Bytes::from(payload)) {
                Ok(c) => c,
                Err(_) => return,
            };
            let mut buf = compressed.to_vec();
            // Flip a byte in the first 10 (gzip header is 10 bytes
            // minimum: 2 magic + method + flags + 4 mtime + xfl + os).
            // xor=0 would be a no-op so force at least one bit.
            let off = (offset as usize) % 10;
            if off < buf.len() {
                buf[off] ^= xor.max(1);
            }
            let result = gzip_frame_decompress(Bytes::from(buf), DECOMPRESS_MAX);
            // Property 1 (still): no panic. Header corruption usually
            // produces Err, but a flip in mtime / os / xfl might still
            // decode — we don't assert Err on this lane (those bytes
            // are non-essential), only no-panic + the bomb cap.
            if let Ok(out) = result {
                assert!(
                    out.len() <= DECOMPRESS_MAX,
                    "header-corruption Ok-path returned {} bytes > {DECOMPRESS_MAX}",
                    out.len(),
                );
            }
        }
    }
});
