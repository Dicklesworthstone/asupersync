#![no_main]

//! Encoder round trip for the in-house Zstandard codec (br-asupersync-t1fblr.11).
//!
//! The first byte chooses the level, the checksum and the streaming chunk
//! sizes. The rest is the plaintext. Every frame the encoder writes must:
//! - be the same on a second encode;
//! - declare its content size, and decode back to the plaintext under limits
//!   that allow exactly that many bytes;
//! - decode the same way through `StreamDecoder` in small chunks;
//! - be refused, not cut short, when the limit is one byte too small.

mod stream;

use asupersync_zstd::{DecodeLimits, EncodeParams, Level, decode_all, encode_all};
use libfuzzer_sys::fuzz_target;

/// The largest plaintext one case encodes, so every case stays fast.
const MAX_INPUT: usize = 256 << 10;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    if input.len() > MAX_INPUT {
        return;
    }
    let level = if selector & 1 == 0 {
        Level::Store
    } else {
        Level::Fast
    };
    let params = EncodeParams::new(level).with_checksum(selector & 2 != 0);
    let frame = encode_all(input, &params);
    assert_eq!(
        frame,
        encode_all(input, &params),
        "encoding is not deterministic"
    );

    let exact = DecodeLimits::new(input.len()).with_require_content_size(true);
    let decoded = decode_all(&frame, &exact)
        .unwrap_or_else(|error| panic!("{params:?} frame of {} bytes: {error:?}", input.len()));
    assert_eq!(decoded, input, "{params:?} round trip changed the data");

    let input_chunk = 1 + usize::from((selector >> 2) & 0x0f) * 61;
    let output_chunk = 1 + usize::from(selector >> 6) * 509;
    let streamed = stream::decode_in_chunks(&frame, exact, input_chunk, output_chunk)
        .unwrap_or_else(|error| panic!("{params:?} streamed: {error:?}"));
    assert_eq!(
        streamed, input,
        "{params:?} streamed round trip changed the data"
    );

    if let Some(short) = input.len().checked_sub(1) {
        assert!(
            decode_all(&frame, &DecodeLimits::new(short)).is_err(),
            "{params:?}: a limit one byte short must refuse the frame"
        );
    }
});
