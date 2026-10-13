#![no_main]

//! Untrusted input for the in-house Zstandard decoder (br-asupersync-t1fblr.11).
//!
//! The first seven bytes choose the limits and the streaming chunk sizes. The
//! rest is the frame data. For every input:
//! - nothing panics;
//! - no entry point produces more than `max_output` bytes;
//! - `decode_all`, `decode_into` (with a `max_output`-byte buffer) and
//!   `StreamDecoder` (fed in the chosen input and output chunks) accept the same
//!   inputs and produce the same bytes.

mod stream;

use asupersync_zstd::{DecodeError, DecodeLimits, decode_all, decode_into};
use libfuzzer_sys::fuzz_target;

/// The largest output one case may allow, so every case stays fast.
const MAX_OUTPUT: usize = 1 << 20;

fn summary(result: &Result<Vec<u8>, DecodeError>) -> String {
    match result {
        Ok(bytes) => format!("Ok({} bytes)", bytes.len()),
        Err(error) => format!("Err({error:?})"),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((header, frame)) = data.split_first_chunk::<7>() else {
        return;
    };
    let max_output =
        (usize::from(header[1]) | (usize::from(header[2]) << 8) | (usize::from(header[3]) << 16))
            % (MAX_OUTPUT + 1);
    let limits = DecodeLimits {
        max_output,
        // 1 KiB through the default 8 MiB.
        max_window: 1 << (10 + header[4] % 14),
        require_content_size: header[0] & 1 != 0,
        allow_skippable_frames: header[0] & 2 != 0,
    };
    let input_chunk = 1 + usize::from(header[5]);
    let output_chunk = 1 + usize::from(header[6]);

    let one_shot = decode_all(frame, &limits);
    if let Ok(bytes) = &one_shot {
        assert!(bytes.len() <= max_output, "decode_all exceeded max_output");
    }

    let mut buffer = vec![0_u8; max_output];
    let buffered = decode_into(frame, &mut buffer, &limits).map(|n| buffer[..n].to_vec());
    match (&one_shot, &buffered) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "decode_all and decode_into produced different bytes"),
        (Err(_), Err(_)) => {}
        _ => panic!(
            "decode_all {} and decode_into {} disagree",
            summary(&one_shot),
            summary(&buffered)
        ),
    }

    let streamed = stream::decode_in_chunks(frame, limits, input_chunk, output_chunk);
    match (&one_shot, &streamed) {
        (Ok(a), Ok(b)) => assert_eq!(
            a, b,
            "decode_all and StreamDecoder produced different bytes"
        ),
        (Err(_), Err(_)) => {}
        _ => panic!(
            "decode_all {} and StreamDecoder {} disagree (input chunk {input_chunk}, output chunk {output_chunk})",
            summary(&one_shot),
            summary(&streamed)
        ),
    }
});
