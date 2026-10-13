//! Chunked `StreamDecoder` driver shared by the zstd fuzz targets.
//!
//! It checks the streaming contract on every call: each call that is offered
//! input or output space makes progress, reports no more than it was given,
//! and never takes the total past `max_output`.

use asupersync_zstd::{DecodeError, DecodeLimits, StreamDecoder, StreamStatus};

/// Decodes `wire` by feeding `input_chunk`-byte pieces into fresh
/// `output_chunk`-byte output buffers, then finishing the stream.
pub fn decode_in_chunks(
    wire: &[u8],
    limits: DecodeLimits,
    input_chunk: usize,
    output_chunk: usize,
) -> Result<Vec<u8>, DecodeError> {
    let mut decoder = StreamDecoder::new(limits);
    let mut decoded = Vec::new();
    let mut out = vec![0_u8; output_chunk];
    for chunk in wire.chunks(input_chunk) {
        let mut offset = 0;
        while offset < chunk.len() {
            let step = decoder.decode(&chunk[offset..], &mut out)?;
            assert!(
                step.input_read > 0 || step.output_written > 0,
                "the stream decoder made no progress with input pending: {step:?}"
            );
            assert!(step.input_read <= chunk.len() - offset);
            assert!(step.output_written <= out.len());
            offset += step.input_read;
            decoded.extend_from_slice(&out[..step.output_written]);
            assert!(
                decoded.len() <= limits.max_output,
                "streamed past max_output"
            );
        }
    }
    loop {
        let step = decoder.finish(&mut out)?;
        decoded.extend_from_slice(&out[..step.output_written]);
        assert!(
            decoded.len() <= limits.max_output,
            "finished past max_output"
        );
        if step.status == StreamStatus::Finished {
            return Ok(decoded);
        }
        assert_eq!(step.status, StreamStatus::NeedOutput, "{step:?}");
        assert!(step.output_written > 0, "finish made no progress: {step:?}");
    }
}
