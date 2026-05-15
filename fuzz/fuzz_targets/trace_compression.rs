#![no_main]

//! Fuzz target for trace file LZ4 compression/decompression.
//!
//! This target focuses on the LZ4 compression handling in trace files, including
//! decompression bomb detection, chunk size validation, and streaming decompression.
//! The trace file format supports optional LZ4 compression with defensive guards
//! against malicious compressed streams.

use libfuzzer_sys::fuzz_target;

const MAX_COMPRESSED_CHUNK_LEN: usize = 64 * 1024 * 1024;
const MAX_RAW_DECOMPRESSED_LEN: usize = 16 * 1024 * 1024;
const MAX_BLOCK_DECOMPRESSED_LEN: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    // Skip tiny inputs
    if data.len() < 4 {
        return;
    }

    // Limit input size to prevent timeout (64MB max - matches MAX_COMPRESSED_CHUNK_LEN)
    if data.len() > MAX_COMPRESSED_CHUNK_LEN {
        return;
    }

    // Test LZ4 decompression with size prefix
    // This is the main decompression path used in trace files
    // The first 4 bytes are expected to be the decompressed size as u32 little-endian
    match lz4_flex::decompress_size_prepended(data) {
        Ok(decompressed) => {
            // Successfully decompressed - test recompression to verify integrity
            let recompressed = lz4_flex::compress_prepend_size(&decompressed);
            let round_trip =
                lz4_flex::decompress_size_prepended(&recompressed).unwrap_or_else(|err| {
                    panic!(
                        "LZ4 prepended-size round trip failed after successful decompression: \
                         decompressed_len={}, err={err:?}",
                        decompressed.len()
                    )
                });
            assert_eq!(
                round_trip, decompressed,
                "LZ4 prepended-size recompression changed decompressed bytes"
            );
            assert_size_prepended_len(data, decompressed.len(), "initial prepended-size decode");

            // Test that decompressed size is reasonable (guard against decompression bombs)
            // The trace file parser has MAX_COMPRESSED_CHUNK_LEN = 64MB limit
            if decompressed.len() > MAX_COMPRESSED_CHUNK_LEN {
                // This would be caught by the trace parser's bounds checking
                return;
            }
        }
        Err(err) => observe_decompress_error(err, "initial prepended-size decode"),
    }

    // Test raw LZ4 decompression (no size prefix)
    if data.len() >= 8 {
        // Extract potential size from first 4 bytes
        let size_bytes = &data[0..4];
        let size = u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]])
            as usize;

        // Only attempt decompression if size is reasonable (prevent memory exhaustion)
        if size <= MAX_RAW_DECOMPRESSED_LEN {
            let compressed_data = &data[4..];
            observe_decompress_result(
                lz4_flex::decompress(compressed_data, size),
                "raw block decode from declared size",
                size,
            );
        }
    }

    // Test LZ4 block format decompression
    if data.len() > 4 {
        observe_decompress_result(
            lz4_flex::block::decompress(data, MAX_BLOCK_DECOMPRESSED_LEN),
            "bounded block decode",
            MAX_BLOCK_DECOMPRESSED_LEN,
        );
    }

    // Test compression of the input data to exercise the compression path
    if data.len() <= MAX_BLOCK_DECOMPRESSED_LEN {
        // Reasonable size for compression testing
        let compressed = lz4_flex::compress(data);
        let decompressed = lz4_flex::decompress(&compressed, data.len()).unwrap_or_else(|err| {
            panic!(
                "LZ4 block decompression failed after successful compression: \
                 input_len={}, compressed_len={}, err={err:?}",
                data.len(),
                compressed.len()
            )
        });
        assert_eq!(
            decompressed, data,
            "LZ4 block compression round trip changed input bytes"
        );

        let compressed_with_size = lz4_flex::compress_prepend_size(data);
        let decompressed_with_size = lz4_flex::decompress_size_prepended(&compressed_with_size)
            .unwrap_or_else(|err| {
                panic!(
                    "LZ4 prepended-size decompression failed after successful compression: \
                     input_len={}, compressed_len={}, err={err:?}",
                    data.len(),
                    compressed_with_size.len()
                )
            });
        assert_eq!(
            decompressed_with_size, data,
            "LZ4 prepended-size compression round trip changed input bytes"
        );
    }

    // Test various size prefix manipulations to catch integer overflow/underflow
    if data.len() >= 8 {
        let mut modified = data.to_vec();

        // Test with maximum u32 size (potential integer overflow)
        modified[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        observe_size_prepended_decode(&modified, "u32::MAX size prefix");

        // Test with zero size
        modified[0..4].copy_from_slice(&0u32.to_le_bytes());
        observe_size_prepended_decode(&modified, "zero size prefix");

        // Test with size larger than remaining data
        if data.len() > 8 {
            let large_size = (data.len() * 10) as u32;
            modified[0..4].copy_from_slice(&large_size.to_le_bytes());
            observe_size_prepended_decode(&modified, "oversized relative size prefix");
        }
    }

    // Test streaming scenarios with partial data
    if data.len() > 20 {
        for chunk_size in [4, 8, 16, data.len() / 3] {
            if chunk_size < data.len() {
                for start in (0..data.len()).step_by(chunk_size) {
                    let end = (start + chunk_size).min(data.len());
                    let chunk = &data[start..end];
                    if chunk.len() >= 4 {
                        observe_size_prepended_decode(chunk, "partial chunk prepended-size decode");
                    }
                }
            }
        }
    }
});

fn observe_size_prepended_decode(data: &[u8], context: &str) {
    match lz4_flex::decompress_size_prepended(data) {
        Ok(decompressed) => {
            assert_size_prepended_len(data, decompressed.len(), context);
            assert!(
                decompressed.len() <= MAX_COMPRESSED_CHUNK_LEN,
                "{context} produced {} bytes, above trace chunk bound {}",
                decompressed.len(),
                MAX_COMPRESSED_CHUNK_LEN
            );
        }
        Err(err) => observe_decompress_error(err, context),
    }
}

fn observe_decompress_result<E: core::fmt::Debug>(
    result: Result<Vec<u8>, E>,
    context: &str,
    max_decompressed_len: usize,
) {
    match result {
        Ok(decompressed) => {
            assert!(
                decompressed.len() <= max_decompressed_len,
                "{context} produced {} bytes, above expected bound {}",
                decompressed.len(),
                max_decompressed_len
            );
        }
        Err(err) => observe_decompress_error(err, context),
    }
}

fn observe_decompress_error<E: core::fmt::Debug>(err: E, context: &str) {
    let err_debug = format!("{err:?}");
    assert!(
        !err_debug.is_empty(),
        "{context} returned an empty decompression error"
    );
}

fn assert_size_prepended_len(data: &[u8], decompressed_len: usize, context: &str) {
    debug_assert!(data.len() >= 4);
    let declared_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    assert_eq!(
        decompressed_len, declared_len,
        "{context} produced {decompressed_len} bytes but declared {declared_len}"
    );
}
