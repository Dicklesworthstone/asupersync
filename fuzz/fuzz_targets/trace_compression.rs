#![no_main]

//! Fuzz target for trace file LZ4 compression/decompression.
//!
//! This target focuses on the LZ4 compression handling in trace files, including
//! decompression bomb detection, chunk size validation, and streaming decompression.
//! The trace file format supports optional LZ4 compression with defensive guards
//! against malicious compressed streams.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip tiny inputs
    if data.len() < 4 {
        return;
    }

    // Limit input size to prevent timeout (64MB max - matches MAX_COMPRESSED_CHUNK_LEN)
    if data.len() > 64 * 1024 * 1024 {
        return;
    }

    // Test LZ4 decompression with size prefix
    // This is the main decompression path used in trace files
    // The first 4 bytes are expected to be the decompressed size as u32 little-endian
    match lz4_flex::decompress_size_prepended(data) {
        Ok(decompressed) => {
            // Successfully decompressed - test recompression to verify integrity
            match lz4_flex::compress_prepend_size(&decompressed) {
                Ok(recompressed) => {
                    // Test round-trip by decompressing again
                    let _ = lz4_flex::decompress_size_prepended(&recompressed);
                }
                Err(_) => {
                    // Compression error
                }
            }

            // Test that decompressed size is reasonable (guard against decompression bombs)
            // The trace file parser has MAX_COMPRESSED_CHUNK_LEN = 64MB limit
            if decompressed.len() > 64 * 1024 * 1024 {
                // This would be caught by the trace parser's bounds checking
                return;
            }
        }
        Err(_) => {
            // Decompression error is expected for malformed input
        }
    }

    // Test raw LZ4 decompression (no size prefix)
    if data.len() >= 8 {
        // Extract potential size from first 4 bytes
        let size_bytes = &data[0..4];
        let size = u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]])
            as usize;

        // Only attempt decompression if size is reasonable (prevent memory exhaustion)
        if size <= 16 * 1024 * 1024 {
            let compressed_data = &data[4..];
            let _ = lz4_flex::decompress(compressed_data, size);
        }
    }

    // Test LZ4 block format decompression
    if data.len() > 4 {
        let _ = lz4_flex::block::decompress(data, 1024 * 1024);
    }

    // Test compression of the input data to exercise the compression path
    if data.len() <= 1024 * 1024 {
        // Reasonable size for compression testing
        match lz4_flex::compress(data) {
            Ok(compressed) => {
                // Test decompression of freshly compressed data
                let _ = lz4_flex::decompress(&compressed, data.len());
                let _ = lz4_flex::decompress_size_prepended(
                    &lz4_flex::compress_prepend_size(data).unwrap_or_default(),
                );
            }
            Err(_) => {
                // Compression error
            }
        }

        // Test with prepended size
        if let Ok(compressed_with_size) = lz4_flex::compress_prepend_size(data) {
            let _ = lz4_flex::decompress_size_prepended(&compressed_with_size);
        }
    }

    // Test various size prefix manipulations to catch integer overflow/underflow
    if data.len() >= 8 {
        let mut modified = data.to_vec();

        // Test with maximum u32 size (potential integer overflow)
        modified[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        let _ = lz4_flex::decompress_size_prepended(&modified);

        // Test with zero size
        modified[0..4].copy_from_slice(&0u32.to_le_bytes());
        let _ = lz4_flex::decompress_size_prepended(&modified);

        // Test with size larger than remaining data
        if data.len() > 8 {
            let large_size = (data.len() * 10) as u32;
            modified[0..4].copy_from_slice(&large_size.to_le_bytes());
            let _ = lz4_flex::decompress_size_prepended(&modified);
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
                        let _ = lz4_flex::decompress_size_prepended(chunk);
                    }
                }
            }
        }
    }
});
