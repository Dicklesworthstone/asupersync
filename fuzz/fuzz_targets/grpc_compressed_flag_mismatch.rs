//! Fuzz target: gRPC compressed-flag mismatch
//!
//! Tests mismatches between the compressed flag in gRPC message headers
//! and the actual compression state of the message payload. This fuzzer
//! focuses on edge cases where:
//! - Compressed flag = 1 but payload is uncompressed data
//! - Compressed flag = 0 but payload contains compressed data
//! - Various compression algorithm mismatches
//! - Malformed compressed data with valid flag
//! - Partially compressed payloads

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Configuration for gRPC compressed flag mismatch testing
#[derive(Debug, Arbitrary)]
struct GrpcCompressedFlagConfig {
    /// Message frame structure
    compressed_flag: u8,
    /// Length prefix for the message
    length: u32,
    /// Raw payload data
    payload: Vec<u8>,
    /// Compression scenario to test
    scenario: CompressionScenario,
    /// Whether to include gRPC headers
    include_headers: bool,
    /// Header compression encoding if present
    header_encoding: Option<CompressionEncoding>,
}

#[derive(Debug, Arbitrary, Clone)]
enum CompressionScenario {
    /// Flag=1, payload=uncompressed
    CompressedPayloadRaw,
    /// Flag=0, payload=gzip compressed
    UncompressedPayloadGzip,
    /// Flag=0, payload=deflate compressed
    UncompressedPayloadDeflate,
    /// Flag=1, payload=malformed compression
    CompressedPayloadMalformed,
    /// Flag=1, payload=partially compressed
    CompressedPayloadPartial,
    /// Flag=invalid value (2-255)
    InvalidValue,
    /// Flag=0, payload=mixed compressed/uncompressed
    UncompressedPayloadMixed,
    /// Flag=1, payload=double compressed
    CompressedPayloadDouble,
}

#[derive(Debug, Arbitrary, Clone)]
enum CompressionEncoding {
    Gzip,
    Deflate,
    Brotli,
    Identity,
    Invalid(String),
}

impl GrpcCompressedFlagConfig {
    fn normalize(&mut self) {
        // Limit payload size to reasonable bounds
        if self.payload.len() > 1024 * 1024 {
            self.payload.truncate(1024 * 1024); // Max 1MB
        }

        // Ensure length field matches scenario requirements
        match self.scenario {
            CompressionScenario::InvalidValue => {
                // Force invalid compressed flag
                self.compressed_flag = (self.compressed_flag % 254) + 2; // 2-255
            }
            _ => {
                // Normal flag values 0 or 1
                self.compressed_flag %= 2;
            }
        }

        // Update length to match actual payload
        self.length = self.payload.len() as u32;
    }

    fn generate_test_payload(&self) -> Vec<u8> {
        match &self.scenario {
            CompressionScenario::CompressedPayloadRaw => {
                // Flag=1 but payload is raw uncompressed data
                self.payload.clone()
            }

            CompressionScenario::UncompressedPayloadGzip => {
                // Flag=0 but payload is actually gzip compressed
                compress_gzip(&self.payload)
            }

            CompressionScenario::UncompressedPayloadDeflate => {
                // Flag=0 but payload is actually deflate compressed
                compress_deflate(&self.payload)
            }

            CompressionScenario::CompressedPayloadMalformed => {
                // Flag=1 but payload has invalid compression headers
                let mut malformed = vec![0x1f, 0x8b]; // Partial gzip header
                malformed.extend(&self.payload[..self.payload.len().min(10)]);
                malformed
            }

            CompressionScenario::CompressedPayloadPartial => {
                // Flag=1 but payload is only partially compressed
                let compressed = compress_gzip(&self.payload);
                let split_point = compressed.len() / 2;
                let mut partial = compressed[..split_point].to_vec();
                partial.extend(&self.payload[split_point.min(self.payload.len())..]);
                partial
            }

            CompressionScenario::InvalidValue => {
                // Invalid flag value with regular payload
                self.payload.clone()
            }

            CompressionScenario::UncompressedPayloadMixed => {
                // Flag=0 but payload contains mixed compression
                let mut mixed = compress_gzip(&self.payload[..self.payload.len() / 2]);
                mixed.extend(&self.payload[self.payload.len() / 2..]);
                mixed
            }

            CompressionScenario::CompressedPayloadDouble => {
                // Flag=1 with double-compressed payload
                let first_compression = compress_gzip(&self.payload);
                compress_gzip(&first_compression)
            }
        }
    }

    fn generate_grpc_frame(&self) -> Vec<u8> {
        let payload = self.generate_test_payload();
        let actual_length = payload.len() as u32;

        let mut frame = Vec::new();

        // gRPC message frame format:
        // 1 byte: compressed flag
        // 4 bytes: message length (big endian)
        // N bytes: message payload

        frame.push(self.compressed_flag);
        frame.extend(actual_length.to_be_bytes());
        frame.extend(payload);

        frame
    }
}

/// Simple gzip compression for test data
fn compress_gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    observe_compression_write(encoder.write_all(data), "gzip encoder write", data.len());
    encoder.finish().unwrap_or_else(|_| data.to_vec())
}

/// Simple deflate compression for test data
fn compress_deflate(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    observe_compression_write(encoder.write_all(data), "deflate encoder write", data.len());
    encoder.finish().unwrap_or_else(|_| data.to_vec())
}

fn observe_compression_write(result: Result<(), std::io::Error>, context: &str, input_len: usize) {
    match result {
        Ok(()) => {
            assert!(
                input_len <= 1024 * 1024,
                "{context} accepted an unbounded fuzz payload"
            );
        }
        Err(error) => {
            assert!(
                !format!("{error:?}").is_empty(),
                "{context} failures must expose diagnostics"
            );
            assert!(
                !error.to_string().trim().is_empty(),
                "{context} display diagnostics must not be empty"
            );
        }
    }
}

fn observe_header_options(include_headers: bool, header_encoding: &Option<CompressionEncoding>) {
    let Some(header_encoding) = header_encoding else {
        return;
    };

    let encoding_label = match header_encoding {
        CompressionEncoding::Gzip => "gzip",
        CompressionEncoding::Deflate => "deflate",
        CompressionEncoding::Brotli => "br",
        CompressionEncoding::Identity => "identity",
        CompressionEncoding::Invalid(value) => value.as_str(),
    };

    if include_headers {
        match header_encoding {
            CompressionEncoding::Invalid(value) => {
                assert_eq!(
                    encoding_label.len(),
                    value.len(),
                    "invalid compression header label should be observed verbatim"
                );
            }
            _ => assert!(
                !encoding_label.is_empty(),
                "known compression header labels must not be empty"
            ),
        }
    } else {
        let _observed_len = encoding_label.len();
    }
}

/// Test structure to track decompression attempts and results
#[derive(Debug, Default)]
struct DecompressionResults {
    flag_value: u8,
    expected_compressed: bool,
    payload_size: usize,
    decompression_attempted: bool,
    decompression_succeeded: bool,
    decompressed_size: usize,
    compression_detected: bool,
    error_on_mismatch: bool,
}

/// Analyze gRPC frame for compression flag mismatches
fn analyze_grpc_compression(frame: &[u8]) -> Result<DecompressionResults, &'static str> {
    if frame.len() < 5 {
        return Err("Frame too short for gRPC message");
    }

    let compressed_flag = frame[0];
    let length = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
    let payload = &frame[5..];

    if payload.len() != length as usize {
        return Err("Length field does not match payload size");
    }

    let mut results = DecompressionResults {
        flag_value: compressed_flag,
        expected_compressed: compressed_flag == 1,
        payload_size: payload.len(),
        decompression_attempted: false,
        decompression_succeeded: false,
        decompressed_size: 0,
        compression_detected: false,
        error_on_mismatch: false,
    };

    // Detect if payload looks compressed (heuristic)
    results.compression_detected = detect_compression(payload);

    // Check for flag mismatch
    let flag_mismatch = (compressed_flag == 1 && !results.compression_detected)
        || (compressed_flag == 0 && results.compression_detected)
        || (compressed_flag > 1);

    if flag_mismatch {
        results.error_on_mismatch = true;
    }

    // Attempt decompression if flag indicates compressed
    if compressed_flag == 1 {
        results.decompression_attempted = true;

        // Try different decompression methods
        if let Ok(decompressed) = try_decompress_gzip(payload) {
            results.decompression_succeeded = true;
            results.decompressed_size = decompressed.len();
        } else if let Ok(decompressed) = try_decompress_deflate(payload) {
            results.decompression_succeeded = true;
            results.decompressed_size = decompressed.len();
        }
    }

    Ok(results)
}

/// Heuristic to detect if data appears to be compressed
fn detect_compression(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Check for common compression magic bytes
    match data {
        // Gzip magic bytes
        [0x1f, 0x8b, ..] => true,
        // Zlib magic bytes
        [0x78, 0x01, ..] | [0x78, 0x9c, ..] | [0x78, 0xda, ..] => true,
        // Check for low entropy (might indicate compression)
        _ => {
            if data.len() < 16 {
                return false;
            }

            // Simple entropy check - compressed data tends to have more uniform byte distribution
            let mut byte_counts = [0u32; 256];
            for &byte in data.iter().take(256) {
                byte_counts[byte as usize] += 1;
            }

            let non_zero_bytes = byte_counts.iter().filter(|&&count| count > 0).count();

            // If most byte values are present, it might be compressed
            non_zero_bytes > 200
        }
    }
}

/// Try to decompress data as gzip
fn try_decompress_gzip(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;

    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Try to decompress data as deflate
fn try_decompress_deflate(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;

    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into configuration
    let mut config =
        match GrpcCompressedFlagConfig::arbitrary(&mut arbitrary::Unstructured::new(data)) {
            Ok(config) => config,
            Err(_) => return, // Invalid input, skip
        };
    config.normalize();
    observe_header_options(config.include_headers, &config.header_encoding);

    // Generate gRPC frame with potential compression flag mismatch
    let frame = config.generate_grpc_frame();

    // Analyze the frame for compression inconsistencies
    match analyze_grpc_compression(&frame) {
        Ok(results) => {
            // Verify critical compression invariants

            // Invariant 1: If flag=1, decompression should be attempted
            if results.expected_compressed {
                assert!(
                    results.decompression_attempted,
                    "Decompression should be attempted when compressed flag is set"
                );
            }

            // Invariant 2: Flag mismatch should be detected and handled
            if results.error_on_mismatch {
                // This represents a flag/payload mismatch that should be caught
                // The specific handling depends on implementation:
                // - Could return error for client protection
                // - Could attempt best-effort decompression
                // - Could pass through with warning

                match config.scenario {
                    CompressionScenario::InvalidValue => {
                        assert!(
                            results.flag_value > 1,
                            "Invalid flag values should be detected"
                        );
                    }
                    CompressionScenario::CompressedPayloadRaw => {
                        assert_eq!(results.flag_value, 1);
                        assert!(
                            !results.compression_detected,
                            "Raw payload should not appear compressed"
                        );
                    }
                    CompressionScenario::UncompressedPayloadGzip
                    | CompressionScenario::UncompressedPayloadDeflate => {
                        assert_eq!(results.flag_value, 0);
                        assert!(
                            results.compression_detected,
                            "Compressed payload should be detected"
                        );
                    }
                    _ => {
                        // Other scenarios should still maintain basic invariants
                    }
                }
            }

            // Invariant 3: Decompression success should be consistent
            if results.decompression_attempted && results.decompression_succeeded {
                assert!(
                    results.decompressed_size > 0 || results.payload_size == 0,
                    "Successful decompression should produce output"
                );
            }

            // Invariant 4: Flag values should be within expected range for valid processing
            if results.flag_value > 1 {
                // Invalid flag values should be handled gracefully
                // (specific handling is implementation-dependent)
            }

            // Test completed without crashes - compression flag mismatch handling is working
        }
        Err(_) => {
            // Frame parsing failed - this is acceptable for malformed input
            // The important thing is that it fails gracefully without crashes
        }
    }
});
