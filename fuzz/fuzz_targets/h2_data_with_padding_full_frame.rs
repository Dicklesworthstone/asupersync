#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::{Frame, FrameCodec};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame header length per RFC 7540 §4.1
const FRAME_HEADER_LEN: usize = 9;

/// HTTP/2 DATA frame type per RFC 7540 §6.1
const DATA_FRAME_TYPE: u8 = 0x0;

/// DATA frame flags per RFC 7540 §6.1
const PADDED_FLAG: u8 = 0x8;
const END_STREAM_FLAG: u8 = 0x1;

/// A fully-padded DATA payload is one pad-length byte plus at most 255 padding bytes.
const MAX_FULLY_PADDED_DATA_PAYLOAD_LEN: u32 = 1 + u8::MAX as u32;

/// Default maximum frame size per RFC 7540 §6.5.2
const DEFAULT_MAX_FRAME_SIZE: u32 = 16384; // 2^14

/// Maximum allowed frame size per RFC 7540 §6.5.2
const MAX_FRAME_SIZE_LIMIT: u32 = 16777215; // 2^24 - 1

/// DATA frame parsing result
#[derive(Debug, PartialEq)]
enum DataFrameParseResult {
    /// Successfully parsed DATA frame
    Valid {
        stream_id: u32,
        flags: u8,
        data_payload: Vec<u8>,
        pad_length: Option<u8>,
        total_frame_size: u32,
        actual_data_size: usize,
        padding_size: usize,
    },
    /// Protocol error - invalid padding configuration
    ProtocolError(String),
    /// Frame size error
    FrameSizeError,
    /// Incomplete frame data
    IncompleteFrame,
    /// Invalid stream ID (0 for DATA frame)
    InvalidStreamId,
}

/// HTTP/2 frame header per RFC 7540 §4.1
#[derive(Debug, Clone)]
struct FrameHeader {
    length: u32,    // 24-bit length
    frame_type: u8, // 8-bit type
    flags: u8,      // 8-bit flags
    stream_id: u32, // 31-bit stream ID
}

impl FrameHeader {
    fn encode(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];

        // Length (24 bits, big-endian)
        buf[0] = (self.length >> 16) as u8;
        buf[1] = (self.length >> 8) as u8;
        buf[2] = self.length as u8;

        // Type and flags
        buf[3] = self.frame_type;
        buf[4] = self.flags;

        // Stream ID (31 bits + reserved bit, big-endian)
        let stream_id = self.stream_id & 0x7FFF_FFFF;
        buf[5] = (stream_id >> 24) as u8;
        buf[6] = (stream_id >> 16) as u8;
        buf[7] = (stream_id >> 8) as u8;
        buf[8] = stream_id as u8;

        buf
    }

    fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 9 {
            return Err("incomplete header");
        }

        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);

        let frame_type = buf[3];
        let flags = buf[4];

        let stream_id = ((buf[5] as u32 & 0x7F) << 24)
            | ((buf[6] as u32) << 16)
            | ((buf[7] as u32) << 8)
            | (buf[8] as u32);

        Ok(FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }
}

/// Live HTTP/2 DATA frame parser focused on padding edge cases.
struct LiveH2DataPaddingParser {
    max_frame_size: u32,
}

impl LiveH2DataPaddingParser {
    fn with_max_frame_size(max_frame_size: u32) -> Self {
        Self { max_frame_size }
    }

    fn legal_fully_padded_payload_len(&self, requested_frame_size: u32) -> u32 {
        requested_frame_size
            .max(1)
            .min(self.max_frame_size)
            .min(MAX_FULLY_PADDED_DATA_PAYLOAD_LEN)
    }

    /// Parse DATA frame with strict padding validation per RFC 7540 §6.1
    ///
    /// Key rules for DATA frame padding:
    /// - If PADDED flag set, first byte is pad length (0-255)
    /// - Pad length must not be greater than the length of the remainder of the frame
    /// - Actual data = frame_length - 1 (pad_length_byte) - pad_length (padding bytes)
    /// - Edge case: pad_length_byte + pad_length = frame_length → 0 data bytes (legal!)
    fn parse_data_frame(&self, buf: &[u8]) -> DataFrameParseResult {
        let header = match FrameHeader::decode(buf) {
            Ok(h) => h,
            Err(_) => return DataFrameParseResult::IncompleteFrame,
        };

        if header.frame_type != DATA_FRAME_TYPE {
            return DataFrameParseResult::ProtocolError(format!(
                "Expected DATA frame (0x0), got 0x{:x}",
                header.frame_type
            ));
        }

        if header.stream_id == 0 {
            return DataFrameParseResult::InvalidStreamId;
        }

        if header.length > self.max_frame_size {
            return DataFrameParseResult::FrameSizeError;
        }

        let total_len = FRAME_HEADER_LEN + header.length as usize;
        if buf.len() < total_len {
            return DataFrameParseResult::IncompleteFrame;
        }

        let payload = &buf[FRAME_HEADER_LEN..total_len];
        let expected_pad_length = if (header.flags & PADDED_FLAG) != 0 {
            payload.first().copied()
        } else {
            None
        };

        let mut wire = BytesMut::from(&buf[..total_len]);
        let mut codec = FrameCodec::new();
        codec.set_max_frame_size(self.max_frame_size);

        let decoded = match codec.decode(&mut wire) {
            Ok(Some(Frame::Data(frame))) => frame,
            Ok(Some(other)) => {
                return DataFrameParseResult::ProtocolError(format!(
                    "Expected DATA frame, decoded {other:?}"
                ));
            }
            Ok(None) => return DataFrameParseResult::IncompleteFrame,
            Err(err) if err.code == ErrorCode::FrameSizeError => {
                return DataFrameParseResult::FrameSizeError;
            }
            Err(err) => return DataFrameParseResult::ProtocolError(err.message),
        };

        let actual_data_size = decoded.data.len();
        let padding_size = expected_pad_length.map_or(0, usize::from);

        if let Some(pad_len) = expected_pad_length {
            let payload_accounting = 1 + actual_data_size + usize::from(pad_len);
            assert_eq!(
                payload_accounting, header.length as usize,
                "live DATA parser returned inconsistent padding accounting"
            );
        }

        DataFrameParseResult::Valid {
            stream_id: decoded.stream_id,
            flags: header.flags,
            data_payload: decoded.data.to_vec(),
            pad_length: expected_pad_length,
            total_frame_size: header.length,
            actual_data_size,
            padding_size,
        }
    }

    /// Create a fully-padded DATA frame for testing
    fn create_fully_padded_frame(
        &self,
        stream_id: u32,
        frame_size: u32,
        end_stream: bool,
    ) -> Vec<u8> {
        // Frame size must be at least 1 for the pad_length byte, and fully-padded DATA
        // cannot exceed the one-byte pad-length encoding limit.
        let frame_size = self.legal_fully_padded_payload_len(frame_size);

        // For fully-padded frame: pad_length = frame_size - 1 (subtract pad_length byte itself)
        let pad_length = (frame_size - 1) as u8;

        // Build frame header
        let mut flags = PADDED_FLAG;
        if end_stream {
            flags |= END_STREAM_FLAG;
        }

        let header = FrameHeader {
            length: frame_size,
            frame_type: DATA_FRAME_TYPE,
            flags,
            stream_id: stream_id & 0x7FFF_FFFF,
        };

        // Build complete frame
        let mut frame = Vec::new();

        // Add frame header
        frame.extend_from_slice(&header.encode());

        // Add pad_length byte
        frame.push(pad_length);

        // Add padding bytes (all zeros)
        frame.extend(vec![0u8; pad_length as usize]);

        frame
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Stream ID for DATA frame
    stream_id: u32,
    /// Maximum frame size setting
    max_frame_size: u32,
    /// Target frame size for padding test
    target_frame_size: u32,
    /// Whether to set END_STREAM flag
    end_stream: bool,
    /// Padding configuration
    padding_config: PaddingConfig,
    /// Whether to test the exact full-padding edge case
    test_full_padding_edge_case: bool,
    /// Extra operations to test
    extra_tests: Vec<PaddingTest>,
}

#[derive(Arbitrary, Debug, Clone)]
enum PaddingConfig {
    /// No padding (PADDED flag not set)
    None,
    /// Minimal padding (1 byte)
    Minimal,
    /// Moderate padding
    Moderate(u8),
    /// Maximum valid padding (frame_size - 1)
    Maximum,
    /// Invalid padding (exceeds frame size)
    Invalid(u8),
    /// Edge case: pad_length = frame_size (invalid)
    ExceedsFrame,
}

#[derive(Arbitrary, Debug, Clone)]
enum PaddingTest {
    /// Test specific frame size with maximum padding
    FullPaddingAtSize(u32),
    /// Test edge cases around frame size limits
    EdgeCaseFrameSize,
    /// Test invalid padding configurations
    InvalidPadding,
    /// Test zero-length frames with PADDED flag
    ZeroLengthPadded,
}

fn normalize_data_stream_id(raw_stream_id: u32) -> u32 {
    let masked = raw_stream_id & 0x7FFF_FFFF;
    if masked == 0 { 1 } else { masked }
}

fn offset_data_stream_id(base_stream_id: u32, offset: u32) -> u32 {
    normalize_data_stream_id(base_stream_id.wrapping_add(offset))
}

fuzz_target!(|input: FuzzInput| {
    // Clamp max frame size to valid range
    let max_frame_size = input
        .max_frame_size
        .clamp(DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT);

    let parser = LiveH2DataPaddingParser::with_max_frame_size(max_frame_size);

    // Ensure valid stream ID (non-zero for DATA frames) after clearing the reserved bit.
    let stream_id = normalize_data_stream_id(input.stream_id);

    // Test the core full-padding edge case
    if input.test_full_padding_edge_case {
        // Test various frame sizes with maximum padding
        let test_sizes = [
            1,                  // Minimum possible (pad_length only)
            2,                  // pad_length + 1 pad byte
            16,                 // Small frame
            256,                // Medium frame
            1024,               // Larger frame
            max_frame_size / 2, // Half max
            max_frame_size - 1, // Near max
            max_frame_size,     // Exactly at max
        ];

        for &size in &test_sizes {
            if size > max_frame_size || size == 0 {
                continue;
            }

            // Create fully-padded frame at this size
            let fully_padded_frame =
                parser.create_fully_padded_frame(stream_id, size, input.end_stream);

            // Parse and validate
            let result = parser.parse_data_frame(&fully_padded_frame);

            match result {
                DataFrameParseResult::Valid {
                    actual_data_size,
                    padding_size,
                    total_frame_size,
                    pad_length,
                    ..
                } => {
                    let expected_frame_size = parser.legal_fully_padded_payload_len(size);

                    // CRITICAL ASSERTION: Fully-padded frame should have 0 data bytes
                    assert_eq!(
                        actual_data_size, 0,
                        "Fully-padded frame should have 0 data bytes, got {} (frame_size: {}, pad_length: {:?})",
                        actual_data_size, total_frame_size, pad_length
                    );

                    assert_eq!(
                        total_frame_size, expected_frame_size,
                        "Fully-padded request for size {} should clamp to legal payload size {}",
                        size, expected_frame_size
                    );

                    // Padding size should be frame_size - 1 (subtract pad_length byte)
                    assert_eq!(
                        padding_size,
                        (total_frame_size - 1) as usize,
                        "Padding size mismatch for fully-padded frame of size {}",
                        total_frame_size
                    );
                    assert_eq!(
                        pad_length,
                        Some((total_frame_size - 1) as u8),
                        "Pad length mismatch for fully-padded frame of size {}",
                        total_frame_size
                    );

                    // Total accounting: pad_length_byte (1) + padding_bytes = frame_size
                    assert_eq!(
                        1 + padding_size,
                        total_frame_size as usize,
                        "Frame size accounting error: 1 + {} != {} for frame size {}",
                        padding_size,
                        total_frame_size,
                        total_frame_size
                    );
                }

                DataFrameParseResult::ProtocolError(msg) => {
                    panic!(
                        "Fully-padded frame size {} should be valid but got protocol error: {}",
                        size, msg
                    );
                }

                DataFrameParseResult::FrameSizeError => {
                    panic!(
                        "Constructed fully-padded frame size {} hit frame-size error within limit {}",
                        size, max_frame_size
                    );
                }

                DataFrameParseResult::IncompleteFrame => {
                    panic!(
                        "Constructed fully-padded frame size {} was reported incomplete",
                        size
                    );
                }

                DataFrameParseResult::InvalidStreamId => {
                    panic!(
                        "Constructed fully-padded frame size {} used invalid DATA stream id",
                        size
                    );
                }
            }
        }
    }

    // Test user-specified padding configuration
    let target_size = input.target_frame_size.clamp(1, max_frame_size);

    let frame_with_config = match input.padding_config {
        PaddingConfig::None => {
            // Create DATA frame without PADDED flag
            let header = FrameHeader {
                length: 10, // Some data
                frame_type: DATA_FRAME_TYPE,
                flags: if input.end_stream { END_STREAM_FLAG } else { 0 },
                stream_id,
            };

            let mut frame = Vec::new();
            frame.extend_from_slice(&header.encode());
            frame.extend_from_slice(b"test data!"); // 10 bytes
            frame
        }

        PaddingConfig::Minimal => {
            // 1 byte of padding
            let header = FrameHeader {
                length: target_size.min(10),
                frame_type: DATA_FRAME_TYPE,
                flags: PADDED_FLAG | if input.end_stream { END_STREAM_FLAG } else { 0 },
                stream_id,
            };

            let mut frame = Vec::new();
            frame.extend_from_slice(&header.encode());
            frame.push(1); // pad_length = 1

            // Add data (if any room left)
            let remaining = (header.length as usize).saturating_sub(2); // -1 for pad_length, -1 for padding
            frame.extend_from_slice(&vec![0x42u8; remaining]);
            frame.push(0); // 1 padding byte
            frame
        }

        PaddingConfig::Moderate(pad_len) => {
            let pad_len = pad_len.min((target_size - 1) as u8); // Ensure valid

            let header = FrameHeader {
                length: target_size,
                frame_type: DATA_FRAME_TYPE,
                flags: PADDED_FLAG | if input.end_stream { END_STREAM_FLAG } else { 0 },
                stream_id,
            };

            let mut frame = Vec::new();
            frame.extend_from_slice(&header.encode());
            frame.push(pad_len);

            // Add data
            let data_size = (target_size as usize).saturating_sub(1 + pad_len as usize);
            frame.extend_from_slice(&vec![0x42u8; data_size]);

            // Add padding
            frame.extend_from_slice(&vec![0u8; pad_len as usize]);
            frame
        }

        PaddingConfig::Maximum => {
            // Use the full-padding creator
            parser.create_fully_padded_frame(stream_id, target_size, input.end_stream)
        }

        PaddingConfig::Invalid(bad_pad_len) => {
            // Create frame with invalid padding that exceeds frame size
            let header = FrameHeader {
                length: target_size,
                frame_type: DATA_FRAME_TYPE,
                flags: PADDED_FLAG | if input.end_stream { END_STREAM_FLAG } else { 0 },
                stream_id,
            };

            let mut frame = Vec::new();
            frame.extend_from_slice(&header.encode());
            frame.push(bad_pad_len); // Invalid pad length

            // Fill rest with data (will be invalid due to bad pad_length)
            let remaining = (target_size as usize).saturating_sub(1);
            frame.extend_from_slice(&vec![0x42u8; remaining]);
            frame
        }

        PaddingConfig::ExceedsFrame => {
            // pad_length = frame_size (invalid - should be frame_size - 1 max)
            let header = FrameHeader {
                length: target_size,
                frame_type: DATA_FRAME_TYPE,
                flags: PADDED_FLAG,
                stream_id,
            };

            let mut frame = Vec::new();
            frame.extend_from_slice(&header.encode());
            frame.push(target_size as u8); // Invalid: pad_length equals total frame size

            // Fill rest (though this will be invalid)
            let remaining = (target_size as usize).saturating_sub(1);
            frame.extend_from_slice(&vec![0u8; remaining]);
            frame
        }
    };

    // Parse the constructed frame
    let result = parser.parse_data_frame(&frame_with_config);

    // Validate behavior based on padding configuration
    match (&input.padding_config, result) {
        (
            PaddingConfig::Maximum,
            DataFrameParseResult::Valid {
                actual_data_size,
                padding_size,
                total_frame_size,
                pad_length,
                ..
            },
        ) => {
            // Maximum padding should result in 0 data bytes
            assert_eq!(
                actual_data_size, 0,
                "Maximum padding should result in 0 data bytes"
            );
            assert_eq!(
                padding_size,
                (total_frame_size - 1) as usize,
                "Maximum padding size should consume the whole payload after the pad-length byte"
            );
            assert_eq!(
                pad_length,
                Some((total_frame_size - 1) as u8),
                "Maximum padding should use the largest legal pad length for the constructed frame"
            );
        }

        (PaddingConfig::Invalid(_), DataFrameParseResult::ProtocolError(_)) => {
            // Expected for invalid padding
        }

        (PaddingConfig::ExceedsFrame, DataFrameParseResult::ProtocolError(_)) => {
            // Expected for pad_length >= frame_size
        }

        (
            PaddingConfig::None,
            DataFrameParseResult::Valid {
                pad_length: None, ..
            },
        ) => {
            // Expected for non-padded frames
        }

        (
            PaddingConfig::Minimal | PaddingConfig::Moderate(_),
            DataFrameParseResult::Valid {
                padding_size,
                actual_data_size,
                ..
            },
        ) => {
            // Should have some padding and potentially some data
            assert!(
                padding_size > 0 || actual_data_size > 0,
                "Frame should have either padding or data"
            );
        }

        _ => {
            // Other combinations may be valid depending on specific values
        }
    }

    // Process extra tests
    for extra_test in &input.extra_tests {
        match extra_test {
            PaddingTest::FullPaddingAtSize(size) => {
                let size = (*size).clamp(1, max_frame_size);
                let test_frame = parser.create_fully_padded_frame(
                    offset_data_stream_id(stream_id, 1),
                    size,
                    false,
                );
                let test_result = parser.parse_data_frame(&test_frame);

                match test_result {
                    DataFrameParseResult::Valid {
                        actual_data_size,
                        total_frame_size,
                        ..
                    } => {
                        assert_eq!(
                            actual_data_size, 0,
                            "Full padding test at size {} should have 0 data bytes",
                            size
                        );
                        assert_eq!(
                            total_frame_size,
                            parser.legal_fully_padded_payload_len(size),
                            "Full padding test at size {} should clamp to the legal wire size",
                            size
                        );
                    }
                    other => {
                        panic!("Full padding test at size {} failed: {:?}", size, other);
                    }
                }
            }

            PaddingTest::EdgeCaseFrameSize => {
                // Test edge cases around frame size limits
                let edge_sizes = [1, 2, 255, 256, 16383, 16384, max_frame_size];

                for &edge_size in &edge_sizes {
                    if edge_size > max_frame_size {
                        continue;
                    }

                    let edge_frame = parser.create_fully_padded_frame(
                        offset_data_stream_id(stream_id, 2),
                        edge_size,
                        false,
                    );
                    let edge_result = parser.parse_data_frame(&edge_frame);

                    // All these should be valid fully-padded frames
                    match edge_result {
                        DataFrameParseResult::Valid {
                            actual_data_size,
                            total_frame_size,
                            ..
                        } => {
                            assert_eq!(actual_data_size, 0);
                            assert_eq!(
                                total_frame_size,
                                parser.legal_fully_padded_payload_len(edge_size),
                                "edge size {} should clamp to the legal full-padding payload size",
                                edge_size
                            );
                        }
                        other => {
                            panic!(
                                "Edge full-padding frame size {} failed: {:?}",
                                edge_size, other
                            );
                        }
                    }
                }
            }

            PaddingTest::InvalidPadding => {
                // Test various invalid padding scenarios
                for bad_pad in [255u8, 200, 150, 100] {
                    if (bad_pad as u32) < target_size {
                        continue; // This would actually be valid
                    }

                    // Create frame with excessive padding
                    let header = FrameHeader {
                        length: target_size.min(50), // Small frame
                        frame_type: DATA_FRAME_TYPE,
                        flags: PADDED_FLAG,
                        stream_id: offset_data_stream_id(stream_id, 3),
                    };

                    let mut invalid_frame = Vec::new();
                    invalid_frame.extend_from_slice(&header.encode());
                    invalid_frame.push(bad_pad); // Excessive pad length

                    // Fill remaining bytes
                    let remaining = (header.length as usize).saturating_sub(1);
                    invalid_frame.extend_from_slice(&vec![0u8; remaining]);

                    let invalid_result = parser.parse_data_frame(&invalid_frame);

                    // Should be rejected
                    assert!(
                        matches!(invalid_result, DataFrameParseResult::ProtocolError(_)),
                        "Invalid padding should be rejected"
                    );
                }
            }

            PaddingTest::ZeroLengthPadded => {
                // Test zero-length frame with PADDED flag (should be invalid)
                let header = FrameHeader {
                    length: 0,
                    frame_type: DATA_FRAME_TYPE,
                    flags: PADDED_FLAG,
                    stream_id: offset_data_stream_id(stream_id, 4),
                };

                let mut zero_frame = Vec::new();
                zero_frame.extend_from_slice(&header.encode());
                // No payload at all

                let zero_result = parser.parse_data_frame(&zero_frame);

                // Should be rejected - can't have PADDED flag with zero-length payload
                assert!(
                    matches!(zero_result, DataFrameParseResult::ProtocolError(_)),
                    "Zero-length frame with PADDED flag should be rejected"
                );
            }
        }
    }

    // FINAL ASSERTION: Test the canonical full-padding edge case
    // Frame size = 256, pad_length = 255, data bytes = 0
    let canonical_size = 256u32.min(max_frame_size);
    if canonical_size >= 2 {
        let canonical_frame = parser.create_fully_padded_frame(
            offset_data_stream_id(stream_id, 10),
            canonical_size,
            true,
        );
        let canonical_result = parser.parse_data_frame(&canonical_frame);

        match canonical_result {
            DataFrameParseResult::Valid {
                actual_data_size,
                padding_size,
                total_frame_size,
                pad_length: Some(pad_len),
                flags,
                ..
            } => {
                // Verify this is the exact edge case we're testing
                assert_eq!(
                    actual_data_size, 0,
                    "Canonical case should have 0 data bytes"
                );
                assert_eq!(
                    padding_size,
                    (canonical_size - 1) as usize,
                    "Canonical case padding size"
                );
                assert_eq!(
                    total_frame_size, canonical_size,
                    "Canonical case frame size"
                );
                assert_eq!(
                    pad_len,
                    (canonical_size - 1) as u8,
                    "Canonical case pad_length"
                );
                assert!(
                    (flags & PADDED_FLAG) != 0,
                    "Canonical case should have PADDED flag"
                );
                assert!(
                    (flags & END_STREAM_FLAG) != 0,
                    "Canonical case should have END_STREAM flag"
                );
            }

            _ => {
                panic!(
                    "Canonical full-padding edge case failed for frame size {}: {:?}",
                    canonical_size, canonical_result
                );
            }
        }
    }
});
