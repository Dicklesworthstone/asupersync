#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 DATA frame padding length validation fuzzing.
///
/// Tests the padding validation logic in DATA frames per RFC 9113 §6.1:
/// - PADDED flag handling and padding length byte extraction
/// - Validation that padding length doesn't exceed frame payload length
/// - Correct data extraction after padding removal
/// - Edge cases with zero-length data, maximum padding, boundary conditions
///
/// Critical security implications:
/// - Buffer overruns from invalid padding calculations
/// - Data corruption from incorrect payload slicing
/// - Connection-level PROTOCOL_ERROR enforcement
/// - Resource exhaustion via padding abuse
///
/// Based on frame.rs DataFrame::parse() logic around lines 334-347.
#[derive(Arbitrary, Debug, Clone)]
pub struct DataPaddingTestCase {
    /// Frame header configuration
    header: FrameHeaderConfig,
    /// Payload configuration including padding
    payload: PayloadConfig,
    /// Edge case scenarios
    scenario: PaddingScenario,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct FrameHeaderConfig {
    /// Frame length field (0-16777215, but will be validated against actual payload)
    declared_length: u32,
    /// Stream ID (must be non-zero for DATA frames)
    stream_id: StreamIdConfig,
    /// Frame flags
    flags: FlagsConfig,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum StreamIdConfig {
    /// Valid stream IDs
    Valid(u32), // 1-2147483647
    /// Edge cases
    Zero, // Invalid for DATA frames
    MaxValid, // 0x7FFFFFFF
    Reserved, // With high bit set
}

#[derive(Arbitrary, Debug, Clone)]
pub struct FlagsConfig {
    /// PADDED flag (0x8)
    padded: bool,
    /// END_STREAM flag (0x1)
    end_stream: bool,
    /// Reserved/unknown flags
    unknown_flags: u8,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum PayloadConfig {
    /// Empty payload
    Empty,
    /// Payload with explicit padding configuration
    WithPadding {
        padding_length_byte: u8,
        data: DataContent,
        padding_bytes: PaddingContent,
    },
    /// Payload without PADDED flag but with suspicious content
    UnflaggedData { data: Vec<u8> },
    /// Malformed payloads
    Malformed(MalformedPayload),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum DataContent {
    Empty,
    Short(Vec<u8>),  // 1-100 bytes
    Medium(Vec<u8>), // 101-1000 bytes
    Large(Vec<u8>),  // 1001+ bytes (up to max frame size)
    Pattern(PatternType),
    Binary(BinaryContent),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum PatternType {
    AllZeros(usize),
    AllOnes(usize),
    Incrementing(usize),
    Random(usize),
    HttpLike(String),
    JsonLike(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum BinaryContent {
    RawBytes(Vec<u8>),
    Utf8Text(String),
    Base64Like(String),
    HighBitSet(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum PaddingContent {
    /// Correct padding (all zeros)
    Zeros(usize),
    /// Non-zero padding (still valid per spec)
    Pattern(u8, usize),
    /// Arbitrary bytes
    Arbitrary(Vec<u8>),
    /// Missing padding bytes
    Missing,
    /// Too many padding bytes
    Excessive(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum MalformedPayload {
    /// Padding length byte but no actual payload
    PaddingByteOnly(u8),
    /// Padding length exceeds remaining bytes
    ExcessivePadding(u8, Vec<u8>),
    /// No padding length byte despite PADDED flag
    MissingPaddingByte,
    /// Truncated payload
    Truncated(Vec<u8>),
    /// Overly long payload
    TooLong(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum PaddingScenario {
    /// Normal valid cases
    ValidPadding,
    /// Boundary conditions
    ZeroPadding,
    MaxPadding,
    ExactFit,
    /// Error conditions
    PaddingOverflow,
    EmptyFrameWithPadding,
    MissingPaddingFlag,
    InvalidStreamId,
    FrameTooLarge,
    MalformedFrame,
    /// Edge cases
    LargeFrameWithPadding,
    MultipleFlags,
    UnknownFlags,
    /// Attack scenarios
    ResourceExhaustion,
    BufferOverrun,
    IntegerOverflow,
}

/// Mock HTTP/2 DATA frame parser for padding validation fuzzing
#[derive(Debug)]
pub struct MockDataFrameParser {
    max_frame_size: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedDataFrame {
    pub stream_id: u32,
    pub data: Vec<u8>,
    pub end_stream: bool,
    pub padding_removed: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FrameParseError {
    FrameTooLarge { declared: u32, max: u32 },
    InvalidStreamId,
    MissingPaddingLength,
    PaddingExceedsData { padding: usize, data_len: usize },
    MalformedFrame(String),
    ProtocolError(String),
}

impl MockDataFrameParser {
    pub fn new() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024, // 16MB default
        }
    }

    pub fn with_max_frame_size(mut self, size: u32) -> Self {
        self.max_frame_size = size;
        self
    }

    pub fn parse_data_frame(
        &self,
        test_case: &DataPaddingTestCase,
    ) -> Result<ParsedDataFrame, FrameParseError> {
        // Build frame from test case
        let (header_bytes, payload_bytes) = self.build_frame(test_case)?;

        // Parse frame header
        let parsed_header = self.parse_frame_header(&header_bytes)?;

        // Validate frame size
        if parsed_header.length > self.max_frame_size {
            return Err(FrameParseError::FrameTooLarge {
                declared: parsed_header.length,
                max: self.max_frame_size,
            });
        }

        // Validate payload length matches header
        if payload_bytes.len() != parsed_header.length as usize {
            return Err(FrameParseError::MalformedFrame(format!(
                "Payload length {} doesn't match declared length {}",
                payload_bytes.len(),
                parsed_header.length
            )));
        }

        // Validate stream ID for DATA frames
        if parsed_header.stream_id == 0 {
            return Err(FrameParseError::InvalidStreamId);
        }

        // Parse DATA frame with padding validation
        self.parse_data_payload(parsed_header, payload_bytes)
    }

    fn build_frame(
        &self,
        test_case: &DataPaddingTestCase,
    ) -> Result<(Vec<u8>, Vec<u8>), FrameParseError> {
        // Build payload first to determine actual length
        let payload_bytes = self.build_payload(&test_case.payload, &test_case.header.flags)?;

        // Determine actual length vs declared length for testing
        let actual_length = payload_bytes.len() as u32;
        let declared_length = match test_case.scenario {
            PaddingScenario::FrameTooLarge | PaddingScenario::MalformedFrame => {
                // Use declared length that doesn't match actual
                test_case.header.declared_length
            }
            _ => actual_length,
        };

        // Build frame header
        let stream_id = self.build_stream_id(&test_case.header.stream_id);
        let flags = self.build_flags(&test_case.header.flags);

        let header_bytes = vec![
            // Length (24 bits)
            ((declared_length >> 16) & 0xFF) as u8,
            ((declared_length >> 8) & 0xFF) as u8,
            (declared_length & 0xFF) as u8,
            // Type (DATA = 0x0)
            0x0,
            // Flags
            flags,
            // Stream ID (31 bits)
            ((stream_id >> 24) & 0x7F) as u8, // Clear reserved bit
            ((stream_id >> 16) & 0xFF) as u8,
            ((stream_id >> 8) & 0xFF) as u8,
            (stream_id & 0xFF) as u8,
        ];

        Ok((header_bytes, payload_bytes))
    }

    fn build_stream_id(&self, config: &StreamIdConfig) -> u32 {
        match config {
            StreamIdConfig::Valid(id) => {
                // Ensure it's in valid range (1-0x7FFFFFFF) and odd (client-initiated)
                let id = *id % 0x7FFFFFFF;
                if id == 0 { 1 } else { id | 1 }
            }
            StreamIdConfig::Zero => 0,
            StreamIdConfig::MaxValid => 0x7FFFFFFF,
            StreamIdConfig::Reserved => 0x80000001, // Set reserved bit
        }
    }

    fn build_flags(&self, config: &FlagsConfig) -> u8 {
        let mut flags = 0u8;

        if config.padded {
            flags |= 0x8; // PADDED flag
        }

        if config.end_stream {
            flags |= 0x1; // END_STREAM flag
        }

        // Add unknown flags (potentially reserved)
        flags |= config.unknown_flags & 0xF6; // Avoid overriding known flags

        flags
    }

    fn build_payload(
        &self,
        config: &PayloadConfig,
        flags: &FlagsConfig,
    ) -> Result<Vec<u8>, FrameParseError> {
        match config {
            PayloadConfig::Empty => Ok(Vec::new()),

            PayloadConfig::WithPadding {
                padding_length_byte,
                data,
                padding_bytes,
            } => {
                let mut payload = Vec::new();

                // Add padding length byte if PADDED flag is set
                if flags.padded {
                    payload.push(*padding_length_byte);
                }

                // Add data content
                payload.extend_from_slice(&self.build_data_content(data));

                // Add padding bytes
                payload.extend_from_slice(&self.build_padding_content(padding_bytes));

                Ok(payload)
            }

            PayloadConfig::UnflaggedData { data } => Ok(data.clone()),

            PayloadConfig::Malformed(malformed) => self.build_malformed_payload(malformed, flags),
        }
    }

    fn build_data_content(&self, data: &DataContent) -> Vec<u8> {
        match data {
            DataContent::Empty => Vec::new(),
            DataContent::Short(bytes) => bytes.clone(),
            DataContent::Medium(bytes) => bytes.clone(),
            DataContent::Large(bytes) => bytes.clone(),

            DataContent::Pattern(pattern) => {
                match pattern {
                    PatternType::AllZeros(size) => vec![0u8; *size % 1000],
                    PatternType::AllOnes(size) => vec![0xFFu8; *size % 1000],
                    PatternType::Incrementing(size) => (0u8..*size as u8 % 255).collect(),
                    PatternType::Random(size) => {
                        // Deterministic "random" pattern for fuzzing reproducibility
                        (0..*size % 1000).map(|i| (i * 17 + 42) as u8).collect()
                    }
                    PatternType::HttpLike(content) => {
                        format!("GET {} HTTP/1.1\r\nHost: example.com\r\n\r\n", content)
                            .into_bytes()
                    }
                    PatternType::JsonLike(content) => {
                        format!("{{\"data\":\"{}\",\"type\":\"test\"}}", content).into_bytes()
                    }
                }
            }

            DataContent::Binary(binary) => {
                match binary {
                    BinaryContent::RawBytes(bytes) => bytes.clone(),
                    BinaryContent::Utf8Text(text) => text.as_bytes().to_vec(),
                    BinaryContent::Base64Like(text) => {
                        // Simulate base64-like content
                        text.chars().map(|c| c as u8).collect()
                    }
                    BinaryContent::HighBitSet(bytes) => bytes.iter().map(|&b| b | 0x80).collect(),
                }
            }
        }
    }

    fn build_padding_content(&self, padding: &PaddingContent) -> Vec<u8> {
        match padding {
            PaddingContent::Zeros(size) => vec![0u8; *size % 256],
            PaddingContent::Pattern(byte, size) => vec![*byte; *size % 256],
            PaddingContent::Arbitrary(bytes) => bytes.clone(),
            PaddingContent::Missing => Vec::new(),
            PaddingContent::Excessive(bytes) => bytes.clone(),
        }
    }

    fn build_malformed_payload(
        &self,
        malformed: &MalformedPayload,
        flags: &FlagsConfig,
    ) -> Result<Vec<u8>, FrameParseError> {
        match malformed {
            MalformedPayload::PaddingByteOnly(byte) => {
                if flags.padded {
                    Ok(vec![*byte])
                } else {
                    Ok(Vec::new())
                }
            }

            MalformedPayload::ExcessivePadding(padding_len, data) => {
                let mut payload = Vec::new();
                if flags.padded {
                    payload.push(*padding_len);
                }
                payload.extend_from_slice(data);
                Ok(payload)
            }

            MalformedPayload::MissingPaddingByte => {
                // PADDED flag set but no padding length byte
                Ok(Vec::new())
            }

            MalformedPayload::Truncated(data) => Ok(data.clone()),
            MalformedPayload::TooLong(data) => Ok(data.clone()),
        }
    }

    fn parse_frame_header(&self, header_bytes: &[u8]) -> Result<FrameHeader, FrameParseError> {
        if header_bytes.len() != 9 {
            return Err(FrameParseError::MalformedFrame(
                "Invalid header size".to_string(),
            ));
        }

        let length = ((header_bytes[0] as u32) << 16)
            | ((header_bytes[1] as u32) << 8)
            | (header_bytes[2] as u32);

        let frame_type = header_bytes[3];
        let flags = header_bytes[4];

        let stream_id = ((header_bytes[5] as u32) << 24)
            | ((header_bytes[6] as u32) << 16)
            | ((header_bytes[7] as u32) << 8)
            | (header_bytes[8] as u32);

        // Clear reserved bit
        let stream_id = stream_id & 0x7FFFFFFF;

        if frame_type != 0x0 {
            return Err(FrameParseError::MalformedFrame(
                "Not a DATA frame".to_string(),
            ));
        }

        Ok(FrameHeader {
            length,
            flags,
            stream_id,
        })
    }

    fn parse_data_payload(
        &self,
        header: FrameHeader,
        mut payload: Vec<u8>,
    ) -> Result<ParsedDataFrame, FrameParseError> {
        let end_stream = (header.flags & 0x1) != 0;
        let padded = (header.flags & 0x8) != 0;
        let mut padding_removed = 0;

        // Handle padding validation
        if padded {
            if payload.is_empty() {
                return Err(FrameParseError::MissingPaddingLength);
            }

            let pad_length = payload[0] as usize;
            payload = payload[1..].to_vec(); // Remove padding length byte

            if pad_length > payload.len() {
                return Err(FrameParseError::PaddingExceedsData {
                    padding: pad_length,
                    data_len: payload.len(),
                });
            }

            // Remove padding from end
            if pad_length > 0 {
                let new_len = payload.len() - pad_length;
                payload.truncate(new_len);
                padding_removed = pad_length;
            }
        }

        Ok(ParsedDataFrame {
            stream_id: header.stream_id,
            data: payload,
            end_stream,
            padding_removed,
        })
    }
}

impl Default for MockDataFrameParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct FrameHeader {
    length: u32,
    flags: u8,
    stream_id: u32,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(test_case) = DataPaddingTestCase::arbitrary(&mut u) {
        let parser = MockDataFrameParser::new();

        // Test main parsing path
        let result = parser.parse_data_frame(&test_case);

        // Validate parsing invariants
        match result {
            Ok(parsed_frame) => {
                // Basic invariants
                assert_ne!(
                    parsed_frame.stream_id, 0,
                    "DATA frame must have non-zero stream ID"
                );

                // Padding invariants
                if let PayloadConfig::WithPadding {
                    padding_length_byte,
                    ..
                } = &test_case.payload
                    && test_case.header.flags.padded
                {
                    // If parsing succeeded with padding, validate constraints
                    assert!(
                        *padding_length_byte as usize >= parsed_frame.padding_removed,
                        "Padding removed should not exceed declared padding length"
                    );
                }

                // Data integrity
                let total_data_len = parsed_frame.data.len() + parsed_frame.padding_removed;
                assert!(
                    total_data_len <= parser.max_frame_size as usize,
                    "Total frame size should not exceed maximum"
                );

                // Stream ID validation
                assert!(
                    parsed_frame.stream_id <= 0x7FFFFFFF,
                    "Stream ID should not exceed 31-bit maximum"
                );
            }

            Err(error) => {
                // Validate error conditions are appropriate
                match error {
                    FrameParseError::FrameTooLarge { declared, max } => {
                        assert!(
                            declared > max,
                            "Frame too large error should only trigger when declared > max"
                        );
                    }

                    FrameParseError::InvalidStreamId => {
                        // Should only happen for stream ID 0
                        assert!(
                            matches!(test_case.header.stream_id, StreamIdConfig::Zero),
                            "Invalid stream ID error should only occur for stream ID 0"
                        );
                    }

                    FrameParseError::MissingPaddingLength => {
                        // Should only happen when PADDED flag is set but no padding byte
                        assert!(
                            test_case.header.flags.padded,
                            "Missing padding length error should only occur with PADDED flag"
                        );
                    }

                    FrameParseError::PaddingExceedsData { padding, data_len } => {
                        assert!(
                            padding > data_len,
                            "Padding exceeds data error should only trigger when padding > data_len"
                        );
                    }

                    FrameParseError::MalformedFrame(_) | FrameParseError::ProtocolError(_) => {
                        // These are expected for malformed input
                    }
                }
            }
        }

        // Test edge cases
        test_padding_edge_cases(&parser, &test_case);

        // Test frame size limits
        test_frame_size_limits(&parser, &test_case);

        // Test flag combinations
        test_flag_combinations(&parser, &test_case);

        // Test padding boundary conditions
        test_padding_boundaries(&parser, &test_case);
    }
});

fn test_padding_edge_cases(parser: &MockDataFrameParser, test_case: &DataPaddingTestCase) {
    // Test zero padding
    let mut zero_padding_case = test_case.clone();
    if let PayloadConfig::WithPadding {
        ref mut padding_length_byte,
        ..
    } = zero_padding_case.payload
    {
        *padding_length_byte = 0;
        let result = parser.parse_data_frame(&zero_padding_case);

        // Zero padding should be valid
        if test_case.header.flags.padded
            && matches!(test_case.header.stream_id, StreamIdConfig::Valid(_))
        {
            assert!(
                result.is_ok() || matches!(result, Err(FrameParseError::MalformedFrame(_))),
                "Zero padding should be valid or fail for structural reasons"
            );
        }
    }

    // Test maximum padding (255 bytes)
    let mut max_padding_case = test_case.clone();
    if let PayloadConfig::WithPadding {
        ref mut padding_length_byte,
        ..
    } = max_padding_case.payload
    {
        *padding_length_byte = 255;
        let result = parser.parse_data_frame(&max_padding_case);

        // This will likely fail due to padding exceeding data length, which is correct
        if let Err(FrameParseError::PaddingExceedsData { .. }) = result {
            // Expected for most cases
        }
    }
}

fn test_frame_size_limits(parser: &MockDataFrameParser, test_case: &DataPaddingTestCase) {
    // Test with restricted max frame size
    let restricted_parser = MockDataFrameParser::new().with_max_frame_size(1024);

    let result = restricted_parser.parse_data_frame(test_case);

    // Large frames should be rejected
    if let Ok((_, payload)) = parser.build_frame(test_case)
        && payload.len() > 1024
    {
        assert!(
            result.is_err(),
            "Large frames should be rejected by restricted parser"
        );
    }
}

fn test_flag_combinations(parser: &MockDataFrameParser, test_case: &DataPaddingTestCase) {
    // Test PADDED flag without padding content
    let mut no_padding_case = test_case.clone();
    no_padding_case.header.flags.padded = false;
    no_padding_case.payload = PayloadConfig::UnflaggedData {
        data: vec![1, 2, 3, 4, 5],
    };

    let result = parser.parse_data_frame(&no_padding_case);

    // Should succeed if stream ID is valid
    if matches!(no_padding_case.header.stream_id, StreamIdConfig::Valid(_)) {
        assert!(
            result.is_ok(),
            "Unflagged data should parse successfully with valid stream ID"
        );
    }
}

fn test_padding_boundaries(parser: &MockDataFrameParser, test_case: &DataPaddingTestCase) {
    // Test padding length exactly equal to remaining data length
    if let PayloadConfig::WithPadding { data, .. } = &test_case.payload {
        let data_bytes = parser.build_data_content(data);
        let mut exact_padding_case = test_case.clone();

        if let PayloadConfig::WithPadding {
            ref mut padding_length_byte,
            ..
        } = exact_padding_case.payload
        {
            *padding_length_byte = data_bytes.len() as u8;

            let result = parser.parse_data_frame(&exact_padding_case);

            // This should result in empty data (all padding) or an error
            match result {
                Ok(parsed) => {
                    assert!(
                        parsed.data.is_empty(),
                        "Exact padding should result in empty data"
                    );
                }
                Err(FrameParseError::PaddingExceedsData { .. }) => {
                    // Also acceptable if padding calculation includes the padding length byte
                }
                _ => {}
            }
        }
    }
}
