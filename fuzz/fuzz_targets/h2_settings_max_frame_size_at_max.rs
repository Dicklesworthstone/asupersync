#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 SETTINGS_MAX_FRAME_SIZE maximum value test input for RFC 7540 §6.5.2 compliance
#[derive(Arbitrary, Debug)]
struct H2MaxFrameSizeInput {
    /// Frame size setting strategy
    setting_strategy: SettingStrategy,
    /// Test data frame scenarios after setting
    data_frame_tests: Vec<DataFrameTest>,
    /// Additional protocol context
    protocol_context: ProtocolContext,
}

#[derive(Arbitrary, Debug)]
enum SettingStrategy {
    /// Set to exact maximum (2^24-1 = 16777215)
    ExactMax,
    /// Set to near maximum (16777214, 16777213, etc.)
    NearMax { offset: u8 },
    /// Set to default first, then update to max
    DefaultThenMax,
    /// Set to various valid values leading up to max
    Progressive { steps: Vec<u32> },
    /// Set to minimum first, then max (test range)
    MinToMax,
}

#[derive(Arbitrary, Debug)]
struct DataFrameTest {
    /// Stream ID for the DATA frame
    stream_id: u32,
    /// Size of the DATA frame payload
    payload_size: PayloadSize,
    /// Frame properties
    properties: DataFrameProperties,
}

#[derive(Arbitrary, Debug)]
enum PayloadSize {
    /// Exactly at the maximum frame size
    AtMaximum,
    /// Just under maximum (max - 1, max - 2, etc.)
    NearMaximum { offset: u16 },
    /// At default frame size (16384)
    AtDefault,
    /// Small frame size (< 1000 bytes)
    Small(u16),
    /// Medium frame size (1000-8192 bytes)
    Medium(u16),
    /// Large frame size (8192-65535 bytes)
    Large(u16),
    /// Custom size for boundary testing
    Custom(u32),
}

#[derive(Arbitrary, Debug)]
struct DataFrameProperties {
    /// Whether frame has END_STREAM flag
    end_stream: bool,
    /// Whether frame has padding
    padded: bool,
    /// Padding length if padded
    padding_length: u8,
    /// Data pattern for testing
    data_pattern: DataPattern,
}

#[derive(Arbitrary, Debug)]
enum DataPattern {
    /// All zeros
    Zeros,
    /// All ones
    Ones,
    /// Incrementing bytes (0, 1, 2, ...)
    Incrementing,
    /// Random-like pattern
    Random(u64), // Seed for reproducible randomness
    /// Repeated pattern
    Repeated(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct ProtocolContext {
    /// Connection state
    connection_state: ConnectionState,
    /// Flow control window size
    initial_window_size: u32,
    /// Other concurrent streams
    concurrent_streams: u8,
    /// Header compression state
    hpack_table_size: u32,
}

#[derive(Arbitrary, Debug)]
enum ConnectionState {
    /// Fresh connection
    New,
    /// Connection with prior activity
    Active,
    /// Connection near flow control limits
    FlowControlLimited,
}

/// Mock HTTP/2 frame size parser for testing RFC 7540 §6.5.2 compliance
struct MockH2MaxFrameSizeParser {
    max_frame_size: u32,
    connection_state: ParserState,
}

#[derive(Debug)]
struct ParserState {
    max_frame_size_setting: u32,
    settings_applied: bool,
    stream_states: std::collections::HashMap<u32, StreamState>,
}

#[derive(Debug)]
struct StreamState {
    state: StreamStateType,
    received_bytes: u64,
}

#[derive(Debug, PartialEq)]
enum StreamStateType {
    Open,
    HalfClosedRemote,
    HalfClosedLocal,
    Closed,
}

#[derive(Debug, PartialEq)]
enum FrameValidationError {
    /// Frame size exceeds SETTINGS_MAX_FRAME_SIZE
    FrameSizeExceeded { size: u32, max: u32 },
    /// SETTINGS_MAX_FRAME_SIZE value is invalid
    InvalidMaxFrameSize { value: u32 },
    /// Frame size is invalid (general)
    InvalidFrameSize,
    /// Padding exceeds frame size
    PaddingExceedsFrame,
    /// Stream ID is invalid
    InvalidStreamId,
    /// Stream is in invalid state for DATA frame
    InvalidStreamState,
}

const RFC_MIN_FRAME_SIZE: u32 = 16384; // 2^14
const RFC_MAX_FRAME_SIZE: u32 = 16777215; // 2^24 - 1
const RFC_DEFAULT_FRAME_SIZE: u32 = 16384; // 2^14

fn assert_data_frame_error(error: &FrameValidationError, context: &str) {
    match error {
        FrameValidationError::FrameSizeExceeded { size, max } => {
            assert!(
                size > max,
                "{}: frame-size error reported non-exceeding frame {} <= {}",
                context,
                size,
                max
            );
        }
        FrameValidationError::InvalidStreamId
        | FrameValidationError::PaddingExceedsFrame
        | FrameValidationError::InvalidStreamState => {}
        FrameValidationError::InvalidMaxFrameSize { value } => {
            panic!(
                "{}: accepted SETTINGS_MAX_FRAME_SIZE value {} was rejected",
                context, value
            );
        }
        FrameValidationError::InvalidFrameSize => {
            panic!(
                "{}: generated DATA frame produced a generic invalid-frame-size result",
                context
            );
        }
    }
}

fn assert_exact_max_data_result(result: &Result<(), FrameValidationError>) {
    match result {
        Ok(()) => {}
        Err(FrameValidationError::InvalidStreamState) => {}
        Err(error) => {
            panic!(
                "unpadded DATA exactly at SETTINGS_MAX_FRAME_SIZE should not fail with {:?}",
                error
            );
        }
    }
}

impl MockH2MaxFrameSizeParser {
    fn new() -> Self {
        Self {
            max_frame_size: RFC_DEFAULT_FRAME_SIZE,
            connection_state: ParserState {
                max_frame_size_setting: RFC_DEFAULT_FRAME_SIZE,
                settings_applied: false,
                stream_states: std::collections::HashMap::new(),
            },
        }
    }

    fn process_settings_frame(&mut self, max_frame_size: u32) -> Result<(), FrameValidationError> {
        // RFC 7540 §6.5.2: Value must be between 2^14 and 2^24-1 inclusive
        if !(RFC_MIN_FRAME_SIZE..=RFC_MAX_FRAME_SIZE).contains(&max_frame_size) {
            return Err(FrameValidationError::InvalidMaxFrameSize {
                value: max_frame_size,
            });
        }

        // Update the setting
        self.max_frame_size = max_frame_size;
        self.connection_state.max_frame_size_setting = max_frame_size;
        self.connection_state.settings_applied = true;

        Ok(())
    }

    fn apply_protocol_context(&mut self, context: &ProtocolContext) {
        self.connection_state.settings_applied |= context.hpack_table_size > 0;
        self.connection_state.max_frame_size_setting = self
            .max_frame_size
            .max(context.initial_window_size.min(RFC_MAX_FRAME_SIZE));

        let tracked_streams = context.concurrent_streams.min(8);
        for stream_index in 0..tracked_streams {
            let stream_id = u32::from(stream_index) + 1;
            self.connection_state
                .stream_states
                .entry(stream_id)
                .or_insert(StreamState {
                    state: StreamStateType::Open,
                    received_bytes: u64::from(context.initial_window_size),
                });
        }

        match context.connection_state {
            ConnectionState::New => {}
            ConnectionState::Active => {
                self.connection_state
                    .stream_states
                    .entry(1)
                    .or_insert(StreamState {
                        state: StreamStateType::HalfClosedLocal,
                        received_bytes: 0,
                    });
            }
            ConnectionState::FlowControlLimited => {
                self.connection_state
                    .stream_states
                    .entry(1)
                    .or_insert(StreamState {
                        state: StreamStateType::HalfClosedRemote,
                        received_bytes: u64::from(context.initial_window_size),
                    });
            }
        }
    }

    fn data_pattern_marker(pattern: &DataPattern) -> u8 {
        match pattern {
            DataPattern::Zeros => 0,
            DataPattern::Ones => u8::MAX,
            DataPattern::Incrementing => 1,
            DataPattern::Random(seed) => seed.to_le_bytes()[0],
            DataPattern::Repeated(bytes) => bytes.first().copied().unwrap_or(0),
        }
    }

    fn process_data_frame(
        &mut self,
        stream_id: u32,
        payload_size: u32,
        properties: &DataFrameProperties,
    ) -> Result<(), FrameValidationError> {
        // Validate stream ID
        if stream_id == 0 {
            return Err(FrameValidationError::InvalidStreamId);
        }

        // Calculate total frame size including padding
        let padding_size = if properties.padded {
            1 + properties.padding_length as u32
        } else {
            0
        };
        let total_frame_size = payload_size + padding_size;

        // RFC 7540 §6.5.2: Frame size must not exceed SETTINGS_MAX_FRAME_SIZE
        if total_frame_size > self.max_frame_size {
            return Err(FrameValidationError::FrameSizeExceeded {
                size: total_frame_size,
                max: self.max_frame_size,
            });
        }

        // Validate padding
        if properties.padded && properties.padding_length as u32 >= payload_size {
            return Err(FrameValidationError::PaddingExceedsFrame);
        }

        let _pattern_marker = Self::data_pattern_marker(&properties.data_pattern);

        // Update stream state
        let stream_state = self
            .connection_state
            .stream_states
            .entry(stream_id)
            .or_insert(StreamState {
                state: StreamStateType::Open,
                received_bytes: 0,
            });

        // Check if stream can receive DATA frames
        match stream_state.state {
            StreamStateType::Open | StreamStateType::HalfClosedLocal => {
                // Can receive DATA frames
            }
            StreamStateType::HalfClosedRemote | StreamStateType::Closed => {
                return Err(FrameValidationError::InvalidStreamState);
            }
        }

        // Update stream state
        stream_state.received_bytes += payload_size as u64;
        if properties.end_stream {
            match stream_state.state {
                StreamStateType::Open => stream_state.state = StreamStateType::HalfClosedRemote,
                StreamStateType::HalfClosedLocal => stream_state.state = StreamStateType::Closed,
                _ => {} // Already closed
            }
        }

        Ok(())
    }

    fn generate_frame_size(size_spec: &PayloadSize, max_frame_size: u32) -> u32 {
        match size_spec {
            PayloadSize::AtMaximum => max_frame_size,
            PayloadSize::NearMaximum { offset } => max_frame_size.saturating_sub(*offset as u32),
            PayloadSize::AtDefault => RFC_DEFAULT_FRAME_SIZE.min(max_frame_size),
            PayloadSize::Small(size) => (*size as u32).min(max_frame_size),
            PayloadSize::Medium(size) => (1000 + (*size as u32 % 7192)).min(max_frame_size),
            PayloadSize::Large(size) => (8192 + (*size as u32 % 57343)).min(max_frame_size),
            PayloadSize::Custom(size) => (*size).min(max_frame_size),
        }
    }

    fn simulate_frame_sequence(
        &mut self,
        input: &H2MaxFrameSizeInput,
    ) -> Result<(), FrameValidationError> {
        self.apply_protocol_context(&input.protocol_context);

        // First, apply the SETTINGS frame
        let target_frame_size = match input.setting_strategy {
            SettingStrategy::ExactMax => RFC_MAX_FRAME_SIZE,
            SettingStrategy::NearMax { offset } => RFC_MAX_FRAME_SIZE - offset as u32,
            SettingStrategy::DefaultThenMax => {
                // First set to default, then to max
                self.process_settings_frame(RFC_DEFAULT_FRAME_SIZE)?;
                RFC_MAX_FRAME_SIZE
            }
            SettingStrategy::Progressive { ref steps } => {
                // Apply progressive steps
                for &step in steps {
                    let frame_size = step.clamp(RFC_MIN_FRAME_SIZE, RFC_MAX_FRAME_SIZE);
                    self.process_settings_frame(frame_size)?;
                }
                RFC_MAX_FRAME_SIZE
            }
            SettingStrategy::MinToMax => {
                // First set to minimum, then to maximum
                self.process_settings_frame(RFC_MIN_FRAME_SIZE)?;
                RFC_MAX_FRAME_SIZE
            }
        };

        // Apply the target frame size
        self.process_settings_frame(target_frame_size)?;

        // Now test DATA frames with the new setting
        for data_frame_test in &input.data_frame_tests {
            let frame_size =
                Self::generate_frame_size(&data_frame_test.payload_size, self.max_frame_size);

            let result = self.process_data_frame(
                data_frame_test.stream_id,
                frame_size,
                &data_frame_test.properties,
            );

            // For this specific test, we expect frames up to max_frame_size to succeed
            if frame_size <= self.max_frame_size {
                if matches!(data_frame_test.payload_size, PayloadSize::AtMaximum)
                    && data_frame_test.stream_id != 0
                    && !data_frame_test.properties.padded
                {
                    assert_exact_max_data_result(&result);
                }
                result?;
            } else {
                // Frame exceeds limit, should fail
                match result {
                    Err(FrameValidationError::FrameSizeExceeded { .. }) => {
                        // Expected error
                    }
                    Ok(()) => {
                        return Err(FrameValidationError::InvalidFrameSize);
                    }
                    Err(other) => return Err(other),
                }
            }
        }

        Ok(())
    }
}

fuzz_target!(|input: H2MaxFrameSizeInput| {
    // Skip inputs that would cause excessive processing
    if input.data_frame_tests.len() > 50 {
        return;
    }

    let mut parser = MockH2MaxFrameSizeParser::new();
    let result = parser.simulate_frame_sequence(&input);

    // Apply test assertions based on the strategy and expected behavior
    match &input.setting_strategy {
        SettingStrategy::ExactMax => {
            // Setting to exact maximum (2^24-1 = 16777215) should succeed
            match &result {
                Ok(()) => {
                    // Expected: maximum frame size should be accepted
                    assert_eq!(parser.max_frame_size, RFC_MAX_FRAME_SIZE);
                }
                Err(FrameValidationError::InvalidMaxFrameSize { value }) => {
                    panic!("RFC maximum frame size {} should be valid", value);
                }
                Err(FrameValidationError::FrameSizeExceeded { size, max }) => {
                    // Expected if DATA frame exceeded the limit
                    assert!(size > max, "Frame size {} should exceed max {}", size, max);
                    assert_eq!(*max, RFC_MAX_FRAME_SIZE);
                }
                Err(error) => assert_data_frame_error(error, "exact max strategy"),
            }
        }
        SettingStrategy::NearMax { offset } => {
            let target_size = RFC_MAX_FRAME_SIZE - *offset as u32;

            if target_size >= RFC_MIN_FRAME_SIZE {
                // Should be valid
                match &result {
                    Ok(()) => {
                        assert_eq!(parser.max_frame_size, target_size);
                    }
                    Err(FrameValidationError::FrameSizeExceeded { .. }) => {
                        // Expected if DATA frame exceeded the limit
                    }
                    Err(FrameValidationError::InvalidMaxFrameSize { .. }) => {
                        panic!(
                            "Frame size {} should be valid (>= {})",
                            target_size, RFC_MIN_FRAME_SIZE
                        );
                    }
                    Err(error) => assert_data_frame_error(error, "near max strategy"),
                }
            } else {
                // Should be invalid (below minimum)
                assert!(matches!(
                    &result,
                    Err(FrameValidationError::InvalidMaxFrameSize { .. })
                ));
            }
        }
        SettingStrategy::DefaultThenMax
        | SettingStrategy::Progressive { .. }
        | SettingStrategy::MinToMax => {
            // Progressive setting changes should all succeed
            match &result {
                Ok(()) => {
                    // Expected: should end up with maximum frame size
                    assert_eq!(parser.max_frame_size, RFC_MAX_FRAME_SIZE);
                }
                Err(FrameValidationError::FrameSizeExceeded { .. }) => {
                    // Expected if DATA frame tests exceeded limits
                }
                Err(FrameValidationError::InvalidMaxFrameSize { value }) => {
                    panic!("Progressive frame size update failed at {}", value);
                }
                Err(error) => assert_data_frame_error(error, "progressive max strategy"),
            }
        }
    }

    // Test invariants for frame size boundary conditions
    test_frame_size_invariants(&input, &result, parser.max_frame_size);
});

fn test_frame_size_invariants(
    input: &H2MaxFrameSizeInput,
    result: &Result<(), FrameValidationError>,
    final_max_frame_size: u32,
) {
    // Invariant: Maximum frame size should never exceed RFC_MAX_FRAME_SIZE
    assert!(
        final_max_frame_size <= RFC_MAX_FRAME_SIZE,
        "Final max frame size {} exceeds RFC maximum {}",
        final_max_frame_size,
        RFC_MAX_FRAME_SIZE
    );

    // Invariant: If we set to exact maximum, it should equal RFC_MAX_FRAME_SIZE
    if matches!(input.setting_strategy, SettingStrategy::ExactMax) && result.is_ok() {
        assert_eq!(final_max_frame_size, RFC_MAX_FRAME_SIZE);
    }

    // Invariant: DATA frames exactly at limit should be accepted
    for data_test in &input.data_frame_tests {
        if let PayloadSize::AtMaximum = data_test.payload_size {
            // Frame at maximum should succeed if no other errors
            if data_test.stream_id != 0 && !data_test.properties.padded {
                // Basic frame should succeed
                match result {
                    Ok(()) => {
                        // Expected
                    }
                    Err(FrameValidationError::FrameSizeExceeded { size, max }) => {
                        // This shouldn't happen for frames exactly at maximum
                        if *size == *max {
                            panic!("Frame at exact maximum size should not be rejected");
                        }
                    }
                    Err(FrameValidationError::InvalidStreamState) => {}
                    Err(error) => {
                        panic!(
                            "unpadded frame at exact maximum failed with unexpected error: {:?}",
                            error
                        );
                    }
                }
            }
        }
    }

    // Invariant: Frames larger than final_max_frame_size should be rejected
    for data_test in &input.data_frame_tests {
        let frame_size = MockH2MaxFrameSizeParser::generate_frame_size(
            &data_test.payload_size,
            final_max_frame_size,
        );

        // Add padding to frame size
        let padding_size = if data_test.properties.padded {
            1 + data_test.properties.padding_length as u32
        } else {
            0
        };
        let total_size = frame_size + padding_size;

        if total_size > final_max_frame_size {
            // Should result in FrameSizeExceeded error
            match result {
                Err(FrameValidationError::FrameSizeExceeded { .. }) => {
                    // Expected
                }
                Ok(()) => {
                    panic!(
                        "DATA frame total size {} exceeded final max {} but was accepted",
                        total_size, final_max_frame_size
                    );
                }
                Err(error) => assert_data_frame_error(error, "oversized DATA invariant"),
            }
        }
    }

    // Invariant: Stream ID 0 for DATA frames should always be rejected
    for data_test in &input.data_frame_tests {
        if data_test.stream_id == 0 {
            match result {
                Err(FrameValidationError::InvalidStreamId) => {
                    // Expected
                }
                Ok(()) => {
                    panic!("DATA frame with stream ID 0 should be rejected");
                }
                Err(error) => assert_data_frame_error(error, "stream ID zero invariant"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc_max_frame_size_accepted() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Setting to RFC maximum should succeed
        let result = parser.process_settings_frame(RFC_MAX_FRAME_SIZE);
        assert!(result.is_ok());
        assert_eq!(parser.max_frame_size, RFC_MAX_FRAME_SIZE);
    }

    #[test]
    fn test_frame_size_above_rfc_max_rejected() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Setting above RFC maximum should fail
        let result = parser.process_settings_frame(RFC_MAX_FRAME_SIZE + 1);
        assert!(matches!(
            result,
            Err(FrameValidationError::InvalidMaxFrameSize { .. })
        ));
    }

    #[test]
    fn test_frame_size_below_rfc_min_rejected() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Setting below RFC minimum should fail
        let result = parser.process_settings_frame(RFC_MIN_FRAME_SIZE - 1);
        assert!(matches!(
            result,
            Err(FrameValidationError::InvalidMaxFrameSize { .. })
        ));
    }

    #[test]
    fn test_data_frame_at_max_size() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Set to maximum frame size
        parser.process_settings_frame(RFC_MAX_FRAME_SIZE).unwrap();

        // DATA frame at maximum size should be accepted
        let properties = DataFrameProperties {
            end_stream: false,
            padded: false,
            padding_length: 0,
            data_pattern: DataPattern::Zeros,
        };

        let result = parser.process_data_frame(1, RFC_MAX_FRAME_SIZE, &properties);
        assert!(result.is_ok());
    }

    #[test]
    fn test_data_frame_exceeds_max_size() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Set to maximum frame size
        parser.process_settings_frame(RFC_MAX_FRAME_SIZE).unwrap();

        // DATA frame exceeding maximum should be rejected
        let properties = DataFrameProperties {
            end_stream: false,
            padded: false,
            padding_length: 0,
            data_pattern: DataPattern::Zeros,
        };

        // This would exceed any possible frame size limit
        let result = parser.process_data_frame(1, RFC_MAX_FRAME_SIZE + 1, &properties);
        assert!(matches!(
            result,
            Err(FrameValidationError::FrameSizeExceeded { .. })
        ));
    }

    #[test]
    fn test_data_frame_with_padding_at_limit() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Set to maximum frame size
        parser.process_settings_frame(RFC_MAX_FRAME_SIZE).unwrap();

        // DATA frame with padding that reaches the limit
        let properties = DataFrameProperties {
            end_stream: false,
            padded: true,
            padding_length: 10,
            data_pattern: DataPattern::Zeros,
        };

        // Payload size that with padding reaches the maximum
        let payload_size = RFC_MAX_FRAME_SIZE - 11; // 1 byte for padding length + 10 bytes padding

        let result = parser.process_data_frame(1, payload_size, &properties);
        assert!(result.is_ok());
    }

    #[test]
    fn test_data_frame_with_padding_exceeds_limit() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Set to maximum frame size
        parser.process_settings_frame(RFC_MAX_FRAME_SIZE).unwrap();

        // DATA frame with padding that exceeds the limit
        let properties = DataFrameProperties {
            end_stream: false,
            padded: true,
            padding_length: 10,
            data_pattern: DataPattern::Zeros,
        };

        // Payload size that with padding exceeds the maximum
        let payload_size = RFC_MAX_FRAME_SIZE - 5; // Not enough room for padding overhead

        let result = parser.process_data_frame(1, payload_size, &properties);
        assert!(matches!(
            result,
            Err(FrameValidationError::FrameSizeExceeded { .. })
        ));
    }

    #[test]
    fn test_progressive_frame_size_updates() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Progressive updates to frame size
        let sizes = [32768, 65536, 131072, RFC_MAX_FRAME_SIZE];

        for size in sizes {
            let result = parser.process_settings_frame(size);
            assert!(result.is_ok());
            assert_eq!(parser.max_frame_size, size);
        }
    }

    #[test]
    fn test_stream_id_zero_rejected() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        let properties = DataFrameProperties {
            end_stream: false,
            padded: false,
            padding_length: 0,
            data_pattern: DataPattern::Zeros,
        };

        // Stream ID 0 should be rejected for DATA frames
        let result = parser.process_data_frame(0, 1000, &properties);
        assert!(matches!(result, Err(FrameValidationError::InvalidStreamId)));
    }

    #[test]
    fn test_boundary_values() {
        let mut parser = MockH2MaxFrameSizeParser::new();

        // Test boundaries around RFC_MAX_FRAME_SIZE
        assert!(parser.process_settings_frame(RFC_MAX_FRAME_SIZE).is_ok());
        assert!(
            parser
                .process_settings_frame(RFC_MAX_FRAME_SIZE - 1)
                .is_ok()
        );
        assert!(matches!(
            parser.process_settings_frame(RFC_MAX_FRAME_SIZE + 1),
            Err(FrameValidationError::InvalidMaxFrameSize { .. })
        ));

        // Test boundaries around RFC_MIN_FRAME_SIZE
        assert!(parser.process_settings_frame(RFC_MIN_FRAME_SIZE).is_ok());
        assert!(matches!(
            parser.process_settings_frame(RFC_MIN_FRAME_SIZE - 1),
            Err(FrameValidationError::InvalidMaxFrameSize { .. })
        ));
    }
}
