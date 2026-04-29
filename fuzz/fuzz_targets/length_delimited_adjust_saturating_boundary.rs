#![no_main]

//! Structure-aware fuzz target for length-delimited codec adjust_target_length saturating boundary.
//!
//! Targets edge cases in adjusted_frame_len calculation and saturating boundary conditions:
//! - Length adjustment overflow and underflow at integer boundaries
//! - Transition from saturating_add to checked_add boundary testing
//! - i64/usize conversion boundary conditions in length calculations
//! - Max frame length boundary conditions with length adjustment
//! - Negative frame length detection after adjustment
//! - Header length overflow in offset + length_field_length calculations

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::BytesMut;
use asupersync::codec::length_delimited::LengthDelimitedCodec;
use asupersync::codec::{Decoder, Encoder};

/// Maximum values for fuzzer performance and memory bounds
const MAX_FRAME_LENGTH: usize = 16 * 1024 * 1024; // 16MB
const MAX_BUFFER_SIZE: usize = 1024 * 1024; // 1MB

/// Test scenario for length adjustment saturating boundary conditions
#[derive(Arbitrary, Debug, Clone)]
struct AdjustSaturatingScenario {
    /// Codec configuration targeting boundary conditions
    codec_config: CodecConfig,
    /// Test cases for length adjustment boundaries
    boundary_tests: Vec<BoundaryTest>,
    /// Operations to test adjustment logic
    operations: Vec<AdjustmentOperation>,
}

/// Codec configuration targeting boundary conditions
#[derive(Arbitrary, Debug, Clone)]
struct CodecConfig {
    /// Length field offset
    length_field_offset: OffsetConfig,
    /// Length field length (1-8 bytes)
    length_field_length: FieldLengthConfig,
    /// Length adjustment (can be negative)
    length_adjustment: AdjustmentConfig,
    /// Number of bytes to skip
    num_skip: SkipConfig,
    /// Maximum frame length
    max_frame_length: MaxFrameConfig,
    /// Endianness
    big_endian: bool,
}

/// Length field offset configuration
#[derive(Arbitrary, Debug, Clone)]
enum OffsetConfig {
    /// Normal small offsets
    Small(u8), // 0-255
    /// Boundary offsets
    Boundary(OffsetBoundary),
    /// Large offsets near limits
    Large(LargeOffset),
}

impl OffsetConfig {
    fn as_usize(self) -> usize {
        match self {
            OffsetConfig::Small(n) => n as usize,
            OffsetConfig::Boundary(b) => b.as_usize(),
            OffsetConfig::Large(l) => l.as_usize(),
        }
    }
}

/// Offset boundary test cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum OffsetBoundary {
    Zero,
    MaxU8,
    MaxU16,
    NearUsizeMax,
}

impl OffsetBoundary {
    fn as_usize(self) -> usize {
        match self {
            OffsetBoundary::Zero => 0,
            OffsetBoundary::MaxU8 => u8::MAX as usize,
            OffsetBoundary::MaxU16 => u16::MAX as usize,
            OffsetBoundary::NearUsizeMax => usize::MAX / 2, // Safe large value
        }
    }
}

/// Large offset configuration
#[derive(Arbitrary, Debug, Clone, Copy)]
enum LargeOffset {
    Near1MB,
    Near16MB,
    NearMax,
}

impl LargeOffset {
    fn as_usize(self) -> usize {
        match self {
            LargeOffset::Near1MB => 1024 * 1024 - 16,
            LargeOffset::Near16MB => 16 * 1024 * 1024 - 64,
            LargeOffset::NearMax => usize::MAX / 4, // Safe large value
        }
    }
}

/// Field length configuration (1-8 bytes valid)
#[derive(Arbitrary, Debug, Clone, Copy)]
enum FieldLengthConfig {
    Valid(u8),    // 1-8
    Boundary(FieldLengthBoundary),
    Invalid(u8),  // 0, 9+
}

impl FieldLengthConfig {
    fn as_usize(self) -> usize {
        match self {
            FieldLengthConfig::Valid(n) => ((n % 8) + 1) as usize, // 1-8
            FieldLengthConfig::Boundary(b) => b.as_usize(),
            FieldLengthConfig::Invalid(n) => n as usize, // Can be 0 or >8
        }
    }
}

/// Field length boundary cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum FieldLengthBoundary {
    Min,        // 1
    Max,        // 8
    JustOver,   // 9
    Zero,       // 0 (invalid)
}

impl FieldLengthBoundary {
    fn as_usize(self) -> usize {
        match self {
            FieldLengthBoundary::Min => 1,
            FieldLengthBoundary::Max => 8,
            FieldLengthBoundary::JustOver => 9,
            FieldLengthBoundary::Zero => 0,
        }
    }
}

/// Length adjustment configuration
#[derive(Arbitrary, Debug, Clone)]
enum AdjustmentConfig {
    /// Small adjustments
    Small(i8), // -128 to 127
    /// Boundary adjustments
    Boundary(AdjustmentBoundary),
    /// Large adjustments near limits
    Large(LargeAdjustment),
}

impl AdjustmentConfig {
    fn as_isize(self) -> isize {
        match self {
            AdjustmentConfig::Small(n) => n as isize,
            AdjustmentConfig::Boundary(b) => b.as_isize(),
            AdjustmentConfig::Large(l) => l.as_isize(),
        }
    }
}

/// Adjustment boundary test cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum AdjustmentBoundary {
    Zero,
    MaxPositive,      // Near i64::MAX
    MaxNegative,      // Near i64::MIN
    UsizeMaxPositive, // Near usize::MAX
    UsizeMaxNegative, // Near -(usize::MAX)
}

impl AdjustmentBoundary {
    fn as_isize(self) -> isize {
        match self {
            AdjustmentBoundary::Zero => 0,
            AdjustmentBoundary::MaxPositive => (i64::MAX / 2) as isize,
            AdjustmentBoundary::MaxNegative => (i64::MIN / 2) as isize,
            AdjustmentBoundary::UsizeMaxPositive => (usize::MAX / 4) as isize,
            AdjustmentBoundary::UsizeMaxNegative => -((usize::MAX / 4) as isize),
        }
    }
}

/// Large adjustment values
#[derive(Arbitrary, Debug, Clone, Copy)]
enum LargeAdjustment {
    LargePositive(u32),
    LargeNegative(u32),
    OverflowPositive,  // Designed to overflow when added
    OverflowNegative,  // Designed to underflow when added
}

impl LargeAdjustment {
    fn as_isize(self) -> isize {
        match self {
            LargeAdjustment::LargePositive(n) => (n % 1_000_000) as isize + 1_000_000,
            LargeAdjustment::LargeNegative(n) => -((n % 1_000_000) as isize + 1_000_000),
            LargeAdjustment::OverflowPositive => (i64::MAX / 2) as isize,
            LargeAdjustment::OverflowNegative => (i64::MIN / 2) as isize,
        }
    }
}

/// Skip configuration
#[derive(Arbitrary, Debug, Clone)]
enum SkipConfig {
    None,              // Use default (header length)
    Small(u8),         // 0-255
    Boundary(SkipBoundary),
    Large(u32),        // Large skip values
}

impl SkipConfig {
    fn as_option_usize(self) -> Option<usize> {
        match self {
            SkipConfig::None => None,
            SkipConfig::Small(n) => Some(n as usize),
            SkipConfig::Boundary(b) => Some(b.as_usize()),
            SkipConfig::Large(n) => Some((n % 1_000_000) as usize + 1000),
        }
    }
}

/// Skip boundary test cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum SkipBoundary {
    Zero,
    HeaderLength,  // Will be set to header length
    MaxU16,
    Large,
}

impl SkipBoundary {
    fn as_usize(self) -> usize {
        match self {
            SkipBoundary::Zero => 0,
            SkipBoundary::HeaderLength => 100, // Placeholder, will be adjusted
            SkipBoundary::MaxU16 => u16::MAX as usize,
            SkipBoundary::Large => 1_000_000,
        }
    }
}

/// Max frame length configuration
#[derive(Arbitrary, Debug, Clone)]
enum MaxFrameConfig {
    /// Small frame limits
    Small(u32), // 1KB - 64KB
    /// Standard frame limits
    Standard(StandardFrameSize),
    /// Large frame limits
    Large(LargeFrameSize),
    /// Boundary frame limits
    Boundary(FrameBoundary),
}

impl MaxFrameConfig {
    fn as_usize(self) -> usize {
        match self {
            MaxFrameConfig::Small(n) => ((n % 64) * 1024 + 1024) as usize, // 1KB-64KB
            MaxFrameConfig::Standard(s) => s.as_usize(),
            MaxFrameConfig::Large(l) => l.as_usize(),
            MaxFrameConfig::Boundary(b) => b.as_usize(),
        }
    }
}

/// Standard frame sizes
#[derive(Arbitrary, Debug, Clone, Copy)]
enum StandardFrameSize {
    Default,   // 8MB
    Medium,    // 16MB
    Large,     // 32MB
}

impl StandardFrameSize {
    fn as_usize(self) -> usize {
        match self {
            StandardFrameSize::Default => 8 * 1024 * 1024,
            StandardFrameSize::Medium => 16 * 1024 * 1024,
            StandardFrameSize::Large => 32 * 1024 * 1024,
        }
    }
}

/// Large frame sizes
#[derive(Arbitrary, Debug, Clone, Copy)]
enum LargeFrameSize {
    VeryLarge,    // 64MB
    Huge,         // 128MB
    Maximum,      // Near usize::MAX
}

impl LargeFrameSize {
    fn as_usize(self) -> usize {
        match self {
            LargeFrameSize::VeryLarge => 64 * 1024 * 1024,
            LargeFrameSize::Huge => 128 * 1024 * 1024,
            LargeFrameSize::Maximum => MAX_FRAME_LENGTH,
        }
    }
}

/// Frame boundary test cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum FrameBoundary {
    One,           // Minimum frame
    MaxU32,        // u32::MAX
    NearUsizeMax,  // Near usize::MAX
}

impl FrameBoundary {
    fn as_usize(self) -> usize {
        match self {
            FrameBoundary::One => 1,
            FrameBoundary::MaxU32 => u32::MAX as usize,
            FrameBoundary::NearUsizeMax => MAX_FRAME_LENGTH,
        }
    }
}

/// Boundary test scenarios
#[derive(Arbitrary, Debug, Clone)]
struct BoundaryTest {
    /// Test name/category
    test_type: BoundaryTestType,
    /// Input length value to adjust
    input_length: LengthInput,
    /// Expected outcome
    expected_outcome: ExpectedOutcome,
}

/// Types of boundary tests
#[derive(Arbitrary, Debug, Clone)]
enum BoundaryTestType {
    /// Test i64 conversion boundaries
    I64Conversion,
    /// Test adjustment overflow
    AdjustmentOverflow,
    /// Test adjustment underflow
    AdjustmentUnderflow,
    /// Test negative length after adjustment
    NegativeLength,
    /// Test usize conversion boundaries
    UsizeConversion,
    /// Test max frame length boundaries
    MaxFrameLength,
    /// Test header length overflow
    HeaderOverflow,
}

/// Input length values for testing
#[derive(Arbitrary, Debug, Clone)]
enum LengthInput {
    /// Normal length values
    Normal(u32),
    /// Boundary length values
    Boundary(LengthBoundary),
    /// Crafted length values for specific overflow scenarios
    Crafted(CraftedLength),
}

impl LengthInput {
    fn as_u64(self) -> u64 {
        match self {
            LengthInput::Normal(n) => n as u64,
            LengthInput::Boundary(b) => b.as_u64(),
            LengthInput::Crafted(c) => c.as_u64(),
        }
    }
}

/// Length boundary values
#[derive(Arbitrary, Debug, Clone, Copy)]
enum LengthBoundary {
    Zero,
    One,
    MaxU32,
    MaxI64Positive,
    MaxI64AsU64,
    MaxU64,
}

impl LengthBoundary {
    fn as_u64(self) -> u64 {
        match self {
            LengthBoundary::Zero => 0,
            LengthBoundary::One => 1,
            LengthBoundary::MaxU32 => u32::MAX as u64,
            LengthBoundary::MaxI64Positive => i64::MAX as u64,
            LengthBoundary::MaxI64AsU64 => i64::MAX as u64,
            LengthBoundary::MaxU64 => u64::MAX,
        }
    }
}

/// Crafted length values for specific scenarios
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CraftedLength {
    /// Length that will overflow when positive adjustment added
    OverflowWithPosAdjust,
    /// Length that will underflow when negative adjustment added
    UnderflowWithNegAdjust,
    /// Length near i64::MAX boundary
    NearI64Max,
    /// Length near usize::MAX boundary
    NearUsizeMax,
}

impl CraftedLength {
    fn as_u64(self) -> u64 {
        match self {
            CraftedLength::OverflowWithPosAdjust => (i64::MAX - 1000) as u64,
            CraftedLength::UnderflowWithNegAdjust => 1000,
            CraftedLength::NearI64Max => (i64::MAX - 100) as u64,
            CraftedLength::NearUsizeMax => (usize::MAX - 1000) as u64,
        }
    }
}

/// Expected test outcomes
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ExpectedOutcome {
    /// Should succeed
    Success,
    /// Should fail with specific error
    Error(ExpectedError),
    /// Either success or specific error is acceptable
    SuccessOrError(ExpectedError),
}

/// Expected error types
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ExpectedError {
    LengthExceedsI64,
    AdjustmentExceedsI64,
    LengthOverflow,
    NegativeFrameLength,
    LengthExceedsUsize,
    FrameLengthExceedsMax,
    HeaderLengthOverflow,
}

/// Operations to test adjustment logic
#[derive(Arbitrary, Debug, Clone)]
enum AdjustmentOperation {
    /// Test codec building with boundary config
    BuildCodec,
    /// Test decoding with crafted frames
    DecodeFrame {
        frame_data: FrameData,
    },
    /// Test encoding with boundary lengths
    EncodeFrame {
        payload_size: PayloadSize,
    },
    /// Test direct adjustment calculation
    DirectAdjustment {
        raw_length: u64,
    },
}

/// Frame data for decoding tests
#[derive(Arbitrary, Debug, Clone)]
enum FrameData {
    /// Well-formed frame
    WellFormed {
        payload: PayloadPattern,
    },
    /// Frame with crafted length header
    CraftedLength {
        length_bytes: Vec<u8>, // Raw length bytes
        payload: PayloadPattern,
    },
    /// Truncated frame
    Truncated {
        declared_length: u32,
        actual_payload: u16, // Shorter than declared
    },
    /// Oversized frame
    Oversized {
        declared_length: u32,
        // Payload will be generated to exceed limits
    },
}

/// Payload patterns
#[derive(Arbitrary, Debug, Clone)]
enum PayloadPattern {
    Empty,
    Fixed(u8),        // Repeated byte
    Random(u32),      // Random with seed
    Incremental,      // 0, 1, 2, ...
}

/// Payload size for encoding tests
#[derive(Arbitrary, Debug, Clone)]
enum PayloadSize {
    Small(u16),       // 0-65535
    Medium(u32),      // Up to 1MB
    Large(u32),       // Up to 16MB
    Boundary(PayloadSizeBoundary),
}

impl PayloadSize {
    fn as_usize(self) -> usize {
        match self {
            PayloadSize::Small(n) => n as usize,
            PayloadSize::Medium(n) => (n as usize % (1024 * 1024)).max(1),
            PayloadSize::Large(n) => (n as usize % MAX_BUFFER_SIZE).max(1),
            PayloadSize::Boundary(b) => b.as_usize(),
        }
    }
}

/// Payload size boundary cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum PayloadSizeBoundary {
    Zero,
    One,
    MaxU16,
    Near1MB,
    Near16MB,
}

impl PayloadSizeBoundary {
    fn as_usize(self) -> usize {
        match self {
            PayloadSizeBoundary::Zero => 0,
            PayloadSizeBoundary::One => 1,
            PayloadSizeBoundary::MaxU16 => u16::MAX as usize,
            PayloadSizeBoundary::Near1MB => 1024 * 1024 - 1,
            PayloadSizeBoundary::Near16MB => MAX_BUFFER_SIZE - 1,
        }
    }
}

fuzz_target!(|scenario: AdjustSaturatingScenario| {
    // Limit complexity for fuzzer performance
    if scenario.boundary_tests.len() > 50 {
        return;
    }
    if scenario.operations.len() > 20 {
        return;
    }

    // Test saturating boundary conditions in length adjustment
    test_adjust_saturating_boundaries(&scenario);

    // Test codec building with boundary configurations
    test_codec_boundary_configs(&scenario);

    // Test frame processing with adjustment edge cases
    test_frame_adjustment_edges(&scenario);
});

fn test_adjust_saturating_boundaries(scenario: &AdjustSaturatingScenario) {
    // Test each boundary scenario
    for test in &scenario.boundary_tests {
        test_single_boundary(&scenario.codec_config, test);
    }
}

fn test_single_boundary(config: &CodecConfig, test: &BoundaryTest) {
    let codec_result = build_codec_from_config(config);

    match codec_result {
        Ok(codec) => {
            // Test the specific boundary condition
            match test.test_type {
                BoundaryTestType::I64Conversion => {
                    test_i64_conversion_boundary(&codec, test);
                }
                BoundaryTestType::AdjustmentOverflow => {
                    test_adjustment_overflow(&codec, test);
                }
                BoundaryTestType::AdjustmentUnderflow => {
                    test_adjustment_underflow(&codec, test);
                }
                BoundaryTestType::NegativeLength => {
                    test_negative_length(&codec, test);
                }
                BoundaryTestType::UsizeConversion => {
                    test_usize_conversion(&codec, test);
                }
                BoundaryTestType::MaxFrameLength => {
                    test_max_frame_length(&codec, test);
                }
                BoundaryTestType::HeaderOverflow => {
                    test_header_overflow(&codec, test);
                }
            }
        }
        Err(_) => {
            // Codec building failed - this is expected for some boundary configs
        }
    }
}

fn test_codec_boundary_configs(scenario: &AdjustSaturatingScenario) {
    // Test that codec building handles boundary configurations appropriately
    let result = build_codec_from_config(&scenario.codec_config);

    match result {
        Ok(mut codec) => {
            // Codec built successfully - test some operations
            for operation in &scenario.operations {
                test_adjustment_operation(&mut codec, operation);
            }
        }
        Err(_) => {
            // Codec building failed - this may be expected for invalid configs
        }
    }
}

fn test_frame_adjustment_edges(scenario: &AdjustSaturatingScenario) {
    if let Ok(mut codec) = build_codec_from_config(&scenario.codec_config) {
        // Test frame operations that exercise adjustment logic
        for operation in &scenario.operations {
            match operation {
                AdjustmentOperation::DecodeFrame { frame_data } => {
                    test_decode_frame(&mut codec, frame_data);
                }
                AdjustmentOperation::EncodeFrame { payload_size } => {
                    test_encode_frame(&mut codec, payload_size);
                }
                _ => {}
            }
        }
    }
}

fn build_codec_from_config(config: &CodecConfig) -> Result<LengthDelimitedCodec, String> {
    let mut builder = LengthDelimitedCodec::builder();

    let offset = config.length_field_offset.as_usize();
    let field_length = config.length_field_length.as_usize();
    let adjustment = config.length_adjustment.as_isize();
    let max_frame = config.max_frame_length.as_usize();

    // Validate basic constraints
    if field_length == 0 || field_length > 8 {
        return Err("Invalid field length".to_string());
    }

    if offset.checked_add(field_length).is_none() {
        return Err("Offset + field_length overflows".to_string());
    }

    builder = builder
        .length_field_offset(offset)
        .length_field_length(field_length)
        .length_adjustment(adjustment)
        .max_frame_length(max_frame);

    if config.big_endian {
        builder = builder.big_endian();
    } else {
        builder = builder.little_endian();
    }

    if let Some(skip) = config.num_skip.as_option_usize() {
        builder = builder.num_skip(skip);
    }

    Ok(builder.new_codec())
}

fn test_adjustment_operation(codec: &mut LengthDelimitedCodec, operation: &AdjustmentOperation) {
    match operation {
        AdjustmentOperation::BuildCodec => {
            // Already built
        }
        AdjustmentOperation::DecodeFrame { frame_data } => {
            test_decode_frame(codec, frame_data);
        }
        AdjustmentOperation::EncodeFrame { payload_size } => {
            test_encode_frame(codec, payload_size);
        }
        AdjustmentOperation::DirectAdjustment { raw_length } => {
            // Can't directly test adjusted_frame_len since it's private
            // But we can test it indirectly through decode operations
            let frame = craft_frame_with_length(*raw_length);
            let mut buf = BytesMut::from(frame.as_slice());
            let _result = codec.decode(&mut buf);
        }
    }
}

fn test_i64_conversion_boundary(codec: &LengthDelimitedCodec, test: &BoundaryTest) {
    let length = test.input_length.as_u64();
    let frame = craft_frame_with_length(length);
    let mut buf = BytesMut::from(frame.as_slice());
    let _result = codec.clone().decode(&mut buf);
}

fn test_adjustment_overflow(codec: &LengthDelimitedCodec, test: &BoundaryTest) {
    let length = test.input_length.as_u64();
    let frame = craft_frame_with_length(length);
    let mut buf = BytesMut::from(frame.as_slice());
    let _result = codec.clone().decode(&mut buf);
}

fn test_adjustment_underflow(codec: &LengthDelimitedCodec, test: &BoundaryTest) {
    let length = test.input_length.as_u64();
    let frame = craft_frame_with_length(length);
    let mut buf = BytesMut::from(frame.as_slice());
    let _result = codec.clone().decode(&mut buf);
}

fn test_negative_length(codec: &LengthDelimitedCodec, test: &BoundaryTest) {
    let length = test.input_length.as_u64();
    let frame = craft_frame_with_length(length);
    let mut buf = BytesMut::from(frame.as_slice());
    let _result = codec.clone().decode(&mut buf);
}

fn test_usize_conversion(codec: &LengthDelimitedCodec, test: &BoundaryTest) {
    let length = test.input_length.as_u64();
    let frame = craft_frame_with_length(length);
    let mut buf = BytesMut::from(frame.as_slice());
    let _result = codec.clone().decode(&mut buf);
}

fn test_max_frame_length(codec: &LengthDelimitedCodec, test: &BoundaryTest) {
    let length = test.input_length.as_u64();
    let frame = craft_frame_with_length(length);
    let mut buf = BytesMut::from(frame.as_slice());
    let _result = codec.clone().decode(&mut buf);
}

fn test_header_overflow(_codec: &LengthDelimitedCodec, _test: &BoundaryTest) {
    // Header overflow is tested during codec building
}

fn test_decode_frame(codec: &mut LengthDelimitedCodec, frame_data: &FrameData) {
    let frame = generate_frame_data(frame_data);
    let mut buf = BytesMut::from(frame.as_slice());
    let _result = codec.decode(&mut buf);
}

fn test_encode_frame(codec: &mut LengthDelimitedCodec, payload_size: &PayloadSize) {
    let size = payload_size.as_usize().min(MAX_BUFFER_SIZE);
    let payload = generate_payload(size);
    let mut buf = BytesMut::new();
    let _result = codec.encode(BytesMut::from(payload.as_slice()), &mut buf);
}

fn craft_frame_with_length(length: u64) -> Vec<u8> {
    let mut frame = Vec::new();

    // Write length as big-endian u32 (default format)
    if length <= u32::MAX as u64 {
        frame.extend_from_slice(&(length as u32).to_be_bytes());
    } else {
        // For lengths > u32::MAX, write u32::MAX to test overflow scenarios
        frame.extend_from_slice(&u32::MAX.to_be_bytes());
    }

    // Add minimal payload to avoid truncation errors
    frame.extend_from_slice(b"test");

    frame
}

fn generate_frame_data(frame_data: &FrameData) -> Vec<u8> {
    match frame_data {
        FrameData::WellFormed { payload } => {
            let payload_data = generate_payload_pattern(payload, 100);
            let mut frame = Vec::new();
            frame.extend_from_slice(&(payload_data.len() as u32).to_be_bytes());
            frame.extend_from_slice(&payload_data);
            frame
        }
        FrameData::CraftedLength { length_bytes, payload } => {
            let mut frame = Vec::new();
            frame.extend_from_slice(length_bytes);
            let payload_data = generate_payload_pattern(payload, 100);
            frame.extend_from_slice(&payload_data);
            frame
        }
        FrameData::Truncated { declared_length, actual_payload } => {
            let mut frame = Vec::new();
            frame.extend_from_slice(&declared_length.to_be_bytes());
            let payload_size = (*actual_payload as usize).min(*declared_length as usize / 2);
            frame.extend_from_slice(&vec![0u8; payload_size]);
            frame
        }
        FrameData::Oversized { declared_length } => {
            let mut frame = Vec::new();
            frame.extend_from_slice(&declared_length.to_be_bytes());
            // Don't actually generate oversized payload for performance
            frame.extend_from_slice(b"oversized");
            frame
        }
    }
}

fn generate_payload_pattern(pattern: &PayloadPattern, size: usize) -> Vec<u8> {
    let actual_size = size.min(MAX_BUFFER_SIZE);

    match pattern {
        PayloadPattern::Empty => vec![],
        PayloadPattern::Fixed(byte) => vec![*byte; actual_size],
        PayloadPattern::Random(seed) => {
            let mut data = Vec::with_capacity(actual_size);
            let mut state = *seed;
            for _ in 0..actual_size {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                data.push((state >> 24) as u8);
            }
            data
        }
        PayloadPattern::Incremental => {
            (0..actual_size).map(|i| (i % 256) as u8).collect()
        }
    }
}

fn generate_payload(size: usize) -> Vec<u8> {
    let actual_size = size.min(MAX_BUFFER_SIZE);
    vec![0x42; actual_size] // Simple test pattern
}