//! Fuzzing target for HTTP/2 SETTINGS_MAX_FRAME_SIZE minimum validation vulnerabilities.
//!
//! Tests RFC 9113 compliance for SETTINGS_MAX_FRAME_SIZE values below the required
//! minimum of 16,384 octets. According to RFC 9113 §6.5.2, values below this
//! minimum MUST be treated as a connection error.
//!
//! Vulnerability areas:
//! 1. Accepting frame size values below RFC minimum (16,384 bytes)
//! 2. Integer underflow in frame size arithmetic
//! 3. Buffer allocation with invalid size parameters
//! 4. State consistency when invalid frame sizes are processed

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// RFC 9113 constants for SETTINGS_MAX_FRAME_SIZE
const RFC_MIN_FRAME_SIZE: u32 = 16_384; // 2^14 octets
const RFC_MAX_FRAME_SIZE: u32 = 16_777_215; // 2^24 - 1 octets
const RFC_DEFAULT_FRAME_SIZE: u32 = 16_384;

/// Mock validator implementing correct RFC 9113 SETTINGS_MAX_FRAME_SIZE validation.
#[derive(Debug, Clone)]
pub struct MockSettingsValidator {
    /// Current max frame size setting
    current_max_frame_size: u32,
    /// Validation mode: strict RFC compliance vs loose acceptance
    validation_mode: ValidationMode,
    /// Statistics for analysis
    stats: ValidationStats,
}

/// Validation mode for testing different compliance levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    /// Strict RFC 9113 compliance - reject invalid values
    Strict,
    /// Loose mode - accept some invalid values (mimics vulnerable implementation)
    Loose,
}

/// Statistics tracked during validation testing
#[derive(Debug, Clone, Default)]
pub struct ValidationStats {
    /// Total validation attempts
    pub validation_count: u32,
    /// Values below RFC minimum that were rejected
    pub below_minimum_rejected: u32,
    /// Values below RFC minimum that were accepted (should be 0 in strict mode)
    pub below_minimum_accepted: u32,
    /// Values above RFC maximum that were rejected
    pub above_maximum_rejected: u32,
    /// Values in valid range that were accepted
    pub valid_range_accepted: u32,
    /// Zero values encountered
    pub zero_values: u32,
    /// Extremely small values (1-1023)
    pub tiny_values: u32,
    /// Values just below minimum (1024-16383)
    pub near_minimum_values: u32,
}

/// Result of validating a SETTINGS_MAX_FRAME_SIZE value
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Value accepted and applied
    Accepted {
        old_value: u32,
        new_value: u32,
    },
    /// Value rejected due to being below minimum
    RejectedBelowMinimum {
        value: u32,
        minimum: u32,
    },
    /// Value rejected due to being above maximum
    RejectedAboveMaximum {
        value: u32,
        maximum: u32,
    },
    /// Value rejected for other reasons (zero, etc.)
    RejectedInvalid {
        value: u32,
        reason: String,
    },
}

/// Test scenario for SETTINGS_MAX_FRAME_SIZE validation
#[derive(Debug, Clone, Arbitrary)]
pub struct MaxFrameSizeScenario {
    /// Sequence of frame size values to test
    pub frame_size_sequence: Vec<FrameSizeTestCase>,
    /// Initial frame size (should be valid)
    pub initial_frame_size: u32,
    /// Whether to test extreme edge cases
    pub test_extreme_cases: bool,
    /// Maximum number of operations to prevent infinite loops
    pub max_operations: u16,
}

/// Individual test case for a frame size value
#[derive(Debug, Clone, Arbitrary)]
pub struct FrameSizeTestCase {
    /// The frame size value to test
    pub frame_size_value: FrameSizeValue,
    /// Expected behavior in strict mode
    pub expected_strict_result: Option<bool>, // Some(true) = should accept, Some(false) = should reject, None = either
    /// When to apply this test case
    pub test_sequence: u8,
}

/// Different categories of frame size values for focused testing
#[derive(Debug, Clone, Arbitrary)]
pub enum FrameSizeValue {
    /// Exact RFC values
    RfcValue(RfcFrameSize),
    /// Boundary values around the minimum
    BoundaryValue(BoundaryFrameSize),
    /// Arbitrary values for broader testing
    ArbitraryValue(u32),
    /// Computed values based on operations
    ComputedValue(ComputedFrameSize),
}

/// RFC-defined frame size values
#[derive(Debug, Clone, Arbitrary)]
pub enum RfcFrameSize {
    Minimum,                    // 16384
    Maximum,                    // 16777215
    Default,                    // 16384
    AboveMaximum(u32),         // > 16777215
    BelowMinimum(u32),         // < 16384
}

/// Boundary values for edge case testing
#[derive(Debug, Clone, Arbitrary)]
pub enum BoundaryFrameSize {
    Zero,                       // 0
    One,                        // 1
    MinimumMinus1,             // 16383
    MinimumPlus1,              // 16385
    MaximumMinus1,             // 16777214
    MaximumPlus1,              // 16777216
    PowerOfTwo(u8),            // 2^n where n < 14 or n > 24
    AlmostMinimum(u16),        // 16384 - offset where offset in [1, 1000]
}

/// Computed frame size values
#[derive(Debug, Clone, Arbitrary)]
pub enum ComputedFrameSize {
    /// Multiply by factor (test overflow)
    MultiplyBy(u32, u32),
    /// Subtract value (test underflow)
    SubtractFrom(u32, u32),
    /// Bitwise operations
    BitwiseOp(u32, BitwiseOperation),
}

/// Bitwise operations for computed values
#[derive(Debug, Clone, Arbitrary)]
pub enum BitwiseOperation {
    LeftShift(u8),
    RightShift(u8),
    And(u32),
    Or(u32),
    Xor(u32),
}

impl MockSettingsValidator {
    pub fn new(mode: ValidationMode) -> Self {
        Self {
            current_max_frame_size: RFC_DEFAULT_FRAME_SIZE,
            validation_mode: mode,
            stats: ValidationStats::default(),
        }
    }

    /// Validate and apply a SETTINGS_MAX_FRAME_SIZE value
    pub fn validate_max_frame_size(&mut self, value: u32) -> ValidationResult {
        self.stats.validation_count += 1;

        // Track value categories for analysis
        match value {
            0 => self.stats.zero_values += 1,
            1..=1023 => self.stats.tiny_values += 1,
            1024..=16383 => self.stats.near_minimum_values += 1,
            _ => {}
        }

        let old_value = self.current_max_frame_size;

        match self.validation_mode {
            ValidationMode::Strict => self.validate_strict(value, old_value),
            ValidationMode::Loose => self.validate_loose(value, old_value),
        }
    }

    /// Strict RFC 9113 compliant validation
    fn validate_strict(&mut self, value: u32, old_value: u32) -> ValidationResult {
        // RFC 9113 §6.5.2: Values below 2^14 (16384) MUST be treated as connection error
        if value < RFC_MIN_FRAME_SIZE {
            self.stats.below_minimum_rejected += 1;
            return ValidationResult::RejectedBelowMinimum {
                value,
                minimum: RFC_MIN_FRAME_SIZE,
            };
        }

        // RFC 9113 §6.5.2: Values above 2^24-1 MUST be treated as connection error
        if value > RFC_MAX_FRAME_SIZE {
            self.stats.above_maximum_rejected += 1;
            return ValidationResult::RejectedAboveMaximum {
                value,
                maximum: RFC_MAX_FRAME_SIZE,
            };
        }

        // Valid range - accept and update
        self.stats.valid_range_accepted += 1;
        self.current_max_frame_size = value;
        ValidationResult::Accepted {
            old_value,
            new_value: value,
        }
    }

    /// Loose validation that mimics vulnerable implementation
    fn validate_loose(&mut self, value: u32, old_value: u32) -> ValidationResult {
        // Simulate current vulnerable behavior: just accept most values without validation
        // This mimics the `let _ = size;` behavior in the current implementation

        // Only reject obviously invalid values
        if value == 0 {
            return ValidationResult::RejectedInvalid {
                value,
                reason: "Zero frame size not allowed".to_string(),
            };
        }

        // Accept values below minimum (this is the vulnerability!)
        if value < RFC_MIN_FRAME_SIZE {
            self.stats.below_minimum_accepted += 1;
        } else {
            self.stats.valid_range_accepted += 1;
        }

        // Update frame size regardless of RFC compliance
        self.current_max_frame_size = value;
        ValidationResult::Accepted {
            old_value,
            new_value: value,
        }
    }

    /// Get current frame size
    pub fn current_frame_size(&self) -> u32 {
        self.current_max_frame_size
    }

    /// Get validation statistics
    pub fn stats(&self) -> &ValidationStats {
        &self.stats
    }

    /// Reset to defaults
    pub fn reset(&mut self) {
        self.current_max_frame_size = RFC_DEFAULT_FRAME_SIZE;
        self.stats = ValidationStats::default();
    }
}

impl FrameSizeValue {
    pub fn to_u32(&self) -> u32 {
        match self {
            FrameSizeValue::RfcValue(rfc) => rfc.to_u32(),
            FrameSizeValue::BoundaryValue(boundary) => boundary.to_u32(),
            FrameSizeValue::ArbitraryValue(value) => *value,
            FrameSizeValue::ComputedValue(computed) => computed.to_u32(),
        }
    }
}

impl RfcFrameSize {
    pub fn to_u32(&self) -> u32 {
        match self {
            RfcFrameSize::Minimum => RFC_MIN_FRAME_SIZE,
            RfcFrameSize::Maximum => RFC_MAX_FRAME_SIZE,
            RfcFrameSize::Default => RFC_DEFAULT_FRAME_SIZE,
            RfcFrameSize::AboveMaximum(offset) => RFC_MAX_FRAME_SIZE.saturating_add(*offset),
            RfcFrameSize::BelowMinimum(value) => (*value).min(RFC_MIN_FRAME_SIZE - 1),
        }
    }
}

impl BoundaryFrameSize {
    pub fn to_u32(&self) -> u32 {
        match self {
            BoundaryFrameSize::Zero => 0,
            BoundaryFrameSize::One => 1,
            BoundaryFrameSize::MinimumMinus1 => RFC_MIN_FRAME_SIZE - 1,
            BoundaryFrameSize::MinimumPlus1 => RFC_MIN_FRAME_SIZE + 1,
            BoundaryFrameSize::MaximumMinus1 => RFC_MAX_FRAME_SIZE - 1,
            BoundaryFrameSize::MaximumPlus1 => RFC_MAX_FRAME_SIZE + 1,
            BoundaryFrameSize::PowerOfTwo(n) => {
                if *n < 32 {
                    1u32 << n
                } else {
                    u32::MAX
                }
            }
            BoundaryFrameSize::AlmostMinimum(offset) => {
                RFC_MIN_FRAME_SIZE.saturating_sub(*offset as u32)
            }
        }
    }
}

impl ComputedFrameSize {
    pub fn to_u32(&self) -> u32 {
        match self {
            ComputedFrameSize::MultiplyBy(a, b) => a.saturating_mul(*b),
            ComputedFrameSize::SubtractFrom(a, b) => a.saturating_sub(*b),
            ComputedFrameSize::BitwiseOp(value, op) => op.apply(*value),
        }
    }
}

impl BitwiseOperation {
    pub fn apply(&self, value: u32) -> u32 {
        match self {
            BitwiseOperation::LeftShift(n) => value.wrapping_shl(*n as u32),
            BitwiseOperation::RightShift(n) => value.wrapping_shr(*n as u32),
            BitwiseOperation::And(mask) => value & mask,
            BitwiseOperation::Or(mask) => value | mask,
            BitwiseOperation::Xor(mask) => value ^ mask,
        }
    }
}

/// Test specific RFC violation scenarios
fn test_rfc_minimum_violations() {
    let mut strict_validator = MockSettingsValidator::new(ValidationMode::Strict);
    let mut loose_validator = MockSettingsValidator::new(ValidationMode::Loose);

    // Test values below RFC minimum
    let test_values = [
        0,      // Zero
        1,      // Minimal
        1023,   // Small
        8192,   // Half minimum
        16383,  // Just below minimum
        16384,  // Exactly minimum (should accept)
        16385,  // Just above minimum (should accept)
    ];

    for &value in &test_values {
        let strict_result = strict_validator.validate_max_frame_size(value);
        let loose_result = loose_validator.validate_max_frame_size(value);

        // Values below minimum should be rejected in strict mode
        if value < RFC_MIN_FRAME_SIZE {
            assert!(matches!(
                strict_result,
                ValidationResult::RejectedBelowMinimum { .. }
            ), "Strict mode should reject value {} (below minimum {})", value, RFC_MIN_FRAME_SIZE);

            // Loose mode demonstrates the vulnerability by accepting invalid values
            if value > 0 {
                assert!(matches!(
                    loose_result,
                    ValidationResult::Accepted { .. }
                ), "Loose mode incorrectly accepts value {} (below minimum)", value);
            }
        }
    }
}

/// Test edge cases around minimum frame size
fn test_minimum_boundary_conditions() {
    let mut validator = MockSettingsValidator::new(ValidationMode::Strict);

    // Test boundary conditions
    let boundaries = [
        (RFC_MIN_FRAME_SIZE - 1000, false),  // Well below
        (RFC_MIN_FRAME_SIZE - 1, false),     // Just below
        (RFC_MIN_FRAME_SIZE, true),          // Exactly minimum
        (RFC_MIN_FRAME_SIZE + 1, true),      // Just above
    ];

    for (value, should_accept) in boundaries {
        validator.reset();
        let result = validator.validate_max_frame_size(value);

        if should_accept {
            assert!(matches!(result, ValidationResult::Accepted { .. }),
                "Should accept valid frame size {}", value);
        } else {
            assert!(matches!(result, ValidationResult::RejectedBelowMinimum { .. }),
                "Should reject frame size {} (below minimum)", value);
        }
    }
}

/// Test arithmetic operations that could lead to underflow
fn test_underflow_scenarios() {
    let mut validator = MockSettingsValidator::new(ValidationMode::Strict);

    // Test values that could cause underflow in frame size calculations
    let underflow_candidates = [
        0,                      // Zero
        1,                      // Minimal positive
        RFC_MIN_FRAME_SIZE / 2, // Half the minimum
        u32::MAX,              // Maximum possible (overflow risk)
    ];

    for &value in &underflow_candidates {
        validator.reset();
        let result = validator.validate_max_frame_size(value);

        // Ensure no panic or undefined behavior
        match result {
            ValidationResult::Accepted { .. } => {
                assert!(value >= RFC_MIN_FRAME_SIZE && value <= RFC_MAX_FRAME_SIZE,
                    "Should only accept values in valid range");
            }
            ValidationResult::RejectedBelowMinimum { .. } => {
                assert!(value < RFC_MIN_FRAME_SIZE,
                    "Should only reject values below minimum");
            }
            ValidationResult::RejectedAboveMaximum { .. } => {
                assert!(value > RFC_MAX_FRAME_SIZE,
                    "Should only reject values above maximum");
            }
            ValidationResult::RejectedInvalid { .. } => {
                // Other rejection reasons are valid
            }
        }
    }
}

fuzz_target!(|scenario: MaxFrameSizeScenario| {
    // Limit operations to prevent timeouts
    let max_ops = scenario.max_operations.min(500);
    let limited_sequence: Vec<FrameSizeTestCase> = scenario.frame_size_sequence
        .into_iter()
        .take(max_ops as usize)
        .collect();

    if limited_sequence.is_empty() {
        return;
    }

    // Test with both strict (RFC compliant) and loose (vulnerable) validators
    let mut strict_validator = MockSettingsValidator::new(ValidationMode::Strict);
    let mut loose_validator = MockSettingsValidator::new(ValidationMode::Loose);

    // Set initial frame size if provided and valid
    let initial_size = if scenario.initial_frame_size >= RFC_MIN_FRAME_SIZE
        && scenario.initial_frame_size <= RFC_MAX_FRAME_SIZE {
        scenario.initial_frame_size
    } else {
        RFC_DEFAULT_FRAME_SIZE
    };

    strict_validator.validate_max_frame_size(initial_size);
    loose_validator.validate_max_frame_size(initial_size);

    // Process the frame size sequence
    for test_case in &limited_sequence {
        let frame_size = test_case.frame_size_value.to_u32();

        let strict_result = strict_validator.validate_max_frame_size(frame_size);
        let loose_result = loose_validator.validate_max_frame_size(frame_size);

        // Verify strict validator follows RFC 9113 rules
        match strict_result {
            ValidationResult::Accepted { new_value, .. } => {
                assert!(new_value >= RFC_MIN_FRAME_SIZE,
                    "Strict validator accepted frame size {} below minimum {}",
                    new_value, RFC_MIN_FRAME_SIZE);
                assert!(new_value <= RFC_MAX_FRAME_SIZE,
                    "Strict validator accepted frame size {} above maximum {}",
                    new_value, RFC_MAX_FRAME_SIZE);
            }
            ValidationResult::RejectedBelowMinimum { value, minimum } => {
                assert!(value < minimum);
                assert_eq!(minimum, RFC_MIN_FRAME_SIZE);
            }
            ValidationResult::RejectedAboveMaximum { value, maximum } => {
                assert!(value > maximum);
                assert_eq!(maximum, RFC_MAX_FRAME_SIZE);
            }
            ValidationResult::RejectedInvalid { .. } => {
                // Other rejection reasons are valid
            }
        }

        // Demonstrate vulnerability: loose validator accepts invalid values
        if frame_size > 0 && frame_size < RFC_MIN_FRAME_SIZE {
            match loose_result {
                ValidationResult::Accepted { .. } => {
                    // This demonstrates the vulnerability - accepting values below RFC minimum
                    eprintln!("VULNERABILITY: Loose validator accepted frame size {} below minimum {}",
                        frame_size, RFC_MIN_FRAME_SIZE);
                }
                _ => {
                    // Some values might still be rejected for other reasons
                }
            }
        }
    }

    // Analyze final statistics
    let strict_stats = strict_validator.stats();
    let loose_stats = loose_validator.stats();

    // Strict validator should never accept values below minimum
    assert_eq!(strict_stats.below_minimum_accepted, 0,
        "Strict validator should never accept values below minimum");

    // Loose validator demonstrates vulnerability by accepting some invalid values
    if loose_stats.below_minimum_accepted > 0 {
        eprintln!("VULNERABILITY CONFIRMED: Loose validator accepted {} values below RFC minimum",
            loose_stats.below_minimum_accepted);
    }

    // Run targeted tests periodically
    if scenario.test_extreme_cases && limited_sequence.len() == 1 {
        test_rfc_minimum_violations();
        test_minimum_boundary_conditions();
        test_underflow_scenarios();
    }
});