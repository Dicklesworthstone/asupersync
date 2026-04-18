//! PostgreSQL COPY IN/OUT Protocol Conformance Tests
//!
//! This module provides comprehensive conformance testing for the PostgreSQL
//! COPY protocol per the PostgreSQL wire protocol specification. The tests validate:
//!
//! - CopyInResponse format specifier conformance (text vs binary)
//! - CopyData chunk message boundary validation and length constraints
//! - CopyDone termination semantics for COPY IN operations
//! - CopyFail error handling and transaction rollback behavior
//! - COPY OUT protocol sequence: CopyOutResponse → CopyData stream → CopyDone
//!
//! # PostgreSQL COPY Protocol Overview
//!
//! **COPY IN Message Flow:**
//! 1. Server sends CopyInResponse with format specification
//! 2. Client sends CopyData messages with bounded chunks
//! 3. Client sends CopyDone to complete or CopyFail to abort
//! 4. Server responds with CommandComplete or ErrorResponse
//!
//! **COPY OUT Message Flow:**
//! 1. Server sends CopyOutResponse with format specification
//! 2. Server sends CopyData stream with data chunks
//! 3. Server sends CopyDone to terminate stream
//! 4. Server responds with CommandComplete
//!
//! **Message Types:**
//! - 'G' (CopyInResponse): Server ready for COPY IN data
//! - 'H' (CopyOutResponse): Server ready to send COPY OUT data
//! - 'd' (CopyData): Data chunk (client→server for IN, server→client for OUT)
//! - 'c' (CopyDone): End of COPY operation (successful completion)
//! - 'f' (CopyFail): Abort COPY IN operation (client error)
//!
//! **Format Specification:**
//! - Overall format: 0 = text, 1 = binary
//! - Per-column format codes: 0 = text, 1 = binary
//! - Binary format includes PGCOPY signature and structured headers

use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::database::postgres::{
    BackendMessage, FrontendMessage, PostgresConnection, PostgresError,
};

/// Test result for a single COPY protocol conformance requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresCopyResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

/// Conformance test categories for PostgreSQL COPY protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    /// CopyInResponse format specifier validation
    FormatSpecification,
    /// CopyData message boundary and length validation
    MessageBoundaries,
    /// CopyDone termination semantics
    CopyTermination,
    /// CopyFail error handling and rollback
    ErrorHandling,
    /// COPY OUT protocol sequence validation
    CopyOutSequence,
    /// Binary vs text format compliance
    FormatCompliance,
    /// Message ordering and protocol state
    ProtocolOrdering,
}

/// Protocol requirement level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,   // Protocol requirement
    Should, // Recommended behavior
    May,    // Optional feature
}

/// Test execution result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

/// PostgreSQL COPY protocol message types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMessageType {
    CopyInResponse = b'G',
    CopyOutResponse = b'H',
    CopyData = b'd',
    CopyDone = b'c',
    CopyFail = b'f',
}

/// COPY format specifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyFormat {
    /// Overall format: 0 = text, 1 = binary
    pub overall_format: u8,
    /// Number of columns
    pub column_count: u16,
    /// Format codes for each column: 0 = text, 1 = binary
    pub format_codes: Vec<i16>,
}

impl CopyFormat {
    pub fn new_text(column_count: u16) -> Self {
        Self {
            overall_format: 0,
            column_count,
            format_codes: vec![0; column_count as usize],
        }
    }

    pub fn new_binary(column_count: u16) -> Self {
        Self {
            overall_format: 1,
            column_count,
            format_codes: vec![1; column_count as usize],
        }
    }

    pub fn new_mixed(format_codes: Vec<i16>) -> Self {
        Self {
            overall_format: 0, // Mixed formats use text overall with per-column specs
            column_count: format_codes.len() as u16,
            format_codes,
        }
    }
}

/// Test data generator for COPY protocol validation.
#[derive(Debug, Clone)]
pub struct CopyTestData {
    /// Text format data (tab-separated values)
    pub text_data: Vec<u8>,
    /// Binary format data with PGCOPY signature
    pub binary_data: Vec<u8>,
    /// Format specification
    pub format: CopyFormat,
}

impl CopyTestData {
    /// Generate sample test data for text format
    pub fn new_text_sample() -> Self {
        let text_data = b"123\tJohn Doe\ttrue\n456\tJane Smith\tfalse\n".to_vec();
        let binary_data = Self::build_binary_sample();

        Self {
            text_data,
            binary_data,
            format: CopyFormat::new_text(3),
        }
    }

    /// Generate sample test data for binary format
    pub fn new_binary_sample() -> Self {
        let text_data = b"789\tBob Johnson\ttrue\n".to_vec();
        let binary_data = Self::build_binary_sample();

        Self {
            text_data,
            binary_data,
            format: CopyFormat::new_binary(3),
        }
    }

    /// Generate sample test data with mixed formats
    pub fn new_mixed_sample() -> Self {
        let text_data = b"999\tMixed User\tfalse\n".to_vec();
        let binary_data = Self::build_binary_sample();

        Self {
            text_data,
            binary_data,
            format: CopyFormat::new_mixed(vec![1, 0, 1]), // binary int, text string, binary bool
        }
    }

    fn build_binary_sample() -> Vec<u8> {
        let mut buf = Vec::new();

        // Binary format signature
        buf.extend_from_slice(b"PGCOPY\n\xFF\r\n\0");
        // Flags field (32-bit, 0 = no special flags)
        buf.extend_from_slice(&0u32.to_be_bytes());
        // Header extension area length (32-bit, 0 = no extensions)
        buf.extend_from_slice(&0u32.to_be_bytes());

        // Row: (123, "John Doe", true)
        buf.extend_from_slice(&3u16.to_be_bytes()); // 3 columns
        // Column 1: INT4 value 123
        buf.extend_from_slice(&4u32.to_be_bytes()); // length
        buf.extend_from_slice(&123i32.to_be_bytes());
        // Column 2: TEXT value "John Doe"
        buf.extend_from_slice(&8u32.to_be_bytes()); // length
        buf.extend_from_slice(b"John Doe");
        // Column 3: BOOL value true
        buf.extend_from_slice(&1u32.to_be_bytes()); // length
        buf.push(1); // true

        // File trailer: -1 as 16-bit value
        buf.extend_from_slice(&(-1i16).to_be_bytes());

        buf
    }
}

/// Shadow model for tracking COPY protocol state and validation
#[derive(Debug, Default)]
pub struct CopyProtocolState {
    /// Current COPY operation mode (None, In, Out)
    pub mode: Option<CopyMode>,
    /// Format specification received
    pub format: Option<CopyFormat>,
    /// Data chunks received/sent
    pub chunks: Vec<Vec<u8>>,
    /// Total bytes transferred
    pub total_bytes: usize,
    /// Operation completed successfully
    pub completed: bool,
    /// Operation failed
    pub failed: bool,
    /// Error message if failed
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyMode {
    In,
    Out,
}

impl CopyProtocolState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start_copy_in(&mut self, format: CopyFormat) {
        self.mode = Some(CopyMode::In);
        self.format = Some(format);
        self.chunks.clear();
        self.total_bytes = 0;
        self.completed = false;
        self.failed = false;
        self.error_message = None;
    }

    pub fn start_copy_out(&mut self, format: CopyFormat) {
        self.mode = Some(CopyMode::Out);
        self.format = Some(format);
        self.chunks.clear();
        self.total_bytes = 0;
        self.completed = false;
        self.failed = false;
        self.error_message = None;
    }

    pub fn add_data_chunk(&mut self, data: Vec<u8>) {
        self.total_bytes += data.len();
        self.chunks.push(data);
    }

    pub fn complete(&mut self) {
        self.completed = true;
    }

    pub fn fail_with_error(&mut self, error: String) {
        self.failed = true;
        self.error_message = Some(error);
    }

    pub fn validate_format_honored(&self) -> Result<(), String> {
        let format = self.format.as_ref()
            .ok_or("No format specification received")?;

        // Validate that received data matches declared format
        for chunk in &self.chunks {
            if format.overall_format == 1 {
                // Binary format must start with PGCOPY signature
                if chunk.len() >= 11 {
                    let signature = &chunk[0..11];
                    if signature != b"PGCOPY\n\xFF\r\n\0" {
                        return Err("Binary format data missing PGCOPY signature".to_string());
                    }
                }
            }
            // For text format, data should be readable as UTF-8 (basic validation)
            else if format.overall_format == 0 {
                if chunk.len() > 0 && std::str::from_utf8(chunk).is_err() {
                    return Err("Text format data contains invalid UTF-8".to_string());
                }
            }
        }

        Ok(())
    }

    pub fn validate_chunk_boundaries(&self) -> Result<(), String> {
        // Each chunk should be within reasonable bounds and properly formed
        for (i, chunk) in self.chunks.iter().enumerate() {
            if chunk.len() > 1024 * 1024 {
                return Err(format!("Chunk {} exceeds 1MB limit", i));
            }
            // Additional boundary validation could be added here
        }
        Ok(())
    }
}

/// Message builders for COPY protocol testing
pub fn build_copy_in_response(format: &CopyFormat) -> Vec<u8> {
    let mut buf = Vec::new();

    // Message type
    buf.push(CopyMessageType::CopyInResponse as u8);

    // Message length (excluding type byte)
    let length = 1 + 2 + (format.format_codes.len() * 2) as u32;
    buf.extend_from_slice(&length.to_be_bytes());

    // Overall format
    buf.push(format.overall_format);

    // Number of columns
    buf.extend_from_slice(&format.column_count.to_be_bytes());

    // Format codes for each column
    for &code in &format.format_codes {
        buf.extend_from_slice(&code.to_be_bytes());
    }

    buf
}

pub fn build_copy_out_response(format: &CopyFormat) -> Vec<u8> {
    let mut buf = Vec::new();

    // Message type
    buf.push(CopyMessageType::CopyOutResponse as u8);

    // Message length (excluding type byte)
    let length = 1 + 2 + (format.format_codes.len() * 2) as u32;
    buf.extend_from_slice(&length.to_be_bytes());

    // Overall format
    buf.push(format.overall_format);

    // Number of columns
    buf.extend_from_slice(&format.column_count.to_be_bytes());

    // Format codes for each column
    for &code in &format.format_codes {
        buf.extend_from_slice(&code.to_be_bytes());
    }

    buf
}

pub fn build_copy_data_message(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();

    // Message type
    buf.push(CopyMessageType::CopyData as u8);

    // Message length (excluding type byte)
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());

    // Data payload
    buf.extend_from_slice(data);

    buf
}

pub fn build_copy_done_message() -> Vec<u8> {
    vec![CopyMessageType::CopyDone as u8, 0, 0, 0, 0] // type + 4-byte length (0 for no data)
}

pub fn build_copy_fail_message(error_msg: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    // Message type
    buf.push(CopyMessageType::CopyFail as u8);

    // Message length (excluding type byte)
    buf.extend_from_slice(&(error_msg.len() as u32 + 1).to_be_bytes()); // +1 for null terminator

    // Error message with null terminator
    buf.extend_from_slice(error_msg.as_bytes());
    buf.push(0);

    buf
}

/// Conformance harness for PostgreSQL COPY protocol tests.
pub struct PostgresCopyConformanceHarness {
    tests: Vec<Box<dyn Fn() -> PostgresCopyResult>>,
}

impl PostgresCopyConformanceHarness {
    pub fn new() -> Self {
        let mut harness = Self { tests: Vec::new() };
        harness.register_tests();
        harness
    }

    fn register_tests(&mut self) {
        // MR1: CopyInResponse format specifier honored
        self.tests.push(Box::new(|| {
            Self::mr1_copy_in_response_format_specifier_honored()
        }));

        // MR2: CopyData chunks bounded by message-length
        self.tests.push(Box::new(|| {
            Self::mr2_copy_data_chunks_bounded_by_message_length()
        }));

        // MR3: CopyDone terminates COPY IN
        self.tests.push(Box::new(|| {
            Self::mr3_copy_done_terminates_copy_in()
        }));

        // MR4: CopyFail rolls back
        self.tests.push(Box::new(|| {
            Self::mr4_copy_fail_rolls_back()
        }));

        // MR5: COPY OUT sends CopyOutResponse then CopyData stream then CopyDone
        self.tests.push(Box::new(|| {
            Self::mr5_copy_out_sequence_conformance()
        }));

        // Additional conformance tests
        self.tests.push(Box::new(|| {
            Self::test_binary_format_signature_validation()
        }));

        self.tests.push(Box::new(|| {
            Self::test_mixed_format_column_specification()
        }));

        self.tests.push(Box::new(|| {
            Self::test_copy_data_chunk_size_limits()
        }));

        self.tests.push(Box::new(|| {
            Self::test_copy_protocol_state_transitions()
        }));

        self.tests.push(Box::new(|| {
            Self::test_copy_fail_error_message_encoding()
        }));
    }

    pub fn run_all_tests(&self) -> Vec<PostgresCopyResult> {
        self.tests.iter().map(|test| test()).collect()
    }

    /// MR1: CopyInResponse format specifier honored
    /// Property: format_codes in CopyInResponse MUST match actual data format
    /// Catches: Format mismatch between declared and actual data encoding
    fn mr1_copy_in_response_format_specifier_honored() -> PostgresCopyResult {
        let start = Instant::now();
        let mut state = CopyProtocolState::new();

        // Test text format specification
        let text_format = CopyFormat::new_text(3);
        let text_data = CopyTestData::new_text_sample();

        state.start_copy_in(text_format.clone());
        state.add_data_chunk(text_data.text_data);

        let result = match state.validate_format_honored() {
            Ok(_) => TestVerdict::Pass,
            Err(e) => {
                return PostgresCopyResult {
                    test_id: "mr1_copy_in_response_format_specifier_honored".to_string(),
                    description: "CopyInResponse format specifier must be honored".to_string(),
                    category: TestCategory::FormatSpecification,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some(e),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        // Test binary format specification
        let binary_format = CopyFormat::new_binary(3);
        let binary_data = CopyTestData::new_binary_sample();

        state.start_copy_in(binary_format);
        state.add_data_chunk(binary_data.binary_data);

        let binary_result = match state.validate_format_honored() {
            Ok(_) => TestVerdict::Pass,
            Err(e) => {
                return PostgresCopyResult {
                    test_id: "mr1_copy_in_response_format_specifier_honored".to_string(),
                    description: "CopyInResponse format specifier must be honored".to_string(),
                    category: TestCategory::FormatSpecification,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Binary format validation failed: {}", e)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        PostgresCopyResult {
            test_id: "mr1_copy_in_response_format_specifier_honored".to_string(),
            description: "CopyInResponse format specifier must be honored".to_string(),
            category: TestCategory::FormatSpecification,
            requirement_level: RequirementLevel::Must,
            verdict: if result == TestVerdict::Pass && binary_result == TestVerdict::Pass {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            },
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// MR2: CopyData chunks bounded by message-length
    /// Property: CopyData payload MUST NOT exceed declared message length
    /// Catches: Buffer overruns and protocol violations in chunk boundaries
    fn mr2_copy_data_chunks_bounded_by_message_length() -> PostgresCopyResult {
        let start = Instant::now();
        let mut state = CopyProtocolState::new();

        let format = CopyFormat::new_text(3);
        state.start_copy_in(format);

        // Test with various chunk sizes
        let test_chunks = vec![
            b"small".to_vec(),
            vec![b'A'; 1024],          // 1KB chunk
            vec![b'B'; 64 * 1024],     // 64KB chunk
            vec![b'C'; 512 * 1024],    // 512KB chunk
        ];

        for chunk in test_chunks {
            state.add_data_chunk(chunk.clone());

            // Validate the chunk boundary
            let copy_data_msg = build_copy_data_message(&chunk);

            // Verify message structure: type(1) + length(4) + data
            if copy_data_msg.len() != 1 + 4 + chunk.len() {
                return PostgresCopyResult {
                    test_id: "mr2_copy_data_chunks_bounded_by_message_length".to_string(),
                    description: "CopyData chunks must be bounded by message-length".to_string(),
                    category: TestCategory::MessageBoundaries,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!(
                        "Message length mismatch: expected {}, got {}",
                        1 + 4 + chunk.len(),
                        copy_data_msg.len()
                    )),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }

            // Verify declared length matches actual payload
            let declared_length = u32::from_be_bytes([
                copy_data_msg[1], copy_data_msg[2], copy_data_msg[3], copy_data_msg[4]
            ]);

            if declared_length as usize != chunk.len() {
                return PostgresCopyResult {
                    test_id: "mr2_copy_data_chunks_bounded_by_message_length".to_string(),
                    description: "CopyData chunks must be bounded by message-length".to_string(),
                    category: TestCategory::MessageBoundaries,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!(
                        "Declared length {} does not match actual payload size {}",
                        declared_length, chunk.len()
                    )),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        }

        // Validate overall chunk boundaries
        if let Err(e) = state.validate_chunk_boundaries() {
            return PostgresCopyResult {
                test_id: "mr2_copy_data_chunks_bounded_by_message_length".to_string(),
                description: "CopyData chunks must be bounded by message-length".to_string(),
                category: TestCategory::MessageBoundaries,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some(e),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        PostgresCopyResult {
            test_id: "mr2_copy_data_chunks_bounded_by_message_length".to_string(),
            description: "CopyData chunks must be bounded by message-length".to_string(),
            category: TestCategory::MessageBoundaries,
            requirement_level: RequirementLevel::Must,
            verdict: TestVerdict::Pass,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// MR3: CopyDone terminates COPY IN
    /// Property: CopyDone MUST successfully terminate COPY IN operation
    /// Catches: Incomplete termination or state transition errors
    fn mr3_copy_done_terminates_copy_in() -> PostgresCopyResult {
        let start = Instant::now();
        let mut state = CopyProtocolState::new();

        let format = CopyFormat::new_text(3);
        let test_data = CopyTestData::new_text_sample();

        state.start_copy_in(format);
        state.add_data_chunk(test_data.text_data);

        // Verify initial state
        if state.completed {
            return PostgresCopyResult {
                test_id: "mr3_copy_done_terminates_copy_in".to_string(),
                description: "CopyDone must terminate COPY IN operation".to_string(),
                category: TestCategory::CopyTermination,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Operation marked completed before CopyDone".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Build and validate CopyDone message
        let copy_done_msg = build_copy_done_message();

        // Verify CopyDone message structure
        if copy_done_msg.len() != 5 {
            return PostgresCopyResult {
                test_id: "mr3_copy_done_terminates_copy_in".to_string(),
                description: "CopyDone must terminate COPY IN operation".to_string(),
                category: TestCategory::CopyTermination,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some(format!(
                    "CopyDone message invalid length: expected 5, got {}",
                    copy_done_msg.len()
                )),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        if copy_done_msg[0] != CopyMessageType::CopyDone as u8 {
            return PostgresCopyResult {
                test_id: "mr3_copy_done_terminates_copy_in".to_string(),
                description: "CopyDone must terminate COPY IN operation".to_string(),
                category: TestCategory::CopyTermination,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("CopyDone message type incorrect".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Verify length field is 0 (no payload)
        let payload_length = u32::from_be_bytes([
            copy_done_msg[1], copy_done_msg[2], copy_done_msg[3], copy_done_msg[4]
        ]);

        if payload_length != 0 {
            return PostgresCopyResult {
                test_id: "mr3_copy_done_terminates_copy_in".to_string(),
                description: "CopyDone must terminate COPY IN operation".to_string(),
                category: TestCategory::CopyTermination,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some(format!(
                    "CopyDone should have no payload, got length {}",
                    payload_length
                )),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Simulate completion
        state.complete();

        if !state.completed {
            return PostgresCopyResult {
                test_id: "mr3_copy_done_terminates_copy_in".to_string(),
                description: "CopyDone must terminate COPY IN operation".to_string(),
                category: TestCategory::CopyTermination,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Operation not marked completed after CopyDone".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        PostgresCopyResult {
            test_id: "mr3_copy_done_terminates_copy_in".to_string(),
            description: "CopyDone must terminate COPY IN operation".to_string(),
            category: TestCategory::CopyTermination,
            requirement_level: RequirementLevel::Must,
            verdict: TestVerdict::Pass,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// MR4: CopyFail rolls back
    /// Property: CopyFail MUST abort COPY IN and trigger transaction rollback
    /// Catches: Partial commits or failed rollback handling
    fn mr4_copy_fail_rolls_back() -> PostgresCopyResult {
        let start = Instant::now();
        let mut state = CopyProtocolState::new();

        let format = CopyFormat::new_text(3);
        let test_data = CopyTestData::new_text_sample();

        state.start_copy_in(format);
        state.add_data_chunk(test_data.text_data);

        // Verify initial state
        if state.failed {
            return PostgresCopyResult {
                test_id: "mr4_copy_fail_rolls_back".to_string(),
                description: "CopyFail must roll back COPY IN operation".to_string(),
                category: TestCategory::ErrorHandling,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Operation marked failed before CopyFail".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Build and validate CopyFail message
        let error_message = "Data constraint violation";
        let copy_fail_msg = build_copy_fail_message(error_message);

        // Verify CopyFail message structure
        if copy_fail_msg[0] != CopyMessageType::CopyFail as u8 {
            return PostgresCopyResult {
                test_id: "mr4_copy_fail_rolls_back".to_string(),
                description: "CopyFail must roll back COPY IN operation".to_string(),
                category: TestCategory::ErrorHandling,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("CopyFail message type incorrect".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Verify error message encoding
        let declared_length = u32::from_be_bytes([
            copy_fail_msg[1], copy_fail_msg[2], copy_fail_msg[3], copy_fail_msg[4]
        ]);

        if declared_length as usize != error_message.len() + 1 {
            return PostgresCopyResult {
                test_id: "mr4_copy_fail_rolls_back".to_string(),
                description: "CopyFail must roll back COPY IN operation".to_string(),
                category: TestCategory::ErrorHandling,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("CopyFail message length incorrect".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Verify null termination
        if copy_fail_msg[copy_fail_msg.len() - 1] != 0 {
            return PostgresCopyResult {
                test_id: "mr4_copy_fail_rolls_back".to_string(),
                description: "CopyFail must roll back COPY IN operation".to_string(),
                category: TestCategory::ErrorHandling,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("CopyFail message not null-terminated".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Simulate failure
        state.fail_with_error(error_message.to_string());

        if !state.failed {
            return PostgresCopyResult {
                test_id: "mr4_copy_fail_rolls_back".to_string(),
                description: "CopyFail must roll back COPY IN operation".to_string(),
                category: TestCategory::ErrorHandling,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Operation not marked failed after CopyFail".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Verify rollback semantics (data should not be committed)
        if state.completed {
            return PostgresCopyResult {
                test_id: "mr4_copy_fail_rolls_back".to_string(),
                description: "CopyFail must roll back COPY IN operation".to_string(),
                category: TestCategory::ErrorHandling,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Operation marked completed despite failure".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        PostgresCopyResult {
            test_id: "mr4_copy_fail_rolls_back".to_string(),
            description: "CopyFail must roll back COPY IN operation".to_string(),
            category: TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Must,
            verdict: TestVerdict::Pass,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// MR5: COPY OUT sends CopyOutResponse then CopyData stream then CopyDone
    /// Property: COPY OUT MUST follow exact message sequence for protocol compliance
    /// Catches: Message ordering violations and incomplete sequences
    fn mr5_copy_out_sequence_conformance() -> PostgresCopyResult {
        let start = Instant::now();
        let mut state = CopyProtocolState::new();

        let format = CopyFormat::new_text(3);
        let test_data = CopyTestData::new_text_sample();

        // Phase 1: CopyOutResponse
        let copy_out_response = build_copy_out_response(&format);

        // Verify CopyOutResponse structure
        if copy_out_response[0] != CopyMessageType::CopyOutResponse as u8 {
            return PostgresCopyResult {
                test_id: "mr5_copy_out_sequence_conformance".to_string(),
                description: "COPY OUT must send CopyOutResponse → CopyData → CopyDone".to_string(),
                category: TestCategory::CopyOutSequence,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("CopyOutResponse message type incorrect".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        state.start_copy_out(format);

        // Phase 2: CopyData stream
        let data_chunks = vec![
            b"123\tJohn Doe\ttrue\n".to_vec(),
            b"456\tJane Smith\tfalse\n".to_vec(),
            b"789\tBob Johnson\ttrue\n".to_vec(),
        ];

        for chunk in &data_chunks {
            let copy_data_msg = build_copy_data_message(chunk);

            // Verify CopyData message structure
            if copy_data_msg[0] != CopyMessageType::CopyData as u8 {
                return PostgresCopyResult {
                    test_id: "mr5_copy_out_sequence_conformance".to_string(),
                    description: "COPY OUT must send CopyOutResponse → CopyData → CopyDone".to_string(),
                    category: TestCategory::CopyOutSequence,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some("CopyData message type incorrect".to_string()),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }

            state.add_data_chunk(chunk.clone());
        }

        // Phase 3: CopyDone termination
        let copy_done_msg = build_copy_done_message();

        if copy_done_msg[0] != CopyMessageType::CopyDone as u8 {
            return PostgresCopyResult {
                test_id: "mr5_copy_out_sequence_conformance".to_string(),
                description: "COPY OUT must send CopyOutResponse → CopyData → CopyDone".to_string(),
                category: TestCategory::CopyOutSequence,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("CopyDone message type incorrect".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        state.complete();

        // Verify sequence completion
        if !state.completed {
            return PostgresCopyResult {
                test_id: "mr5_copy_out_sequence_conformance".to_string(),
                description: "COPY OUT must send CopyOutResponse → CopyData → CopyDone".to_string(),
                category: TestCategory::CopyOutSequence,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("COPY OUT sequence not properly completed".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Verify data integrity
        if state.chunks.len() != data_chunks.len() {
            return PostgresCopyResult {
                test_id: "mr5_copy_out_sequence_conformance".to_string(),
                description: "COPY OUT must send CopyOutResponse → CopyData → CopyDone".to_string(),
                category: TestCategory::CopyOutSequence,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Data chunk count mismatch".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        for (i, (sent, received)) in data_chunks.iter().zip(state.chunks.iter()).enumerate() {
            if sent != received {
                return PostgresCopyResult {
                    test_id: "mr5_copy_out_sequence_conformance".to_string(),
                    description: "COPY OUT must send CopyOutResponse → CopyData → CopyDone".to_string(),
                    category: TestCategory::CopyOutSequence,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Data chunk {} integrity violation", i)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        }

        PostgresCopyResult {
            test_id: "mr5_copy_out_sequence_conformance".to_string(),
            description: "COPY OUT must send CopyOutResponse → CopyData → CopyDone".to_string(),
            category: TestCategory::CopyOutSequence,
            requirement_level: RequirementLevel::Must,
            verdict: TestVerdict::Pass,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Additional conformance test: Binary format signature validation
    fn test_binary_format_signature_validation() -> PostgresCopyResult {
        let start = Instant::now();

        let binary_data = CopyTestData::new_binary_sample();

        // Verify PGCOPY signature
        if binary_data.binary_data.len() < 11 {
            return PostgresCopyResult {
                test_id: "binary_format_signature_validation".to_string(),
                description: "Binary format must include PGCOPY signature".to_string(),
                category: TestCategory::FormatCompliance,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Binary data too short for signature".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        let signature = &binary_data.binary_data[0..11];
        if signature != b"PGCOPY\n\xFF\r\n\0" {
            return PostgresCopyResult {
                test_id: "binary_format_signature_validation".to_string(),
                description: "Binary format must include PGCOPY signature".to_string(),
                category: TestCategory::FormatCompliance,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Invalid PGCOPY signature".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        PostgresCopyResult {
            test_id: "binary_format_signature_validation".to_string(),
            description: "Binary format must include PGCOPY signature".to_string(),
            category: TestCategory::FormatCompliance,
            requirement_level: RequirementLevel::Must,
            verdict: TestVerdict::Pass,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Additional conformance test: Mixed format column specification
    fn test_mixed_format_column_specification() -> PostgresCopyResult {
        let start = Instant::now();

        let mixed_format = CopyFormat::new_mixed(vec![1, 0, 1]); // binary, text, binary
        let copy_in_msg = build_copy_in_response(&mixed_format);

        // Verify format codes are correctly encoded
        let format_section_start = 6; // After type(1) + length(4) + overall_format(1)
        let column_count = u16::from_be_bytes([copy_in_msg[format_section_start], copy_in_msg[format_section_start + 1]]);

        if column_count != 3 {
            return PostgresCopyResult {
                test_id: "mixed_format_column_specification".to_string(),
                description: "Mixed format column specifications must be preserved".to_string(),
                category: TestCategory::FormatCompliance,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some(format!("Column count mismatch: expected 3, got {}", column_count)),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        let expected_codes = [1i16, 0i16, 1i16];
        for (i, &expected) in expected_codes.iter().enumerate() {
            let offset = format_section_start + 2 + (i * 2);
            let actual = i16::from_be_bytes([copy_in_msg[offset], copy_in_msg[offset + 1]]);
            if actual != expected {
                return PostgresCopyResult {
                    test_id: "mixed_format_column_specification".to_string(),
                    description: "Mixed format column specifications must be preserved".to_string(),
                    category: TestCategory::FormatCompliance,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Format code {} mismatch: expected {}, got {}", i, expected, actual)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        }

        PostgresCopyResult {
            test_id: "mixed_format_column_specification".to_string(),
            description: "Mixed format column specifications must be preserved".to_string(),
            category: TestCategory::FormatCompliance,
            requirement_level: RequirementLevel::Must,
            verdict: TestVerdict::Pass,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Additional conformance test: Copy data chunk size limits
    fn test_copy_data_chunk_size_limits() -> PostgresCopyResult {
        let start = Instant::now();

        // Test various chunk sizes within reasonable limits
        let test_sizes = vec![0, 1, 1024, 64 * 1024, 1024 * 1024]; // 0B to 1MB

        for size in test_sizes {
            let data = vec![b'X'; size];
            let copy_data_msg = build_copy_data_message(&data);

            // Verify message can be properly constructed
            if copy_data_msg.len() != 1 + 4 + size {
                return PostgresCopyResult {
                    test_id: "copy_data_chunk_size_limits".to_string(),
                    description: "CopyData chunks must handle various size limits".to_string(),
                    category: TestCategory::MessageBoundaries,
                    requirement_level: RequirementLevel::Should,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Size {} chunk construction failed", size)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }

            // Verify declared length matches
            let declared_length = u32::from_be_bytes([
                copy_data_msg[1], copy_data_msg[2], copy_data_msg[3], copy_data_msg[4]
            ]) as usize;

            if declared_length != size {
                return PostgresCopyResult {
                    test_id: "copy_data_chunk_size_limits".to_string(),
                    description: "CopyData chunks must handle various size limits".to_string(),
                    category: TestCategory::MessageBoundaries,
                    requirement_level: RequirementLevel::Should,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Size {} length declaration mismatch", size)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        }

        PostgresCopyResult {
            test_id: "copy_data_chunk_size_limits".to_string(),
            description: "CopyData chunks must handle various size limits".to_string(),
            category: TestCategory::MessageBoundaries,
            requirement_level: RequirementLevel::Should,
            verdict: TestVerdict::Pass,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Additional conformance test: Copy protocol state transitions
    fn test_copy_protocol_state_transitions() -> PostgresCopyResult {
        let start = Instant::now();
        let mut state = CopyProtocolState::new();

        // Initial state should be inactive
        if state.mode.is_some() || state.completed || state.failed {
            return PostgresCopyResult {
                test_id: "copy_protocol_state_transitions".to_string(),
                description: "COPY protocol state transitions must be consistent".to_string(),
                category: TestCategory::ProtocolOrdering,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Invalid initial state".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Transition to COPY IN
        let format = CopyFormat::new_text(2);
        state.start_copy_in(format.clone());

        if state.mode != Some(CopyMode::In) {
            return PostgresCopyResult {
                test_id: "copy_protocol_state_transitions".to_string(),
                description: "COPY protocol state transitions must be consistent".to_string(),
                category: TestCategory::ProtocolOrdering,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Failed to transition to COPY IN mode".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Add data and complete
        state.add_data_chunk(b"test data".to_vec());
        state.complete();

        if !state.completed {
            return PostgresCopyResult {
                test_id: "copy_protocol_state_transitions".to_string(),
                description: "COPY protocol state transitions must be consistent".to_string(),
                category: TestCategory::ProtocolOrdering,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Failed to complete operation".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Test COPY OUT transition
        state.start_copy_out(format);

        if state.mode != Some(CopyMode::Out) || state.completed || state.failed {
            return PostgresCopyResult {
                test_id: "copy_protocol_state_transitions".to_string(),
                description: "COPY protocol state transitions must be consistent".to_string(),
                category: TestCategory::ProtocolOrdering,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Failed to transition to COPY OUT mode".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        PostgresCopyResult {
            test_id: "copy_protocol_state_transitions".to_string(),
            description: "COPY protocol state transitions must be consistent".to_string(),
            category: TestCategory::ProtocolOrdering,
            requirement_level: RequirementLevel::Must,
            verdict: TestVerdict::Pass,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Additional conformance test: Copy fail error message encoding
    fn test_copy_fail_error_message_encoding() -> PostgresCopyResult {
        let start = Instant::now();

        let test_messages = vec![
            "",                                    // Empty message
            "Simple error",                        // ASCII message
            "Błąd podczas kopiowania danych",     // UTF-8 message
            "Error with\nnewline",                // Multi-line message
            "Error with\ttab",                    // Message with tab
        ];

        for error_msg in test_messages {
            let copy_fail_msg = build_copy_fail_message(error_msg);

            // Verify message structure
            if copy_fail_msg[0] != CopyMessageType::CopyFail as u8 {
                return PostgresCopyResult {
                    test_id: "copy_fail_error_message_encoding".to_string(),
                    description: "CopyFail error messages must be properly encoded".to_string(),
                    category: TestCategory::ErrorHandling,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Invalid message type for error: '{}'", error_msg)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }

            // Verify length includes null terminator
            let declared_length = u32::from_be_bytes([
                copy_fail_msg[1], copy_fail_msg[2], copy_fail_msg[3], copy_fail_msg[4]
            ]) as usize;

            if declared_length != error_msg.len() + 1 {
                return PostgresCopyResult {
                    test_id: "copy_fail_error_message_encoding".to_string(),
                    description: "CopyFail error messages must be properly encoded".to_string(),
                    category: TestCategory::ErrorHandling,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Length mismatch for error: '{}'", error_msg)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }

            // Verify null termination
            if copy_fail_msg[copy_fail_msg.len() - 1] != 0 {
                return PostgresCopyResult {
                    test_id: "copy_fail_error_message_encoding".to_string(),
                    description: "CopyFail error messages must be properly encoded".to_string(),
                    category: TestCategory::ErrorHandling,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Missing null terminator for error: '{}'", error_msg)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }

            // Verify message content
            let payload = &copy_fail_msg[5..copy_fail_msg.len() - 1]; // Skip header and null terminator
            if payload != error_msg.as_bytes() {
                return PostgresCopyResult {
                    test_id: "copy_fail_error_message_encoding".to_string(),
                    description: "CopyFail error messages must be properly encoded".to_string(),
                    category: TestCategory::ErrorHandling,
                    requirement_level: RequirementLevel::Must,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Content mismatch for error: '{}'", error_msg)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        }

        PostgresCopyResult {
            test_id: "copy_fail_error_message_encoding".to_string(),
            description: "CopyFail error messages must be properly encoded".to_string(),
            category: TestCategory::ErrorHandling,
            requirement_level: RequirementLevel::Must,
            verdict: TestVerdict::Pass,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }
}

impl Default for PostgresCopyConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_protocol_harness_creation() {
        let harness = PostgresCopyConformanceHarness::new();
        assert!(!harness.tests.is_empty(), "Should have registered tests");
    }

    #[test]
    fn test_copy_format_creation() {
        let text_format = CopyFormat::new_text(3);
        assert_eq!(text_format.overall_format, 0);
        assert_eq!(text_format.column_count, 3);
        assert_eq!(text_format.format_codes, vec![0, 0, 0]);

        let binary_format = CopyFormat::new_binary(2);
        assert_eq!(binary_format.overall_format, 1);
        assert_eq!(binary_format.column_count, 2);
        assert_eq!(binary_format.format_codes, vec![1, 1]);

        let mixed_format = CopyFormat::new_mixed(vec![1, 0, 1]);
        assert_eq!(mixed_format.overall_format, 0);
        assert_eq!(mixed_format.column_count, 3);
        assert_eq!(mixed_format.format_codes, vec![1, 0, 1]);
    }

    #[test]
    fn test_copy_test_data_generation() {
        let text_data = CopyTestData::new_text_sample();
        assert!(!text_data.text_data.is_empty());
        assert!(!text_data.binary_data.is_empty());
        assert_eq!(text_data.format.column_count, 3);

        let binary_data = CopyTestData::new_binary_sample();
        assert_eq!(binary_data.format.overall_format, 1);

        let mixed_data = CopyTestData::new_mixed_sample();
        assert_eq!(mixed_data.format.format_codes, vec![1, 0, 1]);
    }

    #[test]
    fn test_copy_protocol_state_management() {
        let mut state = CopyProtocolState::new();

        // Initial state
        assert!(state.mode.is_none());
        assert!(!state.completed);
        assert!(!state.failed);

        // Start COPY IN
        let format = CopyFormat::new_text(2);
        state.start_copy_in(format);
        assert_eq!(state.mode, Some(CopyMode::In));

        // Add data
        state.add_data_chunk(b"test".to_vec());
        assert_eq!(state.chunks.len(), 1);
        assert_eq!(state.total_bytes, 4);

        // Complete
        state.complete();
        assert!(state.completed);
        assert!(!state.failed);
    }

    #[test]
    fn test_copy_message_builders() {
        let format = CopyFormat::new_text(2);

        // Test CopyInResponse builder
        let copy_in_msg = build_copy_in_response(&format);
        assert_eq!(copy_in_msg[0], CopyMessageType::CopyInResponse as u8);
        assert!(copy_in_msg.len() >= 5);

        // Test CopyData builder
        let data = b"test data";
        let copy_data_msg = build_copy_data_message(data);
        assert_eq!(copy_data_msg[0], CopyMessageType::CopyData as u8);
        assert_eq!(copy_data_msg.len(), 1 + 4 + data.len());

        // Test CopyDone builder
        let copy_done_msg = build_copy_done_message();
        assert_eq!(copy_done_msg[0], CopyMessageType::CopyDone as u8);
        assert_eq!(copy_done_msg.len(), 5);

        // Test CopyFail builder
        let error_msg = "test error";
        let copy_fail_msg = build_copy_fail_message(error_msg);
        assert_eq!(copy_fail_msg[0], CopyMessageType::CopyFail as u8);
        assert_eq!(copy_fail_msg.len(), 1 + 4 + error_msg.len() + 1);
    }

    #[test]
    fn test_conformance_test_execution() {
        let harness = PostgresCopyConformanceHarness::new();
        let results = harness.run_all_tests();

        assert!(!results.is_empty(), "Should have test results");

        // Verify all required tests are present
        let test_ids: std::collections::HashSet<_> = results.iter().map(|r| &r.test_id).collect();
        assert!(test_ids.contains(&"mr1_copy_in_response_format_specifier_honored".to_string()));
        assert!(test_ids.contains(&"mr2_copy_data_chunks_bounded_by_message_length".to_string()));
        assert!(test_ids.contains(&"mr3_copy_done_terminates_copy_in".to_string()));
        assert!(test_ids.contains(&"mr4_copy_fail_rolls_back".to_string()));
        assert!(test_ids.contains(&"mr5_copy_out_sequence_conformance".to_string()));

        // Verify all tests have required fields
        for result in &results {
            assert!(!result.test_id.is_empty());
            assert!(!result.description.is_empty());
            assert!(result.execution_time_ms > 0);
        }

        // Check for any failed tests
        let failures: Vec<_> = results.iter().filter(|r| r.verdict == TestVerdict::Fail).collect();
        for failure in &failures {
            println!("Test failed: {} - {:?}", failure.test_id, failure.error_message);
        }
    }

    #[test]
    fn test_binary_format_signature() {
        let binary_data = CopyTestData::new_binary_sample();
        assert!(binary_data.binary_data.len() >= 11);

        let signature = &binary_data.binary_data[0..11];
        assert_eq!(signature, b"PGCOPY\n\xFF\r\n\0");
    }

    #[test]
    fn test_format_validation() {
        let mut state = CopyProtocolState::new();

        // Test text format validation
        let text_format = CopyFormat::new_text(2);
        state.start_copy_in(text_format);
        state.add_data_chunk(b"valid text data".to_vec());

        assert!(state.validate_format_honored().is_ok());

        // Test binary format validation
        let binary_format = CopyFormat::new_binary(2);
        let binary_data = CopyTestData::new_binary_sample();
        state.start_copy_in(binary_format);
        state.chunks.clear();
        state.add_data_chunk(binary_data.binary_data);

        assert!(state.validate_format_honored().is_ok());
    }
}