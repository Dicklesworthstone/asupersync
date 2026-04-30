//! Structure-aware fuzz target for PostgreSQL ErrorResponse/NoticeResponse/ParameterStatus messages.
//!
//! This fuzzer targets the PostgreSQL auth and error message parsing family:
//! 1. ErrorResponse - server error messages with SQLSTATE codes and detail fields
//! 2. NoticeResponse - warning/notice messages with same structure as ErrorResponse
//! 3. ParameterStatus - server parameter name/value pairs during session setup
//!
//! Uses structure-aware generation to create realistic message payloads that test:
//! - Field code validation (C, M, D, H for errors; name/value for parameters)
//! - String encoding and null-termination handling
//! - Message boundary detection and parsing state
//! - Error classification and detail extraction
//! - Parameter name/value validation and storage
//!
//! Focuses on auth flow and error handling boundaries that could lead to:
//! - Authentication bypass through malformed error responses
//! - Parameter injection via crafted parameter status messages
//! - Buffer overflows in field parsing or string handling
//! - Protocol state confusion during error/notice processing

#![no_main]

use arbitrary::Arbitrary;
use asupersync::database::postgres::{
    fuzz_parse_command_complete_tag, fuzz_parse_error_response, fuzz_parse_notice_response,
    fuzz_parse_parameter_status,
};
use libfuzzer_sys::fuzz_target;

/// Maximum message size to prevent OOM during fuzzing
const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64KB

/// Maximum number of fields in error/notice messages
const MAX_ERROR_FIELDS: usize = 32;

/// Maximum string length for any single field
const MAX_FIELD_LENGTH: usize = 4096;

/// PostgreSQL message scenarios for structure-aware fuzzing
#[derive(Debug, Clone, Arbitrary)]
enum PgMessageScenario {
    /// Standard error response with common field combinations
    StandardError {
        error_fields: Vec<ErrorField>,
        malformed_termination: MalformedTermination,
    },
    /// Notice response (warnings, info messages)
    NoticeMessage {
        notice_fields: Vec<ErrorField>, // Same structure as error
        encoding_issues: EncodingVariant,
    },
    /// Parameter status during authentication/session setup
    ParameterStatus {
        parameter_name: BoundedString,
        parameter_value: BoundedString,
        boundary_conditions: BoundaryTest,
    },
    /// Edge cases: empty messages, malformed fields, boundary violations
    EdgeCaseMessage {
        message_type: EdgeCaseType,
        payload_modifications: Vec<PayloadModification>,
    },
    /// CommandComplete tag parsing for affected-row extraction.
    CommandComplete { tag: CommandCompleteCase },
}

#[derive(Debug, Clone, Arbitrary)]
struct CommandCompleteCase {
    variant: CommandCompleteVariant,
    trailing_nulls: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum CommandCompleteVariant {
    Insert { oid: u32, count: u64 },
    Update { count: u64 },
    Delete { count: u64 },
    Select { count: u64 },
    Copy { count: u64 },
    Malformed(MalformedCommandComplete),
}

#[derive(Debug, Clone, Arbitrary)]
enum CommandCompleteVerb {
    Insert,
    Update,
    Delete,
    Select,
    Copy,
}

#[derive(Debug, Clone, Arbitrary)]
enum MalformedCommandComplete {
    Empty,
    MissingCount {
        command: CommandCompleteVerb,
    },
    NonNumericCount {
        command: CommandCompleteVerb,
        suffix: BoundedString,
    },
    NumberOnly(u64),
    InvalidUtf8,
}

impl CommandCompleteVerb {
    fn as_str(&self) -> &'static str {
        match self {
            CommandCompleteVerb::Insert => "INSERT",
            CommandCompleteVerb::Update => "UPDATE",
            CommandCompleteVerb::Delete => "DELETE",
            CommandCompleteVerb::Select => "SELECT",
            CommandCompleteVerb::Copy => "COPY",
        }
    }
}

/// PostgreSQL error/notice field with type code and value
#[derive(Debug, Clone, Arbitrary)]
struct ErrorField {
    /// Field type code (C=code, M=message, D=detail, H=hint, etc.)
    field_code: ErrorFieldCode,
    /// Field value as null-terminated string
    value: BoundedString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedErrorResponse {
    code: String,
    message: String,
    detail: Option<String>,
    hint: Option<String>,
}

/// PostgreSQL error field codes per wire protocol
#[derive(Debug, Clone, Arbitrary)]
enum ErrorFieldCode {
    /// Severity: ERROR, FATAL, WARNING, NOTICE, DEBUG, INFO, LOG
    Severity, // 'S'
    /// SQLSTATE code (5-char string)
    Code, // 'C'
    /// Primary human-readable error message
    Message, // 'M'
    /// Optional detail message
    Detail, // 'D'
    /// Optional hint message
    Hint, // 'H'
    /// Position of error in query string
    Position, // 'P'
    /// Internal position (for internally generated commands)
    InternalPosition, // 'p'
    /// Internal query text
    InternalQuery, // 'q'
    /// Context in which error occurred
    Where, // 'W'
    /// Schema name
    SchemaName, // 's'
    /// Table name
    TableName, // 't'
    /// Column name
    ColumnName, // 'c'
    /// Data type name
    DataTypeName, // 'd'
    /// Constraint name
    ConstraintName, // 'n'
    /// Source file name
    File, // 'F'
    /// Source line number
    Line, // 'L'
    /// Source function name
    Routine, // 'R'
    /// Unknown/custom field code
    Unknown(u8),
}

impl ErrorFieldCode {
    fn to_byte(&self) -> u8 {
        match self {
            ErrorFieldCode::Severity => b'S',
            ErrorFieldCode::Code => b'C',
            ErrorFieldCode::Message => b'M',
            ErrorFieldCode::Detail => b'D',
            ErrorFieldCode::Hint => b'H',
            ErrorFieldCode::Position => b'P',
            ErrorFieldCode::InternalPosition => b'p',
            ErrorFieldCode::InternalQuery => b'q',
            ErrorFieldCode::Where => b'W',
            ErrorFieldCode::SchemaName => b's',
            ErrorFieldCode::TableName => b't',
            ErrorFieldCode::ColumnName => b'c',
            ErrorFieldCode::DataTypeName => b'd',
            ErrorFieldCode::ConstraintName => b'n',
            ErrorFieldCode::File => b'F',
            ErrorFieldCode::Line => b'L',
            ErrorFieldCode::Routine => b'R',
            ErrorFieldCode::Unknown(code) => *code,
        }
    }
}

/// Bounded string for preventing OOM during fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct BoundedString {
    #[arbitrary(with = arbitrary_bounded_string)]
    value: String,
}

/// Generate bounded strings to prevent memory exhaustion
fn arbitrary_bounded_string(u: &mut arbitrary::Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(0..=MAX_FIELD_LENGTH)?;
    let bytes: Vec<u8> = (0..len)
        .map(|_| u.arbitrary())
        .collect::<arbitrary::Result<_>>()?;

    // Try to create valid UTF-8, fall back to lossy conversion
    String::from_utf8(bytes).or_else(|e| Ok(String::from_utf8_lossy(&e.into_bytes()).into_owned()))
}

/// Message termination variations for testing boundary detection
#[derive(Debug, Clone, Arbitrary)]
enum MalformedTermination {
    /// Properly terminated with null byte
    Proper,
    /// Missing final null terminator
    MissingTerminator,
    /// Extra null bytes
    ExtraTerminators(u8), // Number of extra nulls (0-7)
    /// Embedded nulls in field values
    EmbeddedNulls,
    /// Truncated message
    Truncated(u8), // Bytes to truncate (0-15)
}

/// String encoding variations for testing UTF-8 handling
#[derive(Debug, Clone, Arbitrary)]
enum EncodingVariant {
    /// Standard UTF-8
    Utf8,
    /// Invalid UTF-8 sequences
    InvalidUtf8,
    /// High Unicode codepoints
    HighUnicode,
    /// Control characters
    ControlChars,
    /// Mixed encoding
    Mixed,
}

/// Boundary testing for parameter parsing
#[derive(Debug, Clone, Arbitrary)]
enum BoundaryTest {
    /// Normal parameters
    Normal,
    /// Empty name or value
    EmptyFields,
    /// Very long name/value
    OversizedFields,
    /// Special characters in names
    SpecialChars,
    /// SQL injection attempts in values
    InjectionAttempts,
}

/// Edge case message types
#[derive(Debug, Clone, Arbitrary)]
enum EdgeCaseType {
    /// Completely empty message
    Empty,
    /// Single byte messages
    SingleByte(u8),
    /// Oversized message
    Oversized,
    /// Random bytes
    RandomBytes,
}

/// Payload modification strategies
#[derive(Debug, Clone, Arbitrary)]
enum PayloadModification {
    /// Flip random bits
    BitFlip(u8), // Position to flip
    /// Insert random bytes
    ByteInsert(u8, u8), // Position, value
    /// Delete bytes
    ByteDelete(u8), // Position
    /// Duplicate sections
    SectionDuplicate,
    /// Reverse byte order
    Reverse,
}

/// Build wire format message from error fields
fn build_error_message(fields: &[ErrorField], termination: &MalformedTermination) -> Vec<u8> {
    let mut message = Vec::new();

    for field in fields {
        message.push(field.field_code.to_byte());
        let value = sanitize_field_value(&field.value.value);
        message.extend_from_slice(value.as_bytes());
        message.push(0); // Null terminator for field value
    }

    // Apply termination variant
    match termination {
        MalformedTermination::Proper => {
            message.push(0); // Final null terminator
        }
        MalformedTermination::MissingTerminator => {
            // Don't add final null
        }
        MalformedTermination::ExtraTerminators(count) => {
            for _ in 0..=*count {
                message.push(0);
            }
        }
        MalformedTermination::EmbeddedNulls => {
            // Insert nulls at random positions in existing data
            if !message.is_empty() && fields.len() > 0 {
                let insert_pos = message.len() / 2;
                message.insert(insert_pos, 0);
            }
            message.push(0); // Still add proper terminator
        }
        MalformedTermination::Truncated(bytes) => {
            let truncate_len = message.len().saturating_sub(*bytes as usize);
            message.truncate(truncate_len);
        }
    }

    message
}

fn sanitize_field_value(value: &str) -> String {
    value
        .chars()
        .take(MAX_FIELD_LENGTH)
        .filter(|&ch| ch != '\0')
        .collect()
}

fn expected_error_response(fields: &[ErrorField]) -> ExpectedErrorResponse {
    let mut expected = ExpectedErrorResponse {
        code: String::new(),
        message: String::new(),
        detail: None,
        hint: None,
    };

    for field in fields.iter().take(MAX_ERROR_FIELDS) {
        let value = sanitize_field_value(&field.value.value);
        match field.field_code {
            ErrorFieldCode::Code => expected.code = value,
            ErrorFieldCode::Message => expected.message = value,
            ErrorFieldCode::Detail => expected.detail = Some(value),
            ErrorFieldCode::Hint => expected.hint = Some(value),
            _ => {}
        }
    }

    expected
}

fn assert_error_response_round_trip(fields: &[ErrorField], message: &[u8]) {
    let expected = expected_error_response(fields);
    match fuzz_parse_error_response(message) {
        Ok(asupersync::database::postgres::PgError::Server {
            code,
            message,
            detail,
            hint,
        }) => {
            assert_eq!(code, expected.code);
            assert_eq!(message, expected.message);
            assert_eq!(detail, expected.detail);
            assert_eq!(hint, expected.hint);
        }
        Ok(other) => panic!("expected PgError::Server, got {other:?}"),
        Err(err) => panic!("expected successful ErrorResponse parse, got {err:?}"),
    }
}

/// Build ParameterStatus message format
fn build_parameter_message(
    name: &BoundedString,
    value: &BoundedString,
    boundary: &BoundaryTest,
) -> Vec<u8> {
    let mut message = Vec::new();

    let (actual_name, actual_value) = match boundary {
        BoundaryTest::Normal => (name.value.clone(), value.value.clone()),
        BoundaryTest::EmptyFields => ("".to_string(), "".to_string()),
        BoundaryTest::OversizedFields => {
            ("x".repeat(MAX_FIELD_LENGTH), "y".repeat(MAX_FIELD_LENGTH))
        }
        BoundaryTest::SpecialChars => ("param\0name\x01\x02".to_string(), value.value.clone()),
        BoundaryTest::InjectionAttempts => {
            (name.value.clone(), "'; DROP TABLE users; --".to_string())
        }
    };

    message.extend_from_slice(actual_name.as_bytes());
    message.push(0); // Null terminator for name
    message.extend_from_slice(actual_value.as_bytes());
    message.push(0); // Null terminator for value

    message
}

/// Apply encoding modifications to string data
fn apply_encoding_variant(data: &mut [u8], encoding: &EncodingVariant) {
    match encoding {
        EncodingVariant::Utf8 => {
            // Keep as-is
        }
        EncodingVariant::InvalidUtf8 => {
            // Insert invalid UTF-8 sequences
            for byte in data.iter_mut() {
                if *byte > 128 && *byte < 192 {
                    *byte = 0xFF; // Invalid continuation byte
                }
            }
        }
        EncodingVariant::HighUnicode => {
            // Add high Unicode in various positions
            if data.len() >= 4 {
                data[0] = 0xF4;
                data[1] = 0x8F;
                data[2] = 0xBF;
                data[3] = 0xBF; // U+10FFFF
            }
        }
        EncodingVariant::ControlChars => {
            // Sprinkle control characters
            for (i, byte) in data.iter_mut().enumerate() {
                if i % 7 == 0 {
                    *byte = (i % 32) as u8; // Control chars 0-31
                }
            }
        }
        EncodingVariant::Mixed => {
            // Mix valid and invalid patterns
            for (i, byte) in data.iter_mut().enumerate() {
                if i % 3 == 0 {
                    *byte = if i % 2 == 0 { 0xC0 } else { 0x80 }; // Invalid UTF-8
                }
            }
        }
    }
}

/// Apply payload modifications for edge case testing
fn apply_modifications(mut data: Vec<u8>, modifications: &[PayloadModification]) -> Vec<u8> {
    for modification in modifications {
        match modification {
            PayloadModification::BitFlip(pos) => {
                let idx = (*pos as usize) % data.len().max(1);
                if let Some(byte) = data.get_mut(idx) {
                    *byte ^= 1; // Flip LSB
                }
            }
            PayloadModification::ByteInsert(pos, value) => {
                let insert_pos = (*pos as usize) % (data.len() + 1);
                data.insert(insert_pos, *value);
            }
            PayloadModification::ByteDelete(pos) => {
                if !data.is_empty() {
                    let delete_pos = (*pos as usize) % data.len();
                    data.remove(delete_pos);
                }
            }
            PayloadModification::SectionDuplicate => {
                if data.len() > 4 {
                    let section_len = data.len() / 4;
                    let section = data[0..section_len].to_vec();
                    data.extend_from_slice(&section);
                }
            }
            PayloadModification::Reverse => {
                data.reverse();
            }
        }
    }
    data
}

fn build_command_complete_message(tag: &CommandCompleteCase) -> Vec<u8> {
    let mut message = match &tag.variant {
        CommandCompleteVariant::Insert { oid, count } => {
            format!("INSERT {oid} {count}").into_bytes()
        }
        CommandCompleteVariant::Update { count } => format!("UPDATE {count}").into_bytes(),
        CommandCompleteVariant::Delete { count } => format!("DELETE {count}").into_bytes(),
        CommandCompleteVariant::Select { count } => format!("SELECT {count}").into_bytes(),
        CommandCompleteVariant::Copy { count } => format!("COPY {count}").into_bytes(),
        CommandCompleteVariant::Malformed(MalformedCommandComplete::Empty) => Vec::new(),
        CommandCompleteVariant::Malformed(MalformedCommandComplete::MissingCount { command }) => {
            command.as_str().as_bytes().to_vec()
        }
        CommandCompleteVariant::Malformed(MalformedCommandComplete::NonNumericCount {
            command,
            suffix,
        }) => format!(
            "{} {}",
            command.as_str(),
            sanitize_field_value(&suffix.value)
        )
        .into_bytes(),
        CommandCompleteVariant::Malformed(MalformedCommandComplete::NumberOnly(count)) => {
            count.to_string().into_bytes()
        }
        CommandCompleteVariant::Malformed(MalformedCommandComplete::InvalidUtf8) => {
            vec![0xFF, 0xFE, 0xFD]
        }
    };

    for _ in 0..tag.trailing_nulls {
        message.push(0);
    }

    message
}

fn expected_command_complete_rows(tag: &CommandCompleteCase) -> Option<u64> {
    match &tag.variant {
        CommandCompleteVariant::Insert { count, .. }
        | CommandCompleteVariant::Update { count }
        | CommandCompleteVariant::Delete { count }
        | CommandCompleteVariant::Select { count }
        | CommandCompleteVariant::Copy { count } => Some(*count),
        CommandCompleteVariant::Malformed(_) => None,
    }
}

fuzz_target!(|scenario: PgMessageScenario| {
    // Size guard - prevent OOM
    let estimated_size = match &scenario {
        PgMessageScenario::StandardError { error_fields, .. } => {
            error_fields.len() * MAX_FIELD_LENGTH
        }
        PgMessageScenario::NoticeMessage { notice_fields, .. } => {
            notice_fields.len() * MAX_FIELD_LENGTH
        }
        PgMessageScenario::ParameterStatus {
            parameter_name,
            parameter_value,
            ..
        } => parameter_name.value.len() + parameter_value.value.len(),
        PgMessageScenario::CommandComplete { .. } => MAX_FIELD_LENGTH,
        PgMessageScenario::EdgeCaseMessage { .. } => MAX_MESSAGE_SIZE,
    };

    if estimated_size > MAX_MESSAGE_SIZE {
        return; // Skip oversized inputs
    }

    match scenario {
        PgMessageScenario::StandardError {
            error_fields,
            malformed_termination,
        } => {
            let message = build_error_message(&error_fields, &malformed_termination);

            match malformed_termination {
                MalformedTermination::Proper => {
                    assert_error_response_round_trip(&error_fields, &message);
                }
                MalformedTermination::MissingTerminator
                | MalformedTermination::ExtraTerminators(_)
                | MalformedTermination::Truncated(_) => {
                    assert!(
                        fuzz_parse_error_response(&message).is_err(),
                        "malformed ErrorResponse payload should return Err"
                    );
                }
                MalformedTermination::EmbeddedNulls => {
                    let _ = fuzz_parse_error_response(&message);
                }
            }

            // Test NoticeResponse parsing (same structure)
            let _ = fuzz_parse_notice_response(&message);
        }

        PgMessageScenario::NoticeMessage {
            notice_fields,
            encoding_issues,
        } => {
            let mut message = build_error_message(&notice_fields, &MalformedTermination::Proper);
            apply_encoding_variant(&mut message, &encoding_issues);

            // NoticeResponse uses same format as ErrorResponse
            let _ = fuzz_parse_notice_response(&message);
        }

        PgMessageScenario::ParameterStatus {
            parameter_name,
            parameter_value,
            boundary_conditions,
        } => {
            let message =
                build_parameter_message(&parameter_name, &parameter_value, &boundary_conditions);

            // Test ParameterStatus parsing
            let _ = fuzz_parse_parameter_status(&message);
        }

        PgMessageScenario::EdgeCaseMessage {
            message_type,
            payload_modifications,
        } => {
            let base_message = match message_type {
                EdgeCaseType::Empty => vec![],
                EdgeCaseType::SingleByte(byte) => vec![byte],
                EdgeCaseType::Oversized => vec![0x41; MAX_MESSAGE_SIZE.min(8192)],
                EdgeCaseType::RandomBytes => {
                    // Generate some pseudo-random bytes deterministically
                    (0..256).map(|i| (i * 17 + 42) as u8).collect()
                }
            };

            let modified_message = apply_modifications(base_message, &payload_modifications);

            // Test all three parsers on edge cases
            let _ = fuzz_parse_error_response(&modified_message);
            let _ = fuzz_parse_notice_response(&modified_message);
            let _ = fuzz_parse_parameter_status(&modified_message);
        }

        PgMessageScenario::CommandComplete { tag } => {
            let message = build_command_complete_message(&tag);
            match expected_command_complete_rows(&tag) {
                Some(expected) => match fuzz_parse_command_complete_tag(&message) {
                    Ok(actual) => assert_eq!(actual, expected),
                    Err(err) => panic!(
                        "expected valid CommandComplete tag {:?}, got {err:?}",
                        String::from_utf8_lossy(&message)
                    ),
                },
                None => assert!(
                    fuzz_parse_command_complete_tag(&message).is_err(),
                    "malformed CommandComplete tag should return Err: {:?}",
                    String::from_utf8_lossy(&message)
                ),
            }
        }
    }
});
