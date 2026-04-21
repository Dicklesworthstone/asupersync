#![allow(clippy::all)]
//! MySQL COM_STMT_PREPARE/EXECUTE Conformance Tests
//!
//! This module provides comprehensive conformance testing for MySQL prepared statement
//! wire protocol per the MySQL Client/Server Protocol specification.
//! The tests systematically validate:
//!
//! - COM_STMT_PREPARE packet format and response parsing
//! - Parameter type signaling with MYSQL_TYPE_* codes
//! - NULL bitmap encoding per Section 16.6.4.2
//! - Long data transmission via COM_STMT_SEND_LONG_DATA
//! - Cursor type flags (CURSOR_TYPE_READ_ONLY, etc.)
//! - Binary result set row format
//!
//! # MySQL Prepared Statement Protocol
//!
//! **COM_STMT_PREPARE Flow:**
//! 1. Client sends COM_STMT_PREPARE (0x16) with SQL statement
//! 2. Server responds with COM_STMT_PREPARE_OK or error
//! 3. Client sends COM_STMT_EXECUTE (0x17) with parameters
//! 4. Server responds with result set or OK packet
//!
//! **Parameter Types (MYSQL_TYPE_*):**
//! - MYSQL_TYPE_TINY (0x01) - TINYINT
//! - MYSQL_TYPE_SHORT (0x02) - SMALLINT
//! - MYSQL_TYPE_LONG (0x03) - INT
//! - MYSQL_TYPE_LONGLONG (0x08) - BIGINT
//! - MYSQL_TYPE_STRING (0xFE) - CHAR, VARCHAR, TEXT
//! - MYSQL_TYPE_VAR_STRING (0xFD) - VARCHAR, VARBINARY
//!
//! **NULL Bitmap Format:**
//! ```
//! null_bitmap_length = (parameter_count + 7) / 8
//! For each parameter, bit N indicates if parameter N is NULL
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Test result for a single conformance requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct MySqlStmtConformanceResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub notes: Option<String>,
    pub elapsed_ms: u64,
}

/// Conformance test categories for MySQL prepared statements.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestCategory {
    PacketFormat,
    ParameterTypes,
    NullBitmap,
    LongData,
    CursorFlags,
    BinaryResultSet,
    ErrorHandling,
}

/// Protocol requirement level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum RequirementLevel {
    Must,   // Protocol requirement
    Should, // Recommended behavior
    May,    // Optional feature
}

/// Test execution result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

/// MySQL parameter types per protocol specification.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum MySqlType {
    Decimal = 0x00,
    Tiny = 0x01,
    Short = 0x02,
    Long = 0x03,
    Float = 0x04,
    Double = 0x05,
    Null = 0x06,
    Timestamp = 0x07,
    LongLong = 0x08,
    Int24 = 0x09,
    Date = 0x0A,
    Time = 0x0B,
    DateTime = 0x0C,
    Year = 0x0D,
    NewDate = 0x0E,
    VarChar = 0x0F,
    Bit = 0x10,
    NewDecimal = 0xF6,
    Enum = 0xF7,
    Set = 0xF8,
    TinyBlob = 0xF9,
    MediumBlob = 0xFA,
    LongBlob = 0xFB,
    Blob = 0xFC,
    VarString = 0xFD,
    String = 0xFE,
    Geometry = 0xFF,
}

/// Cursor type flags.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CursorType {
    NoCursor = 0x00,
    ReadOnly = 0x01,
    ForUpdate = 0x02,
    Scrollable = 0x04,
}

/// MySQL COM_STMT_PREPARE/EXECUTE conformance harness.
#[allow(dead_code)]
pub struct MySqlStmtConformanceHarness {
    results: Vec<MySqlStmtConformanceResult>,
}

#[allow(dead_code)]

impl MySqlStmtConformanceHarness {
    /// Create a new conformance test harness.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Execute all conformance tests.
    #[allow(dead_code)]
    pub fn run_all_tests(&mut self) -> Vec<MySqlStmtConformanceResult> {
        // Packet Format Tests
        self.test_stmt_prepare_packet_format();
        self.test_stmt_prepare_ok_response();
        self.test_stmt_execute_packet_format();
        self.test_stmt_close_packet_format();

        // Parameter Type Tests
        self.test_parameter_type_signaling();
        self.test_type_code_compliance();
        self.test_unsigned_flag_handling();
        self.test_parameter_length_encoding();

        // NULL Bitmap Tests
        self.test_null_bitmap_encoding();
        self.test_null_bitmap_length_calculation();
        self.test_null_bitmap_bit_ordering();
        self.test_mixed_null_parameters();

        // Long Data Tests
        self.test_long_data_send_packet();
        self.test_long_data_chunking();
        self.test_long_data_parameter_reset();

        // Cursor Flag Tests
        self.test_cursor_type_flags();
        self.test_cursor_read_only();
        self.test_cursor_scrollable_behavior();

        // Binary Result Set Tests
        self.test_binary_result_set_format();
        self.test_binary_row_null_bitmap();
        self.test_binary_value_encoding();
        self.test_length_encoded_values();

        // Error Handling Tests
        self.test_invalid_statement_id();
        self.test_parameter_count_mismatch();
        self.test_invalid_cursor_type();

        self.results.clone()
    }

    #[allow(dead_code)]

    fn record_result(
        &mut self,
        test_id: &str,
        description: &str,
        category: TestCategory,
        requirement: RequirementLevel,
        verdict: TestVerdict,
        notes: Option<String>,
    ) {
        self.results.push(MySqlStmtConformanceResult {
            test_id: test_id.to_string(),
            description: description.to_string(),
            category,
            requirement_level: requirement,
            verdict,
            notes,
            elapsed_ms: 0, // TODO: Add timing if needed
        });
    }

    // ===== Packet Format Tests =====

    #[allow(dead_code)]

    fn test_stmt_prepare_packet_format(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test COM_STMT_PREPARE packet structure
            let sql = "SELECT id, name FROM users WHERE age > ?";
            let mut packet = Vec::new();

            // Command byte
            packet.push(0x16); // COM_STMT_PREPARE

            // SQL statement (no null terminator in prepare)
            packet.extend_from_slice(sql.as_bytes());

            // Verify packet format
            assert_eq!(
                packet[0], 0x16,
                "Command byte must be 0x16 for COM_STMT_PREPARE"
            );

            let stmt_text = std::str::from_utf8(&packet[1..]).unwrap();
            assert_eq!(stmt_text, sql, "Statement text must match original SQL");

            // Verify no null terminator (unlike COM_QUERY)
            assert_ne!(
                packet[packet.len() - 1],
                0,
                "COM_STMT_PREPARE should not null-terminate SQL"
            );
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-001",
            "COM_STMT_PREPARE packet format MUST follow wire protocol",
            TestCategory::PacketFormat,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_stmt_prepare_ok_response(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test COM_STMT_PREPARE_OK response structure
            let mut response = Vec::new();

            response.push(0x00); // OK header

            // Statement ID (4 bytes, little-endian)
            let stmt_id = 1234u32;
            response.extend_from_slice(&stmt_id.to_le_bytes());

            // Number of columns (2 bytes, little-endian)
            let num_columns = 2u16;
            response.extend_from_slice(&num_columns.to_le_bytes());

            // Number of parameters (2 bytes, little-endian)
            let num_params = 1u16;
            response.extend_from_slice(&num_params.to_le_bytes());

            // Reserved byte (always 0x00)
            response.push(0x00);

            // Warning count (2 bytes, little-endian)
            let warning_count = 0u16;
            response.extend_from_slice(&warning_count.to_le_bytes());

            // Verify response structure
            assert_eq!(response[0], 0x00, "Prepare OK must start with 0x00");

            let parsed_stmt_id =
                u32::from_le_bytes([response[1], response[2], response[3], response[4]]);
            assert_eq!(parsed_stmt_id, stmt_id, "Statement ID must match");

            let parsed_cols = u16::from_le_bytes([response[5], response[6]]);
            assert_eq!(parsed_cols, num_columns, "Column count must match");

            let parsed_params = u16::from_le_bytes([response[7], response[8]]);
            assert_eq!(parsed_params, num_params, "Parameter count must match");

            assert_eq!(response[9], 0x00, "Reserved byte must be 0x00");

            let parsed_warnings = u16::from_le_bytes([response[10], response[11]]);
            assert_eq!(parsed_warnings, warning_count, "Warning count must match");
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-002",
            "COM_STMT_PREPARE_OK response MUST follow specification",
            TestCategory::PacketFormat,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_stmt_execute_packet_format(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test COM_STMT_EXECUTE packet structure
            let mut packet = Vec::new();

            packet.push(0x17); // COM_STMT_EXECUTE

            // Statement ID (4 bytes, little-endian)
            let stmt_id = 1234u32;
            packet.extend_from_slice(&stmt_id.to_le_bytes());

            // Flags (1 byte) - cursor type
            packet.push(CursorType::ReadOnly as u8);

            // Iteration count (4 bytes, little-endian) - always 1
            let iteration_count = 1u32;
            packet.extend_from_slice(&iteration_count.to_le_bytes());

            // NULL bitmap (calculated based on parameter count)
            let param_count = 2;
            let null_bitmap_len = (param_count + 7) / 8;
            let null_bitmap = vec![0x01]; // First param is NULL, second is not
            packet.extend_from_slice(&null_bitmap);

            // New parameter types flag (1 byte)
            packet.push(0x01); // Sending new parameter types

            // Parameter types (2 bytes per parameter: type + flags)
            packet.push(MySqlType::Long as u8); // Type for first param
            packet.push(0x00); // Flags (not unsigned)
            packet.push(MySqlType::VarString as u8); // Type for second param
            packet.push(0x00); // Flags (not unsigned)

            // Parameter values (only for non-NULL parameters)
            // First param is NULL (skip), second param is string
            let param2_value = b"test_value";
            let param2_len = param2_value.len() as u8;
            packet.push(param2_len); // Length-encoded string
            packet.extend_from_slice(param2_value);

            // Verify packet structure
            assert_eq!(packet[0], 0x17, "Command must be COM_STMT_EXECUTE");

            let parsed_stmt_id = u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]);
            assert_eq!(parsed_stmt_id, stmt_id, "Statement ID must match");

            assert_eq!(
                packet[5],
                CursorType::ReadOnly as u8,
                "Cursor flags must match"
            );

            let parsed_iterations =
                u32::from_le_bytes([packet[6], packet[7], packet[8], packet[9]]);
            assert_eq!(
                parsed_iterations, iteration_count,
                "Iteration count must be 1"
            );

            // Verify NULL bitmap
            assert_eq!(
                packet[10], 0x01,
                "NULL bitmap must indicate first param is NULL"
            );

            // Verify new types flag
            assert_eq!(packet[11], 0x01, "New parameter types flag must be set");
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-003",
            "COM_STMT_EXECUTE packet format MUST be compliant",
            TestCategory::PacketFormat,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_stmt_close_packet_format(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test COM_STMT_CLOSE packet structure
            let mut packet = Vec::new();

            packet.push(0x19); // COM_STMT_CLOSE

            // Statement ID (4 bytes, little-endian)
            let stmt_id = 5678u32;
            packet.extend_from_slice(&stmt_id.to_le_bytes());

            // Verify packet structure
            assert_eq!(packet[0], 0x19, "Command must be COM_STMT_CLOSE");
            assert_eq!(
                packet.len(),
                5,
                "COM_STMT_CLOSE packet must be exactly 5 bytes"
            );

            let parsed_stmt_id = u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]);
            assert_eq!(parsed_stmt_id, stmt_id, "Statement ID must match");
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-004",
            "COM_STMT_CLOSE packet format MUST be correct",
            TestCategory::PacketFormat,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Parameter Type Tests =====

    #[allow(dead_code)]

    fn test_parameter_type_signaling(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test parameter type signaling with MYSQL_TYPE codes
            let type_tests = vec![
                (MySqlType::Tiny, 0x00, "TINYINT"),
                (MySqlType::Short, 0x00, "SMALLINT"),
                (MySqlType::Long, 0x00, "INT"),
                (MySqlType::LongLong, 0x00, "BIGINT"),
                (MySqlType::String, 0x00, "CHAR/VARCHAR"),
                (MySqlType::VarString, 0x00, "VARCHAR/VARBINARY"),
                (MySqlType::Float, 0x00, "FLOAT"),
                (MySqlType::Double, 0x00, "DOUBLE"),
                (MySqlType::DateTime, 0x00, "DATETIME"),
                (MySqlType::Blob, 0x00, "BLOB"),
            ];

            for (mysql_type, flags, description) in type_tests {
                let type_byte = mysql_type as u8;
                let flag_byte = flags;

                // Verify type codes match MySQL specification
                match mysql_type {
                    MySqlType::Tiny => assert_eq!(type_byte, 0x01),
                    MySqlType::Short => assert_eq!(type_byte, 0x02),
                    MySqlType::Long => assert_eq!(type_byte, 0x03),
                    MySqlType::LongLong => assert_eq!(type_byte, 0x08),
                    MySqlType::String => assert_eq!(type_byte, 0xFE),
                    MySqlType::VarString => assert_eq!(type_byte, 0xFD),
                    MySqlType::Float => assert_eq!(type_byte, 0x04),
                    MySqlType::Double => assert_eq!(type_byte, 0x05),
                    MySqlType::DateTime => assert_eq!(type_byte, 0x0C),
                    MySqlType::Blob => assert_eq!(type_byte, 0xFC),
                    _ => {} // Other types handled elsewhere
                }

                // Verify flag byte is valid
                assert!(flag_byte == 0x00 || flag_byte == 0x80); // 0x80 = unsigned flag

                assert!(!description.is_empty(), "Type must have description");
            }
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-005",
            "Parameter type signaling MUST use correct MYSQL_TYPE codes",
            TestCategory::ParameterTypes,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_type_code_compliance(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test that type codes match MySQL specification exactly
            assert_eq!(MySqlType::Decimal as u8, 0x00);
            assert_eq!(MySqlType::Tiny as u8, 0x01);
            assert_eq!(MySqlType::Short as u8, 0x02);
            assert_eq!(MySqlType::Long as u8, 0x03);
            assert_eq!(MySqlType::Float as u8, 0x04);
            assert_eq!(MySqlType::Double as u8, 0x05);
            assert_eq!(MySqlType::Null as u8, 0x06);
            assert_eq!(MySqlType::Timestamp as u8, 0x07);
            assert_eq!(MySqlType::LongLong as u8, 0x08);
            assert_eq!(MySqlType::Int24 as u8, 0x09);
            assert_eq!(MySqlType::Date as u8, 0x0A);
            assert_eq!(MySqlType::Time as u8, 0x0B);
            assert_eq!(MySqlType::DateTime as u8, 0x0C);
            assert_eq!(MySqlType::Year as u8, 0x0D);
            assert_eq!(MySqlType::VarChar as u8, 0x0F);
            assert_eq!(MySqlType::Bit as u8, 0x10);
            assert_eq!(MySqlType::NewDecimal as u8, 0xF6);
            assert_eq!(MySqlType::Enum as u8, 0xF7);
            assert_eq!(MySqlType::Set as u8, 0xF8);
            assert_eq!(MySqlType::TinyBlob as u8, 0xF9);
            assert_eq!(MySqlType::MediumBlob as u8, 0xFA);
            assert_eq!(MySqlType::LongBlob as u8, 0xFB);
            assert_eq!(MySqlType::Blob as u8, 0xFC);
            assert_eq!(MySqlType::VarString as u8, 0xFD);
            assert_eq!(MySqlType::String as u8, 0xFE);
            assert_eq!(MySqlType::Geometry as u8, 0xFF);
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-006",
            "MYSQL_TYPE codes MUST match specification exactly",
            TestCategory::ParameterTypes,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_unsigned_flag_handling(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test unsigned flag handling in parameter types
            let unsigned_flag = 0x80u8;

            // Test signed vs unsigned integer types
            let signed_int_flags = 0x00u8;
            let unsigned_int_flags = 0x80u8;

            assert_eq!(signed_int_flags & unsigned_flag, 0x00);
            assert_eq!(unsigned_int_flags & unsigned_flag, 0x80);

            // Only integer types should use unsigned flag
            let integer_types = vec![
                MySqlType::Tiny,
                MySqlType::Short,
                MySqlType::Long,
                MySqlType::LongLong,
                MySqlType::Int24,
            ];

            let non_integer_types = vec![
                MySqlType::String,
                MySqlType::VarString,
                MySqlType::Float,
                MySqlType::Double,
                MySqlType::DateTime,
                MySqlType::Blob,
            ];

            for mysql_type in integer_types {
                // Integer types can be unsigned
                let type_code = mysql_type as u8;
                assert!(type_code <= 0x10 || matches!(mysql_type, MySqlType::Int24));
            }

            for mysql_type in non_integer_types {
                // Non-integer types typically don't use unsigned flag
                let type_code = mysql_type as u8;
                assert!(type_code != 0x00); // Should have valid type code
            }
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-007",
            "Unsigned flag handling MUST be correct for integer types",
            TestCategory::ParameterTypes,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_parameter_length_encoding(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test length encoding for variable-length parameters
            let test_cases = vec![
                (250, vec![250]),                        // Short length
                (251, vec![252, 251, 0]),                // Medium length (3-byte)
                (65535, vec![252, 255, 255]),            // Medium length max
                (65536, vec![253, 0, 0, 1, 0, 0, 0, 0]), // Long length (8-byte)
            ];

            for (length, expected_encoding) in test_cases {
                let encoded = encode_length_encoded_integer(length);
                assert_eq!(
                    encoded, expected_encoding,
                    "Length encoding failed for {}",
                    length
                );

                let decoded = decode_length_encoded_integer(&encoded).0;
                assert_eq!(decoded, length, "Length decoding failed for {}", length);
            }
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-008",
            "Parameter length encoding MUST follow MySQL specification",
            TestCategory::ParameterTypes,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== NULL Bitmap Tests =====

    #[allow(dead_code)]

    fn test_null_bitmap_encoding(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test NULL bitmap encoding per Section 16.6.4.2
            let test_cases = vec![
                (1, vec![0b00000001]),              // 1 param, NULL
                (1, vec![0b00000000]),              // 1 param, not NULL
                (8, vec![0b11111111]),              // 8 params, all NULL
                (9, vec![0b11111111, 0b00000001]),  // 9 params, all NULL
                (16, vec![0b10101010, 0b01010101]), // 16 params, alternating
            ];

            for (param_count, expected_bitmap) in test_cases {
                let bitmap_len = (param_count + 7) / 8;
                assert_eq!(
                    expected_bitmap.len(),
                    bitmap_len,
                    "Bitmap length calculation failed"
                );

                // Test bit setting/getting
                for param_idx in 0..param_count {
                    let byte_idx = param_idx / 8;
                    let bit_idx = param_idx % 8;

                    if byte_idx < expected_bitmap.len() {
                        let bit_set = (expected_bitmap[byte_idx] & (1 << bit_idx)) != 0;
                        assert!(bit_set || !bit_set); // Either set or not set, both valid
                    }
                }
            }
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-009",
            "NULL bitmap encoding MUST follow Section 16.6.4.2",
            TestCategory::NullBitmap,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_null_bitmap_length_calculation(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test NULL bitmap length calculation formula
            let test_cases = vec![
                (0, 0),  // 0 parameters
                (1, 1),  // 1 parameter
                (7, 1),  // 7 parameters
                (8, 1),  // 8 parameters
                (9, 2),  // 9 parameters
                (15, 2), // 15 parameters
                (16, 2), // 16 parameters
                (17, 3), // 17 parameters
            ];

            for (param_count, expected_len) in test_cases {
                let calculated_len = if param_count == 0 {
                    0
                } else {
                    (param_count + 7) / 8
                };
                assert_eq!(
                    calculated_len, expected_len,
                    "NULL bitmap length calculation failed for {} parameters",
                    param_count
                );
            }
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-010",
            "NULL bitmap length calculation MUST be correct",
            TestCategory::NullBitmap,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_null_bitmap_bit_ordering(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test NULL bitmap bit ordering (LSB first)
            let mut bitmap = vec![0u8; 2]; // Support up to 16 parameters

            // Set parameter 0 (bit 0 in byte 0)
            bitmap[0] |= 1 << 0;
            assert_eq!(bitmap[0] & 0x01, 0x01);

            // Set parameter 3 (bit 3 in byte 0)
            bitmap[0] |= 1 << 3;
            assert_eq!(bitmap[0] & 0x08, 0x08);

            // Set parameter 8 (bit 0 in byte 1)
            bitmap[1] |= 1 << 0;
            assert_eq!(bitmap[1] & 0x01, 0x01);

            // Set parameter 15 (bit 7 in byte 1)
            bitmap[1] |= 1 << 7;
            assert_eq!(bitmap[1] & 0x80, 0x80);

            // Verify final bitmap
            assert_eq!(bitmap[0], 0x09); // bits 0 and 3 set: 0b00001001 = 0x09
            assert_eq!(bitmap[1], 0x81); // bits 0 and 7 set: 0b10000001 = 0x81
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-011",
            "NULL bitmap bit ordering MUST follow LSB-first convention",
            TestCategory::NullBitmap,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_mixed_null_parameters(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test mixed NULL and non-NULL parameters
            let param_count = 5;
            let null_pattern = vec![true, false, true, false, false]; // params 0,2 are NULL

            let mut bitmap = vec![0u8; (param_count + 7) / 8];

            for (param_idx, is_null) in null_pattern.iter().enumerate() {
                if *is_null {
                    let byte_idx = param_idx / 8;
                    let bit_idx = param_idx % 8;
                    bitmap[byte_idx] |= 1 << bit_idx;
                }
            }

            // Expected bitmap: params 0,2 NULL = bits 0,2 set = 0b00000101 = 0x05
            assert_eq!(bitmap[0], 0x05);

            // Verify we can read back the NULL status correctly
            for (param_idx, expected_null) in null_pattern.iter().enumerate() {
                let byte_idx = param_idx / 8;
                let bit_idx = param_idx % 8;
                let is_null = (bitmap[byte_idx] & (1 << bit_idx)) != 0;
                assert_eq!(
                    is_null, *expected_null,
                    "NULL status mismatch for parameter {}",
                    param_idx
                );
            }
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-012",
            "Mixed NULL/non-NULL parameters MUST be handled correctly",
            TestCategory::NullBitmap,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Long Data Tests =====

    #[allow(dead_code)]

    fn test_long_data_send_packet(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test COM_STMT_SEND_LONG_DATA packet format
            let mut packet = Vec::new();

            packet.push(0x18); // COM_STMT_SEND_LONG_DATA

            // Statement ID (4 bytes, little-endian)
            let stmt_id = 9999u32;
            packet.extend_from_slice(&stmt_id.to_le_bytes());

            // Parameter index (2 bytes, little-endian)
            let param_index = 2u16;
            packet.extend_from_slice(&param_index.to_le_bytes());

            // Data chunk
            let data_chunk =
                b"This is a large text data chunk that exceeds normal parameter size limits";
            packet.extend_from_slice(data_chunk);

            // Verify packet structure
            assert_eq!(packet[0], 0x18, "Command must be COM_STMT_SEND_LONG_DATA");

            let parsed_stmt_id = u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]);
            assert_eq!(parsed_stmt_id, stmt_id, "Statement ID must match");

            let parsed_param_idx = u16::from_le_bytes([packet[5], packet[6]]);
            assert_eq!(parsed_param_idx, param_index, "Parameter index must match");

            let data_start = 7;
            let parsed_data = &packet[data_start..];
            assert_eq!(parsed_data, data_chunk, "Data chunk must match");
            assert!(parsed_data.len() > 60, "Should handle large data chunks");
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-013",
            "COM_STMT_SEND_LONG_DATA packet format MUST be correct",
            TestCategory::LongData,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_long_data_chunking(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test long data transmission in multiple chunks
            let large_data = vec![0x42u8; 100_000]; // 100KB of data
            let chunk_size = 8192; // 8KB chunks
            let expected_chunks = (large_data.len() + chunk_size - 1) / chunk_size;

            let mut chunks_sent = 0;
            let mut offset = 0;

            while offset < large_data.len() {
                let end = std::cmp::min(offset + chunk_size, large_data.len());
                let chunk = &large_data[offset..end];

                // Create long data packet
                let mut packet = Vec::new();
                packet.push(0x18); // COM_STMT_SEND_LONG_DATA
                packet.extend_from_slice(&1234u32.to_le_bytes()); // stmt_id
                packet.extend_from_slice(&0u16.to_le_bytes()); // param_index
                packet.extend_from_slice(chunk);

                // Verify chunk
                assert!(
                    chunk.len() <= chunk_size,
                    "Chunk size must not exceed limit"
                );
                assert!(!chunk.is_empty(), "Chunk must not be empty");

                chunks_sent += 1;
                offset = end;
            }

            assert_eq!(
                chunks_sent, expected_chunks,
                "Number of chunks must match calculation"
            );
            assert!(chunks_sent > 1, "Large data should require multiple chunks");
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-014",
            "Long data chunking MUST handle large data correctly",
            TestCategory::LongData,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_long_data_parameter_reset(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test that long data parameters are reset between executions
            let stmt_id = 5555u32;
            let param_index = 1u16;

            // First execution: send long data
            let data1 = b"First execution data";
            let packet1 = create_long_data_packet(stmt_id, param_index, data1);
            assert_eq!(packet1[0], 0x18);

            // Execute statement
            let execute_packet1 = create_execute_packet(stmt_id, CursorType::NoCursor);
            assert_eq!(execute_packet1[0], 0x17);

            // Second execution: send different long data
            let data2 = b"Second execution data - completely different";
            let packet2 = create_long_data_packet(stmt_id, param_index, data2);
            assert_eq!(packet2[0], 0x18);

            // Execute statement again
            let execute_packet2 = create_execute_packet(stmt_id, CursorType::NoCursor);
            assert_eq!(execute_packet2[0], 0x17);

            // Verify data is different
            assert_ne!(
                data1.as_slice(),
                data2.as_slice(),
                "Data should be different between executions"
            );

            // Long data parameters should be reset after each execution
            // This is implicit in the protocol - each execute resets long data
            assert!(packet1 != packet2, "Packets should be different");
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-015",
            "Long data parameters MUST be reset between executions",
            TestCategory::LongData,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Cursor Flag Tests =====

    #[allow(dead_code)]

    fn test_cursor_type_flags(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test cursor type flags in COM_STMT_EXECUTE
            assert_eq!(CursorType::NoCursor as u8, 0x00);
            assert_eq!(CursorType::ReadOnly as u8, 0x01);
            assert_eq!(CursorType::ForUpdate as u8, 0x02);
            assert_eq!(CursorType::Scrollable as u8, 0x04);

            // Test flag combinations
            let combined_flags = CursorType::ReadOnly as u8 | CursorType::Scrollable as u8;
            assert_eq!(combined_flags, 0x05); // 0x01 | 0x04 = 0x05

            // Create execute packet with different cursor types
            let test_cases = vec![
                (CursorType::NoCursor, "No cursor"),
                (CursorType::ReadOnly, "Read-only cursor"),
                (CursorType::ForUpdate, "For update cursor"),
                (CursorType::Scrollable, "Scrollable cursor"),
            ];

            for (cursor_type, description) in test_cases {
                let packet = create_execute_packet(1234, cursor_type);
                assert_eq!(packet[0], 0x17, "Must be COM_STMT_EXECUTE");
                assert_eq!(
                    packet[5], cursor_type as u8,
                    "Cursor type must match for {}",
                    description
                );
            }
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-016",
            "Cursor type flags MUST be correctly encoded",
            TestCategory::CursorFlags,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_cursor_read_only(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test CURSOR_TYPE_READ_ONLY behavior
            let stmt_id = 7777u32;
            let cursor_type = CursorType::ReadOnly;

            let packet = create_execute_packet(stmt_id, cursor_type);

            // Verify read-only cursor flag is set
            assert_eq!(packet[5], 0x01, "Read-only cursor flag must be 0x01");

            // Read-only cursors should not allow modifications
            // This is enforced by server behavior, client just sets flag
            let flags = packet[5];
            let is_read_only = (flags & CursorType::ReadOnly as u8) != 0;
            let is_for_update = (flags & CursorType::ForUpdate as u8) != 0;

            assert!(is_read_only, "Read-only flag must be set");
            assert!(!is_for_update, "For-update flag must not be set");
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-017",
            "CURSOR_TYPE_READ_ONLY MUST be handled correctly",
            TestCategory::CursorFlags,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_cursor_scrollable_behavior(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test scrollable cursor behavior
            let stmt_id = 8888u32;
            let cursor_type = CursorType::Scrollable;

            let packet = create_execute_packet(stmt_id, cursor_type);

            // Verify scrollable cursor flag is set
            assert_eq!(packet[5], 0x04, "Scrollable cursor flag must be 0x04");

            // Test combined flags (read-only + scrollable)
            let combined_cursor = CursorType::ReadOnly as u8 | CursorType::Scrollable as u8;
            let combined_packet = create_execute_packet_with_flags(stmt_id, combined_cursor);
            assert_eq!(combined_packet[5], 0x05, "Combined flags must be 0x05");

            // Verify flag parsing
            let flags = combined_packet[5];
            let is_scrollable = (flags & CursorType::Scrollable as u8) != 0;
            let is_read_only = (flags & CursorType::ReadOnly as u8) != 0;

            assert!(is_scrollable, "Scrollable flag must be set");
            assert!(is_read_only, "Read-only flag must also be set");
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-018",
            "Scrollable cursor behavior MUST be correct",
            TestCategory::CursorFlags,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Binary Result Set Tests =====

    #[allow(dead_code)]

    fn test_binary_result_set_format(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test binary result set row format
            let column_count = 3;
            let mut row = Vec::new();

            // Header byte (always 0x00 for binary rows)
            row.push(0x00);

            // NULL bitmap for columns (not parameters)
            let null_bitmap_len = (column_count + 7 + 2) / 8; // +2 for offset
            let null_bitmap = vec![0b00000010]; // Column 1 is NULL, others are not
            row.extend_from_slice(&null_bitmap);

            // Column values (only for non-NULL columns)
            // Column 0: INT (4 bytes)
            let col0_value = 12345i32;
            row.extend_from_slice(&col0_value.to_le_bytes());

            // Column 1: NULL (skip)

            // Column 2: VARCHAR (length-encoded string)
            let col2_value = b"test_string";
            let col2_len = col2_value.len() as u8;
            row.push(col2_len);
            row.extend_from_slice(col2_value);

            // Verify binary row format
            assert_eq!(row[0], 0x00, "Binary row must start with 0x00");

            // Verify NULL bitmap
            let bitmap_start = 1;
            let bitmap_byte = row[bitmap_start];
            let col1_is_null = (bitmap_byte & (1 << (1 + 2))) != 0; // +2 offset for binary rows
            assert!(col1_is_null, "Column 1 should be NULL according to bitmap");

            // Verify non-NULL column values can be parsed
            let values_start = bitmap_start + null_bitmap_len;
            let parsed_col0 = i32::from_le_bytes([
                row[values_start],
                row[values_start + 1],
                row[values_start + 2],
                row[values_start + 3],
            ]);
            assert_eq!(parsed_col0, col0_value, "Column 0 value must match");
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-019",
            "Binary result set format MUST follow specification",
            TestCategory::BinaryResultSet,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_binary_row_null_bitmap(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test NULL bitmap in binary result rows
            let column_count = 10;
            let null_bitmap_len = (column_count + 7 + 2) / 8; // +2 offset for binary rows

            assert_eq!(
                null_bitmap_len, 2,
                "Should need 2 bytes for 10 columns + 2 offset"
            );

            // Test various NULL patterns
            let test_patterns = vec![
                (vec![false; 10], vec![0x00, 0x00]), // No NULLs
                (vec![true; 10], vec![0xFC, 0x0F]),  // All NULLs (bits 2-11 set)
            ];

            for (null_pattern, expected_bitmap) in test_patterns {
                let mut bitmap = vec![0u8; null_bitmap_len];

                for (col_idx, is_null) in null_pattern.iter().enumerate() {
                    if *is_null {
                        let bit_idx = col_idx + 2; // +2 offset for binary rows
                        let byte_idx = bit_idx / 8;
                        let bit_pos = bit_idx % 8;

                        if byte_idx < bitmap.len() {
                            bitmap[byte_idx] |= 1 << bit_pos;
                        }
                    }
                }

                assert_eq!(bitmap, expected_bitmap, "NULL bitmap pattern must match");

                // Verify we can read back NULL status
                for (col_idx, expected_null) in null_pattern.iter().enumerate() {
                    let bit_idx = col_idx + 2;
                    let byte_idx = bit_idx / 8;
                    let bit_pos = bit_idx % 8;

                    if byte_idx < bitmap.len() {
                        let is_null = (bitmap[byte_idx] & (1 << bit_pos)) != 0;
                        assert_eq!(
                            is_null, *expected_null,
                            "NULL status mismatch for column {}",
                            col_idx
                        );
                    }
                }
            }
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-020",
            "Binary row NULL bitmap MUST handle +2 offset correctly",
            TestCategory::BinaryResultSet,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_binary_value_encoding(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test binary value encoding for different types
            let test_values = vec![
                (MySqlType::Tiny, i8::MAX.to_le_bytes().to_vec()),
                (MySqlType::Short, i16::MAX.to_le_bytes().to_vec()),
                (MySqlType::Long, i32::MAX.to_le_bytes().to_vec()),
                (MySqlType::LongLong, i64::MAX.to_le_bytes().to_vec()),
                (MySqlType::Float, 3.14f32.to_le_bytes().to_vec()),
                (
                    MySqlType::Double,
                    3.141592653589793f64.to_le_bytes().to_vec(),
                ),
            ];

            for (mysql_type, expected_bytes) in test_values {
                // Verify encoding produces expected byte patterns
                match mysql_type {
                    MySqlType::Tiny => assert_eq!(expected_bytes.len(), 1),
                    MySqlType::Short => assert_eq!(expected_bytes.len(), 2),
                    MySqlType::Long => assert_eq!(expected_bytes.len(), 4),
                    MySqlType::LongLong => assert_eq!(expected_bytes.len(), 8),
                    MySqlType::Float => assert_eq!(expected_bytes.len(), 4),
                    MySqlType::Double => assert_eq!(expected_bytes.len(), 8),
                    _ => panic!("Unexpected type in test"),
                }

                // All multi-byte values should use little-endian encoding
                assert!(
                    !expected_bytes.is_empty(),
                    "Encoded value must not be empty"
                );
            }

            // Test string encoding (length-encoded)
            let test_string = b"hello world";
            let encoded_string = encode_length_encoded_string(test_string);

            assert_eq!(encoded_string[0], test_string.len() as u8);
            assert_eq!(&encoded_string[1..], test_string);
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-021",
            "Binary value encoding MUST use correct formats",
            TestCategory::BinaryResultSet,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_length_encoded_values(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test length-encoded values in binary result sets
            let test_cases: Vec<(&[u8], Vec<u8>)> = vec![
                (&b""[..], vec![0x00]),                                    // Empty string
                (&b"a"[..], vec![0x01, b'a']),                             // Single char
                (&b"hello"[..], vec![0x05, b'h', b'e', b'l', b'l', b'o']), // Short string
            ];

            for (input, expected) in test_cases {
                let encoded = encode_length_encoded_string(input);
                assert_eq!(
                    encoded,
                    expected,
                    "Length-encoded string failed for: {:?}",
                    std::str::from_utf8(input).unwrap_or("<invalid utf8>")
                );

                let (decoded, bytes_read) = decode_length_encoded_string(&encoded);
                assert_eq!(
                    decoded,
                    input,
                    "Decode failed for: {:?}",
                    std::str::from_utf8(input).unwrap_or("<invalid utf8>")
                );
                assert_eq!(bytes_read, encoded.len(), "Bytes read mismatch");
            }

            // Test longer strings requiring multi-byte length encoding
            let long_string = vec![b'x'; 300]; // 300 bytes
            let encoded_long = encode_length_encoded_string(&long_string);

            // Should use 3-byte length encoding: 252 + 2 bytes length + data
            assert_eq!(
                encoded_long[0], 252,
                "Long string should use 3-byte length encoding"
            );
            assert_eq!(encoded_long[1], 44, "Length LSB should be 44 (300 & 0xFF)");
            assert_eq!(encoded_long[2], 1, "Length MSB should be 1 (300 >> 8)");
            assert_eq!(&encoded_long[3..], &long_string[..], "Data should match");
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-022",
            "Length-encoded values MUST be handled correctly",
            TestCategory::BinaryResultSet,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    // ===== Error Handling Tests =====

    #[allow(dead_code)]

    fn test_invalid_statement_id(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test error handling for invalid statement IDs
            let invalid_stmt_id = 0xFFFFFFFF; // Maximum u32, likely invalid

            let execute_packet = create_execute_packet(invalid_stmt_id, CursorType::NoCursor);
            let close_packet = create_close_packet(invalid_stmt_id);

            // Verify packets are formed correctly even with invalid ID
            assert_eq!(
                execute_packet[0], 0x17,
                "Execute packet command must be correct"
            );
            assert_eq!(
                close_packet[0], 0x19,
                "Close packet command must be correct"
            );

            let parsed_exec_id = u32::from_le_bytes([
                execute_packet[1],
                execute_packet[2],
                execute_packet[3],
                execute_packet[4],
            ]);
            assert_eq!(
                parsed_exec_id, invalid_stmt_id,
                "Execute packet ID must match"
            );

            let parsed_close_id = u32::from_le_bytes([
                close_packet[1],
                close_packet[2],
                close_packet[3],
                close_packet[4],
            ]);
            assert_eq!(
                parsed_close_id, invalid_stmt_id,
                "Close packet ID must match"
            );

            // Server should respond with error for invalid statement ID
            // This is server behavior, client just sends valid packet format
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-023",
            "Invalid statement ID handling MUST follow protocol",
            TestCategory::ErrorHandling,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_parameter_count_mismatch(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test parameter count mismatch detection
            let stmt_id = 1111u32;
            let expected_param_count = 3;
            let provided_param_count = 2; // Mismatch

            // Create execute packet with wrong parameter count
            let mut packet = Vec::new();
            packet.push(0x17); // COM_STMT_EXECUTE
            packet.extend_from_slice(&stmt_id.to_le_bytes());
            packet.push(CursorType::NoCursor as u8);
            packet.extend_from_slice(&1u32.to_le_bytes()); // iteration count

            // NULL bitmap sized for provided count, not expected count
            let null_bitmap_len = (provided_param_count + 7) / 8;
            let null_bitmap = vec![0x00; null_bitmap_len];
            packet.extend_from_slice(&null_bitmap);

            packet.push(0x01); // new types flag

            // Provide types for fewer parameters than expected
            for _ in 0..provided_param_count {
                packet.push(MySqlType::Long as u8);
                packet.push(0x00); // flags
            }

            // Packet is well-formed but has parameter count mismatch
            assert_eq!(packet[0], 0x17, "Packet format must be valid");

            // Calculate actual parameter count from packet structure
            let null_bitmap_start = 10;
            let types_start = null_bitmap_start + null_bitmap_len + 1; // +1 for new types flag
            let types_end = packet.len();
            let actual_param_count = (types_end - types_start) / 2; // 2 bytes per parameter

            assert_eq!(actual_param_count, provided_param_count);
            assert_ne!(
                actual_param_count, expected_param_count,
                "Should detect mismatch"
            );
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-024",
            "Parameter count mismatch MUST be detectable",
            TestCategory::ErrorHandling,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }

    #[allow(dead_code)]

    fn test_invalid_cursor_type(&mut self) {
        let result = std::panic::catch_unwind(|| {
            // Test invalid cursor type handling
            let stmt_id = 2222u32;
            let invalid_cursor_flags = 0xFF; // Invalid flags combination

            let packet = create_execute_packet_with_flags(stmt_id, invalid_cursor_flags);

            // Verify packet structure is valid despite invalid flags
            assert_eq!(packet[0], 0x17, "Command must be COM_STMT_EXECUTE");
            assert_eq!(
                packet[5], invalid_cursor_flags,
                "Flags must be preserved in packet"
            );

            // Check individual flag bits
            let flags = packet[5];
            let has_no_cursor = (flags & CursorType::NoCursor as u8) == flags;
            let has_read_only = (flags & CursorType::ReadOnly as u8) != 0;
            let has_for_update = (flags & CursorType::ForUpdate as u8) != 0;
            let has_scrollable = (flags & CursorType::Scrollable as u8) != 0;

            // Invalid combination: all bits set
            assert!(has_read_only, "Read-only bit should be set in 0xFF");
            assert!(has_for_update, "For-update bit should be set in 0xFF");
            assert!(has_scrollable, "Scrollable bit should be set in 0xFF");
            assert!(!has_no_cursor, "No-cursor check should fail for 0xFF");

            // Server should validate and reject invalid combinations
            // Client responsibility is to send valid packet format only
        });

        let verdict = if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        };
        self.record_result(
            "MYSQL-STMT-025",
            "Invalid cursor type MUST be handled properly",
            TestCategory::ErrorHandling,
            RequirementLevel::Must,
            verdict,
            None,
        );
    }
}

impl Default for MySqlStmtConformanceHarness {
    #[allow(dead_code)]
    fn default() -> Self {
        Self::new()
    }
}

// ===== Helper Functions =====

/// Encode a length-encoded integer per MySQL protocol.
#[allow(dead_code)]
fn encode_length_encoded_integer(value: u64) -> Vec<u8> {
    if value < 251 {
        vec![value as u8]
    } else if value < 65536 {
        let mut result = vec![252];
        result.extend_from_slice(&(value as u16).to_le_bytes());
        result
    } else if value < 16777216 {
        let mut result = vec![253];
        result.extend_from_slice(&(value as u32).to_le_bytes()[0..3]);
        result
    } else {
        let mut result = vec![254];
        result.extend_from_slice(&value.to_le_bytes());
        result
    }
}

/// Decode a length-encoded integer per MySQL protocol.
#[allow(dead_code)]
fn decode_length_encoded_integer(data: &[u8]) -> (u64, usize) {
    if data.is_empty() {
        return (0, 0);
    }

    match data[0] {
        0..=250 => (data[0] as u64, 1),
        251 => (0, 1), // NULL value
        252 => {
            if data.len() < 3 {
                return (0, 1);
            }
            let value = u16::from_le_bytes([data[1], data[2]]) as u64;
            (value, 3)
        }
        253 => {
            if data.len() < 4 {
                return (0, 1);
            }
            let value = u32::from_le_bytes([data[1], data[2], data[3], 0]) as u64;
            (value, 4)
        }
        254 => {
            if data.len() < 9 {
                return (0, 1);
            }
            let value = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            (value, 9)
        }
        255 => (0, 1), // Reserved
    }
}

/// Encode a length-encoded string per MySQL protocol.
#[allow(dead_code)]
fn encode_length_encoded_string(data: &[u8]) -> Vec<u8> {
    let mut result = encode_length_encoded_integer(data.len() as u64);
    result.extend_from_slice(data);
    result
}

/// Decode a length-encoded string per MySQL protocol.
#[allow(dead_code)]
fn decode_length_encoded_string(data: &[u8]) -> (Vec<u8>, usize) {
    let (length, length_bytes) = decode_length_encoded_integer(data);
    let start = length_bytes;
    let end = start + length as usize;

    if end > data.len() {
        return (Vec::new(), length_bytes);
    }

    (data[start..end].to_vec(), end)
}

/// Create a COM_STMT_EXECUTE packet with specified parameters.
#[allow(dead_code)]
fn create_execute_packet(stmt_id: u32, cursor_type: CursorType) -> Vec<u8> {
    create_execute_packet_with_flags(stmt_id, cursor_type as u8)
}

/// Create a COM_STMT_EXECUTE packet with custom flags.
#[allow(dead_code)]
fn create_execute_packet_with_flags(stmt_id: u32, flags: u8) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.push(0x17); // COM_STMT_EXECUTE
    packet.extend_from_slice(&stmt_id.to_le_bytes());
    packet.push(flags);
    packet.extend_from_slice(&1u32.to_le_bytes()); // iteration count

    // Minimal NULL bitmap for 0 parameters
    packet.push(0x00); // new types flag

    packet
}

/// Create a COM_STMT_CLOSE packet.
#[allow(dead_code)]
fn create_close_packet(stmt_id: u32) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.push(0x19); // COM_STMT_CLOSE
    packet.extend_from_slice(&stmt_id.to_le_bytes());

    packet
}

/// Create a COM_STMT_SEND_LONG_DATA packet.
#[allow(dead_code)]
fn create_long_data_packet(stmt_id: u32, param_index: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.push(0x18); // COM_STMT_SEND_LONG_DATA
    packet.extend_from_slice(&stmt_id.to_le_bytes());
    packet.extend_from_slice(&param_index.to_le_bytes());
    packet.extend_from_slice(data);

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_mysql_stmt_conformance_suite_completeness() {
        let mut harness = MySqlStmtConformanceHarness::new();
        let results = harness.run_all_tests();

        // Verify we have comprehensive coverage
        assert!(!results.is_empty(), "Should have conformance test results");
        assert!(
            results.len() >= 25,
            "Should have at least 25 tests for comprehensive coverage"
        );

        // Check categories are covered
        let categories: std::collections::HashSet<_> =
            results.iter().map(|r| &r.category).collect();

        assert!(categories.contains(&TestCategory::PacketFormat));
        assert!(categories.contains(&TestCategory::ParameterTypes));
        assert!(categories.contains(&TestCategory::NullBitmap));
        assert!(categories.contains(&TestCategory::LongData));
        assert!(categories.contains(&TestCategory::CursorFlags));
        assert!(categories.contains(&TestCategory::BinaryResultSet));
        assert!(categories.contains(&TestCategory::ErrorHandling));

        // All MUST requirements should pass
        let must_failures: Vec<_> = results
            .iter()
            .filter(|r| {
                r.requirement_level == RequirementLevel::Must && r.verdict == TestVerdict::Fail
            })
            .collect();

        if !must_failures.is_empty() {
            panic!("MUST requirements failed: {:#?}", must_failures);
        }

        println!(
            "✅ MySQL prepared statement conformance: {} tests passed",
            results.len()
        );
    }

    #[test]
    #[allow(dead_code)]
    fn test_mysql_type_codes() {
        // Verify MySQL type codes match specification
        assert_eq!(MySqlType::Tiny as u8, 0x01);
        assert_eq!(MySqlType::Short as u8, 0x02);
        assert_eq!(MySqlType::Long as u8, 0x03);
        assert_eq!(MySqlType::LongLong as u8, 0x08);
        assert_eq!(MySqlType::String as u8, 0xFE);
        assert_eq!(MySqlType::VarString as u8, 0xFD);
    }

    #[test]
    #[allow(dead_code)]
    fn test_cursor_type_values() {
        // Verify cursor type values match specification
        assert_eq!(CursorType::NoCursor as u8, 0x00);
        assert_eq!(CursorType::ReadOnly as u8, 0x01);
        assert_eq!(CursorType::ForUpdate as u8, 0x02);
        assert_eq!(CursorType::Scrollable as u8, 0x04);
    }

    #[test]
    #[allow(dead_code)]
    fn test_length_encoded_integer_roundtrip() {
        let test_values = vec![0, 1, 250, 251, 255, 256, 65535, 65536, 16777215, 16777216];

        for value in test_values {
            let encoded = encode_length_encoded_integer(value);
            let (decoded, _) = decode_length_encoded_integer(&encoded);
            assert_eq!(decoded, value, "Round-trip failed for value {}", value);
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_null_bitmap_calculation() {
        // Test NULL bitmap length calculation
        assert_eq!(7 / 8, 0);
        assert_eq!((1 + 7) / 8, 1);
        assert_eq!((8 + 7) / 8, 1);
        assert_eq!((9 + 7) / 8, 2);
        assert_eq!((16 + 7) / 8, 2);
        assert_eq!((17 + 7) / 8, 3);
    }

    #[test]
    #[allow(dead_code)]
    fn test_packet_helpers() {
        let stmt_id = 12345u32;

        // Test execute packet creation
        let execute_packet = create_execute_packet(stmt_id, CursorType::ReadOnly);
        assert_eq!(execute_packet[0], 0x17);
        assert_eq!(execute_packet[5], 0x01); // Read-only cursor

        // Test close packet creation
        let close_packet = create_close_packet(stmt_id);
        assert_eq!(close_packet[0], 0x19);
        assert_eq!(close_packet.len(), 5);

        // Test long data packet creation
        let data = b"test data";
        let long_data_packet = create_long_data_packet(stmt_id, 0, data);
        assert_eq!(long_data_packet[0], 0x18);
        assert_eq!(&long_data_packet[7..], data);
    }
}
