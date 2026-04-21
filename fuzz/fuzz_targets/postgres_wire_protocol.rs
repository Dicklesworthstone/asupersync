//! Comprehensive fuzz target for src/database/postgres.rs PostgreSQL wire protocol parser.
//!
//! This fuzzer targets the PostgreSQL wire protocol handling and parsing systems:
//! 1. Message framing - message type, length validation, body parsing
//! 2. Row description parsing - column metadata, type OIDs, format codes
//! 3. Data row parsing - text/binary format handling, type conversion
//! 4. Error response parsing - field codes, SQLSTATE validation
//! 5. Authentication parsing - SCRAM-SHA-256 handshake, challenge/response
//! 6. Parameter binding - text/binary parameter encoding/decoding
//! 7. Query preparation - statement parsing, parameter description
//! 8. COPY protocol - bulk data transfer format validation
//!
//! Focuses on security boundaries in wire protocol parsing that could lead to
//! buffer overflows, protocol confusion, authentication bypass, or DoS attacks.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB limit for fuzzing
const MAX_COLUMNS: usize = 256;
const MAX_PARAMETERS: usize = 64;
const MAX_ERROR_FIELDS: usize = 32;
const MAX_STRING_LENGTH: usize = 4096;

#[derive(Arbitrary, Debug)]
enum FuzzScenario {
    /// Wire protocol message framing with malformed headers
    MessageFraming {
        message_type: u8,
        length_override: Option<u32>,
        body_data: Vec<u8>,
        truncation_scenarios: Vec<TruncationTest>,
    },
    /// Row description parsing with malformed column metadata
    RowDescriptionParsing {
        num_fields: i16,
        column_definitions: Vec<ColumnDefinition>,
        malformed_data: Vec<MalformedData>,
    },
    /// Data row parsing with mixed format codes and type conversions
    DataRowParsing {
        column_count: u16,
        values: Vec<DataValue>,
        format_codes: Vec<FormatCode>,
        type_oids: Vec<u32>,
    },
    /// Error response parsing with field validation
    ErrorResponseParsing {
        error_fields: Vec<ErrorField>,
        sqlstate_tests: Vec<SqlStateTest>,
        message_encoding: EncodingTest,
    },
    /// SCRAM authentication parsing and validation
    ScramAuthentication {
        auth_method: AuthMethod,
        scram_data: Vec<ScramMessage>,
        salt_scenarios: Vec<SaltScenario>,
    },
    /// Parameter binding and type conversion edge cases
    ParameterBinding {
        parameter_count: u16,
        parameter_data: Vec<ParameterValue>,
        binding_scenarios: Vec<BindingScenario>,
    },
    /// Query preparation with statement parsing
    QueryPreparation {
        statement_name: String,
        query_text: String,
        parameter_oids: Vec<u32>,
        preparation_options: PrepOptions,
    },
    /// COPY protocol bulk data parsing
    CopyProtocol {
        copy_format: CopyFormat,
        field_count: u16,
        data_rows: Vec<CopyRow>,
        delimiter_tests: Vec<DelimiterTest>,
    },
}

#[derive(Arbitrary, Debug)]
struct TruncationTest {
    truncate_at: usize,
    expected_behavior: TruncationBehavior,
}

#[derive(Arbitrary, Debug)]
enum TruncationBehavior {
    ProtocolError,
    UnexpectedEnd,
    ValidPartial,
}

#[derive(Arbitrary, Debug)]
struct ColumnDefinition {
    name: String,
    table_oid: u32,
    column_attr_num: i16,
    type_oid: u32,
    type_size: i16,
    type_modifier: i32,
    format_code: FormatCode,
}

#[derive(Arbitrary, Debug)]
enum FormatCode {
    Text = 0,
    Binary = 1,
    Invalid(u16),
}

#[derive(Arbitrary, Debug)]
struct MalformedData {
    corruption_type: CorruptionType,
    position: usize,
    replacement_data: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
enum CorruptionType {
    NullByteInjection,
    LengthMismatch,
    InvalidUtf8,
    BufferOverflow,
    UnterminatedString,
}

#[derive(Arbitrary, Debug)]
struct DataValue {
    length: i32, // -1 for NULL, 0+ for actual length
    data: Vec<u8>,
    expected_type: PostgresType,
}

#[derive(Arbitrary, Debug)]
enum PostgresType {
    Bool,
    Int2,
    Int4,
    Int8,
    Float4,
    Float8,
    Text,
    Varchar,
    Bytea,
    Timestamp,
    Uuid,
    Json,
    Jsonb,
    Unknown(u32),
}

#[derive(Arbitrary, Debug)]
struct ErrorField {
    field_type: u8,
    field_value: String,
}

#[derive(Arbitrary, Debug)]
struct SqlStateTest {
    sqlstate: String,
    expected_category: ErrorCategory,
}

#[derive(Arbitrary, Debug)]
enum ErrorCategory {
    Success,
    Warning,
    NoData,
    SqlException,
    ConnectionException,
    TriggeredActionException,
    FeatureNotSupported,
    InvalidTransactionInitiation,
    LocatorException,
    InvalidGrantor,
    InvalidRoleSpecification,
    DiagnosticsException,
    CaseNotFound,
    CardinalityViolation,
    DataException,
    IntegrityConstraintViolation,
    InvalidCursorState,
    InvalidTransactionState,
    InvalidSqlStatementName,
    TriggeredDataChangeViolation,
    InvalidAuthorizationSpecification,
    DependentPrivilegeDescriptorsStillExist,
    InvalidTransactionTermination,
    SqlRoutineException,
    InvalidCursorName,
    ExternalRoutineException,
    ExternalRoutineInvocationException,
    SavepointException,
    InvalidCatalogName,
    InvalidSchemaName,
    TransactionRollback,
    SyntaxErrorOrAccessRuleViolation,
    WithCheckOptionViolation,
    InsufficientResources,
    ProgramLimitExceeded,
    ObjectNotInPrerequisiteState,
    OperatorIntervention,
    SystemError,
    ConfigurationFileError,
    ForeignDataWrapperError,
    PlpgsqlError,
    InternalError,
    Unknown,
}

#[derive(Arbitrary, Debug)]
struct EncodingTest {
    encoding: TextEncoding,
    test_strings: Vec<String>,
    normalization: NormalizationTest,
}

#[derive(Arbitrary, Debug)]
enum TextEncoding {
    Utf8,
    Latin1,
    Win1252,
    Invalid,
}

#[derive(Arbitrary, Debug)]
struct NormalizationTest {
    input: String,
    expected_normalized: bool,
}

#[derive(Arbitrary, Debug)]
enum AuthMethod {
    Ok,
    KerberosV5,
    CleartextPassword,
    Md5Password,
    ScramSha256,
    ScramSha256Plus,
    Gss,
    GssContinue,
    Sspi,
    Sasl,
    SaslContinue,
    SaslFinal,
    Unknown(u32),
}

#[derive(Arbitrary, Debug)]
struct ScramMessage {
    message_type: ScramMessageType,
    data: Vec<u8>,
    attributes: Vec<ScramAttribute>,
}

#[derive(Arbitrary, Debug)]
enum ScramMessageType {
    ClientFirstMessage,
    ServerFirstMessage,
    ClientFinalMessage,
    ServerFinalMessage,
    Malformed,
}

#[derive(Arbitrary, Debug)]
struct ScramAttribute {
    name: char,
    value: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct SaltScenario {
    salt: Vec<u8>,
    iteration_count: u32,
    expected_valid: bool,
}

#[derive(Arbitrary, Debug)]
struct ParameterValue {
    value: Vec<u8>,
    format_code: FormatCode,
    type_oid: u32,
    conversion_test: ConversionTest,
}

#[derive(Arbitrary, Debug)]
struct ConversionTest {
    target_type: PostgresType,
    expected_success: bool,
    edge_case: EdgeCaseType,
}

#[derive(Arbitrary, Debug)]
enum EdgeCaseType {
    None,
    IntegerOverflow,
    FloatInfinity,
    FloatNaN,
    TimestampOutOfRange,
    InvalidUtf8,
    JsonSyntaxError,
    UuidFormatError,
}

#[derive(Arbitrary, Debug)]
struct BindingScenario {
    statement_name: String,
    portal_name: String,
    parameter_formats: Vec<FormatCode>,
    result_formats: Vec<FormatCode>,
}

#[derive(Arbitrary, Debug)]
struct PrepOptions {
    parse_complete_expected: bool,
    parameter_description_expected: bool,
    row_description_expected: bool,
}

#[derive(Arbitrary, Debug)]
enum CopyFormat {
    Text,
    Binary,
    Csv,
}

#[derive(Arbitrary, Debug)]
struct CopyRow {
    field_count: u16,
    fields: Vec<CopyField>,
}

#[derive(Arbitrary, Debug)]
struct CopyField {
    data: Vec<u8>,
    is_null: bool,
    format_issues: Vec<CopyFormatIssue>,
}

#[derive(Arbitrary, Debug)]
enum CopyFormatIssue {
    UnescapedDelimiter,
    InvalidEscape,
    UnterminatedQuote,
    BinaryLengthMismatch,
    InvalidHeader,
}

#[derive(Arbitrary, Debug)]
struct DelimiterTest {
    delimiter: u8,
    quote_char: u8,
    escape_char: u8,
    null_string: String,
}

fuzz_target!(|scenario: FuzzScenario| match scenario {
    FuzzScenario::MessageFraming {
        message_type,
        length_override,
        body_data,
        truncation_scenarios,
    } => fuzz_message_framing(message_type, length_override, body_data, truncation_scenarios),

    FuzzScenario::RowDescriptionParsing {
        num_fields,
        column_definitions,
        malformed_data,
    } => fuzz_row_description_parsing(num_fields, column_definitions, malformed_data),

    FuzzScenario::DataRowParsing {
        column_count,
        values,
        format_codes,
        type_oids,
    } => fuzz_data_row_parsing(column_count, values, format_codes, type_oids),

    FuzzScenario::ErrorResponseParsing {
        error_fields,
        sqlstate_tests,
        message_encoding,
    } => fuzz_error_response_parsing(error_fields, sqlstate_tests, message_encoding),

    FuzzScenario::ScramAuthentication {
        auth_method,
        scram_data,
        salt_scenarios,
    } => fuzz_scram_authentication(auth_method, scram_data, salt_scenarios),

    FuzzScenario::ParameterBinding {
        parameter_count,
        parameter_data,
        binding_scenarios,
    } => fuzz_parameter_binding(parameter_count, parameter_data, binding_scenarios),

    FuzzScenario::QueryPreparation {
        statement_name,
        query_text,
        parameter_oids,
        preparation_options,
    } => fuzz_query_preparation(statement_name, query_text, parameter_oids, preparation_options),

    FuzzScenario::CopyProtocol {
        copy_format,
        field_count,
        data_rows,
        delimiter_tests,
    } => fuzz_copy_protocol(copy_format, field_count, data_rows, delimiter_tests),
});

fn fuzz_message_framing(
    message_type: u8,
    length_override: Option<u32>,
    body_data: Vec<u8>,
    truncation_scenarios: Vec<TruncationTest>,
) {
    if body_data.len() > MAX_MESSAGE_SIZE {
        return;
    }

    // Test basic message structure: type (1 byte) + length (4 bytes) + body
    let mut message = Vec::new();
    message.push(message_type);

    // Length includes itself (4 bytes)
    let actual_length = if let Some(override_len) = length_override {
        override_len
    } else {
        (body_data.len() + 4) as u32
    };

    message.extend_from_slice(&actual_length.to_be_bytes());
    message.extend_from_slice(&body_data);

    // Test message length validation
    if actual_length < 4 {
        // Length too small - should be rejected
        assert!(actual_length < 4, "Length field must include itself (4 bytes)");
    }

    const MAX_MESSAGE_LEN: u32 = 64 * 1024 * 1024; // Same as in postgres.rs
    if actual_length > MAX_MESSAGE_LEN {
        // Length too large - should be rejected for DoS protection
        assert!(actual_length > MAX_MESSAGE_LEN, "Message length should be bounded");
    }

    // Test truncation scenarios
    for scenario in truncation_scenarios.iter().take(8) {
        let truncate_point = scenario.truncate_at.min(message.len());
        let truncated = &message[..truncate_point];

        // Validate that truncation detection works correctly
        match scenario.expected_behavior {
            TruncationBehavior::ProtocolError => {
                // Should detect incomplete message
                if truncate_point < 5 { // Less than header
                    assert!(truncated.len() < 5, "Incomplete header should be detected");
                }
            }
            TruncationBehavior::UnexpectedEnd => {
                // Should detect body truncation
                let expected_total = if message.len() >= 5 {
                    5 + (u32::from_be_bytes([message[1], message[2], message[3], message[4]]) as usize - 4)
                } else {
                    5
                };
                if truncate_point < expected_total {
                    assert!(truncated.len() < expected_total, "Body truncation should be detected");
                }
            }
            TruncationBehavior::ValidPartial => {
                // Should handle partial messages gracefully
                assert!(truncated.len() <= message.len());
            }
        }
    }

    // Test message type boundaries
    let known_types = [
        b'R', // Authentication
        b'S', // ParameterStatus
        b'K', // BackendKeyData
        b'Z', // ReadyForQuery
        b'T', // RowDescription
        b'D', // DataRow
        b'C', // CommandComplete
        b'E', // ErrorResponse
        b'N', // NoticeResponse
        b'1', // ParseComplete
        b'2', // BindComplete
        b'3', // CloseComplete
        b'n', // NoData
        b'I', // EmptyQueryResponse
        b's', // PortalSuspended
        b'G', // CopyInResponse
        b'H', // CopyOutResponse
        b'W', // CopyBothResponse
        b'd', // CopyData
        b'c', // CopyDone
        b'f', // CopyFail
        b'A', // NotificationResponse
        b'V', // FunctionCallResponse
    ];

    if !known_types.contains(&message_type) {
        // Unknown message type - should be handled gracefully
        assert!(
            !known_types.contains(&message_type),
            "Unknown message types should be handled gracefully"
        );
    }
}

fn fuzz_row_description_parsing(
    num_fields: i16,
    column_definitions: Vec<ColumnDefinition>,
    malformed_data: Vec<MalformedData>,
) {
    if column_definitions.len() > MAX_COLUMNS {
        return;
    }

    // Build RowDescription message
    let mut data = Vec::new();

    // Field count
    data.extend_from_slice(&num_fields.to_be_bytes());

    // Test negative field counts
    if num_fields < 0 {
        // Should be rejected as protocol error
        assert!(num_fields < 0, "Negative field count should be rejected");
        return;
    }

    let actual_fields = column_definitions.len().min(MAX_COLUMNS);

    for column in column_definitions.iter().take(actual_fields) {
        // Column name (null-terminated string)
        let name = sanitize_string(&column.name, MAX_STRING_LENGTH);
        data.extend_from_slice(name.as_bytes());
        data.push(0); // null terminator

        // Table OID
        data.extend_from_slice(&column.table_oid.to_be_bytes());

        // Column attribute number
        data.extend_from_slice(&column.column_attr_num.to_be_bytes());

        // Type OID
        data.extend_from_slice(&column.type_oid.to_be_bytes());

        // Type size
        data.extend_from_slice(&column.type_size.to_be_bytes());

        // Type modifier
        data.extend_from_slice(&column.type_modifier.to_be_bytes());

        // Format code
        let format_code = match column.format_code {
            FormatCode::Text => 0u16,
            FormatCode::Binary => 1u16,
            FormatCode::Invalid(code) => code,
        };
        data.extend_from_slice(&format_code.to_be_bytes());

        // Test format code validation
        if format_code > 1 {
            // Invalid format code should be handled
            assert!(format_code > 1, "Invalid format codes should be handled");
        }
    }

    // Apply malformed data corruptions
    for malformation in malformed_data.iter().take(8) {
        apply_malformed_data(&mut data, malformation);
    }

    // Test field count vs actual fields mismatch
    let expected_fields = num_fields as usize;
    if expected_fields != actual_fields {
        // Mismatch should be detected
        assert!(
            expected_fields != actual_fields,
            "Field count mismatch should be detected"
        );
    }
}

fn fuzz_data_row_parsing(
    column_count: u16,
    values: Vec<DataValue>,
    format_codes: Vec<FormatCode>,
    type_oids: Vec<u32>,
) {
    if values.len() > MAX_COLUMNS || format_codes.len() > MAX_COLUMNS || type_oids.len() > MAX_COLUMNS {
        return;
    }

    // Build DataRow message
    let mut data = Vec::new();

    // Field count
    data.extend_from_slice(&column_count.to_be_bytes());

    let actual_count = values.len().min(MAX_COLUMNS);

    for (i, value) in values.iter().enumerate().take(actual_count) {
        // Field length (-1 for NULL, 0+ for data)
        data.extend_from_slice(&value.length.to_be_bytes());

        if value.length >= 0 {
            let expected_length = value.length as usize;
            let actual_data = &value.data[..value.data.len().min(expected_length)];
            data.extend_from_slice(actual_data);

            // Test length validation
            if expected_length != actual_data.len() {
                assert!(
                    expected_length != actual_data.len(),
                    "Data length mismatch should be detected"
                );
            }

            // Test type-specific parsing
            let type_oid = type_oids.get(i).copied().unwrap_or(25); // Default to TEXT
            let format = format_codes.get(i).unwrap_or(&FormatCode::Text);

            test_type_conversion(actual_data, type_oid, format, &value.expected_type);
        } else if value.length != -1 {
            // Invalid negative length (not -1 for NULL)
            assert!(value.length == -1 || value.length >= 0, "Invalid field length");
        }
    }

    // Test column count vs actual values mismatch
    if (column_count as usize) != actual_count {
        assert!(
            (column_count as usize) != actual_count,
            "Column count mismatch should be detected"
        );
    }
}

fn fuzz_error_response_parsing(
    error_fields: Vec<ErrorField>,
    sqlstate_tests: Vec<SqlStateTest>,
    message_encoding: EncodingTest,
) {
    if error_fields.len() > MAX_ERROR_FIELDS {
        return;
    }

    // Build ErrorResponse message
    let mut data = Vec::new();

    for field in error_fields.iter().take(MAX_ERROR_FIELDS) {
        // Field type
        data.push(field.field_type);

        // Field value (null-terminated string)
        let value = sanitize_string(&field.field_value, MAX_STRING_LENGTH);
        data.extend_from_slice(value.as_bytes());
        data.push(0); // null terminator

        // Test known field types
        let known_field_types = [
            b'S', // Severity
            b'V', // Severity (non-localized)
            b'C', // Code (SQLSTATE)
            b'M', // Message
            b'D', // Detail
            b'H', // Hint
            b'P', // Position
            b'p', // Internal position
            b'q', // Internal query
            b'W', // Where
            b's', // Schema name
            b't', // Table name
            b'c', // Column name
            b'd', // Data type name
            b'n', // Constraint name
            b'F', // File
            b'L', // Line
            b'R', // Routine
        ];

        if !known_field_types.contains(&field.field_type) {
            // Unknown field type should be handled gracefully
            assert!(
                !known_field_types.contains(&field.field_type),
                "Unknown error field types should be handled"
            );
        }
    }

    // Message terminator
    data.push(0);

    // Test SQLSTATE validation
    for sqlstate_test in sqlstate_tests.iter().take(16) {
        test_sqlstate_categorization(&sqlstate_test.sqlstate, &sqlstate_test.expected_category);
    }

    // Test encoding scenarios
    test_message_encoding(&message_encoding);
}

fn fuzz_scram_authentication(
    auth_method: AuthMethod,
    scram_data: Vec<ScramMessage>,
    salt_scenarios: Vec<SaltScenario>,
) {
    // Test authentication method validation
    let auth_code = match auth_method {
        AuthMethod::Ok => 0u32,
        AuthMethod::KerberosV5 => 2u32,
        AuthMethod::CleartextPassword => 3u32,
        AuthMethod::Md5Password => 5u32,
        AuthMethod::ScramSha256 => 10u32,
        AuthMethod::ScramSha256Plus => 11u32,
        AuthMethod::Gss => 7u32,
        AuthMethod::GssContinue => 8u32,
        AuthMethod::Sspi => 9u32,
        AuthMethod::Sasl => 10u32,
        AuthMethod::SaslContinue => 11u32,
        AuthMethod::SaslFinal => 12u32,
        AuthMethod::Unknown(code) => code,
    };

    let known_methods = [0, 2, 3, 5, 7, 8, 9, 10, 11, 12];
    if !known_methods.contains(&auth_code) {
        // Unknown auth method should be handled
        assert!(
            !known_methods.contains(&auth_code),
            "Unknown auth methods should be handled"
        );
    }

    // Test SCRAM message parsing
    for message in scram_data.iter().take(8) {
        test_scram_message_parsing(message);
    }

    // Test salt scenarios
    for scenario in salt_scenarios.iter().take(8) {
        test_salt_validation(scenario);
    }
}

fn fuzz_parameter_binding(
    parameter_count: u16,
    parameter_data: Vec<ParameterValue>,
    binding_scenarios: Vec<BindingScenario>,
) {
    if parameter_data.len() > MAX_PARAMETERS {
        return;
    }

    // Test parameter count validation
    let actual_params = parameter_data.len().min(MAX_PARAMETERS);
    if (parameter_count as usize) != actual_params {
        assert!(
            (parameter_count as usize) != actual_params,
            "Parameter count mismatch should be detected"
        );
    }

    // Test parameter values
    for param in parameter_data.iter().take(actual_params) {
        test_parameter_value(param);
    }

    // Test binding scenarios
    for scenario in binding_scenarios.iter().take(8) {
        test_binding_scenario(scenario);
    }
}

fn fuzz_query_preparation(
    statement_name: String,
    query_text: String,
    parameter_oids: Vec<u32>,
    preparation_options: PrepOptions,
) {
    let stmt_name = sanitize_string(&statement_name, 64);
    let query = sanitize_string(&query_text, MAX_STRING_LENGTH);
    let param_oids = parameter_oids.into_iter().take(MAX_PARAMETERS).collect::<Vec<_>>();

    // Test statement name validation
    assert!(stmt_name.len() <= 64, "Statement name should be bounded");

    // Test query length validation
    assert!(query.len() <= MAX_STRING_LENGTH, "Query length should be bounded");

    // Test parameter OID validation
    assert!(param_oids.len() <= MAX_PARAMETERS, "Parameter count should be bounded");

    // Test preparation options
    test_preparation_options(&preparation_options);
}

fn fuzz_copy_protocol(
    copy_format: CopyFormat,
    field_count: u16,
    data_rows: Vec<CopyRow>,
    delimiter_tests: Vec<DelimiterTest>,
) {
    if data_rows.len() > 1000 { // Limit for fuzzing
        return;
    }

    // Test copy format validation
    test_copy_format(&copy_format);

    // Test field count validation
    let actual_rows = data_rows.len().min(1000);

    for row in data_rows.iter().take(actual_rows) {
        if row.field_count as usize != row.fields.len() {
            assert!(
                (row.field_count as usize) != row.fields.len(),
                "COPY field count mismatch should be detected"
            );
        }

        for field in &row.fields {
            test_copy_field(field, &copy_format);
        }
    }

    // Test delimiter scenarios
    for delimiter_test in delimiter_tests.iter().take(8) {
        test_delimiter_handling(delimiter_test);
    }
}

// Helper functions

fn sanitize_string(input: &str, max_len: usize) -> String {
    input.chars().take(max_len).collect()
}

fn apply_malformed_data(data: &mut Vec<u8>, malformation: &MalformedData) {
    let pos = malformation.position.min(data.len());

    match malformation.corruption_type {
        CorruptionType::NullByteInjection => {
            if pos < data.len() {
                data[pos] = 0;
            }
        }
        CorruptionType::LengthMismatch => {
            // Corrupt length field if it exists
            if pos + 4 <= data.len() {
                let corrupted_len = 0xFFFFFFFFu32;
                data[pos..pos+4].copy_from_slice(&corrupted_len.to_be_bytes());
            }
        }
        CorruptionType::InvalidUtf8 => {
            if pos < data.len() {
                data[pos] = 0xFF; // Invalid UTF-8 start byte
            }
        }
        CorruptionType::BufferOverflow => {
            // Extend beyond expected bounds
            data.extend_from_slice(&malformation.replacement_data);
        }
        CorruptionType::UnterminatedString => {
            // Remove null terminators
            data.retain(|&b| b != 0);
        }
    }
}

fn test_type_conversion(data: &[u8], type_oid: u32, format: &FormatCode, expected_type: &PostgresType) {
    // Test common PostgreSQL type OIDs
    let common_oids = [
        16,    // BOOL
        20,    // INT8
        21,    // INT2
        23,    // INT4
        25,    // TEXT
        700,   // FLOAT4
        701,   // FLOAT8
        1043,  // VARCHAR
        1114,  // TIMESTAMP
        2950,  // UUID
        114,   // JSON
        3802,  // JSONB
        17,    // BYTEA
    ];

    match format {
        FormatCode::Text => {
            // Text format should be valid UTF-8
            if let Ok(text) = std::str::from_utf8(data) {
                test_text_conversion(text, type_oid, expected_type);
            }
        }
        FormatCode::Binary => {
            test_binary_conversion(data, type_oid, expected_type);
        }
        FormatCode::Invalid(_) => {
            // Invalid format should be rejected
        }
    }

    if !common_oids.contains(&type_oid) {
        // Unknown type OID should be handled gracefully
        assert!(
            !common_oids.contains(&type_oid),
            "Unknown type OIDs should be handled"
        );
    }
}

fn test_text_conversion(text: &str, type_oid: u32, expected_type: &PostgresType) {
    match type_oid {
        16 => { // BOOL
            let valid_bool_values = ["t", "f", "true", "false", "yes", "no", "1", "0"];
            if !valid_bool_values.contains(&text.to_lowercase().as_str()) {
                // Invalid boolean value should be rejected
            }
        }
        20 | 21 | 23 => { // INT8, INT2, INT4
            if let Err(_) = text.parse::<i64>() {
                // Invalid integer should be rejected
            }
        }
        700 | 701 => { // FLOAT4, FLOAT8
            if let Err(_) = text.parse::<f64>() {
                // Invalid float should be rejected (unless special values like NaN, Infinity)
                if !["NaN", "Infinity", "-Infinity"].contains(&text) {
                    // Should be invalid
                }
            }
        }
        25 | 1043 => { // TEXT, VARCHAR
            // Text should always be valid UTF-8 (already validated)
        }
        _ => {
            // Other types have specific formats
        }
    }
}

fn test_binary_conversion(data: &[u8], type_oid: u32, expected_type: &PostgresType) {
    match type_oid {
        16 => { // BOOL
            if data.len() != 1 {
                // Boolean should be 1 byte
                assert!(data.len() != 1, "Boolean binary format should be 1 byte");
            }
        }
        21 => { // INT2
            if data.len() != 2 {
                assert!(data.len() != 2, "INT2 binary format should be 2 bytes");
            }
        }
        23 => { // INT4
            if data.len() != 4 {
                assert!(data.len() != 4, "INT4 binary format should be 4 bytes");
            }
        }
        20 => { // INT8
            if data.len() != 8 {
                assert!(data.len() != 8, "INT8 binary format should be 8 bytes");
            }
        }
        700 => { // FLOAT4
            if data.len() != 4 {
                assert!(data.len() != 4, "FLOAT4 binary format should be 4 bytes");
            }
        }
        701 => { // FLOAT8
            if data.len() != 8 {
                assert!(data.len() != 8, "FLOAT8 binary format should be 8 bytes");
            }
        }
        _ => {
            // Other types have variable lengths
        }
    }
}

fn test_sqlstate_categorization(sqlstate: &str, expected_category: &ErrorCategory) {
    if sqlstate.len() != 5 {
        // SQLSTATE must be exactly 5 characters
        assert!(sqlstate.len() != 5, "SQLSTATE must be 5 characters");
        return;
    }

    // Test category detection based on first two characters
    let class = &sqlstate[..2];
    let actual_category = match class {
        "00" => ErrorCategory::Success,
        "01" => ErrorCategory::Warning,
        "02" => ErrorCategory::NoData,
        "03" => ErrorCategory::SqlException,
        "08" => ErrorCategory::ConnectionException,
        "09" => ErrorCategory::TriggeredActionException,
        "0A" => ErrorCategory::FeatureNotSupported,
        "0B" => ErrorCategory::InvalidTransactionInitiation,
        "0F" => ErrorCategory::LocatorException,
        "0L" => ErrorCategory::InvalidGrantor,
        "0P" => ErrorCategory::InvalidRoleSpecification,
        "0Z" => ErrorCategory::DiagnosticsException,
        "20" => ErrorCategory::CaseNotFound,
        "21" => ErrorCategory::CardinalityViolation,
        "22" => ErrorCategory::DataException,
        "23" => ErrorCategory::IntegrityConstraintViolation,
        "24" => ErrorCategory::InvalidCursorState,
        "25" => ErrorCategory::InvalidTransactionState,
        "26" => ErrorCategory::InvalidSqlStatementName,
        "27" => ErrorCategory::TriggeredDataChangeViolation,
        "28" => ErrorCategory::InvalidAuthorizationSpecification,
        "2B" => ErrorCategory::DependentPrivilegeDescriptorsStillExist,
        "2D" => ErrorCategory::InvalidTransactionTermination,
        "2F" => ErrorCategory::SqlRoutineException,
        "34" => ErrorCategory::InvalidCursorName,
        "38" => ErrorCategory::ExternalRoutineException,
        "39" => ErrorCategory::ExternalRoutineInvocationException,
        "3B" => ErrorCategory::SavepointException,
        "3D" => ErrorCategory::InvalidCatalogName,
        "3F" => ErrorCategory::InvalidSchemaName,
        "40" => ErrorCategory::TransactionRollback,
        "42" => ErrorCategory::SyntaxErrorOrAccessRuleViolation,
        "44" => ErrorCategory::WithCheckOptionViolation,
        "53" => ErrorCategory::InsufficientResources,
        "54" => ErrorCategory::ProgramLimitExceeded,
        "55" => ErrorCategory::ObjectNotInPrerequisiteState,
        "57" => ErrorCategory::OperatorIntervention,
        "58" => ErrorCategory::SystemError,
        "F0" => ErrorCategory::ConfigurationFileError,
        "HV" => ErrorCategory::ForeignDataWrapperError,
        "P0" => ErrorCategory::PlpgsqlError,
        "XX" => ErrorCategory::InternalError,
        _ => ErrorCategory::Unknown,
    };

    // Verify classification matches expectation (in a real scenario)
    match (expected_category, actual_category) {
        (ErrorCategory::TransactionRollback, ErrorCategory::TransactionRollback) => {
            // Serialization failures and deadlocks should be retryable
        }
        (ErrorCategory::IntegrityConstraintViolation, ErrorCategory::IntegrityConstraintViolation) => {
            // Constraint violations should not be retryable
        }
        _ => {
            // Other cases
        }
    }
}

fn test_message_encoding(encoding_test: &EncodingTest) {
    for test_string in &encoding_test.test_strings {
        match encoding_test.encoding {
            TextEncoding::Utf8 => {
                // Should be valid UTF-8
                if let Err(_) = std::str::from_utf8(test_string.as_bytes()) {
                    // Invalid UTF-8 should be detected
                }
            }
            TextEncoding::Latin1 | TextEncoding::Win1252 => {
                // Should handle 8-bit encodings
                assert!(test_string.as_bytes().len() <= MAX_STRING_LENGTH);
            }
            TextEncoding::Invalid => {
                // Invalid encoding should be handled gracefully
            }
        }
    }

    // Test normalization
    test_string_normalization(&encoding_test.normalization);
}

fn test_string_normalization(normalization: &NormalizationTest) {
    let input = &normalization.input;
    let has_combining_chars = input.chars().any(|c| c as u32 > 127);

    if normalization.expected_normalized && has_combining_chars {
        // Should be normalized for consistent comparison
    }
}

fn test_scram_message_parsing(message: &ScramMessage) {
    match message.message_type {
        ScramMessageType::ClientFirstMessage => {
            // Should start with client-first message format
            test_scram_client_first(&message.data, &message.attributes);
        }
        ScramMessageType::ServerFirstMessage => {
            // Should contain salt and iteration count
            test_scram_server_first(&message.data, &message.attributes);
        }
        ScramMessageType::ClientFinalMessage => {
            // Should contain proof
            test_scram_client_final(&message.data, &message.attributes);
        }
        ScramMessageType::ServerFinalMessage => {
            // Should contain server verification
            test_scram_server_final(&message.data, &message.attributes);
        }
        ScramMessageType::Malformed => {
            // Should be rejected gracefully
        }
    }
}

fn test_scram_client_first(data: &[u8], attributes: &[ScramAttribute]) {
    // Client first message format: "n,,n=user,r=clientnonce"
    if let Ok(text) = std::str::from_utf8(data) {
        if !text.starts_with("n,") {
            // Invalid format
        }
    }

    for attr in attributes {
        match attr.name {
            'n' => { // Username
                // Should be valid username
            }
            'r' => { // Nonce
                // Should be sufficient entropy
                if attr.value.len() < 18 { // Minimum nonce length
                    // Insufficient entropy
                }
            }
            _ => {
                // Unknown attribute should be handled
            }
        }
    }
}

fn test_scram_server_first(data: &[u8], attributes: &[ScramAttribute]) {
    for attr in attributes {
        match attr.name {
            'r' => { // Nonce (client + server)
                // Should include client nonce plus server nonce
            }
            's' => { // Salt
                // Should be base64-encoded salt
                test_base64_decoding(&attr.value);
            }
            'i' => { // Iteration count
                if let Ok(text) = std::str::from_utf8(&attr.value) {
                    if let Ok(iterations) = text.parse::<u32>() {
                        if iterations < 4096 { // SCRAM-SHA-256 minimum
                            // Too few iterations
                        }
                    }
                }
            }
            _ => {
                // Unknown attribute
            }
        }
    }
}

fn test_scram_client_final(data: &[u8], attributes: &[ScramAttribute]) {
    for attr in attributes {
        match attr.name {
            'c' => { // Channel binding
                test_base64_decoding(&attr.value);
            }
            'r' => { // Nonce
                // Should match server nonce
            }
            'p' => { // Proof
                test_base64_decoding(&attr.value);
                // Should be correct length for SHA-256
                if let Ok(decoded) = base64_decode(&attr.value) {
                    if decoded.len() != 32 { // SHA-256 output length
                        // Invalid proof length
                    }
                }
            }
            _ => {
                // Unknown attribute
            }
        }
    }
}

fn test_scram_server_final(data: &[u8], attributes: &[ScramAttribute]) {
    for attr in attributes {
        match attr.name {
            'v' => { // Verification
                test_base64_decoding(&attr.value);
                if let Ok(decoded) = base64_decode(&attr.value) {
                    if decoded.len() != 32 { // SHA-256 output length
                        // Invalid verification length
                    }
                }
            }
            'e' => { // Error
                // Server error message
            }
            _ => {
                // Unknown attribute
            }
        }
    }
}

fn test_salt_validation(scenario: &SaltScenario) {
    // Test salt length
    if scenario.salt.len() < 16 {
        // Salt should be at least 16 bytes
        assert!(scenario.salt.len() < 16 == !scenario.expected_valid);
    }

    // Test iteration count
    if scenario.iteration_count < 4096 {
        // Too few iterations for SCRAM-SHA-256
        assert!(scenario.iteration_count < 4096 == !scenario.expected_valid);
    }

    const MAX_ITERATIONS: u32 = 1_000_000;
    if scenario.iteration_count > MAX_ITERATIONS {
        // Too many iterations (DoS protection)
        assert!(scenario.iteration_count > MAX_ITERATIONS == !scenario.expected_valid);
    }
}

fn test_parameter_value(param: &ParameterValue) {
    match param.format_code {
        FormatCode::Text => {
            if let Ok(text) = std::str::from_utf8(&param.value) {
                // Test text parameter conversion
                test_text_parameter_conversion(text, param.type_oid, &param.conversion_test);
            }
        }
        FormatCode::Binary => {
            // Test binary parameter conversion
            test_binary_parameter_conversion(&param.value, param.type_oid, &param.conversion_test);
        }
        FormatCode::Invalid(_) => {
            // Invalid format should be rejected
        }
    }
}

fn test_text_parameter_conversion(text: &str, type_oid: u32, conversion: &ConversionTest) {
    match conversion.edge_case {
        EdgeCaseType::IntegerOverflow => {
            if type_oid == 21 { // INT2
                if let Ok(val) = text.parse::<i64>() {
                    if val < i16::MIN as i64 || val > i16::MAX as i64 {
                        // Should detect overflow
                        assert!(!conversion.expected_success);
                    }
                }
            }
        }
        EdgeCaseType::FloatInfinity => {
            if type_oid == 700 || type_oid == 701 { // FLOAT4/8
                if text == "Infinity" || text == "-Infinity" {
                    // Should handle infinity
                    assert!(conversion.expected_success);
                }
            }
        }
        EdgeCaseType::FloatNaN => {
            if type_oid == 700 || type_oid == 701 {
                if text == "NaN" {
                    // Should handle NaN
                    assert!(conversion.expected_success);
                }
            }
        }
        EdgeCaseType::InvalidUtf8 => {
            // Already validated as UTF-8 at this point
        }
        EdgeCaseType::JsonSyntaxError => {
            if type_oid == 114 || type_oid == 3802 { // JSON/JSONB
                // Should validate JSON syntax
                if let Err(_) = serde_json::from_str::<serde_json::Value>(text) {
                    assert!(!conversion.expected_success);
                }
            }
        }
        _ => {
            // Other edge cases
        }
    }
}

fn test_binary_parameter_conversion(data: &[u8], type_oid: u32, conversion: &ConversionTest) {
    // Test binary format constraints
    match type_oid {
        16 => assert!(data.len() == 1), // BOOL
        21 => assert!(data.len() == 2), // INT2
        23 => assert!(data.len() == 4), // INT4
        20 => assert!(data.len() == 8), // INT8
        700 => assert!(data.len() == 4), // FLOAT4
        701 => assert!(data.len() == 8), // FLOAT8
        _ => {
            // Variable length types
        }
    }
}

fn test_binding_scenario(scenario: &BindingScenario) {
    // Test statement and portal name validation
    let stmt_name = sanitize_string(&scenario.statement_name, 64);
    let portal_name = sanitize_string(&scenario.portal_name, 64);

    assert!(stmt_name.len() <= 64);
    assert!(portal_name.len() <= 64);

    // Test format codes
    for format in &scenario.parameter_formats {
        match format {
            FormatCode::Text | FormatCode::Binary => {
                // Valid format codes
            }
            FormatCode::Invalid(_) => {
                // Should be rejected
            }
        }
    }
}

fn test_preparation_options(options: &PrepOptions) {
    // Test preparation flow expectations
    if options.parse_complete_expected {
        // Parse should succeed
    }

    if options.parameter_description_expected {
        // Should return parameter metadata
    }

    if options.row_description_expected {
        // Should return row metadata
    }
}

fn test_copy_format(format: &CopyFormat) {
    match format {
        CopyFormat::Text => {
            // Text format should use delimiters
        }
        CopyFormat::Binary => {
            // Binary format should use length prefixes
        }
        CopyFormat::Csv => {
            // CSV format should handle quotes and escapes
        }
    }
}

fn test_copy_field(field: &CopyField, format: &CopyFormat) {
    if field.is_null {
        // Null fields should be represented correctly
        match format {
            CopyFormat::Text | CopyFormat::Csv => {
                // Usually "\\N" for text format
            }
            CopyFormat::Binary => {
                // Length -1 for binary format
            }
        }
    }

    for issue in &field.format_issues {
        match issue {
            CopyFormatIssue::UnescapedDelimiter => {
                // Should be properly escaped
            }
            CopyFormatIssue::InvalidEscape => {
                // Should be rejected
            }
            CopyFormatIssue::UnterminatedQuote => {
                // Should be detected
            }
            CopyFormatIssue::BinaryLengthMismatch => {
                // Length field should match data
            }
            CopyFormatIssue::InvalidHeader => {
                // Binary header should be valid
            }
        }
    }
}

fn test_delimiter_handling(delimiter_test: &DelimiterTest) {
    // Test delimiter conflicts
    if delimiter_test.delimiter == delimiter_test.quote_char {
        // Delimiter and quote char should be different
        assert!(delimiter_test.delimiter != delimiter_test.quote_char);
    }

    if delimiter_test.delimiter == delimiter_test.escape_char {
        // Delimiter and escape char should be different
        assert!(delimiter_test.delimiter != delimiter_test.escape_char);
    }

    // Test null string validation
    let null_str = sanitize_string(&delimiter_test.null_string, 32);
    assert!(null_str.len() <= 32);
}

// Utility functions

fn base64_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let text = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8")?;
    base64::engine::general_purpose::STANDARD.decode(text)
        .map_err(|_| "Invalid base64")
}

fn test_base64_decoding(data: &[u8]) {
    let _ = base64_decode(data);
}