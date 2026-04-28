#![no_main]

//! Structure-aware fuzz target for PostgreSQL ParameterDescription and ParameterStatus messages.
//!
//! This target tests the parsing logic in postgres.rs:
//! - ParameterDescription: parse_parameter_description() lines 4947-4963
//! - ParameterStatus: handle_parameter_status() lines 2560-2566
//!
//! ParameterDescription format (message type 't'):
//! - i16: number of parameters (must be >= 0)
//! - For each parameter: i32 OID (type identifier)
//!
//! ParameterStatus format (message type 'S'):
//! - C-string: parameter name (null-terminated)
//! - C-string: parameter value (null-terminated)
//!
//! Test cases:
//! - Valid parameter descriptions with various OID values
//! - Edge cases: zero parameters, maximum parameters, negative counts
//! - Parameter status with common and edge-case parameter names/values
//! - Encoding attacks: embedded nulls, non-UTF8, oversized inputs
//! - Wire-format corruption: truncated messages, malformed length headers

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// Maximum message size for reasonable fuzzing performance
const MAX_MESSAGE_SIZE: usize = 65536;
/// Maximum number of parameters to avoid excessive memory usage
const MAX_PARAMETER_COUNT: u16 = 1024;

/// Structure-aware generator for PostgreSQL parameter messages
#[derive(Arbitrary, Debug, Clone)]
struct ParameterMessage {
    /// The message type variant
    variant: MessageVariant,
    /// Corruption parameters for robustness testing
    corruption: MessageCorruption,
}

/// Different PostgreSQL parameter message types
#[derive(Arbitrary, Debug, Clone)]
enum MessageVariant {
    /// ParameterDescription message (type 't')
    ParameterDescription(ParameterDescription),
    /// ParameterStatus message (type 'S')
    ParameterStatus(ParameterStatus),
}

/// ParameterDescription message structure
#[derive(Arbitrary, Debug, Clone)]
struct ParameterDescription {
    /// List of parameter OIDs
    parameters: Vec<ParameterOid>,
}

/// Parameter OID variants covering common PostgreSQL types
#[derive(Arbitrary, Debug, Clone)]
enum ParameterOid {
    /// Standard PostgreSQL type OIDs
    Standard(StandardOid),
    /// Custom/extension OIDs
    Custom(u32),
    /// Edge case OIDs for robustness testing
    EdgeCase(EdgeCaseOid),
}

/// Common PostgreSQL type OIDs
#[derive(Arbitrary, Debug, Clone)]
enum StandardOid {
    /// BOOL (16)
    Bool,
    /// BYTEA (17)
    Bytea,
    /// CHAR (18)
    Char,
    /// NAME (19)
    Name,
    /// INT8 (20)
    Int8,
    /// INT2 (21)
    Int2,
    /// INT4 (23)
    Int4,
    /// TEXT (25)
    Text,
    /// OID (26)
    Oid,
    /// JSON (114)
    Json,
    /// JSONB (3802)
    Jsonb,
    /// UUID (2950)
    Uuid,
    /// TIMESTAMP (1114)
    Timestamp,
    /// TIMESTAMPTZ (1184)
    Timestamptz,
    /// NUMERIC (1700)
    Numeric,
}

/// Edge case OIDs for testing parser robustness
#[derive(Arbitrary, Debug, Clone)]
enum EdgeCaseOid {
    /// Zero OID (invalid but might appear)
    Zero,
    /// Maximum u32 value
    MaxValue,
    /// Common edge values
    PowersOfTwo(u8), // 2^n where n is the u8 value
    /// Invalid but plausible OIDs
    InvalidButPlausible(u32),
}

/// ParameterStatus message structure
#[derive(Arbitrary, Debug, Clone)]
struct ParameterStatus {
    /// Parameter name
    name: ParameterName,
    /// Parameter value
    value: ParameterValue,
}

/// Common PostgreSQL runtime parameter names
#[derive(Arbitrary, Debug, Clone)]
enum ParameterName {
    /// Standard runtime parameters
    Standard(StandardParameter),
    /// Custom parameter name
    Custom(String),
    /// Edge case names for robustness testing
    EdgeCase(EdgeCaseString),
}

/// Standard PostgreSQL runtime parameters
#[derive(Arbitrary, Debug, Clone)]
enum StandardParameter {
    /// application_name
    ApplicationName,
    /// client_encoding
    ClientEncoding,
    /// DateStyle
    DateStyle,
    /// default_transaction_isolation
    DefaultTransactionIsolation,
    /// in_hot_standby
    InHotStandby,
    /// integer_datetimes
    IntegerDatetimes,
    /// IntervalStyle
    IntervalStyle,
    /// is_superuser
    IsSuperuser,
    /// server_encoding
    ServerEncoding,
    /// server_version
    ServerVersion,
    /// session_authorization
    SessionAuthorization,
    /// standard_conforming_strings
    StandardConformingStrings,
    /// TimeZone
    TimeZone,
}

/// Parameter value variants
#[derive(Arbitrary, Debug, Clone)]
enum ParameterValue {
    /// Common boolean values
    Boolean(bool),
    /// Numeric values
    Numeric(i64),
    /// String values
    String(String),
    /// Edge case values
    EdgeCase(EdgeCaseString),
    /// PostgreSQL-specific values
    PostgresSpecific(PostgresValue),
}

/// PostgreSQL-specific parameter values
#[derive(Arbitrary, Debug, Clone)]
enum PostgresValue {
    /// Encoding names: UTF8, LATIN1, etc.
    Encoding(String),
    /// Date styles: ISO, MDY, German, etc.
    DateStyle(String),
    /// Time zones
    TimeZone(String),
    /// Isolation levels
    IsolationLevel(String),
    /// Version strings
    VersionString(String),
}

/// Edge case strings for testing parser robustness
#[derive(Arbitrary, Debug, Clone)]
enum EdgeCaseString {
    /// Empty string
    Empty,
    /// Very long string
    VeryLong(String),
    /// String with special characters
    SpecialChars(String),
    /// Binary data disguised as string
    BinaryData(Vec<u8>),
    /// Unicode edge cases
    Unicode(UnicodeEdgeCase),
}

/// Unicode edge case variants
#[derive(Arbitrary, Debug, Clone)]
enum UnicodeEdgeCase {
    /// High codepoints
    HighCodepoints(String),
    /// Mixed scripts
    MixedScripts(String),
    /// Control characters
    ControlChars(Vec<u8>),
    /// Normalization edge cases
    Normalization(String),
}

/// Message corruption parameters
#[derive(Arbitrary, Debug, Clone)]
struct MessageCorruption {
    /// Length field manipulation
    length_corruption: LengthCorruption,
    /// Null terminator handling
    null_handling: NullHandling,
    /// Encoding corruption
    encoding: EncodingCorruption,
}

#[derive(Arbitrary, Debug, Clone)]
enum LengthCorruption {
    /// Correct length
    Correct,
    /// Truncated message (length shorter than data)
    Truncated(u8),
    /// Oversized length (length longer than data)
    Oversized(u8),
    /// Negative length (for i16 fields)
    Negative(i16),
}

#[derive(Arbitrary, Debug, Clone)]
enum NullHandling {
    /// Standard null termination
    Standard,
    /// Missing null terminators
    Missing,
    /// Extra null terminators
    Extra(u8),
    /// Embedded nulls in strings
    Embedded,
}

#[derive(Arbitrary, Debug, Clone)]
enum EncodingCorruption {
    /// Valid UTF-8
    Valid,
    /// Invalid UTF-8 sequences
    InvalidUtf8(Vec<u8>),
    /// Mixed valid/invalid encoding
    Mixed { valid_prefix: String, invalid_suffix: Vec<u8> },
}

impl ParameterMessage {
    /// Generate the raw message bytes for fuzzing
    fn generate_bytes(&self) -> Vec<u8> {
        let base_bytes = match &self.variant {
            MessageVariant::ParameterDescription(pd) => pd.generate_bytes(),
            MessageVariant::ParameterStatus(ps) => ps.generate_bytes(),
        };
        self.corruption.apply_corruption(base_bytes)
    }
}

impl ParameterDescription {
    fn generate_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Parameter count as i16 (big-endian)
        let count = (self.parameters.len() as u16).min(MAX_PARAMETER_COUNT) as i16;
        bytes.extend_from_slice(&count.to_be_bytes());

        // Parameter OIDs as i32 (big-endian)
        for param in &self.parameters {
            let oid = param.to_oid();
            bytes.extend_from_slice(&(oid as i32).to_be_bytes());
        }

        bytes
    }
}

impl ParameterOid {
    fn to_oid(&self) -> u32 {
        match self {
            ParameterOid::Standard(std_oid) => std_oid.to_oid(),
            ParameterOid::Custom(oid) => *oid,
            ParameterOid::EdgeCase(edge) => edge.to_oid(),
        }
    }
}

impl StandardOid {
    fn to_oid(&self) -> u32 {
        match self {
            StandardOid::Bool => 16,
            StandardOid::Bytea => 17,
            StandardOid::Char => 18,
            StandardOid::Name => 19,
            StandardOid::Int8 => 20,
            StandardOid::Int2 => 21,
            StandardOid::Int4 => 23,
            StandardOid::Text => 25,
            StandardOid::Oid => 26,
            StandardOid::Json => 114,
            StandardOid::Jsonb => 3802,
            StandardOid::Uuid => 2950,
            StandardOid::Timestamp => 1114,
            StandardOid::Timestamptz => 1184,
            StandardOid::Numeric => 1700,
        }
    }
}

impl EdgeCaseOid {
    fn to_oid(&self) -> u32 {
        match self {
            EdgeCaseOid::Zero => 0,
            EdgeCaseOid::MaxValue => u32::MAX,
            EdgeCaseOid::PowersOfTwo(n) => 1u32 << (*n as u32 % 32),
            EdgeCaseOid::InvalidButPlausible(oid) => *oid,
        }
    }
}

impl ParameterStatus {
    fn generate_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Parameter name as C-string
        let name_str = self.name.to_string();
        bytes.extend_from_slice(name_str.as_bytes());
        bytes.push(0); // null terminator

        // Parameter value as C-string
        let value_str = self.value.to_string();
        bytes.extend_from_slice(value_str.as_bytes());
        bytes.push(0); // null terminator

        bytes
    }
}

impl ParameterName {
    fn to_string(&self) -> String {
        match self {
            ParameterName::Standard(std_param) => std_param.to_string(),
            ParameterName::Custom(name) => name.clone(),
            ParameterName::EdgeCase(edge) => edge.to_string(),
        }
    }
}

impl StandardParameter {
    fn to_string(&self) -> String {
        match self {
            StandardParameter::ApplicationName => "application_name".to_string(),
            StandardParameter::ClientEncoding => "client_encoding".to_string(),
            StandardParameter::DateStyle => "DateStyle".to_string(),
            StandardParameter::DefaultTransactionIsolation => "default_transaction_isolation".to_string(),
            StandardParameter::InHotStandby => "in_hot_standby".to_string(),
            StandardParameter::IntegerDatetimes => "integer_datetimes".to_string(),
            StandardParameter::IntervalStyle => "IntervalStyle".to_string(),
            StandardParameter::IsSuperuser => "is_superuser".to_string(),
            StandardParameter::ServerEncoding => "server_encoding".to_string(),
            StandardParameter::ServerVersion => "server_version".to_string(),
            StandardParameter::SessionAuthorization => "session_authorization".to_string(),
            StandardParameter::StandardConformingStrings => "standard_conforming_strings".to_string(),
            StandardParameter::TimeZone => "TimeZone".to_string(),
        }
    }
}

impl ParameterValue {
    fn to_string(&self) -> String {
        match self {
            ParameterValue::Boolean(b) => if *b { "on".to_string() } else { "off".to_string() },
            ParameterValue::Numeric(n) => n.to_string(),
            ParameterValue::String(s) => s.clone(),
            ParameterValue::EdgeCase(edge) => edge.to_string(),
            ParameterValue::PostgresSpecific(pg) => pg.to_string(),
        }
    }
}

impl PostgresValue {
    fn to_string(&self) -> String {
        match self {
            PostgresValue::Encoding(e) => e.clone(),
            PostgresValue::DateStyle(ds) => ds.clone(),
            PostgresValue::TimeZone(tz) => tz.clone(),
            PostgresValue::IsolationLevel(iso) => iso.clone(),
            PostgresValue::VersionString(vs) => vs.clone(),
        }
    }
}

impl EdgeCaseString {
    fn to_string(&self) -> String {
        match self {
            EdgeCaseString::Empty => String::new(),
            EdgeCaseString::VeryLong(s) => s.clone(),
            EdgeCaseString::SpecialChars(s) => s.clone(),
            EdgeCaseString::BinaryData(data) => {
                // Convert binary data to string (possibly invalid UTF-8)
                String::from_utf8_lossy(data).to_string()
            }
            EdgeCaseString::Unicode(unicode) => unicode.to_string(),
        }
    }
}

impl UnicodeEdgeCase {
    fn to_string(&self) -> String {
        match self {
            UnicodeEdgeCase::HighCodepoints(s) => s.clone(),
            UnicodeEdgeCase::MixedScripts(s) => s.clone(),
            UnicodeEdgeCase::ControlChars(data) => {
                String::from_utf8_lossy(data).to_string()
            }
            UnicodeEdgeCase::Normalization(s) => s.clone(),
        }
    }
}

impl MessageCorruption {
    fn apply_corruption(&self, mut bytes: Vec<u8>) -> Vec<u8> {
        // Apply length corruption
        bytes = self.length_corruption.apply(bytes);

        // Apply null handling corruption
        bytes = self.null_handling.apply(bytes);

        // Apply encoding corruption
        self.encoding.apply(bytes)
    }
}

impl LengthCorruption {
    fn apply(&self, mut bytes: Vec<u8>) -> Vec<u8> {
        match self {
            LengthCorruption::Correct => bytes,
            LengthCorruption::Truncated(amount) => {
                let truncate_by = (*amount as usize).min(bytes.len());
                bytes.truncate(bytes.len().saturating_sub(truncate_by));
                bytes
            }
            LengthCorruption::Oversized(amount) => {
                // Add extra bytes at the end
                bytes.extend(vec![0; *amount as usize]);
                bytes
            }
            LengthCorruption::Negative(neg_val) => {
                // For ParameterDescription, replace the count field with negative value
                if bytes.len() >= 2 {
                    let neg_bytes = neg_val.to_be_bytes();
                    bytes[0] = neg_bytes[0];
                    bytes[1] = neg_bytes[1];
                }
                bytes
            }
        }
    }
}

impl NullHandling {
    fn apply(&self, mut bytes: Vec<u8>) -> Vec<u8> {
        match self {
            NullHandling::Standard => bytes,
            NullHandling::Missing => {
                // Remove null terminators
                bytes.retain(|&b| b != 0);
                bytes
            }
            NullHandling::Extra(count) => {
                // Add extra null bytes
                bytes.extend(vec![0; *count as usize]);
                bytes
            }
            NullHandling::Embedded => {
                // Insert nulls in the middle
                if !bytes.is_empty() {
                    let pos = bytes.len() / 2;
                    bytes.insert(pos, 0);
                }
                bytes
            }
        }
    }
}

impl EncodingCorruption {
    fn apply(&self, bytes: Vec<u8>) -> Vec<u8> {
        match self {
            EncodingCorruption::Valid => bytes,
            EncodingCorruption::InvalidUtf8(invalid_bytes) => invalid_bytes.clone(),
            EncodingCorruption::Mixed { valid_prefix, invalid_suffix } => {
                let mut result = valid_prefix.as_bytes().to_vec();
                result.extend_from_slice(invalid_suffix);
                result
            }
        }
    }
}

/// Test ParameterDescription parsing
fn test_parameter_description_parsing(data: &[u8]) {
    // Guard against oversized inputs for fuzzing performance
    if data.len() > MAX_MESSAGE_SIZE {
        return;
    }

    // Call the actual parser function from postgres.rs
    #[cfg(feature = "test-internals")]
    {
        // This should never panic - only return errors for invalid data
        let _result = asupersync::database::postgres::fuzz_parse_parameter_description(data);

        // Additional invariants we can check:
        if let Ok(oids) = asupersync::database::postgres::fuzz_parse_parameter_description(data) {
            // If parsing succeeds, the OID vector should be finite
            assert!(oids.len() < MAX_PARAMETER_COUNT as usize,
                "Parameter count exceeds reasonable bounds: {}", oids.len());

            // No OID should be a special sentinel value that might indicate parsing errors
            for &oid in &oids {
                // This is a heuristic - we don't expect these specific values in normal operation
                assert_ne!(oid, u32::MAX, "Suspicious OID value: {}", oid);
            }
        }
    }
}

/// Test ParameterStatus parsing
fn test_parameter_status_parsing(data: &[u8]) {
    // Guard against oversized inputs for fuzzing performance
    if data.len() > MAX_MESSAGE_SIZE {
        return;
    }

    // Call the actual parser function from postgres.rs
    #[cfg(feature = "test-internals")]
    {
        // This should never panic - only return errors for invalid data
        let _result = asupersync::database::postgres::fuzz_parse_parameter_status(data);

        // The function doesn't return parsed values, but we can verify it doesn't crash
        // and handles edge cases gracefully
    }
}

fuzz_target!(|data: &[u8]| {
    // Test with raw input first (regression/crash detection)
    test_parameter_description_parsing(data);
    test_parameter_status_parsing(data);

    // Then test with structure-aware generation if we have enough input data
    if data.len() >= std::mem::size_of::<ParameterMessage>() {
        let mut u = Unstructured::new(data);
        if let Ok(param_msg) = ParameterMessage::arbitrary(&mut u) {
            let generated_bytes = param_msg.generate_bytes();

            match param_msg.variant {
                MessageVariant::ParameterDescription(_) => {
                    test_parameter_description_parsing(&generated_bytes);
                }
                MessageVariant::ParameterStatus(_) => {
                    test_parameter_status_parsing(&generated_bytes);
                }
            }

            // Test cross-message contamination: feed ParameterStatus data to
            // ParameterDescription parser and vice versa
            test_parameter_description_parsing(&generated_bytes);
            test_parameter_status_parsing(&generated_bytes);
        }
    }
});