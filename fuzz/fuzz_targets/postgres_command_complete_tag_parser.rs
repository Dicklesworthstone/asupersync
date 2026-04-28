#![no_main]

//! Structure-aware fuzz target for PostgreSQL CommandComplete tag parser.
//!
//! This target specifically tests the parsing logic in postgres.rs lines 3494-3504
//! that extracts affected row counts from CommandComplete message tags.
//!
//! Target parsing logic:
//! 1. UTF-8 decode of tag data
//! 2. Null terminator trimming
//! 3. Space splitting and last-part extraction
//! 4. u64 parsing of row count
//!
//! Test cases:
//! - Standard tags: "INSERT 0 5", "UPDATE 10", "DELETE 3"
//! - Edge cases: empty strings, malformed formats, integer overflow
//! - Unicode/encoding attacks: non-UTF8, embedded nulls, whitespace variations
//! - PostgreSQL command variants: COPY, MERGE, TRUNCATE, custom commands

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// Maximum tag length for reasonable fuzzing performance
const MAX_TAG_LENGTH: usize = 1024;

/// Structure-aware generator for PostgreSQL CommandComplete tags
#[derive(Arbitrary, Debug, Clone)]
struct CommandCompleteTag {
    /// The tag variant to generate
    variant: TagVariant,
    /// Encoding and format corruption parameters
    corruption: TagCorruption,
}

/// Different PostgreSQL command tag patterns
#[derive(Arbitrary, Debug, Clone)]
enum TagVariant {
    /// Standard INSERT: "INSERT oid count"
    Insert { oid: u32, count: u64 },
    /// UPDATE command: "UPDATE count"
    Update { count: u64 },
    /// DELETE command: "DELETE count"
    Delete { count: u64 },
    /// SELECT command: "SELECT count"
    Select { count: u64 },
    /// COPY command: "COPY count"
    Copy { count: u64 },
    /// Custom command with arbitrary name
    Custom { command: String, count: u64 },
    /// Edge case: empty tag
    Empty,
    /// Malformed tags for parser robustness testing
    Malformed(MalformedTag),
}

/// Malformed tag variants for edge case testing
#[derive(Arbitrary, Debug, Clone)]
enum MalformedTag {
    /// No spaces: "UPDATE10"
    NoSpaces(String),
    /// Multiple spaces: "UPDATE   10"
    ExcessiveSpaces { command: String, count: String },
    /// Non-numeric count: "UPDATE abc"
    NonNumericCount { command: String, suffix: String },
    /// Negative numbers: "UPDATE -5"
    NegativeCount { command: String, count: i64 },
    /// Extremely large numbers: "UPDATE 99999999999999999999"
    OversizedCount { command: String, digits: String },
    /// Only numbers: "12345"
    NumberOnly(String),
    /// Special characters: "UP∀ATE 10"
    UnicodeCommand { command: String, count: u64 },
}

/// Parameters for tag encoding and format corruption
#[derive(Arbitrary, Debug, Clone)]
struct TagCorruption {
    /// Null terminator handling
    null_handling: NullHandling,
    /// Whitespace variations
    whitespace: WhitespaceVariant,
    /// Encoding corruption
    encoding: EncodingCorruption,
}

#[derive(Arbitrary, Debug, Clone)]
enum NullHandling {
    /// Standard null termination
    Standard,
    /// No null terminator
    Missing,
    /// Multiple null terminators
    Multiple(u8),
    /// Embedded nulls: "UPDATE\010"
    Embedded,
    /// Only nulls
    OnlyNulls,
}

#[derive(Arbitrary, Debug, Clone)]
enum WhitespaceVariant {
    Standard,
    Tabs,
    Newlines,
    Mixed,
    Leading,
    Trailing,
    /// Unicode whitespace characters
    Unicode,
}

#[derive(Arbitrary, Debug, Clone)]
enum EncodingCorruption {
    /// Valid UTF-8
    Valid,
    /// Invalid UTF-8 sequences
    InvalidUtf8(Vec<u8>),
    /// Mixed valid/invalid bytes
    MixedEncoding { prefix: String, suffix: Vec<u8> },
}

impl CommandCompleteTag {
    /// Generate the raw tag bytes for fuzzing
    fn generate_bytes(&self) -> Vec<u8> {
        let base_tag = self.generate_base_tag();
        self.corruption.apply_corruption(base_tag)
    }

    /// Generate the base tag string without corruption
    fn generate_base_tag(&self) -> String {
        match &self.variant {
            TagVariant::Insert { oid, count } => format!("INSERT {} {}", oid, count),
            TagVariant::Update { count } => format!("UPDATE {}", count),
            TagVariant::Delete { count } => format!("DELETE {}", count),
            TagVariant::Select { count } => format!("SELECT {}", count),
            TagVariant::Copy { count } => format!("COPY {}", count),
            TagVariant::Custom { command, count } => format!("{} {}", command, count),
            TagVariant::Empty => String::new(),
            TagVariant::Malformed(malformed) => malformed.generate_string(),
        }
    }
}

impl MalformedTag {
    fn generate_string(&self) -> String {
        match self {
            MalformedTag::NoSpaces(s) => s.clone(),
            MalformedTag::ExcessiveSpaces { command, count } => {
                format!("{}   {}", command, count)
            }
            MalformedTag::NonNumericCount { command, suffix } => {
                format!("{} {}", command, suffix)
            }
            MalformedTag::NegativeCount { command, count } => {
                format!("{} {}", command, count)
            }
            MalformedTag::OversizedCount { command, digits } => {
                format!("{} {}", command, digits)
            }
            MalformedTag::NumberOnly(num) => num.clone(),
            MalformedTag::UnicodeCommand { command, count } => {
                format!("{} {}", command, count)
            }
        }
    }
}

impl TagCorruption {
    fn apply_corruption(&self, mut base: String) -> Vec<u8> {
        // Apply whitespace variations
        base = self.whitespace.apply_whitespace(base);

        // Handle encoding corruption first
        let mut bytes = match &self.encoding {
            EncodingCorruption::Valid => base.into_bytes(),
            EncodingCorruption::InvalidUtf8(invalid_bytes) => invalid_bytes.clone(),
            EncodingCorruption::MixedEncoding { prefix, suffix } => {
                let mut result = prefix.as_bytes().to_vec();
                result.extend_from_slice(suffix);
                result
            }
        };

        // Apply null terminator handling
        match &self.null_handling {
            NullHandling::Standard => {
                bytes.push(0);
            }
            NullHandling::Missing => {
                // No null terminator
            }
            NullHandling::Multiple(count) => {
                for _ in 0..*count {
                    bytes.push(0);
                }
            }
            NullHandling::Embedded => {
                // Insert null in the middle
                if !bytes.is_empty() {
                    let pos = bytes.len() / 2;
                    bytes.insert(pos, 0);
                }
                bytes.push(0);
            }
            NullHandling::OnlyNulls => {
                bytes = vec![0; bytes.len().max(1)];
            }
        }

        bytes
    }
}

impl WhitespaceVariant {
    fn apply_whitespace(&self, s: String) -> String {
        match self {
            WhitespaceVariant::Standard => s,
            WhitespaceVariant::Tabs => s.replace(' ', "\t"),
            WhitespaceVariant::Newlines => s.replace(' ', "\n"),
            WhitespaceVariant::Mixed => s.replace(' ', " \t\n "),
            WhitespaceVariant::Leading => format!("  {}", s),
            WhitespaceVariant::Trailing => format!("{}  ", s),
            WhitespaceVariant::Unicode => s.replace(' ', "\u{2000}"), // En quad
        }
    }
}

/// Test the CommandComplete tag parsing logic directly
fn test_command_complete_tag_parsing(data: &[u8]) {
    // Guard against oversized inputs
    if data.len() > MAX_TAG_LENGTH {
        return;
    }

    // This replicates the exact parsing logic from postgres.rs:3494-3504
    if let Ok(tag) = std::str::from_utf8(data) {
        let tag = tag.trim_end_matches('\0');
        // Tag format: "INSERT 0 5" or "UPDATE 10" or "DELETE 3"
        if let Some(num_str) = tag.rsplit(' ').next() {
            // Test the u64 parsing - this should never panic
            let _affected_rows = num_str.parse::<u64>().unwrap_or(0);

            // Additional invariant: if parsing succeeds, the number should be valid
            if let Ok(parsed_num) = num_str.parse::<u64>() {
                // Invariant: parsed number should be the same when formatted back
                assert_eq!(num_str, parsed_num.to_string(),
                    "Round-trip parsing invariant violated for: {:?}", num_str);
            }
        }
    }
    // Invalid UTF-8 is silently ignored, which is correct behavior
}

fuzz_target!(|data: &[u8]| {
    // First test with raw input
    test_command_complete_tag_parsing(data);

    // Then test with structure-aware generation if we can parse the input
    if data.len() >= std::mem::size_of::<CommandCompleteTag>() {
        let mut u = Unstructured::new(data);
        if let Ok(tag_case) = CommandCompleteTag::arbitrary(&mut u) {
            let generated_bytes = tag_case.generate_bytes();
            test_command_complete_tag_parsing(&generated_bytes);
        }
    }
});