#![no_main]

//! Structure-aware fuzz target for PostgreSQL CommandComplete tag parser.
//!
//! This target exercises the production PostgreSQL parser seam that extracts
//! affected row counts from CommandComplete message tags.
//!
//! Test cases include valid SELECT/INSERT/UPDATE/DELETE/MOVE/FETCH/COPY tags,
//! malformed tags, integer overflows, non-UTF-8 input, trailing garbage, empty
//! tags, and unknown command families.

use arbitrary::{Arbitrary, Unstructured};
use asupersync::database::postgres::{PgError, fuzz_parse_command_complete_tag};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Maximum tag length for reasonable fuzzing performance
const MAX_TAG_LENGTH: usize = 1024;

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

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
    /// Single-count command: "UPDATE count", "SELECT count", etc.
    Count {
        family: CountCommandFamily,
        count: u64,
    },
    /// Unknown command with a numeric suffix.
    Unknown { count: u64 },
    /// Edge case: empty tag
    Empty,
    /// Malformed tags for parser robustness testing
    Malformed(MalformedTag),
}

/// PostgreSQL command families that carry a single affected-row token.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CountCommandFamily {
    Update,
    Delete,
    Select,
    Copy,
    Move,
    Fetch,
}

impl CountCommandFamily {
    fn as_str(self) -> &'static str {
        match self {
            CountCommandFamily::Update => "UPDATE",
            CountCommandFamily::Delete => "DELETE",
            CountCommandFamily::Select => "SELECT",
            CountCommandFamily::Copy => "COPY",
            CountCommandFamily::Move => "MOVE",
            CountCommandFamily::Fetch => "FETCH",
        }
    }
}

/// Malformed tag variants for edge case testing
#[derive(Arbitrary, Debug, Clone)]
enum MalformedTag {
    /// Missing count token: "UPDATE"
    MissingCount { family: CountCommandFamily },
    /// INSERT missing the affected-row token: "INSERT oid"
    InsertMissingRows { oid: u32 },
    /// Non-numeric count: "UPDATE x"
    NonNumericCount {
        family: CountCommandFamily,
        suffix: String,
    },
    /// One past u64::MAX.
    OverflowCount { family: CountCommandFamily },
    /// Negative count: "UPDATE -1"
    NegativeCount { family: CountCommandFamily },
    /// Valid count followed by trailing garbage.
    TrailingGarbage {
        family: CountCommandFamily,
        count: u64,
        suffix: String,
    },
    /// Only numbers: "12345"
    NumberOnly(String),
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
            TagVariant::Count { family, count } => format!("{} {}", family.as_str(), count),
            TagVariant::Unknown { count } => format!("UNKNOWN {}", count),
            TagVariant::Empty => String::new(),
            TagVariant::Malformed(malformed) => malformed.generate_string(),
        }
    }

    fn expectation(&self) -> ParseExpectation {
        if self.corruption.forces_error() {
            return ParseExpectation::Err;
        }

        match &self.variant {
            TagVariant::Insert { count, .. } | TagVariant::Count { count, .. } => {
                ParseExpectation::Rows(*count)
            }
            TagVariant::Unknown { .. } | TagVariant::Empty | TagVariant::Malformed(_) => {
                ParseExpectation::Err
            }
        }
    }

    fn command_family_label(&self) -> String {
        match &self.variant {
            TagVariant::Insert { .. } => "INSERT".to_string(),
            TagVariant::Count { family, .. } => family.as_str().to_string(),
            TagVariant::Unknown { .. } => "UNKNOWN".to_string(),
            TagVariant::Empty => "EMPTY".to_string(),
            TagVariant::Malformed(malformed) => malformed.command_family_label(),
        }
    }
}

impl MalformedTag {
    fn generate_string(&self) -> String {
        match self {
            MalformedTag::MissingCount { family } => family.as_str().to_string(),
            MalformedTag::InsertMissingRows { oid } => format!("INSERT {}", oid),
            MalformedTag::NonNumericCount { family, suffix } => {
                format!("{} x{}", family.as_str(), sanitize_token(suffix))
            }
            MalformedTag::OverflowCount { family } => {
                format!("{} 18446744073709551616", family.as_str())
            }
            MalformedTag::NegativeCount { family } => format!("{} -1", family.as_str()),
            MalformedTag::TrailingGarbage {
                family,
                count,
                suffix,
            } => format!("{} {} x{}", family.as_str(), count, sanitize_token(suffix)),
            MalformedTag::NumberOnly(num) => num.clone(),
        }
    }

    fn command_family_label(&self) -> String {
        match self {
            MalformedTag::MissingCount { family }
            | MalformedTag::NonNumericCount { family, .. }
            | MalformedTag::OverflowCount { family }
            | MalformedTag::NegativeCount { family }
            | MalformedTag::TrailingGarbage { family, .. } => family.as_str().to_string(),
            MalformedTag::InsertMissingRows { .. } => "INSERT".to_string(),
            MalformedTag::NumberOnly(_) => "NUMBER_ONLY".to_string(),
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
            EncodingCorruption::InvalidUtf8(invalid_bytes) => {
                let mut result = Vec::with_capacity(invalid_bytes.len() + 1);
                result.push(0xFF);
                result.extend_from_slice(invalid_bytes);
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
                bytes.extend(std::iter::repeat_n(0, usize::from(*count)));
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

    fn forces_error(&self) -> bool {
        matches!(self.encoding, EncodingCorruption::InvalidUtf8(_))
            || matches!(
                self.null_handling,
                NullHandling::Embedded | NullHandling::OnlyNulls
            )
            || matches!(self.whitespace, WhitespaceVariant::Unicode)
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
            WhitespaceVariant::Unicode => s.replace(' ', "\u{2000}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ParseExpectation {
    Rows(u64),
    Err,
    Unconstrained,
}

#[derive(Debug)]
struct CommandCompleteLabels {
    command_family: String,
    row_count_token_len: usize,
    utf8_status: &'static str,
    parse_outcome: &'static str,
    error_kind: &'static str,
    panic_free: bool,
}

impl CommandCompleteLabels {
    fn new(command_family: Option<&str>, data: &[u8], result: &Result<u64, PgError>) -> Self {
        let utf8 = std::str::from_utf8(data);
        let command_family = command_family
            .map(ToOwned::to_owned)
            .or_else(|| {
                utf8.ok()
                    .and_then(|tag| tag.trim_end_matches('\0').split_ascii_whitespace().next())
                    .map(|family| family.chars().take(32).collect())
            })
            .unwrap_or_else(|| {
                if utf8.is_ok() {
                    "EMPTY".to_string()
                } else {
                    "NON_UTF8".to_string()
                }
            });
        let row_count_token_len = utf8
            .ok()
            .and_then(|tag| tag.trim_end_matches('\0').split_ascii_whitespace().last())
            .map(str::len)
            .unwrap_or(0);
        let (parse_outcome, error_kind) = match result {
            Ok(_) => ("rows", "none"),
            Err(err) => ("error", pg_error_kind(err)),
        };

        Self {
            command_family,
            row_count_token_len,
            utf8_status: if utf8.is_ok() { "valid" } else { "invalid" },
            parse_outcome,
            error_kind,
            panic_free: true,
        }
    }

    fn corpus_label(&self) -> String {
        format!(
            "command_family={} row_count_token_len={} utf8_status={} parse_outcome={} error_kind={} panic_free={}",
            self.command_family,
            self.row_count_token_len,
            self.utf8_status,
            self.parse_outcome,
            self.error_kind,
            self.panic_free
        )
    }
}

fn pg_error_kind(error: &PgError) -> &'static str {
    match error {
        PgError::Io(_) => "io",
        PgError::Protocol(_) => "protocol",
        PgError::AuthenticationFailed(_) => "authentication_failed",
        PgError::Server { .. } => "server",
        PgError::Cancelled(_) => "cancelled",
        PgError::ConnectionClosed => "connection_closed",
        PgError::ColumnNotFound(_) => "column_not_found",
        PgError::TypeConversion { .. } => "type_conversion",
        PgError::InvalidUrl(_) => "invalid_url",
        PgError::TlsRequired => "tls_required",
        PgError::Tls(_) => "tls",
        PgError::TransactionFinished => "transaction_finished",
        PgError::UnsupportedAuth(_) => "unsupported_auth",
        PgError::IsolationLevelMismatch { .. } => "isolation_level_mismatch",
    }
}

fn sanitize_token(value: &str) -> String {
    let token: String = value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '\0')
        .take(32)
        .collect();
    if token.is_empty() {
        "x".to_string()
    } else {
        token
    }
}

fn exercise_command_complete_parser(
    data: &[u8],
    expectation: ParseExpectation,
    command_family: Option<&str>,
) {
    if data.len() > MAX_TAG_LENGTH {
        return;
    }

    let result = fuzz_parse_command_complete_tag(data);
    let labels = CommandCompleteLabels::new(command_family, data, &result);

    match expectation {
        ParseExpectation::Rows(expected) => match result {
            Ok(actual) => assert_eq!(actual, expected, "{}", labels.corpus_label()),
            Err(err) => {
                panic!(
                    "expected valid CommandComplete tag, got {err:?}; {}",
                    labels.corpus_label()
                )
            }
        },
        ParseExpectation::Err => {
            assert!(
                result.is_err(),
                "expected malformed CommandComplete tag rejection; {}",
                labels.corpus_label()
            );
        }
        ParseExpectation::Unconstrained => {}
    }
}

fn assert_protocol_rejection(data: &[u8], expected: &str) {
    let error = fuzz_parse_command_complete_tag(data)
        .expect_err("fixed CommandComplete tag canary should reject");

    match &error {
        PgError::Protocol(message) => assert_eq!(
            message, expected,
            "CommandComplete protocol diagnostic payload changed"
        ),
        other => panic!("expected CommandComplete protocol error, got {other:?}"),
    }

    assert_eq!(
        error.to_string(),
        format!("PostgreSQL protocol error: {expected}"),
        "CommandComplete Display diagnostic changed"
    );
}

fn assert_fixed_command_complete_error_canaries() {
    assert_protocol_rejection(b"\xff\xfe\x00", "CommandComplete tag must be valid UTF-8");
    assert_protocol_rejection(
        b"UPDATE\0",
        "CommandComplete tag missing numeric row count: \"UPDATE\"",
    );
    assert_protocol_rejection(
        b"INSERT 123\0",
        "CommandComplete tag missing numeric row count: \"INSERT 123\"",
    );
    assert_protocol_rejection(
        b"INSERT 1 2 3\0",
        "CommandComplete tag missing numeric row count: \"INSERT 1 2 3\"",
    );
    assert_protocol_rejection(
        b"UPDATE 18446744073709551616\0",
        "CommandComplete tag missing numeric row count: \"UPDATE 18446744073709551616\"",
    );
    assert_protocol_rejection(
        b"UPDATE -1\0",
        "CommandComplete tag missing numeric row count: \"UPDATE -1\"",
    );
    assert_protocol_rejection(
        b"UPDATE 1 trailing\0",
        "CommandComplete tag missing numeric row count: \"UPDATE 1 trailing\"",
    );
    assert_protocol_rejection(
        b"UNKNOWN 1\0",
        "CommandComplete tag missing numeric row count: \"UNKNOWN 1\"",
    );
    assert_protocol_rejection(b"", "CommandComplete tag missing numeric row count: \"\"");
    assert_protocol_rejection(b"\0", "CommandComplete tag missing numeric row count: \"\"");
}

fuzz_target!(|data: &[u8]| {
    FIXED_CANARIES.get_or_init(assert_fixed_command_complete_error_canaries);

    exercise_command_complete_parser(data, ParseExpectation::Unconstrained, None);

    if data.len() >= std::mem::size_of::<CommandCompleteTag>() {
        let mut u = Unstructured::new(data);
        if let Ok(tag_case) = CommandCompleteTag::arbitrary(&mut u) {
            let generated_bytes = tag_case.generate_bytes();
            let expectation = tag_case.expectation();
            let command_family = tag_case.command_family_label();
            exercise_command_complete_parser(&generated_bytes, expectation, Some(&command_family));
        }
    }
});
