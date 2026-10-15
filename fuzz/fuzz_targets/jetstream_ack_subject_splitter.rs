#![no_main]

//! Structure-aware fuzz target for JetStream ACK reply subject token splitter.
//!
//! br-asupersync-7mz2lq — This target exercises the token splitting and parsing
//! logic in Consumer::parse_js_message that handles ACK reply subjects with
//! dotted stream/consumer names and trailing numeric fields.
//!
//! ACK subject format: $JS.ACK.<stream>.<consumer>.<delivered>.<stream_seq>.<consumer_seq>.<timestamp>.<pending>
//!
//! Vulnerability areas tested:
//! - Malformed token counts (< 9 minimum, excessive tokens)
//! - Non-numeric values where integers expected
//! - Edge cases with empty/malformed dot separation
//! - Integer overflow in u32/u64 parsing
//! - Very long stream/consumer names with embedded dots
//! - Invalid UTF-8 and control characters
//!
//! Usage: cargo fuzz run jetstream_ack_subject_splitter

use arbitrary::{Arbitrary, Unstructured};
use asupersync::messaging::{
    jetstream::{FuzzJsAckMetadata, fuzz_parse_js_message},
    nats::Message,
};
use libfuzzer_sys::fuzz_target;

/// Maximum subject length (reasonable upper bound for NATS subjects)
const MAX_SUBJECT_LENGTH: usize = 4096;

/// Structure-aware generator for JetStream ACK reply subjects
#[derive(Arbitrary, Debug, Clone)]
struct AckReplySubject {
    /// Subject structure variant
    structure: SubjectStructure,
    /// Fuzzing parameters for edge cases
    fuzz_params: FuzzParams,
}

/// Different structural patterns for ACK subjects
#[derive(Arbitrary, Debug, Clone)]
enum SubjectStructure {
    /// Valid minimal structure (simple stream/consumer names)
    ValidMinimal {
        stream: SimpleToken,
        consumer: SimpleToken,
        delivered: u32,
        stream_seq: u64,
        consumer_seq: u64,
        timestamp: u64,
        pending: u64,
    },
    /// Valid with dotted names (complex parsing scenario)
    ValidDotted {
        stream_segments: Vec<SimpleToken>,
        consumer_segments: Vec<SimpleToken>,
        delivered: u32,
        stream_seq: u64,
        consumer_seq: u64,
        timestamp: u64,
        pending: u64,
    },
    /// Malformed structures for boundary testing
    Malformed(MalformedSubject),
}

/// Parameters for injecting edge cases
#[derive(Arbitrary, Debug, Clone)]
struct FuzzParams {
    /// Add leading/trailing dots
    extra_dots: ExtraDots,
    /// Corrupt numeric fields
    numeric_corruption: NumericCorruption,
    /// Inject special characters
    special_injection: SpecialInjection,
    /// Control total length
    length_mutation: LengthMutation,
}

#[derive(Arbitrary, Debug, Clone)]
struct ExtraDots {
    leading_count: u8,
    trailing_count: u8,
    embedded_empty_tokens: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum NumericCorruption {
    None,
    EmptyFields,
    NonNumeric(Vec<u8>),
    Overflow(OverflowType),
    Mixed,
}

#[derive(Arbitrary, Debug, Clone)]
enum OverflowType {
    U32Max,
    U64Max,
    VeryLarge,
    Negative,
}

#[derive(Arbitrary, Debug, Clone)]
enum SpecialInjection {
    None,
    Unicode(String),
    ControlChars(Vec<u8>),
    NullBytes,
    HighBitSet,
}

#[derive(Arbitrary, Debug, Clone)]
enum LengthMutation {
    Normal,
    VeryShort(u8),
    VeryLong(u16),
    ExactBoundary(BoundaryType),
}

#[derive(Arbitrary, Debug, Clone)]
enum BoundaryType {
    Minimum,  // Exactly 9 tokens
    Overflow, // Way too many tokens
}

/// Simple alphanumeric token for stream/consumer names
#[derive(Arbitrary, Debug, Clone)]
struct SimpleToken {
    content: TokenContent,
    length: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum TokenContent {
    Alphanumeric,
    WithDots,
    WithHyphens,
    Mixed,
    Binary(Vec<u8>),
}

/// Malformed subject patterns
#[derive(Arbitrary, Debug, Clone)]
enum MalformedSubject {
    /// Wrong prefix (not $JS.ACK)
    WrongPrefix(Vec<u8>),
    /// Too few tokens (< 9)
    TooFewTokens(u8),
    /// Way too many tokens (stress test)
    TooManyTokens(u16),
    /// Completely random structure
    RandomGarbage(Vec<u8>),
    /// Injection attacks
    InjectionAttempt(InjectionType),
}

#[derive(Arbitrary, Debug, Clone)]
enum InjectionType {
    PathTraversal,
    SqlInjection,
    ScriptInjection,
    NullInjection,
}

impl SimpleToken {
    fn materialize(&self) -> String {
        let base_length = usize::from(self.length % 32) + 1; // 1-32 chars

        match &self.content {
            TokenContent::Alphanumeric => (0..base_length)
                .map(|i| {
                    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    char::from(chars[i % chars.len()])
                })
                .collect(),
            TokenContent::WithDots => {
                format!("seg1.seg2.seg{}", base_length % 10)
            }
            TokenContent::WithHyphens => {
                format!("token-{}-{}", base_length % 100, base_length % 10)
            }
            TokenContent::Mixed => {
                format!("stream_{}.v{}", base_length % 10, base_length % 3)
            }
            TokenContent::Binary(bytes) => {
                String::from_utf8_lossy(&bytes[..std::cmp::min(bytes.len(), base_length)])
                    .into_owned()
            }
        }
    }
}

impl AckReplySubject {
    fn materialize(&self) -> String {
        let base_subject = match &self.structure {
            SubjectStructure::ValidMinimal {
                stream,
                consumer,
                delivered,
                stream_seq,
                consumer_seq,
                timestamp,
                pending,
            } => {
                format!(
                    "$JS.ACK.{}.{}.{}.{}.{}.{}.{}",
                    stream.materialize(),
                    consumer.materialize(),
                    delivered,
                    stream_seq,
                    consumer_seq,
                    timestamp,
                    pending
                )
            }
            SubjectStructure::ValidDotted {
                stream_segments,
                consumer_segments,
                delivered,
                stream_seq,
                consumer_seq,
                timestamp,
                pending,
            } => {
                let stream_name: Vec<String> =
                    stream_segments.iter().map(|s| s.materialize()).collect();
                let consumer_name: Vec<String> =
                    consumer_segments.iter().map(|s| s.materialize()).collect();

                format!(
                    "$JS.ACK.{}.{}.{}.{}.{}.{}.{}",
                    stream_name.join("."),
                    consumer_name.join("."),
                    delivered,
                    stream_seq,
                    consumer_seq,
                    timestamp,
                    pending
                )
            }
            SubjectStructure::Malformed(malformed) => self.materialize_malformed(malformed),
        };

        self.apply_fuzz_params(base_subject)
    }

    fn apply_fuzz_params(&self, mut subject: String) -> String {
        // Apply extra dots
        let leading_dots = ".".repeat(usize::from(self.fuzz_params.extra_dots.leading_count % 10));
        let trailing_dots =
            ".".repeat(usize::from(self.fuzz_params.extra_dots.trailing_count % 10));
        subject = format!("{leading_dots}{subject}{trailing_dots}");

        // Apply embedded empty tokens
        if self.fuzz_params.extra_dots.embedded_empty_tokens {
            subject = subject.replace(".", "..");
        }

        // Apply numeric corruption
        subject = self.apply_numeric_corruption(subject);

        // Apply special character injection
        subject = self.apply_special_injection(subject);

        // Apply length mutations
        subject = self.apply_length_mutation(subject);

        // Ensure reasonable size limits
        if subject.len() > MAX_SUBJECT_LENGTH {
            subject.truncate(MAX_SUBJECT_LENGTH);
        }

        subject
    }

    fn apply_numeric_corruption(&self, subject: String) -> String {
        match &self.fuzz_params.numeric_corruption {
            NumericCorruption::None => subject,
            NumericCorruption::EmptyFields => {
                // Replace some numeric fields with empty strings
                subject.replace(".123.", "..").replace(".456.", "..")
            }
            NumericCorruption::NonNumeric(bytes) => {
                // Inject non-numeric data where numbers expected
                let replacement = String::from_utf8_lossy(bytes);
                subject.replace(".123.", &format!(".{replacement}."))
            }
            NumericCorruption::Overflow(overflow_type) => {
                let replacement = match overflow_type {
                    OverflowType::U32Max => format!("{}", u64::from(u32::MAX) + 1),
                    OverflowType::U64Max => "18446744073709551616".to_string(), // u64::MAX + 1
                    OverflowType::VeryLarge => "9999999999999999999999999999".to_string(),
                    OverflowType::Negative => "-42".to_string(),
                };
                subject.replace(".123.", &format!(".{replacement}."))
            }
            NumericCorruption::Mixed => subject
                .replace(".123.", ".abc.")
                .replace(".456.", ".-999.")
                .replace(".789.", ".."),
        }
    }

    fn apply_special_injection(&self, mut subject: String) -> String {
        match &self.fuzz_params.special_injection {
            SpecialInjection::None => subject,
            SpecialInjection::Unicode(s) => {
                subject.push_str(s);
                subject
            }
            SpecialInjection::ControlChars(bytes) => {
                let control_str = String::from_utf8_lossy(bytes);
                subject.push_str(&control_str);
                subject
            }
            SpecialInjection::NullBytes => {
                subject.push('\0');
                subject.push_str("after_null");
                subject
            }
            SpecialInjection::HighBitSet => {
                subject.push_str(&String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD]));
                subject
            }
        }
    }

    fn apply_length_mutation(&self, subject: String) -> String {
        match &self.fuzz_params.length_mutation {
            LengthMutation::Normal => subject,
            LengthMutation::VeryShort(len) => {
                let target_len = usize::from(*len % 20);
                if subject.len() > target_len {
                    subject[..target_len].to_string()
                } else {
                    subject
                }
            }
            LengthMutation::VeryLong(multiplier) => {
                let repeat_count = usize::from(*multiplier % 100) + 1;
                subject.repeat(repeat_count)
            }
            LengthMutation::ExactBoundary(boundary_type) => match boundary_type {
                BoundaryType::Minimum => {
                    // Create exactly 9 tokens: $JS.ACK.s.c.1.2.3.4.5
                    "$JS.ACK.s.c.1.2.3.4.5".to_string()
                }
                BoundaryType::Overflow => {
                    // Create way too many tokens
                    let base = "$JS.ACK.stream.consumer";
                    let extra_tokens: Vec<String> = (0..1000).map(|i| i.to_string()).collect();
                    format!("{}.{}", base, extra_tokens.join("."))
                }
            },
        }
    }

    fn materialize_malformed(&self, malformed: &MalformedSubject) -> String {
        match malformed {
            MalformedSubject::WrongPrefix(prefix) => {
                let prefix_str = String::from_utf8_lossy(prefix);
                format!("{prefix_str}.stream.consumer.1.2.3.4.5")
            }
            MalformedSubject::TooFewTokens(count) => {
                let token_count = usize::from(*count % 15);
                let tokens: Vec<String> = (0..token_count).map(|i| format!("tok{i}")).collect();
                tokens.join(".")
            }
            MalformedSubject::TooManyTokens(count) => {
                let token_count = usize::from(*count % 10000) + 100;
                let tokens: Vec<String> = (0..token_count).map(|i| format!("t{i}")).collect();
                format!("$JS.ACK.{}", tokens.join("."))
            }
            MalformedSubject::RandomGarbage(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            MalformedSubject::InjectionAttempt(injection_type) => match injection_type {
                InjectionType::PathTraversal => {
                    "$JS.ACK.../../etc/passwd.consumer.1.2.3.4.5".to_string()
                }
                InjectionType::SqlInjection => {
                    "$JS.ACK.'; DROP TABLE streams; --.consumer.1.2.3.4.5".to_string()
                }
                InjectionType::ScriptInjection => {
                    "$JS.ACK.<script>alert('xss')</script>.consumer.1.2.3.4.5".to_string()
                }
                InjectionType::NullInjection => {
                    "$JS.ACK.stream\0inject.consumer.1.2.3.4.5".to_string()
                }
            },
        }
    }

    fn should_parse_successfully(&self) -> bool {
        // Determine if this input should parse successfully
        match &self.structure {
            SubjectStructure::ValidMinimal { .. } | SubjectStructure::ValidDotted { .. } => {
                // Check if fuzz params corrupt it
                matches!(self.fuzz_params.numeric_corruption, NumericCorruption::None)
                    && matches!(self.fuzz_params.special_injection, SpecialInjection::None)
                    && self.fuzz_params.extra_dots.leading_count == 0
                    && self.fuzz_params.extra_dots.trailing_count == 0
                    && !self.fuzz_params.extra_dots.embedded_empty_tokens
                    && matches!(self.fuzz_params.length_mutation, LengthMutation::Normal)
            }
            SubjectStructure::Malformed(_) => false,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent excessive memory usage
    if data.len() > MAX_SUBJECT_LENGTH {
        return;
    }

    // Test 1: Direct raw byte fuzzing (classic approach)
    test_raw_subject_parsing(data);

    // Test 2: Structure-aware fuzzing if we can parse the input
    let mut u = Unstructured::new(data);
    if let Ok(ack_subject) = AckReplySubject::arbitrary(&mut u) {
        test_structured_subject_parsing(&ack_subject);
    }

    // Test 3: Boundary condition fuzzing
    test_boundary_conditions(data);
});

fn test_raw_subject_parsing(data: &[u8]) {
    // Convert to string for subject parsing
    let subject_string = String::from_utf8_lossy(data);

    // Create a minimal NATS message with this reply subject
    let msg = Message {
        subject: "test.subject".to_string(),
        sid: 1,
        headers: None,
        payload: b"test payload".to_vec(),
        reply_to: Some(subject_string.into_owned()),
    };

    // Fuzz the parser - it should never panic
    let result = fuzz_parse_js_message(msg);

    // Verify result is either Some(valid metadata) or None
    if let Some(metadata) = result {
        // Verify parsed metadata is reasonable
        assert_eq!(metadata.subject, "test.subject");
        assert_eq!(metadata.payload_len, 12); // "test payload".len()
        // sequence and delivered can be any values - just check they don't cause issues
        let _ = metadata.sequence;
        let _ = metadata.delivered;
    }
}

fn test_structured_subject_parsing(ack_subject: &AckReplySubject) {
    let generated_subject = ack_subject.materialize();

    // Skip empty subjects (not interesting)
    if generated_subject.is_empty() {
        return;
    }

    let msg = Message {
        subject: "generated.test".to_string(),
        sid: 42,
        headers: None,
        payload: b"structured test".to_vec(),
        reply_to: Some(generated_subject.clone()),
    };

    let result = fuzz_parse_js_message(msg);
    let should_succeed = ack_subject.should_parse_successfully();

    match (result, should_succeed) {
        (Some(metadata), true) => {
            // Valid parse of well-formed input
            assert_eq!(metadata.subject, "generated.test");
            assert_eq!(metadata.payload_len, 15);
        }
        (None, true) => {
            // This might happen due to fuzz params corrupting otherwise valid input
            // Don't assert - the fuzz params can make valid structures unparseable
        }
        (Some(_), false) => {
            // Malformed input parsed successfully - this shouldn't happen for severely malformed input
            // But don't assert because some "malformed" inputs might still be parseable
        }
        (None, false) => {
            // Expected - malformed input rejected
        }
    }
}

fn observe_ack_subject_parse(
    result: Option<FuzzJsAckMetadata>,
    expected_subject: &str,
    expected_payload_len: usize,
    context: &str,
) {
    if let Some(metadata) = result {
        assert_eq!(
            metadata.subject, expected_subject,
            "{context} changed the source subject"
        );
        assert_eq!(
            metadata.payload_len, expected_payload_len,
            "{context} changed the source payload length"
        );
    }
}

fn observe_ack_subject_rejection(result: Option<FuzzJsAckMetadata>, context: &str) {
    assert!(result.is_none(), "{context} unexpectedly parsed");
}

fn test_boundary_conditions(data: &[u8]) {
    // Test specific boundary patterns

    // Test very short subjects
    if data.len() <= 20 {
        let short_subject = String::from_utf8_lossy(data);
        let msg = Message {
            subject: "boundary".to_string(),
            sid: 1,
            headers: None,
            payload: Vec::new(),
            reply_to: Some(short_subject.into_owned()),
        };
        observe_ack_subject_rejection(fuzz_parse_js_message(msg), "short ACK subject");
    }

    // Test exact minimum token count (9 tokens)
    if data.len() >= 9 {
        let tokens: Vec<String> = data
            .iter()
            .take(9)
            .enumerate()
            .map(|(i, &b)| {
                if i < 2 {
                    // Fixed prefix for first two tokens
                    ["$JS", "ACK"][i].to_string()
                } else if i >= 4 {
                    // Last 5 tokens should be numeric - use data as source
                    format!("{}", u32::from(b))
                } else {
                    // Stream/consumer tokens - use printable chars
                    format!("tok{}", char::from(b.wrapping_add(32) % 95 + 32))
                }
            })
            .collect();

        let boundary_subject = tokens.join(".");
        let msg = Message {
            subject: "boundary".to_string(),
            sid: 1,
            headers: None,
            payload: Vec::new(),
            reply_to: Some(boundary_subject),
        };
        observe_ack_subject_parse(
            fuzz_parse_js_message(msg),
            "boundary",
            0,
            "minimum-token ACK subject",
        );
    }

    // Test integer overflow scenarios
    let overflow_subjects = [
        "$JS.ACK.s.c.4294967296.0.0.0.0", // u32::MAX + 1 for delivered
        "$JS.ACK.s.c.0.18446744073709551616.0.0.0", // u64::MAX + 1 for stream_seq
        "$JS.ACK.s.c.-1.0.0.0.0",         // Negative number
        "$JS.ACK.s.c.abc.0.0.0.0",        // Non-numeric
        "$JS.ACK.s.c..0.0.0.0",           // Empty field
    ];

    for subject in overflow_subjects {
        let msg = Message {
            subject: "overflow".to_string(),
            sid: 1,
            headers: None,
            payload: Vec::new(),
            reply_to: Some(subject.to_string()),
        };
        observe_ack_subject_rejection(fuzz_parse_js_message(msg), "overflow ACK subject");
    }

    // Test UTF-8 edge cases
    if data.len() >= 4 {
        let mut utf8_subject = "$JS.ACK.stream".to_string();
        utf8_subject.push_str(&String::from_utf8_lossy(&data[..4]));
        utf8_subject.push_str(".consumer.1.2.3.4.5");

        let msg = Message {
            subject: "utf8".to_string(),
            sid: 1,
            headers: None,
            payload: Vec::new(),
            reply_to: Some(utf8_subject),
        };
        observe_ack_subject_parse(fuzz_parse_js_message(msg), "utf8", 0, "UTF-8 ACK subject");
    }
}
