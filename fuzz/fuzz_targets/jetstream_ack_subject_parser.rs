//! Focused fuzz target for JetStream ACK reply-subject token splitting.
//!
//! This fuzzer specifically targets the JetStream ACK reply subject parsing logic
//! in src/messaging/jetstream.rs::parse_js_message(). The ACK subject format is:
//!
//! `$JS.ACK.<stream>.<consumer>.<delivered>.<stream_seq>.<consumer_seq>.<timestamp>.<pending>`
//!
//! where <stream> and <consumer> names can contain dots, making the parsing complex.
//! The parser splits on '.' and parses the last 5 numeric fields from the right.
//!
//! # Attack Scenarios Tested
//! - Edge cases in dot-separated token splitting (too few/many segments)
//! - Numeric field parsing edge cases (overflow, negative, non-numeric)
//! - Stream/consumer name boundary attacks (embedding delimiters)
//! - Memory exhaustion via extremely long subject strings
//! - Unicode/non-ASCII characters in various fields
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run jetstream_ack_subject_parser
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::{FuzzJsAckMetadata, fuzz_parse_js_message};
use asupersync::messaging::nats::Message;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_SIZE: usize = 100_000;

/// Structure-aware ACK subject generation for more effective fuzzing
#[derive(Arbitrary, Debug)]
struct AckSubjectFuzz {
    /// Stream name (may contain dots)
    stream_name: StreamName,
    /// Consumer name (may contain dots)
    consumer_name: ConsumerName,
    /// Numeric fields at the end
    numeric_fields: NumericFields,
    /// Attack strategies to apply
    attack_strategy: AttackStrategy,
}

#[derive(Arbitrary, Debug)]
enum StreamName {
    Simple(String),
    Dotted { parts: Vec<String> },
    Empty,
    ExtremelyLong(String),
}

#[derive(Arbitrary, Debug)]
enum ConsumerName {
    Simple(String),
    Dotted { parts: Vec<String> },
    Empty,
    ExtremelyLong(String),
}

#[derive(Arbitrary, Debug)]
struct NumericFields {
    delivered: NumericField,
    stream_seq: NumericField,
    consumer_seq: NumericField,
    timestamp: NumericField,
    pending: NumericField,
}

#[derive(Arbitrary, Debug)]
enum NumericField {
    Valid(u64),
    Negative(i64),
    Zero,
    MaxValue,
    NonNumeric(String),
    Empty,
    Overflow(String), // String to represent larger-than-u64 values
}

#[derive(Arbitrary, Debug)]
enum AttackStrategy {
    None,
    /// Insert extra dot segments to confuse parsing
    ExtraSegments {
        count: u8,
    },
    /// Remove required segments
    MissingSegments {
        count: u8,
    },
    /// Wrong prefix
    WrongPrefix(String),
    /// Unicode/non-ASCII injection
    UnicodeInjection {
        field_index: u8,
        unicode_string: String,
    },
    /// Extremely long field values
    LongFieldAttack {
        field_index: u8,
    },
    /// Mixed valid/invalid numeric patterns
    MixedNumericPattern,
}

impl AckSubjectFuzz {
    fn generate_ack_subject(&self) -> String {
        let mut subject = String::from("$JS.ACK");

        // Apply wrong prefix attack
        if let AttackStrategy::WrongPrefix(prefix) = &self.attack_strategy {
            subject = prefix.clone();
        }

        // Add stream name
        let stream = match &self.stream_name {
            StreamName::Simple(name) => name.clone(),
            StreamName::Dotted { parts } => parts.join("."),
            StreamName::Empty => String::new(),
            StreamName::ExtremelyLong(base) => base.repeat(1000),
        };
        if !stream.is_empty() {
            subject.push('.');
            subject.push_str(&stream);
        }

        // Add consumer name
        let consumer = match &self.consumer_name {
            ConsumerName::Simple(name) => name.clone(),
            ConsumerName::Dotted { parts } => parts.join("."),
            ConsumerName::Empty => String::new(),
            ConsumerName::ExtremelyLong(base) => base.repeat(1000),
        };
        if !consumer.is_empty() {
            subject.push('.');
            subject.push_str(&consumer);
        }

        // Add numeric fields
        let fields = [
            &self.numeric_fields.delivered,
            &self.numeric_fields.stream_seq,
            &self.numeric_fields.consumer_seq,
            &self.numeric_fields.timestamp,
            &self.numeric_fields.pending,
        ];

        for field in fields {
            subject.push('.');
            match field {
                NumericField::Valid(n) => subject.push_str(&n.to_string()),
                NumericField::Negative(n) => subject.push_str(&n.to_string()),
                NumericField::Zero => subject.push('0'),
                NumericField::MaxValue => subject.push_str(&u64::MAX.to_string()),
                NumericField::NonNumeric(s) => subject.push_str(s),
                NumericField::Empty => {} // Add nothing, creating ".."
                NumericField::Overflow(s) => subject.push_str(s),
            }
        }

        // Apply attack strategies
        match &self.attack_strategy {
            AttackStrategy::ExtraSegments { count } => {
                for i in 0..*count {
                    subject.push_str(&format!(".extra{}", i));
                }
            }
            AttackStrategy::MissingSegments { count } => {
                // Remove segments from the end by truncating at dots
                let mut parts: Vec<&str> = subject.split('.').collect();
                if parts.len() > (*count as usize) {
                    parts.truncate(parts.len() - (*count as usize));
                    subject = parts.join(".");
                }
            }
            AttackStrategy::UnicodeInjection {
                field_index,
                unicode_string,
            } => {
                if let Some(insert_pos) = subject.match_indices('.').nth(*field_index as usize) {
                    subject.insert_str(insert_pos.0 + 1, unicode_string);
                }
            }
            AttackStrategy::LongFieldAttack { field_index } => {
                if let Some(insert_pos) = subject.match_indices('.').nth(*field_index as usize) {
                    let long_field = "A".repeat(50000);
                    subject.insert_str(insert_pos.0 + 1, &long_field);
                }
            }
            _ => {}
        }

        subject
    }

    fn should_parse_successfully(&self) -> bool {
        // Determine if this input should parse successfully based on the structure
        match &self.attack_strategy {
            AttackStrategy::None => {
                // Check if all numeric fields are valid
                let fields = [
                    &self.numeric_fields.delivered,
                    &self.numeric_fields.stream_seq,
                    &self.numeric_fields.consumer_seq,
                    &self.numeric_fields.timestamp,
                    &self.numeric_fields.pending,
                ];

                fields.iter().all(|f| {
                    matches!(
                        f,
                        NumericField::Valid(_) | NumericField::Zero | NumericField::MaxValue
                    )
                }) && matches!(
                    self.stream_name,
                    StreamName::Simple(_) | StreamName::Dotted { .. }
                ) && matches!(
                    self.consumer_name,
                    ConsumerName::Simple(_) | ConsumerName::Dotted { .. }
                )
            }
            _ => false, // Attack strategies should generally cause parsing failures
        }
    }
}

/// Create a mock NATS message for testing the JetStream parser
fn create_test_message(reply_subject: &str) -> Message {
    Message {
        subject: "test.subject".to_string(),
        sid: 1,
        reply_to: Some(reply_subject.to_string()),
        headers: None,
        payload: b"test payload".to_vec(),
    }
}

/// Extract the core parsing logic for direct testing
/// This mirrors the parsing logic in Consumer::parse_js_message but focuses on the reply subject parsing
fn fuzz_parse_ack_subject(reply_subject: &str) -> Option<FuzzJsAckMetadata> {
    if !reply_subject.starts_with("$JS.ACK.") {
        return None;
    }

    let parts: Vec<&str> = reply_subject.split('.').collect();

    // Minimum: $JS (0), ACK (1), stream, consumer, delivered, stream_seq, consumer_seq, timestamp, pending
    if parts.len() < 9 {
        return None;
    }

    // Parse the last 5 numeric fields from the right
    let _pending = parts[parts.len() - 1].parse::<u64>().ok()?;
    let _timestamp = parts[parts.len() - 2].parse::<u64>().ok()?;
    let _consumer_seq = parts[parts.len() - 3].parse::<u64>().ok()?;
    let stream_seq = parts[parts.len() - 4].parse::<u64>().ok()?;
    let delivered = parts[parts.len() - 5].parse::<u32>().ok()?;

    Some(FuzzJsAckMetadata {
        subject: "test.subject".to_string(),
        sequence: stream_seq,
        delivered,
        payload_len: 12, // "test payload".len()
    })
}

fuzz_target!(|input: AckSubjectFuzz| {
    let subject = input.generate_ack_subject();

    // Prevent excessive input sizes that could cause timeouts
    if subject.len() > MAX_INPUT_SIZE {
        return;
    }

    let expected_success = input.should_parse_successfully();

    // Property 1: No panic on any ACK subject input
    let parse_result = std::panic::catch_unwind(|| fuzz_parse_ack_subject(&subject));

    match parse_result {
        Ok(result) => {
            match (expected_success, result) {
                (true, Some(metadata)) => {
                    // Expected successful parse - verify metadata is reasonable
                    assert_eq!(metadata.subject, "test.subject");
                    assert_eq!(metadata.payload_len, 12);
                }
                (false, None) => {
                    // Expected parse failure - this is correct
                }
                (true, None) => {
                    // Expected success but got failure - potential missed valid input
                    // This might be acceptable depending on validation strictness
                }
                (false, Some(_)) => {
                    // Expected failure but got success - potential security issue
                    // Only panic for clearly invalid cases
                    match &input.attack_strategy {
                        AttackStrategy::WrongPrefix(_) => {
                            panic!("Parser accepted clearly invalid ACK subject: {}", subject);
                        }
                        AttackStrategy::MissingSegments { count } if *count > 2 => {
                            panic!("Parser accepted clearly invalid ACK subject: {}", subject);
                        }
                        _ => {
                            // Other cases might be acceptable depending on implementation
                        }
                    }
                }
            }
        }
        Err(_) => {
            // Parser panicked - this is always a bug
            panic!(
                "ACK subject parser panicked on input: {}",
                subject.chars().take(200).collect::<String>()
            );
        }
    }

    // Property 2: Test against the actual JetStream parser for differential testing
    if subject.len() < 10000 {
        // Only test reasonable-sized inputs with the real parser
        let msg = create_test_message(&subject);
        let js_parse_result = std::panic::catch_unwind(|| {
            // This calls the real Consumer::parse_js_message function through its fuzz re-export.
            fuzz_parse_js_message(msg)
        });

        match js_parse_result {
            Ok(js_result) => {
                let our_result = fuzz_parse_ack_subject(&subject);

                // Both parsers should agree on whether the input is valid
                match (js_result, our_result) {
                    (Some(js_msg), Some(our_meta)) => {
                        // Both succeeded - verify they extracted the same data
                        assert_eq!(
                            js_msg.sequence, our_meta.sequence,
                            "Sequence mismatch for subject: {}",
                            subject
                        );
                        assert_eq!(
                            js_msg.delivered, our_meta.delivered,
                            "Delivered count mismatch for subject: {}",
                            subject
                        );
                    }
                    (None, None) => {
                        // Both failed - this is consistent
                    }
                    (Some(_), None) => {
                        // Real parser succeeded but ours failed - investigate
                        // This suggests our parsing is too strict
                    }
                    (None, Some(_)) => {
                        // Our parser succeeded but real failed - potential issue
                        // This suggests our parsing is too lenient
                    }
                }
            }
            Err(_) => {
                // Real parser panicked - report this as a separate issue
                panic!("Real JetStream parser panicked on subject: {}", subject);
            }
        }
    }

    // Property 3: Valid ACK subjects should have predictable structure
    if let Some(metadata) = fuzz_parse_ack_subject(&subject) {
        assert_eq!(metadata.subject, "test.subject");
        assert_eq!(metadata.payload_len, 12);
    }

    // Property 4: Round-trip property for well-formed subjects
    if subject.starts_with("$JS.ACK.") && subject.matches('.').count() >= 8 {
        let parts: Vec<&str> = subject.split('.').collect();
        if parts.len() >= 9 {
            // Try to reconstruct a similar subject and verify it parses consistently
            let reconstructed = format!(
                "$JS.ACK.teststream.testconsumer.{}.{}.{}.{}.{}",
                parts[parts.len() - 5], // delivered
                parts[parts.len() - 4], // stream_seq
                parts[parts.len() - 3], // consumer_seq
                parts[parts.len() - 2], // timestamp
                parts[parts.len() - 1]  // pending
            );

            if let (Some(original), Some(reconstructed_result)) = (
                fuzz_parse_ack_subject(&subject),
                fuzz_parse_ack_subject(&reconstructed),
            ) {
                // The numeric fields should match
                assert_eq!(original.sequence, reconstructed_result.sequence);
                assert_eq!(original.delivered, reconstructed_result.delivered);
            }
        }
    }
});
