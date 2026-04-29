//! JetStream ACK format conformance test: malformed token counts
//!
//! Differential test comparing our JetStream ACK parsing against nats-server
//! reference behavior for malformed token counts in ACK reply subjects.
//!
//! ACK Format: $JS.ACK.<stream>.<consumer>.<delivered>.<stream_seq>.<consumer_seq>.<timestamp>.<pending>
//! Reference: https://docs.nats.io/jetstream/concepts/core-features/acknowledgments

use asupersync::messaging::jetstream::fuzz_parse_js_message;
use asupersync::messaging::nats::Message;

/// Differential conformance test cases for malformed ACK token counts
/// Each case represents a known divergence point between valid and invalid ACK subjects
#[derive(Debug)]
struct MalformedTokenCase {
    id: &'static str,
    description: &'static str,
    ack_subject: &'static str,
    expected_behavior: ExpectedBehavior,
    requirement_level: RequirementLevel,
}

#[derive(Debug, Clone, PartialEq)]
enum ExpectedBehavior {
    /// Should be rejected (returns None) - malformed
    Reject,
    /// Should be accepted (returns Some) - valid despite edge case
    Accept { delivered: u32, sequence: u64 },
}

#[derive(Debug, Clone, PartialEq)]
enum RequirementLevel {
    Must,   // MUST be handled correctly per spec
    Should, // SHOULD be handled correctly for robustness
    May,    // MAY be handled correctly (implementation-defined)
}

/// Test case matrix for malformed token counts in JetStream ACK subjects
/// Based on nats-server reference behavior for edge cases
const MALFORMED_TOKEN_CASES: &[MalformedTokenCase] = &[
    // MUST cases: Clearly invalid according to spec
    MalformedTokenCase {
        id: "JETSTREAM-ACK-001",
        description: "Too few tokens: missing required fields",
        ack_subject: "$JS.ACK.stream.consumer.1.42.3", // Only 7 tokens, need >=9
        expected_behavior: ExpectedBehavior::Reject,
        requirement_level: RequirementLevel::Must,
    },
    MalformedTokenCase {
        id: "JETSTREAM-ACK-002",
        description: "Empty ACK subject",
        ack_subject: "",
        expected_behavior: ExpectedBehavior::Reject,
        requirement_level: RequirementLevel::Must,
    },
    MalformedTokenCase {
        id: "JETSTREAM-ACK-003",
        description: "Wrong prefix: not a JetStream ACK",
        ack_subject: "$JS.NAK.stream.consumer.1.42.3.1234567890.5", // NAK instead of ACK
        expected_behavior: ExpectedBehavior::Reject,
        requirement_level: RequirementLevel::Must,
    },
    MalformedTokenCase {
        id: "JETSTREAM-ACK-004",
        description: "Missing $JS prefix entirely",
        ack_subject: "ACK.stream.consumer.1.42.3.1234567890.5",
        expected_behavior: ExpectedBehavior::Reject,
        requirement_level: RequirementLevel::Must,
    },
    // SHOULD cases: Edge cases that should be handled robustly
    MalformedTokenCase {
        id: "JETSTREAM-ACK-005",
        description: "Just enough tokens for minimal valid ACK",
        ack_subject: "$JS.ACK.s.c.1.42.3.1234567890.5", // 9 tokens exactly
        expected_behavior: ExpectedBehavior::Accept {
            delivered: 1,
            sequence: 42,
        },
        requirement_level: RequirementLevel::Should,
    },
    MalformedTokenCase {
        id: "JETSTREAM-ACK-006",
        description: "Extra tokens beyond required format",
        ack_subject: "$JS.ACK.stream.consumer.1.42.3.1234567890.5.extra.tokens.here",
        expected_behavior: ExpectedBehavior::Accept {
            delivered: 1,
            sequence: 42,
        },
        requirement_level: RequirementLevel::Should,
    },
    // MAY cases: Implementation-defined behavior
    MalformedTokenCase {
        id: "JETSTREAM-ACK-007",
        description: "Only $JS.ACK prefix with no data",
        ack_subject: "$JS.ACK",
        expected_behavior: ExpectedBehavior::Reject,
        requirement_level: RequirementLevel::May,
    },
    MalformedTokenCase {
        id: "JETSTREAM-ACK-008",
        description: "Dotted stream name with too few total tokens",
        ack_subject: "$JS.ACK.orders.v2.processor.1.42", // 7 tokens but with dotted stream
        expected_behavior: ExpectedBehavior::Reject,
        requirement_level: RequirementLevel::May,
    },
];

/// Create a test message with the given ACK reply subject
fn create_test_message(ack_subject: &str) -> Message {
    Message {
        subject: "test.subject".to_string(),
        sid: 1,
        headers: None,
        payload: b"test payload".to_vec(),
        reply_to: Some(ack_subject.to_string()),
    }
}

/// Test our implementation against the reference behavior for malformed token counts
#[test]
fn jetstream_ack_malformed_token_conformance() {
    let mut passed = 0;
    let mut failed = 0;
    let mut must_failures = Vec::new();

    for case in MALFORMED_TOKEN_CASES {
        let msg = create_test_message(case.ack_subject);
        let result = fuzz_parse_js_message(msg);

        let test_passed = match (&result, &case.expected_behavior) {
            (None, ExpectedBehavior::Reject) => {
                // Correctly rejected malformed subject
                true
            }
            (
                Some(parsed),
                ExpectedBehavior::Accept {
                    delivered,
                    sequence,
                },
            ) => {
                // Correctly accepted and parsed values match
                parsed.delivered == *delivered && parsed.sequence == *sequence
            }
            (Some(_), ExpectedBehavior::Reject) => {
                // Incorrectly accepted malformed subject
                false
            }
            (None, ExpectedBehavior::Accept { .. }) => {
                // Incorrectly rejected valid subject
                false
            }
        };

        if test_passed {
            passed += 1;
            println!("PASS {}: {}", case.id, case.description);
        } else {
            failed += 1;
            println!(
                "FAIL {}: {}\n  ACK subject: {}\n  Expected: {:?}\n  Got: {:?}",
                case.id, case.description, case.ack_subject, case.expected_behavior, result
            );

            if case.requirement_level == RequirementLevel::Must {
                must_failures.push(case);
            }
        }

        // Emit structured JSON for CI parsing
        let status = if test_passed { "PASS" } else { "FAIL" };
        eprintln!(
            "{{\"id\":\"{}\",\"status\":\"{}\",\"level\":\"{:?}\",\"category\":\"malformed_tokens\"}}",
            case.id, status, case.requirement_level
        );
    }

    // Report summary
    let total = passed + failed;
    println!(
        "\nJetStream ACK Malformed Token Conformance: {}/{} passed, {} failed",
        passed, total, failed
    );

    // MUST requirements are non-negotiable
    if !must_failures.is_empty() {
        panic!(
            "CONFORMANCE FAILURE: {} MUST requirements failed: {:?}",
            must_failures.len(),
            must_failures.iter().map(|c| c.id).collect::<Vec<_>>()
        );
    }

    // Calculate conformance score
    let conformance_score = (passed as f64) / (total as f64) * 100.0;
    println!("Conformance score: {:.1}%", conformance_score);

    // Warn if below 95% for robustness
    if conformance_score < 95.0 {
        eprintln!(
            "WARNING: Conformance score {:.1}% below 95% threshold. \
             Consider improving edge case handling for robustness.",
            conformance_score
        );
    }
}

#[cfg(test)]
mod integration {
    use super::*;

    /// Smoke test: ensure the test infrastructure works
    #[test]
    fn conformance_test_infrastructure_works() {
        let msg = create_test_message("$JS.ACK.orders.consumer.1.42.3.1234567890.5");
        let result = fuzz_parse_js_message(msg);

        // Should successfully parse a valid ACK subject
        assert!(
            result.is_some(),
            "Valid ACK subject should parse successfully"
        );

        let parsed = result.unwrap();
        assert_eq!(parsed.delivered, 1);
        assert_eq!(parsed.sequence, 42);
    }

    /// Regression test: dotted names still work (existing functionality)
    #[test]
    fn dotted_names_still_work() {
        let msg = create_test_message("$JS.ACK.orders.v2.retry.consumer.1.42.3.1234567890.5");
        let result = fuzz_parse_js_message(msg);

        assert!(result.is_some(), "Dotted stream names should still work");
        let parsed = result.unwrap();
        assert_eq!(parsed.delivered, 1);
        assert_eq!(parsed.sequence, 42);
    }
}
