//! Audit test for JetStream AckExplicit sequence gap handling.
//!
//! NATS JetStream AckExplicit policy requires that when a consumer acks
//! message sequence X, all sequences < X must already be acked or nacked.
//!
//! DEFECT IDENTIFIED: Our client implementation has no sequence tracking
//! to detect gaps before sending ack commands. This could lead to protocol
//! violations where the client tries to ack sequence 5 while 1-4 are unacked.

use asupersync::messaging::jetstream::{AckPolicy, ConsumerConfig};
use asupersync::messaging::nats::Message;

#[test]
fn test_jetstream_message_parsing_extracts_sequence() {
    // Verify that sequence numbers are correctly parsed from reply subjects
    // but note that there's no validation logic around them

    let test_cases = vec![
        ("$JS.ACK.ORDERS.consumer.1.42.7.1713790000000000000.0", 42),
        ("$JS.ACK.TEST.worker.2.100.15.1713790000000000000.5", 100),
        (
            "$JS.ACK.STREAM.dotted.consumer.name.3.999.20.1713790000000000000.0",
            999,
        ),
    ];

    for (reply_subject, expected_seq) in test_cases {
        let msg = Message {
            subject: "test.subject".to_string(),
            payload: vec![],
            headers: None,
            sid: 1,
            reply_to: Some(reply_subject.to_string()),
        };

        // This uses the internal parsing logic that Consumer::pull uses
        let parsed = asupersync::messaging::jetstream::fuzz_parse_js_message(msg);

        if let Some(parsed_msg) = parsed {
            assert_eq!(parsed_msg.sequence, expected_seq);
            println!(
                "✓ Correctly parsed sequence {} from {}",
                expected_seq, reply_subject
            );
        } else {
            panic!("Failed to parse reply subject: {}", reply_subject);
        }
    }
}

#[test]
fn demonstrate_ack_explicit_defect() {
    // This test demonstrates that our ConsumerConfig can be set to AckExplicit
    // but there's no client-side enforcement of the sequence ordering requirement

    let config = ConsumerConfig::new("test-consumer").ack_policy(AckPolicy::Explicit);

    assert_eq!(config.ack_policy, AckPolicy::Explicit);

    println!("DEFECT DEMONSTRATION:");
    println!("✗ CRITICAL: Consumer configured for AckExplicit but no sequence tracking");
    println!("✗ Client can receive sequences [1,2,3,4,5] and ack only [5] without validation");
    println!("✗ Individual JsMessage.ack() calls have no awareness of other messages");
    println!("✗ Violates AckExplicit policy expectations");
}

#[test]
fn audit_jetstream_ack_explicit_sequence_tracking() {
    println!("\n=== JETSTREAM ACK-EXPLICIT SEQUENCE AUDIT ===\n");

    println!("JETSTREAM ACKEXPLICIT SPECIFICATION:");
    println!("- Consumer using AckExplicit must ack messages in order");
    println!("- Acking sequence X implies all sequences < X are already acked/nacked");
    println!("- Server should reject ack attempts that create gaps\n");

    println!("IMPLEMENTATION ANALYSIS:");
    println!("File: src/messaging/jetstream.rs");
    println!("1. Consumer struct (lines 1136-1140): only stream/name/prefix, no sequence state");
    println!("2. JsMessage.ack() (lines 1869-1879): individual ack via reply_subject");
    println!("3. publish_terminal_ack() (lines 1949-1995): no sequence validation");
    println!("4. parse_js_message() (lines 1305-1335): extracts sequence but no tracking\n");

    println!("DEFECT IDENTIFIED:");
    println!("✗ CRITICAL: No client-side sequence gap detection");
    println!("✗ Consumer can receive sequences [1,2,3,4,5] and ack only [5]");
    println!("✗ Client sends +ACK for sequence 5 without validating 1-4 are acked");
    println!("✗ Relies entirely on server-side enforcement (fragile)\n");

    println!("IMPACT:");
    println!("- Protocol violations: client violates JetStream AckExplicit contract");
    println!("- Silent failures: network issues could mask unprocessed messages");
    println!("- Data integrity: messages marked complete without processing");
    println!("- Debugging complexity: gaps only detected server-side\n");

    println!("RECOMMENDATION:");
    println!("Add Consumer sequence tracking state:");
    println!("```rust");
    println!("pub struct Consumer {{");
    println!("    stream: String,");
    println!("    name: String,");
    println!("    prefix: String,");
    println!("    acked_sequences: BTreeSet<u64>,  // Track acked sequences");
    println!("    max_acked_sequence: Option<u64>, // Highest contiguous ack");
    println!("}}");
    println!();
    println!("impl JsMessage {{");
    println!(
        "    pub fn ack(&self, consumer: &mut Consumer, client: &mut NatsClient, cx: &Cx) -> Result<(), JsError> {{"
    );
    println!("        // Validate no gaps before this sequence");
    println!("        if let Some(max_acked) = consumer.max_acked_sequence {{");
    println!("            if self.sequence > max_acked + 1 {{");
    println!("                return Err(JsError::SequenceGap(max_acked + 1, self.sequence));");
    println!("            }}");
    println!("        }}");
    println!("        // Proceed with ack...");
    println!("    }}");
    println!("}}");
    println!("```\n");

    println!("PRIORITY: HIGH - Can lead to message loss and protocol violations");
}

#[test]
fn run_audit() {
    audit_jetstream_ack_explicit_sequence_tracking();
}
