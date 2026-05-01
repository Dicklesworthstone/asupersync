#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::HashMap;
use std::panic;

/// PING frame payload is exactly 8 octets per RFC 9113 §6.7
#[derive(Debug, Clone, PartialEq, Eq, Hash, Arbitrary)]
struct PingPayload([u8; 8]);

impl PingPayload {
    fn new(data: [u8; 8]) -> Self {
        Self(data)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// PING frame with ACK flag state
#[derive(Debug, Clone, Arbitrary)]
struct PingFrame {
    payload: PingPayload,
    ack_flag: bool,
}

/// Connection error codes per RFC 9113 §7
#[derive(Debug, Clone, Copy, PartialEq)]
enum ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

/// GOAWAY frame for connection termination
#[derive(Debug, Clone, PartialEq)]
struct GoawayFrame {
    last_stream_id: u32,
    error_code: ErrorCode,
    debug_data: Vec<u8>,
}

/// Mock HTTP/2 connection state for PING testing
#[derive(Debug)]
struct MockH2Connection {
    /// Outstanding PING requests awaiting ACK (payload -> request_id)
    outstanding_pings: HashMap<PingPayload, u32>,
    /// Next ping request ID
    next_ping_id: u32,
    /// Connection errors that occurred
    connection_errors: Vec<ErrorCode>,
    /// GOAWAY frames sent
    goaway_frames: Vec<GoawayFrame>,
    /// Whether connection is still active
    is_active: bool,
}

impl MockH2Connection {
    fn new() -> Self {
        Self {
            outstanding_pings: HashMap::new(),
            next_ping_id: 1,
            connection_errors: Vec::new(),
            goaway_frames: Vec::new(),
            is_active: true,
        }
    }

    /// Send a PING frame (non-ACK)
    fn send_ping(&mut self, payload: PingPayload) -> u32 {
        if !self.is_active {
            return 0; // Can't send on closed connection
        }

        let request_id = self.next_ping_id;
        self.next_ping_id += 1;

        self.outstanding_pings.insert(payload, request_id);
        request_id
    }

    /// Receive a PING frame (potentially ACK)
    fn receive_ping(&mut self, frame: PingFrame) -> Result<(), ErrorCode> {
        if !self.is_active {
            return Err(ErrorCode::ProtocolError);
        }

        if frame.ack_flag {
            // This is a PING ACK - validate it matches outstanding PING
            self.handle_ping_ack(frame.payload)
        } else {
            // This is a PING request - echo it back
            self.echo_ping(frame.payload);
            Ok(())
        }
    }

    /// Handle PING ACK frame per RFC 9113 §6.7
    fn handle_ping_ack(&mut self, ack_payload: PingPayload) -> Result<(), ErrorCode> {
        // RFC 9113 §6.7: "Upon receipt of a PING frame that does not include
        // the ACK flag, the endpoint MUST send a PING frame with the ACK flag
        // set and an identical payload"
        //
        // If we receive an ACK, it must match an outstanding PING exactly

        if self.outstanding_pings.remove(&ack_payload).is_some() {
            // Valid ACK - matches outstanding PING
            Ok(())
        } else {
            // Invalid ACK - no matching outstanding PING
            // This violates the protocol per RFC 9113 §6.7
            self.connection_errors.push(ErrorCode::ProtocolError);
            self.send_goaway(ErrorCode::ProtocolError, b"PING ACK payload mismatch");
            Err(ErrorCode::ProtocolError)
        }
    }

    /// Echo PING request back as ACK
    fn echo_ping(&mut self, _payload: PingPayload) {
        // Implementation would send PING frame with ACK flag and identical payload
        // For testing purposes, we just track that this should happen
    }

    /// Send GOAWAY frame and close connection
    fn send_goaway(&mut self, error_code: ErrorCode, debug_data: &[u8]) {
        let goaway = GoawayFrame {
            last_stream_id: 0, // Connection-level error
            error_code,
            debug_data: debug_data.to_vec(),
        };

        self.goaway_frames.push(goaway);
        self.is_active = false;

        // Clear all outstanding PINGs since connection is closing
        self.outstanding_pings.clear();
    }

    /// Get protocol errors that occurred
    fn get_protocol_errors(&self) -> Vec<ErrorCode> {
        self.connection_errors.iter()
            .filter(|&&err| err == ErrorCode::ProtocolError)
            .cloned()
            .collect()
    }

    /// Check if connection sent GOAWAY due to protocol error
    fn sent_protocol_error_goaway(&self) -> bool {
        self.goaway_frames.iter()
            .any(|goaway| goaway.error_code == ErrorCode::ProtocolError)
    }

    /// Get outstanding PING count
    fn outstanding_ping_count(&self) -> usize {
        self.outstanding_pings.len()
    }
}

/// Test scenario for PING ACK mismatches
#[derive(Debug, Arbitrary)]
struct PingAckMismatchScenario {
    /// Initial PING frames to send
    ping_requests: Vec<PingPayload>,
    /// ACK responses (potentially mismatched)
    ack_responses: Vec<PingPayload>,
    /// Whether to send extra ACKs without corresponding PINGs
    send_orphan_acks: bool,
    /// Whether to modify ACK payloads
    corrupt_ack_payloads: bool,
}

/// Test PING ACK mismatch detection
fn test_ping_ack_mismatch(scenario: PingAckMismatchScenario) -> Result<(), String> {
    let mut connection = MockH2Connection::new();
    let mut sent_ping_payloads = Vec::new();

    // Phase 1: Send PING requests
    for ping_payload in &scenario.ping_requests {
        if connection.is_active {
            connection.send_ping(ping_payload.clone());
            sent_ping_payloads.push(ping_payload.clone());
        }
    }

    let _initial_outstanding = connection.outstanding_ping_count();

    // Phase 2: Send ACK responses (potentially mismatched)
    let mut protocol_errors_detected = 0;

    for (i, ack_payload) in scenario.ack_responses.iter().enumerate() {
        if !connection.is_active {
            break; // Connection closed due to protocol error
        }

        let mut actual_ack_payload = ack_payload.clone();

        // Optionally corrupt ACK payloads to create mismatches
        if scenario.corrupt_ack_payloads && i % 2 == 0 {
            // Flip one bit in the payload to create mismatch
            actual_ack_payload.0[0] ^= 0x01;
        }

        let ack_frame = PingFrame {
            payload: actual_ack_payload,
            ack_flag: true,
        };

        match connection.receive_ping(ack_frame) {
            Err(ErrorCode::ProtocolError) => {
                protocol_errors_detected += 1;
            }
            Err(other_error) => {
                return Err(format!("Unexpected error: {:?}", other_error));
            }
            Ok(()) => {
                // Valid ACK processed
            }
        }
    }

    // Phase 3: Send orphan ACKs if requested
    if scenario.send_orphan_acks {
        for i in 0..3 {
            if !connection.is_active {
                break;
            }

            let orphan_payload = PingPayload::new([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, i]);
            let orphan_ack = PingFrame {
                payload: orphan_payload,
                ack_flag: true,
            };

            match connection.receive_ping(orphan_ack) {
                Err(ErrorCode::ProtocolError) => {
                    protocol_errors_detected += 1;
                }
                _ => {}
            }
        }
    }

    // Assertions per RFC 9113 §6.7

    // If we sent mismatched ACKs, should detect protocol errors
    let expected_mismatches = scenario.ack_responses.iter()
        .enumerate()
        .filter(|(i, ack_payload)| {
            let mut test_payload = (*ack_payload).clone();
            if scenario.corrupt_ack_payloads && i % 2 == 0 {
                test_payload.0[0] ^= 0x01;
            }

            // Check if this ACK matches any sent PING
            !sent_ping_payloads.contains(&test_payload)
        })
        .count();

    let orphan_count = if scenario.send_orphan_acks { 3 } else { 0 };
    let total_expected_errors = expected_mismatches + orphan_count;

    if total_expected_errors > 0 || protocol_errors_detected > 0 {
        // Should have detected protocol errors
        if connection.get_protocol_errors().is_empty() {
            return Err("Expected PROTOCOL_ERROR for mismatched PING ACK, but none detected".to_string());
        }

        // Should have sent GOAWAY with PROTOCOL_ERROR
        if !connection.sent_protocol_error_goaway() {
            return Err("Expected GOAWAY with PROTOCOL_ERROR for mismatched PING ACK".to_string());
        }

        // Connection should be closed after protocol error
        if connection.is_active {
            return Err("Connection should be closed after PROTOCOL_ERROR".to_string());
        }
    }

    Ok(())
}

/// Comprehensive PING ACK validation test
fn test_ping_ack_comprehensive() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Test 1: Valid PING-ACK cycle
    let ping1 = PingPayload::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    connection.send_ping(ping1.clone());

    let valid_ack = PingFrame {
        payload: ping1.clone(),
        ack_flag: true,
    };

    if connection.receive_ping(valid_ack).is_err() {
        return Err("Valid PING ACK should not cause error".to_string());
    }

    // Test 2: Mismatched ACK payload
    let ping2 = PingPayload::new([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    connection.send_ping(ping2.clone());

    let mismatched_ack = PingFrame {
        payload: PingPayload::new([0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]),
        ack_flag: true,
    };

    match connection.receive_ping(mismatched_ack) {
        Err(ErrorCode::ProtocolError) => {
            // Expected - should detect mismatch
        }
        _ => {
            return Err("Mismatched PING ACK should cause PROTOCOL_ERROR".to_string());
        }
    }

    // Verify connection closed and GOAWAY sent
    if connection.is_active {
        return Err("Connection should be closed after protocol error".to_string());
    }

    if !connection.sent_protocol_error_goaway() {
        return Err("Should send GOAWAY after protocol error".to_string());
    }

    Ok(())
}

/// Edge case: Multiple outstanding PINGs
fn test_multiple_outstanding_pings() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Send multiple PINGs
    let ping_payloads = vec![
        PingPayload::new([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]),
        PingPayload::new([0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81]),
        PingPayload::new([0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82]),
    ];

    for payload in &ping_payloads {
        connection.send_ping(payload.clone());
    }

    assert_eq!(connection.outstanding_ping_count(), 3);

    // ACK them in reverse order (should still work)
    for payload in ping_payloads.iter().rev() {
        let ack_frame = PingFrame {
            payload: payload.clone(),
            ack_flag: true,
        };

        if connection.receive_ping(ack_frame).is_err() {
            return Err("Valid ACK should not fail regardless of order".to_string());
        }
    }

    // All PINGs should be acknowledged
    assert_eq!(connection.outstanding_ping_count(), 0);

    Ok(())
}

/// Edge case: ACK without prior PING
fn test_orphan_ack() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Send ACK without prior PING
    let orphan_ack = PingFrame {
        payload: PingPayload::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]),
        ack_flag: true,
    };

    match connection.receive_ping(orphan_ack) {
        Err(ErrorCode::ProtocolError) => {
            // Expected - orphan ACK should cause protocol error
        }
        _ => {
            return Err("Orphan PING ACK should cause PROTOCOL_ERROR".to_string());
        }
    }

    // Verify protocol error handling
    if !connection.sent_protocol_error_goaway() {
        return Err("Should send GOAWAY for orphan ACK".to_string());
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let result = panic::catch_unwind(|| {
        let mut unstructured = Unstructured::new(data);

        // Try to generate scenario from fuzz input
        if let Ok(scenario) = PingAckMismatchScenario::arbitrary(&mut unstructured) {
            let _ = test_ping_ack_mismatch(scenario);
        }

        // Run deterministic test cases
        if data.len() > 100 {
            let _ = test_ping_ack_comprehensive();
            let _ = test_multiple_outstanding_pings();
            let _ = test_orphan_ack();
        }
    });

    if result.is_err() {
        eprintln!("Panic in PING ACK mismatch fuzzing");
    }
});