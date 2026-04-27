#![allow(warnings)]
#![allow(clippy::all)]
//! QUIC Stream ID parity conformance tests.
//!
//! Tests RFC 9000 Section 3.3 bidirectional stream ID requirements:
//! client even, server odd, stream ID space exhaustion, MAX_STREAMS enforcement.

use super::*;

/// Run all Stream ID parity conformance tests.
#[allow(dead_code)]
pub fn run_stream_id_parity_tests() -> Vec<QuicConformanceResult> {
    let mut results = Vec::new();

    results.push(test_stream_id_parity_client_even());
    results.push(test_stream_id_parity_server_odd());
    results.push(test_stream_id_space_exhaustion());
    results.push(test_max_streams_frame_enforcement());
    results.push(test_unidirectional_stream_ids());

    results
}

/// RFC 9000 Section 3.3: Client-initiated streams must use even IDs.
#[allow(dead_code)]
fn test_stream_id_parity_client_even() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let client_stream_ids = vec![0, 4, 8, 12, 16]; // Even IDs
        let invalid_client_ids = vec![1, 5, 9, 13]; // Odd IDs (invalid for client)

        // Test valid client stream IDs
        for &stream_id in &client_stream_ids {
            if !is_valid_client_bidi_stream_id(stream_id) {
                return Err(format!("Valid client stream ID {} was rejected", stream_id));
            }
        }

        // Test invalid client stream IDs
        for &stream_id in &invalid_client_ids {
            if is_valid_client_bidi_stream_id(stream_id) {
                return Err(format!("Invalid client stream ID {} was accepted", stream_id));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-3.3-CLIENT-EVEN-IDS",
        "Client-initiated streams must use even stream IDs",
        TestCategory::StreamIdParity,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 3.3: Server-initiated streams must use odd IDs.
#[allow(dead_code)]
fn test_stream_id_parity_server_odd() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let server_stream_ids = vec![1, 5, 9, 13, 17]; // Odd IDs
        let invalid_server_ids = vec![0, 4, 8, 12]; // Even IDs (invalid for server)

        // Test valid server stream IDs
        for &stream_id in &server_stream_ids {
            if !is_valid_server_bidi_stream_id(stream_id) {
                return Err(format!("Valid server stream ID {} was rejected", stream_id));
            }
        }

        // Test invalid server stream IDs
        for &stream_id in &invalid_server_ids {
            if is_valid_server_bidi_stream_id(stream_id) {
                return Err(format!("Invalid server stream ID {} was accepted", stream_id));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-3.3-SERVER-ODD-IDS",
        "Server-initiated streams must use odd stream IDs",
        TestCategory::StreamIdParity,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 3.3: Stream ID space exhaustion handling.
#[allow(dead_code)]
fn test_stream_id_space_exhaustion() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test approaching stream ID space limits
        let max_stream_id = (1u64 << 62) - 4; // Near maximum for bidirectional

        // Should be able to create streams up to limit
        if !is_valid_stream_id_within_limits(max_stream_id - 4, 1000) {
            return Err("Stream ID within limits should be valid".to_string());
        }

        // Should reject stream IDs exceeding space
        if is_valid_stream_id_within_limits(max_stream_id + 4, 1000) {
            return Err("Stream ID exceeding space should be rejected".to_string());
        }

        // Test MAX_STREAMS limit enforcement
        let max_concurrent_streams = 100;
        if !is_within_max_streams_limit(50, max_concurrent_streams) {
            return Err("Stream count within limit should be allowed".to_string());
        }

        if is_within_max_streams_limit(150, max_concurrent_streams) {
            return Err("Stream count exceeding limit should be rejected".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-3.3-STREAM-ID-EXHAUSTION",
        "Stream ID space exhaustion and limits",
        TestCategory::StreamIdParity,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 4.6: MAX_STREAMS frame enforcement.
#[allow(dead_code)]
fn test_max_streams_frame_enforcement() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut stream_manager = StreamManager::new();

        // Set initial limit
        stream_manager.set_max_bidi_streams(10);

        // Should allow opening streams within limit
        for i in 0..10 {
            if !stream_manager.can_open_bidi_stream(i * 4) {
                return Err(format!("Should allow opening stream {} within limit", i * 4));
            }
        }

        // Should reject opening streams beyond limit
        if stream_manager.can_open_bidi_stream(40) {
            return Err("Should reject opening stream beyond MAX_STREAMS limit".to_string());
        }

        // Receive MAX_STREAMS frame to increase limit
        stream_manager.process_max_streams_frame(20, true); // 20 bidi streams

        // Now should allow more streams
        if !stream_manager.can_open_bidi_stream(40) {
            return Err("Should allow opening stream after MAX_STREAMS increase".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-4.6-MAX-STREAMS-ENFORCEMENT",
        "MAX_STREAMS frame enforcement and limit updates",
        TestCategory::StreamIdParity,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 3.3: Unidirectional stream ID validation.
#[allow(dead_code)]
fn test_unidirectional_stream_ids() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Unidirectional streams have different ID pattern (+ 2 from bidi)
        let client_uni_ids = vec![2, 6, 10, 14]; // Client unidirectional
        let server_uni_ids = vec![3, 7, 11, 15]; // Server unidirectional

        // Test client unidirectional stream IDs
        for &stream_id in &client_uni_ids {
            if !is_valid_client_uni_stream_id(stream_id) {
                return Err(format!("Valid client uni stream ID {} was rejected", stream_id));
            }
        }

        // Test server unidirectional stream IDs
        for &stream_id in &server_uni_ids {
            if !is_valid_server_uni_stream_id(stream_id) {
                return Err(format!("Valid server uni stream ID {} was rejected", stream_id));
            }
        }

        // Test invalid unidirectional IDs
        if is_valid_client_uni_stream_id(1) { // Server bidi ID
            return Err("Server bidi ID should not be valid for client uni".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-3.3-UNIDIRECTIONAL-IDS",
        "Unidirectional stream ID validation",
        TestCategory::StreamIdParity,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

// Helper types and functions

struct StreamManager {
    max_bidi_streams: u64,
    max_uni_streams: u64,
    open_bidi_streams: u64,
    open_uni_streams: u64,
}

impl StreamManager {
    fn new() -> Self {
        Self {
            max_bidi_streams: 0,
            max_uni_streams: 0,
            open_bidi_streams: 0,
            open_uni_streams: 0,
        }
    }

    fn set_max_bidi_streams(&mut self, max: u64) {
        self.max_bidi_streams = max;
    }

    fn can_open_bidi_stream(&self, stream_id: u64) -> bool {
        let stream_number = stream_id / 4;
        stream_number < self.max_bidi_streams
    }

    fn process_max_streams_frame(&mut self, max_streams: u64, is_bidi: bool) {
        if is_bidi {
            self.max_bidi_streams = max_streams;
        } else {
            self.max_uni_streams = max_streams;
        }
    }
}

fn is_valid_client_bidi_stream_id(stream_id: u64) -> bool {
    (stream_id % 4) == 0 // Client-initiated bidirectional
}

fn is_valid_server_bidi_stream_id(stream_id: u64) -> bool {
    (stream_id % 4) == 1 // Server-initiated bidirectional
}

fn is_valid_client_uni_stream_id(stream_id: u64) -> bool {
    (stream_id % 4) == 2 // Client-initiated unidirectional
}

fn is_valid_server_uni_stream_id(stream_id: u64) -> bool {
    (stream_id % 4) == 3 // Server-initiated unidirectional
}

fn is_valid_stream_id_within_limits(stream_id: u64, max_concurrent: u64) -> bool {
    stream_id < (1u64 << 62) && (stream_id / 4) < max_concurrent
}

fn is_within_max_streams_limit(stream_count: u64, max_streams: u64) -> bool {
    stream_count <= max_streams
}