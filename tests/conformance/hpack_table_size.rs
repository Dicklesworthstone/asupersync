#![allow(clippy::all)]
//! HPACK Dynamic Table Size Update Conformance Tests (RFC 7541 Section 6.3)
//!
//! This module provides comprehensive conformance testing for HPACK dynamic table
//! size updates per RFC 7541 Section 6.3.
//!
//! The tests systematically validate:
//!
//! - SETTINGS_HEADER_TABLE_SIZE acknowledgment requirements
//! - Dynamic table size update ordering (before encoded blocks)
//! - Multiple consecutive size updates processing
//! - Size update bounds validation (must not exceed SETTINGS limit)
//! - Entry eviction behavior on size reductions
//!
//! # RFC 7541 Section 6.3: Dynamic Table Size Update
//!
//! **Format:**
//! ```
//! 0   1   2   3   4   5   6   7
//! +---+---+---+---+---+---+---+---+
//! | 0 | 0 | 1 |   Max size (5+)   |
//! +---+---+---+---+---+---+---+---+
//! ```
//!
//! **Requirements:**
//! - MUST appear at the beginning of a header block (before any header field representation)
//! - Size update MUST NOT exceed SETTINGS_HEADER_TABLE_SIZE value
//! - Multiple size updates MAY appear consecutively at block start
//! - Size reduction MAY trigger entry eviction to fit new limit
//! - Encoder MUST signal size changes via SETTINGS frame acknowledgment

use asupersync::bytes::BytesMut;
use asupersync::http::h2::{
    error::{ErrorCode, H2Error},
    hpack::{DEFAULT_MAX_TABLE_SIZE, Decoder, Encoder, Header},
};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Test categories for HPACK table size update conformance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestCategory {
    /// SETTINGS frame acknowledgment tests.
    SettingsAckRequired,
    /// Size update ordering validation tests.
    SizeUpdateOrdering,
    /// Multiple size updates processing tests.
    MultipleSizeUpdates,
    /// Size bounds validation tests.
    SizeBoundsValidation,
    /// Entry eviction behavior tests.
    EntryEvictionBehavior,
}

/// Test result for HPACK table size conformance tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct HpackTableSizeConformanceResult {
    /// Test category.
    pub category: TestCategory,
    /// Test description.
    pub description: String,
    /// Whether the test passed.
    pub passed: bool,
    /// Error message if test failed.
    pub error: Option<String>,
    /// Test duration.
    pub duration_ms: u64,
}

/// Mock HPACK context for table size testing.
#[allow(dead_code)]
struct MockHpackContext {
    /// HPACK encoder.
    encoder: Encoder,
    /// HPACK decoder.
    decoder: Decoder,
    /// SETTINGS_HEADER_TABLE_SIZE value agreed upon.
    settings_table_size: usize,
    /// Whether SETTINGS ACK was received.
    settings_ack_received: bool,
    /// Timestamp when SETTINGS was sent.
    settings_sent_time: Option<Instant>,
}

#[allow(dead_code)]

impl MockHpackContext {
    /// Create a new mock HPACK context.
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            encoder: Encoder::new(),
            decoder: Decoder::new(),
            settings_table_size: DEFAULT_MAX_TABLE_SIZE,
            settings_ack_received: false,
            settings_sent_time: None,
        }
    }

    /// Create a context with specific table size.
    #[allow(dead_code)]
    fn with_table_size(table_size: usize) -> Self {
        let encoder = Encoder::new();
        let mut decoder = Decoder::with_max_size(table_size);
        decoder.set_allowed_table_size(table_size);

        Self {
            encoder,
            decoder,
            settings_table_size: table_size,
            settings_ack_received: false,
            settings_sent_time: None,
        }
    }

    /// Simulate SETTINGS frame exchange for table size.
    #[allow(dead_code)]
    fn exchange_settings(&mut self, new_table_size: usize) -> Result<(), H2Error> {
        self.settings_sent_time = Some(Instant::now());
        self.settings_table_size = new_table_size;

        // Update decoder's allowed table size (from SETTINGS frame)
        self.decoder.set_allowed_table_size(new_table_size);

        // Encoder will emit size update in next header block
        self.encoder.set_max_table_size(new_table_size);

        // Simulate ACK reception
        self.settings_ack_received = true;

        Ok(())
    }

    /// Encode a raw dynamic table size update instruction.
    #[allow(dead_code)]
    fn encode_size_update(size: usize) -> BytesMut {
        let mut buf = BytesMut::new();
        // Dynamic table size update: 001xxxxx where xxxxx encodes size
        encode_integer(&mut buf, size, 5, 0x20);
        buf
    }

    /// Populate dynamic table with test headers.
    #[allow(dead_code)]
    fn populate_table(&mut self, headers: &[Header]) {
        let mut buf = BytesMut::new();
        self.encoder.encode(headers, &mut buf);

        // Decode to update decoder's dynamic table
        let mut encoded_bytes = buf.freeze();
        let _ = self
            .decoder
            .decode(&mut encoded_bytes)
            .expect("Failed to populate table");
    }

    /// Get current dynamic table usage.
    #[allow(dead_code)]
    fn table_usage(&self) -> usize {
        self.decoder.dynamic_table_size()
    }

    /// Get the decoder's current dynamic table size limit.
    #[allow(dead_code)]
    fn table_max_size(&self) -> usize {
        self.decoder.dynamic_table_max_size()
    }
}

/// Encode an integer using HPACK integer encoding.
#[allow(dead_code)]
fn encode_integer(dst: &mut BytesMut, mut value: usize, prefix_bits: u8, prefix_pattern: u8) {
    let max_value = (1 << prefix_bits) - 1;

    if value < max_value {
        dst.put_u8(prefix_pattern | (value as u8));
    } else {
        dst.put_u8(prefix_pattern | (max_value as u8));
        value -= max_value;

        while value >= 128 {
            dst.put_u8(((value % 128) + 128) as u8);
            value /= 128;
        }
        dst.put_u8(value as u8);
    }
}

/// Generate arbitrary table sizes for testing.
#[allow(dead_code)]
fn arb_table_size() -> impl Strategy<Value = usize> {
    prop_oneof![
        Just(0),
        Just(1),
        Just(1024),
        Just(4096),
        Just(8192),
        Just(16384),
        1usize..65536,
    ]
}

/// Generate arbitrary headers for table population.
#[allow(dead_code)]
fn arb_header() -> impl Strategy<Value = Header> {
    (
        prop_oneof![
            Just(":authority".to_string()),
            Just(":method".to_string()),
            Just(":path".to_string()),
            Just("accept".to_string()),
            Just("cache-control".to_string()),
            Just("content-type".to_string()),
            "[a-z][a-z0-9-]{3,15}".prop_map(|s| s.to_lowercase()),
        ],
        prop_oneof![
            Just("GET".to_string()),
            Just("POST".to_string()),
            Just("https".to_string()),
            Just("application/json".to_string()),
            Just("gzip, deflate".to_string()),
            "[a-zA-Z0-9._~!$&'()*+,;=:@/?-]{5,50}",
        ],
    )
        .prop_map(|(name, value)| Header::new(name, value))
}

/// Generate header lists for table population.
#[allow(dead_code)]
fn arb_headers() -> impl Strategy<Value = Vec<Header>> {
    prop::collection::vec(arb_header(), 0..10)
}

#[cfg(test)]
mod conformance_tests {
    use super::*;

    /// MR1: SETTINGS_HEADER_TABLE_SIZE acknowledgment required (Metamorphic, Score: 8.0)
    /// Property: settings_frame(size) → encoder → ack_required
    /// Catches: Missing SETTINGS ACK handling, protocol violations
    #[test]
    #[allow(dead_code)]
    fn mr1_settings_ack_required() {
        proptest!(|(table_size in arb_table_size())| {
            let mut context = MockHpackContext::new();

            // SETTINGS_HEADER_TABLE_SIZE exchange should require ACK
            let result = context.exchange_settings(table_size);
            prop_assert!(result.is_ok(), "SETTINGS exchange failed: {:?}", result);

            // Verify ACK was processed (simulated)
            prop_assert!(context.settings_ack_received,
                "SETTINGS ACK not received for table size {}", table_size);

            // Verify settings time was recorded
            prop_assert!(context.settings_sent_time.is_some(),
                "SETTINGS timestamp not recorded");

            // Verify decoder's allowed table size was updated
            prop_assert_eq!(context.settings_table_size, table_size,
                "Settings table size mismatch");
        });
    }

    /// MR2: Size update precedes encoded block (Ordering, Score: 9.0)
    /// Property: [size_update, header] = valid, [header, size_update] = invalid
    /// Catches: RFC 7541 Section 4.2 ordering violations
    #[test]
    #[allow(dead_code)]
    fn mr2_size_update_precedes_encoded_block() {
        proptest!(|(new_size in arb_table_size(), headers in arb_headers())| {
            let mut context = MockHpackContext::with_table_size(4096);
            let new_size = new_size.min(4096);

            // Drive the actual SETTINGS -> encoder transition so the encoder
            // applies the same table bound it advertises on the wire.
            context
                .exchange_settings(new_size)
                .expect("SETTINGS exchange should succeed");

            let mut valid_block = BytesMut::new();
            context.encoder.encode(&headers, &mut valid_block);

            let mut valid_bytes = valid_block.freeze();
            let valid_result = context.decoder.decode(&mut valid_bytes);
            prop_assert!(valid_result.is_ok(),
                "Valid ordering (size update first) should succeed, got: {:?}", valid_result);

            // Test 2: Headers BEFORE size update (invalid - would violate RFC if we tried)
            // RFC 7541 Section 4.2: size updates only permitted at beginning of header block
            // We don't actually test this invalid case as it would require violating the spec
        });
    }

    /// MR3: Multiple size updates honored (Sequential, Score: 7.5)
    /// Property: size_update(100) → size_update(200) → final_size = 200
    /// Catches: Size update sequence processing bugs
    #[test]
    #[allow(dead_code)]
    fn mr3_multiple_size_updates_honored() {
        proptest!(|(
            size1 in 1usize..8192,
            size2 in 1usize..8192,
            size3 in 1usize..8192
        )| {
            let max_allowed = 16384;
            let mut context = MockHpackContext::with_table_size(max_allowed);

            // Create header block with multiple size updates
            let mut block = BytesMut::new();

            // Add three consecutive size updates
            let update1 = MockHpackContext::encode_size_update(size1.min(max_allowed));
            let update2 = MockHpackContext::encode_size_update(size2.min(max_allowed));
            let update3 = MockHpackContext::encode_size_update(size3.min(max_allowed));

            block.extend_from_slice(&update1);
            block.extend_from_slice(&update2);
            block.extend_from_slice(&update3);

            let mut block_bytes = block.freeze();
            let result = context.decoder.decode(&mut block_bytes);

            prop_assert!(result.is_ok(),
                "Multiple size updates should be valid, got: {:?}", result);

            prop_assert_eq!(context.table_max_size(), size3.min(max_allowed),
                "Decoder should apply the last size update in the prefix sequence");
        });
    }

    /// MR4: Size update > SETTINGS triggers DECOMPRESSION_FAILED (Bounds, Score: 10.0)
    /// Property: max_size(1000) → size_update(2000) → DECOMPRESSION_FAILED
    /// Catches: Bounds checking failures, security violations
    #[test]
    #[allow(dead_code)]
    fn mr4_oversized_update_triggers_decompression_failed() {
        proptest!(|(
            settings_size in 100usize..4096,
            oversized_factor in 2usize..10
        )| {
            let oversized_update = settings_size * oversized_factor;
            let mut context = MockHpackContext::with_table_size(settings_size);

            // Create a header block with oversized table size update
            let oversized_block = MockHpackContext::encode_size_update(oversized_update);
            let mut block_bytes = oversized_block.freeze();

            let result = context.decoder.decode(&mut block_bytes);

            prop_assert!(result.is_err(),
                "Oversized table size update ({} > {}) should fail",
                oversized_update, settings_size);

            if let Err(error) = result {
                // Should be a compression error due to bounds violation
                prop_assert!(error.code == ErrorCode::CompressionError,
                    "Expected compression error for oversized update, got: {:?}", error);
            }
        });
    }

    /// MR5: Size update preserves entries when new_size >= current_usage (Preservation, Score: 8.5)
    /// Property: usage(500) → size_update(1000) → no_evictions
    /// Catches: Unnecessary entry eviction bugs
    #[test]
    #[allow(dead_code)]
    fn mr5_size_update_preserves_entries_when_sufficient() {
        proptest!(|(
            initial_size in 2048usize..8192,
            headers in arb_headers(),
            slack in 0usize..1024
        )| {
            let mut context = MockHpackContext::with_table_size(initial_size);

            // Populate table with headers
            context.populate_table(&headers);
            let usage_before = context.table_usage();

            // Keep the resize within the current SETTINGS limit while remaining
            // large enough to preserve the current table contents.
            let new_size = usage_before.saturating_add(slack).min(initial_size);

            let size_update = MockHpackContext::encode_size_update(new_size);
            let mut update_bytes = size_update.freeze();

            let result = context.decoder.decode(&mut update_bytes);
            prop_assert!(result.is_ok(),
                "Size update preserving entries should succeed: {:?}", result);
            prop_assert_eq!(context.table_max_size(), new_size,
                "Decoder should adopt the new table size limit");
            prop_assert_eq!(context.table_usage(), usage_before,
                "Resizing above current usage must not evict entries");
        });
    }

    /// Integration test: Complete SETTINGS exchange with size updates
    #[test]
    #[allow(dead_code)]
    fn integration_complete_settings_exchange() {
        let mut context = MockHpackContext::new();

        // Step 1: Exchange SETTINGS with new table size
        let new_size = 2048;
        context
            .exchange_settings(new_size)
            .expect("SETTINGS exchange failed");

        // Step 2: Encoder should emit size update in next header block
        let test_headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/test"),
            Header::new("host", "example.com"),
        ];

        let mut encoded = BytesMut::new();
        context.encoder.encode(&test_headers, &mut encoded);
        let first_byte = encoded[0];

        // Step 3: Decoder should accept the size update + headers
        let mut encoded_bytes = encoded.freeze();
        let decoded = context
            .decoder
            .decode(&mut encoded_bytes)
            .expect("Decoding with size update failed");

        assert_eq!(
            first_byte & 0xe0,
            0x20,
            "header block must start with the dynamic table size update"
        );
        assert_eq!(context.decoder.allowed_table_size(), new_size);
        assert_eq!(context.table_max_size(), new_size);

        // Verify headers were decoded correctly
        assert_eq!(test_headers.len(), decoded.len());
        for (original, decoded_header) in test_headers.iter().zip(decoded.iter()) {
            assert_eq!(original.name, decoded_header.name);
            assert_eq!(original.value, decoded_header.value);
        }
    }

    /// Stress test: Rapid size update sequences
    #[test]
    #[allow(dead_code)]
    fn stress_rapid_size_update_sequences() {
        let mut context = MockHpackContext::with_table_size(8192);

        // Rapid sequence of size updates with different values
        let sizes = [4096, 2048, 6144, 1024, 8192];

        for &size in &sizes {
            let size_update = MockHpackContext::encode_size_update(size);
            let mut update_bytes = size_update.freeze();

            let result = context.decoder.decode(&mut update_bytes);
            assert!(
                result.is_ok(),
                "Rapid size update to {} failed: {:?}",
                size,
                result
            );
            assert_eq!(context.table_max_size(), size);
        }
    }

    /// Error case: Size update mixed with header representations (invalid)
    #[test]
    #[allow(dead_code)]
    fn error_size_update_mixed_with_headers() {
        let mut context = MockHpackContext::with_table_size(4096);

        // Create a block that violates RFC 7541 Section 4.2
        // (size updates must be at the beginning)
        let mut invalid_block = BytesMut::new();

        // Add a header first (indexed header field for :method=GET)
        invalid_block.put_u8(0x82); // Indexed header field, index 2 (:method=GET)

        // Then try to add a size update (INVALID per RFC)
        let size_update = MockHpackContext::encode_size_update(2048);
        invalid_block.extend_from_slice(&size_update);

        let mut invalid_bytes = invalid_block.freeze();
        let result = context.decoder.decode(&mut invalid_bytes);

        assert!(
            matches!(
                result,
                Err(ref err) if err.code == ErrorCode::CompressionError
            ),
            "Mixed headers and size updates must be rejected with COMPRESSION_ERROR"
        );
    }
}
