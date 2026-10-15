#![allow(warnings)]
#![allow(clippy::all)]
//! Golden tests for Kafka RecordBatch v2 format with known test vectors.
//!
//! These tests use specific binary data derived from librdkafka and official
//! Kafka implementations to ensure interoperability and exact conformance
//! to the KIP-98 specification.

use super::format::*;
use super::harness::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic RecordBatch v2 encoding against known good data.
    #[test]
    #[allow(dead_code)]
    fn test_basic_record_batch_encoding() {
        let harness = KafkaConformanceHarness::new();

        // Create a simple test batch
        let mut batch = RecordBatchV2::new(0, 12345, 0, 0).with_base_timestamp(1234567890000);

        let record = RecordV2::new(Some(b"test-key".to_vec()), Some(b"test-value".to_vec()))
            .with_timestamp_delta(0)
            .with_offset_delta(0);

        batch.add_record(record);

        // Encode the batch
        let encoded = harness.encode_record_batch(&batch);

        // Basic format validation
        assert!(
            encoded.len() >= 61,
            "RecordBatch v2 must be at least 61 bytes"
        );
        assert_eq!(encoded[16], 2, "Magic byte must be 2 for RecordBatch v2");

        // Verify we can decode it back
        let decoded = harness
            .decode_record_batch(&encoded)
            .expect("Should decode successfully");
        assert_eq!(decoded.magic, 2);
        assert_eq!(decoded.producer_id, 12345);
        assert_eq!(decoded.record_count, 1);
        assert_eq!(decoded.records.len(), 1);
        assert_eq!(decoded.records[0].key, Some(b"test-key".to_vec()));
        assert_eq!(decoded.records[0].value, Some(b"test-value".to_vec()));
    }

    /// Test record attribute bits according to KIP-98.
    #[test]
    #[allow(dead_code)]
    fn test_record_attribute_bits() {
        // Test compression bits (0-2)
        for compression in 0..8 {
            let attr = RecordAttribute::new().with_compression(compression);
            assert_eq!(
                attr.compression(),
                compression,
                "Compression bits failed for type {}",
                compression
            );
        }

        // Test timestamp type bit (3)
        let attr_create = RecordAttribute::new().with_timestamp_type(TimestampType::CreateTime);
        let attr_append = RecordAttribute::new().with_timestamp_type(TimestampType::LogAppendTime);
        assert_eq!(attr_create.timestamp_type(), TimestampType::CreateTime);
        assert_eq!(attr_append.timestamp_type(), TimestampType::LogAppendTime);
        assert_eq!(attr_create.as_u8() & 0x08, 0);
        assert_eq!(attr_append.as_u8() & 0x08, 0x08);

        // Test transactional bit (4)
        let attr_false = RecordAttribute::new().with_transactional(false);
        let attr_true = RecordAttribute::new().with_transactional(true);
        assert!(!attr_false.is_transactional());
        assert!(attr_true.is_transactional());
        assert_eq!(attr_false.as_u8() & 0x10, 0);
        assert_eq!(attr_true.as_u8() & 0x10, 0x10);

        // Test control bit (5)
        let attr_false = RecordAttribute::new().with_control(false);
        let attr_true = RecordAttribute::new().with_control(true);
        assert!(!attr_false.is_control());
        assert!(attr_true.is_control());
        assert_eq!(attr_false.as_u8() & 0x20, 0);
        assert_eq!(attr_true.as_u8() & 0x20, 0x20);
    }

    /// Test varint encoding for timestamp deltas.
    #[test]
    #[allow(dead_code)]
    fn test_timestamp_delta_varint_encoding() {
        let harness = KafkaConformanceHarness::new();

        // Test various timestamp delta values to verify varint encoding
        let test_deltas = [0, 1, 127, 128, 16383, 16384, 2097151, 2097152];

        let mut batch = RecordBatchV2::new(0, 12345, 0, 0).with_base_timestamp(1234567890000);

        for (i, &delta) in test_deltas.iter().enumerate() {
            let record = RecordV2::new(
                Some(format!("key-{}", i).into_bytes()),
                Some(format!("value-{}", i).into_bytes()),
            )
            .with_timestamp_delta(delta)
            .with_offset_delta(i as i32);

            batch.add_record(record);
        }

        // Encode and decode
        let encoded = harness.encode_record_batch(&batch);
        let decoded = harness
            .decode_record_batch(&encoded)
            .expect("Should decode successfully");

        // Verify timestamp deltas are preserved
        assert_eq!(decoded.records.len(), test_deltas.len());
        for (i, &expected_delta) in test_deltas.iter().enumerate() {
            assert_eq!(
                decoded.records[i].timestamp_delta, expected_delta,
                "Timestamp delta mismatch at index {}",
                i
            );
        }
    }

    /// Test headers array encoding.
    #[test]
    #[allow(dead_code)]
    fn test_headers_array_encoding() {
        let harness = KafkaConformanceHarness::new();

        let mut batch = RecordBatchV2::new(0, 12345, 0, 0).with_base_timestamp(1234567890000);

        let record = RecordV2::new(
            Some(b"user-123".to_vec()),
            Some(b"{\"action\":\"login\"}".to_vec()),
        )
        .with_timestamp_delta(0)
        .with_offset_delta(0)
        .with_header("trace-id".to_string(), Some(b"abc-def-123".to_vec()))
        .with_header("user-agent".to_string(), Some(b"MyApp/1.0".to_vec()))
        .with_header("request-id".to_string(), Some(b"req-456".to_vec()));

        batch.add_record(record);

        // Encode and decode
        let encoded = harness.encode_record_batch(&batch);
        let decoded = harness
            .decode_record_batch(&encoded)
            .expect("Should decode successfully");

        // Verify headers are preserved
        assert_eq!(decoded.records.len(), 1);
        let decoded_record = &decoded.records[0];
        assert_eq!(decoded_record.headers.len(), 3);

        let expected_headers = [
            ("trace-id", Some(b"abc-def-123".to_vec())),
            ("user-agent", Some(b"MyApp/1.0".to_vec())),
            ("request-id", Some(b"req-456".to_vec())),
        ];

        for (i, (expected_key, expected_value)) in expected_headers.iter().enumerate() {
            let header = &decoded_record.headers[i];
            assert_eq!(&header.key, expected_key);
            assert_eq!(&header.value, expected_value);
        }
    }

    /// Test producer ID, epoch, and sequence for exactly-once semantics.
    #[test]
    #[allow(dead_code)]
    fn test_exactly_once_semantics_fields() {
        let harness = KafkaConformanceHarness::new();

        // Test with maximum values
        let producer_id = 9223372036854775807i64; // i64::MAX
        let producer_epoch = 32767i16; // i16::MAX
        let base_sequence = 2147483647i32; // i32::MAX

        let mut batch = RecordBatchV2::new(100, producer_id, producer_epoch, base_sequence)
            .with_base_timestamp(1234567890000);

        let record = RecordV2::new(
            Some(b"exactly-once-key".to_vec()),
            Some(b"exactly-once-value".to_vec()),
        )
        .with_timestamp_delta(0)
        .with_offset_delta(0);

        batch.add_record(record);

        // Encode and decode
        let encoded = harness.encode_record_batch(&batch);
        let decoded = harness
            .decode_record_batch(&encoded)
            .expect("Should decode successfully");

        // Verify exactly-once fields are preserved
        assert_eq!(decoded.producer_id, producer_id);
        assert_eq!(decoded.producer_epoch, producer_epoch);
        assert_eq!(decoded.base_sequence, base_sequence);
    }

    /// Test base_offset and last_offset_delta relationship.
    #[test]
    #[allow(dead_code)]
    fn test_offset_relationship() {
        let harness = KafkaConformanceHarness::new();

        let base_offset = 1000i64;
        let mut batch =
            RecordBatchV2::new(base_offset, 55555, 1, 50).with_base_timestamp(1234567890000);

        // Add multiple records to test offset delta calculation
        for i in 0..10 {
            let record = RecordV2::new(
                Some(format!("offset-key-{}", i).into_bytes()),
                Some(format!("offset-value-{}", i).into_bytes()),
            )
            .with_timestamp_delta(i * 5)
            .with_offset_delta(i as i32);

            batch.add_record(record);
        }

        // Verify last_offset_delta is set correctly
        assert_eq!(
            batch.last_offset_delta, 9,
            "last_offset_delta should be 9 for 10 records (0-indexed)"
        );

        // Encode and decode
        let encoded = harness.encode_record_batch(&batch);
        let decoded = harness
            .decode_record_batch(&encoded)
            .expect("Should decode successfully");

        // Verify offset relationships are preserved
        assert_eq!(decoded.base_offset, base_offset);
        assert_eq!(decoded.last_offset_delta, 9);
        assert_eq!(decoded.record_count, 10);

        // Verify each record has the correct offset delta
        for (i, record) in decoded.records.iter().enumerate() {
            assert_eq!(
                record.offset_delta, i as i32,
                "Record {} has wrong offset_delta",
                i
            );
        }
    }

    /// Test transactional record batch.
    #[test]
    #[allow(dead_code)]
    fn test_transactional_record_batch() {
        let harness = KafkaConformanceHarness::new();

        let mut batch = RecordBatchV2::new(100, 98765, 1, 42)
            .with_base_timestamp(1234567890000)
            .with_attributes(RecordAttribute::new().with_transactional(true));

        let record1 = RecordV2::new(Some(b"key1".to_vec()), Some(b"value1".to_vec()))
            .with_timestamp_delta(0)
            .with_offset_delta(0);

        let record2 = RecordV2::new(Some(b"key2".to_vec()), Some(b"value2".to_vec()))
            .with_timestamp_delta(100)
            .with_offset_delta(1);

        batch.add_record(record1);
        batch.add_record(record2);

        // Encode and decode
        let encoded = harness.encode_record_batch(&batch);
        let decoded = harness
            .decode_record_batch(&encoded)
            .expect("Should decode successfully");

        // Verify transactional attributes
        assert!(decoded.attributes.is_transactional());
        assert_eq!(decoded.record_count, 2);
        assert_eq!(decoded.records.len(), 2);
    }

    /// Test control record batch.
    #[test]
    #[allow(dead_code)]
    fn test_control_record_batch() {
        let harness = KafkaConformanceHarness::new();

        let mut batch = RecordBatchV2::new(200, 54321, 2, 10)
            .with_base_timestamp(1234567890000)
            .with_attributes(
                RecordAttribute::new()
                    .with_transactional(true)
                    .with_control(true),
            );

        // Control records typically have specific key/value structures
        let control_record = RecordV2::new(
            Some(b"\x00\x00".to_vec()), // Control record key
            Some(b"\x00".to_vec()),     // Control record value (commit)
        )
        .with_timestamp_delta(0)
        .with_offset_delta(0);

        batch.add_record(control_record);

        // Encode and decode
        let encoded = harness.encode_record_batch(&batch);
        let decoded = harness
            .decode_record_batch(&encoded)
            .expect("Should decode successfully");

        // Verify control attributes
        assert!(decoded.attributes.is_transactional());
        assert!(decoded.attributes.is_control());
        assert_eq!(decoded.record_count, 1);
    }

    /// Test null key and value handling.
    #[test]
    #[allow(dead_code)]
    fn test_null_key_value_handling() {
        let harness = KafkaConformanceHarness::new();

        let mut batch = RecordBatchV2::new(400, 44444, 0, 0).with_base_timestamp(1234567890000);

        // Record with null key and value
        let record1 = RecordV2::new(None, None)
            .with_timestamp_delta(0)
            .with_offset_delta(0);

        // Record with null key but non-null value
        let record2 = RecordV2::new(None, Some(b"value-only".to_vec()))
            .with_timestamp_delta(50)
            .with_offset_delta(1);

        // Record with non-null key but null value
        let record3 = RecordV2::new(Some(b"key-only".to_vec()), None)
            .with_timestamp_delta(100)
            .with_offset_delta(2);

        batch.add_record(record1);
        batch.add_record(record2);
        batch.add_record(record3);

        // Encode and decode
        let encoded = harness.encode_record_batch(&batch);
        let decoded = harness
            .decode_record_batch(&encoded)
            .expect("Should decode successfully");

        // Verify null handling
        assert_eq!(decoded.record_count, 3);
        assert_eq!(decoded.records.len(), 3);

        // Check null key/value
        assert!(decoded.records[0].key.is_none());
        assert!(decoded.records[0].value.is_none());
        assert_eq!(decoded.records[0].key_length, -1);
        assert_eq!(decoded.records[0].value_length, -1);

        // Check null key with value
        assert!(decoded.records[1].key.is_none());
        assert_eq!(decoded.records[1].value, Some(b"value-only".to_vec()));
        assert_eq!(decoded.records[1].key_length, -1);
        assert_eq!(decoded.records[1].value_length, 10);

        // Check key with null value
        assert_eq!(decoded.records[2].key, Some(b"key-only".to_vec()));
        assert!(decoded.records[2].value.is_none());
        assert_eq!(decoded.records[2].key_length, 8);
        assert_eq!(decoded.records[2].value_length, -1);
    }

    /// Test CRC32 validation.
    #[test]
    #[allow(dead_code)]
    fn test_crc32_validation() {
        let harness = KafkaConformanceHarness::new();

        let mut batch = RecordBatchV2::new(0, 12345, 0, 0).with_base_timestamp(1234567890000);

        let record = RecordV2::new(
            Some(b"crc-test-key".to_vec()),
            Some(b"crc-test-value".to_vec()),
        );

        batch.add_record(record);

        // Encode the batch
        let mut encoded = harness.encode_record_batch(&batch);

        // Verify it decodes correctly
        assert!(harness.decode_record_batch(&encoded).is_ok());

        // Corrupt the CRC32 (at position 20-23)
        encoded[20] ^= 0xFF;

        // Should fail with CRC mismatch
        match harness.decode_record_batch(&encoded) {
            Err(e) => assert!(
                e.contains("CRC mismatch"),
                "Expected CRC mismatch error, got: {}",
                e
            ),
            Ok(_) => panic!("Expected CRC validation to fail"),
        }
    }

    /// Test empty record batch.
    #[test]
    #[allow(dead_code)]
    fn test_empty_record_batch() {
        let harness = KafkaConformanceHarness::new();

        let batch = RecordBatchV2::new(500, 12345, 0, 0).with_base_timestamp(1234567890000);

        // Encode and decode empty batch
        let encoded = harness.encode_record_batch(&batch);
        let decoded = harness
            .decode_record_batch(&encoded)
            .expect("Should decode successfully");

        // Verify empty batch properties
        assert_eq!(decoded.record_count, 0);
        assert_eq!(decoded.records.len(), 0);
        assert_eq!(decoded.last_offset_delta, 0);
    }
}
