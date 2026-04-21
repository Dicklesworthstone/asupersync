#![allow(clippy::all)]
//! KIP-98 RecordBatch v2 test vectors for conformance testing.

use super::format::*;

/// Test vector for KIP-98 RecordBatch v2 format.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Kip98TestVector {
    pub id: &'static str,
    pub description: &'static str,
    pub record_batch: RecordBatchV2,
    pub expected_encoded: &'static [u8],
    pub requirement_level: RequirementLevel,
}

/// Requirement level for conformance testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

/// Test vector for basic record batch with no compression.
#[allow(dead_code)]
pub fn basic_record_batch_no_compression() -> Kip98TestVector {
    let mut batch = RecordBatchV2::new(0, 12345, 0, 0).with_base_timestamp(1234567890000);

    let record = RecordV2::new(Some(b"test-key".to_vec()), Some(b"test-value".to_vec()))
        .with_timestamp_delta(0)
        .with_offset_delta(0);

    batch.add_record(record);

    Kip98TestVector {
        id: "KIP98-BASIC-NO-COMPRESSION",
        description: "Basic RecordBatch v2 with single record, no compression",
        record_batch: batch,
        // This would be filled with actual encoded bytes from librdkafka
        expected_encoded: &[],
        requirement_level: RequirementLevel::Must,
    }
}

/// Test vector for transactional record batch.
#[allow(dead_code)]
pub fn transactional_record_batch() -> Kip98TestVector {
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

    Kip98TestVector {
        id: "KIP98-TRANSACTIONAL",
        description: "Transactional RecordBatch v2 with multiple records",
        record_batch: batch,
        expected_encoded: &[],
        requirement_level: RequirementLevel::Must,
    }
}

/// Test vector for control record batch.
#[allow(dead_code)]
pub fn control_record_batch() -> Kip98TestVector {
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

    Kip98TestVector {
        id: "KIP98-CONTROL-RECORD",
        description: "Control RecordBatch v2 for transaction commit/abort",
        record_batch: batch,
        expected_encoded: &[],
        requirement_level: RequirementLevel::Must,
    }
}

/// Test vector for record with headers.
#[allow(dead_code)]
pub fn record_with_headers() -> Kip98TestVector {
    let mut batch = RecordBatchV2::new(50, 11111, 0, 5).with_base_timestamp(1234567890000);

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

    Kip98TestVector {
        id: "KIP98-HEADERS",
        description: "RecordBatch v2 with record headers",
        record_batch: batch,
        expected_encoded: &[],
        requirement_level: RequirementLevel::Should,
    }
}

/// Test vector for compressed record batch.
#[allow(dead_code)]
pub fn compressed_record_batch_gzip() -> Kip98TestVector {
    let mut batch = RecordBatchV2::new(75, 22222, 1, 20)
        .with_base_timestamp(1234567890000)
        .with_attributes(RecordAttribute::new().with_compression(1)); // GZIP

    for i in 0..5 {
        let record = RecordV2::new(
            Some(format!("key-{}", i).into_bytes()),
            Some(
                format!(
                    "This is a longer value for record {} to test compression efficiency",
                    i
                )
                .into_bytes(),
            ),
        )
        .with_timestamp_delta(i * 10)
        .with_offset_delta(i as i32);

        batch.add_record(record);
    }

    Kip98TestVector {
        id: "KIP98-GZIP-COMPRESSION",
        description: "RecordBatch v2 with GZIP compression",
        record_batch: batch,
        expected_encoded: &[],
        requirement_level: RequirementLevel::Should,
    }
}

/// Test vector for timestamp delta encoding.
#[allow(dead_code)]
pub fn timestamp_delta_encoding() -> Kip98TestVector {
    let base_timestamp = 1234567890000i64;
    let mut batch = RecordBatchV2::new(300, 33333, 0, 100).with_base_timestamp(base_timestamp);

    // Create records with various timestamp deltas to test varint encoding
    let timestamp_deltas = [0, 1, 127, 128, 16383, 16384, 2097151, 2097152];

    for (i, &delta) in timestamp_deltas.iter().enumerate() {
        let record = RecordV2::new(
            Some(format!("key-{}", i).into_bytes()),
            Some(format!("value-{}", i).into_bytes()),
        )
        .with_timestamp_delta(delta)
        .with_offset_delta(i as i32);

        batch.add_record(record);
    }

    Kip98TestVector {
        id: "KIP98-TIMESTAMP-DELTA",
        description: "RecordBatch v2 testing timestamp delta varint encoding",
        record_batch: batch,
        expected_encoded: &[],
        requirement_level: RequirementLevel::Must,
    }
}

/// Test vector for null key and value.
#[allow(dead_code)]
pub fn null_key_value_record() -> Kip98TestVector {
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

    Kip98TestVector {
        id: "KIP98-NULL-KEY-VALUE",
        description: "RecordBatch v2 with null keys and values",
        record_batch: batch,
        expected_encoded: &[],
        requirement_level: RequirementLevel::Must,
    }
}

/// Test vector for producer ID/epoch/sequence validation.
#[allow(dead_code)]
pub fn producer_id_epoch_sequence() -> Kip98TestVector {
    let mut batch = RecordBatchV2::new(500, 9223372036854775807i64, 32767, 2147483647)
        .with_base_timestamp(1234567890000);

    let record = RecordV2::new(
        Some(b"exactly-once-key".to_vec()),
        Some(b"exactly-once-value".to_vec()),
    )
    .with_timestamp_delta(0)
    .with_offset_delta(0);

    batch.add_record(record);

    Kip98TestVector {
        id: "KIP98-PRODUCER-ID-EPOCH-SEQ",
        description: "RecordBatch v2 with maximum producer ID, epoch, and sequence values",
        record_batch: batch,
        expected_encoded: &[],
        requirement_level: RequirementLevel::Must,
    }
}

/// Test vector for base_offset and last_offset_delta relationship.
#[allow(dead_code)]
pub fn offset_relationship() -> Kip98TestVector {
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

    // Verify last_offset_delta is correctly set to 9 (10 records, 0-indexed)
    assert_eq!(batch.last_offset_delta, 9);

    Kip98TestVector {
        id: "KIP98-OFFSET-RELATIONSHIP",
        description: "RecordBatch v2 testing base_offset and last_offset_delta relationship",
        record_batch: batch,
        expected_encoded: &[],
        requirement_level: RequirementLevel::Must,
    }
}

/// Test vector for LogAppendTime timestamp type.
#[allow(dead_code)]
pub fn log_append_time_timestamp() -> Kip98TestVector {
    let mut batch = RecordBatchV2::new(600, 66666, 0, 0).with_base_timestamp(1234567890000);

    let record = RecordV2::new(
        Some(b"append-time-key".to_vec()),
        Some(b"append-time-value".to_vec()),
    )
    .with_timestamp_delta(0)
    .with_offset_delta(0)
    .with_attributes(RecordAttribute::new().with_timestamp_type(TimestampType::LogAppendTime));

    batch.add_record(record);

    // Batch attributes should also reflect LogAppendTime
    batch.attributes = batch
        .attributes
        .with_timestamp_type(TimestampType::LogAppendTime);

    Kip98TestVector {
        id: "KIP98-LOG-APPEND-TIME",
        description: "RecordBatch v2 with LogAppendTime timestamp type",
        record_batch: batch,
        expected_encoded: &[],
        requirement_level: RequirementLevel::Should,
    }
}

/// Get all test vectors for the conformance test suite.
#[allow(dead_code)]
pub fn all_test_vectors() -> Vec<Kip98TestVector> {
    vec![
        basic_record_batch_no_compression(),
        transactional_record_batch(),
        control_record_batch(),
        record_with_headers(),
        compressed_record_batch_gzip(),
        timestamp_delta_encoding(),
        null_key_value_record(),
        producer_id_epoch_sequence(),
        offset_relationship(),
        log_append_time_timestamp(),
    ]
}

/// Test vectors specifically for edge cases and boundary conditions.
#[allow(dead_code)]
pub fn edge_case_test_vectors() -> Vec<Kip98TestVector> {
    vec![
        producer_id_epoch_sequence(), // Max values
        null_key_value_record(),      // Null handling
        timestamp_delta_encoding(),   // Varint edge cases
    ]
}

/// Test vectors for MUST requirements per KIP-98.
#[allow(dead_code)]
pub fn must_requirement_test_vectors() -> Vec<Kip98TestVector> {
    all_test_vectors()
        .into_iter()
        .filter(|tv| tv.requirement_level == RequirementLevel::Must)
        .collect()
}
