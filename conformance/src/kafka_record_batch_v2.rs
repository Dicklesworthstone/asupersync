//! Kafka RecordBatch v2 conformance tests per KIP-98.
//!
//! This module provides conformance tests for Kafka producer RecordBatch v2 format
//! to ensure compatibility with the Kafka wire protocol specification.
//!
//! # KIP-98 RecordBatch v2 Format
//!
//! The RecordBatch v2 format includes:
//! - Record attribute bits (compression, transactional, control, timestamp type)
//! - Producer ID/epoch/sequence for exactly-once semantics
//! - Varint encoding for timestamp deltas and key/value lengths
//! - Headers array encoding
//! - Base offset and last offset delta relationship
//! - CRC32 validation

use serde::{Deserialize, Serialize};

// ============================================================================
// KIP-98 RecordBatch v2 Format Structures
// ============================================================================

/// RecordBatch v2 format per KIP-98.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordBatchV2 {
    /// First offset in this batch.
    pub base_offset: i64,
    /// Length in bytes of the batch.
    pub batch_length: i32,
    /// Partition leader epoch.
    pub partition_leader_epoch: i32,
    /// Magic byte (must be 2 for RecordBatch v2).
    pub magic: i8,
    /// CRC32 checksum.
    pub crc: u32,
    /// Batch attributes.
    pub attributes: RecordAttribute,
    /// Delta from base_offset to last record.
    pub last_offset_delta: i32,
    /// Timestamp of first record in batch.
    pub first_timestamp: i64,
    /// Highest timestamp in batch.
    pub max_timestamp: i64,
    /// Producer ID for exactly-once semantics.
    pub producer_id: i64,
    /// Producer epoch.
    pub producer_epoch: i16,
    /// Base sequence number.
    pub base_sequence: i32,
    /// Number of records in batch.
    pub record_count: i32,
    /// Records in the batch.
    pub records: Vec<RecordV2>,
}

impl RecordBatchV2 {
    /// Create a new RecordBatch v2.
    pub fn new(base_offset: i64, producer_id: i64, producer_epoch: i16, base_sequence: i32) -> Self {
        Self {
            base_offset,
            batch_length: 0, // Will be calculated during encoding
            partition_leader_epoch: 0,
            magic: 2,
            crc: 0, // Will be calculated during encoding
            attributes: RecordAttribute::new(),
            last_offset_delta: 0,
            first_timestamp: 0,
            max_timestamp: 0,
            producer_id,
            producer_epoch,
            base_sequence,
            record_count: 0,
            records: Vec::new(),
        }
    }

    /// Set the base timestamp.
    pub fn with_base_timestamp(mut self, timestamp: i64) -> Self {
        self.first_timestamp = timestamp;
        self.max_timestamp = timestamp;
        self
    }

    /// Set the attributes.
    pub fn with_attributes(mut self, attributes: RecordAttribute) -> Self {
        self.attributes = attributes;
        self
    }

    /// Add a record to the batch.
    pub fn add_record(&mut self, record: RecordV2) {
        self.record_count += 1;
        self.last_offset_delta = record.offset_delta;

        // Update max timestamp
        let record_timestamp = self.first_timestamp + record.timestamp_delta as i64;
        if record_timestamp > self.max_timestamp {
            self.max_timestamp = record_timestamp;
        }

        self.records.push(record);
    }
}

/// Record attribute bits per KIP-98.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RecordAttribute {
    /// Raw attribute value.
    value: u8,
}

impl RecordAttribute {
    /// Create new attributes with all bits clear.
    pub fn new() -> Self {
        Self { value: 0 }
    }

    /// Set compression type (bits 0-2).
    pub fn with_compression(mut self, compression: u8) -> Self {
        assert!(compression < 8, "Compression type must be 0-7");
        self.value = (self.value & 0xF8) | (compression & 0x07);
        self
    }

    /// Get compression type.
    pub fn compression(self) -> u8 {
        self.value & 0x07
    }

    /// Set timestamp type (bit 3).
    pub fn with_timestamp_type(mut self, timestamp_type: TimestampType) -> Self {
        match timestamp_type {
            TimestampType::CreateTime => self.value &= !0x08,
            TimestampType::LogAppendTime => self.value |= 0x08,
        }
        self
    }

    /// Get timestamp type.
    pub fn timestamp_type(self) -> TimestampType {
        if (self.value & 0x08) != 0 {
            TimestampType::LogAppendTime
        } else {
            TimestampType::CreateTime
        }
    }

    /// Set transactional bit (bit 4).
    pub fn with_transactional(mut self, transactional: bool) -> Self {
        if transactional {
            self.value |= 0x10;
        } else {
            self.value &= !0x10;
        }
        self
    }

    /// Check if this is a transactional record.
    pub fn is_transactional(self) -> bool {
        (self.value & 0x10) != 0
    }

    /// Set control bit (bit 5).
    pub fn with_control(mut self, control: bool) -> Self {
        if control {
            self.value |= 0x20;
        } else {
            self.value &= !0x20;
        }
        self
    }

    /// Check if this is a control record.
    pub fn is_control(self) -> bool {
        (self.value & 0x20) != 0
    }

    /// Get raw byte value.
    pub fn as_u8(self) -> u8 {
        self.value
    }
}

impl Default for RecordAttribute {
    fn default() -> Self {
        Self::new()
    }
}

/// Timestamp type for records.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimestampType {
    /// Timestamp set by producer.
    CreateTime,
    /// Timestamp set by broker.
    LogAppendTime,
}

/// Individual record in RecordBatch v2 format.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordV2 {
    /// Length of record in bytes.
    pub length: i32,
    /// Record attributes (currently unused).
    pub attributes: u8,
    /// Timestamp delta from batch first_timestamp.
    pub timestamp_delta: i64,
    /// Offset delta from batch base_offset.
    pub offset_delta: i32,
    /// Key length (-1 for null).
    pub key_length: i32,
    /// Key bytes (None for null).
    pub key: Option<Vec<u8>>,
    /// Value length (-1 for null).
    pub value_length: i32,
    /// Value bytes (None for null).
    pub value: Option<Vec<u8>>,
    /// Number of headers.
    pub header_count: i32,
    /// Headers array.
    pub headers: Vec<Header>,
}

impl RecordV2 {
    /// Create a new record.
    pub fn new(key: Option<Vec<u8>>, value: Option<Vec<u8>>) -> Self {
        let key_length = key.as_ref().map(|k| k.len() as i32).unwrap_or(-1);
        let value_length = value.as_ref().map(|v| v.len() as i32).unwrap_or(-1);

        Self {
            length: 0, // Will be calculated during encoding
            attributes: 0,
            timestamp_delta: 0,
            offset_delta: 0,
            key_length,
            key,
            value_length,
            value,
            header_count: 0,
            headers: Vec::new(),
        }
    }

    /// Set timestamp delta.
    pub fn with_timestamp_delta(mut self, delta: i64) -> Self {
        self.timestamp_delta = delta;
        self
    }

    /// Set offset delta.
    pub fn with_offset_delta(mut self, delta: i32) -> Self {
        self.offset_delta = delta;
        self
    }

    /// Add a header.
    pub fn with_header(mut self, key: String, value: Option<Vec<u8>>) -> Self {
        self.headers.push(Header { key, value });
        self.header_count = self.headers.len() as i32;
        self
    }
}

/// Header in a record.
#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    /// Header key.
    pub key: String,
    /// Header value (None for null).
    pub value: Option<Vec<u8>>,
}

// ============================================================================
// Wire Format Encoding/Decoding
// ============================================================================

/// Kafka RecordBatch v2 conformance harness.
pub struct KafkaConformanceHarness;

impl KafkaConformanceHarness {
    /// Create a new conformance harness.
    pub fn new() -> Self {
        Self
    }

    /// Encode a RecordBatch v2 to wire format.
    pub fn encode_record_batch(&self, batch: &RecordBatchV2) -> Vec<u8> {
        let mut buf = Vec::new();

        // Encode records first to calculate batch length
        let mut records_data = Vec::new();
        for record in &batch.records {
            let record_bytes = self.encode_record(record);
            records_data.extend_from_slice(&record_bytes);
        }

        // Calculate total batch length (everything after base_offset field)
        let batch_length = 49 + records_data.len(); // Fixed header is 49 bytes after base_offset

        // Encode fixed header
        buf.extend_from_slice(&batch.base_offset.to_be_bytes());      // 8 bytes
        buf.extend_from_slice(&(batch_length as i32).to_be_bytes()); // 4 bytes
        buf.extend_from_slice(&batch.partition_leader_epoch.to_be_bytes()); // 4 bytes
        buf.push(batch.magic as u8);                                  // 1 byte

        // Reserve space for CRC32 (will calculate after)
        let crc_offset = buf.len();
        buf.extend_from_slice(&0u32.to_be_bytes());                  // 4 bytes

        let crc_start = buf.len();

        // Encode attributes and remaining header
        buf.extend_from_slice(&batch.last_offset_delta.to_be_bytes()); // 4 bytes
        buf.extend_from_slice(&batch.first_timestamp.to_be_bytes());   // 8 bytes
        buf.extend_from_slice(&batch.max_timestamp.to_be_bytes());     // 8 bytes
        buf.extend_from_slice(&batch.producer_id.to_be_bytes());       // 8 bytes
        buf.extend_from_slice(&batch.producer_epoch.to_be_bytes());    // 2 bytes
        buf.extend_from_slice(&batch.base_sequence.to_be_bytes());     // 4 bytes
        buf.extend_from_slice(&batch.record_count.to_be_bytes());      // 4 bytes
        buf.push(batch.attributes.as_u8());                           // 1 byte

        // Add records
        buf.extend_from_slice(&records_data);

        // Calculate CRC32 over everything after the CRC field
        let crc = crc32fast::hash(&buf[crc_start..]);

        // Write CRC32
        buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_be_bytes());

        buf
    }

    /// Encode a single record.
    fn encode_record(&self, record: &RecordV2) -> Vec<u8> {
        let mut buf = Vec::new();

        // Calculate record length
        let mut length = 1; // attributes
        length += varint_len(record.timestamp_delta);
        length += varint_len(record.offset_delta as i64);
        length += varint_len(record.key_length as i64);
        if let Some(ref key) = record.key {
            length += key.len();
        }
        length += varint_len(record.value_length as i64);
        if let Some(ref value) = record.value {
            length += value.len();
        }
        length += varint_len(record.header_count as i64);
        for header in &record.headers {
            length += varint_len(header.key.len() as i64);
            length += header.key.len();
            length += varint_len(header.value.as_ref().map(|v| v.len()).unwrap_or(0) as i64);
            if let Some(ref value) = header.value {
                length += value.len();
            }
        }

        // Encode length as varint
        encode_varint(&mut buf, length as i64);

        // Encode record content
        buf.push(record.attributes);
        encode_varint(&mut buf, record.timestamp_delta);
        encode_varint(&mut buf, record.offset_delta as i64);

        // Encode key
        encode_varint(&mut buf, record.key_length as i64);
        if let Some(ref key) = record.key {
            buf.extend_from_slice(key);
        }

        // Encode value
        encode_varint(&mut buf, record.value_length as i64);
        if let Some(ref value) = record.value {
            buf.extend_from_slice(value);
        }

        // Encode headers
        encode_varint(&mut buf, record.header_count as i64);
        for header in &record.headers {
            encode_varint(&mut buf, header.key.len() as i64);
            buf.extend_from_slice(header.key.as_bytes());
            let value_len = header.value.as_ref().map(|v| v.len()).unwrap_or(0);
            encode_varint(&mut buf, value_len as i64);
            if let Some(ref value) = header.value {
                buf.extend_from_slice(value);
            }
        }

        buf
    }

    /// Decode a RecordBatch v2 from wire format.
    pub fn decode_record_batch(&self, data: &[u8]) -> Result<RecordBatchV2, String> {
        if data.len() < 61 {
            return Err("RecordBatch v2 must be at least 61 bytes".to_string());
        }

        let mut offset = 0;

        // Decode fixed header
        let base_offset = i64::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        let batch_length = i32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;

        let partition_leader_epoch = i32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;

        let magic = data[offset] as i8;
        offset += 1;

        if magic != 2 {
            return Err(format!("Invalid magic byte: {}, expected 2", magic));
        }

        let crc = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;

        // Validate CRC32
        let calculated_crc = crc32fast::hash(&data[offset..]);
        if crc != calculated_crc {
            return Err(format!("CRC mismatch: got {}, expected {}", calculated_crc, crc));
        }

        let last_offset_delta = i32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;

        let first_timestamp = i64::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        let max_timestamp = i64::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        let producer_id = i64::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        let producer_epoch = i16::from_be_bytes([
            data[offset], data[offset + 1],
        ]);
        offset += 2;

        let base_sequence = i32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;

        let record_count = i32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;

        let attributes = RecordAttribute { value: data[offset] };
        offset += 1;

        // Decode records
        let mut records = Vec::new();
        for _ in 0..record_count {
            let (record, bytes_read) = self.decode_record(&data[offset..])?;
            records.push(record);
            offset += bytes_read;
        }

        Ok(RecordBatchV2 {
            base_offset,
            batch_length,
            partition_leader_epoch,
            magic,
            crc,
            attributes,
            last_offset_delta,
            first_timestamp,
            max_timestamp,
            producer_id,
            producer_epoch,
            base_sequence,
            record_count,
            records,
        })
    }

    /// Decode a single record.
    fn decode_record(&self, data: &[u8]) -> Result<(RecordV2, usize), String> {
        let mut offset = 0;

        let (length, length_bytes) = decode_varint(&data[offset..])?;
        offset += length_bytes;

        let attributes = data[offset];
        offset += 1;

        let (timestamp_delta, td_bytes) = decode_varint(&data[offset..])?;
        offset += td_bytes;

        let (offset_delta, od_bytes) = decode_varint(&data[offset..])?;
        offset += od_bytes;

        // Decode key
        let (key_length, kl_bytes) = decode_varint(&data[offset..])?;
        offset += kl_bytes;

        let key = if key_length == -1 {
            None
        } else {
            let key_data = data[offset..offset + key_length as usize].to_vec();
            offset += key_length as usize;
            Some(key_data)
        };

        // Decode value
        let (value_length, vl_bytes) = decode_varint(&data[offset..])?;
        offset += vl_bytes;

        let value = if value_length == -1 {
            None
        } else {
            let value_data = data[offset..offset + value_length as usize].to_vec();
            offset += value_length as usize;
            Some(value_data)
        };

        // Decode headers
        let (header_count, hc_bytes) = decode_varint(&data[offset..])?;
        offset += hc_bytes;

        let mut headers = Vec::new();
        for _ in 0..header_count {
            let (key_len, kl_bytes) = decode_varint(&data[offset..])?;
            offset += kl_bytes;

            let header_key = String::from_utf8(data[offset..offset + key_len as usize].to_vec())
                .map_err(|e| format!("Invalid UTF-8 in header key: {}", e))?;
            offset += key_len as usize;

            let (value_len, vl_bytes) = decode_varint(&data[offset..])?;
            offset += vl_bytes;

            let header_value = if value_len == 0 {
                None
            } else {
                let value_data = data[offset..offset + value_len as usize].to_vec();
                offset += value_len as usize;
                Some(value_data)
            };

            headers.push(Header {
                key: header_key,
                value: header_value,
            });
        }

        let record = RecordV2 {
            length: length as i32,
            attributes,
            timestamp_delta,
            offset_delta: offset_delta as i32,
            key_length: key_length as i32,
            key,
            value_length: value_length as i32,
            value,
            header_count: header_count as i32,
            headers,
        };

        Ok((record, offset))
    }

    /// Run all format conformance tests.
    pub fn run_format_tests(&self) -> Vec<ConformanceTestResult> {
        vec![
            self.test_basic_encoding(),
            self.test_record_attributes(),
            self.test_varint_encoding(),
            self.test_headers_encoding(),
            self.test_exactly_once_fields(),
            self.test_offset_relationship(),
            self.test_transactional_batch(),
            self.test_control_batch(),
            self.test_null_key_value(),
            self.test_crc32_validation(),
            self.test_empty_batch(),
        ]
    }

    /// Test basic RecordBatch v2 encoding.
    fn test_basic_encoding(&self) -> ConformanceTestResult {
        let mut batch = RecordBatchV2::new(0, 12345, 0, 0)
            .with_base_timestamp(1234567890000);

        let record = RecordV2::new(
            Some(b"test-key".to_vec()),
            Some(b"test-value".to_vec()),
        )
        .with_timestamp_delta(0)
        .with_offset_delta(0);

        batch.add_record(record);

        // Encode the batch
        let encoded = self.encode_record_batch(&batch);

        // Basic format validation
        if encoded.len() < 61 {
            return ConformanceTestResult::fail(
                "basic_encoding".to_string(),
                "RecordBatch v2 must be at least 61 bytes".to_string(),
            );
        }

        if encoded[16] != 2 {
            return ConformanceTestResult::fail(
                "basic_encoding".to_string(),
                "Magic byte must be 2 for RecordBatch v2".to_string(),
            );
        }

        // Verify we can decode it back
        match self.decode_record_batch(&encoded) {
            Ok(decoded) => {
                if decoded.magic != 2
                    || decoded.producer_id != 12345
                    || decoded.record_count != 1
                    || decoded.records.len() != 1
                    || decoded.records[0].key != Some(b"test-key".to_vec())
                    || decoded.records[0].value != Some(b"test-value".to_vec()) {
                    return ConformanceTestResult::fail(
                        "basic_encoding".to_string(),
                        "Decoded batch does not match original".to_string(),
                    );
                }
            }
            Err(e) => {
                return ConformanceTestResult::fail(
                    "basic_encoding".to_string(),
                    format!("Failed to decode batch: {}", e),
                );
            }
        }

        ConformanceTestResult::pass("basic_encoding".to_string())
    }

    /// Test record attribute bits according to KIP-98.
    fn test_record_attributes(&self) -> ConformanceTestResult {
        // Test compression bits (0-2)
        for compression in 0..8 {
            let attr = RecordAttribute::new().with_compression(compression);
            if attr.compression() != compression {
                return ConformanceTestResult::fail(
                    "record_attributes".to_string(),
                    format!("Compression bits failed for type {}", compression),
                );
            }
        }

        // Test timestamp type bit (3)
        let attr_create = RecordAttribute::new().with_timestamp_type(TimestampType::CreateTime);
        let attr_append = RecordAttribute::new().with_timestamp_type(TimestampType::LogAppendTime);

        if attr_create.timestamp_type() != TimestampType::CreateTime
            || attr_append.timestamp_type() != TimestampType::LogAppendTime
            || (attr_create.as_u8() & 0x08) != 0
            || (attr_append.as_u8() & 0x08) != 0x08 {
            return ConformanceTestResult::fail(
                "record_attributes".to_string(),
                "Timestamp type bit validation failed".to_string(),
            );
        }

        // Test transactional bit (4)
        let attr_false = RecordAttribute::new().with_transactional(false);
        let attr_true = RecordAttribute::new().with_transactional(true);

        if attr_false.is_transactional()
            || !attr_true.is_transactional()
            || (attr_false.as_u8() & 0x10) != 0
            || (attr_true.as_u8() & 0x10) != 0x10 {
            return ConformanceTestResult::fail(
                "record_attributes".to_string(),
                "Transactional bit validation failed".to_string(),
            );
        }

        // Test control bit (5)
        let attr_false = RecordAttribute::new().with_control(false);
        let attr_true = RecordAttribute::new().with_control(true);

        if attr_false.is_control()
            || !attr_true.is_control()
            || (attr_false.as_u8() & 0x20) != 0
            || (attr_true.as_u8() & 0x20) != 0x20 {
            return ConformanceTestResult::fail(
                "record_attributes".to_string(),
                "Control bit validation failed".to_string(),
            );
        }

        ConformanceTestResult::pass("record_attributes".to_string())
    }

    /// Test varint encoding for timestamp deltas.
    fn test_varint_encoding(&self) -> ConformanceTestResult {
        let test_deltas = [0, 1, 127, 128, 16383, 16384, 2097151, 2097152];

        let mut batch = RecordBatchV2::new(0, 12345, 0, 0)
            .with_base_timestamp(1234567890000);

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
        let encoded = self.encode_record_batch(&batch);
        match self.decode_record_batch(&encoded) {
            Ok(decoded) => {
                if decoded.records.len() != test_deltas.len() {
                    return ConformanceTestResult::fail(
                        "varint_encoding".to_string(),
                        "Record count mismatch after varint encoding".to_string(),
                    );
                }

                for (i, &expected_delta) in test_deltas.iter().enumerate() {
                    if decoded.records[i].timestamp_delta != expected_delta {
                        return ConformanceTestResult::fail(
                            "varint_encoding".to_string(),
                            format!("Timestamp delta mismatch at index {}: got {}, expected {}",
                                   i, decoded.records[i].timestamp_delta, expected_delta),
                        );
                    }
                }
            }
            Err(e) => {
                return ConformanceTestResult::fail(
                    "varint_encoding".to_string(),
                    format!("Failed to decode batch with varint encoding: {}", e),
                );
            }
        }

        ConformanceTestResult::pass("varint_encoding".to_string())
    }

    /// Test headers array encoding.
    fn test_headers_encoding(&self) -> ConformanceTestResult {
        let mut batch = RecordBatchV2::new(0, 12345, 0, 0)
            .with_base_timestamp(1234567890000);

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
        let encoded = self.encode_record_batch(&batch);
        match self.decode_record_batch(&encoded) {
            Ok(decoded) => {
                if decoded.records.len() != 1 {
                    return ConformanceTestResult::fail(
                        "headers_encoding".to_string(),
                        "Should have exactly one record".to_string(),
                    );
                }

                let decoded_record = &decoded.records[0];
                if decoded_record.headers.len() != 3 {
                    return ConformanceTestResult::fail(
                        "headers_encoding".to_string(),
                        format!("Expected 3 headers, got {}", decoded_record.headers.len()),
                    );
                }

                let expected_headers = [
                    ("trace-id", Some(b"abc-def-123".to_vec())),
                    ("user-agent", Some(b"MyApp/1.0".to_vec())),
                    ("request-id", Some(b"req-456".to_vec())),
                ];

                for (i, (expected_key, expected_value)) in expected_headers.iter().enumerate() {
                    let header = &decoded_record.headers[i];
                    if &header.key != expected_key || &header.value != expected_value {
                        return ConformanceTestResult::fail(
                            "headers_encoding".to_string(),
                            format!("Header {} mismatch: expected {:?}, got {:?}",
                                   i, (expected_key, expected_value), (&header.key, &header.value)),
                        );
                    }
                }
            }
            Err(e) => {
                return ConformanceTestResult::fail(
                    "headers_encoding".to_string(),
                    format!("Failed to decode batch with headers: {}", e),
                );
            }
        }

        ConformanceTestResult::pass("headers_encoding".to_string())
    }

    /// Test producer ID, epoch, and sequence for exactly-once semantics.
    fn test_exactly_once_fields(&self) -> ConformanceTestResult {
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
        let encoded = self.encode_record_batch(&batch);
        match self.decode_record_batch(&encoded) {
            Ok(decoded) => {
                if decoded.producer_id != producer_id
                    || decoded.producer_epoch != producer_epoch
                    || decoded.base_sequence != base_sequence {
                    return ConformanceTestResult::fail(
                        "exactly_once_fields".to_string(),
                        format!("Exactly-once fields mismatch: producer_id {} vs {}, epoch {} vs {}, sequence {} vs {}",
                               decoded.producer_id, producer_id,
                               decoded.producer_epoch, producer_epoch,
                               decoded.base_sequence, base_sequence),
                    );
                }
            }
            Err(e) => {
                return ConformanceTestResult::fail(
                    "exactly_once_fields".to_string(),
                    format!("Failed to decode batch with exactly-once fields: {}", e),
                );
            }
        }

        ConformanceTestResult::pass("exactly_once_fields".to_string())
    }

    /// Test base_offset and last_offset_delta relationship.
    fn test_offset_relationship(&self) -> ConformanceTestResult {
        let base_offset = 1000i64;
        let mut batch = RecordBatchV2::new(base_offset, 55555, 1, 50)
            .with_base_timestamp(1234567890000);

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
        if batch.last_offset_delta != 9 {
            return ConformanceTestResult::fail(
                "offset_relationship".to_string(),
                format!("last_offset_delta should be 9 for 10 records (0-indexed), got {}",
                       batch.last_offset_delta),
            );
        }

        // Encode and decode
        let encoded = self.encode_record_batch(&batch);
        match self.decode_record_batch(&encoded) {
            Ok(decoded) => {
                if decoded.base_offset != base_offset
                    || decoded.last_offset_delta != 9
                    || decoded.record_count != 10 {
                    return ConformanceTestResult::fail(
                        "offset_relationship".to_string(),
                        format!("Offset relationship validation failed: base {} vs {}, last_delta {} vs 9, count {} vs 10",
                               decoded.base_offset, base_offset,
                               decoded.last_offset_delta,
                               decoded.record_count),
                    );
                }

                // Verify each record has the correct offset delta
                for (i, record) in decoded.records.iter().enumerate() {
                    if record.offset_delta != i as i32 {
                        return ConformanceTestResult::fail(
                            "offset_relationship".to_string(),
                            format!("Record {} has wrong offset_delta: {} vs {}",
                                   i, record.offset_delta, i),
                        );
                    }
                }
            }
            Err(e) => {
                return ConformanceTestResult::fail(
                    "offset_relationship".to_string(),
                    format!("Failed to decode batch with offset relationship: {}", e),
                );
            }
        }

        ConformanceTestResult::pass("offset_relationship".to_string())
    }

    /// Test transactional record batch.
    fn test_transactional_batch(&self) -> ConformanceTestResult {
        let mut batch = RecordBatchV2::new(100, 98765, 1, 42)
            .with_base_timestamp(1234567890000)
            .with_attributes(RecordAttribute::new().with_transactional(true));

        let record1 = RecordV2::new(
            Some(b"key1".to_vec()),
            Some(b"value1".to_vec()),
        )
        .with_timestamp_delta(0)
        .with_offset_delta(0);

        let record2 = RecordV2::new(
            Some(b"key2".to_vec()),
            Some(b"value2".to_vec()),
        )
        .with_timestamp_delta(100)
        .with_offset_delta(1);

        batch.add_record(record1);
        batch.add_record(record2);

        // Encode and decode
        let encoded = self.encode_record_batch(&batch);
        match self.decode_record_batch(&encoded) {
            Ok(decoded) => {
                if !decoded.attributes.is_transactional()
                    || decoded.record_count != 2
                    || decoded.records.len() != 2 {
                    return ConformanceTestResult::fail(
                        "transactional_batch".to_string(),
                        "Transactional attributes or record count validation failed".to_string(),
                    );
                }
            }
            Err(e) => {
                return ConformanceTestResult::fail(
                    "transactional_batch".to_string(),
                    format!("Failed to decode transactional batch: {}", e),
                );
            }
        }

        ConformanceTestResult::pass("transactional_batch".to_string())
    }

    /// Test control record batch.
    fn test_control_batch(&self) -> ConformanceTestResult {
        let mut batch = RecordBatchV2::new(200, 54321, 2, 10)
            .with_base_timestamp(1234567890000)
            .with_attributes(
                RecordAttribute::new()
                    .with_transactional(true)
                    .with_control(true)
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
        let encoded = self.encode_record_batch(&batch);
        match self.decode_record_batch(&encoded) {
            Ok(decoded) => {
                if !decoded.attributes.is_transactional()
                    || !decoded.attributes.is_control()
                    || decoded.record_count != 1 {
                    return ConformanceTestResult::fail(
                        "control_batch".to_string(),
                        "Control attributes validation failed".to_string(),
                    );
                }
            }
            Err(e) => {
                return ConformanceTestResult::fail(
                    "control_batch".to_string(),
                    format!("Failed to decode control batch: {}", e),
                );
            }
        }

        ConformanceTestResult::pass("control_batch".to_string())
    }

    /// Test null key and value handling.
    fn test_null_key_value(&self) -> ConformanceTestResult {
        let mut batch = RecordBatchV2::new(400, 44444, 0, 0)
            .with_base_timestamp(1234567890000);

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
        let encoded = self.encode_record_batch(&batch);
        match self.decode_record_batch(&encoded) {
            Ok(decoded) => {
                if decoded.record_count != 3 || decoded.records.len() != 3 {
                    return ConformanceTestResult::fail(
                        "null_key_value".to_string(),
                        format!("Expected 3 records, got {}", decoded.records.len()),
                    );
                }

                // Check null key/value
                if decoded.records[0].key.is_some()
                    || decoded.records[0].value.is_some()
                    || decoded.records[0].key_length != -1
                    || decoded.records[0].value_length != -1 {
                    return ConformanceTestResult::fail(
                        "null_key_value".to_string(),
                        "Null key/value validation failed for record 0".to_string(),
                    );
                }

                // Check null key with value
                if decoded.records[1].key.is_some()
                    || decoded.records[1].value != Some(b"value-only".to_vec())
                    || decoded.records[1].key_length != -1
                    || decoded.records[1].value_length != 10 {
                    return ConformanceTestResult::fail(
                        "null_key_value".to_string(),
                        "Null key with value validation failed for record 1".to_string(),
                    );
                }

                // Check key with null value
                if decoded.records[2].key != Some(b"key-only".to_vec())
                    || decoded.records[2].value.is_some()
                    || decoded.records[2].key_length != 8
                    || decoded.records[2].value_length != -1 {
                    return ConformanceTestResult::fail(
                        "null_key_value".to_string(),
                        "Key with null value validation failed for record 2".to_string(),
                    );
                }
            }
            Err(e) => {
                return ConformanceTestResult::fail(
                    "null_key_value".to_string(),
                    format!("Failed to decode batch with null key/value: {}", e),
                );
            }
        }

        ConformanceTestResult::pass("null_key_value".to_string())
    }

    /// Test CRC32 validation.
    fn test_crc32_validation(&self) -> ConformanceTestResult {
        let mut batch = RecordBatchV2::new(0, 12345, 0, 0)
            .with_base_timestamp(1234567890000);

        let record = RecordV2::new(
            Some(b"crc-test-key".to_vec()),
            Some(b"crc-test-value".to_vec()),
        );

        batch.add_record(record);

        // Encode the batch
        let mut encoded = self.encode_record_batch(&batch);

        // Verify it decodes correctly
        if self.decode_record_batch(&encoded).is_err() {
            return ConformanceTestResult::fail(
                "crc32_validation".to_string(),
                "Valid CRC32 batch failed to decode".to_string(),
            );
        }

        // Corrupt the CRC32 (at position 20-23)
        encoded[20] ^= 0xFF;

        // Should fail with CRC mismatch
        match self.decode_record_batch(&encoded) {
            Err(e) => {
                if !e.contains("CRC mismatch") {
                    return ConformanceTestResult::fail(
                        "crc32_validation".to_string(),
                        format!("Expected CRC mismatch error, got: {}", e),
                    );
                }
            }
            Ok(_) => {
                return ConformanceTestResult::fail(
                    "crc32_validation".to_string(),
                    "Expected CRC validation to fail".to_string(),
                );
            }
        }

        ConformanceTestResult::pass("crc32_validation".to_string())
    }

    /// Test empty record batch.
    fn test_empty_batch(&self) -> ConformanceTestResult {
        let batch = RecordBatchV2::new(500, 12345, 0, 0)
            .with_base_timestamp(1234567890000);

        // Encode and decode empty batch
        let encoded = self.encode_record_batch(&batch);
        match self.decode_record_batch(&encoded) {
            Ok(decoded) => {
                if decoded.record_count != 0
                    || decoded.records.len() != 0
                    || decoded.last_offset_delta != 0 {
                    return ConformanceTestResult::fail(
                        "empty_batch".to_string(),
                        "Empty batch validation failed".to_string(),
                    );
                }
            }
            Err(e) => {
                return ConformanceTestResult::fail(
                    "empty_batch".to_string(),
                    format!("Failed to decode empty batch: {}", e),
                );
            }
        }

        ConformanceTestResult::pass("empty_batch".to_string())
    }
}

impl Default for KafkaConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Conformance Test Result
// ============================================================================

/// Result of a Kafka conformance test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceTestResult {
    /// Test identifier.
    pub test_id: String,
    /// Whether the test passed.
    pub passed: bool,
    /// Error message if failed.
    pub error_message: Option<String>,
}

impl ConformanceTestResult {
    /// Create a passing test result.
    pub fn pass(test_id: String) -> Self {
        Self {
            test_id,
            passed: true,
            error_message: None,
        }
    }

    /// Create a failing test result.
    pub fn fail(test_id: String, error: String) -> Self {
        Self {
            test_id,
            passed: false,
            error_message: Some(error),
        }
    }
}

// ============================================================================
// Varint Encoding Utilities
// ============================================================================

/// Encode a signed 64-bit integer as a varint.
fn encode_varint(buf: &mut Vec<u8>, value: i64) {
    // Use zigzag encoding for signed values
    let unsigned = ((value << 1) ^ (value >> 63)) as u64;
    encode_varint_unsigned(buf, unsigned);
}

/// Encode an unsigned 64-bit integer as a varint.
fn encode_varint_unsigned(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value & 0x7F | 0x80) as u8);
        value >>= 7;
    }
    buf.push(value as u8);
}

/// Decode a varint from bytes.
fn decode_varint(data: &[u8]) -> Result<(i64, usize), String> {
    let (unsigned, bytes_read) = decode_varint_unsigned(data)?;

    // Decode zigzag encoding
    let signed = ((unsigned >> 1) as i64) ^ -((unsigned & 1) as i64);
    Ok((signed, bytes_read))
}

/// Decode an unsigned varint from bytes.
fn decode_varint_unsigned(data: &[u8]) -> Result<(u64, usize), String> {
    let mut result = 0u64;
    let mut shift = 0;
    let mut bytes_read = 0;

    for &byte in data.iter().take(10) { // Max 10 bytes for 64-bit varint
        bytes_read += 1;
        result |= ((byte & 0x7F) as u64) << shift;

        if (byte & 0x80) == 0 {
            return Ok((result, bytes_read));
        }

        shift += 7;
        if shift >= 64 {
            return Err("Varint too long".to_string());
        }
    }

    Err("Incomplete varint".to_string())
}

/// Calculate the number of bytes needed to encode a varint.
fn varint_len(value: i64) -> usize {
    let unsigned = ((value << 1) ^ (value >> 63)) as u64;
    varint_len_unsigned(unsigned)
}

/// Calculate the number of bytes needed to encode an unsigned varint.
fn varint_len_unsigned(mut value: u64) -> usize {
    if value == 0 {
        return 1;
    }

    let mut len = 0;
    while value > 0 {
        len += 1;
        value >>= 7;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let test_values = [-1, 0, 1, 127, 128, 16383, 16384, 2097151, 2097152, i64::MAX, i64::MIN];

        for &value in &test_values {
            let mut buf = Vec::new();
            encode_varint(&mut buf, value);

            let (decoded, bytes_read) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(bytes_read, buf.len());
        }
    }

    #[test]
    fn test_record_attribute_bits() {
        // Test all compression types
        for compression in 0..8 {
            let attr = RecordAttribute::new().with_compression(compression);
            assert_eq!(attr.compression(), compression);
        }

        // Test timestamp type
        let create_time = RecordAttribute::new().with_timestamp_type(TimestampType::CreateTime);
        let append_time = RecordAttribute::new().with_timestamp_type(TimestampType::LogAppendTime);

        assert_eq!(create_time.timestamp_type(), TimestampType::CreateTime);
        assert_eq!(append_time.timestamp_type(), TimestampType::LogAppendTime);

        // Test transactional bit
        let non_txn = RecordAttribute::new().with_transactional(false);
        let txn = RecordAttribute::new().with_transactional(true);

        assert!(!non_txn.is_transactional());
        assert!(txn.is_transactional());

        // Test control bit
        let non_control = RecordAttribute::new().with_control(false);
        let control = RecordAttribute::new().with_control(true);

        assert!(!non_control.is_control());
        assert!(control.is_control());
    }

    #[test]
    fn test_basic_encoding_roundtrip() {
        let harness = KafkaConformanceHarness::new();

        let mut batch = RecordBatchV2::new(100, 12345, 1, 42)
            .with_base_timestamp(1234567890000);

        let record = RecordV2::new(
            Some(b"test-key".to_vec()),
            Some(b"test-value".to_vec()),
        )
        .with_timestamp_delta(50)
        .with_offset_delta(0);

        batch.add_record(record);

        let encoded = harness.encode_record_batch(&batch);
        let decoded = harness.decode_record_batch(&encoded).unwrap();

        assert_eq!(decoded.base_offset, 100);
        assert_eq!(decoded.magic, 2);
        assert_eq!(decoded.producer_id, 12345);
        assert_eq!(decoded.producer_epoch, 1);
        assert_eq!(decoded.base_sequence, 42);
        assert_eq!(decoded.record_count, 1);
        assert_eq!(decoded.records.len(), 1);
        assert_eq!(decoded.records[0].key, Some(b"test-key".to_vec()));
        assert_eq!(decoded.records[0].value, Some(b"test-value".to_vec()));
        assert_eq!(decoded.records[0].timestamp_delta, 50);
    }
}