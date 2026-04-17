//! Kafka RecordBatch v2 format structures per KIP-98.
//!
//! This module defines the data structures and encoding/decoding logic
//! for Kafka RecordBatch v2 format as specified in KIP-98.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

/// Record attributes bit flags per KIP-98.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordAttribute(u8);

impl RecordAttribute {
    /// Create empty attributes.
    pub fn new() -> Self {
        Self(0)
    }

    /// Set compression type (bits 0-2).
    pub fn with_compression(mut self, compression: u8) -> Self {
        self.0 = (self.0 & 0xF8) | (compression & 0x07);
        self
    }

    /// Set timestamp type (bit 3).
    pub fn with_timestamp_type(mut self, timestamp_type: TimestampType) -> Self {
        if timestamp_type == TimestampType::LogAppendTime {
            self.0 |= 0x08;
        } else {
            self.0 &= !0x08;
        }
        self
    }

    /// Set transactional flag (bit 4).
    pub fn with_transactional(mut self, transactional: bool) -> Self {
        if transactional {
            self.0 |= 0x10;
        } else {
            self.0 &= !0x10;
        }
        self
    }

    /// Set control flag (bit 5).
    pub fn with_control(mut self, control: bool) -> Self {
        if control {
            self.0 |= 0x20;
        } else {
            self.0 &= !0x20;
        }
        self
    }

    /// Get compression type.
    pub fn compression(self) -> u8 {
        self.0 & 0x07
    }

    /// Get timestamp type.
    pub fn timestamp_type(self) -> TimestampType {
        if (self.0 & 0x08) != 0 {
            TimestampType::LogAppendTime
        } else {
            TimestampType::CreateTime
        }
    }

    /// Check if transactional.
    pub fn is_transactional(self) -> bool {
        (self.0 & 0x10) != 0
    }

    /// Check if control record.
    pub fn is_control(self) -> bool {
        (self.0 & 0x20) != 0
    }

    /// Get raw attribute byte.
    pub fn as_u8(self) -> u8 {
        self.0
    }

    /// Create from raw attribute byte.
    pub fn from_u8(value: u8) -> Self {
        Self(value)
    }
}

impl Default for RecordAttribute {
    fn default() -> Self {
        Self::new()
    }
}

/// Timestamp type for records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampType {
    /// Timestamp set by the producer.
    CreateTime,
    /// Timestamp set by the broker when appending to log.
    LogAppendTime,
}

/// Individual record within a RecordBatch.
#[derive(Debug, Clone)]
pub struct RecordV2 {
    /// Length of the record (varint).
    pub length: i32,
    /// Record attributes.
    pub attributes: RecordAttribute,
    /// Timestamp delta from base timestamp (varint).
    pub timestamp_delta: i64,
    /// Offset delta from base offset (varint).
    pub offset_delta: i32,
    /// Key length (varint).
    pub key_length: i32,
    /// Key data.
    pub key: Option<Vec<u8>>,
    /// Value length (varint).
    pub value_length: i32,
    /// Value data.
    pub value: Option<Vec<u8>>,
    /// Headers.
    pub headers: Vec<RecordHeader>,
}

/// Record header key-value pair.
#[derive(Debug, Clone)]
pub struct RecordHeader {
    /// Header key length (varint).
    pub key_length: i32,
    /// Header key.
    pub key: String,
    /// Header value length (varint).
    pub value_length: i32,
    /// Header value.
    pub value: Option<Vec<u8>>,
}

impl RecordV2 {
    /// Create a new record with given key and value.
    pub fn new(key: Option<Vec<u8>>, value: Option<Vec<u8>>) -> Self {
        let key_length = key.as_ref().map_or(-1, |k| k.len() as i32);
        let value_length = value.as_ref().map_or(-1, |v| v.len() as i32);

        Self {
            length: 0, // Will be calculated during encoding
            attributes: RecordAttribute::new(),
            timestamp_delta: 0,
            offset_delta: 0,
            key_length,
            key,
            value_length,
            value,
            headers: Vec::new(),
        }
    }

    /// Add a header to the record.
    pub fn with_header(mut self, key: String, value: Option<Vec<u8>>) -> Self {
        let value_length = value.as_ref().map_or(-1, |v| v.len() as i32);
        self.headers.push(RecordHeader {
            key_length: key.len() as i32,
            key,
            value_length,
            value,
        });
        self
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

    /// Set attributes.
    pub fn with_attributes(mut self, attributes: RecordAttribute) -> Self {
        self.attributes = attributes;
        self
    }
}

/// RecordBatch v2 format per KIP-98.
#[derive(Debug, Clone)]
pub struct RecordBatchV2 {
    /// Base offset of first record in batch.
    pub base_offset: i64,
    /// Length of the batch in bytes.
    pub batch_length: i32,
    /// Partition leader epoch.
    pub partition_leader_epoch: i32,
    /// Magic byte (should be 2 for v2).
    pub magic: i8,
    /// CRC32 checksum.
    pub crc: u32,
    /// Batch attributes.
    pub attributes: RecordAttribute,
    /// Last offset delta (relative to base_offset).
    pub last_offset_delta: i32,
    /// Base timestamp of first record.
    pub base_timestamp: i64,
    /// Max timestamp of records in batch.
    pub max_timestamp: i64,
    /// Producer ID for exactly-once semantics.
    pub producer_id: i64,
    /// Producer epoch for exactly-once semantics.
    pub producer_epoch: i16,
    /// Base sequence number for exactly-once semantics.
    pub base_sequence: i32,
    /// Number of records in the batch.
    pub record_count: i32,
    /// Records in the batch.
    pub records: Vec<RecordV2>,
}

impl RecordBatchV2 {
    /// Create a new RecordBatch v2.
    pub fn new(
        base_offset: i64,
        producer_id: i64,
        producer_epoch: i16,
        base_sequence: i32,
    ) -> Self {
        Self {
            base_offset,
            batch_length: 0, // Will be calculated during encoding
            partition_leader_epoch: 0,
            magic: 2, // RecordBatch v2
            crc: 0,   // Will be calculated during encoding
            attributes: RecordAttribute::new(),
            last_offset_delta: 0,
            base_timestamp: 0,
            max_timestamp: 0,
            producer_id,
            producer_epoch,
            base_sequence,
            record_count: 0,
            records: Vec::new(),
        }
    }

    /// Create a test batch for conformance testing.
    pub fn new_test_batch() -> Self {
        let mut batch = Self::new(0, 12345, 0, 0);

        let record1 = RecordV2::new(Some(b"key1".to_vec()), Some(b"value1".to_vec()))
            .with_timestamp_delta(0)
            .with_offset_delta(0);

        let record2 = RecordV2::new(Some(b"key2".to_vec()), Some(b"value2".to_vec()))
            .with_timestamp_delta(100)
            .with_offset_delta(1)
            .with_header("trace-id".to_string(), Some(b"abc-123".to_vec()));

        batch.add_record(record1);
        batch.add_record(record2);
        batch
    }

    /// Add a record to the batch.
    pub fn add_record(&mut self, mut record: RecordV2) {
        record.offset_delta = self.records.len() as i32;
        self.records.push(record);
        self.record_count = self.records.len() as i32;

        if !self.records.is_empty() {
            self.last_offset_delta = (self.records.len() - 1) as i32;
        }
    }

    /// Set batch attributes.
    pub fn with_attributes(mut self, attributes: RecordAttribute) -> Self {
        self.attributes = attributes;
        self
    }

    /// Set base timestamp.
    pub fn with_base_timestamp(mut self, timestamp: i64) -> Self {
        self.base_timestamp = timestamp;
        self.max_timestamp = timestamp;
        self
    }

    /// Get number of records.
    pub fn record_count(&self) -> i32 {
        self.record_count
    }

    /// Encode the batch to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // Write fixed header first (excluding batch_length and crc which we'll calculate)
        buffer.extend_from_slice(&self.base_offset.to_be_bytes());
        // Skip batch_length for now - we'll write it later
        let length_pos = buffer.len();
        buffer.extend_from_slice(&0i32.to_be_bytes()); // Placeholder
        buffer.extend_from_slice(&self.partition_leader_epoch.to_be_bytes());
        buffer.push(self.magic as u8);
        // Skip CRC for now - we'll calculate it later
        let crc_pos = buffer.len();
        buffer.extend_from_slice(&0u32.to_be_bytes()); // Placeholder
        buffer.push(self.attributes.as_u8());
        buffer.extend_from_slice(&self.last_offset_delta.to_be_bytes());
        buffer.extend_from_slice(&self.base_timestamp.to_be_bytes());
        buffer.extend_from_slice(&self.max_timestamp.to_be_bytes());
        buffer.extend_from_slice(&self.producer_id.to_be_bytes());
        buffer.extend_from_slice(&self.producer_epoch.to_be_bytes());
        buffer.extend_from_slice(&self.base_sequence.to_be_bytes());
        buffer.extend_from_slice(&self.record_count.to_be_bytes());

        // Encode records
        for record in &self.records {
            encode_record(record, &mut buffer);
        }

        // Calculate and write batch_length (total batch size - 8 bytes for base_offset - 4 bytes for length field)
        let batch_length = (buffer.len() - 12) as i32;
        buffer[length_pos..length_pos + 4].copy_from_slice(&batch_length.to_be_bytes());

        // Calculate CRC32 over everything after the CRC field
        let crc_data = &buffer[crc_pos + 4..];
        let crc = crc32fast::hash(crc_data);
        buffer[crc_pos..crc_pos + 4].copy_from_slice(&crc.to_be_bytes());

        buffer
    }

    /// Decode a batch from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 61 {
            return Err("Buffer too short for RecordBatch v2 header".to_string());
        }

        let mut cursor = Cursor::new(data);

        let base_offset = read_i64(&mut cursor)?;
        let batch_length = read_i32(&mut cursor)?;
        let partition_leader_epoch = read_i32(&mut cursor)?;
        let magic = read_i8(&mut cursor)?;

        if magic != 2 {
            return Err(format!("Invalid magic byte: expected 2, got {magic}"));
        }

        let stored_crc = read_u32(&mut cursor)?;
        let attributes = RecordAttribute::from_u8(read_u8(&mut cursor)?);
        let last_offset_delta = read_i32(&mut cursor)?;
        let base_timestamp = read_i64(&mut cursor)?;
        let max_timestamp = read_i64(&mut cursor)?;
        let producer_id = read_i64(&mut cursor)?;
        let producer_epoch = read_i16(&mut cursor)?;
        let base_sequence = read_i32(&mut cursor)?;
        let record_count = read_i32(&mut cursor)?;

        // Verify CRC
        let crc_start = cursor.position() as usize;
        let crc_data = &data[crc_start..];
        let calculated_crc = crc32fast::hash(crc_data);
        if stored_crc != calculated_crc {
            return Err(format!(
                "CRC mismatch: expected {stored_crc:x}, got {calculated_crc:x}"
            ));
        }

        // Decode records
        let mut records = Vec::new();
        for _ in 0..record_count {
            let record = decode_record(&mut cursor)?;
            records.push(record);
        }

        Ok(Self {
            base_offset,
            batch_length,
            partition_leader_epoch,
            magic,
            crc: stored_crc,
            attributes,
            last_offset_delta,
            base_timestamp,
            max_timestamp,
            producer_id,
            producer_epoch,
            base_sequence,
            record_count,
            records,
        })
    }
}

/// Encode a single record.
fn encode_record(record: &RecordV2, buffer: &mut Vec<u8>) {
    let record_start = buffer.len();

    // Skip length field for now
    encode_varint(0, buffer); // Placeholder

    buffer.push(record.attributes.as_u8());
    encode_varint_i64(record.timestamp_delta, buffer);
    encode_varint(record.offset_delta, buffer);

    // Encode key
    encode_varint(record.key_length, buffer);
    if let Some(ref key) = record.key {
        buffer.extend_from_slice(key);
    }

    // Encode value
    encode_varint(record.value_length, buffer);
    if let Some(ref value) = record.value {
        buffer.extend_from_slice(value);
    }

    // Encode headers
    encode_varint(record.headers.len() as i32, buffer);
    for header in &record.headers {
        encode_varint(header.key_length, buffer);
        buffer.extend_from_slice(header.key.as_bytes());
        encode_varint(header.value_length, buffer);
        if let Some(ref value) = header.value {
            buffer.extend_from_slice(value);
        }
    }

    // Calculate and write record length
    let record_length = (buffer.len() - record_start - varint_size(0)) as i32;
    let mut length_bytes = Vec::new();
    encode_varint(record_length, &mut length_bytes);

    // Replace placeholder length
    buffer[record_start..record_start + length_bytes.len()].copy_from_slice(&length_bytes);
}

/// Decode a single record.
fn decode_record(cursor: &mut Cursor<&[u8]>) -> Result<RecordV2, String> {
    let length = decode_varint(cursor)?;
    let attributes = RecordAttribute::from_u8(read_u8(cursor)?);
    let timestamp_delta = decode_varint_i64(cursor)?;
    let offset_delta = decode_varint(cursor)?;

    // Decode key
    let key_length = decode_varint(cursor)?;
    let key = if key_length >= 0 {
        let mut key_buf = vec![0u8; key_length as usize];
        cursor.read_exact(&mut key_buf).map_err(|e| e.to_string())?;
        Some(key_buf)
    } else {
        None
    };

    // Decode value
    let value_length = decode_varint(cursor)?;
    let value = if value_length >= 0 {
        let mut value_buf = vec![0u8; value_length as usize];
        cursor
            .read_exact(&mut value_buf)
            .map_err(|e| e.to_string())?;
        Some(value_buf)
    } else {
        None
    };

    // Decode headers
    let headers_count = decode_varint(cursor)?;
    let mut headers = Vec::new();
    for _ in 0..headers_count {
        let header_key_length = decode_varint(cursor)?;
        let mut header_key_buf = vec![0u8; header_key_length as usize];
        cursor
            .read_exact(&mut header_key_buf)
            .map_err(|e| e.to_string())?;
        let header_key = String::from_utf8(header_key_buf).map_err(|e| e.to_string())?;

        let header_value_length = decode_varint(cursor)?;
        let header_value = if header_value_length >= 0 {
            let mut header_value_buf = vec![0u8; header_value_length as usize];
            cursor
                .read_exact(&mut header_value_buf)
                .map_err(|e| e.to_string())?;
            Some(header_value_buf)
        } else {
            None
        };

        headers.push(RecordHeader {
            key_length: header_key_length,
            key: header_key,
            value_length: header_value_length,
            value: header_value,
        });
    }

    Ok(RecordV2 {
        length,
        attributes,
        timestamp_delta,
        offset_delta,
        key_length,
        key,
        value_length,
        value,
        headers,
    })
}

/// Encode a varint (zigzag encoded signed integer).
fn encode_varint(value: i32, buffer: &mut Vec<u8>) {
    let unsigned = ((value << 1) ^ (value >> 31)) as u32;
    encode_varint_u32(unsigned, buffer);
}

/// Encode a varint (zigzag encoded signed 64-bit integer).
fn encode_varint_i64(value: i64, buffer: &mut Vec<u8>) {
    let unsigned = ((value << 1) ^ (value >> 63)) as u64;
    encode_varint_u64(unsigned, buffer);
}

/// Encode an unsigned varint.
fn encode_varint_u32(mut value: u32, buffer: &mut Vec<u8>) {
    while value >= 0x80 {
        buffer.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

/// Encode an unsigned 64-bit varint.
fn encode_varint_u64(mut value: u64, buffer: &mut Vec<u8>) {
    while value >= 0x80 {
        buffer.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

/// Get the size of a varint encoding.
fn varint_size(value: i32) -> usize {
    let unsigned = ((value << 1) ^ (value >> 31)) as u32;
    if unsigned < 0x80 {
        1
    } else if unsigned < 0x4000 {
        2
    } else if unsigned < 0x200000 {
        3
    } else if unsigned < 0x10000000 {
        4
    } else {
        5
    }
}

/// Decode a varint.
fn decode_varint(cursor: &mut Cursor<&[u8]>) -> Result<i32, String> {
    let unsigned = decode_varint_u32(cursor)?;
    Ok(((unsigned >> 1) as i32) ^ (-((unsigned & 1) as i32)))
}

/// Decode a 64-bit varint.
fn decode_varint_i64(cursor: &mut Cursor<&[u8]>) -> Result<i64, String> {
    let unsigned = decode_varint_u64(cursor)?;
    Ok(((unsigned >> 1) as i64) ^ (-((unsigned & 1) as i64)))
}

/// Decode an unsigned varint.
fn decode_varint_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, String> {
    let mut result = 0u32;
    let mut shift = 0;

    for _ in 0..5 {
        // Max 5 bytes for u32 varint
        let byte = read_u8(cursor)?;
        result |= ((byte & 0x7F) as u32) << shift;
        if (byte & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }

    Err("Varint too long".to_string())
}

/// Decode an unsigned 64-bit varint.
fn decode_varint_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let mut result = 0u64;
    let mut shift = 0;

    for _ in 0..10 {
        // Max 10 bytes for u64 varint
        let byte = read_u8(cursor)?;
        result |= ((byte & 0x7F) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }

    Err("Varint too long".to_string())
}

// Helper functions for reading primitive types
fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, String> {
    let mut buf = [0u8; 1];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf[0])
}

fn read_i8(cursor: &mut Cursor<&[u8]>) -> Result<i8, String> {
    Ok(read_u8(cursor)? as i8)
}

fn read_i16(cursor: &mut Cursor<&[u8]>) -> Result<i16, String> {
    let mut buf = [0u8; 2];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(i16::from_be_bytes(buf))
}

fn read_i32(cursor: &mut Cursor<&[u8]>) -> Result<i32, String> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(i32::from_be_bytes(buf))
}

fn read_i64(cursor: &mut Cursor<&[u8]>) -> Result<i64, String> {
    let mut buf = [0u8; 8];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(i64::from_be_bytes(buf))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, String> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(u32::from_be_bytes(buf))
}
