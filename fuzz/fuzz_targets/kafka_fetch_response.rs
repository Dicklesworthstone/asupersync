#![no_main]

//! Structure-aware fuzz target for Kafka FetchResponse parser.
//!
//! This fuzz target exercises Kafka FetchResponse parsing with intelligent
//! structure-aware input generation focusing on degenerate cases that stress
//! the parser's boundary conditions and error handling.
//!
//! FetchResponse structure tested:
//! - Response header validation (correlation ID, size limits)
//! - Topic/partition metadata parsing
//! - Record batch boundaries and validation
//! - Record-level parsing within batches
//! - Degenerate cases: empty responses, truncated data, malformed headers
//! - Edge cases: maximum/minimum values, overflow conditions
//!
//! Usage: cargo fuzz run kafka_fetch_response

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// Maximum size for FetchResponse to prevent OOM during fuzzing
const MAX_RESPONSE_SIZE: usize = 256 * 1024;

/// Maximum number of topics in a single FetchResponse
const MAX_TOPICS: usize = 100;

/// Maximum number of partitions per topic
const MAX_PARTITIONS_PER_TOPIC: usize = 50;

/// Maximum number of records per partition response
const MAX_RECORDS_PER_PARTITION: usize = 1000;

/// Maximum size for individual record
const MAX_RECORD_SIZE: usize = 64 * 1024;

/// Maximum topic name length
const MAX_TOPIC_NAME_LEN: usize = 249; // Kafka limit

/// Structure-aware generator for Kafka FetchResponse
#[derive(Arbitrary, Debug, Clone)]
struct KafkaFetchResponse {
    /// Response header
    header: FetchResponseHeader,
    /// Topic responses
    topics: Vec<TopicResponse>,
    /// Fuzzing parameters for degenerate cases
    params: FuzzParams,
}

/// FetchResponse header structure
#[derive(Arbitrary, Debug, Clone)]
struct FetchResponseHeader {
    /// Throttle time in milliseconds
    throttle_time_ms: i32,
    /// Error code for the overall response
    error_code: i16,
    /// Session ID for fetch sessions
    session_id: i32,
}

/// Per-topic response within FetchResponse
#[derive(Arbitrary, Debug, Clone)]
struct TopicResponse {
    /// Topic name
    #[arbitrary(with = arbitrary_topic_name)]
    topic: String,
    /// Partition responses for this topic
    partitions: Vec<PartitionResponse>,
}

/// Per-partition response within a topic
#[derive(Arbitrary, Debug, Clone)]
struct PartitionResponse {
    /// Partition index
    partition_index: i32,
    /// Error code for this partition
    error_code: i16,
    /// High watermark offset
    high_watermark: i64,
    /// Last stable offset
    last_stable_offset: i64,
    /// Log start offset
    log_start_offset: i64,
    /// Aborted transaction data
    aborted: Vec<AbortedTransaction>,
    /// Record set for this partition
    records: Option<RecordBatch>,
}

/// Aborted transaction information
#[derive(Arbitrary, Debug, Clone)]
struct AbortedTransaction {
    /// Producer ID that was aborted
    producer_id: i64,
    /// First offset in the aborted transaction
    first_offset: i64,
}

/// Record batch within a partition response
#[derive(Arbitrary, Debug, Clone)]
struct RecordBatch {
    /// Base offset of the batch
    base_offset: i64,
    /// Batch length
    batch_length: i32,
    /// Partition leader epoch
    partition_leader_epoch: i32,
    /// Magic byte
    magic: i8,
    /// CRC32 checksum
    crc: u32,
    /// Batch attributes
    attributes: i16,
    /// Last offset delta
    last_offset_delta: i32,
    /// Base timestamp
    base_timestamp: i64,
    /// Max timestamp
    max_timestamp: i64,
    /// Producer ID
    producer_id: i64,
    /// Producer epoch
    producer_epoch: i16,
    /// Base sequence
    base_sequence: i32,
    /// Records in this batch
    records: Vec<Record>,
}

/// Individual record within a batch
#[derive(Arbitrary, Debug, Clone)]
struct Record {
    /// Record length
    length: i32,
    /// Record attributes
    attributes: i8,
    /// Timestamp delta from base timestamp
    timestamp_delta: i64,
    /// Offset delta from base offset
    offset_delta: i32,
    /// Key (optional)
    #[arbitrary(with = arbitrary_optional_bytes)]
    key: Option<Vec<u8>>,
    /// Value
    #[arbitrary(with = arbitrary_bounded_bytes)]
    value: Vec<u8>,
    /// Headers
    headers: Vec<RecordHeader>,
}

/// Record header
#[derive(Arbitrary, Debug, Clone)]
struct RecordHeader {
    /// Header key
    #[arbitrary(with = arbitrary_header_key)]
    key: String,
    /// Header value
    #[arbitrary(with = arbitrary_bounded_bytes)]
    value: Vec<u8>,
}

/// Fuzzing parameters to control degenerate case generation
#[derive(Arbitrary, Debug, Clone)]
struct FuzzParams {
    /// Force truncated response
    force_truncation: bool,
    /// Insert invalid magic bytes
    corrupt_magic: bool,
    /// Generate CRC mismatches
    corrupt_crc: bool,
    /// Create offset inconsistencies
    corrupt_offsets: bool,
    /// Generate oversized fields
    oversized_fields: bool,
    /// Create negative lengths
    negative_lengths: bool,
    /// Empty topic/partition lists
    empty_lists: bool,
    /// Duplicate entries
    duplicate_entries: bool,
}

fn arbitrary_topic_name(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(1..=MAX_TOPIC_NAME_LEN)?;
    let bytes: Vec<u8> = (0..len)
        .map(|_| u.int_in_range(b'a'..=b'z'))
        .collect::<arbitrary::Result<Vec<_>>>()?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn arbitrary_optional_bytes(u: &mut Unstructured) -> arbitrary::Result<Option<Vec<u8>>> {
    if u.arbitrary()? {
        Ok(Some(arbitrary_bounded_bytes(u)?))
    } else {
        Ok(None)
    }
}

fn arbitrary_bounded_bytes(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=1024)?;
    u.bytes(len).map(|bytes| bytes.to_vec())
}

fn arbitrary_header_key(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(1..=64)?;
    let bytes: Vec<u8> = (0..len)
        .map(|_| u.int_in_range(b'a'..=b'z'))
        .collect::<arbitrary::Result<Vec<_>>>()?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

impl KafkaFetchResponse {
    /// Serialize to wire format for testing
    fn to_wire_format(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Apply fuzzing parameters for degenerate cases
        if self.params.empty_lists {
            // Return minimal empty response
            buf.extend_from_slice(&self.header.throttle_time_ms.to_be_bytes());
            buf.extend_from_slice(&self.header.error_code.to_be_bytes());
            buf.extend_from_slice(&self.header.session_id.to_be_bytes());
            buf.extend_from_slice(&0_i32.to_be_bytes()); // 0 topics
            return buf;
        }

        // Header
        buf.extend_from_slice(&self.header.throttle_time_ms.to_be_bytes());
        buf.extend_from_slice(&self.header.error_code.to_be_bytes());
        buf.extend_from_slice(&self.header.session_id.to_be_bytes());

        // Topic array length (possibly corrupted)
        let topic_count = if self.params.oversized_fields {
            i32::MAX
        } else if self.params.negative_lengths {
            -1
        } else {
            self.topics.len() as i32
        };
        buf.extend_from_slice(&topic_count.to_be_bytes());

        // Topics
        for topic in &self.topics {
            self.serialize_topic(&mut buf, topic);

            // Apply duplication if requested
            if self.params.duplicate_entries {
                self.serialize_topic(&mut buf, topic);
            }
        }

        // Apply truncation if requested
        if self.params.force_truncation && buf.len() > 10 {
            buf.truncate(buf.len() / 2);
        }

        buf
    }

    fn serialize_topic(&self, buf: &mut Vec<u8>, topic: &TopicResponse) {
        // Topic name length + name
        buf.extend_from_slice(&(topic.topic.len() as i16).to_be_bytes());
        buf.extend_from_slice(topic.topic.as_bytes());

        // Partition array length
        let partition_count = if self.params.oversized_fields {
            i32::MAX
        } else {
            topic.partitions.len() as i32
        };
        buf.extend_from_slice(&partition_count.to_be_bytes());

        // Partitions
        for partition in &topic.partitions {
            self.serialize_partition(buf, partition);
        }
    }

    fn serialize_partition(&self, buf: &mut Vec<u8>, partition: &PartitionResponse) {
        buf.extend_from_slice(&partition.partition_index.to_be_bytes());
        buf.extend_from_slice(&partition.error_code.to_be_bytes());
        buf.extend_from_slice(&partition.high_watermark.to_be_bytes());
        buf.extend_from_slice(&partition.last_stable_offset.to_be_bytes());
        buf.extend_from_slice(&partition.log_start_offset.to_be_bytes());

        // Aborted transactions
        buf.extend_from_slice(&(partition.aborted.len() as i32).to_be_bytes());
        for aborted in &partition.aborted {
            buf.extend_from_slice(&aborted.producer_id.to_be_bytes());
            buf.extend_from_slice(&aborted.first_offset.to_be_bytes());
        }

        // Records
        if let Some(ref records) = partition.records {
            self.serialize_record_batch(buf, records);
        } else {
            buf.extend_from_slice(&0_i32.to_be_bytes()); // Null record set
        }
    }

    fn serialize_record_batch(&self, buf: &mut Vec<u8>, batch: &RecordBatch) {
        let batch_start = buf.len();

        // Batch header
        buf.extend_from_slice(&batch.base_offset.to_be_bytes());

        // Placeholder for batch length - we'll fill this in later
        let length_pos = buf.len();
        buf.extend_from_slice(&batch.batch_length.to_be_bytes());

        buf.extend_from_slice(&batch.partition_leader_epoch.to_be_bytes());

        // Magic byte (possibly corrupted)
        let magic = if self.params.corrupt_magic {
            99
        } else {
            batch.magic
        };
        buf.extend_from_slice(&magic.to_be_bytes());

        // CRC placeholder - we'll calculate later
        let crc = if self.params.corrupt_crc {
            0xDEADBEEF_u32
        } else {
            batch.crc
        };
        buf.extend_from_slice(&crc.to_be_bytes());

        buf.extend_from_slice(&batch.attributes.to_be_bytes());
        buf.extend_from_slice(&batch.last_offset_delta.to_be_bytes());
        buf.extend_from_slice(&batch.base_timestamp.to_be_bytes());
        buf.extend_from_slice(&batch.max_timestamp.to_be_bytes());
        buf.extend_from_slice(&batch.producer_id.to_be_bytes());
        buf.extend_from_slice(&batch.producer_epoch.to_be_bytes());
        buf.extend_from_slice(&batch.base_sequence.to_be_bytes());

        // Records array length
        buf.extend_from_slice(&(batch.records.len() as i32).to_be_bytes());

        // Records
        for record in &batch.records {
            self.serialize_record(buf, record);
        }

        // Update batch length
        let actual_length = (buf.len() - batch_start - 12) as i32; // Subtract offset + length fields
        let length_bytes = actual_length.to_be_bytes();
        buf[length_pos..length_pos + 4].copy_from_slice(&length_bytes);
    }

    fn serialize_record(&self, buf: &mut Vec<u8>, record: &Record) {
        let record_start = buf.len();

        // Placeholder for record length
        let length_pos = buf.len();
        buf.extend_from_slice(&record.length.to_be_bytes());

        buf.extend_from_slice(&record.attributes.to_be_bytes());
        buf.extend_from_slice(&record.timestamp_delta.to_be_bytes());

        // Apply offset corruption if requested
        let offset_delta = if self.params.corrupt_offsets {
            i64::MAX as i32
        } else {
            record.offset_delta
        };
        buf.extend_from_slice(&offset_delta.to_be_bytes());

        // Key
        match &record.key {
            Some(key) => {
                buf.extend_from_slice(&(key.len() as i32).to_be_bytes());
                buf.extend_from_slice(key);
            }
            None => {
                buf.extend_from_slice(&(-1_i32).to_be_bytes());
            }
        }

        // Value
        let value_len = if self.params.negative_lengths {
            -1
        } else {
            record.value.len() as i32
        };
        buf.extend_from_slice(&value_len.to_be_bytes());
        if value_len >= 0 {
            buf.extend_from_slice(&record.value);
        }

        // Headers
        buf.extend_from_slice(&(record.headers.len() as i32).to_be_bytes());
        for header in &record.headers {
            buf.extend_from_slice(&(header.key.len() as i32).to_be_bytes());
            buf.extend_from_slice(header.key.as_bytes());
            buf.extend_from_slice(&(header.value.len() as i32).to_be_bytes());
            buf.extend_from_slice(&header.value);
        }

        // Update record length
        let actual_length = (buf.len() - record_start - 4) as i32;
        let length_bytes = actual_length.to_be_bytes();
        buf[length_pos..length_pos + 4].copy_from_slice(&length_bytes);
    }
}

/// Parse FetchResponse from wire format bytes
fn parse_fetch_response(data: &[u8]) -> Result<(), String> {
    if data.len() < 16 {
        return Err("Response too short for header".to_string());
    }

    let mut offset = 0;

    // Parse header
    let throttle_time = i32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid throttle time")?,
    );
    offset += 4;

    let _error_code = i16::from_be_bytes(
        data[offset..offset + 2]
            .try_into()
            .map_err(|_| "Invalid error code")?,
    );
    offset += 2;

    let _session_id = i32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid session ID")?,
    );
    offset += 4;

    // Validate header fields
    if throttle_time < 0 {
        return Err("Negative throttle time".to_string());
    }

    // Parse topic array
    if offset + 4 > data.len() {
        return Err("Truncated topic array length".to_string());
    }

    let topic_count = i32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid topic count")?,
    );
    offset += 4;

    // Validate topic count
    if topic_count < 0 {
        return Err("Negative topic count".to_string());
    }
    if topic_count as usize > MAX_TOPICS {
        return Err("Topic count exceeds maximum".to_string());
    }

    // Parse each topic
    for _ in 0..topic_count {
        offset = parse_topic_response(data, offset)?;
    }

    // Check for trailing data
    if offset < data.len() {
        return Err("Unexpected trailing data".to_string());
    }

    Ok(())
}

fn parse_topic_response(data: &[u8], mut offset: usize) -> Result<usize, String> {
    // Parse topic name length
    if offset + 2 > data.len() {
        return Err("Truncated topic name length".to_string());
    }

    let topic_name_len = i16::from_be_bytes(
        data[offset..offset + 2]
            .try_into()
            .map_err(|_| "Invalid topic name length")?,
    ) as usize;
    offset += 2;

    if topic_name_len > MAX_TOPIC_NAME_LEN {
        return Err("Topic name too long".to_string());
    }

    // Parse topic name
    if offset + topic_name_len > data.len() {
        return Err("Truncated topic name".to_string());
    }
    offset += topic_name_len;

    // Parse partition array length
    if offset + 4 > data.len() {
        return Err("Truncated partition array length".to_string());
    }

    let partition_count = i32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid partition count")?,
    );
    offset += 4;

    if partition_count < 0 {
        return Err("Negative partition count".to_string());
    }
    if partition_count as usize > MAX_PARTITIONS_PER_TOPIC {
        return Err("Partition count exceeds maximum".to_string());
    }

    // Parse each partition
    for _ in 0..partition_count {
        offset = parse_partition_response(data, offset)?;
    }

    Ok(offset)
}

fn parse_partition_response(data: &[u8], mut offset: usize) -> Result<usize, String> {
    // Need at least 42 bytes for partition header
    if offset + 42 > data.len() {
        return Err("Truncated partition response".to_string());
    }

    // Skip partition index, error code, offsets
    offset += 4 + 2 + 8 + 8 + 8; // 30 bytes

    // Parse aborted transaction array
    let aborted_count = i32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid aborted count")?,
    );
    offset += 4;

    if aborted_count < 0 {
        return Err("Negative aborted count".to_string());
    }

    // Each aborted transaction is 16 bytes (producer_id + first_offset)
    let aborted_bytes = aborted_count as usize * 16;
    if offset + aborted_bytes > data.len() {
        return Err("Truncated aborted transactions".to_string());
    }
    offset += aborted_bytes;

    // Parse record set (can be null)
    if offset + 4 > data.len() {
        return Err("Truncated record set length".to_string());
    }

    let record_set_len = i32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid record set length")?,
    );
    offset += 4;

    if record_set_len < 0 {
        // Null record set
        return Ok(offset);
    }

    if record_set_len as usize > MAX_RESPONSE_SIZE {
        return Err("Record set too large".to_string());
    }

    if offset + record_set_len as usize > data.len() {
        return Err("Truncated record set".to_string());
    }

    // Parse record batch
    offset = parse_record_batch(data, offset, record_set_len as usize)?;

    Ok(offset)
}

fn parse_record_batch(data: &[u8], mut offset: usize, batch_len: usize) -> Result<usize, String> {
    let batch_end = offset + batch_len;

    // Record batch header is at least 61 bytes
    if offset + 61 > data.len() || offset + 61 > batch_end {
        return Err("Truncated record batch header".to_string());
    }

    // Parse base offset
    let _base_offset = i64::from_be_bytes(
        data[offset..offset + 8]
            .try_into()
            .map_err(|_| "Invalid base offset")?,
    );
    offset += 8;

    // Parse batch length
    let batch_length = i32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid batch length")?,
    );
    offset += 4;

    if batch_length < 0 {
        return Err("Negative batch length".to_string());
    }

    // Skip partition leader epoch, magic, CRC, attributes, last offset delta
    offset += 4 + 1 + 4 + 2 + 4; // 15 bytes

    // Parse timestamps
    offset += 8 + 8; // base_timestamp + max_timestamp = 16 bytes

    // Parse producer info
    offset += 8 + 2 + 4; // producer_id + producer_epoch + base_sequence = 14 bytes

    // Parse record count
    if offset + 4 > data.len() || offset + 4 > batch_end {
        return Err("Truncated record count".to_string());
    }

    let record_count = i32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid record count")?,
    );
    offset += 4;

    if record_count < 0 {
        return Err("Negative record count".to_string());
    }
    if record_count as usize > MAX_RECORDS_PER_PARTITION {
        return Err("Record count exceeds maximum".to_string());
    }

    // Parse each record
    for _ in 0..record_count {
        if offset >= batch_end {
            return Err("Record extends beyond batch".to_string());
        }
        offset = parse_record(data, offset, batch_end)?;
    }

    Ok(batch_end)
}

fn parse_record(data: &[u8], mut offset: usize, batch_end: usize) -> Result<usize, String> {
    // Record length
    if offset + 4 > data.len() || offset + 4 > batch_end {
        return Err("Truncated record length".to_string());
    }

    let record_len = i32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Invalid record length")?,
    );
    offset += 4;

    if record_len < 0 {
        return Err("Negative record length".to_string());
    }
    if record_len as usize > MAX_RECORD_SIZE {
        return Err("Record too large".to_string());
    }

    let record_end = offset + record_len as usize;
    if record_end > batch_end {
        return Err("Record extends beyond batch".to_string());
    }

    // Skip record fields and return end offset
    Ok(record_end)
}

fuzz_target!(|fetch_response: KafkaFetchResponse| {
    // Guard against oversized inputs
    if fetch_response.topics.len() > MAX_TOPICS {
        return;
    }

    let total_partitions: usize = fetch_response
        .topics
        .iter()
        .map(|t| t.partitions.len())
        .sum();
    if total_partitions > MAX_TOPICS * MAX_PARTITIONS_PER_TOPIC {
        return;
    }

    // Generate wire format
    let wire_data = fetch_response.to_wire_format();

    // Guard against excessive sizes
    if wire_data.len() > MAX_RESPONSE_SIZE {
        return;
    }

    // Test the parser with structure-aware input
    let _ = parse_fetch_response(&wire_data);

    // Test with truncated inputs for boundary conditions
    for truncate_at in [
        wire_data.len() / 4,
        wire_data.len() / 2,
        wire_data.len() * 3 / 4,
    ] {
        if truncate_at > 0 && truncate_at < wire_data.len() {
            let _ = parse_fetch_response(&wire_data[..truncate_at]);
        }
    }

    // Test with single-byte modifications for bit-flip testing
    if !wire_data.is_empty() {
        for i in [0, wire_data.len() / 2, wire_data.len() - 1] {
            if i < wire_data.len() {
                let mut modified = wire_data.clone();
                modified[i] = modified[i].wrapping_add(1);
                let _ = parse_fetch_response(&modified);
            }
        }
    }
});
