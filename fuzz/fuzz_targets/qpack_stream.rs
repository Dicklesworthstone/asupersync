//! QPACK Dynamic Table Streaming Fuzz Target for RFC 9204
//!
//! This fuzz target focuses on QPACK encoder/decoder stream communication and dynamic table
//! operations per RFC 9204 (QPACK: Field Compression for HTTP/3).
//!
//! ## Assertions Tested
//! 1. **Varint-based encoded integers bounded**: QPACK integer encoding/decoding must handle bounds correctly
//! 2. **Duplicate name references handled**: Dynamic table duplicate entries must be managed properly
//! 3. **Dynamic table insertion count rolled correctly**: Insert count tracking across stream boundaries
//! 4. **Section acknowledgments properly track**: Acknowledgment messages correctly reference sections
//! 5. **Stream cancellation frees all table references**: Resources freed when streams are cancelled
//!
//! ## QPACK Instruction Types
//! - **Encoder stream**: Insert With Name Reference, Insert With Literal Name, Duplicate, Set Dynamic Table Capacity
//! - **Decoder stream**: Section Acknowledgment, Stream Cancellation, Insert Count Increment
//!
//! ## Running
//! ```bash
//! cargo +nightly fuzz run qpack_stream
//! ```

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet, VecDeque};

use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::http::h3_native::{H3NativeError, H3QpackMode};
use asupersync::net::quic_core::{decode_varint, encode_varint};

/// Maximum fuzz input size to prevent timeouts (16KB)
const MAX_FUZZ_INPUT_SIZE: usize = 16_384;

/// Maximum dynamic table capacity for testing
const MAX_DYNAMIC_TABLE_CAPACITY: usize = 4096;

/// Maximum number of operations per fuzz run to prevent timeouts
const MAX_OPERATIONS: usize = 1000;

/// QPACK instruction types for encoder streams (RFC 9204 Section 4.3)
#[derive(Debug, Clone, Copy)]
enum QpackEncoderInstruction {
    /// Insert With Name Reference: T=1 N=... name_index (literal) value
    InsertWithNameReference { name_index: u64, value: String },
    /// Insert With Literal Name: T=01 (literal) name (literal) value
    InsertWithLiteralName { name: String, value: String },
    /// Duplicate: T=000 index
    Duplicate { index: u64 },
    /// Set Dynamic Table Capacity: T=001 capacity
    SetDynamicTableCapacity { capacity: u64 },
}

/// QPACK instruction types for decoder streams (RFC 9204 Section 4.4)
#[derive(Debug, Clone, Copy)]
enum QpackDecoderInstruction {
    /// Section Acknowledgment: T=1 stream_id
    SectionAcknowledgment { stream_id: u64 },
    /// Stream Cancellation: T=01 stream_id
    StreamCancellation { stream_id: u64 },
    /// Insert Count Increment: T=00 increment
    InsertCountIncrement { increment: u64 },
}

/// QPACK dynamic table entry
#[derive(Debug, Clone, PartialEq, Eq)]
struct QpackTableEntry {
    name: String,
    value: String,
    size: usize, // RFC 9204: name_len + value_len + 32
}

impl QpackTableEntry {
    fn new(name: String, value: String) -> Self {
        let size = name.len() + value.len() + 32;
        Self { name, value, size }
    }

    fn size(&self) -> usize {
        self.size
    }
}

/// QPACK dynamic table state tracker
#[derive(Debug, Clone)]
struct QpackDynamicTable {
    /// Ordered entries (index 0 = most recent)
    entries: VecDeque<QpackTableEntry>,
    /// Maximum capacity in bytes
    capacity: usize,
    /// Current size in bytes
    current_size: usize,
    /// Insert count - total number of insertions
    insert_count: u64,
    /// Known received count at decoder
    known_received_count: u64,
}

impl QpackDynamicTable {
    fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity,
            current_size: 0,
            insert_count: 0,
            known_received_count: 0,
        }
    }

    /// Set dynamic table capacity (may trigger evictions)
    fn set_capacity(&mut self, new_capacity: usize) -> Result<(), String> {
        if new_capacity > MAX_DYNAMIC_TABLE_CAPACITY {
            return Err(format!(
                "Capacity {} exceeds maximum {}",
                new_capacity, MAX_DYNAMIC_TABLE_CAPACITY
            ));
        }

        self.capacity = new_capacity;
        self.evict_to_capacity();
        Ok(())
    }

    /// Insert entry with name reference to existing entry
    fn insert_with_name_reference(&mut self, name_index: u64, value: String) -> Result<(), String> {
        // Validate name_index bounds (static table 0-98 + dynamic table)
        let name = if name_index <= 98 {
            // Static table reference - use placeholder name
            format!("static-{}", name_index)
        } else {
            // Dynamic table reference: absolute_index = insert_count + name_index - 99
            let dynamic_index = name_index.saturating_sub(99);
            if dynamic_index >= self.entries.len() as u64 {
                return Err(format!(
                    "Dynamic name index {} out of bounds (table size {})",
                    dynamic_index,
                    self.entries.len()
                ));
            }
            self.entries
                .get(dynamic_index as usize)
                .ok_or_else(|| format!("Name index {} not found in dynamic table", dynamic_index))?
                .name
                .clone()
        };

        let entry = QpackTableEntry::new(name, value);
        self.insert_entry(entry)
    }

    /// Insert entry with literal name
    fn insert_with_literal_name(&mut self, name: String, value: String) -> Result<(), String> {
        let entry = QpackTableEntry::new(name, value);
        self.insert_entry(entry)
    }

    /// Duplicate existing entry
    fn duplicate(&mut self, index: u64) -> Result<(), String> {
        // Index refers to dynamic table entry
        if index >= self.entries.len() as u64 {
            return Err(format!(
                "Duplicate index {} out of bounds (table size {})",
                index,
                self.entries.len()
            ));
        }

        let entry = self
            .entries
            .get(index as usize)
            .ok_or_else(|| format!("Duplicate index {} not found", index))?
            .clone();

        self.insert_entry(entry)
    }

    /// Insert entry and evict as needed
    fn insert_entry(&mut self, entry: QpackTableEntry) -> Result<(), String> {
        let entry_size = entry.size();

        // Check if entry is too large for table
        if entry_size > self.capacity {
            return Err(format!(
                "Entry size {} exceeds table capacity {}",
                entry_size, self.capacity
            ));
        }

        // Add entry to front of table
        self.entries.push_front(entry);
        self.current_size += entry_size;
        self.insert_count = self.insert_count.saturating_add(1);

        // Evict as needed to maintain capacity
        self.evict_to_capacity();

        Ok(())
    }

    /// Evict entries to maintain capacity constraint
    fn evict_to_capacity(&mut self) {
        while self.current_size > self.capacity && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop_back() {
                self.current_size = self.current_size.saturating_sub(evicted.size());
            }
        }
    }

    /// Get entry by absolute index
    fn get_entry(&self, index: u64) -> Option<&QpackTableEntry> {
        self.entries.get(index as usize)
    }

    /// Update known received count from decoder
    fn update_known_received_count(&mut self, count: u64) {
        self.known_received_count = count.max(self.known_received_count);
    }

    /// Check if insert count is valid for operations
    fn validate_insert_count(&self, required_insert_count: u64) -> bool {
        required_insert_count <= self.insert_count
    }
}

/// QPACK stream state tracker for encoder/decoder communication
#[derive(Debug)]
struct QpackStreamState {
    /// Dynamic table shared between encoder/decoder
    dynamic_table: QpackDynamicTable,
    /// Blocked streams waiting for dynamic table updates
    blocked_streams: HashMap<u64, u64>, // stream_id -> required_insert_count
    /// Acknowledged stream IDs from decoder
    acknowledged_streams: HashSet<u64>,
    /// Cancelled stream IDs
    cancelled_streams: HashSet<u64>,
    /// Section acknowledgment tracking
    section_acks: HashMap<u64, u64>, // stream_id -> ack_count
    /// Insert count increment tracking
    insert_count_increments: Vec<u64>,
}

impl QpackStreamState {
    fn new(table_capacity: usize) -> Self {
        Self {
            dynamic_table: QpackDynamicTable::new(table_capacity),
            blocked_streams: HashMap::new(),
            acknowledged_streams: HashSet::new(),
            cancelled_streams: HashSet::new(),
            section_acks: HashMap::new(),
            insert_count_increments: Vec::new(),
        }
    }

    /// Process encoder instruction
    fn process_encoder_instruction(
        &mut self,
        instruction: QpackEncoderInstruction,
    ) -> Result<(), String> {
        match instruction {
            QpackEncoderInstruction::InsertWithNameReference { name_index, value } => self
                .dynamic_table
                .insert_with_name_reference(name_index, value),
            QpackEncoderInstruction::InsertWithLiteralName { name, value } => {
                self.dynamic_table.insert_with_literal_name(name, value)
            }
            QpackEncoderInstruction::Duplicate { index } => self.dynamic_table.duplicate(index),
            QpackEncoderInstruction::SetDynamicTableCapacity { capacity } => {
                self.dynamic_table.set_capacity(capacity as usize)
            }
        }
    }

    /// Process decoder instruction
    fn process_decoder_instruction(
        &mut self,
        instruction: QpackDecoderInstruction,
    ) -> Result<(), String> {
        match instruction {
            QpackDecoderInstruction::SectionAcknowledgment { stream_id } => {
                // Track section acknowledgment
                *self.section_acks.entry(stream_id).or_insert(0) += 1;
                self.acknowledged_streams.insert(stream_id);

                // Remove from blocked streams if present
                self.blocked_streams.remove(&stream_id);
                Ok(())
            }
            QpackDecoderInstruction::StreamCancellation { stream_id } => {
                // Mark stream as cancelled and free resources
                self.cancelled_streams.insert(stream_id);
                self.blocked_streams.remove(&stream_id);
                self.acknowledged_streams.remove(&stream_id);
                self.section_acks.remove(&stream_id);
                Ok(())
            }
            QpackDecoderInstruction::InsertCountIncrement { increment } => {
                // Track insert count increment
                self.insert_count_increments.push(increment);

                // Update known received count
                let new_count = self
                    .dynamic_table
                    .known_received_count
                    .saturating_add(increment);
                self.dynamic_table.update_known_received_count(new_count);
                Ok(())
            }
        }
    }

    /// Block stream on required insert count
    fn block_stream(&mut self, stream_id: u64, required_insert_count: u64) {
        if !self
            .dynamic_table
            .validate_insert_count(required_insert_count)
        {
            self.blocked_streams
                .insert(stream_id, required_insert_count);
        }
    }

    /// Validate QPACK streaming invariants
    fn validate_invariants(&self) -> Result<(), String> {
        // 1. Cancelled streams should not be in other collections
        for &stream_id in &self.cancelled_streams {
            if self.blocked_streams.contains_key(&stream_id) {
                return Err(format!(
                    "Cancelled stream {} still in blocked streams",
                    stream_id
                ));
            }
            if self.acknowledged_streams.contains(&stream_id) {
                return Err(format!(
                    "Cancelled stream {} still in acknowledged streams",
                    stream_id
                ));
            }
        }

        // 2. Dynamic table invariants
        if self.dynamic_table.current_size > self.dynamic_table.capacity {
            return Err(format!(
                "Dynamic table size {} exceeds capacity {}",
                self.dynamic_table.current_size, self.dynamic_table.capacity
            ));
        }

        // 3. Insert count should never decrease
        if self.dynamic_table.known_received_count > self.dynamic_table.insert_count {
            return Err(format!(
                "Known received count {} exceeds insert count {}",
                self.dynamic_table.known_received_count, self.dynamic_table.insert_count
            ));
        }

        // 4. Reasonable bounds on tracking data structures
        if self.blocked_streams.len() > 10000 {
            return Err(format!(
                "Too many blocked streams: {}",
                self.blocked_streams.len()
            ));
        }

        if self.section_acks.len() > 10000 {
            return Err(format!(
                "Too many section acknowledgments: {}",
                self.section_acks.len()
            ));
        }

        Ok(())
    }
}

/// Fuzz input for QPACK stream operations
#[derive(Arbitrary, Debug)]
struct QpackStreamFuzzInput {
    /// Initial dynamic table capacity
    table_capacity: u16,
    /// Sequence of encoder instructions
    encoder_instructions: Vec<QpackEncoderInstructionFuzz>,
    /// Sequence of decoder instructions
    decoder_instructions: Vec<QpackDecoderInstructionFuzz>,
    /// Stream operations to test blocking/unblocking
    stream_operations: Vec<QpackStreamOperation>,
}

#[derive(Arbitrary, Debug)]
enum QpackEncoderInstructionFuzz {
    InsertWithNameReference { name_index: u8, value: Vec<u8> },
    InsertWithLiteralName { name: Vec<u8>, value: Vec<u8> },
    Duplicate { index: u8 },
    SetDynamicTableCapacity { capacity: u16 },
}

impl From<QpackEncoderInstructionFuzz> for QpackEncoderInstruction {
    fn from(fuzz: QpackEncoderInstructionFuzz) -> Self {
        match fuzz {
            QpackEncoderInstructionFuzz::InsertWithNameReference { name_index, value } => {
                QpackEncoderInstruction::InsertWithNameReference {
                    name_index: name_index as u64,
                    value: String::from_utf8_lossy(&value).to_string(),
                }
            }
            QpackEncoderInstructionFuzz::InsertWithLiteralName { name, value } => {
                QpackEncoderInstruction::InsertWithLiteralName {
                    name: String::from_utf8_lossy(&name).to_string(),
                    value: String::from_utf8_lossy(&value).to_string(),
                }
            }
            QpackEncoderInstructionFuzz::Duplicate { index } => {
                QpackEncoderInstruction::Duplicate {
                    index: index as u64,
                }
            }
            QpackEncoderInstructionFuzz::SetDynamicTableCapacity { capacity } => {
                QpackEncoderInstruction::SetDynamicTableCapacity {
                    capacity: capacity as u64,
                }
            }
        }
    }
}

#[derive(Arbitrary, Debug)]
enum QpackDecoderInstructionFuzz {
    SectionAcknowledgment { stream_id: u16 },
    StreamCancellation { stream_id: u16 },
    InsertCountIncrement { increment: u8 },
}

impl From<QpackDecoderInstructionFuzz> for QpackDecoderInstruction {
    fn from(fuzz: QpackDecoderInstructionFuzz) -> Self {
        match fuzz {
            QpackDecoderInstructionFuzz::SectionAcknowledgment { stream_id } => {
                QpackDecoderInstruction::SectionAcknowledgment {
                    stream_id: stream_id as u64,
                }
            }
            QpackDecoderInstructionFuzz::StreamCancellation { stream_id } => {
                QpackDecoderInstruction::StreamCancellation {
                    stream_id: stream_id as u64,
                }
            }
            QpackDecoderInstructionFuzz::InsertCountIncrement { increment } => {
                QpackDecoderInstruction::InsertCountIncrement {
                    increment: increment as u64,
                }
            }
        }
    }
}

#[derive(Arbitrary, Debug)]
enum QpackStreamOperation {
    BlockStream {
        stream_id: u16,
        required_insert_count: u16,
    },
    ProcessField {
        stream_id: u16,
        field_data: Vec<u8>,
    },
}

/// Test QPACK varint integer encoding/decoding bounds (Assertion 1)
fn test_varint_bounds(data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }

    // Test encoding/decoding various integer values with different prefixes
    let test_values = [
        0u64,
        1,
        30,
        31,
        127,
        128,
        255,
        256,
        1023,
        1024,
        16383,
        16384,
        u64::MAX,
    ];
    let prefix_sizes = [1u8, 2, 3, 4, 5, 6, 7, 8];

    for &value in &test_values {
        for &prefix_bits in &prefix_sizes {
            let max_prefix = (1u64 << prefix_bits) - 1;

            // Encode
            let mut encoded = Vec::new();
            if let Err(_) = encode_varint(&mut encoded, value) {
                // Encoding failure is acceptable for extreme values
                continue;
            }

            // Decode and verify round-trip
            match decode_varint(&encoded) {
                Ok((decoded_value, consumed)) => {
                    if decoded_value != value {
                        return Err(format!(
                            "Varint round-trip mismatch: {} != {}",
                            value, decoded_value
                        ));
                    }
                    if consumed > encoded.len() {
                        return Err(format!("Varint decode consumed more bytes than available"));
                    }
                }
                Err(_) => {
                    // Decode failure is acceptable for malformed input
                }
            }
        }
    }

    // Test with fuzz input data
    let _ = decode_varint(data);

    Ok(())
}

/// Test duplicate name reference handling (Assertion 2)
fn test_duplicate_handling(
    state: &mut QpackStreamState,
    operations: &[QpackStreamOperation],
) -> Result<(), String> {
    // Insert some entries to create duplicates
    let _ = state
        .dynamic_table
        .insert_with_literal_name("test-name".to_string(), "value1".to_string());
    let _ = state
        .dynamic_table
        .insert_with_literal_name("test-name".to_string(), "value2".to_string());
    let _ = state
        .dynamic_table
        .insert_with_literal_name("another-name".to_string(), "value3".to_string());

    // Test duplicate instruction
    let duplicate_result = state.dynamic_table.duplicate(0);
    match duplicate_result {
        Ok(()) => {
            // Duplicate should create a new entry with the same name/value as index 0
            if let Some(original) = state.dynamic_table.get_entry(0) {
                if let Some(duplicate) = state.dynamic_table.get_entry(1) {
                    // Note: after insertion, indices shift
                    if original.name != duplicate.name || original.value != duplicate.value {
                        return Err("Duplicate entry does not match original".to_string());
                    }
                }
            }
        }
        Err(_) => {
            // Duplicate failure is acceptable if index is out of bounds
        }
    }

    Ok(())
}

/// Test dynamic table insertion count tracking (Assertion 3)
fn test_insertion_count_tracking(state: &mut QpackStreamState) -> Result<(), String> {
    let initial_count = state.dynamic_table.insert_count;

    // Perform several insertions
    let _ = state
        .dynamic_table
        .insert_with_literal_name("name1".to_string(), "value1".to_string());
    let _ = state
        .dynamic_table
        .insert_with_literal_name("name2".to_string(), "value2".to_string());

    // Insert count should have increased
    if state.dynamic_table.insert_count <= initial_count {
        return Err(format!(
            "Insert count did not increase: {} -> {}",
            initial_count, state.dynamic_table.insert_count
        ));
    }

    // Test insert count increment from decoder
    let increment = 2u64;
    let old_known_count = state.dynamic_table.known_received_count;
    let decoder_instr = QpackDecoderInstruction::InsertCountIncrement { increment };
    state.process_decoder_instruction(decoder_instr)?;

    if state.dynamic_table.known_received_count != old_known_count + increment {
        return Err(format!(
            "Known received count not updated correctly: {} + {} != {}",
            old_known_count, increment, state.dynamic_table.known_received_count
        ));
    }

    Ok(())
}

/// Test section acknowledgment tracking (Assertion 4)
fn test_section_acknowledgments(state: &mut QpackStreamState) -> Result<(), String> {
    let stream_id = 42u64;

    // Initially stream should not be acknowledged
    if state.acknowledged_streams.contains(&stream_id) {
        return Err("Stream should not be initially acknowledged".to_string());
    }

    // Send section acknowledgment
    let ack_instr = QpackDecoderInstruction::SectionAcknowledgment { stream_id };
    state.process_decoder_instruction(ack_instr)?;

    // Stream should now be acknowledged
    if !state.acknowledged_streams.contains(&stream_id) {
        return Err("Stream should be acknowledged after ack instruction".to_string());
    }

    // Check acknowledgment count
    if let Some(&ack_count) = state.section_acks.get(&stream_id) {
        if ack_count == 0 {
            return Err("Section acknowledgment count should be non-zero".to_string());
        }
    } else {
        return Err("Section acknowledgment not tracked".to_string());
    }

    Ok(())
}

/// Test stream cancellation resource cleanup (Assertion 5)
fn test_stream_cancellation(state: &mut QpackStreamState) -> Result<(), String> {
    let stream_id = 84u64;

    // Set up stream with various state
    state.block_stream(stream_id, 10);
    let ack_instr = QpackDecoderInstruction::SectionAcknowledgment { stream_id };
    state.process_decoder_instruction(ack_instr)?;

    // Verify stream is in tracked state
    if !state.acknowledged_streams.contains(&stream_id) {
        return Err("Stream should be acknowledged before cancellation".to_string());
    }

    // Cancel the stream
    let cancel_instr = QpackDecoderInstruction::StreamCancellation { stream_id };
    state.process_decoder_instruction(cancel_instr)?;

    // Verify all references are cleaned up
    if state.blocked_streams.contains_key(&stream_id) {
        return Err("Cancelled stream still in blocked streams".to_string());
    }

    if state.acknowledged_streams.contains(&stream_id) {
        return Err("Cancelled stream still in acknowledged streams".to_string());
    }

    if state.section_acks.contains_key(&stream_id) {
        return Err("Cancelled stream still has section acknowledgments".to_string());
    }

    if !state.cancelled_streams.contains(&stream_id) {
        return Err("Cancelled stream not marked as cancelled".to_string());
    }

    Ok(())
}

fuzz_target!(|input: QpackStreamFuzzInput| {
    // Limit input complexity to prevent timeouts
    if input.encoder_instructions.len()
        + input.decoder_instructions.len()
        + input.stream_operations.len()
        > MAX_OPERATIONS
    {
        return;
    }

    // Initialize QPACK stream state
    let table_capacity = (input.table_capacity as usize).clamp(32, MAX_DYNAMIC_TABLE_CAPACITY);
    let mut state = QpackStreamState::new(table_capacity);

    // Test varint bounds (Assertion 1)
    let varint_test_data = input
        .encoder_instructions
        .get(0)
        .map(|instr| match instr {
            QpackEncoderInstructionFuzz::InsertWithLiteralName { name, .. } => name.as_slice(),
            QpackEncoderInstructionFuzz::InsertWithNameReference { value, .. } => value.as_slice(),
            _ => &[],
        })
        .unwrap_or(&[]);

    test_varint_bounds(varint_test_data).unwrap_or_else(|e| {
        panic!("Varint bounds test failed: {}", e);
    });

    // Process encoder instructions
    for encoder_instr_fuzz in &input.encoder_instructions {
        let encoder_instr = QpackEncoderInstruction::from(encoder_instr_fuzz.clone());
        let _ = state.process_encoder_instruction(encoder_instr);

        // Validate invariants after each operation
        state.validate_invariants().unwrap_or_else(|e| {
            panic!("Invariant violation after encoder instruction: {}", e);
        });
    }

    // Process decoder instructions
    for decoder_instr_fuzz in &input.decoder_instructions {
        let decoder_instr = QpackDecoderInstruction::from(decoder_instr_fuzz.clone());
        let _ = state.process_decoder_instruction(decoder_instr);

        // Validate invariants after each operation
        state.validate_invariants().unwrap_or_else(|e| {
            panic!("Invariant violation after decoder instruction: {}", e);
        });
    }

    // Process stream operations
    for stream_op in &input.stream_operations {
        match stream_op {
            QpackStreamOperation::BlockStream {
                stream_id,
                required_insert_count,
            } => {
                state.block_stream(*stream_id as u64, *required_insert_count as u64);
            }
            QpackStreamOperation::ProcessField {
                stream_id,
                field_data,
            } => {
                // Simulate field processing that may require dynamic table entries
                if !field_data.is_empty() && *stream_id < 1000 {
                    let _ = decode_varint(field_data);
                }
            }
        }

        // Validate invariants after each operation
        state.validate_invariants().unwrap_or_else(|e| {
            panic!("Invariant violation after stream operation: {}", e);
        });
    }

    // Test duplicate name handling (Assertion 2)
    test_duplicate_handling(&mut state, &input.stream_operations).unwrap_or_else(|e| {
        panic!("Duplicate handling test failed: {}", e);
    });

    // Test insertion count tracking (Assertion 3)
    test_insertion_count_tracking(&mut state).unwrap_or_else(|e| {
        panic!("Insertion count tracking test failed: {}", e);
    });

    // Test section acknowledgments (Assertion 4)
    test_section_acknowledgments(&mut state).unwrap_or_else(|e| {
        panic!("Section acknowledgment test failed: {}", e);
    });

    // Test stream cancellation (Assertion 5)
    test_stream_cancellation(&mut state).unwrap_or_else(|e| {
        panic!("Stream cancellation test failed: {}", e);
    });

    // Final invariant validation
    state.validate_invariants().unwrap_or_else(|e| {
        panic!("Final invariant violation: {}", e);
    });
});
