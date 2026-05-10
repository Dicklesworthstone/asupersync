#![no_main]
#![allow(dead_code)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 HPACK header table size change test input
#[derive(Arbitrary, Debug)]
struct H2TableSizeChangeInput {
    /// Table size change sequence
    table_size_sequence: TableSizeSequence,
    /// Headers to send between size changes
    header_sequences: Vec<HeaderSequence>,
    /// HPACK encoding options
    encoding_options: HpackEncodingOptions,
    /// Test scenario configuration
    test_scenario: TestScenario,
}

#[derive(Arbitrary, Debug)]
struct TableSizeSequence {
    /// Initial table size (usually 4096)
    initial_size: u32,
    /// Sequence of size changes
    size_changes: Vec<TableSizeChange>,
    /// Whether to include size 0 reduction
    include_zero_reduction: bool,
    /// Final table size after all changes
    final_size: u32,
}

#[derive(Arbitrary, Debug)]
struct TableSizeChange {
    /// New table size
    new_size: u32,
    /// Change strategy
    change_type: SizeChangeType,
    /// Headers to send after this change
    headers_after: u8,
}

#[derive(Arbitrary, Debug)]
enum SizeChangeType {
    /// Gradual reduction
    Gradual,
    /// Immediate reduction to zero
    ImmediateZero,
    /// Increase after reduction
    IncreaseAfterReduction,
    /// Multiple rapid changes
    RapidChanges,
    /// Boundary value changes
    BoundaryValues,
}

#[derive(Arbitrary, Debug)]
struct HeaderSequence {
    /// Headers in this sequence
    headers: Vec<HeaderEntry>,
    /// Encoding strategy for this sequence
    encoding_strategy: HeaderEncodingStrategy,
    /// Whether to force dynamic table updates
    force_dynamic_updates: bool,
}

#[derive(Arbitrary, Debug)]
struct HeaderEntry {
    /// Header name
    name: HeaderName,
    /// Header value
    value: String,
    /// Indexing strategy
    indexing: IndexingStrategy,
}

#[derive(Arbitrary, Debug)]
enum HeaderName {
    /// Standard HTTP/2 pseudo-headers
    Method,
    Path,
    Scheme,
    Authority,
    /// Common headers that benefit from indexing
    ContentType,
    UserAgent,
    Accept,
    Authorization,
    /// Custom headers
    Custom(String),
}

#[derive(Arbitrary, Debug)]
enum IndexingStrategy {
    /// Literal with incremental indexing (added to table)
    LiteralIncremental,
    /// Literal without indexing (not added to table)
    LiteralNoIndexing,
    /// Literal never indexed (sensitive)
    LiteralNeverIndexed,
    /// Indexed reference (use existing table entry)
    Indexed(u8),
    /// Literal with incremental indexing (name from table)
    LiteralIncrementalIndexedName(u8),
}

#[derive(Arbitrary, Debug)]
enum HeaderEncodingStrategy {
    /// Maximize dynamic table usage
    MaximizeDynamic,
    /// Minimize dynamic table usage
    MinimizeDynamic,
    /// Mixed strategy
    Mixed,
    /// Force table growth
    ForceGrowth,
    /// Prepare for table reduction
    PrepareReduction,
}

#[derive(Arbitrary, Debug)]
struct HpackEncodingOptions {
    /// Huffman encoding preference
    huffman_encoding: HuffmanPreference,
    /// String literal encoding
    string_encoding: StringEncoding,
    /// Index encoding strategy
    index_encoding: IndexEncoding,
}

#[derive(Arbitrary, Debug)]
enum HuffmanPreference {
    /// Always use Huffman when beneficial
    Aggressive,
    /// Conservative Huffman usage
    Conservative,
    /// Never use Huffman
    Disabled,
    /// Mixed usage
    Mixed,
}

#[derive(Arbitrary, Debug)]
enum StringEncoding {
    /// Plain ASCII
    Plain,
    /// UTF-8 with special characters
    Utf8,
    /// Binary data
    Binary,
    /// Very long strings
    Long(u16),
}

#[derive(Arbitrary, Debug)]
enum IndexEncoding {
    /// Standard 7-bit integer encoding
    Standard,
    /// Test boundary cases (127, 128, etc.)
    Boundary,
    /// Large index values
    Large,
}

#[derive(Arbitrary, Debug)]
struct TestScenario {
    /// Connection state
    connection_state: ConnectionState,
    /// Whether to test eviction behavior
    test_eviction: bool,
    /// Whether to test table reconstruction
    test_reconstruction: bool,
    /// Memory pressure simulation
    memory_pressure: MemoryPressure,
}

#[derive(Arbitrary, Debug)]
enum ConnectionState {
    Fresh,
    ActiveStreams(u8),
    MidTransfer,
    HighThroughput,
}

#[derive(Arbitrary, Debug)]
enum MemoryPressure {
    Low,
    Medium,
    High,
    Critical,
}

/// Mock HPACK decoder with dynamic table management
struct MockHpackDecoder {
    dynamic_table: HpackDynamicTable,
    static_table: HpackStaticTable,
    max_table_size: u32,
    encoding_context: EncodingContext,
}

#[derive(Debug, Clone)]
struct HpackDynamicTable {
    entries: Vec<HpackEntry>,
    size: u32,
    max_size: u32,
    evicted_count: u32,
}

#[derive(Debug, Clone)]
struct HpackEntry {
    name: String,
    value: String,
    size: u32,
    index: u32,
    evicted: bool,
}

#[derive(Debug)]
struct HpackStaticTable {
    entries: Vec<(String, String)>,
}

#[derive(Debug)]
struct EncodingContext {
    current_stream_id: u32,
    total_headers_processed: u32,
    table_updates_count: u32,
    reductions_requiring_eviction: u32,
    evictions_performed: u32,
}

#[derive(Debug, Clone)]
struct DecodedHeaderList {
    headers: Vec<(String, String)>,
    table_updates: Vec<TableUpdate>,
    table_state_after: TableState,
}

#[derive(Debug, Clone)]
struct TableUpdate {
    update_type: UpdateType,
    name: String,
    value: String,
    index: Option<u32>,
    size_impact: i32,
}

#[derive(Debug, Clone, PartialEq)]
enum UpdateType {
    Added,
    Evicted,
    Referenced,
    SizeChanged,
}

#[derive(Debug, Clone)]
struct TableState {
    size: u32,
    max_size: u32,
    entry_count: usize,
    total_evictions: u32,
}

#[derive(Debug, PartialEq)]
enum HpackDecodingError {
    /// Table size reduction requires eviction
    EvictionRequired { current_size: u32, target_size: u32 },
    /// Invalid index reference
    InvalidIndex { index: u32, table_size: usize },
    /// Table size exceeds maximum
    TableSizeExceeded { size: u32, max: u32 },
    /// Malformed header block
    MalformedHeaderBlock(String),
    /// Invalid table size update
    InvalidTableSizeUpdate { size: u32, reason: String },
    /// Eviction failed
    EvictionFailed(String),
    /// Index encoding error
    IndexEncodingError(String),
}

// RFC 7541 HPACK constants
const DEFAULT_TABLE_SIZE: u32 = 4096;
const STATIC_TABLE_SIZE: usize = 61;
const ENTRY_OVERHEAD: u32 = 32; // RFC 7541 §4.1

// Common static table entries (simplified)
const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

impl HpackEntry {
    fn new(name: String, value: String, index: u32) -> Self {
        let size = (name.len() + value.len()) as u32 + ENTRY_OVERHEAD;
        Self {
            name,
            value,
            size,
            index,
            evicted: false,
        }
    }

    fn total_size(&self) -> u32 {
        self.size
    }
}

impl HpackDynamicTable {
    fn new(max_size: u32) -> Self {
        Self {
            entries: Vec::new(),
            size: 0,
            max_size,
            evicted_count: 0,
        }
    }

    fn add_entry(&mut self, name: String, value: String) -> Result<u32, HpackDecodingError> {
        let entry_index = STATIC_TABLE_SIZE as u32 + self.entries.len() as u32 + 1;
        let new_entry = HpackEntry::new(name, value, entry_index);
        let entry_size = new_entry.total_size();

        // Check if entry fits in table
        if entry_size > self.max_size {
            return Err(HpackDecodingError::TableSizeExceeded {
                size: entry_size,
                max: self.max_size,
            });
        }

        // Evict entries to make space
        self.evict_entries_for_size(entry_size)?;

        // Add new entry at the beginning (most recent)
        self.entries.insert(0, new_entry);
        self.size += entry_size;

        Ok(entry_index)
    }

    fn evict_entries_for_size(&mut self, needed_size: u32) -> Result<(), HpackDecodingError> {
        while self.size + needed_size > self.max_size && !self.entries.is_empty() {
            if let Some(mut evicted_entry) = self.entries.pop() {
                self.size = self.size.saturating_sub(evicted_entry.total_size());
                evicted_entry.evicted = true;
                self.evicted_count += 1;
            }
        }

        if self.size + needed_size > self.max_size {
            return Err(HpackDecodingError::EvictionFailed(format!(
                "Cannot make space for {} bytes (current: {}, max: {})",
                needed_size, self.size, self.max_size
            )));
        }

        Ok(())
    }

    fn set_max_size(&mut self, new_max_size: u32) -> Result<Vec<TableUpdate>, HpackDecodingError> {
        let old_max_size = self.max_size;
        self.max_size = new_max_size;
        let mut updates = Vec::new();

        updates.push(TableUpdate {
            update_type: UpdateType::SizeChanged,
            name: "table_max_size".to_string(),
            value: new_max_size.to_string(),
            index: None,
            size_impact: new_max_size as i32 - old_max_size as i32,
        });

        // If reducing size, evict entries that no longer fit
        if new_max_size < self.size {
            let mut evicted_entries = Vec::new();

            while self.size > new_max_size && !self.entries.is_empty() {
                if let Some(mut evicted_entry) = self.entries.pop() {
                    self.size = self.size.saturating_sub(evicted_entry.total_size());
                    evicted_entry.evicted = true;
                    self.evicted_count += 1;

                    evicted_entries.push(TableUpdate {
                        update_type: UpdateType::Evicted,
                        name: evicted_entry.name.clone(),
                        value: evicted_entry.value.clone(),
                        index: Some(evicted_entry.index),
                        size_impact: -(evicted_entry.total_size() as i32),
                    });
                }
            }

            updates.extend(evicted_entries);
        }

        Ok(updates)
    }

    fn get_entry(&self, index: u32) -> Result<&HpackEntry, HpackDecodingError> {
        if index == 0 || index as usize <= STATIC_TABLE_SIZE {
            return Err(HpackDecodingError::InvalidIndex {
                index,
                table_size: self.entries.len(),
            });
        }

        let dynamic_index = index as usize - STATIC_TABLE_SIZE - 1;

        let table_size = self.entries.len();
        self.entries
            .get(dynamic_index)
            .ok_or(HpackDecodingError::InvalidIndex { index, table_size })
    }

    fn get_state(&self) -> TableState {
        TableState {
            size: self.size,
            max_size: self.max_size,
            entry_count: self.entries.len(),
            total_evictions: self.evicted_count,
        }
    }
}

impl HpackStaticTable {
    fn new() -> Self {
        Self {
            entries: STATIC_TABLE
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        }
    }

    fn get_entry(&self, index: u32) -> Result<(&String, &String), HpackDecodingError> {
        if index == 0 || index as usize > self.entries.len() {
            return Err(HpackDecodingError::InvalidIndex {
                index,
                table_size: self.entries.len(),
            });
        }

        let (name, value) = &self.entries[index as usize - 1];
        Ok((name, value))
    }
}

impl MockHpackDecoder {
    fn new(initial_max_table_size: u32) -> Self {
        Self {
            dynamic_table: HpackDynamicTable::new(initial_max_table_size),
            static_table: HpackStaticTable::new(),
            max_table_size: initial_max_table_size,
            encoding_context: EncodingContext {
                current_stream_id: 1,
                total_headers_processed: 0,
                table_updates_count: 0,
                reductions_requiring_eviction: 0,
                evictions_performed: 0,
            },
        }
    }

    fn update_table_size(&mut self, new_size: u32) -> Result<Vec<TableUpdate>, HpackDecodingError> {
        if new_size > self.max_table_size {
            return Err(HpackDecodingError::InvalidTableSizeUpdate {
                size: new_size,
                reason: format!("Exceeds maximum allowed size: {}", self.max_table_size),
            });
        }

        let size_before = self.dynamic_table.size;
        let eviction_required = size_before > new_size;
        let updates = self.dynamic_table.set_max_size(new_size)?;
        let evictions = updates
            .iter()
            .filter(|u| u.update_type == UpdateType::Evicted)
            .count() as u32;
        self.encoding_context.table_updates_count += 1;
        if eviction_required {
            self.encoding_context.reductions_requiring_eviction += 1;
            assert!(
                evictions > 0,
                "table size reduction from {size_before} to {new_size} required eviction but produced no eviction updates"
            );
        }
        self.encoding_context.evictions_performed += evictions;

        Ok(updates)
    }

    fn decode_header_sequence(
        &mut self,
        sequence: &HeaderSequence,
    ) -> Result<DecodedHeaderList, HpackDecodingError> {
        let mut decoded_headers = Vec::new();
        let mut table_updates = Vec::new();

        for header in &sequence.headers {
            match &header.indexing {
                IndexingStrategy::LiteralIncremental => {
                    let name = self.generate_header_name(&header.name);
                    let value = header.value.clone();

                    // Add to dynamic table
                    let index = self.dynamic_table.add_entry(name.clone(), value.clone())?;

                    decoded_headers.push((name.clone(), value.clone()));
                    table_updates.push(TableUpdate {
                        update_type: UpdateType::Added,
                        name: name.clone(),
                        value: value.clone(),
                        index: Some(index),
                        size_impact: ((name.len() + value.len()) as u32 + ENTRY_OVERHEAD) as i32,
                    });
                }
                IndexingStrategy::LiteralNoIndexing => {
                    let name = self.generate_header_name(&header.name);
                    let value = header.value.clone();
                    decoded_headers.push((name, value));
                }
                IndexingStrategy::LiteralNeverIndexed => {
                    let name = self.generate_header_name(&header.name);
                    let value = header.value.clone();
                    decoded_headers.push((name, value));
                }
                IndexingStrategy::Indexed(index) => {
                    let (name, value) = self.resolve_indexed_header(*index)?;
                    decoded_headers.push((name.clone(), value.clone()));

                    table_updates.push(TableUpdate {
                        update_type: UpdateType::Referenced,
                        name: name.clone(),
                        value: value.clone(),
                        index: Some(*index as u32),
                        size_impact: 0,
                    });
                }
                IndexingStrategy::LiteralIncrementalIndexedName(name_index) => {
                    let (indexed_name, _) = self.resolve_indexed_header(*name_index)?;
                    let indexed_name = indexed_name.clone();
                    let value = header.value.clone();

                    // Add to dynamic table with indexed name
                    let index = self
                        .dynamic_table
                        .add_entry(indexed_name.clone(), value.clone())?;

                    decoded_headers.push((indexed_name.clone(), value.clone()));
                    table_updates.push(TableUpdate {
                        update_type: UpdateType::Added,
                        name: indexed_name.clone(),
                        value: value.clone(),
                        index: Some(index),
                        size_impact: ((indexed_name.len() + value.len()) as u32 + ENTRY_OVERHEAD)
                            as i32,
                    });
                }
            }
        }

        self.encoding_context.total_headers_processed += decoded_headers.len() as u32;

        Ok(DecodedHeaderList {
            headers: decoded_headers,
            table_updates,
            table_state_after: self.dynamic_table.get_state(),
        })
    }

    fn resolve_indexed_header(&self, index: u8) -> Result<(&String, &String), HpackDecodingError> {
        let index = index as u32;

        if index <= STATIC_TABLE_SIZE as u32 {
            // Static table reference
            self.static_table.get_entry(index)
        } else {
            // Dynamic table reference
            let entry = self.dynamic_table.get_entry(index)?;
            Ok((&entry.name, &entry.value))
        }
    }

    fn generate_header_name(&self, name: &HeaderName) -> String {
        match name {
            HeaderName::Method => ":method".to_string(),
            HeaderName::Path => ":path".to_string(),
            HeaderName::Scheme => ":scheme".to_string(),
            HeaderName::Authority => ":authority".to_string(),
            HeaderName::ContentType => "content-type".to_string(),
            HeaderName::UserAgent => "user-agent".to_string(),
            HeaderName::Accept => "accept".to_string(),
            HeaderName::Authorization => "authorization".to_string(),
            HeaderName::Custom(name) => name.clone(),
        }
    }

    fn simulate_table_size_sequence(
        &mut self,
        input: &H2TableSizeChangeInput,
    ) -> Result<Vec<DecodedHeaderList>, HpackDecodingError> {
        let mut results = Vec::new();
        let mut header_seq_index = 0;

        // Process initial headers with default table size
        if header_seq_index < input.header_sequences.len() {
            let decoded = self.decode_header_sequence(&input.header_sequences[header_seq_index])?;
            results.push(decoded);
            header_seq_index += 1;
        }

        // Process size changes and interleaved headers
        for size_change in &input.table_size_sequence.size_changes {
            // Apply table size change
            let _updates = self.update_table_size(size_change.new_size)?;

            // Process headers after this size change
            for _ in 0..size_change.headers_after {
                if header_seq_index < input.header_sequences.len() {
                    let decoded =
                        self.decode_header_sequence(&input.header_sequences[header_seq_index])?;
                    results.push(decoded);
                    header_seq_index += 1;
                }
            }
        }

        // Apply zero reduction if requested
        if input.table_size_sequence.include_zero_reduction {
            let _updates = self.update_table_size(0)?;

            // Process any remaining headers after zero reduction
            while header_seq_index < input.header_sequences.len() {
                let decoded =
                    self.decode_header_sequence(&input.header_sequences[header_seq_index])?;
                results.push(decoded);
                header_seq_index += 1;
            }
        }

        // Apply final table size
        let _final_updates = self.update_table_size(input.table_size_sequence.final_size)?;

        Ok(results)
    }
}

fuzz_target!(|input: H2TableSizeChangeInput| {
    // Skip overly complex scenarios that would timeout
    if input.table_size_sequence.size_changes.len() > 20 || input.header_sequences.len() > 50 {
        return;
    }

    let mut decoder = MockHpackDecoder::new(input.table_size_sequence.initial_size);
    let simulation_result = decoder.simulate_table_size_sequence(&input);

    // Test table size change behavior based on sequence
    match simulation_result {
        Ok(_) => {
            // Verify table size change behavior
            if input.table_size_sequence.include_zero_reduction {
                // After zero reduction, dynamic table should be empty
                let final_state = decoder.dynamic_table.get_state();
                assert_eq!(
                    final_state.entry_count, 0,
                    "Dynamic table should be empty after size reduction to 0"
                );
                assert_eq!(
                    final_state.size, 0,
                    "Dynamic table size should be 0 after evicting all entries"
                );
            }

            // Verify eviction behavior occurred when table size was reduced
            if input.test_scenario.test_eviction {
                let eviction_count = decoder.encoding_context.evictions_performed;
                let required_reductions = decoder.encoding_context.reductions_requiring_eviction;
                assert!(
                    eviction_count >= required_reductions,
                    "eviction accounting under-reported table reductions: {eviction_count} evictions for {required_reductions} required reductions"
                );
            }

            // Verify table reconstruction after zero reduction
            if input.test_scenario.test_reconstruction
                && input.table_size_sequence.include_zero_reduction
                && input.table_size_sequence.final_size > 0
            {
                // After zero reduction and size restoration, table should accept new entries
                let final_max_size = decoder.dynamic_table.max_size;
                assert!(
                    final_max_size == input.table_size_sequence.final_size,
                    "Final table size should match configured final size"
                );
            }
        }
        Err(ref error) => {
            // Analyze error conditions
            match error {
                HpackDecodingError::EvictionRequired {
                    current_size,
                    target_size,
                } => {
                    assert!(
                        *current_size > *target_size,
                        "Eviction should only be required when current > target"
                    );
                }
                HpackDecodingError::TableSizeExceeded { size, max } => {
                    assert!(
                        *size > *max,
                        "Table size exceeded should only occur when size > max"
                    );
                }
                HpackDecodingError::InvalidIndex { index, table_size } => {
                    assert!(
                        *index as usize > STATIC_TABLE_SIZE + *table_size,
                        "Invalid index should be beyond available entries"
                    );
                }
                _ => {
                    // Other errors may occur due to malformed input
                }
            }
        }
    }

    // Test HPACK table invariants
    test_hpack_table_invariants(&input, &decoder, &simulation_result);
});

fn test_hpack_table_invariants(
    input: &H2TableSizeChangeInput,
    decoder: &MockHpackDecoder,
    result: &Result<Vec<DecodedHeaderList>, HpackDecodingError>,
) {
    // Invariant: Dynamic table size should never exceed max size
    let table_state = decoder.dynamic_table.get_state();
    assert!(
        table_state.size <= table_state.max_size,
        "Dynamic table size {} should not exceed max size {}",
        table_state.size,
        table_state.max_size
    );

    // Invariant: After zero reduction, table should be empty
    if input.table_size_sequence.include_zero_reduction && result.is_ok() {
        assert_eq!(
            table_state.entry_count, 0,
            "Table should be empty after size reduction to 0"
        );
        assert_eq!(
            table_state.size, 0,
            "Table size should be 0 after evicting all entries"
        );
    }

    // Invariant: Table max size should match final configured size
    assert_eq!(
        table_state.max_size, input.table_size_sequence.final_size,
        "Final table max size should match configured final size"
    );

    // Invariant: Eviction count should be reasonable
    let eviction_count = decoder.encoding_context.evictions_performed;
    let total_entries_added = if let Ok(sequences) = result {
        sequences
            .iter()
            .flat_map(|seq| &seq.table_updates)
            .filter(|update| update.update_type == UpdateType::Added)
            .count()
    } else {
        0
    };

    assert!(
        eviction_count <= total_entries_added as u32 * 2,
        "Eviction count {} seems excessive for {} entries added",
        eviction_count,
        total_entries_added
    );

    // Invariant: Size changes should be properly tracked
    let size_change_count = input.table_size_sequence.size_changes.len()
        + (if input.table_size_sequence.include_zero_reduction {
            1
        } else {
            0
        })
        + 1; // +1 for final size
    assert_eq!(
        decoder.encoding_context.table_updates_count as usize, size_change_count,
        "Table update count should match number of size changes"
    );

    // Invariant: Entry indices should be consistent
    for entry in &decoder.dynamic_table.entries {
        assert!(
            entry.index > STATIC_TABLE_SIZE as u32,
            "Dynamic entry index {} should be beyond static table size {}",
            entry.index,
            STATIC_TABLE_SIZE
        );
    }

    // Invariant: Entry sizes should be properly calculated
    for entry in &decoder.dynamic_table.entries {
        let expected_size = (entry.name.len() + entry.value.len()) as u32 + ENTRY_OVERHEAD;
        assert_eq!(
            entry.size, expected_size,
            "Entry size calculation incorrect: expected {}, got {}",
            expected_size, entry.size
        );
    }

    // Invariant: Total table size should equal sum of entry sizes
    let calculated_size: u32 = decoder
        .dynamic_table
        .entries
        .iter()
        .map(|entry| entry.total_size())
        .sum();
    assert_eq!(
        table_state.size, calculated_size,
        "Table size {} should equal sum of entry sizes {}",
        table_state.size, calculated_size
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_size_reduction_to_zero() {
        let mut decoder = MockHpackDecoder::new(DEFAULT_TABLE_SIZE);

        // Add some entries to the table
        let _index1 = decoder
            .dynamic_table
            .add_entry("custom-header".to_string(), "value1".to_string())
            .unwrap();
        let _index2 = decoder
            .dynamic_table
            .add_entry("another-header".to_string(), "value2".to_string())
            .unwrap();

        assert!(decoder.dynamic_table.entries.len() > 0);
        assert!(decoder.dynamic_table.size > 0);

        // Reduce table size to 0
        let updates = decoder.update_table_size(0).unwrap();

        // Verify all entries were evicted
        assert_eq!(decoder.dynamic_table.entries.len(), 0);
        assert_eq!(decoder.dynamic_table.size, 0);
        assert_eq!(decoder.dynamic_table.max_size, 0);

        // Verify eviction updates were generated
        let eviction_updates: Vec<_> = updates
            .iter()
            .filter(|update| update.update_type == UpdateType::Evicted)
            .collect();
        assert_eq!(eviction_updates.len(), 2); // Both entries should be evicted
    }

    #[test]
    fn test_table_size_partial_reduction() {
        let mut decoder = MockHpackDecoder::new(DEFAULT_TABLE_SIZE);

        // Add entries that together exceed the new limit
        let _index1 = decoder
            .dynamic_table
            .add_entry(
                "large-header-name".to_string(),
                "large-header-value".to_string(),
            )
            .unwrap();
        let _index2 = decoder
            .dynamic_table
            .add_entry("medium-header".to_string(), "medium-value".to_string())
            .unwrap();
        let _index3 = decoder
            .dynamic_table
            .add_entry("small".to_string(), "val".to_string())
            .unwrap();

        let initial_count = decoder.dynamic_table.entries.len();
        let initial_size = decoder.dynamic_table.size;

        // Reduce to a size that requires partial eviction
        let small_size = initial_size / 3;
        let updates = decoder.update_table_size(small_size).unwrap();

        // Verify some entries were evicted
        assert!(decoder.dynamic_table.entries.len() < initial_count);
        assert!(decoder.dynamic_table.size <= small_size);
        assert_eq!(decoder.dynamic_table.max_size, small_size);

        // Verify eviction updates were generated
        let eviction_count = updates
            .iter()
            .filter(|update| update.update_type == UpdateType::Evicted)
            .count();
        assert!(eviction_count > 0);
    }

    #[test]
    fn test_table_size_increase_after_reduction() {
        let mut decoder = MockHpackDecoder::new(DEFAULT_TABLE_SIZE);

        // Add entries and reduce to zero
        let _index1 = decoder
            .dynamic_table
            .add_entry("header1".to_string(), "value1".to_string())
            .unwrap();
        decoder.update_table_size(0).unwrap();

        assert_eq!(decoder.dynamic_table.entries.len(), 0);

        // Increase table size again
        decoder.update_table_size(2048).unwrap();

        // Should be able to add new entries
        let new_index = decoder
            .dynamic_table
            .add_entry("new-header".to_string(), "new-value".to_string())
            .unwrap();
        assert!(new_index > STATIC_TABLE_SIZE as u32);
        assert_eq!(decoder.dynamic_table.entries.len(), 1);
    }

    #[test]
    fn test_indexed_header_resolution() {
        let mut decoder = MockHpackDecoder::new(DEFAULT_TABLE_SIZE);

        // Test static table resolution
        let (name, value) = decoder.resolve_indexed_header(2).unwrap(); // :method GET
        assert_eq!(name, ":method");
        assert_eq!(value, "GET");

        // Add dynamic entry and test resolution
        let dynamic_index = decoder
            .dynamic_table
            .add_entry("custom".to_string(), "test".to_string())
            .unwrap();
        let (dynamic_name, dynamic_value) =
            decoder.resolve_indexed_header(dynamic_index as u8).unwrap();
        assert_eq!(dynamic_name, "custom");
        assert_eq!(dynamic_value, "test");
    }

    #[test]
    fn test_header_sequence_decoding() {
        let mut decoder = MockHpackDecoder::new(DEFAULT_TABLE_SIZE);

        let sequence = HeaderSequence {
            headers: vec![
                HeaderEntry {
                    name: HeaderName::Method,
                    value: "POST".to_string(),
                    indexing: IndexingStrategy::LiteralIncremental,
                },
                HeaderEntry {
                    name: HeaderName::Path,
                    value: "/api/test".to_string(),
                    indexing: IndexingStrategy::LiteralNoIndexing,
                },
            ],
            encoding_strategy: HeaderEncodingStrategy::Mixed,
            force_dynamic_updates: false,
        };

        let result = decoder.decode_header_sequence(&sequence).unwrap();

        assert_eq!(result.headers.len(), 2);
        assert_eq!(result.headers[0].0, ":method");
        assert_eq!(result.headers[0].1, "POST");
        assert_eq!(result.headers[1].0, ":path");
        assert_eq!(result.headers[1].1, "/api/test");

        // First header should be added to dynamic table
        let added_updates: Vec<_> = result
            .table_updates
            .iter()
            .filter(|update| update.update_type == UpdateType::Added)
            .collect();
        assert_eq!(added_updates.len(), 1);
    }

    #[test]
    fn test_invalid_index_handling() {
        let decoder = MockHpackDecoder::new(DEFAULT_TABLE_SIZE);

        // Test invalid static table index
        let result = decoder.resolve_indexed_header(0);
        assert!(matches!(
            result,
            Err(HpackDecodingError::InvalidIndex { .. })
        ));

        // Test index beyond dynamic table
        let result = decoder.resolve_indexed_header(200);
        assert!(matches!(
            result,
            Err(HpackDecodingError::InvalidIndex { .. })
        ));
    }

    #[test]
    fn test_entry_size_calculation() {
        let entry = HpackEntry::new("test-name".to_string(), "test-value".to_string(), 62);

        let expected_size = ("test-name".len() + "test-value".len()) as u32 + ENTRY_OVERHEAD;
        assert_eq!(entry.total_size(), expected_size);
        assert_eq!(entry.size, expected_size);
    }

    #[test]
    fn test_table_state_consistency() {
        let mut decoder = MockHpackDecoder::new(DEFAULT_TABLE_SIZE);

        // Add entries and check state consistency
        decoder
            .dynamic_table
            .add_entry("header1".to_string(), "value1".to_string())
            .unwrap();
        decoder
            .dynamic_table
            .add_entry("header2".to_string(), "value2".to_string())
            .unwrap();

        let state = decoder.dynamic_table.get_state();
        assert_eq!(state.entry_count, 2);
        assert!(state.size > 0);
        assert_eq!(state.max_size, DEFAULT_TABLE_SIZE);

        // Calculate expected size manually
        let calculated_size: u32 = decoder
            .dynamic_table
            .entries
            .iter()
            .map(|e| e.total_size())
            .sum();
        assert_eq!(state.size, calculated_size);
    }
}
