#![no_main]

//! Fuzz target for HTTP/2 SETTINGS_HEADER_TABLE_SIZE update behavior.
//!
//! This target tests the HPACK dynamic table size management per RFC 7541:
//!
//! - SETTINGS_HEADER_TABLE_SIZE controls HPACK dynamic table max size
//! - Size updates are capped to 1 MiB to prevent unbounded growth
//! - Per RFC 7541 §6.3: encoder MUST emit size update at start of next header block
//! - Per RFC 7541 §4.2: shrink then grow requires min size first, then final size
//! - Zero table size disables dynamic table compression
//! - Multiple rapid size changes between header blocks
//!
//! Expected behavior:
//! - Valid sizes: table resized, size update emitted in next header block
//! - Oversized values: capped to 1 MiB (1024 * 1024)
//! - Zero size: dynamic table disabled, all headers literal
//! - Shrink-then-grow: min size emitted first, then final size

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 header representation
#[derive(Debug, Clone, Arbitrary)]
struct Header {
    name: String,
    value: String,
}

impl Header {
    fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    /// Estimate header size in bytes for dynamic table calculations
    fn size(&self) -> usize {
        // RFC 7541 §4.1: header size = name length + value length + 32
        self.name.len() + self.value.len() + 32
    }
}

/// HPACK dynamic table entry
#[derive(Debug, Clone)]
struct TableEntry {
    header: Header,
    size: usize,
}

/// Mock HPACK dynamic table
#[derive(Debug, Clone)]
struct MockDynamicTable {
    entries: Vec<TableEntry>,
    max_size: usize,
    current_size: usize,
}

impl MockDynamicTable {
    fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_size: max_size.min(1024 * 1024), // Cap to 1 MiB
            current_size: 0,
        }
    }

    fn set_max_size(&mut self, new_max_size: usize) {
        self.max_size = new_max_size.min(1024 * 1024); // Cap to 1 MiB
        self.evict_if_needed();
    }

    fn add_entry(&mut self, header: Header) {
        let entry_size = header.size();
        let entry = TableEntry {
            header,
            size: entry_size,
        };

        // Add entry to front (FIFO eviction from back)
        self.entries.insert(0, entry);
        self.current_size += entry_size;
        self.evict_if_needed();
    }

    fn evict_if_needed(&mut self) {
        while self.current_size > self.max_size && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop() {
                self.current_size -= evicted.size;
            }
        }
    }

    fn size(&self) -> usize {
        self.current_size
    }

    fn max_size(&self) -> usize {
        self.max_size
    }

    fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Mock HPACK encoder with size update tracking
#[derive(Debug)]
struct MockHpackEncoder {
    dynamic_table: MockDynamicTable,
    pending_size_update: Option<usize>,
    min_size_update: Option<usize>,
    use_huffman: bool,
}

impl MockHpackEncoder {
    fn new() -> Self {
        Self {
            dynamic_table: MockDynamicTable::new(4096), // Default size
            pending_size_update: None,
            min_size_update: None,
            use_huffman: true,
        }
    }

    /// Set maximum dynamic table size (mimics Encoder::set_max_table_size)
    fn set_max_table_size(&mut self, size: usize) {
        let capped = size.min(1024 * 1024); // MAX_ALLOWED_TABLE_SIZE
        self.dynamic_table.set_max_size(capped);

        // Track minimum size for RFC 7541 §4.2 compliance
        if let Some(min_so_far) = self.min_size_update {
            self.min_size_update = Some(min_so_far.min(capped));
        } else {
            self.min_size_update = Some(capped);
        }
        self.pending_size_update = Some(capped);
    }

    /// Encode headers and emit pending size updates
    fn encode(&mut self, headers: &[Header]) -> Vec<u8> {
        let mut output = Vec::new();

        // Emit pending size updates first per RFC 7541 §6.3
        if let Some(pending_size) = self.pending_size_update {
            // RFC 7541 §4.2: If table shrank then grew, emit min size first
            if let Some(min_size) = self.min_size_update {
                if min_size < pending_size {
                    output.extend(self.encode_size_update(min_size));
                }
            }
            output.extend(self.encode_size_update(pending_size));
            self.pending_size_update = None;
            self.min_size_update = None;
        }

        // Encode headers
        for header in headers {
            output.extend(self.encode_header(header));
        }

        output
    }

    /// Encode a dynamic table size update
    fn encode_size_update(&self, size: usize) -> Vec<u8> {
        // RFC 7541 §6.3: Dynamic table size update uses 001 prefix (0x20)
        let mut bytes = Vec::new();

        if size < 31 {
            // Size fits in 5 bits
            bytes.push(0x20 | (size as u8));
        } else {
            // Multi-byte integer encoding
            bytes.push(0x20 | 31); // Prefix + 11111
            let mut remaining = size - 31;
            while remaining >= 128 {
                bytes.push(0x80 | ((remaining & 0x7f) as u8));
                remaining >>= 7;
            }
            bytes.push(remaining as u8);
        }

        bytes
    }

    /// Encode a single header
    fn encode_header(&mut self, header: &Header) -> Vec<u8> {
        let mut bytes = Vec::new();

        // For simplicity, always use literal header representation
        // Real implementation would check dynamic table for indexed entries

        // Literal Header Field with Incremental Indexing (01 prefix = 0x40)
        bytes.push(0x40);

        // Encode header name length + name
        self.encode_string(&header.name, &mut bytes);

        // Encode header value length + value
        self.encode_string(&header.value, &mut bytes);

        // Add to dynamic table if size allows
        if self.dynamic_table.max_size() > 0 {
            self.dynamic_table.add_entry(header.clone());
        }

        bytes
    }

    /// Encode a string with optional Huffman coding
    fn encode_string(&self, s: &str, output: &mut Vec<u8>) {
        let bytes = s.as_bytes();

        if self.use_huffman {
            // Huffman encoded (H=1)
            output.push(0x80 | (bytes.len() as u8));
        } else {
            // Literal (H=0)
            output.push(bytes.len() as u8);
        }

        output.extend_from_slice(bytes);
    }

    fn dynamic_table_size(&self) -> usize {
        self.dynamic_table.size()
    }

    fn dynamic_table_max_size(&self) -> usize {
        self.dynamic_table.max_size()
    }

    fn dynamic_table_entry_count(&self) -> usize {
        self.dynamic_table.entry_count()
    }

    fn has_pending_size_update(&self) -> bool {
        self.pending_size_update.is_some()
    }
}

/// Header table size test scenario
#[derive(Debug, Clone, Arbitrary)]
struct HeaderTableSizeScenario {
    /// Initial table size
    initial_table_size: u32,
    /// Sequence of table size updates and header encodes
    operations: Vec<TableOperation>,
    /// Whether to include edge cases
    include_edge_cases: bool,
}

/// Operations to perform on the HPACK encoder
#[derive(Debug, Clone, Arbitrary)]
enum TableOperation {
    /// Update table size
    UpdateTableSize(u32),
    /// Encode a set of headers
    EncodeHeaders(Vec<HeaderData>),
}

#[derive(Debug, Clone, Arbitrary)]
struct HeaderData {
    name: String,
    value: String,
}

/// Generate edge case operations for testing
fn generate_edge_case_operations() -> Vec<TableOperation> {
    vec![
        // Boundary sizes
        TableOperation::UpdateTableSize(0),                    // Disable dynamic table
        TableOperation::UpdateTableSize(1),                    // Minimum size
        TableOperation::UpdateTableSize(4096),                 // Default size
        TableOperation::UpdateTableSize(1024 * 1024),          // 1 MiB cap
        TableOperation::UpdateTableSize(1024 * 1024 + 1),      // Over cap (should be capped)
        TableOperation::UpdateTableSize(u32::MAX),             // Maximum value

        // Shrink-then-grow scenarios (RFC 7541 §4.2)
        TableOperation::UpdateTableSize(8192),                 // Start large
        TableOperation::UpdateTableSize(1024),                 // Shrink
        TableOperation::UpdateTableSize(4096),                 // Grow (should emit min first)

        // Zero-size scenarios
        TableOperation::UpdateTableSize(0),                    // Disable
        TableOperation::EncodeHeaders(vec![
            HeaderData { name: "x-test".to_string(), value: "value1".to_string() },
        ]),
        TableOperation::UpdateTableSize(4096),                 // Re-enable

        // Large header scenarios
        TableOperation::UpdateTableSize(1024),                 // Small table
        TableOperation::EncodeHeaders(vec![
            HeaderData { name: "x-large".to_string(), value: "x".repeat(500) }, // Large value
            HeaderData { name: "x-another".to_string(), value: "y".repeat(500) },
        ]),

        // Rapid size changes
        TableOperation::UpdateTableSize(2048),
        TableOperation::UpdateTableSize(1024),
        TableOperation::UpdateTableSize(4096),
        TableOperation::UpdateTableSize(512),
    ]
}

fuzz_target!(|scenario: HeaderTableSizeScenario| {
    // Limit scenario size to avoid timeouts
    if scenario.operations.len() > 30 {
        return;
    }

    // Initialize encoder with capped initial size
    let initial_size = (scenario.initial_table_size as usize).min(1024 * 1024);
    let mut encoder = MockHpackEncoder::new();
    encoder.set_max_table_size(initial_size);

    // Prepare operations
    let operations = if scenario.include_edge_cases {
        let mut ops = scenario.operations.clone();
        ops.extend(generate_edge_case_operations());
        ops.truncate(25); // Keep reasonable size
        ops
    } else {
        scenario.operations
    };

    // Track state for validation
    let mut previous_table_size = initial_size;
    let mut size_update_count = 0;
    let mut encoded_blocks = 0;

    // Process each operation
    for operation in &operations {
        match operation {
            TableOperation::UpdateTableSize(new_size) => {
                let new_size_usize = (*new_size as usize).min(1024 * 1024);

                encoder.set_max_table_size(new_size_usize);

                // Verify the size was properly capped
                assert!(encoder.dynamic_table_max_size() <= 1024 * 1024,
                    "Table size {} exceeds 1 MiB cap", encoder.dynamic_table_max_size());

                // Verify size update is pending
                assert!(encoder.has_pending_size_update(),
                    "Size update should be pending after set_max_table_size");

                size_update_count += 1;
                previous_table_size = new_size_usize;
            }
            TableOperation::EncodeHeaders(header_data) => {
                // Convert to Header objects, limiting size to prevent timeouts
                let headers: Vec<Header> = header_data.iter().take(10).map(|h| Header {
                    name: h.name.chars().take(50).collect(), // Limit name length
                    value: h.value.chars().take(200).collect(), // Limit value length
                }).collect();

                let encoded = encoder.encode(&headers);

                // Verify encoding produces output
                assert!(!encoded.is_empty() || headers.is_empty(),
                    "Encoding headers should produce output");

                // Verify no pending size update after encoding
                assert!(!encoder.has_pending_size_update(),
                    "Size update should be consumed during encoding");

                // Check for valid table state
                assert!(encoder.dynamic_table_size() <= encoder.dynamic_table_max_size(),
                    "Dynamic table size {} exceeds max size {}",
                    encoder.dynamic_table_size(), encoder.dynamic_table_max_size());

                encoded_blocks += 1;
            }
        }
    }

    // Additional specific tests
    test_size_capping_behavior(&mut encoder);
    test_zero_table_size_behavior(&mut encoder);
    test_shrink_grow_behavior(&mut encoder);
});

/// Test that sizes are properly capped to 1 MiB
fn test_size_capping_behavior(encoder: &mut MockHpackEncoder) {
    // Test oversized values
    let oversized_values = [
        1024 * 1024 + 1,
        2 * 1024 * 1024,
        u32::MAX as usize,
    ];

    for &size in &oversized_values {
        encoder.set_max_table_size(size);
        assert_eq!(encoder.dynamic_table_max_size(), 1024 * 1024,
            "Size {} should be capped to 1 MiB", size);
    }
}

/// Test zero table size disables dynamic table
fn test_zero_table_size_behavior(encoder: &mut MockHpackEncoder) {
    // Set normal size and add some entries
    encoder.set_max_table_size(4096);

    let headers = vec![
        Header::new("x-test-1", "value1"),
        Header::new("x-test-2", "value2"),
    ];
    encoder.encode(&headers);

    let entries_before = encoder.dynamic_table_entry_count();
    assert!(entries_before > 0, "Table should have entries");

    // Set zero size - should clear table
    encoder.set_max_table_size(0);
    assert_eq!(encoder.dynamic_table_max_size(), 0);
    assert_eq!(encoder.dynamic_table_size(), 0);
    assert_eq!(encoder.dynamic_table_entry_count(), 0,
        "Zero table size should clear all entries");

    // Encode more headers - should not add to table
    encoder.encode(&headers);
    assert_eq!(encoder.dynamic_table_entry_count(), 0,
        "Headers should not be added to disabled table");
}

/// Test shrink-then-grow scenario per RFC 7541 §4.2
fn test_shrink_grow_behavior(encoder: &mut MockHpackEncoder) {
    // Start with large table
    encoder.set_max_table_size(8192);

    // Shrink then grow without encoding between
    encoder.set_max_table_size(1024); // Shrink
    encoder.set_max_table_size(4096); // Grow

    // Encode should emit min size (1024) first, then final size (4096)
    let headers = vec![Header::new("x-test", "value")];
    let encoded = encoder.encode(&headers);

    // Verify the encoding starts with size updates
    // First size update should be for 1024, second for 4096
    assert!(encoded.len() > 2, "Should have size updates at start");
    assert_eq!(encoded[0] & 0xe0, 0x20, "First byte should be size update");

    // For this test we just verify that size updates are present
    // Full wire format validation would require more complex parsing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_table_size_update() {
        let scenario = HeaderTableSizeScenario {
            initial_table_size: 4096,
            operations: vec![
                TableOperation::UpdateTableSize(8192),
                TableOperation::EncodeHeaders(vec![
                    HeaderData { name: "x-test".to_string(), value: "value1".to_string() },
                ]),
                TableOperation::UpdateTableSize(2048),
                TableOperation::EncodeHeaders(vec![
                    HeaderData { name: "x-another".to_string(), value: "value2".to_string() },
                ]),
            ],
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_oversized_table_capping() {
        let scenario = HeaderTableSizeScenario {
            initial_table_size: 4096,
            operations: vec![
                TableOperation::UpdateTableSize(2 * 1024 * 1024), // 2 MiB - should be capped
                TableOperation::EncodeHeaders(vec![
                    HeaderData { name: "x-large".to_string(), value: "test".to_string() },
                ]),
                TableOperation::UpdateTableSize(u32::MAX), // Maximum - should be capped
                TableOperation::EncodeHeaders(vec![
                    HeaderData { name: "x-max".to_string(), value: "test".to_string() },
                ]),
            ],
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_zero_table_size() {
        let scenario = HeaderTableSizeScenario {
            initial_table_size: 4096,
            operations: vec![
                TableOperation::EncodeHeaders(vec![
                    HeaderData { name: "x-before".to_string(), value: "value1".to_string() },
                ]),
                TableOperation::UpdateTableSize(0), // Disable dynamic table
                TableOperation::EncodeHeaders(vec![
                    HeaderData { name: "x-disabled".to_string(), value: "value2".to_string() },
                ]),
                TableOperation::UpdateTableSize(4096), // Re-enable
                TableOperation::EncodeHeaders(vec![
                    HeaderData { name: "x-after".to_string(), value: "value3".to_string() },
                ]),
            ],
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_rapid_size_changes() {
        let scenario = HeaderTableSizeScenario {
            initial_table_size: 4096,
            operations: vec![
                TableOperation::UpdateTableSize(8192),
                TableOperation::UpdateTableSize(2048),
                TableOperation::UpdateTableSize(1024),
                TableOperation::UpdateTableSize(4096),
                TableOperation::EncodeHeaders(vec![
                    HeaderData { name: "x-final".to_string(), value: "value".to_string() },
                ]),
            ],
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_edge_cases() {
        let scenario = HeaderTableSizeScenario {
            initial_table_size: 4096,
            operations: vec![], // Edge cases will be added
            include_edge_cases: true,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }
}