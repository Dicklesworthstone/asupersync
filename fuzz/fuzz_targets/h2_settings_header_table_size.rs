#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::HashMap;

// Mock HTTP/2 SETTINGS frame and HPACK dynamic table for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct SettingsUpdateTestCase {
    initial_table_size: u32,
    update_sequence: Vec<HeaderTableSizeUpdate>,
    header_operations: Vec<HeaderOperation>,
    malformed_scenarios: MalformedScenarios,
}

#[derive(Debug, Clone, Arbitrary)]
struct HeaderTableSizeUpdate {
    new_size: u32,
    timing: UpdateTiming,
    acknowledgment_delay: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum UpdateTiming {
    BeforeHeaders,
    DuringHeaders,
    AfterHeaders,
    Immediate,
    Delayed(u8),
}

#[derive(Debug, Clone, Arbitrary)]
struct HeaderOperation {
    operation_type: HeaderOperationType,
    header_name: String,
    header_value: String,
    indexed_position: Option<u8>,
}

#[derive(Debug, Clone, Arbitrary)]
enum HeaderOperationType {
    LiteralWithIncrementalIndexing,
    LiteralWithoutIndexing,
    LiteralNeverIndexed,
    IndexedHeaderField,
    DynamicTableSizeUpdate,
}

#[derive(Debug, Clone, Arbitrary)]
struct MalformedScenarios {
    size_exceeds_limit: bool,
    size_reduction_mid_block: bool,
    unacknowledged_update: bool,
    duplicate_updates: bool,
    zero_size_table: bool,
    negative_size_as_u32: bool,
    rapid_size_changes: bool,
    interleaved_headers: bool,
}

// HTTP/2 and HPACK constants
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;
const MAX_HEADER_TABLE_SIZE: u32 = 65536; // Common implementation limit

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > 100_000 {
        return;
    }

    let mut u = Unstructured::new(data);

    // Try to generate a test case from the fuzz input
    let test_case = match SettingsUpdateTestCase::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return, // Invalid input for generating test case
    };

    // Test scenario 1: Basic SETTINGS_HEADER_TABLE_SIZE update
    test_basic_header_table_size_update(&test_case);

    // Test scenario 2: Table size reduction with entry eviction
    test_table_size_reduction(&test_case);

    // Test scenario 3: Table size increase and new entries
    test_table_size_increase(&test_case);

    // Test scenario 4: Rapid sequence of size changes
    test_rapid_size_changes(&test_case);

    // Test scenario 5: Size update during header block processing
    test_size_update_during_headers(&test_case);

    // Test scenario 6: Zero table size (edge case)
    test_zero_table_size(&test_case);

    // Test scenario 7: Maximum table size limits
    test_maximum_table_size(&test_case);

    // Test scenario 8: Unacknowledged settings updates
    test_unacknowledged_updates(&test_case);

    // Test scenario 9: Duplicate size updates
    test_duplicate_size_updates(&test_case);

    // Test scenario 10: Entry preservation across updates
    test_entry_preservation(&test_case);
});

/// Test basic SETTINGS_HEADER_TABLE_SIZE update functionality
fn test_basic_header_table_size_update(test_case: &SettingsUpdateTestCase) {
    let mut hpack_context = create_hpack_context(test_case.initial_table_size);

    // Add some initial entries to the dynamic table
    let initial_entries = vec![
        ("x-custom-header", "initial-value"),
        ("x-test-header", "test-value"),
        ("content-encoding", "gzip"),
    ];

    for (name, value) in &initial_entries {
        let result = hpack_context.add_to_dynamic_table(name, value);
        assert!(result.is_ok(), "Should be able to add initial entries");
    }

    let initial_count = hpack_context.dynamic_table.len();
    assert!(initial_count > 0, "Should have initial entries");

    // Test first update in sequence
    if let Some(first_update) = test_case.update_sequence.first() {
        let update_result = hpack_context.update_header_table_size(first_update.new_size);

        match update_result {
            Ok(eviction_info) => {
                // Verify table size was updated
                assert_eq!(hpack_context.max_table_size, first_update.new_size);

                // If size was reduced, verify proper eviction occurred
                if first_update.new_size < test_case.initial_table_size {
                    assert!(
                        hpack_context.current_table_size <= first_update.new_size,
                        "Table size should not exceed new limit"
                    );

                    if eviction_info.entries_evicted > 0 {
                        assert!(
                            hpack_context.dynamic_table.len() <= initial_count,
                            "Should have evicted some entries"
                        );
                    }
                }

                // Verify remaining entries are intact
                for entry in &hpack_context.dynamic_table {
                    assert!(!entry.name.is_empty(), "Entry names should not be empty");
                    assert!(!entry.value.is_empty(), "Entry values should not be empty");
                }
            }
            Err(error_msg) => {
                // Size updates that exceed implementation limits should be rejected
                if first_update.new_size > MAX_HEADER_TABLE_SIZE {
                    assert!(
                        error_msg.contains("exceeds maximum"),
                        "Large size update should be properly rejected"
                    );
                }
            }
        }
    }
}

/// Test table size reduction with proper entry eviction
fn test_table_size_reduction(test_case: &SettingsUpdateTestCase) {
    let mut hpack_context = create_hpack_context(DEFAULT_HEADER_TABLE_SIZE);

    // Fill table with entries to test eviction
    let test_entries = vec![
        ("x-large-header-1", "very-large-value-that-takes-up-space-1"),
        ("x-large-header-2", "very-large-value-that-takes-up-space-2"),
        ("x-large-header-3", "very-large-value-that-takes-up-space-3"),
        ("x-large-header-4", "very-large-value-that-takes-up-space-4"),
        ("x-large-header-5", "very-large-value-that-takes-up-space-5"),
    ];

    let mut added_entries = 0;
    for (name, value) in &test_entries {
        if hpack_context.add_to_dynamic_table(name, value).is_ok() {
            added_entries += 1;
        }
    }

    let initial_size = hpack_context.current_table_size;
    let initial_count = hpack_context.dynamic_table.len();

    // Find a size update that reduces table size
    if let Some(reduction_update) = test_case.update_sequence.iter()
        .find(|update| update.new_size < initial_size) {

        let result = hpack_context.update_header_table_size(reduction_update.new_size);

        match result {
            Ok(eviction_info) => {
                // Verify size constraint is satisfied
                assert!(
                    hpack_context.current_table_size <= reduction_update.new_size,
                    "Table size {} should not exceed limit {}",
                    hpack_context.current_table_size, reduction_update.new_size
                );

                // Verify eviction happened if necessary
                if eviction_info.entries_evicted > 0 {
                    assert!(
                        hpack_context.dynamic_table.len() < initial_count,
                        "Should have evicted entries when size reduced"
                    );
                }

                // Verify no entry loss that shouldn't have happened
                if reduction_update.new_size >= initial_size {
                    assert_eq!(
                        eviction_info.entries_evicted, 0,
                        "Should not evict entries when size not reduced"
                    );
                }

                // Verify remaining entries are valid and most recently used
                for (i, entry) in hpack_context.dynamic_table.iter().enumerate() {
                    assert!(!entry.name.is_empty(), "Entry {} name should not be empty", i);
                    assert!(!entry.value.is_empty(), "Entry {} value should not be empty", i);
                }
            }
            Err(_) => {
                // Error is acceptable for some edge cases
            }
        }
    }
}

/// Test table size increase and ability to add new entries
fn test_table_size_increase(test_case: &SettingsUpdateTestCase) {
    // Start with a small table size
    let small_size = 512;
    let mut hpack_context = create_hpack_context(small_size);

    // Fill the small table
    let _ = hpack_context.add_to_dynamic_table("x-header-1", "value-1");
    let _ = hpack_context.add_to_dynamic_table("x-header-2", "value-2");

    let initial_count = hpack_context.dynamic_table.len();

    // Find a size update that increases table size
    if let Some(increase_update) = test_case.update_sequence.iter()
        .find(|update| update.new_size > small_size && update.new_size <= MAX_HEADER_TABLE_SIZE) {

        let result = hpack_context.update_header_table_size(increase_update.new_size);

        match result {
            Ok(_) => {
                // Verify table size was updated
                assert_eq!(hpack_context.max_table_size, increase_update.new_size);

                // Verify existing entries preserved
                assert_eq!(
                    hpack_context.dynamic_table.len(), initial_count,
                    "Existing entries should be preserved during size increase"
                );

                // Verify we can now add more entries
                let large_header_result = hpack_context.add_to_dynamic_table(
                    "x-large-new-header",
                    "large-value-that-should-fit-in-expanded-table"
                );

                // Should succeed if there's actually more space
                if increase_update.new_size > small_size + 100 {
                    assert!(
                        large_header_result.is_ok(),
                        "Should be able to add entries after size increase"
                    );
                }
            }
            Err(_) => {
                // Error might be acceptable for very large sizes
            }
        }
    }
}

/// Test rapid sequence of size changes
fn test_rapid_size_changes(test_case: &SettingsUpdateTestCase) {
    if !test_case.malformed_scenarios.rapid_size_changes {
        return;
    }

    let mut hpack_context = create_hpack_context(test_case.initial_table_size);

    // Add some entries to test preservation across changes
    let _ = hpack_context.add_to_dynamic_table("x-persistent", "should-survive");
    let _ = hpack_context.add_to_dynamic_table("x-test", "rapid-changes");

    let mut previous_size = test_case.initial_table_size;

    // Apply rapid sequence of size changes
    for (i, update) in test_case.update_sequence.iter().enumerate().take(5) {
        let result = hpack_context.update_header_table_size(update.new_size);

        match result {
            Ok(eviction_info) => {
                // Verify table maintains consistency
                assert!(
                    hpack_context.current_table_size <= hpack_context.max_table_size,
                    "Table size should never exceed maximum"
                );

                // Verify eviction logic is consistent
                if update.new_size < previous_size {
                    // Size reduction should potentially evict entries
                    assert!(
                        hpack_context.current_table_size <= update.new_size,
                        "Table should fit within new size limit"
                    );
                }

                // Verify table structure integrity
                for (j, entry) in hpack_context.dynamic_table.iter().enumerate() {
                    assert!(
                        !entry.name.is_empty(),
                        "Entry {} should have valid name after update {}", j, i
                    );
                }

                previous_size = update.new_size;
            }
            Err(_) => {
                // Rapid changes might fail for implementation limits
                break;
            }
        }
    }
}

/// Test size update during header block processing
fn test_size_update_during_headers(test_case: &SettingsUpdateTestCase) {
    let mut hpack_context = create_hpack_context(test_case.initial_table_size);

    // Simulate processing a header block
    hpack_context.start_header_block();

    // Add some headers to the block
    for operation in test_case.header_operations.iter().take(3) {
        match operation.operation_type {
            HeaderOperationType::LiteralWithIncrementalIndexing => {
                let _ = hpack_context.process_literal_header_with_indexing(
                    &operation.header_name,
                    &operation.header_value,
                );
            }
            HeaderOperationType::IndexedHeaderField => {
                if let Some(index) = operation.indexed_position {
                    let _ = hpack_context.process_indexed_header(index);
                }
            }
            HeaderOperationType::DynamicTableSizeUpdate => {
                // Test table size update during header processing
                if let Some(update) = test_case.update_sequence.first() {
                    let result = hpack_context.update_header_table_size_during_block(update.new_size);

                    match result {
                        Ok(_) => {
                            // Verify update was applied
                            assert_eq!(hpack_context.max_table_size, update.new_size);
                        }
                        Err(error_msg) => {
                            // Size update during header block might be restricted
                            assert!(
                                error_msg.contains("during header block") ||
                                error_msg.contains("not allowed"),
                                "Error should indicate timing restriction"
                            );
                        }
                    }
                }
            }
            _ => {
                // Other operations
                let _ = hpack_context.process_literal_header(
                    &operation.header_name,
                    &operation.header_value,
                );
            }
        }
    }

    let _ = hpack_context.end_header_block();
}

/// Test zero table size edge case
fn test_zero_table_size(test_case: &SettingsUpdateTestCase) {
    if !test_case.malformed_scenarios.zero_size_table {
        return;
    }

    let mut hpack_context = create_hpack_context(test_case.initial_table_size);

    // Add some entries first
    let _ = hpack_context.add_to_dynamic_table("x-header", "value");
    let initial_count = hpack_context.dynamic_table.len();

    // Set table size to zero
    let result = hpack_context.update_header_table_size(0);

    match result {
        Ok(eviction_info) => {
            // Zero size should evict all entries
            assert_eq!(hpack_context.max_table_size, 0);
            assert_eq!(hpack_context.current_table_size, 0);
            assert_eq!(hpack_context.dynamic_table.len(), 0);
            assert_eq!(eviction_info.entries_evicted, initial_count);

            // Verify we cannot add new entries
            let add_result = hpack_context.add_to_dynamic_table("x-new", "value");
            assert!(
                add_result.is_err(),
                "Should not be able to add entries with zero table size"
            );
        }
        Err(_) => {
            // Some implementations might reject zero size
        }
    }
}

/// Test maximum table size limits
fn test_maximum_table_size(test_case: &SettingsUpdateTestCase) {
    let mut hpack_context = create_hpack_context(test_case.initial_table_size);

    // Test extremely large size updates
    let large_sizes = [
        MAX_HEADER_TABLE_SIZE + 1,
        u32::MAX,
        0x80000000, // Sign bit set
        1_000_000_000, // 1GB
    ];

    for &large_size in &large_sizes {
        let result = hpack_context.update_header_table_size(large_size);

        match result {
            Ok(_) => {
                // If accepted, verify it's clamped to reasonable limits
                assert!(
                    hpack_context.max_table_size <= MAX_HEADER_TABLE_SIZE,
                    "Table size should be clamped to implementation maximum"
                );
            }
            Err(error_msg) => {
                // Should be rejected with appropriate error
                assert!(
                    error_msg.contains("too large") ||
                    error_msg.contains("exceeds maximum") ||
                    error_msg.contains("limit"),
                    "Large size should be rejected with appropriate error"
                );
            }
        }
    }
}

/// Test unacknowledged settings updates
fn test_unacknowledged_updates(test_case: &SettingsUpdateTestCase) {
    if !test_case.malformed_scenarios.unacknowledged_update {
        return;
    }

    let mut hpack_context = create_hpack_context(test_case.initial_table_size);

    // Send settings update but don't acknowledge
    if let Some(update) = test_case.update_sequence.first() {
        // Simulate settings frame sent but not yet acknowledged
        hpack_context.pending_table_size_update = Some(update.new_size);

        // Try to use new table size before acknowledgment
        let result = hpack_context.add_to_dynamic_table("x-test", "before-ack");

        match result {
            Ok(_) => {
                // Implementation might allow this
            }
            Err(error_msg) => {
                // Or it might require acknowledgment first
                assert!(
                    error_msg.contains("unacknowledged") ||
                    error_msg.contains("pending"),
                    "Should indicate unacknowledged update issue"
                );
            }
        }

        // Now acknowledge the settings
        let ack_result = hpack_context.acknowledge_settings_update();
        assert!(ack_result.is_ok(), "Settings acknowledgment should succeed");

        // Verify table size is now active
        assert_eq!(hpack_context.max_table_size, update.new_size);
    }
}

/// Test duplicate size updates
fn test_duplicate_size_updates(test_case: &SettingsUpdateTestCase) {
    if !test_case.malformed_scenarios.duplicate_updates {
        return;
    }

    let mut hpack_context = create_hpack_context(test_case.initial_table_size);

    if let Some(update) = test_case.update_sequence.first() {
        // Apply update first time
        let first_result = hpack_context.update_header_table_size(update.new_size);
        assert!(first_result.is_ok(), "First update should succeed");

        let table_state_after_first = hpack_context.clone();

        // Apply same update again
        let second_result = hpack_context.update_header_table_size(update.new_size);

        match second_result {
            Ok(eviction_info) => {
                // Duplicate update should be idempotent
                assert_eq!(eviction_info.entries_evicted, 0);
                assert_eq!(hpack_context.max_table_size, table_state_after_first.max_table_size);
                assert_eq!(hpack_context.dynamic_table.len(), table_state_after_first.dynamic_table.len());
            }
            Err(_) => {
                // Some implementations might reject duplicate updates
            }
        }
    }
}

/// Test entry preservation across updates
fn test_entry_preservation(test_case: &SettingsUpdateTestCase) {
    let mut hpack_context = create_hpack_context(test_case.initial_table_size);

    // Add specific test entries
    let test_entries = vec![
        ("x-important", "critical-data"),
        ("x-session", "session-info"),
        ("x-auth", "auth-token"),
    ];

    let mut expected_entries = Vec::new();
    for (name, value) in &test_entries {
        if hpack_context.add_to_dynamic_table(name, value).is_ok() {
            expected_entries.push((name.to_string(), value.to_string()));
        }
    }

    // Apply size updates and verify entry preservation
    for update in &test_case.update_sequence {
        let pre_update_entries = hpack_context.dynamic_table.clone();
        let result = hpack_context.update_header_table_size(update.new_size);

        match result {
            Ok(eviction_info) => {
                // If size increased or stayed same, no entries should be lost
                if update.new_size >= hpack_context.previous_max_size {
                    assert_eq!(
                        eviction_info.entries_evicted, 0,
                        "No entries should be evicted when size increases"
                    );

                    // Verify all entries preserved
                    assert_eq!(
                        hpack_context.dynamic_table.len(), pre_update_entries.len(),
                        "All entries should be preserved"
                    );
                }

                // If size decreased, verify FIFO eviction
                if eviction_info.entries_evicted > 0 {
                    let remaining_count = pre_update_entries.len() - eviction_info.entries_evicted;
                    assert_eq!(
                        hpack_context.dynamic_table.len(), remaining_count,
                        "Should have exact number of remaining entries"
                    );

                    // Verify most recently added entries are preserved (LIFO eviction)
                    for (i, entry) in hpack_context.dynamic_table.iter().enumerate() {
                        let original_index = pre_update_entries.len() - remaining_count + i;
                        if original_index < pre_update_entries.len() {
                            let original_entry = &pre_update_entries[original_index];
                            assert_eq!(entry.name, original_entry.name);
                            assert_eq!(entry.value, original_entry.value);
                        }
                    }
                }

                hpack_context.previous_max_size = update.new_size;
            }
            Err(_) => {
                // Update failed, entries should be unchanged
                assert_eq!(
                    hpack_context.dynamic_table.len(), pre_update_entries.len(),
                    "Failed update should not change table"
                );
            }
        }
    }
}

// Helper structures and functions

#[derive(Debug, Clone)]
struct HpackContext {
    dynamic_table: Vec<HeaderEntry>,
    max_table_size: u32,
    current_table_size: u32,
    previous_max_size: u32,
    pending_table_size_update: Option<u32>,
    in_header_block: bool,
}

#[derive(Debug, Clone)]
struct HeaderEntry {
    name: String,
    value: String,
    size: u32,
}

#[derive(Debug)]
struct EvictionInfo {
    entries_evicted: usize,
    bytes_freed: u32,
}

fn create_hpack_context(initial_size: u32) -> HpackContext {
    HpackContext {
        dynamic_table: Vec::new(),
        max_table_size: initial_size.min(MAX_HEADER_TABLE_SIZE),
        current_table_size: 0,
        previous_max_size: initial_size.min(MAX_HEADER_TABLE_SIZE),
        pending_table_size_update: None,
        in_header_block: false,
    }
}

impl HpackContext {
    fn add_to_dynamic_table(&mut self, name: &str, value: &str) -> Result<(), String> {
        if self.max_table_size == 0 {
            return Err("Cannot add entries with zero table size".to_string());
        }

        let entry_size = calculate_entry_size(name, value);

        if entry_size > self.max_table_size {
            return Err("Entry too large for table".to_string());
        }

        // Evict entries to make space if necessary
        while self.current_table_size + entry_size > self.max_table_size && !self.dynamic_table.is_empty() {
            if let Some(evicted) = self.dynamic_table.pop() {
                self.current_table_size -= evicted.size;
            }
        }

        if self.current_table_size + entry_size <= self.max_table_size {
            let entry = HeaderEntry {
                name: name.to_string(),
                value: value.to_string(),
                size: entry_size,
            };

            self.current_table_size += entry_size;
            self.dynamic_table.insert(0, entry); // Insert at beginning (newest)
            Ok(())
        } else {
            Err("Cannot fit entry in table".to_string())
        }
    }

    fn update_header_table_size(&mut self, new_size: u32) -> Result<EvictionInfo, String> {
        if new_size > MAX_HEADER_TABLE_SIZE {
            return Err("Table size exceeds maximum allowed".to_string());
        }

        let old_size = self.max_table_size;
        self.max_table_size = new_size;

        let mut entries_evicted = 0;
        let mut bytes_freed = 0;

        // If size reduced, evict entries from end (oldest first)
        while self.current_table_size > new_size && !self.dynamic_table.is_empty() {
            if let Some(evicted) = self.dynamic_table.pop() {
                self.current_table_size -= evicted.size;
                bytes_freed += evicted.size;
                entries_evicted += 1;
            }
        }

        self.previous_max_size = old_size;

        Ok(EvictionInfo {
            entries_evicted,
            bytes_freed,
        })
    }

    fn update_header_table_size_during_block(&mut self, new_size: u32) -> Result<EvictionInfo, String> {
        if self.in_header_block {
            return Err("Header table size update not allowed during header block".to_string());
        }
        self.update_header_table_size(new_size)
    }

    fn start_header_block(&mut self) {
        self.in_header_block = true;
    }

    fn end_header_block(&mut self) -> Result<(), String> {
        self.in_header_block = false;
        Ok(())
    }

    fn acknowledge_settings_update(&mut self) -> Result<(), String> {
        if let Some(pending_size) = self.pending_table_size_update.take() {
            self.update_header_table_size(pending_size).map(|_| ())
        } else {
            Ok(())
        }
    }

    fn process_literal_header_with_indexing(&mut self, name: &str, value: &str) -> Result<(), String> {
        self.add_to_dynamic_table(name, value)
    }

    fn process_literal_header(&mut self, _name: &str, _value: &str) -> Result<(), String> {
        // Literal without indexing doesn't affect dynamic table
        Ok(())
    }

    fn process_indexed_header(&mut self, index: u8) -> Result<(), String> {
        let table_index = index as usize;
        if table_index == 0 || table_index > self.dynamic_table.len() {
            return Err("Invalid dynamic table index".to_string());
        }

        // Accessing indexed header is valid
        Ok(())
    }
}

fn calculate_entry_size(name: &str, value: &str) -> u32 {
    // RFC 7541 Section 4.1: entry size = name length + value length + 32
    (name.len() + value.len() + 32) as u32
}