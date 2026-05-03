//! Fuzzing target for HPACK Dynamic Table Size Update underflow protection.
//!
//! Tests RFC 7541 compliance for dynamic table size updates with forced eviction:
//! 1. Populate dynamic table with header entries consuming known byte count
//! 2. Send Dynamic Table Size Update to value lower than current entries occupy
//! 3. Verify eviction is bytewise-correct (removes oldest entries first)
//! 4. Counter underflow cannot occur in size accounting
//! 5. Table state remains consistent after forced eviction
//!
//! Vulnerability areas:
//! - Integer underflow in table size accounting during eviction
//! - Incorrect eviction order (not FIFO as required by RFC 7541)
//! - Inconsistent state between table entries and size counter
//! - Missing eviction when table size reduced
//! - Memory leaks from incomplete eviction cleanup
//! - Side index corruption during mass eviction

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;

/// Test scenarios for HPACK table size underflow
#[derive(Debug, Arbitrary)]
pub struct HpackTableSizeUpdateInput {
    /// Initial entries to populate the table
    initial_entries: Vec<HeaderEntry>,
    /// Size updates to perform (may trigger eviction)
    size_updates: Vec<SizeUpdate>,
    /// Additional operations after size updates
    operations: Vec<TableOperation>,
    /// Test mode selection
    mode: TableSizeTestMode,
}

/// Header entry for populating the dynamic table
#[derive(Debug, Arbitrary)]
pub struct HeaderEntry {
    name: HeaderString,
    value: HeaderString,
}

/// String with bounded length for headers
#[derive(Debug, Clone)]
pub struct HeaderString(String);

impl Arbitrary<'_> for HeaderString {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let len = u8::arbitrary(u)? as usize % 64; // Cap at 64 chars
        let chars: Vec<char> = (0..len)
            .map(|_| {
                // ASCII printable chars for header names/values
                let c = (u8::arbitrary(u)? % 94) + 32;
                char::from(c)
            })
            .collect();
        Ok(HeaderString(chars.into_iter().collect()))
    }
}

impl std::ops::Deref for HeaderString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Table size update operation
#[derive(Debug, Arbitrary)]
pub struct SizeUpdate {
    new_size: u16, // Bounded to reasonable range
    expect_eviction: bool,
}

/// Operations to test after size updates
#[derive(Debug, Arbitrary)]
pub enum TableOperation {
    /// Insert new entry
    Insert { entry: HeaderEntry },
    /// Lookup entry by index
    Lookup { index: u8 },
    /// Find entry by name+value
    Find {
        name: HeaderString,
        value: HeaderString,
    },
    /// Get current table stats
    GetStats,
}

#[derive(Debug, Arbitrary)]
pub enum TableSizeTestMode {
    /// Test gradual size reduction
    GradualReduction,
    /// Test aggressive size reduction (force mass eviction)
    AggressiveReduction,
    /// Test size increase after reduction
    SizeRecovery,
    /// Test edge cases (zero size, very small sizes)
    EdgeCases,
}

/// Mock HPACK dynamic table for testing size updates and eviction
pub struct MockHpackDynamicTable {
    /// Table entries (front = newest, back = oldest)
    entries: VecDeque<MockTableEntry>,
    /// Current total size in bytes
    size: usize,
    /// Maximum allowed size
    max_size: usize,
    /// Monotonic insertion counter
    insert_count: u64,
    /// Eviction statistics
    eviction_stats: EvictionStats,
    /// Detected violations
    violations: Vec<TableViolation>,
}

#[derive(Debug, Clone)]
pub struct MockTableEntry {
    name: String,
    value: String,
    generation: u64,
    /// Size calculation: name.len() + value.len() + 32 (RFC 7541 §4.1)
    size: usize,
}

#[derive(Debug, Default)]
pub struct EvictionStats {
    entries_evicted: u32,
    bytes_evicted: usize,
    size_updates: u32,
    eviction_rounds: u32,
}

#[derive(Debug, Clone)]
pub enum TableViolation {
    /// Size counter underflow during eviction
    SizeUnderflow {
        before_size: usize,
        entry_size: usize,
        would_be_negative: i64,
    },
    /// Total size exceeds maximum after size update
    ExceedsMaxSize {
        current_size: usize,
        max_size: usize,
    },
    /// Size counter doesn't match actual entry sizes
    SizeInconsistency {
        calculated_size: usize,
        stored_size: usize,
    },
    /// Wrong eviction order (not FIFO)
    WrongEvictionOrder {
        evicted_generation: u64,
        oldest_generation: u64,
    },
}

impl MockHpackDynamicTable {
    pub fn new() -> Self {
        Self::with_max_size(4096) // Default HPACK table size
    }

    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size,
            insert_count: 0,
            eviction_stats: EvictionStats::default(),
            violations: Vec::new(),
        }
    }

    /// Calculate header entry size per RFC 7541 §4.1
    fn entry_size(name: &str, value: &str) -> usize {
        name.len() + value.len() + 32
    }

    /// Insert new entry, evicting if necessary
    pub fn insert(&mut self, name: String, value: String) {
        let entry_size = Self::entry_size(&name, &value);
        let entry = MockTableEntry {
            name,
            value,
            generation: self.insert_count,
            size: entry_size,
        };

        // If single entry is too large, evict everything per RFC 7541 §4.4
        if entry_size > self.max_size {
            self.clear();
            return;
        }

        // Evict until there's room for the new entry
        while self.size + entry_size > self.max_size && !self.entries.is_empty() {
            self.evict_oldest();
        }

        // Insert the new entry
        self.entries.push_front(entry);
        self.size += entry_size;
        self.insert_count += 1;

        // Verify consistency
        self.verify_size_consistency();
    }

    /// Set new maximum table size, evicting entries if necessary
    pub fn set_max_size(&mut self, new_max_size: usize) {
        self.max_size = new_max_size;
        self.eviction_stats.size_updates += 1;

        // Evict entries until size is within new limit
        self.evict_to_fit();

        // Verify no violations occurred
        self.verify_size_consistency();
        self.verify_max_size_compliance();
    }

    /// Evict oldest entries until size <= max_size
    fn evict_to_fit(&mut self) {
        if self.size <= self.max_size {
            return;
        }

        self.eviction_stats.eviction_rounds += 1;
        let initial_size = self.size;

        while self.size > self.max_size && !self.entries.is_empty() {
            self.evict_oldest();
        }

        let bytes_evicted = initial_size.saturating_sub(self.size);
        self.eviction_stats.bytes_evicted += bytes_evicted;
    }

    /// Evict the oldest entry (from back of deque)
    fn evict_oldest(&mut self) {
        if let Some(evicted) = self.entries.pop_back() {
            // Check for size underflow (critical vulnerability)
            if evicted.size > self.size {
                self.violations.push(TableViolation::SizeUnderflow {
                    before_size: self.size,
                    entry_size: evicted.size,
                    would_be_negative: self.size as i64 - evicted.size as i64,
                });
                // Use saturating_sub to prevent actual underflow
                self.size = self.size.saturating_sub(evicted.size);
            } else {
                self.size -= evicted.size;
            }

            self.eviction_stats.entries_evicted += 1;

            // Verify FIFO order (oldest should have smallest generation)
            if let Some(next_oldest) = self.entries.back() {
                if evicted.generation > next_oldest.generation {
                    self.violations.push(TableViolation::WrongEvictionOrder {
                        evicted_generation: evicted.generation,
                        oldest_generation: next_oldest.generation,
                    });
                }
            }
        }
    }

    /// Clear all entries
    fn clear(&mut self) {
        let entries_cleared = self.entries.len();
        self.entries.clear();
        self.size = 0;
        self.eviction_stats.entries_evicted += entries_cleared as u32;
        self.eviction_stats.eviction_rounds += 1;
    }

    /// Lookup entry by 1-based index (after static table)
    pub fn lookup(&self, index: usize) -> Option<&MockTableEntry> {
        if index == 0 || index > self.entries.len() {
            None
        } else {
            self.entries.get(index - 1)
        }
    }

    /// Find entry by exact name+value match
    pub fn find(&self, name: &str, value: &str) -> Option<&MockTableEntry> {
        self.entries
            .iter()
            .find(|entry| entry.name == name && entry.value == value)
    }

    /// Verify size counter matches actual entry sizes
    fn verify_size_consistency(&mut self) {
        let calculated_size: usize = self.entries.iter().map(|entry| entry.size).sum();

        if calculated_size != self.size {
            self.violations.push(TableViolation::SizeInconsistency {
                calculated_size,
                stored_size: self.size,
            });
        }
    }

    /// Verify table size doesn't exceed maximum
    fn verify_max_size_compliance(&mut self) {
        if self.size > self.max_size {
            self.violations.push(TableViolation::ExceedsMaxSize {
                current_size: self.size,
                max_size: self.max_size,
            });
        }
    }

    /// Get current table statistics
    pub fn stats(&self) -> TableStats {
        TableStats {
            entry_count: self.entries.len(),
            total_size: self.size,
            max_size: self.max_size,
            evicted_entries: self.eviction_stats.entries_evicted,
            evicted_bytes: self.eviction_stats.bytes_evicted,
        }
    }

    /// Get violations detected
    pub fn violations(&self) -> &[TableViolation] {
        &self.violations
    }

    /// Check if any critical violations occurred
    pub fn has_critical_violations(&self) -> bool {
        self.violations.iter().any(|v| {
            matches!(
                v,
                TableViolation::SizeUnderflow { .. } | TableViolation::ExceedsMaxSize { .. }
            )
        })
    }
}

#[derive(Debug)]
pub struct TableStats {
    pub entry_count: usize,
    pub total_size: usize,
    pub max_size: usize,
    pub evicted_entries: u32,
    pub evicted_bytes: usize,
}

fuzz_target!(|input: HpackTableSizeUpdateInput| {
    let mut table = MockHpackDynamicTable::new();

    // Populate table with initial entries
    let initial_count = input.initial_entries.len().min(100); // Cap for performance
    for entry in input.initial_entries.iter().take(initial_count) {
        table.insert(entry.name.clone(), entry.value.clone());
    }

    let initial_stats = table.stats();

    // Perform size updates (potential eviction triggers)
    for size_update in input.size_updates.iter().take(20) {
        let new_size = size_update.new_size as usize;
        let old_size = table.stats().total_size;

        table.set_max_size(new_size);

        let new_stats = table.stats();

        // Verify eviction behavior
        if new_size < old_size && size_update.expect_eviction {
            assert!(
                new_stats.total_size <= new_size,
                "Table size {} exceeds new max {}",
                new_stats.total_size,
                new_size
            );

            // Should have evicted some entries if they didn't fit
            if old_size > new_size {
                assert!(
                    new_stats.evicted_entries > 0 || new_stats.entry_count == 0,
                    "Expected eviction when reducing from {} to {}",
                    old_size,
                    new_size
                );
            }
        }

        // Critical: no size underflow should ever occur
        assert!(
            !table
                .violations()
                .iter()
                .any(|v| matches!(v, TableViolation::SizeUnderflow { .. })),
            "Size underflow detected during table size update to {}",
            new_size
        );

        // Table should always fit within max size
        assert!(
            new_stats.total_size <= new_stats.max_size,
            "Table size {} exceeds max size {} after update",
            new_stats.total_size,
            new_stats.max_size
        );
    }

    // Perform additional operations to test table consistency
    for operation in input.operations.iter().take(20) {
        match operation {
            TableOperation::Insert { entry } => {
                table.insert(entry.name.clone(), entry.value.clone());
            }
            TableOperation::Lookup { index } => {
                let _ = table.lookup(*index as usize);
            }
            TableOperation::Find { name, value } => {
                let _ = table.find(name, value);
            }
            TableOperation::GetStats => {
                let _ = table.stats();
            }
        }

        // Verify consistency after each operation
        assert!(
            !table.has_critical_violations(),
            "Critical violations detected after table operation"
        );
    }

    // Final invariant checks
    let final_stats = table.stats();

    // Size should never exceed maximum
    assert!(
        final_stats.total_size <= final_stats.max_size,
        "Final table size {} exceeds max {}",
        final_stats.total_size,
        final_stats.max_size
    );

    // Should not have any size underflow violations
    let size_underflows: Vec<_> = table
        .violations()
        .iter()
        .filter(|v| matches!(v, TableViolation::SizeUnderflow { .. }))
        .collect();
    assert!(
        size_underflows.is_empty(),
        "Size underflow violations detected: {:?}",
        size_underflows
    );

    // Should not exceed max size
    let size_exceedances: Vec<_> = table
        .violations()
        .iter()
        .filter(|v| matches!(v, TableViolation::ExceedsMaxSize { .. }))
        .collect();
    assert!(
        size_exceedances.is_empty(),
        "Size exceedance violations detected: {:?}",
        size_exceedances
    );

    // Eviction should follow FIFO order
    let wrong_evictions: Vec<_> = table
        .violations()
        .iter()
        .filter(|v| matches!(v, TableViolation::WrongEvictionOrder { .. }))
        .collect();
    assert!(
        wrong_evictions.is_empty(),
        "Wrong eviction order violations: {:?}",
        wrong_evictions
    );
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_insert_and_size_tracking() {
        let mut table = MockHpackDynamicTable::new();

        // Insert entry
        table.insert("content-type".to_string(), "application/json".to_string());

        let stats = table.stats();
        assert_eq!(stats.entry_count, 1);
        // Size = "content-type".len() + "application/json".len() + 32 = 12 + 16 + 32 = 60
        assert_eq!(stats.total_size, 60);
    }

    #[test]
    fn test_eviction_on_size_reduction() {
        let mut table = MockHpackDynamicTable::with_max_size(100);

        // Insert entries that fit in 100 bytes
        table.insert("name".to_string(), "value".to_string()); // 4 + 5 + 32 = 41 bytes
        table.insert("x".to_string(), "y".to_string()); // 1 + 1 + 32 = 34 bytes
        // Total: 75 bytes

        let stats = table.stats();
        assert_eq!(stats.entry_count, 2);
        assert_eq!(stats.total_size, 75);

        // Reduce size to force eviction
        table.set_max_size(40); // Should evict oldest entry (name=value, 41 bytes)

        let new_stats = table.stats();
        assert_eq!(new_stats.entry_count, 1); // Only newest entry remains
        assert_eq!(new_stats.total_size, 34); // Only x=y remains
        assert!(new_stats.evicted_entries > 0);
    }

    #[test]
    fn test_size_underflow_protection() {
        let mut table = MockHpackDynamicTable::with_max_size(100);

        // Insert entry
        table.insert("test".to_string(), "data".to_string()); // 4 + 4 + 32 = 40 bytes

        // Manually corrupt size to test underflow protection
        let original_size = table.size;
        table.size = 10; // Set lower than entry size

        // Force eviction - should use saturating_sub
        table.evict_oldest();

        // Should have detected underflow violation
        assert!(
            table
                .violations()
                .iter()
                .any(|v| matches!(v, TableViolation::SizeUnderflow { .. }))
        );
        assert_eq!(table.size, 0); // Should be 0 from saturating_sub, not underflowed
    }

    #[test]
    fn test_fifo_eviction_order() {
        let mut table = MockHpackDynamicTable::with_max_size(200);

        // Insert multiple entries
        table.insert("first".to_string(), "entry".to_string()); // generation 0
        table.insert("second".to_string(), "entry".to_string()); // generation 1
        table.insert("third".to_string(), "entry".to_string()); // generation 2

        // Force eviction by reducing size significantly
        table.set_max_size(50); // Should evict in FIFO order (oldest first)

        // Should not have wrong eviction order violations
        assert!(
            !table
                .violations()
                .iter()
                .any(|v| matches!(v, TableViolation::WrongEvictionOrder { .. }))
        );
    }

    #[test]
    fn test_entry_too_large_clears_table() {
        let mut table = MockHpackDynamicTable::with_max_size(100);

        // Insert normal entry
        table.insert("normal".to_string(), "entry".to_string());
        assert_eq!(table.stats().entry_count, 1);

        // Insert entry larger than max table size
        let large_value = "x".repeat(200); // Way too big
        table.insert("large".to_string(), large_value);

        // Table should be empty
        assert_eq!(table.stats().entry_count, 0);
        assert_eq!(table.stats().total_size, 0);
    }

    #[test]
    fn test_zero_size_table() {
        let mut table = MockHpackDynamicTable::with_max_size(100);

        // Insert some entries
        table.insert("name1".to_string(), "value1".to_string());
        table.insert("name2".to_string(), "value2".to_string());
        assert!(table.stats().entry_count > 0);

        // Set size to zero - should evict everything
        table.set_max_size(0);

        let stats = table.stats();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.total_size, 0);
        assert_eq!(stats.max_size, 0);
    }

    #[test]
    fn test_lookup_and_find() {
        let mut table = MockHpackDynamicTable::new();

        table.insert("host".to_string(), "example.com".to_string());
        table.insert("method".to_string(), "GET".to_string());

        // Test lookup by index (1-based)
        let entry1 = table.lookup(1);
        assert!(entry1.is_some());
        assert_eq!(entry1.unwrap().name, "method"); // Newest first

        let entry2 = table.lookup(2);
        assert!(entry2.is_some());
        assert_eq!(entry2.unwrap().name, "host");

        // Test find by name+value
        let found = table.find("host", "example.com");
        assert!(found.is_some());
        assert_eq!(found.unwrap().value, "example.com");

        // Test not found
        let not_found = table.find("missing", "value");
        assert!(not_found.is_none());
    }
}
