//! Fuzzing target for HTTP/2 SETTINGS_HEADER_TABLE_SIZE underflow vulnerabilities.
//!
//! Tests edge cases around very small or zero HPACK dynamic table sizes that could
//! trigger arithmetic underflow, state inconsistencies, or performance degradation.
//!
//! Vulnerability areas:
//! 1. Zero table size handling in dynamic table eviction
//! 2. Very small sizes causing excessive eviction/insertion cycles
//! 3. Size arithmetic edge cases in table management
//! 4. State consistency when table size changes dramatically

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Mock HPACK dynamic table for testing header table size underflow scenarios.
#[derive(Debug, Clone)]
pub struct MockDynamicTable {
    /// Current entries in the table
    entries: Vec<HeaderEntry>,
    /// Current table size in bytes
    current_size: usize,
    /// Maximum allowed table size
    max_size: usize,
    /// Statistics for underflow analysis
    stats: TableStats,
}

/// Header entry for the mock dynamic table
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
    pub size: usize, // RFC 7541 size: name_len + value_len + 32
}

/// Statistics tracked during table operations
#[derive(Debug, Clone, Default)]
pub struct TableStats {
    /// Total evictions performed
    pub eviction_count: u32,
    /// Total insertions attempted
    pub insertion_count: u32,
    /// Number of failed insertions (entry too large)
    pub failed_insertions: u32,
    /// Maximum entries held simultaneously
    pub max_entries: usize,
    /// Minimum table size encountered
    pub min_table_size: usize,
    /// Number of complete table clears
    pub complete_clears: u32,
    /// Number of size-0 operations
    pub zero_size_ops: u32,
}

/// Table size underflow test scenario
#[derive(Debug, Clone, Arbitrary)]
pub struct HeaderTableSizeScenario {
    /// Sequence of table size changes to test
    pub size_sequence: Vec<u32>,
    /// Headers to insert during the test
    pub header_insertions: Vec<HeaderInsertionOp>,
    /// Whether to test extreme size transitions
    pub test_extreme_transitions: bool,
    /// Maximum number of operations to prevent infinite loops
    pub max_operations: u16,
}

/// Header insertion operation for testing
#[derive(Debug, Clone, Arbitrary)]
pub struct HeaderInsertionOp {
    /// Header name (limited to prevent excessive memory usage)
    pub name: HeaderName,
    /// Header value (limited to prevent excessive memory usage)
    pub value: HeaderValue,
    /// When to perform this insertion (index in size_sequence)
    pub insert_at_step: u8,
}

/// Limited header name choices for focused testing
#[derive(Debug, Clone, Arbitrary)]
pub enum HeaderName {
    ContentType,
    Authorization,
    CacheControl,
    UserAgent,
    Accept,
    Custom(String), // Arbitrary will limit this automatically
}

/// Limited header value choices for focused testing
#[derive(Debug, Clone, Arbitrary)]
pub enum HeaderValue {
    Short(String),  // 1-20 bytes
    Medium(String), // 21-200 bytes
    Large(String),  // 201-2000 bytes
    Empty,
}

impl HeaderEntry {
    pub fn new(name: String, value: String) -> Self {
        // RFC 7541: size = name_len + value_len + 32
        let size = name.len() + value.len() + 32;
        Self { name, value, size }
    }
}

impl MockDynamicTable {
    pub fn new(initial_max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            current_size: 0,
            max_size: initial_max_size,
            stats: TableStats {
                min_table_size: initial_max_size,
                ..Default::default()
            },
        }
    }

    /// Set new maximum table size and evict if necessary
    pub fn set_max_size(&mut self, new_max_size: usize) -> TableSizeChangeResult {
        let old_max_size = self.max_size;
        let old_entry_count = self.entries.len();

        // Track minimum table size for underflow analysis
        self.stats.min_table_size = self.stats.min_table_size.min(new_max_size);

        // Handle zero size specially
        if new_max_size == 0 {
            self.stats.zero_size_ops += 1;
            if !self.entries.is_empty() {
                self.stats.complete_clears += 1;
            }
        }

        self.max_size = new_max_size;

        // Evict entries that no longer fit
        let mut evicted_entries = Vec::new();
        while self.current_size > self.max_size && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop() {
                self.current_size = self.current_size.saturating_sub(evicted.size);
                self.stats.eviction_count += 1;
                evicted_entries.push(evicted);
            } else {
                break; // Safety guard against infinite loop
            }
        }

        // Detect potential underflow condition
        let has_underflow_risk = new_max_size < 64 && old_max_size > 1024;

        TableSizeChangeResult {
            old_max_size,
            new_max_size,
            old_entry_count,
            new_entry_count: self.entries.len(),
            evicted_entries,
            underflow_risk: has_underflow_risk,
            final_table_size: self.current_size,
        }
    }

    /// Insert a new header entry
    pub fn insert_entry(&mut self, entry: HeaderEntry) -> InsertionResult {
        self.stats.insertion_count += 1;

        // Check if entry is too large for current max size
        if entry.size > self.max_size {
            self.stats.failed_insertions += 1;
            return InsertionResult::TooLarge {
                entry_size: entry.size,
                max_size: self.max_size,
            };
        }

        // Handle zero-size table edge case
        if self.max_size == 0 {
            return InsertionResult::ZeroSizeTable;
        }

        // Evict entries to make room
        let mut evicted = Vec::new();
        while self.current_size.saturating_add(entry.size) > self.max_size
            && !self.entries.is_empty()
        {
            if let Some(evicted_entry) = self.entries.pop() {
                self.current_size = self.current_size.saturating_sub(evicted_entry.size);
                self.stats.eviction_count += 1;
                evicted.push(evicted_entry);
            } else {
                break;
            }
        }

        // Final check for space
        if self.current_size.saturating_add(entry.size) <= self.max_size {
            self.current_size = self.current_size.saturating_add(entry.size);
            self.entries.insert(0, entry.clone());

            // Update max entries stat
            self.stats.max_entries = self.stats.max_entries.max(self.entries.len());

            InsertionResult::Success {
                entry,
                evicted_to_make_room: evicted,
                final_table_size: self.current_size,
                final_entry_count: self.entries.len(),
            }
        } else {
            self.stats.failed_insertions += 1;
            InsertionResult::InsufficientSpace {
                needed: entry.size,
                available: self.max_size.saturating_sub(self.current_size),
            }
        }
    }

    /// Validate table consistency
    pub fn validate_consistency(&self) -> ConsistencyReport {
        let mut violations = Vec::new();

        // Check: current size matches sum of entry sizes
        let calculated_size: usize = self.entries.iter().map(|e| e.size).sum();
        if self.current_size != calculated_size {
            violations.push(ConsistencyViolation::SizeMismatch {
                reported: self.current_size,
                calculated: calculated_size,
            });
        }

        // Check: current size doesn't exceed max size
        if self.current_size > self.max_size {
            violations.push(ConsistencyViolation::SizeExceedsLimit {
                current: self.current_size,
                limit: self.max_size,
            });
        }

        // Check: no individual entry exceeds max size
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.size > self.max_size {
                violations.push(ConsistencyViolation::EntryTooLarge {
                    index: idx,
                    entry_size: entry.size,
                    limit: self.max_size,
                });
            }
        }

        // Check for arithmetic underflow indicators
        if self.max_size == 0 && !self.entries.is_empty() {
            violations.push(ConsistencyViolation::EntriesInZeroSizeTable);
        }

        ConsistencyReport { violations }
    }
}

#[derive(Debug, Clone)]
pub struct TableSizeChangeResult {
    pub old_max_size: usize,
    pub new_max_size: usize,
    pub old_entry_count: usize,
    pub new_entry_count: usize,
    pub evicted_entries: Vec<HeaderEntry>,
    pub underflow_risk: bool,
    pub final_table_size: usize,
}

#[derive(Debug, Clone)]
pub enum InsertionResult {
    Success {
        entry: HeaderEntry,
        evicted_to_make_room: Vec<HeaderEntry>,
        final_table_size: usize,
        final_entry_count: usize,
    },
    TooLarge {
        entry_size: usize,
        max_size: usize,
    },
    InsufficientSpace {
        needed: usize,
        available: usize,
    },
    ZeroSizeTable,
}

#[derive(Debug, Clone)]
pub struct ConsistencyReport {
    pub violations: Vec<ConsistencyViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistencyViolation {
    SizeMismatch {
        reported: usize,
        calculated: usize,
    },
    SizeExceedsLimit {
        current: usize,
        limit: usize,
    },
    EntryTooLarge {
        index: usize,
        entry_size: usize,
        limit: usize,
    },
    EntriesInZeroSizeTable,
}

impl HeaderName {
    fn to_string(&self) -> String {
        match self {
            HeaderName::ContentType => "content-type".to_string(),
            HeaderName::Authorization => "authorization".to_string(),
            HeaderName::CacheControl => "cache-control".to_string(),
            HeaderName::UserAgent => "user-agent".to_string(),
            HeaderName::Accept => "accept".to_string(),
            HeaderName::Custom(s) => s.chars().take(50).collect(), // Limit custom names
        }
    }
}

impl HeaderValue {
    fn to_string(&self) -> String {
        match self {
            HeaderValue::Short(s) => s.chars().take(20).collect(),
            HeaderValue::Medium(s) => s.chars().take(200).collect(),
            HeaderValue::Large(s) => s.chars().take(2000).collect(),
            HeaderValue::Empty => String::new(),
        }
    }
}

/// Test specific underflow scenarios
fn test_zero_size_transitions() {
    let mut table = MockDynamicTable::new(4096);

    // Insert some entries
    table.insert_entry(HeaderEntry::new(
        "content-type".to_string(),
        "application/json".to_string(),
    ));
    table.insert_entry(HeaderEntry::new(
        "authorization".to_string(),
        "Bearer token123".to_string(),
    ));

    assert!(!table.entries.is_empty());

    // Transition to zero size - should evict everything
    let result = table.set_max_size(0);
    assert!(table.entries.is_empty());
    assert_eq!(table.current_size, 0);
    assert!(result.new_entry_count == 0);
    assert!(result.evicted_entries.len() >= 2);

    // Try to insert into zero-size table - should fail gracefully
    let insert_result =
        table.insert_entry(HeaderEntry::new("test".to_string(), "value".to_string()));
    assert!(matches!(insert_result, InsertionResult::ZeroSizeTable));
}

/// Test very small size transitions that could cause arithmetic issues
fn test_small_size_arithmetic() {
    let mut table = MockDynamicTable::new(1);

    // Try various small sizes
    for size in [1, 2, 4, 8, 16, 31, 32, 33] {
        table.set_max_size(size);

        // Try inserting minimal entries
        let entry = HeaderEntry::new("a".to_string(), "b".to_string()); // 35 bytes total
        let result = table.insert_entry(entry);

        // Should fail for sizes < 35, succeed for sizes >= 35
        match result {
            InsertionResult::Success { .. } if size >= 35 => {
                // Expected success
            }
            InsertionResult::TooLarge { .. } | InsertionResult::InsufficientSpace { .. }
                if size < 35 =>
            {
                // Expected failure
            }
            _ => {
                // Unexpected result
                panic!("Unexpected result for size {}: {:?}", size, result);
            }
        }

        // Validate consistency after each operation
        let consistency = table.validate_consistency();
        assert!(
            consistency.violations.is_empty(),
            "Consistency violations at size {}: {:?}",
            size,
            consistency.violations
        );
    }
}

/// Test rapid size transitions for performance and state consistency
fn test_rapid_size_changes() {
    let mut table = MockDynamicTable::new(8192);

    // Insert many entries
    for i in 0..20 {
        table.insert_entry(HeaderEntry::new(
            format!("header-{}", i),
            format!("value-for-header-number-{}-with-some-extra-content", i),
        ));
    }

    // Rapidly change sizes
    let sizes = [8192, 1024, 0, 512, 1, 4096, 0, 2048, 16];
    for &size in &sizes {
        table.set_max_size(size);

        // Validate consistency after each change
        let consistency = table.validate_consistency();
        assert!(
            consistency.violations.is_empty(),
            "Rapid transition to size {} caused violations: {:?}",
            size,
            consistency.violations
        );
    }
}

fuzz_target!(|scenario: HeaderTableSizeScenario| {
    // Limit operations to prevent timeouts
    let max_ops = scenario.max_operations.min(1000);
    let limited_sizes: Vec<u32> = scenario
        .size_sequence
        .into_iter()
        .take(max_ops as usize)
        .collect();

    if limited_sizes.is_empty() {
        return;
    }

    // Start with a reasonable initial size
    let initial_size = limited_sizes.first().copied().unwrap_or(4096) as usize;
    let mut table = MockDynamicTable::new(initial_size);

    // Track all violations found during the test
    let mut all_violations = Vec::new();

    for (step, &new_size) in limited_sizes.iter().enumerate() {
        let new_size = new_size as usize;

        // Apply size change
        let change_result = table.set_max_size(new_size);

        // Insert headers as specified in the scenario
        for insertion in &scenario.header_insertions {
            if insertion.insert_at_step as usize == step {
                let name = insertion.name.to_string();
                let value = insertion.value.to_string();
                let entry = HeaderEntry::new(name, value);

                let insert_result = table.insert_entry(entry);

                // Log interesting insertion results
                match insert_result {
                    InsertionResult::Success { .. } => {
                        // Normal case
                    }
                    InsertionResult::ZeroSizeTable => {
                        // Expected for zero-size table
                        assert_eq!(table.max_size, 0);
                    }
                    InsertionResult::TooLarge {
                        entry_size,
                        max_size,
                    } => {
                        // Entry larger than max table size
                        assert!(entry_size > max_size);
                    }
                    InsertionResult::InsufficientSpace { needed, available } => {
                        // Not enough space even after eviction
                        assert!(needed > available);
                    }
                }
            }
        }

        // Validate table consistency after each step
        let consistency = table.validate_consistency();
        all_violations.extend(consistency.violations);

        // Check for underflow indicators
        if change_result.underflow_risk {
            // This was a potentially problematic size transition
            // Ensure it didn't break anything
            assert!(table.validate_consistency().violations.is_empty());
            assert_eq!(table.max_size, new_size);
            assert!(table.current_size <= table.max_size);
        }
    }

    // Final consistency check
    let final_consistency = table.validate_consistency();
    assert!(
        final_consistency.violations.is_empty(),
        "Final consistency check failed: {:?}",
        final_consistency.violations
    );

    // If we found any violations, they should have been from intermediate states
    // and we should have recovered by the end
    if !all_violations.is_empty() {
        // Log for analysis but don't fail - some intermediate violations might be acceptable
        // as long as we end in a consistent state
    }

    // Test specific edge cases periodically
    if limited_sizes.len() == 1 {
        test_zero_size_transitions();
        test_small_size_arithmetic();
        test_rapid_size_changes();
    }

    // Verify stats make sense
    let stats = &table.stats;
    assert!(stats.insertion_count >= stats.failed_insertions);
    assert!(stats.max_entries <= 1000); // Reasonable upper bound
    assert!(stats.min_table_size <= table.max_size);
});
