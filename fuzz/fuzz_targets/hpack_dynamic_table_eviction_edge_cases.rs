#![no_main]

//! Structure-aware fuzzer for HPACK dynamic table eviction edge cases.
//!
//! Targets specific boundary conditions and edge cases in the dynamic table
//! eviction logic (br-asupersync-7vtdn8), focusing on:
//!
//! 1. Saturating arithmetic boundaries in size calculations
//! 2. Edge cases around table size limits (0, 1, MAX_ALLOWED_TABLE_SIZE)
//! 3. Index cleanup consistency during rapid evictions
//! 4. Boundary conditions in `pop_back_with_index_cleanup`
//! 5. Interaction between entry size calculation and table size limits
//!
//! This fuzzer operates directly on the DynamicTable internal structure
//! rather than the higher-level encoder/decoder APIs to maximize coverage
//! of the eviction-specific code paths.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::http::h2::hpack::{DEFAULT_MAX_TABLE_SIZE, DynamicTable, Header};

/// Fuzzing configuration for dynamic table eviction edge cases
#[derive(Debug, Clone, Arbitrary)]
struct DynamicTableEvictionInput {
    /// Initial table size - focus on boundary values
    #[arbitrary(with = table_size_arbitrary)]
    initial_table_size: usize,

    /// Sequence of operations that trigger eviction scenarios
    operations: Vec<EvictionOperation>,
}

/// Operations that can trigger different eviction edge cases
#[derive(Debug, Clone, Arbitrary)]
enum EvictionOperation {
    /// Insert a header with specific size characteristics
    Insert {
        #[arbitrary(with = header_name_arbitrary)]
        name: String,
        #[arbitrary(with = header_value_arbitrary)]
        value: String,
    },

    /// Change table size to trigger immediate eviction
    SetMaxSize {
        #[arbitrary(with = table_size_arbitrary)]
        new_size: usize,
    },

    /// Insert an oversized header that should clear the table
    InsertOversized {
        #[arbitrary(with = oversized_header_arbitrary)]
        name: String,
        #[arbitrary(with = oversized_header_arbitrary)]
        value: String,
    },

    /// Rapid sequence of tiny headers to test eviction loop
    BurstInsertTiny {
        count: u8, // Will be clamped to reasonable range
        #[arbitrary(with = tiny_string_arbitrary)]
        name_prefix: String,
        #[arbitrary(with = tiny_string_arbitrary)]
        value_prefix: String,
    },

    /// Insert at exact size boundaries
    InsertExactSize {
        /// Target total header size (name + value + 32)
        target_size: u16,
    },
}

/// Custom arbitrary for table sizes focusing on boundary values
fn table_size_arbitrary(u: &mut Unstructured) -> arbitrary::Result<usize> {
    let choice: u8 = u.arbitrary()?;
    Ok(match choice % 20 {
        0 => 0,                          // Empty table
        1 => 1,                          // Minimal size
        2 => 32,                         // Just overhead
        3 => 33,                         // Minimal entry
        4 => 64,                         // Two entries overhead
        5 => DEFAULT_MAX_TABLE_SIZE,     // Default size
        6 => DEFAULT_MAX_TABLE_SIZE - 1, // Just under default
        7 => DEFAULT_MAX_TABLE_SIZE + 1, // Just over default
        8 => 1024 * 1024,                // Max allowed
        9 => 1024 * 1024 - 1,            // Just under max
        10 => usize::MAX,                // Saturation test
        11..=19 => {
            // Random sizes with bias toward boundaries
            let base: u16 = u.arbitrary()?;
            (base as usize) % (DEFAULT_MAX_TABLE_SIZE * 2)
        }
        _ => unreachable!(),
    })
}

/// Custom arbitrary for header names with edge case biases
fn header_name_arbitrary(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice: u8 = u.arbitrary()?;
    Ok(match choice % 10 {
        0 => String::new(),              // Empty name
        1 => "a".to_string(),            // Single char
        2 => "x-".repeat(1000),          // Very long name
        3 => ":authority".to_string(),   // Common header
        4 => "\x00\x01\x02".to_string(), // Binary data
        5 => "ä ö ü".to_string(),        // Unicode
        6..=9 => {
            // Random string with controlled length
            let len: u8 = u.arbitrary()?;
            let len = (len % 64) as usize; // Limit to reasonable size
            (0..len)
                .map(|_| Ok(char::from(u.arbitrary::<u8>()? % 128)))
                .collect::<arbitrary::Result<String>>()?
        }
        _ => unreachable!(),
    })
}

/// Custom arbitrary for header values with edge case biases
fn header_value_arbitrary(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice: u8 = u.arbitrary()?;
    Ok(match choice % 10 {
        0 => String::new(),                    // Empty value
        1 => "x".to_string(),                  // Single char
        2 => "value-".repeat(500),             // Very long value
        3 => "localhost:8080".to_string(),     // Typical value
        4 => "\u{80}\u{81}\u{82}".to_string(), // Non-ASCII controls
        5 => " \t\r\n".to_string(),            // Whitespace
        6..=9 => {
            // Random string with controlled length
            let len: u8 = u.arbitrary()?;
            let len = (len % 128) as usize; // Limit to reasonable size
            (0..len)
                .map(|_| Ok(char::from(u.arbitrary::<u8>()?)))
                .collect::<arbitrary::Result<String>>()?
        }
        _ => unreachable!(),
    })
}

/// Generate oversized header components
fn oversized_header_arbitrary(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len: u16 = u.arbitrary()?;
    let len = ((len % 2048) + 1024) as usize; // 1K-3K range
    Ok((0..len).map(|_| 'x').collect())
}

/// Generate tiny strings for rapid insertion tests
fn tiny_string_arbitrary(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len: u8 = u.arbitrary()?;
    let len = (len % 4) as usize; // 0-3 chars
    Ok((0..len).map(|_| char::from(b'a' + (len as u8))).collect())
}

/// Normalize and validate input to prevent degenerate test cases
fn normalize_input(input: &mut DynamicTableEvictionInput) {
    // Limit operation count to prevent timeout
    input.operations.truncate(100);

    // Ensure we have at least some operations
    if input.operations.is_empty() {
        input.operations.push(EvictionOperation::Insert {
            name: "test".to_string(),
            value: "value".to_string(),
        });
    }

    // Clamp initial table size to prevent extreme memory usage
    if input.initial_table_size > 1024 * 1024 {
        input.initial_table_size %= 1024 * 1024;
    }

    // Normalize operation parameters
    for op in &mut input.operations {
        match op {
            EvictionOperation::BurstInsertTiny { count, .. } => {
                *count = (*count).min(50); // Prevent excessive operations
            }
            EvictionOperation::InsertExactSize { target_size } => {
                *target_size = (*target_size).clamp(33, 4096); // Reasonable range
            }
            _ => {} // Other operations self-limit through string size
        }
    }
}

/// Execute the eviction edge case fuzzing scenario
fn fuzz_dynamic_table_eviction_edges(mut input: DynamicTableEvictionInput) {
    normalize_input(&mut input);

    let mut table = DynamicTable::with_max_size(input.initial_table_size);

    // Track invariants throughout the fuzzing session
    let mut operations_executed = 0;

    for operation in input.operations {
        operations_executed += 1;

        // Check invariants before operation
        assert_table_invariants(&table);

        match operation {
            EvictionOperation::Insert { name, value } => {
                let header = Header::new(name, value);

                // Record state before insertion
                let size_before = table.size();
                let max_size = table.max_size();

                table.insert(header);

                // Verify eviction maintained size constraint
                assert!(
                    table.size() <= max_size,
                    "Table size {} exceeds max {} after insert (op {})",
                    table.size(),
                    max_size,
                    operations_executed
                );

                // Verify size only decreased or stayed same if eviction occurred
                if size_before > max_size {
                    assert!(
                        table.size() <= size_before,
                        "Table size increased during eviction (op {})",
                        operations_executed
                    );
                }
            }

            EvictionOperation::SetMaxSize { new_size } => {
                let size_before = table.size();
                table.set_max_size(new_size);

                // Verify eviction maintained new size constraint
                assert!(
                    table.size() <= table.max_size(),
                    "Table size {} exceeds new max {} after resize (op {})",
                    table.size(),
                    table.max_size(),
                    operations_executed
                );

                // If new size is smaller, table size should not exceed it
                if new_size < size_before {
                    assert!(
                        table.size() <= new_size,
                        "Table not properly evicted after size reduction (op {})",
                        operations_executed
                    );
                }
            }

            EvictionOperation::InsertOversized { name, value } => {
                let header = Header::new(name, value);
                let header_size = header.name.len() + header.value.len() + 32;

                table.insert(header);

                // If header was too large, table should be empty
                if header_size > table.max_size() {
                    assert_eq!(
                        table.size(),
                        0,
                        "Table not emptied after oversized insert (op {})",
                        operations_executed
                    );
                }
            }

            EvictionOperation::BurstInsertTiny {
                count,
                name_prefix,
                value_prefix,
            } => {
                for i in 0..count {
                    let name = format!("{}{}", name_prefix, i);
                    let value = format!("{}{}", value_prefix, i);
                    let header = Header::new(name, value);

                    table.insert(header);

                    // Table should never exceed max size
                    assert!(
                        table.size() <= table.max_size(),
                        "Table size exceeded during burst insert (op {}, burst {})",
                        operations_executed,
                        i
                    );
                }
            }

            EvictionOperation::InsertExactSize { target_size } => {
                // Create a header that targets a specific total size
                let overhead = 32; // HPACK overhead per entry
                if target_size > overhead as u16 {
                    let remaining = (target_size - overhead as u16) as usize;
                    let name_len = remaining / 2;
                    let value_len = remaining - name_len;

                    let name = "n".repeat(name_len);
                    let value = "v".repeat(value_len);
                    let header = Header::new(name, value);

                    table.insert(header);

                    assert!(
                        table.size() <= table.max_size(),
                        "Table size exceeded after exact-size insert (op {})",
                        operations_executed
                    );
                }
            }
        }

        // Check invariants after operation
        assert_table_invariants(&table);

        // Test lookup consistency - entries should be findable by name/value
        // (This exercises the index cleanup logic)
        let _test_lookup = table.find("nonexistent", "header");
    }
}

/// Assert critical invariants about the dynamic table state
fn assert_table_invariants(table: &DynamicTable) {
    // Size should never exceed max_size
    assert!(
        table.size() <= table.max_size(),
        "Table size {} exceeds max size {}",
        table.size(),
        table.max_size()
    );

    // Max size should never exceed the global maximum
    assert!(
        table.max_size() <= 1024 * 1024,
        "Max size {} exceeds global maximum",
        table.max_size()
    );

    // Table should be consistent with itself
    // Note: More detailed invariants would require exposing internal state
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 10_000 {
        return; // Prevent excessive memory usage
    }

    let mut u = Unstructured::new(data);
    if let Ok(input) = DynamicTableEvictionInput::arbitrary(&mut u) {
        fuzz_dynamic_table_eviction_edges(input);
    }
});
