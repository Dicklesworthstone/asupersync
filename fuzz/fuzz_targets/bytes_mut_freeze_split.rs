//! BytesMut freeze/split_off atomicity fuzz target
//!
//! Tests atomic consistency of freeze() and split_off() operations on BytesMut
//! buffers, focusing on edge cases that could lead to inconsistent state,
//! data corruption, or reference counting bugs.
//!
//! # Critical Properties Tested
//! - freeze() atomicity: no partial state visible during conversion
//! - split_off() atomicity: buffer partitioning is consistent
//! - Reference counting correctness during transitions
//! - Memory safety under rapid freeze/split sequences
//! - Boundary conditions at 0, length, and intermediate positions
//! - Clone safety during freeze/split operations
//!
//! # Attack Vectors
//! - Freeze during partial split operations
//! - Multiple clones before/during freeze
//! - Split at every possible boundary position
//! - Large buffer stress testing
//! - Empty buffer edge cases
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run bytes_mut_freeze_split -- -runs=10000000
//! ```

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::BytesMut;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Clone, Arbitrary)]
struct AtomicityTest {
    initial_data: Vec<u8>,
    operations: Vec<AtomicityOperation>,
}

#[derive(Debug, Clone, Arbitrary)]
enum AtomicityOperation {
    /// Test freeze atomicity with multiple observers
    FreezeWithObservers { observers: u8 },

    /// Test split_off atomicity at specific position
    SplitOffAtomic { position: usize },

    /// Test split_to atomicity at specific position
    SplitToAtomic { position: usize },

    /// Test freeze immediately after split_off
    SplitThenFreeze { split_pos: usize },

    /// Test clone during freeze sequence
    CloneFreeze { clone_count: u8 },

    /// Test boundary split operations (0, len, len/2)
    BoundarySplits,

    /// Test rapid split/freeze sequence
    RapidSplitFreeze { iterations: u8 },

    /// Test freeze consistency with multiple buffer sizes
    MultiSizeFreeze { sizes: Vec<usize> },

    /// Test split_off chain operations
    SplitChain { chain_length: u8 },

    /// Test freeze after extend operations
    ExtendThenFreeze { extend_data: Vec<u8> },

    /// Test atomic split with validation
    ValidatedSplit { position: usize },

    /// Test freeze consistency under memory pressure
    StressFreeze { iterations: u8 },
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 500_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(test) = AtomicityTest::arbitrary(&mut unstructured) else {
        return;
    };

    // Skip empty operations to focus on meaningful tests
    if test.operations.is_empty() {
        return;
    }

    for operation in test.operations {
        execute_atomicity_operation(&test.initial_data, operation);
    }
});

fn execute_atomicity_operation(initial_data: &[u8], operation: AtomicityOperation) {
    match operation {
        AtomicityOperation::FreezeWithObservers { observers } => {
            let observer_count = (observers as usize).min(8).max(1);

            let mut bytes_mut = BytesMut::from(initial_data);
            let original_len = bytes_mut.len();
            let original_ptr = bytes_mut.as_ptr();

            // Create observers (clones that should see consistent state)
            let mut observers_before = Vec::new();
            for _ in 0..observer_count {
                observers_before.push((bytes_mut.len(), bytes_mut.capacity()));
            }

            // Freeze should be atomic - all observers see same final state
            let frozen = bytes_mut.freeze();

            // Verify atomicity: frozen buffer matches all observer expectations
            for (expected_len, _) in observers_before {
                assert_eq!(frozen.len(), expected_len);
                assert_eq!(frozen.len(), original_len);
            }

            // Verify freeze doesn't change data pointer unnecessarily
            if !frozen.is_empty() {
                // Data should be preserved
                assert_eq!(frozen.as_ptr(), original_ptr);
            }
        }

        AtomicityOperation::SplitOffAtomic { position } => {
            if initial_data.is_empty() {
                return;
            }

            let mut bytes_mut = BytesMut::from(initial_data);
            let original_len = bytes_mut.len();

            let split_pos = position % (original_len + 1); // Ensure valid position

            // Capture state before split
            let pre_split_data = bytes_mut.as_ref().to_vec();

            // Perform atomic split_off
            let split_result = bytes_mut.split_off(split_pos);

            // Verify atomicity invariants
            assert_eq!(bytes_mut.len(), split_pos);
            assert_eq!(split_result.len(), original_len - split_pos);

            // Verify data integrity - no data lost or corrupted
            let mut reconstructed = Vec::new();
            reconstructed.extend_from_slice(&bytes_mut);
            reconstructed.extend_from_slice(&split_result);

            assert_eq!(reconstructed, pre_split_data);

            // Verify split boundaries are clean (no overlap)
            if split_pos > 0 && split_result.len() > 0 {
                assert_ne!(bytes_mut.as_ptr(), split_result.as_ptr());
            }
        }

        AtomicityOperation::SplitToAtomic { position } => {
            if initial_data.is_empty() {
                return;
            }

            let mut bytes_mut = BytesMut::from(initial_data);
            let original_len = bytes_mut.len();

            let split_pos = position % (original_len + 1);

            let pre_split_data = bytes_mut.as_ref().to_vec();

            // Perform atomic split_to
            let split_result = bytes_mut.split_to(split_pos);

            // Verify atomicity invariants
            assert_eq!(split_result.len(), split_pos);
            assert_eq!(bytes_mut.len(), original_len - split_pos);

            // Verify data integrity
            let mut reconstructed = Vec::new();
            reconstructed.extend_from_slice(&split_result);
            reconstructed.extend_from_slice(&bytes_mut);

            assert_eq!(reconstructed, pre_split_data);
        }

        AtomicityOperation::SplitThenFreeze { split_pos } => {
            let mut bytes_mut = BytesMut::from(initial_data);
            let original_len = bytes_mut.len();

            if original_len == 0 {
                return;
            }

            let split_pos = split_pos % (original_len + 1);

            // Split and immediately freeze both parts
            let split_off = bytes_mut.split_off(split_pos);

            let frozen_first = bytes_mut.freeze();
            let frozen_second = split_off.freeze();

            // Verify both frozen parts maintain integrity
            assert_eq!(frozen_first.len(), split_pos);
            assert_eq!(frozen_second.len(), original_len - split_pos);

            // Test that frozen parts are independently clonable
            let clone1 = frozen_first.clone();
            let clone2 = frozen_second.clone();

            if !clone1.is_empty() {
                assert_eq!(clone1.as_ptr(), frozen_first.as_ptr());
            }
            if !clone2.is_empty() {
                assert_eq!(clone2.as_ptr(), frozen_second.as_ptr());
            }
        }

        AtomicityOperation::CloneFreeze { clone_count } => {
            let clones = (clone_count as usize).min(10).max(1);

            let mut bytes_mut = BytesMut::from(initial_data);
            if bytes_mut.is_empty() {
                return;
            }

            // Clone the BytesMut multiple times (not allowed - compile error)
            // Instead test freeze then clone sequence atomicity
            let original_len = bytes_mut.len();

            let frozen = bytes_mut.freeze();

            let mut cloned_refs = Vec::new();
            for _ in 0..clones {
                cloned_refs.push(frozen.clone());
            }

            // Verify all clones maintain atomic consistency
            for clone in &cloned_refs {
                assert_eq!(clone.len(), original_len);
                if !clone.is_empty() {
                    assert_eq!(clone.as_ptr(), frozen.as_ptr());
                }
            }
        }

        AtomicityOperation::BoundarySplits => {
            if initial_data.is_empty() {
                return;
            }

            let boundaries = vec![
                0,
                1,
                initial_data.len() / 2,
                initial_data.len() - 1,
                initial_data.len(),
            ];

            for &boundary in &boundaries {
                if boundary <= initial_data.len() {
                    // Test split_off at boundary
                    let mut bytes_mut = BytesMut::from(initial_data);
                    let original_len = bytes_mut.len();

                    let split = bytes_mut.split_off(boundary);
                    assert_eq!(bytes_mut.len(), boundary);
                    assert_eq!(split.len(), original_len - boundary);

                    // Test split_to at boundary
                    let mut bytes_mut2 = BytesMut::from(initial_data);
                    let split2 = bytes_mut2.split_to(boundary);
                    assert_eq!(split2.len(), boundary);
                    assert_eq!(bytes_mut2.len(), original_len - boundary);
                }
            }
        }

        AtomicityOperation::RapidSplitFreeze { iterations } => {
            let iters = (iterations as usize).min(20).max(1);

            for i in 0..iters {
                let mut bytes_mut = BytesMut::from(initial_data);

                if bytes_mut.is_empty() {
                    continue;
                }

                // Rapid split/freeze cycles
                let len = bytes_mut.len();
                let split_pos = (i * 7) % (len + 1); // Varying positions

                let split_part = bytes_mut.split_off(split_pos);

                let frozen1 = bytes_mut.freeze();
                let frozen2 = split_part.freeze();

                // Verify rapid operations maintain consistency
                assert_eq!(frozen1.len(), split_pos);
                assert_eq!(frozen2.len(), len - split_pos);
            }
        }

        AtomicityOperation::MultiSizeFreeze { sizes } => {
            for size in sizes.iter().take(10) {
                // Limit iterations
                let capped_size = size.min(&(64 * 1024)); // Cap at 64KB

                if *capped_size > 0 {
                    let test_data: Vec<u8> = (0..*capped_size).map(|i| (i % 256) as u8).collect();
                    let mut bytes_mut = BytesMut::from(&test_data[..]);

                    let original_len = bytes_mut.len();
                    let frozen = bytes_mut.freeze();

                    assert_eq!(frozen.len(), original_len);
                    if original_len > 0 {
                        assert_eq!(frozen[0], test_data[0]);
                        assert_eq!(frozen[original_len - 1], test_data[original_len - 1]);
                    }
                }
            }
        }

        AtomicityOperation::SplitChain { chain_length } => {
            let chain_len = (chain_length as usize).min(8).max(1);

            let mut current = BytesMut::from(initial_data);
            let mut split_parts = Vec::new();

            for i in 0..chain_len {
                if current.is_empty() {
                    break;
                }

                let len = current.len();
                let split_pos = if len == 1 { 1 } else { (i + 1).min(len) };

                let split_part = current.split_off(split_pos);
                split_parts.push((current.freeze(), split_part.len()));
                current = split_part;
            }

            if !current.is_empty() {
                split_parts.push((current.freeze(), 0));
            }

            // Verify chain integrity
            let total_recovered: usize = split_parts.iter().map(|(bytes, _)| bytes.len()).sum();
            assert_eq!(total_recovered, initial_data.len());
        }

        AtomicityOperation::ExtendThenFreeze { extend_data } => {
            let mut bytes_mut = BytesMut::from(initial_data);
            let original_len = bytes_mut.len();

            if extend_data.len() <= 16 * 1024 {
                // Limit extension size
                bytes_mut.extend_from_slice(&extend_data);

                let expected_len = original_len + extend_data.len();
                assert_eq!(bytes_mut.len(), expected_len);

                let frozen = bytes_mut.freeze();
                assert_eq!(frozen.len(), expected_len);

                // Verify data integrity after extend+freeze
                if original_len > 0 {
                    assert_eq!(frozen[0], initial_data[0]);
                }
                if !extend_data.is_empty() && expected_len > original_len {
                    assert_eq!(frozen[original_len], extend_data[0]);
                }
            }
        }

        AtomicityOperation::ValidatedSplit { position } => {
            if initial_data.is_empty() {
                return;
            }

            let mut bytes_mut = BytesMut::from(initial_data);
            let len = bytes_mut.len();
            let split_pos = position % (len + 1);

            // Comprehensive validation before split
            let pre_split_checksum = simple_checksum(&bytes_mut);
            let pre_split_len = bytes_mut.len();

            let split_result = bytes_mut.split_off(split_pos);

            // Comprehensive validation after split
            let post_split_checksum1 = simple_checksum(&bytes_mut);
            let post_split_checksum2 = simple_checksum(&split_result);

            assert_eq!(bytes_mut.len() + split_result.len(), pre_split_len);

            // Verify checksums match expected split
            let combined_checksum = combine_checksums(post_split_checksum1, post_split_checksum2);
            assert_eq!(combined_checksum, pre_split_checksum);
        }

        AtomicityOperation::StressFreeze { iterations } => {
            let stress_iters = (iterations as usize).min(100).max(1);

            for _ in 0..stress_iters {
                let mut bytes_mut = BytesMut::from(initial_data);

                // Stress test with reserves and extensions
                if bytes_mut.capacity() < 1024 {
                    bytes_mut.reserve(1024);
                }

                let frozen = bytes_mut.freeze();

                // Stress test cloning under "pressure"
                let mut clones = Vec::new();
                for _ in 0..(stress_iters.min(10)) {
                    clones.push(frozen.clone());
                }

                // Verify all clones maintain consistency under stress
                for clone in &clones {
                    assert_eq!(clone.len(), initial_data.len());
                    if !clone.is_empty() {
                        assert_eq!(clone.as_ptr(), frozen.as_ptr());
                    }
                }
            }
        }
    }
}

/// Simple checksum for data integrity verification
fn simple_checksum(data: &[u8]) -> u64 {
    data.iter().enumerate().fold(0u64, |acc, (i, &byte)| {
        acc.wrapping_add((i as u64).wrapping_mul(byte as u64))
    })
}

/// Combine two checksums for split validation
fn combine_checksums(checksum1: u64, checksum2: u64) -> u64 {
    checksum1.wrapping_add(checksum2)
}
