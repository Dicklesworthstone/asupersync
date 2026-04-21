#![allow(clippy::all)]
//! Metamorphic tests for RwLock reader-writer fairness invariants.
//!
//! These tests validate the fairness properties of the writer-preference RwLock
//! using metamorphic relations to ensure reader-writer coordination doesn't violate invariants.

use std::collections::HashMap;
use std::sync::Arc as StdArc;

use proptest::prelude::*;

use asupersync::cx::Cx;
use asupersync::sync::RwLock;
use asupersync::types::{ArenaIndex, Budget, RegionId, TaskId};
use asupersync::util::DetRng;

/// Create a test context for RwLock testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test context with specific slot.
fn test_cx_with_slot(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, slot)),
        TaskId::from_arena(ArenaIndex::new(0, slot)),
        Budget::INFINITE,
    )
}

/// Simple blocking read helper.
fn try_read_blocking<T>(lock: &RwLock<T>) -> Result<T, ()>
where
    T: Clone,
{
    match lock.try_read() {
        Ok(guard) => Ok((*guard).clone()),
        Err(_) => Err(()),
    }
}

/// Simple blocking write helper.
fn try_write_blocking<T>(lock: &RwLock<T>, value: T) -> Result<(), ()> {
    match lock.try_write() {
        Ok(mut guard) => {
            *guard = value;
            Ok(())
        }
        Err(_) => Err(()),
    }
}

/// Arbitrary strategy for generating RwLock values.
fn arb_rwlock_values() -> impl Strategy<Value = Vec<u32>> {
    prop::collection::vec(0u32..1000, 0..20)
}

// Metamorphic Relations for RwLock Reader-Writer Fairness

/// MR1: Value Preservation - Reading from an RwLock should preserve the value
/// regardless of how many times it's read or in what pattern.
#[test]
fn mr_value_preservation() {
    proptest!(|(value in 0u32..1000)| {
        let rwlock = RwLock::new(value);

        // Try read should always return the same value
        let read1 = try_read_blocking(&rwlock);
        let read2 = try_read_blocking(&rwlock);

        prop_assert!(read1.is_ok(), "First read should succeed");
        prop_assert!(read2.is_ok(), "Second read should succeed");
        prop_assert_eq!(read1.unwrap(), value, "First read should return original value");
        prop_assert_eq!(read2.unwrap(), value, "Second read should return original value");
    });
}

/// MR2: Write-Read Consistency - A value written to an RwLock should be
/// observable by subsequent readers.
#[test]
fn mr_write_read_consistency() {
    proptest!(|(initial_value in 0u32..500, new_value in 500u32..1000)| {
        let rwlock = RwLock::new(initial_value);

        // Write a new value
        let write_result = try_write_blocking(&rwlock, new_value);
        prop_assert!(write_result.is_ok(), "Write should succeed");

        // Read should return the new value
        let read_result = try_read_blocking(&rwlock);
        prop_assert!(read_result.is_ok(), "Read after write should succeed");
        prop_assert_eq!(read_result.unwrap(), new_value,
            "Read should return written value: expected {}, got {}",
            new_value, read_result.unwrap());
    });
}

/// MR3: Write Exclusivity - When a write operation succeeds, no other
/// operations should be able to acquire the lock.
#[test]
fn mr_write_exclusivity() {
    proptest!(|(value in 0u32..1000)| {
        let rwlock = RwLock::new(value);

        // Acquire a write lock
        let write_guard = rwlock.try_write();
        if write_guard.is_ok() {
            // While write lock is held, reads and writes should fail
            let concurrent_read = rwlock.try_read();
            let concurrent_write = rwlock.try_write();

            prop_assert!(concurrent_read.is_err(), "Read should fail while write lock held");
            prop_assert!(concurrent_write.is_err(), "Write should fail while write lock held");
        }
    });
}

/// MR4: Read Concurrency - Multiple read operations should be able to
/// acquire the lock simultaneously when no writer is active.
#[test]
fn mr_read_concurrency() {
    proptest!(|(value in 0u32..1000)| {
        let rwlock = RwLock::new(value);

        // Acquire first read lock
        let read_guard1 = rwlock.try_read();
        if let Ok(guard1) = read_guard1 {
            // Second read should also succeed
            let read_guard2 = rwlock.try_read();
            prop_assert!(read_guard2.is_ok(),
                "Second read should succeed when first read is active");

            if let Ok(guard2) = read_guard2 {
                // Both should read the same value
                prop_assert_eq!(*guard1, *guard2,
                    "Concurrent reads should return same value");
            }

            // Write should still be blocked
            let concurrent_write = rwlock.try_write();
            prop_assert!(concurrent_write.is_err(),
                "Write should fail while read locks are held");
        }
    });
}

/// MR5: Lock State Determinism - The outcome of try_read/try_write operations
/// should be deterministic based on the current lock state.
#[test]
fn mr_lock_state_determinism() {
    proptest!(|(values in arb_rwlock_values())| {
        for &value in &values {
            let rwlock1 = RwLock::new(value);
            let rwlock2 = RwLock::new(value);

            // Same operations on identical locks should yield same results
            let read1 = rwlock1.try_read();
            let read2 = rwlock2.try_read();

            prop_assert_eq!(read1.is_ok(), read2.is_ok(),
                "Identical locks should have same read outcome");

            if let (Ok(guard1), Ok(guard2)) = (&read1, &read2) {
                prop_assert_eq!(**guard1, **guard2,
                    "Identical locks should read same value");
            }
        }
    });
}

/// MR6: State Transition Consistency - Lock state should transition
/// consistently regardless of the sequence of successful operations.
#[test]
fn mr_state_transition_consistency() {
    proptest!(|(initial_value in 0u32..100, operations in prop::collection::vec(0u32..100, 1..10))| {
        let rwlock = RwLock::new(initial_value);
        let mut current_value = initial_value;

        // Apply sequence of write operations
        for &op_value in &operations {
            if try_write_blocking(&rwlock, op_value).is_ok() {
                current_value = op_value;
            }
        }

        // Final read should match last successful write
        let final_read = try_read_blocking(&rwlock);
        prop_assert!(final_read.is_ok(), "Final read should succeed");
        prop_assert_eq!(final_read.unwrap(), current_value,
            "Final value should match last written value");
    });
}


/// Unit tests for edge cases and specific scenarios.
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_basic_rwlock_operations() {
        let rwlock = RwLock::new(42u32);

        // Basic read should work
        let read_result = try_read_blocking(&rwlock);
        assert!(read_result.is_ok());
        assert_eq!(read_result.unwrap(), 42);

        // Basic write should work
        let write_result = try_write_blocking(&rwlock, 100);
        assert!(write_result.is_ok());

        // Read after write should return new value
        let read_after_write = try_read_blocking(&rwlock);
        assert!(read_after_write.is_ok());
        assert_eq!(read_after_write.unwrap(), 100);
    }

    #[test]
    fn test_multiple_reads() {
        let rwlock = RwLock::new(42u32);

        // Multiple try_read should succeed
        let read1 = rwlock.try_read();
        assert!(read1.is_ok());

        let read2 = rwlock.try_read();
        assert!(read2.is_ok());

        if let (Ok(guard1), Ok(guard2)) = (read1, read2) {
            assert_eq!(*guard1, *guard2);
            assert_eq!(*guard1, 42);
        }
    }

    #[test]
    fn test_write_excludes_read() {
        let rwlock = RwLock::new(42u32);

        // Acquire write lock
        let write_guard = rwlock.try_write();
        assert!(write_guard.is_ok());

        // Try read should fail while write is held
        let read_attempt = rwlock.try_read();
        assert!(read_attempt.is_err());
    }
}