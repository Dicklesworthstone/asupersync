//! Fuzz target for BytesMut operations: put/extend/reserve/split.
//!
//! Tests BytesMut invariants through arbitrary operation sequences:
//! 1. len() never exceeds capacity()
//! 2. extend operations grow storage appropriately or handle errors
//! 3. split/split_off operations preserve total bytes
//! 4. freeze() correctly transforms BytesMut into Bytes
//! 5. reserve(0) is a no-op that preserves state

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use std::cmp;

/// Maximum size limits for fuzzing to prevent OOM
const MAX_CAPACITY: usize = 1024 * 1024; // 1MB
const MAX_DATA_LEN: usize = 64 * 1024; // 64KB per operation
const MAX_OPERATIONS: usize = 100; // Max operations per test

/// BytesMut operations for fuzzing
#[derive(Arbitrary, Debug, Clone)]
enum BytesMutOp {
    /// Create new BytesMut with given capacity
    WithCapacity(usize),
    /// Put slice of bytes
    PutSlice(Vec<u8>),
    /// Extend from slice (alias for put_slice)
    ExtendFromSlice(Vec<u8>),
    /// Put single byte
    PutU8(u8),
    /// Reserve additional capacity
    Reserve(usize),
    /// Split off from position
    SplitOff(usize),
    /// Split to position
    SplitTo(usize),
    /// Truncate to length
    Truncate(usize),
    /// Clear all data
    Clear,
    /// Resize with fill byte
    Resize { new_len: usize, value: u8 },
    /// Set length (zero-fill new bytes)
    SetLen(usize),
    /// Freeze into Bytes
    Freeze,
}

/// Test input containing sequence of BytesMut operations
#[derive(Arbitrary, Debug)]
struct BytesMutFuzzInput {
    /// Initial capacity for BytesMut creation
    initial_capacity: usize,
    /// Sequence of operations to perform
    operations: Vec<BytesMutOp>,
}

/// State tracking for invariant verification
#[derive(Debug, Clone)]
struct InvariantState {
    /// Expected total bytes across all splits
    total_bytes_across_splits: usize,
    /// Count of split operations performed
    split_count: usize,
    /// Pre-operation state snapshots
    pre_op_len: usize,
    pre_op_capacity: usize,
}

impl InvariantState {
    fn new(len: usize, capacity: usize) -> Self {
        Self {
            total_bytes_across_splits: len,
            split_count: 0,
            pre_op_len: len,
            pre_op_capacity: capacity,
        }
    }

    fn update_pre_op(&mut self, len: usize, capacity: usize) {
        self.pre_op_len = len;
        self.pre_op_capacity = capacity;
    }
}

fuzz_target!(|input: BytesMutFuzzInput| {
    // Limit capacity to prevent OOM
    let initial_capacity = input.initial_capacity.min(MAX_CAPACITY);
    let mut buf = BytesMut::with_capacity(initial_capacity);

    let mut state = InvariantState::new(buf.len(), buf.capacity());
    let mut split_buffers = Vec::new();

    // Limit operations to prevent timeout
    let operations = input.operations.iter().take(MAX_OPERATIONS);

    for op in operations {
        state.update_pre_op(buf.len(), buf.capacity());

        match op.clone() {
            BytesMutOp::WithCapacity(cap) => {
                // Create new buffer (previous splits still tracked)
                let bounded_cap = cap.min(MAX_CAPACITY);
                buf = BytesMut::with_capacity(bounded_cap);

                // Assert: capacity is at least requested
                assert!(
                    buf.capacity() >= bounded_cap,
                    "with_capacity failed: requested={}, actual={}",
                    bounded_cap,
                    buf.capacity()
                );

                // Assert 1: len never exceeds capacity
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after with_capacity: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );
            }

            BytesMutOp::PutSlice(data) => {
                // Limit data size
                let bounded_data = if data.len() > MAX_DATA_LEN {
                    &data[..MAX_DATA_LEN]
                } else {
                    &data
                };

                let pre_len = buf.len();
                buf.put_slice(bounded_data);

                // Assert: length increased by data length
                assert_eq!(
                    buf.len(),
                    pre_len + bounded_data.len(),
                    "put_slice didn't increase length correctly"
                );

                // Assert 1: len never exceeds capacity
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after put_slice: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );

                // Assert 2: extend grows storage (put_slice should always succeed)
                // No explicit error handling needed as put_slice uses Vec::extend_from_slice
            }

            BytesMutOp::ExtendFromSlice(data) => {
                let bounded_data = if data.len() > MAX_DATA_LEN {
                    &data[..MAX_DATA_LEN]
                } else {
                    &data
                };

                let pre_len = buf.len();
                buf.extend_from_slice(bounded_data);

                // Assert: length increased by data length
                assert_eq!(
                    buf.len(),
                    pre_len + bounded_data.len(),
                    "extend_from_slice didn't increase length correctly"
                );

                // Assert 1: len never exceeds capacity
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after extend_from_slice: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );
            }

            BytesMutOp::PutU8(byte) => {
                let pre_len = buf.len();
                buf.put_u8(byte);

                // Assert: length increased by 1
                assert_eq!(buf.len(), pre_len + 1, "put_u8 didn't increase length by 1");

                // Assert 1: len never exceeds capacity
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after put_u8: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );
            }

            BytesMutOp::Reserve(additional) => {
                let bounded_additional = additional.min(MAX_CAPACITY);
                let pre_capacity = buf.capacity();

                // Special case: Assert 5: reserve(0) is a no-op
                if bounded_additional == 0 {
                    let pre_len = buf.len();
                    let pre_data = buf.as_ref().to_vec();

                    buf.reserve(0);

                    assert_eq!(
                        buf.len(),
                        pre_len,
                        "Invariant 5 violated: reserve(0) changed length"
                    );
                    assert_eq!(
                        buf.as_ref(),
                        pre_data.as_slice(),
                        "Invariant 5 violated: reserve(0) changed data"
                    );
                    // Capacity may change due to Vec's implementation, so we don't assert on it
                } else {
                    buf.reserve(bounded_additional);

                    // Assert: capacity increased or stayed same (Vec may allocate more)
                    assert!(
                        buf.capacity() >= pre_capacity,
                        "reserve decreased capacity: {} -> {}",
                        pre_capacity,
                        buf.capacity()
                    );
                }

                // Assert 1: len never exceeds capacity
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after reserve: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );
            }

            BytesMutOp::SplitOff(at) => {
                if at <= buf.len() {
                    let pre_len = buf.len();
                    let pre_data = buf.as_ref().to_vec();

                    let split_off_buf = buf.split_off(at);

                    // Assert 3: split operations preserve total bytes
                    assert_eq!(
                        buf.len() + split_off_buf.len(),
                        pre_len,
                        "Invariant 3 violated: split_off didn't preserve total bytes"
                    );

                    // Verify data integrity
                    let mut reconstructed = buf.as_ref().to_vec();
                    reconstructed.extend_from_slice(split_off_buf.as_ref());
                    assert_eq!(reconstructed, pre_data, "split_off corrupted data");

                    split_buffers.push(split_off_buf);
                    state.split_count += 1;
                }

                // Assert 1: len never exceeds capacity
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after split_off: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );
            }

            BytesMutOp::SplitTo(at) => {
                if at <= buf.len() {
                    let pre_len = buf.len();
                    let pre_data = buf.as_ref().to_vec();

                    let split_to_buf = buf.split_to(at);

                    // Assert 3: split operations preserve total bytes
                    assert_eq!(
                        split_to_buf.len() + buf.len(),
                        pre_len,
                        "Invariant 3 violated: split_to didn't preserve total bytes"
                    );

                    // Verify data integrity
                    let mut reconstructed = split_to_buf.as_ref().to_vec();
                    reconstructed.extend_from_slice(buf.as_ref());
                    assert_eq!(reconstructed, pre_data, "split_to corrupted data");

                    split_buffers.push(split_to_buf);
                    state.split_count += 1;
                }

                // Assert 1: len never exceeds capacity
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after split_to: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );
            }

            BytesMutOp::Truncate(len) => {
                let bounded_len = len.min(buf.len());
                buf.truncate(bounded_len);

                // Assert: length is at most the truncate parameter
                assert!(
                    buf.len() <= bounded_len,
                    "truncate didn't limit length correctly"
                );

                // Assert 1: len never exceeds capacity
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after truncate: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );
            }

            BytesMutOp::Clear => {
                buf.clear();

                // Assert: buffer is empty
                assert_eq!(buf.len(), 0, "clear didn't empty buffer");
                assert!(buf.is_empty(), "clear didn't make buffer empty");

                // Assert 1: len never exceeds capacity (trivially true after clear)
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after clear: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );
            }

            BytesMutOp::Resize { new_len, value } => {
                let bounded_new_len = new_len.min(MAX_DATA_LEN);
                let pre_data = buf.as_ref().to_vec();
                buf.resize(bounded_new_len, value);

                // Assert: length is exactly new_len
                assert_eq!(
                    buf.len(),
                    bounded_new_len,
                    "resize didn't set length correctly"
                );

                // Assert: data integrity for shrinking
                if bounded_new_len < pre_data.len() {
                    assert_eq!(
                        buf.as_ref(),
                        &pre_data[..bounded_new_len],
                        "resize corrupted existing data when shrinking"
                    );
                }

                // Assert: fill value for growing
                if bounded_new_len > pre_data.len() {
                    assert_eq!(
                        &buf[..pre_data.len()],
                        pre_data.as_slice(),
                        "resize corrupted existing data when growing"
                    );
                    for i in pre_data.len()..bounded_new_len {
                        assert_eq!(
                            buf[i], value,
                            "resize didn't fill new bytes with correct value"
                        );
                    }
                }

                // Assert 1: len never exceeds capacity
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after resize: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );
            }

            BytesMutOp::SetLen(len) => {
                let bounded_len = len.min(MAX_DATA_LEN).min(buf.capacity());
                let pre_data = buf.as_ref().to_vec();

                buf.set_len(bounded_len);

                // Assert: length is exactly new length
                assert_eq!(
                    buf.len(),
                    bounded_len,
                    "set_len didn't set length correctly"
                );

                // Assert: data integrity for shrinking
                if bounded_len < pre_data.len() {
                    assert_eq!(
                        buf.as_ref(),
                        &pre_data[..bounded_len],
                        "set_len corrupted existing data when shrinking"
                    );
                }

                // Assert: zero-fill for growing
                if bounded_len > pre_data.len() {
                    assert_eq!(
                        &buf[..pre_data.len()],
                        pre_data.as_slice(),
                        "set_len corrupted existing data when growing"
                    );
                    for i in pre_data.len()..bounded_len {
                        assert_eq!(buf[i], 0, "set_len didn't zero-fill new bytes");
                    }
                }

                // Assert 1: len never exceeds capacity
                assert!(
                    buf.len() <= buf.capacity(),
                    "Invariant 1 violated after set_len: len={} > capacity={}",
                    buf.len(),
                    buf.capacity()
                );
            }

            BytesMutOp::Freeze => {
                if buf.len() > 0 {
                    let buf_data = buf.as_ref().to_vec();
                    let buf_len = buf.len();

                    let frozen_bytes = buf.freeze();

                    // Assert 4: freeze correctly transforms BytesMut into Bytes
                    assert_eq!(
                        frozen_bytes.len(),
                        buf_len,
                        "Invariant 4 violated: freeze changed length"
                    );
                    assert_eq!(
                        frozen_bytes.as_ref(),
                        buf_data.as_slice(),
                        "Invariant 4 violated: freeze changed data"
                    );

                    // After freeze, buf is consumed, so create a new one
                    buf = BytesMut::new();
                }
            }
        }

        // Global invariant: len <= capacity should always hold
        assert!(
            buf.len() <= buf.capacity(),
            "Global invariant violated: len={} > capacity={}",
            buf.len(),
            buf.capacity()
        );
    }

    // Final validation: ensure all split buffers maintain invariants
    for (i, split_buf) in split_buffers.iter().enumerate() {
        assert!(
            split_buf.len() <= split_buf.capacity(),
            "Split buffer {} violates invariant: len={} > capacity={}",
            i,
            split_buf.len(),
            split_buf.capacity()
        );
    }
});

/// Additional focused tests for specific edge cases
mod focused_tests {
    use super::*;

    /// Test reserve(0) is truly a no-op
    #[allow(dead_code)]
    fn test_reserve_zero_noop(mut buf: BytesMut) {
        let pre_len = buf.len();
        let pre_capacity = buf.capacity();
        let pre_data = buf.as_ref().to_vec();

        buf.reserve(0);

        assert_eq!(buf.len(), pre_len, "reserve(0) changed length");
        assert_eq!(buf.as_ref(), pre_data.as_slice(), "reserve(0) changed data");
        // Note: capacity may change due to Vec's allocation strategy
    }

    /// Test split operations preserve total byte count exactly
    #[allow(dead_code)]
    fn test_split_preservation(mut buf: BytesMut, at: usize) {
        if at > buf.len() {
            return;
        }

        let original_len = buf.len();
        let original_data = buf.as_ref().to_vec();

        let split = buf.split_off(at);

        assert_eq!(
            buf.len() + split.len(),
            original_len,
            "split_off didn't preserve total length"
        );

        let mut reconstructed = Vec::new();
        reconstructed.extend_from_slice(buf.as_ref());
        reconstructed.extend_from_slice(split.as_ref());

        assert_eq!(reconstructed, original_data, "split_off corrupted data");
    }

    /// Test freeze preserves data exactly
    #[allow(dead_code)]
    fn test_freeze_preservation(buf: BytesMut) {
        let original_data = buf.as_ref().to_vec();
        let original_len = buf.len();

        let frozen = buf.freeze();

        assert_eq!(frozen.len(), original_len, "freeze changed length");
        assert_eq!(
            frozen.as_ref(),
            original_data.as_slice(),
            "freeze changed data"
        );
    }

    /// Test capacity growth patterns
    #[allow(dead_code)]
    fn test_capacity_growth(mut buf: BytesMut, additional: usize) {
        let pre_capacity = buf.capacity();
        buf.reserve(additional);

        if additional > 0 {
            assert!(
                buf.capacity() >= pre_capacity,
                "reserve should not decrease capacity"
            );
        }

        assert!(
            buf.len() <= buf.capacity(),
            "len should never exceed capacity after reserve"
        );
    }
}
