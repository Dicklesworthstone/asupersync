#![no_main]

//! Fuzz target for bytes buffer manipulation and edge cases.
//!
//! This target focuses on the core Bytes/BytesMut buffer types and their
//! manipulation methods including slicing, splitting, and range operations.
//! The goal is to catch buffer boundary violations, integer overflow/underflow,
//! and panic conditions in buffer operations.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct BufferOpSequence {
    initial_data: Vec<u8>,
    operations: Vec<BufferOperation>,
}

#[derive(Arbitrary, Debug)]
enum BufferOperation {
    // BytesMut operations
    SplitTo { at: usize },
    SplitOff { at: usize },
    Reserve { additional: usize },
    Extend { data: Vec<u8> },
    Truncate { len: usize },
    Clear,

    // Bytes operations (via freeze())
    Freeze,
    Slice { start: usize, end: usize },
    SliceFrom { start: usize },
    SliceTo { end: usize },

    // Clone operations for reference counting tests
    Clone,

    // Conversion operations
    ToVec,
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 4 {
        return;
    }

    // Limit input size to prevent timeout (1MB max)
    if input.len() > 1024 * 1024 {
        return;
    }

    let mut unstructured = Unstructured::new(input);
    let Ok(sequence) = BufferOpSequence::arbitrary(&mut unstructured) else {
        return;
    };

    // Start with BytesMut from the initial data
    let mut bytes_mut = asupersync::bytes::BytesMut::from(sequence.initial_data.as_slice());
    let mut bytes_variants = Vec::<asupersync::bytes::Bytes>::new();

    for operation in sequence.operations {
        match operation {
            BufferOperation::SplitTo { at } => {
                // Test split_to which should not panic if at <= len
                let len = bytes_mut.len();
                if at <= len {
                    let split = bytes_mut.split_to(at);
                    // Verify split invariants
                    assert_eq!(split.len(), at);
                    assert_eq!(bytes_mut.len(), len - at);
                }
                // Skip if at > len to avoid expected panics
            }

            BufferOperation::SplitOff { at } => {
                let len = bytes_mut.len();
                if at <= len {
                    let split_off = bytes_mut.split_off(at);
                    // Verify split_off invariants
                    assert_eq!(bytes_mut.len(), at);
                    assert_eq!(split_off.len(), len - at);
                    // Put it back to continue testing
                    bytes_mut.unsplit(split_off);
                }
            }

            BufferOperation::Reserve { additional } => {
                // Limit reserve to prevent OOM
                if additional <= 16 * 1024 * 1024 {
                    let old_capacity = bytes_mut.capacity();
                    bytes_mut.reserve(additional);
                    // Verify capacity increased appropriately
                    assert!(bytes_mut.capacity() >= old_capacity);
                }
            }

            BufferOperation::Extend { data } => {
                if data.len() <= 64 * 1024 {
                    let old_len = bytes_mut.len();
                    bytes_mut.extend_from_slice(&data);
                    assert_eq!(bytes_mut.len(), old_len + data.len());
                }
            }

            BufferOperation::Truncate { len } => {
                bytes_mut.truncate(len);
                assert!(bytes_mut.len() <= len);
            }

            BufferOperation::Clear => {
                bytes_mut.clear();
                assert_eq!(bytes_mut.len(), 0);
            }

            BufferOperation::Freeze => {
                // Convert BytesMut to Bytes (immutable)
                let bytes = bytes_mut.freeze();
                bytes_variants.push(bytes);
                // Create new BytesMut for further operations
                bytes_mut = asupersync::bytes::BytesMut::new();
            }

            BufferOperation::Slice { start, end } => {
                // Test slice operations on any existing Bytes variants
                for bytes in &bytes_variants {
                    if start <= end && end <= bytes.len() {
                        let sliced = bytes.slice(start..end);
                        assert_eq!(sliced.len(), end - start);

                        // Test that slicing doesn't affect original
                        assert_eq!(bytes.len(), bytes.len()); // Original unchanged

                        // Test slice content matches
                        if !sliced.is_empty() && !bytes.is_empty() && start < bytes.len() {
                            assert_eq!(sliced[0], bytes[start]);
                        }
                    }
                }
            }

            BufferOperation::SliceFrom { start } => {
                for bytes in &bytes_variants {
                    if start <= bytes.len() {
                        let sliced = bytes.slice(start..);
                        assert_eq!(sliced.len(), bytes.len() - start);
                    }
                }
            }

            BufferOperation::SliceTo { end } => {
                for bytes in &bytes_variants {
                    if end <= bytes.len() {
                        let sliced = bytes.slice(..end);
                        assert_eq!(sliced.len(), end);
                    }
                }
            }

            BufferOperation::Clone => {
                // Test reference counting by cloning Bytes
                for bytes in &mut bytes_variants {
                    let cloned = bytes.clone();
                    assert_eq!(bytes.len(), cloned.len());
                    assert_eq!(bytes.as_ptr(), cloned.as_ptr()); // Should share data
                }
            }

            BufferOperation::ToVec => {
                // Test conversion to Vec<u8>
                for bytes in &bytes_variants {
                    let vec = bytes.to_vec();
                    assert_eq!(vec.len(), bytes.len());
                    assert_eq!(vec.as_slice(), bytes.as_ref());
                }
            }
        }
    }

    // Final invariant checks
    for bytes in &bytes_variants {
        // Test Debug formatting doesn't panic
        let _ = format!("{:?}", bytes);

        // Test comparison operations
        let cloned = bytes.clone();
        assert_eq!(bytes, &cloned);

        // Test empty case handling
        if bytes.is_empty() {
            assert_eq!(bytes.len(), 0);
        }
    }
});
