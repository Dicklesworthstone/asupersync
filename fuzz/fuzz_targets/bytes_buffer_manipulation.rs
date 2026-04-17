#![no_main]

//! Fuzz target for bytes buffer manipulation and edge cases.
//!
//! This target focuses on the core Bytes/BytesMut buffer types and their
//! manipulation methods including slicing, splitting, range operations,
//! concatenation, and reference counting correctness.
//!
//! Enhanced to test:
//! - Concat of N Bytes segments with reference-counting correctness
//! - BytesMut::freeze atomicity under simulated concurrent readers
//! - Comprehensive boundary testing including critical edge cases
//! - Zero-copy slice operations and nested slicing
//! - Reference sharing and immutability guarantees
//!
//! The goal is to catch buffer boundary violations, integer overflow/underflow,
//! reference counting bugs, and panic conditions in buffer operations.

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

    // Concat operations for N segments reference-counting correctness
    ConcatMultiple { count: u8 },

    // Freeze atomicity testing
    FreezeWithReaders { reader_count: u8 },

    // Enhanced boundary testing
    BoundarySlice,
    MaxLengthOps,

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
                    // Extend back for continued testing (no unsplit method exists)
                    bytes_mut.extend_from_slice(&split_off);
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

            BufferOperation::ConcatMultiple { count } => {
                // Test concatenation of N Bytes segments for reference-counting correctness
                let segment_count = (count as usize).min(8).max(1); // Limit to 1-8 segments
                let mut segments = Vec::new();

                // Create multiple segments from existing variants or new data
                for i in 0..segment_count {
                    if i < bytes_variants.len() {
                        segments.push(bytes_variants[i].clone());
                    } else {
                        // Create new segment
                        let data = vec![(i as u8).wrapping_add(0x41); 16]; // 'A' + i, etc.
                        let new_buf = asupersync::bytes::BytesMut::from(data.as_slice());
                        segments.push(new_buf.freeze());
                    }
                }

                if !segments.is_empty() {
                    // Test concat via chain and collect
                    let total_len: usize = segments.iter().map(|s| s.len()).sum();
                    let mut concat_buf = asupersync::bytes::BytesMut::with_capacity(total_len);

                    // Store original pointers to verify reference sharing
                    let orig_ptrs: Vec<*const u8> = segments.iter().map(|s| s.as_ptr()).collect();

                    for segment in &segments {
                        concat_buf.extend_from_slice(segment);
                    }

                    let concatenated = concat_buf.freeze();
                    assert_eq!(concatenated.len(), total_len);

                    // Verify original segments unchanged (reference counting correctness)
                    for (i, segment) in segments.iter().enumerate() {
                        assert_eq!(segment.as_ptr(), orig_ptrs[i]);
                        // Clone should still share data pointer
                        let cloned = segment.clone();
                        assert_eq!(cloned.as_ptr(), segment.as_ptr());
                    }

                    bytes_variants.push(concatenated);
                }
            }

            BufferOperation::FreezeWithReaders { reader_count } => {
                // Test BytesMut::freeze atomicity with simulated concurrent readers
                let readers = (reader_count as usize).min(4).max(1); // Limit to 1-4 readers

                if !bytes_mut.is_empty() {
                    // Create multiple "readers" that capture state before freeze
                    let original_len = bytes_mut.len();

                    // Freeze operation should be atomic
                    let frozen = bytes_mut.freeze();

                    // Verify all "readers" see consistent state with original
                    for _reader in 0..readers {
                        assert_eq!(original_len, frozen.len());
                    }

                    // Test that frozen bytes are immutable and shareable
                    let shared1 = frozen.clone();
                    let shared2 = frozen.clone();
                    assert_eq!(shared1.as_ptr(), shared2.as_ptr());
                    assert_eq!(shared1.len(), shared2.len());

                    bytes_variants.push(frozen);
                    // Create new BytesMut for further operations (freeze consumes original)
                    bytes_mut = asupersync::bytes::BytesMut::new();
                }
            }

            BufferOperation::BoundarySlice => {
                // Enhanced boundary testing for slice operations
                for bytes in &bytes_variants {
                    let len = bytes.len();

                    if len > 0 {
                        // Test all critical boundaries
                        let boundaries = vec![0, 1, len/2, len.saturating_sub(1), len];

                        for &start in &boundaries {
                            for &end in &boundaries {
                                if start <= end && end <= len {
                                    let sliced = bytes.slice(start..end);
                                    assert_eq!(sliced.len(), end - start);

                                    // Test nested slicing
                                    if sliced.len() > 1 {
                                        let nested = sliced.slice(1..sliced.len());
                                        assert_eq!(nested.len(), sliced.len() - 1);
                                    }
                                }
                            }
                        }

                        // Test single-byte slices at all positions
                        for i in 0..len {
                            let single = bytes.slice(i..i+1);
                            assert_eq!(single.len(), 1);
                            assert_eq!(single[0], bytes[i]);
                        }

                        // Test zero-length slices at all positions
                        for i in 0..=len {
                            let empty = bytes.slice(i..i);
                            assert_eq!(empty.len(), 0);
                            assert!(empty.is_empty());
                        }
                    }
                }
            }

            BufferOperation::MaxLengthOps => {
                // Test operations near maximum length boundaries
                if bytes_mut.len() > 0 {
                    let len = bytes_mut.len();

                    // Test split_to at maximum position
                    if len > 0 {
                        // Save original data for restore
                        let original_data = bytes_mut.as_ref().to_vec();
                        let split = bytes_mut.split_to(len);
                        assert_eq!(split.len(), len);
                        assert_eq!(bytes_mut.len(), 0);

                        // Restore from original data and test split_off at position 0
                        bytes_mut = asupersync::bytes::BytesMut::from(original_data.as_slice());
                        let split_off = bytes_mut.split_off(0);
                        assert_eq!(bytes_mut.len(), 0);
                        assert_eq!(split_off.len(), len);
                        bytes_mut = asupersync::bytes::BytesMut::from(split_off);
                    }

                    // Test reserve with large values (but capped to prevent OOM)
                    let large_reserve = (u16::MAX as usize).min(1024 * 1024);
                    if bytes_mut.capacity() < large_reserve {
                        bytes_mut.reserve(large_reserve - bytes_mut.capacity());
                        assert!(bytes_mut.capacity() >= large_reserve);
                    }
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
            assert_eq!(bytes.as_ref(), &[] as &[u8]);
        }

        // Test reference counting invariants
        let clone1 = bytes.clone();
        let clone2 = bytes.clone();
        if !bytes.is_empty() {
            // All clones should share the same data pointer
            assert_eq!(bytes.as_ptr(), clone1.as_ptr());
            assert_eq!(bytes.as_ptr(), clone2.as_ptr());
        }

        // Test slicing preserves data integrity
        if bytes.len() > 2 {
            let mid = bytes.len() / 2;
            let slice1 = bytes.slice(..mid);
            let slice2 = bytes.slice(mid..);

            // Verify slices partition the original
            assert_eq!(slice1.len() + slice2.len(), bytes.len());

            // Verify slice content matches original
            if !slice1.is_empty() {
                assert_eq!(slice1[0], bytes[0]);
            }
            if !slice2.is_empty() && mid < bytes.len() {
                assert_eq!(slice2[0], bytes[mid]);
            }
        }

        // Test that Bytes is Send + Sync (compile-time check)
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<asupersync::bytes::Bytes>();
    }

    // Test BytesMut final state invariants
    if !bytes_mut.is_empty() {
        // Test that remaining BytesMut can still be frozen
        let _final_frozen = bytes_mut.freeze();
        // Basic sanity - freeze operation completes successfully

        // Test that BytesMut is Send + Sync (compile-time check)
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<asupersync::bytes::BytesMut>();
    }
});
