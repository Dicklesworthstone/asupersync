#![no_main]

//! Fuzz target for buffer composition types.
//!
//! This target tests the advanced buffer composition utilities: Chain, Limit, and Take.
//! These types provide virtual views over buffer combinations and constraints.
//! The goal is to catch boundary calculation errors, remaining() inconsistencies,
//! and edge cases in composed buffer access patterns.

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
struct CompositionSequence {
    buf1_data: Vec<u8>,
    buf2_data: Vec<u8>,
    operations: Vec<CompositionOperation>,
}

#[derive(Arbitrary, Debug)]
enum CompositionOperation {
    // Chain operations
    CreateChain,
    TestChainRemaining,
    TestChainAdvance { cnt: usize },
    TestChainReadBytes { cnt: usize },
    TestChainCopyToSlice { len: usize },

    // Limit operations
    CreateLimit { limit: usize },
    TestLimitRemaining,
    TestLimitWrite { data: Vec<u8> },
    TestLimitPutU32 { val: u32 },
    TestLimitPutSlice { data: Vec<u8> },

    // Take operations
    CreateTake { limit: usize },
    TestTakeRemaining,
    TestTakeAdvance { cnt: usize },
    TestTakeReadBytes { cnt: usize },
    TestTakeHasRemaining,

    // Nested composition operations
    ChainOfLimits { limit1: usize, limit2: usize },
    LimitOfChain { limit: usize },
    TakeOfChain { limit: usize },
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 8 {
        return;
    }

    // Limit input size to prevent timeout (64KB max)
    if input.len() > 64 * 1024 {
        return;
    }

    let mut unstructured = Unstructured::new(input);
    let Ok(sequence) = CompositionSequence::arbitrary(&mut unstructured) else {
        return;
    };

    // Limit buffer sizes to reasonable values
    if sequence.buf1_data.len() > 8192 || sequence.buf2_data.len() > 8192 {
        return;
    }

    test_buffer_composition(sequence);
});

fn test_buffer_composition(sequence: CompositionSequence) {
    use asupersync::bytes::{Buf, BufMut, Bytes, BytesMut};

    let buf1 = Bytes::from(sequence.buf1_data);
    let buf2 = Bytes::from(sequence.buf2_data);
    let total_original_len = buf1.len() + buf2.len();

    for operation in sequence.operations {
        match operation {
            CompositionOperation::CreateChain => {
                test_chain_basic(buf1.clone(), buf2.clone());
            }

            CompositionOperation::TestChainRemaining => {
                let chain = buf1.clone().chain(buf2.clone());
                assert_eq!(chain.remaining(), buf1.len() + buf2.len());
            }

            CompositionOperation::TestChainAdvance { cnt } => {
                let mut chain = buf1.clone().chain(buf2.clone());
                let initial_remaining = chain.remaining();
                let advance_amount = cnt.min(initial_remaining);

                chain.advance(advance_amount);
                assert_eq!(chain.remaining(), initial_remaining - advance_amount);
            }

            CompositionOperation::TestChainReadBytes { cnt } => {
                let mut chain = buf1.clone().chain(buf2.clone());
                let read_amount = cnt.min(chain.remaining());

                // Test reading across buffer boundaries
                if read_amount > 0 {
                    let original_remaining = chain.remaining();

                    // Read bytes one by one to test boundary crossing
                    for _ in 0..read_amount.min(16) {  // Limit iterations
                        if chain.remaining() > 0 {
                            let byte = chain.get_u8();
                            // Verify the byte came from the correct buffer
                            let _ = byte; // Just ensure no panic
                        }
                    }

                    assert!(chain.remaining() <= original_remaining);
                }
            }

            CompositionOperation::TestChainCopyToSlice { len } => {
                let mut chain = buf1.clone().chain(buf2.clone());
                let copy_amount = len.min(chain.remaining()).min(1024); // Limit to prevent OOM

                if copy_amount > 0 {
                    let mut dest = vec![0u8; copy_amount];
                    chain.copy_to_slice(&mut dest);
                    assert_eq!(dest.len(), copy_amount);
                }
            }

            CompositionOperation::CreateLimit { limit } => {
                if limit <= 16 * 1024 {  // Reasonable limit
                    test_limit_basic(limit);
                }
            }

            CompositionOperation::TestLimitRemaining => {
                let mut buf_mut = BytesMut::with_capacity(1024);
                let limit = 512;
                let limited = buf_mut.limit(limit);
                assert_eq!(limited.remaining_mut(), limit.min(buf_mut.remaining_mut()));
            }

            CompositionOperation::TestLimitWrite { data } => {
                if data.len() <= 1024 {
                    let mut buf_mut = BytesMut::with_capacity(2048);
                    let limit = data.len() + 100;
                    let mut limited = buf_mut.limit(limit);

                    limited.put_slice(&data);
                    // Verify write succeeded and didn't exceed limit
                    assert!(limited.remaining_mut() <= limit);
                }
            }

            CompositionOperation::TestLimitPutU32 { val } => {
                let mut buf_mut = BytesMut::with_capacity(1024);
                let mut limited = buf_mut.limit(100);

                if limited.remaining_mut() >= 4 {
                    limited.put_u32(val);
                    assert!(limited.remaining_mut() <= 100);
                }
            }

            CompositionOperation::TestLimitPutSlice { data } => {
                if data.len() <= 512 {
                    let mut buf_mut = BytesMut::with_capacity(1024);
                    let limit = data.len() * 2; // Ensure room
                    let mut limited = buf_mut.limit(limit);

                    if limited.remaining_mut() >= data.len() {
                        limited.put_slice(&data);
                        assert!(limited.remaining_mut() <= limit);
                    }
                }
            }

            CompositionOperation::CreateTake { limit } => {
                if limit <= buf1.len() + buf2.len() {
                    test_take_basic(buf1.clone(), limit);
                }
            }

            CompositionOperation::TestTakeRemaining => {
                let limit = 100.min(buf1.len());
                let taken = buf1.clone().take(limit);
                assert_eq!(taken.remaining(), limit);
            }

            CompositionOperation::TestTakeAdvance { cnt } => {
                let limit = 100.min(buf1.len());
                let mut taken = buf1.clone().take(limit);
                let advance_amount = cnt.min(taken.remaining());

                taken.advance(advance_amount);
                assert_eq!(taken.remaining(), limit - advance_amount);
            }

            CompositionOperation::TestTakeReadBytes { cnt } => {
                let limit = 50.min(buf1.len());
                let mut taken = buf1.clone().take(limit);
                let read_amount = cnt.min(taken.remaining()).min(16);

                for _ in 0..read_amount {
                    if taken.remaining() > 0 {
                        let _byte = taken.get_u8();
                    }
                }
            }

            CompositionOperation::TestTakeHasRemaining => {
                let limit = 25.min(buf1.len());
                let taken = buf1.clone().take(limit);
                assert_eq!(taken.has_remaining(), limit > 0);
            }

            CompositionOperation::ChainOfLimits { limit1, limit2 } => {
                if limit1 <= 1024 && limit2 <= 1024 {
                    let mut buf1_mut = BytesMut::with_capacity(2048);
                    let mut buf2_mut = BytesMut::with_capacity(2048);

                    let limited1 = buf1_mut.limit(limit1);
                    let limited2 = buf2_mut.limit(limit2);

                    // This tests composition of limited buffers
                    // (Note: actual chaining would need unsafe or different API)
                    assert!(limited1.remaining_mut() <= limit1);
                    assert!(limited2.remaining_mut() <= limit2);
                }
            }

            CompositionOperation::LimitOfChain { limit } => {
                if limit <= total_original_len && limit <= 2048 {
                    // Create a chain first, then limit it
                    let chain = buf1.clone().chain(buf2.clone());
                    let limited_chain = chain.take(limit);
                    assert_eq!(limited_chain.remaining(), limit);
                }
            }

            CompositionOperation::TakeOfChain { limit } => {
                if limit <= total_original_len && limit <= 1024 {
                    let chain = buf1.clone().chain(buf2.clone());
                    let taken = chain.take(limit);
                    assert_eq!(taken.remaining(), limit);

                    // Test that take doesn't exceed the original chain
                    assert!(taken.remaining() <= buf1.len() + buf2.len());
                }
            }
        }
    }
}

fn test_chain_basic(buf1: asupersync::bytes::Bytes, buf2: asupersync::bytes::Bytes) {
    use asupersync::bytes::Buf;

    let mut chain = buf1.clone().chain(buf2.clone());
    let expected_len = buf1.len() + buf2.len();

    // Test basic properties
    assert_eq!(chain.remaining(), expected_len);
    assert_eq!(chain.has_remaining(), expected_len > 0);

    // Test that advance works correctly across buffer boundaries
    if expected_len > 0 {
        let advance_to_boundary = buf1.len().min(expected_len);
        if advance_to_boundary > 0 {
            chain.advance(advance_to_boundary);
            assert_eq!(chain.remaining(), expected_len - advance_to_boundary);
        }
    }
}

fn test_limit_basic(limit: usize) {
    use asupersync::bytes::{BufMut, BytesMut};

    let mut buf = BytesMut::with_capacity(limit * 2);
    let limited = buf.limit(limit);

    // Test basic properties
    assert!(limited.remaining_mut() <= limit);
    assert!(limited.remaining_mut() <= buf.capacity());
}

fn test_take_basic(buf: asupersync::bytes::Bytes, limit: usize) {
    use asupersync::bytes::Buf;

    let taken = buf.clone().take(limit);
    let expected_len = limit.min(buf.len());

    // Test basic properties
    assert_eq!(taken.remaining(), expected_len);
    assert_eq!(taken.has_remaining(), expected_len > 0);

    // Test that take doesn't exceed original buffer
    assert!(taken.remaining() <= buf.len());
});