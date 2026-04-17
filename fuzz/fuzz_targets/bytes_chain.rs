#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Comprehensive fuzz target for bytes::buf::Chain operations
///
/// This fuzzes Chain<T, U> buffer chaining to find:
/// - Memory safety violations in buffer advancement
/// - Logic bugs in cross-buffer advancement
/// - Invariant violations in remaining/chunk consistency
/// - Edge cases in empty buffers and oversized advances
/// - Correctness of derived methods (copy_to_slice, get_*, etc.)
#[derive(Arbitrary, Debug)]
struct BytesChainFuzz {
    /// Operations to execute on chain
    chain_ops: Vec<ChainOperation>,
    /// First buffer content
    first_data: Vec<u8>,
    /// Second buffer content
    second_data: Vec<u8>,
    /// Buffer type variants to test
    buffer_variant: BufferVariant,
}

/// Operations for Chain fuzzing
#[derive(Arbitrary, Debug)]
enum ChainOperation {
    /// Advance cursor by specified amount
    Advance { amount: u16 },
    /// Copy bytes to slice
    CopyToSlice { dst_len: u8 },
    /// Get single u8
    GetU8,
    /// Get u16 big-endian
    GetU16,
    /// Check remaining bytes
    CheckRemaining,
    /// Get current chunk
    GetChunk,
    /// Check has_remaining
    HasRemaining,
    /// Try oversized advance (should panic or handle gracefully)
    OversizedAdvance { amount: u16 },
}

/// Buffer type combinations to test
#[derive(Arbitrary, Debug)]
enum BufferVariant {
    /// Both byte slices
    SliceSlice,
    /// First BytesCursor, second slice
    BytesSlice,
    /// First slice, second BytesCursor
    SliceByte,
    /// Both BytesCursor
    BytesBytes,
}

/// Shadow model for verification
#[derive(Debug)]
struct ShadowChain {
    /// Combined data from both buffers
    data: Vec<u8>,
    /// Current position in combined data
    position: usize,
}

impl ShadowChain {
    fn new(first: &[u8], second: &[u8]) -> Self {
        let mut data = Vec::with_capacity(first.len() + second.len());
        data.extend_from_slice(first);
        data.extend_from_slice(second);
        Self { data, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    fn chunk(&self) -> &[u8] {
        &self.data[self.position..]
    }

    fn advance(&mut self, amount: usize) {
        self.position = (self.position + amount).min(self.data.len());
    }

    fn has_remaining(&self) -> bool {
        self.position < self.data.len()
    }

    fn copy_to_slice(&mut self, dst: &mut [u8]) -> bool {
        if dst.len() > self.remaining() {
            return false; // Would underflow
        }
        dst.copy_from_slice(&self.data[self.position..self.position + dst.len()]);
        self.advance(dst.len());
        true
    }

    fn get_u8(&mut self) -> Option<u8> {
        if self.remaining() >= 1 {
            let val = self.data[self.position];
            self.advance(1);
            Some(val)
        } else {
            None
        }
    }

    fn get_u16(&mut self) -> Option<u16> {
        if self.remaining() >= 2 {
            let val = u16::from_be_bytes([
                self.data[self.position],
                self.data[self.position + 1],
            ]);
            self.advance(2);
            Some(val)
        } else {
            None
        }
    }
}

/// Maximum operation limits for safety
const MAX_OPERATIONS: usize = 100;
const MAX_BUFFER_SIZE: usize = 1000;
const MAX_ADVANCE: usize = 2000; // Allow oversized to test bounds

fuzz_target!(|input: BytesChainFuzz| {
    use asupersync::bytes::{Buf, Bytes};
    use std::panic;

    // Bounds checking
    if input.chain_ops.len() > MAX_OPERATIONS {
        return;
    }

    let first_data = if input.first_data.len() > MAX_BUFFER_SIZE {
        &input.first_data[..MAX_BUFFER_SIZE]
    } else {
        &input.first_data
    };

    let second_data = if input.second_data.len() > MAX_BUFFER_SIZE {
        &input.second_data[..MAX_BUFFER_SIZE]
    } else {
        &input.second_data
    };

    // Create shadow model
    let mut shadow = ShadowChain::new(first_data, second_data);

    // Create chain based on variant
    macro_rules! test_chain {
        ($chain:expr) => {{
            let mut chain = $chain;

            // Initial invariant checks
            assert_eq!(chain.remaining(), shadow.remaining(),
                "Initial remaining mismatch");
            assert_eq!(chain.has_remaining(), shadow.has_remaining(),
                "Initial has_remaining mismatch");

            // Execute operations
            for op in input.chain_ops.iter().take(MAX_OPERATIONS) {
                match op {
                    ChainOperation::Advance { amount } => {
                        let amount = (*amount as usize).min(MAX_ADVANCE);
                        let initial_remaining = chain.remaining();

                        if amount <= initial_remaining {
                            // Valid advance - should work
                            chain.advance(amount);
                            shadow.advance(amount);

                            // Verify state consistency
                            assert_eq!(chain.remaining(), shadow.remaining(),
                                "Remaining mismatch after advance {}", amount);
                        } else {
                            // Oversized advance - should panic
                            let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                                let mut temp_chain = first_data.chain(second_data);
                                temp_chain.advance(amount);
                            }));
                            assert!(result.is_err(),
                                "Oversized advance {} with {} remaining should panic",
                                amount, initial_remaining);
                        }
                    },

                    ChainOperation::CopyToSlice { dst_len } => {
                        let dst_len = *dst_len as usize;
                        if dst_len == 0 { continue; }

                        let mut actual_dst = vec![0u8; dst_len];
                        let mut shadow_dst = vec![0u8; dst_len];

                        let can_copy = dst_len <= chain.remaining();
                        let shadow_can_copy = shadow.copy_to_slice(&mut shadow_dst);

                        assert_eq!(can_copy, shadow_can_copy,
                            "Copy feasibility mismatch for {} bytes", dst_len);

                        if can_copy {
                            chain.copy_to_slice(&mut actual_dst);
                            assert_eq!(actual_dst, shadow_dst,
                                "Copy data mismatch");
                            assert_eq!(chain.remaining(), shadow.remaining(),
                                "Remaining mismatch after copy");
                        } else {
                            // Should panic on underflow
                            let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                                let mut temp_chain = first_data.chain(second_data);
                                temp_chain.copy_to_slice(&mut actual_dst);
                            }));
                            assert!(result.is_err(),
                                "Copy {} bytes with {} remaining should panic",
                                dst_len, chain.remaining());
                        }
                    },

                    ChainOperation::GetU8 => {
                        let can_get = chain.remaining() >= 1;
                        let shadow_val = shadow.get_u8();

                        if can_get {
                            let actual_val = chain.get_u8();
                            assert_eq!(Some(actual_val), shadow_val,
                                "GetU8 value mismatch");
                            assert_eq!(chain.remaining(), shadow.remaining(),
                                "Remaining mismatch after get_u8");
                        } else {
                            // Should panic on underflow
                            let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                                let mut temp_chain = first_data.chain(second_data);
                                temp_chain.get_u8()
                            }));
                            assert!(result.is_err(),
                                "GetU8 with {} remaining should panic", chain.remaining());
                        }
                    },

                    ChainOperation::GetU16 => {
                        let can_get = chain.remaining() >= 2;
                        let shadow_val = shadow.get_u16();

                        if can_get {
                            let actual_val = chain.get_u16();
                            assert_eq!(Some(actual_val), shadow_val,
                                "GetU16 value mismatch");
                            assert_eq!(chain.remaining(), shadow.remaining(),
                                "Remaining mismatch after get_u16");
                        } else {
                            // Should panic on underflow
                            let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                                let mut temp_chain = first_data.chain(second_data);
                                temp_chain.get_u16()
                            }));
                            assert!(result.is_err(),
                                "GetU16 with {} remaining should panic", chain.remaining());
                        }
                    },

                    ChainOperation::CheckRemaining => {
                        assert_eq!(chain.remaining(), shadow.remaining(),
                            "Remaining consistency check failed");
                    },

                    ChainOperation::GetChunk => {
                        let chunk = chain.chunk();
                        let shadow_chunk = shadow.chunk();

                        if !shadow_chunk.is_empty() {
                            // Chunk should start with the same data
                            assert!(!chunk.is_empty(), "Chain chunk empty but shadow non-empty");
                            assert_eq!(chunk[0], shadow_chunk[0],
                                "Chunk first byte mismatch");
                        } else {
                            assert!(chunk.is_empty(), "Chain chunk non-empty but shadow empty");
                        }
                    },

                    ChainOperation::HasRemaining => {
                        assert_eq!(chain.has_remaining(), shadow.has_remaining(),
                            "HasRemaining mismatch");
                    },

                    ChainOperation::OversizedAdvance { amount } => {
                        let amount = (*amount as usize).max(chain.remaining() + 1);

                        // Should always panic
                        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                            let mut temp_chain = first_data.chain(second_data);
                            temp_chain.advance(amount);
                        }));
                        assert!(result.is_err(),
                            "Oversized advance {} should panic", amount);
                    },
                }

                // Invariant: remaining should never exceed initial total
                let initial_total = first_data.len() + second_data.len();
                assert!(chain.remaining() <= initial_total,
                    "Remaining {} exceeds initial total {}",
                    chain.remaining(), initial_total);
            }
        }};
    }

    // Test different buffer type combinations
    match input.buffer_variant {
        BufferVariant::SliceSlice => {
            test_chain!(first_data.chain(second_data));
        },

        BufferVariant::BytesSlice => {
            let first = Bytes::copy_from_slice(first_data).reader();
            test_chain!(first.chain(second_data));
        },

        BufferVariant::SliceByte => {
            let second = Bytes::copy_from_slice(second_data).reader();
            test_chain!(first_data.chain(second));
        },

        BufferVariant::BytesBytes => {
            let first = Bytes::copy_from_slice(first_data).reader();
            let second = Bytes::copy_from_slice(second_data).reader();
            test_chain!(first.chain(second));
        },
    }
});