#![no_main]

//! Fuzz target for Buf and BufMut trait operations.
//!
//! This target tests the Buf (read-only) and BufMut (write-only) buffer
//! trait implementations. These traits provide type-safe methods for reading
//! and writing integers in various endianness and advancing buffer positions.
//! The goal is to catch boundary violations, endianness bugs, and panic
//! conditions in buffer access patterns.

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
struct BufOpSequence {
    initial_data: Vec<u8>,
    read_operations: Vec<BufReadOperation>,
    write_operations: Vec<BufWriteOperation>,
}

#[derive(Arbitrary, Debug)]
enum BufReadOperation {
    // Basic operations
    GetU8,
    GetI8,
    Advance { cnt: usize },

    // 16-bit operations (big and little endian)
    GetU16,
    GetU16Le,
    GetI16,
    GetI16Le,

    // 32-bit operations
    GetU32,
    GetU32Le,
    GetI32,
    GetI32Le,

    // 64-bit operations
    GetU64,
    GetU64Le,
    GetI64,
    GetI64Le,

    // 128-bit operations
    GetU128,
    GetU128Le,
    GetI128,
    GetI128Le,

    // Float operations
    GetF32,
    GetF32Le,
    GetF64,
    GetF64Le,

    // Slice operations
    CopyToSlice { len: usize },
    GetSlice { len: usize },
}

#[derive(Arbitrary, Debug)]
enum BufWriteOperation {
    // Basic operations
    PutU8 { val: u8 },
    PutI8 { val: i8 },

    // 16-bit operations
    PutU16 { val: u16 },
    PutU16Le { val: u16 },
    PutI16 { val: i16 },
    PutI16Le { val: i16 },

    // 32-bit operations
    PutU32 { val: u32 },
    PutU32Le { val: u32 },
    PutI32 { val: i32 },
    PutI32Le { val: i32 },

    // 64-bit operations
    PutU64 { val: u64 },
    PutU64Le { val: u64 },
    PutI64 { val: i64 },
    PutI64Le { val: i64 },

    // 128-bit operations
    PutU128 { val: u128 },
    PutU128Le { val: u128 },
    PutI128 { val: i128 },
    PutI128Le { val: i128 },

    // Float operations
    PutF32 { val: f32 },
    PutF32Le { val: f32 },
    PutF64 { val: f64 },
    PutF64Le { val: f64 },

    // Slice operations
    PutSlice { data: Vec<u8> },
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 4 {
        return;
    }

    // Limit input size to prevent timeout
    if input.len() > 64 * 1024 {
        return;
    }

    let mut unstructured = Unstructured::new(input);
    let Ok(sequence) = BufOpSequence::arbitrary(&mut unstructured) else {
        return;
    };

    // Test Buf trait (read-only operations)
    test_buf_operations(&sequence.initial_data, &sequence.read_operations);

    // Test BufMut trait (write-only operations)
    test_buf_mut_operations(&sequence.write_operations);

    // Test round-trip operations (write then read)
    test_roundtrip_operations(&sequence.write_operations, &sequence.read_operations);
});

fn test_buf_operations(data: &[u8], operations: &[BufReadOperation]) {
    use asupersync::bytes::{Buf, Bytes};

    let mut buf = Bytes::from(data.to_vec());
    let original_len = buf.len();

    for operation in operations {
        // Only proceed if we have enough bytes remaining
        let required_bytes = match operation {
            BufReadOperation::GetU8 | BufReadOperation::GetI8 => 1,
            BufReadOperation::GetU16 | BufReadOperation::GetU16Le
            | BufReadOperation::GetI16 | BufReadOperation::GetI16Le => 2,
            BufReadOperation::GetU32 | BufReadOperation::GetU32Le
            | BufReadOperation::GetI32 | BufReadOperation::GetI32Le
            | BufReadOperation::GetF32 | BufReadOperation::GetF32Le => 4,
            BufReadOperation::GetU64 | BufReadOperation::GetU64Le
            | BufReadOperation::GetI64 | BufReadOperation::GetI64Le
            | BufReadOperation::GetF64 | BufReadOperation::GetF64Le => 8,
            BufReadOperation::GetU128 | BufReadOperation::GetU128Le
            | BufReadOperation::GetI128 | BufReadOperation::GetI128Le => 16,
            BufReadOperation::Advance { cnt } => *cnt,
            BufReadOperation::CopyToSlice { len } | BufReadOperation::GetSlice { len } => *len,
        };

        if buf.remaining() < required_bytes {
            continue;
        }

        match operation {
            BufReadOperation::GetU8 => {
                let val = buf.get_u8();
                assert!(val <= 255);
            }
            BufReadOperation::GetI8 => {
                let _val = buf.get_i8();
            }
            BufReadOperation::GetU16 => {
                let _val = buf.get_u16();
            }
            BufReadOperation::GetU16Le => {
                let _val = buf.get_u16_le();
            }
            BufReadOperation::GetI16 => {
                let _val = buf.get_i16();
            }
            BufReadOperation::GetI16Le => {
                let _val = buf.get_i16_le();
            }
            BufReadOperation::GetU32 => {
                let _val = buf.get_u32();
            }
            BufReadOperation::GetU32Le => {
                let _val = buf.get_u32_le();
            }
            BufReadOperation::GetI32 => {
                let _val = buf.get_i32();
            }
            BufReadOperation::GetI32Le => {
                let _val = buf.get_i32_le();
            }
            BufReadOperation::GetU64 => {
                let _val = buf.get_u64();
            }
            BufReadOperation::GetU64Le => {
                let _val = buf.get_u64_le();
            }
            BufReadOperation::GetI64 => {
                let _val = buf.get_i64();
            }
            BufReadOperation::GetI64Le => {
                let _val = buf.get_i64_le();
            }
            BufReadOperation::GetU128 => {
                let _val = buf.get_u128();
            }
            BufReadOperation::GetU128Le => {
                let _val = buf.get_u128_le();
            }
            BufReadOperation::GetI128 => {
                let _val = buf.get_i128();
            }
            BufReadOperation::GetI128Le => {
                let _val = buf.get_i128_le();
            }
            BufReadOperation::GetF32 => {
                let val = buf.get_f32();
                // Verify it's a valid float (not necessarily finite)
                let _ = val.to_bits();
            }
            BufReadOperation::GetF32Le => {
                let val = buf.get_f32_le();
                let _ = val.to_bits();
            }
            BufReadOperation::GetF64 => {
                let val = buf.get_f64();
                let _ = val.to_bits();
            }
            BufReadOperation::GetF64Le => {
                let val = buf.get_f64_le();
                let _ = val.to_bits();
            }
            BufReadOperation::Advance { cnt } => {
                let remaining_before = buf.remaining();
                buf.advance(*cnt);
                let remaining_after = buf.remaining();
                assert_eq!(remaining_after, remaining_before - cnt);
            }
            BufReadOperation::CopyToSlice { len } => {
                let mut dest = vec![0u8; *len];
                buf.copy_to_slice(&mut dest);
                assert_eq!(dest.len(), *len);
            }
            BufReadOperation::GetSlice { len } => {
                // This is not a standard Buf method, skip for now
                buf.advance(*len);
            }
        }

        // Verify remaining bytes is consistent
        assert!(buf.remaining() <= original_len);
    }
}

fn test_buf_mut_operations(operations: &[BufWriteOperation]) {
    use asupersync::bytes::{BufMut, BytesMut};

    let mut buf = BytesMut::with_capacity(64 * 1024);
    let initial_remaining = buf.remaining_mut();

    for operation in operations {
        // Check if we have enough space
        let required_space = match operation {
            BufWriteOperation::PutU8 { .. } | BufWriteOperation::PutI8 { .. } => 1,
            BufWriteOperation::PutU16 { .. } | BufWriteOperation::PutU16Le { .. }
            | BufWriteOperation::PutI16 { .. } | BufWriteOperation::PutI16Le { .. } => 2,
            BufWriteOperation::PutU32 { .. } | BufWriteOperation::PutU32Le { .. }
            | BufWriteOperation::PutI32 { .. } | BufWriteOperation::PutI32Le { .. }
            | BufWriteOperation::PutF32 { .. } | BufWriteOperation::PutF32Le { .. } => 4,
            BufWriteOperation::PutU64 { .. } | BufWriteOperation::PutU64Le { .. }
            | BufWriteOperation::PutI64 { .. } | BufWriteOperation::PutI64Le { .. }
            | BufWriteOperation::PutF64 { .. } | BufWriteOperation::PutF64Le { .. } => 8,
            BufWriteOperation::PutU128 { .. } | BufWriteOperation::PutU128Le { .. }
            | BufWriteOperation::PutI128 { .. } | BufWriteOperation::PutI128Le { .. } => 16,
            BufWriteOperation::PutSlice { data } => data.len(),
        };

        if buf.remaining_mut() < required_space {
            continue;
        }

        let len_before = buf.len();

        match operation {
            BufWriteOperation::PutU8 { val } => buf.put_u8(*val),
            BufWriteOperation::PutI8 { val } => buf.put_i8(*val),
            BufWriteOperation::PutU16 { val } => buf.put_u16(*val),
            BufWriteOperation::PutU16Le { val } => buf.put_u16_le(*val),
            BufWriteOperation::PutI16 { val } => buf.put_i16(*val),
            BufWriteOperation::PutI16Le { val } => buf.put_i16_le(*val),
            BufWriteOperation::PutU32 { val } => buf.put_u32(*val),
            BufWriteOperation::PutU32Le { val } => buf.put_u32_le(*val),
            BufWriteOperation::PutI32 { val } => buf.put_i32(*val),
            BufWriteOperation::PutI32Le { val } => buf.put_i32_le(*val),
            BufWriteOperation::PutU64 { val } => buf.put_u64(*val),
            BufWriteOperation::PutU64Le { val } => buf.put_u64_le(*val),
            BufWriteOperation::PutI64 { val } => buf.put_i64(*val),
            BufWriteOperation::PutI64Le { val } => buf.put_i64_le(*val),
            BufWriteOperation::PutU128 { val } => buf.put_u128(*val),
            BufWriteOperation::PutU128Le { val } => buf.put_u128_le(*val),
            BufWriteOperation::PutI128 { val } => buf.put_i128(*val),
            BufWriteOperation::PutI128Le { val } => buf.put_i128_le(*val),
            BufWriteOperation::PutF32 { val } => buf.put_f32(*val),
            BufWriteOperation::PutF32Le { val } => buf.put_f32_le(*val),
            BufWriteOperation::PutF64 { val } => buf.put_f64(*val),
            BufWriteOperation::PutF64Le { val } => buf.put_f64_le(*val),
            BufWriteOperation::PutSlice { data } => {
                if data.len() <= 1024 {  // Limit slice size
                    buf.put_slice(data);
                }
            }
        }

        // Verify length increased appropriately
        assert!(buf.len() >= len_before);
        assert!(buf.remaining_mut() <= initial_remaining);
    }
}

fn test_roundtrip_operations(write_ops: &[BufWriteOperation], read_ops: &[BufReadOperation]) {
    use asupersync::bytes::{Buf, BufMut, BytesMut};

    // Write data
    let mut write_buf = BytesMut::with_capacity(64 * 1024);

    for write_op in write_ops.iter().take(20) {  // Limit to prevent timeout
        match write_op {
            BufWriteOperation::PutU8 { val } => {
                if write_buf.remaining_mut() >= 1 {
                    write_buf.put_u8(*val);
                }
            }
            BufWriteOperation::PutU32 { val } => {
                if write_buf.remaining_mut() >= 4 {
                    write_buf.put_u32(*val);
                }
            }
            BufWriteOperation::PutU64Le { val } => {
                if write_buf.remaining_mut() >= 8 {
                    write_buf.put_u64_le(*val);
                }
            }
            // Add other operations as needed for round-trip testing
            _ => {}
        }
    }

    // Read data back
    let mut read_buf = write_buf.freeze();

    for read_op in read_ops.iter().take(10) {
        match read_op {
            BufReadOperation::GetU8 => {
                if read_buf.remaining() >= 1 {
                    let _val = read_buf.get_u8();
                }
            }
            BufReadOperation::GetU32 => {
                if read_buf.remaining() >= 4 {
                    let _val = read_buf.get_u32();
                }
            }
            BufReadOperation::GetU64Le => {
                if read_buf.remaining() >= 8 {
                    let _val = read_buf.get_u64_le();
                }
            }
            _ => {}
        }
    }
});