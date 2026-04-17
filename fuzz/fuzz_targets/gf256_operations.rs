#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::gf256::{
    Gf256, active_kernel, dual_addmul_kernel_decision, dual_mul_kernel_decision, gf256_add_slice,
    gf256_add_slices2, gf256_addmul_slice, gf256_mul_slice,
};
use libfuzzer_sys::fuzz_target;

/// Fuzzing input structure for GF256 operations
#[derive(Arbitrary, Debug)]
struct Gf256FuzzInput {
    /// Single field element operations
    field_ops: Vec<FieldOperation>,
    /// Slice-based operations
    slice_ops: Vec<SliceOperation>,
    /// Kernel decision tests
    kernel_tests: Vec<KernelTest>,
}

/// Single field element operation variants
#[derive(Arbitrary, Debug)]
enum FieldOperation {
    /// Test multiplication: a * b
    Multiply { a: u8, b: u8 },
    /// Test addition: a + b (XOR in GF256)
    Add { a: u8, b: u8 },
    /// Test division: a / b (when b != 0)
    Divide { a: u8, b: u8 },
    /// Test inversion: a^-1 (when a != 0)
    Invert { a: u8 },
    /// Test exponentiation: a^exp
    Power { a: u8, exp: u8 },
    /// Test associativity: (a * b) * c == a * (b * c)
    AssociativityTest { a: u8, b: u8, c: u8 },
    /// Test distributivity: a * (b + c) == (a * b) + (a * c)
    DistributivityTest { a: u8, b: u8, c: u8 },
}

/// Slice operation variants
#[derive(Arbitrary, Debug)]
enum SliceOperation {
    /// Test gf256_add_slice with random data
    AddSlice {
        dst_data: Vec<u8>,
        src_data: Vec<u8>,
    },
    /// Test gf256_add_slices2 with random data
    AddSlices2 {
        dst_a_data: Vec<u8>,
        src_a_data: Vec<u8>,
        dst_b_data: Vec<u8>,
        src_b_data: Vec<u8>,
    },
    /// Test gf256_mul_slice with scalar
    MulSlice { dst_data: Vec<u8>, scalar: u8 },
    /// Test gf256_addmul_slice operation
    AddMulSlice {
        dst_data: Vec<u8>,
        src_data: Vec<u8>,
        scalar: u8,
    },
    /// Test slice operations with misaligned data
    MisalignedAccess {
        data: Vec<u8>,
        offset: usize,
        len: usize,
        scalar: u8,
    },
    /// Test empty slices
    EmptySlices,
    /// Test single-element slices
    SingleElement { element: u8, scalar: u8 },
}

/// Kernel decision testing
#[derive(Arbitrary, Debug)]
struct KernelTest {
    len_a: usize,
    len_b: usize,
}

/// Maximum slice length for fuzzing (to avoid memory exhaustion)
const MAX_SLICE_LEN: usize = 8192;

fuzz_target!(|input: Gf256FuzzInput| {
    // Test field element operations
    for op in input.field_ops {
        test_field_operation(op);
    }

    // Test slice operations
    for op in input.slice_ops {
        test_slice_operation(op);
    }

    // Test kernel decision logic
    for test in input.kernel_tests {
        test_kernel_decisions(test);
    }
});

fn test_field_operation(op: FieldOperation) {
    match op {
        FieldOperation::Multiply { a, b } => {
            let result = Gf256(a).mul_field(Gf256(b));

            // Verify commutativity: a * b == b * a
            let reverse = Gf256(b).mul_field(Gf256(a));
            assert_eq!(
                result.0, reverse.0,
                "Multiplication not commutative: {} * {} != {} * {}",
                a, b, b, a
            );

            // Verify identity: a * 1 == a
            if b == 1 {
                assert_eq!(result.0, a, "Identity element failed: {} * 1 != {}", a, a);
            }

            // Verify zero: a * 0 == 0
            if b == 0 {
                assert_eq!(result.0, 0, "Zero multiplication failed: {} * 0 != 0", a);
            }
        }

        FieldOperation::Add { a, b } => {
            let result = Gf256(a).0 ^ Gf256(b).0; // Addition is XOR in GF(256)

            // Verify commutativity: a + b == b + a
            let reverse = Gf256(b).0 ^ Gf256(a).0;
            assert_eq!(
                result, reverse,
                "Addition not commutative: {} + {} != {} + {}",
                a, b, b, a
            );

            // Verify identity: a + 0 == a
            if b == 0 {
                assert_eq!(result, a, "Additive identity failed: {} + 0 != {}", a, a);
            }

            // Verify self-inverse: a + a == 0
            if a == b {
                assert_eq!(result, 0, "Self-inverse failed: {} + {} != 0", a, a);
            }
        }

        FieldOperation::Divide { a, b } => {
            if b != 0 {
                let result = Gf256(a).div_field(Gf256(b));

                // Verify: (a / b) * b == a
                let check = result.mul_field(Gf256(b));
                assert_eq!(
                    check.0, a,
                    "Division verification failed: ({} / {}) * {} != {}",
                    a, b, b, a
                );
            }
        }

        FieldOperation::Invert { a } => {
            if a != 0 {
                let inv = Gf256(a).inv();

                // Verify: a * a^-1 == 1
                let check = Gf256(a).mul_field(inv);
                assert_eq!(check.0, 1, "Inversion failed: {} * {}^-1 != 1", a, a);
            }
        }

        FieldOperation::Power { a, exp } => {
            let result = Gf256(a).pow(exp);

            // Verify: a^0 == 1 (when a != 0)
            if exp == 0 && a != 0 {
                assert_eq!(result.0, 1, "Power of zero failed: {}^0 != 1", a);
            }

            // Verify: a^1 == a
            if exp == 1 {
                assert_eq!(result.0, a, "Power of one failed: {}^1 != {}", a, a);
            }
        }

        FieldOperation::AssociativityTest { a, b, c } => {
            let left = Gf256(a).mul_field(Gf256(b)).mul_field(Gf256(c));
            let right = Gf256(a).mul_field(Gf256(b).mul_field(Gf256(c)));
            assert_eq!(
                left.0, right.0,
                "Associativity failed: ({} * {}) * {} != {} * ({} * {})",
                a, b, c, a, b, c
            );
        }

        FieldOperation::DistributivityTest { a, b, c } => {
            let left = Gf256(a).mul_field(Gf256(b ^ c)); // Addition is XOR
            let right_b = Gf256(a).mul_field(Gf256(b));
            let right_c = Gf256(a).mul_field(Gf256(c));
            let right = right_b.0 ^ right_c.0;
            assert_eq!(
                left.0, right,
                "Distributivity failed: {} * ({} + {}) != ({} * {}) + ({} * {})",
                a, b, c, a, b, a, c
            );
        }
    }
}

fn test_slice_operation(op: SliceOperation) {
    match op {
        SliceOperation::AddSlice {
            mut dst_data,
            src_data,
        } => {
            // Ensure slices are reasonable size
            if dst_data.len() > MAX_SLICE_LEN {
                dst_data.truncate(MAX_SLICE_LEN);
            }
            let min_len = dst_data.len().min(src_data.len());
            if min_len > 0 {
                let dst_slice = &mut dst_data[..min_len];
                let src_slice = &src_data[..min_len];
                let original_dst = dst_slice.to_vec();

                gf256_add_slice(dst_slice, src_slice);

                // Verify XOR operation
                for i in 0..min_len {
                    let expected = original_dst[i] ^ src_slice[i];
                    assert_eq!(
                        dst_slice[i], expected,
                        "Add slice failed at index {}: {} ^ {} != {}",
                        i, original_dst[i], src_slice[i], expected
                    );
                }
            }
        }

        SliceOperation::AddSlices2 {
            mut dst_a_data,
            src_a_data,
            mut dst_b_data,
            src_b_data,
        } => {
            // Ensure reasonable sizes
            if dst_a_data.len() > MAX_SLICE_LEN {
                dst_a_data.truncate(MAX_SLICE_LEN);
            }
            if dst_b_data.len() > MAX_SLICE_LEN {
                dst_b_data.truncate(MAX_SLICE_LEN);
            }

            let min_len = dst_a_data
                .len()
                .min(src_a_data.len())
                .min(dst_b_data.len())
                .min(src_b_data.len());
            if min_len > 0 {
                let dst_a_slice = &mut dst_a_data[..min_len];
                let src_a_slice = &src_a_data[..min_len];
                let dst_b_slice = &mut dst_b_data[..min_len];
                let src_b_slice = &src_b_data[..min_len];

                let orig_a = dst_a_slice.to_vec();
                let orig_b = dst_b_slice.to_vec();

                gf256_add_slices2(dst_a_slice, src_a_slice, dst_b_slice, src_b_slice);

                // Verify both operations
                for i in 0..min_len {
                    let expected_a = orig_a[i] ^ src_a_slice[i];
                    let expected_b = orig_b[i] ^ src_b_slice[i];
                    assert_eq!(
                        dst_a_slice[i], expected_a,
                        "Add slices2 A failed at index {}",
                        i
                    );
                    assert_eq!(
                        dst_b_slice[i], expected_b,
                        "Add slices2 B failed at index {}",
                        i
                    );
                }
            }
        }

        SliceOperation::MulSlice {
            mut dst_data,
            scalar,
        } => {
            if dst_data.len() > MAX_SLICE_LEN {
                dst_data.truncate(MAX_SLICE_LEN);
            }
            if !dst_data.is_empty() {
                let original = dst_data.clone();
                gf256_mul_slice(&mut dst_data, Gf256(scalar));

                // Verify Gf256(scalar) multiplication
                for i in 0..dst_data.len() {
                    let expected = Gf256(original[i]).mul_field(Gf256(scalar)).0;
                    assert_eq!(
                        dst_data[i],
                        expected,
                        "Mul slice failed at index {}: {} * {} != {}",
                        i,
                        original[i],
                        Gf256(scalar),
                        expected
                    );
                }
            }
        }

        SliceOperation::AddMulSlice {
            mut dst_data,
            src_data,
            scalar,
        } => {
            if dst_data.len() > MAX_SLICE_LEN {
                dst_data.truncate(MAX_SLICE_LEN);
            }
            let min_len = dst_data.len().min(src_data.len());
            if min_len > 0 {
                let dst_slice = &mut dst_data[..min_len];
                let src_slice = &src_data[..min_len];
                let original_dst = dst_slice.to_vec();

                gf256_addmul_slice(dst_slice, src_slice, Gf256(scalar));

                // Verify addmul: dst[i] = dst[i] + (src[i] * Gf256(scalar))
                for i in 0..min_len {
                    let mul_result = Gf256(src_slice[i]).mul_field(Gf256(scalar)).0;
                    let expected = original_dst[i] ^ mul_result; // Addition is XOR
                    assert_eq!(
                        dst_slice[i],
                        expected,
                        "AddMul slice failed at index {}: {} + ({} * {}) != {}",
                        i,
                        original_dst[i],
                        src_slice[i],
                        Gf256(scalar),
                        expected
                    );
                }
            }
        }

        SliceOperation::MisalignedAccess {
            mut data,
            offset,
            len,
            scalar,
        } => {
            if data.len() > MAX_SLICE_LEN {
                data.truncate(MAX_SLICE_LEN);
            }
            if !data.is_empty() && offset < data.len() {
                let actual_len = len.min(data.len() - offset);
                if actual_len > 0 {
                    let slice = &mut data[offset..offset + actual_len];
                    let original = slice.to_vec();

                    // Test that misaligned access doesn't crash
                    gf256_mul_slice(slice, Gf256(scalar));

                    // Verify the operation still works correctly
                    for i in 0..slice.len() {
                        let expected = Gf256(original[i]).mul_field(Gf256(scalar)).0;
                        assert_eq!(
                            slice[i], expected,
                            "Misaligned mul slice failed at index {}",
                            i
                        );
                    }
                }
            }
        }

        SliceOperation::EmptySlices => {
            // Test that empty slice operations don't panic
            let mut empty_dst: Vec<u8> = vec![];
            let empty_src: Vec<u8> = vec![];

            gf256_add_slice(&mut empty_dst, &empty_src);
            gf256_mul_slice(&mut empty_dst, Gf256(42));
            gf256_addmul_slice(&mut empty_dst, &empty_src, Gf256(42));

            let mut empty_dst2: Vec<u8> = vec![];
            gf256_add_slices2(&mut empty_dst, &empty_src, &mut empty_dst2, &empty_src);
        }

        SliceOperation::SingleElement { element, scalar } => {
            // Test single-element operations
            let mut dst = vec![element];
            let src = vec![element];
            let original_element = element;

            // Test mul
            gf256_mul_slice(&mut dst, Gf256(scalar));
            let expected_mul = Gf256(original_element).mul_field(Gf256(scalar)).0;
            assert_eq!(dst[0], expected_mul, "Single element mul failed");

            // Reset and test addmul
            dst[0] = original_element;
            gf256_addmul_slice(&mut dst, &src, Gf256(scalar));
            let mul_part = Gf256(element).mul_field(Gf256(scalar)).0;
            let expected_addmul = original_element ^ mul_part;
            assert_eq!(dst[0], expected_addmul, "Single element addmul failed");
        }
    }
}

fn test_kernel_decisions(test: KernelTest) {
    // Ensure reasonable sizes to avoid infinite loops or memory issues
    let len_a = test.len_a.min(1_000_000);
    let len_b = test.len_b.min(1_000_000);

    // Test that kernel decision functions don't panic
    let _mul_decision = dual_mul_kernel_decision(len_a, len_b);
    let _addmul_decision = dual_addmul_kernel_decision(len_a, len_b);

    // Test that active_kernel() is consistent
    let kernel1 = active_kernel();
    let kernel2 = active_kernel();
    assert_eq!(
        std::mem::discriminant(&kernel1),
        std::mem::discriminant(&kernel2),
        "Active kernel should be consistent across calls"
    );
}
