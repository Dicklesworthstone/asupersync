//! GF(256) kernel performance benchmarks for extreme optimization.
//!
//! Benchmarks all kernel variants (Scalar, AVX2, NEON) and dual-lane operations
//! to validate substantial performance wins over baseline scalar implementation.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use asupersync::raptorq::gf256::{
    Gf256, gf256_mul_slice, gf256_addmul_slice, gf256_mul_slices2, gf256_addmul_slices2,
    active_kernel, Gf256Kernel, dual_addmul_kernel_decision_detail, dual_policy_snapshot
};
use std::hint::black_box as hint_black_box;

/// Benchmark configurations for different operation sizes.
const SIZES: &[usize] = &[64, 256, 1024, 4096, 16384, 65536, 262144];

/// Test scalars for multiplication benchmarks.
const TEST_SCALARS: &[u8] = &[1, 2, 17, 255];

/// Generate deterministic test data for benchmarking.
fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| ((i * 17 + 42) % 256) as u8).collect()
}

/// Benchmark single-slice multiplication: dst[i] = dst[i] * c
fn bench_mul_slice(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_mul_slice");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        let mut data = generate_test_data(size);
        let scalar = Gf256::new(17);

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    gf256_mul_slice(black_box(&mut data), black_box(scalar));
                    hint_black_box(&data);
                });
            }
        );
    }
    group.finish();
}

/// Benchmark single-slice multiply-accumulate: dst[i] = dst[i] + src[i] * c
fn bench_addmul_slice(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_addmul_slice");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64 * 2)); // Read src + write dst

        let mut dst = generate_test_data(size);
        let src = generate_test_data(size);
        let scalar = Gf256::new(42);

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    gf256_addmul_slice(
                        black_box(&mut dst),
                        black_box(&src),
                        black_box(scalar)
                    );
                    hint_black_box(&dst);
                });
            }
        );
    }
    group.finish();
}

/// Benchmark dual-slice multiplication: dst_a[i] = dst_a[i] * c, dst_b[i] = dst_b[i] * c
fn bench_mul_slices2(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_mul_slices2");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64 * 2)); // Two slices

        let mut data_a = generate_test_data(size);
        let mut data_b = generate_test_data(size);
        let scalar = Gf256::new(85);

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    gf256_mul_slices2(
                        black_box(&mut data_a),
                        black_box(&mut data_b),
                        black_box(scalar)
                    );
                    hint_black_box(&data_a);
                    hint_black_box(&data_b);
                });
            }
        );
    }
    group.finish();
}

/// Benchmark dual-slice multiply-accumulate:
/// dst_a[i] = dst_a[i] + src_a[i] * c, dst_b[i] = dst_b[i] + src_b[i] * c
fn bench_addmul_slices2(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_addmul_slices2");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64 * 4)); // Read 2 src + write 2 dst

        let mut dst_a = generate_test_data(size);
        let src_a = generate_test_data(size);
        let mut dst_b = generate_test_data(size);
        let src_b = generate_test_data(size);
        let scalar = Gf256::new(123);

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    gf256_addmul_slices2(
                        black_box(&mut dst_a),
                        black_box(&src_a),
                        black_box(&mut dst_b),
                        black_box(&src_b),
                        black_box(scalar)
                    );
                    hint_black_box(&dst_a);
                    hint_black_box(&dst_b);
                });
            }
        );
    }
    group.finish();
}

/// Benchmark scalar-specific fast paths (c == 1 case)
fn bench_fast_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_fast_paths");

    let size = 16384;
    group.throughput(Throughput::Bytes(size as u64 * 2));

    let mut dst = generate_test_data(size);
    let src = generate_test_data(size);

    // Test c == 1 (should use XOR fast path)
    group.bench_function("addmul_c_eq_1", |b| {
        b.iter(|| {
            gf256_addmul_slice(
                black_box(&mut dst),
                black_box(&src),
                black_box(Gf256::ONE)
            );
            hint_black_box(&dst);
        });
    });

    // Test c == 0 (should use zero fill)
    group.bench_function("addmul_c_eq_0", |b| {
        b.iter(|| {
            gf256_addmul_slice(
                black_box(&mut dst),
                black_box(&src),
                black_box(Gf256::ZERO)
            );
            hint_black_box(&dst);
        });
    });

    group.finish();
}

/// Benchmark kernel dispatch decision overhead
fn bench_dispatch_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_dispatch");

    // Test dual-lane decision making
    group.bench_function("dual_addmul_decision", |b| {
        b.iter(|| {
            let decision = dual_addmul_kernel_decision_detail(
                black_box(4096),
                black_box(4096)
            );
            hint_black_box(&decision);
        });
    });

    // Test policy snapshot
    group.bench_function("policy_snapshot", |b| {
        b.iter(|| {
            let snapshot = dual_policy_snapshot();
            hint_black_box(&snapshot);
        });
    });

    group.finish();
}

/// Compare kernel performance across different architectures
fn bench_kernel_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_kernel_comparison");
    group.throughput(Throughput::Bytes(16384));

    let mut data = generate_test_data(16384);
    let src = generate_test_data(16384);
    let scalar = Gf256::new(199);

    // Benchmark current active kernel
    group.bench_function("active_kernel_addmul", |b| {
        b.iter(|| {
            gf256_addmul_slice(
                black_box(&mut data),
                black_box(&src),
                black_box(scalar)
            );
            hint_black_box(&data);
        });
    });

    // Note kernel type for analysis
    println!("Active kernel: {:?}", active_kernel());

    group.finish();
}

/// Benchmark performance at different data alignments
fn bench_alignment_sensitivity(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_alignment");

    let base_size = 4096;
    let scalar = Gf256::new(77);

    // Test different alignment offsets
    for offset in &[0, 1, 4, 8, 16] {
        let total_size = base_size + offset;
        let mut data = generate_test_data(total_size);
        let src = generate_test_data(total_size);

        // Use offset slices to test alignment sensitivity
        let dst_slice = &mut data[*offset..];
        let src_slice = &src[*offset..];

        group.bench_with_input(
            BenchmarkId::new("addmul_offset", offset),
            offset,
            |b, _| {
                b.iter(|| {
                    gf256_addmul_slice(
                        black_box(dst_slice),
                        black_box(src_slice),
                        black_box(scalar)
                    );
                    hint_black_box(&dst_slice);
                });
            }
        );
    }

    group.finish();
}

/// Benchmark performance with different scalar values
fn bench_scalar_sensitivity(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_scalar_sensitivity");

    let size = 8192;
    group.throughput(Throughput::Bytes(size as u64 * 2));

    let mut dst = generate_test_data(size);
    let src = generate_test_data(size);

    for &scalar_value in TEST_SCALARS {
        let scalar = Gf256::new(scalar_value);

        group.bench_with_input(
            BenchmarkId::new("addmul_scalar", scalar_value),
            &scalar_value,
            |b, _| {
                b.iter(|| {
                    gf256_addmul_slice(
                        black_box(&mut dst),
                        black_box(&src),
                        black_box(scalar)
                    );
                    hint_black_box(&dst);
                });
            }
        );
    }

    group.finish();
}

/// Print benchmark environment information
fn print_bench_info() {
    println!("=== GF(256) Kernel Benchmark Environment ===");
    println!("Active kernel: {:?}", active_kernel());

    let snapshot = dual_policy_snapshot();
    println!("Profile pack: {:?}", snapshot.profile_pack);
    println!("Architecture class: {:?}", snapshot.architecture_class);
    println!("Tuning corpus: {}", snapshot.tuning_corpus_id);

    // Test decision making for a few representative sizes
    for &size in &[1024, 4096, 16384] {
        let decision = dual_addmul_kernel_decision_detail(size, size);
        println!("Size {} dual decision: {:?} (reason: {:?})",
                 size, decision.decision, decision.reason);
    }

    println!("============================================");
}

criterion_group! {
    name = gf256_benches;
    config = Criterion::default()
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets =
        bench_mul_slice,
        bench_addmul_slice,
        bench_mul_slices2,
        bench_addmul_slices2,
        bench_fast_paths,
        bench_dispatch_overhead,
        bench_kernel_comparison,
        bench_alignment_sensitivity,
        bench_scalar_sensitivity
}

fn main() {
    print_bench_info();
    gf256_benches();
}

criterion_main!(gf256_benches);