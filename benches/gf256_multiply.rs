#![allow(missing_docs)]

use asupersync::raptorq::gf256::{Gf256, gf256_mul_slice};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

const HOT_SIZES: &[usize] = &[32, 64, 256, 4096];

fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| ((i * 17 + 42) % 256) as u8).collect()
}

fn bench_gf256_multiply(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf256_multiply");
    let scalar = Gf256::new(17);

    for &size in HOT_SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        let mut data = generate_test_data(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                gf256_mul_slice(black_box(&mut data), black_box(scalar));
                black_box(&data);
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = gf256_multiply_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(300))
        .sample_size(10);
    targets = bench_gf256_multiply
}

criterion_main!(gf256_multiply_benches);
