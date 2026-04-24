//! Performance benchmarks for Bytes/BytesMut allocation hot paths.
//!
//! This benchmark suite profiles memory allocation patterns in the bytes module,
//! focusing on allocation-heavy operations that dominate real-world usage.

use asupersync::bytes::{Bytes, BytesMut};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

/// Scenario A: Incremental BytesMut growth (network buffer simulation)
///
/// Simulates receiving data over a network where a buffer grows incrementally
/// as chunks arrive. This tests Vec::extend_from_slice and reallocation patterns.
fn bench_bytes_mut_incremental_growth(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes_mut_incremental_growth");

    // Test different chunk sizes and total sizes
    let test_cases = [
        (64, 1024),     // Small chunks, small total (typical small messages)
        (256, 8192),    // Medium chunks, medium total (typical HTTP responses)
        (1024, 65536),  // Large chunks, large total (file transfers)
        (4096, 262144), // Very large chunks (bulk data)
    ];

    for (chunk_size, total_size) in test_cases {
        group.throughput(Throughput::Bytes(total_size as u64));

        let test_data = vec![0u8; chunk_size];
        let iterations = total_size / chunk_size;

        group.bench_with_input(
            BenchmarkId::new("no_reserve", format!("{chunk_size}x{iterations}")),
            &(chunk_size, iterations),
            |b, &(chunk_size, iterations)| {
                let test_data = vec![0u8; chunk_size];
                b.iter(|| {
                    let mut buf = BytesMut::new();
                    for _ in 0..iterations {
                        buf.put_slice(black_box(&test_data));
                    }
                    black_box(buf)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("with_reserve", format!("{chunk_size}x{iterations}")),
            &(chunk_size, iterations, total_size),
            |b, &(chunk_size, iterations, total_size)| {
                let test_data = vec![0u8; chunk_size];
                b.iter(|| {
                    let mut buf = BytesMut::with_capacity(total_size);
                    for _ in 0..iterations {
                        buf.put_slice(black_box(&test_data));
                    }
                    black_box(buf)
                });
            },
        );
    }

    group.finish();
}

/// Scenario B: BytesMut split operations (protocol frame splitting)
///
/// Simulates parsing protocol frames where we split buffers to extract
/// individual messages. This tests split_to/split_off allocation patterns.
fn bench_bytes_mut_splitting(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes_mut_splitting");

    let test_cases = [
        (8192, 512),    // 8KB buffer, split into 512-byte frames
        (32768, 1024),  // 32KB buffer, split into 1KB frames
        (131072, 4096), // 128KB buffer, split into 4KB frames
    ];

    for (buffer_size, frame_size) in test_cases {
        let num_frames = buffer_size / frame_size;
        group.throughput(Throughput::Bytes(buffer_size as u64));

        group.bench_with_input(
            BenchmarkId::new("split_to", format!("{buffer_size}÷{frame_size}")),
            &(buffer_size, frame_size),
            |b, &(buffer_size, frame_size)| {
                b.iter(|| {
                    let mut buf = BytesMut::with_capacity(buffer_size);
                    buf.resize(buffer_size, 0x42);

                    let mut frames = Vec::new();
                    while buf.len() >= frame_size {
                        let frame = buf.split_to(frame_size);
                        frames.push(black_box(frame));
                    }
                    black_box(frames)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("split_off", format!("{buffer_size}÷{frame_size}")),
            &(buffer_size, frame_size),
            |b, &(buffer_size, frame_size)| {
                b.iter(|| {
                    let mut buf = BytesMut::with_capacity(buffer_size);
                    buf.resize(buffer_size, 0x42);

                    let mut frames = Vec::new();
                    while buf.len() >= frame_size {
                        let remaining = buf.len() - frame_size;
                        let frame = buf.split_off(remaining);
                        buf.truncate(remaining);
                        frames.push(black_box(frame));
                    }
                    black_box(frames)
                });
            },
        );
    }

    group.finish();
}

/// Scenario C: Bytes creation from various sources
///
/// Tests different ways of creating Bytes to understand allocation patterns
/// in constructors and conversion functions.
fn bench_bytes_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes_creation");

    let test_sizes = [64, 512, 4096, 32768];

    for size in test_sizes {
        group.throughput(Throughput::Bytes(size as u64));

        let test_data = vec![0u8; size];

        group.bench_with_input(
            BenchmarkId::new("copy_from_slice", size),
            &size,
            |b, &size| {
                let test_data = vec![0u8; size];
                b.iter(|| {
                    let bytes = Bytes::copy_from_slice(black_box(&test_data));
                    black_box(bytes)
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("from_vec", size), &size, |b, &size| {
            b.iter(|| {
                let test_data = vec![0u8; size];
                let bytes = Bytes::from(black_box(test_data));
                black_box(bytes)
            });
        });

        group.bench_with_input(
            BenchmarkId::new("freeze_bytes_mut", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut buf = BytesMut::with_capacity(size);
                    buf.resize(size, 0x42);
                    let bytes = black_box(buf).freeze();
                    black_box(bytes)
                });
            },
        );

        // Test static bytes (no allocation) as baseline
        group.bench_function(BenchmarkId::new("from_static", size), |b| {
            // Use a smaller static slice for comparison
            const STATIC_DATA: &[u8] = &[0u8; 1024];
            let data = if size <= STATIC_DATA.len() {
                &STATIC_DATA[..size]
            } else {
                STATIC_DATA
            };

            b.iter(|| {
                let bytes = Bytes::from_static(black_box(data));
                black_box(bytes)
            });
        });
    }

    group.finish();
}

/// Scenario D: Mixed allocation patterns (realistic workload)
///
/// Simulates realistic usage patterns mixing BytesMut growth, splitting,
/// and Bytes creation to understand allocation behavior under mixed load.
fn bench_mixed_allocation_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_allocation_patterns");

    group.bench_function("http_request_parsing", |b| {
        let request_data =
            b"GET /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1024\r\n\r\n";
        let body_data = vec![0u8; 1024];

        b.iter(|| {
            // Simulate receiving HTTP request
            let mut buf = BytesMut::with_capacity(2048);
            buf.put_slice(black_box(request_data));
            buf.put_slice(black_box(&body_data));

            // Parse headers (split at \r\n\r\n)
            let header_end = buf[..].windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let headers = buf.split_to(header_end);

            // Convert to immutable bytes
            let header_bytes = Bytes::from(headers.freeze());
            let body_bytes = buf.freeze();

            black_box((header_bytes, body_bytes))
        });
    });

    group.bench_function("json_streaming", |b| {
        // Simulate JSON streaming where we build up responses
        let records = (0..100)
            .map(|i| format!(r#"{{"id":{i},"name":"item{i}","value":{}}}"#, i * 42))
            .collect::<Vec<_>>();

        b.iter(|| {
            let mut response = BytesMut::with_capacity(8192);
            response.put_slice(b"[");

            for (i, record) in records.iter().enumerate() {
                if i > 0 {
                    response.put_slice(b",");
                }
                response.put_slice(black_box(record.as_bytes()));
            }
            response.put_slice(b"]");

            let json_bytes = response.freeze();
            black_box(json_bytes)
        });
    });

    group.bench_function("frame_processing", |b| {
        // Simulate processing network frames of varying sizes
        let frame_sizes = [64, 128, 256, 512, 1024, 2048];

        b.iter(|| {
            let mut processed = Vec::new();

            for &frame_size in &frame_sizes {
                // Create frame data
                let mut frame = BytesMut::with_capacity(frame_size + 8);
                frame.put_slice(&(frame_size as u32).to_be_bytes()); // Length prefix
                frame.put_slice(&[0x42; 4]); // Header
                frame.resize(frame_size + 8, 0x55); // Payload

                // Extract payload
                let _header = frame.split_to(8);
                let payload = frame.freeze();

                processed.push(black_box(payload));
            }

            black_box(processed)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_bytes_mut_incremental_growth,
    bench_bytes_mut_splitting,
    bench_bytes_creation,
    bench_mixed_allocation_patterns
);
criterion_main!(benches);
