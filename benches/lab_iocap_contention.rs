//! Benchmark for br-asupersync-jyqjh9 — proves the sharded-counter
//! optimization on `LabIoCap::record_submit` / `record_complete`.
//!
//! Pre-fix: two adjacent `AtomicU64` counters in the same struct →
//! same cache line → false-sharing ping-pong on every concurrent
//! submit/complete pair AND no scaling across N writer threads on
//! the SAME counter.
//!
//! Post-fix: each counter is sharded `LAB_IOCAP_SHARD_COUNT=8` ways
//! across cache-padded `AtomicU64`s; thread-local shard index keeps
//! the hot path to a single masked `fetch_add`. Expected scaling is
//! near-linear up to `LAB_IOCAP_SHARD_COUNT` writer threads.
//!
//! This bench measures throughput at 1, 2, 4, 8, 16 writer threads
//! against a shared `Arc<LabIoCap>` for both `record_submit` and a
//! mixed `submit + complete` workload (the realistic I/O case).

#![cfg(feature = "test-internals")]

use asupersync::io::LabIoCap;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde::Serialize;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

const OPS_PER_THREAD: u64 = 100_000;
const ALIGNMENT_PROBE_DEFAULT_OPS: u64 = 65_536;
const ALIGNMENT_PROBE_CHUNK_OPS: u64 = 256;
const ALIGNMENT_PROBE_MAX_THREADS: usize = 64;

#[repr(C, align(64))]
struct Aligned64 {
    value: AtomicU64,
}

#[repr(C, align(128))]
struct Aligned128 {
    value: AtomicU64,
}

trait ProbeCounter: Send + Sync + 'static {
    const ALIGNMENT_BYTES: u64;

    fn new(value: u64) -> Self;

    fn increment(&self) {
        let _ = self.value().fetch_add(1, Ordering::Relaxed);
    }

    fn value(&self) -> &AtomicU64;
}

impl ProbeCounter for Aligned64 {
    const ALIGNMENT_BYTES: u64 = 64;

    fn new(value: u64) -> Self {
        Self {
            value: AtomicU64::new(value),
        }
    }

    fn value(&self) -> &AtomicU64 {
        &self.value
    }
}

impl ProbeCounter for Aligned128 {
    const ALIGNMENT_BYTES: u64 = 128;

    fn new(value: u64) -> Self {
        Self {
            value: AtomicU64::new(value),
        }
    }

    fn value(&self) -> &AtomicU64 {
        &self.value
    }
}

#[derive(Debug)]
struct ThreadProbe {
    elapsed_ns: u64,
    latency_samples_ns: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct AlignmentProbeRow {
    workload_id: &'static str,
    alignment_bytes: u64,
    workers: usize,
    entries: usize,
    operations: u64,
    elapsed_ns: u64,
    throughput_ops_per_second: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    fairness_millionths: u64,
}

#[derive(Debug, Serialize)]
struct AlignmentLayoutRow {
    alignment_bytes: u64,
    entry_bytes: usize,
    array_8_bytes: usize,
    array_16_bytes: usize,
    array_64_bytes: usize,
}

#[derive(Debug, Serialize)]
struct AlignmentProbeReceipt {
    schema_version: u64,
    profile_id: &'static str,
    target_os: &'static str,
    target_arch: &'static str,
    available_parallelism: usize,
    operations_per_writer: u64,
    chunk_operations: u64,
    layouts: Vec<AlignmentLayoutRow>,
    rows: Vec<AlignmentProbeRow>,
}

fn probe_operations() -> u64 {
    std::env::var("ASUP_CACHE_ALIGNMENT_OPS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(ALIGNMENT_PROBE_DEFAULT_OPS, |value| {
            value.clamp(ALIGNMENT_PROBE_CHUNK_OPS, ALIGNMENT_PROBE_DEFAULT_OPS * 64)
        })
        / ALIGNMENT_PROBE_CHUNK_OPS
        * ALIGNMENT_PROBE_CHUNK_OPS
}

fn probe_thread_counts(available: usize) -> Vec<usize> {
    let maximum = available.clamp(1, ALIGNMENT_PROBE_MAX_THREADS);
    let mut counts = [1, 2, 4, 8, 16, 32, 64]
        .into_iter()
        .filter(|count| *count <= maximum)
        .collect::<Vec<_>>();
    if counts.last().copied() != Some(maximum) {
        counts.push(maximum);
    }
    counts
}

fn percentile(sorted: &[u64], thousandths: usize) -> u64 {
    assert!(!sorted.is_empty(), "percentile input must not be empty");
    let index = (sorted.len() - 1) * thousandths / 1_000;
    sorted[index]
}

fn throughput(total_operations: u64, elapsed_ns: u64) -> u64 {
    let numerator = u128::from(total_operations) * 1_000_000_000_u128;
    u64::try_from(numerator / u128::from(elapsed_ns.max(1)))
        .expect("bounded probe throughput fits u64")
}

fn summarize_threads<C: ProbeCounter>(
    workload_id: &'static str,
    workers: usize,
    entries: usize,
    operations: u64,
    results: Vec<ThreadProbe>,
) -> AlignmentProbeRow {
    let elapsed_ns = results
        .iter()
        .map(|result| result.elapsed_ns)
        .max()
        .expect("at least one worker result");
    let fastest_ns = results
        .iter()
        .map(|result| result.elapsed_ns)
        .min()
        .expect("at least one worker result");
    let mut samples = results
        .into_iter()
        .flat_map(|result| result.latency_samples_ns)
        .collect::<Vec<_>>();
    samples.sort_unstable();
    let total_operations = operations
        .checked_mul(u64::try_from(workers).expect("worker count fits u64"))
        .expect("bounded probe operation count");
    let fairness_millionths =
        u64::try_from(u128::from(fastest_ns) * 1_000_000_u128 / u128::from(elapsed_ns.max(1)))
            .expect("fairness ratio fits u64");

    AlignmentProbeRow {
        workload_id,
        alignment_bytes: C::ALIGNMENT_BYTES,
        workers,
        entries,
        operations: total_operations,
        elapsed_ns,
        throughput_ops_per_second: throughput(total_operations, elapsed_ns),
        p50_ns: percentile(&samples, 500),
        p95_ns: percentile(&samples, 950),
        p99_ns: percentile(&samples, 990),
        p999_ns: percentile(&samples, 999),
        fairness_millionths,
    }
}

fn run_independent_write_probe<C: ProbeCounter>(
    workers: usize,
    operations: u64,
) -> AlignmentProbeRow {
    let counters = Arc::new(
        (0..workers)
            .map(|_| ProbeCounterType(C::new(0)))
            .collect::<Vec<ProbeCounterType<C>>>(),
    );
    let barrier = Arc::new(Barrier::new(workers));
    let results = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let counters = Arc::clone(&counters);
            let barrier = Arc::clone(&barrier);
            handles.push(scope.spawn(move || {
                let counter = &counters[worker].0;
                let mut latency_samples_ns =
                    Vec::with_capacity((operations / ALIGNMENT_PROBE_CHUNK_OPS) as usize);
                barrier.wait();
                let total_start = Instant::now();
                for _ in 0..(operations / ALIGNMENT_PROBE_CHUNK_OPS) {
                    let chunk_start = Instant::now();
                    for _ in 0..ALIGNMENT_PROBE_CHUNK_OPS {
                        counter.increment();
                    }
                    let chunk_ns =
                        chunk_start.elapsed().as_nanos() / u128::from(ALIGNMENT_PROBE_CHUNK_OPS);
                    latency_samples_ns
                        .push(u64::try_from(chunk_ns).expect("per-operation latency fits u64"));
                }
                ThreadProbe {
                    elapsed_ns: u64::try_from(total_start.elapsed().as_nanos())
                        .expect("bounded probe duration fits u64"),
                    latency_samples_ns,
                }
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("alignment probe worker"))
            .collect::<Vec<_>>()
    });
    for counter in counters.iter() {
        assert_eq!(
            counter.0.value().load(Ordering::Relaxed),
            operations,
            "every independent counter must retain all increments"
        );
    }
    summarize_threads::<C>(
        "independent_hot_counters",
        workers,
        workers,
        operations,
        results,
    )
}

struct ProbeCounterType<C: ProbeCounter>(C);

fn run_snapshot_scan_probe<C: ProbeCounter>(entries: usize, scans: u64) -> AlignmentProbeRow {
    let counters = (0..entries)
        .map(|index| {
            ProbeCounterType(C::new(
                u64::try_from(index + 1).expect("probe index fits u64"),
            ))
        })
        .collect::<Vec<_>>();
    let expected_sum = u64::try_from(entries)
        .expect("entry count fits u64")
        .checked_mul(u64::try_from(entries + 1).expect("entry count fits u64"))
        .expect("bounded arithmetic")
        / 2;
    let total_start = Instant::now();
    let mut samples = Vec::with_capacity(usize::try_from(scans).expect("scan count fits usize"));
    for _ in 0..scans {
        let scan_start = Instant::now();
        let observed = counters.iter().fold(0_u64, |sum, counter| {
            sum.saturating_add(counter.0.value().load(Ordering::Relaxed))
        });
        black_box(observed);
        assert_eq!(observed, expected_sum, "snapshot scan must retain values");
        let per_entry_ns =
            scan_start.elapsed().as_nanos() / u128::try_from(entries).expect("entries fit u128");
        samples.push(u64::try_from(per_entry_ns).expect("per-entry latency fits u64"));
    }
    let elapsed_ns =
        u64::try_from(total_start.elapsed().as_nanos()).expect("bounded scan duration fits u64");
    samples.sort_unstable();
    let operations = scans
        .checked_mul(u64::try_from(entries).expect("entry count fits u64"))
        .expect("bounded scan operation count");

    AlignmentProbeRow {
        workload_id: "snapshot_scan_density",
        alignment_bytes: C::ALIGNMENT_BYTES,
        workers: 1,
        entries,
        operations,
        elapsed_ns,
        throughput_ops_per_second: throughput(operations, elapsed_ns),
        p50_ns: percentile(&samples, 500),
        p95_ns: percentile(&samples, 950),
        p99_ns: percentile(&samples, 990),
        p999_ns: percentile(&samples, 999),
        fairness_millionths: 1_000_000,
    }
}

fn alignment_layout<C: ProbeCounter>() -> AlignmentLayoutRow {
    let entry_bytes = core::mem::size_of::<ProbeCounterType<C>>();
    AlignmentLayoutRow {
        alignment_bytes: C::ALIGNMENT_BYTES,
        entry_bytes,
        array_8_bytes: entry_bytes * 8,
        array_16_bytes: entry_bytes * 16,
        array_64_bytes: entry_bytes * 64,
    }
}

fn alignment_probe_receipt() -> AlignmentProbeReceipt {
    let available_parallelism = thread::available_parallelism().map_or(1, usize::from);
    let operations = probe_operations();
    let mut rows = Vec::new();
    for workers in probe_thread_counts(available_parallelism) {
        rows.push(run_independent_write_probe::<Aligned64>(
            workers, operations,
        ));
        rows.push(run_independent_write_probe::<Aligned128>(
            workers, operations,
        ));
    }
    for entries in [8, 16, 32, 64] {
        let scans = (operations / u64::try_from(entries).expect("entry count fits u64")).max(2_048);
        rows.push(run_snapshot_scan_probe::<Aligned64>(entries, scans));
        rows.push(run_snapshot_scan_probe::<Aligned128>(entries, scans));
    }
    AlignmentProbeReceipt {
        schema_version: 1,
        profile_id: "cache-alignment-bounded-v1",
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        available_parallelism,
        operations_per_writer: operations,
        chunk_operations: ALIGNMENT_PROBE_CHUNK_OPS,
        layouts: vec![
            alignment_layout::<Aligned64>(),
            alignment_layout::<Aligned128>(),
        ],
        rows,
    }
}

fn scan_counter_values<C: ProbeCounter>(counters: &[ProbeCounterType<C>]) -> u64 {
    counters.iter().fold(0_u64, |sum, counter| {
        sum.saturating_add(counter.0.value().load(Ordering::Relaxed))
    })
}

fn bench_cache_alignment_matrix(c: &mut Criterion) {
    let receipt = alignment_probe_receipt();
    println!(
        "CACHE_ALIGNMENT_RECEIPT={}",
        serde_json::to_string(&receipt).expect("serialize cache-alignment receipt")
    );

    let counters_64 = (0..64)
        .map(|index| ProbeCounterType(Aligned64::new(index)))
        .collect::<Vec<_>>();
    let counters_128 = (0..64)
        .map(|index| ProbeCounterType(Aligned128::new(index)))
        .collect::<Vec<_>>();
    let mut group = c.benchmark_group("cache_alignment/snapshot_scan");
    group.throughput(Throughput::Elements(64));
    group.bench_function("64-byte", |b| {
        b.iter(|| black_box(scan_counter_values(&counters_64)));
    });
    group.bench_function("128-byte", |b| {
        b.iter(|| black_box(scan_counter_values(&counters_128)));
    });
    group.finish();
}

fn bench_record_submit(c: &mut Criterion) {
    let mut group = c.benchmark_group("io_cap/record_submit");
    group.measurement_time(Duration::from_secs(3));
    group.warm_up_time(Duration::from_millis(500));

    for &threads in &[1usize, 2, 4, 8, 16] {
        let total_ops = OPS_PER_THREAD * threads as u64;
        group.throughput(Throughput::Elements(total_ops));
        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let cap = Arc::new(LabIoCap::new_for_tests());
                        let barrier = Arc::new(Barrier::new(threads));
                        let mut handles = Vec::with_capacity(threads);
                        let start = std::time::Instant::now();
                        for _ in 0..threads {
                            let cap = Arc::clone(&cap);
                            let barrier = Arc::clone(&barrier);
                            handles.push(thread::spawn(move || {
                                barrier.wait();
                                for _ in 0..OPS_PER_THREAD {
                                    cap.record_submit();
                                }
                            }));
                        }
                        for h in handles {
                            h.join().expect("worker thread join");
                        }
                        total += start.elapsed();
                        // Validation: total submits across shards must
                        // equal threads × OPS_PER_THREAD. Catches a
                        // sharding bug (lost increments) before any
                        // perf claim.
                        assert_eq!(cap.submitted_total(), threads as u64 * OPS_PER_THREAD);
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

fn bench_record_submit_complete_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("io_cap/submit_complete_mixed");
    group.measurement_time(Duration::from_secs(3));
    group.warm_up_time(Duration::from_millis(500));

    // Mixed workload: each worker does record_submit + record_complete
    // back-to-back, modeling the realistic I/O lifecycle. Pre-fix this
    // was the worst case for false sharing because submit and complete
    // counters lived adjacent.
    for &threads in &[1usize, 2, 4, 8, 16] {
        let total_ops = OPS_PER_THREAD * threads as u64 * 2;
        group.throughput(Throughput::Elements(total_ops));
        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let cap = Arc::new(LabIoCap::new_for_tests());
                        let barrier = Arc::new(Barrier::new(threads));
                        let mut handles = Vec::with_capacity(threads);
                        let start = std::time::Instant::now();
                        for _ in 0..threads {
                            let cap = Arc::clone(&cap);
                            let barrier = Arc::clone(&barrier);
                            handles.push(thread::spawn(move || {
                                barrier.wait();
                                for _ in 0..OPS_PER_THREAD {
                                    cap.record_submit();
                                    cap.record_complete();
                                }
                            }));
                        }
                        for h in handles {
                            h.join().expect("worker thread join");
                        }
                        total += start.elapsed();
                        assert_eq!(cap.submitted_total(), threads as u64 * OPS_PER_THREAD);
                        assert_eq!(cap.completed_total(), threads as u64 * OPS_PER_THREAD);
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets =
        bench_record_submit,
        bench_record_submit_complete_mixed,
        bench_cache_alignment_matrix
);
criterion_main!(benches);
