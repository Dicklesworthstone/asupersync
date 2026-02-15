//! Benchmark suite for cancellation protocol and trace analysis.
//!
//! Covers four categories required by bd-2972:
//! 1. Cancellation protocol: request → drain → finalize lifecycle
//! 2. Trace canonicalization: TraceMonoid, FoataTrace, fingerprinting
//! 3. DPOR / race detection: HappensBeforeGraph, detect_races
//! 4. RaptorQ encode/decode: standalone encode + decode throughput
//!
//! All benchmarks use deterministic inputs from a fixed seed.

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use asupersync::config::RaptorQConfig;
use asupersync::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use asupersync::runtime::RuntimeState;
use asupersync::trace::boundary::SquareComplex;
use asupersync::trace::canonicalize::{trace_fingerprint, TraceMonoid};
use asupersync::trace::dpor::{detect_hb_races, detect_races, HappensBeforeGraph, RaceDetector};
use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
use asupersync::trace::event_structure::TracePoset;
use asupersync::trace::scoring::{score_persistence, seed_fingerprint};
use asupersync::transport::mock::{sim_channel, SimTransportConfig};
use asupersync::types::{
    Budget, CancelKind, CancelReason, ObjectId, ObjectParams, RegionId, TaskId, Time,
};
use asupersync::Cx;
use std::collections::HashSet;

// =============================================================================
// DETERMINISTIC TRACE GENERATORS
// =============================================================================

/// Generate a synthetic trace of `n` events resembling a realistic runtime
/// execution: spawns, schedules, polls, wakes, and completions across
/// multiple tasks and regions.
fn generate_trace(n: usize) -> Vec<TraceEvent> {
    let region = RegionId::new_for_test(0, 0);
    let mut events = Vec::with_capacity(n);

    for (seq, i) in (0..n).enumerate() {
        let task = TaskId::new_for_test(i as u32, 0);
        let time = Time::from_nanos(i as u64 * 1000);
        let kind = match i % 5 {
            0 => TraceEventKind::Spawn,
            1 => TraceEventKind::Schedule,
            2 => TraceEventKind::Poll,
            3 => TraceEventKind::Wake,
            _ => TraceEventKind::Complete,
        };
        events.push(TraceEvent::new(
            seq as u64,
            time,
            kind,
            TraceData::Task { task, region },
        ));
    }
    events
}

/// Generate a trace with concurrent tasks that have potential data races
/// (interleaved reads/writes to the same region).
fn generate_racy_trace(tasks: usize, ops_per_task: usize) -> Vec<TraceEvent> {
    let region = RegionId::new_for_test(0, 0);
    let mut events = Vec::with_capacity(tasks * ops_per_task);
    let mut seq = 0u64;

    for op in 0..ops_per_task {
        for t in 0..tasks {
            let task = TaskId::new_for_test(t as u32, 0);
            let time = Time::from_nanos(seq * 100);
            let kind = match op % 3 {
                0 => TraceEventKind::Schedule,
                1 => TraceEventKind::Poll,
                _ => TraceEventKind::Wake,
            };
            events.push(TraceEvent::new(
                seq,
                time,
                kind,
                TraceData::Task { task, region },
            ));
            seq += 1;
        }
    }
    events
}

/// Generate traces that contain commuting diamonds for homology scoring.
fn generate_commutation_trace(blocks: usize) -> Vec<TraceEvent> {
    let mut events = Vec::with_capacity(blocks * 4);
    for i in 0..blocks {
        let base = (i * 4) as u64;
        let time = i as u64 * 1000;
        events.push(TraceEvent::new(
            base,
            Time::from_nanos(time),
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "chaos-a".to_string(),
                task: None,
                detail: "write global state".to_string(),
            },
        ));
        events.push(TraceEvent::new(
            base + 1,
            Time::from_nanos(time + 10),
            TraceEventKind::Checkpoint,
            TraceData::Checkpoint {
                sequence: base + 1,
                active_tasks: 1,
                active_regions: 1,
            },
        ));
        events.push(TraceEvent::new(
            base + 2,
            Time::from_nanos(time + 20),
            TraceEventKind::Checkpoint,
            TraceData::Checkpoint {
                sequence: base + 2,
                active_tasks: 1,
                active_regions: 1,
            },
        ));
        events.push(TraceEvent::new(
            base + 3,
            Time::from_nanos(time + 30),
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "chaos-b".to_string(),
                task: None,
                detail: "write global state".to_string(),
            },
        ));
    }
    events
}

// =============================================================================
// CANCELLATION PROTOCOL BENCHMARKS
// =============================================================================

#[allow(clippy::too_many_lines)]
fn bench_cancel_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("cancel/protocol");

    // Cancel request on a single root region (no children)
    group.bench_function("request_root_only", |b| {
        b.iter_batched(
            || {
                let mut state = RuntimeState::new();
                let region = state.create_root_region(Budget::INFINITE);
                let reason = CancelReason::new(CancelKind::User);
                (state, region, reason)
            },
            |(mut state, region, reason)| {
                let tasks = state.cancel_request(region, &reason, None);
                black_box(tasks)
            },
            BatchSize::SmallInput,
        )
    });

    // Cancel with multiple sibling root regions (wide cancellation scope)
    for &count in &[2, 5, 10, 20] {
        group.bench_with_input(
            BenchmarkId::new("request_with_sibling_regions", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || {
                        let mut state = RuntimeState::new();
                        let mut regions = Vec::with_capacity(count);
                        for _ in 0..count {
                            regions.push(state.create_root_region(Budget::INFINITE));
                        }
                        let reason = CancelReason::new(CancelKind::Timeout);
                        (state, regions, reason)
                    },
                    |(mut state, regions, reason)| {
                        for &region in &regions {
                            let tasks = state.cancel_request(region, &reason, None);
                            black_box(&tasks);
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Cancel reason construction and strengthening
    group.bench_function("reason_strengthen", |b| {
        let r1 = CancelReason::new(CancelKind::User);
        let r2 = CancelReason::new(CancelKind::Timeout);
        b.iter(|| black_box(r1.clone().strengthen(&r2)))
    });

    // Cancel with different severity levels
    for kind in [
        CancelKind::User,
        CancelKind::Timeout,
        CancelKind::FailFast,
        CancelKind::Shutdown,
    ] {
        group.bench_with_input(
            BenchmarkId::new("request_kind", format!("{kind:?}")),
            &kind,
            |b, &kind| {
                b.iter_batched(
                    || {
                        let mut state = RuntimeState::new();
                        let region = state.create_root_region(Budget::INFINITE);
                        let reason = CancelReason::new(kind);
                        (state, region, reason)
                    },
                    |(mut state, region, reason)| {
                        let tasks = state.cancel_request(region, &reason, None);
                        black_box(tasks)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Obligation lifecycle: create → commit (happy path)
    group.bench_function("obligation_create_commit", |b| {
        b.iter_batched(
            || {
                let mut state = RuntimeState::new();
                let region = state.create_root_region(Budget::INFINITE);
                let task = TaskId::new_for_test(0, 0);
                (state, region, task)
            },
            |(mut state, region, task)| {
                let obligation = state.create_obligation(
                    asupersync::record::ObligationKind::SendPermit,
                    task,
                    region,
                    None,
                );
                if let Ok(oid) = obligation {
                    let _ = state.commit_obligation(oid);
                }
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });

    // Obligation lifecycle: create → abort (cancel path)
    group.bench_function("obligation_create_abort", |b| {
        b.iter_batched(
            || {
                let mut state = RuntimeState::new();
                let region = state.create_root_region(Budget::INFINITE);
                let task = TaskId::new_for_test(0, 0);
                (state, region, task)
            },
            |(mut state, region, task)| {
                let obligation = state.create_obligation(
                    asupersync::record::ObligationKind::SendPermit,
                    task,
                    region,
                    None,
                );
                if let Ok(oid) = obligation {
                    let _ = state
                        .abort_obligation(oid, asupersync::record::ObligationAbortReason::Cancel);
                }
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// TRACE CANONICALIZATION BENCHMARKS
// =============================================================================

fn bench_trace_canonicalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace/canonicalize");

    // TraceMonoid construction from events
    for &size in &[50, 200, 1000, 5000] {
        let events = generate_trace(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("monoid_from_events", size),
            &events,
            |b, events| b.iter(|| black_box(TraceMonoid::from_events(events))),
        );
    }

    // Fingerprint computation
    for &size in &[50, 200, 1000, 5000] {
        let events = generate_trace(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("fingerprint", size),
            &events,
            |b, events| b.iter(|| black_box(trace_fingerprint(events))),
        );
    }

    // Monoid concatenation (composability)
    group.bench_function("monoid_concat", |b| {
        let events_a = generate_trace(500);
        let events_b = generate_trace(500);
        let m_a = TraceMonoid::from_events(&events_a);
        let m_b = TraceMonoid::from_events(&events_b);
        b.iter(|| black_box(m_a.concat(&m_b)))
    });

    // Equivalence checking
    group.bench_function("monoid_equivalent", |b| {
        let events = generate_trace(500);
        let m1 = TraceMonoid::from_events(&events);
        let m2 = TraceMonoid::from_events(&events);
        b.iter(|| black_box(m1.equivalent(&m2)))
    });

    // Foata trace depth and parallelism queries
    group.bench_function("foata_depth_and_parallelism", |b| {
        let events = generate_trace(1000);
        let monoid = TraceMonoid::from_events(&events);
        b.iter(|| {
            let depth = monoid.critical_path_length();
            let par = monoid.max_parallelism();
            black_box((depth, par))
        })
    });

    group.finish();
}

// =============================================================================
// DPOR / RACE DETECTION BENCHMARKS
// =============================================================================

fn bench_dpor_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace/dpor");

    // Happens-before graph construction
    for &size in &[50, 200, 1000] {
        let events = generate_trace(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("hb_graph_build", size),
            &events,
            |b, events| b.iter(|| black_box(HappensBeforeGraph::from_trace(events))),
        );
    }

    // Race detection (full)
    for &size in &[50, 200, 1000] {
        let events = generate_racy_trace(4, size / 4);
        group.throughput(Throughput::Elements(events.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("detect_races", events.len()),
            &events,
            |b, events| b.iter(|| black_box(detect_races(events))),
        );
    }

    // HB-race detection
    for &size in &[50, 200, 1000] {
        let events = generate_racy_trace(4, size / 4);
        group.throughput(Throughput::Elements(events.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("detect_hb_races", events.len()),
            &events,
            |b, events| b.iter(|| black_box(detect_hb_races(events))),
        );
    }

    // RaceDetector construction + query
    group.bench_function("race_detector_build_query", |b| {
        let events = generate_racy_trace(4, 100);
        b.iter(|| {
            let detector = RaceDetector::from_trace(&events);
            let count = detector.races().len();
            let race_free = detector.is_race_free();
            black_box((count, race_free))
        })
    });

    group.finish();
}

// =============================================================================
// HOMOLOGY SCORING BENCHMARKS
// =============================================================================

fn bench_homology_scoring(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace/homology");

    for &blocks in &[10, 50, 200] {
        let events = generate_commutation_trace(blocks);
        group.throughput(Throughput::Elements(events.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("square_complex", events.len()),
            &events,
            |b, events| {
                b.iter(|| {
                    let poset = TracePoset::from_trace(events);
                    let complex = SquareComplex::from_trace_poset(&poset);
                    black_box(complex.boundary_2())
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("score_persistence", events.len()),
            &events,
            |b, events| {
                b.iter_batched(
                    HashSet::new,
                    |mut seen| {
                        let poset = TracePoset::from_trace(events);
                        let complex = SquareComplex::from_trace_poset(&poset);
                        let d2 = complex.boundary_2();
                        let reduced = d2.reduce();
                        let pairs = reduced.persistence_pairs();
                        black_box(score_persistence(
                            &pairs,
                            &mut seen,
                            seed_fingerprint(events.len() as u64),
                        ));
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// RAPTORQ ENCODE/DECODE BENCHMARKS (standalone)
// =============================================================================

fn bench_raptorq_encode_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq/encode_decode");
    let cx: Cx = Cx::for_testing();

    let sizes = [16_usize * 1024, 64 * 1024];

    for &size in &sizes {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let config = raptorq_config_for_size(size);
        let params = object_params_for(&config, size);
        let object_id = params.object_id;

        // Encode only
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encode", size), &size, |b, _| {
            b.iter_batched(
                || {
                    let (sink, _stream) = sim_channel(SimTransportConfig::reliable());
                    RaptorQSenderBuilder::new()
                        .config(config.clone())
                        .transport(sink)
                        .build()
                        .expect("build sender")
                },
                |mut sender| {
                    let result = sender.send_object(&cx, object_id, &data);
                    black_box(result)
                },
                BatchSize::SmallInput,
            )
        });

        // Decode only (pre-encode, then decode)
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("decode", size), &size, |b, _| {
            b.iter_batched(
                || {
                    let (sink, stream) = sim_channel(SimTransportConfig::reliable());
                    let mut sender = RaptorQSenderBuilder::new()
                        .config(config.clone())
                        .transport(sink)
                        .build()
                        .expect("build sender");
                    sender
                        .send_object(&cx, object_id, &data)
                        .expect("send object");
                    let receiver = RaptorQReceiverBuilder::new()
                        .config(config.clone())
                        .source(stream)
                        .build()
                        .expect("build receiver");
                    (receiver, params)
                },
                |(mut receiver, params)| {
                    let result = receiver.receive_object(&cx, &params);
                    black_box(result)
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn raptorq_config_for_size(size: usize) -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    if size > config.encoding.max_block_size {
        config.encoding.max_block_size = size;
    }
    config
}

fn object_params_for(config: &RaptorQConfig, size: usize) -> ObjectParams {
    let symbol_size = usize::from(config.encoding.symbol_size);
    let symbols_per_block = ((size + symbol_size.saturating_sub(1)) / symbol_size) as u16;
    ObjectParams::new(
        ObjectId::new_for_test(1),
        size as u64,
        config.encoding.symbol_size,
        1,
        symbols_per_block,
    )
}

// =============================================================================
// MAIN
// =============================================================================

criterion_group!(
    benches,
    bench_cancel_protocol,
    bench_trace_canonicalize,
    bench_homology_scoring,
    bench_dpor_analysis,
    bench_raptorq_encode_decode,
);

criterion_main!(benches);
