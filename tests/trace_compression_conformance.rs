//! Conformance + metamorphic harness for `asupersync::trace::compression`.
//!
//! `trace::compression` shrinks a trace by dropping events that do not
//! contribute to causal structure. It is a *per-event independent filter*:
//! whether an event is kept depends only on its own `kind` and the chosen
//! `Level`. That structure forces a strong set of algebraic properties,
//! pinned here:
//!
//! - **Subsequence**: the compressed event list is an order-preserving
//!   subset of the input — never reordered, never invented, never mutated.
//! - **Level conformance**: the retained set matches the documented rule for
//!   each level (`Lossless` keeps all, `Structural` drops noise, `Skeleton`
//!   keeps only lifecycle/obligation/cancel/region events).
//! - **Retention lattice**: `Skeleton ⊆ Structural ⊆ Lossless` — a stronger
//!   level never keeps an event a weaker level dropped.
//! - **Idempotence**: re-compressing at the same level is a no-op.
//! - **Distributivity over concatenation**: `compress(a ++ b)` equals
//!   `compress(a) ++ compress(b)` — a direct consequence of per-event
//!   independence, and the property most likely to break if a future
//!   "optimization" introduces cross-event state.
//! - **Filter composition**: compressing an already-compressed trace with a
//!   stronger level equals compressing the original with the stronger level.
//! - **Bookkeeping**: `original_count`, `events_removed`, and `ratio` stay
//!   mutually consistent; `validate_compressed` always holds for a freshly
//!   compressed trace.
//!
//! Traces come from a deterministic in-test SplitMix64 generator; no
//! `proptest` dependency.

#![allow(clippy::needless_range_loop)]

use asupersync::trace::compression::{CompressedTrace, Level, compress, validate_compressed};
use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::Time;

// ---------------------------------------------------------------------------
// Deterministic trace generation
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Every `kind` relevant to the three compression levels: noise kinds that
/// `Structural` drops, skeleton kinds that survive `Skeleton`, and "neither"
/// kinds that `Structural` keeps but `Skeleton` drops.
const KIND_MENU: &[TraceEventKind] = &[
    // noise (Structural drops these)
    TraceEventKind::UserTrace,
    TraceEventKind::Wake,
    TraceEventKind::TimerScheduled,
    TraceEventKind::TimerFired,
    // skeleton (Skeleton keeps these)
    TraceEventKind::Spawn,
    TraceEventKind::Complete,
    TraceEventKind::CancelRequest,
    TraceEventKind::CancelAck,
    TraceEventKind::ObligationReserve,
    TraceEventKind::ObligationCommit,
    TraceEventKind::ObligationAbort,
    TraceEventKind::RegionCreated,
    TraceEventKind::RegionCloseComplete,
    // neither (Structural keeps, Skeleton drops)
    TraceEventKind::Schedule,
    TraceEventKind::Poll,
    TraceEventKind::Yield,
    TraceEventKind::TimerCancelled,
    TraceEventKind::RngValue,
    TraceEventKind::Checkpoint,
    TraceEventKind::RegionCloseBegin,
    TraceEventKind::ObligationLeak,
    TraceEventKind::IoReady,
];

/// Build a trace of `len` events with sequence numbers `base .. base+len`.
fn gen_trace(rng: &mut Rng, len: usize, base: u64) -> Vec<TraceEvent> {
    (0..len)
        .map(|i| {
            let kind = KIND_MENU[(rng.next_u64() as usize) % KIND_MENU.len()];
            TraceEvent::new(base + i as u64, Time::ZERO, kind, TraceData::None)
        })
        .collect()
}

const LEVELS: &[Level] = &[Level::Lossless, Level::Structural, Level::Skeleton];
const TRACE_LENS: &[usize] = &[0, 1, 2, 5, 11, 23, 50, 97];

// ---------------------------------------------------------------------------
// The documented retention rule, re-derived for conformance checking.
// ---------------------------------------------------------------------------

fn is_noise(kind: TraceEventKind) -> bool {
    matches!(
        kind,
        TraceEventKind::UserTrace
            | TraceEventKind::Wake
            | TraceEventKind::TimerScheduled
            | TraceEventKind::TimerFired
    )
}

fn is_skeleton(kind: TraceEventKind) -> bool {
    matches!(
        kind,
        TraceEventKind::Spawn
            | TraceEventKind::Complete
            | TraceEventKind::CancelRequest
            | TraceEventKind::CancelAck
            | TraceEventKind::ObligationReserve
            | TraceEventKind::ObligationCommit
            | TraceEventKind::ObligationAbort
            | TraceEventKind::RegionCreated
            | TraceEventKind::RegionCloseComplete
    )
}

fn retained_at(kind: TraceEventKind, level: Level) -> bool {
    match level {
        Level::Lossless => true,
        Level::Structural => !is_noise(kind),
        Level::Skeleton => is_skeleton(kind),
    }
}

fn seqs(events: &[TraceEvent]) -> Vec<u64> {
    events.iter().map(|e| e.seq).collect()
}

// ---------------------------------------------------------------------------
// Subsequence + level conformance
// ---------------------------------------------------------------------------

#[test]
fn compression_output_is_an_order_preserving_subsequence() {
    for &len in TRACE_LENS {
        for seed in 0..20u64 {
            let mut rng = Rng::new(seed ^ 0x5145 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len, 0);
            let input = seqs(&trace);
            for &level in LEVELS {
                let out = seqs(&compress(&trace, level).events);
                // Every output seq exists in the input, and they appear in the
                // same relative order (a strictly increasing subsequence,
                // since input seqs are strictly increasing).
                let mut cursor = 0usize;
                for s in &out {
                    while cursor < input.len() && input[cursor] != *s {
                        cursor += 1;
                    }
                    assert!(
                        cursor < input.len(),
                        "output seq {s} not found in order (level={level:?})"
                    );
                    cursor += 1;
                }
            }
        }
    }
}

#[test]
fn lossless_retains_every_event_unchanged() {
    for &len in TRACE_LENS {
        for seed in 0..12u64 {
            let mut rng = Rng::new(seed ^ 0x10C5 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len, 0);
            let out = compress(&trace, Level::Lossless);
            assert_eq!(seqs(&out.events), seqs(&trace), "lossless lost an event");
            for (a, b) in out.events.iter().zip(trace.iter()) {
                assert_eq!(a.kind, b.kind, "lossless mutated an event kind");
            }
        }
    }
}

#[test]
fn output_matches_the_documented_retention_rule() {
    // Conformance: the compressed event list is exactly the input filtered by
    // the documented per-level rule (re-derived in `retained_at`).
    for &len in TRACE_LENS {
        for seed in 0..20u64 {
            let mut rng = Rng::new(seed ^ 0xC04F ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len, 0);
            for &level in LEVELS {
                let expected: Vec<u64> = trace
                    .iter()
                    .filter(|e| retained_at(e.kind, level))
                    .map(|e| e.seq)
                    .collect();
                let actual = seqs(&compress(&trace, level).events);
                assert_eq!(
                    actual, expected,
                    "compress diverged from retention rule (level={level:?}, len={len}, seed={seed})"
                );
            }
        }
    }
}

#[test]
fn structural_output_carries_no_noise_kinds() {
    for &len in TRACE_LENS {
        let mut rng = Rng::new(0x7501 ^ len as u64);
        let trace = gen_trace(&mut rng, len, 0);
        for e in &compress(&trace, Level::Structural).events {
            assert!(
                !is_noise(e.kind),
                "Structural kept a noise event: {:?}",
                e.kind
            );
        }
    }
}

#[test]
fn skeleton_output_carries_only_skeleton_kinds() {
    for &len in TRACE_LENS {
        let mut rng = Rng::new(0x5A11 ^ len as u64);
        let trace = gen_trace(&mut rng, len, 0);
        for e in &compress(&trace, Level::Skeleton).events {
            assert!(
                is_skeleton(e.kind),
                "Skeleton kept a non-skeleton event: {:?}",
                e.kind
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Retention lattice: Skeleton ⊆ Structural ⊆ Lossless
// ---------------------------------------------------------------------------

#[test]
fn retention_is_monotone_across_the_level_lattice() {
    use std::collections::BTreeSet;
    for &len in TRACE_LENS {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0x1A77 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len, 0);

            let lossless: BTreeSet<u64> = compress(&trace, Level::Lossless)
                .events
                .iter()
                .map(|e| e.seq)
                .collect();
            let structural: BTreeSet<u64> = compress(&trace, Level::Structural)
                .events
                .iter()
                .map(|e| e.seq)
                .collect();
            let skeleton: BTreeSet<u64> = compress(&trace, Level::Skeleton)
                .events
                .iter()
                .map(|e| e.seq)
                .collect();

            assert!(
                skeleton.is_subset(&structural),
                "Skeleton kept an event Structural dropped (len={len}, seed={seed})"
            );
            assert!(
                structural.is_subset(&lossless),
                "Structural kept an event Lossless dropped (impossible) (len={len})"
            );
            assert_eq!(lossless.len(), trace.len(), "Lossless must keep everything");
        }
    }
}

// ---------------------------------------------------------------------------
// Idempotence and filter composition
// ---------------------------------------------------------------------------

#[test]
fn compression_is_idempotent_at_every_level() {
    for &len in TRACE_LENS {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0x1DE7 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len, 0);
            for &level in LEVELS {
                let once = compress(&trace, level);
                let twice = compress(&once.events, level);
                assert_eq!(
                    seqs(&twice.events),
                    seqs(&once.events),
                    "compress not idempotent (level={level:?}, len={len}, seed={seed})"
                );
            }
        }
    }
}

#[test]
fn stronger_compression_absorbs_weaker_compression() {
    // Filter composition over the lattice: compressing an already-compressed
    // trace with a stronger (or equal) level equals compressing the original
    // with the stronger level. Skeleton ⊆ Structural ⊆ Lossless, so the
    // weaker pre-pass never removes anything the stronger pass would keep.
    for &len in TRACE_LENS {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0xC0FF ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len, 0);

            for &(weak, strong) in &[
                (Level::Lossless, Level::Structural),
                (Level::Lossless, Level::Skeleton),
                (Level::Structural, Level::Skeleton),
                (Level::Lossless, Level::Lossless),
                (Level::Structural, Level::Structural),
            ] {
                let pre = compress(&trace, weak);
                let composed = compress(&pre.events, strong);
                let direct = compress(&trace, strong);
                assert_eq!(
                    seqs(&composed.events),
                    seqs(&direct.events),
                    "filter composition broke: {weak:?} then {strong:?} != {strong:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Metamorphic relation: compression distributes over concatenation.
// ---------------------------------------------------------------------------

#[test]
fn compression_distributes_over_concatenation() {
    // Because retention is per-event independent, compressing a concatenated
    // trace yields the concatenation of the compressed parts. A future change
    // that makes compression stateful (e.g. dedup across events) breaks this.
    for &len_a in &[0usize, 1, 7, 20] {
        for &len_b in &[0usize, 1, 9, 31] {
            for seed in 0..12u64 {
                let mut rng = Rng::new(seed ^ 0xCA7A ^ (len_a as u64) << 8 ^ (len_b as u64));
                let a = gen_trace(&mut rng, len_a, 0);
                let b = gen_trace(&mut rng, len_b, len_a as u64);
                let mut ab = a.clone();
                ab.extend(b.iter().cloned());

                for &level in LEVELS {
                    let whole = seqs(&compress(&ab, level).events);
                    let mut parts = seqs(&compress(&a, level).events);
                    parts.extend(seqs(&compress(&b, level).events));
                    assert_eq!(
                        whole, parts,
                        "compress(a++b) != compress(a)++compress(b) (level={level:?})"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bookkeeping: counts, ratio, certificate
// ---------------------------------------------------------------------------

#[test]
fn counts_and_ratio_stay_mutually_consistent() {
    for &len in TRACE_LENS {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0xC007 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len, 0);
            for &level in LEVELS {
                let c = compress(&trace, level);
                assert_eq!(c.original_count, len, "original_count != input length");
                assert_eq!(
                    c.events_removed(),
                    len - c.events.len(),
                    "events_removed inconsistent"
                );
                let ratio = c.ratio();
                assert!((0.0..=1.0).contains(&ratio), "ratio {ratio} out of [0,1]");
                if len == 0 {
                    assert!(
                        (ratio - 1.0).abs() < f64::EPSILON,
                        "empty ratio must be 1.0"
                    );
                } else {
                    let expected = c.events.len() as f64 / len as f64;
                    assert!(
                        (ratio - expected).abs() < 1e-12,
                        "ratio {ratio} != events/original {expected}"
                    );
                }
            }
        }
    }
}

#[test]
fn freshly_compressed_traces_always_validate() {
    // `compress` builds the certificate from exactly the retained events, so
    // `validate_compressed` must hold unconditionally.
    for &len in TRACE_LENS {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0xCE27 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len, 0);
            for &level in LEVELS {
                let c = compress(&trace, level);
                assert!(
                    validate_compressed(&c),
                    "validate_compressed failed for a freshly compressed trace \
                     (level={level:?}, len={len}, seed={seed})"
                );
            }
        }
    }
}

#[test]
fn compression_is_deterministic() {
    for &len in TRACE_LENS {
        for seed in 0..12u64 {
            let mut rng = Rng::new(seed ^ 0xDDE7 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len, 0);
            for &level in LEVELS {
                let a = compress(&trace, level);
                let b = compress(&trace, level);
                assert_eq!(seqs(&a.events), seqs(&b.events), "non-deterministic events");
                assert_eq!(a.original_count, b.original_count);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Degenerate inputs and Level value semantics
// ---------------------------------------------------------------------------

#[test]
fn empty_trace_compresses_to_empty_with_unit_ratio() {
    for &level in LEVELS {
        let c = compress(&[], level);
        assert!(c.events.is_empty());
        assert_eq!(c.original_count, 0);
        assert_eq!(c.events_removed(), 0);
        assert!((c.ratio() - 1.0).abs() < f64::EPSILON);
        assert!(validate_compressed(&c));
    }
}

#[test]
fn single_event_trace_is_kept_or_dropped_per_rule() {
    for &kind in KIND_MENU {
        let trace = vec![TraceEvent::new(0, Time::ZERO, kind, TraceData::None)];
        for &level in LEVELS {
            let c = compress(&trace, level);
            let kept = c.events.len();
            assert_eq!(
                kept,
                usize::from(retained_at(kind, level)),
                "single-event retention wrong for {kind:?} at {level:?}"
            );
        }
    }
}

#[test]
fn level_has_value_semantics() {
    let l = Level::Structural;
    let copied = l;
    assert_eq!(l, copied);
    assert_ne!(Level::Lossless, Level::Skeleton);
    assert_ne!(Level::Lossless, Level::Structural);
    assert_ne!(Level::Structural, Level::Skeleton);
    for level in LEVELS {
        assert!(!format!("{level:?}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// Performance and Observability Conformance Enhancements
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::time::Instant;

/// Performance metrics for compression operations.
#[derive(Debug, Clone)]
struct CompressionMetrics {
    compression_time: std::time::Duration,
    original_size: usize,
    compressed_size: usize,
    compression_ratio: f64,
    events_removed: usize,
    level: Level,
    memory_peak_estimate: usize,
}

impl CompressionMetrics {
    fn new(compression_time: std::time::Duration, compressed: &CompressedTrace) -> Self {
        Self {
            compression_time,
            original_size: compressed.original_count,
            compressed_size: compressed.events.len(),
            compression_ratio: compressed.ratio(),
            events_removed: compressed.events_removed(),
            level: compressed.level,
            memory_peak_estimate: compressed.events.len() * std::mem::size_of::<TraceEvent>(),
        }
    }

    fn throughput_events_per_ms(&self) -> f64 {
        // Nanosecond precision with a 1µs floor: small traces compress in
        // well under a millisecond, and the previous millisecond-granular
        // computation returned `f64::INFINITY` for them, which poisoned the
        // cross-level variance assertion with inf/NaN comparisons.
        let nanos = self.compression_time.as_nanos().max(1_000) as f64;
        self.original_size as f64 / (nanos / 1_000_000.0)
    }

    fn memory_efficiency_ratio(&self) -> f64 {
        if self.memory_peak_estimate == 0 {
            return 1.0;
        }
        (self.original_size * std::mem::size_of::<TraceEvent>()) as f64
            / self.memory_peak_estimate as f64
    }
}

/// Comprehensive performance and correctness test for trace compression.
///
/// This test validates compression performance characteristics, memory efficiency,
/// and correctness properties under various load patterns and trace sizes.
#[test]
fn comprehensive_compression_performance_conformance() {
    let test_cases = vec![
        (10, "small"),
        (100, "medium"),
        (1000, "large"),
        (5000, "extra_large"),
    ];

    let mut all_metrics = HashMap::new();

    for &(trace_len, size_label) in &test_cases {
        for &level in LEVELS {
            let mut level_metrics = Vec::new();

            // Test multiple random traces for statistical validity
            for seed in 0..10u64 {
                let mut rng = Rng::new(seed ^ 0xCE27 ^ (trace_len as u64) << 16);
                let trace = gen_trace(&mut rng, trace_len, seed * 1000);

                // Measure compression time and validate correctness
                let start_time = Instant::now();
                let compressed = compress(&trace, level);
                let compression_time = start_time.elapsed();

                let metrics = CompressionMetrics::new(compression_time, &compressed);
                assert_eq!(
                    metrics.compressed_size,
                    compressed.events.len(),
                    "Metric compressed size mismatch for {size_label} trace at {level:?}"
                );
                assert_eq!(
                    metrics.events_removed,
                    compressed.events_removed(),
                    "Metric removed-event count mismatch for {size_label} trace at {level:?}"
                );
                assert_eq!(
                    metrics.level, level,
                    "Metric level mismatch for {size_label} trace at {level:?}"
                );
                level_metrics.push(metrics);

                // Validate correctness properties
                assert_eq!(
                    compressed.original_count,
                    trace.len(),
                    "Original count mismatch for {size_label} trace at {level:?}"
                );

                assert!(
                    validate_compressed(&compressed),
                    "Validation failed for {size_label} trace at {level:?}"
                );

                // Validate compression is a subsequence
                let mut compressed_idx = 0;
                for (orig_idx, original_event) in trace.iter().enumerate() {
                    if compressed_idx < compressed.events.len()
                        && compressed.events[compressed_idx].seq == original_event.seq
                    {
                        assert_eq!(
                            compressed.events[compressed_idx], *original_event,
                            "Event mismatch at original index {} for {size_label} trace at {level:?}",
                            orig_idx
                        );
                        compressed_idx += 1;
                    }
                }

                // Performance expectations based on level
                match level {
                    Level::Lossless => {
                        assert_eq!(
                            compressed.events.len(),
                            trace.len(),
                            "Lossless should keep all events"
                        );
                        assert_eq!(
                            compressed.ratio(),
                            1.0,
                            "Lossless should have 1.0 compression ratio"
                        );
                    }
                    Level::Structural | Level::Skeleton => {
                        assert!(
                            compressed.events.len() <= trace.len(),
                            "Compressed trace should not be larger than original"
                        );
                        assert!(
                            compressed.ratio() <= 1.0,
                            "Compression ratio should not exceed 1.0"
                        );
                    }
                }

                // Compression time should be reasonable (< 1ms per 100 events)
                let expected_max_time =
                    std::time::Duration::from_millis((trace_len / 100).max(1) as u64);
                assert!(
                    compression_time <= expected_max_time,
                    "Compression too slow: {:?} for {} events at {level:?} (expected <= {:?})",
                    compression_time,
                    trace_len,
                    expected_max_time
                );
            }

            // Calculate aggregate statistics
            let avg_compression_time = level_metrics
                .iter()
                .map(|m| m.compression_time.as_nanos())
                .sum::<u128>()
                / level_metrics.len() as u128;

            let avg_compression_ratio = level_metrics
                .iter()
                .map(|m| m.compression_ratio)
                .sum::<f64>()
                / level_metrics.len() as f64;

            let avg_throughput = level_metrics
                .iter()
                .map(|m| m.throughput_events_per_ms())
                .sum::<f64>()
                / level_metrics.len() as f64;

            let avg_memory_efficiency = level_metrics
                .iter()
                .map(|m| m.memory_efficiency_ratio())
                .sum::<f64>()
                / level_metrics.len() as f64;

            all_metrics.insert(
                (size_label, level),
                (
                    avg_compression_time,
                    avg_compression_ratio,
                    avg_throughput,
                    avg_memory_efficiency,
                ),
            );

            // Print performance report
            println!(
                "Compression Performance [{size_label}@{level:?}]: \
                 avg_time={:.2}μs, ratio={:.3}, throughput={:.1}evt/ms, memory_eff={:.2}x",
                avg_compression_time as f64 / 1000.0,
                avg_compression_ratio,
                avg_throughput,
                avg_memory_efficiency
            );
        }
    }

    // Cross-level validation: stronger levels should never keep more events than weaker ones
    for &(_, size_label) in &test_cases {
        let lossless_stats = all_metrics.get(&(size_label, Level::Lossless));
        let structural_stats = all_metrics.get(&(size_label, Level::Structural));
        let skeleton_stats = all_metrics.get(&(size_label, Level::Skeleton));

        if let (Some(lossless), Some(structural), Some(skeleton)) =
            (lossless_stats, structural_stats, skeleton_stats)
        {
            // Compression ratios should follow: Skeleton <= Structural <= Lossless
            assert!(
                skeleton.1 <= structural.1,
                "Skeleton compression ratio should be <= Structural for {size_label}"
            );
            assert!(
                structural.1 <= lossless.1,
                "Structural compression ratio should be <= Lossless for {size_label}"
            );

            // Throughput should be reasonable across levels (within 10x of each other)
            assert!(
                skeleton.2 / lossless.2 <= 10.0 && lossless.2 / skeleton.2 <= 10.0,
                "Throughput variance too high across compression levels for {size_label}"
            );
        }
    }

    // Memory efficiency should improve with trace size (economies of scale)
    let small_memory_eff = all_metrics.get(&("small", Level::Structural)).map(|x| x.3);
    let large_memory_eff = all_metrics.get(&("large", Level::Structural)).map(|x| x.3);

    if let (Some(small), Some(large)) = (small_memory_eff, large_memory_eff) {
        // Memory efficiency should not degrade significantly with size
        assert!(
            large >= small * 0.5,
            "Memory efficiency degraded too much with trace size: {small:.2} -> {large:.2}"
        );
    }
}

/// Test compression idempotence with performance tracking.
///
/// Validates that re-compressing a compressed trace is a no-op operation
/// and measures the performance characteristics of this property.
#[test]
fn compression_idempotence_with_performance_tracking() {
    for &len in &[10, 100, 1000] {
        for seed in 0..5u64 {
            let mut rng = Rng::new(seed ^ 0xABCD ^ (len as u64) << 12);
            let original_trace = gen_trace(&mut rng, len, seed * 100);

            for &level in LEVELS {
                // First compression with timing
                let first_start = Instant::now();
                let first_compressed = compress(&original_trace, level);
                let first_duration = first_start.elapsed();

                // Second compression (should be idempotent) with timing
                let second_start = Instant::now();
                let second_compressed = compress(&first_compressed.events, level);
                let second_duration = second_start.elapsed();

                // Validate idempotence
                assert_eq!(
                    first_compressed.events, second_compressed.events,
                    "Compression not idempotent at {level:?} for len={len}, seed={seed}"
                );

                // `ratio()` divides retained events by that pass's own input
                // size, so the two passes have different denominators whenever
                // the first pass filtered anything; comparing them directly
                // can never hold. The idempotence claim in ratio terms is that
                // the second pass filters nothing: its ratio is exactly 1.0.
                assert!(
                    (second_compressed.ratio() - 1.0).abs() < f64::EPSILON,
                    "Re-compression filtered events at {level:?} for len={len}, seed={seed}: \
                     ratio {}",
                    second_compressed.ratio()
                );
                assert_eq!(
                    second_compressed.original_count,
                    first_compressed.events.len(),
                    "Re-compression should report the already-compressed trace length \
                     as its input size at {level:?} for len={len}, seed={seed}"
                );
                assert_eq!(
                    second_compressed.events_removed(),
                    0,
                    "Re-compression should remove no additional events at {level:?} \
                     for len={len}, seed={seed}"
                );

                // Validate both compressed traces pass validation
                assert!(
                    validate_compressed(&first_compressed),
                    "First compressed trace validation failed"
                );
                assert!(
                    validate_compressed(&second_compressed),
                    "Second compressed trace validation failed"
                );

                println!(
                    "Idempotence [{level:?}, len={len}]: first={:.1}μs, second={:.1}μs, \
                     events: {} -> {} (ratio={:.3})",
                    first_duration.as_nanos() as f64 / 1000.0,
                    second_duration.as_nanos() as f64 / 1000.0,
                    original_trace.len(),
                    first_compressed.events.len(),
                    first_compressed.ratio()
                );
            }
        }
    }
}
