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

use asupersync::trace::compression::{Level, compress, validate_compressed};
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
            assert!(!is_noise(e.kind), "Structural kept a noise event: {:?}", e.kind);
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
                    assert!((ratio - 1.0).abs() < f64::EPSILON, "empty ratio must be 1.0");
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
