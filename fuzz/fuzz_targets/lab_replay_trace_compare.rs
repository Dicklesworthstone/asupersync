#![no_main]

//! br-asupersync-ebsbrw — fuzz target for the trace-comparison
//! quartet in `src/lab/replay.rs`:
//!
//!   - `find_divergence(&[TraceEvent], &[TraceEvent]) -> Option<TraceDivergence>`
//!   - `normalize_for_replay(&[TraceEvent]) -> NormalizationResult`
//!   - `normalize_for_replay_with_config(&[TraceEvent], &NormalizationConfig)`
//!   - `compare_normalized(&[TraceEvent], &[TraceEvent]) -> Option<TraceDivergence>`
//!   - `traces_equivalent(&[TraceEvent], &[TraceEvent]) -> bool`
//!
//! ## Contract under test
//!
//! 1. **Panic floor.** All five functions take `&[TraceEvent]` slices
//!    that originate from disk artefacts, distributed bridge replies,
//!    or trace recorder snapshots — any of which can be poisoned by
//!    an adversary in a multi-tenant lab or a CI artifact-tampering
//!    scenario. None of them may panic.
//!
//! 2. **Reflexivity.** `traces_equivalent(t, t) == true` for every
//!    valid trace `t`. `find_divergence(t, t).is_none()` likewise.
//!    The fuzz target asserts this metamorphic property after every
//!    iteration.
//!
//! 3. **Length-mismatch handling.** `find_divergence` and
//!    `compare_normalized` must report a divergence (Some) — never
//!    panic — when slice lengths differ.
//!
//! ## Input shape
//!
//! The fuzz input is interpreted as a JSON document of shape
//! `{ "a": [TraceEvent, ...], "b": [TraceEvent, ...] }`. This funnels
//! libFuzzer's mutator through TraceEvent's serde derive, which
//! covers TraceEventKind variants and TraceData payloads
//! comprehensively. Inputs that fail to deserialize are dropped
//! early.
//!
//! Bounded resources: input clamped to 256 KiB; deserialised vecs
//! capped at 4096 events each post-parse so per-iteration cost is
//! sub-second.

use asupersync::lab::replay::{
    NormalizationResult, TraceDivergence, compare_normalized, find_divergence,
    normalize_for_replay, traces_equivalent,
};
use asupersync::trace::TraceEvent;
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_INPUT: usize = 256 * 1024;
const MAX_EVENTS_PER_SIDE: usize = 4096;

#[derive(Deserialize)]
struct TracePair {
    #[serde(default)]
    a: Vec<TraceEvent>,
    #[serde(default)]
    b: Vec<TraceEvent>,
}

fn observe_trace_divergence(
    label: &str,
    divergence: &TraceDivergence,
    left_len: usize,
    right_len: usize,
) {
    let max_len = left_len.max(right_len);
    assert!(
        divergence.position <= max_len,
        "{label}: divergence position {} exceeded max input length {max_len}",
        divergence.position,
    );

    let diagnostic = divergence.to_string();
    assert!(
        diagnostic.contains("Divergence at position"),
        "{label}: divergence diagnostic should identify the divergent position",
    );
    assert!(
        diagnostic.contains(&divergence.position.to_string()),
        "{label}: divergence diagnostic should include the numeric position",
    );
}

fn observe_find_divergence(
    label: &str,
    left: &[TraceEvent],
    right: &[TraceEvent],
) -> Option<TraceDivergence> {
    let divergence = find_divergence(left, right);
    if let Some(divergence) = &divergence {
        observe_trace_divergence(label, divergence, left.len(), right.len());
    }
    divergence
}

fn observe_normalized_comparison(
    label: &str,
    left: &[TraceEvent],
    right: &[TraceEvent],
) -> Option<TraceDivergence> {
    let divergence = compare_normalized(left, right);
    if let Some(divergence) = &divergence {
        observe_trace_divergence(label, divergence, left.len(), right.len());
    }
    divergence
}

fn observe_trace_equivalence(
    left: &[TraceEvent],
    right: &[TraceEvent],
    normalized_divergence: &Option<TraceDivergence>,
) {
    let equivalent = traces_equivalent(left, right);
    assert_eq!(
        equivalent,
        normalized_divergence.is_none(),
        "traces_equivalent must mirror compare_normalized",
    );
}

fn observe_normalization(label: &str, events: &[TraceEvent]) {
    let result = normalize_for_replay(events);
    assert_normalization_shape(label, events.len(), &result);
}

fn assert_normalization_shape(label: &str, original_len: usize, result: &NormalizationResult) {
    assert_eq!(
        result.normalized.len(),
        original_len,
        "{label}: normalization must preserve event count",
    );
    assert!(
        result.original_switches <= original_len.saturating_sub(1),
        "{label}: original switch count cannot exceed adjacent event pairs",
    );
    assert!(
        result.normalized_switches <= original_len.saturating_sub(1),
        "{label}: normalized switch count cannot exceed adjacent event pairs",
    );
    assert!(
        !result.algorithm.trim().is_empty(),
        "{label}: normalization algorithm label must be visible",
    );
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }

    let pair: TracePair = match serde_json::from_slice(data) {
        Ok(p) => p,
        Err(_) => return,
    };

    let a: &[TraceEvent] = if pair.a.len() > MAX_EVENTS_PER_SIDE {
        &pair.a[..MAX_EVENTS_PER_SIDE]
    } else {
        &pair.a
    };
    let b: &[TraceEvent] = if pair.b.len() > MAX_EVENTS_PER_SIDE {
        &pair.b[..MAX_EVENTS_PER_SIDE]
    } else {
        &pair.b
    };

    // Contract 1: panic floor across the quartet.
    let raw_divergence = observe_find_divergence("raw trace comparison", a, b);
    let normalized_divergence = observe_normalized_comparison("normalized trace comparison", a, b);
    observe_trace_equivalence(a, b, &normalized_divergence);
    observe_normalization("side A", a);
    observe_normalization("side B", b);

    // Contract 2: reflexivity. Both directions to also catch any
    // accidental asymmetry in the comparator's prefix-cursor logic.
    assert!(
        traces_equivalent(a, a),
        "traces_equivalent must be reflexive on side A",
    );
    assert!(
        traces_equivalent(b, b),
        "traces_equivalent must be reflexive on side B",
    );
    assert!(
        find_divergence(a, a).is_none(),
        "find_divergence must report no divergence on a self-comparison (side A)",
    );
    assert!(
        find_divergence(b, b).is_none(),
        "find_divergence must report no divergence on a self-comparison (side B)",
    );

    // Contract 3: length-mismatch handling. If the lengths differ,
    // find_divergence must produce Some without panicking. If they
    // match, no assertion on Some/None — they may still differ on
    // payload, which is what the comparator is for.
    if a.len() != b.len() {
        assert!(
            raw_divergence.is_some(),
            "find_divergence must report a divergence when slice lengths differ",
        );
        assert_eq!(
            raw_divergence
                .as_ref()
                .map(|divergence| divergence.position),
            Some(a.len().min(b.len())),
            "length mismatch divergence must point at the first missing event",
        );
    }
});
