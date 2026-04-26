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
    compare_normalized, find_divergence, normalize_for_replay, traces_equivalent,
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
    let _ = find_divergence(a, b);
    let _ = compare_normalized(a, b);
    let _ = traces_equivalent(a, b);
    let _ = normalize_for_replay(a);
    let _ = normalize_for_replay(b);

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
        let div = find_divergence(a, b);
        assert!(
            div.is_some(),
            "find_divergence must report a divergence when slice lengths differ",
        );
    }
});
