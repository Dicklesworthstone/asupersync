//! Trace canonicalization for DPOR equivalence tracking.
//!
//! Given a trace (sequence of events), canonicalization produces a deterministic
//! representative for the trace's Mazurkiewicz equivalence class. Two traces
//! that differ only in the order of independent events produce the same
//! canonical form.
//!
//! # Foata Normal Form
//!
//! The canonical form is the **Foata normal form**: a sequence of layers where:
//! - Layer 0: events with no dependent predecessors
//! - Layer k: events whose nearest dependent predecessor is in layer k-1
//!
//! Within each layer, events are sorted by a deterministic comparison key
//! derived from the event kind and data. This ensures that equivalent traces
//! produce identical canonical forms.
//!
//! # Why Foata?
//!
//! Foata normal form is a natural choice because:
//! 1. It is well-studied in combinatorics on words (Cartier–Foata, 1969)
//! 2. It has a simple O(n²) construction algorithm
//! 3. The layered structure is useful for parallelism analysis (layer depth
//!    = critical path length)
//! 4. It enables efficient fingerprinting for DPOR equivalence tracking
//!
//! # Complexity
//!
//! - Time: O(n²) where n is the trace length (pairwise independence checks)
//! - Space: O(n)

use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
use crate::trace::independence::independent;
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// A trace in Foata normal form: layers of mutually independent events.
#[derive(Debug)]
pub struct FoataTrace {
    /// Layers of mutually independent events, sorted deterministically.
    layers: Vec<Vec<TraceEvent>>,
}

impl FoataTrace {
    /// Returns the number of layers (the critical path length).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.layers.len()
    }

    /// Returns the total number of events across all layers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.layers.iter().map(|l| l.len()).sum()
    }

    /// Returns `true` if the trace contains no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Returns a slice of all layers.
    #[must_use]
    pub fn layers(&self) -> &[Vec<TraceEvent>] {
        &self.layers
    }

    /// Flatten back into a linear sequence (canonical total order).
    #[must_use]
    pub fn flatten(&self) -> Vec<TraceEvent> {
        self.layers.iter().flat_map(|l| l.iter().cloned()).collect()
    }

    /// Compute a 64-bit fingerprint of this canonical form.
    ///
    /// Two `FoataTrace` values representing the same equivalence class will
    /// produce identical fingerprints.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        for (layer_idx, layer) in self.layers.iter().enumerate() {
            layer_idx.hash(&mut hasher);
            layer.len().hash(&mut hasher);
            for event in layer {
                event_hash_key(event).hash(&mut hasher);
            }
        }
        hasher.finish()
    }
}

/// Compute the Foata normal form of a trace.
///
/// Events are grouped into layers based on the happens-before order induced
/// by the independence relation. Within each layer, events are sorted by a
/// deterministic comparison key.
///
/// # Example
///
/// ```ignore
/// let trace = vec![spawn(1, t1, r1), spawn(2, t2, r2), complete(3, t1, r1)];
/// let foata = canonicalize(&trace);
/// // Layer 0: [spawn(t1, r1), spawn(t2, r2)]  — independent, sorted by key
/// // Layer 1: [complete(t1, r1)]               — depends on spawn(t1)
/// assert_eq!(foata.depth(), 2);
/// ```
#[must_use]
pub fn canonicalize(events: &[TraceEvent]) -> FoataTrace {
    let n = events.len();
    if n == 0 {
        return FoataTrace { layers: vec![] };
    }

    // Step 1: Compute layer assignment for each event.
    // layer[j] = 1 + max(layer[i]) for all i < j where events[i] and events[j]
    // are dependent.
    let mut layer_of = vec![0usize; n];
    let mut max_layer = 0usize;

    for j in 1..n {
        for i in 0..j {
            if !independent(&events[i], &events[j]) {
                layer_of[j] = layer_of[j].max(layer_of[i] + 1);
            }
        }
        max_layer = max_layer.max(layer_of[j]);
    }

    // Step 2: Group events by layer.
    let mut layers: Vec<Vec<TraceEvent>> = vec![vec![]; max_layer + 1];
    for (idx, event) in events.iter().enumerate() {
        layers[layer_of[idx]].push(event.clone());
    }

    // Step 3: Sort within each layer deterministically.
    for layer in &mut layers {
        layer.sort_by(event_cmp);
    }

    FoataTrace { layers }
}

/// Compute a 64-bit fingerprint for a trace's equivalence class.
///
/// Semantically equivalent to `canonicalize(events).fingerprint()` but avoids
/// cloning events (only hashes in place).
#[must_use]
pub fn trace_fingerprint(events: &[TraceEvent]) -> u64 {
    let n = events.len();
    if n == 0 {
        return 0;
    }

    // Layer assignment (same algorithm as canonicalize).
    let mut layer_of = vec![0usize; n];
    let mut max_layer = 0usize;

    for j in 1..n {
        for i in 0..j {
            if !independent(&events[i], &events[j]) {
                layer_of[j] = layer_of[j].max(layer_of[i] + 1);
            }
        }
        max_layer = max_layer.max(layer_of[j]);
    }

    // Group indices by layer, sort within layer, hash.
    let mut layer_indices: Vec<Vec<usize>> = vec![vec![]; max_layer + 1];
    for (idx, &layer) in layer_of.iter().enumerate() {
        layer_indices[layer].push(idx);
    }

    let mut hasher = DefaultHasher::new();
    for (layer_idx, indices) in layer_indices.iter_mut().enumerate() {
        indices.sort_by(|&a, &b| event_cmp(&events[a], &events[b]));
        layer_idx.hash(&mut hasher);
        indices.len().hash(&mut hasher);
        for &idx in indices.iter() {
            event_hash_key(&events[idx]).hash(&mut hasher);
        }
    }
    hasher.finish()
}

// === Internal: deterministic event ordering ===

/// Stable discriminant for `TraceEventKind`.
///
/// These values are fixed for fingerprint stability across versions.
fn kind_discriminant(kind: &TraceEventKind) -> u8 {
    use TraceEventKind::*;
    match kind {
        Spawn => 0,
        Schedule => 1,
        Yield => 2,
        Wake => 3,
        Poll => 4,
        Complete => 5,
        CancelRequest => 6,
        CancelAck => 7,
        RegionCloseBegin => 8,
        RegionCloseComplete => 9,
        RegionCreated => 10,
        RegionCancelled => 11,
        ObligationReserve => 12,
        ObligationCommit => 13,
        ObligationAbort => 14,
        ObligationLeak => 15,
        TimeAdvance => 16,
        TimerScheduled => 17,
        TimerFired => 18,
        TimerCancelled => 19,
        IoRequested => 20,
        IoReady => 21,
        IoResult => 22,
        IoError => 23,
        RngSeed => 24,
        RngValue => 25,
        Checkpoint => 26,
        FuturelockDetected => 27,
        ChaosInjection => 28,
        UserTrace => 29,
    }
}

/// Pack an ArenaIndex into a u64 for deterministic ordering.
fn pack_arena(idx: crate::util::ArenaIndex) -> u64 {
    (idx.index() as u64) << 32 | idx.generation() as u64
}

/// Compute a sort key for deterministic intra-layer ordering.
///
/// The key is a 4-tuple of (kind, primary, secondary, tertiary) where each
/// component is a fixed-width integer. This ensures total, deterministic
/// ordering within a Foata layer.
fn event_sort_key(event: &TraceEvent) -> (u8, u64, u64, u64) {
    let k = kind_discriminant(&event.kind);
    match &event.data {
        TraceData::Task { task, region } => (k, pack_arena(task.0), pack_arena(region.0), 0),
        TraceData::Cancel { task, region, .. } => (k, pack_arena(task.0), pack_arena(region.0), 0),
        TraceData::Region { region, parent } => {
            (k, pack_arena(region.0), parent.map_or(0, |p| pack_arena(p.0)), 0)
        }
        TraceData::RegionCancel { region, .. } => (k, pack_arena(region.0), 0, 0),
        TraceData::Obligation {
            obligation,
            task,
            region,
            ..
        } => (
            k,
            pack_arena(obligation.0),
            pack_arena(task.0),
            pack_arena(region.0),
        ),
        TraceData::Time { old, new } => (k, old.as_nanos(), new.as_nanos(), 0),
        TraceData::Timer { timer_id, .. } => (k, *timer_id, 0, 0),
        TraceData::IoRequested { token, .. } => (k, *token, 0, 0),
        TraceData::IoReady { token, .. } => (k, *token, 0, 0),
        TraceData::IoResult { token, bytes } => (k, *token, *bytes as u64, 0),
        TraceData::IoError { token, kind } => (k, *token, *kind as u64, 0),
        TraceData::RngSeed { seed } => (k, *seed, 0, 0),
        TraceData::RngValue { value } => (k, *value, 0, 0),
        TraceData::Checkpoint {
            sequence,
            active_tasks,
            active_regions,
        } => (k, *sequence, *active_tasks as u64, *active_regions as u64),
        TraceData::Futurelock { task, region, .. } => {
            (k, pack_arena(task.0), pack_arena(region.0), 0)
        }
        TraceData::Chaos { task, .. } => {
            let task_key = task.map_or(0, |t| pack_arena(t.0));
            (k, task_key, 0, 0)
        }
        TraceData::Message(msg) => {
            let mut h = DefaultHasher::new();
            msg.hash(&mut h);
            (k, h.finish(), 0, 0)
        }
        TraceData::None => (k, 0, 0, 0),
    }
}

/// Deterministic comparison of two trace events.
fn event_cmp(a: &TraceEvent, b: &TraceEvent) -> Ordering {
    event_sort_key(a).cmp(&event_sort_key(b))
}

/// Hash key for fingerprinting. Must agree with `event_sort_key` ordering:
/// events with the same sort key produce the same hash key.
fn event_hash_key(event: &TraceEvent) -> (u8, u64, u64, u64) {
    event_sort_key(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::ObligationKind;
    use crate::types::{ObligationId, RegionId, TaskId, Time};

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    fn oid(n: u32) -> ObligationId {
        ObligationId::new_for_test(n, 0)
    }

    // === Basic structure ===

    #[test]
    fn empty_trace() {
        let foata = canonicalize(&[]);
        assert!(foata.is_empty());
        assert_eq!(foata.depth(), 0);
        assert_eq!(foata.len(), 0);
    }

    #[test]
    fn single_event() {
        let events = [TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
        let foata = canonicalize(&events);
        assert_eq!(foata.depth(), 1);
        assert_eq!(foata.len(), 1);
    }

    #[test]
    fn all_independent_events_in_one_layer() {
        // Spawns in different regions with different tasks are independent.
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3)),
        ];
        let foata = canonicalize(&events);
        assert_eq!(foata.depth(), 1);
        assert_eq!(foata.layers()[0].len(), 3);
    }

    #[test]
    fn chain_of_dependent_events() {
        // Same task: spawn -> poll -> complete forms a chain.
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
        ];
        let foata = canonicalize(&events);
        assert_eq!(foata.depth(), 3);
        assert_eq!(foata.layers()[0].len(), 1);
        assert_eq!(foata.layers()[1].len(), 1);
        assert_eq!(foata.layers()[2].len(), 1);
    }

    #[test]
    fn diamond_dependency() {
        // T1 and T2 are independent, but both depend on region creation
        // and both must complete before region close.
        //
        //   region_create(R1)
        //     /          \
        //  spawn(T1,R1) spawn(T2,R1)    -- independent (both read R1)
        //     \          /
        //  complete(T1) complete(T2)     -- independent (different tasks)
        //
        // But region_create writes R1 and spawns read R1 -> dependent.
        // So: layer 0 = [region_create], layer 1 = [spawn T1, spawn T2],
        //     layer 2 = [complete T1, complete T2]
        let events = [
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
            TraceEvent::complete(4, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(5, Time::ZERO, tid(2), rid(1)),
        ];
        let foata = canonicalize(&events);
        assert_eq!(foata.depth(), 3);
        assert_eq!(foata.layers()[0].len(), 1); // region_create
        assert_eq!(foata.layers()[1].len(), 2); // spawn T1, spawn T2
        assert_eq!(foata.layers()[2].len(), 2); // complete T1, complete T2
    }

    // === Equivalence: swapping independent events produces same canonical form ===

    #[test]
    fn swapped_independent_events_same_fingerprint() {
        let trace_a = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];
        let trace_b = [
            TraceEvent::spawn(1, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        ];
        let fp_a = trace_fingerprint(&trace_a);
        let fp_b = trace_fingerprint(&trace_b);
        assert_eq!(fp_a, fp_b);
    }

    #[test]
    fn swapped_independent_events_same_canonical_form() {
        let trace_a = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];
        let trace_b = [
            TraceEvent::spawn(1, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        ];
        let foata_a = canonicalize(&trace_a);
        let foata_b = canonicalize(&trace_b);
        assert_eq!(foata_a.depth(), foata_b.depth());
        assert_eq!(foata_a.fingerprint(), foata_b.fingerprint());
    }

    #[test]
    fn different_dependent_orders_different_fingerprints() {
        // Same-task events in different orders are different traces (not equivalent).
        let trace_a = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let trace_b = [
            TraceEvent::complete(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        ];
        let fp_a = trace_fingerprint(&trace_a);
        let fp_b = trace_fingerprint(&trace_b);
        // These are genuinely different traces (different causal structure).
        assert_ne!(fp_a, fp_b);
    }

    // === Complex equivalence: three independent events in any of 6 orders ===

    #[test]
    fn three_independent_events_all_permutations_same_fingerprint() {
        let e1 = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let e2 = TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2));
        let e3 = TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3));

        let permutations: Vec<Vec<TraceEvent>> = vec![
            vec![e1.clone(), e2.clone(), e3.clone()],
            vec![e1.clone(), e3.clone(), e2.clone()],
            vec![e2.clone(), e1.clone(), e3.clone()],
            vec![e2.clone(), e3.clone(), e1.clone()],
            vec![e3.clone(), e1.clone(), e2.clone()],
            vec![e3.clone(), e2.clone(), e1.clone()],
        ];

        let fp0 = trace_fingerprint(&permutations[0]);
        for (i, perm) in permutations.iter().enumerate() {
            let fp = trace_fingerprint(perm);
            assert_eq!(fp, fp0, "Permutation {i} has different fingerprint");
        }
    }

    // === Mixed independent and dependent events ===

    #[test]
    fn mixed_trace_canonical_form() {
        // T1 in R1 and T2 in R2 are independent.
        // Timer on same timer_id is independent of tasks.
        // But time_advance conflicts with timer events.
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::time_advance(2, Time::ZERO, Time::ZERO, Time::from_nanos(100)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(2)),
            TraceEvent::timer_fired(4, Time::ZERO, 1),
        ];
        let foata = canonicalize(&events);
        // spawn(T1) and spawn(T2) are independent -> same layer
        // time_advance is independent of spawns -> same layer as spawns
        // timer_fired depends on time_advance -> layer 1
        assert_eq!(foata.depth(), 2);
        assert_eq!(foata.layers()[0].len(), 3); // spawn T1, time_advance, spawn T2
        assert_eq!(foata.layers()[1].len(), 1); // timer_fired
    }

    // === Deterministic intra-layer ordering ===

    #[test]
    fn intra_layer_ordering_is_deterministic() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(3), rid(3)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(2)),
        ];
        let foata = canonicalize(&events);
        assert_eq!(foata.depth(), 1);

        // Should be sorted by (kind=Spawn, task_id).
        // tid(1) < tid(2) < tid(3) by ArenaIndex ordering.
        let layer = &foata.layers()[0];
        let keys: Vec<_> = layer.iter().map(event_sort_key).collect();
        assert!(keys.windows(2).all(|w| w[0] <= w[1]));
    }

    // === Fingerprint consistency ===

    #[test]
    fn fingerprint_matches_foata_fingerprint() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
        ];
        let foata = canonicalize(&events);
        let direct = trace_fingerprint(&events);
        assert_eq!(foata.fingerprint(), direct);
    }

    #[test]
    fn empty_trace_fingerprint_is_zero() {
        assert_eq!(trace_fingerprint(&[]), 0);
    }

    // === Layer depth = critical path ===

    #[test]
    fn depth_reflects_critical_path() {
        // Two parallel chains of length 2:
        //   spawn(T1) -> complete(T1)   (depth 2)
        //   spawn(T2) -> complete(T2)   (depth 2)
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)),
        ];
        let foata = canonicalize(&events);
        assert_eq!(foata.depth(), 2);
        assert_eq!(foata.layers()[0].len(), 2); // both spawns
        assert_eq!(foata.layers()[1].len(), 2); // both completes
    }

    // === Flatten round-trip ===

    #[test]
    fn flatten_preserves_event_count() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
        ];
        let foata = canonicalize(&events);
        assert_eq!(foata.flatten().len(), events.len());
    }

    // === Obligation events ===

    #[test]
    fn independent_obligations_same_layer() {
        let events = [
            TraceEvent::obligation_reserve(
                1,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
            ),
            TraceEvent::obligation_reserve(
                2,
                Time::ZERO,
                oid(2),
                tid(2),
                rid(2),
                ObligationKind::Ack,
            ),
        ];
        let foata = canonicalize(&events);
        assert_eq!(foata.depth(), 1);
    }

    #[test]
    fn same_obligation_events_form_chain() {
        let events = [
            TraceEvent::obligation_reserve(
                1,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::Lease,
            ),
            TraceEvent::obligation_commit(
                2,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::Lease,
                5000,
            ),
        ];
        let foata = canonicalize(&events);
        assert_eq!(foata.depth(), 2);
    }
}
