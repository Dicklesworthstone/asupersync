//! Conformance harness for `asupersync::trace::event_structure`.
//!
//! `event_structure` turns a single interleaving trace into a `TracePoset`
//! (the dependency DAG that `trace::boundary` consumes) and an
//! `EventStructure`. Both are induced by the independence relation: for every
//! `i < j` there is a causal edge `i → j` iff the two events are *dependent*.
//!
//! That definition forces a precise contract, verified here on a swept corpus
//! of deterministically generated traces:
//!
//! - **Edge ⇔ dependence**: `has_edge(i, j)` holds exactly when `i < j` and
//!   `!independent(e_i, e_j)`.
//! - **Forward-only DAG**: every edge points from a lower to a higher index;
//!   there are no self-loops and no backward edges, so the poset is acyclic.
//! - **`preds`/`succs` duality**: `j ∈ succs(i) ⇔ i ∈ preds(j) ⇔ has_edge(i,j)`,
//!   and both adjacency lists are strictly ascending (required for the
//!   `binary_search` inside `has_edge`).
//! - **`topo_sort` is total and canonical**: it always returns `Some`, and
//!   because every edge runs low→high the deterministic lowest-index-first
//!   sort is *exactly* the identity permutation `[0, 1, …, n-1]`.
//! - **Prefix stability** (metamorphic): the poset of a trace prefix is the
//!   induced sub-poset of the full trace — appending events never rewrites
//!   edges among earlier events.
//! - **`owner` conformance**: `poset.owner(i)` equals `OwnerKey::for_event`.
//! - **Cross-consistency**: `EventStructure` causality edges coincide with
//!   `TracePoset` edges; conflicts are always empty for single-trace
//!   derivation; `to_hda` yields one 0-cell per event.
//!
//! Traces come from a deterministic in-test SplitMix64 generator over a small
//! id space (so dependent pairs occur frequently); a non-vacuity guard
//! asserts the corpus actually produces edges. No `proptest` dependency.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_lines)]

use asupersync::trace::event_structure::{EventStructure, OwnerKey, TracePoset};
use asupersync::trace::independence::independent;
use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::{CancelReason, ObligationId, RegionId, TaskId, Time};

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
    fn below(&mut self, n: u32) -> u32 {
        (self.next_u64() % u64::from(n)) as u32
    }
}

fn tid(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}
fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}
fn oid(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}

/// Build one random trace event with the given sequence number.
///
/// Ids are drawn from a deliberately tiny space (tasks/regions/timers/tokens
/// each in `1..=3`) so that dependent pairs — and therefore causal edges —
/// occur frequently across a random trace.
fn gen_event(rng: &mut Rng, seq: u64) -> TraceEvent {
    let t = Time::from_nanos(seq * 10);
    let task = tid(1 + rng.below(3));
    let region = rid(1 + rng.below(3));
    match rng.below(16) {
        0 => TraceEvent::spawn(seq, t, task, region),
        1 => TraceEvent::schedule(seq, t, task, region),
        2 => TraceEvent::poll(seq, t, task, region),
        3 => TraceEvent::complete(seq, t, task, region),
        4 => TraceEvent::wake(seq, t, task, region),
        5 => TraceEvent::cancel_request(seq, t, task, region, CancelReason::user("g")),
        6 => TraceEvent::region_created(seq, t, region, None),
        7 => TraceEvent::region_cancelled(seq, t, region, CancelReason::user("h")),
        8 => TraceEvent::obligation_reserve(
            seq,
            t,
            oid(1 + rng.below(3)),
            task,
            region,
            asupersync::record::ObligationKind::SendPermit,
        ),
        9 => TraceEvent::time_advance(seq, t, Time::ZERO, Time::from_nanos(seq * 100)),
        10 => TraceEvent::timer_scheduled(seq, t, u64::from(1 + rng.below(3)), t),
        11 => TraceEvent::timer_fired(seq, t, u64::from(1 + rng.below(3))),
        12 => TraceEvent::io_ready(seq, t, u64::from(1 + rng.below(3)), 0x01),
        13 => TraceEvent::rng_value(seq, t, rng.next_u64()),
        14 => TraceEvent::checkpoint(seq, t, seq, 2, 1),
        _ => TraceEvent::user_trace(seq, t, "annotation"),
    }
}

/// A random trace of `len` events with strictly increasing sequence numbers.
fn gen_trace(rng: &mut Rng, len: usize) -> Vec<TraceEvent> {
    (0..len).map(|i| gen_event(rng, i as u64 + 1)).collect()
}

const TRACE_LENS: &[usize] = &[0, 1, 2, 3, 5, 8, 13, 21, 34];

// ---------------------------------------------------------------------------
// TracePoset — the edge ⇔ dependence contract
// ---------------------------------------------------------------------------

#[test]
fn edges_hold_exactly_when_events_are_dependent() {
    let mut edges_seen = 0usize;
    for &len in TRACE_LENS {
        for seed in 0..24u64 {
            let mut rng = Rng::new(seed ^ 0xED9E ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let poset = TracePoset::from_trace(&trace);

            assert_eq!(poset.len(), len);
            assert_eq!(poset.is_empty(), len == 0);

            for i in 0..len {
                for j in 0..len {
                    let edge = poset.has_edge(i, j);
                    let expected = i < j && !independent(&trace[i], &trace[j]);
                    assert_eq!(
                        edge, expected,
                        "edge {i}->{j} mismatch (len={len}, seed={seed})"
                    );
                    if edge {
                        edges_seen += 1;
                    }
                }
            }
        }
    }
    // Non-vacuity: the dependence-driven branch must actually be exercised.
    assert!(
        edges_seen > 200,
        "random corpus produced too few causal edges ({edges_seen})"
    );
}

#[test]
fn poset_has_no_self_loops_or_backward_edges() {
    for &len in TRACE_LENS {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0xF00D ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let poset = TracePoset::from_trace(&trace);
            for i in 0..len {
                assert!(!poset.has_edge(i, i), "self-loop at {i}");
                for j in 0..=i {
                    assert!(!poset.has_edge(i, j), "backward edge {i}->{j}");
                }
                // Every successor of `i` has a strictly larger index.
                for &s in poset.succs(i) {
                    assert!(s > i, "succ {s} of {i} is not forward");
                }
                // Every predecessor of `i` has a strictly smaller index.
                for &p in poset.preds(i) {
                    assert!(p < i, "pred {p} of {i} is not backward");
                }
            }
        }
    }
}

#[test]
fn preds_and_succs_are_dual_and_sorted() {
    for &len in TRACE_LENS {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0xAB12 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let poset = TracePoset::from_trace(&trace);

            for i in 0..len {
                // succs strictly ascending — required for has_edge's binary_search.
                let succs = poset.succs(i);
                for w in succs.windows(2) {
                    assert!(w[0] < w[1], "succs({i}) not strictly ascending: {succs:?}");
                }
                // preds strictly ascending.
                let preds = poset.preds(i);
                for w in preds.windows(2) {
                    assert!(w[0] < w[1], "preds({i}) not strictly ascending: {preds:?}");
                }
                // Duality: j in succs(i) <=> has_edge(i,j) <=> i in preds(j).
                for j in 0..len {
                    let in_succ = succs.contains(&j);
                    let in_pred = poset.preds(j).contains(&i);
                    let edge = poset.has_edge(i, j);
                    assert_eq!(in_succ, edge, "succs/has_edge disagree {i}->{j}");
                    assert_eq!(in_pred, edge, "preds/has_edge disagree {i}->{j}");
                }
            }
        }
    }
}

#[test]
fn topo_sort_is_total_and_the_identity_permutation() {
    // Every edge runs low→high, so the poset is acyclic and the deterministic
    // lowest-index-first topological sort is exactly [0, 1, …, n-1].
    for &len in TRACE_LENS {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0x7070 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let poset = TracePoset::from_trace(&trace);

            let order = poset
                .topo_sort()
                .expect("single-trace poset is always acyclic");
            let identity: Vec<usize> = (0..len).collect();
            assert_eq!(
                order, identity,
                "topo_sort != identity (len={len}, seed={seed})"
            );
        }
    }
}

#[test]
fn topo_sort_respects_every_edge() {
    // Independent of the identity result above: assert the defining property
    // directly — for every edge i→j, i precedes j in the topological order.
    for &len in TRACE_LENS {
        for seed in 0..12u64 {
            let mut rng = Rng::new(seed ^ 0x9111 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let poset = TracePoset::from_trace(&trace);
            let order = poset.topo_sort().expect("acyclic");

            let mut position = vec![0usize; len];
            for (pos, &node) in order.iter().enumerate() {
                position[node] = pos;
            }
            for i in 0..len {
                for &j in poset.succs(i) {
                    assert!(
                        position[i] < position[j],
                        "topo order violates edge {i}->{j}"
                    );
                }
            }
        }
    }
}

#[test]
fn from_trace_is_deterministic() {
    for &len in TRACE_LENS {
        for seed in 0..12u64 {
            let mut rng = Rng::new(seed ^ 0xDDDD ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let a = TracePoset::from_trace(&trace);
            let b = TracePoset::from_trace(&trace);
            for i in 0..len {
                assert_eq!(a.succs(i), b.succs(i), "non-deterministic succs at {i}");
                assert_eq!(a.preds(i), b.preds(i), "non-deterministic preds at {i}");
                assert_eq!(a.owner(i), b.owner(i), "non-deterministic owner at {i}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Metamorphic relation: prefix stability.
// ---------------------------------------------------------------------------

#[test]
fn poset_of_a_prefix_is_the_induced_sub_poset() {
    // `causality_pairs` only inspects pairs (i, j) with i < j < len, so the
    // poset restricted to nodes 0..k is identical whether built from the
    // prefix trace[0..k] or the full trace. Appending events never rewrites
    // edges among earlier ones.
    for &len in TRACE_LENS {
        if len < 2 {
            continue;
        }
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0x5151 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let full = TracePoset::from_trace(&trace);

            for k in 1..=len {
                let prefix = TracePoset::from_trace(&trace[..k]);
                assert_eq!(prefix.len(), k);
                for i in 0..k {
                    for j in 0..k {
                        assert_eq!(
                            prefix.has_edge(i, j),
                            full.has_edge(i, j),
                            "prefix[{k}] edge {i}->{j} differs from full poset"
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// owner — conformance with OwnerKey::for_event
// ---------------------------------------------------------------------------

#[test]
fn poset_owner_matches_owner_key_for_event() {
    for &len in TRACE_LENS {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0x0E0E ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let poset = TracePoset::from_trace(&trace);
            for i in 0..len {
                assert_eq!(
                    poset.owner(i),
                    OwnerKey::for_event(&trace[i]),
                    "owner({i}) diverged from OwnerKey::for_event"
                );
            }
        }
    }
}

#[test]
fn owner_key_for_event_classifies_each_data_variant() {
    let t = Time::ZERO;
    // Task-bearing events → Task owner.
    assert_eq!(
        OwnerKey::for_event(&TraceEvent::spawn(1, t, tid(2), rid(1))),
        OwnerKey::Task(tid(2))
    );
    // Region events → Region owner.
    assert_eq!(
        OwnerKey::for_event(&TraceEvent::region_created(2, t, rid(3), None)),
        OwnerKey::Region(rid(3))
    );
    // Timer events → Timer owner.
    assert_eq!(
        OwnerKey::for_event(&TraceEvent::timer_fired(3, t, 9)),
        OwnerKey::Timer(9)
    );
    // I/O events → IoToken owner.
    assert_eq!(
        OwnerKey::for_event(&TraceEvent::io_ready(4, t, 7, 0x01)),
        OwnerKey::IoToken(7)
    );
    // Chaos with a task → Task owner.
    let chaos_with_task = TraceEvent::new(
        5,
        t,
        TraceEventKind::ChaosInjection,
        TraceData::Chaos {
            kind: "k".to_string(),
            task: Some(tid(1)),
            detail: "d".to_string(),
        },
    );
    assert_eq!(
        OwnerKey::for_event(&chaos_with_task),
        OwnerKey::Task(tid(1))
    );
    // Events without a stable owner id → Kind fallback.
    assert_eq!(
        OwnerKey::for_event(&TraceEvent::user_trace(6, t, "x")),
        OwnerKey::Kind(TraceEventKind::UserTrace)
    );
    assert_eq!(
        OwnerKey::for_event(&TraceEvent::rng_value(7, t, 1)),
        OwnerKey::Kind(TraceEventKind::RngValue)
    );
}

#[test]
fn owner_key_for_event_is_deterministic() {
    for &len in TRACE_LENS {
        let mut rng = Rng::new(0xC0C0 ^ (len as u64));
        let trace = gen_trace(&mut rng, len);
        for e in &trace {
            assert_eq!(
                OwnerKey::for_event(e),
                OwnerKey::for_event(e),
                "OwnerKey::for_event non-deterministic for {:?}",
                e.kind
            );
        }
    }
}

// ---------------------------------------------------------------------------
// EventStructure — and cross-consistency with TracePoset
// ---------------------------------------------------------------------------

#[test]
fn event_structure_preserves_events_in_order() {
    for &len in TRACE_LENS {
        for seed in 0..12u64 {
            let mut rng = Rng::new(seed ^ 0xE5E5 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let es = EventStructure::from_trace(&trace);

            assert_eq!(es.events().len(), len);
            for (idx, event) in es.events().iter().enumerate() {
                assert_eq!(event.id.index(), idx, "event id index mismatch");
                assert_eq!(
                    event.trace.seq, trace[idx].seq,
                    "event {idx} lost its source trace seq"
                );
                assert_eq!(event.label(), trace[idx].kind, "event {idx} label mismatch");
            }
        }
    }
}

#[test]
fn event_structure_causality_matches_trace_poset_edges() {
    for &len in TRACE_LENS {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0xCA5E ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let es = EventStructure::from_trace(&trace);
            let poset = TracePoset::from_trace(&trace);

            // Every causality edge is a forward, dependent pair and a poset edge.
            for &(from, to) in es.causality() {
                let (i, j) = (from.index(), to.index());
                assert!(i < j, "causality edge {i}->{j} not forward");
                assert!(
                    poset.has_edge(i, j),
                    "causality edge {i}->{j} absent from poset"
                );
            }
            // Every poset edge appears exactly once in the causality list.
            let mut poset_edge_count = 0usize;
            for i in 0..len {
                poset_edge_count += poset.succs(i).len();
            }
            assert_eq!(
                es.causality().len(),
                poset_edge_count,
                "causality edge count != poset edge count (len={len}, seed={seed})"
            );
        }
    }
}

#[test]
fn event_structure_conflicts_are_always_empty_for_single_trace() {
    // Conflicts need branching observations; a single interleaving cannot
    // derive them, so the conflict set must always be empty.
    for &len in TRACE_LENS {
        for seed in 0..8u64 {
            let mut rng = Rng::new(seed ^ 0x9F9F ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let es = EventStructure::from_trace(&trace);
            assert!(
                es.conflicts().is_empty(),
                "single-trace EventStructure must have no conflicts"
            );
        }
    }
}

#[test]
fn to_hda_produces_one_zero_cell_per_event() {
    for &len in TRACE_LENS {
        for seed in 0..8u64 {
            let mut rng = Rng::new(seed ^ 0x4DA0 ^ (len as u64) << 16);
            let trace = gen_trace(&mut rng, len);
            let es = EventStructure::from_trace(&trace);
            let hda = es.to_hda();

            assert_eq!(hda.cells.len(), len, "HDA cell count != event count");
            for (idx, cell) in hda.cells.iter().enumerate() {
                assert_eq!(
                    cell.dimension, 0,
                    "single-trace HDA cell must be 0-dimensional"
                );
                assert_eq!(cell.events.len(), 1, "0-cell should span exactly one event");
                assert_eq!(cell.events[0].index(), idx, "0-cell event index mismatch");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Degenerate inputs
// ---------------------------------------------------------------------------

#[test]
fn empty_trace_yields_empty_structures() {
    let poset = TracePoset::from_trace(&[]);
    assert_eq!(poset.len(), 0);
    assert!(poset.is_empty());
    assert_eq!(poset.topo_sort(), Some(Vec::new()));

    let es = EventStructure::from_trace(&[]);
    assert!(es.events().is_empty());
    assert!(es.causality().is_empty());
    assert!(es.conflicts().is_empty());
    assert!(es.to_hda().cells.is_empty());
}

#[test]
fn single_event_trace_has_no_edges() {
    let trace = vec![TraceEvent::user_trace(1, Time::ZERO, "solo")];
    let poset = TracePoset::from_trace(&trace);
    assert_eq!(poset.len(), 1);
    assert!(poset.succs(0).is_empty());
    assert!(poset.preds(0).is_empty());
    assert!(!poset.has_edge(0, 0));
    assert_eq!(poset.topo_sort(), Some(vec![0]));
}
