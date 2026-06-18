//! RaptorQ offline kernel-tuner conformance.
//!
//! Bead bd-3uox5 (RAPTORQ-RFC6330). Pins the production offline-tuning surface
//! in `raptorq::offline_tuner`, which had ZERO integration coverage. The
//! `OfflineTuner` pipeline is a deterministic, ambient-free projection of a
//! fixed tuning space onto a profile pack:
//!
//!   generate_candidates -> run_systematic_benchmarks
//!                       -> select_optimal_candidate -> emit_profile_pack
//!
//! The benchmark *measurements* are timing-dependent (real GF(256) ops), so we
//! deliberately assert only the structural / cross-function invariants that are
//! oracle-free and hold for ANY timing outcome:
//!
//!   * `generate_candidates()` is the full Cartesian product of the tuning
//!     space (count == product of distinct field cardinalities), every id is
//!     unique and canonically formatted, and it is deterministic;
//!   * config accessors round-trip and the per-pair iteration count is clamped
//!     to at least 1;
//!   * `select_optimal_candidate()` fails closed with `NoBenchmarkResults`
//!     before any benchmark runs, and after benchmarking returns a candidate
//!     that is a member of the generated set, deterministically (re-selecting
//!     on the same populated tuner yields the identical candidate);
//!   * `emit_profile_pack(selected)` projects a consistent pack: the selected
//!     id round-trips, the rejected id list is the sorted/deduped complement of
//!     the selected id within the candidate set, the architecture -> profile-pack
//!     id mapping is exact, the canonical schema/corpus/replay strings are
//!     pinned, the addmul auto-window is ordered, and the mul auto-window is
//!     ordered EXCEPT for `FusionShape::Split`, which intentionally disables it
//!     with the `(usize::MAX, 0)` sentinel.
//!
//! Repro: `cargo test -p asupersync --test raptorq_offline_tuner_conformance`

use asupersync::raptorq::gf256::{Gf256ArchitectureClass, Gf256ProfilePackId};
use asupersync::raptorq::offline_tuner::{
    DEFAULT_BENCHMARK_ITERATIONS, FusionShape, OfflineTuner, OptimizationCriteria, TuningError,
};
use asupersync::types::Time;
use std::collections::{BTreeSet, HashSet};

const ALL_ARCHES: [Gf256ArchitectureClass; 3] = [
    Gf256ArchitectureClass::GenericScalar,
    Gf256ArchitectureClass::X86Avx2,
    Gf256ArchitectureClass::Aarch64Neon,
];

/// A representative, well-formed multi-objective criteria (mirrors the module's
/// own regression fixtures). The exact weights are immaterial to the structural
/// invariants under test.
fn criteria() -> OptimizationCriteria {
    OptimizationCriteria {
        latency_weight: 0.5,
        throughput_weight: 0.3,
        bandwidth_weight: 0.2,
        min_improvement_threshold: 5.0,
    }
}

/// Build a tuner wired for a cheap, replay-stable benchmark sweep: a pinned
/// clock anchor (so emitted timestamps are deterministic) and a single
/// iteration per (candidate, workload) pair (so the sweep is fast while
/// percentile indexing stays well-defined).
fn benchmarked_scalar_tuner() -> OfflineTuner {
    let anchor = Time::from_nanos(0x0123_4567_89ab_cdef);
    let mut tuner = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, criteria())
        .with_clock_anchor(anchor)
        .with_benchmark_iterations(1);
    tuner
        .run_systematic_benchmarks()
        .expect("systematic benchmarks run without error on the default scalar workloads");
    tuner
}

#[test]
fn generate_candidates_is_full_cartesian_product_and_well_formed() {
    for arch in ALL_ARCHES {
        let tuner = OfflineTuner::new(arch, criteria());
        let candidates = tuner.generate_candidates();

        // The tuning space is always non-empty.
        assert!(
            !candidates.is_empty(),
            "{arch:?}: candidate set must be non-empty"
        );

        // Pure projection of the (fixed) tuning space -> deterministic.
        assert_eq!(
            candidates,
            tuner.generate_candidates(),
            "{arch:?}: generate_candidates must be deterministic"
        );

        // Every candidate is tagged with the tuner's architecture.
        for c in &candidates {
            assert_eq!(
                c.architecture_class, arch,
                "{arch:?}: candidate arch mismatch"
            );
        }

        // Candidate ids are unique.
        let ids: HashSet<&str> = candidates.iter().map(|c| c.candidate_id.as_str()).collect();
        assert_eq!(
            ids.len(),
            candidates.len(),
            "{arch:?}: candidate ids must be unique"
        );

        // The candidate set is EXACTLY the Cartesian product of the four knob
        // axes: |candidates| == |tiles| * |unrolls| * |prefetches| * |fusions|.
        // Proving this without reading the private tuning space pins both
        // completeness (no missing combos) and minimality (no duplicates).
        let tiles: HashSet<usize> = candidates.iter().map(|c| c.tile_bytes).collect();
        let unrolls: HashSet<usize> = candidates.iter().map(|c| c.unroll).collect();
        let prefetches: HashSet<usize> = candidates.iter().map(|c| c.prefetch_distance).collect();
        let fusions: HashSet<FusionShape> = candidates.iter().map(|c| c.fusion_shape).collect();
        assert_eq!(
            candidates.len(),
            tiles.len() * unrolls.len() * prefetches.len() * fusions.len(),
            "{arch:?}: candidate set must be the full Cartesian product of the tuning space"
        );

        // Canonical id formatting: lowercase, no spaces, schema-versioned.
        for c in &candidates {
            assert_eq!(
                c.candidate_id,
                c.candidate_id.to_lowercase(),
                "{arch:?}: candidate id {:?} must be lowercase",
                c.candidate_id
            );
            assert!(
                !c.candidate_id.contains(' '),
                "{arch:?}: candidate id {:?} must not contain spaces",
                c.candidate_id
            );
            assert!(
                c.candidate_id.ends_with("-v1"),
                "{arch:?}: candidate id {:?} must carry the -v1 schema suffix",
                c.candidate_id
            );
        }
    }
}

#[test]
fn config_accessors_round_trip_and_iterations_clamp_to_one() {
    // Fresh tuner: no clock anchor, default iteration count.
    let fresh = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, criteria());
    assert_eq!(
        fresh.clock_anchor(),
        None,
        "a fresh tuner has no clock anchor"
    );
    assert_eq!(
        fresh.benchmark_iterations(),
        DEFAULT_BENCHMARK_ITERATIONS,
        "default iteration count must be the documented constant"
    );

    // with_clock_anchor round-trips exactly.
    let anchor = Time::from_nanos(0xdead_beef_0000_0001);
    let anchored = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, criteria())
        .with_clock_anchor(anchor);
    assert_eq!(
        anchored.clock_anchor(),
        Some(anchor),
        "clock anchor must round-trip"
    );

    // Iteration count is clamped to >= 1 so median/p95/p99 indexing is defined.
    let clamped = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, criteria())
        .with_benchmark_iterations(0);
    assert_eq!(
        clamped.benchmark_iterations(),
        1,
        "0 iterations must clamp to 1"
    );

    let kept = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, criteria())
        .with_benchmark_iterations(7);
    assert_eq!(
        kept.benchmark_iterations(),
        7,
        "in-range iteration count is preserved"
    );
}

#[test]
fn select_optimal_candidate_fails_closed_without_benchmarks() {
    let tuner = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, criteria());
    match tuner.select_optimal_candidate() {
        Err(TuningError::NoBenchmarkResults) => {}
        other => panic!("expected NoBenchmarkResults before benchmarking, got {other:?}"),
    }
}

#[test]
fn selected_candidate_is_a_member_and_selection_is_deterministic() {
    let tuner = benchmarked_scalar_tuner();

    let selected = tuner
        .select_optimal_candidate()
        .expect("selection succeeds once benchmark results exist");

    // The winner must be one of the generated candidates (value-equal).
    assert!(
        tuner.generate_candidates().contains(&selected),
        "selected candidate must be a member of the generated tuning space"
    );

    // select_optimal_candidate is a pure projection of the populated tuner, so
    // re-selecting yields the identical candidate (lexicographic tie-break).
    let selected_again = tuner
        .select_optimal_candidate()
        .expect("re-selection succeeds");
    assert_eq!(
        selected, selected_again,
        "selection on a fixed populated tuner must be deterministic"
    );
}

#[test]
fn emit_profile_pack_projection_is_consistent() {
    let tuner = benchmarked_scalar_tuner();
    let candidates = tuner.generate_candidates();
    let selected = tuner
        .select_optimal_candidate()
        .expect("selection succeeds once benchmark results exist");

    let pack = tuner
        .emit_profile_pack(&selected)
        .expect("emit_profile_pack succeeds for a selected candidate");

    // Identity + canonical metadata.
    assert_eq!(pack.selected_tuning_candidate_id, selected.candidate_id);
    assert_eq!(
        pack.architecture_class,
        Gf256ArchitectureClass::GenericScalar
    );
    assert_eq!(pack.profile_pack, Gf256ProfilePackId::ScalarConservativeV1);
    assert_eq!(pack.schema_version, "raptorq-gf256-profile-pack-v2");
    assert_eq!(pack.tuning_corpus_id, "offline_kernel_superoptimization_v1");
    assert_eq!(pack.replay_pointer, "replay:offline-kernel-superopt-v1");
    assert_eq!(pack.decision_role, "automated_offline_kernel_optimization");
    assert!(
        pack.command_bundle.contains(&selected.candidate_id),
        "command bundle must reference the selected candidate id for reproducibility"
    );

    // Rejected set = the sorted, deduped complement of the selected id within
    // the full candidate set (every candidate was benchmarked).
    let rejected = &pack.rejected_tuning_candidate_ids;
    for w in rejected.windows(2) {
        assert!(
            w[0] < w[1],
            "rejected candidate ids must be strictly ascending (sorted & deduped)"
        );
    }
    assert!(
        !rejected.contains(&pack.selected_tuning_candidate_id),
        "the selected candidate must not appear in the rejected set"
    );
    assert_eq!(
        rejected.len(),
        candidates.len() - 1,
        "rejected set must cover every candidate except the selected one"
    );
    let all_ids: BTreeSet<String> = candidates.iter().map(|c| c.candidate_id.clone()).collect();
    let mut union: BTreeSet<String> = rejected.iter().cloned().collect();
    union.insert(pack.selected_tuning_candidate_id.clone());
    assert_eq!(
        union, all_ids,
        "selected and rejected ids must cover the full candidate set"
    );

    // Auto-window bounds. The addmul window is always ordered. The mul window is
    // ordered too, EXCEPT for Split, which disables it with the (MAX, 0)
    // sentinel — assert the exact contract for the selected candidate's shape.
    assert!(
        pack.addmul_min_total <= pack.addmul_max_total,
        "addmul auto-window must be ordered"
    );
    match selected.fusion_shape {
        FusionShape::Split => {
            assert_eq!(
                (pack.mul_min_total, pack.mul_max_total),
                (usize::MAX, 0),
                "Split must disable the mul auto-window via the (MAX, 0) sentinel"
            );
        }
        FusionShape::Fused | FusionShape::Balanced => {
            assert!(
                pack.mul_min_total <= pack.mul_max_total,
                "non-Split mul auto-window must be ordered"
            );
        }
    }
    assert_eq!(
        pack.max_lane_ratio,
        selected.unroll.max(1),
        "max lane ratio is derived from the selected candidate's unroll factor"
    );

    // Determinism: re-emitting on the same populated tuner reproduces the same
    // projection (selected id, sorted rejected list, derived windows).
    let pack2 = tuner
        .emit_profile_pack(&selected)
        .expect("re-emit succeeds");
    assert_eq!(
        pack.selected_tuning_candidate_id,
        pack2.selected_tuning_candidate_id
    );
    assert_eq!(
        pack.rejected_tuning_candidate_ids,
        pack2.rejected_tuning_candidate_ids
    );
    assert_eq!(
        (
            pack.mul_min_total,
            pack.mul_max_total,
            pack.addmul_min_total,
            pack.addmul_max_total
        ),
        (
            pack2.mul_min_total,
            pack2.mul_max_total,
            pack2.addmul_min_total,
            pack2.addmul_max_total
        )
    );
}

#[test]
fn profile_pack_id_maps_to_architecture_for_all_classes() {
    // emit_profile_pack does not require a benchmark sweep: with no results the
    // rejected set is empty, but the architecture -> profile-pack id mapping,
    // selected-id round-trip, and schema string are still exercised cheaply
    // across every architecture class.
    for (arch, expected_pack) in [
        (
            Gf256ArchitectureClass::GenericScalar,
            Gf256ProfilePackId::ScalarConservativeV1,
        ),
        (
            Gf256ArchitectureClass::X86Avx2,
            Gf256ProfilePackId::X86Avx2BalancedV1,
        ),
        (
            Gf256ArchitectureClass::Aarch64Neon,
            Gf256ProfilePackId::Aarch64NeonBalancedV1,
        ),
    ] {
        let tuner = OfflineTuner::new(arch, criteria());
        let candidate = tuner
            .generate_candidates()
            .into_iter()
            .next()
            .expect("tuning space is non-empty");

        let pack = tuner
            .emit_profile_pack(&candidate)
            .expect("emit_profile_pack succeeds without a prior benchmark sweep");

        assert_eq!(pack.architecture_class, arch);
        assert_eq!(
            pack.profile_pack, expected_pack,
            "{arch:?}: profile-pack id mismatch"
        );
        assert_eq!(pack.selected_tuning_candidate_id, candidate.candidate_id);
        assert_eq!(pack.schema_version, "raptorq-gf256-profile-pack-v2");
        assert!(
            pack.rejected_tuning_candidate_ids.is_empty(),
            "{arch:?}: with no benchmarks run, the rejected set is empty"
        );
    }
}
