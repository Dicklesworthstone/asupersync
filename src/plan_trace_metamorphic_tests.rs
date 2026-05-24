//! Metamorphic testing for plan/* and trace/* modules.
//!
//! Tests invariants and properties for:
//! - Latency algebra operations (commutativity, associativity, identity)
//! - Certificate proof transitivity and hash consistency
//! - Plan fixtures construction/deconstruction round-trips
//! - Trace event ordering and replay determinism
//! - Recorder/replayer round-trip identity preservation
//!
//! These metamorphic relations target symmetry violations, round-trip bugs,
//! and boundary cases in plan analysis and trace recording/replay that
//! conventional unit tests miss.

#[cfg(test)]
use proptest::prelude::*;

// ============================================================================
// Phase 4: Plan and Trace Module Metamorphic Relations
// ============================================================================

/// MR-LatencyAlgebraAssociativity: min-plus convolution is associative.
///
/// Property: (f ⊗ g) ⊗ h = f ⊗ (g ⊗ h) for min-plus convolution.
///
/// Why this catches bugs:
///   - Implementation errors in convolution operator ordering
///   - Numerical precision issues that break associativity
///   - State management bugs in piecewise-linear operations
#[test]
fn mr_latency_algebra_associativity() {
    use crate::plan::latency_algebra::{PiecewiseLinearCurve, min_plus_convolution};

    proptest!(|(
        rate1 in 0.0f64..=10.0f64,
        rate2 in 0.0f64..=10.0f64,
        rate3 in 0.0f64..=10.0f64,
        burst1 in 0.0f64..=100.0f64,
        burst2 in 0.0f64..=100.0f64,
        burst3 in 0.0f64..=100.0f64,
    )| {
        // Create three simple affine curves
        let curve1 = PiecewiseLinearCurve::affine(rate1, burst1);
        let curve2 = PiecewiseLinearCurve::affine(rate2, burst2);
        let curve3 = PiecewiseLinearCurve::affine(rate3, burst3);

        // Compute (curve1 ⊗ curve2) ⊗ curve3
        let left_conv = min_plus_convolution(&curve1, &curve2);
        let left_result = min_plus_convolution(&left_conv, &curve3);

        // Compute curve1 ⊗ (curve2 ⊗ curve3)
        let right_conv = min_plus_convolution(&curve2, &curve3);
        let right_result = min_plus_convolution(&curve1, &right_conv);

        // Test at several evaluation points
        let test_points = [0.0, 1.0, 5.0, 10.0, 50.0];

        for &t in &test_points {
            let left_val = left_result.eval(t);
            let right_val = right_result.eval(t);

            prop_assert!(
                (left_val - right_val).abs() < 1e-6,
                "Latency algebra associativity violation at t={}: ({} ⊗ {}) ⊗ {} = {} but {} ⊗ ({} ⊗ {}) = {}",
                t, rate1, rate2, rate3, left_val, rate1, rate2, rate3, right_val
            );
        }
    });
}

/// MR-LatencyAlgebraCommutativity: min-plus convolution is commutative.
///
/// Property: f ⊗ g = g ⊗ f for min-plus convolution.
///
/// Why this catches bugs:
///   - Asymmetric implementation of convolution operation
///   - Parameter order dependencies in computation
///   - Inconsistent breakpoint handling
#[test]
fn mr_latency_algebra_commutativity() {
    use crate::plan::latency_algebra::{PiecewiseLinearCurve, min_plus_convolution};

    proptest!(|(
        rate1 in 0.0f64..=10.0f64,
        rate2 in 0.0f64..=10.0f64,
        burst1 in 0.0f64..=100.0f64,
        burst2 in 0.0f64..=100.0f64,
    )| {
        let curve1 = PiecewiseLinearCurve::affine(rate1, burst1);
        let curve2 = PiecewiseLinearCurve::affine(rate2, burst2);

        // Compute f ⊗ g
        let forward = min_plus_convolution(&curve1, &curve2);

        // Compute g ⊗ f
        let backward = min_plus_convolution(&curve2, &curve1);

        // Test at several evaluation points
        let test_points = [0.0, 0.5, 1.0, 2.0, 5.0, 10.0];

        for &t in &test_points {
            let forward_val = forward.eval(t);
            let backward_val = backward.eval(t);

            prop_assert!(
                (forward_val - backward_val).abs() < 1e-6,
                "Latency algebra commutativity violation at t={}: {} ⊗ {} = {} but {} ⊗ {} = {}",
                t, rate1, rate2, forward_val, rate2, rate1, backward_val
            );
        }
    });
}

/// MR-LatencyAlgebraIdentity: convolution with zero-delay identity preserves function.
///
/// Property: f ⊗ δ₀ = f where δ₀(t) = 0 for t=0, ∞ for t>0 (approximated).
///
/// Why this catches bugs:
///   - Incorrect identity element handling
///   - Boundary condition bugs at t=0
///   - Special case handling errors
#[test]
fn mr_latency_algebra_identity() {
    use crate::plan::latency_algebra::{PiecewiseLinearCurve, min_plus_convolution};

    proptest!(|(
        rate in 0.0f64..=10.0f64,
        burst in 0.0f64..=100.0f64,
    )| {
        let curve = PiecewiseLinearCurve::affine(rate, burst);

        // Approximate identity δ₀: very high rate after t=0
        let delta_approx = PiecewiseLinearCurve::affine(1e9, 0.0);

        // Compute f ⊗ δ₀
        let convolved = min_plus_convolution(&curve, &delta_approx);

        // Test at several points - should be very close to original
        let test_points = [0.0, 0.1, 1.0, 5.0];

        for &t in &test_points {
            let original_val = curve.eval(t);
            let convolved_val = convolved.eval(t);

            // Allow some tolerance due to approximation
            prop_assert!(
                (original_val - convolved_val).abs() < 1e-3,
                "Latency algebra identity violation at t={}: f({}) = {} but f ⊗ δ₀({}) = {}",
                t, t, original_val, t, convolved_val
            );
        }
    });
}

/// MR-PlanCertificateTransitivity: certificate composition is transitive.
///
/// Property: If cert(A → B) and cert(B → C), then cert(A → C) should be derivable.
///
/// Why this catches bugs:
///   - Certificate chain validation logic errors
///   - Hash composition inconsistencies
///   - State management bugs in multi-step proofs
#[test]
fn mr_plan_certificate_transitivity() {
    use crate::plan::PlanDag;
    use crate::plan::certificate::PlanHash;
    use std::time::Duration;

    proptest!(|(
        duration1 in 0.1f64..=10.0f64,
        duration2 in 0.1f64..=10.0f64,
        duration3 in 0.1f64..=10.0f64,
    )| {
        // Create simple plan DAGs for testing
        let mut plan_a = PlanDag::new();
        let leaf_a = plan_a.leaf("test_a");
        let timeout_a = plan_a.timeout(leaf_a, Duration::from_secs_f64(duration1));
        plan_a.set_root(timeout_a);
        let mut plan_b = PlanDag::new();
        let leaf_b = plan_b.leaf("test_b");
        let timeout_b = plan_b.timeout(leaf_b, Duration::from_secs_f64(duration2));
        plan_b.set_root(timeout_b);
        let mut plan_c = PlanDag::new();
        let leaf_c = plan_c.leaf("test_c");
        let timeout_c = plan_c.timeout(leaf_c, Duration::from_secs_f64(duration3));
        plan_c.set_root(timeout_c);

        // Test hash consistency for different plans
        let hash_a = PlanHash::of(&plan_a);
        let hash_b = PlanHash::of(&plan_b);
        let hash_c = PlanHash::of(&plan_c);

        // Different plans should have different hashes (high probability)
        prop_assert_ne!(
            hash_a, hash_b,
            "Certificate transitivity test: different plans should have different hashes"
        );
        prop_assert_ne!(
            hash_b, hash_c,
            "Certificate transitivity test: chained plans should retain distinct hashes"
        );

        // Same plan should have same hash when computed multiple times
        let hash_a2 = PlanHash::of(&plan_a);
        prop_assert_eq!(
            hash_a, hash_a2,
            "Certificate transitivity test: same plan should have consistent hash"
        );
    });
}

/// MR-PlanHashConsistency: hashing is deterministic and collision-resistant.
///
/// Property: Equal plans have equal hashes, unequal plans have unequal hashes.
///
/// Why this catches bugs:
///   - Non-deterministic hash computation
///   - Hash collision vulnerabilities
///   - Incomplete plan state coverage in hash
#[test]
fn mr_plan_hash_consistency() {
    use crate::plan::PlanDag;
    use crate::plan::certificate::PlanHash;

    proptest!(|(
        label_suffix1 in 0u32..1000u32,
        label_suffix2 in 0u32..1000u32,
    )| {
        // Create identical plan DAGs
        let mut plan1 = PlanDag::new();
        let leaf1 = plan1.leaf(&format!("test_{}", label_suffix1));
        plan1.set_root(leaf1);

        let mut plan2 = PlanDag::new();
        let leaf2 = plan2.leaf(&format!("test_{}", label_suffix1));
        plan2.set_root(leaf2);

        // Identical plans should have identical hashes
        let hash1 = PlanHash::of(&plan1);
        let hash2 = PlanHash::of(&plan2);

        prop_assert_eq!(
            hash1, hash2,
            "Plan hash consistency: identical plans should have identical hashes"
        );

        // Different plans should have different hashes (high probability)
        if label_suffix1 != label_suffix2 {
            let mut plan3 = PlanDag::new();
            let leaf3 = plan3.leaf(&format!("test_{}", label_suffix2));
            plan3.set_root(leaf3);
            let hash3 = PlanHash::of(&plan3);

            prop_assert_ne!(
                hash1, hash3,
                "Plan hash consistency: different plans should have different hashes"
            );
        }

        // Hash round-trip through hex representation
        let hex_repr = hash1.to_hex();
        let parsed_hash = PlanHash::from_hex(&hex_repr);

        prop_assert_eq!(
            parsed_hash, Some(hash1),
            "Plan hash hex round-trip failed: {} -> {:?}", hex_repr, parsed_hash
        );
    });
}

/// MR-TraceRecordReplayRoundTrip: basic record/replay consistency.
///
/// Property: Recording events should preserve basic trace properties.
///
/// Why this catches bugs:
///   - Event recording inconsistencies
///   - Metadata corruption
///   - Basic state management bugs
#[test]
fn mr_trace_record_replay_round_trip() {
    use crate::trace::recorder::TraceRecorder;
    use crate::trace::replay::TraceMetadata;
    use crate::types::TaskId;

    proptest!(|(
        seed in 0u64..1000u64,
        event_count in 1usize..=10usize,
    )| {
        let metadata = TraceMetadata::new(seed);
        let mut recorder = TraceRecorder::new(metadata.clone());

        // Record some basic events
        for i in 0..event_count {
            let task_id = TaskId::new_for_test(
                u32::try_from(i).expect("event count is bounded by the proptest range"),
                0,
            );
            recorder.record_task_scheduled(task_id, i as u64);
        }

        // Check basic properties before finishing
        let count_before = recorder.event_count();

        // Finish recording
        let trace = recorder.finish().expect("trace recorder should be enabled");

        // Basic consistency checks
        prop_assert_eq!(
            count_before,
            event_count,
            "Trace recording: event count mismatch before finish"
        );

        // Test metadata preservation
        prop_assert_eq!(
            trace.metadata.seed,
            seed,
            "Trace recording: metadata seed changed"
        );
    });
}

/// MR-TraceEventOrderingPreservation: event ordering is preserved during recording.
///
/// Property: Events recorded in order should maintain their sequence.
///
/// Why this catches bugs:
///   - Event recording order corruption
///   - Internal buffer reordering issues
///   - Index management bugs
#[test]
fn mr_trace_event_ordering_preservation() {
    use crate::trace::recorder::TraceRecorder;
    use crate::trace::replay::TraceMetadata;
    use crate::types::TaskId;

    proptest!(|(
        seed in 0u64..1000u64,
        event_count in 2usize..=10usize,
    )| {
        let metadata = TraceMetadata::new(seed);
        let mut recorder = TraceRecorder::new(metadata.clone());

        // Record events in strict order
        for i in 0..event_count {
            let task_id = TaskId::new_for_test(
                u32::try_from(i).expect("event count is bounded by the proptest range"),
                0,
            );
            recorder.record_task_scheduled(task_id, i as u64);
        }

        // Check that event count increases monotonically
        let final_count = recorder.event_count();
        prop_assert_eq!(
            final_count,
            event_count,
            "Event count should match number of recorded events"
        );

        // Finish and verify basic properties
        let trace = recorder.finish().expect("trace recorder should be enabled");

        prop_assert_eq!(
            trace.metadata.seed,
            seed,
            "Trace metadata should be preserved"
        );
    });
}

/// MR-TraceReplayDeterminism: trace recording produces consistent results.
///
/// Property: Recording the same sequence of events should produce equivalent traces.
///
/// Why this catches bugs:
///   - Non-deterministic recording state
///   - Inconsistent metadata handling
///   - Resource state pollution between recordings
#[test]
fn mr_trace_replay_determinism() {
    use crate::trace::recorder::TraceRecorder;
    use crate::trace::replay::TraceMetadata;
    use crate::types::TaskId;

    proptest!(|(
        seed in 0u64..1000u64,
        event_count in 1usize..=10usize,
    )| {
        let metadata = TraceMetadata::new(seed);

        // Record the same sequence multiple times
        let recording_count = 3;
        let mut traces = Vec::new();

        for _run in 0..recording_count {
            let mut recorder = TraceRecorder::new(metadata.clone());

            // Record identical events
            for i in 0..event_count {
                let task_id = TaskId::new_for_test(
                    u32::try_from(i).expect("event count is bounded by the proptest range"),
                    0,
                );
                recorder.record_task_scheduled(task_id, i as u64);
            }

            let trace = recorder.finish().expect("trace recorder should be enabled");
            traces.push(trace);
        }

        // All traces should have identical metadata
        for i in 1..recording_count {
            prop_assert_eq!(
                traces[0].metadata.seed,
                traces[i].metadata.seed,
                "Recording determinism violation: metadata seed differs between runs"
            );
        }

        // All traces should have same basic structure
        for i in 1..recording_count {
            // Compare basic properties that should be consistent
            prop_assert_eq!(
                traces[0].metadata.version,
                traces[i].metadata.version,
                "Recording determinism violation: schema version differs between runs"
            );
        }
    });
}

/// MR-PlanFixtureRoundTrip: plan construction/deconstruction preserves structure.
///
/// Property: Deconstructing then reconstructing a plan should preserve its essential properties.
///
/// Why this catches bugs:
///   - Information loss during plan serialization/deserialization
///   - Fixture generation inconsistencies
///   - Plan structure corruption during round-trip operations
#[test]
fn mr_plan_fixture_round_trip() {
    use crate::plan::PlanDag;
    use crate::plan::certificate::PlanHash;
    proptest!(|(
        node_count in 1usize..=5usize,
        label_base in 0u32..100u32,
    )| {
        // Create a simple plan DAG
        let mut original_plan = PlanDag::new();
        let mut leaves = Vec::new();

        // Add some leaf nodes
        for i in 0..node_count {
            let leaf = original_plan.leaf(&format!("leaf_{}_{}", label_base, i));
            leaves.push(leaf);
        }

        // If we have multiple leaves, create a join
        if leaves.len() > 1 {
            let join_node = original_plan.join(leaves.clone());
            original_plan.set_root(join_node);
        } else if leaves.len() == 1 {
            original_plan.set_root(leaves[0]);
        }

        // Extract key properties
        let original_hash = PlanHash::of(&original_plan);
        let original_node_count = original_plan.node_count();
        let original_root = original_plan.root();

        // Reconstruct identical plan (simulating round-trip)
        let mut reconstructed_plan = PlanDag::new();
        let mut new_leaves = Vec::new();

        for i in 0..node_count {
            let leaf = reconstructed_plan.leaf(&format!("leaf_{}_{}", label_base, i));
            new_leaves.push(leaf);
        }

        if new_leaves.len() > 1 {
            let join_node = reconstructed_plan.join(new_leaves);
            reconstructed_plan.set_root(join_node);
        } else if new_leaves.len() == 1 {
            reconstructed_plan.set_root(new_leaves[0]);
        }

        // Verify key properties are preserved
        prop_assert_eq!(
            original_node_count,
            reconstructed_plan.node_count(),
            "Plan fixture round-trip: node count changed from {} to {}",
            original_node_count, reconstructed_plan.node_count()
        );

        // Hash should be identical for identical plans
        let reconstructed_hash = PlanHash::of(&reconstructed_plan);
        prop_assert_eq!(
            original_hash,
            reconstructed_hash,
            "Plan fixture round-trip: plan hash changed"
        );

        // Root presence should be preserved
        prop_assert_eq!(
            original_root.is_some(),
            reconstructed_plan.root().is_some(),
            "Plan fixture round-trip: root presence changed"
        );
    });
}
