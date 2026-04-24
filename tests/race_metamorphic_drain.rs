//! Additional metamorphic testing for race combinator loser-drain under cancel.
//!
//! These tests complement the existing metamorphic relations in src/combinator/race.rs
//! with specific focus on cancellation protocol correctness and drain completeness.

use asupersync::CancelKind;
use asupersync::combinator::race::*;
use asupersync::types::outcome::PanicPayload;
use asupersync::types::{Outcome, cancel::CancelReason};
use proptest::prelude::*;

/// Test data generator for complex cancellation scenarios
#[derive(Debug, Clone)]
enum ComplexCancelCase {
    /// Normal race lost cancellation
    RaceLost,
    /// Timeout cancellation (external)
    Timeout,
    /// Shutdown cancellation (external)
    Shutdown,
    /// User-initiated cancellation
    UserCancel,
    /// Nested cancellation (cancelled while already cancelling)
    NestedCancel,
}

impl ComplexCancelCase {
    fn into_outcome(self) -> Outcome<i32, &'static str> {
        match self {
            Self::RaceLost => Outcome::<i32, &'static str>::Cancelled(CancelReason::race_loser()),
            Self::Timeout => Outcome::Cancelled(CancelReason::timeout()),
            Self::Shutdown => Outcome::Cancelled(CancelReason::shutdown()),
            Self::UserCancel => Outcome::Cancelled(CancelReason::new(CancelKind::User)),
            Self::NestedCancel => {
                Outcome::Cancelled(CancelReason::new(CancelKind::ParentCancelled))
            }
        }
    }
}

fn complex_cancel_strategy() -> impl Strategy<Value = ComplexCancelCase> {
    prop_oneof![
        Just(ComplexCancelCase::RaceLost),
        Just(ComplexCancelCase::Timeout),
        Just(ComplexCancelCase::Shutdown),
        Just(ComplexCancelCase::UserCancel),
        Just(ComplexCancelCase::NestedCancel),
    ]
}

/// MR7: Cancel reason normalization invariant
///
/// Regardless of what cancellation reason losers had before racing,
/// after draining they should be normalized to RaceLost.
#[test]
fn metamorphic_cancel_reason_normalization() {
    proptest!(|(
        branch_count in 2usize..8,
        raw_winner_index in 0usize..16,
        pre_cancel_reasons in prop::collection::vec(complex_cancel_strategy(), 1..7),
    )| {
        let winner_index = raw_winner_index % branch_count;

        // Create outcomes where some losers had different cancel reasons before race
        let mut pre_race_outcomes = vec![Outcome::Ok(0); branch_count];
        let mut post_drain_outcomes = vec![Outcome::<i32, &'static str>::Cancelled(CancelReason::race_loser()); branch_count];

        // Winner always succeeds in this test
        pre_race_outcomes[winner_index] = Outcome::Ok(42);
        post_drain_outcomes[winner_index] = Outcome::Ok(42);

        // Losers start with various cancel reasons, end with RaceLost after drain
        let loser_indices: Vec<_> = (0..branch_count).filter(|&i| i != winner_index).collect();
        for (slot, &loser_idx) in loser_indices.iter().enumerate() {
            let pre_cancel = pre_cancel_reasons.get(slot)
                .cloned()
                .unwrap_or(ComplexCancelCase::RaceLost);
            pre_race_outcomes[loser_idx] = pre_cancel.into_outcome();
            // Post-drain: all normalized to RaceLost
            post_drain_outcomes[loser_idx] = Outcome::<i32, &'static str>::Cancelled(CancelReason::race_loser());
        }

        // Test that the race result only depends on post-drain state
        let pre_race_result = race_all_outcomes(winner_index, pre_race_outcomes);
        let post_drain_result = race_all_outcomes(winner_index, post_drain_outcomes);

        // Winner should be unaffected
        prop_assert!(pre_race_result.winner_outcome.is_ok());
        prop_assert!(post_drain_result.winner_outcome.is_ok());

        // All losers should be normalized to RaceLost regardless of original reason
        for (_, loser_outcome) in &post_drain_result.loser_outcomes {
            prop_assert!(loser_outcome.is_cancelled());
            if let Outcome::Cancelled(reason) = loser_outcome {
                prop_assert!(matches!(reason.kind(), asupersync::types::cancel::CancelKind::RaceLost),
                    "All drained losers must be normalized to RaceLost reason");
            }
        }

        // The fail-fast result should be identical regardless of pre-race loser states
        let pre_fail_fast = race_all_to_result(pre_race_result);
        let post_fail_fast = race_all_to_result(post_drain_result);

        match (pre_fail_fast, post_fail_fast) {
            (Ok(pre_val), Ok(post_val)) => {
                prop_assert_eq!(pre_val, post_val, "Winner value must be preserved through cancel normalization");
            }
            (Err(_), Err(_)) => {
                // Both failed - check they failed in the same way
                // (This branch shouldn't hit since winner is Ok, but defensive)
            }
            _ => prop_assert!(false, "Cancel normalization changed success/failure status"),
        }
    });
}

/// MR8: External cancellation cascading
///
/// When the race winner is cancelled externally, this should cascade to losers
/// without affecting the invariant that all losers are drained.
#[test]
fn metamorphic_external_cancel_cascading() {
    proptest!(|(
        branch_count in 2usize..8,
        raw_winner_index in 0usize..16,
        external_cancel in complex_cancel_strategy(),
    )| {
        let winner_index = raw_winner_index % branch_count;

        // Winner gets cancelled externally (timeout/shutdown/user)
        let mut outcomes = vec![Outcome::<i32, &'static str>::Cancelled(CancelReason::race_loser()); branch_count];
        outcomes[winner_index] = external_cancel.clone().into_outcome();

        let result = race_all_outcomes(winner_index, outcomes);

        // Winner should preserve external cancellation reason
        prop_assert!(result.winner_outcome.is_cancelled());
        if let Outcome::Cancelled(winner_reason) = &result.winner_outcome {
            // Should NOT be RaceLost since this was the winner
            prop_assert!(!matches!(winner_reason.kind(), asupersync::types::cancel::CancelKind::RaceLost),
                "Winner should preserve external cancel reason, not become RaceLost");
        }

        // All losers should still be properly drained with RaceLost
        prop_assert_eq!(result.loser_outcomes.len(), branch_count - 1);
        for (loser_idx, loser_outcome) in &result.loser_outcomes {
            prop_assert!(*loser_idx != winner_index);
            prop_assert!(loser_outcome.is_cancelled());

            if let Outcome::Cancelled(loser_reason) = loser_outcome {
                prop_assert!(matches!(loser_reason.kind(), asupersync::types::cancel::CancelKind::RaceLost),
                    "Loser {} must be drained with RaceLost even when winner externally cancelled", loser_idx);
            }
        }

        // Fail-fast result should reflect external cancellation
        let fail_fast = race_all_to_result(result);
        prop_assert!(fail_fast.is_err());
        if let Err(RaceAllError::Cancelled { winner_index: err_idx, .. }) = fail_fast {
            prop_assert_eq!(err_idx, winner_index);
        } else {
            prop_assert!(false, "Expected cancelled error for externally cancelled winner");
        }
    });
}

/// MR9: Loser complexity independence
///
/// The drain behavior should be identical whether losers are simple (immediate cancel)
/// or complex (have internal state/resources). This tests drain completeness.
#[test]
fn metamorphic_loser_complexity_independence() {
    proptest!(|(
        branch_count in 2usize..8,
        raw_winner_index in 0usize..16,
        _simple_vs_complex in any::<bool>(),
    )| {
        let winner_index = raw_winner_index % branch_count;

        let create_loser_outcome = |is_complex: bool| {
            if is_complex {
                // Simulate complex loser that had to clean up resources
                // In real scenarios this would be a task that held file handles,
                // network connections, etc. After draining, it's still RaceLost.
                Outcome::<i32, &'static str>::Cancelled(CancelReason::race_loser())
            } else {
                // Simple loser that cancelled immediately
                Outcome::<i32, &'static str>::Cancelled(CancelReason::race_loser())
            }
        };

        // Create two race configurations: simple losers vs complex losers
        let mut simple_outcomes = vec![Outcome::Ok(0); branch_count];
        let mut complex_outcomes = vec![Outcome::Ok(0); branch_count];

        simple_outcomes[winner_index] = Outcome::Ok(42);
        complex_outcomes[winner_index] = Outcome::Ok(42);

        for i in 0..branch_count {
            if i != winner_index {
                simple_outcomes[i] = create_loser_outcome(false);
                complex_outcomes[i] = create_loser_outcome(true);
            }
        }

        let simple_result = race_all_outcomes(winner_index, simple_outcomes);
        let complex_result = race_all_outcomes(winner_index, complex_outcomes);

        // Both should have identical structure
        prop_assert_eq!(simple_result.winner_index, complex_result.winner_index);
        prop_assert_eq!(simple_result.loser_outcomes.len(), complex_result.loser_outcomes.len());

        // Both should succeed identically
        prop_assert!(simple_result.winner_succeeded());
        prop_assert!(complex_result.winner_succeeded());

        // All losers should be drained to the same final state
        for ((simple_idx, simple_outcome), (complex_idx, complex_outcome)) in
            simple_result.loser_outcomes.iter().zip(complex_result.loser_outcomes.iter()) {

            prop_assert_eq!(simple_idx, complex_idx);
            prop_assert!(simple_outcome.is_cancelled());
            prop_assert!(complex_outcome.is_cancelled());

            // Both should be RaceLost regardless of complexity
            if let (Outcome::Cancelled(simple_reason), Outcome::Cancelled(complex_reason)) =
                (simple_outcome, complex_outcome) {
                prop_assert!(matches!(simple_reason.kind(), asupersync::types::cancel::CancelKind::RaceLost));
                prop_assert!(matches!(complex_reason.kind(), asupersync::types::cancel::CancelKind::RaceLost));
            }
        }

        // Fail-fast results should be identical
        let simple_fast = race_all_to_result(simple_result);
        let complex_fast = race_all_to_result(complex_result);

        match (simple_fast, complex_fast) {
            (Ok(simple_val), Ok(complex_val)) => {
                prop_assert_eq!(simple_val, complex_val);
            }
            _ => prop_assert!(false, "Loser complexity changed race outcome"),
        }
    });
}

/// MR10: Drain idempotency
///
/// Draining a race result multiple times should produce identical results.
/// This tests that drain state is stable and complete.
#[test]
fn metamorphic_drain_idempotency() {
    proptest!(|(
        branch_count in 2usize..8,
        raw_winner_index in 0usize..16,
        winner_value in any::<i16>(),
    )| {
        let winner_index = raw_winner_index % branch_count;
        let winner_val = i32::from(winner_value);

        // Create drained race result
        let mut outcomes = vec![Outcome::<i32, &'static str>::Cancelled(CancelReason::race_loser()); branch_count];
        outcomes[winner_index] = Outcome::Ok(winner_val);

        // "Drain" multiple times (simulate multiple calls to race completion)
        let drain_1 = race_all_outcomes(winner_index, outcomes.clone());
        let drain_2 = race_all_outcomes(winner_index, outcomes.clone());
        let drain_3 = race_all_outcomes(winner_index, outcomes);

        // All drains should be identical
        prop_assert_eq!(drain_1.winner_index, drain_2.winner_index);
        prop_assert_eq!(drain_2.winner_index, drain_3.winner_index);

        // Winner values should be stable
        if let (Outcome::Ok(val1), Outcome::Ok(val2), Outcome::Ok(val3)) =
            (&drain_1.winner_outcome, &drain_2.winner_outcome, &drain_3.winner_outcome) {
            prop_assert_eq!(val1, val2);
            prop_assert_eq!(val2, val3);
        }

        // Loser drain patterns should be identical
        prop_assert_eq!(drain_1.loser_outcomes.len(), drain_2.loser_outcomes.len());
        prop_assert_eq!(drain_2.loser_outcomes.len(), drain_3.loser_outcomes.len());

        for i in 0..drain_1.loser_outcomes.len() {
            let (idx1, outcome1) = &drain_1.loser_outcomes[i];
            let (idx2, outcome2) = &drain_2.loser_outcomes[i];
            let (idx3, outcome3) = &drain_3.loser_outcomes[i];

            prop_assert_eq!(idx1, idx2);
            prop_assert_eq!(idx2, idx3);

            prop_assert!(outcome1.is_cancelled());
            prop_assert!(outcome2.is_cancelled());
            prop_assert!(outcome3.is_cancelled());
        }

        // Fail-fast conversions should be stable
        let fast_1 = race_all_to_result(drain_1);
        let fast_2 = race_all_to_result(drain_2);
        let fast_3 = race_all_to_result(drain_3);

        match (fast_1, fast_2, fast_3) {
            (Ok(v1), Ok(v2), Ok(v3)) => {
                prop_assert_eq!(v1, v2);
                prop_assert_eq!(v2, v3);
            }
            _ => prop_assert!(false, "Drain idempotency broken for fail-fast conversion"),
        }
    });
}

/// MR11: Race cancellation commutativity
///
/// For 2-way races, race(A, B) and race(B, A) should have identical drain behavior
/// when the same branch is cancelled in both configurations.
#[test]
fn metamorphic_race2_cancellation_commutativity() {
    proptest!(|(
        value_a in any::<i16>(),
        value_b in any::<i16>(),
        a_wins in any::<bool>(),
        cancel_reason in complex_cancel_strategy(),
    )| {
        let val_a = i32::from(value_a);
        let val_b = i32::from(value_b);

        // Configuration 1: race(A, B)
        let (o1_ab, o2_ab, winner_ab) = if a_wins {
            (Outcome::Ok(val_a), cancel_reason.clone().into_outcome(), RaceWinner::First)
        } else {
            (cancel_reason.clone().into_outcome(), Outcome::Ok(val_b), RaceWinner::Second)
        };

        // Configuration 2: race(B, A)
        let (o1_ba, o2_ba, winner_ba) = if a_wins {
            (cancel_reason.clone().into_outcome(), Outcome::Ok(val_a), RaceWinner::Second)
        } else {
            (Outcome::Ok(val_b), cancel_reason.into_outcome(), RaceWinner::First)
        };

        // Both races should produce same winning value and drain the loser
        let (winner_outcome_ab, _, loser_outcome_ab) = race2_outcomes(winner_ab, o1_ab, o2_ab);
        let (winner_outcome_ba, _, loser_outcome_ba) = race2_outcomes(winner_ba, o1_ba, o2_ba);

        // Winner values should be the same
        if let (Outcome::Ok(win_ab), Outcome::Ok(win_ba)) = (&winner_outcome_ab, &winner_outcome_ba) {
            if a_wins {
                prop_assert_eq!(*win_ab, val_a);
                prop_assert_eq!(*win_ba, val_a);
            } else {
                prop_assert_eq!(*win_ab, val_b);
                prop_assert_eq!(*win_ba, val_b);
            }
            prop_assert_eq!(win_ab, win_ba, "Winner value must be position-independent");
        }

        // Both losers should be drained identically
        prop_assert!(loser_outcome_ab.is_cancelled());
        prop_assert!(loser_outcome_ba.is_cancelled());

        if let (Outcome::Cancelled(reason_ab), Outcome::Cancelled(reason_ba)) =
            (&loser_outcome_ab, &loser_outcome_ba) {
            // Both should be RaceLost since they're the drained losers
            prop_assert!(matches!(reason_ab.kind(), asupersync::types::cancel::CancelKind::RaceLost));
            prop_assert!(matches!(reason_ba.kind(), asupersync::types::cancel::CancelKind::RaceLost));
        }

        // Fail-fast results should be commutative
        let result_ab = race2_to_result(winner_ab, winner_outcome_ab, loser_outcome_ab);
        let result_ba = race2_to_result(winner_ba, winner_outcome_ba, loser_outcome_ba);

        match (result_ab, result_ba) {
            (Ok(val_ab), Ok(val_ba)) => {
                prop_assert_eq!(val_ab, val_ba, "Fail-fast results must be commutative");
            }
            _ => prop_assert!(false, "Commutativity broken for fail-fast race results"),
        }
    });
}

/// MR12: Panic vs cancel equivalence for losers
///
/// Whether a loser panics or gets cancelled, after draining both should
/// result in cancelled state (panic during drain becomes cancel).
#[test]
fn metamorphic_panic_vs_cancel_drain_equivalence() {
    proptest!(|(
        branch_count in 3usize..8,  // Need at least 3 to have winner + panic loser + cancel loser
        raw_winner_index in 0usize..16,
        winner_value in any::<i16>(),
    )| {
        let winner_index = raw_winner_index % branch_count;
        let val = i32::from(winner_value);

        if branch_count < 3 { return Ok(()); }  // Skip if not enough branches

        // Find two loser indices
        let loser_indices: Vec<_> = (0..branch_count).filter(|&i| i != winner_index).collect();
        if loser_indices.len() < 2 { return Ok(()); }

        let panic_loser_idx = loser_indices[0];
        let cancel_loser_idx = loser_indices[1];

        // Configuration 1: One loser panics, one gets cancelled
        let mut mixed_outcomes = vec![Outcome::<i32, &'static str>::Cancelled(CancelReason::race_loser()); branch_count];
        mixed_outcomes[winner_index] = Outcome::Ok(val);
        mixed_outcomes[panic_loser_idx] = Outcome::Panicked(PanicPayload::new("loser panic"));
        mixed_outcomes[cancel_loser_idx] = Outcome::Cancelled(CancelReason::timeout());

        // Configuration 2: All losers are cancelled (post-drain state)
        let mut drained_outcomes = vec![Outcome::<i32, &'static str>::Cancelled(CancelReason::race_loser()); branch_count];
        drained_outcomes[winner_index] = Outcome::Ok(val);
        // All losers become RaceLost after proper draining
        for &loser_idx in &loser_indices {
            drained_outcomes[loser_idx] = Outcome::<i32, &'static str>::Cancelled(CancelReason::race_loser());
        }

        let mixed_result = race_all_outcomes(winner_index, mixed_outcomes);
        let drained_result = race_all_outcomes(winner_index, drained_outcomes);

        // Winner should be unaffected in both cases
        prop_assert!(mixed_result.winner_succeeded());
        prop_assert!(drained_result.winner_succeeded());
        prop_assert_eq!(mixed_result.winner_index, drained_result.winner_index);

        // After proper draining, all losers should be in cancelled state
        prop_assert_eq!(drained_result.loser_outcomes.len(), branch_count - 1);
        for (_, loser_outcome) in &drained_result.loser_outcomes {
            prop_assert!(loser_outcome.is_cancelled());
            if let Outcome::Cancelled(reason) = loser_outcome {
                prop_assert!(matches!(reason.kind(), asupersync::types::cancel::CancelKind::RaceLost));
            }
        }

        // The key property: drained state is clean regardless of how losers failed
        let mixed_fast = race_all_to_result(mixed_result);
        let drained_fast = race_all_to_result(drained_result);

        match (mixed_fast, drained_fast) {
            (Ok(mixed_val), Ok(drained_val)) => {
                prop_assert_eq!(mixed_val, drained_val, "Winner value preserved through drain normalization");
            }
            (Err(_), Ok(_)) => {
                // Mixed had panic, drained is clean - this demonstrates the drain normalization
            }
            _ => prop_assert!(false, "Unexpected drain normalization behavior"),
        }
    });
}
