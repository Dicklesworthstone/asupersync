//! Property-based tests for capability sets and obligation typestate.
//!
//! Verifies algebraic properties of the capability subset lattice, the
//! VarState abstract domain lattice, and obligation lifecycle invariants
//! using proptest.

#[macro_use]
mod common;
use common::*;

use asupersync::cx::cap::{All, CapSet, None as CapNone};
use asupersync::obligation::graded::{
    GradedObligation, GradedScope, ObligationToken, Resolution, SendPermit, AckKind, LeaseKind,
    IoOpKind,
};
use asupersync::obligation::{BodyBuilder, DiagnosticKind, LeakChecker, ObligationVar, VarState};
use asupersync::record::ObligationKind;
use asupersync::{assert_has_leaks, assert_no_leaks, obligation_body};
use proptest::prelude::*;

// ============================================================================
// Arbitrary generators
// ============================================================================

fn arb_obligation_kind() -> impl Strategy<Value = ObligationKind> {
    prop_oneof![
        Just(ObligationKind::SendPermit),
        Just(ObligationKind::Ack),
        Just(ObligationKind::Lease),
        Just(ObligationKind::IoOp),
    ]
}

fn arb_var_state() -> impl Strategy<Value = VarState> {
    prop_oneof![
        Just(VarState::Empty),
        Just(VarState::Resolved),
        Just(VarState::MayHoldAmbiguous),
        arb_obligation_kind().prop_map(VarState::Held),
        arb_obligation_kind().prop_map(VarState::MayHold),
    ]
}

fn arb_resolution() -> impl Strategy<Value = Resolution> {
    prop_oneof![Just(Resolution::Commit), Just(Resolution::Abort),]
}

// ============================================================================
// VarState lattice properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// VarState join is commutative: a ⊔ b = b ⊔ a.
    #[test]
    fn varstate_join_commutative(
        a in arb_var_state(),
        b in arb_var_state(),
    ) {
        prop_assert_eq!(a.join(b), b.join(a));
    }

    /// VarState join is idempotent: a ⊔ a = a.
    #[test]
    fn varstate_join_idempotent(
        a in arb_var_state(),
    ) {
        prop_assert_eq!(a.join(a), a);
    }

    /// VarState join is associative: (a ⊔ b) ⊔ c = a ⊔ (b ⊔ c).
    #[test]
    fn varstate_join_associative(
        a in arb_var_state(),
        b in arb_var_state(),
        c in arb_var_state(),
    ) {
        let lhs = a.join(b).join(c);
        let rhs = a.join(b.join(c));
        prop_assert_eq!(lhs, rhs);
    }

    /// Empty is a bottom element: Empty ⊔ x absorbs toward x's "side"
    /// (specifically: join(Empty, Held(k)) = MayHold(k), join(Empty, Resolved) = Resolved).
    #[test]
    fn varstate_empty_is_bottom(
        a in arb_var_state(),
    ) {
        let joined = VarState::Empty.join(a);
        // Empty joined with anything should not produce Held (because one path is Empty).
        // The result should be Empty, Resolved, MayHold, or MayHoldAmbiguous.
        match a {
            VarState::Empty => prop_assert_eq!(joined, VarState::Empty),
            VarState::Resolved => prop_assert_eq!(joined, VarState::Resolved),
            VarState::Held(k) => prop_assert_eq!(joined, VarState::MayHold(k)),
            VarState::MayHold(k) => prop_assert_eq!(joined, VarState::MayHold(k)),
            VarState::MayHoldAmbiguous => prop_assert_eq!(joined, VarState::MayHoldAmbiguous),
        }
    }

    /// Held(k) joined with Resolved produces MayHold(k).
    #[test]
    fn varstate_held_resolved_produces_may_hold(
        k in arb_obligation_kind(),
    ) {
        let result = VarState::Held(k).join(VarState::Resolved);
        prop_assert_eq!(result, VarState::MayHold(k));
    }

    /// Held(k1) joined with Held(k2) where k1 != k2 produces MayHoldAmbiguous.
    #[test]
    fn varstate_different_kinds_produce_ambiguous(
        k1 in arb_obligation_kind(),
        k2 in arb_obligation_kind(),
    ) {
        prop_assume!(k1 != k2);
        let result = VarState::Held(k1).join(VarState::Held(k2));
        prop_assert_eq!(result, VarState::MayHoldAmbiguous);
    }

    /// VarState::is_leak correctly identifies leak states.
    #[test]
    fn varstate_is_leak_correct(
        state in arb_var_state(),
    ) {
        let should_leak = matches!(
            state,
            VarState::Held(_) | VarState::MayHold(_) | VarState::MayHoldAmbiguous
        );
        prop_assert_eq!(state.is_leak(), should_leak);
    }
}

// ============================================================================
// Obligation lifecycle property tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// A single obligation that is always resolved produces no leaks.
    #[test]
    fn single_obligation_resolved_is_clean(
        kind in arb_obligation_kind(),
        resolution in arb_resolution(),
    ) {
        let mut b = BodyBuilder::new("prop_clean");
        let v = b.reserve(kind);
        match resolution {
            Resolution::Commit => { b.commit(v); }
            Resolution::Abort => { b.abort(v); }
        }
        let body = b.build();
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        prop_assert!(result.is_clean(), "resolved obligation should be clean: {result}");
    }

    /// An unresolved obligation always produces exactly one definite leak.
    #[test]
    fn unresolved_obligation_is_definite_leak(
        kind in arb_obligation_kind(),
    ) {
        let mut b = BodyBuilder::new("prop_leak");
        let _v = b.reserve(kind);
        let body = b.build();
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        prop_assert!(!result.is_clean());
        let leaks = result.leaks();
        prop_assert_eq!(leaks.len(), 1);
        prop_assert_eq!(&leaks[0].kind, &DiagnosticKind::DefiniteLeak);
        prop_assert_eq!(leaks[0].obligation_kind, Some(kind));
    }

    /// N obligations all resolved produces no leaks.
    #[test]
    fn n_obligations_all_resolved(
        kinds in proptest::collection::vec(arb_obligation_kind(), 1..=8),
        resolve_commit in proptest::collection::vec(proptest::bool::ANY, 1..=8),
    ) {
        let n = kinds.len().min(resolve_commit.len());
        let mut b = BodyBuilder::new("prop_multi");
        let vars: Vec<ObligationVar> = (0..n).map(|i| b.reserve(kinds[i])).collect();
        for (i, v) in vars.iter().enumerate() {
            if resolve_commit[i] {
                b.commit(*v);
            } else {
                b.abort(*v);
            }
        }
        let body = b.build();
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        prop_assert!(result.is_clean(), "all resolved: {result}");
    }

    /// N obligations with K leaked produces exactly K leak diagnostics.
    #[test]
    fn n_obligations_k_leaked(
        kinds in proptest::collection::vec(arb_obligation_kind(), 2..=6),
        leak_mask in proptest::collection::vec(proptest::bool::ANY, 2..=6),
    ) {
        let n = kinds.len().min(leak_mask.len());
        let mut b = BodyBuilder::new("prop_partial_leak");
        let vars: Vec<ObligationVar> = (0..n).map(|i| b.reserve(kinds[i])).collect();
        let mut expected_leaks = 0;
        for (i, v) in vars.iter().enumerate() {
            if leak_mask[i] {
                expected_leaks += 1;
                // Don't resolve — this is a leak.
            } else {
                b.commit(*v);
            }
        }
        let body = b.build();
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        prop_assert_eq!(
            leaks.len(),
            expected_leaks,
            "expected {} leaks: {}",
            expected_leaks,
            result
        );
    }

    /// Branch with all arms resolving produces no leak.
    #[test]
    fn branch_all_arms_resolve_is_clean(
        kind in arb_obligation_kind(),
        n_arms in 2..=5usize,
        resolve_commit in proptest::collection::vec(proptest::bool::ANY, 2..=5),
    ) {
        let n_arms = n_arms.min(resolve_commit.len());
        let mut b = BodyBuilder::new("prop_branch_clean");
        let v = b.reserve(kind);
        b.branch(|bb| {
            for i in 0..n_arms {
                let commit = resolve_commit[i];
                bb.arm(move |a| {
                    if commit {
                        a.commit(v);
                    } else {
                        a.abort(v);
                    }
                });
            }
        });
        let body = b.build();
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        prop_assert!(result.is_clean(), "all arms resolve: {result}");
    }

    /// Branch with one arm missing resolution produces exactly one potential leak.
    #[test]
    fn branch_one_arm_missing_produces_potential_leak(
        kind in arb_obligation_kind(),
        n_arms in 2..=5usize,
        missing_idx in 0..5usize,
    ) {
        let n_arms = n_arms.max(2);
        let missing_idx = missing_idx % n_arms;
        let mut b = BodyBuilder::new("prop_branch_leak");
        let v = b.reserve(kind);
        b.branch(|bb| {
            for i in 0..n_arms {
                if i == missing_idx {
                    bb.arm(|_a| {}); // Missing resolution.
                } else {
                    bb.arm(|a| { a.commit(v); });
                }
            }
        });
        let body = b.build();
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        prop_assert_eq!(leaks.len(), 1, "one missing arm: {}", result);
        prop_assert_eq!(&leaks[0].kind, &DiagnosticKind::PotentialLeak);
    }
}

// ============================================================================
// GradedObligation runtime properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Resolving a GradedObligation does not panic.
    #[test]
    fn graded_obligation_resolve_no_panic(
        kind in arb_obligation_kind(),
        resolution in arb_resolution(),
    ) {
        let ob = GradedObligation::reserve(kind, "prop-test");
        let proof = ob.resolve(resolution);
        prop_assert_eq!(proof.kind, kind);
        prop_assert_eq!(proof.resolution, resolution);
    }

    /// GradedScope with matching reserve/resolve counts closes cleanly.
    #[test]
    fn graded_scope_balanced_closes_cleanly(
        n in 0..=20u32,
    ) {
        let mut scope = GradedScope::open("prop-scope");
        for _ in 0..n {
            scope.on_reserve();
        }
        for _ in 0..n {
            scope.on_resolve();
        }
        let result = scope.close();
        prop_assert!(result.is_ok(), "balanced scope should close cleanly");
        let proof = result.unwrap();
        prop_assert_eq!(proof.total_reserved, n);
        prop_assert_eq!(proof.total_resolved, n);
    }

    /// GradedScope with unbalanced counts returns error on close.
    #[test]
    fn graded_scope_unbalanced_returns_error(
        reserved in 1..=20u32,
        resolved in 0..=20u32,
    ) {
        prop_assume!(resolved < reserved);
        let mut scope = GradedScope::open("prop-unbalanced");
        for _ in 0..reserved {
            scope.on_reserve();
        }
        for _ in 0..resolved {
            scope.on_resolve();
        }
        let result = scope.close();
        prop_assert!(result.is_err(), "unbalanced scope should error");
        let err = result.unwrap_err();
        prop_assert_eq!(err.outstanding, reserved - resolved);
    }
}

// ============================================================================
// Capability set properties
// ============================================================================

#[test]
fn cap_none_is_zst() {
    assert_eq!(std::mem::size_of::<CapNone>(), 0);
}

#[test]
fn cap_all_is_zst() {
    assert_eq!(std::mem::size_of::<All>(), 0);
}

#[test]
fn cap_arbitrary_is_zst() {
    assert_eq!(
        std::mem::size_of::<CapSet<true, false, true, false, true>>(),
        0
    );
}

/// Verify that the SubsetOf relation is consistent:
/// None ⊆ Any ⊆ All.
#[test]
fn cap_subset_chain() {
    fn assert_subset<Sub: asupersync::cx::cap::SubsetOf<Super>, Super>() {}

    // None ⊆ All.
    assert_subset::<CapNone, All>();
    // None ⊆ partial.
    assert_subset::<CapNone, CapSet<true, false, false, false, false>>();
    assert_subset::<CapNone, CapSet<false, true, false, false, false>>();
    // Partial ⊆ All.
    assert_subset::<CapSet<true, false, false, false, false>, All>();
    // Partial ⊆ bigger partial.
    assert_subset::<
        CapSet<true, false, false, false, false>,
        CapSet<true, true, false, true, false>,
    >();
}

/// Verify marker traits align with capability bits.
#[test]
fn cap_marker_traits() {
    fn assert_spawn<C: asupersync::cx::HasSpawn>() {}
    fn assert_time<C: asupersync::cx::HasTime>() {}
    fn assert_random<C: asupersync::cx::HasRandom>() {}
    fn assert_io<C: asupersync::cx::HasIo>() {}
    fn assert_remote<C: asupersync::cx::HasRemote>() {}

    // All has everything.
    assert_spawn::<All>();
    assert_time::<All>();
    assert_random::<All>();
    assert_io::<All>();
    assert_remote::<All>();

    // Individual capabilities.
    assert_spawn::<CapSet<true, false, false, false, false>>();
    assert_time::<CapSet<false, true, false, false, false>>();
    assert_random::<CapSet<false, false, true, false, false>>();
    assert_io::<CapSet<false, false, false, true, false>>();
    assert_remote::<CapSet<false, false, false, false, true>>();
}

/// Compile-time test: SubsetOf is reflexive.
#[test]
fn cap_subset_reflexive() {
    fn assert_subset<Sub: asupersync::cx::cap::SubsetOf<Super>, Super>() {}

    assert_subset::<All, All>();
    assert_subset::<CapNone, CapNone>();
    assert_subset::<CapSet<true, false, true, false, true>, CapSet<true, false, true, false, true>>();
}

/// Compile-time test: SubsetOf is transitive (demonstrated).
#[test]
fn cap_subset_transitive() {
    fn assert_subset<Sub: asupersync::cx::cap::SubsetOf<Super>, Super>() {}

    type A = CapNone;
    type B = CapSet<true, true, false, false, false>;
    type C = CapSet<true, true, false, true, false>;

    // A ⊆ B ⊆ C, therefore A ⊆ C.
    assert_subset::<A, B>();
    assert_subset::<B, C>();
    assert_subset::<A, C>();
}

// ============================================================================
// Ambient authority rejection (sealed trait anti-forgery)
// ============================================================================

/// Tests that the sealed trait pattern prevents ambient authority.
///
/// This test demonstrates that:
/// 1. CapSet types are the only implementors of SubsetOf
/// 2. HasSpawn/HasTime/etc. are sealed — external types cannot implement them
/// 3. Narrowing (dropping capabilities) is the only direction that compiles
///
/// The compile-fail doctests in src/cx/cap.rs verify that widening
/// and external trait impls are rejected at compile time.
#[test]
fn ambient_authority_rejected_by_sealing() {
    init_test_logging();
    test_phase!("ambient_authority_rejected_by_sealing");

    // Verify that only valid narrowing compiles.
    fn narrow<Sub: asupersync::cx::cap::SubsetOf<Super> + Default, Super>(_: &Sub) -> Sub {
        Sub::default()
    }

    let all: All = Default::default();
    let none: CapNone = Default::default();
    let _narrowed: CapNone = narrow::<CapNone, All>(&none);
    let _self: All = narrow::<All, All>(&all);

    // The following would NOT compile (proven by compile_fail doctests in cap.rs):
    // let _widened: All = narrow::<All, CapNone>(&all);
    // struct FakeCaps;
    // impl asupersync::cx::HasSpawn for FakeCaps {}  // sealed trait

    test_complete!("ambient_authority_rejected_by_sealing");
}

// ============================================================================
// ObligationToken typestate property tests
// ============================================================================

#[test]
fn obligation_token_commit_returns_correct_proof() {
    init_test_logging();
    test_phase!("obligation_token_commit_returns_correct_proof");

    let token = ObligationToken::<SendPermit>::reserve("prop-commit");
    let proof = token.commit();
    assert_eq!(proof.kind(), ObligationKind::SendPermit);

    let token = ObligationToken::<AckKind>::reserve("prop-commit-ack");
    let proof = token.commit();
    assert_eq!(proof.kind(), ObligationKind::Ack);

    let token = ObligationToken::<LeaseKind>::reserve("prop-commit-lease");
    let proof = token.commit();
    assert_eq!(proof.kind(), ObligationKind::Lease);

    let token = ObligationToken::<IoOpKind>::reserve("prop-commit-io");
    let proof = token.commit();
    assert_eq!(proof.kind(), ObligationKind::IoOp);

    test_complete!("obligation_token_commit_returns_correct_proof");
}

#[test]
fn obligation_token_abort_returns_correct_proof() {
    init_test_logging();
    test_phase!("obligation_token_abort_returns_correct_proof");

    let token = ObligationToken::<SendPermit>::reserve("prop-abort");
    let proof = token.abort();
    assert_eq!(proof.kind(), ObligationKind::SendPermit);

    let token = ObligationToken::<AckKind>::reserve("prop-abort-ack");
    let proof = token.abort();
    assert_eq!(proof.kind(), ObligationKind::Ack);

    test_complete!("obligation_token_abort_returns_correct_proof");
}

#[test]
fn obligation_token_into_raw_disarms() {
    init_test_logging();
    test_phase!("obligation_token_into_raw_disarms");

    let token = ObligationToken::<LeaseKind>::reserve("raw-escape");
    let raw = token.into_raw();
    assert_eq!(raw.kind, ObligationKind::Lease);
    drop(raw); // Should not panic.

    test_complete!("obligation_token_into_raw_disarms");
}

#[test]
#[should_panic(expected = "OBLIGATION TOKEN LEAKED")]
fn obligation_token_drop_bomb_fires() {
    let _token = ObligationToken::<SendPermit>::reserve("leaked");
    // Dropped without commit/abort — panics.
}

#[test]
#[should_panic(expected = "OBLIGATION LEAKED")]
fn graded_obligation_drop_bomb_fires() {
    let _ob = GradedObligation::reserve(ObligationKind::IoOp, "leaked-io");
    // Dropped without resolve — panics.
}

// ============================================================================
// Macro integration with property-generated data
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// obligation_body! macro produces correct results for random kinds.
    #[test]
    fn macro_with_random_kind(
        kind in arb_obligation_kind(),
    ) {
        let body = obligation_body!("prop_macro", |b| {
            let v = b.reserve(kind);
            b.commit(v);
        });
        let mut checker = LeakChecker::new();
        prop_assert!(checker.check(&body).is_clean());
    }

    /// assert_no_leaks! macro passes for any properly resolved obligation.
    #[test]
    fn assert_no_leaks_with_random_kind(
        kind in arb_obligation_kind(),
    ) {
        assert_no_leaks!("prop_assert", |b| {
            let v = b.reserve(kind);
            b.commit(v);
        });
    }

    /// assert_has_leaks! macro correctly detects one leaked obligation.
    #[test]
    fn assert_has_leaks_with_random_kind(
        kind in arb_obligation_kind(),
    ) {
        let body = obligation_body!("prop_leak", |b| {
            let _v = b.reserve(kind);
        });
        assert_has_leaks!(body, 1);
    }
}

// ============================================================================
// Combined: BodyBuilder + LeakChecker determinism
// ============================================================================

#[test]
fn checker_deterministic_across_runs() {
    init_test_logging();
    test_phase!("checker_deterministic_across_runs");

    let build = || {
        let mut b = BodyBuilder::new("determinism");
        let v0 = b.reserve(ObligationKind::SendPermit);
        let v1 = b.reserve(ObligationKind::Ack);
        let v2 = b.reserve(ObligationKind::Lease);
        b.commit(v0);
        b.branch(|bb| {
            bb.arm(|a| { a.commit(v1); a.commit(v2); });
            bb.arm(|a| { a.abort(v1); });
        });
        b.build()
    };

    let mut checker = LeakChecker::new();
    let r1 = checker.check(&build());
    let r2 = checker.check(&build());
    let r3 = checker.check(&build());

    assert_eq!(r1.diagnostics.len(), r2.diagnostics.len());
    assert_eq!(r2.diagnostics.len(), r3.diagnostics.len());
    for (a, b) in r1.diagnostics.iter().zip(r2.diagnostics.iter()) {
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.var, b.var);
        assert_eq!(a.obligation_kind, b.obligation_kind);
    }

    test_complete!("checker_deterministic_across_runs");
}
