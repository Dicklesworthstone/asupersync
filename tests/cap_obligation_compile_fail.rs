//! Compile-fail emulation and enforcement tests for capability and obligation types.
//!
//! These tests verify that the safety invariants enforced by sealed traits,
//! `#[must_use]`, and drop bombs are maintained. Actual compile-fail tests
//! are in doctests on `src/cx/cap.rs` (4 compile_fail doctests). This file
//! supplements those with runtime enforcement tests.
//!
//! # What compile-fail doctests verify (in src/cx/cap.rs):
//!
//! 1. `CapSet` widening is rejected: `widen::<GrpcCaps, WebCaps>()` fails
//! 2. `None` cannot widen: `widen::<SpawnOnly, None>()` fails
//! 3. `HasSpawn` cannot be forged: `impl HasSpawn for FakeCaps {}` fails
//! 4. `SubsetOf` cannot be forged: `impl SubsetOf<FakeCaps> for FakeCaps {}` fails

mod common;
use common::*;

use asupersync::cx::cap::{All, CapSet, None as CapNone};
use asupersync::obligation::graded::{
    GradedObligation, GradedScope, ObligationToken, Resolution, SendPermit, AckKind, LeaseKind,
    IoOpKind, SendPermitToken, AckToken, LeaseToken, IoOpToken,
};
use asupersync::record::ObligationKind;

// ==================== Drop Bomb Enforcement ====================

#[test]
#[should_panic(expected = "OBLIGATION LEAKED")]
fn graded_obligation_panics_on_drop_without_resolve() {
    init_test_logging();
    test_phase!("graded_obligation_panics_on_drop_without_resolve");

    let _ob = GradedObligation::reserve(ObligationKind::SendPermit, "leaked-send");
    // Dropped here without resolve → panic.
}

#[test]
#[should_panic(expected = "OBLIGATION LEAKED")]
fn graded_obligation_ack_panics_on_drop() {
    let _ob = GradedObligation::reserve(ObligationKind::Ack, "leaked-ack");
}

#[test]
#[should_panic(expected = "OBLIGATION LEAKED")]
fn graded_obligation_lease_panics_on_drop() {
    let _ob = GradedObligation::reserve(ObligationKind::Lease, "leaked-lease");
}

#[test]
#[should_panic(expected = "OBLIGATION LEAKED")]
fn graded_obligation_io_panics_on_drop() {
    let _ob = GradedObligation::reserve(ObligationKind::IoOp, "leaked-io");
}

#[test]
#[should_panic(expected = "OBLIGATION TOKEN LEAKED")]
fn obligation_token_send_panics_on_drop() {
    let _token: SendPermitToken = ObligationToken::reserve("leaked");
}

#[test]
#[should_panic(expected = "OBLIGATION TOKEN LEAKED")]
fn obligation_token_ack_panics_on_drop() {
    let _token: AckToken = ObligationToken::reserve("leaked");
}

#[test]
#[should_panic(expected = "OBLIGATION TOKEN LEAKED")]
fn obligation_token_lease_panics_on_drop() {
    let _token: LeaseToken = ObligationToken::reserve("leaked");
}

#[test]
#[should_panic(expected = "OBLIGATION TOKEN LEAKED")]
fn obligation_token_io_panics_on_drop() {
    let _token: IoOpToken = ObligationToken::reserve("leaked");
}

#[test]
#[should_panic(expected = "SCOPE LEAKED")]
fn graded_scope_panics_on_drop_with_outstanding() {
    let mut scope = GradedScope::open("leaked-scope");
    scope.on_reserve();
    // Drop without close or resolving → panic.
}

// ==================== Correct Resolution (No Panic) ====================

#[test]
fn graded_obligation_commit_no_panic() {
    init_test_logging();
    test_phase!("graded_obligation_commit_no_panic");

    let ob = GradedObligation::reserve(ObligationKind::SendPermit, "send");
    assert!(!ob.is_resolved());
    assert_eq!(ob.kind(), ObligationKind::SendPermit);
    let proof = ob.resolve(Resolution::Commit);
    assert_eq!(proof.kind, ObligationKind::SendPermit);
    assert_eq!(proof.resolution, Resolution::Commit);

    test_complete!("graded_obligation_commit_no_panic");
}

#[test]
fn graded_obligation_abort_no_panic() {
    init_test_logging();
    test_phase!("graded_obligation_abort_no_panic");

    let ob = GradedObligation::reserve(ObligationKind::Lease, "lease");
    let proof = ob.resolve(Resolution::Abort);
    assert_eq!(proof.resolution, Resolution::Abort);

    test_complete!("graded_obligation_abort_no_panic");
}

#[test]
fn graded_obligation_into_raw_disarms() {
    init_test_logging();
    test_phase!("graded_obligation_into_raw_disarms");

    let ob = GradedObligation::reserve(ObligationKind::IoOp, "io");
    let raw = ob.into_raw();
    assert_eq!(raw.kind, ObligationKind::IoOp);
    drop(raw); // No panic.

    test_complete!("graded_obligation_into_raw_disarms");
}

#[test]
fn obligation_token_commit_no_panic() {
    init_test_logging();
    test_phase!("obligation_token_commit_no_panic");

    let token: SendPermitToken = ObligationToken::reserve("send");
    let proof = token.commit();
    assert_eq!(proof.kind(), ObligationKind::SendPermit);

    let token: AckToken = ObligationToken::reserve("ack");
    let proof = token.commit();
    assert_eq!(proof.kind(), ObligationKind::Ack);

    let token: LeaseToken = ObligationToken::reserve("lease");
    let proof = token.commit();
    assert_eq!(proof.kind(), ObligationKind::Lease);

    let token: IoOpToken = ObligationToken::reserve("io");
    let proof = token.commit();
    assert_eq!(proof.kind(), ObligationKind::IoOp);

    test_complete!("obligation_token_commit_no_panic");
}

#[test]
fn obligation_token_abort_no_panic() {
    init_test_logging();
    test_phase!("obligation_token_abort_no_panic");

    let token: SendPermitToken = ObligationToken::reserve("send");
    let proof = token.abort();
    assert_eq!(proof.kind(), ObligationKind::SendPermit);

    let token: IoOpToken = ObligationToken::reserve("io");
    let proof = token.abort();
    assert_eq!(proof.kind(), ObligationKind::IoOp);

    test_complete!("obligation_token_abort_no_panic");
}

#[test]
fn obligation_token_into_raw_disarms() {
    init_test_logging();
    test_phase!("obligation_token_into_raw_disarms");

    let token: LeaseToken = ObligationToken::reserve("lease");
    let raw = token.into_raw();
    assert_eq!(raw.kind, ObligationKind::Lease);
    drop(raw); // No panic.

    test_complete!("obligation_token_into_raw_disarms");
}

// ==================== Proof Token Properties ====================

#[test]
fn committed_proof_bridges_to_resolved() {
    init_test_logging();
    test_phase!("committed_proof_bridges_to_resolved");

    let token: SendPermitToken = ObligationToken::reserve("bridge");
    let committed = token.commit();
    let resolved = committed.into_resolved_proof();
    assert_eq!(resolved.kind, ObligationKind::SendPermit);
    assert_eq!(resolved.resolution, Resolution::Commit);

    test_complete!("committed_proof_bridges_to_resolved");
}

#[test]
fn aborted_proof_bridges_to_resolved() {
    init_test_logging();
    test_phase!("aborted_proof_bridges_to_resolved");

    let token: AckToken = ObligationToken::reserve("bridge");
    let aborted = token.abort();
    let resolved = aborted.into_resolved_proof();
    assert_eq!(resolved.kind, ObligationKind::Ack);
    assert_eq!(resolved.resolution, Resolution::Abort);

    test_complete!("aborted_proof_bridges_to_resolved");
}

// ==================== GradedScope Enforcement ====================

#[test]
fn graded_scope_balanced_closes() {
    init_test_logging();
    test_phase!("graded_scope_balanced_closes");

    let mut scope = GradedScope::open("balanced");
    scope.on_reserve();
    scope.on_reserve();
    scope.on_resolve();
    scope.on_resolve();
    assert_eq!(scope.outstanding(), 0);
    let proof = scope.close().expect("should close cleanly");
    assert_eq!(proof.total_reserved, 2);
    assert_eq!(proof.total_resolved, 2);

    test_complete!("graded_scope_balanced_closes");
}

#[test]
fn graded_scope_unbalanced_returns_error() {
    init_test_logging();
    test_phase!("graded_scope_unbalanced_returns_error");

    let mut scope = GradedScope::open("unbalanced");
    scope.on_reserve();
    scope.on_reserve();
    scope.on_resolve();
    assert_eq!(scope.outstanding(), 1);

    let err = scope.close().expect_err("should fail");
    assert_eq!(err.outstanding, 1);
    assert_eq!(err.reserved, 2);
    assert_eq!(err.resolved, 1);
    let msg = format!("{err}");
    assert!(msg.contains("leaked"));

    test_complete!("graded_scope_unbalanced_returns_error");
}

#[test]
fn graded_scope_empty_closes_cleanly() {
    init_test_logging();
    test_phase!("graded_scope_empty_closes_cleanly");

    let scope = GradedScope::open("empty");
    let proof = scope.close().expect("empty scope should close");
    assert_eq!(proof.total_reserved, 0);

    test_complete!("graded_scope_empty_closes_cleanly");
}

#[test]
fn graded_scope_empty_drop_no_panic() {
    init_test_logging();
    test_phase!("graded_scope_empty_drop_no_panic");

    let _scope = GradedScope::open("empty-drop");
    // Drop without close — OK because no outstanding obligations.

    test_complete!("graded_scope_empty_drop_no_panic");
}

// ==================== Scope + Token Integration ====================

#[test]
fn scope_reserve_and_commit_token() {
    init_test_logging();
    test_phase!("scope_reserve_and_commit_token");

    let mut scope = GradedScope::open("token-scope");
    let token: SendPermitToken = scope.reserve_token("send");
    assert_eq!(scope.outstanding(), 1);

    let proof = scope.resolve_commit(token);
    assert_eq!(scope.outstanding(), 0);
    assert_eq!(proof.kind(), ObligationKind::SendPermit);

    let scope_proof = scope.close().expect("should close");
    assert_eq!(scope_proof.total_reserved, 1);

    test_complete!("scope_reserve_and_commit_token");
}

#[test]
fn scope_reserve_and_abort_token() {
    init_test_logging();
    test_phase!("scope_reserve_and_abort_token");

    let mut scope = GradedScope::open("token-scope-abort");
    let token: AckToken = scope.reserve_token("ack");
    let proof = scope.resolve_abort(token);
    assert_eq!(proof.kind(), ObligationKind::Ack);

    let scope_proof = scope.close().expect("should close");
    assert_eq!(scope_proof.total_reserved, 1);

    test_complete!("scope_reserve_and_abort_token");
}

#[test]
fn scope_multiple_token_kinds() {
    init_test_logging();
    test_phase!("scope_multiple_token_kinds");

    let mut scope = GradedScope::open("multi-token");
    let send: SendPermitToken = scope.reserve_token("send");
    let ack: AckToken = scope.reserve_token("ack");
    let lease: LeaseToken = scope.reserve_token("lease");
    let io: IoOpToken = scope.reserve_token("io");

    assert_eq!(scope.outstanding(), 4);

    let _ = scope.resolve_commit(send);
    let _ = scope.resolve_abort(ack);
    let _ = scope.resolve_commit(lease);
    let _ = scope.resolve_abort(io);

    assert_eq!(scope.outstanding(), 0);
    let proof = scope.close().expect("should close");
    assert_eq!(proof.total_reserved, 4);
    assert_eq!(proof.total_resolved, 4);

    test_complete!("scope_multiple_token_kinds");
}

// ==================== Capability Subset Lattice ====================

#[test]
fn cap_none_subset_of_everything() {
    init_test_logging();
    test_phase!("cap_none_subset_of_everything");

    fn assert_subset<Sub: asupersync::cx::cap::SubsetOf<Super>, Super>() {}

    assert_subset::<CapNone, All>();
    assert_subset::<CapNone, CapSet<true, false, false, false, false>>();
    assert_subset::<CapNone, CapSet<false, true, false, false, false>>();
    assert_subset::<CapNone, CapSet<false, false, true, false, false>>();
    assert_subset::<CapNone, CapSet<false, false, false, true, false>>();
    assert_subset::<CapNone, CapSet<false, false, false, false, true>>();
    assert_subset::<CapNone, CapNone>(); // Reflexive.

    test_complete!("cap_none_subset_of_everything");
}

#[test]
fn cap_all_subset_only_of_self() {
    init_test_logging();
    test_phase!("cap_all_subset_only_of_self");

    fn assert_subset<Sub: asupersync::cx::cap::SubsetOf<Super>, Super>() {}

    // All ⊆ All (reflexive).
    assert_subset::<All, All>();
    // All is NOT a subset of anything smaller — verified by compile_fail doctests.

    test_complete!("cap_all_subset_only_of_self");
}

#[test]
fn cap_framework_wrapper_types() {
    init_test_logging();
    test_phase!("cap_framework_wrapper_types");

    fn assert_subset<Sub: asupersync::cx::cap::SubsetOf<Super>, Super>() {}

    // Real-world framework patterns:
    type WebCaps = CapSet<false, true, false, true, false>; // Time + IO.
    type GrpcCaps = CapSet<true, true, false, true, false>; // Spawn + Time + IO.
    type BackgroundCaps = CapSet<true, true, false, false, false>; // Spawn + Time.

    // WebCaps ⊆ GrpcCaps (Web drops Spawn).
    assert_subset::<WebCaps, GrpcCaps>();
    // BackgroundCaps ⊆ GrpcCaps (Background drops IO).
    assert_subset::<BackgroundCaps, GrpcCaps>();
    // None ⊆ WebCaps.
    assert_subset::<CapNone, WebCaps>();
    // All framework types ⊆ All.
    assert_subset::<WebCaps, All>();
    assert_subset::<GrpcCaps, All>();
    assert_subset::<BackgroundCaps, All>();

    test_complete!("cap_framework_wrapper_types");
}

// ==================== TokenKind Mapping ====================

#[test]
fn token_kind_mapping_correct() {
    init_test_logging();
    test_phase!("token_kind_mapping_correct");

    use asupersync::obligation::graded::TokenKind;
    assert_eq!(SendPermit::obligation_kind(), ObligationKind::SendPermit);
    assert_eq!(AckKind::obligation_kind(), ObligationKind::Ack);
    assert_eq!(LeaseKind::obligation_kind(), ObligationKind::Lease);
    assert_eq!(IoOpKind::obligation_kind(), ObligationKind::IoOp);

    test_complete!("token_kind_mapping_correct");
}
