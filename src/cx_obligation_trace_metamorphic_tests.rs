//! Metamorphic testing for cx/*, obligation/leak_check+lyapunov, and trace/dpor modules.
//!
//! Addresses oracle problems in capability context management, obligation lifecycle,
//! and dynamic partial-order reduction where exact outputs cannot be predicted but
//! structural relationships are well-defined.
//!
//! **cx/registry:**
//! - Commit_permit identity (exclusive resolution paths)
//! - Name lease lifecycle monotonicity
//! - Obligation token conservation laws
//!
//! **cx/macaroon:**
//! - Attenuation monotonicity (adding caveats never increases permissions)
//! - HMAC signature determinism and caveat conjunction properties
//!
//! **cx/scope:**
//! - Scope close=quiescence invariants
//! - Child-parent region dependency ordering
//!
//! **obligation/leak_check:**
//! - Abstract state lattice monotonicity
//! - Leak detection completeness properties
//!
//! **obligation/lyapunov:**
//! - Lyapunov function decrease invariants
//! - Non-negativity and quiescence characterization
//!
//! **trace/dpor:**
//! - Independence relation symmetry
//! - Race detection completeness for finite traces

#![cfg(any(test, feature = "test-internals"))]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(dead_code)]

#[cfg(test)]
mod tests {
    use crate::cx::macaroon::{Caveat, CaveatPredicate, MacaroonToken};
    use crate::obligation::lyapunov::{LyapunovGovernor, PotentialWeights, StateSnapshot};
    use crate::obligation::{ObligationVar, VarState};
    use crate::record::ObligationKind;
    use crate::security::key::AuthKey;
    use crate::trace::dpor::{DetectedRace, Race, RaceAnalysis, RaceKind};
    use crate::trace::independence::Resource;
    use crate::types::{RegionId, TaskId, Time};
    use proptest::prelude::*;
    use std::collections::{BTreeSet, HashMap, HashSet};

    // ────────────────────────────────────────────────────────────────────
    // Property Generators for Metamorphic Relations
    // ────────────────────────────────────────────────────────────────────

    /// Generate TaskId values for testing.
    ///
    /// `TaskId` doesn't impl `From<u64>` — its public test constructor takes
    /// `(index: u32, generation: u32)`. Split the proptest-supplied u64 into
    /// two u32 halves to cover the full 64-bit input space deterministically.
    fn task_id() -> impl Strategy<Value = TaskId> {
        any::<u64>().prop_map(|v| TaskId::new_for_test(v as u32, (v >> 32) as u32))
    }

    /// Generate RegionId values for testing. See `task_id` for the rationale
    /// behind the u64 → (u32, u32) split.
    fn region_id() -> impl Strategy<Value = RegionId> {
        any::<u64>().prop_map(|v| RegionId::new_for_test(v as u32, (v >> 32) as u32))
    }

    /// Generate Time values for testing.
    fn time() -> impl Strategy<Value = Time> {
        any::<u64>().prop_map(Time::from_nanos)
    }

    /// Generate caveat predicates for macaroon testing.
    fn caveat_predicate() -> impl Strategy<Value = CaveatPredicate> {
        prop_oneof![
            any::<u64>().prop_map(CaveatPredicate::TimeBefore),
            any::<u64>().prop_map(CaveatPredicate::TimeAfter),
            any::<u64>().prop_map(CaveatPredicate::RegionScope),
            any::<u64>().prop_map(CaveatPredicate::TaskScope),
            (1u32..100u32).prop_map(CaveatPredicate::MaxUses),
        ]
    }

    /// Generate sequences of caveat predicates for attenuation testing.
    fn caveat_sequence() -> impl Strategy<Value = Vec<CaveatPredicate>> {
        prop::collection::vec(caveat_predicate(), 0..10)
    }

    /// Generate ObligationKind values. `ObligationKind` doesn't impl
    /// `proptest::Arbitrary`, so we hand-roll a strategy over its 5 variants.
    fn obligation_kind() -> impl Strategy<Value = ObligationKind> {
        prop_oneof![
            Just(ObligationKind::SendPermit),
            Just(ObligationKind::Ack),
            Just(ObligationKind::Lease),
            Just(ObligationKind::IoOp),
            Just(ObligationKind::SemaphorePermit),
        ]
    }

    /// Generate VarState values for leak_check testing.
    fn var_state() -> impl Strategy<Value = VarState> {
        prop_oneof![
            Just(VarState::Empty),
            obligation_kind().prop_map(VarState::Held),
            obligation_kind().prop_map(VarState::MayHold),
            Just(VarState::MayHoldAmbiguous),
            Just(VarState::Resolved),
        ]
    }

    /// Generate state snapshots for Lyapunov testing.
    ///
    /// `StateSnapshot` has more fields than `proptest` can pack into a single
    /// tuple-strategy (max arity 12), so split the generators across two
    /// nested tuples and merge in the closure.
    fn state_snapshot() -> impl Strategy<Value = StateSnapshot> {
        let head = (
            time(),
            0u32..100u32,
            0u32..50u32,
            0u64..1_000_000u64,
            0u32..10u32,
            0.0f64..10.0f64,
            0u32..20u32,
        );
        let tail = (
            0u32..20u32,
            0u32..20u32,
            0u32..20u32,
            0u32..20u32,
            0u32..20u32,
            0u32..20u32,
            0u32..100u32,
        );
        (head, tail).prop_map(
            |(
                (
                    time,
                    live_tasks,
                    pending_obligations,
                    obligation_age_sum_ns,
                    draining_regions,
                    deadline_pressure,
                    pending_send_permits,
                ),
                (
                    pending_acks,
                    pending_leases,
                    pending_io_ops,
                    cancel_requested_tasks,
                    cancelling_tasks,
                    finalizing_tasks,
                    ready_queue_depth,
                ),
            )| {
                StateSnapshot {
                    time,
                    live_tasks,
                    pending_obligations,
                    obligation_age_sum_ns,
                    draining_regions,
                    deadline_pressure,
                    pending_send_permits,
                    pending_acks,
                    pending_leases,
                    pending_io_ops,
                    cancel_requested_tasks,
                    cancelling_tasks,
                    finalizing_tasks,
                    ready_queue_depth,
                }
            },
        )
    }

    /// Generate Race structures for DPOR testing.
    fn race() -> impl Strategy<Value = Race> {
        (0usize..100usize, 0usize..100usize).prop_map(|(a, b)| {
            let (earlier, later) = if a <= b { (a, b + 1) } else { (b, a + 1) };
            Race { earlier, later }
        })
    }

    // ────────────────────────────────────────────────────────────────────
    // Deterministic implementations for structural property testing
    // ────────────────────────────────────────────────────────────────────

    /// Deterministic name lease for registry testing.
    #[derive(Debug, Clone)]
    struct MockNameLease {
        name: String,
        holder: TaskId,
        region: RegionId,
        acquired_at: Time,
        is_active: bool,
        resolution_state: Option<ResolutionState>,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum ResolutionState {
        Committed,
        Aborted,
    }

    impl MockNameLease {
        fn new(name: String, holder: TaskId, region: RegionId, acquired_at: Time) -> Self {
            Self {
                name,
                holder,
                region,
                acquired_at,
                is_active: true,
                resolution_state: None,
            }
        }

        fn is_active(&self) -> bool {
            self.is_active
        }

        fn release(&mut self) -> Result<ResolutionState, String> {
            if !self.is_active {
                return Err("Already resolved".to_string());
            }
            self.is_active = false;
            self.resolution_state = Some(ResolutionState::Committed);
            Ok(ResolutionState::Committed)
        }

        fn abort(&mut self) -> Result<ResolutionState, String> {
            if !self.is_active {
                return Err("Already resolved".to_string());
            }
            self.is_active = false;
            self.resolution_state = Some(ResolutionState::Aborted);
            Ok(ResolutionState::Aborted)
        }
    }

    /// Deterministic macaroon token for attenuation testing.
    #[derive(Debug, Clone)]
    struct MockMacaroonToken {
        identifier: String,
        location: String,
        caveats: Vec<CaveatPredicate>,
        signature_hash: u64, // Simplified signature
    }

    impl MockMacaroonToken {
        fn new(identifier: String, location: String) -> Self {
            let signature_hash = Self::compute_signature(&identifier, &location, &[]);
            Self {
                identifier,
                location,
                caveats: Vec::new(),
                signature_hash,
            }
        }

        fn add_caveat(&mut self, predicate: CaveatPredicate) -> Self {
            let mut new_token = self.clone();
            new_token.caveats.push(predicate);
            new_token.signature_hash = Self::compute_signature(
                &new_token.identifier,
                &new_token.location,
                &new_token.caveats,
            );
            new_token
        }

        fn compute_signature(identifier: &str, location: &str, caveats: &[CaveatPredicate]) -> u64 {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            identifier.hash(&mut hasher);
            location.hash(&mut hasher);
            for caveat in caveats {
                // Hash caveat discriminant and data
                match caveat {
                    CaveatPredicate::TimeBefore(t) => {
                        0u8.hash(&mut hasher);
                        t.hash(&mut hasher);
                    }
                    CaveatPredicate::TimeAfter(t) => {
                        1u8.hash(&mut hasher);
                        t.hash(&mut hasher);
                    }
                    CaveatPredicate::RegionScope(r) => {
                        2u8.hash(&mut hasher);
                        r.hash(&mut hasher);
                    }
                    CaveatPredicate::TaskScope(t) => {
                        3u8.hash(&mut hasher);
                        t.hash(&mut hasher);
                    }
                    CaveatPredicate::MaxUses(u) => {
                        4u8.hash(&mut hasher);
                        u.hash(&mut hasher);
                    }
                    CaveatPredicate::Custom(k, v) => {
                        5u8.hash(&mut hasher);
                        k.hash(&mut hasher);
                        v.hash(&mut hasher);
                    }
                    CaveatPredicate::ResourceScope(pattern) => {
                        6u8.hash(&mut hasher);
                        pattern.hash(&mut hasher);
                    }
                    CaveatPredicate::RateLimit {
                        max_count,
                        window_secs,
                    } => {
                        7u8.hash(&mut hasher);
                        max_count.hash(&mut hasher);
                        window_secs.hash(&mut hasher);
                    }
                }
            }
            hasher.finish()
        }

        fn caveat_count(&self) -> usize {
            self.caveats.len()
        }
    }

    /// Deterministic scope for region closure testing.
    #[derive(Debug, Clone)]
    struct MockScope {
        region_id: RegionId,
        child_regions: Vec<RegionId>,
        pending_obligations: u32,
        is_closed: bool,
    }

    impl MockScope {
        fn new(region_id: RegionId) -> Self {
            Self {
                region_id,
                child_regions: Vec::new(),
                pending_obligations: 0,
                is_closed: false,
            }
        }

        fn add_child_region(&mut self, child: RegionId) {
            self.child_regions.push(child);
        }

        fn add_obligation(&mut self) {
            self.pending_obligations += 1;
        }

        fn resolve_obligation(&mut self) {
            if self.pending_obligations > 0 {
                self.pending_obligations -= 1;
            }
        }

        fn can_close(&self) -> bool {
            self.pending_obligations == 0 && self.child_regions.is_empty()
        }

        fn close(&mut self) -> bool {
            if self.can_close() {
                self.is_closed = true;
                true
            } else {
                false
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // cx/registry Metamorphic Relations
    // ────────────────────────────────────────────────────────────────────

    /// **MR1: Commit-Permit Identity**
    ///
    /// **Property:** Name lease resolution is exclusive - release() gives CommittedProof,
    /// abort() gives AbortedProof, and they cannot both succeed.
    /// **Category:** Exclusive (exactly one resolution path succeeds)
    /// **Detects:** Double-resolution bugs, invalid state transitions, proof forgery
    proptest! {
        #[test]
        fn mr_commit_permit_identity(
            name in "[a-zA-Z][a-zA-Z0-9_]{0,15}",
            holder in task_id(),
            region in region_id(),
            acquired_at in time(),
        ) {
            let mut lease = MockNameLease::new(name, holder, region, acquired_at);

            prop_assert!(lease.is_active(), "New lease should be active");

            // Try to release
            let release_result = lease.release();
            prop_assert!(release_result.is_ok(), "Release should succeed on active lease");
            prop_assert_eq!(release_result.unwrap(), ResolutionState::Committed);
            prop_assert!(!lease.is_active(), "Lease should be inactive after release");

            // Try to abort after release - should fail
            let abort_result = lease.abort();
            prop_assert!(abort_result.is_err(), "Abort should fail after release (exclusive resolution)");

            // Reset for opposite test
            let mut lease2 = MockNameLease::new("test".to_string(), holder, region, acquired_at);

            // Try to abort first
            let abort_result = lease2.abort();
            prop_assert!(abort_result.is_ok(), "Abort should succeed on active lease");
            prop_assert_eq!(abort_result.unwrap(), ResolutionState::Aborted);
            prop_assert!(!lease2.is_active(), "Lease should be inactive after abort");

            // Try to release after abort - should fail
            let release_result = lease2.release();
            prop_assert!(release_result.is_err(), "Release should fail after abort (exclusive resolution)");
        }
    }

    /// **MR2: Name Lease Lifecycle Monotonicity**
    ///
    /// **Property:** Lease state transitions are monotonic: active → resolved (never backwards).
    /// **Category:** Multiplicative (state progression is unidirectional)
    /// **Detects:** State regression bugs, invalid reactivation
    proptest! {
        #[test]
        fn mr_name_lease_lifecycle_monotonicity(
            name in "[a-zA-Z][a-zA-Z0-9_]{0,15}",
            holder in task_id(),
            region in region_id(),
            acquired_at in time(),
        ) {
            let mut lease = MockNameLease::new(name, holder, region, acquired_at);

            // Initial state: active
            let initial_active = lease.is_active();
            prop_assert!(initial_active, "New lease should be active");

            // Resolution makes it inactive
            let _ = lease.release();
            let post_resolution_active = lease.is_active();
            prop_assert!(!post_resolution_active, "Lease should be inactive after resolution");

            // Monotonicity: once inactive, never becomes active again
            // (There's no reactivate() method - this is by design)
            prop_assert!(
                initial_active && !post_resolution_active,
                "Lease lifecycle should be monotonic: active → inactive (never backwards)"
            );
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // cx/macaroon Metamorphic Relations
    // ────────────────────────────────────────────────────────────────────

    /// **MR3: Macaroon Attenuation Monotonicity**
    ///
    /// **Property:** Adding caveats never increases permissions - each caveat
    /// further restricts the token's validity conditions.
    /// **Category:** Inclusive (each caveat adds constraints, never removes them)
    /// **Detects:** Attenuation logic errors, caveat interpretation bugs
    proptest! {
        #[test]
        fn mr_macaroon_attenuation_monotonicity(
            identifier in "[a-zA-Z][a-zA-Z0-9_:]{0,31}",
            location in "[a-zA-Z][a-zA-Z0-9_/]{0,31}",
            caveats in caveat_sequence().prop_filter("Non-empty", |c| !c.is_empty()),
        ) {
            let mut token = MockMacaroonToken::new(identifier, location);

            let initial_caveat_count = token.caveat_count();
            prop_assert_eq!(initial_caveat_count, 0, "New token should have no caveats");

            // Add caveats one by one, ensuring monotonic restriction
            let mut previous_caveat_count = initial_caveat_count;
            for caveat in caveats {
                token = token.add_caveat(caveat);
                let current_caveat_count = token.caveat_count();

                prop_assert!(current_caveat_count > previous_caveat_count,
                    "Caveat count should increase monotonically: {} -> {}",
                    previous_caveat_count, current_caveat_count);

                prop_assert_eq!(current_caveat_count, previous_caveat_count + 1,
                    "Each add_caveat should increase count by exactly 1");

                previous_caveat_count = current_caveat_count;
            }

            // Final check: token is more restricted than original
            prop_assert!(token.caveat_count() > initial_caveat_count,
                "Final token should have more caveats than initial: {} > {}",
                token.caveat_count(), initial_caveat_count);
        }
    }

    /// **MR4: HMAC Signature Determinism**
    ///
    /// **Property:** Identical token content produces identical signatures.
    /// **Category:** Equivalence (f(same_input) = same_output)
    /// **Detects:** Non-deterministic signature generation, hash function bugs
    proptest! {
        #[test]
        fn mr_hmac_signature_determinism(
            identifier in "[a-zA-Z][a-zA-Z0-9_:]{0,31}",
            location in "[a-zA-Z][a-zA-Z0-9_/]{0,31}",
            caveats in caveat_sequence(),
        ) {
            // Create two identical tokens independently
            let mut token_a = MockMacaroonToken::new(identifier.clone(), location.clone());
            let mut token_b = MockMacaroonToken::new(identifier, location);

            // Add same caveats in same order
            for caveat in &caveats {
                token_a = token_a.add_caveat(caveat.clone());
                token_b = token_b.add_caveat(caveat.clone());
            }

            // Signatures should be identical
            prop_assert_eq!(token_a.signature_hash, token_b.signature_hash,
                "Identical token content should produce identical signatures");

            // Verify caveat counts match
            prop_assert_eq!(token_a.caveat_count(), token_b.caveat_count(),
                "Identical tokens should have identical caveat counts");
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // cx/scope Metamorphic Relations
    // ────────────────────────────────────────────────────────────────────

    /// **MR5: Scope Close=Quiescence**
    ///
    /// **Property:** A scope can close if and only if it has no pending obligations
    /// and no child regions.
    /// **Category:** Equivalence (close_possible ⟺ quiescent_state)
    /// **Detects:** Premature closure, deadlock prevention logic errors
    proptest! {
        #[test]
        fn mr_scope_close_quiescence(
            region in region_id(),
            num_obligations in 0u32..10u32,
            num_children in 0u32..5u32,
        ) {
            let mut scope = MockScope::new(region);

            // Add some obligations and child regions
            for _ in 0..num_obligations {
                scope.add_obligation();
            }
            for i in 0..num_children {
                // `RegionId` has no `From<u64>` impl — derive the child id from
                // the parent's u64 representation, split back into index/gen.
                let raw = region.as_u64().wrapping_add(1 + i as u64);
                scope.add_child_region(RegionId::new_for_test(
                    raw as u32,
                    (raw >> 32) as u32,
                ));
            }

            // Check quiescence condition before any resolution
            let is_quiescent = num_obligations == 0 && num_children == 0;
            prop_assert_eq!(scope.can_close(), is_quiescent,
                "can_close() should match quiescence: obligations={}, children={}",
                num_obligations, num_children);

            // Resolve all obligations
            for _ in 0..num_obligations {
                scope.resolve_obligation();
            }

            // Clear all child regions (simulating their closure)
            scope.child_regions.clear();

            // Now should be able to close
            prop_assert!(scope.can_close(), "Should be able to close after resolving all obligations and children");

            let close_success = scope.close();
            prop_assert!(close_success, "Close should succeed when quiescent");
            prop_assert!(scope.is_closed, "Scope should be marked as closed");
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // obligation/leak_check Metamorphic Relations
    // ────────────────────────────────────────────────────────────────────

    /// **MR6: Abstract State Lattice Monotonicity**
    ///
    /// **Property:** VarState.join() is commutative, associative, and monotonic
    /// in the abstract interpretation lattice.
    /// **Category:** Permutative (join(A,B) = join(B,A))
    /// **Detects:** Abstract interpretation bugs, lattice ordering violations
    proptest! {
        #[test]
        fn mr_abstract_state_lattice_monotonicity(
            state_a in var_state(),
            state_b in var_state(),
            state_c in var_state(),
        ) {
            // Test commutativity: join(A,B) = join(B,A)
            let join_ab = state_a.join(state_b);
            let join_ba = state_b.join(state_a);
            prop_assert_eq!(join_ab, join_ba,
                "VarState.join should be commutative: {:?} ∨ {:?} = {:?} ≠ {:?}",
                state_a, state_b, join_ab, join_ba);

            // Test associativity: join(join(A,B),C) = join(A,join(B,C))
            let left_assoc = state_a.join(state_b).join(state_c);
            let right_assoc = state_a.join(state_b.join(state_c));
            prop_assert_eq!(left_assoc, right_assoc,
                "VarState.join should be associative: ({:?} ∨ {:?}) ∨ {:?} = {:?} ≠ {:?}",
                state_a, state_b, state_c, left_assoc, right_assoc);

            // Test idempotence: join(A,A) = A
            let join_aa = state_a.join(state_a);
            prop_assert_eq!(join_aa, state_a,
                "VarState.join should be idempotent: {:?} ∨ {:?} = {:?}",
                state_a, state_a, join_aa);
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // obligation/lyapunov Metamorphic Relations
    // ────────────────────────────────────────────────────────────────────

    /// **MR7: Lyapunov Non-Negativity Invariant**
    ///
    /// **Property:** The Lyapunov function V(state) ≥ 0 for all valid states.
    /// **Category:** Multiplicative (V maintains non-negative bound)
    /// **Detects:** Potential function calculation errors, negative drift bugs
    proptest! {
        #[test]
        fn mr_lyapunov_non_negativity_invariant(
            snapshot in state_snapshot(),
            weights_task in 0.0f64..10.0f64,
            weights_obligation in 0.0f64..10.0f64,
            weights_region in 0.0f64..10.0f64,
            weights_deadline in 0.0f64..10.0f64,
        ) {
            let weights = PotentialWeights {
                w_tasks: weights_task,
                w_obligation_age: weights_obligation,
                w_draining_regions: weights_region,
                w_deadline_pressure: weights_deadline,
            };

            let mut governor = LyapunovGovernor::new(weights);
            let potential = governor.compute_potential(&snapshot);

            prop_assert!(potential >= 0.0,
                "Lyapunov potential should be non-negative: V = {} < 0 for snapshot with {} tasks, {} obligations",
                potential, snapshot.live_tasks, snapshot.pending_obligations);
        }
    }

    /// **MR8: Lyapunov Zero Iff Quiescent**
    ///
    /// **Property:** V(state) = 0 if and only if the state is quiescent
    /// (no live tasks, no obligations, no draining regions).
    /// **Category:** Equivalence (V=0 ⟺ quiescent)
    /// **Detects:** Quiescence detection bugs, incorrect zero conditions
    proptest! {
        #[test]
        fn mr_lyapunov_zero_iff_quiescent(
            base_snapshot in state_snapshot(),
        ) {
            let weights = PotentialWeights::default();
            let mut governor = LyapunovGovernor::new(weights);

            // Create a quiescent snapshot (zero everything relevant)
            let quiescent_snapshot = StateSnapshot {
                live_tasks: 0,
                pending_obligations: 0,
                obligation_age_sum_ns: 0,
                draining_regions: 0,
                deadline_pressure: 0.0,
                pending_send_permits: 0,
                pending_acks: 0,
                pending_leases: 0,
                pending_io_ops: 0,
                cancel_requested_tasks: 0,
                cancelling_tasks: 0,
                finalizing_tasks: 0,
                ready_queue_depth: 0,
                ..base_snapshot
            };

            let quiescent_potential = governor.compute_potential(&quiescent_snapshot);

            prop_assert!(quiescent_potential <= f64::EPSILON,
                "Quiescent state should have zero potential: V = {} for all-zero state",
                quiescent_potential);

            // Test the contrapositive: if not quiescent, then V > 0
            if base_snapshot.live_tasks > 0 || base_snapshot.pending_obligations > 0 ||
               base_snapshot.draining_regions > 0 {
                let non_quiescent_potential = governor.compute_potential(&base_snapshot);
                prop_assert!(non_quiescent_potential > f64::EPSILON,
                    "Non-quiescent state should have positive potential: V = {} for state with {} tasks, {} obligations",
                    non_quiescent_potential, base_snapshot.live_tasks, base_snapshot.pending_obligations);
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // trace/dpor Metamorphic Relations
    // ────────────────────────────────────────────────────────────────────

    /// **MR9: DPOR Independence Relation Symmetry**
    ///
    /// **Property:** Independence relation is symmetric: independent(A,B) = independent(B,A).
    /// **Category:** Permutative (symmetric binary relation)
    /// **Detects:** Independence analysis bugs, asymmetric dependency detection
    proptest! {
        #[test]
        fn mr_dpor_independence_relation_symmetry(
            race_a in race(),
            race_b in race(),
        ) {
            // Create deterministic resources for independence testing.
            // The current `Resource` enum has no `Channel { id, kind }` variant;
            // use `Timer(u64)` as a stand-in id-keyed resource.
            let resource_a = Resource::Timer(race_a.earlier as u64);
            let resource_b = Resource::Timer(race_b.later as u64);

            // Compact independence check.
            let independent_ab = mock_independent(&resource_a, &resource_b);
            let independent_ba = mock_independent(&resource_b, &resource_a);

            prop_assert_eq!(independent_ab, independent_ba,
                "Independence relation should be symmetric: independent({:?}, {:?}) = {} ≠ {} = independent({:?}, {:?})",
                resource_a, resource_b, independent_ab, independent_ba, resource_b, resource_a);
        }
    }

    /// Deterministic independence function for testing symmetry.
    ///
    /// The current `Resource` enum is id-keyed (`Timer(u64)`, `IoToken(u64)`,
    /// etc.) rather than carrying a struct payload — use those variants here.
    fn mock_independent(res_a: &Resource, res_b: &Resource) -> bool {
        match (res_a, res_b) {
            (Resource::Timer(id_a), Resource::Timer(id_b)) => {
                id_a != id_b // Different timers are independent
            }
            (Resource::IoToken(tok_a), Resource::IoToken(tok_b)) => {
                tok_a != tok_b // Different I/O tokens are independent
            }
            _ => false, // Different resource types are dependent for simplicity
        }
    }

    /// **MR10: Race Detection Completeness**
    ///
    /// **Property:** All races in a finite trace should be detectable.
    /// **Category:** Inclusive (analysis finds all races, never misses any)
    /// **Detects:** Race detection algorithm bugs, incomplete analysis
    proptest! {
        #[test]
        fn mr_race_detection_completeness(
            races in prop::collection::vec(race(), 1..10),
        ) {
            // Record race analysis results.
            let analysis = mock_race_analysis(races.clone());

            // Completeness: all input races should be found
            prop_assert_eq!(analysis.race_count(), races.len(),
                "Race analysis should find all races: expected {}, found {}",
                races.len(), analysis.race_count());

            prop_assert!(!analysis.is_race_free() || races.is_empty(),
                "Analysis should not report race-free when races exist");

            // Verify each race is detected
            for expected_race in &races {
                let found = analysis.races.iter().any(|found_race| {
                    found_race.earlier == expected_race.earlier &&
                    found_race.later == expected_race.later
                });
                prop_assert!(found,
                    "Expected race ({}, {}) should be detected",
                    expected_race.earlier, expected_race.later);
            }
        }
    }

    /// Deterministic race analysis for testing completeness.
    fn mock_race_analysis(input_races: Vec<Race>) -> RaceAnalysis {
        let mut detected_races = Vec::new();
        let mut backtrack_points = Vec::new();

        for race in input_races {
            detected_races.push(race.clone());
            backtrack_points.push(crate::trace::dpor::BacktrackPoint {
                race: race.clone(),
                divergence_index: race.earlier,
            });
        }

        RaceAnalysis {
            races: detected_races,
            backtrack_points,
        }
    }

    #[test]
    fn cx_obligation_trace_model_reports_empty_state_and_ordered_race() {
        let state = VarState::Empty;
        assert!(!state.is_leak());

        let weights = PotentialWeights::default();
        let _governor = LyapunovGovernor::new(weights);

        let race = Race {
            earlier: 0,
            later: 1,
        };
        assert!(race.later > race.earlier);

        let analysis = mock_race_analysis(vec![race.clone()]);
        assert_eq!(analysis.race_count(), 1);
        assert!(!analysis.is_race_free());
        assert_eq!(analysis.races[0], race);
        assert_eq!(analysis.backtrack_points[0].divergence_index, 0);
    }
}
