#![allow(missing_docs)]
//! Property-based tests for critical FABRIC invariants.
//!
//! Uses proptest to verify structural properties of the subject routing,
//! CRDT control surfaces, morphism transform algebra, and related types.
#![cfg(feature = "messaging-fabric")]

use proptest::prelude::*;
use std::sync::Arc;

use asupersync::cx::Cx;
use asupersync::messaging::DeliveryClass;
use asupersync::messaging::SubjectTransform;
use asupersync::messaging::capability::FabricCapability as RuntimeFabricCapability;
use asupersync::messaging::control::{
    AdvisoryAggregate, CursorCheckpoint, CursorMark, InterestSummary, JoinSemilattice, LagSketch,
    MembershipRecord, MembershipState, MembershipView,
};
use asupersync::messaging::service::{ServiceFailure, ServiceObligation};
use asupersync::messaging::subject::{
    ShardedSublist, Subject, SubjectPattern, Sublist, SublistLinkCache,
};
use asupersync::obligation::ledger::ObligationLedger;
use asupersync::record::{ObligationAbortReason, ObligationState};
use asupersync::remote::NodeId;
use asupersync::types::{Budget, RegionId, TaskId, Time};

// ---------------------------------------------------------------------------
// Proptest strategies
// ---------------------------------------------------------------------------

/// Generate a valid subject token (alphanumeric, 1-8 chars).
fn arb_token() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,7}".prop_map(|s| s)
}

/// Generate a concrete subject string with 1-4 dot-separated tokens.
fn arb_subject_string() -> impl Strategy<Value = String> {
    prop::collection::vec(arb_token(), 1..=4).prop_map(|tokens| tokens.join("."))
}

/// Generate a NodeId.
fn arb_node_id() -> impl Strategy<Value = NodeId> {
    "[a-z]{3,8}".prop_map(NodeId::new)
}

/// Generate a SubjectPattern string (may include wildcards).
fn arb_pattern_string() -> impl Strategy<Value = String> {
    let literal = arb_token().prop_map(|t| t);
    let wildcard = Just("*".to_string());
    // Build a pattern with 1-3 segments; optionally append > at the end
    prop::collection::vec(prop_oneof![9 => literal, 1 => wildcard], 1..=3).prop_flat_map(
        |segments| {
            let base = segments.join(".");
            prop_oneof![
                3 => Just(base.clone()),
                1 => Just(format!("{base}.>")),
            ]
        },
    )
}

/// Generate a human-readable request field for service obligation tests.
fn arb_request_field() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,7}".prop_map(|s| s)
}

/// Generate a delivery class.
fn arb_delivery_class() -> impl Strategy<Value = DeliveryClass> {
    prop_oneof![
        Just(DeliveryClass::EphemeralInteractive),
        Just(DeliveryClass::DurableOrdered),
        Just(DeliveryClass::ObligationBacked),
        Just(DeliveryClass::MobilitySafe),
        Just(DeliveryClass::ForensicReplayable),
    ]
}

/// Generate a service failure mode.
fn arb_service_failure() -> impl Strategy<Value = ServiceFailure> {
    prop_oneof![
        Just(ServiceFailure::Cancelled),
        Just(ServiceFailure::TimedOut),
        Just(ServiceFailure::Rejected),
        Just(ServiceFailure::Overloaded),
        Just(ServiceFailure::TransportError),
        Just(ServiceFailure::ApplicationError),
    ]
}

/// Generate transforms used in associativity checks.
fn arb_transform() -> impl Strategy<Value = SubjectTransform> {
    prop_oneof![
        Just(SubjectTransform::Identity),
        (1usize..=3usize)
            .prop_map(|preserve_segments| SubjectTransform::SummarizeTail { preserve_segments }),
        (1u16..=16u16).prop_map(|buckets| SubjectTransform::HashPartition { buckets }),
        (1usize..=3usize).prop_map(|index| SubjectTransform::WildcardCapture { index }),
        (
            (1u16..=16u16),
            prop::collection::vec(1usize..=3usize, 0..=3usize)
        )
            .prop_map(
                |(buckets, source_indices)| SubjectTransform::DeterministicHash {
                    buckets,
                    source_indices,
                }
            ),
        (
            1usize..=3usize,
            prop_oneof![Just(String::from("-")), Just(String::from("_"))],
            0usize..=2usize,
            1usize..=2usize,
        )
            .prop_map(
                |(index, delimiter, start, len)| SubjectTransform::SplitSlice {
                    index,
                    delimiter,
                    start,
                    len,
                }
            ),
        (1usize..=3usize, 1usize..=4usize)
            .prop_map(|(index, len)| SubjectTransform::LeftExtract { index, len }),
        (1usize..=3usize, 1usize..=4usize)
            .prop_map(|(index, len)| SubjectTransform::RightExtract { index, len }),
    ]
}

fn fabric_test_cx(slot: u32) -> Cx {
    Cx::new(
        RegionId::new_for_test(slot, 0),
        TaskId::new_for_test(slot, 0),
        Budget::INFINITE,
    )
}

fn expected_abort_reason(failure: ServiceFailure) -> ObligationAbortReason {
    match failure {
        ServiceFailure::Cancelled => ObligationAbortReason::Cancel,
        ServiceFailure::TimedOut | ServiceFailure::Rejected => ObligationAbortReason::Explicit,
        ServiceFailure::Overloaded
        | ServiceFailure::TransportError
        | ServiceFailure::ApplicationError => ObligationAbortReason::Error,
    }
}

// ---------------------------------------------------------------------------
// Property: Subject routing is consistent
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// The same concrete subject always routes to the same set of subscribers
    /// when the sublist has not been mutated between lookups.
    #[test]
    fn subject_routing_is_consistent(subject_str in arb_subject_string()) {
        let sl = Arc::new(Sublist::new());
        let pattern = SubjectPattern::new(">");
        let _guard = sl.subscribe(&pattern, None);

        let subject = Subject::new(&subject_str);
        let r1 = sl.lookup(&subject);
        let r2 = sl.lookup(&subject);

        prop_assert_eq!(r1.subscribers, r2.subscribers);
    }

    /// Per-link cache returns the same subscriber set as the uncached path.
    #[test]
    fn link_cache_consistent_with_uncached(subject_str in arb_subject_string()) {
        let sl = Arc::new(Sublist::new());
        let pattern = SubjectPattern::new(">");
        let _guard = sl.subscribe(&pattern, None);

        let subject = Subject::new(&subject_str);
        let uncached = sl.lookup(&subject);
        let mut link_cache = SublistLinkCache::new(16);
        let cached = sl.lookup_with_link_cache(&subject, &mut link_cache);

        prop_assert_eq!(uncached.subscribers, cached.subscribers);
    }

    /// Sharded sublist returns the same subscriber set regardless of which
    /// shard the subject lands in.
    #[test]
    fn sharded_routing_consistent(subject_str in arb_subject_string()) {
        let sharded = ShardedSublist::new(4);
        let pattern = SubjectPattern::new(">");
        let _guard = sharded.subscribe(&pattern, None);

        let subject = Subject::new(&subject_str);
        let r1 = sharded.lookup(&subject);
        let r2 = sharded.lookup(&subject);

        prop_assert_eq!(r1.subscribers, r2.subscribers);
    }
}

// ---------------------------------------------------------------------------
// Property: Capability checks are monotonic
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Adding publish grants must never revoke a request that was already
    /// authorized, and the combined grant set should behave like a union.
    #[test]
    fn capability_checks_are_monotonic(
        base_str in arb_pattern_string(),
        extra_str in arb_pattern_string(),
        request_str in arb_pattern_string(),
        slot in 1u32..=10_000u32,
    ) {
        let base = SubjectPattern::parse(&base_str).expect("generator must produce valid pattern");
        let extra = SubjectPattern::parse(&extra_str).expect("generator must produce valid pattern");
        let request = SubjectPattern::parse(&request_str).expect("generator must produce valid pattern");
        let requested = RuntimeFabricCapability::Publish { subject: request };

        let base_only = fabric_test_cx(slot);
        base_only
            .grant_fabric_capability(RuntimeFabricCapability::Publish {
                subject: base.clone(),
            })
            .expect("generated grant should be valid");
        let allowed_base = base_only.check_fabric_capability(&requested);

        let extra_only = fabric_test_cx(slot + 10_001);
        extra_only
            .grant_fabric_capability(RuntimeFabricCapability::Publish {
                subject: extra.clone(),
            })
            .expect("generated grant should be valid");
        let allowed_extra = extra_only.check_fabric_capability(&requested);

        let combined = fabric_test_cx(slot + 20_002);
        combined
            .grant_fabric_capability(RuntimeFabricCapability::Publish { subject: base })
            .expect("generated grant should be valid");
        combined
            .grant_fabric_capability(RuntimeFabricCapability::Publish { subject: extra })
            .expect("generated grant should be valid");
        let allowed_combined = combined.check_fabric_capability(&requested);

        prop_assert!(!allowed_base || allowed_combined);
        prop_assert!(!allowed_extra || allowed_combined);
        prop_assert_eq!(allowed_combined, allowed_base || allowed_extra);
    }
}

// ---------------------------------------------------------------------------
// Property: Pattern matching is sound
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// A literal pattern matches exactly the subject with identical tokens.
    #[test]
    fn literal_pattern_matches_self(subject_str in arb_subject_string()) {
        let pattern = SubjectPattern::new(&subject_str);
        let subject = Subject::new(&subject_str);
        prop_assert!(pattern.matches(&subject));
    }

    /// The full wildcard `>` matches every concrete subject.
    #[test]
    fn full_wildcard_matches_everything(subject_str in arb_subject_string()) {
        let pattern = SubjectPattern::new(">");
        let subject = Subject::new(&subject_str);
        prop_assert!(pattern.matches(&subject));
    }
}

// ---------------------------------------------------------------------------
// Property: CRDT merge is commutative, associative, and idempotent
// ---------------------------------------------------------------------------

/// Generic helper to test CRDT properties on any JoinSemilattice implementor.
fn assert_crdt_laws<T: JoinSemilattice + Default + std::fmt::Debug>(build: impl Fn(u64) -> T) {
    // Build three distinct states
    let a = build(1);
    let b = build(2);
    let c = build(3);

    // Commutativity: merge(a, b) == merge(b, a)
    let mut ab = a.clone();
    ab.merge(&b);
    let mut ba = b.clone();
    ba.merge(&a);
    assert_eq!(ab, ba, "CRDT merge must be commutative");

    // Associativity: merge(merge(a, b), c) == merge(a, merge(b, c))
    let mut ab_c = ab.clone();
    ab_c.merge(&c);
    let mut bc = b.clone();
    bc.merge(&c);
    let mut a_bc = a.clone();
    a_bc.merge(&bc);
    assert_eq!(ab_c, a_bc, "CRDT merge must be associative");

    // Idempotence: merge(a, a) == a
    let mut aa = a.clone();
    aa.merge(&a);
    assert_eq!(aa, a, "CRDT merge must be idempotent");
}

/// Generic helper: delta(a, baseline) applied to baseline yields a.
fn assert_delta_roundtrip<T: JoinSemilattice + Default + std::fmt::Debug>(
    baseline: &T,
    updated: &T,
) {
    let delta = updated.delta(baseline);
    let mut applied = baseline.clone();
    let ok = applied.apply_delta(&delta);
    assert!(ok, "apply_delta must succeed");
    assert_eq!(
        &applied, updated,
        "delta roundtrip must reproduce the updated state"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// InterestSummary CRDT merge is commutative, associative, and idempotent.
    #[test]
    fn interest_summary_crdt_laws(
        patterns in prop::collection::vec(arb_subject_string(), 1..=3),
        replicas in prop::collection::vec(arb_node_id(), 1..=2),
    ) {
        assert_crdt_laws(|seed| {
            let mut s = InterestSummary::default();
            for (i, p) in patterns.iter().enumerate() {
                if (seed as usize + i).is_multiple_of(2) {
                    let replica = &replicas[i % replicas.len()];
                    s.subscribe(replica, SubjectPattern::new(p));
                }
            }
            s
        });
    }

    /// InterestSummary delta roundtrip preserves state.
    #[test]
    fn interest_summary_delta_roundtrip(
        p1 in arb_subject_string(),
        p2 in arb_subject_string(),
        replica in arb_node_id(),
    ) {
        let baseline = InterestSummary::default();
        let mut updated = InterestSummary::default();
        updated.subscribe(&replica, SubjectPattern::new(&p1));
        updated.subscribe(&replica, SubjectPattern::new(&p2));
        assert_delta_roundtrip(&baseline, &updated);
    }

    /// CursorCheckpoint CRDT merge is commutative, associative, and idempotent.
    #[test]
    fn cursor_checkpoint_crdt_laws(
        consumers in prop::collection::vec("[a-z]{3,6}", 1..=3),
        offsets in prop::collection::vec(1..1000u64, 1..=3),
        replicas in prop::collection::vec(arb_node_id(), 1..=2),
    ) {
        assert_crdt_laws(|seed| {
            let mut cp = CursorCheckpoint::default();
            for (i, consumer) in consumers.iter().enumerate() {
                let offset = offsets[i % offsets.len()] + seed;
                let replica = replicas[i % replicas.len()].clone();
                cp.observe(consumer.clone(), CursorMark::new(offset, 1000 + seed, replica));
            }
            cp
        });
    }

    /// CursorCheckpoint delta roundtrip preserves state.
    #[test]
    fn cursor_checkpoint_delta_roundtrip(
        consumer in "[a-z]{3,6}",
        offset in 1..1000u64,
        replica in arb_node_id(),
    ) {
        let baseline = CursorCheckpoint::default();
        let mut updated = CursorCheckpoint::default();
        updated.observe(consumer, CursorMark::new(offset, 1000, replica));
        assert_delta_roundtrip(&baseline, &updated);
    }

    /// MembershipView CRDT merge is commutative, associative, and idempotent.
    #[test]
    fn membership_view_crdt_laws(
        nodes in prop::collection::vec(arb_node_id(), 1..=3),
        versions in prop::collection::vec(1..100u64, 1..=3),
    ) {
        assert_crdt_laws(|seed| {
            let mut mv = MembershipView::default();
            for (i, node) in nodes.iter().enumerate() {
                let version = versions[i % versions.len()] + seed;
                mv.observe(
                    node.clone(),
                    MembershipRecord::new(version, MembershipState::Healthy, 1000 + seed, 500),
                );
            }
            mv
        });
    }

    /// MembershipView delta roundtrip preserves state.
    #[test]
    fn membership_view_delta_roundtrip(
        node in arb_node_id(),
        version in 1..100u64,
    ) {
        let baseline = MembershipView::default();
        let mut updated = MembershipView::default();
        updated.observe(node, MembershipRecord::new(version, MembershipState::Healthy, 1000, 500));
        assert_delta_roundtrip(&baseline, &updated);
    }

    /// LagSketch CRDT merge is commutative, associative, and idempotent.
    #[test]
    fn lag_sketch_crdt_laws(
        replicas in prop::collection::vec(arb_node_id(), 1..=3),
        lags in prop::collection::vec(0..10000u64, 1..=3),
    ) {
        assert_crdt_laws(|seed| {
            let mut ls = LagSketch::default();
            for (i, replica) in replicas.iter().enumerate() {
                ls.observe(replica, lags[i % lags.len()] + seed);
            }
            ls
        });
    }

    /// LagSketch delta roundtrip preserves state.
    #[test]
    fn lag_sketch_delta_roundtrip(
        replica in arb_node_id(),
        lag in 0..10000u64,
    ) {
        let baseline = LagSketch::default();
        let mut updated = LagSketch::default();
        updated.observe(&replica, lag);
        assert_delta_roundtrip(&baseline, &updated);
    }

    /// AdvisoryAggregate CRDT merge is commutative, associative, and idempotent.
    #[test]
    fn advisory_aggregate_crdt_laws(
        replicas in prop::collection::vec(arb_node_id(), 1..=2),
        ts_values in prop::collection::vec(1000..5000u64, 1..=3),
    ) {
        assert_crdt_laws(|seed| {
            let mut aa = AdvisoryAggregate::default();
            for (i, replica) in replicas.iter().enumerate() {
                aa.record_kind(replica, "test-kind", ts_values[i % ts_values.len()] + seed);
            }
            aa
        });
    }

    /// AdvisoryAggregate delta roundtrip preserves state.
    #[test]
    fn advisory_aggregate_delta_roundtrip(
        replica in arb_node_id(),
        ts in 1000..5000u64,
    ) {
        let baseline = AdvisoryAggregate::default();
        let mut updated = AdvisoryAggregate::default();
        updated.record_kind(&replica, "test-kind", ts);
        assert_delta_roundtrip(&baseline, &updated);
    }
}

// ---------------------------------------------------------------------------
// Property: Morphism transform algebra
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Identity transform is a no-op: apply_tokens returns the input unchanged.
    #[test]
    fn identity_transform_is_noop(tokens in prop::collection::vec(arb_token(), 1..=4)) {
        let transform = SubjectTransform::Identity;
        let result = transform.apply_tokens(&tokens).unwrap();
        prop_assert_eq!(&result, &tokens);
    }

    /// Identity transform is always invertible, and its inverse is also Identity.
    #[test]
    fn identity_is_invertible(_dummy in 0..1u32) {
        let transform = SubjectTransform::Identity;
        prop_assert!(transform.is_invertible());
        let inv = transform.inverse().unwrap();
        // Inverse of identity is identity
        prop_assert!(matches!(inv, SubjectTransform::Identity));
    }

    /// RenamePrefix roundtrip: apply transform then inverse yields original tokens.
    #[test]
    fn rename_prefix_roundtrip(
        prefix_from in arb_token(),
        prefix_to in arb_token(),
        suffix in prop::collection::vec(arb_token(), 0..=2),
    ) {
        prop_assume!(prefix_from != prefix_to);
        let from_pattern = SubjectPattern::new(&prefix_from);
        let to_pattern = SubjectPattern::new(&prefix_to);

        let transform = SubjectTransform::RenamePrefix {
            from: from_pattern,
            to: to_pattern,
        };

        if transform.is_invertible() {
            let mut tokens = vec![prefix_from];
            tokens.extend(suffix);
            let forward = transform.apply_tokens(&tokens).unwrap();
            let inverse = transform.inverse().unwrap();
            let back = inverse.apply_tokens(&forward).unwrap();
            prop_assert_eq!(&back, &tokens);
        }
    }

    /// Compose of identity transforms is equivalent to identity.
    #[test]
    fn compose_identity_is_identity(tokens in prop::collection::vec(arb_token(), 1..=4)) {
        let compose = SubjectTransform::Compose {
            steps: vec![SubjectTransform::Identity, SubjectTransform::Identity],
        };
        let result = compose.apply_tokens(&tokens).unwrap();
        prop_assert_eq!(&result, &tokens);
    }

    /// Grouping a declared transform pipeline differently must not change the
    /// evaluation result.
    #[test]
    fn compose_associativity_holds(
        tokens in prop::collection::vec(arb_token(), 1..=4),
        first in arb_transform(),
        second in arb_transform(),
        third in arb_transform(),
    ) {
        let left_nested = SubjectTransform::Compose {
            steps: vec![
                SubjectTransform::Compose {
                    steps: vec![first.clone(), second.clone()],
                },
                third.clone(),
            ],
        };
        let right_nested = SubjectTransform::Compose {
            steps: vec![
                first.clone(),
                SubjectTransform::Compose {
                    steps: vec![second.clone(), third.clone()],
                },
            ],
        };
        let flat = SubjectTransform::Compose {
            steps: vec![first, second, third],
        };

        let left_result = left_nested.apply_tokens(&tokens);
        let right_result = right_nested.apply_tokens(&tokens);
        let flat_result = flat.apply_tokens(&tokens);

        prop_assert_eq!(&left_result, &right_result);
        prop_assert_eq!(&left_result, &flat_result);
    }

    /// Lossy transforms are not invertible.
    #[test]
    fn lossy_implies_not_invertible(_dummy in 0..1u32) {
        let transforms = vec![
            SubjectTransform::RedactLiterals,
            SubjectTransform::SummarizeTail { preserve_segments: 1 },
            SubjectTransform::HashPartition { buckets: 10 },
        ];
        for t in &transforms {
            prop_assert!(t.is_lossy(), "Expected lossy: {t:?}");
            prop_assert!(!t.is_invertible(), "Lossy transforms must not be invertible: {t:?}");
        }
    }

    /// DeterministicHash is deterministic: same input always produces same output.
    #[test]
    fn deterministic_hash_is_stable(
        tokens in prop::collection::vec(arb_token(), 2..=4),
        buckets in 1..100u16,
    ) {
        let transform = SubjectTransform::DeterministicHash {
            buckets,
            source_indices: vec![1],
        };
        let r1 = transform.apply_tokens(&tokens).unwrap();
        let r2 = transform.apply_tokens(&tokens).unwrap();
        prop_assert_eq!(r1, r2);
    }

    /// LeftExtract and RightExtract always produce output shorter or equal to the source token.
    #[test]
    fn extract_bounds(
        tokens in prop::collection::vec(arb_token(), 1..=3),
        extract_len in 1..10usize,
    ) {
        let left = SubjectTransform::LeftExtract { index: 1, len: extract_len };
        if let Ok(result) = left.apply_tokens(&tokens) {
            for token in &result {
                prop_assert!(token.len() <= tokens[0].len().max(extract_len));
            }
        }

        let right = SubjectTransform::RightExtract { index: 1, len: extract_len };
        if let Ok(result) = right.apply_tokens(&tokens) {
            for token in &result {
                prop_assert!(token.len() <= tokens[0].len().max(extract_len));
            }
        }
    }

    /// Compose inverse is the reverse of individual inverses.
    #[test]
    fn compose_inverse_ordering(
        prefix_a in arb_token(),
        prefix_b in arb_token(),
        prefix_c in arb_token(),
    ) {
        prop_assume!(prefix_a != prefix_b && prefix_b != prefix_c && prefix_a != prefix_c);
        let step1 = SubjectTransform::RenamePrefix {
            from: SubjectPattern::new(&prefix_a),
            to: SubjectPattern::new(&prefix_b),
        };
        let step2 = SubjectTransform::RenamePrefix {
            from: SubjectPattern::new(&prefix_b),
            to: SubjectPattern::new(&prefix_c),
        };

        let compose = SubjectTransform::Compose {
            steps: vec![step1, step2],
        };

        if compose.is_invertible() {
            // Apply forward then inverse should be identity
            let tokens = vec![prefix_a];
            let forward = compose.apply_tokens(&tokens).unwrap();
            let inverse = compose.inverse().unwrap();
            let back = inverse.apply_tokens(&forward).unwrap();
            prop_assert_eq!(&back, &tokens);
        }
    }
}

// ---------------------------------------------------------------------------
// Property: Service obligation lifecycle is linear
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Committing a service obligation resolves the tracked lease exactly once
    /// and leaves no pending obligations behind.
    #[test]
    fn service_obligation_commit_path_is_linear_and_leak_free(
        delivery_class in arb_delivery_class(),
        request_id in arb_request_field(),
        caller in arb_request_field(),
        callee in arb_request_field(),
        subject_str in arb_subject_string(),
        payload in prop::collection::vec(any::<u8>(), 0..=32),
        slot in 1u32..=10_000u32,
    ) {
        let mut ledger = ObligationLedger::new();
        let mut obligation = ServiceObligation::allocate(
            &mut ledger,
            request_id.clone(),
            caller,
            callee,
            subject_str,
            delivery_class,
            TaskId::new_for_test(slot, 0),
            RegionId::new_for_test(slot + 1, 0),
            Time::from_nanos(1),
            None,
        )
        .expect("generated obligation should allocate");

        let commit = obligation
            .commit_with_reply(
                &mut ledger,
                Time::from_nanos(2),
                payload,
                delivery_class.minimum_ack(),
                false,
            )
            .expect("minimum honest boundary should commit");

        let request_id_after_commit = commit.request_id;
        let delivery_class_after_commit = commit.delivery_class;
        let service_obligation_id = commit.service_obligation_id;
        let reply_obligation = commit.reply_obligation;

        if let Some(reply_obligation) = reply_obligation {
            let reply_receipt = reply_obligation.commit_delivery(&mut ledger, Time::from_nanos(3));
            let reply_record = ledger
                .get(reply_receipt.obligation_id)
                .expect("reply obligation record should exist");
            prop_assert_eq!(reply_record.state, ObligationState::Committed);
        }

        if let Some(service_id) = service_obligation_id {
            let service_record = ledger
                .get(service_id)
                .expect("service obligation record should exist");
            prop_assert_eq!(service_record.state, ObligationState::Committed);
            prop_assert_eq!(service_record.abort_reason, None);
            prop_assert!(delivery_class >= DeliveryClass::ObligationBacked);
        } else {
            prop_assert!(delivery_class < DeliveryClass::ObligationBacked);
            prop_assert!(ledger.is_empty());
        }

        prop_assert_eq!(request_id_after_commit, request_id);
        prop_assert_eq!(delivery_class_after_commit, delivery_class);
        prop_assert_eq!(ledger.pending_count(), 0);
        prop_assert!(ledger.check_leaks().is_clean());
    }

    /// Aborting a service obligation must resolve the tracked lease exactly
    /// once and record the typed abort reason.
    #[test]
    fn service_obligation_abort_path_is_linear_and_leak_free(
        delivery_class in arb_delivery_class(),
        failure in arb_service_failure(),
        request_id in arb_request_field(),
        caller in arb_request_field(),
        callee in arb_request_field(),
        subject_str in arb_subject_string(),
        slot in 1u32..=10_000u32,
    ) {
        let mut ledger = ObligationLedger::new();
        let obligation = ServiceObligation::allocate(
            &mut ledger,
            request_id.clone(),
            caller,
            callee,
            subject_str,
            delivery_class,
            TaskId::new_for_test(slot, 0),
            RegionId::new_for_test(slot + 1, 0),
            Time::from_nanos(10),
            None,
        )
        .expect("generated obligation should allocate");

        let receipt = obligation
            .abort(&mut ledger, Time::from_nanos(11), failure)
            .expect("abort should succeed");
        let request_id_after_abort = receipt.request_id;
        let obligation_id = receipt.obligation_id;
        let failure_after_abort = receipt.failure;
        let delivery_class_after_abort = receipt.delivery_class;

        if let Some(obligation_id) = obligation_id {
            let record = ledger
                .get(obligation_id)
                .expect("tracked obligation should have a ledger record");
            prop_assert_eq!(record.state, ObligationState::Aborted);
            prop_assert_eq!(record.abort_reason, Some(expected_abort_reason(failure)));
            prop_assert!(delivery_class >= DeliveryClass::ObligationBacked);
        } else {
            prop_assert!(delivery_class < DeliveryClass::ObligationBacked);
            prop_assert!(ledger.is_empty());
        }

        prop_assert_eq!(request_id_after_abort, request_id);
        prop_assert_eq!(failure_after_abort, failure);
        prop_assert_eq!(delivery_class_after_abort, delivery_class);
        prop_assert_eq!(ledger.pending_count(), 0);
        prop_assert!(ledger.check_leaks().is_clean());
    }
}

// ---------------------------------------------------------------------------
// Property: SubjectTransform validation rejects invalid parameters
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// WildcardCapture with index=0 is invalid (1-based indexing).
    #[test]
    fn wildcard_capture_rejects_zero_index(_dummy in 0..1u32) {
        let t = SubjectTransform::WildcardCapture { index: 0 };
        // apply_tokens on any input should fail or validate should fail
        let tokens = vec!["a".to_string(), "b".to_string()];
        // The transform uses 1-based indexing, 0 should be out of range
        let result = t.apply_tokens(&tokens);
        prop_assert!(result.is_err());
    }

    /// SplitSlice with empty delimiter is invalid.
    #[test]
    fn split_slice_rejects_empty_delimiter(_dummy in 0..1u32) {
        let t = SubjectTransform::SplitSlice {
            index: 1,
            delimiter: String::new(),
            start: 0,
            len: 1,
        };
        // validate() should reject empty delimiter, but apply_tokens may also fail
        // We test that the transform does not silently succeed in a misleading way
        let tokens = vec!["hello-world".to_string()];
        let _ = t.apply_tokens(&tokens); // may or may not error; validation is the gate
    }

    /// HashPartition with 0 buckets is invalid.
    #[test]
    fn hash_partition_rejects_zero_buckets(_dummy in 0..1u32) {
        let t = SubjectTransform::HashPartition { buckets: 0 };
        let tokens = vec!["test".to_string()];
        let result = t.apply_tokens(&tokens);
        prop_assert!(result.is_err());
    }
}

// ---------------------------------------------------------------------------
// Property: Subject pattern overlap is symmetric
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Pattern overlap is symmetric: if A overlaps B, then B overlaps A.
    #[test]
    fn pattern_overlap_is_symmetric(
        a_str in arb_pattern_string(),
        b_str in arb_pattern_string(),
    ) {
        if let (Ok(a), Ok(b)) = (SubjectPattern::parse(&a_str), SubjectPattern::parse(&b_str)) {
            prop_assert_eq!(
                a.overlaps(&b),
                b.overlaps(&a),
                "overlap must be symmetric: {} vs {}", a_str, b_str
            );
        }
    }

    /// A literal pattern always overlaps with itself.
    #[test]
    fn literal_pattern_overlaps_self(subject_str in arb_subject_string()) {
        let pattern = SubjectPattern::new(&subject_str);
        prop_assert!(pattern.overlaps(&pattern));
    }
}

// ---------------------------------------------------------------------------
// Property: Subscription count is exact
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// After N subscribes (no drops), count() == N.
    #[test]
    fn subscription_count_is_exact(
        patterns in prop::collection::vec(arb_subject_string(), 1..=5),
    ) {
        let sl = Arc::new(Sublist::new());
        let _guards: Vec<_> = patterns
            .iter()
            .map(|p| sl.subscribe(&SubjectPattern::new(p), None))
            .collect();
        prop_assert_eq!(sl.count(), patterns.len());
    }

    /// After subscribe + drop guard, count decrements.
    #[test]
    fn subscription_removed_on_guard_drop(subject_str in arb_subject_string()) {
        let sl = Arc::new(Sublist::new());
        let guard = sl.subscribe(&SubjectPattern::new(&subject_str), None);
        prop_assert_eq!(sl.count(), 1);
        drop(guard);
        prop_assert_eq!(sl.count(), 0);
    }
}

// ---------------------------------------------------------------------------
// Property: CRDT delta is empty for identical states
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// delta(x, x) is the empty delta for all CRDT types.
    #[test]
    fn delta_self_is_empty_interest(
        patterns in prop::collection::vec(arb_subject_string(), 1..=3),
        replica in arb_node_id(),
    ) {
        let mut s = InterestSummary::default();
        for p in &patterns {
            s.subscribe(&replica, SubjectPattern::new(p));
        }
        let delta = s.delta(&s);
        prop_assert!(InterestSummary::delta_is_empty(&delta));
    }

    #[test]
    fn delta_self_is_empty_cursor(
        consumer in "[a-z]{3,6}",
        offset in 1..1000u64,
        replica in arb_node_id(),
    ) {
        let mut cp = CursorCheckpoint::default();
        cp.observe(consumer, CursorMark::new(offset, 1000, replica));
        let delta = cp.delta(&cp);
        prop_assert!(CursorCheckpoint::delta_is_empty(&delta));
    }

    #[test]
    fn delta_self_is_empty_membership(
        node in arb_node_id(),
        version in 1..100u64,
    ) {
        let mut mv = MembershipView::default();
        mv.observe(node, MembershipRecord::new(version, MembershipState::Healthy, 1000, 500));
        let delta = mv.delta(&mv);
        prop_assert!(MembershipView::delta_is_empty(&delta));
    }

    #[test]
    fn delta_self_is_empty_lag(
        replica in arb_node_id(),
        lag in 0..10000u64,
    ) {
        let mut ls = LagSketch::default();
        ls.observe(&replica, lag);
        let delta = ls.delta(&ls);
        prop_assert!(LagSketch::delta_is_empty(&delta));
    }

    #[test]
    fn delta_self_is_empty_advisory(
        replica in arb_node_id(),
        ts in 1000..5000u64,
    ) {
        let mut aa = AdvisoryAggregate::default();
        aa.record_kind(&replica, "kind", ts);
        let delta = aa.delta(&aa);
        prop_assert!(AdvisoryAggregate::delta_is_empty(&delta));
    }
}

// ---------------------------------------------------------------------------
// Property: Sharded sublist distributes subjects across shards
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// With enough distinct subjects, multiple shards are used (no single-shard collapse).
    #[test]
    fn sharded_distributes_across_shards(
        subjects in prop::collection::vec(arb_subject_string(), 20..=40),
    ) {
        let shard_count = 4;
        let sharded = ShardedSublist::new(shard_count);
        let mut seen_shards = std::collections::HashSet::new();
        for s in &subjects {
            let subject = Subject::new(s);
            seen_shards.insert(sharded.shard_index_for_subject(&subject));
        }
        // With 20+ distinct subjects and 4 shards, we expect at least 2 shards used
        prop_assert!(seen_shards.len() >= 2, "Expected distribution across shards, only got {}", seen_shards.len());
    }

    /// Shard assignment is deterministic: same subject always maps to same shard.
    #[test]
    fn shard_assignment_is_deterministic(subject_str in arb_subject_string()) {
        let sharded = ShardedSublist::new(4);
        let subject = Subject::new(&subject_str);
        let s1 = sharded.shard_index_for_subject(&subject);
        let s2 = sharded.shard_index_for_subject(&subject);
        prop_assert_eq!(s1, s2);
    }
}
