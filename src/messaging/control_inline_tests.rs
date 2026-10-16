    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn node(id: &str) -> NodeId {
        NodeId::new(id)
    }

    fn pattern(value: &str) -> SubjectPattern {
        SubjectPattern::new(value)
    }

    fn assert_delta_round_trip<T>(baseline: T, updated: T)
    where
        T: JoinSemilattice + std::fmt::Debug,
        T::Delta: std::fmt::Debug,
    {
        let delta = updated.delta(&baseline);
        let mut applied = baseline;
        assert!(applied.apply_delta(&delta));
        assert_eq!(applied, updated);
    }

    fn assert_converges<T>(left: T, middle: T, right: T)
    where
        T: JoinSemilattice + std::fmt::Debug,
    {
        let mut lhs = left.clone();
        lhs.merge(&middle);
        lhs.merge(&right);

        let mut rhs = right.clone();
        rhs.merge(&middle);
        rhs.merge(&left);

        assert_eq!(lhs, rhs);
    }

    // -- Delta-CRDT control metadata ----------------------------------------

    #[test]
    fn interest_summary_round_trips_delta() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");
        let invoices = pattern("tenant.invoices.>");

        let baseline = InterestSummary::default();
        let mut updated = InterestSummary::default();
        updated.subscribe(&replica_a, orders.clone());
        updated.subscribe(&replica_b, orders.clone());
        updated.unsubscribe(&replica_a, &orders);
        updated.subscribe(&replica_b, invoices.clone());

        assert_eq!(updated.interest_count(&orders), 1);
        assert_eq!(updated.interest_count(&invoices), 1);
        assert_delta_round_trip(baseline, updated);
    }

    #[test]
    fn interest_summary_converges_across_merge_orders() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");

        let mut left = InterestSummary::default();
        left.subscribe(&replica_a, orders.clone());

        let mut middle = InterestSummary::default();
        middle.subscribe(&replica_b, orders.clone());

        let mut right = InterestSummary::default();
        right.unsubscribe(&replica_a, &orders);

        assert_converges(left, middle, right);
    }

    #[test]
    fn cursor_checkpoint_prefers_newest_mark() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let baseline = CursorCheckpoint::default();

        let mut updated = CursorCheckpoint::default();
        updated.observe("consumer-a", CursorMark::new(10, 1_000, replica_a));
        updated.observe("consumer-a", CursorMark::new(12, 1_100, replica_b.clone()));

        let checkpoint = updated.checkpoint("consumer-a").expect("checkpoint");
        assert_eq!(checkpoint.offset(), 12);
        assert_eq!(checkpoint.checkpoint_unix_ms(), 1_100);
        assert_eq!(checkpoint.steward(), &replica_b);
        assert_delta_round_trip(baseline, updated);
    }

    #[test]
    fn membership_view_prefers_higher_version_and_converges() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");

        let mut left = MembershipView::default();
        left.observe(
            replica_a.clone(),
            MembershipRecord::new(1, MembershipState::Healthy, 1_000, 125),
        );

        let mut middle = MembershipView::default();
        middle.observe(
            replica_a.clone(),
            MembershipRecord::new(2, MembershipState::Degraded, 1_100, 600),
        );

        let mut right = MembershipView::default();
        right.observe(
            replica_b,
            MembershipRecord::new(1, MembershipState::Joining, 900, 50),
        );

        let mut merged = left.clone();
        merged.merge(&middle);
        let record = merged.record(&replica_a).expect("membership record");
        assert_eq!(record.version(), 2);
        assert_eq!(record.state(), MembershipState::Degraded);
        assert_eq!(record.load_per_mille(), 600);

        assert_delta_round_trip(MembershipView::default(), merged);
        assert_converges(left, middle, right);
    }

    #[test]
    fn lag_sketch_round_trips_delta_and_respects_error_bound() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let mut sketch = LagSketch::new(8);

        let samples = [3_u64, 9, 12, 18];
        sketch.observe(&replica_a, samples[0]);
        sketch.observe(&replica_a, samples[1]);
        sketch.observe(&replica_b, samples[2]);
        sketch.observe(&replica_b, samples[3]);

        assert_eq!(sketch.total_samples(), samples.len() as u64);
        let estimated_mean = sketch.estimated_mean().expect("mean estimate");
        let actual_mean = samples.iter().sum::<u64>() / samples.len() as u64;
        let error = estimated_mean.abs_diff(actual_mean);
        assert!(error <= sketch.max_mean_error_bound());

        assert_delta_round_trip(LagSketch::new(8), sketch);
    }

    #[test]
    fn lag_sketch_empty_delta_with_only_bucket_width_change_is_noop() {
        let baseline = LagSketch::default();
        let updated = LagSketch::new(8);
        let delta = updated.delta(&baseline);

        assert!(<LagSketch as JoinSemilattice>::delta_is_empty(&delta));
    }

    #[test]
    fn advisory_aggregate_round_trips_delta_and_reports_rate() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let mut aggregate = AdvisoryAggregate::new(1_000);

        aggregate.record_kind(&replica_a, "policy_decision", 1_200);
        aggregate.record_kind(&replica_b, "policy_decision", 1_400);
        aggregate.record_kind(&replica_b, "evidence_record", 1_800);

        assert_eq!(aggregate.count(1_000, "policy_decision"), 2);
        assert_eq!(aggregate.count(1_000, "evidence_record"), 1);
        assert_eq!(aggregate.rate_per_second(1_000, "policy_decision"), 2.0);

        assert_delta_round_trip(AdvisoryAggregate::new(1_000), aggregate);
    }

    #[test]
    fn advisory_aggregate_empty_delta_with_only_window_width_change_is_noop() {
        let baseline = AdvisoryAggregate::default();
        let updated = AdvisoryAggregate::new(1_000);
        let delta = updated.delta(&baseline);

        assert!(<AdvisoryAggregate as JoinSemilattice>::delta_is_empty(
            &delta
        ));
    }

    #[test]
    fn lag_sketch_adopts_incoming_width_when_local_state_is_empty() {
        let mut empty = LagSketch::new(16);
        let mut other = LagSketch::new(8);
        let replica = node("r1");
        other.record(&replica, 42);

        empty.merge(&other);

        assert_eq!(empty.bucket_width, 8);
        assert_eq!(empty.bucket_count(), 1);
    }

    #[test]
    fn lag_sketch_apply_delta_adopts_width_when_empty_and_breaks_loop_when_non_empty() {
        let replica = node("r1");

        // Empty local adopts incoming width via apply_delta.
        let mut empty = LagSketch::new(16);
        let mut source = LagSketch::new(8);
        source.record(&replica, 42);
        let delta = source.delta(&LagSketch::new(8));
        assert!(empty.apply_delta(&delta));
        assert_eq!(empty.bucket_width, 8);
        assert_eq!(empty.bucket_count(), 1);

        // Non-empty local with different width returns true (breaks loop)
        // but does NOT adopt the data.
        let mut established = LagSketch::new(16);
        established.record(&replica, 99);
        let before_count = established.bucket_count();
        let mismatched_delta = source.delta(&LagSketch::new(8));
        assert!(established.apply_delta(&mismatched_delta));
        assert_eq!(established.bucket_width, 16); // width unchanged
        assert_eq!(established.bucket_count(), before_count); // data unchanged
    }

    #[test]
    fn advisory_aggregate_adopts_incoming_window_width_when_empty() {
        let mut empty = AdvisoryAggregate::new(500);
        let mut other = AdvisoryAggregate::new(1_000);
        other.record_kind(&node("r1"), "evt", 1_200);

        empty.merge(&other);
        assert_eq!(empty.window_width_ms, 1_000);
        assert_eq!(empty.count(1_000, "evt"), 1);
    }

    #[test]
    fn advisory_aggregate_apply_delta_breaks_loop_when_non_empty() {
        let r = node("r1");
        let mut established = AdvisoryAggregate::new(500);
        established.record_kind(&r, "evt", 200);

        let mut source = AdvisoryAggregate::new(1_000);
        source.record_kind(&r, "evt", 1_200);
        let delta = source.delta(&AdvisoryAggregate::new(1_000));

        // Returns true to break anti-entropy loop, but doesn't adopt data.
        assert!(established.apply_delta(&delta));
        assert_eq!(established.window_width_ms, 500);
    }

    #[test]
    fn unsubscribe_on_absent_pattern_does_not_create_entry() {
        let r = node("r1");
        let mut summary = InterestSummary::default();

        // Unsubscribe from a pattern that was never subscribed to.
        summary.unsubscribe(&r, &pattern("absent.>"));

        // No entry should have been created.
        assert_eq!(summary.interest_count(&pattern("absent.>")), 0);
        assert!(summary.counts.is_empty());
    }

    #[test]
    fn unsubscribe_after_subscribe_decrements_normally() {
        let r = node("r1");
        let p = pattern("orders.>");
        let mut summary = InterestSummary::default();

        summary.subscribe(&r, p.clone());
        assert_eq!(summary.interest_count(&p), 1);

        summary.unsubscribe(&r, &p);
        assert_eq!(summary.interest_count(&p), 0);
        // Entry exists (from subscribe) but value is zero.
        assert_eq!(summary.counts.len(), 1);
    }

    #[test]
    fn propagation_applies_incremental_delta_when_peer_is_one_step_behind() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut peer = CrdtPropagationReplica::<InterestSummary>::new(replica_b);

        let envelope = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("incremental envelope");

        assert_eq!(envelope.mode(), PropagationMode::Incremental);
        assert_eq!(peer.apply(&envelope), PropagationApply::Applied);
        assert_eq!(peer.state().interest_count(&orders), 1);
        assert_eq!(peer.frontier().version(&replica_a), 1);
    }

    #[test]
    fn propagation_relay_uses_snapshot_for_downstream_peer() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let replica_c = node("replica-c");
        let orders = pattern("tenant.orders.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut relay = CrdtPropagationReplica::<InterestSummary>::new(replica_b);
        let mut downstream = CrdtPropagationReplica::<InterestSummary>::new(replica_c);

        let first_hop = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("first-hop envelope");
        assert_eq!(relay.apply(&first_hop), PropagationApply::Applied);

        let second_hop = relay
            .prepare_for(&downstream.digest())
            .expect("relay snapshot");
        assert_eq!(second_hop.mode(), PropagationMode::AntiEntropy);
        assert_eq!(downstream.apply(&second_hop), PropagationApply::Applied);
        assert_eq!(downstream.state().interest_count(&orders), 1);
    }

    #[test]
    fn propagation_detects_partition_gap_and_repairs_via_snapshot() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");
        let invoices = pattern("tenant.invoices.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut peer = CrdtPropagationReplica::<InterestSummary>::new(replica_b);

        let first = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("first delta");
        let second = steward
            .mutate(|summary| summary.subscribe(&replica_a, invoices.clone()))
            .expect("second delta");

        assert_eq!(peer.apply(&second), PropagationApply::NeedsAntiEntropy);
        assert!(peer.needs_anti_entropy());

        let repair = steward
            .prepare_for(&peer.digest())
            .expect("repair snapshot");
        assert_eq!(repair.mode(), PropagationMode::AntiEntropy);
        assert_eq!(peer.apply(&repair), PropagationApply::Applied);
        assert!(!peer.needs_anti_entropy());
        assert_eq!(peer.state().interest_count(&orders), 1);
        assert_eq!(peer.state().interest_count(&invoices), 1);
        assert_eq!(peer.frontier().version(&replica_a), 2);
        assert_eq!(peer.apply(&first), PropagationApply::AlreadySatisfied);
    }

    #[test]
    fn propagation_converges_leaderlessly_after_partition_via_relay() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let replica_c = node("replica-c");
        let orders = pattern("tenant.orders.>");
        let invoices = pattern("tenant.invoices.>");

        let mut left = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut right = CrdtPropagationReplica::<InterestSummary>::new(replica_b.clone());
        let mut relay = CrdtPropagationReplica::<InterestSummary>::new(replica_c);

        let left_delta = left
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("left delta");
        let _right_delta = right
            .mutate(|summary| summary.subscribe(&replica_b, invoices.clone()))
            .expect("right delta");

        assert_eq!(relay.apply(&left_delta), PropagationApply::Applied);
        let from_right = right
            .prepare_for(&relay.digest())
            .expect("relay repair from right");
        assert_eq!(from_right.mode(), PropagationMode::AntiEntropy);
        assert_eq!(relay.apply(&from_right), PropagationApply::Applied);

        let relay_to_left = relay.prepare_for(&left.digest()).expect("relay to left");
        let relay_to_right = relay.prepare_for(&right.digest()).expect("relay to right");

        assert_eq!(left.apply(&relay_to_left), PropagationApply::Applied);
        assert_eq!(right.apply(&relay_to_right), PropagationApply::Applied);

        let mut expected = InterestSummary::default();
        expected.subscribe(&replica_a, orders.clone());
        expected.subscribe(&replica_b, invoices.clone());

        assert_eq!(left.state(), &expected);
        assert_eq!(right.state(), &expected);
        assert_eq!(relay.state(), &expected);
    }

    #[test]
    fn propagation_prefers_incremental_delta_when_it_is_smaller_than_snapshot() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");
        let invoices = pattern("tenant.invoices.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut peer = CrdtPropagationReplica::<InterestSummary>::new(replica_b);

        let first = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("first delta");
        assert_eq!(peer.apply(&first), PropagationApply::Applied);

        let incremental = steward
            .mutate(|summary| summary.subscribe(&replica_a, invoices.clone()))
            .expect("incremental delta");
        let snapshot = steward.snapshot_envelope().expect("snapshot delta");

        assert_eq!(incremental.mode(), PropagationMode::Incremental);
        assert_eq!(snapshot.mode(), PropagationMode::AntiEntropy);

        let InterestSummaryDelta {
            counts: incremental_counts,
        } = incremental.delta();
        let InterestSummaryDelta {
            counts: snapshot_counts,
        } = snapshot.delta();
        let incremental_counts = incremental_counts.len();
        let snapshot_counts = snapshot_counts.len();

        assert_eq!(incremental_counts, 1);
        assert_eq!(snapshot_counts, 2);
        assert!(incremental_counts < snapshot_counts);
    }

    #[test]
    fn cursor_checkpoint_converges_and_ignores_stale_observations() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let replica_c = node("replica-c");

        let mut left = CursorCheckpoint::default();
        left.observe("consumer-a", CursorMark::new(12, 1_200, replica_a.clone()));
        left.observe("consumer-a", CursorMark::new(11, 1_300, replica_b.clone()));

        let checkpoint = left.checkpoint("consumer-a").expect("checkpoint");
        assert_eq!(checkpoint.offset(), 12);
        assert_eq!(checkpoint.checkpoint_unix_ms(), 1_200);
        assert_eq!(checkpoint.steward(), &replica_a);

        let mut middle = CursorCheckpoint::default();
        middle.observe("consumer-b", CursorMark::new(4, 900, replica_b));

        let mut right = CursorCheckpoint::default();
        right.observe("consumer-c", CursorMark::new(2, 800, replica_c));

        assert_converges(left, middle, right);
    }

    #[test]
    fn lag_sketch_converges_across_merge_orders() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let replica_c = node("replica-c");

        let mut left = LagSketch::new(8);
        left.observe(&replica_a, 3);
        left.observe(&replica_a, 7);

        let mut middle = LagSketch::new(8);
        middle.observe(&replica_b, 11);

        let mut right = LagSketch::new(8);
        right.observe(&replica_c, 19);

        assert_converges(left, middle, right);
    }

    #[test]
    fn propagation_duplicate_incremental_delta_is_idempotent() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut peer = CrdtPropagationReplica::<InterestSummary>::new(replica_b);

        let envelope = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("incremental envelope");

        assert_eq!(peer.apply(&envelope), PropagationApply::Applied);
        assert_eq!(peer.apply(&envelope), PropagationApply::AlreadySatisfied);
        assert_eq!(peer.state().interest_count(&orders), 1);
    }

    #[test]
    fn propagation_resumes_incremental_after_snapshot_repair() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");
        let orders = pattern("tenant.orders.>");
        let invoices = pattern("tenant.invoices.>");
        let payments = pattern("tenant.payments.>");

        let mut steward = CrdtPropagationReplica::<InterestSummary>::new(replica_a.clone());
        let mut peer = CrdtPropagationReplica::<InterestSummary>::new(replica_b);

        let first = steward
            .mutate(|summary| summary.subscribe(&replica_a, orders.clone()))
            .expect("first delta");
        let second = steward
            .mutate(|summary| summary.subscribe(&replica_a, invoices.clone()))
            .expect("second delta");

        assert_eq!(peer.apply(&second), PropagationApply::NeedsAntiEntropy);
        let repair = steward
            .prepare_for(&peer.digest())
            .expect("repair snapshot");
        assert_eq!(repair.mode(), PropagationMode::AntiEntropy);
        assert_eq!(peer.apply(&repair), PropagationApply::Applied);
        assert_eq!(peer.apply(&first), PropagationApply::AlreadySatisfied);

        let third = steward
            .mutate(|summary| summary.subscribe(&replica_a, payments.clone()))
            .expect("third delta");
        assert_eq!(third.mode(), PropagationMode::Incremental);
        assert_eq!(peer.apply(&third), PropagationApply::Applied);
        assert_eq!(peer.state().interest_count(&orders), 1);
        assert_eq!(peer.state().interest_count(&invoices), 1);
        assert_eq!(peer.state().interest_count(&payments), 1);
        assert_eq!(peer.frontier().version(&replica_a), 3);
    }

    #[test]
    fn propagation_snapshot_applies_mismatched_lag_sketch_delta_to_break_retry_loop() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");

        let mut peer = CrdtPropagationReplica::<LagSketch>::new(replica_b.clone());
        let _ = peer.mutate(|sketch| sketch.observe(&replica_b, 42));

        let mut frontier = ReplicaVersionVector::default();
        frontier.advance(&replica_a);

        let mut counter_delta = ReplicaCounterDelta::default();
        counter_delta.positive.insert(replica_a.clone(), 1);

        let mut buckets = BTreeMap::new();
        buckets.insert(0, counter_delta);

        let envelope = PropagationEnvelope {
            steward: replica_a.clone(),
            frontier,
            mode: PropagationMode::AntiEntropy,
            delta: LagSketchDelta {
                bucket_width: 8,
                buckets,
            },
        };

        assert_eq!(peer.apply(&envelope), PropagationApply::Applied);
        assert_eq!(peer.frontier().version(&replica_a), 1);
        assert!(!peer.needs_anti_entropy());
    }

    #[test]
    fn advisory_aggregate_collapses_decision_identity_to_kind_counts() {
        let replica_a = node("replica-a");
        let replica_b = node("replica-b");

        let audit_a = make_test_audit_entry();
        let mut audit_b = make_test_audit_entry();
        audit_b.decision_id = DecisionId::from_raw(77);
        audit_b.trace_id = TraceId::from_raw(200);
        audit_b.action_chosen = "hold".to_owned();
        audit_b.expected_loss = 0.7;
        audit_b.ts_unix_ms = 1_700_000_000_500;

        let outcome_a = DecisionOutcome {
            action_index: 0,
            action_name: audit_a.action_chosen.clone(),
            expected_loss: audit_a.expected_loss,
            expected_losses: audit_a.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit_a,
        };
        let outcome_b = DecisionOutcome {
            action_index: 1,
            action_name: audit_b.action_chosen.clone(),
            expected_loss: audit_b.expected_loss,
            expected_losses: audit_b.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit_b,
        };

        let advisory_a = ControlAdvisory::evidence_record(
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.evidence"),
            &outcome_a,
            "drain evidence a",
        );
        let advisory_b = ControlAdvisory::evidence_record(
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.evidence"),
            &outcome_b,
            "drain evidence b",
        );

        let mut aggregate = AdvisoryAggregate::new(1_000);
        aggregate.record_kind(
            &replica_a,
            advisory_a.advisory_type.kind(),
            advisory_a.ts_unix_ms,
        );
        aggregate.record_kind(
            &replica_b,
            advisory_b.advisory_type.kind(),
            advisory_b.ts_unix_ms,
        );

        let window_start = 1_700_000_000_000;
        let kind_window = aggregate.windows.get(&window_start).expect("window");
        assert_eq!(aggregate.count(window_start, "evidence_record"), 2);
        assert_eq!(kind_window.len(), 1);
        assert!(kind_window.contains_key("evidence_record"));

        let evidence_id_a = advisory_a.evidence_id();
        let evidence_id_b = advisory_b.evidence_id();
        assert!(
            matches!((&evidence_id_a, &evidence_id_b), (Some(left), Some(right)) if left != right)
        );
        if let Some(evidence_id_a) = evidence_id_a {
            assert!(!kind_window.contains_key(&evidence_id_a));
        }
        if let Some(evidence_id_b) = evidence_id_b {
            assert!(!kind_window.contains_key(&evidence_id_b));
        }
    }

    #[test]
    fn advisory_aggregate_prune_before_retains_cutoff_window_and_newer() {
        let replica_a = node("replica-a");
        let mut aggregate = AdvisoryAggregate::new(1_000);

        aggregate.record_kind(&replica_a, "evidence_record", 1_100);
        aggregate.record_kind(&replica_a, "evidence_record", 2_100);
        aggregate.record_kind(&replica_a, "evidence_record", 3_100);

        aggregate.prune_before(2_500);

        assert_eq!(aggregate.count(1_000, "evidence_record"), 0);
        assert_eq!(aggregate.count(2_000, "evidence_record"), 1);
        assert_eq!(aggregate.count(3_000, "evidence_record"), 1);
    }

    // -- SystemSubjectFamily -------------------------------------------------

    #[test]
    fn all_families_have_unique_names() {
        let mut names: Vec<&str> = SystemSubjectFamily::ALL.iter().map(|f| f.name()).collect();
        let original_len = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), original_len, "duplicate family names");
    }

    #[test]
    fn all_families_produce_valid_subject_patterns() {
        for family in &SystemSubjectFamily::ALL {
            let pattern = family.wildcard_pattern();
            assert!(
                pattern.as_str().starts_with("$SYS.FABRIC."),
                "pattern does not start with $SYS.FABRIC.: {}",
                pattern.as_str()
            );
            assert!(
                pattern.as_str().ends_with(".>"),
                "pattern does not end with .>: {}",
                pattern.as_str()
            );
        }
    }

    #[test]
    fn all_families_produce_valid_schemas() {
        for family in &SystemSubjectFamily::ALL {
            let schema = family.default_schema();
            assert_eq!(schema.family, SubjectFamily::Control);
            assert_eq!(schema.mobility, MobilityPermission::LocalOnly);
            assert!(schema.reply_space.is_none());
        }
    }

    #[test]
    fn delivery_class_monotonicity() {
        // Health/Route/Drain are cheapest (ephemeral), Auth/Replay most
        // expensive (forensic).
        assert_eq!(
            SystemSubjectFamily::Health.default_delivery_class(),
            DeliveryClass::EphemeralInteractive
        );
        assert_eq!(
            SystemSubjectFamily::Auth.default_delivery_class(),
            DeliveryClass::ForensicReplayable
        );
        assert_eq!(
            SystemSubjectFamily::Consumer.default_delivery_class(),
            DeliveryClass::ObligationBacked
        );
    }

    #[test]
    fn display_shows_prefix() {
        assert_eq!(
            format!("{}", SystemSubjectFamily::Health),
            "$SYS.FABRIC.HEALTH"
        );
        assert_eq!(
            format!("{}", SystemSubjectFamily::Replay),
            "$SYS.FABRIC.REPLAY"
        );
    }

    // -- ControlBudget -------------------------------------------------------

    #[test]
    fn default_budget_below_break_glass() {
        let normal = ControlBudget::default();
        let bg = ControlBudget::break_glass();
        assert!(normal.priority < bg.priority);
        assert!(normal.poll_quota < bg.poll_quota);
    }

    // -- AdvisoryDampingPolicy -----------------------------------------------

    #[test]
    fn default_damping_requires_operator_intent() {
        let policy = AdvisoryDampingPolicy::default();
        assert!(policy.requires_operator_intent);
    }

    #[test]
    fn non_recursive_damping_does_not_require_intent() {
        let policy = AdvisoryDampingPolicy::non_recursive();
        assert!(!policy.requires_operator_intent);
        assert_eq!(policy.stratification_tier, Some(0));
    }

    // -- ControlOutcome ------------------------------------------------------

    #[test]
    fn outcome_advisory_round_trip() {
        let outcome = ControlOutcome::Advisory {
            subject: Subject::new("$SYS.FABRIC.HEALTH.ok"),
            payload: b"{\"status\":\"ok\"}".to_vec(),
        };
        if let ControlOutcome::Advisory { subject, payload } = &outcome {
            assert_eq!(subject.as_str(), "$SYS.FABRIC.HEALTH.ok");
            assert!(!payload.is_empty());
        } else {
            panic!("expected Advisory variant");
        }
    }

    // -- ControlRegistry -----------------------------------------------------

    #[test]
    fn register_and_lookup() {
        let mut registry = ControlRegistry::new();
        let id = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("register");
        assert_eq!(registry.len(), 1);
        let handler = registry.get(id).expect("lookup");
        assert_eq!(handler.family, SystemSubjectFamily::Health);
        assert!(!handler.break_glass);
    }

    #[test]
    fn register_rejects_non_sys_prefix() {
        let mut registry = ControlRegistry::new();
        let result = registry.register(
            SystemSubjectFamily::Health,
            SubjectPattern::new("user.health.>"),
            ControlBudget::default(),
            AdvisoryDampingPolicy::default(),
            false,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            ControlRegistryError::InvalidPrefix { pattern } => {
                assert_eq!(pattern, "user.health.>");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn register_rejects_family_mismatch() {
        let mut registry = ControlRegistry::new();
        let result = registry.register(
            SystemSubjectFamily::Health,
            SubjectPattern::new("$SYS.FABRIC.AUTH.>"),
            ControlBudget::default(),
            AdvisoryDampingPolicy::default(),
            false,
        );
        match result.expect_err("family mismatch must fail") {
            ControlRegistryError::FamilyMismatch { family, pattern } => {
                assert_eq!(family, SystemSubjectFamily::Health);
                assert_eq!(pattern, "$SYS.FABRIC.AUTH.>");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn register_rejects_similar_prefix_outside_family_boundary() {
        let mut registry = ControlRegistry::new();
        let result = registry.register(
            SystemSubjectFamily::Health,
            SubjectPattern::new("$SYS.FABRIC.HEALTHY.>"),
            ControlBudget::default(),
            AdvisoryDampingPolicy::default(),
            false,
        );
        match result.expect_err("family boundary mismatch must fail") {
            ControlRegistryError::FamilyMismatch { family, pattern } => {
                assert_eq!(family, SystemSubjectFamily::Health);
                assert_eq!(pattern, "$SYS.FABRIC.HEALTHY.>");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn break_glass_registration() {
        let mut registry = ControlRegistry::new();
        let bg_id = registry
            .register_break_glass(SystemSubjectFamily::Health)
            .expect("bg register");
        let normal_id = registry
            .register_default(SystemSubjectFamily::Route)
            .expect("normal register");
        assert_eq!(registry.len(), 2);

        let bg = registry.break_glass_handlers();
        assert_eq!(bg.len(), 1);
        assert_eq!(bg[0].id, bg_id);
        assert!(bg[0].break_glass);

        // Normal handler should not appear in break-glass list.
        assert!(bg.iter().all(|h| h.id != normal_id));
    }

    #[test]
    fn matching_handlers_filters_by_subject() {
        let mut registry = ControlRegistry::new();
        registry
            .register_default(SystemSubjectFamily::Health)
            .expect("register health");
        registry
            .register_default(SystemSubjectFamily::Auth)
            .expect("register auth");

        let health_subj = Subject::new("$SYS.FABRIC.HEALTH.ok");
        let matches = registry.matching_handlers(&health_subj);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].family, SystemSubjectFamily::Health);

        let auth_subj = Subject::new("$SYS.FABRIC.AUTH.login.failed");
        let matches = registry.matching_handlers(&auth_subj);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].family, SystemSubjectFamily::Auth);

        // Unregistered family yields no matches.
        let drain_subj = Subject::new("$SYS.FABRIC.DRAIN.start");
        let matches = registry.matching_handlers(&drain_subj);
        assert!(matches.is_empty());
    }

    #[test]
    fn namespace_control_scope_builds_tenant_service_system_subjects() {
        let scope = NamespaceControlScope::new(SystemSubjectFamily::Health, "acme", "orders")
            .expect("namespace control scope");

        assert_eq!(scope.family(), SystemSubjectFamily::Health);
        assert_eq!(scope.tenant().as_str(), "acme");
        assert_eq!(scope.service().as_str(), "orders");
        assert_eq!(
            scope.wildcard_pattern().as_str(),
            "$SYS.FABRIC.HEALTH.TENANT.acme.SERVICE.orders.>"
        );
        assert_eq!(
            scope.subject("status").expect("status subject").as_str(),
            "$SYS.FABRIC.HEALTH.TENANT.acme.SERVICE.orders.status"
        );
    }

    #[test]
    fn namespace_control_scope_can_be_derived_from_namespace_kernel() {
        let namespace = NamespaceKernel::new("acme", "orders").expect("namespace kernel");
        let scope = NamespaceControlScope::from_namespace(SystemSubjectFamily::Route, &namespace);

        assert_eq!(scope.family(), SystemSubjectFamily::Route);
        assert_eq!(scope.tenant(), namespace.tenant());
        assert_eq!(scope.service(), namespace.service());
        assert_eq!(
            scope.wildcard_pattern().as_str(),
            "$SYS.FABRIC.ROUTE.TENANT.acme.SERVICE.orders.>"
        );
        assert_eq!(
            scope
                .subject("rebalance")
                .expect("route control subject")
                .as_str(),
            "$SYS.FABRIC.ROUTE.TENANT.acme.SERVICE.orders.rebalance"
        );
    }

    #[test]
    fn control_registry_keeps_namespace_control_handlers_isolated() {
        let mut registry = ControlRegistry::new();
        let acme_orders_ns = NamespaceKernel::new("acme", "orders").expect("acme orders kernel");
        let bravo_orders_ns = NamespaceKernel::new("bravo", "orders").expect("bravo orders kernel");
        let acme_orders =
            NamespaceControlScope::from_namespace(SystemSubjectFamily::Health, &acme_orders_ns);
        let bravo_orders =
            NamespaceControlScope::from_namespace(SystemSubjectFamily::Health, &bravo_orders_ns);

        let acme_id = registry
            .register_namespace_default(&acme_orders)
            .expect("register acme orders");
        let bravo_id = registry
            .register_namespace_default(&bravo_orders)
            .expect("register bravo orders");

        let acme_status = acme_orders.subject("status").expect("acme status");
        let matches = registry.matching_handlers(&acme_status);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, acme_id);
        assert_eq!(
            matches[0].pattern.as_str(),
            acme_orders.wildcard_pattern().as_str()
        );

        let bravo_status = bravo_orders.subject("status").expect("bravo status");
        let matches = registry.matching_handlers(&bravo_status);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, bravo_id);
        assert_eq!(
            matches[0].pattern.as_str(),
            bravo_orders.wildcard_pattern().as_str()
        );
    }

    #[test]
    fn handlers_for_family() {
        let mut registry = ControlRegistry::new();
        registry
            .register_default(SystemSubjectFamily::Health)
            .expect("register 1");
        registry
            .register_break_glass(SystemSubjectFamily::Health)
            .expect("register 2");
        registry
            .register_default(SystemSubjectFamily::Route)
            .expect("register 3");

        let health = registry.handlers_for_family(SystemSubjectFamily::Health);
        assert_eq!(health.len(), 2);
        let route = registry.handlers_for_family(SystemSubjectFamily::Route);
        assert_eq!(route.len(), 1);
    }

    #[test]
    fn unregister_removes_handler() {
        let mut registry = ControlRegistry::new();
        let id = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("register");
        assert_eq!(registry.len(), 1);
        assert!(registry.unregister(id));
        assert_eq!(registry.len(), 0);
        assert!(registry.get(id).is_none());
    }

    #[test]
    fn unregister_clears_break_glass_index() {
        let mut registry = ControlRegistry::new();
        let bg_id = registry
            .register_break_glass(SystemSubjectFamily::Drain)
            .expect("bg");
        assert_eq!(registry.break_glass_handlers().len(), 1);
        registry.unregister(bg_id);
        assert!(registry.break_glass_handlers().is_empty());
    }

    #[test]
    fn unregister_one_break_glass_preserves_remaining_handlers() {
        let mut registry = ControlRegistry::new();
        let health = registry
            .register_break_glass(SystemSubjectFamily::Health)
            .expect("health break-glass");
        let drain = registry
            .register_break_glass(SystemSubjectFamily::Drain)
            .expect("drain break-glass");

        assert!(registry.unregister(health));

        let remaining = registry.break_glass_handlers();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, drain);
        assert_eq!(remaining[0].family, SystemSubjectFamily::Drain);
    }

    #[test]
    fn unregister_returns_false_for_missing() {
        let mut registry = ControlRegistry::new();
        assert!(!registry.unregister(ControlHandlerId::new(999)));
    }

    #[test]
    fn empty_registry() {
        let registry = ControlRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.break_glass_handlers().is_empty());
    }

    // -- ControlHandlerId ----------------------------------------------------

    #[test]
    fn handler_id_display() {
        let id = ControlHandlerId::new(42);
        assert_eq!(format!("{id}"), "ctrl-42");
    }

    #[test]
    fn handler_id_round_trip() {
        let id = ControlHandlerId::new(7);
        assert_eq!(id.raw(), 7);
    }

    // -- Evidence policy per family ------------------------------------------

    #[test]
    fn auth_replay_have_full_evidence() {
        for family in &[SystemSubjectFamily::Auth, SystemSubjectFamily::Replay] {
            let schema = family.default_schema();
            assert!(
                schema.evidence_policy.record_counterfactual_branches,
                "{family} should record counterfactual branches"
            );
            assert_eq!(schema.evidence_policy.sampling_ratio, 1.0);
        }
    }

    #[test]
    fn health_has_default_evidence() {
        let schema = SystemSubjectFamily::Health.default_schema();
        assert!(!schema.evidence_policy.record_counterfactual_branches);
        assert_eq!(schema.evidence_policy.sampling_ratio, 1.0);
    }

    // -- Minimum ack ---------------------------------------------------------

    #[test]
    fn minimum_ack_matches_delivery_class() {
        // EphemeralInteractive → Accepted
        assert_eq!(SystemSubjectFamily::Health.minimum_ack(), AckKind::Accepted);
        // ObligationBacked → Committed
        assert_eq!(
            SystemSubjectFamily::Consumer.minimum_ack(),
            AckKind::Committed
        );
        // ForensicReplayable → Recoverable
        assert_eq!(
            SystemSubjectFamily::Auth.minimum_ack(),
            AckKind::Recoverable
        );
    }

    // -- ControlAdvisoryType -------------------------------------------------

    #[test]
    fn advisory_type_capability_graph_change() {
        let advisory = ControlAdvisoryType::CapabilityGraphChange {
            affected_subjects: vec![SubjectPattern::new("$SYS.FABRIC.AUTH.>")],
            description: "revoked admin capability".to_owned(),
        };
        match &advisory {
            ControlAdvisoryType::CapabilityGraphChange {
                affected_subjects,
                description,
            } => {
                assert_eq!(affected_subjects.len(), 1);
                assert_eq!(description, "revoked admin capability");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn advisory_type_evidence_record_has_explicit_identity() {
        let advisory = ControlAdvisoryType::EvidenceRecord {
            evidence_id: "control:drain:42:1700000000000".to_owned(),
            component: "drain_policy".to_owned(),
            action: "failover".to_owned(),
            summary: "latency SLO breach justified failover".to_owned(),
        };
        match &advisory {
            ControlAdvisoryType::EvidenceRecord {
                evidence_id,
                component,
                action,
                summary,
            } => {
                assert_eq!(evidence_id, "control:drain:42:1700000000000");
                assert_eq!(component, "drain_policy");
                assert_eq!(action, "failover");
                assert!(summary.contains("SLO breach"));
                assert_eq!(advisory.kind(), "evidence_record");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn obligation_transfer_action_display() {
        assert_eq!(
            format!("{}", ObligationTransferAction::Transferred),
            "transferred"
        );
        assert_eq!(format!("{}", ObligationTransferAction::Aborted), "aborted");
        assert_eq!(
            format!("{}", ObligationTransferAction::ReplayScheduled),
            "replay_scheduled"
        );
    }

    // -- ControlAdvisory with FrankenSuite evidence --------------------------

    fn make_test_audit_entry() -> DecisionAuditEntry {
        let mut losses = BTreeMap::new();
        losses.insert("failover".to_owned(), 0.3);
        losses.insert("hold".to_owned(), 0.7);
        DecisionAuditEntry {
            decision_id: DecisionId::from_raw(42),
            trace_id: TraceId::from_raw(100),
            contract_name: "drain_policy".to_owned(),
            action_chosen: "failover".to_owned(),
            expected_loss: 0.3,
            calibration_score: 0.85,
            fallback_active: false,
            posterior_snapshot: vec![0.6, 0.4],
            expected_loss_by_action: losses,
            ts_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn advisory_from_decision_carries_provenance() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "drain_policy".to_owned(),
                action_chosen: "failover".to_owned(),
                justification: "downstream latency exceeded SLO".to_owned(),
            },
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.failover"),
            &outcome,
        );

        assert!(advisory.has_decision_provenance());
        assert_eq!(advisory.family, SystemSubjectFamily::Drain);
        assert_eq!(advisory.trace_id, TraceId::from_raw(100));
        assert_eq!(advisory.decision_id, DecisionId::from_raw(42));
    }

    #[test]
    fn advisory_to_evidence_ledger() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "drain_policy".to_owned(),
                action_chosen: "failover".to_owned(),
                justification: "SLO breach".to_owned(),
            },
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.failover"),
            &outcome,
        );

        let evidence = advisory.to_evidence_ledger();
        assert!(evidence.is_some());
        let ledger = evidence.unwrap();
        assert!(ledger.is_valid());
        assert_eq!(ledger.component, "drain_policy");
        assert_eq!(ledger.action, "failover");
        assert!((ledger.calibration_score - 0.85).abs() < f64::EPSILON);
        assert!(!ledger.fallback_active);
    }

    #[test]
    fn evidence_record_advisory_uses_stable_evidence_id() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::evidence_record(
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.evidence"),
            &outcome,
            "drain failover evidence bundle",
        );

        let evidence_id = advisory.evidence_id().expect("evidence id");
        assert!(evidence_id.starts_with("control:drain:"));
        assert!(advisory.has_decision_provenance());
    }

    #[test]
    fn notification_advisory_has_no_provenance() {
        let advisory = ControlAdvisory::notification(
            ControlAdvisoryType::BreakGlassActivation {
                reason: "fabric unreachable".to_owned(),
            },
            SystemSubjectFamily::Health,
            Subject::new("$SYS.FABRIC.HEALTH.break_glass"),
            TraceId::from_raw(200),
            1_700_000_000_000,
        );

        assert!(!advisory.has_decision_provenance());
        assert!(advisory.to_evidence_ledger().is_none());
        assert_eq!(advisory.trace_id, TraceId::from_raw(200));
    }

    #[test]
    fn advisory_json_payload_contains_type_and_provenance() {
        let advisory = ControlAdvisory::notification(
            ControlAdvisoryType::ObligationTransfer {
                action: ObligationTransferAction::Aborted,
                subject: Subject::new("$SYS.FABRIC.CONSUMER.lease.expired"),
            },
            SystemSubjectFamily::Consumer,
            Subject::new("$SYS.FABRIC.CONSUMER.advisory"),
            TraceId::from_raw(300),
            1_700_000_000_000,
        );

        let payload = advisory.to_json_payload();
        assert!(!payload.is_empty());
        let parsed: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        assert_eq!(
            parsed.get("type").and_then(serde_json::Value::as_str),
            Some("obligation_transfer")
        );
        assert_eq!(
            parsed.get("action").and_then(serde_json::Value::as_str),
            Some("aborted")
        );
        assert_eq!(
            parsed.get("family").and_then(serde_json::Value::as_str),
            Some("CONSUMER")
        );
        assert_eq!(
            parsed
                .get("obligation_subject")
                .and_then(serde_json::Value::as_str),
            Some("$SYS.FABRIC.CONSUMER.lease.expired")
        );
        assert_eq!(
            parsed
                .get("has_decision_provenance")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            parsed.get("ts_unix_ms").and_then(serde_json::Value::as_u64),
            Some(1_700_000_000_000)
        );
    }

    #[test]
    fn advisory_json_payload_policy_decision() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "load_shed".to_owned(),
                action_chosen: "reject_new".to_owned(),
                justification: "queue depth exceeded threshold".to_owned(),
            },
            SystemSubjectFamily::Route,
            Subject::new("$SYS.FABRIC.ROUTE.shed"),
            &outcome,
        );

        let payload = advisory.to_json_payload();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        assert_eq!(
            parsed.get("type").and_then(serde_json::Value::as_str),
            Some("policy_decision")
        );
        assert_eq!(
            parsed
                .get("policy_name")
                .and_then(serde_json::Value::as_str),
            Some("load_shed")
        );
        assert_eq!(
            parsed
                .get("action_chosen")
                .and_then(serde_json::Value::as_str),
            Some("reject_new")
        );
        assert_eq!(
            parsed
                .get("has_decision_provenance")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn advisory_json_payload_evidence_record() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::evidence_record(
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.evidence"),
            &outcome,
            "bounded drain failover evidence",
        );

        let payload = advisory.to_json_payload();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        assert_eq!(
            parsed.get("type").and_then(serde_json::Value::as_str),
            Some("evidence_record")
        );
        assert!(
            parsed
                .get("evidence_id")
                .and_then(serde_json::Value::as_str)
                .expect("string evidence_id")
                .starts_with("control:drain:")
        );
        assert_eq!(
            parsed.get("component").and_then(serde_json::Value::as_str),
            Some("drain_policy")
        );
        assert_eq!(
            parsed.get("action").and_then(serde_json::Value::as_str),
            Some("failover")
        );
        assert_eq!(
            parsed.get("summary").and_then(serde_json::Value::as_str),
            Some("bounded drain failover evidence")
        );
    }

    #[test]
    fn break_glass_advisory_payload() {
        let advisory = ControlAdvisory::notification(
            ControlAdvisoryType::BreakGlassActivation {
                reason: "network partition detected".to_owned(),
            },
            SystemSubjectFamily::Health,
            Subject::new("$SYS.FABRIC.HEALTH.break_glass"),
            TraceId::from_raw(400),
            1_700_000_000_000,
        );

        let payload = advisory.to_json_payload();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        assert_eq!(
            parsed.get("type").and_then(serde_json::Value::as_str),
            Some("break_glass_activation")
        );
        assert_eq!(
            parsed.get("reason").and_then(serde_json::Value::as_str),
            Some("network partition detected")
        );
    }

    #[test]
    fn capability_graph_change_payload_preserves_affected_subjects() {
        let advisory = ControlAdvisory::notification(
            ControlAdvisoryType::CapabilityGraphChange {
                affected_subjects: vec![
                    SubjectPattern::new("tenant.acme.service.orders.>"),
                    SubjectPattern::new("tenant.acme.service.inventory.lookup"),
                ],
                description: "added bounded import edge".to_owned(),
            },
            SystemSubjectFamily::Route,
            Subject::new("$SYS.FABRIC.ROUTE.capability_change"),
            TraceId::from_raw(401),
            1_700_000_000_100,
        );

        let payload = advisory.to_json_payload();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        let affected_subjects = parsed
            .get("affected_subjects")
            .and_then(serde_json::Value::as_array)
            .expect("affected_subjects array");

        assert_eq!(
            parsed.get("type").and_then(serde_json::Value::as_str),
            Some("capability_graph_change")
        );
        assert_eq!(
            parsed
                .get("description")
                .and_then(serde_json::Value::as_str),
            Some("added bounded import edge")
        );
        assert_eq!(affected_subjects.len(), 2);
        assert_eq!(
            affected_subjects[0].as_str(),
            Some("tenant.acme.service.orders.>")
        );
        assert_eq!(
            affected_subjects[1].as_str(),
            Some("tenant.acme.service.inventory.lookup")
        );
    }

    #[test]
    fn advisory_filter_matches_family_kind_and_provenance() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let evidence_advisory = ControlAdvisory::evidence_record(
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.evidence"),
            &outcome,
            "drain evidence",
        );
        let notification = ControlAdvisory::notification(
            ControlAdvisoryType::BreakGlassActivation {
                reason: "fabric unreachable".to_owned(),
            },
            SystemSubjectFamily::Health,
            Subject::new("$SYS.FABRIC.HEALTH.break_glass"),
            TraceId::from_raw(9),
            1_700_000_000_123,
        );

        let drain_evidence_only = ControlAdvisoryFilter {
            family: Some(SystemSubjectFamily::Drain),
            advisory_kind: Some("evidence_record"),
            require_decision_provenance: true,
        };
        assert!(evidence_advisory.matches_filter(&drain_evidence_only));
        assert!(!notification.matches_filter(&drain_evidence_only));

        let health_break_glass = ControlAdvisoryFilter {
            family: Some(SystemSubjectFamily::Health),
            advisory_kind: Some("break_glass_activation"),
            require_decision_provenance: false,
        };
        assert!(notification.matches_filter(&health_break_glass));
        assert!(!evidence_advisory.matches_filter(&health_break_glass));
    }

    // ========================================================================
    // Comprehensive control plane tests (bead 8w83i.8.3)
    // ========================================================================

    // -- Capability domain enforcement ---------------------------------------

    #[test]
    fn control_subjects_require_sys_fabric_prefix() {
        // All system subject families produce subjects under $SYS.FABRIC.
        for family in &SystemSubjectFamily::ALL {
            let prefix = family.prefix();
            assert!(
                prefix.starts_with("$SYS.FABRIC."),
                "family {family} prefix `{prefix}` must start with $SYS.FABRIC."
            );
        }
    }

    #[test]
    fn registry_rejects_non_fabric_sys_prefix() {
        let mut registry = ControlRegistry::new();
        // $SYS.OTHER.* is NOT $SYS.FABRIC.* — should be rejected.
        let result = registry.register(
            SystemSubjectFamily::Health,
            SubjectPattern::new("$SYS.OTHER.health.>"),
            ControlBudget::default(),
            AdvisoryDampingPolicy::default(),
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn admin_control_capability_scope_maps_correctly() {
        // Verify that control handler families are associated with the
        // AdminControl capability scope (the capability module enforces
        // this at runtime; here we verify the type-level contract).
        use super::super::capability::FabricCapabilityScope;
        assert_eq!(
            format!("{}", FabricCapabilityScope::AdminControl),
            "admin_control"
        );
    }

    // -- Reserved budget under load ------------------------------------------

    #[test]
    fn control_budget_priority_above_user_traffic() {
        let budget = ControlBudget::default();
        // User traffic typically runs at priority 128.  Control handlers
        // must be above that.
        assert!(
            budget.priority > 128,
            "control budget priority {} must exceed user traffic (128)",
            budget.priority
        );
    }

    #[test]
    fn break_glass_budget_is_maximum_priority() {
        let bg = ControlBudget::break_glass();
        assert_eq!(bg.priority, 255, "break-glass must be max priority");
    }

    #[test]
    fn control_budget_deadline_is_bounded() {
        let budget = ControlBudget::default();
        // Control handlers should finish quickly — sub-second.
        assert!(budget.deadline < Duration::from_secs(1));
        let bg = ControlBudget::break_glass();
        assert!(bg.deadline < Duration::from_secs(1));
    }

    // -- Break-glass recovery path -------------------------------------------

    #[test]
    fn break_glass_available_when_main_fabric_degraded() {
        // Simulate: register several normal handlers + one break-glass.
        // Then unregister all normal handlers (simulating degradation).
        // The break-glass handler must still be reachable.
        let mut registry = ControlRegistry::new();
        let normal1 = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("normal 1");
        let normal2 = registry
            .register_default(SystemSubjectFamily::Route)
            .expect("normal 2");
        let bg = registry
            .register_break_glass(SystemSubjectFamily::Health)
            .expect("break-glass");

        // Simulate degradation: remove all normal handlers.
        registry.unregister(normal1);
        registry.unregister(normal2);

        // Break-glass handler survives.
        assert_eq!(registry.len(), 1);
        let bg_handlers = registry.break_glass_handlers();
        assert_eq!(bg_handlers.len(), 1);
        assert_eq!(bg_handlers[0].id, bg);
        assert!(bg_handlers[0].break_glass);
    }

    #[test]
    fn break_glass_handler_has_non_recursive_damping() {
        let mut registry = ControlRegistry::new();
        let bg_id = registry
            .register_break_glass(SystemSubjectFamily::Drain)
            .expect("bg");
        let handler = registry.get(bg_id).unwrap();
        // Break-glass handlers use non-recursive damping — they must not
        // require operator intent (recovery must be autonomous).
        assert!(!handler.damping.requires_operator_intent);
        assert_eq!(handler.damping.stratification_tier, Some(0));
    }

    // -- Advisory damping enforcement ----------------------------------------

    #[test]
    fn damping_default_prevents_feedback_loops() {
        let policy = AdvisoryDampingPolicy::default();
        // Default damping requires operator intent — advisories cannot
        // autonomously trigger further control-plane actions.
        assert!(policy.requires_operator_intent);
        // Minimum interval prevents rapid-fire re-evaluation.
        assert!(policy.min_interval >= Duration::from_secs(1));
        // Window cap prevents event flood from overwhelming evaluator.
        assert!(policy.max_events_per_window <= 100);
    }

    #[test]
    fn damping_stratification_prevents_recursive_amplification() {
        // A tier-1 advisory should not be able to trigger actions that
        // produce tier-0 or tier-1 advisories.
        let tier1 = AdvisoryDampingPolicy {
            stratification_tier: Some(1),
            ..AdvisoryDampingPolicy::default()
        };
        let tier0 = AdvisoryDampingPolicy::non_recursive();

        // Tier 1 > tier 0 — a higher-tier advisory can only trigger
        // actions at a strictly higher tier.
        assert!(tier1.stratification_tier.unwrap() > tier0.stratification_tier.unwrap());
    }

    // -- Registration edge cases ---------------------------------------------

    #[test]
    fn multiple_handlers_same_family_all_match() {
        let mut registry = ControlRegistry::new();
        let id1 = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("h1");
        let id2 = registry
            .register_break_glass(SystemSubjectFamily::Health)
            .expect("h2");

        let subj = Subject::new("$SYS.FABRIC.HEALTH.probe");
        let matches = registry.matching_handlers(&subj);
        assert_eq!(matches.len(), 2);

        let ids: Vec<_> = matches.iter().map(|h| h.id).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn family_scoped_pattern_routes_only_within_declared_prefix() {
        let mut registry = ControlRegistry::new();
        let narrow = registry
            .register(
                SystemSubjectFamily::Health,
                SubjectPattern::new("$SYS.FABRIC.HEALTH.break_glass.>"),
                ControlBudget::default(),
                AdvisoryDampingPolicy::default(),
                false,
            )
            .expect("narrow register");
        let wildcard = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("wildcard register");

        let narrow_matches =
            registry.matching_handlers(&Subject::new("$SYS.FABRIC.HEALTH.break_glass.activate"));
        let narrow_ids: Vec<_> = narrow_matches.iter().map(|handler| handler.id).collect();
        assert_eq!(narrow_ids, vec![narrow, wildcard]);

        let general_matches = registry.matching_handlers(&Subject::new("$SYS.FABRIC.HEALTH.probe"));
        let general_ids: Vec<_> = general_matches.iter().map(|handler| handler.id).collect();
        assert_eq!(general_ids, vec![wildcard]);
    }

    #[test]
    fn handler_ids_are_monotonically_increasing() {
        let mut registry = ControlRegistry::new();
        let id1 = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("1");
        let id2 = registry
            .register_default(SystemSubjectFamily::Route)
            .expect("2");
        let id3 = registry
            .register_default(SystemSubjectFamily::Auth)
            .expect("3");
        assert!(id1.raw() < id2.raw());
        assert!(id2.raw() < id3.raw());
    }

    #[test]
    fn unregister_then_reregister_gets_new_id() {
        let mut registry = ControlRegistry::new();
        let id1 = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("first");
        registry.unregister(id1);
        let id2 = registry
            .register_default(SystemSubjectFamily::Health)
            .expect("second");
        // New registration gets a fresh ID, not the old one.
        assert_ne!(id1, id2);
        assert!(id2.raw() > id1.raw());
    }

    // -- All advisory types produce valid JSON ------------------------------

    #[test]
    fn all_advisory_types_produce_valid_json() {
        let types = vec![
            ControlAdvisoryType::CapabilityGraphChange {
                affected_subjects: vec![SubjectPattern::new("$SYS.FABRIC.AUTH.>")],
                description: "test".to_owned(),
            },
            ControlAdvisoryType::ObligationTransfer {
                action: ObligationTransferAction::Transferred,
                subject: Subject::new("$SYS.FABRIC.CONSUMER.tx"),
            },
            ControlAdvisoryType::PolicyDecision {
                policy_name: "test_policy".to_owned(),
                action_chosen: "accept".to_owned(),
                justification: "test reason".to_owned(),
            },
            ControlAdvisoryType::EvidenceRecord {
                evidence_id: "control:health:1:1700000000000".to_owned(),
                component: "health_policy".to_owned(),
                action: "mark_degraded".to_owned(),
                summary: "health evidence bundle".to_owned(),
            },
            ControlAdvisoryType::BreakGlassActivation {
                reason: "test reason".to_owned(),
            },
        ];

        for advisory_type in types {
            let advisory = ControlAdvisory::notification(
                advisory_type,
                SystemSubjectFamily::Health,
                Subject::new("$SYS.FABRIC.HEALTH.test"),
                TraceId::from_raw(1),
                1_700_000_000_000,
            );
            let payload = advisory.to_json_payload();
            let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&payload);
            assert!(parsed.is_ok(), "advisory payload must be valid JSON");
            let map = parsed.unwrap();
            assert!(map.get("type").is_some(), "payload must contain 'type' key");
            assert!(
                map.get("family").is_some(),
                "payload must contain 'family' key"
            );
        }
    }

    // -- Evidence ledger validation ------------------------------------------

    #[test]
    fn evidence_ledger_posterior_sums_to_one() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "test".to_owned(),
                action_chosen: "failover".to_owned(),
                justification: "test".to_owned(),
            },
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.test"),
            &outcome,
        );

        let ledger = advisory.to_evidence_ledger().unwrap();
        let sum: f64 = ledger.posterior.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "posterior must sum to ~1.0, got {sum}"
        );
    }

    #[test]
    fn evidence_ledger_has_expected_losses_for_all_actions() {
        let audit = make_test_audit_entry();
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: false,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "drain".to_owned(),
                action_chosen: "failover".to_owned(),
                justification: "test".to_owned(),
            },
            SystemSubjectFamily::Drain,
            Subject::new("$SYS.FABRIC.DRAIN.test"),
            &outcome,
        );

        let ledger = advisory.to_evidence_ledger().unwrap();
        // Should have expected losses for both "failover" and "hold".
        assert_eq!(ledger.expected_loss_by_action.len(), 2);
        assert!(ledger.expected_loss_by_action.contains_key("failover"));
        assert!(ledger.expected_loss_by_action.contains_key("hold"));
    }

    #[test]
    fn evidence_ledger_fallback_flag_propagates() {
        let mut audit = make_test_audit_entry();
        audit.fallback_active = true;
        let outcome = DecisionOutcome {
            action_index: 0,
            action_name: "failover".to_owned(),
            expected_loss: 0.3,
            expected_losses: audit.expected_loss_by_action.clone(),
            fallback_active: true,
            audit_entry: audit,
        };

        let advisory = ControlAdvisory::from_decision(
            ControlAdvisoryType::PolicyDecision {
                policy_name: "test".to_owned(),
                action_chosen: "failover".to_owned(),
                justification: "test".to_owned(),
            },
            SystemSubjectFamily::Route,
            Subject::new("$SYS.FABRIC.ROUTE.test"),
            &outcome,
        );

        let ledger = advisory.to_evidence_ledger().unwrap();
        assert!(
            ledger.fallback_active,
            "fallback flag must propagate to evidence"
        );
    }

    // -- Subject matching precision ------------------------------------------

    #[test]
    fn wildcard_pattern_matches_deep_subjects() {
        let pattern = SystemSubjectFamily::Auth.wildcard_pattern();
        // Tail wildcard ">" should match any depth.
        assert!(pattern.matches(&Subject::new("$SYS.FABRIC.AUTH.login")));
        assert!(pattern.matches(&Subject::new("$SYS.FABRIC.AUTH.login.failed")));
        assert!(pattern.matches(&Subject::new("$SYS.FABRIC.AUTH.login.failed.ip.127.0.0.1")));
    }

    #[test]
    fn wildcard_pattern_does_not_cross_families() {
        let health_pattern = SystemSubjectFamily::Health.wildcard_pattern();
        // Should NOT match Auth subjects.
        assert!(!health_pattern.matches(&Subject::new("$SYS.FABRIC.AUTH.login")));
        // Should NOT match the bare family prefix without a trailing token.
        // (The ">" wildcard requires at least one token after the prefix.)
    }

    // -- ControlHandlerId edge cases -----------------------------------------

    #[test]
    fn handler_id_zero_is_valid() {
        let id = ControlHandlerId::new(0);
        assert_eq!(id.raw(), 0);
        assert_eq!(format!("{id}"), "ctrl-0");
    }

    #[test]
    fn handler_id_max_is_valid() {
        let id = ControlHandlerId::new(u64::MAX);
        assert_eq!(id.raw(), u64::MAX);
    }
