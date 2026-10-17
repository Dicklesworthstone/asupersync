    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::monitor::DownReason;
    use crate::record::{ObligationAbortReason, ObligationKind};
    use crate::types::{CancelReason, ObligationId, RegionId, TaskId, Time};
    use insta::assert_json_snapshot;
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    struct CanonicalTraceSnapshot {
        depth: usize,
        len: usize,
        layers: Vec<Vec<CanonicalTraceEventSnapshot>>,
    }

    #[derive(Debug, Serialize)]
    struct CanonicalTraceEventSnapshot {
        seq: u64,
        time_ns: u64,
        kind: &'static str,
        key: TraceEventKey,
        data: String,
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

    fn canonical_trace_snapshot(events: &[TraceEvent]) -> CanonicalTraceSnapshot {
        let foata = canonicalize(events);
        CanonicalTraceSnapshot {
            depth: foata.depth(),
            len: foata.len(),
            layers: foata
                .layers()
                .iter()
                .map(|layer| layer.iter().map(snapshot_event).collect())
                .collect(),
        }
    }

    fn snapshot_event(event: &TraceEvent) -> CanonicalTraceEventSnapshot {
        CanonicalTraceEventSnapshot {
            seq: event.seq,
            time_ns: event.time.as_nanos(),
            kind: event.kind.stable_name(),
            key: trace_event_key(event),
            data: snapshot_event_data(&event.data),
        }
    }

    fn snapshot_event_data(data: &TraceData) -> String {
        match data {
            TraceData::None => "none".to_string(),
            TraceData::Task { task, region } => {
                format!("task={} region={}", task.as_u64(), region.as_u64())
            }
            TraceData::Region { region, parent } => format!(
                "region={} parent={}",
                region.as_u64(),
                parent.map_or_else(|| "none".to_string(), |region| region.as_u64().to_string())
            ),
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => format!(
                "obligation={} task={} region={} kind={} state={state:?} duration_ns={} abort_reason={}",
                pack_arena(obligation.arena_index()),
                task.as_u64(),
                region.as_u64(),
                kind.as_str(),
                duration_ns.map_or_else(|| "none".to_string(), |value| value.to_string()),
                abort_reason
                    .map_or_else(|| "none".to_string(), |reason| reason.as_str().to_string())
            ),
            TraceData::Cancel {
                task,
                region,
                reason,
            } => format!(
                "task={} region={} reason={reason}",
                task.as_u64(),
                region.as_u64()
            ),
            TraceData::RegionCancel { region, reason } => {
                format!("region={} reason={reason}", region.as_u64())
            }
            TraceData::Time { old, new } => {
                format!("old={} new={}", old.as_nanos(), new.as_nanos())
            }
            TraceData::Timer { timer_id, deadline } => format!(
                "timer_id={timer_id} deadline={}",
                deadline.map_or_else(|| "none".to_string(), |time| time.as_nanos().to_string())
            ),
            TraceData::Checkpoint {
                sequence,
                active_tasks,
                active_regions,
            } => format!(
                "sequence={sequence} active_tasks={active_tasks} active_regions={active_regions}"
            ),
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn trace_canonicalize_happy_path_snapshot() {
        let events = [
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
            TraceEvent::poll(4, Time::from_nanos(5), tid(1), rid(1)),
            TraceEvent::complete(5, Time::from_nanos(9), tid(1), rid(1)),
            TraceEvent::complete(6, Time::from_nanos(11), tid(2), rid(1)),
        ];

        assert_json_snapshot!(
            "trace_canonicalize_happy_path",
            canonical_trace_snapshot(&events)
        );
    }

    #[test]
    fn trace_canonicalize_empty_snapshot() {
        assert_json_snapshot!("trace_canonicalize_empty", canonical_trace_snapshot(&[]));
    }

    #[test]
    fn trace_canonicalize_max_budget_snapshot() {
        let events = [
            TraceEvent::region_created(1, Time::ZERO, rid(9), None),
            TraceEvent::spawn(2, Time::from_nanos(1), tid(9), rid(9)),
            TraceEvent::obligation_reserve(
                3,
                Time::from_nanos(2),
                oid(7),
                tid(9),
                rid(9),
                ObligationKind::Lease,
            ),
            TraceEvent::time_advance(4, Time::from_nanos(3), Time::ZERO, Time::MAX),
            TraceEvent::timer_scheduled(5, Time::MAX, u64::MAX, Time::MAX),
            TraceEvent::obligation_commit(
                6,
                Time::MAX,
                oid(7),
                tid(9),
                rid(9),
                ObligationKind::Lease,
                u64::MAX,
            ),
            TraceEvent::checkpoint(7, Time::MAX, u64::MAX, u32::MAX, u32::MAX),
        ];

        assert_json_snapshot!(
            "trace_canonicalize_max_budget",
            canonical_trace_snapshot(&events)
        );
    }

    #[test]
    fn trace_canonicalize_cancellation_chain_snapshot() {
        let cancel = CancelReason::timeout();
        let events = [
            TraceEvent::region_created(1, Time::ZERO, rid(3), None),
            TraceEvent::spawn(2, Time::from_nanos(1), tid(4), rid(3)),
            TraceEvent::obligation_reserve(
                3,
                Time::from_nanos(2),
                oid(4),
                tid(4),
                rid(3),
                ObligationKind::SendPermit,
            ),
            TraceEvent::cancel_request(4, Time::from_nanos(3), tid(4), rid(3), cancel.clone()),
            TraceEvent::new(
                5,
                Time::from_nanos(4),
                TraceEventKind::CancelAck,
                TraceData::Cancel {
                    task: tid(4),
                    region: rid(3),
                    reason: cancel.clone(),
                },
            ),
            TraceEvent::obligation_abort(
                6,
                Time::from_nanos(5),
                oid(4),
                tid(4),
                rid(3),
                ObligationKind::SendPermit,
                17,
                ObligationAbortReason::Cancel,
            ),
            TraceEvent::region_cancelled(7, Time::from_nanos(6), rid(3), cancel),
        ];

        assert_json_snapshot!(
            "trace_canonicalize_cancellation_chain",
            canonical_trace_snapshot(&events)
        );
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

    // === Deterministic ordering keys (bd-wwnkh) ===

    #[test]
    fn down_delivered_canonicalizes_by_completion_vt_monitored_monitor_ref() {
        let e0 = TraceEvent::down_delivered(
            1,
            Time::ZERO,
            1,
            tid(10),
            tid(3),
            Time::from_nanos(4),
            DownReason::Normal,
        );
        let e1 = TraceEvent::down_delivered(
            2,
            Time::ZERO,
            10,
            tid(11),
            tid(1),
            Time::from_nanos(5),
            DownReason::Normal,
        );
        let e2 = TraceEvent::down_delivered(
            3,
            Time::ZERO,
            9,
            tid(12),
            tid(1),
            Time::from_nanos(5),
            DownReason::Normal,
        );
        let e3 = TraceEvent::down_delivered(
            4,
            Time::ZERO,
            1,
            tid(13),
            tid(2),
            Time::from_nanos(5),
            DownReason::Normal,
        );

        // All four events are independent (distinct watcher tasks). Canonical
        // ordering within the layer must follow:
        // (completion_vt, monitored_tid, monitor_ref).
        let trace_a = [e0.clone(), e1.clone(), e2.clone(), e3.clone()];
        let trace_b = [e3.clone(), e2.clone(), e1.clone(), e0.clone()];

        let foata_a = canonicalize(&trace_a);
        let foata_b = canonicalize(&trace_b);
        assert_eq!(foata_a.fingerprint(), foata_b.fingerprint());
        assert_eq!(foata_a.depth(), 1);

        let flat = foata_a.flatten();
        assert_eq!(flat.len(), 4);
        assert_eq!(flat[0], e0);
        assert_eq!(flat[1], e2);
        assert_eq!(flat[2], e1);
        assert_eq!(flat[3], e3);
    }

    #[test]
    fn exit_delivered_canonicalizes_by_failure_vt_from_link_ref() {
        let e0 = TraceEvent::exit_delivered(
            1,
            Time::ZERO,
            1,
            tid(2),
            tid(20),
            Time::from_nanos(9),
            DownReason::Error("boom".to_string()),
        );
        let e1 = TraceEvent::exit_delivered(
            2,
            Time::ZERO,
            10,
            tid(1),
            tid(21),
            Time::from_nanos(10),
            DownReason::Error("boom".to_string()),
        );
        let e2 = TraceEvent::exit_delivered(
            3,
            Time::ZERO,
            9,
            tid(1),
            tid(22),
            Time::from_nanos(10),
            DownReason::Error("boom".to_string()),
        );
        let e3 = TraceEvent::exit_delivered(
            4,
            Time::ZERO,
            1,
            tid(3),
            tid(23),
            Time::from_nanos(10),
            DownReason::Error("boom".to_string()),
        );

        // Canonical ordering must follow:
        // (failure_vt, from_tid, link_ref).
        let trace_a = [e3.clone(), e2.clone(), e1.clone(), e0.clone()];
        let trace_b = [e0.clone(), e1.clone(), e2.clone(), e3.clone()];

        let foata_a = canonicalize(&trace_a);
        let foata_b = canonicalize(&trace_b);
        assert_eq!(foata_a.fingerprint(), foata_b.fingerprint());
        assert_eq!(foata_a.depth(), 1);

        let flat = foata_a.flatten();
        assert_eq!(flat.len(), 4);
        assert_eq!(flat[0], e0);
        assert_eq!(flat[1], e2);
        assert_eq!(flat[2], e1);
        assert_eq!(flat[3], e3);
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
            vec![e3, e2, e1],
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

    #[test]
    fn equal_canonical_keys_still_have_total_sort_order() {
        let events = (0..16)
            .map(|idx| {
                TraceEvent::new(
                    idx,
                    Time::from_nanos(idx),
                    TraceEventKind::UserTrace,
                    TraceData::Message("same canonical message".to_string()),
                )
            })
            .collect::<Vec<_>>();

        let foata = canonicalize(&events);
        assert_eq!(foata.depth(), 1);
        assert_eq!(foata.len(), events.len());

        let fingerprint = trace_fingerprint(&events);
        assert_ne!(fingerprint, 0);
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
    fn empty_trace_fingerprint_matches_identity() {
        let id = TraceMonoid::identity();
        let empty = TraceMonoid::from_events(&[]);
        assert_eq!(trace_fingerprint(&[]), id.class_fingerprint());
        assert_eq!(id.class_fingerprint(), empty.class_fingerprint());
        assert!(id.equivalent(&empty));
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

    // === TraceMonoid: identity law ===

    #[test]
    fn monoid_identity_left() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let t = TraceMonoid::from_events(&events);
        let result = TraceMonoid::identity().concat(&t);
        assert!(result.equivalent(&t));
        assert!(result.equivalent_exact(&t));
    }

    #[test]
    fn monoid_identity_right() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let t = TraceMonoid::from_events(&events);
        let result = t.concat(&TraceMonoid::identity());
        assert!(result.equivalent(&t));
        assert!(result.equivalent_exact(&t));
    }

    #[test]
    fn monoid_identity_is_empty() {
        let id = TraceMonoid::identity();
        assert!(id.is_identity());
        assert!(id.is_empty());
        assert_eq!(id.len(), 0);
        assert_eq!(id.critical_path_length(), 0);
        assert_eq!(id.max_parallelism(), 0);
    }

    // === TraceMonoid: associativity ===

    #[test]
    fn monoid_associativity() {
        let a_events = [TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
        let b_events = [TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2))];
        let c_events = [TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3))];

        let a = TraceMonoid::from_events(&a_events);
        let b = TraceMonoid::from_events(&b_events);
        let c = TraceMonoid::from_events(&c_events);

        let ab_c = a.concat(&b).concat(&c);
        let a_bc = a.concat(&b.concat(&c));
        assert!(ab_c.equivalent(&a_bc));
    }

    #[test]
    fn monoid_associativity_with_dependencies() {
        // a and b are dependent (same task), c is independent
        let a_events = [TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
        let b_events = [TraceEvent::complete(2, Time::ZERO, tid(1), rid(1))];
        let c_events = [TraceEvent::spawn(3, Time::ZERO, tid(2), rid(2))];

        let a = TraceMonoid::from_events(&a_events);
        let b = TraceMonoid::from_events(&b_events);
        let c = TraceMonoid::from_events(&c_events);

        let ab_c = a.concat(&b).concat(&c);
        let a_bc = a.concat(&b.concat(&c));
        assert!(ab_c.equivalent(&a_bc));
    }

    // === TraceMonoid: equivalence ===

    #[test]
    fn monoid_equivalent_traces() {
        // Two orderings of independent events → same monoid element
        let trace_a = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];
        let trace_b = [
            TraceEvent::spawn(1, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        ];
        let ma = TraceMonoid::from_events(&trace_a);
        let mb = TraceMonoid::from_events(&trace_b);
        assert_eq!(ma, mb);
        assert!(ma.equivalent_exact(&mb));
    }

    #[test]
    fn partial_eq_requires_exact_canonical_match_not_just_fingerprint() {
        let trace_a = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let trace_b = [
            TraceEvent::spawn(1, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(2, Time::ZERO, tid(2), rid(2)),
        ];

        let ma = TraceMonoid::from_events(&trace_a);
        let mb = TraceMonoid::from_events(&trace_b);
        assert!(!ma.equivalent_exact(&mb));

        // Construct an impossible-but-valid-internal state to model hash collision:
        // same fingerprint, different canonical form.
        let TraceMonoid {
            canonical: FoataTrace { layers },
            ..
        } = mb;
        let spoof = TraceMonoid {
            canonical: FoataTrace { layers },
            fingerprint: ma.fingerprint,
        };

        // Fingerprint-only equivalence says "equal", but PartialEq must remain exact.
        assert!(ma.equivalent(&spoof));
        assert_ne!(ma, spoof);
    }

    #[test]
    fn exact_equivalence_distinguishes_region_cancel_reason_payload() {
        let trace_a = [TraceEvent::region_cancelled(
            1,
            Time::ZERO,
            rid(1),
            CancelReason::shutdown(),
        )];
        let trace_b = [TraceEvent::region_cancelled(
            1,
            Time::ZERO,
            rid(1),
            CancelReason::timeout(),
        )];

        let ma = TraceMonoid::from_events(&trace_a);
        let mb = TraceMonoid::from_events(&trace_b);

        assert!(ma.equivalent(&mb));
        assert!(!ma.equivalent_exact(&mb));
        assert_ne!(ma, mb);
    }

    #[test]
    fn monoid_nonequivalent_traces() {
        // Different causal structures → different monoid elements
        let trace_a = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let trace_b = [
            TraceEvent::spawn(1, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(2, Time::ZERO, tid(2), rid(2)),
        ];
        let ma = TraceMonoid::from_events(&trace_a);
        let mb = TraceMonoid::from_events(&trace_b);
        assert_ne!(ma, mb);
    }

    // === TraceMonoid: parallelism metrics ===

    #[test]
    fn monoid_parallelism_metrics() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3)),
            TraceEvent::complete(4, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(5, Time::ZERO, tid(2), rid(2)),
        ];
        let m = TraceMonoid::from_events(&events);
        assert_eq!(m.len(), 5);
        assert_eq!(m.critical_path_length(), 2); // spawns then completes
        assert_eq!(m.max_parallelism(), 3); // 3 independent spawns
    }

    #[test]
    fn monoid_from_events_mapping() {
        // Verify the mapping φ: Σ* → M(Σ, I) preserves trace length
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::region_created(2, Time::ZERO, rid(2), None),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(2)),
        ];
        let m = TraceMonoid::from_events(&events);
        assert_eq!(m.len(), events.len());
        assert_eq!(m.class_fingerprint(), trace_fingerprint(&events));
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

    // --- wave 77 trait coverage ---

    #[test]
    fn trace_event_key_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let k = TraceEventKey::new(1, 2, 3, 4);
        let k2 = k; // Copy
        let k3 = k;
        assert_eq!(k, k2);
        assert_eq!(k, k3);
        assert_ne!(k, TraceEventKey::new(1, 2, 3, 5));
        let dbg = format!("{k:?}");
        assert!(dbg.contains("TraceEventKey"));
        let mut set = HashSet::new();
        set.insert(k);
        assert!(set.contains(&k2));
    }

    /// The layer assignment `foata_layers` replaced: compare every pair with
    /// `independent` (br-asupersync-bzict6).
    fn pairwise_layers(events: &[TraceEvent]) -> (Vec<usize>, usize) {
        let n = events.len();
        let mut layer_of = vec![0usize; n];
        let mut max_layer = 0usize;
        for j in 1..n {
            for i in 0..j {
                if !crate::trace::independence::independent(&events[i], &events[j]) {
                    layer_of[j] = layer_of[j].max(layer_of[i] + 1);
                }
            }
            max_layer = max_layer.max(layer_of[j]);
        }
        (layer_of, max_layer)
    }

    fn undecodable_handoff(seq: u64) -> TraceEvent {
        TraceEvent::user_trace(seq, Time::ZERO, "obligation_handoff_v9 {}")
    }

    fn close_begin(seq: u64, region: RegionId) -> TraceEvent {
        TraceEvent::new(
            seq,
            Time::ZERO,
            TraceEventKind::RegionCloseBegin,
            TraceData::Region {
                region,
                parent: None,
            },
        )
    }

    /// `foata_layers` gives every event the layer the pairwise scan gives it,
    /// on hand-picked edge cases and on pseudo-random traces.
    #[test]
    fn foata_layers_match_the_pairwise_scan() {
        let note = |seq| TraceEvent::user_trace(seq, Time::ZERO, "note");
        // Footprint-free notes, two reads of one resource, a read after a
        // write, an undecodable handoff (dependent on everything), and a
        // duplicate sequence number.
        let picked = vec![
            note(1),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::checkpoint(3, Time::ZERO, 0, 0, 0),
            TraceEvent::checkpoint(4, Time::ZERO, 1, 0, 0),
            TraceEvent::spawn(5, Time::ZERO, tid(2), rid(1)),
            close_begin(6, rid(1)),
            undecodable_handoff(7),
            note(8),
            TraceEvent::spawn(2, Time::ZERO, tid(3), rid(2)),
            TraceEvent::region_created(10, Time::ZERO, rid(3), Some(rid(2))),
        ];
        assert_eq!(foata_layers(&picked), pairwise_layers(&picked));

        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = |bound: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % bound
        };
        for trace in 0..24 {
            let len = 40 + next(260);
            let events: Vec<TraceEvent> = (0..len)
                .map(|k| {
                    let seq = if next(16) == 0 { next(len) } else { k };
                    let task = tid(next(6) as u32 + 1);
                    let region = rid(next(3) as u32 + 1);
                    let obligation = oid(next(5) as u32 + 1);
                    match next(12) {
                        0 => TraceEvent::spawn(seq, Time::ZERO, task, region),
                        1 => TraceEvent::complete(seq, Time::ZERO, task, region),
                        2 => TraceEvent::obligation_reserve(
                            seq,
                            Time::ZERO,
                            obligation,
                            task,
                            region,
                            ObligationKind::SendPermit,
                        ),
                        3 => TraceEvent::obligation_commit(
                            seq,
                            Time::ZERO,
                            obligation,
                            task,
                            region,
                            ObligationKind::SendPermit,
                            0,
                        ),
                        4 => TraceEvent::checkpoint(seq, Time::ZERO, k, 0, 0),
                        5 => TraceEvent::time_advance(seq, Time::ZERO, Time::ZERO, Time::MAX),
                        6 => TraceEvent::timer_scheduled(seq, Time::ZERO, next(3), Time::MAX),
                        7 => note(seq),
                        8 => close_begin(seq, region),
                        9 => TraceEvent::region_created(seq, Time::ZERO, region, Some(rid(1))),
                        10 if next(4) == 0 => undecodable_handoff(seq),
                        _ => TraceEvent::poll(seq, Time::ZERO, task, region),
                    }
                })
                .collect();
            assert_eq!(
                foata_layers(&events),
                pairwise_layers(&events),
                "trace {trace}"
            );
        }
    }

    /// Metamorphic tests for the Foata normal form: commutation invariance,
    /// dependency preservation, the `trace_fingerprint`/`canonicalize`
    /// equivalence, and the `TraceMonoid` algebraic laws.
    mod metamorphic {
        use super::*;

        /// SplitMix64 — deterministic shuffles so failures reproduce by seed.
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
            fn below(&mut self, n: usize) -> usize {
                (self.next_u64() % n as u64) as usize
            }
        }

        fn task(n: u32) -> TaskId {
            TaskId::new_for_test(n, 0)
        }
        fn region(n: u32) -> RegionId {
            RegionId::new_for_test(n, 0)
        }

        /// `n` pairwise-independent events: spawns on distinct task+region, so
        /// every footprint is disjoint and the whole set commutes freely.
        fn independent_set(n: u32) -> Vec<TraceEvent> {
            (1..=n)
                .map(|k| TraceEvent::spawn(u64::from(k), Time::ZERO, task(k), region(k)))
                .collect()
        }

        /// A chain of mutually dependent events — every event writes Task(1).
        fn dependent_chain(n: u64) -> Vec<TraceEvent> {
            (0..n)
                .map(|k| {
                    let t = Time::from_nanos(k);
                    match k % 4 {
                        0 => TraceEvent::spawn(k, t, task(1), region(1)),
                        1 => TraceEvent::schedule(k, t, task(1), region(1)),
                        2 => TraceEvent::poll(k, t, task(1), region(1)),
                        _ => TraceEvent::complete(k, t, task(1), region(1)),
                    }
                })
                .collect()
        }

        fn shuffled(items: &[TraceEvent], rng: &mut Rng) -> Vec<TraceEvent> {
            let mut v = items.to_vec();
            for i in (1..v.len()).rev() {
                let j = rng.below(i + 1);
                v.swap(i, j);
            }
            v
        }

        fn canonical_seqs(events: &[TraceEvent]) -> Vec<u64> {
            canonicalize(events)
                .flatten()
                .iter()
                .map(|e| e.seq)
                .collect()
        }

        #[test]
        fn canonicalize_and_fingerprint_are_deterministic() {
            for n in [0u64, 1, 2, 5, 9, 16] {
                let trace = dependent_chain(n);
                assert_eq!(
                    trace_fingerprint(&trace),
                    trace_fingerprint(&trace),
                    "trace_fingerprint non-deterministic (n={n})"
                );
                assert_eq!(
                    canonical_seqs(&trace),
                    canonical_seqs(&trace),
                    "canonicalize non-deterministic (n={n})"
                );
            }
        }

        #[test]
        fn trace_fingerprint_equals_canonicalize_fingerprint() {
            // Documented equivalence: trace_fingerprint is the allocation-free
            // form of canonicalize(events).fingerprint().
            let mixed = {
                let z = Time::ZERO;
                vec![
                    TraceEvent::spawn(1, z, task(1), region(1)),
                    TraceEvent::spawn(2, z, task(2), region(2)),
                    TraceEvent::complete(3, z, task(1), region(1)),
                    TraceEvent::complete(4, z, task(2), region(2)),
                ]
            };
            let cases = [
                Vec::new(),
                independent_set(1),
                independent_set(6),
                dependent_chain(7),
                mixed,
            ];
            for trace in cases {
                assert_eq!(
                    trace_fingerprint(&trace),
                    canonicalize(&trace).fingerprint(),
                    "trace_fingerprint diverged from canonicalize().fingerprint()"
                );
            }
        }

        #[test]
        fn permuting_fully_independent_events_yields_one_identical_layer() {
            // Pairwise-independent events commute freely: every permutation
            // canonicalizes to the same single layer with the same fingerprint.
            for n in [2u32, 3, 5, 8, 13] {
                let base = independent_set(n);
                let baseline = canonicalize(&base);
                assert_eq!(
                    baseline.depth(),
                    1,
                    "independent events must collapse to one layer"
                );
                let baseline_fp = baseline.fingerprint();

                for seed in 0..16u64 {
                    let mut rng = Rng::new(seed ^ u64::from(n) << 8);
                    let permuted = shuffled(&base, &mut rng);
                    let canon = canonicalize(&permuted);
                    assert_eq!(
                        canon.fingerprint(),
                        baseline_fp,
                        "independent permutation changed the fingerprint (n={n}, seed={seed})"
                    );
                    assert_eq!(canon.depth(), 1);
                    assert_eq!(trace_fingerprint(&permuted), baseline_fp);
                }
            }
        }

        #[test]
        fn swapping_an_adjacent_independent_pair_preserves_the_canonical_form() {
            // Indices 1 and 2 are spawns on disjoint task+region: independent,
            // so swapping them must not change the equivalence class.
            let z = Time::ZERO;
            let original = vec![
                TraceEvent::spawn(1, z, task(1), region(1)),
                TraceEvent::spawn(2, z, task(2), region(2)),
                TraceEvent::spawn(3, z, task(3), region(3)),
                TraceEvent::complete(4, z, task(1), region(1)),
            ];
            let mut swapped = original.clone();
            swapped.swap(1, 2);
            assert_eq!(
                trace_fingerprint(&original),
                trace_fingerprint(&swapped),
                "swapping an adjacent independent pair changed the class"
            );
            assert_eq!(
                canonicalize(&original).fingerprint(),
                canonicalize(&swapped).fingerprint()
            );
        }

        #[test]
        fn a_dependent_chain_keeps_one_event_per_layer() {
            // Every event writes Task(1): the canonical form is fully
            // sequential — depth == length, every layer width 1.
            for n in 1u64..=12 {
                let canon = canonicalize(&dependent_chain(n));
                assert_eq!(canon.depth(), n as usize, "chain of {n} needs {n} layers");
                for layer in canon.layers() {
                    assert_eq!(layer.len(), 1, "dependent-chain layer holds one event");
                }
            }
        }

        #[test]
        fn flatten_preserves_the_event_count() {
            for n in [0u64, 1, 4, 10] {
                let dep = dependent_chain(n);
                assert_eq!(canonicalize(&dep).flatten().len(), dep.len());
            }
            for n in [1u32, 5, 11] {
                let ind = independent_set(n);
                assert_eq!(canonicalize(&ind).flatten().len(), ind.len());
            }
        }

        #[test]
        fn monoid_identity_is_empty_and_neutral() {
            let identity = TraceMonoid::identity();
            assert!(identity.is_identity());
            assert!(identity.is_empty());
            assert_eq!(identity.len(), 0);

            let m = TraceMonoid::from_events(&dependent_chain(5));
            assert_eq!(identity.concat(&m), m, "left identity law");
            assert_eq!(m.concat(&identity), m, "right identity law");
        }

        #[test]
        fn monoid_concat_is_associative() {
            let a = TraceMonoid::from_events(&independent_set(3));
            let b = TraceMonoid::from_events(&dependent_chain(4));
            let c = TraceMonoid::from_events(&independent_set(2));
            assert_eq!(
                a.concat(&b).concat(&c),
                a.concat(&b.concat(&c)),
                "concat must be associative"
            );
        }

        #[test]
        fn monoid_groups_independent_reorderings_into_one_class() {
            let base = independent_set(7);
            let mut rng = Rng::new(0xC0FFEE);
            let permuted = shuffled(&base, &mut rng);
            let m1 = TraceMonoid::from_events(&base);
            let m2 = TraceMonoid::from_events(&permuted);
            assert!(m1.equivalent(&m2), "independent reorderings are one class");
            assert_eq!(m1, m2, "and structurally equal");
        }

        #[test]
        fn monoid_equivalence_is_reflexive() {
            for trace in [independent_set(6), dependent_chain(8)] {
                let m = TraceMonoid::from_events(&trace);
                assert!(m.equivalent(&m), "equivalence must be reflexive");
                assert!(
                    m.equivalent_exact(&m),
                    "exact equivalence must be reflexive"
                );
                let again = TraceMonoid::from_events(&trace);
                assert_eq!(m, again, "PartialEq must be reflexive");
                assert_eq!(m.class_fingerprint(), canonicalize(&trace).fingerprint());
            }
        }

        #[test]
        fn critical_path_and_parallelism_track_the_canonical_shape() {
            let ind = TraceMonoid::from_events(&independent_set(9));
            assert_eq!(ind.critical_path_length(), 1);
            assert_eq!(ind.max_parallelism(), 9);

            let dep = TraceMonoid::from_events(&dependent_chain(6));
            assert_eq!(dep.critical_path_length(), 6);
            assert_eq!(dep.max_parallelism(), 1);

            let empty = TraceMonoid::identity();
            assert_eq!(empty.critical_path_length(), 0);
            assert_eq!(empty.max_parallelism(), 0);
        }

        #[test]
        fn empty_trace_canonicalizes_to_zero_layers() {
            let canon = canonicalize(&[]);
            assert_eq!(canon.depth(), 0);
            assert!(canon.is_empty());
            assert!(canon.flatten().is_empty());
            assert_eq!(canon.layers().len(), 0);
            assert_eq!(trace_fingerprint(&[]), canon.fingerprint());
        }
    }
