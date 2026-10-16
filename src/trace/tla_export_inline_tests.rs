    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::ObligationKind;
    use crate::types::{ObligationId, RegionId, TaskId, Time};

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    fn oid(n: u32) -> ObligationId {
        ObligationId::new_for_test(n, 0)
    }

    fn transfer_trace() -> (Vec<TraceEvent>, super::super::event::ObligationHandoff) {
        let handoff = super::super::event::ObligationHandoff {
            id: oid(1),
            source_ticket: 2,
            destination_ticket: 7,
            source_holder: tid(1),
            destination_holder: TaskId::new_for_test(1, 2),
            source_region: rid(1),
            destination_region: RegionId::new_for_test(1, 3),
        };
        (
            vec![
                TraceEvent::region_created(1, Time::ZERO, handoff.source_region, None),
                TraceEvent::region_created(2, Time::ZERO, handoff.destination_region, None),
                TraceEvent::spawn(3, Time::ZERO, handoff.source_holder, handoff.source_region),
                TraceEvent::spawn(
                    4,
                    Time::ZERO,
                    handoff.destination_holder,
                    handoff.destination_region,
                ),
                TraceEvent::obligation_reserve(
                    5,
                    Time::ZERO,
                    handoff.id,
                    handoff.source_holder,
                    handoff.source_region,
                    ObligationKind::Lease,
                ),
            ],
            handoff,
        )
    }

    #[test]
    fn transfer_export_rebinds_one_pending_id_with_distinct_generations() {
        let (mut events, handoff) = transfer_trace();
        events.push(TraceEvent::obligation_handoff(
            6,
            Time::from_nanos(23),
            &handoff,
        ));
        events.push(TraceEvent::complete(
            7,
            Time::from_nanos(24),
            handoff.source_holder,
            handoff.source_region,
        ));
        events.push(TraceEvent::obligation_commit(
            8,
            Time::from_nanos(31),
            handoff.id,
            handoff.destination_holder,
            handoff.destination_region,
            ObligationKind::Lease,
            31,
        ));
        let exporter = TlaExporter::try_from_trace(&events).expect("valid typed ownership history");
        assert_eq!(
            exporter.snapshots[5].obligations[&(1, 0)],
            (TlaObligationState::Reserved, (1, 0), (1, 0))
        );
        assert_eq!(
            exporter.snapshots[6].obligations[&(1, 0)],
            (TlaObligationState::Reserved, (1, 2), (1, 3))
        );
        assert_eq!(exporter.snapshots[6].obligations.len(), 1);
        assert_eq!(
            exporter.snapshots[8].obligations[&(1, 0)],
            (TlaObligationState::Committed, (1, 2), (1, 3))
        );
        assert!(exporter.validation_error().is_none());
        assert!(
            exporter
                .export_behavior("Transferred")
                .source
                .contains("Spec ==")
        );
        // This is the maintained interpreter's output, not an executed TLC proof.
    }

    #[test]
    fn transfer_export_refuses_bad_ownership_without_panicking_or_emitting_a_spec() {
        for scenario in [
            "malformed",
            "unknown",
            "source",
            "generation",
            "ticket",
            "old_terminal",
            "double_terminal",
            "reset_before_terminal",
            "reset_after_terminal",
        ] {
            let (mut events, mut handoff) = transfer_trace();
            match scenario {
                "unknown" => handoff.id = oid(2),
                "source" => handoff.source_region = rid(2),
                "generation" => handoff.destination_holder = TaskId::new_for_test(1, 7),
                "ticket" => handoff.destination_ticket = handoff.source_ticket,
                _ => {}
            }
            events.push(if scenario == "malformed" {
                TraceEvent::user_trace(6, Time::ZERO, "obligation_handoff_v1 {}")
            } else {
                TraceEvent::obligation_handoff(6, Time::ZERO, &handoff)
            });
            if scenario == "reset_after_terminal" {
                events.push(TraceEvent::obligation_commit(
                    7,
                    Time::ZERO,
                    handoff.id,
                    handoff.destination_holder,
                    handoff.destination_region,
                    ObligationKind::Lease,
                    1,
                ));
            }
            if matches!(scenario, "reset_before_terminal" | "reset_after_terminal") {
                events.push(TraceEvent::obligation_reserve(
                    8,
                    Time::ZERO,
                    handoff.id,
                    handoff.source_holder,
                    handoff.source_region,
                    ObligationKind::Lease,
                ));
            }
            if matches!(scenario, "old_terminal" | "double_terminal") {
                let (holder, region) = if scenario == "old_terminal" {
                    (handoff.source_holder, handoff.source_region)
                } else {
                    (handoff.destination_holder, handoff.destination_region)
                };
                events.push(TraceEvent::obligation_commit(
                    7,
                    Time::ZERO,
                    handoff.id,
                    holder,
                    region,
                    ObligationKind::Lease,
                    1,
                ));
                if scenario == "double_terminal" {
                    events.push(TraceEvent::obligation_commit(
                        8,
                        Time::ZERO,
                        handoff.id,
                        holder,
                        region,
                        ObligationKind::Lease,
                        1,
                    ));
                }
            }
            let error = match TlaExporter::try_from_trace(&events) {
                Ok(_) => panic!("invalid handoff accepted: {scenario}"),
                Err(error) => error,
            };
            assert_eq!(error.event_index, events.len() - 1, "{scenario}");
            let legacy = TlaExporter::from_trace(&events);
            assert_eq!(legacy.validation_error(), Some(&error));
            assert_eq!(legacy.snapshot_count(), events.len() + 1);
            let rejected = legacy.export_behavior("CannotProve").source;
            assert!(rejected.starts_with("\\* UNVERIFIABLE_TRANSFER_TRACE"));
            assert!(rejected.lines().all(|line| line.starts_with("\\*")));
            assert!(!rejected.contains("---- MODULE"));
            assert!(!rejected.contains("Spec =="));
            assert!(!rejected.contains("ASSUME FALSE"));
        }
    }

    #[test]
    fn ordinary_annotations_and_existing_negative_trace_export_remain_available() {
        let events = [
            TraceEvent::user_trace(1, Time::ZERO, "ordinary {malformed json"),
            TraceEvent::obligation_leak(
                2,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::Lease,
                1,
            ),
        ];
        let legacy = TlaExporter::from_trace(&events);
        let checked = TlaExporter::try_from_trace(&events).unwrap();
        assert!(legacy.validation_error().is_none());
        assert_eq!(
            legacy.export_behavior("Negative").source,
            checked.export_behavior("Negative").source
        );
        assert!(
            checked
                .export_behavior("Negative")
                .source
                .contains("Spec ==")
        );
    }

    #[test]
    fn transfer_export_cannot_resurrect_completed_task_or_closed_region_generations() {
        for scenario in [
            "task_schedule",
            "task_spawn",
            "region_create",
            "region_close_begin",
            "source_closed",
            "duplicate_reserve_prefix",
            "task_owner_rewrite",
        ] {
            let (mut events, mut handoff) = transfer_trace();
            if scenario == "task_owner_rewrite" {
                handoff.destination_region = rid(2);
                events.push(TraceEvent::spawn(
                    7,
                    Time::ZERO,
                    handoff.destination_holder,
                    handoff.destination_region,
                ));
            } else if scenario == "source_closed" {
                events.insert(
                    1,
                    TraceEvent::new(
                        1,
                        Time::ZERO,
                        TraceEventKind::RegionCloseComplete,
                        TraceData::Region {
                            region: handoff.source_region,
                            parent: None,
                        },
                    ),
                );
            } else if scenario == "duplicate_reserve_prefix" {
                events.push(TraceEvent::obligation_reserve(
                    7,
                    Time::ZERO,
                    handoff.id,
                    handoff.source_holder,
                    handoff.source_region,
                    ObligationKind::Lease,
                ));
            } else if scenario.starts_with("task_") {
                events.push(TraceEvent::complete(
                    6,
                    Time::ZERO,
                    handoff.destination_holder,
                    handoff.destination_region,
                ));
                events.push(TraceEvent::new(
                    7,
                    Time::ZERO,
                    if scenario == "task_schedule" {
                        TraceEventKind::Schedule
                    } else {
                        TraceEventKind::Spawn
                    },
                    TraceData::Task {
                        task: handoff.destination_holder,
                        region: handoff.destination_region,
                    },
                ));
            } else {
                events.push(TraceEvent::new(
                    6,
                    Time::ZERO,
                    TraceEventKind::RegionCloseComplete,
                    TraceData::Region {
                        region: handoff.destination_region,
                        parent: None,
                    },
                ));
                events.push(TraceEvent::new(
                    7,
                    Time::ZERO,
                    if scenario == "region_create" {
                        TraceEventKind::RegionCreated
                    } else {
                        TraceEventKind::RegionCloseBegin
                    },
                    TraceData::Region {
                        region: handoff.destination_region,
                        parent: None,
                    },
                ));
            }
            let ordinary = TlaExporter::try_from_trace(&events)
                .expect("historical negative prefix remains representable");
            assert!(
                ordinary
                    .export_behavior("HistoricalNegative")
                    .source
                    .contains("Spec ==")
            );
            events.push(TraceEvent::obligation_handoff(8, Time::ZERO, &handoff));
            let rejected = TlaExporter::from_trace(&events);
            assert_eq!(
                rejected.validation_error().expect(scenario).event_index,
                events.len() - 1
            );
            assert!(TlaExporter::try_from_trace(&events).is_err());
            assert!(
                rejected
                    .export_behavior("Refused")
                    .source
                    .starts_with("\\* UNVERIFIABLE_TRANSFER_TRACE")
            );
        }
    }

    #[test]
    fn empty_trace_produces_module() {
        let exporter = TlaExporter::from_trace(&[]);
        let module = exporter.export_behavior("EmptyTest");
        assert!(module.source.contains("MODULE EmptyTest"));
        assert!(module.source.contains("Init =="));
        assert!(module.source.contains("Next == FALSE"));
    }

    #[test]
    fn spawn_complete_trace() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let exporter = TlaExporter::from_trace(&events);
        let module = exporter.export_behavior("SpawnComplete");

        // Should have 3 snapshots: initial, after spawn, after complete.
        assert_eq!(exporter.snapshot_count(), 3);
        assert!(module.source.contains("\"Completed\""));
        assert!(module.source.contains("NoObligationLeaks"));
    }

    #[test]
    fn obligation_lifecycle_trace() {
        let events = [
            TraceEvent::obligation_reserve(
                1,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
            ),
            TraceEvent::obligation_commit(
                2,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
                1000,
            ),
        ];
        let exporter = TlaExporter::from_trace(&events);
        let module = exporter.export_behavior("ObligationTest");

        assert!(module.source.contains("\"Committed\""));
        assert!(module.source.contains("ObligationLinearity"));
    }

    #[test]
    fn spec_skeleton_is_valid_structure() {
        let module = TlaExporter::export_spec_skeleton("RuntimeModel");
        assert!(module.source.contains("MODULE RuntimeModel"));
        assert!(module.source.contains("CONSTANTS MaxTasks"));
        assert!(module.source.contains("SpawnTask(r)"));
        assert!(module.source.contains("CompleteTask(t)"));
        assert!(module.source.contains("CloseRegion(r)"));
        assert!(module.source.contains("NoObligationLeaks"));
        assert!(module.source.contains("QuiescenceOnClose"));
    }

    #[test]
    fn region_lifecycle_in_snapshot() {
        let events = [
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::region_cancelled(
                2,
                Time::ZERO,
                rid(1),
                crate::types::CancelReason::user("test"),
            ),
        ];
        let exporter = TlaExporter::from_trace(&events);
        assert_eq!(exporter.snapshot_count(), 3);

        let module = exporter.export_behavior("RegionLifecycle");
        assert!(module.source.contains("\"Cancelled\""));
    }

    #[test]
    fn display_impl_returns_source() {
        let module = TlaExporter::export_spec_skeleton("Test");
        assert_eq!(format!("{module}"), module.source);
    }

    #[test]
    fn tla_task_state_debug() {
        let dbg = format!("{:?}", TlaTaskState::Spawned);
        assert_eq!(dbg, "Spawned");
        let dbg = format!("{:?}", TlaTaskState::Scheduled);
        assert_eq!(dbg, "Scheduled");
        let dbg = format!("{:?}", TlaTaskState::Polling);
        assert_eq!(dbg, "Polling");
        let dbg = format!("{:?}", TlaTaskState::Yielded);
        assert_eq!(dbg, "Yielded");
        let dbg = format!("{:?}", TlaTaskState::Completed);
        assert_eq!(dbg, "Completed");
        let dbg = format!("{:?}", TlaTaskState::Cancelled);
        assert_eq!(dbg, "Cancelled");
    }

    #[test]
    fn tla_task_state_clone_copy_eq() {
        let s = TlaTaskState::Polling;
        let s2 = s;
        let s3 = s;
        assert_eq!(s2, s3);
        assert_ne!(TlaTaskState::Spawned, TlaTaskState::Completed);
    }

    #[test]
    fn tla_task_state_display_all_variants() {
        assert_eq!(format!("{}", TlaTaskState::Spawned), "\"Spawned\"");
        assert_eq!(format!("{}", TlaTaskState::Scheduled), "\"Scheduled\"");
        assert_eq!(format!("{}", TlaTaskState::Polling), "\"Polling\"");
        assert_eq!(format!("{}", TlaTaskState::Yielded), "\"Yielded\"");
        assert_eq!(format!("{}", TlaTaskState::Completed), "\"Completed\"");
        assert_eq!(format!("{}", TlaTaskState::Cancelled), "\"Cancelled\"");
    }

    #[test]
    fn tla_region_state_debug() {
        let dbg = format!("{:?}", TlaRegionState::Open);
        assert_eq!(dbg, "Open");
        let dbg = format!("{:?}", TlaRegionState::Closing);
        assert_eq!(dbg, "Closing");
        let dbg = format!("{:?}", TlaRegionState::Closed);
        assert_eq!(dbg, "Closed");
        let dbg = format!("{:?}", TlaRegionState::Cancelled);
        assert_eq!(dbg, "Cancelled");
    }

    #[test]
    fn tla_region_state_clone_copy_eq() {
        let s = TlaRegionState::Open;
        let s2 = s;
        let s3 = s;
        assert_eq!(s2, s3);
        assert_ne!(TlaRegionState::Open, TlaRegionState::Closed);
    }

    #[test]
    fn tla_region_state_display_all_variants() {
        assert_eq!(format!("{}", TlaRegionState::Open), "\"Open\"");
        assert_eq!(format!("{}", TlaRegionState::Closing), "\"Closing\"");
        assert_eq!(format!("{}", TlaRegionState::Closed), "\"Closed\"");
        assert_eq!(format!("{}", TlaRegionState::Cancelled), "\"Cancelled\"");
    }

    #[test]
    fn tla_obligation_state_debug() {
        let dbg = format!("{:?}", TlaObligationState::Reserved);
        assert_eq!(dbg, "Reserved");
        let dbg = format!("{:?}", TlaObligationState::Committed);
        assert_eq!(dbg, "Committed");
        let dbg = format!("{:?}", TlaObligationState::Aborted);
        assert_eq!(dbg, "Aborted");
        let dbg = format!("{:?}", TlaObligationState::Leaked);
        assert_eq!(dbg, "Leaked");
    }

    #[test]
    fn tla_obligation_state_clone_copy_eq() {
        let s = TlaObligationState::Reserved;
        let s2 = s;
        let s3 = s;
        assert_eq!(s2, s3);
        assert_ne!(TlaObligationState::Reserved, TlaObligationState::Leaked);
    }

    #[test]
    fn tla_obligation_state_display_all_variants() {
        assert_eq!(format!("{}", TlaObligationState::Reserved), "\"Reserved\"");
        assert_eq!(
            format!("{}", TlaObligationState::Committed),
            "\"Committed\""
        );
        assert_eq!(format!("{}", TlaObligationState::Aborted), "\"Aborted\"");
        assert_eq!(format!("{}", TlaObligationState::Leaked), "\"Leaked\"");
    }

    #[test]
    fn tla_state_snapshot_debug_clone() {
        let snap = TlaStateSnapshot::new();
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("TlaStateSnapshot"));
        let snap2 = snap;
        assert_eq!(snap2.step, 0);
        assert_eq!(snap2.time_nanos, 0);
        assert!(snap2.tasks.is_empty());
        assert!(snap2.regions.is_empty());
        assert!(snap2.obligations.is_empty());
    }

    #[test]
    fn tla_state_snapshot_apply_updates_step() {
        let mut snap = TlaStateSnapshot::new();
        let event = TraceEvent::spawn(42, Time::from_nanos(100), tid(1), rid(1));
        snap.apply(&event);
        assert_eq!(snap.step, 42);
        assert_eq!(snap.time_nanos, 100);
        assert!(snap.tasks.contains_key(&(1, 0)));
    }

    #[test]
    fn tla_module_debug() {
        let module = TlaExporter::export_spec_skeleton("DebugTest");
        let dbg = format!("{module:?}");
        assert!(dbg.contains("TlaModule"));
    }

    #[test]
    fn tla_exporter_snapshot_count_with_events() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(1)),
        ];
        let exporter = TlaExporter::from_trace(&events);
        // initial + 2 events = 3 snapshots
        assert_eq!(exporter.snapshot_count(), 3);
    }

    #[test]
    fn tla_behavior_module_snapshot() {
        let events = [
            TraceEvent::region_created(1, Time::from_nanos(10), rid(1), None),
            TraceEvent::spawn(2, Time::from_nanos(20), tid(1), rid(1)),
            TraceEvent::schedule(3, Time::from_nanos(30), tid(1), rid(1)),
            TraceEvent::poll(4, Time::from_nanos(40), tid(1), rid(1)),
            TraceEvent::yield_task(5, Time::from_nanos(50), tid(1), rid(1)),
            TraceEvent::obligation_reserve(
                6,
                Time::from_nanos(60),
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
            ),
            TraceEvent::obligation_commit(
                7,
                Time::from_nanos(70),
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
                10,
            ),
            TraceEvent::complete(8, Time::from_nanos(80), tid(1), rid(1)),
        ];

        let exporter = TlaExporter::from_trace(&events);
        let module = exporter.export_behavior("GoldenBehavior");

        insta::assert_snapshot!(module.source);
    }

    #[test]
    fn format_tla_task_map_empty() {
        let map = BTreeMap::new();
        assert_eq!(format_tla_task_map(&map), "<<>>");
    }

    #[test]
    fn format_tla_task_map_with_entries() {
        let mut map = BTreeMap::new();
        map.insert((1, 0), (TlaTaskState::Spawned, (0, 0)));
        let result = format_tla_task_map(&map);
        assert!(result.contains("\"1.0\" :>"));
        assert!(result.contains("\"Spawned\""));
        // Region reference carries generation and matches a region domain key.
        assert!(result.contains("\"0.0\""));
    }

    #[test]
    fn format_tla_task_map_distinct_generations_are_distinct_keys() {
        // Same arena slot, different generations must be distinct domain
        // elements (no vacuous QuiescenceOnClose via slot-reuse aliasing).
        let mut map = BTreeMap::new();
        map.insert((5, 0), (TlaTaskState::Completed, (1, 0)));
        map.insert((5, 1), (TlaTaskState::Spawned, (1, 0)));
        let result = format_tla_task_map(&map);
        assert!(result.contains("\"5.0\" :>"));
        assert!(result.contains("\"5.1\" :>"));
        assert!(result.contains("\"Completed\""));
        assert!(result.contains("\"Spawned\""));
    }

    #[test]
    fn format_tla_region_map_empty() {
        let map = BTreeMap::new();
        assert_eq!(format_tla_region_map(&map), "<<>>");
    }

    #[test]
    fn format_tla_region_map_with_parent() {
        let mut map = BTreeMap::new();
        map.insert((1, 0), (TlaRegionState::Open, Some((0, 0))));
        let result = format_tla_region_map(&map);
        assert!(result.contains("\"Open\""));
        assert!(result.contains("\"0.0\""));
    }

    #[test]
    fn format_tla_region_map_without_parent() {
        let mut map = BTreeMap::new();
        map.insert((1, 0), (TlaRegionState::Closed, None));
        let result = format_tla_region_map(&map);
        assert!(result.contains("\"NONE\""));
    }

    #[test]
    fn format_tla_obligation_map_empty() {
        let map = BTreeMap::new();
        assert_eq!(format_tla_obligation_map(&map), "<<>>");
    }

    #[test]
    fn format_tla_obligation_map_with_entries() {
        let mut map = BTreeMap::new();
        map.insert((1, 0), (TlaObligationState::Committed, (2, 0), (3, 0)));
        let result = format_tla_obligation_map(&map);
        assert!(result.contains("\"Committed\""));
        assert!(result.contains("\"2.0\""));
        assert!(result.contains("\"3.0\""));
    }

    #[test]
    fn module_name_is_sanitized() {
        // A crafted name with whitespace/newlines/`-`/`=` must not produce an
        // invalid or injected MODULE header.
        let module = TlaExporter::export_spec_skeleton("Bad Name\n==== \\* inject -- x");
        // No raw spaces/newlines/hyphens survive in the module identifier.
        assert!(module.source.contains("---- MODULE Bad_Name"));
        assert!(!module.name.contains(' '));
        assert!(!module.name.contains('\n'));
        assert!(!module.name.contains('-'));
        // Header/footer remain well-formed.
        assert!(module.source.starts_with("---- MODULE "));
        assert!(module.source.trim_end().ends_with("===="));
    }

    #[test]
    fn empty_and_leading_digit_names_sanitized() {
        assert_eq!(sanitize_module_name(""), "Module");
        assert_eq!(sanitize_module_name("   "), "___");
        assert_eq!(sanitize_module_name("3M"), "_3M");
        assert_eq!(sanitize_module_name("Good_Name1"), "Good_Name1");
    }
