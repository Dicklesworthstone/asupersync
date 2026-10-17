    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn r(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn o(n: u32) -> ObligationId {
        ObligationId::from_arena(ArenaIndex::new(n, 0))
    }

    fn reserve(
        time_ns: u64,
        obligation: ObligationId,
        kind: ObligationKind,
        task: TaskId,
        region: RegionId,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Reserve {
                obligation,
                kind,
                task,
                region,
            },
        )
    }

    fn commit(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Commit {
                obligation,
                region,
                kind,
            },
        )
    }

    fn abort(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Abort {
                obligation,
                region,
                kind,
            },
        )
    }

    fn leak(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Leak {
                obligation,
                region,
                kind,
            },
        )
    }

    fn close(time_ns: u64, region: RegionId) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::RegionClose { region },
        )
    }

    fn transfer_trace(
        cross_region: bool,
        kind: ObligationKind,
    ) -> (Vec<TraceEvent>, crate::trace::event::ObligationHandoff) {
        let destination_region = if cross_region { r(1) } else { r(0) };
        let handoff = crate::trace::event::ObligationHandoff {
            id: o(0),
            source_ticket: 4,
            destination_ticket: 7,
            source_holder: t(0),
            destination_holder: TaskId::new_for_test(0, 1),
            source_region: r(0),
            destination_region,
        };
        (
            vec![
                TraceEvent::region_created(0, Time::ZERO, r(0), None),
                TraceEvent::spawn(1, Time::ZERO, handoff.source_holder, r(0)),
                TraceEvent::spawn(
                    2,
                    Time::ZERO,
                    handoff.destination_holder,
                    destination_region,
                ),
                TraceEvent::obligation_reserve(
                    3,
                    Time::ZERO,
                    o(0),
                    handoff.source_holder,
                    r(0),
                    kind,
                ),
            ],
            handoff,
        )
    }

    fn trace_close(seq: u64, region: RegionId, kind: TraceEventKind) -> TraceEvent {
        TraceEvent::new(
            seq,
            Time::from_nanos(seq),
            kind,
            TraceData::Region {
                region,
                parent: None,
            },
        )
    }

    #[test]
    fn transfer_trace_moves_one_marking_without_minting_or_settling() {
        for cross_region in [false, true] {
            for kind in [ObligationKind::Lease, ObligationKind::SemaphorePermit] {
                for abort in [false, true] {
                    let (mut trace, handoff) = transfer_trace(cross_region, kind);
                    trace.push(TraceEvent::obligation_handoff(
                        4,
                        Time::from_nanos(4),
                        &handoff,
                    ));
                    if cross_region {
                        trace.push(TraceEvent::complete(
                            5,
                            Time::from_nanos(5),
                            handoff.source_holder,
                            handoff.source_region,
                        ));
                        trace.push(trace_close(
                            6,
                            handoff.source_region,
                            TraceEventKind::RegionCloseComplete,
                        ));
                    }
                    let mut analyzer = MarkingAnalyzer::new();
                    let pending = analyzer.analyze_trace(&trace);
                    assert!(pending.is_safe(), "pending handoff: {pending}");
                    let marking = pending.timeline.final_marking().unwrap();
                    assert_eq!(marking.total_pending(), 1);
                    assert_eq!(marking.region_pending(handoff.destination_region), 1);
                    if cross_region {
                        assert_eq!(marking.region_pending(handoff.source_region), 0);
                    }
                    assert_eq!(pending.stats.total_reserved, 1);
                    assert_eq!(pending.stats.total_committed, 0);
                    assert_eq!(pending.stats.total_aborted, 0);
                    assert_eq!(pending.stats.max_pending, 1);
                    let terminal = if abort {
                        TraceEvent::obligation_abort(
                            7,
                            Time::from_nanos(7),
                            handoff.id,
                            handoff.destination_holder,
                            handoff.destination_region,
                            kind,
                            7,
                            crate::record::ObligationAbortReason::Explicit,
                        )
                    } else {
                        TraceEvent::obligation_commit(
                            7,
                            Time::from_nanos(7),
                            handoff.id,
                            handoff.destination_holder,
                            handoff.destination_region,
                            kind,
                            7,
                        )
                    };
                    trace.push(terminal);
                    trace.push(trace_close(
                        8,
                        handoff.destination_region,
                        TraceEventKind::RegionCloseComplete,
                    ));
                    let result = analyzer.analyze_trace(&trace);
                    assert!(
                        result.is_safe(),
                        "cross_region={cross_region} abort={abort}: {result}"
                    );
                    assert!(result.timeline.final_marking().unwrap().is_zero());
                    assert_eq!(result.stats.total_reserved, 1);
                    assert_eq!(result.stats.total_committed, u32::from(!abort));
                    assert_eq!(result.stats.total_aborted, u32::from(abort));
                    assert_eq!(result.stats.total_leaked, 0);
                    assert_eq!(result.stats.max_pending, 1);
                    assert!(
                        try_project_trace(&trace).is_err(),
                        "legacy projection must refuse loss of ownership"
                    );
                    eprintln!(
                        "marking transfer cross_region={cross_region} kind={kind:?} abort={abort}: {result}"
                    );
                }
            }
        }
    }

    #[test]
    fn transfer_trace_refuses_stale_or_reset_ownership_and_keeps_destination_leaks() {
        for scenario in [
            "malformed",
            "missing",
            "generation",
            "ticket",
            "source",
            "old_terminal",
            "reset",
            "double_terminal",
            "completed",
            "closed",
            "source_closed",
        ] {
            let (mut trace, mut handoff) = transfer_trace(true, ObligationKind::Lease);
            match scenario {
                "missing" => handoff.id = o(2),
                "generation" => handoff.destination_holder = TaskId::new_for_test(0, 2),
                "ticket" => handoff.destination_ticket = handoff.source_ticket,
                "source" => handoff.source_region = r(2),
                "source_closed" => trace.insert(
                    1,
                    trace_close(
                        0,
                        handoff.source_region,
                        TraceEventKind::RegionCloseComplete,
                    ),
                ),
                "completed" => trace.push(TraceEvent::complete(
                    4,
                    Time::ZERO,
                    handoff.destination_holder,
                    handoff.destination_region,
                )),
                "closed" => trace.push(trace_close(
                    4,
                    handoff.destination_region,
                    TraceEventKind::RegionCloseComplete,
                )),
                _ => {}
            }
            trace.push(if scenario == "malformed" {
                TraceEvent::user_trace(5, Time::ZERO, "obligation_handoff_v1 {}")
            } else {
                TraceEvent::obligation_handoff(5, Time::ZERO, &handoff)
            });
            if scenario == "old_terminal" {
                trace.push(TraceEvent::obligation_commit(
                    6,
                    Time::ZERO,
                    handoff.id,
                    handoff.source_holder,
                    handoff.source_region,
                    ObligationKind::Lease,
                    1,
                ));
            }
            if scenario == "reset" {
                trace.push(TraceEvent::obligation_reserve(
                    6,
                    Time::ZERO,
                    handoff.id,
                    handoff.source_holder,
                    handoff.source_region,
                    ObligationKind::Lease,
                ));
            }
            if scenario == "double_terminal" {
                for seq in [6, 7] {
                    trace.push(TraceEvent::obligation_commit(
                        seq,
                        Time::ZERO,
                        handoff.id,
                        handoff.destination_holder,
                        handoff.destination_region,
                        ObligationKind::Lease,
                        1,
                    ));
                }
            }
            let result = MarkingAnalyzer::new().analyze_trace(&trace);
            assert!(!result.is_safe(), "accepted {scenario}");
            assert_eq!(result.invalid_transitions.len(), 1, "{scenario}: {result}");
            assert_eq!(result.stats.total_reserved, 1, "{scenario}");
        }
        let (mut trace, handoff) = transfer_trace(true, ObligationKind::Lease);
        trace.push(TraceEvent::obligation_handoff(4, Time::ZERO, &handoff));
        trace.push(trace_close(
            5,
            handoff.destination_region,
            TraceEventKind::RegionCloseComplete,
        ));
        let result = MarkingAnalyzer::new().analyze_trace(&trace);
        assert!(!result.is_safe());
        assert_eq!(result.leaks.len(), 1);
        assert_eq!(result.leaks[0].region, handoff.destination_region);
        assert_eq!(result.leaks[0].count, 1);
    }

    #[test]
    fn transfer_trace_queued_close_and_return_chain_preserve_legacy_analysis() {
        let (mut trace, handoff) = transfer_trace(true, ObligationKind::Lease);
        let mut analyzer = MarkingAnalyzer::new();
        let old = analyzer.analyze(&project_trace(&trace));
        let direct = analyzer.analyze_trace(&trace);
        assert_eq!(old.to_string(), direct.to_string());
        assert_eq!(old.timeline.to_string(), direct.timeline.to_string());
        assert!(try_project_trace(&trace).is_ok());
        trace.push(trace_close(
            4,
            handoff.destination_region,
            TraceEventKind::RegionCloseBegin,
        ));
        trace.push(TraceEvent::obligation_handoff(5, Time::ZERO, &handoff));
        let returned = crate::trace::event::ObligationHandoff {
            id: handoff.id,
            source_ticket: 7,
            destination_ticket: 11,
            source_holder: handoff.destination_holder,
            destination_holder: handoff.source_holder,
            source_region: handoff.destination_region,
            destination_region: handoff.source_region,
        };
        trace.push(TraceEvent::obligation_handoff(6, Time::ZERO, &returned));
        trace.push(trace_close(
            7,
            handoff.destination_region,
            TraceEventKind::RegionCloseComplete,
        ));
        trace.push(TraceEvent::obligation_commit(
            8,
            Time::ZERO,
            returned.id,
            returned.destination_holder,
            returned.destination_region,
            ObligationKind::Lease,
            1,
        ));
        let result = analyzer.analyze_trace(&trace);
        assert!(result.is_safe(), "{result}");
        assert_eq!(result.stats.total_reserved, 1);
        assert_eq!(result.stats.total_committed, 1);
        assert_eq!(result.stats.max_pending, 1);
        assert!(result.timeline.final_marking().unwrap().is_zero());
        let legacy_negative = [TraceEvent::obligation_commit(
            1,
            Time::ZERO,
            o(3),
            t(0),
            r(0),
            ObligationKind::Lease,
            1,
        )];
        let old = analyzer.analyze(&project_trace(&legacy_negative));
        let direct = analyzer.analyze_trace(&legacy_negative);
        assert!(!direct.is_safe());
        assert_eq!(old.to_string(), direct.to_string());
        assert_eq!(old.timeline.to_string(), direct.timeline.to_string());
    }

    #[test]
    fn transfer_trace_unrelated_terminal_cannot_consume_destination_marking() {
        for scenario in ["unknown", "other_region", "other_kind", "other_duplicate"] {
            let (mut trace, handoff) = transfer_trace(true, ObligationKind::Lease);
            let other_holder = if scenario == "other_region" {
                handoff.source_holder
            } else {
                handoff.destination_holder
            };
            let other_region = if scenario == "other_region" {
                handoff.source_region
            } else {
                handoff.destination_region
            };
            if scenario != "unknown" {
                trace.push(TraceEvent::obligation_reserve(
                    4,
                    Time::ZERO,
                    o(1),
                    other_holder,
                    other_region,
                    if scenario == "other_kind" {
                        ObligationKind::Ack
                    } else {
                        ObligationKind::Lease
                    },
                ));
            }
            if scenario == "other_duplicate" {
                trace.push(TraceEvent::obligation_commit(
                    5,
                    Time::ZERO,
                    o(1),
                    other_holder,
                    other_region,
                    ObligationKind::Lease,
                    1,
                ));
            }
            trace.push(TraceEvent::obligation_handoff(6, Time::ZERO, &handoff));
            trace.push(TraceEvent::obligation_commit(
                7,
                Time::ZERO,
                o(1),
                other_holder,
                handoff.destination_region,
                ObligationKind::Lease,
                1,
            ));
            if scenario == "other_kind" {
                trace.push(TraceEvent::obligation_commit(
                    8,
                    Time::ZERO,
                    o(1),
                    other_holder,
                    other_region,
                    ObligationKind::Ack,
                    1,
                ));
            }
            trace.push(trace_close(
                8,
                handoff.destination_region,
                TraceEventKind::RegionCloseComplete,
            ));
            let result = MarkingAnalyzer::new().analyze_trace(&trace);
            assert!(!result.is_safe(), "aggregate theft accepted: {scenario}");
            assert_eq!(result.invalid_transitions.len(), 1, "{scenario}: {result}");
            assert_eq!(
                result
                    .timeline
                    .final_marking()
                    .unwrap()
                    .region_pending(handoff.destination_region),
                1
            );
            assert_eq!(result.leaks.len(), 1);
            assert_eq!(result.leaks[0].region, handoff.destination_region);
            assert_eq!(result.leaks[0].count, 1);
            assert_eq!(
                result.stats.total_committed,
                u32::from(matches!(scenario, "other_duplicate" | "other_kind"))
            );
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ConformanceRequirementLevel {
        Must,
        Should,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ConformanceStatus {
        Pass,
        Fail,
    }

    #[derive(Debug, Clone)]
    struct MarkingConformanceResult {
        requirement_id: &'static str,
        description: &'static str,
        level: ConformanceRequirementLevel,
        status: ConformanceStatus,
        evidence: String,
    }

    struct MarkingConformanceHarness;

    impl MarkingConformanceHarness {
        fn run_all() -> Vec<MarkingConformanceResult> {
            vec![
                Self::reserve_commit_close_returns_to_zero(),
                Self::region_close_surfaces_pending_obligations(),
                Self::below_zero_transitions_are_invalid(),
                Self::projection_keeps_only_marking_events(),
            ]
        }

        fn render_matrix(results: &[MarkingConformanceResult]) -> String {
            use std::fmt::Write;

            let mut out = String::new();
            out.push_str("# Obligation Marking VASS Conformance Matrix\n\n");
            out.push_str("| Req ID | Level | Status | Description | Evidence |\n");
            out.push_str("|--------|-------|--------|-------------|----------|\n");

            let mut must_total = 0;
            let mut must_pass = 0;
            let mut should_total = 0;
            let mut should_pass = 0;

            for result in results {
                let level = match result.level {
                    ConformanceRequirementLevel::Must => {
                        must_total += 1;
                        if result.status == ConformanceStatus::Pass {
                            must_pass += 1;
                        }
                        "MUST"
                    }
                    ConformanceRequirementLevel::Should => {
                        should_total += 1;
                        if result.status == ConformanceStatus::Pass {
                            should_pass += 1;
                        }
                        "SHOULD"
                    }
                };
                let status = match result.status {
                    ConformanceStatus::Pass => "PASS",
                    ConformanceStatus::Fail => "FAIL",
                };
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} |",
                    result.requirement_id, level, status, result.description, result.evidence
                );
            }

            let _ = writeln!(out, "\nSummary:");
            let _ = writeln!(out, "- MUST: {must_pass}/{must_total}");
            let _ = writeln!(out, "- SHOULD: {should_pass}/{should_total}");
            let overall = if must_pass == must_total {
                "CONFORMANT"
            } else {
                "NON-CONFORMANT"
            };
            let _ = writeln!(out, "- Overall: {overall}");

            out
        }

        fn reserve_commit_close_returns_to_zero() -> MarkingConformanceResult {
            let events = vec![
                reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
                commit(10, o(0), r(0), ObligationKind::SendPermit),
                close(20, r(0)),
            ];
            let mut analyzer = MarkingAnalyzer::new();
            let result = analyzer.analyze(&events);
            let passes = result.is_safe()
                && result.leak_count() == 0
                && result
                    .timeline
                    .final_marking()
                    .is_some_and(ObligationMarking::is_zero);

            MarkingConformanceResult {
                requirement_id: "VASS-001",
                description: "reserve/commit/close returns to zero marking",
                level: ConformanceRequirementLevel::Must,
                status: if passes {
                    ConformanceStatus::Pass
                } else {
                    ConformanceStatus::Fail
                },
                evidence: format!(
                    "safe={} leaks={} final_zero={}",
                    result.is_safe(),
                    result.leak_count(),
                    result
                        .timeline
                        .final_marking()
                        .is_some_and(ObligationMarking::is_zero)
                ),
            }
        }

        fn region_close_surfaces_pending_obligations() -> MarkingConformanceResult {
            let events = vec![
                reserve(0, o(1), ObligationKind::SendPermit, t(0), r(0)),
                close(10, r(0)),
            ];
            let mut analyzer = MarkingAnalyzer::new();
            let result = analyzer.analyze(&events);
            let passes = !result.is_safe()
                && result.leak_count() == 1
                && result.leaks[0].kind == ObligationKind::SendPermit;

            MarkingConformanceResult {
                requirement_id: "VASS-002",
                description: "region close surfaces pending obligations as leaks",
                level: ConformanceRequirementLevel::Must,
                status: if passes {
                    ConformanceStatus::Pass
                } else {
                    ConformanceStatus::Fail
                },
                evidence: format!(
                    "safe={} leaks={} first_kind={:?}",
                    result.is_safe(),
                    result.leak_count(),
                    result.leaks.first().map(|leak| leak.kind)
                ),
            }
        }

        fn below_zero_transitions_are_invalid() -> MarkingConformanceResult {
            let events = vec![commit(10, o(2), r(0), ObligationKind::Ack)];
            let mut analyzer = MarkingAnalyzer::new();
            let result = analyzer.analyze(&events);
            let passes = result.invalid_transitions.len() == 1 && !result.is_safe();

            MarkingConformanceResult {
                requirement_id: "VASS-003",
                description: "commit below zero is recorded as invalid transition",
                level: ConformanceRequirementLevel::Must,
                status: if passes {
                    ConformanceStatus::Pass
                } else {
                    ConformanceStatus::Fail
                },
                evidence: format!(
                    "invalid={} safe={}",
                    result.invalid_transitions.len(),
                    result.is_safe()
                ),
            }
        }

        fn projection_keeps_only_marking_events() -> MarkingConformanceResult {
            let trace_events = vec![
                TraceEvent::new(
                    0,
                    Time::ZERO,
                    TraceEventKind::Spawn,
                    TraceData::Task {
                        task: t(0),
                        region: r(0),
                    },
                ),
                TraceEvent::new(
                    1,
                    Time::ZERO,
                    TraceEventKind::ObligationReserve,
                    TraceData::Obligation {
                        obligation: o(3),
                        task: t(0),
                        region: r(0),
                        kind: ObligationKind::Lease,
                        state: crate::record::ObligationState::Reserved,
                        duration_ns: None,
                        abort_reason: None,
                    },
                ),
                TraceEvent::new(
                    2,
                    Time::from_nanos(5),
                    TraceEventKind::Poll,
                    TraceData::Task {
                        task: t(0),
                        region: r(0),
                    },
                ),
                TraceEvent::new(
                    3,
                    Time::from_nanos(10),
                    TraceEventKind::ObligationAbort,
                    TraceData::Obligation {
                        obligation: o(3),
                        task: t(0),
                        region: r(0),
                        kind: ObligationKind::Lease,
                        state: crate::record::ObligationState::Aborted,
                        duration_ns: Some(10),
                        abort_reason: None,
                    },
                ),
                TraceEvent::new(
                    4,
                    Time::from_nanos(20),
                    TraceEventKind::RegionCloseBegin,
                    TraceData::Region {
                        region: r(0),
                        parent: None,
                    },
                ),
            ];
            let projected = project_trace(&trace_events);
            let mut analyzer = MarkingAnalyzer::new();
            let result = analyzer.analyze(&projected);
            let passes = projected.len() == 3 && result.is_safe();

            MarkingConformanceResult {
                requirement_id: "VASS-004",
                description: "trace projection keeps only obligation and close events",
                level: ConformanceRequirementLevel::Should,
                status: if passes {
                    ConformanceStatus::Pass
                } else {
                    ConformanceStatus::Fail
                },
                evidence: format!("projected={} safe={}", projected.len(), result.is_safe()),
            }
        }
    }

    // ---- Safe traces -------------------------------------------------------

    #[test]
    fn empty_trace_is_safe() {
        init_test("empty_trace_is_safe");
        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&[]);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let total = result.stats.total_reserved;
        crate::assert_with_log!(total == 0, "reserved", 0, total);
        crate::test_complete!("empty_trace_is_safe");
    }

    #[test]
    fn single_reserve_commit_is_safe() {
        init_test("single_reserve_commit_is_safe");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(20, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let reserved = result.stats.total_reserved;
        crate::assert_with_log!(reserved == 1, "reserved", 1, reserved);
        let committed = result.stats.total_committed;
        crate::assert_with_log!(committed == 1, "committed", 1, committed);
        crate::test_complete!("single_reserve_commit_is_safe");
    }

    #[test]
    fn single_reserve_abort_is_safe() {
        init_test("single_reserve_abort_is_safe");
        let events = vec![
            reserve(0, o(0), ObligationKind::Ack, t(0), r(0)),
            abort(5, o(0), r(0), ObligationKind::Ack),
            close(10, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let aborted = result.stats.total_aborted;
        crate::assert_with_log!(aborted == 1, "aborted", 1, aborted);
        crate::test_complete!("single_reserve_abort_is_safe");
    }

    #[test]
    fn multiple_obligations_safe() {
        init_test("multiple_obligations_safe");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(0), r(0)),
            reserve(2, o(2), ObligationKind::Lease, t(1), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            abort(11, o(1), r(0), ObligationKind::Ack),
            commit(12, o(2), r(0), ObligationKind::Lease),
            close(20, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let max_pending = result.stats.max_pending;
        crate::assert_with_log!(max_pending == 3, "max pending", 3, max_pending);
        crate::test_complete!("multiple_obligations_safe");
    }

    #[test]
    fn multiple_regions_safe() {
        init_test("multiple_regions_safe");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Lease, t(1), r(1)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(11, o(1), r(1), ObligationKind::Lease),
            close(20, r(0)),
            close(21, r(1)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let regions = result.stats.distinct_regions;
        crate::assert_with_log!(regions == 2, "regions", 2, regions);
        crate::test_complete!("multiple_regions_safe");
    }

    // ---- Leak detection ----------------------------------------------------

    #[test]
    fn leak_detected_on_region_close() {
        init_test("leak_detected_on_region_close");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close(10, r(0)), // Close without resolving.
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(!is_safe, "not safe", false, is_safe);
        let leak_count = result.leak_count();
        crate::assert_with_log!(leak_count == 1, "leak count", 1, leak_count);
        let leak = &result.leaks[0];
        let kind = leak.kind;
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "kind",
            ObligationKind::SendPermit,
            kind
        );
        let count = leak.count;
        crate::assert_with_log!(count == 1, "count", 1, count);
        crate::test_complete!("leak_detected_on_region_close");
    }

    #[test]
    fn send_permit_leak_display_has_asup_e202() {
        init_test("send_permit_leak_display_has_asup_e202");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close(10, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let rendered = result.leaks[0].to_string();

        assert!(rendered.starts_with("[ASUP-E202]"));
        assert!(rendered.contains("send_permit obligation(s)"));
        crate::test_complete!("send_permit_leak_display_has_asup_e202");
    }

    #[test]
    fn multiple_leaks_same_region() {
        init_test("multiple_leaks_same_region");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Lease, t(0), r(0)),
            close(10, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let leak_count = result.leak_count();
        crate::assert_with_log!(leak_count == 2, "leak count", 2, leak_count);
        crate::test_complete!("multiple_leaks_same_region");
    }

    #[test]
    fn partial_leak_one_region() {
        init_test("partial_leak_one_region");
        // One obligation resolved, one leaked.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            close(10, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let leak_count = result.leak_count();
        crate::assert_with_log!(leak_count == 1, "leak count", 1, leak_count);
        let kind = result.leaks[0].kind;
        crate::assert_with_log!(
            kind == ObligationKind::Ack,
            "kind",
            ObligationKind::Ack,
            kind
        );
        crate::test_complete!("partial_leak_one_region");
    }

    // ---- Leak event --------------------------------------------------------

    #[test]
    fn explicit_leak_event() {
        init_test("explicit_leak_event");
        let events = vec![
            reserve(0, o(0), ObligationKind::IoOp, t(0), r(0)),
            leak(5, o(0), r(0), ObligationKind::IoOp),
            close(10, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        // The leak event decrements the marking, so region close sees 0 pending.
        // But we still record it in stats.
        let total_leaked = result.stats.total_leaked;
        crate::assert_with_log!(total_leaked == 1, "leaked", 1, total_leaked);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe (marking cleared)", true, is_safe);
        crate::test_complete!("explicit_leak_event");
    }

    // ---- Invalid transitions -----------------------------------------------

    #[test]
    fn commit_below_zero_is_invalid() {
        init_test("commit_below_zero_is_invalid");
        let events = vec![commit(10, o(0), r(0), ObligationKind::SendPermit)];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let invalid = result.invalid_transitions.len();
        crate::assert_with_log!(invalid == 1, "invalid count", 1, invalid);
        crate::test_complete!("commit_below_zero_is_invalid");
    }

    // ---- Marking vector ----------------------------------------------------

    #[test]
    fn marking_vector_operations() {
        init_test("marking_vector_operations");
        let mut marking = ObligationMarking::empty();
        let is_zero = marking.is_zero();
        crate::assert_with_log!(is_zero, "initially zero", true, is_zero);

        marking.increment(ObligationKind::SendPermit, r(0));
        marking.increment(ObligationKind::SendPermit, r(0));
        marking.increment(ObligationKind::Lease, r(1));

        let total = marking.total_pending();
        crate::assert_with_log!(total == 3, "total", 3, total);
        let r0_pending = marking.region_pending(r(0));
        crate::assert_with_log!(r0_pending == 2, "r0 pending", 2, r0_pending);
        let r1_pending = marking.region_pending(r(1));
        crate::assert_with_log!(r1_pending == 1, "r1 pending", 1, r1_pending);

        let ok = marking.decrement(ObligationKind::SendPermit, r(0));
        crate::assert_with_log!(ok, "decrement ok", true, ok);
        let total = marking.total_pending();
        crate::assert_with_log!(total == 2, "total after decrement", 2, total);

        // Decrement to zero and try again.
        let ok = marking.decrement(ObligationKind::SendPermit, r(0));
        crate::assert_with_log!(ok, "second decrement ok", true, ok);
        let fail = marking.decrement(ObligationKind::SendPermit, r(0));
        crate::assert_with_log!(!fail, "third decrement fails", false, fail);

        crate::test_complete!("marking_vector_operations");
    }

    #[test]
    fn marking_display() {
        init_test("marking_display");
        let mut marking = ObligationMarking::empty();
        let empty_str = format!("{marking}");

        marking.increment(ObligationKind::SendPermit, r(0));
        let nonempty_str = format!("{marking}");
        let rendered = format!("empty: {empty_str}\nnonempty: {nonempty_str}");
        let expected = "empty: M = [0]\nnonempty: M = [(send_permit, RegionId(0:0))=1]";
        assert_eq!(rendered, expected);
        crate::test_complete!("marking_display");
    }

    // ---- Timeline ----------------------------------------------------------

    #[test]
    fn timeline_tracks_evolution() {
        init_test("timeline_tracks_evolution");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(5, o(1), ObligationKind::Ack, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(15, o(1), r(0), ObligationKind::Ack),
            close(20, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);

        // initial + 5 events + final = 7 snapshots.
        let snap_count = result.timeline.snapshots.len();
        crate::assert_with_log!(snap_count == 7, "snapshot count", 7, snap_count);

        let max = result.timeline.max_pending();
        crate::assert_with_log!(max == 2, "max pending", 2, max);
        let rendered = format!("{}", result.timeline);
        let expected = r#"Marking Timeline (7 snapshots):
  t=0ns: M = [0] (initial)
  t=0ns: M = [(send_permit, RegionId(0:0))=1] (reserve(send_permit, RegionId(0:0)))
  t=5ns: M = [(send_permit, RegionId(0:0))=1, (ack, RegionId(0:0))=1] (reserve(ack, RegionId(0:0)))
  t=10ns: M = [(ack, RegionId(0:0))=1] (commit(send_permit, RegionId(0:0)))
  t=15ns: M = [0] (commit(ack, RegionId(0:0)))
  t=20ns: M = [0] (region_close(RegionId(0:0)))
  t=20ns: M = [0] (final)
"#;
        assert_eq!(rendered, expected);
        crate::test_complete!("timeline_tracks_evolution");
    }

    // ---- Statistics --------------------------------------------------------

    #[test]
    fn stats_are_accurate() {
        init_test("stats_are_accurate");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(0), r(0)),
            reserve(2, o(2), ObligationKind::Lease, t(1), r(1)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            abort(11, o(1), r(0), ObligationKind::Ack),
            commit(12, o(2), r(1), ObligationKind::Lease),
            close(20, r(0)),
            close(21, r(1)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let reserved = result.stats.total_reserved;
        crate::assert_with_log!(reserved == 3, "reserved", 3, reserved);
        let committed = result.stats.total_committed;
        crate::assert_with_log!(committed == 2, "committed", 2, committed);
        let aborted = result.stats.total_aborted;
        crate::assert_with_log!(aborted == 1, "aborted", 1, aborted);
        let regions = result.stats.distinct_regions;
        crate::assert_with_log!(regions == 2, "regions", 2, regions);
        let kinds = result.stats.distinct_kinds;
        crate::assert_with_log!(kinds == 3, "kinds", 3, kinds);
        crate::test_complete!("stats_are_accurate");
    }

    #[test]
    fn stats_track_semaphore_permit_kind() {
        init_test("stats_track_semaphore_permit_kind");
        let events = vec![
            reserve(0, o(0), ObligationKind::SemaphorePermit, t(0), r(0)),
            commit(1, o(0), r(0), ObligationKind::SemaphorePermit),
            close(2, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);

        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "semaphore permit trace is safe", true, is_safe);
        let reserved = result.stats.total_reserved;
        crate::assert_with_log!(reserved == 1, "reserved", 1, reserved);
        let kinds = result.stats.distinct_kinds;
        crate::assert_with_log!(kinds == 1, "kinds", 1, kinds);
        crate::test_complete!("stats_track_semaphore_permit_kind");
    }

    // ---- Analyzer reuse ----------------------------------------------------

    #[test]
    fn analyzer_reuse() {
        init_test("analyzer_reuse");
        let mut analyzer = MarkingAnalyzer::new();

        let events1 = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close(10, r(0)),
        ];
        let r1 = analyzer.analyze(&events1);
        let r1_safe = r1.is_safe();
        crate::assert_with_log!(!r1_safe, "first not safe", false, r1_safe);

        let events2 = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            close(10, r(0)),
        ];
        let r2 = analyzer.analyze(&events2);
        let r2_safe = r2.is_safe();
        crate::assert_with_log!(r2_safe, "second safe", true, r2_safe);

        // First result unaffected.
        let r1_leaks = r1.leak_count();
        crate::assert_with_log!(r1_leaks == 1, "first still has leak", 1, r1_leaks);
        crate::test_complete!("analyzer_reuse");
    }

    // ---- Display impls -----------------------------------------------------

    #[test]
    fn display_impls() {
        init_test("marking_display_impls");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(5, o(1), ObligationKind::Ack, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(15, r(0)),
            abort(20, o(2), r(1), ObligationKind::Lease),
        ];
        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let rendered = format!(
            "leak: {}\ninvalid: {}\n\n{}",
            result.leaks[0], result.invalid_transitions[0], result
        );
        let expected = r#"leak: leak: 1 ack obligation(s) in RegionId(0:0) at 15ns
invalid: invalid at 20ns: abort(lease, RegionId(1:0)) but marking is already zero

VASS Marking Analysis Result
============================
Events processed: 5
Safe: false

Statistics:
  Reserved:  2
  Committed: 1
  Aborted:   1
  Leaked:    0
  Max pending: 2
  Regions:   1
  Kinds:     2

Leak violations (1):
  leak: 1 ack obligation(s) in RegionId(0:0) at 15ns

Invalid transitions (1):
  invalid at 20ns: abort(lease, RegionId(1:0)) but marking is already zero
"#;
        assert_eq!(rendered, expected);
        crate::test_complete!("marking_display_impls");
    }

    // ---- Realistic: channel send with cancel race --------------------------

    #[test]
    fn realistic_send_cancel_race() {
        init_test("realistic_send_cancel_race");
        // Model: Two tasks in a region, one sends, one gets cancelled.
        // The cancelled task should abort its obligation.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            abort(11, o(1), r(0), ObligationKind::SendPermit), // Cancelled task aborts.
            close(20, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let max = result.stats.max_pending;
        crate::assert_with_log!(max == 2, "max pending", 2, max);
        crate::test_complete!("realistic_send_cancel_race");
    }

    // ---- Realistic: nested regions -----------------------------------------

    #[test]
    fn realistic_nested_regions() {
        init_test("realistic_nested_regions");
        // Model: Parent region r0 with child region r1.
        // Child closes first, then parent.
        let events = vec![
            reserve(0, o(0), ObligationKind::Lease, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(1), r(1)),
            commit(10, o(1), r(1), ObligationKind::SendPermit),
            close(15, r(1)), // Child closes.
            commit(20, o(0), r(0), ObligationKind::Lease),
            close(25, r(0)), // Parent closes.
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let closed = result.closed_regions.len();
        crate::assert_with_log!(closed == 2, "closed regions", 2, closed);
        crate::test_complete!("realistic_nested_regions");
    }

    // ---- project_trace integration -----------------------------------------

    #[test]
    fn project_trace_extracts_obligation_events() {
        init_test("project_trace_extracts_obligation_events");
        // Build synthetic trace events.
        let trace_events = vec![
            TraceEvent::new(
                0,
                Time::ZERO,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: t(0),
                    region: r(0),
                },
            ),
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::ObligationReserve,
                TraceData::Obligation {
                    obligation: o(0),
                    task: t(0),
                    region: r(0),
                    kind: ObligationKind::SendPermit,
                    state: crate::record::ObligationState::Reserved,
                    duration_ns: None,
                    abort_reason: None,
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(10),
                TraceEventKind::ObligationCommit,
                TraceData::Obligation {
                    obligation: o(0),
                    task: t(0),
                    region: r(0),
                    kind: ObligationKind::SendPermit,
                    state: crate::record::ObligationState::Committed,
                    duration_ns: Some(10),
                    abort_reason: None,
                },
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(20),
                TraceEventKind::RegionCloseBegin,
                TraceData::Region {
                    region: r(0),
                    parent: None,
                },
            ),
        ];

        let projected = project_trace(&trace_events);
        let len = projected.len();
        crate::assert_with_log!(len == 3, "projected count", 3, len);

        // Feed to analyzer.
        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&projected);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        crate::test_complete!("project_trace_extracts_obligation_events");
    }

    #[test]
    fn project_trace_ignores_non_obligation() {
        init_test("project_trace_ignores_non_obligation");
        let trace_events = vec![
            TraceEvent::new(
                0,
                Time::ZERO,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: t(0),
                    region: r(0),
                },
            ),
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::Poll,
                TraceData::Task {
                    task: t(0),
                    region: r(0),
                },
            ),
        ];

        let projected = project_trace(&trace_events);
        let len = projected.len();
        crate::assert_with_log!(len == 0, "no obligation events", 0, len);
        crate::test_complete!("project_trace_ignores_non_obligation");
    }

    #[test]
    fn marking_vass_conformance_matrix() {
        init_test("marking_vass_conformance_matrix");
        let results = MarkingConformanceHarness::run_all();
        let must_total = results
            .iter()
            .filter(|result| result.level == ConformanceRequirementLevel::Must)
            .count();
        let must_pass = results
            .iter()
            .filter(|result| {
                result.level == ConformanceRequirementLevel::Must
                    && result.status == ConformanceStatus::Pass
            })
            .count();
        crate::assert_with_log!(
            must_total == must_pass,
            "all MUST requirements pass",
            must_total,
            must_pass
        );

        let rendered = MarkingConformanceHarness::render_matrix(&results);
        let expected = r#"# Obligation Marking VASS Conformance Matrix

| Req ID | Level | Status | Description | Evidence |
|--------|-------|--------|-------------|----------|
| VASS-001 | MUST | PASS | reserve/commit/close returns to zero marking | safe=true leaks=0 final_zero=true |
| VASS-002 | MUST | PASS | region close surfaces pending obligations as leaks | safe=false leaks=1 first_kind=Some(SendPermit) |
| VASS-003 | MUST | PASS | commit below zero is recorded as invalid transition | invalid=1 safe=false |
| VASS-004 | SHOULD | PASS | trace projection keeps only obligation and close events | projected=3 safe=true |

Summary:
- MUST: 3/3
- SHOULD: 1/1
- Overall: CONFORMANT
"#;
        assert_eq!(rendered, expected);
        crate::test_complete!("marking_vass_conformance_matrix");
    }

    #[test]
    fn marking_dimension_debug_clone_copy_eq() {
        let d = MarkingDimension {
            kind: ObligationKind::SendPermit,
            region: r(1),
        };
        let dbg = format!("{d:?}");
        assert!(dbg.contains("MarkingDimension"));

        let d2 = d;
        assert_eq!(d, d2);

        let d3 = d;
        assert_eq!(d, d3);
    }

    #[test]
    fn obligation_marking_debug_clone_default() {
        let m = ObligationMarking::default();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("ObligationMarking"));

        let m2 = m;
        assert!(m2.is_zero());

        let m3 = ObligationMarking::empty();
        assert!(m3.is_zero());
    }

    #[test]
    fn marking_timeline_debug_clone_default() {
        let t = MarkingTimeline::default();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("MarkingTimeline"));

        let t2 = t;
        assert!(t2.snapshots.is_empty());
    }

    #[test]
    fn analysis_stats_debug_clone_default() {
        let s = AnalysisStats::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("AnalysisStats"));

        let s2 = s;
        assert_eq!(s2.total_reserved, 0);
        assert_eq!(s2.total_committed, 0);
    }
