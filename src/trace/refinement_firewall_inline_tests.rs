    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::{ObligationAbortReason, ObligationKind};
    use crate::types::{CancelReason, Time};

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn oid(n: u32) -> ObligationId {
        ObligationId::new_for_test(n, 0)
    }

    fn handoff_prefix() -> (Vec<TraceEvent>, super::super::event::ObligationHandoff) {
        let events = vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::region_created(2, Time::ZERO, rid(2), None),
            TraceEvent::spawn(3, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(4, Time::ZERO, tid(2), rid(2)),
            TraceEvent::obligation_reserve(
                5,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::Lease,
            ),
        ];
        (
            events,
            super::super::event::ObligationHandoff {
                id: oid(1),
                source_ticket: 4,
                destination_ticket: 7,
                source_holder: tid(1),
                destination_holder: tid(2),
                source_region: rid(1),
                destination_region: rid(2),
            },
        )
    }

    #[test]
    fn handoff_moves_close_liability_and_preserves_old_terminal_refusals() {
        let (mut events, handoff) = handoff_prefix();
        events.push(TraceEvent::obligation_handoff(6, Time::ZERO, &handoff));
        events.push(TraceEvent::complete(7, Time::ZERO, tid(1), rid(1)));
        events.push(TraceEvent::new(
            8,
            Time::ZERO,
            TraceEventKind::RegionCloseBegin,
            TraceData::Region {
                region: rid(1),
                parent: None,
            },
        ));
        events.push(TraceEvent::new(
            9,
            Time::ZERO,
            TraceEventKind::RegionCloseComplete,
            TraceData::Region {
                region: rid(1),
                parent: None,
            },
        ));
        assert!(
            check_refinement_firewall(&events).is_ok(),
            "source close no longer owns the pending ID"
        );
        let mut wrong_owner = events.clone();
        wrong_owner.push(TraceEvent::obligation_commit(
            10,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::Lease,
            1,
        ));
        assert_eq!(
            first_refinement_violation(&wrong_owner).unwrap().rule_id,
            "RFW-OBL-009"
        );
        events.push(TraceEvent::obligation_commit(
            10,
            Time::ZERO,
            oid(1),
            tid(2),
            rid(2),
            ObligationKind::Lease,
            1,
        ));
        assert!(check_refinement_firewall(&events).is_ok());
        events.push(TraceEvent::obligation_commit(
            11,
            Time::ZERO,
            oid(1),
            tid(2),
            rid(2),
            ObligationKind::Lease,
            1,
        ));
        assert_eq!(
            first_refinement_violation(&events).unwrap().rule_id,
            "RFW-OBL-010"
        );
    }

    #[test]
    fn handoff_refuses_missing_source_stale_generations_and_reordered_lineage() {
        for scenario in [
            "missing",
            "source",
            "destination_generation",
            "destination_region",
            "completed",
            "resolved",
            "repeat",
            "ticket",
            "malformed",
        ] {
            let (mut events, mut handoff) = handoff_prefix();
            let rule = match scenario {
                "missing" => {
                    handoff.id = oid(9);
                    "RFW-HANDOFF-002"
                }
                "source" => {
                    handoff.source_holder = tid(3);
                    "RFW-HANDOFF-003"
                }
                "destination_generation" => {
                    handoff.destination_holder = TaskId::new_for_test(2, 1);
                    "RFW-HANDOFF-004"
                }
                "destination_region" => {
                    handoff.destination_region = rid(1);
                    "RFW-HANDOFF-004"
                }
                "completed" => {
                    events.push(TraceEvent::complete(6, Time::ZERO, tid(2), rid(2)));
                    "RFW-HANDOFF-004"
                }
                "resolved" => {
                    events.push(TraceEvent::obligation_commit(
                        6,
                        Time::ZERO,
                        oid(1),
                        tid(1),
                        rid(1),
                        ObligationKind::Lease,
                        1,
                    ));
                    "RFW-HANDOFF-003"
                }
                "repeat" => {
                    events.push(TraceEvent::obligation_handoff(6, Time::ZERO, &handoff));
                    "RFW-HANDOFF-003"
                }
                "ticket" => {
                    events.push(TraceEvent::obligation_handoff(6, Time::ZERO, &handoff));
                    handoff = super::super::event::ObligationHandoff {
                        id: oid(1),
                        source_ticket: 8,
                        destination_ticket: 9,
                        source_holder: tid(2),
                        destination_holder: tid(1),
                        source_region: rid(2),
                        destination_region: rid(1),
                    };
                    "RFW-HANDOFF-003"
                }
                "malformed" => "RFW-HANDOFF-001",
                _ => unreachable!(),
            };
            events.push(if scenario == "malformed" {
                TraceEvent::user_trace(7, Time::ZERO, "obligation_handoff_v1 {}")
            } else {
                TraceEvent::obligation_handoff(7, Time::ZERO, &handoff)
            });
            let violation = first_refinement_violation(&events).expect(scenario);
            assert_eq!(violation.rule_id, rule, "{scenario}: {violation}");
            assert_eq!(violation.event_index, events.len() - 1);
        }
    }

    #[test]
    fn handoff_chain_after_destination_close_begin_preserves_accepted_projection() {
        let (mut events, handoff) = handoff_prefix();
        events.push(TraceEvent::new(
            6,
            Time::ZERO,
            TraceEventKind::RegionCloseBegin,
            TraceData::Region {
                region: rid(2),
                parent: None,
            },
        ));
        events.push(TraceEvent::obligation_handoff(7, Time::ZERO, &handoff));
        let return_handoff = super::super::event::ObligationHandoff {
            id: oid(1),
            source_ticket: 7,
            destination_ticket: 11,
            source_holder: tid(2),
            destination_holder: tid(1),
            source_region: rid(2),
            destination_region: rid(1),
        };
        events.push(TraceEvent::obligation_handoff(
            8,
            Time::ZERO,
            &return_handoff,
        ));
        events.push(TraceEvent::obligation_abort(
            9,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::Lease,
            2,
            ObligationAbortReason::Explicit,
        ));
        assert!(check_refinement_firewall(&events).is_ok());
    }

    #[test]
    fn accepts_valid_core_lifecycle() {
        let events = vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::cancel_request(3, Time::ZERO, tid(1), rid(1), CancelReason::shutdown()),
            TraceEvent::new(
                4,
                Time::ZERO,
                TraceEventKind::CancelAck,
                TraceData::Cancel {
                    task: tid(1),
                    region: rid(1),
                    reason: CancelReason::shutdown(),
                },
            ),
            TraceEvent::obligation_reserve(
                5,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
            ),
            TraceEvent::obligation_commit(
                6,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
                3,
            ),
            TraceEvent::complete(7, Time::ZERO, tid(1), rid(1)),
            TraceEvent::new(
                8,
                Time::ZERO,
                TraceEventKind::RegionCloseBegin,
                TraceData::Region {
                    region: rid(1),
                    parent: None,
                },
            ),
            TraceEvent::new(
                9,
                Time::ZERO,
                TraceEventKind::RegionCloseComplete,
                TraceData::Region {
                    region: rid(1),
                    parent: None,
                },
            ),
        ];

        let report = check_refinement_firewall(&events);
        assert!(report.is_ok(), "report={report:?}");
        assert_eq!(report.checked_events, events.len());
        assert!(first_counterexample_prefix(&events).is_none());
    }

    #[test]
    fn duplicate_spawn_is_rejected() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        ];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-SPAWN-001");
        assert_eq!(v.event_index, 1);
    }

    #[test]
    fn cancel_ack_without_request_is_rejected() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::new(
                2,
                Time::ZERO,
                TraceEventKind::CancelAck,
                TraceData::Cancel {
                    task: tid(1),
                    region: rid(1),
                    reason: CancelReason::shutdown(),
                },
            ),
        ];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-CANCEL-006");
    }

    #[test]
    fn close_complete_requires_quiescence() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::new(
                2,
                Time::ZERO,
                TraceEventKind::RegionCloseBegin,
                TraceData::Region {
                    region: rid(1),
                    parent: None,
                },
            ),
            TraceEvent::new(
                3,
                Time::ZERO,
                TraceEventKind::RegionCloseComplete,
                TraceData::Region {
                    region: rid(1),
                    parent: None,
                },
            ),
        ];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-QUIESCE-001");
    }

    #[test]
    fn resolve_without_reserve_is_rejected() {
        let events = vec![TraceEvent::obligation_commit(
            1,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
            1,
        )];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-OBL-007");
    }

    #[test]
    fn obligation_region_mismatch_is_rejected() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::obligation_reserve(
                2,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(2),
                ObligationKind::Ack,
            ),
        ];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-OBL-005");
    }

    #[test]
    fn obligation_leak_event_is_immediate_violation() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::obligation_leak(
                2,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::Ack,
                99,
            ),
        ];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-OBL-004");
    }

    #[test]
    fn counterexample_prefix_cuts_at_first_violation() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::obligation_abort(
                3,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
                1,
                ObligationAbortReason::Cancel,
            ),
        ];

        let prefix = first_counterexample_prefix(&events).expect("expected prefix");
        assert_eq!(prefix.len(), 2);
        assert_eq!(prefix[1].seq, 2);
    }
