    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::PanicPayload;
    use crate::util::ArenaIndex;

    fn test_task_id() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(0, 1))
    }

    fn test_task_id_2() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(0, 2))
    }

    fn test_region_id() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 1))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn evidence_record_render_supervision_restart() {
        init_test("evidence_record_render_supervision_restart");

        let record = EvidenceRecord {
            timestamp: 1_000_000_000,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Restart,
            detail: EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed {
                attempt: 2,
                delay: Some(Duration::from_millis(200)),
            }),
        };

        let rendered = record.render();
        assert!(rendered.contains("supervision RESTART"));
        assert!(rendered.contains("restart allowed (attempt 2, delay 200ms)"));

        crate::test_complete!("evidence_record_render_supervision_restart");
    }

    #[test]
    fn evidence_record_render_supervision_stop() {
        init_test("evidence_record_render_supervision_stop");

        let record = EvidenceRecord {
            timestamp: 2_000_000_000,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Stop,
            detail: EvidenceDetail::Supervision(SupervisionDetail::WindowExhausted {
                max_restarts: 3,
                window: Duration::from_secs(60),
            }),
        };

        let rendered = record.render();
        assert!(rendered.contains("supervision STOP"));
        assert!(rendered.contains("window exhausted: 3 restarts in 60s"));

        crate::test_complete!("evidence_record_render_supervision_stop");
    }

    #[test]
    fn evidence_record_render_registry_accept() {
        init_test("evidence_record_render_registry_accept");

        let record = EvidenceRecord {
            timestamp: 500,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Registry,
            verdict: Verdict::Accept,
            detail: EvidenceDetail::Registry(RegistryDetail::NameAvailable),
        };

        assert_eq!(record.render(), "[500] registry ACCEPT: name available");

        crate::test_complete!("evidence_record_render_registry_accept");
    }

    #[test]
    fn evidence_record_render_registry_reject_collision() {
        init_test("evidence_record_render_registry_reject_collision");

        let record = EvidenceRecord {
            timestamp: 600,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Registry,
            verdict: Verdict::Reject,
            detail: EvidenceDetail::Registry(RegistryDetail::NameCollision {
                existing_holder: test_task_id_2(),
            }),
        };

        let rendered = record.render();
        assert!(rendered.contains("registry REJECT"));
        assert!(rendered.contains("name collision"));

        crate::test_complete!("evidence_record_render_registry_reject_collision");
    }

    #[test]
    fn evidence_record_render_link_propagate() {
        init_test("evidence_record_render_link_propagate");

        let record = EvidenceRecord {
            timestamp: 700,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Link,
            verdict: Verdict::Propagate,
            detail: EvidenceDetail::Link(LinkDetail::ExitPropagated {
                source: test_task_id_2(),
                reason: Outcome::Err(()),
            }),
        };

        let rendered = record.render();
        assert!(rendered.contains("link PROPAGATE"));
        assert!(rendered.contains("exit propagated"));

        crate::test_complete!("evidence_record_render_link_propagate");
    }

    #[test]
    fn evidence_record_render_monitor_deliver() {
        init_test("evidence_record_render_monitor_deliver");

        let record = EvidenceRecord {
            timestamp: 800,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Monitor,
            verdict: Verdict::Deliver,
            detail: EvidenceDetail::Monitor(MonitorDetail::DownDelivered {
                monitored: test_task_id_2(),
                reason: Outcome::Panicked(PanicPayload::new("oops")),
            }),
        };

        let rendered = record.render();
        assert!(rendered.contains("monitor DELIVER"));
        assert!(rendered.contains("down delivered"));

        crate::test_complete!("evidence_record_render_monitor_deliver");
    }

    #[test]
    fn generalized_ledger_push_and_query() {
        init_test("generalized_ledger_push_and_query");

        let mut ledger = GeneralizedLedger::new();
        assert!(ledger.is_empty());

        // Add supervision entry
        ledger.push(EvidenceRecord {
            timestamp: 100,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Restart,
            detail: EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed {
                attempt: 1,
                delay: None,
            }),
        });

        // Add registry entry
        ledger.push(EvidenceRecord {
            timestamp: 200,
            task_id: test_task_id_2(),
            region_id: test_region_id(),
            subsystem: Subsystem::Registry,
            verdict: Verdict::Accept,
            detail: EvidenceDetail::Registry(RegistryDetail::NameAvailable),
        });

        // Add supervision stop
        ledger.push(EvidenceRecord {
            timestamp: 300,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Stop,
            detail: EvidenceDetail::Supervision(SupervisionDetail::ExplicitStop),
        });

        assert_eq!(ledger.len(), 3);

        // Filter by subsystem
        assert_eq!(ledger.for_subsystem(Subsystem::Supervision).count(), 2);

        assert_eq!(ledger.for_subsystem(Subsystem::Registry).count(), 1);

        // Filter by verdict
        assert_eq!(ledger.with_verdict(Verdict::Restart).count(), 1);

        assert_eq!(ledger.with_verdict(Verdict::Stop).count(), 1);

        // Filter by task
        assert_eq!(ledger.for_task(test_task_id()).count(), 2);

        assert_eq!(ledger.for_task(test_task_id_2()).count(), 1);

        crate::test_complete!("generalized_ledger_push_and_query");
    }

    #[test]
    fn generalized_ledger_render_deterministic() {
        init_test("generalized_ledger_render_deterministic");

        let mut ledger_a = GeneralizedLedger::new();
        let mut ledger_b = GeneralizedLedger::new();

        let records = vec![
            EvidenceRecord {
                timestamp: 100,
                task_id: test_task_id(),
                region_id: test_region_id(),
                subsystem: Subsystem::Supervision,
                verdict: Verdict::Restart,
                detail: EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed {
                    attempt: 1,
                    delay: None,
                }),
            },
            EvidenceRecord {
                timestamp: 200,
                task_id: test_task_id(),
                region_id: test_region_id(),
                subsystem: Subsystem::Supervision,
                verdict: Verdict::Stop,
                detail: EvidenceDetail::Supervision(SupervisionDetail::MonotoneSeverity {
                    outcome_kind: "Panicked".to_string(),
                }),
            },
        ];

        for r in &records {
            ledger_a.push(r.clone());
            ledger_b.push(r.clone());
        }

        // Byte-for-byte identical rendering
        assert_eq!(ledger_a.render(), ledger_b.render());

        // Display matches render
        assert_eq!(format!("{ledger_a}"), ledger_a.render());

        crate::test_complete!("generalized_ledger_render_deterministic");
    }

    #[test]
    fn generalized_ledger_clear() {
        init_test("generalized_ledger_clear");

        let mut ledger = GeneralizedLedger::new();
        ledger.push(EvidenceRecord {
            timestamp: 100,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Stop,
            detail: EvidenceDetail::Supervision(SupervisionDetail::ExplicitStop),
        });

        assert_eq!(ledger.len(), 1);
        ledger.clear();
        assert!(ledger.is_empty());

        crate::test_complete!("generalized_ledger_clear");
    }

    #[test]
    fn subsystem_display() {
        init_test("subsystem_display");

        assert_eq!(format!("{}", Subsystem::Supervision), "supervision");
        assert_eq!(format!("{}", Subsystem::Registry), "registry");
        assert_eq!(format!("{}", Subsystem::Link), "link");
        assert_eq!(format!("{}", Subsystem::Monitor), "monitor");

        crate::test_complete!("subsystem_display");
    }

    #[test]
    fn verdict_display() {
        init_test("verdict_display");

        assert_eq!(format!("{}", Verdict::Restart), "RESTART");
        assert_eq!(format!("{}", Verdict::Stop), "STOP");
        assert_eq!(format!("{}", Verdict::Accept), "ACCEPT");
        assert_eq!(format!("{}", Verdict::Reject), "REJECT");
        assert_eq!(format!("{}", Verdict::Propagate), "PROPAGATE");
        assert_eq!(format!("{}", Verdict::Deliver), "DELIVER");

        crate::test_complete!("verdict_display");
    }

    #[test]
    fn registry_detail_display_variants() {
        init_test("registry_detail_display_variants");

        let details = vec![
            (RegistryDetail::NameAvailable, "name available"),
            (
                RegistryDetail::LeaseCommitted,
                "lease committed (normal release)",
            ),
        ];

        for (detail, expected) in details {
            assert_eq!(format!("{detail}"), expected);
        }

        crate::test_complete!("registry_detail_display_variants");
    }

    #[test]
    fn link_detail_display_variants() {
        init_test("link_detail_display_variants");

        assert_eq!(
            format!("{}", LinkDetail::Unlinked),
            "unlinked before failure"
        );

        crate::test_complete!("link_detail_display_variants");
    }

    #[test]
    fn monitor_detail_display_variants() {
        init_test("monitor_detail_display_variants");

        assert_eq!(
            format!("{}", MonitorDetail::Demonitored),
            "demonitored before termination"
        );

        crate::test_complete!("monitor_detail_display_variants");
    }

    #[test]
    fn generalized_ledger_filter_predicate() {
        init_test("generalized_ledger_filter_predicate");

        let mut ledger = GeneralizedLedger::new();
        for i in 0u64..5 {
            ledger.push(EvidenceRecord {
                timestamp: i * 100,
                task_id: test_task_id(),
                region_id: test_region_id(),
                subsystem: Subsystem::Supervision,
                verdict: if i < 3 {
                    Verdict::Restart
                } else {
                    Verdict::Stop
                },
                detail: EvidenceDetail::Supervision(if i < 3 {
                    SupervisionDetail::RestartAllowed {
                        attempt: (i as u32) + 1,
                        delay: None,
                    }
                } else {
                    SupervisionDetail::WindowExhausted {
                        max_restarts: 3,
                        window: Duration::from_secs(60),
                    }
                }),
            });
        }

        // Custom filter: entries after timestamp 200
        assert_eq!(ledger.filter(|e| e.timestamp > 200).count(), 2);

        crate::test_complete!("generalized_ledger_filter_predicate");
    }

    #[test]
    fn evidence_record_render_card_supervision_restart() {
        init_test("evidence_record_render_card_supervision_restart");

        let record = EvidenceRecord {
            timestamp: 1_000_000_001,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Restart,
            detail: EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed {
                attempt: 1,
                delay: Some(Duration::from_millis(10)),
            }),
        };

        let rendered = record.render_card();
        assert!(rendered.contains("supervision RESTART"));
        assert!(rendered.contains("rule: If restart window and budget allow"));
        assert!(rendered.contains("substitution: attempt=1, delay=10ms => RESTART"));
        assert!(rendered.contains("intuition: Restart attempt is permitted"));

        crate::test_complete!("evidence_record_render_card_supervision_restart");
    }

    #[test]
    fn generalized_ledger_render_cards_deterministic() {
        init_test("generalized_ledger_render_cards_deterministic");

        let mut ledger_a = GeneralizedLedger::new();
        let mut ledger_b = GeneralizedLedger::new();

        for ledger in [&mut ledger_a, &mut ledger_b] {
            ledger.push(EvidenceRecord {
                timestamp: 10,
                task_id: test_task_id(),
                region_id: test_region_id(),
                subsystem: Subsystem::Registry,
                verdict: Verdict::Reject,
                detail: EvidenceDetail::Registry(RegistryDetail::NameCollision {
                    existing_holder: test_task_id_2(),
                }),
            });
            ledger.push(EvidenceRecord {
                timestamp: 11,
                task_id: test_task_id(),
                region_id: test_region_id(),
                subsystem: Subsystem::Supervision,
                verdict: Verdict::Stop,
                detail: EvidenceDetail::Supervision(SupervisionDetail::WindowExhausted {
                    max_restarts: 2,
                    window: Duration::from_secs(1),
                }),
            });
        }

        // Byte-for-byte identical rendering
        assert_eq!(ledger_a.render_cards(), ledger_b.render_cards());

        crate::test_complete!("generalized_ledger_render_cards_deterministic");
    }

    // Pure data-type tests (wave 35 – CyanBarn)

    #[test]
    fn subsystem_debug_copy_hash() {
        use std::collections::HashSet;
        let s = Subsystem::Supervision;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Supervision"));

        // Copy
        let s2 = s;
        assert_eq!(s, s2);

        // Hash consistency
        let mut set = HashSet::new();
        set.insert(Subsystem::Supervision);
        set.insert(Subsystem::Registry);
        set.insert(Subsystem::Link);
        set.insert(Subsystem::Monitor);
        assert_eq!(set.len(), 4);
        assert!(set.contains(&Subsystem::Link));
    }

    #[test]
    fn verdict_debug_copy_hash() {
        use std::collections::HashSet;
        let v = Verdict::Restart;
        let dbg = format!("{v:?}");
        assert!(dbg.contains("Restart"));

        // Copy
        let v2 = v;
        assert_eq!(v, v2);

        // Hash - all 11 variants distinct
        let mut set = HashSet::new();
        for v in [
            Verdict::Restart,
            Verdict::Stop,
            Verdict::Escalate,
            Verdict::Accept,
            Verdict::Reject,
            Verdict::Release,
            Verdict::Abort,
            Verdict::Propagate,
            Verdict::Suppress,
            Verdict::Deliver,
            Verdict::Drop,
        ] {
            set.insert(v);
        }
        assert_eq!(set.len(), 11);
    }

    #[test]
    fn evidence_detail_debug_clone_eq() {
        let detail = EvidenceDetail::Supervision(SupervisionDetail::ExplicitStop);
        let dbg = format!("{detail:?}");
        assert!(dbg.contains("Supervision"));
        assert!(dbg.contains("ExplicitStop"));

        let cloned = detail.clone();
        assert_eq!(detail, cloned);

        // Different variants are not equal
        let other = EvidenceDetail::Registry(RegistryDetail::NameAvailable);
        assert_ne!(detail, other);
    }

    #[test]
    fn supervision_detail_debug_clone() {
        let detail = SupervisionDetail::RestartAllowed {
            attempt: 3,
            delay: Some(Duration::from_millis(100)),
        };
        let dbg = format!("{detail:?}");
        assert!(dbg.contains("RestartAllowed"));
        assert!(dbg.contains('3'));

        let cloned = detail.clone();
        assert_eq!(detail, cloned);
    }

    #[test]
    fn evidence_record_debug_clone_eq() {
        let record = EvidenceRecord {
            timestamp: 42,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Registry,
            verdict: Verdict::Accept,
            detail: EvidenceDetail::Registry(RegistryDetail::NameAvailable),
        };
        let dbg = format!("{record:?}");
        assert!(dbg.contains("EvidenceRecord"));
        assert!(dbg.contains("42"));

        let cloned = record.clone();
        assert_eq!(record, cloned);
    }

    #[test]
    fn evidence_card_debug_clone() {
        let record = EvidenceRecord {
            timestamp: 100,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Supervision,
            verdict: Verdict::Stop,
            detail: EvidenceDetail::Supervision(SupervisionDetail::ExplicitStop),
        };
        let card = record.to_card();
        let dbg = format!("{card:?}");
        assert!(dbg.contains("EvidenceCard"));

        let cloned = card.clone();
        assert_eq!(card, cloned);
    }

    #[test]
    fn generalized_ledger_debug_clone_default() {
        let ledger = GeneralizedLedger::default();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);

        let dbg = format!("{ledger:?}");
        assert!(dbg.contains("GeneralizedLedger"));

        let mut ledger2 = GeneralizedLedger::new();
        ledger2.push(EvidenceRecord {
            timestamp: 1,
            task_id: test_task_id(),
            region_id: test_region_id(),
            subsystem: Subsystem::Monitor,
            verdict: Verdict::Deliver,
            detail: EvidenceDetail::Monitor(MonitorDetail::Demonitored),
        });
        let cloned = ledger2.clone();
        assert_eq!(cloned.len(), 1);
        assert_eq!(cloned.entries()[0].timestamp, 1);
    }
