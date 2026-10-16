    use super::*;
    use crate::lab::ldfi::HittingSetBudget;
    use crate::record::ObligationKind;
    use crate::remote::NodeId;
    use crate::trace::distributed::{LogicalTime, VectorClock};
    use crate::types::{RegionId, Time};

    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(id, 0)
    }

    fn region() -> RegionId {
        RegionId::new_for_test(0, 0)
    }

    fn ob(id: u32) -> ObligationId {
        ObligationId::new_for_test(id, 0)
    }

    fn support(lineage: &CausalLineage, seq: u64) -> Vec<u64> {
        lineage
            .support_of(FaultEventId::new(seq))
            .into_iter()
            .map(FaultEventId::get)
            .collect()
    }

    #[test]
    fn classifier_marks_deliveries_faultable_and_structure_not() {
        assert!(default_faultable(TraceEventKind::Wake));
        assert!(default_faultable(TraceEventKind::TimerFired));
        assert!(default_faultable(TraceEventKind::IoReady));
        assert!(default_faultable(TraceEventKind::ObligationCommit));
        assert!(default_faultable(TraceEventKind::DownDelivered));
        assert!(!default_faultable(TraceEventKind::Spawn));
        assert!(!default_faultable(TraceEventKind::Poll));
        assert!(!default_faultable(TraceEventKind::Complete));
        assert!(!default_faultable(TraceEventKind::IoRequested));
        assert!(!default_faultable(TraceEventKind::UserTrace));
    }

    #[test]
    fn program_order_chains_same_task() {
        // spawn(structural) -> wake(faultable) -> complete(structural), all task 1.
        let events = vec![
            TraceEvent::spawn(0, Time::ZERO, task(1), region()),
            TraceEvent::wake(1, Time::ZERO, task(1), region()),
            TraceEvent::complete(2, Time::ZERO, task(1), region()),
        ];
        let lineage = build_causal_lineage(&events, TraceLineageConfig::default());
        // The completion's cone is the whole chain; its fault-able support is just
        // the wake.
        assert_eq!(support(&lineage, 2), vec![1]);
        assert!(!lineage.is_faultable(FaultEventId::new(0)));
        assert!(lineage.is_faultable(FaultEventId::new(1)));
    }

    #[test]
    fn io_token_correlation_links_send_to_ack() {
        // Same token: result(send, faultable) then ready(ack, faultable).
        let events = vec![
            TraceEvent::io_result(0, Time::ZERO, 5, 4),
            TraceEvent::io_ready(1, Time::ZERO, 5, 1),
        ];
        let with_corr = build_causal_lineage(&events, TraceLineageConfig::default());
        assert_eq!(support(&with_corr, 1), vec![0, 1]);

        // Disabling correlation (and logical time) isolates the ack.
        let no_corr = build_causal_lineage(
            &events,
            TraceLineageConfig {
                use_logical_time: false,
                correlate_resources: false,
            },
        );
        assert_eq!(support(&no_corr, 1), vec![1]);
    }

    #[test]
    fn obligation_lifecycle_chains_reserve_to_commit() {
        let events = vec![
            TraceEvent::obligation_reserve(
                0,
                Time::ZERO,
                ob(1),
                task(1),
                region(),
                ObligationKind::Lease,
            ),
            TraceEvent::obligation_commit(
                1,
                Time::ZERO,
                ob(1),
                task(1),
                region(),
                ObligationKind::Lease,
                10,
            ),
        ];
        // Reserve and commit are both fault-able leases; commit's support is both.
        let lineage = build_causal_lineage(
            &events,
            TraceLineageConfig {
                use_logical_time: false,
                correlate_resources: true,
            },
        );
        assert_eq!(support(&lineage, 1), vec![0, 1]);
    }

    #[test]
    fn timer_scheduled_happens_before_fire() {
        let events = vec![
            TraceEvent::timer_scheduled(0, Time::ZERO, 9, Time::ZERO),
            TraceEvent::timer_fired(1, Time::ZERO, 9),
        ];
        let lineage = build_causal_lineage(
            &events,
            TraceLineageConfig {
                use_logical_time: false,
                correlate_resources: true,
            },
        );
        // Scheduled is structural; the fire is fault-able and reachable from it.
        assert_eq!(
            lineage
                .causal_cone(FaultEventId::new(1))
                .into_iter()
                .map(FaultEventId::get)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(support(&lineage, 1), vec![1]);
    }

    #[test]
    fn vector_clock_adds_cross_task_edge() {
        // send (task net) before recv-ack (task b) only via the vector clock.
        let net = NodeId::new("net");
        let b = NodeId::new("b");
        let mut send_vc = VectorClock::new();
        send_vc.increment(&net);
        let mut ack_vc = send_vc.clone();
        ack_vc.increment(&b);

        let events = vec![
            TraceEvent::io_result(0, Time::ZERO, 10, 4)
                .with_logical_time(LogicalTime::Vector(send_vc)),
            TraceEvent::io_ready(1, Time::ZERO, 20, 1)
                .with_logical_time(LogicalTime::Vector(ack_vc)),
        ];
        // Different tokens => only the logical clock can link them.
        let with_lt = build_causal_lineage(&events, TraceLineageConfig::default());
        assert_eq!(support(&with_lt, 1), vec![0, 1]);
        let without_lt = build_causal_lineage(
            &events,
            TraceLineageConfig {
                use_logical_time: false,
                correlate_resources: true,
            },
        );
        assert_eq!(support(&without_lt, 1), vec![1]);
    }

    #[test]
    fn deterministic() {
        let events = vec![
            TraceEvent::spawn(0, Time::ZERO, task(1), region()),
            TraceEvent::wake(1, Time::ZERO, task(1), region()),
            TraceEvent::io_result(2, Time::ZERO, 5, 4),
            TraceEvent::io_ready(3, Time::ZERO, 5, 1),
        ];
        let a = build_causal_lineage(&events, TraceLineageConfig::default());
        let b = build_causal_lineage(&events, TraceLineageConfig::default());
        assert_eq!(a, b);
    }

    #[test]
    fn support_graph_for_pipeline_finds_shared_root() {
        // Two ack tokens both rooted at one send via the vector clock; the outcome
        // user-traces depend on each ack. Minimal breaking hypothesis is {send}.
        let net = NodeId::new("net");
        let a = NodeId::new("a");
        let b = NodeId::new("b");
        let mut send_vc = VectorClock::new();
        send_vc.increment(&net);
        let mut ack_a_vc = send_vc.clone();
        ack_a_vc.increment(&a);
        let mut ack_b_vc = send_vc.clone();
        ack_b_vc.increment(&b);
        let mut ok_a_vc = ack_a_vc.clone();
        ok_a_vc.increment(&a);
        let mut ok_b_vc = ack_b_vc.clone();
        ok_b_vc.increment(&b);

        let events = vec![
            TraceEvent::io_result(1, Time::ZERO, 10, 4)
                .with_logical_time(LogicalTime::Vector(send_vc)),
            TraceEvent::io_ready(2, Time::ZERO, 20, 1)
                .with_logical_time(LogicalTime::Vector(ack_a_vc)),
            TraceEvent::io_ready(3, Time::ZERO, 30, 1)
                .with_logical_time(LogicalTime::Vector(ack_b_vc)),
            TraceEvent::user_trace(10, Time::ZERO, "delivered-a")
                .with_logical_time(LogicalTime::Vector(ok_a_vc)),
            TraceEvent::user_trace(11, Time::ZERO, "delivered-b")
                .with_logical_time(LogicalTime::Vector(ok_b_vc)),
        ];

        let graph = support_graph_for(&events, TraceLineageConfig::default(), |ev| {
            ev.kind == TraceEventKind::UserTrace
        });
        assert_eq!(graph.derivations().len(), 2);
        let result = graph.minimal_hitting_sets(HittingSetBudget::default());
        let smallest = result.hypotheses.first().expect("a hypothesis exists");
        assert_eq!(smallest.len(), 1);
        assert!(smallest.contains(&FaultEventId::new(1)));
    }
