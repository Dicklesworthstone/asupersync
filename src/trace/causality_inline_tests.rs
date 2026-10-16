    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::remote::NodeId;
    use crate::trace::distributed::{LamportClock, VectorClock};
    use crate::types::{RegionId, Time};

    fn task(id: u32) -> TaskId {
        TaskId::new_for_test(id, 0)
    }

    fn region() -> RegionId {
        RegionId::new_for_test(0, 0)
    }

    fn spawn_event(seq: u64, task_id: TaskId, lt: LogicalTime) -> TraceEvent {
        TraceEvent::spawn(seq, Time::ZERO, task_id, region()).with_logical_time(lt)
    }

    fn schedule_event(seq: u64, task_id: TaskId, lt: LogicalTime) -> TraceEvent {
        TraceEvent::schedule(seq, Time::ZERO, task_id, region()).with_logical_time(lt)
    }

    fn wake_event(seq: u64, task_id: TaskId, lt: LogicalTime) -> TraceEvent {
        TraceEvent::wake(seq, Time::ZERO, task_id, region()).with_logical_time(lt)
    }

    fn complete_event(seq: u64, task_id: TaskId, lt: LogicalTime) -> TraceEvent {
        TraceEvent::complete(seq, Time::ZERO, task_id, region()).with_logical_time(lt)
    }

    fn lamport_tick(clock: &LamportClock) -> LogicalTime {
        LogicalTime::Lamport(clock.tick())
    }

    // =========================================================================
    // Lamport clock tests
    // =========================================================================

    #[test]
    fn causal_verify_empty_trace() {
        assert!(CausalOrderVerifier::verify(&[]).is_ok());
    }

    #[test]
    fn causal_verify_single_event() {
        let clock = LamportClock::new();
        let trace = vec![spawn_event(0, task(1), lamport_tick(&clock))];
        assert!(CausalOrderVerifier::verify(&trace).is_ok());
    }

    #[test]
    fn causal_verify_monotonic_lamport() {
        let clock = LamportClock::new();
        let trace = vec![
            spawn_event(0, task(1), lamport_tick(&clock)),
            schedule_event(1, task(1), lamport_tick(&clock)),
            wake_event(2, task(1), lamport_tick(&clock)),
            complete_event(3, task(1), lamport_tick(&clock)),
        ];
        assert!(CausalOrderVerifier::verify(&trace).is_ok());
    }

    #[test]
    fn causal_verify_non_monotonic_lamport() {
        let clock = LamportClock::new();
        let t3 = LogicalTime::Lamport(clock.tick());
        let _t2 = LogicalTime::Lamport(clock.tick());
        let t1 = LogicalTime::Lamport(clock.tick());
        // Deliberately reversed: higher logical time first
        let trace = vec![
            spawn_event(0, task(1), t1),
            schedule_event(1, task(1), t3), // t3 < t1, non-monotonic
        ];
        let err = CausalOrderVerifier::verify(&trace).unwrap_err();
        assert!(
            err.iter()
                .any(|v| v.kind == CausalityViolationKind::NonMonotonic)
        );
    }

    #[test]
    fn causal_verify_same_task_ordering() {
        let clock = LamportClock::new();
        let t1 = LogicalTime::Lamport(clock.tick());
        let t2 = LogicalTime::Lamport(clock.tick());
        // task(1) spawn at t2, then schedule at t1 — violation
        let trace = vec![spawn_event(0, task(1), t2), schedule_event(1, task(1), t1)];
        let err = CausalOrderVerifier::verify(&trace).unwrap_err();
        assert!(
            err.iter()
                .any(|v| v.kind == CausalityViolationKind::SameTaskConcurrent)
        );
    }

    #[test]
    fn causal_verify_spawn_before_wake() {
        let clock = LamportClock::new();
        let trace = vec![
            spawn_event(0, task(1), lamport_tick(&clock)),
            wake_event(1, task(1), lamport_tick(&clock)),
        ];
        assert!(CausalOrderVerifier::verify(&trace).is_ok());
    }

    #[test]
    fn causal_verify_wake_before_spawn_violation() {
        let clock = LamportClock::new();
        let t1 = LogicalTime::Lamport(clock.tick());
        let t2 = LogicalTime::Lamport(clock.tick());
        // Spawn at t2 but wake at t1 — wake doesn't reflect spawn dependency
        let trace = vec![spawn_event(0, task(1), t2), wake_event(1, task(1), t1)];
        let err = CausalOrderVerifier::verify(&trace).unwrap_err();
        assert!(
            err.iter()
                .any(|v| v.kind == CausalityViolationKind::MissingDependency)
        );
    }

    // =========================================================================
    // Vector clock tests
    // =========================================================================

    #[test]
    fn causal_verify_concurrent_tasks_vector_clock() {
        // Two tasks with independent vector clocks — concurrent is fine
        // for different tasks
        let mut vc_a = VectorClock::new();
        let mut vc_b = VectorClock::new();
        let node_a = NodeId::new("node-a");
        let node_b = NodeId::new("node-b");

        vc_a.increment(&node_a);
        vc_b.increment(&node_b);

        let trace = vec![
            spawn_event(0, task(1), LogicalTime::Vector(vc_a.clone())),
            spawn_event(1, task(2), LogicalTime::Vector(vc_b.clone())),
        ];
        // Different tasks, concurrent clocks — should pass
        assert!(CausalOrderVerifier::verify(&trace).is_ok());
    }

    #[test]
    fn causal_verify_vector_clock_happens_before() {
        let mut vc = VectorClock::new();
        let node = NodeId::new("node-a");

        vc.increment(&node);
        let t1 = LogicalTime::Vector(vc.clone());
        vc.increment(&node);
        let t2 = LogicalTime::Vector(vc.clone());

        let trace = vec![spawn_event(0, task(1), t1), schedule_event(1, task(1), t2)];
        assert!(CausalOrderVerifier::verify(&trace).is_ok());
    }

    // =========================================================================
    // Events without logical time
    // =========================================================================

    #[test]
    fn causal_verify_events_without_logical_time_skipped() {
        // Events without logical_time should be ignored
        let trace = vec![
            TraceEvent::spawn(0, Time::ZERO, task(1), region()),
            TraceEvent::complete(1, Time::ZERO, task(1), region()),
        ];
        assert!(CausalOrderVerifier::verify(&trace).is_ok());
    }

    #[test]
    fn causal_verify_mixed_annotated_and_unannotated() {
        let clock = LamportClock::new();
        let trace = vec![
            spawn_event(0, task(1), lamport_tick(&clock)),
            TraceEvent::schedule(1, Time::ZERO, task(1), region()), // no logical time
            wake_event(2, task(1), lamport_tick(&clock)),
        ];
        assert!(CausalOrderVerifier::verify(&trace).is_ok());
    }

    // =========================================================================
    // Multiple tasks interleaved
    // =========================================================================

    #[test]
    fn causal_verify_interleaved_tasks_correct() {
        let clock = LamportClock::new();
        let trace = vec![
            spawn_event(0, task(1), lamport_tick(&clock)),
            spawn_event(1, task(2), lamport_tick(&clock)),
            schedule_event(2, task(1), lamport_tick(&clock)),
            schedule_event(3, task(2), lamport_tick(&clock)),
            complete_event(4, task(1), lamport_tick(&clock)),
            complete_event(5, task(2), lamport_tick(&clock)),
        ];
        assert!(CausalOrderVerifier::verify(&trace).is_ok());
    }
