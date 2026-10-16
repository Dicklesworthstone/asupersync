    use super::{
        CompactTaskId, ProductionSchedule, ProjectionError, ProjectionOptions, ReplayEvent,
    };
    use crate::trace::event::{TraceEvent, TraceEventKind};
    use crate::types::{RegionId, TaskId, Time};

    fn task(n: u32) -> TaskId {
        TaskId::new_for_test(n, 1)
    }

    fn region() -> RegionId {
        RegionId::new_for_test(1, 1)
    }

    fn at(seq: u64) -> Time {
        Time::from_nanos(seq * 10)
    }

    #[test]
    fn interleaved_polls_project_in_order() {
        let events = vec![
            TraceEvent::spawn(1, at(1), task(1), region()),
            TraceEvent::spawn(2, at(2), task(2), region()),
            TraceEvent::schedule(3, at(3), task(1), region()),
            TraceEvent::poll(4, at(4), task(1), region()),
            TraceEvent::poll(5, at(5), task(2), region()),
            TraceEvent::poll(6, at(6), task(1), region()),
            TraceEvent::complete(7, at(7), task(1), region()),
            TraceEvent::complete(8, at(8), task(2), region()),
        ];
        let schedule = ProductionSchedule::from_runtime_trace(&events).expect("projects");
        assert_eq!(
            schedule.steps().collect::<Vec<_>>(),
            vec![(0, 4), (1, 5), (0, 6)],
            "steps are the Poll events in order, keyed by spawn ordinal"
        );
        let summary = schedule.summary();
        assert_eq!(summary.spawned, 2);
        assert_eq!(summary.steps, 3);
        assert_eq!(summary.completed, 2);
        assert_eq!(
            summary.skipped, 1,
            "the Schedule event is dropped when Polls exist"
        );
        assert!(!summary.steps_from_schedule_events);
        assert_eq!((summary.first_seq, summary.last_seq), (1, 8));
        assert_eq!(
            schedule.spawn_order(),
            &[CompactTaskId::from(task(1)), CompactTaskId::from(task(2))]
        );
        assert!(matches!(
            schedule.trace().events.first(),
            Some(ReplayEvent::TaskSpawned { at_tick: 1, .. })
        ));
    }

    #[test]
    fn poll_before_spawn_is_refused_strictly_and_tolerated_as_orphan() {
        let events = vec![
            TraceEvent::spawn(1, at(1), task(1), region()),
            TraceEvent::poll(2, at(2), task(2), region()),
        ];
        assert_eq!(
            ProductionSchedule::from_runtime_trace(&events).err(),
            Some(ProjectionError::MissingSpawn {
                task: CompactTaskId::from(task(2)),
                seq: 2,
                kind: TraceEventKind::Poll,
            })
        );
        let tolerant = ProductionSchedule::from_runtime_trace_with(
            &events,
            ProjectionOptions {
                allow_orphans: true,
            },
        )
        .expect("orphans admitted");
        assert_eq!(
            tolerant.summary().orphans,
            vec![CompactTaskId::from(task(2))]
        );
        assert_eq!(
            tolerant.spawn_ordinal(CompactTaskId::from(task(2))),
            Some(1)
        );
        assert_eq!(tolerant.steps().collect::<Vec<_>>(), vec![(1, 2)]);
    }

    #[test]
    fn schedule_events_are_steps_only_when_no_polls_exist() {
        let events = vec![
            TraceEvent::spawn(1, at(1), task(1), region()),
            TraceEvent::schedule(2, at(2), task(1), region()),
            TraceEvent::schedule(3, at(3), task(1), region()),
        ];
        let schedule = ProductionSchedule::from_runtime_trace(&events).expect("projects");
        assert_eq!(schedule.steps().collect::<Vec<_>>(), vec![(0, 2), (0, 3)]);
        assert!(schedule.summary().steps_from_schedule_events);
        assert_eq!(schedule.summary().skipped, 0);
    }

    #[test]
    fn empty_and_duplicate_spawn_are_errors() {
        assert_eq!(
            ProductionSchedule::from_runtime_trace(&[]).err(),
            Some(ProjectionError::Empty)
        );
        let events = vec![
            TraceEvent::spawn(1, at(1), task(1), region()),
            TraceEvent::spawn(2, at(2), task(1), region()),
        ];
        assert_eq!(
            ProductionSchedule::from_runtime_trace(&events).err(),
            Some(ProjectionError::DuplicateSpawn {
                task: CompactTaskId::from(task(1)),
                seq: 2,
            })
        );
        // Events of kinds the projection does not carry alone are "empty".
        let only_region = vec![TraceEvent::time_advance(
            1,
            Time::ZERO,
            Time::from_nanos(0),
            Time::from_nanos(100),
        )];
        assert_eq!(
            ProductionSchedule::from_runtime_trace(&only_region).err(),
            Some(ProjectionError::Empty)
        );
    }

    #[test]
    fn time_and_timer_hints_are_carried_and_others_counted() {
        let events = vec![
            TraceEvent::spawn(1, at(1), task(1), region()),
            TraceEvent::time_advance(2, at(2), Time::from_nanos(0), Time::from_nanos(100)),
            TraceEvent::timer_scheduled(3, at(3), 7, Time::from_nanos(500)),
            TraceEvent::timer_fired(4, at(4), 7),
            TraceEvent::wake(5, at(5), task(1), region()),
            TraceEvent::poll(6, at(6), task(1), region()),
            TraceEvent::yield_task(7, at(7), task(1), region()),
        ];
        let schedule = ProductionSchedule::from_runtime_trace(&events).expect("projects");
        let summary = schedule.summary();
        assert_eq!(summary.time_advances, 1);
        assert_eq!(summary.timers, 2);
        assert_eq!(summary.yielded, 1);
        assert_eq!(
            summary.skipped, 1,
            "Wake is not a decision the lab re-drives"
        );
        assert!(schedule.trace().events.iter().any(|event| matches!(
            event,
            ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 100
            }
        )));
        assert!(schedule.trace().events.iter().any(|event| matches!(
            event,
            ReplayEvent::TimerCreated {
                timer_id: 7,
                deadline_nanos: 500
            }
        )));
        assert_eq!(schedule.into_trace().len(), 6);
    }
