    use super::*;

    /// A two-participant race whose first participant has finished; `finish`
    /// completes the second participant and the race.
    fn race(recorder: &LoserDrainHistoryRecorder, first_task: u32, finish: bool) -> u64 {
        let participants = vec![
            TaskId::new_for_test(first_task, 1),
            TaskId::new_for_test(first_task + 1, 1),
        ];
        let race_id = recorder.record_race_start(
            RegionId::new_for_test(0, 1),
            participants.clone(),
            Time::ZERO,
        );
        recorder.record_task_complete(participants[0], Time::ZERO);
        if finish {
            recorder.record_task_complete(participants[1], Time::ZERO);
            recorder.record_race_complete(race_id, participants[0], Time::ZERO);
        }
        race_id
    }

    fn started(events: &[LoserDrainHistoryEvent]) -> Vec<u64> {
        events
            .iter()
            .filter_map(|event| match event {
                LoserDrainHistoryEvent::RaceStarted { race_id, .. } => Some(*race_id),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn bounded_loser_drain_history_keeps_in_flight_and_recent_completed_races() {
        let recorder = LoserDrainHistoryRecorder::default();
        recorder.retain_completed_races(2);
        let in_flight = race(&recorder, 100, false);
        for round in 0..5 {
            race(&recorder, round * 2, true);
        }
        let events = recorder.snapshot();
        // Five completed races exceed twice the limit, so the three oldest
        // are forgotten; the in-flight race keeps its partial evidence.
        assert_eq!(started(&events), vec![in_flight, 4, 5]);
        let completed_tasks: Vec<TaskId> = events
            .iter()
            .filter_map(|event| match event {
                LoserDrainHistoryEvent::TaskCompleted { task, .. } => Some(*task),
                _ => None,
            })
            .collect();
        assert_eq!(
            completed_tasks,
            [100, 6, 7, 8, 9].map(|index| TaskId::new_for_test(index, 1))
        );
        let completed_races: Vec<u64> = events
            .iter()
            .filter_map(|event| match event {
                LoserDrainHistoryEvent::RaceCompleted { race_id, .. } => Some(*race_id),
                _ => None,
            })
            .collect();
        assert_eq!(completed_races, vec![4, 5]);
    }

    #[test]
    fn unbounded_loser_drain_history_keeps_every_race_for_oracle_replay() {
        let recorder = LoserDrainHistoryRecorder::default();
        for round in 0..5 {
            race(&recorder, round * 2, true);
        }
        assert_eq!(started(&recorder.snapshot()), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn bounded_finalizer_history_keeps_open_regions_and_recent_closed_regions() {
        let mut state = RuntimeState::new();
        state.bound_oracle_histories(1);
        let open = RegionId::new_for_test(50, 1);
        state
            .finalizer_history
            .push(FinalizerHistoryEvent::Registered {
                id: 900,
                region: open,
                time: Time::ZERO,
            });
        for index in 0..3_u32 {
            let region = RegionId::new_for_test(index, 1);
            let id = u64::from(index);
            state
                .finalizer_history
                .push(FinalizerHistoryEvent::Registered {
                    id,
                    region,
                    time: Time::ZERO,
                });
            state.finalizer_history.push(FinalizerHistoryEvent::Ran {
                id,
                time: Time::ZERO,
            });
            state.record_finalizer_close_for_test(region);
        }
        // Three closed regions exceed twice the limit, so the two oldest are
        // forgotten with their finalizers; the open region is untouched.
        let kept: Vec<(u8, u64, Option<RegionId>)> = state
            .finalizer_history()
            .iter()
            .map(|event| match event {
                FinalizerHistoryEvent::Registered { id, region, .. } => (0, *id, Some(*region)),
                FinalizerHistoryEvent::Ran { id, .. } => (1, *id, None),
                FinalizerHistoryEvent::RegionClosed { region, .. } => (2, 0, Some(*region)),
            })
            .collect();
        let last = RegionId::new_for_test(2, 1);
        assert_eq!(
            kept,
            vec![
                (0, 900, Some(open)),
                (0, 2, Some(last)),
                (1, 2, None),
                (2, 0, Some(last))
            ]
        );
    }
