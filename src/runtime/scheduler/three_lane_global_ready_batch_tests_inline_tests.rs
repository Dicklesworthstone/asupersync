    use super::*;

    /// br-asupersync-5khftq M2: the rest of a batch drained from a deep global
    /// ready queue waits in the draining worker's stealable queue, so an idle
    /// peer can take it while that worker runs a long poll.
    #[test]
    fn the_rest_of_a_global_ready_batch_can_be_stolen_by_an_idle_peer() {
        let state = local_queue::LocalQueue::test_state(10);
        let mut scheduler = ThreeLaneScheduler::new(2, &state);
        for i in 0..8u32 {
            scheduler.inject_ready(TaskId::new_for_test(1, i), 50);
        }
        let global = Arc::clone(&scheduler.global);
        let mut workers = scheduler.take_workers();

        assert_eq!(
            workers[0].try_ready_work(),
            Some(TaskId::new_for_test(1, 0)),
            "the oldest task is dispatched first"
        );
        assert_eq!(
            workers[0].preemption_metrics().global_ready_batch_tasks,
            4,
            "a deep global queue is drained in a batch of four"
        );
        // Busy peers empty the global lane.
        while global.pop_ready().is_some() {}

        let batch: Vec<TaskId> = (1..4).map(|i| TaskId::new_for_test(1, i)).collect();
        let stolen = workers[1].try_steal();
        assert!(
            stolen.is_some_and(|task| batch.contains(&task)),
            "an idle peer could not reach the drained batch: stole {stolen:?}"
        );
    }
