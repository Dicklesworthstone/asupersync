    use super::*;
    use crate::channel::oneshot;
    use crate::runtime::task_handle::RetirementBarrier;
    use crate::types::TaskId;

    /// A branch publishes its result before the scheduler retires its record
    /// and opens its retirement barrier; is_finished() stays false in between.
    /// Dropping the admitted race in that window must not request the
    /// finished branch's cancellation, while an unfinished branch still gets
    /// one.
    #[test]
    fn dropping_a_race_spares_a_branch_published_before_retirement() {
        let cx = Cx::for_testing();
        let finished_cx = Cx::for_testing();
        let running_cx = Cx::for_testing();
        let (finished_tx, finished_rx) = oneshot::channel::<Result<u32, JoinError>>();
        let (_running_tx, running_rx) = oneshot::channel::<Result<u32, JoinError>>();
        let admitted = Admitted {
            handles: vec![
                TaskHandle::with_retirement_barrier_for_test(
                    TaskId::new_for_test(1, 0),
                    finished_rx,
                    Arc::downgrade(&finished_cx.inner),
                    RetirementBarrier::pending(),
                ),
                TaskHandle::with_retirement_barrier_for_test(
                    TaskId::new_for_test(2, 0),
                    running_rx,
                    Arc::downgrade(&running_cx.inner),
                    RetirementBarrier::pending(),
                ),
            ],
        };
        finished_tx
            .send(&cx, Ok(7))
            .expect("the finished branch publishes its result");
        assert!(
            !admitted.handles[0].is_finished(),
            "the closed barrier still gates the published result"
        );

        drop(admitted);

        assert!(
            !finished_cx.is_cancel_requested(),
            "dropping the race cancelled a branch that had already published its result"
        );
        assert!(
            running_cx.is_cancel_requested(),
            "dropping the race must still cancel a branch that has not finished"
        );
    }
