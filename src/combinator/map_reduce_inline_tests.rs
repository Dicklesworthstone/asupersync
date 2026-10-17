    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::{LabConfig, LabRuntime};
    use crate::types::Budget;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn executing_limits(concurrency: usize, retained: usize) -> MapReduceLimits {
        MapReduceLimits::new(
            NonZeroUsize::new(concurrency).unwrap(),
            NonZeroUsize::new(retained).unwrap(),
        )
    }

    fn assert_executing_lab_clean(lab: &mut LabRuntime, region: crate::types::RegionId) {
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "{report:?}");
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.region(region).unwrap().pending_spawn_count(), 0);
        let effects =
            lab.state
                .cancel_request(region, &CancelReason::user("map test complete"), None);
        let (tasks, wakes) = effects.into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(region);
        assert!(lab.state.region(region).is_none());
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    }

    /// A mapped child publishes its result before the scheduler retires its
    /// record and opens its retirement barrier; is_finished() stays false in
    /// between. Dropping the owner in that window must not request the
    /// finished child's cancellation, while an unfinished child still gets one.
    #[test]
    fn dropping_the_owner_spares_a_child_published_before_retirement() {
        use crate::channel::oneshot;
        use crate::runtime::task_handle::RetirementBarrier;
        use crate::types::TaskId;

        let cx = Cx::for_testing();
        let finished_cx = Cx::for_testing();
        let running_cx = Cx::for_testing();
        let (finished_tx, finished_rx) = oneshot::channel::<Result<(), JoinError>>();
        let (_running_tx, running_rx) = oneshot::channel::<Result<(), JoinError>>();
        let slot = |index: usize, handle| ExecutingMapSlot::<u32, ()> {
            index,
            handle: Some(handle),
            returned: Arc::new(parking_lot::Mutex::new(None)),
            value: None,
            drain_reason: None,
        };
        let owner = ExecutingMapOwner {
            cx: cx.clone(),
            cancel_waker: None,
            slots: VecDeque::from([
                slot(
                    0,
                    TaskHandle::with_retirement_barrier_for_test(
                        TaskId::new_for_test(1, 0),
                        finished_rx,
                        Arc::downgrade(&finished_cx.inner),
                        RetirementBarrier::pending(),
                    ),
                ),
                slot(
                    1,
                    TaskHandle::with_retirement_barrier_for_test(
                        TaskId::new_for_test(2, 0),
                        running_rx,
                        Arc::downgrade(&running_cx.inner),
                        RetirementBarrier::pending(),
                    ),
                ),
            ]),
            accumulator: None,
            next_scan: 0,
            scan_end: 0,
        };
        finished_tx
            .send(&cx, Ok(()))
            .expect("the finished child publishes its result");
        assert!(
            !owner.slots[0]
                .handle
                .as_ref()
                .expect("the finished child's handle")
                .is_finished(),
            "the closed barrier still gates the published result"
        );

        drop(owner);

        assert!(
            !finished_cx.is_cancel_requested(),
            "dropping the owner cancelled a child that had already published its result"
        );
        assert!(
            running_cx.is_cancel_requested(),
            "dropping the owner must still cancel a child that has not finished"
        );
    }

    fn run_executing_case<F, Fut, T>(factory: F) -> T
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0100).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let returned = Arc::new(parking_lot::Mutex::new(None));
        let publication = Arc::clone(&returned);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("actual map coordinator");
                let value = factory(cx.clone()).await;
                *publication.lock() = Some((value, cx.cancel_reason()));
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        let (result, cancelled) = returned
            .lock()
            .take()
            .expect("bounded map execution returned");
        // RuntimeState::create_task deliberately uses cancellation-dominant
        // delivery. Its terminal receipt is distinct from the engine report.
        match cancelled {
            Some(reason) => assert_eq!(join.try_join(), Err(JoinError::Cancelled(reason))),
            None => assert_eq!(join.try_join(), Ok(Some(()))),
        }
        assert_executing_lab_clean(&mut lab, root);
        result
    }

    #[test]
    fn executing_map_zero_one_many_move_only_values_and_independent_limits() {
        struct MoveOnly(String);
        assert!(NonZeroUsize::new(0).is_none());
        for count in [0, 1, 9] {
            for (concurrency, retained) in [(1, 1), (4, 2), (2, 5)] {
                let report = run_executing_case(move |cx| async move {
                    cx.scope()
                        .map_reduce(
                            &cx,
                            executing_limits(concurrency, retained),
                            0..count,
                            |_child, index| async move {
                                Outcome::<_, ()>::Ok(MoveOnly(index.to_string()))
                            },
                            |left, right| MoveOnly(format!("{}>{}", left.0, right.0)),
                        )
                        .await
                });
                assert_eq!(report.admitted, count);
                assert_eq!(report.completed, count);
                assert_eq!(report.reduced, count);
                assert!(report.max_in_flight <= concurrency);
                assert!(report.max_retained <= retained);
                assert!(report.stopped_by.is_none());
                let Outcome::Ok(value) = report.outcome else {
                    panic!("all maps succeed")
                };
                assert_eq!(
                    value.map(|value| value.0),
                    (count > 0).then(|| (0..count)
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                        .join(">"))
                );
            }
        }
    }

    #[test]
    fn executing_map_owned_capture_retirement_precedes_terminal_publication() {
        struct Capture {
            cx: Cx,
            drops: Arc<[AtomicUsize; 3]>,
            index: usize,
            cancel: bool,
            panic: bool,
        }

        impl Capture {
            fn observe(&self) {
                assert_eq!(self.drops[self.index].load(Ordering::SeqCst), 0);
            }
        }

        impl Drop for Capture {
            fn drop(&mut self) {
                assert_eq!(self.drops[self.index].fetch_add(1, Ordering::SeqCst), 0);
                if self.cancel {
                    self.cx.cancel_with(
                        crate::types::CancelKind::User,
                        Some("map owned-capture retirement"),
                    );
                }
                if self.panic {
                    panic!("map capture {} retirement panic", self.index);
                }
            }
        }

        struct Inputs {
            capture: Capture,
            fail_construction: bool,
        }

        struct Iter {
            capture: Capture,
            next: u32,
        }

        impl IntoIterator for Inputs {
            type Item = u32;
            type IntoIter = Iter;

            fn into_iter(self) -> Iter {
                assert!(!self.fail_construction, "map primary construction panic");
                Iter {
                    capture: self.capture,
                    next: 0,
                }
            }
        }

        impl Iterator for Iter {
            type Item = u32;

            fn next(&mut self) -> Option<u32> {
                self.capture.observe();
                let value = self.next;
                self.next += 1;
                (value < 3).then_some(value)
            }
        }

        #[derive(Debug)]
        struct Value {
            text: String,
            drops: Arc<AtomicUsize>,
        }

        impl Drop for Value {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        for mode in 0..12 {
            let mut lab = LabRuntime::new(LabConfig::new(0x32_0900 + mode).max_steps(4096));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let drops = Arc::new(std::array::from_fn::<_, 3, _>(|_| AtomicUsize::new(0)));
            let value_drops = Arc::new(AtomicUsize::new(0));
            let children = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let publication = Arc::new(parking_lot::Mutex::new(None));
            let task_drops = Arc::clone(&drops);
            let task_values = Arc::clone(&value_drops);
            let task_children = Arc::clone(&children);
            let task_publication = Arc::clone(&publication);
            let future: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                let cx = Cx::current().expect("actual retirement coordinator");
                let capture = |index| Capture {
                    cx: cx.clone(),
                    drops: Arc::clone(&task_drops),
                    index,
                    cancel: mode == index as u64 + 1 || (mode >= 7 && index == 0),
                    panic: mode == index as u64 + 4
                        || ((7..=9).contains(&mode) && index != 0)
                        || (mode == 11 && index == 0),
                };
                let inputs = Inputs {
                    capture: capture(0),
                    fail_construction: mode == 7,
                };
                let mapper = capture(1);
                let reducer = capture(2);
                let report = cx
                    .scope()
                    .map_reduce(
                        &cx,
                        executing_limits(1, 1),
                        inputs,
                        move |child, value| {
                            mapper.observe();
                            task_children.lock().push(child.task_id());
                            let drops = Arc::clone(&task_values);
                            async move {
                                if mode == 8 {
                                    panic!("map primary mapper panic");
                                }
                                if mode == 10 {
                                    Outcome::Err("map primary error")
                                } else {
                                    Outcome::Ok(Value {
                                        text: value.to_string(),
                                        drops,
                                    })
                                }
                            }
                        },
                        move |mut left: Value, right: Value| {
                            reducer.observe();
                            if mode == 9 {
                                panic!("map primary reducer panic");
                            }
                            left.text = format!("({}|{})", left.text, right.text);
                            left
                        },
                    )
                    .await;
                *task_publication.lock() = Some((report, cx.cancel_reason()));
            });
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, future)
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            let (report, reason) = publication.lock().take().expect("actual terminal report");
            match &reason {
                Some(reason) => {
                    assert_eq!(reason.kind(), crate::types::CancelKind::User);
                    assert_eq!(
                        reason.message.as_deref(),
                        Some("map owned-capture retirement")
                    );
                    assert_eq!(join.try_join(), Err(JoinError::Cancelled(reason.clone())));
                }
                None => assert_eq!(join.try_join(), Ok(Some(()))),
            }
            assert!(drops.iter().all(|count| count.load(Ordering::SeqCst) == 1));
            let counts = match mode {
                7 => (0, 0, 0),
                8 | 10 => (1, 1, 0),
                9 => (2, 2, 1),
                _ => (3, 3, 3),
            };
            assert_eq!((report.admitted, report.completed, report.reduced), counts);
            let trace = lab.state.trace_handle().snapshot();
            let completion =
                |expected| {
                    let matches: Vec<_> = trace.iter().filter(|event| {
                    event.kind == crate::trace::TraceEventKind::Complete
                        && matches!(event.data, crate::trace::TraceData::Task { task, region }
                            if task == expected && region == root)
                }).collect();
                    assert_eq!(matches.len(), 1, "exact terminal for {expected:?}");
                    matches[0].seq
                };
            let parent_complete = completion(parent);
            let children = children.lock();
            assert_eq!(children.len(), report.admitted);
            for (index, child) in children.iter().enumerate() {
                assert!(!children[..index].contains(child));
                assert!(completion(*child) < parent_complete);
            }
            assert_executing_lab_clean(&mut lab, root);
            eprintln!(
                "map capture retirement mode={mode} parent={parent:?} children={children:?} report={report:?} reason={reason:?}"
            );
            if mode == 0 {
                assert_eq!(report.failure_index, None);
                assert_eq!(
                    value_drops.load(Ordering::SeqCst),
                    2,
                    "returned accumulator remains live"
                );
                let Outcome::Ok(Some(value)) = report.outcome else {
                    panic!("successful retirement preserves the returned value");
                };
                assert_eq!(value.text, "((0|1)|2)");
                drop(value);
                assert_eq!(value_drops.load(Ordering::SeqCst), 3);
            } else if matches!(mode, 1..=3 | 10) {
                assert!(
                    matches!(&report.outcome, Outcome::Cancelled(actual) if Some(actual) == reason.as_ref())
                );
                assert_eq!(report.failure_index, Some(if mode == 10 { 1 } else { 3 }));
                if mode == 10 {
                    assert_eq!(report.stopped_by, Some((0, MapReduceStopCause::Error)));
                    assert!(matches!(
                        report.errors.as_slice(),
                        [(0, MapReduceExecutionError::Map("map primary error"))]
                    ));
                }
                assert_eq!(
                    value_drops.load(Ordering::SeqCst),
                    if mode == 10 { 0 } else { 3 }
                );
            } else {
                let (index, message) = match mode {
                    4..=6 => (3, format!("map capture {} retirement panic", mode - 4)),
                    7 => (0, "map primary construction panic".to_owned()),
                    8 => (0, "map primary mapper panic".to_owned()),
                    9 => (1, "map primary reducer panic".to_owned()),
                    11 => (3, "map capture 0 retirement panic".to_owned()),
                    _ => unreachable!(),
                };
                assert_eq!(report.failure_index, Some(index));
                assert!(
                    matches!(&report.outcome, Outcome::Panicked(payload) if payload.message() == message)
                );
                assert_eq!(
                    value_drops.load(Ordering::SeqCst),
                    match mode {
                        7 | 8 => 0,
                        9 => 2,
                        _ => 3,
                    }
                );
            }
        }
    }

    #[test]
    fn executing_map_held_first_input_keeps_completed_results_in_retained_window() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0101).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let gate = Arc::new(crate::sync::Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let pulled = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let input_pulled = Arc::clone(&pulled);
        let mapped_finished = Arc::clone(&finished);
        let child_gate = Arc::clone(&gate);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(2, 3),
                        (0..20).inspect(move |_| {
                            input_pulled.fetch_add(1, Ordering::SeqCst);
                        }),
                        move |child, index| {
                            let gate = Arc::clone(&child_gate);
                            let finished = Arc::clone(&mapped_finished);
                            async move {
                                if index == 0 {
                                    drop(
                                        crate::sync::OwnedMutexGuard::lock(gate, &child)
                                            .await
                                            .unwrap(),
                                    );
                                }
                                finished.fetch_add(1, Ordering::SeqCst);
                                Outcome::<_, ()>::Ok(index.to_string())
                            }
                        },
                        |left, right| format!("{left}>{right}"),
                    )
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert!(join.try_join().unwrap().is_none());
        assert_eq!(gate.waiters(), 1);
        assert_eq!(
            pulled.load(Ordering::SeqCst),
            3,
            "later completions cannot release retained credit"
        );
        assert_eq!(
            finished.load(Ordering::SeqCst),
            2,
            "later maps really completed"
        );
        drop(held);
        lab.run_until_idle();
        let report = join.try_join().unwrap().unwrap();
        assert_eq!(report.admitted, 20);
        assert_eq!(report.completed, 20);
        assert_eq!(report.reduced, 20);
        assert_eq!(report.max_in_flight, 2);
        assert_eq!(report.max_retained, 3);
        assert_eq!(
            report.outcome.unwrap(),
            Some((0..20).map(|i| i.to_string()).collect::<Vec<_>>().join(">"))
        );
        assert_eq!(gate.waiters(), 0);
        assert_executing_lab_clean(&mut lab, root);
        eprintln!(
            "map retained case: pulled=20 completed=20 reduced=20 max_active=2 max_retained=3 first_blocked_later_completed=2"
        );
    }

    #[test]
    fn executing_map_large_window_yields_admission_to_an_actual_other_task() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0106).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let gate = Arc::new(crate::sync::Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let pulled = Arc::new(AtomicUsize::new(0));
        let input_pulled = Arc::clone(&pulled);
        let child_gate = Arc::clone(&gate);
        let returned = Arc::new(parking_lot::Mutex::new(None));
        let publication = Arc::clone(&returned);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let report = cx
                    .scope()
                    .map_reduce(
                        &cx,
                        executing_limits(4096, 4096),
                        (0..4096).inspect(move |_| {
                            input_pulled.fetch_add(1, Ordering::SeqCst);
                        }),
                        move |child, index| {
                            let gate = Arc::clone(&child_gate);
                            async move {
                                if index == 0 {
                                    match crate::sync::OwnedMutexGuard::lock(gate, &child).await {
                                        Ok(guard) => drop(guard),
                                        Err(_) => {
                                            return Outcome::Cancelled(
                                                child.cancel_reason().unwrap(),
                                            );
                                        }
                                    }
                                }
                                Outcome::<_, ()>::Ok(index)
                            }
                        },
                        |left, right| left + right,
                    )
                    .await;
                *publication.lock() = Some(report);
            })
            .unwrap();
        let parent_cx = lab.state.task(parent).unwrap().cx.clone().unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.step_for_test();
        assert_eq!(
            pulled.load(Ordering::SeqCst),
            64,
            "one real coordinator poll has a fixed admission burst"
        );
        assert!(join.try_join().unwrap().is_none());
        let observer_pulled = Arc::clone(&pulled);
        let (observer, mut observation) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let seen = observer_pulled.load(Ordering::SeqCst);
                parent_cx.cancel_with(
                    crate::types::CancelKind::User,
                    Some("observer made progress"),
                );
                // cancel_with publishes the real Cx reason and wakes its
                // registered waiters. It does not call the region cancellation
                // path that emits a canonical TraceData::Cancel event.
                let reason = parent_cx
                    .cancel_reason()
                    .expect("observer published actual parent cancellation");
                (seen, reason)
            })
            .unwrap();
        lab.scheduler.lock().schedule(observer, 255);
        lab.run_until_idle();
        let (seen, published_reason) = observation.try_join().unwrap().unwrap();
        assert!(
            (64..4096).contains(&seen),
            "other task must execute before a large window is exhausted: {seen}"
        );
        assert_eq!(published_reason.kind(), crate::types::CancelKind::User);
        assert_eq!(published_reason.message(), Some("observer made progress"));
        assert_eq!(published_reason.origin_task, Some(parent));
        assert_eq!(published_reason.origin_region, root);
        assert_eq!(
            join.try_join(),
            Err(JoinError::Cancelled(published_reason.clone()))
        );
        let report = returned.lock().take().expect("actual map engine report");
        assert!(
            matches!(&report.outcome, Outcome::Cancelled(reason) if reason == &published_reason)
        );
        let trace = lab.state.trace_handle().snapshot();
        let completion = |expected| {
            let events: Vec<_> = trace
                .iter()
                .filter(|event| {
                    event.kind == crate::trace::TraceEventKind::Complete
                        && matches!(event.data, crate::trace::TraceData::Task { task, region }
                            if task == expected && region == root)
                })
                .collect();
            assert_eq!(events.len(), 1, "exact real terminal for {expected:?}");
            events[0].seq
        };
        let observer_complete = completion(observer);
        let parent_complete = completion(parent);
        assert!(
            observer_complete < parent_complete,
            "actual observer publication must precede the parent terminal"
        );
        assert_eq!(report.admitted, pulled.load(Ordering::SeqCst));
        assert_eq!(report.completed, report.admitted);
        assert_eq!(gate.waiters(), 0);
        drop(held);
        assert_executing_lab_clean(&mut lab, root);
        eprintln!(
            "map admission fairness: first_poll=64 observer_at={seen} admitted={} joined={} observer={observer:?} parent={parent:?} observer_complete={observer_complete} parent_complete={parent_complete} published_reason={published_reason:?}",
            report.admitted, report.completed
        );
    }

    #[test]
    fn executing_map_single_error_remains_an_error_without_cancelled_siblings() {
        let report = run_executing_case(|cx| async move {
            cx.scope()
                .map_reduce(
                    &cx,
                    executing_limits(1, 1),
                    [5],
                    |_child, _| async { Outcome::<usize, _>::Err("map refused") },
                    |left, right| left + right,
                )
                .await
        });
        assert!(matches!(
            report.outcome,
            Outcome::Err(MapReduceExecutionError::Map("map refused"))
        ));
        assert_eq!(report.failure_index, Some(0));
        assert_eq!(report.stopped_by, Some((0, MapReduceStopCause::Error)));
        assert!(report.errors.is_empty());
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (1, 1, 0)
        );
    }

    #[test]
    fn executing_map_missing_gateway_is_an_admission_error_without_running_mapper() {
        let cx = Cx::new(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::new_for_test(0, 1),
            Budget::INFINITE,
        );
        let scope = cx.scope();
        let mapped = Arc::new(AtomicUsize::new(0));
        let child_mapped = Arc::clone(&mapped);
        let mut execution = Box::pin(scope.map_reduce(
            &cx,
            executing_limits(2, 3),
            [1, 2, 3],
            move |_child, value| {
                child_mapped.fetch_add(1, Ordering::SeqCst);
                async move { Outcome::<_, ()>::Ok(value) }
            },
            |left, right| left + right,
        ));
        let mut poll_cx = std::task::Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(report) = execution.as_mut().poll(&mut poll_cx) else {
            panic!("synchronous admission refusal cannot leave a fictitious child pending")
        };
        assert!(matches!(
            report.outcome,
            Outcome::Err(MapReduceExecutionError::Spawn(
                SpawnError::RuntimeUnavailable
            ))
        ));
        assert_eq!(report.failure_index, Some(0));
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (0, 0, 0)
        );
        assert_eq!(mapped.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn executing_map_cancellation_before_or_during_input_does_not_spawn() {
        for cancel_before_input in [false, true] {
            let pulled = Arc::new(AtomicUsize::new(0));
            let mapped = Arc::new(AtomicUsize::new(0));
            let input_pulled = Arc::clone(&pulled);
            let child_mapped = Arc::clone(&mapped);
            let report = run_executing_case(move |cx| async move {
                if cancel_before_input {
                    cx.cancel_with(crate::types::CancelKind::User, Some("before first input"));
                }
                let input_cx = cx.clone();
                let inputs = [1, 2, 3].into_iter().inspect(move |_| {
                    input_pulled.fetch_add(1, Ordering::SeqCst);
                    input_cx.cancel_with(crate::types::CancelKind::User, Some("inside next input"));
                });
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(2, 3),
                        inputs,
                        move |_child, value| {
                            child_mapped.fetch_add(1, Ordering::SeqCst);
                            async move { Outcome::<_, ()>::Ok(value) }
                        },
                        |left, right| left + right,
                    )
                    .await
            });
            assert!(report.outcome.is_cancelled());
            assert_eq!(report.failure_index, Some(0));
            assert_eq!(
                (report.admitted, report.completed, report.reduced),
                (0, 0, 0)
            );
            assert_eq!(
                pulled.load(Ordering::SeqCst),
                usize::from(!cancel_before_input)
            );
            assert_eq!(mapped.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn executing_map_terminal_reducer_and_none_input_cancellation_cannot_return_success() {
        let report = run_executing_case(|cx| async move {
            let reducer_cx = cx.clone();
            cx.scope()
                .map_reduce(
                    &cx,
                    executing_limits(4, 4),
                    [2, 3],
                    |_child, value| async move { Outcome::<_, ()>::Ok(value) },
                    move |left, right| {
                        reducer_cx
                            .cancel_with(crate::types::CancelKind::User, Some("final reducer"));
                        left + right
                    },
                )
                .await
        });
        assert!(report.outcome.is_cancelled());
        assert_eq!(report.failure_index, Some(1));
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (2, 2, 2)
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let input_calls = Arc::clone(&calls);
        let report = run_executing_case(move |cx| async move {
            let input_cx = cx.clone();
            let input = std::iter::from_fn(move || {
                input_calls.fetch_add(1, Ordering::SeqCst);
                input_cx.cancel_with(crate::types::CancelKind::User, Some("terminal None"));
                None::<usize>
            });
            cx.scope()
                .map_reduce(
                    &cx,
                    executing_limits(4, 4),
                    input,
                    |_child, value| async move { Outcome::<_, ()>::Ok(value) },
                    |left, right| left + right,
                )
                .await
        });
        assert!(report.outcome.is_cancelled());
        assert_eq!(report.failure_index, Some(0));
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (0, 0, 0)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn executing_map_stronger_caller_cancel_reconciles_once_at_original_reducer_index() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0110).max_steps(8192));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (started, first_wait) = crate::channel::oneshot::channel::<()>();
        let started = Arc::new(parking_lot::Mutex::new(Some(started)));
        let first_wait = Arc::new(parking_lot::Mutex::new(Some(first_wait)));
        let (release, held) = crate::channel::oneshot::channel::<()>();
        let held = Arc::new(parking_lot::Mutex::new(Some(held)));
        let returned = Arc::new(parking_lot::Mutex::new(None));
        let publication = Arc::clone(&returned);
        let third_id = Arc::new(parking_lot::Mutex::new(None));
        let actual_third = Arc::clone(&third_id);
        let (parent, mut joined) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let reducer_cx = cx.clone();
                let report = cx
                    .scope()
                    .map_reduce(
                        &cx,
                        executing_limits(3, 3),
                        [0, 1, 2],
                        move |child, index| {
                            let started = Arc::clone(&started);
                            let first_wait = Arc::clone(&first_wait);
                            let held = Arc::clone(&held);
                            let actual_third = Arc::clone(&actual_third);
                            async move {
                                if index == 0 {
                                    let mut receiver = first_wait.lock().take().unwrap();
                                    receiver.recv_uninterruptible().await.unwrap();
                                } else if index == 2 {
                                    *actual_third.lock() = Some(child.task_id());
                                    started.lock().take().unwrap().send_blocking(()).unwrap();
                                    let mut receiver = held.lock().take().unwrap();
                                    receiver.recv_uninterruptible().await.unwrap();
                                }
                                Outcome::<_, ()>::Ok(index)
                            }
                        },
                        move |left, right| {
                            reducer_cx.cancel_with(
                                crate::types::CancelKind::User,
                                Some("reducer owns first cancellation"),
                            );
                            left + right
                        },
                    )
                    .await;
                *publication.lock() = Some(report);
            })
            .unwrap();
        let parent_cx = lab.state.task(parent).unwrap().cx.clone().unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert!(lab.steps() < 8192);
        assert!(lab.scheduler.lock().is_empty());
        assert_eq!(lab.run_until_idle(), 0);
        assert_eq!(joined.try_join(), Ok(None));
        assert!(returned.lock().is_none());
        let third = third_id.lock().unwrap();
        assert!(
            lab.state.task(third).is_some(),
            "the higher input really remains owned"
        );
        assert_eq!(lab.state.live_task_count(), 2);
        assert_eq!(
            lab.state
                .task(parent)
                .unwrap()
                .cancel_reason()
                .unwrap()
                .kind,
            crate::types::CancelKind::User
        );

        parent_cx.cancel_with(
            crate::types::CancelKind::Timeout,
            Some("stronger request during held cleanup"),
        );
        let stronger = parent_cx.cancel_reason().unwrap();
        assert_eq!(stronger.kind, crate::types::CancelKind::Timeout);
        let progress = lab.run_until_idle();
        assert!(
            progress > 0,
            "the owned cancellation waker must publish real progress"
        );
        assert!(lab.steps() < 8192);
        assert!(
            lab.scheduler.lock().is_empty(),
            "unchanged strengthened cancellation must park again"
        );
        assert_eq!(lab.run_until_idle(), 0);
        let holder = lab.state.task(parent).unwrap();
        assert_eq!(holder.cancel_reason(), Some(&stronger));
        assert_eq!(holder.cleanup_budget(), Some(stronger.cleanup_budget()));
        assert_eq!(joined.try_join(), Ok(None));
        assert!(returned.lock().is_none());
        assert!(lab.state.task(third).is_some());

        release.send_blocking(()).unwrap();
        lab.run_until_idle();
        assert_eq!(
            joined.try_join(),
            Err(JoinError::Cancelled(stronger.clone()))
        );
        let report = returned
            .lock()
            .take()
            .expect("engine waits for the actual third terminal");
        assert_eq!(
            report.failure_index,
            Some(1),
            "caller attribution stays at the actual reducer"
        );
        assert_eq!(report.stopped_by, Some((1, MapReduceStopCause::Cancelled)));
        assert!(matches!(report.outcome, Outcome::Cancelled(reason) if reason == stronger));
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (3, 3, 2)
        );
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_completed_prefix_folds_in_bounded_cooperative_bursts() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0107).max_steps(8192));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let gate = Arc::new(crate::sync::Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let finished = Arc::new(AtomicUsize::new(0));
        let reductions = Arc::new(AtomicUsize::new(0));
        let child_gate = Arc::clone(&gate);
        let child_finished = Arc::clone(&finished);
        let reducer_calls = Arc::clone(&reductions);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(192, 193),
                        0..192,
                        move |child, value| {
                            let gate = Arc::clone(&child_gate);
                            let finished = Arc::clone(&child_finished);
                            async move {
                                if value == 0 {
                                    drop(
                                        crate::sync::OwnedMutexGuard::lock(gate, &child)
                                            .await
                                            .unwrap(),
                                    );
                                }
                                finished.fetch_add(1, Ordering::SeqCst);
                                Outcome::<_, ()>::Ok(value)
                            }
                        },
                        move |left, right| {
                            reducer_calls.fetch_add(1, Ordering::SeqCst);
                            left - right
                        },
                    )
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert_eq!(finished.load(Ordering::SeqCst), 191);
        assert_eq!(reductions.load(Ordering::SeqCst), 0);
        assert_eq!(gate.waiters(), 1);
        drop(held);
        for _ in 0..1024 {
            lab.step_for_test();
            if reductions.load(Ordering::SeqCst) != 0 {
                break;
            }
        }
        assert_eq!(
            reductions.load(Ordering::SeqCst),
            63,
            "first fold consumes 64 values and yields with 128 still retained"
        );
        assert!(
            join.try_join().unwrap().is_none(),
            "all children being complete cannot publish an unfinished fold"
        );
        let observer_reductions = Arc::clone(&reductions);
        let (observer, mut observed) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                observer_reductions.load(Ordering::SeqCst)
            })
            .unwrap();
        lab.scheduler.lock().schedule(observer, 255);
        lab.run_until_idle();
        let seen = observed.try_join().unwrap().unwrap();
        assert!(
            (63..191).contains(&seen),
            "another task progresses before the entire buffered fold: {seen}"
        );
        let report = join.try_join().unwrap().unwrap();
        assert_eq!(report.outcome.unwrap(), Some(-(1..192).sum::<i32>()));
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (192, 192, 192)
        );
        assert_eq!(report.max_retained, 192);
        assert_eq!(reductions.load(Ordering::SeqCst), 191);
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_failure_waits_for_real_pending_cleanup_and_preserves_cause() {
        for mode in ["error", "cancel", "panic", "encoded_panic"] {
            let mut lab = LabRuntime::new(LabConfig::new(0x32_0102).max_steps(4096));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let trigger = Arc::new(crate::sync::Mutex::new(()));
            let held_trigger = trigger.try_lock_owned().unwrap();
            let (keep_sender, receiver) = crate::channel::mpsc::channel::<()>(1);
            let receiver = Arc::new(parking_lot::Mutex::new(Some(receiver)));
            let (finish_cleanup, cleanup) = crate::channel::oneshot::channel::<()>();
            let cleanup = Arc::new(parking_lot::Mutex::new(Some(cleanup)));
            let cleanup_started = Arc::new(AtomicUsize::new(0));
            let cleanup_finished = Arc::new(AtomicUsize::new(0));
            let started = Arc::clone(&cleanup_started);
            let finished = Arc::clone(&cleanup_finished);
            let child_trigger = Arc::clone(&trigger);
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    cx.scope()
                        .map_reduce(
                            &cx,
                            executing_limits(2, 2),
                            0..100,
                            move |child, index| {
                                let trigger = Arc::clone(&child_trigger);
                                let receiver = Arc::clone(&receiver);
                                let cleanup = Arc::clone(&cleanup);
                                let started = Arc::clone(&started);
                                let finished = Arc::clone(&finished);
                                async move {
                                    if index == 0 {
                                        drop(
                                            crate::sync::OwnedMutexGuard::lock(trigger, &child)
                                                .await
                                                .unwrap(),
                                        );
                                        match mode {
                                            "error" => Outcome::Err("triggering map failure"),
                                            "cancel" => Outcome::Cancelled(CancelReason::timeout()),
                                            "panic" => panic!("actual mapper panic"),
                                            "encoded_panic" => Outcome::Panicked(
                                                PanicPayload::new("encoded mapper panic"),
                                            ),
                                            _ => unreachable!(),
                                        }
                                    } else {
                                        assert_eq!(
                                            index, 1,
                                            "admission stops at the bounded failure window"
                                        );
                                        let mut receiver = receiver.lock().take().unwrap();
                                        assert_eq!(
                                            receiver.recv(&child).await,
                                            Err(crate::channel::mpsc::RecvError::Cancelled)
                                        );
                                        started.fetch_add(1, Ordering::SeqCst);
                                        let mut cleanup = cleanup.lock().take().unwrap();
                                        cleanup.recv_uninterruptible().await.unwrap();
                                        finished.fetch_add(1, Ordering::SeqCst);
                                        Outcome::Ok(index)
                                    }
                                }
                            },
                            |left, right| left + right,
                        )
                        .await
                })
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            assert_eq!(trigger.waiters(), 1);
            assert_eq!(keep_sender.telemetry_snapshot(3202).recv_waiter_count, 1);
            drop(held_trigger);
            lab.run_until_idle();
            assert!(
                join.try_join().unwrap().is_none(),
                "cleanup Pending is not a terminal child"
            );
            assert_eq!(cleanup_started.load(Ordering::SeqCst), 1);
            assert_eq!(cleanup_finished.load(Ordering::SeqCst), 0);
            assert_eq!(keep_sender.telemetry_snapshot(3202).recv_waiter_count, 0);
            finish_cleanup.send_blocking(()).unwrap();
            lab.run_until_idle();
            let report = join.try_join().unwrap().unwrap();
            assert_eq!(report.admitted, 2);
            assert_eq!(report.completed, 2);
            assert_eq!(report.reduced, 0);
            assert_eq!(cleanup_finished.load(Ordering::SeqCst), 1);
            assert_eq!(report.stopped_by.as_ref().unwrap().0, 0);
            if mode == "error" {
                assert!(matches!(
                    report.outcome,
                    Outcome::Err(MapReduceExecutionError::Map("triggering map failure"))
                ));
                assert_eq!(report.failure_index, Some(0));
                assert!(report.errors.is_empty());
            } else if mode == "cancel" {
                assert!(matches!(
                    report.outcome,
                    Outcome::Cancelled(reason) if reason == CancelReason::timeout()
                ));
                assert_eq!(report.failure_index, Some(0));
            } else {
                assert!(report.outcome.is_panicked());
                assert_eq!(report.failure_index, Some(0));
            }
            assert_executing_lab_clean(&mut lab, root);
            eprintln!(
                "map failure mode={mode} admitted=2 joined=2 cleanup_started=1 cleanup_finished=1"
            );
        }
    }

    /// Review r33-e8 of 9476ea562, end to end on the lab runtime: a sibling
    /// at a LOWER input index that maps the engine's drain cancellation to
    /// `Err` keeps that error as a diagnostic and does not replace the failure
    /// that started the drain. Before 9476ea562 the lowest-index error, the
    /// drained sibling's, was selected.
    #[test]
    fn executing_map_drained_lower_index_error_does_not_replace_the_trigger() {
        let mut lab = LabRuntime::new(LabConfig::new(0x33_00e8).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let trigger = Arc::new(crate::sync::Mutex::new(()));
        let held_trigger = trigger.try_lock_owned().unwrap();
        let (keep_sender, receiver) = crate::channel::mpsc::channel::<()>(1);
        let receiver = Arc::new(parking_lot::Mutex::new(Some(receiver)));
        let child_trigger = Arc::clone(&trigger);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(2, 2),
                        0..100,
                        move |child, index| {
                            let trigger = Arc::clone(&child_trigger);
                            let receiver = Arc::clone(&receiver);
                            async move {
                                if index == 0 {
                                    // Parked until the engine drains it, then
                                    // reports its cancellation as an error.
                                    let mut receiver = receiver.lock().take().unwrap();
                                    match receiver.recv(&child).await {
                                        Err(crate::channel::mpsc::RecvError::Cancelled) => {
                                            Outcome::<usize, &str>::Err("drained receive")
                                        }
                                        other => panic!("the parked sibling is drained: {other:?}"),
                                    }
                                } else {
                                    assert_eq!(
                                        index, 1,
                                        "admission stops at the bounded failure window"
                                    );
                                    drop(
                                        crate::sync::OwnedMutexGuard::lock(trigger, &child)
                                            .await
                                            .unwrap(),
                                    );
                                    Outcome::Err("triggering map failure")
                                }
                            }
                        },
                        |left, right| left + right,
                    )
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        // Witness: index 0 is parked on its receive, index 1 on the trigger.
        assert_eq!(trigger.waiters(), 1);
        assert_eq!(keep_sender.telemetry_snapshot(3301).recv_waiter_count, 1);
        drop(held_trigger);
        lab.run_until_idle();
        let report = join.try_join().unwrap().unwrap();
        assert_eq!(report.admitted, 2);
        assert_eq!(report.completed, 2);
        assert_eq!(report.stopped_by.as_ref().unwrap().0, 1);
        assert!(matches!(
            report.outcome,
            Outcome::Err(MapReduceExecutionError::Map("triggering map failure"))
        ));
        assert_eq!(report.failure_index, Some(1));
        assert!(matches!(
            report.errors.as_slice(),
            [(0, MapReduceExecutionError::Map("drained receive"))]
        ));
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_iteration_factory_and_reducer_panics_stop_admission() {
        for mode in ["iterator", "factory", "reducer"] {
            let report = run_executing_case(move |cx| async move {
                let mut next = 0;
                let input = std::iter::from_fn(move || {
                    if mode == "iterator" && next == 2 {
                        panic!("actual input iterator panic");
                    }
                    if next == 8 {
                        return None;
                    }
                    let index = next;
                    next += 1;
                    Some(index)
                });
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(1, 1),
                        input,
                        move |_child, index| {
                            if mode == "factory" {
                                panic!("actual factory construction panic");
                            }
                            async move { Outcome::<_, ()>::Ok(index) }
                        },
                        move |left, right| {
                            if mode == "reducer" {
                                panic!("actual reducer panic");
                            }
                            left - right
                        },
                    )
                    .await
            });
            assert!(report.outcome.is_panicked());
            assert_eq!(report.completed, report.admitted);
            assert_eq!(report.admitted, if mode == "factory" { 1 } else { 2 });
            assert_eq!(
                report.stopped_by.unwrap().1,
                match mode {
                    "iterator" => MapReduceStopCause::InputPanicked,
                    "factory" => MapReduceStopCause::MapPanicked,
                    "reducer" => MapReduceStopCause::ReducerPanicked,
                    _ => unreachable!(),
                }
            );
        }
    }

    #[test]
    fn executing_map_caller_cancel_wakes_coordinator_and_keeps_noncooperative_child_owned() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0103).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (release, gate) = crate::channel::oneshot::channel::<()>();
        let gate = Arc::new(parking_lot::Mutex::new(Some(gate)));
        let started = Arc::new(AtomicUsize::new(0));
        let child_started = Arc::clone(&started);
        let returned = Arc::new(parking_lot::Mutex::new(None));
        let publication = Arc::clone(&returned);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let report = cx
                    .scope()
                    .map_reduce(
                        &cx,
                        executing_limits(1, 1),
                        0..10,
                        move |_child, index| {
                            let gate = Arc::clone(&gate);
                            let started = Arc::clone(&child_started);
                            async move {
                                started.fetch_add(1, Ordering::SeqCst);
                                let mut gate = gate.lock().take().unwrap();
                                gate.recv_uninterruptible().await.unwrap();
                                Outcome::<_, ()>::Ok(index)
                            }
                        },
                        |left, right| left + right,
                    )
                    .await;
                *publication.lock() = Some(report);
            })
            .unwrap();
        let parent_cx = lab.state.task(parent).unwrap().cx.clone().unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert_eq!(started.load(Ordering::SeqCst), 1);
        let child = lab
            .state
            .region(root)
            .unwrap()
            .task_ids()
            .into_iter()
            .find(|id| *id != parent)
            .unwrap();
        let child_cx = lab.state.task(child).unwrap().cx.clone().unwrap();
        parent_cx.cancel_with(
            crate::types::CancelKind::User,
            Some("cancel map coordinator"),
        );
        lab.run_until_idle();
        assert!(join.try_join().unwrap().is_none());
        assert!(
            child_cx.is_cancel_requested(),
            "owned cancellation waker repolls coordinator to abort its child"
        );
        assert!(lab.state.task(child).is_some());
        assert_eq!(lab.state.live_task_count(), 2);
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert!(
            lab.steps() < 4096,
            "parked cleanup must not exhaust the step bound"
        );
        assert!(
            lab.scheduler.lock().is_empty(),
            "cancellation is acknowledged once, then the coordinator parks"
        );
        assert_eq!(
            lab.run_until_idle(),
            0,
            "no input or child wake means no draining polls"
        );
        assert!(
            returned.lock().is_none(),
            "no report before the actual child terminal"
        );
        release.send_blocking(()).unwrap();
        lab.run_until_idle();
        assert_eq!(
            join.try_join(),
            Err(JoinError::Cancelled(parent_cx.cancel_reason().unwrap()))
        );
        let report = returned
            .lock()
            .take()
            .expect("actual map engine report after child join");
        assert!(report.outcome.is_cancelled());
        assert_eq!(report.admitted, 1);
        assert_eq!(report.completed, 1);
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_drop_requests_abort_without_claiming_child_completion() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0104).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (release, gate) = crate::channel::oneshot::channel::<()>();
        let gate = Arc::new(parking_lot::Mutex::new(Some(gate)));
        let started = Arc::new(AtomicUsize::new(0));
        let child_started = Arc::clone(&started);
        let (notify_started, mut receive_started) = crate::channel::oneshot::channel::<()>();
        let notify_started = Arc::new(parking_lot::Mutex::new(Some(notify_started)));
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let mut execution = Box::pin(scope.map_reduce(
                    &cx,
                    executing_limits(1, 1),
                    [7],
                    move |_child, value| {
                        let gate = Arc::clone(&gate);
                        let started = Arc::clone(&child_started);
                        let notify_started = Arc::clone(&notify_started);
                        async move {
                            started.fetch_add(1, Ordering::SeqCst);
                            notify_started
                                .lock()
                                .take()
                                .unwrap()
                                .send_blocking(())
                                .unwrap();
                            let mut gate = gate.lock().take().unwrap();
                            gate.recv_uninterruptible().await.unwrap();
                            Outcome::<_, ()>::Ok(value)
                        }
                    },
                    |left, right| left + right,
                ));
                std::future::poll_fn(|poll_cx| {
                    assert!(execution.as_mut().poll(poll_cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                receive_started.recv_uninterruptible().await.unwrap();
                drop(execution);
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert_eq!(join.try_join().unwrap(), Some(()));
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(
            lab.state.live_task_count(),
            1,
            "dropped owner did not fabricate a drain"
        );
        let child = lab.state.region(root).unwrap().task_ids()[0];
        assert!(
            lab.state
                .task(child)
                .unwrap()
                .cx
                .as_ref()
                .unwrap()
                .is_cancel_requested()
        );
        release.send_blocking(()).unwrap();
        lab.run_until_idle();
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_late_lower_index_encoded_panic_outranks_drain_cancellation() {
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0105).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (release, gate) = crate::channel::oneshot::channel::<()>();
        let gate = Arc::new(parking_lot::Mutex::new(Some(gate)));
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .map_reduce(
                        &cx,
                        executing_limits(2, 2),
                        0..10,
                        move |_child, index| {
                            let gate = Arc::clone(&gate);
                            async move {
                                if index == 0 {
                                    let mut gate = gate.lock().take().unwrap();
                                    gate.recv_uninterruptible().await.unwrap();
                                }
                                Outcome::<usize, ()>::Panicked(PanicPayload::new(format!(
                                    "panic at {index}"
                                )))
                            }
                        },
                        |left, right| left + right,
                    )
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert!(join.try_join().unwrap().is_none());
        release.send_blocking(()).unwrap();
        lab.run_until_idle();
        let report = join.try_join().unwrap().unwrap();
        assert_eq!(
            report.stopped_by,
            Some((1, MapReduceStopCause::MapPanicked))
        );
        assert_eq!(report.failure_index, Some(0));
        let Outcome::Panicked(payload) = report.outcome else {
            panic!("encoded panic must survive cancellation-dominant generic spawn")
        };
        assert_eq!(payload.message(), "panic at 0");
        assert_eq!(report.admitted, 2);
        assert_eq!(report.completed, 2);
        assert_executing_lab_clean(&mut lab, root);
    }

    #[test]
    fn executing_map_result_destructor_panics_preserve_pending_cleanup_and_drop_abort() {
        #[derive(Debug)]
        struct ResultDrop {
            panics: bool,
            dropped: Arc<AtomicUsize>,
        }

        impl Drop for ResultDrop {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::SeqCst);
                assert!(!self.panics, "actual discarded map result panic");
            }
        }

        for (buffered, drop_execution) in [(false, false), (true, false), (true, true)] {
            let mut lab = LabRuntime::new(LabConfig::new(0x32_0108).max_steps(8192));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let count = if buffered { 3 } else { 2 };
            let mut senders = Vec::new();
            let mut receivers = Vec::new();
            for _ in 0..count {
                let (sender, receiver) = crate::channel::mpsc::channel::<()>(1);
                senders.push(sender);
                receivers.push(parking_lot::Mutex::new(Some(receiver)));
            }
            let receivers = Arc::new(receivers);
            let (finish_cleanup, cleanup) = crate::channel::oneshot::channel::<()>();
            let cleanup = Arc::new(parking_lot::Mutex::new(Some(cleanup)));
            let (request_drop, mut drop_requested) = crate::channel::oneshot::channel::<()>();
            let ready_values = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let cleanup_started = Arc::new(AtomicUsize::new(0));
            let cleanup_finished = Arc::new(AtomicUsize::new(0));
            let child_ready = Arc::clone(&ready_values);
            let child_dropped = Arc::clone(&dropped);
            let child_started = Arc::clone(&cleanup_started);
            let child_finished = Arc::clone(&cleanup_finished);
            let returned = Arc::new(parking_lot::Mutex::new(None));
            let publication = Arc::clone(&returned);
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let scope = cx.scope();
                    let mut execution = Box::pin(scope.map_reduce(
                        &cx,
                        executing_limits(count, count),
                        0..count,
                        move |child, index| {
                            let receivers = Arc::clone(&receivers);
                            let cleanup = Arc::clone(&cleanup);
                            let ready = Arc::clone(&child_ready);
                            let dropped = Arc::clone(&child_dropped);
                            let started = Arc::clone(&child_started);
                            let finished = Arc::clone(&child_finished);
                            async move {
                                if buffered && index != 0 {
                                    ready.fetch_add(1, Ordering::SeqCst);
                                    return Outcome::<_, ()>::Ok(ResultDrop {
                                        panics: true,
                                        dropped,
                                    });
                                }
                                let mut receiver = receivers[index].lock().take().unwrap();
                                assert_eq!(
                                    receiver.recv(&child).await,
                                    Err(crate::channel::mpsc::RecvError::Cancelled)
                                );
                                if buffered || index == 1 {
                                    started.fetch_add(1, Ordering::SeqCst);
                                    let mut cleanup = cleanup.lock().take().unwrap();
                                    cleanup.recv_uninterruptible().await.unwrap();
                                    finished.fetch_add(1, Ordering::SeqCst);
                                }
                                Outcome::Ok(ResultDrop {
                                    panics: !buffered && index == 0,
                                    dropped,
                                })
                            }
                        },
                        |_left, _right| -> ResultDrop {
                            panic!("a held first input prevents any reduction")
                        },
                    ));
                    let report = if drop_execution {
                        let mut requested = std::pin::pin!(drop_requested.recv_uninterruptible());
                        std::future::poll_fn(|poll_cx| {
                            if let Poll::Ready(result) = requested.as_mut().poll(poll_cx) {
                                result.unwrap();
                                return Poll::Ready(());
                            }
                            assert!(execution.as_mut().poll(poll_cx).is_pending());
                            Poll::Pending
                        })
                        .await;
                        drop(execution);
                        None
                    } else {
                        Some(execution.await)
                    };
                    *publication.lock() = Some(report);
                })
                .unwrap();
            let parent_cx = lab.state.task(parent).unwrap().cx.clone().unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            assert_eq!(
                ready_values.load(Ordering::SeqCst),
                if buffered { 2 } else { 0 }
            );
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            assert_eq!(senders[0].telemetry_snapshot(3208).recv_waiter_count, 1);
            if !buffered {
                assert_eq!(senders[1].telemetry_snapshot(3208).recv_waiter_count, 1);
            }
            if drop_execution {
                request_drop.send_blocking(()).unwrap();
            } else {
                parent_cx.cancel_with(crate::types::CancelKind::User, Some("retire map results"));
            }
            lab.run_until_idle();
            assert_eq!(dropped.load(Ordering::SeqCst), if buffered { 2 } else { 1 });
            assert_eq!(cleanup_started.load(Ordering::SeqCst), 1);
            assert_eq!(cleanup_finished.load(Ordering::SeqCst), 0);
            assert!(
                lab.steps() < 8192,
                "cleanup Pending must park before the step bound"
            );
            assert!(
                lab.scheduler.lock().is_empty(),
                "all held cleanup tasks really parked"
            );
            assert_eq!(lab.run_until_idle(), 0);
            if drop_execution {
                assert_eq!(join.try_join(), Ok(Some(())));
                assert!(matches!(returned.lock().take(), Some(None)));
                assert_eq!(
                    lab.state.live_task_count(),
                    1,
                    "result destructor panics cannot skip the remaining child's abort"
                );
            } else {
                assert!(
                    join.try_join().unwrap().is_none(),
                    "Panicked is not permission to abandon asynchronous cleanup"
                );
                assert!(returned.lock().is_none());
            }
            finish_cleanup.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert_eq!(cleanup_finished.load(Ordering::SeqCst), 1);
            assert_eq!(dropped.load(Ordering::SeqCst), count);
            if !drop_execution {
                assert_eq!(
                    join.try_join(),
                    Err(JoinError::Cancelled(parent_cx.cancel_reason().unwrap()))
                );
                let report = returned
                    .lock()
                    .take()
                    .expect("actual engine return")
                    .unwrap();
                let Outcome::Panicked(payload) = report.outcome else {
                    panic!("actual result destructor panic must dominate cancellation")
                };
                assert_eq!(payload.message(), "actual discarded map result panic");
                assert_eq!(
                    (report.admitted, report.completed, report.reduced),
                    (count, count, 0)
                );
            }
            assert_executing_lab_clean(&mut lab, root);
            eprintln!(
                "map destructor buffered={buffered} drop_execution={drop_execution} values_dropped={count} cleanup_completed=1"
            );
        }
    }

    #[test]
    fn executing_map_simultaneous_cancelled_results_retire_in_bounded_join_sweeps() {
        struct CountDrop(Arc<AtomicUsize>);
        impl Drop for CountDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let count = 192;
        let mut lab = LabRuntime::new(LabConfig::new(0x32_0109).max_steps(16384));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..count {
            let (sender, receiver) = crate::channel::mpsc::channel::<()>(1);
            senders.push(sender);
            receivers.push(parking_lot::Mutex::new(Some(receiver)));
        }
        let receivers = Arc::new(receivers);
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (all_started, mut receive_started) = crate::channel::oneshot::channel::<()>();
        let all_started = Arc::new(parking_lot::Mutex::new(Some(all_started)));
        let (resume, mut receive_resume) = crate::channel::oneshot::channel::<()>();
        let child_started = Arc::clone(&started);
        let child_dropped = Arc::clone(&dropped);
        let probe_dropped = Arc::clone(&dropped);
        let (parent, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let mut execution = Box::pin(scope.map_reduce(
                    &cx,
                    executing_limits(count, count),
                    0..count,
                    move |child, index| {
                        let receivers = Arc::clone(&receivers);
                        let started = Arc::clone(&child_started);
                        let all_started = Arc::clone(&all_started);
                        let dropped = Arc::clone(&child_dropped);
                        async move {
                            if started.fetch_add(1, Ordering::SeqCst) + 1 == count {
                                all_started
                                    .lock()
                                    .take()
                                    .unwrap()
                                    .send_blocking(())
                                    .unwrap();
                            }
                            let mut receiver = receivers[index].lock().take().unwrap();
                            assert_eq!(
                                receiver.recv(&child).await,
                                Err(crate::channel::mpsc::RecvError::Cancelled)
                            );
                            Outcome::<_, ()>::Ok(CountDrop(dropped))
                        }
                    },
                    |_left, _right| -> CountDrop { panic!("cancelled values cannot be reduced") },
                ));
                let mut ready = std::pin::pin!(receive_started.recv_uninterruptible());
                std::future::poll_fn(|poll_cx| {
                    assert!(execution.as_mut().poll(poll_cx).is_pending());
                    ready.as_mut().poll(poll_cx)
                })
                .await
                .unwrap();
                // Keep every real result cell owned but stop polling the engine
                // until the host has observed all actual children terminate.
                receive_resume.recv_uninterruptible().await.unwrap();
                assert_eq!(probe_dropped.load(Ordering::SeqCst), 0);
                std::future::poll_fn(|poll_cx| {
                    assert!(execution.as_mut().poll(poll_cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert_eq!(
                    probe_dropped.load(Ordering::SeqCst),
                    64,
                    "one engine poll retires only one bounded terminal sweep"
                );
                execution.await
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert_eq!(started.load(Ordering::SeqCst), count);
        assert!(
            senders
                .iter()
                .all(|sender| sender.telemetry_snapshot(3209).recv_waiter_count == 1)
        );
        let children: Vec<_> = lab
            .state
            .region(root)
            .unwrap()
            .task_ids()
            .into_iter()
            .filter(|id| *id != parent)
            .map(|id| lab.state.task(id).unwrap().cx.clone().unwrap())
            .collect();
        assert_eq!(children.len(), count);
        for child in &children {
            child.cancel_with(
                crate::types::CancelKind::User,
                Some("simultaneous result retirement"),
            );
        }
        lab.run_until_idle();
        assert_eq!(
            lab.state.live_task_count(),
            1,
            "every actual child has terminated before the bounded poll"
        );
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            0,
            "all terminal values are still owned by the parked engine"
        );
        assert!(join.try_join().unwrap().is_none());
        resume.send_blocking(()).unwrap();
        lab.run_until_idle();
        let report = join.try_join().unwrap().unwrap();
        assert!(report.outcome.is_cancelled());
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (count, count, 0)
        );
        assert_eq!(dropped.load(Ordering::SeqCst), count);
        assert!(
            senders
                .iter()
                .all(|sender| sender.telemetry_snapshot(3209).recv_waiter_count == 0)
        );
        assert_executing_lab_clean(&mut lab, root);
    }

    // ========== MapReduce marker type tests ==========

    #[test]
    fn map_reduce_marker_type() {
        let _mr: MapReduce<i32> = MapReduce::new();
        let _mr_default: MapReduce<String> = MapReduce::default();

        // Test Clone and Copy
        let m1: MapReduce<i32> = MapReduce::new();
        let m2 = m1;
        let m3 = m1;
        assert!(std::mem::size_of_val(&m1) == std::mem::size_of_val(&m2));
        assert!(std::mem::size_of_val(&m1) == std::mem::size_of_val(&m3));
    }

    // ========== MapReduceResult tests ==========

    #[test]
    fn map_reduce_result_all_succeeded() {
        let result: MapReduceResult<i32, &str> = MapReduceResult::new(
            AggregateDecision::AllOk,
            Some(6),
            vec![(0, 1), (1, 2), (2, 3)],
            3,
        );
        assert!(result.all_succeeded());
        assert_eq!(result.success_count(), 3);
        assert_eq!(result.failure_count(), 0);
        assert!(result.has_reduced());
    }

    #[test]
    fn map_reduce_result_partial_failure() {
        let result: MapReduceResult<i32, &str> = MapReduceResult::new(
            AggregateDecision::FirstError("oops"),
            Some(4), // Partial reduction of successes
            vec![(0, 1), (2, 3)],
            3,
        );
        assert!(!result.all_succeeded());
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.failure_count(), 1);
        assert!(result.has_reduced());
    }

    // ========== MapReduceError tests ==========

    #[test]
    fn map_reduce_error_predicates() {
        let err: MapReduceError<&str> = MapReduceError::Error {
            error: "test",
            index: 2,
            total_failures: 1,
            success_count: 2,
        };
        assert!(err.is_error());
        assert!(!err.is_cancelled());
        assert!(!err.is_panicked());
        assert!(!err.is_empty());
        assert_eq!(err.error_index(), Some(2));

        let err: MapReduceError<&str> = MapReduceError::Cancelled(CancelReason::timeout());
        assert!(!err.is_error());
        assert!(err.is_cancelled());
        assert_eq!(err.error_index(), None);

        let err: MapReduceError<&str> = MapReduceError::Panicked {
            payload: PanicPayload::new("boom"),
            index: 3,
        };
        assert!(!err.is_error());
        assert!(err.is_panicked());
        assert_eq!(err.panic_index(), Some(3));

        let err: MapReduceError<&str> = MapReduceError::Empty;
        assert!(err.is_empty());
    }

    #[test]
    fn map_reduce_error_display() {
        let err: MapReduceError<&str> = MapReduceError::Error {
            error: "test error",
            index: 3,
            total_failures: 2,
            success_count: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("task 3"));
        assert!(msg.contains("test error"));
        assert!(msg.contains("2 failures"));
        assert!(msg.contains("5 successes"));

        let err: MapReduceError<&str> = MapReduceError::Panicked {
            payload: PanicPayload::new("boom"),
            index: 1,
        };
        assert!(err.to_string().contains("task 1 panicked"));
        assert!(err.to_string().contains("boom"));

        let err: MapReduceError<&str> = MapReduceError::Empty;
        assert!(err.to_string().contains("at least one input"));
    }

    // ========== map_reduce_outcomes tests ==========

    #[test]
    fn map_reduce_outcomes_all_ok_sum() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];

        let (decision, reduced, successes) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::AllOk));
        assert_eq!(reduced, Some(6)); // 1 + 2 + 3
        assert_eq!(successes.len(), 3);
    }

    #[test]
    fn map_reduce_outcomes_all_ok_product() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(2), Outcome::Ok(3), Outcome::Ok(4)];

        let (decision, reduced, _) = map_reduce_outcomes(outcomes, |a, b| a * b);

        assert!(matches!(decision, AggregateDecision::AllOk));
        assert_eq!(reduced, Some(24)); // 2 * 3 * 4
    }

    #[test]
    fn map_reduce_outcomes_partial_failure() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("failed"), Outcome::Ok(3)];

        let (decision, reduced, successes) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::FirstError("failed")));
        assert_eq!(reduced, Some(4)); // 1 + 3 (partial reduction)
        assert_eq!(successes.len(), 2);
    }

    #[test]
    fn map_reduce_outcomes_cancelled() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Ok(3),
        ];

        let (decision, reduced, _) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::Cancelled(_)));
        assert_eq!(reduced, Some(4)); // Partial reduction still works
    }

    #[test]
    fn map_reduce_outcomes_panicked() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Ok(3),
        ];

        let (decision, reduced, successes) = map_reduce_outcomes(outcomes, |a, b| a + b);

        match decision {
            AggregateDecision::Panicked {
                payload: _,
                first_panic_index,
            } => assert_eq!(first_panic_index, 1),
            _ => panic!("Expected Panicked decision"),
        }
        // All successful values collected and reduced (join semantics: all branches complete)
        assert_eq!(successes.len(), 2);
        assert_eq!(reduced, Some(4)); // 1 + 3 = 4
    }

    #[test]
    fn map_reduce_outcomes_preserves_input_order() {
        // Values should be reduced in input order regardless of completion order
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(10), Outcome::Ok(100)];

        // Using subtraction to verify order matters
        let (_, reduced, _) = map_reduce_outcomes(outcomes, |a, b| a - b);

        // Left fold: ((1 - 10) - 100) = -109
        assert_eq!(reduced, Some(-109));
    }

    #[test]
    fn map_reduce_outcomes_single_value() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(42)];

        let (decision, reduced, successes) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::AllOk));
        assert_eq!(reduced, Some(42)); // Single value returned as-is
        assert_eq!(successes.len(), 1);
    }

    #[test]
    fn map_reduce_outcomes_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];

        let (decision, reduced, successes) = map_reduce_outcomes(outcomes, |a, b| a + b);

        assert!(matches!(decision, AggregateDecision::AllOk));
        assert_eq!(reduced, None); // No values to reduce
        assert!(successes.is_empty());
    }

    #[test]
    fn map_reduce_result_empty_not_all_succeeded() {
        // Empty input should NOT report all_succeeded() = true,
        // even though the decision is vacuously AllOk.
        // This prevents callers from doing result.reduced.unwrap() after
        // checking all_succeeded(), which would panic on empty input.
        let result: MapReduceResult<i32, &str> =
            MapReduceResult::new(AggregateDecision::AllOk, None, vec![], 0);
        assert!(!result.all_succeeded());
        assert!(!result.has_reduced());
    }

    // ========== make_map_reduce_result tests ==========

    #[test]
    fn make_map_reduce_result_success() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];

        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        assert!(result.all_succeeded());
        assert_eq!(result.reduced, Some(6));
        assert_eq!(result.total_count, 3);
    }

    // ========== map_reduce_to_result tests ==========

    #[test]
    fn map_reduce_to_result_all_ok() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let value = map_reduce_to_result(result);
        assert_eq!(value.unwrap(), 6);
    }

    #[test]
    fn map_reduce_to_result_error() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("failed"), Outcome::Ok(3)];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let value = map_reduce_to_result(result);
        match value {
            Err(MapReduceError::Error {
                error,
                index,
                total_failures,
                success_count,
            }) => {
                assert_eq!(error, "failed");
                assert_eq!(index, 1);
                assert_eq!(total_failures, 1);
                assert_eq!(success_count, 2);
            }
            _ => panic!("expected MapReduceError::Error"),
        }
    }

    #[test]
    fn map_reduce_to_result_cancelled() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Cancelled(CancelReason::timeout())];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let value = map_reduce_to_result(result);
        assert!(matches!(value, Err(MapReduceError::Cancelled(_))));
    }

    #[test]
    fn map_reduce_to_result_panicked() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Panicked(PanicPayload::new("crash"))];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let value = map_reduce_to_result(result);
        match value {
            Err(MapReduceError::Panicked { payload: _, index }) => assert_eq!(index, 0),
            _ => panic!("Expected Panicked error"),
        }
    }

    #[test]
    fn map_reduce_to_result_empty() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let value = map_reduce_to_result(result);
        assert!(matches!(value, Err(MapReduceError::Empty)));
    }

    // ========== reduce_successes tests ==========

    #[test]
    fn reduce_successes_partial() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Err("failed"), Outcome::Ok(3)];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let partial = reduce_successes(&result);
        assert_eq!(partial, Some(4)); // 1 + 3
    }

    #[test]
    fn reduce_successes_none_succeeded() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Err("failed1"), Outcome::Err("failed2")];
        let result = make_map_reduce_result(outcomes, |a, b| a + b);

        let partial = reduce_successes(&result);
        assert_eq!(partial, None);
    }

    // ========== String concatenation tests (non-numeric) ==========

    #[test]
    fn map_reduce_string_concat() {
        let outcomes: Vec<Outcome<String, &str>> = vec![
            Outcome::Ok("Hello".to_string()),
            Outcome::Ok(" ".to_string()),
            Outcome::Ok("World".to_string()),
        ];

        let result = make_map_reduce_result(outcomes, |a, b| a + &b);
        assert_eq!(result.reduced, Some("Hello World".to_string()));
    }

    // ========== Associativity documentation test ==========

    #[test]
    fn map_reduce_associative_vs_non_associative() {
        // Demonstrate that associative operations give consistent results
        let outcomes_a: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let outcomes_b = outcomes_a.clone();

        // Addition is associative
        let sum_result = make_map_reduce_result(outcomes_a, |a, b| a + b);
        assert_eq!(sum_result.reduced, Some(6)); // Always 6

        // Subtraction is NOT associative - order matters
        let difference_result = make_map_reduce_result(outcomes_b, |a, b| a - b);
        // Left fold: ((1 - 2) - 3) = -4
        assert_eq!(difference_result.reduced, Some(-4));
        // Note: If we did right fold it would be different: (1 - (2 - 3)) = 2
        // Our implementation always does left fold for determinism
    }

    #[test]
    fn metamorphic_commutative_reducer_is_permutation_invariant() {
        let outcomes_a: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(3),
            Outcome::Ok(1),
            Outcome::Ok(4),
            Outcome::Ok(2),
        ];
        let outcomes_b: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(2),
            Outcome::Ok(4),
            Outcome::Ok(1),
            Outcome::Ok(3),
        ];

        let (decision_a, reduced_a, successes_a) = map_reduce_outcomes(outcomes_a, |a, b| a + b);
        let (decision_b, reduced_b, successes_b) = map_reduce_outcomes(outcomes_b, |a, b| a + b);

        assert!(matches!(decision_a, AggregateDecision::AllOk));
        assert!(matches!(decision_b, AggregateDecision::AllOk));
        assert_eq!(
            reduced_a, reduced_b,
            "commutative reduction should be invariant under permutation of successful inputs"
        );
        assert_eq!(reduced_a, Some(10));
        assert_eq!(successes_a.len(), successes_b.len());
        assert_eq!(successes_a.len(), 4);
        assert_ne!(
            successes_a, successes_b,
            "permuted inputs should still preserve their own input-order success traces"
        );
    }

    // --- wave 79 trait coverage ---

    #[test]
    fn map_reduce_error_debug_clone() {
        let e: MapReduceError<&str> = MapReduceError::Error {
            error: "bad",
            index: 2,
            total_failures: 1,
            success_count: 3,
        };
        let e2 = e.clone();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Error"));
        let dbg2 = format!("{e2:?}");
        assert!(dbg2.contains("Error"));

        let empty: MapReduceError<&str> = MapReduceError::Empty;
        let empty2 = empty.clone();
        let dbg3 = format!("{empty:?}");
        assert!(dbg3.contains("Empty"));
        let dbg4 = format!("{empty2:?}");
        assert!(dbg4.contains("Empty"));
    }

    fn empty_executing_failures<E>() -> ExecutingMapFailures<E> {
        ExecutingMapFailures {
            stopped_by: None,
            errors: Vec::new(),
            primary_error_index: None,
            cancelled: None,
            panicked: None,
        }
    }

    #[test]
    fn executing_map_drain_error_is_retained_without_replacing_the_trigger() {
        let drain = CancelReason::race_loser().with_message("map-reduce sibling drain");
        let mut failures = empty_executing_failures();
        failures.error(1, MapReduceExecutionError::Map("trigger"));
        failures.map_error(
            0,
            "cancelled receive",
            &Err(JoinError::Cancelled(drain.clone())),
            Some(&drain),
        );
        failures.errors.sort_by_key(|(index, _)| *index);
        assert!(matches!(
            failures.take_primary_error(),
            Some((1, MapReduceExecutionError::Map("trigger")))
        ));
        assert_eq!(failures.stopped_by, Some((1, MapReduceStopCause::Error)));
        assert!(matches!(
            failures.errors.as_slice(),
            [(0, MapReduceExecutionError::Map("cancelled receive"))]
        ));
        assert!(failures.take_primary_error().is_none());
    }

    #[test]
    fn executing_map_drain_error_requires_the_exact_runtime_terminal() {
        let drain = CancelReason::race_loser().with_message("map-reduce sibling drain");
        let other = CancelReason::race_loser().with_message("independent race");
        for (joined, recorded) in [
            (Ok(()), Some(drain.clone())),
            (Err(JoinError::Cancelled(drain.clone())), None),
            (Err(JoinError::Cancelled(other)), Some(drain.clone())),
            (
                Err(JoinError::Cancelled(CancelReason::timeout())),
                Some(drain.clone()),
            ),
        ] {
            let mut failures = empty_executing_failures();
            failures.error(1, MapReduceExecutionError::Map("trigger"));
            failures.map_error(0, "independent", &joined, recorded.as_ref());
            assert!(matches!(
                failures.take_primary_error(),
                Some((0, MapReduceExecutionError::Map("independent")))
            ));
            assert_eq!(failures.stopped_by, Some((1, MapReduceStopCause::Error)));
        }
    }

    #[test]
    fn executing_map_independent_error_order_is_unchanged_by_drain_diagnostics() {
        let drain = CancelReason::race_loser().with_message("map-reduce sibling drain");
        for order in [[1, 2, 3], [1, 3, 2], [2, 1, 3], [2, 3, 1], [3, 1, 2], [3, 2, 1]] {
            let mut failures = empty_executing_failures();
            for index in order {
                failures.error(index, MapReduceExecutionError::Map(index));
            }
            failures.map_error(
                0,
                0,
                &Err(JoinError::Cancelled(drain.clone())),
                Some(&drain),
            );
            failures.errors.sort_by_key(|(index, _)| *index);
            assert!(matches!(
                failures.take_primary_error(),
                Some((1, MapReduceExecutionError::Map(1)))
            ));
            assert_eq!(
                failures.errors.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
                vec![0, 2, 3]
            );
            assert_eq!(failures.stopped_by, Some((order[0], MapReduceStopCause::Error)));
        }
    }

    #[test]
    fn executing_map_drain_errors_remain_owned_without_clone_or_early_drop() {
        struct MoveOnlyError(Arc<AtomicUsize>);
        impl Drop for MoveOnlyError {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let drain = CancelReason::race_loser().with_message("map-reduce sibling drain");
        let mut failures = empty_executing_failures();
        failures.error(1, MapReduceExecutionError::Map(MoveOnlyError(Arc::clone(&drops))));
        failures.map_error(
            0,
            MoveOnlyError(Arc::clone(&drops)),
            &Err(JoinError::Cancelled(drain.clone())),
            Some(&drain),
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let selected = failures.take_primary_error().unwrap();
        assert_eq!(selected.0, 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(selected);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(failures);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }
