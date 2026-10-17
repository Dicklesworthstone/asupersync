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
    use crate::record::{ObligationState, RegionLimits};
    use crate::types::{Budget, RegionId};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Waker;

    #[test]
    fn executing_pipeline_concrete_error_survives_disconnect_in_every_join_order() {
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            for stronger in 0..3 {
                let cx = Cx::for_testing();
                let mut owner = PipelineOwner::new(cx.clone(), 2);
                for event in order {
                    match event {
                        0 => owner.record(0, Outcome::Err(PipelineExecutionError::Disconnected)),
                        1 => owner.record(
                            1,
                            Outcome::Err(PipelineExecutionError::Stage {
                                stage: 1,
                                input: 0,
                                error: "initiating failure",
                            }),
                        ),
                        _ => match stronger {
                            0 => {}
                            1 => owner.record(2, pipeline_cancelled(&cx)),
                            _ => owner
                                .record(2, Outcome::Panicked(PanicPayload::new("cleanup panic"))),
                        },
                    }
                }
                let report = owner.finish();
                assert!(
                    matches!(
                        report.error(),
                        Some(PipelineExecutionError::Stage {
                            stage: 1,
                            input: 0,
                            error: "initiating failure",
                        })
                    ),
                    "order={order:?}, stronger={stronger}: {report:?}"
                );
                match stronger {
                    0 => assert!(report.outcome.is_err()),
                    1 => assert!(report.outcome.is_cancelled()),
                    _ => assert!(report.outcome.is_panicked()),
                }
            }
        }
    }

    #[test]
    fn a_consequential_disconnection_is_never_reported_beside_a_stronger_outcome() {
        // A sibling that sees its channel close before its own cancellation
        // reports Disconnected. That is a consequence of the stronger exit, so
        // `error()` must stay None whichever the scheduler records first
        // (e2e_stream_pipeline's panic control failed on some runs only).
        for disconnection_first in [true, false] {
            for panic in [false, true] {
                let cx = Cx::for_testing();
                let mut owner: PipelineOwner<&'static str> = PipelineOwner::new(cx.clone(), 2);
                let stronger = if panic {
                    Outcome::Panicked(PanicPayload::new("stage panic"))
                } else {
                    pipeline_cancelled(&cx)
                };
                if disconnection_first {
                    owner.record(0, Outcome::Err(PipelineExecutionError::Disconnected));
                    owner.record(1, stronger);
                } else {
                    owner.record(1, stronger);
                    owner.record(0, Outcome::Err(PipelineExecutionError::Disconnected));
                }
                let report = owner.finish();
                assert!(
                    report.error().is_none(),
                    "disconnection_first={disconnection_first}, panic={panic}: {report:?}"
                );
                assert_eq!(report.outcome.is_panicked(), panic, "{report:?}");
                assert_eq!(report.outcome.is_cancelled(), !panic, "{report:?}");
            }
        }
    }

    #[derive(Default)]
    struct ExecutionGate {
        open: AtomicBool,
        waiter: Mutex<Option<Waker>>,
    }

    impl ExecutionGate {
        fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
            if self.open.load(Ordering::SeqCst) {
                return Poll::Ready(());
            }
            *self.waiter.lock().unwrap() = Some(cx.waker().clone());
            if self.open.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }

        async fn wait(&self) {
            std::future::poll_fn(|cx| self.poll(cx)).await;
        }

        fn release(&self) {
            self.open.store(true, Ordering::SeqCst);
            let wake = self.waiter.lock().unwrap().take();
            if let Some(waker) = wake {
                waker.wake();
            }
        }

        fn is_parked(&self) -> bool {
            self.waiter.lock().unwrap().is_some()
        }
    }

    struct ExecutionInputs {
        end: u32,
        pulled: Arc<AtomicUsize>,
        panic_factory: bool,
        panic_next: Option<u32>,
    }

    struct ExecutionIter {
        next: u32,
        inputs: ExecutionInputs,
    }

    impl IntoIterator for ExecutionInputs {
        type Item = u32;
        type IntoIter = ExecutionIter;

        fn into_iter(self) -> Self::IntoIter {
            assert!(!self.panic_factory, "executing iterator factory panic");
            ExecutionIter {
                next: 0,
                inputs: self,
            }
        }
    }

    impl Iterator for ExecutionIter {
        type Item = u32;

        fn next(&mut self) -> Option<Self::Item> {
            assert_ne!(
                self.inputs.panic_next,
                Some(self.next),
                "executing iterator next panic"
            );
            if self.next == self.inputs.end {
                return None;
            }
            let value = self.next;
            self.next += 1;
            self.inputs.pulled.fetch_add(1, Ordering::SeqCst);
            Some(value)
        }
    }

    fn execution_config(window: usize) -> PipelineExecutionConfig {
        PipelineExecutionConfig::new(
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(window).unwrap(),
        )
    }

    fn execution_lab(seed: u64) -> LabRuntime {
        LabRuntime::new(
            LabConfig::new(seed)
                .max_steps(100_000)
                .trace_capacity(200_000),
        )
    }

    fn execution_cleanup(lab: &mut LabRuntime, region: RegionId) {
        assert_eq!(
            lab.state.tasks_iter().count(),
            0,
            "every actual child joined"
        );
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        let gateway = lab.state.obligation_gateway().unwrap();
        let mailbox = gateway.mailbox();
        let stats = mailbox.stats();
        assert_eq!(stats.posted, stats.applied, "no unapplied lifecycle suffix");
        assert_eq!(stats.reserved, stats.committed + stats.aborted);
        assert_eq!(mailbox.open_tickets(), 0);
        assert!(mailbox.is_empty());
        for (_, obligation) in lab.state.obligations.iter() {
            assert!(matches!(
                obligation.state,
                ObligationState::Committed | ObligationState::Aborted
            ));
        }
        let record = lab.state.region(region).unwrap();
        assert_eq!(record.pending_obligations(), 0);
        assert_eq!(record.unapplied_obligation_count(), 0);
        lab.state.close_region_command(
            region,
            &CancelReason::user("executing pipeline test complete"),
        );
        assert!(lab.state.region(region).is_none());
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "{report:?}");
        assert!(!report.refinement_firewall_skipped_due_to_trace_truncation);
        eprintln!("executing_pipeline_cleanup region={region:?} stats={stats:?} report={report:?}");
    }

    #[test]
    fn executing_pipeline_heterogeneous_sink_ack_bounds_all_work() {
        for seed in [7, 71, 701] {
            let mut lab = execution_lab(seed);
            let region = lab.state.create_root_region(Budget::INFINITE);
            let gate = Arc::new(ExecutionGate::default());
            let sink_gate = Arc::clone(&gate);
            let outputs = Arc::new(Mutex::new(Vec::new()));
            let sink_outputs = Arc::clone(&outputs);
            let pulled = Arc::new(AtomicUsize::new(0));
            let inputs = ExecutionInputs {
                end: 9,
                pulled: Arc::clone(&pulled),
                panic_factory: false,
                panic_next: None,
            };
            let lazy_pulls = Arc::clone(&pulled);
            let (task, mut handle) = lab
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let scope = cx.scope();
                    let pipeline = scope
                        .pipeline::<_, &'static str>(&cx, execution_config(2), inputs)
                        .then(NonZeroUsize::new(1).unwrap(), |_, value| async move {
                            Outcome::Ok(format!("value={value}"))
                        })
                        .then(
                            NonZeroUsize::new(1).unwrap(),
                            |_, value: String| async move { Outcome::Ok(value.into_bytes()) },
                        );
                    assert_eq!(lazy_pulls.load(Ordering::SeqCst), 0, "building is lazy");
                    pipeline
                        .run(move |_, value: Vec<u8>| {
                            let gate = Arc::clone(&sink_gate);
                            let outputs = Arc::clone(&sink_outputs);
                            async move {
                                if value == b"value=0" {
                                    gate.wait().await;
                                }
                                outputs.lock().unwrap().push(value);
                                Outcome::Ok(())
                            }
                        })
                        .await
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            assert!(lab.run_until_idle() > 0);
            assert!(gate.is_parked(), "the actual async sink reached Pending");
            assert!(handle.try_join().unwrap().is_none());
            assert_eq!(
                pulled.load(Ordering::SeqCst),
                2,
                "sink ack controls the total window"
            );
            assert!(outputs.lock().unwrap().is_empty());
            let live_credits: Vec<_> = lab
                .state
                .obligations
                .iter()
                .filter_map(|(_, record)| {
                    (record.holder == task
                        && record.kind == ObligationKind::Lease
                        && record.state == ObligationState::Reserved)
                        .then_some(record.id)
                })
                .collect();
            assert_eq!(
                live_credits.len(),
                2,
                "both IDs remain owned by the coordinator"
            );
            assert_ne!(live_credits[0], live_credits[1]);
            gate.release();
            lab.run_until_quiescent();
            let report = handle.try_join().unwrap().expect("actual pipeline joined");
            assert!(report.outcome.is_ok(), "{report:?}");
            assert_eq!(
                report.summary,
                PipelineExecutionSummary {
                    admitted: 9,
                    consumed: 9,
                    max_in_flight: 2,
                    stages: 2
                }
            );
            assert!(report.error().is_none());
            assert_eq!(
                *outputs.lock().unwrap(),
                (0..9)
                    .map(|value| format!("value={value}").into_bytes())
                    .collect::<Vec<_>>()
            );
            assert_eq!(pulled.load(Ordering::SeqCst), 9);
            let leases: Vec<_> = lab
                .state
                .obligations
                .iter()
                .filter(|(_, record)| record.kind == ObligationKind::Lease)
                .collect();
            assert_eq!(leases.len(), 10, "nine inputs plus one aborted EOF probe");
            assert_eq!(
                leases
                    .iter()
                    .filter(|(_, record)| record.state == ObligationState::Committed)
                    .count(),
                9
            );
            assert_eq!(
                leases
                    .iter()
                    .filter(|(_, record)| record.state == ObligationState::Aborted)
                    .count(),
                1
            );
            assert!(
                leases
                    .iter()
                    .all(|(_, record)| record.holder == task && record.region == region)
            );
            for id in live_credits {
                assert_eq!(
                    lab.state.obligation(id).unwrap().state,
                    ObligationState::Committed
                );
            }
            execution_cleanup(&mut lab, region);
        }
    }

    #[test]
    fn executing_pipeline_identity_and_empty_inputs_do_real_bounded_work() {
        for count in [0_u32, 1, 97] {
            for stages in [false, true] {
                let mut lab = execution_lab(190 + u64::from(count));
                let region = lab.state.create_root_region(Budget::INFINITE);
                let outputs = Arc::new(Mutex::new(Vec::new()));
                let actual = Arc::clone(&outputs);
                let calls = Arc::new(AtomicUsize::new(0));
                let transforms = Arc::clone(&calls);
                let (task, mut handle) = lab
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        let cx = Cx::current().unwrap();
                        let scope = cx.scope();
                        let pipeline =
                            scope.pipeline::<_, &'static str>(&cx, execution_config(1), 0..count);
                        let pipeline = if stages {
                            pipeline.then(NonZeroUsize::new(1).unwrap(), move |_, value| {
                                transforms.fetch_add(1, Ordering::SeqCst);
                                async move { Outcome::Ok(value + 10) }
                            })
                        } else {
                            pipeline
                        };
                        pipeline
                            .run(move |_, value| {
                                actual.lock().unwrap().push(value);
                                async { Outcome::Ok(()) }
                            })
                            .await
                    })
                    .unwrap();
                lab.scheduler.lock().schedule(task, 0);
                lab.run_until_quiescent();
                let report = handle.try_join().unwrap().expect("identity/empty executed");
                assert!(report.outcome.is_ok(), "{report:?}");
                assert_eq!(report.summary.admitted, count as usize);
                assert_eq!(report.summary.consumed, count as usize);
                assert_eq!(report.summary.stages, usize::from(stages));
                assert_eq!(report.summary.max_in_flight, usize::from(count != 0));
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    if stages { count as usize } else { 0 }
                );
                assert_eq!(
                    *outputs.lock().unwrap(),
                    (0..count)
                        .map(|value| value + if stages { 10 } else { 0 })
                        .collect::<Vec<_>>()
                );
                execution_cleanup(&mut lab, region);
            }
        }
    }

    #[test]
    fn executing_pipeline_owned_capture_retirement_precedes_terminal_publication() {
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
                        Some("pipeline owned-capture retirement"),
                    );
                }
                if self.panic {
                    panic!("pipeline capture {} retirement panic", self.index);
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
                assert!(
                    !self.fail_construction,
                    "pipeline primary construction panic"
                );
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

        for mode in 0..10 {
            let mut lab = execution_lab(0x32_1900 + mode);
            let root = lab.state.create_root_region(Budget::INFINITE);
            let drops = Arc::new(std::array::from_fn::<_, 3, _>(|_| AtomicUsize::new(0)));
            let outputs = Arc::new(Mutex::new(Vec::new()));
            let publication = Arc::new(Mutex::new(None));
            let task_drops = Arc::clone(&drops);
            let task_outputs = Arc::clone(&outputs);
            let task_publication = Arc::clone(&publication);
            let future: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                let cx = Cx::current().expect("actual pipeline retirement coordinator");
                let capture = |index| Capture {
                    cx: cx.clone(),
                    drops: Arc::clone(&task_drops),
                    index,
                    cancel: mode == index as u64 + 1 || (mode >= 7 && index == 0),
                    panic: mode == index as u64 + 4 || (mode == 7 && index == 0),
                };
                let inputs = Inputs {
                    capture: capture(0),
                    fail_construction: mode == 9,
                };
                let transform = capture(1);
                let sink = capture(2);
                let report = cx
                    .scope()
                    .pipeline::<_, &'static str>(&cx, execution_config(1), inputs)
                    .then(NonZeroUsize::new(1).unwrap(), move |_, value| {
                        transform.observe();
                        async move {
                            if value == 1 && mode == 7 {
                                Outcome::Panicked(PanicPayload::new("pipeline primary stage panic"))
                            } else if value == 1 && mode == 8 {
                                Outcome::Err("pipeline primary error")
                            } else {
                                Outcome::Ok(value)
                            }
                        }
                    })
                    .run(move |_, value| {
                        sink.observe();
                        task_outputs.lock().unwrap().push(value);
                        async { Outcome::Ok(()) }
                    })
                    .await;
                *task_publication.lock().unwrap() = Some((report, cx.cancel_reason()));
            });
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, future)
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            let (report, reason) = publication
                .lock()
                .unwrap()
                .take()
                .expect("actual terminal report");
            match &reason {
                Some(reason) => {
                    assert_eq!(reason.kind(), crate::types::CancelKind::User);
                    assert_eq!(
                        reason.message.as_deref(),
                        Some("pipeline owned-capture retirement")
                    );
                    assert_eq!(join.try_join(), Err(JoinError::Cancelled(reason.clone())));
                }
                None => assert_eq!(join.try_join(), Ok(Some(()))),
            }
            assert!(drops.iter().all(|count| count.load(Ordering::SeqCst) == 1));
            let (admitted, consumed) = match mode {
                7 | 8 => (2, 1),
                9 => (0, 0),
                _ => (3, 3),
            };
            assert_eq!(report.summary.admitted, admitted);
            assert_eq!(report.summary.consumed, consumed);
            assert_eq!(report.summary.stages, 1);
            assert_eq!(report.summary.max_in_flight, usize::from(admitted != 0));
            assert_eq!(
                *outputs.lock().unwrap(),
                (0..consumed as u32).collect::<Vec<_>>()
            );
            let credits: Vec<_> = lab
                .state
                .obligations
                .iter()
                .filter_map(|(_, record)| {
                    (record.holder == parent && record.kind == ObligationKind::Lease)
                        .then_some(record)
                })
                .collect();
            assert_eq!(credits.len(), admitted + usize::from(mode < 7));
            assert_eq!(
                credits
                    .iter()
                    .filter(|record| record.state == ObligationState::Committed)
                    .count(),
                consumed
            );
            assert_eq!(
                credits
                    .iter()
                    .filter(|record| record.state == ObligationState::Aborted)
                    .count(),
                credits.len() - consumed
            );
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
            let children: Vec<_> = trace
                .iter()
                .filter_map(|event| {
                    if event.kind == crate::trace::TraceEventKind::Spawn {
                        if let crate::trace::TraceData::Task { task, region } = event.data {
                            if task != parent && region == root {
                                return Some(task);
                            }
                        }
                    }
                    None
                })
                .collect();
            assert_eq!(children.len(), 2, "actual transform and sink admissions");
            assert_ne!(children[0], children[1]);
            assert!(
                children
                    .iter()
                    .all(|child| completion(*child) < parent_complete)
            );
            execution_cleanup(&mut lab, root);
            eprintln!(
                "pipeline capture retirement mode={mode} parent={parent:?} children={children:?} report={report:?} reason={reason:?}"
            );
            match mode {
                0 => assert!(
                    matches!(report.outcome, Outcome::Ok(summary) if summary == report.summary)
                ),
                1..=3 | 8 => {
                    assert!(
                        matches!(&report.outcome, Outcome::Cancelled(actual) if Some(actual) == reason.as_ref())
                    );
                    if mode == 8 {
                        assert!(matches!(
                            report.error(),
                            Some(PipelineExecutionError::Stage {
                                stage: 0,
                                input: 1,
                                error: "pipeline primary error"
                            })
                        ));
                    }
                }
                _ => {
                    let message = match mode {
                        4..=6 => format!("pipeline capture {} retirement panic", mode - 4),
                        7 => "pipeline primary stage panic".to_owned(),
                        9 => "pipeline primary construction panic".to_owned(),
                        _ => unreachable!(),
                    };
                    assert!(
                        matches!(&report.outcome, Outcome::Panicked(payload) if payload.message() == message)
                    );
                }
            }
        }
    }

    #[test]
    fn executing_pipeline_quota_refusal_remains_typed_after_cancelled_drain() {
        let mut lab = execution_lab(290);
        let region = lab.state.create_root_region(Budget::INFINITE);
        lab.state.region(region).unwrap().set_limits(RegionLimits {
            max_obligations: Some(0),
            ..RegionLimits::UNLIMITED
        });
        let pulled = Arc::new(AtomicUsize::new(0));
        let inputs = ExecutionInputs {
            end: 8,
            pulled: Arc::clone(&pulled),
            panic_factory: false,
            panic_next: None,
        };
        let (task, mut handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .pipeline::<_, &'static str>(&cx, execution_config(1), inputs)
                    .run(|_, _| async {
                        panic!("quota zero must not call the sink");
                    })
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_quiescent();
        let report = handle
            .try_join()
            .unwrap()
            .expect("refusal drained its real sink task");
        assert!(
            report.outcome.is_cancelled(),
            "the aborted pending sink contributes its actual severity: {report:?}"
        );
        assert!(matches!(
            report.error(),
            Some(PipelineExecutionError::Admission {
                stage: None,
                input: 0,
                error: ObligationAdmissionError::LimitReached { limit: 0, live: 0 }
            })
        ));
        assert_eq!(report.summary.admitted, 0);
        assert_eq!(report.summary.consumed, 0);
        assert_eq!(
            pulled.load(Ordering::SeqCst),
            0,
            "authority is checked before iterator.next"
        );
        assert_eq!(lab.state.obligations.iter().count(), 0);
        execution_cleanup(&mut lab, region);
    }

    #[test]
    fn executing_pipeline_factory_poll_and_domain_failures_drain_all_tasks() {
        for cause in 0..7 {
            let mut lab = execution_lab(390 + cause);
            let region = lab.state.create_root_region(Budget::INFINITE);
            let pulled = Arc::new(AtomicUsize::new(0));
            let inputs = ExecutionInputs {
                end: 8,
                pulled,
                panic_factory: cause == 0,
                panic_next: (cause == 1).then_some(0),
            };
            let outputs = Arc::new(Mutex::new(Vec::new()));
            let actual = Arc::clone(&outputs);
            let (task, mut handle) = lab
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    cx.scope()
                        .pipeline::<_, &'static str>(&cx, execution_config(1), inputs)
                        .then(NonZeroUsize::new(1).unwrap(), move |_, value| {
                            assert_ne!(cause, 2, "executing transform factory panic");
                            async move {
                                assert_ne!(cause, 3, "executing transform poll panic");
                                if cause == 6 {
                                    Outcome::Err("typed stage refusal")
                                } else {
                                    Outcome::Ok(value)
                                }
                            }
                        })
                        .run(move |_, value| {
                            assert_ne!(cause, 4, "executing sink factory panic");
                            let actual = Arc::clone(&actual);
                            async move {
                                assert_ne!(cause, 5, "executing sink poll panic");
                                actual.lock().unwrap().push(value);
                                Outcome::Ok(())
                            }
                        })
                        .await
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            lab.run_until_quiescent();
            let report = handle
                .try_join()
                .unwrap()
                .expect("failure returned only after joining its children");
            if cause == 6 {
                assert!(matches!(
                    report.error(),
                    Some(PipelineExecutionError::Stage {
                        stage: 0,
                        input: 0,
                        error: "typed stage refusal"
                    })
                ));
                assert!(
                    matches!(report.outcome, Outcome::Err(_) | Outcome::Cancelled(_)),
                    "{report:?}"
                );
            } else {
                let Outcome::Panicked(payload) = &report.outcome else {
                    panic!("expected actual panic for cause {cause}: {report:?}");
                };
                assert!(payload.message().contains("executing"), "{payload:?}");
            }
            assert_eq!(report.summary.consumed, 0);
            assert!(report.summary.admitted <= 1);
            assert!(outputs.lock().unwrap().is_empty());
            execution_cleanup(&mut lab, region);
        }
    }

    #[test]
    fn executing_pipeline_cancel_and_future_drop_leave_async_cleanup_owned() {
        for drop_future in [false, true] {
            let mut lab = execution_lab(490 + u64::from(drop_future));
            let region = lab.state.create_root_region(Budget::INFINITE);
            let entered = Arc::new(AtomicBool::new(false));
            let cancelled = Arc::new(AtomicBool::new(false));
            let cleanup = Arc::new(ExecutionGate::default());
            let drop_request = Arc::new(ExecutionGate::default());
            let result = Arc::new(Mutex::new(None));
            let worker_entered = Arc::clone(&entered);
            let worker_cancelled = Arc::clone(&cancelled);
            let worker_cleanup = Arc::clone(&cleanup);
            let request = Arc::clone(&drop_request);
            let returned = Arc::clone(&result);
            let (task, mut handle) = lab
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let scope = cx.scope();
                    let pipeline = scope
                        .pipeline::<_, &'static str>(&cx, execution_config(1), 0..8_u32)
                        .then(NonZeroUsize::new(1).unwrap(), move |worker_cx, value| {
                            let entered = Arc::clone(&worker_entered);
                            let cancelled = Arc::clone(&worker_cancelled);
                            let cleanup = Arc::clone(&worker_cleanup);
                            async move {
                                entered.store(true, Ordering::SeqCst);
                                let mut registration = None;
                                std::future::poll_fn(|poll| {
                                    registration = Some(
                                        worker_cx.refresh_cancel_waker(registration, poll.waker()),
                                    );
                                    if worker_cx.checkpoint().is_err() {
                                        Poll::Ready(())
                                    } else {
                                        Poll::Pending
                                    }
                                })
                                .await;
                                worker_cx.clear_cancel_waker(registration.take().unwrap());
                                cancelled.store(true, Ordering::SeqCst);
                                // This is user async cleanup: it deliberately needs
                                // a separate event after observing cancellation.
                                cleanup.wait().await;
                                let _: u32 = value;
                                pipeline_cancelled(&worker_cx)
                            }
                        });
                    let mut execution = Box::pin(pipeline.run(|_, _: u32| async {
                        panic!("cancelled transform cannot publish a value");
                    }));
                    if drop_future {
                        std::future::poll_fn(|poll| {
                            if request.poll(poll).is_ready() {
                                return Poll::Ready(());
                            }
                            assert!(
                                execution.as_mut().poll(poll).is_pending(),
                                "execution cannot finish while its transform is parked"
                            );
                            Poll::Pending
                        })
                        .await;
                        drop(execution);
                    } else {
                        *returned.lock().unwrap() = Some(execution.await);
                    }
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            lab.run_until_idle();
            assert!(entered.load(Ordering::SeqCst));
            assert!(!cancelled.load(Ordering::SeqCst));
            assert!(handle.try_join().unwrap().is_none());
            if drop_future {
                drop_request.release();
            } else {
                handle.abort();
            }
            lab.run_until_idle();
            assert!(
                cancelled.load(Ordering::SeqCst),
                "actual child cancellation waker fired"
            );
            assert!(
                cleanup.is_parked(),
                "cleanup crossed a separate Pending boundary"
            );
            assert!(
                result.lock().unwrap().is_none(),
                "no report may claim a drained operation yet"
            );
            assert!(
                lab.state.tasks_iter().count() > 0,
                "region still owns actual cleanup"
            );
            if drop_future {
                assert_eq!(
                    handle.try_join().unwrap(),
                    Some(()),
                    "dropping the operation requests abort without pretending to drain"
                );
            } else {
                assert!(handle.try_join().unwrap().is_none());
                assert_eq!(
                    lab.state
                        .obligations
                        .iter()
                        .filter(|(_, record)| record.kind == ObligationKind::Lease
                            && record.state == ObligationState::Reserved)
                        .count(),
                    1,
                    "the coordinator retains its original work credit while draining"
                );
            }
            cleanup.release();
            lab.run_until_quiescent();
            if !drop_future {
                let report = result
                    .lock()
                    .unwrap()
                    .take()
                    .expect("cancelled operation drained after real cleanup completion");
                assert!(report.outcome.is_cancelled(), "{report:?}");
                assert_eq!(report.summary.admitted, 1);
                assert_eq!(report.summary.consumed, 0);
                match handle.try_join() {
                    Ok(Some(())) | Err(JoinError::Cancelled(_)) => {}
                    other => panic!("unexpected owner completion: {other:?}"),
                }
            }
            execution_cleanup(&mut lab, region);
        }
    }

    #[test]
    fn executing_pipeline_late_logical_cleanup_panic_dominates_cancelled_join() {
        for late_panic in [true, false] {
            let mut lab = execution_lab(590 + u64::from(late_panic));
            let region = lab.state.create_root_region(Budget::INFINITE);
            let second_entered = Arc::new(ExecutionGate::default());
            let first_gate = Arc::clone(&second_entered);
            let second_gate = Arc::clone(&second_entered);
            let cleanup = Arc::new(ExecutionGate::default());
            let actual_cleanup = Arc::clone(&cleanup);
            let cancelled = Arc::new(AtomicBool::new(false));
            let actual_cancelled = Arc::clone(&cancelled);
            let (task, mut handle) = lab
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    cx.scope()
                        .pipeline::<_, &'static str>(&cx, execution_config(2), 0..2_u32)
                        .then(NonZeroUsize::new(1).unwrap(), move |worker_cx, value| {
                            let entered = Arc::clone(&first_gate);
                            let cleanup = Arc::clone(&actual_cleanup);
                            let cancelled = Arc::clone(&actual_cancelled);
                            async move {
                                if value == 0 {
                                    return Outcome::Ok(value);
                                }
                                entered.release();
                                let mut registration = None;
                                std::future::poll_fn(|poll| {
                                    registration = Some(
                                        worker_cx.refresh_cancel_waker(registration, poll.waker()),
                                    );
                                    if worker_cx.checkpoint().is_err() {
                                        Poll::Ready(())
                                    } else {
                                        Poll::Pending
                                    }
                                })
                                .await;
                                worker_cx.clear_cancel_waker(registration.take().unwrap());
                                cancelled.store(true, Ordering::SeqCst);
                                cleanup.wait().await;
                                if late_panic {
                                    Outcome::Panicked(PanicPayload::new(
                                        "logical cleanup panic after sibling failure",
                                    ))
                                } else {
                                    Outcome::Err("secondary cleanup error")
                                }
                            }
                        })
                        .then(NonZeroUsize::new(1).unwrap(), move |_, _: u32| {
                            let gate = Arc::clone(&second_gate);
                            async move {
                                gate.wait().await;
                                Outcome::<u32, _>::Err("initiating stage failure")
                            }
                        })
                        .run(|_, _: u32| async {
                            panic!("failing stage cannot publish to the sink")
                        })
                        .await
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            lab.run_until_idle();
            assert!(second_entered.open.load(Ordering::SeqCst));
            assert!(cancelled.load(Ordering::SeqCst));
            assert!(cleanup.is_parked());
            assert!(
                handle.try_join().unwrap().is_none(),
                "the first worker has not finished cleanup"
            );
            cleanup.release();
            lab.run_until_quiescent();
            let report = handle
                .try_join()
                .unwrap()
                .expect("both logical and task terminals collected");
            if late_panic {
                let Outcome::Panicked(payload) = &report.outcome else {
                    panic!("cleanup panic was erased by cancellation: {report:?}");
                };
                assert_eq!(
                    payload.message(),
                    "logical cleanup panic after sibling failure"
                );
            } else {
                assert!(
                    report.outcome.is_cancelled(),
                    "actual cancellation dominates the later logical cleanup Err: {report:?}"
                );
            }
            assert!(matches!(
                report.error(),
                Some(PipelineExecutionError::Stage {
                    stage: 1,
                    input: 0,
                    error: "initiating stage failure"
                })
            ));
            assert_eq!(report.summary.admitted, 2);
            assert_eq!(report.summary.consumed, 0);
            execution_cleanup(&mut lab, region);
        }
    }

    #[test]
    fn executing_pipeline_downstream_failure_retains_error_and_drains_bounded_channels() {
        for seed in 700..708 {
            let mut lab = execution_lab(seed);
            let region = lab.state.create_root_region(Budget::INFINITE);
            let (task, mut handle) = lab
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    cx.scope()
                        .pipeline::<_, &'static str>(&cx, execution_config(8), 0..64_u32)
                        .then(NonZeroUsize::new(1).unwrap(), |_, value| async move {
                            Outcome::Ok(value)
                        })
                        .then(NonZeroUsize::new(1).unwrap(), |_, _: u32| async {
                            Outcome::<u32, _>::Err("downstream failed")
                        })
                        .run(|_, _: u32| async {
                            panic!("the failing transform must not publish to the sink")
                        })
                        .await
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            lab.run_until_quiescent();
            let report = handle.try_join().unwrap().expect("pipeline drained");
            assert!(
                matches!(
                    report.error(),
                    Some(PipelineExecutionError::Stage {
                        stage: 1,
                        input: 0,
                        error: "downstream failed",
                    })
                ),
                "seed={seed}: {report:?}"
            );
            assert_eq!(report.summary.consumed, 0);
            assert!(report.summary.admitted > 0);
            assert!(report.summary.max_in_flight <= 8);
            execution_cleanup(&mut lab, region);
        }
    }

    #[test]
    fn executing_pipeline_failed_sink_keeps_same_poll_acknowledged_prefix() {
        let mut lab = execution_lab(690);
        let region = lab.state.create_root_region(Budget::INFINITE);
        let gate = Arc::new(ExecutionGate::default());
        let sink_gate = Arc::clone(&gate);
        let outputs = Arc::new(Mutex::new(Vec::new()));
        let actual = Arc::clone(&outputs);
        let (task, mut handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                cx.scope()
                    .pipeline::<_, &'static str>(&cx, execution_config(2), 0..2_u32)
                    .run(move |_, value| {
                        let gate = Arc::clone(&sink_gate);
                        let actual = Arc::clone(&actual);
                        async move {
                            if value == 0 {
                                gate.wait().await;
                                actual.lock().unwrap().push(value);
                                Outcome::Ok(())
                            } else {
                                Outcome::Err("failure after delivered prefix")
                            }
                        }
                    })
                    .await
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        assert!(gate.is_parked());
        assert!(handle.try_join().unwrap().is_none());
        let original: Vec<_> = lab
            .state
            .obligations
            .iter()
            .filter_map(|(_, record)| {
                (record.holder == task && record.kind == ObligationKind::Lease).then_some(record.id)
            })
            .collect();
        assert_eq!(original.len(), 2);
        assert!(outputs.lock().unwrap().is_empty());
        // Input 1 is already queued behind the pending input-0 callback.
        // The sink can publish ack0 and return Err(1) in this single poll,
        // before the coordinator observes either event.
        gate.release();
        lab.run_until_quiescent();
        let report = handle
            .try_join()
            .unwrap()
            .expect("sink error and queued ACK both drained");
        assert!(matches!(
            report.error(),
            Some(PipelineExecutionError::Stage {
                stage: 0,
                input: 1,
                error: "failure after delivered prefix"
            })
        ));
        assert_eq!(*outputs.lock().unwrap(), vec![0]);
        assert_eq!(report.summary.admitted, 2);
        assert_eq!(report.summary.consumed, 1);
        assert_eq!(
            lab.state.obligation(original[0]).unwrap().state,
            ObligationState::Committed
        );
        assert_eq!(
            lab.state.obligation(original[1]).unwrap().state,
            ObligationState::Aborted
        );
        assert_eq!(
            lab.state
                .obligations
                .iter()
                .filter(|(_, record)| record.kind == ObligationKind::Lease)
                .count(),
            2,
            "failure did not pull another input or an EOF probe"
        );
        execution_cleanup(&mut lab, region);
    }

    /// A sink effect that completes after the pipeline was cancelled is
    /// acknowledged: its credit is committed and counted as consumed, not
    /// aborted (a caller resuming from `consumed` would repeat the write).
    #[test]
    fn executing_pipeline_acknowledges_a_sink_effect_finished_after_cancellation() {
        let mut lab = execution_lab(691);
        let region = lab.state.create_root_region(Budget::INFINITE);
        let gate = Arc::new(ExecutionGate::default());
        let sink_gate = Arc::clone(&gate);
        let outputs = Arc::new(Mutex::new(Vec::new()));
        let actual = Arc::clone(&outputs);
        let result = Arc::new(Mutex::new(None));
        let returned = Arc::clone(&result);
        let (task, mut handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let report = cx
                    .scope()
                    .pipeline::<_, &'static str>(&cx, execution_config(2), 0..1_u32)
                    .run(move |_, value| {
                        let gate = Arc::clone(&sink_gate);
                        let actual = Arc::clone(&actual);
                        async move {
                            gate.wait().await;
                            actual.lock().unwrap().push(value);
                            Outcome::Ok(())
                        }
                    })
                    .await;
                *returned.lock().unwrap() = Some(report);
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        assert!(gate.is_parked());
        let original: Vec<_> = lab
            .state
            .obligations
            .iter()
            .filter_map(|(_, record)| {
                (record.holder == task
                    && record.kind == ObligationKind::Lease
                    && record.state == ObligationState::Reserved)
                    .then_some(record.id)
            })
            .collect();
        assert_eq!(
            original.len(),
            1,
            "input 0's lease is held; the EOF probe's is already aborted"
        );
        handle.abort();
        lab.run_until_idle();
        gate.release();
        lab.run_until_quiescent();
        assert_eq!(
            *outputs.lock().unwrap(),
            vec![0],
            "the sink effect happened"
        );
        let report = result
            .lock()
            .unwrap()
            .take()
            .expect("the cancelled pipeline still drains and reports");
        assert_eq!(
            report.summary.consumed, 1,
            "the completed effect counts: {report:?}"
        );
        assert_eq!(
            lab.state.obligation(original[0]).unwrap().state,
            ObligationState::Committed
        );
        match handle.try_join() {
            Ok(Some(())) | Err(JoinError::Cancelled(_)) => {}
            other => panic!("unexpected cancelled coordinator completion: {other:?}"),
        }
        execution_cleanup(&mut lab, region);
    }

    #[test]
    fn executing_pipeline_captured_iterator_drop_panic_still_joins_admitted_workers() {
        struct PanickingIterator {
            pulled: Arc<AtomicUsize>,
            dropped: Arc<AtomicUsize>,
        }

        impl Iterator for PanickingIterator {
            type Item = u32;
            fn next(&mut self) -> Option<Self::Item> {
                self.pulled.fetch_add(1, Ordering::SeqCst);
                Some(0)
            }
        }

        impl Drop for PanickingIterator {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::SeqCst);
                panic!("captured iterator destruction panic after cancellation");
            }
        }

        let mut lab = execution_lab(790);
        let region = lab.state.create_root_region(Budget::INFINITE);
        let dropped = Arc::new(AtomicUsize::new(0));
        let pulled = Arc::new(AtomicUsize::new(0));
        let inputs = PanickingIterator {
            pulled: Arc::clone(&pulled),
            dropped: Arc::clone(&dropped),
        };
        let result = Arc::new(Mutex::new(None));
        let returned = Arc::clone(&result);
        let (task, mut handle) = lab
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let report = cx
                    .scope()
                    .pipeline::<_, &'static str>(&cx, execution_config(1), inputs)
                    .then(NonZeroUsize::new(1).unwrap(), |_, value| async move {
                        Outcome::Ok(value)
                    })
                    .then(NonZeroUsize::new(1).unwrap(), |_, value| async move {
                        Outcome::Ok(value)
                    })
                    .run(|_, _| async {
                        panic!("cancellation during spawning precedes all inputs")
                    })
                    .await;
                *returned.lock().unwrap() = Some(report);
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        // Each actual coordinator poll spawns at most one worker before
        // yielding. Two scheduler steps admit at least the first worker,
        // while three total workers are needed before the iterator is used.
        lab.step_for_test();
        lab.step_for_test();
        assert!(lab.state.tasks_iter().count() >= 2);
        assert_eq!(pulled.load(Ordering::SeqCst), 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert!(handle.try_join().unwrap().is_none());
        handle.abort();
        lab.run_until_quiescent();
        let report = result
            .lock()
            .unwrap()
            .take()
            .expect("iterator destruction must not bypass async drain");
        let Outcome::Panicked(payload) = &report.outcome else {
            panic!("iterator destruction must remain the stronger failure: {report:?}");
        };
        assert_eq!(
            payload.message(),
            "captured iterator destruction panic after cancellation"
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(pulled.load(Ordering::SeqCst), 0);
        assert_eq!(report.summary.admitted, 0);
        assert_eq!(report.summary.consumed, 0);
        assert_eq!(lab.state.obligations.iter().count(), 0);
        match handle.try_join() {
            Ok(Some(())) | Err(JoinError::Cancelled(_)) => {}
            other => panic!("unexpected cancelled coordinator completion: {other:?}"),
        }
        execution_cleanup(&mut lab, region);
    }

    // =========================================================================
    // PipelineConfig Tests
    // =========================================================================

    #[test]
    fn pipeline_config_default() {
        let config = PipelineConfig::default();
        assert!(config.check_cancellation);
        assert!(!config.continue_on_error);
    }

    #[test]
    fn pipeline_config_with_cancellation_check() {
        let config = PipelineConfig::with_cancellation_check();
        assert!(config.check_cancellation);
    }

    #[test]
    fn pipeline_config_without_cancellation_check() {
        let config = PipelineConfig::without_cancellation_check();
        assert!(!config.check_cancellation);
    }

    // =========================================================================
    // Pipeline Type Tests
    // =========================================================================

    #[test]
    fn pipeline_creation() {
        let pipeline = Pipeline::<()>::new();
        assert!(pipeline.config.check_cancellation);
    }

    #[test]
    fn pipeline_with_config() {
        let config = PipelineConfig::without_cancellation_check();
        let pipeline = Pipeline::<()>::with_config(config);
        assert!(!pipeline.config.check_cancellation);
    }

    #[test]
    fn pipeline_clone_and_copy() {
        let p1 = Pipeline::<()>::new();
        let p2 = p1; // Copy
        let p3 = p1; // Also copy

        assert_eq!(p1.config.check_cancellation, p2.config.check_cancellation);
        assert_eq!(p1.config.check_cancellation, p3.config.check_cancellation);
    }

    #[test]
    fn pipeline_macro_chains_stages_sequentially() {
        let cx = crate::cx::Cx::for_testing();
        let fut = crate::pipeline!(cx, 2usize, |_, x| async move { x + 3 }, |_, x| async move {
            x * 4
        });
        let out = futures_lite::future::block_on(fut);
        assert_eq!(out, 20);
    }

    // =========================================================================
    // FailedStage Tests
    // =========================================================================

    #[test]
    fn failed_stage_first() {
        let stage = FailedStage::new(0, 3);
        assert!(stage.is_first());
        assert!(!stage.is_last());
        assert_eq!(stage.stage_number(), 1);
    }

    #[test]
    fn failed_stage_middle() {
        let stage = FailedStage::new(1, 3);
        assert!(!stage.is_first());
        assert!(!stage.is_last());
        assert_eq!(stage.stage_number(), 2);
    }

    #[test]
    fn failed_stage_last() {
        let stage = FailedStage::new(2, 3);
        assert!(!stage.is_first());
        assert!(stage.is_last());
        assert_eq!(stage.stage_number(), 3);
    }

    #[test]
    fn failed_stage_display() {
        let stage = FailedStage::new(1, 5);
        assert_eq!(stage.to_string(), "stage 2/5");
    }

    // =========================================================================
    // PipelineResult Tests
    // =========================================================================

    #[test]
    fn pipeline_result_completed() {
        let result: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);

        assert!(result.is_completed());
        assert!(!result.is_failed());
        assert!(!result.is_cancelled());
        assert!(!result.is_panicked());
        assert_eq!(result.stages_executed(), 3);
    }

    #[test]
    fn pipeline_result_failed() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::failed("error", FailedStage::new(1, 3));

        assert!(!result.is_completed());
        assert!(result.is_failed());
        assert_eq!(result.stages_executed(), 2); // Stages 0 and 1 were executed
    }

    #[test]
    fn pipeline_result_cancelled() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(1, 3));

        assert!(!result.is_completed());
        assert!(result.is_cancelled());
        assert_eq!(result.stages_executed(), 1); // Only stage 0 completed before cancel
    }

    #[test]
    fn pipeline_result_panicked() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::panicked(PanicPayload::new("boom"), FailedStage::new(2, 3));

        assert!(!result.is_completed());
        assert!(result.is_panicked());
        assert_eq!(result.stages_executed(), 3); // All stages were attempted
    }

    #[test]
    fn pipeline_result_into_outcome() {
        let completed: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);
        assert!(matches!(completed.into_outcome(), Outcome::Ok(42)));

        let failed: PipelineResult<i32, &str> =
            PipelineResult::failed("error", FailedStage::new(0, 1));
        assert!(matches!(failed.into_outcome(), Outcome::Err("error")));

        let cancelled: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(0, 1));
        assert!(cancelled.into_outcome().is_cancelled());

        let panicked: PipelineResult<i32, &str> =
            PipelineResult::panicked(PanicPayload::new("oops"), FailedStage::new(0, 1));
        assert!(panicked.into_outcome().is_panicked());
    }

    // =========================================================================
    // stage_outcome_to_result Tests
    // =========================================================================

    #[test]
    fn stage_outcome_ok_returns_none() {
        let result = stage_outcome_to_result::<i32, &str>(Outcome::Ok(42), 0, 3);
        assert!(result.is_none());
    }

    #[test]
    fn stage_outcome_err_returns_failed() {
        let result = stage_outcome_to_result::<i32, &str>(Outcome::Err("error"), 1, 3);
        assert!(result.is_some());
        assert!(result.unwrap().is_failed());
    }

    #[test]
    fn stage_outcome_cancelled_returns_cancelled() {
        let result = stage_outcome_to_result::<i32, &str>(
            Outcome::Cancelled(CancelReason::shutdown()),
            2,
            3,
        );
        assert!(result.is_some());
        assert!(result.unwrap().is_cancelled());
    }

    #[test]
    fn stage_outcome_panicked_returns_panicked() {
        let result = stage_outcome_to_result::<i32, &str>(
            Outcome::Panicked(PanicPayload::new("boom")),
            0,
            3,
        );
        assert!(result.is_some());
        assert!(result.unwrap().is_panicked());
    }

    // =========================================================================
    // pipeline2_outcomes Tests
    // =========================================================================

    #[test]
    fn pipeline2_both_ok() {
        let result = pipeline2_outcomes::<i32, &str>(Outcome::Ok(1), Some(Outcome::Ok(2)));

        assert!(result.is_completed());
        if let PipelineResult::Completed {
            value,
            stages_completed,
        } = result
        {
            assert_eq!(value, 2);
            assert_eq!(stages_completed, 2);
        } else {
            unreachable!("Expected Completed");
        }
    }

    #[test]
    fn pipeline2_first_fails() {
        let result = pipeline2_outcomes::<i32, &str>(Outcome::Err("stage1 error"), None);

        assert!(result.is_failed());
        if let PipelineResult::Failed { error, failed_at } = result {
            assert_eq!(error, "stage1 error");
            assert!(failed_at.is_first());
        } else {
            unreachable!("Expected Failed");
        }
    }

    #[test]
    fn pipeline2_second_fails() {
        let result = pipeline2_outcomes(Outcome::Ok(1), Some(Outcome::Err("stage2 error")));

        assert!(result.is_failed());
        if let PipelineResult::Failed { error, failed_at } = result {
            assert_eq!(error, "stage2 error");
            assert!(failed_at.is_last());
            assert_eq!(failed_at.index, 1);
        } else {
            unreachable!("Expected Failed");
        }
    }

    #[test]
    fn pipeline2_first_cancelled() {
        let result =
            pipeline2_outcomes::<i32, &str>(Outcome::Cancelled(CancelReason::shutdown()), None);

        assert!(result.is_cancelled());
    }

    #[test]
    fn pipeline2_panicked_when_o2_missing() {
        let result = pipeline2_outcomes::<i32, &str>(Outcome::Ok(1), None);
        assert!(result.is_panicked());
        if let PipelineResult::Panicked {
            payload,
            panicked_at,
        } = result
        {
            assert_eq!(payload.message(), "o2 must be provided when o1 succeeds");
            assert_eq!(panicked_at.index, 1);
        } else {
            panic!("Expected Panicked");
        }
    }

    // =========================================================================
    // pipeline3_outcomes Tests
    // =========================================================================

    #[test]
    fn pipeline3_all_ok() {
        let result = pipeline3_outcomes::<i32, &str>(
            Outcome::<i32, &str>::Ok(1),
            Some(Outcome::Ok(2)),
            Some(Outcome::Ok(3)),
        );

        assert!(result.is_completed());
        if let PipelineResult::Completed {
            value,
            stages_completed,
        } = result
        {
            assert_eq!(value, 3);
            assert_eq!(stages_completed, 3);
        } else {
            unreachable!("Expected Completed");
        }
    }

    #[test]
    fn pipeline3_first_fails() {
        let result = pipeline3_outcomes::<i32, &str>(Outcome::Err("s1"), None, None);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 0);
        }
    }

    #[test]
    fn pipeline3_second_fails() {
        let result =
            pipeline3_outcomes::<i32, &str>(Outcome::Ok(1), Some(Outcome::Err("s2")), None);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 1);
        }
    }

    #[test]
    fn pipeline3_third_fails() {
        let result = pipeline3_outcomes(
            Outcome::Ok(1),
            Some(Outcome::Ok(2)),
            Some(Outcome::Err("s3")),
        );

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 2);
            assert!(failed_at.is_last());
        }
    }

    #[test]
    fn pipeline3_panicked_when_o2_missing() {
        let result = pipeline3_outcomes::<i32, &str>(Outcome::Ok(1), None, None);
        assert!(result.is_panicked());
        if let PipelineResult::Panicked {
            payload,
            panicked_at,
        } = result
        {
            assert_eq!(payload.message(), "o2 must be provided when o1 succeeds");
            assert_eq!(panicked_at.index, 1);
        } else {
            panic!("Expected Panicked");
        }
    }

    #[test]
    fn pipeline3_panicked_when_o3_missing() {
        let result = pipeline3_outcomes::<i32, &str>(Outcome::Ok(1), Some(Outcome::Ok(2)), None);
        assert!(result.is_panicked());
        if let PipelineResult::Panicked {
            payload,
            panicked_at,
        } = result
        {
            assert_eq!(
                payload.message(),
                "o3 must be provided when o1 and o2 succeed"
            );
            assert_eq!(panicked_at.index, 2);
        } else {
            panic!("Expected Panicked");
        }
    }

    // =========================================================================
    // pipeline_with_final Tests
    // =========================================================================

    #[test]
    fn pipeline_with_final_all_ok() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);

        assert!(result.is_completed());
        if let PipelineResult::Completed { value, .. } = result {
            assert_eq!(value, 42);
        }
    }

    #[test]
    fn pipeline_with_final_intermediate_fails() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Err("mid fail")];
        let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 1);
        }
    }

    #[test]
    fn pipeline_with_final_final_fails() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = pipeline_with_final(intermediates, Outcome::Err("final fail"), 3);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 2);
            assert!(failed_at.is_last());
        }
    }

    // =========================================================================
    // pipeline_to_result Tests
    // =========================================================================

    #[test]
    fn pipeline_to_result_completed() {
        let result: PipelineResult<i32, &str> = PipelineResult::completed(42, 3);
        assert_eq!(pipeline_to_result(result).unwrap(), 42);
    }

    #[test]
    fn pipeline_to_result_failed() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::failed("error", FailedStage::new(1, 3));
        let err = pipeline_to_result(result).unwrap_err();
        assert!(matches!(err, PipelineError::StageError { .. }));
    }

    #[test]
    fn pipeline_to_result_cancelled() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(0, 3));
        let err = pipeline_to_result(result).unwrap_err();
        assert!(matches!(err, PipelineError::Cancelled { .. }));
    }

    #[test]
    fn pipeline_to_result_panicked() {
        let result: PipelineResult<i32, &str> =
            PipelineResult::panicked(PanicPayload::new("boom"), FailedStage::new(2, 3));
        let err = pipeline_to_result(result).unwrap_err();
        assert!(matches!(err, PipelineError::Panicked { .. }));
    }

    // =========================================================================
    // PipelineError Tests
    // =========================================================================

    #[test]
    fn pipeline_error_display_stage_error() {
        let err: PipelineError<&str> = PipelineError::StageError {
            error: "test error",
            stage: FailedStage::new(1, 3),
        };
        let display = err.to_string();
        assert!(display.contains("stage 2/3"));
        assert!(display.contains("test error"));
    }

    #[test]
    fn pipeline_error_display_cancelled() {
        let err: PipelineError<&str> = PipelineError::Cancelled {
            reason: CancelReason::shutdown(),
            stage: FailedStage::new(0, 2),
        };
        let display = err.to_string();
        assert!(display.contains("cancelled"));
        assert!(display.contains("stage 1/2"));
    }

    #[test]
    fn pipeline_error_display_panicked() {
        let err: PipelineError<&str> = PipelineError::Panicked {
            payload: PanicPayload::new("boom"),
            stage: FailedStage::new(2, 3),
        };
        let display = err.to_string();
        assert!(display.contains("panicked"));
        assert!(display.contains("boom"));
    }

    // =========================================================================
    // pipeline_n_outcomes Tests
    // =========================================================================

    #[test]
    fn pipeline_n_all_ok() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let result = pipeline_n_outcomes(outcomes, 3);

        assert!(result.is_completed());
        if let PipelineResult::Completed {
            value,
            stages_completed,
        } = result
        {
            assert_eq!(value, 3);
            assert_eq!(stages_completed, 3);
        } else {
            unreachable!("Expected Completed");
        }
    }

    #[test]
    fn pipeline_n_first_error() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("fail"), Outcome::Ok(2)];
        let result = pipeline_n_outcomes(outcomes, 3);

        assert!(result.is_failed());
        if let PipelineResult::Failed { error, failed_at } = result {
            assert_eq!(error, "fail");
            assert_eq!(failed_at.index, 0);
            assert_eq!(failed_at.total_stages, 3);
        } else {
            unreachable!("Expected Failed");
        }
    }

    #[test]
    fn pipeline_n_middle_cancel() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Cancelled(CancelReason::shutdown())];
        let result = pipeline_n_outcomes(outcomes, 4);

        assert!(result.is_cancelled());
        if let PipelineResult::Cancelled { cancelled_at, .. } = result {
            assert_eq!(cancelled_at.index, 1);
            assert_eq!(cancelled_at.total_stages, 4);
        } else {
            panic!("Expected Cancelled");
        }
    }

    #[test]
    #[should_panic(expected = "all successful outcomes must cover every pipeline stage")]
    fn pipeline_n_all_ok_partial_run_is_rejected() {
        // Provide fewer outcomes than total_stages, all Ok
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(10), Outcome::Ok(20)];
        let _ = pipeline_n_outcomes(outcomes, 5);
    }

    #[test]
    fn pipeline_n_single_ok() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(42)];
        let result = pipeline_n_outcomes(outcomes, 1);

        assert!(result.is_completed());
        if let PipelineResult::Completed {
            value,
            stages_completed,
        } = result
        {
            assert_eq!(value, 42);
            assert_eq!(stages_completed, 1);
        } else {
            unreachable!("Expected Completed");
        }
    }

    #[test]
    fn pipeline_n_single_error() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Err("only stage fails")];
        let result = pipeline_n_outcomes(outcomes, 1);

        assert!(result.is_failed());
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 0);
            assert!(failed_at.is_first());
            assert!(failed_at.is_last());
        } else {
            unreachable!("Expected Failed");
        }
    }

    #[test]
    fn pipeline_n_panic_mid_pipeline() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Ok(2),
            Outcome::Panicked(PanicPayload::new("stage 3 panicked")),
        ];
        let result = pipeline_n_outcomes(outcomes, 4);

        assert!(result.is_panicked());
        if let PipelineResult::Panicked { panicked_at, .. } = result {
            assert_eq!(panicked_at.index, 2);
            assert_eq!(panicked_at.total_stages, 4);
        } else {
            panic!("Expected Panicked");
        }
    }

    #[test]
    #[should_panic(expected = "outcomes must not be empty")]
    fn pipeline_n_empty_outcomes_panics() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![];
        let _ = pipeline_n_outcomes(outcomes, 3);
    }

    #[test]
    #[should_panic(expected = "more outcomes than stages")]
    fn pipeline_n_too_many_outcomes_panics() {
        let outcomes: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
        let _ = pipeline_n_outcomes(outcomes, 2);
    }

    // =========================================================================
    // pipeline_with_final Validation Tests
    // =========================================================================

    #[test]
    #[should_panic(expected = "total_stages must be positive")]
    fn pipeline_with_final_zero_stages_panics() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![];
        let _ = pipeline_with_final(intermediates, Outcome::Ok(42), 0);
    }

    #[test]
    #[should_panic(expected = "must equal total_stages")]
    fn pipeline_with_final_mismatched_stages_panics() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1)];
        // 1 intermediate + 1 final = 2, but total_stages = 5
        let _ = pipeline_with_final(intermediates, Outcome::Ok(42), 5);
    }

    #[test]
    fn pipeline_with_final_cancelled_final() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let result = pipeline_with_final(
            intermediates,
            Outcome::Cancelled(CancelReason::shutdown()),
            3,
        );

        assert!(result.is_cancelled());
        if let PipelineResult::Cancelled { cancelled_at, .. } = result {
            assert_eq!(cancelled_at.index, 2);
            assert!(cancelled_at.is_last());
        } else {
            panic!("Expected Cancelled");
        }
    }

    #[test]
    fn pipeline_with_final_panicked_final() {
        let intermediates: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1)];
        let result = pipeline_with_final(
            intermediates,
            Outcome::Panicked(PanicPayload::new("final boom")),
            2,
        );

        assert!(result.is_panicked());
        if let PipelineResult::Panicked { panicked_at, .. } = result {
            assert_eq!(panicked_at.index, 1);
            assert!(panicked_at.is_last());
        } else {
            panic!("Expected Panicked");
        }
    }

    #[test]
    fn pipeline_with_final_single_stage() {
        // 0 intermediates + 1 final = 1 total stage
        let intermediates: Vec<Outcome<i32, &str>> = vec![];
        let result = pipeline_with_final(intermediates, Outcome::Ok(99), 1);

        assert!(result.is_completed());
        if let PipelineResult::Completed { value, .. } = result {
            assert_eq!(value, 99);
        } else {
            unreachable!("Expected Completed");
        }
    }

    // =========================================================================
    // Invariant Tests
    // =========================================================================

    #[test]
    fn error_short_circuits_at_first_failure() {
        // Simulate a 5-stage pipeline where stage 2 (index 2) fails.
        // pipeline_with_final requires intermediates.len() + 1 == total_stages,
        // so provide all 4 intermediates even though short-circuit stops at stage 2.
        let intermediates: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Ok(2),
            Outcome::Err("stage 3 failed"),
            Outcome::Ok(4), // Never reached due to short-circuit
        ];
        let result = pipeline_with_final(intermediates, Outcome::Ok(999), 5);

        assert!(result.is_failed());
        assert_eq!(result.stages_executed(), 3); // Executed stages 0, 1, 2
        if let PipelineResult::Failed { failed_at, .. } = result {
            assert_eq!(failed_at.index, 2);
            assert_eq!(failed_at.total_stages, 5);
        }
    }

    #[test]
    fn cancelled_stops_at_boundary() {
        let intermediates: Vec<Outcome<i32, &str>> =
            vec![Outcome::Ok(1), Outcome::Cancelled(CancelReason::shutdown())];
        let result = pipeline_with_final(intermediates, Outcome::Ok(42), 3);

        assert!(result.is_cancelled());
        // Stage 0 succeeded, stage 1 cancelled
        if let PipelineResult::Cancelled { cancelled_at, .. } = result {
            assert_eq!(cancelled_at.index, 1);
        }
    }

    #[test]
    fn stages_executed_reflects_actual_execution() {
        // All stages complete
        let completed: PipelineResult<i32, &str> = PipelineResult::completed(42, 5);
        assert_eq!(completed.stages_executed(), 5);

        // Failed at stage 2 (index 1)
        let failed: PipelineResult<i32, &str> =
            PipelineResult::failed("err", FailedStage::new(1, 5));
        assert_eq!(failed.stages_executed(), 2); // Stages 0 and 1 were executed

        // Cancelled before stage 3 (index 2)
        let cancelled: PipelineResult<i32, &str> =
            PipelineResult::cancelled(CancelReason::shutdown(), FailedStage::new(2, 5));
        assert_eq!(cancelled.stages_executed(), 2); // Stages 0 and 1 completed
    }

    // =========================================================================
    // Wave 54 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn pipeline_config_debug_clone_copy_eq_default() {
        let cfg = PipelineConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("PipelineConfig"), "{dbg}");
        let copied = cfg;
        let cloned = cfg;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn failed_stage_debug_clone_copy_eq() {
        let fs = FailedStage::new(2, 5);
        let dbg = format!("{fs:?}");
        assert!(dbg.contains("FailedStage"), "{dbg}");
        let copied = fs;
        let cloned = fs;
        assert_eq!(copied, cloned);
        assert_ne!(fs, FailedStage::new(3, 5));
    }

    // =========================================================================
    // Composition laws (conformance suite).
    //
    // The four public pipeline constructors —
    //     pipeline2_outcomes, pipeline3_outcomes,
    //     pipeline_n_outcomes, pipeline_with_final
    // — must agree on every input they can all represent. These laws encode
    // that contract so an accidental short-circuit or failed_at mismatch in
    // one constructor does not escape review.
    // =========================================================================

    mod composition_laws {
        use super::super::*;
        use crate::types::Outcome;
        use crate::types::cancel::CancelReason;

        /// Compare two PipelineResults ignoring Panicked payload identity
        /// (PanicPayload does not implement PartialEq on the inner Any).
        #[track_caller]
        fn assert_same_shape<T: std::fmt::Debug + PartialEq, E: std::fmt::Debug + PartialEq>(
            lhs: &PipelineResult<T, E>,
            rhs: &PipelineResult<T, E>,
        ) {
            match (lhs, rhs) {
                (
                    PipelineResult::Completed {
                        value: v1,
                        stages_completed: s1,
                    },
                    PipelineResult::Completed {
                        value: v2,
                        stages_completed: s2,
                    },
                ) => {
                    assert_eq!(v1, v2, "completed values diverge");
                    assert_eq!(s1, s2, "stages_completed diverges");
                }
                (
                    PipelineResult::Failed {
                        error: e1,
                        failed_at: f1,
                    },
                    PipelineResult::Failed {
                        error: e2,
                        failed_at: f2,
                    },
                ) => {
                    assert_eq!(e1, e2, "failed errors diverge");
                    assert_eq!(f1, f2, "failed_at diverges");
                }
                (
                    PipelineResult::Cancelled {
                        reason: r1,
                        cancelled_at: f1,
                    },
                    PipelineResult::Cancelled {
                        reason: r2,
                        cancelled_at: f2,
                    },
                ) => {
                    assert_eq!(r1, r2, "cancel reasons diverge");
                    assert_eq!(f1, f2, "cancelled_at diverges");
                }
                (
                    PipelineResult::Panicked {
                        panicked_at: f1, ..
                    },
                    PipelineResult::Panicked {
                        panicked_at: f2, ..
                    },
                ) => {
                    assert_eq!(f1, f2, "panicked_at diverges");
                }
                (lhs, rhs) => panic!("variant mismatch:\n  lhs={lhs:?}\n  rhs={rhs:?}"),
            }
        }

        /// LAW-1: `pipeline2_outcomes` and `pipeline_n_outcomes` agree on the
        /// full 2-stage input matrix. Every Outcome shape is checked for both
        /// stages.
        #[test]
        fn law_pipeline2_equiv_pipeline_n_across_outcome_matrix() {
            fn outcomes() -> Vec<Outcome<i32, &'static str>> {
                vec![
                    Outcome::Ok(1),
                    Outcome::Err("boom"),
                    Outcome::Cancelled(CancelReason::user("test")),
                ]
            }
            for o1 in outcomes() {
                for o2 in outcomes() {
                    let lhs = pipeline2_outcomes::<i32, &'static str>(o1.clone(), Some(o2.clone()));
                    let rhs =
                        pipeline_n_outcomes::<i32, &'static str>(vec![o1.clone(), o2.clone()], 2);
                    assert_same_shape(&lhs, &rhs);
                }
            }
        }

        /// LAW-2: `pipeline3_outcomes` and `pipeline_n_outcomes` agree on the
        /// 3-stage matrix. Short-circuit means pipeline3 is only called with
        /// None for stages after a non-Ok, so we only compare the complete
        /// [Ok, Ok, X] and [Ok, X] branches.
        #[test]
        fn law_pipeline3_equiv_pipeline_n() {
            let terminal_shapes: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(3),
                Outcome::Err("boom"),
                Outcome::Cancelled(CancelReason::user("test")),
            ];
            // All-three-stages-executed branch: [Ok, Ok, X]
            for term in terminal_shapes.iter() {
                let lhs = pipeline3_outcomes::<i32, &'static str>(
                    Outcome::Ok(1),
                    Some(Outcome::Ok(2)),
                    Some(term.clone()),
                );
                let rhs = pipeline_n_outcomes::<i32, &'static str>(
                    vec![Outcome::Ok(1), Outcome::Ok(2), term.clone()],
                    3,
                );
                assert_same_shape(&lhs, &rhs);
            }
            // Short-circuit at stage 2: [Ok, X, None]. pipeline_n sees the
            // 2-element vec since the third stage never ran.
            for term in terminal_shapes
                .iter()
                .filter(|o| !matches!(o, Outcome::Ok(_)))
            {
                let lhs = pipeline3_outcomes::<i32, &'static str>(
                    Outcome::Ok(1),
                    Some(term.clone()),
                    None,
                );
                let rhs =
                    pipeline_n_outcomes::<i32, &'static str>(vec![Outcome::Ok(1), term.clone()], 3);
                assert_same_shape(&lhs, &rhs);
            }
        }

        /// LAW-3: `pipeline_with_final` agrees with `pipeline_n_outcomes` when
        /// the caller supplies a full run (intermediates.len() + 1 == total).
        #[test]
        fn law_pipeline_with_final_equiv_pipeline_n_for_complete_runs() {
            let sample: Vec<Outcome<i32, &'static str>> =
                vec![Outcome::Ok(10), Outcome::Ok(20), Outcome::Ok(30)];
            let final_variants: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(99),
                Outcome::Err("late"),
                Outcome::Cancelled(CancelReason::user("test")),
            ];
            for final_out in final_variants {
                let mut full = sample.clone();
                full.push(final_out.clone());
                let total = full.len();
                let lhs =
                    pipeline_with_final::<i32, &'static str>(sample.clone(), final_out, total);
                let rhs = pipeline_n_outcomes::<i32, &'static str>(full, total);
                assert_same_shape(&lhs, &rhs);
            }
        }

        /// LAW-4: Short-circuit is strict — a non-Ok at index N makes the
        /// result depend only on outcomes[..=N]. Trailing Oks in the vec are
        /// ignored, i.e. passing them vs truncating yields the same result.
        #[test]
        fn law_short_circuit_ignores_trailing_outcomes() {
            let with_trailing: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(1),
                Outcome::Err("midway"),
                Outcome::Ok(999),    // ignored
                Outcome::Ok(12_345), // ignored
            ];
            let truncated: Vec<Outcome<i32, &'static str>> = with_trailing[..2].to_vec();
            let lhs = pipeline_n_outcomes::<i32, &'static str>(with_trailing, 5);
            let rhs = pipeline_n_outcomes::<i32, &'static str>(truncated, 5);
            assert_same_shape(&lhs, &rhs);
        }

        /// LAW-5: `failed_at.total_stages` is exactly the caller-supplied
        /// total across every failure mode in every constructor, even when
        /// the vec is shorter than total.
        #[test]
        fn law_failed_at_total_stages_is_preserved() {
            for &total in &[1usize, 2, 3, 5, 10] {
                // 2-variant: o1 fails
                let r = pipeline2_outcomes::<i32, &'static str>(Outcome::Err("x"), None);
                if let PipelineResult::Failed { failed_at, .. } = r {
                    assert_eq!(failed_at.total_stages, 2);
                }
                // n-variant: fail at index 0 with various totals
                let r =
                    pipeline_n_outcomes::<i32, &'static str>(vec![Outcome::Err("x")], total.max(1));
                if let PipelineResult::Failed { failed_at, .. } = r {
                    assert_eq!(failed_at.total_stages, total.max(1));
                    assert_eq!(failed_at.index, 0);
                }
            }
        }

        /// LAW-6: Cancel and panic precedence — a Cancelled or Panicked at
        /// index N wins over any later Ok/Err in the vec. Distinct from a
        /// plain Err because the failure category carries different recovery
        /// semantics downstream.
        #[test]
        fn law_cancelled_and_panicked_beat_later_outcomes() {
            let vec_with_late_ok: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(1),
                Outcome::Cancelled(CancelReason::user("test")),
                Outcome::Ok(2),
            ];
            let r = pipeline_n_outcomes::<i32, &'static str>(vec_with_late_ok, 3);
            match r {
                PipelineResult::Cancelled { cancelled_at, .. } => {
                    assert_eq!(cancelled_at.index, 1);
                    assert_eq!(cancelled_at.total_stages, 3);
                }
                other => panic!("expected Cancelled, got {other:?}"),
            }

            let vec_with_panic: Vec<Outcome<i32, &'static str>> = vec![
                Outcome::Ok(1),
                Outcome::Panicked(PanicPayload::new("boom")),
                Outcome::Err("late"),
            ];
            let r = pipeline_n_outcomes::<i32, &'static str>(vec_with_panic, 3);
            match r {
                PipelineResult::Panicked { panicked_at, .. } => {
                    assert_eq!(panicked_at.index, 1);
                    assert_eq!(panicked_at.total_stages, 3);
                }
                other => panic!("expected Panicked, got {other:?}"),
            }
        }

        /// LAW-7: Single-stage identity — pipeline_n_outcomes of a single Ok
        /// equals Completed(value, 1).
        #[test]
        fn law_single_stage_ok_is_identity() {
            let r = pipeline_n_outcomes::<i32, &'static str>(vec![Outcome::Ok(42)], 1);
            match r {
                PipelineResult::Completed {
                    value,
                    stages_completed,
                } => {
                    assert_eq!(value, 42);
                    assert_eq!(stages_completed, 1);
                }
                other => panic!("expected Completed(42, 1), got {other:?}"),
            }
        }

        /// LAW-8: Completion is total — an all-Ok vec shorter than
        /// total_stages is invalid constructor input, never a Completed
        /// result.
        #[test]
        fn law_all_ok_partial_run_is_rejected() {
            let result = std::panic::catch_unwind(|| {
                pipeline_n_outcomes::<i32, &'static str>(vec![Outcome::Ok(1), Outcome::Ok(2)], 5)
            });
            assert!(
                result.is_err(),
                "an incomplete all-Ok run must not produce a PipelineResult"
            );
        }
    }
