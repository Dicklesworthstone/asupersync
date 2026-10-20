//! Holder, quota, and exact terminal accounting for the owned H1 body path.

#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use crate::lab::{LabConfig, LabRuntime};
use crate::record::{ObligationAbortReason, ObligationKind, ObligationState};
use crate::runtime::obligation_mailbox::{
    ObligationAdmissionError, apply_obligation_posts,
};
use crate::runtime::{JoinError, TaskHandle};
use crate::trace::{TraceData, TraceEventKind};
use crate::types::Budget;

fn fixture(limit: usize) -> (LabRuntime, Cx, TaskHandle<()>) {
    crate::test_utils::init_test_logging();
    let mut lab = LabRuntime::new(LabConfig::new(0xb0d9_a001).max_steps(512));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let region = lab.state.create_child_region(root, Budget::INFINITE).unwrap();
    assert!(lab.state.set_region_limits(
        region,
        crate::record::region::RegionLimits {
            max_obligations: Some(limit),
            ..crate::record::region::RegionLimits::UNLIMITED
        },
    ));
    let (task, handle) = lab.state.create_task(region, Budget::INFINITE, async {}).unwrap();
    let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
    (lab, cx, handle)
}

fn flush(lab: &mut LabRuntime) {
    let gateway = lab.state.obligation_gateway().unwrap();
    let mailbox = Arc::clone(gateway.mailbox());
    apply_obligation_posts(&mut lab.state, &mailbox, usize::MAX);
}

fn poll_body(body: &mut IncomingRequestBody) -> Poll<Option<Result<Frame<BytesCursor>, IncomingBodyError>>> {
    Pin::new(body).poll_frame(&mut Context::from_waker(Waker::noop()))
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("operation must complete without waiting"),
    }
}

fn assert_live(lab: &mut LabRuntime, cx: &Cx) {
    flush(lab);
    let live: Vec<_> = lab.state.obligations_iter().filter_map(|(_, record)| {
        (record.kind == ObligationKind::IoOp && record.state == ObligationState::Reserved)
            .then_some(record)
    }).collect();
    assert_eq!(live.len(), 1, "one protocol body, independently of frame permits");
    assert_eq!(live[0].holder, cx.task_id());
    assert_eq!(live[0].region, cx.region_id());
    assert_eq!(lab.state.pending_obligation_count_for_kind(ObligationKind::IoOp), 1);
}

fn assert_terminal(lab: &mut LabRuntime, cx: &Cx, abort: Option<ObligationAbortReason>) {
    flush(lab);
    let trace = lab.state.trace_handle().snapshot();
    let body: Vec<_> = trace.iter().filter(|event| matches!(event.data,
        TraceData::Obligation { task, kind: ObligationKind::IoOp, .. }
        if task == cx.task_id()
    )).collect();
    assert_eq!(body.iter().filter(|event| event.kind == TraceEventKind::ObligationReserve).count(), 1);
    let terminal: Vec<_> = body.iter().filter(|event| matches!(event.kind,
        TraceEventKind::ObligationCommit | TraceEventKind::ObligationAbort | TraceEventKind::ObligationLeak
    )).collect();
    assert_eq!(terminal.len(), 1, "body credit resolves exactly once");
    let expected = if abort.is_some() { TraceEventKind::ObligationAbort } else { TraceEventKind::ObligationCommit };
    assert_eq!(terminal[0].kind, expected);
    assert!(matches!(terminal[0].data,
        TraceData::Obligation { abort_reason, .. } if abort_reason == abort
    ));
    assert_eq!(lab.state.pending_obligation_count_for_kind(ObligationKind::IoOp), 0);
    assert_eq!(lab.state.leak_count(), 0);
}

fn retire(mut lab: LabRuntime, cx: &Cx, mut handle: TaskHandle<()>) {
    flush(&mut lab);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    lab.scheduler.lock().schedule(cx.task_id(), 0);
    let report = lab.run_until_quiescent_with_report();
    assert!(report.invariant_violations.is_empty(), "{report:?}");
    assert!(report.oracle_report.all_passed(), "{:?}", report.oracle_report.failures());
    assert!(matches!(handle.try_join(), Ok(Some(())) | Err(JoinError::Cancelled(_))));
    let gateway = lab.state.obligation_gateway().unwrap();
    assert_eq!(gateway.mailbox().open_tickets(), 0);
    assert_eq!(gateway.mailbox().stats().leaked, 0);
}

#[test]
fn checked_body_tracks_its_actual_holder_until_protocol_eof() {
    let (mut lab, cx, handle) = fixture(4);
    let (mut writer, mut body) = IncomingRequestBody::channel_with_limits_checked(
        &cx, BodyKind::ContentLength(3), 1, 3, 3,
    ).unwrap();
    assert!(poll_body(&mut body).is_pending());
    assert_live(&mut lab, &cx);
    ready(writer.push_bytes(&cx, b"abc")).unwrap();
    assert_eq!(body.queued_bytes(), 3);
    assert!(writer.drain_progress().synchronized_eof);
    writer.finish(&cx).unwrap();
    writer.finish(&cx).unwrap();
    assert_terminal(&mut lab, &cx, None);
    let Poll::Ready(Some(Ok(frame))) = poll_body(&mut body) else { panic!("queued body data"); };
    assert_eq!(frame.into_data().unwrap().chunk(), b"abc");
    assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
    assert!(matches!(poll_body(&mut body), Poll::Ready(Some(Err(IncomingBodyError::AlreadyTerminal)))));
    drop(writer);
    drop(body);
    assert_terminal(&mut lab, &cx, None);
    retire(lab, &cx, handle);
}

#[test]
fn consumer_drop_retains_credit_through_bounded_discard_and_remainder() {
    let (mut lab, cx, handle) = fixture(4);
    let (mut writer, body) = IncomingRequestBody::channel_with_limits_checked(
        &cx, BodyKind::ContentLength(4), 1, 2, 4,
    ).unwrap();
    ready(writer.push_bytes(&cx, b"ab")).unwrap();
    drop(body);
    assert!(writer.consumer_dropped());
    let progress = writer.discard_bytes(&[]).unwrap();
    assert_eq!(progress.bytes, 2);
    assert!(!progress.synchronized_eof);
    assert!(writer.sender.is_none(), "no channel sender owns the remaining drain");
    assert_live(&mut lab, &cx);
    let progress = writer.discard_bytes(b"cdNEXT").unwrap();
    assert_eq!(progress.bytes, 4);
    assert_eq!(progress.frames, 2);
    assert!(progress.synchronized_eof);
    assert_eq!(writer.take_remainder().as_ref(), b"NEXT");
    drop(writer);
    assert_terminal(&mut lab, &cx, None);
    retire(lab, &cx, handle);
}

#[test]
fn dropping_unfinished_discard_aborts_even_without_a_sender() {
    let (mut lab, cx, handle) = fixture(1);
    let (mut writer, body) = IncomingRequestBody::channel_with_limits_checked(
        &cx, BodyKind::ContentLength(4), 1, 4, 4,
    ).unwrap();
    drop(body);
    assert!(!writer.discard_bytes(b"a").unwrap().synchronized_eof);
    assert!(writer.sender.is_none());
    assert_live(&mut lab, &cx);
    drop(writer);
    assert_terminal(&mut lab, &cx, Some(ObligationAbortReason::Error));
    retire(lab, &cx, handle);
}

#[test]
fn producer_backpressure_cancellation_aborts_without_certifying_eof() {
    let (mut lab, cx, handle) = fixture(4);
    let (mut writer, mut body) = IncomingRequestBody::channel_with_limits_checked(
        &cx, BodyKind::ContentLength(4), 1, 2, 4,
    ).unwrap();
    ready(writer.push_bytes(&cx, b"ab")).unwrap();
    {
        let mut pushing = std::pin::pin!(writer.push_bytes(&cx, b"cd"));
        assert!(pushing.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        assert_live(&mut lab, &cx);
        assert_eq!(body.queued_bytes(), 2);
        cx.cancel_fast(CancelKind::Deadline);
        assert!(matches!(pushing.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(IncomingBodyError::Cancelled { kind: CancelKind::Deadline }))
        ));
    }
    assert!(!writer.drain_progress().synchronized_eof);
    assert!(writer.take_remainder().is_empty());
    assert!(matches!(poll_body(&mut body), Poll::Ready(Some(Err(IncomingBodyError::Cancelled { kind: CancelKind::Deadline })))));
    drop(body);
    drop(writer);
    assert_terminal(&mut lab, &cx, Some(ObligationAbortReason::Cancel));
    retire(lab, &cx, handle);
}

#[test]
fn checked_writer_drop_preserves_owner_cancellation_kind() {
    let (mut lab, cx, handle) = fixture(1);
    let (writer, mut body) = IncomingRequestBody::channel_with_limits_checked(
        &cx, BodyKind::ContentLength(1), 1, 1, 1,
    ).unwrap();
    assert!(poll_body(&mut body).is_pending());
    assert_live(&mut lab, &cx);
    cx.cancel_fast(CancelKind::Shutdown);
    drop(writer);
    assert!(matches!(poll_body(&mut body), Poll::Ready(Some(Err(IncomingBodyError::Cancelled { kind: CancelKind::Shutdown })))));
    drop(body);
    assert_terminal(&mut lab, &cx, Some(ObligationAbortReason::Cancel));
    retire(lab, &cx, handle);
}

#[test]
fn first_framing_failure_survives_later_cancel_and_never_claims_eof() {
    let (mut lab, cx, handle) = fixture(2);
    let (mut writer, mut body) = IncomingRequestBody::channel_with_limits_checked(
        &cx, BodyKind::Chunked, 1, 8, 8,
    ).unwrap();
    assert_eq!(ready(writer.push_bytes(&cx, b"G\r\n")), Err(IncomingBodyError::BadChunkedEncoding));
    writer.fail(IncomingBodyError::ClientAborted);
    cx.cancel_fast(CancelKind::Shutdown);
    assert!(!writer.drain_progress().synchronized_eof);
    assert!(writer.take_remainder().is_empty());
    assert!(matches!(poll_body(&mut body), Poll::Ready(Some(Err(IncomingBodyError::BadChunkedEncoding)))));
    drop(writer);
    drop(body);
    assert_terminal(&mut lab, &cx, Some(ObligationAbortReason::Error));
    retire(lab, &cx, handle);
}

#[test]
fn static_limit_and_quota_refusal_publish_no_body_or_credit() {
    let (mut lab, cx, handle) = fixture(0);
    assert!(matches!(IncomingRequestBody::channel_with_limits_checked(
        &cx, BodyKind::ContentLength(2), 1, 2, 1,
    ), Err(IncomingBodyAdmissionError::Policy(IncomingBodyError::BodyTooLarge { actual: Some(2), limit: 1 }))));
    assert!(matches!(IncomingRequestBody::channel_with_limits_checked(
        &cx, BodyKind::ContentLength(1), 1, 1, 1,
    ), Err(IncomingBodyAdmissionError::Runtime(ObligationAdmissionError::LimitReached { limit: 0, live: 0 }))));
    // The established constructor retains its stateless/unchecked API.
    let (writer, body) = IncomingRequestBody::channel_with_limits(&cx, BodyKind::Empty, 1, 1);
    drop(writer);
    drop(body);
    flush(&mut lab);
    assert_eq!(lab.state.obligation_gateway().unwrap().mailbox().stats().reserved, 0);
    retire(lab, &cx, handle);
}

#[test]
fn stateless_cancelled_and_retired_holders_cannot_admit_checked_bodies() {
    assert!(matches!(IncomingRequestBody::channel_with_limits_checked(
        &Cx::for_testing(), BodyKind::Empty, 1, 1, 1,
    ), Err(IncomingBodyAdmissionError::RuntimeRequired)));
    let (mut lab, cx, mut handle) = fixture(1);
    cx.cancel_fast(CancelKind::Timeout);
    assert!(matches!(IncomingRequestBody::channel_with_limits_checked(
        &cx, BodyKind::Empty, 1, 1, 1,
    ), Err(IncomingBodyAdmissionError::Cancelled { kind: CancelKind::Timeout })));
    flush(&mut lab);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    lab.scheduler.lock().schedule(cx.task_id(), 0);
    lab.run_until_quiescent();
    assert!(matches!(handle.try_join(), Ok(Some(())) | Err(JoinError::Cancelled(_))));
    let (mut lab, cx, mut handle) = fixture(1);
    lab.scheduler.lock().schedule(cx.task_id(), 0);
    lab.run_until_quiescent();
    assert_eq!(handle.try_join().unwrap(), Some(()));
    assert!(matches!(IncomingRequestBody::channel_with_limits_checked(
        &cx, BodyKind::Empty, 1, 1, 1,
    ), Err(IncomingBodyAdmissionError::Runtime(ObligationAdmissionError::HolderNotLive))));
    assert_eq!(lab.state.pending_obligation_count(), 0);
}

#[test]
fn admitted_empty_body_commits_its_single_credit_immediately() {
    for kind in [BodyKind::Empty, BodyKind::ContentLength(0)] {
        let (mut lab, cx, handle) = fixture(1);
        let (writer, mut body) = IncomingRequestBody::channel_with_limits_checked(
            &cx, kind, 1, 1, 0,
        ).unwrap();
        assert!(writer.drain_progress().synchronized_eof);
        assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
        drop(writer);
        drop(body);
        assert_terminal(&mut lab, &cx, None);
        retire(lab, &cx, handle);
    }
}

#[cfg(any(feature = "http2-streaming", all(feature = "http3", feature = "tls")))]
mod framed {
    use super::*;
    use crate::channel::oneshot;
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder, RuntimeHandle};
    use crate::trace::TraceEvent;
    use crate::types::ObligationId;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    use std::time::Duration;

    fn native<F, Fut>(scenario: F)
    where
        F: Fn(Cx, RuntimeHandle) -> Fut + Copy + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                for workers in [1, 2] {
                    for sharded in [false, true] {
                        let builder = if workers == 1 {
                            RuntimeBuilder::current_thread()
                        } else {
                            RuntimeBuilder::new().worker_threads(workers)
                        };
                        let runtime = builder.with_sharded_state(sharded).build().unwrap();
                        runtime.block_on(async {
                            let root = Cx::current().unwrap();
                            let handle = runtime.handle();
                            let mut task = root.spawn(move |cx| scenario(cx, handle)).unwrap();
                            task.join(&root).await.unwrap();
                        });
                        let report = runtime.shutdown_drained(Duration::from_secs(5));
                        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                        assert_eq!(report.live_tasks, 0);
                        assert_eq!(report.pending_spawns, 0);
                        assert_eq!(report.pending_obligations, 0);
                    }
                }
            }));
            let _ = send.send(result);
        });
        let result = receive.recv_timeout(Duration::from_secs(40))
            .expect("framed body owner and retained writer must retire");
        worker.join().unwrap();
        if let Err(payload) = result {
            resume_unwind(payload);
        }
    }

    fn events<'a>(trace: &'a [TraceEvent], owner: &Cx) -> Vec<(usize, &'a TraceEvent)> {
        trace.iter().enumerate().filter(|(_, event)| matches!(event.data,
            TraceData::Obligation { task, region, kind: ObligationKind::IoOp, .. }
            if task == owner.task_id() && region == owner.region_id()
        )).collect()
    }

    async fn pending_credit(runtime: &RuntimeHandle, owner: &Cx) -> ObligationId {
        loop {
            let trace = runtime.trace_snapshot().unwrap();
            let events = events(&trace, owner);
            if let Some((_, reserve)) = events.first() {
                assert_eq!(events.len(), 1, "one unresolved credit at actual work Pending");
                assert_eq!(reserve.kind, TraceEventKind::ObligationReserve);
                let TraceData::Obligation { obligation, .. } = reserve.data else {
                    unreachable!("filtered obligation");
                };
                return obligation;
            }
            crate::runtime::yield_now().await;
        }
    }

    async fn settled(
        runtime: &RuntimeHandle,
        owner: &Cx,
        credit: ObligationId,
        abort: Option<ObligationAbortReason>,
        completed: bool,
    ) {
        loop {
            let trace = runtime.trace_snapshot().unwrap();
            let events = events(&trace, owner);
            if events.len() < 2 {
                crate::runtime::yield_now().await;
                continue;
            }
            assert_eq!(events.len(), 2, "one reserve and one terminal verdict");
            assert_eq!(events[0].1.kind, TraceEventKind::ObligationReserve);
            assert_eq!(events[1].1.kind, if abort.is_some() {
                TraceEventKind::ObligationAbort
            } else {
                TraceEventKind::ObligationCommit
            });
            assert!(matches!(events[1].1.data,
                TraceData::Obligation { obligation, abort_reason, .. }
                if obligation == credit && abort_reason == abort
            ));
            let retired = trace.iter().position(|event| {
                event.kind == TraceEventKind::Complete
                    && matches!(event.data, TraceData::Task { task, .. }
                        if task == owner.task_id())
            });
            if completed {
                assert!(events[1].0 < retired.expect("actual holder completed"));
            } else {
                assert!(retired.is_none(), "wire terminal settles while holder is still parked");
            }
            return;
        }
    }

    async fn explicit_fin(cx: Cx, runtime: RuntimeHandle) {
        let (source_tx, mut source_rx) = oneshot::channel();
        let (parked_tx, mut parked_rx) = oneshot::channel();
        let (release_tx, mut release_rx) = oneshot::channel();
        let mut task = cx.spawn(move |owner| async move {
            let (writer, body, guard) = IncomingRequestBody::framed_channel_with_limits_checked(
                &owner, Some(0), 1, 8, 0,
            ).unwrap();
            source_tx.send_blocking((owner.clone(), writer, body)).unwrap();
            guard.run(async {
                let mut parked = Some(parked_tx);
                let mut waiting = std::pin::pin!(release_rx.recv(&owner));
                std::future::poll_fn(|task_cx| {
                    let result = waiting.as_mut().poll(task_cx);
                    if result.is_pending() {
                        if let Some(parked) = parked.take() {
                            parked.send_blocking(()).unwrap();
                        }
                    }
                    result
                }).await.unwrap();
            }).await;
        }).unwrap();
        let (owner, mut writer, mut body) = source_rx.recv(&cx).await.unwrap();
        parked_rx.recv(&cx).await.unwrap();
        assert!(!body.is_end_stream());
        assert!(poll_body(&mut body).is_pending());
        let credit = pending_credit(&runtime, &owner).await;
        writer.finish(&owner).unwrap();
        writer.finish(&owner).unwrap();
        assert!(matches!(poll_body(&mut body), Poll::Ready(None)),
            "guard must not keep the sender alive after explicit FIN");
        settled(&runtime, &owner, credit, None, false).await;
        assert!(!task.is_finished(), "a terminal wake must settle without completing user work");
        release_tx.send_blocking(()).unwrap();
        task.join(&cx).await.unwrap();
        drop(writer);
        drop(body);
        settled(&runtime, &owner, credit, None, true).await;
    }

    #[test]
    fn checked_framed_native_fin_settles_while_the_real_holder_remains_parked() {
        native(explicit_fin);
    }

    #[derive(Clone, Copy)]
    enum Exit {
        EarlyResponse,
        Panic,
        Cancel,
        FailureThenCancel,
    }

    async fn retained_writer(cx: Cx, runtime: RuntimeHandle) {
        for exit in [Exit::EarlyResponse, Exit::Panic, Exit::Cancel, Exit::FailureThenCancel] {
            let (source_tx, mut source_rx) = oneshot::channel();
            let (parked_tx, mut parked_rx) = oneshot::channel();
            let (release_tx, mut release_rx) = oneshot::channel();
            let mut task = cx.spawn(move |owner| async move {
                let (writer, body, guard) = IncomingRequestBody::framed_channel_with_limits_checked(
                    &owner, None, 1, 8, 8,
                ).unwrap();
                source_tx.send_blocking((owner.clone(), writer, body)).unwrap();
                guard.run(async {
                    let mut parked = Some(parked_tx);
                    if matches!(exit, Exit::Cancel | Exit::FailureThenCancel) {
                        // Deliberately cancellation-blind after an actual
                        // Pending witness, forcing the wrapper to drop this
                        // work while the connection-side writer stays live.
                        std::future::poll_fn(|_| {
                            if let Some(parked) = parked.take() {
                                parked.send_blocking(()).unwrap();
                            }
                            Poll::<()>::Pending
                        }).await;
                    } else {
                        let mut waiting = std::pin::pin!(release_rx.recv(&owner));
                        std::future::poll_fn(|task_cx| {
                            let result = waiting.as_mut().poll(task_cx);
                            if result.is_pending() {
                                if let Some(parked) = parked.take() {
                                    parked.send_blocking(()).unwrap();
                                }
                            }
                            result
                        }).await.unwrap();
                        if matches!(exit, Exit::Panic) {
                            panic!("framed holder panic after body ownership");
                        }
                    }
                }).await;
            }).unwrap();
            let (owner, mut writer, mut body) = source_rx.recv(&cx).await.unwrap();
            parked_rx.recv(&cx).await.unwrap();
            assert!(poll_body(&mut body).is_pending());
            let credit = pending_credit(&runtime, &owner).await;
            let expected = match exit {
                Exit::EarlyResponse => IncomingBodyError::ConsumerDropped,
                Exit::Panic => IncomingBodyError::SourceDisconnected,
                Exit::Cancel => IncomingBodyError::Cancelled { kind: CancelKind::Deadline },
                Exit::FailureThenCancel => IncomingBodyError::BadContentLength,
            };
            if matches!(exit, Exit::FailureThenCancel) {
                writer.fail(expected.clone());
            }
            if matches!(exit, Exit::Cancel | Exit::FailureThenCancel) {
                task.abort_with_reason(crate::types::CancelReason::with_origin(
                    CancelKind::Deadline, cx.region_id(), cx.now(),
                ));
            } else {
                release_tx.send_blocking(()).unwrap();
            }
            let result = task.join(&cx).await;
            match exit {
                Exit::EarlyResponse => assert!(matches!(result, Ok(()))),
                Exit::Panic => assert!(matches!(result, Err(JoinError::Panicked(_)))),
                Exit::Cancel | Exit::FailureThenCancel => {
                    assert!(matches!(result, Err(JoinError::Cancelled(_))));
                }
            }
            let abort = Some(if matches!(exit, Exit::Cancel) {
                ObligationAbortReason::Cancel
            } else {
                ObligationAbortReason::Error
            });
            settled(&runtime, &owner, credit, abort, true).await;
            assert_eq!(writer.finish(&owner), Err(expected.clone()),
                "retained driver cannot certify EOF after holder retirement");
            let mut frame = Some(Frame::data(BytesCursor::new(Bytes::from_static(b"late"))));
            assert_eq!(writer.poll_send_frame(
                &owner, &mut Context::from_waker(Waker::noop()), &mut frame,
            ), Poll::Ready(Err(expected.clone())));
            assert!(frame.is_some(), "late bytes cannot enter the consumer queue");
            let observed = writer.poll_consumer_dropped(&mut Context::from_waker(Waker::noop()));
            assert_eq!(observed, if matches!(exit, Exit::EarlyResponse) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(expected.clone()))
            });
            assert!(matches!(poll_body(&mut body),
                Poll::Ready(Some(Err(error))) if error == expected
            ));
            drop(body);
            drop(writer);
            settled(&runtime, &owner, credit, abort, true).await;
        }
    }

    #[test]
    fn checked_framed_native_retirement_seals_a_writer_retained_by_the_protocol() {
        native(retained_writer);
    }

    struct BodyOwnedWork {
        body: Option<IncomingRequestBody>,
        parked: Option<oneshot::Sender<()>>,
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Future for BodyOwnedWork {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<()> {
            if let Some(parked) = self.parked.take() {
                assert!(Pin::new(self.body.as_mut().unwrap()).poll_frame(task_cx).is_pending());
                parked.send_blocking(()).unwrap();
            }
            // Keep the body inside user work while the native wrapper is
            // forced to drop a cancellation-blind, already parked future.
            Poll::Pending
        }
    }

    impl Drop for BodyOwnedWork {
        fn drop(&mut self) {
            let body = self.body.as_ref().unwrap();
            assert_eq!(body.shared.framed_terminal(), Some(Err(IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            })), "owner cancellation must be published before user work begins structural Drop");
            drop(self.body.take());
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn work_owned_body_drop(cx: Cx, runtime: RuntimeHandle) {
        let (source_tx, mut source_rx) = oneshot::channel();
        let (parked_tx, mut parked_rx) = oneshot::channel();
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let work_drops = Arc::clone(&drops);
        let mut task = cx.spawn(move |owner| async move {
            let (writer, body, guard) = IncomingRequestBody::framed_channel_with_limits_checked(
                &owner, None, 1, 8, 8,
            ).unwrap();
            source_tx.send_blocking((owner.clone(), writer)).unwrap();
            guard.run(BodyOwnedWork {
                body: Some(body),
                parked: Some(parked_tx),
                drops: work_drops,
            }).await;
        }).unwrap();
        let (owner, mut writer) = source_rx.recv(&cx).await.unwrap();
        parked_rx.recv(&cx).await.unwrap();
        let credit = pending_credit(&runtime, &owner).await;
        task.abort_with_reason(crate::types::CancelReason::with_origin(
            CancelKind::Deadline, cx.region_id(), cx.now(),
        ));
        assert!(matches!(task.join(&cx).await, Err(JoinError::Cancelled(_))));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let expected = IncomingBodyError::Cancelled { kind: CancelKind::Deadline };
        assert_eq!(writer.poll_consumer_dropped(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(expected.clone())));
        writer.fail(IncomingBodyError::ConsumerDropped);
        assert_eq!(writer.finish(&owner), Err(expected));
        drop(writer);
        settled(&runtime, &owner, credit, Some(ObligationAbortReason::Cancel), true).await;
    }

    #[test]
    fn checked_framed_native_guard_settles_before_dropping_user_owned_body() {
        native(work_owned_body_drop);

        // Synchronous wrapper construction also protects a captured body
        // when the returned future has never been polled.
        let (mut lab, cx, handle) = fixture(1);
        let (writer, body, guard) = IncomingRequestBody::framed_channel_with_limits_checked(
            &cx, None, 1, 8, 8,
        ).unwrap();
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let running = guard.run(BodyOwnedWork {
            body: Some(body),
            parked: None,
            drops: Arc::clone(&drops),
        });
        assert_live(&mut lab, &cx);
        cx.cancel_fast(CancelKind::Deadline);
        drop(running);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(writer);
        assert_terminal(&mut lab, &cx, Some(ObligationAbortReason::Cancel));
        retire(lab, &cx, handle);

        let (mut lab, cx, handle) = fixture(1);
        let (writer, mut body, guard) = IncomingRequestBody::framed_channel_with_limits_checked(
            &cx, None, 1, 8, 8,
        ).unwrap();
        cx.cancel_fast(CancelKind::Shutdown);
        drop(writer);
        assert!(matches!(poll_body(&mut body), Poll::Ready(Some(Err(IncomingBodyError::Cancelled {
            kind: CancelKind::Shutdown,
        })))));
        drop(guard);
        drop(body);
        assert_terminal(&mut lab, &cx, Some(ObligationAbortReason::Cancel));
        retire(lab, &cx, handle);
    }

    #[test]
    fn checked_framed_known_cancellation_wins_a_body_drop_callback_inside_user_poll() {
        struct Driver {
            writer: Arc<Mutex<FramedIncomingRequestBodyWriter>>,
            observed: Arc<Mutex<Option<IncomingBodyError>>>,
        }
        impl std::task::Wake for Driver {
            fn wake(self: Arc<Self>) {
                // Consumer Drop invokes this connection-side observer before
                // the user's poll returns to the task-local guard.
                let mut writer = self.writer.lock();
                let Poll::Ready(Err(error)) = writer.poll_consumer_dropped(
                    &mut Context::from_waker(Waker::noop()),
                ) else {
                    panic!("an already cancelled owner is not an ordinary early response");
                };
                *self.observed.lock() = Some(error);
                // Even a previously captured abandon decision must be
                // normalized when the writer now knows its owner cancelled.
                writer.fail(IncomingBodyError::ConsumerDropped);
            }
        }
        let (mut lab, cx, handle) = fixture(1);
        let (writer, body, guard) = IncomingRequestBody::framed_channel_with_limits_checked(
            &cx, None, 1, 8, 8,
        ).unwrap();
        let writer = Arc::new(Mutex::new(writer));
        let observed = Arc::new(Mutex::new(None));
        let waker = Waker::from(Arc::new(Driver {
            writer: Arc::clone(&writer),
            observed: Arc::clone(&observed),
        }));
        assert!(writer.lock().poll_consumer_dropped(&mut Context::from_waker(&waker)).is_pending());
        assert_live(&mut lab, &cx);
        ready(guard.run(async {
            cx.cancel_fast(CancelKind::Deadline);
            assert!(cx.checkpoint().is_err(), "work acknowledges the real owner cancellation");
            drop(body);
        }));
        let expected = IncomingBodyError::Cancelled { kind: CancelKind::Deadline };
        assert_eq!(*observed.lock(), Some(expected.clone()));
        assert_eq!(writer.lock().finish(&cx), Err(expected));
        drop(waker);
        drop(writer);
        assert_terminal(&mut lab, &cx, Some(ObligationAbortReason::Cancel));
        retire(lab, &cx, handle);
    }

    async fn finish_racing_retirement(cx: Cx, runtime: RuntimeHandle) {
        for _ in 0..8 {
            let (source_tx, mut source_rx) = oneshot::channel();
            let (parked_tx, mut parked_rx) = oneshot::channel();
            let (release_tx, mut release_rx) = oneshot::channel();
            let mut task = cx.spawn(move |owner| async move {
                let (writer, body, guard) = IncomingRequestBody::framed_channel_with_limits_checked(
                    &owner, Some(0), 1, 8, 0,
                ).unwrap();
                source_tx.send_blocking((owner.clone(), writer, body)).unwrap();
                guard.run(async {
                    let mut parked = Some(parked_tx);
                    let mut waiting = std::pin::pin!(release_rx.recv(&owner));
                    std::future::poll_fn(|task_cx| {
                        let result = waiting.as_mut().poll(task_cx);
                        if result.is_pending() {
                            if let Some(parked) = parked.take() {
                                parked.send_blocking(()).unwrap();
                            }
                        }
                        result
                    }).await.unwrap();
                }).await;
            }).unwrap();
            let (owner, mut writer, mut body) = source_rx.recv(&cx).await.unwrap();
            parked_rx.recv(&cx).await.unwrap();
            let credit = pending_credit(&runtime, &owner).await;
            // A multi-worker holder can exit as this connection-side FIN
            // validates. Whichever terminal decision wins must be the same
            // decision seen by the writer, consumer, and obligation ledger.
            release_tx.send_blocking(()).unwrap();
            let finished = writer.finish(&owner);
            task.join(&cx).await.unwrap();
            let abort = match finished {
                Ok(()) => {
                    assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
                    None
                }
                Err(IncomingBodyError::ConsumerDropped) => {
                    assert!(matches!(poll_body(&mut body),
                        Poll::Ready(Some(Err(IncomingBodyError::ConsumerDropped)))
                    ));
                    Some(ObligationAbortReason::Error)
                }
                other => panic!("FIN/normal retirement has one of two exact outcomes: {other:?}"),
            };
            drop(body);
            drop(writer);
            settled(&runtime, &owner, credit, abort, true).await;
        }
    }

    #[test]
    fn checked_framed_native_fin_and_holder_exit_share_one_terminal_decision() {
        native(finish_racing_retirement);
    }

    #[test]
    fn checked_framed_holder_wakes_and_waker_retirement_run_outside_shared_locks() {
        struct Probe {
            shared: Arc<IncomingBodyShared>,
            wakes: Arc<std::sync::atomic::AtomicUsize>,
            drops: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Probe {
            fn check_locks(&self) {
                assert!(self.shared.terminal_error.try_lock().is_some());
                assert!(self.shared.framed_holder_waker.try_lock().is_some());
                assert!(self.shared.framed_consumer_waker.try_lock().is_some());
                assert!(self.shared.framed_consumer_error.try_lock().is_some());
                assert!(self.shared.queued_bytes.state.try_lock().is_some());
            }
        }
        impl std::task::Wake for Probe {
            fn wake(self: Arc<Self>) {
                self.check_locks();
                self.wakes.fetch_add(1, Ordering::SeqCst);
            }
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                self.check_locks();
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        let (mut lab, cx, handle) = fixture(1);
        let (mut writer, body, guard) = IncomingRequestBody::framed_channel_with_limits_checked(
            &cx, Some(0), 1, 8, 0,
        ).unwrap();
        let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut running = Box::pin(guard.run(std::future::pending::<()>()));
        for _ in 0..2 {
            let waker = Waker::from(Arc::new(Probe {
                shared: Arc::clone(&body.shared),
                wakes: Arc::clone(&wakes),
                drops: Arc::clone(&drops),
            }));
            assert!(running.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1, "replacement retired the first waker");
        writer.finish(&cx).unwrap();
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert!(running.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        assert_terminal(&mut lab, &cx, None);
        drop(running);
        drop(writer);
        drop(body);
        assert_terminal(&mut lab, &cx, None);
        retire(lab, &cx, handle);
    }

    #[test]
    fn checked_framed_policy_and_holder_refusals_never_publish_a_body() {
        assert!(matches!(IncomingRequestBody::framed_channel_with_limits_checked(
            &Cx::for_testing(), None, 1, 8, 8,
        ), Err(IncomingBodyAdmissionError::RuntimeRequired)));
        let (mut lab, cx, handle) = fixture(1);
        assert!(matches!(IncomingRequestBody::framed_channel_with_limits_checked(
            &cx, Some(9), 1, 8, 8,
        ), Err(IncomingBodyAdmissionError::Policy(IncomingBodyError::BodyTooLarge {
            actual: Some(9), limit: 8,
        }))));
        flush(&mut lab);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        let (writer, body, guard) = IncomingRequestBody::framed_channel_with_limits_checked(
            &cx, Some(0), 1, 8, 0,
        ).unwrap();
        assert_live(&mut lab, &cx);
        assert!(IncomingRequestBody::framed_channel_with_limits_checked(
            &cx, None, 1, 8, 8,
        ).is_err(), "second body cannot bypass the region's obligation ceiling");
        drop(guard);
        drop(writer);
        drop(body);
        assert_terminal(&mut lab, &cx, Some(ObligationAbortReason::Error));
        retire(lab, &cx, handle);
    }
}
