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
