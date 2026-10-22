//! Producer regressions for the additive task-vector lab mode (.97).
//! These exercise admitted tasks and real wake paths, including missing-edge
//! controls; no seed count or race estimate is treated as exploration proof.

use super::*;
use crate::cx::{Cx, Scope};
use crate::trace::distributed::{CausalOrder, LogicalClockKind, LogicalTime};
use crate::types::{Budget, CancelReason, FailFast};

fn message_time(events: &[TraceEvent], message: &str) -> LogicalTime {
    events
        .iter()
        .find(|event| matches!(&event.data, TraceData::Message(text) if text == message))
        .and_then(|event| event.logical_time.clone())
        .unwrap_or_else(|| panic!("missing logical timestamp for {message}"))
}

fn context(lab: &LabRuntime, task: TaskId) -> Cx {
    lab.state.task(task).unwrap().cx.as_ref().unwrap().clone()
}

#[test]
fn legacy_lab_keeps_lamport_clocks_and_does_not_add_poll_events() {
    let mut lab = LabRuntime::with_seed(97);
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, async {})
        .unwrap();
    assert_eq!(
        context(&lab, task).logical_now().kind(),
        LogicalClockKind::Lamport
    );
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    assert!(
        !lab.trace()
            .snapshot()
            .iter()
            .any(|event| event.kind == TraceEventKind::Poll)
    );
}

#[test]
fn independent_tasks_keep_concurrent_clocks_despite_dispatch_order() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97));
    let root = lab.state.create_root_region(Budget::INFINITE);
    for name in ["independent-left", "independent-right"] {
        let (task, _join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                Cx::current().unwrap().trace(name);
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
    }
    let events = lab.trace().snapshot();
    assert_eq!(
        message_time(&events, "independent-left")
            .causal_order(&message_time(&events, "independent-right")),
        CausalOrder::Concurrent
    );
    let polls: Vec<_> = events
        .iter()
        .filter(|event| event.kind == TraceEventKind::Poll)
        .collect();
    assert_eq!(polls.len(), 2);
    assert!(
        polls.iter().all(|event| {
            event.logical_time.as_ref().unwrap().kind() == LogicalClockKind::Vector
        })
    );
    assert_eq!(lab.detected_races().race_count(), 0);
}

fn channel_trace(receiver_waits: bool) -> Vec<TraceEvent> {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (tx, mut rx) = crate::channel::oneshot::channel::<()>();
    let (receiver, _receiver_join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            rx.recv(&cx).await.unwrap();
            cx.trace("received");
        })
        .unwrap();
    let (sender, _sender_join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            cx.trace("before-send");
            tx.send(&cx, ()).unwrap();
            cx.trace("after-send");
        })
        .unwrap();
    if receiver_waits {
        lab.scheduler.lock().schedule(receiver, 0);
        lab.step();
        assert!(lab.state.task(receiver).is_some());
    }
    lab.scheduler.lock().schedule(sender, 0);
    lab.step();
    if !receiver_waits {
        lab.scheduler.lock().schedule(receiver, 0);
    }
    lab.run_until_idle();
    assert!(lab.is_quiescent());
    lab.trace().snapshot()
}

#[test]
fn real_channel_wake_carries_only_the_senders_past() {
    let events = channel_trace(true);
    let before = message_time(&events, "before-send");
    let after = message_time(&events, "after-send");
    let received = message_time(&events, "received");
    assert_eq!(before.causal_order(&received), CausalOrder::Before);
    assert_eq!(after.causal_order(&received), CausalOrder::Concurrent);
    // Reconstructed executions have identical clocks despite runtime IDs
    // differing. The ID is provenance, not a serialized vector component.
    let repeated = channel_trace(true);
    assert_eq!(received, message_time(&repeated, "received"));
}

#[test]
fn buffered_receive_without_a_wake_does_not_invent_an_edge() {
    let events = channel_trace(false);
    assert_eq!(
        message_time(&events, "before-send").causal_order(&message_time(&events, "received")),
        CausalOrder::Concurrent
    );
}

#[test]
fn parked_join_observes_the_childs_retirement_clock() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (release, mut gate) = crate::channel::oneshot::channel::<()>();
    let (parent, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            let mut child = cx
                .spawn(move |child_cx| async move {
                    gate.recv(&child_cx).await.unwrap();
                    child_cx.trace("child-before-retirement");
                    child_cx.task_id()
                })
                .unwrap();
            let _ = child.join(&cx).await.unwrap();
            cx.trace("parent-after-join");
        })
        .unwrap();
    lab.scheduler.lock().schedule(parent, 0);
    lab.run_until_idle();
    // Both tasks park: the child on the gate, the parent on the admitted
    // child's retirement barrier (not merely its admission notification).
    release.send_blocking(()).unwrap();
    lab.run_until_idle();
    let events = lab.trace().snapshot();
    let joined = message_time(&events, "parent-after-join");
    let retired = events
        .iter()
        .find(|event| {
            event.kind == TraceEventKind::Complete
                && matches!(&event.data, TraceData::Task { task, .. } if *task != parent)
        })
        .and_then(|event| event.logical_time.as_ref())
        .expect("child completion has a timestamp");
    assert_eq!(retired.causal_order(&joined), CausalOrder::Before);
}

#[test]
fn queued_spawn_inherits_at_enqueue_and_shares_its_admitted_clock() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (parent, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            cx.trace("before-spawn");
            let child = cx
                .spawn(|child_cx| async move {
                    let before = child_cx.logical_tick();
                    let installed = Cx::current().unwrap();
                    assert_eq!(
                        before.causal_order(&installed.logical_tick()),
                        CausalOrder::Before
                    );
                    child_cx.trace("child-start");
                })
                .unwrap();
            cx.trace("after-spawn");
            child
        })
        .unwrap();
    lab.scheduler.lock().schedule(parent, 0);
    lab.run_until_idle();
    let events = lab.trace().snapshot();
    let child = message_time(&events, "child-start");
    assert_eq!(
        message_time(&events, "before-spawn").causal_order(&child),
        CausalOrder::Before
    );
    assert_eq!(
        message_time(&events, "after-spawn").causal_order(&child),
        CausalOrder::Concurrent
    );
}

#[test]
fn direct_and_scoped_spawn_inherit_without_ordering_siblings() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (parent, _parent_join) = lab
        .state
        .create_task(root, Budget::INFINITE, std::future::pending::<()>())
        .unwrap();
    let parent_cx = context(&lab, parent);
    let before = parent_cx.logical_tick();
    let (direct, _direct_join) = lab
        .state
        .create_task_with_auth(&parent_cx, root, Budget::INFINITE, async {})
        .unwrap();
    let scope = Scope::<FailFast>::new(root, Budget::INFINITE);
    let scoped = scope
        .spawn_registered(&mut lab.state, &parent_cx, |_| async {})
        .unwrap();
    let direct = context(&lab, direct).logical_tick();
    let scoped = context(&lab, scoped.task_id()).logical_tick();
    assert_eq!(before.causal_order(&direct), CausalOrder::Before);
    assert_eq!(before.causal_order(&scoped), CausalOrder::Before);
    assert_eq!(direct.causal_order(&scoped), CausalOrder::Concurrent);
}

#[test]
fn child_region_principal_shares_its_live_tasks_clock() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            let child = cx
                .open_child_region(crate::cx::ChildRegionSpec::inherit())
                .await
                .unwrap();
            assert_eq!(cx.task_id(), child.cx().task_id());
            let before = cx.logical_tick();
            let principal = child.cx().logical_tick();
            let after = cx.logical_tick();
            assert_eq!(before.causal_order(&principal), CausalOrder::Before);
            assert_eq!(principal.causal_order(&after), CausalOrder::Before);
            child.close().await.unwrap();
        })
        .unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    assert_eq!(join.try_join(), Ok(Some(())));
}

#[test]
fn recycled_task_slots_receive_distinct_clock_components() {
    let lab = LabRuntime::new_with_task_causality(LabConfig::new(97));
    let first = lab
        .state
        .build_task_logical_clock(TaskId::new_for_test(4, 1), None);
    let reused = lab
        .state
        .build_task_logical_clock(TaskId::new_for_test(4, 2), None);
    assert_eq!(
        first.tick().causal_order(&reused.tick()),
        CausalOrder::Concurrent
    );
}

#[test]
fn external_and_foreign_runtime_wakes_leave_the_source_unknown() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let registered = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&registered);
    let (task, _join) = lab
        .state
        .create_task(
            root,
            Budget::INFINITE,
            std::future::poll_fn(move |cx| {
                *capture.lock() = Some(cx.waker().clone());
                Poll::<()>::Pending
            }),
        )
        .unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.step();
    let target = context(&lab, task);
    let before = target.logical_now();
    let waker = registered.lock().take().unwrap();
    waker.wake_by_ref();
    assert_eq!(target.logical_now(), before);

    let mut other = LabRuntime::new_with_task_causality(LabConfig::new(97));
    let other_root = other.state.create_root_region(Budget::INFINITE);
    let (other_task, _other_join) = other
        .state
        .create_task(other_root, Budget::INFINITE, std::future::pending::<()>())
        .unwrap();
    let foreign = context(&other, other_task);
    for _ in 0..10 {
        let _ = foreign.logical_tick();
    }
    let _guard = Cx::set_current(Some(foreign));
    waker.wake_by_ref();
    assert_eq!(target.logical_now(), before);
}

#[test]
fn dpor_conflict_model_consumes_real_channel_producer_evidence() {
    fn conflicts(receiver_waits: bool) -> Vec<TraceEvent> {
        let events = channel_trace(receiver_waits);
        let region = RegionId::new_for_test(0, 0);
        // Use the existing region-write footprint as a two-event conflict
        // model. Its timestamps come from actual task/channel execution;
        // these are deliberately not represented as real cancellation calls.
        vec![
            TraceEvent::cancel_request(
                1,
                Time::ZERO,
                TaskId::new_for_test(1, 0),
                region,
                CancelReason::user("model-before-send"),
            )
            .with_logical_time(message_time(&events, "before-send")),
            TraceEvent::cancel_request(
                2,
                Time::ZERO,
                TaskId::new_for_test(0, 0),
                region,
                CancelReason::user("model-received"),
            )
            .with_logical_time(message_time(&events, "received")),
        ]
    }

    let racing = conflicts(false);
    assert_eq!(racing.len(), 2);
    assert_eq!(crate::trace::detect_hb_races(&racing).race_count(), 1);
    let ordered = conflicts(true);
    assert_eq!(ordered.len(), 2);
    assert_eq!(crate::trace::detect_hb_races(&ordered).race_count(), 0);
}
