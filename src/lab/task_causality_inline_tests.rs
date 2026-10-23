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
fn buffered_receive_observes_the_exact_publication_without_a_wake() {
    let events = channel_trace(false);
    assert_eq!(
        message_time(&events, "before-send").causal_order(&message_time(&events, "received")),
        CausalOrder::Before
    );
    assert_eq!(
        message_time(&events, "after-send").causal_order(&message_time(&events, "received")),
        CausalOrder::Concurrent
    );
    assert_eq!(
        message_time(&events, "received"),
        message_time(&channel_trace(false), "received")
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
    fn conflicts(receiver_waits: bool, sender_event: &str) -> Vec<TraceEvent> {
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
                CancelReason::user("model-sender-event"),
            )
            .with_logical_time(message_time(&events, sender_event)),
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

    // A sender's subsequent event is still concurrent with the consumer;
    // buffered delivery must not accidentally acquire that later clock.
    let racing = conflicts(false, "after-send");
    assert_eq!(racing.len(), 2);
    assert_eq!(crate::trace::detect_hb_races(&racing).race_count(), 1);
    for receiver_waits in [false, true] {
        let ordered = conflicts(receiver_waits, "before-send");
        assert_eq!(ordered.len(), 2);
        assert_eq!(crate::trace::detect_hb_races(&ordered).race_count(), 0);
    }
}

fn run_channel_task(
    lab: &mut LabRuntime,
    root: RegionId,
    future: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, future)
        .unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.step();
}

#[test]
fn buffered_mpsc_keeps_each_senders_evidence_with_its_own_message() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (tx, mut rx) = crate::channel::mpsc::channel(3);
    // Activating the lazy evidence queue must preserve earlier host entries.
    tx.try_send(0).unwrap();
    for (value, before, after) in [(1, "one-before", "one-after"), (2, "two-before", "two-after")] {
        let sender = tx.clone();
        run_channel_task(&mut lab, root, async move {
            let cx = Cx::current().unwrap();
            cx.trace(before);
            if value == 1 {
                sender.send(&cx, value).await.unwrap();
            } else {
                sender.try_send(value).unwrap();
            }
            cx.trace(after);
        });
    }
    run_channel_task(&mut lab, root, async move {
        let cx = Cx::current().unwrap();
        assert_eq!(rx.try_recv(), Ok(0));
        cx.trace("host-received");
        assert_eq!(rx.recv(&cx).await, Ok(1));
        cx.trace("one-received");
        assert_eq!(rx.try_recv(), Ok(2));
        cx.trace("two-received");
    });
    lab.run_until_idle();
    assert!(lab.is_quiescent());
    let events = lab.trace().snapshot();
    let host = message_time(&events, "host-received");
    let first = message_time(&events, "one-received");
    let second = message_time(&events, "two-received");
    for name in ["one-before", "two-before"] {
        assert_eq!(message_time(&events, name).causal_order(&host), CausalOrder::Concurrent);
        assert_eq!(message_time(&events, name).causal_order(&second), CausalOrder::Before);
    }
    assert_eq!(message_time(&events, "one-before").causal_order(&first), CausalOrder::Before);
    assert_eq!(message_time(&events, "two-before").causal_order(&first), CausalOrder::Concurrent);
    for name in ["one-after", "two-after"] {
        assert_eq!(message_time(&events, name).causal_order(&second), CausalOrder::Concurrent);
    }
}

#[test]
fn mpsc_batch_receives_merge_only_the_consumed_prefix() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (tx, mut rx) = crate::channel::mpsc::unbounded_channel();
    for (value, name) in [(1, "batch-one"), (2, "batch-two"), (3, "batch-three")] {
        let sender = tx.clone();
        run_channel_task(&mut lab, root, async move {
            Cx::current().unwrap().trace(name);
            sender.send(value).unwrap();
        });
    }
    run_channel_task(&mut lab, root, async move {
        let cx = Cx::current().unwrap();
        let mut values = Vec::new();
        assert_eq!(rx.recv_many(&cx, &mut values, 0).await, Ok(0));
        assert!(values.is_empty());
        cx.trace("zero-batch");
        assert_eq!(rx.recv_many(&cx, &mut values, 2).await, Ok(2));
        assert_eq!(values, vec![1, 2]);
        cx.trace("first-batch");
        assert_eq!(rx.try_recv(), Ok(3));
        cx.trace("batch-tail");
    });
    lab.run_until_idle();
    assert!(lab.is_quiescent());
    let events = lab.trace().snapshot();
    for name in ["batch-one", "batch-two", "batch-three"] {
        assert_eq!(
            message_time(&events, name).causal_order(&message_time(&events, "zero-batch")),
            CausalOrder::Concurrent
        );
        assert_eq!(
            message_time(&events, name).causal_order(&message_time(&events, "batch-tail")),
            CausalOrder::Before
        );
    }
    for name in ["batch-one", "batch-two"] {
        assert_eq!(
            message_time(&events, name).causal_order(&message_time(&events, "first-batch")),
            CausalOrder::Before
        );
    }
    assert_eq!(
        message_time(&events, "batch-three").causal_order(&message_time(&events, "first-batch")),
        CausalOrder::Concurrent
    );
}

#[test]
fn mpsc_eviction_and_failed_send_do_not_relabel_surviving_messages() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (tx, mut rx) = crate::channel::mpsc::channel(3);
    for (value, name) in [(1, "kept-first"), (2, "evicted-middle"), (3, "kept-last"), (4, "refused-full")] {
        let sender = tx.clone();
        run_channel_task(&mut lab, root, async move {
            Cx::current().unwrap().trace(name);
            if value == 4 {
                assert_eq!(sender.try_send(value), Err(crate::channel::mpsc::SendError::Full(value)));
            } else {
                sender.try_send(value).unwrap();
            }
        });
    }
    assert_eq!(tx.send_evict_oldest_where(5, |value| *value == 2), Ok(Some(2)));
    run_channel_task(&mut lab, root, async move {
        let cx = Cx::current().unwrap();
        assert_eq!(rx.try_recv(), Ok(1));
        cx.trace("eviction-first-received");
        assert_eq!(rx.recv(&cx).await, Ok(3));
        cx.trace("eviction-last-received");
        assert_eq!(rx.try_recv(), Ok(5));
        cx.trace("replacement-received");
    });
    lab.run_until_idle();
    assert!(lab.is_quiescent());
    let events = lab.trace().snapshot();
    let first = message_time(&events, "eviction-first-received");
    let last = message_time(&events, "eviction-last-received");
    assert_eq!(message_time(&events, "kept-first").causal_order(&first), CausalOrder::Before);
    assert_eq!(message_time(&events, "kept-last").causal_order(&first), CausalOrder::Concurrent);
    assert_eq!(message_time(&events, "kept-last").causal_order(&last), CausalOrder::Before);
    for name in ["evicted-middle", "refused-full"] {
        assert_eq!(
            message_time(&events, name).causal_order(&message_time(&events, "replacement-received")),
            CausalOrder::Concurrent
        );
    }
}

#[test]
fn channel_permits_capture_the_committing_task_at_publication() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let mut tasks = Vec::new();
    let mut contexts = Vec::new();
    let mut joins = Vec::new();
    for _ in 0..5 {
        let (task, join) = lab.state.create_task(root, Budget::INFINITE, async {}).unwrap();
        tasks.push(task);
        contexts.push(context(&lab, task));
        joins.push(join);
    }
    let (oneshot_tx, mut oneshot_rx) = crate::channel::oneshot::channel();
    let (mpsc_tx, mut mpsc_rx) = crate::channel::mpsc::channel(1);
    let (broadcast_tx, mut broadcast_rx) = crate::channel::broadcast::channel(1);
    let reserver_before = contexts[0].logical_tick();
    let (oneshot_permit, mpsc_permit, broadcast_permit) = {
        let _guard = Cx::set_current(Some(contexts[0].clone()));
        (
            oneshot_tx.reserve_checked(&contexts[0]).unwrap(),
            mpsc_tx.try_reserve_checked(&contexts[0]).unwrap(),
            broadcast_tx.reserve_checked(&contexts[0]).unwrap(),
        )
    };
    {
        let _guard = Cx::set_current(Some(contexts[1].clone()));
        contexts[1].trace("committer-before");
        oneshot_permit.send(11).unwrap();
        mpsc_permit.try_send(12).unwrap();
        assert_eq!(broadcast_permit.send(13), 1);
        contexts[1].trace("committer-after");
    }
    {
        let _guard = Cx::set_current(Some(contexts[2].clone()));
        assert_eq!(oneshot_rx.try_recv(), Ok(11));
        contexts[2].trace("oneshot-permit-received");
    }
    {
        let _guard = Cx::set_current(Some(contexts[3].clone()));
        assert_eq!(mpsc_rx.try_recv(), Ok(12));
        contexts[3].trace("mpsc-permit-received");
    }
    {
        let _guard = Cx::set_current(Some(contexts[4].clone()));
        assert_eq!(broadcast_rx.try_recv(), Ok(13));
        contexts[4].trace("broadcast-permit-received");
    }
    let events = lab.trace().snapshot();
    for received in [
        "oneshot-permit-received",
        "mpsc-permit-received",
        "broadcast-permit-received",
    ] {
        let received = message_time(&events, received);
        assert_eq!(reserver_before.causal_order(&received), CausalOrder::Concurrent);
        assert_eq!(message_time(&events, "committer-before").causal_order(&received), CausalOrder::Before);
        assert_eq!(message_time(&events, "committer-after").causal_order(&received), CausalOrder::Concurrent);
    }
    for task in tasks {
        lab.scheduler.lock().schedule(task, 0);
    }
    lab.run_until_idle();
    assert!(lab.is_quiescent());
    assert!(joins.iter_mut().all(|join| join.try_join() == Ok(Some(()))));
}

#[test]
fn channel_messages_from_another_runtime_do_not_merge_colliding_task_ids() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, _join) = lab.state.create_task(root, Budget::INFINITE, async {}).unwrap();
    let receiver = context(&lab, task);
    let mut foreign_lab = LabRuntime::new_with_task_causality(LabConfig::new(97));
    let foreign_root = foreign_lab.state.create_root_region(Budget::INFINITE);
    let (foreign_task, _foreign_join) = foreign_lab.state.create_task(foreign_root, Budget::INFINITE, async {}).unwrap();
    let sender = context(&foreign_lab, foreign_task);
    assert_eq!(task, foreign_task);
    for _ in 0..10 {
        let _ = sender.logical_tick();
    }
    let (oneshot_tx, mut oneshot_rx) = crate::channel::oneshot::channel();
    let (mpsc_tx, mut mpsc_rx) = crate::channel::mpsc::channel(1);
    let (broadcast_tx, mut broadcast_rx) = crate::channel::broadcast::channel(1);
    {
        let _guard = Cx::set_current(Some(sender.clone()));
        oneshot_tx.send_blocking(11).unwrap();
        mpsc_tx.try_send(12).unwrap();
        assert_eq!(broadcast_tx.send(&sender, 13), Ok(1));
    }
    {
        let _guard = Cx::set_current(Some(receiver.clone()));
        let before = receiver.logical_now();
        assert_eq!(oneshot_rx.try_recv(), Ok(11));
        assert_eq!(mpsc_rx.try_recv(), Ok(12));
        assert_eq!(broadcast_rx.try_recv(), Ok(13));
        assert_eq!(receiver.logical_now(), before);
    }
    lab.scheduler.lock().schedule(task, 0);
    foreign_lab.scheduler.lock().schedule(foreign_task, 0);
    lab.run_until_idle();
    foreign_lab.run_until_idle();
    assert!(lab.is_quiescent());
    assert!(foreign_lab.is_quiescent());
}

#[test]
fn host_publications_and_legacy_contexts_do_not_advance_message_clocks() {
    for task_causal in [false, true] {
        let mut lab = if task_causal {
            LabRuntime::new_with_task_causality(LabConfig::new(97))
        } else {
            LabRuntime::with_seed(97)
        };
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, _join) = lab.state.create_task(root, Budget::INFINITE, async {}).unwrap();
        let cx = context(&lab, task);
        let before = cx.logical_now();
        let (oneshot_tx, mut oneshot_rx) = crate::channel::oneshot::channel();
        let (mpsc_tx, mut mpsc_rx) = crate::channel::mpsc::channel(1);
        let (broadcast_tx, mut broadcast_rx) = crate::channel::broadcast::channel(1);
        {
            let _guard = Cx::set_current((!task_causal).then(|| cx.clone()));
            oneshot_tx.send_blocking(11).unwrap();
            mpsc_tx.try_send(12).unwrap();
            assert_eq!(broadcast_tx.send(&cx, 13), Ok(1));
        }
        {
            let _guard = Cx::set_current(Some(cx.clone()));
            assert_eq!(oneshot_rx.try_recv(), Ok(11));
            assert_eq!(mpsc_rx.try_recv(), Ok(12));
            assert_eq!(broadcast_rx.try_recv(), Ok(13));
            assert_eq!(cx.logical_now(), before);
        }
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        assert!(lab.is_quiescent());
    }
}

#[test]
fn dropping_buffered_receivers_does_not_observe_their_messages() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (oneshot_tx, oneshot_rx) = crate::channel::oneshot::channel();
    let (mpsc_tx, mpsc_rx) = crate::channel::mpsc::channel(1);
    let (broadcast_tx, broadcast_rx) = crate::channel::broadcast::channel(1);
    run_channel_task(&mut lab, root, async move {
        let cx = Cx::current().unwrap();
        cx.trace("before-dropped-values");
        oneshot_tx.send_blocking(11).unwrap();
        mpsc_tx.try_send(12).unwrap();
        assert_eq!(broadcast_tx.send(&cx, 13), Ok(1));
    });
    run_channel_task(&mut lab, root, async move {
        drop(oneshot_rx);
        drop(mpsc_rx);
        drop(broadcast_rx);
        Cx::current().unwrap().trace("after-receiver-drop");
    });
    lab.run_until_idle();
    assert!(lab.is_quiescent());
    let events = lab.trace().snapshot();
    assert_eq!(
        message_time(&events, "before-dropped-values").causal_order(&message_time(&events, "after-receiver-drop")),
        CausalOrder::Concurrent
    );
}

#[test]
fn moved_receive_futures_observe_only_the_actual_polling_task() {
    use crate::remote::NodeId;
    use crate::trace::distributed::LogicalClockMode;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    fn causal_context(runtime: u64, node: &str) -> Cx {
        Cx::for_testing()
            .with_logical_clock(
                LogicalClockMode::Vector {
                    node: NodeId::new(node),
                }
                .build_handle(None),
            )
            .with_task_causality_runtime(Some(runtime))
    }

    fn poll_once<F: Future>(future: F, current: Option<Cx>) -> Poll<F::Output> {
        let mut future = pin!(future);
        let _current = Cx::set_current(current);
        let mut task = Context::from_waker(Waker::noop());
        future.as_mut().poll(&mut task)
    }

    let _host = Cx::set_current(None);
    for api in 0..4 {
        for observer_mode in 0..3 {
            let source = causal_context(97, "source");
            let constructor = causal_context(97, "constructor");
            let poller = causal_context(
                if observer_mode == 2 { 98 } else { 97 },
                "poller",
            );
            let source_before = source.logical_tick();
            let _ = constructor.logical_tick();
            let _ = poller.logical_tick();
            let (oneshot_tx, mut oneshot_rx) = crate::channel::oneshot::channel();
            let (mpsc_tx, mut mpsc_rx) = crate::channel::mpsc::channel(1);
            let (broadcast_tx, mut broadcast_rx) = crate::channel::broadcast::channel(1);
            {
                let _current = Cx::set_current(Some(source.clone()));
                oneshot_tx.send_blocking(11).unwrap();
                mpsc_tx.try_send(12).unwrap();
                assert_eq!(broadcast_tx.send(&source, 13), Ok(1));
            }
            let source_after = source.logical_tick();
            let poller_before = poller.logical_now();
            let current = (observer_mode != 1).then(|| poller.clone());
            match api {
                0 => assert_eq!(
                    poll_once(oneshot_rx.recv(&constructor), current),
                    Poll::Ready(Ok(11))
                ),
                1 => assert_eq!(
                    poll_once(mpsc_rx.recv(&constructor), current),
                    Poll::Ready(Ok(12))
                ),
                2 => {
                    let mut values = Vec::new();
                    assert_eq!(
                        poll_once(mpsc_rx.recv_many(&constructor, &mut values, 1), current),
                        Poll::Ready(Ok(1))
                    );
                    assert_eq!(values, vec![12]);
                }
                _ => assert_eq!(
                    poll_once(broadcast_rx.recv(&constructor), current),
                    Poll::Ready(Ok(13))
                ),
            }
            let constructor_after = constructor.logical_tick();
            let poller_after = poller.logical_now();
            if observer_mode == 0 {
                assert_eq!(source_before.causal_order(&poller_after), CausalOrder::Before);
                assert_eq!(source_after.causal_order(&poller_after), CausalOrder::Concurrent);
                assert_eq!(
                    source_before.causal_order(&constructor_after),
                    CausalOrder::Concurrent
                );
            } else if observer_mode == 1 {
                // An explicit context is the observer only outside a task.
                assert_eq!(
                    source_before.causal_order(&constructor_after),
                    CausalOrder::Before
                );
                assert_eq!(
                    source_after.causal_order(&constructor_after),
                    CausalOrder::Concurrent
                );
                assert_eq!(poller_after, poller_before);
            } else {
                // An active foreign task must not fall back to the constructor.
                assert_eq!(poller_after, poller_before);
                assert_eq!(
                    source_before.causal_order(&constructor_after),
                    CausalOrder::Concurrent
                );
            }
        }
    }
}

#[test]
fn buffered_broadcast_fanout_keeps_each_publication_and_reader_independent() {
    use crate::stream::{BroadcastStream, StreamExt};

    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (tx, first) = crate::channel::broadcast::channel(3);
    let second = first.clone();
    let third = first.clone();
    assert_eq!(tx.send(&Cx::for_testing(), 0), Ok(3));

    for (value, before, after) in [
        (1, "broadcast-one-before", "broadcast-one-after"),
        (2, "broadcast-two-before", "broadcast-two-after"),
    ] {
        let sender = tx.clone();
        run_channel_task(&mut lab, root, async move {
            let cx = Cx::current().unwrap();
            cx.trace(before);
            assert_eq!(sender.send_checked(&cx, value), Ok(3));
            cx.trace(after);
        });
    }

    // All messages are ready before any receiver runs, so no sender wake can
    // supply the missing edge. Each API must observe its own consumed prefix.
    for (api, receiver) in [(0, first), (1, second), (2, third)] {
        run_channel_task(&mut lab, root, async move {
            let cx = Cx::current().unwrap();
            let mut stream = BroadcastStream::new(cx.clone(), receiver);
            for expected in 0..3 {
                let received = match api {
                    0 => stream.get_mut().try_recv().unwrap(),
                    1 => stream.get_mut().recv(&cx).await.unwrap(),
                    _ => stream.next().await.unwrap().unwrap(),
                };
                assert_eq!(received, expected);
                cx.trace(&format!("broadcast-reader-{api}-value-{expected}"));
            }
        });
    }
    lab.run_until_idle();
    assert!(lab.is_quiescent());

    let events = lab.trace().snapshot();
    for api in 0..3 {
        let host = message_time(&events, &format!("broadcast-reader-{api}-value-0"));
        let first = message_time(&events, &format!("broadcast-reader-{api}-value-1"));
        let second = message_time(&events, &format!("broadcast-reader-{api}-value-2"));
        for before in ["broadcast-one-before", "broadcast-two-before"] {
            assert_eq!(message_time(&events, before).causal_order(&host), CausalOrder::Concurrent);
            assert_eq!(message_time(&events, before).causal_order(&second), CausalOrder::Before);
        }
        assert_eq!(
            message_time(&events, "broadcast-one-before").causal_order(&first),
            CausalOrder::Before
        );
        assert_eq!(
            message_time(&events, "broadcast-two-before").causal_order(&first),
            CausalOrder::Concurrent
        );
        for after in ["broadcast-one-after", "broadcast-two-after"] {
            assert_eq!(message_time(&events, after).causal_order(&second), CausalOrder::Concurrent);
        }
        for other in api + 1..3 {
            assert_eq!(
                second.causal_order(&message_time(
                    &events,
                    &format!("broadcast-reader-{other}-value-2"),
                )),
                CausalOrder::Concurrent
            );
        }
    }
}

#[test]
fn broadcast_lag_empty_and_close_do_not_observe_unread_publications() {
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (tx, mut lagged) = crate::channel::broadcast::channel(1);
    for (value, name) in [(1, "broadcast-evicted"), (2, "broadcast-retained")] {
        let sender = tx.clone();
        run_channel_task(&mut lab, root, async move {
            let cx = Cx::current().unwrap();
            cx.trace(name);
            assert_eq!(sender.send(&cx, value), Ok(1));
        });
    }
    let mut fresh = tx.subscribe();
    run_channel_task(&mut lab, root, async move {
        let cx = Cx::current().unwrap();
        assert_eq!(
            lagged.recv(&cx).await,
            Err(crate::channel::broadcast::RecvError::Lagged(1))
        );
        cx.trace("broadcast-lag-only");
        assert_eq!(lagged.try_recv(), Ok(2));
        cx.trace("broadcast-retained-received");
    });
    run_channel_task(&mut lab, root, async move {
        let cx = Cx::current().unwrap();
        assert_eq!(
            fresh.try_recv(),
            Err(crate::channel::broadcast::TryRecvError::Empty)
        );
        cx.trace("broadcast-empty-only");
        drop(tx);
        assert_eq!(
            fresh.recv(&cx).await,
            Err(crate::channel::broadcast::RecvError::Closed)
        );
        cx.trace("broadcast-closed-only");
    });
    lab.run_until_idle();
    assert!(lab.is_quiescent());

    let events = lab.trace().snapshot();
    for name in [
        "broadcast-lag-only",
        "broadcast-empty-only",
        "broadcast-closed-only",
    ] {
        let observed = message_time(&events, name);
        for publication in ["broadcast-evicted", "broadcast-retained"] {
            assert_eq!(
                message_time(&events, publication).causal_order(&observed),
                CausalOrder::Concurrent
            );
        }
    }
    let received = message_time(&events, "broadcast-retained-received");
    assert_eq!(
        message_time(&events, "broadcast-retained").causal_order(&received),
        CausalOrder::Before
    );
    assert_eq!(
        message_time(&events, "broadcast-evicted").causal_order(&received),
        CausalOrder::Concurrent
    );
}

#[test]
fn broadcast_clone_effects_observe_the_retained_publication_before_eviction() {
    type CloneAction = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

    struct CloneEffect {
        value: u32,
        action: CloneAction,
    }

    impl Clone for CloneEffect {
        fn clone(&self) -> Self {
            let action = self.action.lock().take();
            if let Some(action) = action {
                action();
            }
            Self {
                value: self.value,
                action: Arc::clone(&self.action),
            }
        }
    }

    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (tx, mut rx) = crate::channel::broadcast::channel(1);
    let action: CloneAction = Arc::new(Mutex::new(None));
    let evictor = tx.clone();
    *action.lock() = Some(Box::new(move || {
        let cx = Cx::current().unwrap();
        cx.trace("broadcast-clone-before-eviction");
        {
            // Reenter while the original payload is retained, replacing its
            // ring slot with a deliberately unattributed host publication.
            let _host = Cx::set_current(None);
            assert_eq!(
                evictor.send(
                    &cx,
                    CloneEffect {
                        value: 2,
                        action: Arc::new(Mutex::new(None)),
                    },
                ).ok(),
                Some(1)
            );
        }
        cx.trace("broadcast-clone-after-eviction");
    }));
    run_channel_task(&mut lab, root, async move {
        let cx = Cx::current().unwrap();
        cx.trace("broadcast-clone-source-before");
        assert_eq!(tx.send(&cx, CloneEffect { value: 1, action }).ok(), Some(1));
        cx.trace("broadcast-clone-source-after");
    });
    run_channel_task(&mut lab, root, async move {
        let cx = Cx::current().unwrap();
        assert_eq!(rx.recv(&cx).await.unwrap().value, 1);
        cx.trace("broadcast-original-cloned");
        let before = cx.logical_now();
        assert_eq!(rx.try_recv().unwrap().value, 2);
        assert_eq!(cx.logical_now(), before);
    });
    lab.run_until_idle();
    assert!(lab.is_quiescent());

    let events = lab.trace().snapshot();
    for effect in [
        "broadcast-clone-before-eviction",
        "broadcast-clone-after-eviction",
        "broadcast-original-cloned",
    ] {
        let observed = message_time(&events, effect);
        assert_eq!(
            message_time(&events, "broadcast-clone-source-before").causal_order(&observed),
            CausalOrder::Before
        );
        assert_eq!(
            message_time(&events, "broadcast-clone-source-after").causal_order(&observed),
            CausalOrder::Concurrent
        );
    }
}
