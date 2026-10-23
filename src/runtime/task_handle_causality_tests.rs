//! Retirement edges for ready joins in the opt-in task-causal lab (.97).

use super::*;
use crate::lab::{LabConfig, LabRuntime};
use crate::remote::NodeId;
use crate::trace::distributed::{CausalOrder, LogicalClockMode};
use crate::trace::{TraceData, TraceEventKind};
use crate::types::Budget;
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

#[test]
fn retirement_evidence_is_frozen_at_open_and_not_exposed_while_closed() {
    let source = causal_context(97, "source");
    let consumer = causal_context(97, "consumer");
    let barrier = RetirementBarrier::pending();
    barrier.attach_task_causality(&source);
    let completed = source.logical_tick();
    let initial = consumer.logical_now();
    barrier.observe(&consumer);
    assert_eq!(
        consumer.logical_now(),
        initial,
        "closed barrier is not observed"
    );
    barrier.open_and_wake();
    let later = source.logical_tick();
    barrier.open_and_wake();
    barrier.observe(&consumer);
    let joined = consumer.logical_tick();
    assert_eq!(completed.causal_order(&joined), CausalOrder::Before);
    assert_eq!(later.causal_order(&joined), CausalOrder::Concurrent);
}

#[test]
fn retirement_evidence_rejects_other_runtimes_and_keeps_default_clocks_empty() {
    let source = causal_context(97, "source");
    let foreign = causal_context(98, "consumer");
    let barrier = RetirementBarrier::pending();
    barrier.attach_task_causality(&source);
    barrier.open_and_wake();
    let initial = foreign.logical_now();
    barrier.observe(&foreign);
    assert_eq!(
        foreign.logical_now(),
        initial,
        "runtime provenance is required"
    );
    let ordinary = Cx::for_testing();
    let ordinary_barrier = RetirementBarrier::pending();
    ordinary_barrier.attach_task_causality(&ordinary);
    let initial = ordinary.logical_now();
    ordinary_barrier.open_and_wake();
    ordinary_barrier.observe(&ordinary);
    assert!(ordinary_barrier.causality.get().is_none());
    assert_eq!(ordinary.logical_now(), initial);
}

#[test]
fn ready_join_apis_observe_retirement_without_any_consumer_wake() {
    for mode in 0..3 {
        let source = causal_context(97, "source");
        let consumer = causal_context(97, "consumer");
        let barrier = RetirementBarrier::pending();
        barrier.attach_task_causality(&source);
        let (sender, receiver) = task_result_channel::<u8>();
        let mut handle = TaskHandle::with_retirement_barrier_for_test(
            source.task_id(),
            receiver,
            Arc::downgrade(&source.inner),
            Arc::clone(&barrier),
        );
        // No active source Cx: channel metadata cannot satisfy this regression.
        publish_terminal_result(sender, Ok(42));
        let completed = source.logical_tick();
        barrier.open_and_wake();
        let after_retirement = source.logical_tick();
        assert!(!barrier.has_waker());
        let mut task = Context::from_waker(Waker::noop());
        match mode {
            0 => {
                let _current = Cx::set_current(Some(consumer.clone()));
                assert_eq!(handle.try_join(), Ok(Some(42)));
            }
            1 => {
                let _current = Cx::set_current(Some(consumer.clone()));
                assert_eq!(handle.poll_join(&mut task), Poll::Ready(Ok(42)));
            }
            _ => {
                // The explicit observer works without an ambient Cx.
                let mut joined = pin!(handle.join(&consumer));
                assert_eq!(joined.as_mut().poll(&mut task), Poll::Ready(Ok(42)));
            }
        }
        let observed = consumer.logical_tick();
        assert_eq!(
            completed.causal_order(&observed),
            CausalOrder::Before,
            "mode={mode}"
        );
        assert_eq!(
            after_retirement.causal_order(&observed),
            CausalOrder::Concurrent,
            "mode={mode}"
        );
        let before_repoll = consumer.logical_now();
        let _current = Cx::set_current(Some(consumer.clone()));
        assert_eq!(handle.try_join(), Err(JoinError::PolledAfterCompletion));
        assert_eq!(
            consumer.logical_now(),
            before_repoll,
            "terminal repoll is not a new observation"
        );
    }
}

#[test]
fn ready_closed_result_still_observes_the_retired_task() {
    let source = causal_context(97, "source");
    let consumer = causal_context(97, "consumer");
    let barrier = RetirementBarrier::pending();
    barrier.attach_task_causality(&source);
    let (sender, receiver) = task_result_channel::<()>();
    let mut handle = TaskHandle::with_retirement_barrier_for_test(
        source.task_id(),
        receiver,
        Arc::downgrade(&source.inner),
        Arc::clone(&barrier),
    );
    drop(sender);
    let completed = source.logical_tick();
    barrier.open_after_shutdown();
    let _current = Cx::set_current(Some(consumer.clone()));
    assert!(matches!(handle.try_join(), Err(JoinError::Cancelled(_))));
    assert_eq!(
        completed.causal_order(&consumer.logical_now()),
        CausalOrder::Before
    );
}

#[test]
fn admitted_ready_joins_follow_complete_but_not_later_retained_context_events() {
    for mode in 0..3 {
        let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let handle_slot = Arc::new(Mutex::new(None));
        let retained_context = Arc::new(Mutex::new(None));
        let output = Arc::clone(&handle_slot);
        let retained = Arc::clone(&retained_context);
        let (parent, _parent_join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let parent_cx = Cx::current().unwrap();
                let child = parent_cx
                    .spawn(move |child_cx| async move {
                        child_cx.trace("child-before-return");
                        *retained.lock() = Some(child_cx);
                        42_u8
                    })
                    .unwrap();
                *output.lock() = Some(child);
            })
            .unwrap();
        lab.scheduler.lock().schedule(parent, 0);
        lab.run_until_idle();
        assert!(lab.is_quiescent());
        let mut child = handle_slot.lock().take().unwrap();
        let child_id = child.task_id();
        assert!(child.is_finished());
        assert!(
            !child.barrier.has_waker(),
            "no consumer ever parked on the child"
        );
        retained_context
            .lock()
            .as_ref()
            .unwrap()
            .trace("child-after-retirement");
        let (consumer, _consumer_join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                match mode {
                    0 => assert_eq!(child.try_join(), Ok(Some(42))),
                    1 => assert_eq!(
                        std::future::poll_fn(|task| child.poll_join(task)).await,
                        Ok(42)
                    ),
                    _ => assert_eq!(child.join(&cx).await, Ok(42)),
                }
                cx.trace("consumer-after-join");
            })
            .unwrap();
        lab.scheduler.lock().schedule(consumer, 0);
        lab.run_until_idle();
        assert!(lab.is_quiescent());
        let events = lab.trace().snapshot();
        let completed = events
            .iter()
            .find(|event| {
                event.kind == TraceEventKind::Complete
                    && matches!(&event.data, TraceData::Task { task, .. } if *task == child_id)
            })
            .and_then(|event| event.logical_time.as_ref())
            .expect("child Complete timestamp");
        let message = |name| {
            events
                .iter()
                .find(|event| matches!(&event.data, TraceData::Message(text) if text == name))
                .and_then(|event| event.logical_time.as_ref())
                .unwrap()
        };
        let observed = message("consumer-after-join");
        assert_eq!(
            completed.causal_order(observed),
            CausalOrder::Before,
            "mode={mode}, child={child_id:?}"
        );
        assert_eq!(
            message("child-after-retirement").causal_order(observed),
            CausalOrder::Concurrent,
            "mode={mode}, child={child_id:?}"
        );
    }
}
