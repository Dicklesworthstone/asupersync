//! Live cancellation mask observations for asupersync-vcu2oz H1.
//! Fixed seed 0xCACE; run this module and the native cancellation audit through RCH.

use super::*;
use crate::cx::Cx;
use crate::lab::oracle::cancellation_protocol::{
    CancelCorrectnessConfig, CancellationProtocolOracle, CancellationProtocolViolation,
    EnforcementMode,
};
use crate::types::{Budget, CancelKind};
use std::sync::atomic::{AtomicUsize, Ordering};

fn mask_lab(enabled: bool) -> LabRuntime {
    let mut lab = LabRuntime::new(
        LabConfig::new(0xCACE)
            .with_cancellation_oracle(enabled)
            .panic_on_cancellation_violation(false),
    );
    lab.oracles.cancellation_protocol =
        CancellationProtocolOracle::with_config(CancelCorrectnessConfig {
            enforcement: EnforcementMode::Collect,
            capture_stacks: false,
            max_violations_tracked: 100,
            structured_logging: false,
        });
    lab
}

fn context(lab: &LabRuntime, task: TaskId) -> Cx {
    lab.state.task(task).unwrap().cx.as_ref().unwrap().clone()
}

fn plant_masked_ack(cx: &Cx, with_message: bool) {
    cx.masked(|| {
        // Deliberately corrupt only the implementation counter while the real
        // lexical MaskGuard stays live. Ordered observation must catch this;
        // the final zero-depth snapshot alone cannot distinguish it.
        cx.inner.write().mask_depth = 0;
        cx.cancel_with(CancelKind::User, Some("planted masked acknowledgement"));
        let result = if with_message {
            cx.checkpoint_with("planted checkpoint")
        } else {
            cx.checkpoint()
        };
        assert!(result.is_err());
    });
}

#[test]
fn live_nested_masks_defer_ack_and_restore_after_caught_unwind() {
    let mut lab = mask_lab(true);
    let root = lab.state.create_root_region(Budget::INFINITE);
    let finished = Arc::new(AtomicUsize::new(0));
    let marker = Arc::clone(&finished);
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            cx.masked(|| {
                cx.cancel_with(CancelKind::User, Some("nested mask"));
                assert!(cx.checkpoint().is_ok());
                let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    cx.masked(|| {
                        assert!(cx.checkpoint_with("nested").is_ok());
                        panic!("unwind only the nested mask");
                    });
                }));
                assert!(panic.is_err());
                assert!(cx.checkpoint_with("outer remains masked").is_ok());
            });
            assert!(cx.checkpoint().is_err());
            marker.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    assert_eq!(finished.load(Ordering::SeqCst), 1);
    assert_eq!(lab.oracles.cancellation_protocol.task_mask_depth(task), Some(0));
    assert!(
        lab.oracles.cancellation_protocol.all_violations().is_empty(),
        "{:?}",
        lab.oracles.cancellation_protocol.all_violations()
    );
    assert!(lab.is_quiescent());
}

#[test]
fn live_checkpoint_ack_before_same_poll_mask_exit_is_detected() {
    for with_message in [false, true] {
        let mut lab = mask_lab(true);
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task, _join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                plant_masked_ack(&Cx::current().unwrap(), with_message);
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        let violations = lab.oracles.cancellation_protocol.all_violations();
        assert_eq!(
            violations
                .iter()
                .filter(|v| matches!(
                    v,
                    CancellationProtocolViolation::CancelAckWhileMasked {
                        task: observed,
                        mask_depth: 1,
                        ..
                    } if *observed == task
                ))
                .count(),
            1,
            "the checkpoint is checked before its later exit: {violations:?}"
        );
        assert_eq!(lab.oracles.cancellation_protocol.task_mask_depth(task), Some(0));
        assert!(lab.is_quiescent());
    }
}

#[test]
fn live_mask_observation_excludes_derived_and_foreign_same_id_contexts() {
    let mut lab = mask_lab(true);
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, async {
            let primary = Cx::current().unwrap();
            let derived = primary.derive_cancel_scope();
            let foreign = Cx::new(primary.region_id(), primary.task_id(), Budget::INFINITE);
            for context in [derived, foreign] {
                assert_eq!(context.task_id(), primary.task_id());
                assert!(!Arc::ptr_eq(&context.inner, &primary.inner));
                plant_masked_ack(&context, true);
            }
            assert!(primary.checkpoint().is_ok());
        })
        .unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    assert_eq!(lab.oracles.cancellation_protocol.task_mask_depth(task), Some(0));
    assert!(lab.oracles.cancellation_protocol.all_violations().is_empty());
}

#[test]
fn disabled_lab_mask_observer_does_not_record_planted_faults() {
    let mut lab = mask_lab(false);
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, async {
            plant_masked_ack(&Cx::current().unwrap(), false);
        })
        .unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    assert_eq!(lab.oracles.cancellation_protocol.task_mask_depth(task), None);
    assert!(lab.oracles.cancellation_protocol.all_violations().is_empty());
}

#[test]
fn host_mask_spanning_polls_is_seeded_then_cleared_before_ack() {
    let mut lab = mask_lab(true);
    let root = lab.state.create_root_region(Budget::INFINITE);
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&polls);
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            std::future::poll_fn(move |poll_cx| {
                let cx = Cx::current().unwrap();
                let poll = observed.fetch_add(1, Ordering::SeqCst);
                if poll < 2 {
                    cx.cancel_with(CancelKind::User, Some("host mask"));
                    cx.masked(|| assert!(cx.checkpoint_with("still masked").is_ok()));
                    assert!(cx.checkpoint().is_ok());
                    poll_cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    assert!(cx.checkpoint().is_err());
                    Poll::Ready(())
                }
            })
            .await;
        })
        .unwrap();
    let cx = context(&lab, task);
    lab.scheduler.lock().schedule(task, 0);
    cx.masked(|| {
        lab.step_for_test();
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(lab.oracles.cancellation_protocol.task_mask_depth(task), Some(1));
        lab.step_for_test();
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(lab.oracles.cancellation_protocol.task_mask_depth(task), Some(1));
    });
    lab.run_until_idle();
    assert_eq!(polls.load(Ordering::SeqCst), 3);
    assert_eq!(lab.oracles.cancellation_protocol.task_mask_depth(task), Some(0));
    assert!(lab.oracles.cancellation_protocol.all_violations().is_empty());
}

#[test]
fn live_poll_snapshot_checks_the_mask_depth_bound() {
    let mut lab = mask_lab(true);
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, async {
            Cx::current().unwrap().inner.write().mask_depth = 0;
        })
        .unwrap();
    context(&lab, task).inner.write().mask_depth = crate::types::MAX_MASK_DEPTH + 1;
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    assert!(
        lab.oracles.cancellation_protocol.all_violations().iter().any(|v| matches!(
            v,
            CancellationProtocolViolation::MaskDepthExceeded { task: observed, .. }
                if *observed == task
        ))
    );
}

#[test]
fn admitted_async_finalizer_masks_are_observed_across_poll_and_completion() {
    for broken in [false, true] {
        let mut lab = mask_lab(true);
        let root = lab.state.create_root_region(Budget::INFINITE);
        let observed = Arc::new(Mutex::new(None));
        let completed = Arc::new(AtomicUsize::new(0));
        let task_slot = Arc::clone(&observed);
        let marker = Arc::clone(&completed);
        assert!(lab.state.register_async_finalizer(root, async move {
            let cx = Cx::current().expect("admitted finalizer context");
            *task_slot.lock() = Some(cx.task_id());
            assert_eq!(cx.inner.read().mask_depth, 1);
            cx.cancel_with(CancelKind::User, Some("finalizer mask observation"));
            if broken {
                cx.inner.write().mask_depth = 0;
                assert!(cx.checkpoint_with("planted finalizer acknowledgement").is_err());
            } else {
                assert!(cx.checkpoint().is_ok());
                let mut pending = true;
                std::future::poll_fn(move |poll_cx| {
                    if pending {
                        pending = false;
                        poll_cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;
                assert!(cx.checkpoint_with("finalizer remains masked").is_ok());
            }
            marker.fetch_add(1, Ordering::SeqCst);
        }));
        lab.state.close_region_command(
            root,
            &crate::types::CancelReason::user("observe admitted finalizer"),
        );
        lab.schedule_async_finalizers();
        lab.run_until_idle();
        let task = (*observed.lock()).expect("the finalizer really ran");
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        assert_eq!(lab.oracles.cancellation_protocol.task_mask_depth(task), Some(0));
        let masked_acks = lab
            .oracles
            .cancellation_protocol
            .all_violations()
            .into_iter()
            .filter(|violation| matches!(
                violation,
                CancellationProtocolViolation::CancelAckWhileMasked {
                    task: observed,
                    ..
                } if *observed == task
            ))
            .count();
        assert_eq!(masked_acks, usize::from(broken));
        assert!(lab.is_quiescent());
    }
}

#[test]
fn acknowledgement_before_a_persistent_finalizer_mask_is_not_rechecked_at_receipt() {
    for acknowledge_in_poll in [false, true] {
        let mut lab = mask_lab(true);
        let root = lab.state.create_root_region(Budget::INFINITE);
        let completed = Arc::new(AtomicUsize::new(0));
        let marker = Arc::clone(&completed);
        assert!(lab.state.register_async_finalizer(root, async move {
            let cx = Cx::current().unwrap();
            assert!(cx.checkpoint_with("finalizer starts masked").is_ok());
            let mut pending = true;
            std::future::poll_fn(move |poll_cx| {
                if pending {
                    pending = false;
                    poll_cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            assert!(cx.checkpoint_with("finalizer remains masked").is_ok());
            marker.fetch_add(1, Ordering::SeqCst);
        }));
        lab.state.close_region_command(
            root,
            &crate::types::CancelReason::user("acknowledgement before cleanup"),
        );
        let mut admitted = lab.state.drain_ready_async_finalizers();
        assert_eq!(admitted.len(), 1);
        let (task, priority, effects) = admitted.pop().unwrap();
        let cx = context(&lab, task);
        if !acknowledge_in_poll {
            // A host can acknowledge before the next observed poll begins.
            cx.cancel_with(CancelKind::User, Some("host acknowledgement"));
            assert!(cx.checkpoint().is_err());
        }
        // Keep the actual admitted finalizer and its persistent runtime mask.
        // The wrapper adds a valid unmasked checkpoint before its first poll.
        let mut stored = lab.state.remove_stored_future(task).unwrap();
        let mut first = true;
        let wrapped = std::future::poll_fn(move |poll_cx| {
            if first {
                first = false;
                if acknowledge_in_poll {
                    let cx = Cx::current().unwrap();
                    cx.cancel_with(CancelKind::User, Some("in-poll acknowledgement"));
                    assert!(cx.checkpoint().is_err());
                }
            }
            stored.poll(poll_cx)
        });
        lab.state.store_spawned_task(
            task,
            crate::runtime::StoredTask::new_with_id(wrapped, task),
        );
        lab.scheduler.lock().schedule(task, priority);
        effects.dispatch();
        lab.step_for_test();
        assert_eq!(completed.load(Ordering::SeqCst), 0);
        assert_eq!(lab.oracles.cancellation_protocol.task_mask_depth(task), Some(1));
        assert!(
            !lab.oracles.cancellation_protocol.all_violations().iter().any(|violation| {
                matches!(violation, CancellationProtocolViolation::CancelAckWhileMasked { .. })
            })
        );
        lab.run_until_idle();
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        assert_eq!(lab.oracles.cancellation_protocol.task_mask_depth(task), Some(0));
        assert!(lab.oracles.cancellation_protocol.all_violations().is_empty());
        assert!(lab.is_quiescent());
    }
}
