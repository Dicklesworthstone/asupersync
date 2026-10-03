//! Runtime monitors and links fire when the watched task finishes
//! (br-asupersync-issue65-criticisms-kpmoy5.6.1).
//!
//! Every case runs on the native current-thread and multi-thread runtimes
//! through the public API. Targets wait on a gate until the watcher has its
//! monitor or link, so each test reaches the "watch established, target
//! live" state before the target exits.

#![allow(missing_docs)]

use asupersync::Cx;
use asupersync::monitor::{DownNotification, WatchError};
use asupersync::runtime::{JoinError, Runtime, RuntimeBuilder, yield_now};
use asupersync::types::{CancelKind, TaskId};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

fn runtimes() -> Vec<(&'static str, Runtime)> {
    vec![
        (
            "current_thread",
            RuntimeBuilder::current_thread()
                .build()
                .expect("current-thread runtime"),
        ),
        (
            "multi_thread",
            RuntimeBuilder::new()
                .worker_threads(2)
                .build()
                .expect("multi-thread runtime"),
        ),
    ]
}

/// Runs `body` inside a spawned task, so it has a task `Cx`.
fn in_task<F, Fut, T>(rt: &Runtime, body: F) -> T
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    rt.block_on(rt.handle().spawn(async move {
        let cx = Cx::current().expect("a spawned task has a Cx");
        body(cx).await
    }))
}

/// Yields until `gate` opens.
async fn wait_for(gate: &AtomicBool) {
    while !gate.load(Ordering::Acquire) {
        yield_now().await;
    }
}

/// Yields until `cx` is cancelled; returns the cancellation kind.
async fn run_until_cancelled(cx: &Cx) -> Option<CancelKind> {
    loop {
        if cx.checkpoint().is_err() {
            return cx.cancel_reason().map(|reason| reason.kind);
        }
        yield_now().await;
    }
}

#[test]
fn a_monitor_delivers_one_down_with_the_exit_reason() {
    for (flavor, rt) in runtimes() {
        let (normal, panicked, cancelled, ids_match) = in_task(&rt, |cx| async move {
            let gate = Arc::new(AtomicBool::new(false));
            let g = Arc::clone(&gate);
            let ok = cx
                .spawn(move |_| async move { wait_for(&g).await })
                .expect("spawn ok");
            let g = Arc::clone(&gate);
            let panics = cx
                .spawn(move |_| async move {
                    wait_for(&g).await;
                    panic!("monitored task panics");
                })
                .expect("spawn panics");
            let cancelled = cx
                .spawn(|cx| async move { run_until_cancelled(&cx).await })
                .expect("spawn cancelled");

            // Monitor through the handles: the spawns may not be admitted yet.
            let m_ok = cx.monitor(&ok).await.expect("monitor ok");
            let m_panics = cx.monitor(&panics).await.expect("monitor panics");
            let m_cancelled = cx.monitor(&cancelled).await.expect("monitor cancelled");
            assert!(m_ok.try_down().is_none(), "targets wait on the gate");
            let ids_match = m_ok.monitored() == ok.task_id()
                && m_panics.monitored() == panics.task_id()
                && m_cancelled.monitored() == cancelled.task_id();

            gate.store(true, Ordering::Release);
            cancelled.abort();
            let normal = m_ok.down(&cx).await.expect("DOWN for ok");
            let panicked = m_panics.down(&cx).await.expect("DOWN for panics");
            let cancelled_down = m_cancelled.down(&cx).await.expect("DOWN for cancelled");
            // Later calls return the same notification.
            let again = m_ok.down(&cx).await.expect("DOWN again");
            assert_eq!(again.monitor_ref, normal.monitor_ref);
            (normal, panicked, cancelled_down, ids_match)
        });
        assert!(normal.reason.is_normal(), "{flavor}: {:?}", normal.reason);
        assert!(
            panicked.reason.is_panicked(),
            "{flavor}: {:?}",
            panicked.reason
        );
        assert!(
            cancelled.reason.is_cancelled(),
            "{flavor}: {:?}",
            cancelled.reason
        );
        assert!(ids_match, "{flavor}: Monitor::monitored is the admitted id");
    }
}

#[test]
fn a_monitor_on_a_finished_task_is_not_found() {
    for (flavor, rt) in runtimes() {
        let result = in_task(&rt, |cx| async move {
            let mut done = cx.spawn(|_| async {}).expect("spawn");
            let id = done.task_id();
            done.join(&cx).await.expect("join");
            cx.monitor(id).await.map(|monitor| monitor.monitor_ref())
        });
        assert_eq!(result, Err(WatchError::NotFound), "{flavor}");
    }
}

#[test]
fn dropping_a_monitor_before_exit_delivers_nothing_to_it() {
    for (flavor, rt) in runtimes() {
        let (kept, outcome) = in_task(&rt, |cx| async move {
            let gate = Arc::new(AtomicBool::new(false));
            let g = Arc::clone(&gate);
            let mut target = cx
                .spawn(move |_| async move { wait_for(&g).await })
                .expect("spawn");
            let dropped = cx.monitor(&target).await.expect("monitor");
            let kept = cx.monitor(&target).await.expect("monitor");
            drop(dropped);
            gate.store(true, Ordering::Release);
            let down: DownNotification = kept.down(&cx).await.expect("DOWN");
            let outcome = target.join(&cx).await.map_err(|e| format!("{e:?}"));
            (down, outcome)
        });
        assert!(kept.reason.is_normal(), "{flavor}");
        assert_eq!(outcome, Ok(()), "{flavor}");
    }
}

#[test]
fn an_abnormal_exit_cancels_the_linked_task_with_a_linked_exit_reason() {
    for (flavor, rt) in runtimes() {
        let worker_cancel = in_task(&rt, |cx| async move {
            let worker_id = Arc::new(OnceLock::<TaskId>::new());
            let w = Arc::clone(&worker_id);
            let mut worker = cx
                .spawn(move |cx| async move {
                    let _ = w.set(cx.task_id());
                    run_until_cancelled(&cx).await
                })
                .expect("spawn worker");
            let w = Arc::clone(&worker_id);
            let linked = Arc::new(AtomicBool::new(false));
            let l = Arc::clone(&linked);
            let _crasher = cx
                .spawn(move |cx| async move {
                    let peer = loop {
                        if let Some(id) = w.get() {
                            break *id;
                        }
                        yield_now().await;
                    };
                    let _link = cx.link(peer).await.expect("link to worker");
                    l.store(true, Ordering::Release);
                    panic!("linked task panics");
                })
                .expect("spawn crasher");
            // A task that acknowledged cancellation and returned keeps or loses
            // its value depending on the spawn policy; either way the kind is
            // visible.
            match worker.join(&cx).await {
                Ok(kind) => kind,
                Err(JoinError::Cancelled(reason)) => Some(reason.kind),
                Err(other) => panic!("worker failed: {other:?}"),
            }
        });
        assert_eq!(worker_cancel, Some(CancelKind::LinkedExit), "{flavor}");
    }
}

#[test]
fn a_normal_exit_leaves_the_linked_task_running() {
    for (flavor, rt) in runtimes() {
        let worker_was_cancelled = in_task(&rt, |cx| async move {
            let gate = Arc::new(AtomicBool::new(false));
            let g = Arc::clone(&gate);
            let mut worker = cx
                .spawn(move |cx| async move {
                    wait_for(&g).await;
                    cx.is_cancel_requested()
                })
                .expect("spawn worker");
            let link = cx.link(&worker).await.expect("link");
            assert!(link.try_exit().is_none());
            drop(link); // Dropping the handle does not unlink.
            gate.store(true, Ordering::Release);
            worker.join(&cx).await.expect("worker finishes")
        });
        assert!(
            !worker_was_cancelled,
            "{flavor}: a normal exit must not cancel"
        );
    }
}

#[test]
fn a_trapping_link_delivers_the_peer_exit_and_keeps_the_caller_running() {
    for (flavor, rt) in runtimes() {
        let (abnormal, normal, still_running) = in_task(&rt, |cx| async move {
            let gate = Arc::new(AtomicBool::new(false));
            let g = Arc::clone(&gate);
            let crasher = cx
                .spawn(move |_| async move {
                    wait_for(&g).await;
                    panic!("trapped peer panics");
                })
                .expect("spawn crasher");
            let g = Arc::clone(&gate);
            let quitter = cx
                .spawn(move |_| async move { wait_for(&g).await })
                .expect("spawn quitter");
            let trap_crash = cx.link_trapping(&crasher).await.expect("trap crasher");
            let trap_quit = cx.link_trapping(&quitter).await.expect("trap quitter");
            gate.store(true, Ordering::Release);
            let abnormal = trap_crash.exit(&cx).await.expect("exit signal");
            let normal = trap_quit.exit(&cx).await.expect("exit signal");
            (abnormal, normal, cx.checkpoint().is_ok())
        });
        assert!(
            abnormal.reason.is_panicked(),
            "{flavor}: {:?}",
            abnormal.reason
        );
        assert!(normal.reason.is_normal(), "{flavor}: {:?}", normal.reason);
        assert!(still_running, "{flavor}: a trapping task is not cancelled");
    }
}

#[test]
fn monitors_and_links_are_deterministic_under_the_lab() {
    fn scenario(seed: u64) -> (Vec<String>, bool) {
        let (downs, report) = asupersync::lab::run_async_under_lab(seed, |cx| async move {
            let gate = Arc::new(AtomicBool::new(false));
            let mut monitors = Vec::new();
            let mut handles = Vec::new();
            for i in 0..4u32 {
                let g = Arc::clone(&gate);
                // Even children finish normally; odd ones run until cancelled.
                let child = cx
                    .spawn(move |cx| async move {
                        if i % 2 == 0 {
                            wait_for(&g).await;
                        } else {
                            let _ = run_until_cancelled(&cx).await;
                        }
                    })
                    .expect("spawn child");
                monitors.push(cx.monitor(&child).await.expect("monitor child"));
                handles.push(child);
            }
            gate.store(true, Ordering::Release);
            for (i, handle) in handles.iter().enumerate() {
                if i % 2 == 1 {
                    handle.abort();
                }
            }
            let mut downs = Vec::new();
            for monitor in &monitors {
                let down = monitor.down(&cx).await.expect("DOWN");
                downs.push(format!("{} {}", down.monitor_ref, down.reason));
            }
            downs
        });
        (downs, report.quiescent)
    }
    let (first, quiescent) = scenario(0x5eed);
    let (second, _) = scenario(0x5eed);
    assert!(quiescent, "the lab run reaches quiescence");
    assert_eq!(first.len(), 4);
    assert_eq!(first, second, "same seed, same DOWN sequence");
    for (i, line) in first.iter().enumerate() {
        let expected = if i % 2 == 0 { "normal" } else { "cancelled" };
        assert!(line.contains(expected), "child {i}: {line}");
    }
}
