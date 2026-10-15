//! br-e2e-226: channel/mpsc <-> combinator/select integration E2E tests
//!
//! Tests integration between MPSC channels and select combinators for
//! multi-producer coordination, proper selection logic, and resource management.

use crate::channel::mpsc::{self, RecvError};
use crate::combinator::select::{Either, Select, SelectAll, SelectAllDrain};
use crate::cx::{Cx, cap};
use futures_lite::future::block_on;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Message {
    channel: &'static str,
    sequence: u64,
}

/// Runs the channel/MPSC select scenarios through the public API surface.
///
/// This is intentionally available outside `cfg(test)` so the exact public
/// runner can execute the same scenarios without compiling the unrelated
/// conformance dev-dependency tail.
pub fn run_all() {
    select_recv_keeps_unselected_channel_drained_by_caller();
    select_all_can_mix_bounded_and_unbounded_receivers();
    select_all_drain_returns_pending_mpsc_losers();
    selected_receiver_can_continue_with_recv_many_batching();
    checked_payload_disconnect_finalize_and_reuse();
}

fn select_recv_keeps_unselected_channel_drained_by_caller() {
    let cx = Cx::<cap::None>::detached_cancel_context();
    let (left_tx, mut left_rx) = mpsc::channel(2);
    let (right_tx, mut right_rx) = mpsc::channel(2);

    left_tx
        .try_send(Message {
            channel: "left",
            sequence: 1,
        })
        .expect("left channel has capacity");
    right_tx
        .try_send(Message {
            channel: "right",
            sequence: 2,
        })
        .expect("right channel has capacity");

    let selected =
        block_on(Select::new(left_rx.recv(&cx), right_rx.recv(&cx))).expect("fresh select future");

    match selected {
        Either::Left(Ok(message)) => {
            assert_eq!(
                message,
                Message {
                    channel: "left",
                    sequence: 1
                }
            );
        }
        other => panic!("expected left mpsc receiver to win select, got {other:?}"),
    }

    assert_eq!(
        right_rx.try_recv(),
        Ok(Message {
            channel: "right",
            sequence: 2
        }),
        "raw Select drops the loser future; callers still own draining"
    );
}

fn select_all_can_mix_bounded_and_unbounded_receivers() {
    let cx = Cx::<cap::None>::detached_cancel_context();
    let (_bounded_tx, mut bounded_rx) = mpsc::channel::<Message>(2);
    let (unbounded_tx, mut unbounded_rx) = mpsc::unbounded_channel();

    unbounded_tx
        .send(Message {
            channel: "unbounded",
            sequence: 7,
        })
        .expect("unbounded receiver is live");

    let (selected, index) = block_on(SelectAll::new(vec![
        bounded_rx.recv(&cx),
        unbounded_rx.recv(&cx),
    ]))
    .expect("fresh select_all future");

    assert_eq!(index, 1);
    assert_eq!(
        selected.expect("unbounded recv succeeds"),
        Message {
            channel: "unbounded",
            sequence: 7
        }
    );
}

fn select_all_drain_returns_pending_mpsc_losers() {
    let cx = Cx::<cap::None>::detached_cancel_context();
    let (_first_tx, mut first_rx) = mpsc::channel::<Message>(1);
    let (second_tx, mut second_rx) = mpsc::channel(1);
    let (_third_tx, mut third_rx) = mpsc::channel::<Message>(1);

    second_tx
        .try_send(Message {
            channel: "second",
            sequence: 11,
        })
        .expect("second channel has capacity");

    {
        let result = block_on(SelectAllDrain::new(vec![
            first_rx.recv(&cx),
            second_rx.recv(&cx),
            third_rx.recv(&cx),
        ]))
        .expect("fresh select_all_drain future");

        let winner_index = result.winner_index;
        let value = result.value;
        let losers = result.losers;

        assert_eq!(winner_index, 1);
        assert_eq!(
            value.expect("winning recv succeeds"),
            Message {
                channel: "second",
                sequence: 11
            }
        );
        assert_eq!(losers.len(), 2);
        drop(losers);
    }

    assert_eq!(first_rx.try_recv(), Err(RecvError::Empty));
    assert_eq!(third_rx.try_recv(), Err(RecvError::Empty));
}

fn selected_receiver_can_continue_with_recv_many_batching() {
    let cx = Cx::<cap::None>::detached_cancel_context();
    let (batch_tx, mut batch_rx) = mpsc::channel(8);
    let (_idle_tx, mut idle_rx) = mpsc::channel::<Message>(1);

    for sequence in 0..5 {
        batch_tx
            .try_send(Message {
                channel: "batch",
                sequence,
            })
            .expect("batch channel has capacity");
    }

    let selected =
        block_on(Select::new(batch_rx.recv(&cx), idle_rx.recv(&cx))).expect("fresh select future");
    let Either::Left(Ok(first)) = selected else {
        panic!("expected populated batch receiver to win select, got {selected:?}");
    };
    assert_eq!(
        first,
        Message {
            channel: "batch",
            sequence: 0
        }
    );

    let mut batch = Vec::new();
    let drained = block_on(batch_rx.recv_many(&cx, &mut batch, 16)).expect("recv_many succeeds");

    assert_eq!(drained, 4);
    assert_eq!(
        batch,
        vec![
            Message {
                channel: "batch",
                sequence: 1
            },
            Message {
                channel: "batch",
                sequence: 2
            },
            Message {
                channel: "batch",
                sequence: 3
            },
            Message {
                channel: "batch",
                sequence: 4
            },
        ]
    );
}

/// A public checked-channel journey through two actual region lifetimes.
/// No synthetic obligation records or manually fed oracle events are used.
fn checked_payload_disconnect_finalize_and_reuse() {
    use crate::lab::{LabConfig, LabRuntime};
    use crate::record::RegionLimits;
    use crate::runtime::yield_now;
    use crate::types::{Budget, CancelReason};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FIRST: &[u8] = b"checked payload before disconnect";
    const REFUSED: &[u8] = b"preserve these disconnected bytes";
    const REUSED: &[u8] = b"same channel after region finalization";
    let mut lab = LabRuntime::new(LabConfig::new(0x29_0501).max_steps(256));
    let first_region = lab.state.create_root_region(Budget::INFINITE);
    let limits = RegionLimits {
        max_obligations: Some(1),
        ..RegionLimits::UNLIMITED
    };
    assert!(lab.state.set_region_limits(first_region, limits.clone()));
    let finalizer_started = Arc::new(AtomicUsize::new(0));
    let finalizer_finished = Arc::new(AtomicUsize::new(0));
    let started = Arc::clone(&finalizer_started);
    let finished = Arc::clone(&finalizer_finished);
    assert!(
        lab.state
            .register_async_finalizer(first_region, async move {
                assert_eq!(started.fetch_add(1, Ordering::SeqCst), 0);
                yield_now().await;
                assert_eq!(finished.fetch_add(1, Ordering::SeqCst), 0);
            })
    );
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(1);
    let observed_sender = sender.clone();
    let (first_holder, mut first_join) = lab
        .state
        .create_task(first_region, Budget::INFINITE, async move {
            let cx = Cx::current().expect("actual first checked journey holder");
            sender.send_checked(&cx, FIRST.to_vec()).await.unwrap();
            assert_eq!(receiver.recv(&cx).await.unwrap(), FIRST);
            sender.reserve_checked(&cx).await.unwrap().abort();
            drop(sender.reserve_checked(&cx).await.unwrap());

            let (disconnected, disconnected_receiver) = mpsc::channel::<Vec<u8>>(1);
            let permit = disconnected.reserve_checked(&cx).await.unwrap();
            assert_eq!(
                disconnected
                    .telemetry_snapshot(2906)
                    .reserved_uncommitted_obligations,
                1
            );
            drop(disconnected_receiver);
            assert_eq!(
                permit.try_send(REFUSED.to_vec()),
                Err(mpsc::SendError::Disconnected(REFUSED.to_vec()))
            );
            assert_eq!(
                disconnected.try_send_checked(&cx, REFUSED.to_vec()),
                Err(mpsc::CheckedSendError::Channel(
                    mpsc::SendError::Disconnected(REFUSED.to_vec())
                ))
            );
            let physical = disconnected.telemetry_snapshot(2906);
            assert_eq!(physical.reserved_uncommitted_obligations, 0);
            assert_eq!(physical.queued_messages, 0);
            assert_eq!(physical.send_waiter_count, 0);
            assert_eq!(physical.recv_waiter_count, 0);
            (sender, receiver)
        })
        .unwrap();
    lab.scheduler.lock().schedule(first_holder, 0);
    assert!(lab.run_until_idle() > 0);
    let (sender, mut receiver) = first_join
        .try_join()
        .unwrap()
        .expect("first holder completes before region close");
    assert!(lab.state.task(first_holder).is_none());
    let gateway = lab.state.obligation_gateway().unwrap();
    let mailbox = gateway.mailbox();
    let first_counts = mailbox.stats();
    assert_eq!(first_counts.reserved, 4);
    assert_eq!(first_counts.committed, 1);
    assert_eq!(first_counts.aborted, 3);
    assert_eq!(first_counts.refused, 0);
    assert_eq!(first_counts.leaked, 0);
    assert_eq!(first_counts.posted, first_counts.applied);
    assert_eq!(mailbox.open_tickets(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert_eq!(finalizer_started.load(Ordering::SeqCst), 0);
    assert_eq!(finalizer_finished.load(Ordering::SeqCst), 0);
    let close_effects = lab.state.cancel_request(
        first_region,
        &CancelReason::user("checked journey first region complete"),
        None,
    );
    let (tasks_to_cancel, wakes) = close_effects.into_parts();
    assert!(tasks_to_cancel.is_empty());
    wakes.dispatch();
    lab.state.advance_region_state(first_region);
    let close_report = lab.run_until_quiescent_with_report();
    assert!(close_report.lab_test_passed(), "{close_report:?}");
    assert_eq!(finalizer_started.load(Ordering::SeqCst), 1);
    assert_eq!(finalizer_finished.load(Ordering::SeqCst), 1);
    assert!(lab.state.region(first_region).is_none());

    // Preserve the original physical endpoints across complete region close;
    // fresh holder/region authority must admit their next use.
    let second_region = lab.state.create_root_region(Budget::INFINITE);
    assert_ne!(second_region, first_region);
    assert!(lab.state.set_region_limits(second_region, limits));
    let (second_holder, mut second_join) = lab
        .state
        .create_task(second_region, Budget::INFINITE, async move {
            let cx = Cx::current().expect("actual post-finalizer checked holder");
            sender.send_checked(&cx, REUSED.to_vec()).await.unwrap();
            assert_eq!(receiver.recv(&cx).await.unwrap(), REUSED);
            REUSED.len()
        })
        .unwrap();
    assert_ne!(first_holder, second_holder);
    lab.scheduler.lock().schedule(second_holder, 0);
    assert!(lab.run_until_idle() > 0);
    assert_eq!(second_join.try_join().unwrap(), Some(REUSED.len()));
    let close_effects = lab.state.cancel_request(
        second_region,
        &CancelReason::user("checked journey reuse complete"),
        None,
    );
    let (tasks_to_cancel, wakes) = close_effects.into_parts();
    assert!(tasks_to_cancel.is_empty());
    wakes.dispatch();
    lab.state.advance_region_state(second_region);
    let report = lab.run_until_quiescent_with_report();
    assert!(report.lab_test_passed(), "{report:?}");
    assert!(lab.state.region(second_region).is_none());
    assert!(lab.state.task(second_holder).is_none());
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert_eq!(lab.state.leak_count(), 0);
    let counts = mailbox.stats();
    assert_eq!(counts.reserved, 5);
    assert_eq!(counts.committed, 2);
    assert_eq!(counts.aborted, 3);
    assert_eq!(counts.refused, 0);
    assert_eq!(counts.leaked, 0);
    assert_eq!(counts.posted, counts.applied);
    assert_eq!(mailbox.open_tickets(), 0);
    let physical = observed_sender.telemetry_snapshot(2906);
    assert_eq!(physical.reserved_uncommitted_obligations, 0);
    assert_eq!(physical.queued_messages, 0);
    assert_eq!(physical.send_waiter_count, 0);
    assert_eq!(physical.recv_waiter_count, 0);
    println!(
        "ASUPERSYNC_CHECKED_OBLIGATION_JOURNEY {}",
        serde_json::json!({
            "schema_version": "asupersync.checked_obligation_journey.v1",
            "bead_id": "asupersync-bi2462.29",
            "seed": 0x29_0501_u64,
            "holders": [first_holder, second_holder],
            "regions": [first_region, second_region],
            "delivered_bytes": FIRST.len() + REUSED.len(),
            "disconnect_preserved_bytes": REFUSED.len(),
            "reserved": counts.reserved, "committed": counts.committed,
            "aborted": counts.aborted, "refused": counts.refused,
            "leaked": counts.leaked, "posted": counts.posted,
            "applied": counts.applied, "pending": lab.state.pending_obligation_count(),
            "open_tickets": mailbox.open_tickets(),
            "finalizers_started": finalizer_started.load(Ordering::SeqCst),
            "finalizers_finished": finalizer_finished.load(Ordering::SeqCst),
            "physical_reserved": physical.reserved_uncommitted_obligations,
            "queued_messages": physical.queued_messages,
            "send_waiters": physical.send_waiter_count,
            "recv_waiters": physical.recv_waiter_count,
            "same_channel_reused_after_close": true,
            "report": report.to_json(),
        })
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn select_recv_keeps_unselected_channel_drained_by_caller() {
        super::select_recv_keeps_unselected_channel_drained_by_caller();
    }

    #[test]
    fn select_all_can_mix_bounded_and_unbounded_receivers() {
        super::select_all_can_mix_bounded_and_unbounded_receivers();
    }

    #[test]
    fn select_all_drain_returns_pending_mpsc_losers() {
        super::select_all_drain_returns_pending_mpsc_losers();
    }

    #[test]
    fn selected_receiver_can_continue_with_recv_many_batching() {
        super::selected_receiver_can_continue_with_recv_many_batching();
    }

    #[test]
    fn checked_payload_disconnect_finalize_and_reuse() {
        super::checked_payload_disconnect_finalize_and_reuse();
    }
}
