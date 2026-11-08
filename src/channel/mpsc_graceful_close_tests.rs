//! Graceful admission sealing preserves accepted two-phase sends until drain.

use super::*;
use crate::types::CancelKind;
use std::task::Wake;

#[derive(Default)]
struct WakeStats {
    wakes: AtomicUsize,
    drops: AtomicUsize,
}

struct UnlockedWake {
    shared: Weak<ChannelShared<u8>>,
    stats: Arc<WakeStats>,
    panic_on_wake: bool,
}

impl UnlockedWake {
    fn assert_unlocked(&self) {
        if let Some(shared) = self.shared.upgrade() {
            assert!(
                shared.inner.try_lock().is_some(),
                "callback under channel lock"
            );
        }
    }
}

impl Wake for UnlockedWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.assert_unlocked();
        self.stats.wakes.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic_on_wake, "injected graceful-close wake panic");
    }
}

impl Drop for UnlockedWake {
    fn drop(&mut self) {
        self.assert_unlocked();
        self.stats.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn unlocked_waker(sender: &Sender<u8>, panic_on_wake: bool) -> (Arc<WakeStats>, Waker) {
    crate::test_utils::init_test_logging();
    let stats = Arc::new(WakeStats::default());
    let waker = Waker::from(Arc::new(UnlockedWake {
        shared: Arc::downgrade(&sender.shared),
        stats: Arc::clone(&stats),
        panic_on_wake,
    }));
    (stats, waker)
}

#[test]
fn graceful_close_preserves_permits_and_fifo_while_sealing_every_sender() {
    let (sender, mut receiver) = channel::<u8>(3);
    sender.try_send(10).unwrap();
    let first = sender.try_reserve().unwrap();
    let second = sender.try_reserve().unwrap();
    let weak = sender.downgrade();

    receiver.close_gracefully();
    receiver.close_gracefully();
    assert!(sender.is_closed());
    assert!(
        !receiver.is_closed(),
        "live senders keep their existing meaning"
    );
    assert_eq!(sender.try_send(99), Err(SendError::Disconnected(99)));
    assert!(matches!(
        sender.try_reserve(),
        Err(SendError::Disconnected(()))
    ));
    assert_eq!(sender.clone().try_send(98), Err(SendError::Disconnected(98)));
    assert_eq!(
        weak.upgrade().unwrap().try_send(97),
        Err(SendError::Disconnected(97))
    );
    let snapshot = sender.telemetry_snapshot(1);
    assert!(snapshot.closed);
    assert_eq!(snapshot.receiver_health, "gracefully_closed");
    assert_eq!(snapshot.reserved_uncommitted_obligations, 2);

    assert_eq!(receiver.try_recv(), Ok(10));
    assert_eq!(receiver.try_recv(), Err(RecvError::Empty));
    first.try_send(20).unwrap();
    assert_eq!(receiver.try_recv(), Ok(20));
    assert_eq!(receiver.try_recv(), Err(RecvError::Empty));
    second.try_send(30).unwrap();
    assert_eq!(receiver.try_recv(), Ok(30));
    assert_eq!(receiver.try_recv(), Err(RecvError::Disconnected));
    assert_eq!(sender.debug_counts(), (0, 0));
}

#[test]
fn final_unused_permit_wakes_single_and_batch_receivers_without_producer_activity() {
    for batch in [false, true] {
        for explicit_abort in [false, true] {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = channel::<u8>(2);
            let first = sender.try_reserve().unwrap();
            let last = sender.try_reserve().unwrap();
            receiver.close_gracefully();
            let mut buffer = vec![42];
            let stats = {
                let (stats, waker) = unlocked_waker(&sender, false);
                let mut task = Context::from_waker(&waker);
                if batch {
                    assert!(
                        receiver
                            .poll_recv_many(&cx, &mut buffer, 4, &mut task)
                            .is_pending()
                    );
                } else {
                    assert!(receiver.poll_recv(&cx, &mut task).is_pending());
                }
                stats
            };
            first.abort();
            assert_eq!(stats.wakes.load(Ordering::SeqCst), 0);
            assert_eq!(receiver.try_recv(), Err(RecvError::Empty));
            if explicit_abort {
                last.abort();
            } else {
                drop(last);
            }
            assert_eq!(stats.wakes.load(Ordering::SeqCst), 1);
            assert_eq!(stats.drops.load(Ordering::SeqCst), 1);
            let mut task = Context::from_waker(Waker::noop());
            if batch {
                assert_eq!(
                    receiver.poll_recv_many(&cx, &mut buffer, 4, &mut task),
                    Poll::Ready(Ok(0))
                );
            } else {
                assert_eq!(
                    receiver.poll_recv(&cx, &mut task),
                    Poll::Ready(Err(RecvError::Disconnected))
                );
            }
            assert_eq!(buffer, [42]);
            assert_eq!(sender.debug_counts(), (0, 0));
        }
    }
}

#[test]
fn graceful_batch_drain_waits_for_late_commits_and_retains_buffer_prefix() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel::<u8>(4);
    sender.try_send(1).unwrap();
    sender.try_send(2).unwrap();
    let accepted = sender.try_reserve().unwrap();
    let unused = sender.try_reserve().unwrap();
    receiver.close_gracefully();
    let (stats, waker) = unlocked_waker(&sender, false);
    let mut task = Context::from_waker(&waker);
    let mut buffer = vec![99];

    assert_eq!(
        receiver.poll_recv_many(&cx, &mut buffer, 1, &mut task),
        Poll::Ready(Ok(1))
    );
    assert_eq!(buffer, [99, 1]);
    assert_eq!(
        receiver.poll_recv_many(&cx, &mut buffer, 8, &mut task),
        Poll::Ready(Ok(1))
    );
    assert!(
        receiver
            .poll_recv_many(&cx, &mut buffer, 8, &mut task)
            .is_pending()
    );
    accepted.try_send(3).unwrap();
    assert_eq!(stats.wakes.load(Ordering::SeqCst), 1);
    {
        let mut batch = Box::pin(receiver.recv_many(&cx, &mut buffer, 8));
        assert_eq!(batch.as_mut().poll(&mut task), Poll::Ready(Ok(1)));
    }
    assert_eq!(buffer, [99, 1, 2, 3]);
    assert!(
        receiver
            .poll_recv_many(&cx, &mut buffer, 8, &mut task)
            .is_pending()
    );
    unused.abort();
    assert_eq!(stats.wakes.load(Ordering::SeqCst), 2);
    assert_eq!(
        receiver.poll_recv_many(&cx, &mut buffer, 8, &mut task),
        Poll::Ready(Ok(0))
    );
    assert_eq!(buffer, [99, 1, 2, 3]);
}

#[test]
fn seal_wakes_blocked_reservers_and_closed_observers_before_drain() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel::<u8>(1);
    let accepted = sender.try_reserve().unwrap();
    let (sender_stats, sender_waker) = unlocked_waker(&sender, false);
    let (closed_stats, closed_waker) = unlocked_waker(&sender, false);
    let mut sender_task = Context::from_waker(&sender_waker);
    let mut closed_task = Context::from_waker(&closed_waker);
    let mut waiting = Box::pin(sender.reserve(&cx));
    let mut closed = Box::pin(sender.closed());
    assert!(waiting.as_mut().poll(&mut sender_task).is_pending());
    assert!(closed.as_mut().poll(&mut closed_task).is_pending());

    receiver.close_gracefully();
    assert!(sender_stats.wakes.load(Ordering::SeqCst) > 0);
    assert!(closed_stats.wakes.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        waiting.as_mut().poll(&mut sender_task),
        Poll::Ready(Err(SendError::Disconnected(())))
    ));
    assert!(closed.as_mut().poll(&mut closed_task).is_ready());
    assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 0);
    assert_eq!(receiver.try_recv(), Err(RecvError::Empty));
    accepted.try_send(7).unwrap();
    assert_eq!(receiver.try_recv(), Ok(7));
    assert_eq!(receiver.try_recv(), Err(RecvError::Disconnected));
}

#[test]
fn hard_close_strengthens_graceful_close_and_wakes_parked_receive() {
    for through_sender in [false, true] {
        for batch in [false, true] {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = channel::<u8>(1);
            let accepted = sender.try_reserve().unwrap();
            receiver.close_gracefully();
            let (stats, waker) = unlocked_waker(&sender, false);
            let mut task = Context::from_waker(&waker);
            let mut buffer = Vec::new();
            if batch {
                assert!(
                    receiver
                        .poll_recv_many(&cx, &mut buffer, 1, &mut task)
                        .is_pending()
                );
            } else {
                assert!(receiver.poll_recv(&cx, &mut task).is_pending());
            }

            if through_sender {
                sender.close_receiver();
            } else {
                receiver.close();
            }
            assert_eq!(stats.wakes.load(Ordering::SeqCst), 1);
            receiver.close_gracefully();
            assert_eq!(receiver.try_recv(), Err(RecvError::Disconnected));
            assert_eq!(accepted.try_send(8), Err(SendError::Disconnected(8)));
            assert_eq!(sender.debug_counts(), (0, 0));
        }
    }
}

#[test]
fn dropping_graceful_receiver_revokes_remaining_permits_and_preserves_values() {
    let (sender, mut receiver) = channel::<String>(2);
    sender.try_send("queued".to_owned()).unwrap();
    let accepted = sender.try_reserve().unwrap();
    receiver.close_gracefully();
    drop(receiver);

    let value = "not published".to_owned();
    let original = value.as_ptr();
    let Err(SendError::Disconnected(returned)) = accepted.try_send(value) else {
        panic!("dropping the receiver must revoke a preserved permit");
    };
    assert_eq!(returned, "not published");
    assert_eq!(returned.as_ptr(), original);
    assert_eq!(sender.debug_counts(), (0, 0));
}

#[test]
fn cancellation_during_graceful_drain_does_not_revoke_accepted_work() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel::<u8>(1);
    let accepted = sender.try_reserve().unwrap();
    receiver.close_gracefully();
    let (stats, waker) = unlocked_waker(&sender, false);
    let mut task = Context::from_waker(&waker);
    {
        let mut waiting = Box::pin(receiver.recv(&cx));
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        cx.cancel_fast(CancelKind::User);
        assert!(stats.wakes.load(Ordering::SeqCst) > 0);
        assert_eq!(
            waiting.as_mut().poll(&mut task),
            Poll::Ready(Err(RecvError::Cancelled))
        );
    }
    assert_eq!(sender.telemetry_snapshot(1).recv_waiter_count, 0);
    accepted.try_send(12).unwrap();
    let drain_cx = Cx::for_testing();
    assert_eq!(receiver.poll_recv(&drain_cx, &mut task), Poll::Ready(Ok(12)));
    assert_eq!(
        receiver.poll_recv(&drain_cx, &mut task),
        Poll::Ready(Err(RecvError::Disconnected))
    );
}

#[test]
fn graceful_close_conserves_checked_obligations_on_commit_abort_and_drop() {
    let mut lab = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(0x9a_c105).max_steps(128));
    let root = lab.state.create_root_region(crate::types::Budget::INFINITE);
    assert!(lab.state.set_region_limits(
        root,
        crate::record::region::RegionLimits {
            max_obligations: Some(3),
            ..crate::record::region::RegionLimits::UNLIMITED
        }
    ));
    let (task, mut handle) = lab
        .state
        .create_task(root, crate::types::Budget::INFINITE, async {})
        .unwrap();
    let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
    let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
    let (sender, mut receiver) = channel::<u8>(3);
    let committed = sender.try_reserve_checked(&cx).unwrap();
    let aborted = sender.try_reserve_checked(&cx).unwrap();
    let dropped = sender.try_reserve_checked(&cx).unwrap();
    receiver.close_gracefully();
    assert!(matches!(
        sender.try_reserve_checked(&cx),
        Err(CheckedSendError::Channel(SendError::Disconnected(())))
    ));
    committed.try_send(11).unwrap();
    aborted.abort();
    drop(dropped);
    assert_eq!(receiver.try_recv(), Ok(11));
    assert_eq!(receiver.try_recv(), Err(RecvError::Disconnected));

    lab.scheduler.lock().schedule(cx.task_id(), 0);
    let report = lab.run_until_quiescent_with_report();
    assert!(
        report.oracle_report.all_passed(),
        "{:?}",
        report.oracle_report.failures()
    );
    assert!(report.invariant_violations.is_empty());
    assert!(handle.try_join().unwrap().is_some());
    let stats = mailbox.stats();
    assert_eq!(stats.posted, stats.applied);
    assert_eq!(stats.reserved, 3);
    assert_eq!(stats.committed, 1);
    assert_eq!(stats.aborted, 2);
    assert_eq!(stats.refused, 0);
    assert_eq!(stats.leaked, 0);
    assert_eq!(mailbox.open_tickets(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert_eq!(lab.state.leak_count(), 0);
}

#[test]
fn sealing_during_obligation_admission_preserves_or_retires_the_physical_slot() {
    use crate::runtime::obligation_mailbox::ObligationAdmissionError;

    for admitted in [false, true] {
        let cx = Cx::for_testing();
        let (sender, mut receiver) = channel::<u8>(1);
        let (stats, waker) = unlocked_waker(&sender, false);
        let mut task = Context::from_waker(&waker);
        let mut reserve = Box::pin(sender.reserve(&cx));
        let result = reserve.as_mut().poll_with_registration(&mut task, |_| {
            // The slot already exists, but reserve has not returned a permit.
            // Exercise the real unlocked admission boundary deterministically.
            receiver.close_gracefully();
            let mut receive_task = Context::from_waker(&waker);
            assert!(receiver.poll_recv(&cx, &mut receive_task).is_pending());
            if admitted {
                Ok(None)
            } else {
                Err(CheckedSendError::Admission {
                    error: ObligationAdmissionError::LimitReached { limit: 0, live: 0 },
                    value: (),
                })
            }
        });
        drop(reserve);
        if admitted {
            let Poll::Ready(Ok(permit)) = result else {
                panic!("pre-seal physical admission must retain its commit right");
            };
            assert_eq!(stats.wakes.load(Ordering::SeqCst), 0);
            permit.try_send(23).unwrap();
            assert_eq!(receiver.try_recv(), Ok(23));
        } else {
            assert!(matches!(
                result,
                Poll::Ready(Err(CheckedSendError::Admission { .. }))
            ));
        }
        assert_eq!(stats.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(receiver.try_recv(), Err(RecvError::Disconnected));
        assert_eq!(sender.debug_counts(), (0, 0));
    }
}

#[test]
fn panicking_seal_waker_cannot_strand_other_waiters_or_revoke_accepted_work() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = channel::<u8>(1);
    let accepted = sender.try_reserve().unwrap();
    let (first_stats, first_waker) = unlocked_waker(&sender, true);
    let (second_stats, second_waker) = unlocked_waker(&sender, false);
    let (recv_stats, recv_waker) = unlocked_waker(&sender, false);
    let (closed_stats, closed_waker) = unlocked_waker(&sender, false);
    let mut first_task = Context::from_waker(&first_waker);
    let mut second_task = Context::from_waker(&second_waker);
    let mut recv_task = Context::from_waker(&recv_waker);
    let mut closed_task = Context::from_waker(&closed_waker);
    let mut first = Box::pin(sender.reserve(&cx));
    let mut second = Box::pin(sender.reserve(&cx));
    let mut closed = Box::pin(sender.closed());
    assert!(first.as_mut().poll(&mut first_task).is_pending());
    assert!(second.as_mut().poll(&mut second_task).is_pending());
    assert!(receiver.poll_recv(&cx, &mut recv_task).is_pending());
    assert!(closed.as_mut().poll(&mut closed_task).is_pending());

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        receiver.close_gracefully();
    }));
    assert!(result.is_err());
    for stats in [&first_stats, &second_stats, &recv_stats, &closed_stats] {
        assert_eq!(stats.wakes.load(Ordering::SeqCst), 1);
    }
    assert!(matches!(
        first.as_mut().poll(&mut first_task),
        Poll::Ready(Err(SendError::Disconnected(())))
    ));
    assert!(matches!(
        second.as_mut().poll(&mut second_task),
        Poll::Ready(Err(SendError::Disconnected(())))
    ));
    assert!(closed.as_mut().poll(&mut closed_task).is_ready());
    accepted.try_send(9).unwrap();
    assert_eq!(receiver.try_recv(), Ok(9));
    assert_eq!(receiver.try_recv(), Err(RecvError::Disconnected));
}

#[test]
fn unbounded_graceful_close_drains_accepted_values_and_seals_clones() {
    let (sender, mut receiver) = unbounded::<u8>();
    sender.send(1).unwrap();
    sender.send(2).unwrap();
    receiver.close_gracefully();
    assert!(sender.is_closed());
    assert_eq!(sender.clone().send(3), Err(SendError::Disconnected(3)));
    assert_eq!(receiver.try_recv(), Ok(1));
    assert_eq!(receiver.try_recv(), Ok(2));
    assert_eq!(receiver.try_recv(), Err(RecvError::Disconnected));
}
