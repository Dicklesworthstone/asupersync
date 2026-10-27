//! `time::DelayQueue` and `stream::StreamMap`.
//!
//! DelayQueue: entries come due in deadline order on the real runtime;
//! remove and reset take effect; an insert with an earlier deadline wakes a
//! poll parked on a later one; and under the lab runtime hours of virtual
//! time pass without waiting. StreamMap: items arrive labelled by key, streams
//! are inserted and removed while it is polled, ended streams drop out, and a
//! pending stream's later item still wakes the map.

use asupersync::Cx;
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::stream::{Stream, StreamExt, StreamMap, iter};
use asupersync::time::DelayQueue;
use asupersync::types::{Budget, Time};
use asupersync::{LabConfig, LabRuntime};
use parking_lot::Mutex;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

#[derive(Default)]
struct CountingWaker(AtomicUsize);

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn entries_come_due_in_deadline_order_and_respond_to_remove_and_reset() {
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    runtime.block_on(async {
        let started = Instant::now();
        let mut queue = DelayQueue::new();
        queue.insert("c", Duration::from_millis(60));
        let a = queue.insert("a", Duration::from_millis(200));
        let b = queue.insert("b", Duration::from_millis(40));
        assert!(queue.deadline(&b) < queue.deadline(&a));
        let gone = queue.insert("gone", Duration::from_millis(10));
        assert_eq!(queue.len(), 4);

        assert_eq!(queue.remove(&gone).into_inner(), "gone");
        assert!(!queue.contains(&gone));
        assert!(queue.try_remove(&gone).is_none());
        queue.reset(&a, Duration::from_millis(20));
        assert!(queue.contains(&a), "a reset key stays valid");
        assert!(queue.deadline(&a) < queue.deadline(&b));

        let mut order = Vec::new();
        while let Some(expired) = queue.next().await {
            assert!(
                started.elapsed() >= Duration::from_millis(15),
                "nothing is yielded before its deadline"
            );
            order.push(*expired.get_ref());
            assert!(!queue.contains(&expired.key()));
        }
        assert_eq!(order, ["a", "b", "c"]);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(queue.is_empty());

        // An empty queue yields None; later inserts are yielded by later polls.
        queue.insert("again", Duration::from_millis(5));
        assert_eq!(queue.next().await.map(|e| e.into_inner()), Some("again"));
    });
}

#[test]
fn an_earlier_insert_wakes_a_poll_parked_on_a_later_deadline() {
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    runtime.block_on(async {
        let mut queue = DelayQueue::new();
        queue.insert("hour", Duration::from_secs(3600));
        let counter = Arc::new(CountingWaker::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut context = Context::from_waker(&waker);
        assert!(queue.poll_expired(&mut context).is_pending());

        queue.insert("soon", Duration::from_millis(10));
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            1,
            "the parked poll is woken"
        );

        let started = Instant::now();
        let soon = poll_fn(|cx| queue.poll_expired(cx)).await;
        assert_eq!(soon.map(|e| e.into_inner()), Some("soon"));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(queue.len(), 1);

        // Repeated resets without polling keep working (stale timers are
        // skipped and compacted).
        let key = queue.insert("reset", Duration::from_secs(3600));
        for _ in 0..1_000 {
            queue.reset(&key, Duration::from_secs(3600));
        }
        queue.reset(&key, Duration::from_millis(5));
        let reset = poll_fn(|cx| queue.poll_expired(cx)).await;
        assert_eq!(reset.map(|e| e.into_inner()), Some("reset"));
    });
}

/// A cancelled task parked on a queue stays parked until an entry comes due.
/// The queue's timer used to be polled as a cancellation point: it completed
/// at once under the pending cancel, was re-armed, and the task was re-polled
/// on every scheduler turn until the deadline really passed
/// (br-asupersync-973voq).
#[test]
fn a_cancelled_wait_on_a_delay_queue_parks_instead_of_spinning() {
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&polls);
    let handle = runtime.handle();
    let (yielded, waited) = runtime.block_on(handle.spawn(async move {
        let cx = Cx::current().expect("a spawned task has a Cx");
        let mut waiter = cx
            .spawn(move |_cx| async move {
                let mut queue = DelayQueue::new();
                queue.insert("due", Duration::from_millis(300));
                let expired = poll_fn(|context| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    queue.poll_expired(context)
                })
                .await;
                expired.map(|e| e.into_inner())
            })
            .expect("spawn the waiter");
        for _ in 0..10 {
            yield_now().await;
        }
        waiter.abort();
        let started = Instant::now();
        let yielded = waiter.join(&cx).await.ok().flatten();
        (yielded, started.elapsed())
    }));
    let polls = polls.load(Ordering::SeqCst);
    eprintln!("cancelled delay-queue wait: polls={polls} waited={waited:?} yielded={yielded:?}");
    assert!(
        polls < 10,
        "the cancelled waiter was polled {polls} times while its entry was not due"
    );
    assert!(waited < Duration::from_secs(5));
}

/// A poll that found the queue empty is woken by the next insert
/// (br-asupersync-973voq).
#[test]
fn an_insert_wakes_a_poll_that_found_the_queue_empty() {
    let counter = Arc::new(CountingWaker::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut context = Context::from_waker(&waker);
    let mut queue = DelayQueue::new();
    assert!(matches!(
        queue.poll_expired(&mut context),
        Poll::Ready(None)
    ));
    queue.insert("mine", Duration::from_secs(3600));
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        1,
        "the poll that saw the queue empty is woken"
    );
}

/// A key from one queue is never valid in another; both used to number their
/// entries from zero, so a foreign key could remove an unrelated entry
/// (br-asupersync-973voq).
#[test]
fn a_key_from_another_queue_is_not_valid() {
    let mut queue = DelayQueue::new();
    queue.insert("mine", Duration::from_secs(3600));
    let mut other = DelayQueue::new();
    let foreign = other.insert("theirs", Duration::from_secs(3600));
    assert!(
        !queue.contains(&foreign),
        "a key from another queue is not valid here"
    );
    assert!(queue.try_remove(&foreign).is_none());
    assert_eq!(queue.len(), 1);
    assert!(other.contains(&foreign));
}

#[test]
fn hours_of_virtual_time_pass_instantly_under_the_lab_runtime() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut lab = LabRuntime::new(LabConfig::new(7).with_auto_advance());
    let root = lab.state.create_root_region(Budget::INFINITE);
    let record = Arc::clone(&order);
    let (task, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let mut queue = DelayQueue::new();
            queue.insert(2_u64, Duration::from_secs(2 * 3600));
            queue.insert(1, Duration::from_secs(3600));
            queue.insert_at(3, Time::from_secs(3 * 3600));
            while let Some(expired) = queue.next().await {
                record
                    .lock()
                    .push((expired.into_inner(), asupersync::time::wall_now()));
            }
        })
        .expect("create task");
    lab.scheduler.lock().schedule(task, 0);
    let started = Instant::now();
    lab.run_with_auto_advance();
    assert!(started.elapsed() < Duration::from_secs(30));

    let order = order.lock();
    let values: Vec<_> = order.iter().map(|(value, _)| *value).collect();
    assert_eq!(values, [1, 2, 3]);
    for (value, at) in order.iter() {
        assert!(
            *at >= Time::from_secs(value * 3600),
            "{value} was yielded at {at:?}, before its virtual deadline"
        );
    }
}

/// A stream fed by hand: `Pending` until an item is pushed.
#[derive(Clone, Default)]
struct Manual {
    state: Arc<Mutex<(Vec<u32>, bool, Option<Waker>)>>,
}

impl Manual {
    fn push(&self, item: u32) {
        let waker = {
            let mut state = self.state.lock();
            state.0.push(item);
            state.2.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn finish(&self) {
        let waker = {
            let mut state = self.state.lock();
            state.1 = true;
            state.2.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Stream for Manual {
    type Item = u32;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<u32>> {
        let mut state = self.state.lock();
        if !state.0.is_empty() {
            return Poll::Ready(Some(state.0.remove(0)));
        }
        if state.1 {
            return Poll::Ready(None);
        }
        state.2 = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[test]
fn stream_map_labels_items_and_tracks_inserts_and_removals() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        let mut map: StreamMap<&str, Manual> = StreamMap::new();
        let alpha = Manual::default();
        let beta = Manual::default();
        assert!(map.insert("alpha", alpha.clone()).is_none());
        assert!(map.insert("beta", beta.clone()).is_none());
        assert!(map.contains_key("beta"));

        alpha.push(1);
        beta.push(2);
        let mut first_two = vec![map.next().await.unwrap(), map.next().await.unwrap()];
        first_two.sort_unstable();
        assert_eq!(first_two, [("alpha", 1), ("beta", 2)]);

        // A pending map is woken by an item pushed from another task.
        let feeder = beta.clone();
        let feed = handle.spawn(async move {
            for _ in 0..20 {
                asupersync::runtime::yield_now().await;
            }
            feeder.push(3);
        });
        assert_eq!(map.next().await, Some(("beta", 3)));
        feed.await;

        // Removed streams are no longer polled; ended streams drop out.
        let removed = map.remove("alpha").expect("alpha");
        removed.push(99);
        beta.finish();
        let gamma = Manual::default();
        gamma.push(4);
        map.insert("gamma", gamma.clone());
        assert_eq!(map.next().await, Some(("gamma", 4)));
        assert!(!map.contains_key("beta"), "beta ended and was removed");
        gamma.finish();
        assert_eq!(map.next().await, None);
        assert!(map.is_empty());

        // Fair: a stream with many ready items does not starve its peer.
        let mut map = StreamMap::new();
        map.insert(0, iter(vec![0; 100]));
        map.insert(1, iter(vec![1; 3]));
        let first_six: Vec<_> = map.take(6).map(|(key, _)| key).collect().await;
        assert_eq!(first_six.iter().filter(|key| **key == 1).count(), 3);
    });
}

#[cfg(not(target_arch = "wasm32"))]
mod context_expiry {
    use super::*;
    use asupersync::cx::ChildRegionSpec;
    use asupersync::time::{DelayQueueNextError, TimerDriverHandle, VirtualClock};
    use asupersync::types::{CancelKind, CancelReason};
    use std::future::Future;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;

    fn virtual_scenario<F>(budget: Budget, scenario: F)
    where
        F: FnOnce(Cx, Arc<VirtualClock>, TimerDriverHandle) + Send + 'static,
    {
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .with_timer_driver(driver.clone())
            .build()
            .unwrap();
        let completed = Arc::new(AtomicBool::new(false));
        let completion = Arc::clone(&completed);
        let observed_driver = driver.clone();
        runtime.block_on(runtime.handle().spawn(async move {
            let parent = Cx::current().unwrap();
            let region = parent
                .open_child_region(ChildRegionSpec::inherit().with_budget(budget))
                .await
                .unwrap();
            let mut task = region
                .cx()
                .spawn(move |cx| async move { scenario(cx, clock, driver) })
                .unwrap();
            task.join(&parent).await.unwrap();
            region.close().await.unwrap();
            completion.store(true, Ordering::Release);
        }));
        assert!(completed.load(Ordering::Acquire));
        assert!(observed_driver.is_empty(), "no expiry registration outlives its owner");
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }

    #[test]
    fn empty_queues_need_no_timer_but_nonempty_queues_require_time_authority() {
        virtual_scenario(Budget::INFINITE, |cx, _, driver| {
            let mut queue = DelayQueue::new();
            let restriction = cx
                .restrict::<asupersync::cx::cap::None>()
                .set_current_restricted();
            let masked = Cx::current().unwrap();
            assert!(masked.timer_driver().is_none());
            let mut empty = Box::pin(queue.next_expired(&masked));
            assert!(matches!(
                empty.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(None))
            ));
            drop(empty);
            let key = queue.insert_at("due", Time::ZERO);
            let mut denied = Box::pin(queue.next_expired(&masked));
            assert!(matches!(
                denied.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(DelayQueueNextError::TimerUnavailable))
            ));
            drop(denied);
            assert_eq!(queue.len(), 1);
            assert!(queue.contains(&key));
            assert!(driver.is_empty());
            drop(restriction);

            type TimeOnly = asupersync::cx::cap::CapSet<false, true, false, false, false>;
            let restricted = cx.restrict::<TimeOnly>();
            let mut due = Box::pin(queue.next_expired(&restricted));
            match due.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(expired))) => assert_eq!(expired.into_inner(), "due"),
                other => panic!("the explicit time-only context must deliver its due value: {other:?}"),
            }
            drop(due);
            assert!(queue.is_empty());
            assert!(!queue.contains(&key));
        });
    }

    #[test]
    fn dropping_pending_or_fired_expiry_preserves_values_keys_and_removes_timer() {
        for fired in [false, true] {
            virtual_scenario(Budget::INFINITE, move |cx, clock, driver| {
                let mut queue = DelayQueue::new();
                let first = queue.insert_at("first", Time::from_millis(100));
                let second = queue.insert_at("second", Time::from_millis(200));
                let counter = Arc::new(CountingWaker::default());
                let waker = Waker::from(Arc::clone(&counter));
                let mut task = Context::from_waker(&waker);
                let mut waiting = Box::pin(queue.next_expired(&cx));
                assert!(waiting.as_mut().poll(&mut task).is_pending());
                assert_eq!(driver.pending_count(), 1);
                if fired {
                    clock.advance_to(Time::from_millis(100));
                    assert_eq!(driver.process_timers(), 1);
                    assert_eq!(counter.0.load(Ordering::Acquire), 1);
                }
                drop(waiting);
                assert!(driver.is_empty());
                assert_eq!(queue.len(), 2);
                assert!(queue.contains(&first));
                assert!(queue.contains(&second));
                assert_eq!(queue.deadline(&first), Time::from_millis(100));

                // Cancellation released the mutable borrow: move a different
                // key ahead, then continue with the same surviving identities.
                queue.reset_at(&second, Time::from_millis(50));
                clock.advance_to(Time::from_millis(100));
                for (key, value) in [(second, "second"), (first, "first")] {
                    let mut waiting = Box::pin(queue.next_expired(&cx));
                    match waiting.as_mut().poll(&mut task) {
                        Poll::Ready(Ok(Some(expired))) => {
                            assert_eq!(expired.key(), key);
                            assert_eq!(expired.into_inner(), value);
                        }
                        other => panic!("retained value must be recoverable: {other:?}"),
                    }
                    drop(waiting);
                    assert!(!queue.contains(&key));
                }
                assert!(queue.is_empty());
            });
        }
    }

    #[test]
    fn explicit_expiry_retires_a_previous_stream_timer_and_uses_one_registration() {
        virtual_scenario(Budget::INFINITE, |cx, clock, driver| {
            let mut queue = DelayQueue::new();
            let key = queue.insert_at("kept", Time::from_millis(100));
            let mut task = Context::from_waker(Waker::noop());
            assert!(queue.poll_expired(&mut task).is_pending());
            assert_eq!(driver.pending_count(), 1);
            let mut waiting = Box::pin(queue.next_expired(&cx));
            assert!(waiting.as_mut().poll(&mut task).is_pending());
            assert_eq!(driver.pending_count(), 1, "legacy registration was replaced");
            clock.advance_to(Time::from_millis(99));
            assert_eq!(driver.process_timers(), 0);
            assert!(waiting.as_mut().poll(&mut task).is_pending());
            drop(waiting);
            assert!(driver.is_empty());
            assert!(queue.contains(&key));
            assert_eq!(queue.remove(&key).into_inner(), "kept");
        });
    }

    #[test]
    fn early_refusal_retires_a_previous_stream_timer_without_consuming_its_value() {
        virtual_scenario(Budget::INFINITE, |cx, _, driver| {
            let mut queue = DelayQueue::new();
            let key = queue.insert_at("kept", Time::from_secs(3600));
            let mut task = Context::from_waker(Waker::noop());
            assert!(queue.poll_expired(&mut task).is_pending());
            assert_eq!(driver.pending_count(), 1);

            let restriction = cx
                .restrict::<asupersync::cx::cap::None>()
                .set_current_restricted();
            let masked = Cx::current().unwrap();
            let mut denied = Box::pin(queue.next_expired(&masked));
            assert!(matches!(
                denied.as_mut().poll(&mut task),
                Poll::Ready(Err(DelayQueueNextError::TimerUnavailable))
            ));
            drop(denied);
            assert!(driver.is_empty());
            assert!(queue.contains(&key));
            drop(restriction);

            // A legacy caller can re-arm the same retained entry. A later
            // explicitly cancelled wait must retire that registration too.
            assert!(queue.poll_expired(&mut task).is_pending());
            assert_eq!(driver.pending_count(), 1);
            cx.set_cancel_reason(CancelReason::user("cancel the new queue wait"));
            let mut cancelled = Box::pin(queue.next_expired(&cx));
            assert!(matches!(
                cancelled.as_mut().poll(&mut task),
                Poll::Ready(Err(DelayQueueNextError::Cancelled(reason)))
                    if reason.kind == CancelKind::User
            ));
            drop(cancelled);
            assert!(driver.is_empty());
            assert!(queue.contains(&key));
            assert_eq!(queue.remove(&key).into_inner(), "kept");
        });
    }

    #[test]
    fn explicit_owner_drives_expiry_while_the_ambient_context_has_no_timer() {
        virtual_scenario(Budget::INFINITE, |cx, clock, driver| {
            let mut queue = DelayQueue::new();
            let key = queue.insert_at("explicit clock", Time::from_millis(100));
            let ambient = Cx::detached_cancel_context().set_current_restricted();
            assert!(Cx::current().unwrap().timer_driver().is_none());
            let counter = Arc::new(CountingWaker::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            let mut waiting = Box::pin(queue.next_expired(&cx));
            assert!(waiting.as_mut().poll(&mut task).is_pending());
            assert_eq!(driver.pending_count(), 1);
            clock.advance_to(Time::from_millis(100));
            assert_eq!(driver.process_timers(), 1);
            assert_eq!(counter.0.load(Ordering::Acquire), 1);
            match waiting.as_mut().poll(&mut task) {
                Poll::Ready(Ok(Some(expired))) => {
                    assert_eq!(expired.key(), key);
                    assert_eq!(expired.deadline(), Time::from_millis(100));
                    assert_eq!(expired.into_inner(), "explicit clock");
                }
                other => panic!("the explicit owner's timer must drive expiry: {other:?}"),
            }
            drop(waiting);
            assert!(queue.is_empty());
            assert!(driver.is_empty());
            drop(ambient);
        });
    }

    #[test]
    fn cancellation_wins_over_due_and_empty_and_retains_every_entry() {
        virtual_scenario(Budget::INFINITE, |cx, clock, driver| {
            let mut queue = DelayQueue::new();
            let first = queue.insert_at("first", Time::from_millis(100));
            let second = queue.insert_at("second", Time::from_millis(200));
            let counter = Arc::new(CountingWaker::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            let mut waiting = Box::pin(queue.next_expired(&cx));
            assert!(waiting.as_mut().poll(&mut task).is_pending());
            assert_eq!(driver.pending_count(), 1);
            clock.advance_to(Time::from_millis(200));
            cx.set_cancel_reason(CancelReason::user("retain queued expiry values"));
            assert!(counter.0.load(Ordering::Acquire) > 0);
            assert!(matches!(
                waiting.as_mut().poll(&mut task),
                Poll::Ready(Err(DelayQueueNextError::Cancelled(reason))) if reason.kind == CancelKind::User
            ));
            drop(waiting);
            assert!(driver.is_empty());
            assert_eq!(queue.len(), 2);
            assert_eq!(queue.remove(&first).into_inner(), "first");
            assert_eq!(queue.remove(&second).into_inner(), "second");
            let mut empty = Box::pin(queue.next_expired(&cx));
            assert!(matches!(
                empty.as_mut().poll(&mut task),
                Poll::Ready(Err(DelayQueueNextError::Cancelled(reason))) if reason.kind == CancelKind::User
            ));
        });
    }

    #[test]
    fn masked_expired_owner_deadline_does_not_spin_or_remove_a_value() {
        virtual_scenario(
            Budget::new().with_deadline(Time::from_millis(1)),
            |cx, clock, driver| {
                clock.advance_to(Time::from_millis(2));
                let mut queue = DelayQueue::new();
                let key = queue.insert_at("kept", Time::from_millis(100));
                let counter = Arc::new(CountingWaker::default());
                let waker = Waker::from(Arc::clone(&counter));
                let mut task = Context::from_waker(&waker);
                let mut waiting = Box::pin(queue.next_expired(&cx));
                cx.masked(|| assert!(waiting.as_mut().poll(&mut task).is_pending()));
                assert_eq!(driver.next_deadline(), Some(Time::from_millis(100)));
                assert_eq!(counter.0.load(Ordering::Acquire), 0);
                // Explicit repoll after the synchronous mask; unmasking does
                // not itself promise a wakeup.
                assert!(matches!(
                    waiting.as_mut().poll(&mut task),
                    Poll::Ready(Err(DelayQueueNextError::Cancelled(reason))) if reason.kind == CancelKind::Deadline
                ));
                drop(waiting);
                assert!(queue.contains(&key));
                assert_eq!(queue.remove(&key).into_inner(), "kept");
            },
        );
    }

    fn native<F, Fut>(workers: usize, scenario: F)
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let runner = std::thread::spawn(move || {
            let builder = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::multi_thread().worker_threads(workers)
            };
            let runtime = builder.build().unwrap();
            let completed = Arc::new(AtomicBool::new(false));
            let completion = Arc::clone(&completed);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout(cx.now(), Duration::from_secs(10), scenario(cx))
                    .await
                    .expect("context expiry watchdog");
                completion.store(true, Ordering::Release);
            }));
            assert!(completed.load(Ordering::Acquire));
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
            done_tx.send(()).unwrap();
        });
        match done_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                runner.join().expect("native context expiry");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("native context expiry exceeded watchdog"),
        }
    }

    #[derive(Debug)]
    struct Retained {
        value: u32,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for Retained {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn native_cancel_releases_a_parked_expiry_without_destroying_queued_values() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                let parked = Arc::new(AtomicBool::new(false));
                let child_parked = Arc::clone(&parked);
                let drops = Arc::new(AtomicUsize::new(0));
                let child_drops = Arc::clone(&drops);
                let mut child = cx
                    .spawn(move |owner| async move {
                        let mut queue = DelayQueue::new();
                        let deadline = owner.now() + Duration::from_secs(3600);
                        let key = queue.insert_at(Retained { value: 7, drops: child_drops }, deadline);
                        let mut waiting = Box::pin(queue.next_expired(&owner));
                        let result = poll_fn(|task| {
                            let polled = waiting.as_mut().poll(task);
                            if polled.is_pending() {
                                child_parked.store(true, Ordering::Release);
                            }
                            polled
                        })
                        .await;
                        assert!(matches!(
                            result,
                            Err(DelayQueueNextError::Cancelled(reason)) if reason.kind == CancelKind::User
                        ));
                        drop(waiting);
                        assert!(queue.contains(&key));
                        assert_eq!(queue.deadline(&key), deadline);
                        (queue, key)
                    })
                    .unwrap();
                while !parked.load(Ordering::Acquire) {
                    yield_now().await;
                }
                assert_eq!(drops.load(Ordering::Acquire), 0);
                child = std::thread::spawn(move || {
                    child.abort();
                    child
                })
                .join()
                .unwrap();
                let (mut queue, key) = child.join(&cx).await.expect("typed cancellation acknowledgement");
                assert_eq!(queue.len(), 1);
                assert_eq!(drops.load(Ordering::Acquire), 0);
                let retained = queue.remove(&key).into_inner();
                assert_eq!(retained.value, 7);
                drop(retained);
                assert_eq!(drops.load(Ordering::Acquire), 1);
                assert!(queue.is_empty());
            });
        }
    }

    #[test]
    fn native_expiry_and_inherited_deadline_wake_without_manual_progress() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                let mut queue = DelayQueue::new();
                let deadline = cx.now() + Duration::from_millis(250);
                let key = queue.insert_at("due", deadline);
                let mut waiting = Box::pin(queue.next_expired(&cx));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                let expired = waiting.await.unwrap().unwrap();
                assert_eq!(expired.key(), key);
                assert_eq!(expired.deadline(), deadline);
                assert_eq!(expired.into_inner(), "due");
                assert!(cx.now() >= deadline);
                assert!(queue.is_empty());

                let region = cx
                    .open_child_region(ChildRegionSpec::inherit().with_budget(
                        Budget::new().with_deadline(cx.now() + Duration::from_millis(250)),
                    ))
                    .await
                    .unwrap();
                let parked = Arc::new(AtomicBool::new(false));
                let child_parked = Arc::clone(&parked);
                let mut child = region
                    .cx()
                    .spawn(move |owner| async move {
                        let mut queue = DelayQueue::new();
                        let key = queue.insert_at("kept", owner.now() + Duration::from_secs(3600));
                        let mut waiting = Box::pin(queue.next_expired(&owner));
                        let result = poll_fn(|task| {
                            let polled = waiting.as_mut().poll(task);
                            if polled.is_pending() {
                                child_parked.store(true, Ordering::Release);
                            }
                            polled
                        })
                        .await;
                        assert!(matches!(
                            result,
                            Err(DelayQueueNextError::Cancelled(reason)) if reason.kind == CancelKind::Deadline
                        ));
                        drop(waiting);
                        assert_eq!(queue.remove(&key).into_inner(), "kept");
                    })
                    .unwrap();
                while !parked.load(Ordering::Acquire) {
                    yield_now().await;
                }
                child.join(&cx).await.unwrap();
                region.close().await.unwrap();
            });
        }
    }

    #[test]
    fn lab_expiry_preserves_reset_order_equal_deadlines_and_max_time() {
        for seed in [17, 41, 93] {
            let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(8192));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let (task, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async {
                    let cx = Cx::current().unwrap();
                    let mut queue = DelayQueue::new();
                    let first = queue.insert_at("first", Time::from_millis(100));
                    let second = queue.insert_at("second", Time::from_millis(100));
                    let reset = queue.insert_at("reset", Time::from_secs(3600));
                    let removed = queue.insert_at("removed", Time::from_millis(10));
                    assert_eq!(queue.remove(&removed).into_inner(), "removed");
                    queue.reset_at(&reset, Time::from_millis(50));
                    for (key, value, deadline) in [
                        (reset, "reset", Time::from_millis(50)),
                        (first, "first", Time::from_millis(100)),
                        (second, "second", Time::from_millis(100)),
                    ] {
                        let expired = queue.next_expired(&cx).await.unwrap().unwrap();
                        assert_eq!(expired.key(), key);
                        assert_eq!(expired.deadline(), deadline);
                        assert_eq!(expired.into_inner(), value);
                        assert_eq!(cx.now(), deadline);
                        assert!(!queue.contains(&key));
                    }
                    assert!(queue.next_expired(&cx).await.unwrap().is_none());
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            let virtual_time = lab.run_with_auto_advance();
            let report = lab.run_until_quiescent_with_report();
            assert!(matches!(join.try_join(), Ok(Some(()))), "seed={seed}: {virtual_time:?} {report:?}");
            assert!(lab.state.tasks_is_empty());
            assert!(lab.state.obligations_iter().all(|(_, obligation)| !obligation.is_pending()));
            assert!(report.lab_test_passed(), "seed={seed}: {report:?}");
        }
        virtual_scenario(Budget::INFINITE, |cx, clock, driver| {
            let mut queue = DelayQueue::new();
            let key = queue.insert_at("last", Time::MAX);
            clock.advance_to(Time::MAX);
            let mut due = Box::pin(queue.next_expired(&cx));
            match due.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(expired))) => {
                    assert_eq!(expired.key(), key);
                    assert_eq!(expired.deadline(), Time::MAX);
                    assert_eq!(expired.into_inner(), "last");
                }
                other => panic!("the final representable expiry must be delivered: {other:?}"),
            }
            drop(due);
            assert!(queue.is_empty());
            let mut empty = Box::pin(queue.next_expired(&cx));
            assert!(matches!(
                empty.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(None))
            ));
            assert!(driver.is_empty());
        });
    }
}

