//! `time::DelayQueue` and `stream::StreamMap`.
//!
//! DelayQueue: entries come due in deadline order on the real runtime;
//! remove and reset take effect; an insert with an earlier deadline wakes a
//! poll parked on a later one; and under the lab runtime hours of virtual
//! time pass without waiting. StreamMap: items arrive labelled by key, streams
//! are inserted and removed while it is polled, ended streams drop out, and a
//! pending stream's later item still wakes the map.

use asupersync::runtime::RuntimeBuilder;
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
