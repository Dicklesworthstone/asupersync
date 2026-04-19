//! Metamorphic tests for channel::watch snapshot and ordering invariants.

use asupersync::channel::watch;
use asupersync::cx::Cx;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use proptest::prelude::*;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

fn test_cx(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(slot, 0)),
        TaskId::from_arena(ArenaIndex::new(slot, 0)),
        Budget::INFINITE,
    )
}

fn non_empty_sequences() -> impl Strategy<Value = Vec<i32>> {
    prop::collection::vec(-1000_i32..=1000, 1..16)
}

fn poll_ready<F: Future + Unpin>(future: &mut F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    match Pin::new(future).poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("expected future to be immediately ready"),
    }
}

proptest! {
    #[test]
    fn mr_watch_latest_snapshot_wins_after_burst_send(
        values in non_empty_sequences(),
        extra_receivers in 0_usize..4,
    ) {
        let (tx, mut rx) = watch::channel(values[0]);
        for value in values.iter().skip(1) {
            tx.send(*value).expect("burst send must succeed");
        }

        let expected = *values.last().expect("non-empty sequence");
        prop_assert_eq!(*rx.borrow(), expected);
        prop_assert_eq!(rx.has_changed(), values.len() > 1);
        prop_assert_eq!(*rx.borrow_and_update(), expected);
        prop_assert!(!rx.has_changed());

        for _ in 0..extra_receivers {
            let mut subscribed = tx.subscribe();
            prop_assert_eq!(*subscribed.borrow(), expected);
            prop_assert!(!subscribed.has_changed());
            prop_assert_eq!(*subscribed.borrow_and_update(), expected);
            prop_assert!(!subscribed.has_changed());
        }
    }

    #[test]
    fn mr_watch_borrow_and_update_clears_pending_change(values in non_empty_sequences()) {
        let cx = test_cx(1);
        let (tx, mut rx) = watch::channel(values[0]);

        for value in values.iter().skip(1) {
            tx.send(*value).expect("send must succeed");
            prop_assert!(rx.has_changed());

            let mut changed = rx.changed(&cx);
            poll_ready(&mut changed)
                .expect("send before changed should make future ready");

            let observed = *rx.borrow_and_update();
            prop_assert_eq!(observed, *value);
            prop_assert!(!rx.has_changed());
        }
    }

    #[test]
    fn mr_watch_mark_seen_acknowledges_latest_not_stale_snapshot(
        first in -1000_i32..=1000,
        second in -1000_i32..=1000,
        third in -1000_i32..=1000,
    ) {
        let cx = test_cx(2);
        let (tx, mut rx) = watch::channel(first);

        tx.send(second).expect("send second");
        let stale_snapshot = *rx.borrow();
        prop_assert_eq!(stale_snapshot, second);

        tx.send(third).expect("send third");
        prop_assert!(rx.has_changed());

        rx.mark_seen();
        prop_assert!(!rx.has_changed());
        prop_assert_eq!(*rx.borrow(), third);

        tx.send(first).expect("send follow-up");
        let mut changed = rx.changed(&cx);
        poll_ready(&mut changed)
            .expect("follow-up send should make changed ready");
        prop_assert_eq!(*rx.borrow_and_update(), first);
    }

    #[test]
    fn mr_watch_late_subscriber_observes_only_future_ordering(values in non_empty_sequences()) {
        let cx1 = test_cx(3);
        let cx2 = test_cx(4);
        let (tx, mut early_rx) = watch::channel(values[0]);

        for value in values.iter().skip(1).take(values.len().saturating_sub(2)) {
            tx.send(*value).expect("historical send must succeed");
            let mut changed = early_rx.changed(&cx1);
            poll_ready(&mut changed)
                .expect("historical send should make changed ready");
            prop_assert_eq!(*early_rx.borrow_and_update(), *value);
        }

        let mut late_rx = tx.subscribe();
        let current = *values.last().unwrap_or(&values[0]);
        let latest_before_future = if values.len() > 1 {
            values[values.len() - 2]
        } else {
            values[0]
        };
        prop_assert_eq!(*late_rx.borrow(), latest_before_future);
        prop_assert!(!late_rx.has_changed());

        tx.send(current).expect("future send must succeed");

        let mut early_changed = early_rx.changed(&cx1);
        poll_ready(&mut early_changed)
            .expect("future send should wake early rx");
        let mut late_changed = late_rx.changed(&cx2);
        poll_ready(&mut late_changed)
            .expect("future send should wake late rx");

        prop_assert_eq!(*early_rx.borrow_and_update(), current);
        prop_assert_eq!(*late_rx.borrow_and_update(), current);
        prop_assert!(!early_rx.has_changed());
        prop_assert!(!late_rx.has_changed());
    }
}
