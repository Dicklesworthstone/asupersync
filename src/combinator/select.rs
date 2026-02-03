//! Select combinator: wait for the first of two futures to complete.
//!
//! # Loser-Drain Responsibility
//!
//! `Select` and `SelectAll` are low-level primitives that pick the winner
//! and drop losers when the future is consumed. **Dropping a loser is NOT
//! the same as draining it.** In asupersync, the "losers are drained"
//! invariant requires that losers be explicitly cancelled and awaited to
//! terminal state before the enclosing region can close.
//!
//! Callers MUST drain losers after select completes. The canonical pattern:
//!
//! ```text
//! match Select::new(f1, f2).await {
//!     Either::Left(val)  => { cancel(loser); await(loser); val }
//!     Either::Right(val) => { cancel(loser); await(loser); val }
//! }
//! ```
//!
//! For task handles, use [`Scope::race`](crate::cx::Scope::race) which
//! handles loser-drain automatically. Use raw `Select` only when you
//! manage drain yourself.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Result of a select operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Either<A, B> {
    /// The first future completed first.
    Left(A),
    /// The second future completed first.
    Right(B),
}

impl<A, B> Either<A, B> {
    /// Returns true if this is the Left variant.
    pub fn is_left(&self) -> bool {
        matches!(self, Self::Left(_))
    }

    /// Returns true if this is the Right variant.
    pub fn is_right(&self) -> bool {
        matches!(self, Self::Right(_))
    }
}

/// Future for the `select` combinator.
///
/// # Loser-Drain Warning
///
/// When `Select` resolves, the losing future is dropped (not drained).
/// If the loser holds obligations or resources, the caller MUST cancel
/// and drain it. See [`Scope::race`](crate::cx::Scope::race) for a
/// higher-level API that handles draining automatically.
pub struct Select<A, B> {
    a: A,
    b: B,
}

impl<A, B> Select<A, B> {
    /// Creates a new select combinator.
    pub fn new(a: A, b: B) -> Self {
        Self { a, b }
    }
}

impl<A: Future + Unpin, B: Future + Unpin> Future for Select<A, B> {
    type Output = Either<A::Output, B::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if let Poll::Ready(val) = Pin::new(&mut this.a).poll(cx) {
            return Poll::Ready(Either::Left(val));
        }

        if let Poll::Ready(val) = Pin::new(&mut this.b).poll(cx) {
            return Poll::Ready(Either::Right(val));
        }

        Poll::Pending
    }
}

/// Future for the `select_all` combinator.
///
/// # Loser-Drain Warning
///
/// When `SelectAll` completes, losers are dropped (not drained). Callers
/// MUST drain losers themselves. See module-level docs.
pub struct SelectAll<F> {
    futures: Vec<F>,
}

impl<F> SelectAll<F> {
    /// Creates a new select_all combinator.
    #[must_use]
    pub fn new(futures: Vec<F>) -> Self {
        Self { futures }
    }
}

impl<F: Future + Unpin> Future for SelectAll<F> {
    type Output = (F::Output, usize);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut first_ready: Option<(F::Output, usize)> = None;

        // CRITICAL: Poll ALL futures to ensure they're initialized.
        // This is required for cancel-correctness: if a future wraps a JoinFuture,
        // the JoinFuture must be created (by polling) so its Drop can abort the task
        // when this SelectAll is dropped. Without this, losers may never be polled,
        // their JoinFutures never created, and tasks would leak (violating the
        // "losers are drained" invariant).
        for (i, f) in self.futures.iter_mut().enumerate() {
            if let Poll::Ready(v) = Pin::new(f).poll(cx) {
                if first_ready.is_none() {
                    first_ready = Some((v, i));
                }
                // Continue polling remaining futures to ensure they're initialized
            }
        }

        if let Some(result) = first_ready {
            return Poll::Ready(result);
        }

        Poll::Pending
    }
}

/// Drain-aware select_all: returns the winner value, winner index, and
/// remaining (loser) futures so the caller can cancel and drain them.
///
/// This is the preferred variant when the "losers are drained" invariant
/// must be enforced, as it makes it impossible to forget the losers.
pub struct SelectAllDrain<F> {
    futures: Option<Vec<F>>,
}

impl<F> SelectAllDrain<F> {
    /// Creates a new drain-aware select_all combinator.
    #[must_use]
    pub fn new(futures: Vec<F>) -> Self {
        Self {
            futures: Some(futures),
        }
    }
}

/// Result of [`SelectAllDrain`]: winner value, winner index, and remaining futures.
pub struct SelectAllDrainResult<T, F> {
    /// The winning future's output.
    pub value: T,
    /// Index of the winning future in the original vec.
    pub winner_index: usize,
    /// Remaining (loser) futures that the caller MUST cancel and drain.
    pub losers: Vec<F>,
}

impl<F: Future + Unpin> Future for SelectAllDrain<F> {
    type Output = SelectAllDrainResult<F::Output, F>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let futures = self.futures.as_mut().expect("polled after completion");
        let mut first_ready: Option<(F::Output, usize)> = None;

        // Poll ALL futures to ensure initialization (same as SelectAll).
        for (i, f) in futures.iter_mut().enumerate() {
            if let Poll::Ready(v) = Pin::new(f).poll(cx) {
                if first_ready.is_none() {
                    first_ready = Some((v, i));
                }
            }
        }

        if let Some((value, winner_index)) = first_ready {
            let mut all = self.futures.take().expect("polled after completion");
            // Remove the winner; remaining are losers.
            all.swap_remove(winner_index);
            return Poll::Ready(SelectAllDrainResult {
                value,
                winner_index,
                losers: all,
            });
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::Wake;

    struct NoopWaker;
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> std::task::Waker {
        Arc::new(NoopWaker).into()
    }

    fn poll_once<F: Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(fut).poll(&mut cx)
    }

    // ========== Either tests ==========

    #[test]
    fn test_either_left_is_left() {
        let e: Either<i32, &str> = Either::Left(42);
        assert!(e.is_left());
        assert!(!e.is_right());
    }

    #[test]
    fn test_either_right_is_right() {
        let e: Either<i32, &str> = Either::Right("hello");
        assert!(!e.is_left());
        assert!(e.is_right());
    }

    #[test]
    fn test_either_clone_and_copy() {
        let e: Either<i32, i32> = Either::Left(1);
        let e2 = e; // Copy
        let e3 = e; // Also copy
        assert_eq!(e, e2);
        assert_eq!(e, e3);
    }

    #[test]
    fn test_either_equality() {
        assert_eq!(Either::<i32, i32>::Left(1), Either::Left(1));
        assert_ne!(Either::<i32, i32>::Left(1), Either::Left(2));
        assert_ne!(Either::<i32, i32>::Left(1), Either::Right(1));
        assert_eq!(Either::<i32, i32>::Right(1), Either::Right(1));
    }

    #[test]
    fn test_either_debug() {
        let e: Either<i32, &str> = Either::Left(42);
        let debug = format!("{e:?}");
        assert!(debug.contains("Left"));
        assert!(debug.contains("42"));
    }

    // ========== Select (2-way) tests ==========

    #[test]
    fn test_select_left_ready_first() {
        let left = std::future::ready(42);
        let right = std::future::pending::<&str>();
        let mut sel = Select::new(left, right);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready(Either::Left(42))));
    }

    #[test]
    fn test_select_right_ready_first() {
        let left = std::future::pending::<i32>();
        let right = std::future::ready("hello");
        let mut sel = Select::new(left, right);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready(Either::Right("hello"))));
    }

    #[test]
    fn test_select_both_ready_left_biased() {
        // When both are ready, left wins (poll order bias)
        let left = std::future::ready(1);
        let right = std::future::ready(2);
        let mut sel = Select::new(left, right);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready(Either::Left(1))));
    }

    #[test]
    fn test_select_both_pending() {
        let left = std::future::pending::<i32>();
        let right = std::future::pending::<&str>();
        let mut sel = Select::new(left, right);

        let result = poll_once(&mut sel);
        assert!(result.is_pending());
    }

    #[test]
    fn test_select_unit_outputs() {
        let left = std::future::ready(());
        let right = std::future::pending::<()>();
        let mut sel = Select::new(left, right);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready(Either::Left(()))));
    }

    #[test]
    fn test_select_different_types() {
        let left = std::future::pending::<Vec<u8>>();
        let right = std::future::ready(String::from("done"));
        let mut sel = Select::new(left, right);

        let result = poll_once(&mut sel);
        match result {
            Poll::Ready(Either::Right(s)) => assert_eq!(s, "done"),
            other => unreachable!("expected Right(\"done\"), got {other:?}"),
        }
    }

    #[test]
    fn test_select_nested_composition() {
        // select(select(a, b), c) — composition test
        let a = std::future::pending::<i32>();
        let b = std::future::pending::<i32>();
        let c = std::future::ready(99);

        let inner = Select::new(a, b);
        let mut outer = Select::new(inner, c);

        let result = poll_once(&mut outer);
        assert!(matches!(result, Poll::Ready(Either::Right(99))));
    }

    #[test]
    fn test_select_loser_dropped_on_completion() {
        // Verify that when Select resolves, the losing future is dropped
        use std::sync::atomic::{AtomicBool, Ordering};

        struct DropTracker(Arc<AtomicBool>);
        impl Drop for DropTracker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        impl Future for DropTracker {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let tracker = DropTracker(Arc::clone(&dropped));

        {
            let mut sel = Select::new(std::future::ready(42), tracker);
            let result = poll_once(&mut sel);
            assert!(matches!(result, Poll::Ready(Either::Left(42))));
            // sel is dropped here
        }

        assert!(dropped.load(Ordering::SeqCst), "loser should be dropped");
    }

    // ========== SelectAll tests ==========

    #[test]
    fn test_select_all_first_ready() {
        let futures = vec![
            std::future::ready(10),
            std::future::ready(20),
            std::future::ready(30),
        ];
        let mut sel = SelectAll::new(futures);

        let result = poll_once(&mut sel);
        // First ready wins (index 0)
        assert!(matches!(result, Poll::Ready((10, 0))));
    }

    #[test]
    fn test_select_all_middle_ready() {
        // Use a custom future that is either ready or pending
        struct MaybeReady {
            value: Option<i32>,
        }
        impl Future for MaybeReady {
            type Output = i32;
            fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<i32> {
                self.value.take().map_or(Poll::Pending, Poll::Ready)
            }
        }

        let futures = vec![
            MaybeReady { value: None },
            MaybeReady { value: Some(42) },
            MaybeReady { value: None },
        ];
        let mut sel = SelectAll::new(futures);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready((42, 1))));
    }

    #[test]
    fn test_select_all_last_ready() {
        struct MaybeReady(Option<i32>);
        impl Future for MaybeReady {
            type Output = i32;
            fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<i32> {
                self.0.take().map_or(Poll::Pending, Poll::Ready)
            }
        }

        let futures = vec![MaybeReady(None), MaybeReady(None), MaybeReady(Some(99))];
        let mut sel = SelectAll::new(futures);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready((99, 2))));
    }

    #[test]
    fn test_select_all_all_pending() {
        let futures: Vec<std::future::Pending<i32>> =
            vec![std::future::pending(), std::future::pending()];
        let mut sel = SelectAll::new(futures);

        let result = poll_once(&mut sel);
        assert!(result.is_pending());
    }

    #[test]
    fn test_select_all_single_future() {
        let futures = vec![std::future::ready(7)];
        let mut sel = SelectAll::new(futures);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready((7, 0))));
    }

    #[test]
    fn test_select_all_empty_vec() {
        let futures: Vec<std::future::Ready<i32>> = vec![];
        let mut sel = SelectAll::new(futures);

        // Empty: should be pending forever (no future can complete)
        let result = poll_once(&mut sel);
        assert!(result.is_pending());
    }

    #[test]
    fn test_select_all_polls_all_futures() {
        // Verify the CRITICAL invariant: SelectAll polls ALL futures,
        // not just until first ready. This ensures cancel-correctness.
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingFuture {
            counter: Arc<AtomicUsize>,
            ready: bool,
        }
        impl Future for CountingFuture {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                if self.ready {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let futures = vec![
            CountingFuture {
                counter: Arc::clone(&counter),
                ready: true,
            }, // Ready (index 0)
            CountingFuture {
                counter: Arc::clone(&counter),
                ready: false,
            }, // Pending
            CountingFuture {
                counter: Arc::clone(&counter),
                ready: false,
            }, // Pending
        ];
        let mut sel = SelectAll::new(futures);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready(((), 0))));

        // All 3 futures should have been polled (not just the first)
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_select_all_multiple_ready_first_wins() {
        // When multiple futures are ready, the lowest index wins
        let futures = vec![
            std::future::ready(1),
            std::future::ready(2),
            std::future::ready(3),
        ];
        let mut sel = SelectAll::new(futures);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready((1, 0))));
    }

    // ========== SelectAllDrain tests ==========

    #[test]
    fn test_select_all_drain_returns_losers() {
        let futures = vec![
            std::future::ready(10),
            std::future::ready(20),
            std::future::ready(30),
        ];
        let mut sel = SelectAllDrain::new(futures);

        let result = poll_once(&mut sel);
        match result {
            Poll::Ready(r) => {
                assert_eq!(r.value, 10);
                assert_eq!(r.winner_index, 0);
                // 2 losers remain (indices 1 and 2 originally)
                assert_eq!(r.losers.len(), 2);
            }
            Poll::Pending => unreachable!("expected Ready"),
        }
    }

    #[test]
    fn test_select_all_drain_single_future() {
        let futures = vec![std::future::ready(42)];
        let mut sel = SelectAllDrain::new(futures);

        let result = poll_once(&mut sel);
        match result {
            Poll::Ready(r) => {
                assert_eq!(r.value, 42);
                assert_eq!(r.winner_index, 0);
                assert!(r.losers.is_empty());
            }
            Poll::Pending => unreachable!("expected Ready"),
        }
    }

    #[test]
    fn test_select_all_drain_middle_wins() {
        struct MaybeReady(Option<i32>);
        impl Future for MaybeReady {
            type Output = i32;
            fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<i32> {
                self.0.take().map_or(Poll::Pending, Poll::Ready)
            }
        }

        let futures = vec![MaybeReady(None), MaybeReady(Some(42)), MaybeReady(None)];
        let mut sel = SelectAllDrain::new(futures);

        let result = poll_once(&mut sel);
        match result {
            Poll::Ready(r) => {
                assert_eq!(r.value, 42);
                assert_eq!(r.winner_index, 1);
                assert_eq!(r.losers.len(), 2);
            }
            Poll::Pending => unreachable!("expected Ready"),
        }
    }

    #[test]
    fn test_select_all_drain_pending_returns_pending() {
        let futures: Vec<std::future::Pending<i32>> =
            vec![std::future::pending(), std::future::pending()];
        let mut sel = SelectAllDrain::new(futures);

        let result = poll_once(&mut sel);
        assert!(result.is_pending());
    }

    // ========== Loser-drain invariant tests ==========

    #[test]
    fn test_select_loser_is_not_drained_only_dropped() {
        // This test documents the current behavior: Select drops losers
        // but does NOT drain them. Callers must drain manually.
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

        struct DrainTracker {
            polled_count: Arc<AtomicU32>,
            dropped: Arc<AtomicBool>,
        }
        impl Drop for DrainTracker {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }
        impl Future for DrainTracker {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
                self.polled_count.fetch_add(1, Ordering::SeqCst);
                Poll::Pending
            }
        }

        let polled = Arc::new(AtomicU32::new(0));
        let dropped = Arc::new(AtomicBool::new(false));

        {
            let tracker = DrainTracker {
                polled_count: Arc::clone(&polled),
                dropped: Arc::clone(&dropped),
            };
            let mut sel = Select::new(std::future::ready(42), tracker);
            let result = poll_once(&mut sel);
            assert!(matches!(result, Poll::Ready(Either::Left(42))));
        }

        // Loser was dropped (cleanup via Drop) but NOT drained (not polled to completion)
        assert!(dropped.load(Ordering::SeqCst), "loser must be dropped");
        // Loser was polled exactly once (during Select::poll) but never reached Ready
        assert_eq!(
            polled.load(Ordering::SeqCst),
            0,
            "loser should not be polled when winner is left-biased and immediately ready"
        );
    }

    #[test]
    fn test_select_all_drain_losers_are_available_for_draining() {
        // Verify that SelectAllDrain provides losers that can be further polled
        // (i.e., drained) by the caller.
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountFuture {
            count: Arc<AtomicU32>,
            ready_on: u32,
        }
        impl Future for CountFuture {
            type Output = u32;
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<u32> {
                let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
                if n >= self.ready_on {
                    Poll::Ready(n)
                } else {
                    Poll::Pending
                }
            }
        }

        let counter_a = Arc::new(AtomicU32::new(0));
        let counter_b = Arc::new(AtomicU32::new(0));

        let futures = vec![
            CountFuture {
                count: Arc::clone(&counter_a),
                ready_on: 1,
            }, // Ready on first poll
            CountFuture {
                count: Arc::clone(&counter_b),
                ready_on: 3,
            }, // Needs 3 polls
        ];
        let mut sel = SelectAllDrain::new(futures);

        let result = poll_once(&mut sel);
        match result {
            Poll::Ready(r) => {
                assert_eq!(r.value, 1);
                assert_eq!(r.losers.len(), 1);

                // Drain the loser by polling it to completion
                let mut loser = r.losers.into_iter().next().unwrap();
                assert!(poll_once(&mut loser).is_pending()); // 2nd poll
                let final_result = poll_once(&mut loser); // 3rd poll
                assert!(matches!(final_result, Poll::Ready(3)));
            }
            Poll::Pending => unreachable!("expected Ready"),
        }
    }
}
