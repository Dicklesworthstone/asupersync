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
//! match Select::new(f1, f2).await.expect("fresh select future") {
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

/// Error returned by [`Select`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectError {
    /// The future was polled after already returning a terminal result.
    PolledAfterCompletion,
}

impl std::fmt::Display for SelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolledAfterCompletion => write!(f, "select future polled after completion"),
        }
    }
}

impl std::error::Error for SelectError {}

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
    poll_a_first: bool,
    completed: bool,
}

impl<A, B> Select<A, B> {
    /// Creates a new select combinator.
    pub fn new(a: A, b: B) -> Self {
        Self {
            a,
            b,
            poll_a_first: true,
            completed: false,
        }
    }
}

impl<A: Future + Unpin, B: Future + Unpin> Future for Select<A, B> {
    type Output = Result<Either<A::Output, B::Output>, SelectError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        if this.completed {
            return Poll::Ready(Err(SelectError::PolledAfterCompletion));
        }

        if this.poll_a_first {
            if let Poll::Ready(val) = Pin::new(&mut this.a).poll(cx) {
                this.completed = true;
                return Poll::Ready(Ok(Either::Left(val)));
            }
            if let Poll::Ready(val) = Pin::new(&mut this.b).poll(cx) {
                this.completed = true;
                return Poll::Ready(Ok(Either::Right(val)));
            }
        } else {
            if let Poll::Ready(val) = Pin::new(&mut this.b).poll(cx) {
                this.completed = true;
                return Poll::Ready(Ok(Either::Right(val)));
            }
            if let Poll::Ready(val) = Pin::new(&mut this.a).poll(cx) {
                this.completed = true;
                return Poll::Ready(Ok(Either::Left(val)));
            }
        }

        this.poll_a_first = !this.poll_a_first;
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
    start_idx: usize,
    completed: bool,
}

impl<F> SelectAll<F> {
    /// Creates a new select_all combinator.
    #[must_use]
    pub fn new(futures: Vec<F>) -> Self {
        assert!(
            !futures.is_empty(),
            "select_all requires at least one future"
        );
        Self {
            futures,
            start_idx: 0,
            completed: false,
        }
    }
}

/// Error returned by [`SelectAll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectAllError {
    /// The future was polled after already returning a terminal result.
    PolledAfterCompletion,
}

impl std::fmt::Display for SelectAllError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolledAfterCompletion => {
                write!(f, "select_all future polled after completion")
            }
        }
    }
}

impl std::error::Error for SelectAllError {}

impl<F: Future + Unpin> Future for SelectAll<F> {
    type Output = Result<(F::Output, usize), SelectAllError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(SelectAllError::PolledAfterCompletion));
        }

        let len = self.futures.len();
        if len == 0 {
            return Poll::Pending;
        }

        let start = self.start_idx % len;
        for i in 0..len {
            let idx = (start + i) % len;
            if let Poll::Ready(v) = Pin::new(&mut self.futures[idx]).poll(cx) {
                self.completed = true;
                return Poll::Ready(Ok((v, idx)));
            }
        }

        self.start_idx = self.start_idx.wrapping_add(1);
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
    start_idx: usize,
    completed: bool,
}

impl<F> SelectAllDrain<F> {
    /// Creates a new drain-aware select_all combinator.
    #[must_use]
    pub fn new(futures: Vec<F>) -> Self {
        assert!(
            !futures.is_empty(),
            "select_all_drain requires at least one future"
        );
        Self {
            futures: Some(futures),
            start_idx: 0,
            completed: false,
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

/// Error returned by [`SelectAllDrain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectAllDrainError {
    /// The future was polled after already returning a terminal result.
    PolledAfterCompletion,
}

impl std::fmt::Display for SelectAllDrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolledAfterCompletion => {
                write!(f, "select_all_drain future polled after completion")
            }
        }
    }
}

impl std::error::Error for SelectAllDrainError {}

impl<F: Future + Unpin> Future for SelectAllDrain<F> {
    type Output = Result<SelectAllDrainResult<F::Output, F>, SelectAllDrainError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        if this.completed {
            return Poll::Ready(Err(SelectAllDrainError::PolledAfterCompletion));
        }
        let start_idx = this.start_idx;
        let mut ready = None;

        {
            let Some(futures) = this.futures.as_mut() else {
                this.completed = true;
                return Poll::Ready(Err(SelectAllDrainError::PolledAfterCompletion));
            };
            let len = futures.len();
            if len == 0 {
                return Poll::Pending;
            }

            let start = start_idx % len;
            for i in 0..len {
                let idx = (start + i) % len;
                if let Poll::Ready(value) = Pin::new(&mut futures[idx]).poll(cx) {
                    ready = Some((idx, value));
                    break;
                }
            }
        }

        if let Some((idx, value)) = ready {
            this.completed = true;
            let Some(mut all) = this.futures.take() else {
                return Poll::Ready(Err(SelectAllDrainError::PolledAfterCompletion));
            };
            all.swap_remove(idx);
            return Poll::Ready(Ok(SelectAllDrainResult {
                value,
                winner_index: idx,
                losers: all,
            }));
        }

        this.start_idx = this.start_idx.wrapping_add(1);
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
        assert!(matches!(result, Poll::Ready(Ok(Either::Left(42)))));
    }

    #[test]
    fn test_select_right_ready_first() {
        let left = std::future::pending::<i32>();
        let right = std::future::ready("hello");
        let mut sel = Select::new(left, right);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready(Ok(Either::Right("hello")))));
    }

    #[test]
    fn test_select_both_ready_left_biased() {
        // When both are ready, left wins (poll order bias)
        let left = std::future::ready(1);
        let right = std::future::ready(2);
        let mut sel = Select::new(left, right);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready(Ok(Either::Left(1)))));
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
        assert!(matches!(result, Poll::Ready(Ok(Either::Left(())))));
    }

    #[test]
    fn test_select_different_types() {
        let left = std::future::pending::<Vec<u8>>();
        let right = std::future::ready(String::from("done"));
        let mut sel = Select::new(left, right);

        let result = poll_once(&mut sel);
        match result {
            Poll::Ready(Ok(Either::Right(s))) => assert_eq!(s, "done"),
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
        assert!(matches!(result, Poll::Ready(Ok(Either::Right(99)))));
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
            assert!(matches!(result, Poll::Ready(Ok(Either::Left(42)))));
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
        assert!(matches!(result, Poll::Ready(Ok((10, 0)))));
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
        assert!(matches!(result, Poll::Ready(Ok((42, 1)))));
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
        assert!(matches!(result, Poll::Ready(Ok((99, 2)))));
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
        assert!(matches!(result, Poll::Ready(Ok((7, 0)))));
    }

    #[test]
    #[should_panic(expected = "select_all requires at least one future")]
    fn test_select_all_empty_vec_rejected() {
        let futures: Vec<std::future::Ready<i32>> = vec![];
        let _sel = SelectAll::new(futures);
    }

    #[test]
    fn test_select_all_does_not_eagerly_poll_all_futures() {
        // Verify that SelectAll does NOT eagerly poll all futures after finding
        // a ready one. Eager polling swallows panics and drops ready results.
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
        assert!(matches!(result, Poll::Ready(Ok(((), 0)))));

        // Only the first future should have been polled
        assert_eq!(counter.load(Ordering::SeqCst), 1);
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
        assert!(matches!(result, Poll::Ready(Ok((1, 0)))));
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
            Poll::Ready(Ok(r)) => {
                assert_eq!(r.value, 10);
                assert_eq!(r.winner_index, 0);
                // The first future wins, and because SelectAllDrain short-circuits,
                // the other futures are never polled and are returned as losers.
                assert_eq!(r.losers.len(), 2);
            }
            Poll::Ready(Err(err)) => panic!("unexpected SelectAllDrain error: {err}"),
            Poll::Pending => unreachable!("expected Ready"),
        }
    }

    #[test]
    fn test_select_all_drain_single_future() {
        let futures = vec![std::future::ready(42)];
        let mut sel = SelectAllDrain::new(futures);

        let result = poll_once(&mut sel);
        match result {
            Poll::Ready(Ok(r)) => {
                assert_eq!(r.value, 42);
                assert_eq!(r.winner_index, 0);
                assert!(r.losers.is_empty());
            }
            Poll::Ready(Err(err)) => panic!("unexpected SelectAllDrain error: {err}"),
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
            Poll::Ready(Ok(r)) => {
                assert_eq!(r.value, 42);
                assert_eq!(r.winner_index, 1);
                assert_eq!(r.losers.len(), 2);
            }
            Poll::Ready(Err(err)) => panic!("unexpected SelectAllDrain error: {err}"),
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

    #[test]
    #[should_panic(expected = "select_all_drain requires at least one future")]
    fn test_select_all_drain_empty_vec_rejected() {
        let futures: Vec<std::future::Ready<i32>> = vec![];
        let _sel = SelectAllDrain::new(futures);
    }

    #[test]
    fn test_select_all_drain_simultaneous_ready_returns_unpolled_losers() {
        // When multiple futures are ready, the ones after the winner are NOT polled
        // during this SelectAllDrain::poll call. Thus they are safe to be returned
        // in losers, where the caller will poll them for the first time to drain them.
        use std::sync::atomic::{AtomicU32, Ordering};

        struct TrackableFuture {
            poll_count: Arc<AtomicU32>,
            ready: bool,
        }
        impl Future for TrackableFuture {
            type Output = &'static str;
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<&'static str> {
                self.poll_count.fetch_add(1, Ordering::SeqCst);
                if self.ready {
                    Poll::Ready("done")
                } else {
                    Poll::Pending
                }
            }
        }

        let pending_count = Arc::new(AtomicU32::new(0));
        let ready1_count = Arc::new(AtomicU32::new(0));
        let ready2_count = Arc::new(AtomicU32::new(0));

        let futures = vec![
            TrackableFuture {
                poll_count: Arc::clone(&pending_count),
                ready: false,
            },
            TrackableFuture {
                poll_count: Arc::clone(&ready1_count),
                ready: true,
            }, // winner (first ready)
            TrackableFuture {
                poll_count: Arc::clone(&ready2_count),
                ready: true,
            }, // also ready but non-winner, should not be polled
        ];
        let mut sel = SelectAllDrain::new(futures);

        let result = poll_once(&mut sel);
        match result {
            Poll::Ready(Ok(r)) => {
                assert_eq!(r.value, "done");
                assert_eq!(r.winner_index, 1);
                // Both the pending future and the unpolled ready future should be in losers.
                assert_eq!(r.losers.len(), 2, "all remaining futures should be losers");

                // Only the first two were polled.
                assert_eq!(pending_count.load(Ordering::SeqCst), 1);
                assert_eq!(ready1_count.load(Ordering::SeqCst), 1);
                assert_eq!(ready2_count.load(Ordering::SeqCst), 0);
            }
            Poll::Ready(Err(err)) => panic!("unexpected SelectAllDrain error: {err}"),
            Poll::Pending => unreachable!("expected Ready"),
        }
    }

    #[test]
    fn test_select_all_drain_rotates_start_index_after_pending_poll() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct ReadyOnSecondPoll {
            polls: Arc<AtomicU32>,
        }

        impl Future for ReadyOnSecondPoll {
            type Output = u32;

            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<u32> {
                let polls = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
                if polls >= 2 {
                    Poll::Ready(polls)
                } else {
                    Poll::Pending
                }
            }
        }

        let first_polls = Arc::new(AtomicU32::new(0));
        let second_polls = Arc::new(AtomicU32::new(0));
        let futures = vec![
            ReadyOnSecondPoll {
                polls: Arc::clone(&first_polls),
            },
            ReadyOnSecondPoll {
                polls: Arc::clone(&second_polls),
            },
        ];
        let mut sel = SelectAllDrain::new(futures);

        assert!(poll_once(&mut sel).is_pending());
        match poll_once(&mut sel) {
            Poll::Ready(Ok(r)) => {
                assert_eq!(r.winner_index, 1);
                assert_eq!(r.value, 2);
                assert_eq!(r.losers.len(), 1);
                assert_eq!(first_polls.load(Ordering::SeqCst), 1);
                assert_eq!(second_polls.load(Ordering::SeqCst), 2);
            }
            Poll::Ready(Err(err)) => panic!("unexpected SelectAllDrain error: {err}"),
            Poll::Pending => unreachable!("expected Ready"),
        }
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
            assert!(matches!(result, Poll::Ready(Ok(Either::Left(42)))));
        }

        // Loser was dropped (cleanup via Drop) but NOT drained (not polled to completion)
        assert!(dropped.load(Ordering::SeqCst), "loser must be dropped");
        // Loser should NOT be polled if the winner is immediately ready. Eager polling
        // was removed to prevent dropping ready results (which swallows panics).
        assert_eq!(
            polled.load(Ordering::SeqCst),
            0,
            "loser should not be polled if winner is left-biased and immediately ready"
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
            Poll::Ready(Ok(r)) => {
                assert_eq!(r.value, 1);
                assert_eq!(r.losers.len(), 1);

                // Drain the loser by polling it to completion
                let mut loser = r.losers.into_iter().next().unwrap();
                assert!(poll_once(&mut loser).is_pending()); // 1st poll
                assert!(poll_once(&mut loser).is_pending()); // 2nd poll
                let final_result = poll_once(&mut loser); // 3rd poll
                assert!(matches!(final_result, Poll::Ready(3)));
            }
            Poll::Ready(Err(err)) => panic!("unexpected SelectAllDrain error: {err}"),
            Poll::Pending => unreachable!("expected Ready"),
        }
    }

    #[test]
    fn test_select_all_drain_second_poll_fails_closed_without_repolling_upstream() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct TrackableFuture {
            poll_count: Arc<AtomicU32>,
        }
        impl Future for TrackableFuture {
            type Output = u32;
            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<u32> {
                self.poll_count.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(42)
            }
        }

        let count = Arc::new(AtomicU32::new(0));
        let futures = vec![TrackableFuture {
            poll_count: Arc::clone(&count),
        }];
        let mut sel = SelectAllDrain::new(futures);

        // First poll completes normally.
        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready(Ok(_))));
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Second poll must fail closed immediately without touching the (now-gone)
        // upstream futures.
        let second = poll_once(&mut sel);
        assert!(matches!(
            second,
            Poll::Ready(Err(SelectAllDrainError::PolledAfterCompletion))
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_select_repoll_after_completion_fails_closed() {
        let left = std::future::ready(42);
        let right = std::future::pending::<i32>();
        let mut sel = Select::new(left, right);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready(Ok(Either::Left(42)))));
        let result2 = poll_once(&mut sel);
        assert!(matches!(
            result2,
            Poll::Ready(Err(SelectError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn test_select_all_repoll_after_completion_fails_closed() {
        let futures = vec![std::future::ready(10)];
        let mut sel = SelectAll::new(futures);

        let result = poll_once(&mut sel);
        assert!(matches!(result, Poll::Ready(Ok((10, 0)))));
        let result2 = poll_once(&mut sel);
        assert!(matches!(
            result2,
            Poll::Ready(Err(SelectAllError::PolledAfterCompletion))
        ));
    }
}
