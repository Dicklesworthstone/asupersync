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
    #[inline]
    pub fn is_left(&self) -> bool {
        matches!(self, Self::Left(_))
    }

    /// Returns true if this is the Right variant.
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    /// Remaining (loser) futures that the caller MUST cancel and drain, in
    /// their original order without the winner: the loser at original index
    /// `i` is `losers[i]` before `winner_index` and `losers[i - 1]` after it.
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
            // `remove`, not `swap_remove`: the losers keep their original
            // order, the coordinates `winner_index` is given in.
            all.remove(idx);
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
#[path = "select_inline_tests.rs"]
mod tests;
