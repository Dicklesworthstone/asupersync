//! Select combinator: wait for the first of two futures to complete.

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
        for (i, f) in self.futures.iter_mut().enumerate() {
            if let Poll::Ready(v) = Pin::new(f).poll(cx) {
                return Poll::Ready((v, i));
            }
        }
        Poll::Pending
    }
}
