//! Fold combinator for streams.
//!
//! The `Fold` future consumes a stream and folds all items into a single value.

use super::Stream;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Cooperative budget for items folded in a single poll.
///
/// Without this cap, a synchronously ready stream can keep `Fold` inside one
/// `poll` call until exhaustion and starve sibling tasks.
const FOLD_COOPERATIVE_BUDGET: usize = 1024;

/// A future that folds all items from a stream into a single value.
///
/// Created by [`StreamExt::fold`](super::StreamExt::fold).
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct Fold<S, F, Acc> {
    stream: S,
    f: F,
    acc: Option<Acc>,
    completed: bool,
}

struct FoldProj<'a, S, F, Acc> {
    stream: Pin<&'a mut S>,
    f: &'a mut F,
    acc: &'a mut Option<Acc>,
    completed: &'a mut bool,
}

impl<S, F, Acc> Fold<S, F, Acc> {
    #[allow(unsafe_code)]
    fn project(self: Pin<&mut Self>) -> FoldProj<'_, S, F, Acc> {
        // SAFETY: `stream` is structurally pinned; remaining fields are not pinned.
        let this = unsafe { self.get_unchecked_mut() };
        FoldProj {
            stream: unsafe { Pin::new_unchecked(&mut this.stream) },
            f: &mut this.f,
            acc: &mut this.acc,
            completed: &mut this.completed,
        }
    }

    /// Creates a new `Fold` future.
    #[inline]
    pub(crate) fn new(stream: S, init: Acc, f: F) -> Self {
        Self {
            stream,
            f,
            acc: Some(init),
            completed: false,
        }
    }
}

impl<S, F, Acc> Future for Fold<S, F, Acc>
where
    S: Stream,
    F: FnMut(Acc, S::Item) -> Acc,
{
    type Output = Acc;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Acc> {
        let mut this = self.project();
        assert!(!*this.completed, "Fold polled after completion");
        let mut folded_this_poll = 0usize;
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    let acc = this.acc.take().expect("Fold polled after completion");
                    *this.acc = Some((this.f)(acc, item));
                    folded_this_poll += 1;
                    if folded_this_poll >= FOLD_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    *this.completed = true;
                    return Poll::Ready(this.acc.take().expect("Fold polled after completion"));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
#[path = "fold_inline_tests.rs"]
mod tests;
