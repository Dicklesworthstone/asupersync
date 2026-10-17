//! Cooperative yielding primitive for the asupersync runtime.
//!
//! This module provides the `yield_now()` function that allows tasks to voluntarily
//! yield execution back to the runtime scheduler, enabling fair cooperative multitasking.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Future that yields execution back to the runtime.
pub struct YieldNow {
    yielded: bool,
    completed: bool,
}

impl Future for YieldNow {
    type Output = ();

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        assert!(!self.completed, "yield_now future polled after completion");
        if self.yielded {
            self.completed = true;
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Yields execution back to the runtime, allowing other tasks to run.
#[inline]
#[must_use]
pub fn yield_now() -> YieldNow {
    YieldNow {
        yielded: false,
        completed: false,
    }
}

#[cfg(test)]
#[path = "yield_now_inline_tests.rs"]
mod tests;
