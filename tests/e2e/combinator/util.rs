//! Test utilities for combinator E2E tests.

#![allow(dead_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::{Context, Poll, Waker};

/// A flag that tracks whether a cleanup action was executed.
#[derive(Debug, Default)]
pub struct DrainFlag {
    drained: AtomicBool,
}

impl DrainFlag {
    /// Create a new drain flag.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            drained: AtomicBool::new(false),
        })
    }

    /// Mark as drained.
    pub fn set_drained(&self) {
        self.drained.store(true, Ordering::SeqCst);
    }

    /// Check if drained.
    pub fn is_drained(&self) -> bool {
        self.drained.load(Ordering::SeqCst)
    }
}

/// Counter for tracking poll counts and other metrics.
#[derive(Debug, Default)]
pub struct Counter {
    count: AtomicU32,
}

impl Counter {
    /// Create a new counter.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            count: AtomicU32::new(0),
        })
    }

    /// Increment the counter.
    pub fn increment(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }

    /// Get the current count.
    pub fn get(&self) -> u32 {
        self.count.load(Ordering::SeqCst)
    }
}

/// A future that tracks when it is dropped (for drain verification).
pub struct DrainTracker<F> {
    inner: F,
    on_drop: Arc<DrainFlag>,
}

impl<F> DrainTracker<F> {
    /// Create a new drain tracker wrapping a future.
    pub fn new(inner: F, on_drop: Arc<DrainFlag>) -> Self {
        Self { inner, on_drop }
    }
}

impl<F: Future + Unpin> Future for DrainTracker<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

impl<F> Drop for DrainTracker<F> {
    fn drop(&mut self) {
        self.on_drop.set_drained();
    }
}

/// A future that never completes (infinite pending).
pub struct NeverComplete;

impl Future for NeverComplete {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

/// A future that completes after a specified number of polls.
pub struct CompleteAfterPolls {
    polls_remaining: u32,
    poll_counter: Arc<Counter>,
}

impl CompleteAfterPolls {
    /// Create a future that completes after `n` polls.
    pub fn new(n: u32, counter: Arc<Counter>) -> Self {
        Self {
            polls_remaining: n,
            poll_counter: counter,
        }
    }
}

impl Future for CompleteAfterPolls {
    type Output = u32;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll_counter.increment();
        if self.polls_remaining == 0 {
            Poll::Ready(self.poll_counter.get())
        } else {
            self.polls_remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// A controllable future for precise test control.
pub struct ControllableFuture<T> {
    result: Option<T>,
    waker: Option<Waker>,
    ready: AtomicBool,
}

impl<T> ControllableFuture<T> {
    /// Create a new controllable future.
    pub fn new(result: T) -> Arc<std::sync::Mutex<Self>> {
        Arc::new(std::sync::Mutex::new(Self {
            result: Some(result),
            waker: None,
            ready: AtomicBool::new(false),
        }))
    }

    /// Mark the future as ready to complete.
    pub fn complete(this: &Arc<std::sync::Mutex<Self>>) {
        let mut guard = this.lock().unwrap();
        guard.ready.store(true, Ordering::SeqCst);
        if let Some(waker) = guard.waker.take() {
            waker.wake();
        }
    }
}

/// Wrapper to make `ControllableFuture` a `Future`.
pub struct ControllableFutureHandle<T> {
    inner: Arc<std::sync::Mutex<ControllableFuture<T>>>,
}

impl<T> ControllableFutureHandle<T> {
    /// Create a handle from a controllable future.
    pub fn new(inner: Arc<std::sync::Mutex<ControllableFuture<T>>>) -> Self {
        Self { inner }
    }
}

impl<T: Clone> Future for ControllableFutureHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.inner.lock().unwrap();
        if guard.ready.load(Ordering::SeqCst) {
            Poll::Ready(guard.result.clone().unwrap())
        } else {
            guard.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// Assert helper for drain verification.
#[macro_export]
macro_rules! assert_drained {
    ($flag:expr) => {
        assert!(
            $flag.is_drained(),
            "CRITICAL: Loser was not drained! This violates the asupersync cancel-correct invariant."
        );
    };
    ($flag:expr, $msg:expr) => {
        assert!($flag.is_drained(), "CRITICAL: {} - loser not drained", $msg);
    };
}

/// Assert helper for NOT drained (winner shouldn't be drained).
#[macro_export]
macro_rules! assert_not_drained {
    ($flag:expr) => {
        assert!(
            !$flag.is_drained(),
            "Winner should not be drained - it completed normally"
        );
    };
}
