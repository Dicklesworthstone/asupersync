//! Symbol stream traits and implementations for transport layer.
//!
//! This module defines the streaming abstractions used by the transport layer
//! to send and receive authenticated symbols between peers. Symbol streams
//! provide flow control, buffering, and cancellation-safe transmission.
//!
//! # Core Abstractions
//!
//! - **Symbol streams**: Async streams of [`AuthenticatedSymbol`] with flow control
//! - **Shared channels**: Multi-producer, multi-consumer symbol distribution
//! - **Channel waiters**: Efficient waiting for stream readiness without polling
//! - **Stream lifecycle**: Proper setup, transmission, and teardown protocols
//!
//! # Design Properties
//!
//! - **Cancellation safety**: Streams handle cancellation without data loss
//! - **Flow control**: Back-pressure prevents memory exhaustion
//! - **Authentication**: All symbols are authenticated before transmission
//! - **Efficiency**: Zero-copy transmission where possible, minimal allocations

use crate::cx::Cx;
use crate::security::authenticated::AuthenticatedSymbol;
use crate::time::Sleep;
use crate::transport::error::StreamError;
use crate::transport::{ChannelWaiter, SharedChannel, SymbolSet};
use crate::types::Time;
use smallvec::SmallVec;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// Cooperative budget for rejected symbols drained in a single poll.
///
/// Without this cap, an always-ready upstream stream can monopolize one
/// executor turn if every symbol is rejected by the predicate.
const FILTER_REJECTION_BUDGET: usize = 64;

/// Cooperative budget for symbols collected into a set in a single poll.
///
/// Without this cap, `collect_to_set()` can monopolize one executor turn when
/// the upstream stream is always-ready for long runs.
const COLLECT_TO_SET_COOPERATIVE_BUDGET: usize = 1024;

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn upsert_channel_waiter(
    wakers: &mut SmallVec<[ChannelWaiter; 2]>,
    queued: &Arc<AtomicBool>,
    waker: &Waker,
) {
    if let Some(existing) = wakers
        .iter_mut()
        .find(|entry| Arc::ptr_eq(&entry.queued, queued))
    {
        if !existing.waker.will_wake(waker) {
            existing.waker.clone_from(waker);
        }
    } else {
        wakers.push(ChannelWaiter {
            waker: waker.clone(),
            queued: Arc::clone(queued),
        });
    }
}

fn pop_next_queued_waiter(wakers: &mut SmallVec<[ChannelWaiter; 2]>) -> Option<ChannelWaiter> {
    wakers.retain(|entry| entry.queued.load(Ordering::Acquire));
    if wakers.is_empty() {
        None
    } else {
        // Preserve FIFO wake order to avoid starving earlier waiters.
        Some(wakers.remove(0))
    }
}

/// A stream of incoming symbols.
pub trait SymbolStream: Send {
    /// Receive the next symbol.
    ///
    /// Returns `None` when stream is exhausted or closed.
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>>;

    /// Hint about remaining symbols (if known).
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }

    /// Check if the stream is exhausted.
    fn is_exhausted(&self) -> bool {
        false
    }
}

/// Extension methods for SymbolStream.
pub trait SymbolStreamExt: SymbolStream {
    /// Receive the next symbol.
    fn next(&mut self) -> NextFuture<'_, Self>
    where
        Self: Unpin,
    {
        NextFuture {
            stream: self,
            completed: false,
        }
    }

    /// Collect all symbols into a SymbolSet.
    fn collect_to_set<'a>(&'a mut self, set: &'a mut SymbolSet) -> CollectToSetFuture<'a, Self>
    where
        Self: Unpin,
    {
        CollectToSetFuture {
            stream: self,
            set,
            count: 0,
            completed: false,
        }
    }

    /// Transform successful symbols while preserving stream shape.
    ///
    /// Errors and end-of-stream are passed through unchanged.
    fn map<F>(self, f: F) -> MapStream<Self, F>
    where
        Self: Sized,
        F: FnMut(AuthenticatedSymbol) -> AuthenticatedSymbol + Send + Unpin,
    {
        MapStream {
            inner: self,
            f,
            exhausted: false,
        }
    }

    /// Filter symbols.
    fn filter<F>(self, f: F) -> FilterStream<Self, F>
    where
        Self: Sized,
        F: FnMut(&AuthenticatedSymbol) -> bool,
    {
        FilterStream {
            inner: self,
            f,
            exhausted: false,
        }
    }

    /// Take only symbols for a specific block.
    #[allow(clippy::type_complexity)]
    fn for_block(
        self,
        sbn: u8,
    ) -> FilterStream<Self, Box<dyn FnMut(&AuthenticatedSymbol) -> bool + Send>>
    where
        Self: Sized + 'static,
    {
        let f = Box::new(move |s: &AuthenticatedSymbol| s.symbol().sbn() == sbn);
        FilterStream {
            inner: self,
            f,
            exhausted: false,
        }
    }

    /// Timeout on symbol reception.
    fn timeout(self, duration: Duration) -> TimeoutStream<Self>
    where
        Self: Sized,
    {
        TimeoutStream::new(self, duration)
    }

    /// Receive the next symbol with cancellation support.
    fn next_with_cancel<'a>(&'a mut self, cx: &'a Cx) -> NextWithCancelFuture<'a, Self>
    where
        Self: Unpin,
    {
        NextWithCancelFuture {
            stream: self,
            cx,
            completed: false,
        }
    }
}

impl<S: SymbolStream + ?Sized> SymbolStreamExt for S {}

// ---- Futures ----

/// Future for `next()`.
pub struct NextFuture<'a, S: ?Sized> {
    stream: &'a mut S,
    completed: bool,
}

impl<S: SymbolStream + Unpin + ?Sized> Future for NextFuture<'_, S> {
    type Output = Option<Result<AuthenticatedSymbol, StreamError>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if this.completed {
            return Poll::Ready(Some(Err(StreamError::PolledAfterCompletion)));
        }

        match Pin::new(&mut *this.stream).poll_next(cx) {
            Poll::Ready(result) => {
                this.completed = true;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Future for `collect_to_set()`.
pub struct CollectToSetFuture<'a, S: ?Sized> {
    stream: &'a mut S,
    set: &'a mut SymbolSet,
    count: usize,
    completed: bool,
}

impl<S: SymbolStream + Unpin + ?Sized> Future for CollectToSetFuture<'_, S> {
    type Output = Result<usize, StreamError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if this.completed {
            return Poll::Ready(Err(StreamError::PolledAfterCompletion));
        }

        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
            this.completed = true;
            return Poll::Ready(Err(StreamError::Cancelled));
        }

        let mut collected_this_poll = 0usize;
        loop {
            match Pin::new(&mut *this.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(symbol))) => {
                    if this.set.insert(symbol.into_symbol()) {
                        this.count = this.count.saturating_add(1);
                    }
                    collected_this_poll += 1;
                    if collected_this_poll >= COLLECT_TO_SET_COOPERATIVE_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    this.completed = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(None) => {
                    this.completed = true;
                    return Poll::Ready(Ok(this.count));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Future for `next_with_cancel()`.
pub struct NextWithCancelFuture<'a, S: ?Sized> {
    stream: &'a mut S,
    cx: &'a Cx,
    completed: bool,
}

impl<S: SymbolStream + Unpin + ?Sized> Future for NextWithCancelFuture<'_, S> {
    type Output = Result<Option<AuthenticatedSymbol>, StreamError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if this.completed {
            return Poll::Ready(Err(StreamError::PolledAfterCompletion));
        }

        if this.cx.checkpoint().is_err() {
            this.completed = true;
            return Poll::Ready(Err(StreamError::Cancelled));
        }

        match Pin::new(&mut *this.stream).poll_next(cx) {
            Poll::Ready(Some(Ok(symbol))) => {
                this.completed = true;
                Poll::Ready(Ok(Some(symbol)))
            }
            Poll::Ready(Some(Err(err))) => {
                this.completed = true;
                Poll::Ready(Err(err))
            }
            Poll::Ready(None) => {
                this.completed = true;
                Poll::Ready(Ok(None))
            }
            Poll::Pending => {
                if this.cx.checkpoint().is_err() {
                    this.completed = true;
                    Poll::Ready(Err(StreamError::Cancelled))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

// ---- Stream Adapters ----

/// Stream that maps items.
pub struct MapStream<S, F> {
    inner: S,
    f: F,
    exhausted: bool,
}

impl<S, F> SymbolStream for MapStream<S, F>
where
    S: SymbolStream + Unpin,
    F: FnMut(AuthenticatedSymbol) -> AuthenticatedSymbol + Send + Unpin,
{
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let this = self.get_mut();
        if this.exhausted {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(s))) => Poll::Ready(Some(Ok((this.f)(s)))),
            Poll::Ready(None) => {
                this.exhausted = true;
                Poll::Ready(None)
            }
            other => other,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            (0, Some(0))
        } else {
            self.inner.size_hint()
        }
    }

    fn is_exhausted(&self) -> bool {
        self.exhausted || self.inner.is_exhausted()
    }
}

/// Stream that filters items.
pub struct FilterStream<S, F> {
    inner: S,
    f: F,
    exhausted: bool,
}

impl<S, F> SymbolStream for FilterStream<S, F>
where
    S: SymbolStream + Unpin,
    F: FnMut(&AuthenticatedSymbol) -> bool + Send + Unpin,
{
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let this = self.get_mut();
        if this.exhausted {
            return Poll::Ready(None);
        }
        let mut rejected = 0usize;
        loop {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return Poll::Ready(Some(Err(StreamError::Cancelled)));
            }

            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(s))) => {
                    if (this.f)(&s) {
                        return Poll::Ready(Some(Ok(s)));
                    }
                    rejected = rejected.saturating_add(1);
                    if rejected >= FILTER_REJECTION_BUDGET {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    this.exhausted = true;
                    return Poll::Ready(None);
                }
                other => return other,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.exhausted {
            return (0, Some(0));
        }
        let (_, upper) = self.inner.size_hint();
        (0, upper)
    }

    fn is_exhausted(&self) -> bool {
        self.exhausted || self.inner.is_exhausted()
    }
}

/// Stream that merges multiple streams in round-robin order.
pub struct MergedStream<S> {
    streams: Vec<S>,
    current: usize,
}

impl<S> MergedStream<S> {
    /// Creates a merged stream from the provided streams.
    #[must_use]
    pub fn new(streams: Vec<S>) -> Self {
        Self {
            streams,
            current: 0,
        }
    }
}

impl<S: SymbolStream + Unpin> SymbolStream for MergedStream<S> {
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        if self.streams.is_empty() {
            return Poll::Ready(None);
        }

        let mut checked = 0;
        let mut idx = self.current;

        while checked < self.streams.len() {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return Poll::Ready(Some(Err(StreamError::Cancelled)));
            }

            if idx >= self.streams.len() {
                idx = 0;
            }

            match Pin::new(&mut self.streams[idx]).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.current = (idx + 1) % self.streams.len();
                    return Poll::Ready(Some(item));
                }
                Poll::Ready(None) => {
                    self.streams.remove(idx);
                    if self.streams.is_empty() {
                        return Poll::Ready(None);
                    }
                    if idx < self.current && self.current > 0 {
                        self.current -= 1;
                    }
                    if self.current >= self.streams.len() {
                        self.current = 0;
                    }
                }
                Poll::Pending => {
                    idx += 1;
                    checked += 1;
                }
            }
        }

        Poll::Pending
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut lower: usize = 0;
        let mut upper = Some(0usize);

        for stream in &self.streams {
            let (l, u) = stream.size_hint();
            lower = lower.saturating_add(l);
            match (upper, u) {
                (Some(acc), Some(u)) => upper = acc.checked_add(u),
                _ => upper = None,
            }
        }

        (lower, upper)
    }

    fn is_exhausted(&self) -> bool {
        self.streams.iter().all(SymbolStream::is_exhausted)
    }
}

// ---- Implementations ----

/// In-memory channel stream.
pub struct ChannelStream {
    pub(crate) shared: Arc<SharedChannel>,
    /// Tracks if we already have a waiter registered to prevent unbounded queue growth.
    waiter: Option<Arc<AtomicBool>>,
}

impl ChannelStream {
    pub(crate) fn new(shared: Arc<SharedChannel>) -> Self {
        Self {
            shared,
            waiter: None,
        }
    }
}

impl Drop for ChannelStream {
    fn drop(&mut self) {
        let Some(waiter) = self.waiter.as_ref() else {
            return;
        };

        waiter.store(false, Ordering::Release);
        {
            let mut wakers = self.shared.recv_wakers.lock();
            wakers.retain(|entry| !Arc::ptr_eq(&entry.queued, waiter));
        }

        // Pass the baton: if we were woken but dropped before consuming the
        // symbol, we must wake the next waiter to prevent a lost wakeup.
        let has_items_or_closed = {
            let queue = self.shared.queue.lock();
            !queue.is_empty() || self.shared.closed.load(Ordering::Acquire)
        };

        if has_items_or_closed {
            let next_waiter = {
                let mut wakers = self.shared.recv_wakers.lock();
                pop_next_queued_waiter(&mut wakers)
            };
            if let Some(w) = next_waiter {
                w.queued.store(false, Ordering::Release);
                w.waker.wake();
            }
        }
    }
}

impl SymbolStream for ChannelStream {
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let this = self.get_mut();
        let mut symbol = None;
        let mut closed = false;
        {
            let mut queue = this.shared.queue.lock();
            if let Some(entry) = queue.pop_front() {
                symbol = Some(entry);
            } else if this.shared.closed.load(Ordering::Acquire) {
                closed = true;
            }
        }

        if let Some(symbol) = symbol {
            // Mark as no longer queued if we had a waiter
            if let Some(waiter) = this.waiter.as_ref() {
                waiter.store(false, Ordering::Release);
            }
            // Wake sender if we freed space.
            let waiter = {
                let mut wakers = this.shared.send_wakers.lock();
                pop_next_queued_waiter(&mut wakers)
            };
            if let Some(w) = waiter {
                w.queued.store(false, Ordering::Release);
                w.waker.wake();
            }
            return Poll::Ready(Some(Ok(symbol)));
        }

        if closed {
            return Poll::Ready(None);
        }

        // Only register waiter once to prevent unbounded queue growth.
        // If the same waiter is still queued, refresh its waker to avoid
        // stale wakeups after task context/executor migration.
        let mut new_waiter = None;
        let mut closed = false;
        {
            let mut wakers = this.shared.recv_wakers.lock();
            if this.shared.closed.load(Ordering::Acquire) {
                closed = true;
            } else {
                match this.waiter.as_ref() {
                    Some(waiter) if !waiter.load(Ordering::Acquire) => {
                        // We were woken but no message yet - re-register
                        waiter.store(true, Ordering::Release);
                        upsert_channel_waiter(&mut wakers, waiter, cx.waker());
                    }
                    Some(waiter) => {
                        upsert_channel_waiter(&mut wakers, waiter, cx.waker());
                    }
                    None => {
                        // First time waiting - create new waiter
                        let waiter = Arc::new(AtomicBool::new(true));
                        upsert_channel_waiter(&mut wakers, &waiter, cx.waker());
                        new_waiter = Some(waiter);
                    }
                }
            }
            drop(wakers);
        }
        if closed {
            return Poll::Ready(None);
        }
        if let Some(waiter) = new_waiter {
            this.waiter = Some(waiter);
        }

        // Re-check the queue after waiter registration to close a lost-wakeup
        // race: a sender may push between our queue check and waiter
        // registration, finding no recv_waker to wake.
        {
            let queue = this.shared.queue.lock();
            if !queue.is_empty() || this.shared.closed.load(Ordering::Acquire) {
                drop(queue);
                cx.waker().wake_by_ref();
            }
        }

        Poll::Pending
    }
}

/// Stream from a Vec.
pub struct VecStream {
    symbols: std::vec::IntoIter<AuthenticatedSymbol>,
}

impl VecStream {
    /// Creates a stream from a vector of symbols.
    #[must_use]
    pub fn new(symbols: Vec<AuthenticatedSymbol>) -> Self {
        Self {
            symbols: symbols.into_iter(),
        }
    }
}

impl SymbolStream for VecStream {
    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        Poll::Ready(self.get_mut().symbols.next().map(Ok))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.symbols.size_hint()
    }
}

// ---- Timeout ----

// Implementation of TimeoutStream requires a timer facility.
// Asupersync has `time::sleep`.
// But that returns a Future. `poll_next` is synchronous-ish (returns Poll).
// To implement timeout in `poll_next`, we need to poll a Sleep future stored in the struct.

/// Stream wrapper that yields timeout errors after a fixed duration.
pub struct TimeoutStream<S> {
    inner: S,
    duration: Duration,
    sleep: Sleep,
    time_getter: fn() -> Time,
    exhausted: bool,
}

impl<S> TimeoutStream<S> {
    /// Creates a timeout stream using wall-clock time.
    ///
    /// The timeout registers with the timer driver (or spawns a fallback
    /// thread) so it fires independently of the inner stream's wakeups.
    pub fn new(inner: S, duration: Duration) -> Self {
        let now = wall_clock_now();
        let deadline = now.saturating_add_nanos(duration_to_nanos(duration));
        Self {
            inner,
            duration,
            sleep: Sleep::new(deadline),
            time_getter: wall_clock_now,
            exhausted: false,
        }
    }

    /// Creates a timeout stream using a custom time source.
    ///
    /// **Note:** With a custom time getter, the timeout only fires when the
    /// stream is polled (no independent waker is registered). This is
    /// appropriate for virtual-time testing where the caller controls polling.
    pub fn with_time_getter(inner: S, duration: Duration, time_getter: fn() -> Time) -> Self {
        let now = time_getter();
        let deadline = now.saturating_add_nanos(duration_to_nanos(duration));
        let sleep = Sleep::with_time_getter(deadline, time_getter);
        Self {
            inner,
            duration,
            sleep,
            time_getter,
            exhausted: false,
        }
    }

    fn reset_timer(&mut self) {
        let now = (self.time_getter)();
        self.sleep.reset_after(now, self.duration);
    }
}

impl<S: SymbolStream + Unpin> SymbolStream for TimeoutStream<S> {
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        if self.exhausted {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(item)) => {
                self.reset_timer();
                return Poll::Ready(Some(item));
            }
            Poll::Ready(None) => {
                self.exhausted = true;
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        // Poll Sleep as a Future so it can register with the timer driver
        // (or spawn a fallback thread) for an independent wakeup. Without
        // this, the timeout only fires when the inner stream is polled,
        // which defeats the purpose of a receive timeout on silent channels.
        match Pin::new(&mut self.sleep).poll(cx) {
            Poll::Ready(()) => {
                self.reset_timer();
                Poll::Ready(Some(Err(StreamError::Timeout)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.is_exhausted() {
            return (0, Some(0));
        }
        let (lower, _) = self.inner.size_hint();
        (lower, None)
    }

    fn is_exhausted(&self) -> bool {
        self.exhausted || self.inner.is_exhausted()
    }
}

#[cfg(test)]
#[path = "stream_inline_tests.rs"]
mod tests;
