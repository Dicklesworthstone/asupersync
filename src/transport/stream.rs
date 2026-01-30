//! Symbol stream traits and implementations.

use crate::cx::Cx;
use crate::security::authenticated::AuthenticatedSymbol;
use crate::time::{Sleep, TimeSource, WallClock};
use crate::transport::error::StreamError;
use crate::transport::{ChannelWaiter, SharedChannel, SymbolSet};
use crate::types::Time;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

fn wall_clock_now() -> Time {
    static CLOCK: OnceLock<WallClock> = OnceLock::new();
    CLOCK.get_or_init(WallClock::new).now()
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
        NextFuture { stream: self }
    }

    /// Collect all symbols into a SymbolSet.
    fn collect_to_set<'a>(&'a mut self, set: &'a mut SymbolSet) -> CollectToSetFuture<'a, Self>
    where
        Self: Unpin,
    {
        CollectToSetFuture { stream: self, set }
    }

    /// Map symbols through a function.
    fn map<F, T>(self, f: F) -> MapStream<Self, F>
    where
        Self: Sized,
        F: FnMut(AuthenticatedSymbol) -> T,
    {
        MapStream { inner: self, f }
    }

    /// Filter symbols.
    fn filter<F>(self, f: F) -> FilterStream<Self, F>
    where
        Self: Sized,
        F: FnMut(&AuthenticatedSymbol) -> bool,
    {
        FilterStream { inner: self, f }
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
        FilterStream { inner: self, f }
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
        NextWithCancelFuture { stream: self, cx }
    }
}

impl<S: SymbolStream + ?Sized> SymbolStreamExt for S {}

// ---- Futures ----

/// Future for `next()`.
pub struct NextFuture<'a, S: ?Sized> {
    stream: &'a mut S,
}

impl<S: SymbolStream + Unpin + ?Sized> Future for NextFuture<'_, S> {
    type Output = Option<Result<AuthenticatedSymbol, StreamError>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.stream).poll_next(cx)
    }
}

/// Future for `collect_to_set()`.
pub struct CollectToSetFuture<'a, S: ?Sized> {
    stream: &'a mut S,
    set: &'a mut SymbolSet,
}

impl<S: SymbolStream + Unpin + ?Sized> Future for CollectToSetFuture<'_, S> {
    type Output = Result<usize, StreamError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match Pin::new(&mut *self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(symbol))) => {
                    self.set.insert(symbol.into_symbol());
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(self.set.len())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Future for `next_with_cancel()`.
pub struct NextWithCancelFuture<'a, S: ?Sized> {
    stream: &'a mut S,
    cx: &'a Cx,
}

impl<S: SymbolStream + Unpin + ?Sized> Future for NextWithCancelFuture<'_, S> {
    type Output = Result<Option<AuthenticatedSymbol>, StreamError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cx.is_cancel_requested() {
            return Poll::Ready(Err(StreamError::Cancelled));
        }

        match Pin::new(&mut *self.stream).poll_next(cx) {
            Poll::Ready(Some(Ok(symbol))) => Poll::Ready(Ok(Some(symbol))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(err)),
            Poll::Ready(None) => Poll::Ready(Ok(None)),
            Poll::Pending => {
                if self.cx.is_cancel_requested() {
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
}

// MapStream is not a SymbolStream because it changes the type T.
// But SymbolStream forces Item = Result<AuthenticatedSymbol...
// So MapStream is only valid if T is Result<AuthenticatedSymbol...
// But generic map allows any T.
// The trait `SymbolStream` is specific to `AuthenticatedSymbol`.
// `map` in `SymbolStreamExt` returns `MapStream` which might NOT implement `SymbolStream`.
// It implements `futures::Stream` if I had it.
// But here `map` is only useful if it produces `AuthenticatedSymbol`.
// The description says: `fn map<F, T>(self, f: F) -> MapStream<Self, F>`.
// If `T` is not `AuthenticatedSymbol`, then `MapStream` cannot be `SymbolStream`.
// I will implement `SymbolStream` for `MapStream` ONLY IF `T` is `Result<AuthenticatedSymbol, StreamError>`.
// Wait, `SymbolStream` returns `Result`. `map` transforms `AuthenticatedSymbol`.
// If `f` returns `AuthenticatedSymbol`, then we can wrap it in `Ok`.
// Let's assume `map` transforms the *success* value.

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
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(s))) => Poll::Ready(Some(Ok((this.f)(s)))),
            other => other,
        }
    }
}

/// Stream that filters items.
pub struct FilterStream<S, F> {
    inner: S,
    f: F,
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
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(s))) => {
                    if (this.f)(&s) {
                        return Poll::Ready(Some(Ok(s)));
                    }
                    // Loop to next
                }
                other => return other,
            }
        }
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

impl SymbolStream for ChannelStream {
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let this = self.get_mut();
        let mut symbol = None;
        let mut closed = false;
        {
            let mut queue = this.shared.queue.lock().unwrap();
            if let Some(entry) = queue.pop_front() {
                symbol = Some(entry);
            } else if this.shared.closed.load(Ordering::SeqCst) {
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
                let mut wakers = this.shared.send_wakers.lock().unwrap();
                wakers.pop()
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
        // If the waker changes between polls, we accept the stale waker -
        // another waiter will be woken instead, which is harmless.
        let mut new_waiter = None;
        let mut closed = false;
        {
            let mut wakers = this.shared.recv_wakers.lock().unwrap();
            if this.shared.closed.load(Ordering::SeqCst) {
                closed = true;
            } else {
                match this.waiter.as_ref() {
                    Some(waiter) if !waiter.load(Ordering::Acquire) => {
                        // We were woken but no message yet - re-register
                        waiter.store(true, Ordering::Release);
                        wakers.push(ChannelWaiter {
                            waker: cx.waker().clone(),
                            queued: Arc::clone(waiter),
                        });
                    }
                    Some(_) => {} // Still queued, no need to re-register
                    None => {
                        // First time waiting - create new waiter
                        let waiter = Arc::new(AtomicBool::new(true));
                        wakers.push(ChannelWaiter {
                            waker: cx.waker().clone(),
                            queued: Arc::clone(&waiter),
                        });
                        new_waiter = Some(waiter);
                    }
                }
            }
        }
        if closed {
            return Poll::Ready(None);
        }
        if let Some(waiter) = new_waiter {
            this.waiter = Some(waiter);
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
}

impl<S> TimeoutStream<S> {
    /// Creates a timeout stream using wall-clock time.
    pub fn new(inner: S, duration: Duration) -> Self {
        Self::with_time_getter(inner, duration, wall_clock_now)
    }

    /// Creates a timeout stream using a custom time source.
    pub fn with_time_getter(inner: S, duration: Duration, time_getter: fn() -> Time) -> Self {
        let now = time_getter();
        let deadline = now.saturating_add_nanos(duration.as_nanos() as u64);
        let sleep = Sleep::with_time_getter(deadline, time_getter);
        Self {
            inner,
            duration,
            sleep,
            time_getter,
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
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(item)) => {
                self.reset_timer();
                return Poll::Ready(Some(item));
            }
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => {}
        }

        let now = (self.time_getter)();
        if self.sleep.poll_with_time(now).is_ready() {
            self.reset_timer();
            return Poll::Ready(Some(Err(StreamError::Timeout)));
        }

        Poll::Pending
    }
}
