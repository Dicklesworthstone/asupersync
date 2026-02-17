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

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
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

impl Drop for ChannelStream {
    fn drop(&mut self) {
        let Some(waiter) = self.waiter.as_ref() else {
            return;
        };

        waiter.store(false, Ordering::Release);
        let mut wakers = self.shared.recv_wakers.lock();
        wakers.retain(|entry| !Arc::ptr_eq(&entry.queued, waiter));
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
                let mut wakers = this.shared.send_wakers.lock();
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
        // If the same waiter is still queued, refresh its waker to avoid
        // stale wakeups after task context/executor migration.
        let mut new_waiter = None;
        let mut closed = false;
        {
            let mut wakers = this.shared.recv_wakers.lock();
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
                    Some(waiter) => {
                        if let Some(existing) = wakers
                            .iter_mut()
                            .find(|entry| Arc::ptr_eq(&entry.queued, waiter))
                        {
                            existing.waker.clone_from(cx.waker());
                        } else {
                            wakers.push(ChannelWaiter {
                                waker: cx.waker().clone(),
                                queued: Arc::clone(waiter),
                            });
                        }
                    }
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
            if !queue.is_empty() || this.shared.closed.load(Ordering::SeqCst) {
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
}

impl<S> TimeoutStream<S> {
    /// Creates a timeout stream using wall-clock time.
    pub fn new(inner: S, duration: Duration) -> Self {
        Self::with_time_getter(inner, duration, wall_clock_now)
    }

    /// Creates a timeout stream using a custom time source.
    pub fn with_time_getter(inner: S, duration: Duration, time_getter: fn() -> Time) -> Self {
        let now = time_getter();
        let deadline = now.saturating_add_nanos(duration_to_nanos(duration));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::authenticated::AuthenticatedSymbol;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::sink::SymbolSink;
    use crate::transport::{channel, SymbolStreamExt};
    use crate::types::{Symbol, SymbolId, SymbolKind};
    use futures_lite::future;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::task::{Wake, Waker};
    use std::thread;
    use std::time::Instant;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn create_symbol(esi: u32) -> AuthenticatedSymbol {
        let id = SymbolId::new_for_test(1, 0, esi);
        let symbol = Symbol::new(id, vec![esi as u8], SymbolKind::Source);
        let tag = AuthenticationTag::zero();
        AuthenticatedSymbol::new_verified(symbol, tag)
    }

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWake))
    }

    struct FlagWake {
        flag: Arc<AtomicBool>,
    }

    impl Wake for FlagWake {
        fn wake(self: Arc<Self>) {
            self.flag.store(true, Ordering::SeqCst);
        }
    }

    fn flagged_waker(flag: Arc<AtomicBool>) -> Waker {
        Waker::from(Arc::new(FlagWake { flag }))
    }

    struct PendingStream;

    impl SymbolStream for PendingStream {
        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            Poll::Pending
        }
    }

    struct ErrorStream {
        returned: bool,
    }

    impl ErrorStream {
        fn new() -> Self {
            Self { returned: false }
        }
    }

    impl SymbolStream for ErrorStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            if self.returned {
                Poll::Ready(None)
            } else {
                self.returned = true;
                Poll::Ready(Some(Err(StreamError::Reset)))
            }
        }
    }

    struct ExhaustedStream {
        items: Vec<AuthenticatedSymbol>,
        index: usize,
    }

    impl ExhaustedStream {
        fn new(items: Vec<AuthenticatedSymbol>) -> Self {
            Self { items, index: 0 }
        }
    }

    impl SymbolStream for ExhaustedStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            if self.index < self.items.len() {
                let item = self.items[self.index].clone();
                self.index += 1;
                Poll::Ready(Some(Ok(item)))
            } else {
                Poll::Ready(None)
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.items.len().saturating_sub(self.index);
            (remaining, Some(remaining))
        }

        fn is_exhausted(&self) -> bool {
            self.index >= self.items.len()
        }
    }

    #[test]
    fn test_next_future_yields_items_and_none() {
        init_test("test_next_future_yields_items_and_none");
        let mut stream = VecStream::new(vec![create_symbol(1), create_symbol(2)]);

        future::block_on(async {
            let first = stream.next().await.unwrap().unwrap();
            let second = stream.next().await.unwrap().unwrap();
            let done = stream.next().await;

            let first_esi = first.symbol().id().esi();
            let second_esi = second.symbol().id().esi();
            crate::assert_with_log!(first_esi == 1, "first esi", 1u32, first_esi);
            crate::assert_with_log!(second_esi == 2, "second esi", 2u32, second_esi);
            crate::assert_with_log!(done.is_none(), "stream done", true, done.is_none());
        });

        crate::test_complete!("test_next_future_yields_items_and_none");
    }

    #[test]
    fn test_collect_to_set_deduplicates_and_counts() {
        init_test("test_collect_to_set_deduplicates_and_counts");
        let mut stream = VecStream::new(vec![create_symbol(1), create_symbol(1), create_symbol(2)]);
        let mut set = SymbolSet::new();

        let count = future::block_on(async { stream.collect_to_set(&mut set).await.unwrap() });

        crate::assert_with_log!(count == 2, "unique count", 2usize, count);
        crate::assert_with_log!(set.len() == 2, "set size", 2usize, set.len());
        crate::test_complete!("test_collect_to_set_deduplicates_and_counts");
    }

    #[test]
    fn test_next_with_cancel_immediate() {
        init_test("test_next_with_cancel_immediate");
        let (_sink, mut stream) = channel(1);
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        future::block_on(async {
            let res = stream.next_with_cancel(&cx).await;
            crate::assert_with_log!(
                matches!(res, Err(StreamError::Cancelled)),
                "cancelled",
                true,
                matches!(res, Err(StreamError::Cancelled))
            );
        });

        crate::test_complete!("test_next_with_cancel_immediate");
    }

    #[test]
    fn test_next_with_cancel_after_pending() {
        init_test("test_next_with_cancel_after_pending");
        let mut stream = PendingStream;
        let cx: Cx = Cx::for_testing();

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut fut = stream.next_with_cancel(&cx);
        let mut fut = Pin::new(&mut fut);

        let first = fut.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first pending",
            true,
            matches!(first, Poll::Pending)
        );

        cx.set_cancel_requested(true);
        let second = fut.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(StreamError::Cancelled))),
            "cancel after pending",
            true,
            matches!(second, Poll::Ready(Err(StreamError::Cancelled)))
        );

        crate::test_complete!("test_next_with_cancel_after_pending");
    }

    #[test]
    fn test_map_stream_transforms_symbol() {
        init_test("test_map_stream_transforms_symbol");
        let stream = VecStream::new(vec![create_symbol(7)]);
        let mut mapped = stream.map(|symbol| {
            let id = symbol.symbol().id();
            let new_symbol = Symbol::new(id, vec![42u8], SymbolKind::Source);
            AuthenticatedSymbol::new_verified(new_symbol, AuthenticationTag::zero())
        });

        future::block_on(async {
            let item = mapped.next().await.unwrap().unwrap();
            crate::assert_with_log!(
                item.symbol().data() == [42u8],
                "mapped data",
                true,
                item.symbol().data() == [42u8]
            );
        });

        crate::test_complete!("test_map_stream_transforms_symbol");
    }

    #[test]
    fn test_filter_stream_skips_and_passes() {
        init_test("test_filter_stream_skips_and_passes");
        let stream = VecStream::new(vec![create_symbol(1), create_symbol(2), create_symbol(3)]);
        let mut filtered = stream.filter(|symbol| symbol.symbol().id().esi() % 2 == 1);

        future::block_on(async {
            let first = filtered.next().await.unwrap().unwrap();
            let second = filtered.next().await.unwrap().unwrap();
            let done = filtered.next().await;

            let first_esi = first.symbol().id().esi();
            let second_esi = second.symbol().id().esi();
            crate::assert_with_log!(first_esi == 1, "first", 1u32, first_esi);
            crate::assert_with_log!(second_esi == 3, "second", 3u32, second_esi);
            crate::assert_with_log!(done.is_none(), "done", true, done.is_none());
        });

        crate::test_complete!("test_filter_stream_skips_and_passes");
    }

    #[test]
    fn test_filter_stream_propagates_error() {
        init_test("test_filter_stream_propagates_error");
        let stream = ErrorStream::new();
        let mut filtered = stream.filter(|_symbol| true);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let poll = Pin::new(&mut filtered).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(poll, Poll::Ready(Some(Err(StreamError::Reset)))),
            "error propagates",
            true,
            matches!(poll, Poll::Ready(Some(Err(StreamError::Reset))))
        );

        crate::test_complete!("test_filter_stream_propagates_error");
    }

    #[test]
    fn test_merged_stream_round_robin_and_drop_exhausted() {
        init_test("test_merged_stream_round_robin_and_drop_exhausted");
        let s1 = VecStream::new(vec![create_symbol(1), create_symbol(3)]);
        let s2 = VecStream::new(vec![create_symbol(2), create_symbol(4)]);
        let mut merged = MergedStream::new(vec![s1, s2]);

        future::block_on(async {
            let mut out = Vec::new();
            while let Some(item) = merged.next().await {
                out.push(item.unwrap().symbol().id().esi());
            }
            crate::assert_with_log!(
                out == vec![1, 2, 3, 4],
                "merged order",
                true,
                out == vec![1, 2, 3, 4]
            );
        });

        crate::test_complete!("test_merged_stream_round_robin_and_drop_exhausted");
    }

    #[test]
    fn test_merged_stream_size_hint_and_is_exhausted() {
        init_test("test_merged_stream_size_hint_and_is_exhausted");
        let s1 = ExhaustedStream::new(vec![create_symbol(1), create_symbol(2)]);
        let s2 = ExhaustedStream::new(vec![create_symbol(3)]);
        let mut merged = MergedStream::new(vec![s1, s2]);

        let hint = merged.size_hint();
        crate::assert_with_log!(hint == (3, Some(3)), "size hint", (3, Some(3)), hint);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        while let Poll::Ready(Some(_)) = Pin::new(&mut merged).poll_next(&mut context) {}
        crate::assert_with_log!(
            merged.is_exhausted(),
            "exhausted",
            true,
            merged.is_exhausted()
        );

        crate::test_complete!("test_merged_stream_size_hint_and_is_exhausted");
    }

    #[test]
    fn test_channel_stream_registers_waiter_and_receives() {
        init_test("test_channel_stream_registers_waiter_and_receives");
        let shared = Arc::new(SharedChannel::new(1));
        let mut stream = ChannelStream::new(Arc::clone(&shared));
        let mut sink = crate::transport::sink::ChannelSink::new(shared);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "pending when empty",
            true,
            matches!(first, Poll::Pending)
        );
        let queued = stream
            .waiter
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));
        crate::assert_with_log!(queued, "waiter queued", true, queued);

        let symbol = create_symbol(9);
        let send = Pin::new(&mut sink).poll_send(&mut context, symbol);
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send ok",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let second = Pin::new(&mut stream).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(Ok(_)))),
            "receive after send",
            true,
            matches!(second, Poll::Ready(Some(Ok(_))))
        );
        let queued_after = stream
            .waiter
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));
        crate::assert_with_log!(!queued_after, "waiter cleared", false, queued_after);

        crate::test_complete!("test_channel_stream_registers_waiter_and_receives");
    }

    #[test]
    fn test_channel_stream_drop_removes_queued_waiter() {
        init_test("test_channel_stream_drop_removes_queued_waiter");
        let shared = Arc::new(SharedChannel::new(1));
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut stream = ChannelStream::new(Arc::clone(&shared));

        let pending = Pin::new(&mut stream).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(pending, Poll::Pending),
            "pending when queue empty",
            true,
            matches!(pending, Poll::Pending)
        );
        let queued_before = shared.recv_wakers.lock().len();
        crate::assert_with_log!(
            queued_before == 1,
            "one waiter registered",
            1usize,
            queued_before
        );

        drop(stream);

        let queued_after = shared.recv_wakers.lock().len();
        crate::assert_with_log!(
            queued_after == 0,
            "queued waiter removed on drop",
            0usize,
            queued_after
        );
        crate::test_complete!("test_channel_stream_drop_removes_queued_waiter");
    }

    #[test]
    fn test_channel_stream_refreshes_queued_waker_on_repoll() {
        init_test("test_channel_stream_refreshes_queued_waker_on_repoll");
        let (mut sink, mut stream) = channel(1);

        let first_flag = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::new(AtomicBool::new(false));
        let first_waker = flagged_waker(Arc::clone(&first_flag));
        let second_waker = flagged_waker(Arc::clone(&second_flag));
        let mut first_context = Context::from_waker(&first_waker);
        let mut second_context = Context::from_waker(&second_waker);

        let first_pending = Pin::new(&mut stream).poll_next(&mut first_context);
        crate::assert_with_log!(
            matches!(first_pending, Poll::Pending),
            "first poll pending",
            true,
            matches!(first_pending, Poll::Pending)
        );

        let second_pending = Pin::new(&mut stream).poll_next(&mut second_context);
        crate::assert_with_log!(
            matches!(second_pending, Poll::Pending),
            "second poll pending",
            true,
            matches!(second_pending, Poll::Pending)
        );

        let ready_waker = noop_waker();
        let mut ready_context = Context::from_waker(&ready_waker);
        let sent = Pin::new(&mut sink).poll_send(&mut ready_context, create_symbol(77));
        crate::assert_with_log!(
            matches!(sent, Poll::Ready(Ok(()))),
            "send wakes waiting stream",
            true,
            matches!(sent, Poll::Ready(Ok(())))
        );

        let first_woke = first_flag.load(Ordering::Acquire);
        let second_woke = second_flag.load(Ordering::Acquire);
        crate::assert_with_log!(!first_woke, "stale waker not used", false, first_woke);
        crate::assert_with_log!(second_woke, "latest waker used", true, second_woke);
        crate::test_complete!("test_channel_stream_refreshes_queued_waker_on_repoll");
    }

    #[test]
    fn test_timeout_stream_triggers_and_resets() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn fake_now() -> Time {
            Time::from_nanos(NOW.load(Ordering::SeqCst))
        }

        init_test("test_timeout_stream_triggers_and_resets");
        let inner = PendingStream;
        let mut timed = TimeoutStream::with_time_getter(inner, Duration::from_nanos(10), fake_now);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        NOW.store(0, Ordering::SeqCst);
        let first = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "pending before timeout",
            true,
            matches!(first, Poll::Pending)
        );

        NOW.store(10, Ordering::SeqCst);
        let second = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(Err(StreamError::Timeout)))),
            "timeout",
            true,
            matches!(second, Poll::Ready(Some(Err(StreamError::Timeout))))
        );

        NOW.store(10, Ordering::SeqCst);
        let third = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(third, Poll::Pending),
            "reset after timeout",
            true,
            matches!(third, Poll::Pending)
        );

        crate::test_complete!("test_timeout_stream_triggers_and_resets");
    }

    #[test]
    fn test_timeout_stream_resets_on_item() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn fake_now() -> Time {
            Time::from_nanos(NOW.load(Ordering::SeqCst))
        }

        struct OneItemThenPending {
            item: Option<AuthenticatedSymbol>,
        }

        impl SymbolStream for OneItemThenPending {
            fn poll_next(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
                self.item
                    .take()
                    .map_or(Poll::Pending, |item| Poll::Ready(Some(Ok(item))))
            }
        }

        init_test("test_timeout_stream_resets_on_item");
        let inner = OneItemThenPending {
            item: Some(create_symbol(5)),
        };
        let mut timed = TimeoutStream::with_time_getter(inner, Duration::from_nanos(10), fake_now);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        NOW.store(0, Ordering::SeqCst);
        let first = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Some(Ok(_)))),
            "item received",
            true,
            matches!(first, Poll::Ready(Some(Ok(_))))
        );

        NOW.store(5, Ordering::SeqCst);
        let second = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Pending),
            "pending before new deadline",
            true,
            matches!(second, Poll::Pending)
        );

        crate::test_complete!("test_timeout_stream_resets_on_item");
    }

    #[test]
    fn test_timeout_stream_duration_max_saturates_deadline() {
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn fake_now() -> Time {
            Time::from_nanos(NOW.load(Ordering::SeqCst))
        }

        init_test("test_timeout_stream_duration_max_saturates_deadline");
        NOW.store(123, Ordering::SeqCst);

        let inner = PendingStream;
        let mut timed = TimeoutStream::with_time_getter(inner, Duration::MAX, fake_now);
        crate::assert_with_log!(
            timed.sleep.deadline() == Time::MAX,
            "deadline saturates to max",
            Time::MAX,
            timed.sleep.deadline()
        );

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let before_max = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(before_max, Poll::Pending),
            "pending before max time",
            true,
            matches!(before_max, Poll::Pending)
        );

        NOW.store(u64::MAX, Ordering::SeqCst);
        let at_max = Pin::new(&mut timed).poll_next(&mut context);
        crate::assert_with_log!(
            matches!(at_max, Poll::Ready(Some(Err(StreamError::Timeout)))),
            "times out at max deadline",
            true,
            matches!(at_max, Poll::Ready(Some(Err(StreamError::Timeout))))
        );

        crate::test_complete!("test_timeout_stream_duration_max_saturates_deadline");
    }

    /// Regression test for lost-wakeup race in ChannelStream::poll_next.
    ///
    /// A sender may push between the queue check and waiter registration,
    /// finding no recv_waker to wake. The re-check after registration
    /// closes this race by self-waking when items are found.
    #[test]
    fn test_channel_stream_no_lost_wakeup_concurrent() {
        init_test("test_channel_stream_no_lost_wakeup_concurrent");

        // Run many iterations to maximise the chance of hitting the race window.
        for iteration in 0..200 {
            let (mut sink, mut stream) = channel(1);

            let send_handle = thread::spawn(move || {
                let waker = noop_waker();
                let mut cx = Context::from_waker(&waker);
                let _ = Pin::new(&mut sink).poll_send(&mut cx, create_symbol(iteration));
            });

            let recv_handle = thread::spawn(move || {
                let flag = Arc::new(AtomicBool::new(false));
                let waker = flagged_waker(Arc::clone(&flag));
                let mut cx = Context::from_waker(&waker);
                let start = Instant::now();

                loop {
                    match Pin::new(&mut stream).poll_next(&mut cx) {
                        Poll::Ready(Some(Ok(_))) => return true,
                        Poll::Ready(Some(Err(_)) | None) => return false,
                        Poll::Pending => {
                            if start.elapsed() > Duration::from_millis(500) {
                                return false; // Timeout — lost wakeup
                            }
                            // If the waker was invoked, repoll immediately.
                            if flag.swap(false, Ordering::AcqRel) {
                                continue;
                            }
                            thread::yield_now();
                        }
                    }
                }
            });

            send_handle.join().unwrap();
            let received = recv_handle.join().unwrap();
            crate::assert_with_log!(received, "no lost wakeup", true, received);
        }

        crate::test_complete!("test_channel_stream_no_lost_wakeup_concurrent");
    }

    // ── Audit regression tests (asupersync-10x0x.82) ─────────────────────

    #[test]
    fn merged_stream_removal_adjusts_current_when_removing_before() {
        init_test("merged_stream_removal_adjusts_current_when_removing_before");
        // Streams: [done, A, B]. current = 2 (starts at B).
        // Removing done at idx 0 should adjust current from 2 to 1,
        // so B (now at idx 1) is still reached next round.
        let done_stream = VecStream::new(vec![]); // exhausted immediately
        let s_a = VecStream::new(vec![create_symbol(10)]);
        let s_b = VecStream::new(vec![create_symbol(20)]);
        let mut merged = MergedStream::new(vec![done_stream, s_a, s_b]);
        merged.current = 2; // start at B

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll: starts at idx 2 (B) → Ready(Ok(20)).
        // Round-robin advances to next.
        let first = Pin::new(&mut merged).poll_next(&mut cx);
        let esi = match &first {
            Poll::Ready(Some(Ok(sym))) => sym.symbol().id().esi(),
            _ => panic!("expected Ready(Some(Ok))"),
        };
        crate::assert_with_log!(esi == 20, "B dispatched first", 20u32, esi);

        // Second poll: should visit the done stream (removed) and then A.
        let second = Pin::new(&mut merged).poll_next(&mut cx);
        let esi2 = match &second {
            Poll::Ready(Some(Ok(sym))) => sym.symbol().id().esi(),
            _ => panic!("expected Ready(Some(Ok))"),
        };
        crate::assert_with_log!(esi2 == 10, "A dispatched after removal", 10u32, esi2);

        // Third: all exhausted.
        let third = Pin::new(&mut merged).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(third, Poll::Ready(None)),
            "all exhausted",
            true,
            matches!(third, Poll::Ready(None))
        );
        crate::test_complete!("merged_stream_removal_adjusts_current_when_removing_before");
    }

    #[test]
    fn channel_stream_closed_after_waiter_registration() {
        init_test("channel_stream_closed_after_waiter_registration");
        let shared = Arc::new(SharedChannel::new(1));
        let mut stream = ChannelStream::new(Arc::clone(&shared));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll registers waiter.
        let first = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "pending on empty",
            true,
            matches!(first, Poll::Pending)
        );

        // Close channel — should wake and detect closed on next poll.
        shared.close();
        let second = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(None)),
            "returns None after close",
            true,
            matches!(second, Poll::Ready(None))
        );
        crate::test_complete!("channel_stream_closed_after_waiter_registration");
    }

    /// Stream that produces 1 good item then an error.
    struct GoodThenError(bool);
    impl SymbolStream for GoodThenError {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            if self.0 {
                Poll::Ready(None)
            } else {
                self.0 = true;
                Poll::Ready(Some(Err(StreamError::Reset)))
            }
        }
    }

    #[test]
    fn collect_to_set_propagates_error_stops_early() {
        init_test("collect_to_set_propagates_error_stops_early");
        let mut stream = GoodThenError(false);
        let mut set = SymbolSet::new();
        let result = future::block_on(async { stream.collect_to_set(&mut set).await });
        crate::assert_with_log!(result.is_err(), "error propagated", true, result.is_err());
        crate::assert_with_log!(set.is_empty(), "set empty on error", true, set.is_empty());
        crate::test_complete!("collect_to_set_propagates_error_stops_early");
    }

    #[test]
    fn vec_stream_size_hint_tracks_remaining() {
        init_test("vec_stream_size_hint_tracks_remaining");
        let mut stream = VecStream::new(vec![create_symbol(1), create_symbol(2), create_symbol(3)]);

        let hint = stream.size_hint();
        crate::assert_with_log!(hint == (3, Some(3)), "initial hint", (3, Some(3)), hint);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = Pin::new(&mut stream).poll_next(&mut cx); // consume one

        let hint2 = stream.size_hint();
        crate::assert_with_log!(hint2 == (2, Some(2)), "after one", (2, Some(2)), hint2);
        crate::test_complete!("vec_stream_size_hint_tracks_remaining");
    }
}
