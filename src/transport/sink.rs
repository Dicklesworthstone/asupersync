//! Symbol sink traits and implementations.

use crate::security::authenticated::AuthenticatedSymbol;
use crate::transport::error::SinkError;
use crate::transport::{ChannelWaiter, SharedChannel};
use smallvec::SmallVec;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

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

/// A sink for outgoing symbols.
pub trait SymbolSink: Send + Unpin {
    /// Send a symbol.
    fn poll_send(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>>;

    /// Flush any buffered symbols.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>>;

    /// Close the sink.
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>>;

    /// Check if sink is ready to accept more symbols.
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>>;
}

/// Extension methods for SymbolSink.
pub trait SymbolSinkExt: SymbolSink {
    /// Send a symbol.
    fn send(&mut self, symbol: AuthenticatedSymbol) -> SendFuture<'_, Self>
    where
        Self: Unpin,
    {
        SendFuture {
            sink: self,
            symbol: Some(symbol),
            completed: false,
        }
    }

    /// Send all symbols from an iterator.
    fn send_all<I>(&mut self, symbols: I) -> SendAllFuture<'_, Self, I::IntoIter>
    where
        Self: Unpin,
        I: IntoIterator<Item = AuthenticatedSymbol>,
    {
        SendAllFuture {
            sink: self,
            iter: symbols.into_iter(),
            buffered: None,
            count: 0,
            completed: false,
            iter_exhausted: false,
        }
    }

    /// Flush buffered symbols.
    fn flush(&mut self) -> FlushFuture<'_, Self>
    where
        Self: Unpin,
    {
        FlushFuture {
            sink: self,
            completed: false,
        }
    }

    /// Close the sink.
    fn close(&mut self) -> CloseFuture<'_, Self>
    where
        Self: Unpin,
    {
        CloseFuture {
            sink: self,
            completed: false,
        }
    }

    /// Buffer symbols for batch sending.
    fn buffer(self, capacity: usize) -> BufferedSink<Self>
    where
        Self: Sized,
    {
        BufferedSink::new(self, capacity)
    }
}

impl<S: SymbolSink + ?Sized> SymbolSinkExt for S {}

// ---- Futures ----

/// Cooperative budget for successful sends drained in a single poll.
///
/// Without this cap, `send_all()` can monopolize one executor turn when both
/// the iterator and sink stay always-ready for long runs.
const SEND_ALL_COOPERATIVE_BUDGET: usize = 1024;

/// Future for `send()`.
pub struct SendFuture<'a, S: ?Sized> {
    sink: &'a mut S,
    symbol: Option<AuthenticatedSymbol>,
    completed: bool,
}

impl<S: SymbolSink + Unpin + ?Sized> Future for SendFuture<'_, S> {
    type Output = Result<(), SinkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if this.completed {
            return Poll::Ready(Err(SinkError::PolledAfterCompletion));
        }

        if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
            this.completed = true;
            return Poll::Ready(Err(SinkError::Io {
                source: std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"),
            }));
        }

        // First wait for ready
        match Pin::new(&mut *this.sink).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                this.completed = true;
                return Poll::Ready(Err(e));
            }
            Poll::Pending => return Poll::Pending,
        }

        // Then send
        if let Some(symbol) = this.symbol.take() {
            match Pin::new(&mut *this.sink).poll_send(cx, symbol.clone()) {
                Poll::Ready(Ok(())) => {
                    this.completed = true;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => {
                    this.completed = true;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => {
                    this.symbol = Some(symbol);
                    Poll::Pending
                }
            }
        } else {
            this.completed = true;
            Poll::Ready(Err(SinkError::PolledAfterCompletion))
        }
    }
}

/// Future for `send_all()`.
pub struct SendAllFuture<'a, S: ?Sized, I> {
    sink: &'a mut S,
    iter: I,
    buffered: Option<AuthenticatedSymbol>,
    count: usize,
    completed: bool,
    iter_exhausted: bool,
}

impl<S, I> Future for SendAllFuture<'_, S, I>
where
    S: SymbolSink + Unpin + ?Sized,
    I: Iterator<Item = AuthenticatedSymbol> + Unpin,
{
    type Output = Result<usize, SinkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(SinkError::PolledAfterCompletion));
        }

        if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
            self.completed = true;
            return Poll::Ready(Err(SinkError::Io {
                source: std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"),
            }));
        }

        let mut sent_this_poll = 0usize;
        loop {
            // Try to send buffered item
            if let Some(symbol) = self.buffered.take() {
                match Pin::new(&mut *self.sink).poll_ready(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => {
                        self.completed = true;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        self.buffered = Some(symbol);
                        return Poll::Pending;
                    }
                }
                match Pin::new(&mut *self.sink).poll_send(cx, symbol.clone()) {
                    Poll::Ready(Ok(())) => {
                        self.count += 1;
                        sent_this_poll += 1;
                        if sent_this_poll >= SEND_ALL_COOPERATIVE_BUDGET {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        self.completed = true;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        self.buffered = Some(symbol);
                        return Poll::Pending;
                    }
                }
            }

            if self.iter_exhausted {
                // Flush
                match Pin::new(&mut *self.sink).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        self.completed = true;
                        return Poll::Ready(Ok(self.count));
                    }
                    Poll::Ready(Err(e)) => {
                        self.completed = true;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Get next
            match self.iter.next() {
                Some(symbol) => self.buffered = Some(symbol),
                None => {
                    self.iter_exhausted = true;
                }
            }
        }
    }
}

/// Future for `flush()`.
pub struct FlushFuture<'a, S: ?Sized> {
    sink: &'a mut S,
    completed: bool,
}

impl<S: SymbolSink + Unpin + ?Sized> Future for FlushFuture<'_, S> {
    type Output = Result<(), SinkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(SinkError::PolledAfterCompletion));
        }

        if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
            self.completed = true;
            return Poll::Ready(Err(SinkError::Io {
                source: std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"),
            }));
        }

        match Pin::new(&mut *self.sink).poll_flush(cx) {
            Poll::Ready(result) => {
                self.completed = true;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Future for `close()`.
pub struct CloseFuture<'a, S: ?Sized> {
    sink: &'a mut S,
    completed: bool,
}

impl<S: SymbolSink + Unpin + ?Sized> Future for CloseFuture<'_, S> {
    type Output = Result<(), SinkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(Err(SinkError::PolledAfterCompletion));
        }

        if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
            self.completed = true;
            return Poll::Ready(Err(SinkError::Io {
                source: std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"),
            }));
        }

        match Pin::new(&mut *self.sink).poll_close(cx) {
            Poll::Ready(result) => {
                self.completed = true;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---- Adapters ----

use std::collections::VecDeque;

/// A sink that buffers symbols.
pub struct BufferedSink<S> {
    inner: S,
    buffer: VecDeque<AuthenticatedSymbol>,
    /// Symbols staged after direct `poll_send()` calls outrun the local buffer.
    ///
    /// This queue preserves FIFO order for callers that drive `poll_send()`
    /// directly while a previous full-buffer flush is still draining.
    staged_symbols: VecDeque<AuthenticatedSymbol>,
    capacity: usize,
}

impl<S> BufferedSink<S> {
    /// Creates a buffered sink with the given capacity.
    pub fn new(inner: S, capacity: usize) -> Self {
        Self {
            inner,
            buffer: VecDeque::with_capacity(capacity),
            staged_symbols: VecDeque::new(),
            capacity,
        }
    }
}

impl<S: SymbolSink + Unpin> BufferedSink<S> {
    /// Detect terminal inner-sink failures without collapsing valid buffering.
    ///
    /// When the local buffer still has capacity, `BufferedSink` should keep
    /// accepting items through transient inner backpressure, but it must fail
    /// closed if the inner sink has already entered a terminal error state.
    fn poll_inner_terminal_error(&mut self, cx: &mut Context<'_>) -> Option<SinkError> {
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Err(err)) => Some(err),
            Poll::Ready(Ok(())) | Poll::Pending => None,
        }
    }
}

impl<S: SymbolSink + Unpin> SymbolSink for BufferedSink<S> {
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        if this.buffer.len() < this.capacity && this.staged_symbols.is_empty() {
            this.poll_inner_terminal_error(cx)
                .map_or(Poll::Ready(Ok(())), |err| Poll::Ready(Err(err)))
        } else {
            // Try to flush
            Pin::new(this).poll_flush(cx)
        }
    }

    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
        let this = self.as_mut().get_mut();

        // Reject sends immediately if the inner sink is in a terminal error state,
        // even if we have local buffer capacity.
        if let Some(err) = this.poll_inner_terminal_error(cx) {
            return Poll::Ready(Err(err));
        }

        if this.buffer.len() >= this.capacity || !this.staged_symbols.is_empty() {
            // Try to flush existing backlog to make room. This also registers
            // the waker if the inner sink is blocked.
            match Pin::new(&mut *this).poll_flush(cx) {
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                _ => {} // Pending or Ready(Ok(()))
            }
        }

        if this.buffer.len() < this.capacity && this.staged_symbols.is_empty() {
            this.buffer.push_back(symbol);
            return Poll::Ready(Ok(()));
        }

        // We couldn't clear the buffer, so we must stage it.
        if this.staged_symbols.len() >= this.capacity.saturating_mul(2).max(16) {
            // Staged backlog is full. Since we already called poll_flush,
            // the waker is registered.
            return Poll::Pending;
        }

        this.staged_symbols.push_back(symbol);
        
        // We accepted the symbol into our backlog. Return Ok so callers do
        // not retry and cause duplicate delivery.
        Poll::Ready(Ok(()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.as_mut().get_mut();

        loop {
            while this.buffer.len() < this.capacity {
                let Some(symbol) = this.staged_symbols.pop_front() else {
                    break;
                };
                this.buffer.push_back(symbol);
            }

            if this.buffer.is_empty() {
                break;
            }

            // Check if inner is ready
            match Pin::new(&mut this.inner).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            let symbol = match this.buffer.front() {
                Some(symbol) => symbol.clone(),
                None => break,
            };
            match Pin::new(&mut this.inner).poll_send(cx, symbol) {
                Poll::Ready(Ok(())) => {
                    this.buffer.pop_front();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }

        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.as_mut().get_mut();
        // Flush first
        match Pin::new(this).poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

// ---- Implementations ----

/// In-memory channel sink.
pub struct ChannelSink {
    shared: Arc<SharedChannel>,
    /// Tracks if we already have a waiter registered to prevent unbounded queue growth.
    waiter: Option<Arc<AtomicBool>>,
}

impl ChannelSink {
    pub(crate) fn new(shared: Arc<SharedChannel>) -> Self {
        Self {
            shared,
            waiter: None,
        }
    }
}

impl Drop for ChannelSink {
    fn drop(&mut self) {
        let Some(waiter) = self.waiter.as_ref() else {
            return;
        };

        waiter.store(false, Ordering::Release);
        {
            let mut wakers = self.shared.send_wakers.lock();
            wakers.retain(|entry| !Arc::ptr_eq(&entry.queued, waiter));
        }

        // Pass the baton: if we were woken but dropped before consuming the
        // capacity, we must wake the next waiter to prevent a lost wakeup.
        let has_capacity = {
            let queue = self.shared.queue.lock();
            queue.len() < self.shared.capacity && !self.shared.closed.load(Ordering::Acquire)
        };

        if has_capacity {
            let next_waiter = {
                let mut wakers = self.shared.send_wakers.lock();
                pop_next_queued_waiter(&mut wakers)
            };
            if let Some(w) = next_waiter {
                w.queued.store(false, Ordering::Release);
                w.waker.wake();
            }
        }
    }
}

impl SymbolSink for ChannelSink {
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        let queue = this.shared.queue.lock();

        if this.shared.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(SinkError::Closed));
        }

        if queue.len() < this.shared.capacity {
            // Mark as no longer queued if we had a waiter
            if let Some(waiter) = this.waiter.as_ref() {
                waiter.store(false, Ordering::Release);
            }
            Poll::Ready(Ok(()))
        } else {
            drop(queue); // Release queue lock before acquiring wakers lock
            if this.shared.closed.load(Ordering::Acquire) {
                return Poll::Ready(Err(SinkError::Closed));
            }

            // Only register waiter once to prevent unbounded queue growth.
            // If the same waiter is still queued, refresh its waker to avoid
            // stale wakeups after task context/executor migration.
            let mut new_waiter = None;
            let mut closed = false;
            {
                let mut wakers = this.shared.send_wakers.lock();
                if this.shared.closed.load(Ordering::Acquire) {
                    closed = true;
                } else {
                    match this.waiter.as_ref() {
                        Some(waiter) if !waiter.load(Ordering::Acquire) => {
                            // We were woken but capacity isn't available yet - re-register
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
                return Poll::Ready(Err(SinkError::Closed));
            }
            if let Some(waiter) = new_waiter {
                this.waiter = Some(waiter);
            }

            // Re-check the queue after waiter registration to close a
            // lost-wakeup race: a receiver may pop between our capacity check
            // and waiter registration, finding no send_waker to wake.
            {
                let queue = this.shared.queue.lock();
                if queue.len() < this.shared.capacity || this.shared.closed.load(Ordering::Acquire)
                {
                    drop(queue);
                    cx.waker().wake_by_ref();
                }
            }

            Poll::Pending
        }
    }

    fn poll_send(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        {
            let mut queue = this.shared.queue.lock();

            if this.shared.closed.load(Ordering::Acquire) {
                return Poll::Ready(Err(SinkError::Closed));
            }

            // We assume poll_ready checked capacity, but we check again for safety
            if queue.len() >= this.shared.capacity {
                return Poll::Ready(Err(SinkError::BufferFull));
            }

            queue.push_back(symbol);
        }

        // Wake receiver.
        let waiter = {
            let mut wakers = this.shared.recv_wakers.lock();
            pop_next_queued_waiter(&mut wakers)
        };
        if let Some(w) = waiter {
            w.queued.store(false, Ordering::Release);
            w.waker.wake();
        }

        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        self.shared.close();
        Poll::Ready(Ok(()))
    }
}

/// Sink that collects symbols into a Vec.
pub struct CollectingSink {
    symbols: Vec<AuthenticatedSymbol>,
}

impl CollectingSink {
    /// Creates an empty collecting sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    /// Returns the collected symbols.
    #[must_use]
    pub fn symbols(&self) -> &[AuthenticatedSymbol] {
        &self.symbols
    }

    /// Consumes the sink and returns the collected symbols.
    #[must_use]
    pub fn into_symbols(self) -> Vec<AuthenticatedSymbol> {
        self.symbols
    }
}

impl Default for CollectingSink {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolSink for CollectingSink {
    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_send(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
        self.symbols.push(symbol);
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::authenticated::AuthenticatedSymbol;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::SharedChannel;
    use crate::transport::channel;
    use crate::transport::stream::SymbolStream;
    use crate::transport::stream::SymbolStreamExt;
    use crate::types::{Symbol, SymbolId, SymbolKind};
    use futures_lite::future;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

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

    #[allow(clippy::struct_excessive_bools)]
    struct TrackingSinkState {
        ready_after: usize,
        ready_polls: usize,
        send_pending_once: bool,
        send_pending_done: bool,
        send_error_once: bool,
        sent: Vec<AuthenticatedSymbol>,
        flush_count: usize,
        closed: bool,
    }

    impl TrackingSinkState {
        fn new() -> Self {
            Self {
                ready_after: 0,
                ready_polls: 0,
                send_pending_once: false,
                send_pending_done: false,
                send_error_once: false,
                sent: Vec::new(),
                flush_count: 0,
                closed: false,
            }
        }
    }

    #[derive(Clone)]
    struct TrackingSink {
        state: Arc<Mutex<TrackingSinkState>>,
    }

    impl TrackingSink {
        fn new(state: TrackingSinkState) -> Self {
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn state(&self) -> Arc<Mutex<TrackingSinkState>> {
            Arc::clone(&self.state)
        }
    }

    impl SymbolSink for TrackingSink {
        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            if state.closed {
                drop(state);
                return Poll::Ready(Err(SinkError::Closed));
            }
            if state.ready_polls < state.ready_after {
                state.ready_polls += 1;
                drop(state);
                return Poll::Pending;
            }
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            if state.closed {
                drop(state);
                return Poll::Ready(Err(SinkError::Closed));
            }
            if state.send_error_once {
                state.send_error_once = false;
                drop(state);
                return Poll::Ready(Err(SinkError::SendFailed {
                    reason: "send failed".to_string(),
                }));
            }
            if state.send_pending_once && !state.send_pending_done {
                state.send_pending_done = true;
                drop(state);
                return Poll::Pending;
            }
            state.sent.push(symbol);
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            if state.closed {
                drop(state);
                return Poll::Ready(Err(SinkError::Closed));
            }
            state.flush_count += 1;
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            state.closed = true;
            drop(state);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct SequencedSendSinkState {
        send_calls: usize,
        pending_send_call: usize,
        sent: Vec<AuthenticatedSymbol>,
        flush_count: usize,
    }

    #[derive(Clone)]
    struct SequencedSendSink {
        state: Arc<Mutex<SequencedSendSinkState>>,
    }

    impl SequencedSendSink {
        fn new(pending_send_call: usize) -> Self {
            Self {
                state: Arc::new(Mutex::new(SequencedSendSinkState {
                    pending_send_call,
                    ..SequencedSendSinkState::default()
                })),
            }
        }

        fn state(&self) -> Arc<Mutex<SequencedSendSinkState>> {
            Arc::clone(&self.state)
        }
    }

    impl SymbolSink for SequencedSendSink {
        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            state.send_calls = state.send_calls.saturating_add(1);
            if state.pending_send_call != 0 && state.send_calls == state.pending_send_call {
                return Poll::Pending;
            }
            state.sent.push(symbol);
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock();
            state.flush_count = state.flush_count.saturating_add(1);
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn test_send_future_pending_then_ready() {
        init_test("test_send_future_pending_then_ready");
        let mut sink = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.ready_after = 1;
            state
        });

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut fut = sink.send(create_symbol(1));
        let mut fut = Pin::new(&mut fut);

        let first = fut.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "pending",
            true,
            matches!(first, Poll::Pending)
        );

        let second = fut.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Ok(()))),
            "ready",
            true,
            matches!(second, Poll::Ready(Ok(())))
        );

        let sent_len = {
            let state = sink.state.lock();
            state.sent.len()
        };
        crate::assert_with_log!(sent_len == 1, "sent", 1usize, sent_len);
        crate::test_complete!("test_send_future_pending_then_ready");
    }

    #[test]
    fn test_send_future_propagates_send_error() {
        init_test("test_send_future_propagates_send_error");
        let mut sink = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.send_error_once = true;
            state
        });

        let res = future::block_on(async { sink.send(create_symbol(2)).await });
        crate::assert_with_log!(
            matches!(res, Err(SinkError::SendFailed { .. })),
            "send failed",
            true,
            matches!(res, Err(SinkError::SendFailed { .. }))
        );

        let sent_empty = {
            let state = sink.state.lock();
            state.sent.is_empty()
        };
        crate::assert_with_log!(sent_empty, "no sent", true, sent_empty);
        crate::test_complete!("test_send_future_propagates_send_error");
    }

    #[test]
    fn test_send_future_repoll_after_completion_fails_closed() {
        init_test("test_send_future_repoll_after_completion_fails_closed");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = sink.send(create_symbol(44));
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first send completes",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );

        let second = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion))),
            "second poll fails closed",
            true,
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion)))
        );

        let sent_len = {
            let state = sink.state.lock();
            state.sent.len()
        };
        crate::assert_with_log!(sent_len == 1, "symbol sent once", 1usize, sent_len);
        crate::test_complete!("test_send_future_repoll_after_completion_fails_closed");
    }

    #[test]
    fn test_send_all_counts_and_flushes() {
        init_test("test_send_all_counts_and_flushes");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let symbols = vec![create_symbol(1), create_symbol(2), create_symbol(3)];

        let count = future::block_on(async { sink.send_all(symbols).await.unwrap() });
        let (sent_len, flush_count) = {
            let state = sink.state.lock();
            (state.sent.len(), state.flush_count)
        };

        crate::assert_with_log!(count == 3, "count", 3usize, count);
        crate::assert_with_log!(sent_len == 3, "sent", 3usize, sent_len);
        crate::assert_with_log!(flush_count == 1, "flush count", 1usize, flush_count);
        crate::test_complete!("test_send_all_counts_and_flushes");
    }

    #[test]
    fn test_send_all_yields_after_budget_on_always_ready_sink() {
        init_test("test_send_all_yields_after_budget_on_always_ready_sink");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let state = sink.state();
        let symbols = (0..(SEND_ALL_COOPERATIVE_BUDGET as u32 + 5))
            .map(create_symbol)
            .collect::<Vec<_>>();
        let woke = Arc::new(AtomicBool::new(false));
        let waker = flagged_waker(woke.clone());
        let mut context = Context::from_waker(&waker);
        let mut future = sink.send_all(symbols);
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll yields cooperatively",
            "Poll::Pending",
            first
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "cooperative yield self-wakes",
            true,
            woke.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            future.count == SEND_ALL_COOPERATIVE_BUDGET,
            "budgeted sends counted before yielding",
            SEND_ALL_COOPERATIVE_BUDGET,
            future.count
        );
        let (sent_len, flush_count) = {
            let state = state.lock();
            (state.sent.len(), state.flush_count)
        };
        crate::assert_with_log!(
            sent_len == SEND_ALL_COOPERATIVE_BUDGET,
            "sink observed only budgeted sends on first poll",
            SEND_ALL_COOPERATIVE_BUDGET,
            sent_len
        );
        crate::assert_with_log!(
            flush_count == 0,
            "flush deferred until iterator drains",
            0usize,
            flush_count
        );

        let second = future.as_mut().poll(&mut context);
        let second_total = match second {
            Poll::Ready(Ok(total)) => Some(total),
            _ => None,
        };
        crate::assert_with_log!(
            second_total == Some(SEND_ALL_COOPERATIVE_BUDGET + 5),
            "second poll completes remaining sends",
            Some(SEND_ALL_COOPERATIVE_BUDGET + 5),
            second_total
        );
        let (sent_len, flush_count) = {
            let state = state.lock();
            (state.sent.len(), state.flush_count)
        };
        crate::assert_with_log!(
            sent_len == SEND_ALL_COOPERATIVE_BUDGET + 5,
            "all symbols were eventually sent",
            SEND_ALL_COOPERATIVE_BUDGET + 5,
            sent_len
        );
        crate::assert_with_log!(
            flush_count == 1,
            "final completion still flushes exactly once",
            1usize,
            flush_count
        );
        crate::test_complete!("test_send_all_yields_after_budget_on_always_ready_sink");
    }

    #[test]
    fn test_send_all_repoll_after_completion_fails_closed() {
        init_test("test_send_all_repoll_after_completion_fails_closed");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = sink.send_all(vec![create_symbol(8), create_symbol(9)]);
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(2))),
            "first poll sends all",
            true,
            matches!(first, Poll::Ready(Ok(2)))
        );

        let second = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion))),
            "second poll fails closed",
            true,
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion)))
        );

        let (sent_len, flush_count) = {
            let state = sink.state.lock();
            (state.sent.len(), state.flush_count)
        };
        crate::assert_with_log!(sent_len == 2, "symbols sent once", 2usize, sent_len);
        crate::assert_with_log!(flush_count == 1, "flush ran once", 1usize, flush_count);
        crate::test_complete!("test_send_all_repoll_after_completion_fails_closed");
    }

    #[test]
    fn test_send_all_propagates_error() {
        init_test("test_send_all_propagates_error");
        let mut sink = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.send_error_once = true;
            state
        });

        let res = future::block_on(async { sink.send_all(vec![create_symbol(9)]).await });
        crate::assert_with_log!(
            matches!(res, Err(SinkError::SendFailed { .. })),
            "error",
            true,
            matches!(res, Err(SinkError::SendFailed { .. }))
        );
        crate::test_complete!("test_send_all_propagates_error");
    }

    #[test]
    fn test_flush_future_repoll_after_completion_fails_closed() {
        init_test("test_flush_future_repoll_after_completion_fails_closed");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = sink.flush();
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first flush completes",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );

        let second = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion))),
            "second flush poll fails closed",
            true,
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion)))
        );

        let flush_count = {
            let state = sink.state.lock();
            state.flush_count
        };
        crate::assert_with_log!(flush_count == 1, "flush invoked once", 1usize, flush_count);
        crate::test_complete!("test_flush_future_repoll_after_completion_fails_closed");
    }

    #[test]
    fn test_close_future_repoll_after_completion_fails_closed() {
        init_test("test_close_future_repoll_after_completion_fails_closed");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut future = sink.close();
        let mut future = Pin::new(&mut future);

        let first = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first close completes",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );

        let second = future.as_mut().poll(&mut context);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion))),
            "second close poll fails closed",
            true,
            matches!(second, Poll::Ready(Err(SinkError::PolledAfterCompletion)))
        );

        let closed = {
            let state = sink.state.lock();
            state.closed
        };
        crate::assert_with_log!(closed, "sink closed", true, closed);
        crate::test_complete!("test_close_future_repoll_after_completion_fails_closed");
    }

    #[test]
    fn test_buffered_sink_defers_send_until_flush() {
        init_test("test_buffered_sink_defers_send_until_flush");
        let mut buffered = BufferedSink::new(CollectingSink::new(), 2);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(1));
        let second = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(2));
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first buffered",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Ok(()))),
            "second buffered",
            true,
            matches!(second, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            buffered.inner.symbols.is_empty(),
            "inner empty before flush",
            true,
            buffered.inner.symbols.is_empty()
        );

        let flushed = Pin::new(&mut buffered).poll_flush(&mut context);
        crate::assert_with_log!(
            matches!(flushed, Poll::Ready(Ok(()))),
            "flush ok",
            true,
            matches!(flushed, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            buffered.inner.symbols.len() == 2,
            "inner received",
            2usize,
            buffered.inner.symbols.len()
        );
        crate::test_complete!("test_buffered_sink_defers_send_until_flush");
    }

    #[test]
    fn test_buffered_sink_ready_pending_when_inner_not_ready() {
        init_test("test_buffered_sink_ready_pending_when_inner_not_ready");
        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            // The terminal-error probe in poll_send's poll_ready path consumes
            // one poll_ready call on the inner. Set ready_after=2 so the inner
            // is still not ready when the full-buffer flush attempts to drain.
            state.ready_after = 2;
            state
        });
        let mut buffered = BufferedSink::new(inner, 1);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let send = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(7));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "buffered send",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let ready = Pin::new(&mut buffered).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Pending),
            "ready pending",
            true,
            matches!(ready, Poll::Pending)
        );
        crate::assert_with_log!(
            buffered.buffer.len() == 1,
            "buffer retained",
            1usize,
            buffered.buffer.len()
        );
        crate::test_complete!("test_buffered_sink_ready_pending_when_inner_not_ready");
    }

    #[test]
    fn test_buffered_sink_pending_full_send_retains_staged_symbol() {
        init_test("test_buffered_sink_pending_full_send_retains_staged_symbol");
        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            // First send consumes one transient pending poll via the terminal
            // probe. The second send then sees another transient pending in the
            // full-buffer flush path and must retain the staged symbol.
            state.ready_after = 3;
            state
        });
        let mut buffered = BufferedSink::new(inner, 1);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let first = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(1));
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first symbol buffered",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );

        let second = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(2));
        crate::assert_with_log!(
            matches!(second, Poll::Pending),
            "second send backpressures instead of dropping",
            true,
            matches!(second, Poll::Pending)
        );
        crate::assert_with_log!(
            buffered.buffer.len() == 1,
            "full buffer still holds original symbol",
            1usize,
            buffered.buffer.len()
        );
        crate::assert_with_log!(
            buffered.staged_symbols.len() == 1,
            "staged symbol retained across flush backpressure",
            true,
            buffered.staged_symbols.len() == 1
        );

        let flushed = Pin::new(&mut buffered).poll_flush(&mut context);
        crate::assert_with_log!(
            matches!(flushed, Poll::Ready(Ok(()))),
            "flush drains both buffered and pending symbols",
            true,
            matches!(flushed, Poll::Ready(Ok(())))
        );

        let sent_ids = {
            let state = buffered.inner.state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };
        crate::assert_with_log!(
            sent_ids == vec![1, 2],
            "flush preserves symbol order and retention",
            vec![1_u32, 2_u32],
            sent_ids
        );
        crate::assert_with_log!(
            buffered.staged_symbols.is_empty(),
            "staged backlog cleared after flush",
            true,
            buffered.staged_symbols.is_empty()
        );
        crate::test_complete!("test_buffered_sink_pending_full_send_retains_staged_symbol");
    }

    #[test]
    fn test_buffered_sink_direct_poll_send_preserves_fifo_with_staged_backlog() {
        init_test("test_buffered_sink_direct_poll_send_preserves_fifo_with_staged_backlog");
        let inner = SequencedSendSink::new(2);
        let state = inner.state();
        let mut buffered = BufferedSink::new(inner, 2);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let first = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(1));
        let second = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(2));
        let third = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(3));

        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(()))),
            "first symbol buffered",
            true,
            matches!(first, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Ok(()))),
            "second symbol buffered",
            true,
            matches!(second, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            matches!(third, Poll::Pending),
            "third symbol stalls on partial drain",
            true,
            matches!(third, Poll::Pending)
        );

        let sent_after_third = {
            let state = state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };
        crate::assert_with_log!(
            sent_after_third == vec![1],
            "partial drain only sends the head symbol",
            vec![1_u32],
            sent_after_third
        );

        let fourth = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(4));
        crate::assert_with_log!(
            matches!(fourth, Poll::Ready(Ok(()))),
            "fourth direct send is retained and drained without reordering",
            true,
            matches!(fourth, Poll::Ready(Ok(())))
        );

        let flushed = Pin::new(&mut buffered).poll_flush(&mut context);
        crate::assert_with_log!(
            matches!(flushed, Poll::Ready(Ok(()))),
            "final flush completes",
            true,
            matches!(flushed, Poll::Ready(Ok(())))
        );

        let sent_ids = {
            let state = state.lock();
            state
                .sent
                .iter()
                .map(|symbol| symbol.symbol().id().esi())
                .collect::<Vec<_>>()
        };
        crate::assert_with_log!(
            sent_ids == vec![1, 2, 3, 4],
            "all directly-polled sends retain FIFO order",
            vec![1_u32, 2_u32, 3_u32, 4_u32],
            sent_ids
        );
        crate::assert_with_log!(
            buffered.buffer.is_empty(),
            "local buffer drained",
            true,
            buffered.buffer.is_empty()
        );
        crate::assert_with_log!(
            buffered.staged_symbols.is_empty(),
            "staged backlog drained",
            true,
            buffered.staged_symbols.is_empty()
        );
        crate::test_complete!(
            "test_buffered_sink_direct_poll_send_preserves_fifo_with_staged_backlog"
        );
    }

    #[test]
    fn test_buffered_sink_ready_errors_when_inner_closed() {
        init_test("test_buffered_sink_ready_errors_when_inner_closed");
        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.closed = true;
            state
        });
        let mut buffered = BufferedSink::new(inner, 2);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let ready = Pin::new(&mut buffered).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Err(SinkError::Closed))),
            "closed inner fails poll_ready",
            true,
            matches!(ready, Poll::Ready(Err(SinkError::Closed)))
        );
        crate::assert_with_log!(
            buffered.buffer.is_empty(),
            "buffer remains empty",
            true,
            buffered.buffer.is_empty()
        );
        crate::test_complete!("test_buffered_sink_ready_errors_when_inner_closed");
    }

    #[test]
    fn test_buffered_sink_send_future_rejects_closed_inner_without_buffering() {
        init_test("test_buffered_sink_send_future_rejects_closed_inner_without_buffering");
        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.closed = true;
            state
        });
        let mut buffered = BufferedSink::new(inner, 2);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        {
            let mut send = buffered.send(create_symbol(13));
            let poll = Pin::new(&mut send).poll(&mut context);
            crate::assert_with_log!(
                matches!(poll, Poll::Ready(Err(SinkError::Closed))),
                "closed inner fails send future",
                true,
                matches!(poll, Poll::Ready(Err(SinkError::Closed)))
            );
        }
        crate::assert_with_log!(
            buffered.buffer.is_empty(),
            "symbol not stranded in buffer",
            true,
            buffered.buffer.is_empty()
        );
        crate::test_complete!(
            "test_buffered_sink_send_future_rejects_closed_inner_without_buffering"
        );
    }

    #[test]
    fn test_buffered_sink_ready_still_buffers_through_transient_inner_pending() {
        init_test("test_buffered_sink_ready_still_buffers_through_transient_inner_pending");
        let inner = TrackingSink::new({
            let mut state = TrackingSinkState::new();
            state.ready_after = 1;
            state
        });
        let mut buffered = BufferedSink::new(inner, 2);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let ready = Pin::new(&mut buffered).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Ok(()))),
            "transient inner pending still permits buffering",
            true,
            matches!(ready, Poll::Ready(Ok(())))
        );

        let send = Pin::new(&mut buffered).poll_send(&mut context, create_symbol(14));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send buffers symbol despite transient backpressure",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );
        crate::assert_with_log!(
            buffered.buffer.len() == 1,
            "symbol buffered locally",
            1usize,
            buffered.buffer.len()
        );
        crate::test_complete!(
            "test_buffered_sink_ready_still_buffers_through_transient_inner_pending"
        );
    }

    #[test]
    fn test_channel_sink_pending_when_full_and_ready_after_recv() {
        init_test("test_channel_sink_pending_when_full_and_ready_after_recv");
        let (mut sink, mut stream) = channel(1);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let ready = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Ok(()))),
            "ready ok",
            true,
            matches!(ready, Poll::Ready(Ok(())))
        );
        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(1));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send ok",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let pending = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(pending, Poll::Pending),
            "pending when full",
            true,
            matches!(pending, Poll::Pending)
        );
        let queued = sink
            .waiter
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));
        crate::assert_with_log!(queued, "waiter queued", true, queued);

        future::block_on(async {
            let _ = stream.next().await.unwrap().unwrap();
        });

        let ready_after = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready_after, Poll::Ready(Ok(()))),
            "ready after recv",
            true,
            matches!(ready_after, Poll::Ready(Ok(())))
        );
        let queued_after = sink
            .waiter
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));
        crate::assert_with_log!(!queued_after, "waiter cleared", false, queued_after);

        crate::test_complete!("test_channel_sink_pending_when_full_and_ready_after_recv");
    }

    #[test]
    fn test_channel_sink_drop_removes_queued_waiter() {
        init_test("test_channel_sink_drop_removes_queued_waiter");
        let shared = Arc::new(SharedChannel::new(1));
        {
            let mut queue = shared.queue.lock();
            queue.push_back(create_symbol(1));
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut sink = ChannelSink::new(Arc::clone(&shared));
        let pending = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(pending, Poll::Pending),
            "ready pending when full",
            true,
            matches!(pending, Poll::Pending)
        );
        let queued_before = shared.send_wakers.lock().len();
        crate::assert_with_log!(
            queued_before == 1,
            "one waiter registered",
            1usize,
            queued_before
        );

        drop(sink);

        let queued_after = shared.send_wakers.lock().len();
        crate::assert_with_log!(
            queued_after == 0,
            "queued waiter removed on drop",
            0usize,
            queued_after
        );
        crate::test_complete!("test_channel_sink_drop_removes_queued_waiter");
    }

    #[test]
    fn test_channel_sink_refreshes_queued_waker_on_repoll() {
        init_test("test_channel_sink_refreshes_queued_waker_on_repoll");
        let (mut sink, mut stream) = channel(1);
        let ready_waker = noop_waker();
        let mut ready_context = Context::from_waker(&ready_waker);
        let _ = Pin::new(&mut sink).poll_send(&mut ready_context, create_symbol(1));

        let first_flag = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::new(AtomicBool::new(false));
        let first_waker = flagged_waker(Arc::clone(&first_flag));
        let second_waker = flagged_waker(Arc::clone(&second_flag));
        let mut first_context = Context::from_waker(&first_waker);
        let mut second_context = Context::from_waker(&second_waker);

        let first_pending = Pin::new(&mut sink).poll_ready(&mut first_context);
        crate::assert_with_log!(
            matches!(first_pending, Poll::Pending),
            "first poll pending",
            true,
            matches!(first_pending, Poll::Pending)
        );

        let second_pending = Pin::new(&mut sink).poll_ready(&mut second_context);
        crate::assert_with_log!(
            matches!(second_pending, Poll::Pending),
            "second poll pending",
            true,
            matches!(second_pending, Poll::Pending)
        );

        let _ = SymbolStream::poll_next(Pin::new(&mut stream), &mut ready_context);

        let first_woke = first_flag.load(Ordering::Acquire);
        let second_woke = second_flag.load(Ordering::Acquire);
        crate::assert_with_log!(!first_woke, "stale waker not used", false, first_woke);
        crate::assert_with_log!(second_woke, "latest waker used", true, second_woke);
        crate::test_complete!("test_channel_sink_refreshes_queued_waker_on_repoll");
    }

    #[test]
    fn test_channel_sink_skips_stale_recv_waiter_entries() {
        init_test("test_channel_sink_skips_stale_recv_waiter_entries");
        let shared = Arc::new(SharedChannel::new(1));
        let mut sink = ChannelSink::new(Arc::clone(&shared));

        let stale_flag = Arc::new(AtomicBool::new(false));
        let active_flag = Arc::new(AtomicBool::new(false));
        let stale_queued = Arc::new(AtomicBool::new(false));
        let active_queued = Arc::new(AtomicBool::new(true));

        {
            let mut recv_wakers = shared.recv_wakers.lock();
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&active_flag)),
                queued: Arc::clone(&active_queued),
            });
            // Stale waiter remains in the queue until pop-time pruning.
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&stale_flag)),
                queued: Arc::clone(&stale_queued),
            });
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(5));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send succeeds",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let stale_woke = stale_flag.load(Ordering::Acquire);
        let active_woke = active_flag.load(Ordering::Acquire);
        crate::assert_with_log!(!stale_woke, "stale waiter not woken", false, stale_woke);
        crate::assert_with_log!(active_woke, "active waiter woken", true, active_woke);
        let active_cleared = !active_queued.load(Ordering::Acquire);
        crate::assert_with_log!(
            active_cleared,
            "active waiter flag cleared",
            true,
            active_cleared
        );
        let recv_waiters_empty = shared.recv_wakers.lock().is_empty();
        crate::assert_with_log!(
            recv_waiters_empty,
            "stale entries pruned",
            true,
            recv_waiters_empty
        );

        crate::test_complete!("test_channel_sink_skips_stale_recv_waiter_entries");
    }

    #[test]
    fn test_channel_sink_wakes_oldest_recv_waiter_first() {
        init_test("test_channel_sink_wakes_oldest_recv_waiter_first");
        let shared = Arc::new(SharedChannel::new(2));
        let mut sink = ChannelSink::new(Arc::clone(&shared));

        let first_flag = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::new(AtomicBool::new(false));
        let first_queued = Arc::new(AtomicBool::new(true));
        let second_queued = Arc::new(AtomicBool::new(true));

        {
            let mut recv_wakers = shared.recv_wakers.lock();
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&first_flag)),
                queued: Arc::clone(&first_queued),
            });
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&second_flag)),
                queued: Arc::clone(&second_queued),
            });
        }

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(9));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send succeeds",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let first_woke = first_flag.load(Ordering::Acquire);
        let second_woke = second_flag.load(Ordering::Acquire);
        crate::assert_with_log!(first_woke, "first waiter woken", true, first_woke);
        crate::assert_with_log!(
            !second_woke,
            "second waiter still waiting",
            false,
            second_woke
        );
        let second_still_queued = second_queued.load(Ordering::Acquire);
        crate::assert_with_log!(
            second_still_queued,
            "second waiter remains queued",
            true,
            second_still_queued
        );
        let queued_len = shared.recv_wakers.lock().len();
        crate::assert_with_log!(queued_len == 1, "one waiter remains", 1usize, queued_len);

        crate::test_complete!("test_channel_sink_wakes_oldest_recv_waiter_first");
    }

    #[test]
    fn test_channel_sink_poll_send_buffer_full() {
        init_test("test_channel_sink_poll_send_buffer_full");
        let (mut sink, _stream) = channel(1);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let ready = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Ok(()))),
            "ready ok",
            true,
            matches!(ready, Poll::Ready(Ok(())))
        );
        let send = Pin::new(&mut sink).poll_send(&mut context, create_symbol(1));
        crate::assert_with_log!(
            matches!(send, Poll::Ready(Ok(()))),
            "send ok",
            true,
            matches!(send, Poll::Ready(Ok(())))
        );

        let full = Pin::new(&mut sink).poll_send(&mut context, create_symbol(2));
        crate::assert_with_log!(
            matches!(full, Poll::Ready(Err(SinkError::BufferFull))),
            "buffer full",
            true,
            matches!(full, Poll::Ready(Err(SinkError::BufferFull)))
        );

        crate::test_complete!("test_channel_sink_poll_send_buffer_full");
    }

    #[test]
    fn test_collecting_sink_collects() {
        init_test("test_collecting_sink_collects");
        let mut sink = CollectingSink::new();

        future::block_on(async {
            sink.send(create_symbol(1)).await.unwrap();
            sink.send(create_symbol(2)).await.unwrap();
        });

        crate::assert_with_log!(
            sink.symbols().len() == 2,
            "len",
            2usize,
            sink.symbols().len()
        );
        crate::test_complete!("test_collecting_sink_collects");
    }

    #[test]
    fn test_channel_sink_close_sets_closed_and_ready_errors() {
        init_test("test_channel_sink_close_sets_closed_and_ready_errors");
        let (mut sink, _stream) = channel(1);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let close = Pin::new(&mut sink).poll_close(&mut context);
        crate::assert_with_log!(
            matches!(close, Poll::Ready(Ok(()))),
            "close ok",
            true,
            matches!(close, Poll::Ready(Ok(())))
        );

        let ready = Pin::new(&mut sink).poll_ready(&mut context);
        crate::assert_with_log!(
            matches!(ready, Poll::Ready(Err(SinkError::Closed))),
            "ready closed",
            true,
            matches!(ready, Poll::Ready(Err(SinkError::Closed)))
        );

        crate::test_complete!("test_channel_sink_close_sets_closed_and_ready_errors");
    }
}
