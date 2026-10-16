//! Symbol sink traits and implementations for transport layer.
//!
//! This module defines the sink side of symbol transmission, handling the
//! outbound flow of [`AuthenticatedSymbol`]s to transport destinations.
//! Sinks provide buffering, flow control, and reliable delivery semantics.
//!
//! # Core Abstractions
//!
//! - **Symbol sinks**: Async sinks for sending [`AuthenticatedSymbol`]s with flow control
//! - **Channel coordination**: Integration with shared channels for distribution
//! - **Waker management**: Efficient notification when sinks become ready
//! - **Error handling**: Comprehensive error recovery for transmission failures
//!
//! # Design Properties
//!
//! - **Backpressure**: Sinks apply flow control to prevent memory exhaustion
//! - **Reliability**: Transmission failures are detected and reported
//! - **Efficiency**: Batch operations and waker deduplication minimize overhead
//! - **Cancellation behavior**: The one-phase `send` convenience future is
//!   *not* cancel-safe — a symbol that has not yet been accepted by the sink
//!   when the future is cancelled is dropped (the resulting [`SinkError`] does
//!   not carry the un-sent payload). Callers that require cancel-safe, no-loss
//!   delivery must use the two-phase reserve/commit channels in
//!   [`crate::channel`] (`mpsc`/`oneshot`), which hand the value back on a
//!   cancelled reservation instead of losing it (aasraf).

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
///
/// This one-phase send is *not* cancel-safe: if the future is cancelled (or the
/// ambient `Cx` is cancelled) before the sink accepts the symbol, the symbol
/// held in `symbol` is dropped and the returned [`SinkError`] does not carry it.
/// For cancel-safe, no-loss delivery use the two-phase reserve/commit channels
/// in [`crate::channel`] instead (aasraf).
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

        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
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

        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
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

        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
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

        if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
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
        if this.capacity == 0 {
            return this
                .poll_inner_terminal_error(cx)
                .map_or(Poll::Ready(Err(SinkError::BufferFull)), |err| {
                    Poll::Ready(Err(err))
                });
        }
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

        if this.capacity == 0 {
            return Poll::Ready(Err(SinkError::BufferFull));
        }

        if this.buffer.len() >= this.capacity || !this.staged_symbols.is_empty() {
            // Try to flush existing backlog to make room. This also registers
            // the waker if the inner sink is blocked.
            if let Poll::Ready(Err(err)) = Pin::new(&mut *this).poll_flush(cx) {
                return Poll::Ready(Err(err));
            }
            // Pending or Ready(Ok(()))
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
#[derive(Default)]
pub struct CollectingSink {
    symbols: Vec<AuthenticatedSymbol>,
    closed: bool,
}

impl CollectingSink {
    /// Creates an empty collecting sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

impl SymbolSink for CollectingSink {
    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        if self.closed {
            Poll::Ready(Err(SinkError::Closed))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_send(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
        if self.closed {
            return Poll::Ready(Err(SinkError::Closed));
        }
        self.symbols.push(symbol);
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        if self.closed {
            Poll::Ready(Err(SinkError::Closed))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[path = "sink_inline_tests.rs"]
mod tests;
