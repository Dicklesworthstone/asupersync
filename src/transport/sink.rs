//! Symbol sink traits and implementations.

use crate::security::authenticated::AuthenticatedSymbol;
use crate::transport::error::SinkError;
use crate::transport::{ChannelWaiter, SharedChannel};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

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
        }
    }

    /// Flush buffered symbols.
    fn flush(&mut self) -> FlushFuture<'_, Self>
    where
        Self: Unpin,
    {
        FlushFuture { sink: self }
    }

    /// Close the sink.
    fn close(&mut self) -> CloseFuture<'_, Self>
    where
        Self: Unpin,
    {
        CloseFuture { sink: self }
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

/// Future for `send()`.
pub struct SendFuture<'a, S: ?Sized> {
    sink: &'a mut S,
    symbol: Option<AuthenticatedSymbol>,
}

impl<S: SymbolSink + Unpin + ?Sized> Future for SendFuture<'_, S> {
    type Output = Result<(), SinkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        // First wait for ready
        match Pin::new(&mut *this.sink).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        // Then send
        if let Some(symbol) = this.symbol.take() {
            match Pin::new(&mut *this.sink).poll_send(cx, symbol.clone()) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.symbol = Some(symbol);
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

/// Future for `send_all()`.
pub struct SendAllFuture<'a, S: ?Sized, I> {
    sink: &'a mut S,
    iter: I,
    buffered: Option<AuthenticatedSymbol>,
    count: usize,
}

impl<S, I> Future for SendAllFuture<'_, S, I>
where
    S: SymbolSink + Unpin + ?Sized,
    I: Iterator<Item = AuthenticatedSymbol> + Unpin,
{
    type Output = Result<usize, SinkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Try to send buffered item
            if let Some(symbol) = self.buffered.take() {
                match Pin::new(&mut *self.sink).poll_ready(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        self.buffered = Some(symbol);
                        return Poll::Pending;
                    }
                }
                match Pin::new(&mut *self.sink).poll_send(cx, symbol.clone()) {
                    Poll::Ready(Ok(())) => self.count += 1,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        self.buffered = Some(symbol);
                        return Poll::Pending;
                    }
                }
            }

            // Get next
            match self.iter.next() {
                Some(symbol) => self.buffered = Some(symbol),
                None => {
                    // Flush
                    match Pin::new(&mut *self.sink).poll_flush(cx) {
                        Poll::Ready(Ok(())) => return Poll::Ready(Ok(self.count)),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

/// Future for `flush()`.
pub struct FlushFuture<'a, S: ?Sized> {
    sink: &'a mut S,
}

impl<S: SymbolSink + Unpin + ?Sized> Future for FlushFuture<'_, S> {
    type Output = Result<(), SinkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.sink).poll_flush(cx)
    }
}

/// Future for `close()`.
pub struct CloseFuture<'a, S: ?Sized> {
    sink: &'a mut S,
}

impl<S: SymbolSink + Unpin + ?Sized> Future for CloseFuture<'_, S> {
    type Output = Result<(), SinkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.sink).poll_close(cx)
    }
}

// ---- Adapters ----

/// A sink that buffers symbols.
pub struct BufferedSink<S> {
    inner: S,
    buffer: Vec<AuthenticatedSymbol>,
    capacity: usize,
}

impl<S> BufferedSink<S> {
    /// Creates a buffered sink with the given capacity.
    pub fn new(inner: S, capacity: usize) -> Self {
        Self {
            inner,
            buffer: Vec::with_capacity(capacity),
            capacity,
        }
    }
}

impl<S: SymbolSink + Unpin> SymbolSink for BufferedSink<S> {
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        if this.buffer.len() < this.capacity {
            Poll::Ready(Ok(()))
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
        if this.buffer.len() >= this.capacity {
            // Must flush first
            match Pin::new(this).poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.get_mut().buffer.push(symbol);
        Poll::Ready(Ok(()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.as_mut().get_mut();

        while !this.buffer.is_empty() {
            // Check if inner is ready
            match Pin::new(&mut this.inner).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            let symbol = match this.buffer.first() {
                Some(symbol) => symbol.clone(),
                None => break,
            };
            match Pin::new(&mut this.inner).poll_send(cx, symbol) {
                Poll::Ready(Ok(())) => {
                    this.buffer.remove(0);
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

impl SymbolSink for ChannelSink {
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let this = self.get_mut();
        let queue = this.shared.queue.lock().unwrap();

        if this.shared.closed.load(Ordering::SeqCst) {
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
            if this.shared.closed.load(Ordering::SeqCst) {
                return Poll::Ready(Err(SinkError::Closed));
            }

            // Only register waiter once to prevent unbounded queue growth.
            // If the waker changes between polls, we accept the stale waker -
            // another waiter will be woken instead, which is harmless.
            let mut new_waiter = None;
            let mut closed = false;
            {
                let mut wakers = this.shared.send_wakers.lock().unwrap();
                if this.shared.closed.load(Ordering::SeqCst) {
                    closed = true;
                } else {
                    match this.waiter.as_ref() {
                        Some(waiter) if !waiter.load(Ordering::Acquire) => {
                            // We were woken but capacity isn't available yet - re-register
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
                drop(wakers);
            }
            if closed {
                return Poll::Ready(Err(SinkError::Closed));
            }
            if let Some(waiter) = new_waiter {
                this.waiter = Some(waiter);
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
            let mut queue = this.shared.queue.lock().unwrap();

            if this.shared.closed.load(Ordering::SeqCst) {
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
            let mut wakers = this.shared.recv_wakers.lock().unwrap();
            wakers.pop()
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
