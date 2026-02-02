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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::authenticated::AuthenticatedSymbol;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::channel;
    use crate::transport::stream::SymbolStreamExt;
    use crate::types::{Symbol, SymbolId, SymbolKind};
    use futures_lite::future;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::task::{Wake, Waker};

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
            let mut state = self.state.lock().unwrap();
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
            let mut state = self.state.lock().unwrap();
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
            let mut state = self.state.lock().unwrap();
            if state.closed {
                drop(state);
                return Poll::Ready(Err(SinkError::Closed));
            }
            state.flush_count += 1;
            drop(state);
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            let mut state = self.state.lock().unwrap();
            state.closed = true;
            drop(state);
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
            let state = sink.state.lock().unwrap();
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
            let state = sink.state.lock().unwrap();
            state.sent.is_empty()
        };
        crate::assert_with_log!(sent_empty, "no sent", true, sent_empty);
        crate::test_complete!("test_send_future_propagates_send_error");
    }

    #[test]
    fn test_send_all_counts_and_flushes() {
        init_test("test_send_all_counts_and_flushes");
        let mut sink = TrackingSink::new(TrackingSinkState::new());
        let symbols = vec![create_symbol(1), create_symbol(2), create_symbol(3)];

        let count = future::block_on(async { sink.send_all(symbols).await.unwrap() });
        let (sent_len, flush_count) = {
            let state = sink.state.lock().unwrap();
            (state.sent.len(), state.flush_count)
        };

        crate::assert_with_log!(count == 3, "count", 3usize, count);
        crate::assert_with_log!(sent_len == 3, "sent", 3usize, sent_len);
        crate::assert_with_log!(flush_count == 1, "flush count", 1usize, flush_count);
        crate::test_complete!("test_send_all_counts_and_flushes");
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
            state.ready_after = 1;
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
