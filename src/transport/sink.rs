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

use crate::distributed::encoding::PathQualitySnapshot;
use crate::security::authenticated::AuthenticatedSymbol;
use crate::transport::aggregator::PathId;
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

/// Local ownership and progress counters for one [`MultipathSink`] path.
///
/// A successful downstream send or flush is not a remote acknowledgement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MultipathPathStats {
    /// Symbols currently retained by the adapter, including an uncertain send.
    pub queued_symbols: usize,
    /// Symbols accepted downstream since its last successful flush.
    pub unflushed_symbols: usize,
    /// Largest combined queued and unflushed count observed on this path.
    pub high_water_symbols: usize,
    /// Symbols whose downstream `poll_send` returned success.
    pub sent_symbols: u64,
    /// Symbols covered by a successful local downstream flush.
    pub flushed_symbols: u64,
    /// Never-attempted symbols moved from this failed path to another path.
    pub reassigned_symbols: u64,
    /// Whether the path has returned a terminal error.
    pub failed: bool,
    /// Whether a send or flush failed after downstream ownership was possible.
    pub outcome_uncertain: bool,
}

/// A symbol retained when a multipath sink is decomposed for recovery.
#[derive(Debug)]
pub struct MultipathPendingSymbol {
    /// The original authenticated symbol.
    pub symbol: AuthenticatedSymbol,
    /// Whether downstream `poll_send` was already invoked for this symbol.
    ///
    /// When true, replay can duplicate an operation with an unknown outcome.
    /// Only false entries are known never to have crossed that boundary.
    pub attempted: bool,
}

struct MultipathOutput {
    id: PathId,
    quality: PathQualitySnapshot,
    weight: i64,
    credit: i64,
    sink: Box<dyn SymbolSink>,
    queue: VecDeque<MultipathPendingSymbol>,
    stats: MultipathPathStats,
    error: Option<SinkError>,
    ready: bool,
    closed: bool,
}

/// Bounded, opt-in source striping and repair routing over real symbol sinks.
///
/// Source symbols use deterministic smooth weighted round-robin. Weights use
/// the supplied RTT, loss and reorder snapshot; [`Self::update_path_quality`]
/// starts a fresh scheduling window. Repair symbols prefer the highest-weight
/// ready path, falling back to available bounded queue capacity. Equal scores
/// select the lowest [`PathId`]. There is no delivery-order guarantee.
///
/// Each path owns at most `capacity_per_path` queued plus accepted-but-unflushed
/// symbols, each with at most `max_symbol_bytes` payload bytes. The adapter
/// copies accepted payloads to discard arbitrary spare input capacity, allocates
/// queues lazily and retains at most one temporary symbol clone per downstream
/// poll. Underlying sinks can have their own allocations and queues;
/// their successful flush is a local progress boundary, not a remote ACK.
///
/// `poll_send` returns success once the adapter owns the symbol. It never
/// retains a newly supplied symbol while returning `Pending`. Dropping a send
/// future after that acceptance cannot remove the owned symbol: later readiness,
/// flush or close polls continue driving it. Dropping the sink itself releases
/// its retained work, just like [`BufferedSink`]; there are no hidden tasks.
///
/// A path failure before any downstream send attempt permits reassignment of
/// that queued symbol. An attempted send or an unflushed acceptance is never
/// replayed automatically. Such a failure prevents new admission, while flush
/// and close still drain healthy paths before reporting the failure. The exact
/// path error remains available through [`Self::path_error`], and
/// [`Self::into_paths`] preserves remaining symbols and their uncertainty.
pub struct MultipathSink {
    paths: Vec<MultipathOutput>,
    max_paths: usize,
    capacity_per_path: usize,
    max_symbol_bytes: usize,
    next_start: usize,
    closing: bool,
    closed: bool,
    close_failed: bool,
}

impl std::fmt::Debug for MultipathSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultipathSink")
            .field("paths", &self.paths.len())
            .field("capacity_per_path", &self.capacity_per_path)
            .field("max_symbol_bytes", &self.max_symbol_bytes)
            .field("closing", &self.closing)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl MultipathSink {
    /// Construct an empty sink with immutable ownership bounds.
    ///
    /// All limits must be nonzero, at most 1024 paths may be configured, and
    /// the aggregate payload bound must fit `isize::MAX`.
    pub fn new(
        max_paths: usize,
        capacity_per_path: usize,
        max_symbol_bytes: usize,
    ) -> Result<Self, SinkError> {
        let bound = max_paths
            .checked_mul(capacity_per_path)
            .and_then(|count| count.checked_mul(max_symbol_bytes));
        if max_paths == 0
            || max_paths > 1024
            || capacity_per_path == 0
            || max_symbol_bytes == 0
            || bound.is_none_or(|bytes| bytes > isize::MAX as usize)
        {
            return Err(Self::failure("invalid multipath ownership bounds"));
        }
        Ok(Self {
            paths: Vec::new(),
            max_paths,
            capacity_per_path,
            max_symbol_bytes,
            next_start: 0,
            closing: false,
            closed: false,
            close_failed: false,
        })
    }

    /// Add a concrete transport. Path identifiers must be unique.
    pub fn add_path<S: SymbolSink + 'static>(
        &mut self,
        id: PathId,
        quality: PathQualitySnapshot,
        sink: S,
    ) -> Result<(), SinkError> {
        if self.closing || self.closed {
            return Err(SinkError::Closed);
        }
        if self.paths.len() == self.max_paths || self.paths.iter().any(|path| path.id == id) {
            return Err(Self::failure("multipath path limit or duplicate identifier"));
        }
        self.paths.push(MultipathOutput {
            id,
            quality,
            weight: Self::quality_weight(quality),
            credit: 0,
            sink: Box::new(sink),
            queue: VecDeque::new(),
            stats: MultipathPathStats::default(),
            error: None,
            ready: false,
            closed: false,
        });
        self.paths.sort_by_key(|path| path.id);
        self.reset_credits();
        Ok(())
    }

    /// Replace the caller-observed quality and begin a fresh weighting window.
    /// This does not resurrect a transport that has returned a terminal error.
    pub fn update_path_quality(&mut self, id: PathId, quality: PathQualitySnapshot) -> bool {
        let Some(path) = self.paths.iter_mut().find(|path| path.id == id) else {
            return false;
        };
        path.quality = quality;
        path.weight = Self::quality_weight(quality);
        self.reset_credits();
        true
    }

    /// Snapshot local counts without claiming remote receipt or loss.
    #[must_use]
    pub fn path_stats(&self, id: PathId) -> Option<MultipathPathStats> {
        self.paths.iter().find(|path| path.id == id).map(|path| {
            let mut stats = path.stats;
            stats.queued_symbols = path.queue.len();
            stats
        })
    }

    /// The caller-supplied quality snapshot used for current routing weights.
    #[must_use]
    pub fn path_quality(&self, id: PathId) -> Option<PathQualitySnapshot> {
        self.paths
            .iter()
            .find(|path| path.id == id)
            .map(|path| path.quality)
    }

    /// The original terminal error returned by a path, if any.
    #[must_use]
    pub fn path_error(&self, id: PathId) -> Option<&SinkError> {
        self.paths.iter().find(|path| path.id == id)?.error.as_ref()
    }

    /// Recover transports and retained symbols without retrying uncertain work.
    ///
    /// Successful downstream sends are owned by those transports and are not
    /// duplicated here. Inspect `attempted` before deciding how to recover each
    /// returned symbol. The iterator is in ascending path-ID order.
    pub fn into_paths(
        self,
    ) -> impl Iterator<Item = (PathId, Box<dyn SymbolSink>, VecDeque<MultipathPendingSymbol>)> {
        self.paths
            .into_iter()
            .map(|path| (path.id, path.sink, path.queue))
    }

    fn failure(reason: &str) -> SinkError {
        SinkError::SendFailed {
            reason: reason.to_owned(),
        }
    }

    fn quality_weight(quality: PathQualitySnapshot) -> i64 {
        let success = u64::from(1000 - quality.loss_ewma_permille.min(1000));
        let cost = (u64::from(quality.rtt_ewma_ms) + 1) * (u64::from(quality.reorder_depth) + 1);
        // Positive, bounded integer weights avoid floating-point drift, zero
        // divisors and starvation of the sole surviving low-quality path.
        i64::try_from((success * 1024 / (cost * 1000)).clamp(1, 1024)).unwrap_or(1)
    }

    fn reset_credits(&mut self) {
        self.next_start = 0;
        for path in &mut self.paths {
            path.credit = 0;
        }
    }

    fn has_capacity(path: &MultipathOutput, capacity: usize) -> bool {
        !path.stats.failed
            && !path.closed
            && path.queue.len() < capacity.saturating_sub(path.stats.unflushed_symbols)
    }

    fn choose_path(&mut self, repair: bool) -> Option<usize> {
        let prefer_ready = repair
            && self
                .paths
                .iter()
                .any(|path| path.ready && Self::has_capacity(path, self.capacity_per_path));
        let mut selected = None;
        let mut best = i64::MIN;
        let mut total = 0_i64;
        for (index, path) in self.paths.iter_mut().enumerate() {
            if !Self::has_capacity(path, self.capacity_per_path) || (prefer_ready && !path.ready) {
                continue;
            }
            let score = if repair {
                path.weight
            } else {
                path.credit = path.credit.saturating_add(path.weight);
                total += path.weight;
                path.credit
            };
            if score > best {
                best = score;
                selected = Some(index);
            }
        }
        if !repair
            && let Some(index) = selected
        {
            self.paths[index].credit = self.paths[index].credit.saturating_sub(total);
        }
        selected
    }

    fn mark_failed(path: &mut MultipathOutput, error: SinkError) {
        path.stats.outcome_uncertain |= path.stats.unflushed_symbols != 0
            || path.queue.front().is_some_and(|symbol| symbol.attempted);
        path.stats.failed = true;
        path.ready = false;
        path.error.get_or_insert(error);
    }

    fn terminal_error(&self) -> Option<SinkError> {
        if self.paths.iter().any(|path| path.stats.outcome_uncertain) {
            Some(Self::failure(
                "multipath downstream outcome is uncertain; inspect path_error",
            ))
        } else if self.close_failed {
            Some(Self::failure(
                "multipath path close failed; inspect path_error",
            ))
        } else {
            None
        }
    }

    /// Poll every usable path so one blocked path cannot hide another's wake.
    fn drive(&mut self, cx: &mut Context<'_>) {
        if self.paths.is_empty() {
            return;
        }
        let mut yielded = false;
        let start = self.next_start % self.paths.len();
        let mut last_progress = None;
        let mut send_budget = 64;
        for offset in 0..self.paths.len() {
            let index = (start + offset) % self.paths.len();
            let path = &mut self.paths[index];
            if path.stats.failed || path.closed {
                continue;
            }
            path.ready = false;
            let mut sent_this_poll = 0;
            for _ in 0..16 {
                match Pin::new(&mut *path.sink).poll_ready(cx) {
                    Poll::Ready(Ok(())) => path.ready = true,
                    Poll::Ready(Err(error)) => {
                        Self::mark_failed(path, error);
                        break;
                    }
                    Poll::Pending => break,
                }
                let Some(front) = path.queue.front_mut() else {
                    break;
                };
                if send_budget == 0 {
                    yielded = true;
                    break;
                }
                send_budget -= 1;
                last_progress = Some(index);
                // The original stays owned until the downstream result is
                // known. A Pending send remains bound to this exact path.
                front.attempted = true;
                match Pin::new(&mut *path.sink).poll_send(cx, front.symbol.clone()) {
                    Poll::Ready(Ok(())) => {
                        path.queue.pop_front();
                        path.ready = false;
                        sent_this_poll += 1;
                        path.stats.sent_symbols = path.stats.sent_symbols.saturating_add(1);
                        path.stats.unflushed_symbols += 1;
                    }
                    Poll::Ready(Err(error)) => {
                        Self::mark_failed(path, error);
                        break;
                    }
                    Poll::Pending => {
                        path.ready = false;
                        break;
                    }
                }
            }
            if path.stats.failed {
                continue;
            }
            if path.stats.unflushed_symbols != 0 {
                match Pin::new(&mut *path.sink).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        path.stats.flushed_symbols = path
                            .stats
                            .flushed_symbols
                            .saturating_add(path.stats.unflushed_symbols as u64);
                        path.stats.unflushed_symbols = 0;
                        // Flushing earlier accepted work can unblock the
                        // retained front whose send just returned Pending.
                        yielded |= !path.queue.is_empty();
                    }
                    Poll::Ready(Err(error)) => Self::mark_failed(path, error),
                    Poll::Pending => {}
                }
            }
            yielded |= sent_this_poll == 16 && !path.queue.is_empty();
        }
        self.next_start = (last_progress.unwrap_or(start) + 1) % self.paths.len();
        // Only never-attempted symbols can cross paths after a failure. Take
        // from the back: an uncertain front remains pinned and recoverable.
        let mut reassign_budget = 64;
        for offset in 0..self.paths.len() {
            let source = (start + offset) % self.paths.len();
            if !self.paths[source].stats.failed {
                continue;
            }
            for _ in 0..16 {
                let Some(symbol) = self.paths[source].queue.back() else {
                    break;
                };
                if symbol.attempted {
                    break;
                }
                if reassign_budget == 0 {
                    yielded = true;
                    break;
                }
                let repair = symbol.symbol.symbol().kind().is_repair();
                let Some(target) = self.choose_path(repair) else {
                    break;
                };
                let symbol = self.paths[source]
                    .queue
                    .pop_back()
                    .expect("queued symbol checked");
                reassign_budget -= 1;
                self.paths[source].stats.reassigned_symbols = self.paths[source]
                    .stats
                    .reassigned_symbols
                    .saturating_add(1);
                self.paths[target].queue.push_back(symbol);
                self.update_high_water(target);
                yielded = true;
            }
        }
        if yielded {
            cx.waker().wake_by_ref();
        }
    }

    fn update_high_water(&mut self, index: usize) {
        let path = &mut self.paths[index];
        path.stats.high_water_symbols = path.stats.high_water_symbols
            .max(path.queue.len() + path.stats.unflushed_symbols);
    }
}

impl SymbolSink for MultipathSink {
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        if self.closing || self.closed {
            return Poll::Ready(Err(SinkError::Closed));
        }
        self.drive(cx);
        if let Some(error) = self.terminal_error() {
            return Poll::Ready(Err(error));
        }
        if self
            .paths
            .iter()
            .any(|path| Self::has_capacity(path, self.capacity_per_path))
        {
            Poll::Ready(Ok(()))
        } else if self.paths.iter().all(|path| path.stats.failed || path.closed) {
            Poll::Ready(Err(Self::failure("no usable multipath transport")))
        } else {
            Poll::Pending
        }
    }

    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        symbol: AuthenticatedSymbol,
    ) -> Poll<Result<(), SinkError>> {
        if symbol.symbol().data().len() > self.max_symbol_bytes {
            return Poll::Ready(Err(Self::failure(
                "multipath symbol exceeds payload bound",
            )));
        }
        match self.as_mut().poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        let repair = symbol.symbol().kind().is_repair();
        let Some(index) = self.choose_path(repair) else {
            return Poll::Pending;
        };
        // Vec::clone copies the payload length, not an arbitrarily large spare
        // input capacity. Preserve the authentication metadata with that copy.
        let owned_symbol = symbol.clone();
        drop(symbol);
        self.paths[index].queue.push_back(MultipathPendingSymbol {
            symbol: owned_symbol,
            attempted: false,
        });
        self.update_high_water(index);
        Poll::Ready(Ok(()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        if !self.closed {
            self.drive(cx);
        }
        if self.paths.iter().any(|path| {
            !path.stats.failed && (!path.queue.is_empty() || path.stats.unflushed_symbols != 0)
        }) {
            return Poll::Pending;
        }
        if let Some(error) = self.terminal_error() {
            return Poll::Ready(Err(error));
        }
        if self.paths.iter().any(|path| !path.queue.is_empty()) {
            return Poll::Ready(Err(Self::failure(
                "multipath retained unsent symbols without a usable path",
            )));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        self.closing = true;
        if self.closed {
            return self.as_mut().poll_flush(cx);
        }
        if self.as_mut().poll_flush(cx).is_pending() {
            return Poll::Pending;
        }
        let mut pending = false;
        let mut failed = false;
        for path in &mut self.paths {
            if path.closed {
                continue;
            }
            match Pin::new(&mut *path.sink).poll_close(cx) {
                Poll::Ready(Ok(())) => path.closed = true,
                Poll::Ready(Err(error)) => {
                    Self::mark_failed(path, error);
                    path.closed = true;
                    failed = true;
                }
                Poll::Pending => pending = true,
            }
        }
        self.close_failed |= failed;
        if pending {
            Poll::Pending
        } else {
            self.closed = true;
            self.as_mut().poll_flush(cx)
        }
    }
}

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
