//! Browser ReadableStream/WritableStream bridge for runtime I/O traits.
//!
//! This module defines the contract-level types and traits that map browser
//! Streams API semantics to asupersync's `AsyncRead`/`AsyncWrite`/`Stream`.
//!
//! # Browser Streams API Model
//!
//! The WHATWG Streams API (`ReadableStream`, `WritableStream`) uses a
//! pull-based backpressure model:
//!
//! ```text
//! ReadableStream:
//!   reader.read()  → {done: false, value: Uint8Array}  (pull from source)
//!   reader.cancel() → close reader, signal source
//!
//! WritableStream:
//!   writer.ready → Promise (backpressure: wait until sink is ready)
//!   writer.write(chunk) → Promise (enqueue chunk)
//!   writer.close() → Promise (graceful shutdown)
//!   writer.abort(reason) → Promise (abrupt termination)
//! ```
//!
//! # Bridge Contracts
//!
//! This module bridges these semantics to asupersync traits:
//!
//! | Browser API | Runtime Trait | Backpressure Mechanism |
//! |-------------|--------------|----------------------|
//! | `ReadableStream.getReader().read()` | `AsyncRead::poll_read` | ReadBuf capacity |
//! | `WritableStream.getWriter().ready` | `AsyncWrite::poll_write` | Poll::Pending |
//! | `WritableStream.getWriter().write()` | `AsyncWrite::poll_write` | Return bytes written |
//! | `WritableStream.getWriter().close()` | `AsyncWrite::poll_shutdown` | Poll until done |
//! | `reader.cancel()` / `writer.abort()` | Cancel protocol | Drop + drain |
//!
//! # Cancellation Semantics
//!
//! Browser stream cancellation maps to asupersync's cancel protocol:
//!
//! 1. `reader.cancel(reason)` → cancel signal propagated to source
//! 2. `writer.abort(reason)` → pending writes may be lost (abort semantics)
//! 3. Region close → all bridge streams cancelled, obligations resolved
//!
//! The bridge ensures that:
//! - Abrupt stream closure produces a clean `io::Error` (not a panic)
//! - Partial reads/writes are correctly accounted
//! - Backpressure propagates correctly between browser and runtime
//!
//! # Cancel Safety
//!
//! All bridge operations follow the same cancel-safety contract as the
//! underlying `AsyncRead`/`AsyncWrite` traits:
//! - `poll_read` is cancel-safe (partial data discarded by caller)
//! - `poll_write` is cancel-safe (returns bytes written)
//! - `poll_flush`/`poll_shutdown` are cancel-safe (can retry)

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::task::{Context, Poll};

#[cfg(target_arch = "wasm32")]
use js_sys::{ArrayBuffer, Reflect, Uint8Array};
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
#[cfg(target_arch = "wasm32")]
use std::future::Future;
#[cfg(target_arch = "wasm32")]
use std::rc::Rc;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{
    BroadcastChannel, EventTarget, MessageChannel, MessageEvent, MessagePort, ReadableStream,
    ReadableStreamDefaultReader, WritableStream, WritableStreamDefaultWriter,
};

use crate::io::cap::{
    BrowserHostApiIoCap, HostApiIoCap, HostApiPolicyError, HostApiRequest, HostApiSurface, IoCap,
    IoCapabilities, IoStats,
};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};

// ============================================================================
// Stream state
// ============================================================================

/// The lifecycle state of a browser stream bridge.
///
/// Models the WHATWG Streams API reader/writer states:
/// ```text
/// Open → Closing → Closed
///   ↘              ↗
///     → Errored ──┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserStreamState {
    /// Stream is open and ready for I/O.
    Open,
    /// Graceful shutdown initiated (writer.close() or reader reaching EOF).
    Closing,
    /// Stream is fully closed. No further I/O.
    Closed,
    /// Stream encountered an error. All subsequent I/O returns the error.
    Errored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamTerminalState {
    Open,
    Closed,
    Aborted,
}

#[derive(Debug)]
struct StreamAccounting {
    stats: Option<Arc<StreamStats>>,
    terminal: StreamTerminalState,
}

impl StreamAccounting {
    fn new(stats: Option<Arc<StreamStats>>) -> Self {
        Self {
            stats,
            terminal: StreamTerminalState::Open,
        }
    }

    fn record_read_bytes(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }

        if let Some(stats) = &self.stats {
            stats
                .total_bytes_read
                .fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn record_written_bytes(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }

        if let Some(stats) = &self.stats {
            stats
                .total_bytes_written
                .fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn mark_closed(&mut self) {
        if self.terminal != StreamTerminalState::Open {
            return;
        }

        if let Some(stats) = &self.stats {
            stats
                .streams_closed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.terminal = StreamTerminalState::Closed;
    }

    fn mark_aborted(&mut self) {
        if self.terminal != StreamTerminalState::Open {
            return;
        }

        if let Some(stats) = &self.stats {
            stats
                .streams_aborted
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.terminal = StreamTerminalState::Aborted;
    }
}

impl Drop for StreamAccounting {
    fn drop(&mut self) {
        if self.terminal == StreamTerminalState::Open {
            self.mark_aborted();
        }
    }
}

impl fmt::Display for BrowserStreamState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => f.write_str("open"),
            Self::Closing => f.write_str("closing"),
            Self::Closed => f.write_str("closed"),
            Self::Errored => f.write_str("errored"),
        }
    }
}

// ============================================================================
// Backpressure policy
// ============================================================================

/// Backpressure strategy for the browser stream bridge.
///
/// Controls how the bridge communicates flow control between the browser's
/// Streams API and the runtime's async I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureStrategy {
    /// High-water mark based. The bridge buffers up to `high_water_mark`
    /// bytes before signaling backpressure (returning `Poll::Pending`).
    /// This matches the default WHATWG Streams API behavior.
    HighWaterMark(usize),

    /// Unbuffered mode. Every write immediately attempts to push to the
    /// sink. Useful for latency-sensitive streams (e.g., WebSocket frames).
    Unbuffered,
}

impl Default for BackpressureStrategy {
    /// Default: 64KB high-water mark (matches WHATWG default for byte streams).
    fn default() -> Self {
        Self::HighWaterMark(65_536)
    }
}

// ============================================================================
// Browser stream bridge configuration
// ============================================================================

/// Configuration for a browser stream bridge instance.
#[derive(Debug, Clone)]
pub struct BrowserStreamConfig {
    /// Backpressure strategy for the write side.
    pub write_backpressure: BackpressureStrategy,

    /// Maximum bytes to read in a single `poll_read` call.
    /// Limits memory allocation per read operation.
    pub max_read_chunk: usize,

    /// Maximum total bytes readable from this stream.
    /// Enforces body size limits (matches `FetchStreamPolicy`).
    pub max_total_read_bytes: u64,

    /// Maximum total bytes writable to this stream.
    pub max_total_write_bytes: u64,

    /// Whether to allow partial writes (true) or fail closed after a short write (false).
    /// Partial writes are the norm for `AsyncWrite`; when disabled, any committed
    /// prefix is still surfaced via the returned byte count and the stream is
    /// moved to `Errored` so later writes cannot silently continue.
    pub allow_partial_writes: bool,
}

impl Default for BrowserStreamConfig {
    fn default() -> Self {
        Self {
            write_backpressure: BackpressureStrategy::default(),
            max_read_chunk: 65_536,         // 64KB per read
            max_total_read_bytes: 16 << 20, // 16MB
            max_total_write_bytes: 4 << 20, // 4MB
            allow_partial_writes: true,
        }
    }
}

// ============================================================================
// Browser stream error
// ============================================================================

/// Error produced by browser stream bridge operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserStreamError {
    /// Stream was aborted by the browser (e.g., navigation, AbortController).
    Aborted(String),
    /// Stream was closed while an operation was pending.
    ClosedDuringOperation,
    /// Read exceeded the configured maximum total bytes.
    ReadLimitExceeded {
        /// Bytes already read.
        read: u64,
        /// Configured limit.
        limit: u64,
    },
    /// Write exceeded the configured maximum total bytes.
    WriteLimitExceeded {
        /// Bytes already written.
        written: u64,
        /// Configured limit.
        limit: u64,
    },
    /// Backpressure: the sink is not ready to accept more data.
    /// Caller should retry after the writer signals readiness.
    BackpressureFull,
    /// The stream entered an error state from a host-side error.
    HostError(String),
}

impl fmt::Display for BrowserStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aborted(reason) => write!(f, "browser stream aborted: {reason}"),
            Self::ClosedDuringOperation => {
                f.write_str("browser stream closed during pending operation")
            }
            Self::ReadLimitExceeded { read, limit } => {
                write!(f, "read limit exceeded: {read}/{limit} bytes")
            }
            Self::WriteLimitExceeded { written, limit } => {
                write!(f, "write limit exceeded: {written}/{limit} bytes")
            }
            Self::BackpressureFull => f.write_str("stream backpressure: sink not ready"),
            Self::HostError(msg) => write!(f, "browser host error: {msg}"),
        }
    }
}

impl std::error::Error for BrowserStreamError {}

impl From<BrowserStreamError> for io::Error {
    fn from(err: BrowserStreamError) -> Self {
        match err {
            BrowserStreamError::Aborted(_) => {
                Self::new(io::ErrorKind::ConnectionAborted, err.to_string())
            }
            BrowserStreamError::ClosedDuringOperation => {
                Self::new(io::ErrorKind::BrokenPipe, err.to_string())
            }
            BrowserStreamError::ReadLimitExceeded { .. }
            | BrowserStreamError::WriteLimitExceeded { .. }
            | BrowserStreamError::HostError(_) => Self::other(err.to_string()),
            BrowserStreamError::BackpressureFull => {
                Self::new(io::ErrorKind::WouldBlock, err.to_string())
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn js_host_io_error(err: &JsValue, op: &str) -> io::Error {
    let detail = err
        .as_string()
        .unwrap_or_else(|| "non-string JavaScript error".to_owned());
    io::Error::other(format!("{op} failed: {detail}"))
}

// ============================================================================
// wasm32 host-backed adapters
// ============================================================================

#[cfg(target_arch = "wasm32")]
/// Host-backed reader for WHATWG `ReadableStream` objects.
pub struct WasmReadableStreamSource {
    reader: ReadableStreamDefaultReader,
    pending_read: Option<JsFuture>,
    staged: Vec<u8>,
    staged_offset: usize,
    done: bool,
}

#[cfg(target_arch = "wasm32")]
impl fmt::Debug for WasmReadableStreamSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmReadableStreamSource")
            .field("pending_read", &self.pending_read.is_some())
            .field("staged_len", &self.staged.len())
            .field("staged_offset", &self.staged_offset)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

#[cfg(target_arch = "wasm32")]
impl WasmReadableStreamSource {
    /// Construct from a browser `ReadableStream`.
    pub fn new(stream: &ReadableStream) -> Result<Self, BrowserStreamError> {
        let reader = stream
            .get_reader()
            .dyn_into::<ReadableStreamDefaultReader>()
            .map_err(|_| {
                BrowserStreamError::HostError(
                    "ReadableStream.getReader() did not return default reader".to_owned(),
                )
            })?;
        Ok(Self {
            reader,
            pending_read: None,
            staged: Vec::new(),
            staged_offset: 0,
            done: false,
        })
    }

    /// Request cancellation on the underlying browser reader.
    pub fn cancel_with_reason(&self, reason: &str) {
        let _ = self.reader.cancel_with_reason(&JsValue::from_str(reason));
    }
}

#[cfg(target_arch = "wasm32")]
impl Drop for WasmReadableStreamSource {
    fn drop(&mut self) {
        self.reader.release_lock();
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncRead for WasmReadableStreamSource {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let available = self.staged.len().saturating_sub(self.staged_offset);
        if available > 0 {
            let to_copy = available.min(buf.remaining());
            let start = self.staged_offset;
            let end = start + to_copy;
            buf.put_slice(&self.staged[start..end]);
            self.staged_offset = end;
            if self.staged_offset == self.staged.len() {
                self.staged.clear();
                self.staged_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        if self.done {
            return Poll::Ready(Ok(()));
        }

        if self.pending_read.is_none() {
            self.pending_read = Some(JsFuture::from(self.reader.read()));
        }

        let pending = self
            .pending_read
            .as_mut()
            .expect("pending_read initialized");
        match Pin::new(pending).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.pending_read = None;
                Poll::Ready(Err(js_host_io_error(
                    &err,
                    "ReadableStreamDefaultReader.read",
                )))
            }
            Poll::Ready(Ok(result)) => {
                self.pending_read = None;

                let done = Reflect::get(&result, &JsValue::from_str("done"))
                    .map_err(|err| js_host_io_error(&err, "ReadableStream read result.done"))?
                    .as_bool()
                    .unwrap_or(false);
                if done {
                    self.done = true;
                    return Poll::Ready(Ok(()));
                }

                let value = Reflect::get(&result, &JsValue::from_str("value"))
                    .map_err(|err| js_host_io_error(&err, "ReadableStream read result.value"))?;
                if value.is_null() || value.is_undefined() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                self.staged = Uint8Array::new(&value).to_vec();
                self.staged_offset = 0;
                if self.staged.is_empty() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                let to_copy = self.staged.len().min(buf.remaining());
                buf.put_slice(&self.staged[..to_copy]);
                self.staged_offset = to_copy;
                if self.staged_offset == self.staged.len() {
                    self.staged.clear();
                    self.staged_offset = 0;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
/// Host-backed writer for WHATWG `WritableStream` objects.
pub struct WasmWritableStreamSink {
    writer: WritableStreamDefaultWriter,
    pending_ready: Option<JsFuture>,
    pending_write: Option<(usize, JsFuture)>,
    pending_close: Option<JsFuture>,
    closed: bool,
}

#[cfg(target_arch = "wasm32")]
impl fmt::Debug for WasmWritableStreamSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmWritableStreamSink")
            .field("pending_ready", &self.pending_ready.is_some())
            .field("pending_write", &self.pending_write.is_some())
            .field("pending_close", &self.pending_close.is_some())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

#[cfg(target_arch = "wasm32")]
impl WasmWritableStreamSink {
    /// Construct from a browser `WritableStream`.
    pub fn new(stream: &WritableStream) -> Result<Self, BrowserStreamError> {
        let writer = stream.get_writer().map_err(|err| {
            BrowserStreamError::HostError(
                js_host_io_error(&err, "WritableStream.getWriter").to_string(),
            )
        })?;
        Ok(Self {
            writer,
            pending_ready: None,
            pending_write: None,
            pending_close: None,
            closed: false,
        })
    }

    /// Abort the underlying writer with a reason.
    pub fn abort_with_reason(&mut self, reason: &str) {
        let _ = self.writer.abort_with_reason(&JsValue::from_str(reason));
        self.closed = true;
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_ready.is_none() {
            self.pending_ready = Some(JsFuture::from(self.writer.ready()));
        }
        let pending = self
            .pending_ready
            .as_mut()
            .expect("pending_ready initialized");
        match Pin::new(pending).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.pending_ready = None;
                Poll::Ready(Err(js_host_io_error(
                    &err,
                    "WritableStreamDefaultWriter.ready",
                )))
            }
            Poll::Ready(Ok(_)) => {
                self.pending_ready = None;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_inflight_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some((_, pending)) = self.pending_write.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(pending).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.pending_write = None;
                Poll::Ready(Err(js_host_io_error(
                    &err,
                    "WritableStreamDefaultWriter.write",
                )))
            }
            Poll::Ready(Ok(_)) => {
                self.pending_write = None;
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl Drop for WasmWritableStreamSink {
    fn drop(&mut self) {
        self.writer.release_lock();
    }
}

#[cfg(target_arch = "wasm32")]
impl AsyncWrite for WasmWritableStreamSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "browser writable stream is closed",
            )));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some((requested, pending)) = self.pending_write.as_mut() {
            return match Pin::new(pending).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(err)) => {
                    self.pending_write = None;
                    Poll::Ready(Err(js_host_io_error(
                        &err,
                        "WritableStreamDefaultWriter.write",
                    )))
                }
                Poll::Ready(Ok(_)) => {
                    let written = *requested;
                    self.pending_write = None;
                    Poll::Ready(Ok(written))
                }
            };
        }

        match self.poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }

        let chunk = Uint8Array::new_with_length(buf.len() as u32);
        chunk.copy_from(buf);
        self.pending_write = Some((
            buf.len(),
            JsFuture::from(self.writer.write_with_chunk(&chunk.into())),
        ));

        match self.pending_write.as_mut() {
            Some((requested, pending)) => match Pin::new(pending).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(err)) => {
                    self.pending_write = None;
                    Poll::Ready(Err(js_host_io_error(
                        &err,
                        "WritableStreamDefaultWriter.write",
                    )))
                }
                Poll::Ready(Ok(_)) => {
                    let written = *requested;
                    self.pending_write = None;
                    Poll::Ready(Ok(written))
                }
            },
            None => Poll::Ready(Err(io::Error::other(
                "internal error: missing pending write after scheduling",
            ))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_inflight_write(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }
        self.poll_ready(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        match self.poll_inflight_write(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }

        match self.poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }

        if self.pending_close.is_none() {
            self.pending_close = Some(JsFuture::from(self.writer.close()));
        }

        let pending = self
            .pending_close
            .as_mut()
            .expect("pending_close initialized");
        match Pin::new(pending).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.pending_close = None;
                Poll::Ready(Err(js_host_io_error(
                    &err,
                    "WritableStreamDefaultWriter.close",
                )))
            }
            Poll::Ready(Ok(_)) => {
                self.pending_close = None;
                self.closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

// ============================================================================
// Browser ReadableStream bridge
// ============================================================================

/// Bridge from browser `ReadableStream` to asupersync `AsyncRead`.
///
/// This type models the readable side of a browser stream. On the actual
/// wasm32 target, the `source` callback would interface with
/// `ReadableStreamDefaultReader.read()` via wasm-bindgen. On native,
/// this is backed by any `AsyncRead` source for testing.
///
/// # Backpressure
///
/// Backpressure is naturally handled by `ReadBuf` capacity: the bridge
/// only requests as many bytes from the source as `ReadBuf::remaining()`
/// allows. The browser source can produce data at its own pace.
///
/// # Cancellation
///
/// Dropping the bridge cancels the underlying source. The `cancel_reason`
/// field records why the stream was cancelled (for diagnostics).
pub struct BrowserReadableStream<R> {
    source: R,
    state: BrowserStreamState,
    config: BrowserStreamConfig,
    total_read: u64,
    cancel_reason: Option<String>,
    accounting: StreamAccounting,
}

impl<R: fmt::Debug> fmt::Debug for BrowserReadableStream<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserReadableStream")
            .field("source", &self.source)
            .field("state", &self.state)
            .field("config", &self.config)
            .field("total_read", &self.total_read)
            .field("cancel_reason", &self.cancel_reason)
            .field("accounting", &self.accounting)
            .finish()
    }
}

impl<R> BrowserReadableStream<R> {
    /// Creates a new readable stream bridge wrapping the given source.
    pub fn new(source: R, config: BrowserStreamConfig) -> Self {
        Self::with_stats(source, config, None)
    }

    fn with_stats(source: R, config: BrowserStreamConfig, stats: Option<Arc<StreamStats>>) -> Self {
        Self {
            source,
            state: BrowserStreamState::Open,
            config,
            total_read: 0,
            cancel_reason: None,
            accounting: StreamAccounting::new(stats),
        }
    }

    /// Creates a bridge with default configuration.
    pub fn with_defaults(source: R) -> Self {
        Self::new(source, BrowserStreamConfig::default())
    }

    /// Returns the current stream state.
    #[must_use]
    pub fn state(&self) -> BrowserStreamState {
        self.state
    }

    /// Returns the total bytes read so far.
    #[must_use]
    pub fn total_read(&self) -> u64 {
        self.total_read
    }

    /// Cancels the stream with the given reason.
    ///
    /// After cancellation, all subsequent reads return `io::ErrorKind::ConnectionAborted`.
    pub fn cancel(&mut self, reason: impl Into<String>) {
        if self.state == BrowserStreamState::Open || self.state == BrowserStreamState::Closing {
            self.state = BrowserStreamState::Errored;
            self.cancel_reason = Some(reason.into());
            self.accounting.mark_aborted();
        }
    }

    /// Returns the cancel reason, if any.
    #[must_use]
    pub fn cancel_reason(&self) -> Option<&str> {
        self.cancel_reason.as_deref()
    }

    /// Returns a reference to the underlying source.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.source
    }

    /// Returns a mutable reference to the underlying source.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.source
    }

    /// Consumes the bridge and returns the underlying source.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.source
    }
}

#[cfg(target_arch = "wasm32")]
impl BrowserReadableStream<WasmReadableStreamSource> {
    /// Creates a browser-readable bridge backed by a real WHATWG `ReadableStream`.
    pub fn from_web_readable_stream(
        stream: &ReadableStream,
        config: BrowserStreamConfig,
    ) -> Result<Self, BrowserStreamError> {
        let source = WasmReadableStreamSource::new(stream)?;
        Ok(Self::new(source, config))
    }

    /// Creates a browser-readable bridge with default stream configuration.
    pub fn from_web_readable_stream_with_defaults(
        stream: &ReadableStream,
    ) -> Result<Self, BrowserStreamError> {
        Self::from_web_readable_stream(stream, BrowserStreamConfig::default())
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BrowserReadableStream<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // State checks
        match this.state {
            BrowserStreamState::Closed => {
                return Poll::Ready(Ok(())); // EOF
            }
            BrowserStreamState::Errored => {
                let reason = this.cancel_reason.as_deref().unwrap_or("stream errored");
                return Poll::Ready(Err(BrowserStreamError::Aborted(reason.to_owned()).into()));
            }
            BrowserStreamState::Closing | BrowserStreamState::Open => {}
        }

        // Check read limit
        if this.total_read >= this.config.max_total_read_bytes {
            this.state = BrowserStreamState::Errored;
            return Poll::Ready(Err(BrowserStreamError::ReadLimitExceeded {
                read: this.total_read,
                limit: this.config.max_total_read_bytes,
            }
            .into()));
        }

        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Compute per-read cap: min(buf remaining, chunk limit, budget remaining)
        let remaining = buf.remaining() as u64;
        let budget_remaining = this
            .config
            .max_total_read_bytes
            .saturating_sub(this.total_read);
        let effective_max = remaining
            .min(this.config.max_read_chunk as u64)
            .min(budget_remaining) as usize;

        if effective_max == 0 {
            this.state = BrowserStreamState::Closed;
            this.accounting.mark_closed();
            return Poll::Ready(Ok(()));
        }

        // If effective_max < remaining, we must cap the read via a temporary
        // buffer so the source cannot overshoot our limit. This branch is only
        // taken when we are near the total-byte budget or when max_read_chunk
        // is smaller than the caller's buffer — the common case goes direct.
        if effective_max < remaining as usize {
            let mut tmp_buf = ReadBuf::new(&mut buf.unfilled()[..effective_max]);
            let result = Pin::new(&mut this.source).poll_read(cx, &mut tmp_buf);
            match &result {
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    buf.advance(n);
                    this.total_read = this.total_read.saturating_add(n as u64);
                    if n == 0 {
                        this.state = BrowserStreamState::Closed;
                        this.accounting.mark_closed();
                    } else {
                        this.accounting.record_read_bytes(n);
                    }
                }
                Poll::Ready(Err(_)) => {
                    this.state = BrowserStreamState::Errored;
                    this.accounting.mark_aborted();
                }
                Poll::Pending => {}
            }
            result
        } else {
            // Direct read — no limiting needed
            let filled_before = buf.filled().len();
            let result = Pin::new(&mut this.source).poll_read(cx, buf);
            match &result {
                Poll::Ready(Ok(())) => {
                    let n = (buf.filled().len() - filled_before) as u64;
                    this.total_read = this.total_read.saturating_add(n);
                    if n == 0 {
                        this.state = BrowserStreamState::Closed;
                        this.accounting.mark_closed();
                    } else {
                        this.accounting.record_read_bytes(n as usize);
                    }
                }
                Poll::Ready(Err(_)) => {
                    this.state = BrowserStreamState::Errored;
                    this.accounting.mark_aborted();
                }
                Poll::Pending => {}
            }
            result
        }
    }
}

// ============================================================================
// Browser WritableStream bridge
// ============================================================================

/// Bridge from asupersync `AsyncWrite` to browser `WritableStream`.
///
/// This type models the writable side of a browser stream. On wasm32,
/// the `sink` would interface with `WritableStreamDefaultWriter` via
/// wasm-bindgen. On native, this wraps any `AsyncWrite` for testing.
///
/// # Backpressure
///
/// Backpressure is handled via the internal buffer and high-water mark:
/// - When `buffered < high_water_mark`: writes accepted immediately
/// - When `buffered >= high_water_mark`: `poll_write` returns `Poll::Pending`
///   until the sink drains below the mark
///
/// In unbuffered mode, every write goes directly to the sink.
///
/// # Cancellation
///
/// `abort(reason)` transitions the stream to `Errored` state and drops
/// any buffered data. `poll_shutdown` performs graceful close.
pub struct BrowserWritableStream<W> {
    sink: W,
    state: BrowserStreamState,
    config: BrowserStreamConfig,
    total_written: u64,
    buffered: usize,
    abort_reason: Option<String>,
    accounting: StreamAccounting,
}

impl<W: fmt::Debug> fmt::Debug for BrowserWritableStream<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserWritableStream")
            .field("sink", &self.sink)
            .field("state", &self.state)
            .field("config", &self.config)
            .field("total_written", &self.total_written)
            .field("buffered", &self.buffered)
            .field("abort_reason", &self.abort_reason)
            .field("accounting", &self.accounting)
            .finish()
    }
}

impl<W> BrowserWritableStream<W> {
    /// Creates a new writable stream bridge wrapping the given sink.
    pub fn new(sink: W, config: BrowserStreamConfig) -> Self {
        Self::with_stats(sink, config, None)
    }

    fn with_stats(sink: W, config: BrowserStreamConfig, stats: Option<Arc<StreamStats>>) -> Self {
        Self {
            sink,
            state: BrowserStreamState::Open,
            config,
            total_written: 0,
            buffered: 0,
            abort_reason: None,
            accounting: StreamAccounting::new(stats),
        }
    }

    /// Creates a bridge with default configuration.
    pub fn with_defaults(sink: W) -> Self {
        Self::new(sink, BrowserStreamConfig::default())
    }

    /// Returns the current stream state.
    #[must_use]
    pub fn state(&self) -> BrowserStreamState {
        self.state
    }

    /// Returns the total bytes written so far.
    #[must_use]
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Returns the current buffered byte count.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// Aborts the stream with the given reason.
    ///
    /// After abort, all subsequent writes return `io::ErrorKind::ConnectionAborted`.
    /// Any buffered data is discarded.
    pub fn abort(&mut self, reason: impl Into<String>) {
        if self.state == BrowserStreamState::Open || self.state == BrowserStreamState::Closing {
            self.state = BrowserStreamState::Errored;
            self.abort_reason = Some(reason.into());
            self.buffered = 0; // Discard buffered data on abort
            self.accounting.mark_aborted();
        }
    }

    /// Returns the abort reason, if any.
    #[must_use]
    pub fn abort_reason(&self) -> Option<&str> {
        self.abort_reason.as_deref()
    }

    /// Returns a reference to the underlying sink.
    #[must_use]
    pub fn get_ref(&self) -> &W {
        &self.sink
    }

    /// Returns a mutable reference to the underlying sink.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.sink
    }

    /// Consumes the bridge and returns the underlying sink.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.sink
    }

    /// Returns true if the backpressure threshold has been reached.
    #[must_use]
    pub fn is_backpressured(&self) -> bool {
        match self.config.write_backpressure {
            BackpressureStrategy::HighWaterMark(hwm) => self.buffered >= hwm,
            BackpressureStrategy::Unbuffered => false,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl BrowserWritableStream<WasmWritableStreamSink> {
    /// Creates a browser-writable bridge backed by a real WHATWG `WritableStream`.
    pub fn from_web_writable_stream(
        stream: &WritableStream,
        config: BrowserStreamConfig,
    ) -> Result<Self, BrowserStreamError> {
        let sink = WasmWritableStreamSink::new(stream)?;
        Ok(Self::new(sink, config))
    }

    /// Creates a browser-writable bridge with default stream configuration.
    pub fn from_web_writable_stream_with_defaults(
        stream: &WritableStream,
    ) -> Result<Self, BrowserStreamError> {
        Self::from_web_writable_stream(stream, BrowserStreamConfig::default())
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for BrowserWritableStream<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // State checks
        match this.state {
            BrowserStreamState::Closed | BrowserStreamState::Closing => {
                return Poll::Ready(Err(BrowserStreamError::ClosedDuringOperation.into()));
            }
            BrowserStreamState::Errored => {
                let reason = this.abort_reason.as_deref().unwrap_or("stream errored");
                return Poll::Ready(Err(BrowserStreamError::Aborted(reason.to_owned()).into()));
            }
            BrowserStreamState::Open => {}
        }

        // Check write limit
        if this.total_written >= this.config.max_total_write_bytes {
            this.state = BrowserStreamState::Errored;
            this.accounting.mark_aborted();
            return Poll::Ready(Err(BrowserStreamError::WriteLimitExceeded {
                written: this.total_written,
                limit: this.config.max_total_write_bytes,
            }
            .into()));
        }

        // Backpressure check
        if this.is_backpressured() {
            // Try to flush buffered data to make room
            match Pin::new(&mut this.sink).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    this.buffered = 0; // Flush succeeded, buffer drained
                }
                Poll::Ready(Err(e)) => {
                    this.state = BrowserStreamState::Errored;
                    this.accounting.mark_aborted();
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    // Still backpressured
                    return Poll::Pending;
                }
            }
        }

        // Compute how much we can write
        let budget_remaining = this
            .config
            .max_total_write_bytes
            .saturating_sub(this.total_written);

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if !this.config.allow_partial_writes && (buf.len() as u64) > budget_remaining {
            this.state = BrowserStreamState::Errored;
            this.accounting.mark_aborted();
            return Poll::Ready(Err(BrowserStreamError::WriteLimitExceeded {
                written: this.total_written,
                limit: this.config.max_total_write_bytes,
            }
            .into()));
        }

        let to_write = (buf.len() as u64).min(budget_remaining) as usize;

        if to_write == 0 {
            this.state = BrowserStreamState::Errored;
            this.accounting.mark_aborted();
            return Poll::Ready(Err(BrowserStreamError::WriteLimitExceeded {
                written: this.total_written,
                limit: this.config.max_total_write_bytes,
            }
            .into()));
        }

        // Write to the underlying sink
        let result = Pin::new(&mut this.sink).poll_write(cx, &buf[..to_write]);

        match &result {
            Poll::Ready(Ok(n)) => {
                this.total_written = this.total_written.saturating_add(*n as u64);
                this.buffered = this.buffered.saturating_add(*n);
                this.accounting.record_written_bytes(*n);
                if !this.config.allow_partial_writes && *n < to_write {
                    this.state = BrowserStreamState::Errored;
                    this.accounting.mark_aborted();
                    if *n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            format!(
                                "partial write not permitted by policy: wrote {n} of {to_write} bytes"
                            ),
                        )));
                    }

                    // Surface the committed prefix honestly, then fail closed on
                    // subsequent writes via the errored state.
                    return Poll::Ready(Ok(*n));
                }
            }
            Poll::Ready(Err(_)) => {
                this.state = BrowserStreamState::Errored;
                this.accounting.mark_aborted();
            }
            Poll::Pending => {}
        }

        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.state == BrowserStreamState::Errored {
            let reason = this.abort_reason.as_deref().unwrap_or("stream errored");
            return Poll::Ready(Err(BrowserStreamError::Aborted(reason.to_owned()).into()));
        }

        let result = Pin::new(&mut this.sink).poll_flush(cx);
        if matches!(&result, Poll::Ready(Ok(()))) {
            this.buffered = 0;
        } else if matches!(&result, Poll::Ready(Err(_))) {
            this.state = BrowserStreamState::Errored;
            this.accounting.mark_aborted();
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match this.state {
            BrowserStreamState::Closed => return Poll::Ready(Ok(())),
            BrowserStreamState::Errored => {
                let reason = this.abort_reason.as_deref().unwrap_or("stream errored");
                return Poll::Ready(Err(BrowserStreamError::Aborted(reason.to_owned()).into()));
            }
            _ => {
                this.state = BrowserStreamState::Closing;
            }
        }

        let result = Pin::new(&mut this.sink).poll_shutdown(cx);
        if matches!(&result, Poll::Ready(Ok(()))) {
            this.state = BrowserStreamState::Closed;
            this.buffered = 0;
            this.accounting.mark_closed();
        } else if matches!(&result, Poll::Ready(Err(_))) {
            this.state = BrowserStreamState::Errored;
            this.accounting.mark_aborted();
        }
        result
    }
}

// ============================================================================
// BrowserStreamIoCap: stream-oriented IoCap
// ============================================================================

/// Browser I/O capability for stream-oriented operations.
///
/// Extends the base `IoCap` with stream-specific policy enforcement
/// (backpressure strategy, size limits).
pub struct BrowserStreamIoCap {
    config: BrowserStreamConfig,
    stats: Arc<StreamStats>,
}

/// Stream operation statistics.
#[derive(Debug, Default)]
pub struct StreamStats {
    /// Total streams opened.
    pub streams_opened: std::sync::atomic::AtomicU64,
    /// Total streams closed cleanly.
    pub streams_closed: std::sync::atomic::AtomicU64,
    /// Total streams aborted.
    pub streams_aborted: std::sync::atomic::AtomicU64,
    /// Total bytes read across all streams.
    pub total_bytes_read: std::sync::atomic::AtomicU64,
    /// Total bytes written across all streams.
    pub total_bytes_written: std::sync::atomic::AtomicU64,
}

impl fmt::Debug for BrowserStreamIoCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserStreamIoCap")
            .field("config", &self.config)
            .field("stats", &self.stats)
            .finish()
    }
}

impl BrowserStreamIoCap {
    /// Creates a new stream I/O capability with the given configuration.
    #[must_use]
    pub fn new(config: BrowserStreamConfig) -> Self {
        Self {
            config,
            stats: Arc::new(StreamStats::default()),
        }
    }

    /// Returns the stream configuration.
    #[must_use]
    pub fn config(&self) -> &BrowserStreamConfig {
        &self.config
    }

    /// Returns stream statistics.
    #[must_use]
    pub fn stream_stats(&self) -> &StreamStats {
        &self.stats
    }

    /// Records that a stream was opened.
    pub fn record_open(&self) {
        self.stats
            .streams_opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Records that a stream was closed cleanly.
    pub fn record_close(&self) {
        self.stats
            .streams_closed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Records that a stream was aborted.
    pub fn record_abort(&self) {
        self.stats
            .streams_aborted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Wraps a source in a readable browser stream bridge using this capability policy.
    pub fn open_readable<R>(&self, source: R) -> BrowserReadableStream<R> {
        self.record_open();
        BrowserReadableStream::with_stats(
            source,
            self.config.clone(),
            Some(Arc::clone(&self.stats)),
        )
    }

    /// Wraps a sink in a writable browser stream bridge using this capability policy.
    pub fn open_writable<W>(&self, sink: W) -> BrowserWritableStream<W> {
        self.record_open();
        BrowserWritableStream::with_stats(sink, self.config.clone(), Some(Arc::clone(&self.stats)))
    }

    #[cfg(target_arch = "wasm32")]
    /// Wraps a WHATWG `ReadableStream` in a host-backed browser stream bridge.
    pub fn open_web_readable(
        &self,
        stream: &ReadableStream,
    ) -> Result<BrowserReadableStream<WasmReadableStreamSource>, BrowserStreamError> {
        self.record_open();
        let source = WasmReadableStreamSource::new(stream)?;
        Ok(BrowserReadableStream::with_stats(
            source,
            self.config.clone(),
            Some(Arc::clone(&self.stats)),
        ))
    }

    #[cfg(target_arch = "wasm32")]
    /// Wraps a WHATWG `WritableStream` in a host-backed browser stream bridge.
    pub fn open_web_writable(
        &self,
        stream: &WritableStream,
    ) -> Result<BrowserWritableStream<WasmWritableStreamSink>, BrowserStreamError> {
        self.record_open();
        let sink = WasmWritableStreamSink::new(stream)?;
        Ok(BrowserWritableStream::with_stats(
            sink,
            self.config.clone(),
            Some(Arc::clone(&self.stats)),
        ))
    }
}

impl IoCap for BrowserStreamIoCap {
    fn is_real_io(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "browser-stream"
    }

    fn capabilities(&self) -> IoCapabilities {
        IoCapabilities {
            file_ops: false,
            network_ops: true,
            timer_integration: true,
            deterministic: false,
        }
    }

    fn stats(&self) -> IoStats {
        let opened = self
            .stats
            .streams_opened
            .load(std::sync::atomic::Ordering::Relaxed);
        let completed = self
            .stats
            .streams_closed
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_add(
                self.stats
                    .streams_aborted
                    .load(std::sync::atomic::Ordering::Relaxed),
            );
        IoStats {
            submitted: opened,
            completed,
        }
    }
}

// ============================================================================
// Browser-native messaging wrappers
// ============================================================================

/// Browser-native message payload supported by the wrapper types in this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessagePayload {
    /// UTF-8 text payload.
    Text(String),
    /// Raw byte payload.
    Bytes(Vec<u8>),
}

/// State of a browser-native messaging wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserMessageState {
    /// Wrapper is open and can send/receive.
    Open,
    /// Wrapper was explicitly closed.
    Closed,
    /// Wrapper observed a host-side error.
    Errored,
}

/// Error returned by browser-native messaging wrapper operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessageError {
    /// Host API policy denied access to the messaging surface.
    Policy(HostApiPolicyError),
    /// Wrapper or peer is already closed.
    Closed,
    /// Wrapper was explicitly aborted or cancelled.
    Aborted(String),
    /// Host side returned an operation error.
    HostError(String),
    /// Incoming payload type was outside the supported wrapper contract.
    UnsupportedPayloadType,
}

impl fmt::Display for BrowserMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(error) => write!(f, "{error}"),
            Self::Closed => f.write_str("browser message wrapper is closed"),
            Self::Aborted(reason) => write!(f, "browser message wrapper aborted: {reason}"),
            Self::HostError(message) => write!(f, "browser host messaging error: {message}"),
            Self::UnsupportedPayloadType => f.write_str("unsupported browser message payload type"),
        }
    }
}

impl std::error::Error for BrowserMessageError {}

impl From<HostApiPolicyError> for BrowserMessageError {
    fn from(error: HostApiPolicyError) -> Self {
        Self::Policy(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QueuedBrowserMessage {
    Payload(BrowserMessagePayload),
    Error(BrowserMessageError),
}

fn authorize_message_channel_surface(cap: &dyn HostApiIoCap) -> Result<(), BrowserMessageError> {
    cap.authorize(&HostApiRequest::new(HostApiSurface::MessageChannel))
        .map_err(BrowserMessageError::Policy)
}

fn authorize_degraded_message_channel_surface(
    cap: &dyn HostApiIoCap,
) -> Result<(), BrowserMessageError> {
    cap.authorize(&HostApiRequest::new(HostApiSurface::MessageChannel).with_degraded_mode())
        .map_err(BrowserMessageError::Policy)
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[derive(Debug)]
struct InMemoryMessagePortState {
    inbox: Arc<Mutex<VecDeque<QueuedBrowserMessage>>>,
    peer_inbox: Arc<Mutex<VecDeque<QueuedBrowserMessage>>>,
    local_closed: Arc<AtomicBool>,
    peer_closed: Arc<AtomicBool>,
}

impl InMemoryMessagePortState {
    fn pair() -> (Self, Self) {
        let left_inbox = Arc::new(Mutex::new(VecDeque::new()));
        let right_inbox = Arc::new(Mutex::new(VecDeque::new()));
        let left_closed = Arc::new(AtomicBool::new(false));
        let right_closed = Arc::new(AtomicBool::new(false));

        (
            Self {
                inbox: Arc::clone(&left_inbox),
                peer_inbox: Arc::clone(&right_inbox),
                local_closed: Arc::clone(&left_closed),
                peer_closed: Arc::clone(&right_closed),
            },
            Self {
                inbox: right_inbox,
                peer_inbox: left_inbox,
                local_closed: right_closed,
                peer_closed: left_closed,
            },
        )
    }

    fn send(&self, message: &BrowserMessagePayload) -> Result<(), BrowserMessageError> {
        if self.local_closed.load(Ordering::Acquire) || self.peer_closed.load(Ordering::Acquire) {
            return Err(BrowserMessageError::Closed);
        }
        lock_or_recover(&self.peer_inbox).push_back(QueuedBrowserMessage::Payload(message.clone()));
        Ok(())
    }

    fn try_recv(&self) -> Option<QueuedBrowserMessage> {
        lock_or_recover(&self.inbox).pop_front()
    }

    fn close(&self) {
        self.local_closed.store(true, Ordering::Release);
    }
}

#[cfg(target_arch = "wasm32")]
const BROWSER_MESSAGE_EVENT: &str = "message";
#[cfg(target_arch = "wasm32")]
const BROWSER_MESSAGE_ERROR_EVENT: &str = "messageerror";

#[cfg(target_arch = "wasm32")]
fn attach_browser_message_listeners(
    target: &EventTarget,
    on_message: &wasm_bindgen::closure::Closure<dyn FnMut(MessageEvent)>,
    on_message_error: &wasm_bindgen::closure::Closure<dyn FnMut(MessageEvent)>,
    message_op: &str,
    message_error_op: &str,
) -> Result<(), BrowserMessageError> {
    target
        .add_event_listener_with_callback(
            BROWSER_MESSAGE_EVENT,
            on_message.as_ref().unchecked_ref(),
        )
        .map_err(|err| browser_message_host_error(&err, message_op))?;

    if let Err(err) = target.add_event_listener_with_callback(
        BROWSER_MESSAGE_ERROR_EVENT,
        on_message_error.as_ref().unchecked_ref(),
    ) {
        detach_browser_message_listeners(target, on_message, on_message_error);
        return Err(browser_message_host_error(&err, message_error_op));
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn detach_browser_message_listeners(
    target: &EventTarget,
    on_message: &wasm_bindgen::closure::Closure<dyn FnMut(MessageEvent)>,
    on_message_error: &wasm_bindgen::closure::Closure<dyn FnMut(MessageEvent)>,
) {
    let _ = target.remove_event_listener_with_callback(
        BROWSER_MESSAGE_EVENT,
        on_message.as_ref().unchecked_ref(),
    );
    let _ = target.remove_event_listener_with_callback(
        BROWSER_MESSAGE_ERROR_EVENT,
        on_message_error.as_ref().unchecked_ref(),
    );
}

#[cfg(target_arch = "wasm32")]
struct WasmMessagePortState {
    port: MessagePort,
    inbox: Rc<RefCell<VecDeque<QueuedBrowserMessage>>>,
    on_message: wasm_bindgen::closure::Closure<dyn FnMut(MessageEvent)>,
    on_message_error: wasm_bindgen::closure::Closure<dyn FnMut(MessageEvent)>,
}

#[cfg(target_arch = "wasm32")]
impl WasmMessagePortState {
    fn new(port: &MessagePort) -> Result<Self, BrowserMessageError> {
        let inbox = Rc::new(RefCell::new(VecDeque::new()));

        let inbox_for_message = Rc::clone(&inbox);
        let on_message =
            wasm_bindgen::closure::Closure::wrap(Box::new(move |event: MessageEvent| {
                let entry = decode_message_event(event)
                    .map_or_else(QueuedBrowserMessage::Error, QueuedBrowserMessage::Payload);
                inbox_for_message.borrow_mut().push_back(entry);
            }) as Box<dyn FnMut(MessageEvent)>);

        let inbox_for_error = Rc::clone(&inbox);
        let on_message_error =
            wasm_bindgen::closure::Closure::wrap(Box::new(move |_event: MessageEvent| {
                inbox_for_error
                    .borrow_mut()
                    .push_back(QueuedBrowserMessage::Error(BrowserMessageError::HostError(
                        "browser messageerror event".to_owned(),
                    )));
            }) as Box<dyn FnMut(MessageEvent)>);

        let target: &EventTarget = AsRef::<EventTarget>::as_ref(port);
        attach_browser_message_listeners(
            target,
            &on_message,
            &on_message_error,
            "MessagePort.addEventListener(message)",
            "MessagePort.addEventListener(messageerror)",
        )?;
        port.start();

        Ok(Self {
            port: port.clone(),
            inbox,
            on_message,
            on_message_error,
        })
    }

    fn send(&self, message: &BrowserMessagePayload) -> Result<(), BrowserMessageError> {
        let value = js_value_from_message_payload(message);
        self.port
            .post_message(&value)
            .map_err(|err| browser_message_host_error(&err, "MessagePort.postMessage"))
    }

    fn try_recv(&self) -> Option<QueuedBrowserMessage> {
        self.inbox.borrow_mut().pop_front()
    }

    fn close(&self) {
        let target: &EventTarget = AsRef::<EventTarget>::as_ref(&self.port);
        detach_browser_message_listeners(target, &self.on_message, &self.on_message_error);
        self.port.close();
    }
}

enum BrowserMessagePortBackend {
    InMemory(InMemoryMessagePortState),
    #[cfg(target_arch = "wasm32")]
    Host(WasmMessagePortState),
}

/// Explicit wrapper around a browser-native `MessagePort`.
///
/// This models the browser host messaging surface directly. It is not an
/// asupersync task/channel primitive, and it does not imply worker-runtime
/// support outside the explicit browser host capability boundary.
pub struct BrowserMessagePort {
    state: BrowserMessageState,
    terminal_error: Option<BrowserMessageError>,
    backend: BrowserMessagePortBackend,
}

impl fmt::Debug for BrowserMessagePort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserMessagePort")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl BrowserMessagePort {
    fn from_in_memory(state: InMemoryMessagePortState) -> Self {
        Self {
            state: BrowserMessageState::Open,
            terminal_error: None,
            backend: BrowserMessagePortBackend::InMemory(state),
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn from_host(port: &MessagePort) -> Result<Self, BrowserMessageError> {
        Ok(Self {
            state: BrowserMessageState::Open,
            terminal_error: None,
            backend: BrowserMessagePortBackend::Host(WasmMessagePortState::new(port)?),
        })
    }

    /// Wrap an existing browser `MessagePort` after explicit authority checks.
    #[cfg(target_arch = "wasm32")]
    pub fn from_web_message_port(
        cap: &dyn HostApiIoCap,
        port: &MessagePort,
    ) -> Result<Self, BrowserMessageError> {
        authorize_message_channel_surface(cap)?;
        Self::from_host(port)
    }

    /// Returns the current wrapper state.
    #[must_use]
    pub fn state(&self) -> BrowserMessageState {
        self.state
    }

    /// Returns the terminal error, if the wrapper has entered `Errored`.
    #[must_use]
    pub fn error(&self) -> Option<&BrowserMessageError> {
        self.terminal_error.as_ref()
    }

    /// Aborts the wrapped message port and records a stable terminal error.
    pub fn abort(&mut self, reason: impl Into<String>) {
        let error = BrowserMessageError::Aborted(reason.into());
        self.fail(error);
    }

    /// Sends a payload through the wrapped message port.
    pub fn send(&mut self, message: &BrowserMessagePayload) -> Result<(), BrowserMessageError> {
        match self.state {
            BrowserMessageState::Closed => return Err(BrowserMessageError::Closed),
            BrowserMessageState::Errored => return Err(self.current_error()),
            BrowserMessageState::Open => {}
        }

        let result = match &self.backend {
            BrowserMessagePortBackend::InMemory(state) => state.send(message),
            #[cfg(target_arch = "wasm32")]
            BrowserMessagePortBackend::Host(state) => state.send(message),
        };

        if let Err(error) = &result {
            match error {
                BrowserMessageError::Closed => {
                    self.close_backend();
                    self.state = BrowserMessageState::Closed;
                }
                _ => self.fail(error.clone()),
            }
        }

        result
    }

    /// Attempts to receive one queued payload without blocking.
    pub fn try_recv(&mut self) -> Result<Option<BrowserMessagePayload>, BrowserMessageError> {
        match self.state {
            BrowserMessageState::Closed => return Err(BrowserMessageError::Closed),
            BrowserMessageState::Errored => return Err(self.current_error()),
            BrowserMessageState::Open => {}
        }

        let next = match &self.backend {
            BrowserMessagePortBackend::InMemory(state) => state.try_recv(),
            #[cfg(target_arch = "wasm32")]
            BrowserMessagePortBackend::Host(state) => state.try_recv(),
        };

        match next {
            Some(QueuedBrowserMessage::Payload(payload)) => Ok(Some(payload)),
            Some(QueuedBrowserMessage::Error(error)) => {
                self.fail(error.clone());
                Err(error)
            }
            None => Ok(None),
        }
    }

    /// Closes the wrapped message port.
    pub fn close(&mut self) {
        if self.state == BrowserMessageState::Closed {
            return;
        }
        self.close_backend();
        if self.state != BrowserMessageState::Errored {
            self.state = BrowserMessageState::Closed;
        }
    }

    fn fail(&mut self, error: BrowserMessageError) {
        if self.state == BrowserMessageState::Errored {
            return;
        }
        self.close_backend();
        self.terminal_error = Some(error);
        self.state = BrowserMessageState::Errored;
    }

    fn current_error(&self) -> BrowserMessageError {
        self.terminal_error.clone().unwrap_or_else(|| {
            BrowserMessageError::HostError("browser message wrapper is errored".to_owned())
        })
    }

    fn close_backend(&self) {
        match &self.backend {
            BrowserMessagePortBackend::InMemory(state) => state.close(),
            #[cfg(target_arch = "wasm32")]
            BrowserMessagePortBackend::Host(state) => state.close(),
        }
    }
}

impl Drop for BrowserMessagePort {
    fn drop(&mut self) {
        if self.state != BrowserMessageState::Closed {
            self.close_backend();
        }
    }
}

/// Explicit wrapper around a browser-native `MessageChannel`.
#[derive(Debug)]
pub struct BrowserMessageChannelPair {
    left: BrowserMessagePort,
    right: BrowserMessagePort,
}

/// Alias for the explicit browser-native `MessageChannel` wrapper pair.
pub type BrowserMessageChannel = BrowserMessageChannelPair;

impl BrowserMessageChannelPair {
    /// Creates a new explicit browser-native message channel pair.
    pub fn open(cap: &dyn HostApiIoCap) -> Result<Self, BrowserMessageError> {
        #[cfg(target_arch = "wasm32")]
        {
            authorize_message_channel_surface(cap)?;
            let channel = MessageChannel::new()
                .map_err(|err| browser_message_host_error(&err, "MessageChannel::new"))?;
            let left_port = channel.port1();
            let right_port = channel.port2();
            return Ok(Self {
                left: BrowserMessagePort::from_host(&left_port)?,
                right: BrowserMessagePort::from_host(&right_port)?,
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            authorize_degraded_message_channel_surface(cap)?;
            let (left, right) = InMemoryMessagePortState::pair();
            Ok(Self {
                left: BrowserMessagePort::from_in_memory(left),
                right: BrowserMessagePort::from_in_memory(right),
            })
        }
    }

    /// Splits the pair into its two explicit message-port wrappers.
    #[must_use]
    pub fn split(self) -> (BrowserMessagePort, BrowserMessagePort) {
        (self.left, self.right)
    }
}

impl BrowserHostApiIoCap {
    /// Opens an explicit browser-native message-channel wrapper pair.
    pub fn open_message_channel(&self) -> Result<BrowserMessageChannelPair, BrowserMessageError> {
        BrowserMessageChannelPair::open(self)
    }

    /// Opens an explicit browser-native broadcast-channel wrapper.
    pub fn open_broadcast_channel(
        &self,
        name: impl Into<String>,
    ) -> Result<BrowserBroadcastChannel, BrowserMessageError> {
        BrowserBroadcastChannel::open(self, name)
    }

    /// Wraps an existing browser-native `MessagePort`.
    #[cfg(target_arch = "wasm32")]
    pub fn wrap_message_port(
        &self,
        port: &MessagePort,
    ) -> Result<BrowserMessagePort, BrowserMessageError> {
        BrowserMessagePort::from_web_message_port(self, port)
    }
}

#[derive(Debug, Clone)]
struct InMemoryBroadcastSubscriber {
    id: u64,
    inbox: Arc<Mutex<VecDeque<QueuedBrowserMessage>>>,
    closed: Arc<AtomicBool>,
}

static NEXT_IN_MEMORY_BROADCAST_ID: AtomicU64 = AtomicU64::new(1);

fn in_memory_broadcast_registry()
-> &'static Mutex<BTreeMap<String, Vec<InMemoryBroadcastSubscriber>>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<String, Vec<InMemoryBroadcastSubscriber>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[derive(Debug)]
struct InMemoryBroadcastChannelState {
    name: String,
    id: u64,
    inbox: Arc<Mutex<VecDeque<QueuedBrowserMessage>>>,
    closed: Arc<AtomicBool>,
}

impl InMemoryBroadcastChannelState {
    fn open(name: impl Into<String>) -> Self {
        let name = name.into();
        let id = NEXT_IN_MEMORY_BROADCAST_ID.fetch_add(1, Ordering::Relaxed);
        let inbox = Arc::new(Mutex::new(VecDeque::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let subscriber = InMemoryBroadcastSubscriber {
            id,
            inbox: Arc::clone(&inbox),
            closed: Arc::clone(&closed),
        };
        lock_or_recover(in_memory_broadcast_registry())
            .entry(name.clone())
            .or_default()
            .push(subscriber);
        Self {
            name,
            id,
            inbox,
            closed,
        }
    }

    fn send(&self, message: &BrowserMessagePayload) -> Result<(), BrowserMessageError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(BrowserMessageError::Closed);
        }

        let mut registry = lock_or_recover(in_memory_broadcast_registry());
        if let Some(subscribers) = registry.get_mut(&self.name) {
            subscribers.retain(|subscriber| !subscriber.closed.load(Ordering::Acquire));
            for subscriber in subscribers.iter() {
                if subscriber.id == self.id {
                    continue;
                }
                lock_or_recover(&subscriber.inbox)
                    .push_back(QueuedBrowserMessage::Payload(message.clone()));
            }
        }
        drop(registry);
        Ok(())
    }

    fn try_recv(&self) -> Option<QueuedBrowserMessage> {
        lock_or_recover(&self.inbox).pop_front()
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let mut registry = lock_or_recover(in_memory_broadcast_registry());
        if let Some(subscribers) = registry.get_mut(&self.name) {
            subscribers.retain(|subscriber| {
                subscriber.id != self.id && !subscriber.closed.load(Ordering::Acquire)
            });
            if subscribers.is_empty() {
                registry.remove(&self.name);
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
struct WasmBroadcastChannelState {
    channel: BroadcastChannel,
    inbox: Rc<RefCell<VecDeque<QueuedBrowserMessage>>>,
    on_message: wasm_bindgen::closure::Closure<dyn FnMut(MessageEvent)>,
    on_message_error: wasm_bindgen::closure::Closure<dyn FnMut(MessageEvent)>,
}

#[cfg(target_arch = "wasm32")]
impl WasmBroadcastChannelState {
    fn open(name: &str) -> Result<Self, BrowserMessageError> {
        let channel = BroadcastChannel::new(name)
            .map_err(|err| browser_message_host_error(&err, "BroadcastChannel::new"))?;
        let inbox = Rc::new(RefCell::new(VecDeque::new()));

        let inbox_for_message = Rc::clone(&inbox);
        let on_message =
            wasm_bindgen::closure::Closure::wrap(Box::new(move |event: MessageEvent| {
                let entry = decode_message_event(event)
                    .map_or_else(QueuedBrowserMessage::Error, QueuedBrowserMessage::Payload);
                inbox_for_message.borrow_mut().push_back(entry);
            }) as Box<dyn FnMut(MessageEvent)>);

        let inbox_for_error = Rc::clone(&inbox);
        let on_message_error =
            wasm_bindgen::closure::Closure::wrap(Box::new(move |_event: MessageEvent| {
                inbox_for_error
                    .borrow_mut()
                    .push_back(QueuedBrowserMessage::Error(BrowserMessageError::HostError(
                        "broadcast channel messageerror event".to_owned(),
                    )));
            }) as Box<dyn FnMut(MessageEvent)>);

        let target: &EventTarget = AsRef::<EventTarget>::as_ref(&channel);
        attach_browser_message_listeners(
            target,
            &on_message,
            &on_message_error,
            "BroadcastChannel.addEventListener(message)",
            "BroadcastChannel.addEventListener(messageerror)",
        )?;

        Ok(Self {
            channel,
            inbox,
            on_message,
            on_message_error,
        })
    }

    fn send(&self, message: &BrowserMessagePayload) -> Result<(), BrowserMessageError> {
        let value = js_value_from_message_payload(message);
        self.channel
            .post_message(&value)
            .map_err(|err| browser_message_host_error(&err, "BroadcastChannel.postMessage"))
    }

    fn try_recv(&self) -> Option<QueuedBrowserMessage> {
        self.inbox.borrow_mut().pop_front()
    }

    fn close(&self) {
        let target: &EventTarget = AsRef::<EventTarget>::as_ref(&self.channel);
        detach_browser_message_listeners(target, &self.on_message, &self.on_message_error);
        self.channel.close();
    }
}

enum BrowserBroadcastChannelBackend {
    InMemory(InMemoryBroadcastChannelState),
    #[cfg(target_arch = "wasm32")]
    Host(WasmBroadcastChannelState),
}

/// Explicit wrapper around a browser-native `BroadcastChannel`.
///
/// This is an explicit browser host messaging surface, not a worker-runtime
/// abstraction and not a bridge-only adapter for unsupported runtimes.
pub struct BrowserBroadcastChannel {
    state: BrowserMessageState,
    name: String,
    terminal_error: Option<BrowserMessageError>,
    backend: BrowserBroadcastChannelBackend,
}

impl fmt::Debug for BrowserBroadcastChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserBroadcastChannel")
            .field("state", &self.state)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl BrowserBroadcastChannel {
    /// Opens a browser-native broadcast channel wrapper after explicit authority checks.
    pub fn open(
        cap: &dyn HostApiIoCap,
        name: impl Into<String>,
    ) -> Result<Self, BrowserMessageError> {
        let name = name.into();

        #[cfg(target_arch = "wasm32")]
        {
            authorize_message_channel_surface(cap)?;
            let backend = WasmBroadcastChannelState::open(&name)?;
            return Ok(Self {
                state: BrowserMessageState::Open,
                name,
                terminal_error: None,
                backend: BrowserBroadcastChannelBackend::Host(backend),
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            authorize_degraded_message_channel_surface(cap)?;
            Ok(Self {
                state: BrowserMessageState::Open,
                name: name.clone(),
                terminal_error: None,
                backend: BrowserBroadcastChannelBackend::InMemory(
                    InMemoryBroadcastChannelState::open(name),
                ),
            })
        }
    }

    /// Returns the current wrapper state.
    #[must_use]
    pub fn state(&self) -> BrowserMessageState {
        self.state
    }

    /// Returns the logical broadcast-channel name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the terminal error, if the wrapper has entered `Errored`.
    #[must_use]
    pub fn error(&self) -> Option<&BrowserMessageError> {
        self.terminal_error.as_ref()
    }

    /// Aborts the wrapped broadcast channel and records a stable terminal error.
    pub fn abort(&mut self, reason: impl Into<String>) {
        let error = BrowserMessageError::Aborted(reason.into());
        self.fail(error);
    }

    /// Sends a payload to the wrapped broadcast channel.
    pub fn send(&mut self, message: &BrowserMessagePayload) -> Result<(), BrowserMessageError> {
        match self.state {
            BrowserMessageState::Closed => return Err(BrowserMessageError::Closed),
            BrowserMessageState::Errored => return Err(self.current_error()),
            BrowserMessageState::Open => {}
        }

        let result = match &self.backend {
            BrowserBroadcastChannelBackend::InMemory(state) => state.send(message),
            #[cfg(target_arch = "wasm32")]
            BrowserBroadcastChannelBackend::Host(state) => state.send(message),
        };

        if let Err(error) = &result {
            match error {
                BrowserMessageError::Closed => {
                    self.close_backend();
                    self.state = BrowserMessageState::Closed;
                }
                _ => self.fail(error.clone()),
            }
        }

        result
    }

    /// Attempts to receive one queued broadcast payload without blocking.
    pub fn try_recv(&mut self) -> Result<Option<BrowserMessagePayload>, BrowserMessageError> {
        match self.state {
            BrowserMessageState::Closed => return Err(BrowserMessageError::Closed),
            BrowserMessageState::Errored => return Err(self.current_error()),
            BrowserMessageState::Open => {}
        }

        let next = match &self.backend {
            BrowserBroadcastChannelBackend::InMemory(state) => state.try_recv(),
            #[cfg(target_arch = "wasm32")]
            BrowserBroadcastChannelBackend::Host(state) => state.try_recv(),
        };

        match next {
            Some(QueuedBrowserMessage::Payload(payload)) => Ok(Some(payload)),
            Some(QueuedBrowserMessage::Error(error)) => {
                self.fail(error.clone());
                Err(error)
            }
            None => Ok(None),
        }
    }

    /// Closes the wrapped broadcast channel.
    pub fn close(&mut self) {
        if self.state == BrowserMessageState::Closed {
            return;
        }
        self.close_backend();
        if self.state != BrowserMessageState::Errored {
            self.state = BrowserMessageState::Closed;
        }
    }

    fn fail(&mut self, error: BrowserMessageError) {
        if self.state == BrowserMessageState::Errored {
            return;
        }
        self.close_backend();
        self.terminal_error = Some(error);
        self.state = BrowserMessageState::Errored;
    }

    fn current_error(&self) -> BrowserMessageError {
        self.terminal_error.clone().unwrap_or_else(|| {
            BrowserMessageError::HostError("browser broadcast wrapper is errored".to_owned())
        })
    }

    fn close_backend(&self) {
        match &self.backend {
            BrowserBroadcastChannelBackend::InMemory(state) => state.close(),
            #[cfg(target_arch = "wasm32")]
            BrowserBroadcastChannelBackend::Host(state) => state.close(),
        }
    }
}

impl Drop for BrowserBroadcastChannel {
    fn drop(&mut self) {
        if self.state != BrowserMessageState::Closed {
            self.close_backend();
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn browser_message_host_error(err: &JsValue, op: &str) -> BrowserMessageError {
    BrowserMessageError::HostError(js_host_io_error(err, op).to_string())
}

#[cfg(target_arch = "wasm32")]
fn js_value_from_message_payload(message: &BrowserMessagePayload) -> JsValue {
    match message {
        BrowserMessagePayload::Text(text) => JsValue::from_str(text),
        BrowserMessagePayload::Bytes(bytes) => Uint8Array::from(bytes.as_slice()).into(),
    }
}

#[cfg(target_arch = "wasm32")]
fn decode_message_event(event: MessageEvent) -> Result<BrowserMessagePayload, BrowserMessageError> {
    let data = event.data();
    if let Some(text) = data.as_string() {
        return Ok(BrowserMessagePayload::Text(text));
    }
    if data.is_instance_of::<Uint8Array>() || data.is_instance_of::<ArrayBuffer>() {
        return Ok(BrowserMessagePayload::Bytes(
            Uint8Array::new(&data).to_vec(),
        ));
    }
    Err(BrowserMessageError::UnsupportedPayloadType)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::cap::HostApiAuthority;
    use std::io::Cursor;

    // A simple in-memory AsyncWrite for testing
    #[derive(Debug, Default)]
    struct MemSink {
        data: Vec<u8>,
        flush_count: u32,
        shutdown: bool,
    }

    impl AsyncWrite for MemSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flush_count += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown = true;
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Default)]
    struct PartialSink {
        data: Vec<u8>,
        max_chunk: usize,
    }

    impl AsyncWrite for PartialSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let chunk = buf.len().min(self.max_chunk.max(1));
            self.data.extend_from_slice(&buf[..chunk]);
            Poll::Ready(Ok(chunk))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn strict_message_host_cap() -> BrowserHostApiIoCap {
        BrowserHostApiIoCap::new(
            HostApiAuthority::deny_all().grant_surface(HostApiSurface::MessageChannel),
            true,
        )
    }

    fn degraded_message_host_cap() -> BrowserHostApiIoCap {
        BrowserHostApiIoCap::new(
            HostApiAuthority::deny_all()
                .grant_surface(HostApiSurface::MessageChannel)
                .with_degraded_mode_allowed(),
            true,
        )
    }

    // -- BrowserStreamState --

    #[test]
    fn stream_state_display() {
        assert_eq!(BrowserStreamState::Open.to_string(), "open");
        assert_eq!(BrowserStreamState::Closing.to_string(), "closing");
        assert_eq!(BrowserStreamState::Closed.to_string(), "closed");
        assert_eq!(BrowserStreamState::Errored.to_string(), "errored");
    }

    // -- BackpressureStrategy --

    #[test]
    fn backpressure_default_is_64kb_hwm() {
        let bp = BackpressureStrategy::default();
        assert_eq!(bp, BackpressureStrategy::HighWaterMark(65_536));
    }

    // -- BrowserStreamConfig --

    #[test]
    fn config_defaults_are_reasonable() {
        let config = BrowserStreamConfig::default();
        assert_eq!(config.max_read_chunk, 65_536);
        assert_eq!(config.max_total_read_bytes, 16 << 20); // 16MB
        assert_eq!(config.max_total_write_bytes, 4 << 20); // 4MB
        assert!(config.allow_partial_writes);
    }

    // -- BrowserStreamError --

    #[test]
    fn stream_error_display() {
        let err = BrowserStreamError::Aborted("user navigated".into());
        assert!(err.to_string().contains("user navigated"));

        let err = BrowserStreamError::ReadLimitExceeded {
            read: 100,
            limit: 50,
        };
        assert!(err.to_string().contains("100/50"));

        let err = BrowserStreamError::ClosedDuringOperation;
        assert!(err.to_string().contains("closed during"));
    }

    #[test]
    fn stream_error_to_io_error() {
        let aborted: io::Error = BrowserStreamError::Aborted("nav".into()).into();
        assert_eq!(aborted.kind(), io::ErrorKind::ConnectionAborted);

        let closed: io::Error = BrowserStreamError::ClosedDuringOperation.into();
        assert_eq!(closed.kind(), io::ErrorKind::BrokenPipe);

        let bp: io::Error = BrowserStreamError::BackpressureFull.into();
        assert_eq!(bp.kind(), io::ErrorKind::WouldBlock);
    }

    // -- BrowserReadableStream --

    #[test]
    fn readable_stream_reads_from_source() {
        let source = Cursor::new(b"hello browser world".to_vec());
        let mut stream = BrowserReadableStream::with_defaults(source);

        assert_eq!(stream.state(), BrowserStreamState::Open);
        assert_eq!(stream.total_read(), 0);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);

        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"hello browser world");
        assert_eq!(stream.total_read(), 19);
    }

    #[test]
    fn readable_stream_reaches_eof() {
        let source = Cursor::new(b"short".to_vec());
        let mut stream = BrowserReadableStream::with_defaults(source);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First read
        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);
        let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert_eq!(read_buf.filled(), b"short");

        // Second read: EOF
        let mut buf2 = [0u8; 64];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf2);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf2.filled().len(), 0);
        assert_eq!(stream.state(), BrowserStreamState::Closed);
    }

    #[test]
    fn readable_stream_cancel_produces_error() {
        let source = Cursor::new(b"data".to_vec());
        let mut stream = BrowserReadableStream::with_defaults(source);

        stream.cancel("user navigated away");
        assert_eq!(stream.state(), BrowserStreamState::Errored);
        assert_eq!(stream.cancel_reason(), Some("user navigated away"));

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);

        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn readable_stream_enforces_read_limit() {
        let source = Cursor::new(vec![0u8; 1000]);
        let config = BrowserStreamConfig {
            max_total_read_bytes: 10,
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserReadableStream::new(source, config);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First read: ok (reads up to 10 bytes)
        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 10); // Capped at budget

        // Second read: limit exceeded
        let mut buf2 = [0u8; 64];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf2);
        assert!(matches!(result, Poll::Ready(Err(_))));
        assert_eq!(stream.state(), BrowserStreamState::Errored);
    }

    #[test]
    fn readable_stream_inner_access() {
        let source = Cursor::new(b"data".to_vec());
        let stream = BrowserReadableStream::with_defaults(source);

        assert_eq!(stream.get_ref().position(), 0);
        let inner = stream.into_inner();
        assert_eq!(inner.position(), 0);
    }

    // -- BrowserWritableStream --

    #[test]
    fn writable_stream_writes_to_sink() {
        let sink = MemSink::default();
        let mut stream = BrowserWritableStream::with_defaults(sink);

        assert_eq!(stream.state(), BrowserStreamState::Open);
        assert_eq!(stream.total_written(), 0);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"hello");
        assert!(matches!(result, Poll::Ready(Ok(5))));
        assert_eq!(stream.total_written(), 5);
        assert_eq!(stream.get_ref().data, b"hello");
    }

    #[test]
    fn writable_stream_flush_resets_buffer() {
        let sink = MemSink::default();
        let mut stream = BrowserWritableStream::with_defaults(sink);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = Pin::new(&mut stream).poll_write(&mut cx, b"data");
        assert!(stream.buffered() > 0);

        let _ = Pin::new(&mut stream).poll_flush(&mut cx);
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.get_ref().flush_count, 1);
    }

    #[test]
    fn writable_stream_shutdown_transitions_to_closed() {
        let sink = MemSink::default();
        let mut stream = BrowserWritableStream::with_defaults(sink);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut stream).poll_shutdown(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(stream.state(), BrowserStreamState::Closed);
        assert!(stream.get_ref().shutdown);
    }

    #[test]
    fn writable_stream_abort_transitions_to_errored() {
        let sink = MemSink::default();
        let mut stream = BrowserWritableStream::with_defaults(sink);

        stream.abort("AbortController.abort()");
        assert_eq!(stream.state(), BrowserStreamState::Errored);
        assert_eq!(stream.abort_reason(), Some("AbortController.abort()"));
        assert_eq!(stream.buffered(), 0); // Buffer cleared on abort

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"nope");
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn writable_stream_enforces_write_limit() {
        let sink = MemSink::default();
        let config = BrowserStreamConfig {
            max_total_write_bytes: 8,
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserWritableStream::new(sink, config);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First write: ok (8 bytes budget)
        let result = Pin::new(&mut stream).poll_write(&mut cx, b"12345678");
        assert!(matches!(result, Poll::Ready(Ok(8))));

        // Second write: limit exceeded
        let result = Pin::new(&mut stream).poll_write(&mut cx, b"X");
        assert!(matches!(result, Poll::Ready(Err(_))));
        assert_eq!(stream.state(), BrowserStreamState::Errored);
    }

    #[test]
    fn writable_stream_write_after_close_fails() {
        let sink = MemSink::default();
        let mut stream = BrowserWritableStream::with_defaults(sink);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = Pin::new(&mut stream).poll_shutdown(&mut cx);

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"too late");
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn writable_stream_inner_access() {
        let sink = MemSink::default();
        let stream = BrowserWritableStream::with_defaults(sink);
        assert!(stream.get_ref().data.is_empty());
        let inner = stream.into_inner();
        assert!(inner.data.is_empty());
    }

    #[test]
    fn writable_stream_backpressure_detection() {
        let sink = MemSink::default();
        let config = BrowserStreamConfig {
            write_backpressure: BackpressureStrategy::HighWaterMark(4),
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserWritableStream::new(sink, config);

        assert!(!stream.is_backpressured());

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write 4 bytes → at high water mark
        let _ = Pin::new(&mut stream).poll_write(&mut cx, b"1234");
        assert!(stream.is_backpressured());

        // Flush → buffer cleared
        let _ = Pin::new(&mut stream).poll_flush(&mut cx);
        assert!(!stream.is_backpressured());
    }

    #[test]
    fn writable_stream_abort_clears_backpressure_state() {
        let sink = MemSink::default();
        let config = BrowserStreamConfig {
            write_backpressure: BackpressureStrategy::HighWaterMark(4),
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserWritableStream::new(sink, config);

        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = Pin::new(&mut stream).poll_write(&mut cx, b"1234");
        assert!(stream.is_backpressured());

        stream.abort("route change");
        assert_eq!(stream.abort_reason(), Some("route change"));
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.state(), BrowserStreamState::Errored);
        assert!(!stream.is_backpressured());

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"5");
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn writable_stream_allows_partial_write_when_configured() {
        let sink = PartialSink {
            data: Vec::new(),
            max_chunk: 2,
        };
        let config = BrowserStreamConfig {
            allow_partial_writes: true,
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserWritableStream::new(sink, config);
        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"hello");
        assert!(matches!(result, Poll::Ready(Ok(2))));
        assert_eq!(stream.total_written(), 2);
    }

    #[test]
    fn writable_stream_partial_write_when_disallowed_surfaces_prefix_and_errors_later() {
        let sink = PartialSink {
            data: Vec::new(),
            max_chunk: 2,
        };
        let config = BrowserStreamConfig {
            allow_partial_writes: false,
            ..BrowserStreamConfig::default()
        };
        let mut stream = BrowserWritableStream::new(sink, config);
        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"hello");
        assert!(matches!(result, Poll::Ready(Ok(2))));
        assert_eq!(stream.state(), BrowserStreamState::Errored);
        assert_eq!(stream.total_written(), 2);
        assert_eq!(stream.get_ref().data, b"he");

        let retry = Pin::new(&mut stream).poll_write(&mut cx, b"llo");
        assert!(matches!(retry, Poll::Ready(Err(_))));
        assert_eq!(stream.get_ref().data, b"he");
    }

    // -- BrowserStreamIoCap --

    #[test]
    fn stream_io_cap_tracks_stats() {
        let cap = BrowserStreamIoCap::new(BrowserStreamConfig::default());

        cap.record_open();
        cap.record_open();
        cap.record_close();
        cap.record_abort();

        let stats = cap.stream_stats();
        assert_eq!(
            stats
                .streams_opened
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            stats
                .streams_closed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .streams_aborted
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn stream_io_cap_opens_bridges_with_config() {
        let cap = BrowserStreamIoCap::new(BrowserStreamConfig {
            max_read_chunk: 8,
            max_total_read_bytes: 128,
            ..BrowserStreamConfig::default()
        });
        let reader = cap.open_readable(Cursor::new(b"abc".to_vec()));
        assert_eq!(reader.state(), BrowserStreamState::Open);
        assert_eq!(reader.total_read(), 0);
        assert_eq!(
            cap.stream_stats()
                .streams_opened
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn stream_io_cap_readable_bridge_updates_bytes_and_close_stats() {
        let cap = BrowserStreamIoCap::new(BrowserStreamConfig::default());
        let mut reader = cap.open_readable(Cursor::new(b"abc".to_vec()));
        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"abc");

        let mut eof_buf = [0u8; 8];
        let mut eof_read_buf = ReadBuf::new(&mut eof_buf);
        let eof = Pin::new(&mut reader).poll_read(&mut cx, &mut eof_read_buf);
        assert!(matches!(eof, Poll::Ready(Ok(()))));
        assert_eq!(reader.state(), BrowserStreamState::Closed);

        let stats = cap.stream_stats();
        assert_eq!(
            stats
                .total_bytes_read
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
        assert_eq!(
            stats
                .streams_closed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .streams_aborted
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn stream_io_cap_writable_bridge_updates_bytes_and_close_stats() {
        let cap = BrowserStreamIoCap::new(BrowserStreamConfig::default());
        let mut writer = cap.open_writable(MemSink::default());
        let waker = futures_task_noop_waker();
        let mut cx = Context::from_waker(&waker);

        let wrote = Pin::new(&mut writer).poll_write(&mut cx, b"hello");
        assert!(matches!(wrote, Poll::Ready(Ok(5))));
        let shutdown = Pin::new(&mut writer).poll_shutdown(&mut cx);
        assert!(matches!(shutdown, Poll::Ready(Ok(()))));
        assert_eq!(writer.state(), BrowserStreamState::Closed);

        let stats = cap.stream_stats();
        assert_eq!(
            stats
                .total_bytes_written
                .load(std::sync::atomic::Ordering::Relaxed),
            5
        );
        assert_eq!(
            stats
                .streams_closed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .streams_aborted
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn stream_io_cap_records_abort_from_bridge_abort_path() {
        let cap = BrowserStreamIoCap::new(BrowserStreamConfig::default());
        let mut writer = cap.open_writable(MemSink::default());

        writer.abort("route change");

        let stats = cap.stream_stats();
        assert_eq!(
            stats
                .streams_aborted
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .streams_closed
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    // -- Browser-native messaging wrappers --

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_message_channel_wrapper_requires_degraded_mode_grant() {
        let error = strict_message_host_cap()
            .open_message_channel()
            .expect_err("native fallback should require degraded-mode authority");
        assert_eq!(
            error,
            BrowserMessageError::Policy(HostApiPolicyError::DegradedModeDenied(
                HostApiSurface::MessageChannel
            ))
        );
    }

    #[test]
    fn message_channel_wrapper_transfers_payloads_and_close_rejects_operations() {
        let channel = degraded_message_host_cap()
            .open_message_channel()
            .expect("message channel wrapper should open");
        let (mut left, mut right) = channel.split();

        left.send(&BrowserMessagePayload::Text("hello".to_owned()))
            .expect("send should succeed");
        assert_eq!(
            right.try_recv().expect("receive should succeed"),
            Some(BrowserMessagePayload::Text("hello".to_owned()))
        );

        right.close();
        assert_eq!(right.state(), BrowserMessageState::Closed);
        assert_eq!(
            left.send(&BrowserMessagePayload::Bytes(vec![1, 2, 3])),
            Err(BrowserMessageError::Closed)
        );
    }

    #[test]
    fn message_port_abort_marks_errored_and_rejects_subsequent_operations() {
        let channel = degraded_message_host_cap()
            .open_message_channel()
            .expect("message channel wrapper should open");
        let (mut left, mut right) = channel.split();

        left.abort("route change");
        assert_eq!(left.state(), BrowserMessageState::Errored);
        assert_eq!(
            left.error(),
            Some(&BrowserMessageError::Aborted("route change".to_owned()))
        );
        assert_eq!(
            left.send(&BrowserMessagePayload::Text("late".to_owned())),
            Err(BrowserMessageError::Aborted("route change".to_owned()))
        );
        assert_eq!(
            left.try_recv(),
            Err(BrowserMessageError::Aborted("route change".to_owned()))
        );
        assert_eq!(
            right.send(&BrowserMessagePayload::Text("peer".to_owned())),
            Err(BrowserMessageError::Closed)
        );
    }

    #[test]
    fn broadcast_channel_wrapper_delivers_payloads_and_abort_is_sticky() {
        let cap = degraded_message_host_cap();
        let mut sender = cap
            .open_broadcast_channel("browser-stream-tests")
            .expect("broadcast channel wrapper should open");
        let mut receiver = cap
            .open_broadcast_channel("browser-stream-tests")
            .expect("broadcast channel wrapper should open");

        sender
            .send(&BrowserMessagePayload::Bytes(vec![9, 8, 7]))
            .expect("broadcast send should succeed");
        assert_eq!(
            receiver
                .try_recv()
                .expect("broadcast receive should succeed"),
            Some(BrowserMessagePayload::Bytes(vec![9, 8, 7]))
        );

        sender.abort("page hidden");
        assert_eq!(sender.state(), BrowserMessageState::Errored);
        assert_eq!(
            sender.send(&BrowserMessagePayload::Text("late".to_owned())),
            Err(BrowserMessageError::Aborted("page hidden".to_owned()))
        );
    }

    // -- Helpers --

    /// Construct a no-op waker for synchronous polling in tests.
    fn futures_task_noop_waker() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable};

        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTABLE)
        }

        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

        // SAFETY: The no-op waker has no resources and all operations are no-ops.
        #[allow(unsafe_code)]
        unsafe {
            std::task::Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE))
        }
    }
}
