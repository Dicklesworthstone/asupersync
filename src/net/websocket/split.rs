//! WebSocket split implementation for independent read/write halves.
//!
//! This module provides the ability to split a WebSocket into separate read and
//! write halves that can be used concurrently. This is essential for patterns like:
//!
//! - Reading messages while simultaneously sending keepalive pings
//! - Processing received messages while sending responses in parallel
//! - Integrating with select/join patterns for concurrent I/O
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::websocket::{WebSocket, Message};
//!
//! let ws = WebSocket::connect(&cx, "ws://example.com/chat").await?;
//! let (mut read, mut write) = ws.split();
//!
//! // Spawn tasks for concurrent read/write
//! let reader = async move {
//!     while let Some(msg) = read.recv(&cx).await? {
//!         println!("Received: {:?}", msg);
//!     }
//!     Ok::<_, WsError>(())
//! };
//!
//! let writer = async move {
//!     write.send(&cx, Message::text("Hello!")).await?;
//!     Ok::<_, WsError>(())
//! };
//!
//! // Run concurrently
//! futures::try_join!(reader, writer)?;
//! ```
#![allow(clippy::significant_drop_tightening)]

use super::client::{Message, MessageAssembler, WebSocket, WebSocketConfig, WsCancelWakerGuard};
use super::close::{CloseDeadline, CloseHandshake, CloseReason, CloseState, close_timeout_error};
use super::frame::{Frame, FrameCodec, Opcode, WsError};
use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder;
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::util::EntropySource;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

const MAX_PENDING_PONGS: usize = 16;

fn enqueue_pending_pong(pending_pongs: &mut std::collections::VecDeque<Bytes>, payload: Bytes) {
    if pending_pongs.len() >= MAX_PENDING_PONGS {
        let _ = pending_pongs.pop_front();
    }
    pending_pongs.push_back(payload);
}

struct WriterWaiter {
    id: u64,
    waker: Waker,
}

/// Shared state between read and write halves.
struct WebSocketShared<IO> {
    /// Underlying I/O stream.
    io: IO,
    /// Frame codec for encoding/decoding.
    codec: FrameCodec,
    /// Read buffer.
    read_buf: BytesMut,
    /// Write buffer.
    write_buf: BytesMut,
    /// A queued Close still needs its transport flush, even if write_buf is
    /// empty. A successful flush or abortive close clears it, as when unsplit.
    close_flush_pending: bool,
    /// Close handshake state.
    close_handshake: CloseHandshake,
    /// A first Close or timeout wakes operations already parked on transport I/O.
    close_changed: Arc<crate::sync::Notify>,
    /// Configuration.
    config: WebSocketConfig,
    /// Message assembler for fragmented frames.
    assembler: MessageAssembler,
    /// Negotiated subprotocol (if any).
    protocol: Option<String>,
    /// Pending pong payloads to send.
    pending_pongs: std::collections::VecDeque<Bytes>,
    /// Whether the read half already encoded pong bytes that still need flushing.
    pending_pong_flush: bool,
    /// Entropy used for client masking when no per-call Cx is available.
    entropy: Arc<dyn EntropySource>,
    /// Same heartbeat owner before split and after reunite.
    heartbeat: super::heartbeat::Heartbeat,
    /// True while one half is performing a frame write sequence.
    writer_active: bool,
    /// Wake the current writer when receive-side heartbeat expires.
    heartbeat_writer: Option<Waker>,
    /// Wakers for waiters blocked on `writer_active`.
    writer_waiters: SmallVec<[WriterWaiter; 2]>,
    /// Next waiter ID.
    next_waiter_id: u64,
    /// Unique ID for reunite verification.
    id: u64,
}

impl<IO> WebSocketShared<IO> {
    fn force_close(&mut self, reason: CloseReason) {
        // A prior peer reason survives force_close, but retained output must
        // not turn an abortive close into a retryable graceful close.
        self.close_flush_pending = false;
        self.close_handshake.force_close(reason);
    }

    fn check_write_heartbeat(&mut self, task: &Context<'_>) -> io::Result<()> {
        // Another half may expire the close budget after this operation's
        // outer watchdog poll. Check under the same lock as transport I/O so
        // an abort can never be followed by a stale retained frame write.
        if self.close_handshake.timed_out() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "WebSocket close handshake timed out",
            ));
        }
        if self.heartbeat.failed() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "WebSocket heartbeat timed out",
            ));
        }
        if self
            .heartbeat_writer
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(task.waker()))
        {
            self.heartbeat_writer = Some(task.waker().clone());
        }
        Ok(())
    }
}

struct SplitWritePermit<IO> {
    shared: Arc<Mutex<WebSocketShared<IO>>>,
}

fn split_close_deadline<IO>(shared: &Arc<Mutex<WebSocketShared<IO>>>) -> Option<CloseDeadline> {
    let shared = shared.lock();
    if shared.close_handshake.timed_out()
        || !shared.close_handshake.is_closed()
        || shared.close_flush_pending
    {
        shared.close_handshake.deadline()
    } else {
        None
    }
}

/// Watch for the first Close as well as its deadline. A read or DATA write
/// may already be parked when the other half starts closing, so a snapshot
/// taken only at operation entry is insufficient.
async fn watch_split_close<IO, T>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
    op_cx: Option<&Cx>,
    future: impl Future<Output = Result<T, WsError>>,
) -> Result<Option<T>, WsError> {
    let changed = Arc::clone(&shared.lock().close_changed);
    let mut notification = std::pin::pin!(changed.notified());
    let mut future = std::pin::pin!(future);
    let mut timer: Option<(CloseDeadline, crate::time::Sleep)> = None;
    std::future::poll_fn(|task| {
        let is_open = shared.lock().close_handshake.is_open();
        // Pending transport/permit waits already own their cancellation
        // registrations. Keep priority here without registering a second one.
        if write_path_cancelled(op_cx, is_open) {
            return Poll::Ready(Err(WsError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled",
            ))));
        }

        // Register before inspecting shared state. A notification between the
        // snapshot and a pending transport poll must still wake this operation.
        loop {
            let _ = notification.as_mut().enable();
            if notification.as_mut().poll(task).is_pending() {
                break;
            }
            notification.set(changed.notified());
        }
        if let Some(deadline) = split_close_deadline(shared) {
            if timer.is_none() {
                let sleep = deadline.sleep();
                timer = Some((deadline, sleep));
            }
        } else {
            timer = None;
        }
        if let Some((deadline, sleep)) = &mut timer {
            // Both injected clocks and timer Wakers can run arbitrary code.
            // No shared connection mutex is held while creating/polling them.
            if deadline.poll(sleep, task).is_ready() {
                let expired = {
                    let mut state = shared.lock();
                    if state.close_handshake.timed_out()
                        || !state.close_handshake.is_closed()
                        || state.close_flush_pending
                    {
                        deadline.expire();
                        state.force_close(CloseReason::going_away());
                        true
                    } else {
                        false
                    }
                };
                if expired {
                    changed.notify_waiters();
                    return Poll::Ready(Ok(None));
                }
                timer = None;
            }
        }
        let result = future.as_mut().poll(task);
        let interrupted = matches!(&result, Poll::Ready(Err(WsError::Io(error)))
            if error.kind() == io::ErrorKind::Interrupted);
        if shared.lock().close_handshake.timed_out() && !interrupted {
            // A nested close flush may have observed the same deadline first.
            Poll::Ready(Ok(None))
        } else {
            result.map(|result| result.map(Some))
        }
    })
    .await
}

impl<IO> Drop for SplitWritePermit<IO> {
    fn drop(&mut self) {
        let next_waker = {
            let mut shared = self.shared.lock();
            shared.writer_active = false;
            shared.heartbeat_writer = None;
            shared.writer_waiters.first().map(|w| w.waker.clone())
        };
        if let Some(waker) = next_waker {
            waker.wake();
        }
    }
}

struct AcquireWritePermitFuture<'a, IO> {
    shared: &'a Arc<Mutex<WebSocketShared<IO>>>,
    waiter_id: Option<u64>,
}

impl<IO> Future for AcquireWritePermitFuture<'_, IO> {
    type Output = SplitWritePermit<IO>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.shared.lock();
        let must_wait = if state.writer_active {
            true
        } else if let Some(id) = self.waiter_id {
            state.writer_waiters.first().is_some_and(|w| w.id != id)
        } else {
            !state.writer_waiters.is_empty()
        };
        if must_wait {
            if let Some(id) = self.waiter_id {
                if let Some(existing) = state.writer_waiters.iter_mut().find(|w| w.id == id) {
                    if !existing.waker.will_wake(cx.waker()) {
                        existing.waker.clone_from(cx.waker());
                    }
                }
            } else {
                let id = state.next_waiter_id;
                state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
                state.writer_waiters.push(WriterWaiter {
                    id,
                    waker: cx.waker().clone(),
                });
                self.waiter_id = Some(id);
            }
            drop(state);
            Poll::Pending
        } else {
            state.writer_active = true;
            if let Some(id) = self.waiter_id {
                if let Some(pos) = state.writer_waiters.iter().position(|w| w.id == id) {
                    state.writer_waiters.remove(pos);
                }
                self.waiter_id = None;
            }
            drop(state);
            Poll::Ready(SplitWritePermit {
                shared: Arc::clone(self.shared),
            })
        }
    }
}

impl<IO> Drop for AcquireWritePermitFuture<'_, IO> {
    fn drop(&mut self) {
        if let Some(id) = self.waiter_id {
            let next_waker = {
                let mut state = self.shared.lock();
                let is_head = state.writer_waiters.first().is_some_and(|w| w.id == id);
                if let Some(pos) = state.writer_waiters.iter().position(|w| w.id == id) {
                    state.writer_waiters.remove(pos);
                }
                if is_head && !state.writer_active {
                    state.writer_waiters.first().map(|w| w.waker.clone())
                } else {
                    None
                }
            };
            if let Some(w) = next_waker {
                w.wake();
            }
        }
    }
}

#[cfg(test)]
async fn acquire_write_permit<IO>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
) -> SplitWritePermit<IO> {
    AcquireWritePermitFuture {
        shared,
        waiter_id: None,
    }
    .await
}

async fn acquire_write_permit_with_cx<IO>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
    op_cx: Option<&Cx>,
) -> Result<SplitWritePermit<IO>, WsError> {
    let ambient = op_cx.is_none().then(Cx::current).flatten();
    let mut cancel_wake = op_cx.or(ambient.as_ref()).map(WsCancelWakerGuard::new);
    let mut acquire = AcquireWritePermitFuture {
        shared,
        waiter_id: None,
    };
    std::future::poll_fn(|task| {
        let is_open = shared.lock().close_handshake.is_open();
        if is_open || op_cx.is_some() {
            if let Some(guard) = cancel_wake.as_mut() {
                // Register before checking: cancellation between the check
                // and parking must not strand this waiter behind a writer.
                guard.refresh(task.waker());
            }
        }
        if write_path_cancelled(op_cx, is_open) {
            return Poll::Ready(Err(WsError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled",
            ))));
        }
        Pin::new(&mut acquire).poll(task).map(Ok)
    })
    .await
}

#[cfg(test)]
/// Flush the shared write buffer to the underlying I/O.
async fn flush_write_buf<IO: AsyncWrite + Unpin>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
) -> Result<(), WsError> {
    flush_write_buf_with_cx(shared, None).await
}

fn write_path_cancelled(op_cx: Option<&Cx>, is_open: bool) -> bool {
    match op_cx {
        // An explicitly supplied operation context remains authoritative even
        // after a Close frame changes the handshake state to `CloseSent`.
        // Otherwise a close write parked in the underlying transport can no
        // longer observe an abort and the task can remain stuck forever.
        Some(cx) => cx.checkpoint().is_err(),
        // Legacy callers without an explicit context retain the established
        // behavior: ambient cancellation is observed only while the
        // connection is open, not while an already-started close is flushed.
        None => {
            is_open && crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false)
        }
    }
}

async fn flush_write_buf_with_cx<IO: AsyncWrite + Unpin>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
    op_cx: Option<&Cx>,
) -> Result<(), WsError> {
    watch_split_close(shared, op_cx, async {
        let _permit = acquire_write_permit_with_cx(shared, op_cx).await?;
        flush_shared_write_buf_with_permit(shared, op_cx).await
    })
    .await?
    .ok_or_else(close_timeout_error)
}

async fn flush_shared_write_buf_with_permit<IO: AsyncWrite + Unpin>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
    op_cx: Option<&Cx>,
) -> Result<(), WsError> {
    use std::future::poll_fn;

    let ambient = op_cx.is_none().then(Cx::current).flatten();
    let mut cancel_wake = op_cx.or(ambient.as_ref()).map(WsCancelWakerGuard::new);
    while {
        let guard = shared.lock();
        !guard.write_buf.is_empty()
    } {
        let is_open = shared.lock().close_handshake.is_open();
        let n = poll_fn(|poll_cx| {
            if is_open || op_cx.is_some() {
                if let Some(guard) = cancel_wake.as_mut() {
                    guard.refresh(poll_cx.waker());
                }
            }
            if write_path_cancelled(op_cx, is_open) {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }
            let mut guard = shared.lock();
            guard.check_write_heartbeat(poll_cx)?;
            if guard.write_buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let WebSocketShared { io, write_buf, .. } = &mut *guard;
            Pin::new(io).poll_write(poll_cx, &write_buf[..])
        })
        .await?;

        if n == 0 {
            let guard = shared.lock();
            if !guard.write_buf.is_empty() {
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write returned 0",
                )));
            }
            break;
        }
        let mut guard = shared.lock();
        let _ = guard.write_buf.split_to(n);
    }

    // Ensure the underlying I/O stream is flushed
    let is_open = shared.lock().close_handshake.is_open();
    poll_fn(|poll_cx| {
        if is_open || op_cx.is_some() {
            if let Some(guard) = cancel_wake.as_mut() {
                guard.refresh(poll_cx.waker());
            }
        }
        if write_path_cancelled(op_cx, is_open) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            )));
        }
        let mut guard = shared.lock();
        guard.check_write_heartbeat(poll_cx)?;
        let result = Pin::new(&mut guard.io).poll_flush(poll_cx);
        // The reader can queue a Close without the permit. Clear only while
        // holding this same lock, after the transport flush succeeds and no
        // newly queued bytes remain; otherwise that Close still needs I/O.
        if matches!(&result, Poll::Ready(Ok(()))) && guard.write_buf.is_empty() {
            guard.close_flush_pending = false;
        }
        result
    })
    .await?;

    Ok(())
}

async fn write_owned_buf_with_permit<IO: AsyncWrite + Unpin>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
    op_cx: Option<&Cx>,
    buf: &mut BytesMut,
    require_open: bool,
) -> Result<(), WsError> {
    watch_split_close(
        shared,
        op_cx,
        write_owned_buf_with_permit_inner(shared, op_cx, buf, require_open),
    )
    .await?
    .ok_or_else(close_timeout_error)
}

async fn write_owned_buf_with_permit_inner<IO: AsyncWrite + Unpin>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
    op_cx: Option<&Cx>,
    buf: &mut BytesMut,
    require_open: bool,
) -> Result<(), WsError> {
    use std::future::poll_fn;

    let _permit = acquire_write_permit_with_cx(shared, op_cx).await?;
    flush_shared_write_buf_with_permit(shared, op_cx).await?;

    if buf.is_empty() {
        return Ok(());
    }
    check_shared_outbound_write_budget(shared, 0, buf.len())?;

    let is_open = shared.lock().close_handshake.is_open();
    // The read half can receive and queue a Close while this send waits for
    // the permit or flushes an earlier frame. Recheck admission after both
    // waits: otherwise the flush sends our Close echo and this new DATA frame
    // follows it on the wire (br-asupersync-fmw87f L3).
    if require_open && !is_open {
        return Err(WsError::Io(io::Error::new(
            io::ErrorKind::NotConnected,
            "connection is closing",
        )));
    }
    let ambient = op_cx.is_none().then(Cx::current).flatten();
    let mut cancel_wake = op_cx.or(ambient.as_ref()).map(WsCancelWakerGuard::new);
    let n = poll_fn(|poll_cx| {
        if is_open || op_cx.is_some() {
            if let Some(guard) = cancel_wake.as_mut() {
                guard.refresh(poll_cx.waker());
            }
        }
        if write_path_cancelled(op_cx, is_open) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            )));
        }
        let mut guard = shared.lock();
        guard.check_write_heartbeat(poll_cx)?;
        Pin::new(&mut guard.io).poll_write(poll_cx, &buf[..])
    })
    .await?;

    if n == 0 {
        return Err(WsError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            "write returned 0",
        )));
    }

    let _ = buf.split_to(n);
    if !buf.is_empty() {
        {
            let mut guard = shared.lock();
            // Part of this frame is on the wire, so its tail is retained
            // whatever the budget says: the frame was admitted whole above,
            // and dropping the tail would leave the peer a truncated frame
            // that the next queued bytes complete (br-asupersync-4en1sw W3).
            // The read half queues its Close echo without the permit, so whole
            // frames may have arrived in write_buf while this one was being
            // written. Its unsent tail goes ahead of them; appended after,
            // the wire would carry this frame split around them.
            let mut ordered = BytesMut::with_capacity(buf.len() + guard.write_buf.len());
            ordered.extend_from_slice(&buf[..]);
            ordered.extend_from_slice(&guard.write_buf[..]);
            guard.write_buf = ordered;
            buf.clear();
        }
        drop(cancel_wake);
        return flush_shared_write_buf_with_permit(shared, op_cx).await;
    }

    let is_open = shared.lock().close_handshake.is_open();
    poll_fn(|poll_cx| {
        if is_open || op_cx.is_some() {
            if let Some(guard) = cancel_wake.as_mut() {
                guard.refresh(poll_cx.waker());
            }
        }
        if write_path_cancelled(op_cx, is_open) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            )));
        }
        let mut guard = shared.lock();
        guard.check_write_heartbeat(poll_cx)?;
        let result = Pin::new(&mut guard.io).poll_flush(poll_cx);
        if matches!(&result, Poll::Ready(Ok(()))) && guard.write_buf.is_empty() {
            guard.close_flush_pending = false;
        }
        result
    })
    .await?;

    Ok(())
}

fn check_shared_outbound_write_budget<IO>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
    pending: usize,
    attempted: usize,
) -> Result<(), WsError> {
    let mut guard = shared.lock();
    if let Err(err) = guard.config.check_outbound_write_budget(pending, attempted) {
        close_shared_after_outbound_backpressure(&mut guard);
        return Err(err);
    }
    Ok(())
}

fn close_shared_after_outbound_backpressure<IO>(shared: &mut WebSocketShared<IO>) {
    if let Some(reason) = shared.config.slow_consumer_close_reason() {
        shared.force_close(reason);
    }
}

/// The read half of a split WebSocket.
///
/// This half can receive messages but cannot send. Use `reunite()` to
/// recombine with the write half.
pub struct WebSocketRead<IO> {
    shared: Arc<Mutex<WebSocketShared<IO>>>,
}

/// The write half of a split WebSocket.
///
/// This half can send messages but cannot receive. Use the read half's
/// `reunite()` to recombine.
pub struct WebSocketWrite<IO> {
    shared: Arc<Mutex<WebSocketShared<IO>>>,
}

/// Type marker for a split WebSocket write half that can still send data.
#[derive(Debug, Clone, Copy, Default)]
pub struct WebSocketWriteOpen;

/// Type marker for a split WebSocket write half after local close initiation.
///
/// This state intentionally has no data-send methods. Code that initiates a
/// close through an open [`TypedWebSocketWrite`] receives this type back, so a
/// later text/binary send is rejected by the compiler instead of by the dynamic
/// `connection is closing` guard.
///
/// ```compile_fail
/// # async fn no_data_after_close<IO>(
/// #     write: asupersync::net::websocket::WebSocketWrite<IO>,
/// #     cx: &asupersync::cx::Cx,
/// # ) -> Result<(), asupersync::net::websocket::WsError>
/// # where
/// #     IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
/// # {
/// use asupersync::net::websocket::CloseReason;
///
/// let open = write.into_typed_open();
/// let mut closing = open.close(cx, CloseReason::normal()).await?;
/// closing.send_text(cx, "late payload").await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct WebSocketWriteCloseSent;

/// Opt-in typestate wrapper for the split WebSocket write half.
///
/// The dynamic [`WebSocketWrite`] API remains available for protocol
/// dispatchers that must handle arbitrary state. This wrapper narrows the
/// common local lifecycle at compile time: data-send methods exist only for
/// [`WebSocketWriteOpen`], while local close initiation consumes that state and
/// returns [`WebSocketWriteCloseSent`].
pub struct TypedWebSocketWrite<IO, State> {
    write: WebSocketWrite<IO>,
    _state: PhantomData<fn() -> State>,
}

/// Split write half that is statically known to be open for local data sends.
pub type OpenWebSocketWrite<IO> = TypedWebSocketWrite<IO, WebSocketWriteOpen>;

/// Split write half after local close initiation.
pub type CloseSentWebSocketWrite<IO> = TypedWebSocketWrite<IO, WebSocketWriteCloseSent>;

/// Error returned when attempting to reunite mismatched halves.
pub struct ReuniteError<IO> {
    /// The read half that couldn't be reunited.
    pub read: WebSocketRead<IO>,
    /// The write half that couldn't be reunited.
    pub write: WebSocketWrite<IO>,
}

impl<IO> std::fmt::Debug for ReuniteError<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReuniteError")
            .field("read", &"WebSocketRead { .. }")
            .field("write", &"WebSocketWrite { .. }")
            .finish()
    }
}

impl<IO> std::fmt::Display for ReuniteError<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "attempted to reunite mismatched WebSocket halves")
    }
}

impl<IO> std::error::Error for ReuniteError<IO> {}

impl<IO> WebSocket<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Split the WebSocket into independent read and write halves.
    ///
    /// The halves share the underlying connection and can be used concurrently.
    /// Use `WebSocketRead::reunite()` to recombine them.
    ///
    /// # Cancel-Safety
    ///
    /// If one half is dropped while the other is still in use, the connection
    /// remains valid. The remaining half can continue operating until both
    /// halves are dropped or `reunite()` is called.
    pub fn split(self) -> (WebSocketRead<IO>, WebSocketWrite<IO>) {
        // Generate a unique ID for reunite verification
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pending_pong_flush = !self.write_buf.is_empty();

        let shared = Arc::new(Mutex::new(WebSocketShared {
            io: self.io,
            codec: self.codec,
            read_buf: self.read_buf,
            write_buf: self.write_buf,
            close_flush_pending: self.close_flush_pending,
            close_handshake: self.close_handshake,
            close_changed: Arc::new(crate::sync::Notify::new()),
            config: self.config,
            assembler: self.assembler,
            protocol: self.protocol,
            pending_pongs: self.pending_pongs,
            pending_pong_flush,
            entropy: self.entropy,
            heartbeat: self.heartbeat,
            writer_active: false,
            heartbeat_writer: None,
            writer_waiters: SmallVec::new(),
            next_waiter_id: 0,
            id,
        }));

        let read = WebSocketRead {
            shared: Arc::clone(&shared),
        };
        let write = WebSocketWrite { shared };

        (read, write)
    }
}

impl<IO> WebSocketRead<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Receive a message.
    ///
    /// Returns `None` when the connection is closed.
    ///
    /// # Cancel-Safety
    ///
    /// This method is cancel-safe. If cancelled, no data is lost.
    pub async fn recv(&mut self, cx: &Cx) -> Result<Option<Message>, WsError> {
        let shared = Arc::clone(&self.shared);
        watch_split_close(&shared, Some(cx), self.recv_inner(cx))
            .await
            .map(Option::flatten)
    }

    async fn recv_inner(&mut self, cx: &Cx) -> Result<Option<Message>, WsError> {
        let mut steps = 0;
        loop {
            steps += 1;
            if steps >= 64 {
                crate::runtime::yield_now().await;
                steps = 0;
            }

            // Check cancellation
            if cx.checkpoint().is_err() {
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }

            let update = {
                let shared = &mut *self.shared.lock();
                if shared.heartbeat.failed() {
                    return Ok(None);
                }
                shared
                    .heartbeat
                    .update(
                        cx,
                        shared.config.ping_interval,
                        shared.close_handshake.is_open(),
                        !shared.read_buf.is_empty(),
                    )
                    .map(|ping| (ping, shared.heartbeat.write_deadline()))
            };
            let (ping, deadline) = match update {
                Ok(update) => update,
                Err(error) => {
                    self.fail_heartbeat();
                    return Err(error);
                }
            };

            let flush_control = {
                let shared = self.shared.lock();
                ping.is_some() || shared.pending_pong_flush || !shared.pending_pongs.is_empty()
            };
            if flush_control {
                // Serialize control encoding with the complete write sequence.
                // A concurrent writer may own a partially committed frame;
                // inserting a Ping before its retained tail corrupts the wire.
                // The heartbeat retains a not-yet-encoded Ping if this permit
                // wait is dropped, including across split/reunite.
                let flush = async {
                    let _permit = acquire_write_permit_with_cx(&self.shared, Some(cx)).await?;
                    {
                        let shared = &mut *self.shared.lock();
                        if let Some(payload) = ping {
                            let mut encoded = BytesMut::new();
                            shared.codec.encode_with_entropy(
                                &Frame::ping(payload),
                                &mut encoded,
                                cx.entropy(),
                            )?;
                            shared.config.check_outbound_write_budget(
                                shared.write_buf.len(),
                                encoded.len(),
                            )?;
                            shared.write_buf.extend_from_slice(&encoded);
                            shared.heartbeat.ping_queued();
                            shared.pending_pong_flush = true;
                        }
                        while let Some(payload) = shared.pending_pongs.pop_front() {
                            shared.codec.encode_with_entropy(
                                &Frame::pong(payload),
                                &mut shared.write_buf,
                                cx.entropy(),
                            )?;
                            shared.pending_pong_flush = true;
                        }
                    }
                    flush_shared_write_buf_with_permit(&self.shared, Some(cx)).await
                };
                if super::heartbeat::wait_until(cx, deadline, flush)
                    .await?
                    .is_none()
                {
                    self.fail_heartbeat();
                    return Err(super::heartbeat::timeout_error());
                }
                self.shared.lock().pending_pong_flush = false;
            }

            // A compressed message decodes in bounded steps with a yield
            // between them, so one large message cannot hold this worker for
            // its whole decode (br-asupersync-ydis91). Like push_frame below,
            // each step runs on the assembler taken out of the mutex.
            let inflating = self.shared.lock().assembler.is_inflating();
            if inflating {
                let mut assembler = {
                    let mut shared = self.shared.lock();
                    let max = shared.config.max_message_size;
                    std::mem::replace(&mut shared.assembler, MessageAssembler::new(max))
                };
                let result = assembler.resume();
                self.shared.lock().assembler = assembler;
                match result {
                    Ok(Some(msg)) => return Ok(Some(msg)),
                    Ok(None) => {
                        crate::runtime::yield_now().await;
                        continue;
                    }
                    Err(err) => {
                        // RFC 6455 §7.1.7, as for push_frame below.
                        let mut shared = self.shared.lock();
                        shared.codec.poison();
                        shared.force_close(CloseReason::new(err.as_close_code(), None));
                        return Err(err);
                    }
                }
            }

            // Try to decode a frame from the buffer
            let maybe_frame = {
                let shared = &mut *self.shared.lock();
                let (codec, read_buf) = (&mut shared.codec, &mut shared.read_buf);
                match codec.decode(read_buf) {
                    Ok(frame) => frame,
                    Err(error) => {
                        shared.force_close(CloseReason::new(error.as_close_code(), None));
                        return Err(error);
                    }
                }
            };

            if let Some(frame) = maybe_frame {
                // Handle control frames
                match frame.opcode {
                    Opcode::Ping => {
                        // Cap pending pongs to prevent memory DoS via ping
                        // flooding while preserving FIFO order of newest items.
                        let mut shared = self.shared.lock();
                        enqueue_pending_pong(&mut shared.pending_pongs, frame.payload);
                    }
                    Opcode::Pong => {
                        self.shared.lock().heartbeat.received_pong(&frame.payload);
                    }
                    Opcode::Close => {
                        let timeout = self.shared.lock().close_handshake.close_timeout();
                        let candidate = CloseDeadline::new(Some(cx), timeout);
                        let changed = Arc::clone(&self.shared.lock().close_changed);
                        let flush_close = (|| {
                            let shared = &mut *self.shared.lock();
                            let response = shared.close_handshake.receive_close(&frame)?;
                            if response.is_some() || shared.close_flush_pending {
                                shared.close_handshake.start_deadline(candidate);
                            }
                            if let Some(response_frame) = response {
                                // CloseReceived must never be visible without
                                // its retained echo: the write half may retry
                                // close concurrently as soon as this lock drops.
                                shared.codec.encode_with_entropy(
                                    &response_frame,
                                    &mut shared.write_buf,
                                    cx.entropy(),
                                )?;
                                shared.close_flush_pending = true;
                                Ok::<_, WsError>(true)
                            } else {
                                // A peer Close can cross a dropped local close
                                // before its first byte was written. Finishing
                                // the handshake must still flush our retained
                                // Close, including a prior cancelled retry.
                                Ok(shared.close_flush_pending)
                            }
                        })();
                        changed.notify_waiters();
                        let flush_close = flush_close?;

                        if flush_close {
                            let deadline = self.shared.lock().heartbeat.write_deadline();
                            let send_result = super::heartbeat::wait_until(
                                cx,
                                deadline,
                                flush_write_buf_with_cx(&self.shared, Some(cx)),
                            )
                            .await;
                            if send_result?.is_none() {
                                self.fail_heartbeat();
                                return Err(super::heartbeat::timeout_error());
                            }
                            self.shared.lock().close_handshake.mark_response_sent();
                        }

                        let reason = CloseReason::parse(&frame.payload).ok();
                        return Ok(Some(Message::Close(reason)));
                    }
                    _ => {
                        // Only the read half mutates assembly. Take it out for
                        // bounded decompression so a writer never waits for the
                        // entire inflate operation while holding this mutex.
                        let mut assembler = {
                            let mut shared = self.shared.lock();
                            let max = shared.config.max_message_size;
                            std::mem::replace(&mut shared.assembler, MessageAssembler::new(max))
                        };
                        let result = assembler.push_frame(frame);
                        self.shared.lock().assembler = assembler;
                        match result {
                            Ok(Some(msg)) => return Ok(Some(msg)),
                            Ok(None) => {}
                            Err(err) => {
                                // RFC 6455 §7.1.7: a failed connection processes
                                // no further peer data, including frames already
                                // buffered behind the violation.
                                let mut shared = self.shared.lock();
                                shared.codec.poison();
                                shared.force_close(CloseReason::new(err.as_close_code(), None));
                                return Err(err);
                            }
                        }
                    }
                }
            } else {
                // A retained Close (our echo, or our own Close after a
                // crossing peer Close) whose flush an earlier recv dropped is
                // resumed before this recv reports the end or waits for input;
                // a retried recv used to return without ever writing it
                // (br-asupersync-4en1sw W1). Only once the peer's Close is in:
                // in CloseSent the peer's Close is read first, as before.
                let resume_close_flush = {
                    let mut shared = self.shared.lock();
                    shared.heartbeat.note_drained();
                    shared.close_flush_pending
                        && shared.close_handshake.state() != CloseState::CloseSent
                };
                if resume_close_flush {
                    let deadline = self.shared.lock().heartbeat.write_deadline();
                    let send_result = super::heartbeat::wait_until(
                        cx,
                        deadline,
                        flush_write_buf_with_cx(&self.shared, Some(cx)),
                    )
                    .await;
                    if send_result?.is_none() {
                        self.fail_heartbeat();
                        return Err(super::heartbeat::timeout_error());
                    }
                    let shared = &mut *self.shared.lock();
                    if !shared.close_flush_pending
                        && shared.close_handshake.state() == CloseState::CloseReceived
                    {
                        shared.close_handshake.mark_response_sent();
                    }
                    continue;
                }

                // Check if closed
                if self.shared.lock().close_handshake.is_closed() {
                    return Ok(None);
                }

                // Need more data - read from socket
                let deadline = self.shared.lock().heartbeat.deadline();
                let Some(n) =
                    super::heartbeat::wait_until(cx, deadline, self.read_more(cx)).await?
                else {
                    continue;
                };
                if n == 0 {
                    // EOF - connection closed
                    self.shared
                        .lock()
                        .force_close(CloseReason::new(super::CloseCode::Abnormal, None));
                    return Ok(None);
                }
            }
        }
    }

    /// Check if the connection is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.shared.lock().close_handshake.is_open()
    }

    /// Check if the close handshake is complete.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.lock().close_handshake.is_closed()
    }

    fn fail_heartbeat(&self) {
        let (writer, waiters) = {
            let shared = &mut *self.shared.lock();
            shared.heartbeat.fail();
            shared.force_close(CloseReason::new(super::CloseCode::Abnormal, None));
            (
                shared.heartbeat_writer.take(),
                shared
                    .writer_waiters
                    .iter()
                    .map(|waiter| waiter.waker.clone())
                    .collect::<Vec<_>>(),
            )
        };
        if let Some(writer) = writer {
            writer.wake();
        }
        for waiter in waiters {
            waiter.wake();
        }
    }

    /// Reunite with the write half to reform the original WebSocket.
    ///
    /// # Errors
    ///
    /// Returns an error if the halves don't originate from the same WebSocket.
    pub fn reunite(self, write: WebSocketWrite<IO>) -> Result<WebSocket<IO>, ReuniteError<IO>> {
        // Check that both halves have the same ID
        let self_id = self.shared.lock().id;
        let write_id = write.shared.lock().id;

        if self_id != write_id {
            return Err(ReuniteError::<IO> { read: self, write });
        }

        // Drop the write half first to release its Arc reference, then
        // try_unwrap the read half's Arc.  If a background task still holds
        // a reference (e.g. a SplitWritePermit), try_unwrap will fail —
        // return a ReuniteError rather than panicking.
        drop(write);
        let shared = match Arc::try_unwrap(self.shared) {
            Ok(mutex) => mutex.into_inner(),
            Err(arc) => {
                // Reconstruct halves so the caller can retry later.
                let write = WebSocketWrite {
                    shared: Arc::clone(&arc),
                };
                let read = Self { shared: arc };
                return Err(ReuniteError::<IO> { read, write });
            }
        };

        Ok(WebSocket {
            io: shared.io,
            codec: shared.codec,
            read_buf: shared.read_buf,
            write_buf: shared.write_buf,
            close_flush_pending: shared.close_flush_pending,
            close_handshake: shared.close_handshake,
            config: shared.config,
            assembler: shared.assembler,
            protocol: shared.protocol,
            pending_pongs: shared.pending_pongs,
            entropy: shared.entropy,
            heartbeat: shared.heartbeat,
        })
    }

    fn encode_frame_with_entropy(
        &self,
        frame: &Frame,
        entropy: &dyn EntropySource,
    ) -> Result<(), WsError> {
        let mut shared = self.shared.lock();
        let shared = &mut *shared;
        shared
            .codec
            .encode_with_entropy(frame, &mut shared.write_buf, entropy)?;
        if frame.opcode == Opcode::Close {
            shared.close_flush_pending = true;
        }
        Ok(())
    }

    /// Queues `frame` before taking the write permit, so it stays queued if
    /// this wait is cancelled. A writer that holds the permit with part of its
    /// own frame unsent puts that tail ahead of it
    /// (`write_owned_buf_with_permit`).
    async fn send_frame_internal_with_entropy(
        &self,
        op_cx: Option<&Cx>,
        frame: &Frame,
        entropy: &dyn EntropySource,
    ) -> Result<(), WsError> {
        self.encode_frame_with_entropy(frame, entropy)?;
        flush_write_buf_with_cx(&self.shared, op_cx).await
    }

    /// Internal: send a single frame (for control messages like pong/close).
    #[allow(dead_code)] // WebSocket control frame API
    async fn send_frame_internal(&self, frame: &Frame) -> Result<(), WsError> {
        let entropy = { Arc::clone(&self.shared.lock().entropy) };
        self.send_frame_internal_with_entropy(None, frame, entropy.as_ref())
            .await
    }

    /// Internal: read more data into buffer.
    async fn read_more(&self, cx: &Cx) -> Result<usize, WsError> {
        use std::future::poll_fn;

        let is_open = self.shared.lock().close_handshake.is_open();
        poll_fn(|poll_cx| {
            if is_open && cx.checkpoint().is_err() {
                return Poll::Ready(Err(WsError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                ))));
            }
            let mut temp = [0u8; 4096];
            let mut shared = self.shared.lock();
            if shared.close_handshake.timed_out() {
                return Poll::Ready(Err(close_timeout_error()));
            }
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut shared.io).poll_read(poll_cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n > 0 {
                        // Ensure we have space
                        if shared.read_buf.capacity() - shared.read_buf.len() < n {
                            shared.read_buf.reserve(8192.max(n));
                        }
                        shared.read_buf.extend_from_slice(&temp[..n]);
                        shared.heartbeat.note_read();
                    }
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(WsError::Io(e))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
}

impl<IO> WebSocketWrite<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Convert this dynamic write half into the opt-in typestate API.
    ///
    /// Call this at the point where the caller knows it owns an open write
    /// lifecycle. Existing runtime close checks are retained underneath, so
    /// this is a compile-time narrowing layer rather than a replacement for
    /// protocol validation.
    #[must_use]
    pub fn into_typed_open(self) -> OpenWebSocketWrite<IO> {
        TypedWebSocketWrite {
            write: self,
            _state: PhantomData,
        }
    }

    /// Send a message.
    ///
    /// # Cancel-Safety
    ///
    /// If cancelled, the message may be partially sent. The connection should
    /// be closed if cancellation occurs mid-send.
    pub async fn send(&mut self, cx: &Cx, msg: Message) -> Result<(), WsError> {
        // Check cancellation
        if cx.checkpoint().is_err() {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled",
            )));
        }

        // Don't send data messages if we're closing
        {
            let shared = self.shared.lock();
            if !msg.is_control() && !shared.close_handshake.is_open() {
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "connection is closing",
                )));
            }
        }

        if let Message::Close(reason) = msg {
            return self
                .initiate_close_with_cx(Some(cx), reason.unwrap_or_else(CloseReason::normal))
                .await;
        }
        if let Message::Ping(payload) | Message::Pong(payload) = &msg {
            super::frame::check_control_payload_len(payload.len())?;
        }

        let (enabled, max_message, max_encoded) = {
            let shared = self.shared.lock();
            (shared.codec.permessage_deflate_enabled(), shared.config.max_message_size,
                shared.config.max_frame_size)
        };
        // Compression is synchronous and bounded, and must not hold the shared
        // read/write mutex while doing CPU work. No dictionary crosses messages.
        let frame = super::compression::outgoing(Frame::from(msg), enabled, max_message, max_encoded)?;
        self.send_frame_with_entropy(Some(cx), &frame, cx.entropy())
            .await
    }

    /// Initiate a close handshake.
    ///
    /// Sends a close frame. The read half will receive the peer's response.
    pub async fn close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        self.initiate_close(reason).await
    }

    /// Send a ping frame.
    pub async fn ping(&mut self, payload: impl Into<Bytes>) -> Result<(), WsError> {
        let payload: Bytes = payload.into();
        super::frame::check_control_payload_len(payload.len())?;
        let frame = Frame::ping(payload);
        Self::send_frame(self, &frame).await
    }

    /// Check if the connection is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.shared.lock().close_handshake.is_open()
    }

    /// Check if the close handshake is complete.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.lock().close_handshake.is_closed()
    }

    /// Get the close state.
    #[must_use]
    pub fn close_state(&self) -> CloseState {
        self.shared.lock().close_handshake.state()
    }

    /// Internal: initiate close without waiting.
    async fn initiate_close(&self, reason: CloseReason) -> Result<(), WsError> {
        Self::initiate_close_with_cx(self, None, reason).await
    }

    async fn initiate_close_with_cx(
        &self,
        op_cx: Option<&Cx>,
        reason: CloseReason,
    ) -> Result<(), WsError> {
        let timeout = self.shared.lock().close_handshake.close_timeout();
        let candidate = CloseDeadline::new(op_cx, timeout);
        let changed = Arc::clone(&self.shared.lock().close_changed);
        let close_state = {
            let shared = &mut *self.shared.lock();
            let state = shared.close_handshake.state();
            if state == CloseState::Closed && !shared.close_flush_pending {
                return Ok(());
            }
            if state == CloseState::Open {
                let mut encoded = BytesMut::new();
                shared.codec.encode_with_entropy(
                    &reason.to_frame(),
                    &mut encoded,
                    shared.entropy.as_ref(),
                )?;
                // The Close is admitted on its own size: bytes already
                // retained (a partly written frame's tail) go out first
                // and are not this frame's to account (br-asupersync-4en1sw W2).
                if let Err(err) = shared.config.check_outbound_write_budget(0, encoded.len()) {
                    close_shared_after_outbound_backpressure(shared);
                    return Err(err);
                }

                // Publish CloseSent and its retained bytes together, before
                // awaiting either the writer permit or the first write. A
                // dropped close is then retried by flushing this same frame,
                // including after reunite (br-asupersync-fmw87f M2).
                let _ = shared.close_handshake.initiate(reason);
                shared.write_buf.extend_from_slice(&encoded);
                shared.close_flush_pending = true;
            }
            shared.close_handshake.start_deadline(candidate);
            state
        };
        changed.notify_waiters();

        // The permit still serializes the wire. An active writer retains any
        // partially committed DATA tail ahead of this queued Close. A crossing
        // peer Close may have marked the handshake Closed before a dropped
        // local close's bytes were flushed, so that state can still need I/O,
        // including poll_flush after every byte left the shared write buffer.
        if let Err(error) = flush_write_buf_with_cx(&self.shared, op_cx).await {
            if self.shared.lock().close_handshake.timed_out()
                && matches!(&error, WsError::Io(error) if error.kind() == io::ErrorKind::TimedOut)
            {
                return Ok(());
            }
            return Err(error);
        }
        if close_state == CloseState::CloseReceived {
            self.shared.lock().close_handshake.mark_response_sent();
        }
        Ok(())
    }

    async fn send_frame_with_entropy(
        &self,
        op_cx: Option<&Cx>,
        frame: &Frame,
        entropy: &dyn EntropySource,
    ) -> Result<(), WsError> {
        self.send_frame_with_entropy_impl(op_cx, frame, entropy)
            .await
    }

    async fn send_frame_with_entropy_impl(
        &self,
        op_cx: Option<&Cx>,
        frame: &Frame,
        entropy: &dyn EntropySource,
    ) -> Result<(), WsError> {
        let mut encoded = BytesMut::new();
        {
            let shared = &mut *self.shared.lock();
            shared
                .codec
                .encode_with_entropy(frame, &mut encoded, entropy)?;
        }
        write_owned_buf_with_permit(
            &self.shared,
            op_cx,
            &mut encoded,
            !frame.opcode.is_control(),
        )
        .await
    }

    /// Internal: send a single frame.
    async fn send_frame(&self, frame: &Frame) -> Result<(), WsError> {
        self.send_frame_with_cx(None, frame).await
    }

    async fn send_frame_with_cx(&self, op_cx: Option<&Cx>, frame: &Frame) -> Result<(), WsError> {
        let entropy = { Arc::clone(&self.shared.lock().entropy) };
        self.send_frame_with_entropy_impl(op_cx, frame, entropy.as_ref())
            .await
    }
}

impl<IO, State> TypedWebSocketWrite<IO, State>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Return to the dynamic split write API.
    #[must_use]
    pub fn into_dynamic(self) -> WebSocketWrite<IO> {
        self.write
    }

    /// Check if the close handshake is complete.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.write.is_closed()
    }

    /// Get the underlying dynamic close-handshake state.
    #[must_use]
    pub fn close_state(&self) -> CloseState {
        self.write.close_state()
    }
}

impl<IO> TypedWebSocketWrite<IO, WebSocketWriteOpen>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Send a text message while the local write side is statically open.
    pub async fn send_text(&mut self, cx: &Cx, text: impl Into<String>) -> Result<(), WsError> {
        self.write.send(cx, Message::Text(text.into())).await
    }

    /// Send a binary message while the local write side is statically open.
    pub async fn send_binary(&mut self, cx: &Cx, data: impl Into<Bytes>) -> Result<(), WsError> {
        self.write.send(cx, Message::Binary(data.into())).await
    }

    /// Send a ping frame while the local write side is statically open.
    pub async fn ping(&mut self, payload: impl Into<Bytes>) -> Result<(), WsError> {
        self.write.ping(payload).await
    }

    /// Initiate the close handshake and consume the open write state.
    pub async fn close(
        self,
        cx: &Cx,
        reason: CloseReason,
    ) -> Result<CloseSentWebSocketWrite<IO>, WsError> {
        self.write.initiate_close_with_cx(Some(cx), reason).await?;
        Ok(TypedWebSocketWrite {
            write: self.write,
            _state: PhantomData,
        })
    }

    /// Check if the dynamic close handshake still reports open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.write.is_open()
    }
}

impl<IO> TypedWebSocketWrite<IO, WebSocketWriteCloseSent>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Flush a previously initiated close frame without reopening data sends.
    pub async fn flush_close(&mut self, cx: &Cx) -> Result<(), WsError> {
        self.write
            .initiate_close_with_cx(Some(cx), CloseReason::normal())
            .await
    }
}

#[cfg(test)]
#[path = "split_inline_tests.rs"]
mod tests;
