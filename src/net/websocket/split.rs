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

use super::client::{Message, MessageAssembler, WebSocket, WebSocketConfig};
use super::close::{CloseHandshake, CloseReason, CloseState};
use super::frame::{Frame, FrameCodec, Opcode, WsError};
use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder;
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::util::EntropySource;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, Waker};

const MAX_PENDING_PONGS: usize = 16;

fn enqueue_pending_pong(pending_pongs: &mut std::collections::VecDeque<Bytes>, payload: Bytes) {
    if pending_pongs.len() >= MAX_PENDING_PONGS {
        let _ = pending_pongs.pop_front();
    }
    pending_pongs.push_back(payload);
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
    /// Close handshake state.
    close_handshake: CloseHandshake,
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
    /// True while one half is performing a frame write sequence.
    writer_active: bool,
    /// Wakers for waiters blocked on `writer_active`.
    writer_waiters: SmallVec<[Waker; 2]>,
    /// Unique ID for reunite verification.
    id: u64,
}

struct SplitWritePermit<IO> {
    shared: Arc<Mutex<WebSocketShared<IO>>>,
}

impl<IO> Drop for SplitWritePermit<IO> {
    fn drop(&mut self) {
        let waiters = {
            let mut shared = self.shared.lock();
            shared.writer_active = false;
            std::mem::take(&mut shared.writer_waiters)
        };
        for waker in waiters {
            waker.wake();
        }
    }
}

async fn acquire_write_permit<IO>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
) -> SplitWritePermit<IO> {
    use std::future::poll_fn;

    poll_fn(|cx| {
        let mut state = shared.lock();
        if state.writer_active {
            let waiter = cx.waker();
            if !state
                .writer_waiters
                .iter()
                .any(|existing| existing.will_wake(waiter))
            {
                state.writer_waiters.push(waiter.clone());
            }
            drop(state);
            Poll::Pending
        } else {
            state.writer_active = true;
            drop(state);
            Poll::Ready(())
        }
    })
    .await;

    SplitWritePermit {
        shared: Arc::clone(shared),
    }
}

/// Flush the shared write buffer to the underlying I/O.
async fn flush_write_buf<IO: AsyncWrite + Unpin>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
) -> Result<(), WsError> {
    let _permit = acquire_write_permit(shared).await;
    flush_shared_write_buf_with_permit(shared).await
}

async fn flush_shared_write_buf_with_permit<IO: AsyncWrite + Unpin>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
) -> Result<(), WsError> {
    use std::future::poll_fn;

    while {
        let guard = shared.lock();
        !guard.write_buf.is_empty()
    } {
        let n = poll_fn(|poll_cx| {
            let mut guard = shared.lock();
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
    poll_fn(|poll_cx| {
        let mut guard = shared.lock();
        Pin::new(&mut guard.io).poll_flush(poll_cx)
    })
    .await?;

    Ok(())
}

async fn write_owned_buf_with_permit<IO: AsyncWrite + Unpin>(
    shared: &Arc<Mutex<WebSocketShared<IO>>>,
    buf: &mut BytesMut,
) -> Result<(), WsError> {
    use std::future::poll_fn;

    let _permit = acquire_write_permit(shared).await;
    flush_shared_write_buf_with_permit(shared).await?;

    if buf.is_empty() {
        return Ok(());
    }

    let n = poll_fn(|poll_cx| {
        let mut guard = shared.lock();
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
            guard.write_buf.extend_from_slice(&buf[..]);
            buf.clear();
        }
        return flush_shared_write_buf_with_permit(shared).await;
    }

    poll_fn(|poll_cx| {
        let mut guard = shared.lock();
        Pin::new(&mut guard.io).poll_flush(poll_cx)
    })
    .await?;

    Ok(())
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

        let shared = Arc::new(Mutex::new(WebSocketShared {
            io: self.io,
            codec: self.codec,
            read_buf: self.read_buf,
            write_buf: self.write_buf,
            close_handshake: self.close_handshake,
            config: self.config,
            assembler: self.assembler,
            protocol: self.protocol,
            pending_pongs: self.pending_pongs,
            pending_pong_flush: false,
            entropy: self.entropy,
            writer_active: false,
            writer_waiters: SmallVec::new(),
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
        loop {
            // Check cancellation
            if cx.is_cancel_requested() {
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }

            // Send any pending pongs (under lock)
            let flush_pending_pongs = {
                let shared = &mut *self.shared.lock();
                let mut flush_pending_pongs = shared.pending_pong_flush;
                // cancel-safe: pop_front() takes one at a time from the front without reversing the whole queue
                while let Some(payload) = shared.pending_pongs.pop_front() {
                    flush_pending_pongs = true;
                    shared.pending_pong_flush = true;
                    let pong = Frame::pong(payload);
                    let shared = &mut *shared;
                    shared
                        .codec
                        .encode_with_entropy(&pong, &mut shared.write_buf, cx.entropy())?;
                }
                flush_pending_pongs
            };

            // Flush pending pongs if this call queued them or a prior recv()
            // was cancelled after encoding them but before the flush.
            if flush_pending_pongs {
                flush_write_buf(&self.shared).await?;
                self.shared.lock().pending_pong_flush = false;
            }

            // Try to decode a frame from the buffer
            let maybe_frame = {
                let shared = &mut *self.shared.lock();
                let (codec, read_buf) = (&mut shared.codec, &mut shared.read_buf);
                codec.decode(read_buf)?
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
                        // Pong received - keepalive confirmed
                    }
                    Opcode::Close => {
                        // Handle close handshake
                        let response =
                            { self.shared.lock().close_handshake.receive_close(&frame)? };

                        if let Some(response_frame) = response {
                            let send_result = self
                                .send_frame_internal_with_entropy(&response_frame, cx.entropy())
                                .await;
                            send_result?;
                            self.shared.lock().close_handshake.mark_response_sent();
                        }

                        let reason = CloseReason::parse(&frame.payload).ok();
                        return Ok(Some(Message::Close(reason)));
                    }
                    _ => {
                        let result = { self.shared.lock().assembler.push_frame(frame) };
                        match result {
                            Ok(Some(msg)) => return Ok(Some(msg)),
                            Ok(None) => {}
                            Err(err) => {
                                self.shared
                                    .lock()
                                    .close_handshake
                                    .force_close(CloseReason::new(
                                        super::CloseCode::ProtocolError,
                                        None,
                                    ));
                                return Err(err);
                            }
                        }
                    }
                }
            } else {
                // Check if closed
                if self.shared.lock().close_handshake.is_closed() {
                    return Ok(None);
                }

                // Need more data - read from socket
                let n = self.read_more().await?;
                if n == 0 {
                    // EOF - connection closed
                    self.shared
                        .lock()
                        .close_handshake
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
            close_handshake: shared.close_handshake,
            config: shared.config,
            assembler: shared.assembler,
            protocol: shared.protocol,
            pending_pongs: shared.pending_pongs,
            entropy: shared.entropy,
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
            .encode_with_entropy(frame, &mut shared.write_buf, entropy)
    }

    async fn send_frame_internal_with_entropy(
        &self,
        frame: &Frame,
        entropy: &dyn EntropySource,
    ) -> Result<(), WsError> {
        self.encode_frame_with_entropy(frame, entropy)?;
        flush_write_buf(&self.shared).await
    }

    /// Internal: send a single frame (for control messages like pong/close).
    #[allow(dead_code)] // WebSocket control frame API
    async fn send_frame_internal(&self, frame: &Frame) -> Result<(), WsError> {
        let entropy = { Arc::clone(&self.shared.lock().entropy) };
        self.send_frame_internal_with_entropy(frame, entropy.as_ref())
            .await
    }

    /// Internal: read more data into buffer.
    async fn read_more(&self) -> Result<usize, WsError> {
        use std::future::poll_fn;

        poll_fn(|poll_cx| {
            let mut temp = [0u8; 4096];
            let mut shared = self.shared.lock();
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
    /// Send a message.
    ///
    /// # Cancel-Safety
    ///
    /// If cancelled, the message may be partially sent. The connection should
    /// be closed if cancellation occurs mid-send.
    pub async fn send(&mut self, cx: &Cx, msg: Message) -> Result<(), WsError> {
        // Check cancellation
        if cx.is_cancel_requested() {
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
                .initiate_close(reason.unwrap_or_else(CloseReason::normal))
                .await;
        }

        let frame = Frame::from(msg);
        self.send_frame_with_entropy(&frame, cx.entropy()).await
    }

    /// Initiate a close handshake.
    ///
    /// Sends a close frame. The read half will receive the peer's response.
    pub async fn close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        Self::initiate_close(self, reason).await
    }

    /// Send a ping frame.
    pub async fn ping(&mut self, payload: impl Into<Bytes>) -> Result<(), WsError> {
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
        let close_state = {
            let shared = self.shared.lock();
            shared.close_handshake.state()
        };
        if close_state == CloseState::CloseReceived {
            flush_write_buf(&self.shared).await?;
            self.shared.lock().close_handshake.mark_response_sent();
            return Ok(());
        }

        if close_state == CloseState::CloseSent {
            flush_write_buf(&self.shared).await?;
            return Ok(());
        }

        let frame = {
            let mut shared = self.shared.lock();
            shared.close_handshake.initiate(reason)
        };

        if let Some(f) = frame {
            self.send_frame(&f).await?;
        }
        Ok(())
    }

    async fn send_frame_with_entropy(
        &self,
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
        write_owned_buf_with_permit(&self.shared, &mut encoded).await
    }

    /// Internal: send a single frame.
    async fn send_frame(&self, frame: &Frame) -> Result<(), WsError> {
        let entropy = { Arc::clone(&self.shared.lock().entropy) };
        self.send_frame_with_entropy(frame, entropy.as_ref()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Encoder;
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::EntropySource;
    use futures_lite::future;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    // In-memory I/O for testing
    struct TestIo {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
        fail_writes: bool,
        pending_first_write: bool,
        partial_first_write_len: Option<usize>,
        pending_after_partial_write: bool,
    }

    impl TestIo {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                written: Vec::new(),
                fail_writes: false,
                pending_first_write: false,
                partial_first_write_len: None,
                pending_after_partial_write: false,
            }
        }

        fn with_write_failure(mut self) -> Self {
            self.fail_writes = true;
            self
        }

        fn with_pending_first_write(mut self) -> Self {
            self.pending_first_write = true;
            self
        }

        fn with_partial_first_write(mut self, len: usize) -> Self {
            self.partial_first_write_len = Some(len);
            self.pending_after_partial_write = true;
            self
        }
    }

    struct InterleavingIo {
        written: Vec<u8>,
        pending_next: bool,
    }

    impl InterleavingIo {
        fn new() -> Self {
            Self {
                written: Vec::new(),
                pending_next: false,
            }
        }
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let remaining = &self.read_data[self.read_pos..];
            let to_read = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_read]);
            self.read_pos += to_read;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for InterleavingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fail_writes {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic write failure",
                )));
            }
            if self.pending_first_write {
                self.pending_first_write = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Some(len) = self.partial_first_write_len.take() {
                let to_write = len.min(buf.len());
                self.written.extend_from_slice(&buf[..to_write]);
                return Poll::Ready(Ok(to_write));
            }
            if self.pending_after_partial_write {
                self.pending_after_partial_write = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for InterleavingIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if self.pending_next {
                self.pending_next = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.pending_next = true;
            self.written.push(buf[0]);
            Poll::Ready(Ok(1))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn encode_server_frame(frame: Frame) -> Vec<u8> {
        let mut codec = FrameCodec::server();
        let mut out = BytesMut::new();
        codec
            .encode(frame, &mut out)
            .expect("frame encoding should succeed");
        out.to_vec()
    }

    fn encode_client_frame_with_entropy(frame: &Frame, entropy: &dyn EntropySource) -> Vec<u8> {
        let codec = FrameCodec::client();
        let mut out = BytesMut::new();
        codec
            .encode_with_entropy(frame, &mut out, entropy)
            .expect("frame encoding should succeed");
        out.to_vec()
    }

    #[test]
    fn split_writes_do_not_interleave_frame_bytes() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(InterleavingIo::new(), WebSocketConfig::default());
            let (read, write) = ws.split();

            let read_frame = Frame::binary(Bytes::from_static(b"read-half"));
            let write_frame = Frame::binary(Bytes::from_static(b"write-half"));

            let expected_read = encode_server_frame(read_frame.clone());
            let expected_write = encode_server_frame(write_frame.clone());

            {
                let mut shared = read.shared.lock();
                shared.codec = FrameCodec::server();
            }

            let (read_result, write_result): (Result<(), _>, Result<(), _>) = future::zip(
                read.send_frame_internal(&read_frame),
                write.send_frame(&write_frame),
            )
            .await;
            assert!(read_result.is_ok(), "read half frame send must succeed");
            assert!(write_result.is_ok(), "write half frame send must succeed");

            let ws = read.reunite(write).expect("split halves must reunite");
            let written = ws.io.written;

            let mut read_then_write = expected_read.clone();
            read_then_write.extend_from_slice(&expected_write);

            let mut write_then_read = expected_write;
            write_then_read.extend_from_slice(&expected_read);

            assert!(
                written == read_then_write || written == write_then_read,
                "concurrent writes must preserve full-frame atomicity"
            );
        });
    }

    #[test]
    fn test_reunite_error_display() {
        let err_msg = "attempted to reunite mismatched WebSocket halves";
        // Just verify the message format is correct
        assert!(err_msg.contains("reunite"));
        assert!(err_msg.contains("mismatched"));
    }

    #[test]
    fn flush_write_buf_clears_eagerly_for_cancel_safety() {
        // Verifies that write_buf is cleared before writing, so a cancel
        // during write_all won't leave stale data for the next flush.
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, _write) = ws.split();

            // Manually inject data into write_buf
            {
                let mut shared = read.shared.lock();
                shared.write_buf.extend_from_slice(b"stale-pong-data");
            }

            // flush_write_buf should clear write_buf before writing
            let result = flush_write_buf(&read.shared).await;
            assert!(result.is_ok());

            // write_buf must be empty after flush regardless of outcome
            let is_empty = read.shared.lock().write_buf.is_empty();
            assert!(
                is_empty,
                "write_buf must be cleared eagerly, not after write completes"
            );
        });
    }

    #[test]
    fn multiple_pong_payloads_all_encoded() {
        // Verifies that when multiple pongs are pending, all are encoded
        // and in FIFO order.
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, _write) = ws.split();

            // Push multiple pong payloads
            {
                let mut shared = read.shared.lock();
                shared
                    .pending_pongs
                    .push_back(Bytes::from_static(b"pong-a"));
                shared
                    .pending_pongs
                    .push_back(Bytes::from_static(b"pong-b"));
                shared
                    .pending_pongs
                    .push_back(Bytes::from_static(b"pong-c"));
                shared.pending_pong_flush = false;
            }

            // Encode pongs (same block as recv() does)
            {
                let shared = &mut *read.shared.lock();
                shared.write_buf.clear();
                let pongs: Vec<_> = shared.pending_pongs.drain(..).collect();
                for payload in pongs {
                    let pong = Frame::pong(payload);
                    shared.codec.encode(pong, &mut shared.write_buf).unwrap();
                }
                shared.pending_pong_flush = true;
            }

            let encoded = {
                let shared = read.shared.lock();
                BytesMut::from(shared.write_buf.as_ref())
            };
            let mut decode_buf = encoded;
            let mut decoder = FrameCodec::server();
            let mut payloads = Vec::new();

            while let Some(frame) = decoder.decode(&mut decode_buf).unwrap() {
                assert_eq!(frame.opcode, Opcode::Pong);
                payloads.push(frame.payload);
            }

            assert_eq!(
                payloads,
                vec![
                    Bytes::from_static(b"pong-a"),
                    Bytes::from_static(b"pong-b"),
                    Bytes::from_static(b"pong-c"),
                ],
                "pending pong payloads must be emitted in receive order"
            );
        });
    }

    #[test]
    fn recv_flushes_pongs_left_encoded_by_cancelled_attempt() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (mut read, _write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([0xAB, 0xCD, 0xEF, 0x01])));

            {
                let shared = &mut *read.shared.lock();
                let pong = Frame::pong(Bytes::from_static(b"pong-after-cancel"));
                shared
                    .codec
                    .encode(pong, &mut shared.write_buf)
                    .expect("must encode synthetic pong");
                shared.pending_pong_flush = true;
            }

            let result = read.recv(&cx).await.expect("recv must succeed");
            assert!(
                result.is_none(),
                "EOF should surface once buffered pongs flush"
            );

            let shared = read.shared.lock();
            assert!(
                !shared.pending_pong_flush,
                "recv must clear the deferred pong flush marker after flushing"
            );
            assert!(
                shared.write_buf.is_empty(),
                "recv must flush the encoded pong bytes before returning"
            );
            assert!(
                !shared.io.written.is_empty(),
                "recv must actually flush deferred pong bytes to the transport"
            );
        });
    }

    #[test]
    fn pending_pong_queue_keeps_most_recent_payloads() {
        let mut pending = std::collections::VecDeque::new();
        for n in 0u8..20 {
            enqueue_pending_pong(&mut pending, Bytes::from(vec![n]));
        }

        assert_eq!(pending.len(), MAX_PENDING_PONGS);
        let kept: Vec<u8> = pending
            .into_iter()
            .map(|payload| *payload.first().expect("single-byte payload"))
            .collect();
        assert_eq!(kept, (4u8..20).collect::<Vec<_>>());
    }

    #[test]
    fn reunite_mismatched_halves_returns_error() {
        let ws1 = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
        let ws2 = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
        let (read1, _write1) = ws1.split();
        let (_read2, write2) = ws2.split();

        let result = read1.reunite(write2);
        assert!(result.is_err(), "mismatched halves must fail reunite");
    }

    #[test]
    fn reunite_matching_halves_succeeds() {
        let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
        let (read, write) = ws.split();

        let result = read.reunite(write);
        assert!(result.is_ok(), "matching halves must reunite successfully");
    }

    #[test]
    fn writer_permit_serializes_access() {
        // Verifies that the write permit prevents concurrent access.
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, _write) = ws.split();

            // Acquire write permit
            let permit = acquire_write_permit(&read.shared).await;

            // Verify writer_active is true
            assert!(
                read.shared.lock().writer_active,
                "writer_active must be true while permit is held"
            );

            // Drop permit
            drop(permit);

            // Verify writer_active is false
            assert!(
                !read.shared.lock().writer_active,
                "writer_active must be false after permit is dropped"
            );
        });
    }

    struct CountingWake {
        wake_count: AtomicUsize,
    }

    impl CountingWake {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                wake_count: AtomicUsize::new(0),
            })
        }

        fn count(&self) -> usize {
            self.wake_count.load(Ordering::SeqCst)
        }
    }

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wake_count.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wake_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}

        fn wake_by_ref(self: &Arc<Self>) {}
    }

    #[test]
    fn writer_permit_release_wakes_all_waiters() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, _write) = ws.split();

            // Hold permit so subsequent acquires become waiters.
            let permit = acquire_write_permit(&read.shared).await;

            let mut first_waiter = Box::pin(acquire_write_permit(&read.shared));
            let mut second_waiter = Box::pin(acquire_write_permit(&read.shared));

            let counter_a = CountingWake::new();
            let counter_b = CountingWake::new();
            let first_task_waker: Waker = Waker::from(Arc::clone(&counter_a));
            let second_task_waker: Waker = Waker::from(Arc::clone(&counter_b));
            let mut first_context = Context::from_waker(&first_task_waker);
            let mut second_context = Context::from_waker(&second_task_waker);

            assert!(matches!(
                first_waiter.as_mut().poll(&mut first_context),
                Poll::Pending
            ));
            assert!(matches!(
                second_waiter.as_mut().poll(&mut second_context),
                Poll::Pending
            ));

            drop(permit);

            assert!(
                counter_a.count() > 0,
                "first waiter must be woken when permit is released"
            );
            assert!(
                counter_b.count() > 0,
                "second waiter must be woken when permit is released"
            );
        });
    }

    #[test]
    fn split_send_close_message_initiates_close_handshake() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (_read, mut write) = ws.split();
            let cx = Cx::for_testing();

            assert!(write.is_open(), "connection should start open");
            write
                .send(&cx, Message::Close(None))
                .await
                .expect("sending close should succeed");
            assert!(
                !write.is_open(),
                "sending Message::Close must transition handshake out of open state"
            );

            let err = write
                .send(&cx, Message::text("late payload"))
                .await
                .expect_err("data frames must be rejected after close initiation");
            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::NotConnected),
                "expected NotConnected after close initiation, got {err:?}"
            );
        });
    }

    #[test]
    fn split_recv_keeps_close_received_state_if_response_send_fails() {
        future::block_on(async {
            let read_data = encode_server_frame(Frame::close(Some(1000), None));
            let ws = WebSocket::from_upgraded(
                TestIo::new(read_data).with_write_failure(),
                WebSocketConfig::default(),
            );
            let (mut read, _write) = ws.split();
            let cx = Cx::for_testing();

            let err = read
                .recv(&cx)
                .await
                .expect_err("close response write should fail");
            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::BrokenPipe),
                "expected synthetic broken-pipe write failure, got {err:?}"
            );
            assert!(
                !read.is_closed(),
                "failed close response writes must not incorrectly finish the handshake"
            );
            assert_eq!(
                read.shared.lock().close_handshake.state(),
                CloseState::CloseReceived,
                "failed close response writes must leave the handshake waiting for a retry"
            );
        });
    }

    #[test]
    fn cancelled_write_half_send_does_not_flush_frame_later() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, mut write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([0xAA, 0xBB, 0xCC, 0xDD])));

            {
                let mut shared = read.shared.lock();
                shared.codec = FrameCodec::server();
            }

            let permit = acquire_write_permit(&read.shared).await;
            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let mut cancelled_send = Box::pin(write.send(&cx, cancelled));
            let wake_counter = CountingWake::new();
            let task_waker: Waker = Waker::from(Arc::clone(&wake_counter));
            let mut task_cx = Context::from_waker(&task_waker);

            assert!(
                matches!(cancelled_send.as_mut().poll(&mut task_cx), Poll::Pending),
                "first send should park waiting for the write permit"
            );
            drop(cancelled_send);
            assert!(
                read.shared.lock().write_buf.is_empty(),
                "dropping a parked split send must not leave bytes in the shared write buffer"
            );

            drop(permit);
            write
                .send(&cx, delivered.clone())
                .await
                .expect("second send should succeed");

            let ws = read.reunite(write).expect("split halves must reunite");
            assert_eq!(
                ws.io.written,
                encode_server_frame(Frame::from(delivered)),
                "later flushes must not emit bytes from a cancelled split send"
            );
        });
    }

    #[test]
    fn cancelled_write_half_send_after_partial_write_preserves_tail_for_later_flush() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(
                TestIo::new(vec![]).with_partial_first_write(1),
                WebSocketConfig::default(),
            );
            let (read, mut write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([0xAA, 0xBB, 0xCC, 0xDD])));

            {
                let mut shared = read.shared.lock();
                shared.codec = FrameCodec::server();
            }

            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let expected_cancelled = encode_server_frame(Frame::from(cancelled.clone()));
            let expected_delivered = encode_server_frame(Frame::from(delivered.clone()));
            let mut cancelled_send = Box::pin(write.send(&cx, cancelled));
            let waker = Waker::from(Arc::new(NoopWake));
            let mut poll_cx = Context::from_waker(&waker);

            assert!(
                matches!(cancelled_send.as_mut().poll(&mut poll_cx), Poll::Pending),
                "send should park after partially writing the frame and buffering the tail"
            );
            drop(cancelled_send);

            assert!(
                !read.shared.lock().write_buf.is_empty(),
                "after any byte hits the wire, the unwritten split-send tail must stay durable"
            );

            write
                .send(&cx, delivered)
                .await
                .expect("later sends should flush the durable tail first");

            let ws = read.reunite(write).expect("split halves must reunite");
            let mut expected = expected_cancelled;
            expected.extend_from_slice(&expected_delivered);
            assert_eq!(
                ws.io.written, expected,
                "later flushes must preserve the partially written split frame before the next send"
            );
        });
    }

    #[test]
    fn close_after_cancelled_recv_flushes_pending_echo_without_second_close() {
        future::block_on(async {
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let ws = WebSocket::from_upgraded(
                TestIo::new(peer_close).with_pending_first_write(),
                WebSocketConfig::default(),
            );
            let (mut read, mut write) = ws.split();
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x46, 0xD0, 0x1B, 0x0A]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let mut cancelled_recv = Box::pin(read.recv(&cx));
            let waker = Waker::from(Arc::new(NoopWake));
            let mut poll_cx = Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park while flushing the echoed close response"
            );
            drop(cancelled_recv);

            assert_eq!(
                write.close_state(),
                CloseState::CloseReceived,
                "cancelling recv mid-flush must leave the echoed response pending"
            );
            assert!(
                !read.shared.lock().write_buf.is_empty(),
                "the echoed close response should stay buffered for a later retry"
            );

            write
                .close(CloseReason::going_away())
                .await
                .expect("close should finish the pending echoed response");

            assert_eq!(
                write.close_state(),
                CloseState::Closed,
                "finishing the pending echoed response must close the handshake"
            );

            let ws = read.reunite(write).expect("split halves must reunite");
            assert_eq!(
                ws.io.written,
                encode_client_frame_with_entropy(&Frame::close(Some(1000), None), entropy.as_ref()),
                "retrying close after a cancelled recv must not append a second close frame"
            );
        });
    }

    #[test]
    fn close_after_partially_flushed_echo_preserves_tail_without_second_close() {
        future::block_on(async {
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let ws = WebSocket::from_upgraded(
                TestIo::new(peer_close).with_partial_first_write(1),
                WebSocketConfig::default(),
            );
            let (mut read, mut write) = ws.split();
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x46, 0xD0, 0x1B, 0x0A]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1000), None), entropy.as_ref());
            let mut cancelled_recv = Box::pin(read.recv(&cx));
            let waker = Waker::from(Arc::new(NoopWake));
            let mut poll_cx = Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park after partially flushing the echoed close response"
            );
            drop(cancelled_recv);

            assert_eq!(
                write.close_state(),
                CloseState::CloseReceived,
                "partial close-response flush must leave the split handshake awaiting completion"
            );
            assert!(
                !read.shared.lock().write_buf.is_empty(),
                "the echoed split close tail must remain buffered after partial I/O"
            );
            {
                let guard = read.shared.lock();
                assert_eq!(
                    guard.io.written,
                    expected[..1].to_vec(),
                    "only the committed close-frame prefix should hit the transport before retry"
                );
            }

            write
                .close(CloseReason::going_away())
                .await
                .expect("close should flush the durable close tail");

            assert_eq!(
                write.close_state(),
                CloseState::Closed,
                "completing the echoed close tail must close the split handshake"
            );

            let ws = read.reunite(write).expect("split halves must reunite");
            assert_eq!(
                ws.io.written, expected,
                "retrying close must finish the original split close frame without appending a second one"
            );
        });
    }

    #[test]
    fn close_retry_flushes_partially_sent_close_without_second_close() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(
                TestIo::new(vec![]).with_partial_first_write(1),
                WebSocketConfig::default(),
            );
            let (_read, mut write) = ws.split();
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0xD2, 0x10, 0x44, 0x9A]));
            write.shared.lock().entropy = Arc::clone(&entropy);
            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1001), None), entropy.as_ref());
            let mut cancelled_close = Box::pin(write.close(CloseReason::going_away()));
            let waker = Waker::from(Arc::new(NoopWake));
            let mut poll_cx = Context::from_waker(&waker);

            assert!(
                matches!(cancelled_close.as_mut().poll(&mut poll_cx), Poll::Pending),
                "close should park after partially writing the initiated split close frame"
            );
            drop(cancelled_close);

            assert_eq!(
                write.close_state(),
                CloseState::CloseSent,
                "cancelling split close after a partial write must keep the handshake in CloseSent"
            );
            assert!(
                !write.shared.lock().write_buf.is_empty(),
                "the initiated split close tail must remain buffered after partial I/O"
            );
            {
                let guard = write.shared.lock();
                assert_eq!(
                    guard.io.written,
                    expected[..1].to_vec(),
                    "only the committed split close prefix should hit the transport before retry"
                );
            }

            write
                .close(CloseReason::going_away())
                .await
                .expect("retrying close should flush the durable split close tail");

            assert_eq!(
                write.close_state(),
                CloseState::CloseSent,
                "split close retries should flush bytes without inventing a peer response"
            );
            {
                let guard = write.shared.lock();
                assert_eq!(
                    guard.io.written, expected,
                    "retrying split close must finish the original close frame without appending another"
                );
            }
        });
    }

    #[derive(Debug, Clone, Copy)]
    struct FixedEntropy([u8; 4]);

    impl EntropySource for FixedEntropy {
        fn fill_bytes(&self, dest: &mut [u8]) {
            for (idx, byte) in dest.iter_mut().enumerate() {
                *byte = self.0[idx % self.0.len()];
            }
        }

        fn next_u64(&self) -> u64 {
            u64::from_le_bytes([
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[0], self.0[1], self.0[2],
                self.0[3],
            ])
        }

        fn fork(&self, _task_id: TaskId) -> Arc<dyn EntropySource> {
            Arc::new(*self)
        }

        fn source_id(&self) -> &'static str {
            "fixed"
        }
    }

    fn test_cx_with_entropy(entropy: Arc<dyn EntropySource>) -> Cx {
        Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            Some(entropy),
        )
    }

    #[test]
    fn split_send_uses_cx_entropy_for_client_masking() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, mut write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([0xDE, 0xAD, 0xBE, 0xEF])));

            write
                .send(&cx, Message::text("hi"))
                .await
                .expect("split send should succeed");

            let ws = read.reunite(write).expect("split halves must reunite");
            assert_eq!(&ws.io.written[2..6], &[0xDE, 0xAD, 0xBE, 0xEF]);
        });
    }
}
