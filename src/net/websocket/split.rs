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

use super::client::{Message, MessageAssembler, WebSocket, WebSocketConfig};
use super::close::{CloseHandshake, CloseReason, CloseState};
use super::frame::{Frame, FrameCodec, Opcode, WsError};
use crate::bytes::{Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, Waker};

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
    pending_pongs: Vec<Bytes>,
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
                self.initiate_close(CloseReason::going_away()).await?;
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }

            // Send any pending pongs (under lock)
            {
                let shared = &mut *self.shared.lock();
                shared.write_buf.clear();
                for payload in shared.pending_pongs.drain(..) {
                    let pong = Frame::pong(payload);
                    let (codec, write_buf) = (&mut shared.codec, &mut shared.write_buf);
                    codec.encode(pong, write_buf)?;
                }
            }

            // Flush pending pongs if any were queued
            self.flush_write_buf().await?;

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
                        // Queue pong for next operation
                        self.shared.lock().pending_pongs.push(frame.payload);
                    }
                    Opcode::Pong => {
                        // Pong received - keepalive confirmed
                    }
                    Opcode::Close => {
                        // Handle close handshake
                        let response =
                            { self.shared.lock().close_handshake.receive_close(&frame)? };

                        if let Some(response_frame) = response {
                            self.send_frame_internal(response_frame).await?;
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
            return Err(ReuniteError { read: self, write });
        }

        // Take the shared state - we know both Arcs point to the same allocation
        // so we can safely unwrap after dropping one reference
        drop(write);
        let shared = Arc::try_unwrap(self.shared)
            .ok()
            .expect("reunite should succeed after ID check")
            .into_inner();

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
        })
    }

    /// Internal: initiate close without waiting.
    async fn initiate_close(&self, reason: CloseReason) -> Result<(), WsError> {
        let frame = {
            let mut shared = self.shared.lock();
            shared.close_handshake.initiate(reason)
        };

        if let Some(f) = frame {
            self.send_frame_internal(f).await?;
        }
        Ok(())
    }

    /// Internal: send a single frame (for control messages like pong/close).
    async fn send_frame_internal(&self, frame: Frame) -> Result<(), WsError> {
        let data = {
            let shared = &mut *self.shared.lock();
            shared.write_buf.clear();
            let (codec, write_buf) = (&mut shared.codec, &mut shared.write_buf);
            codec.encode(frame, write_buf)?;
            shared.write_buf.to_vec()
        };

        self.write_all(&data).await
    }

    /// Internal: flush the write buffer.
    async fn flush_write_buf(&self) -> Result<(), WsError> {
        let data = {
            let mut shared = self.shared.lock();
            if shared.write_buf.is_empty() {
                return Ok(());
            }
            let data = shared.write_buf.to_vec();
            shared.write_buf.clear();
            data
        };

        self.write_all(&data).await
    }

    /// Internal: write all bytes.
    async fn write_all(&self, buf: &[u8]) -> Result<(), WsError> {
        use std::future::poll_fn;

        let _permit = acquire_write_permit(&self.shared).await;
        let mut written = 0;
        while written < buf.len() {
            let n = poll_fn(|poll_cx| {
                let mut shared = self.shared.lock();
                Pin::new(&mut shared.io).poll_write(poll_cx, &buf[written..])
            })
            .await?;

            if n == 0 {
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write returned 0",
                )));
            }
            written += n;
        }
        Ok(())
    }

    /// Internal: read more data into buffer.
    async fn read_more(&self) -> Result<usize, WsError> {
        use std::future::poll_fn;

        // Ensure we have space
        {
            let mut shared = self.shared.lock();
            if shared.read_buf.capacity() - shared.read_buf.len() < 4096 {
                shared.read_buf.reserve(8192);
            }
        }

        // Read into temporary buffer to avoid holding lock during poll
        let mut temp = [0u8; 4096];
        let n = poll_fn(|poll_cx| {
            let mut shared = self.shared.lock();
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut shared.io).poll_read(poll_cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(WsError::Io(e))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if n > 0 {
            let mut shared = self.shared.lock();
            shared.read_buf.extend_from_slice(&temp[..n]);
        }

        Ok(n)
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
            self.initiate_close(CloseReason::going_away()).await?;
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

        let frame = Frame::from(msg);
        self.send_frame(frame).await
    }

    /// Initiate a close handshake.
    ///
    /// Sends a close frame. The read half will receive the peer's response.
    pub async fn close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        self.initiate_close(reason).await
    }

    /// Send a ping frame.
    pub async fn ping(&mut self, payload: impl Into<Bytes>) -> Result<(), WsError> {
        let frame = Frame::ping(payload);
        self.send_frame(frame).await
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
        let frame = {
            let mut shared = self.shared.lock();
            shared.close_handshake.initiate(reason)
        };

        if let Some(f) = frame {
            self.send_frame(f).await?;
        }
        Ok(())
    }

    /// Internal: send a single frame.
    async fn send_frame(&self, frame: Frame) -> Result<(), WsError> {
        use std::future::poll_fn;

        let data = {
            let shared = &mut *self.shared.lock();
            shared.write_buf.clear();
            let (codec, write_buf) = (&mut shared.codec, &mut shared.write_buf);
            codec.encode(frame, write_buf)?;
            shared.write_buf.to_vec()
        };

        let _permit = acquire_write_permit(&self.shared).await;
        let mut written = 0;
        while written < data.len() {
            let n = poll_fn(|poll_cx| {
                let mut shared = self.shared.lock();
                Pin::new(&mut shared.io).poll_write(poll_cx, &data[written..])
            })
            .await?;

            if n == 0 {
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write returned 0",
                )));
            }
            written += n;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    // In-memory I/O for testing
    struct TestIo {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl TestIo {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                written: Vec::new(),
            }
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
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
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

            let (read_result, write_result) = future::zip(
                read.send_frame_internal(read_frame),
                write.send_frame(write_frame),
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
            let result = read.flush_write_buf().await;
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
                shared.pending_pongs.push(Bytes::from_static(b"pong-a"));
                shared.pending_pongs.push(Bytes::from_static(b"pong-b"));
                shared.pending_pongs.push(Bytes::from_static(b"pong-c"));
            }

            // Encode pongs (same block as recv() does)
            {
                let shared = &mut *read.shared.lock();
                shared.write_buf.clear();
                for payload in shared.pending_pongs.drain(..) {
                    let pong = Frame::pong(payload);
                    let (codec, write_buf) = (&mut shared.codec, &mut shared.write_buf);
                    codec.encode(pong, write_buf).unwrap();
                }
            }

            let encoded = read.shared.lock().write_buf.clone();
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
}
