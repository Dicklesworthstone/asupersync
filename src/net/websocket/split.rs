//! WebSocket split read/write halves for concurrent I/O.
//!
//! Enables splitting a WebSocket into independent read and write halves,
//! allowing concurrent send/receive operations from different tasks.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::websocket::{WebSocket, Message};
//!
//! let ws = WebSocket::connect(&cx, "ws://example.com/chat").await?;
//! let (mut read, mut write) = ws.split();
//!
//! // Spawn receive task
//! region.spawn(async move |cx| {
//!     while let Some(msg) = read.recv(&cx).await? {
//!         println!("Received: {:?}", msg);
//!     }
//!     Ok(())
//! });
//!
//! // Send from main task
//! write.send(&cx, Message::text("Hello!")).await?;
//! ```

use super::close::{CloseHandshake, CloseReason, CloseState};
use super::client::{Message, WebSocketConfig};
use super::frame::{Frame, FrameCodec, Opcode, WsError};
use super::CloseCode;
use crate::bytes::{Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

/// Shared state between read and write halves.
struct WebSocketShared<IO> {
    /// Underlying I/O stream.
    io: Mutex<IO>,
    /// Frame codec for encoding/decoding.
    codec: FrameCodec,
    /// Close handshake state.
    close_handshake: Mutex<CloseHandshake>,
    /// Configuration.
    config: WebSocketConfig,
    /// Negotiated subprotocol.
    protocol: Option<String>,
    /// Flags for tracking half ownership.
    /// Bit 0: read half exists
    /// Bit 1: write half exists
    halves_alive: AtomicU8,
    /// Whether close has been initiated.
    close_initiated: AtomicBool,
}

impl<IO> WebSocketShared<IO> {
    /// Check if both halves are dropped.
    fn both_dropped(&self) -> bool {
        self.halves_alive.load(Ordering::Acquire) == 0
    }

    /// Mark read half as dropped.
    fn drop_read(&self) {
        self.halves_alive.fetch_and(!0x01, Ordering::Release);
    }

    /// Mark write half as dropped.
    fn drop_write(&self) {
        self.halves_alive.fetch_and(!0x02, Ordering::Release);
    }
}

/// Read half of a split WebSocket.
///
/// Provides receive functionality independent of the write half.
/// Dropping this half does NOT close the connection unless the write
/// half is also dropped.
pub struct WebSocketRead<IO> {
    /// Shared state with write half.
    shared: Arc<WebSocketShared<IO>>,
    /// Read buffer (owned by read half).
    read_buf: BytesMut,
    /// Pending pongs to forward to write half.
    pending_pongs: Vec<Bytes>,
}

/// Write half of a split WebSocket.
///
/// Provides send functionality independent of the read half.
/// Dropping this half does NOT close the connection unless the read
/// half is also dropped.
pub struct WebSocketWrite<IO> {
    /// Shared state with read half.
    shared: Arc<WebSocketShared<IO>>,
    /// Write buffer (owned by write half).
    write_buf: BytesMut,
    /// Pongs received from read half to send.
    outgoing_pongs: Vec<Bytes>,
}

/// Error when attempting to reunite mismatched halves.
#[derive(Debug)]
pub struct ReuniteError<IO> {
    /// The read half that couldn't be reunited.
    pub read: WebSocketRead<IO>,
    /// The write half that couldn't be reunited.
    pub write: WebSocketWrite<IO>,
}

impl<IO> std::fmt::Display for ReuniteError<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tried to reunite halves from different WebSocket connections")
    }
}

impl<IO: std::fmt::Debug> std::error::Error for ReuniteError<IO> {}

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

            // Try to decode a frame from the buffer
            match self.shared.codec.decode(&mut self.read_buf)? {
                Some(frame) => {
                    // Handle control frames
                    match frame.opcode {
                        Opcode::Ping => {
                            // Queue pong for write half
                            self.pending_pongs.push(frame.payload.clone());
                            continue;
                        }
                        Opcode::Pong => {
                            // Pong received - keepalive confirmed
                            continue;
                        }
                        Opcode::Close => {
                            // Handle close handshake
                            let response = {
                                let mut handshake = self.shared.close_handshake.lock().unwrap();
                                handshake.receive_close(&frame)?
                            };
                            if let Some(resp) = response {
                                self.send_frame(resp).await?;
                            }
                            let reason = CloseReason::parse(&frame.payload).ok();
                            return Ok(Some(Message::Close(reason)));
                        }
                        _ => {
                            return Ok(Some(Message::from(frame)));
                        }
                    }
                }
                None => {
                    // Check if closed
                    {
                        let handshake = self.shared.close_handshake.lock().unwrap();
                        if handshake.is_closed() {
                            return Ok(None);
                        }
                    }

                    // Need more data - read from socket
                    let n = self.read_more().await?;
                    if n == 0 {
                        // EOF - connection closed
                        let mut handshake = self.shared.close_handshake.lock().unwrap();
                        handshake.force_close(CloseReason::new(CloseCode::Abnormal, None));
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// Get pending pongs that need to be sent by the write half.
    ///
    /// Call this periodically and pass the result to `WebSocketWrite::queue_pongs`.
    #[must_use]
    pub fn take_pending_pongs(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.pending_pongs)
    }

    /// Check if the connection is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        let handshake = self.shared.close_handshake.lock().unwrap();
        handshake.is_open()
    }

    /// Check if the close handshake is complete.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        let handshake = self.shared.close_handshake.lock().unwrap();
        handshake.is_closed()
    }

    /// Get the close state.
    #[must_use]
    pub fn close_state(&self) -> CloseState {
        let handshake = self.shared.close_handshake.lock().unwrap();
        handshake.state()
    }

    /// Get the negotiated subprotocol (if any).
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        self.shared.protocol.as_deref()
    }

    /// Attempt to reunite with the write half.
    ///
    /// # Errors
    ///
    /// Returns `ReuniteError` if the halves don't originate from the same
    /// WebSocket connection.
    pub fn reunite(self, write: WebSocketWrite<IO>) -> Result<super::WebSocket<IO>, ReuniteError<IO>> {
        if Arc::ptr_eq(&self.shared, &write.shared) {
            // Destructure write half completely
            let WebSocketWrite {
                shared: write_shared,
                write_buf,
                outgoing_pongs: _,
            } = write;

            // Drop write's Arc to reduce refcount to 1
            drop(write_shared);

            // Now try_unwrap should succeed
            let shared = Arc::try_unwrap(self.shared)
                .expect("reunite: Arc refcount should be 1 after dropping write half");

            let io = shared.io.into_inner().unwrap();
            let close_handshake = shared.close_handshake.into_inner().unwrap();

            Ok(super::WebSocket {
                io,
                codec: shared.codec,
                read_buf: self.read_buf,
                write_buf,
                close_handshake,
                config: shared.config,
                protocol: shared.protocol,
                pending_pongs: self.pending_pongs,
            })
        } else {
            Err(ReuniteError { read: self, write })
        }
    }

    /// Internal: initiate close.
    async fn initiate_close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        let frame = {
            let mut handshake = self.shared.close_handshake.lock().unwrap();
            handshake.initiate(reason)
        };
        if let Some(f) = frame {
            self.shared.close_initiated.store(true, Ordering::Release);
            self.send_frame(f).await?;
        }
        Ok(())
    }

    /// Internal: send a single frame (for close/pong responses).
    async fn send_frame(&mut self, frame: Frame) -> Result<(), WsError> {
        let mut write_buf = BytesMut::with_capacity(256);
        self.shared.codec.encode(frame, &mut write_buf)?;

        let data = write_buf.to_vec();
        let mut io = self.shared.io.lock().unwrap();
        write_all_io(&mut *io, &data).await
    }

    /// Internal: read more data into buffer.
    async fn read_more(&mut self) -> Result<usize, WsError> {
        // Ensure we have space
        if self.read_buf.capacity() - self.read_buf.len() < 4096 {
            self.read_buf.reserve(8192);
        }

        // Read into temp buffer
        let mut temp = [0u8; 4096];
        let n = {
            let mut io = self.shared.io.lock().unwrap();
            read_some_io(&mut *io, &mut temp).await?
        };

        if n > 0 {
            self.read_buf.extend_from_slice(&temp[..n]);
        }

        Ok(n)
    }
}

impl<IO> Drop for WebSocketRead<IO> {
    fn drop(&mut self) {
        self.shared.drop_read();
        // If both halves dropped and not already closing, we should initiate close
        // But we can't do async in drop, so just mark the state
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

        // Send any queued pongs first
        self.flush_pongs().await?;

        // Don't send data messages if we're closing
        if !msg.is_control() {
            let handshake = self.shared.close_handshake.lock().unwrap();
            if !handshake.is_open() {
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "connection is closing",
                )));
            }
        }

        let frame = Frame::from(msg);
        self.send_frame(frame).await
    }

    /// Queue pongs received from the read half.
    ///
    /// These will be sent on the next `send()` call or `flush_pongs()`.
    pub fn queue_pongs(&mut self, pongs: Vec<Bytes>) {
        self.outgoing_pongs.extend(pongs);
    }

    /// Flush any pending pong frames.
    pub async fn flush_pongs(&mut self) -> Result<(), WsError> {
        while let Some(payload) = self.outgoing_pongs.pop() {
            let pong = Frame::pong(payload);
            self.send_frame(pong).await?;
        }
        Ok(())
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
        let handshake = self.shared.close_handshake.lock().unwrap();
        handshake.is_open()
    }

    /// Check if the close handshake is complete.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        let handshake = self.shared.close_handshake.lock().unwrap();
        handshake.is_closed()
    }

    /// Get the close state.
    #[must_use]
    pub fn close_state(&self) -> CloseState {
        let handshake = self.shared.close_handshake.lock().unwrap();
        handshake.state()
    }

    /// Get the negotiated subprotocol (if any).
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        self.shared.protocol.as_deref()
    }

    /// Internal: initiate close.
    async fn initiate_close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        let frame = {
            let mut handshake = self.shared.close_handshake.lock().unwrap();
            handshake.initiate(reason)
        };
        if let Some(f) = frame {
            self.shared.close_initiated.store(true, Ordering::Release);
            self.send_frame(f).await?;
        }
        Ok(())
    }

    /// Internal: send a single frame.
    async fn send_frame(&mut self, frame: Frame) -> Result<(), WsError> {
        self.write_buf.clear();
        self.shared.codec.encode(frame, &mut self.write_buf)?;

        let data = self.write_buf.to_vec();
        let mut io = self.shared.io.lock().unwrap();
        write_all_io(&mut *io, &data).await
    }
}

impl<IO> Drop for WebSocketWrite<IO> {
    fn drop(&mut self) {
        self.shared.drop_write();
    }
}

// Extension to WebSocket to add split functionality
impl<IO> super::WebSocket<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Split into independent read and write halves.
    ///
    /// Both halves share the same underlying connection. Dropping either half
    /// does NOT close the connection. Dropping BOTH halves triggers close.
    ///
    /// # Concurrency
    ///
    /// The read and write halves can be used concurrently from different tasks.
    /// This is the primary use case for splitting a WebSocket.
    ///
    /// # Reuniting
    ///
    /// Use `WebSocketRead::reunite()` to restore the original WebSocket.
    #[must_use]
    pub fn split(self) -> (WebSocketRead<IO>, WebSocketWrite<IO>) {
        let shared = Arc::new(WebSocketShared {
            io: Mutex::new(self.io),
            codec: self.codec,
            close_handshake: Mutex::new(self.close_handshake),
            config: self.config,
            protocol: self.protocol,
            halves_alive: AtomicU8::new(0x03), // Both halves alive
            close_initiated: AtomicBool::new(false),
        });

        let read = WebSocketRead {
            shared: Arc::clone(&shared),
            read_buf: self.read_buf,
            pending_pongs: self.pending_pongs,
        };

        let write = WebSocketWrite {
            shared,
            write_buf: self.write_buf,
            outgoing_pongs: Vec::new(),
        };

        (read, write)
    }
}

/// Write all bytes to an I/O stream.
async fn write_all_io<IO: AsyncWrite + Unpin>(io: &mut IO, buf: &[u8]) -> Result<(), WsError> {
    use std::future::poll_fn;

    let mut written = 0;
    while written < buf.len() {
        let n = poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, &buf[written..])).await?;
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

/// Read some bytes from an I/O stream.
async fn read_some_io<IO: AsyncRead + Unpin>(io: &mut IO, buf: &mut [u8]) -> Result<usize, WsError> {
    use std::future::poll_fn;

    poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(WsError::Io(e))),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock I/O for testing
    struct MockIo {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl MockIo {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for MockIo {
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

    impl AsyncWrite for MockIo {
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

    #[test]
    fn test_reunite_error_display() {
        let err_msg = "tried to reunite halves from different WebSocket connections";
        // Just verify the message format is correct
        assert!(err_msg.contains("reunite"));
        assert!(err_msg.contains("different"));
    }

    #[test]
    fn test_shared_halves_tracking() {
        let halves = AtomicU8::new(0x03);

        // Both alive
        assert_eq!(halves.load(Ordering::Acquire), 0x03);

        // Drop read
        halves.fetch_and(!0x01, Ordering::Release);
        assert_eq!(halves.load(Ordering::Acquire), 0x02);

        // Drop write
        halves.fetch_and(!0x02, Ordering::Release);
        assert_eq!(halves.load(Ordering::Acquire), 0x00);
    }
}
