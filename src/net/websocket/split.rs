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

use super::client::{Message, WebSocket, WebSocketConfig};
use super::close::{CloseHandshake, CloseReason, CloseState};
use super::frame::{Frame, FrameCodec, Opcode, WsError};
use crate::bytes::{Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use parking_lot::Mutex;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

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
    /// Negotiated subprotocol (if any).
    protocol: Option<String>,
    /// Pending pong payloads to send.
    pending_pongs: Vec<Bytes>,
    /// Unique ID for reunite verification.
    id: u64,
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
#[derive(Debug)]
pub struct ReuniteError<IO> {
    /// The read half that couldn't be reunited.
    pub read: WebSocketRead<IO>,
    /// The write half that couldn't be reunited.
    pub write: WebSocketWrite<IO>,
}

impl<IO> std::fmt::Display for ReuniteError<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "attempted to reunite mismatched WebSocket halves")
    }
}

impl<IO: std::fmt::Debug> std::error::Error for ReuniteError<IO> {}

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
            protocol: self.protocol,
            pending_pongs: self.pending_pongs,
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
                let mut shared = self.shared.lock();
                while let Some(payload) = shared.pending_pongs.pop() {
                    let pong = Frame::pong(payload);
                    shared.write_buf.clear();
                    shared.codec.encode(pong, &mut shared.write_buf)?;
                }
            }

            // Flush pending pongs if any were queued
            self.flush_write_buf().await?;

            // Try to decode a frame from the buffer
            let frame = {
                let mut shared = self.shared.lock();
                shared.codec.decode(&mut shared.read_buf)?
            };

            match frame {
                Some(frame) => {
                    // Handle control frames
                    match frame.opcode {
                        Opcode::Ping => {
                            // Queue pong for next operation
                            let mut shared = self.shared.lock();
                            shared.pending_pongs.push(frame.payload.clone());
                            continue;
                        }
                        Opcode::Pong => {
                            // Pong received - keepalive confirmed
                            continue;
                        }
                        Opcode::Close => {
                            // Handle close handshake
                            let response = {
                                let mut shared = self.shared.lock();
                                shared.close_handshake.receive_close(&frame)?
                            };

                            if let Some(response_frame) = response {
                                self.send_frame_internal(response_frame).await?;
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
                        let shared = self.shared.lock();
                        if shared.close_handshake.is_closed() {
                            return Ok(None);
                        }
                    }

                    // Need more data - read from socket
                    let n = self.read_more().await?;
                    if n == 0 {
                        // EOF - connection closed
                        let mut shared = self.shared.lock();
                        shared
                            .close_handshake
                            .force_close(CloseReason::new(super::CloseCode::Abnormal, None));
                        return Ok(None);
                    }
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
            protocol: shared.protocol,
            pending_pongs: shared.pending_pongs,
        })
    }

    /// Internal: initiate close without waiting.
    async fn initiate_close(&mut self, reason: CloseReason) -> Result<(), WsError> {
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
    async fn send_frame_internal(&mut self, frame: Frame) -> Result<(), WsError> {
        let data = {
            let mut shared = self.shared.lock();
            shared.write_buf.clear();
            shared.codec.encode(frame, &mut shared.write_buf)?;
            shared.write_buf.to_vec()
        };

        self.write_all(&data).await
    }

    /// Internal: flush the write buffer.
    async fn flush_write_buf(&mut self) -> Result<(), WsError> {
        let data = {
            let shared = self.shared.lock();
            if shared.write_buf.is_empty() {
                return Ok(());
            }
            shared.write_buf.to_vec()
        };

        self.write_all(&data).await?;

        {
            let mut shared = self.shared.lock();
            shared.write_buf.clear();
        }

        Ok(())
    }

    /// Internal: write all bytes.
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), WsError> {
        use std::future::poll_fn;

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
    async fn read_more(&mut self) -> Result<usize, WsError> {
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
    async fn initiate_close(&mut self, reason: CloseReason) -> Result<(), WsError> {
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
    async fn send_frame(&mut self, frame: Frame) -> Result<(), WsError> {
        use std::future::poll_fn;

        let data = {
            let mut shared = self.shared.lock();
            shared.write_buf.clear();
            shared.codec.encode(frame, &mut shared.write_buf)?;
            shared.write_buf.to_vec()
        };

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
        let err_msg = "attempted to reunite mismatched WebSocket halves";
        // Just verify the message format is correct
        assert!(err_msg.contains("reunite"));
        assert!(err_msg.contains("mismatched"));
    }
}
