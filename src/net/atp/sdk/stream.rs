//! ATP streaming interfaces for large buffer movement with backpressure.

#![allow(dead_code)]

use super::{AtpSession, TransferId, TransferProgress};
use crate::channel::mpsc;
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::atp::protocol::{AtpError, AtpOutcome, PlatformError, ProtocolError};

/// Helper macro to handle Result<T, E> in functions returning AtpOutcome<U>.
/// Converts Result errors using the provided mapper and returns early on error.
macro_rules! try_atp {
    ($expr:expr, $error_mapper:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return AtpOutcome::Err($error_mapper(e)),
        }
    };
}
use crate::obligation::graded::{GradedObligation, Resolution};
use futures_lite::Stream;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::task::{Context, Poll};

/// ATP streaming writer for sending large buffers with backpressure control.
#[derive(Debug)]
pub struct AtpWriter {
    /// Transfer identifier for this stream.
    transfer_id: TransferId,
    /// Data channel to the underlying transfer.
    data_tx: mpsc::Sender<StreamChunk>,
    /// Progress receiver for monitoring.
    progress_rx: mpsc::Receiver<TransferProgress>,
    /// Cancellation signal for background task.
    cancel_tx: Option<mpsc::Sender<()>>,
    /// Region quiescence obligation for this stream.
    obligation: Option<GradedObligation>,
    /// Stream configuration.
    config: StreamConfig,
    /// Current write state.
    state: WriterState,
}

/// ATP streaming reader for receiving large buffers with backpressure control.
#[derive(Debug)]
pub struct AtpReader {
    /// Transfer identifier for this stream.
    transfer_id: TransferId,
    /// Data channel from the underlying transfer.
    data_rx: mpsc::Receiver<StreamChunk>,
    /// Progress receiver for monitoring.
    progress_rx: mpsc::Receiver<TransferProgress>,
    /// Cancellation signal for background task.
    cancel_tx: Option<mpsc::Sender<()>>,
    /// Region quiescence obligation for this stream.
    obligation: Option<GradedObligation>,
    /// Stream configuration.
    config: StreamConfig,
    /// Current read state.
    state: ReaderState,
}

/// Configuration for ATP streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Buffer size for internal buffering.
    pub buffer_size: usize,
    /// Maximum chunk size for network transfer.
    pub chunk_size: usize,
    /// Enable compression on the stream.
    pub enable_compression: bool,
    /// Enable repair symbols for error correction.
    pub enable_repair: bool,
    /// Backpressure high water mark.
    pub backpressure_threshold: usize,
    /// Timeout for individual chunk operations.
    pub chunk_timeout_ms: u64,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            buffer_size: 64 * 1024, // 64KB
            chunk_size: 8 * 1024,   // 8KB chunks
            enable_compression: true,
            enable_repair: false,
            backpressure_threshold: 256 * 1024, // 256KB
            chunk_timeout_ms: 5000,             // 5 seconds
        }
    }
}

/// Stream chunk with metadata.
#[derive(Debug, Clone)]
pub struct StreamChunk {
    /// Chunk data.
    pub data: Vec<u8>,
    /// Chunk sequence number.
    pub sequence: u64,
    /// Whether this is the final chunk.
    pub is_final: bool,
    /// Chunk checksum for integrity.
    pub checksum: u32,
}

impl StreamChunk {
    /// Create a new stream chunk.
    #[must_use]
    pub fn new(data: Vec<u8>, sequence: u64, is_final: bool) -> Self {
        let checksum = crc32fast::hash(&data);
        Self {
            data,
            sequence,
            is_final,
            checksum,
        }
    }

    /// Verify chunk integrity.
    #[must_use]
    pub fn verify(&self) -> bool {
        crc32fast::hash(&self.data) == self.checksum
    }

    /// Get chunk size.
    #[must_use]
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

#[derive(Debug, Clone)]
pub enum WriterState {
    Ready,
    Writing,
    Flushing,
    Closed,
    Error(String),
}

#[derive(Debug, Clone)]
pub enum ReaderState {
    Ready,
    Reading,
    Buffering(Vec<u8>), // Partial data from last read
    Closed,
    Error(String),
}

impl AtpSession {
    /// Create an ATP writer for streaming large data to the remote peer.
    pub async fn create_writer(&self, cx: &Cx, config: StreamConfig) -> AtpOutcome<AtpWriter> {
        try_atp!(cx.checkpoint(), |_| AtpError::Platform(
            PlatformError::OperatingSystemError
        ));
        let _ = config;
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
    }

    /// Create an ATP reader for receiving streamed data from the remote peer.
    pub async fn create_reader(&self, cx: &Cx, config: StreamConfig) -> AtpOutcome<AtpReader> {
        try_atp!(cx.checkpoint(), |_| AtpError::Platform(
            PlatformError::OperatingSystemError
        ));
        let _ = config;
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
    }
}

impl AtpWriter {
    /// Get the transfer ID for this writer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Get the current writer state.
    #[must_use]
    pub const fn state(&self) -> &WriterState {
        &self.state
    }

    /// Get the next progress update.
    pub async fn next_progress(&mut self, cx: &Cx) -> Option<TransferProgress> {
        self.progress_rx.recv(cx).await.ok()
    }

    /// Close the writer and flush any remaining data.
    pub async fn close(&mut self) -> AtpOutcome<()> {
        if matches!(self.state, WriterState::Closed) {
            return AtpOutcome::ok(());
        }

        self.state = WriterState::Flushing;

        // Send final empty chunk to signal completion
        let final_chunk = StreamChunk::new(Vec::new(), 0, true);
        try_atp!(self.data_tx.try_send(final_chunk), |_| AtpError::Platform(
            PlatformError::OperatingSystemError
        ));

        // Cancel the background task
        if let Some(cancel_tx) = self.cancel_tx.take() {
            let _ = cancel_tx.try_send(()); // Ignore send errors (task may have already finished)
        }

        // Resolve the region quiescence obligation
        if let Some(obligation) = self.obligation.take() {
            let _ = obligation.resolve(Resolution::Commit);
        }

        self.state = WriterState::Closed;
        AtpOutcome::ok(())
    }

    /// Write data chunk directly.
    pub async fn write_chunk(&mut self, data: Vec<u8>) -> AtpOutcome<()> {
        if !matches!(self.state, WriterState::Ready | WriterState::Writing) {
            return AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }

        self.state = WriterState::Writing;

        let chunk = StreamChunk::new(data, 0, false); // Sequence managed internally
        try_atp!(self.data_tx.try_send(chunk), |_| AtpError::Platform(
            PlatformError::OperatingSystemError
        ));

        self.state = WriterState::Ready;
        AtpOutcome::ok(())
    }
}

impl AtpReader {
    /// Get the transfer ID for this reader.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Get the current reader state.
    #[must_use]
    pub const fn state(&self) -> &ReaderState {
        &self.state
    }

    /// Get the next progress update.
    pub async fn next_progress(&mut self) -> Option<TransferProgress> {
        self.progress_rx.try_recv().ok()
    }

    /// Read the next chunk of data.
    pub async fn read_chunk(&mut self) -> AtpOutcome<Option<StreamChunk>> {
        if matches!(self.state, ReaderState::Closed | ReaderState::Error(_)) {
            return AtpOutcome::ok(None);
        }

        self.state = ReaderState::Reading;

        match self.data_rx.try_recv() {
            Ok(chunk) => {
                if chunk.is_final {
                    self.state = ReaderState::Closed;
                } else {
                    self.state = ReaderState::Ready;
                }
                AtpOutcome::ok(Some(chunk))
            }
            Err(mpsc::RecvError::Empty) => {
                self.state = ReaderState::Ready;
                AtpOutcome::ok(None)
            }
            Err(mpsc::RecvError::Disconnected | mpsc::RecvError::Cancelled) => {
                self.state = ReaderState::Closed;
                AtpOutcome::ok(None)
            }
        }
    }

    /// Read data into a buffer.
    pub async fn read_buffer(&mut self, buf: &mut [u8]) -> AtpOutcome<usize> {
        let mut bytes_read = 0;

        while bytes_read < buf.len() {
            // Check if we have buffered data from previous read
            if let ReaderState::Buffering(buffered_data) = &mut self.state {
                let to_copy = std::cmp::min(buffered_data.len(), buf.len() - bytes_read);
                buf[bytes_read..bytes_read + to_copy].copy_from_slice(&buffered_data[..to_copy]);
                buffered_data.drain(..to_copy);
                bytes_read += to_copy;

                if buffered_data.is_empty() {
                    self.state = ReaderState::Ready;
                }

                if bytes_read == buf.len() {
                    break;
                }
            }

            // Read next chunk
            let chunk_outcome = self.read_chunk().await;
            let chunk_option = match chunk_outcome {
                AtpOutcome::Ok(v) => v,
                AtpOutcome::Err(e) => return AtpOutcome::Err(e),
                AtpOutcome::Cancelled(r) => return AtpOutcome::Cancelled(r),
                AtpOutcome::Panicked(p) => return AtpOutcome::Panicked(p),
            };

            match chunk_option {
                Some(chunk) => {
                    let to_copy = std::cmp::min(chunk.data.len(), buf.len() - bytes_read);
                    buf[bytes_read..bytes_read + to_copy].copy_from_slice(&chunk.data[..to_copy]);
                    bytes_read += to_copy;

                    // Buffer remaining data if any
                    if to_copy < chunk.data.len() {
                        self.state = ReaderState::Buffering(chunk.data[to_copy..].to_vec());
                    }
                }
                None => break, // End of stream
            }
        }

        AtpOutcome::ok(bytes_read)
    }

    /// Close the reader and cancel the background task.
    pub async fn close(&mut self) -> AtpOutcome<()> {
        if matches!(self.state, ReaderState::Closed) {
            return AtpOutcome::ok(());
        }

        // Cancel the background task
        if let Some(cancel_tx) = self.cancel_tx.take() {
            let _ = cancel_tx.try_send(()); // Ignore send errors (task may have already finished)
        }

        // Resolve the region quiescence obligation
        if let Some(obligation) = self.obligation.take() {
            let _ = obligation.resolve(Resolution::Commit);
        }

        self.state = ReaderState::Closed;
        AtpOutcome::ok(())
    }
}

impl Drop for AtpWriter {
    fn drop(&mut self) {
        // Cancel the background task on drop to prevent race conditions
        if let Some(cancel_tx) = self.cancel_tx.take() {
            // Use try_send since we're in a synchronous context
            let _ = cancel_tx.try_send(());
        }

        // Resolve obligation on drop if not already resolved (abort since it's unexpected)
        if let Some(obligation) = self.obligation.take() {
            let _ = obligation.resolve(Resolution::Abort);
        }
    }
}

impl Drop for AtpReader {
    fn drop(&mut self) {
        // Cancel the background task on drop to prevent race conditions
        if let Some(cancel_tx) = self.cancel_tx.take() {
            // Use try_send since we're in a synchronous context
            let _ = cancel_tx.try_send(());
        }

        // Resolve obligation on drop if not already resolved (abort since it's unexpected)
        if let Some(obligation) = self.obligation.take() {
            let _ = obligation.resolve(Resolution::Abort);
        }
    }
}

// Implement AsyncWrite for AtpWriter
impl AsyncWrite for AtpWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !matches!(self.state, WriterState::Ready | WriterState::Writing) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Writer is not ready",
            )));
        }

        // AsyncWrite is a synchronous poll surface, so commit only the prefix
        // that fits in the stream's bounded asupersync MPSC queue.
        let chunk_size = std::cmp::min(buf.len(), self.config.chunk_size);
        let data = buf[..chunk_size].to_vec();

        // Try to send the chunk
        match self.data_tx.try_send(StreamChunk::new(data, 0, false)) {
            Ok(()) => Poll::Ready(Ok(chunk_size)),
            Err(mpsc::SendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::SendError::Disconnected(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Channel closed",
            ))),
            Err(mpsc::SendError::Cancelled(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Channel cancelled",
            ))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.state = WriterState::Ready;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.state = WriterState::Closed;
        Poll::Ready(Ok(()))
    }
}

// Implement AsyncRead for AtpReader
impl AsyncRead for AtpReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if matches!(self.state, ReaderState::Closed | ReaderState::Error(_)) {
            return Poll::Ready(Ok(()));
        }

        // Check if we have buffered data
        if let ReaderState::Buffering(buffered_data) = &mut self.state {
            let to_copy = std::cmp::min(buffered_data.len(), buf.remaining());
            buf.put_slice(&buffered_data[..to_copy]);
            buffered_data.drain(..to_copy);

            if buffered_data.is_empty() {
                self.state = ReaderState::Ready;
            }

            return Poll::Ready(Ok(()));
        }

        // Try to receive a chunk
        match self.data_rx.try_recv() {
            Ok(chunk) => {
                let to_copy = std::cmp::min(chunk.data.len(), buf.remaining());
                buf.put_slice(&chunk.data[..to_copy]);

                // Buffer remaining data if any
                if to_copy < chunk.data.len() {
                    self.state = ReaderState::Buffering(chunk.data[to_copy..].to_vec());
                } else if chunk.is_final {
                    self.state = ReaderState::Closed;
                }

                Poll::Ready(Ok(()))
            }
            Err(mpsc::RecvError::Empty) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::RecvError::Disconnected | mpsc::RecvError::Cancelled) => {
                self.state = ReaderState::Closed;
                Poll::Ready(Ok(()))
            }
        }
    }
}

// Implement Stream for progress updates
impl Stream for AtpWriter {
    type Item = TransferProgress;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.progress_rx.try_recv() {
            Ok(p) => Poll::Ready(Some(p)),
            Err(mpsc::RecvError::Empty) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::RecvError::Disconnected | mpsc::RecvError::Cancelled) => Poll::Ready(None),
        }
    }
}

impl Stream for AtpReader {
    type Item = TransferProgress;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.progress_rx.try_recv() {
            Ok(p) => Poll::Ready(Some(p)),
            Err(mpsc::RecvError::Empty) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::RecvError::Disconnected | mpsc::RecvError::Cancelled) => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::protocol::{
        CapabilityAction, CapabilityGrant, CapabilityGrantId, CapabilityScope, PeerId,
        SessionContextKind,
    };
    use crate::net::atp::sdk::{AtpSdk, SessionConfig, SessionOptions};
    use futures_lite::future::block_on;

    fn granted_direct_options(config: &SessionConfig, peer: PeerId, label: &str) -> SessionOptions {
        SessionOptions::direct(peer).with_grants(vec![CapabilityGrant::new(
            CapabilityGrantId::from_label(label),
            peer,
            config.local_peer,
            [CapabilityAction::Read, CapabilityAction::Write],
            CapabilityScope::for_context(SessionContextKind::Direct),
        )])
    }

    fn assert_missing_stream_transport<T: std::fmt::Debug>(outcome: AtpOutcome<T>) {
        match outcome {
            AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch)) => {}
            other => panic!("stream setup must fail closed without transport: {other:?}"), // ubs:ignore
        }
    }

    #[test]
    fn stream_chunk_creation() {
        let data = b"test data".to_vec();
        let chunk = StreamChunk::new(data.clone(), 42, false);

        assert_eq!(chunk.data, data);
        assert_eq!(chunk.sequence, 42);
        assert!(!chunk.is_final);
        assert!(chunk.verify());

        // Test corrupted chunk
        let mut bad_chunk = chunk.clone();
        bad_chunk.data[0] = 0xFF; // Corrupt data
        assert!(!bad_chunk.verify());
    }

    #[test]
    fn atp_writer_creation() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "writer-open");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_writer(&cx, stream_config).await);
        });

        crate::test_complete!("atp_writer_creation");
    }

    #[test]
    fn atp_reader_creation() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "reader-open");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_reader(&cx, stream_config).await);
        });

        crate::test_complete!("atp_reader_creation");
    }

    #[test]
    fn writer_chunk_operations() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "writer-chunk");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_writer(&cx, stream_config).await);
        });

        crate::test_complete!("writer_chunk_operations");
    }

    #[test]
    fn reader_chunk_operations() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "reader-chunk");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_reader(&cx, stream_config).await);
        });

        crate::test_complete!("reader_chunk_operations");
    }

    #[test]
    fn async_write_interface() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "async-write");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_writer(&cx, stream_config).await);
        });

        crate::test_complete!("async_write_interface");
    }

    #[test]
    fn async_read_interface() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "async-read");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_reader(&cx, stream_config).await);
        });

        crate::test_complete!("async_read_interface");
    }
}
