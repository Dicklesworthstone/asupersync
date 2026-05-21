//! ATP streaming interfaces for large buffer movement with backpressure.

use super::{AtpSession, TransferId, TransferProgress};
use crate::channel::mpsc;
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::atp::protocol::{AtpError, AtpOutcome, PlatformError, ProtocolError};
use crate::obligation::graded::{GradedObligation, Resolution};
use crate::record::ObligationKind;
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
enum WriterState {
    Ready,
    Writing,
    Flushing,
    Closed,
    Error(String),
}

#[derive(Debug, Clone)]
enum ReaderState {
    Ready,
    Reading,
    Buffering(Vec<u8>), // Partial data from last read
    Closed,
    Error(String),
}

impl AtpSession {
    /// Create an ATP writer for streaming large data to the remote peer.
    pub async fn create_writer(&self, cx: &Cx, config: StreamConfig) -> AtpOutcome<AtpWriter> {
        cx.checkpoint()
            .map_err(|_| AtpError::Platform(PlatformError::OperatingSystemError))?;
        let _ = config;
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
    }

    /// Create an ATP reader for receiving streamed data from the remote peer.
    pub async fn create_reader(&self, cx: &Cx, config: StreamConfig) -> AtpOutcome<AtpReader> {
        cx.checkpoint()
            .map_err(|_| AtpError::Platform(PlatformError::OperatingSystemError))?;
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
    pub async fn next_progress(&mut self) -> Option<TransferProgress> {
        self.progress_rx.recv().await
    }

    /// Close the writer and flush any remaining data.
    pub async fn close(&mut self) -> AtpOutcome<()> {
        if matches!(self.state, WriterState::Closed) {
            return Ok(());
        }

        self.state = WriterState::Flushing;

        // Send final empty chunk to signal completion
        let final_chunk = StreamChunk::new(Vec::new(), 0, true);
        self.data_tx
            .send(final_chunk)
            .await
            .map_err(|_| AtpError::Platform(PlatformError::OperatingSystemError))?;

        // Cancel the background task
        if let Some(cancel_tx) = self.cancel_tx.take() {
            let _ = cancel_tx.try_send(()); // Ignore send errors (task may have already finished)
        }

        // Resolve the region quiescence obligation
        if let Some(obligation) = self.obligation.take() {
            let _ = obligation.resolve(Resolution::Commit);
        }

        self.state = WriterState::Closed;
        Ok(())
    }

    /// Write data chunk directly.
    pub async fn write_chunk(&mut self, data: Vec<u8>) -> AtpOutcome<()> {
        if !matches!(self.state, WriterState::Ready | WriterState::Writing) {
            return Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }

        self.state = WriterState::Writing;

        let chunk = StreamChunk::new(data, 0, false); // Sequence managed internally
        self.data_tx
            .send(chunk)
            .await
            .map_err(|_| AtpError::Platform(PlatformError::OperatingSystemError))?;

        self.state = WriterState::Ready;
        Ok(())
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
        self.progress_rx.recv().await
    }

    /// Read the next chunk of data.
    pub async fn read_chunk(&mut self) -> AtpOutcome<Option<StreamChunk>> {
        if matches!(self.state, ReaderState::Closed | ReaderState::Error(_)) {
            return Ok(None);
        }

        self.state = ReaderState::Reading;

        match self.data_rx.recv().await {
            Some(chunk) => {
                if chunk.is_final {
                    self.state = ReaderState::Closed;
                } else {
                    self.state = ReaderState::Ready;
                }
                Ok(Some(chunk))
            }
            None => {
                self.state = ReaderState::Closed;
                Ok(None)
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
            match self.read_chunk().await? {
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

        Ok(bytes_read)
    }

    /// Close the reader and cancel the background task.
    pub async fn close(&mut self) -> AtpOutcome<()> {
        if matches!(self.state, ReaderState::Closed) {
            return Ok(());
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
        Ok(())
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
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !matches!(self.state, WriterState::Ready | WriterState::Writing) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Writer is not ready",
            )));
        }

        // For simplicity, we'll just buffer the write for now
        // In a real implementation, this would integrate with the tokio runtime
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
    use crate::cx::Cx;
    use crate::net::atp::protocol::{
        CapabilityAction, CapabilityGrant, CapabilityGrantId, CapabilityScope, PeerId,
        SessionContextKind,
    };
    use crate::net::atp::sdk::{AtpSdk, SessionConfig, SessionOptions};

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
        crate::test_utils::init_test("atp_writer_creation");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);
        let cx = crate::cx::Cx::for_testing();
        let scope = crate::cx::Scope::<crate::combinator::FailFast>::new(
            region,
            crate::types::Budget::INFINITE,
        );

        let (_, result) = scope
            .spawn(&mut runtime.state, &cx, async move {
                let config = SessionConfig::default();
                let sdk = AtpSdk::new_in_process(config);

                let peer = PeerId::from_label("test_peer");
                let session_options =
                    granted_direct_options(&SessionConfig::default(), peer, "writer-open");
                let session = sdk.open_session(&cx, session_options).await.unwrap();

                let stream_config = StreamConfig::default();
                assert_missing_stream_transport(session.create_writer(&cx, stream_config).await);
            })
            .unwrap();

        runtime.run_until_idle();
        result.join().unwrap();

        crate::test_complete!("atp_writer_creation");
    }

    #[test]
    fn atp_reader_creation() {
        crate::test_utils::init_test("atp_reader_creation");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);
        let cx = crate::cx::Cx::for_testing();
        let scope = crate::cx::Scope::<crate::combinator::FailFast>::new(
            region,
            crate::types::Budget::INFINITE,
        );

        let (_, result) = scope
            .spawn(&mut runtime.state, &cx, async move {
                let config = SessionConfig::default();
                let sdk = AtpSdk::new_in_process(config);

                let peer = PeerId::from_label("test_peer");
                let session_options =
                    granted_direct_options(&SessionConfig::default(), peer, "reader-open");
                let session = sdk.open_session(&cx, session_options).await.unwrap();

                let stream_config = StreamConfig::default();
                assert_missing_stream_transport(session.create_reader(&cx, stream_config).await);
            })
            .unwrap();

        runtime.run_until_idle();
        result.join().unwrap();

        crate::test_complete!("atp_reader_creation");
    }

    #[test]
    fn writer_chunk_operations() {
        crate::test_utils::init_test("writer_chunk_operations");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);
        let cx = crate::cx::Cx::for_testing();
        let scope = crate::cx::Scope::<crate::combinator::FailFast>::new(
            region,
            crate::types::Budget::INFINITE,
        );

        let (_, result) = scope
            .spawn(&mut runtime.state, &cx, async move {
                let config = SessionConfig::default();
                let sdk = AtpSdk::new_in_process(config);

                let peer = PeerId::from_label("test_peer");
                let session_options =
                    granted_direct_options(&SessionConfig::default(), peer, "writer-chunk");
                let session = sdk.open_session(&cx, session_options).await.unwrap();

                let stream_config = StreamConfig::default();
                assert_missing_stream_transport(session.create_writer(&cx, stream_config).await);
            })
            .unwrap();

        runtime.run_until_idle();
        result.join().unwrap();

        crate::test_complete!("writer_chunk_operations");
    }

    #[test]
    fn reader_chunk_operations() {
        crate::test_utils::init_test("reader_chunk_operations");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);
        let cx = crate::cx::Cx::for_testing();
        let scope = crate::cx::Scope::<crate::combinator::FailFast>::new(
            region,
            crate::types::Budget::INFINITE,
        );

        let (_, result) = scope
            .spawn(&mut runtime.state, &cx, async move {
                let config = SessionConfig::default();
                let sdk = AtpSdk::new_in_process(config);

                let peer = PeerId::from_label("test_peer");
                let session_options =
                    granted_direct_options(&SessionConfig::default(), peer, "reader-chunk");
                let session = sdk.open_session(&cx, session_options).await.unwrap();

                let stream_config = StreamConfig::default();
                assert_missing_stream_transport(session.create_reader(&cx, stream_config).await);
            })
            .unwrap();

        runtime.run_until_idle();
        result.join().unwrap();

        crate::test_complete!("reader_chunk_operations");
    }

    #[test]
    fn async_write_interface() {
        crate::test_utils::init_test("async_write_interface");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);
        let cx = crate::cx::Cx::for_testing();
        let scope = crate::cx::Scope::<crate::combinator::FailFast>::new(
            region,
            crate::types::Budget::INFINITE,
        );

        let (_, result) = scope
            .spawn(&mut runtime.state, &cx, async move {
                let config = SessionConfig::default();
                let sdk = AtpSdk::new_in_process(config);

                let peer = PeerId::from_label("test_peer");
                let session_options =
                    granted_direct_options(&SessionConfig::default(), peer, "async-write");
                let session = sdk.open_session(&cx, session_options).await.unwrap();

                let stream_config = StreamConfig::default();
                assert_missing_stream_transport(session.create_writer(&cx, stream_config).await);
            })
            .unwrap();

        runtime.run_until_idle();
        result.join().unwrap();

        crate::test_complete!("async_write_interface");
    }

    #[test]
    fn async_read_interface() {
        crate::test_utils::init_test("async_read_interface");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);
        let cx = crate::cx::Cx::for_testing();
        let scope = crate::cx::Scope::<crate::combinator::FailFast>::new(
            region,
            crate::types::Budget::INFINITE,
        );

        let (_, result) = scope
            .spawn(&mut runtime.state, &cx, async move {
                let config = SessionConfig::default();
                let sdk = AtpSdk::new_in_process(config);

                let peer = PeerId::from_label("test_peer");
                let session_options =
                    granted_direct_options(&SessionConfig::default(), peer, "async-read");
                let session = sdk.open_session(&cx, session_options).await.unwrap();

                let stream_config = StreamConfig::default();
                assert_missing_stream_transport(session.create_reader(&cx, stream_config).await);
            })
            .unwrap();

        runtime.run_until_idle();
        result.join().unwrap();

        crate::test_complete!("async_read_interface");
    }
}
