//! ATP SDK - High-Level Ergonomic APIs
//!
//! Provides simple, ergonomic APIs for ATP operations that hide complexity
//! while preserving Asupersync semantics and cancellation safety.

pub mod client;
pub mod writer;
pub mod reader;

use crate::cx::Cx;
use crate::net::atp::sink::{AtpWriter, WriteOptions, WriteResult, WriteError};
use crate::types::outcome::Outcome;
use std::path::Path;

/// High-level ATP client for ergonomic operations
pub struct AtpClient {
    inner: client::AtpClientImpl,
}

impl AtpClient {
    /// Create a new ATP client
    pub async fn new() -> Result<Self, AtpError> {
        Ok(Self {
            inner: client::AtpClientImpl::new().await?,
        })
    }

    /// Write a really big buffer with automatic chunking and backpressure
    ///
    /// This is the main ergonomic API for large data transfers.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use asupersync::atp::sdk::AtpClient;
    /// use asupersync::cx::Cx;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = AtpClient::new().await?;
    /// let cx = Cx::root();
    ///
    /// // Write a huge buffer (could be GBs)
    /// let big_data = vec![0u8; 1_000_000_000]; // 1GB
    /// let result = client.write_really_big_buffer(&cx, &big_data).await?;
    ///
    /// println!("Transferred {} bytes with proof: {:?}",
    ///     result.total_bytes, result.proof);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn write_really_big_buffer(
        &mut self,
        cx: &Cx,
        data: &[u8],
    ) -> Outcome<WriteResult, AtpError> {
        self.write_buffer_with_options(cx, data, WriteOptions::default()).await
    }

    /// Write buffer with custom options
    pub async fn write_buffer_with_options(
        &mut self,
        cx: &Cx,
        data: &[u8],
        options: WriteOptions,
    ) -> Outcome<WriteResult, AtpError> {
        match self.inner.get_writer().write_buffer(cx, data, options).await {
            Outcome::Ok(result) => Outcome::Ok(result),
            Outcome::Err(e) => Outcome::Err(AtpError::Write(e)),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Send a file with automatic detection of optimal settings
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = AtpClient::new().await?;
    /// let cx = Cx::root();
    ///
    /// let result = client.send_file(&cx, "large_dataset.zip").await?;
    /// println!("File sent: {}", result.transfer_id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_file(
        &mut self,
        cx: &Cx,
        file_path: impl AsRef<Path>,
    ) -> Outcome<WriteResult, AtpError> {
        match self.inner.get_writer().write_file(cx, file_path.as_ref(), WriteOptions::default()).await {
            Outcome::Ok(result) => Outcome::Ok(result),
            Outcome::Err(e) => Outcome::Err(AtpError::Write(e)),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Send a directory tree with parallel processing
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = AtpClient::new().await?;
    /// let cx = Cx::root();
    ///
    /// let result = client.send_directory(&cx, "/path/to/large/project").await?;
    /// println!("Directory sent: {} files in {} chunks",
    ///     result.metrics.round_trips, result.chunk_count);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_directory(
        &mut self,
        cx: &Cx,
        dir_path: impl AsRef<Path>,
    ) -> Outcome<WriteResult, AtpError> {
        match self.inner.get_writer().write_directory(cx, dir_path.as_ref(), WriteOptions::default()).await {
            Outcome::Ok(result) => Outcome::Ok(result),
            Outcome::Err(e) => Outcome::Err(AtpError::Write(e)),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Send from a stream with unknown size
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use futures::stream;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = AtpClient::new().await?;
    /// let cx = Cx::root();
    ///
    /// // Create a stream of data chunks
    /// let data_stream = stream::iter(0..1000)
    ///     .map(|i| Ok(vec![i as u8; 1024])); // 1KB chunks
    ///
    /// let result = client.send_stream(&cx, data_stream).await?;
    /// println!("Stream sent: {} bytes", result.total_bytes);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_stream<S, E>(
        &mut self,
        cx: &Cx,
        stream: S,
    ) -> Outcome<WriteResult, AtpError>
    where
        S: futures::Stream<Item = Result<Vec<u8>, E>> + Send + Unpin,
        E: Into<AtpError> + Send + Sync + 'static,
    {
        // Convert error type
        let error_mapped_stream = stream.map(|result| {
            result.map_err(|e| WriteError::Internal {
                message: format!("Stream error: {:?}", e.into()),
            })
        });

        match self.inner.get_writer().write_stream(cx, error_mapped_stream, WriteOptions::default()).await {
            Outcome::Ok(result) => Outcome::Ok(result),
            Outcome::Err(e) => Outcome::Err(AtpError::Write(e)),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Send application-defined object
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use asupersync::atp::sdk::{AtpClient, AtpObject};
    ///
    /// #[derive(Debug)]
    /// struct MyData {
    ///     content: Vec<u8>,
    ///     metadata: std::collections::HashMap<String, String>,
    /// }
    ///
    /// impl AtpObject for MyData {
    ///     type Error = std::io::Error;
    ///
    ///     fn object_kind(&self) -> asupersync::atp::object::ObjectKind {
    ///         asupersync::atp::object::ObjectKind::ApplicationDefined("MyData".to_string())
    ///     }
    ///
    ///     fn size_hint(&self) -> Option<u64> {
    ///         Some(self.content.len() as u64)
    ///     }
    ///
    ///     async fn serialize_chunks(&self) -> Result<Vec<Vec<u8>>, Self::Error> {
    ///         // Chunk the content
    ///         let mut chunks = Vec::new();
    ///         for chunk in self.content.chunks(1024) {
    ///             chunks.push(chunk.to_vec());
    ///         }
    ///         Ok(chunks)
    ///     }
    ///
    ///     fn metadata(&self) -> std::collections::HashMap<String, String> {
    ///         self.metadata.clone()
    ///     }
    /// }
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = AtpClient::new().await?;
    /// let cx = Cx::root();
    ///
    /// let my_object = MyData {
    ///     content: vec![1, 2, 3, 4, 5],
    ///     metadata: [("type".to_string(), "example".to_string())].into(),
    /// };
    ///
    /// let result = client.send_object(&cx, my_object).await?;
    /// println!("Object sent: {:?}", result.object_id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_object<T>(
        &mut self,
        cx: &Cx,
        object: T,
    ) -> Outcome<WriteResult, AtpError>
    where
        T: crate::net::atp::sink::AtpObject + Send,
        T::Error: Into<AtpError>,
    {
        match self.inner.get_writer().write_object(cx, object, WriteOptions::default()).await {
            Outcome::Ok(result) => Outcome::Ok(result),
            Outcome::Err(e) => Outcome::Err(AtpError::Write(e)),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Resume a previous transfer
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = AtpClient::new().await?;
    /// let cx = Cx::root();
    ///
    /// // Resume from a previous transfer
    /// let resume_token = load_resume_token_from_disk()?;
    /// let result = client.resume_transfer(&cx, resume_token).await?;
    /// println!("Transfer resumed: {}", result.transfer_id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn resume_transfer(
        &mut self,
        cx: &Cx,
        resume_token: crate::net::atp::sink::ResumeToken,
    ) -> Outcome<WriteResult, AtpError> {
        match self.inner.get_writer().resume_transfer(cx, resume_token, WriteOptions::default()).await {
            Outcome::Ok(result) => Outcome::Ok(result),
            Outcome::Err(e) => Outcome::Err(AtpError::Write(e)),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Cancel an ongoing transfer
    pub async fn cancel_transfer(
        &mut self,
        transfer_id: crate::net::atp::sink::TransferId,
    ) -> Outcome<crate::net::atp::sink::CancellationResult, AtpError> {
        match self.inner.get_writer().cancel_transfer(transfer_id).await {
            Outcome::Ok(result) => Outcome::Ok(result),
            Outcome::Err(e) => Outcome::Err(AtpError::Write(e)),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Get progress for an active transfer
    pub fn get_transfer_progress(
        &self,
        transfer_id: crate::net::atp::sink::TransferId,
    ) -> Option<crate::net::atp::sink::TransferProgress> {
        self.inner.get_writer().get_progress(transfer_id)
    }
}

/// ATP SDK errors
#[derive(Debug, thiserror::Error)]
pub enum AtpError {
    #[error("Write operation failed: {0}")]
    Write(#[from] WriteError),

    #[error("Read operation failed: {0}")]
    Read(String),

    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

// Re-export key types for convenience
pub use crate::net::atp::sink::{
    AtpObject, WriteOptions, WriteResult, TransferProgress, TransferId,
    ResumeToken, CancellationResult, ChunkingStrategy, CompressionPreference,
    EncryptionPreference, ResumeBehavior, ProofRequirements, TransferPhase,
    VerificationStatus, TransferMetrics,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atp_error_display() {
        let error = AtpError::Configuration("Invalid timeout".to_string());
        assert_eq!(error.to_string(), "Configuration error: Invalid timeout");
    }

    #[test]
    fn test_write_options_defaults() {
        let options = WriteOptions::default();
        assert_eq!(options.priority, 128);
        assert_eq!(options.compression, CompressionPreference::Auto);
    }
}

/// Example usage and documentation tests
#[cfg(test)]
mod examples {
    use super::*;
    use futures::stream;

    /// Example showing the main ergonomic API for huge buffers
    #[tokio::test]
    #[ignore] // Integration test
    async fn example_write_really_big_buffer() {
        // This example shows how simple it is to send huge amounts of data

        // let mut client = AtpClient::new().await.unwrap();
        // let cx = Cx::root();

        // Create a really big buffer (1GB simulation)
        let big_data = vec![42u8; 1_000_000]; // 1MB for test

        // The ergonomic API handles everything automatically:
        // - Chunking strategy selection
        // - Backpressure management
        // - Progress reporting
        // - Proof generation
        // - Error handling
        // let result = client.write_really_big_buffer(&cx, &big_data).await.unwrap();

        // assert_eq!(result.total_bytes, big_data.len() as u64);
        // assert!(result.chunk_count > 0);
        // assert!(result.metrics.duration > Duration::ZERO);

        println!("Example: would transfer {} bytes", big_data.len());
    }

    /// Example showing streaming with unknown size
    #[tokio::test]
    #[ignore] // Integration test
    async fn example_stream_unknown_size() {
        // let mut client = AtpClient::new().await.unwrap();
        // let cx = Cx::root();

        // Create a stream that generates data dynamically
        let data_stream = stream::iter(0..1000)
            .map(|i| Ok::<_, AtpError>(vec![i as u8; 1024])); // 1KB chunks

        // The SDK handles:
        // - Dynamic sizing
        // - Backpressure from receiver
        // - Cancellation safety
        // - Progress tracking without knowing final size
        // let result = client.send_stream(&cx, data_stream).await.unwrap();

        // assert_eq!(result.chunk_count, 1000);

        println!("Example: would stream 1000 chunks");
    }
}