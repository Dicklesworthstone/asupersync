//! Callable registered server streams, independent of the transport executor.

use std::future::Future;
use std::pin::Pin;

use crate::bytes::Bytes;
use crate::grpc::status::Status;
use crate::grpc::streaming::{Metadata, Streaming};

/// An owned, pinned response stream with initial metadata and completion trailers.
///
/// The native produced-response lane invokes the service factory and polls this
/// stream inside the response producer's request context, not inside the earlier
/// HTTP handler whose context has already retired. The stream may retain a clone
/// of that context. It need not be `Unpin`.
///
/// Methods opting into [`super::ServiceHandler::defer_response_headers`] publish
/// initial metadata to the transport before polling the message source, after
/// the service factory succeeds. The transport validates reserved keys and the
/// encoded byte bound before committing its response head. Successful-completion
/// trailers remain separate; an error item replaces them with its terminal status.
/// Dropping this owner releases the stream's resources; independently spawned
/// work must remain region-owned.
pub struct RegisteredServerStream {
    stream: Pin<Box<dyn Streaming<Message = Bytes> + Send + 'static>>,
    initial_metadata: Metadata,
    trailers: Metadata,
}

impl RegisteredServerStream {
    /// Wrap a lazily polled stream of already-serialized gRPC message payloads.
    ///
    /// ```
    /// use asupersync::bytes::Bytes;
    /// use asupersync::grpc::service::RegisteredServerStream;
    /// use asupersync::grpc::streaming::{Metadata, StreamingRequest};
    ///
    /// let mut messages = StreamingRequest::open();
    /// messages.push(Bytes::from_static(b"serialized message")).unwrap();
    /// messages.close();
    /// let mut trailers = Metadata::new();
    /// assert!(trailers.insert("x-result", "complete"));
    /// let response = RegisteredServerStream::new(messages).with_trailers(trailers);
    /// let (_, trailers) = response.into_parts();
    /// assert_eq!(trailers.len(), 1);
    /// ```
    #[must_use]
    pub fn new<S>(stream: S) -> Self
    where
        S: Streaming<Message = Bytes> + Send + 'static,
    {
        Self {
            stream: Box::pin(stream),
            initial_metadata: Metadata::new(),
            trailers: Metadata::new(),
        }
    }

    /// Attach application metadata to the initial response headers.
    ///
    /// The service must opt this method into
    /// [`super::ServiceHandler::defer_response_headers`]. Native H2 server-streaming
    /// and duplex listeners, and the gRPC-Web streaming adapter, then publish
    /// this block before polling the message source. A nonempty block without
    /// that opt-in fails with `INTERNAL`, without polling the source. Binary
    /// values use unpadded base64 on the wire. Protocol-owned `grpc-*`, framing,
    /// and connection headers cannot be overridden.
    ///
    /// The encoded field-name and field-value bytes must fit the server's
    /// nonzero `max_metadata_size` and a 64 KiB transport ceiling. A zero
    /// configured limit disables only the configured cap. Invalid metadata
    /// terminates with `INTERNAL`; excess bytes terminate with
    /// `RESOURCE_EXHAUSTED`, without polling the source or sending its metadata.
    #[must_use]
    pub fn with_initial_metadata(mut self, metadata: Metadata) -> Self {
        self.initial_metadata = metadata;
        self
    }

    /// Application metadata selected for the initial response headers.
    #[must_use]
    pub fn initial_metadata(&self) -> &Metadata {
        &self.initial_metadata
    }

    /// Attach metadata emitted only after successful stream completion.
    ///
    /// The transport validates reserved keys and its trailer byte bound after
    /// response interceptors run. This does not permit overriding `grpc-status`.
    #[must_use]
    pub fn with_trailers(mut self, trailers: Metadata) -> Self {
        self.trailers = trailers;
        self
    }

    /// Split the pinned stream from its successful-completion metadata.
    ///
    /// This legacy decomposition discards any initial metadata. Use
    /// [`Self::into_parts_with_metadata`] to preserve both metadata blocks.
    /// The caller takes over polling, termination policy, and resource ownership.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Pin<Box<dyn Streaming<Message = Bytes> + Send + 'static>>,
        Metadata,
    ) {
        (self.stream, self.trailers)
    }

    /// Split into the pinned source, initial metadata, and completion trailers.
    ///
    /// The caller takes over header validation, polling, termination policy,
    /// and resource ownership. Initial metadata must precede all messages.
    #[must_use]
    pub fn into_parts_with_metadata(
        self,
    ) -> (
        Pin<Box<dyn Streaming<Message = Bytes> + Send + 'static>>,
        Metadata,
        Metadata,
    ) {
        (self.stream, self.initial_metadata, self.trailers)
    }
}

impl std::fmt::Debug for RegisteredServerStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredServerStream")
            .field("initial_metadata_entries", &self.initial_metadata.len())
            .field("trailer_entries", &self.trailers.len())
            .finish_non_exhaustive()
    }
}

/// Future returned by `ServiceHandler::call_server_streaming`.
///
/// Factory setup can borrow the explicit request context and service. Its
/// returned stream owns its captures so the transport can retain it until drain.
pub type ServiceStreamingFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RegisteredServerStream, Status>> + Send + 'a>>;

#[cfg(test)]
#[path = "server_stream_inline_tests.rs"]
mod tests;
