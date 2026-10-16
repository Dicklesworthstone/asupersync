//! Callable registered server streams, independent of the transport executor.

use std::future::Future;
use std::pin::Pin;

use crate::bytes::Bytes;
use crate::grpc::status::Status;
use crate::grpc::streaming::{Metadata, Streaming};

/// An owned, pinned response stream and its successful-completion trailers.
///
/// The native produced-response lane invokes the service factory and polls this
/// stream inside the response producer's request context, not inside the earlier
/// HTTP handler whose context has already retired. The stream may retain a clone
/// of that context. It need not be `Unpin`.
///
/// That lane sends transport-owned initial headers. Application metadata here
/// is explicitly **trailing** metadata; it is not silently moved from an initial
/// response block. The transport stops on an error item and replaces successful
/// trailers with that status. Dropping this owner releases the stream's resources;
/// independently spawned work must remain region-owned.
pub struct RegisteredServerStream {
    stream: Pin<Box<dyn Streaming<Message = Bytes> + Send + 'static>>,
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
            trailers: Metadata::new(),
        }
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
}

impl std::fmt::Debug for RegisteredServerStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredServerStream")
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
