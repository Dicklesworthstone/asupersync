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
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::grpc::service::{ServiceDescriptor, ServiceHandler};
    use crate::grpc::status::Code;
    use crate::grpc::streaming::{MetadataValue, Request};
    use std::cell::Cell;
    use std::marker::PhantomPinned;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    struct PinnedSource {
        position: Cell<usize>,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        _pin: PhantomPinned,
    }

    impl Streaming for PinnedSource {
        type Message = Bytes;

        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Bytes, Status>>> {
            let this = self.as_ref().get_ref();
            this.polls.fetch_add(1, Ordering::SeqCst);
            let position = this.position.replace(this.position.get() + 1);
            Poll::Ready((position == 0).then(|| Ok(Bytes::from_static(b"private payload"))))
        }
    }

    impl Drop for PinnedSource {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn source(polls: &Arc<AtomicUsize>, drops: &Arc<AtomicUsize>) -> PinnedSource {
        PinnedSource {
            position: Cell::new(0),
            polls: Arc::clone(polls),
            drops: Arc::clone(drops),
            _pin: PhantomPinned,
        }
    }

    #[test]
    fn registered_stream_is_lazy_pinned_and_releases_its_source_once() {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut trailers = Metadata::new();
        assert!(trailers.insert("x-receipt", "private receipt"));
        let response = RegisteredServerStream::new(source(&polls, &drops)).with_trailers(trailers);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let debug = format!("{response:?}");
        assert!(!debug.contains("private"));
        let (mut stream, trailers) = response.into_parts();
        assert!(matches!(
            trailers.get("x-receipt"),
            Some(MetadataValue::Ascii(value)) if value == "private receipt"
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            stream.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(value))) if value.as_ref() == b"private payload"
        ));
        assert!(matches!(stream.as_mut().poll_next(&mut cx), Poll::Ready(None)));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        drop(stream);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unpolled_registered_stream_drop_releases_without_calling_user_poll() {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        drop(RegisteredServerStream::new(source(&polls, &drops)));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn legacy_service_remains_object_safe_and_refuses_unimplemented_streams() {
        struct Legacy;
        static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor::new("Legacy", "test", &[]);
        impl ServiceHandler for Legacy {
            fn descriptor(&self) -> &ServiceDescriptor {
                &DESCRIPTOR
            }

            fn method_names(&self) -> Vec<&str> {
                Vec::new()
            }
        }
        fn require_send<T: Send>(_: &T) {}
        let service: Box<dyn ServiceHandler> = Box::new(Legacy);
        let cx = Cx::for_testing();
        let mut future = service.call_server_streaming(
            &cx,
            "/test.Legacy/Watch",
            Request::new(Bytes::new()),
            Metadata::new(),
        );
        require_send(&future);
        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            future.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(status)) if status.code() == Code::Unimplemented
        ));
    }
}
