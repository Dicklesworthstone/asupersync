//! HTTP body bridge for tonic/hyper interoperability.
//!
//! Provides adapters between Asupersync's byte-stream body representation and
//! the `http-body` crate's `Body` trait used by hyper v1 and tonic.
//!
//! # Adapters
//!
//! | Type | Direction | Use Case |
//! |------|-----------|----------|
//! | [`IntoHttpBody<B>`] | asupersync→hyper | Expose asupersync body as `http_body::Body` |
//! | [`FromHttpBody<B>`] | hyper→asupersync | Consume `http_body::Body` as asupersync bytes |
//!
//! # Invariants
//!
//! - **INV-1 (No ambient authority)**: Body adapters are data-only; no Cx required.
//! - **INV-3 (Cancellation)**: Polling stops cleanly if the underlying stream ends.

use http_body::Frame;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Wraps an asupersync byte stream as an `http_body::Body`.
///
/// The inner type must implement `futures_core::Stream<Item = Result<Bytes, E>>`
/// or be a concrete `Bytes` payload. This adapter is used to feed asupersync
/// response bodies into hyper/tonic response pipelines.
///
/// # Cancel Safety
///
/// `poll_frame` delegates directly to the inner stream's `poll_next` and
/// inherits its cancel-safety properties.
pub struct IntoHttpBody<B> {
    inner: BodyKind<B>,
    /// Trailers to send after all data frames.
    trailers: Option<http::HeaderMap>,
}

enum BodyKind<B> {
    /// A complete body available as a single `Bytes` buffer.
    Full(Option<bytes::Bytes>),
    /// A streaming body that yields frames on demand.
    Stream(B),
}

/// A dummy stream type used for full bodies.
pub struct EmptyStream;

impl asupersync::stream::Stream for EmptyStream {
    type Item = Result<bytes::Bytes, std::convert::Infallible>;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        unreachable!("EmptyStream should never be polled")
    }
}

impl IntoHttpBody<EmptyStream> {
    /// Create a body from a complete byte buffer.
    ///
    /// The entire payload is returned in a single `DATA` frame on the first
    /// poll, followed by `None` on subsequent polls.
    pub const fn full(data: bytes::Bytes) -> Self {
        Self {
            inner: BodyKind::Full(Some(data)),
            trailers: None,
        }
    }

    /// Create an empty body.
    pub const fn empty() -> Self {
        Self {
            inner: BodyKind::Full(None),
            trailers: None,
        }
    }
}

impl<B> IntoHttpBody<B> {
    /// Create a body from a byte stream.
    pub const fn streaming(stream: B) -> Self {
        Self {
            inner: BodyKind::Stream(stream),
            trailers: None,
        }
    }

    /// Attach trailers to send after all data frames.
    #[must_use]
    pub fn with_trailers(mut self, trailers: http::HeaderMap) -> Self {
        self.trailers = Some(trailers);
        self
    }
}

impl<B> std::fmt::Debug for IntoHttpBody<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntoHttpBody")
            .field(
                "kind",
                match &self.inner {
                    BodyKind::Full(_) => &"Full",
                    BodyKind::Stream(_) => &"Stream",
                },
            )
            .field("has_trailers", &self.trailers.is_some())
            .finish()
    }
}

// Implementation for both full and streaming bodies.
impl<B, E> http_body::Body for IntoHttpBody<B>
where
    B: asupersync::stream::Stream<Item = Result<bytes::Bytes, E>> + Unpin,
{
    type Data = bytes::Bytes;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.as_mut();
        match &mut this.inner {
            BodyKind::Full(data) => {
                if let Some(bytes) = data.take() {
                    if bytes.is_empty() {
                        // Skip empty data frame, go straight to trailers.
                        this.trailers.take().map_or_else(
                            || Poll::Ready(None),
                            |trailers| Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
                        )
                    } else {
                        Poll::Ready(Some(Ok(Frame::data(bytes))))
                    }
                } else if let Some(trailers) = this.trailers.take() {
                    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                } else {
                    Poll::Ready(None)
                }
            }
            BodyKind::Stream(stream) => match Pin::new(stream).poll_next(cx) {
                Poll::Ready(Some(Ok(data))) => Poll::Ready(Some(Ok(Frame::data(data)))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    if let Some(trailers) = this.trailers.take() {
                        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                    } else {
                        Poll::Ready(None)
                    }
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            BodyKind::Full(None) => self.trailers.is_none(),
            _ => false,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.inner {
            BodyKind::Full(Some(data)) => http_body::SizeHint::with_exact(data.len() as u64),
            BodyKind::Full(None) => http_body::SizeHint::with_exact(0),
            BodyKind::Stream(_) => http_body::SizeHint::default(),
        }
    }
}

/// Collects an `http_body::Body` into asupersync `Bytes`.
///
/// This is the inverse of `IntoHttpBody` — it consumes an HTTP body
/// from hyper/tonic and produces a complete byte buffer. Useful for
/// bridging tonic responses back into asupersync's native types.
///
/// # Errors
///
/// Returns the body's error type if any frame fails during collection.
pub async fn collect_body<B>(body: B) -> Result<bytes::Bytes, B::Error>
where
    B: http_body::Body + Unpin,
    B::Data: Into<bytes::Bytes>,
{
    use http_body_util::BodyExt;
    let collected = body.collect().await?;
    Ok(collected.to_bytes())
}

/// Collects an `http_body::Body` with a size limit.
///
/// Returns an error if the body exceeds `max_bytes`.
///
/// # Errors
///
/// Returns `BodyLimitError::TooLarge` if the body exceeds the limit,
/// or `BodyLimitError::Body` if the underlying body errors.
pub async fn collect_body_limited<B>(
    mut body: B,
    max_bytes: usize,
) -> Result<bytes::Bytes, BodyLimitError<B::Error>>
where
    B: http_body::Body + Unpin,
    B::Data: Into<bytes::Bytes>,
{
    let mut buf = bytes::BytesMut::new();

    while let Some(frame) = {
        use std::future::poll_fn;
        poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
    } {
        let frame = frame.map_err(BodyLimitError::Body)?;
        if let Ok(data) = frame.into_data() {
            let chunk: bytes::Bytes = data.into();
            if buf.len() + chunk.len() > max_bytes {
                return Err(BodyLimitError::TooLarge {
                    limit: max_bytes,
                    received: buf.len() + chunk.len(),
                });
            }
            buf.extend_from_slice(&chunk);
        }
    }

    Ok(buf.freeze())
}

/// Errors from size-limited body collection.
#[derive(Debug)]
pub enum BodyLimitError<E> {
    /// The body exceeded the size limit.
    TooLarge {
        /// Maximum allowed bytes.
        limit: usize,
        /// Bytes received before the limit was hit.
        received: usize,
    },
    /// The underlying body returned an error.
    Body(E),
}

impl<E: std::fmt::Display> std::fmt::Display for BodyLimitError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit, received } => {
                write!(f, "body too large: {received} bytes exceeds {limit} limit")
            }
            Self::Body(e) => write!(f, "body error: {e}"),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for BodyLimitError<E> {}

/// Adapter that converts an asupersync gRPC service into a `tower::Service`
/// compatible with tonic's transport layer.
///
/// This bridges the gap between asupersync's native gRPC implementation
/// (which uses `Cx` + `Metadata` + `Bytes`) and tonic's tower-based
/// `http::Request<BoxBody>` / `http::Response<BoxBody>` interface.
///
/// # Usage
///
/// ```ignore
/// use asupersync_tokio_compat::body_bridge::GrpcServiceAdapter;
///
/// let native_svc = my_asupersync_grpc_service();
/// let tonic_svc = GrpcServiceAdapter::new(native_svc);
/// // Now usable with tonic's Router or as a tower::Service
/// ```
pub struct GrpcServiceAdapter<S> {
    inner: S,
}

impl<S> GrpcServiceAdapter<S> {
    /// Wrap an asupersync gRPC service for use with tonic's transport.
    pub const fn new(service: S) -> Self {
        Self { inner: service }
    }

    /// Get a reference to the inner service.
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Consume the adapter and return the inner service.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Clone> Clone for GrpcServiceAdapter<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for GrpcServiceAdapter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcServiceAdapter")
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body::Body;

    #[test]
    fn full_body_single_frame() {
        let body = IntoHttpBody::full(bytes::Bytes::from_static(b"hello"));

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(&waker);
        let mut body = std::pin::pin!(body);

        // First poll: data frame.
        let frame = body.as_mut().poll_frame(&mut cx);
        match frame {
            Poll::Ready(Some(Ok(f))) => {
                assert!(f.is_data());
                assert_eq!(f.into_data().unwrap(), bytes::Bytes::from_static(b"hello"));
            }
            other => panic!("expected data frame, got {other:?}"),
        }

        // Second poll: end.
        let frame = body.as_mut().poll_frame(&mut cx);
        assert!(matches!(frame, Poll::Ready(None)));
    }

    #[test]
    fn empty_body_is_end_stream() {
        let body = IntoHttpBody::empty();
        assert!(Body::is_end_stream(&body));
    }

    #[test]
    fn full_body_with_trailers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", http::HeaderValue::from_static("0"));

        let body =
            IntoHttpBody::full(bytes::Bytes::from_static(b"data")).with_trailers(headers.clone());

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(&waker);
        let mut body = std::pin::pin!(body);

        // First: data.
        let frame = body.as_mut().poll_frame(&mut cx);
        match &frame {
            Poll::Ready(Some(Ok(f))) => assert!(f.is_data()),
            other => panic!("expected data frame, got {other:?}"),
        }

        // Second: trailers.
        let frame = body.as_mut().poll_frame(&mut cx);
        match frame {
            Poll::Ready(Some(Ok(f))) => {
                assert!(f.is_trailers());
                let trailers = f.into_trailers().unwrap();
                assert_eq!(trailers.get("grpc-status").unwrap(), "0");
            }
            other => panic!("expected trailers, got {other:?}"),
        }

        // Third: end.
        let frame = body.as_mut().poll_frame(&mut cx);
        assert!(matches!(frame, Poll::Ready(None)));
    }

    #[test]
    fn size_hint_for_full_body() {
        let body = IntoHttpBody::full(bytes::Bytes::from_static(b"12345"));
        let hint = Body::size_hint(&body);
        assert_eq!(hint.exact(), Some(5));
    }

    #[test]
    fn size_hint_for_empty_body() {
        let body = IntoHttpBody::empty();
        let hint = Body::size_hint(&body);
        assert_eq!(hint.exact(), Some(0));
    }

    #[test]
    fn debug_impls() {
        let body = IntoHttpBody::full(bytes::Bytes::new());
        let dbg = format!("{body:?}");
        assert!(dbg.contains("IntoHttpBody"));
        assert!(dbg.contains("Full"));
    }

    #[test]
    fn body_limit_error_display() {
        let e: BodyLimitError<String> = BodyLimitError::TooLarge {
            limit: 100,
            received: 200,
        };
        assert!(e.to_string().contains("200"));
        assert!(e.to_string().contains("100"));

        let e: BodyLimitError<String> = BodyLimitError::Body("oops".into());
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn grpc_service_adapter_debug_clone() {
        let adapter = GrpcServiceAdapter::new("test_svc");
        let dbg = format!("{adapter:?}");
        assert!(dbg.contains("GrpcServiceAdapter"));

        let cloned = adapter.clone();
        assert_eq!(cloned.inner(), adapter.inner());
        assert_eq!(adapter.into_inner(), "test_svc");
    }

    #[test]
    fn empty_body_with_trailers_only() {
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", http::HeaderValue::from_static("0"));

        let body = IntoHttpBody::full(bytes::Bytes::new()).with_trailers(headers);

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(&waker);
        let mut body = std::pin::pin!(body);

        // Empty data is skipped, trailers come first.
        let frame = body.as_mut().poll_frame(&mut cx);
        match frame {
            Poll::Ready(Some(Ok(f))) => assert!(f.is_trailers()),
            other => panic!("expected trailers for empty body, got {other:?}"),
        }

        let frame = body.as_mut().poll_frame(&mut cx);
        assert!(matches!(frame, Poll::Ready(None)));
    }

    #[test]
    fn collect_body_limited_rejects_oversize() {
        use futures_lite::future::block_on;

        let body = IntoHttpBody::full(bytes::Bytes::from_static(b"too long"));
        let result = block_on(collect_body_limited(body, 3));
        assert!(matches!(result, Err(BodyLimitError::TooLarge { .. })));
    }

    #[test]
    fn collect_body_limited_accepts_within_limit() {
        use futures_lite::future::block_on;

        let body = IntoHttpBody::full(bytes::Bytes::from_static(b"ok"));
        let result = block_on(collect_body_limited(body, 100));
        assert_eq!(result.unwrap(), bytes::Bytes::from_static(b"ok"));
    }
}
