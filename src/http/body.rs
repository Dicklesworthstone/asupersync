//! HTTP body abstraction for streaming request and response bodies.
//!
//! This module provides the [`Body`] trait and common body implementations
//! for handling HTTP message bodies in a cancel-safe, streaming manner.
//!
//! # Body Trait
//!
//! The [`Body`] trait is the core abstraction for HTTP bodies. It provides
//! a streaming interface that yields [`Frame`]s containing either data chunks
//! or trailers.
//!
//! # Cancel Safety
//!
//! All body implementations are cancel-safe. Dropping a body at any point
//! is valid and will not cause data loss beyond the dropped body itself.

use std::convert::Infallible;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::bytes::{Buf, Bytes, BytesCursor};

/// A frame of body content: either data or trailers.
///
/// HTTP bodies are delivered as a stream of frames. Most frames contain
/// data chunks, but the final frame may contain trailers (additional
/// headers sent after the body).
#[derive(Debug)]
pub enum Frame<T> {
    /// A data chunk.
    Data(T),
    /// Trailing headers (HTTP/2, chunked encoding).
    Trailers(HeaderMap),
}

impl<T> Frame<T> {
    /// Creates a new data frame.
    #[must_use]
    pub fn data(data: T) -> Self {
        Self::Data(data)
    }

    /// Creates a new trailers frame.
    #[must_use]
    pub fn trailers(trailers: HeaderMap) -> Self {
        Self::Trailers(trailers)
    }

    /// Returns `true` if this is a data frame.
    #[must_use]
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data(_))
    }

    /// Returns `true` if this is a trailers frame.
    #[must_use]
    pub fn is_trailers(&self) -> bool {
        matches!(self, Self::Trailers(_))
    }

    /// Consumes the frame, returning the data if this is a data frame.
    pub fn into_data(self) -> Option<T> {
        match self {
            Self::Data(data) => Some(data),
            Self::Trailers(_) => None,
        }
    }

    /// Consumes the frame, returning the trailers if this is a trailers frame.
    pub fn into_trailers(self) -> Option<HeaderMap> {
        match self {
            Self::Data(_) => None,
            Self::Trailers(trailers) => Some(trailers),
        }
    }

    /// Returns a reference to the data if this is a data frame.
    #[must_use]
    pub fn data_ref(&self) -> Option<&T> {
        match self {
            Self::Data(data) => Some(data),
            Self::Trailers(_) => None,
        }
    }

    /// Returns a mutable reference to the data if this is a data frame.
    pub fn data_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Data(data) => Some(data),
            Self::Trailers(_) => None,
        }
    }

    /// Maps the data in this frame using the provided function.
    pub fn map_data<U, F>(self, f: F) -> Frame<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            Self::Data(data) => Frame::Data(f(data)),
            Self::Trailers(trailers) => Frame::Trailers(trailers),
        }
    }
}

/// A simple header map type for trailers.
///
/// In a full implementation, this would integrate with a proper HTTP
/// headers library. For now, we use a simple vector of key-value pairs.
#[derive(Debug, Clone, Default)]
pub struct HeaderMap {
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl HeaderMap {
    /// Creates a new empty header map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
        }
    }

    /// Creates a new header map with the given capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            headers: Vec::with_capacity(capacity),
        }
    }

    /// Inserts a header into the map.
    pub fn insert(&mut self, name: HeaderName, value: HeaderValue) {
        // Remove existing header with this name
        self.headers.retain(|(n, _)| n != &name);
        self.headers.push((name, value));
    }

    /// Appends a header to the map (allows duplicates).
    pub fn append(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers.push((name, value));
    }

    /// Gets the first value for a header name.
    #[must_use]
    pub fn get(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Returns an iterator over the headers.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.headers.iter().map(|(n, v)| (n, v))
    }

    /// Returns the number of headers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Returns `true` if the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

/// A header name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderName(String);

impl HeaderName {
    /// Creates a new header name from a string.
    ///
    /// The name is converted to lowercase per HTTP/2 requirements.
    #[must_use]
    pub fn from_static(name: &'static str) -> Self {
        Self(name.to_lowercase())
    }

    /// Creates a new header name from a string.
    #[must_use]
    pub fn from_string(name: &str) -> Self {
        Self(name.to_lowercase())
    }

    /// Returns the header name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderValue(Vec<u8>);

impl HeaderValue {
    /// Creates a new header value from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Creates a new header value from a static string.
    #[must_use]
    pub fn from_static(s: &'static str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    /// Creates a new header value from a string.
    #[must_use]
    pub fn from_string(s: String) -> Self {
        Self(s.into_bytes())
    }

    /// Returns the header value as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Attempts to convert the header value to a string.
    pub fn to_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }
}

impl fmt::Display for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_str() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "{:?}", self.0),
        }
    }
}

/// Size hint for a body.
///
/// Provides upper and lower bounds on the body size, useful for
/// setting Content-Length headers and buffer allocation.
#[derive(Debug, Clone, Copy, Default)]
pub struct SizeHint {
    lower: u64,
    upper: Option<u64>,
}

impl SizeHint {
    /// Creates a new size hint with default values (0 lower, no upper).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a size hint for a body of exact known size.
    #[must_use]
    pub fn with_exact(size: u64) -> Self {
        Self {
            lower: size,
            upper: Some(size),
        }
    }

    /// Returns the lower bound.
    #[must_use]
    pub fn lower(&self) -> u64 {
        self.lower
    }

    /// Returns the upper bound, if known.
    #[must_use]
    pub fn upper(&self) -> Option<u64> {
        self.upper
    }

    /// Returns the exact size if lower and upper bounds are equal.
    #[must_use]
    pub fn exact(&self) -> Option<u64> {
        match self.upper {
            Some(upper) if upper == self.lower => Some(upper),
            _ => None,
        }
    }

    /// Sets the lower bound.
    pub fn set_lower(&mut self, lower: u64) {
        self.lower = lower;
    }

    /// Sets the upper bound.
    pub fn set_upper(&mut self, upper: u64) {
        self.upper = Some(upper);
    }
}

/// The body trait for HTTP message bodies.
///
/// This trait provides a streaming interface for reading body content.
/// Bodies can be polled for frames containing either data or trailers.
///
/// # Example
///
/// ```ignore
/// async fn read_body<B: Body>(mut body: B) -> Result<Vec<u8>, B::Error> {
///     let mut data = Vec::new();
///     while let Some(frame) = body.frame().await? {
///         if let Some(chunk) = frame.into_data() {
///             data.extend_from_slice(chunk.chunk());
///         }
///     }
///     Ok(data)
/// }
/// ```
#[allow(clippy::type_complexity)]
pub trait Body {
    /// The buffer type for data frames.
    type Data: Buf;

    /// The error type for body operations.
    type Error;

    /// Polls for the next frame.
    ///
    /// Returns `Poll::Ready(Some(Ok(frame)))` when a frame is available,
    /// `Poll::Ready(Some(Err(e)))` on error, `Poll::Ready(None)` when the
    /// body is complete, or `Poll::Pending` if the body is not ready.
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>>;

    /// Returns `true` if the body is known to be complete.
    ///
    /// This is a hint that may be used to avoid additional polling.
    fn is_end_stream(&self) -> bool {
        false
    }

    /// Returns a hint about the body's size.
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

// Implement Body for Pin<Box<dyn Body>>
impl<B: Body + ?Sized> Body for Pin<Box<B>> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Pin<Box<B>> is always Unpin since Box<B>: Unpin
        // Use get_mut() to access the inner Pin<Box<B>>, then as_mut() to get Pin<&mut B>
        self.get_mut().as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.as_ref().is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.as_ref().size_hint()
    }
}

// Implement Body for &mut B where B: Body
impl<B: Body + Unpin + ?Sized> Body for &mut B {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut **self).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        (**self).is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        (**self).size_hint()
    }
}

// Implement Body for Box<B> where B: Body + Unpin
impl<B: Body + Unpin + ?Sized> Body for Box<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut **self).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        (**self).is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        (**self).size_hint()
    }
}

/// An empty body with no content.
///
/// Useful for requests or responses that have no body (e.g., GET requests,
/// 204 No Content responses).
#[derive(Debug, Clone, Copy, Default)]
pub struct Empty;

impl Empty {
    /// Creates a new empty body.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Body for Empty {
    type Data = BytesCursor;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        true
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(0)
    }
}

/// A body containing a single chunk of known data.
///
/// Useful for bodies where the entire content is available upfront.
#[derive(Debug, Clone)]
pub struct Full<D> {
    data: Option<D>,
}

impl<D> Full<D> {
    /// Creates a new full body with the given data.
    #[must_use]
    pub fn new(data: D) -> Self {
        Self { data: Some(data) }
    }
}

impl<D: Buf + Unpin> Body for Full<D> {
    type Data = D;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Full<D> is Unpin when D: Unpin, so we can use get_mut()
        let this = self.get_mut();
        match this.data.take() {
            Some(data) if data.remaining() > 0 => Poll::Ready(Some(Ok(Frame::Data(data)))),
            _ => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.data.as_ref().is_none_or(|d| d.remaining() == 0)
    }

    fn size_hint(&self) -> SizeHint {
        self.data.as_ref().map_or_else(
            || SizeHint::with_exact(0),
            |data| SizeHint::with_exact(data.remaining() as u64),
        )
    }
}

impl<D> From<D> for Full<D>
where
    D: Buf,
{
    fn from(data: D) -> Self {
        Self::new(data)
    }
}

impl From<&'static str> for Full<BytesCursor> {
    fn from(s: &'static str) -> Self {
        Self::new(BytesCursor::new(Bytes::from_static(s.as_bytes())))
    }
}

impl From<String> for Full<BytesCursor> {
    fn from(s: String) -> Self {
        Self::new(BytesCursor::new(Bytes::from(s.into_bytes())))
    }
}

impl From<Vec<u8>> for Full<BytesCursor> {
    fn from(v: Vec<u8>) -> Self {
        Self::new(BytesCursor::new(Bytes::from(v)))
    }
}

/// A body that wraps a stream of frames.
///
/// This allows converting any stream that yields body frames into a Body.
#[derive(Debug)]
pub struct StreamBody<S> {
    stream: S,
}

impl<S> StreamBody<S> {
    /// Creates a new stream body from the given stream.
    #[must_use]
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Consumes the body and returns the inner stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

// We implement Body for StreamBody when S implements the necessary traits.
// In a full implementation, this would use futures::Stream.
// For now, we provide a manual poll-based implementation.

/// A body that collects data from another body.
///
/// This is useful for buffering an entire body into memory.
#[derive(Debug)]
pub struct Collected<B: Body> {
    inner: B,
    data: Vec<u8>,
    trailers: Option<HeaderMap>,
    done: bool,
}

impl<B: Body> Collected<B>
where
    B::Data: Buf,
{
    /// Creates a new collecting body.
    pub fn new(inner: B) -> Self {
        Self {
            inner,
            data: Vec::new(),
            trailers: None,
            done: false,
        }
    }

    /// Returns the collected data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the trailers, if any.
    #[must_use]
    pub fn trailers(&self) -> Option<&HeaderMap> {
        self.trailers.as_ref()
    }

    /// Consumes the collector and returns the collected data.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

/// A body that limits the size of another body.
///
/// Returns an error if the inner body exceeds the limit.
#[derive(Debug)]
pub struct Limited<B> {
    inner: B,
    remaining: u64,
}

impl<B> Limited<B> {
    /// Creates a new limited body with the given limit.
    pub fn new(inner: B, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

/// Error returned when a limited body exceeds its limit.
#[derive(Debug, Clone, Copy)]
pub struct LengthLimitError;

impl fmt::Display for LengthLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "body length limit exceeded")
    }
}

impl std::error::Error for LengthLimitError {}

impl<B: Body + Unpin> Body for Limited<B>
where
    B::Data: Buf,
{
    type Data = B::Data;
    type Error = LimitedError<B::Error>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.remaining() as u64;
                    if len > this.remaining {
                        return Poll::Ready(Some(Err(LimitedError::LengthLimit)));
                    }
                    this.remaining -= len;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(LimitedError::Inner(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let inner = self.inner.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().min(self.remaining));
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper.min(self.remaining));
        } else {
            hint.set_upper(self.remaining);
        }
        hint
    }
}

/// Error from a limited body.
#[derive(Debug)]
pub enum LimitedError<E> {
    /// The length limit was exceeded.
    LengthLimit,
    /// An error from the inner body.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for LimitedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthLimit => write!(f, "body length limit exceeded"),
            Self::Inner(e) => write!(f, "{e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LimitedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LengthLimit => None,
            Self::Inner(e) => Some(e),
        }
    }
}

/// A boxed body with type-erased data and error types.
///
/// Useful for storing bodies of different concrete types.
pub type BoxBody<D, E> = Pin<Box<dyn Body<Data = D, Error = E> + Send + 'static>>;

/// Creates a boxed body from any body type.
pub fn boxed<B>(body: B) -> BoxBody<B::Data, B::Error>
where
    B: Body + Send + 'static,
{
    Box::pin(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Wake;

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: std::sync::Arc<Self>) {}
    }

    fn noop_waker() -> std::task::Waker {
        std::sync::Arc::new(NoopWaker).into()
    }

    #[allow(clippy::type_complexity)]
    fn poll_body<B: Body + Unpin>(body: &mut B) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(body).poll_frame(&mut cx)
    }

    #[test]
    fn empty_body_is_end_stream() {
        let body = Empty::new();
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
    }

    #[test]
    fn empty_body_returns_none() {
        let mut body = Empty::new();
        match poll_body(&mut body) {
            Poll::Ready(None) => {}
            _ => panic!("expected Poll::Ready(None)"),
        }
    }

    #[test]
    fn full_body_returns_data_then_none() {
        // Use BytesCursor which implements Buf (Bytes alone doesn't implement Buf)
        let cursor = BytesCursor::new(Bytes::from_static(b"hello"));
        let mut body = Full::new(cursor);

        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(5));

        match poll_body(&mut body) {
            Poll::Ready(Some(Ok(frame))) => {
                let data = frame.into_data().expect("expected data frame");
                assert_eq!(data.chunk(), b"hello");
            }
            _ => panic!("expected data frame"),
        }

        assert!(body.is_end_stream());

        match poll_body(&mut body) {
            Poll::Ready(None) => {}
            _ => panic!("expected Poll::Ready(None)"),
        }
    }

    #[test]
    fn full_body_from_string() {
        // BytesCursor wraps Bytes and implements Buf
        let cursor = BytesCursor::new(Bytes::from_static(b"hello world"));
        let body = Full::new(cursor);
        assert_eq!(body.size_hint().exact(), Some(11));
    }

    #[test]
    fn full_body_from_vec() {
        // BytesCursor wraps Bytes and implements Buf
        let cursor = BytesCursor::new(Bytes::from(vec![1_u8, 2, 3, 4, 5]));
        let body = Full::new(cursor);
        assert_eq!(body.size_hint().exact(), Some(5));
    }

    #[test]
    fn size_hint_exact() {
        let hint = SizeHint::with_exact(42);
        assert_eq!(hint.lower(), 42);
        assert_eq!(hint.upper(), Some(42));
        assert_eq!(hint.exact(), Some(42));
    }

    #[test]
    fn size_hint_default() {
        let hint = SizeHint::default();
        assert_eq!(hint.lower(), 0);
        assert_eq!(hint.upper(), None);
        assert_eq!(hint.exact(), None);
    }

    #[test]
    fn frame_data_methods() {
        let frame: Frame<Bytes> = Frame::data(Bytes::from_static(b"test"));
        assert!(frame.is_data());
        assert!(!frame.is_trailers());
        assert_eq!(frame.data_ref().unwrap().as_ref(), b"test");
    }

    #[test]
    fn frame_trailers_methods() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-checksum"),
            HeaderValue::from_static("abc123"),
        );

        let frame: Frame<Bytes> = Frame::trailers(headers);
        assert!(!frame.is_data());
        assert!(frame.is_trailers());
    }

    #[test]
    fn header_map_operations() {
        let mut headers = HeaderMap::new();
        assert!(headers.is_empty());

        let name = HeaderName::from_static("content-type");
        let value = HeaderValue::from_static("application/json");

        headers.insert(name.clone(), value);
        assert_eq!(headers.len(), 1);
        assert!(!headers.is_empty());

        let retrieved = headers.get(&name).expect("header should exist");
        assert_eq!(retrieved.as_bytes(), b"application/json");
    }

    #[test]
    fn header_name_lowercase() {
        let name = HeaderName::from_static("Content-Type");
        assert_eq!(name.as_str(), "content-type");
    }

    // ========================================================================
    // Pure data-type tests (wave 9 – CyanBarn)
    // ========================================================================

    #[test]
    fn frame_into_data_some() {
        let frame: Frame<Vec<u8>> = Frame::data(vec![1, 2, 3]);
        let data = frame.into_data();
        assert_eq!(data, Some(vec![1, 2, 3]));
    }

    #[test]
    fn frame_into_data_none_for_trailers() {
        let frame: Frame<Vec<u8>> = Frame::trailers(HeaderMap::new());
        assert!(frame.into_data().is_none());
    }

    #[test]
    fn frame_into_trailers_some() {
        let mut hm = HeaderMap::new();
        hm.insert(
            HeaderName::from_static("x-foo"),
            HeaderValue::from_static("bar"),
        );
        let frame: Frame<Vec<u8>> = Frame::trailers(hm);
        let trailers = frame.into_trailers().expect("should be trailers");
        assert_eq!(trailers.len(), 1);
    }

    #[test]
    fn frame_into_trailers_none_for_data() {
        let frame: Frame<Vec<u8>> = Frame::data(vec![]);
        assert!(frame.into_trailers().is_none());
    }

    #[test]
    fn frame_data_mut() {
        let mut frame: Frame<Vec<u8>> = Frame::data(vec![1]);
        if let Some(data) = frame.data_mut() {
            data.push(2);
        }
        assert_eq!(frame.data_ref(), Some(&vec![1, 2]));
    }

    #[test]
    fn frame_data_mut_none_for_trailers() {
        let mut frame: Frame<Vec<u8>> = Frame::trailers(HeaderMap::new());
        assert!(frame.data_mut().is_none());
    }

    #[test]
    fn frame_map_data() {
        let frame: Frame<u32> = Frame::data(5);
        let mapped = frame.map_data(|n| n * 2);
        assert_eq!(mapped.into_data(), Some(10));
    }

    #[test]
    fn frame_map_data_preserves_trailers() {
        let frame: Frame<u32> = Frame::trailers(HeaderMap::new());
        let mapped = frame.map_data(|n: u32| n * 2);
        assert!(mapped.is_trailers());
    }

    #[test]
    fn frame_debug() {
        let frame: Frame<u32> = Frame::data(42);
        let dbg = format!("{frame:?}");
        assert!(dbg.contains("Data"), "{dbg}");
    }

    #[test]
    fn header_map_with_capacity() {
        let hm = HeaderMap::with_capacity(10);
        assert!(hm.is_empty());
        assert_eq!(hm.len(), 0);
    }

    #[test]
    fn header_map_insert_replaces() {
        let mut hm = HeaderMap::new();
        let name = HeaderName::from_static("x-key");
        hm.insert(name.clone(), HeaderValue::from_static("v1"));
        hm.insert(name.clone(), HeaderValue::from_static("v2"));
        assert_eq!(hm.len(), 1);
        assert_eq!(hm.get(&name).unwrap().to_str().unwrap(), "v2");
    }

    #[test]
    fn header_map_append_allows_duplicates() {
        let mut hm = HeaderMap::new();
        let name = HeaderName::from_static("x-multi");
        hm.append(name.clone(), HeaderValue::from_static("a"));
        hm.append(name.clone(), HeaderValue::from_static("b"));
        assert_eq!(hm.len(), 2);
    }

    #[test]
    fn header_map_iter() {
        let mut hm = HeaderMap::new();
        hm.insert(
            HeaderName::from_static("a"),
            HeaderValue::from_static("1"),
        );
        hm.insert(
            HeaderName::from_static("b"),
            HeaderValue::from_static("2"),
        );
        let count = hm.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn header_map_get_missing() {
        let hm = HeaderMap::new();
        let name = HeaderName::from_static("missing");
        assert!(hm.get(&name).is_none());
    }

    #[test]
    fn header_map_debug_clone_default() {
        let hm = HeaderMap::default();
        assert!(hm.is_empty());
        let dbg = format!("{hm:?}");
        assert!(dbg.contains("HeaderMap"), "{dbg}");

        let mut hm2 = hm.clone();
        hm2.insert(
            HeaderName::from_static("x"),
            HeaderValue::from_static("y"),
        );
        assert_eq!(hm2.len(), 1);
    }

    #[test]
    fn header_name_from_string() {
        let name = HeaderName::from_string("X-Custom");
        assert_eq!(name.as_str(), "x-custom");
    }

    #[test]
    fn header_name_display() {
        let name = HeaderName::from_static("content-type");
        assert_eq!(format!("{name}"), "content-type");
    }

    #[test]
    fn header_name_eq_hash() {
        let a = HeaderName::from_static("x-foo");
        let b = HeaderName::from_string("X-Foo");
        assert_eq!(a, b);

        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
    }

    #[test]
    fn header_value_from_bytes() {
        let v = HeaderValue::from_bytes(b"hello");
        assert_eq!(v.as_bytes(), b"hello");
        assert_eq!(v.to_str().unwrap(), "hello");
    }

    #[test]
    fn header_value_from_string() {
        let v = HeaderValue::from_string("world".to_string());
        assert_eq!(v.as_bytes(), b"world");
    }

    #[test]
    fn header_value_display_utf8() {
        let v = HeaderValue::from_static("text/plain");
        assert_eq!(format!("{v}"), "text/plain");
    }

    #[test]
    fn header_value_display_non_utf8() {
        let v = HeaderValue::from_bytes(&[0xFF, 0xFE]);
        let disp = format!("{v}");
        // Non-UTF8 goes through Debug path
        assert!(disp.contains("255"), "{disp}");
    }

    #[test]
    fn header_value_eq_clone() {
        let a = HeaderValue::from_static("x");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn size_hint_set_lower_upper() {
        let mut hint = SizeHint::new();
        hint.set_lower(10);
        hint.set_upper(100);
        assert_eq!(hint.lower(), 10);
        assert_eq!(hint.upper(), Some(100));
        assert_eq!(hint.exact(), None); // lower != upper
    }

    #[test]
    fn size_hint_exact_mismatch() {
        let mut hint = SizeHint::new();
        hint.set_lower(5);
        hint.set_upper(10);
        assert_eq!(hint.exact(), None);
    }

    #[test]
    fn size_hint_debug_clone_copy() {
        let hint = SizeHint::with_exact(42);
        let dbg = format!("{hint:?}");
        assert!(dbg.contains("SizeHint"), "{dbg}");
        let copied = hint; // Copy
        let cloned = hint.clone();
        assert_eq!(copied.exact(), cloned.exact());
    }

    #[test]
    fn empty_debug_clone_copy_default() {
        let e = Empty::new();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Empty"), "{dbg}");
        let copied = e; // Copy
        let cloned = e.clone();
        let defaulted = Empty::default();
        // All are the unit struct
        let _ = (copied, cloned, defaulted);
    }

    #[test]
    fn full_debug_clone() {
        let cursor = BytesCursor::new(Bytes::from_static(b"abc"));
        let body = Full::new(cursor);
        let dbg = format!("{body:?}");
        assert!(dbg.contains("Full"), "{dbg}");
        let cloned = body.clone();
        assert_eq!(cloned.size_hint().exact(), Some(3));
    }

    #[test]
    fn full_from_static_str() {
        let body: Full<BytesCursor> = Full::from("hello");
        assert_eq!(body.size_hint().exact(), Some(5));
    }

    #[test]
    fn full_from_string_conversion() {
        let body: Full<BytesCursor> = Full::from("world".to_string());
        assert_eq!(body.size_hint().exact(), Some(5));
    }

    #[test]
    fn full_from_vec() {
        let body: Full<BytesCursor> = Full::from(vec![1u8, 2, 3]);
        assert_eq!(body.size_hint().exact(), Some(3));
    }

    #[test]
    fn full_empty_data_is_end_stream() {
        let cursor = BytesCursor::new(Bytes::from_static(b""));
        let body = Full::new(cursor);
        assert!(body.is_end_stream());
    }

    #[test]
    fn stream_body_debug_and_into_inner() {
        let stream = vec![1, 2, 3];
        let body = StreamBody::new(stream);
        let dbg = format!("{body:?}");
        assert!(dbg.contains("StreamBody"), "{dbg}");
        let inner = body.into_inner();
        assert_eq!(inner, vec![1, 2, 3]);
    }

    #[test]
    fn length_limit_error_display() {
        let err = LengthLimitError;
        assert_eq!(format!("{err}"), "body length limit exceeded");
    }

    #[test]
    fn length_limit_error_debug_clone_copy() {
        let err = LengthLimitError;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("LengthLimitError"), "{dbg}");
        let copied = err; // Copy
        let cloned = err.clone();
        let _ = (copied, cloned);
    }

    #[test]
    fn length_limit_error_is_std_error() {
        let err = LengthLimitError;
        let _: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn limited_error_display() {
        let err: LimitedError<std::io::Error> = LimitedError::LengthLimit;
        assert_eq!(format!("{err}"), "body length limit exceeded");

        let inner_err = LimitedError::Inner(std::io::Error::new(
            std::io::ErrorKind::Other,
            "inner",
        ));
        let disp = format!("{inner_err}");
        assert!(disp.contains("inner"), "{disp}");
    }

    #[test]
    fn limited_error_debug() {
        let err: LimitedError<&str> = LimitedError::LengthLimit;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("LengthLimit"), "{dbg}");
    }

    #[test]
    fn limited_error_source() {
        let err: LimitedError<std::io::Error> = LimitedError::LengthLimit;
        assert!(std::error::Error::source(&err).is_none());

        let inner = LimitedError::Inner(std::io::Error::new(
            std::io::ErrorKind::Other,
            "cause",
        ));
        assert!(std::error::Error::source(&inner).is_some());
    }

    #[test]
    fn collected_body_initial_state() {
        let body = Collected::new(Empty::new());
        assert!(body.data().is_empty());
        assert!(body.trailers().is_none());
    }

    #[test]
    fn collected_body_into_data() {
        let body = Collected::new(Empty::new());
        let data = body.into_data();
        assert!(data.is_empty());
    }

    #[test]
    fn limited_body_new() {
        let inner = Empty::new();
        let limited = Limited::new(inner, 1024);
        let dbg = format!("{limited:?}");
        assert!(dbg.contains("Limited"), "{dbg}");
    }
}
