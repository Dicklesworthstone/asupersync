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

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::bytes::{Buf, Bytes, BytesCursor};
use crate::stream::Stream;

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

/// A header map type for trailers.
///
/// Uses a vector of key-value pairs internally, which is well-suited for
/// trailers (typically 1-3 headers). Header names are case-insensitive
/// per HTTP/2 requirements (lowercased on construction in [`HeaderName`]).
///
/// br-asupersync-yrwie0: `positions` uses `std::collections::HashMap`
/// with the default `RandomState` (per-process random seed) instead of
/// the deterministic `DetHashMap`. `HeaderName` is fully attacker-
/// controlled (HTTP requests carry arbitrary header names), and
/// `DetHasher` uses a fixed published seed — an attacker who reads
/// this source can pre-compute thousands of header names that all hash
/// to the same bucket and submit them in one request, turning HashMap
/// insert/get into O(n²). `RandomState` defeats the offline collision
/// search by re-seeding from OS entropy at process start. Determinism
/// is not required here: trailers are observed via `iter()` which
/// reads from the order-preserving `headers: Vec<…>`, not from the
/// HashMap's iteration order.
#[derive(Debug, Clone, Default)]
pub struct HeaderMap {
    headers: Vec<(HeaderName, HeaderValue)>,
    positions: HashMap<HeaderName, Vec<usize>>,
}

impl HeaderMap {
    /// Creates a new empty header map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new header map with the given capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            headers: Vec::with_capacity(capacity),
            positions: HashMap::with_capacity(capacity),
        }
    }

    /// Inserts a header into the map.
    pub fn insert(&mut self, name: HeaderName, value: HeaderValue) {
        if let Some(indices) = self.positions.remove(&name) {
            for index in indices.into_iter().rev() {
                self.headers.remove(index);
            }
            self.rebuild_positions();
        }

        self.append(name, value);
    }

    /// Appends a header to the map (allows duplicates).
    pub fn append(&mut self, name: HeaderName, value: HeaderValue) {
        let index = self.headers.len();
        self.positions.entry(name.clone()).or_default().push(index);
        self.headers.push((name, value));
    }

    /// Gets the first value for a header name.
    #[must_use]
    pub fn get(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.positions
            .get(name)
            .and_then(|indices| indices.first())
            .and_then(|index| self.headers.get(*index))
            .map(|(_, value)| value)
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

    fn rebuild_positions(&mut self) {
        self.positions.clear();
        for (index, (name, _)) in self.headers.iter().enumerate() {
            self.positions.entry(name.clone()).or_default().push(index);
        }
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
        assert!(
            self.upper.is_none_or(|upper| lower <= upper),
            "lower bound exceeds upper bound"
        );
        self.lower = lower;
    }

    /// Sets the upper bound.
    pub fn set_upper(&mut self, upper: u64) {
        assert!(upper >= self.lower, "upper bound is below lower bound");
        self.upper = Some(upper);
    }

    /// Sets both bounds to the same exact value.
    pub fn set_exact(&mut self, exact: u64) {
        self.lower = exact;
        self.upper = Some(exact);
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

/// Treat an already-buffered byte string as a single-frame HTTP body.
///
/// This compatibility-preserving implementation lets the public
/// `web::Response::body` field participate in the same [`Body`] contract as
/// [`Full`] and channel-backed streaming bodies without changing its `Bytes`
/// type. Polling transfers the immutable buffer into a [`BytesCursor`] without
/// copying it; an empty buffer is already at end-of-stream.
impl Body for Bytes {
    type Data = BytesCursor;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let bytes = std::mem::take(self.get_mut());
        if bytes.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some(Ok(Frame::Data(BytesCursor::new(bytes)))))
        }
    }

    fn is_end_stream(&self) -> bool {
        self.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(u64::try_from(self.len()).unwrap_or(u64::MAX))
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
    done: bool,
}

impl<S> StreamBody<S> {
    /// Creates a new stream body from the given stream.
    #[must_use]
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            done: false,
        }
    }

    /// Consumes the body and returns the inner stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S, D, E> Body for StreamBody<S>
where
    S: Stream<Item = Result<Frame<D>, E>> + Unpin,
    D: Buf,
{
    type Data = D;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.stream).poll_next(cx) {
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || matches!(self.stream.size_hint(), (0, Some(0)))
    }

    fn size_hint(&self) -> SizeHint {
        if self.done || matches!(self.stream.size_hint(), (0, Some(0))) {
            SizeHint::with_exact(0)
        } else {
            SizeHint::default()
        }
    }
}

/// A body that collects data from another body.
///
/// This is useful for buffering an entire body into memory.
#[derive(Debug)]
pub struct Collected<B: Body> {
    _inner: B,
    data: Vec<u8>,
    trailers: Option<HeaderMap>,
    _done: bool,
}

impl<B: Body> Collected<B>
where
    B::Data: Buf,
{
    /// Creates a new collecting body.
    pub fn new(inner: B) -> Self {
        Self {
            _inner: inner,
            data: Vec::new(),
            trailers: None,
            _done: false,
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
    consumed: u64,
    length_limit_actual: Option<u64>,
    // After a terminal result, stop polling the inner body again. Clean EOF
    // stays idempotent, while terminal failures fail closed on repoll.
    state: LimitedState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimitedState {
    Open,
    Completed,
    Failed,
}

impl<B> Limited<B> {
    /// Creates a new limited body with the given limit.
    pub fn new(inner: B, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
            consumed: 0,
            length_limit_actual: None,
            state: LimitedState::Open,
        }
    }

    /// Returns the total attempted DATA length that exceeded the limit.
    ///
    /// This is populated only after [`LimitedError::LengthLimit`] and lets a
    /// transport adapter preserve an exact over-limit diagnostic without
    /// exposing the refused frame.
    #[must_use]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn length_limit_actual(&self) -> Option<u64> {
        self.length_limit_actual
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
        match this.state {
            LimitedState::Completed => return Poll::Ready(None),
            LimitedState::Failed => {
                return Poll::Ready(Some(Err(LimitedError::PolledAfterCompletion)));
            }
            LimitedState::Open => {}
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.remaining() as u64;
                    if len > this.remaining {
                        this.length_limit_actual = this.consumed.checked_add(len);
                        this.state = LimitedState::Failed;
                        return Poll::Ready(Some(Err(LimitedError::LengthLimit)));
                    }
                    this.remaining -= len;
                    this.consumed += len;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.state = LimitedState::Failed;
                Poll::Ready(Some(Err(LimitedError::Inner(e))))
            }
            Poll::Ready(None) => {
                this.state = LimitedState::Completed;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.state != LimitedState::Open || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.state != LimitedState::Open {
            return SizeHint::with_exact(0);
        }
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
    /// This body was polled after a terminal failure.
    PolledAfterCompletion,
    /// An error from the inner body.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for LimitedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthLimit => write!(f, "body length limit exceeded"),
            Self::PolledAfterCompletion => write!(f, "limited body polled after completion"),
            Self::Inner(e) => write!(f, "{e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LimitedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LengthLimit | Self::PolledAfterCompletion => None,
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
#[path = "body_inline_tests.rs"]
mod tests;
