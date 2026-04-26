//! gRPC streaming types and patterns.
//!
//! Implements the four gRPC streaming patterns:
//! - Unary: single request, single response
//! - Server streaming: single request, stream of responses
//! - Client streaming: stream of requests, single response
//! - Bidirectional streaming: stream of requests and responses

use std::any::{Any, TypeId};
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use crate::bytes::Bytes;

use super::status::{GrpcError, Status};

/// A gRPC request with metadata.
#[derive(Debug)]
pub struct Request<T> {
    /// Request metadata (headers).
    metadata: Metadata,
    /// The request message.
    message: T,
    /// Server-side typed extensions populated by interceptors. Not on
    /// the wire; cleared between independent requests.
    extensions: Extensions,
}

impl<T> Request<T> {
    /// Create a new request with the given message.
    #[must_use]
    pub fn new(message: T) -> Self {
        Self {
            metadata: Metadata::new(),
            message,
            extensions: Extensions::new(),
        }
    }

    /// Create a request with metadata.
    #[must_use]
    pub fn with_metadata(message: T, metadata: Metadata) -> Self {
        Self {
            metadata,
            message,
            extensions: Extensions::new(),
        }
    }

    /// Get a reference to the request metadata.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Get a mutable reference to the request metadata.
    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    /// Get a reference to the typed server-side extensions.
    ///
    /// Extensions are populated by interceptors and read by downstream
    /// interceptors / handlers. Unlike metadata, extensions are NOT
    /// transmitted on the wire — use them for capabilities like
    /// `AuthContext` that downstream code needs but the peer must not
    /// see (br-asupersync-z719f7).
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Get a mutable reference to the typed server-side extensions.
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }

    /// Get a reference to the request message.
    pub fn get_ref(&self) -> &T {
        &self.message
    }

    /// Get a mutable reference to the request message.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.message
    }

    /// Consume the request and return the message.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.message
    }

    /// Map the message type. Extensions and metadata are preserved.
    pub fn map<F, U>(self, f: F) -> Request<U>
    where
        F: FnOnce(T) -> U,
    {
        Request {
            metadata: self.metadata,
            message: f(self.message),
            extensions: self.extensions,
        }
    }
}

// ─── Extensions ──────────────────────────────────────────────────────────────

/// Server-side typed extension map for interceptor-injected data.
///
/// Lets earlier interceptors share typed values (e.g. an `AuthContext`)
/// with downstream interceptors and handlers WITHOUT routing the value
/// through `Metadata` (which is on the wire and could leak server-side
/// state to the peer or upstream services).
///
/// Stores values keyed by `TypeId`, so each concrete type T has at most
/// one entry. Insert another value of the same T to replace it.
///
/// # Example
///
/// ```ignore
/// use asupersync::grpc::interceptor::AuthContext;
/// use asupersync::grpc::server::Interceptor;
///
/// struct AuthInterceptor;
/// impl Interceptor for AuthInterceptor {
///     fn intercept_request(&self, req: &mut Request<Bytes>) -> Result<(), Status> {
///         let token = req.metadata().get("authorization").ok_or_else(|| {
///             Status::unauthenticated("missing authorization")
///         })?;
///         let auth = AuthContext::with_principal(parse_user_id(token));
///         req.extensions_mut().insert_typed(auth);
///         Ok(())
///     }
/// }
///
/// // Downstream interceptor reads:
/// fn handle(req: &Request<Bytes>) {
///     if let Some(auth) = req.extensions().get_typed::<AuthContext>() {
///         tracing::info!(principal = %auth.principal, "authenticated");
///     }
/// }
/// ```
#[derive(Clone, Default)]
pub struct Extensions {
    typed_data: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl std::fmt::Debug for Extensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extensions")
            .field("typed_count", &self.typed_data.len())
            .finish()
    }
}

impl Extensions {
    /// Create an empty extensions map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a typed value. Replaces any previous value of the same type.
    pub fn insert_typed<T>(&mut self, value: T)
    where
        T: Send + Sync + 'static,
    {
        self.typed_data.insert(TypeId::of::<T>(), Arc::new(value));
    }

    /// Get a typed value by reference.
    #[must_use]
    pub fn get_typed<T>(&self) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.typed_data
            .get(&TypeId::of::<T>())
            .and_then(|value| value.as_ref().downcast_ref::<T>())
    }

    /// Get a clone of a typed value if present.
    #[must_use]
    pub fn get_typed_cloned<T>(&self) -> Option<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        self.get_typed::<T>().cloned()
    }

    /// Returns the number of distinct typed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.typed_data.len()
    }

    /// Returns `true` if no extensions are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.typed_data.is_empty()
    }
}

/// A gRPC response with metadata.
#[derive(Debug)]
pub struct Response<T> {
    /// Response metadata (headers).
    metadata: Metadata,
    /// The response message.
    message: T,
}

impl<T> Response<T> {
    /// Create a new response with the given message.
    #[must_use]
    pub fn new(message: T) -> Self {
        Self {
            metadata: Metadata::new(),
            message,
        }
    }

    /// Create a response with metadata.
    #[must_use]
    pub fn with_metadata(message: T, metadata: Metadata) -> Self {
        Self { metadata, message }
    }

    /// Get a reference to the response metadata.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Get a mutable reference to the response metadata.
    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    /// Get a reference to the response message.
    pub fn get_ref(&self) -> &T {
        &self.message
    }

    /// Get a mutable reference to the response message.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.message
    }

    /// Consume the response and return the message.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.message
    }

    /// Map the message type.
    pub fn map<F, U>(self, f: F) -> Response<U>
    where
        F: FnOnce(T) -> U,
    {
        Response {
            metadata: self.metadata,
            message: f(self.message),
        }
    }
}

/// gRPC metadata (headers/trailers).
#[derive(Debug, Clone)]
pub struct Metadata {
    /// The metadata entries.
    entries: Vec<(String, MetadataValue)>,
}

/// A metadata value (either ASCII or binary).
#[derive(Debug, Clone, PartialEq)]
pub enum MetadataValue {
    /// ASCII text value.
    Ascii(String),
    /// Binary value (key must end in "-bin").
    Binary(Bytes),
}

pub(crate) fn normalize_metadata_key(key: &str, binary: bool) -> Option<String> {
    let mut normalized = key.to_ascii_lowercase();
    if binary && !normalized.ends_with("-bin") {
        normalized.push_str("-bin");
    }
    if normalized.is_empty() {
        return None;
    }

    for ch in normalized.chars() {
        let valid = ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.');
        if !valid {
            return None;
        }
    }

    Some(normalized)
}

pub(crate) fn sanitize_metadata_ascii_value(value: &str) -> Cow<'_, str> {
    if value.contains(['\r', '\n']) {
        Cow::Owned(value.replace(['\r', '\n'], ""))
    } else {
        Cow::Borrowed(value)
    }
}

impl Metadata {
    /// Create empty metadata.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(4),
        }
    }

    /// Reserve capacity for at least `additional` more entries.
    pub fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
    }

    /// Insert an ASCII value.
    ///
    /// Returns `false` when the metadata key is invalid and the entry is
    /// rejected. CR/LF are stripped from ASCII values to prevent header or
    /// trailer injection when metadata is encoded onto the wire.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> bool {
        let key = key.into();
        let Some(key) = normalize_metadata_key(&key, false) else {
            return false;
        };
        let value = value.into();
        let sanitized = sanitize_metadata_ascii_value(&value).into_owned();
        self.entries.push((key, MetadataValue::Ascii(sanitized)));
        true
    }

    /// Insert an ASCII value, replacing any existing entries for the same key.
    ///
    /// Returns `false` when the metadata key is invalid and the entry is
    /// rejected. CR/LF are stripped from ASCII values to prevent header or
    /// trailer injection when metadata is encoded onto the wire.
    pub fn insert_or_replace(&mut self, key: impl Into<String>, value: impl Into<String>) -> bool {
        let key = key.into();
        let Some(key) = normalize_metadata_key(&key, false) else {
            return false;
        };
        let value = value.into();
        let sanitized = sanitize_metadata_ascii_value(&value).into_owned();
        self.entries
            .retain(|(existing_key, _)| !existing_key.eq_ignore_ascii_case(&key));
        self.entries.push((key, MetadataValue::Ascii(sanitized)));
        true
    }

    /// Insert a binary value.
    ///
    /// Returns `false` when the metadata key is invalid and the entry is
    /// rejected.
    pub fn insert_bin(&mut self, key: impl Into<String>, value: Bytes) -> bool {
        let key = key.into();
        let Some(key) = normalize_metadata_key(&key, true) else {
            return false;
        };
        self.entries.push((key, MetadataValue::Binary(value)));
        true
    }

    /// Get a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&MetadataValue> {
        // Return the most recently inserted value for the key.
        // gRPC metadata keys are case-insensitive (HTTP/2 header semantics).
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    }

    /// Iterate over entries.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &MetadataValue)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Returns true if metadata is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self::new()
    }
}

/// A streaming body for gRPC messages.
pub trait Streaming: Send {
    /// The message type.
    type Message;

    /// Poll for the next message.
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Message, Status>>>;
}

/// Maximum items buffered in a streaming request or response before
/// backpressure is applied to the sender.
pub(crate) const MAX_STREAM_BUFFERED: usize = 1024;

/// A streaming request body.
#[derive(Debug)]
pub struct StreamingRequest<T> {
    /// Buffered stream items.
    items: VecDeque<Result<T, Status>>,
    /// Whether no further items will arrive.
    closed: bool,
    /// Last waker waiting for a new item.
    waiter: Option<Waker>,
}

impl<T> StreamingRequest<T> {
    /// Create a new streaming request.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: VecDeque::new(),
            closed: true,
            waiter: None,
        }
    }

    /// Creates an open request stream that may receive additional items.
    #[must_use]
    pub fn open() -> Self {
        Self {
            items: VecDeque::new(),
            closed: false,
            waiter: None,
        }
    }

    /// Pushes a message into the stream queue.
    ///
    /// Returns an error if the stream has been closed.
    pub fn push(&mut self, item: T) -> Result<(), Status> {
        self.push_result(Ok(item))
    }

    /// Pushes a pre-constructed stream result.
    ///
    /// Returns an error if the stream has been closed.
    pub fn push_result(&mut self, item: Result<T, Status>) -> Result<(), Status> {
        if self.closed {
            return Err(Status::failed_precondition(
                "cannot push to a closed streaming request",
            ));
        }
        // Cap buffer size to prevent unbounded growth from a flooding client.
        if self.items.len() >= MAX_STREAM_BUFFERED {
            return Err(Status::resource_exhausted(
                "streaming request buffer full — apply backpressure",
            ));
        }
        self.items.push_back(item);
        if let Some(waiter) = self.waiter.take() {
            waiter.wake();
        }
        Ok(())
    }

    /// Closes the stream. Remaining buffered items can still be consumed.
    pub fn close(&mut self) {
        self.closed = true;
        if let Some(waiter) = self.waiter.take() {
            waiter.wake();
        }
    }
}

impl<T> Default for StreamingRequest<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send + std::marker::Unpin> Streaming for StreamingRequest<T> {
    type Message = T;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Message, Status>>> {
        let this = self.get_mut();
        if let Some(next) = this.items.pop_front() {
            return Poll::Ready(Some(next));
        }
        if this.closed {
            return Poll::Ready(None);
        }
        this.waiter = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Server streaming response.
#[derive(Debug)]
pub struct ServerStreaming<T, S> {
    /// The underlying stream.
    inner: S,
    /// Phantom data for the message type.
    _marker: PhantomData<T>,
}

impl<T, S> ServerStreaming<T, S> {
    /// Create a new server streaming response.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    /// Get a reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume and return the inner stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<T: Send + Unpin, S: Streaming<Message = T> + Unpin> Streaming for ServerStreaming<T, S> {
    type Message = T;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Message, Status>>> {
        // Safety: ServerStreaming is Unpin if S is Unpin
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_next(cx)
    }
}

/// Client streaming request handler.
#[derive(Debug)]
pub struct ClientStreaming<T> {
    /// Phantom data for the message type.
    _marker: PhantomData<T>,
}

impl<T> ClientStreaming<T> {
    /// Create a new client streaming handler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<T> Default for ClientStreaming<T> {
    fn default() -> Self {
        Self::new()
    }
}

// br-asupersync-iuoayq: deleted the `Bidirectional<Req, Resp>` PhantomData
// stub. It carried no state, did no I/O, and had zero internal users
// other than a Debug-print test. The real bidirectional surface is
// reached via `crate::grpc::client::Channel::client_bidirectional` →
// `(RequestSink, ResponseStream)` (both from `crate::grpc::client`).

/// Streaming result type.
pub type StreamingResult<T> = Result<Response<T>, Status>;

/// Unary call future.
pub trait UnaryFuture: Future<Output = Result<Response<Self::Response>, Status>> + Send {
    /// The response type.
    type Response;
}

impl<T, F> UnaryFuture for F
where
    F: Future<Output = Result<Response<T>, Status>> + Send,
    T: Send,
{
    type Response = T;
}

/// In-file buffer-only stream used by this module's unit tests.
///
/// **Not a production type.** This `ResponseStream` is shadowed at the
/// `crate::grpc` namespace by [`crate::grpc::client::ResponseStream`],
/// which is the network-backed implementation re-exported from
/// `crate::grpc::*`. New code reaching for "the gRPC response stream"
/// should use `crate::grpc::ResponseStream` (the client version) — the
/// only path to *this* type is the fully qualified
/// `crate::grpc::streaming::ResponseStream`, which exists solely so the
/// adjacent `Streaming` trait + `ServerStreaming` adapter have an
/// in-file driver to exercise their poll loop without spinning up a
/// real connection (br-asupersync-iuoayq).
#[derive(Debug)]
pub struct ResponseStream<T> {
    /// Buffered stream items.
    items: VecDeque<Result<T, Status>>,
    /// Whether the stream is terminal.
    closed: bool,
    /// Last pending poll waker.
    waiter: Option<Waker>,
}

impl<T> ResponseStream<T> {
    /// Create a new response stream.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: VecDeque::new(),
            closed: true,
            waiter: None,
        }
    }

    /// Creates an open stream.
    #[must_use]
    pub fn open() -> Self {
        Self {
            items: VecDeque::new(),
            closed: false,
            waiter: None,
        }
    }

    /// Enqueue a streamed response item.
    pub fn push(&mut self, item: Result<T, Status>) -> Result<(), Status> {
        if self.closed {
            return Err(Status::failed_precondition(
                "cannot push to a closed response stream",
            ));
        }
        // Cap buffer size to prevent unbounded growth from a flooding sender.
        if self.items.len() >= MAX_STREAM_BUFFERED {
            return Err(Status::resource_exhausted(
                "response stream buffer full — apply backpressure",
            ));
        }
        self.items.push_back(item);
        if let Some(waiter) = self.waiter.take() {
            waiter.wake();
        }
        Ok(())
    }

    /// Mark stream completion.
    pub fn close(&mut self) {
        self.closed = true;
        if let Some(waiter) = self.waiter.take() {
            waiter.wake();
        }
    }
}

impl<T> Default for ResponseStream<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send + std::marker::Unpin> Streaming for ResponseStream<T> {
    type Message = T;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Message, Status>>> {
        let this = self.get_mut();
        if let Some(next) = this.items.pop_front() {
            return Poll::Ready(Some(next));
        }
        if this.closed {
            return Poll::Ready(None);
        }
        this.waiter = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// In-file no-op sink used by this module's unit tests.
///
/// **Not a production type.** `send` and `close` only update an internal
/// counter — no bytes ever leave the process. The production
/// `RequestSink` lives in [`crate::grpc::client`] (network-backed,
/// codec-aware, integrates with `Channel::client_streaming` /
/// `Channel::client_bidirectional`). It is **not** re-exported from
/// `crate::grpc`, so callers that mistakenly type
/// `use crate::grpc::streaming::RequestSink` and reach this stub will
/// observe silently dropped sends; importing
/// `crate::grpc::client::RequestSink` is the only correct production
/// path (br-asupersync-iuoayq).
#[derive(Debug)]
pub struct RequestSink<T> {
    /// Whether the sink has been closed.
    closed: bool,
    /// Number of sent items.
    sent_count: usize,
    /// Phantom data for the message type.
    _marker: PhantomData<T>,
}

impl<T> RequestSink<T> {
    /// Create a new request sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            closed: false,
            sent_count: 0,
            _marker: PhantomData,
        }
    }

    /// Returns the number of successfully sent items.
    #[must_use]
    pub const fn sent_count(&self) -> usize {
        self.sent_count
    }

    /// Send a message.
    #[allow(clippy::unused_async)]
    pub async fn send(&mut self, _item: T) -> Result<(), GrpcError> {
        if self.closed {
            return Err(GrpcError::protocol("request sink is already closed"));
        }
        self.sent_count += 1;
        Ok(())
    }

    /// Close the sink and wait for the response.
    #[allow(clippy::unused_async)]
    pub async fn close(&mut self) -> Result<(), GrpcError> {
        self.closed = true;
        Ok(())
    }
}

impl<T> Default for RequestSink<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::grpc::Code;
    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_request_creation() {
        init_test("test_request_creation");
        let request = Request::new("hello");
        let value = request.get_ref();
        crate::assert_with_log!(value == &"hello", "get_ref", &"hello", value);
        let empty = request.metadata().is_empty();
        crate::assert_with_log!(empty, "metadata empty", true, empty);
        crate::test_complete!("test_request_creation");
    }

    #[test]
    fn test_request_with_metadata() {
        init_test("test_request_with_metadata");
        let mut metadata = Metadata::new();
        metadata.insert("x-custom", "value");

        let request = Request::with_metadata("hello", metadata);
        let has = request.metadata().get("x-custom").is_some();
        crate::assert_with_log!(has, "custom metadata", true, has);
        crate::test_complete!("test_request_with_metadata");
    }

    #[test]
    fn test_request_into_inner() {
        init_test("test_request_into_inner");
        let request = Request::new(42);
        let value = request.into_inner();
        crate::assert_with_log!(value == 42, "into_inner", 42, value);
        crate::test_complete!("test_request_into_inner");
    }

    #[test]
    fn test_request_map() {
        init_test("test_request_map");
        let request = Request::new(42);
        let mapped = request.map(|n| n * 2);
        let value = mapped.into_inner();
        crate::assert_with_log!(value == 84, "mapped", 84, value);
        crate::test_complete!("test_request_map");
    }

    #[test]
    fn test_response_creation() {
        init_test("test_response_creation");
        let response = Response::new("world");
        let value = response.get_ref();
        crate::assert_with_log!(value == &"world", "get_ref", &"world", value);
        crate::test_complete!("test_response_creation");
    }

    #[test]
    fn test_metadata_operations() {
        init_test("test_metadata_operations");
        let mut metadata = Metadata::new();
        let empty = metadata.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);

        metadata.insert("key1", "value1");
        metadata.insert("key2", "value2");

        let len = metadata.len();
        crate::assert_with_log!(len == 2, "len", 2, len);
        let empty = metadata.is_empty();
        crate::assert_with_log!(!empty, "not empty", false, empty);

        match metadata.get("key1") {
            Some(MetadataValue::Ascii(v)) => {
                crate::assert_with_log!(v == "value1", "value1", "value1", v);
            }
            _ => panic!("expected ascii value"),
        }
        crate::test_complete!("test_metadata_operations");
    }

    #[test]
    fn test_metadata_binary() {
        init_test("test_metadata_binary");
        let mut metadata = Metadata::new();
        metadata.insert_bin("data-bin", Bytes::from_static(b"\x00\x01\x02"));

        match metadata.get("data-bin") {
            Some(MetadataValue::Binary(v)) => {
                crate::assert_with_log!(v.as_ref() == [0, 1, 2], "binary", &[0, 1, 2], v.as_ref());
            }
            _ => panic!("expected binary value"),
        }
        crate::test_complete!("test_metadata_binary");
    }

    #[test]
    fn test_metadata_binary_key_suffix_is_normalized() {
        init_test("test_metadata_binary_key_suffix_is_normalized");
        let mut metadata = Metadata::new();
        metadata.insert_bin("raw-key", Bytes::from_static(b"\x01\x02"));

        let has = metadata.get("raw-key-bin").is_some();
        crate::assert_with_log!(has, "normalized -bin key present", true, has);

        let missing_raw = metadata.get("raw-key").is_none();
        crate::assert_with_log!(missing_raw, "raw key absent", true, missing_raw);
        crate::test_complete!("test_metadata_binary_key_suffix_is_normalized");
    }

    #[test]
    fn test_metadata_get_prefers_latest_value() {
        init_test("test_metadata_get_prefers_latest_value");
        let mut metadata = Metadata::new();
        metadata.insert("authorization", "old-token");
        metadata.insert("authorization", "new-token");

        match metadata.get("authorization") {
            Some(MetadataValue::Ascii(v)) => {
                crate::assert_with_log!(v == "new-token", "latest value", "new-token", v);
            }
            _ => panic!("expected ascii value"),
        }
        crate::test_complete!("test_metadata_get_prefers_latest_value");
    }

    #[test]
    fn test_metadata_insert_or_replace_removes_older_values() {
        init_test("test_metadata_insert_or_replace_removes_older_values");
        let mut metadata = Metadata::new();
        metadata.insert("grpc-timeout", "bogus");
        metadata.insert_or_replace("grpc-timeout", "5S");

        match metadata.get("grpc-timeout") {
            Some(MetadataValue::Ascii(v)) => {
                crate::assert_with_log!(v == "5S", "replaced value", "5S", v);
            }
            _ => panic!("expected ascii value"),
        }

        let timeout_count = metadata
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("grpc-timeout"))
            .count();
        crate::assert_with_log!(timeout_count == 1, "single timeout entry", 1, timeout_count);
        crate::test_complete!("test_metadata_insert_or_replace_removes_older_values");
    }

    #[test]
    fn test_metadata_reserve_preserves_behavior() {
        init_test("test_metadata_reserve_preserves_behavior");
        let mut metadata = Metadata::new();
        metadata.reserve(8);
        metadata.insert("x-key", "value");
        let has = metadata.get("x-key").is_some();
        crate::assert_with_log!(has, "reserved metadata insert", true, has);
        crate::test_complete!("test_metadata_reserve_preserves_behavior");
    }

    #[test]
    fn test_metadata_insert_normalizes_ascii_key_case() {
        init_test("test_metadata_insert_normalizes_ascii_key_case");
        let mut metadata = Metadata::new();
        metadata.insert("X-Request-ID", "abc-123");

        let stored_key = metadata
            .iter()
            .next()
            .map(|(key, _)| key)
            .expect("metadata entry");
        crate::assert_with_log!(
            stored_key == "x-request-id",
            "ascii metadata key normalized to lowercase",
            "x-request-id",
            stored_key
        );

        let has_upper = metadata.get("X-REQUEST-ID").is_some();
        crate::assert_with_log!(
            has_upper,
            "uppercase lookup remains supported after normalization",
            true,
            has_upper
        );
        crate::test_complete!("test_metadata_insert_normalizes_ascii_key_case");
    }

    #[test]
    fn test_metadata_insert_bin_normalizes_key_case_and_suffix() {
        init_test("test_metadata_insert_bin_normalizes_key_case_and_suffix");
        let mut metadata = Metadata::new();
        metadata.insert_bin("Trace-Context-BIN", Bytes::from_static(b"\x01\x02"));

        let stored_key = metadata
            .iter()
            .next()
            .map(|(key, _)| key)
            .expect("metadata entry");
        crate::assert_with_log!(
            stored_key == "trace-context-bin",
            "binary metadata key normalized to lowercase with single -bin suffix",
            "trace-context-bin",
            stored_key
        );

        match metadata.get("TRACE-CONTEXT-BIN") {
            Some(MetadataValue::Binary(v)) => {
                crate::assert_with_log!(
                    v.as_ref() == [1, 2],
                    "binary lookup after normalization",
                    &[1, 2],
                    v.as_ref()
                );
            }
            _ => panic!("expected binary value"),
        }
        crate::test_complete!("test_metadata_insert_bin_normalizes_key_case_and_suffix");
    }

    #[test]
    fn test_metadata_insert_rejects_invalid_key() {
        init_test("test_metadata_insert_rejects_invalid_key");
        let mut metadata = Metadata::new();

        let inserted = metadata.insert("x-good\r\nx-evil", "value");
        crate::assert_with_log!(!inserted, "invalid metadata key rejected", false, inserted);
        crate::assert_with_log!(
            metadata.is_empty(),
            "rejected metadata key not stored",
            true,
            metadata.is_empty()
        );
        crate::test_complete!("test_metadata_insert_rejects_invalid_key");
    }

    #[test]
    fn test_metadata_insert_rejects_pseudo_header_key() {
        init_test("test_metadata_insert_rejects_pseudo_header_key");
        let mut metadata = Metadata::new();

        let inserted = metadata.insert(":path", "/evil");
        crate::assert_with_log!(
            !inserted,
            "pseudo-header metadata key rejected",
            false,
            inserted
        );
        crate::assert_with_log!(
            metadata.is_empty(),
            "rejected pseudo-header key not stored",
            true,
            metadata.is_empty()
        );
        crate::test_complete!("test_metadata_insert_rejects_pseudo_header_key");
    }

    #[test]
    fn test_metadata_insert_bin_rejects_pseudo_header_key() {
        init_test("test_metadata_insert_bin_rejects_pseudo_header_key");
        let mut metadata = Metadata::new();

        let inserted = metadata.insert_bin(":path", Bytes::from_static(b"/evil"));
        crate::assert_with_log!(
            !inserted,
            "binary pseudo-header metadata key rejected",
            false,
            inserted
        );
        crate::assert_with_log!(
            metadata.is_empty(),
            "rejected binary pseudo-header key not stored",
            true,
            metadata.is_empty()
        );
        crate::test_complete!("test_metadata_insert_bin_rejects_pseudo_header_key");
    }

    #[test]
    fn test_metadata_insert_strips_ascii_crlf() {
        init_test("test_metadata_insert_strips_ascii_crlf");
        let mut metadata = Metadata::new();

        let inserted = metadata.insert("x-request-id", "line1\r\nline2");
        crate::assert_with_log!(inserted, "valid key inserted", true, inserted);

        match metadata.get("x-request-id") {
            Some(MetadataValue::Ascii(value)) => {
                crate::assert_with_log!(
                    value == "line1line2",
                    "ascii metadata CRLF sanitized",
                    "line1line2",
                    value
                );
            }
            _ => panic!("expected sanitized ascii metadata value"),
        }
        crate::test_complete!("test_metadata_insert_strips_ascii_crlf");
    }

    // =========================================================================
    // Wave 48 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn metadata_debug_clone_default() {
        let def = Metadata::default();
        let dbg = format!("{def:?}");
        assert!(dbg.contains("Metadata"), "{dbg}");
        assert!(def.is_empty());

        let mut md = Metadata::new();
        md.insert("key", "val");
        let cloned = md.clone();
        assert_eq!(cloned.len(), 1);
        match cloned.get("key") {
            Some(MetadataValue::Ascii(v)) => assert_eq!(v, "val"),
            _ => panic!("expected ascii value"),
        }
    }

    #[test]
    fn metadata_value_debug_clone() {
        let ascii = MetadataValue::Ascii("hello".into());
        let dbg = format!("{ascii:?}");
        assert!(dbg.contains("Ascii"), "{dbg}");
        let cloned = ascii;
        assert!(matches!(cloned, MetadataValue::Ascii(s) if s == "hello"));

        let binary = MetadataValue::Binary(Bytes::from_static(b"\x00\x01"));
        let dbg2 = format!("{binary:?}");
        assert!(dbg2.contains("Binary"), "{dbg2}");
        let cloned2 = binary;
        assert!(matches!(cloned2, MetadataValue::Binary(_)));
    }

    #[test]
    fn streaming_request_open_push_poll_close() {
        init_test("streaming_request_open_push_poll_close");
        let mut stream = StreamingRequest::<u32>::open();
        stream.push(7).expect("push succeeds");
        stream.push(9).expect("push succeeds");

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(7)))
        ));
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(9)))
        ));

        stream.close();
        let mut pinned = Pin::new(&mut stream);
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
        crate::test_complete!("streaming_request_open_push_poll_close");
    }

    #[test]
    fn response_stream_push_and_close() {
        init_test("response_stream_push_and_close");
        let mut stream = ResponseStream::<u32>::open();
        stream.push(Ok(11)).expect("push succeeds");

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(11)))
        ));

        stream.close();
        let mut pinned = Pin::new(&mut stream);
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
        crate::test_complete!("response_stream_push_and_close");
    }

    #[test]
    fn streaming_request_push_rejects_when_buffer_full_and_recovers_after_drain() {
        init_test("streaming_request_push_rejects_when_buffer_full_and_recovers_after_drain");
        let mut stream = StreamingRequest::<u32>::open();
        for i in 0..MAX_STREAM_BUFFERED as u32 {
            stream.push(i).expect("push before saturation succeeds");
        }

        let err = stream
            .push(MAX_STREAM_BUFFERED as u32)
            .expect_err("push past cap must fail");
        crate::assert_with_log!(
            err.code() == Code::ResourceExhausted,
            "resource exhausted when full",
            Code::ResourceExhausted,
            err.code()
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(0)))
        ));

        stream
            .push(MAX_STREAM_BUFFERED as u32)
            .expect("push should succeed after draining one slot");
        crate::test_complete!(
            "streaming_request_push_rejects_when_buffer_full_and_recovers_after_drain"
        );
    }

    #[test]
    fn response_stream_push_rejects_when_buffer_full_and_recovers_after_drain() {
        init_test("response_stream_push_rejects_when_buffer_full_and_recovers_after_drain");
        let mut stream = ResponseStream::<u32>::open();
        for i in 0..MAX_STREAM_BUFFERED as u32 {
            stream.push(Ok(i)).expect("push before saturation succeeds");
        }

        let err = stream
            .push(Ok(MAX_STREAM_BUFFERED as u32))
            .expect_err("push past cap must fail");
        crate::assert_with_log!(
            err.code() == Code::ResourceExhausted,
            "resource exhausted when full",
            Code::ResourceExhausted,
            err.code()
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(0)))
        ));

        stream
            .push(Ok(MAX_STREAM_BUFFERED as u32))
            .expect("push should succeed after draining one slot");
        crate::test_complete!(
            "response_stream_push_rejects_when_buffer_full_and_recovers_after_drain"
        );
    }

    #[test]
    fn request_sink_send_rejects_after_close() {
        init_test("request_sink_send_rejects_after_close");
        futures_lite::future::block_on(async {
            let mut sink = RequestSink::<u32>::new();
            sink.send(1).await.expect("first send must succeed");
            assert_eq!(sink.sent_count(), 1);
            sink.close().await.expect("close must succeed");

            let err = sink.send(2).await.expect_err("send after close must fail");
            assert!(matches!(err, GrpcError::Protocol(_)));
        });
        crate::test_complete!("request_sink_send_rejects_after_close");
    }

    // =========================================================================
    // gRPC Specification Conformance Tests for Server Streaming RPC Completion
    // =========================================================================

    /// GRPC-CONF-001: Server streaming completion must signal proper termination
    /// Per gRPC spec: "A streaming RPC ends with a status and optional trailing metadata"
    #[test]
    fn conformance_server_streaming_proper_termination() {
        init_test("conformance_server_streaming_proper_termination");
        let mut stream = ResponseStream::<String>::open();

        // Stream some responses
        stream
            .push(Ok("response1".to_string()))
            .expect("first response");
        stream
            .push(Ok("response2".to_string()))
            .expect("second response");
        stream
            .push(Ok("response3".to_string()))
            .expect("third response");

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        {
            let mut pinned = Pin::new(&mut stream);

            // Consume all responses
            assert!(
                matches!(
                    pinned.as_mut().poll_next(&mut cx),
                    Poll::Ready(Some(Ok(ref s))) if s == "response1"
                ),
                "first response consumed"
            );

            assert!(
                matches!(
                    pinned.as_mut().poll_next(&mut cx),
                    Poll::Ready(Some(Ok(ref s))) if s == "response2"
                ),
                "second response consumed"
            );

            assert!(
                matches!(
                    pinned.as_mut().poll_next(&mut cx),
                    Poll::Ready(Some(Ok(ref s))) if s == "response3"
                ),
                "third response consumed"
            );
        }

        // Stream termination - close() signals completion
        stream.close();
        let mut pinned = Pin::new(&mut stream); // Re-pin after close

        // Per gRPC spec: stream completion returns None to signal end
        assert!(
            matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(None)),
            "stream properly terminates with None after close()"
        );

        crate::test_complete!("conformance_server_streaming_proper_termination");
    }

    /// GRPC-CONF-002: Error during streaming should propagate status code
    /// Per gRPC spec: "Status codes indicate success or failure of gRPC calls"
    #[test]
    fn conformance_server_streaming_error_propagation() {
        init_test("conformance_server_streaming_error_propagation");
        let mut stream = ResponseStream::<u32>::open();

        // Send valid response followed by error
        stream.push(Ok(42)).expect("valid response");
        stream
            .push(Err(Status::invalid_argument("malformed request data")))
            .expect("error response");

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        {
            let mut pinned = Pin::new(&mut stream);

            // First response should be valid
            assert!(
                matches!(
                    pinned.as_mut().poll_next(&mut cx),
                    Poll::Ready(Some(Ok(42)))
                ),
                "valid response received before error"
            );

            // Error response should contain proper status
            match pinned.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Err(status))) => {
                    assert_eq!(
                        status.code(),
                        Code::InvalidArgument,
                        "error code propagated"
                    );
                    assert!(
                        status.message().contains("malformed request"),
                        "error message preserved"
                    );
                }
                other => panic!("expected error status, got {other:?}"),
            }
        }

        stream.close();
        let mut pinned = Pin::new(&mut stream); // Re-pin after close
        assert!(
            matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(None)),
            "stream terminates after error"
        );

        crate::test_complete!("conformance_server_streaming_error_propagation");
    }

    /// GRPC-CONF-003: Backpressure behavior must comply with gRPC flow control
    /// Per gRPC spec: "Flow control prevents fast senders from overwhelming slow receivers"
    #[test]
    fn conformance_server_streaming_backpressure() {
        init_test("conformance_server_streaming_backpressure");
        let mut stream = ResponseStream::<u64>::open();

        // Fill buffer to capacity
        for i in 0..MAX_STREAM_BUFFERED {
            stream
                .push(Ok(i as u64))
                .expect("responses should fill buffer");
        }

        // Next push should fail with ResourceExhausted per gRPC spec
        let overflow_result = stream.push(Ok(9999));
        assert!(
            overflow_result.is_err(),
            "buffer overflow should be rejected"
        );

        match overflow_result.unwrap_err() {
            status if status.code() == Code::ResourceExhausted => {
                assert!(
                    status.message().contains("buffer full"),
                    "backpressure error message should indicate buffer state"
                );
            }
            other_status => panic!("expected ResourceExhausted, got {other_status:?}"),
        }

        // Drain one message to free buffer space
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);
        assert!(
            matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(Some(Ok(0)))),
            "draining first message should succeed"
        );

        // Now backpressure should be relieved
        stream
            .push(Ok(9999))
            .expect("push after drain should succeed due to available buffer space");

        crate::test_complete!("conformance_server_streaming_backpressure");
    }

    /// GRPC-CONF-004: Stream must not accept new messages after close()
    /// Per gRPC spec: "Once a stream is closed, no further messages can be sent"
    #[test]
    fn conformance_server_streaming_post_close_rejection() {
        init_test("conformance_server_streaming_post_close_rejection");
        let mut stream = ResponseStream::<&'static str>::open();

        stream
            .push(Ok("valid_message"))
            .expect("pre-close message succeeds");
        stream.close();

        // Attempt to send after close should fail
        let post_close_result = stream.push(Ok("post_close_message"));
        assert!(
            post_close_result.is_err(),
            "post-close push should be rejected"
        );

        match post_close_result.unwrap_err() {
            status if status.code() == Code::FailedPrecondition => {
                assert!(
                    status.message().contains("closed"),
                    "error should indicate stream is closed"
                );
            }
            other => panic!("expected FailedPrecondition, got {other:?}"),
        }

        // Stream should still terminate properly
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);

        assert!(
            matches!(
                pinned.as_mut().poll_next(&mut cx),
                Poll::Ready(Some(Ok("valid_message")))
            ),
            "pre-close message should still be available"
        );

        assert!(
            matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(None)),
            "stream should terminate with None"
        );

        crate::test_complete!("conformance_server_streaming_post_close_rejection");
    }

    /// GRPC-CONF-005: Server streaming wrapper preserves inner stream semantics
    /// Per gRPC spec: "Server streaming responses are ordered"
    #[test]
    fn conformance_server_streaming_wrapper_semantics() {
        init_test("conformance_server_streaming_wrapper_semantics");
        let mut inner_stream = ResponseStream::<i32>::open();
        inner_stream.push(Ok(100)).expect("inner stream message");
        inner_stream.push(Ok(200)).expect("inner stream message");
        inner_stream.close();

        let mut server_streaming = ServerStreaming::new(inner_stream);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut server_streaming);

        // Server streaming should preserve order and completion semantics
        assert!(
            matches!(
                pinned.as_mut().poll_next(&mut cx),
                Poll::Ready(Some(Ok(100)))
            ),
            "first message preserves order"
        );

        assert!(
            matches!(
                pinned.as_mut().poll_next(&mut cx),
                Poll::Ready(Some(Ok(200)))
            ),
            "second message preserves order"
        );

        assert!(
            matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(None)),
            "completion signal preserved"
        );

        crate::test_complete!("conformance_server_streaming_wrapper_semantics");
    }

    /// GRPC-CONF-006: Empty stream completion should be valid
    /// Per gRPC spec: "A server may immediately close a stream with no messages"
    #[test]
    fn conformance_server_streaming_empty_completion() {
        init_test("conformance_server_streaming_empty_completion");
        let mut stream = ResponseStream::<String>::open();

        // Immediately close without sending any messages
        stream.close();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);

        // Empty stream should immediately return None
        assert!(
            matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(None)),
            "empty stream should complete immediately with None"
        );

        crate::test_complete!("conformance_server_streaming_empty_completion");
    }

    /// GRPC-CONF-007: Stream wakeup behavior on close should be immediate
    /// Per gRPC spec: "Stream completion should wake pending consumers"
    #[test]
    fn conformance_server_streaming_close_wakeup() {
        init_test("conformance_server_streaming_close_wakeup");
        let mut stream = ResponseStream::<bool>::open();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        {
            let mut pinned = Pin::new(&mut stream);

            // Poll on empty stream should return Pending
            assert!(
                matches!(pinned.as_mut().poll_next(&mut cx), Poll::Pending),
                "empty open stream should be pending"
            );
        }

        // Close should allow immediate completion on next poll
        stream.close();
        let mut pinned = Pin::new(&mut stream); // Re-pin after close

        assert!(
            matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(None)),
            "close should enable immediate completion on next poll"
        );

        crate::test_complete!("conformance_server_streaming_close_wakeup");
    }

    /// GRPC-CONF-008: Multiple polling attempts after completion should be idempotent
    /// Per gRPC spec: "Completed streams should consistently return completion signal"
    #[test]
    fn conformance_server_streaming_completion_idempotence() {
        init_test("conformance_server_streaming_completion_idempotence");
        let mut stream = ResponseStream::<f64>::open();
        stream
            .push(Ok(std::f64::consts::PI))
            .expect("single message");
        stream.close();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);

        // First poll gets the message
        assert!(
            matches!(
                pinned.as_mut().poll_next(&mut cx),
                Poll::Ready(Some(Ok(val))) if (val - std::f64::consts::PI).abs() < f64::EPSILON
            ),
            "message received on first poll"
        );

        // Subsequent polls should consistently return None (completion)
        for attempt in 1..=5 {
            assert!(
                matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(None)),
                "completion signal should be idempotent on attempt {attempt}"
            );
        }

        crate::test_complete!("conformance_server_streaming_completion_idempotence");
    }

    /// GRPC-CONF-009: Metadata preservation throughout streaming lifecycle
    /// Per gRPC spec: "Metadata must be preserved for request/response pairs"
    #[test]
    fn conformance_server_streaming_metadata_preservation() {
        init_test("conformance_server_streaming_metadata_preservation");

        // Create request with metadata
        let mut metadata = Metadata::new();
        metadata.insert("x-client-id", "test-client-123");
        metadata.insert("x-request-timeout", "30s");
        metadata.insert_bin("trace-context-bin", Bytes::from_static(b"\x01\x02\x03\x04"));

        let request = Request::with_metadata("stream_request", metadata.clone());

        // Verify metadata preservation in request
        assert_eq!(
            request.metadata().get("x-client-id"),
            Some(&MetadataValue::Ascii("test-client-123".to_string())),
            "ASCII metadata preserved"
        );

        assert_eq!(
            request.metadata().get("x-request-timeout"),
            Some(&MetadataValue::Ascii("30s".to_string())),
            "ASCII metadata preserved"
        );

        match request.metadata().get("trace-context-bin") {
            Some(MetadataValue::Binary(bytes)) => {
                assert_eq!(bytes.as_ref(), &[1, 2, 3, 4], "binary metadata preserved");
            }
            other => panic!("expected binary metadata, got {other:?}"),
        }

        // Create response with metadata
        let mut resp_metadata = Metadata::new();
        resp_metadata.insert("x-server-version", "1.0.0");
        let response = Response::with_metadata("stream_response", resp_metadata);

        assert_eq!(
            response.metadata().get("x-server-version"),
            Some(&MetadataValue::Ascii("1.0.0".to_string())),
            "response metadata preserved"
        );

        crate::test_complete!("conformance_server_streaming_metadata_preservation");
    }

    /// GRPC-CONF-010: Stream status propagation with detailed error information
    /// Per gRPC spec: "Status should include error code and descriptive message"
    #[test]
    fn conformance_server_streaming_detailed_status() {
        init_test("conformance_server_streaming_detailed_status");
        let mut stream = ResponseStream::<u8>::open();

        // Test various error codes as per gRPC spec
        let test_statuses = [
            Status::cancelled("client cancelled request"),
            Status::deadline_exceeded("request timeout after 30s"),
            Status::not_found("resource /api/v1/users/999 not found"),
            Status::permission_denied("insufficient privileges for admin operation"),
            Status::internal("database connection lost"),
            Status::unimplemented("feature not yet implemented"),
        ];

        for (i, status) in test_statuses.iter().enumerate() {
            stream
                .push(Ok(i as u8))
                .expect("valid response before error");
            stream.push(Err(status.clone())).expect("error status");
        }
        stream.close();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);

        // Verify each status is properly propagated
        for (i, expected_status) in test_statuses.iter().enumerate() {
            // Consume valid response
            assert!(
                matches!(
                    pinned.as_mut().poll_next(&mut cx),
                    Poll::Ready(Some(Ok(val))) if val == i as u8
                ),
                "valid response {i} received"
            );

            // Verify error status
            match pinned.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Err(actual_status))) => {
                    assert_eq!(
                        actual_status.code(),
                        expected_status.code(),
                        "error code preserved for status {i}"
                    );
                    assert_eq!(
                        actual_status.message(),
                        expected_status.message(),
                        "error message preserved for status {i}"
                    );
                }
                other => panic!("expected error status for {i}, got {other:?}"),
            }
        }

        // Stream should terminate properly after errors
        assert!(
            matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(None)),
            "stream terminates after error sequence"
        );

        crate::test_complete!("conformance_server_streaming_detailed_status");
    }

    // =============================================================================
    // GOLDEN ARTIFACT TESTS: gRPC Streaming Stable Output Verification
    // =============================================================================

    /// Universal golden assertion for this module.
    fn assert_golden(test_name: &str, actual: &str) {
        let golden_path =
            std::path::Path::new("tests/golden/grpc/streaming").join(format!("{test_name}.golden"));

        // UPDATE MODE: overwrite golden with actual output
        if std::env::var("UPDATE_GOLDENS").is_ok() {
            std::fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
            std::fs::write(&golden_path, actual).unwrap();
            eprintln!("[GOLDEN] Updated: {}", golden_path.display());
            return;
        }

        // COMPARE MODE: diff actual vs golden
        let expected = std::fs::read_to_string(&golden_path).unwrap_or_else(|_| {
            panic!(
                "Golden file missing: {}\n\
                 Run with UPDATE_GOLDENS=1 to create it\n\
                 Then review and commit: git diff tests/golden/",
                golden_path.display()
            )
        });

        if actual != expected {
            // Write actual for easy diffing
            let actual_path = golden_path.with_extension("actual");
            std::fs::write(&actual_path, actual).unwrap();
            panic!(
                "GOLDEN MISMATCH: {test_name}\n\
                 Expected file: {}\n\
                 Actual file:   {}\n\
                 To update: UPDATE_GOLDENS=1 cargo test -- {test_name}\n\
                 To diff: diff {} {}",
                golden_path.display(),
                actual_path.display(),
                golden_path.display(),
                actual_path.display(),
            );
        }
    }

    #[test]
    fn golden_metadata_debug_formatting() {
        init_test("golden_metadata_debug_formatting");

        // Test various metadata configurations to ensure stable debug output
        let mut outputs = Vec::new();

        // Empty metadata
        let empty_metadata = Metadata::new();
        outputs.push(format!("=== Empty Metadata ===\n{empty_metadata:?}\n"));

        // Single ASCII entry
        let mut single_ascii = Metadata::new();
        single_ascii.insert("content-type", "application/json");
        outputs.push(format!("=== Single ASCII Entry ===\n{single_ascii:?}\n"));

        // Multiple ASCII entries
        let mut multi_ascii = Metadata::new();
        multi_ascii.insert("authorization", "Bearer token123");
        multi_ascii.insert("x-request-id", "req-456-789");
        multi_ascii.insert("user-agent", "asupersync/1.0");
        outputs.push(format!("=== Multiple ASCII Entries ===\n{multi_ascii:?}\n"));

        // Binary entry
        let mut binary_metadata = Metadata::new();
        binary_metadata.insert_bin("trace-context", Bytes::from_static(b"\x01\x02\x03\x04"));
        outputs.push(format!("=== Binary Entry ===\n{binary_metadata:?}\n"));

        // Mixed ASCII and binary
        let mut mixed_metadata = Metadata::new();
        mixed_metadata.insert("content-type", "application/grpc");
        mixed_metadata.insert_bin("custom-data", Bytes::from_static(b"\x00\xFF\x42"));
        mixed_metadata.insert("grpc-timeout", "30s");
        outputs.push(format!(
            "=== Mixed ASCII and Binary ===\n{mixed_metadata:?}\n"
        ));

        let combined_output = outputs.join("\n");
        assert_golden("metadata_debug_formatting", &combined_output);
    }

    #[test]
    fn golden_metadata_value_debug_formatting() {
        init_test("golden_metadata_value_debug_formatting");

        let mut outputs = Vec::new();

        // ASCII values
        let ascii_simple = MetadataValue::Ascii("hello".to_string());
        outputs.push(format!("ASCII Simple: {ascii_simple:?}"));

        let ascii_complex =
            MetadataValue::Ascii("Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".to_string());
        outputs.push(format!("ASCII Complex: {ascii_complex:?}"));

        let ascii_with_special =
            MetadataValue::Ascii("value with spaces and symbols!@#$%".to_string());
        outputs.push(format!("ASCII Special Chars: {ascii_with_special:?}"));

        // Binary values
        let binary_empty = MetadataValue::Binary(Bytes::new());
        outputs.push(format!("Binary Empty: {binary_empty:?}"));

        let binary_simple = MetadataValue::Binary(Bytes::from_static(b"\x01\x02\x03"));
        outputs.push(format!("Binary Simple: {binary_simple:?}"));

        let binary_complex = MetadataValue::Binary(Bytes::from_static(b"\x00\xFF\x7F\x80\x42\x24"));
        outputs.push(format!("Binary Complex: {binary_complex:?}"));

        let combined_output = outputs.join("\n");
        assert_golden("metadata_value_debug_formatting", &combined_output);
    }

    #[test]
    fn golden_request_response_debug_formatting() {
        init_test("golden_request_response_debug_formatting");

        let mut outputs = Vec::new();

        // Simple request
        let simple_request = Request::new("hello world");
        outputs.push(format!("=== Simple Request ===\n{simple_request:?}\n"));

        // Request with metadata
        let mut metadata = Metadata::new();
        metadata.insert("authorization", "Bearer secret-token");
        metadata.insert("x-trace-id", "trace-123-456");
        let request_with_metadata = Request::with_metadata(42u32, metadata);
        outputs.push(format!(
            "=== Request with Metadata ===\n{request_with_metadata:?}\n"
        ));

        // Simple response
        let simple_response = Response::new("response data");
        outputs.push(format!("=== Simple Response ===\n{simple_response:?}\n"));

        // Response with metadata
        let mut resp_metadata = Metadata::new();
        resp_metadata.insert("content-type", "application/grpc+proto");
        resp_metadata.insert_bin("custom-bin", Bytes::from_static(b"\x01\x02"));
        let response_with_metadata =
            Response::with_metadata(vec!["item1", "item2", "item3"], resp_metadata);
        outputs.push(format!(
            "=== Response with Metadata ===\n{response_with_metadata:?}\n"
        ));

        let combined_output = outputs.join("\n");
        assert_golden("request_response_debug_formatting", &combined_output);
    }

    #[test]
    fn golden_metadata_key_normalization() {
        init_test("golden_metadata_key_normalization");

        let test_cases = vec![
            // (input_key, binary_flag, description)
            ("Content-Type", false, "ASCII uppercase"),
            ("x-REQUEST-id", false, "ASCII mixed case"),
            ("user_agent", false, "ASCII with underscore"),
            ("trace.id", false, "ASCII with dot"),
            ("CUSTOM-HEADER-123", false, "ASCII with numbers"),
            ("Trace-Context", true, "Binary without -bin suffix"),
            ("Custom-Data-BIN", true, "Binary with -BIN suffix"),
            ("trace-context-bin", true, "Binary with correct suffix"),
            ("", false, "Empty key"),
            ("invalid key", false, "Key with space"),
            ("invalid\rkeyyyy", false, "Key with control char"),
            (":authority", false, "Pseudo header"),
        ];

        let mut outputs = Vec::new();

        for (input_key, binary, description) in test_cases {
            let result = normalize_metadata_key(input_key, binary);
            outputs.push(format!(
                "{}: \"{}\" (binary={}) -> {:?}",
                description, input_key, binary, result
            ));
        }

        let combined_output = outputs.join("\n");
        assert_golden("metadata_key_normalization", &combined_output);
    }

    #[test]
    fn golden_metadata_value_sanitization() {
        init_test("golden_metadata_value_sanitization");

        let test_cases = vec![
            "normal-value",
            "value with spaces",
            "value\rwith\rcarriage\rreturns",
            "value\nwith\nnewlines",
            "value\r\nwith\r\nboth",
            "value\r\n\r\nwith\r\n\r\nmultiple",
            "",
            "single\r",
            "single\n",
            "symbols!@#$%^&*()",
            "unicode-αβγδε",
        ];

        let mut outputs = Vec::new();

        for input_value in test_cases {
            let sanitized = sanitize_metadata_ascii_value(input_value);
            outputs.push(format!(
                "Input:  {:?}\nOutput: {:?}\nSame:   {}\n",
                input_value,
                sanitized.as_ref(),
                std::ptr::eq(input_value, sanitized.as_ref())
            ));
        }

        let combined_output = outputs.join("\n");
        assert_golden("metadata_value_sanitization", &combined_output);
    }

    #[test]
    fn golden_streaming_request_state_snapshots() {
        init_test("golden_streaming_request_state_snapshots");

        let mut outputs = Vec::new();

        // Empty stream
        let empty_stream = StreamingRequest::<u32>::open();
        outputs.push(format!("=== Empty Stream ===\n{empty_stream:?}\n"));

        // Stream with items
        let mut populated_stream = StreamingRequest::<String>::open();
        populated_stream.push("item1".to_string()).unwrap();
        populated_stream.push("item2".to_string()).unwrap();
        outputs.push(format!(
            "=== Populated Stream (2 items) ===\n{populated_stream:?}\n"
        ));

        // Stream with mixed success/error
        let mut mixed_stream = StreamingRequest::<i32>::open();
        mixed_stream.push(42).unwrap();
        mixed_stream.push(84).unwrap();
        outputs.push(format!("=== Mixed Stream ===\n{mixed_stream:?}\n"));

        // Closed stream
        let mut closed_stream = StreamingRequest::<bool>::open();
        closed_stream.push(true).unwrap();
        closed_stream.close();
        outputs.push(format!("=== Closed Stream ===\n{closed_stream:?}\n"));

        let combined_output = outputs.join("\n");
        assert_golden("streaming_request_state_snapshots", &combined_output);
    }

    #[test]
    fn golden_response_stream_state_snapshots() {
        init_test("golden_response_stream_state_snapshots");

        let mut outputs = Vec::new();

        // Empty response stream
        let empty_stream = ResponseStream::<f64>::open();
        outputs.push(format!("=== Empty Response Stream ===\n{empty_stream:?}\n"));

        // Response stream with successful results
        let mut success_stream = ResponseStream::<String>::open();
        success_stream.push(Ok("response1".to_string())).unwrap();
        success_stream.push(Ok("response2".to_string())).unwrap();
        outputs.push(format!(
            "=== Success Response Stream ===\n{success_stream:?}\n"
        ));

        // Response stream with error
        let mut error_stream = ResponseStream::<u32>::open();
        error_stream.push(Ok(100)).unwrap();
        error_stream
            .push(Err(Status::invalid_argument("bad input")))
            .unwrap();
        outputs.push(format!("=== Error Response Stream ===\n{error_stream:?}\n"));

        // Closed response stream
        let mut closed_stream = ResponseStream::<char>::open();
        closed_stream.push(Ok('A')).unwrap();
        closed_stream.close();
        outputs.push(format!(
            "=== Closed Response Stream ===\n{closed_stream:?}\n"
        ));

        let combined_output = outputs.join("\n");
        assert_golden("response_stream_state_snapshots", &combined_output);
    }

    #[test]
    fn golden_streaming_types_debug_formatting() {
        init_test("golden_streaming_types_debug_formatting");

        let mut outputs = Vec::new();

        // Server streaming
        let server_streaming =
            ServerStreaming::<String, ResponseStream<String>>::new(ResponseStream::open());
        outputs.push(format!("=== Server Streaming ===\n{server_streaming:?}\n"));

        // Client streaming
        let client_streaming = ClientStreaming::<u32>::new();
        outputs.push(format!("=== Client Streaming ===\n{client_streaming:?}\n"));

        // Bidirectional streaming: the in-file stub was removed
        // (br-asupersync-iuoayq); the real bidirectional surface lives
        // in `crate::grpc::client`. The previous Debug-print line is
        // intentionally omitted from the snapshot.

        // Request sink
        let request_sink = RequestSink::<bool>::new();
        outputs.push(format!("=== Request Sink ===\n{request_sink:?}\n"));

        let combined_output = outputs.join("\n");
        assert_golden("streaming_types_debug_formatting", &combined_output);
    }
}
