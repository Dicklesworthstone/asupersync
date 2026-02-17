//! gRPC streaming types and patterns.
//!
//! Implements the four gRPC streaming patterns:
//! - Unary: single request, single response
//! - Server streaming: single request, stream of responses
//! - Client streaming: stream of requests, single response
//! - Bidirectional streaming: stream of requests and responses

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::bytes::Bytes;

use super::status::{GrpcError, Status};

/// A gRPC request with metadata.
#[derive(Debug)]
pub struct Request<T> {
    /// Request metadata (headers).
    metadata: Metadata,
    /// The request message.
    message: T,
}

impl<T> Request<T> {
    /// Create a new request with the given message.
    #[must_use]
    pub fn new(message: T) -> Self {
        Self {
            metadata: Metadata::new(),
            message,
        }
    }

    /// Create a request with metadata.
    #[must_use]
    pub fn with_metadata(message: T, metadata: Metadata) -> Self {
        Self { metadata, message }
    }

    /// Get a reference to the request metadata.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Get a mutable reference to the request metadata.
    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
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

    /// Map the message type.
    pub fn map<F, U>(self, f: F) -> Request<U>
    where
        F: FnOnce(T) -> U,
    {
        Request {
            metadata: self.metadata,
            message: f(self.message),
        }
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
#[derive(Debug, Clone)]
pub enum MetadataValue {
    /// ASCII text value.
    Ascii(String),
    /// Binary value (key must end in "-bin").
    Binary(Bytes),
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
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries
            .push((key.into(), MetadataValue::Ascii(value.into())));
    }

    /// Insert a binary value.
    pub fn insert_bin(&mut self, key: impl Into<String>, value: Bytes) {
        let mut key = key.into();
        if !key.ends_with("-bin") {
            key.push_str("-bin");
        }
        self.entries.push((key, MetadataValue::Binary(value)));
    }

    /// Get a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&MetadataValue> {
        // Return the most recently inserted value for the key.
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k == key)
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

/// A streaming request body.
#[derive(Debug)]
pub struct StreamingRequest<T> {
    /// Phantom data for the message type.
    _marker: PhantomData<T>,
}

impl<T> StreamingRequest<T> {
    /// Create a new streaming request.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<T> Default for StreamingRequest<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send> Streaming for StreamingRequest<T> {
    type Message = T;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Message, Status>>> {
        // This is a placeholder - actual implementation would poll the underlying stream
        Poll::Ready(None)
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

/// Bidirectional streaming.
#[derive(Debug)]
pub struct Bidirectional<Req, Resp> {
    /// Phantom data for request type.
    _req: PhantomData<Req>,
    /// Phantom data for response type.
    _resp: PhantomData<Resp>,
}

impl<Req, Resp> Bidirectional<Req, Resp> {
    /// Create a new bidirectional stream.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _req: PhantomData,
            _resp: PhantomData,
        }
    }
}

impl<Req, Resp> Default for Bidirectional<Req, Resp> {
    fn default() -> Self {
        Self::new()
    }
}

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

/// A stream of responses from the server.
pub struct ResponseStream<T> {
    /// Inner stream state.
    _marker: PhantomData<T>,
}

impl<T> ResponseStream<T> {
    /// Create a new response stream.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<T> Default for ResponseStream<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send> Streaming for ResponseStream<T> {
    type Message = T;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Message, Status>>> {
        Poll::Ready(None)
    }
}

/// A sink for sending requests to the server.
#[derive(Debug)]
pub struct RequestSink<T> {
    /// Phantom data for the message type.
    _marker: PhantomData<T>,
}

impl<T> RequestSink<T> {
    /// Create a new request sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    /// Send a message.
    #[allow(clippy::unused_async)]
    pub async fn send(&mut self, _item: T) -> Result<(), GrpcError> {
        // Placeholder implementation
        Ok(())
    }

    /// Close the sink and wait for the response.
    #[allow(clippy::unused_async)]
    pub async fn close(self) -> Result<(), GrpcError> {
        // Placeholder implementation
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
    use super::*;

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
    fn test_metadata_reserve_preserves_behavior() {
        init_test("test_metadata_reserve_preserves_behavior");
        let mut metadata = Metadata::new();
        metadata.reserve(8);
        metadata.insert("x-key", "value");
        let has = metadata.get("x-key").is_some();
        crate::assert_with_log!(has, "reserved metadata insert", true, has);
        crate::test_complete!("test_metadata_reserve_preserves_behavior");
    }
}
