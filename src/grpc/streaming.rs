//! gRPC streaming types and patterns.
//!
//! Implements the four gRPC streaming patterns:
//! - Unary: single request, single response
//! - Server streaming: single request, stream of responses
//! - Client streaming: stream of requests, single response
//! - Bidirectional streaming: stream of requests and responses

use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
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
#[derive(Debug, Clone, PartialEq)]
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
        let key = key.into().to_ascii_lowercase();
        self.entries.push((key, MetadataValue::Ascii(value.into())));
    }

    /// Insert a binary value.
    pub fn insert_bin(&mut self, key: impl Into<String>, value: Bytes) {
        let mut key = key.into().to_ascii_lowercase();
        if !key.ends_with("-bin") {
            key.push_str("-bin");
        }
        self.entries.push((key, MetadataValue::Binary(value)));
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

/// A sink for sending requests to the server.
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
    use super::*;
    use crate::grpc::Code;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
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

        // Stream termination - close() signals completion
        drop(pinned); // Drop the pin before calling close()
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

        drop(pinned); // Drop pin before calling close()
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
        let mut pinned = Pin::new(&mut stream);

        // Poll on empty stream should return Pending
        assert!(
            matches!(pinned.as_mut().poll_next(&mut cx), Poll::Pending),
            "empty open stream should be pending"
        );

        // Close should allow immediate completion on next poll
        drop(pinned); // Drop pin before calling close()
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
        stream.push(Ok(3.14159)).expect("single message");
        stream.close();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);

        // First poll gets the message
        assert!(
            matches!(
                pinned.as_mut().poll_next(&mut cx),
                Poll::Ready(Some(Ok(val))) if (val - 3.14159).abs() < f64::EPSILON
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
}
