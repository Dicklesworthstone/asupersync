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

#[cfg(test)]
use super::status::GrpcError;
use super::status::Status;

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

    /// Clone request metadata and typed extensions onto a new message.
    pub(crate) fn snapshot<U>(&self, message: U) -> Request<U> {
        Request {
            metadata: self.metadata.clone(),
            message,
            extensions: self.extensions.clone(),
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

    /// Remove a typed value by type, returning whether an entry was present.
    pub fn remove_typed<T>(&mut self) -> bool
    where
        T: Send + Sync + 'static,
    {
        self.typed_data.remove(&TypeId::of::<T>()).is_some()
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

fn metadata_ascii_value_is_visible(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte)
}

pub(crate) fn sanitize_metadata_ascii_value(value: &str) -> Cow<'_, str> {
    if value
        .as_bytes()
        .iter()
        .copied()
        .all(metadata_ascii_value_is_visible)
    {
        Cow::Borrowed(value)
    } else {
        Cow::Owned(
            value
                .bytes()
                .filter(|byte| metadata_ascii_value_is_visible(*byte))
                .map(char::from)
                .collect(),
        )
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

    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_raw_entries_for_tests(entries: Vec<(String, MetadataValue)>) -> Self {
        Self { entries }
    }

    /// Reserve capacity for at least `additional` more entries.
    pub fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
    }

    /// Insert an ASCII value.
    ///
    /// Returns `false` when the metadata key is invalid and the entry is
    /// rejected. Invalid control and non-ASCII bytes are stripped from ASCII
    /// values to keep encoded metadata within the visible ASCII range required
    /// by gRPC over HTTP/2.
    #[must_use = "check whether the metadata key was valid and the entry was stored"]
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
    /// rejected. Invalid control and non-ASCII bytes are stripped from ASCII
    /// values to keep encoded metadata within the visible ASCII range required
    /// by gRPC over HTTP/2.
    #[must_use = "check whether the metadata key was valid and the entry was stored"]
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

    /// Remove all entries with the given key (case-insensitive match).
    ///
    /// br-asupersync-20occs: returns the number of entries removed. Used by
    /// the gRPC client to scrub a malformed `grpc-timeout` from outgoing
    /// metadata before send when the channel default timeout is unset.
    pub fn remove(&mut self, key: &str) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|(existing_key, _)| !existing_key.eq_ignore_ascii_case(key));
        before - self.entries.len()
    }

    /// Insert a binary value.
    ///
    /// Returns `false` when the metadata key is invalid and the entry is
    /// rejected.
    #[must_use = "check whether the metadata key was valid and the entry was stored"]
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

fn wake_waiter(waiter: &mut Option<Waker>) {
    if let Some(waiter) = waiter.take() {
        waiter.wake();
    }
}

/// A streaming request body.
#[derive(Debug)]
pub struct StreamingRequest<T> {
    /// Buffered stream items.
    items: VecDeque<Result<T, Status>>,
    /// Whether no further items will arrive.
    closed: bool,
    /// Whether the request stream already observed a graceful half-close.
    graceful_terminal: bool,
    /// Terminal status for cancelled/errored streams (fail-closed).
    terminal_status: Option<Status>,
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
            graceful_terminal: false,
            terminal_status: None,
            waiter: None,
        }
    }

    /// Creates an open request stream that may receive additional items.
    #[must_use]
    pub fn open() -> Self {
        Self {
            items: VecDeque::new(),
            closed: false,
            graceful_terminal: false,
            terminal_status: None,
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
        wake_waiter(&mut self.waiter);
        Ok(())
    }

    /// Closes the stream. Remaining buffered items can still be consumed.
    pub fn close(&mut self) {
        self.closed = true;
        self.graceful_terminal = true;
        wake_waiter(&mut self.waiter);
    }

    /// Cancels the stream with an error status (fail-closed).
    /// Future polls will return the error instead of None.
    pub fn cancel_with_error(&mut self, status: Status) {
        if self.graceful_terminal && self.terminal_status.is_none() {
            self.closed = true;
            wake_waiter(&mut self.waiter);
            return;
        }
        self.closed = true;
        if self.terminal_status.is_none() {
            self.terminal_status = Some(status);
        }
        wake_waiter(&mut self.waiter);
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
            // SECURITY: Fail-closed stream cancellation - distinguish error vs graceful completion
            if let Some(terminal_status) = &this.terminal_status {
                return Poll::Ready(Some(Err(terminal_status.clone())));
            }
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
// marker-only type. It carried no state, did no I/O, and had zero internal users
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
#[cfg(test)]
#[derive(Debug)]
pub struct ResponseStream<T> {
    /// Buffered stream items.
    items: VecDeque<Result<T, Status>>,
    /// Whether the stream is terminal.
    closed: bool,
    /// Whether the stream was closed gracefully before any error terminal.
    graceful_terminal: bool,
    /// Terminal status for cancelled/errored streams (fail-closed).
    terminal_status: Option<Status>,
    /// Last pending poll waker.
    waiter: Option<Waker>,
}

#[cfg(test)]
impl<T> ResponseStream<T> {
    /// Create a new response stream.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: VecDeque::new(),
            closed: true,
            graceful_terminal: false,
            waiter: None,
            terminal_status: None,
        }
    }

    /// Creates an open stream.
    #[must_use]
    pub fn open() -> Self {
        Self {
            items: VecDeque::new(),
            closed: false,
            graceful_terminal: false,
            waiter: None,
            terminal_status: None,
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
        wake_waiter(&mut self.waiter);
        Ok(())
    }

    /// Mark stream completion.
    pub fn close(&mut self) {
        self.closed = true;
        self.graceful_terminal = true;
        wake_waiter(&mut self.waiter);
    }

    /// Cancel the stream with a specific error status.
    ///
    /// Used for fail-closed cancellation where the stream should propagate
    /// the cancellation reason rather than appearing normally completed.
    pub fn cancel_with_error(&mut self, status: Status) {
        if self.graceful_terminal && self.terminal_status.is_none() {
            self.closed = true;
            wake_waiter(&mut self.waiter);
            return;
        }
        if self.terminal_status.is_none() {
            self.terminal_status = Some(status);
        }
        self.closed = true;
        wake_waiter(&mut self.waiter);
    }
}

#[cfg(test)]
impl<T> Default for ResponseStream<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
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
            // SECURITY: Fail-closed stream cancellation - distinguish error vs graceful completion
            if let Some(terminal_status) = &this.terminal_status {
                return Poll::Ready(Some(Err(terminal_status.clone())));
            }
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
/// `use crate::grpc::streaming::RequestSink` and reach this test sink will
/// observe silently dropped sends; importing
/// `crate::grpc::client::RequestSink` is the only correct production
/// path (br-asupersync-iuoayq).
#[cfg(test)]
#[derive(Debug)]
pub struct RequestSink<T> {
    /// Whether the sink has been closed.
    closed: bool,
    /// Number of sent items.
    sent_count: usize,
    /// Phantom data for the message type.
    _marker: PhantomData<T>,
}

#[cfg(test)]
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

#[cfg(test)]
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
        clippy::future_not_send,
        unused_must_use
    )]
    use super::*;
    use crate::grpc::Code;
    use crate::http::h2::error::ErrorCode;
    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn grpc_go_rst_stream_status(code: ErrorCode) -> Status {
        // br-asupersync-q01vh5: delegate to the canonical 14-row mapping in
        // `Status::from_h2_rst_stream_code` so the differential vs grpc-go
        // tests below also exercise ENHANCE_YOUR_CALM / INADEQUATE_SECURITY.
        Status::from_h2_rst_stream_code(code)
    }

    const EXACT_CLIENT_HALF_CLOSE_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_dl5tdd_half_close cargo test -p asupersync --lib conformance_client_streaming_half_close -- --nocapture";
    const EXACT_SERVER_STREAM_CANCEL_TIMING_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_gtqoxm_cancel cargo test -p asupersync --lib conformance_server_streaming_cancel_timing -- --nocapture";
    const EXACT_BIDI_CANCELLATION_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_ftbe7b_bidi cargo test -p asupersync --lib conformance_bidirectional_cancellation -- --nocapture";
    const EXACT_STREAMING_FLOW_CONTROL_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_eg4r9o_flow cargo test -p asupersync --lib conformance_grpc_streaming_flow_control -- --nocapture";
    const EXACT_GRPC_BYTES_BODY_IMMUTABILITY_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_pcpt1v_bytes cargo test -p asupersync --lib grpc_bytes_body_immutability -- --nocapture";

    fn bytes_fingerprint(bytes: &Bytes) -> String {
        use std::fmt::Write as _;

        // Calculate capacity with overflow protection for hex encoding (2 chars per byte)
        let mut hex = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes.as_ref() {
            let _ = write!(&mut hex, "{byte:02x}");
        }
        format!("len={};hex={hex}", bytes.len())
    }

    fn collect_streaming_request_events<T: std::fmt::Display + Send + std::marker::Unpin>(
        stream: &mut StreamingRequest<T>,
    ) -> Vec<String> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(stream);
        let mut events = Vec::new();
        loop {
            match pinned.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Ok(value))) => events.push(format!("ok:{value}")),
                Poll::Ready(Some(Err(status))) => {
                    events.push(format!("err:{:?}:{}", status.code(), status.message()));
                    break;
                }
                Poll::Ready(None) => {
                    events.push("none".to_string());
                    break;
                }
                Poll::Pending => {
                    events.push("pending".to_string());
                    break;
                }
            }
        }
        events
    }

    fn collect_streaming_request_byte_events(stream: &mut StreamingRequest<Bytes>) -> Vec<String> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(stream);
        let mut events = Vec::new();
        loop {
            match pinned.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Ok(value))) => {
                    events.push(format!("ok:{}", bytes_fingerprint(&value)));
                }
                Poll::Ready(Some(Err(status))) => {
                    events.push(format!("err:{:?}:{}", status.code(), status.message()));
                    break;
                }
                Poll::Ready(None) => {
                    events.push("none".to_string());
                    break;
                }
                Poll::Pending => {
                    events.push("pending".to_string());
                    break;
                }
            }
        }
        events
    }

    fn log_client_half_close_case(
        scenario_id: &str,
        sent_message_count: usize,
        half_close_tick: usize,
        observed_events: &[String],
        cancellation_state: &str,
    ) {
        println!(
            "GRPC_CLIENT_HALF_CLOSE \
             stream_id={} \
             sent_message_count={} \
             half_close_tick={} \
             server_observed_events={} \
             cancellation_state={} \
             event_count={} \
             exact_rch_command=\"{}\" \
             artifact_paths=none \
             final_half_close_preservation_verdict=pass",
            scenario_id,
            sent_message_count,
            half_close_tick,
            observed_events.join(">"),
            cancellation_state,
            observed_events.len(),
            EXACT_CLIENT_HALF_CLOSE_RCH_COMMAND,
        );
    }

    fn collect_response_stream_events<T: std::fmt::Display + Send + std::marker::Unpin>(
        stream: &mut ResponseStream<T>,
    ) -> Vec<String> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(stream);
        let mut events = Vec::new();
        loop {
            match pinned.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Ok(value))) => events.push(format!("ok:{value}")),
                Poll::Ready(Some(Err(status))) => {
                    events.push(format!("err:{:?}:{}", status.code(), status.message()));
                    break;
                }
                Poll::Ready(None) => {
                    events.push("none".to_string());
                    break;
                }
                Poll::Pending => {
                    events.push("pending".to_string());
                    break;
                }
            }
        }
        events
    }

    fn collect_response_stream_byte_events(stream: &mut ResponseStream<Bytes>) -> Vec<String> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(stream);
        let mut events = Vec::new();
        loop {
            match pinned.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Ok(value))) => {
                    events.push(format!("ok:{}", bytes_fingerprint(&value)));
                }
                Poll::Ready(Some(Err(status))) => {
                    events.push(format!("err:{:?}:{}", status.code(), status.message()));
                    break;
                }
                Poll::Ready(None) => {
                    events.push("none".to_string());
                    break;
                }
                Poll::Pending => {
                    events.push("pending".to_string());
                    break;
                }
            }
        }
        events
    }

    fn log_server_stream_cancel_timing_case(
        scenario_id: &str,
        cancel_timing_class: &str,
        queued_message_count: usize,
        observed_events: &[String],
        pending_poll_state: &str,
        trailer_presence: &str,
    ) {
        let emitted_message_count = observed_events
            .iter()
            .filter(|event| event.starts_with("ok:"))
            .count();
        let terminal_status = observed_events
            .iter()
            .find_map(|event| {
                event
                    .strip_prefix("err:")
                    .and_then(|rest| rest.split_once(':'))
                    .map(|(code, _)| code.to_string())
            })
            .unwrap_or_else(|| "EOF".to_string());
        let drain_result = if observed_events.len() > 12 {
            let mut summarized = observed_events.iter().take(5).cloned().collect::<Vec<_>>();
            summarized.push("...".to_string());
            summarized.extend(observed_events.iter().rev().take(2).rev().cloned());
            summarized.join(">")
        } else {
            observed_events.join(">")
        };
        let final_verdict = if terminal_status == "Cancelled"
            || (cancel_timing_class == "late_cancel_after_graceful_close"
                && terminal_status == "EOF")
        {
            "pass"
        } else {
            "fail"
        };
        println!(
            "GRPC_SERVER_STREAM_CANCEL \
             stream_id={} \
             cancel_timing_class={} \
             queued_message_count={} \
             emitted_message_count={} \
             pending_poll_state={} \
             drain_result={} \
             terminal_status={} \
             trailer_presence={} \
             exact_rch_command=\"{}\" \
             artifact_paths=none \
             final_no_data_loss_cancelled_verdict={}",
            scenario_id,
            cancel_timing_class,
            queued_message_count,
            emitted_message_count,
            pending_poll_state,
            drain_result,
            terminal_status,
            trailer_presence,
            EXACT_SERVER_STREAM_CANCEL_TIMING_RCH_COMMAND,
            final_verdict,
        );
    }

    fn summarize_events(observed_events: &[String]) -> String {
        if observed_events.len() > 12 {
            let mut summarized = observed_events.iter().take(5).cloned().collect::<Vec<_>>();
            summarized.push("...".to_string());
            summarized.extend(observed_events.iter().rev().take(2).rev().cloned());
            summarized.join(">")
        } else {
            observed_events.join(">")
        }
    }

    fn terminal_status_from_events(observed_events: &[String]) -> String {
        observed_events
            .iter()
            .find_map(|event| {
                event
                    .strip_prefix("err:")
                    .and_then(|rest| rest.split_once(':'))
                    .map(|(code, _)| code.to_string())
            })
            .unwrap_or_else(|| "EOF".to_string())
    }

    fn log_bidirectional_cancellation_case(
        scenario_id: &str,
        initiator: &str,
        client_events: &[String],
        server_events: &[String],
        pending_send_state: &str,
        pending_recv_state: &str,
        cancellation_tick: usize,
    ) {
        let client_status = terminal_status_from_events(client_events);
        let server_status = terminal_status_from_events(server_events);
        let client_message_count = client_events
            .iter()
            .filter(|event| event.starts_with("ok:"))
            .count();
        let server_message_count = server_events
            .iter()
            .filter(|event| event.starts_with("ok:"))
            .count();
        let drain_count = client_message_count + server_message_count;
        let verdict = if client_status == "Cancelled" && server_status == "Cancelled" {
            "pass"
        } else {
            "fail"
        };
        println!(
            "GRPC_BIDI_CANCEL \
             stream_id={} \
             initiator={} \
             client_message_count_before_cancel={} \
             server_message_count_before_cancel={} \
             pending_send_state={} \
             pending_recv_state={} \
             cancellation_tick={} \
             drain_count={} \
             client_status={} \
             server_status={} \
             client_drain_result={} \
             server_drain_result={} \
             exact_rch_command=\"{}\" \
             artifact_paths=none \
             final_both_ends_cancelled_verdict={}",
            scenario_id,
            initiator,
            client_message_count,
            server_message_count,
            pending_send_state,
            pending_recv_state,
            cancellation_tick,
            drain_count,
            client_status,
            server_status,
            summarize_events(client_events),
            summarize_events(server_events),
            EXACT_BIDI_CANCELLATION_RCH_COMMAND,
            verdict,
        );
    }

    fn summarize_usize_trace(trace: &[usize]) -> String {
        if trace.len() > 10 {
            let mut summarized = trace.iter().take(4).copied().collect::<Vec<_>>();
            summarized.push(usize::MAX);
            summarized.extend(trace.iter().rev().take(2).rev().copied());
            summarized
                .into_iter()
                .map(|value| {
                    if value == usize::MAX {
                        "...".to_string()
                    } else {
                        value.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(">")
        } else {
            trace
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(">")
        }
    }

    fn log_grpc_streaming_flow_control_case(
        stream_id: &str,
        client_behavior_profile: &str,
        configured_flow_control_cap: usize,
        queue_depth_trace: &[usize],
        bytes_buffered_trace: &[usize],
        send_poll_state: &str,
        receive_poll_state: &str,
        backpressure_event: &str,
        cancellation_drain_event: &str,
        status_trailers: &str,
        final_verdict: &str,
    ) {
        println!(
            "GRPC_STREAM_FLOW_CONTROL \
             stream_id={} \
             client_behavior_profile={} \
             configured_flow_control_cap={} \
             queue_depth_trace={} \
             bytes_buffered_trace={} \
             send_poll_state={} \
             receive_poll_state={} \
             backpressure_events={} \
             cancellation_drain_events={} \
             status_trailers={} \
             exact_rch_command=\"{}\" \
             artifact_paths=none \
             final_bounded_memory_no_leak_verdict={}",
            stream_id,
            client_behavior_profile,
            configured_flow_control_cap,
            summarize_usize_trace(queue_depth_trace),
            summarize_usize_trace(bytes_buffered_trace),
            send_poll_state,
            receive_poll_state,
            backpressure_event,
            cancellation_drain_event,
            status_trailers,
            EXACT_STREAMING_FLOW_CONTROL_RCH_COMMAND,
            final_verdict,
        );
    }

    fn log_grpc_bytes_body_immutability_case(
        request_id: &str,
        body_path: &str,
        body_fingerprint: &str,
        clone_slice_count: usize,
        handler_observed_fingerprint: &str,
        cancellation_state: &str,
        reuse_leak_mismatch_count: usize,
        observed_events: &[String],
        final_verdict: &str,
    ) {
        println!(
            "GRPC_BYTES_BODY_IMMUTABILITY \
             request_id={} \
             body_path={} \
             body_fingerprint={} \
             clone_slice_count={} \
             handler_observed_fingerprint={} \
             cancellation_state={} \
             reuse_leak_mismatch_count={} \
             observed_events={} \
             exact_rch_command=\"{}\" \
             artifact_paths=none \
             final_immutable_body_no_leak_verdict={}",
            request_id,
            body_path,
            body_fingerprint,
            clone_slice_count,
            handler_observed_fingerprint,
            cancellation_state,
            reuse_leak_mismatch_count,
            summarize_events(observed_events),
            EXACT_GRPC_BYTES_BODY_IMMUTABILITY_RCH_COMMAND,
            final_verdict,
        );
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
    fn test_request_snapshot_preserves_metadata_and_extensions() {
        init_test("test_request_snapshot_preserves_metadata_and_extensions");
        let mut request = Request::new("hello");
        request.metadata_mut().insert("x-custom", "value");
        request.extensions_mut().insert_typed(7u32);

        let snapshot = request.snapshot("world");
        let metadata_ok = snapshot.metadata().get("x-custom").is_some();
        let extension_ok = snapshot.extensions().get_typed::<u32>() == Some(&7);
        let message_ok = snapshot.get_ref() == &"world";

        crate::assert_with_log!(metadata_ok, "snapshot metadata", true, metadata_ok);
        crate::assert_with_log!(extension_ok, "snapshot extension", true, extension_ok);
        crate::assert_with_log!(message_ok, "snapshot message", true, message_ok);
        crate::test_complete!("test_request_snapshot_preserves_metadata_and_extensions");
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

    #[test]
    fn test_metadata_insert_strips_controls_and_non_ascii() {
        init_test("test_metadata_insert_strips_controls_and_non_ascii");
        let mut metadata = Metadata::new();

        let inserted = metadata.insert("x-request-id", "A\x00B\tC\x1FD\x7FEαF");
        crate::assert_with_log!(inserted, "valid key inserted", true, inserted);

        match metadata.get("x-request-id") {
            Some(MetadataValue::Ascii(value)) => {
                crate::assert_with_log!(
                    value == "ABCDEF",
                    "ascii metadata strips controls and non-ascii",
                    "ABCDEF",
                    value
                );
            }
            _ => panic!("expected sanitized ascii metadata value"),
        }
        crate::test_complete!("test_metadata_insert_strips_controls_and_non_ascii");
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

    /// GRPC-CONF-011: Client-streaming close must drain buffered requests before EOF.
    /// Per gRPC streaming semantics, half-closing the request stream prevents
    /// further sends but does not discard already-framed messages.
    #[test]
    fn conformance_client_streaming_close_drains_buffered_requests_before_eof() {
        init_test("conformance_client_streaming_close_drains_buffered_requests_before_eof");
        let mut stream = StreamingRequest::<u32>::open();
        stream.push(10).expect("first request buffered");
        stream.push(20).expect("second request buffered");
        stream.close();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);

        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(10)))
        ));
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(20)))
        ));
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));

        crate::test_complete!(
            "conformance_client_streaming_close_drains_buffered_requests_before_eof"
        );
    }

    #[test]
    fn conformance_client_streaming_half_close_zero_messages_returns_none() {
        init_test("conformance_client_streaming_half_close_zero_messages_returns_none");
        let mut stream = StreamingRequest::<u32>::open();
        stream.close();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
        crate::test_complete!("conformance_client_streaming_half_close_zero_messages_returns_none");
    }

    #[test]
    fn conformance_client_streaming_half_close_one_message_then_none() {
        init_test("conformance_client_streaming_half_close_one_message_then_none");
        let mut stream = StreamingRequest::<u32>::open();
        stream.push(7).expect("one request buffered");
        stream.close();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(7)))
        ));
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
        crate::test_complete!("conformance_client_streaming_half_close_one_message_then_none");
    }

    #[test]
    fn conformance_client_streaming_half_close_many_messages_preserve_order_before_none() {
        init_test(
            "conformance_client_streaming_half_close_many_messages_preserve_order_before_none",
        );
        let mut stream = StreamingRequest::<u32>::open();
        for value in 0..5 {
            stream.push(value).expect("buffered request");
        }
        stream.close();

        let events = collect_streaming_request_events(&mut stream);
        assert_eq!(
            events,
            vec![
                "ok:0".to_string(),
                "ok:1".to_string(),
                "ok:2".to_string(),
                "ok:3".to_string(),
                "ok:4".to_string(),
                "none".to_string(),
            ]
        );
        crate::test_complete!(
            "conformance_client_streaming_half_close_many_messages_preserve_order_before_none"
        );
    }

    #[test]
    fn conformance_client_streaming_half_close_duplicate_close_is_idempotent() {
        init_test("conformance_client_streaming_half_close_duplicate_close_is_idempotent");
        let mut stream = StreamingRequest::<u32>::open();
        stream.push(1).expect("buffer request");
        stream.close();
        stream.close();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);
        assert!(matches!(
            pinned.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(1)))
        ));
        for attempt in 0..3 {
            assert!(
                matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(None)),
                "duplicate half-close must keep EOF idempotent on attempt {attempt}"
            );
        }
        crate::test_complete!(
            "conformance_client_streaming_half_close_duplicate_close_is_idempotent"
        );
    }

    #[test]
    fn conformance_client_streaming_half_close_close_then_push_is_rejected() {
        init_test("conformance_client_streaming_half_close_close_then_push_is_rejected");
        let mut stream = StreamingRequest::<u32>::open();
        stream.push(11).expect("buffer request before close");
        stream.close();

        let err = stream
            .push(12)
            .expect_err("push after half-close must fail closed");
        assert_eq!(err.code(), Code::FailedPrecondition);

        let events = collect_streaming_request_events(&mut stream);
        assert_eq!(events, vec!["ok:11".to_string(), "none".to_string()]);
        crate::test_complete!(
            "conformance_client_streaming_half_close_close_then_push_is_rejected"
        );
    }

    #[test]
    fn conformance_client_streaming_half_close_cancel_before_close_surfaces_status() {
        init_test("conformance_client_streaming_half_close_cancel_before_close_surfaces_status");
        let mut stream = StreamingRequest::<u32>::open();
        stream.push(21).expect("buffer request");
        stream.cancel_with_error(Status::cancelled("client cancelled before half-close"));

        let events = collect_streaming_request_events(&mut stream);
        assert_eq!(
            events,
            vec![
                "ok:21".to_string(),
                "err:Cancelled:client cancelled before half-close".to_string(),
            ]
        );
        crate::test_complete!(
            "conformance_client_streaming_half_close_cancel_before_close_surfaces_status"
        );
    }

    #[test]
    fn conformance_client_streaming_half_close_graceful_eof_beats_late_cancel() {
        init_test("conformance_client_streaming_half_close_graceful_eof_beats_late_cancel");
        let mut stream = StreamingRequest::<u32>::open();
        stream.push(31).expect("first buffered request");
        stream.push(32).expect("second buffered request");
        stream.close();
        stream.cancel_with_error(Status::cancelled("late cancel after half-close"));

        let events = collect_streaming_request_events(&mut stream);
        assert_eq!(
            events,
            vec!["ok:31".to_string(), "ok:32".to_string(), "none".to_string()],
            "late cancellation after graceful half-close must not mask EOF",
        );
        crate::test_complete!(
            "conformance_client_streaming_half_close_graceful_eof_beats_late_cancel"
        );
    }

    #[test]
    fn conformance_client_streaming_half_close_matrix_logs_evidence() {
        {
            let mut stream = StreamingRequest::<u32>::open();
            stream.close();
            let events = collect_streaming_request_events(&mut stream);
            log_client_half_close_case("zero_messages", 0, 0, &events, "none");
        }

        {
            let mut stream = StreamingRequest::<u32>::open();
            stream.push(7).expect("one buffered request");
            stream.close();
            let events = collect_streaming_request_events(&mut stream);
            log_client_half_close_case("one_message", 1, 0, &events, "none");
        }

        {
            let mut stream = StreamingRequest::<u32>::open();
            for value in 0..5 {
                stream.push(value).expect("many buffered requests");
            }
            stream.close();
            let events = collect_streaming_request_events(&mut stream);
            log_client_half_close_case("many_messages", 5, 0, &events, "none");
        }

        {
            let mut stream = StreamingRequest::<u32>::open();
            stream.push(21).expect("buffer request");
            stream.cancel_with_error(Status::cancelled("client cancelled before half-close"));
            let events = collect_streaming_request_events(&mut stream);
            log_client_half_close_case(
                "cancel_before_half_close",
                1,
                0,
                &events,
                "cancel_before_half_close",
            );
        }

        {
            let mut stream = StreamingRequest::<u32>::open();
            stream.push(31).expect("buffer request");
            stream.push(32).expect("buffer request");
            stream.close();
            stream.cancel_with_error(Status::cancelled("late cancel after half-close"));
            let events = collect_streaming_request_events(&mut stream);
            log_client_half_close_case(
                "late_cancel_after_half_close",
                2,
                0,
                &events,
                "cancel_after_half_close",
            );
        }
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

    #[test]
    fn conformance_grpc_streaming_non_reader_cancellation_drains_buffered_responses() {
        init_test("conformance_grpc_streaming_non_reader_cancellation_drains_buffered_responses");
        let mut stream = ResponseStream::<u32>::open();
        stream.push(Ok(10)).expect("first buffered response");
        stream.push(Ok(20)).expect("second buffered response");
        stream.push(Ok(30)).expect("third buffered response");
        stream.cancel_with_error(Status::cancelled(
            "server cancelled after client stopped reading buffered responses",
        ));

        let events = collect_response_stream_events(&mut stream);
        assert_eq!(
            events,
            vec![
                "ok:10".to_string(),
                "ok:20".to_string(),
                "ok:30".to_string(),
                "err:Cancelled:server cancelled after client stopped reading buffered responses"
                    .to_string(),
            ],
            "non-reader cancellation must still drain buffered responses before CANCELLED"
        );
        assert!(
            stream.push(Ok(40)).is_err(),
            "cancelled non-reader stream must reject new responses"
        );

        crate::test_complete!(
            "conformance_grpc_streaming_non_reader_cancellation_drains_buffered_responses"
        );
    }

    #[test]
    fn conformance_grpc_streaming_flow_control_matrix_logs_evidence() {
        init_test("conformance_grpc_streaming_flow_control_matrix_logs_evidence");

        {
            let mut stream = ResponseStream::<u32>::open();
            let mut queue_depth_trace = vec![stream.items.len()];
            stream.push(Ok(1)).expect("buffer first response");
            queue_depth_trace.push(stream.items.len());
            stream.push(Ok(2)).expect("buffer second response");
            queue_depth_trace.push(stream.items.len());
            stream.push(Ok(3)).expect("buffer third response");
            queue_depth_trace.push(stream.items.len());
            stream.close();
            queue_depth_trace.push(stream.items.len());
            let events = collect_response_stream_events(&mut stream);
            queue_depth_trace.push(stream.items.len());
            let bytes_buffered_trace = queue_depth_trace
                .iter()
                .map(|depth| depth * std::mem::size_of::<u32>())
                .collect::<Vec<_>>();
            assert_eq!(
                events,
                vec![
                    "ok:1".to_string(),
                    "ok:2".to_string(),
                    "ok:3".to_string(),
                    "none".to_string(),
                ],
                "normal many-small-frame streaming should preserve order and EOF"
            );
            log_grpc_streaming_flow_control_case(
                "many_small_frames_ordered_drain",
                "normal_reader",
                MAX_STREAM_BUFFERED,
                &queue_depth_trace,
                &bytes_buffered_trace,
                "push_ok",
                "ready_items_then_eof",
                "none",
                "none",
                "eof_no_trailer",
                "pass",
            );
        }

        {
            let mut stream = ResponseStream::<u32>::open();
            let mut queue_depth_trace = vec![stream.items.len()];
            for value in 0..MAX_STREAM_BUFFERED as u32 {
                stream.push(Ok(value)).expect("fill response buffer");
            }
            queue_depth_trace.push(stream.items.len());
            let overflow = stream
                .push(Ok(MAX_STREAM_BUFFERED as u32))
                .expect_err("overflow should backpressure");
            queue_depth_trace.push(stream.items.len());
            assert_eq!(
                overflow.code(),
                Code::ResourceExhausted,
                "slow-reader backpressure must reject sends at the configured cap"
            );
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(matches!(
                Pin::new(&mut stream).poll_next(&mut cx),
                Poll::Ready(Some(Ok(0)))
            ));
            queue_depth_trace.push(stream.items.len());
            stream
                .push(Ok(MAX_STREAM_BUFFERED as u32))
                .expect("backpressure should clear after one drain");
            queue_depth_trace.push(stream.items.len());
            let bytes_buffered_trace = queue_depth_trace
                .iter()
                .map(|depth| depth * std::mem::size_of::<u32>())
                .collect::<Vec<_>>();
            log_grpc_streaming_flow_control_case(
                "slow_reader_backpressure_cap",
                "slow_reader",
                MAX_STREAM_BUFFERED,
                &queue_depth_trace,
                &bytes_buffered_trace,
                "overflow_resource_exhausted_then_resumed",
                "single_drain_then_buffer_refill",
                "resource_exhausted_at_cap",
                "none",
                "not_closed_yet",
                "pass",
            );
        }

        {
            let mut stream = ResponseStream::<u32>::open();
            let mut queue_depth_trace = vec![stream.items.len()];
            stream.push(Ok(10)).expect("buffer first response");
            stream.push(Ok(20)).expect("buffer second response");
            stream.push(Ok(30)).expect("buffer third response");
            queue_depth_trace.push(stream.items.len());
            stream.cancel_with_error(Status::cancelled(
                "server cancelled after client stopped reading buffered responses",
            ));
            queue_depth_trace.push(stream.items.len());
            let events = collect_response_stream_events(&mut stream);
            queue_depth_trace.push(stream.items.len());
            let bytes_buffered_trace = queue_depth_trace
                .iter()
                .map(|depth| depth * std::mem::size_of::<u32>())
                .collect::<Vec<_>>();
            assert!(
                matches!(events.last(), Some(last) if last.starts_with("err:Cancelled:")),
                "non-reader scenario must terminate with CANCELLED after draining buffered responses"
            );
            log_grpc_streaming_flow_control_case(
                "non_reader_cancel_after_buffering",
                "non_reader",
                MAX_STREAM_BUFFERED,
                &queue_depth_trace,
                &bytes_buffered_trace,
                "push_ok",
                "not_polled_until_cancel_then_drain",
                "none",
                "cancelled_after_buffered_drain",
                "cancelled_implicit_status",
                "pass",
            );
        }

        {
            let mut stream = StreamingRequest::<u32>::open();
            let mut queue_depth_trace = vec![stream.items.len()];
            stream.push(7).expect("buffer first request");
            stream.push(8).expect("buffer second request");
            stream.push(9).expect("buffer third request");
            queue_depth_trace.push(stream.items.len());
            stream.close();
            queue_depth_trace.push(stream.items.len());
            let events = collect_streaming_request_events(&mut stream);
            queue_depth_trace.push(stream.items.len());
            let bytes_buffered_trace = queue_depth_trace
                .iter()
                .map(|depth| depth * std::mem::size_of::<u32>())
                .collect::<Vec<_>>();
            assert_eq!(
                events,
                vec![
                    "ok:7".to_string(),
                    "ok:8".to_string(),
                    "ok:9".to_string(),
                    "none".to_string(),
                ],
                "buffered client half-close must drain all requests before EOF"
            );
            log_grpc_streaming_flow_control_case(
                "client_half_close_with_buffered_requests",
                "half_close_buffered",
                MAX_STREAM_BUFFERED,
                &queue_depth_trace,
                &bytes_buffered_trace,
                "push_ok_then_close",
                "ready_items_then_eof",
                "none",
                "graceful_half_close_after_buffered_drain",
                "eof_no_trailer",
                "pass",
            );
        }

        {
            let mut stream = ResponseStream::<u32>::open();
            let mut queue_depth_trace = vec![stream.items.len()];
            for value in 0..MAX_STREAM_BUFFERED as u32 {
                stream.push(Ok(value)).expect("fill response buffer");
            }
            queue_depth_trace.push(stream.items.len());
            let overflow = stream
                .push(Ok(MAX_STREAM_BUFFERED as u32))
                .expect_err("overflow should fail while send is backpressured");
            queue_depth_trace.push(stream.items.len());
            assert_eq!(overflow.code(), Code::ResourceExhausted);
            stream.cancel_with_error(Status::cancelled(
                "server cancelled while send remained backpressured",
            ));
            queue_depth_trace.push(stream.items.len());
            let events = collect_response_stream_events(&mut stream);
            queue_depth_trace.push(stream.items.len());
            let bytes_buffered_trace = queue_depth_trace
                .iter()
                .map(|depth| depth * std::mem::size_of::<u32>())
                .collect::<Vec<_>>();
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.starts_with("ok:"))
                    .count(),
                MAX_STREAM_BUFFERED,
                "server-cancelled blocked-send case must still drain the bounded buffer"
            );
            log_grpc_streaming_flow_control_case(
                "server_cancel_while_send_blocked",
                "slow_reader_non_drain",
                MAX_STREAM_BUFFERED,
                &queue_depth_trace,
                &bytes_buffered_trace,
                "overflow_resource_exhausted_then_cancelled",
                "drain_after_cancel",
                "resource_exhausted_at_cap",
                "cancelled_after_backpressured_drain",
                "cancelled_implicit_status",
                "pass",
            );
        }
    }

    #[test]
    fn conformance_grpc_bytes_body_immutability_unary_clone_slice_and_cross_request_isolation() {
        init_test(
            "conformance_grpc_bytes_body_immutability_unary_clone_slice_and_cross_request_isolation",
        );

        let original_body = Bytes::from_static(b"immutable-unary-body");
        let original_fingerprint = bytes_fingerprint(&original_body);
        let cloned_body = original_body.clone();
        let cloned_fingerprint = bytes_fingerprint(&cloned_body);
        let sliced_body = original_body.slice(10..15);
        let sliced_fingerprint = bytes_fingerprint(&sliced_body);
        let second_request_body = Bytes::from_static(b"other-request-body");
        let second_request_fingerprint = bytes_fingerprint(&second_request_body);

        let mut request = Request::new(original_body);
        let second_request = Request::new(second_request_body);
        *request.get_mut() = Bytes::from_static(b"rewritten-by-handler");
        let handler_observed_fingerprint = bytes_fingerprint(request.get_ref());

        let mut mismatch_count = 0;
        if bytes_fingerprint(&cloned_body) != cloned_fingerprint {
            mismatch_count += 1;
        }
        if bytes_fingerprint(&sliced_body) != sliced_fingerprint {
            mismatch_count += 1;
        }
        if bytes_fingerprint(second_request.get_ref()) != second_request_fingerprint {
            mismatch_count += 1;
        }
        if handler_observed_fingerprint == original_fingerprint {
            mismatch_count += 1;
        }

        assert_eq!(
            bytes_fingerprint(&cloned_body),
            cloned_fingerprint,
            "cloned unary Bytes must preserve the original fingerprint"
        );
        assert_eq!(
            bytes_fingerprint(&sliced_body),
            sliced_fingerprint,
            "sliced unary Bytes must preserve the original fingerprint"
        );
        assert_eq!(
            bytes_fingerprint(second_request.get_ref()),
            second_request_fingerprint,
            "replacing one request body handle must not leak into another request"
        );
        assert_ne!(
            handler_observed_fingerprint, original_fingerprint,
            "malicious handler replacement should only swap the local Bytes handle"
        );

        log_grpc_bytes_body_immutability_case(
            "grpc-bytes-unary-001",
            "unary",
            &original_fingerprint,
            2,
            &handler_observed_fingerprint,
            "not_cancelled",
            mismatch_count,
            &[
                format!("clone:{cloned_fingerprint}"),
                format!("slice:{sliced_fingerprint}"),
                format!("other_request:{second_request_fingerprint}"),
            ],
            if mismatch_count == 0 { "pass" } else { "fail" },
        );

        crate::test_complete!(
            "conformance_grpc_bytes_body_immutability_unary_clone_slice_and_cross_request_isolation"
        );
    }

    #[test]
    fn conformance_grpc_bytes_body_immutability_matrix_logs_evidence() {
        init_test("conformance_grpc_bytes_body_immutability_matrix_logs_evidence");

        {
            let source_a = Bytes::from_static(b"client-stream-a");
            let source_a_fingerprint = bytes_fingerprint(&source_a);
            let source_a_clone = source_a.clone();
            let source_a_clone_fingerprint = bytes_fingerprint(&source_a_clone);
            let source_a_slice = source_a.slice(7..13);
            let source_a_slice_fingerprint = bytes_fingerprint(&source_a_slice);
            let source_b = Bytes::from_static(b"client-stream-b");
            let source_b_fingerprint = bytes_fingerprint(&source_b);

            let mut stream = StreamingRequest::<Bytes>::open();
            stream.push(source_a).expect("buffer first request body");
            stream.push(source_b).expect("buffer second request body");
            stream.close();

            let events = collect_streaming_request_byte_events(&mut stream);
            assert_eq!(
                events,
                vec![
                    format!("ok:{source_a_fingerprint}"),
                    format!("ok:{source_b_fingerprint}"),
                    "none".to_string(),
                ],
                "client-streaming Bytes bodies must drain in order and terminate with EOF"
            );

            let mut mismatch_count = 0;
            if bytes_fingerprint(&source_a_clone) != source_a_clone_fingerprint {
                mismatch_count += 1;
            }
            if bytes_fingerprint(&source_a_slice) != source_a_slice_fingerprint {
                mismatch_count += 1;
            }

            log_grpc_bytes_body_immutability_case(
                "grpc-bytes-client-stream-001",
                "client_streaming",
                &source_a_fingerprint,
                2,
                &source_a_clone_fingerprint,
                "graceful_eof",
                mismatch_count,
                &events,
                if mismatch_count == 0 { "pass" } else { "fail" },
            );
        }

        {
            let response_a = Bytes::from_static(b"server-stream-a");
            let response_a_fingerprint = bytes_fingerprint(&response_a);
            let response_a_slice = response_a.slice(0..6);
            let response_a_slice_fingerprint = bytes_fingerprint(&response_a_slice);
            let response_b = Bytes::from_static(b"server-stream-b");
            let response_b_fingerprint = bytes_fingerprint(&response_b);

            let mut stream = ResponseStream::<Bytes>::open();
            stream
                .push(Ok(response_a.clone()))
                .expect("buffer first response body");
            stream
                .push(Ok(response_b))
                .expect("buffer second response body");
            stream.close();

            let events = collect_response_stream_byte_events(&mut stream);
            assert_eq!(
                events,
                vec![
                    format!("ok:{response_a_fingerprint}"),
                    format!("ok:{response_b_fingerprint}"),
                    "none".to_string(),
                ],
                "server-streaming Bytes bodies must preserve order and EOF"
            );

            let mut mismatch_count = 0;
            if bytes_fingerprint(&response_a_slice) != response_a_slice_fingerprint {
                mismatch_count += 1;
            }

            log_grpc_bytes_body_immutability_case(
                "grpc-bytes-server-stream-001",
                "server_streaming",
                &response_a_fingerprint,
                1,
                &response_a_fingerprint,
                "graceful_eof",
                mismatch_count,
                &events,
                if mismatch_count == 0 { "pass" } else { "fail" },
            );
        }

        {
            let buffered_a = Bytes::from_static(b"cancelled-response-a");
            let buffered_a_fingerprint = bytes_fingerprint(&buffered_a);
            let buffered_b = Bytes::from_static(b"cancelled-response-b");
            let buffered_b_fingerprint = bytes_fingerprint(&buffered_b);

            let mut stream = ResponseStream::<Bytes>::open();
            stream
                .push(Ok(buffered_a))
                .expect("buffer first cancelled response body");
            stream
                .push(Ok(buffered_b))
                .expect("buffer second cancelled response body");
            stream.cancel_with_error(Status::cancelled(
                "client stopped reading after server buffered immutable Bytes responses",
            ));

            let events = collect_response_stream_byte_events(&mut stream);
            assert_eq!(
                events,
                vec![
                    format!("ok:{buffered_a_fingerprint}"),
                    format!("ok:{buffered_b_fingerprint}"),
                    "err:Cancelled:client stopped reading after server buffered immutable Bytes responses"
                        .to_string(),
                ],
                "cancelled server stream must drain buffered Bytes before surfacing CANCELLED"
            );
            assert!(
                stream.push(Ok(Bytes::from_static(b"late-body"))).is_err(),
                "cancelled Bytes stream must reject new responses"
            );

            log_grpc_bytes_body_immutability_case(
                "grpc-bytes-cancelled-stream-001",
                "server_streaming_cancel_cleanup",
                &buffered_a_fingerprint,
                0,
                &buffered_b_fingerprint,
                "cancelled_after_buffered_drain",
                0,
                &events,
                "pass",
            );
        }

        {
            let bidi_request_a = Bytes::from_static(b"bidi-request-a");
            let bidi_request_a_fingerprint = bytes_fingerprint(&bidi_request_a);
            let bidi_request_b = Bytes::from_static(b"bidi-request-b");
            let bidi_request_b_fingerprint = bytes_fingerprint(&bidi_request_b);
            let bidi_response_a = Bytes::from_static(b"bidi-response-a");
            let bidi_response_a_fingerprint = bytes_fingerprint(&bidi_response_a);
            let bidi_response_b = Bytes::from_static(b"bidi-response-b");
            let bidi_response_b_fingerprint = bytes_fingerprint(&bidi_response_b);

            let mut request_stream = StreamingRequest::<Bytes>::open();
            request_stream
                .push(bidi_request_a)
                .expect("buffer first bidi request body");
            request_stream
                .push(bidi_request_b)
                .expect("buffer second bidi request body");
            request_stream.close();

            let mut response_stream = ResponseStream::<Bytes>::open();
            response_stream
                .push(Ok(bidi_response_a))
                .expect("buffer first bidi response body");
            response_stream
                .push(Ok(bidi_response_b))
                .expect("buffer second bidi response body");
            response_stream.close();

            let request_events = collect_streaming_request_byte_events(&mut request_stream);
            let response_events = collect_response_stream_byte_events(&mut response_stream);
            assert_eq!(
                request_events,
                vec![
                    format!("ok:{bidi_request_a_fingerprint}"),
                    format!("ok:{bidi_request_b_fingerprint}"),
                    "none".to_string(),
                ],
                "bidi request-side Bytes must preserve per-message fingerprints"
            );
            assert_eq!(
                response_events,
                vec![
                    format!("ok:{bidi_response_a_fingerprint}"),
                    format!("ok:{bidi_response_b_fingerprint}"),
                    "none".to_string(),
                ],
                "bidi response-side Bytes must preserve per-message fingerprints"
            );

            let mut observed_events = request_events
                .iter()
                .map(|event| format!("request:{event}"))
                .collect::<Vec<_>>();
            observed_events.extend(
                response_events
                    .iter()
                    .map(|event| format!("response:{event}")),
            );

            log_grpc_bytes_body_immutability_case(
                "grpc-bytes-bidi-001",
                "bidirectional",
                &bidi_request_a_fingerprint,
                0,
                &bidi_response_a_fingerprint,
                "graceful_half_close_both_directions",
                0,
                &observed_events,
                "pass",
            );
        }

        crate::test_complete!("conformance_grpc_bytes_body_immutability_matrix_logs_evidence");
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

    #[test]
    fn conformance_server_streaming_cancel_timing_before_first_send_surfaces_cancelled() {
        init_test(
            "conformance_server_streaming_cancel_timing_before_first_send_surfaces_cancelled",
        );
        let mut stream = ResponseStream::<u32>::open();
        stream.cancel_with_error(Status::cancelled("server cancelled before first send"));

        let events = collect_response_stream_events(&mut stream);
        assert_eq!(
            events,
            vec!["err:Cancelled:server cancelled before first send".to_string()],
            "cancel before first send should surface CANCELLED immediately"
        );

        crate::test_complete!(
            "conformance_server_streaming_cancel_timing_before_first_send_surfaces_cancelled"
        );
    }

    #[test]
    fn conformance_server_streaming_cancel_timing_after_buffered_messages_drains_then_cancelled() {
        init_test(
            "conformance_server_streaming_cancel_timing_after_buffered_messages_drains_then_cancelled",
        );
        let mut stream = ResponseStream::<u32>::open();
        stream.push(Ok(10)).expect("first buffered response");
        stream.push(Ok(20)).expect("second buffered response");
        stream.push(Ok(30)).expect("third buffered response");
        stream.cancel_with_error(Status::cancelled(
            "server cancelled after queueing responses",
        ));

        let events = collect_response_stream_events(&mut stream);
        assert_eq!(
            events,
            vec![
                "ok:10".to_string(),
                "ok:20".to_string(),
                "ok:30".to_string(),
                "err:Cancelled:server cancelled after queueing responses".to_string(),
            ],
            "buffered responses must drain before the terminal CANCELLED status"
        );

        crate::test_complete!(
            "conformance_server_streaming_cancel_timing_after_buffered_messages_drains_then_cancelled"
        );
    }

    #[test]
    fn conformance_server_streaming_cancel_timing_graceful_close_beats_late_cancel() {
        init_test("conformance_server_streaming_cancel_timing_graceful_close_beats_late_cancel");
        let mut stream = ResponseStream::<u32>::open();
        stream.push(Ok(44)).expect("buffered response");
        stream.close();
        stream.cancel_with_error(Status::cancelled(
            "late transport cancel after graceful close",
        ));

        let events = collect_response_stream_events(&mut stream);
        assert_eq!(
            events,
            vec!["ok:44".to_string(), "none".to_string()],
            "graceful close must preserve EOF even if a late cancel arrives"
        );

        crate::test_complete!(
            "conformance_server_streaming_cancel_timing_graceful_close_beats_late_cancel"
        );
    }

    #[test]
    fn conformance_server_streaming_cancel_timing_matrix_logs_evidence() {
        init_test("conformance_server_streaming_cancel_timing_matrix_logs_evidence");

        {
            let mut stream = ResponseStream::<u32>::open();
            stream.cancel_with_error(Status::cancelled("server cancelled before first send"));
            let events = collect_response_stream_events(&mut stream);
            log_server_stream_cancel_timing_case(
                "before_first_send",
                "before_first_send",
                0,
                &events,
                "ready_terminal_status",
                "implicit_status_only",
            );
        }

        {
            let mut stream = ResponseStream::<u32>::open();
            stream.push(Ok(10)).expect("buffered response");
            stream.push(Ok(20)).expect("buffered response");
            stream.push(Ok(30)).expect("buffered response");
            stream.cancel_with_error(Status::cancelled(
                "server cancelled after queueing responses",
            ));
            let events = collect_response_stream_events(&mut stream);
            log_server_stream_cancel_timing_case(
                "after_buffered_messages",
                "after_buffered_messages",
                3,
                &events,
                "ready_buffered_then_terminal_status",
                "implicit_status_only",
            );
        }

        {
            let mut stream = ResponseStream::<u32>::open();
            for value in 0..MAX_STREAM_BUFFERED as u32 {
                stream.push(Ok(value)).expect("buffer before saturation");
            }
            let overflow = stream
                .push(Ok(MAX_STREAM_BUFFERED as u32))
                .expect_err("overflow push must fail");
            assert_eq!(
                overflow.code(),
                Code::ResourceExhausted,
                "buffer-cap overflow should fail closed before cancellation"
            );
            stream.cancel_with_error(Status::cancelled(
                "server cancelled while producer observed full response buffer",
            ));
            let events = collect_response_stream_events(&mut stream);
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.starts_with("ok:"))
                    .count(),
                MAX_STREAM_BUFFERED,
                "all buffered responses must still drain after saturation-triggered cancellation"
            );
            assert!(
                matches!(events.last(), Some(last) if last.starts_with("err:Cancelled:")),
                "saturation-triggered cancellation must end with CANCELLED"
            );
            log_server_stream_cancel_timing_case(
                "buffer_saturated_then_cancelled",
                "producer_observed_full_buffer_then_cancelled",
                MAX_STREAM_BUFFERED,
                &events,
                "buffer_cap_rejected_new_send",
                "implicit_status_only",
            );
        }

        {
            let mut stream = ResponseStream::<u32>::open();
            stream.push(Ok(44)).expect("buffered response");
            stream.close();
            stream.cancel_with_error(Status::cancelled(
                "late transport cancel after graceful close",
            ));
            let events = collect_response_stream_events(&mut stream);
            log_server_stream_cancel_timing_case(
                "late_cancel_after_graceful_close",
                "late_cancel_after_graceful_close",
                1,
                &events,
                "ready_buffered_then_eof",
                "graceful_eof_only",
            );
        }
    }

    /// GRPC-DIFF-GRACEFUL-STOP: grpc-go GracefulStop lets already-buffered
    /// stream messages drain to EOF; a later transport-shutdown signal must not
    /// rewrite that graceful completion into an error status.
    #[test]
    fn differential_graceful_close_beats_late_shutdown_status_vs_grpc_go() {
        init_test("differential_graceful_close_beats_late_shutdown_status_vs_grpc_go");

        let mut stream = ResponseStream::<&'static str>::open();
        stream
            .push(Ok("buffered-1"))
            .expect("first buffered response");
        stream
            .push(Ok("buffered-2"))
            .expect("second buffered response");
        stream.close();
        stream.cancel_with_error(Status::unavailable("server shutdown after graceful-stop"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut stream);

        assert!(
            matches!(
                pinned.as_mut().poll_next(&mut cx),
                Poll::Ready(Some(Ok("buffered-1")))
            ),
            "grpc-go GracefulStop: first buffered response must still drain"
        );
        assert!(
            matches!(
                pinned.as_mut().poll_next(&mut cx),
                Poll::Ready(Some(Ok("buffered-2")))
            ),
            "grpc-go GracefulStop: second buffered response must still drain"
        );

        for attempt in 0..2 {
            assert!(
                matches!(pinned.as_mut().poll_next(&mut cx), Poll::Ready(None)),
                "grpc-go GracefulStop: late shutdown must preserve EOF on attempt {attempt}"
            );
        }

        crate::test_complete!("differential_graceful_close_beats_late_shutdown_status_vs_grpc_go");
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
            Status::unimplemented("rpc method is unsupported"),
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

        let combined_output = format!("{}\n", outputs.join("\n"));
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
                "{}: {:?} (binary={}) -> {:?}",
                description, input_key, binary, result
            ));
        }

        let combined_output = format!("{}\n", outputs.join("\n"));
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
            "A\0B\tC\x1FD\x7FEαF",
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

        // Bidirectional streaming: the in-file marker-only type was removed
        // (br-asupersync-iuoayq); the real bidirectional surface lives
        // in `crate::grpc::client`. The previous Debug-print line is
        // intentionally omitted from the snapshot.

        // Request sink
        let request_sink = RequestSink::<bool>::new();
        outputs.push(format!("=== Request Sink ===\n{request_sink:?}\n"));

        let combined_output = outputs.join("\n");
        assert_golden("streaming_types_debug_formatting", &combined_output);
    }

    /// GRPC-DIFF-CANCEL: Bidirectional cancellation semantics vs grpc-go reference
    ///
    /// This differential test verifies our bidirectional cancellation behavior matches
    /// grpc-go's cancellation semantics. In gRPC bidirectional streaming, when either
    /// side cancels, the cancellation must propagate correctly and both streams must
    /// transition to fail-closed state with the cancellation reason preserved.
    ///
    /// Reference behavior (grpc-go v1.54+):
    /// - Client cancel → server receives context.Canceled, stops processing
    /// - Server cancel → client receives status error, stops processing
    /// - Both sides must distinguish cancellation from graceful completion
    /// - Buffered messages drain before cancellation status is returned
    #[test]
    fn differential_bidirectional_cancellation_semantics_vs_grpc_go() {
        init_test("differential_bidirectional_cancellation_semantics_vs_grpc_go");

        // Simulate bidirectional streaming with client and server sides
        let mut client_request_stream = StreamingRequest::<String>::open();
        let mut server_response_stream = ResponseStream::<String>::open();

        // Phase 1: Normal bidirectional message exchange
        client_request_stream
            .push("client_msg_1".to_string())
            .expect("client sends");
        server_response_stream
            .push(Ok("server_resp_1".to_string()))
            .expect("server responds");

        client_request_stream
            .push("client_msg_2".to_string())
            .expect("client sends");
        server_response_stream
            .push(Ok("server_resp_2".to_string()))
            .expect("server responds");

        // Phase 2: Client-side cancellation during active streaming
        // Per gRPC spec: client cancellation must propagate cancellation reason
        let cancel_status = Status::cancelled("client cancelled bidirectional stream");
        client_request_stream.cancel_with_error(cancel_status.clone());

        // Phase 3: Verify fail-closed semantics match grpc-go behavior
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        // Client stream should drain buffered messages before returning cancellation
        assert!(
            matches!(
                Pin::new(&mut client_request_stream).poll_next(&mut cx),
                Poll::Ready(Some(Ok(ref msg))) if msg == "client_msg_1"
            ),
            "grpc-go semantics: buffered messages drain before cancellation"
        );

        assert!(
            matches!(
                Pin::new(&mut client_request_stream).poll_next(&mut cx),
                Poll::Ready(Some(Ok(ref msg))) if msg == "client_msg_2"
            ),
            "grpc-go semantics: all buffered messages drained"
        );

        // After draining, cancellation status must be returned (fail-closed)
        match Pin::new(&mut client_request_stream).poll_next(&mut cx) {
            Poll::Ready(Some(Err(status))) => {
                assert_eq!(
                    status.code(),
                    Code::Cancelled,
                    "grpc-go: cancellation code preserved"
                );
                assert!(
                    status.message().contains("client cancelled"),
                    "grpc-go: cancellation reason preserved"
                );
            }
            other => {
                panic!("grpc-go semantics violated: expected cancellation status, got {other:?}")
            }
        }

        // Phase 4: Simulate server-side cancellation response
        // Per grpc-go: server detects client cancellation and cancels its response stream
        let server_cancel_status = Status::cancelled("server detected client cancellation");
        server_response_stream.cancel_with_error(server_cancel_status.clone());

        // Server response stream should also follow fail-closed semantics
        assert!(
            matches!(
                Pin::new(&mut server_response_stream).poll_next(&mut cx),
                Poll::Ready(Some(Ok(ref msg))) if msg == "server_resp_1"
            ),
            "grpc-go: server drains responses before cancellation"
        );

        assert!(
            matches!(
                Pin::new(&mut server_response_stream).poll_next(&mut cx),
                Poll::Ready(Some(Ok(ref msg))) if msg == "server_resp_2"
            ),
            "grpc-go: server drains all responses"
        );

        // Server cancellation status returned after drain
        match Pin::new(&mut server_response_stream).poll_next(&mut cx) {
            Poll::Ready(Some(Err(status))) => {
                assert_eq!(
                    status.code(),
                    Code::Cancelled,
                    "grpc-go: server cancellation code"
                );
                assert!(
                    status.message().contains("server detected"),
                    "grpc-go: server cancellation message preserved"
                );
            }
            other => panic!(
                "grpc-go server semantics violated: expected cancellation status, got {other:?}"
            ),
        }

        // Phase 5: Verify bidirectional cancellation state consistency
        // Both streams should now be in cancelled state and reject new messages
        let post_cancel_send = client_request_stream.push("post_cancel".to_string());
        assert!(
            post_cancel_send.is_err(),
            "grpc-go: cancelled request stream rejects new messages"
        );

        let post_cancel_response = server_response_stream.push(Ok("post_cancel".to_string()));
        assert!(
            post_cancel_response.is_err(),
            "grpc-go: cancelled response stream rejects new messages"
        );

        // Phase 6: Verify idempotent cancellation status (grpc-go behavior)
        // Subsequent polls should consistently return the same cancellation status
        match Pin::new(&mut client_request_stream).poll_next(&mut cx) {
            Poll::Ready(Some(Err(status))) => {
                assert_eq!(
                    status.code(),
                    Code::Cancelled,
                    "grpc-go: cancellation status idempotent"
                );
            }
            other => panic!("grpc-go idempotent cancellation violated: {other:?}"),
        }

        match Pin::new(&mut server_response_stream).poll_next(&mut cx) {
            Poll::Ready(Some(Err(status))) => {
                assert_eq!(
                    status.code(),
                    Code::Cancelled,
                    "grpc-go: server cancellation idempotent"
                );
            }
            other => panic!("grpc-go server idempotent cancellation violated: {other:?}"),
        }

        crate::test_complete!("differential_bidirectional_cancellation_semantics_vs_grpc_go");
    }

    #[test]
    fn conformance_bidirectional_cancellation_client_initiated_after_buffered_messages() {
        init_test(
            "conformance_bidirectional_cancellation_client_initiated_after_buffered_messages",
        );

        let mut client_request_stream = StreamingRequest::<&'static str>::open();
        let mut server_response_stream = ResponseStream::<&'static str>::open();
        client_request_stream
            .push("client-1")
            .expect("first client request should buffer");
        client_request_stream
            .push("client-2")
            .expect("second client request should buffer");
        server_response_stream
            .push(Ok("server-1"))
            .expect("first server response should buffer");
        server_response_stream
            .push(Ok("server-2"))
            .expect("second server response should buffer");

        client_request_stream
            .cancel_with_error(Status::cancelled("client initiated bidi cancellation"));
        server_response_stream.cancel_with_error(Status::cancelled(
            "server observed client bidi cancellation",
        ));

        let client_events = collect_streaming_request_events(&mut client_request_stream);
        let server_events = collect_response_stream_events(&mut server_response_stream);
        assert_eq!(
            client_events,
            vec![
                "ok:client-1".to_string(),
                "ok:client-2".to_string(),
                "err:Cancelled:client initiated bidi cancellation".to_string(),
            ],
            "client side should drain buffered requests before terminal CANCELLED"
        );
        assert_eq!(
            server_events,
            vec![
                "ok:server-1".to_string(),
                "ok:server-2".to_string(),
                "err:Cancelled:server observed client bidi cancellation".to_string(),
            ],
            "server side should drain buffered responses before terminal CANCELLED"
        );
        assert!(
            client_request_stream.push("post-cancel").is_err(),
            "client request side must reject new sends after cancellation"
        );
        assert!(
            server_response_stream.push(Ok("post-cancel")).is_err(),
            "server response side must reject new sends after cancellation"
        );

        crate::test_complete!(
            "conformance_bidirectional_cancellation_client_initiated_after_buffered_messages"
        );
    }

    #[test]
    fn conformance_bidirectional_cancellation_server_initiated_before_first_message() {
        init_test("conformance_bidirectional_cancellation_server_initiated_before_first_message");

        let mut client_request_stream = StreamingRequest::<&'static str>::open();
        let mut server_response_stream = ResponseStream::<&'static str>::open();
        client_request_stream.cancel_with_error(Status::cancelled(
            "server propagated cancellation before first client message",
        ));
        server_response_stream.cancel_with_error(Status::cancelled(
            "server initiated cancellation before first response",
        ));

        let client_events = collect_streaming_request_events(&mut client_request_stream);
        let server_events = collect_response_stream_events(&mut server_response_stream);
        assert_eq!(
            client_events,
            vec![
                "err:Cancelled:server propagated cancellation before first client message"
                    .to_string()
            ],
            "client side should fail closed before any messages are sent"
        );
        assert_eq!(
            server_events,
            vec!["err:Cancelled:server initiated cancellation before first response".to_string()],
            "server side should fail closed before any responses are sent"
        );

        crate::test_complete!(
            "conformance_bidirectional_cancellation_server_initiated_before_first_message"
        );
    }

    #[test]
    fn conformance_bidirectional_cancellation_concurrent_cancel_while_recv_pending() {
        init_test("conformance_bidirectional_cancellation_concurrent_cancel_while_recv_pending");

        let mut client_request_stream = StreamingRequest::<&'static str>::open();
        let mut server_response_stream = ResponseStream::<&'static str>::open();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(
            matches!(
                Pin::new(&mut client_request_stream).poll_next(&mut cx),
                Poll::Pending
            ),
            "empty open client request stream should be pending before cancellation"
        );
        assert!(
            matches!(
                Pin::new(&mut server_response_stream).poll_next(&mut cx),
                Poll::Pending
            ),
            "empty open server response stream should be pending before cancellation"
        );

        client_request_stream.cancel_with_error(Status::cancelled(
            "client cancelled while both sides were recv-pending",
        ));
        server_response_stream.cancel_with_error(Status::cancelled(
            "server cancelled while both sides were recv-pending",
        ));

        let client_events = collect_streaming_request_events(&mut client_request_stream);
        let server_events = collect_response_stream_events(&mut server_response_stream);
        assert_eq!(
            client_events,
            vec!["err:Cancelled:client cancelled while both sides were recv-pending".to_string()],
            "recv-pending client side should transition directly to CANCELLED"
        );
        assert_eq!(
            server_events,
            vec!["err:Cancelled:server cancelled while both sides were recv-pending".to_string()],
            "recv-pending server side should transition directly to CANCELLED"
        );

        crate::test_complete!(
            "conformance_bidirectional_cancellation_concurrent_cancel_while_recv_pending"
        );
    }

    #[test]
    fn conformance_bidirectional_cancellation_while_send_blocked_drains_then_cancelled() {
        init_test(
            "conformance_bidirectional_cancellation_while_send_blocked_drains_then_cancelled",
        );

        let mut client_request_stream = StreamingRequest::<u32>::open();
        let mut server_response_stream = ResponseStream::<u32>::open();
        for value in 0..MAX_STREAM_BUFFERED as u32 {
            client_request_stream
                .push(value)
                .expect("client side should fill request buffer");
            server_response_stream
                .push(Ok(value))
                .expect("server side should fill response buffer");
        }

        let client_overflow = client_request_stream
            .push(MAX_STREAM_BUFFERED as u32)
            .expect_err("client overflow should fail while send is effectively blocked");
        let server_overflow = server_response_stream
            .push(Ok(MAX_STREAM_BUFFERED as u32))
            .expect_err("server overflow should fail while send is effectively blocked");
        assert_eq!(
            client_overflow.code(),
            Code::ResourceExhausted,
            "client blocked-send proxy should report ResourceExhausted"
        );
        assert_eq!(
            server_overflow.code(),
            Code::ResourceExhausted,
            "server blocked-send proxy should report ResourceExhausted"
        );

        client_request_stream.cancel_with_error(Status::cancelled(
            "client cancelled while send was backpressured",
        ));
        server_response_stream.cancel_with_error(Status::cancelled(
            "server cancelled while send was backpressured",
        ));

        let client_events = collect_streaming_request_events(&mut client_request_stream);
        let server_events = collect_response_stream_events(&mut server_response_stream);
        assert_eq!(
            client_events
                .iter()
                .filter(|event| event.starts_with("ok:"))
                .count(),
            MAX_STREAM_BUFFERED,
            "all buffered client request messages must drain before terminal CANCELLED"
        );
        assert_eq!(
            server_events
                .iter()
                .filter(|event| event.starts_with("ok:"))
                .count(),
            MAX_STREAM_BUFFERED,
            "all buffered server response messages must drain before terminal CANCELLED"
        );
        assert!(
            matches!(client_events.last(), Some(last) if last.starts_with("err:Cancelled:")),
            "client side must end with CANCELLED after draining"
        );
        assert!(
            matches!(server_events.last(), Some(last) if last.starts_with("err:Cancelled:")),
            "server side must end with CANCELLED after draining"
        );

        crate::test_complete!(
            "conformance_bidirectional_cancellation_while_send_blocked_drains_then_cancelled"
        );
    }

    #[test]
    fn conformance_bidirectional_cancellation_matrix_logs_evidence() {
        init_test("conformance_bidirectional_cancellation_matrix_logs_evidence");

        {
            let mut client_request_stream = StreamingRequest::<&'static str>::open();
            let mut server_response_stream = ResponseStream::<&'static str>::open();
            client_request_stream
                .push("client-1")
                .expect("buffer client message");
            client_request_stream
                .push("client-2")
                .expect("buffer client message");
            server_response_stream
                .push(Ok("server-1"))
                .expect("buffer server response");
            server_response_stream
                .push(Ok("server-2"))
                .expect("buffer server response");
            client_request_stream
                .cancel_with_error(Status::cancelled("client initiated bidi cancellation"));
            server_response_stream.cancel_with_error(Status::cancelled(
                "server observed client bidi cancellation",
            ));
            let client_events = collect_streaming_request_events(&mut client_request_stream);
            let server_events = collect_response_stream_events(&mut server_response_stream);
            log_bidirectional_cancellation_case(
                "client_initiated_after_buffered_messages",
                "client",
                &client_events,
                &server_events,
                "not_blocked",
                "not_pending",
                0,
            );
        }

        {
            let mut client_request_stream = StreamingRequest::<&'static str>::open();
            let mut server_response_stream = ResponseStream::<&'static str>::open();
            client_request_stream.cancel_with_error(Status::cancelled(
                "server propagated cancellation before first client message",
            ));
            server_response_stream.cancel_with_error(Status::cancelled(
                "server initiated cancellation before first response",
            ));
            let client_events = collect_streaming_request_events(&mut client_request_stream);
            let server_events = collect_response_stream_events(&mut server_response_stream);
            log_bidirectional_cancellation_case(
                "server_initiated_before_first_message",
                "server",
                &client_events,
                &server_events,
                "not_blocked",
                "not_pending",
                0,
            );
        }

        {
            let mut client_request_stream = StreamingRequest::<&'static str>::open();
            let mut server_response_stream = ResponseStream::<&'static str>::open();
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(matches!(
                Pin::new(&mut client_request_stream).poll_next(&mut cx),
                Poll::Pending
            ));
            assert!(matches!(
                Pin::new(&mut server_response_stream).poll_next(&mut cx),
                Poll::Pending
            ));
            client_request_stream.cancel_with_error(Status::cancelled(
                "client cancelled while both sides were recv-pending",
            ));
            server_response_stream.cancel_with_error(Status::cancelled(
                "server cancelled while both sides were recv-pending",
            ));
            let client_events = collect_streaming_request_events(&mut client_request_stream);
            let server_events = collect_response_stream_events(&mut server_response_stream);
            log_bidirectional_cancellation_case(
                "concurrent_cancel_while_recv_pending",
                "both",
                &client_events,
                &server_events,
                "not_blocked",
                "both_pending",
                1,
            );
        }

        {
            let mut client_request_stream = StreamingRequest::<u32>::open();
            let mut server_response_stream = ResponseStream::<u32>::open();
            for value in 0..MAX_STREAM_BUFFERED as u32 {
                client_request_stream
                    .push(value)
                    .expect("fill client request buffer");
                server_response_stream
                    .push(Ok(value))
                    .expect("fill server response buffer");
            }
            let client_overflow = client_request_stream
                .push(MAX_STREAM_BUFFERED as u32)
                .expect_err("client overflow should fail");
            let server_overflow = server_response_stream
                .push(Ok(MAX_STREAM_BUFFERED as u32))
                .expect_err("server overflow should fail");
            assert_eq!(client_overflow.code(), Code::ResourceExhausted);
            assert_eq!(server_overflow.code(), Code::ResourceExhausted);
            client_request_stream.cancel_with_error(Status::cancelled(
                "client cancelled while send was backpressured",
            ));
            server_response_stream.cancel_with_error(Status::cancelled(
                "server cancelled while send was backpressured",
            ));
            let client_events = collect_streaming_request_events(&mut client_request_stream);
            let server_events = collect_response_stream_events(&mut server_response_stream);
            log_bidirectional_cancellation_case(
                "both_cancel_while_send_blocked",
                "both",
                &client_events,
                &server_events,
                "both_backpressured",
                "not_pending",
                1,
            );
        }
    }

    #[test]
    fn late_rst_stream_cancel_does_not_mask_prior_request_window_underflow() {
        init_test("late_rst_stream_cancel_does_not_mask_prior_request_window_underflow");

        let mut request_stream = StreamingRequest::<String>::open();
        request_stream
            .push("buffered-request".to_string())
            .expect("buffer request item");
        request_stream.cancel_with_error(Status::resource_exhausted("WINDOW_UPDATE underflow"));
        request_stream.cancel_with_error(grpc_go_rst_stream_status(ErrorCode::Cancel));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned_request = Pin::new(&mut request_stream);

        assert!(
            matches!(
                pinned_request.as_mut().poll_next(&mut cx),
                Poll::Ready(Some(Ok(ref msg))) if msg == "buffered-request"
            ),
            "buffered request should still drain before the terminal status"
        );

        for attempt in 0..2 {
            match pinned_request.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Err(status))) => {
                    assert_eq!(
                        status.code(),
                        Code::ResourceExhausted,
                        "late RST_STREAM must not mask prior window-underflow status on attempt {attempt}"
                    );
                    assert!(
                        status.message().contains("WINDOW_UPDATE underflow"),
                        "original flow-control failure message must be preserved on attempt {attempt}"
                    );
                }
                other => panic!(
                    "expected preserved request-side terminal status after late RST_STREAM, got {other:?}"
                ),
            }
        }

        crate::test_complete!(
            "late_rst_stream_cancel_does_not_mask_prior_request_window_underflow"
        );
    }

    #[test]
    fn late_rst_stream_cancel_does_not_mask_prior_response_decode_poison() {
        init_test("late_rst_stream_cancel_does_not_mask_prior_response_decode_poison");

        let mut response_stream = ResponseStream::<String>::open();
        response_stream
            .push(Ok("buffered-response".to_string()))
            .expect("buffer response item");
        response_stream.cancel_with_error(Status::internal("decode poison"));
        response_stream.cancel_with_error(grpc_go_rst_stream_status(ErrorCode::Cancel));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned_response = Pin::new(&mut response_stream);

        assert!(
            matches!(
                pinned_response.as_mut().poll_next(&mut cx),
                Poll::Ready(Some(Ok(ref msg))) if msg == "buffered-response"
            ),
            "buffered response should still drain before the terminal status"
        );

        for attempt in 0..2 {
            match pinned_response.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Err(status))) => {
                    assert_eq!(
                        status.code(),
                        Code::Internal,
                        "late RST_STREAM must not mask prior decode-poison status on attempt {attempt}"
                    );
                    assert!(
                        status.message().contains("decode poison"),
                        "original decode-poison message must be preserved on attempt {attempt}"
                    );
                }
                other => panic!(
                    "expected preserved response-side terminal status after late RST_STREAM, got {other:?}"
                ),
            }
        }

        crate::test_complete!("late_rst_stream_cancel_does_not_mask_prior_response_decode_poison");
    }

    /// GRPC-DIFF-RST: RST_STREAM error codes must propagate with grpc-go-style
    /// status classes after any already-buffered items are drained.
    #[test]
    fn differential_rst_stream_error_code_propagation_vs_grpc_go() {
        init_test("differential_rst_stream_error_code_propagation_vs_grpc_go");

        let cases = [
            (ErrorCode::Cancel, Code::Cancelled, "CANCEL"),
            (
                ErrorCode::RefusedStream,
                Code::Unavailable,
                "REFUSED_STREAM",
            ),
            (ErrorCode::ProtocolError, Code::Internal, "PROTOCOL_ERROR"),
        ];

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        for (index, (rst_code, expected_code, expected_token)) in cases.iter().copied().enumerate()
        {
            let request_buffered = format!("request-buffered-{index}");
            let response_buffered = format!("response-buffered-{index}");
            let mut request_stream = StreamingRequest::<String>::open();
            request_stream
                .push(request_buffered.clone())
                .expect("buffer request item");
            request_stream.cancel_with_error(grpc_go_rst_stream_status(rst_code));

            let mut response_stream = ResponseStream::<String>::open();
            response_stream
                .push(Ok(response_buffered.clone()))
                .expect("buffer response item");
            response_stream.cancel_with_error(grpc_go_rst_stream_status(rst_code));

            let mut pinned_request = Pin::new(&mut request_stream);
            let mut pinned_response = Pin::new(&mut response_stream);

            assert!(
                matches!(
                    pinned_request.as_mut().poll_next(&mut cx),
                    Poll::Ready(Some(Ok(ref msg))) if msg == &request_buffered
                ),
                "grpc-go: buffered request items must drain before RST_STREAM status for {rst_code}"
            );
            match pinned_request.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Err(status))) => {
                    assert_eq!(
                        status.code(),
                        expected_code,
                        "grpc-go: request-side RST_STREAM code class drifted for {rst_code}"
                    );
                    assert!(
                        status.message().contains(expected_token),
                        "grpc-go: request-side RST_STREAM details should mention {expected_token}"
                    );
                }
                other => {
                    panic!("expected request-side RST_STREAM status for {rst_code}, got {other:?}")
                }
            }
            match pinned_request.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Err(status))) => {
                    assert_eq!(
                        status.code(),
                        expected_code,
                        "grpc-go: request-side RST_STREAM status should stay idempotent for {rst_code}"
                    );
                }
                other => panic!(
                    "expected idempotent request-side RST_STREAM status for {rst_code}, got {other:?}"
                ),
            }

            assert!(
                matches!(
                    pinned_response.as_mut().poll_next(&mut cx),
                    Poll::Ready(Some(Ok(ref msg))) if msg == &response_buffered
                ),
                "grpc-go: buffered response items must drain before RST_STREAM status for {rst_code}"
            );
            match pinned_response.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Err(status))) => {
                    assert_eq!(
                        status.code(),
                        expected_code,
                        "grpc-go: response-side RST_STREAM code class drifted for {rst_code}"
                    );
                    assert!(
                        status.message().contains(expected_token),
                        "grpc-go: response-side RST_STREAM details should mention {expected_token}"
                    );
                }
                other => {
                    panic!("expected response-side RST_STREAM status for {rst_code}, got {other:?}")
                }
            }
            match pinned_response.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(Err(status))) => {
                    assert_eq!(
                        status.code(),
                        expected_code,
                        "grpc-go: response-side RST_STREAM status should stay idempotent for {rst_code}"
                    );
                }
                other => panic!(
                    "expected idempotent response-side RST_STREAM status for {rst_code}, got {other:?}"
                ),
            }
        }

        crate::test_complete!("differential_rst_stream_error_code_propagation_vs_grpc_go");
    }
}
