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
use std::sync::{Arc, Mutex};
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

fn metadata_ascii_value_is_valid(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .copied()
        .all(metadata_ascii_value_is_visible)
}

/// Defensively sanitize a raw ASCII metadata value at an encoding boundary.
///
/// Public [`Metadata`] insertion rejects invalid values instead of calling this
/// helper. Keeping the lossy transform out of insertion is security-sensitive:
/// stripping a control byte can turn a malformed protocol value into a valid
/// value with different semantics.
pub(crate) fn sanitize_metadata_ascii_value(value: &str) -> Cow<'_, str> {
    if metadata_ascii_value_is_valid(value) {
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
    /// Returns `false` without modifying the metadata when the key is invalid
    /// (including an ASCII key ending in the binary-only `-bin` suffix) or the
    /// value contains bytes outside the printable ASCII range required by gRPC
    /// over HTTP/2. Invalid values are rejected as a whole rather than stripped
    /// because removal could transmute malformed protocol values.
    #[must_use = "check whether the metadata key and value were valid and the entry was stored"]
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> bool {
        let key = key.into();
        let Some(key) = normalize_metadata_key(&key, false) else {
            return false;
        };
        if key.ends_with("-bin") {
            return false;
        }
        let value = value.into();
        if !metadata_ascii_value_is_valid(&value) {
            return false;
        }
        self.entries.push((key, MetadataValue::Ascii(value)));
        true
    }

    /// Insert an ASCII value, replacing any existing entries for the same key.
    ///
    /// Returns `false` without modifying the metadata when the key is invalid
    /// (including an ASCII key ending in the binary-only `-bin` suffix) or the
    /// value contains bytes outside the printable ASCII range required by gRPC
    /// over HTTP/2. Validation happens before existing values are removed, so a
    /// rejected replacement preserves the prior entry.
    #[must_use = "check whether the metadata key and value were valid and the entry was stored"]
    pub fn insert_or_replace(&mut self, key: impl Into<String>, value: impl Into<String>) -> bool {
        let key = key.into();
        let Some(key) = normalize_metadata_key(&key, false) else {
            return false;
        };
        if key.ends_with("-bin") {
            return false;
        }
        let value = value.into();
        if !metadata_ascii_value_is_valid(&value) {
            return false;
        }
        self.entries
            .retain(|(existing_key, _)| !existing_key.eq_ignore_ascii_case(&key));
        self.entries.push((key, MetadataValue::Ascii(value)));
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
pub const MAX_STREAM_BUFFERED: usize = 1024;

fn wake_waiter(waiter: &mut Option<Waker>) {
    if let Some(waiter) = waiter.take() {
        waiter.wake();
    }
}

/// Shared, cheap-clone cancellation handle that couples both halves of a
/// streaming gRPC call to ONE cancellation.
///
/// Without it, the request and response streams cancel independently — a caller
/// has to remember to `cancel_with_error` both. With both halves opened against
/// the same `CallCancellation`, a single [`cancel`](CallCancellation::cancel)
/// (driven by a client RST_STREAM, deadline expiry, or a server `Cx` cancel)
/// makes both halves drain their buffered messages and then surface the same
/// terminal [`Status`] — one coherent cancellation protocol over the whole
/// call. This is the call-scoped coupling primitive for
/// `br-asupersync-server-stack-hardening-eeexl1.10` (AC1); wiring it into the
/// h2/gRPC dispatch (RST / deadline / server-cancel sources) is layered on top.
///
/// The first status wins (idempotent); buffered items already queued before the
/// cancel are still drained before the terminal status, matching
/// [`StreamingRequest::cancel_with_error`].
#[derive(Clone, Debug, Default)]
pub struct CallCancellation {
    inner: Arc<Mutex<CallCancellationState>>,
}

#[derive(Debug, Default)]
struct CallCancellationState {
    status: Option<Status>,
    wakers: Vec<Waker>,
}

impl CallCancellation {
    /// Create an un-cancelled call cancellation handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel the whole call with one coherent status.
    ///
    /// Idempotent: the first status wins. Wakes every stream half currently
    /// parked on this call so they re-poll and observe the cancellation.
    pub fn cancel(&self, status: Status) {
        let wakers = {
            let mut state = self.lock();
            if state.status.is_none() {
                state.status = Some(status);
            }
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }

    /// The terminal status, if the call has been cancelled.
    #[must_use]
    pub fn status(&self) -> Option<Status> {
        self.lock().status.clone()
    }

    /// Whether the call has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.lock().status.is_some()
    }

    /// Register a waker to be notified on cancellation. If already cancelled,
    /// wakes immediately so the caller re-polls and observes the terminal
    /// status (drain-then-cancel) instead of parking.
    fn register(&self, waker: &Waker) {
        let mut state = self.lock();
        if state.status.is_some() {
            drop(state);
            waker.wake_by_ref();
            return;
        }
        if !state
            .wakers
            .iter()
            .any(|existing| existing.will_wake(waker))
        {
            state.wakers.push(waker.clone());
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CallCancellationState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    /// Last producer waker parked on [`StreamingRequest::poll_reserve`] when
    /// the bounded buffer is full; woken on the next consumer drain.
    capacity_waiter: Option<Waker>,
    /// Call-scoped cancellation shared with the response half, if any.
    call_cancellation: Option<CallCancellation>,
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
            capacity_waiter: None,
            call_cancellation: None,
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
            capacity_waiter: None,
            call_cancellation: None,
        }
    }

    /// Creates an open request stream coupled to a call-scoped
    /// [`CallCancellation`], so cancelling the call drives this half and the
    /// response half from one coherent cancellation.
    #[must_use]
    pub fn open_in_call(call_cancellation: CallCancellation) -> Self {
        Self {
            items: VecDeque::new(),
            closed: false,
            graceful_terminal: false,
            terminal_status: None,
            waiter: None,
            capacity_waiter: None,
            call_cancellation: Some(call_cancellation),
        }
    }

    /// Number of queued request items currently waiting to be consumed.
    #[must_use]
    pub fn buffer_len(&self) -> usize {
        self.items.len()
    }

    /// Maximum number of request items this stream will buffer before applying
    /// sender backpressure.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        MAX_STREAM_BUFFERED
    }

    /// Remaining enqueue slots before the stream applies sender backpressure.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        MAX_STREAM_BUFFERED.saturating_sub(self.items.len())
    }

    /// Whether the stream has reached its bounded buffer cap.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.items.len() >= MAX_STREAM_BUFFERED
    }

    /// Polls for buffer capacity, *suspending* the producer at the
    /// bounded-buffer window when it is exhausted.
    ///
    /// This is the suspend/resume counterpart to [`push`](Self::push) /
    /// [`push_result`](Self::push_result): where those fail fast with
    /// [`Code::ResourceExhausted`](crate::grpc::status::Code::ResourceExhausted)
    /// once the buffer is full, `poll_reserve` instead parks the producer
    /// until the consumer drains an item (the "window update"), then wakes it
    /// so the next push is guaranteed a free slot. A producer that gates each
    /// push behind `poll_reserve` is flow-controlled — it cannot outrun a slow
    /// consumer, and the buffer never exceeds [`MAX_STREAM_BUFFERED`].
    ///
    /// Returns:
    /// - `Poll::Ready(Ok(()))` when at least one slot is free,
    /// - `Poll::Pending` (registering `cx`'s waker) when the buffer is full,
    /// - `Poll::Ready(Err(_))` when the stream is closed — the producer should
    ///   stop rather than spin.
    pub fn poll_reserve(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Status>> {
        // A call-scoped cancel must stop the producer too, not just the
        // consumer: a producer parked at a full window when the peer cancels
        // would otherwise hang on a window that never reopens. Fail closed with
        // the call's terminal status so one cancel drives BOTH halves (AC1).
        if let Some(status) = self
            .call_cancellation
            .as_ref()
            .and_then(CallCancellation::status)
        {
            return Poll::Ready(Err(status));
        }
        if self.closed {
            return Poll::Ready(Err(Status::failed_precondition(
                "cannot reserve capacity on a closed streaming request",
            )));
        }
        if self.items.len() < MAX_STREAM_BUFFERED {
            return Poll::Ready(Ok(()));
        }
        self.capacity_waiter = Some(cx.waker().clone());
        // Also park on the call cancellation so a cancel (not just a consumer
        // drain) unparks the producer.
        if let Some(call_cancellation) = &self.call_cancellation {
            call_cancellation.register(cx.waker());
        }
        Poll::Pending
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
        // Wake any producer parked on `poll_reserve` so it re-polls, observes
        // the close, and stops rather than hanging on a window that will never
        // reopen.
        wake_waiter(&mut self.capacity_waiter);
    }

    /// Cancels the stream with an error status (fail-closed).
    /// Future polls will return the error instead of None.
    pub fn cancel_with_error(&mut self, status: Status) {
        if self.graceful_terminal && self.terminal_status.is_none() {
            self.closed = true;
            wake_waiter(&mut self.waiter);
            wake_waiter(&mut self.capacity_waiter);
            return;
        }
        self.closed = true;
        if self.terminal_status.is_none() {
            self.terminal_status = Some(status);
        }
        wake_waiter(&mut self.waiter);
        wake_waiter(&mut self.capacity_waiter);
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
            // A buffer slot just freed: wake a producer parked on
            // `poll_reserve` so it observes the window update and resumes.
            wake_waiter(&mut this.capacity_waiter);
            return Poll::Ready(Some(next));
        }
        // Apply a call-scoped cancellation: buffered items above are drained
        // first, then both halves of the call surface the same terminal status.
        // A graceful half-close already observed wins over a late call cancel.
        if this.terminal_status.is_none() && !this.graceful_terminal {
            if let Some(status) = this
                .call_cancellation
                .as_ref()
                .and_then(CallCancellation::status)
            {
                this.closed = true;
                this.terminal_status = Some(status);
            }
        }
        if this.closed {
            // SECURITY: Fail-closed stream cancellation - distinguish error vs graceful completion
            if let Some(terminal_status) = &this.terminal_status {
                return Poll::Ready(Some(Err(terminal_status.clone())));
            }
            return Poll::Ready(None);
        }
        this.waiter = Some(cx.waker().clone());
        if let Some(call_cancellation) = &this.call_cancellation {
            call_cancellation.register(cx.waker());
        }
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
    /// Call-scoped cancellation shared with the request half, if any.
    call_cancellation: Option<CallCancellation>,
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
            call_cancellation: None,
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
            call_cancellation: None,
        }
    }

    /// Creates an open response stream coupled to a call-scoped
    /// [`CallCancellation`], so cancelling the call drives this half and the
    /// request half from one coherent cancellation.
    #[must_use]
    pub fn open_in_call(call_cancellation: CallCancellation) -> Self {
        Self {
            items: VecDeque::new(),
            closed: false,
            graceful_terminal: false,
            waiter: None,
            terminal_status: None,
            call_cancellation: Some(call_cancellation),
        }
    }

    /// Number of queued response items currently waiting to be consumed.
    #[must_use]
    pub fn buffer_len(&self) -> usize {
        self.items.len()
    }

    /// Maximum number of response items this stream will buffer before applying
    /// sender backpressure.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        MAX_STREAM_BUFFERED
    }

    /// Remaining enqueue slots before the stream applies sender backpressure.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        MAX_STREAM_BUFFERED.saturating_sub(self.items.len())
    }

    /// Whether the stream has reached its bounded buffer cap.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.items.len() >= MAX_STREAM_BUFFERED
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
        // Apply a call-scoped cancellation: buffered items above are drained
        // first, then both halves of the call surface the same terminal status.
        // A graceful half-close already observed wins over a late call cancel.
        if this.terminal_status.is_none() && !this.graceful_terminal {
            if let Some(status) = this
                .call_cancellation
                .as_ref()
                .and_then(CallCancellation::status)
            {
                this.closed = true;
                this.terminal_status = Some(status);
            }
        }
        if this.closed {
            // SECURITY: Fail-closed stream cancellation - distinguish error vs graceful completion
            if let Some(terminal_status) = &this.terminal_status {
                return Poll::Ready(Some(Err(terminal_status.clone())));
            }
            return Poll::Ready(None);
        }
        this.waiter = Some(cx.waker().clone());
        if let Some(call_cancellation) = &this.call_cancellation {
            call_cancellation.register(cx.waker());
        }
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
#[path = "streaming_inline_tests.rs"]
mod tests;
