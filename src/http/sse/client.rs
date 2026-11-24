//! Caller-driven native Server-Sent Events over owned pooled HTTP responses.

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::cx::{CancelWakerToken, Cx};
use crate::http::body::Empty;
use crate::http::h1::{
    ClientError, HttpClient, HttpError, Method, ParsedUrl, PooledClientIncomingBody,
    PooledClientStreamingResponse,
};
use crate::stream::Stream;
use crate::time::Sleep;
use crate::types::{CancelReason, Time};

use super::{SseDecodeError, SseDecoder, SseEvent, SseLimits, SseStream, SseStreamError};

/// A finite reconnect allowance for one [`EventSource`].
///
/// The allowance is shared by the entire event source: receiving an event
/// does not replenish it. Clean EOF and transport I/O failures may reconnect;
/// HTTP status, framing, decoding, cancellation and deadline failures do not.
/// The initial GET is not a reconnect. The default performs that GET only.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    max_reconnects: u32,
    initial_delay: Duration,
    max_retry_delay: Duration,
}

impl ReconnectPolicy {
    /// Allows at most `max_reconnects` additional GET attempts.
    ///
    /// Initially `delay` is also the upper bound on server `retry` directives.
    /// Use [`Self::with_max_retry_delay`] to select a different bound. Zero
    /// delay is allowed; the finite allowance and per-poll work limit still
    /// prevent an unbounded synchronous reconnect loop.
    #[must_use]
    pub const fn new(max_reconnects: u32, delay: Duration) -> Self {
        Self {
            max_reconnects,
            initial_delay: delay,
            max_retry_delay: delay,
        }
    }

    /// Caps every wait, including the initial delay and server retry values.
    #[must_use]
    pub const fn with_max_retry_delay(mut self, delay: Duration) -> Self {
        self.max_retry_delay = delay;
        self
    }

    /// Returns the lifetime allowance, excluding the initial GET.
    #[must_use]
    pub const fn max_reconnects(self) -> u32 {
        self.max_reconnects
    }

    /// Returns the configured delay before any valid server retry directive.
    #[must_use]
    pub const fn initial_delay(self) -> Duration {
        self.initial_delay
    }

    /// Returns the upper bound on each reconnect wait.
    #[must_use]
    pub const fn max_retry_delay(self) -> Duration {
        self.max_retry_delay
    }
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::new(0, Duration::from_secs(3)).with_max_retry_delay(Duration::from_secs(60))
    }
}

/// Bounds, request headers and optional reconnect state for an event source.
#[derive(Debug, Clone, Default)]
pub struct EventSourceOptions {
    limits: SseLimits,
    reconnect: ReconnectPolicy,
    headers: Vec<(String, String)>,
    last_event_id: String,
}

impl EventSourceOptions {
    /// Sets the incremental parser and retained DATA frame bounds.
    #[must_use]
    pub fn limits(mut self, limits: SseLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Enables an explicit, finite reconnect policy.
    #[must_use]
    pub fn reconnect(mut self, reconnect: ReconnectPolicy) -> Self {
        self.reconnect = reconnect;
        self
    }

    /// Adds a header replayed only to the configured URL.
    ///
    /// `Accept`, `Accept-Encoding`, `Cache-Control` and `Last-Event-ID` are
    /// owned by the event source and override values supplied here or in the
    /// HTTP client's default headers. Redirects are never followed.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Resumes from a previously committed event ID.
    ///
    /// The constructor checks the decoder's bounds and HTTP header safety
    /// before any connection is attempted.
    #[must_use]
    pub fn last_event_id(mut self, id: impl Into<String>) -> Self {
        self.last_event_id = id.into();
        self
    }
}

/// A terminal native event-source failure.
///
/// Recoverable transport failures are retried only while the caller's finite
/// allowance remains. Once an error is yielded, subsequent polls return EOF.
#[derive(Debug)]
#[non_exhaustive]
pub enum EventSourceError {
    /// Request setup, connection, HTTP framing or transport failure.
    Http(ClientError),
    /// The incremental event stream failed.
    Stream(SseStreamError<ClientError>),
    /// An initial reconnect cursor violates a parser limit.
    Decode(SseDecodeError),
    /// Only HTTP 200 opens an event stream; HTTP 204 ends it without error.
    UnexpectedStatus(u16),
    /// Exactly one `Content-Type: text/event-stream` field is required.
    InvalidContentType,
    /// The server ignored `Accept-Encoding: identity`.
    UnsupportedContentEncoding(String),
    /// A committed cursor cannot safely be serialized as an HTTP header.
    InvalidLastEventId,
    /// The explicit owner acknowledged cancellation.
    Cancelled(CancelReason),
}

impl fmt::Display for EventSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(error) => write!(f, "event-source HTTP request failed: {error}"),
            Self::Stream(error) => write!(f, "event stream failed: {error}"),
            Self::Decode(error) => write!(f, "invalid event-source cursor: {error}"),
            Self::UnexpectedStatus(status) => write!(f, "event source returned HTTP {status}"),
            Self::InvalidContentType => f.write_str("event source requires text/event-stream"),
            Self::UnsupportedContentEncoding(encoding) => {
                write!(f, "event source returned unsupported content encoding: {encoding}")
            }
            Self::InvalidLastEventId => f.write_str("event ID is not a safe HTTP header value"),
            Self::Cancelled(reason) => write!(f, "event source cancelled: {reason}"),
        }
    }
}

impl std::error::Error for EventSourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(error) => Some(error),
            Self::Stream(error) => Some(error),
            Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

type OpenFuture = Pin<
    Box<dyn Future<Output = Result<PooledClientStreamingResponse, ClientError>> + Send + 'static>,
>;

enum State {
    Initial,
    Opening(OpenFuture),
    Reading(Box<SseStream<PooledClientIncomingBody>>),
    Waiting(Sleep),
    Closed,
}

/// A native, backpressured Server-Sent Events client.
///
/// Construction is lazy. [`Self::next_event`] or [`Stream::poll_next`] drives
/// the GET, decoding and any explicitly enabled reconnects. No background
/// task is created. Dropping a pending `next_event` future preserves the
/// request, partial event and reconnect wait in this object; dropping or
/// closing the object retires them and closes an unfinished response socket.
/// Fully consumed HTTP responses retain the ordinary client's pooling rules.
///
/// Every attempt uses the same URL and the HTTP client's pooled, one-shot
/// request API. Redirects are returned as errors even if the supplied client
/// follows redirects for ordinary requests, so credentials and event IDs are
/// never silently replayed to a redirect target. TLS, proxies, cookies,
/// connection admission and configured request timeouts use that client's
/// existing implementation. Its request timeout and response-body byte cap
/// apply separately to each HTTP exchange. Configure those bounds for the
/// expected lifetime and volume of a long-lived subscription. The original
/// `Cx` budget deadline remains observable throughout the event source,
/// including buffered events and reconnect waits; its checkpoints own
/// cancellation acknowledgement and masking.
///
/// Requests advertise `Accept: text/event-stream`, `Accept-Encoding: identity`
/// and `Cache-Control: no-cache`. `Last-Event-ID` always comes from the last
/// committed SSE block. An empty field deliberately overrides any stale
/// client default, including after an `id:` reset. An incomplete block at
/// disconnect never advances this cursor. HTTP 204 ends the source without
/// reconnecting; any other status besides 200 is a terminal error.
///
/// With no reconnect allowance, clean EOF ends the stream. With an allowance,
/// EOF and transport I/O failures reconnect after a capped delay. Successful
/// events do not reset the lifetime counter. Exhausting the allowance ends a
/// cleanly closed stream, or yields the last transport error. Syntax/size
/// errors, invalid HTTP metadata, cancellation and deadlines are terminal.
pub struct EventSource {
    cx: Cx,
    client: HttpClient,
    url: String,
    options: EventSourceOptions,
    state: State,
    last_event_id: String,
    retry_millis: Option<u64>,
    reconnects: u32,
    cancellation: Option<CancelWakerToken>,
    observed_deadline: Option<Time>,
    deadline: Option<Sleep>,
}

impl fmt::Debug for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.state {
            State::Initial => "initial",
            State::Opening(_) => "opening",
            State::Reading(_) => "reading",
            State::Waiting(_) => "waiting",
            State::Closed => "closed",
        };
        f.debug_struct("EventSource")
            .field("state", &state)
            .field("reconnects", &self.reconnects)
            .field("max_reconnects", &self.options.reconnect.max_reconnects)
            .finish_non_exhaustive()
    }
}

impl EventSource {
    /// Constructs a lazy event source with default bounds and no reconnects.
    pub fn new(
        cx: &Cx,
        client: HttpClient,
        url: impl Into<String>,
    ) -> Result<Self, EventSourceError> {
        Self::with_options(cx, client, url, EventSourceOptions::default())
    }

    /// Constructs a lazy event source with explicit bounds and retry policy.
    pub fn with_options(
        cx: &Cx,
        client: HttpClient,
        url: impl Into<String>,
        options: EventSourceOptions,
    ) -> Result<Self, EventSourceError> {
        let url = url.into();
        ParsedUrl::parse(&url).map_err(EventSourceError::Http)?;
        validate_cursor(&options.last_event_id)?;
        let _ = SseDecoder::new(options.limits)
            .with_last_event_id(options.last_event_id.clone())
            .map_err(EventSourceError::Decode)?;
        for (name, value) in &options.headers {
            crate::http::h1::codec::validate_header_field(name, value)
                .map_err(|error| EventSourceError::Http(ClientError::HttpError(error)))?;
        }
        let observed_deadline = cx.budget().deadline;
        Ok(Self {
            cx: cx.clone(),
            client,
            url,
            last_event_id: options.last_event_id.clone(),
            options,
            state: State::Initial,
            retry_millis: None,
            reconnects: 0,
            cancellation: None,
            observed_deadline,
            deadline: observed_deadline.map(|at| cx.sleep_until_on_clock(at)),
        })
    }

    /// Waits for the next event without transferring ownership of the stream.
    ///
    /// Dropping this wait leaves partial input and any in-flight GET intact.
    pub async fn next_event(&mut self) -> Option<Result<SseEvent, EventSourceError>> {
        poll_fn(|task| Pin::new(&mut *self).poll_next(task)).await
    }

    /// Returns the cursor committed by complete SSE block boundaries.
    #[must_use]
    pub fn last_event_id(&self) -> &str {
        &self.last_event_id
    }

    /// Returns additional GET attempts started, excluding the initial GET.
    #[must_use]
    pub const fn reconnects(&self) -> u32 {
        self.reconnects
    }

    /// Returns whether the stream is closed and will yield no further items.
    #[must_use]
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, State::Closed)
    }

    /// Closes the body, pending GET and retry wait synchronously.
    pub fn close(&mut self) {
        // Retire transport ownership before removing the external stop wake.
        self.state = State::Closed;
        self.deadline = None;
        if let Some(token) = self.cancellation.take() {
            self.cx.clear_cancel_waker(token);
        }
    }

    fn poll_stop(&mut self, task: &mut Context<'_>) -> Option<EventSourceError> {
        self.cancellation = Some(self.cx.refresh_cancel_waker(self.cancellation, task.waker()));
        if let Some(at) = self.cx.budget().deadline
            && self.observed_deadline.is_none_or(|previous| at < previous)
        {
            self.observed_deadline = Some(at);
            self.deadline = Some(self.cx.sleep_until_on_clock(at));
        }
        let _owner = self.cx.clone().set_current_restricted();
        if let Some(error) = self.checkpoint() {
            return Some(error);
        }
        if let Some(deadline) = self.deadline.as_mut()
            && Pin::new(deadline).poll_deadline(task).is_ready()
        {
            // A budget wake asks checkpoint to deliver cancellation. Under a
            // mask it must neither end cleanup nor repoll a completed timer.
            self.deadline = None;
        }
        // Timer registration can run a user Waker callback; close that race.
        self.checkpoint()
    }

    fn checkpoint(&self) -> Option<EventSourceError> {
        self.cx.checkpoint().err().map(|_| {
            EventSourceError::Cancelled(
                self.cx
                    .cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("event-source owner cancelled")),
            )
        })
    }

    fn start_request(&mut self) -> Result<(), EventSourceError> {
        validate_cursor(&self.last_event_id)?;
        let mut headers: Vec<_> = self
            .options
            .headers
            .iter()
            .filter(|(name, _)| !owned_header(name))
            .cloned()
            .collect();
        headers.extend([
            ("Accept".to_owned(), "text/event-stream".to_owned()),
            ("Accept-Encoding".to_owned(), "identity".to_owned()),
            ("Cache-Control".to_owned(), "no-cache".to_owned()),
            ("Last-Event-ID".to_owned(), self.last_event_id.clone()),
        ]);
        let client = self.client.clone();
        let cx = self.cx.clone();
        let url = self.url.clone();
        self.state = State::Opening(Box::pin(async move {
            // This pooled API deliberately does not follow redirects or retry
            // the upload. An Empty GET lets this state machine own both rules.
            client
                .request_with_body(&cx, Method::Get, &url, headers, Empty::new())
                .await
        }));
        Ok(())
    }

    fn schedule_reconnect(&mut self) -> bool {
        if self.reconnects >= self.options.reconnect.max_reconnects {
            return false;
        }
        let policy = self.options.reconnect;
        let delay = self
            .retry_millis
            .map_or(policy.initial_delay, Duration::from_millis)
            .min(policy.max_retry_delay);
        // A driverless owner's now() must not borrow a foreign polling task's
        // virtual epoch while sleep_until_on_clock captures the wall clock.
        let _owner = self.cx.clone().set_current_restricted();
        self.state = State::Waiting(self.cx.sleep_until_on_clock(self.cx.now() + delay));
        true
    }

    fn fail(&mut self, error: EventSourceError) -> Poll<Option<Result<SseEvent, EventSourceError>>> {
        self.close();
        Poll::Ready(Some(Err(error)))
    }
}

impl Stream for EventSource {
    type Item = Result<SseEvent, EventSourceError>;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.is_terminated() {
            return Poll::Ready(None);
        }
        if let Some(error) = this.poll_stop(task) {
            return this.fail(error);
        }
        // Even an immediately closing endpoint with retry:0 receives bounded
        // work per poll. The reconnect allowance bounds the whole lifetime.
        for _ in 0..16 {
            // If a user callback panics while polling, its local state drops
            // and the source remains closed instead of repolling that future.
            match std::mem::replace(&mut this.state, State::Closed) {
                State::Initial => {
                    if let Err(error) = this.start_request() {
                        return this.fail(error);
                    }
                }
                State::Opening(mut request) => match request.as_mut().poll(task) {
                    Poll::Pending => {
                        this.state = State::Opening(request);
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(error)) => {
                        drop(request);
                        if !retryable(&error) || !this.schedule_reconnect() {
                            return this.fail(EventSourceError::Http(error));
                        }
                    }
                    Poll::Ready(Ok(response)) => {
                        drop(request);
                        if response.head.status == 204 {
                            drop(response);
                            this.close();
                            return Poll::Ready(None);
                        }
                        if let Err(error) = validate_response(&response) {
                            drop(response);
                            return this.fail(error);
                        }
                        match SseStream::new(&this.cx, response.body, this.options.limits)
                            .with_last_event_id(this.last_event_id.clone())
                        {
                            Ok(stream) => this.state = State::Reading(Box::new(stream)),
                            Err(error) => return this.fail(EventSourceError::Decode(error)),
                        }
                    }
                },
                State::Reading(mut stream) => {
                    let result = Pin::new(stream.as_mut()).poll_next(task);
                    this.last_event_id.clear();
                    this.last_event_id.push_str(stream.last_event_id());
                    if let Some(retry) = stream.retry_millis() {
                        this.retry_millis = Some(retry);
                    }
                    match result {
                        Poll::Pending => {
                            this.state = State::Reading(stream);
                            return Poll::Pending;
                        }
                        Poll::Ready(Some(Ok(event))) => {
                            this.state = State::Reading(stream);
                            return Poll::Ready(Some(Ok(event)));
                        }
                        Poll::Ready(Some(Err(error))) => {
                            drop(stream);
                            let may_retry = matches!(
                                &error,
                                SseStreamError::Source(error) if retryable(error)
                            );
                            if !may_retry || !this.schedule_reconnect() {
                                return this.fail(EventSourceError::Stream(error));
                            }
                        }
                        Poll::Ready(None) => {
                            drop(stream);
                            if !this.schedule_reconnect() {
                                this.close();
                                return Poll::Ready(None);
                            }
                        }
                    }
                }
                State::Waiting(mut delay) => {
                    if Pin::new(&mut delay).poll_deadline(task).is_pending() {
                        this.state = State::Waiting(delay);
                        return Poll::Pending;
                    }
                    drop(delay);
                    this.reconnects += 1;
                    if let Err(error) = this.start_request() {
                        return this.fail(error);
                    }
                }
                State::Closed => {
                    this.close();
                    return Poll::Ready(None);
                }
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }
}

impl Drop for EventSource {
    fn drop(&mut self) {
        self.close();
    }
}

fn validate_cursor(id: &str) -> Result<(), EventSourceError> {
    crate::http::h1::codec::validate_header_field("Last-Event-ID", id)
        .map_err(|_| EventSourceError::InvalidLastEventId)
}

fn owned_header(name: &str) -> bool {
    ["accept", "accept-encoding", "cache-control", "last-event-id"]
        .into_iter()
        .any(|owned| name.eq_ignore_ascii_case(owned))
}

fn retryable(error: &ClientError) -> bool {
    match error {
        ClientError::DnsError(error)
        | ClientError::ConnectError(error)
        | ClientError::Io(error)
        | ClientError::HttpError(HttpError::Io(error)) => matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::Interrupted
        ),
        _ => false,
    }
}

fn validate_response(response: &PooledClientStreamingResponse) -> Result<(), EventSourceError> {
    if response.head.status != 200 {
        return Err(EventSourceError::UnexpectedStatus(response.head.status));
    }
    let mut content_types = response
        .head
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    let valid_type = content_types.next().is_some_and(|(_, value)| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/event-stream"))
    });
    if !valid_type || content_types.next().is_some() {
        return Err(EventSourceError::InvalidContentType);
    }
    for (_, encoding) in response
        .head
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
    {
        if !encoding.trim().eq_ignore_ascii_case("identity") {
            return Err(EventSourceError::UnsupportedContentEncoding(encoding.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
