//! W3C propagation without buffering the HTTP response body.

use std::fmt;

use crate::cx::Cx;
use crate::http::h1::ClientStreamingResponse;
use crate::http::h1::http_client::ClientIo;
use crate::http::{HttpClient, Method};
use crate::observability::w3c_trace_context::W3CTraceContext;

use super::{TracedClientError, TracedHttpClient, is_propagation_header, outgoing_context};

impl TracedHttpClient {
    /// Starts a traced request that returns its response body incrementally.
    ///
    /// The client's configured timeout and the Cx budget bound the exchange
    /// through the response head. As with [`HttpClient::request_streaming`],
    /// consuming the body afterwards requires the caller's own cancellation
    /// checkpoints and deadline policy. No per-call timeout is implied.
    ///
    /// The underlying streaming path opens a fresh connection rather than
    /// borrowing a pooled buffered connection. The returned body owns that
    /// connection; dropping the body closes it instead of returning unread bytes
    /// to the pool. Response content decoding remains the caller's responsibility.
    pub fn streaming_request_builder<'a>(
        &'a self,
        method: Method,
        url: impl Into<String>,
        parent: &'a W3CTraceContext,
    ) -> TracedStreamingRequestBuilder<'a> {
        TracedStreamingRequestBuilder {
            client: &self.client,
            method,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            parent,
            forward_baggage: false,
        }
    }

    /// Starts a traced GET with an incremental response body.
    ///
    /// See [`Self::streaming_request_builder`] for connection ownership and the
    /// distinction between response-head deadlines and body consumption.
    pub fn get_streaming<'a>(
        &'a self,
        url: impl Into<String>,
        parent: &'a W3CTraceContext,
    ) -> TracedStreamingRequestBuilder<'a> {
        self.streaming_request_builder(Method::Get, url, parent)
    }
}

/// A request that propagates an explicit parent and streams the response body.
///
/// Each send derives its own child context from the supplied Cx's entropy.
/// Cloning an unsent builder does not duplicate a previously generated span ID.
#[must_use = "streaming traced requests do nothing unless sent"]
#[derive(Clone)]
pub struct TracedStreamingRequestBuilder<'a> {
    client: &'a HttpClient,
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    parent: &'a W3CTraceContext,
    forward_baggage: bool,
}

impl fmt::Debug for TracedStreamingRequestBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TracedStreamingRequestBuilder")
            .field("trace_id", &self.parent.trace_id.to_hex())
            .field("forward_baggage", &self.forward_baggage)
            .finish_non_exhaustive()
    }
}

impl TracedStreamingRequestBuilder<'_> {
    /// Adds a header except for traceparent, tracestate, and baggage (any case).
    /// Those three headers belong to the typed parent and baggage opt-in policy.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        if !is_propagation_header(&name) {
            self.headers.push((name, value.into()));
        }
        self
    }

    /// Adds headers with the propagation-header ownership of [`Self::header`].
    pub fn headers<I, N, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        for (name, value) in headers {
            self = self.header(name, value);
        }
        self
    }

    /// Sets the buffered request body. Only the response body is streamed.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Serializes a JSON request body and sets its content type.
    ///
    /// # Errors
    /// Returns the serialization error without sending a request.
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Result<Self, serde_json::Error> {
        self.body = serde_json::to_vec(value)?;
        self.headers
            .push(("Content-Type".into(), "application/json".into()));
        Ok(self)
    }

    /// Opts in to forwarding the parent's baggage to the selected origin.
    ///
    /// Disabled by default. Cross-origin redirects are never followed, including
    /// when this option is enabled. The destination must still be trusted by the
    /// caller to receive the baggage.
    pub fn propagate_baggage(mut self, enabled: bool) -> Self {
        self.forward_baggage = enabled;
        self
    }

    /// Sends the request and returns when the response head is available.
    ///
    /// The body is not drained, copied into a Vec, or detached into a task.
    /// Its native Body implementation preserves framing, trailers, limits, and
    /// connection ownership. Retries and redirects are exactly those of the
    /// existing streaming HTTP path, not those of the buffered response path.
    ///
    /// # Errors
    /// Returns propagation errors before I/O, or the underlying HTTP error.
    /// A body error occurring after the response head is returned is reported by
    /// the body's [`Body::poll_frame`](crate::http::body::Body::poll_frame).
    pub async fn send(mut self, cx: &Cx) -> Result<TracedStreamingResponse, TracedClientError> {
        let context = outgoing_context(self.parent, self.forward_baggage, |bytes| {
            cx.random_bytes(bytes);
        })
        .map_err(TracedClientError::Propagation)?;
        self.headers
            .push(("traceparent".into(), context.to_traceparent()));
        if let Some(state) = &context.tracestate {
            self.headers.push(("tracestate".into(), state.clone()));
        }
        if !context.baggage.is_empty() {
            let baggage = context
                .baggage
                .to_header()
                .map_err(TracedClientError::Propagation)?;
            self.headers.push(("baggage".into(), baggage));
        }
        let response = self
            .client
            .request_streaming(cx, self.method, &self.url, self.headers, self.body)
            .await
            .map_err(TracedClientError::Http)?;
        Ok(TracedStreamingResponse { response, context })
    }
}

/// A response head, its owned incremental body, and the outgoing trace context.
///
/// Consuming the body after this value is returned requires the caller's own
/// cancellation checkpoints and deadline policy. Dropping it closes the stream.
#[derive(Debug)]
#[non_exhaustive]
pub struct TracedStreamingResponse {
    /// The native response, including its head and owned body reader.
    pub response: ClientStreamingResponse<ClientIo>,
    /// Context for this logical outgoing request, not peer-supplied headers.
    pub context: W3CTraceContext,
}
