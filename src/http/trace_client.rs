//! Explicit outbound W3C trace propagation through the pooled HTTP client.
//!
//! Construct one [`TracedHttpClient`] and reuse it across requests. Each request
//! supplies its parent context explicitly and gets a new child span ID from its
//! [`Cx`]'s entropy when prepared or sent. There is no thread-local trace, global
//! client, or new runtime task. The underlying client still owns pooling,
//! cancellation, request deadlines, retries, and response decoding.
//!
//! Trace context is sent only to the origin the caller selects: this client
//! follows same-origin redirects only, including when its configuration asks for
//! unrestricted redirects. Baggage is omitted unless a request opts in. Neither
//! guard changes the behavior of the ordinary [`HttpClient`].
//!
//! This is propagation, not span recording or export. [`TracedResponse`] returns
//! the outgoing context so an application can correlate its own telemetry. Use
//! [`TracedClientRequestBuilder::prepare`] to retain that context on HTTP errors.
//!
//! ```no_run
//! # async fn example(cx: &asupersync::Cx) -> Result<(), Box<dyn std::error::Error>> {
//! use asupersync::http::TracedHttpClient;
//! use asupersync::observability::w3c_trace_context::W3CTraceContext;
//!
//! // In a server, pass the context established by its W3C middleware instead.
//! let parent: W3CTraceContext =
//!     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?;
//! let client = TracedHttpClient::new();
//! let result = client.get("https://service.example/items", &parent).send(cx).await?;
//! assert_eq!(result.context.trace_id, parent.trace_id);
//! assert_eq!(result.context.parent_span_id, parent.span_id);
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use crate::cx::Cx;
use crate::observability::w3c_trace_context::{
    TraceContextError, W3CBaggage, W3CTraceContext, continue_or_start_trace_with, inject_to_http,
};

use super::{
    ClientError, ClientRequestBuilder, HttpClient, HttpClientConfig, Method, PoolStats,
    RedirectPolicy, Response,
};

/// A reusable pooled HTTP client with explicit, request-scoped W3C propagation.
///
/// Clones share the underlying pool. A parent context belongs to a request, not
/// to the client, so concurrent requests cannot overwrite each other's traces.
#[derive(Clone)]
pub struct TracedHttpClient {
    client: HttpClient,
}

impl fmt::Debug for TracedHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TracedHttpClient").finish_non_exhaustive()
    }
}

impl Default for TracedHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl TracedHttpClient {
    /// Creates a client with the ordinary HTTP defaults, except that redirects
    /// are restricted to the original origin.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(HttpClientConfig::default())
    }

    /// Creates a traced client using the supplied pool, TLS, timeout, retry,
    /// proxy, cookie, and decoding configuration.
    ///
    /// `Limited(n)` redirects are narrowed to `SameOrigin(n)`; `None` and an
    /// existing `SameOrigin(n)` are preserved. An origin includes the scheme,
    /// host, and port, so an HTTPS downgrade is not followed either.
    ///
    /// Default `traceparent`, `tracestate`, and `baggage` headers are removed,
    /// case-insensitively. They belong to individual requests, and retaining
    /// client-wide values could join unrelated traces or leak stale baggage.
    #[must_use]
    pub fn with_config(config: HttpClientConfig) -> Self {
        Self {
            client: HttpClient::with_config(propagation_config(config)),
        }
    }

    /// Returns the shared connection pool's current statistics.
    #[must_use]
    pub fn pool_stats(&self) -> PoolStats {
        self.client.pool_stats()
    }

    /// Starts a request under an explicit parent context.
    ///
    /// No entropy is consumed and no I/O occurs until the request is prepared
    /// or sent. Cloning an unsent builder and sending both copies creates two
    /// independently derived child contexts, not two requests with one span ID.
    pub fn request_builder<'a>(
        &'a self,
        method: Method,
        url: impl Into<String>,
        parent: &'a W3CTraceContext,
    ) -> TracedClientRequestBuilder<'a> {
        TracedClientRequestBuilder {
            request: self.client.request_builder(method, url),
            parent,
            forward_baggage: false,
        }
    }

    /// Starts a traced GET request.
    pub fn get<'a>(
        &'a self,
        url: impl Into<String>,
        parent: &'a W3CTraceContext,
    ) -> TracedClientRequestBuilder<'a> {
        self.request_builder(Method::Get, url, parent)
    }

    /// Starts a traced POST request.
    pub fn post<'a>(
        &'a self,
        url: impl Into<String>,
        parent: &'a W3CTraceContext,
    ) -> TracedClientRequestBuilder<'a> {
        self.request_builder(Method::Post, url, parent)
    }
}

fn is_propagation_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("traceparent")
        || name.eq_ignore_ascii_case("tracestate")
        || name.eq_ignore_ascii_case("baggage")
}

fn propagation_config(mut config: HttpClientConfig) -> HttpClientConfig {
    if let RedirectPolicy::Limited(limit) = config.redirect_policy {
        config.redirect_policy = RedirectPolicy::SameOrigin(limit);
    }
    config
        .default_headers
        .retain(|(name, _)| !is_propagation_header(name));
    config
}

/// A fluent request whose propagation headers are owned by its typed context.
#[must_use = "traced requests do nothing unless prepared or sent"]
#[derive(Clone)]
pub struct TracedClientRequestBuilder<'a> {
    request: ClientRequestBuilder<'a>,
    parent: &'a W3CTraceContext,
    forward_baggage: bool,
}

impl fmt::Debug for TracedClientRequestBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not expose request credentials or baggage through this wrapper.
        f.debug_struct("TracedClientRequestBuilder")
            .field("trace_id", &self.parent.trace_id.to_hex())
            .field("forward_baggage", &self.forward_baggage)
            .finish_non_exhaustive()
    }
}

impl<'a> TracedClientRequestBuilder<'a> {
    /// Adds a header, except for the three propagation headers.
    ///
    /// `traceparent`, `tracestate`, and `baggage` (in any case) are ignored here:
    /// the typed parent and [`Self::propagate_baggage`] are authoritative. This
    /// also makes it safe to pass a header collection carrying stale context.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        if !is_propagation_header(&name) {
            self.request = self.request.header(name, value);
        }
        self
    }

    /// Adds headers with the same propagation-header ownership as [`Self::header`].
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

    /// Sets the request body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.request = self.request.body(body);
        self
    }

    /// Serializes a JSON request body and sets its content type.
    ///
    /// # Errors
    /// Returns the underlying serialization error without sending a request.
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Result<Self, serde_json::Error> {
        self.request = self.request.json(value)?;
        Ok(self)
    }

    /// Sets a per-call timeout, meet-composed with the client and Cx budgets.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.request = self.request.timeout(timeout);
        self
    }

    /// Opts in to forwarding the parent's baggage to the selected origin.
    ///
    /// Off by default: baggage can contain application-sensitive information.
    /// The caller must trust the selected destination, including its same-origin
    /// redirect targets. Cross-origin redirects are never followed by this client.
    pub fn propagate_baggage(mut self, enabled: bool) -> Self {
        self.forward_baggage = enabled;
        self
    }

    /// Prepares the outgoing child context and the underlying HTTP request.
    ///
    /// IDs come from `cx.random_bytes`, so deterministic entropy replays them.
    /// The same child context follows the logical request's retries and
    /// same-origin redirects. To create a separate logical request, prepare or
    /// send another traced builder rather than cloning the prepared HTTP builder.
    ///
    /// This performs no network I/O. Retaining the returned context separately
    /// allows the caller to correlate both successful responses and HTTP errors.
    ///
    /// # Errors
    /// Returns a propagation error if opted-in baggage cannot be encoded.
    pub fn prepare(
        self,
        cx: &Cx,
    ) -> Result<(ClientRequestBuilder<'a>, W3CTraceContext), TraceContextError> {
        let context = outgoing_context(self.parent, self.forward_baggage, |bytes| {
            cx.random_bytes(bytes);
        })?;
        let mut request = self.request.header("traceparent", context.to_traceparent());
        if let Some(state) = &context.tracestate {
            request = request.header("tracestate", state.clone());
        }
        if !context.baggage.is_empty() {
            request = request.header("baggage", context.baggage.to_header()?);
        }
        Ok((request, context))
    }

    /// Sends the request through the ordinary pooled HTTP path.
    ///
    /// # Errors
    /// Returns propagation errors before I/O, or the underlying HTTP error,
    /// including cancellation and the existing meet-composed deadline errors.
    pub async fn send(self, cx: &Cx) -> Result<TracedResponse, TracedClientError> {
        let (request, context) = self.prepare(cx).map_err(TracedClientError::Propagation)?;
        let response = request.send(cx).await.map_err(TracedClientError::Http)?;
        Ok(TracedResponse { response, context })
    }
}

fn outgoing_context(
    parent: &W3CTraceContext,
    forward_baggage: bool,
    fill: impl FnMut(&mut [u8]),
) -> Result<W3CTraceContext, TraceContextError> {
    let mut parent = parent.clone();
    if !forward_baggage {
        parent.baggage = W3CBaggage::new();
    }
    let mut headers = HashMap::new();
    inject_to_http(&parent, &mut headers)?;
    Ok(continue_or_start_trace_with(&headers, fill))
}

/// A buffered response and the child context actually sent on the wire.
#[derive(Debug)]
#[non_exhaustive]
pub struct TracedResponse {
    /// The ordinary HTTP response, including its body and trailers.
    pub response: Response,
    /// Context for this logical outgoing request, not the peer's response headers.
    pub context: W3CTraceContext,
}

/// Failure to prepare propagation headers or execute a traced HTTP request.
#[derive(Debug)]
#[non_exhaustive]
pub enum TracedClientError {
    /// Propagation failed before network I/O.
    Propagation(TraceContextError),
    /// The underlying HTTP request failed.
    Http(ClientError),
}

impl fmt::Display for TracedClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Propagation(error) => write!(f, "HTTP trace propagation: {error}"),
            Self::Http(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for TracedClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Propagation(error) => Some(error),
            Self::Http(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent() -> W3CTraceContext {
        let mut context: W3CTraceContext =
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
                .parse()
                .unwrap();
        context.tracestate = Some("vendor=opaque,second=kept".into());
        context.baggage.insert("tenant", "private").unwrap();
        context
    }

    #[test]
    fn outgoing_child_preserves_lineage_flags_and_vendor_order_without_mutating_parent() {
        let parent = parent();
        let before = parent.clone();
        let child = outgoing_context(&parent, false, |bytes| bytes.fill(0x22)).unwrap();
        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(child.parent_span_id, parent.span_id);
        assert_ne!(child.span_id, parent.span_id);
        assert_eq!(child.flags, parent.flags);
        assert!(!child.flags.is_sampled());
        assert_eq!(child.tracestate, parent.tracestate);
        assert!(child.baggage.is_empty());
        assert_eq!(parent, before);
    }

    #[test]
    fn opted_in_baggage_keeps_values_and_properties() {
        let mut parent = parent();
        parent
            .baggage
            .insert_with_metadata("locale", "en US", Some("source=user"))
            .unwrap();
        let child = outgoing_context(&parent, true, |bytes| bytes.fill(0x33)).unwrap();
        assert_eq!(child.baggage, parent.baggage);
        assert_eq!(child.baggage.metadata("locale"), Some("source=user"));
    }

    #[test]
    fn child_ids_use_only_the_supplied_entropy_and_repair_zero() {
        let parent = parent();
        let mut counter = 0_u8;
        let mut fill = |bytes: &mut [u8]| {
            counter += 1;
            bytes.fill(counter);
        };
        let first = outgoing_context(&parent, false, &mut fill).unwrap();
        let second = outgoing_context(&parent, false, &mut fill).unwrap();
        assert_ne!(first.span_id, second.span_id);
        let replay = outgoing_context(&parent, false, |bytes| bytes.fill(1)).unwrap();
        assert_eq!(first, replay);
        let zero = outgoing_context(&parent, false, |bytes| bytes.fill(0)).unwrap();
        assert!(zero.to_traceparent().parse::<W3CTraceContext>().is_ok());
        assert_eq!(zero.trace_id, parent.trace_id);
    }

    #[test]
    fn configuration_cannot_forward_context_across_origins_or_keep_stale_defaults() {
        let mut config = HttpClientConfig::default();
        config.redirect_policy = RedirectPolicy::Limited(7);
        config.default_headers = vec![
            ("TraceParent".into(), "stale".into()),
            ("TRACESTATE".into(), "stale=state".into()),
            ("Baggage".into(), "secret=old".into()),
            ("X-Application".into(), "kept".into()),
        ];
        config.request_timeout = Some(Duration::from_secs(3));
        let config = propagation_config(config);
        assert!(matches!(config.redirect_policy, RedirectPolicy::SameOrigin(7)));
        assert_eq!(
            config.default_headers,
            vec![("X-Application".into(), "kept".into())]
        );
        assert_eq!(config.request_timeout, Some(Duration::from_secs(3)));
    }

    #[test]
    fn disabled_redirects_and_existing_same_origin_limits_are_preserved() {
        let mut config = HttpClientConfig::default();
        config.redirect_policy = RedirectPolicy::None;
        assert!(matches!(
            propagation_config(config).redirect_policy,
            RedirectPolicy::None
        ));
        let mut config = HttpClientConfig::default();
        config.redirect_policy = RedirectPolicy::SameOrigin(2);
        assert!(matches!(
            propagation_config(config).redirect_policy,
            RedirectPolicy::SameOrigin(2)
        ));
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod wire_tests;
