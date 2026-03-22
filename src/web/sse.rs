//! Server-Sent Events (SSE) support.
//!
//! Implements the [SSE protocol](https://html.spec.whatwg.org/multipage/server-sent-events.html)
//! for pushing events from server to client over a long-lived HTTP connection.
//!
//! # Wire Format
//!
//! Each event is a sequence of `field: value\n` lines terminated by a blank
//! line (`\n\n`). Supported fields:
//!
//! - `data:` — event payload (multi-line supported)
//! - `event:` — event type name
//! - `id:` — last event ID for reconnection
//! - `retry:` — reconnection interval in milliseconds
//! - `:` (comment) — keep-alive or ignored data
//!
//! # Example
//!
//! ```ignore
//! use asupersync::web::sse::{SseEvent, Sse};
//!
//! fn handler() -> Sse {
//!     Sse::new(vec![
//!         SseEvent::default().data("hello"),
//!         SseEvent::default().event("ping").data("alive"),
//!     ])
//! }
//! ```

use std::fmt::{self, Write};
use std::time::Duration;

use super::response::{IntoResponse, Response, StatusCode};

// ─── SseEvent ────────────────────────────────────────────────────────────────

/// A single Server-Sent Event.
///
/// Build events using the builder methods. At minimum, an event should
/// have a `data` field, though comment-only events are also valid.
///
/// # Wire Format
///
/// ```text
/// event: message
/// id: 42
/// data: Hello, world!
///
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    /// Event type name (the `event:` field).
    event: Option<String>,
    /// Event data (the `data:` field). Multi-line data is split on `\n`.
    data: Option<String>,
    /// Last event ID (the `id:` field). Must not contain null bytes.
    id: Option<String>,
    /// Reconnection time in milliseconds (the `retry:` field).
    retry: Option<u64>,
    /// Comment lines (each prefixed with `:`).
    comment: Option<String>,
}

impl SseEvent {
    /// Set the event type.
    #[must_use]
    pub fn event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    /// Set the event data.
    ///
    /// Multi-line data is automatically split into multiple `data:` lines
    /// per the SSE specification.
    #[must_use]
    pub fn data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Set the last event ID.
    ///
    /// The ID must not contain null bytes (U+0000). If it does, the ID
    /// is silently ignored per the specification.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        if !id.contains('\0') {
            self.id = Some(id);
        }
        self
    }

    /// Set the reconnection time in milliseconds.
    #[must_use]
    pub fn retry(mut self, millis: u64) -> Self {
        self.retry = Some(millis);
        self
    }

    /// Set the retry interval from a [`Duration`].
    #[must_use]
    pub fn retry_duration(mut self, duration: Duration) -> Self {
        self.retry = Some(duration.as_millis().min(u128::from(u64::MAX)) as u64);
        self
    }

    /// Add a comment line.
    ///
    /// Comments are prefixed with `:` and are typically used for keep-alive
    /// messages. They are ignored by EventSource clients.
    #[must_use]
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Write this event to the given buffer in SSE wire format.
    fn write_to(&self, buf: &mut String) {
        // Comment lines first.
        if let Some(ref comment) = self.comment {
            for line in comment.lines() {
                let _ = writeln!(buf, ":{line}");
            }
        }

        // Event type (sanitize to prevent SSE field injection).
        if let Some(ref event) = self.event {
            let event = event.replace(['\r', '\n'], "");
            let _ = writeln!(buf, "event:{event}");
        }

        // Data — each line gets its own `data:` prefix.
        // Normalize bare \r to \n before splitting so the browser's
        // EventSource parser (WHATWG SSE spec) can't interpret a bare
        // \r as a field separator and inject retry:/event:/id: fields.
        if let Some(ref data) = self.data {
            let normalized = data.replace("\r\n", "\n").replace('\r', "\n");
            for line in normalized.split('\n') {
                let _ = writeln!(buf, "data:{line}");
            }
        }

        // ID (sanitize to prevent SSE field injection).
        if let Some(ref id) = self.id {
            let id = id.replace(['\r', '\n'], "");
            let _ = writeln!(buf, "id:{id}");
        }

        // Retry.
        if let Some(millis) = self.retry {
            let _ = writeln!(buf, "retry:{millis}");
        }

        // Terminate with blank line.
        buf.push('\n');
    }
}

impl fmt::Display for SseEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = String::new();
        self.write_to(&mut buf);
        f.write_str(&buf)
    }
}

// ─── Sse Response ────────────────────────────────────────────────────────────

/// An SSE response containing a sequence of events.
///
/// Wraps a collection of [`SseEvent`]s and serializes them as a
/// `text/event-stream` response body. Implements [`IntoResponse`] for
/// direct use as a handler return type.
///
/// # Keep-Alive
///
/// Use [`Sse::keep_alive`] to prepend a comment-based keep-alive event
/// that prevents proxies from closing idle connections.
///
/// # Example
///
/// ```ignore
/// use asupersync::web::sse::{SseEvent, Sse};
///
/// fn handler() -> Sse {
///     Sse::new(vec![
///         SseEvent::default().event("update").data("{\"count\": 1}"),
///         SseEvent::default().event("update").data("{\"count\": 2}"),
///     ])
///     .keep_alive()
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Sse {
    events: Vec<SseEvent>,
    keep_alive: bool,
    last_event_id: Option<String>,
}

impl Sse {
    /// Create an SSE response from a list of events.
    #[must_use]
    pub fn new(events: Vec<SseEvent>) -> Self {
        Self {
            events,
            keep_alive: false,
            last_event_id: None,
        }
    }

    /// Create an empty SSE response.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Create an SSE response from a single event.
    #[must_use]
    pub fn event(event: SseEvent) -> Self {
        Self::new(vec![event])
    }

    /// Enable keep-alive by prepending a comment event.
    #[must_use]
    pub fn keep_alive(mut self) -> Self {
        self.keep_alive = true;
        self
    }

    /// Set the `Last-Event-ID` value for reconnection support.
    ///
    /// When set, the response includes the ID on the last event,
    /// allowing clients to resume from where they left off.
    #[must_use]
    pub fn last_event_id(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        if !id.contains('\0') {
            self.last_event_id = Some(id);
        }
        self
    }

    /// Serialize all events to the SSE wire format.
    #[must_use]
    pub fn to_body(&self) -> String {
        let mut body = String::new();

        // Keep-alive comment.
        if self.keep_alive {
            body.push_str(":keep-alive\n\n");
        }

        // Serialize each event.
        for (i, event) in self.events.iter().enumerate() {
            // If this is the last event and we have a last_event_id, inject it.
            if i == self.events.len() - 1 && self.last_event_id.is_some() {
                let mut event_with_id = event.clone();
                if event_with_id.id.is_none() {
                    event_with_id.id.clone_from(&self.last_event_id);
                }
                event_with_id.write_to(&mut body);
            } else {
                event.write_to(&mut body);
            }
        }

        body
    }

    /// Return the number of events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Return `true` if there are no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl IntoResponse for Sse {
    fn into_response(self) -> Response {
        let body = self.to_body();
        Response::new(StatusCode::OK, body.into_bytes())
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .header("connection", "keep-alive")
    }
}

impl IntoResponse for SseEvent {
    fn into_response(self) -> Response {
        Sse::event(self).into_response()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ================================================================
    // SseEvent serialization
    // ================================================================

    #[test]
    fn event_data_only() {
        let event = SseEvent::default().data("hello");
        assert_eq!(event.to_string(), "data:hello\n\n");
    }

    #[test]
    fn event_with_type() {
        let event = SseEvent::default().event("message").data("hello");
        assert_eq!(event.to_string(), "event:message\ndata:hello\n\n");
    }

    #[test]
    fn event_with_id() {
        let event = SseEvent::default().data("hello").id("42");
        assert_eq!(event.to_string(), "data:hello\nid:42\n\n");
    }

    #[test]
    fn event_with_retry() {
        let event = SseEvent::default().data("hello").retry(3000);
        assert_eq!(event.to_string(), "data:hello\nretry:3000\n\n");
    }

    #[test]
    fn event_with_retry_duration() {
        let event = SseEvent::default()
            .data("hello")
            .retry_duration(Duration::from_secs(5));
        assert_eq!(event.to_string(), "data:hello\nretry:5000\n\n");
    }

    #[test]
    fn event_with_comment() {
        let event = SseEvent::default().comment("keep-alive");
        assert_eq!(event.to_string(), ":keep-alive\n\n");
    }

    #[test]
    fn event_multiline_data() {
        let event = SseEvent::default().data("line1\nline2\nline3");
        assert_eq!(event.to_string(), "data:line1\ndata:line2\ndata:line3\n\n");
    }

    #[test]
    fn event_all_fields() {
        let event = SseEvent::default()
            .comment("ping")
            .event("update")
            .data("payload")
            .id("7")
            .retry(1000);
        assert_eq!(
            event.to_string(),
            ":ping\nevent:update\ndata:payload\nid:7\nretry:1000\n\n"
        );
    }

    #[test]
    fn event_id_rejects_null_bytes() {
        let event = SseEvent::default().data("hello").id("bad\0id");
        assert!(event.id.is_none(), "null bytes in ID should be rejected");
        assert_eq!(event.to_string(), "data:hello\n\n");
    }

    #[test]
    fn event_empty() {
        let event = SseEvent::default();
        assert_eq!(event.to_string(), "\n");
    }

    #[test]
    fn event_multiline_comment() {
        let event = SseEvent::default().comment("line1\nline2");
        assert_eq!(event.to_string(), ":line1\n:line2\n\n");
    }

    // ================================================================
    // Sse response
    // ================================================================

    #[test]
    fn sse_empty() {
        let sse = Sse::empty();
        assert!(sse.is_empty());
        assert_eq!(sse.len(), 0);
        assert_eq!(sse.to_body(), "");
    }

    #[test]
    fn sse_single_event() {
        let sse = Sse::event(SseEvent::default().data("hello"));
        assert_eq!(sse.len(), 1);
        assert_eq!(sse.to_body(), "data:hello\n\n");
    }

    #[test]
    fn sse_multiple_events() {
        let sse = Sse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("second"),
        ]);
        assert_eq!(sse.to_body(), "data:first\n\ndata:second\n\n");
    }

    #[test]
    fn sse_keep_alive() {
        let sse = Sse::new(vec![SseEvent::default().data("hello")]).keep_alive();
        assert_eq!(sse.to_body(), ":keep-alive\n\ndata:hello\n\n");
    }

    #[test]
    fn sse_last_event_id() {
        let sse = Sse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("last"),
        ])
        .last_event_id("99");
        let body = sse.to_body();
        // First event should not have an ID.
        assert!(body.starts_with("data:first\n\n"));
        // Last event should have the injected ID.
        assert!(body.contains("id:99"));
    }

    #[test]
    fn sse_last_event_id_does_not_overwrite_existing() {
        let sse = Sse::new(vec![SseEvent::default().data("event").id("existing")])
            .last_event_id("injected");
        let body = sse.to_body();
        // Existing ID should be preserved.
        assert!(body.contains("id:existing"));
        assert!(!body.contains("id:injected"));
    }

    #[test]
    fn sse_last_event_id_rejects_null_bytes() {
        let sse = Sse::new(vec![SseEvent::default().data("event")]).last_event_id("bad\0id");
        let body = sse.to_body();
        // Null-byte ID should be silently rejected, matching SseEvent::id() behavior.
        assert!(
            !body.contains("id:"),
            "null-byte ID should not appear in output"
        );
        assert_eq!(body, "data:event\n\n");
    }

    // ================================================================
    // IntoResponse
    // ================================================================

    #[test]
    fn sse_into_response_headers() {
        let sse = Sse::event(SseEvent::default().data("hello"));
        let resp = sse.into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/event-stream"
        );
        assert_eq!(resp.headers.get("cache-control").unwrap(), "no-cache");
        assert_eq!(resp.headers.get("connection").unwrap(), "keep-alive");
    }

    #[test]
    fn sse_into_response_body() {
        let sse = Sse::new(vec![
            SseEvent::default().event("msg").data("hello"),
            SseEvent::default().event("msg").data("world"),
        ]);
        let resp = sse.into_response();
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert_eq!(body, "event:msg\ndata:hello\n\nevent:msg\ndata:world\n\n");
    }

    #[test]
    fn sse_event_into_response() {
        let event = SseEvent::default().data("direct");
        let resp = event.into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/event-stream"
        );
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert_eq!(body, "data:direct\n\n");
    }

    #[test]
    fn sse_keep_alive_with_multiple_events() {
        let sse = Sse::new(vec![
            SseEvent::default().data("a"),
            SseEvent::default().data("b"),
            SseEvent::default().data("c"),
        ])
        .keep_alive();
        let body = sse.to_body();
        assert!(body.starts_with(":keep-alive\n\n"));
        assert_eq!(body, ":keep-alive\n\ndata:a\n\ndata:b\n\ndata:c\n\n");
    }

    // ================================================================
    // Data type coverage
    // ================================================================

    #[test]
    fn sse_event_debug_clone_default_eq() {
        let event = SseEvent::default();
        let dbg = format!("{event:?}");
        assert!(dbg.contains("SseEvent"));

        let cloned = event.clone();
        assert_eq!(event, cloned);

        let event2 = SseEvent::default().data("different");
        assert_ne!(event, event2);
    }

    #[test]
    fn sse_debug_clone() {
        let sse = Sse::event(SseEvent::default().data("test"));
        let dbg = format!("{sse:?}");
        assert!(dbg.contains("Sse"));
    }

    // ================================================================
    // Realistic usage patterns
    // ================================================================

    #[test]
    fn sse_json_events() {
        let sse = Sse::new(vec![
            SseEvent::default()
                .event("update")
                .data(r#"{"count": 1}"#)
                .id("1"),
            SseEvent::default()
                .event("update")
                .data(r#"{"count": 2}"#)
                .id("2"),
        ]);
        let body = sse.to_body();
        assert!(body.contains("event:update"));
        assert!(body.contains(r#"data:{"count": 1}"#));
        assert!(body.contains("id:1"));
        assert!(body.contains(r#"data:{"count": 2}"#));
        assert!(body.contains("id:2"));
    }

    #[test]
    fn sse_with_retry_and_reconnection() {
        let sse = Sse::new(vec![
            SseEvent::default().retry(5000).comment("reconnect hint"),
            SseEvent::default().event("heartbeat").data(""),
        ]);
        let body = sse.to_body();
        assert!(body.contains("retry:5000"));
        assert!(body.contains(":reconnect hint"));
        assert!(body.contains("event:heartbeat"));
    }
}
