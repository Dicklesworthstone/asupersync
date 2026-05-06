//! Audit + regression test for `src/web/sse.rs` Server-Sent
//! Events disconnect handling.
//!
//! Operator's question: "when the client disconnects mid-stream,
//! does the server's emit-loop terminate promptly (within ~100ms
//! detection) or hang waiting for the next event?"
//!
//! Audit findings:
//!
//!   (a) **There is no emit-loop in `src/web/sse.rs`.** The
//!       `Sse` type (sse.rs:218-225) is a `Vec<SseEvent>`-backed
//!       BATCH, not a stream. The doc comment is explicit:
//!       "SSE response: a list of events serialized to the SSE
//!       wire format and emitted as a single HTTP response body".
//!       A second doc note (sse.rs:207-210) confirms: "The
//!       single-shot non-streaming serialization in
//!       [`IntoResponse`] is retained for bounded batch
//!       responses, while the separate `StreamingSse` state
//!       machine owns incremental chunks and cancellation checks.
//!
//!   (b) **`IntoResponse for Sse`** (sse.rs:308-343) calls
//!       `self.to_body()` synchronously to produce the entire
//!       response body in memory, then wraps it in a single
//!       `Response::new(StatusCode::OK, body.into_bytes())`. No
//!       async, no channels, no poll loop, no client interaction
//!       during serialization.
//!
//!   (c) **Per-response caps are enforced before / during
//!       materialization** (`DEFAULT_SSE_MAX_EVENTS = 100_000`
//!       and `DEFAULT_SSE_MAX_TOTAL_BYTES = 16 MiB`,
//!       br-asupersync-tamnew). A handler that tries to emit
//!       more events or larger bytes than the configured caps
//!       gets `413 Payload Too Large` instead of an unbounded
//!       allocation. This bounds the worst-case
//!       memory-per-request.
//!
//!   (d) **The streaming surface is explicit and not hidden
//!       inside `Sse::into_response`.** `StreamingSse` exposes
//!       pull-based `next_chunk(&Cx)` / `heartbeat_chunk(&Cx)`
//!       methods. It does not implement `IntoResponse`, `Stream`,
//!       or `poll_next`, so callers must wire it to a transport
//!       loop that owns request-region cancellation.
//!
//!   (e) **Client-disconnect surfaces at the HTTP transport
//!       layer.** The `Response` is consumed by the HTTP
//!       writer; if the underlying socket is closed the writer
//!       observes EPIPE/ECONNRESET on its next write — the SSE
//!       module does not need to detect that itself because it
//!       is not driving any per-event push.
//!
//! Verdict: **SOUND**. The existing batch `Sse` response still
//! has no emit-loop. The new `StreamingSse` surface is separate
//! and cancel-aware: it checkpoints the request `Cx` before
//! each event/heartbeat chunk and exposes an explicit
//! disconnect hook that closes producer state.
//!
//! This file pins both surfaces so future work cannot silently
//! replace the safe batch response or regress `StreamingSse`
//! into a hidden, non-cancel-aware emit loop.

use std::path::PathBuf;

fn read_sse_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/web/sse.rs");
    std::fs::read_to_string(&path).expect("read sse.rs")
}

#[test]
fn sse_struct_is_a_vec_backed_batch_not_a_stream() {
    // Pin (a): the Sse type holds events in a plain Vec, NOT a
    // Stream / Receiver / channel. A regression that swapped
    // the field for a streaming source without adding cancel-
    // aware termination logic would re-introduce hang-on-
    // disconnect.
    let source = read_sse_source();

    let struct_marker = "pub struct Sse {";
    let start = source.find(struct_marker).expect("Sse struct must exist");
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("Sse struct must close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("events: Vec<SseEvent>,"),
        "REGRESSION: Sse no longer holds events in a Vec<SseEvent>. \
         If a streaming source was introduced, the audit invariant \
         (no emit-loop, no disconnect-hang risk) is broken. The \
         streaming variant MUST be a separate type with explicit \
         cancel-aware emit-loop semantics — do NOT silently swap \
         this field's type. struct body:\n{body}",
    );

    // Defense-in-depth: forbid common streaming-source field
    // types that would let events arrive lazily.
    let suspect_field_types = [
        "events: Receiver<",
        "events: Box<dyn Stream",
        "events: Pin<Box<dyn Stream",
        "events: mpsc::",
        "events: broadcast::",
        "events: watch::",
    ];
    for pat in &suspect_field_types {
        assert!(
            !body.contains(pat),
            "REGRESSION: Sse field is now `{pat}` — a streaming \
             source. This needs a cancel-aware emit loop OR the \
             change should land as a separate type \
             (StreamingSse). Update this audit test together with \
             the new design.",
        );
    }
}

#[test]
fn sse_into_response_materializes_body_synchronously() {
    // Pin (b) AUDIT-CRITICAL: IntoResponse for Sse materializes
    // the entire body via self.to_body() and wraps it in a
    // single Response. No async, no channels, no poll loop. This
    // is what removes the disconnect-hang failure mode.
    let source = read_sse_source();

    let impl_marker = "impl IntoResponse for Sse {";
    let start = source.find(impl_marker).expect("IntoResponse for Sse");
    let end_rel = source[start..].find("\n}\n").expect("impl close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("self.to_body()"),
        "REGRESSION: IntoResponse for Sse no longer calls \
         self.to_body() to materialize the response body \
         synchronously. If a per-event push path was introduced, \
         it MUST be cancel-aware (checkpoint on the Cx between \
         events, terminate within bounded time after \
         disconnect) and this audit test MUST be updated to \
         verify those properties.\n\nimpl body:\n{body}",
    );

    // Forbid async / await / poll inside the IntoResponse impl
    // body.
    let suspect_async_patterns = ["async ", ".await", "poll_next", "Pin::new(", "Box::pin("];
    for pat in &suspect_async_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: IntoResponse for Sse now contains `{pat}` \
             — looks like an async / streaming path. Without \
             explicit cancel-aware termination logic and a \
             disconnect-detection bound, this re-introduces the \
             hang-on-disconnect failure mode the audit guards \
             against.\n\nimpl body:\n{body}",
        );
    }
}

#[test]
fn sse_module_has_no_async_or_stream_imports() {
    // Pin (d): streaming remains an explicit pull-based state
    // machine, not an implicit async task/channel hidden inside
    // the response type. A regression that pulled these imports
    // in for any reason should be reviewed.
    let source = read_sse_source();

    let suspect_imports = [
        "use std::future::",
        "use std::pin::",
        "use std::task::",
        "use crate::channel::",
        "use crate::sync::watch",
        "use crate::sync::broadcast",
        "use futures::",
        // Stream trait imports.
        "use crate::stream::Stream",
    ];
    for pat in &suspect_imports {
        assert!(
            !source.contains(pat),
            "REGRESSION: sse.rs now imports `{pat}` — async / \
             channel machinery appeared. Verify the code is \
             request-region owned and cancel-aware before allowing \
             this dependency.",
        );
    }

    // Also catch direct Stream trait impls and poll_next fns.
    let suspect_traits = ["impl Stream for", "fn poll_next("];
    for pat in &suspect_traits {
        assert!(
            !source.contains(pat),
            "REGRESSION: sse.rs now defines `{pat}` — a \
             streaming surface. `StreamingSse` is intentionally \
             pull-based via next_chunk(&Cx); update this audit \
             only with equivalent cancel-aware proof.",
        );
    }
}

#[test]
fn streaming_sse_variant_is_separate_and_cancel_checked() {
    let source = read_sse_source();

    for phrase in [
        "pub struct StreamingSse<",
        "pub trait StreamingSseSource",
        "pub fn next_chunk(&mut self, cx: &Cx)",
        "pub fn heartbeat_chunk(&mut self, cx: &Cx)",
        "cx.checkpoint()",
        "StreamingSseError::Cancelled",
        "self.source.cancel()",
    ] {
        assert!(
            source.contains(phrase),
            "REGRESSION: streaming SSE source no longer contains `{phrase}`; \
             cancel-aware incremental emission must stay explicit.",
        );
    }

    assert!(
        !source.contains("impl IntoResponse for StreamingSse"),
        "REGRESSION: StreamingSse must not be hidden behind the synchronous \
         IntoResponse batch path; transport integration must own the request \
         Cx and drive next_chunk(&Cx).",
    );
}

#[test]
fn sse_per_response_caps_are_enforced() {
    // Pin (c): the per-response caps prevent unbounded memory
    // allocation. A regression that removed them would let a
    // misbehaving handler construct a multi-GB body in memory.
    let source = read_sse_source();

    assert!(
        source.contains("pub const DEFAULT_SSE_MAX_EVENTS: usize = 100_000;"),
        "REGRESSION: DEFAULT_SSE_MAX_EVENTS constant is gone or \
         changed. The cap defends against unbounded event-list \
         expansion under attacker-controlled input.",
    );
    assert!(
        source.contains("pub const DEFAULT_SSE_MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;"),
        "REGRESSION: DEFAULT_SSE_MAX_TOTAL_BYTES constant is gone \
         or changed. The 16 MiB cap defends against unbounded \
         body-size expansion.",
    );

    // The IntoResponse impl must check both caps and surface
    // 413 PAYLOAD_TOO_LARGE.
    let impl_marker = "impl IntoResponse for Sse {";
    let start = source.find(impl_marker).expect("IntoResponse for Sse");
    let end_rel = source[start..].find("\n}\n").expect("impl close");
    let impl_body = &source[start..start + end_rel];

    assert!(
        impl_body.contains("PAYLOAD_TOO_LARGE"),
        "REGRESSION: cap-exceeded path no longer returns \
         PAYLOAD_TOO_LARGE (413). A regression that switched to \
         silent truncation would let a misbehaving handler \
         exceed limits without the operator noticing.\n\n\
         impl body:\n{impl_body}",
    );
    assert!(
        impl_body.contains("self.events.len() > self.max_events"),
        "REGRESSION: event-count cap check is gone or changed. \
         The cap MUST be checked BEFORE materializing the body \
         so a 100k+ event list is rejected without serializing.",
    );
    assert!(
        impl_body.contains("body.len() > self.max_total_bytes"),
        "REGRESSION: byte-size cap check is gone or changed. \
         A handler building a 100 MiB body must be rejected \
         (413), not allowed through.",
    );
}

#[test]
fn sse_doc_comment_explicitly_notes_non_streaming_design() {
    // Pin: the doc comment EXPLICITLY notes the deliberate
    // non-streaming batch design and points streaming callers to
    // the separate StreamingSse surface. Pinning the doc text
    // ensures the architectural intent stays visible in the source.
    let source = read_sse_source();

    // The doc phrasing wraps across lines. Match individual
    // load-bearing fragments rather than a single multi-word
    // substring so reflowing doesn't break the pin.
    let required_doc_phrases = [
        "single-shot",
        "non-streaming serialization",
        "bounded batch",
        "StreamingSse",
        "checkpoint request cancellation",
        "br-asupersync-o74l7u.1",
    ];
    for phrase in &required_doc_phrases {
        assert!(
            source.contains(phrase),
            "REGRESSION: sse.rs doc no longer contains `{phrase}`. \
             If the doc was just reworded, ensure the new wording \
             still distinguishes bounded batch SSE from the explicit \
             StreamingSse incremental path.",
        );
    }
}

#[test]
fn sse_to_body_is_a_pure_synchronous_serializer() {
    // Pin: `pub fn to_body(&self) -> String` is sync, returns
    // String, takes &self. A regression to async / streaming
    // / Future-returning would re-open the hang-on-disconnect
    // failure mode.
    let source = read_sse_source();

    assert!(
        source.contains("pub fn to_body(&self) -> String {"),
        "REGRESSION: Sse::to_body signature changed. The audit \
         relies on `to_body` being a synchronous String \
         serializer that returns the full body in one call. \
         If it became async (-> impl Future<Output = String>) \
         or streaming (-> impl Stream<Item = String>), the \
         IntoResponse impl above would also need to change \
         shape, and this audit must be updated to verify the \
         new semantics.",
    );
}

// ─── Behavioral end-to-end pin (default features) ───────────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::web::response::{IntoResponse, StatusCode};
    use asupersync::web::sse::{Sse, SseEvent};

    #[test]
    fn sse_into_response_returns_complete_body_synchronously() {
        // Pin (b): no async / no streaming. Calling
        // into_response is a synchronous call that returns the
        // full Response immediately.
        let sse = Sse::new(vec![
            SseEvent::default().data("hello"),
            SseEvent::default().data("world"),
        ]);
        let resp = sse.into_response();

        assert_eq!(resp.status, StatusCode::OK);
        let body = std::str::from_utf8(&resp.body).expect("utf8");
        assert!(body.contains("hello"));
        assert!(body.contains("world"));
        // Both events present in a single response body — proof
        // they were materialized eagerly, not pushed lazily.
        assert!(
            body.find("hello").unwrap() < body.find("world").unwrap(),
            "events MUST be in declared order in the materialized body",
        );
    }

    #[test]
    fn sse_oversized_event_count_rejects_with_413() {
        // Pin (c): the per-response event-count cap surfaces as
        // 413 Payload Too Large. A regression that silently
        // truncated would let an attacker drive memory pressure
        // without triggering an alert.
        let mut events = Vec::new();
        for i in 0..1000 {
            events.push(SseEvent::default().data(format!("event {i}")));
        }
        // Override the default cap to a tiny value to exercise
        // the path without building 100k+ events.
        let sse = Sse::new(events).max_events(10);
        let resp = sse.into_response();

        assert_eq!(
            resp.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "1000 events with cap=10 MUST surface as 413",
        );
    }

    #[test]
    fn sse_oversized_total_bytes_rejects_with_413() {
        // Pin (c): the per-response byte-size cap surfaces as
        // 413. We use a tiny cap (100 bytes) and a single event
        // with a large payload to drive the body past the cap.
        let big = "X".repeat(10_000);
        let sse = Sse::new(vec![SseEvent::default().data(big)]).max_total_bytes(100);
        let resp = sse.into_response();

        assert_eq!(
            resp.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "body=10k with cap=100 MUST surface as 413",
        );
    }

    #[test]
    fn sse_into_response_does_not_block_or_yield() {
        // Pin (b): into_response is synchronous and returns
        // immediately. Wall-clock latency is bounded by
        // serialization cost, not by any I/O / channel /
        // future. We verify by timing a non-trivial response
        // — it should complete in well under 100 ms (the
        // audit's threshold).
        use std::time::Instant;
        let events: Vec<_> = (0..1000)
            .map(|i| SseEvent::default().data(format!("event {i}")))
            .collect();
        let sse = Sse::new(events);

        let start = Instant::now();
        let _resp = sse.into_response();
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 100,
            "REGRESSION: Sse::into_response took {} ms — this \
             is supposed to be a pure synchronous serializer \
             with no I/O. If a streaming / channel path was \
             introduced, the audit pin above (no async/Stream/\
             channel imports) should have caught it; if not, \
             investigate.",
            elapsed.as_millis(),
        );
    }

    #[test]
    fn sse_response_headers_signal_event_stream_content_type() {
        // Pin: content-type is text/event-stream. Without this,
        // EventSource clients won't parse the body as SSE and
        // the whole response is wasted. (Also: cache-control
        // no-cache prevents proxies from re-replaying the same
        // events on reconnect.)
        let sse = Sse::event(SseEvent::default().data("x"));
        let resp = sse.into_response();

        let ct = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map_or("", |(_, v)| v.as_str());
        assert_eq!(
            ct, "text/event-stream",
            "content-type MUST be text/event-stream so EventSource \
             clients parse the body correctly",
        );

        let cc = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
            .map_or("", |(_, v)| v.as_str());
        assert_eq!(
            cc, "no-cache",
            "cache-control MUST be no-cache so proxies don't \
             cache and re-replay the event stream",
        );
    }
}
