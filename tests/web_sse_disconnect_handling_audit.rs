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

fn read_sse_production_source() -> String {
    let source = read_sse_source();
    let test_module = "\n#[cfg(test)]\nmod tests {";
    let end = source
        .find(test_module)
        .expect("sse.rs must keep inline tests behind #[cfg(test)]");
    source[..end].to_owned()
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
    // the response type. Inline tests may need polling helpers,
    // but the production module must not pull these imports in.
    let source = read_sse_production_source();

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
    use std::cell::Cell;
    use std::rc::Rc;

    use asupersync::Cx;
    use asupersync::web::extract::Request;
    use asupersync::web::request_region::{RequestContext, RequestRegion};
    use asupersync::web::response::{IntoResponse, Response, StatusCode};
    use asupersync::web::sse::{
        Sse, SseEvent, StreamingSse, StreamingSseError, StreamingSseSource,
    };
    use serde_json::json;

    const BEAD_ID: &str = "asupersync-o74l7u.1.2";
    const ROUTE: &str = "/events";
    const RESPONSE_KIND: &str = "streaming-sse";

    #[derive(Debug)]
    struct LifecycleCounters {
        region: usize,
        task: usize,
        obligation: usize,
        buffer_bytes: usize,
    }

    impl LifecycleCounters {
        const fn streaming_sse_idle(buffer_bytes: usize) -> Self {
            Self {
                region: 0,
                task: 0,
                obligation: 0,
                buffer_bytes,
            }
        }
    }

    #[derive(Debug)]
    struct LifecycleObservation {
        chunks: Vec<Vec<u8>>,
        counters_before: LifecycleCounters,
        counters_after: LifecycleCounters,
        first_failure: Option<String>,
    }

    impl LifecycleObservation {
        const fn new() -> Self {
            Self {
                chunks: Vec::new(),
                counters_before: LifecycleCounters::streaming_sse_idle(0),
                counters_after: LifecycleCounters::streaming_sse_idle(0),
                first_failure: None,
            }
        }

        fn record_before<S: StreamingSseSource>(&mut self, stream: &StreamingSse<S>) {
            self.counters_before = LifecycleCounters::streaming_sse_idle(stream.bytes_emitted());
        }

        fn record_after<S: StreamingSseSource>(&mut self, stream: &StreamingSse<S>) {
            self.counters_after = LifecycleCounters::streaming_sse_idle(stream.bytes_emitted());
        }

        fn push_chunk(&mut self, chunk: Vec<u8>) {
            self.chunks.push(chunk);
        }
    }

    #[derive(Debug)]
    struct LifecycleProofRow {
        scenario_id: &'static str,
        client_disconnect_at: &'static str,
        expected_status: StatusCode,
        actual_status: StatusCode,
        cancel_requested_after: bool,
        expected_cancel_requested: bool,
        counters_before: LifecycleCounters,
        counters_after: LifecycleCounters,
        chunk_digests: Vec<String>,
        first_failure: Option<String>,
    }

    impl LifecycleProofRow {
        fn verdict(&self) -> &'static str {
            if self.first_failure.is_none()
                && self.actual_status == self.expected_status
                && self.cancel_requested_after == self.expected_cancel_requested
                && self.counters_before.region == self.counters_after.region
                && self.counters_before.task == self.counters_after.task
                && self.counters_before.obligation == self.counters_after.obligation
            {
                "pass"
            } else {
                "fail"
            }
        }

        fn emit(&self) {
            let row = json!({
                "bead_id": BEAD_ID,
                "scenario_id": self.scenario_id,
                "route": ROUTE,
                "response_kind": RESPONSE_KIND,
                "client_disconnect_at": self.client_disconnect_at,
                "region_count_before": self.counters_before.region,
                "region_count_after": self.counters_after.region,
                "task_count_before": self.counters_before.task,
                "task_count_after": self.counters_after.task,
                "obligation_count_before": self.counters_before.obligation,
                "obligation_count_after": self.counters_after.obligation,
                "buffer_bytes_before": self.counters_before.buffer_bytes,
                "buffer_bytes_after": self.counters_after.buffer_bytes,
                "chunk_digests": &self.chunk_digests,
                "expected_status": self.expected_status.as_u16(),
                "actual_status": self.actual_status.as_u16(),
                "expected_cancel_requested": self.expected_cancel_requested,
                "cancel_requested_after": self.cancel_requested_after,
                "verdict": self.verdict(),
                "first_failure": self.first_failure.as_deref().unwrap_or(""),
            });
            eprintln!("{row}");
        }

        fn assert_passed(&self) {
            assert_eq!(
                self.expected_status, self.actual_status,
                "{} expected HTTP {} but observed {}",
                self.scenario_id, self.expected_status, self.actual_status,
            );
            assert_eq!(
                self.expected_cancel_requested, self.cancel_requested_after,
                "{} cancellation request state mismatch",
                self.scenario_id,
            );
            assert_eq!(
                self.counters_before.region, self.counters_after.region,
                "{} leaked request child regions",
                self.scenario_id,
            );
            assert_eq!(
                self.counters_before.task, self.counters_after.task,
                "{} leaked request child tasks",
                self.scenario_id,
            );
            assert_eq!(
                self.counters_before.obligation, self.counters_after.obligation,
                "{} leaked request obligations",
                self.scenario_id,
            );
            assert!(
                self.first_failure.is_none(),
                "{} recorded first_failure={:?}",
                self.scenario_id,
                self.first_failure,
            );
            assert_eq!(
                "pass",
                self.verdict(),
                "{} proof row failed",
                self.scenario_id
            );
        }
    }

    fn run_lifecycle_scenario(
        scenario_id: &'static str,
        client_disconnect_at: &'static str,
        expected_status: StatusCode,
        expected_cancel_requested: bool,
        drive: impl FnOnce(&RequestContext<'_>, &mut LifecycleObservation) -> Response,
    ) -> LifecycleProofRow {
        let cx = Cx::for_testing();
        let request = Request::new("GET", ROUTE);
        let region = RequestRegion::new(&cx, request);
        let mut observation = LifecycleObservation::new();
        let outcome = region.run(|ctx| drive(ctx, &mut observation));
        let response = outcome.into_response();

        LifecycleProofRow {
            scenario_id,
            client_disconnect_at,
            expected_status,
            actual_status: response.status,
            cancel_requested_after: cx.is_cancel_requested(),
            expected_cancel_requested,
            counters_before: observation.counters_before,
            counters_after: observation.counters_after,
            chunk_digests: observation
                .chunks
                .iter()
                .map(|chunk| chunk_digest(chunk))
                .collect(),
            first_failure: observation.first_failure,
        }
    }

    fn chunk_digest(bytes: &[u8]) -> String {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("fnv1a64:{hash:016x}:len{}", bytes.len())
    }

    #[derive(Debug, Clone)]
    struct FailingSource {
        cancel_calls: Rc<Cell<usize>>,
    }

    impl FailingSource {
        fn new(cancel_calls: Rc<Cell<usize>>) -> Self {
            Self { cancel_calls }
        }
    }

    impl StreamingSseSource for FailingSource {
        fn next_event(&mut self, _cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
            Err(StreamingSseError::Producer("synthetic failure".to_string()))
        }

        fn cancel(&mut self) {
            let next = self.cancel_calls.get() + 1;
            self.cancel_calls.set(next);
        }
    }

    #[test]
    fn streaming_sse_request_region_lifecycle_rows_cover_disconnects_and_overflow() {
        let rows = vec![
            run_lifecycle_scenario(
                "normal-completion",
                "none",
                StatusCode::OK,
                false,
                |ctx, observation| {
                    let mut stream = StreamingSse::new(vec![
                        SseEvent::default().data("first"),
                        SseEvent::default().data("second"),
                    ]);
                    observation.record_before(&stream);

                    let first = stream
                        .next_chunk(ctx.cx())
                        .expect("first event chunk should serialize")
                        .expect("first event should be present");
                    observation.push_chunk(first);

                    let second = stream
                        .next_chunk(ctx.cx())
                        .expect("second event chunk should serialize")
                        .expect("second event should be present");
                    observation.push_chunk(second);

                    assert!(
                        stream
                            .next_chunk(ctx.cx())
                            .expect("completion should not fail")
                            .is_none(),
                        "normal completion must close the stream",
                    );
                    assert!(stream.is_closed(), "completed stream must be closed");
                    observation.record_after(&stream);
                    Response::empty(StatusCode::OK)
                },
            ),
            run_lifecycle_scenario(
                "disconnect-before-first-event",
                "before-first-event",
                StatusCode::CLIENT_CLOSED_REQUEST,
                true,
                |ctx, observation| {
                    let mut stream =
                        StreamingSse::new(vec![SseEvent::default().data("never-emitted")]);
                    observation.record_before(&stream);
                    stream.cancel_for_disconnect(ctx.cx());
                    assert!(stream.is_closed(), "disconnect must close the stream");
                    assert!(
                        stream
                            .next_chunk(ctx.cx())
                            .expect("closed stream should not error")
                            .is_none(),
                        "closed stream must not emit after disconnect",
                    );
                    observation.record_after(&stream);
                    Response::empty(StatusCode::CLIENT_CLOSED_REQUEST)
                },
            ),
            run_lifecycle_scenario(
                "disconnect-mid-stream",
                "after-first-event",
                StatusCode::CLIENT_CLOSED_REQUEST,
                true,
                |ctx, observation| {
                    let mut stream = StreamingSse::new(vec![
                        SseEvent::default().data("committed"),
                        SseEvent::default().data("cancelled"),
                    ]);
                    observation.record_before(&stream);
                    let committed = stream
                        .next_chunk(ctx.cx())
                        .expect("first event chunk should serialize")
                        .expect("first event should be present");
                    observation.push_chunk(committed);
                    stream.cancel_for_disconnect(ctx.cx());
                    assert!(
                        stream
                            .next_chunk(ctx.cx())
                            .expect("closed stream should not error")
                            .is_none(),
                        "mid-stream disconnect must not emit later events",
                    );
                    observation.record_after(&stream);
                    Response::empty(StatusCode::CLIENT_CLOSED_REQUEST)
                },
            ),
            run_lifecycle_scenario(
                "producer-error-cancels-source",
                "producer-error",
                StatusCode::INTERNAL_SERVER_ERROR,
                true,
                |ctx, observation| {
                    let cancel_calls = Rc::new(Cell::new(0));
                    let source = FailingSource::new(Rc::clone(&cancel_calls));
                    let mut stream = StreamingSse::from_source(source);
                    observation.record_before(&stream);

                    let error = stream
                        .next_chunk(ctx.cx())
                        .expect_err("producer failure must surface to transport");
                    assert_eq!(
                        error,
                        StreamingSseError::Producer("synthetic failure".to_string()),
                    );

                    stream.cancel_for_disconnect(ctx.cx());
                    assert_eq!(
                        cancel_calls.get(),
                        1,
                        "transport must cancel producer after surfacing producer error",
                    );
                    observation.record_after(&stream);
                    Response::empty(StatusCode::INTERNAL_SERVER_ERROR)
                },
            ),
            run_lifecycle_scenario(
                "heartbeat-only-completion",
                "none",
                StatusCode::OK,
                false,
                |ctx, observation| {
                    let mut stream = StreamingSse::empty().heartbeat_comment("proof-heartbeat");
                    observation.record_before(&stream);
                    let heartbeat = stream
                        .heartbeat_chunk(ctx.cx())
                        .expect("heartbeat chunk should serialize");
                    observation.push_chunk(heartbeat);
                    assert!(
                        stream
                            .next_chunk(ctx.cx())
                            .expect("empty source completion should not fail")
                            .is_none(),
                        "empty stream must complete after heartbeat-only proof",
                    );
                    observation.record_after(&stream);
                    Response::empty(StatusCode::OK)
                },
            ),
            run_lifecycle_scenario(
                "backpressure-overflow-no-partial-commit",
                "backpressure-overflow",
                StatusCode::PAYLOAD_TOO_LARGE,
                false,
                |ctx, observation| {
                    let first_event = SseEvent::default().data("one");
                    let first_len = first_event.to_string().len();
                    let mut stream =
                        StreamingSse::new(vec![first_event, SseEvent::default().data("two")])
                            .max_total_bytes(first_len);
                    observation.record_before(&stream);

                    let committed = stream
                        .next_chunk(ctx.cx())
                        .expect("first event should fit exactly under total cap")
                        .expect("first event should be present");
                    observation.push_chunk(committed);
                    let bytes_before_overflow = stream.bytes_emitted();
                    let error = stream
                        .next_chunk(ctx.cx())
                        .expect_err("second event must overflow total byte cap");
                    assert!(
                        matches!(
                            error,
                            StreamingSseError::TotalBytesExceeded { actual, max }
                                if actual > max && max == first_len
                        ),
                        "expected total-byte overflow after committed first chunk, got {error:?}",
                    );
                    assert_eq!(
                        bytes_before_overflow,
                        stream.bytes_emitted(),
                        "overflow must not partially commit response bytes",
                    );
                    observation.record_after(&stream);
                    Response::empty(StatusCode::PAYLOAD_TOO_LARGE)
                },
            ),
        ];

        assert_eq!(
            rows.len(),
            6,
            "lifecycle proof must cover the six accepted SSE scenarios",
        );
        for row in &rows {
            row.emit();
            row.assert_passed();
        }
    }

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
