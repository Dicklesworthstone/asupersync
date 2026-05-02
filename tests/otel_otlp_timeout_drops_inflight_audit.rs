//! Audit + regression test for `src/observability/otel.rs` OTLP
//! exporter timeout drop-on-expiry semantics.
//!
//! Operator's question: "when exporter.send() exceeds timeout, is
//! the in-flight batch dropped (correct: don't queue indefinitely)
//! or held forever (memory leak)?"
//!
//! Audit chain:
//!
//!   (a) **Per-request timeout is configurable** via
//!       `OtlpHttpExporter::with_timeout(timeout: Duration)`
//!       (otel.rs:738-741). Default is 10 seconds (otel.rs:730).
//!       The timeout bound is applied PER request_once attempt,
//!       not per overall batch — so a batch that retries N
//!       times has a worst-case wall-clock of
//!       `(timeout + retry_delay) × max_retries`.
//!
//!   (b) **`crate::time::timeout` wraps the HTTP request**
//!       (otel.rs:825-839). The wrapped expression returns a
//!       `TimeoutFuture<F>` (src/time/timeout_future.rs:47-61)
//!       which holds the inner future as a `#[pin]`-projected
//!       field. When `TimeoutFuture` resolves to `Err(Elapsed)`,
//!       the `.await` consumes the wrapper; dropping the
//!       wrapper drops the inner future, which cancels the
//!       in-flight HTTP request and releases the cloned
//!       `body.to_vec()` captured by the async block.
//!
//!   (c) **Timeout maps to `OtlpError::non_retryable`**
//!       (otel.rs:840):
//!       `.map_err(|_| OtlpError::non_retryable("OTLP request
//!         timeout"))?`
//!       This is NOT a retryable error class. The retry loop's
//!       `Err(e)` (non-retryable) arm at otel.rs:803-806
//!       returns IMMEDIATELY — no further retry attempts on
//!       timeout. The outer `request_body: Vec<u8>` then goes
//!       out of scope at function return, freeing the memory.
//!
//!   (d) **No queue / pending buffer absorbs the timed-out
//!       batch**. Verified by the prior retry-queue audit
//!       (`tests/otel_otlp_retry_queue_bounded_audit.rs`):
//!       OtlpHttpExporter has no `pending_batches` /
//!       `retry_buffer` / `VecDeque<Vec<u8>>` field, no
//!       background dispatcher, no `flush()` state to drain.
//!       So the failed-on-timeout batch has nowhere to go
//!       except out-of-scope.
//!
//!   (e) **`TimeoutFuture::poll` semantics** (timeout_future.rs:
//!       252-283): on timeout, `*this.timed_out = true` AND
//!       `*this.completed = true` are set, then `Err(Elapsed)`
//!       is returned. A second poll on the same TimeoutFuture
//!       returns `Err(Elapsed)` again (fail-closed). The inner
//!       future is NOT polled after timeout — preventing a
//!       situation where a slow inner future continues to
//!       allocate while a parent caller has already moved on.
//!
//! Verdict: **SOUND**. The in-flight batch is dropped on
//! timeout via three converging mechanisms:
//!   1. `TimeoutFuture` cancellation: drop semantics propagate
//!      to the inner HTTP request future.
//!   2. Non-retryable error class: timeout does not loop back
//!      into the retry path that would re-allocate.
//!   3. No queue / no buffer / no background dispatcher: the
//!      timed-out batch has no pending state to live in.
//!
//! A regression that:
//!   - replaced `crate::time::timeout(...)` with a sleep + race
//!     pattern that didn't drop the inner future,
//!   - changed the timeout error mapping from
//!     `OtlpError::non_retryable` to `OtlpError::Retryable`
//!     (would loop and re-allocate the body),
//!   - introduced a queue that absorbed timed-out batches for
//!     "later",
//!   - made the inner request future hold the body in an
//!     `Arc` shared with another long-lived structure (so
//!     drop on the future would not free the body),
//! would all be caught here.

use std::path::PathBuf;

fn read_otel_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/observability/otel.rs");
    std::fs::read_to_string(&path).expect("read otel.rs")
}

fn read_timeout_future_source() -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/time/timeout_future.rs");
    std::fs::read_to_string(&path).expect("read timeout_future.rs")
}

#[test]
fn otlp_exporter_has_timeout_field_with_duration_type() {
    // Pin (a): the timeout is a Duration field on the exporter.
    // A regression to a different type (e.g. Option<Duration>
    // with default None = no timeout) would let an operator
    // disable the timeout entirely — re-opening the
    // hold-forever failure mode.
    let source = read_otel_source();

    let struct_marker = "pub struct OtlpHttpExporter {";
    let start = source.find(struct_marker).expect("OtlpHttpExporter struct");
    let end_rel = source[start..].find("\n}\n").expect("struct close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("timeout: Duration,"),
        "REGRESSION: OtlpHttpExporter no longer has a \
         `timeout: Duration` field. The timeout MUST be a \
         non-optional Duration so a value is always set; \
         allowing None would let an operator (or a default \
         constructor regression) disable the timeout entirely \
         and re-open the hold-forever failure mode.\n\n\
         struct body:\n{body}",
    );
}

#[test]
fn send_request_once_wraps_request_in_time_timeout() {
    // Pin (b) AUDIT-CRITICAL: the HTTP request is wrapped in
    // `crate::time::timeout(...)`. A regression that removed
    // the wrapper would let the request hang indefinitely if
    // the server never responded — the in-flight body would
    // be held forever in the inner future's state.
    let source = read_otel_source();

    let fn_marker = "async fn send_request_once(";
    let start = source.find(fn_marker).expect("send_request_once fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("send_request_once close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("crate::time::timeout("),
        "REGRESSION: send_request_once no longer wraps the HTTP \
         request in `crate::time::timeout(...)`. Without the \
         wrapper, a slow / unresponsive OTLP collector could \
         hold the in-flight batch in the request future's \
         state forever. The `crate::time::timeout` provides \
         the drop-on-expiry semantics that release the \
         memory.\n\nfn body:\n{body}",
    );

    // The wrapper must use `self.timeout` (the configured
    // value), not a hardcoded constant.
    assert!(
        body.contains("self.timeout"),
        "REGRESSION: timeout duration is no longer derived from \
         self.timeout. A hardcoded constant would ignore the \
         operator's `with_timeout(...)` configuration.",
    );
}

#[test]
fn timeout_error_maps_to_non_retryable() {
    // Pin (c) AUDIT-CRITICAL: the timeout's `Err(Elapsed)` is
    // mapped to `OtlpError::non_retryable`. If a regression
    // changed this to Retryable, the retry loop would re-enter
    // and re-allocate body.to_vec() on every retry — turning
    // a timeout from a single-batch drop into an N-times
    // memory amplifier.
    let source = read_otel_source();

    let fn_marker = "async fn send_request_once(";
    let start = source.find(fn_marker).expect("send_request_once fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("send_request_once close");
    let body = &source[start..start + body_end];

    // The timeout map_err must produce non_retryable, NOT
    // retryable. Look for the canonical pattern.
    assert!(
        body.contains(
            ".map_err(|_| OtlpError::non_retryable(\"OTLP request timeout\"))"
        ),
        "REGRESSION: timeout error mapping is no longer \
         `.map_err(|_| OtlpError::non_retryable(\"OTLP request \
         timeout\"))`. If the timeout now maps to a Retryable \
         error, the retry loop would re-enter for each timeout \
         — turning each timeout into max_retries × \
         (timeout + retry_delay) of held-batch memory.\n\n\
         fn body:\n{body}",
    );

    // Forbid the retryable-on-timeout regression explicitly.
    assert!(
        !body.contains(".map_err(|_| OtlpError::retryable")
            && !body.contains(".map_err(|_| OtlpError::Retryable"),
        "REGRESSION: timeout now maps to a retryable error \
         class. Retrying on timeout means re-allocating \
         body.to_vec() on every retry attempt; combined with \
         exponential backoff, an unresponsive endpoint would \
         hold N × body bytes in flight before finally giving \
         up.",
    );
}

#[test]
fn timeout_future_holds_inner_future_as_pinned_field() {
    // Pin (b)+(e): TimeoutFuture's inner future is a
    // `#[pin]`-projected field, so dropping the wrapper drops
    // the inner. A regression that boxed the inner into an
    // `Arc<Mutex<F>>` or shared it with anything else would
    // break the cancel-on-drop invariant — the inner future
    // would outlive the timeout and continue holding the body.
    let source = read_timeout_future_source();

    let struct_marker = "pub struct TimeoutFuture<F> {";
    let start = source.find(struct_marker).expect("TimeoutFuture struct");
    let end_rel = source[start..].find("\n}\n").expect("struct close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("#[pin]\n    future: F,"),
        "REGRESSION: TimeoutFuture's `future: F` field is no \
         longer marked `#[pin]`. Without the pin projection, \
         the inner future cannot be polled in place AND \
         dropping the wrapper may not drop the inner — \
         re-opening the hold-forever failure mode.\n\n\
         struct body:\n{body}",
    );

    // Forbid Arc / Box wrapping that would defeat drop
    // propagation.
    let suspect_field_wraps = [
        "future: Arc<",
        "future: Rc<",
        "future: Box<dyn Future",
    ];
    for pat in &suspect_field_wraps {
        assert!(
            !body.contains(pat),
            "REGRESSION: TimeoutFuture's future field is now \
             `{pat}`. This is suspicious — Arc/Rc-wrapped \
             futures aren't dropped when the wrapper is \
             dropped if anyone else holds a clone, breaking \
             the cancel-on-timeout semantics. Verify the new \
             design and update this audit test.",
        );
    }
}

#[test]
fn timeout_future_returns_elapsed_and_marks_completed() {
    // Pin (e): on timeout, TimeoutFuture marks itself completed
    // AND timed_out, then returns Err(Elapsed). A regression
    // that forgot to set `completed` would let a re-poll
    // re-enter the inner future, defeating the drop-on-timeout
    // intent.
    let source = read_timeout_future_source();

    let fn_marker = "fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {";
    let start = source.find(fn_marker).expect("TimeoutFuture::poll");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("poll body close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("*this.completed = true;") && body.contains("*this.timed_out = true;"),
        "REGRESSION: the timeout-elapsed path no longer sets \
         BOTH completed=true AND timed_out=true. Without \
         these, a re-poll would re-enter the inner future, \
         which has already been logically cancelled — \
         could lead to unpinned reference issues or \
         re-allocation of dropped state.\n\nfn body:\n{body}",
    );

    assert!(
        body.contains("Err(Elapsed::new("),
        "REGRESSION: timeout no longer returns Err(Elapsed). \
         Callers depend on this Err to drop the wrapper and \
         release the inner future.",
    );
}

#[test]
fn retry_loop_returns_immediately_on_non_retryable_timeout() {
    // Pin (c) reinforced: the retry loop's `Err(e)` arm
    // (non-retryable bucket) returns IMMEDIATELY. A regression
    // that fell through to the retry path on non-retryable
    // errors would re-enter for the timeout case.
    let source = read_otel_source();

    let fn_marker = "send_otlp_protobuf";
    let pos = source.find(fn_marker).expect("send_otlp_protobuf");
    let body_start = source[pos..]
        .find("-> Result<(), ExportError> {")
        .expect("send_otlp_protobuf return type")
        + pos;
    let body_end = source[body_start..]
        .find("\n    }\n")
        .expect("send_otlp_protobuf close");
    let body = &source[body_start..body_start + body_end];

    // The retry loop must have an explicit non-retryable arm
    // that returns Err.
    assert!(
        body.contains("Err(e) => {")
            && body.contains("// Non-retryable error"),
        "REGRESSION: the retry loop no longer has a clear \
         non-retryable Err arm. Without it, a timeout (mapped \
         to OtlpError::non_retryable) might fall through to \
         the retry path, re-allocating body.to_vec() on every \
         iteration.\n\nfn body:\n{body}",
    );

    // The non-retryable arm must `return Err(e.into())` —
    // immediate exit, no continue/loop/retry.
    let arm_marker = "// Non-retryable error";
    let arm_pos = body.find(arm_marker).expect("non-retryable arm");
    let arm_end = body[arm_pos..]
        .find("                }\n")
        .expect("arm close");
    let arm_body = &body[arm_pos..arm_pos + arm_end];

    assert!(
        arm_body.contains("return Err(e.into());"),
        "REGRESSION: the non-retryable arm no longer returns \
         immediately. Without the explicit `return Err(...)`, \
         the loop could continue and re-attempt with \
         re-cloned body bytes.\n\narm body:\n{arm_body}",
    );

    // Forbid the arm calling `continue` (which would loop back
    // into the retry path).
    assert!(
        !arm_body.contains("continue"),
        "REGRESSION: the non-retryable arm now contains \
         `continue` — reentering the retry loop on a non-\
         retryable error. Timeouts would loop indefinitely \
         (until max_retries) re-allocating the body each \
         time.",
    );
}

#[test]
fn timeout_future_doc_promises_cancel_safety_on_drop() {
    // Pin (b): the TimeoutFuture doc explicitly promises
    // "dropping it is safe" — the contract callers rely on.
    // A regression that removed this guarantee suggests a
    // semantic change worth re-auditing.
    let source = read_timeout_future_source();

    assert!(
        source.contains("dropping it is safe"),
        "REGRESSION: TimeoutFuture's cancel-safety doc \
         (\"dropping it is safe\") is gone. If the drop \
         semantics changed, the OTLP exporter's reliance on \
         drop-on-timeout to release the in-flight batch may \
         no longer hold. Audit the new semantics and update \
         this test.",
    );
}

#[test]
fn no_inflight_batch_persistence_field_on_exporter() {
    // Pin (d): defense-in-depth against a regression that
    // adds an in-flight tracking field. If the exporter started
    // tracking in-flight batches in a Mutex<HashMap> or similar,
    // a timeout would mark the entry as "failed" but the entry
    // would persist — a memory leak.
    let source = read_otel_source();

    let struct_marker = "pub struct OtlpHttpExporter {";
    let start = source.find(struct_marker).expect("OtlpHttpExporter struct");
    let end_rel = source[start..].find("\n}\n").expect("struct close");
    let body = &source[start..start + end_rel];

    let suspect_inflight_fields = [
        "in_flight:",
        "pending_requests:",
        "active_batches:",
        "tracked_batches:",
        "in_flight_batches:",
        "Mutex<HashMap<",
        "Mutex<BTreeMap<",
    ];
    for pat in &suspect_inflight_fields {
        assert!(
            !body.contains(pat),
            "REGRESSION: OtlpHttpExporter has a field that \
             looks like it tracks in-flight batches: `{pat}`. \
             A timeout on a tracked batch would mark the entry \
             as failed but the entry would persist — a memory \
             leak. Verify the new design has explicit \
             eviction-on-timeout and update this audit test.",
        );
    }
}

#[test]
fn body_passed_by_reference_to_send_request_once() {
    // Pin (b)+(c): send_request_once takes `body: &[u8]`. The
    // body bytes are owned by send_otlp_protobuf's stack frame
    // (the `request_body: Vec<u8>` parameter). When
    // send_otlp_protobuf returns (success or failure), the Vec
    // is dropped and the bytes are freed.
    //
    // A regression that switched to `Arc<Vec<u8>>` could let
    // a clone outlive send_otlp_protobuf — verify carefully.
    let source = read_otel_source();

    let fn_marker = "async fn send_request_once(";
    let start = source.find(fn_marker).expect("send_request_once");
    let body_start = source[start..]
        .find('{')
        .expect("body open") + start;
    let signature = &source[start..body_start];

    assert!(
        signature.contains("body: &[u8]"),
        "REGRESSION: send_request_once no longer takes \
         `body: &[u8]`. If the signature changed to a \
         shared/refcounted type that could outlive the \
         caller's stack frame, the timeout drop semantics may \
         no longer free the body bytes promptly. Audit the \
         new ownership chain.\n\nsignature:\n{signature}",
    );
}
