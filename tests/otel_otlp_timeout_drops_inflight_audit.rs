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
//!       `OtlpHttpExporter::with_timeout(timeout: Duration)`.
//!       Default is 10 seconds in `OtlpHttpExporter::new`.
//!       The timeout bound is applied per request attempt. Retryable HTTP
//!       responses can still consume the configured retry delays, but a request
//!       that reaches this timeout exits immediately because expiry is
//!       classified as non-retryable.
//!
//!   (b) **`drive_otlp_request_with_timeout` owns and pins the HTTP request**
//!       inside `send_request_with_compression`. The helper uses the caller's
//!       `Cx` timer driver, polls the request before its deadline sleeper, and
//!       keeps both futures on its own stack. When it returns on timeout or
//!       cancellation, dropping that stack frame drops the pinned HTTP request
//!       and releases the cloned `body.to_vec()` captured by the async block.
//!
//!   (c) **Timeout maps to `OtlpError::non_retryable`**
//!       Timeout errors map to:
//!       `Err(OtlpError::non_retryable("OTLP request timeout"))`
//!       This is NOT a retryable error class. The retry loop's
//!       `Err(e)` (non-retryable) arm in `send_otlp_protobuf`
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
//!   (e) **The helper is cancellation-aware and boundary-correct**: it refreshes
//!       a cancellation waker, checks `cx.checkpoint()` on every poll, polls the
//!       request before the sleeper so completed work wins at the exact deadline,
//!       and clears the registered waker before returning.
//!
//! Verdict: **SOUND**. The in-flight batch is dropped on
//! timeout via three converging mechanisms:
//!   1. Stack-owned future cancellation: returning from the `Cx`-driven helper
//!      drops the pinned inner HTTP request future.
//!   2. Non-retryable error class: timeout does not loop back
//!      into the retry path that would re-allocate.
//!   3. No queue / no buffer / no background dispatcher: the
//!      timed-out batch has no pending state to live in.
//!
//! A regression that:
//!   - detached the request from the stack-owned `Cx`-driven timeout helper,
//!   - changed the timeout error mapping from
//!     `OtlpError::non_retryable` to `OtlpError::Retryable`
//!     (would loop and re-allocate the body),
//!   - introduced a queue that absorbed timed-out batches for
//!     "later",
//!   - made the inner request future hold the body in an
//!     `Arc` shared with another long-lived structure (so
//!     drop on the future would not free the body),
//!     would all be caught here.

use std::path::PathBuf;

fn read_otel_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/observability/otel.rs");
    std::fs::read_to_string(&path).expect("read otel.rs")
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
fn send_request_with_compression_uses_cx_driven_timeout() {
    // Pin (b) AUDIT-CRITICAL: the HTTP request is owned by the
    // caller-capability-aware timeout helper. A regression that removed this
    // wrapper would let the request hang indefinitely and would also put
    // deterministic runtimes on the wrong clock.
    let source = read_otel_source();

    let fn_marker = "async fn send_request_with_compression(";
    let start = source
        .find(fn_marker)
        .expect("send_request_with_compression fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("send_request_with_compression close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("drive_otlp_request_with_timeout(cx, self.timeout, async {"),
        "REGRESSION: send_request_with_compression no longer routes the HTTP \
         request through `drive_otlp_request_with_timeout(cx, self.timeout, ...)`. \
         The helper is the cancellation, timer-capability, and drop-on-expiry \
         boundary for the in-flight request body.\n\nfn body:\n{body}",
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
fn timeout_helper_returns_non_retryable_timeout() {
    // Pin (c) AUDIT-CRITICAL: deadline expiry is returned as
    // `OtlpError::non_retryable`. If a regression
    // changed this to Retryable, the retry loop would re-enter
    // and re-allocate body.to_vec() on every retry — turning
    // a timeout from a single-batch drop into an N-times
    // memory amplifier.
    let source = read_otel_source();

    let fn_marker = "async fn drive_otlp_request_with_timeout<F>(";
    let start = source
        .find(fn_marker)
        .expect("drive_otlp_request_with_timeout fn");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("drive_otlp_request_with_timeout close");
    let body = &source[start..start + body_end];

    // The timeout map_err must produce non_retryable, NOT
    // retryable. Look for the canonical pattern.
    assert!(
        body.contains("Poll::Ready(Err(OtlpError::non_retryable(\"OTLP request timeout\")))"),
        "REGRESSION: the Cx-driven timeout helper no longer returns the canonical \
         non-retryable OTLP timeout. If the timeout now maps to a Retryable \
         error, the retry loop would re-enter for each timeout \
         — turning each timeout into max_retries × \
         (timeout + retry_delay) of held-batch memory.\n\n\
         fn body:\n{body}",
    );

    // Forbid the retryable-on-timeout regression explicitly.
    assert!(
        !body.contains("OtlpError::retryable") && !body.contains("OtlpError::Retryable"),
        "REGRESSION: timeout now maps to a retryable error \
         class. Retrying on timeout means re-allocating \
         body.to_vec() on every retry attempt; combined with \
         exponential backoff, an unresponsive endpoint would \
         hold N × body bytes in flight before finally giving \
         up.",
    );
}

#[test]
fn otlp_timeout_helper_pins_the_request_on_its_stack() {
    let source = read_otel_source();
    let start = source
        .find("async fn drive_otlp_request_with_timeout<F>(")
        .expect("drive_otlp_request_with_timeout fn");
    let end = source[start..]
        .find("\n}\n")
        .expect("drive_otlp_request_with_timeout close");
    let body = &source[start..start + end];

    assert!(
        body.contains("let mut future = pin!(future);")
            && body.contains("let mut sleeper =")
            && body.contains("future.as_mut().poll(task_cx)"),
        "REGRESSION: the OTLP timeout helper must own and pin both the request \
         future and deadline sleeper so returning drops the in-flight request.\n\n\
         helper body:\n{body}",
    );
}

#[test]
fn otlp_timeout_helper_checks_cancellation_and_clears_its_waker() {
    let source = read_otel_source();
    let start = source
        .find("async fn drive_otlp_request_with_timeout<F>(")
        .expect("drive_otlp_request_with_timeout fn");
    let end = source[start..]
        .find("\n}\n")
        .expect("drive_otlp_request_with_timeout close");
    let body = &source[start..start + end];

    assert!(
        body.contains("cancel_waker.refresh(task_cx.waker());")
            && body.matches("cx.checkpoint().is_err()").count() >= 2
            && body.contains("cancel_waker.clear();"),
        "REGRESSION: OTLP timeout/cancellation must register a wake path, check \
         cancellation before work and at the deadline boundary, and unlink the \
         waker before returning.\n\nhelper body:\n{body}",
    );
}

#[test]
fn retry_loop_returns_immediately_on_non_retryable_timeout() {
    // Pin (c) reinforced: the retry loop's `Err(e)` arm
    // (non-retryable bucket) returns IMMEDIATELY. A regression
    // that fell through to the retry path on non-retryable
    // errors would re-enter for the timeout case.
    let source = read_otel_source();

    let impl_marker = "impl OtlpHttpExporter {";
    let impl_start = source.find(impl_marker).expect("OtlpHttpExporter impl");
    let fn_marker = "pub async fn send_otlp_protobuf(";
    let pos = source[impl_start..]
        .find(fn_marker)
        .map(|offset| impl_start + offset)
        .expect("OtlpHttpExporter::send_otlp_protobuf");
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
        body.contains("Err(e) => {") && body.contains("// Non-retryable error"),
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
fn otlp_timeout_helper_uses_the_cx_timer_driver() {
    let source = read_otel_source();
    let start = source
        .find("async fn drive_otlp_request_with_timeout<F>(")
        .expect("drive_otlp_request_with_timeout fn");
    let end = source[start..]
        .find("\n}\n")
        .expect("drive_otlp_request_with_timeout close");
    let body = &source[start..start + end];

    assert!(
        body.contains("let timer_driver = cx.timer_driver();")
            && body.contains("crate::time::Sleep::with_timer_driver(deadline, timer_driver)"),
        "REGRESSION: the OTLP request timeout must use the caller's timer \
         capability when present; an ambient clock would diverge under \
         deterministic runtimes.\n\nhelper body:\n{body}",
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
    let body_start = source[start..].find('{').expect("body open") + start;
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
