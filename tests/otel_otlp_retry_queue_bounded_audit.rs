//! Audit + regression test for `src/observability/otel.rs` OTLP
//! exporter retry-queue memory boundedness.
//!
//! Operator's question: "when retries exceed configured
//! max-retries, are old batches dropped (correct: bounded memory)
//! or accumulated forever (memory leak)?"
//!
//! Audit findings:
//!
//!   (a) **There is NO retry QUEUE in the OTLP exporter.** The
//!       retry logic in `OtlpHttpExporter::send_otlp_protobuf`
//!       (otel.rs:758-809) is INLINE: a single async function
//!       call drives the retry loop with stack-local
//!       `retry_count` and `current_delay`. There is no
//!       background dispatcher, no shared queue between
//!       caller invocations, no per-batch state held across
//!       calls.
//!
//!   (b) **`max_retries: u32` is the hard cap on iterations.**
//!       The retry loop checks `if retry_count >= self.max_retries`
//!       and IMMEDIATELY returns `Err(ExportError)` on
//!       exhaustion. There is no fall-through to a "retry
//!       later" buffer. The failed batch (the `request_body:
//!       Vec<u8>` argument) goes out of scope when
//!       `send_otlp_protobuf` returns, freeing the memory.
//!
//!   (c) **Single in-flight batch per call**. The
//!       `request_body: Vec<u8>` is passed by value into
//!       `send_otlp_protobuf`; only one copy lives at any
//!       moment. After return (success OR failure), the
//!       Vec is dropped.
//!
//!   (d) **MetricsExporter::export sync API for OTLP returns
//!       an error**: the sync trait method (otel.rs:883-893)
//!       explicitly returns `Err("OTLP HTTP export requires
//!       async context - use send_otlp_protobuf() directly")`.
//!       So there is no sync queue / batch buffer either —
//!       the only entry point is the async `send_otlp_protobuf`,
//!       which is bounded as described above.
//!
//!   (e) **`flush()` is a no-op** (otel.rs:890-893): "OTLP is
//!       stateless — nothing to flush". A regression that
//!       introduced a queue requiring `flush()` to drain it
//!       would change the doc comment.
//!
//! Verdict: **SOUND**. The operator's failure mode (batches
//! accumulating forever) is STRUCTURALLY IMPOSSIBLE because no
//! queue exists. Memory is bounded by:
//!   - `max_retries: u32` caps loop iterations,
//!   - the single `request_body: Vec<u8>` in flight per call
//!     (drops on return),
//!   - the absence of any background queue, retry-buffer, or
//!     per-batch state held across `send_otlp_protobuf` calls.
//!
//! When the producer of batches calls `send_otlp_protobuf` and
//! it returns Err, the caller decides what to do — typically
//! log and move on. No batch ever stays "pending" inside the
//! exporter.
//!
//! A regression that:
//!   - introduced a `pending_batches: VecDeque<Vec<u8>>` field
//!     on `OtlpHttpExporter` for "retry later" buffering,
//!   - added a background task / dispatcher loop that pulled
//!     from a queue,
//!   - changed `max_retries` to `u64` or `usize` and removed
//!     the bound,
//!   - made `flush()` non-trivial (suggesting state to drain),
//!   - changed the loop's exhaustion path from immediate Err
//!     to a fall-through that pushed the batch onto a queue,
//! would all be caught here.

use std::path::PathBuf;

fn read_otel_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/observability/otel.rs");
    std::fs::read_to_string(&path).expect("read otel.rs")
}

fn otlp_struct_body(source: &str) -> &str {
    let marker = "pub struct OtlpHttpExporter {";
    let start = source
        .find(marker)
        .expect("OtlpHttpExporter struct must exist");
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("OtlpHttpExporter struct must close");
    &source[start..start + end_rel]
}

fn send_otlp_protobuf_body(source: &str) -> &str {
    // Look for the `send_otlp_protobuf` async fn body.
    let marker = "send_otlp_protobuf";
    let mut pos = source.find(marker).expect("send_otlp_protobuf must exist");
    // Find the `{` opening the body. It may be on a different
    // line than the marker (multi-line signature).
    let body_start = source[pos..]
        .find("-> Result<(), ExportError> {")
        .expect("send_otlp_protobuf return type")
        + pos;
    pos = body_start;
    // Find the matching closing brace (a function body of the
    // form ` async fn send_otlp_protobuf(...) -> ... { ... }`
    // ends at the next `\n    }\n` at the impl-block indent).
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("send_otlp_protobuf body close");
    &source[pos..pos + body_end]
}

#[test]
fn otlp_exporter_has_no_retry_queue_field() {
    // Pin (a): the OtlpHttpExporter struct has NO field that
    // looks like a retry queue (VecDeque<Vec<u8>>, Vec of
    // pending batches, Mutex<Queue>). All retry state is
    // stack-local in send_otlp_protobuf.
    let source = read_otel_source();
    let body = otlp_struct_body(&source);

    let suspect_field_patterns = [
        "VecDeque<Vec<u8>",
        "VecDeque<Bytes>",
        "pending_batches:",
        "pending_retries:",
        "retry_queue:",
        "retry_buffer:",
        "batch_queue:",
        "pending: Mutex<Vec<",
    ];
    for pat in &suspect_field_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: OtlpHttpExporter has a field that looks \
             like a retry queue: `{pat}`. The audit invariant \
             relies on inline retry semantics (no accumulation). \
             If a queue was genuinely needed (e.g., for write-\
             ahead-on-disk), it MUST be bounded with explicit \
             eviction-on-overflow and the audit test must be \
             updated to verify the cap.\n\nstruct body:\n{body}",
        );
    }
}

#[test]
fn otlp_max_retries_field_is_u32() {
    // Pin (b): `max_retries: u32` provides the hard cap on
    // retry iterations. A regression to `u64` / `usize` would
    // implicitly weaken the bound (and on 64-bit could allow
    // 2^64 retries before saturation), but more importantly a
    // type change suggests a behavioral rework worth re-
    // auditing.
    let source = read_otel_source();
    let body = otlp_struct_body(&source);

    assert!(
        body.contains("max_retries: u32,"),
        "REGRESSION: max_retries field is no longer u32. The \
         audit invariant assumes u32 is the cap; if the type \
         changed, verify the new semantics still bound the \
         retry loop and update this test.\n\nstruct body:\n{body}",
    );
}

#[test]
fn send_otlp_protobuf_loop_returns_err_on_max_retries_exhaustion() {
    // Pin (b) AUDIT-CRITICAL: when retry_count >= max_retries,
    // the function MUST return Err immediately. A regression
    // that fell through to a "queue for later" path would
    // re-open the accumulation failure mode.
    let source = read_otel_source();
    let body = send_otlp_protobuf_body(&source);

    assert!(
        body.contains("if retry_count >= self.max_retries"),
        "REGRESSION: the retry exhaustion guard `if retry_count \
         >= self.max_retries` is gone. Without it, the retry \
         loop has no bounded termination — it could spin \
         forever (CPU/network hot-loop) or accumulate batches.\n\n\
         fn body:\n{body}",
    );

    // The exhaustion branch must return an Err immediately
    // (not push to a queue or call self.queue.push or similar).
    let guard_pos = body
        .find("if retry_count >= self.max_retries")
        .expect("guard must exist");
    let post_guard = &body[guard_pos..];
    let return_pos = post_guard
        .find("return Err(ExportError::new(")
        .expect("exhaustion path must return Err");

    // Within the first ~300 chars after the guard, no queue-
    // looking call should appear before the return.
    let exhaustion_block = &post_guard[..return_pos];
    let suspect_queue_calls = [
        "self.queue.push",
        "self.pending.push",
        "self.retry_buffer.push",
        "pending_batches.push",
        "queue.push_back",
        ".lock().push",
    ];
    for pat in &suspect_queue_calls {
        assert!(
            !exhaustion_block.contains(pat),
            "REGRESSION: between the max_retries guard and the \
             return Err, the code calls `{pat}` — it's queueing \
             the batch for later instead of dropping it. This \
             is the memory-leak path the audit guards against.\n\
             \nexhaustion block:\n{exhaustion_block}",
        );
    }
}

#[test]
fn send_otlp_protobuf_takes_request_body_by_value() {
    // Pin (c): the function takes `request_body: Vec<u8>` by
    // VALUE. After return, the Vec is dropped. A regression
    // that switched to `&[u8]` (let the caller own the buffer)
    // would still be fine, but `Vec<u8>` is the doc'd contract;
    // a switch to `Arc<Vec<u8>>` could indicate sharing across
    // a queue.
    let source = read_otel_source();

    let sig_marker = "async fn send_otlp_protobuf(";
    let sig_start = source.find(sig_marker).expect("send_otlp_protobuf signature");
    let body_start = source[sig_start..]
        .find('{')
        .expect("body start") + sig_start;
    let signature = &source[sig_start..body_start];

    assert!(
        signature.contains("request_body: Vec<u8>"),
        "REGRESSION: send_otlp_protobuf no longer takes \
         `request_body: Vec<u8>` by value. If the signature \
         changed to a shared/refcounted type (Arc<Vec<u8>>, \
         Bytes, &[u8]), audit whether the new owner can hold \
         the batch alive across multiple retry calls — that \
         would re-open the accumulation failure mode.\n\n\
         signature:\n{signature}",
    );
}

#[test]
fn otlp_sync_export_returns_error_no_queue() {
    // Pin (d): the MetricsExporter::export sync method on
    // OtlpHttpExporter returns Err with a clear message.
    // It does NOT enqueue the snapshot for later async
    // processing. A regression that buffered the snapshot
    // for a background task would re-open the accumulation
    // failure mode.
    let source = read_otel_source();

    let impl_marker = "impl MetricsExporter for OtlpHttpExporter {";
    let start = source
        .find(impl_marker)
        .expect("MetricsExporter for OtlpHttpExporter");
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("impl close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("Err(ExportError::new(")
            && body.contains("OTLP HTTP export requires async context"),
        "REGRESSION: OtlpHttpExporter's sync export() no longer \
         returns an immediate Err. If it now buffers the \
         snapshot internally for later async processing, that's \
         a queue — verify it's bounded, has an overflow \
         strategy, and update this audit test.\n\n\
         impl body:\n{body}",
    );

    // Forbid suspicious queue-like calls in the export body.
    let suspect_calls = [
        "self.queue.push",
        "self.pending.push",
        "self.snapshots.lock().push",
        "self.buffer.push",
    ];
    for pat in &suspect_calls {
        assert!(
            !body.contains(pat),
            "REGRESSION: sync export() now contains `{pat}` — \
             queueing the snapshot for later processing. \
             Verify the queue is bounded.",
        );
    }
}

#[test]
fn otlp_flush_is_a_noop() {
    // Pin (e): flush() has a single-line "stateless, nothing to
    // flush" comment + Ok(()) return. A regression that made
    // flush non-trivial would suggest internal state needing
    // to drain — i.e. a queue.
    let source = read_otel_source();

    // Look up the flush method in the FULL source AFTER the
    // OtlpHttpExporter impl marker. Multiple exporters share
    // the `fn flush(&self) -> Result<(), ExportError>` signature
    // so we must anchor on the impl marker first.
    let flush_marker = "fn flush(&self) -> Result<(), ExportError> {";
    let impl_abs = source
        .find("impl MetricsExporter for OtlpHttpExporter {")
        .expect("OtlpHttpExporter impl");
    let flush_rel = source[impl_abs..]
        .find(flush_marker)
        .expect("flush method inside OtlpHttpExporter impl");
    let flush_abs = impl_abs + flush_rel;
    let flush_end = source[flush_abs..]
        .find("\n    }\n")
        .expect("flush close");
    let flush_body = &source[flush_abs..flush_abs + flush_end];

    assert!(
        flush_body.contains("Ok(())") && flush_body.contains("OTLP is stateless"),
        "REGRESSION: flush() is no longer a no-op. The audit \
         invariant relies on OTLP being stateless (nothing to \
         drain). If flush became non-trivial, the exporter now \
         holds state — verify it's bounded.\n\n\
         flush body:\n{flush_body}",
    );
}

#[test]
fn no_background_dispatcher_or_retry_task() {
    // Pin (a) defense-in-depth: there is no spawn / task /
    // background loop in the OtlpHttpExporter impl. A
    // regression that introduced a background dispatcher
    // (e.g. `let _ = self.runtime.spawn(retry_dispatcher)`)
    // would imply a queue feeding the dispatcher.
    let source = read_otel_source();

    // Find the OtlpHttpExporter impl block (the inherent
    // impl, not the trait impl).
    let impl_marker = "impl OtlpHttpExporter {";
    let start = source.find(impl_marker).expect("inherent impl");
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("inherent impl close");
    let body = &source[start..start + end_rel];

    let suspect_dispatcher_patterns = [
        "tokio::spawn",
        "asupersync::spawn",
        "runtime.spawn",
        "self.runtime.spawn",
        "spawn_blocking",
        "background_task",
        "dispatcher_loop",
    ];
    for pat in &suspect_dispatcher_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: OtlpHttpExporter inherent impl now \
             contains `{pat}` — looks like a background \
             dispatcher. A dispatcher implies a queue feeding \
             it; verify the queue is bounded with an explicit \
             overflow strategy.",
        );
    }
}

#[test]
fn retry_loop_increments_count_on_every_iteration() {
    // Pin (b): the retry loop increments retry_count on every
    // retryable error so the guard `retry_count >= max_retries`
    // is reachable. A regression that forgot to increment would
    // cause an infinite loop (different failure mode than
    // accumulation, but equally severe).
    let source = read_otel_source();
    let body = send_otlp_protobuf_body(&source);

    assert!(
        body.contains("retry_count += 1;"),
        "REGRESSION: the retry loop no longer increments \
         retry_count. Without the increment, the guard \
         `retry_count >= max_retries` is unreachable and the \
         loop runs forever.\n\nfn body:\n{body}",
    );
}

#[test]
fn retry_delay_is_capped_at_max_retry_delay() {
    // Pin: the delay is bounded by max_retry_delay via
    // cmp::min. A regression that removed the cap would let
    // exponential backoff grow without bound (still bounded
    // total iterations by max_retries, but each sleep could
    // become arbitrarily large — effectively a different
    // class of resource exhaustion: thread/task time).
    let source = read_otel_source();
    let body = send_otlp_protobuf_body(&source);

    assert!(
        body.contains("cmp::min(") && body.contains("self.max_retry_delay"),
        "REGRESSION: retry delay is no longer capped at \
         self.max_retry_delay via cmp::min. Exponential \
         backoff without a cap can produce arbitrarily large \
         per-retry sleeps.\n\nfn body:\n{body}",
    );
}
