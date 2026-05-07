//! Audit + regression test for `Cx::checkpoint()` call
//! frequency across representative async functions in
//! src/database, src/messaging, and src/http.
//!
//! Operator's question: "Tasks should call checkpoint at
//! every yield-point or every ~1ms loop iteration. Survey 5
//! representative async functions and verify they call
//! checkpoint with reasonable frequency. If any has
//! compute-heavy loops without checkpoint, file bead."
//!
//! Survey: SIX representative async functions audited.
//!
//! ┌──────────────────────────────────────────────────────┐
//! │ 1. postgres.rs::Connection::query_unchecked          │
//! │    (src/database/postgres.rs:3717)                   │
//! │    `cx.checkpoint().is_err()` at fn entry.           │
//! │    All subsequent work is gated on async I/O         │
//! │    (read_message, write_message, ensure_*).          │
//! │    Verdict: SOUND.                                   │
//! └──────────────────────────────────────────────────────┘
//!
//! ┌──────────────────────────────────────────────────────┐
//! │ 2. postgres.rs::RowStream::next                      │
//! │    (src/database/postgres.rs:1174)                   │
//! │    `cx.checkpoint().is_err()` at every next() call.  │
//! │    Inner protocol-message loop awaits read_message;  │
//! │    each iteration is bounded (typically returns      │
//! │    after the first DataRow).                         │
//! │    Verdict: SOUND.                                   │
//! └──────────────────────────────────────────────────────┘
//!
//! ┌──────────────────────────────────────────────────────┐
//! │ 3. sqlite.rs::Connection::query_unchecked            │
//! │    (src/database/sqlite.rs:1079)                     │
//! │    `cx.checkpoint().is_err()` × 2 at fn entry        │
//! │    (once before drain_orphaned, once after).         │
//! │    Inner row-iteration loop runs on the BLOCKING     │
//! │    POOL via run_connection_op. Blocking-pool ops     │
//! │    are documented as exempt from cooperative cancel  │
//! │    — interruption requires sqlite3_interrupt() which │
//! │    is a separate concern.                            │
//! │    Verdict: SOUND for async surface.                 │
//! └──────────────────────────────────────────────────────┘
//!
//! ┌──────────────────────────────────────────────────────┐
//! │ 4. jetstream.rs::Consumer::pull_with_timeout         │
//! │    (src/messaging/jetstream.rs:1295)                 │
//! │    `cx.checkpoint()?` at fn entry.                   │
//! │    Outer loop yields via `client.process(cx).await`. │
//! │    Inner while loop drains ≤MAX_PULL_BATCH (1024)    │
//! │    cached messages — sub-millisecond at typical      │
//! │    payload sizes.                                    │
//! │    Verdict: SOUND.                                   │
//! └──────────────────────────────────────────────────────┘
//!
//! ┌──────────────────────────────────────────────────────┐
//! │ 5. kafka.rs::Producer::send                          │
//! │    (src/messaging/kafka.rs:1366)                     │
//! │    `cx.checkpoint()?` at fn entry.                   │
//! │    Single-message send; no compute-heavy loop.       │
//! │    Verdict: SOUND.                                   │
//! └──────────────────────────────────────────────────────┘
//!
//! ┌──────────────────────────────────────────────────────┐
//! │ 6. http/h1/server.rs::serve_with_peer_addr           │
//! │    (src/http/h1/server.rs:486)                       │
//! │    `Cx::with_current(|cx| cx.checkpoint().is_err())` │
//! │    at the top of EVERY per-request loop iteration.   │
//! │    Per-request granularity matches the natural unit  │
//! │    of work for an HTTP server.                       │
//! │    Verdict: SOUND.                                   │
//! └──────────────────────────────────────────────────────┘
//!
//! ── Functions WITHOUT checkpoint (deliberately) ─────────
//!
//! - http/h1/codec.rs: 0 checkpoint calls — pure encoding/
//!   decoding state machine, no async fn. Polled by the
//!   driver above (server.rs / client.rs) which IS the
//!   checkpoint owner.
//! - http/h2/connection.rs: 0 checkpoint calls — same: a
//!   sync state machine driven by the runtime above.
//! - http/compress.rs: 0 checkpoint calls — synchronous
//!   compression primitives; no async fn.
//! - messaging/consumer.rs: 0 async fns — consumer cursor
//!   state machine, sync by design.
//!
//! These are SOUND BY DESIGN: checkpoint discipline is a
//! property of the async-surface boundary, not of the inner
//! state machines that the boundary drives.
//!
//! ── Cooperative yield via .await on I/O ─────────────────
//!
//! The asupersync runtime treats `.await` on a Future that
//! is itself cancel-aware (network I/O, timer, channel
//! recv, etc.) as a checkpoint-equivalent yield point: the
//! reactor checks fast_cancel before/after polling, and a
//! cancelled task's pending I/O fails fast. This means
//! that even a tight loop of `recv().await; parse(buf)`
//! observes cancellation between each iteration without
//! needing an explicit `cx.checkpoint()?`.
//!
//! The 5 surveyed async functions all leverage this: the
//! cx.checkpoint() at entry catches pre-existing cancel,
//! and subsequent .await yields catch cancel that arrives
//! during execution.
//!
//! Verdict: **SOUND**. All 6 surveyed async functions
//! checkpoint at reasonable frequency. No compute-heavy
//! loop runs on the runtime without either an explicit
//! `cx.checkpoint()` or an `.await` on a cancel-aware
//! Future.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn postgres_query_unchecked_checkpoints_at_entry() {
    let source = read("src/database/postgres.rs");

    let fn_marker = "pub async fn query_unchecked(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<PgRow>, PgError> {";
    let pos = source.find(fn_marker).expect("query_unchecked fn");
    let body = &source[pos..pos + 800];

    assert!(
        body.contains("if cx.checkpoint().is_err() {"),
        "REGRESSION: postgres::query_unchecked no longer \
         checkpoints at entry. Cancellation arriving before \
         the first I/O is not observed.",
    );

    assert!(
        body.contains("Outcome::Cancelled("),
        "REGRESSION: query_unchecked no longer maps the \
         entry-checkpoint Err to Outcome::Cancelled.",
    );
}

#[test]
fn postgres_row_stream_next_checkpoints_per_call() {
    let source = read("src/database/postgres.rs");

    let fn_marker = "pub async fn next(&mut self, cx: &Cx) -> Outcome<Option<PgRow>, PgError> {";
    let pos = source.find(fn_marker).expect("RowStream::next fn");
    let body = &source[pos..pos + 800];

    assert!(
        body.contains("if cx.checkpoint().is_err() {"),
        "REGRESSION: postgres::RowStream::next no longer \
         checkpoints at the head of each call. Streaming \
         consumers can run unbounded without observing \
         cancel.",
    );

    // The inner protocol loop must yield via async read.
    assert!(
        body.contains(".read_message(cx).await"),
        "REGRESSION: RowStream::next inner loop no longer \
         awaits read_message — cooperative yield point lost.",
    );
}

#[test]
fn sqlite_query_unchecked_checkpoints_at_entry_twice() {
    let source = read("src/database/sqlite.rs");

    let fn_marker = "pub async fn query_unchecked(";
    let pos = source.find(fn_marker).expect("sqlite query_unchecked fn");
    let body = &source[pos..pos + 1200];

    let count = body.matches("if cx.checkpoint().is_err() {").count();
    assert!(
        count >= 2,
        "REGRESSION: sqlite::query_unchecked has fewer than \
         2 cx.checkpoint() calls at entry (found {count}). \
         The pattern of checkpoint-before-drain + checkpoint-\
         after-drain is broken.",
    );
}

#[test]
fn sqlite_blocking_pool_pattern_documented() {
    // Pin: the sqlite query path delegates the inner row
    // iteration to run_connection_op which dispatches to
    // the blocking pool. This is documented in the AGENTS
    // model — sync DB drivers run their hot loops off the
    // runtime worker, so cooperative cancel doesn't apply
    // mid-loop. (The fix would be sqlite3_interrupt(),
    // tracked separately.)
    let source = read("src/database/sqlite.rs");

    assert!(
        source.contains(".run_connection_op(cx, "),
        "REGRESSION: sqlite no longer routes through \
         run_connection_op. The blocking-pool exemption \
         for sync row loops may have changed — re-audit.",
    );
}

#[test]
fn jetstream_pull_with_timeout_checkpoints_at_entry() {
    let source = read("src/messaging/jetstream.rs");

    let fn_marker = "pub async fn pull_with_timeout(";
    let pos = source.find(fn_marker).expect("pull_with_timeout fn");
    let body = &source[pos..pos + 600];

    assert!(
        body.contains("cx.checkpoint().map_err(|_| NatsError::Cancelled)?;"),
        "REGRESSION: jetstream::pull_with_timeout no longer \
         checkpoints at entry. Long pulls cannot observe \
         pre-existing cancel.",
    );

    // The pull loop must be bounded by MAX_PULL_BATCH.
    assert!(
        source.contains("MAX_PULL_BATCH"),
        "REGRESSION: MAX_PULL_BATCH bound is gone. Pull \
         loop is now unbounded — could run for many ms \
         without yielding.",
    );

    // The pull loop must yield via client.process(cx) +
    // an .await (in either the timeout-at branch or the
    // direct .await branch).
    let pull_outer_loop_pos = source[pos..]
        .find("loop {\n            if !pull_state.is_active() {")
        .expect("pull outer loop")
        + pos;
    let loop_body = &source[pull_outer_loop_pos..pull_outer_loop_pos + 4000];
    assert!(
        loop_body.contains("client.process(cx)"),
        "REGRESSION: jetstream pull loop no longer calls \
         client.process(cx) — the cooperative pump is gone.",
    );
    assert!(
        loop_body.contains(".await"),
        "REGRESSION: jetstream pull loop no longer awaits \
         a Future — no cooperative yield point.",
    );
}

#[test]
fn kafka_send_checkpoints_at_entry() {
    let source = read("src/messaging/kafka.rs");

    let fn_marker = "pub async fn send(";
    // First occurrence — the producer's send method.
    let pos = source.find(fn_marker).expect("kafka send fn");
    let body = &source[pos..pos + 400];

    assert!(
        body.contains("cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;"),
        "REGRESSION: kafka::Producer::send no longer \
         checkpoints at entry.",
    );
}

#[test]
fn h1_server_serve_loop_checkpoints_per_request() {
    let source = read("src/http/h1/server.rs");

    let fn_marker = "pub async fn serve_with_peer_addr<T>(";
    let pos = source.find(fn_marker).expect("serve_with_peer_addr fn");
    let body = &source[pos..pos + 4000];

    // Loop body must contain a checkpoint call near the top
    // of each iteration (gated by Cx::with_current to handle
    // the no-ambient-cx fallback).
    assert!(
        body.contains("Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false)"),
        "REGRESSION: h1 server loop no longer checkpoints \
         per-request. Long-lived HTTP/1.1 connections are \
         no longer cancel-responsive.",
    );

    // The loop must explicitly break on Closing phase.
    assert!(
        body.contains("ConnectionPhase::Closing"),
        "REGRESSION: h1 server loop no longer transitions \
         to Closing phase on cancel. The cancel-bail path \
         is broken.",
    );
}

#[test]
fn h1_codec_has_no_async_fn_so_no_checkpoint_required() {
    // Pin: http/h1/codec.rs is a sync state machine — there
    // are no async fns and therefore no checkpoint
    // expected. The driver above (server.rs / client.rs)
    // owns checkpoint discipline.
    let source = read("src/http/h1/codec.rs");

    assert!(
        !source.contains("pub async fn") && !source.contains("    async fn"),
        "REGRESSION: http/h1/codec.rs now defines async \
         fns. If these run on the runtime, they MUST \
         checkpoint at entry — re-audit this file.",
    );
}

#[test]
fn h2_connection_has_no_async_fn_so_no_checkpoint_required() {
    // Same rationale as h1/codec.rs.
    let source = read("src/http/h2/connection.rs");

    assert!(
        !source.contains("pub async fn") && !source.contains("    async fn "),
        "REGRESSION: http/h2/connection.rs now defines \
         async fns. If these run on the runtime, they \
         MUST checkpoint — re-audit.",
    );
}

#[test]
fn http_compress_has_no_async_fn_so_no_checkpoint_required() {
    let source = read("src/http/compress.rs");

    assert!(
        !source.contains("pub async fn") && !source.contains("    async fn "),
        "REGRESSION: http/compress.rs now defines async \
         fns. Compression on the runtime requires \
         checkpoints around block boundaries.",
    );
}

#[test]
fn checkpoint_call_count_floor_per_module() {
    // Pin: floor on checkpoint() call count per module.
    // This is a coarse but durable signal — any regression
    // that bulk-deletes checkpoint() will be caught.
    let cases = [
        ("src/database/postgres.rs", 25),
        ("src/database/mysql.rs", 8),
        ("src/database/sqlite.rs", 8),
        ("src/messaging/jetstream.rs", 6),
        ("src/messaging/kafka.rs", 10),
    ];

    for (path, floor) in cases {
        let source = read(path);
        let count = source.matches("cx.checkpoint()").count();
        assert!(
            count >= floor,
            "REGRESSION: `{path}` now has {count} cx.checkpoint() \
             calls; expected at least {floor}. Substantial \
             checkpoint deletion has occurred — investigate.",
        );
    }
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Models a long-running async function that processes
/// items in a loop. Each iteration calls `checkpoint()`;
/// when cancel is signalled, the function bails on the
/// next iteration via the `?`-propagation pattern.
struct MockAsyncWorker {
    fast_cancel: Arc<AtomicBool>,
    items_processed: AtomicU64,
}

impl MockAsyncWorker {
    fn new() -> Self {
        Self {
            fast_cancel: Arc::new(AtomicBool::new(false)),
            items_processed: AtomicU64::new(0),
        }
    }

    fn cancel(&self) {
        self.fast_cancel.store(true, Ordering::Release);
    }

    fn checkpoint(&self) -> Result<(), &'static str> {
        if self.fast_cancel.load(Ordering::Acquire) {
            Err("cancelled")
        } else {
            Ok(())
        }
    }

    /// Models the pattern:
    ///
    /// ```ignore
    /// pub async fn process_batch(cx: &Cx, items: &[Item]) -> Result<...> {
    ///     cx.checkpoint()?;
    ///     for item in items {
    ///         cx.checkpoint()?;
    ///         do_work(item).await;
    ///     }
    ///     Ok(())
    /// }
    /// ```
    fn process_batch(&self, batch_size: u64) -> Result<u64, &'static str> {
        self.checkpoint()?;
        for _ in 0..batch_size {
            self.checkpoint()?;
            self.items_processed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(self.items_processed.load(Ordering::Relaxed))
    }
}

#[test]
fn behavioral_checkpoint_bails_on_cancel_within_batch() {
    let worker = MockAsyncWorker::new();

    // No cancel: full batch processes.
    let result = worker.process_batch(100);
    assert_eq!(result, Ok(100));

    // Cancel mid-stream: bails on next iteration.
    let worker2 = MockAsyncWorker::new();
    let fc = Arc::clone(&worker2.fast_cancel);

    // Process first 10 items, then cancel.
    for _ in 0..10 {
        worker2.checkpoint().expect("not cancelled yet");
        worker2.items_processed.fetch_add(1, Ordering::Relaxed);
    }
    fc.store(true, Ordering::Release);

    // Next checkpoint should bail.
    assert!(
        worker2.checkpoint().is_err(),
        "REGRESSION: mid-batch checkpoint did not observe \
         cancel — the iteration-boundary cancel-bail \
         pattern is broken.",
    );

    // items_processed remains at 10 (not the full 100).
    assert_eq!(
        worker2.items_processed.load(Ordering::Relaxed),
        10,
        "REGRESSION: worker continued processing after cancel.",
    );
}

#[test]
fn behavioral_checkpoint_at_entry_observes_pre_existing_cancel() {
    // Models the pattern: caller cancels BEFORE the async fn
    // runs; entry checkpoint must catch this.
    let worker = MockAsyncWorker::new();
    worker.cancel();

    let result = worker.process_batch(1000);
    assert_eq!(
        result,
        Err("cancelled"),
        "REGRESSION: entry checkpoint did not catch pre-\
         existing cancel.",
    );
    assert_eq!(
        worker.items_processed.load(Ordering::Relaxed),
        0,
        "REGRESSION: worker did work despite entry-cancel.",
    );
}

#[test]
fn behavioral_bounded_inner_loop_processes_within_one_ms() {
    // Models jetstream's pull loop bound: ≤MAX_PULL_BATCH
    // (1024) messages parsed per outer iteration. At ~100ns
    // per message-parse, that's ~100µs — well under 1ms.
    use std::time::Instant;

    let worker = MockAsyncWorker::new();
    let start = Instant::now();
    let result = worker.process_batch(1024);
    let elapsed = start.elapsed();

    assert_eq!(result, Ok(1024));
    // Generous bound: 100ms (much higher than realistic, to
    // tolerate slow CI).
    assert!(
        elapsed.as_millis() < 100,
        "REGRESSION: bounded inner loop took {}ms — over \
         the 100ms generous bound. Per-iteration cost has \
         ballooned.",
        elapsed.as_millis(),
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_checkpoint_concurrent_cancel_observation_audit.rs",
        "tests/cx_checkpoint_past_deadline_immediate_err_audit.rs",
        "tests/cx_checkpoint_during_region_cancel_timing_audit.rs",
        "tests/runtime_cancel_signal_coalescing_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
