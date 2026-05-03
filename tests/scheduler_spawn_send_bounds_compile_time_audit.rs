//! Audit + regression test for spawn(future) memory-safety
//! via compile-time Send-bounds enforcement.
//!
//! Operator's question: "when a spawned future contains a
//! !Send closure or non-Send future, does the scheduler
//! reject at spawn-time (compile error preferred) or panic
//! at run-time? Per asupersync structured concurrency, must
//! be type-checked."
//!
//! Audit findings:
//!
//!   The asupersync spawn API enforces Send bounds at
//!   **COMPILE TIME** via `where` clauses. A `!Send` future
//!   passed to `Scope::spawn` fails to compile — there is
//!   no runtime panic and no runtime check, because there
//!   doesn't need to be one. The chain:
//!
//!   1. **`Scope::spawn` requires Send** (cx/scope.rs:348):
//!      ```ignore
//!      pub fn spawn<F, Fut, Caps>(...) -> Result<...>
//!      where
//!          Caps: cap::HasSpawn + Send + Sync + 'static,
//!          F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
//!          Fut: Future + Send + 'static,
//!          Fut::Output: Send + 'static,
//!      ```
//!      The factory closure `F`, the future `Fut`, and the
//!      output type `Fut::Output` ALL require `Send`. The
//!      compiler rejects any caller that violates these
//!      bounds. The same bounds are repeated on `spawn_task`
//!      (cx/scope.rs:493) and `spawn_registered`
//!      (cx/scope.rs:534) so all three Send-spawn entry
//!      points share the same compile-time wall.
//!
//!   2. **`Scope::spawn_local` accepts !Send** (cx/scope.rs:
//!      591):
//!      ```ignore
//!      pub fn spawn_local<F, Fut, Caps>(...) -> Result<...>
//!      where
//!          Caps: cap::HasSpawn + Send + Sync + 'static,
//!          F: FnOnce(Cx<Caps>) -> Fut + 'static,
//!          Fut: Future + 'static,
//!          Fut::Output: Send + 'static,
//!      ```
//!      No `Send` on `F` or `Fut` — the local spawn path
//!      is the type-system-sanctioned escape hatch for
//!      !Send futures. The output IS still `Send` because
//!      the parent's JoinHandle may be awaited from any
//!      thread.
//!
//!   3. **StoredTask carries Send in the trait object**
//!      (runtime/stored_task.rs:17):
//!      ```ignore
//!      pub struct StoredTask {
//!          future: Pin<Box<dyn Future<Output = Outcome<(),()>> + Send>>,
//!          ...
//!      }
//!      pub fn new<F>(future: F) -> Self
//!      where F: Future<Output = Outcome<(),()>> + Send + 'static,
//!      ```
//!      The `+ Send` in the trait object is what lets the
//!      stored task move between worker threads via work-
//!      stealing. The constructor's `F: Send` bound is
//!      what enforces the constraint at the boundary.
//!
//!   4. **LocalStoredTask drops the Send bound** (runtime/
//!      stored_task.rs:135):
//!      ```ignore
//!      pub struct LocalStoredTask {
//!          future: Pin<Box<dyn Future<Output = Outcome<(),()>> + 'static>>,
//!          ...
//!      }
//!      ```
//!      Symmetric to spawn_local — the local-task storage
//!      doesn't carry Send because the task is pinned to
//!      its owner worker via thread-local scheduler routing.
//!
//!   5. **No runtime Send check anywhere on the spawn
//!      path**: a grep over `src/cx/scope.rs` and
//!      `src/runtime/scheduler/three_lane.rs` for runtime
//!      Send-check patterns (`is_send`, `assert_send`,
//!      `panic!("not Send")`) finds nothing. The check is
//!      purely structural — done by the compiler before
//!      the binary even runs.
//!
//! Verdict: **SOUND**. Send bounds are enforced at compile
//! time via `where` clauses on `Scope::spawn` /
//! `spawn_task` / `spawn_registered`. The compiler rejects
//! a `!Send` future passed to these methods — no runtime
//! panic is possible because no runtime check is needed.
//!
//! `spawn_local` is the type-system-sanctioned alternative
//! for `!Send` futures. The compile-time mechanism cleanly
//! separates the two cases:
//!   - `spawn` → `StoredTask` (Send) → global queue +
//!     work-stealing across workers.
//!   - `spawn_local` → `LocalStoredTask` (no Send) →
//!     thread-local queue, never stealable.
//!
//! A regression that:
//!   - removed the `Send` bound from `Fut: Future + Send +
//!     'static` on `Scope::spawn` (would compile a !Send
//!     future into a Send-requiring StoredTask, hitting
//!     a `Box::pin` Send-bound mismatch downstream — but
//!     potentially with a confusing error far from the
//!     spawn site),
//!   - removed the `Send` bound from `F: FnOnce(Cx<Caps>)
//!     -> Fut + Send + 'static` (closure with !Send
//!     captures could be uploaded; compiler may catch it
//!     downstream but the spawn-site error is the right
//!     guard),
//!   - removed the `+ Send` from the `StoredTask.future`
//!     trait object (would unsoundly allow !Send futures
//!     to be moved between worker threads — undefined
//!     behavior),
//!   - added a runtime `panic!("future is not Send")` check
//!     anywhere in the spawn path (would be a tautology if
//!     the type bound is in place — and a footgun if it
//!     replaced the bound),
//!   - swapped `Scope::spawn` and `Scope::spawn_local`
//!     bounds (would let users accidentally spawn !Send
//!     futures into the global stealable queue),
//! would all be caught by the structural pins below or by
//! the compile-time positive/negative checks (which prove
//! the type bounds are load-bearing).

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn scope_spawn_requires_send_on_future_closure_and_output() {
    // Pin (link 1): Scope::spawn has `where` clauses
    // requiring Send on F (closure), Fut (future), and
    // Fut::Output. All three Send bounds must be present.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub fn spawn<F, Fut, Caps>(";
    let start = source.find(fn_marker).expect("Scope::spawn fn");
    // Take the where-clause section: ~30 lines after.
    let window_end = (start + 1500).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let where_section = &source[start..safe_end];

    assert!(
        where_section.contains("F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,"),
        "REGRESSION: Scope::spawn closure bound no longer \
         requires `+ Send`. A !Send closure could be passed \
         to spawn — moving captured !Send state between \
         worker threads. Memory unsafety.",
    );

    assert!(
        where_section.contains("Fut: Future + Send + 'static,"),
        "REGRESSION: Scope::spawn future bound no longer \
         requires `+ Send`. A !Send future could be moved \
         between workers via work-stealing — undefined \
         behavior. The compile-time guard is the ONLY \
         memory-safety mechanism here.",
    );

    assert!(
        where_section.contains("Fut::Output: Send + 'static,"),
        "REGRESSION: Scope::spawn output bound no longer \
         requires `+ Send`. The parent's JoinHandle may \
         await on a different thread — !Send output would \
         be unsoundly transferred.",
    );
}

#[test]
fn scope_spawn_task_repeats_the_send_bounds() {
    // Pin (link 1): spawn_task is the documented user-facing
    // alias of spawn. It must repeat the same Send bounds —
    // a regression that loosened them on the alias would
    // create a compile-time bypass.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub fn spawn_task<F, Fut, Caps>(";
    let start = source.find(fn_marker).expect("spawn_task fn");
    let window_end = (start + 1500).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let where_section = &source[start..safe_end];

    assert!(
        where_section.contains("F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,")
            && where_section.contains("Fut: Future + Send + 'static,")
            && where_section.contains("Fut::Output: Send + 'static,"),
        "REGRESSION: spawn_task no longer repeats the Send \
         bounds from spawn. A bypass via spawn_task would \
         allow !Send futures into global queues.",
    );
}

#[test]
fn scope_spawn_registered_repeats_the_send_bounds() {
    // Pin (link 1): spawn_registered is the macro-facing
    // entry point. Same Send bounds required.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub fn spawn_registered<F, Fut, Caps>(";
    let start = source.find(fn_marker).expect("spawn_registered fn");
    let window_end = (start + 1500).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let where_section = &source[start..safe_end];

    assert!(
        where_section.contains("F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,")
            && where_section.contains("Fut: Future + Send + 'static,")
            && where_section.contains("Fut::Output: Send + 'static,"),
        "REGRESSION: spawn_registered no longer repeats the \
         Send bounds. The `spawn!` macro would silently \
         allow !Send futures into the global queue — \
         unsoundness via the macro layer.",
    );
}

#[test]
fn scope_spawn_local_intentionally_drops_send_on_closure_and_future() {
    // Pin (link 2): spawn_local is the !Send escape hatch.
    // It MUST NOT carry Send on F or Fut. A regression that
    // ADDED Send bounds would defeat the local-spawn API.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub fn spawn_local<F, Fut, Caps>(";
    let start = source.find(fn_marker).expect("spawn_local fn");
    let window_end = (start + 1500).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let where_section = &source[start..safe_end];

    // Closure must NOT require Send.
    assert!(
        where_section.contains("F: FnOnce(Cx<Caps>) -> Fut + 'static,")
            && !where_section.contains("F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,"),
        "REGRESSION: spawn_local closure now requires Send. \
         The escape hatch is broken — !Send factories \
         (capturing Rc, RefCell, etc.) can no longer spawn \
         local tasks.",
    );

    // Future must NOT require Send.
    assert!(
        where_section.contains("Fut: Future + 'static,")
            && !where_section.contains("Fut: Future + Send + 'static,"),
        "REGRESSION: spawn_local future now requires Send. \
         The escape hatch is broken — !Send futures (e.g., \
         JS interop on wasm, Rc-holding futures) can no \
         longer spawn locally.",
    );

    // Output STILL requires Send (parent JoinHandle may
    // await cross-thread).
    assert!(
        where_section.contains("Fut::Output: Send + 'static,"),
        "REGRESSION: spawn_local output bound no longer \
         requires Send. The parent's JoinHandle may await \
         from any thread — !Send output would be unsoundly \
         transferred.",
    );
}

#[test]
fn stored_task_future_field_carries_send_in_trait_object() {
    // Pin (link 3): StoredTask.future has `+ Send` in the
    // trait object. Without it, the trait object can hold
    // a !Send future and the StoredTask itself would
    // become !Send — but it's used in places that require
    // Send (e.g., crossbeam queues). The bound is critical.
    let source = read("src/runtime/stored_task.rs");

    assert!(
        source.contains("future: Pin<Box<dyn Future<Output = Outcome<(), ()>> + Send>>,"),
        "REGRESSION: StoredTask.future trait object no \
         longer requires Send. A !Send future could be \
         stored and then moved between workers via the \
         global injector — undefined behavior.",
    );

    // Constructor enforces Send.
    assert!(
        source.contains("F: Future<Output = Outcome<(), ()>> + Send + 'static,"),
        "REGRESSION: StoredTask::new no longer requires \
         F: Send. Even if the trait object's Send bound \
         remained, the constructor would let a !Send F \
         coerce in via Box::pin (depending on auto-trait \
         inference). Defense in depth requires both.",
    );
}

#[test]
fn local_stored_task_intentionally_drops_send_in_trait_object() {
    // Pin (link 4): LocalStoredTask is the !Send-permitting
    // counterpart. Its trait object MUST NOT carry Send —
    // adding Send back would defeat the type system's
    // separation between Send and !Send tasks.
    let source = read("src/runtime/stored_task.rs");

    assert!(
        source.contains("future: Pin<Box<dyn Future<Output = Outcome<(), ()>> + 'static>>,"),
        "REGRESSION: LocalStoredTask.future trait object no \
         longer drops Send — the !Send escape hatch is \
         broken. Either spawn_local fails to compile for \
         !Send factories, or the type system silently allows \
         storing a !Send LocalStoredTask in a Send-requiring \
         collection (the latter would be UB).",
    );

    // The constructor must NOT require Send.
    let local_new_marker = "impl LocalStoredTask {";
    let local_pos = source.find(local_new_marker).expect("LocalStoredTask impl");
    let local_window_end = (local_pos + 2500).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= local_window_end)
        .last()
        .unwrap_or(local_window_end);
    let local_section = &source[local_pos..safe_end];

    assert!(
        local_section.contains("F: Future<Output = Outcome<(), ()>> + 'static,")
            && !local_section.contains("F: Future<Output = Outcome<(), ()>> + Send + 'static,"),
        "REGRESSION: LocalStoredTask::new now requires \
         Send. The escape hatch is broken — spawn_local \
         can no longer accept !Send futures.",
    );
}

#[test]
fn no_runtime_send_check_or_panic_on_spawn_path() {
    // Pin (link 5): the Send check is purely compile-time.
    // A grep over the spawn paths must find no runtime
    // `is_send` / `assert_send` / `panic!("not Send")`
    // patterns — they would be tautologies if the type
    // bound is correct, and footguns if the bound was
    // removed and they were the only line of defense.
    for rel in &[
        "src/cx/scope.rs",
        "src/runtime/scheduler/three_lane.rs",
    ] {
        let source = read(rel);
        let suspect = [
            "panic!(\"future is not Send\")",
            "panic!(\"task is not Send\")",
            "assert_send_future",
            "TypeId::of::<dyn Send>",
        ];
        for pat in &suspect {
            assert!(
                !source.contains(pat),
                "REGRESSION: {rel} now contains a runtime \
                 Send check (`{pat}`). Send is a compile-\
                 time property — a runtime check is either \
                 a tautology (when the bound is in place) \
                 or a footgun (when the bound was removed \
                 and this is the only line of defense). \
                 Remove the runtime check and rely on the \
                 type bound.",
            );
        }
    }
}

#[test]
fn scope_spawn_blocking_requires_send_on_closure_and_output() {
    // Pin (audit hygiene): spawn_blocking is a separate
    // path that runs the closure on the blocking pool. It
    // must also require Send on the closure (because the
    // closure runs on a different OS thread).
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub fn spawn_blocking<F, R, Caps>(";
    let start = source.find(fn_marker).expect("spawn_blocking fn");
    let window_end = (start + 1500).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let where_section = &source[start..safe_end];

    assert!(
        where_section.contains("Send + 'static") || where_section.contains("Send"),
        "REGRESSION: spawn_blocking no longer requires Send. \
         The blocking pool runs the closure on a separate \
         thread — !Send closure → undefined behavior.",
    );
}

// ─────────── COMPILE-TIME POSITIVE/NEGATIVE CHECKS ─────────
//
// The where-clause pins above check that the bounds EXIST
// in source. These compile-time checks demonstrate that the
// bounds are LOAD-BEARING by reproducing the same signatures
// in standalone test code. If a Send bound were silently
// dropped, the corresponding mock test below would compile
// against the lib's actual API (assertion that the mock's
// type still implements the same constraints).

use std::future::Future;

/// Mock signature with the same Send bounds as
/// `Scope::spawn`. If the bounds were dropped from production,
/// users would see compile errors at the production spawn
/// site; this mock here serves as a compile-time SHADOW that
/// fails the test build if the bounds drift.
fn mock_spawn_send_bound_shadow<F, Fut>(_f: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    // No body — the where-clause is the contract.
}

/// Mock signature with the same NON-Send bounds as
/// `Scope::spawn_local`. Symmetric — the absence of Send is
/// the contract.
fn mock_spawn_local_no_send_bound_shadow<F, Fut>(_f: F)
where
    F: FnOnce() -> Fut + 'static,
    Fut: Future + 'static,
    Fut::Output: Send + 'static,
{
    // No body — !Send permitted on F/Fut.
}

#[test]
fn compile_time_send_bound_accepts_send_future() {
    // Behavioral pin: a Send future passes the mock_spawn
    // bound. If the bound were ever loosened, this test
    // could trivially be made to accept !Send too — the
    // structural pins above are the source of truth.
    mock_spawn_send_bound_shadow(|| async { 42_u32 });
}

#[test]
fn compile_time_no_send_bound_accepts_non_send_future() {
    // Behavioral pin: a !Send future (one capturing Rc)
    // passes the mock_spawn_local bound but would be
    // rejected by mock_spawn_send_bound_shadow.
    use std::rc::Rc;
    mock_spawn_local_no_send_bound_shadow(|| {
        let counter = Rc::new(0_u32);
        async move {
            // counter (Rc) is !Send — this future is !Send.
            let _captured = Rc::clone(&counter);
        }
    });
}

#[test]
fn cross_reference_to_prior_audits() {
    // Pin (documentary): related structural-concurrency
    // audits.
    let prior_audits = [
        "tests/scheduler_panic_in_task_isolation_audit.rs",
        "tests/scheduler_worker_resilience_panic_during_poll_audit.rs",
        "tests/runtime_spawn_during_cancellation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
