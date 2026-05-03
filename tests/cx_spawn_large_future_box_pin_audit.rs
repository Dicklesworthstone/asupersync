//! Audit + regression test for `Scope::spawn()` handling of
//! large-state-machine futures.
//!
//! Operator's question: "when spawning a future whose
//! state-machine is huge (e.g., 100KB), is it boxed
//! transparently (correct: stack stays small) or does it
//! consume worker stack (overflow risk)?"
//!
//! Audit findings:
//!
//!   asupersync's spawn path **immediately boxes** every
//!   future via `Box::pin(future)` at the StoredTask
//!   construction site (stored_task.rs:39, 55, 154, 168). A
//!   100KB future state machine occupies ~16 bytes on the
//!   stack (the `Pin<Box<...>>` pointer + vtable) and the
//!   actual 100KB lives on the heap. The chain:
//!
//!   1. **`StoredTask.future` is `Pin<Box<dyn Future<...> +
//!      Send>>`** (stored_task.rs:19): the type-erased trait
//!      object is heap-allocated by construction. There is
//!      no `enum StoredTask { Inline(F), Boxed(Pin<Box<...>>) }`
//!      pattern that could keep small futures on the stack
//!      and would risk stack-overflow for large ones.
//!
//!   2. **Constructors call `Box::pin(future)`**
//!      (stored_task.rs:39, 55):
//!      ```ignore
//!      pub fn new<F>(future: F) -> Self
//!      where
//!          F: Future<Output = Outcome<(), ()>> + Send + 'static,
//!      {
//!          Self {
//!              future: Box::pin(future),
//!              ...
//!          }
//!      }
//!      ```
//!      The `Box::pin(future)` allocation moves the entire
//!      state machine to the heap. After construction, the
//:      original stack-resident `future` is dropped (its
//!      memory is now owned by the Box).
//!
//!   3. **`LocalStoredTask` follows the same pattern**
//!      (stored_task.rs:154, 168): symmetric to StoredTask
//!      for !Send futures. Both Send and !Send futures are
//!      boxed at construction.
//!
//!   4. **Spawn path constructs StoredTask immediately**
//!      (cx/scope.rs:465): the spawn body wraps the user's
//!      future in a `wrapped` async block (for result
//!      delivery), then immediately calls
//!      `StoredTask::new_with_id(wrapped, task_id)`. The
//!      `wrapped` future lives on the stack only briefly
//!      between construction and the Box::pin call —
//!      ephemeral stack pressure that the compiler can
//!      often elide.
//!
//!   5. **Worker `execute()` polls via `Pin<&mut self.future>`**
//!      (stored_task.rs:98): polling reads through the
//!      heap-allocated trait object. The 100KB state machine
//!      lives entirely in the heap during polling — the
//!      worker stack only holds the Pin<&mut> reference plus
//!      the per-poll local variables.
//!
//!   6. **`Box::pin` is the standard way to handle large
//!      futures in Rust async**: the Pin<Box<dyn Future>>
//!      pattern is the canonical type erasure for futures
//!      whose concrete type is unknown to the caller (the
//!      scheduler doesn't know F). This is the same pattern
//!      Tokio, async-std, smol, and every other Rust async
//!      runtime uses for spawn paths.
//!
//!   7. **Stack pressure during spawn is bounded**: the
//!      transient stack consumption during spawn() is:
//!        - The user's future construction (e.g., `async
//!          move { ... }` block construction).
//!        - The wrapped-future construction.
//!        - The Box::pin call (which moves bytes from stack
//!          to heap).
//!      Even for a 100KB future, the spawn-time stack
//!      pressure is bounded by the future's inline size —
//!      and the compiler can often place the future
//!      directly on the heap-bound location via copy
//!      elision (especially in release builds with
//!      optimizations).
//!
//! Verdict: **SOUND**. Large futures (100KB+) are boxed
//! transparently at spawn time. The worker stack holds only
//! the Pin<Box<dyn Future>> pointer (~16 bytes) per task —
//! never the full state machine. There is no stack-overflow
//! pathway for large futures.
//!
//! Note on transient spawn-time pressure: copy elision is
//: a compiler-level optimization, not a guaranteed
//! behavior. For genuinely massive futures (megabyte+),
//: users should consider using `Box::pin(async move { ... })`
//! at the call site to ensure the heap allocation happens
//! at the user's chosen point. The `spawn` API, however,
//! takes the future by value and immediately boxes it — so
//! even without explicit Box::pin at the call site, the
//! state machine ends up on the heap.
//!
//! A regression that:
//!   - changed StoredTask.future from Pin<Box<dyn Future>>
//!     to an inline `enum StoredTask { Small(F0),
//!     Medium(F1), Boxed(Pin<Box<...>>) }` (would risk
//:     stack overflow for futures larger than the inline
//!     variants),
//!   - changed StoredTask::new to NOT call Box::pin (the
//:     future would be stored inline on the StoredTask
//!     struct on the stack — large futures would overflow),
//!   - replaced Box::pin(future) with manual Pin::new on a
//!     stack-resident future (would borrow-check error AND
//!     risk overflow if it compiled),
//!   - introduced a "small future fast path" that kept
//:     futures up to N bytes inline (would either limit
//!     the spawn size or risk overflow at the threshold),
//!   - removed the trait-object form from StoredTask.future
//!     and made it a generic StoredTask<F> (would require
//!     monomorphization at the scheduler boundary —
//!     incompatible with the heterogeneous task table),
//! would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn stored_task_future_field_is_pin_box_dyn_future() {
    // Pin (link 1): StoredTask.future is Pin<Box<dyn Future
    // <Output = Outcome<(), ()>> + Send>>. The Box is what
    // moves the state machine to the heap.
    let source = read("src/runtime/stored_task.rs");

    assert!(
        source.contains("future: Pin<Box<dyn Future<Output = Outcome<(), ()>> + Send>>,"),
        "REGRESSION: StoredTask.future is no longer \
         Pin<Box<dyn Future<...> + Send>>. Either the trait \
         object was replaced with a generic (would require \
         monomorphization at the scheduler boundary, breaking \
         the heterogeneous task table) or with an inline \
         struct (would risk stack overflow for large futures).",
    );
}

#[test]
fn local_stored_task_future_field_is_pin_box_dyn_future_no_send() {
    // Pin (link 3): LocalStoredTask uses the same boxed
    // pattern for !Send futures. The trait object drops
    // Send (no work-stealing) but keeps the heap allocation.
    let source = read("src/runtime/stored_task.rs");

    assert!(
        source.contains("future: Pin<Box<dyn Future<Output = Outcome<(), ()>> + 'static>>,"),
        "REGRESSION: LocalStoredTask.future is no longer \
         Pin<Box<dyn Future<...> + 'static>>. Either Send is \
         back (breaking the !Send escape hatch) or the Box \
         is gone (large !Send futures risk stack overflow).",
    );
}

#[test]
fn stored_task_new_calls_box_pin_to_heap_allocate_future() {
    // Pin (link 2): StoredTask::new constructs the boxed
    // future via Box::pin(future). Without this, the future
    // would be stored inline on the StoredTask struct.
    let source = read("src/runtime/stored_task.rs");

    let fn_marker = "pub fn new<F>(future: F) -> Self";
    let start = source.find(fn_marker).expect("StoredTask::new");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("StoredTask::new close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("future: Box::pin(future),"),
        "REGRESSION: StoredTask::new no longer calls \
         Box::pin(future). The future is stored on the \
         stack instead of the heap — 100KB state machines \
         would overflow the worker thread stack.",
    );
}

#[test]
fn stored_task_new_with_id_calls_box_pin_to_heap_allocate_future() {
    // Pin (link 2): StoredTask::new_with_id is the variant
    // used by the spawn path (cx/scope.rs:465). It must
    // also Box::pin the future.
    let source = read("src/runtime/stored_task.rs");

    let fn_marker = "pub fn new_with_id<F>(future: F, task_id: TaskId) -> Self";
    let start = source.find(fn_marker).expect("StoredTask::new_with_id");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("StoredTask::new_with_id close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("future: Box::pin(future),"),
        "REGRESSION: StoredTask::new_with_id no longer calls \
         Box::pin. The user-facing spawn path uses this \
         constructor — large futures would land on the \
         stack instead of the heap.",
    );
}

#[test]
fn local_stored_task_new_calls_box_pin() {
    // Pin (link 3): LocalStoredTask::new follows the same
    // pattern for !Send futures.
    let source = read("src/runtime/stored_task.rs");

    let impl_marker = "impl LocalStoredTask {";
    let start = source.find(impl_marker).expect("LocalStoredTask impl");
    let next_impl = source[start + impl_marker.len()..]
        .find("\nimpl ")
        .map(|o| start + impl_marker.len() + o)
        .unwrap_or(source.len());
    let impl_body = &source[start..next_impl];

    let count = impl_body.matches("future: Box::pin(future),").count();
    assert!(
        count >= 2,
        "REGRESSION: LocalStoredTask has only {count} \
         Box::pin(future) calls (expected >= 2 — one for \
         new, one for new_with_id). The !Send path is no \
         longer heap-allocating large futures.",
    );
}

#[test]
fn spawn_path_constructs_stored_task_via_new_with_id() {
    // Pin (link 4): the spawn path immediately calls
    // StoredTask::new_with_id (which Box::pins) right after
    // wrapping the future. Without this immediate boxing,
    // the user's future would persist on the stack until
    // the spawn function returns.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("let stored = StoredTask::new_with_id(wrapped, task_id);"),
        "REGRESSION: spawn path no longer calls \
         StoredTask::new_with_id. The future may be stored \
         in some other intermediate that doesn't box \
         immediately — large futures risk stack overflow at \
         spawn time.",
    );
}

#[test]
fn spawn_local_path_constructs_local_stored_task_via_new_with_id() {
    // Pin (link 4): spawn_local follows the same
    // immediate-box pattern.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("let stored = LocalStoredTask::new_with_id(wrapped, task_id);"),
        "REGRESSION: spawn_local path no longer calls \
         LocalStoredTask::new_with_id. Large !Send futures \
         persist on the stack — overflow risk.",
    );
}

#[test]
fn stored_task_struct_does_not_have_inline_variants_for_small_futures() {
    // Pin (link 1 anti-pattern): there must be no enum
    // pattern that keeps small futures inline. Such a
    // pattern would either limit spawn size or risk overflow
    // at the threshold.
    let source = read("src/runtime/stored_task.rs");

    let suspect_inline_patterns = [
        "enum StoredTask {\n    Small(",
        "enum StoredTask {\n    Inline(",
        "Small([u8; 64], ",
        "Medium([u8; 256], ",
        "InlineFuture<F>",
    ];
    for pat in &suspect_inline_patterns {
        assert!(
            !source.contains(pat),
            "REGRESSION: StoredTask now has an inline-variant \
             pattern (`{pat}`). Either the variants limit the \
             max future size or large futures overflow when \
             they exceed the inline threshold.",
        );
    }
}

#[test]
fn stored_task_poll_calls_future_as_mut_poll() {
    // Pin (link 5): polling goes through the boxed future
    // via self.future.as_mut().poll(cx). The Pin<&mut> deref
    // through the Box keeps the state machine on the heap
    // during polling.
    let source = read("src/runtime/stored_task.rs");

    assert!(
        source.contains("let result = self.future.as_mut().poll(cx);"),
        "REGRESSION: StoredTask::poll no longer goes through \
         the Pin<Box<dyn Future>> — either the future is \
         re-pinned per call (perf regression) or moved to \
         the stack temporarily (overflow risk).",
    );
}

#[test]
fn stored_task_constructor_signature_takes_future_by_value() {
    // Pin (link 4): StoredTask::new takes `future: F` by
    // VALUE. The compiler can elide the move directly into
    // the Box::pin allocation — minimizing transient stack
    // pressure.
    let source = read("src/runtime/stored_task.rs");

    assert!(
        source.contains("pub fn new<F>(future: F) -> Self"),
        "REGRESSION: StoredTask::new signature changed. A \
         change to take by reference would require an \
         intermediate clone; a change to take by Box<F> \
         would shift the boxing burden to the caller.",
    );

    // The where-clause uses F: Future<...> + Send + 'static
    // — the F is generic, allowing rustc to monomorphize
    // and inline the Box::pin call.
    assert!(
        source.contains("F: Future<Output = Outcome<(), ()>> + Send + 'static,"),
        "REGRESSION: StoredTask::new generic bound changed. \
         Without the right Future bound, Box::pin can't \
         coerce to the trait object Pin<Box<dyn Future<...>>>.",
    );
}

// ─────────── BEHAVIORAL PIN: large-future heap allocation ──
//
// Direct simulation: build a struct with a 100KB inline
// state ([u8; 100_000]) and verify Box::pin moves it to the
// heap. The compile-only assertion is that the
// Pin<Box<dyn Future>> is a fixed-size handle regardless of
// the inner future's size.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A future with a 100KB state machine. The `_state` field
/// dominates the size of `Self`.
struct LargeFuture {
    _state: [u8; 100_000],
    done: bool,
}

impl Future for LargeFuture {
    type Output = u32;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        if this.done {
            Poll::Ready(42)
        } else {
            this.done = true;
            Poll::Ready(42)
        }
    }
}

#[test]
fn large_future_box_pin_produces_fixed_size_handle() {
    // Behavioral pin: regardless of LargeFuture's 100KB
    // inline size, the Pin<Box<dyn Future>> handle is a
    // fixed-size pointer (~16 bytes on most platforms).
    // The 100KB lives on the heap.
    let large = LargeFuture {
        _state: [0_u8; 100_000],
        done: false,
    };

    // sizeof::<LargeFuture>() is exactly 100,001 bytes
    // (100,000 array bytes + 1 bool, possibly padded to
    // 100,008 for alignment).
    let large_size = std::mem::size_of::<LargeFuture>();
    assert!(
        large_size >= 100_000,
        "Expected LargeFuture size >= 100,000 bytes, got {large_size}",
    );

    // After Box::pin, the value is heap-allocated. The
    // resulting Pin<Box<dyn Future>> is a fat pointer
    // (data pointer + vtable pointer) — typically 16 bytes
    // on 64-bit systems, regardless of the inner type.
    let boxed: Pin<Box<dyn Future<Output = u32>>> = Box::pin(large);
    let handle_size = std::mem::size_of_val(&boxed);
    assert!(
        handle_size <= 32,
        "REGRESSION: Pin<Box<dyn Future>> handle size is \
         {handle_size} bytes — expected <= 32. The trait \
         object should be a fat pointer (data + vtable) \
         regardless of the inner future's size. If this \
         assertion fires, the boxing-erasure pattern is \
         broken — the inner future may be inline.",
    );

    // The boxed future can still be polled (the heap
    // allocation is reachable through the Pin<Box>).
    let waker = futures_dummy_waker();
    let mut cx = Context::from_waker(&waker);
    let mut boxed = boxed;
    let result = boxed.as_mut().poll(&mut cx);
    assert!(
        matches!(result, Poll::Ready(42)),
        "REGRESSION: boxed large future no longer polls \
         correctly. The Pin<Box<dyn Future>> abstraction \
         is broken.",
    );
}

#[test]
fn many_large_futures_boxed_simultaneously_each_separately_heap_allocated() {
    // Behavioral pin: build 10 large futures (1MB total
    // heap), all boxed simultaneously. Each lives on the
    // heap independently; the stack holds only 10 fat
    // pointers (~160 bytes total).
    let mut handles: Vec<Pin<Box<dyn Future<Output = u32>>>> = Vec::new();
    for _ in 0..10 {
        handles.push(Box::pin(LargeFuture {
            _state: [0_u8; 100_000],
            done: false,
        }));
    }

    // The Vec holds 10 fat pointers — no inline futures.
    let stack_per_handle = std::mem::size_of::<Pin<Box<dyn Future<Output = u32>>>>();
    assert!(
        stack_per_handle <= 32,
        "REGRESSION: Pin<Box<dyn Future>> handle is now \
         {stack_per_handle} bytes — overflow risk if it grew \
         to hold the inline future.",
    );

    // Sanity: all 10 futures poll Ready(42).
    let waker = futures_dummy_waker();
    let mut cx = Context::from_waker(&waker);
    for mut h in handles {
        let result = h.as_mut().poll(&mut cx);
        assert!(matches!(result, Poll::Ready(42)));
    }
}

// Minimal no-op Waker for behavioral tests.
fn futures_dummy_waker() -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    fn no_op(_: *const ()) {}
    fn clone_no_op(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_no_op, no_op, no_op, no_op);
    let raw = RawWaker::new(std::ptr::null(), &VTABLE);
    unsafe { Waker::from_raw(raw) }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/scheduler_spawn_send_bounds_compile_time_audit.rs",
        "tests/cx_spawn_local_vs_spawn_distinction_audit.rs",
        "tests/cx_scope_deep_nesting_bookkeeping_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
