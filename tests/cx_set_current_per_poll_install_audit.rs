//! Audit + regression test for `Cx::set_current()` storage
//! semantics.
//!
//! Operator's question: "set_current should be the explicit
//! Cx-handoff API (vs implicit propagation via async fn).
//! Verify it correctly updates per-task-local Cx storage.
//! If only stores in thread-local (incorrect for async),
//! file bead. If task-local, pin behavior."
//!
//! Audit findings: **SOUND BY DESIGN — multi-layered**.
//!
//! The framing in the operator's question conflates two
//! mechanisms that asupersync deliberately keeps separate:
//!
//! 1. **PRIMARY (explicit handoff)**: every async fn takes
//!    `&Cx` as first parameter. The Cx flows through
//!    function arguments — this is the canonical
//!    structured-concurrency capability propagation. The
//!    Cx is OWNED by the spawned task's record (StoredTask
//!    / TaskRecord) and travels with the task through
//!    suspension/resumption.
//!
//! 2. **SECONDARY (ambient lookup)**: `Cx::current()` /
//!    `Cx::set_current()` provide an AMBIENT lookup for
//!    code that doesn't have a `&Cx` parameter (panic
//!    handlers, Drop impls, observability hooks). Backed
//!    by a thread-local stack reinstalled per-poll by the
//!    scheduler.
//!
//! ── Per-task storage IS correct ─────────────────────────
//!
//! The Cx struct itself is the per-task storage:
//!
//! ```ignore
//! pub struct Cx<Caps = cap::All> {
//!     inner: Arc<RwLock<CxInner>>,         // shared state
//!     observability: Arc<Observability>,    // shared state
//!     handles: Arc<RuntimeHandles>,         // shared state
//!     runtime_mask: cap::CapMask,
//!     _caps: PhantomData<Caps>,
//! }
//! ```
//!
//! Each spawned task gets ITS OWN Cx instance owned by
//! its TaskRecord. The Arc-wrapped fields share the
//! cancel state, observability, and handles across the
//! task's lifetime — surviving thread migration in the
//! work-stealing scheduler.
//!
//! ── Per-poll thread-local re-install ─────────────────────
//!
//! `src/runtime/scheduler/three_lane.rs:5265` shows the
//! per-poll install pattern:
//!
//! ```ignore
//! let _cx_guard = crate::cx::Cx::set_current(task_cx);
//! let mut guard = TaskExecutionGuard { ... };
//! let poll_result = std::panic::catch_unwind(...);
//! // _cx_guard drops here — thread-local frame popped
//! ```
//!
//! Critical properties:
//!
//! - Each poll() call installs a FRESH thread-local frame.
//! - The frame is dropped via RAII when the poll returns.
//! - The Cx itself persists in the TaskRecord between
//!   polls; only the thread-local mirror is transient.
//! - Across thread migration, the Cx is reinstalled on
//!   the new thread by the scheduler before polling.
//!
//! ── The thread-local is a STACK, not a single slot ──────
//!
//! `CURRENT_CX_STACK: RefCell<Vec<CurrentCxFrame>>` (cx.rs:312)
//! supports nested installation — useful for restricted-
//! capability sub-contexts (`set_current_restricted`,
//! `push_restriction`). Each push is matched by a guard
//! drop. (br-asupersync-5ckssb)
//!
//! ── Why not "task-local" via OS-thread TLS ──────────────
//!
//! A "task-local" via per-task TLS would be wrong for
//! asupersync because:
//!
//! 1. Tasks migrate between worker threads (work-stealing
//!    scheduler). Per-task TLS would need to be migrated
//!    too — extra mechanism for no benefit.
//! 2. Sub-tasks within the same poll() share the Cx via
//!    explicit `&Cx` propagation. TLS lookups from inside
//!    a poll add lookup cost vs argument access.
//! 3. The `&Cx` argument IS the per-task handle. The
//!    thread-local is the AMBIENT mirror.
//!
//! ── Defense against ambient-authority leak ──────────────
//!
//! `set_current_restricted` and `push_restriction`
//! (cx.rs:507, 533) let a caller install a NARROWED
//! capability mask. Untrusted callees that reach for
//! ambient Cx via `Cx::current()` see the narrowed mask,
//! preventing capability escape via thread-local lookup.
//! See br-asupersync-5ckssb.
//!
//! ── Drop-during-teardown safety ─────────────────────────
//!
//! `CurrentCxGuard::drop` uses `try_with(...)` rather than
//! `with(...)` so that pop attempts during thread-local
//! teardown don't trigger double-panic abort.
//!
//! Verdict: **SOUND BY DESIGN**. Per-task Cx storage is
//! the Cx struct itself owned by the TaskRecord. The
//! thread-local stack is the per-poll ambient mirror,
//! reinstalled freshly by the scheduler around every
//! poll. Async fn argument propagation is the primary
//! handoff API; set_current is the secondary ambient
//! mechanism. Both layers cooperate to give correct
//! Cx visibility across thread migration.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cx_set_current_returns_raii_guard() {
    // Pin: set_current returns a CurrentCxGuard that
    // pops the thread-local frame on drop. Without RAII,
    // panics would leave stale frames.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub(crate) fn set_current(cx: Option<Self>) -> CurrentCxGuard {")
            || source.contains("pub fn set_current(cx: Option<Self>) -> CurrentCxGuard {"),
        "REGRESSION: Cx::set_current no longer returns \
         CurrentCxGuard. The RAII pop-on-drop pattern is \
         broken — stale thread-local frames may persist \
         across panics or returns.",
    );
}

#[test]
fn current_cx_storage_is_a_stack_not_a_single_slot() {
    // Pin: the storage is `RefCell<Vec<CurrentCxFrame>>`.
    // A single Option slot would not support nested
    // restricted-cap installations.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("static CURRENT_CX_STACK: RefCell<Vec<CurrentCxFrame>>"),
        "REGRESSION: CURRENT_CX_STACK is no longer a \
         RefCell<Vec<CurrentCxFrame>>. Nested capability-\
         restricted installations are broken.",
    );

    // The frame must carry both cx AND mask.
    assert!(
        source.contains("struct CurrentCxFrame {")
            && source.contains("cx: FullCx,")
            && source.contains("mask: cap::CapMask,"),
        "REGRESSION: CurrentCxFrame no longer holds (cx, \
         mask). Capability attenuation via the ambient \
         lookup is broken.",
    );
}

#[test]
fn current_cx_guard_pops_via_try_with_for_teardown_safety() {
    // Pin: drop uses try_with(...).pop() to avoid double-
    // panic during TLS teardown.
    let source = read("src/cx/cx.rs");

    let drop_marker = "impl Drop for CurrentCxGuard {";
    let pos = source.find(drop_marker).expect("CurrentCxGuard Drop impl");
    let body_end = source[pos..]
        .find("\n}\n")
        .expect("Drop impl close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("CURRENT_CX_STACK.try_with("),
        "REGRESSION: CurrentCxGuard::drop no longer uses \
         try_with for TLS access. Drop during thread-local \
         teardown will trigger double-panic abort.",
    );

    assert!(
        body.contains("stack.borrow_mut().pop();"),
        "REGRESSION: CurrentCxGuard::drop no longer pops \
         the stack frame.",
    );
}

#[test]
fn cx_current_walks_stack_and_returns_innermost() {
    // Pin: Cx::current() returns the INNERMOST installed
    // frame (last on stack). This gives nested restricted
    // installations the correct narrowed view.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn current() -> Option<Self> {";
    let pos = source.find(fn_marker).expect("Cx::current fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("Cx::current close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("slot.borrow().last()"),
        "REGRESSION: Cx::current no longer reads .last() of \
         the stack. Nested-frame innermost-wins semantic is \
         broken.",
    );

    assert!(
        body.contains("cx.runtime_mask = frame.mask;"),
        "REGRESSION: Cx::current no longer applies the \
         frame's narrowed mask. Capability attenuation via \
         ambient lookup is broken.",
    );
}

#[test]
fn cx_current_uses_try_with_for_teardown_safety() {
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn current() -> Option<Self> {";
    let pos = source.find(fn_marker).expect("Cx::current fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("Cx::current close");
    let body = &source[pos..pos + body_end];

    // The call site is split across lines:
    //   CURRENT_CX_STACK
    //       .try_with(|slot| {
    // so check both fragments.
    assert!(
        body.contains("CURRENT_CX_STACK") && body.contains(".try_with("),
        "REGRESSION: Cx::current no longer uses try_with \
         for TLS access.",
    );

    assert!(
        body.contains(".unwrap_or(None)") || body.contains(".ok().flatten()"),
        "REGRESSION: Cx::current no longer falls back \
         gracefully on TLS access failure.",
    );
}

#[test]
fn scheduler_installs_cx_per_poll() {
    // Pin: the scheduler calls Cx::set_current(task_cx)
    // BEFORE polling each task. This is the per-poll
    // re-install that handles thread migration.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("let _cx_guard = crate::cx::Cx::set_current(task_cx);"),
        "REGRESSION: scheduler no longer installs the \
         task's Cx via set_current before polling. Tasks \
         migrating between worker threads will not have \
         their Cx mirrored to the new thread's TLS — \
         ambient Cx::current() lookups in async code \
         will return None or stale.",
    );
}

#[test]
fn scheduler_install_is_raii_guard_dropped_after_poll() {
    // Pin: the install is via a guard that drops AFTER
    // the poll returns. Without this, the thread-local
    // frame leaks beyond the poll boundary.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let install_marker = "let _cx_guard = crate::cx::Cx::set_current(task_cx);";
    let pos = source.find(install_marker).expect("set_current install");
    let window = &source[pos..pos + 1500];

    assert!(
        window.contains("std::panic::catch_unwind(") && window.contains("stored.poll("),
        "REGRESSION: scheduler no longer wraps the poll() \
         call in catch_unwind after installing Cx. Either \
         panic safety or the install order has changed.",
    );
}

#[test]
fn scheduler_install_documented_for_panic_unwind_ordering() {
    // Pin: the comment documenting the install-BEFORE-
    // TaskExecutionGuard ordering must remain. Future
    // maintainers may otherwise reorder the guards.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("Install the task context BEFORE creating TaskExecutionGuard"),
        "REGRESSION: the panic-unwind ordering comment is \
         gone. Future maintainers may reorder the guards \
         and break Cx access from drop handlers.",
    );
}

#[test]
fn cx_struct_uses_arc_for_per_task_shared_state() {
    // Pin: the Cx struct's per-task state is Arc-shared,
    // so it survives thread migration intact.
    let source = read("src/cx/cx.rs");

    let suspect_field_patterns = [
        "inner: Arc<",
        "observability: Arc<",
        "handles: Arc<",
    ];
    for pat in &suspect_field_patterns {
        assert!(
            source.contains(pat),
            "REGRESSION: Cx field starting with `{pat}` is \
             gone. Cx state is no longer Arc-wrapped — \
             tasks migrating across threads may not \
             preserve cancel state, observability, or \
             handle references.",
        );
    }
}

#[test]
fn set_current_restricted_for_capability_attenuation() {
    // Pin: set_current_restricted exists and pushes with
    // a narrowed mask.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn set_current_restricted(self) -> CurrentCxGuard {"),
        "REGRESSION: set_current_restricted is gone. \
         Untrusted callees can no longer be sandboxed via \
         a narrowed ambient mask.",
    );

    let fn_marker = "pub fn set_current_restricted(self) -> CurrentCxGuard {";
    let pos = source.find(fn_marker).expect("set_current_restricted fn");
    let body = &source[pos..pos + 800];

    assert!(
        body.contains("<Caps as cap::CapSetRuntimeMask>::MASK"),
        "REGRESSION: set_current_restricted no longer \
         derives the mask from the type-level Caps \
         parameter. Capability attenuation is broken.",
    );
}

#[test]
fn push_restriction_intersects_with_existing_mask() {
    // Pin: push_restriction can only NARROW the mask,
    // never widen it. Without this, untrusted code could
    // push a wider restriction frame and re-acquire caps.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn push_restriction(mask: cap::CapMask) -> CurrentCxGuard {";
    let pos = source.find(fn_marker).expect("push_restriction fn");
    let body = &source[pos..pos + 1500];

    assert!(
        body.contains("intersect(mask)") || body.contains(".intersect("),
        "REGRESSION: push_restriction no longer intersects \
         with the current mask. A push could now WIDEN \
         the mask — capability escape vector.",
    );
}

#[test]
fn explicit_cx_argument_pattern_documented_in_agents_md() {
    // Pin: AGENTS.md documents the "every async fn takes &Cx
    // as first parameter" pattern. If this doc is lost, the
    // distinction between explicit handoff (primary) and
    // ambient lookup (secondary) blurs.
    let source = read("AGENTS.md");

    assert!(
        source.contains("Pattern**: All async functions take `&Cx` as first parameter")
            || source.contains("All async functions take `&Cx`"),
        "REGRESSION: AGENTS.md no longer documents the \
         &Cx-first-parameter pattern. The primary explicit-\
         handoff convention is no longer canonical.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
struct MockCx {
    id: u64,
    state: Arc<AtomicU64>,
}

thread_local! {
    static CURRENT_CX: RefCell<Vec<MockCx>> = const { RefCell::new(Vec::new()) };
}

struct Guard {
    pushed: bool,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if self.pushed {
            let _ = CURRENT_CX.try_with(|c| {
                c.borrow_mut().pop();
            });
        }
    }
}

fn set_current(cx: Option<MockCx>) -> Guard {
    let pushed = CURRENT_CX.with(|c| match cx {
        Some(cx) => {
            c.borrow_mut().push(cx);
            true
        }
        None => false,
    });
    Guard { pushed }
}

fn current_cx() -> Option<MockCx> {
    CURRENT_CX
        .try_with(|c| c.borrow().last().cloned())
        .unwrap_or(None)
}

#[test]
fn behavioral_set_current_pushes_and_drop_pops() {
    let cx = MockCx {
        id: 1,
        state: Arc::new(AtomicU64::new(0)),
    };
    assert!(current_cx().is_none());

    let guard = set_current(Some(cx.clone()));
    let observed = current_cx().expect("installed");
    assert_eq!(observed.id, 1);

    drop(guard);
    assert!(current_cx().is_none());
}

#[test]
fn behavioral_nested_installs_innermost_wins() {
    let outer = MockCx {
        id: 10,
        state: Arc::new(AtomicU64::new(0)),
    };
    let inner = MockCx {
        id: 20,
        state: Arc::new(AtomicU64::new(0)),
    };

    let _g1 = set_current(Some(outer));
    assert_eq!(current_cx().unwrap().id, 10);

    {
        let _g2 = set_current(Some(inner));
        assert_eq!(
            current_cx().unwrap().id,
            20,
            "REGRESSION: nested set_current did not return \
             innermost. The stack-based ambient lookup is \
             broken.",
        );
    }

    assert_eq!(
        current_cx().unwrap().id,
        10,
        "REGRESSION: after inner guard drop, outer is not \
         restored. Stack push/pop is broken.",
    );
}

#[test]
fn behavioral_per_task_state_persists_across_thread_migration() {
    // Models a task whose Cx is owned by the TaskRecord
    // (Arc-shared state). The runtime polls it on thread A,
    // then on thread B. The shared state is observable on
    // both threads.
    let task_cx = MockCx {
        id: 100,
        state: Arc::new(AtomicU64::new(0)),
    };

    // Poll on "thread A": runtime installs cx, increments
    // shared state, drops install.
    let task_a = task_cx.clone();
    let handle_a = std::thread::spawn(move || {
        let _g = set_current(Some(task_a));
        let observed = current_cx().expect("installed on A");
        observed.state.fetch_add(1, Ordering::Relaxed);
    });
    handle_a.join().unwrap();

    // Cx state should now be 1.
    assert_eq!(task_cx.state.load(Ordering::Relaxed), 1);

    // Poll on "thread B": same Cx (cloned Arc), runtime
    // installs again, increments again.
    let task_b = task_cx.clone();
    let handle_b = std::thread::spawn(move || {
        let _g = set_current(Some(task_b));
        let observed = current_cx().expect("installed on B");
        observed.state.fetch_add(1, Ordering::Relaxed);
    });
    handle_b.join().unwrap();

    // Shared state survived thread migration.
    assert_eq!(
        task_cx.state.load(Ordering::Relaxed),
        2,
        "REGRESSION: per-task Cx state did not survive \
         thread migration. The Arc-shared design is \
         broken.",
    );
}

#[test]
fn behavioral_thread_local_does_not_leak_across_threads() {
    // Models the per-poll thread-local install: thread A
    // installs cx, thread B has no Cx in its own TLS.
    let task_cx = MockCx {
        id: 200,
        state: Arc::new(AtomicU64::new(0)),
    };

    let cx_for_a = task_cx.clone();
    let handle_a = std::thread::spawn(move || {
        let _g = set_current(Some(cx_for_a));
        // Inside this thread, current_cx is Some.
        assert!(current_cx().is_some());
    });
    handle_a.join().unwrap();

    // On a fresh thread, no Cx is installed (thread-local
    // is per-thread).
    let handle_b = std::thread::spawn(|| {
        assert!(
            current_cx().is_none(),
            "REGRESSION: thread B sees a Cx that was \
             installed on thread A. The thread-local is \
             leaking across threads — per-poll re-install \
             discipline is broken."
        );
    });
    handle_b.join().unwrap();
}

#[test]
fn behavioral_explicit_argument_works_without_ambient() {
    // Models the PRIMARY handoff: pass &Cx as a function
    // argument. No ambient install needed.
    fn do_work(cx: &MockCx) -> u64 {
        cx.state.fetch_add(1, Ordering::Relaxed);
        cx.state.load(Ordering::Relaxed)
    }

    let cx = MockCx {
        id: 300,
        state: Arc::new(AtomicU64::new(0)),
    };

    // No set_current install. Function takes &Cx.
    assert!(current_cx().is_none());
    let result = do_work(&cx);
    assert_eq!(result, 1);
    assert_eq!(cx.state.load(Ordering::Relaxed), 1);
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_api_decision_tree_with_vs_scope_audit.rs",
        "tests/runtime_current_handle_returns_option_not_panic_audit.rs",
        "tests/cx_drop_semantics_parent_persistence_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
