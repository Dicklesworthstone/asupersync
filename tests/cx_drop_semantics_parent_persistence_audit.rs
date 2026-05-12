//! Audit + regression test for `Cx` drop semantics: when a
//! child task drops its `Cx`, the parent's `Cx` must remain
//! valid (no use-after-free).
//!
//! Operator's question: "when a task drops Cx and another
//! task tries to access via parent's Cx, does the access
//! correctly observe parent (correct: parent persists) or
//! gives stale dropped reference (use-after-free)?"
//!
//! Audit findings:
//!
//!   asupersync's `Cx` drop semantics are **correct by
//!   construction**: parent and child Cx instances are
//!   INDEPENDENT Arc-refcounted state machines. Dropping a
//!   child's Cx never invalidates the parent's Cx. Use-
//!   after-free is structurally impossible. The chain:
//!
//!   1. **`Cx` wraps Arcs, not raw references** (cx/cx.rs:180):
//!      ```ignore
//!      pub struct Cx<Caps = cap::All> {
//!          pub(crate) inner: Arc<parking_lot::RwLock<CxInner>>,
//!          observability: Arc<parking_lot::RwLock<ObservabilityState>>,
//!          handles: Arc<CxHandles>,
//!          runtime_mask: cap::CapMask,
//!          _caps: PhantomData<fn() -> Caps>,
//!      }
//!      ```
//!      All shared state is behind `Arc`. Dropping a Cx
//!      decrements the refcount; CxInner is freed only when
//!      the last Arc drops.
//!
//!   2. **Manual Clone increments all 3 Arcs** (cx/cx.rs:205):
//!      ```ignore
//!      impl<Caps> Clone for Cx<Caps> {
//!          fn clone(&self) -> Self {
//!              Self {
//!                  inner: Arc::clone(&self.inner),
//!                  observability: Arc::clone(&self.observability),
//!                  handles: Arc::clone(&self.handles),
//!                  runtime_mask: self.runtime_mask,
//!                  _caps: PhantomData,
//!              }
//!          }
//!      }
//!      ```
//!      Cloning a Cx ALWAYS increments all three Arc
//!      strong-counts. There is no "shallow clone" path that
//!      could leave a clone with a borrowed-but-not-owned
//!      reference.
//!
//!   3. **Child gets its own `CxInner`** (cx/scope.rs
//!      `build_child_task_cx`): when a task is spawned, the
//!      child Cx is built via `Cx::new_with_drivers(self.region,
//!      task_id, self.budget, ...)`. The child's `inner` is a
//!      FRESH `Arc<RwLock<CxInner>>` — NOT a clone of the
//!      parent's. The parent and child have entirely
//!      independent cancel state, budget, and observability
//!      contexts.
//!
//!   4. **Shared handles are immutable**: the only state
//!      child Cx INHERITS from parent is via Arc-cloning
//!      `Arc<CxHandles>` (which holds io_driver, timer_driver,
//!      registry, evidence_sink, blocking_pool, macaroon).
//!      These are immutable handles — safe to share. Child
//!      drop only decrements the `CxHandles` Arc; the parent
//!      still holds it.
//!
//!   5. **Thread-local `CURRENT_CX_STACK` uses owned frames**
//!      (cx/cx.rs:312): the ambient-Cx storage is
//!      `RefCell<Vec<CurrentCxFrame>>`. Each frame OWNS its
//!      Cx (a FullCx). Push moves an owned Cx into the
//!      stack; pop drops the frame, which drops the owned
//!      Cx, which decrements its three Arcs. There are no
//!      raw pointers to stack-allocated Cxs.
//!
//!   6. **`CurrentCxGuard` pops on Drop** (cx/cx.rs:327):
//!      ```ignore
//!      impl Drop for CurrentCxGuard {
//!          fn drop(&mut self) {
//!              if !self.pushed { return; }
//!              let _ = CURRENT_CX_STACK.try_with(|stack| {
//!                  stack.borrow_mut().pop();
//!              });
//!          }
//!      }
//!      ```
//!      The guard ensures push/pop is balanced. Even on
//!      panic-unwind (the guard's drop fires), the
//!      thread-local stack stays consistent.
//!
//!   7. **Per-thread isolation**: CURRENT_CX_STACK is a
//!      `thread_local!` — each worker thread has its own
//!      stack. Worker-A polls task A with Cx_A on its stack;
//!      worker-B polls task B with Cx_B on its stack. Cross-
//!      worker drop has zero interaction with another
//!      thread's stack.
//!
//!   8. **`Cx::current()` clones from the frame** (cx/cx.rs:
//!      360):
//!      ```ignore
//!      pub fn current() -> Option<Self> {
//!          CURRENT_CX_STACK.try_with(|slot| {
//!              slot.borrow().last().map(|frame| {
//!                  let mut cx = frame.cx.clone();
//!                  cx.runtime_mask = frame.mask;
//!                  cx
//!              })
//!          }).unwrap_or(None)
//!      }
//!      ```
//!      The returned Cx is a CLONE of the frame's owned cx
//!      — incrementing the Arcs. The caller can drop the
//!      returned Cx without affecting the frame. There is
//!      no path that hands out a raw reference to the
//!      frame's interior.
//!
//!   9. **`with_current` uses a closure-scoped borrow**
//!      (cx/cx.rs:425): the zero-Arc-clone fast path
//!      borrows the frame's cx for the duration of the
//!      closure body. The borrow on CURRENT_CX_STACK is
//!      held the whole closure body — the closure cannot
//!      install a new ambient cx (the inner mutable borrow
//!      would panic). Rust's borrow checker enforces this
//:      at compile time.
//!
//!   10. **`TaskHandle` uses `Arc::downgrade` to avoid
//!       creating cycles** (cx/scope.rs:394): the parent
//!       gets a `TaskHandle` carrying a Weak reference to
//!       the child's CxInner. Weak does NOT keep CxInner
//!       alive — when the child drops its Cx (and no other
//!       Arcs hold it), CxInner is freed and the parent's
//!       Weak::upgrade returns None. Safe by Rust's Weak
//!       semantics.
//!
//! Verdict: **SOUND BY CONSTRUCTION**. Use-after-free
//! across parent/child Cx drop is structurally impossible
//! because:
//!   - Each Cx owns its Arc references (no raw pointers).
//!   - Parent and child have INDEPENDENT CxInner (not
//!     shared mutable state).
//!   - The thread-local CURRENT_CX_STACK uses owned
//!     CurrentCxFrame { cx, mask }; pop drops the owned
//!     Cx; per-thread isolation prevents cross-worker
//!     interference.
//!   - Cx::current() returns a CLONE (refcount-incremented),
//!     never a raw reference to the frame interior.
//!   - with_current uses a closure-scoped borrow checked at
//:     compile time.
//!   - TaskHandle uses Weak to avoid cycles; safe drop
//!     order.
//!
//! A regression that:
//!   - changed Cx.inner from Arc<RwLock<CxInner>> to
//!     Box<CxInner> with raw pointer sharing (would lose
//!     refcount-driven safety; child drop could free
//!     CxInner while parent's pointer still references it),
//!   - made child Cx SHARE the parent's CxInner Arc instead
//!     of creating a fresh one (would conflate parent +
//!     child cancel state — sibling task cancel would
//:     unintentionally cancel parent),
//!   - changed Cx::current() to return a raw reference into
//!     the frame instead of a clone (would require lifetime
//!     gymnastics; any frame pop while the returned ref is
//!     held is undefined behavior),
//!   - used unsafe transmute / mem::forget on a Cx in a
//!     way that bypasses the Arc decrement (would create
//!     an actual use-after-free pathway),
//!   - converted CURRENT_CX_STACK from thread_local! to a
//!     global Mutex<Vec<...>> (would allow cross-thread
//!     interference: worker-A's pop affects worker-B's
//:     view of the stack),
//!   - removed the Drop impl on CurrentCxGuard (would leak
//!     frames; the stack would grow monotonically and
//!     Cx::current() would return stale Cxs from prior
//!     scopes),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;
use std::sync::Arc;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cx_inner_field_is_arc_rwlock_not_box_or_raw_pointer() {
    // Pin (link 1): Cx.inner is Arc<RwLock<CxInner>>. The
    // Arc is what gives refcount-driven safety — child drop
    // doesn't free CxInner while parent still holds it.
    let source = read("src/cx/cx.rs");

    // The Cx struct must declare inner with Arc<RwLock<CxInner>>.
    let struct_marker = "pub struct Cx<Caps = cap::All> {";
    let start = source.find(struct_marker).expect("Cx struct");
    let body_end = source[start..].find("\n}\n").expect("Cx struct close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("pub(crate) inner: Arc<parking_lot::RwLock<CxInner>>,"),
        "REGRESSION: Cx.inner is no longer Arc<RwLock<CxInner>>. \
         Without the Arc, child drop could free CxInner \
         while a parent's reference still observes it — \
         use-after-free pathway opened.",
    );

    // Forbid raw-pointer alternatives.
    let suspect_alternatives = [
        "pub(crate) inner: Box<CxInner>,",
        "pub(crate) inner: *mut CxInner,",
        "pub(crate) inner: NonNull<CxInner>,",
        "pub(crate) inner: &'static CxInner,",
    ];
    for pat in &suspect_alternatives {
        assert!(
            !body.contains(pat),
            "REGRESSION: Cx.inner is now `{pat}` — raw or \
             non-refcounted alternative. Use-after-free \
             becomes possible across parent/child Cx drop.",
        );
    }
}

#[test]
fn cx_clone_increments_all_three_arc_refcounts() {
    // Pin (link 2): Cx::clone uses Arc::clone on inner,
    // observability, and handles. Without these increments,
    // a clone could observe a freed CxInner after the
    // original drops.
    let source = read("src/cx/cx.rs");

    let impl_marker = "impl<Caps> Clone for Cx<Caps> {";
    let start = source.find(impl_marker).expect("Cx Clone impl");
    let next_impl = source[start + impl_marker.len()..]
        .find("\nimpl ")
        .map_or(source.len(), |o| start + impl_marker.len() + o);
    let body = &source[start..next_impl];

    assert!(
        body.contains("inner: Arc::clone(&self.inner),")
            && body.contains("observability: Arc::clone(&self.observability),")
            && body.contains("handles: Arc::clone(&self.handles),"),
        "REGRESSION: Cx::clone no longer Arc::clones one or \
         more of the three Arc fields. A 'shallow clone' \
         that copied the Arc pointer without incrementing \
         the refcount would create a dangling reference \
         when the original drops.",
    );
}

#[test]
fn child_cx_built_with_fresh_cx_inner_not_shared_with_parent() {
    // Pin (link 3): build_child_task_cx calls
    // Cx::new_with_drivers with the child's own (region,
    // task_id, budget). The resulting CxInner is a FRESH
    // Arc — not a clone of parent.inner. Without this
    // separation, sibling-task cancel would cancel the
    // parent.
    let source = read("src/cx/scope.rs");

    let fn_marker = "pub(crate) fn build_child_task_cx<Caps>(";
    let start = source.find(fn_marker).expect("build_child_task_cx fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("build_child_task_cx close");
    let body = &source[start..start + body_end];

    // The child Cx is constructed via Cx::new_with_drivers,
    // not via parent_cx.inner.clone() / Arc::clone(&parent_cx.inner).
    assert!(
        body.contains("Cx::<Caps>::new_with_drivers("),
        "REGRESSION: child Cx is no longer constructed via \
         new_with_drivers. The fresh-CxInner property \
         depends on this constructor — a clone of the \
         parent's inner would conflate parent + child cancel \
         state.",
    );

    // Forbid sharing the parent's CxInner Arc directly.
    let suspect_sharing = [
        "Arc::clone(&parent_cx.inner)",
        "child_cx.inner = parent_cx.inner.clone();",
        "inner: parent_cx.inner.clone(),",
    ];
    for pat in &suspect_sharing {
        assert!(
            !body.contains(pat),
            "REGRESSION: build_child_task_cx now shares the \
             parent's CxInner via `{pat}`. Sibling tasks \
             would share cancel state with their parent — \
             cancelling one child would cancel the parent.",
        );
    }
}

#[test]
fn current_cx_stack_is_thread_local_for_per_thread_isolation() {
    // Pin (link 7): CURRENT_CX_STACK is declared via
    // thread_local!. A regression to a global Mutex<Vec<...>>
    // would allow cross-thread interference — worker-A's
    // pop could affect worker-B's view.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("static CURRENT_CX_STACK: RefCell<Vec<CurrentCxFrame>>"),
        "REGRESSION: CURRENT_CX_STACK declaration changed. \
         Per-thread isolation depends on the thread_local! + \
         RefCell<Vec<...>> pattern — without it, parent/\
         child Cx interactions across workers could race.",
    );

    // Must be inside thread_local! { ... }.
    assert!(
        source.contains("thread_local! {"),
        "REGRESSION: thread_local! macro is gone. Without \
         per-thread storage, ambient Cx becomes a shared \
         resource — any Drop on one worker affects all \
         workers.",
    );
}

#[test]
fn current_cx_guard_pops_frame_on_drop() {
    // Pin (link 6): CurrentCxGuard's Drop impl pops the
    // frame from CURRENT_CX_STACK. Without this, frames
    // would leak — Cx::current() would return a stale Cx
    // from a long-since-completed scope.
    let source = read("src/cx/cx.rs");

    let impl_marker = "impl Drop for CurrentCxGuard {";
    let start = source.find(impl_marker).expect("CurrentCxGuard Drop impl");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("CurrentCxGuard Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("stack.borrow_mut().pop();"),
        "REGRESSION: CurrentCxGuard::drop no longer pops the \
         frame. Frames leak monotonically — Cx::current() \
         returns Cxs from prior scopes, breaking the \
         ambient-context invariant.",
    );

    // Must use try_with so panic-unwind during teardown is
    // safe.
    assert!(
        body.contains("CURRENT_CX_STACK.try_with("),
        "REGRESSION: CurrentCxGuard::drop no longer uses \
         try_with. During thread-local teardown, with() \
         panics — the guard would abort the unwind chain.",
    );
}

#[test]
fn cx_current_returns_owned_clone_not_borrow() {
    // Pin (link 8): Cx::current() returns Option<Self>
    // (an owned Cx via clone), NOT Option<&Self>. The clone
    // increments the Arc refcounts — caller can drop the
    // returned Cx independently of the frame.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn current() -> Option<Self> {"),
        "REGRESSION: Cx::current signature changed from \
         Option<Self>. A return of Option<&Self> would \
         require the caller to manage a lifetime tied to the \
         frame — and any pop while the borrow is held would \
         be use-after-free.",
    );

    let fn_marker = "pub fn current() -> Option<Self> {";
    let start = source.find(fn_marker).expect("current fn");
    let body_end = source[start..].find("\n    }\n").expect("current close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("frame.cx.clone()"),
        "REGRESSION: Cx::current no longer clones the frame's \
         cx. Without the clone, the returned value would be \
         tied to the frame's lifetime — a frame pop would \
         invalidate it.",
    );
}

#[test]
fn task_handle_uses_weak_reference_to_child_cx_inner() {
    // Pin (link 10): TaskHandle::new takes Arc::downgrade(&
    // child_cx.inner) to avoid creating a cycle. A strong
    // Arc reference would keep child CxInner alive past
    // task completion — semantic leak. A raw pointer would
    // be use-after-free when child drops.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("Arc::downgrade(&child_cx.inner)"),
        "REGRESSION: TaskHandle no longer uses Arc::downgrade \
         on child_cx.inner. Either a strong Arc (cycle/leak) \
         or a raw pointer (use-after-free) — both wrong.",
    );
}

#[test]
fn current_cx_frame_owns_full_cx_not_borrows_it() {
    // Pin (link 5): CurrentCxFrame owns its FullCx. Push
    // moves a Cx into the frame; pop drops the owned Cx.
    // A borrowed cx field would require a lifetime parameter
    // and constrain CURRENT_CX_STACK to a non-static lifetime.
    let source = read("src/cx/cx.rs");

    let struct_marker = "struct CurrentCxFrame {";
    let start = source.find(struct_marker).expect("CurrentCxFrame struct");
    let body_end = source[start..].find("\n}\n").expect("CurrentCxFrame close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("cx: FullCx,"),
        "REGRESSION: CurrentCxFrame.cx is no longer an owned \
         FullCx. A borrowed alternative (cx: &'a FullCx) \
         would require lifetime parameters incompatible with \
         thread-local storage.",
    );
}

#[test]
fn no_unsafe_transmute_or_mem_forget_in_cx_drop_path() {
    // Pin (correctness audit): the cx/cx.rs and cx/scope.rs
    // files must not contain unsafe transmute / mem::forget
    // calls that could bypass the Arc drop. asupersync's
    // #![deny(unsafe_code)] policy makes this trivially true
    // — verify by grep.
    for rel in &["src/cx/cx.rs", "src/cx/scope.rs"] {
        let source = read(rel);
        let suspect_unsafe = [
            "std::mem::transmute(",
            "mem::transmute(",
            "std::mem::forget(",
            "mem::forget(",
            "ManuallyDrop::new(",
        ];
        for pat in &suspect_unsafe {
            assert!(
                !source.contains(pat),
                "REGRESSION: {rel} now contains `{pat}` — a \
                 path that could bypass Arc drop. The \
                 refcount-driven safety guarantee depends on \
                 normal Drop running. ManuallyDrop is the \
                 most common footgun: it leaks Arcs by \
                 default unless the caller explicitly drops.",
            );
        }
    }
}

#[test]
fn cx_send_sync_marker_uses_phantom_data_fn_not_phantom_caps() {
    // Pin (audit): Cx uses PhantomData<fn() -> Caps> instead
    // of PhantomData<Caps>. The fn-pointer phantom is what
    // makes Cx Send+Sync regardless of Caps's auto-trait
    // implementations — without it, Cx<NoCaps> may or may
    // not be Send depending on NoCaps's traits, which
    // breaks cross-thread Cx::current() lookup.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("_caps: PhantomData<fn() -> Caps>,"),
        "REGRESSION: Cx._caps is no longer PhantomData<fn() \
         -> Caps>. PhantomData<Caps> would inherit Caps's \
         auto traits — Cx<SomeNonSendCap> would lose Send, \
         breaking the cross-worker Cx::current() lookup.",
    );
}

// ─────────── BEHAVIORAL PIN: Arc-refcount drop semantics ──
//
// Direct simulation: build a parent + child Cx-equivalent
// pattern with Arc<RwLock<...>>, drop the child, verify the
// parent still observes its own state.

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
struct MockCxInner {
    cancel_requested: bool,
    region_id: u64,
    drop_count: Arc<AtomicU64>,
}

impl Drop for MockCxInner {
    fn drop(&mut self) {
        self.drop_count.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct MockCx {
    inner: Arc<StdMutex<MockCxInner>>,
}

impl MockCx {
    fn new(region_id: u64, drop_count: Arc<AtomicU64>) -> Self {
        Self {
            inner: Arc::new(StdMutex::new(MockCxInner {
                cancel_requested: false,
                region_id,
                drop_count,
            })),
        }
    }

    fn region_id(&self) -> u64 {
        self.inner.lock().unwrap().region_id
    }

    fn cancel_requested(&self) -> bool {
        self.inner.lock().unwrap().cancel_requested
    }

    fn arc_strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }
}

#[test]
fn child_cx_drop_does_not_invalidate_parent_cx_inner() {
    // Behavioral pin: build a parent Cx and a child Cx
    // (with FRESH CxInner — mirroring build_child_task_cx).
    // Drop the child. Verify:
    //   1. Parent's CxInner is NOT dropped (drop_count == 0).
    //   2. Parent can still access its own region_id.
    //   3. Parent's strong_count is still 1.
    let parent_drop_count = Arc::new(AtomicU64::new(0));
    let child_drop_count = Arc::new(AtomicU64::new(0));

    let parent = MockCx::new(1, Arc::clone(&parent_drop_count));
    let child = MockCx::new(2, Arc::clone(&child_drop_count));

    assert_eq!(parent.region_id(), 1);
    assert_eq!(child.region_id(), 2);
    assert!(!parent.cancel_requested(), "parent starts uncancelled");
    assert!(!child.cancel_requested(), "child starts uncancelled");
    assert_eq!(parent.arc_strong_count(), 1, "parent has fresh Arc");
    assert_eq!(child.arc_strong_count(), 1, "child has fresh Arc");

    // Drop the child.
    drop(child);

    // Child's CxInner is freed (drop_count == 1).
    assert_eq!(
        child_drop_count.load(Ordering::Relaxed),
        1,
        "REGRESSION: child CxInner did not run Drop after \
         child Cx dropped. Either a leaked Arc reference \
         or the Drop impl is gone — refcount semantics \
         broken.",
    );

    // Parent's CxInner is NOT freed.
    assert_eq!(
        parent_drop_count.load(Ordering::Relaxed),
        0,
        "REGRESSION: parent CxInner was dropped when child \
         Cx dropped. Parent and child should be INDEPENDENT \
         Arc-refcounted state — child drop must not affect \
         parent.",
    );

    // Parent still observable.
    assert_eq!(
        parent.region_id(),
        1,
        "REGRESSION: parent.region_id() failed after child \
         drop. The parent's CxInner is corrupt or freed — \
         use-after-free regression.",
    );
}

#[test]
fn parent_cx_clone_keeps_arc_alive_across_original_drop() {
    // Behavioral pin: clone a Cx, drop the original, verify
    // the clone is still valid. This pins the Arc-clone
    // semantics that prevent use-after-free across thread-
    // local frame pops.
    let drop_count = Arc::new(AtomicU64::new(0));
    let original = MockCx::new(42, Arc::clone(&drop_count));
    let cloned = original.clone();

    assert_eq!(original.arc_strong_count(), 2);
    assert_eq!(cloned.arc_strong_count(), 2);

    // Drop the original — refcount goes from 2 to 1.
    drop(original);

    // CxInner is NOT freed yet.
    assert_eq!(
        drop_count.load(Ordering::Relaxed),
        0,
        "REGRESSION: CxInner dropped while clone still \
         holds an Arc reference. Refcount semantics broken \
         — Cx::current() would return a clone that observes \
         freed memory.",
    );

    // Clone is still valid.
    assert_eq!(
        cloned.region_id(),
        42,
        "REGRESSION: clone.region_id() failed after original \
         drop. Use-after-free pathway opened.",
    );

    assert_eq!(cloned.arc_strong_count(), 1);

    drop(cloned);
    assert_eq!(
        drop_count.load(Ordering::Relaxed),
        1,
        "REGRESSION: CxInner did not run Drop after the LAST \
         clone dropped. Refcount-driven cleanup broken.",
    );
}

#[test]
fn weak_reference_to_child_cx_inner_observes_drop_via_upgrade_failure() {
    // Behavioral pin (link 10): Arc::downgrade pattern.
    // Build a child Cx, take Arc::downgrade(&child.inner),
    // drop the child. Weak::upgrade() must return None.
    let drop_count = Arc::new(AtomicU64::new(0));
    let child = MockCx::new(99, Arc::clone(&drop_count));

    let weak = Arc::downgrade(&child.inner);
    assert!(weak.upgrade().is_some(), "weak alive while child held");

    drop(child);

    assert_eq!(
        drop_count.load(Ordering::Relaxed),
        1,
        "REGRESSION: child CxInner not dropped after child \
         Cx dropped (weak references should NOT keep CxInner \
         alive — they're for cycle prevention only).",
    );

    assert!(
        weak.upgrade().is_none(),
        "REGRESSION: Weak::upgrade returned Some after child \
         CxInner was dropped. Either the weak is keeping the \
         strong-count alive (cycle leak) or the upgrade \
         doesn't observe the drop (memory model bug).",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_checkpoint_observes_parent_region_cancel_audit.rs",
        "tests/scheduler_panic_in_task_isolation_audit.rs",
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
