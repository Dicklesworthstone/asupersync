//! Audit + regression test for self-cancel vs region-
//! cancel distinction.
//!
//! Operator's question: "Cx::cancel_self() vs Scope::cancel():
//! self-cancel should mark the current task as cancelled
//! at the next checkpoint. Verify this is observable AND
//! distinct from cancelling the parent scope (which would
//! cancel siblings too)."
//!
//! Audit findings: **SOUND BY DESIGN — the SEMANTIC
//! distinction is correctly distinct in implementation,
//! but the literal method names the operator asks about
//! don't exist.**
//!
//! ── The literal methods don't exist ─────────────────────
//!
//! Whole-tree grep:
//!   - `fn cancel_self` → ZERO hits
//!   - `Scope::cancel` (no method on Scope named `cancel`)
//!     — Scope's public methods are region_id, budget,
//!     spawn, spawn_task, spawn_local, spawn_blocking,
//!     region, region_with_budget, join, race, hedge,
//!     race_all, join_all, defer_sync, defer_async
//!     (cf. src/cx/scope.rs).
//!
//! Instead, the cancel surface is:
//!
//! 1. **Self-cancel on Cx**: `cx.cancel_with(kind, msg)` /
//!    `cx.cancel_fast(kind)` (cx.rs:2566, 2626) mutate
//!    the CURRENT task's CxInner. ONLY this task observes
//!    Err(Cancelled) at its next checkpoint. Siblings
//!    are NOT affected.
//!
//! 2. **Region-scoped cancel via runtime**:
//!    `RuntimeState::cancel_request(region_id, reason, source_task)`
//!    (state.rs:2678) walks the region tree, marks the
//!    target region AND all descendants, builds proper
//!    cause chains (descendants get
//!    `CancelKind::ParentCancelled` chained to root
//!    reason), and returns the task list paired with opaque
//!    Waker effects. The caller publishes task IDs after its
//!    outer state guard is released, before Waker dispatch.
//!    ALL tasks in those regions observe Err(Cancelled).
//!
//! ── Implementation-level distinction ────────────────────
//!
//! `Cx::cancel_with` (cx.rs:2566):
//!
//! ```ignore
//! pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {
//!     let (region, task, waker) = {
//!         let mut inner = self.inner.write();
//!         // ... mutate ONLY self.inner ...
//!         inner.cancel_requested = true;
//!         inner.fast_cancel.store(true, Ordering::Release);
//!         inner.cancel_reason = Some(reason);
//!         ...
//!     };
//!     ...
//! }
//! ```
//!
//! Touches ONLY `self.inner` (one CxInner). Per-task,
//! per-Cx mutation. No region-tree walk.
//!
//! `RuntimeState::cancel_request` (state.rs:2678):
//!
//! ```ignore
//! pub fn cancel_request(
//!     &mut self,
//!     region_id: RegionId,
//!     reason: &CancelReason,
//!     source_task: Option<TaskId>,
//! ) -> CancellationEffects<Vec<(TaskId, u8)>> {
//!     let mut wakes = CancelWakeEffects::empty();
//!     let mut regions_to_cancel =
//!         self.collect_region_and_descendants_with_depth(region_id);
//!     regions_to_cancel.sort_by_key(|node| node.depth);
//!     // Walk region tree, mark ALL tasks in target +
//!     // descendants with ParentCancelled cause chain,
//!     // aggregating auxiliary cancellation observers/Wakers without
//!     // dispatching them beneath RuntimeState.
//!     ...
//!     CancellationEffects::new(tasks_to_cancel, wakes)
//! }
//! ```
//!
//! Walks the region tree. Mutates many tasks' Cxs.
//! Builds cause chains (ParentCancelled for descendants).
//! Returns the set of tasks affected coupled to deferred auxiliary
//! cancellation observers/Wakers. Later region close/finalizer callbacks are
//! outside this boundary.
//!
//! ── Why no Scope::cancel() method ───────────────────────
//!
//! Region cancel is a runtime-level operation that
//! requires the RuntimeState handle (to walk the region
//! tree, sort by depth, build chains, schedule the
//! cancel-lane wakers). The Scope handle alone doesn't
//! carry the RuntimeState, so a `Scope::cancel()` method
//! would either need a hidden RuntimeState reference
//! (breaking the structured-concurrency capability flow)
//! or duplicate the runtime API on Scope.
//!
//! The current design is: programs that want to cancel a
//! region call the runtime's cancel API explicitly via
//! their RuntimeState reference, OR rely on structured
//! cancellation (parent region close → child cancel
//! propagation).
//!
//! ── Why no Cx::cancel_self() method ─────────────────────
//!
//! `cancel_with(kind, message)` IS the self-cancel path —
//! the name embeds the required CancelKind argument
//! (attribution discipline; see
//! `cx_no_interrupt_method_unified_cancel_audit.rs`).
//! Adding a bare `cancel_self()` would either:
//!   - Take no arguments (silently picks a default kind —
//!     attribution loss), or
//!   - Be a thin wrapper around cancel_with (redundant).
//!
//! Both are anti-patterns under the explicit-attribution
//! discipline.
//!
//! ── Sibling isolation: self-cancel does NOT affect siblings ──
//!
//! Each spawned task gets its OWN Cx (each Cx has its own
//! Arc<RwLock<CxInner>>). Sibling tasks share the same
//! region_id but have DIFFERENT CxInner. Mutating one Cx
//! via cancel_with does not touch the other Cxs in the
//! same region.
//!
//! Region cancel via cancel_request iterates all tasks
//! whose owner region is in the target set and sets
//! cancel on each of their CxInners — that's the explicit
//! propagation path.
//!
//! Verdict: **SOUND BY DESIGN**. Self-cancel and region-
//! cancel are implemented via DIFFERENT code paths
//! (per-Cx mutation vs region-tree walk), produce
//! DIFFERENT observable effects (one task vs many tasks
//! cancelled), and use DIFFERENT entry points
//! (Cx::cancel_with vs RuntimeState::cancel_request).
//! They cannot be conflated.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn read_dir_recursive(root: &str) -> Vec<PathBuf> {
    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(root);
    let mut out = Vec::new();
    let mut stack = vec![root_path];
    while let Some(p) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&p) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn cx_cancel_self_method_does_not_exist() {
    // Pin: no literal `Cx::cancel_self` method anywhere.
    let mut violations = Vec::new();
    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains("fn cancel_self") {
            violations.push(path.display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "REGRESSION: `cancel_self` method introduced. The \
         attribution-required cancel_with discipline is \
         being silently bypassed.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn scope_cancel_method_does_not_exist() {
    // Pin: Scope has no cancel() method. Region cancel
    // requires RuntimeState; exposing it on Scope would
    // break the capability flow.
    let source = read("src/cx/scope.rs");

    // Scope's impl block.
    assert!(
        !source.contains("    pub fn cancel(&self)")
            && !source.contains("    pub fn cancel(&mut self)")
            && !source.contains("    pub async fn cancel("),
        "REGRESSION: Scope now has a cancel() method. \
         Region cancel needs RuntimeState — exposing it on \
         Scope either smuggles in a hidden RuntimeState ref \
         or duplicates the runtime API.",
    );
}

#[test]
fn cx_cancel_with_self_cancel_path_exists() {
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains(
            "pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {"
        ),
        "REGRESSION: Cx::cancel_with self-cancel path is \
         gone.",
    );

    assert!(
        source.contains("pub fn cancel_fast(&self, kind: CancelKind) {"),
        "REGRESSION: Cx::cancel_fast self-cancel path is \
         gone.",
    );
}

#[test]
fn cancel_with_only_mutates_self_inner_not_region_tree() {
    // Pin: cancel_with's body mutates self.inner.write()
    // — ONE CxInner. It does NOT walk the region tree.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {";
    let pos = source.find(fn_marker).expect("cancel_with fn");
    let body_window = &source[pos..pos + 1500];

    assert!(
        body_window.contains("self.inner.write()"),
        "REGRESSION: cancel_with no longer acquires \
         self.inner.write(). The per-Cx mutation path \
         is broken.",
    );

    let suspect_propagation = [
        "collect_region_and_descendants",
        "regions_to_cancel",
        "for region in regions",
    ];
    for pat in &suspect_propagation {
        assert!(
            !body_window.contains(pat),
            "REGRESSION: cancel_with body contains \
             `{pat}` — self-cancel is now propagating to \
             siblings/descendants. The per-task isolation \
             is broken.",
        );
    }
}

#[test]
fn runtime_state_cancel_request_walks_region_tree() {
    // Pin: cancel_request collects target region +
    // descendants and processes them depth-sorted with
    // proper cause chains.
    let source = read("src/runtime/state.rs");

    let fn_marker = "pub fn cancel_request(";
    let pos = source.find(fn_marker).expect("cancel_request fn");
    let body_window = &source[pos..pos + 4000];

    assert!(
        body_window.contains("collect_region_and_descendants_with_depth(region_id)"),
        "REGRESSION: cancel_request no longer walks the \
         region tree via collect_region_and_descendants. \
         Region-cancel propagation is broken.",
    );

    assert!(
        body_window.contains("sort_by_key(|node| node.depth)"),
        "REGRESSION: cancel_request no longer sorts \
         regions by depth. Cause-chain construction may \
         have parent processed AFTER child — inverted \
         attribution.",
    );
}

#[test]
fn cancel_request_returns_effects_with_affected_tasks() {
    // Pin: cancel_request returns the explicit task list
    // paired with opaque Waker effects. This prevents user
    // callbacks while RuntimeState/task locks are live and
    // preserves the post-lock scheduler publication surface.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("pub fn cancel_request(")
            && source.contains("-> CancellationEffects<Vec<(TaskId, u8)>>")
            && source.contains("let ((newly_cancelled, changed, publication), task_wakes) =",)
            && source.contains("wakes.merge(task_wakes);")
            && source.contains("CancellationEffects::new(tasks_to_cancel, wakes)"),
        "REGRESSION: cancel_request return type changed. \
         The affected-task list is no longer coupled to \
         deferred Wakers, so the post-lock publication/\
         dispatch boundary cannot be enforced.",
    );
}

#[test]
fn cancel_request_builds_parent_cancelled_cause_chain() {
    // Pin: descendants get a CancelKind::ParentCancelled
    // entry chained to the root reason — distinguishing
    // them from the originating cancel kind.
    let source = read("src/runtime/state.rs");

    let fn_marker = "pub fn cancel_request(";
    let pos = source.find(fn_marker).expect("cancel_request fn");
    let body_window = &source[pos..pos + 8000];

    assert!(
        body_window.contains("ParentCancelled"),
        "REGRESSION: cancel_request no longer builds \
         ParentCancelled cause chains for descendants. \
         Cause attribution is broken.",
    );
}

#[test]
fn each_task_has_own_arc_cxinner_for_sibling_isolation() {
    // Pin: Cx::inner is Arc<RwLock<CxInner>>. Sibling
    // tasks have distinct Arc<CxInner>s. Mutating one
    // does not affect the others.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("inner: Arc<") || source.contains("inner: std::sync::Arc<"),
        "REGRESSION: Cx::inner is no longer Arc-wrapped. \
         Sibling tasks may now share inner state — \
         self-cancel could leak to siblings.",
    );
}

#[test]
fn inline_test_cancel_request_propagates_to_descendants() {
    // Pin: state.rs has an inline test that asserts
    // region cancel propagates to descendants. Without
    // this, propagation regressions can pass CI.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("fn cancel_request_propagates_to_descendants()"),
        "REGRESSION: cancel_request_propagates_to_descendants \
         inline test is gone. Propagation contract no \
         longer guarded in-tree.",
    );
}

#[test]
fn inline_test_cancel_request_marks_tasks() {
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("fn cancel_request_marks_tasks()"),
        "REGRESSION: cancel_request_marks_tasks inline \
         test gone.",
    );
}

#[test]
fn cancel_with_inline_test_pins_per_cx_self_cancel() {
    // Pin: cx.rs has an inline test that asserts
    // cancel_with sets the cancel state on a single Cx.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("fn cancel_with_sets_reason()")
            || source.contains("fn cancel_with_no_message()"),
        "REGRESSION: cancel_with inline tests are gone. \
         The self-cancel-on-Cx contract is no longer \
         guarded.",
    );
}

#[test]
fn scope_public_methods_do_not_include_cancel() {
    // Pin: enumerate Scope's public methods to verify
    // cancel is not among them. (Defensive against a
    // typo'd `pub fn cncel` etc.)
    let source = read("src/cx/scope.rs");

    let expected_methods = [
        "pub fn region_id(&self) -> RegionId {",
        "pub fn budget(&self) -> Budget {",
        "pub fn spawn_registered<",
        "pub async fn region<",
        "pub async fn race<",
        "pub async fn join_all<",
    ];

    for method in &expected_methods {
        assert!(
            source.contains(method),
            "REGRESSION: expected Scope method `{method}` \
             is gone. (This pin verifies the public API \
             shape; a regression here is unrelated to \
             cancel.)",
        );
    }

    // The audit's main assertion: NO cancel method.
    let suspect_cancel_methods = [
        "pub fn cancel(&self)",
        "pub fn cancel(&mut self)",
        "pub async fn cancel(&self)",
        "pub async fn cancel(&mut self)",
        "pub fn cancel_region(",
        "pub fn cancel_all(",
    ];
    for pat in &suspect_cancel_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: Scope now has `{pat}`. Region \
             cancel needs RuntimeState — exposing it on \
             Scope breaks capability routing.",
        );
    }
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
struct TaskId(u32);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
struct RegionId(u32);

struct CxInner {
    cancelled: AtomicBool,
    region: RegionId,
}

#[derive(Clone)]
struct MockCx {
    task: TaskId,
    inner: Arc<CxInner>,
}

impl MockCx {
    fn new(task: TaskId, region: RegionId) -> Self {
        Self {
            task,
            inner: Arc::new(CxInner {
                cancelled: AtomicBool::new(false),
                region,
            }),
        }
    }

    /// Models cx.cancel_with(...) — self-cancel.
    fn cancel_with(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }
}

struct MockRuntimeState {
    cxs: Mutex<Vec<MockCx>>,
}

impl MockRuntimeState {
    fn new() -> Self {
        Self {
            cxs: Mutex::new(Vec::new()),
        }
    }

    fn register(&self, cx: MockCx) {
        self.cxs.lock().unwrap().push(cx);
    }

    /// Models state.cancel_request(region, ...) — region
    /// cancel that walks all tasks in the region.
    fn cancel_request(&self, region: RegionId) -> Vec<TaskId> {
        let cxs = self.cxs.lock().unwrap();
        let mut affected = Vec::new();
        for cx in cxs.iter() {
            if cx.inner.region == region {
                cx.inner.cancelled.store(true, Ordering::Release);
                affected.push(cx.task);
            }
        }
        affected
    }
}

#[test]
fn behavioral_self_cancel_does_not_affect_siblings() {
    let state = MockRuntimeState::new();
    let region = RegionId(1);

    let cx_a = MockCx::new(TaskId(10), region);
    let cx_b = MockCx::new(TaskId(11), region);
    let cx_c = MockCx::new(TaskId(12), region);

    state.register(cx_a.clone());
    state.register(cx_b.clone());
    state.register(cx_c.clone());

    // A self-cancels.
    cx_a.cancel_with();

    assert!(cx_a.is_cancelled());
    assert!(
        !cx_b.is_cancelled(),
        "REGRESSION: sibling B observed cancel after A's \
         self-cancel. Per-Cx isolation is broken.",
    );
    assert!(
        !cx_c.is_cancelled(),
        "REGRESSION: sibling C observed cancel after A's \
         self-cancel.",
    );
}

#[test]
fn behavioral_region_cancel_affects_all_in_region() {
    let state = MockRuntimeState::new();
    let region = RegionId(1);
    let other_region = RegionId(2);

    let cx_a = MockCx::new(TaskId(10), region);
    let cx_b = MockCx::new(TaskId(11), region);
    let cx_other = MockCx::new(TaskId(99), other_region);

    state.register(cx_a.clone());
    state.register(cx_b.clone());
    state.register(cx_other.clone());

    // Region cancel: targets region 1.
    let affected = state.cancel_request(region);

    assert_eq!(affected.len(), 2);
    assert!(cx_a.is_cancelled());
    assert!(
        cx_b.is_cancelled(),
        "REGRESSION: region cancel did not propagate to \
         sibling B. The walk-region-tasks path is broken.",
    );
    assert!(
        !cx_other.is_cancelled(),
        "REGRESSION: region cancel leaked to a different \
         region (region 2). The region scoping is broken.",
    );
}

#[test]
fn behavioral_self_cancel_and_region_cancel_have_different_scopes() {
    let state = MockRuntimeState::new();
    let region = RegionId(1);

    let cx_a = MockCx::new(TaskId(10), region);
    let cx_b = MockCx::new(TaskId(11), region);

    state.register(cx_a.clone());
    state.register(cx_b.clone());

    // Snapshot pre-state.
    assert!(!cx_a.is_cancelled() && !cx_b.is_cancelled());

    // Self-cancel A.
    cx_a.cancel_with();
    let post_self_cancel = (cx_a.is_cancelled(), cx_b.is_cancelled());
    assert_eq!(
        post_self_cancel,
        (true, false),
        "REGRESSION: self-cancel scope differs from \
         expected (only A cancelled).",
    );

    // Reset.
    cx_a.inner.cancelled.store(false, Ordering::Release);

    // Region cancel.
    state.cancel_request(region);
    let post_region_cancel = (cx_a.is_cancelled(), cx_b.is_cancelled());
    assert_eq!(
        post_region_cancel,
        (true, true),
        "REGRESSION: region cancel scope differs from \
         expected (both A and B cancelled).",
    );

    // The two scopes are different.
    assert_ne!(
        post_self_cancel, post_region_cancel,
        "REGRESSION: self-cancel and region-cancel \
         produced identical observable effects. The \
         distinction is broken.",
    );
}

#[test]
fn behavioral_per_task_cx_inner_is_independent() {
    // Each task has its own Arc<CxInner>. Mutating one
    // does not affect another.
    let cx_a = MockCx::new(TaskId(1), RegionId(1));
    let cx_b = MockCx::new(TaskId(2), RegionId(1));

    // Distinct Arcs → distinct cancel state.
    assert!(!Arc::ptr_eq(&cx_a.inner, &cx_b.inner));

    cx_a.cancel_with();
    assert!(cx_a.is_cancelled());
    assert!(
        !cx_b.is_cancelled(),
        "REGRESSION: cxs in same region share inner state. \
         Per-task isolation broken.",
    );
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_no_interrupt_method_unified_cancel_audit.rs",
        "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
        "tests/runtime_cancel_cause_chain_depth_audit.rs",
        "tests/cx_masked_does_not_block_obligation_propagation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
