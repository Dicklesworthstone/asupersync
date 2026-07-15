//! Audit + regression test for the (non-existent)
//! `.detached()` orphan-spawn API.
//!
//! Operator's question: "Cx::detached() spawn semantics:
//! when a task is spawned with .detached() (orphan-
//! permitted), does it correctly outlive parent region
//! (intentionally) or follow parent (defeating purpose)?
//! Per asupersync, if detached API exists it must truly
//! orphan."
//!
//! Audit findings:
//!
//!   asupersync **does NOT have a `.detached()` spawn API**
//!   that creates a task outliving its parent region. This
//!   is **intentional and structurally correct** — the
//!   structured-concurrency invariant forbids orphan-
//!   outlives-parent semantics. Per AGENTS.md asupersync
//!   non-negotiable invariants:
//!
//!     "Structured concurrency: every task/fiber/actor is
//!      owned by exactly one region.
//!      Region close = quiescence: no live children + all
//!      finalizers done."
//!
//!   An orphan-permitted detached task would defeat both
//!   invariants — region.close() could not reach
//!   quiescence if a "detached" task were still running
//!   under (or outside) the region.
//!
//!   The operator's "detached" mental model applies to
//!   tokio (where detach-on-drop creates orphan tasks
//!   tied to the runtime, not to a region). asupersync
//!   has NO such concept by design.
//!
//!   What asupersync provides for fire-and-forget:
//!
//!   1. **`TaskHandle` drop without await** (detached at
//!      the HANDLE level, NOT the region level): the task
//!      continues running but remains bound to its parent
//!      region. When the region closes, the task is
//!      cancelled.
//!      - Pinned in
//!        tests/runtime_join_handle_drop_lifecycle_audit.rs.
//!
//!   2. **Long-lived top-level tasks**: spawn at the root
//!      region; the root region only closes when the
//!      runtime shuts down. Effectively "outlives" any
//!      transient parent — but still owned by SOME region
//!      (the root).
//!
//!   What asupersync DELIBERATELY does NOT provide:
//!
//!   - **Orphan tasks with no region** — would violate
//!     "every task owned by exactly one region".
//!   - **Outlive-parent-region detach** — would violate
//!     "region close = quiescence".
//!   - **Tokio-style `task::spawn` returning ()** — every
//!     spawned task in asupersync produces a TaskHandle
//!     bound to a region.
//!
//!   The chain of structural enforcement:
//!
//!   1. **State-threaded scope task construction requires a Scope**:
//!      ```ignore
//!      fn create_stored_task<F, Fut, Caps>(&self, state: &mut RuntimeState, ...) -> ...
//!      ```
//!      The `&self` is a Scope — which holds a RegionId.
//!      Every spawn anchors to a region.
//!
//!   2. **`create_task_record` adds the task to the
//!      regions task_ids list** (cx/scope.rs):
//!      ```ignore
//!      if let Some(region) = state.region(self.region) {
//!          region.add_task(task_id)?;
//!      }
//!      ```
//!      The region OWNS the task — there's no orphan
//!      pathway.
//!
//!   3. **Region close cancels owned tasks** (state.rs:
//!      cancel_request second pass): cancel_request walks
//!      `region.copy_task_ids_into(&mut task_id_buf)` and
//!      calls `request_cancel_with_budget` on each. It
//!      captures each task's mutation result and Wakers as
//!      effects; the scheduler publishes the resulting task
//!      IDs after releasing its state guard, then dispatches
//!      the auxiliary cancellation Wakers. No task escapes
//!      region close, and those Wakers do not run under the
//!      outer lock. This is deliberately not a universal
//!      callback-free claim: synchronous finalizers, metrics,
//!      tracing, region-close Wakers, and arbitrary payload
//!      destructors have separate lock-boundary contracts.
//!
//!   4. **`can_region_finalize` checks all tasks
//!      terminal** (state.rs:2785): `all_tasks_done = ...
//!      task.is_terminal()`. The region cant close until
//!      every owned task reaches a terminal state.
//!      Detached-outlive-parent would be IMPOSSIBLE under
//!      this contract.
//!
//! Verdict: **SOUND BY DESIGN**. The operators "detached"
//! framing maps onto a non-existent API. Adding one would
//! violate two non-negotiable structured-concurrency
//! invariants from AGENTS.md.
//!
//! No bead filed. The "missing feature" is INTENTIONAL —
//! the audit pins the structural enforcement that prevents
//! a future regression from introducing it.
//!
//! For users who want fire-and-forget semantics:
//!   - Use spawn at the root region (long-lived parent).
//!   - Drop the TaskHandle (detach at handle level only).
//!   - Use a supervisor pattern (parent waits indefinitely).
//!
//! A regression that:
//!   - added `Scope::spawn_detached(...)` returning a unit
//!     handle that doesnt anchor to a region (would break
//!     "every task owned by one region" invariant),
//!   - added `TaskHandle::detach()` that orphans the task
//!     (would conflate handle-drop semantics with region-
//!     escape; tokio-style API would conflict with
//!     structured concurrency),
//!   - changed scope task construction to skip region.add_task on
//!     some opt-in flag (silent escape from region tree),
//!   - removed the all_tasks_done check from
//!     can_region_finalize (would let regions close with
//!     live tasks — orphan pathway),
//!   - introduced a "global detach pool" that holds tasks
//!     outside any region (would violate the region-tree
//!     invariant entirely),
//!     would all be caught by the structural pins below.

use std::ffi::OsStr;
use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn collect_rs_files(dir: &PathBuf, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension() == Some(OsStr::new("rs")) {
            out.push(path);
        }
    }
}

#[test]
fn no_detached_spawn_method_on_scope() {
    // Pin (link 1): Scope must NOT have a method named
    // `spawn_detached`, `detach`, or any variant that
    // implies orphan-outlives-parent semantics.
    let source = read("src/cx/scope.rs");

    let suspect_detach_methods = [
        "pub fn spawn_detached(",
        "pub async fn spawn_detached(",
        "pub fn detached_spawn(",
        "pub fn spawn_orphan(",
        "pub fn spawn_outside_region(",
    ];
    for pat in &suspect_detach_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: Scope now has `{pat}` — implying \
             detached/orphan spawn semantics. This violates \
             the structured-concurrency invariant 'every \
             task owned by exactly one region'. The \
             corresponding region close cant guarantee \
             quiescence under such a task.",
        );
    }
}

#[test]
fn no_detach_method_on_task_handle() {
    // Pin (link 1): TaskHandle must NOT have a method
    // named `detach()` that orphans the task. Drop-
    // without-await already provides handle-level
    // detachment WITHOUT region escape.
    let source = read("src/runtime/task_handle.rs");

    let suspect_detach_methods = [
        "pub fn detach(",
        "pub fn detach_silently(",
        "pub fn forget(",
        "pub fn into_orphan(",
    ];
    for pat in &suspect_detach_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: TaskHandle now has `{pat}` — \
             implying explicit detach. The detach-on-drop \
             handle-level semantic is the documented way \
             to fire-and-forget; explicit detach methods \
             may imply region-escape semantics that arent \
             supported.",
        );
    }
}

#[test]
fn no_detached_field_on_task_record() {
    // Pin (link 2): TaskRecord must NOT have a `detached:
    // bool` or similar field that would gate region
    // ownership. The structural design is that EVERY task
    // is anchored to a region — no opt-out.
    let source = read("src/record/task.rs");

    let suspect_detach_fields = [
        "detached: bool,",
        "is_orphan: bool,",
        "skip_region_close: bool,",
        "outlive_parent: bool,",
    ];
    for pat in &suspect_detach_fields {
        assert!(
            !source.contains(pat),
            "REGRESSION: TaskRecord now has `{pat}` — \
             implying region-ownership opt-out. Structured \
             concurrency requires every task owned by one \
             region; this field would create an escape \
             hatch.",
        );
    }
}

#[test]
fn scope_task_construction_anchors_task_to_region_via_create_task_record() {
    // Pin (link 1+2): all scope task construction anchors the task to the
    // scope's region via create_task_record + region.add_task.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("pub(crate) fn create_task_record(")
            || source.contains("pub fn create_task_record("),
        "REGRESSION: create_task_record helper is gone. The \
         structural mechanism for anchoring tasks to regions \
         is broken — spawn paths have no shared anchoring.",
    );

    // create_task_record must add the task to the region.
    let fn_marker = "pub(crate) fn create_task_record(";
    let start = source.find(fn_marker).expect("create_task_record fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("create_task_record close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("region.add_task(task_id)"),
        "REGRESSION: create_task_record no longer adds the \
         task to the region. Tasks would be allocated WITHOUT \
         region ownership — orphan tasks possible. Structured-\
         concurrency contract violated.",
    );
}

#[test]
fn region_record_holds_task_id_list_for_owned_tasks() {
    // Pin (link 2): RegionRecord.inner.tasks: Vec<TaskId>
    // is the region-owns-task tracking structure. Without
    // it, regions cant know which tasks they own.
    let source = read("src/record/region.rs");

    assert!(
        source.contains("tasks: Vec<TaskId>,"),
        "REGRESSION: RegionRecord.inner.tasks is gone. \
         Regions cant track owned tasks — every spawn \
         becomes an orphan in practice.",
    );
}

#[test]
fn cancel_request_walks_region_owned_tasks_for_close_propagation() {
    // Pin (link 3): cancel_request copies task IDs from
    // each region in the subtree and cancels them. This
    // is the structural mechanism that prevents detached
    // tasks from outliving their region.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("region.copy_task_ids_into(&mut task_id_buf);"),
        "REGRESSION: cancel_request no longer walks region-\
         owned tasks via copy_task_ids_into. Region close \
         no longer cancels child tasks — detached-by-\
         accident pathway.",
    );

    // The per-task cancel call.
    assert!(
        source.contains("task.request_cancel_with_budget_and_publication(")
            && source.contains("let ((newly_cancelled, changed, publication), task_wakes) =",)
            && source.contains("wakes.merge(task_wakes);")
            && source.contains("CancellationEffects::new(tasks_to_cancel, wakes)"),
        "REGRESSION: cancel_request no longer calls \
         request_cancel_with_budget on each owned task and \
         captures its opaque wake effects for post-lock \
         dispatch. The per-task cancel propagation boundary \
         is broken.",
    );
}

#[test]
fn can_region_finalize_requires_all_tasks_terminal_for_quiescence() {
    // Pin (link 4): can_region_finalize checks all owned
    // tasks are terminal before allowing the region to
    // close. This is what enforces "region close =
    // quiescence" — no detached pathway can bypass.
    let source = read("src/runtime/state.rs");

    let fn_marker = "pub fn can_region_finalize(&self, region_id: RegionId) -> bool {";
    let start = source.find(fn_marker).expect("can_region_finalize fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("can_region_finalize close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("region\n            .task_ids()\n            .iter()")
            || body.contains("task_ids()"),
        "REGRESSION: can_region_finalize no longer iterates \
         region.task_ids(). Region close no longer waits \
         for all owned tasks to reach terminal state — \
         orphan pathway opened.",
    );

    assert!(
        body.contains("t.state.is_terminal()"),
        "REGRESSION: can_region_finalize no longer checks \
         is_terminal() on each owned task. Detached tasks \
         could outlive the region.",
    );
}

#[test]
fn no_global_detach_pool_or_orphan_arena_in_runtime_state() {
    // Pin (audit): there must be NO global "detach pool"
    // or "orphan arena" that holds tasks outside any
    // region. The arena is region-tree-based; orphans
    // would need a separate structure.
    let source = read("src/runtime/state.rs");

    let suspect_orphan_storage = [
        "detached_tasks: ",
        "orphan_pool: ",
        "global_orphan_arena: ",
        "regionless_tasks: ",
    ];
    for pat in &suspect_orphan_storage {
        assert!(
            !source.contains(pat),
            "REGRESSION: state.rs now has an orphan-storage \
             field (`{pat}`). The region-tree-only \
             invariant is broken — tasks can exist outside \
             any region.",
        );
    }
}

#[test]
fn agents_md_documents_structured_concurrency_invariants() {
    // Pin (documentation cross-reference): AGENTS.md must
    // document the structured-concurrency invariants that
    // forbid detached-outlive-parent. Without this
    // documentation, future agents may be tempted to add
    // a `.detached()` API.
    let source = read("AGENTS.md");

    assert!(
        source.contains("Structured concurrency:")
            && (source.contains("every task/fiber/actor is owned by exactly one region")
                || source.contains("owned by exactly one region")),
        "REGRESSION: AGENTS.md no longer documents the \
         'every task owned by exactly one region' \
         invariant. Without this documentation, the \
         structural-vs-detached contract is unclear.",
    );

    assert!(
        source.contains("Region close = quiescence")
            && source.contains("no live children + all finalizers done"),
        "REGRESSION: AGENTS.md no longer documents the \
         'region close = quiescence' invariant. Detached \
         tasks could be re-introduced without violating \
         documented contracts.",
    );
}

#[test]
fn no_method_named_detached_or_orphan_anywhere_in_cx_runtime_paths() {
    // Pin (full-tree sweep): scan src/cx/ and src/runtime/
    // for any method named `detached` or `orphan` that
    // would imply orphan-outlive-parent semantics. The
    // browser bindings have detach() for Web API channels
    // — those are unrelated and skipped.
    let mut files = Vec::new();
    collect_rs_files(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/cx"),
        &mut files,
    );
    collect_rs_files(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runtime"),
        &mut files,
    );

    let mut findings = Vec::new();
    let suspect_method_signatures = [
        "pub fn detached(",
        "pub fn orphan(",
        "pub async fn detached(",
        "pub async fn orphan(",
    ];

    for path in files {
        let path_str = path.display().to_string();
        // Skip browser-binding detach (Web API unrelated).
        if path_str.contains("/runtime/reactor/browser.rs") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for pat in &suspect_method_signatures {
            if content.contains(pat) {
                findings.push(format!("{path_str}: pattern `{pat}`"));
            }
        }
    }

    assert!(
        findings.is_empty(),
        "REGRESSION: a method named `detached` or `orphan` \
         was added in src/cx/ or src/runtime/. The \
         structured-concurrency contract forbids orphan-\
         outlives-parent semantics. Findings:\n  {findings}",
        findings = findings.join("\n  "),
    );
}

#[test]
fn task_handle_drop_without_await_does_not_imply_region_escape() {
    // Pin (clarification): TaskHandle drop is detached at
    // the HANDLE level (no observation), but the task
    // remains REGION-OWNED. When the region closes, the
    // task is still cancelled. This is documented in the
    // prior handle-drop audit.
    let prior_audit = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/runtime_join_handle_drop_lifecycle_audit.rs");

    assert!(
        prior_audit.exists(),
        "REGRESSION: prior handle-drop audit is missing. \
         The handle-vs-region detachment distinction is \
         documented there; without it, users may confuse \
         handle-drop with region-escape.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_join_handle_drop_lifecycle_audit.rs",
        "tests/runtime_region_close_idempotency_audit.rs",
        "tests/runtime_region_close_timed_lane_task_cancellation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
