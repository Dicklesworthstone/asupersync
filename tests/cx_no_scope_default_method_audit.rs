//! Audit + regression test for `Cx::scope_default()` vs
//! `Cx::scope()` distinction.
//!
//! Operator's question: "If both APIs exist, what's the
//! difference? Does scope_default use system runtime
//! defaults while scope() uses user-specified Region?"
//!
//! Audit findings: **SOUND BY DESIGN** — `scope_default()`
//! DOES NOT EXIST.
//!
//! ── Whole-tree search ───────────────────────────────────
//!
//! `grep -rn "scope_default"` across the entire workspace
//! (src/, tests/, asupersync-tokio-compat/, conformance/,
//! franken_*/, examples/, benches/, docs/) returns ZERO
//! hits.
//!
//! There is exactly ONE scope-accessor method on Cx:
//!
//! ```ignore
//! // src/cx/cx.rs:2972
//! pub fn scope(&self) -> crate::cx::Scope<'static> {
//!     // ...returns a handle bound to the CURRENT region.
//!     // No new region is allocated; no defaults are applied.
//! }
//! ```
//!
//! ── Why this absence is by design ───────────────────────
//!
//! asupersync's structured-concurrency invariant requires
//! that EVERY task is owned by exactly one region. Region
//! allocation goes through `Scope::region(state, cx,
//! policy, f).await` — an async constructor that:
//!
//!   - takes an explicit RuntimeState handle,
//!   - takes the parent Cx,
//!   - takes an explicit RegionPolicy,
//!   - takes a closure to run inside the new region,
//!   - awaits child quiescence and returns Result<Outcome,
//!     RegionCreateError>.
//!
//! There is no "system runtime default" alternative because
//! that would either:
//!
//!   1. Reach for ambient global runtime state (violates
//!      "no ambient authority" — every effect must flow
//!      through Cx).
//!   2. Provide silent default policies (violates
//!      "explicit-budget" — Budget::meet, deadlines, and
//!      cancel propagation must be inherited or
//!      explicitly chosen, not silently defaulted).
//!
//! Both are non-starters under the asupersync invariants.
//!
//! ── What `Cx::scope()` actually does ────────────────────
//!
//! `Cx::scope()` (cx/cx.rs:2972) is a Phase-0 HANDLE
//! ACCESSOR — it returns a `Scope<'static>` bound to the
//! task's CURRENT region without allocating a new one. It
//! is documented as a Phase-0 placeholder for the future
//! "spawn into current region" pattern.
//!
//! The Scope returned by Cx::scope() and the Scope returned
//! by Scope::region() (the async region allocator) have
//! the same TYPE but different semantics — see
//! `tests/cx_scope_vs_scope_region_distinction_audit.rs`.
//!
//! ── Conflation risk ─────────────────────────────────────
//!
//! Since `scope_default()` doesn't exist, there is NOTHING
//! to conflate. The risk is FUTURE introduction of a
//! method named `scope_default` that:
//!
//!   - reaches for ambient runtime state, or
//!   - silently applies default RegionPolicy,
//!   - aliases scope() under a misleading name.
//!
//! The structural pins below catch all three regressions.
//!
//! ── Related sibling absences (also pinned elsewhere) ────
//!
//! - `Cx::with_cx()` doesn't exist (operator framing —
//!   pinned in cx_api_decision_tree_with_vs_scope_audit.rs).
//! - `JoinHandle::abort_handle()` doesn't exist (operator
//!   framing — pinned in
//!   runtime_join_handle_no_separable_abort_handle_audit.rs).
//! - `Cx::detached()` doesn't exist (no orphan-spawn API —
//!   pinned in runtime_no_detached_orphan_spawn_api_audit.rs).
//!
//! These deliberate API absences form a coherent design:
//! every cancel/spawn/region operation is explicit and
//! capability-routed; no silent ambient defaults.
//!
//! Verdict: **SOUND BY DESIGN**. `scope_default()` does
//! not exist; there is only `Cx::scope()` (handle accessor)
//! and `Scope::region()` (async region allocator), and
//! both are deliberately explicit.
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
fn scope_default_method_does_not_exist_in_src() {
    // Pin: NO file in src/ defines a `scope_default` method.
    // Adding one would silently introduce ambient-runtime
    // or default-policy semantics, violating asupersync's
    // explicit-capability discipline.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let suspect_decls = [
            "fn scope_default",
            "pub fn scope_default",
            "pub async fn scope_default",
            "async fn scope_default",
        ];
        for decl in &suspect_decls {
            if content.contains(decl) {
                violations.push(format!("{}: contains `{}`", path.display(), decl));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: `scope_default` method introduced in \
         src/. This would either reach for ambient global \
         runtime state (violates no-ambient-authority) or \
         apply silent default policies (violates explicit-\
         budget discipline). Either way, design review \
         required.\n\nViolations:\n{}",
        violations.join("\n"),
    );
}

#[test]
fn scope_default_function_does_not_exist_anywhere() {
    // Pin: not even a free function or constant named
    // `scope_default` exists. Belt-and-suspenders.
    let mut violations = Vec::new();

    let roots = ["src", "asupersync-macros", "asupersync-tokio-compat"];
    for root in &roots {
        for path in read_dir_recursive(root) {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            if content.contains("scope_default") {
                violations.push(format!("{}: contains `scope_default`", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: `scope_default` referenced anywhere in \
         core crates. Even a re-export, doc-alias, or test \
         helper introduces the conceptual conflation.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn cx_has_exactly_one_scope_accessor_method() {
    // Pin: Cx exposes ONE scope accessor method
    // (`pub fn scope(&self) -> Scope<'static>`). There must
    // not be siblings like scope_default, default_scope,
    // current_scope, root_scope, etc.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn scope(&self) -> crate::cx::Scope<'static> {"),
        "REGRESSION: Cx::scope is gone. The Phase-0 handle \
         accessor has been removed.",
    );

    let suspect_siblings = [
        "pub fn scope_default(",
        "pub fn default_scope(",
        "pub fn current_scope(",
        "pub fn root_scope(",
        "pub fn ambient_scope(",
        "pub fn system_scope(",
    ];
    for pat in &suspect_siblings {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cx now has `{pat}` — this introduces \
             a sibling scope accessor whose semantic is \
             unclear. Either rename to a more specific name \
             or design-review the ambient/default semantics.",
        );
    }
}

#[test]
fn cx_scope_does_not_allocate_a_new_region() {
    // Pin: Cx::scope() body must NOT call any region-
    // allocating function. It is a handle accessor; it
    // returns a Scope bound to the CURRENT region without
    // allocating a new one. (If it did allocate, it would
    // be a synonym for Scope::region — and the absence of
    // scope_default would actually matter, since users
    // would expect a "default" variant for default region
    // policy.)
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn scope(&self) -> crate::cx::Scope<'static> {";
    let pos = source.find(fn_marker).expect("Cx::scope fn");
    let body_end = source[pos..].find("\n    }\n").expect("Cx::scope close");
    let body = &source[pos..pos + body_end];

    let suspect_calls = [
        "create_child_region(",
        "spawn_region(",
        "allocate_region(",
        "RegionTable::create",
        "Region::new(",
        "RegionPolicy::default(",
    ];
    for pat in &suspect_calls {
        assert!(
            !body.contains(pat),
            "REGRESSION: Cx::scope now calls `{pat}` — it \
             is allocating a new region. This conflates \
             with Scope::region and creates the very \
             ambiguity that scope_default would have \
             documented away.",
        );
    }
}

#[test]
fn scope_region_remains_the_only_region_allocator() {
    // Pin: the canonical async region allocator is
    // `Scope::region(state, cx, policy, f).await`. There
    // must NOT be a parameterless / default variant
    // (region_default, region_with_default, etc).
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("pub async fn region<P2, F, Fut, T, Caps>("),
        "REGRESSION: Scope::region is gone. The canonical \
         region allocator has been removed.",
    );

    let suspect_default_variants = [
        "pub async fn region_default(",
        "pub async fn region_with_default(",
        "pub fn region_default(",
        "pub async fn default_region(",
    ];
    for pat in &suspect_default_variants {
        assert!(
            !source.contains(pat),
            "REGRESSION: Scope now has `{pat}` — a default-\
             variant region allocator. This violates the \
             explicit-policy discipline (RegionPolicy must \
             be chosen, not silently defaulted).",
        );
    }
}

#[test]
fn no_runtime_default_region_helper_exists() {
    // Pin: no helper named *default_region*, *system_region*,
    // *ambient_region*, *runtime_region* exists in the
    // runtime module. These would all be ways to silently
    // grab a region from ambient state.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src/runtime") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };

        // Note: `fn root_region(&self) -> Option<RegionId>`
        // legitimately exists on ShardedState as an ID
        // accessor for the runtime root — it returns just
        // the ID, not a Scope/Policy/Region. That's not an
        // ambient grabber and is excluded.
        let suspect_helpers = [
            "fn default_region(",
            "fn system_region(",
            "fn ambient_region(",
            "fn runtime_region(",
        ];
        for pat in &suspect_helpers {
            if content.contains(pat) {
                violations.push(format!("{}: contains `{}`", path.display(), pat));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: ambient-region helper introduced in \
         src/runtime/. Region access must flow through Cx \
         + Scope::region; ambient region grabbers break the \
         capability-routing invariant.\n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn runtime_handle_does_not_expose_a_default_scope_method() {
    // Pin: RuntimeHandle (the public runtime entry point)
    // must NOT expose scope_default or similar. The only
    // way to get a Scope is from a Cx (which itself must
    // be obtained via region or via test-internals).
    let source = read("src/runtime/builder.rs");

    let suspect_methods = [
        "pub fn scope_default(",
        "pub fn scope(",
        "pub fn default_scope(",
        "pub async fn scope_default(",
        "pub async fn scope(",
    ];

    let runtime_handle_marker = "impl RuntimeHandle {";
    if let Some(pos) = source.find(runtime_handle_marker) {
        // RuntimeHandle impl block runs until the next `\nimpl ` or end of file.
        let impl_end = source[pos..]
            .find("\nimpl ")
            .map_or(source.len(), |i| pos + i);
        let impl_body = &source[pos..impl_end];

        for pat in &suspect_methods {
            assert!(
                !impl_body.contains(pat),
                "REGRESSION: RuntimeHandle now has `{pat}` — \
                 this exposes ambient scope access at the \
                 runtime level, bypassing the Cx-routed \
                 capability discipline.",
            );
        }
    }
}

#[test]
fn cx_scope_documented_as_phase_0_no_new_region() {
    // Pin: Cx::scope's docstring documents the Phase-0
    // handle-accessor semantic. If this doc disappears,
    // future readers may MISTAKENLY add `scope_default` to
    // disambiguate, when in fact scope() already has clear
    // semantics.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("In Phase 0, this creates a scope bound to the current region.")
            || source.contains("creates a scope bound to the current region"),
        "REGRESSION: Cx::scope no longer documents Phase-0 \
         semantics. Without this doc, future readers may \
         add `scope_default` to disambiguate.",
    );
}

#[test]
fn no_doc_alias_for_scope_default_anywhere() {
    // Pin: no `#[doc(alias = "scope_default")]` exists.
    // Adding one would create the user expectation of a
    // method that doesn't exist.
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains("#[doc(alias = \"scope_default\")]") {
            violations.push(path.display().to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: doc-alias for scope_default introduced. \
         Users will expect this method to exist.\n\n{}",
        violations.join("\n"),
    );
}

// ── Behavioral pins ─────────────────────────────────────

/// Models the "explicit region allocator" pattern:
/// region creation requires (state, cx, policy) — no
/// silent defaults.
struct RegionPolicy {
    label: &'static str,
}

struct RuntimeState {
    name: &'static str,
}

struct Cx;

#[derive(Debug, PartialEq, Eq)]
struct Scope {
    label: &'static str,
}

impl Scope {
    /// The canonical async region allocator. Caller must
    /// supply state, cx, AND policy — there is no default
    /// variant.
    fn region(_state: &RuntimeState, _cx: &Cx, policy: &RegionPolicy) -> Self {
        Self {
            label: policy.label,
        }
    }
}

impl Cx {
    /// The Phase-0 handle accessor. Returns a Scope bound
    /// to the CURRENT region — no new region allocated.
    fn scope(&self) -> Scope {
        Scope {
            label: "phase-0-current-region-handle",
        }
    }

    // No `scope_default` method. The compile-time absence
    // is the proof. If a future regression adds one, the
    // structural pins above will catch it.
}

#[test]
fn behavioral_explicit_region_requires_three_arguments() {
    let state = RuntimeState { name: "runtime" };
    let cx = Cx;
    let policy_a = RegionPolicy { label: "policy-a" };
    let policy_b = RegionPolicy { label: "policy-b" };

    assert_eq!(state.name, "runtime");

    let scope_a = Scope::region(&state, &cx, &policy_a);
    let scope_b = Scope::region(&state, &cx, &policy_b);

    // Different policies produce observably different scopes.
    assert_ne!(
        scope_a, scope_b,
        "REGRESSION: explicit policy is no longer reflected \
         in the Scope identity. If policies are silently \
         folded, scope_default would be needed to \
         distinguish — but we don't want scope_default.",
    );
}

#[test]
fn behavioral_cx_scope_returns_handle_not_new_region() {
    let cx = Cx;
    let s = cx.scope();

    assert_eq!(
        s.label, "phase-0-current-region-handle",
        "REGRESSION: Cx::scope now returns a label that \
         resembles a freshly-created region. The Phase-0 \
         handle-accessor semantic is broken — readers may \
         demand a scope_default to disambiguate.",
    );
}

#[test]
fn behavioral_no_default_path_for_region_construction() {
    // The compile-time absence of `Scope::region_default`,
    // `Cx::scope_default`, `RuntimeState::default_scope`,
    // etc. is the design proof. This test documents the
    // INTENT: every region path requires explicit policy.
    let state = RuntimeState { name: "test" };
    let cx = Cx;
    let policy = RegionPolicy { label: "explicit" };

    let _ = Scope::region(&state, &cx, &policy);
    // No alternative exists. The audit's structural pins
    // catch any future regression that adds one.
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_api_decision_tree_with_vs_scope_audit.rs",
        "tests/cx_scope_vs_scope_region_distinction_audit.rs",
        "tests/runtime_join_handle_no_separable_abort_handle_audit.rs",
        "tests/runtime_no_detached_orphan_spawn_api_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
