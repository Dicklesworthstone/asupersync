//! Audit + regression test for tracing-subscriber lifecycle vs.
//! `Runtime` drop.
//!
//! Operator's question: "when asupersync runtime is dropped, is the
//! global tracing subscriber properly uninstalled (correct:
//! prevents post-drop log emissions panicking) or left dangling
//! (incorrect)?"
//!
//! Audit findings:
//!
//!   The asupersync runtime **does not install a global tracing
//!   subscriber**. There is therefore nothing to uninstall on
//!   drop, and the operator's "left dangling" failure mode is
//!   structurally impossible.
//!
//!   Two facts establish this:
//!
//!   1. **Production code never calls `set_global_default`** or
//!      any equivalent global install API. A repository-wide
//!      grep across `src/` finds no
//!      `tracing::subscriber::set_global_default(...)` /
//!      `tracing_subscriber::registry().init()` /
//!      `SubscriberInitExt::init` / `SubscriberInitExt::try_init`
//!      sites in production paths. The runtime emits via
//!      `tracing::warn!` / `error!` / etc. from
//!      `crate::tracing_compat`, which are NO-OP macros when
//!      the `tracing-integration` feature is off and dispatch
//!      to whatever subscriber the USER installed in their
//!      `main()` when the feature is on.
//!
//!   2. **The only subscriber installs are scoped**, inside
//!      `lab/oracle/fabric.rs:920` and `lab/oracle/mod.rs:1679`,
//!      both via `tracing::subscriber::with_default(subscriber,
//!      || ...)`. `with_default` returns a `DefaultGuard` that
//!      is dropped at the end of the closure — the subscriber
//!      is automatically uninstalled when the closure returns,
//!      regardless of whether the closure panicked. There is
//!      NO scenario where these scoped installs outlive the
//!      runtime that uses them.
//!
//!   `RuntimeInner::drop` (`src/runtime/builder.rs:3696-3714`)
//!   handles three teardown actions: signal-and-join the
//!   deadline-monitor thread, call `scheduler.shutdown()`, and
//!   shutdown the blocking pool. It does NOT touch any tracing
//!   subscriber state because the runtime never installed one.
//!
//!   The user owns subscriber lifecycle entirely:
//!     - User installs in `main()` (typically via
//!       `tracing_subscriber::registry().init()`).
//!     - User's subscriber lives for the entire process lifetime.
//!     - When the user's `Runtime` drops, the runtime stops
//!       emitting events but the user's subscriber is still
//!       registered to handle any further events from other
//!       sources (the user's own code, third-party libs, etc.).
//!     - Post-drop emissions from the runtime simply don't
//!       happen — `RuntimeInner::drop` joins all worker
//!       threads before returning, so there is no live
//!       runtime code emitting events after drop.
//!
//! Verdict: **SOUND**. The "post-drop log emissions panicking"
//! failure mode the operator flags is structurally impossible
//! because:
//!   - No production code installs a global subscriber that
//!     could be left dangling.
//!   - All scoped installs are RAII-bounded by `with_default`,
//!     which always uninstalls on guard drop.
//!   - `RuntimeInner::drop` joins all worker threads, so no
//!     post-drop emissions can occur from the runtime.
//!
//! A regression that:
//!   - introduced `tracing::subscriber::set_global_default(...)`
//!     anywhere in `src/` outside test fixtures (would make
//!     the runtime own the subscriber's lifecycle and need
//!     explicit uninstall),
//!   - replaced `with_default(...)` in lab/oracle/* with
//!     `set_global_default(...)` (would leak the test fixture's
//!     subscriber into the global slot),
//!   - removed the worker-thread join from `RuntimeInner::drop`
//!     (would let runtime worker code emit events after the
//!     user's process started teardown — a different but
//!     related failure),
//! would all be caught here.

use std::ffi::OsStr;
use std::path::PathBuf;

fn project_dir(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn collect_rs_files(dir: &PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_rs_files(&path));
        } else if path.extension() == Some(OsStr::new("rs")) {
            out.push(path);
        }
    }
    out
}

#[test]
fn no_set_global_default_in_production_code() {
    // Pin AUDIT-CRITICAL: NO production source file calls
    // `set_global_default`, `init`, or any equivalent global
    // tracing-subscriber install API. A regression that
    // introduced one would shift subscriber lifecycle into
    // the runtime — making the "left dangling on drop"
    // failure possible.
    //
    // Allowlist: lab/oracle/* uses scoped `with_default` only,
    // not global install. Test fixtures and #[cfg(test)] code
    // are scoped to test runs and don't affect production.
    let src_dir = project_dir("src");
    let mut findings: Vec<String> = Vec::new();

    let suspect_global_apis = [
        "set_global_default(",
        "tracing_subscriber::registry().init()",
        "SubscriberInitExt::init",
        ".try_init()",
        "tracing::dispatcher::set_global_default(",
    ];

    for path in collect_rs_files(&src_dir) {
        let path_str = path.display().to_string();
        // Skip lab fixtures (they may use init() in their own
        // test scaffolding) and test-only modules.
        if path_str.contains("/lab/") {
            continue;
        }
        // Skip the tracing_compat shim itself — it's the
        // re-export point and may reference these APIs in
        // doc comments.
        if path_str.ends_with("/tracing_compat.rs") {
            continue;
        }
        // Skip test-infrastructure files. test_utils.rs's
        // init_test_logging is invoked by in-crate tests only;
        // it's `pub` so tests across modules share it.
        if path_str.ends_with("/test_utils.rs")
            || path_str.ends_with("/test_logging.rs")
            || path_str.ends_with("/test_ndjson.rs")
            || path_str.ends_with("/test_log_schema.rs")
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Skip in-crate test modules (#[cfg(test)] blocks
        // commonly use init for test-only subscribers).
        // We pin only the production paths; test paths are
        // documented in the audit doc comment as expected.
        for pat in &suspect_global_apis {
            if content.contains(pat) {
                // Walk the content line-by-line and report each
                // line where the pattern appears, EXCLUDING
                // lines that are inside a `#[cfg(test)]` block
                // OR lines that are doc comments.
                for (line_no, line) in content.lines().enumerate() {
                    if line.contains(pat) {
                        let trimmed = line.trim_start();
                        let is_doc = trimmed.starts_with("///") || trimmed.starts_with("//!");
                        let is_comment = trimmed.starts_with("//") && !is_doc;
                        if is_doc || is_comment {
                            continue;
                        }
                        findings.push(format!(
                            "{path_str}:{line_no}: {line}",
                            line_no = line_no + 1,
                        ));
                    }
                }
            }
        }
    }

    // Filter out findings inside #[cfg(test)] / mod tests blocks
    // — heuristic but conservative.
    let production_findings: Vec<&String> = findings
        .iter()
        .filter(|f| {
            // If the finding is in a path that includes "tests"
            // or under a #[cfg(test)] mod, skip. This is a coarse
            // filter; the comprehensive list is the audit doc.
            !f.contains("/tests/") && !f.contains("_tests.rs")
        })
        .collect();

    if !production_findings.is_empty() {
        let mut report = String::from(
            "REGRESSION: production code now installs a global \
             tracing subscriber. The runtime previously did NOT \
             own subscriber lifecycle — the user's main() did. \
             Adding a global install here means RuntimeInner::\
             drop must also uninstall, OR the runtime accepts a \
             subscriber lifecycle constraint it didn't have \
             before. Audit the new install site and update this \
             pin.\n\nFindings:\n",
        );
        for finding in &production_findings {
            report.push_str(&format!("  {finding}\n"));
        }
        panic!("{report}");
    }
}

#[test]
fn lab_oracle_uses_scoped_with_default_only() {
    // Pin: the only subscriber installs in lab fixtures use
    // `with_default(subscriber, || ...)` — RAII-bounded by the
    // closure scope. A regression that switched to
    // `set_global_default` would leak the test subscriber into
    // the global slot for the duration of the process.
    let lab_oracle_files = ["src/lab/oracle/fabric.rs", "src/lab/oracle/mod.rs"];

    for rel in &lab_oracle_files {
        let path = project_dir(rel);
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };

        // The file should contain `with_default` calls.
        assert!(
            content.contains("tracing::subscriber::with_default("),
            "REGRESSION: {rel} no longer uses scoped \
             `tracing::subscriber::with_default(...)`. Test \
             fixtures install subscribers via with_default to \
             ensure auto-uninstall on closure return.",
        );

        // The file MUST NOT contain `set_global_default`.
        assert!(
            !content.contains("tracing::subscriber::set_global_default("),
            "REGRESSION: {rel} now uses \
             `tracing::subscriber::set_global_default(...)`. \
             A global install in a test fixture leaks the \
             subscriber into the process-wide slot — every \
             other test that runs after this one will dispatch \
             to it. Switch back to with_default for scoped \
             install.",
        );
    }
}

#[test]
fn runtime_inner_drop_does_not_touch_tracing() {
    // Pin: RuntimeInner::drop touches deadline_monitor /
    // scheduler / blocking_pool / worker_threads — but NOT
    // tracing subscriber state. A regression that added
    // tracing-subscriber teardown here would couple the
    // runtime to subscriber lifecycle.
    let path = project_dir("src/runtime/builder.rs");
    let content = std::fs::read_to_string(&path).expect("read builder.rs");

    let impl_marker = "impl Drop for RuntimeInner {";
    let start = content.find(impl_marker).expect("RuntimeInner Drop impl");
    let end_rel = content[start..].find("\n}\n").expect("Drop close");
    let body = &content[start..start + end_rel];

    let suspect_subscriber_ops = [
        "set_global_default",
        "DefaultGuard",
        "subscriber.uninstall",
        "tracing::dispatcher",
        "Dispatcher::default",
    ];
    for pat in &suspect_subscriber_ops {
        assert!(
            !body.contains(pat),
            "REGRESSION: RuntimeInner::drop now references \
             `{pat}` — looks like tracing-subscriber teardown \
             work. The audit invariant is that the runtime \
             does NOT own subscriber lifecycle. If lifecycle \
             ownership genuinely needs to move into the \
             runtime, update this pin AND verify drop is \
             panic-safe (a panic during drop is double-fault \
             abort).\n\nimpl body:\n{body}",
        );
    }
}

#[test]
fn runtime_inner_drop_joins_worker_threads_no_post_drop_emissions() {
    // Pin: RuntimeInner::drop joins all worker threads via
    // handle.join(). After drop returns, no runtime code is
    // running — so there are NO post-drop tracing emissions
    // from the runtime even if the user has a subscriber
    // installed.
    let path = project_dir("src/runtime/builder.rs");
    let content = std::fs::read_to_string(&path).expect("read builder.rs");

    let impl_marker = "impl Drop for RuntimeInner {";
    let start = content.find(impl_marker).expect("RuntimeInner Drop impl");
    let end_rel = content[start..].find("\n}\n").expect("Drop close");
    let body = &content[start..start + end_rel];

    assert!(
        body.contains("for handle in handles.drain(..) {"),
        "REGRESSION: RuntimeInner::drop no longer drains and \
         joins worker thread handles. Without join, runtime \
         worker threads can keep running after drop returns — \
         emitting tracing events into the user's still-live \
         subscriber from a 'logically dead' runtime. While this \
         doesn't cause a panic, it DOES surface 'phantom' \
         events that confuse SREs.\n\nimpl body:\n{body}",
    );

    assert!(
        body.contains("let _ = handle.join();"),
        "REGRESSION: worker thread join is no longer fire-and-\
         forget via `let _ = handle.join()`. A regression that \
         propagated the join error could panic in drop, which \
         is a double-fault abort.",
    );

    assert!(
        body.contains("self.scheduler.shutdown();"),
        "REGRESSION: RuntimeInner::drop no longer signals the \
         scheduler to shutdown. Without the signal, worker \
         threads continue running until they observe shutdown \
         via some other path — delaying the join.",
    );
}

#[test]
fn tracing_compat_emits_via_re_exported_macros() {
    // Pin: the runtime emits via `crate::tracing_compat::warn!`
    // etc. — re-exports of `tracing::warn!` when the
    // `tracing-integration` feature is on, and no-op macros
    // when off. Either way, the runtime DOES NOT own subscriber
    // lifecycle; it just emits events that the user's
    // subscriber (if any) handles.
    let path = project_dir("src/tracing_compat.rs");
    let content = std::fs::read_to_string(&path).expect("read tracing_compat.rs");

    // Feature-gated re-export: when tracing-integration is on,
    // re-export tracing's macros.
    assert!(
        content.contains("#[cfg(feature = \"tracing-integration\")]")
            && content.contains("pub use tracing::"),
        "REGRESSION: tracing_compat no longer feature-gates the \
         tracing re-exports on `tracing-integration`. The \
         feature-gate is what lets the runtime compile with \
         zero tracing dependencies for users who don't want \
         them.\n\ncontent excerpt: ..(see file)..",
    );

    // No-op fallback when feature is off.
    assert!(
        content.contains("#[cfg(not(feature = \"tracing-integration\"))]"),
        "REGRESSION: tracing_compat no longer has the no-op \
         fallback for the off-feature case. Without it, the \
         runtime would fail to compile when the user disables \
         the feature.",
    );

    // The fallback macros expand to nothing — they don't try
    // to install or interact with a subscriber.
    let suspect_subscriber_in_fallback = ["set_global_default", "Dispatcher", "subscriber"];
    let fallback_marker = "#[cfg(not(feature = \"tracing-integration\"))]";
    if let Some(fb_pos) = content.find(fallback_marker) {
        let fb_end = content[fb_pos..]
            .find("\n#[cfg(")
            .map_or(content.len(), |o| fb_pos + o);
        let fallback_block = &content[fb_pos..fb_end];
        for pat in &suspect_subscriber_in_fallback {
            assert!(
                !fallback_block.contains(pat),
                "REGRESSION: tracing_compat's no-op fallback \
                 references `{pat}` — but the fallback exists \
                 specifically to AVOID any subscriber \
                 interaction when the feature is off. The \
                 fallback must be macros that expand to \
                 nothing.",
            );
        }
    }
}

#[test]
fn no_subscriber_field_on_runtime_inner() {
    // Pin: RuntimeInner does NOT have a `subscriber:
    // Box<dyn Subscriber>` (or DefaultGuard / similar) field.
    // If it did, the runtime would own subscriber lifecycle
    // and need explicit uninstall on drop. The audit invariant
    // is that the runtime is subscriber-agnostic.
    let path = project_dir("src/runtime/builder.rs");
    let content = std::fs::read_to_string(&path).expect("read builder.rs");

    let struct_marker = "struct RuntimeInner {";
    let start = content.find(struct_marker).expect("RuntimeInner struct");
    let end_rel = content[start..].find("\n}\n").expect("RuntimeInner close");
    let body = &content[start..start + end_rel];

    let suspect_field_patterns = [
        "Box<dyn Subscriber",
        "DefaultGuard",
        "tracing_subscriber::Registry",
        "subscriber: ",
        "tracing_dispatcher: ",
    ];
    for pat in &suspect_field_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: RuntimeInner now has a field that \
             looks like a subscriber handle: `{pat}`. The \
             audit invariant relies on the runtime being \
             subscriber-agnostic — adding a subscriber field \
             couples runtime drop to subscriber teardown, \
             re-opening the operator's failure mode.\n\n\
             struct body:\n{body}",
        );
    }
}
