//! Audit + regression test for `src/runtime/scheduler/three_lane.rs`
//! `ThreeLaneScheduler` constructor edge-case handling for
//! `worker_count == 0` and `worker_count == 1`.
//!
//! Operator's question: "when worker count is configured to 0 or
//! 1, do we (a) panic with clear error, (b) silently create 1
//! worker (correct fallback), or (c) deadlock?"
//!
//! Audit findings:
//!
//!   Per `br-asupersync-niczb3` (a prior fix referenced in the
//!   constructor docs), the asupersync scheduler offers BOTH
//!   options:
//!
//!   1. **Infallible constructors** (`new`, `new_with_options`,
//!      `new_with_options_and_task_table`) clamp `worker_count
//!      == 0` to `1` via `let worker_count = worker_count.max(1)`
//!      (three_lane.rs:1108). This is option (b): silently
//!      create 1 worker (correct fallback). The clamp is
//!      explicit AND documented in the constructor doc-
//!      comments — NOT a silent surprise; existing callers
//!      that pass `0` get the documented clamp behavior.
//!
//!   2. **Fallible constructors** (`try_new`,
//!      `try_new_with_options_and_task_table`) return
//!      `Err(crate::error::Error::new(ErrorKind::ConfigError))`
//!      with a clear human-readable message
//!      (three_lane.rs:1306-1315). This is option (a) — typed
//!      error, NOT a panic. New callers that want strict
//!      validation use these.
//!
//!   The historical context: the fix doc explicitly notes
//!   "pre-fix the silent clamp existed only to clamp
//!   cancel_streak_limit, and worker_count == 0 produced an
//!   empty `workers` Vec that silently hung `block_on`
//!   forever" (three_lane.rs:1025-1028). So option (c)
//!   deadlock WAS the pre-fix behavior; the fix moved
//!   infallible callers to (b) clamp and added (a) Err for
//!   strict callers.
//!
//!   `worker_count == 1` is the ordinary single-worker case
//!   and needs no special handling — both constructor paths
//!   accept it.
//!
//! Verdict: **SOUND**. Neither path deadlocks. Operators
//! choose between clamp-to-1 (b) and typed-error (a) via
//! constructor selection.
//!
//! A regression that:
//!   - removed the `.max(1)` clamp from the infallible
//!     constructors (would re-introduce the
//!     hung-block_on failure mode the fix closed),
//!   - changed the fallible constructors to panic instead of
//!     returning Err (would force callers to wrap in
//!     catch_unwind for graceful failure),
//!   - lost the documented contract about the clamp /
//!     typed-error split (operators would get unexpected
//!     behavior from one constructor or the other),
//!   - removed the br-asupersync-niczb3 reference from the
//!     constructor docs (would lose the historical context
//!     for future maintainers — the silent-hang failure
//!     mode the fix closed),
//! would all be caught here.

use std::path::PathBuf;

fn read_three_lane_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/runtime/scheduler/three_lane.rs");
    std::fs::read_to_string(&path).expect("read three_lane.rs")
}

#[test]
fn infallible_constructor_clamps_worker_count_to_at_least_one() {
    // Pin AUDIT-CRITICAL: the infallible
    // `new_with_options_and_task_table` clamps `worker_count
    // == 0` to `1`. Without this clamp, an empty workers Vec
    // would silently hang block_on forever (the documented
    // pre-fix bug).
    let source = read_three_lane_source();

    let fn_marker = "pub fn new_with_options_and_task_table(";
    let start = source
        .find(fn_marker)
        .expect("new_with_options_and_task_table fn");
    let after = &source[start + fn_marker.len()..];
    // Take a generous window for the long fn body.
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let body = &source[start..safe_end];
    let _ = after;

    assert!(
        body.contains("let worker_count = worker_count.max(1);"),
        "REGRESSION: new_with_options_and_task_table no longer \
         clamps worker_count to >= 1. Without the clamp, \
         worker_count=0 produces an empty workers Vec; the \
         scheduler accepts spawn calls but never dispatches \
         them — block_on hangs forever. This is the EXACT \
         pre-fix bug the br-asupersync-niczb3 audit closed.\n\n\
         fn body:\n{body}",
    );
}

#[test]
fn fallible_constructor_rejects_zero_with_config_error() {
    // Pin AUDIT-CRITICAL: try_new_with_options_and_task_table
    // returns Err(ConfigError) for worker_count == 0. New
    // callers that want strict validation use this; old
    // callers that want clamp-to-1 use the infallible path.
    let source = read_three_lane_source();

    let fn_marker = "pub fn try_new_with_options_and_task_table(";
    let start = source
        .find(fn_marker)
        .expect("try_new_with_options_and_task_table fn");
    let after = &source[start + fn_marker.len()..];
    let window_end = (start + 3000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let body = &source[start..safe_end];
    let _ = after;

    assert!(
        body.contains("if worker_count == 0 {")
            && body.contains("crate::error::ErrorKind::ConfigError"),
        "REGRESSION: try_new_with_options_and_task_table no \
         longer rejects worker_count == 0 with \
         ErrorKind::ConfigError. The fallible path is the \
         strict-validation entry point; without the early-\
         return, fallible callers don't get a clean typed \
         error.\n\nfn body:\n{body}",
    );

    // The error message must be diagnostic — not a generic
    // "ConfigError" with no context.
    assert!(
        body.contains("worker_count >= 1"),
        "REGRESSION: try_new error message no longer mentions \
         the worker_count >= 1 requirement. The diagnostic is \
         what tells operators what's wrong; without it, they \
         see only a generic ConfigError.",
    );
}

#[test]
fn try_new_top_level_constructor_exists() {
    // Pin: the top-level try_new constructor exists alongside
    // the underlying try_new_with_options_and_task_table.
    // Most callers want this convenience entry point.
    let source = read_three_lane_source();

    assert!(
        source.contains("pub fn try_new(\n        worker_count: usize,"),
        "REGRESSION: try_new top-level constructor is gone. \
         Without it, callers must use the verbose \
         try_new_with_options_and_task_table for strict \
         validation. Re-add the convenience entry point.",
    );
}

#[test]
fn infallible_constructor_doc_documents_the_clamp_behavior() {
    // Pin: the infallible new() doc-comment explicitly
    // documents the clamp. Operators relying on the
    // infallible path need to know what happens with
    // worker_count == 0.
    let source = read_three_lane_source();

    // The doc above `pub fn new(` must mention the clamp
    // behavior and the historical bug.
    let fn_marker = "pub fn new(worker_count: usize, state: &Arc<ContendedMutex<RuntimeState>>) -> Self {";
    let fn_pos = source.find(fn_marker).expect("new constructor");
    let mut doc_start = fn_pos;
    for _ in 0..30 {
        match source[..doc_start].rfind('\n') {
            Some(p) => doc_start = p,
            None => {
                doc_start = 0;
                break;
            }
        }
    }
    let doc_window = &source[doc_start..fn_pos];

    let required_phrases = [
        "br-asupersync-niczb3",
        "worker_count` MUST be `>= 1`",
        "clamp",
        "try_new",
    ];
    for phrase in &required_phrases {
        assert!(
            doc_window.contains(phrase),
            "REGRESSION: infallible new() doc no longer \
             mentions `{phrase}`. The doc is the public \
             contract for the silent-clamp behavior; without \
             it, operators don't know that worker_count=0 \
             gets clamped to 1 (and don't know about the \
             try_new alternative).\n\ndoc window:\n{doc_window}",
        );
    }
}

#[test]
fn fallible_constructor_doc_documents_the_error_path() {
    // Pin: the fallible try_new_with_options_and_task_table
    // doc-comment documents the # Errors section AND the
    // br-asupersync-niczb3 reference.
    let source = read_three_lane_source();

    let fn_marker = "pub fn try_new_with_options_and_task_table(";
    let fn_pos = source.find(fn_marker).expect("try_new fn");
    let mut doc_start = fn_pos;
    for _ in 0..40 {
        match source[..doc_start].rfind('\n') {
            Some(p) => doc_start = p,
            None => {
                doc_start = 0;
                break;
            }
        }
    }
    let doc_window = &source[doc_start..fn_pos];

    assert!(
        doc_window.contains("# Errors"),
        "REGRESSION: try_new doc no longer has a `# Errors` \
         section. Standard rustdoc convention; without it, \
         clippy::missing_errors_doc may fire.\n\n\
         doc window:\n{doc_window}",
    );
    assert!(
        doc_window.contains("ErrorKind::ConfigError")
            && doc_window.contains("worker_count == 0"),
        "REGRESSION: try_new doc no longer documents the \
         specific error variant + condition. Operators rely \
         on this documentation to write their match arms.\n\n\
         doc window:\n{doc_window}",
    );
}

#[test]
fn historical_pre_fix_failure_mode_documented_in_doc() {
    // Pin: the doc explicitly documents the pre-fix silent-
    // hang failure mode. Future maintainers reading the
    // constructor doc see WHY the clamp / typed-error split
    // exists.
    let source = read_three_lane_source();

    assert!(
        source.contains("silently hung `block_on` forever")
            || source.contains("silently hangs block_on"),
        "REGRESSION: the pre-fix failure mode (silent block_on \
         hang on worker_count==0) is no longer documented. \
         The doc is the institutional memory of this audit's \
         resolution; without it, a future maintainer might \
         remove the clamp thinking it's redundant.",
    );
}

#[test]
fn cancel_streak_limit_clamped_to_at_least_one() {
    // Pin: the constructor also clamps cancel_streak_limit
    // and governor_interval to >= 1. A 0-cancel-streak-limit
    // would mean the cancel-streak fairness gate fires
    // immediately, starving cancel work; a 0-governor-
    // interval would divide-by-zero in the governor's
    // adaptive budget calculation.
    let source = read_three_lane_source();

    let fn_marker = "pub fn new_with_options_and_task_table(";
    let start = source.find(fn_marker).expect("new_with_options fn");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("let cancel_streak_limit = cancel_streak_limit.max(1);"),
        "REGRESSION: cancel_streak_limit no longer clamped \
         to >= 1. A 0-limit would cause the cancel-streak \
         fairness gate (`if cancel_streak < limit`) to be \
         falsy on first iteration, indefinitely starving \
         cancel work even when cancel_lane has tasks.\n\n\
         fn body:\n{body}",
    );

    assert!(
        body.contains("let governor_interval = governor_interval.max(1);"),
        "REGRESSION: governor_interval no longer clamped to \
         >= 1. A 0-interval would divide-by-zero in adaptive \
         budget calc.\n\nfn body:\n{body}",
    );
}

#[test]
fn worker_count_one_is_a_valid_first_class_configuration() {
    // Pin: worker_count == 1 is a valid configuration with
    // no special-case handling. It just creates a 1-worker
    // scheduler. We verify by checking that the workers
    // SmallVec is allocated with `worker_count` capacity AFTER
    // the clamp.
    let source = read_three_lane_source();

    assert!(
        source.contains("SmallVec::<[ThreeLaneWorker; 16]>::with_capacity(worker_count)"),
        "REGRESSION: workers SmallVec is no longer constructed \
         with `with_capacity(worker_count)`. After the \
         clamp-to->=1, the capacity must be the actual \
         worker count (1 or higher) so allocations are \
         right-sized.",
    );
}

// ─── Behavioral end-to-end pin (gated on test-internals) ────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::runtime::scheduler::ThreeLaneScheduler;
    use asupersync::runtime::state::RuntimeState;
    use asupersync::sync::ContendedMutex;
    use std::sync::Arc;

    fn fresh_state() -> Arc<ContendedMutex<RuntimeState>> {
        Arc::new(ContendedMutex::new("test_state", RuntimeState::new()))
    }

    #[test]
    fn infallible_new_with_zero_worker_count_clamps_to_one() {
        // Pin AUDIT-CRITICAL: infallible new(0) does NOT
        // panic AND does NOT hang — produces a 1-worker
        // scheduler.
        let state = fresh_state();
        let scheduler = ThreeLaneScheduler::new(0, &state);
        assert_eq!(
            scheduler.worker_count(),
            1,
            "REGRESSION: ThreeLaneScheduler::new(0) did not \
             clamp to 1 worker. Got {} workers — the silent-\
             hang pre-fix bug is back.",
            scheduler.worker_count(),
        );
    }

    #[test]
    fn try_new_with_zero_worker_count_returns_config_error() {
        // Pin: try_new(0) returns Err(ConfigError), NOT
        // panic, NOT clamp.
        let state = fresh_state();
        let result = ThreeLaneScheduler::try_new(0, &state);
        match result {
            Err(e) => {
                assert_eq!(
                    e.kind(),
                    asupersync::error::ErrorKind::ConfigError,
                    "REGRESSION: try_new(0) returned wrong \
                     error kind: {:?}",
                    e.kind(),
                );
            }
            Ok(_) => panic!(
                "REGRESSION: try_new(0) returned Ok — strict \
                 validation is broken; the fallible path \
                 should reject 0."
            ),
        }
    }

    #[test]
    fn infallible_new_with_one_worker_count_creates_one_worker() {
        // Pin: worker_count == 1 is a valid configuration.
        let state = fresh_state();
        let scheduler = ThreeLaneScheduler::new(1, &state);
        assert_eq!(scheduler.worker_count(), 1);
    }

    #[test]
    fn try_new_with_one_worker_count_returns_ok() {
        // Pin: try_new(1) succeeds with a 1-worker scheduler.
        let state = fresh_state();
        let result = ThreeLaneScheduler::try_new(1, &state);
        assert!(
            result.is_ok(),
            "REGRESSION: try_new(1) returned Err — \
             worker_count=1 is valid and must succeed.",
        );
        assert_eq!(result.unwrap().worker_count(), 1);
    }

    #[test]
    fn infallible_new_with_typical_worker_count_succeeds() {
        // Pin: typical worker counts (e.g. 4, 8, 16) work
        // unchanged.
        let state = fresh_state();
        for n in [2, 4, 8, 16] {
            let scheduler = ThreeLaneScheduler::new(n, &state);
            assert_eq!(
                scheduler.worker_count(),
                n,
                "REGRESSION: new({n}) produced wrong worker \
                 count {}",
                scheduler.worker_count(),
            );
        }
    }
}
