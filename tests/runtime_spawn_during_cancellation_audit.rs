//! Audit + regression test for spawn-during-cancellation
//! correctness in `src/runtime/state.rs` and the region admission
//! gate.
//!
//! Operator's question: "when task A is being cancelled and during
//! its drop-handler it spawns task B, does B observe parent A as
//! cancelled (correct: structured) or run independently (orphan)?
//! Per AGENTS.md."
//!
//! Audit findings:
//!
//!   When task A is being cancelled, A's region transitions to
//!   Closing state (via `region.begin_close(reason)`). The
//!   region's admission gate (`can_spawn() / can_accept_work()`)
//!   returns false for any state other than Open. So a user
//!   call to `state.create_task(region, ...)` from A's drop-
//!   handler is REJECTED with a typed
//!   `SpawnError::RegionClosed(region)` error — NOT silently
//!   created as an orphan.
//!
//!   Audit chain:
//!
//!   1. **`RegionState::can_spawn`** (`src/record/region.rs:127`)
//!      returns `matches!(self, Self::Open)`. Only Open regions
//!      accept new work. Closing / Draining / Finalizing /
//!      Closed all reject.
//!
//!   2. **`RegionRecord::add_task`** is the admission gate. When
//!      called in non-Open state, it returns
//!      `AdmissionError::Closed`.
//!
//!   3. **`RuntimeState::create_task`** (state.rs:1619) calls
//!      `region_record.add_task(task_id)`. On
//!      `AdmissionError::Closed`, it rolls back the partial task
//!      creation (`remove_task`) AND returns
//!      `SpawnError::RegionClosed(region)` (state.rs:1533).
//!
//!   4. **The user-facing spawn path** propagates this error to
//!      the caller via the standard `Result<TaskId, SpawnError>`
//!      return type. A drop-handler spawn that ignored the Err
//!      would be the user's bug — but the FRAMEWORK refuses to
//!      create the orphan.
//!
//!   5. **The legitimate during-cancel spawn path** is
//!      `RuntimeState::spawn_finalizer_task` (state.rs:3000-3060)
//!      which uses `create_task_infrastructure(region_id, budget,
//!      true)` where `true` is `is_cleanup`. This routes through
//!      `add_cleanup_task` instead of `add_task`. Cleanup tasks
//!      ARE allowed in Finalizing state — that's the whole point
//!      of finalizers. But cleanup admission is NOT exposed as a
//!      user-spawn API; it's restricted to the finalizer
//!      registry.
//!
//!   In-crate test `cancel_request_should_prevent_new_spawns`
//!   (state.rs:7911) explicitly pins this: after
//!   `state.cancel_request(region, ...)`,
//!   `region_state.can_spawn()` returns false AND
//!   `state.create_task(region, ...)` returns
//!   `Err(SpawnError::RegionClosed(_))`.
//!
//! Verdict: **SOUND**. The "no orphan tasks" invariant from
//! AGENTS.md is upheld for spawns during cancellation. The
//! framework rejects user spawns with a typed error rather
//! than creating an orphan; the controlled finalizer-spawn path
//! is the only during-cancel admission and it's bound to the
//! same closing region (NOT orphaned).
//!
//! A regression that:
//!   - changed `RegionState::can_spawn` to accept Closing /
//!     Draining (would let drop-handler spawns silently
//!     orphan into a closing region — they'd still be tracked
//!     but their parent has logically committed to close),
//!   - changed `add_task` admission to silently succeed in
//!     non-Open states (would create the orphan — task in a
//!     closed region),
//!   - changed the SpawnError mapping in create_task to swallow
//!     the AdmissionError::Closed (would let create_task
//!     return Ok with a half-created task — leak risk),
//!   - opened the cleanup-spawn path to user code without
//!     restriction (would let any code masquerade as a
//!     finalizer and spawn into closed regions),
//!   - removed the existing
//!     cancel_request_should_prevent_new_spawns in-crate
//!     test (would let regressions slip through CI),
//!     would all be caught here.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn region_can_spawn_only_when_open() {
    // Pin AUDIT-CRITICAL: RegionState::can_spawn returns true
    // ONLY for Open. A regression that accepted Closing /
    // Draining would let drop-handler spawns succeed and
    // orphan tasks into a region that's already committing to
    // close.
    let source = read("src/record/region.rs");

    let fn_marker = "pub const fn can_spawn(self) -> bool {";
    let start = source.find(fn_marker).expect("can_spawn fn");
    let body_end = source[start..].find("\n    }\n").expect("can_spawn close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("matches!(self, Self::Open)"),
        "REGRESSION: RegionState::can_spawn no longer returns \
         `matches!(self, Self::Open)`. The Open-only admission \
         is what makes spawn-during-cancel rejection \
         load-bearing — accepting Closing / Draining states \
         would let user drop-handlers create orphans.\n\n\
         fn body:\n{body}",
    );
}

#[test]
fn region_can_accept_work_only_when_open() {
    // Pin: can_accept_work (used by add_task admission) ALSO
    // returns true only for Open. Doc explicitly notes
    // Finalizing is excluded so admission can't silently
    // re-open a closing region.
    let source = read("src/record/region.rs");

    let fn_marker = "pub const fn can_accept_work(self) -> bool {";
    let start = source.find(fn_marker).expect("can_accept_work fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("can_accept_work close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("matches!(self, Self::Open)"),
        "REGRESSION: can_accept_work no longer restricts to \
         Open. Without this gate, user spawns into a \
         Closing/Draining/Finalizing region would silently \
         succeed — orphan tasks attached to a closing parent.",
    );

    // Doc must explain WHY Finalizing is excluded.
    let mut doc_start = source.find(fn_marker).unwrap();
    for _ in 0..15 {
        match source[..doc_start].rfind('\n') {
            Some(p) => doc_start = p,
            None => {
                doc_start = 0;
                break;
            }
        }
    }
    let doc_window = &source[doc_start..source.find(fn_marker).unwrap()];

    assert!(
        doc_window.contains("Finalizing is intentionally excluded"),
        "REGRESSION: can_accept_work doc no longer explains \
         the Finalizing exclusion. The doc is the public \
         contract — without it, future maintainers might \
         loosen the gate without realizing the orphan-leak \
         risk.\n\ndoc window:\n{doc_window}",
    );
}

#[test]
fn create_task_maps_admission_closed_to_spawn_error_region_closed() {
    // Pin AUDIT-CRITICAL: when add_task returns
    // AdmissionError::Closed, create_task maps it to
    // SpawnError::RegionClosed(region) AND rolls back the
    // partial task creation. A regression that swallowed the
    // error or returned Ok would create an orphan record.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("AdmissionError::Closed => SpawnError::RegionClosed(region),"),
        "REGRESSION: create_task no longer maps \
         AdmissionError::Closed to SpawnError::RegionClosed. \
         Without the typed-error mapping, callers can't \
         distinguish 'region closed' from other admission \
         failures — and the rollback path may not fire.",
    );

    // The rollback (recycle_task) MUST happen before the
    // error return.
    let admission_pos = source
        .find("AdmissionError::Closed => SpawnError::RegionClosed(region),")
        .expect("admission match arm");
    let pre_admission = &source[..admission_pos];

    // The chars preceding the match arm should contain the
    // rollback `recycle_task` call. recycle_task removes the
    // partial task record and returns the slot to the pool.
    let rollback_window_start = pre_admission.len().saturating_sub(500);
    let rollback_window = &pre_admission[rollback_window_start..];

    assert!(
        rollback_window.contains("self.recycle_task(task_id)"),
        "REGRESSION: create_task no longer calls \
         self.recycle_task(task_id) before returning \
         SpawnError::RegionClosed. Without rollback, a \
         partial task record is left in the task table — \
         observable as a leaked task in diagnostics.\n\n\
         rollback window:\n{rollback_window}",
    );
}

#[test]
fn spawn_error_region_closed_variant_carries_region_id() {
    // Pin: SpawnError::RegionClosed carries the region id.
    // Operators / tests need to know WHICH region rejected.
    // A regression to a unit variant `RegionClosed` (no
    // payload) would lose the diagnostic information.
    let source = read("src/runtime/state.rs");

    // Look for the variant declaration in the SpawnError
    // enum. It may live in the same file or be re-exported.
    // Conservative check: the pattern `SpawnError::RegionClosed(`
    // appears in match contexts — the parenthesis means
    // it's a tuple variant, not a unit variant.
    assert!(
        source.contains("SpawnError::RegionClosed(region)"),
        "REGRESSION: SpawnError::RegionClosed no longer \
         carries the region id as a payload. Without it, \
         operators can't tell from the error which region \
         rejected the spawn.",
    );
}

#[test]
fn spawn_finalizer_task_uses_cleanup_admission_path() {
    // Pin: the legitimate during-cancel spawn path is
    // spawn_finalizer_task (state.rs:3000). It calls
    // create_task_infrastructure(region_id, budget, true)
    // where `true` is the is_cleanup flag. The cleanup path
    // routes through add_cleanup_task (allowed in Finalizing)
    // instead of add_task.
    //
    // This is the ONLY documented during-cancel admission;
    // user spawns NEVER get this treatment.
    let source = read("src/runtime/state.rs");

    let fn_marker = "fn spawn_finalizer_task(";
    let start = source.find(fn_marker).expect("spawn_finalizer_task fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("spawn_finalizer_task close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.create_task_infrastructure::<()>(&system_cx, region_id, budget, true)"),
        "REGRESSION: spawn_finalizer_task no longer calls \
         create_task_infrastructure with is_cleanup=true. \
         Without the cleanup flag, finalizer admission goes \
         through the same Open-only gate as user spawns — \
         finalizers would fail to spawn during region close, \
         leaving cleanup undone.\n\nfn body:\n{body}",
    );
}

#[test]
fn cancel_request_should_prevent_new_spawns_test_exists_in_crate() {
    // Pin: the in-crate test
    // `cancel_request_should_prevent_new_spawns` (state.rs:7911)
    // is the existing regression pin for this audit. A
    // regression that removed it would let a behavioral
    // regression slip through CI.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("fn cancel_request_should_prevent_new_spawns()"),
        "REGRESSION: in-crate test \
         cancel_request_should_prevent_new_spawns is gone. \
         This was the existing regression pin for spawn-\
         during-cancel rejection.",
    );

    // The test body must contain the assertion that
    // create_task returns Err(SpawnError::RegionClosed(_)).
    let test_marker = "fn cancel_request_should_prevent_new_spawns()";
    let start = source.find(test_marker).expect("test fn");
    let body_end = source[start..].find("\n    }\n").expect("test close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("matches!(result, Err(SpawnError::RegionClosed(_)))"),
        "REGRESSION: the in-crate test no longer asserts \
         create_task returns SpawnError::RegionClosed. The \
         exact error variant is part of the public contract; \
         a typed change would break callers.",
    );
}

#[test]
fn region_state_enum_has_five_canonical_variants() {
    // Pin: RegionState has 5 variants: Open, Closing,
    // Draining, Finalizing, Closed. The state machine is
    // documented and load-bearing — a regression that
    // collapsed states (e.g. merging Closing+Draining) would
    // change admission behavior in subtle ways.
    let source = read("src/record/region.rs");

    let enum_marker = "pub enum RegionState {";
    let start = source.find(enum_marker).expect("RegionState enum");
    let end_rel = source[start..].find("\n}\n").expect("enum close");
    let body = &source[start..start + end_rel];

    for variant in &["Open,", "Closing,", "Draining,", "Finalizing,", "Closed,"] {
        assert!(
            body.contains(variant),
            "REGRESSION: RegionState no longer has variant \
             `{variant}`. The 5-state machine is documented \
             in the doc comment AND drives admission \
             decisions; merging or removing a state could \
             silently change spawn-rejection behavior.\n\n\
             enum body:\n{body}",
        );
    }
}

#[test]
fn cancel_request_propagates_to_region_begin_close() {
    // Pin: the cancel-request path calls
    // region.begin_close_without_subscriber(Some(reason)) to transition the
    // region state without entering a tracing subscriber under RuntimeState.
    // Without this transition, the admission
    // gate would still see Open and let drop-handler
    // spawns succeed.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("region.begin_close_without_subscriber(Some(region_reason.clone()))"),
        "REGRESSION: state.rs no longer calls \
         the subscriber-free region close transition with the region_reason. Without \
         the state transition, the region stays Open and \
         user spawns continue to succeed — defeating the \
         spawn-during-cancel rejection invariant.",
    );
}

// ─── Behavioral end-to-end pin (gated on test-internals) ────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::record::region::RegionState;

    #[test]
    fn region_state_can_spawn_pins_open_only() {
        // Pin AUDIT-CRITICAL behavioral: only Open accepts
        // new work. All other states reject.
        assert!(
            RegionState::Open.can_spawn(),
            "RegionState::Open MUST accept spawns",
        );
        assert!(
            !RegionState::Closing.can_spawn(),
            "REGRESSION: RegionState::Closing now accepts \
             spawns. This is the EXACT failure mode the \
             audit guards against — drop-handler spawns \
             would silently orphan into a closing region.",
        );
        assert!(
            !RegionState::Draining.can_spawn(),
            "REGRESSION: RegionState::Draining now accepts \
             spawns.",
        );
        assert!(
            !RegionState::Finalizing.can_spawn(),
            "REGRESSION: RegionState::Finalizing now accepts \
             spawns.",
        );
        assert!(
            !RegionState::Closed.can_spawn(),
            "REGRESSION: RegionState::Closed now accepts \
             spawns. Closed is terminal — accepting work \
             would be a use-after-close bug.",
        );
    }

    #[test]
    fn region_state_can_accept_work_pins_open_only() {
        // Pin: can_accept_work (used by add_task admission)
        // is also Open-only. A regression that opened it
        // up to Closing would route normal-task admission
        // through the cleanup path, breaking the
        // structured-concurrency invariant.
        assert!(RegionState::Open.can_accept_work());
        assert!(!RegionState::Closing.can_accept_work());
        assert!(!RegionState::Draining.can_accept_work());
        assert!(!RegionState::Finalizing.can_accept_work());
        assert!(!RegionState::Closed.can_accept_work());
    }

    #[test]
    fn region_state_is_terminal_pins_closed_only() {
        // Pin: is_terminal returns true ONLY for Closed.
        // Other states are transient — observable mid-flight
        // by the runtime.
        assert!(!RegionState::Open.is_terminal());
        assert!(!RegionState::Closing.is_terminal());
        assert!(!RegionState::Draining.is_terminal());
        assert!(!RegionState::Finalizing.is_terminal());
        assert!(RegionState::Closed.is_terminal());
    }
}
