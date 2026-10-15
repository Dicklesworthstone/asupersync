//! Audit + regression test for the operator's question
//! about `Cx::checkpoint_with_cause()`.
//!
//! Operator's question: "Is there an API to attach a
//! cause-string to checkpoints (for debugging)? If yes,
//! verify the cause is preserved through cancel-cause
//! chain. If not, file feature bead."
//!
//! Audit findings: **SOUND BY DESIGN** — there is no
//! literal `checkpoint_with_cause()`, but the operator's
//! requirements are met by TWO distinct APIs that
//! deliberately serve different purposes:
//!
//!   1. `cx.checkpoint_with(msg)` — progress message
//!      attached to CheckpointState (diagnostic).
//!   2. `cx.cancel_with(kind, message)` — cancel reason
//!      attached to CancelReason.message (cancel chain
//!      attribution).
//!
//! No feature bead filed. The conceptual gap the operator
//! describes is bridged by the separation: the design
//! intentionally keeps "what was the task doing" (progress)
//! distinct from "why did the task cancel" (attribution).
//!
//! ── checkpoint_with(msg) ─────────────────────────────────
//!
//! ```ignore
//! // src/cx/cx.rs:1797
//! pub fn checkpoint_with(&self, msg: impl Into<String>)
//!     -> Result<(), crate::error::Error>
//! ```
//!
//! Behavior:
//!   - Like `cx.checkpoint()` (returns Err(Cancelled) if
//!     cancel is pending and not masked).
//!   - Additionally records `msg` into
//!     `CheckpointState.last_message` (cx.rs:1818 calls
//!     `inner.checkpoint_state.record_with_message_at(msg.into(), checkpoint_time)`).
//!   - The message is retrievable via
//!     `cx.checkpoint_state().last_message` — a snapshot
//!     read for diagnostic introspection.
//!
//! Use case: "Processing item 42/100" — you want this
//! visible in observability tools but it has no bearing
//! on cancel attribution.
//!
//! ── cancel_with(kind, message) ──────────────────────────
//!
//! ```ignore
//! // src/cx/cx.rs:2566
//! pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>)
//! ```
//!
//! Behavior:
//!   - Sets `inner.cancel_requested = true`.
//!   - Sets `inner.fast_cancel.store(true, Release)`.
//!   - Builds a `CancelReason` with kind, region, task,
//!     and the supplied `message`.
//!   - The message is preserved in `CancelReason.message`
//!     (cancel.rs:531) and travels through the
//!     `CancelReason.cause: Option<Box<Self>>` chain when
//!     `strengthen` is called.
//!
//! Use case: "Network timeout: read after deadline" —
//! attribution that travels through the cancel chain so
//! observers (parent regions, failure handlers, replay
//! tools) can see why this task was cancelled.
//!
//! ── Why two channels, not one ───────────────────────────
//!
//! The two messages answer different questions:
//!
//!   - `CheckpointState.last_message` — "what was the task
//!     doing AT this point?" (progress).
//!   - `CancelReason.message` — "why was the task cancelled?"
//!     (attribution).
//!
//! Conflating them would either:
//!   - Pollute cancel attribution with every per-iteration
//!     progress string (noise), or
//!   - Lose progress messages on uncancelled tasks (since
//!     CancelReason exists only when cancel is pending).
//!
//! Neither is desirable. The current two-channel design
//! gives both signals clean homes.
//!
//! The cancel-cause CHAIN itself uses `CancelReason.cause:
//! Option<Box<Self>>` — built via `cancel_with` callsites
//! and `CancelReason::strengthen` for hierarchical
//! attribution (e.g., parent region cancel → child
//! cancel chain).
//!
//! ── Bridging the two ────────────────────────────────────
//!
//! A user who wants a checkpoint-time cause-string THAT
//! ALSO flows into the cancel chain on subsequent
//! cancellation can write:
//!
//! ```ignore
//! cx.checkpoint_with(format!("phase: {phase}"))?;  // diagnostic
//! if some_failure_condition {
//!     cx.cancel_with(CancelKind::User, Some("phase failure: foo")); // attribution
//!     return Err(...);
//! }
//! ```
//!
//! This is idiomatic and explicit — the user chooses which
//! channel each message belongs in.
//!
//! Verdict: **SOUND BY DESIGN**. Two distinct APIs with
//! clean semantic separation. No feature bead filed.
//!
//! A regression that:
//!   - merged the two channels (e.g., checkpoint_with msg
//!     leaking into cancel_reason.message),
//!   - lost the CancelReason.cause chain field,
//!   - lost the CancelReason.message field,
//!     would all be caught by the structural pins below.

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
fn checkpoint_with_cause_method_does_not_exist() {
    // Pin: there is no Cx::checkpoint_with_cause method
    // (the literal name the operator asks about). If a
    // future regression adds one, it requires explicit
    // design review — does it merge the progress and
    // attribution channels?
    let mut violations = Vec::new();

    for path in read_dir_recursive("src") {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.contains("fn checkpoint_with_cause") {
            violations.push(path.display().to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "REGRESSION: `checkpoint_with_cause` introduced. \
         The two-channel design (progress vs attribution) \
         is being silently merged. Design review required.\
         \n\n{}",
        violations.join("\n"),
    );
}

#[test]
fn checkpoint_with_msg_api_exists() {
    // Pin: the progress-message channel is checkpoint_with(msg).
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains(
            "pub fn checkpoint_with(&self, msg: impl Into<String>) -> Result<(), crate::error::Error>"
        ),
        "REGRESSION: Cx::checkpoint_with signature gone or \
         changed. Progress-message channel broken.",
    );
}

#[test]
fn checkpoint_with_records_message_into_checkpoint_state() {
    // Pin: checkpoint_with stores the message in
    // CheckpointState via record_with_message_at — NOT in
    // CancelReason. This separation is the design property.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint_with(&self, msg: impl Into<String>) -> Result<(), crate::error::Error> {";
    let pos = source.find(fn_marker).expect("checkpoint_with fn");
    let body_window = &source[pos..pos + 2500];

    let conversion = body_window
        .find("let msg = msg.into();")
        .expect("message conversion");
    let inner_lock = body_window
        .find("let mut inner = self.inner.write();")
        .expect("CxInner write lock");
    let record = body_window
        .find(".record_with_message_at(msg, checkpoint_time);")
        .expect("checkpoint message record");
    assert!(
        conversion < inner_lock && inner_lock < record,
        "REGRESSION: checkpoint_with no longer records the \
         materialized message into CheckpointState, or it invokes \
         user-controlled Into<String> while holding CxInner. The \
         progress-message channel must convert before locking and \
         record afterward.",
    );
}

#[test]
fn checkpoint_with_does_not_pollute_cancel_reason_with_user_message() {
    // Pin: the user-supplied msg in checkpoint_with must
    // NOT be merged into CancelReason.message. This
    // pollution would make every checkpoint message look
    // like a cancel cause.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint_with(&self, msg: impl Into<String>) -> Result<(), crate::error::Error> {";
    let pos = source.find(fn_marker).expect("checkpoint_with fn");
    let body_window = &source[pos..pos + 2500];

    // Must NOT call .with_message(msg) where msg is the
    // user's progress string — that would route into the
    // cancel chain.
    assert!(
        !body_window.contains(".with_message(msg")
            && !body_window.contains("cancel_reason = Some(... msg"),
        "REGRESSION: checkpoint_with now routes the user \
         progress message into CancelReason.with_message. \
         The two-channel separation is broken.",
    );
}

#[test]
fn cancel_with_attribution_api_exists() {
    // Pin: the cancel-attribution channel is
    // cancel_with(kind, message).
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains(
            "pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {"
        ),
        "REGRESSION: Cx::cancel_with signature gone or \
         changed. Cancel-attribution channel broken.",
    );
}

#[test]
fn cancel_with_records_message_into_cancel_reason() {
    // Pin: cancel_with builds a CancelReason that holds
    // the message via with_message.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {";
    let pos = source.find(fn_marker).expect("cancel_with fn");
    let body_window = &source[pos..pos + 1500];

    assert!(
        body_window.contains("CancelReason::") && body_window.contains("with_message"),
        "REGRESSION: cancel_with no longer attaches the \
         message to CancelReason via with_message. The \
         attribution path is broken.",
    );
}

#[test]
fn cancel_reason_struct_has_message_field() {
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub message: Option<String>,"),
        "REGRESSION: CancelReason::message field is gone. \
         Cancel attribution loses string context.",
    );
}

#[test]
fn cancel_reason_struct_has_cause_chain_field() {
    // Pin: the cancel cause chain is built via
    // CancelReason.cause: Option<Box<Self>>. Without it,
    // hierarchical attribution is lost.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub cause: Option<Box<Self>>,"),
        "REGRESSION: CancelReason::cause chain field is \
         gone. Hierarchical cancel attribution is broken \
         — parent->child cause linkage cannot be recorded.",
    );
}

#[test]
fn cancel_reason_with_message_setter_exists() {
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn with_message(mut self, message: &'static str) -> Self {"),
        "REGRESSION: CancelReason::with_message setter \
         gone. cancel_with cannot attach a message to the \
         reason struct.",
    );
}

#[test]
fn checkpoint_state_has_last_message_field_for_progress() {
    let source = read("src/types/task_context.rs");

    assert!(
        source.contains("last_message") && source.contains("Option<String>"),
        "REGRESSION: CheckpointState::last_message field \
         appears to be gone or no longer Option<String>. \
         The progress-message channel has lost its \
         storage.",
    );
}

#[test]
fn checkpoint_state_record_with_message_at_records_into_last_message() {
    let source = read("src/types/task_context.rs");

    assert!(
        source.contains("pub fn record_with_message_at(&mut self, message: String, at: Time) {"),
        "REGRESSION: CheckpointState::record_with_message_at \
         signature changed. The progress-message recorder \
         is broken.",
    );
}

#[test]
fn cx_checkpoint_state_accessor_exposes_message_for_diagnostics() {
    // Pin: cx.checkpoint_state() returns a snapshot whose
    // last_message field is the progress string. This is
    // the user-facing read path for the progress channel.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn checkpoint_state(&self) -> crate::types::CheckpointState {"),
        "REGRESSION: Cx::checkpoint_state accessor is \
         gone. Users can no longer read back the progress \
         message recorded via checkpoint_with.",
    );
}

#[test]
fn cx_cancel_reason_accessor_exposes_attribution_message() {
    // Pin: cx.cancel_reason() returns the CancelReason
    // (with message + cause chain). This is the user-
    // facing read path for the attribution channel.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn cancel_reason(&self) -> Option<CancelReason> {"),
        "REGRESSION: Cx::cancel_reason accessor is gone. \
         Users can no longer read back the cancel \
         attribution message.",
    );
}

#[test]
fn checkpoint_with_inline_test_pins_message_records() {
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("fn checkpoint_with_records_message()"),
        "REGRESSION: checkpoint_with_records_message inline \
         test gone. The progress-message recording is no \
         longer guarded.",
    );
}

#[test]
fn cancel_chain_strengthen_path_exists() {
    // Pin: CancelReason::strengthen builds the cause chain
    // when subsequent cancels arrive. This is what makes
    // attribution hierarchical.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn strengthen") || source.contains("fn strengthen("),
        "REGRESSION: CancelReason::strengthen is gone. \
         The cause-chain construction path is broken.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Mutex;

/// Mock CheckpointState — progress channel.
#[derive(Default, Clone)]
struct MockCheckpointState {
    last_message: Option<String>,
    checkpoint_count: u64,
}

/// Mock CancelReason — attribution channel with cause chain.
#[derive(Default, Clone)]
struct MockCancelReason {
    kind: &'static str,
    message: Option<String>,
    cause: Option<Box<Self>>,
}

impl MockCancelReason {
    fn strengthen(&mut self, deeper: &Self) {
        // The new cause becomes a parent in the chain.
        self.cause = Some(Box::new(deeper.clone()));
    }
}

struct MockCx {
    state: Mutex<MockCheckpointState>,
    cancel: Mutex<Option<MockCancelReason>>,
    cancel_requested: Mutex<bool>,
    mask_depth: Mutex<u32>,
}

impl MockCx {
    fn new() -> Self {
        Self {
            state: Mutex::new(MockCheckpointState::default()),
            cancel: Mutex::new(None),
            cancel_requested: Mutex::new(false),
            mask_depth: Mutex::new(0),
        }
    }

    fn checkpoint_with(&self, msg: impl Into<String>) -> Result<(), &'static str> {
        let mut s = self.state.lock().unwrap();
        s.last_message = Some(msg.into());
        s.checkpoint_count += 1;
        drop(s);

        let cancelled = *self.cancel_requested.lock().unwrap();
        let mask = *self.mask_depth.lock().unwrap();
        if cancelled && mask == 0 {
            return Err("cancelled");
        }
        Ok(())
    }

    fn cancel_with(&self, kind: &'static str, message: Option<&'static str>) {
        *self.cancel_requested.lock().unwrap() = true;
        let new_reason = MockCancelReason {
            kind,
            message: message.map(|s| s.to_string()),
            cause: None,
        };
        let mut slot = self.cancel.lock().unwrap();
        match slot.as_mut() {
            Some(existing) => existing.strengthen(&new_reason),
            None => *slot = Some(new_reason),
        }
    }

    fn checkpoint_state(&self) -> MockCheckpointState {
        self.state.lock().unwrap().clone()
    }

    fn cancel_reason(&self) -> Option<MockCancelReason> {
        self.cancel.lock().unwrap().clone()
    }
}

#[test]
fn behavioral_checkpoint_with_msg_visible_in_checkpoint_state_only() {
    // Pin: the progress message lives in CheckpointState,
    // NOT in CancelReason.
    let cx = MockCx::new();
    cx.checkpoint_with("phase: parsing").expect("not cancelled");

    let state = cx.checkpoint_state();
    assert_eq!(state.last_message.as_deref(), Some("phase: parsing"));

    // Cancel reason is None (never cancelled).
    assert!(
        cx.cancel_reason().is_none(),
        "REGRESSION: progress message leaked into \
         CancelReason. The two-channel separation is \
         broken.",
    );
}

#[test]
fn behavioral_cancel_with_msg_visible_in_cancel_reason_only() {
    // Pin: the cancel attribution lives in CancelReason,
    // NOT in CheckpointState.
    let cx = MockCx::new();
    cx.cancel_with("Timeout", Some("read after deadline"));

    let reason = cx.cancel_reason().expect("cancelled");
    assert_eq!(reason.kind, "Timeout");
    assert_eq!(reason.message.as_deref(), Some("read after deadline"));

    // CheckpointState is empty (no checkpoint was called).
    let state = cx.checkpoint_state();
    assert!(
        state.last_message.is_none(),
        "REGRESSION: cancel message leaked into \
         CheckpointState.",
    );
}

#[test]
fn behavioral_both_channels_can_coexist_independently() {
    let cx = MockCx::new();

    // Progress.
    cx.checkpoint_with("phase: parsing").expect("not cancelled");

    // Then cancel with attribution.
    cx.cancel_with("User", Some("user requested abort"));

    // The progress message is preserved in CheckpointState.
    let state = cx.checkpoint_state();
    assert_eq!(state.last_message.as_deref(), Some("phase: parsing"));

    // The cancel attribution is in CancelReason.
    let reason = cx.cancel_reason().expect("cancelled");
    assert_eq!(reason.message.as_deref(), Some("user requested abort"));

    // The two messages are distinct (not merged).
    assert_ne!(
        state.last_message, reason.message,
        "REGRESSION: the two channels collapsed into one — \
         progress and attribution are now indistinguishable.",
    );
}

#[test]
fn behavioral_cancel_chain_strengthen_builds_cause_hierarchy() {
    // Pin: subsequent cancel_with calls build the cause
    // chain (deeper cause becomes parent of inner reason).
    let cx = MockCx::new();

    cx.cancel_with("Inner", Some("inner cause"));
    cx.cancel_with("Outer", Some("outer cause"));

    let reason = cx.cancel_reason().expect("cancelled");

    // The cause chain has been built.
    assert!(
        reason.cause.is_some(),
        "REGRESSION: cancel_with no longer builds a cause \
         chain on subsequent calls. Hierarchical \
         attribution is broken.",
    );
}

#[test]
fn behavioral_post_cancel_checkpoint_returns_err_progress_still_recorded() {
    // Pin: even after cancel, checkpoint_with still
    // records the progress message before returning Err.
    // This gives observability tools the "task reached
    // this checkpoint, then observed cancel" trail.
    let cx = MockCx::new();
    cx.cancel_with("Timeout", Some("deadline"));

    let result = cx.checkpoint_with("phase: cleanup");

    assert!(result.is_err(), "checkpoint should return Err post-cancel");

    // The progress message IS still recorded.
    let state = cx.checkpoint_state();
    assert_eq!(
        state.last_message.as_deref(),
        Some("phase: cleanup"),
        "REGRESSION: post-cancel checkpoint_with did not \
         record the message. The diagnostic trail is \
         broken.",
    );

    // Cancel attribution is unchanged (it's "deadline",
    // not "phase: cleanup").
    let reason = cx.cancel_reason().expect("cancelled");
    assert_eq!(reason.message.as_deref(), Some("deadline"));
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/cx_checkpoint_during_region_cancel_timing_audit.rs",
        "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
        "tests/runtime_cancel_cause_chain_depth_audit.rs",
        "tests/cx_no_interrupt_method_unified_cancel_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
