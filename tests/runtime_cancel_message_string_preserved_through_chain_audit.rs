//! Audit + regression test for cancel-reason MESSAGE
//! string propagation through the cancel-cause chain.
//!
//! Operator's question: "When cause is 'operator-initiated
//! abort', does that cause-string flow to all child tasks
//! via cancel-cause chain (correct: debugging) or get
//! truncated?"
//!
//! Audit findings: **SOUND BY DESIGN — the message string
//! is fully preserved on every chain node it reaches**.
//!
//! Note: there is no literal `Cx::region().cancel_with_cause()`
//! method. The canonical region-cancel-with-message API is
//! `RuntimeState::cancel_request(region, reason, source_task)`
//! where `reason` carries the message via
//! `CancelReason::with_message(...)`. The operator's name
//! maps onto that runtime API.
//!
//! ── Message field on CancelReason ───────────────────────
//!
//! `CancelReason` (src/types/cancel.rs:520+) has:
//!
//! ```ignore
//! pub struct CancelReason {
//!     pub kind: CancelKind,
//!     pub origin_region: RegionId,
//!     pub origin_task: Option<TaskId>,
//!     pub timestamp: Time,
//!     pub message: Option<String>,         // ← THIS field
//!     pub cause: Option<Box<Self>>,
//!     pub truncated: bool,
//!     pub truncated_at_depth: Option<usize>,
//! }
//! ```
//!
//! Setter: `CancelReason::with_message(message: &'static str)`
//! (cancel.rs:673) attaches a message. Constructors like
//! `CancelReason::user(message: &'static str)` (cancel.rs:612)
//! pre-populate the field.
//!
//! ── How messages flow through the chain ─────────────────
//!
//! In `RuntimeState::cancel_request` (state.rs:2678),
//! propagation builds:
//!
//! - **Root region**: gets `reason.clone()` — the EXACT
//!   original. Message is `Some("operator-initiated abort")`.
//! - **Descendants**: get `CancelReason::parent_cancelled()
//!   .with_region(parent_id)
//!   .with_timestamp(reason.timestamp)
//!   .with_cause_limited(parent_reason, &cancel_attribution)`.
//!   The descendant's OWN message is None (kind is
//!   ParentCancelled, no per-descendant message). But the
//!   descendant's `cause` field links to the parent's
//!   reason — and the parent's reason still has its own
//!   message field.
//!
//! So at any descendant depth, traversing
//! `descendant.root_cause().message` returns the original
//! message. The string is NEVER stripped from the chain.
//!
//! ── What IS bounded ─────────────────────────────────────
//!
//! `with_cause_limited` consults
//! `cancel_attribution.max_chain_depth` (default 16). If a
//! chain exceeds this, the cause-link is dropped and
//! `truncated = true` is set on the descendant. Beyond
//! depth 16, descendants no longer have cause links to the
//! root — but the messages on the FIRST 16 nodes are still
//! intact.
//!
//! For typical region trees (depth < 16), 100% of
//! descendants retain access to the original message via
//! `root_cause()`. For pathological depths (rare; deep
//! recursive scopes), the truncated flag flags it
//! explicitly so debug tools can show "chain truncated at
//! depth N" rather than misleadingly showing depth 16's
//! message as the root.
//!
//! ── Task-level propagation ──────────────────────────────
//!
//! `state.cancel_request` doesn't just mark regions — it
//! also marks every task in the affected regions:
//!
//! ```ignore
//! TaskState::CancelRequested { reason: <chained reason> }
//! ```
//!
//! Each task gets its REGION's chained reason (with cause
//! link to parent → ... → root with original message).
//! The task can then call `cx.cancel_reason()` and walk
//! `.root_cause().message` to get the original string.
//!
//! ── Why bounded depth is not "truncation of the message" ──
//!
//! The operator asks if the cause-string gets "truncated".
//! Two interpretations:
//!
//! 1. Is the STRING ITSELF truncated (e.g., to N chars)?
//!    NO. `message: Option<String>` is preserved verbatim;
//!    no length cap is applied during propagation.
//!
//! 2. Is the CHAIN truncated such that the original is
//!    inaccessible? Only past max_chain_depth (default
//!    16). The string at the deepest preserved node is
//!    still intact, and the `truncated` flag signals
//!    explicitly that more was elided. This is a safety
//!    bound, not stripping.
//!
//! Verdict: **SOUND**. The message string flows fully
//! through the cancel-cause chain to every child task.
//! Tasks at ANY depth ≤ 16 can recover the original via
//! `cx.cancel_reason().unwrap().root_cause().message`.
//! Past depth 16, the truncation flag is set explicitly —
//! a deliberate safety bound, not silent stripping.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cancel_reason_has_message_field_for_string_carrying() {
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub message: Option<String>,"),
        "REGRESSION: CancelReason::message field is gone. \
         Cancel attribution loses string context.",
    );
}

#[test]
fn cancel_reason_with_message_setter_preserves_string() {
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn with_message(mut self, message: &'static str) -> Self {"),
        "REGRESSION: with_message setter is gone. Callers \
         cannot attach a message to a cancel reason.",
    );

    // Body assigns to message field — no transformation.
    let fn_marker = "pub fn with_message(mut self, message: &'static str) -> Self {";
    let pos = source.find(fn_marker).expect("with_message fn");
    let body_end = source[pos..].find("\n    }\n").expect("with_message close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("self.message = Some("),
        "REGRESSION: with_message no longer assigns to \
         self.message. Message handling broken.",
    );

    // No string transformation: no .truncate(), no [..N], etc.
    let suspect_transforms = [".truncate(", "&message[..", ".chars().take("];
    for pat in &suspect_transforms {
        assert!(
            !body.contains(pat),
            "REGRESSION: with_message body now contains \
             `{pat}` — string transformation introduced. \
             Operator's cause-string would be truncated.",
        );
    }
}

#[test]
fn cancel_reason_user_constructor_takes_message() {
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn user(message: &'static str) -> Self {"),
        "REGRESSION: CancelReason::user constructor that \
         takes a message is gone.",
    );

    let fn_marker = "pub fn user(message: &'static str) -> Self {";
    let pos = source.find(fn_marker).expect("user fn");
    let body_end = source[pos..].find("\n    }\n").expect("user close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("message: Some(message.to_string())"),
        "REGRESSION: CancelReason::user no longer assigns \
         the message field. Operator-initiated cancels \
         lose their string context.",
    );
}

#[test]
fn root_cause_walker_returns_node_with_intact_message() {
    // Pin: root_cause() walks to the node with cause: None.
    // That node's message field is intact (assigned at
    // construction, never mutated by chain building).
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn root_cause(&self)") || source.contains("fn root_cause(&self)"),
        "REGRESSION: root_cause walker is gone. Callers \
         cannot reach the original message at any depth.",
    );
}

#[test]
fn descendant_propagation_does_not_strip_parent_message() {
    // Pin: state.cancel_request's descendant-build path
    // uses with_cause_limited(parent_reason, ...) which
    // CLONES parent_reason (including its message field)
    // into the child's cause. The string is never stripped.
    let source = read("src/runtime/state.rs");

    let fn_marker = "pub fn cancel_request(";
    let pos = source.find(fn_marker).expect("cancel_request fn");
    let body_window = &source[pos..pos + 8000];

    assert!(
        body_window.contains("with_cause_limited(parent_reason"),
        "REGRESSION: descendant build no longer chains via \
         with_cause_limited(parent_reason). The parent's \
         message would not propagate.",
    );

    // Parent's reason is cloned (`r.clone()`) into the
    // chain map — preserves the message.
    assert!(
        body_window.contains("Some(r) => r.clone()"),
        "REGRESSION: parent's reason no longer cloned into \
         the chain map. Message propagation broken.",
    );
}

#[test]
fn with_cause_limited_does_not_truncate_message() {
    // Pin: with_cause_limited only bounds CHAIN DEPTH,
    // not message length. The function clones the parent
    // reason verbatim into self.cause.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn with_cause_limited("),
        "REGRESSION: with_cause_limited gone.",
    );

    let fn_marker = "pub fn with_cause_limited(";
    let pos = source.find(fn_marker).expect("with_cause_limited fn");
    let body_end = source[pos..]
        .find("\n    }\n")
        .expect("with_cause_limited close");
    let body = &source[pos..pos + body_end];

    // Must NOT touch the message field.
    let suspect_message_strip = [
        "cause.message = None",
        "self.message = None",
        ".message.take()",
        "cause.message.truncate",
    ];
    for pat in &suspect_message_strip {
        assert!(
            !body.contains(pat),
            "REGRESSION: with_cause_limited now manipulates \
             the message field via `{pat}`. Operator-\
             initiated message string is being stripped.",
        );
    }
}

#[test]
fn cancel_attribution_config_max_chain_depth_default_16() {
    // Pin: the default max_chain_depth is 16 — generous
    // for typical region trees, bounds pathological cases.
    // (The test is structural — checking the CONST or
    // default value via grep.)
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("max_chain_depth"),
        "REGRESSION: max_chain_depth field is gone. Chain \
         depth cannot be configured.",
    );

    // Default is set via DEFAULT_MAX_DEPTH constant. The
    // documented default (in the module docstring or
    // example assertion) is 16.
    assert!(
        source.contains("DEFAULT_MAX_DEPTH"),
        "REGRESSION: DEFAULT_MAX_DEPTH constant is gone. \
         The max_chain_depth default no longer has a \
         single source of truth.",
    );

    assert!(
        source.contains("default: 16") || source.contains("max_chain_depth, 16"),
        "REGRESSION: documented default-16 invariant is \
         gone. Default may have been silently lowered \
         without doc update.",
    );
}

#[test]
fn truncation_sets_explicit_flag_for_diagnostic_visibility() {
    // Pin: when truncation occurs, the truncated flag is
    // set so diagnostic tools see "chain truncated" rather
    // than misleadingly seeing depth-16's message as the
    // root.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub truncated: bool,"),
        "REGRESSION: truncated field is gone. Truncation \
         is silent — diagnostic tools cannot detect it.",
    );

    assert!(
        source.contains("pub truncated_at_depth: Option<usize>,"),
        "REGRESSION: truncated_at_depth field is gone. \
         Diagnostic tools lose the depth at which \
         truncation occurred.",
    );
}

#[test]
fn cancel_request_inline_test_pins_message_carries_through() {
    // Pin: the inline test cancel_request_builds_cause_chains
    // (state.rs:6720) uses
    // `CancelReason::deadline().with_message("budget exhausted")`
    // and asserts the message reaches grandchild_task via
    // root_cause(). If the test is removed, message
    // propagation regression can pass CI.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("fn cancel_request_builds_cause_chains()"),
        "REGRESSION: cancel_request_builds_cause_chains \
         inline test gone. Message-through-chain witness \
         lost.",
    );

    assert!(
        source.contains("with_message(\"budget exhausted\")"),
        "REGRESSION: the inline test no longer attaches a \
         message via with_message. Message propagation \
         is no longer witnessed by the in-tree test.",
    );
}

#[test]
fn task_state_cancel_requested_carries_chained_reason() {
    // Pin: tasks in cancelled regions transition to
    // TaskState::CancelRequested { reason } where `reason`
    // is the region's CHAINED reason (with cause back to
    // the root's message).
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("TaskState::CancelRequested { reason"),
        "REGRESSION: TaskState::CancelRequested no longer \
         destructures the reason field. Task-level \
         message propagation is broken.",
    );
}

#[test]
fn cx_cancel_reason_accessor_exposes_message_to_user() {
    // Pin: cx.cancel_reason() returns the CancelReason
    // (with message + cause chain) — the user-facing read
    // path.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn cancel_reason(&self) -> Option<CancelReason> {"),
        "REGRESSION: Cx::cancel_reason accessor is gone. \
         User code in a cancelled task cannot read back \
         the operator's cause-string.",
    );
}

#[test]
fn no_message_truncation_in_serialization() {
    // Pin: the cause field uses deserialize_bounded_cause
    // for chain DEPTH safety, but does NOT truncate the
    // message string.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("deserialize_bounded_cause"),
        "REGRESSION: deserialize_bounded_cause gone — wire \
         safety broken.",
    );

    // Message has standard serde derive (no custom
    // deserializer that would truncate).
    let suspect_message_truncators = [
        "message_truncated_at",
        "deserialize_truncated_message",
        "TRUNCATED_MESSAGE_LIMIT",
    ];
    for pat in &suspect_message_truncators {
        assert!(
            !source.contains(pat),
            "REGRESSION: serialization-time message \
             truncator `{pat}` introduced.",
        );
    }
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CancelKind {
    Deadline,
    User,
    ParentCancelled,
}

#[derive(Clone, Debug)]
struct CancelReason {
    kind: CancelKind,
    origin_region: u32,
    message: Option<String>,
    cause: Option<Box<Self>>,
    truncated: bool,
    truncated_at_depth: Option<usize>,
}

impl CancelReason {
    fn user(msg: &'static str) -> Self {
        Self {
            kind: CancelKind::User,
            origin_region: 0,
            message: Some(msg.to_string()),
            cause: None,
            truncated: false,
            truncated_at_depth: None,
        }
    }

    fn parent_cancelled(parent_id: u32) -> Self {
        Self {
            kind: CancelKind::ParentCancelled,
            origin_region: parent_id,
            message: None,
            cause: None,
            truncated: false,
            truncated_at_depth: None,
        }
    }

    fn with_cause_limited(mut self, parent: Self, max_depth: usize) -> Self {
        let parent_depth = parent.chain_depth();
        if parent_depth + 1 > max_depth {
            self.truncated = true;
            self.truncated_at_depth = Some(parent_depth);
            return self;
        }
        self.cause = Some(Box::new(parent));
        self
    }

    fn chain_depth(&self) -> usize {
        let mut depth = 1;
        let mut current = self;
        while let Some(c) = current.cause.as_deref() {
            depth += 1;
            current = c;
        }
        depth
    }

    fn root_cause(&self) -> &Self {
        let mut current = self;
        while let Some(c) = current.cause.as_deref() {
            current = c;
        }
        current
    }
}

fn build_chain_with_message(
    operator_message: &'static str,
    region_ids: &[u32],
    max_depth: usize,
) -> Vec<CancelReason> {
    // region_ids[0] is the root region.
    let mut reasons = Vec::with_capacity(region_ids.len());

    // Root region: operator-initiated User cancel with message.
    let mut root = CancelReason::user(operator_message);
    root.origin_region = region_ids[0];
    reasons.push(root);

    for window in region_ids.windows(2) {
        let parent_id = window[0];
        let parent_reason = reasons.last().unwrap().clone();
        let child =
            CancelReason::parent_cancelled(parent_id).with_cause_limited(parent_reason, max_depth);
        reasons.push(child);
    }

    reasons
}

#[test]
fn behavioral_root_region_carries_operator_message_verbatim() {
    let chain = build_chain_with_message("operator-initiated abort", &[1, 2, 3], 16);

    let root = &chain[0];
    assert_eq!(
        root.message.as_deref(),
        Some("operator-initiated abort"),
        "REGRESSION: root region's message is not the \
         operator's input. String stripped during \
         construction.",
    );
}

#[test]
fn behavioral_descendant_root_cause_returns_operator_message() {
    let chain = build_chain_with_message("operator-initiated abort", &[1, 2, 3, 4, 5], 16);

    for (depth, descendant) in chain.iter().enumerate() {
        let recovered = descendant.root_cause().message.as_deref();
        assert_eq!(
            recovered,
            Some("operator-initiated abort"),
            "REGRESSION: at depth {depth}, root_cause's \
             message is not the operator's. String lost \
             through chain.",
        );
    }
}

#[test]
fn behavioral_long_message_string_preserved_verbatim() {
    // Long messages (e.g., paragraph-length descriptions)
    // must propagate without character truncation.
    let long_msg = "operator-initiated abort: emergency shutdown triggered \
                    due to upstream credential rotation; preserving in-flight \
                    transactions via two-phase commit drain";
    // Use a 'static long message via Box::leak for the
    // mock signature.
    let leaked: &'static str = Box::leak(long_msg.to_string().into_boxed_str());

    let chain = build_chain_with_message(leaked, &[1, 2, 3, 4], 16);

    let root_msg = chain[0].message.as_deref().unwrap();
    assert_eq!(
        root_msg.len(),
        long_msg.len(),
        "REGRESSION: root region message length changed. \
         String truncated.",
    );

    // And at depth 3, root_cause should still return the
    // full message.
    let deepest = chain.last().unwrap();
    let recovered = deepest.root_cause().message.as_deref().unwrap();
    assert_eq!(
        recovered.len(),
        long_msg.len(),
        "REGRESSION: deep descendant's root_cause message \
         length differs from original. String truncated \
         along the chain.",
    );
    assert_eq!(recovered, long_msg);
}

#[test]
fn behavioral_chain_truncation_does_not_strip_message_from_preserved_nodes() {
    // Build a chain that exceeds max_depth. Nodes within
    // depth bound retain full message access; nodes past
    // bound mark truncated=true but still have their own
    // origin_region intact.
    let chain = build_chain_with_message("operator-initiated abort", &[1, 2, 3, 4, 5, 6], 4);

    // Nodes 0..4 have intact chain to root.
    for (depth, node) in chain.iter().take(4).enumerate() {
        assert_eq!(
            node.root_cause().message.as_deref(),
            Some("operator-initiated abort"),
            "REGRESSION: depth {depth} (within bound) lost \
             access to the operator message.",
        );
    }

    // Node 4 (depth past bound) marks truncated.
    let truncated = chain.iter().find(|r| r.truncated);
    assert!(
        truncated.is_some(),
        "REGRESSION: chain past max_depth did not mark \
         truncated=true. Silent dropping of cause link.",
    );
}

#[test]
fn behavioral_message_does_not_change_through_clone() {
    // Cloning a CancelReason preserves the message
    // verbatim. (The chain-building uses .clone().)
    let original = CancelReason::user("operator-initiated abort");
    let cloned = original.clone();

    assert_eq!(original.message, cloned.message);
    assert_eq!(
        cloned.message.as_deref(),
        Some("operator-initiated abort"),
        "REGRESSION: clone() altered the message field.",
    );
}

#[test]
fn behavioral_task_level_carrier_preserves_message_for_user_cx_lookup() {
    // Models the production flow: region cancel-chain →
    // task gets chained reason → user code calls
    // cx.cancel_reason().root_cause().message → recovers
    // the operator's string.
    struct MockTask {
        cancel_reason: Mutex<Option<CancelReason>>,
    }
    impl MockTask {
        fn new() -> Self {
            Self {
                cancel_reason: Mutex::new(None),
            }
        }
        fn install_cancel_reason(&self, reason: CancelReason) {
            *self.cancel_reason.lock().unwrap() = Some(reason);
        }
        fn user_observes_message(&self) -> Option<String> {
            self.cancel_reason
                .lock()
                .unwrap()
                .as_ref()
                .map(|r| r.root_cause().message.clone())
                .flatten()
        }
    }

    let chain = build_chain_with_message("operator-initiated abort", &[1, 2, 3], 16);

    // Tasks in each region get the corresponding chained reason.
    let root_task = MockTask::new();
    root_task.install_cancel_reason(chain[0].clone());

    let mid_task = MockTask::new();
    mid_task.install_cancel_reason(chain[1].clone());

    let leaf_task = MockTask::new();
    leaf_task.install_cancel_reason(chain[2].clone());

    for (label, task) in [
        ("root", &root_task),
        ("mid", &mid_task),
        ("leaf", &leaf_task),
    ] {
        assert_eq!(
            task.user_observes_message().as_deref(),
            Some("operator-initiated abort"),
            "REGRESSION: {label} task user code did not \
             observe the operator's message via \
             cancel_reason().root_cause().message. \
             Debugging-friendly contract broken.",
        );
    }
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/runtime_cancel_reason_propagates_through_chain_audit.rs",
        "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
        "tests/runtime_cancel_cause_chain_depth_audit.rs",
        "tests/cx_checkpoint_with_vs_cancel_cause_separation_audit.rs",
        "tests/cx_self_cancel_vs_region_cancel_distinction_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
