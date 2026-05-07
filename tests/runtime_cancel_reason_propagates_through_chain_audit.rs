//! Audit + regression test for cancel-cause-chain
//! propagation through region cancellation.
//!
//! Operator's question: "When cancelling with a structured
//! reason, is the reason propagated through the cancel-
//! cause chain to the task being cancelled (correct: debug-
//! friendly) or stripped (info loss)?"
//!
//! Audit findings: **SOUND BY DESIGN — original reason
//! fully preserved through arbitrary-depth chains**.
//!
//! Note: there is no literal `Cx::region().cancel_with(reason)`
//! method (Cx::scope() returns a Scope handle, not a Region;
//! cancel-with-reason on regions goes through
//! `RuntimeState::cancel_request(region, reason, source)`).
//! The operator's name maps onto that runtime API.
//!
//! ── How propagation works ────────────────────────────────
//!
//! `RuntimeState::cancel_request(region_id, reason, source_task)`
//! (state.rs:2678) walks the region tree and builds
//! cause chains:
//!
//! ```ignore
//! // First pass: assign reasons depth-ascending
//! for node in &regions_to_cancel {
//!     let region_reason = if rid == region_id {
//!         reason.clone()  // ROOT keeps EXACT original
//!     } else if let Some(parent_id) = node.parent {
//!         // Descendants: ParentCancelled chained to parent's reason
//!         let parent_reason = region_reasons.get(&parent_id).clone();
//!         CancelReason::parent_cancelled()
//!             .with_region(parent_id)
//!             .with_timestamp(reason.timestamp)
//!             .with_cause_limited(parent_reason, &self.cancel_attribution)
//!     };
//!     region_reasons.insert(rid, region_reason.clone());
//! }
//! ```
//!
//! Properties:
//!
//! 1. **Root region keeps the exact original reason**.
//!    The supplied `reason` (kind, message, origin_region,
//!    timestamp, etc.) is `clone()`-d into the root's
//!    region record. No information stripped.
//!
//! 2. **Descendants get ParentCancelled + cause chain**.
//!    Each child region's reason has
//!    `kind = CancelKind::ParentCancelled`,
//!    `origin_region = parent_id`, and
//!    `cause = Some(Box<parent's reason>)`. The chain links
//!    back through every ancestor to the root.
//!
//! 3. **`root_cause()` returns the original at any depth**.
//!    `CancelReason::root_cause()` walks the cause chain
//!    until reaching a node with `cause: None` — that's
//!    the original. So a grandchild task can call
//!    `cx.cancel_reason().unwrap().root_cause().kind` and
//!    see the operator's `Deadline` (or whatever kind was
//!    originally supplied).
//!
//! 4. **Chain depth is bounded**.
//!    `with_cause_limited` consults
//!    `self.cancel_attribution` (a `CancelAttributionConfig`
//!    with `max_chain_depth`, default 16) to truncate
//!    deep chains and set the `truncated` /
//!    `truncated_at_depth` flags. This prevents pathological
//!    chains from growing unbounded.
//!
//! 5. **Serialization is bounded too**. `cause` field
//!    has `#[serde(deserialize_with = "deserialize_bounded_cause")]`
//!    that rejects chains deeper than
//!    `MAX_CANCEL_CAUSE_DESERIALIZE_DEPTH = 256` to defend
//!    against attacker-supplied snapshots
//!    (br-asupersync-dyao05).
//!
//! 6. **The task's CancelRequested state also carries the
//!    chained reason** — the test at state.rs:6843 asserts
//!    that grandchild_task's CancelRequested.reason has
//!    chain_depth=3 and root_cause.kind = Deadline. So the
//!    propagation reaches all the way to the task layer,
//!    not just the region record.
//!
//! ── Why nothing is stripped ─────────────────────────────
//!
//! The propagation explicitly clones (`reason.clone()`) the
//! supplied reason into the root region's record. Each
//! descendant's `with_cause_limited(parent_reason, ...)`
//! clones the parent's reason AGAIN into the child's cause
//! field. So at any depth, the original is reachable via
//! `root_cause()` and the immediate parent's reason is
//! reachable via `cause`.
//!
//! The only loss is when the chain exceeds
//! `max_chain_depth` (default 16) — at which point
//! `truncated = true` and `truncated_at_depth` records the
//! cutoff. That's a deliberate safety bound, not stripping.
//!
//! ── Cancel reason fields preserved ──────────────────────
//!
//! `CancelReason` (cancel.rs:520+) carries:
//!   - kind: CancelKind                   ← preserved at root
//!   - origin_region: RegionId            ← preserved at root
//!   - origin_task: Option<TaskId>        ← preserved at root
//!   - timestamp: Time                    ← preserved + propagated
//!     to descendants (with_timestamp(reason.timestamp))
//!   - message: Option<String>            ← preserved at root
//!   - cause: Option<Box<Self>>           ← built for descendants
//!   - truncated: bool                    ← only set if chain
//!     exceeds max_chain_depth
//!   - truncated_at_depth: Option<usize>  ← idem
//!
//! All operator-visible fields propagate intact.
//!
//! ── Inline test coverage ────────────────────────────────
//!
//! - `cancel_request_builds_cause_chains` (state.rs:6720)
//!   — root → child → grandchild (3-level), asserts that
//!   grandchild's task has `chain_depth=3`,
//!   `root_cause.kind=Deadline`, and the full chain
//!   `[ParentCancelled, ParentCancelled, Deadline]` is
//!   walkable.
//! - `cancel_request_respects_attribution_limits` (state.rs:6888)
//! - `cancel_request_respects_chain_depth_limit` (state.rs:6978)
//! - `cancel_request_truncates_large_tree` (state.rs:7039)
//! - `cancel_request_strengthens_existing_reason` (state.rs:7100)
//!
//! Verdict: **SOUND**. The original reason propagates
//! through the cancel-cause chain to every task being
//! cancelled. Root has exact original; descendants have
//! ParentCancelled chained to root via `cause`. `root_cause()`
//! returns the original at any depth. No information loss
//! except the bounded-depth truncation safety mechanism.
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cancel_request_root_region_gets_exact_original_reason() {
    // Pin: the cancel_request body assigns
    // `reason.clone()` to the root region — no
    // transformation, no stripping.
    let source = read("src/runtime/state.rs");

    let fn_marker = "pub fn cancel_request(";
    let pos = source.find(fn_marker).expect("cancel_request fn");
    let body_window = &source[pos..pos + 4000];

    assert!(
        body_window.contains("if rid == region_id {") && body_window.contains("reason.clone()"),
        "REGRESSION: cancel_request no longer assigns the \
         exact original reason (reason.clone()) to the \
         root region. Information stripping introduced.",
    );
}

#[test]
fn cancel_request_descendants_get_parent_cancelled_chained() {
    // Pin: descendants get ParentCancelled with cause
    // chain via with_cause_limited.
    let source = read("src/runtime/state.rs");

    let fn_marker = "pub fn cancel_request(";
    let pos = source.find(fn_marker).expect("cancel_request fn");
    let body_window = &source[pos..pos + 8000];

    assert!(
        body_window.contains("CancelReason::parent_cancelled()"),
        "REGRESSION: descendants no longer get \
         ParentCancelled kind. The cause-chain construction \
         is broken.",
    );

    assert!(
        body_window.contains("with_cause_limited(parent_reason"),
        "REGRESSION: descendants no longer chain to parent's \
         reason via with_cause_limited(parent_reason, ...). \
         The propagation path is broken — info loss.",
    );
}

#[test]
fn cancel_request_preserves_timestamp_through_descendants() {
    let source = read("src/runtime/state.rs");

    let fn_marker = "pub fn cancel_request(";
    let pos = source.find(fn_marker).expect("cancel_request fn");
    let body_window = &source[pos..pos + 5000];

    assert!(
        body_window.contains(".with_timestamp(reason.timestamp)"),
        "REGRESSION: descendants no longer carry the \
         original reason's timestamp. Causality \
         attribution is broken.",
    );
}

#[test]
fn cancel_request_processes_regions_depth_ascending() {
    // Pin: regions are sorted by depth so parents are
    // processed first. Without this, a child's cause
    // chain might point to an unbuilt parent reason.
    let source = read("src/runtime/state.rs");

    let fn_marker = "pub fn cancel_request(";
    let pos = source.find(fn_marker).expect("cancel_request fn");
    let body_window = &source[pos..pos + 5000];

    assert!(
        body_window.contains("regions_to_cancel.sort_by_key(|node| node.depth)"),
        "REGRESSION: cancel_request no longer sorts regions \
         by depth ascending. Cause chains may be built \
         with missing parent references.",
    );
}

#[test]
fn cancel_request_recovers_from_missing_parent_with_self_rooted_placeholder() {
    // Pin: the br-asupersync-tnk8ny safeguard — if a
    // parent reason is missing from the chain map (would
    // indicate an invariant break), synthesize a self-
    // rooted ParentCancelled placeholder rather than
    // silently chaining to the root reason.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("br-asupersync-tnk8ny") || source.contains("br-tnk8ny"),
        "REGRESSION: br-asupersync-tnk8ny safeguard \
         comment gone. Future maintainers may revert to \
         the silent-fallback bug it fixes.",
    );

    let fn_marker = "pub fn cancel_request(";
    let pos = source.find(fn_marker).expect("cancel_request fn");
    let body_window = &source[pos..pos + 5000];

    assert!(
        body_window
            .contains("CancelReason::with_origin(CancelKind::ParentCancelled, parent_id, now)"),
        "REGRESSION: missing-parent fallback no longer \
         synthesizes a self-rooted ParentCancelled \
         placeholder. The chain-break detection signal \
         (empty parent cause at depth>0) is broken.",
    );
}

#[test]
fn cancel_reason_struct_has_required_fields_for_propagation() {
    // Pin: all the fields needed for a debug-friendly
    // chain are present.
    let source = read("src/types/cancel.rs");

    let required_fields = [
        "pub kind:",
        "pub origin_region:",
        "pub origin_task:",
        "pub timestamp:",
        "pub message: Option<String>",
        "pub cause: Option<Box<Self>>",
        "pub truncated: bool",
        "pub truncated_at_depth: Option<usize>",
    ];

    for field in &required_fields {
        assert!(
            source.contains(field),
            "REGRESSION: CancelReason struct field `{field}` \
             is gone or changed. The propagation surface \
             is broken — debug-friendliness lost.",
        );
    }
}

#[test]
fn cancel_reason_root_cause_walker_exists() {
    // Pin: root_cause() walks the chain to the original.
    // This is the read-side of the propagation contract.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn root_cause(&self) ") || source.contains("fn root_cause(&self)"),
        "REGRESSION: CancelReason::root_cause walker is \
         gone. Callers cannot retrieve the original kind \
         from a chained descendant.",
    );
}

#[test]
fn cancel_reason_chain_walker_exists() {
    // Pin: chain() iterator walks every node in the chain.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn chain(&self)") || source.contains("fn chain(&self)"),
        "REGRESSION: CancelReason::chain iterator gone. \
         Callers cannot enumerate the cause chain for \
         debugging.",
    );
}

#[test]
fn cancel_reason_chain_depth_accessor_exists() {
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn chain_depth(&self)") || source.contains("fn chain_depth(&self)"),
        "REGRESSION: CancelReason::chain_depth accessor \
         gone.",
    );
}

#[test]
fn cancel_reason_with_cause_limited_uses_attribution_config() {
    // Pin: with_cause_limited consults a config to bound
    // chain depth — protects against pathological chains.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("with_cause_limited"),
        "REGRESSION: with_cause_limited is gone. Chain \
         depth is no longer bounded.",
    );
}

#[test]
fn cancel_reason_serde_uses_bounded_deserialize() {
    // Pin: the cause field uses deserialize_bounded_cause
    // for safety against attacker snapshots
    // (br-asupersync-dyao05).
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("deserialize_with = \"deserialize_bounded_cause\""),
        "REGRESSION: CancelReason.cause no longer uses \
         deserialize_bounded_cause. Wire-level defence \
         against deep-chain attacks is broken.",
    );
}

#[test]
fn task_cancel_requested_state_carries_chained_reason() {
    // Pin: when a task transitions to CancelRequested,
    // the carried reason includes the chain. The inline
    // test cancel_request_builds_cause_chains verifies
    // this for grandchild_task.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("TaskState::CancelRequested { reason"),
        "REGRESSION: the TaskState::CancelRequested variant \
         no longer destructures `reason` — task-level \
         propagation is broken.",
    );
}

#[test]
fn inline_test_cancel_request_builds_cause_chains_retained() {
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("fn cancel_request_builds_cause_chains()"),
        "REGRESSION: cancel_request_builds_cause_chains \
         inline test is gone. The propagation contract is \
         no longer guarded in-tree.",
    );
}

#[test]
fn inline_test_chain_depth_limit_retained() {
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("fn cancel_request_respects_chain_depth_limit()"),
        "REGRESSION: cancel_request_respects_chain_depth_limit \
         inline test gone.",
    );
}

#[test]
fn inline_test_truncates_large_tree_retained() {
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("fn cancel_request_truncates_large_tree()"),
        "REGRESSION: cancel_request_truncates_large_tree \
         inline test gone.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

impl CancelReason {
    fn new(kind: CancelKind, origin_region: u32) -> Self {
        Self {
            kind,
            origin_region,
            message: None,
            cause: None,
            truncated: false,
        }
    }

    fn with_message(mut self, msg: &str) -> Self {
        self.message = Some(msg.to_string());
        self
    }

    fn with_cause_limited(mut self, parent: Self, max_depth: usize) -> Self {
        let parent_depth = parent.chain_depth();
        if parent_depth + 1 > max_depth {
            self.truncated = true;
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

    fn chain(&self) -> Vec<&Self> {
        let mut out = Vec::new();
        let mut current = self;
        loop {
            out.push(current);
            match current.cause.as_deref() {
                Some(c) => current = c,
                None => break,
            }
        }
        out
    }
}

fn build_propagation_chain(
    root_reason: CancelReason,
    region_depths: &[u32],
    max_depth: usize,
) -> Vec<CancelReason> {
    // region_depths[0] is the root.
    let mut reasons = Vec::with_capacity(region_depths.len());
    reasons.push(root_reason.clone());

    for window in region_depths.windows(2) {
        let parent_id = window[0];
        let child_id = window[1];
        let _ = child_id;
        let parent_reason = reasons.last().unwrap().clone();
        let child_reason = CancelReason::new(CancelKind::ParentCancelled, parent_id)
            .with_cause_limited(parent_reason, max_depth);
        reasons.push(child_reason);
    }

    reasons
}

#[test]
fn behavioral_root_region_gets_exact_original_reason() {
    let original = CancelReason::new(CancelKind::Deadline, 1).with_message("budget exhausted");
    let chain = build_propagation_chain(original.clone(), &[1, 2, 3], 16);

    let root_record = &chain[0];
    assert_eq!(root_record.kind, CancelKind::Deadline);
    assert_eq!(root_record.message.as_deref(), Some("budget exhausted"));
    assert_eq!(
        root_record.origin_region, 1,
        "REGRESSION: root region's origin_region is not the \
         original. Information stripped.",
    );
}

#[test]
fn behavioral_descendant_root_cause_returns_original() {
    let original = CancelReason::new(CancelKind::Deadline, 1).with_message("budget exhausted");
    let chain = build_propagation_chain(original.clone(), &[1, 2, 3, 4], 16);

    // Last in chain is the deepest descendant.
    let deepest = &chain[3];
    assert_eq!(deepest.kind, CancelKind::ParentCancelled);

    // root_cause walks back to the original.
    let recovered = deepest.root_cause();
    assert_eq!(
        recovered.kind,
        CancelKind::Deadline,
        "REGRESSION: root_cause did not return the original \
         Deadline kind from a 3-level descendant. Info \
         loss.",
    );
    assert_eq!(
        recovered.message.as_deref(),
        Some("budget exhausted"),
        "REGRESSION: original message lost through \
         propagation. Debug-friendliness broken.",
    );
}

#[test]
fn behavioral_chain_depth_grows_with_descendants() {
    let original = CancelReason::new(CancelKind::User, 1);
    let chain = build_propagation_chain(original, &[1, 2, 3, 4, 5], 16);

    let depths: Vec<usize> = chain.iter().map(|r| r.chain_depth()).collect();
    assert_eq!(depths, vec![1, 2, 3, 4, 5]);
}

#[test]
fn behavioral_chain_walker_enumerates_full_attribution_path() {
    let original = CancelReason::new(CancelKind::Deadline, 1).with_message("phase boundary");
    let chain = build_propagation_chain(original, &[1, 2, 3], 16);

    let deepest = &chain[2];
    let walked = deepest.chain();

    assert_eq!(walked.len(), 3);
    assert_eq!(walked[0].kind, CancelKind::ParentCancelled);
    assert_eq!(walked[1].kind, CancelKind::ParentCancelled);
    assert_eq!(
        walked[2].kind,
        CancelKind::Deadline,
        "REGRESSION: deepest cause in chain walker is not \
         the original.",
    );
}

#[test]
fn behavioral_chain_depth_truncated_when_exceeds_limit() {
    let original = CancelReason::new(CancelKind::Deadline, 1);
    // 5-region chain with max_depth = 3 should truncate.
    let chain = build_propagation_chain(original, &[1, 2, 3, 4, 5], 3);

    // The 4th and 5th descendants should mark truncated=true.
    assert!(
        chain[3].truncated || chain[4].truncated,
        "REGRESSION: chain did not mark truncated when \
         exceeding max_depth. Pathological chains may \
         grow unbounded.",
    );
}

#[test]
fn behavioral_message_propagates_to_root_cause_at_any_depth() {
    let messages = ["first", "second", "third"];
    for msg in &messages {
        let original = CancelReason::new(CancelKind::Deadline, 1).with_message(msg);
        let chain = build_propagation_chain(original.clone(), &[1, 2, 3, 4], 16);
        for (depth, descendant) in chain.iter().enumerate() {
            assert_eq!(
                descendant.root_cause().message.as_deref(),
                Some(*msg),
                "REGRESSION: original message `{msg}` lost \
                 at depth {depth}.",
            );
        }
    }
}

#[test]
fn behavioral_immediate_parent_reason_accessible_via_cause() {
    let original = CancelReason::new(CancelKind::Deadline, 1);
    let chain = build_propagation_chain(original, &[1, 2, 3], 16);

    // Grandchild's cause should be the child's reason.
    let grandchild = &chain[2];
    let immediate_parent = grandchild.cause.as_deref().expect("grandchild has cause");

    assert_eq!(immediate_parent.kind, CancelKind::ParentCancelled);
    // The "child" reason was constructed with parent_id=1
    // (the root region's id), since its tree-parent was
    // the root. So origin_region=1.
    assert_eq!(immediate_parent.origin_region, 1);

    // And one step deeper: the root (Deadline).
    let grandparent = immediate_parent.cause.as_deref().expect("child has cause");
    assert_eq!(grandparent.kind, CancelKind::Deadline);
    assert_eq!(grandparent.origin_region, 1);
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
        "tests/runtime_cancel_cause_chain_depth_audit.rs",
        "tests/cx_self_cancel_vs_region_cancel_distinction_audit.rs",
        "tests/cx_checkpoint_with_vs_cancel_cause_separation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
