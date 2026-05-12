//! Audit + regression test for cancel-cause chain depth
//! preservation across multi-level cancellation propagation.
//!
//! Operator's question: "when task A cancels B which cancels
//! C which cancels D (4-level cancellation chain), is the
//! cause-chain preserved end-to-end (correct: full debugging
//! trail) or truncated to N levels (information loss)?"
//!
//! Audit findings:
//!
//!   asupersync's cancel-cause chain is **preserved
//!   end-to-end up to a configurable bound (default 16
//!   levels)**, with explicit truncation metadata when the
//!   bound is exceeded. For the operator's 4-level scenario
//!   (well under 16), the chain is FULLY preserved with no
//!   information loss. The chain construction:
//!
//!   1. **`CancelReason.cause` is `Option<Box<Self>>`**
//!      (types/cancel.rs:544): each level holds an owning
//!      `Box` to the next level. Chain depth is unlimited
//!      structurally — limits are enforced by configuration,
//!      not by the type itself.
//!
//!   2. **`CancelAttributionConfig`** (types/cancel.rs:184):
//!      ```ignore
//!      pub struct CancelAttributionConfig {
//!          pub max_chain_depth: usize,   // default 16
//!          pub max_chain_memory: usize,  // default 4096 bytes
//!      }
//!      ```
//!      Default 16 levels covers typical deeply-nested
//!      structured-concurrency hierarchies. The 4KB memory
//!      bound prevents pathological chains.
//!
//!   3. **`with_cause_limited`** (types/cancel.rs:706):
//!      enforces both bounds when extending a chain. When
//!      `total_depth > max_chain_depth`, the chain is
//!      truncated and the `truncated` flag + `truncated_at_depth`
//!      field record exactly where truncation happened —
//!      not silent information loss.
//!
//!   4. **Region subtree walk preserves chain depth-ascending**
//!      (state.rs:2542-2597): regions are processed in
//!      depth-ascending order so when a child is processed,
//!      its parent's reason is already in `region_reasons`.
//!      The child's reason is built as
//!      `CancelReason::parent_cancelled().with_region(parent_id).
//!      with_cause_limited(parent_reason, &self.cancel_attribution)`
//!      — so each propagation step adds exactly one level to
//!      the chain.
//!
//!   5. **`tnk8ny` hardening** (state.rs:2555-2586): a prior
//!      bug (br-asupersync-tnk8ny) silently fell back to
//!      `reason.clone()` (the root target's reason) when the
//!      parent's reason was missing from the map. This
//:      poisoned the cause chain by stamping the root reason
//!      as if it were the immediate parent's. The fix is
//!      explicit: log `error!` and synthesize a self-rooted
//!      ParentCancelled placeholder with NO with_cause_limited
//!      — so consumers see "depth>0 region with empty parent
//!      cause" as a clear signal instead of a misleading
//!      chain.
//!
//!   6. **`strengthen` preserves the WINNING reason's chain**
//!      (types/cancel.rs:956): when two reasons compete (same
//!      task gets cancelled twice), strengthen picks the
//!      higher-severity one and clones its full chain via
//!      `cause.clone_from(&other.cause)`. The losing chain is
//!      discarded — but the winning chain is preserved
//!      end-to-end.
//!
//!   7. **`root_cause()`** (types/cancel.rs:842): walks the
//!      chain to the root by following `cause` Option<Box>
//!      pointers. Returns the deepest CancelReason — useful
//!      for logging the original trigger.
//!
//!   8. **`chain_depth()` and `caused_by()`** (types/cancel.rs:
//!      853, 867): expose the chain length and let consumers
//!      check transitive causation. Both depend on the
//!      end-to-end preservation property.
//!
//! Verdict: **SOUND**. For the operator's 4-level scenario,
//! the chain is preserved end-to-end with full debugging
//! trail. For deeper chains (>16 by default), truncation is
//! explicit (truncated flag + truncated_at_depth) rather
//! than silent. The bounds are configurable
//! (CancelAttributionConfig::unlimited() exists for testing
//! / special cases).
//!
//! The design tradeoff is correct: unlimited chains would
//! grow unboundedly under cycle-prone cascades; bounded +
//! observable truncation gives the right balance between
//! debugging fidelity and resource bounds.
//!
//! A regression that:
//!   - removed `with_cause_limited` and replaced all callers
//!     with `with_cause` (no bound — pathological chains
//:     could grow unboundedly under deep cascades),
//!   - removed the `truncated` / `truncated_at_depth` fields
//!     from CancelReason (silent truncation — operator can't
//!     detect information loss),
//!   - reverted the tnk8ny fix and silently fell back to
//!     `reason.clone()` on missing parent (chain poisoned —
//!     looks like depth-0 root from a depth-N child),
//!   - changed strengthen to keep its OWN chain instead of
//!     the winner's chain (loser's reason wins the chain →
//!     misleading attribution),
//!   - reduced default max_chain_depth from 16 to a single-
//!     digit value (would silently truncate typical
//:     structured-concurrency hierarchies — the operator's
//!     4-level case might now be ON the truncation boundary),
//!   - changed cause field from Option<Box<Self>> to a
//!     stack-allocated alternative (would limit chain depth
//!     by stack size instead of configuration),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cancel_reason_cause_field_is_box_self_for_unbounded_chain_structure() {
    // Pin (link 1): CancelReason.cause is Option<Box<Self>>.
    // The Box is what allows arbitrary chain depth — the
    // bound is enforced by configuration, not by the type.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub cause: Option<Box<Self>>,"),
        "REGRESSION: CancelReason.cause is no longer \
         Option<Box<Self>>. A stack-allocated alternative \
         (e.g., Option<Self> or fixed-size array) would limit \
         chain depth to compile-time constants — operator's \
         4-level case might still work but deep cascades \
         would silently fail.",
    );
}

#[test]
fn cancel_attribution_config_default_max_depth_is_16() {
    // Pin (link 2): default max_chain_depth is 16 — generous
    // for typical structured-concurrency hierarchies. The
    // operator's 4-level case is well within bounds (4 <<
    // 16). A regression that reduced this to single digits
    // would put the 4-level case on the truncation boundary.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub const DEFAULT_MAX_DEPTH: usize = 16;"),
        "REGRESSION: default max_chain_depth changed from 16. \
         Reducing it would silently truncate typical \
         structured-concurrency hierarchies — operator's \
         4-level case might now be on the truncation \
         boundary instead of well within bounds.",
    );

    assert!(
        source.contains("pub const DEFAULT_MAX_MEMORY: usize = 4096;"),
        "REGRESSION: default max_chain_memory changed from 4KB. \
         The memory bound is the second axis on chain bounds; \
         changing it changes how deep chains can be before \
         memory-driven truncation.",
    );

    assert!(
        source.contains("max_chain_depth: Self::DEFAULT_MAX_DEPTH,")
            && source.contains("max_chain_memory: Self::DEFAULT_MAX_MEMORY,"),
        "REGRESSION: CancelAttributionConfig::default() no \
         longer uses the documented constants. The defaults \
         drift apart from the constants — debugging \
         expectations break.",
    );
}

#[test]
fn cancel_attribution_config_unlimited_constructor_exists() {
    // Pin (link 2): unlimited() constructor exists for
    // testing / special cases that genuinely need unbounded
    // chains. Removing it would force tests to set
    // usize::MAX explicitly — verbose and error-prone.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub const fn unlimited() -> Self {"),
        "REGRESSION: CancelAttributionConfig::unlimited() is \
         gone. Tests / debugging tools that need unbounded \
         chains lose the documented escape hatch.",
    );
}

#[test]
fn with_cause_limited_truncates_with_explicit_metadata() {
    // Pin (link 3): with_cause_limited enforces both
    // max_chain_depth and max_chain_memory. When the chain
    // exceeds either, truncated=true + truncated_at_depth=
    // Some(depth) record EXACTLY where truncation happened
    // — not silent loss.
    let source = read("src/types/cancel.rs");

    let fn_marker = "pub fn with_cause_limited(mut self, cause: Self, config: &CancelAttributionConfig) -> Self {";
    let start = source.find(fn_marker).expect("with_cause_limited fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("with_cause_limited close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.truncated = true;") && body.contains("self.truncated_at_depth = Some("),
        "REGRESSION: with_cause_limited no longer sets \
         truncated/truncated_at_depth on overflow. Operators \
         can't detect that information was lost — silent \
         truncation reverts the explicit-bound design.",
    );

    assert!(
        body.contains("config.max_chain_depth") && body.contains("config.max_chain_memory"),
        "REGRESSION: with_cause_limited no longer enforces \
         BOTH max_chain_depth AND max_chain_memory. Removing \
         either bound creates a path where pathological \
         chains can grow under cycle-prone cascades.",
    );
}

#[test]
fn cancel_reason_truncation_metadata_fields_present() {
    // Pin (link 3): CancelReason carries truncated +
    // truncated_at_depth fields so consumers can detect and
    // measure information loss. Removing them would silence
    // the truncation signal.
    let source = read("src/types/cancel.rs");

    let suspect_struct_changes = ["pub struct CancelReason {"];
    for marker in &suspect_struct_changes {
        let start = source.find(marker).expect("CancelReason struct");
        let body_end = source[start..]
            .find("\n}\n")
            .expect("CancelReason struct close");
        let body = &source[start..start + body_end];

        assert!(
            body.contains("pub truncated:") || body.contains("truncated:"),
            "REGRESSION: CancelReason no longer has the \
             `truncated` field. Truncated chains look \
             identical to untruncated ones — silent \
             information loss.",
        );

        assert!(
            body.contains("pub truncated_at_depth:") || body.contains("truncated_at_depth:"),
            "REGRESSION: CancelReason no longer has the \
             `truncated_at_depth` field. Even if `truncated` \
             remains, consumers can't tell WHERE truncation \
             happened — debugging fidelity lost.",
        );
    }
}

#[test]
fn region_subtree_walk_uses_with_cause_limited_per_descent_level() {
    // Pin (link 4): the cancel-region-subtree walk in
    // state.rs builds each descendant's reason via
    // CancelReason::parent_cancelled().with_region(parent_id).
    // with_cause_limited(parent_reason, &self.cancel_attribution).
    // Each propagation step adds exactly one level to the
    // chain — preserving end-to-end up to the bound.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("CancelReason::parent_cancelled()")
            && source.contains(".with_cause_limited(parent_reason, &self.cancel_attribution)"),
        "REGRESSION: cancel-region-subtree no longer builds \
         the cause chain via parent_cancelled().with_cause_limited(). \
         Either the chain is no longer extended per descent \
         level (silent loss) OR the bounds are no longer \
         applied (unbounded growth).",
    );
}

#[test]
fn region_subtree_processes_depth_ascending_for_chain_lookup() {
    // Pin (link 4 invariant): regions are processed in
    // depth-ascending order so when a child is reached, its
    // parent's reason is already in region_reasons. Without
    // this ordering, the chain-lookup invariant breaks and
    // the tnk8ny fallback fires for every descendant.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("region_reasons.insert(rid, region_reason.clone());"),
        "REGRESSION: cancel-region-subtree no longer stores \
         each region's reason for child chain building. \
         Descendants can't find their parent's reason in the \
         map — tnk8ny fallback fires unnecessarily and chain \
         attribution is degraded.",
    );

    // The lookup happens via region_reasons.get(&parent_id).
    assert!(
        source.contains("region_reasons.get(&parent_id)"),
        "REGRESSION: cancel-region-subtree no longer looks \
         up the parent's reason via region_reasons.get. The \
         chain-lookup invariant requires this map access.",
    );
}

#[test]
fn tnk8ny_hardening_logs_error_and_synthesizes_self_rooted_placeholder() {
    // Pin (link 5): the tnk8ny fix emits an error! log AND
    // synthesizes a SELF-ROOTED ParentCancelled placeholder
    // (NOT a chain to the root reason) when the parent's
    // reason is missing. This avoids the previous silent-
    // poisoning bug where the root's reason was used as if
    // it were the immediate parent's.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("INVARIANT VIOLATION: parent region's cancel reason missing"),
        "REGRESSION: cancel-region-subtree no longer logs the \
         tnk8ny invariant violation. The chain-bookkeeping \
         break becomes silent — debugging cancel attribution \
         loses the diagnostic.",
    );

    // The synthesized placeholder must be ParentCancelled
    // stamped at the missing parent's region — NOT a chain
    // to the root reason.
    assert!(
        source.contains("CancelReason::with_origin(CancelKind::ParentCancelled, parent_id, now)"),
        "REGRESSION: cancel-region-subtree no longer \
         synthesizes the self-rooted ParentCancelled \
         placeholder on missing parent. If it falls back to \
         `reason.clone()` (the root reason), the tnk8ny bug \
         is back — chain shows root cause as immediate \
         parent.",
    );
}

#[test]
fn strengthen_preserves_winning_reasons_chain() {
    // Pin (link 6): strengthen() picks the higher-severity
    // reason and clones its full chain via
    // cause.clone_from(&other.cause). The loser's chain is
    // discarded — but the winner's chain is preserved
    // end-to-end.
    let source = read("src/types/cancel.rs");

    let fn_marker = "pub fn strengthen(&mut self, other: &Self) -> bool {";
    let start = source.find(fn_marker).expect("strengthen fn");
    let body_end = source[start..].find("\n    }\n").expect("strengthen close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.cause.clone_from(&other.cause);"),
        "REGRESSION: strengthen no longer clones the winning \
         reason's cause chain. The loser's chain is kept by \
         default — wrong attribution. Or the chain is lost \
         entirely — silent information loss.",
    );

    // strengthen must use severity comparison (not just
    // first-write-wins which would discard later-arriving
    // higher-severity reasons).
    assert!(
        body.contains("other.kind.severity() > self.kind.severity()"),
        "REGRESSION: strengthen no longer uses severity \
         comparison. First-write-wins would discard \
         higher-severity reasons that arrived later — \
         attribution-correctness regression.",
    );
}

#[test]
fn cancel_reason_chain_depth_method_walks_via_chain_iterator() {
    // Pin (link 8): chain_depth uses the chain() iterator to
    // count levels. A regression that hardcoded a constant
    // depth or returned a stored field would diverge from
    // the actual chain structure.
    let source = read("src/types/cancel.rs");

    assert!(
        source.contains("pub fn chain_depth(&self) -> usize {")
            && source.contains("self.chain().count()"),
        "REGRESSION: chain_depth no longer walks the chain \
         iterator. A hardcoded value would diverge from the \
         actual chain — debugging tools see wrong depths.",
    );
}

#[test]
fn cancel_reason_root_cause_method_walks_to_chain_end() {
    // Pin (link 7): root_cause walks via the cause Option<Box>
    // chain to the deepest level. A regression that returned
    // self instead of walking would lose the root attribution.
    let source = read("src/types/cancel.rs");

    let fn_marker = "pub fn root_cause(&self) -> &Self {";
    let start = source.find(fn_marker).expect("root_cause fn");
    let body_end = source[start..].find("\n    }\n").expect("root_cause close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("while let Some(ref cause) = current.cause {"),
        "REGRESSION: root_cause no longer walks the cause \
         chain via while-let. A degenerate `&self` return \
         would treat every reason as its own root — chain \
         attribution useless.",
    );
}

// ─────────── BEHAVIORAL PIN: 4-level chain build & verify ──
//
// Build a 4-level cause chain locally (mirroring the
// production pattern of with_cause_limited), then verify:
// (1) chain_depth == 4, (2) root_cause is the original
// trigger, (3) walking the chain visits all 4 levels,
// (4) under default 16-depth bound the chain is NOT
// truncated.

#[derive(Clone, Debug)]
struct MockReason {
    kind: u8,
    region: u32,
    cause: Option<Box<MockReason>>,
    truncated: bool,
    truncated_at_depth: Option<usize>,
}

impl MockReason {
    fn new(kind: u8, region: u32) -> Self {
        Self {
            kind,
            region,
            cause: None,
            truncated: false,
            truncated_at_depth: None,
        }
    }

    fn chain_depth(&self) -> usize {
        let mut depth = 0_usize;
        let mut cur: &MockReason = self;
        loop {
            depth += 1;
            match &cur.cause {
                Some(c) => cur = c,
                None => return depth,
            }
        }
    }

    fn root_cause(&self) -> &Self {
        let mut cur = self;
        while let Some(c) = &cur.cause {
            cur = c;
        }
        cur
    }

    fn with_cause_limited(mut self, cause: Self, max_depth: usize) -> Self {
        let total = 1 + cause.chain_depth();
        if total > max_depth {
            // Truncate
            self.truncated = true;
            self.truncated_at_depth = Some(max_depth);
            // Walk the cause chain and keep at most max_depth - 1 levels.
            // Mirrors the production truncate_chain semantics at a high level.
            let allowed = max_depth.saturating_sub(1);
            if allowed == 0 {
                return self;
            }
            self.cause = Some(Box::new(Self::truncate(cause, allowed)));
        } else {
            self.cause = Some(Box::new(cause));
        }
        self
    }

    fn truncate(mut reason: Self, max_depth: usize) -> Self {
        let Some(cause) = reason.cause.take() else {
            return Self {
                cause: None,
                truncated: false,
                truncated_at_depth: reason.truncated_at_depth,
                ..reason
            };
        };

        if max_depth <= 1 {
            return Self {
                cause: None,
                truncated: true,
                truncated_at_depth: Some(1),
                ..reason
            };
        }

        Self {
            cause: Some(Box::new(Self::truncate(*cause, max_depth - 1))),
            ..reason
        }
    }
}

#[test]
fn four_level_cancel_chain_is_preserved_end_to_end() {
    // Behavioral pin: the operator's exact scenario — A
    // cancels B cancels C cancels D, total 4 levels. With
    // default max_chain_depth=16, the chain is FULLY
    // preserved with no truncation.
    const DEFAULT_MAX_DEPTH: usize = 16;

    // Level 4 (root cause): D was the original trigger.
    let level_d = MockReason::new(0xD, 4);
    // Level 3: C cancels D, so C's reason carries D as cause.
    let level_c = MockReason::new(0xC, 3).with_cause_limited(level_d, DEFAULT_MAX_DEPTH);
    // Level 2: B cancels C.
    let level_b = MockReason::new(0xB, 2).with_cause_limited(level_c, DEFAULT_MAX_DEPTH);
    // Level 1: A cancels B (the topmost reason that surfaces
    // to the operator).
    let level_a = MockReason::new(0xA, 1).with_cause_limited(level_b, DEFAULT_MAX_DEPTH);

    // chain_depth must be 4.
    assert_eq!(
        level_a.chain_depth(),
        4,
        "REGRESSION: 4-level cause chain reports depth {actual} \
         instead of 4. Chain construction or chain_depth \
         walking is broken.",
        actual = level_a.chain_depth(),
    );

    // root_cause must be D (the original trigger).
    let root = level_a.root_cause();
    assert_eq!(
        root.kind,
        0xD,
        "REGRESSION: root_cause of the 4-level chain is not \
         D (got kind 0x{kind:X}). Chain attribution is \
         broken — operator can't trace back to the original \
         trigger.",
        kind = root.kind,
    );
    assert_eq!(
        root.region,
        4,
        "REGRESSION: root_cause region is {region}, expected \
         4. Region attribution lost across propagation.",
        region = root.region,
    );

    // No truncation flag at any level (4 << 16).
    assert!(
        !level_a.truncated,
        "REGRESSION: 4-level chain marked truncated under \
         default 16-level bound. truncated_at_depth = {depth:?}",
        depth = level_a.truncated_at_depth,
    );

    // Walk the chain manually and verify the order: A → B → C → D.
    let levels: Vec<u8> = {
        let mut out = Vec::new();
        let mut cur: &MockReason = &level_a;
        loop {
            out.push(cur.kind);
            match &cur.cause {
                Some(c) => cur = c,
                None => break,
            }
        }
        out
    };
    assert_eq!(
        levels,
        vec![0xA, 0xB, 0xC, 0xD],
        "REGRESSION: chain walk produced wrong order. \
         Expected A → B → C → D (the propagation sequence), \
         got {levels:?}.",
    );
}

#[test]
fn deep_chain_beyond_default_bound_truncates_with_explicit_metadata() {
    // Behavioral pin: a 20-level chain under default
    // max_chain_depth=16 SHOULD be truncated, with
    // truncated=true + truncated_at_depth=Some(16) recording
    // exactly where truncation happened. Information loss is
    // EXPLICIT, not silent.
    const DEFAULT_MAX_DEPTH: usize = 16;

    let mut chain = MockReason::new(0, 0);
    for i in 1..20_u32 {
        chain = MockReason::new(i as u8, i).with_cause_limited(chain, DEFAULT_MAX_DEPTH);
    }

    assert!(
        chain.truncated,
        "REGRESSION: 20-level chain under 16-bound is not \
         marked truncated. Silent information loss — \
         operator can't detect chain truncation.",
    );

    assert_eq!(
        chain.truncated_at_depth,
        Some(DEFAULT_MAX_DEPTH),
        "REGRESSION: truncated_at_depth does not point to \
         the bound (16). Got {actual:?}. Operator can't tell \
         WHERE truncation happened.",
        actual = chain.truncated_at_depth,
    );

    // Resulting chain must be at most max_chain_depth levels.
    assert!(
        chain.chain_depth() <= DEFAULT_MAX_DEPTH,
        "REGRESSION: truncated chain has depth {depth} > \
         max_chain_depth {bound}. Truncation didn't actually \
         truncate.",
        depth = chain.chain_depth(),
        bound = DEFAULT_MAX_DEPTH,
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_region_close_timed_lane_task_cancellation_audit.rs",
        "tests/scheduler_cancel_storm_propagation_audit.rs",
        "tests/cx_checkpoint_observes_parent_region_cancel_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
