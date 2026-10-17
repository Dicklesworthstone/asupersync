//! Plan rewrite certificates with stable hashing.
//!
//! Certificates attest that a sequence of rewrite steps transformed a plan DAG
//! from one state to another. The hash function is deterministic, stable
//! across Rust versions, and **cryptographically strong** so a third party
//! cannot construct two distinct plans that hash to the same value.
//!
//! br-asupersync-eyb1s5: prior versions used 64-bit FNV-1a, which has no
//! collision resistance against an attacker who controls the plan input
//! (e.g., a malicious extractor producing a plan that hashes to the same
//! value as a benign certificate). The hash now wraps the full 256-bit
//! SHA-256 digest. The wire/golden representation switched from a `u64`
//! to a 64-character lowercase hex string.

use super::analysis::SideConditionChecker;
use super::rewrite::{
    RewritePolicy, RewriteReport, RewriteRule, RewriteStep, check_side_conditions,
};
use super::{PlanDag, PlanId, PlanNode};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Stable hashing (SHA-256, 256-bit)
// ---------------------------------------------------------------------------

/// Deterministic 256-bit hash of a plan DAG.
///
/// Uses SHA-256 for both cross-version stability and collision resistance
/// against adversarial inputs. The hash covers node structure, labels,
/// children order, durations, and the root pointer.
///
/// Encoding (do not change without bumping `CertificateVersion`):
/// each scalar is fed in little-endian and length-prefixed where variable;
/// node discriminants use the byte tags 0=Leaf, 1=Join, 2=Race, 3=Timeout.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlanHash([u8; 32]);

impl PlanHash {
    /// Returns the raw 32-byte hash value.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the hash as a 64-character lowercase hex string.
    ///
    /// Used for stable wire/golden representation and human-readable
    /// error fields. Round-trippable via [`Self::from_hex`].
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        use std::fmt::Write;
        for byte in &self.0 {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// Parses a 64-character lowercase hex string into a `PlanHash`.
    ///
    /// Returns `None` on length mismatch or non-hex characters.
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let bytes = hex.as_bytes();
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let pair = [*bytes.get(i * 2)?, *bytes.get(i * 2 + 1)?];
            let s = std::str::from_utf8(&pair).ok()?;
            *byte = u8::from_str_radix(s, 16).ok()?;
        }
        Some(Self(out))
    }

    /// Test-only helper: build a `PlanHash` from a 64-bit seed, embedded in
    /// the leading 8 bytes of the digest with the rest zero. Stable across
    /// the binary so tests that pin a specific hash value can keep doing so
    /// without re-deriving from a `PlanDag` shape.
    #[cfg(test)]
    pub(crate) fn from_u64_seed(seed: u64) -> Self {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&seed.to_le_bytes());
        Self(out)
    }

    /// Compute the stable SHA-256 hash of a plan DAG.
    #[must_use]
    pub fn of(dag: &PlanDag) -> Self {
        let mut hasher = Sha256::new();
        // Frame marker: node count.
        hasher.update((dag.nodes.len() as u64).to_le_bytes());
        for node in &dag.nodes {
            hash_node(&mut hasher, node);
        }
        // Hash root presence and value.
        match dag.root {
            Some(id) => {
                hasher.update([1u8]);
                hasher.update((id.index() as u64).to_le_bytes());
            }
            None => {
                hasher.update([0u8]);
            }
        }
        let digest: [u8; 32] = hasher.finalize().into();
        Self(digest)
    }
}

impl std::fmt::Debug for PlanHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PlanHash({})", self.to_hex())
    }
}

impl std::fmt::Display for PlanHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

fn hash_node(hasher: &mut Sha256, node: &PlanNode) {
    match node {
        PlanNode::Leaf { label } => {
            hasher.update([0u8]); // discriminant
            hasher.update((label.len() as u64).to_le_bytes());
            hasher.update(label.as_bytes());
        }
        PlanNode::Join { children } => {
            hasher.update([1u8]);
            hasher.update((children.len() as u64).to_le_bytes());
            for child in children {
                hasher.update((child.index() as u64).to_le_bytes());
            }
        }
        PlanNode::Race { children } => {
            hasher.update([2u8]);
            hasher.update((children.len() as u64).to_le_bytes());
            for child in children {
                hasher.update((child.index() as u64).to_le_bytes());
            }
        }
        PlanNode::Timeout { child, duration } => {
            hasher.update([3u8]);
            hasher.update((child.index() as u64).to_le_bytes());
            hasher.update(
                u64::try_from(duration.as_nanos())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate schema
// ---------------------------------------------------------------------------

/// Schema version for forward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateVersion(u32);

impl CertificateVersion {
    /// Current schema version.
    pub const CURRENT: Self = Self(1);

    /// Returns the numeric version.
    #[must_use]
    pub const fn number(self) -> u32 {
        self.0
    }

    /// Constructs a version from a raw number (test only).
    #[cfg(test)]
    pub(crate) const fn from_number(n: u32) -> Self {
        Self(n)
    }
}

/// A certified rewrite step: captures rule, before/after node ids, and detail.
#[derive(Debug, Clone)]
pub struct CertifiedStep {
    /// The rewrite rule that was applied.
    pub rule: RewriteRule,
    /// Node id that was replaced.
    pub before: PlanId,
    /// Node id that was introduced.
    pub after: PlanId,
    /// Human-readable explanation.
    pub detail: String,
}

impl CertifiedStep {
    fn from_rewrite_step(step: &RewriteStep) -> Self {
        Self {
            rule: step.rule,
            before: step.before,
            after: step.after,
            detail: step.detail.clone(),
        }
    }
}

/// Certificate attesting a plan rewrite.
///
/// Records the before/after hashes, the policy used, and each rewrite step.
/// A verifier can recompute hashes and compare to detect tampering or
/// divergence.
#[derive(Debug, Clone)]
pub struct RewriteCertificate {
    /// Schema version.
    pub version: CertificateVersion,
    /// Policy under which rewrites were applied.
    pub policy: RewritePolicy,
    /// Stable hash of the plan DAG before rewrites.
    pub before_hash: PlanHash,
    /// Stable hash of the plan DAG after rewrites.
    pub after_hash: PlanHash,
    /// Number of nodes in the DAG before rewrites.
    pub before_node_count: usize,
    /// Number of nodes in the DAG after rewrites.
    pub after_node_count: usize,
    /// Rewrite steps in application order.
    pub steps: Vec<CertifiedStep>,
}

impl RewriteCertificate {
    /// Returns true if no rewrites were applied.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.steps.is_empty() && self.before_hash == self.after_hash
    }

    /// Stable identity hash of this certificate (for dedup / indexing).
    ///
    /// br-asupersync-eyb1s5: returns the full SHA-256 digest of the
    /// certificate's identity-relevant fields (version, policy, hashes,
    /// step list). Encoded as a `PlanHash` so callers see one hash type.
    #[must_use]
    pub fn fingerprint(&self) -> PlanHash {
        let mut hasher = Sha256::new();
        hasher.update(self.version.number().to_le_bytes());
        // Hash policy as packed bits: assoc|comm|dist|require_binary_joins|timeout_simplification
        let policy_bits: u8 = pack_policy(self.policy);
        hasher.update([policy_bits]);
        hasher.update(self.before_hash.as_bytes());
        hasher.update(self.after_hash.as_bytes());
        hasher.update((self.steps.len() as u64).to_le_bytes());
        for step in &self.steps {
            hasher.update([step.rule as u8]);
            hasher.update((step.before.index() as u64).to_le_bytes());
            hasher.update((step.after.index() as u64).to_le_bytes());
        }
        let digest: [u8; 32] = hasher.finalize().into();
        PlanHash(digest)
    }

    /// Eliminate redundant steps to produce a minimal certificate.
    ///
    /// Removes:
    /// - Consecutive inverse pairs (commute(A→B) followed by commute(B→A))
    /// - No-op steps where before == after
    /// - Duplicate consecutive steps on the same node pair with the same rule
    #[must_use]
    pub fn minimize(&self) -> Self {
        let mut minimized: Vec<CertifiedStep> = Vec::with_capacity(self.steps.len());

        for step in &self.steps {
            // Skip no-ops where before and after are identical.
            if step.before == step.after {
                continue;
            }

            // Check for inverse pair: last step applied the same commutative rule
            // mapping B→A, and this step maps A→B (or vice versa).
            let is_inverse = minimized.last().is_some_and(|prev| {
                prev.rule == step.rule
                    && is_self_inverse(step.rule)
                    && prev.before == step.after
                    && prev.after == step.before
            });
            if is_inverse {
                minimized.pop();
                continue;
            }

            // Skip exact duplicate of the immediately preceding step.
            let is_dup = minimized.last().is_some_and(|prev| {
                prev.rule == step.rule && prev.before == step.before && prev.after == step.after
            });
            if is_dup {
                continue;
            }

            minimized.push(step.clone());
        }

        Self {
            version: self.version,
            policy: self.policy,
            before_hash: self.before_hash,
            after_hash: self.after_hash,
            before_node_count: self.before_node_count,
            after_node_count: self.after_node_count,
            steps: minimized,
        }
    }

    /// Produce a compact representation suitable for serialization.
    ///
    /// Strips detail strings and encodes steps as `(rule_discriminant, before, after)`.
    pub fn compact(&self) -> Result<CompactCertificate, CompactCertificateError> {
        let before_node_count = u32::try_from(self.before_node_count).map_err(|_| {
            CompactCertificateError::NodeCountOverflow {
                field: "before_node_count",
                value: self.before_node_count,
            }
        })?;
        let after_node_count = u32::try_from(self.after_node_count).map_err(|_| {
            CompactCertificateError::NodeCountOverflow {
                field: "after_node_count",
                value: self.after_node_count,
            }
        })?;

        let mut steps = Vec::with_capacity(self.steps.len());
        for (idx, step) in self.steps.iter().enumerate() {
            steps.push(CompactStep::try_from_certified(idx, step)?);
        }

        Ok(CompactCertificate {
            version: self.version,
            policy_bits: pack_policy(self.policy),
            before_hash: self.before_hash,
            after_hash: self.after_hash,
            before_node_count,
            after_node_count,
            steps,
        })
    }
}

/// Returns true if the rule is its own inverse (applying twice yields identity).
fn is_self_inverse(rule: RewriteRule) -> bool {
    matches!(rule, RewriteRule::JoinCommute | RewriteRule::RaceCommute)
}

fn pack_policy(policy: RewritePolicy) -> u8 {
    u8::from(policy.associativity)
        | (u8::from(policy.commutativity) << 1)
        | (u8::from(policy.distributivity) << 2)
        | (u8::from(policy.require_binary_joins) << 3)
        | (u8::from(policy.timeout_simplification) << 4)
}

// ---------------------------------------------------------------------------
// Compact certificate (detail-free, bounded-size)
// ---------------------------------------------------------------------------

/// A single rewrite step without the human-readable detail string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactStep {
    /// Rule discriminant (0..5 for current rules).
    pub rule: u8,
    /// Before node index.
    pub before: u32,
    /// After node index.
    pub after: u32,
}

/// Errors produced when compacting a rewrite certificate into the fixed-width
/// wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactCertificateError {
    /// A node count does not fit in the compact `u32` field.
    NodeCountOverflow {
        /// The overflowing count field.
        field: &'static str,
        /// The original value that could not be represented.
        value: usize,
    },
    /// A step references a node id that does not fit in the compact `u32` field.
    StepNodeOverflow {
        /// Step index in the full certificate.
        step: usize,
        /// The overflowing step field.
        field: &'static str,
        /// The original value that could not be represented.
        value: usize,
    },
}

impl CompactStep {
    fn try_from_certified(
        step_index: usize,
        step: &CertifiedStep,
    ) -> Result<Self, CompactCertificateError> {
        let before = u32::try_from(step.before.index()).map_err(|_| {
            CompactCertificateError::StepNodeOverflow {
                step: step_index,
                field: "before",
                value: step.before.index(),
            }
        })?;
        let after = u32::try_from(step.after.index()).map_err(|_| {
            CompactCertificateError::StepNodeOverflow {
                step: step_index,
                field: "after",
                value: step.after.index(),
            }
        })?;
        Ok(Self {
            rule: step.rule as u8,
            before,
            after,
        })
    }

    /// Wire size of one compact step: 1 (rule) + 4 (before) + 4 (after) = 9 bytes.
    pub const WIRE_SIZE: usize = 9;
}

/// Detail-free certificate for serialization and size-bounded storage.
///
/// Each step is 9 bytes (1-byte rule discriminant + two 4-byte node indices).
/// The header is fixed at 81 bytes. Total wire size = 81 + 9 * step_count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactCertificate {
    /// Schema version.
    pub version: CertificateVersion,
    /// Packed policy bits.
    pub policy_bits: u8,
    /// Stable hash before rewrites.
    pub before_hash: PlanHash,
    /// Stable hash after rewrites.
    pub after_hash: PlanHash,
    /// Node count before rewrites.
    pub before_node_count: u32,
    /// Node count after rewrites.
    pub after_node_count: u32,
    /// Compact rewrite steps.
    pub steps: Vec<CompactStep>,
}

impl CompactCertificate {
    /// Fixed header size: version(4) + policy(1) + 2*hash(64) + 2*node_count(8) = 77 bytes,
    /// plus step_count(4) = 81 bytes total header.
    ///
    /// br-asupersync-eyb1s5: hash bytes grew from 8 (FNV-1a u64) to 32
    /// (SHA-256), so the header expanded by 48 bytes.
    pub const HEADER_SIZE: usize = 81;

    /// Upper bound on wire size in bytes.
    #[must_use]
    pub fn byte_size_bound(&self) -> usize {
        Self::HEADER_SIZE.saturating_add(self.steps.len().saturating_mul(CompactStep::WIRE_SIZE))
    }

    /// Returns true if the certificate size is within the linear bound
    /// `HEADER_SIZE + 9 * max_steps`. Use `max_steps = after_node_count`
    /// as a conservative bound (each compact step references a node in the
    /// pre- or post-rewrite DAG).
    #[must_use]
    pub fn is_within_linear_bound(&self) -> bool {
        // A well-formed rewrite sequence touches each node at most a constant
        // number of times. We use after_node_count as the bound since rewrites
        // can only reduce or maintain the node count.
        let node_bound = self.after_node_count.max(self.before_node_count) as usize;
        self.steps.len() <= node_bound
    }
}

// ---------------------------------------------------------------------------
// Explanation ledger (deterministic, human-readable rewrite audit)
// ---------------------------------------------------------------------------

/// Cost snapshot for a single DAG state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DagCostSnapshot {
    /// Total node count.
    pub node_count: usize,
    /// Number of Join nodes.
    pub joins: usize,
    /// Number of Race nodes.
    pub races: usize,
    /// Number of Timeout nodes.
    pub timeouts: usize,
    /// DAG depth (longest root-to-leaf path).
    pub depth: usize,
}

impl DagCostSnapshot {
    /// Compute a cost snapshot from a plan DAG.
    #[must_use]
    pub fn of(dag: &PlanDag) -> Self {
        let mut joins = 0;
        let mut races = 0;
        let mut timeouts = 0;
        for node in &dag.nodes {
            match node {
                PlanNode::Join { .. } => joins += 1,
                PlanNode::Race { .. } => races += 1,
                PlanNode::Timeout { .. } => timeouts += 1,
                PlanNode::Leaf { .. } => {}
            }
        }
        Self {
            node_count: dag.nodes.len(),
            joins,
            races,
            timeouts,
            depth: dag_depth(dag),
        }
    }
}

fn dag_depth(dag: &PlanDag) -> usize {
    fn depth_of(dag: &PlanDag, id: PlanId, memo: &mut Vec<Option<usize>>) -> usize {
        let idx = id.index();
        if idx >= memo.len() {
            return 0;
        }
        if let Some(d) = memo[idx] {
            return d;
        }
        let d = match dag.node(id) {
            Some(PlanNode::Leaf { .. }) => 1,
            Some(PlanNode::Join { children } | PlanNode::Race { children }) => {
                let max_child = children
                    .iter()
                    .map(|c| depth_of(dag, *c, memo))
                    .max()
                    .unwrap_or(0);
                max_child + 1
            }
            Some(PlanNode::Timeout { child, .. }) => depth_of(dag, *child, memo) + 1,
            None => 0,
        };
        memo[idx] = Some(d);
        d
    }

    if dag.nodes.is_empty() {
        return 0;
    }
    let mut memo = vec![None; dag.nodes.len()];
    dag.root.map_or(0, |root| depth_of(dag, root, &mut memo))
}

/// One entry in the explanation ledger.
#[derive(Debug, Clone)]
pub struct ExplanationEntry {
    /// Step index in the certificate.
    pub step_index: usize,
    /// Human-readable law name.
    pub law: &'static str,
    /// Human-readable description of what happened.
    pub description: String,
    /// Side conditions that were verified (empty if none).
    pub side_conditions: Vec<&'static str>,
}

/// Deterministic, human-readable explanation of a plan optimization.
#[derive(Debug, Clone)]
pub struct ExplanationLedger {
    /// Cost snapshot before rewrites.
    pub before: DagCostSnapshot,
    /// Cost snapshot after rewrites.
    pub after: DagCostSnapshot,
    /// Per-step explanations.
    pub entries: Vec<ExplanationEntry>,
}

impl ExplanationLedger {
    /// Render the ledger as a deterministic multi-line string.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        out.push_str("=== Plan Rewrite Explanation ===\n");
        let _ = writeln!(
            out,
            "Before: {} nodes (J={} R={} T={}, depth={})",
            self.before.node_count,
            self.before.joins,
            self.before.races,
            self.before.timeouts,
            self.before.depth,
        );
        let _ = writeln!(
            out,
            "After:  {} nodes (J={} R={} T={}, depth={})",
            self.after.node_count,
            self.after.joins,
            self.after.races,
            self.after.timeouts,
            self.after.depth,
        );
        let node_delta = self.after.node_count.cast_signed() - self.before.node_count.cast_signed();
        let depth_delta = self.after.depth.cast_signed() - self.before.depth.cast_signed();
        let _ = writeln!(out, "Delta:  nodes={node_delta:+}, depth={depth_delta:+}");
        let _ = writeln!(out, "Steps:  {}", self.entries.len());

        for entry in &self.entries {
            let _ = writeln!(
                out,
                "\n  [{}] {}: {}",
                entry.step_index, entry.law, entry.description,
            );
            for cond in &entry.side_conditions {
                let _ = writeln!(out, "       condition: {cond}");
            }
        }
        out
    }
}

impl RewriteCertificate {
    /// Produce a deterministic explanation ledger from a certificate and the
    /// post-rewrite DAG. The `before_dag` is the DAG before rewrites (used for
    /// cost comparison).
    #[must_use]
    pub fn explain(&self, before_dag: &PlanDag, after_dag: &PlanDag) -> ExplanationLedger {
        let before = DagCostSnapshot::of(before_dag);
        let after = DagCostSnapshot::of(after_dag);
        let entries = self
            .steps
            .iter()
            .enumerate()
            .map(|(i, step)| explain_step(i, step, self.policy, after_dag))
            .collect();
        ExplanationLedger {
            before,
            after,
            entries,
        }
    }
}

fn rule_law_name(rule: RewriteRule) -> &'static str {
    match rule {
        RewriteRule::JoinAssoc => "Join Associativity",
        RewriteRule::RaceAssoc => "Race Associativity",
        RewriteRule::JoinCommute => "Join Commutativity",
        RewriteRule::RaceCommute => "Race Commutativity",
        RewriteRule::TimeoutMin => "Timeout Minimization",
        RewriteRule::DedupRaceJoin => "Race-Join Deduplication",
    }
}

fn rule_side_conditions(rule: RewriteRule, policy: RewritePolicy) -> Vec<&'static str> {
    match rule {
        RewriteRule::JoinAssoc | RewriteRule::RaceAssoc => {
            if policy.associativity {
                vec!["associativity enabled"]
            } else {
                vec![]
            }
        }
        RewriteRule::JoinCommute | RewriteRule::RaceCommute => {
            let mut conds = Vec::new();
            if policy.commutativity {
                conds.push("commutativity enabled");
            }
            conds.push("children are pairwise independent");
            conds
        }
        RewriteRule::TimeoutMin => vec!["nested timeout structure"],
        RewriteRule::DedupRaceJoin => {
            let mut conds = vec!["shared child across race branches"];
            if policy.distributivity {
                conds.push("distributivity enabled");
            }
            if policy.require_binary_joins {
                conds.push("binary joins required (conservative)");
            }
            conds
        }
    }
}

fn describe_node_brief(dag: &PlanDag, id: PlanId) -> String {
    match dag.node(id) {
        Some(PlanNode::Leaf { label }) => format!("Leaf({label})"),
        Some(PlanNode::Join { children }) => format!("Join[{}]", children.len()),
        Some(PlanNode::Race { children }) => format!("Race[{}]", children.len()),
        Some(PlanNode::Timeout { duration, .. }) => format!("Timeout({duration:?})"),
        None => format!("?{}", id.index()),
    }
}

fn explain_step(
    idx: usize,
    step: &CertifiedStep,
    policy: RewritePolicy,
    dag: &PlanDag,
) -> ExplanationEntry {
    let before_desc = describe_node_brief(dag, step.before);
    let after_desc = describe_node_brief(dag, step.after);
    let description = format!(
        "node {} ({}) -> node {} ({})",
        step.before.index(),
        before_desc,
        step.after.index(),
        after_desc,
    );
    ExplanationEntry {
        step_index: idx,
        law: rule_law_name(step.rule),
        description,
        side_conditions: rule_side_conditions(step.rule, policy),
    }
}

/// Verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Schema version mismatch.
    VersionMismatch {
        /// Version the verifier supports.
        expected: u32,
        /// Version found in the certificate.
        found: u32,
    },
    /// The after-hash in the certificate doesn't match the DAG.
    ///
    /// br-asupersync-eyb1s5: hashes are the full SHA-256 digest, encoded
    /// as a 64-character lowercase hex string for human-readable error
    /// reporting. Use [`PlanHash::from_hex`] to reconstruct.
    HashMismatch {
        /// Hash recorded in the certificate (hex).
        expected: String,
        /// Hash computed from the DAG (hex).
        actual: String,
    },
    /// The after-node count in the certificate doesn't match the DAG.
    NodeCountMismatch {
        /// Node count recorded in the certificate.
        expected: usize,
        /// Node count computed from the DAG.
        actual: usize,
    },
    /// A certified rewrite step was not structurally valid for the DAG.
    InvalidStep(StepVerifyError),
}

/// Error from step-level verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepVerifyError {
    /// The `before` node id doesn't exist in the DAG.
    MissingBeforeNode {
        /// Step index in the certificate.
        step: usize,
        /// Node id that was expected.
        node: PlanId,
    },
    /// The `after` node id doesn't exist in the DAG.
    MissingAfterNode {
        /// Step index in the certificate.
        step: usize,
        /// Node id that was expected.
        node: PlanId,
    },
    /// The before node wasn't the expected shape for this rule.
    InvalidBeforeShape {
        /// Step index.
        step: usize,
        /// Description of what was expected.
        expected: &'static str,
    },
    /// The after node wasn't the expected shape for this rule.
    InvalidAfterShape {
        /// Step index.
        step: usize,
        /// Description of what was expected.
        expected: &'static str,
    },
    /// A side condition of the rewrite rule was violated.
    SideConditionViolated {
        /// Step index.
        step: usize,
        /// Description of the violated condition.
        condition: String,
    },
}

/// Verify that each step in the certificate is structurally valid in the
/// post-rewrite DAG. This checks that the `after` nodes have the expected
/// shape for each rewrite rule.
///
/// Note: this verifies the *result* of the rewrite, not a replay. It checks
/// that the claimed transformation produced valid structure.
pub fn verify_steps(cert: &RewriteCertificate, dag: &PlanDag) -> Result<(), StepVerifyError> {
    for (idx, step) in cert.steps.iter().enumerate() {
        verify_single_step(idx, step, cert.policy, dag)?;
    }
    Ok(())
}

fn verify_single_step(
    idx: usize,
    step: &CertifiedStep,
    policy: RewritePolicy,
    dag: &PlanDag,
) -> Result<(), StepVerifyError> {
    match step.rule {
        RewriteRule::JoinAssoc => verify_join_assoc_result(idx, step, policy, dag),
        RewriteRule::RaceAssoc => verify_race_assoc_result(idx, step, policy, dag),
        RewriteRule::JoinCommute => verify_join_commute_result(idx, step, policy, dag),
        RewriteRule::RaceCommute => verify_race_commute_result(idx, step, policy, dag),
        RewriteRule::TimeoutMin => verify_timeout_min_result(idx, step, policy, dag),
        RewriteRule::DedupRaceJoin => verify_dedup_race_join_result(idx, step, policy, dag),
    }
}

fn verify_side_conditions(
    idx: usize,
    step: &CertifiedStep,
    policy: RewritePolicy,
    dag: &PlanDag,
) -> Result<(), StepVerifyError> {
    let checker = SideConditionChecker::new(dag);
    if let Err(condition) =
        check_side_conditions(step.rule, policy, &checker, dag, step.before, step.after)
    {
        return Err(StepVerifyError::SideConditionViolated {
            step: idx,
            condition,
        });
    }
    Ok(())
}

fn verify_join_assoc_result(
    idx: usize,
    step: &CertifiedStep,
    policy: RewritePolicy,
    dag: &PlanDag,
) -> Result<(), StepVerifyError> {
    let before = dag
        .node(step.before)
        .ok_or(StepVerifyError::MissingBeforeNode {
            step: idx,
            node: step.before,
        })?;
    let PlanNode::Join { children } = before else {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Join with at least one nested Join child",
        });
    };
    let mut expected = Vec::new();
    let mut changed = false;
    for child in children {
        match dag.node(*child) {
            Some(PlanNode::Join { children }) => {
                expected.extend(children.iter().copied());
                changed = true;
            }
            Some(_) => expected.push(*child),
            None => {
                return Err(StepVerifyError::InvalidBeforeShape {
                    step: idx,
                    expected: "Join children must exist",
                });
            }
        }
    }
    if !changed {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Join with at least one nested Join child",
        });
    }

    let after = dag
        .node(step.after)
        .ok_or(StepVerifyError::MissingAfterNode {
            step: idx,
            node: step.after,
        })?;
    let PlanNode::Join {
        children: after_children,
    } = after
    else {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Join after JoinAssoc",
        });
    };
    if *after_children != expected {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Flattened Join children",
        });
    }

    verify_side_conditions(idx, step, policy, dag)
}

fn verify_race_assoc_result(
    idx: usize,
    step: &CertifiedStep,
    policy: RewritePolicy,
    dag: &PlanDag,
) -> Result<(), StepVerifyError> {
    let before = dag
        .node(step.before)
        .ok_or(StepVerifyError::MissingBeforeNode {
            step: idx,
            node: step.before,
        })?;
    let PlanNode::Race { children } = before else {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Race with at least one nested Race child",
        });
    };
    let mut expected = Vec::new();
    let mut changed = false;
    for child in children {
        match dag.node(*child) {
            Some(PlanNode::Race { children }) => {
                expected.extend(children.iter().copied());
                changed = true;
            }
            Some(_) => expected.push(*child),
            None => {
                return Err(StepVerifyError::InvalidBeforeShape {
                    step: idx,
                    expected: "Race children must exist",
                });
            }
        }
    }
    if !changed {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Race with at least one nested Race child",
        });
    }

    let after = dag
        .node(step.after)
        .ok_or(StepVerifyError::MissingAfterNode {
            step: idx,
            node: step.after,
        })?;
    let PlanNode::Race {
        children: after_children,
    } = after
    else {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Race after RaceAssoc",
        });
    };
    if *after_children != expected {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Flattened Race children",
        });
    }

    verify_side_conditions(idx, step, policy, dag)
}

/// Returns true iff `a` and `b` are permutations of each other (same multiset).
///
/// The `Commute` rewrite rules (JoinCommute / RaceCommute) are valid only
/// when the after-node carries the SAME children as the before-node (in
/// possibly different order). Without this check, a forged certificate
/// could replace a Commute step's `after` with an arbitrary Join/Race
/// node carrying COMPLETELY DIFFERENT children — the previous shape-only
/// check would silently accept it (br-asupersync-kpd3k3).
fn is_permutation(a: &[PlanId], b: &[PlanId]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut a_sorted: Vec<u32> = a.iter().map(|id| id.index() as u32).collect();
    let mut b_sorted: Vec<u32> = b.iter().map(|id| id.index() as u32).collect();
    a_sorted.sort_unstable();
    b_sorted.sort_unstable();
    a_sorted == b_sorted
}

fn verify_join_commute_result(
    idx: usize,
    step: &CertifiedStep,
    policy: RewritePolicy,
    dag: &PlanDag,
) -> Result<(), StepVerifyError> {
    let before = dag
        .node(step.before)
        .ok_or(StepVerifyError::MissingBeforeNode {
            step: idx,
            node: step.before,
        })?;
    let PlanNode::Join {
        children: before_children,
    } = before
    else {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Join before JoinCommute",
        });
    };
    let after = dag
        .node(step.after)
        .ok_or(StepVerifyError::MissingAfterNode {
            step: idx,
            node: step.after,
        })?;
    let PlanNode::Join {
        children: after_children,
    } = after
    else {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Join after JoinCommute",
        });
    };
    // Replay-style check: a Commute rule MUST preserve the multiset of
    // children. Without this assertion the verifier accepts forged
    // certificates whose `after` carries unrelated children — the prior
    // shape-only check passed any well-formed Join. (br-asupersync-kpd3k3.)
    if !is_permutation(before_children, after_children) {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Join with same multiset of children as before (JoinCommute)",
        });
    }
    verify_side_conditions(idx, step, policy, dag)
}

fn verify_race_commute_result(
    idx: usize,
    step: &CertifiedStep,
    policy: RewritePolicy,
    dag: &PlanDag,
) -> Result<(), StepVerifyError> {
    let before = dag
        .node(step.before)
        .ok_or(StepVerifyError::MissingBeforeNode {
            step: idx,
            node: step.before,
        })?;
    let PlanNode::Race {
        children: before_children,
    } = before
    else {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Race before RaceCommute",
        });
    };
    let after = dag
        .node(step.after)
        .ok_or(StepVerifyError::MissingAfterNode {
            step: idx,
            node: step.after,
        })?;
    let PlanNode::Race {
        children: after_children,
    } = after
    else {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Race after RaceCommute",
        });
    };
    // Replay-style check: a Commute rule MUST preserve the multiset of
    // children. Without this assertion the verifier accepts forged
    // certificates whose `after` carries unrelated children — the prior
    // shape-only check passed any well-formed Race. (br-asupersync-kpd3k3.)
    if !is_permutation(before_children, after_children) {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Race with same multiset of children as before (RaceCommute)",
        });
    }
    verify_side_conditions(idx, step, policy, dag)
}

fn verify_timeout_min_result(
    idx: usize,
    step: &CertifiedStep,
    policy: RewritePolicy,
    dag: &PlanDag,
) -> Result<(), StepVerifyError> {
    let before = dag
        .node(step.before)
        .ok_or(StepVerifyError::MissingBeforeNode {
            step: idx,
            node: step.before,
        })?;
    let PlanNode::Timeout { child, duration } = before else {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Timeout wrapping a Timeout child",
        });
    };
    let PlanNode::Timeout {
        child: inner_child,
        duration: inner_duration,
    } = dag
        .node(*child)
        .ok_or(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Timeout wrapping a Timeout child",
        })?
    else {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Timeout wrapping a Timeout child",
        });
    };
    let expected_duration = if *duration <= *inner_duration {
        *duration
    } else {
        *inner_duration
    };

    let after = dag
        .node(step.after)
        .ok_or(StepVerifyError::MissingAfterNode {
            step: idx,
            node: step.after,
        })?;
    let PlanNode::Timeout {
        child: after_child,
        duration: after_duration,
    } = after
    else {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Timeout after TimeoutMin",
        });
    };
    if *after_child != *inner_child || *after_duration != expected_duration {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Timeout with min(d1,d2) over inner child",
        });
    }

    verify_side_conditions(idx, step, policy, dag)
}

/// Verify that a `DedupRaceJoin` step produced valid structure:
/// the `after` node should be `Join[shared, Race[...remaining]]`.
#[allow(clippy::too_many_lines)]
fn verify_dedup_race_join_result(
    idx: usize,
    step: &CertifiedStep,
    policy: RewritePolicy,
    dag: &PlanDag,
) -> Result<(), StepVerifyError> {
    let after_node = dag
        .node(step.after)
        .ok_or(StepVerifyError::MissingAfterNode {
            step: idx,
            node: step.after,
        })?;

    // After node must be a Join.
    let PlanNode::Join {
        children: after_children,
    } = after_node
    else {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Join node after DedupRaceJoin",
        });
    };

    if after_children.len() != 2 {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Join with exactly 2 children (shared + race)",
        });
    }

    let before_node = dag
        .node(step.before)
        .ok_or(StepVerifyError::MissingBeforeNode {
            step: idx,
            node: step.before,
        })?;
    let PlanNode::Race { children } = before_node else {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Race of Join children before DedupRaceJoin",
        });
    };
    if children.len() < 2 {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Race with >= 2 Join children before DedupRaceJoin",
        });
    }

    let requires_binary_joins = policy.requires_binary_joins();
    let allows_shared_non_leaf = policy.allows_shared_non_leaf();

    if requires_binary_joins && children.len() != 2 {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Binary race required by Conservative policy",
        });
    }

    let mut join_children = Vec::with_capacity(children.len());
    for child in children {
        match dag.node(*child) {
            Some(PlanNode::Join { children }) => {
                if requires_binary_joins && children.len() != 2 {
                    return Err(StepVerifyError::InvalidBeforeShape {
                        step: idx,
                        expected: "Binary joins required by Conservative policy",
                    });
                }
                join_children.push(children.clone());
            }
            _ => {
                return Err(StepVerifyError::InvalidBeforeShape {
                    step: idx,
                    expected: "Race children must be Join nodes",
                });
            }
        }
    }

    let mut intersection: std::collections::BTreeSet<PlanId> =
        join_children[0].iter().copied().collect();
    for join_nodes in join_children.iter().skip(1) {
        let set: std::collections::BTreeSet<PlanId> = join_nodes.iter().copied().collect();
        intersection.retain(|id| set.contains(id));
    }
    if intersection.len() != 1 {
        return Err(StepVerifyError::InvalidBeforeShape {
            step: idx,
            expected: "Race joins must share exactly one child",
        });
    }
    let shared = *intersection.iter().next().expect("shared");
    if !allows_shared_non_leaf {
        match dag.node(shared) {
            Some(PlanNode::Leaf { .. }) => {}
            _ => {
                return Err(StepVerifyError::InvalidBeforeShape {
                    step: idx,
                    expected: "Shared child must be a Leaf under Conservative policy",
                });
            }
        }
    }

    // One child should be the shared leaf/node, and the other a Race.
    if !after_children.contains(&shared) {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Join containing the shared child after DedupRaceJoin",
        });
    }
    let has_race_child = after_children.iter().any(|child_id| {
        dag.node(*child_id)
            .is_some_and(|n| matches!(n, PlanNode::Race { .. }))
    });

    if !has_race_child {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Join containing a Race child after DedupRaceJoin",
        });
    }

    verify_side_conditions(idx, step, policy, dag)
}

/// Verify that a certificate matches the given post-rewrite DAG.
///
/// This checks:
/// - schema version compatibility
/// - post-rewrite hash stability
/// - post-rewrite node-count stability
/// - structural validity of every certified rewrite step
pub fn verify(cert: &RewriteCertificate, dag: &PlanDag) -> Result<(), VerifyError> {
    if cert.version != CertificateVersion::CURRENT {
        return Err(VerifyError::VersionMismatch {
            expected: CertificateVersion::CURRENT.number(),
            found: cert.version.number(),
        });
    }
    let actual = PlanHash::of(dag);
    if cert.after_hash != actual {
        return Err(VerifyError::HashMismatch {
            expected: cert.after_hash.to_hex(),
            actual: actual.to_hex(),
        });
    }
    let actual_node_count = dag.nodes.len();
    if cert.after_node_count != actual_node_count {
        return Err(VerifyError::NodeCountMismatch {
            expected: cert.after_node_count,
            actual: actual_node_count,
        });
    }
    verify_steps(cert, dag).map_err(VerifyError::InvalidStep)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// PlanDag integration
// ---------------------------------------------------------------------------

impl PlanDag {
    /// Apply rewrites and produce a certificate.
    pub fn apply_rewrites_certified(
        &mut self,
        policy: RewritePolicy,
        rules: &[RewriteRule],
    ) -> (RewriteReport, RewriteCertificate) {
        let before_hash = PlanHash::of(self);
        let before_node_count = self.nodes.len();

        let report = self.apply_rewrites(policy, rules);

        let after_hash = PlanHash::of(self);
        let after_node_count = self.nodes.len();

        let steps = report
            .steps()
            .iter()
            .map(CertifiedStep::from_rewrite_step)
            .collect();

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy,
            before_hash,
            after_hash,
            before_node_count,
            after_node_count,
            steps,
        };

        (report, cert)
    }
}

#[cfg(test)]
#[path = "certificate_inline_tests.rs"]
mod tests;
