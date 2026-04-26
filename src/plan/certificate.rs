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
/// The header is fixed at 33 bytes. Total wire size = 33 + 9 * step_count.
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::time::Duration;

    fn init_test() {
        init_test_logging();
    }

    fn dedup_race_join_ledger() -> ExplanationLedger {
        let mut before_dag = PlanDag::new();
        let shared = before_dag.leaf("shared");
        let left = before_dag.leaf("left");
        let right = before_dag.leaf("right");
        let join_a = before_dag.join(vec![shared, left]);
        let join_b = before_dag.join(vec![shared, right]);
        let race = before_dag.race(vec![join_a, join_b]);
        before_dag.set_root(race);

        let mut after_dag = before_dag.clone();
        let (_, cert) = after_dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        cert.explain(&before_dag, &after_dag)
    }

    #[test]
    fn hash_deterministic_across_calls() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let h1 = PlanHash::of(&dag);
        let h2 = PlanHash::of(&dag);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_dags_produce_different_hashes() {
        init_test();
        let mut dag1 = PlanDag::new();
        let a = dag1.leaf("a");
        let b = dag1.leaf("b");
        let join = dag1.join(vec![a, b]);
        dag1.set_root(join);

        let mut dag2 = PlanDag::new();
        let c = dag2.leaf("c");
        let d = dag2.leaf("d");
        let race = dag2.race(vec![c, d]);
        dag2.set_root(race);

        assert_ne!(PlanHash::of(&dag1), PlanHash::of(&dag2));
    }

    #[test]
    fn child_order_matters() {
        init_test();
        let mut dag1 = PlanDag::new();
        let a = dag1.leaf("a");
        let b = dag1.leaf("b");
        let join1 = dag1.join(vec![a, b]);
        dag1.set_root(join1);

        let mut dag2 = PlanDag::new();
        let a2 = dag2.leaf("a");
        let b2 = dag2.leaf("b");
        let join2 = dag2.join(vec![b2, a2]);
        dag2.set_root(join2);

        assert_ne!(PlanHash::of(&dag1), PlanHash::of(&dag2));
    }

    #[test]
    fn timeout_duration_affects_hash() {
        init_test();
        let mut dag1 = PlanDag::new();
        let a = dag1.leaf("a");
        let t1 = dag1.timeout(a, Duration::from_secs(1));
        dag1.set_root(t1);

        let mut dag2 = PlanDag::new();
        let a2 = dag2.leaf("a");
        let t2 = dag2.timeout(a2, Duration::from_secs(2));
        dag2.set_root(t2);

        assert_ne!(PlanHash::of(&dag1), PlanHash::of(&dag2));
    }

    #[test]
    fn certified_rewrite_produces_valid_certificate() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (report, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        assert_eq!(report.steps().len(), 1);
        assert_eq!(cert.steps.len(), 1);
        assert_eq!(cert.version, CertificateVersion::CURRENT);
        assert_eq!(cert.policy, RewritePolicy::conservative());
        assert_ne!(cert.before_hash, cert.after_hash);
        assert!(!cert.is_identity());

        // Verify against post-rewrite DAG.
        assert!(verify(&cert, &dag).is_ok());
    }

    #[test]
    fn identity_rewrite_produces_identity_certificate() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let (_report, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        assert!(cert.is_identity());
        assert!(verify(&cert, &dag).is_ok());
    }

    #[test]
    fn verify_detects_hash_mismatch() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_report, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        // Mutate the DAG after certification.
        dag.leaf("extra");

        let result = verify(&cert, &dag);
        assert!(result.is_err());
        assert!(matches!(result, Err(VerifyError::HashMismatch { .. })));
    }

    #[test]
    fn verify_detects_node_count_mismatch() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_report, mut cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        cert.after_node_count += 1;

        let result = verify(&cert, &dag);
        assert!(matches!(result, Err(VerifyError::NodeCountMismatch { .. })));
    }

    #[test]
    fn certificate_fingerprint_is_deterministic() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let fp1 = cert.fingerprint();
        let fp2 = cert.fingerprint();
        assert_eq!(fp1, fp2);
        assert!(
            fp1.as_bytes().iter().any(|b| *b != 0),
            "fingerprint must not be all-zero"
        );
    }

    #[test]
    fn version_mismatch_detected() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let (_, mut cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        cert.version = CertificateVersion::from_number(99);

        let result = verify(&cert, &dag);
        assert!(matches!(result, Err(VerifyError::VersionMismatch { .. })));
    }

    #[test]
    fn verify_steps_accepts_valid_rewrite() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        assert!(verify_steps(&cert, &dag).is_ok());
    }

    #[test]
    fn verify_steps_rejects_missing_after_node() {
        init_test();
        // Create a valid DedupRaceJoin structure (Race of Joins with shared child)
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared"); // node 0
        let left = dag.leaf("left"); // node 1
        let right = dag.leaf("right"); // node 2
        let join_a = dag.join(vec![shared, left]); // node 3
        let join_b = dag.join(vec![shared, right]); // node 4
        let race = dag.race(vec![join_a, join_b]); // node 5
        dag.set_root(race);

        // Create certificate with valid before (the race) but non-existent after
        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: 6,
            after_node_count: 6,
            steps: vec![CertifiedStep {
                rule: RewriteRule::DedupRaceJoin,
                before: race,
                after: PlanId::new(999), // doesn't exist
                detail: "fake".to_string(),
            }],
        };

        let result = verify_steps(&cert, &dag);
        assert!(matches!(
            result,
            Err(StepVerifyError::MissingAfterNode { .. })
        ));
    }

    #[test]
    fn verify_steps_rejects_wrong_after_shape() {
        init_test();
        // Create a valid DedupRaceJoin structure (Race of Joins with shared child)
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared"); // node 0
        let left = dag.leaf("left"); // node 1
        let right = dag.leaf("right"); // node 2
        let join_a = dag.join(vec![shared, left]); // node 3
        let join_b = dag.join(vec![shared, right]); // node 4
        let race = dag.race(vec![join_a, join_b]); // node 5
        dag.set_root(race);

        // Create certificate with valid before (the race) but wrong after shape (a Leaf)
        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: 6,
            after_node_count: 6,
            steps: vec![CertifiedStep {
                rule: RewriteRule::DedupRaceJoin,
                before: race,
                after: shared, // points to a Leaf, not a Join
                detail: "fake".to_string(),
            }],
        };

        let result = verify_steps(&cert, &dag);
        assert!(matches!(
            result,
            Err(StepVerifyError::InvalidAfterShape { .. })
        ));
    }

    #[test]
    fn verify_rejects_invalid_step_structure() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: dag.nodes.len(),
            after_node_count: dag.nodes.len(),
            steps: vec![CertifiedStep {
                rule: RewriteRule::DedupRaceJoin,
                before: race,
                after: shared,
                detail: "fake".to_string(),
            }],
        };

        let result = verify(&cert, &dag);
        assert!(matches!(
            result,
            Err(VerifyError::InvalidStep(
                StepVerifyError::InvalidAfterShape { .. }
            ))
        ));
    }

    #[test]
    fn verify_steps_identity_passes() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        assert!(cert.is_identity());
        assert!(verify_steps(&cert, &dag).is_ok());
    }

    // -----------------------------------------------------------------------
    // Certificate minimization tests (bd-35xx)
    // -----------------------------------------------------------------------

    #[test]
    fn minimize_removes_noop_steps() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let (_, base_cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        // Inject a no-op step (before == after).
        let mut cert = base_cert;
        cert.steps.push(CertifiedStep {
            rule: RewriteRule::JoinAssoc,
            before: a,
            after: a,
            detail: "no-op".to_string(),
        });
        assert_eq!(cert.steps.len(), 1);

        let minimized = cert.minimize();
        assert!(minimized.steps.is_empty());
    }

    #[test]
    fn minimize_removes_inverse_commute_pair() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let hash = PlanHash::of(&dag);
        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: hash,
            after_hash: hash,
            before_node_count: 3,
            after_node_count: 3,
            steps: vec![
                CertifiedStep {
                    rule: RewriteRule::JoinCommute,
                    before: PlanId::new(2),
                    after: PlanId::new(3),
                    detail: "commute forward".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::JoinCommute,
                    before: PlanId::new(3),
                    after: PlanId::new(2),
                    detail: "commute back".to_string(),
                },
            ],
        };

        let minimized = cert.minimize();
        assert!(minimized.steps.is_empty());
    }

    #[test]
    fn minimize_removes_consecutive_duplicates() {
        init_test();
        let hash = PlanHash::from_u64_seed(0x1234);
        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: hash,
            after_hash: hash,
            before_node_count: 4,
            after_node_count: 4,
            steps: vec![
                CertifiedStep {
                    rule: RewriteRule::JoinAssoc,
                    before: PlanId::new(0),
                    after: PlanId::new(1),
                    detail: "assoc".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::JoinAssoc,
                    before: PlanId::new(0),
                    after: PlanId::new(1),
                    detail: "assoc dup".to_string(),
                },
            ],
        };

        let minimized = cert.minimize();
        assert_eq!(minimized.steps.len(), 1);
    }

    #[test]
    fn minimize_preserves_non_redundant_steps() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let minimized = cert.minimize();
        assert_eq!(minimized.steps.len(), cert.steps.len());
        assert_eq!(minimized.before_hash, cert.before_hash);
        assert_eq!(minimized.after_hash, cert.after_hash);
    }

    #[test]
    fn compact_certificate_strips_details() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let compact = cert
            .compact()
            .expect("compact certificate fits u32 wire format");
        assert_eq!(compact.steps.len(), cert.steps.len());
        assert_eq!(compact.version, cert.version);
        assert_eq!(compact.before_hash, cert.before_hash);
        assert_eq!(compact.after_hash, cert.after_hash);

        for (cs, fs) in compact.steps.iter().zip(cert.steps.iter()) {
            assert_eq!(cs.rule, fs.rule as u8);
            assert_eq!(cs.before, u32::try_from(fs.before.index()).unwrap());
            assert_eq!(cs.after, u32::try_from(fs.after.index()).unwrap());
        }
    }

    #[test]
    fn compact_byte_size_bound_is_tight() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let compact = cert
            .compact()
            .expect("compact certificate fits u32 wire format");
        let bound = compact.byte_size_bound();
        // 1 step => 33 + 9 = 42 bytes
        assert_eq!(
            bound,
            CompactCertificate::HEADER_SIZE + CompactStep::WIRE_SIZE
        );
        assert_eq!(bound, 42);
    }

    #[test]
    fn certificate_within_linear_bound() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let compact = cert
            .compact()
            .expect("compact certificate fits u32 wire format");
        assert!(compact.is_within_linear_bound());
    }

    #[test]
    fn identity_certificate_compact_is_minimal() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        assert!(cert.is_identity());
        let compact = cert
            .compact()
            .expect("compact certificate fits u32 wire format");
        assert!(compact.steps.is_empty());
        assert_eq!(compact.byte_size_bound(), CompactCertificate::HEADER_SIZE);
        assert!(compact.is_within_linear_bound());
    }

    #[test]
    fn minimize_then_compact_reduces_size() {
        init_test();
        let hash = PlanHash::from_u64_seed(0xABCD);
        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: hash,
            after_hash: hash,
            before_node_count: 5,
            after_node_count: 5,
            steps: vec![
                CertifiedStep {
                    rule: RewriteRule::RaceCommute,
                    before: PlanId::new(0),
                    after: PlanId::new(1),
                    detail: "commute".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::RaceCommute,
                    before: PlanId::new(1),
                    after: PlanId::new(0),
                    detail: "un-commute".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::JoinAssoc,
                    before: PlanId::new(2),
                    after: PlanId::new(3),
                    detail: "assoc".to_string(),
                },
            ],
        };

        let raw_compact = cert
            .compact()
            .expect("compact certificate fits u32 wire format");
        let minimized_compact = cert
            .minimize()
            .compact()
            .expect("compact certificate fits u32 wire format");

        assert_eq!(raw_compact.steps.len(), 3);
        assert_eq!(minimized_compact.steps.len(), 1);
        assert!(minimized_compact.byte_size_bound() < raw_compact.byte_size_bound());
    }

    #[test]
    fn compact_rejects_node_count_overflow() {
        init_test();
        if usize::BITS <= u32::BITS {
            return;
        }

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: PlanHash::from_u64_seed(0xABCD),
            after_hash: PlanHash::from_u64_seed(0xABCD),
            before_node_count: (u32::MAX as usize) + 1,
            after_node_count: 1,
            steps: Vec::new(),
        };

        let err = cert.compact().expect_err("overflow must be rejected");
        assert_eq!(
            err,
            CompactCertificateError::NodeCountOverflow {
                field: "before_node_count",
                value: (u32::MAX as usize) + 1,
            }
        );
    }

    #[test]
    fn compact_rejects_step_node_overflow() {
        init_test();
        if usize::BITS <= u32::BITS {
            return;
        }

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: PlanHash::from_u64_seed(0x1234),
            after_hash: PlanHash::from_u64_seed(0x1234),
            before_node_count: 1,
            after_node_count: 1,
            steps: vec![CertifiedStep {
                rule: RewriteRule::JoinAssoc,
                before: PlanId::new((u32::MAX as usize) + 1),
                after: PlanId::new(0),
                detail: "overflow".to_string(),
            }],
        };

        let err = cert.compact().expect_err("overflow must be rejected");
        assert_eq!(
            err,
            CompactCertificateError::StepNodeOverflow {
                step: 0,
                field: "before",
                value: (u32::MAX as usize) + 1,
            }
        );
    }

    // -----------------------------------------------------------------------
    // Explanation ledger tests (bd-1rup)
    // -----------------------------------------------------------------------

    #[test]
    fn dag_cost_snapshot_counts_nodes() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        let c = dag.leaf("c");
        let race = dag.race(vec![join, c]);
        dag.set_root(race);

        let snap = DagCostSnapshot::of(&dag);
        assert_eq!(snap.node_count, 5);
        assert_eq!(snap.joins, 1);
        assert_eq!(snap.races, 1);
        assert_eq!(snap.timeouts, 0);
        assert_eq!(snap.depth, 3); // race -> join -> leaf
    }

    #[test]
    fn dag_depth_handles_timeout() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_secs(1));
        dag.set_root(t);

        let snap = DagCostSnapshot::of(&dag);
        assert_eq!(snap.depth, 2); // timeout -> leaf
        assert_eq!(snap.timeouts, 1);
    }

    #[test]
    fn explain_produces_entries_for_each_step() {
        init_test();
        let mut before_dag = PlanDag::new();
        let shared = before_dag.leaf("shared");
        let left = before_dag.leaf("left");
        let right = before_dag.leaf("right");
        let join_a = before_dag.join(vec![shared, left]);
        let join_b = before_dag.join(vec![shared, right]);
        let race = before_dag.race(vec![join_a, join_b]);
        before_dag.set_root(race);

        let mut after_dag = before_dag.clone();
        let (_, cert) = after_dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let ledger = cert.explain(&before_dag, &after_dag);
        assert_eq!(ledger.entries.len(), cert.steps.len());
        assert_eq!(ledger.entries[0].law, "Race-Join Deduplication");
        assert!(!ledger.entries[0].side_conditions.is_empty());
    }

    #[test]
    fn explain_identity_is_empty() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let before_dag = dag.clone();
        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let ledger = cert.explain(&before_dag, &dag);
        assert!(ledger.entries.is_empty());
        assert_eq!(ledger.before.node_count, ledger.after.node_count);
    }

    #[test]
    fn explain_render_is_deterministic() {
        init_test();
        let ledger = dedup_race_join_ledger();
        let r1 = ledger.render();
        let r2 = ledger.render();
        assert_eq!(r1, r2);
        assert!(r1.contains("Plan Rewrite Explanation"));
        assert!(r1.contains("Race-Join Deduplication"));
        assert!(r1.contains("Before:"));
        assert!(r1.contains("After:"));
        assert!(r1.contains("Delta:"));
    }

    #[test]
    fn explain_shows_cost_delta() {
        init_test();
        let ledger = dedup_race_join_ledger();
        // DedupRaceJoin adds nodes (the new Join+Race structure), so after >= before.
        assert!(ledger.after.node_count >= ledger.before.node_count);
        // The render should show the delta.
        let rendered = ledger.render();
        assert!(rendered.contains("nodes="));
        assert!(rendered.contains("depth="));
    }

    #[test]
    fn explain_render_snapshot_dedup_race_join() {
        init_test();
        let ledger = dedup_race_join_ledger();

        insta::assert_snapshot!("plan_certificate_dedup_race_join_render", ledger.render());
    }

    #[test]
    fn plan_hash_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;

        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);
        let h = PlanHash::of(&dag);

        let dbg = format!("{h:?}");
        assert!(dbg.contains("PlanHash"));

        let h2 = h;
        assert_eq!(h, h2);

        // Copy
        let h3 = h;
        assert_eq!(h, h3);

        // Hash: usable in HashSet
        let mut set = HashSet::new();
        set.insert(h);
        assert!(set.contains(&h));
    }

    #[test]
    fn certificate_version_debug_clone_copy_eq() {
        let v = CertificateVersion::CURRENT;
        let dbg = format!("{v:?}");
        assert!(dbg.contains("CertificateVersion"));

        let v2 = v;
        assert_eq!(v, v2);

        let v3 = v;
        assert_eq!(v, v3);
    }

    #[test]
    fn compact_step_debug_clone_copy_eq() {
        let s = CompactStep {
            rule: 1,
            before: 10,
            after: 20,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("CompactStep"));

        let s2 = s;
        assert_eq!(s, s2);

        let s3 = s;
        assert_eq!(s, s3);
    }

    // -----------------------------------------------------------------------
    // Comprehensive Golden Artifact Tests for latency_algebra certificate format
    // -----------------------------------------------------------------------

    #[test]
    fn golden_certificate_join_associativity_render() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let inner = dag.join(vec![a, b]);
        let outer = dag.join(vec![inner, c]);
        dag.set_root(outer);

        let before_dag = dag.clone();
        let (_, cert) =
            dag.apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::JoinAssoc]);

        let ledger = cert.explain(&before_dag, &dag);
        insta::assert_snapshot!(
            "plan_certificate_join_associativity_render",
            ledger.render()
        );
    }

    #[test]
    fn golden_certificate_race_associativity_render() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let inner = dag.race(vec![a, b]);
        let outer = dag.race(vec![inner, c]);
        dag.set_root(outer);

        let before_dag = dag.clone();
        let (_, cert) =
            dag.apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::RaceAssoc]);

        let ledger = cert.explain(&before_dag, &dag);
        insta::assert_snapshot!(
            "plan_certificate_race_associativity_render",
            ledger.render()
        );
    }

    #[test]
    fn golden_certificate_timeout_minimization_render() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let inner_timeout = dag.timeout(a, Duration::from_millis(200));
        let outer_timeout = dag.timeout(inner_timeout, Duration::from_millis(100));
        dag.set_root(outer_timeout);

        let before_dag = dag.clone();
        let (_, cert) =
            dag.apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::TimeoutMin]);

        let ledger = cert.explain(&before_dag, &dag);
        insta::assert_snapshot!(
            "plan_certificate_timeout_minimization_render",
            ledger.render()
        );
    }

    #[test]
    fn golden_certificate_join_commutativity_render() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("fast");
        let b = dag.leaf("slow");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let before_dag = dag.clone();
        let (_, cert) =
            dag.apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::JoinCommute]);

        if !cert.is_identity() {
            let ledger = cert.explain(&before_dag, &dag);
            insta::assert_snapshot!(
                "plan_certificate_join_commutativity_render",
                ledger.render()
            );
        }
    }

    #[test]
    fn golden_certificate_race_commutativity_render() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("option_a");
        let b = dag.leaf("option_b");
        let race = dag.race(vec![a, b]);
        dag.set_root(race);

        let before_dag = dag.clone();
        let (_, cert) =
            dag.apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::RaceCommute]);

        if !cert.is_identity() {
            let ledger = cert.explain(&before_dag, &dag);
            insta::assert_snapshot!(
                "plan_certificate_race_commutativity_render",
                ledger.render()
            );
        }
    }

    #[test]
    fn golden_certificate_compact_format_variations() {
        init_test();

        // Identity certificate (no rewrites)
        let mut dag = PlanDag::new();
        let a = dag.leaf("isolated");
        dag.set_root(a);

        let (_, identity_cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let identity_compact = identity_cert.compact().unwrap();
        insta::assert_debug_snapshot!("plan_certificate_identity_compact", identity_compact);

        // Multi-step certificate
        let mut complex_dag = PlanDag::new();
        let shared = complex_dag.leaf("shared");
        let left = complex_dag.leaf("left");
        let right = complex_dag.leaf("right");
        let extra = complex_dag.leaf("extra");

        let join_a = complex_dag.join(vec![shared, left]);
        let join_b = complex_dag.join(vec![shared, right]);
        let inner_race = complex_dag.race(vec![join_a, join_b]);
        let outer_join = complex_dag.join(vec![inner_race, extra]);
        complex_dag.set_root(outer_join);

        let (_, multi_cert) = complex_dag.apply_rewrites_certified(
            RewritePolicy::assume_all(),
            &[RewriteRule::DedupRaceJoin, RewriteRule::JoinAssoc],
        );

        if !multi_cert.steps.is_empty() {
            let multi_compact = multi_cert.compact().unwrap();
            insta::assert_debug_snapshot!("plan_certificate_multi_step_compact", multi_compact);
        }
    }

    #[test]
    fn golden_certificate_fingerprints() {
        init_test();

        // Different certificates should have different fingerprints
        let mut dag1 = PlanDag::new();
        let a = dag1.leaf("a");
        let b = dag1.leaf("b");
        let join1 = dag1.join(vec![a, b]);
        dag1.set_root(join1);

        let mut dag2 = PlanDag::new();
        let x = dag2.leaf("x");
        let y = dag2.leaf("y");
        let race2 = dag2.race(vec![x, y]);
        dag2.set_root(race2);

        let (_, cert1) =
            dag1.apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::JoinAssoc]);

        let (_, cert2) =
            dag2.apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::RaceAssoc]);

        let fingerprint1 = cert1.fingerprint();
        let fingerprint2 = cert2.fingerprint();

        // Capture fingerprints as stable golden artifacts
        insta::assert_snapshot!(
            "plan_certificate_join_fingerprint",
            format!("{fingerprint1:#018x}")
        );

        insta::assert_snapshot!(
            "plan_certificate_race_fingerprint",
            format!("{fingerprint2:#018x}")
        );

        assert_ne!(
            fingerprint1, fingerprint2,
            "Different certificates should have different fingerprints"
        );
    }

    #[test]
    fn golden_certificate_policy_variations() {
        init_test();

        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        // Conservative policy
        let before_dag = dag.clone();
        let mut conservative_dag = dag.clone();
        let (_, conservative_cert) = conservative_dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let conservative_ledger = conservative_cert.explain(&before_dag, &conservative_dag);
        insta::assert_snapshot!(
            "plan_certificate_conservative_policy_render",
            conservative_ledger.render()
        );

        // Permissive policy
        let mut permissive_dag = dag.clone();
        let (_, permissive_cert) = permissive_dag
            .apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::DedupRaceJoin]);

        let permissive_ledger = permissive_cert.explain(&before_dag, &permissive_dag);
        insta::assert_snapshot!(
            "plan_certificate_permissive_policy_render",
            permissive_ledger.render()
        );
    }

    #[test]
    fn golden_certificate_minimization_effects() {
        init_test();

        // Create certificate with redundant steps
        let hash = PlanHash::from_u64_seed(0xDEADBEEF);
        let cert_with_redundancy = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: hash,
            after_hash: hash,
            before_node_count: 4,
            after_node_count: 4,
            steps: vec![
                CertifiedStep {
                    rule: RewriteRule::JoinCommute,
                    before: PlanId::new(0),
                    after: PlanId::new(1),
                    detail: "commute forward".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::JoinAssoc,
                    before: PlanId::new(2),
                    after: PlanId::new(2), // no-op
                    detail: "no-op associativity".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::JoinCommute,
                    before: PlanId::new(1),
                    after: PlanId::new(0),
                    detail: "commute back (inverse)".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::RaceAssoc,
                    before: PlanId::new(3),
                    after: PlanId::new(4),
                    detail: "meaningful step".to_string(),
                },
            ],
        };

        let minimized = cert_with_redundancy.minimize();

        // Capture before and after minimization
        insta::assert_snapshot!(
            "plan_certificate_before_minimization",
            format!(
                "steps: {}\nfingerprint: {:#018x}",
                cert_with_redundancy.steps.len(),
                cert_with_redundancy.fingerprint()
            )
        );

        insta::assert_snapshot!(
            "plan_certificate_after_minimization",
            format!(
                "steps: {}\nfingerprint: {:#018x}",
                minimized.steps.len(),
                minimized.fingerprint()
            )
        );
    }

    #[test]
    fn golden_certificate_dag_cost_snapshots() {
        init_test();

        // Complex DAG with all node types
        let mut dag = PlanDag::new();
        let a = dag.leaf("service_a");
        let b = dag.leaf("service_b");
        let c = dag.leaf("service_c");

        let timeout_a = dag.timeout(a, Duration::from_millis(500));
        let join_ab = dag.join(vec![timeout_a, b]);
        let race_abc = dag.race(vec![join_ab, c]);
        let timeout_root = dag.timeout(race_abc, Duration::from_secs(2));
        dag.set_root(timeout_root);

        let snapshot = DagCostSnapshot::of(&dag);

        insta::assert_snapshot!(
            "plan_certificate_dag_cost_snapshot",
            format!(
                "node_count: {}\njoins: {}\nraces: {}\ntimeouts: {}\ndepth: {}",
                snapshot.node_count,
                snapshot.joins,
                snapshot.races,
                snapshot.timeouts,
                snapshot.depth
            )
        );
    }

    #[test]
    fn golden_certificate_plan_hash_stability() {
        init_test();

        // Create several DAGs and capture their stable hashes
        let test_cases = [
            ("single_leaf", vec![("a", None)]),
            (
                "simple_join",
                vec![("a", None), ("b", None), ("join_ab", Some("join"))],
            ),
            (
                "simple_race",
                vec![("x", None), ("y", None), ("race_xy", Some("race"))],
            ),
            (
                "nested_timeout",
                vec![
                    ("task", None),
                    ("timeout_inner", Some("timeout")),
                    ("timeout_outer", Some("timeout")),
                ],
            ),
        ];

        let mut hash_outputs = Vec::new();

        for (name, nodes) in test_cases {
            let mut dag = PlanDag::new();
            let mut node_ids = Vec::new();

            for (label, node_type) in nodes {
                let id = match node_type {
                    None => dag.leaf(label),
                    Some("join") => {
                        assert!(node_ids.len() >= 2, "Need at least 2 nodes for join");
                        dag.join(node_ids.clone())
                    }
                    Some("race") => {
                        assert!(node_ids.len() >= 2, "Need at least 2 nodes for race");
                        dag.race(node_ids.clone())
                    }
                    Some("timeout") => {
                        assert!(!node_ids.is_empty(), "Need a child for timeout");
                        dag.timeout(node_ids[node_ids.len() - 1], Duration::from_millis(100))
                    }
                    _ => panic!("Unknown node type"),
                };
                node_ids.push(id);
            }

            if !node_ids.is_empty() {
                dag.set_root(node_ids[node_ids.len() - 1]);
            }

            let hash = PlanHash::of(&dag);
            hash_outputs.push(format!("{}: {:#018x}", name, hash.value()));
        }

        insta::assert_snapshot!("plan_certificate_hash_stability", hash_outputs.join("\n"));
    }

    // -----------------------------------------------------------------------
    // br-asupersync-kpd3k3: replay-style multiset check on Commute rules
    // -----------------------------------------------------------------------

    #[test]
    fn join_commute_rejects_forged_after_with_unrelated_children() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let x = dag.leaf("x");
        let y = dag.leaf("y");
        let before = dag.join(vec![a, b]);
        let after = dag.join(vec![x, y]);
        dag.set_root(before);

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::assume_all(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: dag.nodes.len(),
            after_node_count: dag.nodes.len(),
            steps: vec![CertifiedStep {
                rule: RewriteRule::JoinCommute,
                before,
                after,
                detail: "forged JoinCommute".to_string(),
            }],
        };

        match verify_steps(&cert, &dag) {
            Err(StepVerifyError::InvalidAfterShape { .. }) => {}
            other => panic!("expected InvalidAfterShape, got {other:?}"),
        }
    }

    #[test]
    fn race_commute_rejects_forged_after_with_unrelated_children() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let x = dag.leaf("x");
        let y = dag.leaf("y");
        let before = dag.race(vec![a, b]);
        let after = dag.race(vec![x, y]);
        dag.set_root(before);

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::assume_all(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: dag.nodes.len(),
            after_node_count: dag.nodes.len(),
            steps: vec![CertifiedStep {
                rule: RewriteRule::RaceCommute,
                before,
                after,
                detail: "forged RaceCommute".to_string(),
            }],
        };

        match verify_steps(&cert, &dag) {
            Err(StepVerifyError::InvalidAfterShape { .. }) => {}
            other => panic!("expected InvalidAfterShape, got {other:?}"),
        }
    }

    #[test]
    fn join_commute_accepts_legitimate_permutation() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let before = dag.join(vec![a, b, c]);
        let after = dag.join(vec![c, a, b]);
        dag.set_root(before);

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::assume_all(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: dag.nodes.len(),
            after_node_count: dag.nodes.len(),
            steps: vec![CertifiedStep {
                rule: RewriteRule::JoinCommute,
                before,
                after,
                detail: "legitimate JoinCommute permutation".to_string(),
            }],
        };

        verify_steps(&cert, &dag)
            .expect("legitimate JoinCommute permutation must verify (multiset preserved)");
    }
}
