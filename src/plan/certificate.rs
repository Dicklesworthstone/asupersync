//! Plan rewrite certificates with stable hashing.
//!
//! Certificates attest that a sequence of rewrite steps transformed a plan DAG
//! from one state to another. The hash function is deterministic and stable
//! across Rust versions (FNV-1a, not `DefaultHasher`).

use super::rewrite::{RewritePolicy, RewriteReport, RewriteRule, RewriteStep};
use super::{PlanDag, PlanId, PlanNode};

// ---------------------------------------------------------------------------
// Stable hashing (FNV-1a 64-bit)
// ---------------------------------------------------------------------------

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// Deterministic 64-bit hash of a plan DAG.
///
/// Uses FNV-1a for cross-version stability. The hash covers node structure,
/// labels, children order, durations, and the root pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlanHash(u64);

impl PlanHash {
    /// Returns the raw 64-bit hash value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Compute the stable hash of a plan DAG.
    #[must_use]
    pub fn of(dag: &PlanDag) -> Self {
        let mut h = FNV_OFFSET;
        // Hash node count as a frame marker.
        h = fnv_u64(h, dag.nodes.len() as u64);
        for node in &dag.nodes {
            h = hash_node(h, node);
        }
        // Hash root presence and value.
        match dag.root {
            Some(id) => {
                h = fnv_u8(h, 1);
                h = fnv_u64(h, id.index() as u64);
            }
            None => {
                h = fnv_u8(h, 0);
            }
        }
        Self(h)
    }
}

fn fnv_u8(h: u64, byte: u8) -> u64 {
    (h ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
}

fn fnv_u64(mut h: u64, val: u64) -> u64 {
    for &byte in &val.to_le_bytes() {
        h = fnv_u8(h, byte);
    }
    h
}

fn fnv_bytes(mut h: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        h = fnv_u8(h, byte);
    }
    h
}

fn hash_node(mut h: u64, node: &PlanNode) -> u64 {
    match node {
        PlanNode::Leaf { label } => {
            h = fnv_u8(h, 0); // discriminant
            h = fnv_u64(h, label.len() as u64);
            h = fnv_bytes(h, label.as_bytes());
        }
        PlanNode::Join { children } => {
            h = fnv_u8(h, 1);
            h = fnv_u64(h, children.len() as u64);
            for child in children {
                h = fnv_u64(h, child.index() as u64);
            }
        }
        PlanNode::Race { children } => {
            h = fnv_u8(h, 2);
            h = fnv_u64(h, children.len() as u64);
            for child in children {
                h = fnv_u64(h, child.index() as u64);
            }
        }
        PlanNode::Timeout { child, duration } => {
            h = fnv_u8(h, 3);
            h = fnv_u64(h, child.index() as u64);
            h = fnv_u64(h, duration.as_nanos() as u64);
        }
    }
    h
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
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let mut h = FNV_OFFSET;
        h = fnv_u64(h, u64::from(self.version.number()));
        h = fnv_u8(h, self.policy as u8);
        h = fnv_u64(h, self.before_hash.value());
        h = fnv_u64(h, self.after_hash.value());
        h = fnv_u64(h, self.steps.len() as u64);
        for step in &self.steps {
            h = fnv_u8(h, step.rule as u8);
            h = fnv_u64(h, step.before.index() as u64);
            h = fnv_u64(h, step.after.index() as u64);
        }
        h
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
    HashMismatch {
        /// Hash recorded in the certificate.
        expected: u64,
        /// Hash computed from the DAG.
        actual: u64,
    },
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
        RewriteRule::DedupRaceJoin => verify_dedup_race_join_result(idx, step, policy, dag),
    }
}

/// Verify that a `DedupRaceJoin` step produced valid structure:
/// the `after` node should be `Join[shared, Race[...remaining]]`.
fn verify_dedup_race_join_result(
    idx: usize,
    step: &CertifiedStep,
    _policy: RewritePolicy,
    dag: &PlanDag,
) -> Result<(), StepVerifyError> {
    let after_node = dag
        .node(step.after)
        .ok_or(StepVerifyError::MissingAfterNode {
            step: idx,
            node: step.after,
        })?;

    // After node must be a Join.
    let PlanNode::Join { children } = after_node else {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Join node after DedupRaceJoin",
        });
    };

    if children.len() != 2 {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Join with exactly 2 children (shared + race)",
        });
    }

    // One child should be the shared leaf/node, and the other a Race.
    let has_race_child = children.iter().any(|child_id| {
        dag.node(*child_id)
            .is_some_and(|n| matches!(n, PlanNode::Race { .. }))
    });

    if !has_race_child {
        return Err(StepVerifyError::InvalidAfterShape {
            step: idx,
            expected: "Join containing a Race child after DedupRaceJoin",
        });
    }

    Ok(())
}

/// Verify that a certificate's `after_hash` matches the given (post-rewrite) DAG.
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
            expected: cert.after_hash.value(),
            actual: actual.value(),
        });
    }
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
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::time::Duration;

    fn init_test() {
        init_test_logging();
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
            .apply_rewrites_certified(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);

        assert_eq!(report.steps().len(), 1);
        assert_eq!(cert.steps.len(), 1);
        assert_eq!(cert.version, CertificateVersion::CURRENT);
        assert_eq!(cert.policy, RewritePolicy::Conservative);
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
            .apply_rewrites_certified(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);

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
            .apply_rewrites_certified(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);

        // Mutate the DAG after certification.
        dag.leaf("extra");

        let result = verify(&cert, &dag);
        assert!(result.is_err());
        assert!(matches!(result, Err(VerifyError::HashMismatch { .. })));
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
            .apply_rewrites_certified(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);

        let fp1 = cert.fingerprint();
        let fp2 = cert.fingerprint();
        assert_eq!(fp1, fp2);
        assert_ne!(fp1, 0);
    }

    #[test]
    fn version_mismatch_detected() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let (_, mut cert) = dag
            .apply_rewrites_certified(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);
        cert.version = CertificateVersion(99);

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
            .apply_rewrites_certified(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);

        assert!(verify_steps(&cert, &dag).is_ok());
    }

    #[test]
    fn verify_steps_rejects_missing_after_node() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::Conservative,
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: 1,
            after_node_count: 1,
            steps: vec![CertifiedStep {
                rule: RewriteRule::DedupRaceJoin,
                before: PlanId::new(0),
                after: PlanId::new(999),
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
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::Conservative,
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: 1,
            after_node_count: 1,
            steps: vec![CertifiedStep {
                rule: RewriteRule::DedupRaceJoin,
                before: PlanId::new(0),
                after: PlanId::new(0), // points to a Leaf, not a Join
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
    fn verify_steps_identity_passes() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);

        assert!(cert.is_identity());
        assert!(verify_steps(&cert, &dag).is_ok());
    }
}
