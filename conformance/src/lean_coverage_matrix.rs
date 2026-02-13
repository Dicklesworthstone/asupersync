//! Lean proof coverage ontology and machine-readable matrix model.
//!
//! This module defines a deterministic schema for tracking Lean proof coverage
//! across semantic rules, invariants, refinement obligations, and operational
//! CI gates.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

/// Stable schema version for Lean coverage matrix artifacts.
pub const LEAN_COVERAGE_SCHEMA_VERSION: &str = "1.0.0";

/// Canonical row types in the Lean coverage matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageRowType {
    /// A small-step semantic rule or constructor-level proof obligation.
    SemanticRule,
    /// A project invariant (for example, no obligation leaks).
    Invariant,
    /// A Rust-to-Lean refinement obligation.
    RefinementObligation,
    /// A CI/operational gate proving proof health in automation.
    OperationalGate,
}

/// Canonical status model for Lean coverage rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageStatus {
    /// Work not started.
    NotStarted,
    /// Work actively in progress.
    InProgress,
    /// Work is blocked by a known blocker.
    Blocked,
    /// The proof is complete and locally validated.
    Proven,
    /// Proven and validated in CI automation.
    ValidatedInCi,
}

/// Deterministic blocker taxonomy codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockerCode {
    /// Missing helper lemma(s) or dependency theorem(s).
    #[serde(rename = "BLK_PROOF_MISSING_LEMMA")]
    ProofMissingLemma,
    /// Proof shape/tactic path mismatch after model evolution.
    #[serde(rename = "BLK_PROOF_SHAPE_MISMATCH")]
    ProofShapeMismatch,
    /// Lean model/spec is incomplete or inconsistent with intended semantics.
    #[serde(rename = "BLK_MODEL_GAP")]
    ModelGap,
    /// Rust runtime behavior diverges from formal model assumptions.
    #[serde(rename = "BLK_IMPL_DIVERGENCE")]
    ImplDivergence,
    /// CI/build/toolchain infrastructure prevents validation.
    #[serde(rename = "BLK_TOOLCHAIN_FAILURE")]
    ToolchainFailure,
    /// External dependency or sequencing blocker.
    #[serde(rename = "BLK_EXTERNAL_DEPENDENCY")]
    ExternalDependency,
}

/// Optional blocker payload when a row is blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageBlocker {
    /// Deterministic blocker code.
    pub code: BlockerCode,
    /// Human-readable blocker detail.
    pub detail: String,
}

/// Evidence record for a coverage row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageEvidence {
    /// Lean theorem name associated with this row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theorem_name: Option<String>,
    /// Source file containing theorem/proof evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// 1-based source line for the theorem/proof evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Path to a generated proof artifact (log/manifest/report).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_artifact: Option<String>,
    /// CI job identifier that validated the proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci_job: Option<String>,
    /// Reviewer identity for human validation/sign-off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
}

impl CoverageEvidence {
    fn is_empty(&self) -> bool {
        self.theorem_name.is_none()
            && self.file_path.is_none()
            && self.line.is_none()
            && self.proof_artifact.is_none()
            && self.ci_job.is_none()
            && self.reviewer.is_none()
    }
}

/// One row in the Lean proof coverage matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRow {
    /// Stable row identifier (for example, `sem.cancel.request.wf`).
    pub id: String,
    /// Human-readable row title.
    pub title: String,
    /// Row type classification.
    pub row_type: CoverageRowType,
    /// Current coverage status.
    pub status: CoverageStatus,
    /// Free-form row description.
    pub description: String,
    /// Optional owner for coordination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Stable IDs this row depends on.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Optional tags for query/filter.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional blocker payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker: Option<CoverageBlocker>,
    /// Proof/CI evidence for this row.
    #[serde(default)]
    pub evidence: Vec<CoverageEvidence>,
}

/// Top-level Lean proof coverage matrix artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeanCoverageMatrix {
    /// Schema version for compatibility and migrations.
    pub schema_version: String,
    /// Matrix identifier for downstream references.
    pub matrix_id: String,
    /// Matrix title.
    pub title: String,
    /// Scope narrative and interpretation guidance.
    pub scope: String,
    /// Coverage rows.
    pub rows: Vec<CoverageRow>,
}

impl LeanCoverageMatrix {
    /// Parse a matrix from JSON text.
    pub fn from_json_str(input: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(input)
    }

    /// Serialize the matrix into pretty-printed JSON.
    pub fn to_pretty_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Validate matrix structure and status/evidence consistency.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.schema_version != LEAN_COVERAGE_SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be '{LEAN_COVERAGE_SCHEMA_VERSION}' (got '{}')",
                self.schema_version
            ));
        }

        if !is_valid_stable_id(&self.matrix_id) {
            errors.push(format!(
                "matrix_id '{}' must be lowercase stable-id format [a-z0-9._-]",
                self.matrix_id
            ));
        }

        let mut ids = HashSet::new();
        let mut all_ids = BTreeSet::new();
        for row in &self.rows {
            if !is_valid_stable_id(&row.id) {
                errors.push(format!(
                    "row '{}' has invalid id format; use lowercase stable-id [a-z0-9._-]",
                    row.title
                ));
            }
            if !ids.insert(row.id.clone()) {
                errors.push(format!("duplicate row id '{}'", row.id));
            }
            all_ids.insert(row.id.clone());
        }

        for row in &self.rows {
            for dep in &row.depends_on {
                if !all_ids.contains(dep) {
                    errors.push(format!(
                        "row '{}' depends_on missing row id '{}'",
                        row.id, dep
                    ));
                }
                if dep == &row.id {
                    errors.push(format!("row '{}' cannot depend on itself", row.id));
                }
            }
            if let Some(blocker) = &row.blocker {
                if blocker.detail.trim().is_empty() {
                    errors.push(format!(
                        "row '{}' has blocker '{:?}' with empty detail",
                        row.id, blocker.code
                    ));
                }
            }

            match row.status {
                CoverageStatus::Blocked => {
                    if row.blocker.is_none() {
                        errors.push(format!(
                            "row '{}' is blocked but missing blocker payload",
                            row.id
                        ));
                    }
                }
                CoverageStatus::Proven | CoverageStatus::ValidatedInCi => {
                    if row.evidence.is_empty() {
                        errors.push(format!(
                            "row '{}' is {:?} but has no evidence entries",
                            row.id, row.status
                        ));
                    }
                    if row.blocker.is_some() {
                        errors.push(format!(
                            "row '{}' is {:?} but still has blocker payload",
                            row.id, row.status
                        ));
                    }
                }
                CoverageStatus::NotStarted | CoverageStatus::InProgress => {
                    if row.blocker.is_some() {
                        errors.push(format!(
                            "row '{}' has blocker payload but status is {:?}",
                            row.id, row.status
                        ));
                    }
                }
            }

            if row.status == CoverageStatus::ValidatedInCi
                && !row.evidence.iter().any(|e| e.ci_job.is_some())
            {
                errors.push(format!(
                    "row '{}' is validated-in-ci but has no ci_job in evidence",
                    row.id
                ));
            }

            for (index, evidence) in row.evidence.iter().enumerate() {
                if evidence.is_empty() {
                    errors.push(format!(
                        "row '{}' evidence[{index}] is empty; at least one evidence field is required",
                        row.id
                    ));
                }
                if evidence.line.is_some() && evidence.file_path.is_none() {
                    errors.push(format!(
                        "row '{}' evidence[{index}] has line but missing file_path",
                        row.id
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn is_valid_stable_id(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    id.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BlockerCode, CoverageBlocker, CoverageEvidence, CoverageRow, CoverageRowType,
        CoverageStatus, LeanCoverageMatrix, LEAN_COVERAGE_SCHEMA_VERSION,
    };

    fn valid_matrix() -> LeanCoverageMatrix {
        LeanCoverageMatrix {
            schema_version: LEAN_COVERAGE_SCHEMA_VERSION.to_string(),
            matrix_id: "lean.coverage.v1".to_string(),
            title: "Lean Coverage".to_string(),
            scope: "Spec to implementation coverage".to_string(),
            rows: vec![
                CoverageRow {
                    id: "sem.cancel.request.wf".to_string(),
                    title: "cancel request preserves wf".to_string(),
                    row_type: CoverageRowType::SemanticRule,
                    status: CoverageStatus::ValidatedInCi,
                    description: "requestCancel branch preserves well-formedness".to_string(),
                    owner: Some("MagentaBridge".to_string()),
                    depends_on: vec![],
                    tags: vec!["cancel".to_string()],
                    blocker: None,
                    evidence: vec![CoverageEvidence {
                        theorem_name: Some("requestCancel_preserves_wf".to_string()),
                        file_path: Some("formal/lean/Asupersync.lean".to_string()),
                        line: Some(2321),
                        proof_artifact: Some("target/lean-e2e/manifest.json".to_string()),
                        ci_job: Some("proof-checks".to_string()),
                        reviewer: Some("FoggyMarsh".to_string()),
                    }],
                },
                CoverageRow {
                    id: "inv.no_obligation_leak".to_string(),
                    title: "No obligation leaks".to_string(),
                    row_type: CoverageRowType::Invariant,
                    status: CoverageStatus::Blocked,
                    description: "No leaked obligations after close".to_string(),
                    owner: None,
                    depends_on: vec!["sem.cancel.request.wf".to_string()],
                    tags: vec![],
                    blocker: Some(CoverageBlocker {
                        code: BlockerCode::ProofMissingLemma,
                        detail: "Need helper lemma for resolve obligation map".to_string(),
                    }),
                    evidence: vec![],
                },
            ],
        }
    }

    #[test]
    fn valid_matrix_passes_validation() {
        let matrix = valid_matrix();
        assert!(matrix.validate().is_ok());
    }

    #[test]
    fn duplicate_ids_fail_validation() {
        let mut matrix = valid_matrix();
        matrix.rows[1].id = matrix.rows[0].id.clone();
        let errors = matrix.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("duplicate row id")));
    }

    #[test]
    fn missing_dependency_fails_validation() {
        let mut matrix = valid_matrix();
        matrix.rows[1].depends_on = vec!["missing.row.id".to_string()];
        let errors = matrix.validate().expect_err("should fail");
        assert!(errors
            .iter()
            .any(|e| e.contains("depends_on missing row id")));
    }

    #[test]
    fn blocked_requires_blocker_payload() {
        let mut matrix = valid_matrix();
        matrix.rows[1].blocker = None;
        let errors = matrix.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("missing blocker payload")));
    }

    #[test]
    fn validated_in_ci_requires_ci_job_evidence() {
        let mut matrix = valid_matrix();
        matrix.rows[0].evidence[0].ci_job = None;
        let errors = matrix.validate().expect_err("should fail");
        assert!(errors
            .iter()
            .any(|e| e.contains("validated-in-ci but has no ci_job")));
    }
}
