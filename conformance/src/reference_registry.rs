//! Source-owned reference-surface registry for conformance harnesses.
//!
//! A harness may only report a runtime verdict that the registry allows for
//! its surface. Missing rows and unwired-reference pass claims fail closed.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// The root conformance registry contract embedded in the conformance crate.
pub const SOURCE_CONFORMANCE_REGISTRY_CONTRACT: &str =
    include_str!("../../artifacts/conformance_registry_contract_v1.json");

/// Runtime verdicts a conformance harness can report through the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeConformanceVerdict {
    /// The harness has a live reference and observed parity.
    Pass,
    /// The harness ran and found a real mismatch.
    Fail,
    /// The harness ran local checks but a required reference is unavailable.
    Xfail,
    /// The harness could not run because its reference surface is unavailable.
    Unavailable,
}

impl RuntimeConformanceVerdict {
    /// Stable lowercase string used in registry artifacts.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Xfail => "xfail",
            Self::Unavailable => "unavailable",
        }
    }
}

impl fmt::Display for RuntimeConformanceVerdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One registered conformance reference surface.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReferenceSurfaceRow {
    pub surface_id: String,
    pub binary: String,
    pub source_path: String,
    pub reference_family: String,
    pub reference_status: String,
    pub fail_closed_without_live_reference: bool,
    pub runtime_allowed_verdicts: Vec<RuntimeConformanceVerdict>,
    pub proof_command: String,
    pub proof_lane: String,
}

impl ReferenceSurfaceRow {
    /// Whether this row names a live independent reference.
    pub fn has_live_reference(&self) -> bool {
        self.reference_status == "live_reference_wired"
    }

    /// Whether the row explicitly allows the verdict.
    pub fn allows(&self, verdict: RuntimeConformanceVerdict) -> bool {
        self.runtime_allowed_verdicts.contains(&verdict)
    }
}

/// Successful registry admission for a harness verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceVerdictAdmission {
    pub surface_id: String,
    pub binary: String,
    pub verdict: RuntimeConformanceVerdict,
    pub reference_status: String,
}

/// One fail-closed finding from the registry e2e guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReferenceRegistryGuardFailure {
    pub surface_id: String,
    pub binary: String,
    pub reason: String,
}

/// Deterministic report emitted by the registry e2e guard command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReferenceRegistryGuardReport {
    pub schema_version: &'static str,
    pub verdict: String,
    pub checked_surface_count: usize,
    pub checked_binaries: Vec<String>,
    pub failures: Vec<ReferenceRegistryGuardFailure>,
}

impl ReferenceRegistryGuardReport {
    /// Whether the guard found no fail-closed findings.
    pub fn is_pass(&self) -> bool {
        self.failures.is_empty() && self.verdict == "pass"
    }
}

/// Fail-closed registry validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceRegistryError {
    Json(String),
    EmptySurfaceId,
    DuplicateSurfaceId(String),
    MissingSurfaceId(String),
    UnwiredReferencePass {
        surface_id: String,
        reference_status: String,
    },
    DisallowedVerdict {
        surface_id: String,
        verdict: RuntimeConformanceVerdict,
        allowed: Vec<RuntimeConformanceVerdict>,
    },
}

impl fmt::Display for ReferenceRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid conformance registry JSON: {error}"),
            Self::EmptySurfaceId => {
                formatter.write_str("conformance registry row has empty surface_id")
            }
            Self::DuplicateSurfaceId(surface_id) => {
                write!(formatter, "duplicate conformance surface_id: {surface_id}")
            }
            Self::MissingSurfaceId(surface_id) => {
                write!(
                    formatter,
                    "missing conformance registry surface_id: {surface_id}"
                )
            }
            Self::UnwiredReferencePass {
                surface_id,
                reference_status,
            } => write!(
                formatter,
                "surface {surface_id} cannot report pass while reference_status={reference_status}"
            ),
            Self::DisallowedVerdict {
                surface_id,
                verdict,
                allowed,
            } => write!(
                formatter,
                "surface {surface_id} cannot report verdict {verdict}; allowed verdicts are {allowed:?}"
            ),
        }
    }
}

impl std::error::Error for ReferenceRegistryError {}

#[derive(Debug, Deserialize)]
struct ReferenceSurfaceContract {
    reference_surfaces: Vec<ReferenceSurfaceRow>,
}

/// Queryable conformance reference-surface registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceSurfaceRegistry {
    rows: BTreeMap<String, ReferenceSurfaceRow>,
}

impl ReferenceSurfaceRegistry {
    /// Load the embedded root registry contract.
    pub fn source_contract() -> Result<Self, ReferenceRegistryError> {
        Self::from_json_str(SOURCE_CONFORMANCE_REGISTRY_CONTRACT)
    }

    /// Parse a registry contract JSON document.
    pub fn from_json_str(json: &str) -> Result<Self, ReferenceRegistryError> {
        let contract = serde_json::from_str::<ReferenceSurfaceContract>(json)
            .map_err(|error| ReferenceRegistryError::Json(error.to_string()))?;
        Self::from_rows(contract.reference_surfaces)
    }

    /// Build a registry from decoded rows.
    pub fn from_rows(rows: Vec<ReferenceSurfaceRow>) -> Result<Self, ReferenceRegistryError> {
        let mut by_id = BTreeMap::new();
        for row in rows {
            let surface_id = row.surface_id.trim().to_string();
            if surface_id.is_empty() {
                return Err(ReferenceRegistryError::EmptySurfaceId);
            }
            if by_id.insert(surface_id.clone(), row).is_some() {
                return Err(ReferenceRegistryError::DuplicateSurfaceId(surface_id));
            }
        }
        Ok(Self { rows: by_id })
    }

    /// Number of registered reference surfaces.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the registry has no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Registered surfaces in deterministic surface-id order.
    pub fn surfaces(&self) -> impl Iterator<Item = &ReferenceSurfaceRow> {
        self.rows.values()
    }

    /// Fetch one row by surface id.
    pub fn surface(
        &self,
        surface_id: &str,
    ) -> Result<&ReferenceSurfaceRow, ReferenceRegistryError> {
        self.rows
            .get(surface_id)
            .ok_or_else(|| ReferenceRegistryError::MissingSurfaceId(surface_id.to_string()))
    }

    /// Admit or reject a harness verdict for a registered surface.
    pub fn admit_runtime_verdict(
        &self,
        surface_id: &str,
        verdict: RuntimeConformanceVerdict,
    ) -> Result<ReferenceVerdictAdmission, ReferenceRegistryError> {
        let row = self.surface(surface_id)?;
        if verdict == RuntimeConformanceVerdict::Pass
            && row.fail_closed_without_live_reference
            && !row.has_live_reference()
        {
            return Err(ReferenceRegistryError::UnwiredReferencePass {
                surface_id: row.surface_id.clone(),
                reference_status: row.reference_status.clone(),
            });
        }
        if !row.allows(verdict) {
            return Err(ReferenceRegistryError::DisallowedVerdict {
                surface_id: row.surface_id.clone(),
                verdict,
                allowed: row.runtime_allowed_verdicts.clone(),
            });
        }
        Ok(ReferenceVerdictAdmission {
            surface_id: row.surface_id.clone(),
            binary: row.binary.clone(),
            verdict,
            reference_status: row.reference_status.clone(),
        })
    }

    /// Walk every registered reference surface and produce an e2e guard report.
    pub fn guard_report(&self) -> ReferenceRegistryGuardReport {
        let mut checked_binaries = Vec::new();
        let mut failures = Vec::new();

        for row in self.surfaces() {
            checked_binaries.push(row.binary.clone());

            push_if_empty(&mut failures, row, &row.binary, "missing-binary");
            push_if_empty(&mut failures, row, &row.source_path, "missing-source-path");
            push_if_empty(&mut failures, row, &row.proof_lane, "missing-proof-lane");
            push_if_empty(
                &mut failures,
                row,
                &row.proof_command,
                "missing-proof-command",
            );

            if !row.source_path.ends_with(".rs") {
                push_failure(&mut failures, row, "source-path-not-rust");
            }
            if !row.proof_command.starts_with("rch exec -- ") {
                push_failure(&mut failures, row, "proof-command-not-rch");
            }
            if !row.proof_command.contains("cargo test") {
                push_failure(&mut failures, row, "proof-command-not-cargo-test");
            }
            let bin_arg = format!("--bin {}", row.binary);
            if !row.proof_command.contains(&bin_arg) {
                push_failure(&mut failures, row, "proof-command-missing-bin");
            }
            if row.has_live_reference() && row.proof_lane.trim().is_empty() {
                push_failure(&mut failures, row, "live-reference-missing-proof-lane");
            }
            if !row.has_live_reference() {
                if !row.fail_closed_without_live_reference {
                    push_failure(&mut failures, row, "unwired-reference-not-fail-closed");
                }
                if row.allows(RuntimeConformanceVerdict::Pass) {
                    push_failure(&mut failures, row, "unwired-reference-allows-pass");
                }
                if !matches!(
                    self.admit_runtime_verdict(&row.surface_id, RuntimeConformanceVerdict::Pass),
                    Err(ReferenceRegistryError::UnwiredReferencePass { .. })
                ) {
                    push_failure(
                        &mut failures,
                        row,
                        "unwired-reference-pass-not-rejected-by-admission",
                    );
                }
            }
        }

        let verdict = if failures.is_empty() {
            "pass"
        } else {
            "fail_closed"
        };
        ReferenceRegistryGuardReport {
            schema_version: "conformance-reference-registry-guard-v1",
            verdict: verdict.to_string(),
            checked_surface_count: checked_binaries.len(),
            checked_binaries,
            failures,
        }
    }
}

fn push_if_empty(
    failures: &mut Vec<ReferenceRegistryGuardFailure>,
    row: &ReferenceSurfaceRow,
    value: &str,
    reason: &str,
) {
    if value.trim().is_empty() {
        push_failure(failures, row, reason);
    }
}

fn push_failure(
    failures: &mut Vec<ReferenceRegistryGuardFailure>,
    row: &ReferenceSurfaceRow,
    reason: &str,
) {
    failures.push(ReferenceRegistryGuardFailure {
        surface_id: row.surface_id.clone(),
        binary: row.binary.clone(),
        reason: reason.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inline_contract(reference_status: &str, allowed: &[&str]) -> String {
        let allowed = allowed
            .iter()
            .map(|verdict| format!("\"{verdict}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{
                "reference_surfaces": [
                    {{
                        "surface_id": "demo-surface",
                        "binary": "demo_conformance",
                        "source_path": "conformance/src/bin/demo_conformance.rs",
                        "reference_family": "demo",
                        "reference_status": "{reference_status}",
                        "fail_closed_without_live_reference": true,
                        "runtime_allowed_verdicts": [{allowed}],
                        "proof_command": "rch exec -- cargo test --manifest-path conformance/Cargo.toml --bin demo_conformance",
                        "proof_lane": "binary-unit"
                    }}
                ]
            }}"#
        )
    }

    #[test]
    fn source_contract_loads_registered_reference_surfaces() {
        let registry = ReferenceSurfaceRegistry::source_contract().expect("load source registry");
        assert!(
            registry.len() >= 5,
            "source registry should carry the hardened reference surfaces"
        );
        let row = registry
            .surface("otel-trace-context-propagation")
            .expect("trace-context surface row");
        assert_eq!(row.binary, "otel_trace_context_propagation_conformance");
        assert!(!row.has_live_reference());
    }

    #[test]
    fn unwired_surface_rejects_pass_before_allowed_verdict_check() {
        let registry = ReferenceSurfaceRegistry::from_json_str(&inline_contract(
            "live_reference_not_wired",
            &["pass", "xfail"],
        ))
        .expect("parse inline registry");
        let error = registry
            .admit_runtime_verdict("demo-surface", RuntimeConformanceVerdict::Pass)
            .expect_err("unwired reference must reject pass");
        assert!(matches!(
            error,
            ReferenceRegistryError::UnwiredReferencePass { .. }
        ));
    }

    #[test]
    fn xfail_is_admitted_when_registry_allows_it() {
        let registry = ReferenceSurfaceRegistry::from_json_str(&inline_contract(
            "live_reference_not_wired",
            &["xfail", "fail"],
        ))
        .expect("parse inline registry");
        let admission = registry
            .admit_runtime_verdict("demo-surface", RuntimeConformanceVerdict::Xfail)
            .expect("xfail should be admitted");
        assert_eq!(admission.surface_id, "demo-surface");
        assert_eq!(admission.verdict, RuntimeConformanceVerdict::Xfail);
    }

    #[test]
    fn live_reference_can_report_pass_when_allowed() {
        let registry = ReferenceSurfaceRegistry::from_json_str(&inline_contract(
            "live_reference_wired",
            &["pass", "fail"],
        ))
        .expect("parse inline registry");
        let admission = registry
            .admit_runtime_verdict("demo-surface", RuntimeConformanceVerdict::Pass)
            .expect("live reference pass should be admitted");
        assert_eq!(admission.reference_status, "live_reference_wired");
    }

    #[test]
    fn missing_surface_fails_closed() {
        let registry = ReferenceSurfaceRegistry::from_json_str(&inline_contract(
            "live_reference_wired",
            &["pass"],
        ))
        .expect("parse inline registry");
        let error = registry
            .admit_runtime_verdict("missing-surface", RuntimeConformanceVerdict::Pass)
            .expect_err("missing row must fail closed");
        assert_eq!(
            error,
            ReferenceRegistryError::MissingSurfaceId("missing-surface".to_string())
        );
    }

    #[test]
    fn duplicate_surface_ids_fail_closed() {
        let json = r#"{
            "reference_surfaces": [
                {
                    "surface_id": "demo-surface",
                    "binary": "demo_a",
                    "source_path": "a.rs",
                    "reference_family": "demo",
                    "reference_status": "live_reference_wired",
                    "fail_closed_without_live_reference": false,
                    "runtime_allowed_verdicts": ["pass"],
                    "proof_command": "rch exec -- cargo test --bin demo_a",
                    "proof_lane": "binary-unit"
                },
                {
                    "surface_id": "demo-surface",
                    "binary": "demo_b",
                    "source_path": "b.rs",
                    "reference_family": "demo",
                    "reference_status": "live_reference_wired",
                    "fail_closed_without_live_reference": false,
                    "runtime_allowed_verdicts": ["pass"],
                    "proof_command": "rch exec -- cargo test --bin demo_b",
                    "proof_lane": "binary-unit"
                }
            ]
        }"#;
        let error = ReferenceSurfaceRegistry::from_json_str(json)
            .expect_err("duplicate ids must fail closed");
        assert_eq!(
            error,
            ReferenceRegistryError::DuplicateSurfaceId("demo-surface".to_string())
        );
    }

    #[test]
    fn source_contract_guard_report_passes_registered_surfaces() {
        let registry = ReferenceSurfaceRegistry::source_contract().expect("load source registry");
        let report = registry.guard_report();
        assert!(
            report.is_pass(),
            "guard report failures: {:?}",
            report.failures
        );
        assert_eq!(report.checked_surface_count, registry.len());
        assert!(
            report
                .checked_binaries
                .contains(&"otel_trace_context_propagation_conformance".to_string())
        );
    }

    #[test]
    fn guard_report_fails_closed_for_live_reference_without_proof_lane() {
        let registry = ReferenceSurfaceRegistry::from_json_str(
            r#"{
                "reference_surfaces": [
                    {
                        "surface_id": "live-reference-without-proof",
                        "binary": "live_reference_without_proof_conformance",
                        "source_path": "conformance/src/bin/live_reference_without_proof_conformance.rs",
                        "reference_family": "demo",
                        "reference_status": "live_reference_wired",
                        "fail_closed_without_live_reference": false,
                        "runtime_allowed_verdicts": ["pass"],
                        "proof_command": "rch exec -- cargo test --manifest-path conformance/Cargo.toml --bin live_reference_without_proof_conformance",
                        "proof_lane": ""
                    }
                ]
            }"#,
        )
        .expect("parse inline registry");
        let report = registry.guard_report();
        assert!(!report.is_pass());
        assert_eq!(report.verdict, "fail_closed");
        assert!(report.failures.iter().any(|failure| {
            failure.surface_id == "live-reference-without-proof"
                && failure.reason == "missing-proof-lane"
        }));
    }
}
