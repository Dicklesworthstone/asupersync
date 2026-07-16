//! Reservation-aware clean-overlay runner handshake (PROOF-TRAFFIC A3).
//!
//! This module composes the existing clean-overlay planner and command builder
//! with installed RCH capability evidence. The planner still owns path and
//! reservation decisions; this wrapper owns proof admission: if the installed
//! `rch exec` surface does not support clean-overlay flags, it emits a
//! deterministic `blocked-by-capability-drift` receipt and no proof command.

use super::clean_overlay_planner::{
    CleanOverlayManifest, CleanOverlayRequest, ExcludedPath, ExclusionReason, plan_clean_overlay,
};
/// Installed clean-overlay capability evidence used by the proof-traffic handshake.
pub use super::overlay_proof_command::CleanOverlayCapability as ProofTrafficOverlayCapability;
use super::overlay_proof_command::{CLEAN_OVERLAY_CAPABILITY_BLOCKER, OverlayProofCommand};
use super::proof_traffic_receipt::ProofTrafficDecision;
use serde::{Deserialize, Serialize};

/// Stable schema version for A3 clean-overlay handshake receipts.
pub const PROOF_TRAFFIC_OVERLAY_HANDSHAKE_SCHEMA_VERSION: &str =
    "proof-traffic-clean-overlay-handshake-v1";

const FORBIDDEN_COMMAND_TOKENS: &[&str] = &[
    "|| cargo",
    "; cargo",
    "\ncargo ",
    "run cargo locally",
    "git branch",
    "git checkout -b",
    "git switch -c",
    "git worktree",
    "worktree add",
    "git clone",
    "git clean",
    "git reset",
    "rm -rf",
    "rm -r ",
    "rm -f ",
];

const NO_CLAIM_BOUNDARIES: &[&str] = &[
    "No release-readiness claim.",
    "No broad workspace-health claim.",
    "No runtime-correctness claim.",
    "No performance-improvement claim.",
    "No live RCH fleet-availability claim.",
    "No local Cargo fallback approval.",
    "No peer-owned build cancellation authority.",
    "No permission to delete files, clean worktrees, create branches, or create worktrees.",
    "No claim that peer dirt was excluded unless installed RCH clean-overlay capability evidence is supported and an admitted command completed with terminal execution evidence.",
];

/// Input to the A3 clean-overlay handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofTrafficOverlayHandshakeInput {
    /// Stable receipt/gate id, usually the bead id.
    pub gate_id: String,
    /// Clean-overlay planner request.
    pub request: CleanOverlayRequest,
    /// `CARGO_TARGET_DIR` intended for the eventual RCH proof command.
    pub target_dir: String,
    /// Installed RCH capability evidence.
    pub capability: ProofTrafficOverlayCapability,
}

impl ProofTrafficOverlayHandshakeInput {
    /// Construct a clean-overlay handshake input.
    #[must_use]
    pub fn new(
        gate_id: impl Into<String>,
        request: CleanOverlayRequest,
        target_dir: impl Into<String>,
        capability: ProofTrafficOverlayCapability,
    ) -> Self {
        Self {
            gate_id: gate_id.into(),
            request,
            target_dir: target_dir.into(),
            capability,
        }
    }
}

/// Deterministic receipt for the reservation-aware clean-overlay handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficOverlayHandshake {
    /// Stable schema version.
    pub schema_version: String,
    /// Stable receipt/gate id, usually the bead id.
    pub gate_id: String,
    /// Proof-traffic admission decision.
    pub decision: ProofTrafficDecision,
    /// `HEAD` commit the overlay is based on.
    pub head_commit: String,
    /// Cargo validation intent, recorded but not run by this receipt.
    pub command_intent: String,
    /// `CARGO_TARGET_DIR` intended for the eventual RCH proof command.
    pub target_dir: String,
    /// Normalized selected paths.
    pub selected_paths: Vec<String>,
    /// Paths the planner would overlay on `HEAD`.
    pub included_paths: Vec<String>,
    /// Paths excluded from the overlay with planner-owned reasons.
    pub excluded_paths: Vec<ExcludedPath>,
    /// Reservation patterns that justified included dirty/untracked paths.
    pub reservation_evidence: Vec<String>,
    /// Installed capability probe/version string.
    pub capability_probe_version: String,
    /// Whether installed RCH supports clean-overlay flags.
    pub clean_overlay_supported: bool,
    /// Missing clean-overlay flags.
    pub missing_flags: Vec<String>,
    /// Operator-facing capability findings.
    pub capability_findings: Vec<String>,
    /// Exact command to run, or a blocker marker when no proof is admitted.
    pub rendered_command: String,
    /// Whether the receipt admits a proof command.
    pub admitted: bool,
    /// Whether the source planner request was report-only.
    pub report_only: bool,
    /// Compact retry condition for Agent Mail / `br` handoff.
    pub retry_condition: String,
    /// Honest non-claim boundaries.
    pub no_claim_boundaries: Vec<String>,
}

impl ProofTrafficOverlayHandshake {
    /// Build a deterministic clean-overlay handshake from a caller snapshot.
    #[must_use]
    pub fn from_input(input: &ProofTrafficOverlayHandshakeInput) -> Self {
        let manifest = plan_clean_overlay(&input.request);
        let decision = classify(&manifest, &input.capability);
        let rendered_command = rendered_command(&manifest, &input.target_dir, &input.capability);
        let admitted = matches!(decision, ProofTrafficDecision::RunNow);
        let retry_condition = retry_condition(&manifest, &input.capability, decision);

        Self {
            schema_version: PROOF_TRAFFIC_OVERLAY_HANDSHAKE_SCHEMA_VERSION.to_string(),
            gate_id: input.gate_id.clone(),
            decision,
            head_commit: manifest.head_commit.clone(),
            command_intent: manifest.command_intent.clone(),
            target_dir: input.target_dir.clone(),
            selected_paths: manifest.selected_paths.clone(),
            included_paths: manifest.included_paths.clone(),
            excluded_paths: manifest.excluded_paths.clone(),
            reservation_evidence: manifest.reservation_evidence.clone(),
            capability_probe_version: input.capability.capability_probe_version().to_string(),
            clean_overlay_supported: input.capability.supports_required_flags(),
            missing_flags: input.capability.missing_flags().to_vec(),
            capability_findings: input.capability.capability_findings().to_vec(),
            rendered_command,
            admitted,
            report_only: manifest.report_only,
            retry_condition,
            no_claim_boundaries: NO_CLAIM_BOUNDARIES
                .iter()
                .map(|boundary| (*boundary).to_string())
                .collect(),
        }
    }

    /// Render a deterministic Markdown report for operators.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("## Proof-traffic clean-overlay handshake - ");
        out.push_str(self.decision.label());
        out.push_str("\n\n");
        self.push_handoff_fields(&mut out);
        out.push_str("\n### rendered_command\n```sh\n");
        out.push_str(&self.rendered_command);
        out.push_str("\n```\n\n");
        push_path_section(&mut out, "selected_paths", &self.selected_paths);
        push_path_section(&mut out, "included_paths", &self.included_paths);
        push_excluded_section(&mut out, &self.excluded_paths);
        push_path_section(&mut out, "reservation_evidence", &self.reservation_evidence);
        push_string_section(&mut out, "missing_flags", &self.missing_flags);
        push_string_section(&mut out, "capability_findings", &self.capability_findings);
        push_string_section(&mut out, "no_claim_boundaries", &self.no_claim_boundaries);
        out
    }

    /// Render the Agent Mail handoff body with structured fields first.
    #[must_use]
    pub fn agent_mail_body(&self) -> String {
        let mut out = String::new();
        out.push_str("proof_traffic_clean_overlay_handshake:\n");
        self.push_handoff_fields(&mut out);
        out
    }

    /// Render the `br comment` handoff body with structured fields first.
    #[must_use]
    pub fn br_comment_body(&self) -> String {
        let mut out = String::new();
        out.push_str("Proof-traffic clean-overlay handshake\n\n");
        self.push_handoff_fields(&mut out);
        out
    }

    /// Forbidden command tokens found in the emitted command surface.
    #[must_use]
    pub fn forbidden_command_tokens(&self) -> Vec<&'static str> {
        let surface = self.rendered_command.to_ascii_lowercase();
        FORBIDDEN_COMMAND_TOKENS
            .iter()
            .copied()
            .filter(|token| surface.contains(token))
            .collect()
    }

    /// Whether the emitted command suggests local Cargo fallback.
    #[must_use]
    pub fn uses_local_cargo_fallback(&self) -> bool {
        let surface = self.rendered_command.to_ascii_lowercase();
        surface.contains("|| cargo")
            || surface.contains("; cargo")
            || surface.contains("\ncargo ")
            || surface.contains("run cargo locally")
            || surface.contains("local fallback allowed")
            || (surface.contains("cargo") && !surface.contains("rch exec"))
    }

    fn push_handoff_fields(&self, out: &mut String) {
        out.push_str("- gate_id: `");
        out.push_str(&self.gate_id);
        out.push_str("`\n- status: `");
        out.push_str(self.decision.label());
        out.push_str("`\n- head_commit: `");
        out.push_str(&self.head_commit);
        out.push_str("`\n- command_intent: `");
        out.push_str(&self.command_intent);
        out.push_str("`\n- target_dir: `");
        out.push_str(&self.target_dir);
        out.push_str("`\n- clean_overlay_supported: `");
        out.push_str(if self.clean_overlay_supported {
            "true"
        } else {
            "false"
        });
        out.push_str("`\n- capability_probe_version: `");
        out.push_str(&self.capability_probe_version);
        out.push_str("`\n- admitted: `");
        out.push_str(if self.admitted { "true" } else { "false" });
        out.push_str("`\n- report_only: `");
        out.push_str(if self.report_only { "true" } else { "false" });
        out.push_str("`\n- retry_condition: ");
        out.push_str(&self.retry_condition);
        out.push_str("\n- selected_paths: `");
        out.push_str(&self.selected_paths.join(","));
        out.push_str("`\n- included_paths: `");
        out.push_str(&self.included_paths.join(","));
        out.push_str("`\n- excluded_paths: `");
        out.push_str(
            &self
                .excluded_paths
                .iter()
                .map(|excluded| format!("{}:{}", excluded.path, exclusion_label(excluded.reason)))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("`\n- reservation_evidence: `");
        out.push_str(&self.reservation_evidence.join(","));
        out.push_str("`\n- missing_flags: `");
        out.push_str(&self.missing_flags.join(","));
        out.push_str("`\n- capability_findings: `");
        out.push_str(&self.capability_findings.join(" | "));
        out.push_str("`\n- rendered_command: `");
        out.push_str(&self.rendered_command);
        out.push_str("`\n- no_claim_boundaries: `");
        out.push_str(&self.no_claim_boundaries.join(" | "));
        out.push_str(
            "`\n- terminal_execution_evidence: `none; pre-execution admission receipt only`",
        );
        out.push_str("\n- rch_worker_or_refusal: `");
        out.push_str(if self.admitted {
            "not recorded; pre-execution admission receipt only"
        } else {
            self.decision.label()
        });
        out.push_str("`\n- dirty_frontier: `");
        out.push_str(
            if self
                .excluded_paths
                .iter()
                .any(|excluded| excluded.reason == ExclusionReason::PeerDirtyUnselected)
            {
                "peer-dirty observed; no command admitted and no exclusion claim"
            } else if self.admitted {
                "owned/clean selected frontier at admission; execution not attested"
            } else {
                "no peer-dirty exclusion claim; command not admitted"
            },
        );
        out.push_str("`\n- rollback_action: `leave peer dirt unstaged; refresh evidence and rerun capability-gated handshake`");
        out.push_str("\n- local_cargo_fallback_allowed: `false`\n");
        out.push_str("- peer_build_cancellation_allowed: `false`\n");
        out.push_str("- branch_or_worktree_allowed: `false`\n");
        out.push_str("- file_deletion_allowed: `false`\n");
    }
}

fn classify(
    manifest: &CleanOverlayManifest,
    capability: &ProofTrafficOverlayCapability,
) -> ProofTrafficDecision {
    if !capability.supports_required_flags() {
        return ProofTrafficDecision::BlockedByCapabilityDrift;
    }
    if manifest.report_only {
        return ProofTrafficDecision::ReportOnly;
    }
    if manifest.blocked {
        return if manifest
            .excluded_paths
            .iter()
            .any(|excluded| excluded.reason == ExclusionReason::PeerDirtyUnselected)
        {
            ProofTrafficDecision::BlockedByPeer
        } else {
            ProofTrafficDecision::ParkRerunRequired
        };
    }
    if manifest.selected_paths.is_empty() {
        return ProofTrafficDecision::ParkRerunRequired;
    }
    ProofTrafficDecision::RunNow
}

fn rendered_command(
    manifest: &CleanOverlayManifest,
    target_dir: &str,
    capability: &ProofTrafficOverlayCapability,
) -> String {
    if !capability.supports_required_flags() {
        return CLEAN_OVERLAY_CAPABILITY_BLOCKER.to_string();
    }
    if manifest.report_only {
        return "# REPORT-ONLY: clean-overlay handshake dry run; no proof command emitted"
            .to_string();
    }
    OverlayProofCommand::from_manifest_with_target(manifest, target_dir, capability)
        .rendered_command()
}

fn retry_condition(
    manifest: &CleanOverlayManifest,
    capability: &ProofTrafficOverlayCapability,
    decision: ProofTrafficDecision,
) -> String {
    match decision {
        ProofTrafficDecision::RunNow => {
            "none; selected paths are reserved and installed clean-overlay capability is supported"
                .to_string()
        }
        ProofTrafficDecision::ReportOnly => "report-only; no proof command emitted".to_string(),
        ProofTrafficDecision::BlockedByCapabilityDrift => {
            if capability.capability_probe_version().is_empty() {
                "rerun after capturing a fresh non-empty installed RCH capability probe version and rch exec --help output"
                    .to_string()
            } else {
                let missing = capability.missing_flags().join(",");
                format!("rerun after installed RCH exposes clean-overlay flags [{missing}]")
            }
        }
        ProofTrafficDecision::BlockedByPeer => {
            "rerun after peer-dirty unselected paths are cleared or selected by their owner"
                .to_string()
        }
        ProofTrafficDecision::ParkRerunRequired => {
            if manifest.selected_paths.is_empty() {
                "rerun with at least one selected path".to_string()
            } else if manifest
                .excluded_paths
                .iter()
                .any(|excluded| excluded.reason == ExclusionReason::DeletedSelectionRefused)
            {
                "rerun with a non-deleted selected path; clean-overlay cannot prove removals"
                    .to_string()
            } else {
                "rerun after selected dirty/untracked paths have exclusive self reservations"
                    .to_string()
            }
        }
        ProofTrafficDecision::QueueWait | ProofTrafficDecision::RemoteRequiredRefused => {
            "not used by clean-overlay handshake".to_string()
        }
    }
}

fn push_path_section(out: &mut String, title: &str, paths: &[String]) {
    out.push_str(&format!("### {title} ({})\n", paths.len()));
    if paths.is_empty() {
        out.push_str("- _none_\n");
    } else {
        for path in paths {
            out.push_str("- `");
            out.push_str(path);
            out.push_str("`\n");
        }
    }
    out.push('\n');
}

fn push_string_section(out: &mut String, title: &str, values: &[String]) {
    out.push_str(&format!("### {title} ({})\n", values.len()));
    if values.is_empty() {
        out.push_str("- _none_\n");
    } else {
        for value in values {
            out.push_str("- ");
            out.push_str(value);
            out.push('\n');
        }
    }
    out.push('\n');
}

fn push_excluded_section(out: &mut String, excluded_paths: &[ExcludedPath]) {
    out.push_str(&format!("### excluded_paths ({})\n", excluded_paths.len()));
    if excluded_paths.is_empty() {
        out.push_str("- _none_\n");
    } else {
        for excluded in excluded_paths {
            out.push_str("- `");
            out.push_str(&excluded.path);
            out.push_str("` - ");
            out.push_str(exclusion_label(excluded.reason));
            out.push('\n');
        }
    }
    out.push('\n');
}

const fn exclusion_label(reason: ExclusionReason) -> &'static str {
    match reason {
        ExclusionReason::PeerDirtyUnselected => "peer-dirty-unselected",
        ExclusionReason::UnreservedSelection => "unreserved-selection",
        ExclusionReason::DeletedSelectionRefused => "deleted-selection-refused",
    }
}
