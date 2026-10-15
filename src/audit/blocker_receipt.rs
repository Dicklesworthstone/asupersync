//! Dirty-peer blocker receipt schema and operator report (PROOF-ORCH A2).
//!
//! The A1 [`clean_overlay_planner`](super::clean_overlay_planner) decides which
//! paths a clean-overlay RCH proof run is permitted to prove and emits a
//! [`CleanOverlayManifest`]. This module is the documented downstream consumer:
//! it turns that manifest plus the run's outcome into a machine-readable
//! [`BlockerReceipt`] and a deterministic operator Markdown report suitable for
//! pasting into Agent Mail or a `br` comment.
//!
//! The taxonomy is **fail-closed**: a blocked overlay can never report a green
//! proof, and a fresh RCH heartbeat with stalled build progress
//! ([`ProofAttemptOutcome::StaleProgress`]) is never treated as success. The
//! report states honest no-claim boundaries and never implies broad workspace
//! health — only the listed overlay paths are attested.

use super::clean_overlay_planner::{CleanOverlayManifest, ExclusionReason};
use serde::{Deserialize, Serialize};

/// Fail-closed outcome taxonomy for a clean-overlay proof attempt.
///
/// The variants are ordered from least to most trustworthy, but trust is decided
/// by [`Self::is_proof_success`], not ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofAttemptOutcome {
    /// The enforced overlay refused to proceed (peer dirt outside the overlay,
    /// unreserved selected dirt, or a selected deletion). The proof never ran.
    Blocked,
    /// The proof command executed but failed (compile / clippy / test failure).
    Failed,
    /// The RCH heartbeat is fresh but build progress is stale — the run is not
    /// making forward progress. This is **not** a successful proof.
    StaleProgress,
    /// The proof ran to completion and was green for the selected overlay.
    Green,
}

impl ProofAttemptOutcome {
    /// Whether this outcome attests a successful, trustworthy proof.
    ///
    /// Only [`Green`](Self::Green) proves the slice. In particular
    /// [`StaleProgress`](Self::StaleProgress) is **not** success: a fresh RCH
    /// heartbeat over a stalled build must never be read as a green proof.
    #[must_use]
    pub const fn is_proof_success(self) -> bool {
        matches!(self, Self::Green)
    }

    /// Whether this outcome is a hard block — the proof could not run at all, so
    /// no claim about the slice is possible.
    #[must_use]
    pub const fn is_blocked(self) -> bool {
        matches!(self, Self::Blocked)
    }

    /// Stable lowercase machine label for the outcome.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Failed => "failed",
            Self::StaleProgress => "stale_progress",
            Self::Green => "green",
        }
    }

    /// One-line operator-facing status line, always honest about non-green
    /// outcomes (never implies a proof when there was none).
    #[must_use]
    const fn status_sentence(self) -> &'static str {
        match self {
            Self::Blocked => "BLOCKED — the overlay refused to run; this attests no proof.",
            Self::Failed => "FAILED — the proof command failed; not a green proof.",
            Self::StaleProgress => {
                "STALE-PROGRESS — RCH heartbeat fresh but build progress stalled; NOT a green proof."
            }
            Self::Green => "GREEN — the selected overlay proved clean (these paths only).",
        }
    }
}

/// RCH worker / build identifiers for a proof attempt, when the lane surfaced
/// them. Absent ids render as `n/a` and never fabricate evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchExecutionEvidence {
    /// Identifier of the RCH worker that ran (or would run) the proof, if known.
    pub worker_id: Option<String>,
    /// Identifier of the RCH build/job, if known.
    pub build_id: Option<String>,
}

impl RchExecutionEvidence {
    /// Construct execution evidence from optional worker and build identifiers.
    #[must_use]
    pub fn new(worker_id: Option<String>, build_id: Option<String>) -> Self {
        Self {
            worker_id,
            build_id,
        }
    }
}

/// Machine-readable receipt for a clean-overlay proof attempt.
///
/// Records exactly what was proved (or refused), against which paths, with what
/// reservation evidence, under which fail-closed outcome.
///
/// Built from an A1 [`CleanOverlayManifest`] via [`Self::from_manifest`]. Every
/// list field inherits the manifest's deterministic sorted ordering, so the
/// receipt (and its rendered report) are byte-stable for the same inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockerReceipt {
    /// The `HEAD` commit the overlay was based on.
    pub head_commit: String,
    /// The recorded RCH command intent (recorded, not necessarily run).
    pub command_intent: String,
    /// The fail-closed outcome of the attempt.
    pub outcome: ProofAttemptOutcome,
    /// Paths that overlaid `HEAD`, sorted and de-duplicated (from the manifest).
    pub included_paths: Vec<String>,
    /// Excluded paths with their reasons, sorted (from the manifest).
    pub excluded_paths: Vec<super::clean_overlay_planner::ExcludedPath>,
    /// Reservation patterns that justified an inclusion (from the manifest).
    pub reservation_evidence: Vec<String>,
    /// RCH worker/build identifiers, when available.
    pub execution: RchExecutionEvidence,
    /// Whether the overlay was a report-only (dry-run) manifest.
    pub report_only: bool,
    /// True when the proof used RCH exclusively with no local Cargo fallback.
    pub no_local_fallback: bool,
    /// Honest no-claim boundary statements, in the manifest's fixed order.
    pub no_claim_boundaries: Vec<String>,
}

impl BlockerReceipt {
    /// Build a receipt from an A1 manifest, the attempt `outcome`, and RCH
    /// execution evidence.
    ///
    /// **Fail-closed:** if the manifest is `blocked` (an enforced overlay refused
    /// to proceed), the outcome is forced to [`ProofAttemptOutcome::Blocked`]
    /// regardless of the `outcome` argument — a blocked overlay never ran, so it
    /// can never attest a green/failed/stale result. `no_local_fallback` records
    /// that the proof lane is RCH-only (no local Cargo fallback is permitted).
    #[must_use]
    pub fn from_manifest(
        manifest: &CleanOverlayManifest,
        outcome: ProofAttemptOutcome,
        execution: RchExecutionEvidence,
    ) -> Self {
        let outcome = if manifest.blocked {
            ProofAttemptOutcome::Blocked
        } else {
            outcome
        };
        Self {
            head_commit: manifest.head_commit.clone(),
            command_intent: manifest.command_intent.clone(),
            outcome,
            included_paths: manifest.included_paths.clone(),
            excluded_paths: manifest.excluded_paths.clone(),
            reservation_evidence: manifest.reservation_evidence.clone(),
            execution,
            report_only: manifest.report_only,
            no_local_fallback: true,
            no_claim_boundaries: manifest.no_claim_boundaries.clone(),
        }
    }

    /// Whether this receipt attests a successful proof (green, and not blocked).
    #[must_use]
    pub const fn proves_clean(&self) -> bool {
        self.outcome.is_proof_success()
    }

    /// The excluded paths attributed to unrelated peer dirt outside the overlay.
    #[must_use]
    pub fn peer_dirty_paths(&self) -> Vec<&str> {
        self.excluded_with(ExclusionReason::PeerDirtyUnselected)
    }

    /// Excluded paths matching a specific [`ExclusionReason`], in manifest order.
    #[must_use]
    pub fn excluded_with(&self, reason: ExclusionReason) -> Vec<&str> {
        self.excluded_paths
            .iter()
            .filter(|excluded| excluded.reason == reason)
            .map(|excluded| excluded.path.as_str())
            .collect()
    }

    /// Render a deterministic operator Markdown report, safe to paste into Agent
    /// Mail or a `br` comment.
    ///
    /// The report states the fail-closed outcome, the included/excluded paths
    /// with reasons, reservation evidence, RCH worker/build ids, the
    /// no-local-fallback note, and the honest no-claim boundaries. It attests
    /// only the listed overlay paths and never implies broad workspace health.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("## Clean-overlay proof receipt — ");
        out.push_str(self.outcome.label());
        out.push_str("\n\n");

        out.push_str("- Command intent: `");
        out.push_str(&self.command_intent);
        out.push_str("`\n- HEAD: `");
        out.push_str(&self.head_commit);
        out.push_str("`\n- Mode: ");
        out.push_str(if self.report_only {
            "report-only (dry run)"
        } else {
            "enforced"
        });
        out.push('\n');
        out.push_str("- Lane: ");
        out.push_str(if self.no_local_fallback {
            "RCH-only; no local Cargo fallback"
        } else {
            "RCH with local fallback"
        });
        out.push_str("\n- RCH worker: ");
        out.push_str(self.execution.worker_id.as_deref().unwrap_or("n/a"));
        out.push_str(" · build: ");
        out.push_str(self.execution.build_id.as_deref().unwrap_or("n/a"));
        out.push_str("\n- Proof status: ");
        out.push_str(self.outcome.status_sentence());
        out.push_str("\n\n");

        push_path_section(&mut out, "Included overlay paths", &self.included_paths);

        out.push_str(&format!(
            "### Excluded paths ({})\n",
            self.excluded_paths.len()
        ));
        if self.excluded_paths.is_empty() {
            out.push_str("- _none_\n");
        } else {
            for excluded in &self.excluded_paths {
                out.push_str("- `");
                out.push_str(&excluded.path);
                out.push_str("` — ");
                out.push_str(exclusion_label(excluded.reason));
                out.push('\n');
            }
        }
        out.push('\n');

        push_path_section(&mut out, "Reservation evidence", &self.reservation_evidence);

        out.push_str("### No-claim boundaries\n");
        if self.no_claim_boundaries.is_empty() {
            out.push_str("- _none recorded_\n");
        } else {
            for boundary in &self.no_claim_boundaries {
                out.push_str("- ");
                out.push_str(boundary);
                out.push('\n');
            }
        }
        out
    }
}

/// Append a `### <title> (N)` section listing back-ticked paths, or `_none_`.
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

/// Operator-facing label for an [`ExclusionReason`].
const fn exclusion_label(reason: ExclusionReason) -> &'static str {
    match reason {
        ExclusionReason::PeerDirtyUnselected => "peer-dirty (unselected)",
        ExclusionReason::UnreservedSelection => "unreserved selection (no held lease)",
        ExclusionReason::DeletedSelectionRefused => {
            "deleted selection (an overlay cannot prove a removal)"
        }
    }
}
