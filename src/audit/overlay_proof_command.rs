//! Clean-overlay RCH validation command builder (PROOF-ORCH A3).
//!
//! The A1 [`clean_overlay_planner`](super::clean_overlay_planner) decides which
//! paths a focused proof run is permitted to overlay on `HEAD`; the A2
//! [`blocker_receipt`](super::blocker_receipt) turns the run's *outcome* into an
//! operator receipt. This module is the missing middle: the deterministic
//! *runner* that turns an admitted [`CleanOverlayManifest`] into the **exact RCH
//! command** that validates the slice, scoped so that unrelated peer dirt is
//! provably never fed to Cargo.
//!
//! The clean-overlay guarantee is mechanical, not aspirational: RCH normally
//! syncs the whole working tree, which would drag a peer's broken edit into the
//! build and fail (or stall) the proof before the intended slice is ever
//! compiled. [`OverlayProofCommand`] emits an *overlay-scoped* invocation that
//! uploads only the manifest's included paths on top of `HEAD`, so an excluded
//! poison path — even one that would fail compilation — can never reach the
//! compiler.
//!
//! # Invariants
//!
//! * **Fail closed.** A blocked manifest yields a command with `admitted=false`
//!   and emits *no* proof invocation; the run cannot accidentally report green.
//! * **RCH-only.** The validation command is always routed through `rch exec`.
//!   [`OverlayProofCommand::uses_local_cargo_fallback`] is `false` by
//!   construction, and the failure-reproduction guidance never suggests running
//!   Cargo locally.
//! * **No destructive orchestration.** The builder performs no I/O. It never
//!   constructs a branch, worktree, scratch clone, or deletion;
//!   [`OverlayProofCommand::forbidden_operations`] scans its own rendered
//!   command surface and is empty by construction.
//! * **Deterministic.** Every field inherits the manifest's sorted ordering, so
//!   the rendered command, reproduction command, and report are byte-stable for
//!   the same inputs.

use super::clean_overlay_planner::{CleanOverlayManifest, ExcludedPath, ExclusionReason};
use serde::{Deserialize, Serialize};

/// Default `CARGO_TARGET_DIR` for clean-overlay proof runs. A dedicated dir keeps
/// the warm RCH cache from colliding with ad-hoc local builds.
pub const DEFAULT_TARGET_DIR: &str = "/data/tmp/rch_target_asupersync_test";

/// Forbidden orchestration tokens. A clean-overlay run is RCH-only and
/// non-destructive: it never branches, clones, makes a worktree, or deletes.
/// Each entry is matched as a substring against the full rendered command
/// surface (command + reproduction command).
const FORBIDDEN_TOKENS: &[&str] = &[
    "git branch",
    "git worktree",
    "worktree add",
    "git clone",
    "git clean",
    "git reset",
    "git checkout -b",
    "rm -rf",
    "rm -r ",
    "rm -f ",
];

/// A deterministic, overlay-scoped RCH validation command built from an admitted
/// clean-overlay manifest.
///
/// Build it with [`Self::from_manifest`]. When the source manifest is blocked
/// (an enforced overlay refused to proceed), the command is *not admitted*: it
/// records the fail-closed context but emits no Cargo invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayProofCommand {
    /// The `HEAD` commit the overlay is based on.
    pub head_commit: String,
    /// `CARGO_TARGET_DIR` the RCH run uses.
    pub target_dir: String,
    /// The Cargo validation intent, e.g. `cargo test --test foo`.
    pub validation_intent: String,
    /// Selected paths the request asked for (from the manifest), sorted.
    pub selected_paths: Vec<String>,
    /// Overlay paths uploaded on top of `HEAD` (the manifest's included paths),
    /// sorted. These — and only these — local edits reach the build.
    pub overlay_paths: Vec<String>,
    /// Paths excluded from the overlay with their reasons (from the manifest).
    pub excluded_paths: Vec<ExcludedPath>,
    /// Reservation patterns that justified an inclusion (from the manifest).
    pub reservation_evidence: Vec<String>,
    /// Whether an enforced proof invocation is admitted. `false` when the
    /// manifest blocked or was report-only — no proof command is emitted.
    pub admitted: bool,
    /// Whether the source manifest was a report-only (dry-run) manifest.
    pub report_only: bool,
    /// Number of paths that failed closed (peer dirt, unreserved, deleted).
    pub fail_closed_path_count: usize,
    /// Honest no-claim boundary statements, in the manifest's fixed order.
    pub no_claim_boundaries: Vec<String>,
}

impl OverlayProofCommand {
    /// Build an overlay-scoped RCH validation command from an A1 manifest, using
    /// [`DEFAULT_TARGET_DIR`].
    #[must_use]
    pub fn from_manifest(manifest: &CleanOverlayManifest) -> Self {
        Self::from_manifest_with_target(manifest, DEFAULT_TARGET_DIR)
    }

    /// Build an overlay-scoped RCH validation command with an explicit
    /// `CARGO_TARGET_DIR`.
    ///
    /// **Fail-closed:** a blocked manifest is never admitted; a report-only
    /// manifest is a dry run and is never admitted either. Only an enforced,
    /// unblocked manifest with at least one selected path is admitted.
    #[must_use]
    pub fn from_manifest_with_target(manifest: &CleanOverlayManifest, target_dir: &str) -> Self {
        let fail_closed_path_count = manifest
            .excluded_paths
            .iter()
            .filter(|excluded| is_fail_closed(excluded.reason))
            .count();
        let admitted =
            !manifest.blocked && !manifest.report_only && !manifest.selected_paths.is_empty();
        Self {
            head_commit: manifest.head_commit.clone(),
            target_dir: target_dir.to_string(),
            validation_intent: manifest.command_intent.clone(),
            selected_paths: manifest.selected_paths.clone(),
            overlay_paths: manifest.included_paths.clone(),
            excluded_paths: manifest.excluded_paths.clone(),
            reservation_evidence: manifest.reservation_evidence.clone(),
            admitted,
            report_only: manifest.report_only,
            fail_closed_path_count,
            no_claim_boundaries: manifest.no_claim_boundaries.clone(),
        }
    }

    /// The repeated `--overlay-path <p>` flags scoping the upload to the included
    /// paths only. Empty when there is no local edit to overlay.
    #[must_use]
    pub fn overlay_path_flags(&self) -> String {
        self.overlay_paths
            .iter()
            .map(|path| format!("--overlay-path {path}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The exact RCH command that validates the slice, or a `# BLOCKED` /
    /// `# REPORT-ONLY` comment line when no proof invocation is admitted.
    ///
    /// The admitted form is always routed through `rch exec` with
    /// `RCH_REQUIRE_REMOTE=1` and is scoped to the overlay paths, so an excluded
    /// path can never reach the build. There is never a local Cargo fallback.
    #[must_use]
    pub fn rendered_command(&self) -> String {
        if !self.admitted {
            if self.report_only {
                return format!(
                    "# REPORT-ONLY: clean-overlay dry run; no RCH proof command emitted ({} path(s) would fail closed)",
                    self.fail_closed_path_count
                );
            }
            return format!(
                "# BLOCKED: clean-overlay refused; no RCH proof command emitted ({} fail-closed path(s))",
                self.fail_closed_path_count
            );
        }
        let flags = self.overlay_path_flags();
        let base = format!(
            "RCH_REQUIRE_REMOTE=1 rch exec --base {} --clean-overlay",
            self.head_commit
        );
        let scope = if flags.is_empty() {
            // Selected paths were all clean at HEAD: nothing to overlay, but the
            // run is still explicitly scoped to refuse implicit whole-tree sync.
            "--no-overlay".to_string()
        } else {
            flags
        };
        format!(
            "{base} {scope} -- env CARGO_TARGET_DIR={} {}",
            self.target_dir, self.validation_intent
        )
    }

    /// A deterministic command an operator can paste to reproduce this attempt.
    ///
    /// For an admitted run it re-issues the same RCH-routed command. For a
    /// blocked run it re-runs the focused E2E proof (which re-derives the
    /// fail-closed decision); it **never** suggests a local Cargo fallback.
    #[must_use]
    pub fn reproduction_command(&self) -> String {
        if self.admitted {
            return self.rendered_command();
        }
        format!(
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR={} \
cargo test --test proof_orch_clean_overlay_e2e -- --nocapture",
            self.target_dir
        )
    }

    /// Forbidden orchestration tokens found in the rendered command surface.
    ///
    /// A clean-overlay run is RCH-only and non-destructive, so this is empty by
    /// construction. The E2E proof asserts it stays empty.
    #[must_use]
    pub fn forbidden_operations(&self) -> Vec<&'static str> {
        let surface = format!(
            "{}\n{}",
            self.rendered_command(),
            self.reproduction_command()
        );
        FORBIDDEN_TOKENS
            .iter()
            .copied()
            .filter(|token| surface.contains(token))
            .collect()
    }

    /// Whether the command surface suggests a local Cargo fallback.
    ///
    /// `false` by construction: every Cargo invocation is routed through
    /// `rch exec`, and no `|| cargo` / "run locally" fallback is ever emitted.
    #[must_use]
    pub fn uses_local_cargo_fallback(&self) -> bool {
        let surface = format!(
            "{}\n{}",
            self.rendered_command(),
            self.reproduction_command()
        );
        // A bare `cargo` invocation only ever appears immediately after an
        // `rch exec -- env ...` prefix in our output; any `|| cargo`, `; cargo`,
        // or "locally" phrasing would be a local fallback.
        surface.contains("|| cargo")
            || surface.contains("; cargo")
            || surface.contains("locally")
            || surface.contains("local fallback")
            || (surface.contains("cargo") && !surface.contains("rch exec"))
    }

    /// Whether an excluded path with the given reason is present.
    #[must_use]
    pub fn has_exclusion(&self, reason: ExclusionReason) -> bool {
        self.excluded_paths
            .iter()
            .any(|excluded| excluded.reason == reason)
    }

    /// Render a deterministic operator report for this proof command.
    ///
    /// Identifies the selected paths, overlay (included) paths, excluded paths
    /// with reasons, `HEAD`, reservation evidence, the exact RCH command, the
    /// reproduction command, and the honest no-claim boundaries. Suitable for an
    /// E2E artifact, Agent Mail, or a `br` comment. It attests only the listed
    /// overlay paths and never implies broad workspace health.
    #[must_use]
    pub fn render_report(&self) -> String {
        let mut out = String::new();
        out.push_str("## Clean-overlay focused proof — ");
        out.push_str(if self.admitted {
            "admitted"
        } else if self.report_only {
            "report-only"
        } else {
            "blocked (fail-closed)"
        });
        out.push_str("\n\n- HEAD: `");
        out.push_str(&self.head_commit);
        out.push_str("`\n- Lane: RCH-only; no local Cargo fallback\n- Validation intent: `");
        out.push_str(&self.validation_intent);
        out.push_str("`\n- Exact RCH command:\n```sh\n");
        out.push_str(&self.rendered_command());
        out.push_str("\n```\n- Reproduction command:\n```sh\n");
        out.push_str(&self.reproduction_command());
        out.push_str("\n```\n\n");

        push_path_list(&mut out, "Selected paths", &self.selected_paths);
        push_path_list(&mut out, "Overlay (included) paths", &self.overlay_paths);

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

        push_path_list(&mut out, "Reservation evidence", &self.reservation_evidence);

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

/// Whether an exclusion reason represents a fail-closed admission refusal.
const fn is_fail_closed(reason: ExclusionReason) -> bool {
    matches!(
        reason,
        ExclusionReason::PeerDirtyUnselected
            | ExclusionReason::UnreservedSelection
            | ExclusionReason::DeletedSelectionRefused
    )
}

/// Append a `### <title> (N)` section listing back-ticked paths, or `_none_`.
fn push_path_list(out: &mut String, title: &str, paths: &[String]) {
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
        ExclusionReason::PeerDirtyUnselected => "peer-dirty (unselected) — excluded from overlay",
        ExclusionReason::UnreservedSelection => "unreserved selection (no held lease)",
        ExclusionReason::DeletedSelectionRefused => {
            "deleted selection (an overlay cannot prove a removal)"
        }
    }
}
