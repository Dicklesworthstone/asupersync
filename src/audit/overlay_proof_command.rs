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
//! compiled. [`OverlayProofCommand`] emits an *overlay-scoped* invocation only
//! after [`CleanOverlayCapability`] confirms the installed client declares the
//! complete required flag surface. Unsupported clients emit a deterministic
//! blocker and no invocation. An admitted command uploads only the manifest's
//! included paths on top of `HEAD`, so an excluded poison path — even one that
//! would fail compilation — can never reach the compiler.
//!
//! # Invariants
//!
//! * **Fail closed.** A blocked manifest or unsupported installed client yields
//!   a command with `admitted=false` and emits *no* proof invocation; the run
//!   cannot accidentally report green.
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
use serde::Serialize;

/// Default `CARGO_TARGET_DIR` for clean-overlay proof runs. A dedicated dir keeps
/// the warm RCH cache from colliding with ad-hoc local builds.
pub const DEFAULT_TARGET_DIR: &str = "/data/tmp/rch_target_asupersync_test";

/// `rch exec` flags required by the clean-overlay command surface.
pub const REQUIRED_CLEAN_OVERLAY_FLAGS: [&str; 4] = [
    "--base",
    "--clean-overlay",
    "--overlay-path",
    "--no-overlay",
];

/// Stable fail-closed marker emitted when installed RCH lacks overlay support.
pub const CLEAN_OVERLAY_CAPABILITY_BLOCKER: &str =
    "# BLOCKED: installed RCH clean-overlay capability unsupported; no proof command emitted";

/// Installed `rch exec` clean-overlay capability evidence.
///
/// The command builder remains pure and performs no process I/O. The only
/// public constructor derives this immutable snapshot from captured
/// `rch exec --help` output; callers cannot hand-classify or mutate admission
/// fields.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CleanOverlayCapability {
    /// Probe/version string, for example `rch-1.0.49-exec-help`.
    capability_probe_version: String,
    /// Whether every flag in [`REQUIRED_CLEAN_OVERLAY_FLAGS`] is present.
    clean_overlay_supported: bool,
    /// Missing required flags, sorted and de-duplicated.
    missing_flags: Vec<String>,
    /// Operator-facing findings, sorted and de-duplicated.
    capability_findings: Vec<String>,
}

impl CleanOverlayCapability {
    /// Derive capability evidence from captured `rch exec --help` output.
    ///
    /// Only option-declaration lines count. Mentioning a flag in prose or an
    /// example cannot accidentally admit the command surface.
    #[must_use]
    pub fn from_rch_exec_help(
        capability_probe_version: impl Into<String>,
        help_text: &str,
    ) -> Self {
        let capability_probe_version = capability_probe_version.into().trim().to_string();
        let missing_flags = sorted_unique(
            REQUIRED_CLEAN_OVERLAY_FLAGS
                .iter()
                .filter(|flag| !help_declares_flag(help_text, flag))
                .map(|flag| (*flag).to_string())
                .collect::<Vec<_>>(),
        );
        let mut capability_findings = Vec::new();
        if missing_flags.is_empty() {
            capability_findings.push(
                "installed rch exec help exposes all required clean-overlay flags".to_string(),
            );
        } else {
            capability_findings.push(format!(
                "installed rch exec help lacks required clean-overlay flags: {}",
                missing_flags.join(",")
            ));
        }
        if capability_probe_version.is_empty() {
            capability_findings.push("installed capability probe version is missing".to_string());
        }
        let clean_overlay_supported =
            missing_flags.is_empty() && !capability_probe_version.is_empty();
        Self {
            capability_probe_version,
            clean_overlay_supported,
            missing_flags,
            capability_findings: sorted_unique(capability_findings),
        }
    }

    /// Whether the snapshot consistently supports the complete flag surface.
    #[must_use]
    pub fn supports_required_flags(&self) -> bool {
        self.clean_overlay_supported
            && self.missing_flags.is_empty()
            && !self.capability_probe_version.trim().is_empty()
    }

    /// Captured probe/version identity. Empty evidence always fails closed.
    #[must_use]
    pub fn capability_probe_version(&self) -> &str {
        &self.capability_probe_version
    }

    /// Whether the captured help declares every required flag and has a probe
    /// identity.
    #[must_use]
    pub fn clean_overlay_supported(&self) -> bool {
        self.supports_required_flags()
    }

    /// Missing required flags derived from the captured options section.
    #[must_use]
    pub fn missing_flags(&self) -> &[String] {
        &self.missing_flags
    }

    /// Deterministic operator-facing findings derived from captured evidence.
    #[must_use]
    pub fn capability_findings(&self) -> &[String] {
        &self.capability_findings
    }
}

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
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverlayProofCommand {
    /// The `HEAD` commit the overlay is based on.
    head_commit: String,
    /// `CARGO_TARGET_DIR` the RCH run uses.
    target_dir: String,
    /// The Cargo validation intent, e.g. `cargo test --test foo`.
    validation_intent: String,
    /// Selected paths the request asked for (from the manifest), sorted.
    selected_paths: Vec<String>,
    /// Overlay paths uploaded on top of `HEAD` (the manifest's included paths),
    /// sorted. These — and only these — local edits reach the build.
    overlay_paths: Vec<String>,
    /// Paths excluded from the overlay with their reasons (from the manifest).
    excluded_paths: Vec<ExcludedPath>,
    /// Reservation patterns that justified an inclusion (from the manifest).
    reservation_evidence: Vec<String>,
    /// Installed RCH capability probe/version string.
    capability_probe_version: String,
    /// Whether installed `rch exec` supports the complete overlay flag surface.
    clean_overlay_supported: bool,
    /// Required clean-overlay flags missing from installed RCH.
    missing_flags: Vec<String>,
    /// Operator-facing installed capability findings.
    capability_findings: Vec<String>,
    /// Whether an enforced proof invocation is admitted. `false` when the
    /// manifest blocked or was report-only — no proof command is emitted.
    admitted: bool,
    /// Whether the source manifest was a report-only (dry-run) manifest.
    report_only: bool,
    /// Number of paths that failed closed (peer dirt, unreserved, deleted).
    fail_closed_path_count: usize,
    /// Honest no-claim boundary statements, in the manifest's fixed order.
    no_claim_boundaries: Vec<String>,
}

impl OverlayProofCommand {
    /// Build an overlay-scoped RCH validation command from an A1 manifest, using
    /// [`DEFAULT_TARGET_DIR`].
    #[must_use]
    pub fn from_manifest(
        manifest: &CleanOverlayManifest,
        capability: &CleanOverlayCapability,
    ) -> Self {
        Self::from_manifest_with_target(manifest, DEFAULT_TARGET_DIR, capability)
    }

    /// Build an overlay-scoped RCH validation command with an explicit
    /// `CARGO_TARGET_DIR`.
    ///
    /// **Fail-closed:** a blocked manifest is never admitted; a report-only
    /// manifest is a dry run and is never admitted either. Only an enforced,
    /// unblocked manifest with at least one selected path and supported
    /// installed capability evidence is admitted.
    #[must_use]
    pub fn from_manifest_with_target(
        manifest: &CleanOverlayManifest,
        target_dir: &str,
        capability: &CleanOverlayCapability,
    ) -> Self {
        let fail_closed_path_count = manifest
            .excluded_paths
            .iter()
            .filter(|excluded| is_fail_closed(excluded.reason))
            .count();
        let admitted = !manifest.blocked
            && !manifest.report_only
            && !manifest.selected_paths.is_empty()
            && capability.supports_required_flags();
        let mut no_claim_boundaries = manifest.no_claim_boundaries.clone();
        no_claim_boundaries.push(
            "no claim that peer dirt was excluded unless installed RCH clean-overlay capability evidence is supported and an admitted command completed with terminal execution evidence"
                .to_string(),
        );
        Self {
            head_commit: manifest.head_commit.clone(),
            target_dir: target_dir.to_string(),
            validation_intent: manifest.command_intent.clone(),
            selected_paths: manifest.selected_paths.clone(),
            overlay_paths: manifest.included_paths.clone(),
            excluded_paths: manifest.excluded_paths.clone(),
            reservation_evidence: manifest.reservation_evidence.clone(),
            capability_probe_version: capability.capability_probe_version().to_string(),
            clean_overlay_supported: capability.supports_required_flags(),
            missing_flags: capability.missing_flags().to_vec(),
            capability_findings: capability.capability_findings().to_vec(),
            admitted,
            report_only: manifest.report_only,
            fail_closed_path_count,
            no_claim_boundaries,
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
        if !self.clean_overlay_supported {
            return CLEAN_OVERLAY_CAPABILITY_BLOCKER.to_string();
        }
        if self.report_only {
            return format!(
                "# REPORT-ONLY: clean-overlay dry run; no RCH proof command emitted ({} path(s) would fail closed)",
                self.fail_closed_path_count
            );
        }
        if !self.admitted {
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
    /// For an admitted run it re-issues the same RCH-routed command. Every
    /// non-admitted run repeats its deterministic receipt and emits no command,
    /// because ordinary RCH would sync the peer dirt that may have caused the
    /// refusal. It **never** suggests a local Cargo fallback.
    #[must_use]
    pub fn reproduction_command(&self) -> String {
        self.rendered_command()
    }

    /// Whether this builder admitted an executable proof command.
    #[must_use]
    pub fn admitted(&self) -> bool {
        self.admitted
    }

    /// Whether the source request was report-only.
    #[must_use]
    pub fn report_only(&self) -> bool {
        self.report_only
    }

    /// Whether captured installed capability evidence supports the command.
    #[must_use]
    pub fn clean_overlay_supported(&self) -> bool {
        self.clean_overlay_supported
    }

    /// Selected paths recorded by the planner.
    #[must_use]
    pub fn selected_paths(&self) -> &[String] {
        &self.selected_paths
    }

    /// Paths that an admitted command overlays on `HEAD`.
    #[must_use]
    pub fn overlay_paths(&self) -> &[String] {
        &self.overlay_paths
    }

    /// Planner exclusions and their reasons.
    #[must_use]
    pub fn excluded_paths(&self) -> &[ExcludedPath] {
        &self.excluded_paths
    }

    /// Reservation patterns that justified included dirty paths.
    #[must_use]
    pub fn reservation_evidence(&self) -> &[String] {
        &self.reservation_evidence
    }

    /// Required clean-overlay flags missing from captured capability evidence.
    #[must_use]
    pub fn missing_flags(&self) -> &[String] {
        &self.missing_flags
    }

    /// Operator-facing capability findings.
    #[must_use]
    pub fn capability_findings(&self) -> &[String] {
        &self.capability_findings
    }

    /// Honest boundaries on what this command can prove.
    #[must_use]
    pub fn no_claim_boundaries(&self) -> &[String] {
        &self.no_claim_boundaries
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
        out.push_str(if !self.clean_overlay_supported {
            "blocked (capability drift)"
        } else if self.report_only {
            "report-only"
        } else if self.admitted {
            "admitted"
        } else {
            "blocked (fail-closed)"
        });
        out.push_str("\n\n- HEAD: `");
        out.push_str(&self.head_commit);
        out.push_str("`\n- Lane: RCH-only; no local Cargo fallback\n- Validation intent: `");
        out.push_str(&self.validation_intent);
        out.push_str("`\n- Capability probe: `");
        out.push_str(&self.capability_probe_version);
        out.push_str("`\n- Clean-overlay capability supported: `");
        out.push_str(if self.clean_overlay_supported {
            "true"
        } else {
            "false"
        });
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
        push_path_list(&mut out, "Missing capability flags", &self.missing_flags);
        push_path_list(&mut out, "Capability findings", &self.capability_findings);

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

fn help_declares_flag(help_text: &str, flag: &str) -> bool {
    let mut in_options = false;

    for line in help_text.lines() {
        let declaration = line.trim();

        if declaration.eq_ignore_ascii_case("options:") {
            in_options = true;
            continue;
        }

        if !in_options {
            continue;
        }
        if !declaration.is_empty() && !declaration.starts_with('-') && declaration.ends_with(':') {
            in_options = false;
            continue;
        }
        if !declaration.starts_with('-') {
            continue;
        }

        for token in declaration.split_whitespace() {
            let token = token.trim_end_matches(',');
            let token = token.split_once('=').map_or(token, |(name, _)| name);
            if !token.starts_with('-') {
                break;
            }
            if token == flag {
                return true;
            }
        }
    }

    false
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
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
