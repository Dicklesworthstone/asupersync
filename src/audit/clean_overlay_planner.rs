//! Clean-overlay RCH input planner (PROOF-ORCH A1).
//!
//! Shared-main asupersync work routinely mixes an agent's own reserved local
//! changes with unrelated peer dirt. A focused RCH proof command that compiles
//! or syncs the *whole* working tree can drag that peer dirt in and stall or
//! fail before the intended slice is ever proved.
//!
//! This planner is the deterministic, fail-closed decision core for a
//! clean-overlay proof run. Given a snapshot of `HEAD`, the current working
//! tree, the explicitly selected paths, and the requesting agent's own
//! reservation leases, it computes a manifest of exactly which paths overlay
//! `HEAD` and which are excluded. Enforced runs fail closed on peer dirt outside
//! the selected overlay, unreserved selected dirt, and selected deletions.
//!
//! # Non-goals
//!
//! The planner is pure: it performs no git invocation, creates no branches,
//! worktrees, or clones, runs no commands, and deletes nothing. It only decides
//! what a downstream RCH lane is permitted to prove. Callers feed it a snapshot
//! and serialize the resulting [`CleanOverlayManifest`] into receipts.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Working-tree dirtiness classification for a single path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathChange {
    /// Tracked file with staged or unstaged modifications relative to `HEAD`.
    Modified,
    /// Newly added file not yet present in `HEAD`.
    Added,
    /// Path present in `HEAD` but removed from the working tree.
    Deleted,
    /// Path present in the working tree but untracked by git.
    Untracked,
}

/// A single dirty or untracked working-tree entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkingTreeEntry {
    /// Repository-relative path.
    pub path: String,
    /// How the path differs from `HEAD`.
    pub change: PathChange,
}

impl WorkingTreeEntry {
    /// Construct a working-tree entry from a path and its change kind.
    pub fn new(path: impl Into<String>, change: PathChange) -> Self {
        Self {
            path: path.into(),
            change,
        }
    }
}

/// One reservation lease held by the requesting agent.
///
/// Patterns use fnmatch-style globbing (`*` spans path separators, `?` matches a
/// single character), matching the Agent Mail file-reservation semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationLease {
    /// Path or glob pattern the lease covers.
    pub pattern: String,
    /// Whether the lease is exclusive; only exclusive leases authorize dirty overlay input.
    pub exclusive: bool,
}

impl ReservationLease {
    /// Construct a reservation lease from a pattern and exclusivity flag.
    pub fn new(pattern: impl Into<String>, exclusive: bool) -> Self {
        Self {
            pattern: pattern.into(),
            exclusive,
        }
    }
}

/// Inputs to the clean-overlay planner — a snapshot, not a live handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanOverlayRequest {
    /// The `HEAD` commit object id this overlay is based on.
    pub head_commit: String,
    /// Current dirty/untracked working-tree entries.
    pub working_tree: Vec<WorkingTreeEntry>,
    /// Paths the agent explicitly wants in the overlay.
    pub selected_paths: Vec<String>,
    /// Reservation leases the agent currently holds.
    pub reservations: Vec<ReservationLease>,
    /// The RCH command intent this overlay will feed (recorded, not run).
    pub command_intent: String,
    /// When true, never hard-block: produce a report-only dry-run manifest.
    pub report_only: bool,
}

/// Reason a path was excluded from the overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    /// Dirty in the working tree but not selected — peer dirt outside the overlay.
    PeerDirtyUnselected,
    /// Selected, but no held reservation covers it — fail closed.
    UnreservedSelection,
    /// Selected, but deleted in the working tree — an overlay cannot prove a removal.
    DeletedSelectionRefused,
}

/// A path excluded from the overlay, with its reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExcludedPath {
    /// Repository-relative path.
    pub path: String,
    /// Why it was excluded.
    pub reason: ExclusionReason,
}

/// Deterministic clean-overlay manifest produced by [`plan_clean_overlay`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanOverlayManifest {
    /// The `HEAD` commit the overlay is based on.
    pub head_commit: String,
    /// The normalized selected paths the request asked for, sorted and de-duplicated.
    pub selected_paths: Vec<String>,
    /// Paths overlaid on `HEAD`, sorted and de-duplicated.
    pub included_paths: Vec<String>,
    /// Excluded paths, sorted by `(path, reason)`.
    pub excluded_paths: Vec<ExcludedPath>,
    /// Reservation patterns that justified an inclusion, sorted and de-duplicated.
    pub reservation_evidence: Vec<String>,
    /// The recorded RCH command intent.
    pub command_intent: String,
    /// Whether this manifest was produced in report-only (dry-run) mode.
    pub report_only: bool,
    /// True when an enforced run refused to proceed (fail closed).
    pub blocked: bool,
    /// Honest no-claim boundary statements, in a fixed order.
    pub no_claim_boundaries: Vec<String>,
}

/// Normalize a repository-relative path for stable comparison.
///
/// Trims surrounding whitespace, converts backslashes, strips repeated leading
/// `./`, collapses repeated slashes, and removes a trailing slash. Empty
/// results signal "skip".
fn normalize_path(raw: &str) -> String {
    let trimmed = raw.trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_slash = false;
    for ch in trimmed.chars() {
        let ch = if ch == '\\' { '/' } else { ch };
        if ch == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out.push(ch);
    }
    while out.starts_with("./") {
        out.drain(..2);
    }
    while out.ends_with('/') {
        out.pop();
    }
    out
}

/// fnmatch-style glob match where `*` spans separators and `?` matches one char.
fn glob_match(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = name.chars().collect();
    let mut p = 0usize;
    let mut t = 0usize;
    let mut star: Option<usize> = None;
    let mut star_t = 0usize;
    while t < txt.len() {
        if p < pat.len() && (pat[p] == '?' || pat[p] == txt[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == '*' {
            star = Some(p);
            star_t = t;
            p += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

/// Return the lexicographically-smallest reservation pattern covering `path`.
///
/// Smallest-match keeps inclusion evidence deterministic when several leases
/// overlap a path.
fn covering_reservation(path: &str, patterns: &[String]) -> Option<String> {
    let mut best: Option<&String> = None;
    for pattern in patterns {
        if glob_match(pattern, path) {
            match best {
                Some(current) if current <= pattern => {}
                _ => best = Some(pattern),
            }
        }
    }
    best.cloned()
}

/// Stable sort rank for an exclusion reason.
fn reason_rank(reason: ExclusionReason) -> u8 {
    match reason {
        ExclusionReason::DeletedSelectionRefused => 0,
        ExclusionReason::UnreservedSelection => 1,
        ExclusionReason::PeerDirtyUnselected => 2,
    }
}

/// Build the fixed-order honest no-claim boundary statements.
fn build_boundaries(
    request: &CleanOverlayRequest,
    included: &[String],
    excluded: &[ExcludedPath],
    effective_blocked: bool,
    fail_closed_path_count: usize,
) -> Vec<String> {
    let peer = excluded
        .iter()
        .filter(|e| e.reason == ExclusionReason::PeerDirtyUnselected)
        .count();
    let unreserved = excluded
        .iter()
        .filter(|e| e.reason == ExclusionReason::UnreservedSelection)
        .count();
    let deleted = excluded
        .iter()
        .filter(|e| e.reason == ExclusionReason::DeletedSelectionRefused)
        .count();

    let mut out = Vec::with_capacity(5);
    out.push(format!("head_commit={}", request.head_commit.trim()));
    out.push(format!(
        "included={} path(s) overlaid on HEAD",
        included.len()
    ));
    out.push(format!(
        "excluded={} path(s): peer_dirty={peer}, unreserved={unreserved}, deleted={deleted}",
        excluded.len()
    ));
    if effective_blocked {
        out.push(format!(
            "BLOCKED: fail-closed on {fail_closed_path_count} dirty/deleted path(s); no proof claim emitted"
        ));
    } else if fail_closed_path_count > 0 && request.report_only {
        out.push(format!(
            "report-only: {fail_closed_path_count} path(s) would fail closed in an enforced run; no proof claim"
        ));
    } else {
        out.push("proof claim limited to included paths; HEAD baseline otherwise".to_string());
    }
    out.push(
        "constraints: no git branch/worktree/clone; RCH-only; no file deletion; no workspace-wide health claim"
            .to_string(),
    );
    out
}

/// Compute a deterministic clean-overlay manifest for an RCH proof run.
///
/// Selected dirty/untracked paths are included only when a held reservation
/// covers them; otherwise they fail closed. Selected deleted paths are refused.
/// Unselected working-tree paths are excluded as peer dirt and also fail closed
/// for enforced proof admission. In `report_only` mode the same decisions are
/// computed but the manifest never hard-blocks.
pub fn plan_clean_overlay(request: &CleanOverlayRequest) -> CleanOverlayManifest {
    // Index the working tree by normalized path (last entry for a path wins).
    let mut change_by_path: BTreeMap<String, PathChange> = BTreeMap::new();
    for entry in &request.working_tree {
        let path = normalize_path(&entry.path);
        if !path.is_empty() {
            change_by_path.insert(path, entry.change);
        }
    }

    let mut patterns: Vec<String> = request
        .reservations
        .iter()
        .filter(|lease| lease.exclusive)
        .map(|lease| normalize_path(&lease.pattern))
        .filter(|pattern| !pattern.is_empty())
        .collect();
    patterns.sort();
    patterns.dedup();

    let mut selected: BTreeSet<String> = BTreeSet::new();
    let mut included: BTreeSet<String> = BTreeSet::new();
    let mut evidence: BTreeSet<String> = BTreeSet::new();
    let mut excluded: Vec<ExcludedPath> = Vec::new();
    let mut fail_closed_path_count = 0usize;
    let mut blocked = false;

    for raw in &request.selected_paths {
        let path = normalize_path(raw);
        if path.is_empty() || !selected.insert(path.clone()) {
            continue;
        }
        match change_by_path.get(&path).copied() {
            Some(PathChange::Deleted) => {
                excluded.push(ExcludedPath {
                    path,
                    reason: ExclusionReason::DeletedSelectionRefused,
                });
                fail_closed_path_count += 1;
                blocked = true;
            }
            Some(PathChange::Modified | PathChange::Added | PathChange::Untracked) => {
                if let Some(pattern) = covering_reservation(&path, &patterns) {
                    included.insert(path);
                    evidence.insert(pattern);
                } else {
                    excluded.push(ExcludedPath {
                        path,
                        reason: ExclusionReason::UnreservedSelection,
                    });
                    fail_closed_path_count += 1;
                    blocked = true;
                }
            }
            None => {
                // Selected but clean / already at HEAD: safe to overlay, no
                // reservation required because there is no local change.
                included.insert(path);
            }
        }
    }

    // Any working-tree path the agent did not select is peer dirt by construction.
    for path in change_by_path.keys() {
        if !selected.contains(path) {
            excluded.push(ExcludedPath {
                path: path.clone(),
                reason: ExclusionReason::PeerDirtyUnselected,
            });
            fail_closed_path_count += 1;
            blocked = true;
        }
    }

    // report_only is the only documented override of the fail-closed default.
    let effective_blocked = blocked && !request.report_only;

    excluded.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| reason_rank(a.reason).cmp(&reason_rank(b.reason)))
    });
    excluded.dedup();

    let included_paths: Vec<String> = included.into_iter().collect();
    let reservation_evidence: Vec<String> = evidence.into_iter().collect();
    let no_claim_boundaries = build_boundaries(
        request,
        &included_paths,
        &excluded,
        effective_blocked,
        fail_closed_path_count,
    );

    CleanOverlayManifest {
        head_commit: request.head_commit.trim().to_string(),
        selected_paths: selected.into_iter().collect(),
        included_paths,
        excluded_paths: excluded,
        reservation_evidence,
        command_intent: request.command_intent.clone(),
        report_only: request.report_only,
        blocked: effective_blocked,
        no_claim_boundaries,
    }
}
