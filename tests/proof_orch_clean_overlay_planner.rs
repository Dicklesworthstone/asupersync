//! Behavioral tests for the clean-overlay RCH input planner (PROOF-ORCH A1,
//! bead asupersync-proof-orch-clean-overlay-5ve2ao.1).
//!
//! Run as an integration test (the lib is linked in non-test mode) so these
//! assertions are immune to peer `#[cfg(test)]` breakage in the shared tree:
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test proof_orch_clean_overlay_planner -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::audit::clean_overlay_planner::{
    CleanOverlayManifest, CleanOverlayRequest, ExclusionReason, PathChange, ReservationLease,
    WorkingTreeEntry, plan_clean_overlay,
};

const HEAD: &str = "e6abc3db2c0ffee0000000000000000000000000";
const INTENT: &str = "cargo test --test foo";

fn wte(path: &str, change: PathChange) -> WorkingTreeEntry {
    WorkingTreeEntry::new(path, change)
}

fn lease(pattern: &str) -> ReservationLease {
    ReservationLease::new(pattern, true)
}

fn shared_lease(pattern: &str) -> ReservationLease {
    ReservationLease::new(pattern, false)
}

fn request(
    working_tree: Vec<WorkingTreeEntry>,
    selected: &[&str],
    reservations: Vec<ReservationLease>,
    report_only: bool,
) -> CleanOverlayRequest {
    CleanOverlayRequest {
        head_commit: HEAD.to_string(),
        working_tree,
        selected_paths: selected.iter().map(|s| (*s).to_string()).collect(),
        reservations,
        command_intent: INTENT.to_string(),
        report_only,
    }
}

fn excluded_reason(manifest: &CleanOverlayManifest, path: &str) -> Option<ExclusionReason> {
    manifest
        .excluded_paths
        .iter()
        .find(|e| e.path == path)
        .map(|e| e.reason)
}

// AC1.1 — clean tree.
#[test]
fn clean_tree_yields_empty_overlay() {
    let manifest = plan_clean_overlay(&request(vec![], &[], vec![], false));
    assert!(manifest.included_paths.is_empty());
    assert!(manifest.excluded_paths.is_empty());
    assert!(manifest.reservation_evidence.is_empty());
    assert!(!manifest.blocked);
    assert_eq!(manifest.head_commit, HEAD);
    assert!(manifest.selected_paths.is_empty());
    assert_eq!(manifest.command_intent, INTENT);
}

// AC1.2 — selected dirty file, reserved → included.
#[test]
fn selected_reserved_modified_file_is_included() {
    let manifest = plan_clean_overlay(&request(
        vec![wte("src/a.rs", PathChange::Modified)],
        &["src/a.rs"],
        vec![lease("src/a.rs")],
        false,
    ));
    assert_eq!(manifest.included_paths, vec!["src/a.rs".to_string()]);
    assert_eq!(manifest.reservation_evidence, vec!["src/a.rs".to_string()]);
    assert!(manifest.excluded_paths.is_empty());
    assert!(!manifest.blocked);
}

// AC1.3 — selected untracked file, reserved by glob → included.
#[test]
fn selected_reserved_untracked_file_is_included() {
    let manifest = plan_clean_overlay(&request(
        vec![wte("src/new.rs", PathChange::Untracked)],
        &["src/new.rs"],
        vec![lease("src/*.rs")],
        false,
    ));
    assert_eq!(manifest.included_paths, vec!["src/new.rs".to_string()]);
    assert_eq!(manifest.reservation_evidence, vec!["src/*.rs".to_string()]);
    assert!(!manifest.blocked);
}

#[test]
fn selected_dirty_file_with_shared_reservation_fails_closed() {
    let manifest = plan_clean_overlay(&request(
        vec![wte("src/shared.rs", PathChange::Modified)],
        &["src/shared.rs"],
        vec![shared_lease("src/shared.rs")],
        false,
    ));
    assert!(manifest.included_paths.is_empty());
    assert!(manifest.reservation_evidence.is_empty());
    assert!(manifest.blocked);
    assert_eq!(
        excluded_reason(&manifest, "src/shared.rs"),
        Some(ExclusionReason::UnreservedSelection)
    );
}

// AC1.4 — unreserved dirty file selected → fail closed.
#[test]
fn unreserved_dirty_selection_fails_closed() {
    let manifest = plan_clean_overlay(&request(
        vec![wte("src/b.rs", PathChange::Modified)],
        &["src/b.rs"],
        vec![],
        false,
    ));
    assert!(manifest.included_paths.is_empty());
    assert!(manifest.blocked);
    assert_eq!(
        excluded_reason(&manifest, "src/b.rs"),
        Some(ExclusionReason::UnreservedSelection)
    );
    assert!(
        manifest
            .no_claim_boundaries
            .iter()
            .any(|b| b.contains("BLOCKED"))
    );
}

// AC1.5 — selected deleted path → refused.
#[test]
fn deleted_selection_is_refused() {
    let manifest = plan_clean_overlay(&request(
        vec![wte("src/gone.rs", PathChange::Deleted)],
        &["src/gone.rs"],
        vec![lease("src/gone.rs")],
        false,
    ));
    assert!(manifest.included_paths.is_empty());
    assert!(manifest.blocked);
    assert_eq!(
        excluded_reason(&manifest, "src/gone.rs"),
        Some(ExclusionReason::DeletedSelectionRefused)
    );
}

// AC1.6 — glob match + path normalization (`./`, backslash, doubled separators).
#[test]
fn glob_and_path_normalization() {
    let manifest = plan_clean_overlay(&request(
        vec![wte("src/grpc/client.rs", PathChange::Modified)],
        &[r"././src\grpc//client.rs"],
        vec![lease("src/grpc/*.rs")],
        false,
    ));
    assert_eq!(
        manifest.included_paths,
        vec!["src/grpc/client.rs".to_string()]
    );
    assert_eq!(
        manifest.reservation_evidence,
        vec!["src/grpc/*.rs".to_string()]
    );
    assert!(!manifest.blocked);
}

// AC1.7 — unselected dirty paths are excluded as peer dirt and block default proof.
#[test]
fn peer_dirty_unselected_is_excluded_and_blocks() {
    let manifest = plan_clean_overlay(&request(
        vec![
            wte("src/mine.rs", PathChange::Modified),
            wte("src/peer.rs", PathChange::Modified),
        ],
        &["src/mine.rs"],
        vec![lease("src/mine.rs")],
        false,
    ));
    assert_eq!(manifest.included_paths, vec!["src/mine.rs".to_string()]);
    assert_eq!(
        excluded_reason(&manifest, "src/peer.rs"),
        Some(ExclusionReason::PeerDirtyUnselected)
    );
    assert!(manifest.blocked, "peer dirt must fail closed by default");
}

// report_only is the only documented override of the fail-closed default.
#[test]
fn report_only_overrides_fail_closed() {
    let manifest = plan_clean_overlay(&request(
        vec![wte("src/b.rs", PathChange::Modified)],
        &["src/b.rs"],
        vec![],
        true,
    ));
    assert!(!manifest.blocked, "report-only must never hard-block");
    assert!(manifest.report_only);
    assert_eq!(
        excluded_reason(&manifest, "src/b.rs"),
        Some(ExclusionReason::UnreservedSelection)
    );
    assert!(
        manifest
            .no_claim_boundaries
            .iter()
            .any(|b| b.contains("report-only")),
        "report-only boundary statement must be present"
    );
}

// AC2 — the planner never emits branch/worktree/clone/destructive intent; its
// boundary statements assert those constraints explicitly.
#[test]
fn boundaries_assert_no_branch_or_worktree_or_deletion() {
    let manifest = plan_clean_overlay(&request(vec![], &[], vec![], false));
    let constraints = manifest
        .no_claim_boundaries
        .iter()
        .find(|b| b.starts_with("constraints:"))
        .expect("a constraints boundary statement");
    for needle in [
        "no git branch/worktree/clone",
        "RCH-only",
        "no file deletion",
        "no workspace-wide health claim",
    ] {
        assert!(constraints.contains(needle), "missing constraint: {needle}");
    }
}

// AC4 — deterministic output ordering, golden-tested. Input is deliberately
// scrambled; the manifest must be sorted, stable across runs, and byte-equal to
// the golden serialization.
#[test]
fn output_ordering_is_deterministic_golden() {
    let scrambled = request(
        vec![
            wte("src/zeta.rs", PathChange::Modified),
            wte("src/alpha.rs", PathChange::Modified),
            wte("src/peer_two.rs", PathChange::Untracked),
            wte("src/peer_one.rs", PathChange::Modified),
            wte("src/gone.rs", PathChange::Deleted),
        ],
        &["src/zeta.rs", "src/alpha.rs", "src/gone.rs", "src/zeta.rs"],
        vec![lease("src/*.rs")],
        false,
    );

    let manifest = plan_clean_overlay(&scrambled);

    // Sorted + de-duplicated includes.
    assert_eq!(
        manifest.included_paths,
        vec!["src/alpha.rs".to_string(), "src/zeta.rs".to_string()]
    );
    let mut sorted_includes = manifest.included_paths.clone();
    sorted_includes.sort();
    assert_eq!(manifest.included_paths, sorted_includes);

    // Excluded sorted by path then reason.
    let excluded_order: Vec<(&str, ExclusionReason)> = manifest
        .excluded_paths
        .iter()
        .map(|e| (e.path.as_str(), e.reason))
        .collect();
    assert_eq!(
        excluded_order,
        vec![
            ("src/gone.rs", ExclusionReason::DeletedSelectionRefused),
            ("src/peer_one.rs", ExclusionReason::PeerDirtyUnselected),
            ("src/peer_two.rs", ExclusionReason::PeerDirtyUnselected),
        ]
    );

    // Determinism: a second run is byte-identical.
    let again = plan_clean_overlay(&scrambled);
    let first = serde_json::to_string_pretty(&manifest).expect("serialize");
    let second = serde_json::to_string_pretty(&again).expect("serialize");
    assert_eq!(first, second, "planner output must be deterministic");

    // Golden serialization.
    println!("--- ACTUAL GOLDEN ---\n{first}\n--- END GOLDEN ---");
    assert_eq!(first, GOLDEN, "golden manifest serialization drifted");
}

const GOLDEN: &str = r#"{
  "head_commit": "e6abc3db2c0ffee0000000000000000000000000",
  "selected_paths": [
    "src/alpha.rs",
    "src/gone.rs",
    "src/zeta.rs"
  ],
  "included_paths": [
    "src/alpha.rs",
    "src/zeta.rs"
  ],
  "excluded_paths": [
    {
      "path": "src/gone.rs",
      "reason": "deleted_selection_refused"
    },
    {
      "path": "src/peer_one.rs",
      "reason": "peer_dirty_unselected"
    },
    {
      "path": "src/peer_two.rs",
      "reason": "peer_dirty_unselected"
    }
  ],
  "reservation_evidence": [
    "src/*.rs"
  ],
  "command_intent": "cargo test --test foo",
  "report_only": false,
  "blocked": true,
  "no_claim_boundaries": [
    "head_commit=e6abc3db2c0ffee0000000000000000000000000",
    "included=2 path(s) overlaid on HEAD",
    "excluded=3 path(s): peer_dirty=2, unreserved=0, deleted=1",
    "BLOCKED: fail-closed on 3 dirty/deleted path(s); no proof claim emitted",
    "constraints: no git branch/worktree/clone; RCH-only; no file deletion; no workspace-wide health claim"
  ]
}"#;
