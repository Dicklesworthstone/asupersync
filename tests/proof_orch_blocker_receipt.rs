//! Contract + golden tests for the PROOF-ORCH A2 blocker receipt
//! (br-asupersync-proof-orch-clean-overlay-5ve2ao.2): a machine-readable receipt
//! and deterministic operator report for clean-overlay proof attempts, with a
//! fail-closed outcome taxonomy that never reads stale-progress as success.

#![allow(missing_docs)]

use asupersync::audit::blocker_receipt::{
    BlockerReceipt, ProofAttemptOutcome, RchExecutionEvidence,
};
use asupersync::audit::clean_overlay_planner::{
    CleanOverlayManifest, CleanOverlayRequest, ExcludedPath, ExclusionReason, PathChange,
    ReservationLease, WorkingTreeEntry, plan_clean_overlay,
};

fn manifest(
    excluded: Vec<ExcludedPath>,
    included: Vec<&str>,
    reservations: Vec<&str>,
    blocked: bool,
    report_only: bool,
) -> CleanOverlayManifest {
    CleanOverlayManifest {
        head_commit: "deadbeefcafe".to_string(),
        selected_paths: included.iter().map(|p| (*p).to_string()).collect(),
        included_paths: included.iter().map(|p| (*p).to_string()).collect(),
        excluded_paths: excluded,
        reservation_evidence: reservations.iter().map(|p| (*p).to_string()).collect(),
        command_intent: "cargo test --test foo".to_string(),
        report_only,
        blocked,
        no_claim_boundaries: vec![
            "This receipt attests only the listed overlay paths, not workspace health.".to_string(),
        ],
    }
}

fn excluded(path: &str, reason: ExclusionReason) -> ExcludedPath {
    ExcludedPath {
        path: path.to_string(),
        reason,
    }
}

// --- AC1 / AC3: taxonomy and fail-closed success semantics ---------------------

#[test]
fn outcome_taxonomy_labels_and_success() {
    // Stable machine labels and the single-success rule (only Green proves).
    assert_eq!(ProofAttemptOutcome::Blocked.label(), "blocked");
    assert_eq!(ProofAttemptOutcome::Failed.label(), "failed");
    assert_eq!(ProofAttemptOutcome::StaleProgress.label(), "stale_progress");
    assert_eq!(ProofAttemptOutcome::Green.label(), "green");

    assert!(ProofAttemptOutcome::Green.is_proof_success());
    assert!(!ProofAttemptOutcome::Blocked.is_proof_success());
    assert!(!ProofAttemptOutcome::Failed.is_proof_success());
    // AC3: a fresh heartbeat over a stalled build is NOT success.
    assert!(!ProofAttemptOutcome::StaleProgress.is_proof_success());

    assert!(ProofAttemptOutcome::Blocked.is_blocked());
    assert!(!ProofAttemptOutcome::Green.is_blocked());
}

#[test]
fn blocked_manifest_forces_blocked_outcome_even_if_caller_claims_green() {
    // Fail-closed: a blocked overlay never ran, so it can never attest success,
    // even if a buggy caller passes Green.
    let man = manifest(
        vec![excluded(
            "src/peer.rs",
            ExclusionReason::PeerDirtyUnselected,
        )],
        vec!["src/mine.rs"],
        vec!["src/mine.rs"],
        true,
        false,
    );
    let receipt = BlockerReceipt::from_manifest(
        &man,
        ProofAttemptOutcome::Green,
        RchExecutionEvidence::default(),
    );
    assert_eq!(receipt.outcome, ProofAttemptOutcome::Blocked);
    assert!(!receipt.proves_clean());
    assert_eq!(receipt.peer_dirty_paths(), vec!["src/peer.rs"]);
}

#[test]
fn stale_progress_receipt_does_not_prove_clean() {
    // AC3: a clean overlay that went stale-progress is recorded as such and is
    // not a successful proof.
    let man = manifest(
        vec![],
        vec!["src/mine.rs"],
        vec!["src/mine.rs"],
        false,
        false,
    );
    let receipt = BlockerReceipt::from_manifest(
        &man,
        ProofAttemptOutcome::StaleProgress,
        RchExecutionEvidence::default(),
    );
    assert_eq!(receipt.outcome, ProofAttemptOutcome::StaleProgress);
    assert!(!receipt.proves_clean());
}

#[test]
fn green_clean_overlay_proves_clean() {
    let man = manifest(
        vec![],
        vec!["src/mine.rs"],
        vec!["src/mine.rs"],
        false,
        false,
    );
    let receipt = BlockerReceipt::from_manifest(
        &man,
        ProofAttemptOutcome::Green,
        RchExecutionEvidence::default(),
    );
    assert!(receipt.proves_clean());
}

#[test]
fn receipt_serde_roundtrips() {
    // AC1: the receipt is a stable machine-readable schema.
    let man = manifest(
        vec![excluded("a/b.rs", ExclusionReason::UnreservedSelection)],
        vec!["c/d.rs"],
        vec!["c/*.rs"],
        true,
        false,
    );
    let receipt = BlockerReceipt::from_manifest(
        &man,
        ProofAttemptOutcome::Blocked,
        RchExecutionEvidence::new(Some("vmi-7".to_string()), Some("b-42".to_string())),
    );
    let json = serde_json::to_string(&receipt).expect("serialize");
    let back: BlockerReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, receipt);
}

// --- AC2 / AC4: deterministic golden Markdown, paste-ready ----------------------

#[test]
fn golden_blocked_peer_dirty_report() {
    let man = manifest(
        vec![excluded(
            "src/peer.rs",
            ExclusionReason::PeerDirtyUnselected,
        )],
        vec!["src/mine.rs"],
        vec!["src/mine.rs"],
        true,
        false,
    );
    let receipt = BlockerReceipt::from_manifest(
        &man,
        ProofAttemptOutcome::Blocked,
        RchExecutionEvidence::default(),
    );
    let expected = "## Clean-overlay proof receipt — blocked\n\
\n\
- Command intent: `cargo test --test foo`\n\
- HEAD: `deadbeefcafe`\n\
- Mode: enforced\n\
- Lane: RCH-only; no local Cargo fallback\n\
- RCH worker: n/a · build: n/a\n\
- Proof status: BLOCKED — the overlay refused to run; this attests no proof.\n\
\n\
### Included overlay paths (1)\n\
- `src/mine.rs`\n\
\n\
### Excluded paths (1)\n\
- `src/peer.rs` — peer-dirty (unselected)\n\
\n\
### Reservation evidence (1)\n\
- `src/mine.rs`\n\
\n\
### No-claim boundaries\n\
- This receipt attests only the listed overlay paths, not workspace health.\n";
    assert_eq!(receipt.render_markdown(), expected);
    // Deterministic.
    assert_eq!(receipt.render_markdown(), receipt.render_markdown());
}

#[test]
fn golden_unselected_untracked_report() {
    // An untracked, unselected path is peer dirt outside the overlay.
    let man = manifest(
        vec![excluded(
            "scratch/notes.txt",
            ExclusionReason::PeerDirtyUnselected,
        )],
        vec![],
        vec![],
        true,
        false,
    );
    let receipt = BlockerReceipt::from_manifest(
        &man,
        ProofAttemptOutcome::Blocked,
        RchExecutionEvidence::default(),
    );
    let expected = "## Clean-overlay proof receipt — blocked\n\
\n\
- Command intent: `cargo test --test foo`\n\
- HEAD: `deadbeefcafe`\n\
- Mode: enforced\n\
- Lane: RCH-only; no local Cargo fallback\n\
- RCH worker: n/a · build: n/a\n\
- Proof status: BLOCKED — the overlay refused to run; this attests no proof.\n\
\n\
### Included overlay paths (0)\n\
- _none_\n\
\n\
### Excluded paths (1)\n\
- `scratch/notes.txt` — peer-dirty (unselected)\n\
\n\
### Reservation evidence (0)\n\
- _none_\n\
\n\
### No-claim boundaries\n\
- This receipt attests only the listed overlay paths, not workspace health.\n";
    assert_eq!(receipt.render_markdown(), expected);
}

#[test]
fn golden_stale_progress_report_with_rch_ids() {
    let man = manifest(
        vec![],
        vec!["src/mine.rs"],
        vec!["src/mine.rs"],
        false,
        false,
    );
    let receipt = BlockerReceipt::from_manifest(
        &man,
        ProofAttemptOutcome::StaleProgress,
        RchExecutionEvidence::new(Some("vmi-1227854".to_string()), Some("job-9".to_string())),
    );
    let expected = "## Clean-overlay proof receipt — stale_progress\n\
\n\
- Command intent: `cargo test --test foo`\n\
- HEAD: `deadbeefcafe`\n\
- Mode: enforced\n\
- Lane: RCH-only; no local Cargo fallback\n\
- RCH worker: vmi-1227854 · build: job-9\n\
- Proof status: STALE-PROGRESS — RCH heartbeat fresh but build progress stalled; NOT a green proof.\n\
\n\
### Included overlay paths (1)\n\
- `src/mine.rs`\n\
\n\
### Excluded paths (0)\n\
- _none_\n\
\n\
### Reservation evidence (1)\n\
- `src/mine.rs`\n\
\n\
### No-claim boundaries\n\
- This receipt attests only the listed overlay paths, not workspace health.\n";
    assert_eq!(receipt.render_markdown(), expected);
}

// --- A1 -> A2 integration: real planner output drives the receipt --------------

#[test]
fn receipt_from_real_planner_blocked_overlay() {
    // Feed the real A1 planner a peer-dirty enforced request; its blocked
    // manifest must produce a Blocked receipt naming the peer-dirty path.
    let request = CleanOverlayRequest {
        head_commit: "abc123".to_string(),
        working_tree: vec![WorkingTreeEntry::new(
            "src/peer/thing.rs",
            PathChange::Modified,
        )],
        selected_paths: vec!["src/mine.rs".to_string()],
        reservations: vec![ReservationLease::new("src/mine.rs", true)],
        command_intent: "cargo test --lib".to_string(),
        report_only: false,
    };
    let man = plan_clean_overlay(&request);
    assert!(
        man.blocked,
        "peer dirt outside the overlay must block enforced runs"
    );

    let receipt = BlockerReceipt::from_manifest(
        &man,
        ProofAttemptOutcome::Green,
        RchExecutionEvidence::default(),
    );
    assert_eq!(receipt.outcome, ProofAttemptOutcome::Blocked);
    assert!(!receipt.proves_clean());
    assert!(receipt.peer_dirty_paths().contains(&"src/peer/thing.rs"));
    // The rendered report is non-empty and names the blocked status.
    assert!(receipt.render_markdown().contains("BLOCKED"));
}
