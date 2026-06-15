//! Focused clean-overlay proof E2E (PROOF-ORCH A3,
//! bead asupersync-proof-orch-clean-overlay-5ve2ao.3).
//!
//! This is the end-to-end proof that a focused clean-overlay run **includes the
//! selected dirty/untracked work and excludes unrelated dirty peer work**. It
//! drives each scenario through the full A1→A3→A2 chain:
//!
//! ```text
//! plan_clean_overlay (A1)  ->  OverlayProofCommand (A3)  ->  BlockerReceipt (A2)
//! ```
//!
//! The construction is deterministic and hermetic: each scenario is a fixed
//! [`CleanOverlayRequest`]. In the exclusion scenarios the unrelated peer path is
//! a *poison* path — `src/peer_poison_would_not_compile.rs` — that would break
//! the build if RCH synced the whole working tree. The E2E proves the overlay
//! mechanism scopes it out: it never appears in the emitted RCH command. The
//! test asserts the *mechanism* only and makes no broad runtime-correctness
//! claim (AC5).
//!
//! Run as an integration test (the lib is linked in non-test mode), so these
//! assertions are immune to peer `#[cfg(test)]` breakage in the shared tree:
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test proof_orch_clean_overlay_e2e -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::audit::blocker_receipt::{
    BlockerReceipt, ProofAttemptOutcome, RchExecutionEvidence,
};
use asupersync::audit::clean_overlay_planner::{
    CleanOverlayManifest, CleanOverlayRequest, ExclusionReason, PathChange, ReservationLease,
    WorkingTreeEntry, plan_clean_overlay,
};
use asupersync::audit::overlay_proof_command::OverlayProofCommand;

const HEAD: &str = "5ve2ao3c0ffee00000000000000000000000000a";
const INTENT: &str = "cargo test --test slice_under_proof -- --nocapture";
const SELECTED_DIRTY: &str = "src/runtime/scheduler/three_lane.rs";
const SELECTED_UNTRACKED: &str = "tests/proof_orch_clean_overlay_e2e_slice.rs";
/// Unrelated peer path that would fail compilation if RCH synced it. The overlay
/// mechanism must keep it out of the emitted command.
const POISON: &str = "src/peer_poison_would_not_compile.rs";

fn wte(path: &str, change: PathChange) -> WorkingTreeEntry {
    WorkingTreeEntry::new(path, change)
}

fn lease(pattern: &str) -> ReservationLease {
    ReservationLease::new(pattern, true)
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

fn plan(request: &CleanOverlayRequest) -> (CleanOverlayManifest, OverlayProofCommand) {
    let manifest = plan_clean_overlay(request);
    let command = OverlayProofCommand::from_manifest(&manifest);
    (manifest, command)
}

/// Invariants that must hold for *every* scenario, admitted or not (AC3, AC4,
/// AC5): RCH-only with no local Cargo fallback, no destructive orchestration,
/// and the honest no-claim boundary present.
fn assert_universal_invariants(command: &OverlayProofCommand) {
    // AC4 — no branch, worktree, scratch clone, rm, git clean, or git reset.
    assert!(
        command.forbidden_operations().is_empty(),
        "forbidden orchestration tokens leaked: {:?}\ncommand: {}\nrepro: {}",
        command.forbidden_operations(),
        command.rendered_command(),
        command.reproduction_command()
    );
    // AC3 — never a local Cargo fallback.
    assert!(
        !command.uses_local_cargo_fallback(),
        "command surface suggested a local Cargo fallback:\n{}\n{}",
        command.rendered_command(),
        command.reproduction_command()
    );
    // AC3 — the reproduction command is deterministic and RCH-routed.
    assert!(
        command.reproduction_command().contains("rch exec"),
        "reproduction command must route through rch exec: {}",
        command.reproduction_command()
    );
    assert!(
        !command
            .reproduction_command()
            .to_lowercase()
            .contains("locally"),
        "reproduction command must not suggest running locally: {}",
        command.reproduction_command()
    );
    // AC5 — scoped to the mechanism; the no-claim boundary is honest about not
    // attesting broad workspace health.
    assert!(
        command
            .no_claim_boundaries
            .iter()
            .any(|boundary| boundary.contains("no workspace-wide health claim")),
        "missing honest no-broad-health boundary: {:?}",
        command.no_claim_boundaries
    );
}

// ---------------------------------------------------------------------------
// AC1.1 — clean HEAD: a selected path that is clean at HEAD is overlaid and the
// run is admitted with no exclusions.
// ---------------------------------------------------------------------------
#[test]
fn scenario_clean_head_admits_selected_clean_path() {
    let (manifest, command) = plan(&request(vec![], &[SELECTED_DIRTY], vec![], false));

    assert!(!manifest.blocked, "clean HEAD must not block");
    assert!(command.admitted, "clean-HEAD overlay must be admitted");
    assert!(
        command.excluded_paths.is_empty(),
        "no exclusions on a clean tree"
    );
    assert_eq!(command.overlay_paths, vec![SELECTED_DIRTY.to_string()]);

    let rendered = command.rendered_command();
    assert!(
        rendered.contains("rch exec"),
        "must route through RCH: {rendered}"
    );
    assert!(
        rendered.contains(HEAD),
        "must pin the HEAD base: {rendered}"
    );
    assert!(
        rendered.contains(INTENT),
        "must carry the validation intent: {rendered}"
    );
    assert!(
        rendered.contains(SELECTED_DIRTY),
        "must overlay the selected path: {rendered}"
    );

    assert_universal_invariants(&command);
}

// ---------------------------------------------------------------------------
// AC1.2 — selected dirty file inclusion: a reserved, selected dirty file is
// overlaid and the run is admitted.
// ---------------------------------------------------------------------------
#[test]
fn scenario_selected_dirty_file_included() {
    let (manifest, command) = plan(&request(
        vec![wte(SELECTED_DIRTY, PathChange::Modified)],
        &[SELECTED_DIRTY],
        vec![lease(SELECTED_DIRTY)],
        false,
    ));

    assert!(!manifest.blocked, "reserved selected dirt must not block");
    assert!(command.admitted, "reserved selected dirt must be admitted");
    assert_eq!(command.overlay_paths, vec![SELECTED_DIRTY.to_string()]);
    assert!(
        command
            .reservation_evidence
            .contains(&SELECTED_DIRTY.to_string()),
        "reservation evidence must justify the inclusion: {:?}",
        command.reservation_evidence
    );

    let rendered = command.rendered_command();
    assert!(
        rendered.contains(&format!("--overlay-path {SELECTED_DIRTY}")),
        "selected dirty file must be in the overlay scope: {rendered}"
    );

    assert_universal_invariants(&command);
}

// ---------------------------------------------------------------------------
// AC1.3 — unrelated dirty file exclusion: a poison peer-dirty file (unselected,
// unreserved) is excluded as peer dirt; the run fails closed and the poison
// never reaches the emitted command — even though the selected path is still
// correctly classified as included.
// ---------------------------------------------------------------------------
#[test]
fn scenario_unrelated_dirty_file_excluded_and_fails_closed() {
    let (manifest, command) = plan(&request(
        vec![
            wte(SELECTED_DIRTY, PathChange::Modified),
            wte(POISON, PathChange::Modified),
        ],
        &[SELECTED_DIRTY],
        vec![lease(SELECTED_DIRTY)],
        false,
    ));

    // The selected path is still correctly recognized as overlay-eligible...
    assert!(
        manifest
            .included_paths
            .contains(&SELECTED_DIRTY.to_string()),
        "selected path must be classified included even amid peer dirt: {:?}",
        manifest.included_paths
    );
    // ...but unrelated peer dirt fails the enforced run closed.
    assert!(
        manifest.blocked,
        "peer dirt must fail an enforced run closed"
    );
    assert!(!command.admitted, "blocked overlay must not be admitted");
    assert_eq!(
        command
            .excluded_paths
            .iter()
            .find(|excluded| excluded.path == POISON)
            .map(|excluded| excluded.reason),
        Some(ExclusionReason::PeerDirtyUnselected),
        "poison path must be excluded as peer dirt"
    );

    // The crux: the poison path NEVER appears in the emitted RCH command, so it
    // can never reach the compiler.
    let rendered = command.rendered_command();
    assert!(
        !rendered.contains(POISON),
        "poison peer path must never reach the RCH command: {rendered}"
    );
    assert!(
        rendered.starts_with("# BLOCKED"),
        "blocked run must emit no proof invocation: {rendered}"
    );

    // The downstream A2 receipt forces a fail-closed Blocked outcome regardless
    // of any optimistic caller hint.
    let receipt = BlockerReceipt::from_manifest(
        &manifest,
        ProofAttemptOutcome::Green,
        RchExecutionEvidence::default(),
    );
    assert_eq!(receipt.outcome, ProofAttemptOutcome::Blocked);
    assert!(!receipt.proves_clean(), "a blocked overlay proves nothing");
    assert!(
        receipt.peer_dirty_paths().contains(&POISON),
        "receipt must attribute the poison path to peer dirt: {:?}",
        receipt.peer_dirty_paths()
    );

    assert_universal_invariants(&command);
}

// ---------------------------------------------------------------------------
// AC1.4 — selected untracked file inclusion: a reserved, selected untracked file
// is overlaid and the run is admitted.
// ---------------------------------------------------------------------------
#[test]
fn scenario_selected_untracked_file_included() {
    let (manifest, command) = plan(&request(
        vec![wte(SELECTED_UNTRACKED, PathChange::Untracked)],
        &[SELECTED_UNTRACKED],
        vec![lease(SELECTED_UNTRACKED)],
        false,
    ));

    assert!(
        !manifest.blocked,
        "reserved selected untracked file must not block"
    );
    assert!(
        command.admitted,
        "reserved selected untracked file must be admitted"
    );
    assert_eq!(command.overlay_paths, vec![SELECTED_UNTRACKED.to_string()]);

    let rendered = command.rendered_command();
    assert!(
        rendered.contains(&format!("--overlay-path {SELECTED_UNTRACKED}")),
        "selected untracked file must be in the overlay scope: {rendered}"
    );

    assert_universal_invariants(&command);
}

// ---------------------------------------------------------------------------
// AC1.5 — unselected untracked file refusal: an untracked peer file (unselected,
// unreserved) is refused; the run fails closed and the file never reaches the
// emitted command.
// ---------------------------------------------------------------------------
#[test]
fn scenario_unselected_untracked_file_refused() {
    let (manifest, command) = plan(&request(
        vec![wte(POISON, PathChange::Untracked)],
        &[],
        vec![],
        false,
    ));

    assert!(
        manifest.blocked,
        "untracked peer file must fail an enforced run closed"
    );
    assert!(!command.admitted, "refused overlay must not be admitted");
    assert_eq!(
        command
            .excluded_paths
            .iter()
            .find(|excluded| excluded.path == POISON)
            .map(|excluded| excluded.reason),
        Some(ExclusionReason::PeerDirtyUnselected),
        "untracked peer file must be refused as peer dirt"
    );
    assert!(
        !command.rendered_command().contains(POISON),
        "refused untracked file must never reach the RCH command: {}",
        command.rendered_command()
    );

    assert_universal_invariants(&command);
}

// ---------------------------------------------------------------------------
// AC2 — logs and artifacts identify selected paths, excluded paths, HEAD,
// reservations, and the exact RCH command.
// ---------------------------------------------------------------------------
#[test]
fn report_identifies_selection_exclusion_head_reservations_and_command() {
    let (_manifest, command) = plan(&request(
        vec![
            wte(SELECTED_DIRTY, PathChange::Modified),
            wte(POISON, PathChange::Modified),
        ],
        &[SELECTED_DIRTY],
        vec![lease(SELECTED_DIRTY)],
        true, // report-only: a dry-run artifact that still surfaces the decision
    ));

    let report = command.render_report();
    // Emit the artifact to the test log (AC2 — "logs and artifacts").
    println!("{report}");

    assert!(report.contains(HEAD), "report must identify HEAD");
    assert!(
        report.contains(SELECTED_DIRTY),
        "report must identify the selected path"
    );
    assert!(
        report.contains(POISON),
        "report must identify the excluded peer path"
    );
    assert!(
        report.contains("peer-dirty (unselected)"),
        "report must identify the exclusion reason"
    );
    assert!(
        report.contains(SELECTED_DIRTY) && report.contains("Reservation evidence"),
        "report must identify reservation evidence"
    );
    assert!(
        report.contains(&command.rendered_command()),
        "report must embed the exact RCH command"
    );
    assert!(
        report.contains(&command.reproduction_command()),
        "report must embed the reproduction command"
    );
    assert!(
        report.contains("RCH-only; no local Cargo fallback"),
        "report must state the RCH-only lane"
    );

    assert_universal_invariants(&command);
}

// ---------------------------------------------------------------------------
// AC3 — the failure reproduction command is deterministic and routes through
// RCH (never a local Cargo fallback), for a blocked run.
// ---------------------------------------------------------------------------
#[test]
fn blocked_run_reproduction_is_deterministic_and_rch_routed() {
    let scenario = || {
        plan(&request(
            vec![wte(POISON, PathChange::Modified)],
            &[SELECTED_DIRTY],
            vec![lease(SELECTED_DIRTY)],
            false,
        ))
    };
    let (_m1, c1) = scenario();
    let (_m2, c2) = scenario();

    assert!(!c1.admitted, "peer dirt must block");
    // Determinism: identical inputs render identical commands.
    assert_eq!(c1.rendered_command(), c2.rendered_command());
    assert_eq!(c1.reproduction_command(), c2.reproduction_command());

    let repro = c1.reproduction_command();
    assert!(
        repro.contains("rch exec"),
        "repro must be RCH-routed: {repro}"
    );
    assert!(
        repro.contains("proof_orch_clean_overlay_e2e"),
        "blocked repro must re-run the focused E2E proof: {repro}"
    );
    assert!(!c1.uses_local_cargo_fallback());

    assert_universal_invariants(&c1);
}

// ---------------------------------------------------------------------------
// AC4 — across an admitted run with multiple overlay paths, no branch, worktree,
// scratch clone, rm, git clean, or git reset appears anywhere in the
// orchestration surface.
// ---------------------------------------------------------------------------
#[test]
fn orchestration_surface_is_free_of_destructive_operations() {
    let (_manifest, command) = plan(&request(
        vec![
            wte(SELECTED_DIRTY, PathChange::Modified),
            wte(SELECTED_UNTRACKED, PathChange::Untracked),
        ],
        &[SELECTED_DIRTY, SELECTED_UNTRACKED],
        vec![lease(SELECTED_DIRTY), lease(SELECTED_UNTRACKED)],
        false,
    ));

    assert!(command.admitted);
    // The "orchestration" is the actual command surface (the command an operator
    // runs plus the reproduction command) — NOT the report prose, which
    // legitimately *disclaims* branches/worktrees/clones in the no-claim
    // boundaries. The builder's own scan covers exactly that surface.
    assert!(
        command.forbidden_operations().is_empty(),
        "forbidden operations leaked: {:?}",
        command.forbidden_operations()
    );
    let surface = format!(
        "{}\n{}",
        command.rendered_command(),
        command.reproduction_command()
    );
    for forbidden in [
        "git branch",
        "worktree",
        "git clone",
        "git clean",
        "git reset",
        "rm -rf",
        "rm -r ",
        "rm -f ",
        "checkout -b",
        "scratch clone",
    ] {
        assert!(
            !surface.contains(forbidden),
            "destructive/branching token `{forbidden}` leaked into the orchestration command surface"
        );
    }

    assert_universal_invariants(&command);
}

// ---------------------------------------------------------------------------
// AC5 — the proof is scoped to the clean-overlay mechanism and makes no broad
// runtime-correctness claim. Even an admitted command attests only the listed
// overlay paths.
// ---------------------------------------------------------------------------
#[test]
fn proof_is_scoped_to_mechanism_only() {
    let (_manifest, command) = plan(&request(
        vec![wte(SELECTED_DIRTY, PathChange::Modified)],
        &[SELECTED_DIRTY],
        vec![lease(SELECTED_DIRTY)],
        false,
    ));

    let report = command.render_report();
    assert!(
        command
            .no_claim_boundaries
            .iter()
            .any(|b| b.contains("no workspace-wide health claim")),
        "boundaries must disclaim workspace-wide health"
    );
    assert!(
        command
            .no_claim_boundaries
            .iter()
            .any(|b| b.contains("RCH-only")),
        "boundaries must record the RCH-only constraint"
    );
    // The report never claims broad correctness — only the overlay slice.
    assert!(
        !report.to_lowercase().contains("workspace is healthy")
            && !report.to_lowercase().contains("all tests pass"),
        "report must not claim broad workspace health: {report}"
    );

    assert_universal_invariants(&command);
}
