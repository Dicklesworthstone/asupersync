//! Deterministic blocked proof-loop e2e packet (PROOF-TRAFFIC A5).
//!
//! This module composes the A2 admission receipt, A3 clean-overlay handshake,
//! and A4 parking lot into one replayable, deterministic scenario. It is not a
//! live runner: callers provide fixtures, the module renders structured logs and
//! handoff bodies, and no path starts Cargo, shells out, creates branches,
//! creates worktrees, deletes files, or treats live RCH fleet state as proof.

use super::clean_overlay_planner::{
    CleanOverlayRequest, PathChange, ReservationLease, WorkingTreeEntry,
};
use super::proof_traffic_overlay_handshake::{
    ProofTrafficOverlayCapability, ProofTrafficOverlayHandshake, ProofTrafficOverlayHandshakeInput,
};
use super::proof_traffic_parking_lot::{
    ParkedProofAttempt, ProofTrafficParkingLot, ProofTrafficRetryPredicate,
};
use super::proof_traffic_receipt::{
    ProofTrafficActiveBuild, ProofTrafficAdmissionInput, ProofTrafficAdmissionReceipt,
    ProofTrafficBuildOwner, ProofTrafficCapabilityProbe, ProofTrafficDecision, ProofTrafficIntent,
    ProofTrafficQueueSnapshot,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Stable schema version for the A5 blocked-loop e2e packet.
pub const PROOF_TRAFFIC_BLOCKED_LOOP_E2E_SCHEMA_VERSION: &str = "proof-traffic-blocked-loop-e2e-v1";

/// Stable bead/scenario id for A5.
pub const PROOF_TRAFFIC_BLOCKED_LOOP_E2E_ID: &str = "asupersync-proof-traffic-control-kuyx64.5";

/// Deterministic fixture `HEAD` used by the A5 packet.
pub const PROOF_TRAFFIC_BLOCKED_LOOP_HEAD: &str = "1f6e579fcafebabe0000000000000000000000";

/// Deterministic focused proof command intent used by the A5 packet.
pub const PROOF_TRAFFIC_BLOCKED_LOOP_COMMAND: &str =
    "cargo test -p asupersync --test proof_traffic_blocked_loop_e2e_contract -- --nocapture";

/// Deterministic target directory for the A5 packet.
pub const PROOF_TRAFFIC_BLOCKED_LOOP_TARGET_DIR: &str =
    "${TMPDIR:-/tmp}/rch_target_proof_traffic_blocked_loop_e2e";

/// Owned dirty source path in the deterministic fixture.
pub const PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY: &str =
    "src/audit/proof_traffic_blocked_loop_e2e.rs";

/// Owned untracked test path in the deterministic fixture.
pub const PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_TEST: &str =
    "tests/proof_traffic_blocked_loop_e2e_contract.rs";

/// Peer poison path used to prove excluded dirt cannot enter admitted commands.
pub const PROOF_TRAFFIC_BLOCKED_LOOP_PEER_POISON: &str = "src/peer_poison_would_not_compile.rs";

const NO_CLAIM_BOUNDARIES: &[&str] = &[
    "No release-readiness claim.",
    "No broad workspace-health claim.",
    "No runtime-correctness claim.",
    "No performance-improvement claim.",
    "No live RCH fleet-availability claim.",
    "No local Cargo fallback approval.",
    "No peer-owned build cancellation authority.",
    "No permission to delete files, clean worktrees, create branches, or create worktrees.",
    "Deterministic fixtures are the correctness source; live RCH fleet state is operator evidence only.",
];

const FORBIDDEN_ADMITTED_COMMAND_TOKENS: &[&str] = &[
    "|| cargo",
    "; cargo",
    "\ncargo ",
    "run cargo locally",
    "local fallback allowed",
    "cancel peer-owned build",
    "cancel peer build",
    "git branch",
    "git checkout -b",
    "git switch -c",
    "git worktree",
    "worktree add",
    "git clone",
    "scratch clone",
    "git clean",
    "git reset",
    "rm -rf",
    "rm -r ",
    "rm -f ",
];

/// One structured decision log emitted by the A5 e2e packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficBlockedLoopStep {
    /// Stable fixture id.
    pub step_id: String,
    /// Input command intent. This is recorded, not executed.
    pub input_command: String,
    /// Selected paths for this proof attempt.
    pub selected_paths: Vec<String>,
    /// Reservation state summarized for handoff.
    pub reservation_state: String,
    /// Queue or planner snapshot summarized for handoff.
    pub queue_snapshot: String,
    /// A2/A3 decision produced by the composed receipt.
    pub decision: ProofTrafficDecision,
    /// Paste-ready handoff body for the relevant receipt.
    pub rendered_handoff: String,
    /// One explicit no-claim boundary tied to this step.
    pub no_claim_boundary: String,
    /// Proof command admitted by the receipt, if any.
    pub admitted_command: Option<String>,
    /// Replay or resume output for a future operator.
    pub replay_or_resume_command: String,
}

/// Deterministic handoff bundle emitted by the A5 packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficBlockedLoopArtifactBundle {
    /// JSON-serializable parking receipt used as the replay ledger.
    pub json_receipt: ProofTrafficParkingLot,
    /// Deterministic Markdown report.
    pub markdown_report: String,
    /// Agent Mail handoff body.
    pub agent_mail_body: String,
    /// `br comment` handoff body.
    pub br_comment_body: String,
    /// Replay/resume command or parked marker.
    pub replay_resume_command: String,
}

/// Deterministic A5 scenario packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficBlockedLoopScenario {
    /// Stable schema version.
    pub schema_version: String,
    /// Stable scenario id.
    pub scenario_id: String,
    /// Structured decision logs.
    pub steps: Vec<ProofTrafficBlockedLoopStep>,
    /// Parking lot for blocked/refused/stale attempts.
    pub parking_lot: ProofTrafficParkingLot,
    /// Operator-facing bundle: JSON receipt, Markdown, Agent Mail, `br`, resume.
    pub artifact_bundle: ProofTrafficBlockedLoopArtifactBundle,
    /// Peer poison paths that must never enter admitted proof commands.
    pub peer_poison_paths: Vec<String>,
    /// Rule for live RCH fleet state in this e2e.
    pub live_fleet_state_rule: String,
    /// Honest no-claim boundaries.
    pub no_claim_boundaries: Vec<String>,
}

impl ProofTrafficBlockedLoopScenario {
    /// Build the deterministic A5 fixture.
    #[must_use]
    pub fn fixture() -> Self {
        let admitted = overlay_handshake(
            "owned-dirty-admitted-control",
            vec![
                working_tree(PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY, PathChange::Modified),
                working_tree(PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_TEST, PathChange::Untracked),
            ],
            vec![
                PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY,
                PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_TEST,
            ],
            vec![
                lease(PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY),
                lease("tests/*.rs"),
            ],
            supported_overlay_capability(),
        );

        let peer_poison = overlay_handshake(
            "peer-poison-excluded",
            vec![
                working_tree(PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY, PathChange::Modified),
                working_tree(PROOF_TRAFFIC_BLOCKED_LOOP_PEER_POISON, PathChange::Modified),
            ],
            vec![PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY],
            vec![lease(PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY)],
            supported_overlay_capability(),
        );

        let missing_capability = overlay_handshake(
            "missing-overlay-capability",
            vec![working_tree(
                PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY,
                PathChange::Modified,
            )],
            vec![PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY],
            vec![lease(PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY)],
            unsupported_overlay_capability(),
        );

        let active_project_refusal = admission_receipt(
            "active-project-refusal",
            ProofTrafficQueueSnapshot::new(true, false, false, Vec::new()),
        );
        let progress_stale_peer = admission_receipt(
            "progress-stale-peer-build",
            ProofTrafficQueueSnapshot::new(
                false,
                false,
                false,
                vec![ProofTrafficActiveBuild::new(
                    "29887347701055984",
                    ProofTrafficBuildOwner::PeerOwned,
                    true,
                    true,
                    true,
                    "cargo test -p asupersync --test peer_lane".to_string(),
                )],
            ),
        );

        let parking_lot = ProofTrafficParkingLot::new(
            PROOF_TRAFFIC_BLOCKED_LOOP_E2E_ID,
            vec![
                parked_from_handshake(
                    "peer-poison-excluded",
                    "peer-poison-path",
                    &peer_poison,
                    "peer poison path clears or is selected by its owner",
                ),
                parked_from_handshake(
                    "missing-overlay-capability",
                    "capability-drift:clean-overlay",
                    &missing_capability,
                    "installed RCH exposes clean-overlay flags",
                ),
                parked_from_admission(
                    "active-project-refusal",
                    "active-project-exclusion",
                    &active_project_refusal,
                    "active_project_exclusion clears",
                )
                .with_exact_rch_command(remote_required_command()),
                parked_from_admission(
                    "progress-stale-peer-build",
                    "peer-stale:29887347701055984",
                    &progress_stale_peer,
                    "peer owner reports terminal output",
                )
                .with_exact_rch_command(remote_required_command()),
            ],
        );

        let steps = vec![
            step_from_handshake(
                "owned-dirty-admitted-control",
                "exclusive self reservations cover owned dirty and test paths",
                "empty overlay queue; no peer poison",
                &admitted,
                admitted.rendered_command.clone(),
            ),
            step_from_handshake(
                "peer-poison-excluded",
                "exclusive self reservation covers owned dirty path; peer poison is unselected",
                "planner sees peer poison path and fails closed",
                &peer_poison,
                parking_lot
                    .render_resume("peer-poison-excluded")
                    .unwrap_or_else(|| peer_poison.rendered_command.clone()),
            ),
            step_from_handshake(
                "missing-overlay-capability",
                "exclusive self reservation covers owned dirty path",
                "installed RCH clean-overlay capability missing",
                &missing_capability,
                parking_lot
                    .render_resume("missing-overlay-capability")
                    .unwrap_or_else(|| missing_capability.rendered_command.clone()),
            ),
            step_from_admission(
                "active-project-refusal",
                "selected paths are owned by this proof attempt",
                "active_project_exclusion=true",
                &active_project_refusal,
                parking_lot
                    .render_resume("active-project-refusal")
                    .unwrap_or_else(|| active_project_refusal.br_comment_body()),
            ),
            step_from_admission(
                "progress-stale-peer-build",
                "selected paths are owned by this proof attempt",
                "peer build 29887347701055984 heartbeat_fresh=true progress_stale=true",
                &progress_stale_peer,
                parking_lot
                    .render_resume("progress-stale-peer-build")
                    .unwrap_or_else(|| progress_stale_peer.br_comment_body()),
            ),
        ];

        let mut scenario = Self {
            schema_version: PROOF_TRAFFIC_BLOCKED_LOOP_E2E_SCHEMA_VERSION.to_string(),
            scenario_id: PROOF_TRAFFIC_BLOCKED_LOOP_E2E_ID.to_string(),
            steps,
            artifact_bundle: ProofTrafficBlockedLoopArtifactBundle {
                json_receipt: parking_lot.clone(),
                markdown_report: String::new(),
                agent_mail_body: String::new(),
                br_comment_body: String::new(),
                replay_resume_command: parking_lot
                    .render_resume("active-project-refusal")
                    .unwrap_or_else(|| "# PARKED: missing active-project-refusal".to_string()),
            },
            parking_lot,
            peer_poison_paths: vec![PROOF_TRAFFIC_BLOCKED_LOOP_PEER_POISON.to_string()],
            live_fleet_state_rule:
                "operator evidence only; deterministic fixtures are the correctness source"
                    .to_string(),
            no_claim_boundaries: NO_CLAIM_BOUNDARIES
                .iter()
                .map(|boundary| (*boundary).to_string())
                .collect(),
        };

        scenario.artifact_bundle.markdown_report = scenario.render_markdown();
        scenario.artifact_bundle.agent_mail_body = scenario.agent_mail_body();
        scenario.artifact_bundle.br_comment_body = scenario.br_comment_body();
        scenario
    }

    /// Render deterministic Markdown for the whole scenario.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("## Proof-traffic blocked-loop e2e - ");
        out.push_str(&self.scenario_id);
        out.push_str("\n\n");
        out.push_str(&format!(
            "- schema_version: `{}`\n- step_count: `{}`\n- live_fleet_state_rule: {}\n\n",
            self.schema_version,
            self.steps.len(),
            self.live_fleet_state_rule
        ));

        out.push_str("### steps\n");
        for step in &self.steps {
            out.push_str("- `");
            out.push_str(&step.step_id);
            out.push_str("` decision=`");
            out.push_str(step.decision.label());
            out.push_str("` selected=`");
            out.push_str(&step.selected_paths.join(","));
            out.push_str("` queue_snapshot=`");
            out.push_str(&step.queue_snapshot);
            out.push_str("`\n");
        }
        out.push('\n');

        push_string_section(&mut out, "peer_poison_paths", &self.peer_poison_paths);
        push_string_section(&mut out, "no_claim_boundaries", &self.no_claim_boundaries);
        out
    }

    /// Render Agent Mail body with structured fields first.
    #[must_use]
    pub fn agent_mail_body(&self) -> String {
        let mut out = String::new();
        out.push_str("proof_traffic_blocked_loop_e2e:\n");
        out.push_str(&format!(
            "- scenario_id: `{}`\n- schema_version: `{}`\n- step_count: `{}`\n",
            self.scenario_id,
            self.schema_version,
            self.steps.len()
        ));
        for step in &self.steps {
            out.push_str("- step: `");
            out.push_str(&step.step_id);
            out.push_str("` decision: `");
            out.push_str(step.decision.label());
            out.push_str("`\n");
        }
        out.push_str("- local_cargo_fallback_allowed: `false`\n");
        out.push_str("- branch_or_worktree_allowed: `false`\n");
        out.push_str("- file_deletion_allowed: `false`\n");
        out
    }

    /// Render `br comment` body with structured fields first.
    #[must_use]
    pub fn br_comment_body(&self) -> String {
        let mut out = String::new();
        out.push_str("Proof-traffic blocked-loop e2e\n\n");
        out.push_str(&format!(
            "- scenario_id: `{}`\n- step_count: `{}`\n- live_fleet_state_rule: {}\n",
            self.scenario_id,
            self.steps.len(),
            self.live_fleet_state_rule
        ));
        out
    }

    /// Admitted proof commands in deterministic step order.
    #[must_use]
    pub fn admitted_commands(&self) -> Vec<&str> {
        self.steps
            .iter()
            .filter_map(|step| step.admitted_command.as_deref())
            .collect()
    }

    /// Forbidden tokens found in admitted proof commands.
    #[must_use]
    pub fn forbidden_admitted_command_tokens(&self) -> Vec<&'static str> {
        let surface = self
            .admitted_commands()
            .into_iter()
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join("\n");
        FORBIDDEN_ADMITTED_COMMAND_TOKENS
            .iter()
            .copied()
            .filter(|token| surface.contains(token))
            .collect()
    }

    /// Whether any admitted command uses local Cargo fallback.
    #[must_use]
    pub fn uses_local_cargo_fallback(&self) -> bool {
        self.admitted_commands().into_iter().any(|command| {
            let lower = command.to_ascii_lowercase();
            lower.contains("|| cargo")
                || lower.contains("; cargo")
                || lower.contains("\ncargo ")
                || lower.contains("run cargo locally")
                || lower.contains("local fallback allowed")
                || (lower.contains("cargo") && !lower.contains("rch exec"))
        })
    }

    /// Peer poison paths that leaked into admitted proof commands.
    #[must_use]
    pub fn peer_poison_paths_in_admitted_commands(&self) -> Vec<String> {
        let admitted = self.admitted_commands();
        let mut leaked = BTreeSet::new();
        for path in &self.peer_poison_paths {
            if admitted.iter().any(|command| command.contains(path)) {
                leaked.insert(path.clone());
            }
        }
        leaked.into_iter().collect()
    }
}

/// Build the deterministic A5 fixture.
#[must_use]
pub fn proof_traffic_blocked_loop_fixture() -> ProofTrafficBlockedLoopScenario {
    ProofTrafficBlockedLoopScenario::fixture()
}

fn overlay_handshake(
    gate_id: &str,
    working_tree: Vec<WorkingTreeEntry>,
    selected_paths: Vec<&str>,
    reservations: Vec<ReservationLease>,
    capability: ProofTrafficOverlayCapability,
) -> ProofTrafficOverlayHandshake {
    let request = CleanOverlayRequest {
        head_commit: PROOF_TRAFFIC_BLOCKED_LOOP_HEAD.to_string(),
        working_tree,
        selected_paths: selected_paths
            .into_iter()
            .map(std::string::ToString::to_string)
            .collect(),
        reservations,
        command_intent: PROOF_TRAFFIC_BLOCKED_LOOP_COMMAND.to_string(),
        report_only: false,
    };
    let input = ProofTrafficOverlayHandshakeInput::new(
        gate_id,
        request,
        PROOF_TRAFFIC_BLOCKED_LOOP_TARGET_DIR,
        capability,
    );
    ProofTrafficOverlayHandshake::from_input(&input)
}

fn admission_receipt(
    gate_id: &str,
    queue: ProofTrafficQueueSnapshot,
) -> ProofTrafficAdmissionReceipt {
    let intent = ProofTrafficIntent::new(
        PROOF_TRAFFIC_BLOCKED_LOOP_HEAD,
        PROOF_TRAFFIC_BLOCKED_LOOP_COMMAND,
        PROOF_TRAFFIC_BLOCKED_LOOP_TARGET_DIR,
        vec![
            PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_DIRTY.to_string(),
            PROOF_TRAFFIC_BLOCKED_LOOP_OWNED_TEST.to_string(),
        ],
    );
    let input = ProofTrafficAdmissionInput::new(
        gate_id,
        intent,
        ProofTrafficCapabilityProbe::new(
            "rch-1.0.41-help",
            true,
            vec!["remote-required supported".to_string()],
        ),
        queue,
        false,
        false,
    );
    ProofTrafficAdmissionReceipt::decide(&input)
}

fn step_from_handshake(
    step_id: &str,
    reservation_state: &str,
    queue_snapshot: &str,
    receipt: &ProofTrafficOverlayHandshake,
    replay_or_resume_command: String,
) -> ProofTrafficBlockedLoopStep {
    ProofTrafficBlockedLoopStep {
        step_id: step_id.to_string(),
        input_command: receipt.command_intent.clone(),
        selected_paths: receipt.selected_paths.clone(),
        reservation_state: reservation_state.to_string(),
        queue_snapshot: queue_snapshot.to_string(),
        decision: receipt.decision,
        rendered_handoff: receipt.agent_mail_body(),
        no_claim_boundary: receipt
            .no_claim_boundaries
            .iter()
            .find(|boundary| boundary.contains("No local Cargo fallback"))
            .cloned()
            .unwrap_or_else(|| "No local Cargo fallback approval.".to_string()),
        admitted_command: receipt.admitted.then(|| receipt.rendered_command.clone()),
        replay_or_resume_command,
    }
}

fn step_from_admission(
    step_id: &str,
    reservation_state: &str,
    queue_snapshot: &str,
    receipt: &ProofTrafficAdmissionReceipt,
    replay_or_resume_command: String,
) -> ProofTrafficBlockedLoopStep {
    ProofTrafficBlockedLoopStep {
        step_id: step_id.to_string(),
        input_command: receipt.command_intent.clone(),
        selected_paths: receipt.selected_paths.clone(),
        reservation_state: reservation_state.to_string(),
        queue_snapshot: queue_snapshot.to_string(),
        decision: receipt.decision,
        rendered_handoff: receipt.agent_mail_body(),
        no_claim_boundary: receipt
            .no_claim_boundaries
            .iter()
            .find(|boundary| boundary.contains("No local Cargo fallback"))
            .cloned()
            .unwrap_or_else(|| "No local Cargo fallback approval.".to_string()),
        admitted_command: None,
        replay_or_resume_command,
    }
}

fn parked_from_handshake(
    attempt_id: &str,
    blocker_key: &str,
    receipt: &ProofTrafficOverlayHandshake,
    retry_condition: &str,
) -> ParkedProofAttempt {
    ParkedProofAttempt::new(
        attempt_id,
        blocker_key,
        &receipt.head_commit,
        &receipt.command_intent,
        &receipt.target_dir,
        receipt.decision,
        ProofTrafficRetryPredicate::new(
            format!("retry-{attempt_id}"),
            retry_condition,
            "fresh deterministic receipt plus terminal RCH output",
            false,
        ),
    )
    .with_blocker_marker(receipt.rendered_command.clone())
    .with_paths(
        receipt.included_paths.clone(),
        receipt.reservation_evidence.clone(),
    )
}

fn parked_from_admission(
    attempt_id: &str,
    blocker_key: &str,
    receipt: &ProofTrafficAdmissionReceipt,
    retry_condition: &str,
) -> ParkedProofAttempt {
    ParkedProofAttempt::new(
        attempt_id,
        blocker_key,
        &receipt.head_commit,
        &receipt.command_intent,
        &receipt.target_dir,
        receipt.decision,
        ProofTrafficRetryPredicate::new(
            format!("retry-{attempt_id}"),
            retry_condition,
            "fresh RCH terminal output",
            false,
        ),
    )
    .with_blocker_marker(format!(
        "# PARKED: {}; no proof command emitted",
        receipt.rch_worker_or_refusal
    ))
    .with_paths(
        receipt.selected_paths.clone(),
        receipt.selected_paths.clone(),
    )
}

fn supported_overlay_capability() -> ProofTrafficOverlayCapability {
    ProofTrafficOverlayCapability::from_rch_exec_help(
        "rch-1.0.99-help",
        r"Options:
  -b, --base=<HEAD>
      --clean-overlay
  -o, --overlay-path=<PATH>
      --no-overlay
",
    )
}

fn unsupported_overlay_capability() -> ProofTrafficOverlayCapability {
    ProofTrafficOverlayCapability::from_rch_exec_help(
        "rch-1.0.41-help",
        r"Options:
  -v, --verbose
  Examples:
  --base HEAD
  --clean-overlay
  --overlay-path PATH
  --no-overlay
",
    )
}

fn remote_required_command() -> String {
    format!(
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=\"{}\" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' {}",
        PROOF_TRAFFIC_BLOCKED_LOOP_TARGET_DIR, PROOF_TRAFFIC_BLOCKED_LOOP_COMMAND
    )
}

fn working_tree(path: &str, change: PathChange) -> WorkingTreeEntry {
    WorkingTreeEntry::new(path, change)
}

fn lease(pattern: &str) -> ReservationLease {
    ReservationLease::new(pattern, true)
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
