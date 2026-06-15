//! Proof-traffic admission receipt schema (PROOF-TRAFFIC A2).
//!
//! This module is the pure, deterministic admission layer between an agent's
//! focused proof intent and an RCH proof run. It does not inspect live RCH state
//! itself and it never starts Cargo. Callers pass a compact queue/capability
//! snapshot, and [`ProofTrafficAdmissionReceipt::decide`] returns the fail-closed
//! operator receipt that should be pasted into Agent Mail or a `br` comment.
//!
//! The taxonomy intentionally distinguishes a queue wait from a refusal or a
//! peer-owned stale build. None of those states is green proof evidence, and no
//! decision path recommends local Cargo fallback, peer build cancellation,
//! branch/worktree isolation, or file deletion.

use serde::{Deserialize, Serialize};

/// Stable schema version for proof-traffic A2 admission receipts.
pub const PROOF_TRAFFIC_ADMISSION_SCHEMA_VERSION: &str = "proof-traffic-admission-receipt-v1";

const NO_CLAIM_BOUNDARIES: &[&str] = &[
    "No release-readiness claim.",
    "No broad workspace-health claim.",
    "No runtime-correctness claim.",
    "No performance-improvement claim.",
    "No live RCH fleet-availability claim.",
    "No local Cargo fallback approval.",
    "No peer-owned build cancellation authority.",
    "No permission to delete files, clean worktrees, create branches, or create worktrees.",
    "No claim that documented clean-overlay flags are available unless installed capability evidence says they are supported.",
];

const FORBIDDEN_RECOMMENDATION_TOKENS: &[&str] = &[
    "|| cargo",
    "; cargo",
    "\ncargo ",
    "local cargo fallback allowed",
    "run cargo locally",
    "cancel peer-owned build",
    "cancel peer build",
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

/// Exhaustive proof-traffic admission taxonomy for focused RCH proof intents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofTrafficDecision {
    /// No active blockers are present; a remote-required focused proof may run.
    RunNow,
    /// Healthy active work is ahead of this proof; queue or wait for it.
    QueueWait,
    /// The attempt must be parked and rerun after same-project or health
    /// pressure clears.
    ParkRerunRequired,
    /// A peer-owned stale-progress build blocks trustworthy proof admission.
    BlockedByPeer,
    /// The installed RCH capability surface cannot support the requested proof
    /// shape.
    BlockedByCapabilityDrift,
    /// `RCH_REQUIRE_REMOTE=1` refused before assigning a worker.
    RemoteRequiredRefused,
    /// Dry-run/report-only receipt; no proof command is admitted.
    ReportOnly,
}

impl ProofTrafficDecision {
    /// Stable machine label used in JSON, Markdown, Agent Mail, and `br`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RunNow => "run-now",
            Self::QueueWait => "queue-wait",
            Self::ParkRerunRequired => "park-rerun-required",
            Self::BlockedByPeer => "blocked-by-peer",
            Self::BlockedByCapabilityDrift => "blocked-by-capability-drift",
            Self::RemoteRequiredRefused => "remote-required-refused",
            Self::ReportOnly => "report-only",
        }
    }

    /// Whether this decision admits a proof run immediately.
    #[must_use]
    pub const fn admits_run_now(self) -> bool {
        matches!(self, Self::RunNow)
    }

    /// Whether this decision is an explicit block or refusal.
    #[must_use]
    pub const fn is_blocked(self) -> bool {
        matches!(
            self,
            Self::BlockedByPeer | Self::BlockedByCapabilityDrift | Self::RemoteRequiredRefused
        )
    }
}

/// Ownership classification for an active RCH build observed in the queue
/// snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofTrafficBuildOwner {
    /// Build belongs to the current agent / same proof lane.
    SelfOwned,
    /// Build belongs to another agent and must be treated as handoff evidence.
    PeerOwned,
    /// Owner could not be determined from the snapshot.
    Unknown,
}

/// A single active RCH build row relevant to proof admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficActiveBuild {
    /// Stable RCH build/job id surfaced by the queue snapshot.
    pub build_id: String,
    /// Agent ownership classification for the build.
    pub owner: ProofTrafficBuildOwner,
    /// True when the worker heartbeat is fresh enough to trust as liveness.
    pub heartbeat_fresh: bool,
    /// True when build progress is stale despite heartbeat/liveness signals.
    pub progress_stale: bool,
    /// True when worker health preflight says the worker may accept work.
    pub worker_healthy: bool,
    /// Recorded proof command intent for operator context.
    pub command_intent: String,
}

impl ProofTrafficActiveBuild {
    /// Construct an active build row.
    #[must_use]
    pub fn new(
        build_id: impl Into<String>,
        owner: ProofTrafficBuildOwner,
        heartbeat_fresh: bool,
        progress_stale: bool,
        worker_healthy: bool,
        command_intent: impl Into<String>,
    ) -> Self {
        Self {
            build_id: build_id.into(),
            owner,
            heartbeat_fresh,
            progress_stale,
            worker_healthy,
            command_intent: command_intent.into(),
        }
    }

    /// Whether this row represents heartbeat-fresh but progress-stale work.
    #[must_use]
    pub const fn is_stale_progress(&self) -> bool {
        self.heartbeat_fresh && self.progress_stale
    }
}

/// Installed RCH capability evidence used by admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficCapabilityProbe {
    /// Installed probe/version string, for example `rch-1.0.41-help`.
    pub capability_probe_version: String,
    /// Whether the installed `rch exec` supports clean-overlay command flags.
    pub clean_overlay_supported: bool,
    /// Deterministic operator findings copied into receipts.
    pub capability_findings: Vec<String>,
}

impl ProofTrafficCapabilityProbe {
    /// Construct a capability probe row with sorted, de-duplicated findings.
    #[must_use]
    pub fn new(
        capability_probe_version: impl Into<String>,
        clean_overlay_supported: bool,
        capability_findings: Vec<String>,
    ) -> Self {
        Self {
            capability_probe_version: capability_probe_version.into(),
            clean_overlay_supported,
            capability_findings: sorted_unique(capability_findings),
        }
    }
}

/// Queue and refusal snapshot used by proof-traffic admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficQueueSnapshot {
    /// True when same-project active-work exclusion is currently blocking
    /// immediate admission.
    pub active_project_exclusion: bool,
    /// True when `RCH_REQUIRE_REMOTE=1` refused before worker assignment.
    pub remote_required_refused: bool,
    /// True when worker-health preflight refused admission.
    pub worker_health_refusal: bool,
    /// Active builds visible to the admission receipt.
    pub active_builds: Vec<ProofTrafficActiveBuild>,
}

impl ProofTrafficQueueSnapshot {
    /// Construct a queue snapshot with active builds sorted by build id.
    #[must_use]
    pub fn new(
        active_project_exclusion: bool,
        remote_required_refused: bool,
        worker_health_refusal: bool,
        active_builds: Vec<ProofTrafficActiveBuild>,
    ) -> Self {
        let mut active_builds = active_builds;
        active_builds.sort_by(|left, right| left.build_id.cmp(&right.build_id));
        Self {
            active_project_exclusion,
            remote_required_refused,
            worker_health_refusal,
            active_builds,
        }
    }

    /// Empty, healthy queue snapshot.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            active_project_exclusion: false,
            remote_required_refused: false,
            worker_health_refusal: false,
            active_builds: Vec::new(),
        }
    }
}

/// Focused proof intent submitted to admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficIntent {
    /// `HEAD` commit the proof intent is based on.
    pub head_commit: String,
    /// Cargo command intent; admission records it but does not run it.
    pub command_intent: String,
    /// Isolated `CARGO_TARGET_DIR` intended for the focused proof.
    pub target_dir: String,
    /// Selected owned paths the proof intends to validate.
    pub selected_paths: Vec<String>,
}

impl ProofTrafficIntent {
    /// Construct a proof intent with selected paths sorted and de-duplicated.
    #[must_use]
    pub fn new(
        head_commit: impl Into<String>,
        command_intent: impl Into<String>,
        target_dir: impl Into<String>,
        selected_paths: Vec<String>,
    ) -> Self {
        Self {
            head_commit: head_commit.into(),
            command_intent: command_intent.into(),
            target_dir: target_dir.into(),
            selected_paths: sorted_unique(selected_paths),
        }
    }
}

/// Full input to [`ProofTrafficAdmissionReceipt::decide`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficAdmissionInput {
    /// Stable receipt/gate id, usually the bead id.
    pub gate_id: String,
    /// Focused proof intent.
    pub intent: ProofTrafficIntent,
    /// Installed RCH capability evidence.
    pub capability: ProofTrafficCapabilityProbe,
    /// Current queue/refusal snapshot.
    pub queue: ProofTrafficQueueSnapshot,
    /// Whether this proof depends on clean-overlay command support.
    pub clean_overlay_required: bool,
    /// Whether the caller requested report-only dry-run mode.
    pub report_only: bool,
}

impl ProofTrafficAdmissionInput {
    /// Construct a proof-traffic admission input.
    #[must_use]
    pub fn new(
        gate_id: impl Into<String>,
        intent: ProofTrafficIntent,
        capability: ProofTrafficCapabilityProbe,
        queue: ProofTrafficQueueSnapshot,
        clean_overlay_required: bool,
        report_only: bool,
    ) -> Self {
        Self {
            gate_id: gate_id.into(),
            intent,
            capability,
            queue,
            clean_overlay_required,
            report_only,
        }
    }
}

/// Deterministic proof-traffic admission receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTrafficAdmissionReceipt {
    /// Stable schema version.
    pub schema_version: String,
    /// Stable receipt/gate id, usually the bead id.
    pub gate_id: String,
    /// Fail-closed admission decision.
    pub decision: ProofTrafficDecision,
    /// `HEAD` commit the proof intent is based on.
    pub head_commit: String,
    /// Cargo command intent; recorded, not run by the receipt.
    pub command_intent: String,
    /// Isolated `CARGO_TARGET_DIR` for the eventual RCH proof.
    pub target_dir: String,
    /// Selected owned paths the proof intends to validate.
    pub selected_paths: Vec<String>,
    /// Installed probe/version string.
    pub capability_probe_version: String,
    /// Deterministic capability findings copied from the probe.
    pub capability_findings: Vec<String>,
    /// Active RCH build ids visible to the admission decision.
    pub active_build_ids: Vec<String>,
    /// Compact worker/refusal summary for handoff.
    pub rch_worker_or_refusal: String,
    /// Condition that must clear before a parked/refused proof is rerun.
    pub retry_condition: String,
    /// Operator action that follows from the decision.
    pub recommended_operator_action: String,
    /// Whether this receipt admits a remote-required proof immediately.
    pub proof_may_run_now: bool,
    /// Proof traffic is RCH-only; this is always false.
    pub local_cargo_fallback_allowed: bool,
    /// Peer-owned builds are handoff evidence only; this is always false.
    pub peer_build_cancellation_allowed: bool,
    /// Branch/worktree isolation is forbidden for this repo; this is always false.
    pub branch_or_worktree_allowed: bool,
    /// File deletion is forbidden for this receipt; this is always false.
    pub file_deletion_allowed: bool,
    /// Honest non-claims copied into Markdown/Agent Mail/`br` bodies.
    pub no_claim_boundaries: Vec<String>,
}

impl ProofTrafficAdmissionReceipt {
    /// Decide proof admission from a caller-provided snapshot.
    ///
    /// Decision order is fail-closed:
    ///
    /// 1. report-only dry run;
    /// 2. unsupported clean-overlay capability when required;
    /// 3. remote-required refusal;
    /// 4. peer-owned stale-progress blocker;
    /// 5. active-project / worker-health / self-owned stale-progress pressure;
    /// 6. healthy active queue wait;
    /// 7. run now.
    #[must_use]
    pub fn decide(input: &ProofTrafficAdmissionInput) -> Self {
        let decision = classify(input);
        let active_build_ids = input
            .queue
            .active_builds
            .iter()
            .map(|build| build.build_id.clone())
            .collect::<Vec<_>>();
        let rch_worker_or_refusal = rch_worker_or_refusal(input, decision);
        let retry_condition = retry_condition(input, decision);
        let recommended_operator_action = recommended_operator_action(input, decision);

        Self {
            schema_version: PROOF_TRAFFIC_ADMISSION_SCHEMA_VERSION.to_string(),
            gate_id: input.gate_id.clone(),
            decision,
            head_commit: input.intent.head_commit.clone(),
            command_intent: input.intent.command_intent.clone(),
            target_dir: input.intent.target_dir.clone(),
            selected_paths: input.intent.selected_paths.clone(),
            capability_probe_version: input.capability.capability_probe_version.clone(),
            capability_findings: input.capability.capability_findings.clone(),
            active_build_ids,
            rch_worker_or_refusal,
            retry_condition,
            recommended_operator_action,
            proof_may_run_now: decision.admits_run_now(),
            local_cargo_fallback_allowed: false,
            peer_build_cancellation_allowed: false,
            branch_or_worktree_allowed: false,
            file_deletion_allowed: false,
            no_claim_boundaries: NO_CLAIM_BOUNDARIES
                .iter()
                .map(|boundary| (*boundary).to_string())
                .collect(),
        }
    }

    /// Render a deterministic operator Markdown report.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("## Proof-traffic admission receipt - ");
        out.push_str(self.decision.label());
        out.push_str("\n\n");
        self.push_handoff_fields(&mut out);
        out.push('\n');
        push_path_section(&mut out, "selected_paths", &self.selected_paths);
        push_string_section(&mut out, "capability_findings", &self.capability_findings);
        push_string_section(&mut out, "active_build_ids", &self.active_build_ids);
        out.push_str("### no_claim_boundaries\n");
        for boundary in &self.no_claim_boundaries {
            out.push_str("- ");
            out.push_str(boundary);
            out.push('\n');
        }
        out
    }

    /// Render the Agent Mail handoff body with structured fields first.
    #[must_use]
    pub fn agent_mail_body(&self) -> String {
        let mut out = String::new();
        out.push_str("proof_traffic_admission_receipt:\n");
        self.push_handoff_fields(&mut out);
        out
    }

    /// Render the `br comment` handoff body with structured fields first.
    #[must_use]
    pub fn br_comment_body(&self) -> String {
        let mut out = String::new();
        out.push_str("Proof-traffic admission receipt\n\n");
        self.push_handoff_fields(&mut out);
        out
    }

    /// Forbidden recommendation tokens found in the decision/action surface.
    ///
    /// The scan intentionally focuses on recommendation fields, not the
    /// no-claim boundaries, because the boundaries must mention forbidden
    /// categories while never recommending them.
    #[must_use]
    pub fn forbidden_recommendations(&self) -> Vec<&'static str> {
        let surface = format!(
            "{}\n{}\n{}",
            self.rch_worker_or_refusal, self.retry_condition, self.recommended_operator_action
        )
        .to_ascii_lowercase();
        FORBIDDEN_RECOMMENDATION_TOKENS
            .iter()
            .copied()
            .filter(|token| surface.contains(token))
            .collect()
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
        out.push_str("`\n- capability_probe_version: `");
        out.push_str(&self.capability_probe_version);
        out.push_str("`\n- rch_worker_or_refusal: `");
        out.push_str(&self.rch_worker_or_refusal);
        out.push_str("`\n- retry_condition: ");
        out.push_str(&self.retry_condition);
        out.push_str("\n- recommended_operator_action: ");
        out.push_str(&self.recommended_operator_action);
        out.push_str("\n- proof_may_run_now: `");
        out.push_str(if self.proof_may_run_now {
            "true"
        } else {
            "false"
        });
        out.push_str("`\n- local_cargo_fallback_allowed: `false`\n");
        out.push_str("- peer_build_cancellation_allowed: `false`\n");
        out.push_str("- branch_or_worktree_allowed: `false`\n");
        out.push_str("- file_deletion_allowed: `false`\n");
    }
}

fn classify(input: &ProofTrafficAdmissionInput) -> ProofTrafficDecision {
    if input.report_only {
        return ProofTrafficDecision::ReportOnly;
    }
    if input.clean_overlay_required && !input.capability.clean_overlay_supported {
        return ProofTrafficDecision::BlockedByCapabilityDrift;
    }
    if input.queue.remote_required_refused {
        return ProofTrafficDecision::RemoteRequiredRefused;
    }
    if input
        .queue
        .active_builds
        .iter()
        .any(|build| build.owner == ProofTrafficBuildOwner::PeerOwned && build.is_stale_progress())
    {
        return ProofTrafficDecision::BlockedByPeer;
    }
    if input.queue.active_project_exclusion
        || input.queue.worker_health_refusal
        || input.queue.active_builds.iter().any(|build| {
            build.owner == ProofTrafficBuildOwner::SelfOwned && build.is_stale_progress()
        })
    {
        return ProofTrafficDecision::ParkRerunRequired;
    }
    if input.queue.active_builds.is_empty() {
        ProofTrafficDecision::RunNow
    } else {
        ProofTrafficDecision::QueueWait
    }
}

fn rch_worker_or_refusal(
    input: &ProofTrafficAdmissionInput,
    decision: ProofTrafficDecision,
) -> String {
    match decision {
        ProofTrafficDecision::RunNow => "no-active-builds".to_string(),
        ProofTrafficDecision::QueueWait => format!(
            "waiting-on-active-builds:{}",
            build_id_csv(&input.queue.active_builds)
        ),
        ProofTrafficDecision::ParkRerunRequired => {
            if input.queue.active_project_exclusion {
                "active-project-exclusion".to_string()
            } else if input.queue.worker_health_refusal {
                "worker-health-refusal".to_string()
            } else {
                format!(
                    "self-owned-stale-progress:{}",
                    build_id_csv(&input.queue.active_builds)
                )
            }
        }
        ProofTrafficDecision::BlockedByPeer => format!(
            "peer-owned-stale-progress:{}",
            stale_peer_build_id_csv(&input.queue.active_builds)
        ),
        ProofTrafficDecision::BlockedByCapabilityDrift => "capability-drift".to_string(),
        ProofTrafficDecision::RemoteRequiredRefused => {
            "remote-required-refused-before-worker-assignment".to_string()
        }
        ProofTrafficDecision::ReportOnly => "report-only-no-worker".to_string(),
    }
}

fn retry_condition(input: &ProofTrafficAdmissionInput, decision: ProofTrafficDecision) -> String {
    match decision {
        ProofTrafficDecision::RunNow => {
            "none; proof may run now through remote-required RCH".to_string()
        }
        ProofTrafficDecision::QueueWait => {
            "retry after active build ids finish, or submit with RCH_QUEUE_WHEN_BUSY=1".to_string()
        }
        ProofTrafficDecision::ParkRerunRequired => {
            if input.queue.active_project_exclusion {
                "rerun after active_project_exclusion clears".to_string()
            } else if input.queue.worker_health_refusal {
                "rerun after worker-health refusal clears".to_string()
            } else {
                "rerun after self-owned stale-progress build reaches terminal output".to_string()
            }
        }
        ProofTrafficDecision::BlockedByPeer => {
            "handoff peer-owned stale-progress build ids; rerun after owner reports terminal output"
                .to_string()
        }
        ProofTrafficDecision::BlockedByCapabilityDrift => {
            "rerun after installed RCH supports required clean-overlay flags, or keep report-only"
                .to_string()
        }
        ProofTrafficDecision::RemoteRequiredRefused => {
            "rerun after remote-required admission accepts a worker".to_string()
        }
        ProofTrafficDecision::ReportOnly => "report-only; no proof command emitted".to_string(),
    }
}

fn recommended_operator_action(
    input: &ProofTrafficAdmissionInput,
    decision: ProofTrafficDecision,
) -> String {
    match decision {
        ProofTrafficDecision::RunNow => {
            "run the focused RCH command with RCH_REQUIRE_REMOTE=1 and the recorded target_dir"
                .to_string()
        }
        ProofTrafficDecision::QueueWait => format!(
            "wait or queue behind active build ids [{}] without changing proof scope",
            build_id_csv(&input.queue.active_builds)
        ),
        ProofTrafficDecision::ParkRerunRequired => {
            "park this proof and preserve the receipt until the retry condition clears".to_string()
        }
        ProofTrafficDecision::BlockedByPeer => {
            "send Agent Mail handoff with peer-owned build ids and keep this proof parked"
                .to_string()
        }
        ProofTrafficDecision::BlockedByCapabilityDrift => {
            "record capability drift and emit no Cargo proof command that assumes overlay exclusion"
                .to_string()
        }
        ProofTrafficDecision::RemoteRequiredRefused => {
            "record the remote-required refusal as rerun-required evidence".to_string()
        }
        ProofTrafficDecision::ReportOnly => {
            "publish the deterministic report only; do not admit a proof command".to_string()
        }
    }
}

fn build_id_csv(builds: &[ProofTrafficActiveBuild]) -> String {
    builds
        .iter()
        .map(|build| build.build_id.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn stale_peer_build_id_csv(builds: &[ProofTrafficActiveBuild]) -> String {
    builds
        .iter()
        .filter(|build| {
            build.owner == ProofTrafficBuildOwner::PeerOwned && build.is_stale_progress()
        })
        .map(|build| build.build_id.as_str())
        .collect::<Vec<_>>()
        .join(",")
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

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}
