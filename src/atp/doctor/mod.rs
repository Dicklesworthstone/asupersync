//! ATP doctor reports.

use crate::atp::path::{
    PathAttemptState, PathBudget, PathCandidate, PathCandidateId, PathDiagnosticSnapshot,
    PathFailureKind, PathFamily, PathKind, PathOutcome, PathOutcomeResult, PathRace,
    PathSelectionReason, PathSuccessKind,
};
use crate::atp::platform::{
    CapabilityProbe, FilesystemCapabilityProfile, NetworkCapabilityProfile,
    PlatformCapabilityProvider, PlatformCapabilityReport, PlatformProbeFamily, ProbeSource,
    ServiceCapabilityProfile, build_atp_platform_capability_report,
    detect_atp_platform_capabilities,
};
use serde::{Deserialize, Serialize};

/// Stable schema for ATP platform doctor output.
pub const ATP_PLATFORM_DOCTOR_SCHEMA: &str = "asupersync.atp.doctor.platform.v1";

/// Stable schema for one ATP platform probe log entry.
pub const ATP_PLATFORM_PROBE_LOG_SCHEMA: &str = "asupersync.atp.doctor.platform.probe_log.v1";

/// Stable schema for ATP path doctor output.
pub const ATP_PATH_DOCTOR_SCHEMA: &str = "asupersync.atp.doctor.path.v1";

/// Stable schema for one ATP path trace attempt log entry.
pub const ATP_PATH_TRACE_ATTEMPT_SCHEMA: &str = "asupersync.atp.doctor.path.trace_attempt.v1";

/// ATP path doctor document for peer reachability diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpPathDoctorDocument {
    /// Stable document schema.
    pub schema_version: String,
    /// Redaction-safe peer label supplied by the caller.
    pub peer: String,
    /// Stable summary of the path race.
    pub summary: AtpPathDoctorSummary,
    /// Selected path, when one candidate won.
    pub selected_path: Option<AtpPathDoctorSelectedPath>,
    /// Deterministic candidate table.
    pub candidates: Vec<AtpPathDoctorCandidate>,
    /// Structured path trace attempt rows.
    pub trace: Vec<AtpPathTraceAttemptLogEntry>,
    /// Concise operator recommendations.
    pub recommendations: Vec<AtpPathDoctorRecommendation>,
}

/// Stable summary section for ATP path doctor output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpPathDoctorSummary {
    /// Overall health bucket for automation.
    pub overall_health: String,
    /// Machine-readable selection reason.
    pub reason_code: String,
    /// Selected path family, when a candidate won.
    pub selected_family: Option<String>,
    /// Total candidates in the race.
    pub candidate_count: usize,
    /// Candidates still actively racing.
    pub racing_count: usize,
    /// Candidates that succeeded.
    pub success_count: usize,
    /// Candidates that failed.
    pub failure_count: usize,
    /// Candidates cancelled without loser-drain classification.
    pub cancelled_count: usize,
    /// Candidates drained because a different path won.
    pub drained_loser_count: usize,
    /// Direct path candidates.
    pub direct_count: usize,
    /// Tailscale path candidates.
    pub tailscale_count: usize,
    /// Relay path candidates.
    pub relay_count: usize,
    /// Offline mailbox path candidates.
    pub mailbox_count: usize,
}

/// Selected ATP path entry for path doctor output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpPathDoctorSelectedPath {
    /// Candidate id.
    pub candidate_id: u64,
    /// Candidate kind.
    pub kind: String,
    /// Candidate family.
    pub family: String,
    /// Path trace id for correlation with ATP logs.
    pub trace_id: u64,
    /// Observed RTT, when the selected path reported one.
    pub observed_rtt_micros: Option<u64>,
}

/// Stable candidate row for ATP path doctor JSON.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpPathDoctorCandidate {
    /// Candidate id.
    pub candidate_id: u64,
    /// Candidate kind.
    pub kind: String,
    /// Candidate family.
    pub family: String,
    /// Path trace id for correlation with ATP logs.
    pub trace_id: u64,
    /// Stable attempt state.
    pub state: String,
    /// Terminal outcome code, when any.
    pub outcome: Option<String>,
    /// Whether this is the selected path.
    pub selected: bool,
    /// Whether this candidate was drained after losing the race.
    pub drained_loser: bool,
    /// Winning candidate id when this candidate is a drained loser.
    pub winner_candidate_id: Option<u64>,
    /// Attempt budget snapshot.
    pub budget: AtpPathDoctorBudget,
    /// Security/privacy properties for this path.
    pub security: AtpPathDoctorSecurity,
    /// Monotonic completion timestamp in microseconds, when terminal.
    pub completed_at_micros: Option<u64>,
    /// Observed RTT, when available.
    pub observed_rtt_micros: Option<u64>,
    /// Probe/control bytes sent while establishing the path.
    pub bytes_sent: u64,
    /// Probe/control bytes received while establishing the path.
    pub bytes_received: u64,
}

/// Attempt budget snapshot for path doctor output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpPathDoctorBudget {
    /// Maximum time spent establishing the path.
    pub connect_timeout_micros: u64,
    /// Maximum time spent draining a losing attempt after cancellation.
    pub loser_drain_timeout_micros: u64,
    /// Maximum probe bytes allowed before validation.
    pub max_probe_bytes: u64,
}

/// Security/privacy properties for one path candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpPathDoctorSecurity {
    /// Whether the path requires authenticated ATP peer identity.
    pub authenticated_peer: bool,
    /// Whether ATP payload bytes remain encrypted end to end.
    pub end_to_end_encrypted: bool,
    /// Whether the remote peer can directly see the local public IP.
    pub exposes_local_ip_to_peer: bool,
    /// Whether a third-party relay sees peer metadata or timing.
    pub relay_metadata_visible: bool,
    /// Whether the path can complete while peers are not online together.
    pub store_and_forward: bool,
}

/// Structured trace row for one ATP path attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpPathTraceAttemptLogEntry {
    /// Stable log-entry schema.
    pub schema_version: String,
    /// Candidate id.
    pub candidate_id: u64,
    /// Path trace id.
    pub trace_id: u64,
    /// Candidate kind.
    pub kind: String,
    /// Candidate family.
    pub family: String,
    /// Stable attempt state.
    pub state: String,
    /// Terminal outcome code, when any.
    pub outcome: Option<String>,
    /// Whether this is the selected path.
    pub selected: bool,
    /// Concise detail suitable for human and proof summaries.
    pub detail: String,
}

/// Path doctor recommendation row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtpPathDoctorRecommendation {
    /// Severity bucket.
    pub severity: String,
    /// Stable recommendation code.
    pub code: String,
    /// Operator-facing message.
    pub message: String,
}

/// Builds an ATP path doctor document from a path race.
#[must_use]
pub fn build_path_doctor_document(
    peer: impl Into<String>,
    race: &PathRace,
) -> AtpPathDoctorDocument {
    let snapshot = race.diagnostic_snapshot();
    let winner = race.winner();
    let candidates = race
        .candidates()
        .map(|candidate| path_doctor_candidate(candidate, winner))
        .collect::<Vec<_>>();
    let trace = race
        .candidates()
        .map(|candidate| path_trace_entry(candidate, winner))
        .collect::<Vec<_>>();
    let selected_path = winner.and_then(|id| race.candidate(id).map(selected_path));
    let recommendations = path_recommendations(&snapshot);

    AtpPathDoctorDocument {
        schema_version: ATP_PATH_DOCTOR_SCHEMA.to_string(),
        peer: peer.into(),
        summary: path_summary(&snapshot),
        selected_path,
        candidates,
        trace,
        recommendations,
    }
}

/// Renders an ATP path doctor document for concise human CLI output.
#[must_use]
pub fn render_path_doctor_human(document: &AtpPathDoctorDocument) -> String {
    let mut lines = vec![
        format!("Schema: {}", document.schema_version),
        format!("Peer: {}", document.peer),
        format!(
            "Overall: {} reason={}",
            document.summary.overall_health, document.summary.reason_code
        ),
    ];

    if let Some(selected) = &document.selected_path {
        lines.push(format!(
            "Selected: candidate={} kind={} family={} trace={}",
            selected.candidate_id, selected.kind, selected.family, selected.trace_id
        ));
    } else {
        lines.push("Selected: none".to_string());
    }

    lines.push(format!("Candidates: {}", document.candidates.len()));
    for candidate in &document.candidates {
        let outcome = candidate.outcome.as_deref().unwrap_or("none");
        lines.push(format!(
            "  - candidate={} kind={} state={} outcome={} trace={}",
            candidate.candidate_id, candidate.kind, candidate.state, outcome, candidate.trace_id
        ));
    }

    lines.push(format!(
        "Recommendations: {}",
        document.recommendations.len()
    ));
    for recommendation in &document.recommendations {
        lines.push(format!(
            "  - {} {}: {}",
            recommendation.severity, recommendation.code, recommendation.message
        ));
    }

    lines.push(format!("Structured trace rows: {}", document.trace.len()));
    lines.join("\n")
}

fn path_summary(snapshot: &PathDiagnosticSnapshot) -> AtpPathDoctorSummary {
    AtpPathDoctorSummary {
        overall_health: path_health(snapshot.reason).to_string(),
        reason_code: snapshot.reason.code().to_string(),
        selected_family: snapshot
            .selected_family()
            .map(|family| path_family_label(family).to_string()),
        candidate_count: snapshot.candidate_count,
        racing_count: snapshot.racing_count,
        success_count: snapshot.success_count,
        failure_count: snapshot.failure_count,
        cancelled_count: snapshot.cancelled_count,
        drained_loser_count: snapshot.drained_loser_count,
        direct_count: snapshot.direct_count,
        tailscale_count: snapshot.tailscale_count,
        relay_count: snapshot.relay_count,
        mailbox_count: snapshot.mailbox_count,
    }
}

fn selected_path(candidate: &PathCandidate) -> AtpPathDoctorSelectedPath {
    let observed_rtt_micros =
        terminal_outcome(candidate.state).and_then(|outcome| match outcome.result {
            PathOutcomeResult::Success(_) => outcome.observed_rtt_micros,
            PathOutcomeResult::Failure(_) | PathOutcomeResult::Cancelled(_) => None,
        });

    AtpPathDoctorSelectedPath {
        candidate_id: candidate.id.get(),
        kind: path_kind_label(candidate.kind).to_string(),
        family: path_family_label(candidate.kind.family()).to_string(),
        trace_id: candidate.trace_id.get(),
        observed_rtt_micros,
    }
}

fn path_doctor_candidate(
    candidate: &PathCandidate,
    winner: Option<PathCandidateId>,
) -> AtpPathDoctorCandidate {
    let outcome = terminal_outcome(candidate.state);
    let (drained_loser, winner_candidate_id) = match candidate.state {
        PathAttemptState::DrainedLoser { winner, .. } => (true, Some(winner.get())),
        _ => (false, None),
    };

    AtpPathDoctorCandidate {
        candidate_id: candidate.id.get(),
        kind: path_kind_label(candidate.kind).to_string(),
        family: path_family_label(candidate.kind.family()).to_string(),
        trace_id: candidate.trace_id.get(),
        state: path_state_label(candidate.state).to_string(),
        outcome: outcome.map(|outcome| path_outcome_label(outcome.result).to_string()),
        selected: winner == Some(candidate.id),
        drained_loser,
        winner_candidate_id,
        budget: path_budget(candidate.budget),
        security: AtpPathDoctorSecurity {
            authenticated_peer: candidate.security.authenticated_peer,
            end_to_end_encrypted: candidate.security.end_to_end_encrypted,
            exposes_local_ip_to_peer: candidate.security.exposes_local_ip_to_peer,
            relay_metadata_visible: candidate.security.relay_metadata_visible,
            store_and_forward: candidate.security.store_and_forward,
        },
        completed_at_micros: outcome.map(|outcome| outcome.completed_at_micros),
        observed_rtt_micros: outcome.and_then(|outcome| outcome.observed_rtt_micros),
        bytes_sent: outcome.map_or(0, |outcome| outcome.bytes_sent),
        bytes_received: outcome.map_or(0, |outcome| outcome.bytes_received),
    }
}

fn path_trace_entry(
    candidate: &PathCandidate,
    winner: Option<PathCandidateId>,
) -> AtpPathTraceAttemptLogEntry {
    let outcome = terminal_outcome(candidate.state);
    AtpPathTraceAttemptLogEntry {
        schema_version: ATP_PATH_TRACE_ATTEMPT_SCHEMA.to_string(),
        candidate_id: candidate.id.get(),
        trace_id: candidate.trace_id.get(),
        kind: path_kind_label(candidate.kind).to_string(),
        family: path_family_label(candidate.kind.family()).to_string(),
        state: path_state_label(candidate.state).to_string(),
        outcome: outcome.map(|outcome| path_outcome_label(outcome.result).to_string()),
        selected: winner == Some(candidate.id),
        detail: path_attempt_detail(candidate.state),
    }
}

const fn path_budget(budget: PathBudget) -> AtpPathDoctorBudget {
    AtpPathDoctorBudget {
        connect_timeout_micros: budget.connect_timeout_micros,
        loser_drain_timeout_micros: budget.loser_drain_timeout_micros,
        max_probe_bytes: budget.max_probe_bytes,
    }
}

fn path_recommendations(snapshot: &PathDiagnosticSnapshot) -> Vec<AtpPathDoctorRecommendation> {
    let (severity, code, message) = match snapshot.reason {
        PathSelectionReason::DirectCandidateValidated => (
            "info",
            "direct_path_selected",
            "Direct path is usable; relay is not required for this peer.",
        ),
        PathSelectionReason::TailscaleCandidateValidated => (
            "info",
            "tailscale_path_selected",
            "Optional private-network path is usable; keep non-Tailscale fallback candidates visible.",
        ),
        PathSelectionReason::RelayFallbackValidated => (
            "warning",
            if snapshot.selected_kind == Some(PathKind::AtpRelayTcpTls443) {
                "tcp_tls_443_fallback_selected"
            } else {
                "relay_fallback_selected"
            },
            if snapshot.selected_kind == Some(PathKind::AtpRelayTcpTls443) {
                "TCP/TLS 443 fallback won; expect head-of-line blocking and nested retransmission penalties while UDP remains blocked."
            } else {
                "Relay path won; inspect failed direct candidates before assuming peer-to-peer reachability."
            },
        ),
        PathSelectionReason::OfflineMailboxAccepted => (
            "warning",
            "offline_mailbox_selected",
            "Store-and-forward path accepted the transfer; peer co-presence was not proven.",
        ),
        PathSelectionReason::RaceStillPending => (
            "warning",
            "path_race_pending",
            "Path race is still pending; wait for terminal outcomes before presenting a reachability claim.",
        ),
        PathSelectionReason::NoSuccessfulCandidate => (
            "error",
            "no_successful_candidate",
            "No candidate succeeded; check NAT, UDP reachability, relay availability, and policy denial logs.",
        ),
        PathSelectionReason::MissingWinnerCandidate => (
            "critical",
            "missing_winner_candidate",
            "Path race winner metadata is inconsistent; preserve the trace bundle for debugging.",
        ),
    };

    vec![AtpPathDoctorRecommendation {
        severity: severity.to_string(),
        code: code.to_string(),
        message: message.to_string(),
    }]
}

const fn path_health(reason: PathSelectionReason) -> &'static str {
    match reason {
        PathSelectionReason::DirectCandidateValidated
        | PathSelectionReason::TailscaleCandidateValidated => "healthy",
        PathSelectionReason::RelayFallbackValidated
        | PathSelectionReason::OfflineMailboxAccepted
        | PathSelectionReason::RaceStillPending => "degraded",
        PathSelectionReason::NoSuccessfulCandidate => "unreachable",
        PathSelectionReason::MissingWinnerCandidate => "critical",
    }
}

fn path_attempt_detail(state: PathAttemptState) -> String {
    match state {
        PathAttemptState::Pending => "candidate has not started".to_string(),
        PathAttemptState::Racing => "candidate is actively racing".to_string(),
        PathAttemptState::Succeeded(outcome) => format!(
            "{} at {}us",
            path_outcome_label(outcome.result),
            outcome.completed_at_micros
        ),
        PathAttemptState::Failed(outcome) => format!(
            "{} at {}us",
            path_outcome_label(outcome.result),
            outcome.completed_at_micros
        ),
        PathAttemptState::Cancelled(outcome) => format!(
            "{} at {}us",
            path_outcome_label(outcome.result),
            outcome.completed_at_micros
        ),
        PathAttemptState::DrainedLoser { winner, outcome } => format!(
            "lost to candidate {} and drained as {} at {}us",
            winner.get(),
            path_outcome_label(outcome.result),
            outcome.completed_at_micros
        ),
    }
}

const fn terminal_outcome(state: PathAttemptState) -> Option<PathOutcome> {
    match state {
        PathAttemptState::Succeeded(outcome)
        | PathAttemptState::Failed(outcome)
        | PathAttemptState::Cancelled(outcome)
        | PathAttemptState::DrainedLoser { outcome, .. } => Some(outcome),
        PathAttemptState::Pending | PathAttemptState::Racing => None,
    }
}

const fn path_state_label(state: PathAttemptState) -> &'static str {
    match state {
        PathAttemptState::Pending => "pending",
        PathAttemptState::Racing => "racing",
        PathAttemptState::Succeeded(_) => "succeeded",
        PathAttemptState::Failed(_) => "failed",
        PathAttemptState::Cancelled(_) => "cancelled",
        PathAttemptState::DrainedLoser { .. } => "drained_loser",
    }
}

const fn path_outcome_label(result: PathOutcomeResult) -> &'static str {
    match result {
        PathOutcomeResult::Success(kind) => match kind {
            PathSuccessKind::DirectValidated => "success_direct_validated",
            PathSuccessKind::TailscaleSelected => "success_tailscale_selected",
            PathSuccessKind::RelaySelected => "success_relay_selected",
            PathSuccessKind::MailboxAccepted => "success_mailbox_accepted",
        },
        PathOutcomeResult::Failure(kind) => match kind {
            PathFailureKind::Timeout => "failure_timeout",
            PathFailureKind::HardNat => "failure_hard_nat",
            PathFailureKind::UdpBlocked => "failure_udp_blocked",
            PathFailureKind::AuthFailure => "failure_auth",
            PathFailureKind::PolicyDenied => "failure_policy_denied",
            PathFailureKind::RelayUnavailable => "failure_relay_unavailable",
            PathFailureKind::UnsupportedPlatform => "failure_unsupported_platform",
            PathFailureKind::ProtocolError => "failure_protocol",
        },
        PathOutcomeResult::Cancelled(reason) => match reason {
            crate::atp::path::PathCancelReason::LoserOfRace => "cancelled_loser_of_race",
            crate::atp::path::PathCancelReason::ParentCancelled => "cancelled_parent",
            crate::atp::path::PathCancelReason::BudgetExceeded => "cancelled_budget_exceeded",
        },
    }
}

const fn path_kind_label(kind: PathKind) -> &'static str {
    match kind {
        PathKind::LanMulticast => "lan_multicast",
        PathKind::ExplicitPublicUdp => "explicit_public_udp",
        PathKind::PublicIpv6 => "public_ipv6",
        PathKind::NatPunchedUdp => "nat_punched_udp",
        PathKind::TailscaleIp => "tailscale_ip",
        PathKind::AtpRelayUdp => "atp_relay_udp",
        PathKind::AtpRelayTcpTls443 => "atp_relay_tcp_tls_443",
        PathKind::MasqueConnectUdp => "masque_connect_udp",
        PathKind::OfflineMailbox => "offline_mailbox",
    }
}

const fn path_family_label(family: PathFamily) -> &'static str {
    match family {
        PathFamily::Direct => "direct",
        PathFamily::Tailscale => "tailscale",
        PathFamily::Relay => "relay",
        PathFamily::OfflineMailbox => "offline_mailbox",
    }
}

/// ATP doctor report for platform capability diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AtpPlatformDoctorDocument {
    /// Stable document schema.
    pub schema_version: String,
    /// Compile-time platform family bucket.
    pub platform_family: PlatformProbeFamily,
    /// Capability report used by transfer, disk, scheduler, and packaging policy.
    pub report: PlatformCapabilityReport,
    /// Structured operator logs for every probe.
    pub logs: Vec<AtpPlatformProbeLogEntry>,
}

/// Structured log entry for one platform probe.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AtpPlatformProbeLogEntry {
    /// Stable log-entry schema.
    pub schema_version: String,
    /// Compact platform profile for log correlation.
    pub platform_profile: String,
    /// Capability key.
    pub capability: String,
    /// Capability status.
    pub status: String,
    /// Probe source.
    pub probe_source: String,
    /// Whether this probe was measured, assumed, configured, or skipped.
    pub measurement_kind: String,
    /// Operator-facing probe detail.
    pub detail: String,
    /// Conservative degradation reason, when any.
    pub degradation_reason: Option<String>,
    /// Explicit skip reason for skipped probes.
    pub skip_reason: Option<String>,
    /// Suggested recovery command, when any.
    pub suggested_recovery_command: Option<String>,
}

/// Detects the host platform and builds an ATP doctor document.
#[must_use]
pub fn detect_platform_doctor_document() -> AtpPlatformDoctorDocument {
    document_from_report(detect_atp_platform_capabilities())
}

/// Builds an ATP doctor document from an injected platform provider.
#[must_use]
pub fn build_platform_doctor_document(
    provider: &impl PlatformCapabilityProvider,
) -> AtpPlatformDoctorDocument {
    document_from_report(build_atp_platform_capability_report(provider))
}

fn document_from_report(report: PlatformCapabilityReport) -> AtpPlatformDoctorDocument {
    let logs = collect_probes(&report.filesystem, &report.network, &report.service)
        .into_iter()
        .map(|probe| log_entry(&report, probe))
        .collect();
    AtpPlatformDoctorDocument {
        schema_version: ATP_PLATFORM_DOCTOR_SCHEMA.to_string(),
        platform_family: PlatformProbeFamily::current(),
        report,
        logs,
    }
}

fn log_entry(
    report: &PlatformCapabilityReport,
    probe: &CapabilityProbe,
) -> AtpPlatformProbeLogEntry {
    let platform_profile = format!(
        "{}/{}/{}:{}",
        report.target.family, report.target.os, report.target.arch, report.target.pointer_width
    );
    AtpPlatformProbeLogEntry {
        schema_version: ATP_PLATFORM_PROBE_LOG_SCHEMA.to_string(),
        platform_profile,
        capability: probe.name.clone(),
        status: probe.status.as_str().to_string(),
        probe_source: probe.source.as_str().to_string(),
        measurement_kind: probe.source.as_str().to_string(),
        detail: probe.detail.clone(),
        degradation_reason: probe.degradation_reason.clone(),
        skip_reason: (probe.source == ProbeSource::Skipped).then(|| probe.detail.clone()), // ubs:ignore - enum comparison, not a secret
        suggested_recovery_command: probe.suggested_recovery_command.clone(),
    }
}

fn collect_probes<'a>(
    filesystem: &'a FilesystemCapabilityProfile,
    network: &'a NetworkCapabilityProfile,
    service: &'a ServiceCapabilityProfile,
) -> Vec<&'a CapabilityProbe> {
    vec![
        &filesystem.sparse_files,
        &filesystem.preallocation,
        &filesystem.atomic_rename,
        &filesystem.fsync_durability,
        &filesystem.max_path_length,
        &filesystem.case_sensitive_paths,
        &filesystem.symlink_behavior,
        &network.socket_buffers,
        &network.ipv6,
        &network.router_assist,
        &service.service_manager,
    ]
}

/// Renders the ATP platform doctor document for human CLI output.
#[must_use]
pub fn render_platform_doctor_human(document: &AtpPlatformDoctorDocument) -> String {
    let report = &document.report;
    let mut lines = vec![
        format!("Schema: {}", document.schema_version),
        format!("Platform family: {}", document.platform_family.as_str()),
        format!(
            "Target: {}/{}/{} pointer_width={}",
            report.target.family, report.target.os, report.target.arch, report.target.pointer_width
        ),
        "Filesystem:".to_string(),
    ];
    append_filesystem_capabilities(&mut lines, &report.filesystem);
    lines.push("Network:".to_string());
    append_network_capabilities(&mut lines, &report.network);
    lines.push("Service:".to_string());
    append_service_capabilities(&mut lines, &report.service);
    lines.push("Degradation policy:".to_string());
    lines.push(format!(
        "  disk_writer_mode: {}",
        report.degradation_policy.disk_writer_mode
    ));
    lines.push(format!(
        "  atomic_commit_mode: {}",
        report.degradation_policy.atomic_commit_mode
    ));
    lines.push(format!(
        "  endpoint_mode: {}",
        report.degradation_policy.endpoint_mode
    ));
    lines.push(format!(
        "  packaging_mode: {}",
        report.degradation_policy.packaging_mode
    ));
    lines.push(format!("Caveats: {}", report.caveats.len()));
    for caveat in &report.caveats {
        lines.push(format!("  - {caveat}"));
    }
    lines.push(format!(
        "Suggested recovery commands: {}",
        report.suggested_recovery_commands.len()
    ));
    for command in &report.suggested_recovery_commands {
        lines.push(format!("  - {command}"));
    }
    lines.push(format!("Structured probe logs: {}", document.logs.len()));
    lines.join("\n")
}

fn append_filesystem_capabilities(lines: &mut Vec<String>, profile: &FilesystemCapabilityProfile) {
    append_capability(lines, &profile.sparse_files);
    append_capability(lines, &profile.preallocation);
    append_capability(lines, &profile.atomic_rename);
    append_capability(lines, &profile.fsync_durability);
    append_capability(lines, &profile.max_path_length);
    append_capability(lines, &profile.case_sensitive_paths);
    append_capability(lines, &profile.symlink_behavior);
}

fn append_network_capabilities(lines: &mut Vec<String>, profile: &NetworkCapabilityProfile) {
    append_capability(lines, &profile.socket_buffers);
    append_capability(lines, &profile.ipv6);
    append_capability(lines, &profile.router_assist);
}

fn append_service_capabilities(lines: &mut Vec<String>, profile: &ServiceCapabilityProfile) {
    append_capability(lines, &profile.service_manager);
}

fn append_capability(lines: &mut Vec<String>, capability: &CapabilityProbe) {
    lines.push(format!(
        "  {}: {} source={} detail={}",
        capability.name,
        capability.status.as_str(),
        capability.source.as_str(),
        capability.detail
    ));
    if let Some(reason) = &capability.degradation_reason {
        lines.push(format!("    degradation: {reason}"));
    }
    if let Some(command) = &capability.suggested_recovery_command {
        lines.push(format!("    recovery: {command}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::path::{
        PathCandidateId, PathFailureKind, PathKind, PathOutcome, PathSuccessKind, PathTraceId,
    };
    use crate::atp::platform::DeterministicLabPlatformProvider;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn path_candidate(raw: u64, kind: PathKind) -> PathCandidate {
        PathCandidate::new(
            PathCandidateId::new(raw),
            kind,
            PathTraceId::new(90_000 + raw),
        )
    }

    fn relay_fallback_race() -> PathRace {
        let direct = PathCandidateId::new(1);
        let relay = PathCandidateId::new(2);
        let tailscale = PathCandidateId::new(3);
        let mut race = PathRace::new();
        race.add_candidate(path_candidate(direct.get(), PathKind::NatPunchedUdp))
            .expect("direct candidate");
        race.add_candidate(path_candidate(relay.get(), PathKind::AtpRelayTcpTls443))
            .expect("relay candidate");
        race.add_candidate(path_candidate(tailscale.get(), PathKind::TailscaleIp))
            .expect("tailscale candidate");
        race.start_all().expect("start race");
        race.record_outcome(
            direct,
            PathOutcome::failure(PathFailureKind::UdpBlocked, 10_000).with_bytes(120, 0),
        )
        .expect("direct failure");
        race.record_outcome(
            relay,
            PathOutcome::success(PathSuccessKind::RelaySelected, 22_000, Some(9_000))
                .with_bytes(512, 512),
        )
        .expect("relay success");
        race
    }

    #[test]
    fn path_doctor_document_reports_relay_fallback_and_loser_drain_trace() {
        init_test("path_doctor_document_reports_relay_fallback_and_loser_drain_trace");
        let document = build_path_doctor_document("peer-alpha", &relay_fallback_race());

        assert_eq!(document.schema_version, ATP_PATH_DOCTOR_SCHEMA);
        assert_eq!(document.summary.overall_health, "degraded");
        assert_eq!(document.summary.reason_code, "relay_fallback_validated");
        assert_eq!(document.summary.selected_family.as_deref(), Some("relay"));
        assert_eq!(document.summary.candidate_count, 3);
        assert_eq!(document.summary.failure_count, 1);
        assert_eq!(document.summary.drained_loser_count, 1);

        let selected = document.selected_path.as_ref().expect("selected path");
        assert_eq!(selected.candidate_id, 2);
        assert_eq!(selected.kind, "atp_relay_tcp_tls_443");
        assert_eq!(selected.observed_rtt_micros, Some(9_000));

        let direct = document
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == 1)
            .expect("direct candidate");
        assert_eq!(direct.state, "failed");
        assert_eq!(direct.outcome.as_deref(), Some("failure_udp_blocked"));

        let tailscale = document
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == 3)
            .expect("tailscale candidate");
        assert_eq!(tailscale.state, "drained_loser");
        assert!(tailscale.drained_loser);
        assert_eq!(tailscale.winner_candidate_id, Some(2));

        assert!(document.trace.iter().all(|entry| {
            entry.schema_version == ATP_PATH_TRACE_ATTEMPT_SCHEMA && !entry.detail.is_empty()
        }));
        assert!(document.trace.iter().any(|entry| {
            entry.candidate_id == 3 && entry.detail.contains("lost to candidate 2")
        }));
        assert_eq!(
            document.recommendations[0].code,
            "tcp_tls_443_fallback_selected"
        );
        crate::test_complete!("path_doctor_document_reports_relay_fallback_and_loser_drain_trace");
    }

    #[test]
    fn path_doctor_json_and_human_output_have_stable_fields() {
        init_test("path_doctor_json_and_human_output_have_stable_fields");
        let document = build_path_doctor_document("peer-alpha", &relay_fallback_race());
        let json = serde_json::to_value(&document).expect("serialize path doctor");

        assert_eq!(json["schema_version"], ATP_PATH_DOCTOR_SCHEMA);
        assert_eq!(json["summary"]["reason_code"], "relay_fallback_validated");
        assert_eq!(json["selected_path"]["family"], "relay");
        assert_eq!(
            json["trace"][0]["schema_version"],
            ATP_PATH_TRACE_ATTEMPT_SCHEMA
        );

        let rendered = render_path_doctor_human(&document);
        assert!(rendered.contains("Schema: asupersync.atp.doctor.path.v1"));
        assert!(rendered.contains("Overall: degraded reason=relay_fallback_validated"));
        assert!(
            rendered.contains(
                "Selected: candidate=2 kind=atp_relay_tcp_tls_443 family=relay trace=90002"
            )
        );
        assert!(rendered.contains("Recommendations: 1"));
        crate::test_complete!("path_doctor_json_and_human_output_have_stable_fields");
    }

    #[test]
    fn platform_doctor_document_has_stable_shape() {
        init_test("platform_doctor_document_has_stable_shape");
        let provider = DeterministicLabPlatformProvider::fully_supported();
        let document = build_platform_doctor_document(&provider);

        assert_eq!(document.schema_version, ATP_PLATFORM_DOCTOR_SCHEMA);
        assert_eq!(document.report.filesystem.sparse_files.name, "sparse_files");
        assert_eq!(document.logs.len(), 11);
        assert!(
            document
                .logs
                .iter()
                .any(|entry| entry.capability == "service_manager"
                    && entry.measurement_kind == "measured")
        );
        crate::test_complete!("platform_doctor_document_has_stable_shape");
    }

    #[test]
    fn platform_doctor_logs_failed_and_skipped_probe_details() {
        init_test("platform_doctor_logs_failed_and_skipped_probe_details");
        let provider = DeterministicLabPlatformProvider::conservative_degradation();
        let document = build_platform_doctor_document(&provider);

        let sparse = document
            .logs
            .iter()
            .find(|entry| entry.capability == "sparse_files")
            .expect("sparse log");
        assert_eq!(
            sparse.degradation_reason.as_deref(),
            Some("write into quarantine before verified exposure")
        );

        let service = document
            .logs
            .iter()
            .find(|entry| entry.capability == "service_manager")
            .expect("service-manager log");
        assert_eq!(service.probe_source, "skipped");
        assert!(service.skip_reason.is_some());
        assert_eq!(
            service.suggested_recovery_command.as_deref(),
            Some("run atpd under a supported service manager")
        );
        crate::test_complete!("platform_doctor_logs_failed_and_skipped_probe_details");
    }

    #[test]
    fn platform_doctor_human_output_has_stable_sections() {
        init_test("platform_doctor_human_output_has_stable_sections");
        let provider = DeterministicLabPlatformProvider::fully_supported();
        let document = build_platform_doctor_document(&provider);
        let rendered = render_platform_doctor_human(&document);

        assert!(rendered.contains("Schema: asupersync.atp.doctor.platform.v1"));
        assert!(rendered.contains("Filesystem:"));
        assert!(rendered.contains("Network:"));
        assert!(rendered.contains("Service:"));
        assert!(rendered.contains("Degradation policy:"));
        assert!(rendered.contains("Structured probe logs: 11"));
        crate::test_complete!("platform_doctor_human_output_has_stable_sections");
    }

    #[test]
    fn platform_doctor_json_output_has_stable_fields() {
        init_test("platform_doctor_json_output_has_stable_fields");
        let provider = DeterministicLabPlatformProvider::conservative_degradation();
        let document = build_platform_doctor_document(&provider);
        let json = serde_json::to_value(&document).expect("serialize doctor document");

        assert_eq!(json["schema_version"], ATP_PLATFORM_DOCTOR_SCHEMA);
        assert_eq!(
            json["report"]["degradation_policy"]["disk_writer_mode"],
            "contiguous-verified-quarantine"
        );
        assert!(json["logs"].as_array().expect("logs array").iter().any(
            |entry| entry["capability"] == "ipv6"
                && entry["suggested_recovery_command"]
                    == "enable IPv6 loopback/networking on this host"
        ));
        crate::test_complete!("platform_doctor_json_output_has_stable_fields");
    }
}
