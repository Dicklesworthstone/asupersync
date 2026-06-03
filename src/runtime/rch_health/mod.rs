//! Deterministic RCH worker health and cache-warm admission.
//!
//! This module is intentionally fixture driven. It models worker health snapshots
//! that were captured by an explicit capability outside the core runtime and
//! turns them into structured admission receipts. It does not probe RCH, SSH,
//! Cargo, Beads, Agent Mail, or the filesystem.

use std::cmp::Ordering;

const REDACTION_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const REDACTION_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Stable, redacted worker identity used in receipts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RchWorkerId(String);

impl RchWorkerId {
    /// Redacts a raw worker identifier into a stable non-reversible handle.
    #[must_use]
    pub fn redacted(raw: &str) -> Self {
        let mut hash = REDACTION_OFFSET;
        for byte in raw.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(REDACTION_PRIME);
        }
        Self(format!("rchw-{hash:016x}"))
    }

    /// Returns the redacted worker handle.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Queue state reported by a worker snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RchQueueState {
    /// Worker can admit a new proof command immediately.
    Open,
    /// Worker is busy, but foreground proof lanes may still be admitted.
    Busy,
    /// Worker is saturated and should not receive new work.
    Saturated,
}

/// Proof lane target-dir cache class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RchTargetDirClass {
    /// Unknown or uncategorized target-dir state.
    Unknown,
    /// Fresh target directory with little reusable compiler state.
    Cold,
    /// Target directory likely contains reusable incremental/build artifacts.
    Warm,
    /// Target directory is known hot for this proof lane.
    Hot,
}

/// Relative priority for RCH proof-lane admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RchProofPriority {
    /// Background or optional proof work.
    Background,
    /// Foreground proof work requested by an active agent.
    Foreground,
    /// Critical proof work on the release/admission frontier.
    Critical,
}

/// A proof command request evaluated against worker health snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RchProofLaneRequest {
    /// Stable proof-lane identifier, for example `cargo-test-admission`.
    pub lane_id: String,
    /// Target-dir class requested by this lane.
    pub target_dir_class: RchTargetDirClass,
    /// Whether this lane requires remote RCH execution.
    pub remote_required: bool,
    /// Lane priority used for work-conserving busy-worker admission.
    pub priority: RchProofPriority,
}

impl RchProofLaneRequest {
    /// Creates a new proof-lane request.
    #[must_use]
    pub fn new(
        lane_id: impl Into<String>,
        target_dir_class: RchTargetDirClass,
        remote_required: bool,
        priority: RchProofPriority,
    ) -> Self {
        Self {
            lane_id: lane_id.into(),
            target_dir_class,
            remote_required,
            priority,
        }
    }
}

/// Cache warmth hint for a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RchCacheWarmthHint {
    /// Optional exact proof-lane match.
    pub lane_id: Option<String>,
    /// Target-dir class this hint describes.
    pub target_dir_class: RchTargetDirClass,
    /// Warmth score from 0 to 100.
    pub warmth_bps: u16,
}

impl RchCacheWarmthHint {
    /// Creates a bounded cache-warmth hint.
    #[must_use]
    pub fn new(
        lane_id: Option<impl Into<String>>,
        target_dir_class: RchTargetDirClass,
        warmth_bps: u16,
    ) -> Self {
        Self {
            lane_id: lane_id.map(Into::into),
            target_dir_class,
            warmth_bps: warmth_bps.min(100),
        }
    }
}

/// Disk and pressure signals captured for an RCH worker.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RchWorkerDiskPressure {
    /// Free space on the worker root filesystem.
    pub root_free_gb: f64,
    /// Free space on the worker `/tmp` filesystem.
    pub tmp_free_gb: f64,
    /// Linux PSI `io some avg10` value.
    pub io_some_avg10: f64,
    /// Linux PSI `memory some avg10` value.
    pub memory_some_avg10: f64,
}

impl RchWorkerDiskPressure {
    /// Creates a disk-pressure snapshot.
    #[must_use]
    pub fn new(
        root_free_gb: f64,
        tmp_free_gb: f64,
        io_some_avg10: f64,
        memory_some_avg10: f64,
    ) -> Self {
        Self {
            root_free_gb,
            tmp_free_gb,
            io_some_avg10,
            memory_some_avg10,
        }
    }
}

/// Artifact retrieval reliability captured from recent proof runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RchArtifactRetrievalReliability {
    /// Recent remote proof runs whose artifacts were retrieved successfully.
    pub successes: u16,
    /// Recent artifact retrieval timeouts.
    pub timeouts: u16,
    /// Recent artifact retrieval failures other than timeouts.
    pub failures: u16,
}

impl RchArtifactRetrievalReliability {
    /// Creates a retrieval reliability snapshot.
    #[must_use]
    pub fn new(successes: u16, timeouts: u16, failures: u16) -> Self {
        Self {
            successes,
            timeouts,
            failures,
        }
    }
}

/// Refusal class used when a worker or fleet cannot admit a proof lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RchRefusalClass {
    /// No worker snapshots were available.
    NoWorkers,
    /// Worker could not be reached.
    Unreachable,
    /// Worker queue was saturated.
    QueueSaturated,
    /// Worker is excluded by active-project admission limits.
    ActiveProjectExcluded,
    /// Worker disk or pressure snapshot is outside policy.
    DiskPressure,
    /// Worker artifact retrieval has become too flaky.
    RetrievalFlaky,
    /// Snapshot is too old to drive admission.
    StaleSnapshot,
    /// Snapshot contains contradictory signals.
    ContradictorySnapshot,
    /// Worker is in deterministic hysteresis/backoff.
    HysteresisBackoff,
    /// Remote-required proof work had no admissible remote worker.
    LocalFallbackRefused,
}

impl RchRefusalClass {
    /// Stable machine code used in admission receipts and schedule rows.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoWorkers => "no_workers",
            Self::Unreachable => "unreachable",
            Self::QueueSaturated => "queue_saturated",
            Self::ActiveProjectExcluded => "active_project_excluded",
            Self::DiskPressure => "disk_pressure",
            Self::RetrievalFlaky => "retrieval_flaky",
            Self::StaleSnapshot => "stale_snapshot",
            Self::ContradictorySnapshot => "contradictory_snapshot",
            Self::HysteresisBackoff => "hysteresis_backoff",
            Self::LocalFallbackRefused => "local_fallback_refused",
        }
    }
}

/// Deterministic worker snapshot captured outside the core runtime.
#[derive(Debug, Clone, PartialEq)]
pub struct RchWorkerSnapshot {
    /// Redacted worker identity.
    pub worker_id: RchWorkerId,
    /// Whether the worker is reachable.
    pub reachable: bool,
    /// Queue/admission state.
    pub queue_state: RchQueueState,
    /// Whether same-project active exclusion blocks this worker.
    pub active_project_exclusion: bool,
    /// Cache-warmth hints by lane or target-dir class.
    pub cache_warmth: Vec<RchCacheWarmthHint>,
    /// Disk and PSI pressure snapshot.
    pub disk_pressure: RchWorkerDiskPressure,
    /// Artifact retrieval reliability.
    pub retrieval: RchArtifactRetrievalReliability,
    /// Age of the captured snapshot in seconds.
    pub last_seen_age_secs: u64,
    /// Confidence score from 0 to 100.
    pub confidence_bps: u16,
    /// Consecutive unhealthy samples before this snapshot.
    pub consecutive_unhealthy_samples: u16,
}

impl RchWorkerSnapshot {
    /// Creates a worker snapshot and redacts the raw worker identity.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        raw_worker_id: &str,
        reachable: bool,
        queue_state: RchQueueState,
        active_project_exclusion: bool,
        cache_warmth: Vec<RchCacheWarmthHint>,
        disk_pressure: RchWorkerDiskPressure,
        retrieval: RchArtifactRetrievalReliability,
        last_seen_age_secs: u64,
        confidence_bps: u16,
        consecutive_unhealthy_samples: u16,
    ) -> Self {
        Self {
            worker_id: RchWorkerId::redacted(raw_worker_id),
            reachable,
            queue_state,
            active_project_exclusion,
            cache_warmth,
            disk_pressure,
            retrieval,
            last_seen_age_secs,
            confidence_bps: confidence_bps.min(100),
            consecutive_unhealthy_samples,
        }
    }
}

/// Admission policy thresholds for RCH worker snapshots.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RchWorkerAdmissionPolicy {
    /// Maximum snapshot age before it fails closed.
    pub stale_after_secs: u64,
    /// Minimum free root filesystem GiB.
    pub min_root_free_gb: f64,
    /// Minimum free `/tmp` filesystem GiB.
    pub min_tmp_free_gb: f64,
    /// Maximum accepted Linux PSI `io some avg10`.
    pub max_io_some_avg10: f64,
    /// Maximum accepted Linux PSI `memory some avg10`.
    pub max_memory_some_avg10: f64,
    /// Retrieval failures/timeouts at or above this count are disqualifying.
    pub retrieval_failure_backoff_after: u16,
    /// Consecutive unhealthy samples at or above this count trigger backoff.
    pub unhealthy_hysteresis_after: u16,
    /// Minimum worker confidence score.
    pub min_confidence_bps: u16,
}

impl Default for RchWorkerAdmissionPolicy {
    fn default() -> Self {
        Self {
            stale_after_secs: 10 * 60,
            min_root_free_gb: 20.0,
            min_tmp_free_gb: 20.0,
            max_io_some_avg10: 5.0,
            max_memory_some_avg10: 8.0,
            retrieval_failure_backoff_after: 2,
            unhealthy_hysteresis_after: 2,
            min_confidence_bps: 50,
        }
    }
}

/// Fleet-level admission result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RchAdmissionDecision {
    /// A worker is selected for remote proof execution.
    Admit,
    /// Work should wait for a fresher or less busy remote worker.
    Defer,
    /// Work cannot proceed under the current remote-required policy.
    Refuse,
}

impl RchAdmissionDecision {
    /// Stable machine code used in admission receipts and schedule rows.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Defer => "defer",
            Self::Refuse => "refuse",
        }
    }
}

/// Per-worker candidate row included in an admission receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RchWorkerCandidateReceipt {
    /// Redacted worker identity.
    pub worker_id: RchWorkerId,
    /// Whether this worker was admissible for the request.
    pub admissible: bool,
    /// Refusal class when not admissible.
    pub refusal_class: Option<RchRefusalClass>,
    /// Cache-warmth score used for deterministic ranking.
    pub cache_warmth_bps: u16,
    /// Confidence score used for deterministic ranking.
    pub confidence_bps: u16,
    /// Structured reasons for the worker decision.
    pub reasons: Vec<String>,
}

/// Structured receipt for RCH worker admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RchWorkerAdmissionReceipt {
    /// Schema version for stable downstream consumption.
    pub schema_version: &'static str,
    /// Proof lane evaluated by this receipt.
    pub lane_id: String,
    /// Whether the request required remote execution.
    pub remote_required: bool,
    /// Final fleet decision.
    pub decision: RchAdmissionDecision,
    /// Selected redacted worker, if admitted.
    pub selected_worker: Option<RchWorkerId>,
    /// Fleet-level refusal class.
    pub refusal_class: Option<RchRefusalClass>,
    /// Whether local Cargo fallback is allowed by this receipt.
    pub local_fallback_allowed: bool,
    /// Per-worker candidate rows.
    pub candidates: Vec<RchWorkerCandidateReceipt>,
    /// Structured fleet-level reasons.
    pub reasons: Vec<String>,
}

/// ASW workload-admission schedule row derived from an RCH health receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RchWorkerAdmissionScheduleRow {
    /// Schema version for downstream ASW scheduling consumers.
    pub schema_version: &'static str,
    /// Proof lane evaluated by this row.
    pub lane_id: String,
    /// Final fleet decision.
    pub decision: RchAdmissionDecision,
    /// Stable decision code for log and JSON consumers.
    pub decision_code: &'static str,
    /// Whether the proof lane required remote execution.
    pub remote_required: bool,
    /// Selected redacted worker, if admitted.
    pub selected_worker: Option<RchWorkerId>,
    /// Fleet-level refusal class.
    pub refusal_class: Option<RchRefusalClass>,
    /// Stable refusal code for log and JSON consumers.
    pub refusal_code: Option<&'static str>,
    /// Whether local Cargo fallback is allowed.
    pub local_fallback_allowed: bool,
    /// Number of worker snapshots evaluated.
    pub candidate_count: usize,
    /// Number of workers that can accept this proof lane.
    pub admissible_worker_count: usize,
    /// Number of workers blocked by policy or health signals.
    pub blocked_worker_count: usize,
    /// Number of admissible workers with cache-warmth evidence.
    pub cache_warm_admissible_worker_count: usize,
    /// Stable structured reason codes for admission scheduling.
    pub reason_codes: Vec<&'static str>,
}

impl RchWorkerAdmissionReceipt {
    /// Counts workers that can accept this proof lane.
    #[must_use]
    pub fn admissible_worker_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.admissible)
            .count()
    }

    /// Counts workers that were present but blocked by policy or health signals.
    #[must_use]
    pub fn blocked_worker_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| !candidate.admissible)
            .count()
    }

    /// Counts admissible workers with any cache-warmth signal for this lane.
    #[must_use]
    pub fn cache_warm_admissible_worker_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.admissible && candidate.cache_warmth_bps > 0)
            .count()
    }

    /// Projects this receipt into a compact ASW workload-admission schedule row.
    #[must_use]
    pub fn schedule_row(&self) -> RchWorkerAdmissionScheduleRow {
        let refusal_code = self.refusal_class.map(RchRefusalClass::code);
        let mut reason_codes = Vec::new();
        let push_reason = |reason_codes: &mut Vec<&'static str>, code| {
            if !reason_codes.contains(&code) {
                reason_codes.push(code);
            }
        };
        push_reason(&mut reason_codes, self.decision.code());
        if let Some(code) = refusal_code {
            push_reason(&mut reason_codes, code);
        }
        if self.remote_required {
            push_reason(&mut reason_codes, "remote_required");
        }
        if self.remote_required && self.decision != RchAdmissionDecision::Admit {
            push_reason(&mut reason_codes, "local_fallback_refused");
        }
        if self.cache_warm_admissible_worker_count() > 0 {
            push_reason(&mut reason_codes, "cache_warm_capacity_present");
        }

        RchWorkerAdmissionScheduleRow {
            schema_version: "rch-worker-admission-schedule-row-v1",
            lane_id: self.lane_id.clone(),
            decision: self.decision,
            decision_code: self.decision.code(),
            remote_required: self.remote_required,
            selected_worker: self.selected_worker.clone(),
            refusal_class: self.refusal_class,
            refusal_code,
            local_fallback_allowed: self.local_fallback_allowed,
            candidate_count: self.candidates.len(),
            admissible_worker_count: self.admissible_worker_count(),
            blocked_worker_count: self.blocked_worker_count(),
            cache_warm_admissible_worker_count: self.cache_warm_admissible_worker_count(),
            reason_codes,
        }
    }
}

/// Evaluates worker snapshots for a proof-lane request.
#[must_use]
pub fn admit_rch_worker(
    request: &RchProofLaneRequest,
    snapshots: &[RchWorkerSnapshot],
    policy: &RchWorkerAdmissionPolicy,
) -> RchWorkerAdmissionReceipt {
    let mut candidates: Vec<_> = snapshots
        .iter()
        .map(|snapshot| evaluate_candidate(request, snapshot, policy))
        .collect();
    candidates.sort_by(compare_candidates);

    if let Some(selected) = candidates.iter().find(|candidate| candidate.admissible) {
        return RchWorkerAdmissionReceipt {
            schema_version: "rch-worker-admission-receipt-v1",
            lane_id: request.lane_id.clone(),
            remote_required: request.remote_required,
            decision: RchAdmissionDecision::Admit,
            selected_worker: Some(selected.worker_id.clone()),
            refusal_class: None,
            local_fallback_allowed: !request.remote_required,
            candidates,
            reasons: vec!["selected admissible cache-aware remote worker".to_string()],
        };
    }

    let refusal_class = fleet_refusal_class(&candidates, snapshots.is_empty(), request);
    let decision = if request.remote_required {
        RchAdmissionDecision::Refuse
    } else {
        RchAdmissionDecision::Defer
    };
    let mut reasons = vec![fleet_reason(refusal_class).to_string()];
    if request.remote_required {
        reasons.push("remote-required proof refused local Cargo fallback".to_string());
    } else {
        reasons.push("remote proof deferred; local Cargo fallback remains allowed".to_string());
    }

    RchWorkerAdmissionReceipt {
        schema_version: "rch-worker-admission-receipt-v1",
        lane_id: request.lane_id.clone(),
        remote_required: request.remote_required,
        decision,
        selected_worker: None,
        refusal_class: Some(refusal_class),
        local_fallback_allowed: !request.remote_required,
        candidates,
        reasons,
    }
}

fn evaluate_candidate(
    request: &RchProofLaneRequest,
    snapshot: &RchWorkerSnapshot,
    policy: &RchWorkerAdmissionPolicy,
) -> RchWorkerCandidateReceipt {
    let cache_warmth_bps = cache_warmth_score(request, snapshot);
    let mut reasons = Vec::new();

    let refusal_class = if snapshot.consecutive_unhealthy_samples
        >= policy.unhealthy_hysteresis_after
    {
        reasons
            .push("worker is in hysteresis backoff after repeated unhealthy samples".to_string());
        Some(RchRefusalClass::HysteresisBackoff)
    } else if is_contradictory(snapshot) {
        reasons
            .push("worker snapshot has contradictory reachability and queue signals".to_string());
        Some(RchRefusalClass::ContradictorySnapshot)
    } else if !snapshot.reachable {
        reasons.push("worker is unreachable".to_string());
        Some(RchRefusalClass::Unreachable)
    } else if snapshot.last_seen_age_secs > policy.stale_after_secs
        || snapshot.confidence_bps < policy.min_confidence_bps
    {
        reasons.push("worker snapshot is stale or below confidence threshold".to_string());
        Some(RchRefusalClass::StaleSnapshot)
    } else if snapshot.active_project_exclusion {
        reasons.push("active-project exclusion blocks this worker".to_string());
        Some(RchRefusalClass::ActiveProjectExcluded)
    } else if disk_pressure_exceeds_policy(snapshot, policy) {
        reasons.push("worker disk or PSI pressure exceeds policy".to_string());
        Some(RchRefusalClass::DiskPressure)
    } else if retrieval_flaky(snapshot, policy) {
        reasons.push("artifact retrieval reliability is below policy".to_string());
        Some(RchRefusalClass::RetrievalFlaky)
    } else if snapshot.queue_state == RchQueueState::Saturated {
        reasons.push("worker queue is saturated".to_string());
        Some(RchRefusalClass::QueueSaturated)
    } else if snapshot.queue_state == RchQueueState::Busy
        && request.priority == RchProofPriority::Background
    {
        reasons.push("worker queue is busy; background proof lane should wait".to_string());
        Some(RchRefusalClass::QueueSaturated)
    } else {
        if snapshot.queue_state == RchQueueState::Busy {
            reasons.push("worker is busy but foreground lane remains work-conserving".to_string());
        } else {
            reasons.push("worker is reachable and inside admission policy".to_string());
        }
        None
    };

    RchWorkerCandidateReceipt {
        worker_id: snapshot.worker_id.clone(),
        admissible: refusal_class.is_none(),
        refusal_class,
        cache_warmth_bps,
        confidence_bps: snapshot.confidence_bps,
        reasons,
    }
}

fn is_contradictory(snapshot: &RchWorkerSnapshot) -> bool {
    !snapshot.reachable
        && (snapshot.queue_state == RchQueueState::Open
            || snapshot.active_project_exclusion
            || !snapshot.cache_warmth.is_empty())
}

fn disk_pressure_exceeds_policy(
    snapshot: &RchWorkerSnapshot,
    policy: &RchWorkerAdmissionPolicy,
) -> bool {
    snapshot.disk_pressure.root_free_gb < policy.min_root_free_gb
        || snapshot.disk_pressure.tmp_free_gb < policy.min_tmp_free_gb
        || snapshot.disk_pressure.io_some_avg10 > policy.max_io_some_avg10
        || snapshot.disk_pressure.memory_some_avg10 > policy.max_memory_some_avg10
}

fn retrieval_flaky(snapshot: &RchWorkerSnapshot, policy: &RchWorkerAdmissionPolicy) -> bool {
    snapshot
        .retrieval
        .timeouts
        .saturating_add(snapshot.retrieval.failures)
        >= policy.retrieval_failure_backoff_after
}

fn cache_warmth_score(request: &RchProofLaneRequest, snapshot: &RchWorkerSnapshot) -> u16 {
    snapshot
        .cache_warmth
        .iter()
        .map(|hint| {
            let exact_lane = hint.lane_id.as_deref() == Some(request.lane_id.as_str());
            let class_match = hint.target_dir_class == request.target_dir_class;
            match (exact_lane, class_match) {
                (true, true) => hint.warmth_bps,
                (true, false) => hint.warmth_bps.saturating_sub(20),
                (false, true) => hint.warmth_bps.saturating_sub(40),
                (false, false) => 0,
            }
        })
        .max()
        .unwrap_or(0)
}

fn compare_candidates(
    left: &RchWorkerCandidateReceipt,
    right: &RchWorkerCandidateReceipt,
) -> Ordering {
    right
        .admissible
        .cmp(&left.admissible)
        .then_with(|| right.cache_warmth_bps.cmp(&left.cache_warmth_bps))
        .then_with(|| right.confidence_bps.cmp(&left.confidence_bps))
        .then_with(|| left.worker_id.cmp(&right.worker_id))
}

fn fleet_refusal_class(
    candidates: &[RchWorkerCandidateReceipt],
    no_snapshots: bool,
    request: &RchProofLaneRequest,
) -> RchRefusalClass {
    if no_snapshots {
        return RchRefusalClass::NoWorkers;
    }
    if request.remote_required {
        return RchRefusalClass::LocalFallbackRefused;
    }
    candidates
        .first()
        .and_then(|candidate| candidate.refusal_class)
        .unwrap_or(RchRefusalClass::NoWorkers)
}

fn fleet_reason(refusal_class: RchRefusalClass) -> &'static str {
    match refusal_class {
        RchRefusalClass::NoWorkers => "no RCH worker snapshots were available",
        RchRefusalClass::Unreachable => "all candidate RCH workers are unreachable",
        RchRefusalClass::QueueSaturated => "all candidate RCH workers are busy or saturated",
        RchRefusalClass::ActiveProjectExcluded => {
            "active-project exclusion blocks all candidate RCH workers"
        }
        RchRefusalClass::DiskPressure => "all candidate RCH workers exceed disk pressure policy",
        RchRefusalClass::RetrievalFlaky => {
            "all candidate RCH workers have unreliable artifact retrieval"
        }
        RchRefusalClass::StaleSnapshot => "all candidate RCH worker snapshots are stale",
        RchRefusalClass::ContradictorySnapshot => {
            "all candidate RCH worker snapshots are contradictory"
        }
        RchRefusalClass::HysteresisBackoff => "all candidate RCH workers are in hysteresis backoff",
        RchRefusalClass::LocalFallbackRefused => "no admissible remote worker is available",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RchProofLaneRequest {
        RchProofLaneRequest::new(
            "cargo-test-admission",
            RchTargetDirClass::Warm,
            true,
            RchProofPriority::Foreground,
        )
    }

    fn healthy_worker(name: &str) -> RchWorkerSnapshot {
        RchWorkerSnapshot::new(
            name,
            true,
            RchQueueState::Open,
            false,
            vec![RchCacheWarmthHint::new(
                Some("cargo-test-admission"),
                RchTargetDirClass::Warm,
                80,
            )],
            RchWorkerDiskPressure::new(80.0, 100.0, 0.2, 0.3),
            RchArtifactRetrievalReliability::new(3, 0, 0),
            30,
            95,
            0,
        )
    }

    fn admit(snapshots: &[RchWorkerSnapshot]) -> RchWorkerAdmissionReceipt {
        admit_rch_worker(&request(), snapshots, &RchWorkerAdmissionPolicy::default())
    }

    #[test]
    fn healthy_worker_is_admitted_with_redacted_identity() {
        let receipt = admit(&[healthy_worker("vmi-prod-a.internal")]);

        assert_eq!(receipt.decision, RchAdmissionDecision::Admit);
        assert_eq!(receipt.refusal_class, None);
        assert!(!receipt.local_fallback_allowed);
        let selected = receipt.selected_worker.expect("selected worker");
        assert!(selected.as_str().starts_with("rchw-"));
        assert!(!selected.as_str().contains("vmi-prod-a"));
    }

    #[test]
    fn cache_warm_worker_wins_deterministically() {
        let mut cold = healthy_worker("vmi-cold");
        cold.cache_warmth = vec![RchCacheWarmthHint::new(
            Some("cargo-test-admission"),
            RchTargetDirClass::Warm,
            10,
        )];
        let mut hot = healthy_worker("vmi-hot");
        hot.cache_warmth = vec![RchCacheWarmthHint::new(
            Some("cargo-test-admission"),
            RchTargetDirClass::Warm,
            100,
        )];

        let receipt = admit(&[cold, hot.clone()]);

        assert_eq!(receipt.decision, RchAdmissionDecision::Admit);
        assert_eq!(receipt.selected_worker, Some(hot.worker_id));
        assert_eq!(receipt.candidates[0].cache_warmth_bps, 100);
    }

    #[test]
    fn receipt_counts_cache_warm_capacity_without_leaking_worker_names() {
        let mut cold = healthy_worker("vmi-cold.internal");
        cold.cache_warmth.clear();
        let mut blocked = healthy_worker("vmi-blocked.internal");
        blocked.queue_state = RchQueueState::Saturated;
        let hot = healthy_worker("vmi-hot.internal");

        let receipt = admit(&[blocked, cold, hot]);

        assert_eq!(receipt.admissible_worker_count(), 2);
        assert_eq!(receipt.blocked_worker_count(), 1);
        assert_eq!(receipt.cache_warm_admissible_worker_count(), 1);
        assert!(
            receipt
                .candidates
                .iter()
                .all(|candidate| !candidate.worker_id.as_str().contains("vmi-"))
        );
    }

    #[test]
    fn background_lane_defers_busy_worker_but_foreground_can_use_it() {
        let mut busy = healthy_worker("vmi-busy");
        busy.queue_state = RchQueueState::Busy;
        let background = RchProofLaneRequest::new(
            "cargo-test-admission",
            RchTargetDirClass::Warm,
            true,
            RchProofPriority::Background,
        );

        let deferred = admit_rch_worker(
            &background,
            &[busy.clone()],
            &RchWorkerAdmissionPolicy::default(),
        );
        let foreground = admit(&[busy]);

        assert_eq!(deferred.decision, RchAdmissionDecision::Refuse);
        assert_eq!(
            deferred.refusal_class,
            Some(RchRefusalClass::LocalFallbackRefused)
        );
        assert_eq!(foreground.decision, RchAdmissionDecision::Admit);
    }

    #[test]
    fn lane_specific_cache_warmth_preserves_fairness_between_proof_lanes() {
        let mut cargo_hot = healthy_worker("vmi-cargo-hot.internal");
        cargo_hot.cache_warmth = vec![
            RchCacheWarmthHint::new(Some("cargo-test-admission"), RchTargetDirClass::Warm, 100),
            RchCacheWarmthHint::new(Some("cargo-clippy-admission"), RchTargetDirClass::Warm, 20),
        ];
        let mut clippy_hot = healthy_worker("vmi-clippy-hot.internal");
        clippy_hot.cache_warmth = vec![
            RchCacheWarmthHint::new(Some("cargo-test-admission"), RchTargetDirClass::Warm, 30),
            RchCacheWarmthHint::new(Some("cargo-clippy-admission"), RchTargetDirClass::Warm, 95),
        ];
        let clippy_request = RchProofLaneRequest::new(
            "cargo-clippy-admission",
            RchTargetDirClass::Warm,
            true,
            RchProofPriority::Foreground,
        );

        let cargo_receipt = admit(&[clippy_hot.clone(), cargo_hot.clone()]);
        let clippy_receipt = admit_rch_worker(
            &clippy_request,
            &[clippy_hot.clone(), cargo_hot.clone()],
            &RchWorkerAdmissionPolicy::default(),
        );

        assert_eq!(
            cargo_receipt.selected_worker,
            Some(cargo_hot.worker_id.clone())
        );
        assert_eq!(
            clippy_receipt.selected_worker,
            Some(clippy_hot.worker_id.clone())
        );
        assert_eq!(cargo_receipt.candidates[0].cache_warmth_bps, 100);
        assert_eq!(clippy_receipt.candidates[0].cache_warmth_bps, 95);
        assert!(
            cargo_receipt
                .candidates
                .iter()
                .chain(clippy_receipt.candidates.iter())
                .all(|candidate| !candidate.worker_id.as_str().contains("vmi-"))
        );
    }

    #[test]
    fn active_project_exclusion_refuses_remote_required_without_local_fallback() {
        let mut excluded = healthy_worker("vmi-excluded");
        excluded.active_project_exclusion = true;

        let receipt = admit(&[excluded]);

        assert_eq!(receipt.decision, RchAdmissionDecision::Refuse);
        assert_eq!(
            receipt.refusal_class,
            Some(RchRefusalClass::LocalFallbackRefused)
        );
        assert!(!receipt.local_fallback_allowed);
        assert!(
            receipt
                .reasons
                .iter()
                .any(|reason| reason.contains("local Cargo fallback"))
        );
    }

    #[test]
    fn disk_pressure_disqualifies_worker() {
        let mut worker = healthy_worker("vmi-disk");
        worker.disk_pressure = RchWorkerDiskPressure::new(100.0, 2.0, 0.1, 0.1);

        let receipt = admit(&[worker]);

        assert_eq!(receipt.decision, RchAdmissionDecision::Refuse);
        assert_eq!(
            receipt.candidates[0].refusal_class,
            Some(RchRefusalClass::DiskPressure)
        );
    }

    #[test]
    fn retrieval_flakiness_triggers_backoff() {
        let mut worker = healthy_worker("vmi-flaky");
        worker.retrieval = RchArtifactRetrievalReliability::new(1, 2, 0);

        let receipt = admit(&[worker]);

        assert_eq!(
            receipt.candidates[0].refusal_class,
            Some(RchRefusalClass::RetrievalFlaky)
        );
    }

    #[test]
    fn stale_snapshot_fails_closed() {
        let mut worker = healthy_worker("vmi-stale");
        worker.last_seen_age_secs = 3_600;

        let receipt = admit(&[worker]);

        assert_eq!(
            receipt.candidates[0].refusal_class,
            Some(RchRefusalClass::StaleSnapshot)
        );
    }

    #[test]
    fn contradictory_snapshot_fails_closed_before_reachability() {
        let mut worker = healthy_worker("vmi-contradictory");
        worker.reachable = false;
        worker.queue_state = RchQueueState::Open;

        let receipt = admit(&[worker]);

        assert_eq!(
            receipt.candidates[0].refusal_class,
            Some(RchRefusalClass::ContradictorySnapshot)
        );
    }

    #[test]
    fn hysteresis_backoff_blocks_flapping_worker() {
        let mut worker = healthy_worker("vmi-flap");
        worker.consecutive_unhealthy_samples = 2;

        let receipt = admit(&[worker]);

        assert_eq!(
            receipt.candidates[0].refusal_class,
            Some(RchRefusalClass::HysteresisBackoff)
        );
    }

    #[test]
    fn schedule_row_summarizes_cache_warm_capacity_without_host_leaks() {
        let mut blocked = healthy_worker("vmi-blocked.internal");
        blocked.queue_state = RchQueueState::Saturated;
        let hot = healthy_worker("vmi-hot.internal");

        let receipt = admit(&[blocked, hot.clone()]);
        let row = receipt.schedule_row();

        assert_eq!(row.schema_version, "rch-worker-admission-schedule-row-v1");
        assert_eq!(row.lane_id, "cargo-test-admission");
        assert_eq!(row.decision, RchAdmissionDecision::Admit);
        assert_eq!(row.decision_code, "admit");
        assert_eq!(row.refusal_class, None);
        assert_eq!(row.refusal_code, None);
        assert_eq!(row.selected_worker, Some(hot.worker_id));
        assert_eq!(row.candidate_count, 2);
        assert_eq!(row.admissible_worker_count, 1);
        assert_eq!(row.blocked_worker_count, 1);
        assert_eq!(row.cache_warm_admissible_worker_count, 1);
        assert!(row.reason_codes.contains(&"remote_required"));
        assert!(row.reason_codes.contains(&"cache_warm_capacity_present"));
        assert!(!row.reason_codes.contains(&"local_fallback_refused"));
        assert!(
            row.selected_worker
                .as_ref()
                .is_some_and(|worker| !worker.as_str().contains("vmi-"))
        );
    }

    #[test]
    fn schedule_row_records_remote_required_refusal_without_local_fallback() {
        let mut excluded = healthy_worker("vmi-excluded.internal");
        excluded.active_project_exclusion = true;

        let receipt = admit(&[excluded]);
        let row = receipt.schedule_row();

        assert_eq!(row.decision, RchAdmissionDecision::Refuse);
        assert_eq!(row.decision_code, "refuse");
        assert_eq!(
            row.refusal_class,
            Some(RchRefusalClass::LocalFallbackRefused)
        );
        assert_eq!(row.refusal_code, Some("local_fallback_refused"));
        assert!(!row.local_fallback_allowed);
        assert!(row.reason_codes.contains(&"remote_required"));
        assert!(row.reason_codes.contains(&"local_fallback_refused"));
        assert_eq!(
            row.reason_codes
                .iter()
                .filter(|code| **code == "local_fallback_refused")
                .count(),
            1
        );
    }

    #[test]
    fn non_remote_required_defer_preserves_local_fallback_allowed() {
        let mut saturated = healthy_worker("vmi-saturated.internal");
        saturated.queue_state = RchQueueState::Saturated;
        let local_allowed_request = RchProofLaneRequest::new(
            "cargo-test-admission",
            RchTargetDirClass::Warm,
            false,
            RchProofPriority::Foreground,
        );

        let receipt = admit_rch_worker(
            &local_allowed_request,
            &[saturated],
            &RchWorkerAdmissionPolicy::default(),
        );
        let row = receipt.schedule_row();

        assert_eq!(receipt.decision, RchAdmissionDecision::Defer);
        assert_eq!(receipt.refusal_class, Some(RchRefusalClass::QueueSaturated));
        assert!(receipt.local_fallback_allowed);
        assert!(row.local_fallback_allowed);
        assert!(row.reason_codes.contains(&"defer"));
        assert!(!row.reason_codes.contains(&"remote_required"));
        assert!(!row.reason_codes.contains(&"local_fallback_refused"));
        assert!(
            receipt
                .reasons
                .iter()
                .any(|reason| reason.contains("local Cargo fallback remains allowed"))
        );
    }
}
