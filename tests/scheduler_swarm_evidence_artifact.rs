//! Integration tests for scheduler evidence artifacts and recommendations.

use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::{
    SCHEDULER_EVIDENCE_SCHEMA_VERSION, SWARM_ADMISSION_POLICY_REPORT_SCHEMA_VERSION,
    SWARM_CAPACITY_SNAPSHOT_SCHEMA_VERSION, SWARM_MEMORY_BUDGET_PLAN_SCHEMA_VERSION,
    SchedulerEvidenceArtifact, SchedulerEvidenceError, SchedulerEvidenceMetrics,
    SchedulerKnobProfile, SchedulerRecommendationReason, SchedulerTopologyDescriptor,
    SchedulerWorkloadClass, SwarmAdmissionDecision, SwarmAdmissionLane, SwarmAdmissionReasonCode,
    SwarmAdmissionReport, SwarmCapacitySnapshot, SwarmCoordinationBacklogSignals,
    SwarmCpuTopologyHints, SwarmDiskCapacity, SwarmDiskPressureLevel, SwarmMemoryBudgetPlan,
    SwarmMemoryCapacity, SwarmMemoryHostTier, SwarmMemoryPressureTier, SwarmRchAdmissibility,
    SwarmRchCapacity, SwarmValidationClass, ThreeLaneScheduler,
};
use asupersync::sync::ContendedMutex;
use asupersync::types::{TaskId, Time};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

fn sample_artifact() -> SchedulerEvidenceArtifact {
    SchedulerEvidenceArtifact {
        schema_version: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
        run_label: "mixed-burst-64c".to_string(),
        workload_class: SchedulerWorkloadClass::MixedBurst,
        topology: SchedulerTopologyDescriptor {
            worker_threads: 64,
            cohort_count: 2,
            memory_budget_gib: 256,
        },
        current_knobs: SchedulerKnobProfile {
            worker_threads: 64,
            steal_batch_size: 8,
            cancel_streak_limit: 16,
            global_queue_limit: 0,
            parking_enabled: true,
        },
        metrics: SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: 8_000,
            wake_to_run_p95_ns: 90_000,
            wake_to_run_p99_ns: 220_000,
            queue_residency_p50_ns: 16_000,
            queue_residency_p95_ns: 200_000,
            queue_residency_p99_ns: 520_000,
            ready_backlog_p95: 192,
            ready_backlog_p99: 320,
            cancel_debt_p95: 48,
            cancel_debt_p99: 128,
            remote_steal_ratio_pct: Some(42),
            cross_cohort_wake_p99_ns: Some(180_000),
        },
        notes: vec!["deterministic_lab".to_string()],
    }
}

fn sample_capacity_snapshot(snapshot_id: &str) -> SwarmCapacitySnapshot {
    const GIB: u64 = 1_024 * 1_024 * 1_024;

    SwarmCapacitySnapshot {
        schema_version: SWARM_CAPACITY_SNAPSHOT_SCHEMA_VERSION.to_string(),
        snapshot_id: snapshot_id.to_string(),
        cpu: SwarmCpuTopologyHints {
            logical_cpus: 64,
            physical_cores: Some(32),
            numa_nodes: Some(2),
            scheduler_worker_target: Some(64),
        },
        memory: SwarmMemoryCapacity {
            available_bytes: Some(192 * GIB),
            total_bytes: Some(256 * GIB),
            pressure_tier: SwarmMemoryPressureTier::Healthy,
        },
        disk: SwarmDiskCapacity {
            free_bytes: Some(768 * GIB),
            total_bytes: Some(2 * 1_024 * GIB),
            pressure_level: SwarmDiskPressureLevel::Healthy,
        },
        rch: SwarmRchCapacity {
            admissibility: SwarmRchAdmissibility::Available,
            healthy_worker_count: Some(6),
            available_slots: Some(12),
            blocked_reason_codes: Vec::new(),
        },
        coordination: SwarmCoordinationBacklogSignals {
            ready_beads: 3,
            open_beads: 7,
            in_progress_beads: 1,
            active_reservations: 5,
            active_dirty_paths: 2,
            active_agents: 4,
            stale_in_progress_beads: 0,
        },
    }
}

fn admission_for(
    report: &SwarmAdmissionReport,
    lane: SwarmAdmissionLane,
) -> &asupersync::runtime::scheduler::SwarmLaneAdmission {
    report
        .lanes
        .iter()
        .find(|admission| admission.lane == lane)
        .unwrap_or_else(|| panic!("missing lane admission for {lane:?}"))
}

fn assert_memory_plan_invariants(plan: &SwarmMemoryBudgetPlan) {
    assert_eq!(
        plan.total_planned_bytes,
        plan.interactive_runtime_bytes
            + plan.trace_replay_bytes
            + plan.proof_artifact_staging_bytes
            + plan.compiler_cache_bytes
    );
    let allocatable_bytes = plan
        .available_bytes
        .saturating_sub(plan.emergency_reserve_bytes);
    assert!(
        plan.total_planned_bytes <= allocatable_bytes,
        "planned bytes must fit inside memory left after emergency reserve"
    );
}

#[test]
fn scheduler_evidence_artifact_round_trips_through_json() {
    let artifact = sample_artifact();
    let json = serde_json::to_string_pretty(&artifact).expect("serialize artifact");
    let reparsed: SchedulerEvidenceArtifact =
        serde_json::from_str(&json).expect("deserialize artifact");
    assert_eq!(reparsed, artifact);
}

#[test]
fn scheduler_evidence_artifact_generates_stable_recommendations() {
    let artifact = sample_artifact();
    let report = artifact.tune_report().expect("valid report");

    assert_eq!(report.source_run_label, "mixed-burst-64c");
    assert_eq!(report.profile_name, "scale_workers");
    assert_eq!(report.recommended_knobs.worker_threads, 66);
    assert_eq!(report.recommended_knobs.steal_batch_size, 16);
    assert_eq!(report.recommended_knobs.cancel_streak_limit, 32);
    assert_eq!(report.global_queue_limit_hint, Some(640));
    assert_eq!(report.fallback_profile, artifact.current_knobs);
    assert_eq!(report.confidence_percent, 90);
    assert_eq!(
        report.reason_codes,
        vec![
            SchedulerRecommendationReason::WorkersSaturated,
            SchedulerRecommendationReason::QueueResidencyDominant,
            SchedulerRecommendationReason::CancelDebtDominant,
            SchedulerRecommendationReason::RemoteStealPressure,
        ]
    );
}

#[test]
fn scheduler_evidence_recommendation_is_deterministic_for_fixed_inputs() {
    let artifact = sample_artifact();
    let first = artifact.tune_report().expect("first report");
    let first_json = serde_json::to_value(&first).expect("serialize first report");

    for iteration in 0..16 {
        let next = artifact
            .tune_report()
            .unwrap_or_else(|err| panic!("report {iteration} should tune: {err}"));
        let next_json = serde_json::to_value(&next).expect("serialize next report");
        assert_eq!(
            next_json, first_json,
            "fixed scheduler evidence must produce byte-stable recommendation fields at iteration {iteration}"
        );
    }
}

#[test]
fn scheduler_evidence_json_stays_compact_for_routine_collection() {
    let artifact = sample_artifact();
    let report = artifact.tune_report().expect("valid report");

    let artifact_json = serde_json::to_vec(&artifact).expect("serialize compact artifact");
    let report_json = serde_json::to_vec(&report).expect("serialize compact report");

    assert!(
        artifact_json.len() <= 2_048,
        "scheduler evidence artifact should stay compact enough for routine collection: {} bytes",
        artifact_json.len()
    );
    assert!(
        report_json.len() <= 2_048,
        "scheduler tuning report should stay compact enough for routine collection: {} bytes",
        report_json.len()
    );
}

#[test]
fn scheduler_evidence_artifact_rejects_invalid_inputs() {
    let mut artifact = sample_artifact();
    artifact.schema_version = "asupersync.scheduler-evidence.v0".to_string();
    assert_eq!(
        artifact.validate(),
        Err(SchedulerEvidenceError::UnsupportedSchemaVersion {
            expected: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
            found: "asupersync.scheduler-evidence.v0".to_string(),
        })
    );

    let mut artifact = sample_artifact();
    artifact.metrics.remote_steal_ratio_pct = Some(101);
    assert_eq!(
        artifact.validate(),
        Err(SchedulerEvidenceError::RemoteStealRatioOutOfRange(101))
    );
}

#[test]
fn swarm_capacity_snapshot_round_trips_resource_pressure_fixtures() {
    let healthy = sample_capacity_snapshot("healthy-64c");

    let mut disk_red = sample_capacity_snapshot("disk-red");
    disk_red.disk.free_bytes = Some(8 * 1_024 * 1_024 * 1_024);
    disk_red.disk.pressure_level = SwarmDiskPressureLevel::Critical;
    disk_red.rch.admissibility = SwarmRchAdmissibility::DeferredByPolicy;
    disk_red
        .rch
        .blocked_reason_codes
        .push("disk-critical".to_string());

    let mut memory_saturated = sample_capacity_snapshot("memory-saturated");
    memory_saturated.memory.available_bytes = Some(4 * 1_024 * 1_024 * 1_024);
    memory_saturated.memory.pressure_tier = SwarmMemoryPressureTier::Saturated;
    memory_saturated.rch.admissibility = SwarmRchAdmissibility::Degraded;

    let mut rch_unavailable = sample_capacity_snapshot("rch-unavailable");
    rch_unavailable.rch.admissibility = SwarmRchAdmissibility::Unavailable;
    rch_unavailable.rch.healthy_worker_count = Some(0);
    rch_unavailable.rch.available_slots = Some(0);
    rch_unavailable
        .rch
        .blocked_reason_codes
        .push("no-admissible-workers".to_string());

    let mut backlog_heavy = sample_capacity_snapshot("coordination-backlog-heavy");
    backlog_heavy.coordination.ready_beads = 42;
    backlog_heavy.coordination.open_beads = 96;
    backlog_heavy.coordination.in_progress_beads = 18;
    backlog_heavy.coordination.active_reservations = 27;
    backlog_heavy.coordination.active_dirty_paths = 9;
    backlog_heavy.coordination.active_agents = 14;
    backlog_heavy.coordination.stale_in_progress_beads = 3;

    let fixtures = [
        healthy,
        disk_red,
        memory_saturated,
        rch_unavailable,
        backlog_heavy,
    ];
    let mut observed_labels = BTreeSet::new();

    for snapshot in fixtures {
        snapshot
            .validate()
            .expect("fixture snapshot should validate");

        let value = serde_json::to_value(&snapshot).expect("serialize snapshot");
        assert_eq!(
            value["schema_version"].as_str(),
            Some(SWARM_CAPACITY_SNAPSHOT_SCHEMA_VERSION)
        );
        observed_labels.insert((
            snapshot.snapshot_id.clone(),
            value["memory"]["pressure_tier"]
                .as_str()
                .expect("memory tier label")
                .to_string(),
            value["disk"]["pressure_level"]
                .as_str()
                .expect("disk pressure label")
                .to_string(),
            value["rch"]["admissibility"]
                .as_str()
                .expect("rch admissibility label")
                .to_string(),
        ));

        let reparsed: SwarmCapacitySnapshot =
            serde_json::from_value(value).expect("deserialize snapshot");
        assert_eq!(reparsed, snapshot);
    }

    assert!(observed_labels.contains(&(
        "healthy-64c".to_string(),
        "healthy".to_string(),
        "healthy".to_string(),
        "available".to_string(),
    )));
    assert!(observed_labels.contains(&(
        "disk-red".to_string(),
        "healthy".to_string(),
        "critical".to_string(),
        "deferred_by_policy".to_string(),
    )));
    assert!(observed_labels.contains(&(
        "memory-saturated".to_string(),
        "saturated".to_string(),
        "healthy".to_string(),
        "degraded".to_string(),
    )));
    assert!(observed_labels.contains(&(
        "rch-unavailable".to_string(),
        "healthy".to_string(),
        "healthy".to_string(),
        "unavailable".to_string(),
    )));
}

#[test]
fn swarm_capacity_snapshot_rejects_invalid_dimensions() {
    let mut snapshot = sample_capacity_snapshot("invalid-schema");
    snapshot.schema_version = "asupersync.swarm-capacity-snapshot.v0".to_string();
    assert_eq!(
        snapshot.validate(),
        Err(SchedulerEvidenceError::UnsupportedSchemaVersion {
            expected: SWARM_CAPACITY_SNAPSHOT_SCHEMA_VERSION.to_string(),
            found: "asupersync.swarm-capacity-snapshot.v0".to_string(),
        })
    );

    let snapshot = sample_capacity_snapshot("   ");
    assert_eq!(
        snapshot.validate(),
        Err(SchedulerEvidenceError::EmptyCapacitySnapshotId)
    );

    let mut snapshot = sample_capacity_snapshot("zero-logical-cpus");
    snapshot.cpu.logical_cpus = 0;
    assert_eq!(
        snapshot.validate(),
        Err(SchedulerEvidenceError::InvalidCapacityDimension {
            field: "cpu.logical_cpus",
        })
    );

    let mut snapshot = sample_capacity_snapshot("zero-physical-cores");
    snapshot.cpu.physical_cores = Some(0);
    assert_eq!(
        snapshot.validate(),
        Err(SchedulerEvidenceError::InvalidCapacityDimension {
            field: "cpu.physical_cores",
        })
    );

    let mut snapshot = sample_capacity_snapshot("memory-available-too-large");
    snapshot.memory.available_bytes = Some(256);
    snapshot.memory.total_bytes = Some(128);
    assert_eq!(
        snapshot.validate(),
        Err(SchedulerEvidenceError::CapacityAvailableExceedsTotal {
            available_field: "memory.available_bytes",
            total_field: "memory.total_bytes",
        })
    );

    let mut snapshot = sample_capacity_snapshot("disk-free-too-large");
    snapshot.disk.free_bytes = Some(256);
    snapshot.disk.total_bytes = Some(128);
    assert_eq!(
        snapshot.validate(),
        Err(SchedulerEvidenceError::CapacityAvailableExceedsTotal {
            available_field: "disk.free_bytes",
            total_field: "disk.total_bytes",
        })
    );
}

#[test]
fn swarm_capacity_snapshot_defaults_and_unknown_fields_are_stable() {
    let raw = serde_json::json!({
        "schema_version": SWARM_CAPACITY_SNAPSHOT_SCHEMA_VERSION,
        "snapshot_id": "sparse-adapter-v1",
        "ignored_top_level": "kept out of the contract",
        "cpu": {
            "logical_cpus": 64,
            "ignored_cpu_hint": 2,
        },
        "memory": {
            "available_bytes": null,
            "total_bytes": null,
            "ignored_memory_hint": true,
        },
        "disk": {
            "ignored_disk_hint": "remote-only",
        },
        "rch": {
            "available_slots": 0,
            "ignored_rch_hint": "preflight-red",
        },
        "coordination": {
            "ready_beads": 1,
            "active_agents": 4,
            "ignored_coordination_hint": "mail-lag",
        },
    });

    let snapshot: SwarmCapacitySnapshot =
        serde_json::from_value(raw).expect("deserialize sparse snapshot");

    assert_eq!(snapshot.validate(), Ok(()));
    assert_eq!(snapshot.cpu.logical_cpus, 64);
    assert_eq!(snapshot.cpu.physical_cores, None);
    assert_eq!(
        snapshot.memory.pressure_tier,
        SwarmMemoryPressureTier::Unknown
    );
    assert_eq!(
        snapshot.disk.pressure_level,
        SwarmDiskPressureLevel::Unknown
    );
    assert_eq!(snapshot.rch.admissibility, SwarmRchAdmissibility::Unknown);
    assert_eq!(snapshot.rch.blocked_reason_codes, Vec::<String>::new());
    assert_eq!(snapshot.coordination.ready_beads, 1);
    assert_eq!(snapshot.coordination.open_beads, 0);
    assert_eq!(snapshot.coordination.active_agents, 4);
    assert_eq!(snapshot.coordination.active_dirty_paths, 0);
}

#[test]
fn swarm_admission_policy_blocks_local_artifacts_under_red_disk() {
    let mut snapshot = sample_capacity_snapshot("red-disk-admission");
    snapshot.disk.free_bytes = Some(8 * 1_024 * 1_024 * 1_024);
    snapshot.disk.pressure_level = SwarmDiskPressureLevel::Critical;
    snapshot.coordination.active_dirty_paths = 4;

    let report = snapshot
        .admission_report()
        .expect("red disk snapshot should produce report");

    assert_eq!(
        report.schema_version,
        SWARM_ADMISSION_POLICY_REPORT_SCHEMA_VERSION
    );
    assert_eq!(report.source_snapshot_id, "red-disk-admission");
    assert_eq!(
        report.recommended_lane,
        SwarmAdmissionLane::InteractiveSourceOnly
    );

    let source = admission_for(&report, SwarmAdmissionLane::InteractiveSourceOnly);
    assert_eq!(source.decision, SwarmAdmissionDecision::Admit);
    assert_eq!(source.validation_class, SwarmValidationClass::SourceOnly);
    assert!(
        source
            .reason_codes
            .contains(&SwarmAdmissionReasonCode::DiskCriticalPreferSourceOnly)
    );
    assert!(
        source
            .reason_codes
            .contains(&SwarmAdmissionReasonCode::PeerDirtyPathsRequireNarrowReservations)
    );

    let tracker = admission_for(&report, SwarmAdmissionLane::TrackerOnlyPlanning);
    assert_eq!(tracker.decision, SwarmAdmissionDecision::Admit);
    assert_eq!(tracker.validation_class, SwarmValidationClass::SourceOnly);

    let remote = admission_for(&report, SwarmAdmissionLane::RemoteProof);
    assert_eq!(remote.decision, SwarmAdmissionDecision::Admit);
    assert!(
        remote
            .reason_codes
            .contains(&SwarmAdmissionReasonCode::DiskCriticalRemoteOnly)
    );

    let local_artifacts = admission_for(&report, SwarmAdmissionLane::LocalArtifactRetrieval);
    assert_eq!(local_artifacts.decision, SwarmAdmissionDecision::Defer);
    assert_eq!(
        local_artifacts.validation_class,
        SwarmValidationClass::LocalArtifact
    );
    assert!(
        local_artifacts
            .reason_codes
            .contains(&SwarmAdmissionReasonCode::DiskCriticalBlocksLocalArtifacts)
    );

    let cleanup = admission_for(&report, SwarmAdmissionLane::CleanupAuthorization);
    assert_eq!(
        cleanup.decision,
        SwarmAdmissionDecision::RequireAuthorization
    );
    assert!(
        cleanup
            .reason_codes
            .contains(&SwarmAdmissionReasonCode::CleanupRequiresAuthorization)
    );
}

#[test]
fn swarm_admission_policy_defers_remote_proof_when_rch_unavailable() {
    let mut snapshot = sample_capacity_snapshot("rch-unavailable-admission");
    snapshot.rch.admissibility = SwarmRchAdmissibility::Unavailable;
    snapshot.rch.healthy_worker_count = Some(0);
    snapshot.rch.available_slots = Some(0);

    let report = snapshot
        .admission_report()
        .expect("rch-unavailable snapshot should produce report");

    let remote = admission_for(&report, SwarmAdmissionLane::RemoteProof);
    assert_eq!(remote.decision, SwarmAdmissionDecision::Defer);
    assert_eq!(remote.validation_class, SwarmValidationClass::RemoteRch);
    assert!(
        remote
            .reason_codes
            .contains(&SwarmAdmissionReasonCode::RchUnavailable)
    );

    let source = admission_for(&report, SwarmAdmissionLane::InteractiveSourceOnly);
    assert_eq!(source.decision, SwarmAdmissionDecision::Admit);
    assert_eq!(
        report.recommended_lane,
        SwarmAdmissionLane::InteractiveSourceOnly
    );
}

#[test]
fn swarm_admission_policy_admits_green_state_heavy_lanes() {
    let snapshot = sample_capacity_snapshot("green-admission");
    let report = snapshot
        .admission_report()
        .expect("green snapshot should produce report");

    assert_eq!(report.recommended_lane, SwarmAdmissionLane::RemoteProof);

    let remote = admission_for(&report, SwarmAdmissionLane::RemoteProof);
    assert_eq!(remote.decision, SwarmAdmissionDecision::Admit);
    assert!(
        remote
            .reason_codes
            .contains(&SwarmAdmissionReasonCode::RchAvailable)
    );

    let local_artifacts = admission_for(&report, SwarmAdmissionLane::LocalArtifactRetrieval);
    assert_eq!(local_artifacts.decision, SwarmAdmissionDecision::Admit);
    assert!(
        local_artifacts
            .reason_codes
            .contains(&SwarmAdmissionReasonCode::DiskHealthy)
    );
}

#[test]
fn swarm_admission_policy_keeps_work_conserving_fallback_on_sparse_queue() {
    let mut snapshot = sample_capacity_snapshot("sparse-queue-admission");
    snapshot.coordination.ready_beads = 0;
    snapshot.disk.pressure_level = SwarmDiskPressureLevel::Critical;
    snapshot.rch.admissibility = SwarmRchAdmissibility::DeferredByPolicy;

    let report = snapshot
        .admission_report()
        .expect("sparse queue snapshot should produce report");

    assert_eq!(
        report.recommended_lane,
        SwarmAdmissionLane::InteractiveSourceOnly
    );
    let source = admission_for(&report, SwarmAdmissionLane::InteractiveSourceOnly);
    let tracker = admission_for(&report, SwarmAdmissionLane::TrackerOnlyPlanning);
    assert_eq!(source.decision, SwarmAdmissionDecision::Admit);
    assert_eq!(tracker.decision, SwarmAdmissionDecision::Admit);
    assert!(
        source
            .reason_codes
            .contains(&SwarmAdmissionReasonCode::SparseReadyQueueUseFallback)
    );
    assert!(
        tracker
            .reason_codes
            .contains(&SwarmAdmissionReasonCode::SparseReadyQueueUseFallback)
    );
}

#[test]
fn swarm_memory_budget_planner_handles_32gb_hosts() {
    const GIB: u64 = 1_024 * 1_024 * 1_024;

    let mut snapshot = sample_capacity_snapshot("memory-budget-32gb");
    snapshot.memory.total_bytes = Some(32 * GIB);
    snapshot.memory.available_bytes = Some(24 * GIB);

    let plan = snapshot
        .memory_budget_plan()
        .expect("32GB snapshot should produce memory budget plan");

    assert_eq!(plan.schema_version, SWARM_MEMORY_BUDGET_PLAN_SCHEMA_VERSION);
    assert_eq!(plan.source_snapshot_id, "memory-budget-32gb");
    assert_eq!(plan.host_tier, SwarmMemoryHostTier::Small);
    assert_eq!(plan.pressure_tier, SwarmMemoryPressureTier::Healthy);
    assert_eq!(plan.emergency_reserve_bytes, 4 * GIB);
    assert_memory_plan_invariants(&plan);
    assert!(plan.interactive_runtime_bytes > plan.proof_artifact_staging_bytes);
}

#[test]
fn swarm_memory_budget_planner_scales_trace_and_proof_windows_on_128gb_hosts() {
    const GIB: u64 = 1_024 * 1_024 * 1_024;

    let mut small = sample_capacity_snapshot("memory-budget-small-baseline");
    small.memory.total_bytes = Some(32 * GIB);
    small.memory.available_bytes = Some(24 * GIB);
    let small_plan = small
        .memory_budget_plan()
        .expect("small host should produce memory budget plan");

    let mut standard = sample_capacity_snapshot("memory-budget-128gb");
    standard.memory.total_bytes = Some(128 * GIB);
    standard.memory.available_bytes = Some(96 * GIB);
    let standard_plan = standard
        .memory_budget_plan()
        .expect("128GB snapshot should produce memory budget plan");

    assert_eq!(standard_plan.host_tier, SwarmMemoryHostTier::Standard);
    assert_memory_plan_invariants(&standard_plan);
    assert!(standard_plan.trace_replay_bytes > small_plan.trace_replay_bytes);
    assert!(standard_plan.proof_artifact_staging_bytes > small_plan.proof_artifact_staging_bytes);
    assert!(standard_plan.compiler_cache_bytes > small_plan.compiler_cache_bytes);
}

#[test]
fn swarm_memory_budget_planner_expands_256gb_trace_and_proof_budgets() {
    const GIB: u64 = 1_024 * 1_024 * 1_024;

    let mut standard = sample_capacity_snapshot("memory-budget-128gb-baseline");
    standard.memory.total_bytes = Some(128 * GIB);
    standard.memory.available_bytes = Some(96 * GIB);
    let standard_plan = standard
        .memory_budget_plan()
        .expect("128GB snapshot should produce memory budget plan");

    let snapshot = sample_capacity_snapshot("memory-budget-256gb");
    let plan = snapshot
        .memory_budget_plan()
        .expect("256GB snapshot should produce memory budget plan");

    assert_eq!(plan.host_tier, SwarmMemoryHostTier::HighMemory);
    assert_eq!(plan.emergency_reserve_bytes, 32 * GIB);
    assert_memory_plan_invariants(&plan);
    assert!(plan.trace_replay_bytes > standard_plan.trace_replay_bytes);
    assert!(plan.proof_artifact_staging_bytes > standard_plan.proof_artifact_staging_bytes);
    assert!(plan.interactive_runtime_bytes > 0);
}

#[test]
fn swarm_memory_budget_planner_degrades_artifacts_before_interactive_under_pressure() {
    const GIB: u64 = 1_024 * 1_024 * 1_024;

    let mut snapshot = sample_capacity_snapshot("memory-budget-saturated");
    snapshot.memory.available_bytes = Some(64 * GIB);
    snapshot.memory.pressure_tier = SwarmMemoryPressureTier::Saturated;

    let saturated = snapshot
        .memory_budget_plan()
        .expect("saturated snapshot should produce memory budget plan");

    assert_eq!(saturated.host_tier, SwarmMemoryHostTier::HighMemory);
    assert_eq!(saturated.pressure_tier, SwarmMemoryPressureTier::Saturated);
    assert_memory_plan_invariants(&saturated);
    assert!(saturated.interactive_runtime_bytes > saturated.proof_artifact_staging_bytes);
    assert!(saturated.interactive_runtime_bytes > saturated.compiler_cache_bytes);
    assert!(saturated.emergency_reserve_bytes >= saturated.available_bytes / 3);

    snapshot.memory.pressure_tier = SwarmMemoryPressureTier::Critical;
    let critical = snapshot
        .memory_budget_plan()
        .expect("critical snapshot should produce memory budget plan");

    assert_eq!(critical.proof_artifact_staging_bytes, 0);
    assert_eq!(critical.compiler_cache_bytes, 0);
    assert!(critical.interactive_runtime_bytes > 0);
    assert_memory_plan_invariants(&critical);
}

#[test]
fn swarm_memory_budget_planner_emits_stable_golden_shapes() {
    const GIB: u64 = 1_024 * 1_024 * 1_024;

    let mut small = sample_capacity_snapshot("memory-budget-golden-32gb");
    small.memory.total_bytes = Some(32 * GIB);
    small.memory.available_bytes = Some(24 * GIB);
    let small_plan = small
        .memory_budget_plan()
        .expect("32GB snapshot should produce memory budget plan");
    assert_eq!(
        serde_json::to_value(&small_plan).expect("serialize small memory budget plan"),
        serde_json::json!({
            "schema_version": SWARM_MEMORY_BUDGET_PLAN_SCHEMA_VERSION,
            "source_snapshot_id": "memory-budget-golden-32gb",
            "host_tier": "small",
            "pressure_tier": "healthy",
            "available_bytes": 24 * GIB,
            "total_bytes": 32 * GIB,
            "emergency_reserve_bytes": 4 * GIB,
            "interactive_runtime_bytes": 9 * GIB,
            "trace_replay_bytes": 5 * GIB,
            "proof_artifact_staging_bytes": 3 * GIB,
            "compiler_cache_bytes": 3 * GIB,
            "total_planned_bytes": 20 * GIB,
        })
    );

    let high_memory = sample_capacity_snapshot("memory-budget-golden-256gb");
    let high_memory_plan = high_memory
        .memory_budget_plan()
        .expect("256GB snapshot should produce memory budget plan");
    assert_eq!(
        serde_json::to_value(&high_memory_plan).expect("serialize high-memory budget plan"),
        serde_json::json!({
            "schema_version": SWARM_MEMORY_BUDGET_PLAN_SCHEMA_VERSION,
            "source_snapshot_id": "memory-budget-golden-256gb",
            "host_tier": "high_memory",
            "pressure_tier": "healthy",
            "available_bytes": 192 * GIB,
            "total_bytes": 256 * GIB,
            "emergency_reserve_bytes": 32 * GIB,
            "interactive_runtime_bytes": 40 * GIB,
            "trace_replay_bytes": 56 * GIB,
            "proof_artifact_staging_bytes": 40 * GIB,
            "compiler_cache_bytes": 24 * GIB,
            "total_planned_bytes": 160 * GIB,
        })
    );

    let mut critical = sample_capacity_snapshot("memory-budget-golden-critical");
    critical.memory.available_bytes = Some(64 * GIB);
    critical.memory.pressure_tier = SwarmMemoryPressureTier::Critical;
    let critical_plan = critical
        .memory_budget_plan()
        .expect("critical snapshot should produce memory budget plan");
    assert_eq!(
        serde_json::to_value(&critical_plan).expect("serialize critical budget plan"),
        serde_json::json!({
            "schema_version": SWARM_MEMORY_BUDGET_PLAN_SCHEMA_VERSION,
            "source_snapshot_id": "memory-budget-golden-critical",
            "host_tier": "high_memory",
            "pressure_tier": "critical",
            "available_bytes": 64 * GIB,
            "total_bytes": 256 * GIB,
            "emergency_reserve_bytes": 32 * GIB,
            "interactive_runtime_bytes": 30_923_764_531_u64,
            "trace_replay_bytes": 3_435_973_836_u64,
            "proof_artifact_staging_bytes": 0_u64,
            "compiler_cache_bytes": 0_u64,
            "total_planned_bytes": 34_359_738_367_u64,
        })
    );
}

#[test]
fn runtime_scheduler_evidence_disabled_mode_is_semantics_neutral() {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);

    scheduler.inject_ready(TaskId::new_for_test(21, 0), 30);
    scheduler.inject_cancel(TaskId::new_for_test(22, 0), 90);
    scheduler.inject_timed(TaskId::new_for_test(23, 0), Time::ZERO);

    let mut worker = scheduler.take_workers().remove(0);
    let dispatch_trace = vec![
        worker.next_task(),
        worker.next_task(),
        worker.next_task(),
        worker.next_task(),
    ];

    assert_eq!(
        dispatch_trace,
        vec![
            Some(TaskId::new_for_test(22, 0)),
            Some(TaskId::new_for_test(23, 0)),
            Some(TaskId::new_for_test(21, 0)),
            None,
        ],
        "disabled evidence capture must not perturb lane dispatch order"
    );
    drop(worker);

    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
    scheduler.set_scheduler_evidence_window(0);
    assert!(
        scheduler
            .scheduler_evidence_artifact("disabled", SchedulerWorkloadClass::MixedBurst, 256)
            .is_none(),
        "zero sample window should keep runtime evidence capture disabled"
    );
}

#[test]
fn runtime_scheduler_evidence_artifact_captures_live_dispatch_samples() {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(2, &state, 16);
    scheduler.set_scheduler_evidence_window(32);
    scheduler
        .set_worker_cohort_map(&[0, 1])
        .expect("cohort map should apply");

    let local_ready = TaskId::new_for_test(10, 0);
    let ready_a = TaskId::new_for_test(11, 0);
    let ready_b = TaskId::new_for_test(12, 0);
    let cancel = TaskId::new_for_test(13, 0);
    let timed = TaskId::new_for_test(14, 0);

    scheduler.inject_ready(ready_a, 30);
    scheduler.inject_ready(ready_b, 40);
    scheduler.inject_cancel(cancel, 90);
    scheduler.inject_timed(timed, Time::ZERO);

    let mut dispatched_ready = BTreeSet::new();
    {
        let worker = scheduler.worker_mut_for_test(0);
        worker.schedule_local(local_ready, 60);

        assert_eq!(worker.next_task(), Some(cancel));
        assert_eq!(worker.next_task(), Some(timed));
        dispatched_ready.insert(worker.next_task().expect("first ready task"));
        dispatched_ready.insert(worker.next_task().expect("second ready task"));
        dispatched_ready.insert(worker.next_task().expect("third ready task"));
        assert_eq!(
            dispatched_ready,
            BTreeSet::from([local_ready, ready_a, ready_b])
        );
        assert_eq!(worker.next_task(), None);
    }

    let artifact = scheduler
        .scheduler_evidence_artifact("runtime-capture", SchedulerWorkloadClass::MixedBurst, 256)
        .expect("runtime evidence should be available");

    assert_eq!(artifact.validate(), Ok(()));
    assert_eq!(
        artifact.schema_version,
        SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string()
    );
    assert_eq!(artifact.run_label, "runtime-capture");
    assert_eq!(artifact.topology.worker_threads, 2);
    assert_eq!(artifact.topology.cohort_count, 2);
    assert_eq!(artifact.topology.memory_budget_gib, 256);
    assert_eq!(artifact.current_knobs.worker_threads, 2);
    assert!(artifact.current_knobs.steal_batch_size > 0);
    assert!(artifact.current_knobs.cancel_streak_limit > 0);
    assert!(
        artifact.metrics.wake_to_run_p95_ns >= artifact.metrics.wake_to_run_p50_ns,
        "wake-to-run percentiles should be monotone"
    );
    assert!(
        artifact.metrics.wake_to_run_p99_ns >= artifact.metrics.wake_to_run_p95_ns,
        "wake-to-run percentiles should be monotone"
    );
    assert!(
        artifact.metrics.queue_residency_p95_ns >= artifact.metrics.queue_residency_p50_ns,
        "queue residency percentiles should be monotone"
    );
    assert!(
        artifact.metrics.queue_residency_p99_ns >= artifact.metrics.queue_residency_p95_ns,
        "queue residency percentiles should be monotone"
    );
    assert!(
        artifact.metrics.ready_backlog_p99 >= artifact.metrics.ready_backlog_p95,
        "ready backlog percentiles should be monotone"
    );
    assert!(
        artifact.metrics.cancel_debt_p99 >= artifact.metrics.cancel_debt_p95,
        "cancel debt percentiles should be monotone"
    );
    assert!(
        artifact.notes.iter().any(|note| note == "runtime_capture"),
        "artifact should mark live runtime capture"
    );
    assert!(
        artifact.notes.iter().any(|note| note == "sample_window=32"),
        "artifact should surface the configured sample window"
    );
    assert!(
        artifact
            .notes
            .iter()
            .any(|note| note.starts_with("sample_counts=")),
        "artifact should surface collected sample counts"
    );

    if let Ok(capture_path) = std::env::var("ASUPERSYNC_SCHEDULER_EVIDENCE_CAPTURE_PATH") {
        let capture_path = Path::new(&capture_path);
        if let Some(parent) = capture_path.parent() {
            std::fs::create_dir_all(parent).expect("create capture directory");
        }
        let payload =
            serde_json::to_vec_pretty(&artifact).expect("serialize runtime capture artifact");
        std::fs::write(capture_path, payload).expect("write runtime capture artifact");
    }
}

fn measure_scheduler_evidence_overhead(
    sample_window: usize,
    iterations: usize,
    ready_tasks_per_iteration: usize,
) -> (u128, usize, usize, Option<SchedulerEvidenceArtifact>) {
    let mut total_elapsed_ns = 0u128;
    let mut total_drained = 0usize;
    let mut max_artifact_bytes = 0usize;
    let mut last_artifact = None;

    for _ in 0..iterations {
        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
        scheduler.set_scheduler_evidence_window(sample_window);

        for task in 0..ready_tasks_per_iteration as u32 {
            scheduler.inject_ready(TaskId::new_for_test(task, 0), 50);
        }

        let started = Instant::now();
        {
            let worker = scheduler.worker_mut_for_test(0);
            while worker.next_task().is_some() {
                total_drained += 1;
            }
        }

        if sample_window > 0 {
            let artifact = scheduler
                .scheduler_evidence_artifact(
                    "overhead-capture",
                    SchedulerWorkloadClass::MixedBurst,
                    256,
                )
                .expect("enabled evidence window should emit a scheduler artifact");
            max_artifact_bytes = max_artifact_bytes.max(
                serde_json::to_vec(&artifact)
                    .expect("serialize overhead artifact")
                    .len(),
            );
            last_artifact = Some(artifact);
        }

        total_elapsed_ns += started.elapsed().as_nanos();
    }

    (
        total_elapsed_ns,
        total_drained,
        max_artifact_bytes,
        last_artifact,
    )
}

#[test]
fn runtime_scheduler_evidence_overhead_stays_bounded() {
    const ITERATIONS: usize = 8;
    const READY_TASKS_PER_ITERATION: usize = 4096;
    const SAMPLE_WINDOW: usize = 256;
    const OVERHEAD_RATIO_BUDGET: f64 = 4.0;

    let (baseline_elapsed_ns, baseline_drained, _, _) =
        measure_scheduler_evidence_overhead(0, ITERATIONS, READY_TASKS_PER_ITERATION);
    let (evidence_elapsed_ns, evidence_drained, artifact_bytes, artifact) =
        measure_scheduler_evidence_overhead(SAMPLE_WINDOW, ITERATIONS, READY_TASKS_PER_ITERATION);

    assert_eq!(
        baseline_drained, evidence_drained,
        "evidence capture must not change how many ready tasks drain through the worker"
    );

    let overhead_ratio = evidence_elapsed_ns as f64 / baseline_elapsed_ns.max(1) as f64;
    assert!(
        overhead_ratio.is_finite(),
        "overhead ratio must remain finite"
    );
    assert!(
        overhead_ratio <= OVERHEAD_RATIO_BUDGET,
        "scheduler evidence overhead ratio {:.3} exceeded conservative budget {:.3} (baseline={}ns evidence={}ns)",
        overhead_ratio,
        OVERHEAD_RATIO_BUDGET,
        baseline_elapsed_ns,
        evidence_elapsed_ns
    );
    assert!(
        artifact_bytes <= 2_048,
        "enabled evidence artifact should stay compact during overhead capture: {} bytes",
        artifact_bytes
    );

    let artifact = artifact.expect("enabled capture should return an artifact");
    let report = serde_json::json!({
        "schema_version": "scheduler-evidence-overhead-report-v1",
        "iterations": ITERATIONS,
        "ready_tasks_per_iteration": READY_TASKS_PER_ITERATION,
        "sample_window": SAMPLE_WINDOW,
        "baseline_elapsed_ns": baseline_elapsed_ns,
        "evidence_elapsed_ns": evidence_elapsed_ns,
        "baseline_drained_tasks": baseline_drained,
        "evidence_drained_tasks": evidence_drained,
        "artifact_bytes": artifact_bytes,
        "overhead_ratio": overhead_ratio,
        "overhead_ratio_budget": OVERHEAD_RATIO_BUDGET,
        "bounded_overhead": overhead_ratio <= OVERHEAD_RATIO_BUDGET,
        "capture_notes": artifact.notes,
    });

    println!("SCHEDULER_EVIDENCE_OVERHEAD_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize overhead report")
    );
    println!("SCHEDULER_EVIDENCE_OVERHEAD_REPORT_JSON_END");

    if let Ok(report_path) = std::env::var("ASUPERSYNC_SCHEDULER_EVIDENCE_OVERHEAD_REPORT_PATH") {
        let report_path = Path::new(&report_path);
        if let Some(parent) = report_path.parent() {
            std::fs::create_dir_all(parent).expect("create overhead report directory");
        }
        std::fs::write(
            report_path,
            serde_json::to_vec_pretty(&report).expect("serialize overhead report payload"),
        )
        .expect("write overhead report payload");
    }
}

fn load_scheduler_recommend_contract() -> Value {
    serde_json::from_str(include_str!(
        "../artifacts/scheduler_recommend_smoke_contract_v1.json"
    ))
    .expect("parse scheduler recommend smoke contract")
}

fn scenario_by_id<'a>(contract: &'a Value, scenario_id: &str) -> &'a Value {
    contract["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios should be an array")
        .iter()
        .find(|scenario| scenario["scenario_id"].as_str() == Some(scenario_id))
        .unwrap_or_else(|| panic!("missing scenario: {scenario_id}"))
}

fn missing_required_fields(
    contract: &Value,
    field_list_key: &str,
    artifact: &Value,
) -> Vec<String> {
    contract[field_list_key]
        .as_array()
        .unwrap_or_else(|| panic!("{field_list_key} should be an array"))
        .iter()
        .map(|field| {
            field
                .as_str()
                .unwrap_or_else(|| panic!("{field_list_key} entries should be strings"))
        })
        .filter(|field| artifact.get(*field).is_none() || artifact[*field].is_null())
        .map(str::to_string)
        .collect()
}

fn assert_required_fields_present(
    contract: &Value,
    field_list_key: &str,
    artifact: &Value,
    label: &str,
) {
    let missing = missing_required_fields(contract, field_list_key, artifact);
    assert!(
        missing.is_empty(),
        "{label} missing required {field_list_key} fields: {missing:?}"
    );
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn scheduler_recommend_required_field_validator_reports_missing_fields() {
    let contract = load_scheduler_recommend_contract();
    let incomplete_bundle = serde_json::json!({
        "schema_version": "scheduler-recommend-smoke-bundle-v1",
        "contract_version": contract["contract_version"],
        "scenario_id": "AA-SCHED-RECOMMEND-MIXED-BURST-64C",
    });

    let missing = missing_required_fields(&contract, "required_bundle_fields", &incomplete_bundle);

    assert!(
        missing.iter().any(|field| field == "host_fingerprint"),
        "validator should report missing host_fingerprint"
    );
    assert!(
        missing.iter().any(|field| field == "workload_seed"),
        "validator should report missing workload_seed"
    );
    assert!(
        missing.iter().any(|field| field == "verdict_summary"),
        "validator should report missing verdict_summary"
    );
}

#[test]
fn scheduler_recommend_smoke_contract_matches_tuning_projection() {
    let contract = load_scheduler_recommend_contract();
    assert_eq!(
        contract["runner_script"].as_str(),
        Some("scripts/run_scheduler_recommend_smoke.sh")
    );
    assert!(
        contract["required_bundle_fields"]
            .as_array()
            .expect("required_bundle_fields")
            .iter()
            .any(|field| field.as_str() == Some("scenario_class"))
    );
    assert!(
        contract["required_run_report_fields"]
            .as_array()
            .expect("required_run_report_fields")
            .iter()
            .any(|field| field.as_str() == Some("execution_policy"))
    );
    assert!(
        contract["required_bundle_fields"]
            .as_array()
            .expect("required_bundle_fields")
            .iter()
            .any(|field| field.as_str() == Some("capture_mode"))
    );
    assert!(
        contract["required_run_report_fields"]
            .as_array()
            .expect("required_run_report_fields")
            .iter()
            .any(|field| field.as_str() == Some("capture_command_exit_code"))
    );
    assert!(
        contract["required_bundle_fields"]
            .as_array()
            .expect("required_bundle_fields")
            .iter()
            .any(|field| field.as_str() == Some("host_fingerprint"))
    );
    assert!(
        contract["required_bundle_fields"]
            .as_array()
            .expect("required_bundle_fields")
            .iter()
            .any(|field| field.as_str() == Some("throughput_summary"))
    );
    assert!(
        contract["required_bundle_fields"]
            .as_array()
            .expect("required_bundle_fields")
            .iter()
            .any(|field| field.as_str() == Some("config_snapshot"))
    );
    assert!(
        contract["required_run_report_fields"]
            .as_array()
            .expect("required_run_report_fields")
            .iter()
            .any(|field| field.as_str() == Some("controller_state_references"))
    );
    assert!(
        contract["required_run_report_fields"]
            .as_array()
            .expect("required_run_report_fields")
            .iter()
            .any(|field| field.as_str() == Some("latency_summary"))
    );
    assert!(
        contract["required_run_report_fields"]
            .as_array()
            .expect("required_run_report_fields")
            .iter()
            .any(|field| field.as_str() == Some("verdict_summary"))
    );

    let scenarios = contract["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios should be an array");
    assert_eq!(
        scenarios.len(),
        3,
        "expected fixture, runtime-capture, and real-host scenarios"
    );

    let scenario = scenario_by_id(&contract, "AA-SCHED-RECOMMEND-MIXED-BURST-64C");
    assert_eq!(
        scenario["scenario_id"].as_str(),
        Some("AA-SCHED-RECOMMEND-MIXED-BURST-64C")
    );
    assert_eq!(
        scenario["scenario_class"].as_str(),
        Some("deterministic_lab_safe")
    );
    assert_eq!(
        scenario["execution_policy"].as_str(),
        Some("execute_or_dry_run")
    );
    assert_eq!(
        scenario["topology_profile"]["name"].as_str(),
        Some("dual_cohort_64c")
    );
    assert_eq!(scenario["memory_profile"]["budget_gib"].as_u64(), Some(256));
    assert_eq!(
        scenario["workload_seed"].as_str(),
        Some("mixed-burst-64c-seed-v1")
    );
    assert_eq!(
        scenario["queue_storm_shape"]["shape"].as_str(),
        Some("mixed_burst_ready_spike")
    );
    assert_eq!(
        scenario["cancel_storm_shape"]["shape"].as_str(),
        Some("moderate_cancel_debt")
    );
    assert_eq!(
        scenario["controller_state_references"]
            .as_array()
            .expect("controller_state_references")
            .len(),
        4
    );

    let evidence: SchedulerEvidenceArtifact =
        serde_json::from_value(scenario["evidence_artifact"].clone())
            .expect("scenario evidence should deserialize");
    let report = evidence
        .tune_report()
        .expect("scenario evidence should tune");

    let actual_projection = serde_json::json!({
        "schema_version": report.schema_version,
        "source_run_label": report.source_run_label,
        "workload_class": report.workload_class,
        "profile_name": report.profile_name,
        "recommended_knobs": report.recommended_knobs,
        "global_queue_limit_hint": report.global_queue_limit_hint,
        "fallback_profile": report.fallback_profile,
        "confidence_percent": report.confidence_percent,
        "reason_codes": report.reason_codes,
    });

    assert_eq!(actual_projection, scenario["expected_report"]);
}

#[test]
fn scheduler_recommend_smoke_contract_declares_runtime_capture_scenario() {
    let contract = load_scheduler_recommend_contract();
    let scenario = scenario_by_id(&contract, "AA-SCHED-RECOMMEND-RUNTIME-CAPTURE-2W");

    assert_eq!(
        scenario["scenario_class"].as_str(),
        Some("deterministic_lab_safe")
    );
    assert_eq!(
        scenario["execution_policy"].as_str(),
        Some("execute_or_dry_run")
    );
    assert_eq!(
        scenario["capture_mode"].as_str(),
        Some("runtime_test_capture")
    );
    let capture_command = scenario["capture_command"]
        .as_str()
        .expect("runtime capture scenario should declare a capture command");
    assert!(
        capture_command
            .contains("runtime_scheduler_evidence_artifact_captures_live_dispatch_samples"),
        "capture command should target the live runtime evidence test"
    );
    assert_eq!(scenario["expected_report"], serde_json::Value::Null);
    assert!(
        scenario["template_env"]["ASUPERSYNC_SCHEDULER_EVIDENCE_CAPTURE_PATH"]
            .as_str()
            .is_some(),
        "runner-managed capture path should be documented"
    );
    assert_eq!(
        scenario["throughput_summary"]["source"].as_str(),
        Some("runtime_capture_test")
    );
    assert_eq!(scenario["throughput_summary"]["observed"].as_u64(), Some(5));
    assert_eq!(
        scenario["queue_storm_shape"]["dispatch_samples"].as_u64(),
        Some(5)
    );
    assert_eq!(
        scenario["fallback_activations_hint"]["activated"].as_bool(),
        Some(true)
    );
}

#[test]
fn scheduler_recommend_smoke_contract_declares_real_host_template() {
    let contract = load_scheduler_recommend_contract();
    let scenario = scenario_by_id(&contract, "AA-SCHED-RECOMMEND-REAL-HOST-64C-256G");

    assert_eq!(
        scenario["scenario_class"].as_str(),
        Some("real_host_template")
    );
    assert_eq!(scenario["execution_policy"].as_str(), Some("dry_run_only"));
    assert_eq!(
        scenario["host_requirements"]["min_worker_threads"].as_u64(),
        Some(64)
    );
    assert_eq!(
        scenario["host_requirements"]["min_memory_gib"].as_u64(),
        Some(256)
    );
    assert_eq!(
        scenario["expected_profile_name_hint"].as_str(),
        Some("operator_captured")
    );
    assert_eq!(
        scenario["expected_report"],
        serde_json::Value::Null,
        "template scenario should not pin a synthetic report projection"
    );
    assert!(
        scenario["template_env"]["ASUPERSYNC_SCHEDULER_EVIDENCE_CAPTURE"]
            .as_str()
            .is_some()
    );
    assert_eq!(
        scenario["throughput_summary"]["source"].as_str(),
        Some("operator_capture")
    );
    assert_eq!(
        scenario["queue_storm_shape"]["shape"].as_str(),
        Some("operator_supplied")
    );
    assert_eq!(
        scenario["cancel_storm_shape"]["shape"].as_str(),
        Some("operator_supplied")
    );
    assert_eq!(
        scenario["memory_profile"]["name"].as_str(),
        Some("operator_template_256g")
    );

    let evidence: SchedulerEvidenceArtifact =
        serde_json::from_value(scenario["evidence_artifact"].clone())
            .expect("real host template evidence should deserialize");
    assert!(
        evidence
            .notes
            .iter()
            .any(|note| note == "real_host_template"),
        "template evidence should self-identify as real-host-only"
    );
}

#[test]
fn scheduler_recommend_smoke_runner_dry_run_emits_template_bundle_contract() {
    let root = repo_root();
    let output_root = tempfile::tempdir().expect("tempdir");
    let script_path = root.join("scripts/run_scheduler_recommend_smoke.sh");
    let run_id = "run_contract_real_host";

    let status = Command::new("bash")
        .arg(&script_path)
        .arg("--scenario")
        .arg("AA-SCHED-RECOMMEND-REAL-HOST-64C-256G")
        .arg("--dry-run")
        .current_dir(&root)
        .env("SCHEDULER_RECOMMEND_SMOKE_RUN_ID", run_id)
        .arg("--output-root")
        .arg(output_root.path())
        .status()
        .expect("run real-host dry-run runner");
    assert!(status.success(), "real-host dry-run should succeed");

    let bundle_path = output_root
        .path()
        .join(run_id)
        .join("AA-SCHED-RECOMMEND-REAL-HOST-64C-256G")
        .join("bundle_manifest.json");
    let report_path = output_root
        .path()
        .join(run_id)
        .join("AA-SCHED-RECOMMEND-REAL-HOST-64C-256G")
        .join("run_report.json");
    assert!(bundle_path.exists(), "bundle manifest must exist");
    assert!(report_path.exists(), "run report must exist");

    let bundle_raw = std::fs::read_to_string(&bundle_path).expect("read bundle manifest");
    let bundle: Value = serde_json::from_str(&bundle_raw).expect("parse bundle manifest");
    let report_raw = std::fs::read_to_string(&report_path).expect("read run report");
    let report: Value = serde_json::from_str(&report_raw).expect("parse run report");
    let contract = load_scheduler_recommend_contract();

    assert_required_fields_present(
        &contract,
        "required_bundle_fields",
        &bundle,
        "real-host dry-run bundle",
    );
    assert_required_fields_present(
        &contract,
        "required_run_report_fields",
        &report,
        "real-host dry-run report",
    );

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("scheduler-recommend-smoke-bundle-v1")
    );
    assert_eq!(
        bundle["artifact_path"].as_str(),
        bundle_path.to_str(),
        "bundle path should be recorded verbatim"
    );
    assert_eq!(
        report["artifact_path"].as_str(),
        report_path.to_str(),
        "report path should be recorded verbatim"
    );
    assert_eq!(bundle["run_id"].as_str(), Some(run_id));
    assert_eq!(report["run_id"].as_str(), Some(run_id));
    assert_eq!(bundle["status"].as_str(), Some("dry_run"));
    assert_eq!(report["status"].as_str(), Some("dry_run"));
    assert_eq!(
        bundle["verdict_summary"]["status"].as_str(),
        Some("dry_run")
    );
    assert_eq!(
        report["verdict_summary"]["execution_policy"].as_str(),
        Some("dry_run_only")
    );
    assert_eq!(
        bundle["config_snapshot"]["current_knobs"]["worker_threads"].as_u64(),
        Some(64)
    );
    assert_eq!(
        report["config_snapshot"]["source"].as_str(),
        Some("scheduler_evidence.current_knobs")
    );
    assert!(
        bundle["host_fingerprint"]["cpu_threads"]
            .as_u64()
            .is_some_and(|threads| threads > 0),
        "host fingerprint should record the executing host's nonzero CPU thread count"
    );
    assert_eq!(
        report["memory_profile"]["name"].as_str(),
        Some("operator_template_256g")
    );
    assert_eq!(
        report["queue_storm_shape"]["shape"].as_str(),
        Some("operator_supplied")
    );
    assert_eq!(bundle["workload_seed"].as_str(), Some("operator-supplied"));
    assert_eq!(report["workload_seed"].as_str(), Some("operator-supplied"));
    assert_eq!(
        bundle["verdict_summary"], report["verdict_summary"],
        "bundle and run report should share one verdict summary"
    );

    let run_log_path = bundle["run_log_path"]
        .as_str()
        .expect("bundle should record run_log_path");
    let run_log_raw = std::fs::read_to_string(run_log_path).expect("read run log");
    assert!(
        run_log_raw.contains("CAPTURE_EMBEDDED"),
        "dry-run log should preserve evidence capture event"
    );
    assert!(
        run_log_raw.contains("DRY_RUN"),
        "dry-run log should record the refused command layout"
    );
}

#[test]
fn scheduler_recommend_smoke_runner_executes_commands_without_local_shell_wrapper() {
    let script = std::fs::read_to_string("scripts/run_scheduler_recommend_smoke.sh")
        .expect("scheduler recommend smoke runner should load");
    let forbidden = ["bash", " -lc"].concat();

    assert!(
        script.contains("split_command_words()"),
        "runner should split artifact command strings into argv"
    );
    assert!(
        script.contains("COMMAND_ARGS=("),
        "runner should store the offline tuner invocation as argv"
    );
    assert!(
        script.contains(r#""${COMMAND_ARGS[@]}" 2>&1 | tee -a "$LOG_FILE""#),
        "offline tuner should execute without a local shell wrapper"
    );
    assert!(
        script.contains(r#""${command_args[@]}" 2>&1 | tee -a "$LOG_FILE""#),
        "runtime capture should execute without a local shell wrapper"
    );
    assert!(
        script.contains(r#"printf -v COMMAND '%q ' "${COMMAND_ARGS[@]}""#),
        "runner should retain shell-escaped command provenance"
    );
    assert!(
        !script.contains(&forbidden),
        "runner should not use a local shell wrapper for proof commands"
    );
}

#[test]
fn scheduler_recommend_smoke_runner_execute_emits_config_snapshot_and_verdict() {
    let root = repo_root();
    let output_root = tempfile::tempdir().expect("tempdir");
    let target_root = tempfile::tempdir().expect("tempdir");
    let script_path = root.join("scripts/run_scheduler_recommend_smoke.sh");
    let run_id = "run_contract_execute";

    let status = Command::new("bash")
        .arg(&script_path)
        .arg("--scenario")
        .arg("AA-SCHED-RECOMMEND-MIXED-BURST-64C")
        .arg("--execute")
        .current_dir(&root)
        .env("SCHEDULER_RECOMMEND_SMOKE_RUN_ID", run_id)
        .env("CARGO_TARGET_DIR", target_root.path())
        .arg("--output-root")
        .arg(output_root.path())
        .status()
        .expect("run execute runner");
    assert!(status.success(), "execute runner should succeed");

    let bundle_path = output_root
        .path()
        .join(run_id)
        .join("AA-SCHED-RECOMMEND-MIXED-BURST-64C")
        .join("bundle_manifest.json");
    let report_path = output_root
        .path()
        .join(run_id)
        .join("AA-SCHED-RECOMMEND-MIXED-BURST-64C")
        .join("run_report.json");
    assert!(bundle_path.exists(), "bundle manifest must exist");
    assert!(report_path.exists(), "run report must exist");

    let bundle_raw = std::fs::read_to_string(&bundle_path).expect("read bundle manifest");
    let bundle: Value = serde_json::from_str(&bundle_raw).expect("parse bundle manifest");
    let report_raw = std::fs::read_to_string(&report_path).expect("read run report");
    let report: Value = serde_json::from_str(&report_raw).expect("parse run report");
    let contract = load_scheduler_recommend_contract();

    assert_required_fields_present(
        &contract,
        "required_bundle_fields",
        &bundle,
        "execute bundle",
    );
    assert_required_fields_present(
        &contract,
        "required_run_report_fields",
        &report,
        "execute run report",
    );

    assert_eq!(bundle["status"].as_str(), Some("passed"));
    assert_eq!(report["status"].as_str(), Some("passed"));
    assert_eq!(
        bundle["verdict_summary"]["actual_profile_name"].as_str(),
        Some("scale_workers")
    );
    assert_eq!(
        report["verdict_summary"]["message"].as_str(),
        Some("report matched expected projection")
    );
    assert_eq!(
        bundle["config_snapshot"]["recommended_knobs"]["worker_threads"].as_u64(),
        Some(66)
    );
    assert_eq!(
        report["config_snapshot"]["fallback_profile"]["worker_threads"].as_u64(),
        Some(64)
    );
    assert_eq!(
        bundle["latency_summary"]["wake_to_run_ns"]["p99"].as_u64(),
        Some(220_000)
    );
    assert_eq!(
        report["throughput_summary"]["source"].as_str(),
        Some("contract_fixture")
    );
    assert_eq!(
        bundle["artifact_path"].as_str(),
        bundle_path.to_str(),
        "bundle path should be recorded verbatim"
    );
    assert_eq!(
        report["bundle_manifest_path"].as_str(),
        bundle_path.to_str(),
        "run report should point back to the bundle manifest"
    );
    assert_eq!(
        bundle["workload_seed"].as_str(),
        Some("mixed-burst-64c-seed-v1")
    );
    assert_eq!(
        report["workload_seed"].as_str(),
        Some("mixed-burst-64c-seed-v1")
    );
    assert_eq!(
        bundle["verdict_summary"], report["verdict_summary"],
        "bundle and run report should share one verdict summary"
    );

    let run_log_path = bundle["run_log_path"]
        .as_str()
        .expect("bundle should record run_log_path");
    let run_log_raw = std::fs::read_to_string(run_log_path).expect("read run log");
    assert!(
        run_log_raw.contains("CAPTURE_EMBEDDED"),
        "execute log should preserve evidence capture event before offline_tuner output"
    );
    assert!(
        run_log_raw.contains("asupersync.scheduler-evidence.v1"),
        "execute log should include the offline_tuner report payload"
    );
}
