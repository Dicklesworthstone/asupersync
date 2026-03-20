//! LabRuntime integration coverage for the current FABRIC subject-cell foundation.
#![cfg(feature = "messaging-fabric")]

use asupersync::cx::{Cx, cap};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::messaging::capability::{
    FabricCapability as RuntimeFabricCapability, FabricCapabilityScope,
};
use asupersync::messaging::compiler::FabricCompiler;
use asupersync::messaging::fabric::{
    CellEpoch, CellTemperature, DataCapsule, Fabric, NodeRole, NormalizationPolicy,
    ObservedCellLoad, PlacementPolicy, RebalanceBudget, RebalancePlan, RepairPolicy,
    ReplySpaceCompactionPolicy, StewardCandidate, StorageClass, SubjectCell, SubjectPattern,
    SubjectPrefixMorphism,
};
use asupersync::messaging::ir::{
    CostVector, EvidencePolicy, FabricIr, MobilityPermission, PrivacyPolicy, ReplySpaceRule,
    SubjectFamily, SubjectSchema,
};
use asupersync::messaging::{
    DeliveryClass, FabricCapability as MorphismCapability, Morphism, MorphismClass, ResponsePolicy,
    ReversibilityRequirement, ShardedSublist, SharingPolicy, Subject, SubjectTransform,
};
use asupersync::remote::NodeId;
use asupersync::runtime::yield_now;
use asupersync::types::{Budget, RegionId, TaskId};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CellSnapshot {
    input_subject: String,
    canonical_partition: String,
    cell_id: u128,
    steward_set: Vec<String>,
    active_sequencer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RebalanceSnapshot {
    input_subject: String,
    next_temperature: CellTemperature,
    next_stewards: Vec<String>,
    added_stewards: Vec<String>,
    removed_stewards: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FabricLogEntry {
    seq: u64,
    lane: &'static str,
    action: &'static str,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct CapabilityScenarioSummary {
    child_publish_visible_before_revoke: bool,
    child_subscribe_visible_before_revoke: bool,
    removed_by_scope: usize,
    removed_by_subject: usize,
    final_grants: usize,
}

#[derive(Debug, Clone, PartialEq)]
struct CompilerScenarioSummary {
    subject_patterns: Vec<String>,
    aggregate_cost: CostVector,
    export_fingerprint: String,
    export_capabilities: Vec<MorphismCapability>,
    export_reply_space: Option<ReplySpaceRule>,
    import_fingerprint: String,
    import_reply_space: Option<ReplySpaceRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PacketPlaneScenarioSummary {
    wildcard_subjects: Vec<String>,
    exact_subjects: Vec<String>,
    cancelled_next_is_none: bool,
    reply_subject: String,
    reply_payload_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShardedRoutingSummary {
    first_four_queue_picks: Vec<u64>,
    after_drop_queue_pick: u64,
    created_total_before_drop: usize,
    updated_total_before_drop: usize,
    created_total_after_one_drop: usize,
    created_total_after_all_drops: usize,
    exact_shard: Option<usize>,
    wildcard_shard: Option<usize>,
    remaining_after_all_drops: usize,
}

fn candidate(
    name: &str,
    domain: &str,
    storage_class: StorageClass,
    latency_millis: u32,
) -> StewardCandidate {
    StewardCandidate::new(NodeId::new(name), domain)
        .with_role(NodeRole::Steward)
        .with_role(NodeRole::RepairWitness)
        .with_storage_class(storage_class)
        .with_latency_millis(latency_millis)
}

fn role_mixed_candidates() -> Vec<StewardCandidate> {
    vec![
        candidate("node-a", "rack-a", StorageClass::Durable, 5),
        candidate("node-b", "rack-b", StorageClass::Standard, 6),
        candidate("node-c", "rack-c", StorageClass::Standard, 7),
        StewardCandidate::new(NodeId::new("observer"), "rack-d").with_role(NodeRole::Subscriber),
        StewardCandidate::new(NodeId::new("bridge"), "rack-e").with_role(NodeRole::Bridge),
    ]
}

fn alias_policy() -> PlacementPolicy {
    PlacementPolicy {
        normalization: NormalizationPolicy {
            morphisms: vec![
                SubjectPrefixMorphism::new("svc.orders", "orders").expect("svc -> orders"),
            ],
            reply_space_policy: ReplySpaceCompactionPolicy {
                enabled: true,
                preserve_segments: 3,
            },
        },
        ..PlacementPolicy::default()
    }
}

fn hot_rebalance_policy() -> PlacementPolicy {
    PlacementPolicy {
        cold_stewards: 1,
        warm_stewards: 2,
        hot_stewards: 3,
        candidate_pool_size: 5,
        rebalance_budget: RebalanceBudget {
            max_steward_changes: 2,
        },
        normalization: NormalizationPolicy {
            morphisms: vec![
                SubjectPrefixMorphism::new("svc.orders", "orders").expect("svc -> orders"),
            ],
            reply_space_policy: ReplySpaceCompactionPolicy {
                enabled: true,
                preserve_segments: 3,
            },
        },
        ..PlacementPolicy::default()
    }
}

fn snapshot_cell(cell: SubjectCell, input_subject: &str) -> CellSnapshot {
    CellSnapshot {
        input_subject: input_subject.to_string(),
        canonical_partition: cell.subject_partition.canonical_key(),
        cell_id: cell.cell_id.raw(),
        steward_set: cell
            .steward_set
            .into_iter()
            .map(|node| node.as_str().to_string())
            .collect(),
        active_sequencer: cell
            .control_capsule
            .active_sequencer
            .map(|node| node.as_str().to_string()),
    }
}

fn snapshot_rebalance(plan: RebalancePlan, input_subject: &str) -> RebalanceSnapshot {
    RebalanceSnapshot {
        input_subject: input_subject.to_string(),
        next_temperature: plan.next_temperature,
        next_stewards: plan
            .next_stewards
            .into_iter()
            .map(|node| node.as_str().to_string())
            .collect(),
        added_stewards: plan
            .added_stewards
            .into_iter()
            .map(|node| node.as_str().to_string())
            .collect(),
        removed_stewards: plan
            .removed_stewards
            .into_iter()
            .map(|node| node.as_str().to_string())
            .collect(),
    }
}

fn test_fabric_cx(slot: u32) -> Cx {
    Cx::new(
        RegionId::new_for_test(slot, 0),
        TaskId::new_for_test(slot, 0),
        Budget::INFINITE,
    )
}

fn push_log(
    log: &Arc<Mutex<Vec<FabricLogEntry>>>,
    seq: &Arc<AtomicU64>,
    lane: &'static str,
    action: &'static str,
    detail: impl Into<String>,
) {
    log.lock().expect("log lock").push(FabricLogEntry {
        seq: seq.fetch_add(1, Ordering::SeqCst),
        lane,
        action,
        detail: detail.into(),
    });
}

fn sample_fabric_ir() -> FabricIr {
    FabricIr {
        subjects: vec![
            SubjectSchema {
                pattern: SubjectPattern::new("tenant.orders.command"),
                family: SubjectFamily::Command,
                delivery_class: DeliveryClass::ObligationBacked,
                evidence_policy: EvidencePolicy::default(),
                privacy_policy: PrivacyPolicy::default(),
                reply_space: Some(ReplySpaceRule::CallerInbox),
                mobility: MobilityPermission::Federated,
                quantitative_obligation: None,
            },
            SubjectSchema {
                pattern: SubjectPattern::new("tenant.orders.event"),
                family: SubjectFamily::Event,
                delivery_class: DeliveryClass::DurableOrdered,
                evidence_policy: EvidencePolicy::default(),
                privacy_policy: PrivacyPolicy::default(),
                reply_space: None,
                mobility: MobilityPermission::Federated,
                quantitative_obligation: None,
            },
        ],
        ..FabricIr::default()
    }
}

fn authoritative_morphism() -> Morphism {
    Morphism {
        source_language: SubjectPattern::new("tenant.orders"),
        dest_language: SubjectPattern::new("authority.orders"),
        class: MorphismClass::Authoritative,
        transform: SubjectTransform::RenamePrefix {
            from: SubjectPattern::new("tenant.orders"),
            to: SubjectPattern::new("authority.orders"),
        },
        reversibility: ReversibilityRequirement::EvidenceBacked,
        capability_requirements: vec![
            MorphismCapability::CarryAuthority,
            MorphismCapability::ReplyAuthority,
        ],
        sharing_policy: SharingPolicy::Federated,
        privacy_policy: PrivacyPolicy {
            allow_cross_tenant_flow: true,
            ..PrivacyPolicy::default()
        },
        response_policy: ResponsePolicy::ReplyAuthoritative,
        ..Morphism::default()
    }
}

fn delegation_morphism() -> Morphism {
    let mut morphism = Morphism {
        source_language: SubjectPattern::new("tenant.rpc"),
        dest_language: SubjectPattern::new("delegate.rpc"),
        class: MorphismClass::Delegation,
        capability_requirements: vec![MorphismCapability::DelegateNamespace],
        sharing_policy: SharingPolicy::TenantScoped,
        privacy_policy: PrivacyPolicy {
            allow_cross_tenant_flow: true,
            ..PrivacyPolicy::default()
        },
        response_policy: ResponsePolicy::ForwardOpaque,
        ..Morphism::default()
    };
    morphism.quota_policy.max_handoff_duration = Some(Duration::from_secs(30));
    morphism.quota_policy.revocation_required = true;
    morphism
}

fn run_capability_scenario(seed: u64) -> (CapabilityScenarioSummary, Vec<FabricLogEntry>, u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let parent = Arc::new(test_fabric_cx(100));
    let child = Arc::new(parent.restrict::<cap::None>());
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(CapabilityScenarioSummary::default()));

    {
        let parent = Arc::clone(&parent);
        let child = Arc::clone(&child);
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                let publish = parent
                    .grant_fabric_capability(RuntimeFabricCapability::Publish {
                        subject: SubjectPattern::new("orders.>"),
                    })
                    .expect("publish grant");
                push_log(
                    &log,
                    &seq,
                    "capability",
                    "grant_publish",
                    format!(
                        "grant_id={} active_grants={}",
                        publish.id().raw(),
                        parent.fabric_capabilities().len()
                    ),
                );

                yield_now().await;
                let subscribe = parent
                    .grant_fabric_capability(RuntimeFabricCapability::Subscribe {
                        subject: SubjectPattern::new("orders.created"),
                    })
                    .expect("subscribe grant");
                push_log(
                    &log,
                    &seq,
                    "capability",
                    "grant_subscribe",
                    format!(
                        "grant_id={} active_grants={}",
                        subscribe.id().raw(),
                        parent.fabric_capabilities().len()
                    ),
                );

                let publish_visible =
                    child.check_fabric_capability(&RuntimeFabricCapability::Publish {
                        subject: SubjectPattern::new("orders.created"),
                    });
                let subscribe_visible =
                    child.check_fabric_capability(&RuntimeFabricCapability::Subscribe {
                        subject: SubjectPattern::new("orders.created"),
                    });
                {
                    let mut guard = summary.lock().expect("summary lock");
                    guard.child_publish_visible_before_revoke = publish_visible;
                    guard.child_subscribe_visible_before_revoke = subscribe_visible;
                }
                push_log(
                    &log,
                    &seq,
                    "capability",
                    "check_child_visibility",
                    format!(
                        "publish_visible={publish_visible} subscribe_visible={subscribe_visible}"
                    ),
                );

                yield_now().await;
                let removed =
                    child.revoke_fabric_capability_scope(FabricCapabilityScope::Subscribe);
                summary.lock().expect("summary lock").removed_by_scope = removed;
                push_log(
                    &log,
                    &seq,
                    "capability",
                    "revoke_scope",
                    format!(
                        "removed={removed} remaining={}",
                        child.fabric_capabilities().len()
                    ),
                );

                yield_now().await;
                let removed = parent
                    .revoke_fabric_capability_by_subject(&SubjectPattern::new("orders.created"));
                summary.lock().expect("summary lock").removed_by_subject = removed;
                push_log(
                    &log,
                    &seq,
                    "capability",
                    "revoke_by_subject",
                    format!(
                        "removed={removed} remaining={}",
                        parent.fabric_capabilities().len()
                    ),
                );
            })
            .expect("create capability scenario task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    let pending_obligations = runtime.state.pending_obligation_count();
    assert!(
        runtime.is_quiescent(),
        "runtime should quiesce after capability scenario"
    );
    assert_eq!(
        pending_obligations, 0,
        "capability scenario should not leave pending obligations"
    );
    assert!(
        violations.is_empty(),
        "capability scenario should not violate lab invariants: {violations:?}"
    );

    let mut summary = summary.lock().expect("summary lock").clone();
    summary.final_grants = parent.fabric_capabilities().len();

    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    (summary, log_entries, runtime.steps())
}

fn run_compiler_scenario(seed: u64) -> (CompilerScenarioSummary, Vec<FabricLogEntry>, u64) {
    #[derive(Debug, Clone, Default)]
    struct CompilerState {
        subject_patterns: Vec<String>,
        aggregate_cost: Option<CostVector>,
        export_fingerprint: Option<String>,
        export_capabilities: Vec<MorphismCapability>,
        export_reply_space: Option<ReplySpaceRule>,
        import_fingerprint: Option<String>,
        import_reply_space: Option<ReplySpaceRule>,
    }

    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let state = Arc::new(Mutex::new(CompilerState::default()));

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let state = Arc::clone(&state);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                let report =
                    FabricCompiler::compile(&sample_fabric_ir()).expect("sample IR should compile");
                {
                    let mut guard = state.lock().expect("state lock");
                    guard.subject_patterns = report
                        .subject_costs
                        .iter()
                        .map(|subject| subject.pattern.clone())
                        .collect();
                    guard.aggregate_cost = Some(report.aggregate_cost);
                }
                push_log(
                    &log,
                    &seq,
                    "compiler",
                    "compile_ir",
                    format!(
                        "subjects={} schema={}",
                        report.subject_costs.len(),
                        report.schema_version
                    ),
                );
            })
            .expect("create compiler task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let state = Arc::clone(&state);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                yield_now().await;
                let plan = authoritative_morphism()
                    .compile_export_plan(None)
                    .expect("authoritative export plan should compile");
                {
                    let mut guard = state.lock().expect("state lock");
                    guard.export_fingerprint = Some(plan.certificate.fingerprint.clone());
                    guard.export_capabilities = plan.attached_capabilities.clone();
                    guard.export_reply_space = plan.selected_reply_space.clone();
                }
                push_log(
                    &log,
                    &seq,
                    "morphism",
                    "compile_export_plan",
                    format!(
                        "fingerprint={} reply_space={:?}",
                        plan.certificate.fingerprint, plan.selected_reply_space
                    ),
                );
            })
            .expect("create export plan task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let state = Arc::clone(&state);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                yield_now().await;
                yield_now().await;
                let plan = delegation_morphism()
                    .compile_import_plan(None)
                    .expect("delegation import plan should compile");
                {
                    let mut guard = state.lock().expect("state lock");
                    guard.import_fingerprint = Some(plan.certificate.fingerprint.clone());
                    guard.import_reply_space = plan.selected_reply_space.clone();
                }
                push_log(
                    &log,
                    &seq,
                    "morphism",
                    "compile_import_plan",
                    format!(
                        "fingerprint={} reply_space={:?}",
                        plan.certificate.fingerprint, plan.selected_reply_space
                    ),
                );
            })
            .expect("create import plan task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    let pending_obligations = runtime.state.pending_obligation_count();
    assert!(
        runtime.is_quiescent(),
        "runtime should quiesce after compiler scenario"
    );
    assert_eq!(
        pending_obligations, 0,
        "compiler scenario should not leave pending obligations"
    );
    assert!(
        violations.is_empty(),
        "compiler scenario should not violate lab invariants: {violations:?}"
    );

    let state = state.lock().expect("state lock").clone();
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);

    (
        CompilerScenarioSummary {
            subject_patterns: state.subject_patterns,
            aggregate_cost: state.aggregate_cost.expect("aggregate cost"),
            export_fingerprint: state.export_fingerprint.expect("export fingerprint"),
            export_capabilities: state.export_capabilities,
            export_reply_space: state.export_reply_space,
            import_fingerprint: state.import_fingerprint.expect("import fingerprint"),
            import_reply_space: state.import_reply_space,
        },
        log_entries,
        runtime.steps(),
    )
}

fn run_subject_cell_scenario(seed: u64, inputs: &[&str]) -> (Vec<CellSnapshot>, u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let results = Arc::new(Mutex::new(Vec::new()));
    let candidates = Arc::new(role_mixed_candidates());
    let policy = Arc::new(alias_policy());

    for input in inputs {
        let input = (*input).to_string();
        let results = Arc::clone(&results);
        let candidates = Arc::clone(&candidates);
        let policy = Arc::clone(&policy);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                let pattern = SubjectPattern::parse(&input).expect("valid subject pattern");
                yield_now().await;
                let cell = SubjectCell::new(
                    &pattern,
                    CellEpoch::new(41, 7),
                    &candidates,
                    &policy,
                    RepairPolicy::default(),
                    DataCapsule {
                        temperature: CellTemperature::Warm,
                        retained_message_blocks: 4,
                    },
                )
                .expect("cell should build");
                yield_now().await;
                results
                    .lock()
                    .expect("results lock")
                    .push(snapshot_cell(cell, &input));
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    let pending_obligations = runtime.state.pending_obligation_count();
    assert!(
        runtime.is_quiescent(),
        "runtime should quiesce after subject scenario"
    );
    assert_eq!(
        pending_obligations, 0,
        "subject scenario should not leave pending obligations"
    );
    assert!(
        violations.is_empty(),
        "subject scenario should not violate lab invariants: {violations:?}"
    );

    let mut snapshots = results.lock().expect("results lock").clone();
    snapshots.sort_unstable_by(|left, right| left.input_subject.cmp(&right.input_subject));
    (snapshots, runtime.steps())
}

fn run_rebalance_scenario(seed: u64, inputs: &[&str]) -> (Vec<RebalanceSnapshot>, u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let results = Arc::new(Mutex::new(Vec::new()));
    let candidates = Arc::new(role_mixed_candidates());
    let policy = Arc::new(hot_rebalance_policy());

    for input in inputs {
        let input = (*input).to_string();
        let results = Arc::clone(&results);
        let candidates = Arc::clone(&candidates);
        let policy = Arc::clone(&policy);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                let pattern = SubjectPattern::parse(&input).expect("valid subject pattern");
                let current = vec![NodeId::new("node-a")];
                yield_now().await;
                let plan = policy
                    .plan_rebalance(
                        &pattern,
                        &candidates,
                        &current,
                        CellTemperature::Cold,
                        ObservedCellLoad::new(2_048),
                    )
                    .expect("rebalance plan");
                yield_now().await;
                results
                    .lock()
                    .expect("results lock")
                    .push(snapshot_rebalance(plan, &input));
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    let pending_obligations = runtime.state.pending_obligation_count();
    assert!(
        runtime.is_quiescent(),
        "runtime should quiesce after rebalance scenario"
    );
    assert_eq!(
        pending_obligations, 0,
        "rebalance scenario should not leave pending obligations"
    );
    assert!(
        violations.is_empty(),
        "rebalance scenario should not violate lab invariants: {violations:?}"
    );

    let mut snapshots = results.lock().expect("results lock").clone();
    snapshots.sort_unstable_by(|left, right| left.input_subject.cmp(&right.input_subject));
    (snapshots, runtime.steps())
}

fn run_packet_plane_scenario(seed: u64) -> (PacketPlaneScenarioSummary, Vec<FabricLogEntry>, u64) {
    #[derive(Debug, Clone, Default)]
    struct PacketPlaneState {
        wildcard_subjects: Vec<String>,
        exact_subjects: Vec<String>,
        cancelled_next_is_none: bool,
        reply_subject: Option<String>,
        reply_payload_len: Option<usize>,
    }

    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let state = Arc::new(Mutex::new(PacketPlaneState::default()));

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let state = Arc::clone(&state);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = test_fabric_cx(700);
                let cancelled = test_fabric_cx(701);

                yield_now().await;
                let fabric = Fabric::connect(&cx, "lab://fabric").await.expect("connect");
                push_log(
                    &log,
                    &seq,
                    "packet",
                    "connect",
                    fabric.endpoint().to_string(),
                );

                let mut wildcard = fabric.subscribe(&cx, "orders.>").await.expect("wildcard");
                let mut exact = fabric
                    .subscribe(&cx, "orders.created")
                    .await
                    .expect("exact");
                push_log(
                    &log,
                    &seq,
                    "packet",
                    "subscribe",
                    "orders.> + orders.created",
                );

                yield_now().await;
                let _receipt = fabric
                    .publish(&cx, "orders.created", b"created".to_vec())
                    .await
                    .expect("publish created");
                push_log(&log, &seq, "packet", "publish", "orders.created");

                yield_now().await;
                let _receipt = fabric
                    .publish(&cx, "orders.updated", b"updated".to_vec())
                    .await
                    .expect("publish updated");
                push_log(&log, &seq, "packet", "publish", "orders.updated");

                let wildcard_created = wildcard.next(&cx).await.expect("wildcard created");
                let exact_created = exact.next(&cx).await.expect("exact created");
                let wildcard_updated = wildcard.next(&cx).await.expect("wildcard updated");

                cancelled.set_cancel_requested(true);
                let cancelled_next_is_none = wildcard.next(&cancelled).await.is_none();
                push_log(
                    &log,
                    &seq,
                    "packet",
                    "cancelled_next",
                    format!("none={cancelled_next_is_none}"),
                );

                let reply = fabric
                    .request(&cx, "service.lookup", b"lookup".to_vec())
                    .await
                    .expect("request");
                push_log(
                    &log,
                    &seq,
                    "packet",
                    "request",
                    format!("reply_subject={}", reply.subject.as_str()),
                );

                let mut guard = state.lock().expect("state lock");
                guard.wildcard_subjects = vec![
                    wildcard_created.subject.as_str().to_string(),
                    wildcard_updated.subject.as_str().to_string(),
                ];
                guard.exact_subjects = vec![exact_created.subject.as_str().to_string()];
                guard.cancelled_next_is_none = cancelled_next_is_none;
                guard.reply_subject = Some(reply.subject.as_str().to_string());
                guard.reply_payload_len = Some(reply.payload.len());
            })
            .expect("create packet-plane task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    let pending_obligations = runtime.state.pending_obligation_count();
    assert!(
        runtime.is_quiescent(),
        "runtime should quiesce after packet-plane scenario"
    );
    assert_eq!(
        pending_obligations, 0,
        "packet-plane scenario should not leave pending obligations"
    );
    assert!(
        violations.is_empty(),
        "packet-plane scenario should not violate lab invariants: {violations:?}"
    );

    let state = state.lock().expect("state lock").clone();
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);

    (
        PacketPlaneScenarioSummary {
            wildcard_subjects: state.wildcard_subjects,
            exact_subjects: state.exact_subjects,
            cancelled_next_is_none: state.cancelled_next_is_none,
            reply_subject: state.reply_subject.expect("reply subject"),
            reply_payload_len: state.reply_payload_len.expect("reply payload len"),
        },
        log_entries,
        runtime.steps(),
    )
}

fn run_sharded_routing_scenario(seed: u64) -> (ShardedRoutingSummary, Vec<FabricLogEntry>, u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<ShardedRoutingSummary>));

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let index = ShardedSublist::with_prefix_depth(8, 2);
                let exact_pattern = SubjectPattern::new("orders.created");
                let wildcard_pattern = SubjectPattern::new("orders.>");
                let created = Subject::new("orders.created");
                let updated = Subject::new("orders.updated");

                yield_now().await;
                let queue_a = index.subscribe(&exact_pattern, Some("workers".to_string()));
                let queue_b = index.subscribe(&exact_pattern, Some("workers".to_string()));
                let plain_exact = index.subscribe(&exact_pattern, None);
                let wildcard = index.subscribe(&wildcard_pattern, None);
                let exact_shard = queue_a.shard_index();
                let wildcard_shard = wildcard.shard_index();

                push_log(
                    &log,
                    &seq,
                    "routing",
                    "subscribe",
                    format!(
                        "exact_shard={:?} wildcard_shard={:?}",
                        exact_shard, wildcard_shard
                    ),
                );

                let mut first_four_queue_picks = Vec::new();
                let created_total_before_drop = {
                    let first = index.lookup(&created);
                    let first_pick = first.queue_group_picks[0].1.raw();
                    first_four_queue_picks.push(first_pick);
                    first.total()
                };

                for _ in 0..3 {
                    yield_now().await;
                    let result = index.lookup(&created);
                    first_four_queue_picks.push(result.queue_group_picks[0].1.raw());
                }

                let updated_total_before_drop = index.lookup(&updated).total();
                push_log(
                    &log,
                    &seq,
                    "routing",
                    "lookup_before_drop",
                    format!(
                        "created_total={created_total_before_drop} updated_total={updated_total_before_drop}"
                    ),
                );

                let remaining_queue_id = queue_b.id().raw();
                drop(queue_a);
                yield_now().await;
                let after_one_drop = index.lookup(&created);
                let created_total_after_one_drop = after_one_drop.total();
                let after_drop_queue_pick = after_one_drop.queue_group_picks[0].1.raw();
                push_log(
                    &log,
                    &seq,
                    "routing",
                    "lookup_after_one_drop",
                    format!(
                        "created_total={created_total_after_one_drop} queue_pick={after_drop_queue_pick}"
                    ),
                );

                drop(queue_b);
                drop(plain_exact);
                drop(wildcard);
                yield_now().await;
                let created_total_after_all_drops = index.lookup(&created).total();
                let remaining_after_all_drops = index.count();
                push_log(
                    &log,
                    &seq,
                    "routing",
                    "lookup_after_all_drops",
                    format!(
                        "created_total={created_total_after_all_drops} remaining={remaining_after_all_drops}"
                    ),
                );

                *summary.lock().expect("summary lock") = Some(ShardedRoutingSummary {
                    first_four_queue_picks,
                    after_drop_queue_pick,
                    created_total_before_drop,
                    updated_total_before_drop,
                    created_total_after_one_drop,
                    created_total_after_all_drops,
                    exact_shard,
                    wildcard_shard,
                    remaining_after_all_drops,
                });

                assert_eq!(
                    after_drop_queue_pick, remaining_queue_id,
                    "after one drop only the remaining queue member should receive picks"
                );
            })
            .expect("create sharded routing task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    let pending_obligations = runtime.state.pending_obligation_count();
    assert!(
        runtime.is_quiescent(),
        "runtime should quiesce after sharded routing scenario"
    );
    assert_eq!(
        pending_obligations, 0,
        "sharded routing scenario should not leave pending obligations"
    );
    assert!(
        violations.is_empty(),
        "sharded routing scenario should not violate lab invariants: {violations:?}"
    );

    let summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("scenario summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    (summary, log_entries, runtime.steps())
}

#[test]
fn subject_cell_replay_is_deterministic_across_seeded_lab_runs() {
    let inputs = [
        "orders.created",
        "svc.orders.created",
        "orders.updated",
        "svc.orders.updated",
        "_INBOX.orders.region.instance.123",
    ];

    let (first, first_steps) = run_subject_cell_scenario(0x5EED_FAB1, &inputs);
    let (second, second_steps) = run_subject_cell_scenario(0x5EED_FAB1, &inputs);

    assert_eq!(
        first, second,
        "same seed should yield identical cell snapshots"
    );
    assert_eq!(
        first_steps, second_steps,
        "same seed should yield identical scheduler step counts"
    );
}

#[test]
fn concurrent_alias_subjects_converge_to_one_canonical_cell() {
    let inputs = [
        "orders.created",
        "svc.orders.created",
        "svc.orders.created",
        "orders.created",
    ];

    let (snapshots, _) = run_subject_cell_scenario(0xA11A_5EED, &inputs);
    let canonical = snapshots
        .iter()
        .map(|snapshot| (snapshot.canonical_partition.clone(), snapshot.cell_id))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        canonical.len(),
        1,
        "all aliases should collapse to the same cell"
    );
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.active_sequencer == snapshot.steward_set.first().cloned()),
        "active sequencer should stay aligned with the first steward"
    );
}

#[test]
fn reply_space_subjects_compact_to_a_shared_cell_under_lab_runtime() {
    let inputs = [
        "_INBOX.orders.region.instance.123",
        "_INBOX.orders.region.instance.456",
        "_INBOX.orders.region.instance.789",
    ];

    let (snapshots, _) = run_subject_cell_scenario(0xA11A_5E12, &inputs);
    let canonical_partitions = snapshots
        .iter()
        .map(|snapshot| snapshot.canonical_partition.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let cell_ids = snapshots
        .iter()
        .map(|snapshot| snapshot.cell_id)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        canonical_partitions,
        std::collections::BTreeSet::from(["_INBOX.orders.region.>".to_string()]),
        "reply-space subjects should compact before placement"
    );
    assert_eq!(
        cell_ids.len(),
        1,
        "compacted reply-space subjects should share one cell"
    );
}

#[test]
fn concurrent_placement_filters_non_steward_roles() {
    let inputs = ["orders.created", "orders.updated", "orders.deleted"];
    let (snapshots, _) = run_subject_cell_scenario(0xCA11_AB1E, &inputs);

    for snapshot in snapshots {
        assert!(
            snapshot
                .steward_set
                .iter()
                .all(|node| node != "observer" && node != "bridge"),
            "non-steward roles must never appear in steward placement"
        );
    }
}

#[test]
fn rebalance_planning_stays_deterministic_for_alias_inputs() {
    let inputs = [
        "orders.created",
        "svc.orders.created",
        "orders.updated",
        "svc.orders.updated",
    ];

    let (first, first_steps) = run_rebalance_scenario(0xB16B_00B5, &inputs);
    let (second, second_steps) = run_rebalance_scenario(0xB16B_00B5, &inputs);

    assert_eq!(
        first, second,
        "same seed should yield identical rebalance plans"
    );
    assert_eq!(
        first_steps, second_steps,
        "same seed should yield identical rebalance scheduler steps"
    );
    assert!(
        first
            .iter()
            .all(|snapshot| snapshot.next_temperature == CellTemperature::Hot),
        "hot observed load should drive the cell into the hot tier"
    );
}

#[test]
fn rebalance_aliases_choose_the_same_hot_steward_set() {
    let inputs = ["orders.created", "svc.orders.created"];
    let (snapshots, _) = run_rebalance_scenario(0x600D_F11E, &inputs);

    assert_eq!(
        snapshots.len(),
        2,
        "expected both alias inputs to produce a plan"
    );
    assert_eq!(
        snapshots[0].next_stewards, snapshots[1].next_stewards,
        "alias subjects should rebalance to the same steward set after normalization"
    );
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.added_stewards.len() <= 2),
        "rebalance budget should bound steward churn per planning step"
    );
}

#[test]
fn fabric_capability_mutations_are_deterministic_across_seeded_lab_runs() {
    let (first_summary, first_log, first_steps) = run_capability_scenario(0xFACE_CAFE);
    let (second_summary, second_log, second_steps) = run_capability_scenario(0xFACE_CAFE);

    assert_eq!(
        first_summary, second_summary,
        "same seed should yield identical capability summaries"
    );
    assert_eq!(
        first_log, second_log,
        "same seed should yield identical capability logs"
    );
    assert_eq!(
        first_steps, second_steps,
        "same seed should yield identical capability scheduler steps"
    );
}

#[test]
fn fabric_capability_mutations_propagate_and_drain_cleanly() {
    let (summary, log, _) = run_capability_scenario(0xC0DE_CAFE);

    assert!(
        summary.child_publish_visible_before_revoke,
        "child view should observe inherited publish capability before revocation"
    );
    assert!(
        summary.child_subscribe_visible_before_revoke,
        "child view should observe inherited subscribe capability before revocation"
    );
    assert_eq!(
        summary.removed_by_scope, 1,
        "scope revoke should remove the subscribe grant"
    );
    assert_eq!(
        summary.removed_by_subject, 1,
        "subject revoke should remove the remaining publish grant"
    );
    assert_eq!(
        summary.final_grants, 0,
        "all shared grants should be drained by the end of the scenario"
    );
    assert_eq!(
        log.len(),
        5,
        "expected one structured log entry per operation"
    );
    assert!(
        log.windows(2).all(|window| window[0].seq < window[1].seq),
        "structured capability logs should preserve a strict monotone sequence"
    );
}

#[test]
fn fabric_compiler_and_morphism_plans_are_deterministic_across_seeded_lab_runs() {
    let (first_summary, first_log, first_steps) = run_compiler_scenario(0xC011_AB1E);
    let (second_summary, second_log, second_steps) = run_compiler_scenario(0xC011_AB1E);

    assert_eq!(
        first_summary, second_summary,
        "same seed should yield identical compiler and morphism summaries"
    );
    assert_eq!(
        first_log, second_log,
        "same seed should yield identical compiler and morphism logs"
    );
    assert_eq!(
        first_steps, second_steps,
        "same seed should yield identical compiler scheduler steps"
    );
}

#[test]
fn fabric_compiler_and_morphism_plans_match_expected_surfaces() {
    let (summary, log, _) = run_compiler_scenario(0xA11C_0DE5);

    assert_eq!(
        summary.subject_patterns,
        vec![
            "tenant.orders.command".to_string(),
            "tenant.orders.event".to_string()
        ],
        "compiler should preserve declaration order for deterministic reporting"
    );
    assert_eq!(
        summary.export_capabilities,
        vec![
            MorphismCapability::CarryAuthority,
            MorphismCapability::ReplyAuthority
        ],
        "authoritative export plans should carry the authority-bearing capability set"
    );
    assert_eq!(
        summary.export_reply_space,
        Some(ReplySpaceRule::DedicatedPrefix {
            prefix: "authority.orders".to_string(),
        }),
        "authoritative export plans should default to a dedicated authority reply prefix"
    );
    assert_eq!(
        summary.import_reply_space,
        Some(ReplySpaceRule::CallerInbox),
        "delegation import plans should preserve caller inbox replies by default"
    );
    assert!(!summary.export_fingerprint.is_empty());
    assert!(!summary.import_fingerprint.is_empty());
    assert_eq!(
        log.len(),
        3,
        "expected one structured log entry per compile lane"
    );
}

#[test]
fn fabric_public_publish_subscribe_is_deterministic_across_seeded_lab_runs() {
    let (first_summary, first_log, first_steps) = run_packet_plane_scenario(0xFA61_1C01);
    let (second_summary, second_log, second_steps) = run_packet_plane_scenario(0xFA61_1C01);

    assert_eq!(
        first_summary, second_summary,
        "same seed should yield identical packet-plane summaries"
    );
    assert_eq!(
        first_log, second_log,
        "same seed should yield identical packet-plane logs"
    );
    assert_eq!(
        first_steps, second_steps,
        "same seed should yield identical packet-plane scheduler steps"
    );
}

#[test]
fn fabric_public_subscription_respects_routing_and_cancellation() {
    let (summary, log, _) = run_packet_plane_scenario(0xFA61_1C02);

    assert_eq!(
        summary.wildcard_subjects,
        vec!["orders.created".to_string(), "orders.updated".to_string()],
        "wildcard subscriber should observe both matching subjects in publish order"
    );
    assert_eq!(
        summary.exact_subjects,
        vec!["orders.created".to_string()],
        "exact subscriber should only observe the exact subject"
    );
    assert!(
        summary.cancelled_next_is_none,
        "cancelled contexts should short-circuit subscription polling"
    );
    assert_eq!(summary.reply_subject, "service.lookup");
    assert_eq!(summary.reply_payload_len, 6);
    assert_eq!(
        log.len(),
        6,
        "expected one structured log entry per packet-plane phase"
    );
}

#[test]
fn sharded_routing_is_deterministic_across_seeded_lab_runs() {
    let (first_summary, first_log, first_steps) = run_sharded_routing_scenario(0x5A4D_0001);
    let (second_summary, second_log, second_steps) = run_sharded_routing_scenario(0x5A4D_0001);

    assert_eq!(
        first_summary, second_summary,
        "same seed should yield identical sharded-routing summaries"
    );
    assert_eq!(
        first_log, second_log,
        "same seed should yield identical sharded-routing logs"
    );
    assert_eq!(
        first_steps, second_steps,
        "same seed should yield identical sharded-routing scheduler steps"
    );
}

#[test]
fn sharded_queue_group_selection_rotates_fairly_under_lab_runtime() {
    let (summary, _, _) = run_sharded_routing_scenario(0x5A4D_0002);

    assert_eq!(
        summary.first_four_queue_picks.len(),
        4,
        "expected four queue-group selections before drops"
    );
    assert_ne!(
        summary.first_four_queue_picks[0], summary.first_four_queue_picks[1],
        "queue-group picks should rotate between members"
    );
    assert_eq!(
        summary.first_four_queue_picks[0], summary.first_four_queue_picks[2],
        "round-robin should cycle back to the first queue member"
    );
    assert_eq!(
        summary.first_four_queue_picks[1], summary.first_four_queue_picks[3],
        "round-robin should cycle back to the second queue member"
    );
}

#[test]
fn sharded_fallback_and_concrete_routes_compose_under_lab_runtime() {
    let (summary, _, _) = run_sharded_routing_scenario(0x5A4D_0003);

    assert!(
        summary.exact_shard.is_some(),
        "fully literal patterns should route to a concrete shard"
    );
    assert_eq!(
        summary.wildcard_shard, None,
        "broad wildcard patterns should live in the fallback shard"
    );
    assert_eq!(
        summary.created_total_before_drop, 3,
        "created lookups should include concrete plain interest, fallback interest, and one queue pick"
    );
    assert_eq!(
        summary.updated_total_before_drop, 1,
        "updated lookups should still hit the fallback wildcard interest"
    );
    assert_eq!(
        summary.created_total_after_one_drop, 3,
        "dropping one queue member should preserve the remaining queue pick plus plain and fallback interest"
    );
}

#[test]
fn sharded_routing_drains_cancelled_interest_without_ghosts() {
    let (summary, _, _) = run_sharded_routing_scenario(0x5A4D_0004);

    assert_eq!(
        summary.created_total_after_all_drops, 0,
        "after all guards drop there should be no remaining interest"
    );
    assert_eq!(
        summary.remaining_after_all_drops, 0,
        "sharded sublist count should drain to zero after all guards drop"
    );
}
