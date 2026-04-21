#![allow(warnings)]
#![allow(clippy::all)]
//! Replayable distributed FABRIC scenarios exercised under LabRuntime and DPOR.
#![cfg(feature = "messaging-fabric")]

use asupersync::cx::{Cx, cap};
use asupersync::distributed::RegionBridge;
use asupersync::lab::explorer::{DporExplorer, ExplorerConfig};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::messaging::capability::{
    FabricCapability as RuntimeFabricCapability, FabricCapabilityScope,
};
use asupersync::messaging::consumer::{
    AckResolution, AttemptCertificate, FabricConsumer, FabricConsumerConfig, FabricConsumerOwner,
    RecoverableCapsule, SequenceWindow,
};
use asupersync::messaging::control::{ControlBudget, SystemSubjectFamily};
use asupersync::messaging::fabric::{
    CellEpoch, CellTemperature, DataCapsule, NodeRole, PlacementPolicy, RepairPolicy,
    StewardCandidate, StorageClass, SubjectCell, SubjectPattern,
};
use asupersync::messaging::federation::{
    FederationBridge, FederationDirection, FederationRole, GatewayConfig, LeafConfig,
    ReplicationCatchUpAction, ReplicationConfig,
};
use asupersync::messaging::stream::{CapturePolicy, InMemoryStorageBackend, Stream, StreamConfig};
use asupersync::messaging::{
    DeliveryClass, FabricCapability as MorphismCapability, Morphism, MorphismClass, ResponsePolicy,
    ReversibilityRequirement, ShardedSublist, SharingPolicy, Subject, SubjectTransform,
};
use asupersync::remote::NodeId;
use asupersync::runtime::yield_now;
use asupersync::types::{Budget, RegionId, TaskId, Time};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeafPartitionSummary {
    immediate_forwarded: bool,
    drained_routes: usize,
    dropped_routes: u64,
    drained_subjects: Vec<String>,
    ghost_interest_after_drop: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapabilityRevocationSummary {
    export_fingerprint: String,
    import_fingerprint: String,
    child_publish_visible_before_revoke: bool,
    child_subscribe_visible_before_revoke: bool,
    removed_by_scope: usize,
    removed_by_subject: usize,
    final_grants: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AckRaceSummary {
    committed_acks: usize,
    stale_acks: usize,
    pending_after: u64,
    ack_floor_after: u64,
    total_acquired: u64,
    total_committed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplicationReorderSummary {
    catch_up_action: ReplicationCatchUpAction,
    snapshot_sequence: u64,
    target_task_count: usize,
    not_quiescent_before_drain: bool,
    closed_after_drain: bool,
    mirror_remaining: usize,
    source_remaining: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdvisoryStormSummary {
    propagated_interest_count: usize,
    forwarded_advisory_count: usize,
    timed_out: bool,
    no_ghost_interest: bool,
}

#[derive(Debug, Clone, Default)]
struct RevocationState {
    export_fingerprint: Option<String>,
    import_fingerprint: Option<String>,
}

fn test_fabric_cx(slot: u32) -> Cx {
    Cx::new(
        RegionId::new_for_test(slot, 0),
        TaskId::new_for_test(slot, 0),
        Budget::INFINITE,
    )
}

fn candidate(name: &str, domain: &str) -> StewardCandidate {
    StewardCandidate::new(NodeId::new(name), domain)
        .with_role(NodeRole::Steward)
        .with_role(NodeRole::RepairWitness)
        .with_storage_class(StorageClass::Durable)
}

fn test_cell() -> SubjectCell {
    SubjectCell::new(
        &SubjectPattern::parse("orders.created").expect("pattern"),
        CellEpoch::new(7, 11),
        &[
            candidate("node-a", "rack-a"),
            candidate("node-b", "rack-b"),
            candidate("node-c", "rack-c"),
        ],
        &PlacementPolicy {
            cold_stewards: 3,
            warm_stewards: 3,
            hot_stewards: 3,
            ..PlacementPolicy::default()
        },
        RepairPolicy::default(),
        DataCapsule {
            temperature: CellTemperature::Warm,
            retained_message_blocks: 4,
        },
    )
    .expect("cell")
}

fn derived_view_morphism() -> Morphism {
    Morphism::default()
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
        response_policy: ResponsePolicy::ForwardOpaque,
        ..Morphism::default()
    };
    morphism.quota_policy.max_handoff_duration = Some(Duration::from_secs(30));
    morphism.quota_policy.revocation_required = true;
    morphism
}

fn assert_runtime_clean(runtime: &mut LabRuntime, label: &str) {
    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    let pending = runtime.state.pending_obligation_count();
    assert!(runtime.is_quiescent(), "{label} should quiesce");
    assert_eq!(pending, 0, "{label} should not leak obligations");
    assert!(
        violations.is_empty(),
        "{label} should not violate lab invariants: {violations:?}"
    );
}

fn assert_dpor_clean(label: &str, seed: u64, max_runs: usize, build: fn(&mut LabRuntime)) {
    let mut explorer = DporExplorer::new(
        ExplorerConfig::new(seed, max_runs)
            .worker_count(1)
            .max_steps(10_000),
    );
    let report = explorer.explore(|runtime| {
        build(runtime);
        runtime.run_until_quiescent();
        assert!(runtime.is_quiescent(), "{label} should quiesce under DPOR");
        assert_eq!(
            runtime.state.pending_obligation_count(),
            0,
            "{label} should not leak obligations under DPOR"
        );
    });

    assert!(
        !report.has_violations(),
        "{label} should remain invariant-clean across explored schedules: {:?}",
        report.violation_seeds()
    );
    assert!(
        report.unique_classes >= 1,
        "{label} should produce at least one explored equivalence class"
    );
}

#[allow(clippy::too_many_lines)]
fn schedule_leaf_partition(
    runtime: &mut LabRuntime,
    summary: &Arc<Mutex<Option<LeafPartitionSummary>>>,
) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let bridge = Arc::new(Mutex::new(
        FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig {
                offline_buffer_limit: 2,
                ..LeafConfig::default()
            }),
            vec![derived_view_morphism()],
            Vec::new(),
            [MorphismCapability::RewriteNamespace],
        )
        .expect("leaf bridge"),
    ));
    let partitioned = Arc::new(AtomicBool::new(false));
    let routed = Arc::new(AtomicUsize::new(0));

    {
        let bridge = Arc::clone(&bridge);
        let partitioned = Arc::clone(&partitioned);
        let routed = Arc::clone(&routed);
        let summary = Arc::clone(summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let index = ShardedSublist::with_prefix_depth(8, 2);
                let guard = index.subscribe(&SubjectPattern::new("tenant.orders.>"), None);
                assert_eq!(
                    index.lookup(&Subject::new("tenant.orders.created")).total(),
                    1
                );

                let immediate_forwarded = {
                    let mut bridge = bridge.lock().expect("bridge lock");
                    bridge.activate().expect("activate");
                    let immediate = bridge
                        .queue_leaf_route(
                            FederationDirection::LocalToRemote,
                            SubjectPattern::new("tenant.orders.alpha"),
                            1,
                        )
                        .expect("forward initial route");
                    bridge.mark_degraded().expect("degrade");
                    let forwarded = matches!(
                        immediate,
                        asupersync::messaging::federation::LeafRouteDisposition::Forwarded { .. }
                    );
                    drop(bridge);
                    forwarded
                };
                partitioned.store(true, Ordering::SeqCst);

                drop(guard);
                let ghost_interest_after_drop =
                    index.lookup(&Subject::new("tenant.orders.created")).total();

                for _ in 0..16 {
                    if routed.load(Ordering::SeqCst) == 3 {
                        break;
                    }
                    yield_now().await;
                }
                assert_eq!(
                    routed.load(Ordering::SeqCst),
                    3,
                    "all degraded routes should queue"
                );

                let mut bridge = bridge.lock().expect("bridge lock");
                bridge.activate().expect("re-activate");
                let drain = bridge.drain_leaf_buffer().expect("drain leaf buffer");
                let mut drained_subjects = drain
                    .routes
                    .iter()
                    .map(|route| route.subject.canonical_key())
                    .collect::<Vec<_>>();
                drained_subjects.sort_unstable();
                drop(bridge);
                *summary.lock().expect("summary lock") = Some(LeafPartitionSummary {
                    immediate_forwarded,
                    drained_routes: drain.routes.len(),
                    dropped_routes: drain.dropped_entries,
                    drained_subjects,
                    ghost_interest_after_drop,
                });
            })
            .expect("create controller");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    for subject in [
        "tenant.orders.beta",
        "tenant.orders.gamma",
        "tenant.orders.delta",
    ] {
        let bridge = Arc::clone(&bridge);
        let partitioned = Arc::clone(&partitioned);
        let routed = Arc::clone(&routed);
        let subject = subject.to_string();
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                for _ in 0..8 {
                    if partitioned.load(Ordering::SeqCst) {
                        break;
                    }
                    yield_now().await;
                }
                assert!(
                    partitioned.load(Ordering::SeqCst),
                    "partition should be active"
                );

                bridge
                    .lock()
                    .expect("bridge lock")
                    .queue_leaf_route(
                        FederationDirection::LocalToRemote,
                        SubjectPattern::new(&subject),
                        1,
                    )
                    .expect("buffer degraded route");
                routed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create route task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }
}

fn run_leaf_partition(seed: u64) -> LeafPartitionSummary {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let summary = Arc::new(Mutex::new(None));
    schedule_leaf_partition(&mut runtime, &summary);
    assert_runtime_clean(&mut runtime, "leaf partition replay");
    summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("leaf partition summary")
}

fn build_leaf_partition(runtime: &mut LabRuntime) {
    let summary = Arc::new(Mutex::new(None));
    schedule_leaf_partition(runtime, &summary);
}

fn schedule_capability_revocation(
    runtime: &mut LabRuntime,
    summary: &Arc<Mutex<Option<CapabilityRevocationSummary>>>,
) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let parent = Arc::new(test_fabric_cx(410));
    let child = Arc::new(parent.restrict::<cap::None>());
    let state = Arc::new(Mutex::new(RevocationState::default()));

    {
        let parent = Arc::clone(&parent);
        let state = Arc::clone(&state);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                let plan = authoritative_morphism()
                    .compile_export_plan(None)
                    .expect("compile export plan");
                parent
                    .grant_fabric_capability(RuntimeFabricCapability::Publish {
                        subject: SubjectPattern::new("orders.created"),
                    })
                    .expect("grant publish");
                state.lock().expect("state lock").export_fingerprint =
                    Some(plan.certificate.fingerprint);
            })
            .expect("create export task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    {
        let parent = Arc::clone(&parent);
        let state = Arc::clone(&state);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                yield_now().await;
                yield_now().await;
                let plan = delegation_morphism()
                    .compile_import_plan(None)
                    .expect("compile import plan");
                parent
                    .grant_fabric_capability(RuntimeFabricCapability::Subscribe {
                        subject: SubjectPattern::new("delegate.rpc"),
                    })
                    .expect("grant subscribe");
                state.lock().expect("state lock").import_fingerprint =
                    Some(plan.certificate.fingerprint);
            })
            .expect("create import task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    {
        let parent = Arc::clone(&parent);
        let child = Arc::clone(&child);
        let state = Arc::clone(&state);
        let summary = Arc::clone(summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let mut ready = false;
                for _ in 0..16 {
                    let have_fingerprints = {
                        let guard = state.lock().expect("state lock");
                        guard.export_fingerprint.is_some() && guard.import_fingerprint.is_some()
                    };
                    if have_fingerprints && parent.fabric_capabilities().len() >= 2 {
                        ready = true;
                        break;
                    }
                    yield_now().await;
                }
                assert!(
                    ready,
                    "import/export plans should be ready before revocation"
                );

                let child_publish_visible_before_revoke =
                    child.check_fabric_capability(&RuntimeFabricCapability::Publish {
                        subject: SubjectPattern::new("orders.created"),
                    });
                let child_subscribe_visible_before_revoke =
                    child.check_fabric_capability(&RuntimeFabricCapability::Subscribe {
                        subject: SubjectPattern::new("delegate.rpc"),
                    });
                let removed_by_scope =
                    child.revoke_fabric_capability_scope(FabricCapabilityScope::Subscribe);
                let removed_by_subject = parent
                    .revoke_fabric_capability_by_subject(&SubjectPattern::new("orders.created"));
                let state = state.lock().expect("state lock").clone();

                *summary.lock().expect("summary lock") = Some(CapabilityRevocationSummary {
                    export_fingerprint: state.export_fingerprint.expect("export fingerprint"),
                    import_fingerprint: state.import_fingerprint.expect("import fingerprint"),
                    child_publish_visible_before_revoke,
                    child_subscribe_visible_before_revoke,
                    removed_by_scope,
                    removed_by_subject,
                    final_grants: parent.fabric_capabilities().len(),
                });
            })
            .expect("create revocation task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }
}

fn run_capability_revocation(seed: u64) -> CapabilityRevocationSummary {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let summary = Arc::new(Mutex::new(None));
    schedule_capability_revocation(&mut runtime, &summary);
    assert_runtime_clean(&mut runtime, "capability revocation replay");
    summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("capability revocation summary")
}

fn build_capability_revocation(runtime: &mut LabRuntime) {
    let summary = Arc::new(Mutex::new(None));
    schedule_capability_revocation(runtime, &summary);
}

fn schedule_ack_race(runtime: &mut LabRuntime, summary: &Arc<Mutex<Option<AckRaceSummary>>>) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let owner = FabricConsumerOwner {
        holder: TaskId::new_for_test(41, 0),
        region: RegionId::new_for_test(7, 0),
    };
    let consumer = Arc::new(Mutex::new(
        FabricConsumer::new_owned(&test_cell(), FabricConsumerConfig::default(), owner)
            .expect("consumer"),
    ));
    let attempt = Arc::new(Mutex::new(None::<AttemptCertificate>));
    let acked = Arc::new(AtomicUsize::new(0));
    let counts = Arc::new(Mutex::new((0usize, 0usize)));

    {
        let consumer = Arc::clone(&consumer);
        let attempt = Arc::clone(&attempt);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let window = SequenceWindow::new(5, 6).expect("window");
                let capsule =
                    RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);
                let delivery = consumer
                    .lock()
                    .expect("consumer lock")
                    .dispatch_push(window, &capsule, None)
                    .expect("dispatch push");
                *attempt.lock().expect("attempt lock") = Some(delivery.attempt);
            })
            .expect("create dispatch task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    for slot in 0..2 {
        let consumer = Arc::clone(&consumer);
        let attempt = Arc::clone(&attempt);
        let acked = Arc::clone(&acked);
        let counts = Arc::clone(&counts);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let attempt = loop {
                    let ready_attempt = attempt.lock().expect("attempt lock").clone();
                    if let Some(attempt) = ready_attempt {
                        break attempt;
                    }
                    yield_now().await;
                };

                if slot == 1 {
                    yield_now().await;
                }

                let resolution = consumer
                    .lock()
                    .expect("consumer lock")
                    .acknowledge_delivery(&attempt)
                    .expect("ack delivery");
                let mut counts = counts.lock().expect("counts lock");
                match resolution {
                    AckResolution::Committed { .. } => counts.0 += 1,
                    AckResolution::StaleNoOp { .. } => counts.1 += 1,
                }
                drop(counts);
                acked.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create ack task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    {
        let consumer = Arc::clone(&consumer);
        let acked = Arc::clone(&acked);
        let counts = Arc::clone(&counts);
        let summary = Arc::clone(summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                for _ in 0..16 {
                    if acked.load(Ordering::SeqCst) == 2 {
                        break;
                    }
                    yield_now().await;
                }
                assert_eq!(
                    acked.load(Ordering::SeqCst),
                    2,
                    "both ack racers should finish"
                );

                let consumer = consumer.lock().expect("consumer lock");
                let (committed_acks, stale_acks) = *counts.lock().expect("counts lock");
                *summary.lock().expect("summary lock") = Some(AckRaceSummary {
                    committed_acks,
                    stale_acks,
                    pending_after: consumer.state().pending_count,
                    ack_floor_after: consumer.state().ack_floor,
                    total_acquired: consumer.obligation_stats().total_acquired,
                    total_committed: consumer.obligation_stats().total_committed,
                });
            })
            .expect("create collector");
        runtime.scheduler.lock().schedule(task_id, 0);
    }
}

fn run_ack_race(seed: u64) -> AckRaceSummary {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let summary = Arc::new(Mutex::new(None));
    schedule_ack_race(&mut runtime, &summary);
    assert_runtime_clean(&mut runtime, "ack race replay");
    summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("ack race summary")
}

fn build_ack_race(runtime: &mut LabRuntime) {
    let summary = Arc::new(Mutex::new(None));
    schedule_ack_race(runtime, &summary);
}

#[allow(clippy::too_many_lines)]
fn schedule_replication_reorder(
    runtime: &mut LabRuntime,
    summary: &Arc<Mutex<Option<ReplicationReorderSummary>>>,
) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let stream = Arc::new(Mutex::new(
        Stream::new(
            "orders-mirror",
            RegionId::new_for_test(60, 0),
            Time::ZERO,
            StreamConfig {
                subject_filter: SubjectPattern::new("orders.>"),
                capture_policy: CapturePolicy::IncludeReplySubjects,
                delivery_class: DeliveryClass::DurableOrdered,
                ..StreamConfig::default()
            },
            InMemoryStorageBackend::default(),
        )
        .expect("stream"),
    ));
    {
        let mut stream = stream.lock().expect("stream lock");
        stream
            .append(
                Subject::new("orders.created"),
                b"snapshot".to_vec(),
                Time::ZERO,
            )
            .expect("append record");
        stream
            .add_mirror_region(RegionId::new_for_test(61, 0))
            .expect("mirror region");
        stream
            .add_source_region(RegionId::new_for_test(62, 0))
            .expect("source region");
    }

    let ready = Arc::new(AtomicBool::new(false));
    let removed = Arc::new(AtomicUsize::new(0));

    {
        let stream = Arc::clone(&stream);
        let ready = Arc::clone(&ready);
        let removed = Arc::clone(&removed);
        let summary = Arc::clone(summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let mut federation = FederationBridge::new(
                    FederationRole::ReplicationLink(ReplicationConfig::default()),
                    vec![derived_view_morphism()],
                    Vec::new(),
                    [MorphismCapability::RewriteNamespace],
                )
                .expect("replication bridge");

                let mut source =
                    RegionBridge::new_local(RegionId::new_for_test(70, 0), None, Budget::new());
                source
                    .add_task(TaskId::new_for_test(71, 0))
                    .expect("source task");
                let transfer = federation
                    .export_replication_transfer(&mut source, Time::from_secs(1))
                    .expect("export transfer");
                let catch_up = federation
                    .plan_replication_catch_up(transfer.sequence, 0)
                    .expect("plan catch up");
                let mut target =
                    RegionBridge::new_local(RegionId::new_for_test(70, 0), None, Budget::new());
                let snapshot = federation
                    .apply_replication_transfer(&mut target, &transfer)
                    .expect("apply transfer");

                let not_quiescent_before_drain = {
                    let mut stream = stream.lock().expect("stream lock");
                    stream.close().is_err()
                };
                ready.store(true, Ordering::SeqCst);

                for _ in 0..16 {
                    if removed.load(Ordering::SeqCst) == 2 {
                        break;
                    }
                    yield_now().await;
                }
                assert_eq!(
                    removed.load(Ordering::SeqCst),
                    2,
                    "mirror and source should drain"
                );

                let mut stream = stream.lock().expect("stream lock");
                let closed_after_drain = stream.close().is_ok();
                let snapshot_state = stream.snapshot().expect("snapshot");
                drop(stream);
                *summary.lock().expect("summary lock") = Some(ReplicationReorderSummary {
                    catch_up_action: catch_up.action,
                    snapshot_sequence: snapshot.sequence,
                    target_task_count: target.local().task_ids().len(),
                    not_quiescent_before_drain,
                    closed_after_drain,
                    mirror_remaining: snapshot_state.mirror_regions.len(),
                    source_remaining: snapshot_state.source_regions.len(),
                });
            })
            .expect("create controller");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    {
        let stream = Arc::clone(&stream);
        let ready = Arc::clone(&ready);
        let removed = Arc::clone(&removed);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                while !ready.load(Ordering::SeqCst) {
                    yield_now().await;
                }
                if stream
                    .lock()
                    .expect("stream lock")
                    .remove_mirror_region(RegionId::new_for_test(61, 0))
                {
                    removed.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("create mirror task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    {
        let stream = Arc::clone(&stream);
        let ready = Arc::clone(&ready);
        let removed = Arc::clone(&removed);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                while !ready.load(Ordering::SeqCst) {
                    yield_now().await;
                }
                yield_now().await;
                if stream
                    .lock()
                    .expect("stream lock")
                    .remove_source_region(RegionId::new_for_test(62, 0))
                {
                    removed.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("create source task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }
}

fn run_replication_reorder(seed: u64) -> ReplicationReorderSummary {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let summary = Arc::new(Mutex::new(None));
    schedule_replication_reorder(&mut runtime, &summary);
    assert_runtime_clean(&mut runtime, "replication reorder replay");
    summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("replication reorder summary")
}

fn build_replication_reorder(runtime: &mut LabRuntime) {
    let summary = Arc::new(Mutex::new(None));
    schedule_replication_reorder(runtime, &summary);
}

#[allow(clippy::too_many_lines)]
fn schedule_advisory_storm(
    runtime: &mut LabRuntime,
    summary: &Arc<Mutex<Option<AdvisoryStormSummary>>>,
) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let bridge = Arc::new(Mutex::new(
        FederationBridge::new(
            FederationRole::GatewayFabric(GatewayConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [MorphismCapability::RewriteNamespace],
        )
        .expect("gateway bridge"),
    ));
    let ready = Arc::new(AtomicBool::new(false));
    let interests_done = Arc::new(AtomicUsize::new(0));
    let advisories_done = Arc::new(AtomicUsize::new(0));

    {
        let bridge = Arc::clone(&bridge);
        let ready = Arc::clone(&ready);
        let interests_done = Arc::clone(&interests_done);
        let advisories_done = Arc::clone(&advisories_done);
        let summary = Arc::clone(summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let index = ShardedSublist::with_prefix_depth(8, 1);
                let guard = index.subscribe(&SubjectPattern::new("advisory.>"), None);
                assert_eq!(
                    index.lookup(&Subject::new("advisory.control.tick")).total(),
                    1
                );

                bridge
                    .lock()
                    .expect("bridge lock")
                    .activate()
                    .expect("activate");
                ready.store(true, Ordering::SeqCst);

                for _ in 0..20 {
                    if interests_done.load(Ordering::SeqCst) == 3
                        && advisories_done.load(Ordering::SeqCst) == 4
                    {
                        break;
                    }
                    yield_now().await;
                }
                assert_eq!(
                    interests_done.load(Ordering::SeqCst),
                    3,
                    "all interests should plan"
                );
                assert_eq!(
                    advisories_done.load(Ordering::SeqCst),
                    4,
                    "all advisories should forward"
                );

                drop(guard);
                let no_ghost_interest =
                    index.lookup(&Subject::new("advisory.control.tick")).total() == 0;

                let timed_out = bridge
                    .lock()
                    .expect("bridge lock")
                    .reconcile_gateway_convergence(Duration::from_secs(20))
                    .expect("convergence")
                    .timed_out;
                let runtime = bridge.lock().expect("bridge lock").runtime();
                let (propagated_interest_count, forwarded_advisory_count) = match runtime {
                    asupersync::messaging::federation::FederationBridgeRuntime::Gateway(
                        runtime,
                    ) => (
                        runtime.propagated_interests.len(),
                        runtime.forwarded_advisories.len(),
                    ),
                    other => panic!("expected gateway runtime, got {other:?}"),
                };

                *summary.lock().expect("summary lock") = Some(AdvisoryStormSummary {
                    propagated_interest_count,
                    forwarded_advisory_count,
                    timed_out,
                    no_ghost_interest,
                });
            })
            .expect("create controller");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    for pattern in ["tenant.route.>", "tenant.replay.>", "tenant.audit.>"] {
        let bridge = Arc::clone(&bridge);
        let ready = Arc::clone(&ready);
        let interests_done = Arc::clone(&interests_done);
        let pattern = pattern.to_string();
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                while !ready.load(Ordering::SeqCst) {
                    yield_now().await;
                }
                bridge
                    .lock()
                    .expect("bridge lock")
                    .plan_gateway_interest(
                        SystemSubjectFamily::Route,
                        SubjectPattern::new(&pattern),
                        2,
                        ControlBudget::default(),
                    )
                    .expect("plan interest");
                interests_done.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create interest task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    for pattern in [
        "tenant.advisory.alpha",
        "tenant.advisory.beta",
        "tenant.advisory.gamma",
        "tenant.advisory.delta",
    ] {
        let bridge = Arc::clone(&bridge);
        let ready = Arc::clone(&ready);
        let advisories_done = Arc::clone(&advisories_done);
        let pattern = pattern.to_string();
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                while !ready.load(Ordering::SeqCst) {
                    yield_now().await;
                }
                bridge
                    .lock()
                    .expect("bridge lock")
                    .forward_gateway_advisory(
                        SystemSubjectFamily::Replay,
                        SubjectPattern::new(&pattern),
                        ControlBudget::break_glass(),
                    )
                    .expect("forward advisory");
                advisories_done.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create advisory task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }
}

fn run_advisory_storm(seed: u64) -> AdvisoryStormSummary {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let summary = Arc::new(Mutex::new(None));
    schedule_advisory_storm(&mut runtime, &summary);
    assert_runtime_clean(&mut runtime, "advisory storm replay");
    summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("advisory storm summary")
}

fn build_advisory_storm(runtime: &mut LabRuntime) {
    let summary = Arc::new(Mutex::new(None));
    schedule_advisory_storm(runtime, &summary);
}

#[test]
fn federation_link_partition_replay_drains_buffered_routes_without_ghost_interest() {
    let summary = run_leaf_partition(0xFAB1_1701);

    assert!(summary.immediate_forwarded);
    assert_eq!(summary.drained_routes, 2);
    assert_eq!(summary.dropped_routes, 1);
    assert_eq!(summary.ghost_interest_after_drop, 0);
    assert_eq!(summary.drained_subjects.len(), 2);
    assert!(
        summary
            .drained_subjects
            .iter()
            .all(|subject| subject.starts_with("tenant.orders."))
    );

    assert_dpor_clean(
        "leaf partition replay",
        0xFAB1_1701,
        6,
        build_leaf_partition,
    );
}

#[test]
fn import_export_revocation_replay_fences_capabilities_without_leaks() {
    let summary = run_capability_revocation(0xFAB1_1702);

    assert!(!summary.export_fingerprint.is_empty());
    assert!(!summary.import_fingerprint.is_empty());
    assert!(summary.child_publish_visible_before_revoke);
    assert!(summary.child_subscribe_visible_before_revoke);
    assert_eq!(summary.removed_by_scope, 1);
    assert_eq!(summary.removed_by_subject, 1);
    assert_eq!(summary.final_grants, 0);

    assert_dpor_clean(
        "capability revocation replay",
        0xFAB1_1702,
        6,
        build_capability_revocation,
    );
}

#[test]
fn consumer_ack_race_replay_commits_once_and_drains_pending_state() {
    let summary = run_ack_race(0xFAB1_1703);

    assert_eq!(summary.committed_acks, 1);
    assert_eq!(summary.stale_acks, 1);
    assert_eq!(summary.pending_after, 0);
    assert_eq!(summary.ack_floor_after, 6);
    assert_eq!(summary.total_acquired, 1);
    assert_eq!(summary.total_committed, 1);

    assert_dpor_clean("ack race replay", 0xFAB1_1703, 8, build_ack_race);
}

#[test]
fn replication_and_stream_reorder_replay_reaches_quiescent_close() {
    let summary = run_replication_reorder(0xFAB1_1704);

    assert_eq!(
        summary.catch_up_action,
        ReplicationCatchUpAction::SnapshotThenDelta
    );
    assert_eq!(summary.snapshot_sequence, 1);
    assert_eq!(summary.target_task_count, 1);
    assert!(summary.not_quiescent_before_drain);
    assert!(summary.closed_after_drain);
    assert_eq!(summary.mirror_remaining, 0);
    assert_eq!(summary.source_remaining, 0);

    assert_dpor_clean(
        "replication reorder replay",
        0xFAB1_1704,
        6,
        build_replication_reorder,
    );
}

#[test]
fn control_plane_advisory_storm_replay_preserves_quiescence_and_no_ghost_interest() {
    let summary = run_advisory_storm(0xFAB1_1705);

    assert_eq!(summary.propagated_interest_count, 3);
    assert_eq!(summary.forwarded_advisory_count, 4);
    assert!(summary.timed_out);
    assert!(summary.no_ghost_interest);

    assert_dpor_clean(
        "advisory storm replay",
        0xFAB1_1705,
        6,
        build_advisory_storm,
    );
}
