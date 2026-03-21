//! FABRIC hot-path performance benchmarks.
//!
//! Criterion benchmarks for subject routing, CRDT merge, morphism
//! transform application, sharded routing, and link-cache acceleration.

#![allow(missing_docs)]
#![cfg(feature = "messaging-fabric")]

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures_lite::future::block_on;
use std::future::Future;
use std::hint::black_box;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::mpsc;
use asupersync::config::RaptorQConfig;
use asupersync::cx::Scope;
use asupersync::gen_server::{CallError, GenServer, Reply, SystemMsg};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::messaging::SubjectTransform;
use asupersync::messaging::capability::EventFamily;
use asupersync::messaging::capability::routing::{
    RoutingOperationKind, RoutingProgram, RoutingRequest,
};
use asupersync::messaging::class::{AckKind, DeliveryClass};
use asupersync::messaging::consumer::{
    FabricConsumer, FabricConsumerConfig, RecoverableCapsule, SequenceWindow,
};
use asupersync::messaging::control::{
    CursorCheckpoint, CursorMark, InterestSummary, JoinSemilattice, LagSketch, MembershipRecord,
    MembershipState, MembershipView,
};
use asupersync::messaging::fabric::{
    CellEpoch, CellTemperature, DataCapsule, Fabric, NodeRole, PlacementPolicy, RepairPolicy,
    StewardCandidate, StorageClass, SubjectCell,
};
use asupersync::messaging::ir::{
    CapabilityPermission, CapabilityTokenSchema, MorphismPlan, MorphismTransform, SubjectFamily,
};
use asupersync::messaging::service::ServiceObligation;
use asupersync::messaging::subject::{
    ShardedSublist, Subject, SubjectPattern, Sublist, SublistLinkCache,
};
use asupersync::obligation::ledger::ObligationLedger;
use asupersync::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use asupersync::remote::NodeId;
use asupersync::transport::mock::{SimTransportConfig, sim_channel};
use asupersync::types::policy::FailFast;
use asupersync::types::{Budget, ObjectId, ObjectParams, RegionId, TaskId, Time};

const FABRIC_BENCH_PAYLOAD: &[u8] = b"fabric benchmark payload";

fn deterministic_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_add(1);
    let mut out = vec![0u8; len];
    for byte in &mut out {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let value = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        *byte = (value & 0xFF) as u8;
    }
    out
}

fn fabric_capability_schema() -> CapabilityTokenSchema {
    CapabilityTokenSchema {
        name: "fabric.bench.publish".to_owned(),
        families: vec![SubjectFamily::Event],
        delivery_classes: vec![DeliveryClass::EphemeralInteractive],
        permissions: vec![CapabilityPermission::Publish],
    }
}

fn fabric_routing_program() -> RoutingProgram {
    let plan = MorphismPlan {
        name: "fabric-bench-routing".to_owned(),
        source_pattern: SubjectPattern::new("orders.>"),
        target_prefix: "fabric.orders".to_owned(),
        allowed_families: vec![SubjectFamily::Event],
        transforms: vec![MorphismTransform::RenamePrefix {
            from: "orders".to_owned(),
            to: "fabric.orders".to_owned(),
        }],
    };

    RoutingProgram::compile_export(&plan, RoutingOperationKind::Publish)
        .expect("routing program should compile")
}

fn bench_fabric_candidate(name: &str, domain: &str) -> StewardCandidate {
    StewardCandidate::new(NodeId::new(name), domain)
        .with_role(NodeRole::Steward)
        .with_role(NodeRole::RepairWitness)
        .with_storage_class(StorageClass::Durable)
}

fn bench_fabric_cell() -> SubjectCell {
    SubjectCell::new(
        &SubjectPattern::parse("orders.created").expect("pattern"),
        CellEpoch::new(7, 11),
        &[
            bench_fabric_candidate("node-a", "rack-a"),
            bench_fabric_candidate("node-b", "rack-b"),
            bench_fabric_candidate("node-c", "rack-c"),
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

fn connect_bench_fabric(cx: &Cx, lane: &str, counter: &mut u64) -> Fabric {
    *counter = counter.saturating_add(1);
    let endpoint = format!("bench://fabric/{lane}/{}", *counter);
    block_on(Fabric::connect(cx, &endpoint)).expect("connect")
}

fn allocate_bench_service_obligation(
    ledger: &mut ObligationLedger,
    delivery_class: DeliveryClass,
) -> ServiceObligation {
    ServiceObligation::allocate(
        ledger,
        "bench-request",
        "caller",
        "callee",
        "svc.fabric",
        delivery_class,
        TaskId::new_for_test(1, 0),
        RegionId::new_for_test(1, 0),
        Time::from_nanos(1),
        Some(Duration::from_secs(5)),
    )
    .expect("allocate")
}

fn raptorq_config_for_size(size: usize) -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    if size > config.encoding.max_block_size {
        config.encoding.max_block_size = size;
    }
    config
}

fn object_params_for(config: &RaptorQConfig, size: usize) -> ObjectParams {
    let symbol_size = usize::from(config.encoding.symbol_size);
    let symbols_per_block = ((size + symbol_size.saturating_sub(1)) / symbol_size) as u16;
    ObjectParams::new(
        ObjectId::new_for_test(1),
        size as u64,
        config.encoding.symbol_size,
        1,
        symbols_per_block,
    )
}

struct BenchCounter {
    count: u64,
}

enum BenchCall {
    Add(u64),
}

impl GenServer for BenchCounter {
    type Call = BenchCall;
    type Reply = u64;
    type Cast = ();
    type Info = SystemMsg;

    fn handle_call(
        &mut self,
        _cx: &Cx,
        request: BenchCall,
        reply: Reply<u64>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        match request {
            BenchCall::Add(n) => {
                self.count += n;
                let _ = reply.send(self.count);
            }
        }
        Box::pin(async {})
    }
}

// ---------------------------------------------------------------------------
// Subject lookup benchmarks
// ---------------------------------------------------------------------------

fn bench_literal_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("subject_lookup");

    let sl = Arc::new(Sublist::new());
    // Subscribe 100 literal patterns
    let guards: Vec<_> = (0..100)
        .map(|i| {
            let pattern = SubjectPattern::new(&format!("orders.region{i}.created"));
            sl.subscribe(&pattern, None)
        })
        .collect();

    let subject = Subject::new("orders.region42.created");
    group.bench_function("literal_cached", |b| {
        b.iter(|| sl.lookup(&subject));
    });

    let miss_subject = Subject::new("orders.region999.created");
    group.bench_function("literal_miss", |b| {
        b.iter(|| sl.lookup(&miss_subject));
    });

    drop(guards);
    group.finish();
}

fn bench_wildcard_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("subject_wildcard_lookup");

    let sl = Arc::new(Sublist::new());
    let _g1 = sl.subscribe(&SubjectPattern::new("orders.*.created"), None);
    let _g2 = sl.subscribe(&SubjectPattern::new("orders.>"), None);
    let _g3 = sl.subscribe(&SubjectPattern::new(">"), None);

    let subject = Subject::new("orders.region1.created");

    group.bench_function("single_wildcard", |b| {
        b.iter(|| sl.lookup(&subject));
    });

    group.finish();
}

fn bench_link_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("subject_link_cache");

    let sl = Arc::new(Sublist::new());
    let _g = sl.subscribe(&SubjectPattern::new("orders.>"), None);

    let subject = Subject::new("orders.region1.created");

    // Uncached path
    group.bench_function("uncached", |b| {
        b.iter(|| sl.lookup(&subject));
    });

    // Cached path (pre-warm then measure hits)
    let mut link_cache = SublistLinkCache::new(64);
    let _ = sl.lookup_with_link_cache(&subject, &mut link_cache); // warm
    group.bench_function("cached_hit", |b| {
        b.iter(|| {
            let _ = sl.lookup_with_link_cache(&subject, &mut link_cache);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Sharded sublist benchmarks
// ---------------------------------------------------------------------------

fn bench_sharded_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("sharded_sublist");

    for shard_count in [1, 4, 8, 16] {
        let sharded = ShardedSublist::new(shard_count);
        let _g = sharded.subscribe(&SubjectPattern::new(">"), None);

        let subject = Subject::new("orders.region1.created");

        group.bench_with_input(
            BenchmarkId::new("lookup", shard_count),
            &shard_count,
            |b, _| {
                b.iter(|| sharded.lookup(&subject));
            },
        );
    }

    group.finish();
}

fn bench_shard_assignment(c: &mut Criterion) {
    let mut group = c.benchmark_group("shard_assignment");

    let sharded = ShardedSublist::new(8);
    let subject = Subject::new("orders.region1.created");

    group.bench_function("shard_index", |b| {
        b.iter(|| sharded.shard_index_for_subject(&subject));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// CRDT merge benchmarks
// ---------------------------------------------------------------------------

fn bench_crdt_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("crdt_merge");

    let node_a = NodeId::new("node-a");
    let node_b = NodeId::new("node-b");

    // InterestSummary merge
    {
        let mut a = InterestSummary::default();
        a.subscribe(&node_a, SubjectPattern::new("orders.>"));
        a.subscribe(&node_a, SubjectPattern::new("events.*"));
        let mut b = InterestSummary::default();
        b.subscribe(&node_b, SubjectPattern::new("orders.>"));
        b.subscribe(&node_b, SubjectPattern::new("logs.>"));

        group.bench_function("interest_summary", |bench| {
            bench.iter(|| {
                let mut merged = a.clone();
                merged.merge(&b);
                merged
            });
        });
    }

    // CursorCheckpoint merge
    {
        let mut a = CursorCheckpoint::default();
        a.observe("consumer-1", CursorMark::new(100, 1000, node_a.clone()));
        a.observe("consumer-2", CursorMark::new(200, 2000, node_a.clone()));
        let mut b = CursorCheckpoint::default();
        b.observe("consumer-1", CursorMark::new(150, 1500, node_b.clone()));
        b.observe("consumer-3", CursorMark::new(50, 500, node_b.clone()));

        group.bench_function("cursor_checkpoint", |bench| {
            bench.iter(|| {
                let mut merged = a.clone();
                merged.merge(&b);
                merged
            });
        });
    }

    // LagSketch merge
    {
        let mut a = LagSketch::default();
        for i in 0..10 {
            a.observe(&node_a, i * 100);
        }
        let mut b = LagSketch::default();
        for i in 0..10 {
            b.observe(&node_b, i * 150);
        }

        group.bench_function("lag_sketch", |bench| {
            bench.iter(|| {
                let mut merged = a.clone();
                merged.merge(&b);
                merged
            });
        });
    }

    // MembershipView merge
    {
        let mut a = MembershipView::default();
        a.observe(
            node_a.clone(),
            MembershipRecord::new(10, MembershipState::Healthy, 1000, 500),
        );
        let mut b = MembershipView::default();
        b.observe(
            node_b.clone(),
            MembershipRecord::new(12, MembershipState::Healthy, 1200, 300),
        );

        group.bench_function("membership_view", |bench| {
            bench.iter(|| {
                let mut merged = a.clone();
                merged.merge(&b);
                merged
            });
        });
    }

    group.finish();
}

fn bench_crdt_delta(c: &mut Criterion) {
    let mut group = c.benchmark_group("crdt_delta");

    let node_a = NodeId::new("node-a");

    // InterestSummary delta
    {
        let baseline = InterestSummary::default();
        let mut updated = InterestSummary::default();
        updated.subscribe(&node_a, SubjectPattern::new("orders.>"));
        updated.subscribe(&node_a, SubjectPattern::new("events.*"));

        group.bench_function("interest_summary_delta", |bench| {
            bench.iter(|| updated.delta(&baseline));
        });

        let delta = updated.delta(&baseline);
        group.bench_function("interest_summary_apply", |bench| {
            bench.iter(|| {
                let mut applied = baseline.clone();
                applied.apply_delta(&delta);
                applied
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Morphism transform benchmarks
// ---------------------------------------------------------------------------

fn bench_transform_apply(c: &mut Criterion) {
    let mut group = c.benchmark_group("transform_apply");

    let tokens = vec![
        "orders".to_string(),
        "region1".to_string(),
        "created".to_string(),
    ];

    // Identity
    group.bench_function("identity", |b| {
        let t = SubjectTransform::Identity;
        b.iter(|| t.apply_tokens(&tokens));
    });

    // RenamePrefix
    group.bench_function("rename_prefix", |b| {
        let t = SubjectTransform::RenamePrefix {
            from: SubjectPattern::new("orders"),
            to: SubjectPattern::new("processed"),
        };
        b.iter(|| t.apply_tokens(&tokens));
    });

    // DeterministicHash
    group.bench_function("deterministic_hash", |b| {
        let t = SubjectTransform::DeterministicHash {
            buckets: 16,
            source_indices: vec![1, 2],
        };
        b.iter(|| t.apply_tokens(&tokens));
    });

    // HashPartition
    group.bench_function("hash_partition", |b| {
        let t = SubjectTransform::HashPartition { buckets: 8 };
        b.iter(|| t.apply_tokens(&tokens));
    });

    // Compose (rename + hash)
    group.bench_function("compose_two", |b| {
        let t = SubjectTransform::Compose {
            steps: vec![
                SubjectTransform::RenamePrefix {
                    from: SubjectPattern::new("orders"),
                    to: SubjectPattern::new("processed"),
                },
                SubjectTransform::DeterministicHash {
                    buckets: 8,
                    source_indices: vec![1],
                },
            ],
        };
        b.iter(|| t.apply_tokens(&tokens));
    });

    // LeftExtract
    group.bench_function("left_extract", |b| {
        let t = SubjectTransform::LeftExtract { index: 2, len: 3 };
        b.iter(|| t.apply_tokens(&tokens));
    });

    // SplitSlice
    group.bench_function("split_slice", |b| {
        let tokens_with_delim = vec!["key-val".to_string(), "data".to_string()];
        let t = SubjectTransform::SplitSlice {
            index: 1,
            delimiter: "-".to_string(),
            start: 0,
            len: 1,
        };
        b.iter(|| t.apply_tokens(&tokens_with_delim));
    });

    group.finish();
}

fn bench_transform_invertibility(c: &mut Criterion) {
    let mut group = c.benchmark_group("transform_invertibility");

    let rename = SubjectTransform::RenamePrefix {
        from: SubjectPattern::new("orders"),
        to: SubjectPattern::new("processed"),
    };

    group.bench_function("is_invertible_rename", |b| {
        b.iter(|| rename.is_invertible());
    });

    let compose = SubjectTransform::Compose {
        steps: vec![
            SubjectTransform::RenamePrefix {
                from: SubjectPattern::new("a"),
                to: SubjectPattern::new("b"),
            },
            SubjectTransform::RenamePrefix {
                from: SubjectPattern::new("b"),
                to: SubjectPattern::new("c"),
            },
        ],
    };

    group.bench_function("is_invertible_compose", |b| {
        b.iter(|| compose.is_invertible());
    });

    group.bench_function("inverse_compose", |b| {
        b.iter(|| compose.inverse());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Pattern matching benchmarks
// ---------------------------------------------------------------------------

fn bench_pattern_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_matching");

    let literal = SubjectPattern::new("orders.region1.created");
    let wildcard = SubjectPattern::new("orders.*.created");
    let tail = SubjectPattern::new("orders.>");
    let subject = Subject::new("orders.region1.created");

    group.bench_function("literal_matches", |b| {
        b.iter(|| literal.matches(&subject));
    });

    group.bench_function("single_wildcard_matches", |b| {
        b.iter(|| wildcard.matches(&subject));
    });

    group.bench_function("tail_wildcard_matches", |b| {
        b.iter(|| tail.matches(&subject));
    });

    let p1 = SubjectPattern::new("orders.*.created");
    let p2 = SubjectPattern::new("orders.region1.*");
    group.bench_function("overlaps", |b| {
        b.iter(|| p1.overlaps(&p2));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Subscribe/unsubscribe throughput
// ---------------------------------------------------------------------------

fn bench_subscribe_unsubscribe(c: &mut Criterion) {
    let mut group = c.benchmark_group("subscribe_unsubscribe");

    let sl = Arc::new(Sublist::new());
    let pattern = SubjectPattern::new("orders.region1.created");

    group.bench_function("subscribe_then_drop", |b| {
        b.iter(|| {
            let guard = sl.subscribe(&pattern, None);
            drop(guard);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Scaled lookup benchmarks
// ---------------------------------------------------------------------------

fn bench_scaled_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaled_lookup");

    for sub_count in [10, 100, 1000] {
        let sl = Arc::new(Sublist::new());
        let guards: Vec<_> = (0..sub_count)
            .map(|i| {
                let pattern = SubjectPattern::new(&format!("svc{i}.events.created"));
                sl.subscribe(&pattern, None)
            })
            .collect();

        let subject = Subject::new("svc0.events.created");

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("literal", sub_count),
            &sub_count,
            |b, _| {
                b.iter(|| sl.lookup(&subject));
            },
        );

        drop(guards);
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Capability and routing benchmarks
// ---------------------------------------------------------------------------

fn bench_capability_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("fabric_capability_checks");

    let cx = Cx::for_testing();
    let schema = fabric_capability_schema();
    let token = cx
        .grant_publish_capability::<EventFamily>(
            SubjectPattern::new("orders.>"),
            &schema,
            DeliveryClass::EphemeralInteractive,
        )
        .expect("grant publish capability");
    let program = fabric_routing_program();
    let request = RoutingRequest::Publish(Subject::new("orders.created"));

    group.bench_function("in_process_token", |b| {
        b.iter(|| {
            black_box(
                program
                    .authorize_in_process(&token, SubjectFamily::Event, &request)
                    .expect("in-process authorization"),
            )
        });
    });

    group.bench_function("distributed_cx_check", |b| {
        b.iter(|| {
            black_box(
                program
                    .authorize_distributed(&cx, SubjectFamily::Event, &request)
                    .expect("distributed authorization"),
            )
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Publish and request/reply benchmarks
// ---------------------------------------------------------------------------

fn bench_publish_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("fabric_publish");

    let cx = Cx::for_testing();
    let mut endpoint_counter = 0u64;

    group.bench_function("ephemeral_public_api", |b| {
        b.iter_batched(
            || connect_bench_fabric(&cx, "publish", &mut endpoint_counter),
            |fabric| {
                black_box(
                    block_on(fabric.publish(&cx, "orders.created", FABRIC_BENCH_PAYLOAD.to_vec()))
                        .expect("publish"),
                );
            },
            BatchSize::SmallInput,
        );
    });

    // The public Fabric surface currently exposes only the cheap ephemeral
    // publish API. For the stronger-guarantee comparison, benchmark the
    // existing obligation-backed service admission/commit path as the current
    // tracked publish surrogate.
    group.bench_function("tracked_publish_surrogate", |b| {
        b.iter_batched(
            ObligationLedger::new,
            |mut ledger| {
                let mut obligation =
                    allocate_bench_service_obligation(&mut ledger, DeliveryClass::ObligationBacked);
                black_box(
                    obligation
                        .commit_with_reply(
                            &mut ledger,
                            Time::from_nanos(2),
                            FABRIC_BENCH_PAYLOAD.to_vec(),
                            AckKind::Served,
                            false,
                        )
                        .expect("tracked publish surrogate commit"),
                );
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_request_reply_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("fabric_request_reply");

    let cx = Cx::for_testing();
    let mut endpoint_counter = 0u64;

    group.bench_function("ephemeral_loopback", |b| {
        b.iter_batched(
            || connect_bench_fabric(&cx, "request", &mut endpoint_counter),
            |fabric| {
                black_box(
                    block_on(fabric.request(&cx, "svc.lookup", FABRIC_BENCH_PAYLOAD.to_vec()))
                        .expect("request"),
                );
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("obligation_backed_roundtrip", |b| {
        b.iter_batched(
            ObligationLedger::new,
            |mut ledger| {
                let mut obligation =
                    allocate_bench_service_obligation(&mut ledger, DeliveryClass::ObligationBacked);
                let committed = obligation
                    .commit_with_reply(
                        &mut ledger,
                        Time::from_nanos(2),
                        FABRIC_BENCH_PAYLOAD.to_vec(),
                        AckKind::Received,
                        true,
                    )
                    .expect("obligation-backed commit");
                let reply = committed.reply_obligation.expect("reply obligation");
                black_box(reply.commit_delivery(&mut ledger, Time::from_nanos(3)));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Consumer and RaptorQ benchmarks
// ---------------------------------------------------------------------------

fn bench_consumer_ack(c: &mut Criterion) {
    let mut group = c.benchmark_group("fabric_consumer");

    group.bench_function("dispatch_push_plus_ack", |b| {
        b.iter_batched(
            || {
                let cell = bench_fabric_cell();
                let consumer =
                    FabricConsumer::new(&cell, FabricConsumerConfig::default()).expect("consumer");
                let window = SequenceWindow::new(10, 10).expect("window");
                let capsule =
                    RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);
                (consumer, window, capsule)
            },
            |(mut consumer, window, capsule)| {
                let delivery = consumer
                    .dispatch_push(window, &capsule, None)
                    .expect("dispatch");
                black_box(
                    consumer
                        .acknowledge_delivery(&delivery.attempt)
                        .expect("ack"),
                );
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_raptorq_data_capsule(c: &mut Criterion) {
    let mut group = c.benchmark_group("fabric_raptorq_data_capsule");
    let cx = Cx::for_testing();

    for size in [1024usize, 4096usize] {
        let data = deterministic_bytes(size, size as u64);
        let config = raptorq_config_for_size(size);
        let params = object_params_for(&config, size);
        let object_id = params.object_id;

        let symbol_size = usize::from(config.encoding.symbol_size);
        let source_symbols = size.div_ceil(symbol_size);
        let total_with_overhead =
            (source_symbols as f64 * config.encoding.repair_overhead).ceil() as usize;
        let transport_capacity = total_with_overhead + total_with_overhead / 4;

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("encode_decode_roundtrip", size),
            &size,
            |b, _| {
                b.iter_batched(
                    || {
                        let mut transport_config = SimTransportConfig::reliable();
                        transport_config.capacity = transport_capacity;
                        let (sink, stream) = sim_channel(transport_config);
                        let sender = RaptorQSenderBuilder::new()
                            .config(config.clone())
                            .transport(sink)
                            .build()
                            .expect("build sender");
                        let receiver = RaptorQReceiverBuilder::new()
                            .config(config.clone())
                            .source(stream)
                            .build()
                            .expect("build receiver");
                        (sender, receiver)
                    },
                    |(mut sender, mut receiver)| {
                        black_box(
                            sender
                                .send_object(&cx, object_id, &data)
                                .expect("send object"),
                        );
                        black_box(
                            receiver
                                .receive_object(&cx, &params)
                                .expect("receive object"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Baseline comparisons
// ---------------------------------------------------------------------------

fn bench_baseline_compare(c: &mut Criterion) {
    let mut group = c.benchmark_group("fabric_baseline_compare");

    group.bench_function("direct_mpsc_send_recv", |b| {
        b.iter_batched(
            || mpsc::channel::<u64>(1),
            |(tx, mut rx)| {
                tx.try_send(1).expect("send");
                black_box(rx.try_recv().expect("recv"));
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("gen_server_call_roundtrip", |b| {
        b.iter(|| {
            let budget = Budget::new().with_poll_quota(100_000);
            let mut runtime = LabRuntime::new(LabConfig::new(42));
            let region = runtime.state.create_root_region(budget);
            let cx = Cx::for_testing();
            let scope = Scope::<FailFast>::new(region, budget);

            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, BenchCounter { count: 0 }, 32)
                .expect("spawn server");
            let server_task_id = handle.task_id();
            runtime.state.store_spawned_task(server_task_id, stored);

            let server_ref = handle.server_ref();
            let result: Arc<Mutex<Option<Result<u64, CallError>>>> = Arc::new(Mutex::new(None));
            let result_clone = Arc::clone(&result);

            let (client_handle, client_stored) = scope
                .spawn(&mut runtime.state, &cx, move |cx| async move {
                    let call_result = server_ref.call(&cx, BenchCall::Add(1)).await;
                    *result_clone.lock().expect("result mutex") = Some(call_result);
                })
                .expect("spawn client");
            let client_task_id = client_handle.task_id();
            runtime
                .state
                .store_spawned_task(client_task_id, client_stored);

            {
                let mut scheduler = runtime.scheduler.lock();
                scheduler.schedule(server_task_id, 0);
                scheduler.schedule(client_task_id, 0);
            }
            runtime.run_until_idle();
            {
                let mut scheduler = runtime.scheduler.lock();
                scheduler.schedule(server_task_id, 0);
                scheduler.schedule(client_task_id, 0);
            }
            runtime.run_until_idle();

            let guard = result.lock().expect("result mutex");
            black_box(guard.as_ref().expect("call result").is_ok());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_literal_lookup,
    bench_wildcard_lookup,
    bench_link_cache,
    bench_sharded_lookup,
    bench_shard_assignment,
    bench_crdt_merge,
    bench_crdt_delta,
    bench_transform_apply,
    bench_transform_invertibility,
    bench_pattern_matching,
    bench_subscribe_unsubscribe,
    bench_scaled_lookup,
    bench_capability_checks,
    bench_publish_paths,
    bench_request_reply_paths,
    bench_consumer_ack,
    bench_raptorq_data_capsule,
    bench_baseline_compare,
);

criterion_main!(benches);
