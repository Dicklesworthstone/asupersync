//! Real authenticated cutover and retirement of node-owned discovery sources.

use super::*;
use asupersync::distributed::{
    NativeDistributedClient, NativeDistributedDiscoveryHandle, NativeDistributedDiscoveryResult,
    NativeDistributedDiscoveryStartError,
};
use asupersync::remote::{
    NativeRemoteDiscoveryBuildError, NativeRemoteDiscoveryConfig, NativeRemoteDiscoveryError,
    NativeRemoteDiscoveryReport,
};
use asupersync::runtime::BlockingAdmissionPolicy;
use asupersync::service::discover::{Change, Discover};
use std::io;
use std::sync::{Mutex as StdMutex, mpsc};

enum Step {
    Snapshot(Vec<SocketAddr>),
    Failure,
}

// A source poll is observably running on the real blocking pool before the test
// releases it. Every wait is bounded; dropping the sender also releases a poll
// during panic cleanup, without an untracked helper task or sleeping OS thread.
struct ControlledDiscovery {
    incoming: StdMutex<mpsc::Receiver<Step>>,
    snapshot: StdMutex<Vec<SocketAddr>>,
    polls: AtomicUsize,
    reads: AtomicUsize,
}

fn controlled() -> (Arc<ControlledDiscovery>, mpsc::Sender<Step>) {
    let (sender, receiver) = mpsc::channel();
    (Arc::new(ControlledDiscovery {
        incoming: StdMutex::new(receiver),
        snapshot: StdMutex::new(Vec::new()),
        polls: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
    }), sender)
}

impl Discover for ControlledDiscovery {
    type Key = SocketAddr;
    type Error = io::Error;

    fn poll_discover(&self) -> Result<Vec<Change<SocketAddr>>, io::Error> {
        self.polls.fetch_add(1, Ordering::AcqRel);
        let step = self.incoming.lock().unwrap().recv_timeout(WINDOW)
            .map_err(|error| io::Error::other(error.to_string()))?;
        match step {
            Step::Snapshot(endpoints) => {
                *self.snapshot.lock().unwrap() = endpoints;
                Ok(Vec::new())
            }
            Step::Failure => Err(io::Error::other("controlled discovery failure")),
        }
    }

    fn endpoints(&self) -> Vec<SocketAddr> {
        self.reads.fetch_add(1, Ordering::AcqRel);
        self.snapshot.lock().unwrap().clone()
    }
}

fn discovery_config() -> NativeRemoteDiscoveryConfig {
    NativeRemoteDiscoveryConfig::new()
        .with_poll_interval(Duration::from_millis(1))
        .with_retry_backoff(Duration::from_millis(1))
        .with_max_consecutive_failures(1)
}

async fn source_entered(cx: &Cx, source: &ControlledDiscovery, polls: usize) {
    eventually(cx, || source.polls.load(Ordering::Acquire) == polls).await;
}

async fn join_discovery(
    cx: &Cx, owner: &mut NativeDistributedDiscoveryHandle,
) -> NativeDistributedDiscoveryResult {
    asupersync::time::timeout(cx.now(), WINDOW, assert_send(owner.join()))
        .await.expect("discovery retirement")
}

fn stopped_report(result: NativeDistributedDiscoveryResult) -> NativeRemoteDiscoveryReport {
    assert_retired(result.retirement);
    result.outcome.expect("entered discovery retained its actual report").unwrap()
}

async fn echo(cx: &Cx, client: &NativeDistributedClient, incarnation: u64, bytes: &[u8]) {
    let mut owner = client.spawn_remote(
        NodeId::new("worker"), incarnation, ComputationName::new("echo"),
        RemoteInput::new(bytes.to_vec()), remote_run_config(),
    ).unwrap();
    let result = asupersync::time::timeout(cx.now(), WINDOW, assert_send(owner.join()))
        .await.expect("authenticated routed computation");
    assert_node_remote_success(result, bytes);
}

#[test]
fn discovery_cuts_over_authenticated_work_and_keeps_both_route_catalogs_current() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let runtime_handle = runtime.handle();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, membership, client, hello, echo_calls: original_calls, .. } =
                fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
            let original_address = service.local_addr().unwrap();
            let Fixture {
                service: next_service, membership: next_membership, echo_calls: next_calls, ..
            } = fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
            let next_address = next_service.local_addr().unwrap();
            let next_node = NativeDistributedNode::start(
                &cx, next_service, next_membership, None, ChildRegionSpec::inherit(),
            ).await.unwrap();
            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            let node = NativeDistributedNode::start_with_outbound(
                &cx, service, membership, None, outbound_config(runtime_handle), ChildRegionSpec::inherit(),
            ).await.unwrap();
            let outbound = node.client().unwrap();
            outbound.publish_peer(NativeRemoteRoute::new(NodeId::new("worker"), hello, client), 1).unwrap();
            echo(&cx, &outbound, 1, b"before discovery").await;
            assert_eq!(original_calls.load(Ordering::Acquire), 1);
            assert_eq!(next_calls.load(Ordering::Acquire), 0);

            let (source, advance) = controlled();
            let mut discovery = assert_send(outbound.spawn_peer_discovery(
                NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 2,
            ).unwrap());
            assert_eq!(discovery.destination(), &NodeId::new("worker"));
            assert_eq!(discovery.incarnation(), 1);
            source_entered(&cx, &source, 1).await;
            assert_eq!(outbound.retained_discoveries(), 1);
            assert!(!discovery.is_finished());

            // Discovery does not consume the single named-computation credit.
            let mut work = outbound.spawn_remote(
                NodeId::new("worker"), 1, ComputationName::new("echo"),
                RemoteInput::new(b"independent capacity".to_vec()), remote_run_config(),
            ).unwrap();
            eventually(&cx, || work.is_finished()).await;
            assert_eq!(outbound.retained_operations(), 1);
            assert!(matches!(outbound.spawn_peer_discovery(
                NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 2,
            ), Err(NativeDistributedDiscoveryStartError::PeerOccupied)));
            assert_node_remote_success(work.join().await, b"independent capacity");

            advance.send(Step::Snapshot(vec![next_address])).unwrap();
            source_entered(&cx, &source, 2).await;
            assert_eq!(outbound.route_generation(), 2);
            echo(&cx, &outbound, 1, b"after discovery").await;
            assert_eq!(original_calls.load(Ordering::Acquire), 2);
            assert_eq!(next_calls.load(Ordering::Acquire), 1);

            // This rebuilds every private native route from the node's peer
            // catalog. It must not restore the obsolete original endpoint or
            // invalidate discovery merely because the global generation moved.
            assert_eq!(outbound.remove_peer(&NodeId::new("unrelated")).unwrap(), 3);
            advance.send(Step::Snapshot(vec![next_address])).unwrap();
            source_entered(&cx, &source, 3).await;
            assert_eq!(outbound.route_generation(), 3);
            assert!(!discovery.is_finished());
            echo(&cx, &outbound, 1, b"after catalog rebuild").await;
            assert_eq!(original_calls.load(Ordering::Acquire), 2);
            assert_eq!(next_calls.load(Ordering::Acquire), 2);

            discovery.abort();
            poll_fn(|task| {
                assert!(discovery.poll_join(task).is_pending(),
                    "cancelled source still owns its running blocking poll");
                Poll::Ready(())
            }).await;
            assert_eq!(outbound.retained_discoveries(), 1);
            advance.send(Step::Snapshot(vec![original_address])).unwrap();
            let report = stopped_report(join_discovery(&cx, &mut discovery).await);
            assert_eq!(report.polls(), 3);
            assert_eq!(report.route_publications(), 1);
            assert_eq!(report.unchanged_snapshots(), 1);
            assert_eq!(report.final_route_generation(), 3);
            assert_eq!(outbound.retained_discoveries(), 0);
            echo(&cx, &outbound, 1, b"late cancelled snapshot ignored").await;
            assert_eq!(original_calls.load(Ordering::Acquire), 2);
            assert_eq!(next_calls.load(Ordering::Acquire), 3);

            let report = node.close().await;
            assert!(matches!(report.region_close, Some(Ok(()))));
            let remote = report.outbound.unwrap();
            assert_eq!(remote.active_sessions, 0);
            assert_eq!(remote.retained_discoveries, 0);
            assert!(matches!(next_node.close().await.region_close, Some(Ok(()))));
        });
        finish(runtime);
    }
}

#[test]
fn discovery_refuses_invalid_snapshots_and_retains_unread_failure_credit() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let runtime_handle = runtime.handle();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let Fixture { service, membership, client, hello, echo_calls, .. } =
            fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
        let address = service.local_addr().unwrap();
        membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
        let node = NativeDistributedNode::start_with_outbound(
            &cx, service, membership, None, outbound_config(runtime_handle), ChildRegionSpec::inherit(),
        ).await.unwrap();
        let outbound = node.client().unwrap();
        outbound.publish_peer(NativeRemoteRoute::new(NodeId::new("worker"), hello, client), 1).unwrap();
        let (source, advance) = controlled();
        let mut discovery = outbound.spawn_peer_discovery(
            NodeId::new("worker"), 1, Arc::clone(&source),
            discovery_config().with_max_consecutive_failures(4), 2,
        ).unwrap();
        source_entered(&cx, &source, 1).await;
        advance.send(Step::Snapshot(vec![])).unwrap();
        source_entered(&cx, &source, 2).await;
        advance.send(Step::Snapshot(vec![address, address])).unwrap();
        source_entered(&cx, &source, 3).await;
        advance.send(Step::Snapshot(vec![address, "127.0.0.1:9".parse().unwrap(),
            "127.0.0.1:10".parse().unwrap()])).unwrap();
        source_entered(&cx, &source, 4).await;
        advance.send(Step::Failure).unwrap();
        eventually(&cx, || discovery.is_finished()).await;
        assert_eq!(outbound.route_generation(), 1);
        assert_eq!(outbound.retained_discoveries(), 1);
        assert_eq!(source.reads.load(Ordering::Acquire), 3);
        assert!(matches!(outbound.spawn_peer_discovery(
            NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 2,
        ), Err(NativeDistributedDiscoveryStartError::PeerOccupied)));
        echo(&cx, &outbound, 1, b"last good endpoint").await;
        assert_eq!(echo_calls.load(Ordering::Acquire), 1);

        let terminal = join_discovery(&cx, &mut discovery).await;
        assert_eq!(terminal.retirement, Ok(()));
        let error = terminal.outcome.unwrap().unwrap_err();
        assert!(matches!(&error, NativeRemoteDiscoveryError::RetryExhausted {
            consecutive_failures: 4, ..
        }));
        assert_eq!(error.report().polls(), 4);
        assert_eq!(error.report().refused_snapshots(), 3);
        assert_eq!(error.report().source_failures(), 1);
        assert_eq!(error.report().route_publications(), 0);
        assert_eq!(error.report().final_route_generation(), 1);
        assert_eq!(outbound.retained_discoveries(), 0);
        let repeated = discovery.join().await;
        assert!(repeated.outcome.is_none());
        assert_eq!(repeated.retirement, Err(JoinError::PolledAfterCompletion));
        assert!(matches!(node.close().await.region_close, Some(Ok(()))));
    });
    finish(runtime);
}

#[test]
fn pending_discovery_cannot_restore_replaced_removed_or_revoked_peer_authority() {
    for replacement in 0..5 {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let runtime_handle = runtime.handle();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, membership, client, hello, .. } =
                fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            let route = NativeRemoteRoute::new(NodeId::new("worker"), hello, client);
            let node = NativeDistributedNode::start_with_outbound(
                &cx, service, membership.clone(), None, outbound_config(runtime_handle), ChildRegionSpec::inherit(),
            ).await.unwrap();
            let outbound = node.client().unwrap();
            outbound.publish_peer(route.clone(), 1).unwrap();
            let (source, advance) = controlled();
            let mut discovery = outbound.spawn_peer_discovery(
                NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 2,
            ).unwrap();
            source_entered(&cx, &source, 1).await;
            let (generation, usable_incarnation) = match replacement {
                0 => (outbound.publish_peer(route.clone(), 1).unwrap(), Some(1)),
                1 => (outbound.remove_peer(&NodeId::new("worker")).unwrap(), None),
                2 => {
                    outbound.remove_peer(&NodeId::new("worker")).unwrap();
                    (outbound.publish_peer(route.clone(), 1).unwrap(), Some(1))
                }
                3 => {
                    membership.apply_authenticated(&NodeId::new("authority"),
                        &member_statement(1, 2, MembershipKind::Dead)).unwrap();
                    membership.apply_authenticated(&NodeId::new("authority"),
                        &member_statement(2, 3, MembershipKind::Alive)).unwrap();
                    (outbound.publish_peer(route.clone(), 2).unwrap(), Some(2))
                }
                _ => {
                    membership.apply_authenticated(&NodeId::new("authority"),
                        &member_statement(1, 2, MembershipKind::Dead)).unwrap();
                    (outbound.route_generation(), None)
                }
            };
            advance.send(Step::Snapshot(vec!["127.0.0.1:9".parse().unwrap()])).unwrap();
            let terminal = join_discovery(&cx, &mut discovery).await;
            assert_eq!(terminal.retirement, Ok(()));
            let error = terminal.outcome.unwrap().unwrap_err();
            assert!(matches!(&error, NativeRemoteDiscoveryError::DestinationRemoved { .. }), "{error:?}");
            assert_eq!(error.report().polls(), 1);
            assert_eq!(error.report().route_publications(), 0);
            assert_eq!(error.report().final_route_generation(), generation);
            assert_eq!(outbound.route_generation(), generation);
            assert_eq!(source.polls.load(Ordering::Acquire), 1);
            assert_eq!(outbound.retained_discoveries(), 0);
            if let Some(incarnation) = usable_incarnation {
                echo(&cx, &outbound, incarnation, b"explicit provisioning survives stale discovery").await;
            } else {
                assert!(matches!(outbound.spawn_remote(
                    NodeId::new("worker"), 1, ComputationName::new("echo"),
                    RemoteInput::empty(), remote_run_config(),
                ), Err(NativeDistributedOutboundError::Membership)));
            }
            assert!(matches!(node.close().await.region_close, Some(Ok(()))));
        });
        finish(runtime);
    }
}

#[test]
fn discovery_drop_and_node_close_drain_the_actual_source_before_releasing_ownership() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let runtime_handle = runtime.handle();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, membership, client, hello, .. } =
                fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
            let address = service.local_addr().unwrap();
            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            let node = NativeDistributedNode::start_with_outbound(
                &cx, service, membership, None, outbound_config(runtime_handle), ChildRegionSpec::inherit(),
            ).await.unwrap();
            let outbound = node.client().unwrap();
            outbound.publish_peer(NativeRemoteRoute::new(NodeId::new("worker"), hello, client), 1).unwrap();
            let (source, advance) = controlled();
            let discovery = outbound.spawn_peer_discovery(
                NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 2,
            ).unwrap();
            source_entered(&cx, &source, 1).await;
            drop(discovery);
            assert_eq!(outbound.retained_discoveries(), 1);
            assert!(matches!(outbound.spawn_peer_discovery(
                NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 2,
            ), Err(NativeDistributedDiscoveryStartError::PeerOccupied)));
            echo(&cx, &outbound, 1, b"source draining independently").await;
            advance.send(Step::Snapshot(vec!["127.0.0.1:9".parse().unwrap()])).unwrap();
            eventually(&cx, || outbound.retained_discoveries() == 0).await;
            assert_eq!(outbound.route_generation(), 1);

            let (last_source, last_advance) = controlled();
            let mut last = outbound.spawn_peer_discovery(
                NodeId::new("worker"), 1, Arc::clone(&last_source), discovery_config(), 2,
            ).unwrap();
            source_entered(&cx, &last_source, 1).await;
            node.begin_close();
            assert!(outbound.is_closed());
            assert!(matches!(outbound.spawn_peer_discovery(
                NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 2,
            ), Err(NativeDistributedDiscoveryStartError::Outbound(NativeDistributedOutboundError::Closed))));
            let mut closing = std::pin::pin!(assert_send(node.close()));
            poll_fn(|task| {
                assert!(closing.as_mut().poll(task).is_pending(),
                    "node close must await the source callback already executing");
                Poll::Ready(())
            }).await;
            assert!(!last.is_finished());
            last_advance.send(Step::Snapshot(vec![address])).unwrap();
            let report = asupersync::time::timeout(cx.now(), WINDOW, closing)
                .await.expect("node discovery drain");
            assert!(matches!(report.region_close, Some(Ok(()))));
            let remote = report.outbound.unwrap();
            assert!(remote.graceful);
            assert_eq!(remote.active_sessions, 0);
            assert_eq!(remote.route_generation, 1);
            assert_eq!(remote.retained_discoveries, 1, "unread actual report remains charged");
            let actual = stopped_report(join_discovery(&cx, &mut last).await);
            assert_eq!(actual.polls(), 1);
            assert_eq!(actual.route_publications(), 0);
            assert_eq!(actual.unchanged_snapshots(), 0, "closed owner cannot even accept a late unchanged snapshot");
            assert_eq!(outbound.retained_discoveries(), 0);
            assert_eq!(source.polls.load(Ordering::Acquire), 1);
            assert_eq!(last_source.polls.load(Ordering::Acquire), 1);
        });
        finish(runtime);
    }
}

#[test]
fn discovery_admission_refuses_before_source_effects_and_charges_retired_peer_slots() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let runtime_handle = runtime.handle();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let Fixture { service, membership, client, hello, .. } = fixture_protocol_members(
            &cx, RemoteProtocolVersion::V3,
            ["worker", "other"].into_iter().map(|name| MembershipFloor {
                node: NodeId::new(name), incarnation: 0, sequence: 0,
            }).collect(),
        ).await;
        membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
        let other = MembershipUpdate {
            event: MembershipEvent { node: NodeId::new("other"), incarnation: 1, kind: MembershipKind::Alive },
            sequence: 1,
        }.authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42)).unwrap();
        membership.apply_authenticated(&NodeId::new("authority"), &other).unwrap();
        let node = NativeDistributedNode::start_with_outbound(
            &cx, service, membership, None, outbound_config(runtime_handle), ChildRegionSpec::inherit(),
        ).await.unwrap();
        let outbound = node.client().unwrap();
        let (source, advance) = controlled();
        assert!(matches!(outbound.spawn_peer_discovery(
            NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 2,
        ), Err(NativeDistributedDiscoveryStartError::Outbound(NativeDistributedOutboundError::Membership))));
        outbound.publish_peer(NativeRemoteRoute::new(NodeId::new("worker"), hello.clone(), client.clone()), 1).unwrap();
        for peer in ["missing", "other"] {
            assert!(matches!(outbound.spawn_peer_discovery(
                NodeId::new(peer), 1, Arc::clone(&source), discovery_config(), 2,
            ), Err(NativeDistributedDiscoveryStartError::Outbound(NativeDistributedOutboundError::Membership))));
        }
        assert!(matches!(outbound.spawn_peer_discovery(
            NodeId::new("worker"), 2, Arc::clone(&source), discovery_config(), 2,
        ), Err(NativeDistributedDiscoveryStartError::Outbound(NativeDistributedOutboundError::Membership))));
        assert!(matches!(outbound.spawn_peer_discovery(
            NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 0,
        ), Err(NativeDistributedDiscoveryStartError::ZeroEndpointLimit)));
        for (config, expected) in [
            (discovery_config().with_poll_interval(Duration::ZERO), NativeRemoteDiscoveryBuildError::ZeroPollInterval),
            (discovery_config().with_retry_backoff(Duration::ZERO), NativeRemoteDiscoveryBuildError::ZeroRetryBackoff),
            (discovery_config().with_max_consecutive_failures(0), NativeRemoteDiscoveryBuildError::ZeroMaxConsecutiveFailures),
        ] {
            let error = outbound.spawn_peer_discovery(NodeId::new("worker"), 1, Arc::clone(&source), config, 2)
                .unwrap_err();
            assert!(matches!(error, NativeDistributedDiscoveryStartError::Configuration(actual) if actual == expected));
        }
        assert_eq!(source.polls.load(Ordering::Acquire), 0);
        assert_eq!(source.reads.load(Ordering::Acquire), 0);
        assert_eq!(outbound.retained_discoveries(), 0);

        let mut old = outbound.spawn_peer_discovery(
            NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 2,
        ).unwrap();
        source_entered(&cx, &source, 1).await;
        outbound.remove_peer(&NodeId::new("worker")).unwrap();
        outbound.publish_peer(NativeRemoteRoute::new(NodeId::new("other"), hello, client), 1).unwrap();
        let (fresh, fresh_advance) = controlled();
        assert!(matches!(outbound.spawn_peer_discovery(
            NodeId::new("other"), 1, Arc::clone(&fresh), discovery_config(), 2,
        ), Err(NativeDistributedDiscoveryStartError::Capacity)));
        advance.send(Step::Snapshot(vec!["127.0.0.1:9".parse().unwrap()])).unwrap();
        eventually(&cx, || old.is_finished()).await;
        assert!(matches!(outbound.spawn_peer_discovery(
            NodeId::new("other"), 1, Arc::clone(&fresh), discovery_config(), 2,
        ), Err(NativeDistributedDiscoveryStartError::Capacity)));
        assert_eq!(fresh.polls.load(Ordering::Acquire), 0);
        let terminal = join_discovery(&cx, &mut old).await;
        assert!(matches!(terminal.outcome, Some(Err(NativeRemoteDiscoveryError::DestinationRemoved { .. }))));
        assert_eq!(terminal.retirement, Ok(()));
        let mut next = outbound.spawn_peer_discovery(
            NodeId::new("other"), 1, Arc::clone(&fresh), discovery_config(), 2,
        ).unwrap();
        source_entered(&cx, &fresh, 1).await;
        next.abort();
        fresh_advance.send(Step::Snapshot(vec!["127.0.0.1:9".parse().unwrap()])).unwrap();
        let actual = stopped_report(join_discovery(&cx, &mut next).await);
        assert_eq!(actual.route_publications(), 0);
        assert_eq!(outbound.retained_discoveries(), 0);
        assert!(matches!(node.close().await.region_close, Some(Ok(()))));
    });
    finish(runtime);
}

#[test]
fn discovery_requires_owner_time_and_permitted_blocking_pool_authority() {
    for forbidden in [false, true] {
        let builder = RuntimeBuilder::current_thread();
        let runtime = if forbidden {
            builder.blocking_admission_policy(BlockingAdmissionPolicy::Forbidden).build().unwrap()
        } else { builder.blocking_threads(0, 0).build().unwrap() };
        let runtime_handle = runtime.handle();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let Fixture { service, membership, client, hello, .. } =
                fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
            membership.apply_authenticated(&NodeId::new("authority"), &statement(1)).unwrap();
            let node = NativeDistributedNode::start_with_outbound(
                &cx, service, membership, None, outbound_config(runtime_handle), ChildRegionSpec::inherit(),
            ).await.unwrap();
            let outbound = node.client().unwrap();
            outbound.publish_peer(NativeRemoteRoute::new(NodeId::new("worker"), hello, client), 1).unwrap();
            let (source, _advance) = controlled();
            assert!(matches!(outbound.spawn_peer_discovery(
                NodeId::new("worker"), 1, Arc::clone(&source), discovery_config(), 2,
            ), Err(NativeDistributedDiscoveryStartError::BlockingPoolUnavailable)));
            assert_eq!(source.polls.load(Ordering::Acquire), 0);
            assert_eq!(source.reads.load(Ordering::Acquire), 0);
            assert_eq!(outbound.retained_discoveries(), 0);
            assert!(matches!(node.close().await.region_close, Some(Ok(()))));
        });
        finish(runtime);
    }

    // A node principal without TIME is refused at startup, before a public
    // discovery client or any source task can exist.
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let runtime_handle = runtime.handle();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let Fixture { service, membership, .. } =
            fixture_protocol(&cx, RemoteProtocolVersion::V3).await;
        type NoTime = CapSet<true, false, true, true, true>;
        let restricted = {
            let _guard = Cx::push_restriction(<NoTime as CapSetRuntimeMask>::MASK);
            Cx::current().unwrap()
        };
        let error = NativeDistributedNode::start_with_outbound(
            &restricted, service, membership, None, outbound_config(runtime_handle), ChildRegionSpec::inherit(),
        ).await.unwrap_err();
        assert!(matches!(error.cause, NativeDistributedNodeStartFailure::MissingTimer));
        assert!(error.rollback.region_id.is_none());
        assert_eq!(error.rollback.outbound.unwrap().retained_discoveries, 0);
    });
    finish(runtime);
}
