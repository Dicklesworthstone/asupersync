//! Actual native admission journeys for the opt-in strict spawn policy.

use super::{Runtime, RuntimeBuilder};
use crate::cx::macaroon::{CaveatPredicate, MacaroonToken};
use crate::cx::{ChildRegionSpec, Cx, SpawnBatchError};
use crate::runtime::{JoinError, SpawnError};
use crate::security::key::AuthKey;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, Time};
use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

const MODES: [(bool, bool); 4] = [(true, false), (true, true), (false, false), (false, true)];

fn builder(current_thread: bool, sharded: bool) -> RuntimeBuilder {
    let builder = if current_thread {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(2)
    };
    builder.with_sharded_state(sharded)
}

fn token(key: &AuthKey, cx: &Cx) -> MacaroonToken {
    MacaroonToken::mint(
        key,
        &format!("spawn:region_{}", cx.region_id().as_u64()),
        "native-test",
    )
}

fn denied<T>(result: Result<T, SpawnError>) {
    assert!(matches!(
        result,
        Err(SpawnError::AuthorizationDenied { .. })
    ));
}

#[test]
fn strict_denial_precedes_ids_credits_factories_and_blocking_jobs() {
    for (current_thread, sharded) in MODES {
        let runtime = builder(current_thread, sharded)
            .require_spawn_authorization(AuthKey::from_seed(17))
            .build()
            .unwrap();
        let factories = Arc::new(AtomicUsize::new(0));
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let gateway = cx.spawn_gateway_handle().unwrap();
            let before = gateway.mailbox().allocate_task_id();
            let count = Arc::clone(&factories);
            denied(cx.spawn(move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                async { 1 }
            }));
            let count = Arc::clone(&factories);
            let batch = cx.spawn_batch([move |_: Cx| {
                count.fetch_add(1, Ordering::SeqCst);
                async { 2 }
            }]);
            assert!(matches!(
                batch,
                Err(SpawnBatchError::Spawn(
                    SpawnError::AuthorizationDenied { .. }
                ))
            ));
            let count = Arc::clone(&factories);
            denied(cx.spawn_blocking(move |_| count.fetch_add(1, Ordering::SeqCst)));
            let count = Arc::clone(&factories);
            denied(cx.spawn_blocking_drained(move |_| count.fetch_add(1, Ordering::SeqCst)));
            let scope = cx.scope();
            denied(cx.spawn_in(&scope, |_| async {}));
            {
                let mut state = runtime.inner.state.lock().unwrap();
                let before = state.live_task_count();
                denied(scope.spawn_registered(&mut state, &cx, |_| async {}));
                assert_eq!(state.live_task_count(), before);
            }
            let after = gateway.mailbox().allocate_task_id();
            assert_eq!(
                before.arena_index().generation(),
                after.arena_index().generation()
            );
            assert_eq!(
                before.arena_index().index() + 1,
                after.arena_index().index()
            );
            assert_eq!(cx.pending_spawn_counter_handle().unwrap().count(), 0);
            assert_eq!(factories.load(Ordering::SeqCst), 0);
            denied(runtime.handle().try_spawn(async {}));
            denied(runtime.handle().try_spawn_with_cx(|_| async {}));
            denied(runtime.try_spawn_local(async {}));
        });
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn authorized_children_inherit_same_region_authority_and_batch_runs() {
    for (current_thread, sharded) in MODES {
        let key = AuthKey::from_seed(29);
        let runtime = builder(current_thread, sharded)
            .require_spawn_authorization(key.clone())
            .build()
            .unwrap();
        runtime.block_on(async {
            let root = Cx::current().unwrap();
            let cx = root.clone().with_macaroon(token(&key, &root));
            let mut task = cx
                .spawn(|child| async move {
                    let ambient = Cx::current().unwrap();
                    assert_eq!(ambient.task_id(), child.task_id());
                    assert!(ambient.macaroon().is_some());
                    let mut nested = ambient.spawn(|_| async { 42_u32 }).unwrap();
                    nested.join(&child).await.unwrap()
                })
                .unwrap();
            assert_eq!(task.join(&root).await.unwrap(), 42);
            let mut handles = cx
                .spawn_batch((0..4).map(|i| move |_: Cx| async move { i }))
                .unwrap();
            let mut outputs = Vec::new();
            for task in &mut handles {
                outputs.push(task.join(&root).await.unwrap());
            }
            assert_eq!(outputs, [0, 1, 2, 3]);
            assert_eq!(cx.pending_spawn_counter_handle().unwrap().count(), 0);
        });
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn private_race_branches_keep_parent_authority_for_nested_work() {
    for (current_thread, sharded) in MODES {
        let key = AuthKey::from_seed(30);
        let runtime = builder(current_thread, sharded)
            .require_spawn_authorization(key.clone())
            .build()
            .unwrap();
        runtime.block_on(async {
            let root = Cx::current().unwrap();
            let parent_region = root.region_id();
            let grant = token(&key, &root)
                .add_caveat(CaveatPredicate::RegionScope(parent_region.as_u64()))
                .add_caveat(CaveatPredicate::ResourceScope(format!(
                    "regions/{}/spawn",
                    parent_region.as_u64()
                )));
            let cx = root.clone().with_macaroon(grant);
            let value = cx
                .race_drained_with(vec![Box::new(move |branch: Cx| {
                    Box::pin(async move {
                        assert_ne!(
                            branch.region_id(),
                            parent_region,
                            "the actual private region was minted"
                        );
                        let mut nested = branch
                            .spawn(|nested| async move {
                                let mut grandchild = nested.spawn(|_| async { 23_u32 }).unwrap();
                                grandchild.join(&nested).await.unwrap()
                            })
                            .unwrap();
                        nested.join(&branch).await.unwrap()
                    })
                })])
                .await
                .unwrap();
            assert_eq!(value, 23);
        });
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn strict_caveats_bind_runtime_clock_caller_target_resource_and_budget() {
    for (current_thread, sharded) in MODES {
        let key = AuthKey::from_seed(31);
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(100)));
        let runtime = builder(current_thread, sharded)
            .with_timer_driver(TimerDriverHandle::with_virtual_clock(clock))
            .require_spawn_authorization(key.clone())
            .build()
            .unwrap();
        runtime.block_on(async {
            let root = Cx::current().unwrap();
            let valid = token(&key, &root)
                .add_caveat(CaveatPredicate::TimeAfter(90))
                .add_caveat(CaveatPredicate::TimeBefore(200))
                .add_caveat(CaveatPredicate::RegionScope(root.region_id().as_u64()))
                .add_caveat(CaveatPredicate::TaskScope(root.task_id().as_u64()))
                .add_caveat(CaveatPredicate::ResourceScope(format!(
                    "regions/{}/spawn",
                    root.region_id().as_u64()
                )))
                .add_caveat(CaveatPredicate::Custom("operation".into(), "spawn".into()))
                .add_caveat(CaveatPredicate::Custom("poll_quota".into(), "99".into()));
            let cx = root.clone().with_macaroon(valid);
            let scope = cx.scope_with_budget(Budget::INFINITE.with_poll_quota(99));
            let mut task = cx
                .spawn_in(&scope, |child| async move {
                    // The token is inherited, but its original caller-task caveat
                    // cannot authorize this different task's next generation.
                    denied(child.spawn(|_| async {}));
                    7
                })
                .unwrap();
            assert_eq!(task.join(&root).await.unwrap(), 7);
            denied(cx.spawn(|_| async {})); // wrong requested poll quota

            for predicate in [
                CaveatPredicate::TimeBefore(99),
                CaveatPredicate::TimeAfter(101),
                CaveatPredicate::RegionScope(root.region_id().as_u64().wrapping_add(1)),
                CaveatPredicate::TaskScope(root.task_id().as_u64().wrapping_add(1)),
                CaveatPredicate::ResourceScope("regions/another/spawn".into()),
                CaveatPredicate::Custom("operation".into(), "read".into()),
                CaveatPredicate::MaxUses(1),
                CaveatPredicate::RateLimit {
                    max_count: 1,
                    window_secs: 1,
                },
                CaveatPredicate::Custom("unknown".into(), "value".into()),
            ] {
                let denied_cx = root
                    .clone()
                    .with_macaroon(token(&key, &root).add_caveat(predicate));
                denied(denied_cx.spawn(|_| async {}));
            }
            let wrong_key = root
                .clone()
                .with_macaroon(token(&AuthKey::from_seed(32), &root));
            denied(wrong_key.spawn(|_| async {}));
            let wrong_target = root.clone().with_macaroon(MacaroonToken::mint(
                &key,
                "another-operation",
                "native-test",
            ));
            denied(wrong_target.spawn(|_| async {}));
            let discharge_required =
                root.clone()
                    .with_macaroon(token(&key, &root).add_third_party_caveat(
                        "issuer",
                        "approval",
                        &AuthKey::from_seed(33),
                    ));
            denied(discharge_required.spawn(|_| async {}));
        });
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn a_child_region_requires_its_own_capability_and_real_finalizers_still_run() {
    for (current_thread, sharded) in MODES {
        let key = AuthKey::from_seed(41);
        let runtime = builder(current_thread, sharded)
            .require_spawn_authorization(key.clone())
            .build()
            .unwrap();
        let finalized = Arc::new(AtomicUsize::new(0));
        runtime.block_on(async {
            let root = Cx::current().unwrap();
            let parent = root.clone().with_macaroon(token(&key, &root));
            let child = parent
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let region_cx = child.cx();
            denied(region_cx.spawn(|_| async {}));
            let authorized = region_cx.clone().with_macaroon(token(&key, region_cx));
            let mut task = authorized.spawn(|_| async { 12 }).unwrap();
            assert_eq!(task.join(&root).await.unwrap(), 12);
            let finalized = Arc::clone(&finalized);
            assert!(
                runtime
                    .inner
                    .state
                    .lock()
                    .unwrap()
                    .register_async_finalizer(child.region_id(), async move {
                        let cleanup = Cx::current().expect("real finalizer context");
                        assert!(cleanup.inner.read().budget_deadline_exempt);
                        // Cleanup infrastructure does not manufacture caller authority.
                        denied(cleanup.spawn(|_| async {}));
                        finalized.fetch_add(1, Ordering::SeqCst);
                    })
            );
            child.close().await.unwrap();
        });
        assert_eq!(finalized.load(Ordering::SeqCst), 1);
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn local_spawns_require_authority_and_preserve_non_send_capture() {
    for sharded in [false, true] {
        let key = AuthKey::from_seed(51);
        let runtime = builder(true, sharded)
            .require_spawn_authorization(key.clone())
            .build()
            .unwrap();
        runtime.block_on(async {
            let root = Cx::current().unwrap();
            denied(root.spawn_local(|_| async {}));
            let cx = root.clone().with_macaroon(token(&key, &root));
            let value = Rc::new(Cell::new(0));
            let capture = Rc::clone(&value);
            let mut task = cx
                .spawn_local(move |_| async move {
                    capture.set(19);
                    19
                })
                .unwrap();
            assert_eq!(task.join(&root).await.unwrap(), 19);
            assert_eq!(value.get(), 19);
        });
        assert!(runtime.is_quiescent());
    }
}

#[test]
fn queued_send_and_local_spawns_recheck_expiry_before_factory_or_task_mint() {
    for sharded in [false, true] {
        for local in [false, true] {
            let key = AuthKey::from_seed(61);
            let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(100)));
            let runtime = builder(true, sharded)
                .with_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)))
                .require_spawn_authorization(key.clone())
                .build()
                .unwrap();
            let factories = Arc::new(AtomicUsize::new(0));
            runtime.block_on(async {
                let root = Cx::current().unwrap();
                let cx = root
                    .clone()
                    .with_macaroon(token(&key, &root).add_caveat(CaveatPredicate::TimeBefore(101)));
                let count = Arc::clone(&factories);
                let factory = move |_: Cx| {
                    count.fetch_add(1, Ordering::SeqCst);
                    async { 1 }
                };
                let mut task = if local {
                    cx.spawn_local(factory)
                } else {
                    cx.spawn(factory)
                }
                .unwrap();
                assert_eq!(
                    cx.pending_spawn_counter_handle().unwrap().count(),
                    1,
                    "caller still owns the only worker, so the request is queued"
                );
                clock.advance_to(Time::from_millis(102));
                let Err(JoinError::Cancelled(reason)) = task.join(&root).await else {
                    panic!("expired queued request must fail admission");
                };
                assert!(
                    reason
                        .message
                        .as_deref()
                        .is_some_and(|message| message.contains("authorization denied"))
                );
                assert_eq!(factories.load(Ordering::SeqCst), 0);
                assert_eq!(cx.pending_spawn_counter_handle().unwrap().count(), 0);
            });
            assert!(runtime.is_quiescent());
        }
    }
}

#[test]
fn legacy_key_setting_and_explicit_disable_preserve_existing_spawns() {
    let key = AuthKey::from_seed(71);
    for builder in [
        RuntimeBuilder::current_thread().with_spawn_authorization_key(key.clone()),
        RuntimeBuilder::current_thread()
            .require_spawn_authorization(key.clone())
            .disable_spawn_authorization(),
    ] {
        let runtime = builder.build().unwrap();
        runtime.block_on(async {
            let root = Cx::current().unwrap();
            let mut task = root.spawn(|_| async { 5 }).unwrap();
            assert_eq!(task.join(&root).await.unwrap(), 5);
            assert_eq!(runtime.handle().try_spawn(async { 6 }).unwrap().await, 6);
        });
        assert!(runtime.is_quiescent());
    }
    // Legacy configuration does not silently replace the separately selected
    // strict key; the last explicit strict selection wins.
    let final_key = AuthKey::from_seed(73);
    let runtime = RuntimeBuilder::current_thread()
        .require_spawn_authorization(AuthKey::from_seed(72))
        .require_spawn_authorization(final_key.clone())
        .with_spawn_authorization_key(key.clone())
        .build()
        .unwrap();
    runtime.block_on(async {
        let root = Cx::current().unwrap();
        denied(
            root.clone()
                .with_macaroon(token(&key, &root))
                .spawn(|_| async {}),
        );
        let authorized = root.clone().with_macaroon(token(&final_key, &root));
        let mut task = authorized.spawn(|_| async { 8 }).unwrap();
        assert_eq!(task.join(&root).await.unwrap(), 8);
    });
    assert!(runtime.is_quiescent());
}

#[test]
fn strict_policy_is_installed_before_native_thread_start_callbacks() {
    let (results_tx, results_rx) = mpsc::channel();
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .blocking_threads(0, 0)
        .require_spawn_authorization(AuthKey::from_seed(81))
        .on_thread_start(move || {
            let handle =
                Runtime::current_handle().expect("worker installs runtime handle before hook");
            results_tx
                .send(matches!(
                    handle.try_spawn(async {}),
                    Err(SpawnError::AuthorizationDenied { .. })
                ))
                .unwrap();
        })
        .build()
        .unwrap();
    for _ in 0..2 {
        assert!(
            results_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "on_thread_start must not observe an unprotected runtime"
        );
    }
    assert!(runtime.is_quiescent());
}
