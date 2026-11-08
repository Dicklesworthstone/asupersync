#![forbid(unsafe_code)]
//! Observe public scoped-timeout retirement without assuming that `block_on`
//! synchronously drains every worker-side cancellation callback.

use asupersync::Cx;
use asupersync::cx::macaroon::{CaveatPredicate, MacaroonToken};
use asupersync::cx::{ScopedTimeoutError, ScopedTimeoutStop, ScopedTimeoutTask};
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::state::SpawnError;
use asupersync::security::key::AuthKey;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::Time;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const TRIALS: usize = 100;
const RETIREMENT_WATCHDOG: Duration = Duration::from_secs(5);

fn observe_retirement(current_thread: bool, sharded: bool) {
    let mut initially_nonquiescent = 0;
    let mut longest_observation = Duration::ZERO;
    for trial in 0..TRIALS {
        let key = AuthKey::from_seed(121);
        let builder = if current_thread {
            RuntimeBuilder::current_thread()
        } else {
            RuntimeBuilder::multi_thread().worker_threads(2)
        };
        let runtime = builder
            .with_sharded_state(sharded)
            .with_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
                VirtualClock::starting_at(Time::from_millis(100)),
            )))
            .require_spawn_authorization(key.clone())
            .build()
            .unwrap();
        let denied_factories = Arc::new(AtomicUsize::new(0));
        runtime.block_on(async {
            let root = Cx::current().unwrap();
            let parent = root.region_id();
            let mint = |key: &AuthKey| {
                MacaroonToken::mint(
                    key,
                    &format!("spawn:region_{}", parent.as_u64()),
                    "scoped-timeout-retirement",
                )
            };
            for denied in [
                root.clone(),
                root.clone().with_macaroon(mint(&AuthKey::from_seed(122))),
                root.clone()
                    .with_macaroon(mint(&key).add_caveat(CaveatPredicate::TimeBefore(99))),
            ] {
                let factories = Arc::clone(&denied_factories);
                let result = denied
                    .timeout_scoped(Duration::from_secs(60), move |_| {
                        factories.fetch_add(1, Ordering::SeqCst);
                        async { 0_u32 }
                    })
                    .await;
                assert!(matches!(
                    result,
                    Err(ScopedTimeoutError::Spawn(
                        SpawnError::AuthorizationDenied { .. }
                    ))
                ));
            }
            let grant = mint(&key)
                .add_caveat(CaveatPredicate::RegionScope(parent.as_u64()))
                .add_caveat(CaveatPredicate::ResourceScope(format!(
                    "regions/{}/spawn",
                    parent.as_u64()
                )));
            let owner = root.with_macaroon(grant);
            let report = owner
                .timeout_scoped(Duration::from_secs(60), move |body| async move {
                    assert_ne!(body.region_id(), parent);
                    let mut child = body
                        .spawn(|child| async move {
                            let mut grandchild = child.spawn(|_| async { 42_u32 }).unwrap();
                            grandchild.join(&child).await.unwrap()
                        })
                        .unwrap();
                    child.join(&body).await.unwrap()
                })
                .await
                .unwrap();
            assert!(matches!(report.stop, ScopedTimeoutStop::TaskFinished));
            assert!(matches!(report.task, ScopedTimeoutTask::Joined(Ok(42))));
            assert!(report.close.unwrap().is_ok());
        });
        assert_eq!(denied_factories.load(Ordering::SeqCst), 0);

        let started = Instant::now();
        let immediate = runtime.is_quiescent();
        if !immediate {
            initially_nonquiescent += 1;
            if initially_nonquiescent <= 3 {
                eprintln!(
                    "SCOPED_TIMEOUT_RETIREMENT_PENDING current_thread={current_thread} \
                     sharded={sharded} trial={trial} quiescent_now={} active={:?} \
                     obligations={:?} confirmed_leaks={:?} draining_regions={}",
                    runtime.is_quiescent(),
                    runtime
                        .task_inspector(Default::default())
                        .list_active_tasks(),
                    runtime.diagnostics().find_leaked_obligations(),
                    runtime.diagnostics().find_confirmed_obligation_leaks(),
                    runtime.draining_region_count(),
                );
            }
        }
        // Observation only: do not cancel, close the root, shut down, advance
        // virtual time, or drive additional runtime work to make this settle.
        while !runtime.is_quiescent() {
            assert!(
                started.elapsed() < RETIREMENT_WATCHDOG,
                "retirement leaked: current_thread={current_thread} sharded={sharded} trial={trial} \
                 quiescent_now={} active={:?} obligations={:?} confirmed_leaks={:?} \
                 draining_regions={}",
                runtime.is_quiescent(),
                runtime
                    .task_inspector(Default::default())
                    .list_active_tasks(),
                runtime.diagnostics().find_leaked_obligations(),
                runtime.diagnostics().find_confirmed_obligation_leaks(),
                runtime.draining_region_count(),
            );
            std::thread::yield_now();
        }
        // Includes the bounded diagnostic snapshots: this is an observation
        // duration, not an uncontaminated worker-retirement latency estimate.
        longest_observation = longest_observation.max(started.elapsed());
        assert!(runtime.is_quiescent());
        assert!(
            runtime
                .task_inspector(Default::default())
                .list_active_tasks()
                .is_empty()
        );
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(
            runtime
                .diagnostics()
                .find_confirmed_obligation_leaks()
                .is_empty()
        );
        assert_eq!(runtime.draining_region_count(), 0);
        assert_eq!(denied_factories.load(Ordering::SeqCst), 0);
    }
    eprintln!(
        "SCOPED_TIMEOUT_RETIREMENT current_thread={current_thread} sharded={sharded} \
         trials={TRIALS} initially_nonquiescent={initially_nonquiescent} \
         longest_observation_ns={}",
        longest_observation.as_nanos(),
    );
}

#[test]
fn current_thread_embedded_retirement() {
    observe_retirement(true, false);
}

#[test]
fn current_thread_sharded_retirement() {
    observe_retirement(true, true);
}

#[test]
fn multi_thread_embedded_retirement() {
    observe_retirement(false, false);
}

#[test]
fn multi_thread_sharded_retirement() {
    observe_retirement(false, true);
}
