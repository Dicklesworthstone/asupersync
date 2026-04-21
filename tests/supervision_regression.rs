#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

use asupersync::actor::Actor;
use asupersync::cx::Cx;
use asupersync::supervision::{
    BackoffStrategy, RestartConfig, RestartTracker, RestartTrackerConfig, StormMonitorConfig,
};
use asupersync::types::Budget;
use asupersync::types::policy::FailFast;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

#[test]
fn test_backoff_handles_invalid_multiplier() {
    // Negative multiplier should fallback to safe default (2.0) or handle gracefully
    let backoff = BackoffStrategy::Exponential {
        initial: Duration::from_millis(100),
        max: Duration::from_secs(10),
        multiplier: -5.0,
    };
    // Should not panic
    let delay = backoff.delay_for_attempt(1);
    assert!(delay.is_some());

    // NaN multiplier
    let backoff = BackoffStrategy::Exponential {
        initial: Duration::from_millis(100),
        max: Duration::from_secs(10),
        multiplier: f64::NAN,
    };
    // Should not panic
    let delay = backoff.delay_for_attempt(1);
    assert!(delay.is_some());

    // Infinite multiplier
    let backoff = BackoffStrategy::Exponential {
        initial: Duration::from_millis(100),
        max: Duration::from_secs(10),
        multiplier: f64::INFINITY,
    };
    // Should cap at max or fallback
    let delay = backoff.delay_for_attempt(10).unwrap();
    assert!(delay <= Duration::from_secs(10));
}

#[test]
fn supervised_actor_panic_restarts_under_restart_strategy() {
    #[derive(Debug)]
    struct PanicOnMessage {
        handled: u32,
        final_handled: Arc<AtomicU32>,
    }

    impl Actor for PanicOnMessage {
        type Message = u32;

        fn handle(&mut self, _cx: &Cx, msg: u32) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            assert!(msg != 999, "intentional supervision regression panic");
            self.handled += msg;
            Box::pin(async {})
        }

        fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.final_handled.store(self.handled, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    let mut runtime = asupersync::lab::LabRuntime::new(asupersync::lab::LabConfig::default());
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let cx = Cx::for_testing();
    let scope = asupersync::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

    let factory_calls = Arc::new(AtomicU32::new(0));
    let factory_calls_for_actor = Arc::clone(&factory_calls);
    let final_handled = Arc::new(AtomicU32::new(u32::MAX));
    let final_handled_for_actor = Arc::clone(&final_handled);
    let strategy = asupersync::supervision::SupervisionStrategy::Restart(
        asupersync::supervision::RestartConfig::new(3, Duration::from_secs(60))
            .with_backoff(asupersync::supervision::BackoffStrategy::None),
    );

    let (mut handle, stored) = scope
        .spawn_supervised_actor(
            &mut runtime.state,
            &cx,
            move || {
                factory_calls_for_actor.fetch_add(1, Ordering::SeqCst);
                PanicOnMessage {
                    handled: 0,
                    final_handled: Arc::clone(&final_handled_for_actor),
                }
            },
            strategy,
            8,
        )
        .expect("spawn supervised actor");
    let task_id = handle.task_id();
    runtime.state.store_spawned_task(task_id, stored);

    handle.try_send(999).expect("enqueue panic message");
    handle.try_send(1).expect("enqueue post-restart message");
    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_until_idle();
    handle.abort();
    runtime.run_until_quiescent();

    let join = futures_lite::future::block_on(handle.join(&cx));
    let actor = join.expect("aborting the restarted actor should still return final state");
    assert_eq!(
        factory_calls.load(Ordering::SeqCst),
        2,
        "panic must trigger exactly one supervised restart"
    );
    assert_eq!(
        actor.handled, 1,
        "restarted actor should keep the queued post-crash work"
    );
    assert_eq!(
        final_handled.load(Ordering::SeqCst),
        1,
        "restarted actor should handle queued work before abort"
    );
}

#[test]
fn explicit_storm_monitor_rate_is_preserved_across_builder_order() {
    let explicit_monitor = StormMonitorConfig {
        alpha: 0.01,
        expected_rate: StormMonitorConfig::default().expected_rate,
        min_observations: 1,
        tolerance: 1.2,
    };

    let build_tracker = |threshold_first: bool| {
        let config = if threshold_first {
            RestartTrackerConfig::from_restart(RestartConfig::new(10, Duration::from_secs(10)))
                .with_storm_detection(2.0)
                .with_storm_monitor(explicit_monitor)
        } else {
            RestartTrackerConfig::from_restart(RestartConfig::new(10, Duration::from_secs(10)))
                .with_storm_monitor(explicit_monitor)
                .with_storm_detection(2.0)
        };
        let mut tracker = RestartTracker::new(config);
        tracker.record(0);
        tracker
            .storm_snapshot()
            .expect("storm monitor enabled")
            .e_value
    };

    let threshold_then_monitor = build_tracker(true);
    let monitor_then_threshold = build_tracker(false);

    assert!(
        threshold_then_monitor > 1.0,
        "explicit expected_rate must not be overwritten by threshold inference"
    );
    assert!(
        (threshold_then_monitor - monitor_then_threshold).abs() < f64::EPSILON,
        "builder order must not change explicit storm monitor behavior"
    );
}
