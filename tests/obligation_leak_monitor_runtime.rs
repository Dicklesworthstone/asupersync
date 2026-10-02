//! The runtime feeds an opt-in obligation leak monitor (a change detector)
//! one observation per resolved obligation (br-asupersync-bi2462.150.2).
//!
//! Each committed or aborted obligation counts exactly once, at its age when
//! it resolves; a leaked obligation counts once, as conclusive evidence. The
//! lab tests control ages through virtual time; the native test goes through
//! the public checked-obligation API.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::obligation::eprocess::{AlertState, MonitorConfig};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::config::ObligationLeakResponse;
use asupersync::types::Budget;
use std::time::{Duration, Instant};

/// 1 ms expected lifetime; an alert needs at least three observations.
const FAST: MonitorConfig = MonitorConfig {
    alpha: 0.01,
    expected_lifetime_ns: 1_000_000,
    min_observations: 3,
};

/// Detector horizon: a false alarm within 10^6 resolutions has probability
/// at most alpha, and the threshold is 10^6 / 0.01 = 10^8.
const HORIZON: u64 = 1_000_000;

fn log(case: &str, detail: String) {
    eprintln!(
        "{}",
        serde_json::json!({"bead": "asupersync-bi2462.150.2", "case": case, "detail": detail})
    );
}

#[test]
fn lab_monitor_is_off_until_enabled() {
    let mut lab = LabRuntime::new(LabConfig::new(1));
    assert!(lab.state.obligation_leak_monitor_snapshot().is_none());
    lab.state.enable_obligation_leak_monitor(FAST, HORIZON);
    let snapshot = lab
        .state
        .obligation_leak_monitor_snapshot()
        .expect("enabled monitor");
    assert_eq!(snapshot.observations, 0);
    assert_eq!(snapshot.alert_state, AlertState::Clear);
}

#[test]
fn lab_monitor_counts_each_resolution_once_and_stays_clear_for_fast_obligations() {
    let mut lab = LabRuntime::new(LabConfig::new(2));
    let region = lab.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create holder task");
    // Resolved before the monitor exists: not observed.
    let early = lab
        .state
        .create_obligation(ObligationKind::Ack, task, region, None)
        .expect("reserve early obligation");
    lab.state.commit_obligation(early).expect("commit early");

    lab.state.enable_obligation_leak_monitor(FAST, HORIZON);
    let obligations: Vec<_> = (0..20)
        .map(|_| {
            lab.state
                .create_obligation(ObligationKind::SendPermit, task, region, None)
                .expect("reserve obligation")
        })
        .collect();
    // 10 us of virtual time, far inside the 1 ms expected lifetime.
    lab.advance_time(10_000);
    for (index, obligation) in obligations.iter().enumerate() {
        if index % 2 == 0 {
            lab.state
                .commit_obligation(*obligation)
                .expect("commit obligation");
        } else {
            lab.state
                .abort_obligation(*obligation, ObligationAbortReason::Explicit)
                .expect("abort obligation");
        }
    }
    let snapshot = lab
        .state
        .obligation_leak_monitor_snapshot()
        .expect("enabled monitor");
    log("fast", format!("{snapshot:?}"));
    assert_eq!(snapshot.observations, 20, "one observation per resolution");
    assert_eq!(snapshot.alert_state, AlertState::Clear);
    // The runtime's change detector stays at or below e, its fixed point for
    // on-time ages, however many fast obligations it sees.
    assert!(
        snapshot.e_value <= std::f64::consts::E,
        "fast obligations add no evidence: {}",
        snapshot.e_value
    );
    assert_eq!(snapshot.alert_count, 0);
}

/// Many on-time resolutions must not bury the evidence of a later slowdown.
/// A plain e-process fed 200 fast obligations needs about eleven obligations
/// held 1 s against 1 ms before it alarms; the runtime's change detector, at
/// a 10^8 threshold, alarms on the third, and the alarm latches through later
/// fast ones.
#[test]
fn lab_monitor_detects_a_slowdown_after_many_healthy_resolutions() {
    let mut lab = LabRuntime::new(LabConfig::new(5));
    lab.state.enable_obligation_leak_monitor(FAST, HORIZON);
    let region = lab.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create holder task");
    let resolve = |lab: &mut LabRuntime, hold_ns: u64, count: usize| {
        let obligations: Vec<_> = (0..count)
            .map(|_| {
                lab.state
                    .create_obligation(ObligationKind::SendPermit, task, region, None)
                    .expect("reserve obligation")
            })
            .collect();
        lab.advance_time(hold_ns);
        for obligation in obligations {
            lab.state
                .commit_obligation(obligation)
                .expect("commit obligation");
        }
    };
    resolve(&mut lab, 10_000, 200);
    let healthy = lab
        .state
        .obligation_leak_monitor_snapshot()
        .expect("enabled monitor");
    assert_eq!(healthy.alert_state, AlertState::Clear);
    resolve(&mut lab, 1_000_000_000, 2);
    let two_slow = lab
        .state
        .obligation_leak_monitor_snapshot()
        .expect("enabled monitor");
    assert_eq!(two_slow.alert_state, AlertState::Clear, "{two_slow:?}");
    resolve(&mut lab, 1_000_000_000, 1);
    let slow = lab
        .state
        .obligation_leak_monitor_snapshot()
        .expect("enabled monitor");
    log("slowdown", format!("healthy={healthy:?} slow={slow:?}"));
    assert_eq!(slow.observations, 203);
    assert_eq!(slow.alert_state, AlertState::Alert, "{slow:?}");
    resolve(&mut lab, 10_000, 50);
    let after = lab
        .state
        .obligation_leak_monitor_snapshot()
        .expect("enabled monitor");
    assert_eq!(after.alert_state, AlertState::Alert, "the alarm latches");
    assert_eq!(after.alert_count, 1);
}

#[test]
fn lab_monitor_alerts_when_obligations_outlive_their_expected_lifetime() {
    let mut lab = LabRuntime::new(LabConfig::new(3));
    lab.state.enable_obligation_leak_monitor(FAST, HORIZON);
    let region = lab.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create holder task");
    let obligations: Vec<_> = (0..3)
        .map(|_| {
            lab.state
                .create_obligation(ObligationKind::Lease, task, region, None)
                .expect("reserve obligation")
        })
        .collect();
    // Held 1 s of virtual time against a 1 ms expected lifetime.
    lab.advance_time(1_000_000_000);
    for (index, obligation) in obligations.iter().enumerate() {
        lab.state
            .commit_obligation(*obligation)
            .expect("commit obligation");
        let snapshot = lab
            .state
            .obligation_leak_monitor_snapshot()
            .expect("enabled monitor");
        log("slow", format!("after {} commits: {snapshot:?}", index + 1));
        if index + 1 < 3 {
            assert_ne!(
                snapshot.alert_state,
                AlertState::Alert,
                "no alert before the minimum observation count"
            );
        }
    }
    let snapshot = lab
        .state
        .obligation_leak_monitor_snapshot()
        .expect("enabled monitor");
    assert_eq!(snapshot.observations, 3);
    assert_eq!(snapshot.alert_state, AlertState::Alert);
    assert_eq!(snapshot.alert_count, 1);
}

/// A leak is conclusive evidence, not an age: an obligation leaked right after
/// it was reserved used to read as an on-time resolution and lower the
/// e-value.
#[test]
fn lab_monitor_alarms_on_a_leaked_obligation_and_counts_it_once() {
    let mut lab = LabRuntime::new(LabConfig::new(4).panic_on_leak(false));
    lab.state.enable_obligation_leak_monitor(FAST, HORIZON);
    let region = lab.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create holder task");
    lab.state
        .create_obligation(ObligationKind::IoOp, task, region, None)
        .expect("reserve obligation");
    lab.scheduler.lock().schedule(task, 0);
    // The holder completes normally while still holding the obligation.
    lab.run_until_quiescent();
    let snapshot = lab
        .state
        .obligation_leak_monitor_snapshot()
        .expect("enabled monitor");
    log(
        "leak",
        format!("leak_count={} {snapshot:?}", lab.state.leak_count()),
    );
    assert_eq!(lab.state.leak_count(), 1);
    assert_eq!(snapshot.observations, 1, "a leak is observed exactly once");
    assert_eq!(
        snapshot.alert_state,
        AlertState::Alert,
        "one leak alarms, before min_observations"
    );
    assert!(snapshot.e_value.is_infinite(), "{snapshot:?}");
    assert_eq!(snapshot.alert_count, 1);
}

/// Under the `Recover` policy a leaked obligation is aborted for cleanup, but
/// it is still a leak to the monitor. Its abort used to feed the monitor the
/// leak's age instead (here 0 ns, an on-time resolution), and the monitor
/// stayed clear.
#[test]
fn lab_monitor_alarms_on_a_leak_the_recover_policy_aborts() {
    let mut lab = LabRuntime::new(LabConfig::new(6).panic_on_leak(false));
    lab.state
        .set_obligation_leak_response(ObligationLeakResponse::Recover);
    lab.state.enable_obligation_leak_monitor(FAST, HORIZON);
    let region = lab.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create holder task");
    lab.state
        .create_obligation(ObligationKind::IoOp, task, region, None)
        .expect("reserve obligation");
    lab.scheduler.lock().schedule(task, 0);
    // The holder completes normally while still holding the obligation.
    lab.run_until_quiescent();
    let snapshot = lab
        .state
        .obligation_leak_monitor_snapshot()
        .expect("enabled monitor");
    log(
        "recovered-leak",
        format!("leak_count={} {snapshot:?}", lab.state.leak_count()),
    );
    assert_eq!(lab.state.leak_count(), 1);
    assert_eq!(
        snapshot.observations, 1,
        "a recovered leak is observed once"
    );
    assert_eq!(snapshot.alert_state, AlertState::Alert, "{snapshot:?}");
    assert!(snapshot.e_value.is_infinite(), "{snapshot:?}");
    assert_eq!(snapshot.alert_count, 1);
}

#[test]
fn native_runtime_monitor_observes_checked_obligations() {
    let runtime = RuntimeBuilder::new().worker_threads(1).build().unwrap();
    assert!(runtime.obligation_leak_monitor_snapshot().is_none());
    // A 10 s expected lifetime: these obligations resolve far faster.
    runtime.enable_obligation_leak_monitor(
        MonitorConfig {
            alpha: 0.01,
            expected_lifetime_ns: 10_000_000_000,
            min_observations: 3,
        },
        HORIZON,
    );
    let join = runtime.handle().spawn(async {
        let cx = Cx::current().expect("admitted task context");
        let holder = cx.task_id();
        for index in 0..4 {
            let token = cx
                .try_register_obligation_checked(ObligationKind::Ack, holder)
                .expect("admit checked obligation")
                .expect("native context tracks the obligation");
            if index % 2 == 0 {
                assert!(token.commit());
            } else {
                assert!(token.abort(ObligationAbortReason::Explicit));
            }
        }
    });
    runtime.block_on(join);
    // The runtime applies obligation posts from its mailbox; wait, bounded,
    // until all four resolutions have reached the monitor.
    let deadline = Instant::now() + Duration::from_secs(10);
    let snapshot = loop {
        let snapshot = runtime
            .obligation_leak_monitor_snapshot()
            .expect("enabled monitor");
        if snapshot.observations >= 4 || Instant::now() >= deadline {
            break snapshot;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    log("native", format!("{snapshot:?}"));
    assert_eq!(snapshot.observations, 4, "one observation per resolution");
    assert_eq!(snapshot.alert_state, AlertState::Clear);
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
}
