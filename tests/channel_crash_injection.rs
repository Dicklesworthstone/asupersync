#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
//! Channel crash/restart fault injection integration tests (bd-2ktrc.3).
//!
//! Validates the `CrashController` and `CrashSender` wrapper under
//! crash/restart scenarios. Pass criteria:
//!
//! 1. **Crash blocks delivery**: Messages sent after a crash return
//!    `SendError::Disconnected`.
//! 2. **Restart re-enables delivery**: After restart, messages flow normally.
//! 3. **Cold restart resets state**: Send count and send stats reset atomically.
//! 4. **Warm restart preserves state**: Send count and send stats are preserved.
//! 5. **Restart exhaustion**: After max restarts, controller is permanently
//!    exhausted and refuses further restarts.
//! 6. **Deterministic crash after N sends**: Crash triggers at exact send count.
//! 7. **Probabilistic crash**: Crash triggered by RNG with correct seed
//!    determinism.
//! 8. **Evidence logging**: All crash/restart events are logged.
//! 9. **Stats tracking**: All operations are counted accurately.
//! 10. **Two-phase commit safety**: Crash after reserve aborts cleanly.

use asupersync::channel::crash::{
    CrashConfig, CrashSender, CrashStatsSnapshot, RestartMode, crash_channel,
};
use asupersync::channel::mpsc;
use asupersync::evidence_sink::{CollectorSink, EvidenceSink};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

fn test_cx() -> asupersync::cx::Cx {
    asupersync::Cx::for_testing()
}

fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut pinned = Box::pin(f);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn make_crash_channel(
    config: CrashConfig,
) -> (
    CrashSender<u32>,
    mpsc::Receiver<u32>,
    Arc<asupersync::channel::crash::CrashController>,
    Arc<CollectorSink>,
) {
    let collector = Arc::new(CollectorSink::new());
    let sink: Arc<dyn EvidenceSink> = collector.clone();
    let (tx, rx, ctrl) = crash_channel::<u32>(16, config, sink);
    (tx, rx, ctrl, collector)
}

// ---------------------------------------------------------------------------
// Criterion 1: Crash blocks delivery
// ---------------------------------------------------------------------------

#[test]
fn crash_blocks_all_messages() {
    let config = CrashConfig::new(42);
    let (tx, mut rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    // Send before crash — should arrive.
    block_on(tx.send(&cx, 1)).unwrap();
    assert_eq!(rx.try_recv().unwrap(), 1);

    // Crash the actor.
    ctrl.crash();

    // All subsequent sends should fail.
    for i in 2..12 {
        let err = block_on(tx.send(&cx, i));
        assert!(err.is_err(), "Expected Disconnected for message {i}");
    }

    // No messages should have arrived after crash.
    assert!(rx.is_empty());
}

#[test]
fn crash_returns_value_in_error() {
    let config = CrashConfig::new(42);
    let (tx, _rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    ctrl.crash();
    let err = block_on(tx.send(&cx, 42)).unwrap_err();
    match err {
        mpsc::SendError::Disconnected(v) => assert_eq!(v, 42),
        other => panic!("Expected Disconnected, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Criterion 2: Restart re-enables delivery
// ---------------------------------------------------------------------------

#[test]
fn restart_allows_new_messages() {
    let config = CrashConfig::new(42);
    let (tx, mut rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    // Pre-crash send.
    block_on(tx.send(&cx, 1)).unwrap();

    // Crash + restart.
    ctrl.crash();
    assert!(block_on(tx.send(&cx, 99)).is_err());
    ctrl.restart();

    // Post-restart send.
    block_on(tx.send(&cx, 2)).unwrap();

    assert_eq!(rx.try_recv().unwrap(), 1);
    assert_eq!(rx.try_recv().unwrap(), 2);
}

#[test]
fn multiple_crash_restart_cycles() {
    let config = CrashConfig::new(42);
    let (tx, mut rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    for cycle in 0..5 {
        block_on(tx.send(&cx, cycle * 10)).unwrap();
        ctrl.crash();
        assert!(block_on(tx.send(&cx, cycle * 10 + 1)).is_err());
        ctrl.restart();
        block_on(tx.send(&cx, cycle * 10 + 2)).unwrap();
    }

    // Verify all successful sends arrived in order.
    let mut received = Vec::new();
    while let Ok(v) = rx.try_recv() {
        received.push(v);
    }
    assert_eq!(received, vec![0, 2, 10, 12, 20, 22, 30, 32, 40, 42]);
}

// ---------------------------------------------------------------------------
// Criterion 3: Cold restart resets state
// ---------------------------------------------------------------------------

#[test]
fn cold_restart_resets_send_counter() {
    let config = CrashConfig::new(42)
        .with_crash_after_sends(3)
        .with_restart_mode(RestartMode::Cold);
    let (tx, mut rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    // 3 successful sends, then crash on 4th.
    for i in 0..3 {
        block_on(tx.send(&cx, i)).unwrap();
    }
    assert!(block_on(tx.send(&cx, 3)).is_err());
    assert!(ctrl.is_crashed());

    // Cold restart completes its own counter reset.
    assert!(ctrl.restart());
    assert_eq!(tx.send_count(), 0);
    let restarted = ctrl.stats().snapshot();
    assert_eq!(restarted.sends_attempted, 0);
    assert_eq!(restarted.sends_succeeded, 0);
    assert_eq!(restarted.sends_rejected, 0);
    assert_eq!(restarted.crashes, 1);
    assert_eq!(restarted.restarts, 1);

    // Should be able to send 3 more before crash.
    for i in 100..103 {
        block_on(tx.send(&cx, i)).unwrap();
    }
    assert!(block_on(tx.send(&cx, 103)).is_err());

    // Verify all 6 successful messages arrived.
    let mut received = Vec::new();
    while let Ok(v) = rx.try_recv() {
        received.push(v);
    }
    assert_eq!(received, vec![0, 1, 2, 100, 101, 102]);
}

// ---------------------------------------------------------------------------
// Criterion 4: Warm restart preserves state
// ---------------------------------------------------------------------------

#[test]
fn warm_restart_keeps_send_counter() {
    let config = CrashConfig::new(42)
        .with_crash_after_sends(3)
        .with_restart_mode(RestartMode::Warm);
    let (tx, _rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    // 3 successful sends, then crash.
    for i in 0..3 {
        block_on(tx.send(&cx, i)).unwrap();
    }
    assert!(block_on(tx.send(&cx, 3)).is_err());
    let before_restart = ctrl.stats().snapshot();

    // Warm restart: counter preserved at 3, so immediate crash on next send.
    assert!(ctrl.restart());
    assert_eq!(tx.send_count(), 3);
    assert_eq!(
        ctrl.stats().snapshot(),
        CrashStatsSnapshot {
            restarts: before_restart.restarts + 1,
            ..before_restart
        }
    );
    assert!(block_on(tx.send(&cx, 4)).is_err());
    assert!(ctrl.is_crashed());
}

fn pending_send_across_restart(mode: RestartMode) {
    let config = CrashConfig::new(42).with_restart_mode(mode);
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let (sender1, mut rx, ctrl) = crash_channel::<u32>(1, config.clone(), sink.clone());
    let sender2 = CrashSender::new(sender1.inner().clone(), ctrl.clone(), config, sink);
    let cx = test_cx();

    block_on(sender1.send(&cx, 10)).unwrap();
    assert_eq!(sender2.send_count(), 1);
    let mut stale_send = Box::pin(sender1.send(&cx, 20));
    let mut task_cx = Context::from_waker(Waker::noop());
    assert!(stale_send.as_mut().poll(&mut task_cx).is_pending());
    assert_eq!(ctrl.stats().snapshot().sends_attempted, 2);

    // The first incarnation has a committed value and an observed pending
    // send. Restart must invalidate that send without discarding queued data.
    assert!(ctrl.crash());
    assert!(matches!(
        block_on(sender2.send(&cx, 21)),
        Err(mpsc::SendError::Disconnected(21))
    ));
    assert!(ctrl.restart());
    let cold = mode == RestartMode::Cold;
    let restarted = CrashStatsSnapshot {
        sends_attempted: if cold { 0 } else { 3 },
        sends_succeeded: u64::from(!cold),
        sends_rejected: u64::from(!cold),
        crashes: 1,
        restarts: 1,
    };
    assert_eq!(ctrl.stats().snapshot(), restarted);
    assert_eq!(sender1.send_count(), u64::from(!cold));
    assert_eq!(sender2.send_count(), u64::from(!cold));

    assert_eq!(rx.try_recv(), Ok(10));
    assert!(matches!(
        stale_send.as_mut().poll(&mut task_cx),
        Poll::Ready(Err(mpsc::SendError::Disconnected(20)))
    ));
    assert!(rx.is_empty(), "prior-incarnation send must not publish");
    let rejected = CrashStatsSnapshot {
        sends_rejected: if cold { 0 } else { 2 },
        ..restarted
    };
    assert_eq!(ctrl.stats().snapshot(), rejected);

    // A second wrapper sees the same new incarnation, and the rejected send
    // released its capacity reservation so the next commit can complete.
    block_on(sender2.send(&cx, 30)).unwrap();
    assert_eq!(rx.try_recv(), Ok(30));
    assert!(rx.is_empty());
    assert_eq!(sender1.send_count(), if cold { 1 } else { 2 });
    assert_eq!(sender2.send_count(), sender1.send_count());
    assert_eq!(
        ctrl.stats().snapshot(),
        CrashStatsSnapshot {
            sends_attempted: rejected.sends_attempted + 1,
            sends_succeeded: rejected.sends_succeeded + 1,
            ..rejected
        }
    );
    assert!(!ctrl.is_crashed());
}

#[test]
fn cold_restart_rejects_pending_prior_incarnation_without_polluting_fresh_stats() {
    pending_send_across_restart(RestartMode::Cold);
}

#[test]
fn warm_restart_rejects_pending_prior_incarnation_and_retains_its_stats() {
    pending_send_across_restart(RestartMode::Warm);
}

// ---------------------------------------------------------------------------
// Criterion 5: Restart exhaustion
// ---------------------------------------------------------------------------

#[test]
fn cold_restart_send_resets_cannot_replenish_restart_budget() {
    let config = CrashConfig::new(42)
        .with_crash_after_sends(1)
        .with_max_restarts(2)
        .with_restart_mode(RestartMode::Cold);
    let (tx, mut rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    for incarnation in 0..=2 {
        assert_eq!(tx.send_count(), 0);
        block_on(tx.send(&cx, incarnation)).unwrap();
        assert_eq!(rx.try_recv(), Ok(incarnation));
        assert!(matches!(
            block_on(tx.send(&cx, 100 + incarnation)),
            Err(mpsc::SendError::Disconnected(value)) if value == 100 + incarnation
        ));
        let crashed = ctrl.stats().snapshot();
        assert_eq!(crashed.sends_attempted, 2);
        assert_eq!(crashed.sends_succeeded, 1);
        assert_eq!(crashed.sends_rejected, 1);
        assert_eq!(crashed.crashes, u64::from(incarnation) + 1);
        assert_eq!(crashed.restarts, u64::from(incarnation));

        if incarnation < 2 {
            assert!(ctrl.restart());
            assert_eq!(
                ctrl.stats().snapshot(),
                CrashStatsSnapshot {
                    sends_attempted: 0,
                    sends_succeeded: 0,
                    sends_rejected: 0,
                    crashes: crashed.crashes,
                    restarts: crashed.restarts + 1,
                }
            );
        } else {
            assert!(!ctrl.restart());
            assert!(ctrl.is_exhausted());
            assert!(ctrl.is_crashed());
            assert_eq!(tx.send_count(), 1);
            assert_eq!(ctrl.stats().snapshot(), crashed);
            assert!(!ctrl.restart(), "exhaustion must remain permanent");
            assert_eq!(ctrl.stats().snapshot(), crashed);
        }
    }
    assert!(rx.is_empty());
}

#[test]
fn max_restarts_enforced() {
    let config = CrashConfig::new(42).with_max_restarts(3);
    let (tx, _rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    for attempt in 0..3 {
        ctrl.crash();
        assert!(ctrl.restart(), "Restart {attempt} should succeed");
    }

    // 4th crash: restart should be refused.
    ctrl.crash();
    assert!(!ctrl.restart());
    assert!(ctrl.is_exhausted());

    // Sends should fail permanently.
    assert!(block_on(tx.send(&cx, 1)).is_err());
}

#[test]
fn exhausted_controller_is_permanent() {
    let config = CrashConfig::new(42).with_max_restarts(1);
    let (_, _, ctrl, _) = make_crash_channel(config);

    ctrl.crash();
    ctrl.restart(); // 1 restart
    ctrl.crash();
    assert!(!ctrl.restart()); // Exhausted

    // Even crash() returns false now (already crashed + exhausted).
    assert!(!ctrl.crash());
    assert!(ctrl.is_exhausted());
    assert!(ctrl.is_crashed());
}

// ---------------------------------------------------------------------------
// Criterion 6: Deterministic crash after N sends
// ---------------------------------------------------------------------------

#[test]
fn deterministic_crash_at_exact_count() {
    let config = CrashConfig::new(42).with_crash_after_sends(10);
    let (tx, mut rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    // Exactly 10 sends should succeed.
    for i in 0..10 {
        block_on(tx.send(&cx, i)).unwrap();
    }

    // 11th triggers crash.
    assert!(block_on(tx.send(&cx, 10)).is_err());
    assert!(ctrl.is_crashed());
    assert_eq!(tx.send_count(), 10);

    // Verify all 10 messages arrived.
    for i in 0..10 {
        assert_eq!(rx.try_recv().unwrap(), i);
    }
    assert!(rx.is_empty());
}

#[test]
fn crash_after_zero_sends() {
    let config = CrashConfig::new(42).with_crash_after_sends(0);
    let (tx, _rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    // First send should trigger crash immediately.
    assert!(block_on(tx.send(&cx, 0)).is_err());
    assert!(ctrl.is_crashed());
    assert_eq!(tx.send_count(), 0);
}

// ---------------------------------------------------------------------------
// Criterion 7: Probabilistic crash (determinism)
// ---------------------------------------------------------------------------

#[test]
fn probabilistic_crash_is_deterministic() {
    // Run the same scenario twice with the same seed.
    let mut results = Vec::new();

    for _ in 0..2 {
        let config = CrashConfig::new(12345).with_crash_probability(0.3);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        let mut sent = 0u32;
        for i in 0..100 {
            if block_on(tx.send(&cx, i)).is_ok() {
                sent += 1;
            } else {
                break;
            }
        }
        results.push(sent);
        assert!(ctrl.is_crashed());
    }

    // Same seed should produce same crash point.
    assert_eq!(
        results[0], results[1],
        "Determinism violated: crash at different send counts"
    );
}

#[test]
fn probabilistic_crash_with_high_probability() {
    let config = CrashConfig::new(42).with_crash_probability(0.99);
    let (tx, _rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    // With 99% crash probability, crash should happen within a few sends.
    let mut crash_triggered = false;
    for i in 0..20 {
        if block_on(tx.send(&cx, i)).is_err() {
            crash_triggered = true;
            break;
        }
    }
    assert!(crash_triggered, "Expected crash within 20 sends at p=0.99");
    assert!(ctrl.is_crashed());
}

// ---------------------------------------------------------------------------
// Criterion 8: Evidence logging
// ---------------------------------------------------------------------------

#[test]
fn evidence_logged_for_crash_and_restart() {
    let config = CrashConfig::new(42).with_crash_after_sends(2);
    let (tx, _rx, ctrl, collector) = make_crash_channel(config);
    let cx = test_cx();

    // 2 sends, then crash, then restart.
    block_on(tx.send(&cx, 0)).unwrap();
    block_on(tx.send(&cx, 1)).unwrap();
    let _ = block_on(tx.send(&cx, 2)); // Crash triggers.
    ctrl.restart();

    let entries = collector.entries();
    let actions: Vec<&str> = entries.iter().map(|e| e.action.as_str()).collect();

    assert!(
        actions.iter().any(|a| a.contains("crash")),
        "Expected crash evidence in {actions:?}"
    );
    assert!(
        actions.iter().any(|a| a.contains("restart")),
        "Expected restart evidence in {actions:?}"
    );
}

#[test]
fn evidence_logged_for_rejected_sends() {
    let config = CrashConfig::new(42);
    let (tx, _rx, ctrl, collector) = make_crash_channel(config);
    let cx = test_cx();

    ctrl.crash();
    let _ = block_on(tx.send(&cx, 1));
    let _ = block_on(tx.send(&cx, 2));

    let entries = collector.entries();
    let rejected_count = entries
        .iter()
        .filter(|e| e.action.contains("rejected"))
        .count();
    assert!(
        rejected_count >= 2,
        "Expected at least 2 rejection evidence entries, got {rejected_count}"
    );
}

#[test]
fn evidence_includes_component_channel_crash() {
    let config = CrashConfig::new(42).with_crash_after_sends(1);
    let (tx, _rx, _ctrl, collector) = make_crash_channel(config);
    let cx = test_cx();

    block_on(tx.send(&cx, 0)).unwrap();
    let _ = block_on(tx.send(&cx, 1));

    let entries = collector.entries();
    assert!(
        entries.iter().all(|e| e.component == "channel_crash"),
        "All entries should have component='channel_crash'"
    );
}

// ---------------------------------------------------------------------------
// Criterion 9: Stats tracking
// ---------------------------------------------------------------------------

#[test]
fn stats_accurate_across_crash_restart_cycles() {
    let config = CrashConfig::new(42).with_crash_after_sends(2);
    let (tx, _rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    // Cycle 1: 2 success, 1 crash, 1 rejected.
    block_on(tx.send(&cx, 0)).unwrap();
    block_on(tx.send(&cx, 1)).unwrap();
    let _ = block_on(tx.send(&cx, 2)); // Crash.
    let _ = block_on(tx.send(&cx, 3)); // Rejected.

    assert!(ctrl.restart());

    // Cycle 2: 2 success, 1 crash.
    block_on(tx.send(&cx, 4)).unwrap();
    block_on(tx.send(&cx, 5)).unwrap();
    let _ = block_on(tx.send(&cx, 6)); // Crash.

    let snap = ctrl.stats().snapshot();
    assert_eq!(snap.sends_attempted, 3);
    assert_eq!(snap.sends_succeeded, 2);
    assert_eq!(snap.sends_rejected, 1);
    assert_eq!(snap.crashes, 2);
    assert_eq!(snap.restarts, 1);
}

#[test]
fn send_count_tracks_shared_actor_incarnation() {
    let config = CrashConfig::new(42).with_crash_after_sends(5);
    let (tx, _rx, _ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    for i in 0..5 {
        block_on(tx.send(&cx, i)).unwrap();
    }

    assert_eq!(tx.send_count(), 5);
}

// ---------------------------------------------------------------------------
// Criterion 10: Two-phase commit safety
// ---------------------------------------------------------------------------

#[test]
fn reserve_then_crash_aborts_permit() {
    // Create a normal mpsc channel and get a reserve permit.
    let (tx, mut rx) = mpsc::channel::<u32>(16);
    let cx = test_cx();

    // Reserve a slot (phase 1 of two-phase commit).
    let permit = block_on(tx.reserve(&cx)).unwrap();

    // Simulate crash by dropping the permit without sending.
    // The permit's Drop impl should abort cleanly.
    drop(permit);

    // Channel should still be functional (no leaked capacity).
    let permit2 = block_on(tx.reserve(&cx)).unwrap();
    permit2.send(42);
    assert_eq!(rx.try_recv().unwrap(), 42);
}

#[test]
fn crash_during_send_sequence_no_obligation_leak() {
    let config = CrashConfig::new(42).with_crash_after_sends(5);
    let (tx, mut rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    // Send 5 messages successfully.
    for i in 0..5 {
        block_on(tx.send(&cx, i)).unwrap();
    }

    // 6th send crashes — the value is returned in the error.
    let err = block_on(tx.send(&cx, 5)).unwrap_err();
    match err {
        mpsc::SendError::Disconnected(v) => assert_eq!(v, 5),
        other => panic!("Expected Disconnected(5), got {other:?}"),
    }

    // Restart and send more.
    assert!(ctrl.restart());
    block_on(tx.send(&cx, 100)).unwrap();

    // Verify: 5 pre-crash + 1 post-restart = 6 messages received.
    let mut received = Vec::new();
    while let Ok(v) = rx.try_recv() {
        received.push(v);
    }
    assert_eq!(received, vec![0, 1, 2, 3, 4, 100]);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn crash_with_no_faults_enabled_is_manual_only() {
    let config = CrashConfig::new(42);
    let (tx, _rx, ctrl, _) = make_crash_channel(config);
    let cx = test_cx();

    // Without any fault injection, sends always succeed.
    // Channel capacity is 16, so send at most that many without draining.
    for i in 0..16 {
        block_on(tx.send(&cx, i)).unwrap();
    }
    assert!(!ctrl.is_crashed());
}

#[test]
fn controller_shared_across_multiple_senders() {
    let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
    let config = CrashConfig::new(42).with_crash_after_sends(2);

    let (tx1, mut rx) = mpsc::channel::<u32>(16);
    let tx2 = tx1.clone();
    let ctrl = Arc::new(asupersync::channel::crash::CrashController::new(
        &config,
        sink.clone(),
    ));

    let sender1 = CrashSender::new(tx1, ctrl.clone(), config.clone(), sink.clone());
    let sender2 = CrashSender::new(tx2, ctrl.clone(), config, sink);
    let cx = test_cx();

    block_on(sender1.send(&cx, 1)).unwrap();
    block_on(sender2.send(&cx, 2)).unwrap();
    assert_eq!(sender1.send_count(), 2);
    assert_eq!(sender2.send_count(), 2);

    // The shared actor-wide limit affects both senders.
    assert!(block_on(sender1.send(&cx, 3)).is_err());
    assert!(block_on(sender2.send(&cx, 4)).is_err());

    // Cold restart resets the shared incarnation and re-enables both.
    assert!(ctrl.restart());
    assert_eq!(sender1.send_count(), 0);
    assert_eq!(sender2.send_count(), 0);
    block_on(sender1.send(&cx, 5)).unwrap();
    block_on(sender2.send(&cx, 6)).unwrap();
    assert_eq!(sender1.send_count(), 2);
    assert_eq!(sender2.send_count(), 2);

    let mut received = Vec::new();
    while let Ok(v) = rx.try_recv() {
        received.push(v);
    }
    assert_eq!(received, vec![1, 2, 5, 6]);
}
