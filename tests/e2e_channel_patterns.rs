//! E2E channel producer/consumer pattern tests (T1.3).
//!
//! Three sub-scenarios exercising realistic channel usage under
//! the deterministic LabRuntime with oracle verification:
//!
//! 1. mpsc backpressure — 10 producers, 1 consumer, bounded(16)
//! 2. broadcast fanout  — 1 producer, 5 consumers
//! 3. watch state sync  — 1 writer, 3 readers

#[macro_use]
mod common;

use common::e2e_harness::E2eLabHarness;
use common::payloads;

use asupersync::channel::{broadcast, mpsc, watch};
use asupersync::cx::Cx;
use asupersync::runtime::yield_now;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// ============================================================================
// 1. mpsc backpressure: 10 producers × 100 messages → 1 consumer
// ============================================================================

#[test]
fn e2e_channel_mpsc_backpressure() {
    const NUM_PRODUCERS: usize = 10;
    const MSGS_PER_PRODUCER: usize = 100;
    const TOTAL_MSGS: usize = NUM_PRODUCERS * MSGS_PER_PRODUCER;
    const CHANNEL_CAP: usize = 16;

    let mut h = E2eLabHarness::new("e2e_channel_mpsc_backpressure", 0xE2E3_0001);
    let root = h.create_root();

    let (tx, rx) = mpsc::channel::<String>(CHANNEL_CAP);
    let consumed = Arc::new(AtomicUsize::new(0));

    // --- Spawn producers ---
    e2e_phase!(h, "spawn_producers", {
        for producer_id in 0..NUM_PRODUCERS {
            let tx = tx.clone();
            h.spawn(root, async move {
                let Some(cx) = Cx::current() else { return };
                for seq in 0..MSGS_PER_PRODUCER {
                    if cx.checkpoint().is_err() {
                        return;
                    }
                    let global_seq = (producer_id * MSGS_PER_PRODUCER + seq) as u64;
                    let event = payloads::json_log_event(global_seq, "INFO", "channel-e2e");
                    if tx.send(&cx, event).await.is_err() {
                        return;
                    }
                    yield_now().await;
                }
            });
        }
    });

    // Drop the original sender so the consumer sees channel closure.
    drop(tx);

    // --- Spawn consumer ---
    let consumed_clone = Arc::clone(&consumed);
    e2e_phase!(h, "spawn_consumer", {
        let mut rx = rx;
        h.spawn(root, async move {
            let Some(cx) = Cx::current() else { return };
            loop {
                if cx.checkpoint().is_err() {
                    return;
                }
                match rx.recv(&cx).await {
                    Ok(_msg) => {
                        consumed_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => break, // channel closed
                }
                yield_now().await;
            }
        });
    });

    // --- Run ---
    e2e_phase!(h, "run", {
        let steps = h.run_until_quiescent();
        tracing::info!(steps = steps, "mpsc backpressure run complete");
    });

    // --- Verify ---
    let count = consumed.load(Ordering::Relaxed);
    assert_eq!(
        count, TOTAL_MSGS,
        "consumer must receive exactly {TOTAL_MSGS} messages, got {count}"
    );

    h.finish();
}

// ============================================================================
// 2. broadcast fanout: 1 producer → 5 consumers
// ============================================================================

#[test]
fn e2e_channel_broadcast_fanout() {
    const NUM_CONSUMERS: usize = 5;
    const NUM_MESSAGES: usize = 50;
    const CHANNEL_CAP: usize = 64;

    let mut h = E2eLabHarness::new("e2e_channel_broadcast_fanout", 0xE2E3_0002);
    let root = h.create_root();

    let (tx, _) = broadcast::channel::<String>(CHANNEL_CAP);

    // Per-consumer received counts.
    let counts: Vec<Arc<AtomicUsize>> = (0..NUM_CONSUMERS)
        .map(|_| Arc::new(AtomicUsize::new(0)))
        .collect();

    // --- Spawn consumers (subscribe before producing) ---
    e2e_phase!(h, "spawn_consumers", {
        for counter in counts.iter().take(NUM_CONSUMERS) {
            let mut rx = tx.subscribe();
            let counter = Arc::clone(counter);
            h.spawn(root, async move {
                let Some(cx) = Cx::current() else { return };
                loop {
                    if cx.checkpoint().is_err() {
                        return;
                    }
                    match rx.recv(&cx).await {
                        Ok(_msg) => {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => break,
                    }
                    yield_now().await;
                }
            });
        }
    });

    // --- Spawn producer ---
    e2e_phase!(h, "spawn_producer", {
        let tx = tx;
        h.spawn(root, async move {
            let Some(cx) = Cx::current() else { return };
            for version in 1..=NUM_MESSAGES {
                if cx.checkpoint().is_err() {
                    return;
                }
                let msg = payloads::config_update_message(version as u32);
                // broadcast send is synchronous; ignore the receiver count.
                let _ = tx.send(&cx, msg);
                yield_now().await;
            }
            // Dropping tx closes the channel for all subscribers.
        });
    });

    // --- Run ---
    e2e_phase!(h, "run", {
        let steps = h.run_until_quiescent();
        tracing::info!(steps = steps, "broadcast fanout run complete");
    });

    // --- Verify each consumer got all messages ---
    for (i, counter) in counts.iter().enumerate() {
        let got = counter.load(Ordering::Relaxed);
        assert_eq!(
            got, NUM_MESSAGES,
            "consumer {i} must receive {NUM_MESSAGES} messages, got {got}"
        );
    }

    h.finish();
}

// ============================================================================
// 3. watch state sync: 1 writer, 3 readers
// ============================================================================

#[test]
fn e2e_channel_watch_state_sync() {
    const NUM_READERS: usize = 3;

    let mut h = E2eLabHarness::new("e2e_channel_watch_state_sync", 0xE2E3_0003);
    let root = h.create_root();

    let (tx, rx) = watch::channel::<String>("starting".to_string());

    // Track how many state transitions each reader observed.
    let transition_counts: Vec<Arc<AtomicUsize>> = (0..NUM_READERS)
        .map(|_| Arc::new(AtomicUsize::new(0)))
        .collect();

    // Track the final state each reader saw.
    let final_states: Vec<Arc<std::sync::Mutex<String>>> = (0..NUM_READERS)
        .map(|_| Arc::new(std::sync::Mutex::new(String::new())))
        .collect();

    // --- Spawn readers ---
    e2e_phase!(h, "spawn_readers", {
        for i in 0..NUM_READERS {
            let mut reader_rx = rx.clone();
            let counter = Arc::clone(&transition_counts[i]);
            let final_state = Arc::clone(&final_states[i]);
            h.spawn(root, async move {
                let Some(cx) = Cx::current() else { return };
                loop {
                    if cx.checkpoint().is_err() {
                        return;
                    }
                    match reader_rx.changed(&cx).await {
                        Ok(()) => {
                            let val = reader_rx.borrow_and_update_clone();
                            counter.fetch_add(1, Ordering::Relaxed);
                            *final_state.lock().unwrap() = val;
                        }
                        Err(_) => break, // sender dropped
                    }
                    yield_now().await;
                }
            });
        }
    });

    // Drop the original receiver (readers already have their own clones).
    drop(rx);

    // --- Spawn writer ---
    e2e_phase!(h, "spawn_writer", {
        h.spawn(root, async move {
            let Some(cx) = Cx::current() else { return };
            let states = ["ready", "draining", "stopped"];
            for state in &states {
                if cx.checkpoint().is_err() {
                    return;
                }
                let _ = tx.send((*state).to_string());
                yield_now().await;
            }
            // Dropping tx signals channel closure.
        });
    });

    // --- Run ---
    e2e_phase!(h, "run", {
        let steps = h.run_until_quiescent();
        tracing::info!(steps = steps, "watch state sync run complete");
    });

    // --- Verify final state ---
    for (i, final_state) in final_states.iter().enumerate() {
        let state = final_state.lock().unwrap();
        let state_val = state.clone();
        drop(state);
        assert_eq!(
            state_val, "stopped",
            "reader {i} must observe final state 'stopped', got '{state_val}'"
        );
    }

    // Each reader should have seen at least 1 transition (watch coalesces
    // intermediate values, so the exact count depends on scheduling, but
    // the final value must always be visible before the sender drops).
    for (i, counter) in transition_counts.iter().enumerate() {
        let n = counter.load(Ordering::Relaxed);
        assert!(
            n >= 1,
            "reader {i} must observe at least 1 state transition, got {n}"
        );
    }

    h.finish();
}
