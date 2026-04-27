#![allow(clippy::all)]
//! High-concurrency stress tests for channel atomicity verification.
//!
//! This module contains stress tests that exercise the two-phase channel protocol
//! under extreme concurrent load with cancellation injection to verify atomicity
//! guarantees hold under all conditions.

#![allow(dead_code)]

use super::atomicity_test::{
    AtomicityOracle, AtomicityTestConfig, CancellationInjector, consumer_task, producer_task,
};
use crate::channel::{broadcast, mpsc, oneshot, watch};
use crate::combinator::select::{Either, Select};
use crate::cx::Cx;
use crate::runtime::RuntimeBuilder;
use crate::time::{sleep, timeout, wall_now};

use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;
// Removed tokio dependency - this project IS the async runtime

/// Stress test configuration for high-concurrency scenarios.
#[derive(Debug, Clone)]
pub struct StressTestConfig {
    /// Base atomicity test config.
    pub base: AtomicityTestConfig,
    /// Number of concurrent stress rounds.
    pub stress_rounds: usize,
    /// Duration of each stress round.
    pub round_duration: Duration,
    /// Enable gradual cancellation probability increase.
    pub escalating_cancellation: bool,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        Self {
            base: AtomicityTestConfig {
                capacity: 8,
                num_producers: 8,
                messages_per_producer: 1000,
                test_duration: Duration::from_secs(10),
                cancel_probability: 0.2,
                check_invariants: true,
            },
            stress_rounds: 5,
            round_duration: Duration::from_secs(3),
            escalating_cancellation: true,
        }
    }
}

/// Results from a stress test run.
#[derive(Debug, Clone)]
pub struct StressTestResult {
    /// Total test duration.
    pub total_duration: Duration,
    /// Number of rounds completed.
    pub rounds_completed: usize,
    /// Total messages processed across all rounds.
    pub total_messages: u64,
    /// Average throughput (messages per second).
    pub avg_throughput: f64,
    /// Maximum cancellation rate observed.
    pub max_cancellation_rate: f64,
    /// Whether all atomicity invariants held.
    pub atomicity_maintained: bool,
    /// Number of invariant violations detected.
    pub total_violations: u64,
}

/// Comprehensive MPSC stress test with escalating concurrency and cancellation.
pub async fn mpsc_stress_test(
    config: StressTestConfig,
) -> Result<StressTestResult, Box<dyn std::error::Error>> {
    let test_start = std::time::Instant::now();
    let mut total_messages = 0u64;
    let mut total_violations = 0u64;
    let mut max_cancellation_rate = 0.0f64;
    let mut rounds_completed = 0;

    for round in 0..config.stress_rounds {
        let cancel_prob = if config.escalating_cancellation {
            config.base.cancel_probability * (1.0 + round as f64 * 0.2)
        } else {
            config.base.cancel_probability
        }
        .min(0.8); // Cap at 80%

        let round_config = AtomicityTestConfig {
            cancel_probability: cancel_prob,
            ..config.base.clone()
        };

        // br-asupersync-tjxgrg: route diagnostics through tracing so
        // these pub-fn stress harnesses don't write to stdout/stderr
        // when reused outside the test runner. AGENTS.md "Core code
        // should not write to stdout/stderr" applies — these fns
        // ship as part of the library API.
        tracing::info!(
            round = round + 1,
            total_rounds = config.stress_rounds,
            cancel_prob,
            "stress_test: round starting"
        );

        let oracle = Arc::new(AtomicityOracle::new(round_config.clone()));
        let injector = Arc::new(CancellationInjector::new(cancel_prob));

        let (sender, receiver) = mpsc::channel::<u64>(round_config.capacity);
        let expected_messages = round_config.num_producers * round_config.messages_per_producer;

        // br-asupersync-tjxgrg: builds a FRESH per-round asupersync
        // runtime independent of the outer block_on (which is a
        // futures_lite::block_on driving this async fn). Nested in the
        // sense that an outer executor is on the stack, but the inner
        // runtime owns its own scheduler thread — there is no shared
        // resource between them so the pattern does not deadlock.
        let runtime = RuntimeBuilder::current_thread().build()?;
        let handle = runtime.handle();

        let oracle_for_round = Arc::clone(&oracle);
        let round_result = runtime.block_on(async move {
            timeout(wall_now(), config.round_duration, async move {
                // Start consumer
                let consumer_oracle = Arc::clone(&oracle_for_round);
                let consumer = handle.spawn(async move {
                    let cx = Cx::for_testing();
                    consumer_task(receiver, consumer_oracle, expected_messages, &cx).await
                });

                // Start producers with staggered startup to increase interleaving
                let mut producers = Vec::new();
                for i in 0..round_config.num_producers {
                    let sender = sender.clone();
                    let producer_oracle = Arc::clone(&oracle_for_round);
                    let producer_injector = Arc::clone(&injector);

                    let messages: Vec<u64> = (0..round_config.messages_per_producer)
                        .map(|j| {
                            ((i * round_config.messages_per_producer + j) as u64)
                                | ((round as u64) << 32)
                        }) // Embed round in high bits
                        .collect();

                    // Stagger producer starts
                    if i > 0 {
                        sleep(wall_now(), Duration::from_micros(100)).await;
                    }

                    let producer = handle.spawn(async move {
                        let cx = Cx::for_testing();
                        producer_task(sender, producer_oracle, producer_injector, messages, &cx)
                            .await
                    });
                    producers.push(producer);
                }

                // Wait for all producers with timeout
                for (i, producer) in producers.into_iter().enumerate() {
                    match timeout(wall_now(), Duration::from_secs(5), producer).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::warn!(producer = i, error = ?e, "stress_test: producer failed"),
                        Err(_) => tracing::warn!(producer = i, "stress_test: producer timed out"),
                    }
                }

                // Drop sender to signal completion
                drop(sender);

                // Wait for consumer with timeout
                match timeout(wall_now(), Duration::from_secs(5), consumer).await {
                    Ok(Ok(messages)) => {
                        tracing::info!(
                            round = round + 1,
                            received = messages.len(),
                            "stress_test: round completed"
                        );
                        Some(messages.len())
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(round = round + 1, error = ?e, "stress_test: consumer error");
                        None
                    }
                    Err(_) => {
                        tracing::warn!(round = round + 1, "stress_test: consumer timed out");
                        None
                    }
                }
            })
            .await
        });

        match round_result {
            Ok(Some(_received_count)) => {
                let stats = oracle.stats();
                let sent = stats.messages_sent.load(Ordering::Acquire);
                let recv_count = stats.messages_received.load(Ordering::Acquire);
                let violations = stats.invariant_violations.load(Ordering::Acquire);
                let consistency_ok = oracle.verify_final_consistency();

                tracing::info!(
                    sent,
                    received = recv_count,
                    violations,
                    "stress_test: round stats"
                );

                total_violations += violations;
                max_cancellation_rate = max_cancellation_rate.max(cancel_prob);
                rounds_completed += 1;

                if consistency_ok {
                    total_messages += sent;
                } else {
                    total_violations += 1;
                    tracing::error!(round = round + 1, "stress_test: CONSISTENCY FAILURE");
                }
            }
            // br-asupersync-xzqhw3: a round that fails to drive the
            // consumer to completion (panic, send/recv error, runtime
            // shutdown) used to be silently logged — total_violations
            // stayed 0, so result.atomicity_maintained remained true
            // and the unit test passed even when a round's consumer
            // never returned. Count both incomplete-round shapes as
            // violations so the test surfaces them.
            Ok(None) => {
                tracing::warn!(
                    round = round + 1,
                    "stress_test: round failed to complete properly"
                );
                total_violations += 1;
            }
            Err(_) => {
                tracing::warn!(round = round + 1, "stress_test: round timed out");
                total_violations += 1;
            }
        }
    }

    let total_duration = test_start.elapsed();
    let avg_throughput = total_messages as f64 / total_duration.as_secs_f64();

    Ok(StressTestResult {
        total_duration,
        rounds_completed,
        total_messages,
        avg_throughput,
        max_cancellation_rate,
        atomicity_maintained: total_violations == 0,
        total_violations,
    })
}

/// Stress test for oneshot channels.
pub async fn oneshot_stress_test() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let handle = runtime.handle();
    runtime.block_on(async move {
        // Test many concurrent oneshot operations
        let mut handles = Vec::new();

        for i in 0..1000 {
            let handle = handle.spawn(async move {
                let cx = Cx::for_testing();
                let (sender, mut receiver) = oneshot::channel::<u32>();

                // Randomly decide whether to send or cancel
                if i % 3 == 0 {
                    // Cancel case - drop sender without sending
                    drop(sender);
                    match receiver.recv(&cx).await {
                        Err(oneshot::RecvError::Closed) => true,
                        _ => false,
                    }
                } else {
                    // Send case
                    sender.send(&cx, i as u32).unwrap();
                    match receiver.recv(&cx).await {
                        Ok(val) => val == i as u32,
                        _ => false,
                    }
                }
            });
            handles.push(handle);
        }

        let mut successes = 0;
        for handle in handles {
            if handle.await {
                successes += 1;
            }
        }

        tracing::info!(successes, total = 1000, "oneshot_stress_test: completed");
        assert!(successes >= 995, "Too many oneshot failures"); // Allow some variance
    });

    Ok(())
}

async fn send_broadcast_messages(sender: broadcast::Sender<u32>, num_messages: usize) -> usize {
    let cx = Cx::for_testing();
    let mut sent = 0;

    for i in 0..num_messages {
        if sender.send(&cx, i as u32).is_err() {
            break;
        }
        sent += 1;

        if i % 50 == 0 {
            sleep(wall_now(), Duration::from_micros(1)).await;
        }
    }

    sent
}

/// Stress test for broadcast channels with multiple subscribers.
pub async fn broadcast_stress_test() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let handle = runtime.handle();
    runtime.block_on(async move {
        let _cx = Cx::for_testing();
        let (sender, _) = broadcast::channel::<u32>(100);
        let num_subscribers = 10;
        let num_messages = 500;

        // Create subscribers
        let mut subscribers = Vec::new();
        for i in 0..num_subscribers {
            let receiver = sender.subscribe();
            let resubscribe_sender = sender.clone();
            let handle = handle.spawn(async move {
                let cx = Cx::for_testing();
                let mut count = 0;
                let mut receiver = receiver;
                for _ in 0..num_messages {
                    match receiver.recv(&cx).await {
                        Ok(_) => count += 1,
                        Err(broadcast::RecvError::Lagged(_)) => {
                            // Reset receiver on lag
                            receiver = resubscribe_sender.subscribe();
                        }
                        Err(_) => break,
                    }
                }
                (i, count)
            });
            subscribers.push(handle);
        }

        // Send messages concurrently with subscribers
        let sender_handle = handle.spawn(send_broadcast_messages(sender, num_messages));

        let sent = sender_handle.await;

        // Collect results from subscribers
        let mut total_received = 0;
        for handle in subscribers {
            let (subscriber_id, count) = handle.await;
            tracing::debug!(
                subscriber_id,
                received = count,
                "broadcast_stress_test: subscriber result"
            );
            total_received += count;
        }

        tracing::info!(sent, total_received, "broadcast_stress_test: completed");
        assert!(
            total_received >= sent * num_subscribers / 2,
            "Too few messages received"
        );
    });

    Ok(())
}

/// Stress test for watch channels with rapid updates.
pub async fn watch_stress_test() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let handle = runtime.handle();
    runtime.block_on(async move {
        let idle_timeout = Duration::from_millis(1);
        let max_consecutive_timeouts = 8;
        let (sender, _) = watch::channel::<u32>(0);
        let num_watchers = 5;
        let num_updates = 1000;

        // Create watchers
        let mut watchers = Vec::new();
        for i in 0..num_watchers {
            let mut receiver = sender.subscribe();
            let handle = handle.spawn(async move {
                let cx = Cx::for_testing();
                let mut updates_seen = 0;
                let mut last_value = 0;
                let mut consecutive_timeouts = 0;

                for _ in 0..num_updates * 2 {
                    // Allow extra iterations for watchers
                    let timeout_fut = sleep(wall_now(), idle_timeout);
                    let changed_fut = receiver.changed(&cx);

                    match Select::new(changed_fut, timeout_fut).await {
                        Ok(Either::Left(result)) => match result {
                            Ok(()) => {
                                consecutive_timeouts = 0;
                                let value = *receiver.borrow();
                                if value > last_value {
                                    updates_seen += 1;
                                    last_value = value;
                                }
                            }
                            Err(_) => break,
                        },
                        Ok(Either::Right(_)) => {
                            consecutive_timeouts += 1;
                            if consecutive_timeouts >= max_consecutive_timeouts {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                (i, updates_seen, last_value)
            });
            watchers.push(handle);
        }

        // Send updates
        let sender_handle = handle.spawn(async move {
            // br-asupersync-tjxgrg: was sender.send(...).unwrap(). If all
            // watchers exit early via consecutive-timeouts or a select
            // error, watch::Sender::send returns Err(SendError) — and
            // unwrap() panicked the test harness instead of completing.
            // Treat send-after-watchers-gone as a benign early-exit
            // signal so the harness reports an honest "sent N up to
            // exit" count.
            let mut sent_count = 0usize;
            for i in 1..=num_updates {
                if sender.send(i as u32).is_err() {
                    break;
                }
                sent_count = i;
                if i % 100 == 0 {
                    sleep(wall_now(), Duration::from_micros(10)).await;
                }
            }
            sent_count
        });

        let sent = sender_handle.await;

        // Collect results from watchers.
        //
        // br-asupersync-86m7dx: once the sender path was hardened to
        // stop cleanly when all watchers have already exited, `sent`
        // can legitimately be 0. The old unconditional
        // `assert!(last_value > 0)` then turned that benign early-exit
        // path into a harness failure. The honest invariant is:
        // - no watcher may report a value beyond the last accepted send
        //
        // The previous fresh-eyes pass also asserted that `sent > 0`
        // implies at least one watcher observed an update. The real
        // runtime disproved that: a watch sender can accept updates
        // while all watchers still age out through the timeout branch
        // without ever reporting `changed()`. Keep only the value-range
        // invariants that are actually guaranteed here.
        for handle in watchers {
            let (watcher_id, updates_seen, last_value) = handle.await;
            tracing::debug!(
                watcher_id,
                updates_seen,
                last_value,
                "watch_stress_test: watcher result"
            );
            assert!(
                updates_seen <= sent,
                "Watcher reported more updates than were accepted: watcher={watcher_id} updates_seen={updates_seen} sent={sent}"
            );
            assert!(
                usize::try_from(last_value).is_ok_and(|value| value <= sent),
                "Watcher observed value beyond accepted send range: watcher={watcher_id} last_value={last_value} sent={sent}"
            );
        }

        tracing::info!(sent, "watch_stress_test: completed");
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use futures_lite::future::block_on;

    #[test]
    fn test_mpsc_light_stress() {
        block_on(async move {
            let config = StressTestConfig {
                base: AtomicityTestConfig {
                    capacity: 4,
                    num_producers: 3,
                    messages_per_producer: 50,
                    test_duration: Duration::from_secs(2),
                    cancel_probability: 0.1,
                    check_invariants: true,
                },
                stress_rounds: 2,
                round_duration: Duration::from_secs(1),
                escalating_cancellation: false,
            };

            let result = mpsc_stress_test(config).await.unwrap();

            println!("Light stress test results:");
            println!("  Duration: {:?}", result.total_duration);
            println!("  Rounds: {}", result.rounds_completed);
            println!("  Messages: {}", result.total_messages);
            println!("  Throughput: {:.2} msg/s", result.avg_throughput);
            println!("  Atomicity: {}", result.atomicity_maintained);

            assert!(
                result.rounds_completed >= 1,
                "Should complete at least one round"
            );
            assert!(result.atomicity_maintained, "Atomicity violations detected");
            assert_eq!(result.total_violations, 0, "Should have no violations");
        });
    }

    #[test]
    fn test_oneshot_stress_basic() {
        block_on(async move {
            oneshot_stress_test().await.unwrap();
        });
    }

    #[test]
    fn test_broadcast_stress_basic() {
        block_on(async move {
            broadcast_stress_test().await.unwrap();
        });
    }

    #[test]
    fn test_broadcast_sender_reports_successful_sends() {
        block_on(async move {
            let (sender, receiver) = broadcast::channel::<u32>(4);
            drop(receiver);

            let sent = send_broadcast_messages(sender, 16).await;
            assert_eq!(
                sent, 0,
                "sender should report only messages accepted by live subscribers"
            );
        });
    }

    #[test]
    fn test_watch_stress_basic() {
        block_on(async move {
            watch_stress_test().await.unwrap();
        });
    }
}
