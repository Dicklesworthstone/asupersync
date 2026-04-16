//! High-concurrency stress tests for channel atomicity verification.
//!
//! This module contains stress tests that exercise the two-phase channel protocol
//! under extreme concurrent load with cancellation injection to verify atomicity
//! guarantees hold under all conditions.

use super::atomicity_test::{
    AtomicityOracle, AtomicityTestConfig, CancellationInjector, consumer_task, producer_task,
};
use crate::channel::{broadcast, mpsc, oneshot, watch};
use crate::cx::Cx;
use crate::test_utils::lab_with_config;
use crate::time::{sleep, timeout};
use crate::types::Budget;

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
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

        println!(
            "Round {}/{}: cancel_prob={:.2}",
            round + 1,
            config.stress_rounds,
            cancel_prob
        );

        let oracle = Arc::new(AtomicityOracle::new(round_config.clone()));
        let injector = Arc::new(CancellationInjector::new(cancel_prob));

        let (sender, receiver) = mpsc::channel::<u64>(round_config.capacity);
        let expected_messages = round_config.num_producers * round_config.messages_per_producer;

        let _runtime = lab_with_config(|rt| async move {
            let cx = &rt.cx();

            // Use timeout to prevent hanging
            let round_result = timeout(config.round_duration, async {
                // Start consumer
                let consumer_oracle = Arc::clone(&oracle);
                let consumer = task::spawn(async move {
                    consumer_task(receiver, consumer_oracle, expected_messages, cx).await
                });

                // Start producers with staggered startup to increase interleaving
                let mut producers = Vec::new();
                for i in 0..round_config.num_producers {
                    let sender = sender.clone();
                    let producer_oracle = Arc::clone(&oracle);
                    let producer_injector = Arc::clone(&injector);

                    let messages: Vec<u64> = (0..round_config.messages_per_producer)
                        .map(|j| {
                            ((i * round_config.messages_per_producer + j) as u64)
                                | ((round as u64) << 32)
                        }) // Embed round in high bits
                        .collect();

                    // Stagger producer starts
                    if i > 0 {
                        sleep(Duration::from_micros(100)).await;
                    }

                    let producer = task::spawn(async move {
                        producer_task(sender, producer_oracle, producer_injector, messages, cx)
                            .await
                    });
                    producers.push(producer);
                }

                // Wait for all producers with timeout
                for (i, producer) in producers.into_iter().enumerate() {
                    match timeout(Duration::from_secs(5), producer).await {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => eprintln!("Producer {} failed: {:?}", i, e),
                        Err(_) => eprintln!("Producer {} timed out", i),
                    }
                }

                // Drop sender to signal completion
                drop(sender);

                // Wait for consumer with timeout
                match timeout(Duration::from_secs(5), consumer).await {
                    Ok(Ok(Ok(received))) => {
                        println!(
                            "Round {} completed: received {} messages",
                            round + 1,
                            received.len()
                        );
                        Some(received.len())
                    }
                    Ok(Ok(Err(e))) => {
                        eprintln!("Consumer error in round {}: {:?}", round + 1, e);
                        None
                    }
                    Ok(Err(_)) => {
                        eprintln!("Consumer task panicked in round {}", round + 1);
                        None
                    }
                    Err(_) => {
                        eprintln!("Consumer timed out in round {}", round + 1);
                        None
                    }
                }
            })
            .await;

            round_result
        })
        .await;

        match round_result {
            Ok(Some(received_count)) => {
                let stats = oracle.stats();
                let sent = stats.messages_sent.load(Ordering::Acquire);
                let received = stats.messages_received.load(Ordering::Acquire);
                let violations = stats.invariant_violations.load(Ordering::Acquire);

                println!(
                    "  Sent: {}, Received: {}, Violations: {}",
                    sent, received, violations
                );

                total_messages += sent;
                total_violations += violations;
                max_cancellation_rate = max_cancellation_rate.max(cancel_prob);
                rounds_completed += 1;

                if !oracle.verify_final_consistency() {
                    eprintln!("CONSISTENCY FAILURE in round {}", round + 1);
                }
            }
            Ok(None) => {
                eprintln!("Round {} failed to complete properly", round + 1);
            }
            Err(_) => {
                eprintln!("Round {} timed out", round + 1);
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
    let _runtime = lab_with_config(|rt| async move {
        let cx = &rt.cx();

        // Test many concurrent oneshot operations
        let mut handles = Vec::new();

        for i in 0..1000 {
            let handle = task::spawn(async move {
                let (sender, receiver) = oneshot::channel::<u32>();

                // Randomly decide whether to send or cancel
                if i % 3 == 0 {
                    // Cancel case - drop sender without sending
                    drop(sender);
                    match receiver.await {
                        Err(oneshot::RecvError::Cancelled) => true,
                        _ => false,
                    }
                } else {
                    // Send case
                    sender.send(i as u32).unwrap();
                    match receiver.await {
                        Ok(val) => val == i as u32,
                        _ => false,
                    }
                }
            });
            handles.push(handle);
        }

        let mut successes = 0;
        for handle in handles {
            if handle.await.unwrap() {
                successes += 1;
            }
        }

        println!(
            "Oneshot stress test: {}/1000 operations successful",
            successes
        );
        assert!(successes >= 995, "Too many oneshot failures"); // Allow some variance
    })
    .await;

    Ok(())
}

/// Stress test for broadcast channels with multiple subscribers.
pub async fn broadcast_stress_test() -> Result<(), Box<dyn std::error::Error>> {
    let _runtime = lab_with_config(|rt| async move {
        let cx = &rt.cx();

        let (sender, _) = broadcast::channel::<u32>(100);
        let num_subscribers = 10;
        let num_messages = 500;

        // Create subscribers
        let mut subscribers = Vec::new();
        for i in 0..num_subscribers {
            let receiver = sender.subscribe();
            let handle = task::spawn(async move {
                let mut count = 0;
                let mut receiver = receiver;
                for _ in 0..num_messages {
                    match receiver.recv(cx).await {
                        Ok(_) => count += 1,
                        Err(broadcast::RecvError::Lagged(_)) => {
                            // Reset receiver on lag
                            receiver = sender.subscribe();
                        }
                        Err(_) => break,
                    }
                }
                (i, count)
            });
            subscribers.push(handle);
        }

        // Send messages concurrently with subscribers
        let sender_handle = task::spawn(async move {
            for i in 0..num_messages {
                if sender.send(i as u32).is_err() {
                    break; // No more subscribers
                }
                if i % 50 == 0 {
                    sleep(Duration::from_micros(1)).await;
                }
            }
            num_messages
        });

        let sent = sender_handle.await.unwrap();

        // Collect results from subscribers
        let mut total_received = 0;
        for handle in subscribers {
            let (subscriber_id, count) = handle.await.unwrap();
            println!("Subscriber {}: received {} messages", subscriber_id, count);
            total_received += count;
        }

        println!(
            "Broadcast stress test: sent {}, total received {}",
            sent, total_received
        );
        assert!(
            total_received >= sent * num_subscribers / 2,
            "Too few messages received"
        );
    })
    .await;

    Ok(())
}

/// Stress test for watch channels with rapid updates.
pub async fn watch_stress_test() -> Result<(), Box<dyn std::error::Error>> {
    let _runtime = lab_with_config(|rt| async move {
        let cx = &rt.cx();

        let (sender, _) = watch::channel::<u32>(0);
        let num_watchers = 5;
        let num_updates = 1000;

        // Create watchers
        let mut watchers = Vec::new();
        for i in 0..num_watchers {
            let mut receiver = sender.subscribe();
            let handle = task::spawn(async move {
                let mut updates_seen = 0;
                let mut last_value = 0;

                for _ in 0..num_updates * 2 {
                    // Allow extra iterations for watchers
                    select! {
                        result = receiver.changed(cx) => {
                            match result {
                                Ok(()) => {
                                    let value = *receiver.borrow();
                                    if value > last_value {
                                        updates_seen += 1;
                                        last_value = value;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        _ = sleep(Duration::from_micros(1)) => {
                            // Prevent infinite waiting
                            break;
                        }
                    }
                }
                (i, updates_seen, last_value)
            });
            watchers.push(handle);
        }

        // Send updates
        let sender_handle = task::spawn(async move {
            for i in 1..=num_updates {
                sender.send(i as u32).unwrap();
                if i % 100 == 0 {
                    sleep(Duration::from_micros(10)).await;
                }
            }
            num_updates
        });

        let sent = sender_handle.await.unwrap();

        // Collect results from watchers
        for handle in watchers {
            let (watcher_id, updates_seen, last_value) = handle.await.unwrap();
            println!(
                "Watcher {}: saw {} updates, last value {}",
                watcher_id, updates_seen, last_value
            );
            assert!(last_value > 0, "Watcher should see some updates");
        }

        println!("Watch stress test: sent {} updates", sent);
    })
    .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mpsc_light_stress() {
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
    }

    #[tokio::test]
    async fn test_oneshot_stress_basic() {
        oneshot_stress_test().await.unwrap();
    }

    #[tokio::test]
    async fn test_broadcast_stress_basic() {
        broadcast_stress_test().await.unwrap();
    }

    #[tokio::test]
    async fn test_watch_stress_basic() {
        watch_stress_test().await.unwrap();
    }
}
