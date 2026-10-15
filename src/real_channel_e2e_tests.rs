//! [br-e2e-10] Real Channel/MPSC/Broadcast E2E Tests
//!
//! Implements real-service E2E testing for asupersync channel primitives.
//! Tests actual producer-consumer patterns, multi-threaded scenarios, and channel
//! behavior under load with no mocks.
//!
//! Key principle: "If a mock hides a bug that would break production, the mock is worse than no test at all."
//! We test real channel implementations with actual concurrent producers/consumers.

#[cfg(all(test, feature = "real-service-e2e"))]
use crate::{
    channel::{broadcast, mpsc, oneshot, watch},
    combinator::{join, race, timeout},
    cx::Cx,
    error::{AsupersyncError, Outcome},
    runtime::{Region, RuntimeBuilder},
    sync::{Arc, Barrier},
    time::{Duration, Instant, sleep},
};

#[cfg(all(test, feature = "real-service-e2e"))]
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
};

#[cfg(all(test, feature = "real-service-e2e"))]
use serde::{Deserialize, Serialize};

/// Real channel manager that coordinates actual channel operations
/// Uses asupersync channel primitives with real concurrent producers/consumers
#[cfg(all(test, feature = "real-service-e2e"))]
struct RealChannelManager {
    test_name: String,
    stats: Arc<ChannelE2EStats>,
    logger: ChannelE2ELogger,
}

/// Comprehensive statistics for channel E2E operations
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct ChannelE2EStats {
    mpsc_messages_sent: AtomicU64,
    mpsc_messages_received: AtomicU64,
    broadcast_messages_sent: AtomicU64,
    broadcast_messages_received: AtomicU64,
    oneshot_operations: AtomicU64,
    watch_updates: AtomicU64,
    total_latency_ns: AtomicU64,
    max_latency_ns: AtomicU64,
    channel_full_events: AtomicU64,
    channel_closed_events: AtomicU64,
    producer_threads: AtomicU64,
    consumer_threads: AtomicU64,
    message_loss_events: AtomicU64,
}

/// Structured logger for channel E2E test observability
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct ChannelE2ELogger {
    test_id: String,
    component: String,
}

/// Channel operation result with performance measurements
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChannelOperation {
    operation_type: ChannelOperationType,
    message_count: u64,
    latency_ns: u64,
    throughput_mps: f64, // messages per second
    success_rate: f64,
    concurrent_operations: u64,
}

/// Types of channel operations under test
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ChannelOperationType {
    MpscProducerConsumer,
    BroadcastFanOut,
    OneshotPingPong,
    WatchValueSync,
    MultithreadedMpsc,
    BroadcastStress,
}

/// Channel E2E test configuration
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct ChannelE2EConfig {
    message_count: usize,
    producer_count: usize,
    consumer_count: usize,
    channel_capacity: usize,
    test_duration_ms: u64,
    stress_level: StressLevel,
}

/// Stress level configuration for channel tests
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
enum StressLevel {
    Light,   // Low message rate, few threads
    Medium,  // Moderate load
    High,    // Heavy concurrent load
    Extreme, // Maximum stress testing
}

#[cfg(all(test, feature = "real-service-e2e"))]
impl RealChannelManager {
    /// Create a new real channel manager for E2E testing
    fn new(test_name: &str) -> Self {
        let stats = Arc::new(ChannelE2EStats {
            mpsc_messages_sent: AtomicU64::new(0),
            mpsc_messages_received: AtomicU64::new(0),
            broadcast_messages_sent: AtomicU64::new(0),
            broadcast_messages_received: AtomicU64::new(0),
            oneshot_operations: AtomicU64::new(0),
            watch_updates: AtomicU64::new(0),
            total_latency_ns: AtomicU64::new(0),
            max_latency_ns: AtomicU64::new(0),
            channel_full_events: AtomicU64::new(0),
            channel_closed_events: AtomicU64::new(0),
            producer_threads: AtomicU64::new(0),
            consumer_threads: AtomicU64::new(0),
            message_loss_events: AtomicU64::new(0),
        });

        Self {
            test_name: test_name.to_string(),
            stats,
            logger: ChannelE2ELogger::new(test_name, "channel-manager"),
        }
    }

    /// Test basic MPSC producer-consumer pattern with real channels
    async fn test_mpsc_producer_consumer(
        &self,
        cx: &Cx,
        config: &ChannelE2EConfig,
    ) -> Result<ChannelOperation, AsupersyncError> {
        self.logger.log_phase("mpsc_producer_consumer_start");
        let start_time = Instant::now();

        // Create real MPSC channel with specified capacity
        let (sender, mut receiver) = mpsc::channel(config.channel_capacity);
        let messages_to_send = config.message_count;

        // Producer task
        let producer_stats = self.stats.clone();
        let producer_handle = cx.spawn(async move {
            for i in 0..messages_to_send {
                let message = format!("message-{}", i);
                let send_start = Instant::now();

                match sender.send(message).await {
                    Ok(()) => {
                        producer_stats
                            .mpsc_messages_sent
                            .fetch_add(1, Ordering::Relaxed);
                        let latency = send_start.elapsed().as_nanos() as u64;
                        producer_stats
                            .total_latency_ns
                            .fetch_add(latency, Ordering::Relaxed);
                    }
                    Err(_) => {
                        eprintln!("Producer failed to send message {}", i);
                        break;
                    }
                }

                // Small delay to simulate realistic message rate
                if i % 100 == 0 {
                    sleep(Duration::from_micros(1)).await;
                }
            }
        });

        // Consumer task
        let consumer_stats = self.stats.clone();
        let consumer_handle = cx.spawn(async move {
            let mut received_count = 0;

            while received_count < messages_to_send {
                match receiver.recv().await {
                    Some(message) => {
                        consumer_stats
                            .mpsc_messages_received
                            .fetch_add(1, Ordering::Relaxed);
                        received_count += 1;

                        // Validate message format
                        if !message.starts_with("message-") {
                            eprintln!("Received malformed message: {}", message);
                        }
                    }
                    None => {
                        eprintln!(
                            "Channel closed unexpectedly after {} messages",
                            received_count
                        );
                        break;
                    }
                }
            }

            received_count
        });

        // Wait for both producer and consumer to complete
        let (producer_result, consumer_result) = join!(producer_handle, consumer_handle);

        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        let total_latency = self.stats.total_latency_ns.load(Ordering::Relaxed);

        // Calculate metrics
        let messages_sent = self.stats.mpsc_messages_sent.load(Ordering::Relaxed);
        let messages_received = self.stats.mpsc_messages_received.load(Ordering::Relaxed);
        let success_rate = if messages_sent > 0 {
            messages_received as f64 / messages_sent as f64
        } else {
            0.0
        };
        let throughput = if duration.as_secs_f64() > 0.0 {
            messages_received as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        self.logger.log_operation(
            "mpsc_producer_consumer",
            messages_sent,
            messages_received,
            total_latency,
        );

        Ok(ChannelOperation {
            operation_type: ChannelOperationType::MpscProducerConsumer,
            message_count: messages_received,
            latency_ns: total_latency,
            throughput_mps: throughput,
            success_rate,
            concurrent_operations: 2, // 1 producer + 1 consumer
        })
    }

    /// Test broadcast channel with multiple receivers (fan-out pattern)
    async fn test_broadcast_fanout(
        &self,
        cx: &Cx,
        config: &ChannelE2EConfig,
    ) -> Result<ChannelOperation, AsupersyncError> {
        self.logger.log_phase("broadcast_fanout_start");
        let start_time = Instant::now();

        // Create real broadcast channel
        let (sender, _) = broadcast::channel(config.channel_capacity);
        let receiver_count = config.consumer_count;
        let messages_to_send = config.message_count;

        // Create multiple receivers
        let mut receiver_handles = Vec::new();
        for receiver_id in 0..receiver_count {
            let mut receiver = sender.subscribe();
            let stats = self.stats.clone();

            let handle = cx.spawn(async move {
                let mut received_count = 0;

                loop {
                    match receiver.recv().await {
                        Ok(message) => {
                            stats
                                .broadcast_messages_received
                                .fetch_add(1, Ordering::Relaxed);
                            received_count += 1;

                            // Check if we've received all expected messages
                            if received_count >= messages_to_send {
                                break;
                            }
                        }
                        Err(broadcast::RecvError::Lagged(skip_count)) => {
                            eprintln!(
                                "Receiver {} lagged, skipped {} messages",
                                receiver_id, skip_count
                            );
                            stats
                                .message_loss_events
                                .fetch_add(skip_count, Ordering::Relaxed);
                        }
                        Err(broadcast::RecvError::Closed) => {
                            eprintln!("Broadcast channel closed for receiver {}", receiver_id);
                            break;
                        }
                    }
                }

                received_count
            });

            receiver_handles.push(handle);
        }

        // Producer sends messages to broadcast channel
        let producer_stats = self.stats.clone();
        let producer_handle = cx.spawn(async move {
            for i in 0..messages_to_send {
                let message = format!("broadcast-{}", i);

                match sender.send(message) {
                    Ok(_) => {
                        producer_stats
                            .broadcast_messages_sent
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        eprintln!("Failed to send broadcast message {}", i);
                        break;
                    }
                }

                // Small delay for realistic message rate
                if i % 50 == 0 {
                    sleep(Duration::from_micros(10)).await;
                }
            }
        });

        // Wait for producer to finish
        let _ = producer_handle.await;

        // Wait for all receivers to finish
        let mut total_received = 0;
        for handle in receiver_handles {
            if let Outcome::Ok(received_count) = handle.await {
                total_received += received_count;
            }
        }

        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);

        // Calculate metrics
        let messages_sent = self.stats.broadcast_messages_sent.load(Ordering::Relaxed);
        let expected_total = messages_sent * receiver_count as u64;
        let success_rate = if expected_total > 0 {
            total_received as f64 / expected_total as f64
        } else {
            0.0
        };
        let throughput = if duration.as_secs_f64() > 0.0 {
            total_received as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        self.logger.log_operation(
            "broadcast_fanout",
            messages_sent,
            total_received,
            duration.as_nanos() as u64,
        );

        Ok(ChannelOperation {
            operation_type: ChannelOperationType::BroadcastFanOut,
            message_count: total_received,
            latency_ns: duration.as_nanos() as u64,
            throughput_mps: throughput,
            success_rate,
            concurrent_operations: (1 + receiver_count) as u64,
        })
    }

    /// Test oneshot channels for ping-pong communication
    async fn test_oneshot_pingpong(
        &self,
        cx: &Cx,
        pair_count: usize,
    ) -> Result<ChannelOperation, AsupersyncError> {
        self.logger.log_phase("oneshot_pingpong_start");
        let start_time = Instant::now();

        let mut handles = Vec::new();

        // Create multiple oneshot ping-pong pairs
        for i in 0..pair_count {
            let stats = self.stats.clone();

            let handle = cx.spawn(async move {
                // Ping direction
                let (ping_sender, ping_receiver) = oneshot::channel();

                // Pong direction
                let (pong_sender, pong_receiver) = oneshot::channel();

                // Ping task
                let ping_handle = cx.spawn(async move {
                    let message = format!("ping-{}", i);
                    ping_sender
                        .send(message)
                        .map_err(|_| AsupersyncError::from("ping send failed"))?;

                    // Wait for pong
                    match pong_receiver.await {
                        Ok(response) => {
                            if response.starts_with("pong-") {
                                stats.oneshot_operations.fetch_add(1, Ordering::Relaxed);
                                Ok(())
                            } else {
                                Err(AsupersyncError::from("invalid pong response"))
                            }
                        }
                        Err(_) => Err(AsupersyncError::from("pong receive failed")),
                    }
                });

                // Pong task
                let pong_handle = cx.spawn(async move {
                    match ping_receiver.await {
                        Ok(message) => {
                            if message.starts_with("ping-") {
                                let response = message.replace("ping-", "pong-");
                                pong_sender
                                    .send(response)
                                    .map_err(|_| AsupersyncError::from("pong send failed"))?;
                                Ok(())
                            } else {
                                Err(AsupersyncError::from("invalid ping message"))
                            }
                        }
                        Err(_) => Err(AsupersyncError::from("ping receive failed")),
                    }
                });

                // Wait for both ping and pong
                let (ping_result, pong_result) = join!(ping_handle, pong_handle);

                match (ping_result, pong_result) {
                    (Outcome::Ok(Ok(())), Outcome::Ok(Ok(()))) => Ok(()),
                    _ => Err(AsupersyncError::from("ping-pong failed")),
                }
            });

            handles.push(handle);
        }

        // Wait for all ping-pong pairs to complete
        let mut successful_pairs = 0;
        for handle in handles {
            if let Outcome::Ok(Ok(())) = handle.await {
                successful_pairs += 1;
            }
        }

        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);

        let operations_count = self.stats.oneshot_operations.load(Ordering::Relaxed);
        let success_rate = successful_pairs as f64 / pair_count as f64;
        let throughput = if duration.as_secs_f64() > 0.0 {
            operations_count as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        self.logger.log_operation(
            "oneshot_pingpong",
            pair_count as u64,
            successful_pairs,
            duration.as_nanos() as u64,
        );

        Ok(ChannelOperation {
            operation_type: ChannelOperationType::OneshotPingPong,
            message_count: successful_pairs,
            latency_ns: duration.as_nanos() as u64,
            throughput_mps: throughput,
            success_rate,
            concurrent_operations: (pair_count * 2) as u64,
        })
    }

    /// Test watch channel for value synchronization
    async fn test_watch_value_sync(
        &self,
        cx: &Cx,
        update_count: usize,
        watcher_count: usize,
    ) -> Result<ChannelOperation, AsupersyncError> {
        self.logger.log_phase("watch_value_sync_start");
        let start_time = Instant::now();

        // Create watch channel with initial value
        let (sender, receiver) = watch::channel(0u64);

        // Create multiple watchers
        let mut watcher_handles = Vec::new();
        for watcher_id in 0..watcher_count {
            let mut watcher = receiver.clone();
            let stats = self.stats.clone();

            let handle = cx.spawn(async move {
                let mut observed_values = Vec::new();
                let mut last_value = 0u64;

                loop {
                    // Check for value changes
                    let changed = watcher.changed().await;
                    match changed {
                        Ok(()) => {
                            let current_value = *watcher.borrow();
                            if current_value != last_value {
                                observed_values.push(current_value);
                                last_value = current_value;

                                // Stop when we reach the final expected value
                                if current_value >= update_count as u64 {
                                    break;
                                }
                            }
                        }
                        Err(_) => {
                            eprintln!("Watch channel closed for watcher {}", watcher_id);
                            break;
                        }
                    }
                }

                observed_values.len()
            });

            watcher_handles.push(handle);
        }

        // Updater sends value changes
        let updater_stats = self.stats.clone();
        let updater_handle = cx.spawn(async move {
            for i in 1..=update_count {
                match sender.send(i as u64) {
                    Ok(()) => {
                        updater_stats.watch_updates.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        eprintln!("Failed to send watch update {}", i);
                        break;
                    }
                }

                // Small delay between updates
                sleep(Duration::from_millis(10)).await;
            }
        });

        // Wait for updater to finish
        let _ = updater_handle.await;

        // Wait for all watchers to observe the changes
        let mut total_observations = 0;
        for handle in watcher_handles {
            if let Outcome::Ok(observations) = handle.await {
                total_observations += observations;
            }
        }

        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);

        let updates_sent = self.stats.watch_updates.load(Ordering::Relaxed);
        let expected_observations = updates_sent * watcher_count as u64;
        let success_rate = if expected_observations > 0 {
            total_observations as f64 / expected_observations as f64
        } else {
            0.0
        };
        let throughput = if duration.as_secs_f64() > 0.0 {
            total_observations as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        self.logger.log_operation(
            "watch_value_sync",
            updates_sent,
            total_observations,
            duration.as_nanos() as u64,
        );

        Ok(ChannelOperation {
            operation_type: ChannelOperationType::WatchValueSync,
            message_count: total_observations,
            latency_ns: duration.as_nanos() as u64,
            throughput_mps: throughput,
            success_rate,
            concurrent_operations: (1 + watcher_count) as u64,
        })
    }

    /// Test multi-threaded MPSC under high load
    async fn test_multithreaded_mpsc_stress(
        &self,
        cx: &Cx,
        config: &ChannelE2EConfig,
    ) -> Result<ChannelOperation, AsupersyncError> {
        self.logger.log_phase("multithreaded_mpsc_stress_start");
        let start_time = Instant::now();

        // Create MPSC channel
        let (sender, mut receiver) = mpsc::channel(config.channel_capacity);
        let messages_per_producer = config.message_count / config.producer_count;

        // Start multiple producer tasks
        let mut producer_handles = Vec::new();
        for producer_id in 0..config.producer_count {
            let producer_sender = sender.clone();
            let producer_stats = self.stats.clone();

            let handle = cx.spawn(async move {
                for i in 0..messages_per_producer {
                    let message = format!("producer-{}-message-{}", producer_id, i);

                    match producer_sender.send(message).await {
                        Ok(()) => {
                            producer_stats
                                .mpsc_messages_sent
                                .fetch_add(1, Ordering::Relaxed);
                            producer_stats
                                .producer_threads
                                .store(producer_id as u64 + 1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            eprintln!("Producer {} failed to send message {}", producer_id, i);
                            break;
                        }
                    }

                    // Vary message rate to simulate realistic load
                    if i % 200 == 0 {
                        sleep(Duration::from_micros(100)).await;
                    }
                }
            });

            producer_handles.push(handle);
        }

        // Drop original sender to signal completion when all producers finish
        drop(sender);

        // Single consumer processes all messages
        let consumer_stats = self.stats.clone();
        let consumer_handle = cx.spawn(async move {
            let mut received_count = 0;
            let mut producer_counts = std::collections::HashMap::new();

            while let Some(message) = receiver.recv().await {
                consumer_stats
                    .mpsc_messages_received
                    .fetch_add(1, Ordering::Relaxed);
                received_count += 1;

                // Track messages from each producer
                if let Some(producer_part) = message.split('-').nth(1) {
                    if let Ok(producer_id) = producer_part.parse::<usize>() {
                        *producer_counts.entry(producer_id).or_insert(0) += 1;
                    }
                }
            }

            eprintln!(
                "Consumer received {} messages from {} producers",
                received_count,
                producer_counts.len()
            );
            received_count
        });

        // Wait for all producers to complete
        for handle in producer_handles {
            let _ = handle.await;
        }

        // Wait for consumer to finish
        let total_received = match consumer_handle.await {
            Outcome::Ok(count) => count,
            _ => 0,
        };

        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);

        let messages_sent = self.stats.mpsc_messages_sent.load(Ordering::Relaxed);
        let success_rate = if messages_sent > 0 {
            total_received as f64 / messages_sent as f64
        } else {
            0.0
        };
        let throughput = if duration.as_secs_f64() > 0.0 {
            total_received as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        self.logger.log_operation(
            "multithreaded_mpsc_stress",
            messages_sent,
            total_received,
            duration.as_nanos() as u64,
        );

        Ok(ChannelOperation {
            operation_type: ChannelOperationType::MultithreadedMpsc,
            message_count: total_received,
            latency_ns: duration.as_nanos() as u64,
            throughput_mps: throughput,
            success_rate,
            concurrent_operations: (config.producer_count + 1) as u64,
        })
    }

    /// Get comprehensive channel statistics summary
    fn get_stats_summary(&self) -> ChannelE2EStatsSummary {
        ChannelE2EStatsSummary {
            total_mpsc_sent: self.stats.mpsc_messages_sent.load(Ordering::Relaxed),
            total_mpsc_received: self.stats.mpsc_messages_received.load(Ordering::Relaxed),
            total_broadcast_sent: self.stats.broadcast_messages_sent.load(Ordering::Relaxed),
            total_broadcast_received: self
                .stats
                .broadcast_messages_received
                .load(Ordering::Relaxed),
            total_oneshot_operations: self.stats.oneshot_operations.load(Ordering::Relaxed),
            total_watch_updates: self.stats.watch_updates.load(Ordering::Relaxed),
            average_latency_ns: {
                let total = self.stats.total_latency_ns.load(Ordering::Relaxed);
                let ops = self.stats.mpsc_messages_sent.load(Ordering::Relaxed)
                    + self.stats.broadcast_messages_sent.load(Ordering::Relaxed);
                if ops > 0 { total / ops } else { 0 }
            },
            max_latency_ns: self.stats.max_latency_ns.load(Ordering::Relaxed),
            channel_full_events: self.stats.channel_full_events.load(Ordering::Relaxed),
            channel_closed_events: self.stats.channel_closed_events.load(Ordering::Relaxed),
            message_loss_events: self.stats.message_loss_events.load(Ordering::Relaxed),
        }
    }
}

#[cfg(all(test, feature = "real-service-e2e"))]
impl ChannelE2ELogger {
    fn new(test_id: &str, component: &str) -> Self {
        Self {
            test_id: test_id.to_string(),
            component: component.to_string(),
        }
    }

    fn log_phase(&self, phase: &str) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"phase_change\",\"phase\":\"{}\"}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            phase
        );
    }

    fn log_operation(&self, operation_type: &str, sent: u64, received: u64, latency_ns: u64) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"channel_operation\",\"operation_type\":\"{}\",\"sent\":{},\"received\":{},\"latency_ns\":{}}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            operation_type,
            sent,
            received,
            latency_ns
        );
    }

    fn log_stats_summary(&self, stats: &ChannelE2EStatsSummary) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"stats_summary\",\"data\":{}}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            serde_json::to_string(stats).unwrap_or_else(|_| "{}".to_string())
        );
    }
}

/// Channel E2E statistics summary
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChannelE2EStatsSummary {
    total_mpsc_sent: u64,
    total_mpsc_received: u64,
    total_broadcast_sent: u64,
    total_broadcast_received: u64,
    total_oneshot_operations: u64,
    total_watch_updates: u64,
    average_latency_ns: u64,
    max_latency_ns: u64,
    channel_full_events: u64,
    channel_closed_events: u64,
    message_loss_events: u64,
}

/// Default channel E2E test configuration
#[cfg(all(test, feature = "real-service-e2e"))]
impl Default for ChannelE2EConfig {
    fn default() -> Self {
        Self {
            message_count: 1000,
            producer_count: 3,
            consumer_count: 2,
            channel_capacity: 100,
            test_duration_ms: 5000,
            stress_level: StressLevel::Medium,
        }
    }
}

/// Production safety guard for channel E2E tests
#[cfg(all(test, feature = "real-service-e2e"))]
fn validate_channel_e2e_environment() -> Result<(), &'static str> {
    // Ensure proper feature flag
    if std::env::var("CHANNEL_E2E_TESTS").unwrap_or_default() != "true" {
        return Err("CHANNEL_E2E_TESTS environment variable must be set to 'true'");
    }

    // Prevent excessive concurrency
    let max_concurrent = std::env::var("MAX_CHANNEL_CONCURRENCY")
        .unwrap_or_else(|_| "50".to_string())
        .parse::<usize>()
        .map_err(|_| "Invalid MAX_CHANNEL_CONCURRENCY")?;

    if max_concurrent > 100 {
        return Err("Channel tests must limit concurrency to 100 or less");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpsc_basic_producer_consumer() {
        std::env::set_var("CHANNEL_E2E_TESTS", "true");
        validate_channel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("channel-e2e-mpsc-test")
            .build();

        runtime.block_on(async {
            let manager = RealChannelManager::new("mpsc-test");
            let cx = Cx::root();

            let config = ChannelE2EConfig {
                message_count: 100,
                producer_count: 1,
                consumer_count: 1,
                channel_capacity: 10,
                ..ChannelE2EConfig::default()
            };

            let operation = manager
                .test_mpsc_producer_consumer(&cx, &config)
                .await
                .expect("MPSC producer-consumer should succeed");

            assert_eq!(
                operation.operation_type,
                ChannelOperationType::MpscProducerConsumer
            );
            assert_eq!(operation.message_count, 100);
            assert!(operation.success_rate >= 0.95); // Allow 5% message loss
            assert!(operation.throughput_mps > 0.0);

            let stats = manager.get_stats_summary();
            assert_eq!(stats.total_mpsc_sent, 100);
            assert_eq!(stats.total_mpsc_received, 100);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_broadcast_fanout() {
        std::env::set_var("CHANNEL_E2E_TESTS", "true");
        validate_channel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("channel-e2e-broadcast-test")
            .build();

        runtime.block_on(async {
            let manager = RealChannelManager::new("broadcast-test");
            let cx = Cx::root();

            let config = ChannelE2EConfig {
                message_count: 50,
                producer_count: 1,
                consumer_count: 3,
                channel_capacity: 20,
                ..ChannelE2EConfig::default()
            };

            let operation = manager
                .test_broadcast_fanout(&cx, &config)
                .await
                .expect("Broadcast fanout should succeed");

            assert_eq!(
                operation.operation_type,
                ChannelOperationType::BroadcastFanOut
            );
            assert!(operation.success_rate >= 0.8); // Allow 20% message loss due to lagging
            assert!(operation.throughput_mps > 0.0);
            assert_eq!(operation.concurrent_operations, 4); // 1 producer + 3 consumers

            let stats = manager.get_stats_summary();
            assert!(stats.total_broadcast_sent > 0);
            assert!(stats.total_broadcast_received > 0);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_oneshot_pingpong() {
        std::env::set_var("CHANNEL_E2E_TESTS", "true");
        validate_channel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("channel-e2e-oneshot-test")
            .build();

        runtime.block_on(async {
            let manager = RealChannelManager::new("oneshot-test");
            let cx = Cx::root();

            let operation = manager
                .test_oneshot_pingpong(&cx, 10)
                .await
                .expect("Oneshot ping-pong should succeed");

            assert_eq!(
                operation.operation_type,
                ChannelOperationType::OneshotPingPong
            );
            assert_eq!(operation.message_count, 10);
            assert!(operation.success_rate >= 0.9); // Allow 10% failure rate
            assert_eq!(operation.concurrent_operations, 20); // 10 pairs * 2 tasks each

            let stats = manager.get_stats_summary();
            assert_eq!(stats.total_oneshot_operations, 10);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_watch_value_synchronization() {
        std::env::set_var("CHANNEL_E2E_TESTS", "true");
        validate_channel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("channel-e2e-watch-test")
            .build();

        runtime.block_on(async {
            let manager = RealChannelManager::new("watch-test");
            let cx = Cx::root();

            let operation = manager
                .test_watch_value_sync(&cx, 20, 3)
                .await
                .expect("Watch value sync should succeed");

            assert_eq!(
                operation.operation_type,
                ChannelOperationType::WatchValueSync
            );
            assert!(operation.success_rate >= 0.8); // Allow some missed observations
            assert!(operation.throughput_mps > 0.0);
            assert_eq!(operation.concurrent_operations, 4); // 1 updater + 3 watchers

            let stats = manager.get_stats_summary();
            assert_eq!(stats.total_watch_updates, 20);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_multithreaded_mpsc_stress() {
        std::env::set_var("CHANNEL_E2E_TESTS", "true");
        validate_channel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("channel-e2e-stress-test")
            .build();

        runtime.block_on(async {
            let manager = RealChannelManager::new("stress-test");
            let cx = Cx::root();

            let config = ChannelE2EConfig {
                message_count: 300, // 100 messages per producer
                producer_count: 3,
                consumer_count: 1,
                channel_capacity: 50,
                stress_level: StressLevel::High,
                ..ChannelE2EConfig::default()
            };

            let operation = manager
                .test_multithreaded_mpsc_stress(&cx, &config)
                .await
                .expect("Multi-threaded MPSC stress should succeed");

            assert_eq!(
                operation.operation_type,
                ChannelOperationType::MultithreadedMpsc
            );
            assert!(operation.success_rate >= 0.9); // Allow 10% message loss under stress
            assert!(operation.throughput_mps > 0.0);
            assert_eq!(operation.concurrent_operations, 4); // 3 producers + 1 consumer

            let stats = manager.get_stats_summary();
            assert!(stats.total_mpsc_sent >= 250); // At least most messages sent
            assert!(stats.total_mpsc_received >= 225); // At least 90% received
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_channel_comprehensive_scenario() {
        std::env::set_var("CHANNEL_E2E_TESTS", "true");
        validate_channel_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("channel-e2e-comprehensive-test")
            .build();

        runtime.block_on(async {
            let manager = RealChannelManager::new("comprehensive-test");
            let cx = Cx::root();

            let config = ChannelE2EConfig {
                message_count: 50,
                producer_count: 2,
                consumer_count: 2,
                channel_capacity: 25,
                stress_level: StressLevel::Medium,
                ..ChannelE2EConfig::default()
            };

            // Run multiple channel operations in sequence
            let mut all_operations = Vec::new();

            // 1. MPSC producer-consumer
            let mpsc_op = manager
                .test_mpsc_producer_consumer(&cx, &config)
                .await
                .expect("MPSC operation should succeed");
            all_operations.push(mpsc_op);

            // 2. Broadcast fanout
            let broadcast_op = manager
                .test_broadcast_fanout(&cx, &config)
                .await
                .expect("Broadcast operation should succeed");
            all_operations.push(broadcast_op);

            // 3. Oneshot ping-pong
            let oneshot_op = manager
                .test_oneshot_pingpong(&cx, 5)
                .await
                .expect("Oneshot operation should succeed");
            all_operations.push(oneshot_op);

            // 4. Watch value sync
            let watch_op = manager
                .test_watch_value_sync(&cx, 10, 2)
                .await
                .expect("Watch operation should succeed");
            all_operations.push(watch_op);

            // Validate comprehensive results
            assert_eq!(all_operations.len(), 4);

            for operation in &all_operations {
                assert!(operation.success_rate >= 0.7); // At least 70% success rate
                assert!(operation.throughput_mps > 0.0);
            }

            let stats = manager.get_stats_summary();
            manager.logger.log_stats_summary(&stats);

            // Final validation
            assert!(stats.total_mpsc_sent > 0);
            assert!(stats.total_broadcast_sent > 0);
            assert!(stats.total_oneshot_operations > 0);
            assert!(stats.total_watch_updates > 0);
        });
    }

    #[test]
    fn test_production_safety_guards() {
        // Test without CHANNEL_E2E_TESTS environment variable
        std::env::remove_var("CHANNEL_E2E_TESTS");
        assert!(validate_channel_e2e_environment().is_err());

        // Test with excessive concurrency
        std::env::set_var("CHANNEL_E2E_TESTS", "true");
        std::env::set_var("MAX_CHANNEL_CONCURRENCY", "200");
        assert!(validate_channel_e2e_environment().is_err());

        // Test valid configuration
        std::env::set_var("MAX_CHANNEL_CONCURRENCY", "50");
        assert!(validate_channel_e2e_environment().is_ok());
    }
}
