//! Real E2E integration tests: channel/broadcast ↔ stream/broadcast_stream (br-e2e-179).
//!
//! Tests that broadcast channels correctly integrate with broadcast stream adapters
//! for seamless streaming from broadcast receivers. Verifies the integration between:
//!
//! - `channel::broadcast`: Multi-producer, multi-consumer broadcast channels
//! - `stream::broadcast_stream`: Stream adapters for broadcast receivers
//!
//! Key integration properties:
//! - BroadcastStream properly adapts broadcast::Receiver to Stream trait
//! - Backpressure handling between broadcast channels and stream consumers
//! - Error propagation (lagged messages, closure) from broadcast to stream
//! - Stream combinators work correctly with broadcast-backed streams
//! - Multiple concurrent stream consumers from single broadcast channel
//! - Two-phase broadcast semantics preserved through stream interface

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::{
        channel::broadcast::{self, RecvError, SendError, TryRecvError},
        cx::{Cx, Scope},
        error::{Error, Result},
        runtime::{Runtime, spawn},
        stream::{
            Stream, StreamExt,
            broadcast_stream::{BroadcastStream, BroadcastStreamRecvError},
        },
        sync::{Arc, Mutex, RwLock},
        time::{Duration, Instant, sleep},
        types::{Budget, Outcome, TaskId},
    };
    use std::{
        collections::{HashMap, VecDeque},
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // Broadcast + BroadcastStream Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BroadcastStreamTestPhase {
        Setup,
        CreateBroadcastChannel,
        AttachStreamAdapters,
        TestBasicStreamIntegration,
        TestBackpressureHandling,
        TestErrorPropagation,
        TestStreamCombinators,
        TestMultipleConsumers,
        TestLaggedMessageHandling,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone)]
    pub struct BroadcastStreamTestResult {
        pub test_name: String,
        pub phase: BroadcastStreamTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub integration_stats: BroadcastStreamStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct BroadcastStreamStats {
        pub messages_sent: u64,
        pub messages_received_via_streams: u64,
        pub stream_adapters_created: u64,
        pub lagged_errors_handled: u64,
        pub stream_combinators_applied: u64,
        pub concurrent_stream_consumers: u64,
        pub backpressure_events: u64,
        pub channel_closure_propagated: u64,
    }

    /// Test framework for broadcast channel + stream integration
    #[derive(Debug)]
    struct BroadcastStreamTestFramework {
        runtime: Runtime,
        sender: Arc<Mutex<Option<broadcast::Sender<TestMessage>>>>,
        receivers: Arc<Mutex<Vec<broadcast::Receiver<TestMessage>>>>,
        streams: Arc<Mutex<Vec<BroadcastStream<TestMessage>>>>,
        stats: Arc<Mutex<BroadcastStreamStats>>,
        message_collector: Arc<MessageCollector>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestMessage {
        id: u64,
        content: String,
        timestamp: u64,
        priority: MessagePriority,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MessagePriority {
        Low,
        Normal,
        High,
        Critical,
    }

    #[derive(Debug)]
    struct MessageCollector {
        received_messages: Arc<RwLock<HashMap<String, Vec<TestMessage>>>>,
        error_messages: Arc<Mutex<Vec<(String, BroadcastStreamRecvError)>>>,
    }

    impl MessageCollector {
        fn new() -> Self {
            Self {
                received_messages: Arc::new(RwLock::new(HashMap::new())),
                error_messages: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn record_message(&self, consumer_id: String, message: TestMessage) {
            self.received_messages
                .write()
                .unwrap()
                .entry(consumer_id)
                .or_insert_with(Vec::new)
                .push(message);
        }

        fn record_error(&self, consumer_id: String, error: BroadcastStreamRecvError) {
            self.error_messages
                .lock()
                .unwrap()
                .push((consumer_id, error));
        }

        fn get_messages(&self, consumer_id: &str) -> Vec<TestMessage> {
            self.received_messages
                .read()
                .unwrap()
                .get(consumer_id)
                .cloned()
                .unwrap_or_default()
        }

        fn get_errors(&self) -> Vec<(String, BroadcastStreamRecvError)> {
            self.error_messages.lock().unwrap().clone()
        }

        fn total_messages_received(&self) -> u64 {
            self.received_messages
                .read()
                .unwrap()
                .values()
                .map(|msgs| msgs.len() as u64)
                .sum()
        }

        fn total_errors(&self) -> u64 {
            self.error_messages.lock().unwrap().len() as u64
        }
    }

    impl BroadcastStreamTestFramework {
        fn new(channel_capacity: usize) -> Result<Self> {
            let runtime = Runtime::new()?;
            let (sender, receiver) = broadcast::channel(channel_capacity);

            Ok(Self {
                runtime,
                sender: Arc::new(Mutex::new(Some(sender))),
                receivers: Arc::new(Mutex::new(vec![receiver])),
                streams: Arc::new(Mutex::new(Vec::new())),
                stats: Arc::new(Mutex::new(BroadcastStreamStats::default())),
                message_collector: Arc::new(MessageCollector::new()),
            })
        }

        async fn execute_integration_test(&self, cx: &Cx) -> Result<BroadcastStreamTestResult> {
            let start_time = Instant::now();
            let mut stats = BroadcastStreamStats::default();

            // Phase 1: Test basic broadcast → stream integration
            self.test_basic_stream_integration(cx, &mut stats).await?;

            // Phase 2: Test backpressure handling
            self.test_backpressure_handling(cx, &mut stats).await?;

            // Phase 3: Test error propagation
            self.test_error_propagation(cx, &mut stats).await?;

            // Phase 4: Test stream combinators with broadcast streams
            self.test_stream_combinators(cx, &mut stats).await?;

            // Phase 5: Test multiple concurrent consumers
            self.test_multiple_consumers(cx, &mut stats).await?;

            // Phase 6: Test lagged message handling
            self.test_lagged_message_handling(cx, &mut stats).await?;

            let duration = start_time.elapsed();

            Ok(BroadcastStreamTestResult {
                test_name: "broadcast_stream_integration".to_string(),
                phase: BroadcastStreamTestPhase::Assert,
                success: self.verify_integration_properties(&stats).await?,
                error: None,
                duration_ms: duration.as_millis() as u64,
                integration_stats: stats,
            })
        }

        async fn test_basic_stream_integration(
            &self,
            cx: &Cx,
            stats: &mut BroadcastStreamStats,
        ) -> Result<()> {
            // Create broadcast stream adapter
            let receiver = {
                let sender = self.sender.lock().unwrap();
                let sender = sender.as_ref().unwrap();
                sender.subscribe()
            };

            let mut broadcast_stream = BroadcastStream::new(cx.clone(), receiver);
            stats.stream_adapters_created += 1;

            // Send messages via broadcast channel
            let messages = vec![
                TestMessage {
                    id: 1,
                    content: "Hello from broadcast".to_string(),
                    timestamp: 1000,
                    priority: MessagePriority::Normal,
                },
                TestMessage {
                    id: 2,
                    content: "Stream integration test".to_string(),
                    timestamp: 2000,
                    priority: MessagePriority::High,
                },
                TestMessage {
                    id: 3,
                    content: "Broadcast → Stream".to_string(),
                    timestamp: 3000,
                    priority: MessagePriority::Critical,
                },
            ];

            let sender = self.sender.lock().unwrap();
            let sender = sender.as_ref().unwrap();

            for msg in &messages {
                sender.send(msg.clone()).await?;
                stats.messages_sent += 1;
            }

            // Receive messages via stream interface
            let consumer_id = "basic_integration".to_string();
            let received_count = self
                .consume_stream_messages(cx, &mut broadcast_stream, &consumer_id, messages.len())
                .await?;

            stats.messages_received_via_streams += received_count;

            // Verify all messages received correctly
            let received_messages = self.message_collector.get_messages(&consumer_id);
            assert_eq!(received_messages.len(), messages.len());

            for (i, expected) in messages.iter().enumerate() {
                assert_eq!(&received_messages[i], expected);
            }

            Ok(())
        }

        async fn test_backpressure_handling(
            &self,
            cx: &Cx,
            stats: &mut BroadcastStreamStats,
        ) -> Result<()> {
            // Create slow consumer stream
            let receiver = {
                let sender = self.sender.lock().unwrap();
                sender.as_ref().unwrap().subscribe()
            };

            let mut slow_stream = BroadcastStream::new(cx.clone(), receiver);
            stats.stream_adapters_created += 1;

            // Send messages faster than stream can consume
            let fast_sender_task = spawn(cx, async {
                let sender = self.sender.lock().unwrap();
                let sender = sender.as_ref().unwrap().clone();
                drop(self.sender.lock().unwrap()); // Release lock

                for i in 0..20 {
                    let msg = TestMessage {
                        id: 100 + i,
                        content: format!("Fast message {}", i),
                        timestamp: 5000 + i * 100,
                        priority: MessagePriority::Normal,
                    };

                    sender.send(msg).await?;
                    stats.messages_sent += 1;

                    // Send quickly
                    sleep(Duration::from_millis(10)).await;
                }
                Ok::<(), Error>(())
            })
            .await;

            // Consume slowly to create backpressure
            let slow_consumer_task = spawn(cx, async {
                let consumer_id = "backpressure_test".to_string();
                let mut received = 0;

                while received < 15 {
                    // Don't consume all to test backpressure
                    match slow_stream.next().await {
                        Some(Ok(msg)) => {
                            self.message_collector
                                .record_message(consumer_id.clone(), msg);
                            received += 1;
                            stats.messages_received_via_streams += 1;

                            // Consume slowly
                            sleep(Duration::from_millis(50)).await;
                        }
                        Some(Err(BroadcastStreamRecvError::Lagged(_))) => {
                            // Backpressure caused lagging
                            stats.backpressure_events += 1;
                            break;
                        }
                        None => break,
                    }
                }

                Ok::<(), Error>(())
            })
            .await;

            // Wait for both tasks
            fast_sender_task?;
            slow_consumer_task?;

            Ok(())
        }

        async fn test_error_propagation(
            &self,
            cx: &Cx,
            stats: &mut BroadcastStreamStats,
        ) -> Result<()> {
            // Create stream that will experience lagged errors
            let receiver = {
                let sender = self.sender.lock().unwrap();
                sender.as_ref().unwrap().subscribe()
            };

            let mut lagged_stream = BroadcastStream::new(cx.clone(), receiver);
            stats.stream_adapters_created += 1;

            // Fill up channel to cause lagging
            let sender = self.sender.lock().unwrap();
            let sender = sender.as_ref().unwrap();

            // Send many messages quickly to overflow receiver buffer
            for i in 0..50 {
                let msg = TestMessage {
                    id: 200 + i,
                    content: format!("Overflow message {}", i),
                    timestamp: 10000 + i * 10,
                    priority: MessagePriority::Low,
                };

                sender.send(msg).await?;
                stats.messages_sent += 1;
            }

            // Try to consume from lagged stream
            let consumer_id = "error_propagation".to_string();
            let mut lagged_errors = 0;

            for _ in 0..10 {
                match lagged_stream.next().await {
                    Some(Ok(msg)) => {
                        self.message_collector
                            .record_message(consumer_id.clone(), msg);
                        stats.messages_received_via_streams += 1;
                    }
                    Some(Err(BroadcastStreamRecvError::Lagged(count))) => {
                        self.message_collector.record_error(
                            consumer_id.clone(),
                            BroadcastStreamRecvError::Lagged(count),
                        );
                        lagged_errors += 1;
                        stats.lagged_errors_handled += 1;
                        break; // Exit after first lagged error
                    }
                    None => break,
                }
            }

            assert!(lagged_errors > 0, "Should have encountered lagged errors");

            // Test channel closure propagation
            drop(sender);
            *self.sender.lock().unwrap() = None;

            // Stream should eventually return None after channel closure
            let mut channel_closed = false;
            for _ in 0..5 {
                match lagged_stream.next().await {
                    None => {
                        channel_closed = true;
                        stats.channel_closure_propagated += 1;
                        break;
                    }
                    Some(Ok(_)) => {
                        // May still have buffered messages
                        continue;
                    }
                    Some(Err(_)) => {
                        // May still have errors
                        continue;
                    }
                }
            }

            assert!(
                channel_closed,
                "Stream should terminate after channel closure"
            );

            Ok(())
        }

        async fn test_stream_combinators(
            &self,
            cx: &Cx,
            stats: &mut BroadcastStreamStats,
        ) -> Result<()> {
            // Recreate channel for combinator tests
            let (sender, receiver) = broadcast::channel(32);
            *self.sender.lock().unwrap() = Some(sender);

            let broadcast_stream = BroadcastStream::new(cx.clone(), receiver);
            stats.stream_adapters_created += 1;

            // Test filter combinator with broadcast stream
            let filtered_stream = broadcast_stream.filter(|result| {
                if let Ok(msg) = result {
                    msg.priority == MessagePriority::High
                        || msg.priority == MessagePriority::Critical
                } else {
                    true // Pass through errors
                }
            });

            stats.stream_combinators_applied += 1;

            // Send mixed priority messages
            let test_messages = vec![
                TestMessage {
                    id: 301,
                    content: "Low priority".to_string(),
                    timestamp: 20000,
                    priority: MessagePriority::Low,
                },
                TestMessage {
                    id: 302,
                    content: "High priority".to_string(),
                    timestamp: 20100,
                    priority: MessagePriority::High,
                },
                TestMessage {
                    id: 303,
                    content: "Normal priority".to_string(),
                    timestamp: 20200,
                    priority: MessagePriority::Normal,
                },
                TestMessage {
                    id: 304,
                    content: "Critical priority".to_string(),
                    timestamp: 20300,
                    priority: MessagePriority::Critical,
                },
            ];

            let sender = self.sender.lock().unwrap();
            let sender = sender.as_ref().unwrap().clone();
            drop(self.sender.lock().unwrap());

            for msg in &test_messages {
                sender.send(msg.clone()).await?;
                stats.messages_sent += 1;
            }

            // Consume filtered messages
            let consumer_id = "combinator_test".to_string();
            let mut filtered_count = 0;

            let mut filtered_stream = Box::pin(filtered_stream);

            for _ in 0..test_messages.len() {
                match filtered_stream.next().await {
                    Some(Ok(msg)) => {
                        // Should only receive High and Critical priority messages
                        assert!(matches!(
                            msg.priority,
                            MessagePriority::High | MessagePriority::Critical
                        ));
                        self.message_collector
                            .record_message(consumer_id.clone(), msg);
                        filtered_count += 1;
                        stats.messages_received_via_streams += 1;
                    }
                    Some(Err(e)) => {
                        self.message_collector.record_error(consumer_id.clone(), e);
                    }
                    None => break,
                }
            }

            // Should have received exactly 2 messages (High and Critical)
            assert_eq!(filtered_count, 2);

            Ok(())
        }

        async fn test_multiple_consumers(
            &self,
            cx: &Cx,
            stats: &mut BroadcastStreamStats,
        ) -> Result<()> {
            // Create multiple stream consumers
            let num_consumers = 5;
            let mut consumer_tasks = Vec::new();

            for i in 0..num_consumers {
                let receiver = {
                    let sender = self.sender.lock().unwrap();
                    sender.as_ref().unwrap().subscribe()
                };

                let consumer_stream = BroadcastStream::new(cx.clone(), receiver);
                stats.stream_adapters_created += 1;
                stats.concurrent_stream_consumers += 1;

                let consumer_id = format!("consumer_{}", i);
                let message_collector = self.message_collector.clone();

                let task = spawn(cx, async move {
                    let mut stream = consumer_stream;
                    let mut received_count = 0;

                    while received_count < 10 {
                        match stream.next().await {
                            Some(Ok(msg)) => {
                                message_collector.record_message(consumer_id.clone(), msg);
                                received_count += 1;
                            }
                            Some(Err(e)) => {
                                message_collector.record_error(consumer_id.clone(), e);
                            }
                            None => break,
                        }
                    }

                    received_count
                })
                .await;

                consumer_tasks.push(task);
            }

            // Send messages to all consumers
            let sender = self.sender.lock().unwrap();
            let sender = sender.as_ref().unwrap();

            for i in 0..10 {
                let msg = TestMessage {
                    id: 400 + i,
                    content: format!("Multi-consumer message {}", i),
                    timestamp: 30000 + i * 100,
                    priority: MessagePriority::Normal,
                };

                sender.send(msg).await?;
                stats.messages_sent += 1;
            }

            // Wait for all consumers to finish
            let mut total_received = 0;
            for task in consumer_tasks {
                let received = task.await?;
                total_received += received;
                stats.messages_received_via_streams += received;
            }

            // Each consumer should receive all messages (fan-out behavior)
            assert_eq!(total_received, 10 * num_consumers as u64);

            Ok(())
        }

        async fn test_lagged_message_handling(
            &self,
            cx: &Cx,
            stats: &mut BroadcastStreamStats,
        ) -> Result<()> {
            // Create stream with small buffer to force lagging
            let (sender, receiver) = broadcast::channel(5); // Small capacity
            *self.sender.lock().unwrap() = Some(sender);

            let mut stream = BroadcastStream::new(cx.clone(), receiver);
            stats.stream_adapters_created += 1;

            // Send more messages than buffer can hold
            let sender = self.sender.lock().unwrap();
            let sender = sender.as_ref().unwrap();

            for i in 0..20 {
                let msg = TestMessage {
                    id: 500 + i,
                    content: format!("Lag test message {}", i),
                    timestamp: 40000 + i * 50,
                    priority: MessagePriority::Normal,
                };

                sender.send(msg).await?;
                stats.messages_sent += 1;
            }

            // Try to consume and verify lagged error handling
            let consumer_id = "lag_test".to_string();
            let mut received_after_lag = 0;

            while let Some(result) = stream.next().await {
                match result {
                    Ok(msg) => {
                        self.message_collector
                            .record_message(consumer_id.clone(), msg);
                        received_after_lag += 1;
                        stats.messages_received_via_streams += 1;
                    }
                    Err(BroadcastStreamRecvError::Lagged(count)) => {
                        self.message_collector.record_error(
                            consumer_id.clone(),
                            BroadcastStreamRecvError::Lagged(count),
                        );
                        stats.lagged_errors_handled += 1;
                        // Continue consuming after lag error
                    }
                }

                if received_after_lag >= 10 {
                    break; // Don't consume all to avoid infinite loop
                }
            }

            assert!(
                stats.lagged_errors_handled > 0,
                "Should have handled lagged message errors"
            );

            Ok(())
        }

        async fn consume_stream_messages(
            &self,
            cx: &Cx,
            stream: &mut BroadcastStream<TestMessage>,
            consumer_id: &str,
            expected_count: usize,
        ) -> Result<u64> {
            let mut received = 0;

            for _ in 0..expected_count {
                match stream.next().await {
                    Some(Ok(msg)) => {
                        self.message_collector
                            .record_message(consumer_id.to_string(), msg);
                        received += 1;
                    }
                    Some(Err(e)) => {
                        self.message_collector
                            .record_error(consumer_id.to_string(), e);
                    }
                    None => break,
                }
            }

            Ok(received)
        }

        async fn verify_integration_properties(
            &self,
            stats: &BroadcastStreamStats,
        ) -> Result<bool> {
            let total_messages_collected = self.message_collector.total_messages_received();
            let total_errors = self.message_collector.total_errors();

            // Verify basic integration properties
            let properties_verified =
                // Messages were sent and received via streams
                stats.messages_sent > 0
                && stats.messages_received_via_streams > 0
                // Stream adapters were created
                && stats.stream_adapters_created > 0
                // Backpressure was tested
                && stats.backpressure_events > 0
                // Error propagation was tested
                && stats.lagged_errors_handled > 0
                // Stream combinators were applied
                && stats.stream_combinators_applied > 0
                // Multiple consumers were tested
                && stats.concurrent_stream_consumers > 0
                // Channel closure was propagated
                && stats.channel_closure_propagated > 0
                // Message collector received messages
                && total_messages_collected > 0;

            // Verify that broadcast fan-out behavior is maintained through streams
            let fan_out_verified = stats.messages_received_via_streams >= stats.messages_sent;

            Ok(properties_verified && fan_out_verified)
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Actual Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_broadcast_channel_stream_basic_integration() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = BroadcastStreamTestFramework::new(16)?;

            let result = framework.execute_integration_test(&cx).await?;

            assert!(
                result.success,
                "Basic broadcast-stream integration should succeed: {:?}",
                result.error
            );
            assert!(
                result.integration_stats.messages_sent > 0,
                "Should have sent messages"
            );
            assert!(
                result.integration_stats.messages_received_via_streams > 0,
                "Should have received messages via streams"
            );
            assert!(
                result.integration_stats.stream_adapters_created > 0,
                "Should have created stream adapters"
            );

            println!("✓ Basic broadcast channel ↔ stream integration verified");
            println!(
                "  Messages sent: {}",
                result.integration_stats.messages_sent
            );
            println!(
                "  Messages via streams: {}",
                result.integration_stats.messages_received_via_streams
            );
            println!(
                "  Stream adapters: {}",
                result.integration_stats.stream_adapters_created
            );
            println!("  Duration: {}ms", result.duration_ms);

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_broadcast_stream_backpressure_handling() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = BroadcastStreamTestFramework::new(8)?; // Small capacity

            let mut stats = BroadcastStreamStats::default();
            framework
                .test_backpressure_handling(&cx, &mut stats)
                .await?;

            assert!(
                stats.backpressure_events > 0,
                "Should have detected backpressure events"
            );

            println!("✓ Broadcast stream backpressure handling verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_broadcast_stream_error_propagation() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = BroadcastStreamTestFramework::new(8)?;

            let mut stats = BroadcastStreamStats::default();
            framework.test_error_propagation(&cx, &mut stats).await?;

            assert!(
                stats.lagged_errors_handled > 0,
                "Should have handled lagged errors"
            );
            assert!(
                stats.channel_closure_propagated > 0,
                "Should have propagated channel closure"
            );

            println!("✓ Broadcast stream error propagation verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_broadcast_stream_combinators() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = BroadcastStreamTestFramework::new(16)?;

            let mut stats = BroadcastStreamStats::default();
            framework.test_stream_combinators(&cx, &mut stats).await?;

            assert!(
                stats.stream_combinators_applied > 0,
                "Should have applied stream combinators"
            );

            println!("✓ Broadcast stream combinators integration verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_broadcast_stream_multiple_consumers() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = BroadcastStreamTestFramework::new(32)?;

            let mut stats = BroadcastStreamStats::default();
            framework.test_multiple_consumers(&cx, &mut stats).await?;

            assert!(
                stats.concurrent_stream_consumers >= 5,
                "Should have multiple concurrent consumers"
            );
            // Fan-out: each message should be received by each consumer
            assert!(
                stats.messages_received_via_streams >= stats.messages_sent,
                "Should maintain broadcast fan-out behavior through streams"
            );

            println!("✓ Broadcast stream multiple consumers integration verified");

            Ok(())
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    async fn test_broadcast_stream_lagged_message_recovery() -> Result<()> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let cx = Cx::root(&runtime)?;
            let framework = BroadcastStreamTestFramework::new(4)?; // Very small capacity

            let mut stats = BroadcastStreamStats::default();
            framework
                .test_lagged_message_handling(&cx, &mut stats)
                .await?;

            assert!(
                stats.lagged_errors_handled > 0,
                "Should have handled lagged message errors"
            );

            println!("✓ Broadcast stream lagged message recovery verified");

            Ok(())
        })
    }
}
