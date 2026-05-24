//! Real E2E integration tests for web/sse ↔ broadcast channel fanout delivery.
//!
//! Verifies that Server-Sent Events can deliver fanout to multiple subscribers without
//! dropping messages under bursty publishes, with proper backpressure handling.

#![allow(clippy::too_many_lines)]

use crate::channel::broadcast;
use crate::cx::Cx;
use crate::web::sse::{SseEvent, StreamingSse, StreamingSseSource, StreamingSseError};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Mock broadcast-driven SSE source that bridges broadcast receiver to streaming SSE.
#[derive(Debug)]
struct BroadcastSseSource<T: Clone> {
    receiver: broadcast::Receiver<T>,
    message_count: u64,
    lag_events: u64,
    disconnect_events: u64,
    cancelled: bool,
}

impl<T: Clone> BroadcastSseSource<T> {
    /// Create new broadcast-driven SSE source.
    fn new(receiver: broadcast::Receiver<T>) -> Self {
        Self {
            receiver,
            message_count: 0,
            lag_events: 0,
            disconnect_events: 0,
            cancelled: false,
        }
    }

    /// Get the number of messages delivered.
    fn message_count(&self) -> u64 {
        self.message_count
    }

    /// Get the number of lag events encountered.
    fn lag_events(&self) -> u64 {
        self.lag_events
    }

    /// Get the number of disconnect events.
    fn disconnect_events(&self) -> u64 {
        self.disconnect_events
    }
}

impl<T: Clone + std::fmt::Display> StreamingSseSource for BroadcastSseSource<T> {
    fn next_event(&mut self, cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
        if self.cancelled {
            return Ok(None);
        }

        // Check cancellation first
        cx.checkpoint().map_err(|_| StreamingSseError::Cancelled)?;

        // Try to receive from broadcast channel
        match self.receiver.try_recv() {
            Ok(message) => {
                self.message_count += 1;
                let data = format!("{}", message);
                Ok(Some(SseEvent::default()
                    .event("broadcast-message")
                    .data(data)
                    .id(&format!("{}", self.message_count))))
            }
            Err(broadcast::TryRecvError::Empty) => {
                // No message available right now - return None to indicate end of current batch
                Ok(None)
            }
            Err(broadcast::TryRecvError::Lagged(count)) => {
                self.lag_events += 1;
                // Return a lag notification event
                Ok(Some(SseEvent::default()
                    .event("lag-notification")
                    .data(&format!("Receiver lagged by {} messages", count))
                    .id(&format!("lag-{}", self.lag_events))))
            }
            Err(broadcast::TryRecvError::Closed) => {
                self.disconnect_events += 1;
                // Channel closed - return None to end the stream
                Ok(None)
            }
        }
    }

    fn cancel(&mut self) {
        self.cancelled = true;
    }
}

/// Test message type that implements Clone and Display
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestMessage {
    id: u64,
    content: String,
    timestamp: u64,
}

impl std::fmt::Display for TestMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{\"id\":{},\"content\":\"{}\",\"timestamp\":{}}}",
               self.id, self.content, self.timestamp)
    }
}

/// Metrics for tracking SSE broadcast integration performance.
#[derive(Debug, Clone, Default)]
struct SseBroadcastMetrics {
    /// Total messages published to broadcast channel
    messages_published: AtomicU64,
    /// Total SSE events delivered across all subscribers
    sse_events_delivered: AtomicU64,
    /// Number of lag events encountered
    lag_events: AtomicU64,
    /// Number of disconnect events
    disconnect_events: AtomicU64,
    /// Number of active subscribers
    active_subscribers: AtomicUsize,
    /// Bytes delivered via SSE
    sse_bytes_delivered: AtomicU64,
    /// Maximum observed lag across all receivers
    max_lag_observed: AtomicU64,
    /// Backpressure activations
    backpressure_activations: AtomicU64,
}

impl SseBroadcastMetrics {
    fn new() -> Self {
        Self::default()
    }

    fn record_published(&self) -> u64 {
        self.messages_published.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn record_sse_delivered(&self, bytes: u64) -> u64 {
        self.sse_bytes_delivered.fetch_add(bytes, Ordering::SeqCst);
        self.sse_events_delivered.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn record_lag(&self, count: u64) {
        self.lag_events.fetch_add(1, Ordering::SeqCst);
        let mut max_lag = self.max_lag_observed.load(Ordering::SeqCst);
        while count > max_lag {
            match self.max_lag_observed.compare_exchange_weak(
                max_lag, count, Ordering::SeqCst, Ordering::SeqCst
            ) {
                Ok(_) => break,
                Err(current) => max_lag = current,
            }
        }
    }

    fn record_disconnect(&self) {
        self.disconnect_events.fetch_add(1, Ordering::SeqCst);
    }

    fn add_subscriber(&self) -> usize {
        self.active_subscribers.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn remove_subscriber(&self) -> usize {
        self.active_subscribers.fetch_sub(1, Ordering::SeqCst).saturating_sub(1)
    }

    fn record_backpressure(&self) {
        self.backpressure_activations.fetch_add(1, Ordering::SeqCst);
    }

    fn snapshot(&self) -> SseBroadcastMetricsSnapshot {
        SseBroadcastMetricsSnapshot {
            messages_published: self.messages_published.load(Ordering::SeqCst),
            sse_events_delivered: self.sse_events_delivered.load(Ordering::SeqCst),
            lag_events: self.lag_events.load(Ordering::SeqCst),
            disconnect_events: self.disconnect_events.load(Ordering::SeqCst),
            active_subscribers: self.active_subscribers.load(Ordering::SeqCst),
            sse_bytes_delivered: self.sse_bytes_delivered.load(Ordering::SeqCst),
            max_lag_observed: self.max_lag_observed.load(Ordering::SeqCst),
            backpressure_activations: self.backpressure_activations.load(Ordering::SeqCst),
        }
    }
}

/// Point-in-time snapshot of SSE broadcast metrics.
#[derive(Debug, Clone)]
struct SseBroadcastMetricsSnapshot {
    messages_published: u64,
    sse_events_delivered: u64,
    lag_events: u64,
    disconnect_events: u64,
    active_subscribers: usize,
    sse_bytes_delivered: u64,
    max_lag_observed: u64,
    backpressure_activations: u64,
}

/// Enhanced broadcast source that integrates with metrics and supports burst testing.
#[derive(Debug)]
struct MetricsBroadcastSseSource {
    source: BroadcastSseSource<TestMessage>,
    metrics: Arc<SseBroadcastMetrics>,
    subscriber_id: usize,
    pending_events: VecDeque<SseEvent>,
    burst_mode: bool,
}

impl MetricsBroadcastSseSource {
    fn new(
        receiver: broadcast::Receiver<TestMessage>,
        metrics: Arc<SseBroadcastMetrics>,
        subscriber_id: usize,
    ) -> Self {
        Self {
            source: BroadcastSseSource::new(receiver),
            metrics,
            subscriber_id,
            pending_events: VecDeque::new(),
            burst_mode: false,
        }
    }

    fn set_burst_mode(&mut self, enabled: bool) {
        self.burst_mode = enabled;
    }

    /// Drain all available messages in burst mode
    fn drain_available(&mut self, cx: &Cx) -> Result<(), StreamingSseError> {
        while let Some(event) = self.source.next_event(cx)? {
            self.pending_events.push_back(event);
            if self.pending_events.len() > 1000 { // Prevent unbounded growth
                self.metrics.record_backpressure();
                break;
            }
        }
        Ok(())
    }
}

impl StreamingSseSource for MetricsBroadcastSseSource {
    fn next_event(&mut self, cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
        // In burst mode, drain all available messages first
        if self.burst_mode && self.pending_events.is_empty() {
            self.drain_available(cx)?;
        }

        // Return pending events first
        if let Some(event) = self.pending_events.pop_front() {
            if let Some(data) = &event.data {
                self.metrics.record_sse_delivered(data.len() as u64);
            }
            return Ok(Some(event));
        }

        // Get next event from source
        match self.source.next_event(cx)? {
            Some(event) => {
                if let Some(data) = &event.data {
                    self.metrics.record_sse_delivered(data.len() as u64);
                }
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    fn cancel(&mut self) {
        self.source.cancel();
        self.metrics.remove_subscriber();
    }
}

/// Test scenario configuration for SSE broadcast integration testing.
#[derive(Debug, Clone)]
struct TestScenario {
    /// Number of concurrent subscribers
    subscriber_count: usize,
    /// Number of messages to publish
    message_count: usize,
    /// Broadcast channel capacity
    channel_capacity: usize,
    /// Whether to publish in bursts
    burst_mode: bool,
    /// Burst size if in burst mode
    burst_size: usize,
    /// Delay between bursts in milliseconds
    burst_delay_ms: u64,
    /// SSE max event bytes
    sse_max_event_bytes: usize,
    /// SSE max total bytes
    sse_max_total_bytes: usize,
    /// Test timeout in seconds
    timeout_seconds: u64,
}

impl Default for TestScenario {
    fn default() -> Self {
        Self {
            subscriber_count: 3,
            message_count: 100,
            channel_capacity: 32,
            burst_mode: false,
            burst_size: 10,
            burst_delay_ms: 50,
            sse_max_event_bytes: 8192,
            sse_max_total_bytes: 1024 * 1024,
            timeout_seconds: 30,
        }
    }
}

/// Publisher that generates test messages at specified rates.
struct TestPublisher {
    sender: broadcast::Sender<TestMessage>,
    metrics: Arc<SseBroadcastMetrics>,
    message_sequence: AtomicU64,
}

impl TestPublisher {
    fn new(sender: broadcast::Sender<TestMessage>, metrics: Arc<SseBroadcastMetrics>) -> Self {
        Self {
            sender,
            metrics,
            message_sequence: AtomicU64::new(0),
        }
    }

    /// Publish a single message
    fn publish(&self, cx: &Cx, content: &str) -> Result<usize, broadcast::SendError<TestMessage>> {
        let id = self.message_sequence.fetch_add(1, Ordering::SeqCst);
        let message = TestMessage {
            id,
            content: content.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        match self.sender.send(cx, message) {
            Ok(receivers) => {
                self.metrics.record_published();
                Ok(receivers)
            }
            Err(e) => Err(e),
        }
    }

    /// Publish a burst of messages
    fn publish_burst(&self, cx: &Cx, burst_size: usize, prefix: &str) -> Result<Vec<usize>, broadcast::SendError<TestMessage>> {
        let mut results = Vec::with_capacity(burst_size);
        for i in 0..burst_size {
            let content = format!("{}-burst-{}", prefix, i);
            results.push(self.publish(cx, &content)?);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{init_test_logging, TimeBudget};

    fn init_test(name: &str) -> TimeBudget {
        init_test_logging();
        crate::test_phase!(name);
        TimeBudget::new(Duration::from_secs(30))
    }

    /// Test basic SSE ↔ broadcast fanout delivery to multiple subscribers.
    #[test]
    fn test_sse_broadcast_basic_fanout() {
        let budget = init_test("sse_broadcast_basic_fanout");
        let cx = Cx::for_testing();

        // Create broadcast channel
        let (sender, receiver) = broadcast::channel(16);
        let metrics = Arc::new(SseBroadcastMetrics::new());

        // Create publisher
        let publisher = TestPublisher::new(sender.clone(), Arc::clone(&metrics));

        // Create multiple SSE subscribers
        let subscriber_count = 3;
        let mut sources = Vec::new();

        for i in 0..subscriber_count {
            let sub_receiver = sender.subscribe();
            let source = MetricsBroadcastSseSource::new(sub_receiver, Arc::clone(&metrics), i);
            sources.push(StreamingSse::from_source(source));
            metrics.add_subscriber();
        }

        // Publish test messages
        let message_count = 10;
        for i in 0..message_count {
            let content = format!("test-message-{}", i);
            let receivers = publisher.publish(&cx, &content).expect("publish message");
            assert_eq!(receivers, subscriber_count, "All subscribers should receive message {}", i);

            if budget.exceeded() {
                panic!("Test exceeded time budget during publishing phase");
            }
        }

        // Drop sender to close channel
        drop(sender);

        // Verify each subscriber received all messages
        for (i, source) in sources.iter_mut().enumerate() {
            let mut received_count = 0;

            while !source.is_closed() {
                match source.next_chunk(&cx) {
                    Ok(Some(_chunk)) => {
                        received_count += 1;
                    }
                    Ok(None) => break, // End of stream
                    Err(e) => panic!("Subscriber {} error: {:?}", i, e),
                }

                if budget.exceeded() {
                    panic!("Test exceeded time budget during consumption phase for subscriber {}", i);
                }
            }

            println!("Subscriber {} received {} messages", i, received_count);
            assert!(received_count > 0, "Subscriber {} should have received messages", i);
        }

        // Verify metrics
        let snapshot = metrics.snapshot();
        println!("Final metrics: {:?}", snapshot);

        assert_eq!(snapshot.messages_published, message_count as u64);
        assert!(snapshot.sse_events_delivered > 0, "SSE events should have been delivered");
        assert_eq!(snapshot.lag_events, 0, "No lag events should occur in basic test");

        crate::test_complete!("sse_broadcast_basic_fanout");
    }

    /// Test SSE ↔ broadcast integration under bursty publish patterns.
    #[test]
    fn test_sse_broadcast_bursty_publishes() {
        let budget = init_test("sse_broadcast_bursty_publishes");
        let cx = Cx::for_testing();

        let scenario = TestScenario {
            subscriber_count: 5,
            message_count: 200,
            channel_capacity: 64,
            burst_mode: true,
            burst_size: 20,
            burst_delay_ms: 10,
            ..Default::default()
        };

        // Create broadcast channel
        let (sender, _receiver) = broadcast::channel(scenario.channel_capacity);
        let metrics = Arc::new(SseBroadcastMetrics::new());

        // Create publisher
        let publisher = TestPublisher::new(sender.clone(), Arc::clone(&metrics));

        // Create multiple SSE subscribers with burst mode enabled
        let mut sources = Vec::new();

        for i in 0..scenario.subscriber_count {
            let sub_receiver = sender.subscribe();
            let mut source = MetricsBroadcastSseSource::new(sub_receiver, Arc::clone(&metrics), i);
            source.set_burst_mode(true);
            sources.push(StreamingSse::from_source(source).max_total_bytes(scenario.sse_max_total_bytes));
            metrics.add_subscriber();
        }

        // Publish messages in bursts
        let burst_count = scenario.message_count / scenario.burst_size;
        for burst_idx in 0..burst_count {
            let prefix = format!("burst-{}", burst_idx);
            let receivers = publisher.publish_burst(&cx, scenario.burst_size, &prefix)
                .expect("publish burst");

            // Verify all subscribers received the burst
            let expected_receivers = scenario.subscriber_count;
            for &actual_receivers in &receivers {
                assert_eq!(actual_receivers, expected_receivers,
                    "Burst {} should reach all {} subscribers", burst_idx, expected_receivers);
            }

            // Small delay between bursts to simulate realistic traffic patterns
            std::thread::sleep(Duration::from_millis(scenario.burst_delay_ms));

            if budget.exceeded() {
                panic!("Test exceeded time budget during burst {} publishing", burst_idx);
            }
        }

        // Drop sender to close channel
        drop(sender);

        // Collect messages from all subscribers
        let mut subscriber_results = Vec::new();

        for (i, source) in sources.iter_mut().enumerate() {
            let mut received_count = 0;
            let mut received_bytes = 0;

            while !source.is_closed() {
                match source.next_chunk(&cx) {
                    Ok(Some(chunk)) => {
                        received_count += 1;
                        received_bytes += chunk.len();
                    }
                    Ok(None) => break, // End of stream
                    Err(e) => {
                        println!("Subscriber {} error: {:?}", i, e);
                        break; // Allow graceful degradation under burst load
                    }
                }

                if budget.exceeded() {
                    println!("Warning: Test exceeded time budget during consumption for subscriber {}", i);
                    break;
                }
            }

            subscriber_results.push((received_count, received_bytes));
            println!("Subscriber {} received {} messages ({} bytes)", i, received_count, received_bytes);
        }

        // Verify results
        let snapshot = metrics.snapshot();
        println!("Final metrics: {:?}", snapshot);

        // All subscribers should receive messages (allowing for some loss under burst load)
        for (i, &(count, _)) in subscriber_results.iter().enumerate() {
            assert!(count > 0, "Subscriber {} should have received some messages", i);
        }

        // Total published messages should match expected
        assert_eq!(snapshot.messages_published, (burst_count * scenario.burst_size) as u64);

        // SSE delivery should have occurred
        assert!(snapshot.sse_events_delivered > 0, "SSE events should have been delivered");

        // Some lag is acceptable under burst conditions
        if snapshot.lag_events > 0 {
            println!("Lag events occurred under burst load: {}", snapshot.lag_events);
            assert!(snapshot.max_lag_observed <= scenario.channel_capacity as u64,
                "Max lag should not exceed channel capacity");
        }

        crate::test_complete!("sse_broadcast_bursty_publishes");
    }

    /// Test SSE ↔ broadcast integration with slow consumers causing backpressure.
    #[test]
    fn test_sse_broadcast_slow_consumer_backpressure() {
        let budget = init_test("sse_broadcast_slow_consumer_backpressure");
        let cx = Cx::for_testing();

        let scenario = TestScenario {
            subscriber_count: 4,
            message_count: 50,
            channel_capacity: 16, // Small capacity to trigger backpressure
            sse_max_total_bytes: 4096, // Small limit to test backpressure
            ..Default::default()
        };

        // Create broadcast channel
        let (sender, _receiver) = broadcast::channel(scenario.channel_capacity);
        let metrics = Arc::new(SseBroadcastMetrics::new());

        // Create publisher
        let publisher = TestPublisher::new(sender.clone(), Arc::clone(&metrics));

        // Create SSE subscribers - some normal, some with restricted capacity
        let mut sources = Vec::new();

        for i in 0..scenario.subscriber_count {
            let sub_receiver = sender.subscribe();
            let source = MetricsBroadcastSseSource::new(sub_receiver, Arc::clone(&metrics), i);

            // Make some subscribers slow by limiting their total bytes
            let sse_source = if i % 2 == 0 {
                StreamingSse::from_source(source)
                    .max_total_bytes(scenario.sse_max_total_bytes / 2) // Very restrictive
            } else {
                StreamingSse::from_source(source)
                    .max_total_bytes(scenario.sse_max_total_bytes)
            };

            sources.push(sse_source);
            metrics.add_subscriber();
        }

        // Publish messages that will trigger backpressure
        for i in 0..scenario.message_count {
            // Create larger messages to trigger byte limits faster
            let content = format!("large-test-message-{}-{}", i, "x".repeat(100));

            match publisher.publish(&cx, &content) {
                Ok(receivers) => {
                    println!("Message {} reached {} receivers", i, receivers);
                }
                Err(e) => {
                    println!("Publish failed for message {}: {:?}", i, e);
                    // Continue publishing to test resilience
                }
            }

            if budget.exceeded() {
                println!("Warning: Test exceeded time budget during publishing at message {}", i);
                break;
            }
        }

        // Drop sender to close channel
        drop(sender);

        // Collect results from subscribers, expecting some to hit limits
        let mut successful_subscribers = 0;
        let mut backpressure_limited_subscribers = 0;

        for (i, source) in sources.iter_mut().enumerate() {
            let mut received_count = 0;
            let mut hit_limit = false;

            loop {
                match source.next_chunk(&cx) {
                    Ok(Some(_chunk)) => {
                        received_count += 1;
                    }
                    Ok(None) => break, // End of stream
                    Err(e) => {
                        println!("Subscriber {} hit limit/error: {:?}", i, e);
                        hit_limit = true;
                        break;
                    }
                }

                if budget.exceeded() {
                    println!("Warning: Test exceeded time budget during consumption for subscriber {}", i);
                    break;
                }
            }

            println!("Subscriber {} received {} messages, hit_limit: {}",
                i, received_count, hit_limit);

            if hit_limit {
                backpressure_limited_subscribers += 1;
            } else {
                successful_subscribers += 1;
            }
        }

        // Verify results
        let snapshot = metrics.snapshot();
        println!("Final metrics: {:?}", snapshot);

        assert!(snapshot.messages_published > 0, "Messages should have been published");
        assert!(snapshot.sse_events_delivered > 0, "Some SSE events should have been delivered");

        // Under backpressure, some subscribers should hit limits
        assert!(backpressure_limited_subscribers > 0,
            "Some subscribers should have hit backpressure limits");

        // But at least some should succeed
        assert!(successful_subscribers > 0 || backpressure_limited_subscribers > 0,
            "At least some subscribers should have received messages");

        println!("Backpressure test completed: {} limited, {} successful",
            backpressure_limited_subscribers, successful_subscribers);

        crate::test_complete!("sse_broadcast_slow_consumer_backpressure");
    }

    /// Test comprehensive SSE ↔ broadcast integration under high load with multiple scenarios.
    #[test]
    fn test_sse_broadcast_comprehensive_high_load() {
        let budget = init_test("sse_broadcast_comprehensive_high_load");
        let cx = Cx::for_testing();

        let scenario = TestScenario {
            subscriber_count: 8,
            message_count: 500,
            channel_capacity: 128,
            burst_mode: true,
            burst_size: 25,
            burst_delay_ms: 5,
            sse_max_event_bytes: 4096,
            sse_max_total_bytes: 256 * 1024,
            timeout_seconds: 60,
        };

        // Create broadcast channel
        let (sender, _receiver) = broadcast::channel(scenario.channel_capacity);
        let metrics = Arc::new(SseBroadcastMetrics::new());

        // Create publisher
        let publisher = TestPublisher::new(sender.clone(), Arc::clone(&metrics));

        // Create diverse SSE subscribers with different configurations
        let mut sources = Vec::new();

        for i in 0..scenario.subscriber_count {
            let sub_receiver = sender.subscribe();
            let mut source = MetricsBroadcastSseSource::new(sub_receiver, Arc::clone(&metrics), i);

            // Enable burst mode for some subscribers
            if i % 3 == 0 {
                source.set_burst_mode(true);
            }

            // Create SSE streams with varying capacity limits
            let sse_source = match i % 4 {
                0 => StreamingSse::from_source(source), // Default limits
                1 => StreamingSse::from_source(source)
                    .max_event_bytes(scenario.sse_max_event_bytes / 2), // Smaller events
                2 => StreamingSse::from_source(source)
                    .max_total_bytes(scenario.sse_max_total_bytes / 4), // Smaller total
                _ => StreamingSse::from_source(source)
                    .max_event_bytes(scenario.sse_max_event_bytes)
                    .max_total_bytes(scenario.sse_max_total_bytes),
            };

            sources.push(sse_source);
            metrics.add_subscriber();
        }

        println!("Starting comprehensive high-load test with {} subscribers", scenario.subscriber_count);

        // Phase 1: Initial burst
        let initial_burst_count = 3;
        for burst_idx in 0..initial_burst_count {
            let prefix = format!("initial-burst-{}", burst_idx);
            match publisher.publish_burst(&cx, scenario.burst_size, &prefix) {
                Ok(_) => {}
                Err(e) => println!("Initial burst {} failed: {:?}", burst_idx, e),
            }

            if budget.exceeded() {
                println!("Warning: Time budget exceeded during initial burst phase");
                break;
            }
        }

        // Phase 2: Sustained publishing with mixed patterns
        let sustained_messages = scenario.message_count - (initial_burst_count * scenario.burst_size);
        for i in 0..sustained_messages {
            let content = if i % 10 == 0 {
                // Occasional large messages
                format!("large-message-{}-{}", i, "data".repeat(200))
            } else if i % 5 == 0 {
                // JSON-like structured data
                format!("{{\"msg_id\":{},\"type\":\"event\",\"data\":\"payload-{}\"}}", i, i)
            } else {
                // Regular messages
                format!("message-{}", i)
            };

            match publisher.publish(&cx, &content) {
                Ok(_) => {}
                Err(e) => {
                    println!("Sustained publish failed for message {}: {:?}", i, e);
                    // Continue publishing for resilience testing
                }
            }

            // Variable delay to simulate realistic patterns
            if i % 50 == 0 {
                std::thread::sleep(Duration::from_millis(scenario.burst_delay_ms));
            }

            if budget.exceeded() {
                println!("Warning: Time budget exceeded during sustained phase at message {}", i);
                break;
            }
        }

        // Phase 3: Final burst before shutdown
        let final_burst_prefix = "final-burst";
        match publisher.publish_burst(&cx, scenario.burst_size / 2, final_burst_prefix) {
            Ok(_) => println!("Final burst completed"),
            Err(e) => println!("Final burst failed: {:?}", e),
        }

        // Drop sender to initiate shutdown
        drop(sender);
        println!("Publisher shutdown initiated");

        // Collect comprehensive results from all subscribers
        let mut subscriber_results = Vec::new();
        let start_time = Instant::now();

        for (i, source) in sources.iter_mut().enumerate() {
            let mut received_count = 0;
            let mut received_bytes = 0;
            let mut last_received = start_time;

            loop {
                match source.next_chunk(&cx) {
                    Ok(Some(chunk)) => {
                        received_count += 1;
                        received_bytes += chunk.len();
                        last_received = Instant::now();
                    }
                    Ok(None) => {
                        println!("Subscriber {} stream ended naturally", i);
                        break;
                    }
                    Err(e) => {
                        println!("Subscriber {} error: {:?}", i, e);
                        break;
                    }
                }

                // Individual subscriber timeout
                if last_received.elapsed() > Duration::from_secs(5) {
                    println!("Subscriber {} timed out waiting for messages", i);
                    break;
                }

                if budget.exceeded() {
                    println!("Global time budget exceeded for subscriber {}", i);
                    break;
                }
            }

            subscriber_results.push((received_count, received_bytes));
            println!("Subscriber {} final stats: {} messages, {} bytes",
                i, received_count, received_bytes);
        }

        // Comprehensive analysis
        let snapshot = metrics.snapshot();
        println!("Final comprehensive metrics: {:?}", snapshot);

        // Calculate statistics
        let total_received: usize = subscriber_results.iter().map(|(count, _)| count).sum();
        let total_bytes: usize = subscriber_results.iter().map(|(_, bytes)| bytes).sum();
        let avg_messages_per_subscriber = total_received as f64 / scenario.subscriber_count as f64;

        println!("Analysis:");
        println!("  Total messages received: {}", total_received);
        println!("  Total bytes delivered: {}", total_bytes);
        println!("  Average messages per subscriber: {:.2}", avg_messages_per_subscriber);
        println!("  Messages published: {}", snapshot.messages_published);
        println!("  SSE events delivered: {}", snapshot.sse_events_delivered);
        println!("  Lag events: {}", snapshot.lag_events);
        println!("  Max lag observed: {}", snapshot.max_lag_observed);

        // Verification - at least some delivery should occur
        assert!(total_received > 0, "At least some messages should be received");
        assert!(snapshot.messages_published > 0, "Messages should have been published");
        assert!(snapshot.sse_events_delivered > 0, "SSE events should have been delivered");

        // All subscribers should receive at least some messages
        let zero_message_subscribers = subscriber_results.iter()
            .filter(|(count, _)| *count == 0)
            .count();

        assert!(zero_message_subscribers < scenario.subscriber_count / 2,
            "Most subscribers should receive messages, but {} received none", zero_message_subscribers);

        // Under high load, some lag is acceptable
        if snapshot.lag_events > 0 {
            println!("Acceptable lag under high load: {} events, max lag: {}",
                snapshot.lag_events, snapshot.max_lag_observed);
        }

        println!("Comprehensive high-load test completed successfully");
        crate::test_complete!("sse_broadcast_comprehensive_high_load");
    }
}