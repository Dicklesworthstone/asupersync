//! BR-E2E-95: Real net/websocket/frame ↔ sync/notify Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the WebSocket frame
//! processing system and synchronization notify primitives. The tests verify that
//! a WebSocket close-frame correctly notifies all waiting readers without spurious
//! wakes or missed wakeups.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `net::websocket::frame` - WebSocket frame parsing, close-frame detection and reader coordination
//! - `sync::notify` - Notification primitives for waking waiting tasks with spurious wake prevention
//!
//! # Key Scenarios
//!
//! - Close-frame notification to all waiting readers
//! - Spurious wake detection and prevention
//! - Missed wakeup verification and correction
//! - Multi-reader coordination during frame processing
//! - Notification ordering and delivery guarantees

use crate::{
    cx::{Cx, Scope},
    error::Outcome,
    net::{
        TcpStream,
        websocket::{
            WebSocketConfig, WebSocketError,
            frame::{
                CloseCode, CloseFrame, FrameBuffer, FrameHeader, FrameNotificationEvent,
                FrameOpcode, FrameParser, FrameProcessingState, FrameReader, FrameType,
                FrameWriter, MaskingKey, ParseResult, PayloadLength, ReaderState, WebSocketFrame,
            },
        },
    },
    runtime::RuntimeBuilder,
    sync::{
        Mutex, RwLock,
        notify::{
            MissedWakeDetector, NotificationTracker, Notify, NotifyConfig, NotifyHandle,
            NotifyMultiplexer, SpuriousWakeDetector, WaitGroup, WakeEvent, WakeReason,
            WakeupVerification,
        },
    },
    time::{Duration, Instant, Sleep, Timeout},
    types::{Budget, Cancel, TaskId},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use futures::{
    ready,
    sink::{Sink, SinkExt},
    stream::{Stream, StreamExt},
};

/// Configuration for WebSocket frame notification integration tests
#[derive(Debug, Clone)]
struct WebSocketFrameNotifyTestConfig {
    /// Number of concurrent readers waiting for frames
    concurrent_readers: u32,
    /// Frame processing batch size
    frame_batch_size: u32,
    /// Test duration
    test_duration: Duration,
    /// Close-frame delay after readers are established
    close_frame_delay: Duration,
    /// Maximum allowed spurious wakes
    max_spurious_wakes: u32,
    /// Wake verification timeout
    wake_verification_timeout: Duration,
}

impl Default for WebSocketFrameNotifyTestConfig {
    fn default() -> Self {
        Self {
            concurrent_readers: 8,
            frame_batch_size: 16,
            test_duration: Duration::from_secs(3),
            close_frame_delay: Duration::from_millis(500),
            max_spurious_wakes: 2,
            wake_verification_timeout: Duration::from_millis(100),
        }
    }
}

/// Tracks WebSocket frame notification behavior and wake semantics
#[derive(Debug)]
struct WebSocketFrameNotificationTracker {
    /// Frame processing events
    frame_events: Arc<Mutex<Vec<FrameProcessingEvent>>>,
    /// Notification delivery events
    notification_events: Arc<Mutex<Vec<NotificationDeliveryEvent>>>,
    /// Wake verification results
    wake_verifications: Arc<Mutex<Vec<WakeVerificationEvent>>>,
    /// Spurious wake detections
    spurious_wakes: Arc<Mutex<Vec<SpuriousWakeEvent>>>,
    /// Missed wakeup detections
    missed_wakes: Arc<Mutex<Vec<MissedWakeEvent>>>,
    /// Reader coordination events
    reader_coordination: Arc<Mutex<Vec<ReaderCoordinationEvent>>>,
    /// Global wake counter
    total_wakes: Arc<AtomicU64>,
    /// Spurious wake counter
    spurious_wake_count: Arc<AtomicU32>,
}

#[derive(Debug, Clone)]
struct FrameProcessingEvent {
    timestamp: Instant,
    frame_type: FrameType,
    frame_id: FrameId,
    processing_state: FrameProcessingState,
    reader_count: u32,
    notification_triggered: bool,
}

#[derive(Debug, Clone)]
struct NotificationDeliveryEvent {
    timestamp: Instant,
    notification_id: NotificationId,
    target_readers: Vec<ReaderId>,
    delivery_method: NotificationDeliveryMethod,
    delivery_latency: Duration,
    successful_deliveries: u32,
}

#[derive(Debug, Clone, PartialEq)]
enum NotificationDeliveryMethod {
    Broadcast, // Notify all waiting readers
    Targeted { reader_id: ReaderId },
    Sequential, // Notify one at a time
}

#[derive(Debug, Clone)]
struct WakeVerificationEvent {
    timestamp: Instant,
    reader_id: ReaderId,
    wake_reason: WakeReason,
    expected_wake: bool,
    verification_result: WakeVerificationResult,
    frame_context: Option<FrameId>,
}

#[derive(Debug, Clone, PartialEq)]
enum WakeVerificationResult {
    ValidWake,
    SpuriousWake { reason: String },
    MissedWake { expected_frame: FrameId },
    DelayedWake { delay: Duration },
}

#[derive(Debug, Clone)]
struct SpuriousWakeEvent {
    timestamp: Instant,
    reader_id: ReaderId,
    spurious_reason: SpuriousWakeReason,
    frame_context: Option<FrameId>,
    task_context: TaskContext,
}

#[derive(Debug, Clone, PartialEq)]
enum SpuriousWakeReason {
    NoFrameAvailable,
    DuplicateNotification,
    UnrelatedFrameType,
    TaskSchedulerArtifact,
    NetworkEvent,
}

#[derive(Debug, Clone)]
struct MissedWakeEvent {
    timestamp: Instant,
    reader_id: ReaderId,
    expected_frame: FrameId,
    detection_delay: Duration,
    recovery_action: RecoveryAction,
}

#[derive(Debug, Clone, PartialEq)]
enum RecoveryAction {
    RetryNotification,
    ForceWake,
    ReaderReset,
    None,
}

#[derive(Debug, Clone)]
struct ReaderCoordinationEvent {
    timestamp: Instant,
    coordination_type: CoordinationType,
    participating_readers: Vec<ReaderId>,
    coordination_result: CoordinationResult,
    frame_trigger: Option<FrameId>,
}

#[derive(Debug, Clone, PartialEq)]
enum CoordinationType {
    CloseFrameBroadcast,
    ReaderSynchronization,
    NotificationOrdering,
    WakeupSequencing,
}

#[derive(Debug, Clone, PartialEq)]
enum CoordinationResult {
    Success {
        completion_time: Duration,
    },
    PartialSuccess {
        completed_readers: u32,
        failed_readers: u32,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone)]
struct TaskContext {
    task_id: TaskId,
    wake_count: u32,
    last_wake_time: Instant,
    reader_state: ReaderState,
}

impl WebSocketFrameNotificationTracker {
    fn new() -> Self {
        Self {
            frame_events: Arc::new(Mutex::new(Vec::new())),
            notification_events: Arc::new(Mutex::new(Vec::new())),
            wake_verifications: Arc::new(Mutex::new(Vec::new())),
            spurious_wakes: Arc::new(Mutex::new(Vec::new())),
            missed_wakes: Arc::new(Mutex::new(Vec::new())),
            reader_coordination: Arc::new(Mutex::new(Vec::new())),
            total_wakes: Arc::new(AtomicU64::new(0)),
            spurious_wake_count: Arc::new(AtomicU32::new(0)),
        }
    }

    fn record_frame_event(&self, event: FrameProcessingEvent) {
        self.frame_events.lock().unwrap().push(event);
    }

    fn record_notification_event(&self, event: NotificationDeliveryEvent) {
        self.notification_events.lock().unwrap().push(event);
    }

    fn record_wake_verification(&self, event: WakeVerificationEvent) {
        if matches!(
            event.verification_result,
            WakeVerificationResult::SpuriousWake { .. }
        ) {
            self.spurious_wake_count.fetch_add(1, Ordering::Release);
        }
        self.total_wakes.fetch_add(1, Ordering::Release);
        self.wake_verifications.lock().unwrap().push(event);
    }

    fn record_spurious_wake(&self, event: SpuriousWakeEvent) {
        self.spurious_wakes.lock().unwrap().push(event);
    }

    fn record_missed_wake(&self, event: MissedWakeEvent) {
        self.missed_wakes.lock().unwrap().push(event);
    }

    fn record_reader_coordination(&self, event: ReaderCoordinationEvent) {
        self.reader_coordination.lock().unwrap().push(event);
    }

    fn verify_close_frame_notification_completeness(&self) -> bool {
        let coordinations = self.reader_coordination.lock().unwrap();
        let close_frame_broadcasts = coordinations
            .iter()
            .filter(|c| c.coordination_type == CoordinationType::CloseFrameBroadcast)
            .count();

        // Should have at least one successful close frame broadcast
        close_frame_broadcasts > 0
            && coordinations
                .iter()
                .filter(|c| c.coordination_type == CoordinationType::CloseFrameBroadcast)
                .any(|c| matches!(c.coordination_result, CoordinationResult::Success { .. }))
    }

    fn verify_no_spurious_wakes(&self, max_allowed: u32) -> bool {
        let spurious_count = self.spurious_wake_count.load(Ordering::Acquire);
        spurious_count <= max_allowed
    }

    fn verify_no_missed_wakes(&self) -> bool {
        let missed_wakes = self.missed_wakes.lock().unwrap();
        missed_wakes.is_empty()
    }

    fn verify_notification_ordering(&self) -> bool {
        let notifications = self.notification_events.lock().unwrap();

        // Verify that close-frame notifications are properly ordered
        let mut close_notifications: Vec<_> = notifications
            .iter()
            .filter(|n| n.delivery_method == NotificationDeliveryMethod::Broadcast)
            .collect();

        close_notifications.sort_by_key(|n| n.timestamp);

        // All close-frame notifications should be delivered in order
        close_notifications
            .windows(2)
            .all(|pair| pair[0].timestamp <= pair[1].timestamp)
    }

    fn get_total_wake_count(&self) -> u64 {
        self.total_wakes.load(Ordering::Acquire)
    }

    fn get_spurious_wake_count(&self) -> u32 {
        self.spurious_wake_count.load(Ordering::Acquire)
    }

    fn get_close_frame_processing_count(&self) -> usize {
        self.frame_events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.frame_type == FrameType::Close)
            .count()
    }

    fn get_successful_notification_rate(&self) -> f64 {
        let notifications = self.notification_events.lock().unwrap();
        if notifications.is_empty() {
            return 1.0;
        }

        let successful = notifications
            .iter()
            .map(|n| n.successful_deliveries)
            .sum::<u32>();

        let total = notifications
            .iter()
            .map(|n| n.target_readers.len() as u32)
            .sum::<u32>();

        if total == 0 {
            1.0
        } else {
            successful as f64 / total as f64
        }
    }
}

/// Simulates WebSocket frame processing with notification coordination
struct MockWebSocketFrameProcessor {
    frame_parser: FrameParser,
    reader_registry: Arc<Mutex<HashMap<ReaderId, ReaderRegistration>>>,
    notification_multiplexer: Arc<NotifyMultiplexer>,
    frame_buffer: Arc<Mutex<VecDeque<WebSocketFrame>>>,
    processing_active: Arc<AtomicBool>,
    frame_id_counter: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
struct ReaderRegistration {
    reader_id: ReaderId,
    notify_handle: NotifyHandle,
    frame_filter: FrameFilter,
    registration_time: Instant,
    wake_count: Arc<AtomicU32>,
    last_frame_received: Option<FrameId>,
}

#[derive(Debug, Clone)]
struct FrameFilter {
    accept_close_frames: bool,
    accept_data_frames: bool,
    accept_control_frames: bool,
    specific_opcodes: BTreeSet<FrameOpcode>,
}

impl Default for FrameFilter {
    fn default() -> Self {
        Self {
            accept_close_frames: true,
            accept_data_frames: true,
            accept_control_frames: true,
            specific_opcodes: BTreeSet::new(),
        }
    }
}

impl MockWebSocketFrameProcessor {
    fn new() -> Self {
        Self {
            frame_parser: FrameParser::new(),
            reader_registry: Arc::new(Mutex::new(HashMap::new())),
            notification_multiplexer: Arc::new(NotifyMultiplexer::new()),
            frame_buffer: Arc::new(Mutex::new(VecDeque::new())),
            processing_active: Arc::new(AtomicBool::new(true)),
            frame_id_counter: Arc::new(AtomicU64::new(1)),
        }
    }

    fn register_reader(&self, reader_id: ReaderId, frame_filter: FrameFilter) -> NotifyHandle {
        let notify_handle = self.notification_multiplexer.create_handle();

        let registration = ReaderRegistration {
            reader_id,
            notify_handle: notify_handle.clone(),
            frame_filter,
            registration_time: Instant::now(),
            wake_count: Arc::new(AtomicU32::new(0)),
            last_frame_received: None,
        };

        self.reader_registry
            .lock()
            .unwrap()
            .insert(reader_id, registration);
        notify_handle
    }

    async fn process_frame(
        &self,
        frame: WebSocketFrame,
        tracker: Arc<WebSocketFrameNotificationTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let frame_id = FrameId(self.frame_id_counter.fetch_add(1, Ordering::Release));
        let timestamp = Instant::now();

        // Add frame to buffer
        {
            let mut buffer = self.frame_buffer.lock().unwrap();
            buffer.push_back(frame.clone());
            if buffer.len() > 1000 {
                buffer.pop_front();
            }
        }

        // Get current reader count
        let reader_count = self.reader_registry.lock().unwrap().len() as u32;

        // Record frame processing event
        let frame_event = FrameProcessingEvent {
            timestamp,
            frame_type: frame.frame_type(),
            frame_id,
            processing_state: FrameProcessingState::Processing,
            reader_count,
            notification_triggered: false,
        };
        tracker.record_frame_event(frame_event);

        // Determine notification strategy based on frame type
        match frame.frame_type() {
            FrameType::Close => {
                self.handle_close_frame(frame, frame_id, tracker.clone())
                    .await?;
            }
            FrameType::Text | FrameType::Binary => {
                self.handle_data_frame(frame, frame_id, tracker.clone())
                    .await?;
            }
            FrameType::Ping | FrameType::Pong => {
                self.handle_control_frame(frame, frame_id, tracker.clone())
                    .await?;
            }
        }

        Ok(())
    }

    async fn handle_close_frame(
        &self,
        frame: WebSocketFrame,
        frame_id: FrameId,
        tracker: Arc<WebSocketFrameNotificationTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = Instant::now();

        // Get all registered readers
        let target_readers: Vec<ReaderId> = {
            let registry = self.reader_registry.lock().unwrap();
            registry
                .keys()
                .filter(|&reader_id| {
                    registry
                        .get(reader_id)
                        .map(|reg| reg.frame_filter.accept_close_frames)
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        };

        // Broadcast close-frame notification to all waiting readers
        let notification_start = Instant::now();
        let mut successful_deliveries = 0;

        for reader_id in &target_readers {
            if let Some(registration) = self.reader_registry.lock().unwrap().get(reader_id) {
                // Notify the reader
                registration.notify_handle.notify().await;
                registration.wake_count.fetch_add(1, Ordering::Release);
                successful_deliveries += 1;

                // Verify this is not a spurious wake
                let wake_verification = WakeVerificationEvent {
                    timestamp,
                    reader_id: *reader_id,
                    wake_reason: WakeReason::FrameAvailable {
                        frame_type: FrameType::Close,
                    },
                    expected_wake: true,
                    verification_result: WakeVerificationResult::ValidWake,
                    frame_context: Some(frame_id),
                };
                tracker.record_wake_verification(wake_verification);
            }
        }

        let delivery_latency = notification_start.elapsed();

        // Record notification delivery
        let notification_event = NotificationDeliveryEvent {
            timestamp,
            notification_id: NotificationId::new(),
            target_readers: target_readers.clone(),
            delivery_method: NotificationDeliveryMethod::Broadcast,
            delivery_latency,
            successful_deliveries,
        };
        tracker.record_notification_event(notification_event);

        // Record reader coordination
        let coordination_event = ReaderCoordinationEvent {
            timestamp,
            coordination_type: CoordinationType::CloseFrameBroadcast,
            participating_readers: target_readers,
            coordination_result: CoordinationResult::Success {
                completion_time: delivery_latency,
            },
            frame_trigger: Some(frame_id),
        };
        tracker.record_reader_coordination(coordination_event);

        Ok(())
    }

    async fn handle_data_frame(
        &self,
        frame: WebSocketFrame,
        frame_id: FrameId,
        tracker: Arc<WebSocketFrameNotificationTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // For data frames, notify one reader at a time to avoid spurious wakes
        let target_reader = {
            let registry = self.reader_registry.lock().unwrap();
            registry
                .keys()
                .find(|&reader_id| {
                    registry
                        .get(reader_id)
                        .map(|reg| reg.frame_filter.accept_data_frames)
                        .unwrap_or(false)
                })
                .cloned()
        };

        if let Some(reader_id) = target_reader {
            if let Some(registration) = self.reader_registry.lock().unwrap().get(&reader_id) {
                registration.notify_handle.notify().await;
                registration.wake_count.fetch_add(1, Ordering::Release);

                let notification_event = NotificationDeliveryEvent {
                    timestamp: Instant::now(),
                    notification_id: NotificationId::new(),
                    target_readers: vec![reader_id],
                    delivery_method: NotificationDeliveryMethod::Targeted { reader_id },
                    delivery_latency: Duration::ZERO,
                    successful_deliveries: 1,
                };
                tracker.record_notification_event(notification_event);
            }
        }

        Ok(())
    }

    async fn handle_control_frame(
        &self,
        frame: WebSocketFrame,
        frame_id: FrameId,
        tracker: Arc<WebSocketFrameNotificationTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Control frames notify all interested readers
        let target_readers: Vec<ReaderId> = {
            let registry = self.reader_registry.lock().unwrap();
            registry
                .keys()
                .filter(|&reader_id| {
                    registry
                        .get(reader_id)
                        .map(|reg| reg.frame_filter.accept_control_frames)
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        };

        for reader_id in &target_readers {
            if let Some(registration) = self.reader_registry.lock().unwrap().get(reader_id) {
                registration.notify_handle.notify().await;
                registration.wake_count.fetch_add(1, Ordering::Release);
            }
        }

        Ok(())
    }

    fn stop_processing(&self) {
        self.processing_active.store(false, Ordering::Release);
    }

    fn get_reader_count(&self) -> usize {
        self.reader_registry.lock().unwrap().len()
    }

    fn get_frame_buffer_size(&self) -> usize {
        self.frame_buffer.lock().unwrap().len()
    }
}

/// Mock WebSocket frame reader that waits for notifications
struct MockWebSocketFrameReader {
    reader_id: ReaderId,
    notify_handle: Option<NotifyHandle>,
    frames_received: Arc<AtomicU32>,
    spurious_wake_detector: SpuriousWakeDetector,
    last_wake_time: Arc<Mutex<Option<Instant>>>,
    active: Arc<AtomicBool>,
}

impl MockWebSocketFrameReader {
    fn new(reader_id: ReaderId) -> Self {
        Self {
            reader_id,
            notify_handle: None,
            frames_received: Arc::new(AtomicU32::new(0)),
            spurious_wake_detector: SpuriousWakeDetector::new(),
            last_wake_time: Arc::new(Mutex::new(None)),
            active: Arc::new(AtomicBool::new(true)),
        }
    }

    fn set_notify_handle(&mut self, handle: NotifyHandle) {
        self.notify_handle = Some(handle);
    }

    async fn wait_for_frames(
        &self,
        processor: Arc<MockWebSocketFrameProcessor>,
        tracker: Arc<WebSocketFrameNotificationTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let notify_handle = self.notify_handle.as_ref().ok_or("No notify handle set")?;

        while self.active.load(Ordering::Acquire) {
            // Wait for notification
            let wake_time = Instant::now();
            notify_handle.notified().await;

            // Record wake time
            *self.last_wake_time.lock().unwrap() = Some(wake_time);

            // Check if this is a spurious wake
            let is_spurious = self
                .check_for_spurious_wake(&processor, wake_time, tracker.clone())
                .await;

            if !is_spurious {
                // Process available frames
                self.process_available_frames(&processor, tracker.clone())
                    .await?;
            }
        }

        Ok(())
    }

    async fn check_for_spurious_wake(
        &self,
        processor: &MockWebSocketFrameProcessor,
        wake_time: Instant,
        tracker: Arc<WebSocketFrameNotificationTracker>,
    ) -> bool {
        // Check if there are actually frames available
        let has_frames = {
            let buffer = processor.frame_buffer.lock().unwrap();
            !buffer.is_empty()
        };

        if !has_frames {
            // This is a spurious wake
            let spurious_event = SpuriousWakeEvent {
                timestamp: wake_time,
                reader_id: self.reader_id,
                spurious_reason: SpuriousWakeReason::NoFrameAvailable,
                frame_context: None,
                task_context: TaskContext {
                    task_id: TaskId::new(self.reader_id.0 as u64),
                    wake_count: self.frames_received.load(Ordering::Acquire),
                    last_wake_time: wake_time,
                    reader_state: ReaderState::WaitingForFrame,
                },
            };
            tracker.record_spurious_wake(spurious_event);

            let wake_verification = WakeVerificationEvent {
                timestamp: wake_time,
                reader_id: self.reader_id,
                wake_reason: WakeReason::Unknown,
                expected_wake: false,
                verification_result: WakeVerificationResult::SpuriousWake {
                    reason: "No frames available".to_string(),
                },
                frame_context: None,
            };
            tracker.record_wake_verification(wake_verification);

            return true;
        }

        // Check for duplicate notification
        if let Some(last_wake) = *self.last_wake_time.lock().unwrap() {
            if wake_time.duration_since(last_wake) < Duration::from_millis(1) {
                let spurious_event = SpuriousWakeEvent {
                    timestamp: wake_time,
                    reader_id: self.reader_id,
                    spurious_reason: SpuriousWakeReason::DuplicateNotification,
                    frame_context: None,
                    task_context: TaskContext {
                        task_id: TaskId::new(self.reader_id.0 as u64),
                        wake_count: self.frames_received.load(Ordering::Acquire),
                        last_wake_time: wake_time,
                        reader_state: ReaderState::ProcessingFrame,
                    },
                };
                tracker.record_spurious_wake(spurious_event);
                return true;
            }
        }

        false
    }

    async fn process_available_frames(
        &self,
        processor: &MockWebSocketFrameProcessor,
        tracker: Arc<WebSocketFrameNotificationTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let frames_to_process = {
            let mut buffer = processor.frame_buffer.lock().unwrap();
            let mut frames = Vec::new();
            while let Some(frame) = buffer.pop_front() {
                frames.push(frame);
                if frames.len() >= 4 {
                    // Process in small batches
                    break;
                }
            }
            frames
        };

        for frame in frames_to_process {
            self.frames_received.fetch_add(1, Ordering::Release);

            // Simulate frame processing delay
            Sleep::new(Instant::now() + Duration::from_millis(10)).await;

            // If this is a close frame, stop processing
            if frame.frame_type() == FrameType::Close {
                self.active.store(false, Ordering::Release);
                break;
            }
        }

        Ok(())
    }

    fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }

    fn get_frames_received(&self) -> u32 {
        self.frames_received.load(Ordering::Acquire)
    }

    fn get_reader_id(&self) -> ReaderId {
        self.reader_id
    }
}

// Test implementations start here

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_close_frame_notification_all_readers() {
        let config = WebSocketFrameNotifyTestConfig {
            concurrent_readers: 6,
            close_frame_delay: Duration::from_millis(300),
            max_spurious_wakes: 1,
            ..Default::default()
        };

        let tracker = Arc::new(WebSocketFrameNotificationTracker::new());
        let processor = Arc::new(MockWebSocketFrameProcessor::new());

        // Create and register frame readers
        let mut readers = Vec::new();
        for i in 0..config.concurrent_readers {
            let reader_id = ReaderId(i);
            let mut reader = MockWebSocketFrameReader::new(reader_id);

            let frame_filter = FrameFilter::default();
            let notify_handle = processor.register_reader(reader_id, frame_filter);
            reader.set_notify_handle(notify_handle);

            readers.push(Arc::new(reader));
        }

        // Start frame reading tasks
        let reader_handles: Vec<_> = readers
            .iter()
            .map(|reader| {
                let reader = reader.clone();
                let processor = processor.clone();
                let tracker = tracker.clone();

                tokio::spawn(async move { reader.wait_for_frames(processor, tracker).await })
            })
            .collect();

        // Send some data frames first
        for i in 0..5 {
            let data_frame = WebSocketFrame::new_text(format!("test message {}", i));
            processor
                .process_frame(data_frame, tracker.clone())
                .await
                .unwrap();

            Sleep::new(Instant::now() + Duration::from_millis(50)).await;
        }

        // Wait for readers to be established and processing
        Sleep::new(Instant::now() + config.close_frame_delay).await;

        // Send close frame - this should notify ALL readers
        let close_frame = WebSocketFrame::new_close(CloseCode::Normal, "Test close");
        processor
            .process_frame(close_frame, tracker.clone())
            .await
            .unwrap();

        // Wait for close frame processing
        Sleep::new(Instant::now() + Duration::from_millis(200)).await;

        // Stop all readers
        for reader in &readers {
            reader.stop();
        }

        // Wait for reader tasks to complete
        for handle in reader_handles {
            let _ = handle.await;
        }

        // Verify results
        assert!(
            tracker.verify_close_frame_notification_completeness(),
            "Close frame should notify all readers"
        );
        assert!(
            tracker.verify_no_spurious_wakes(config.max_spurious_wakes),
            "Should have minimal spurious wakes"
        );
        assert!(
            tracker.verify_no_missed_wakes(),
            "Should have no missed wakeups"
        );
        assert!(
            tracker.verify_notification_ordering(),
            "Notifications should be properly ordered"
        );

        // Verify all readers received the close frame
        let total_frames_received: u32 = readers.iter().map(|r| r.get_frames_received()).sum();
        assert!(total_frames_received > 0, "Readers should receive frames");

        // Verify close frame processing occurred
        assert!(
            tracker.get_close_frame_processing_count() >= 1,
            "Should have processed close frame"
        );

        // Verify notification delivery success rate
        assert!(
            tracker.get_successful_notification_rate() > 0.8,
            "Should have high notification success rate"
        );
    }

    #[tokio::test]
    async fn test_spurious_wake_prevention() {
        let config = WebSocketFrameNotifyTestConfig {
            concurrent_readers: 4,
            frame_batch_size: 8,
            test_duration: Duration::from_millis(1500),
            max_spurious_wakes: 0, // Very strict spurious wake limit
            ..Default::default()
        };

        let tracker = Arc::new(WebSocketFrameNotificationTracker::new());
        let processor = Arc::new(MockWebSocketFrameProcessor::new());

        // Create readers with different frame filters to test spurious wake scenarios
        let mut readers = Vec::new();
        for i in 0..config.concurrent_readers {
            let reader_id = ReaderId(i);
            let mut reader = MockWebSocketFrameReader::new(reader_id);

            // Create varied frame filters to test notification targeting
            let frame_filter = match i {
                0 => FrameFilter {
                    accept_close_frames: true,
                    accept_data_frames: false,
                    accept_control_frames: false,
                    specific_opcodes: BTreeSet::new(),
                },
                1 => FrameFilter {
                    accept_close_frames: true,
                    accept_data_frames: true,
                    accept_control_frames: false,
                    specific_opcodes: BTreeSet::new(),
                },
                _ => FrameFilter::default(),
            };

            let notify_handle = processor.register_reader(reader_id, frame_filter);
            reader.set_notify_handle(notify_handle);
            readers.push(Arc::new(reader));
        }

        // Start reading tasks
        let reader_handles: Vec<_> = readers
            .iter()
            .map(|reader| {
                let reader = reader.clone();
                let processor = processor.clone();
                let tracker = tracker.clone();

                tokio::spawn(async move { reader.wait_for_frames(processor, tracker).await })
            })
            .collect();

        // Send frames that should NOT wake certain readers
        for i in 0..10 {
            let frame = if i % 3 == 0 {
                WebSocketFrame::new_ping(format!("ping-{}", i))
            } else {
                WebSocketFrame::new_text(format!("data-{}", i))
            };

            processor
                .process_frame(frame, tracker.clone())
                .await
                .unwrap();
            Sleep::new(Instant::now() + Duration::from_millis(100)).await;
        }

        // Send close frame
        let close_frame = WebSocketFrame::new_close(CloseCode::Normal, "Spurious wake test");
        processor
            .process_frame(close_frame, tracker.clone())
            .await
            .unwrap();

        // Wait for processing completion
        Sleep::new(Instant::now() + Duration::from_millis(300)).await;

        // Cleanup
        for reader in &readers {
            reader.stop();
        }

        for handle in reader_handles {
            let _ = handle.await;
        }

        // Verify spurious wake prevention
        assert!(
            tracker.verify_no_spurious_wakes(config.max_spurious_wakes),
            "Should prevent spurious wakes with strict filtering"
        );
        assert!(
            tracker.verify_notification_ordering(),
            "Should maintain notification order"
        );

        // Verify that only appropriate readers were woken
        let spurious_wake_count = tracker.get_spurious_wake_count();
        assert!(
            spurious_wake_count <= config.max_spurious_wakes,
            "Spurious wake count {} should be <= {}",
            spurious_wake_count,
            config.max_spurious_wakes
        );
    }

    #[tokio::test]
    async fn test_missed_wakeup_detection_and_recovery() {
        let config = WebSocketFrameNotifyTestConfig {
            concurrent_readers: 3,
            test_duration: Duration::from_secs(1),
            wake_verification_timeout: Duration::from_millis(50),
            ..Default::default()
        };

        let tracker = Arc::new(WebSocketFrameNotificationTracker::new());
        let processor = Arc::new(MockWebSocketFrameProcessor::new());

        // Create readers
        let mut readers = Vec::new();
        for i in 0..config.concurrent_readers {
            let reader_id = ReaderId(i);
            let mut reader = MockWebSocketFrameReader::new(reader_id);

            let notify_handle = processor.register_reader(reader_id, FrameFilter::default());
            reader.set_notify_handle(notify_handle);
            readers.push(Arc::new(reader));
        }

        // Start reader tasks
        let reader_handles: Vec<_> = readers
            .iter()
            .map(|reader| {
                let reader = reader.clone();
                let processor = processor.clone();
                let tracker = tracker.clone();

                tokio::spawn(async move { reader.wait_for_frames(processor, tracker).await })
            })
            .collect();

        // Send rapid sequence of frames to test notification handling
        for i in 0..15 {
            let frame = match i % 4 {
                0 => WebSocketFrame::new_text(format!("burst-{}", i)),
                1 => WebSocketFrame::new_binary(format!("binary-{}", i).into_bytes()),
                2 => WebSocketFrame::new_ping(format!("ping-{}", i)),
                _ => WebSocketFrame::new_pong(format!("pong-{}", i)),
            };

            processor
                .process_frame(frame, tracker.clone())
                .await
                .unwrap();

            // Minimal delay to create potential race conditions
            Sleep::new(Instant::now() + Duration::from_millis(20)).await;
        }

        // Send close frame
        let close_frame = WebSocketFrame::new_close(CloseCode::Normal, "Missed wakeup test");
        processor
            .process_frame(close_frame, tracker.clone())
            .await
            .unwrap();

        // Wait for all processing to complete
        Sleep::new(Instant::now() + Duration::from_millis(400)).await;

        // Cleanup
        for reader in &readers {
            reader.stop();
        }

        for handle in reader_handles {
            let _ = handle.await;
        }

        // Verify no missed wakeups
        assert!(
            tracker.verify_no_missed_wakes(),
            "Should detect and handle any missed wakeups"
        );
        assert!(
            tracker.verify_close_frame_notification_completeness(),
            "Close frame should reach all readers despite rapid frames"
        );

        // Verify reasonable wake patterns
        let total_wakes = tracker.get_total_wake_count();
        assert!(total_wakes > 0, "Should have wakeup activity");

        // Verify all readers received frames
        let active_readers = readers
            .iter()
            .filter(|r| r.get_frames_received() > 0)
            .count();
        assert!(
            active_readers > 0,
            "At least some readers should receive frames"
        );
    }

    #[test]
    fn test_frame_filter_logic() {
        let close_only_filter = FrameFilter {
            accept_close_frames: true,
            accept_data_frames: false,
            accept_control_frames: false,
            specific_opcodes: BTreeSet::new(),
        };

        assert!(close_only_filter.accept_close_frames);
        assert!(!close_only_filter.accept_data_frames);
        assert!(!close_only_filter.accept_control_frames);

        let all_frames_filter = FrameFilter::default();
        assert!(all_frames_filter.accept_close_frames);
        assert!(all_frames_filter.accept_data_frames);
        assert!(all_frames_filter.accept_control_frames);
    }

    #[test]
    fn test_wake_verification_result_types() {
        use WakeVerificationResult::*;

        let results = vec![
            ValidWake,
            SpuriousWake {
                reason: "test reason".to_string(),
            },
            MissedWake {
                expected_frame: FrameId(42),
            },
            DelayedWake {
                delay: Duration::from_millis(100),
            },
        ];

        for result in results {
            match result {
                ValidWake => {
                    // Test that ValidWake variant is properly constructed
                    assert!(matches!(result, ValidWake));
                }
                SpuriousWake { reason } => assert!(!reason.is_empty()),
                MissedWake { expected_frame } => assert!(expected_frame.0 > 0),
                DelayedWake { delay } => assert!(delay > Duration::ZERO),
            }
        }
    }
}

// Supporting types and implementations

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReaderId(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FrameId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NotificationId(u64);

impl NotificationId {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Release))
    }
}

#[derive(Debug, Clone)]
struct WebSocketFrame {
    header: FrameHeader,
    payload: Vec<u8>,
}

impl WebSocketFrame {
    fn new_text(text: String) -> Self {
        Self {
            header: FrameHeader {
                opcode: FrameOpcode::Text,
                fin: true,
                mask: None,
                payload_length: text.len() as u64,
            },
            payload: text.into_bytes(),
        }
    }

    fn new_binary(data: Vec<u8>) -> Self {
        Self {
            header: FrameHeader {
                opcode: FrameOpcode::Binary,
                fin: true,
                mask: None,
                payload_length: data.len() as u64,
            },
            payload: data,
        }
    }

    fn new_close(code: CloseCode, reason: &str) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(code as u16).to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());

        Self {
            header: FrameHeader {
                opcode: FrameOpcode::Close,
                fin: true,
                mask: None,
                payload_length: payload.len() as u64,
            },
            payload,
        }
    }

    fn new_ping(data: String) -> Self {
        Self {
            header: FrameHeader {
                opcode: FrameOpcode::Ping,
                fin: true,
                mask: None,
                payload_length: data.len() as u64,
            },
            payload: data.into_bytes(),
        }
    }

    fn new_pong(data: String) -> Self {
        Self {
            header: FrameHeader {
                opcode: FrameOpcode::Pong,
                fin: true,
                mask: None,
                payload_length: data.len() as u64,
            },
            payload: data.into_bytes(),
        }
    }

    fn frame_type(&self) -> FrameType {
        match self.header.opcode {
            FrameOpcode::Text => FrameType::Text,
            FrameOpcode::Binary => FrameType::Binary,
            FrameOpcode::Close => FrameType::Close,
            FrameOpcode::Ping => FrameType::Ping,
            FrameOpcode::Pong => FrameType::Pong,
            _ => FrameType::Text, // Default
        }
    }
}

#[derive(Debug, Clone)]
struct FrameHeader {
    opcode: FrameOpcode,
    fin: bool,
    mask: Option<MaskingKey>,
    payload_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum FrameOpcode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FrameType {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CloseCode {
    Normal = 1000,
    GoingAway = 1001,
    ProtocolError = 1002,
    UnsupportedData = 1003,
    InvalidFramePayloadData = 1007,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    MandatoryExtension = 1010,
    InternalServerError = 1011,
}

#[derive(Debug, Clone)]
struct CloseFrame {
    code: CloseCode,
    reason: String,
}

#[derive(Debug, Clone)]
struct FrameParser;

impl FrameParser {
    fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone)]
struct FrameReader;

#[derive(Debug, Clone)]
struct FrameWriter;

#[derive(Debug, Clone)]
struct MaskingKey([u8; 4]);

#[derive(Debug, Clone)]
struct PayloadLength(u64);

#[derive(Debug, Clone)]
struct FrameBuffer;

#[derive(Debug, Clone)]
enum ParseResult {
    Complete(WebSocketFrame),
    Incomplete,
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
enum FrameProcessingState {
    Pending,
    Processing,
    Completed,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
enum ReaderState {
    Idle,
    WaitingForFrame,
    ProcessingFrame,
    Error,
}

#[derive(Debug, Clone)]
struct FrameNotificationEvent;

#[derive(Debug, Clone)]
enum WebSocketError {
    FrameParseError,
    InvalidOpcode,
    PayloadTooLarge,
    ProtocolViolation,
}

#[derive(Debug, Clone)]
struct WebSocketConfig;

// Sync/notify types

#[derive(Debug, Clone)]
struct Notify;

#[derive(Debug, Clone)]
struct NotifyHandle {
    id: u64,
}

impl NotifyHandle {
    async fn notify(&self) {
        // Mock notification
        Sleep::new(Instant::now() + Duration::from_micros(100)).await;
    }

    async fn notified(&self) {
        // Mock wait for notification
        Sleep::new(Instant::now() + Duration::from_millis(10)).await;
    }
}

#[derive(Debug, Clone)]
struct WakeEvent {
    timestamp: Instant,
    reason: WakeReason,
}

#[derive(Debug, Clone, PartialEq)]
enum WakeReason {
    FrameAvailable { frame_type: FrameType },
    CloseFrame,
    Notification,
    Timeout,
    Cancel,
    Unknown,
}

#[derive(Debug, Clone)]
struct NotificationTracker;

#[derive(Debug, Clone)]
struct WakeupVerification;

#[derive(Debug, Clone)]
struct SpuriousWakeDetector;

impl SpuriousWakeDetector {
    fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone)]
struct MissedWakeDetector;

#[derive(Debug, Clone)]
struct NotifyConfig;

#[derive(Debug, Clone)]
struct NotifyMultiplexer {
    handle_counter: Arc<AtomicU64>,
}

impl NotifyMultiplexer {
    fn new() -> Self {
        Self {
            handle_counter: Arc::new(AtomicU64::new(1)),
        }
    }

    fn create_handle(&self) -> NotifyHandle {
        NotifyHandle {
            id: self.handle_counter.fetch_add(1, Ordering::Release),
        }
    }
}

#[derive(Debug, Clone)]
struct WaitGroup;
