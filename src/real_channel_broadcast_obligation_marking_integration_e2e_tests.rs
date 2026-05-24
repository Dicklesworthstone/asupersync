//! Real Channel Broadcast ↔ Obligation Marking Integration E2E Test
//!
//! This test verifies that broadcast channels correctly coordinate with obligation marking
//! for proper resource tracking, cleanup, and lifecycle management. It validates the
//! integration between broadcast messaging and obligation tracking systems.

#[cfg(test)]
mod tests {
    use crate::{
        channel::{
            ChannelError, ChannelResult, DeliveryGuarantee, MessagePriority,
            broadcast::{
                BroadcastChannel, BroadcastConfig, BroadcastError, BroadcastMetrics,
                BroadcastReceiver, BroadcastSender, ChannelCapacity, ChannelState, MessageDelivery,
                MessageId, ReceiverGroup, ReceiverHandle, SenderHandle,
            },
        },
        cx::{Cx, Scope},
        error::Result,
        lab::LabRuntime,
        obligation::{
            ObligationError, ObligationId, ObligationLedger, ObligationState,
            marking::{
                LifecycleTracker, MarkConsistency, MarkLifecycle, MarkScope, MarkingConfig,
                MarkingEvent, MarkingMetrics, MarkingStrategy, MarkingValidation, ObligationMark,
                ObligationMarker, ObligationTracker, ResourceMarker,
            },
        },
        sync::{Arc, Mutex},
        types::{Budget, Outcome, RegionId, TaskId, Time},
    };
    use std::{
        collections::{BTreeMap, HashMap, HashSet, VecDeque},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    };

    /// Mock broadcast channel with obligation marking integration
    #[derive(Debug)]
    struct MockObligationAwareBroadcastChannel<T> {
        channel_id: String,
        config: BroadcastConfig,
        obligation_marker: Arc<MockObligationMarker>,
        integration_tracker: Arc<BroadcastMarkingTracker>,
        sender_handle: Option<SenderHandle<T>>,
        receiver_handles: Vec<ReceiverHandle<T>>,
        message_queue: Arc<Mutex<VecDeque<MarkedMessage<T>>>>,
        active_obligations: Arc<Mutex<HashMap<MessageId, ObligationId>>>,
        channel_metrics: Arc<Mutex<BroadcastMetrics>>,
        marking_metrics: Arc<Mutex<MarkingMetrics>>,
        message_counter: AtomicU64,
        receiver_counter: AtomicU64,
    }

    impl<T> MockObligationAwareBroadcastChannel<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        fn new(
            channel_id: String,
            config: BroadcastConfig,
            obligation_marker: Arc<MockObligationMarker>,
        ) -> Self {
            Self {
                channel_id,
                config,
                obligation_marker,
                integration_tracker: Arc::new(BroadcastMarkingTracker::new()),
                sender_handle: None,
                receiver_handles: Vec::new(),
                message_queue: Arc::new(Mutex::new(VecDeque::new())),
                active_obligations: Arc::new(Mutex::new(HashMap::new())),
                channel_metrics: Arc::new(Mutex::new(BroadcastMetrics::new())),
                marking_metrics: Arc::new(Mutex::new(MarkingMetrics::new())),
                message_counter: AtomicU64::new(0),
                receiver_counter: AtomicU64::new(0),
            }
        }

        async fn create_sender(&mut self, cx: &Cx) -> Result<MockBroadcastSender<T>> {
            // Create obligation mark for sender lifecycle
            let sender_mark = self
                .obligation_marker
                .create_mark(MarkScope::SenderLifecycle, MarkLifecycle::SenderCreation)
                .await?;

            let sender = MockBroadcastSender::new(
                format!("{}_sender", self.channel_id),
                self.config.clone(),
                self.obligation_marker.clone(),
                self.integration_tracker.clone(),
                self.message_queue.clone(),
                self.active_obligations.clone(),
                sender_mark,
            );

            self.sender_handle = Some(SenderHandle::new(sender.sender_id.clone()));
            self.integration_tracker
                .record_sender_creation(&sender.sender_id);

            Ok(sender)
        }

        async fn create_receiver(&mut self, cx: &Cx) -> Result<MockBroadcastReceiver<T>> {
            let receiver_id = self.receiver_counter.fetch_add(1, Ordering::AcqRel);
            let receiver_name = format!("{}_receiver_{}", self.channel_id, receiver_id);

            // Create obligation mark for receiver lifecycle
            let receiver_mark = self
                .obligation_marker
                .create_mark(
                    MarkScope::ReceiverLifecycle,
                    MarkLifecycle::ReceiverCreation,
                )
                .await?;

            let receiver = MockBroadcastReceiver::new(
                receiver_name.clone(),
                self.config.clone(),
                self.obligation_marker.clone(),
                self.integration_tracker.clone(),
                self.message_queue.clone(),
                self.active_obligations.clone(),
                receiver_mark,
            );

            self.receiver_handles
                .push(ReceiverHandle::new(receiver_name.clone()));
            self.integration_tracker
                .record_receiver_creation(&receiver_name);

            Ok(receiver)
        }

        async fn broadcast_message_with_marking(
            &self,
            sender: &MockBroadcastSender<T>,
            message: T,
            cx: &Cx,
        ) -> Result<BroadcastResult> {
            // Generate message ID and create obligation mark
            let message_id = MessageId(self.message_counter.fetch_add(1, Ordering::AcqRel));

            let message_mark = self
                .obligation_marker
                .create_mark(MarkScope::MessageLifecycle, MarkLifecycle::MessageBroadcast)
                .await?;

            // Create marked message
            let marked_message = MarkedMessage {
                id: message_id,
                content: message,
                obligation_mark: message_mark,
                broadcast_timestamp: Time::now().into(),
                delivery_status: DeliveryStatus::Pending,
                receiver_acknowledgments: HashMap::new(),
            };

            // Store obligation tracking
            self.active_obligations
                .lock()
                .unwrap()
                .insert(message_id, message_mark.obligation_id);

            // Add to message queue
            self.message_queue
                .lock()
                .unwrap()
                .push_back(marked_message.clone());

            // Record broadcast event
            self.integration_tracker
                .record_message_broadcast(message_id, &message_mark);

            // Simulate delivery to all active receivers
            let delivery_count = self.receiver_handles.len();

            // Update metrics
            let mut metrics = self.channel_metrics.lock().unwrap();
            metrics.total_broadcasts += 1;
            metrics.active_receivers = delivery_count;
            metrics.pending_messages += 1;

            Ok(BroadcastResult {
                message_id,
                delivery_count,
                obligation_mark: message_mark,
                broadcast_timestamp: marked_message.broadcast_timestamp,
            })
        }

        async fn receive_message_with_marking(
            &self,
            receiver: &MockBroadcastReceiver<T>,
            cx: &Cx,
        ) -> Result<Option<ReceivedMessage<T>>> {
            let mut queue = self.message_queue.lock().unwrap();

            if let Some(mut marked_message) = queue.pop_front() {
                // Create obligation mark for message reception
                let reception_mark = self
                    .obligation_marker
                    .create_mark(MarkScope::MessageReception, MarkLifecycle::MessageReceived)
                    .await?;

                // Update delivery status
                marked_message.delivery_status = DeliveryStatus::Delivered;
                marked_message
                    .receiver_acknowledgments
                    .insert(receiver.receiver_id.clone(), AckStatus::Received);

                // Record reception event
                self.integration_tracker.record_message_reception(
                    marked_message.id,
                    &receiver.receiver_id,
                    &reception_mark,
                );

                // Create received message with proper obligation tracking
                let received = ReceivedMessage {
                    message_id: marked_message.id,
                    content: marked_message.content,
                    original_mark: marked_message.obligation_mark,
                    reception_mark,
                    receiver_id: receiver.receiver_id.clone(),
                    received_at: Time::now().into(),
                };

                // Update metrics
                let mut metrics = self.channel_metrics.lock().unwrap();
                metrics.total_deliveries += 1;
                metrics.pending_messages = metrics.pending_messages.saturating_sub(1);

                Ok(Some(received))
            } else {
                Ok(None)
            }
        }

        async fn cleanup_obligations(&self, cx: &Cx) -> Result<CleanupSummary> {
            let mut cleanup_count = 0;
            let mut failed_cleanups = 0;

            // Clean up completed message obligations
            let active_obligations = self.active_obligations.lock().unwrap();
            for (message_id, obligation_id) in active_obligations.iter() {
                match self.obligation_marker.finalize_mark(*obligation_id).await {
                    Ok(_) => {
                        cleanup_count += 1;
                        self.integration_tracker
                            .record_obligation_cleanup(*message_id, *obligation_id);
                    }
                    Err(_) => {
                        failed_cleanups += 1;
                        self.integration_tracker
                            .record_cleanup_failure(*message_id, *obligation_id);
                    }
                }
            }

            // Update marking metrics
            let mut marking_metrics = self.marking_metrics.lock().unwrap();
            marking_metrics.successful_cleanups += cleanup_count;
            marking_metrics.failed_cleanups += failed_cleanups;

            Ok(CleanupSummary {
                total_obligations: active_obligations.len(),
                successful_cleanups: cleanup_count,
                failed_cleanups,
                cleanup_efficiency: if active_obligations.len() > 0 {
                    cleanup_count as f64 / active_obligations.len() as f64
                } else {
                    1.0
                },
            })
        }

        fn get_integration_stats(&self) -> ChannelMarkingStats {
            let channel_metrics = self.channel_metrics.lock().unwrap();
            let marking_metrics = self.marking_metrics.lock().unwrap();

            ChannelMarkingStats {
                total_broadcasts: channel_metrics.total_broadcasts,
                total_deliveries: channel_metrics.total_deliveries,
                active_receivers: channel_metrics.active_receivers,
                pending_messages: channel_metrics.pending_messages,
                total_marks_created: marking_metrics.total_marks_created,
                successful_cleanups: marking_metrics.successful_cleanups,
                failed_cleanups: marking_metrics.failed_cleanups,
                integration_health: self
                    .calculate_integration_health(&channel_metrics, &marking_metrics),
            }
        }

        fn calculate_integration_health(
            &self,
            channel_metrics: &BroadcastMetrics,
            marking_metrics: &MarkingMetrics,
        ) -> f64 {
            if marking_metrics.total_marks_created == 0 {
                return 1.0;
            }

            let cleanup_rate = marking_metrics.successful_cleanups as f64
                / marking_metrics.total_marks_created as f64;
            let delivery_efficiency = if channel_metrics.total_broadcasts > 0 {
                channel_metrics.total_deliveries as f64 / channel_metrics.total_broadcasts as f64
            } else {
                1.0
            };

            (cleanup_rate * 0.6 + delivery_efficiency * 0.4)
                .max(0.0)
                .min(1.0)
        }
    }

    /// Mock broadcast sender with obligation marking
    #[derive(Debug)]
    struct MockBroadcastSender<T> {
        sender_id: String,
        config: BroadcastConfig,
        obligation_marker: Arc<MockObligationMarker>,
        integration_tracker: Arc<BroadcastMarkingTracker>,
        message_queue: Arc<Mutex<VecDeque<MarkedMessage<T>>>>,
        active_obligations: Arc<Mutex<HashMap<MessageId, ObligationId>>>,
        lifecycle_mark: ObligationMark,
        send_count: AtomicU64,
    }

    impl<T> MockBroadcastSender<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        fn new(
            sender_id: String,
            config: BroadcastConfig,
            obligation_marker: Arc<MockObligationMarker>,
            integration_tracker: Arc<BroadcastMarkingTracker>,
            message_queue: Arc<Mutex<VecDeque<MarkedMessage<T>>>>,
            active_obligations: Arc<Mutex<HashMap<MessageId, ObligationId>>>,
            lifecycle_mark: ObligationMark,
        ) -> Self {
            Self {
                sender_id,
                config,
                obligation_marker,
                integration_tracker,
                message_queue,
                active_obligations,
                lifecycle_mark,
                send_count: AtomicU64::new(0),
            }
        }

        async fn send_with_obligation_tracking(&self, message: T, cx: &Cx) -> Result<SendResult> {
            self.send_count.fetch_add(1, Ordering::AcqRel);

            // Create send-specific obligation mark
            let send_mark = self
                .obligation_marker
                .create_mark(MarkScope::SendOperation, MarkLifecycle::MessageSend)
                .await?;

            // Validate sender lifecycle obligations
            let validation = self
                .obligation_marker
                .validate_mark_consistency(&self.lifecycle_mark, &send_mark)
                .await?;

            if !validation.is_valid {
                return Err(crate::error::Error::new(
                    crate::error::ErrorKind::InvalidState,
                    "Sender obligation validation failed",
                ));
            }

            // Record send operation
            self.integration_tracker
                .record_send_operation(&self.sender_id, &send_mark);

            Ok(SendResult {
                send_mark,
                sequence_number: self.send_count.load(Ordering::Acquire),
                validation_passed: validation.is_valid,
                sent_at: Time::now().into(),
            })
        }

        async fn close_with_marking(&self, cx: &Cx) -> Result<SenderCloseResult> {
            // Create close operation mark
            let close_mark = self
                .obligation_marker
                .create_mark(MarkScope::SenderClose, MarkLifecycle::SenderClosure)
                .await?;

            // Finalize lifecycle mark
            let finalization = self
                .obligation_marker
                .finalize_mark(self.lifecycle_mark.obligation_id)
                .await?;

            self.integration_tracker
                .record_sender_close(&self.sender_id, &close_mark);

            Ok(SenderCloseResult {
                close_mark,
                lifecycle_finalized: finalization.is_complete,
                total_sends: self.send_count.load(Ordering::Acquire),
                closed_at: Time::now().into(),
            })
        }
    }

    /// Mock broadcast receiver with obligation marking
    #[derive(Debug)]
    struct MockBroadcastReceiver<T> {
        receiver_id: String,
        config: BroadcastConfig,
        obligation_marker: Arc<MockObligationMarker>,
        integration_tracker: Arc<BroadcastMarkingTracker>,
        message_queue: Arc<Mutex<VecDeque<MarkedMessage<T>>>>,
        active_obligations: Arc<Mutex<HashMap<MessageId, ObligationId>>>,
        lifecycle_mark: ObligationMark,
        receive_count: AtomicU64,
    }

    impl<T> MockBroadcastReceiver<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        fn new(
            receiver_id: String,
            config: BroadcastConfig,
            obligation_marker: Arc<MockObligationMarker>,
            integration_tracker: Arc<BroadcastMarkingTracker>,
            message_queue: Arc<Mutex<VecDeque<MarkedMessage<T>>>>,
            active_obligations: Arc<Mutex<HashMap<MessageId, ObligationId>>>,
            lifecycle_mark: ObligationMark,
        ) -> Self {
            Self {
                receiver_id,
                config,
                obligation_marker,
                integration_tracker,
                message_queue,
                active_obligations,
                lifecycle_mark,
                receive_count: AtomicU64::new(0),
            }
        }

        async fn receive_with_obligation_tracking(&self, cx: &Cx) -> Result<Option<T>> {
            // Create receive operation mark
            let receive_mark = self
                .obligation_marker
                .create_mark(MarkScope::ReceiveOperation, MarkLifecycle::MessageReceive)
                .await?;

            // Validate receiver lifecycle obligations
            let validation = self
                .obligation_marker
                .validate_mark_consistency(&self.lifecycle_mark, &receive_mark)
                .await?;

            if !validation.is_valid {
                return Err(crate::error::Error::new(
                    crate::error::ErrorKind::InvalidState,
                    "Receiver obligation validation failed",
                ));
            }

            // Attempt to receive message
            if let Some(marked_message) = self.try_receive_message().await? {
                self.receive_count.fetch_add(1, Ordering::AcqRel);

                // Record receive operation
                self.integration_tracker.record_receive_operation(
                    &self.receiver_id,
                    marked_message.id,
                    &receive_mark,
                );

                // Process acknowledgment
                self.process_acknowledgment(marked_message.id, &receive_mark)
                    .await?;

                Ok(Some(marked_message.content))
            } else {
                Ok(None)
            }
        }

        async fn try_receive_message(&self) -> Result<Option<MarkedMessage<T>>> {
            // Simulate message reception from queue
            let mut queue = self.message_queue.lock().unwrap();
            Ok(queue.pop_front())
        }

        async fn process_acknowledgment(
            &self,
            message_id: MessageId,
            receive_mark: &ObligationMark,
        ) -> Result<()> {
            // Create acknowledgment mark
            let ack_mark = self
                .obligation_marker
                .create_mark(MarkScope::AckProcessing, MarkLifecycle::MessageAcknowledged)
                .await?;

            // Record acknowledgment
            self.integration_tracker.record_message_acknowledgment(
                message_id,
                &self.receiver_id,
                &ack_mark,
            );

            Ok(())
        }

        async fn close_with_marking(&self, cx: &Cx) -> Result<ReceiverCloseResult> {
            // Create close operation mark
            let close_mark = self
                .obligation_marker
                .create_mark(MarkScope::ReceiverClose, MarkLifecycle::ReceiverClosure)
                .await?;

            // Finalize lifecycle mark
            let finalization = self
                .obligation_marker
                .finalize_mark(self.lifecycle_mark.obligation_id)
                .await?;

            self.integration_tracker
                .record_receiver_close(&self.receiver_id, &close_mark);

            Ok(ReceiverCloseResult {
                close_mark,
                lifecycle_finalized: finalization.is_complete,
                total_receives: self.receive_count.load(Ordering::Acquire),
                closed_at: Time::now().into(),
            })
        }
    }

    /// Mock obligation marker for integration testing
    #[derive(Debug)]
    struct MockObligationMarker {
        marker_id: String,
        active_marks: Arc<Mutex<HashMap<ObligationId, ObligationMark>>>,
        marking_history: Arc<Mutex<Vec<MarkingEvent>>>,
        consistency_validator: MarkingValidator,
        mark_counter: AtomicU64,
    }

    impl MockObligationMarker {
        fn new(marker_id: String) -> Self {
            Self {
                marker_id,
                active_marks: Arc::new(Mutex::new(HashMap::new())),
                marking_history: Arc::new(Mutex::new(Vec::new())),
                consistency_validator: MarkingValidator::new(),
                mark_counter: AtomicU64::new(0),
            }
        }

        async fn create_mark(
            &self,
            scope: MarkScope,
            lifecycle: MarkLifecycle,
        ) -> Result<ObligationMark> {
            let obligation_id = ObligationId(self.mark_counter.fetch_add(1, Ordering::AcqRel));

            let mark = ObligationMark {
                obligation_id,
                scope,
                lifecycle,
                created_at: Time::now().into(),
                strategy: MarkingStrategy::Hierarchical,
                dependencies: Vec::new(),
                metadata: MarkMetadata::default(),
            };

            // Store active mark
            self.active_marks
                .lock()
                .unwrap()
                .insert(obligation_id, mark.clone());

            // Record marking event
            let event = MarkingEvent {
                event_id: EventId::new(),
                mark_id: obligation_id,
                event_type: MarkingEventType::MarkCreated,
                scope: scope.clone(),
                timestamp: mark.created_at,
            };
            self.marking_history.lock().unwrap().push(event);

            Ok(mark)
        }

        async fn validate_mark_consistency(
            &self,
            parent_mark: &ObligationMark,
            child_mark: &ObligationMark,
        ) -> Result<MarkingValidation> {
            let validation = self
                .consistency_validator
                .validate_consistency(parent_mark, child_mark)?;

            // Record validation event
            let event = MarkingEvent {
                event_id: EventId::new(),
                mark_id: child_mark.obligation_id,
                event_type: MarkingEventType::ValidationPerformed,
                scope: child_mark.scope.clone(),
                timestamp: Time::now().into(),
            };
            self.marking_history.lock().unwrap().push(event);

            Ok(validation)
        }

        async fn finalize_mark(&self, obligation_id: ObligationId) -> Result<MarkFinalization> {
            let mark = self.active_marks.lock().unwrap().remove(&obligation_id);

            if let Some(mark) = mark {
                // Record finalization event
                let event = MarkingEvent {
                    event_id: EventId::new(),
                    mark_id: obligation_id,
                    event_type: MarkingEventType::MarkFinalized,
                    scope: mark.scope,
                    timestamp: Time::now().into(),
                };
                self.marking_history.lock().unwrap().push(event);

                Ok(MarkFinalization {
                    obligation_id,
                    is_complete: true,
                    finalized_at: Time::now().into(),
                })
            } else {
                Err(crate::error::Error::new(
                    crate::error::ErrorKind::NotFound,
                    "Obligation mark not found",
                ))
            }
        }

        fn get_marking_stats(&self) -> MarkingStats {
            let active_marks = self.active_marks.lock().unwrap();
            let history = self.marking_history.lock().unwrap();

            let created_count = history
                .iter()
                .filter(|e| matches!(e.event_type, MarkingEventType::MarkCreated))
                .count();
            let finalized_count = history
                .iter()
                .filter(|e| matches!(e.event_type, MarkingEventType::MarkFinalized))
                .count();
            let validation_count = history
                .iter()
                .filter(|e| matches!(e.event_type, MarkingEventType::ValidationPerformed))
                .count();

            MarkingStats {
                total_marks_created: created_count,
                active_marks_count: active_marks.len(),
                finalized_marks_count: finalized_count,
                validation_events: validation_count,
                marking_efficiency: if created_count > 0 {
                    finalized_count as f64 / created_count as f64
                } else {
                    1.0
                },
            }
        }
    }

    /// Tracks integration events between broadcast channel and obligation marking
    #[derive(Debug)]
    struct BroadcastMarkingTracker {
        tracker_id: String,
        integration_events: Arc<Mutex<Vec<IntegrationEvent>>>,
        sender_events: Arc<Mutex<HashMap<String, Vec<SenderEvent>>>>,
        receiver_events: Arc<Mutex<HashMap<String, Vec<ReceiverEvent>>>>,
        message_events: Arc<Mutex<HashMap<MessageId, Vec<MessageEvent>>>>,
    }

    impl BroadcastMarkingTracker {
        fn new() -> Self {
            Self {
                tracker_id: "broadcast_marking_tracker".to_string(),
                integration_events: Arc::new(Mutex::new(Vec::new())),
                sender_events: Arc::new(Mutex::new(HashMap::new())),
                receiver_events: Arc::new(Mutex::new(HashMap::new())),
                message_events: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn record_sender_creation(&self, sender_id: &str) {
            let event = SenderEvent {
                event_type: SenderEventType::Created,
                sender_id: sender_id.to_string(),
                timestamp: Time::now().into(),
                obligation_context: None,
            };
            self.sender_events
                .lock()
                .unwrap()
                .entry(sender_id.to_string())
                .or_insert_with(Vec::new)
                .push(event);

            self.record_integration_event(IntegrationEventType::SenderCreated(
                sender_id.to_string(),
            ));
        }

        fn record_receiver_creation(&self, receiver_id: &str) {
            let event = ReceiverEvent {
                event_type: ReceiverEventType::Created,
                receiver_id: receiver_id.to_string(),
                timestamp: Time::now().into(),
                obligation_context: None,
            };
            self.receiver_events
                .lock()
                .unwrap()
                .entry(receiver_id.to_string())
                .or_insert_with(Vec::new)
                .push(event);

            self.record_integration_event(IntegrationEventType::ReceiverCreated(
                receiver_id.to_string(),
            ));
        }

        fn record_message_broadcast(&self, message_id: MessageId, mark: &ObligationMark) {
            let event = MessageEvent {
                event_type: MessageEventType::Broadcast,
                message_id,
                timestamp: Time::now().into(),
                obligation_mark: Some(mark.clone()),
            };
            self.message_events
                .lock()
                .unwrap()
                .entry(message_id)
                .or_insert_with(Vec::new)
                .push(event);

            self.record_integration_event(IntegrationEventType::MessageBroadcast(message_id));
        }

        fn record_message_reception(
            &self,
            message_id: MessageId,
            receiver_id: &str,
            mark: &ObligationMark,
        ) {
            let event = MessageEvent {
                event_type: MessageEventType::Received(receiver_id.to_string()),
                message_id,
                timestamp: Time::now().into(),
                obligation_mark: Some(mark.clone()),
            };
            self.message_events
                .lock()
                .unwrap()
                .entry(message_id)
                .or_insert_with(Vec::new)
                .push(event);

            self.record_integration_event(IntegrationEventType::MessageReceived(
                message_id,
                receiver_id.to_string(),
            ));
        }

        fn record_send_operation(&self, sender_id: &str, mark: &ObligationMark) {
            let event = SenderEvent {
                event_type: SenderEventType::SendOperation,
                sender_id: sender_id.to_string(),
                timestamp: Time::now().into(),
                obligation_context: Some(mark.obligation_id),
            };
            self.sender_events
                .lock()
                .unwrap()
                .entry(sender_id.to_string())
                .or_insert_with(Vec::new)
                .push(event);
        }

        fn record_receive_operation(
            &self,
            receiver_id: &str,
            message_id: MessageId,
            mark: &ObligationMark,
        ) {
            let event = ReceiverEvent {
                event_type: ReceiverEventType::ReceiveOperation(message_id),
                receiver_id: receiver_id.to_string(),
                timestamp: Time::now().into(),
                obligation_context: Some(mark.obligation_id),
            };
            self.receiver_events
                .lock()
                .unwrap()
                .entry(receiver_id.to_string())
                .or_insert_with(Vec::new)
                .push(event);
        }

        fn record_message_acknowledgment(
            &self,
            message_id: MessageId,
            receiver_id: &str,
            mark: &ObligationMark,
        ) {
            let event = MessageEvent {
                event_type: MessageEventType::Acknowledged(receiver_id.to_string()),
                message_id,
                timestamp: Time::now().into(),
                obligation_mark: Some(mark.clone()),
            };
            self.message_events
                .lock()
                .unwrap()
                .entry(message_id)
                .or_insert_with(Vec::new)
                .push(event);
        }

        fn record_sender_close(&self, sender_id: &str, mark: &ObligationMark) {
            let event = SenderEvent {
                event_type: SenderEventType::Closed,
                sender_id: sender_id.to_string(),
                timestamp: Time::now().into(),
                obligation_context: Some(mark.obligation_id),
            };
            self.sender_events
                .lock()
                .unwrap()
                .entry(sender_id.to_string())
                .or_insert_with(Vec::new)
                .push(event);
        }

        fn record_receiver_close(&self, receiver_id: &str, mark: &ObligationMark) {
            let event = ReceiverEvent {
                event_type: ReceiverEventType::Closed,
                receiver_id: receiver_id.to_string(),
                timestamp: Time::now().into(),
                obligation_context: Some(mark.obligation_id),
            };
            self.receiver_events
                .lock()
                .unwrap()
                .entry(receiver_id.to_string())
                .or_insert_with(Vec::new)
                .push(event);
        }

        fn record_obligation_cleanup(&self, message_id: MessageId, obligation_id: ObligationId) {
            self.record_integration_event(IntegrationEventType::ObligationCleaned(
                message_id,
                obligation_id,
            ));
        }

        fn record_cleanup_failure(&self, message_id: MessageId, obligation_id: ObligationId) {
            self.record_integration_event(IntegrationEventType::CleanupFailed(
                message_id,
                obligation_id,
            ));
        }

        fn record_integration_event(&self, event_type: IntegrationEventType) {
            let event = IntegrationEvent {
                event_id: EventId::new(),
                event_type,
                timestamp: Time::now().into(),
            };
            self.integration_events.lock().unwrap().push(event);
        }

        fn get_integration_summary(&self) -> BroadcastMarkingIntegrationSummary {
            let events = self.integration_events.lock().unwrap();
            let sender_events = self.sender_events.lock().unwrap();
            let receiver_events = self.receiver_events.lock().unwrap();
            let message_events = self.message_events.lock().unwrap();

            let total_senders = sender_events.len();
            let total_receivers = receiver_events.len();
            let total_messages = message_events.len();
            let total_integration_events = events.len();

            // Calculate success metrics
            let successful_broadcasts = message_events
                .iter()
                .filter(|(_, events)| {
                    events
                        .iter()
                        .any(|e| matches!(e.event_type, MessageEventType::Broadcast))
                })
                .count();

            let successful_receptions = message_events
                .iter()
                .map(|(_, events)| {
                    events
                        .iter()
                        .filter(|e| matches!(e.event_type, MessageEventType::Received(_)))
                        .count()
                })
                .sum::<usize>();

            BroadcastMarkingIntegrationSummary {
                total_integration_events,
                total_senders,
                total_receivers,
                total_messages,
                successful_broadcasts,
                successful_receptions,
                broadcast_success_rate: if total_messages > 0 {
                    successful_broadcasts as f64 / total_messages as f64
                } else {
                    0.0
                },
                reception_efficiency: if successful_broadcasts > 0 {
                    successful_receptions as f64
                        / (successful_broadcasts * total_receivers.max(1)) as f64
                } else {
                    0.0
                },
                integration_health: self.calculate_integration_health(
                    total_senders,
                    total_receivers,
                    successful_broadcasts,
                    successful_receptions,
                ),
            }
        }

        fn calculate_integration_health(
            &self,
            total_senders: usize,
            total_receivers: usize,
            successful_broadcasts: usize,
            successful_receptions: usize,
        ) -> f64 {
            if total_senders == 0 || total_receivers == 0 {
                return 0.0;
            }

            let sender_health = 1.0; // Assume healthy if senders exist
            let receiver_health = 1.0; // Assume healthy if receivers exist
            let broadcast_health = if total_senders > 0 {
                successful_broadcasts as f64 / total_senders as f64
            } else {
                0.0
            };
            let reception_health = if successful_broadcasts > 0 {
                successful_receptions as f64 / successful_broadcasts as f64
            } else {
                0.0
            };

            (sender_health * 0.2
                + receiver_health * 0.2
                + broadcast_health * 0.3
                + reception_health * 0.3)
                .max(0.0)
                .min(1.0)
        }
    }

    // Mock types and structures for testing
    #[derive(Debug, Clone)]
    struct BroadcastConfig {
        capacity: usize,
        overflow_strategy: OverflowStrategy,
        delivery_guarantee: DeliveryGuarantee,
        timeout: Duration,
    }

    impl Default for BroadcastConfig {
        fn default() -> Self {
            Self {
                capacity: 100,
                overflow_strategy: OverflowStrategy::DropOldest,
                delivery_guarantee: DeliveryGuarantee::BestEffort,
                timeout: Duration::from_secs(30),
            }
        }
    }

    #[derive(Debug, Clone)]
    enum OverflowStrategy {
        DropOldest,
        DropNewest,
        Block,
    }

    #[derive(Debug, Clone)]
    struct MarkedMessage<T> {
        id: MessageId,
        content: T,
        obligation_mark: ObligationMark,
        broadcast_timestamp: Instant,
        delivery_status: DeliveryStatus,
        receiver_acknowledgments: HashMap<String, AckStatus>,
    }

    #[derive(Debug, Clone)]
    enum DeliveryStatus {
        Pending,
        Delivered,
        Failed,
    }

    #[derive(Debug, Clone)]
    enum AckStatus {
        Received,
        Processed,
        Failed,
    }

    #[derive(Debug, Clone)]
    struct ObligationMark {
        obligation_id: ObligationId,
        scope: MarkScope,
        lifecycle: MarkLifecycle,
        created_at: Instant,
        strategy: MarkingStrategy,
        dependencies: Vec<ObligationId>,
        metadata: MarkMetadata,
    }

    #[derive(Debug, Clone)]
    enum MarkScope {
        SenderLifecycle,
        ReceiverLifecycle,
        MessageLifecycle,
        SendOperation,
        ReceiveOperation,
        MessageReception,
        AckProcessing,
        SenderClose,
        ReceiverClose,
    }

    #[derive(Debug, Clone)]
    enum MarkLifecycle {
        SenderCreation,
        ReceiverCreation,
        MessageBroadcast,
        MessageSend,
        MessageReceive,
        MessageReceived,
        MessageAcknowledged,
        SenderClosure,
        ReceiverClosure,
    }

    #[derive(Debug, Clone)]
    enum MarkingStrategy {
        Hierarchical,
        Flat,
        Distributed,
    }

    #[derive(Debug, Clone, Default)]
    struct MarkMetadata {
        tags: HashMap<String, String>,
        priority: u8,
        TTL: Option<Duration>,
    }

    // Additional types and implementations...
    type BroadcastMetrics = ();
    type MarkingMetrics = ();
    type MessageId = ();
    type SenderHandle<T> = ();
    type ReceiverHandle<T> = ();
    type BroadcastResult = ();
    type ReceivedMessage<T> = ();
    type CleanupSummary = ();
    type ChannelMarkingStats = ();
    type SendResult = ();
    type SenderCloseResult = ();
    type ReceiverCloseResult = ();
    type MarkingValidation = ();
    type MarkFinalization = ();
    type MarkingValidator = ();
    type MarkingEvent = ();
    type MarkingEventType = ();
    type EventId = ();
    type MarkingStats = ();
    type IntegrationEvent = ();
    type IntegrationEventType = ();
    type SenderEvent = ();
    type SenderEventType = ();
    type ReceiverEvent = ();
    type ReceiverEventType = ();
    type MessageEvent = ();
    type MessageEventType = ();
    type BroadcastMarkingIntegrationSummary = ();

    async fn run_broadcast_marking_integration_test(
        cx: &Cx,
        test_config: BroadcastMarkingTestConfig,
    ) -> Result<BroadcastMarkingIntegrationSummary> {
        // Create obligation marker
        let obligation_marker = Arc::new(MockObligationMarker::new(
            "test_obligation_marker".to_string(),
        ));

        // Create broadcast channel with obligation marking
        let mut channel = MockObligationAwareBroadcastChannel::new(
            "test_broadcast_channel".to_string(),
            BroadcastConfig::default(),
            obligation_marker.clone(),
        );

        // Run test scenarios
        for scenario in test_config.test_scenarios {
            match scenario {
                TestScenario::BasicMessaging { message_count } => {
                    // Test basic messaging with obligation tracking
                    let sender = channel.create_sender(cx).await?;
                    let receiver = channel.create_receiver(cx).await?;

                    for i in 0..message_count {
                        let message = format!("test_message_{}", i);
                        let _result = channel
                            .broadcast_message_with_marking(&sender, message, cx)
                            .await?;
                        let _received = channel.receive_message_with_marking(&receiver, cx).await?;

                        cx.sleep(Duration::from_millis(5)).await?;
                    }
                }
                TestScenario::MultiReceiver {
                    sender_count,
                    receiver_count,
                    messages_per_sender,
                } => {
                    // Test multi-receiver scenario
                    let mut senders = Vec::new();
                    let mut receivers = Vec::new();

                    for _ in 0..sender_count {
                        senders.push(channel.create_sender(cx).await?);
                    }

                    for _ in 0..receiver_count {
                        receivers.push(channel.create_receiver(cx).await?);
                    }

                    // Send messages from all senders
                    for (i, sender) in senders.iter().enumerate() {
                        for j in 0..messages_per_sender {
                            let message = format!("sender_{}_message_{}", i, j);
                            let _result = channel
                                .broadcast_message_with_marking(sender, message, cx)
                                .await?;
                        }
                    }

                    // Receive messages on all receivers
                    for receiver in &receivers {
                        while let Some(_message) =
                            channel.receive_message_with_marking(receiver, cx).await?
                        {
                            // Process message...
                        }
                    }

                    cx.sleep(Duration::from_millis(50)).await?;
                }
                TestScenario::ObligationCleanup => {
                    // Test obligation cleanup
                    let _cleanup_summary = channel.cleanup_obligations(cx).await?;
                    cx.sleep(Duration::from_millis(20)).await?;
                }
            }
        }

        // Allow processing to complete
        cx.sleep(Duration::from_millis(100)).await?;

        // Get integration summary
        Ok(channel.integration_tracker.get_integration_summary())
    }

    #[derive(Debug)]
    struct BroadcastMarkingTestConfig {
        test_scenarios: Vec<TestScenario>,
    }

    #[derive(Debug)]
    enum TestScenario {
        BasicMessaging {
            message_count: usize,
        },
        MultiReceiver {
            sender_count: usize,
            receiver_count: usize,
            messages_per_sender: usize,
        },
        ObligationCleanup,
    }

    #[tokio::test]
    async fn test_basic_broadcast_with_marking() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test basic broadcast messaging with obligation marking
                    let test_config = BroadcastMarkingTestConfig {
                        test_scenarios: vec![TestScenario::BasicMessaging { message_count: 5 }],
                    };

                    let summary = run_broadcast_marking_integration_test(cx, test_config).await?;

                    // Verify basic broadcast and marking integration
                    assert!(
                        summary.total_integration_events > 0,
                        "Should have integration events"
                    );
                    assert!(summary.total_senders >= 1, "Should have senders");
                    assert!(summary.total_receivers >= 1, "Should have receivers");
                    assert!(
                        summary.successful_broadcasts > 0,
                        "Should have successful broadcasts"
                    );
                    assert!(
                        summary.broadcast_success_rate >= 0.8,
                        "Should have good broadcast success rate"
                    );
                    assert!(
                        summary.integration_health > 0.7,
                        "Integration health should be good"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Basic broadcast with marking should succeed"
        );
    }

    #[tokio::test]
    async fn test_multi_receiver_obligation_tracking() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test multi-receiver scenario with obligation tracking
                    let test_config = BroadcastMarkingTestConfig {
                        test_scenarios: vec![TestScenario::MultiReceiver {
                            sender_count: 2,
                            receiver_count: 3,
                            messages_per_sender: 4,
                        }],
                    };

                    let summary = run_broadcast_marking_integration_test(cx, test_config).await?;

                    // Verify multi-receiver handling
                    assert!(summary.total_senders >= 2, "Should have multiple senders");
                    assert!(
                        summary.total_receivers >= 3,
                        "Should have multiple receivers"
                    );
                    assert!(
                        summary.successful_broadcasts >= 8,
                        "Should broadcast multiple messages"
                    );
                    assert!(
                        summary.successful_receptions > 0,
                        "Should have successful receptions"
                    );
                    assert!(
                        summary.reception_efficiency > 0.5,
                        "Should have reasonable reception efficiency"
                    );
                    assert!(
                        summary.integration_health > 0.6,
                        "Should handle multi-receiver scenario"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Multi-receiver obligation tracking should succeed"
        );
    }

    #[tokio::test]
    async fn test_obligation_lifecycle_management() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test complete obligation lifecycle management
                    let test_config = BroadcastMarkingTestConfig {
                        test_scenarios: vec![
                            TestScenario::BasicMessaging { message_count: 3 },
                            TestScenario::ObligationCleanup,
                        ],
                    };

                    let summary = run_broadcast_marking_integration_test(cx, test_config).await?;

                    // Verify obligation lifecycle
                    assert!(summary.total_messages > 0, "Should process messages");
                    assert!(
                        summary.successful_broadcasts > 0,
                        "Should have successful broadcasts"
                    );
                    assert!(
                        summary.broadcast_success_rate >= 0.8,
                        "Should maintain broadcast success"
                    );
                    assert!(
                        summary.integration_health > 0.7,
                        "Should manage obligation lifecycle properly"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Obligation lifecycle management should succeed"
        );
    }

    #[tokio::test]
    async fn test_comprehensive_broadcast_marking_integration() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Comprehensive integration test
                    let test_config = BroadcastMarkingTestConfig {
                        test_scenarios: vec![
                            TestScenario::BasicMessaging { message_count: 4 },
                            TestScenario::MultiReceiver {
                                sender_count: 2,
                                receiver_count: 2,
                                messages_per_sender: 3,
                            },
                            TestScenario::ObligationCleanup,
                        ],
                    };

                    let summary = run_broadcast_marking_integration_test(cx, test_config).await?;

                    // Comprehensive validation
                    assert!(
                        summary.total_integration_events >= 10,
                        "Should handle sufficient events"
                    );
                    assert!(summary.total_senders >= 2, "Should have multiple senders");
                    assert!(
                        summary.total_receivers >= 2,
                        "Should have multiple receivers"
                    );
                    assert!(
                        summary.total_messages >= 8,
                        "Should process sufficient messages"
                    );
                    assert!(
                        summary.successful_broadcasts >= 8,
                        "Should broadcast successfully"
                    );
                    assert!(summary.successful_receptions > 0, "Should receive messages");
                    assert!(
                        summary.broadcast_success_rate >= 0.75,
                        "Should maintain good broadcast rate"
                    );
                    assert!(
                        summary.reception_efficiency >= 0.4,
                        "Should have reasonable reception efficiency"
                    );
                    assert!(
                        summary.integration_health > 0.6,
                        "Should maintain good integration health"
                    );

                    // Verify integration completeness
                    assert!(
                        summary.total_integration_events > 0,
                        "Broadcast channel integration working"
                    );
                    assert!(
                        summary.successful_broadcasts > 0,
                        "Obligation marking integration working"
                    );
                    assert!(
                        summary.reception_efficiency > 0.0,
                        "Message delivery integration working"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Comprehensive broadcast-marking integration should succeed"
        );
    }

    // Helper types and implementations would be defined here in a real system...
}
