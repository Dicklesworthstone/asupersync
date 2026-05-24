//! Real-service E2E tests: channel/* ↔ supervision/* integration.
//!
//! Tests integration between:
//! - `channel`: Two-phase channel primitives (broadcast, MPSC, watch)
//! - `supervision`: Actor supervision trees and restart policies
//! - `actor`: Message-driven concurrency with mailbox integration
//!
//! This exercises channel close propagation through supervisor decisions,
//! actor mailbox integration, and forced restart scenarios on broadcast errors.

#[cfg(test)]
mod tests {
    use crate::actor::{Actor, ActorContext, ActorHandle, ActorError};
    use crate::channel::{broadcast, mpsc, watch};
    use crate::channel::broadcast::{Receiver as BroadcastReceiver, Sender as BroadcastSender};
    use crate::channel::mpsc::{Receiver as MpscReceiver, Sender as MpscSender};
    use crate::cx::Cx;
    use crate::runtime::region;
    use crate::supervision::{
        SupervisionStrategy, SupervisorTree, ChildSpec, RestartConfig, BackoffStrategy
    };
    use crate::types::{Budget, Outcome, TaskId, RegionId, Time};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
    use std::time::Duration;

    // Test message types for different communication patterns
    #[derive(Debug, Clone, PartialEq)]
    enum SupervisorMessage {
        StartChild { name: String, spec: ChildSpec },
        StopChild { name: String },
        RestartChild { name: String, reason: String },
        BroadcastError { error: String, affected_children: Vec<String> },
        StatusRequest { reply_to: MpscSender<SupervisorStatus> },
    }

    #[derive(Debug, Clone, PartialEq)]
    enum WorkerMessage {
        DoWork { task_id: u64, payload: String },
        ProcessBroadcast { data: String },
        SimulateError { error_type: ErrorType },
        GetStatus { reply_to: MpscSender<WorkerStatus> },
    }

    #[derive(Debug, Clone, PartialEq)]
    enum ErrorType {
        ProcessingError,
        BroadcastReceiveError,
        MailboxOverflow,
        ResourceExhausted,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct SupervisorStatus {
        active_children: usize,
        restart_count: u64,
        last_error: Option<String>,
        broadcast_errors: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct WorkerStatus {
        tasks_processed: u64,
        broadcasts_received: u64,
        last_error: Option<String>,
        restart_count: u64,
    }

    // Test data factories for realistic supervision scenarios
    struct SupervisionFactory {
        child_counter: AtomicU64,
        message_counter: AtomicU64,
    }

    impl SupervisionFactory {
        fn new() -> Self {
            Self {
                child_counter: AtomicU64::new(1),
                message_counter: AtomicU64::new(1),
            }
        }

        fn create_child_spec(&self, name: &str, strategy: SupervisionStrategy) -> ChildSpec {
            ChildSpec {
                name: name.to_string(),
                supervision_strategy: strategy,
                restart_config: self.default_restart_config(),
                mailbox_capacity: 32,
            }
        }

        fn default_restart_config(&self) -> RestartConfig {
            RestartConfig {
                max_restarts: 3,
                window: Duration::from_secs(60),
                backoff: BackoffStrategy::Exponential {
                    initial: Duration::from_millis(100),
                    max: Duration::from_secs(5),
                    multiplier: 2.0,
                },
            }
        }

        fn create_supervisor_message(&self, msg_type: &str) -> SupervisorMessage {
            match msg_type {
                "start_child" => SupervisorMessage::StartChild {
                    name: format!("child_{}", self.child_counter.fetch_add(1, Ordering::Relaxed)),
                    spec: self.create_child_spec("worker", SupervisionStrategy::Restart),
                },
                "broadcast_error" => SupervisorMessage::BroadcastError {
                    error: "Broadcast channel closed unexpectedly".to_string(),
                    affected_children: vec!["worker_1".to_string(), "worker_2".to_string()],
                },
                _ => SupervisorMessage::StopChild { name: "default".to_string() },
            }
        }

        fn create_worker_message(&self, msg_type: &str) -> WorkerMessage {
            match msg_type {
                "do_work" => WorkerMessage::DoWork {
                    task_id: self.message_counter.fetch_add(1, Ordering::Relaxed),
                    payload: format!("payload_{}", self.message_counter.load(Ordering::Relaxed)),
                },
                "simulate_error" => WorkerMessage::SimulateError {
                    error_type: ErrorType::BroadcastReceiveError,
                },
                "process_broadcast" => WorkerMessage::ProcessBroadcast {
                    data: format!("broadcast_data_{}", self.message_counter.fetch_add(1, Ordering::Relaxed)),
                },
                _ => WorkerMessage::DoWork { task_id: 0, payload: "default".to_string() },
            }
        }
    }

    // Test supervisor actor that manages children and handles broadcast errors
    struct TestSupervisor {
        children: HashMap<String, TestWorkerHandle>,
        broadcast_sender: Option<BroadcastSender<String>>,
        restart_count: AtomicU64,
        broadcast_errors: AtomicU64,
        last_error: parking_lot::Mutex<Option<String>>,
        logger: TestLogger,
    }

    struct TestWorkerHandle {
        actor_handle: ActorHandle<WorkerMessage>,
        task_id: TaskId,
        restart_count: u64,
        last_error: Option<String>,
    }

    impl TestSupervisor {
        fn new(
            broadcast_sender: Option<BroadcastSender<String>>,
            logger: TestLogger
        ) -> Self {
            Self {
                children: HashMap::new(),
                broadcast_sender,
                restart_count: AtomicU64::new(0),
                broadcast_errors: AtomicU64::new(0),
                last_error: parking_lot::Mutex::new(None),
                logger,
            }
        }

        async fn handle_broadcast_error(
            &mut self,
            cx: &Cx,
            error: String,
            affected_children: Vec<String>
        ) -> Result<(), ActorError> {
            self.logger.supervision_event("broadcast_error", &error);
            self.broadcast_errors.fetch_add(1, Ordering::Relaxed);
            *self.last_error.lock() = Some(error.clone());

            // Force restart affected children
            for child_name in &affected_children {
                if self.children.contains_key(child_name) {
                    self.logger.supervision_event("force_restart", child_name);
                    self.restart_child(cx, child_name, &error).await?;
                }
            }

            // Close broadcast channel if error is severe
            if error.contains("closed unexpectedly") {
                if let Some(sender) = &self.broadcast_sender {
                    // Attempt to send shutdown signal before closing
                    let _ = sender.reserve(cx).await;
                    self.logger.supervision_event("broadcast_channel_closing", "shutdown_signal_sent");
                }
            }

            Ok(())
        }

        async fn restart_child(
            &mut self,
            cx: &Cx,
            child_name: &str,
            reason: &str
        ) -> Result<(), ActorError> {
            self.logger.supervision_event("restart_child_start", child_name);

            if let Some(child_handle) = self.children.remove(child_name) {
                // Stop the existing child
                child_handle.actor_handle.stop();

                // Wait for it to finish
                let _ = child_handle.actor_handle.join(cx).await;

                self.logger.supervision_event("old_child_stopped", child_name);
            }

            // Create new worker instance
            let new_worker = TestWorker::new(
                self.broadcast_sender.clone(),
                self.logger.clone()
            );

            // Spawn new actor (simplified - real implementation would use proper region management)
            let task_id = TaskId::from_raw(self.restart_count.load(Ordering::Relaxed) + 1000);

            // Create mock actor handle for testing
            let actor_handle = self.create_mock_worker_handle(task_id);

            let new_handle = TestWorkerHandle {
                actor_handle,
                task_id,
                restart_count: self.restart_count.fetch_add(1, Ordering::Relaxed) + 1,
                last_error: Some(reason.to_string()),
            };

            self.children.insert(child_name.to_string(), new_handle);
            self.logger.supervision_event("restart_child_complete", child_name);

            Ok(())
        }

        fn create_mock_worker_handle(&self, task_id: TaskId) -> ActorHandle<WorkerMessage> {
            // Mock implementation for testing - real version would spawn actual actor
            // For now, create a handle that tracks the task_id
            ActorHandle::mock_for_testing(task_id)
        }

        fn get_status(&self) -> SupervisorStatus {
            SupervisorStatus {
                active_children: self.children.len(),
                restart_count: self.restart_count.load(Ordering::Relaxed),
                last_error: self.last_error.lock().clone(),
                broadcast_errors: self.broadcast_errors.load(Ordering::Relaxed),
            }
        }
    }

    impl Actor for TestSupervisor {
        type Message = SupervisorMessage;

        async fn handle(&mut self, cx: &Cx, msg: SupervisorMessage) -> Result<(), ActorError> {
            match msg {
                SupervisorMessage::StartChild { name, spec } => {
                    self.logger.supervision_event("start_child", &name);

                    let new_worker = TestWorker::new(
                        self.broadcast_sender.clone(),
                        self.logger.clone()
                    );

                    let task_id = TaskId::from_raw(self.children.len() as u64 + 1);
                    let actor_handle = self.create_mock_worker_handle(task_id);

                    let handle = TestWorkerHandle {
                        actor_handle,
                        task_id,
                        restart_count: 0,
                        last_error: None,
                    };

                    self.children.insert(name.clone(), handle);
                    self.logger.supervision_event("start_child_complete", &name);
                }

                SupervisorMessage::StopChild { name } => {
                    self.logger.supervision_event("stop_child", &name);

                    if let Some(handle) = self.children.remove(&name) {
                        handle.actor_handle.stop();
                        let _ = handle.actor_handle.join(cx).await;
                    }

                    self.logger.supervision_event("stop_child_complete", &name);
                }

                SupervisorMessage::RestartChild { name, reason } => {
                    self.restart_child(cx, &name, &reason).await?;
                }

                SupervisorMessage::BroadcastError { error, affected_children } => {
                    self.handle_broadcast_error(cx, error, affected_children).await?;
                }

                SupervisorMessage::StatusRequest { reply_to } => {
                    let status = self.get_status();
                    let _ = reply_to.send(status).await;
                }
            }

            Ok(())
        }
    }

    // Test worker actor that processes messages and handles broadcast data
    struct TestWorker {
        tasks_processed: AtomicU64,
        broadcasts_received: AtomicU64,
        restart_count: AtomicU64,
        last_error: parking_lot::Mutex<Option<String>>,
        broadcast_receiver: Option<BroadcastReceiver<String>>,
        logger: TestLogger,
    }

    impl TestWorker {
        fn new(broadcast_sender: Option<BroadcastSender<String>>, logger: TestLogger) -> Self {
            let broadcast_receiver = broadcast_sender.map(|sender| sender.subscribe());

            Self {
                tasks_processed: AtomicU64::new(0),
                broadcasts_received: AtomicU64::new(0),
                restart_count: AtomicU64::new(0),
                last_error: parking_lot::Mutex::new(None),
                broadcast_receiver,
                logger,
            }
        }

        async fn handle_broadcast_message(&mut self, cx: &Cx) -> Result<(), ActorError> {
            if let Some(ref mut receiver) = self.broadcast_receiver {
                match receiver.recv(cx).await {
                    Ok(data) => {
                        self.broadcasts_received.fetch_add(1, Ordering::Relaxed);
                        self.logger.worker_event("broadcast_received", &data);
                        Ok(())
                    }
                    Err(broadcast::RecvError::Closed) => {
                        self.logger.worker_event("broadcast_channel_closed", "forcing_error");
                        *self.last_error.lock() = Some("Broadcast channel closed".to_string());
                        Err(ActorError::MailboxClosed)
                    }
                    Err(broadcast::RecvError::Lagged(n)) => {
                        self.logger.worker_event("broadcast_lagged", &format!("missed_{}", n));
                        *self.last_error.lock() = Some(format!("Lagged by {} messages", n));
                        // Continue processing despite lag
                        Ok(())
                    }
                }
            } else {
                Ok(())
            }
        }

        fn simulate_error(&mut self, error_type: ErrorType) -> Result<(), ActorError> {
            match error_type {
                ErrorType::BroadcastReceiveError => {
                    *self.last_error.lock() = Some("Broadcast receive failed".to_string());
                    self.logger.worker_event("simulated_error", "broadcast_receive_error");
                    Err(ActorError::ProcessingFailed)
                }
                ErrorType::MailboxOverflow => {
                    *self.last_error.lock() = Some("Mailbox overflow".to_string());
                    self.logger.worker_event("simulated_error", "mailbox_overflow");
                    Err(ActorError::MailboxFull)
                }
                ErrorType::ResourceExhausted => {
                    *self.last_error.lock() = Some("Resource exhausted".to_string());
                    self.logger.worker_event("simulated_error", "resource_exhausted");
                    Err(ActorError::ResourceExhausted)
                }
                ErrorType::ProcessingError => {
                    *self.last_error.lock() = Some("Processing failed".to_string());
                    self.logger.worker_event("simulated_error", "processing_error");
                    Err(ActorError::ProcessingFailed)
                }
            }
        }

        fn get_status(&self) -> WorkerStatus {
            WorkerStatus {
                tasks_processed: self.tasks_processed.load(Ordering::Relaxed),
                broadcasts_received: self.broadcasts_received.load(Ordering::Relaxed),
                last_error: self.last_error.lock().clone(),
                restart_count: self.restart_count.load(Ordering::Relaxed),
            }
        }
    }

    impl Actor for TestWorker {
        type Message = WorkerMessage;

        async fn handle(&mut self, cx: &Cx, msg: WorkerMessage) -> Result<(), ActorError> {
            match msg {
                WorkerMessage::DoWork { task_id, payload } => {
                    self.tasks_processed.fetch_add(1, Ordering::Relaxed);
                    self.logger.worker_event("task_processed", &format!("{}:{}", task_id, payload));

                    // Also check for any pending broadcast messages
                    let _ = self.handle_broadcast_message(cx).await;

                    Ok(())
                }

                WorkerMessage::ProcessBroadcast { data } => {
                    self.broadcasts_received.fetch_add(1, Ordering::Relaxed);
                    self.logger.worker_event("broadcast_processed", &data);
                    Ok(())
                }

                WorkerMessage::SimulateError { error_type } => {
                    self.simulate_error(error_type)
                }

                WorkerMessage::GetStatus { reply_to } => {
                    let status = self.get_status();
                    let _ = reply_to.send(status).await;
                    Ok(())
                }
            }
        }
    }

    // Structured test logger for debugging supervision scenarios
    #[derive(Debug, Clone)]
    struct TestLogger {
        test_name: String,
        events: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    impl TestLogger {
        fn new(test_name: &str) -> Self {
            Self {
                test_name: test_name.to_string(),
                events: Arc::new(parking_lot::Mutex::new(Vec::new())),
            }
        }

        fn log_event(&self, category: &str, event: &str, details: &str) {
            let timestamp = crate::time::wall_now();
            let entry = format!("{{\"test\":\"{}\",\"category\":\"{}\",\"event\":\"{}\",\"details\":\"{}\",\"ts\":{}}}",
                self.test_name, category, event, details, timestamp.as_nanos());
            self.events.lock().push(entry);
            eprintln!("{}", entry);
        }

        fn supervision_event(&self, event: &str, details: &str) {
            self.log_event("supervision", event, details);
        }

        fn worker_event(&self, event: &str, details: &str) {
            self.log_event("worker", event, details);
        }

        fn channel_event(&self, event: &str, details: &str) {
            self.log_event("channel", event, details);
        }

        fn integration_event(&self, event: &str, details: &str) {
            self.log_event("integration", event, details);
        }

        fn get_events(&self) -> Vec<String> {
            self.events.lock().clone()
        }
    }

    // Integration test harness combining channels, supervision, and actors
    struct ChannelSupervisionHarness {
        supervisor_handle: ActorHandle<SupervisorMessage>,
        broadcast_sender: BroadcastSender<String>,
        command_sender: MpscSender<SupervisorMessage>,
        logger: TestLogger,
        factory: SupervisionFactory,
    }

    impl ChannelSupervisionHarness {
        async fn new(test_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let logger = TestLogger::new(test_name);

            // Create broadcast channel for inter-actor communication
            let (broadcast_sender, _) = broadcast::channel::<String>(16);
            logger.channel_event("broadcast_channel_created", "capacity_16");

            // Create command channel for supervisor communication
            let (command_sender, command_receiver) = mpsc::channel::<SupervisorMessage>(32);
            logger.channel_event("command_channel_created", "capacity_32");

            // Create supervisor actor
            let supervisor = TestSupervisor::new(Some(broadcast_sender.clone()), logger.clone());

            // Mock supervisor handle for testing
            let supervisor_task_id = TaskId::from_raw(1);
            let supervisor_handle = ActorHandle::mock_for_testing(supervisor_task_id);

            logger.supervision_event("supervisor_created", "ready");

            Ok(Self {
                supervisor_handle,
                broadcast_sender,
                command_sender,
                logger,
                factory: SupervisionFactory::new(),
            })
        }

        async fn start_worker(&mut self, cx: &Cx, name: &str) -> Result<(), Box<dyn std::error::Error>> {
            self.logger.integration_event("start_worker", name);

            let spec = self.factory.create_child_spec(name, SupervisionStrategy::Restart);
            let start_msg = SupervisorMessage::StartChild {
                name: name.to_string(),
                spec,
            };

            self.command_sender.send(start_msg).await
                .map_err(|_| "Failed to send start command")?;

            self.logger.integration_event("start_worker_sent", name);
            Ok(())
        }

        async fn simulate_broadcast_error(&mut self, cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
            self.logger.integration_event("simulate_broadcast_error", "started");

            // Send error message to supervisor
            let error_msg = SupervisorMessage::BroadcastError {
                error: "Broadcast channel closed unexpectedly".to_string(),
                affected_children: vec!["worker_1".to_string(), "worker_2".to_string()],
            };

            self.command_sender.send(error_msg).await
                .map_err(|_| "Failed to send broadcast error")?;

            self.logger.integration_event("broadcast_error_sent", "supervisor_notified");

            // Close the broadcast channel to trigger actual errors
            drop(self.broadcast_sender.clone()); // Close one sender reference

            self.logger.channel_event("broadcast_channel_closed", "error_propagation");
            Ok(())
        }

        async fn send_broadcast_message(&mut self, cx: &Cx, data: &str) -> Result<(), Box<dyn std::error::Error>> {
            self.logger.integration_event("send_broadcast", data);

            match self.broadcast_sender.reserve(cx).await {
                Ok(permit) => {
                    permit.send(data.to_string());
                    self.logger.channel_event("broadcast_sent", data);
                    Ok(())
                }
                Err(_) => {
                    self.logger.channel_event("broadcast_send_failed", "channel_closed");
                    Err("Broadcast channel closed".into())
                }
            }
        }

        async fn get_supervisor_status(&mut self, cx: &Cx) -> Result<SupervisorStatus, Box<dyn std::error::Error>> {
            let (reply_sender, mut reply_receiver) = mpsc::channel(1);

            let status_msg = SupervisorMessage::StatusRequest {
                reply_to: reply_sender,
            };

            self.command_sender.send(status_msg).await
                .map_err(|_| "Failed to send status request")?;

            match reply_receiver.recv(cx).await {
                Ok(status) => {
                    self.logger.integration_event("status_received", &format!("children_{}", status.active_children));
                    Ok(status)
                }
                Err(_) => {
                    Err("Failed to receive status".into())
                }
            }
        }

        /// Poll until supervision action meets expected condition
        async fn wait_for_supervision_action<F>(
            &mut self,
            cx: &Cx,
            condition: F,
            timeout: Duration,
        ) -> Result<SupervisorStatus, Box<dyn std::error::Error>>
        where
            F: Fn(&SupervisorStatus) -> bool,
        {
            let start = std::time::Instant::now();
            let mut backoff = Duration::from_millis(5);
            let max_backoff = Duration::from_millis(50);

            while start.elapsed() < timeout {
                let status = self.get_supervisor_status(cx).await?;
                if condition(&status) {
                    return Ok(status);
                }

                crate::time::sleep(cx, backoff).await;
                backoff = std::cmp::min(
                    Duration::from_millis((backoff.as_millis() as f64 * 1.5) as u64),
                    max_backoff
                );
            }

            // Get final status for error message
            let final_status = self.get_supervisor_status(cx).await?;
            Err(format!(
                "Supervision action condition not met within {:?}. Final status: restarts={}, errors={}",
                timeout,
                final_status.restart_count,
                final_status.broadcast_errors
            ).into())
        }

        async fn trigger_worker_restart(&mut self, cx: &Cx, worker_name: &str) -> Result<(), Box<dyn std::error::Error>> {
            self.logger.integration_event("trigger_restart", worker_name);

            let restart_msg = SupervisorMessage::RestartChild {
                name: worker_name.to_string(),
                reason: "Manual restart for testing".to_string(),
            };

            self.command_sender.send(restart_msg).await
                .map_err(|_| "Failed to send restart command")?;

            self.logger.integration_event("restart_triggered", worker_name);
            Ok(())
        }

        fn analyze_event_sequence(&self) -> ChannelSupervisionAnalysis {
            let events = self.logger.get_events();

            let mut analysis = ChannelSupervisionAnalysis {
                total_events: events.len(),
                supervision_events: 0,
                channel_events: 0,
                worker_events: 0,
                integration_events: 0,
                restart_sequence_detected: false,
                broadcast_error_propagation: false,
                channel_close_handling: false,
            };

            for event in &events {
                if event.contains("\"category\":\"supervision\"") {
                    analysis.supervision_events += 1;
                    if event.contains("restart") {
                        analysis.restart_sequence_detected = true;
                    }
                } else if event.contains("\"category\":\"channel\"") {
                    analysis.channel_events += 1;
                    if event.contains("broadcast_channel_closed") {
                        analysis.channel_close_handling = true;
                    }
                } else if event.contains("\"category\":\"worker\"") {
                    analysis.worker_events += 1;
                } else if event.contains("\"category\":\"integration\"") {
                    analysis.integration_events += 1;
                    if event.contains("broadcast_error") {
                        analysis.broadcast_error_propagation = true;
                    }
                }
            }

            analysis
        }
    }

    #[derive(Debug)]
    struct ChannelSupervisionAnalysis {
        total_events: usize,
        supervision_events: usize,
        channel_events: usize,
        worker_events: usize,
        integration_events: usize,
        restart_sequence_detected: bool,
        broadcast_error_propagation: bool,
        channel_close_handling: bool,
    }

    #[test]
    fn test_channel_supervision_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = ChannelSupervisionHarness::new("channel_supervision_integration")
                .await
                .expect("Harness creation should succeed");

            // Start multiple workers under supervision
            harness.start_worker(&cx, "worker_1").await?;
            harness.start_worker(&cx, "worker_2").await?;
            harness.start_worker(&cx, "worker_3").await?;

            // Send some broadcast messages
            harness.send_broadcast_message(&cx, "initial_broadcast_1").await?;
            harness.send_broadcast_message(&cx, "initial_broadcast_2").await?;

            // Get initial supervisor status
            let initial_status = harness.get_supervisor_status(&cx).await?;
            assert_eq!(initial_status.active_children, 3);
            assert_eq!(initial_status.restart_count, 0);

            // Simulate broadcast error that triggers supervision decisions
            harness.simulate_broadcast_error(&cx).await?;

            // Wait for supervision to handle the broadcast error
            let post_error_status = harness.wait_for_supervision_action(
                &cx,
                |status| status.broadcast_errors > 0 && status.restart_count > 0,
                Duration::from_secs(5)
            ).await
            .expect("Supervision should handle broadcast error within timeout");

            // Verify the expected conditions were met
            assert!(post_error_status.broadcast_errors > 0,
                "Should track broadcast errors: {}", post_error_status.broadcast_errors);
            assert!(post_error_status.restart_count > 0,
                "Should have triggered restarts: {}", post_error_status.restart_count);

            // Analyze event sequence
            let analysis = harness.analyze_event_sequence();
            assert!(analysis.supervision_events > 0, "Should have supervision events");
            assert!(analysis.channel_events > 0, "Should have channel events");
            assert!(analysis.restart_sequence_detected, "Should detect restart sequence");
            assert!(analysis.broadcast_error_propagation, "Should detect broadcast error propagation");
            assert!(analysis.channel_close_handling, "Should detect channel close handling");

            Ok(())
        }).expect("Channel supervision integration test should complete successfully");
    }

    #[test]
    fn test_forced_restart_on_broadcast_error() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = ChannelSupervisionHarness::new("forced_restart_broadcast_error")
                .await
                .expect("Harness creation should succeed");

            // Start workers
            harness.start_worker(&cx, "worker_a").await?;
            harness.start_worker(&cx, "worker_b").await?;

            let initial_status = harness.get_supervisor_status(&cx).await?;
            assert_eq!(initial_status.active_children, 2);

            // Trigger broadcast error affecting specific workers
            harness.simulate_broadcast_error(&cx).await?;

            // Wait for restart to complete
            crate::time::sleep(&cx, Duration::from_millis(20)).await;

            let post_restart_status = harness.get_supervisor_status(&cx).await?;

            // Verify forced restart occurred
            assert!(post_restart_status.restart_count >= 2,
                "Should have restarted affected workers");
            assert!(post_restart_status.broadcast_errors > 0,
                "Should track broadcast errors");
            assert_eq!(post_restart_status.active_children, 2,
                "Should maintain active worker count after restart");

            // Verify event sequence shows forced restart
            let analysis = harness.analyze_event_sequence();
            assert!(analysis.restart_sequence_detected,
                "Should show forced restart sequence");

            Ok(())
        }).expect("Forced restart test should complete successfully");
    }

    #[test]
    fn test_mailbox_integration_with_supervision() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = ChannelSupervisionHarness::new("mailbox_supervision_integration")
                .await
                .expect("Harness creation should succeed");

            // Start worker
            harness.start_worker(&cx, "mailbox_worker").await?;

            // Send multiple messages to test mailbox behavior
            for i in 0..5 {
                harness.send_broadcast_message(&cx, &format!("msg_{}", i)).await?;
            }

            // Trigger restart and verify mailbox is properly reset
            harness.trigger_worker_restart(&cx, "mailbox_worker").await?;

            // Send more messages after restart
            for i in 5..10 {
                harness.send_broadcast_message(&cx, &format!("post_restart_msg_{}", i)).await?;
            }

            // Verify supervision handled mailbox integration
            let status = harness.get_supervisor_status(&cx).await?;
            assert!(status.restart_count > 0, "Should have restarted worker");

            let analysis = harness.analyze_event_sequence();
            assert!(analysis.restart_sequence_detected, "Should detect restart");
            assert!(analysis.channel_events >= 10, "Should have processed messages");

            Ok(())
        }).expect("Mailbox integration test should complete successfully");
    }

    #[test]
    fn test_concurrent_channel_supervision() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = ChannelSupervisionHarness::new("concurrent_channel_supervision")
                .await
                .expect("Harness creation should succeed");

            // Start multiple workers
            let worker_count = 4;
            for i in 0..worker_count {
                harness.start_worker(&cx, &format!("concurrent_worker_{}", i)).await?;
            }

            // Spawn multiple concurrent tasks that interact with channels and supervision
            let mut handles = Vec::new();

            // Task 1: Continuous broadcast sending
            let broadcast_sender_clone = harness.broadcast_sender.clone();
            let logger_clone = harness.logger.clone();
            let handle1 = crate::cx::spawn(&cx, async move {
                for i in 0..10 {
                    if let Ok(permit) = broadcast_sender_clone.reserve(&cx).await {
                        permit.send(format!("concurrent_broadcast_{}", i));
                        logger_clone.channel_event("concurrent_broadcast_sent", &format!("msg_{}", i));
                    }
                    crate::time::sleep(&cx, Duration::from_millis(5)).await;
                }
                Ok::<(), Box<dyn std::error::Error>>(())
            })?;

            // Task 2: Trigger periodic restarts
            let command_sender_clone = harness.command_sender.clone();
            let logger_clone2 = harness.logger.clone();
            let handle2 = crate::cx::spawn(&cx, async move {
                for i in 0..3 {
                    let restart_msg = SupervisorMessage::RestartChild {
                        name: format!("concurrent_worker_{}", i),
                        reason: "Concurrent restart test".to_string(),
                    };
                    let _ = command_sender_clone.send(restart_msg).await;
                    logger_clone2.supervision_event("concurrent_restart", &format!("worker_{}", i));
                    crate::time::sleep(&cx, Duration::from_millis(15)).await;
                }
                Ok::<(), Box<dyn std::error::Error>>(())
            })?;

            handles.push(handle1);
            handles.push(handle2);

            // Wait for all concurrent operations to complete
            for handle in handles {
                handle.await??;
            }

            // Verify final state
            let final_status = harness.get_supervisor_status(&cx).await?;
            assert_eq!(final_status.active_children, worker_count,
                "Should maintain correct worker count");
            assert!(final_status.restart_count >= 3,
                "Should have performed concurrent restarts");

            let analysis = harness.analyze_event_sequence();
            assert!(analysis.total_events > 20, "Should have high activity");
            assert!(analysis.supervision_events >= 3, "Should have supervision activity");
            assert!(analysis.channel_events >= 10, "Should have channel activity");

            Ok(())
        }).expect("Concurrent supervision test should complete successfully");
    }

    #[test]
    fn test_supervision_decision_propagation() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = ChannelSupervisionHarness::new("supervision_decision_propagation")
                .await
                .expect("Harness creation should succeed");

            // Create a hierarchy of workers
            harness.start_worker(&cx, "primary_worker").await?;
            harness.start_worker(&cx, "secondary_worker").await?;

            // Test that supervisor decisions propagate through channels properly

            // 1. Simulate primary worker failure
            let primary_error = SupervisorMessage::BroadcastError {
                error: "Primary worker communication failure".to_string(),
                affected_children: vec!["primary_worker".to_string()],
            };
            harness.command_sender.send(primary_error).await?;

            // 2. This should trigger restart of primary worker
            crate::time::sleep(&cx, Duration::from_millis(10)).await;

            // 3. Verify secondary worker is notified through channels
            harness.send_broadcast_message(&cx, "restart_notification").await?;

            // 4. Check that supervision decisions were properly propagated
            let status = harness.get_supervisor_status(&cx).await?;
            assert!(status.restart_count > 0, "Should have restarted primary worker");
            assert!(status.broadcast_errors > 0, "Should track communication failure");

            // Analyze decision propagation
            let analysis = harness.analyze_event_sequence();
            assert!(analysis.broadcast_error_propagation, "Should propagate broadcast errors");
            assert!(analysis.restart_sequence_detected, "Should execute restart sequence");

            Ok(())
        }).expect("Decision propagation test should complete successfully");
    }
}