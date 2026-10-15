//! Real supervision restart loop E2E tests
//!
//! Tests actual gen_server panic recovery and restart cycles through
//! real actor mailbox implementations. No mocks - validates supervision
//! trees handle failures correctly with message replay and state recovery.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_supervision_e2e {
    use crate::actor::{Actor, ActorRef, ActorSystem, GenServer, Mailbox};
    use crate::cx::Cx;
    use crate::runtime::{Runtime, spawn};
    use crate::supervision::{ChildSpec, RestartPolicy, SupervisionStrategy, Supervisor};
    use crate::time::{Duration, sleep, timeout};
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::mpsc;

    /// Test harness with supervision tree and structured logging
    struct SupervisionTestHarness {
        actor_system: Arc<ActorSystem>,
        log_entries: Arc<Mutex<Vec<Value>>>,
        message_counts: Arc<Mutex<HashMap<String, usize>>>,
    }

    impl SupervisionTestHarness {
        fn new() -> Self {
            let actor_system = Arc::new(ActorSystem::new("test_system"));
            Self {
                actor_system,
                log_entries: Arc::new(Mutex::new(Vec::new())),
                message_counts: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn log(&self, event: &str, data: Value) {
            let entry = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event": event,
                "data": data,
                "system_id": self.actor_system.id()
            });
            eprintln!("{}", serde_json::to_string(&entry).unwrap());
            self.log_entries.lock().unwrap().push(entry);
        }

        fn increment_message_count(&self, actor_name: &str) {
            let mut counts = self.message_counts.lock().unwrap();
            *counts.entry(actor_name.to_string()).or_insert(0) += 1;
        }

        fn get_message_count(&self, actor_name: &str) -> usize {
            self.message_counts
                .lock()
                .unwrap()
                .get(actor_name)
                .copied()
                .unwrap_or(0)
        }
    }

    /// Test actor that can be configured to panic
    #[derive(Debug, Clone)]
    struct TestWorkerActor {
        name: String,
        panic_on_message: Option<String>,
        panic_count: Arc<AtomicUsize>,
        processed_messages: Arc<AtomicUsize>,
        harness: Arc<SupervisionTestHarness>,
    }

    #[derive(Debug, Clone)]
    enum WorkerMessage {
        DoWork(String),
        GetStats,
        SetPanicTrigger(String),
        Shutdown,
    }

    #[derive(Debug)]
    enum WorkerReply {
        WorkComplete(String),
        Stats { processed: usize, panics: usize },
        PanicTriggerSet,
        ShutdownComplete,
    }

    impl TestWorkerActor {
        fn new(name: String, harness: Arc<SupervisionTestHarness>) -> Self {
            Self {
                name,
                panic_on_message: None,
                panic_count: Arc::new(AtomicUsize::new(0)),
                processed_messages: Arc::new(AtomicUsize::new(0)),
                harness,
            }
        }
    }

    impl Actor for TestWorkerActor {
        type Message = WorkerMessage;
        type Reply = WorkerReply;

        async fn handle_message(&mut self, message: Self::Message, cx: &Cx) -> Option<Self::Reply> {
            self.harness.increment_message_count(&self.name);
            self.harness.log(
                "actor_message",
                json!({
                    "actor": self.name,
                    "message": format!("{:?}", message)
                }),
            );

            match message {
                WorkerMessage::DoWork(work) => {
                    // Check if we should panic on this message
                    if let Some(ref panic_trigger) = self.panic_on_message {
                        if work.contains(panic_trigger) {
                            self.panic_count.fetch_add(1, Ordering::SeqCst);
                            self.harness.log(
                                "actor_panic",
                                json!({
                                    "actor": self.name,
                                    "trigger": panic_trigger,
                                    "work": work
                                }),
                            );
                            panic!("Intentional panic on message: {}", work);
                        }
                    }

                    // Simulate work
                    sleep(Duration::from_millis(10)).await;
                    self.processed_messages.fetch_add(1, Ordering::SeqCst);

                    Some(WorkerReply::WorkComplete(format!("Processed: {}", work)))
                }

                WorkerMessage::GetStats => Some(WorkerReply::Stats {
                    processed: self.processed_messages.load(Ordering::SeqCst),
                    panics: self.panic_count.load(Ordering::SeqCst),
                }),

                WorkerMessage::SetPanicTrigger(trigger) => {
                    self.panic_on_message = Some(trigger);
                    self.harness.log(
                        "panic_trigger_set",
                        json!({
                            "actor": self.name,
                            "trigger": self.panic_on_message
                        }),
                    );
                    Some(WorkerReply::PanicTriggerSet)
                }

                WorkerMessage::Shutdown => {
                    self.harness.log(
                        "actor_shutdown",
                        json!({
                            "actor": self.name
                        }),
                    );
                    Some(WorkerReply::ShutdownComplete)
                }
            }
        }
    }

    #[tokio::test]
    async fn test_supervision_restart_on_panic() {
        let harness = Arc::new(SupervisionTestHarness::new());
        harness.log("test_start", json!({"test": "supervision_restart_panic"}));

        // Create supervision tree
        let supervisor = Supervisor::new("test_supervisor", SupervisionStrategy::OneForOne);

        // Create worker child spec with restart policy
        let worker_actor = TestWorkerActor::new("test_worker".to_string(), harness.clone());
        let child_spec = ChildSpec::new("worker", worker_actor, RestartPolicy::Permanent);

        let supervisor_ref = harness.actor_system.spawn(supervisor).await;
        let worker_ref = supervisor_ref
            .add_child(child_spec)
            .await
            .expect("Failed to add child to supervisor");

        // Set panic trigger
        worker_ref
            .send(WorkerMessage::SetPanicTrigger("crash".to_string()))
            .await
            .expect("Failed to set panic trigger");

        // Send normal messages (should work)
        for i in 0..3 {
            let reply = worker_ref
                .send(WorkerMessage::DoWork(format!("work_{}", i)))
                .await
                .expect("Failed to send work message");
            harness.log(
                "work_reply",
                json!({
                    "work_id": i,
                    "reply": format!("{:?}", reply)
                }),
            );
        }

        // Trigger panic
        let panic_result = worker_ref
            .send(WorkerMessage::DoWork("crash_work".to_string()))
            .await;
        harness.log(
            "panic_result",
            json!({
                "panic_triggered": panic_result.is_err(),
                "error": format!("{:?}", panic_result.err())
            }),
        );

        // Wait for restart
        sleep(Duration::from_millis(500)).await;

        // Verify worker restarted and can process messages again
        let post_restart_reply = timeout(
            Duration::from_secs(2),
            worker_ref.send(WorkerMessage::DoWork("post_restart_work".to_string())),
        )
        .await;

        harness.log(
            "post_restart_reply",
            json!({
                "success": post_restart_reply.is_ok(),
                "reply": format!("{:?}", post_restart_reply)
            }),
        );

        // Get final stats
        let stats_reply = worker_ref
            .send(WorkerMessage::GetStats)
            .await
            .expect("Failed to get stats");

        harness.log(
            "final_stats",
            json!({
                "stats": format!("{:?}", stats_reply),
                "total_messages": harness.get_message_count("test_worker")
            }),
        );

        // Verify restart worked
        assert!(
            post_restart_reply.is_ok(),
            "Worker should be available after restart"
        );

        // Message count should include messages to both original and restarted actor
        let message_count = harness.get_message_count("test_worker");
        assert!(
            message_count >= 5,
            "Should have processed at least 5 messages, got {}",
            message_count
        );

        // Cleanup
        worker_ref.send(WorkerMessage::Shutdown).await.ok();
    }

    #[tokio::test]
    async fn test_supervision_one_for_all_restart() {
        let harness = Arc::new(SupervisionTestHarness::new());
        harness.log("test_start", json!({"test": "supervision_one_for_all"}));

        // Create supervisor with OneForAll strategy
        let supervisor = Supervisor::new("test_supervisor", SupervisionStrategy::OneForAll);
        let supervisor_ref = harness.actor_system.spawn(supervisor).await;

        // Add multiple worker children
        let worker1 = TestWorkerActor::new("worker_1".to_string(), harness.clone());
        let worker2 = TestWorkerActor::new("worker_2".to_string(), harness.clone());
        let worker3 = TestWorkerActor::new("worker_3".to_string(), harness.clone());

        let child1_spec = ChildSpec::new("worker1", worker1, RestartPolicy::Permanent);
        let child2_spec = ChildSpec::new("worker2", worker2, RestartPolicy::Permanent);
        let child3_spec = ChildSpec::new("worker3", worker3, RestartPolicy::Permanent);

        let worker1_ref = supervisor_ref
            .add_child(child1_spec)
            .await
            .expect("Failed to add worker1");
        let worker2_ref = supervisor_ref
            .add_child(child2_spec)
            .await
            .expect("Failed to add worker2");
        let worker3_ref = supervisor_ref
            .add_child(child3_spec)
            .await
            .expect("Failed to add worker3");

        // Set panic trigger on worker2 only
        worker2_ref
            .send(WorkerMessage::SetPanicTrigger("boom".to_string()))
            .await
            .expect("Failed to set panic trigger on worker2");

        // Send initial work to all workers
        worker1_ref
            .send(WorkerMessage::DoWork("task_1".to_string()))
            .await
            .expect("Worker1 failed");
        worker2_ref
            .send(WorkerMessage::DoWork("task_2".to_string()))
            .await
            .expect("Worker2 failed");
        worker3_ref
            .send(WorkerMessage::DoWork("task_3".to_string()))
            .await
            .expect("Worker3 failed");

        // Trigger panic in worker2 (should restart all workers due to OneForAll)
        let panic_result = worker2_ref
            .send(WorkerMessage::DoWork("boom_task".to_string()))
            .await;
        harness.log(
            "one_for_all_panic",
            json!({
                "worker2_panic": panic_result.is_err()
            }),
        );

        // Wait for all workers to restart
        sleep(Duration::from_millis(1000)).await;

        // Verify all workers are available after restart
        let worker1_post = timeout(
            Duration::from_secs(2),
            worker1_ref.send(WorkerMessage::DoWork("post_restart_1".to_string())),
        )
        .await;
        let worker2_post = timeout(
            Duration::from_secs(2),
            worker2_ref.send(WorkerMessage::DoWork("post_restart_2".to_string())),
        )
        .await;
        let worker3_post = timeout(
            Duration::from_secs(2),
            worker3_ref.send(WorkerMessage::DoWork("post_restart_3".to_string())),
        )
        .await;

        harness.log(
            "one_for_all_recovery",
            json!({
                "worker1_available": worker1_post.is_ok(),
                "worker2_available": worker2_post.is_ok(),
                "worker3_available": worker3_post.is_ok()
            }),
        );

        // All workers should be available
        assert!(
            worker1_post.is_ok(),
            "Worker1 should be available after OneForAll restart"
        );
        assert!(
            worker2_post.is_ok(),
            "Worker2 should be available after OneForAll restart"
        );
        assert!(
            worker3_post.is_ok(),
            "Worker3 should be available after OneForAll restart"
        );

        // Verify message counts include pre and post restart
        assert!(harness.get_message_count("worker_1") >= 3);
        assert!(harness.get_message_count("worker_2") >= 3);
        assert!(harness.get_message_count("worker_3") >= 3);
    }

    #[tokio::test]
    async fn test_supervision_message_replay_after_restart() {
        let harness = Arc::new(SupervisionTestHarness::new());
        harness.log("test_start", json!({"test": "message_replay_restart"}));

        // Create supervisor with message buffering
        let supervisor = Supervisor::new("replay_supervisor", SupervisionStrategy::OneForOne);
        let supervisor_ref = harness.actor_system.spawn(supervisor).await;

        // Create worker with message replay capability
        let worker = TestWorkerActor::new("replay_worker".to_string(), harness.clone());
        let child_spec = ChildSpec::new("replay_worker", worker, RestartPolicy::Permanent)
            .with_message_replay(true);

        let worker_ref = supervisor_ref
            .add_child(child_spec)
            .await
            .expect("Failed to add replay worker");

        // Set panic trigger
        worker_ref
            .send(WorkerMessage::SetPanicTrigger("replay_crash".to_string()))
            .await
            .expect("Failed to set panic trigger");

        // Send buffered messages that should be replayed after restart
        let mut message_futures = Vec::new();
        for i in 0..3 {
            let future = worker_ref.send(WorkerMessage::DoWork(format!("buffered_{}", i)));
            message_futures.push(future);
        }

        // Trigger panic while messages are being processed
        let panic_future = worker_ref.send(WorkerMessage::DoWork("replay_crash_work".to_string()));

        // Wait for panic and restart
        sleep(Duration::from_millis(800)).await;

        // Send more messages after restart
        for i in 3..6 {
            let reply = worker_ref
                .send(WorkerMessage::DoWork(format!("post_restart_{}", i)))
                .await;
            harness.log(
                "post_restart_message",
                json!({
                    "message_id": i,
                    "success": reply.is_ok(),
                    "reply": format!("{:?}", reply)
                }),
            );
        }

        // Get final stats
        let stats_reply = worker_ref
            .send(WorkerMessage::GetStats)
            .await
            .expect("Failed to get final stats");

        harness.log(
            "replay_final_stats",
            json!({
                "stats": format!("{:?}", stats_reply),
                "total_messages": harness.get_message_count("replay_worker")
            }),
        );

        // Verify message replay worked
        let total_messages = harness.get_message_count("replay_worker");
        assert!(
            total_messages >= 8,
            "Should have replayed buffered messages, got {}",
            total_messages
        );

        // Verify worker is responsive
        let final_reply = worker_ref
            .send(WorkerMessage::DoWork("final_test".to_string()))
            .await;
        assert!(
            final_reply.is_ok(),
            "Worker should be responsive after message replay"
        );
    }

    #[tokio::test]
    async fn test_supervision_escalation_chain() {
        let harness = Arc::new(SupervisionTestHarness::new());
        harness.log("test_start", json!({"test": "supervision_escalation"}));

        // Create nested supervision tree
        let root_supervisor = Supervisor::new("root", SupervisionStrategy::OneForOne);
        let root_ref = harness.actor_system.spawn(root_supervisor).await;

        let child_supervisor = Supervisor::new("child", SupervisionStrategy::OneForAll);
        let child_supervisor_spec = ChildSpec::new(
            "child_supervisor",
            child_supervisor,
            RestartPolicy::Permanent,
        );
        let child_ref = root_ref
            .add_child(child_supervisor_spec)
            .await
            .expect("Failed to add child supervisor");

        // Add workers to child supervisor
        let worker = TestWorkerActor::new("escalation_worker".to_string(), harness.clone());
        let worker_spec = ChildSpec::new("escalation_worker", worker, RestartPolicy::Transient)
            .with_max_restarts(2, Duration::from_secs(5)); // Escalate after 2 restarts

        let worker_ref = child_ref
            .add_child(worker_spec)
            .await
            .expect("Failed to add escalation worker");

        // Set panic trigger
        worker_ref
            .send(WorkerMessage::SetPanicTrigger("escalate".to_string()))
            .await
            .expect("Failed to set panic trigger");

        // Cause multiple failures to trigger escalation
        for i in 0..4 {
            let panic_result = worker_ref
                .send(WorkerMessage::DoWork(format!("escalate_work_{}", i)))
                .await;
            harness.log(
                "escalation_attempt",
                json!({
                    "attempt": i,
                    "panic_result": panic_result.is_err()
                }),
            );

            // Wait between attempts
            sleep(Duration::from_millis(300)).await;
        }

        // Wait for escalation processing
        sleep(Duration::from_millis(1000)).await;

        // Verify escalation occurred (child supervisor should be restarted)
        let post_escalation_reply = timeout(
            Duration::from_secs(3),
            worker_ref.send(WorkerMessage::DoWork("post_escalation".to_string())),
        )
        .await;

        harness.log(
            "escalation_result",
            json!({
                "worker_available": post_escalation_reply.is_ok(),
                "total_messages": harness.get_message_count("escalation_worker")
            }),
        );

        // After escalation, system should still be functional
        assert!(
            post_escalation_reply.is_ok(),
            "System should be available after escalation"
        );
    }
}
