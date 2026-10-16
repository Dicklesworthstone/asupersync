    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn worker_envelope(
        worker_id: &str,
        message_id: u64,
        seq_no: u64,
        issued_at_turn: u64,
        op: WorkerOp,
    ) -> WorkerEnvelope {
        WorkerEnvelope::from_worker(worker_id, message_id, seq_no, 42, issued_at_turn, op)
    }

    fn test_worker_envelope(
        message_id: u64,
        seq_no: u64,
        issued_at_turn: u64,
        op: WorkerOp,
    ) -> WorkerEnvelope {
        worker_envelope("test-worker-1", message_id, seq_no, issued_at_turn, op)
    }

    fn bootstrap_ready_envelope(seq: u64) -> WorkerEnvelope {
        worker_envelope(
            "test-worker-1",
            seq,
            seq,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-1".into(),
            },
        )
    }

    fn bootstrap_failed_envelope(seq: u64, worker_id: &str, reason: &str) -> WorkerEnvelope {
        worker_envelope(
            worker_id,
            seq,
            seq,
            0,
            WorkerOp::BootstrapFailed {
                worker_id: worker_id.into(),
                reason: reason.into(),
            },
        )
    }

    #[test]
    fn coordinator_rejects_spawn_before_bootstrap() {
        let mut coord = WorkerCoordinator::new(42);
        let result = coord.spawn_job(1, 100, 200, 300, vec![1, 2, 3]);
        assert_eq!(result, Err(WorkerChannelError::WorkerNotReady));
    }

    #[test]
    fn coordinator_accepts_spawn_after_bootstrap() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        assert!(coord.is_worker_ready());

        let job_id = coord.spawn_job(1, 100, 200, 300, vec![1, 2, 3]).unwrap();
        assert_eq!(job_id, 1);
        assert_eq!(coord.job_state(1), Some(JobState::Queued));
        assert_eq!(coord.inflight_count(), 1);

        let msg = coord.drain_outbox().unwrap();
        assert!(matches!(msg.op, WorkerOp::SpawnJob(_)));
        assert_eq!(msg.version, WORKER_PROTOCOL_VERSION);
        assert_eq!(msg.seed, 42);
    }

    #[test]
    fn coordinator_tracks_full_job_lifecycle() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox(); // consume spawn message

        // Job completed successfully (Queued → Completed is valid for
        // fast-completing jobs that skip the Running notification)
        let result_env = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::JobCompleted(JobResult {
                job_id: 1,
                outcome: JobOutcome::Ok { payload: vec![42] },
            }),
        );
        coord.handle_inbound(&result_env).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Completed));
        assert_eq!(coord.inflight_count(), 0);
        assert_eq!(
            JobOutcome::Ok { payload: vec![42] }.payload_transfer(),
            Some(WorkerPayloadTransfer::StructuredClone)
        );
    }

    #[test]
    fn coordinator_tracks_cancellation_lifecycle() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Running));

        // Request cancellation
        coord.cancel_job(1, "test cancel".into()).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));
        let cancel_msg = coord.drain_outbox().unwrap();
        assert!(matches!(cancel_msg.op, WorkerOp::CancelJob { .. }));

        // Worker acknowledges and coordinator emits the explicit drain phase request.
        let ack = test_worker_envelope(3, 3, 2, WorkerOp::CancelAcknowledged { job_id: 1 });
        coord.handle_inbound(&ack).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Draining));
        let drain_request = coord.drain_outbox().unwrap();
        assert!(matches!(drain_request.op, WorkerOp::DrainJob { job_id: 1 }));

        // Worker completes drain and coordinator emits the finalize phase request.
        let drain = test_worker_envelope(4, 4, 3, WorkerOp::DrainCompleted { job_id: 1 });
        coord.handle_inbound(&drain).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Finalizing));
        let finalize_request = coord.drain_outbox().unwrap();
        assert!(matches!(
            finalize_request.op,
            WorkerOp::FinalizeJob { job_id: 1 }
        ));

        // Finalize completed
        let finalize = test_worker_envelope(5, 5, 4, WorkerOp::FinalizeCompleted { job_id: 1 });
        coord.handle_inbound(&finalize).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Completed));
        assert_eq!(coord.inflight_count(), 0);
        assert_eq!(coord.remove_job(1), Some(JobState::Completed));
        assert_eq!(coord.job_state(1), None);
    }

    #[test]
    fn coordinator_rejects_finalize_completed_before_finalize_phase() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let finalize = test_worker_envelope(2, 2, 1, WorkerOp::FinalizeCompleted { job_id: 1 });
        assert_eq!(
            coord.handle_inbound(&finalize),
            Err(WorkerChannelError::InvalidTransition {
                job_id: 1,
                from: JobState::Queued,
                to: JobState::Completed,
            })
        );
        assert_eq!(coord.job_state(1), Some(JobState::Queued));
    }

    #[test]
    fn coordinator_rejects_terminal_status_snapshot() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let snapshot = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Completed,
                detail: Some("terminal snapshots must use job_completed".into()),
            }),
        );
        assert!(matches!(
            coord.handle_inbound(&snapshot),
            Err(WorkerChannelError::TerminalStatusSnapshot {
                job_id: 1,
                state: JobState::Completed,
            })
        ));
        assert_eq!(coord.job_state(1), Some(JobState::Queued));
    }

    #[test]
    fn coordinator_rejects_status_snapshot_for_protocol_owned_drain_phase() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: None,
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.cancel_job(1, "test cancel".into()).unwrap();
        let _ = coord.drain_outbox();
        assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));

        let draining_snapshot = test_worker_envelope(
            3,
            3,
            2,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Draining,
                detail: Some("worker tried to skip cancel_acknowledged".into()),
            }),
        );
        assert!(matches!(
            coord.handle_inbound(&draining_snapshot),
            Err(WorkerChannelError::InvalidStatusSnapshotState {
                job_id: 1,
                state: JobState::Draining,
            })
        ));
        assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));
    }

    #[test]
    fn coordinator_rejects_status_snapshot_for_protocol_owned_finalize_phase() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: None,
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.cancel_job(1, "test cancel".into()).unwrap();
        let _ = coord.drain_outbox();

        let ack = test_worker_envelope(3, 3, 2, WorkerOp::CancelAcknowledged { job_id: 1 });
        coord.handle_inbound(&ack).unwrap();
        let _ = coord.drain_outbox();
        assert_eq!(coord.job_state(1), Some(JobState::Draining));

        let finalizing_snapshot = test_worker_envelope(
            4,
            4,
            3,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Finalizing,
                detail: Some("worker tried to skip drain_completed".into()),
            }),
        );
        assert!(matches!(
            coord.handle_inbound(&finalizing_snapshot),
            Err(WorkerChannelError::InvalidStatusSnapshotState {
                job_id: 1,
                state: JobState::Finalizing,
            })
        ));
        assert_eq!(coord.job_state(1), Some(JobState::Draining));
    }

    #[test]
    fn coordinator_rejects_job_completed_while_cancellation_protocol_active() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: None,
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.cancel_job(1, "test cancel".into()).unwrap();
        let _ = coord.drain_outbox();

        let ack = test_worker_envelope(3, 3, 2, WorkerOp::CancelAcknowledged { job_id: 1 });
        coord.handle_inbound(&ack).unwrap();
        let _ = coord.drain_outbox();

        let drain = test_worker_envelope(4, 4, 3, WorkerOp::DrainCompleted { job_id: 1 });
        coord.handle_inbound(&drain).unwrap();
        let _ = coord.drain_outbox();

        let completed = test_worker_envelope(
            5,
            5,
            4,
            WorkerOp::JobCompleted(JobResult {
                job_id: 1,
                outcome: JobOutcome::Cancelled {
                    reason: "worker skipped finalize".into(),
                },
            }),
        );
        assert!(matches!(
            coord.handle_inbound(&completed),
            Err(WorkerChannelError::UnexpectedCompletionPhase {
                job_id: 1,
                state: JobState::Finalizing,
            })
        ));
        assert_eq!(coord.job_state(1), Some(JobState::Finalizing));
    }

    #[test]
    fn coordinator_accepts_job_completed_racing_with_cancel_request() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.cancel_job(1, "test cancel".into()).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));
        let cancel_msg = coord.drain_outbox().unwrap();
        assert!(matches!(cancel_msg.op, WorkerOp::CancelJob { .. }));

        let completed = test_worker_envelope(
            3,
            3,
            2,
            WorkerOp::JobCompleted(JobResult {
                job_id: 1,
                outcome: JobOutcome::Ok { payload: vec![7] },
            }),
        );
        coord.handle_inbound(&completed).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Completed));
        assert_eq!(coord.inflight_count(), 0);
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_rejects_invalid_transition() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        coord.cancel_job(1, "cancel before running".into()).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));
        let cancel = coord.drain_outbox().unwrap();
        assert!(matches!(cancel.op, WorkerOp::CancelJob { job_id: 1, .. }));
    }

    #[test]
    fn coordinator_allows_cancel_before_running_snapshot() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();

        let spawn = coord.drain_outbox().unwrap();
        assert!(matches!(spawn.op, WorkerOp::SpawnJob(_)));

        coord
            .cancel_job(1, "cancel before worker starts".into())
            .unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));

        let cancel = coord.drain_outbox().unwrap();
        assert!(matches!(cancel.op, WorkerOp::CancelJob { job_id: 1, .. }));
    }

    #[test]
    fn coordinator_rejects_oversized_payload() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        let big_payload = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let result = coord.spawn_job(1, 100, 200, 300, big_payload);
        assert!(matches!(
            result,
            Err(WorkerChannelError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn coordinator_rejects_duplicate_job_id() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let result = coord.spawn_job(1, 100, 200, 300, vec![]);
        assert_eq!(result, Err(WorkerChannelError::DuplicateJobId(1)));
    }

    #[test]
    fn coordinator_shutdown_lifecycle() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();

        coord.request_shutdown("test shutdown".into()).unwrap();
        assert!(coord.is_shutdown_requested());

        let msg = coord.drain_outbox().unwrap();
        assert!(matches!(msg.op, WorkerOp::ShutdownWorker { .. }));

        // Reject spawn during shutdown
        let result = coord.spawn_job(1, 100, 200, 300, vec![]);
        assert_eq!(result, Err(WorkerChannelError::ShutdownInProgress));

        // Worker completes shutdown
        let done = test_worker_envelope(2, 2, 1, WorkerOp::ShutdownCompleted);
        coord.handle_inbound(&done).unwrap();
        assert!(!coord.is_shutdown_requested());
        assert!(!coord.is_worker_ready());
        assert_eq!(
            coord.spawn_job(1, 100, 200, 300, vec![]),
            Err(WorkerChannelError::WorkerNotReady)
        );
    }

    #[test]
    fn coordinator_request_shutdown_discards_queued_spawn_before_shutdown() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![1, 2, 3]).unwrap();

        coord.request_shutdown("shutdown now".into()).unwrap();

        let shutdown = coord.drain_outbox().unwrap();
        assert!(matches!(shutdown.op, WorkerOp::ShutdownWorker { .. }));
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_request_shutdown_discards_queued_poll_and_cancel_before_shutdown() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.poll_status(1).unwrap();
        coord
            .cancel_job(1, "shutdown supersedes cancel".into())
            .unwrap();
        coord.request_shutdown("shutdown now".into()).unwrap();

        let shutdown = coord.drain_outbox().unwrap();
        assert!(matches!(shutdown.op, WorkerOp::ShutdownWorker { .. }));
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_rejects_cancel_after_shutdown_requested_without_mutating_job() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.request_shutdown("shutdown now".into()).unwrap();
        assert_eq!(
            coord.cancel_job(1, "too late".into()),
            Err(WorkerChannelError::ShutdownInProgress)
        );
        assert_eq!(coord.job_state(1), Some(JobState::Running));

        let shutdown = coord.drain_outbox().unwrap();
        assert!(matches!(shutdown.op, WorkerOp::ShutdownWorker { .. }));
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_rejects_poll_after_shutdown_requested_without_enqueuing_follow_up() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.request_shutdown("shutdown now".into()).unwrap();
        assert_eq!(
            coord.poll_status(1),
            Err(WorkerChannelError::ShutdownInProgress)
        );
        assert_eq!(coord.job_state(1), Some(JobState::Running));

        let shutdown = coord.drain_outbox().unwrap();
        assert!(matches!(shutdown.op, WorkerOp::ShutdownWorker { .. }));
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_shutdown_supersedes_cancel_acknowledged_follow_up() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.cancel_job(1, "begin cancel".into()).unwrap();
        let cancel = coord.drain_outbox().unwrap();
        assert!(matches!(cancel.op, WorkerOp::CancelJob { job_id: 1, .. }));
        assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));

        coord.request_shutdown("shutdown now".into()).unwrap();
        assert!(coord.is_shutdown_requested());

        let ack = test_worker_envelope(3, 3, 2, WorkerOp::CancelAcknowledged { job_id: 1 });
        coord.handle_inbound(&ack).unwrap();

        assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));
        let shutdown = coord.drain_outbox().unwrap();
        assert!(matches!(shutdown.op, WorkerOp::ShutdownWorker { .. }));
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_shutdown_supersedes_drain_completed_follow_up() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.cancel_job(1, "begin cancel".into()).unwrap();
        let _ = coord.drain_outbox();

        let ack = test_worker_envelope(3, 3, 2, WorkerOp::CancelAcknowledged { job_id: 1 });
        coord.handle_inbound(&ack).unwrap();
        let drain = coord.drain_outbox().unwrap();
        assert!(matches!(drain.op, WorkerOp::DrainJob { job_id: 1 }));
        assert_eq!(coord.job_state(1), Some(JobState::Draining));

        coord.request_shutdown("shutdown now".into()).unwrap();
        assert!(coord.is_shutdown_requested());

        let drain_completed = test_worker_envelope(4, 4, 3, WorkerOp::DrainCompleted { job_id: 1 });
        coord.handle_inbound(&drain_completed).unwrap();

        assert_eq!(coord.job_state(1), Some(JobState::Draining));
        let shutdown = coord.drain_outbox().unwrap();
        assert!(matches!(shutdown.op, WorkerOp::ShutdownWorker { .. }));
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_marks_nonterminal_job_failed_when_shutdown_completes() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker started".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.cancel_job(1, "shutdown".into()).unwrap();
        let _ = coord.drain_outbox();

        let ack = test_worker_envelope(3, 3, 2, WorkerOp::CancelAcknowledged { job_id: 1 });
        coord.handle_inbound(&ack).unwrap();
        let _ = coord.drain_outbox();

        let drain = test_worker_envelope(4, 4, 3, WorkerOp::DrainCompleted { job_id: 1 });
        coord.handle_inbound(&drain).unwrap();
        let _ = coord.drain_outbox();
        assert_eq!(coord.job_state(1), Some(JobState::Finalizing));
        assert_eq!(coord.inflight_count(), 1);

        let shutdown = test_worker_envelope(5, 5, 4, WorkerOp::ShutdownCompleted);
        coord.handle_inbound(&shutdown).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Failed));
        assert_eq!(coord.inflight_count(), 0);
        assert!(!coord.is_worker_ready());
    }

    #[test]
    fn coordinator_rejects_wrong_direction_messages() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();

        // Worker should not send SpawnJob to coordinator
        let bad = WorkerEnvelope::new(
            2,
            2,
            42,
            1,
            WorkerOp::SpawnJob(SpawnJobRequest {
                job_id: 1,
                region_id: 100,
                task_id: 200,
                obligation_id: 300,
                payload: vec![],
            }),
        );
        let result = coord.handle_inbound(&bad);
        assert!(matches!(
            result,
            Err(WorkerChannelError::UnexpectedDirection { .. })
        ));
    }

    #[test]
    fn coordinator_polls_status_and_applies_snapshot() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        coord.poll_status(1).unwrap();
        let poll = coord.drain_outbox().unwrap();
        assert!(matches!(poll.op, WorkerOp::PollStatus { job_id: 1 }));

        let snapshot = test_worker_envelope(
            3,
            3,
            2,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: None,
            }),
        );
        coord.handle_inbound(&snapshot).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Running));
    }

    #[test]
    fn coordinator_rejects_poll_after_job_completed_without_enqueuing_follow_up() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let completed = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::JobCompleted(JobResult {
                job_id: 1,
                outcome: JobOutcome::Ok { payload: vec![7] },
            }),
        );
        coord.handle_inbound(&completed).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Completed));

        assert_eq!(
            coord.poll_status(1),
            Err(WorkerChannelError::JobNotPollable {
                job_id: 1,
                state: JobState::Completed,
            })
        );
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_rejects_poll_after_rebootstrap_fails_prior_job_without_enqueuing_follow_up() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let reboot = worker_envelope(
            "test-worker-2",
            2,
            2,
            1,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-2".into(),
            },
        );
        coord.handle_inbound(&reboot).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Failed));

        assert_eq!(
            coord.poll_status(1),
            Err(WorkerChannelError::JobNotPollable {
                job_id: 1,
                state: JobState::Failed,
            })
        );
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_rejects_duplicate_inbound_sequence() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();

        let diag = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::Diagnostic(DiagnosticEvent {
                level: DiagnosticLevel::Info,
                category: "lifecycle".into(),
                message: "worker initialized".into(),
                metadata: None,
            }),
        );
        coord.handle_inbound(&diag).unwrap();
        assert_eq!(coord.last_inbound_seq_no, 2);

        let duplicate = test_worker_envelope(3, 2, 2, WorkerOp::ShutdownCompleted);
        assert_eq!(
            coord.handle_inbound(&duplicate),
            Err(WorkerChannelError::InboundSequenceNotFresh {
                last_seen: 2,
                actual: 2,
            })
        );
        assert_eq!(coord.last_inbound_seq_no, 2);
        assert!(coord.is_worker_ready());
    }

    #[test]
    fn coordinator_accepts_fresh_bootstrap_after_shutdown_completed() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.request_shutdown("done".into()).unwrap();
        let _ = coord.drain_outbox();

        let shutdown = test_worker_envelope(2, 2, 1, WorkerOp::ShutdownCompleted);
        coord.handle_inbound(&shutdown).unwrap();
        assert_eq!(coord.last_inbound_seq_no, 2);
        assert!(!coord.is_worker_ready());

        let reboot = worker_envelope(
            "test-worker-2",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-2".into(),
            },
        );
        coord.handle_inbound(&reboot).unwrap();
        assert!(coord.is_worker_ready());
        assert_eq!(coord.last_inbound_seq_no, 1);
    }

    #[test]
    fn coordinator_allows_reusing_failed_job_id_after_shutdown_completed() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![1]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker one accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.request_shutdown("done".into()).unwrap();
        let _ = coord.drain_outbox();
        let shutdown = test_worker_envelope(3, 3, 2, WorkerOp::ShutdownCompleted);
        coord.handle_inbound(&shutdown).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Failed));

        let reboot = worker_envelope(
            "test-worker-2",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-2".into(),
            },
        );
        coord.handle_inbound(&reboot).unwrap();

        coord.spawn_job(1, 100, 201, 301, vec![7, 8]).unwrap();
        let respawn = coord.drain_outbox().unwrap();
        match respawn.op {
            WorkerOp::SpawnJob(request) => {
                assert_eq!(request.job_id, 1);
                assert_eq!(request.task_id, 201);
                assert_eq!(request.obligation_id, 301);
                assert_eq!(request.payload, vec![7, 8]);
            }
            other => panic!("expected respawn after shutdown-complete reboot, got {other:?}"),
        }
        assert_eq!(coord.job_state(1), Some(JobState::Queued));
    }

    #[test]
    fn coordinator_marks_running_job_failed_when_worker_instance_changes() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker one accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Running));
        assert_eq!(coord.inflight_count(), 1);

        let reboot = worker_envelope(
            "test-worker-2",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-2".into(),
            },
        );
        coord.handle_inbound(&reboot).unwrap();
        assert!(coord.is_worker_ready());
        assert_eq!(coord.last_inbound_seq_no, 1);
        assert_eq!(coord.job_state(1), Some(JobState::Failed));
        assert_eq!(coord.inflight_count(), 0);
    }

    #[test]
    fn coordinator_discards_queued_spawn_when_worker_instance_changes() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![1, 2, 3]).unwrap();

        let reboot = worker_envelope(
            "test-worker-2",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-2".into(),
            },
        );
        coord.handle_inbound(&reboot).unwrap();

        assert_eq!(coord.job_state(1), Some(JobState::Failed));
        assert!(coord.drain_outbox().is_none());

        coord.spawn_job(2, 100, 201, 301, vec![9]).unwrap();
        let fresh_spawn = coord.drain_outbox().unwrap();
        match fresh_spawn.op {
            WorkerOp::SpawnJob(request) => assert_eq!(request.job_id, 2),
            other => panic!("expected fresh spawn after reboot, got {other:?}"),
        }
    }

    #[test]
    fn coordinator_allows_reusing_failed_job_id_after_worker_instance_change() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![1, 2, 3]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker one accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        let reboot = worker_envelope(
            "test-worker-2",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-2".into(),
            },
        );
        coord.handle_inbound(&reboot).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Failed));

        coord.spawn_job(1, 100, 201, 301, vec![9]).unwrap();
        let respawn = coord.drain_outbox().unwrap();
        match respawn.op {
            WorkerOp::SpawnJob(request) => {
                assert_eq!(request.job_id, 1);
                assert_eq!(request.task_id, 201);
                assert_eq!(request.obligation_id, 301);
                assert_eq!(request.payload, vec![9]);
            }
            other => panic!("expected respawn after reboot, got {other:?}"),
        }
        assert_eq!(coord.job_state(1), Some(JobState::Queued));
    }

    #[test]
    fn coordinator_discards_queued_cancel_when_worker_instance_changes() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.cancel_job(1, "worker replaced".into()).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));

        let reboot = worker_envelope(
            "test-worker-2",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-2".into(),
            },
        );
        coord.handle_inbound(&reboot).unwrap();

        assert_eq!(coord.job_state(1), Some(JobState::Failed));
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_discards_queued_finalize_when_shutdown_completes() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker started".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        coord.cancel_job(1, "shutdown".into()).unwrap();
        let _ = coord.drain_outbox();

        let ack = test_worker_envelope(3, 3, 2, WorkerOp::CancelAcknowledged { job_id: 1 });
        coord.handle_inbound(&ack).unwrap();
        let _ = coord.drain_outbox();

        let drain = test_worker_envelope(4, 4, 3, WorkerOp::DrainCompleted { job_id: 1 });
        coord.handle_inbound(&drain).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Finalizing));

        let pending_finalize = coord.drain_outbox().unwrap();
        assert!(matches!(
            pending_finalize.op,
            WorkerOp::FinalizeJob { job_id: 1 }
        ));

        coord
            .enqueue_job_message(1, WorkerOp::FinalizeJob { job_id: 1 })
            .unwrap();
        let shutdown = test_worker_envelope(5, 5, 4, WorkerOp::ShutdownCompleted);
        coord.handle_inbound(&shutdown).unwrap();

        assert_eq!(coord.job_state(1), Some(JobState::Failed));
        assert!(coord.drain_outbox().is_none());
    }

    #[test]
    fn coordinator_accepts_fresh_bootstrap_after_bootstrap_failed() {
        let mut coord = WorkerCoordinator::new(42);

        let failed = bootstrap_failed_envelope(1, "failed-worker-1", "synthetic boot failure");
        assert_eq!(
            coord.handle_inbound(&failed),
            Err(WorkerChannelError::BootstrapFailed(
                "synthetic boot failure".into()
            ))
        );
        assert_eq!(coord.last_inbound_seq_no, 1);
        assert!(!coord.is_worker_ready());

        let retry = worker_envelope(
            "test-worker-2",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-2".into(),
            },
        );
        coord.handle_inbound(&retry).unwrap();
        assert!(coord.is_worker_ready());
        assert_eq!(coord.last_inbound_seq_no, 1);
    }

    #[test]
    fn coordinator_accepts_fresh_bootstrap_failed_after_live_session() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: Some("worker one accepted job".into()),
            }),
        );
        coord.handle_inbound(&running).unwrap();

        let failed = bootstrap_failed_envelope(1, "failed-worker-2", "reboot failed to init");
        assert_eq!(
            coord.handle_inbound(&failed),
            Err(WorkerChannelError::BootstrapFailed(
                "reboot failed to init".into()
            ))
        );
        assert_eq!(coord.last_inbound_seq_no, 1);
        assert!(!coord.is_worker_ready());
        assert_eq!(coord.job_state(1), Some(JobState::Failed));
        assert_eq!(coord.inflight_count(), 0);
    }

    #[test]
    fn coordinator_keeps_prior_high_water_mark_until_rebootstrap() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.request_shutdown("done".into()).unwrap();
        let _ = coord.drain_outbox();

        let shutdown = test_worker_envelope(2, 2, 1, WorkerOp::ShutdownCompleted);
        coord.handle_inbound(&shutdown).unwrap();
        assert_eq!(coord.last_inbound_seq_no, 2);
        assert!(!coord.is_worker_ready());

        let stale = test_worker_envelope(
            1,
            1,
            0,
            WorkerOp::Diagnostic(DiagnosticEvent {
                level: DiagnosticLevel::Info,
                category: "lifecycle".into(),
                message: "stale pre-restart message".into(),
                metadata: None,
            }),
        );
        assert_eq!(
            coord.handle_inbound(&stale),
            Err(WorkerChannelError::InboundWorkerSessionMismatch {
                expected: None,
                actual: "test-worker-1".into(),
            })
        );
        assert_eq!(coord.last_inbound_seq_no, 2);

        let reboot = worker_envelope(
            "test-worker-2",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-2".into(),
            },
        );
        coord.handle_inbound(&reboot).unwrap();
        assert!(coord.is_worker_ready());
        assert_eq!(coord.last_inbound_seq_no, 1);
    }

    #[test]
    fn coordinator_rejects_replayed_bootstrap_from_same_worker_session() {
        let mut coord = WorkerCoordinator::new(42);

        let ready = worker_envelope(
            "stable-worker",
            5,
            5,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "stable-worker".into(),
            },
        );
        coord.handle_inbound(&ready).unwrap();

        let replay = worker_envelope(
            "stable-worker",
            1,
            1,
            1,
            WorkerOp::BootstrapReady {
                worker_id: "stable-worker".into(),
            },
        );
        assert_eq!(
            coord.handle_inbound(&replay),
            Err(WorkerChannelError::InboundSequenceNotFresh {
                last_seen: 5,
                actual: 1,
            })
        );
    }

    #[test]
    fn coordinator_rejects_replayed_bootstrap_failed_from_same_worker_session() {
        let mut coord = WorkerCoordinator::new(42);

        let ready = worker_envelope(
            "stable-worker",
            5,
            5,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "stable-worker".into(),
            },
        );
        coord.handle_inbound(&ready).unwrap();

        let replay = bootstrap_failed_envelope(1, "stable-worker", "stale failure replay");
        assert_eq!(
            coord.handle_inbound(&replay),
            Err(WorkerChannelError::InboundSequenceNotFresh {
                last_seen: 5,
                actual: 1,
            })
        );
        assert!(coord.is_worker_ready());
    }

    #[test]
    fn coordinator_rejects_out_of_order_job_message_sequence() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        let running = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::StatusSnapshot(JobStatusSnapshot {
                job_id: 1,
                state: JobState::Running,
                detail: None,
            }),
        );
        coord.handle_inbound(&running).unwrap();

        let diag = test_worker_envelope(
            3,
            4,
            2,
            WorkerOp::Diagnostic(DiagnosticEvent {
                level: DiagnosticLevel::Info,
                category: "scheduler".into(),
                message: "worker tick".into(),
                metadata: None,
            }),
        );
        coord.handle_inbound(&diag).unwrap();

        let stale_completion = test_worker_envelope(
            4,
            3,
            3,
            WorkerOp::JobCompleted(JobResult {
                job_id: 1,
                outcome: JobOutcome::Ok { payload: vec![7] },
            }),
        );
        assert_eq!(
            coord.handle_inbound(&stale_completion),
            Err(WorkerChannelError::InboundSequenceNotFresh {
                last_seen: 4,
                actual: 3,
            })
        );
        assert_eq!(coord.last_inbound_seq_no, 4);
        assert_eq!(coord.job_state(1), Some(JobState::Running));
    }

    #[test]
    fn envelope_validates_version() {
        let mut env = worker_envelope(
            "w",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "w".into(),
            },
        );
        assert!(env.validate().is_ok());

        env.version = 99;
        assert!(matches!(
            env.validate(),
            Err(WorkerChannelError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn envelope_validates_replay_metadata() {
        let mut env = worker_envelope(
            "w",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "w".into(),
            },
        );
        assert!(env.validate().is_ok());

        env.decision_seq = 2;
        env.replay_hash = replay_hash(
            env.message_id,
            env.seq_no,
            env.decision_seq,
            env.seed,
            env.issued_at_turn,
            env.worker_id.as_deref(),
            &env.op,
        );
        assert!(env.validate().is_ok());

        env.op = WorkerOp::ShutdownCompleted;
        assert!(matches!(
            env.validate(),
            Err(WorkerChannelError::ReplayHashMismatch { .. })
        ));
    }

    #[test]
    fn envelope_validates_payload_size() {
        let env = WorkerEnvelope::new(
            1,
            1,
            42,
            0,
            WorkerOp::SpawnJob(SpawnJobRequest {
                job_id: 1,
                region_id: 100,
                task_id: 200,
                obligation_id: 300,
                payload: vec![0u8; MAX_PAYLOAD_BYTES + 1],
            }),
        );
        assert!(matches!(
            env.validate(),
            Err(WorkerChannelError::PayloadTooLarge { .. })
        ));

        let completed = test_worker_envelope(
            2,
            2,
            0,
            WorkerOp::JobCompleted(JobResult {
                job_id: 1,
                outcome: JobOutcome::Ok {
                    payload: vec![0u8; MAX_PAYLOAD_BYTES + 1],
                },
            }),
        );
        assert!(matches!(
            completed.validate(),
            Err(WorkerChannelError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn job_state_transitions_are_correct() {
        // Valid transitions
        assert!(JobState::Created.can_transition_to(JobState::Queued));
        assert!(JobState::Created.can_transition_to(JobState::Failed));
        assert!(JobState::Queued.can_transition_to(JobState::Running));
        assert!(JobState::Queued.can_transition_to(JobState::CancelRequested));
        assert!(JobState::Queued.can_transition_to(JobState::Failed));
        assert!(JobState::Running.can_transition_to(JobState::Completed));
        assert!(JobState::Running.can_transition_to(JobState::CancelRequested));
        assert!(JobState::Running.can_transition_to(JobState::Failed));
        assert!(JobState::CancelRequested.can_transition_to(JobState::Completed));
        assert!(JobState::CancelRequested.can_transition_to(JobState::Draining));
        assert!(JobState::CancelRequested.can_transition_to(JobState::Failed));
        assert!(JobState::Draining.can_transition_to(JobState::Finalizing));
        assert!(JobState::Draining.can_transition_to(JobState::Failed));
        assert!(JobState::Finalizing.can_transition_to(JobState::Completed));
        assert!(JobState::Finalizing.can_transition_to(JobState::Failed));

        assert!(JobState::Queued.can_transition_to(JobState::Completed));

        // Invalid transitions
        assert!(!JobState::Created.can_transition_to(JobState::Running));
        assert!(!JobState::Created.can_transition_to(JobState::Completed));
        assert!(!JobState::Draining.can_transition_to(JobState::Completed));
        assert!(!JobState::Completed.can_transition_to(JobState::Running));
    }

    #[test]
    fn envelope_serialization_round_trip() {
        let env = WorkerEnvelope::new(
            1,
            1,
            42,
            0,
            WorkerOp::SpawnJob(SpawnJobRequest {
                job_id: 1,
                region_id: 100,
                task_id: 200,
                obligation_id: 300,
                payload: vec![1, 2, 3],
            }),
        );
        let json = serde_json::to_string(&env).unwrap();
        let deserialized: WorkerEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, deserialized);
    }

    #[test]
    fn worker_envelope_serialization_round_trip_preserves_worker_identity() {
        let env = worker_envelope(
            "worker-round-trip",
            7,
            9,
            3,
            WorkerOp::Diagnostic(DiagnosticEvent {
                level: DiagnosticLevel::Info,
                category: "serde".into(),
                message: "round-trip".into(),
                metadata: Some("worker identity must survive serialization".into()),
            }),
        );
        let json = serde_json::to_string(&env).unwrap();
        let deserialized: WorkerEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, deserialized);
        assert!(deserialized.validate().is_ok());
    }

    #[test]
    fn coordinator_sequence_numbers_are_monotonic() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();

        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        coord.spawn_job(2, 100, 201, 301, vec![]).unwrap();

        let msg1 = coord.drain_outbox().unwrap();
        let msg2 = coord.drain_outbox().unwrap();
        assert!(msg2.seq_no > msg1.seq_no);
        assert!(msg2.message_id > msg1.message_id);
    }

    #[test]
    fn coordinator_emits_independent_decision_sequence() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.next_decision_seq = 19;

        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        coord.spawn_job(2, 100, 201, 301, vec![]).unwrap();

        let msg1 = coord.drain_outbox().unwrap();
        let msg2 = coord.drain_outbox().unwrap();

        assert_eq!(msg1.seq_no, 1);
        assert_eq!(msg1.decision_seq, 19);
        assert_ne!(msg1.seq_no, msg1.decision_seq);
        assert!(msg1.validate().is_ok());

        assert_eq!(msg2.seq_no, 2);
        assert_eq!(msg2.decision_seq, 20);
        assert_ne!(msg2.seq_no, msg2.decision_seq);
        assert!(msg2.validate().is_ok());
    }

    #[test]
    fn diagnostic_events_are_accepted() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();

        let diag = test_worker_envelope(
            2,
            2,
            1,
            WorkerOp::Diagnostic(DiagnosticEvent {
                level: DiagnosticLevel::Info,
                category: "lifecycle".into(),
                message: "worker initialized".into(),
                metadata: None,
            }),
        );
        assert!(coord.handle_inbound(&diag).is_ok());
    }

    #[test]
    fn coordinator_rejects_stale_old_worker_message_after_rebootstrap() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();

        let reboot = worker_envelope(
            "test-worker-2",
            1,
            1,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-2".into(),
            },
        );
        coord.handle_inbound(&reboot).unwrap();

        let stale = test_worker_envelope(
            9,
            9,
            1,
            WorkerOp::Diagnostic(DiagnosticEvent {
                level: DiagnosticLevel::Warn,
                category: "stale".into(),
                message: "late message from replaced worker".into(),
                metadata: None,
            }),
        );
        assert_eq!(
            coord.handle_inbound(&stale),
            Err(WorkerChannelError::InboundWorkerSessionMismatch {
                expected: Some("test-worker-2".into()),
                actual: "test-worker-1".into(),
            })
        );

        let fresh = worker_envelope(
            "test-worker-2",
            2,
            2,
            1,
            WorkerOp::Diagnostic(DiagnosticEvent {
                level: DiagnosticLevel::Info,
                category: "fresh".into(),
                message: "new worker follow-up".into(),
                metadata: None,
            }),
        );
        coord.handle_inbound(&fresh).unwrap();
        assert_eq!(coord.last_inbound_seq_no, 2);
    }

    #[test]
    fn envelope_rejects_worker_message_without_session_identity() {
        let env = WorkerEnvelope::new(2, 2, 42, 1, WorkerOp::ShutdownCompleted);
        assert_eq!(
            env.validate(),
            Err(WorkerChannelError::MissingWorkerSessionIdentity)
        );
    }
