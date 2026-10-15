//! Regression coverage for stale worker status snapshots during cancellation.

use asupersync::net::worker_channel::{
    JobState, JobStatusSnapshot, WorkerCoordinator, WorkerEnvelope, WorkerOp,
};

#[test]
fn stale_running_snapshot_after_cancel_does_not_reopen_job() {
    let mut coord = WorkerCoordinator::new(42);
    let ready = WorkerEnvelope::from_worker(
        "worker",
        1,
        1,
        42,
        0,
        WorkerOp::BootstrapReady {
            worker_id: "worker".into(),
        },
    );
    coord.handle_inbound(&ready).unwrap();
    coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
    let _ = coord.drain_outbox();

    coord.cancel_job(1, "test cancel".into()).unwrap();
    assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));

    let running = WorkerEnvelope::from_worker(
        "worker",
        2,
        2,
        42,
        1,
        WorkerOp::StatusSnapshot(JobStatusSnapshot {
            job_id: 1,
            state: JobState::Running,
            detail: None,
        }),
    );

    let res = coord.handle_inbound(&running);
    assert!(res.is_ok(), "Should ignore stale status snapshot");
    assert_eq!(
        coord.job_state(1),
        Some(JobState::CancelRequested),
        "stale running snapshot must not reopen a cancellation-requested job"
    );

    let cancel = coord.drain_outbox().unwrap();
    assert!(matches!(cancel.op, WorkerOp::CancelJob { job_id: 1, .. }));
}
