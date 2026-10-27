use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

#[test]
fn worker_policy_rejects_unbounded_or_empty_work_allowances() {
    let valid = SymbolRepairWorkerConfig::new(Duration::from_secs(1), 8);
    assert!(valid.validate().is_ok());
    assert!(
        valid
            .with_interval(Duration::from_nanos(1))
            .validate()
            .is_ok()
    );
    assert!(
        valid
            .with_retry_policy(2, Duration::from_millis(1))
            .validate()
            .is_ok()
    );
    for invalid in [
        SymbolRepairWorkerConfig::new(Duration::ZERO, 8),
        SymbolRepairWorkerConfig::new(Duration::from_secs(1), 0),
        SymbolRepairWorkerConfig::new(Duration::from_secs(u64::MAX), 8),
        valid.with_interval(Duration::ZERO),
        valid.with_retry_policy(0, Duration::from_secs(1)),
        valid.with_retry_policy(2, Duration::ZERO),
        valid.with_retry_policy(2, Duration::from_secs(u64::MAX)),
        SymbolRepairWorkerConfig::new(Duration::from_secs(1), usize::MAX)
            .with_retry_policy(2, Duration::from_secs(1)),
    ] {
        assert!(matches!(
            invalid.validate(),
            Err(SymbolRepairWorkerError::Configuration)
        ));
    }
}

#[test]
fn retry_interval_and_round_clocks_require_an_actual_future_instant() {
    assert_eq!(
        after(Time::from_nanos(u64::MAX - 1), Duration::from_nanos(1)).unwrap(),
        Time::MAX
    );
    for (now, interval) in [
        (Time::MAX, Duration::from_nanos(1)),
        (Time::from_nanos(u64::MAX - 1), Duration::from_nanos(2)),
        (Time::ZERO, Duration::ZERO),
        (Time::ZERO, Duration::from_secs(u64::MAX)),
    ] {
        assert!(matches!(
            after(now, interval),
            Err(SymbolRepairWorkerError::ClockExhausted)
        ));
    }
}

#[test]
fn convergence_after_cancel_or_deadline_is_retained_without_claiming_round_success() {
    let progress = SymbolRepairProgress {
        source_snapshot: [0; 32],
        complete: true,
        visited_nodes: 1,
        repaired_batches: 1,
        repaired_bytes: 256,
        already_present: 0,
    };
    let mut report = SymbolRepairRoundReport {
        sequence: 1,
        attempts: 1,
        steps: 1,
        progress: Some(progress),
        trigger: SymbolRepairRoundTrigger::Completed,
        outcome: Outcome::Ok(()),
    };
    assert!(report.is_success());
    report.trigger = SymbolRepairRoundTrigger::Deadline;
    assert!(!report.is_success());
    report.trigger = SymbolRepairRoundTrigger::ParentCancelled(CancelReason::user("operator stop"));
    assert!(!report.is_success());
    report.trigger = SymbolRepairRoundTrigger::Completed;
    report.progress.as_mut().unwrap().complete = false;
    assert!(!report.is_success());
}

#[test]
fn retries_do_not_revive_cancelled_deadline_or_invalid_transport_authority() {
    for failure in [
        SymbolRepairError::Cancelled,
        SymbolRepairError::Authority,
        SymbolRepairError::Catalog(CatalogError::Integrity),
        SymbolRepairError::Fetch(RemoteSymbolError::Deadline),
        SymbolRepairError::Fetch(RemoteSymbolError::Client(
            RemoteComputationClientError::InvalidConfig("missing authority"),
        )),
        SymbolRepairError::Fetch(RemoteSymbolError::Client(
            RemoteComputationClientError::Cancelled { attempts: 1 },
        )),
        SymbolRepairError::Fetch(RemoteSymbolError::Client(
            RemoteComputationClientError::ResponseTaskMismatch {
                attempts: 1,
                expected: 1,
                actual: 2,
            },
        )),
    ] {
        assert!(!retryable(&SymbolRepairRoundError::Repair(failure)));
    }
    assert!(retryable(&SymbolRepairRoundError::Repair(
        SymbolRepairError::Catalog(CatalogError::SnapshotChanged,)
    )));
    assert!(retryable(&SymbolRepairRoundError::Repair(
        SymbolRepairError::Fetch(RemoteSymbolError::Client(
            RemoteComputationClientError::Connect {
                attempts: 1,
                source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
            }
        ),)
    )));
}

fn prepared_handle() -> SymbolRepairWorkerHandle {
    SymbolRepairWorkerHandle {
        shared: Arc::new(Shared {
            state: Mutex::new(State {
                snapshot: SymbolRepairWorkerSnapshot {
                    status: SymbolRepairWorkerStatus::Prepared,
                    pending: false,
                    rounds_started: 0,
                    rounds_finished: 0,
                    successful_rounds: 0,
                    last_round: None,
                },
                stop: false,
            }),
            changed: Notify::new(),
        }),
    }
}

struct WakePayload {
    retired: Arc<AtomicUsize>,
    control: SymbolRepairWorkerHandle,
}

impl Drop for WakePayload {
    fn drop(&mut self) {
        // Destruction must be outside the admission lock and must release
        // ordinary captured allocations instead of leaking one per round.
        let _ = self.control.snapshot();
        self.retired.fetch_add(1, Ordering::AcqRel);
    }
}

struct PanickingWake {
    retired: Arc<AtomicUsize>,
    control: SymbolRepairWorkerHandle,
}

impl Wake for PanickingWake {
    fn wake(self: Arc<Self>) {
        std::panic::panic_any(WakePayload {
            retired: Arc::clone(&self.retired),
            control: self.control.clone(),
        });
    }
}

#[test]
fn observer_wake_panics_release_their_payload_without_holding_admission() {
    let control = prepared_handle();
    let retired = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(PanickingWake {
        retired: Arc::clone(&retired),
        control: control.clone(),
    }));
    let mut context = Context::from_waker(&waker);
    let mut observation = std::pin::pin!(control.changed(0));
    assert!(observation.as_mut().poll(&mut context).is_pending());
    assert_eq!(control.request(), SymbolRepairRequest::Scheduled);
    assert_eq!(retired.load(Ordering::Acquire), 1);
    assert!(control.snapshot().pending);
    assert_eq!(control.request(), SymbolRepairRequest::Coalesced);
    control.stop();
    assert_eq!(control.request(), SymbolRepairRequest::Closed);
}
