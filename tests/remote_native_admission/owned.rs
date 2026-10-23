//! Admitted native transport composed with checked region-owned invocation.
use super::*;
use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::remote_owned::{
    RemoteLeaseSettlement, RemoteRunConfig, RemoteRunHandleError, RemoteRunTaskError,
};
use asupersync::remote::{NativeRemoteOwnedError, RemoteError};
use asupersync::runtime::{JoinError, RuntimeHandle};

const CHARGE: usize = 16 * (4096 + 4) + 256 * 1024;

fn config() -> RemoteRunConfig {
    RemoteRunConfig {
        timeout: Duration::from_secs(10),
        child: ChildRegionSpec::inherit(),
    }
}

fn domain(handle: &RuntimeHandle, route: NativeRemoteRoute) -> AdmittedNativeRemoteRuntime {
    AdmittedNativeRemoteRuntime::new(
        handle.clone(),
        NodeId::new("origin"),
        [(route, NativeRemotePeerAdmissionLimits {
            max_in_flight: 1,
            max_buffer_bytes: CHARGE,
            max_input_bytes: 1024,
        })],
        NativeRemoteAdmissionLimits {
            max_routes: 1,
            max_in_flight: 1,
            max_buffer_bytes: CHARGE,
            max_waiters: 1,
            max_waiters_per_peer: 1,
        },
        NativeRemoteRuntimeConfig::new()
            .with_max_in_flight(1)
            .with_drain_timeout(Duration::from_secs(3)),
    )
    .unwrap()
}

struct Stop {
    admitted: AdmittedNativeRemoteRuntime,
    service: RemoteComputationServiceHandle,
    witness: Arc<Witness>,
}
impl Drop for Stop {
    fn drop(&mut self) {
        // A failed assertion must release deliberately withheld remote cleanup.
        self.witness.release();
        self.admitted.begin_drain();
        let _ = self.service.begin_drain();
    }
}

#[derive(Clone, Copy, Debug)]
enum Case {
    UnreadSuccess,
    ParentClose,
    HandleDrop,
    InlineDrop,
    UnpolledInline,
    CancelBeforePoll,
    ClosedBeforeDispatch,
    FrameRefusal,
    Attenuated,
    LastDomainOwner,
}

fn exercise_owned(workers: usize, case: Case) {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap()
    };
    let runtime_handle = runtime.handle();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.remote().is_none(), "the reservation is the route authority");
        assert!(cx.capabilities().remote);
        let witness = Arc::new(Witness::default());
        let mut serving = start_service(
            &cx, "owned", include_bytes!("../fixtures/tls/server.crt"),
            include_bytes!("../fixtures/tls/server.key"), Arc::clone(&witness),
        )
        .await;
        let admitted = domain(&runtime_handle, serving.route.clone());
        let _stop = Stop {
            admitted: admitted.clone(),
            service: serving.operator.clone(),
            witness: Arc::clone(&witness),
        };
        let node = NodeId::new("owned");
        let wait = Duration::from_secs(2);
        let lease = Duration::from_millis(600);
        let echo = ComputationName::new("echo");
        let parked = ComputationName::new("wait");

        match case {
            Case::UnreadSuccess => {
                let mut invocation = admitted.reserve(&cx, &node, 4, wait).await.unwrap()
                    .spawn_owned(&cx, &echo, b"live", lease, config()).unwrap();
                eventually(&cx, || invocation.is_finished()).await;
                assert_eq!(admitted.usage().in_flight, 1);
                assert_eq!(admitted.usage().buffer_bytes, CHARGE,
                    "unread runtime-owned terminal bytes remain charged");
                let report = invocation.try_join().unwrap().expect("terminal report");
                assert!(report.is_success(), "{report:?}");
                assert!(matches!(&report.task.as_ref().unwrap().outcome,
                    Outcome::Ok(RemoteOutcome::Success(bytes)) if bytes == b"live"));
                eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
                // Report bytes are now caller-owned, even while report stays live.
                assert!(matches!(invocation.try_join(),
                    Err(RemoteRunHandleError::Join(JoinError::PolledAfterCompletion))));
                drop(report);
                let next = admitted.reserve(&cx, &node, 4, wait).await.unwrap()
                    .run_owned(&cx, &echo, b"next", lease, config()).await.unwrap();
                assert!(next.is_success(), "capacity is reusable after report transfer");
            }
            Case::ParentClose | Case::HandleDrop => {
                let parent = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let mut invocation = Some(admitted.reserve(&cx, &node, 0, wait).await.unwrap()
                    .spawn_owned(parent.cx(), &parked, &[], lease, config()).unwrap());
                eventually(&cx, || witness.parked.load(Ordering::Acquire)).await;
                assert!(invocation.as_mut().unwrap().try_join().unwrap().is_none());
                assert_eq!(admitted.usage().buffer_bytes, CHARGE);
                // Local attribution exceeds the entire wire-frame envelope.
                // Owned cancellation must still fit protected native control.
                let mut reason = CancelReason::user("owned parent attribution");
                reason.message = Some("owned parent attribution ".repeat(1024));
                if matches!(case, Case::HandleDrop) {
                    drop(invocation.take());
                } else {
                    parent.cancel(reason.clone()).unwrap();
                }
                let mut close = Box::pin(parent.close());
                let mut cancelled = std::pin::pin!(
                    witness.changed.wait_until(|| witness.cancelled.load(Ordering::Acquire)));
                asupersync::time::timeout(cx.now(), Duration::from_secs(3), poll_fn(|task| {
                    assert!(close.as_mut().poll(task).is_pending(),
                        "parent close must await actual remote cleanup");
                    cancelled.as_mut().poll(task)
                })).await.expect("owned cancellation reaches the parked native handler");
                assert_eq!(admitted.usage().in_flight, 1);
                assert_eq!(admitted.usage().buffer_bytes, CHARGE);
                assert!(!witness.retired.load(Ordering::Acquire));
                if let Some(handle) = &invocation {
                    assert!(!handle.is_finished());
                }
                witness.release();
                close.await.unwrap();
                assert!(witness.retired.load(Ordering::Acquire));
                if let Some(mut handle) = invocation {
                    assert_eq!(admitted.usage().buffer_bytes, CHARGE,
                        "parent close does not consume the unread result");
                    let report = handle.join(&cx).await.unwrap();
                    assert!(!report.is_success());
                    assert!(report.close.is_ok());
                    assert!(report.cancel_error.is_none());
                    let reply = report.task.unwrap();
                    assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
                    assert!(matches!(reply.outcome, Outcome::Ok(RemoteOutcome::Cancelled(_))));
                    assert!(reply.cancellation.unwrap().chain().any(
                        |cause| cause.message == reason.message),
                        "full local attribution survives bounded wire cancellation");
                }
                eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
            }
            Case::InlineDrop => {
                let parent = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let owner = parent.cx().clone();
                let permit = admitted.reserve(&cx, &node, 0, wait).await.unwrap();
                let mut invocation = Box::pin(
                    permit.run_owned(&owner, &parked, &[], lease, config()));
                let mut started = std::pin::pin!(
                    witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire)));
                asupersync::time::timeout(cx.now(), Duration::from_secs(3), poll_fn(|task| {
                    assert!(invocation.as_mut().poll(task).is_pending());
                    started.as_mut().poll(task)
                })).await.expect("inline proxy starts real remote work");
                drop(invocation);
                eventually(&cx, || witness.cancelled.load(Ordering::Acquire)).await;
                assert_eq!(admitted.usage().buffer_bytes, CHARGE,
                    "proxy and driver retain credit after inline owner abandonment");
                let mut close = Box::pin(parent.close());
                poll_fn(|task| {
                    assert!(close.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                assert!(!witness.retired.load(Ordering::Acquire));
                witness.release();
                close.await.unwrap();
                eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
                assert!(witness.retired.load(Ordering::Acquire));
            }
            Case::UnpolledInline => {
                let permit = admitted.reserve(&cx, &node, 0, wait).await.unwrap();
                let invocation = permit.run_owned(&cx, &parked, &[], lease, config());
                assert_eq!(admitted.usage().buffer_bytes, CHARGE);
                drop(invocation);
                assert_eq!(admitted.usage().buffer_bytes, 0);
                assert!(!witness.parked.load(Ordering::Acquire));
            }
            Case::CancelBeforePoll => {
                assert_eq!(workers, 1, "no worker may poll the owner before abort");
                let mut invocation = admitted.reserve(&cx, &node, 0, wait).await.unwrap()
                    .spawn_owned(&cx, &parked, &[], lease, config()).unwrap();
                let reason = CancelReason::user("cancel queued native owner");
                invocation.abort_with_reason(reason.clone());
                eventually(&cx, || invocation.is_finished()).await;
                assert_eq!(admitted.usage().buffer_bytes, CHARGE,
                    "even an unread terminal JoinError retains the handle share");
                assert!(matches!(invocation.try_join(),
                    Err(RemoteRunHandleError::Join(JoinError::Cancelled(actual))) if actual == reason));
                eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
                assert!(!witness.parked.load(Ordering::Acquire));
            }
            Case::ClosedBeforeDispatch | Case::FrameRefusal => {
                let input = if matches!(case, Case::FrameRefusal) { vec![255; 1024] } else { Vec::new() };
                let mut invocation = admitted.reserve(&cx, &node, input.len(), wait).await.unwrap()
                    .spawn_owned(&cx, &parked, &input, lease, config()).unwrap();
                if matches!(case, Case::ClosedBeforeDispatch) {
                    assert_eq!(workers, 1, "close precedes the first owner poll");
                    admitted.begin_drain();
                }
                eventually(&cx, || invocation.is_finished()).await;
                assert_eq!(admitted.usage().buffer_bytes, CHARGE);
                let report = invocation.join(&cx).await.unwrap();
                assert!(!report.is_success());
                assert!(report.close.is_ok());
                match case {
                    Case::ClosedBeforeDispatch => assert!(matches!(report.task,
                        Err(RemoteRunTaskError::NativeAdmission(NativeRemoteAdmissionError::Closed)))),
                    Case::FrameRefusal => assert!(matches!(report.task,
                        Err(RemoteRunTaskError::NativeAdmission(NativeRemoteAdmissionError::RequestTooLarge)))),
                    _ => unreachable!(),
                }
                assert!(!witness.parked.load(Ordering::Acquire));
                eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
                if matches!(case, Case::FrameRefusal) {
                    let next = admitted.reserve(&cx, &node, 0, wait).await.unwrap()
                        .run_owned(&cx, &echo, &[], lease, config()).await.unwrap();
                    assert!(next.is_success(), "wire refusal returned capacity");
                }
            }
            Case::Attenuated => {
                let restricted = {
                    type LocalCaps = asupersync::cx::cap::CapSet<true, true, true, true, false>;
                    let _guard = cx.restrict::<LocalCaps>().set_current_restricted();
                    Cx::current().unwrap()
                };
                let permit = admitted.reserve(&cx, &node, 0, wait).await.unwrap();
                assert!(matches!(permit.spawn_owned(&restricted, &parked, &[], lease, config()),
                    Err(NativeRemoteOwnedError::Admission(
                        NativeRemoteAdmissionError::Remote(RemoteError::NoCapability)))));
                assert_eq!(admitted.usage().buffer_bytes, 0);
                assert!(!witness.parked.load(Ordering::Acquire));
            }
            Case::LastDomainOwner => {
                let ephemeral = domain(&runtime_handle, serving.route.clone());
                let permit = ephemeral.reserve(&cx, &node, 4, wait).await.unwrap();
                drop(ephemeral);
                let report = permit.run_owned(&cx, &echo, b"last", lease, config()).await.unwrap();
                assert!(report.is_success(),
                    "consuming the last reservation must not drain its live native driver");
                assert!(matches!(report.task.unwrap().outcome,
                    Outcome::Ok(RemoteOutcome::Success(bytes)) if bytes == b"last"));
            }
        }

        eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
        assert_eq!(admitted.usage().in_flight, 0);
        assert_eq!(admitted.usage().waiters, 0);
        assert!(admitted.close(&cx).await.unwrap());
        let _ = serving.operator.begin_drain();
        assert!(serving.task.join(&cx).await.unwrap().is_ok());
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

fn checked(workers: usize, case: Case) {
    let (done, result) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        exercise_owned(workers, case);
        done.send(()).unwrap();
    });
    result.recv_timeout(Duration::from_secs(30))
        .expect("owned native lifecycle must finish without a wall-clock hang");
    thread.join().unwrap();
}

#[test]
fn admitted_native_owned_reports_and_admission_failures() {
    for workers in [1, 2] {
        for case in [Case::UnreadSuccess, Case::UnpolledInline, Case::FrameRefusal,
            Case::Attenuated, Case::LastDomainOwner] {
            checked(workers, case);
        }
    }
}

#[test]
fn admitted_native_owned_parent_and_drop_paths_drain_real_remote_cleanup() {
    for workers in [1, 2] {
        for case in [Case::ParentClose, Case::HandleDrop, Case::InlineDrop] {
            checked(workers, case);
        }
    }
}

#[test]
fn admitted_native_owned_queued_cancel_and_close_never_dispatch() {
    checked(1, Case::CancelBeforePoll);
    checked(1, Case::ClosedBeforeDispatch);
}
