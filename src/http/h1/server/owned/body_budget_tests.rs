//! Buffered-body admission follows the actual request subtree after abandonment.

use super::{RequestExecutionConfig, Response, ServerHopOutcome, run_owned_request};
use crate::channel::oneshot;
use crate::cx::Cx;
use crate::http::body::admission::{BodyBudget, BodyReservation};
use crate::http::h1::types::{Method, Request, Version};
use crate::lab::{LabConfig, LabRuntime};
use crate::types::{Budget, CancelReason};
use crate::web::request_region::RequestBudgetSource;
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

struct Retired(Arc<AtomicUsize>);

impl Drop for Retired {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

async fn wait_for_cancel(cx: &Cx, pending: &AtomicUsize) {
    let mut cancelled = std::pin::pin!(cx.cancelled());
    let mut witnessed = false;
    poll_fn(|task| {
        let result = cancelled.as_mut().poll(task);
        if result.is_pending() && !witnessed {
            pending.fetch_add(1, Ordering::SeqCst);
            witnessed = true;
        }
        result
    })
    .await;
    assert!(
        cx.checkpoint().is_err(),
        "the actual task observed cancellation"
    );
}

async fn park_cleanup(mut gate: oneshot::Receiver<()>, entered: &AtomicUsize) {
    let mut release = std::pin::pin!(gate.recv_uninterruptible());
    let mut witnessed = false;
    poll_fn(|task| {
        let result = release.as_mut().poll(task);
        if result.is_pending() && !witnessed {
            entered.fetch_add(1, Ordering::SeqCst);
            witnessed = true;
        }
        result
    })
    .await
    .expect("cleanup gate released");
}

#[test]
fn abandoned_request_keeps_body_credit_until_descendant_retirement() {
    const PAYLOAD: &[u8] = b"retained";
    const STEP_LIMIT: u64 = 2048;

    for seed in [0x11_801, 0x11_802] {
        let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(STEP_LIMIT));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let budget = Arc::new(BodyBudget::default());
        budget.set_limit(NonZeroUsize::new(PAYLOAD.len()).unwrap());
        let mut reservation = BodyReservation::new(Arc::clone(&budget));
        reservation.try_grow(PAYLOAD.len()).unwrap();
        let request = Request {
            method: Method::Post,
            uri: "/owned-body".to_owned(),
            version: Version::Http11,
            headers: Vec::new(),
            body: PAYLOAD.to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let pending = Arc::new(AtomicUsize::new(0));
        let cleanup = Arc::new(AtomicUsize::new(0));
        let body_retired = Arc::new(AtomicUsize::new(0));
        let body_completed = Arc::new(AtomicUsize::new(0));
        let child_retired = Arc::new(AtomicUsize::new(0));
        let payload_verified = Arc::new(AtomicUsize::new(0));
        let (release_body, body_gate) = oneshot::channel::<()>();
        let (release_child, child_gate) = oneshot::channel::<()>();
        let (abandon_owner, mut abandon) = oneshot::channel::<()>();

        let body_pending = Arc::clone(&pending);
        let body_cleanup = Arc::clone(&cleanup);
        let retired_body = Arc::clone(&body_retired);
        let completed_body = Arc::clone(&body_completed);
        let retired_child = Arc::clone(&child_retired);
        let verified = Arc::clone(&payload_verified);
        let (owner, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("admitted coordinator");
                let config = RequestExecutionConfig {
                    budget: Budget::INFINITE,
                    started_at: cx.now(),
                    source: RequestBudgetSource::Inherited,
                    drain_grace: Duration::from_secs(1),
                    connection: Some(cx.clone()),
                    shutdown: None,
                    // No test-side token clone can keep the reservation alive.
                    body_reservation: Some(Arc::new(reservation)),
                };
                let mut execution = Box::pin(run_owned_request(
                    &cx,
                    config,
                    move |body, region| async move {
                        let _region = region;
                        let _retired = Retired(retired_body);
                        let child_pending = Arc::clone(&body_pending);
                        let child_cleanup = Arc::clone(&body_cleanup);
                        let _descendant = body
                            .spawn(move |child| async move {
                                let _retired = Retired(retired_child);
                                // Move the original received Vec into real child work.
                                let payload = request.body;
                                wait_for_cancel(&child, &child_pending).await;
                                park_cleanup(child_gate, &child_cleanup).await;
                                assert_eq!(payload.as_slice(), PAYLOAD);
                                // The outer test must fail if a contained child panic
                                // bypasses the actual payload check.
                                verified.fetch_add(1, Ordering::SeqCst);
                            })
                            .unwrap();
                        wait_for_cancel(&body, &body_pending).await;
                        park_cleanup(body_gate, &body_cleanup).await;
                        completed_body.fetch_add(1, Ordering::SeqCst);
                        ServerHopOutcome::Ok(Response::new(200, "OK", Vec::new()))
                    },
                ));
                let mut abandoned = std::pin::pin!(abandon.recv_uninterruptible());
                poll_fn(|task| {
                    if abandoned.as_mut().poll(task).is_ready() {
                        return Poll::Ready(());
                    }
                    assert!(execution.as_mut().poll(task).is_pending());
                    Poll::Pending
                })
                .await;
                drop(execution);
            })
            .unwrap();
        lab.scheduler.lock().schedule(owner, 0);

        assert!(lab.run_until_idle() < STEP_LIMIT);
        assert_eq!(pending.load(Ordering::SeqCst), 2);
        assert_eq!(cleanup.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.live_task_count(), 3);
        assert_eq!(budget.reserved_bytes(), PAYLOAD.len());

        abandon_owner.send_blocking(()).unwrap();
        assert!(lab.run_until_idle() < STEP_LIMIT);
        assert_eq!(join.try_join(), Ok(Some(())));
        assert_eq!(cleanup.load(Ordering::SeqCst), 2);
        assert_eq!(body_retired.load(Ordering::SeqCst), 0);
        assert_eq!(child_retired.load(Ordering::SeqCst), 0);
        assert_eq!(budget.reserved_bytes(), PAYLOAD.len());
        assert_eq!(lab.state.live_task_count(), 2);
        assert_eq!(lab.run_until_idle(), 0, "abandoned cleanup must park");

        release_body.send_blocking(()).unwrap();
        assert!(lab.run_until_idle() < STEP_LIMIT);
        assert_eq!(body_completed.load(Ordering::SeqCst), 1);
        assert_eq!(body_retired.load(Ordering::SeqCst), 1);
        assert_eq!(child_retired.load(Ordering::SeqCst), 0);
        assert_eq!(payload_verified.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.live_task_count(), 1);
        assert_eq!(
            lab.state.regions_len(),
            2,
            "request subtree still owns the child"
        );
        assert_eq!(budget.reserved_bytes(), PAYLOAD.len());
        assert_eq!(
            lab.run_until_idle(),
            0,
            "descendant cleanup must still park"
        );

        let mut replacement = BodyReservation::new(Arc::clone(&budget));
        assert!(replacement.try_grow(1).is_err());
        assert_eq!(budget.reserved_bytes(), PAYLOAD.len());

        release_child.send_blocking(()).unwrap();
        assert!(lab.run_until_idle() < STEP_LIMIT);
        assert_eq!(payload_verified.load(Ordering::SeqCst), 1);
        assert_eq!(child_retired.load(Ordering::SeqCst), 1);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(budget.refusals(), 1);
        replacement.try_grow(PAYLOAD.len()).unwrap();
        drop(replacement);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.regions_len(), 1, "only the root remains");
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());

        lab.state
            .close_region_command(root, &CancelReason::user("H1 body budget test finished"));
        assert!(lab.run_until_idle() < STEP_LIMIT);
        assert_eq!(lab.state.regions_len(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert!(
            lab.state
                .timer_driver_handle()
                .unwrap()
                .next_deadline()
                .is_none()
        );
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    }
}
