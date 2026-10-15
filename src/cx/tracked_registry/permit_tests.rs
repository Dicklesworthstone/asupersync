#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use super::super::tests::{finish, fixture, flush};
use crate::channel::mpsc;
use crate::cx::registry::NameLeaseError;
use crate::runtime::obligation_mailbox::ObligationAdmissionError;
use crate::types::CancelKind;
use std::future::Future;
use std::task::{Context, Poll, Waker};

#[test]
fn reserved_name_is_hidden_but_cannot_be_taken_by_a_competitor() {
    let (lab, cx, handle) = fixture(2);
    let registry = TrackedNameRegistry::new();
    let permit = registry.reserve(&cx, "worker").unwrap();
    assert_eq!(permit.name(), "worker");
    assert_eq!(permit.holder(), cx.task_id());
    assert_eq!(permit.region(), cx.region_id());
    assert_eq!(permit.reserved_at(), cx.now());
    assert_eq!(registry.whereis("worker"), None);
    assert!(matches!(registry.register(&cx, "worker"),
        Err(TrackedNameError::Registry(NameLeaseError::NameTaken { .. }))));
    assert_eq!(registry.whereis("worker"), None);
    let lease = permit.commit().unwrap();
    assert_eq!(registry.whereis("worker"), Some(cx.task_id()));
    lease.release().unwrap();
    finish(lab, &cx, handle, 2);
}

#[test]
fn publication_preserves_ticket_and_one_credit_without_a_terminal_gap() {
    let (mut lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let permit = registry.reserve(&cx, "worker").unwrap();
    let ticket = permit.obligation_ticket();
    flush(&mut lab);
    assert_eq!(lab.state.pending_obligation_count(), 1);
    let posted = lab.state.obligation_gateway().unwrap().mailbox().stats().posted;
    let lease = permit.commit().unwrap();
    assert_eq!(lease.obligation_ticket(), ticket);
    assert_eq!(lab.state.pending_obligation_count(), 1);
    assert_eq!(lab.state.obligation_gateway().unwrap().mailbox().stats().posted, posted);
    assert!(matches!(registry.register(&cx, "other"),
        Err(TrackedNameError::Admission(ObligationAdmissionError::LimitReached {
            limit: 1, live: 1,
        }))));
    lease.release().unwrap();
    registry.register(&cx, "other").unwrap().release().unwrap();
    finish(lab, &cx, handle, 2);
}

#[test]
fn drop_and_abort_remove_pending_name_and_return_credit_without_drain() {
    for explicit in [false, true] {
        let (lab, cx, handle) = fixture(1);
        let registry = TrackedNameRegistry::new();
        let permit = registry.reserve(&cx, "worker").unwrap();
        if explicit { permit.abort().unwrap(); } else { drop(permit); }
        assert_eq!(registry.whereis("worker"), None);
        registry.reserve(&cx, "worker").unwrap().commit().unwrap().release().unwrap();
        finish(lab, &cx, handle, 2);
    }
}

#[test]
fn dropping_a_future_during_async_setup_releases_its_reservation() {
    let (lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let mut setup = Box::pin(async {
        let _permit = registry.reserve(&cx, "worker").unwrap();
        std::future::pending::<()>().await;
    });
    assert!(matches!(setup.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Pending));
    assert_eq!(registry.whereis("worker"), None);
    drop(setup);
    registry.register(&cx, "worker").unwrap().release().unwrap();
    finish(lab, &cx, handle, 2);
}

#[test]
fn cancellation_before_publication_aborts_the_unpublished_name() {
    let (mut lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let permit = registry.reserve(&cx, "worker").unwrap();
    cx.cancel_fast(CancelKind::User);
    assert!(matches!(permit.commit(), Err(TrackedNameError::Cancelled)));
    assert_eq!(registry.whereis("worker"), None);
    // Masked recovery proves both the name and quota were returned, without
    // clearing cancellation or bypassing the checked admission path.
    let replacement = cx.masked(|| registry.register(&cx, "worker")).unwrap();
    replacement.release().unwrap();
    flush(&mut lab);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert_eq!(lab.state.leak_count(), 0);
    let stats = lab.state.obligation_gateway().unwrap().mailbox().stats();
    assert_eq!(stats.reserved, 2);
    assert_eq!(stats.aborted, 1);
    assert_eq!(stats.committed, 1);
    drop(handle);
}

#[test]
fn publication_honors_the_original_contexts_checkpoint_mask() {
    let (mut lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let permit = registry.reserve(&cx, "worker").unwrap();
    cx.cancel_fast(CancelKind::User);
    let lease = cx.masked(|| permit.commit()).unwrap();
    assert_eq!(registry.whereis("worker"), Some(cx.task_id()));
    lease.release().unwrap();
    flush(&mut lab);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert_eq!(lab.state.leak_count(), 0);
    drop(handle);
}

#[test]
fn panic_during_setup_does_not_leave_a_drop_bomb_or_stale_name() {
    let (lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _permit = registry.reserve(&cx, "worker").unwrap();
        panic!("planted startup failure");
    }));
    assert!(result.is_err());
    registry.register(&cx, "worker").unwrap().release().unwrap();
    finish(lab, &cx, handle, 2);
}

#[test]
fn refused_raw_commit_aborts_runtime_credit_instead_of_leaking_it() {
    let (lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let permit = registry.reserve(&cx, "worker").unwrap();
    // A private fault injection exercises a canonical commit refusal. No
    // public API exposes the backing registry or an unguarded mutation path.
    registry.inner.lock().cancel_permit(permit.permit.as_ref().unwrap(), cx.now()).unwrap();
    assert!(matches!(permit.commit(),
        Err(TrackedNameError::Registry(NameLeaseError::NotFound { .. }))));
    registry.register(&cx, "worker").unwrap().release().unwrap();
    finish(lab, &cx, handle, 2);
}

#[test]
fn channel_permits_and_names_compete_for_the_same_region_quota() {
    let (lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let (sender, _receiver) = mpsc::channel::<u8>(1);
    let channel_permit = sender.try_reserve_checked(&cx).unwrap();
    assert!(matches!(registry.reserve(&cx, "worker"),
        Err(TrackedNameError::Admission(ObligationAdmissionError::LimitReached {
            limit: 1, live: 1,
        }))));
    drop(channel_permit);
    let name_permit = registry.reserve(&cx, "worker").unwrap();
    assert!(matches!(sender.try_reserve_checked(&cx),
        Err(mpsc::CheckedSendError::Admission {
            error: ObligationAdmissionError::LimitReached { limit: 1, live: 1 },
            value: (),
        })));
    let lease = name_permit.commit().unwrap();
    lease.release().unwrap();
    sender.try_reserve_checked(&cx).unwrap().abort();
    finish(lab, &cx, handle, 3);
}

#[test]
fn uncommitted_reservation_is_visible_to_holder_completion_leak_audit() {
    let (mut lab, cx, mut handle) = fixture(1);
    lab.state.set_obligation_leak_response(crate::runtime::config::ObligationLeakResponse::Silent);
    let registry = TrackedNameRegistry::new();
    let retained = std::mem::ManuallyDrop::new(registry.reserve(&cx, "worker").unwrap());
    flush(&mut lab);
    assert_eq!(lab.state.pending_obligation_count(), 1);
    assert_eq!(registry.whereis("worker"), None);
    lab.scheduler.lock().schedule(cx.task_id(), 0);
    let _report = lab.run_until_quiescent_with_report();
    assert!(!matches!(handle.try_join(), Ok(None)), "holder must terminate");
    assert_eq!(lab.state.leak_count(), 1);
    let result = std::mem::ManuallyDrop::into_inner(retained).abort();
    assert!(matches!(result, Err(TrackedNameError::SettlementRejected)));
    assert_eq!(lab.state.leak_count(), 1);
}
