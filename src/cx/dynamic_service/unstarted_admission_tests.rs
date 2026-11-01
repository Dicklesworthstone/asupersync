use super::*;
use crate::cx::ChildRegionSpec;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn assert_send<T: Send>(_: &T) {}

fn assert_first_retirement_panic(action: impl FnOnce()) {
    let failure = catch_unwind(AssertUnwindSafe(action))
        .expect_err("retire every capture before resuming the first destructor panic");
    assert_eq!(
        failure.downcast_ref::<String>().map(String::as_str),
        Some("queued factory legacy-first")
    );
}

fn assert_unstarted_tree_retired(started: &AtomicUsize, dropped: &AtomicUsize) {
    assert_eq!(started.load(Ordering::SeqCst), 0);
    assert_eq!(dropped.load(Ordering::SeqCst), 4);
}

#[test]
fn never_polled_client_start_retires_every_capture_without_request_credit() {
    let client = standalone_client(1);
    let cx = Cx::for_testing();
    let started = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let tree = panicking_tree_for_dequeue(&client, &started, &dropped);
    let pending = client.start_child(&cx, "tree", tree);
    assert_send(&pending);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert_eq!(client.outstanding_requests(), 0);
    assert_first_retirement_panic(move || drop(pending));
    assert_unstarted_tree_retired(&started, &dropped);
    assert_eq!(client.outstanding_requests(), 0);
    assert!(client.shared.mailbox.lock().queue.is_empty());
}

#[test]
fn never_polled_owner_start_retires_every_capture_without_admission() {
    run_case(|cx| async move {
        let mut owner = cx
            .open_dynamic_supervisor::<()>(DynamicSupervisorConfig::new(1))
            .await
            .unwrap();
        let client = standalone_client(1);
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let tree = panicking_tree_for_dequeue(&client, &started, &dropped);
        let pending = owner.start_child("tree", tree);
        assert_send(&pending);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_first_retirement_panic(move || drop(pending));
        assert_unstarted_tree_retired(&started, &dropped);
        assert!(owner.is_empty());
        assert!(!owner.is_closing());
        let report = owner.shutdown().await;
        assert!(report.close.is_ok());
        assert!(report.children.is_empty());
    });
}

#[test]
fn never_polled_managed_run_retires_every_capture() {
    let client = standalone_client(1);
    let cx = Cx::for_testing();
    let started = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let tree = panicking_tree_for_dequeue(&client, &started, &dropped);
    let pending = tree.run(&cx);
    assert_send(&pending);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert_first_retirement_panic(move || drop(pending));
    assert_unstarted_tree_retired(&started, &dropped);
}

#[test]
fn client_refusal_before_enqueue_retires_every_capture_outside_mailbox_lock() {
    for case in ["busy", "closed", "cancelled"] {
        let client = standalone_client(1);
        let cx = Cx::for_testing();
        let held = if case == "busy" {
            Some(client.submit(&cx, Operation::Ready).unwrap())
        } else {
            None
        };
        if case == "closed" {
            client.shared.close();
        }
        if case == "cancelled" {
            cx.set_cancel_requested(true);
        }
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let tree = panicking_tree_for_dequeue(&client, &started, &dropped);
        assert_first_retirement_panic(|| {
            let mut pending = Box::pin(client.start_child(&cx, "tree", tree));
            assert!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready(),
                "{case}: refusal cannot wait for a controller"
            );
        });
        assert_unstarted_tree_retired(&started, &dropped);
        let retained = usize::from(case == "busy");
        assert_eq!(client.outstanding_requests(), retained, "{case}");
        assert_eq!(client.shared.mailbox.lock().queue.len(), retained, "{case}");
        drop(held);
        client.shared.close();
        assert_eq!(client.outstanding_requests(), 0, "{case}");
    }
}

#[test]
fn owner_admission_refusal_retires_every_capture_before_returning() {
    for case in ["capacity", "invalid", "closing"] {
        run_case(move |cx| async move {
            let capacity = usize::from(case != "capacity");
            let mut owner = cx
                .open_dynamic_supervisor::<()>(DynamicSupervisorConfig::new(capacity))
                .await
                .unwrap();
            if case == "closing" {
                owner.begin_shutdown();
            }
            let client = standalone_client(1);
            let started = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let tree = panicking_tree_for_dequeue(&client, &started, &dropped);
            let name = if case == "invalid" { "" } else { "tree" };
            assert_first_retirement_panic(|| {
                let mut pending = Box::pin(owner.start_child(name, tree));
                assert!(
                    pending
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_ready(),
                    "{case}: refuse before minting a child boundary"
                );
            });
            assert_unstarted_tree_retired(&started, &dropped);
            assert!(owner.is_empty());
            let report = owner.shutdown().await;
            assert!(report.close.is_ok());
            assert!(report.children.is_empty());
        });
    }
}

#[test]
fn dropped_or_cancelled_region_admission_retires_tree_and_reaches_quiescence() {
    for cancelled in [false, true] {
        run_case(move |cx| async move {
            let enclosing = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let mut owner = enclosing
                .cx()
                .open_dynamic_supervisor::<()>(DynamicSupervisorConfig::new(1))
                .await
                .unwrap();
            let client = standalone_client(1);
            let started = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let tree = panicking_tree_for_dequeue(&client, &started, &dropped);
            let mut pending = Box::pin(owner.start_child("tree", tree));
            assert!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            // The lab has not had a scheduler turn: the boundary mint is
            // queued, but no child controller or application factory exists.
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            if cancelled {
                // Change the owner's principal, keeping this test's parent
                // live so it can observe the real asynchronous boundary close.
                enclosing.cx().set_cancel_requested(true);
                let failure = poll_fn(|task_cx| {
                    match catch_unwind(AssertUnwindSafe(|| pending.as_mut().poll(task_cx))) {
                        Err(payload) => Poll::Ready(payload),
                        Ok(Poll::Pending) => Poll::Pending,
                        Ok(Poll::Ready(_)) => {
                            panic!("cancelled admission must retire its panicking captures")
                        }
                    }
                })
                .await;
                assert_eq!(
                    failure.downcast_ref::<String>().map(String::as_str),
                    Some("queued factory legacy-first")
                );
                drop(pending);
            } else {
                assert_first_retirement_panic(move || drop(pending));
            }
            assert_unstarted_tree_retired(&started, &dropped);
            assert!(owner.is_empty());
            assert_eq!(owner.is_closing(), cancelled);
            let report = owner.shutdown().await;
            assert!(report.close.is_ok());
            assert!(report.children.is_empty());
            enclosing.close().await.unwrap();
            // run_case checks the actual task, obligation and region barriers.
        });
    }
}

struct PanickingName {
    conversions: Arc<AtomicUsize>,
}

impl From<PanickingName> for ChildName {
    fn from(name: PanickingName) -> Self {
        name.conversions.fetch_add(1, Ordering::SeqCst);
        panic!("name conversion panic");
    }
}

#[test]
fn name_conversion_stays_lazy_and_existing_unwind_survives_retirement() {
    for poll_name in [false, true] {
        let client = standalone_client(1);
        let cx = Cx::for_testing();
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let conversions = Arc::new(AtomicUsize::new(0));
        let tree = panicking_tree_for_dequeue(&client, &started, &dropped);
        let failure = catch_unwind(AssertUnwindSafe(|| {
            let mut pending = Box::pin(client.start_child(
                &cx,
                PanickingName {
                    conversions: Arc::clone(&conversions),
                },
                tree,
            ));
            assert_eq!(conversions.load(Ordering::SeqCst), 0);
            if poll_name {
                let _ = pending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()));
                panic!("name conversion should have panicked");
            }
            panic!("original owner unwind");
        }))
        .expect_err("the original panic remains visible after complete retirement");
        assert_eq!(
            failure.downcast_ref::<&str>().copied(),
            Some(if poll_name {
                "name conversion panic"
            } else {
                "original owner unwind"
            })
        );
        assert_eq!(conversions.load(Ordering::SeqCst), usize::from(poll_name));
        assert_unstarted_tree_retired(&started, &dropped);
        assert_eq!(client.outstanding_requests(), 0);
        assert!(client.shared.mailbox.lock().queue.is_empty());
    }
}

#[test]
fn refused_managed_spawn_retires_every_capture() {
    for controlled in [false, true] {
        let client = standalone_client(1);
        let cx = Cx::for_testing();
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let tree = panicking_tree_for_dequeue(&client, &started, &dropped);
        assert_first_retirement_panic(|| {
            if controlled {
                let _ = tree.spawn_controlled(&cx, std::num::NonZeroUsize::new(1).unwrap());
            } else {
                let _ = tree.spawn(&cx);
            }
        });
        assert_unstarted_tree_retired(&started, &dropped);
    }
}

#[test]
fn closed_region_refuses_unpolled_controller_and_retires_every_capture() {
    for controlled in [false, true] {
        run_case(move |cx| async move {
            let enclosing = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let closed_cx = enclosing.cx().clone();
            enclosing.close().await.unwrap();
            let client = standalone_client(1);
            let started = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let tree = panicking_tree_for_dequeue(&client, &started, &dropped);
            let (mut handle, control) = if controlled {
                let (handle, control) = tree
                    .spawn_controlled(&closed_cx, std::num::NonZeroUsize::new(1).unwrap())
                    .unwrap();
                (handle, Some(control))
            } else {
                (tree.spawn(&closed_cx).unwrap(), None)
            };
            // This ordinary child principal has no race-branch fallback.
            // The scheduler must refuse the queued factory for its closed
            // region; no controller ever takes ownership of the tree.
            assert_eq!(started.load(Ordering::SeqCst), 0);
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            handle.abort();
            assert!(matches!(handle.join().await, Err(JoinError::Cancelled(_))));
            drop(control);
            assert_unstarted_tree_retired(&started, &dropped);
        });
    }
}
