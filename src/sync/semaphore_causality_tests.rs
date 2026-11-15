//! Capacity-publication regressions for br-asupersync-bi2462.97.

use super::*;
use crate::lab::{LabConfig, LabRuntime};
use crate::remote::NodeId;
use crate::trace::distributed::{CausalOrder, LogicalClockMode, LogicalTime};
use crate::types::Budget;
use futures_lite::future::block_on;

fn causal_context(runtime: u64, node: &str) -> Cx {
    Cx::for_testing()
        .with_logical_clock(
            LogicalClockMode::Vector {
                node: NodeId::new(node),
            }
            .build_handle(None),
        )
        .with_task_causality_runtime(Some(runtime))
}

fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
}

fn assert_capacity_receipts(semaphore: &Semaphore) {
    let state = semaphore.state.lock();
    if let Some(batches) = &state.causality {
        assert!(batches.iter().all(|batch| batch.count > 0));
        assert_eq!(
            batches.iter().map(|batch| batch.count).sum::<usize>(),
            state.permits
        );
    }
    assert_eq!(semaphore.available_permits(), state.permits);
}

fn acquire_and_forget(semaphore: &Arc<Semaphore>, cx: &Cx, api: usize, count: usize) {
    match api {
        0 => semaphore.try_acquire(count).unwrap().forget(),
        1 => block_on(semaphore.acquire(cx, count)).unwrap().forget(),
        2 => semaphore.try_acquire_checked(cx, count).unwrap().forget(),
        3 => block_on(semaphore.acquire_many_checked(cx, count))
            .unwrap()
            .forget(),
        4 => OwnedSemaphorePermit::try_acquire(Arc::clone(semaphore), count)
            .unwrap()
            .forget(),
        5 => OwnedSemaphorePermit::try_acquire_arc(semaphore, count)
            .unwrap()
            .forget(),
        6 => block_on(OwnedSemaphorePermit::acquire(
            Arc::clone(semaphore),
            cx,
            count,
        ))
        .unwrap()
        .forget(),
        7 => OwnedSemaphorePermit::try_acquire_checked(Arc::clone(semaphore), cx, count)
            .unwrap()
            .forget(),
        8 => OwnedSemaphorePermit::try_acquire_arc_checked(semaphore, cx, count)
            .unwrap()
            .forget(),
        9 => block_on(OwnedSemaphorePermit::acquire_checked(
            Arc::clone(semaphore),
            cx,
            count,
        ))
        .unwrap()
        .forget(),
        _ => block_on(OwnedAcquireFuture::new_uncancelable(
            Arc::clone(semaphore),
            count,
        ))
        .unwrap()
        .forget(),
    }
}

#[test]
fn all_acquire_forms_observe_fixed_release_batches_without_ordering_sibling_units() {
    let _host = Cx::set_current(None);
    for api in 0..11 {
        let source = causal_context(97, "source");
        let first = causal_context(97, "first");
        let second = causal_context(97, "second");
        let semaphore = Arc::new(Semaphore::new(2));
        let published = {
            let _current = Cx::set_current(Some(source.clone()));
            let held = semaphore.try_acquire(2).unwrap();
            let published = source.logical_tick();
            held.commit();
            published
        };
        let later = source.logical_tick();
        {
            let _current = Cx::set_current(Some(first.clone()));
            acquire_and_forget(&semaphore, &first, api, 1);
        }
        let first_seen = first.logical_tick();
        {
            let _current = Cx::set_current(Some(second.clone()));
            acquire_and_forget(&semaphore, &second, api, 1);
        }
        let second_seen = second.logical_tick();
        assert_eq!(
            published.causal_order(&first_seen),
            CausalOrder::Before,
            "api={api}"
        );
        assert_eq!(
            published.causal_order(&second_seen),
            CausalOrder::Before,
            "api={api}"
        );
        assert_eq!(
            later.causal_order(&first_seen),
            CausalOrder::Concurrent,
            "api={api}"
        );
        assert_eq!(
            later.causal_order(&second_seen),
            CausalOrder::Concurrent,
            "api={api}"
        );
        assert_eq!(
            first_seen.causal_order(&second_seen),
            CausalOrder::Concurrent,
            "api={api}"
        );
        assert_eq!(source.logical_now(), later);
        assert_eq!(semaphore.available_permits(), 0);
        assert_capacity_receipts(&semaphore);
    }
}

#[test]
fn initial_capacity_and_different_releases_do_not_acquire_false_dependencies() {
    let _host = Cx::set_current(None);
    let source = causal_context(97, "source");
    let other_source = causal_context(97, "other-source");
    let initial_reader = causal_context(97, "initial-reader");
    let first_reader = causal_context(97, "first-reader");
    let second_reader = causal_context(97, "second-reader");
    let semaphore = Semaphore::new(2);
    let first_release = {
        let _current = Cx::set_current(Some(source.clone()));
        let held = semaphore.try_acquire(1).unwrap();
        let before = source.logical_tick();
        drop(held);
        before
    };
    let second_release = {
        let _current = Cx::set_current(Some(other_source.clone()));
        let before = other_source.logical_tick();
        semaphore.add_permits(1);
        before
    };
    for cx in [&initial_reader, &first_reader, &second_reader] {
        let _current = Cx::set_current(Some(cx.clone()));
        semaphore.try_acquire(1).unwrap().forget();
    }
    let initial_seen = initial_reader.logical_tick();
    let first_seen = first_reader.logical_tick();
    let second_seen = second_reader.logical_tick();
    assert_eq!(
        first_release.causal_order(&initial_seen),
        CausalOrder::Concurrent
    );
    assert_eq!(
        second_release.causal_order(&initial_seen),
        CausalOrder::Concurrent
    );
    assert_eq!(first_release.causal_order(&first_seen), CausalOrder::Before);
    assert_eq!(
        second_release.causal_order(&first_seen),
        CausalOrder::Concurrent
    );
    assert_eq!(
        first_release.causal_order(&second_seen),
        CausalOrder::Concurrent
    );
    assert_eq!(
        second_release.causal_order(&second_seen),
        CausalOrder::Before
    );
    assert_capacity_receipts(&semaphore);
}

#[test]
fn multi_acquire_joins_each_consumed_publication_only() {
    let _host = Cx::set_current(None);
    let a = causal_context(97, "a");
    let b = causal_context(97, "b");
    let untouched = causal_context(97, "untouched");
    let reader = causal_context(97, "reader");
    let semaphore = Semaphore::new(0);
    let mut snapshots = Vec::new();
    for cx in [&a, &b, &untouched] {
        let _current = Cx::set_current(Some(cx.clone()));
        snapshots.push(cx.logical_tick());
        semaphore.add_permits(1);
    }
    {
        let _current = Cx::set_current(Some(reader.clone()));
        block_on(semaphore.acquire_many(&reader, 2))
            .unwrap()
            .forget();
    }
    let observed = reader.logical_tick();
    assert_eq!(snapshots[0].causal_order(&observed), CausalOrder::Before);
    assert_eq!(snapshots[1].causal_order(&observed), CausalOrder::Before);
    assert_eq!(
        snapshots[2].causal_order(&observed),
        CausalOrder::Concurrent
    );
    assert_eq!(semaphore.available_permits(), 1);
    assert_capacity_receipts(&semaphore);
}

#[test]
fn owned_acquire_callback_panic_restores_original_receipt_and_wakes_successor() {
    struct PanicOnDrop;
    impl std::task::Wake for PanicOnDrop {
        fn wake(self: Arc<Self>) {}
    }
    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("planted semaphore causal waiter retirement panic");
        }
    }
    struct CountWakes(AtomicUsize);
    impl std::task::Wake for CountWakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let _host = Cx::set_current(None);
    let source = causal_context(97, "source");
    let failed = causal_context(97, "failed");
    let follower = causal_context(97, "follower");
    let semaphore = Arc::new(Semaphore::new(0));
    let mut first = OwnedAcquireFuture::new(Arc::clone(&semaphore), failed.clone(), 1);
    let mut second = OwnedAcquireFuture::new(Arc::clone(&semaphore), follower.clone(), 1);
    let panic_waker = Waker::from(Arc::new(PanicOnDrop));
    assert!(
        Pin::new(&mut first)
            .poll(&mut Context::from_waker(&panic_waker))
            .is_pending()
    );
    drop(panic_waker);
    let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
    let follower_waker = Waker::from(Arc::clone(&wakes));
    assert!(
        Pin::new(&mut second)
            .poll(&mut Context::from_waker(&follower_waker))
            .is_pending()
    );
    let published = {
        let _current = Cx::set_current(Some(source.clone()));
        let before = source.logical_tick();
        semaphore.add_permits(1);
        before
    };
    let failed_before = failed.logical_tick();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll_once(&mut first)));
    assert!(panic.is_err());
    assert_eq!(
        failed.logical_now(),
        failed_before,
        "no successful acquisition"
    );
    assert_eq!(semaphore.available_permits(), 1);
    assert_eq!(
        wakes.0.load(Ordering::SeqCst),
        1,
        "rollback wakes the parked successor"
    );
    let Poll::Ready(Ok(permit)) = poll_once(&mut second) else {
        panic!("successor must acquire the restored unit");
    };
    let seen = follower.logical_tick();
    assert_eq!(published.causal_order(&seen), CausalOrder::Before);
    assert_eq!(failed_before.causal_order(&seen), CausalOrder::Concurrent);
    permit.forget();
    assert_capacity_receipts(&semaphore);
}

#[test]
fn checked_admission_refusal_restores_each_producer_without_observing_or_publishing() {
    let _host = Cx::set_current(None);
    for asynchronous in [false, true] {
        let mut lab = LabRuntime::new(LabConfig::new(97).max_steps(128));
        let root = lab.state.create_root_region(Budget::INFINITE);
        assert!(lab.state.set_region_limits(
            root,
            crate::record::region::RegionLimits {
                max_obligations: Some(0),
                ..crate::record::region::RegionLimits::UNLIMITED
            },
        ));
        let (task, _handle) = lab
            .state
            .create_task(root, Budget::INFINITE, async {})
            .unwrap();
        let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
        let refused = cx
            .with_logical_clock(
                LogicalClockMode::Vector {
                    node: NodeId::new("refused"),
                }
                .build_handle(None),
            )
            .with_task_causality_runtime(Some(97));
        let source_a = causal_context(97, "source-a");
        let source_b = causal_context(97, "source-b");
        let semaphore = Semaphore::new(0);
        let mut sources = Vec::new();
        for source in [&source_a, &source_b] {
            let _current = Cx::set_current(Some(source.clone()));
            sources.push(source.logical_tick());
            semaphore.add_permits(1);
        }
        let before_refusal = refused.logical_tick();
        {
            let _current = Cx::set_current(Some(refused.clone()));
            let error = if asynchronous {
                block_on(semaphore.acquire_checked(&refused, 2)).unwrap_err()
            } else {
                semaphore.try_acquire_checked(&refused, 2).unwrap_err()
            };
            assert!(matches!(error, CheckedAcquireError::Admission(_)));
        }
        assert_eq!(refused.logical_now(), before_refusal);
        assert_eq!(semaphore.available_permits(), 2);
        for index in 0..2 {
            let reader = causal_context(97, &format!("reader-{index}"));
            let _current = Cx::set_current(Some(reader.clone()));
            semaphore.try_acquire(1).unwrap().forget();
            let seen = reader.logical_tick();
            assert_eq!(sources[index].causal_order(&seen), CausalOrder::Before);
            assert_eq!(
                sources[1 - index].causal_order(&seen),
                CausalOrder::Concurrent
            );
            assert_eq!(before_refusal.causal_order(&seen), CausalOrder::Concurrent);
        }
        assert_capacity_receipts(&semaphore);
        drop(lab);
    }
}

#[test]
fn actual_poller_and_returner_override_borrowed_context_and_foreign_runtimes() {
    let _host = Cx::set_current(None);
    let constructor = causal_context(97, "constructor");
    let source = causal_context(97, "source");
    let poller = causal_context(97, "poller");
    let returner = causal_context(97, "returner");
    let reader = causal_context(97, "reader");
    let semaphore = Arc::new(Semaphore::new(0));
    let published = {
        let _current = Cx::set_current(Some(source.clone()));
        let before = source.logical_tick();
        semaphore.add_permits(1);
        before
    };
    let constructor_before = constructor.logical_tick();
    let held = {
        let _current = Cx::set_current(Some(poller.clone()));
        block_on(OwnedSemaphorePermit::acquire_checked(
            Arc::clone(&semaphore),
            &constructor,
            1,
        ))
        .unwrap()
    };
    let poller_after = poller.logical_tick();
    assert_eq!(published.causal_order(&poller_after), CausalOrder::Before);
    assert_eq!(constructor.logical_now(), constructor_before);
    let returned = {
        let _current = Cx::set_current(Some(returner.clone()));
        let before = returner.logical_tick();
        drop(held);
        before
    };
    let returner_later = returner.logical_tick();
    {
        let _current = Cx::set_current(Some(reader.clone()));
        semaphore.try_acquire(1).unwrap().forget();
    }
    let observed = reader.logical_tick();
    assert_eq!(returned.causal_order(&observed), CausalOrder::Before);
    assert_eq!(
        returner_later.causal_order(&observed),
        CausalOrder::Concurrent
    );
    assert_eq!(
        poller_after.causal_order(&observed),
        CausalOrder::Concurrent
    );

    for observer in [causal_context(98, "other-runtime"), Cx::for_testing()] {
        {
            let _current = Cx::set_current(Some(source.clone()));
            semaphore.add_permits(1);
        }
        let before = observer.logical_now();
        {
            let _current = Cx::set_current(Some(observer.clone()));
            block_on(semaphore.acquire(&constructor, 1))
                .unwrap()
                .forget();
        }
        assert_eq!(observer.logical_now(), before);
        assert_eq!(constructor.logical_now(), constructor_before);
    }
}

#[test]
fn host_fallback_is_preserved_through_owned_conversion_but_not_ambient_escape() {
    let _host = Cx::set_current(None);
    for api in 0..4 {
        let source = causal_context(97, "source");
        let observer = causal_context(97, "observer");
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = match api {
            0 => block_on(OwnedSemaphorePermit::acquire(
                Arc::clone(&semaphore),
                &source,
                1,
            ))
            .unwrap(),
            1 => block_on(OwnedSemaphorePermit::acquire_checked(
                Arc::clone(&semaphore),
                &source,
                1,
            ))
            .unwrap(),
            2 => OwnedSemaphorePermit::try_acquire_checked(Arc::clone(&semaphore), &source, 1)
                .unwrap(),
            _ => OwnedSemaphorePermit::try_acquire_arc_checked(&semaphore, &source, 1).unwrap(),
        };
        let published = source.logical_tick();
        drop(permit);
        let later = source.logical_tick();
        block_on(semaphore.acquire(&observer, 1)).unwrap().forget();
        let seen = observer.logical_tick();
        assert_eq!(
            published.causal_order(&seen),
            CausalOrder::Before,
            "api={api}"
        );
        assert_eq!(
            later.causal_order(&seen),
            CausalOrder::Concurrent,
            "api={api}"
        );

        let escaped = {
            let _current = Cx::set_current(Some(source.clone()));
            semaphore.add_permits(1);
            OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap()
        };
        let source_later = source.logical_tick();
        drop(escaped);
        let unrelated = causal_context(97, "unrelated");
        block_on(semaphore.acquire(&unrelated, 1)).unwrap().forget();
        assert_eq!(
            source_later.causal_order(&unrelated.logical_tick()),
            CausalOrder::Concurrent
        );
        assert_capacity_receipts(&semaphore);
    }
}

#[test]
fn pending_cancelled_zero_forgotten_closed_and_diagnostic_paths_are_inert() {
    let _host = Cx::set_current(None);
    let source = causal_context(97, "source");
    let waiter = causal_context(97, "waiter");
    let semaphore = Semaphore::new(0);
    let mut wait = semaphore.acquire(&waiter, 2);
    assert!(poll_once(&mut wait).is_pending());
    let published = {
        let _current = Cx::set_current(Some(source.clone()));
        let before = source.logical_tick();
        semaphore.add_permits(1);
        before
    };
    let before = waiter.logical_now();
    assert!(poll_once(&mut wait).is_pending());
    assert_eq!(waiter.logical_now(), before);
    waiter.set_cancel_requested(true);
    assert!(matches!(
        poll_once(&mut wait),
        Poll::Ready(Err(AcquireError::Cancelled))
    ));
    assert_eq!(waiter.logical_now(), before);
    drop(wait);
    {
        let _current = Cx::set_current(Some(waiter.clone()));
        semaphore.try_acquire(0).unwrap().forget();
        let _ = semaphore.telemetry_snapshot(97);
        let _ = format!("{semaphore:?}");
    }
    assert_eq!(waiter.logical_now(), before);
    let reader = causal_context(97, "reader");
    let permit = block_on(semaphore.acquire(&reader, 1)).unwrap();
    assert_eq!(
        published.causal_order(&reader.logical_now()),
        CausalOrder::Before
    );
    permit.forget();
    assert_eq!(semaphore.available_permits(), 0);
    semaphore.close();
    {
        let _current = Cx::set_current(Some(source.clone()));
        semaphore.add_permits(1);
    }
    assert!(semaphore.state.lock().causality.is_none());
    let reader_before = reader.logical_now();
    assert!(matches!(
        block_on(semaphore.acquire(&reader, 1)),
        Err(AcquireError::Closed)
    ));
    assert_eq!(reader.logical_now(), reader_before);
}

#[test]
fn default_paths_do_not_allocate_causal_metadata_and_public_traits_remain() {
    fn semaphore_traits<T: Send + Sync + Unpin + std::panic::UnwindSafe>() {}
    semaphore_traits::<Semaphore>();
    let _host = Cx::set_current(None);
    let cx = Cx::for_testing();
    let semaphore = Arc::new(Semaphore::new(4));
    for api in 0..11 {
        let _current = Cx::set_current(Some(cx.clone()));
        acquire_and_forget(&semaphore, &cx, api, 1);
        semaphore.add_permits(1);
    }
    assert!(semaphore.state.lock().causality.is_none());
    let permit = block_on(semaphore.acquire(&cx, 1)).unwrap();
    assert!(permit.causal_owner.is_none());
    drop(permit);
    assert!(semaphore.state.lock().causality.is_none());
}

#[test]
fn saturating_release_and_rollback_keep_provenance_equal_to_capacity() {
    let _host = Cx::set_current(None);
    let source = causal_context(97, "source");
    let semaphore = Semaphore::new(usize::MAX - 1);
    {
        let _current = Cx::set_current(Some(source));
        semaphore.add_permits(10);
    }
    assert_capacity_receipts(&semaphore);
    assert_eq!(
        semaphore
            .state
            .lock()
            .causality
            .as_ref()
            .unwrap()
            .back()
            .unwrap()
            .count,
        1
    );
    let mut rollback = AcquisitionRollbackGuard::new(&semaphore, usize::MAX);
    {
        let mut state = semaphore.state.lock();
        rollback.publications = state.take_causality(usize::MAX);
        state.permits = 0;
        semaphore.permits_shadow.store(0, Ordering::Relaxed);
        rollback.arm();
    }
    semaphore.add_permits(usize::MAX - 1);
    drop(rollback);
    assert_eq!(semaphore.available_permits(), usize::MAX);
    assert_capacity_receipts(&semaphore);
    assert!(
        semaphore
            .state
            .lock()
            .causality
            .as_ref()
            .unwrap()
            .iter()
            .all(|batch| batch.publication.is_none())
    );
}

#[test]
fn admitted_lab_tasks_observe_semaphore_handoffs_deterministically() {
    fn run(seed: u64) -> (LogicalTime, LogicalTime, LogicalTime) {
        let _host = Cx::set_current(None);
        let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(seed).max_steps(128));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let semaphore = Arc::new(Semaphore::new(0));
        let reader_semaphore = Arc::clone(&semaphore);
        let (reader_id, mut reader) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let permit = reader_semaphore.acquire_checked(&cx, 1).await.unwrap();
                let observed = cx.logical_tick();
                drop(permit);
                observed
            })
            .unwrap();
        lab.scheduler.lock().schedule(reader_id, 0);
        lab.run_until_idle();
        assert_eq!(
            semaphore.telemetry_snapshot(97).waiter_count,
            1,
            "reader really parked before release"
        );
        let writer_semaphore = Arc::clone(&semaphore);
        let (writer_id, mut writer) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let published = cx.logical_tick();
                writer_semaphore.add_permits(1);
                let later = cx.logical_tick();
                (published, later)
            })
            .unwrap();
        lab.scheduler.lock().schedule(writer_id, 0);
        lab.run_until_idle();
        let observed = reader.try_join().unwrap().unwrap();
        let (published, later) = writer.try_join().unwrap().unwrap();
        assert_eq!(published.causal_order(&observed), CausalOrder::Before);
        assert_eq!(later.causal_order(&observed), CausalOrder::Concurrent);
        assert_eq!(semaphore.telemetry_snapshot(97).waiter_count, 0);
        assert_eq!(semaphore.available_permits(), 1);
        lab.run_until_quiescent();
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        (published, later, observed)
    }
    for seed in [97, 0x5e_a0, 0x5e_a1] {
        assert_eq!(run(seed), run(seed));
    }
}
