//! Actual publication and observation regressions for br-asupersync-bi2462.97.

use super::*;
use crate::lab::{LabConfig, LabRuntime};
use crate::remote::NodeId;
use crate::trace::distributed::{CausalOrder, LogicalClockMode, VectorClock};
use crate::trace::{TraceData, TraceEvent};
use crate::types::{Budget, CancelKind};
use futures_lite::future::{block_on, pending};
use std::sync::Arc;

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

fn poll_once<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn every_publication_and_value_access_uses_a_fixed_snapshot() {
    let _host = Cx::set_current(None);
    for publisher in 0..8 {
        for reader in 0..9 {
            let source = causal_context(97, "source");
            let observer = causal_context(97, "observer");
            let published = source.logical_tick();
            let mut cell = {
                let _current = Cx::set_current(Some(source.clone()));
                let cell = OnceCell::new();
                match publisher {
                    0 => OnceCell::with_value(41_u32),
                    1 => {
                        assert_eq!(cell.set(41), Ok(()));
                        cell
                    }
                    2 => {
                        assert_eq!(cell.get_or_init_blocking(|| 41), &41);
                        cell
                    }
                    3 => {
                        assert_eq!(block_on(cell.get_or_init(|| async { 41 })), &41);
                        cell
                    }
                    4 => {
                        assert_eq!(
                            block_on(cell.get_or_try_init(|| async { Ok::<_, ()>(41) })),
                            Ok(&41)
                        );
                        cell
                    }
                    5 => {
                        assert_eq!(
                            block_on(cell.get_or_init_cx(&source, || async { 41 })),
                            Ok(&41)
                        );
                        cell
                    }
                    6 => {
                        assert_eq!(
                            block_on(
                                cell.get_or_try_init_cx(&source, || async { Ok::<_, ()>(41) })
                            ),
                            Ok(Ok(&41))
                        );
                        cell
                    }
                    _ => OnceCell::from(41),
                }
            };
            let after_publication = source.logical_tick();
            {
                let _current = Cx::set_current(Some(observer.clone()));
                match reader {
                    0 => assert_eq!(cell.get(), Some(&41)),
                    1 => assert_eq!(cell.get_or_init_blocking(|| panic!("already set")), &41),
                    2 => assert_eq!(
                        block_on(cell.get_or_init(|| async { panic!("already set") })),
                        &41
                    ),
                    3 => assert_eq!(
                        block_on(cell.get_or_try_init(|| async { Err::<u32, _>(()) })),
                        Ok(&41)
                    ),
                    4 => assert_eq!(
                        block_on(
                            cell.get_or_init_cx(&observer, || async { panic!("already set") })
                        ),
                        Ok(&41)
                    ),
                    5 => assert_eq!(
                        block_on(
                            cell.get_or_try_init_cx(&observer, || async { Err::<u32, _>(()) })
                        ),
                        Ok(Ok(&41))
                    ),
                    6 => assert_eq!(block_on(cell.wait(&observer)), Ok(())),
                    7 => assert_eq!(cell.take(), Some(41)),
                    _ => assert_eq!(cell.into_inner(), Some(41)),
                }
            }
            let observed = observer.logical_tick();
            assert_eq!(
                published.causal_order(&observed),
                CausalOrder::Before,
                "publisher={publisher} reader={reader}"
            );
            assert_eq!(
                after_publication.causal_order(&observed),
                CausalOrder::Concurrent,
                "publisher={publisher} reader={reader}: later source work leaked"
            );
            assert_eq!(source.logical_now(), after_publication);
        }
    }
}

#[test]
fn explicit_contexts_follow_the_actual_poller_and_fence_other_runtimes() {
    let _host = Cx::set_current(None);
    for fallible in [false, true] {
        let constructor = causal_context(97, "constructor");
        let source = causal_context(97, "source");
        let observer = causal_context(97, "observer");
        let constructor_before = constructor.logical_tick();
        let published = source.logical_tick();
        let cell = OnceCell::new();
        {
            let _current = Cx::set_current(Some(source.clone()));
            if fallible {
                assert_eq!(
                    block_on(cell.get_or_try_init_cx(&constructor, || async { Ok::<_, ()>(41) })),
                    Ok(Ok(&41))
                );
            } else {
                assert_eq!(
                    block_on(cell.get_or_init_cx(&constructor, || async { 41 })),
                    Ok(&41)
                );
            }
        }
        let source_after = source.logical_tick();
        {
            let _current = Cx::set_current(Some(observer.clone()));
            assert_eq!(block_on(cell.wait(&constructor)), Ok(()));
        }
        let observed = observer.logical_tick();
        assert_eq!(published.causal_order(&observed), CausalOrder::Before);
        assert_eq!(
            source_after.causal_order(&observed),
            CausalOrder::Concurrent
        );
        assert_eq!(
            constructor_before.causal_order(&observed),
            CausalOrder::Concurrent
        );
        assert_eq!(constructor.logical_now(), constructor_before);

        for actual in [Cx::for_testing(), causal_context(98, "source")] {
            let before = actual.logical_now();
            {
                let _current = Cx::set_current(Some(actual.clone()));
                assert_eq!(block_on(cell.wait(&constructor)), Ok(()));
                assert_eq!(
                    block_on(cell.get_or_init_cx(&constructor, || async { 0 })),
                    Ok(&41)
                );
            }
            assert_eq!(actual.logical_now(), before, "foreign or disabled poller");
            assert_eq!(
                constructor.logical_now(),
                constructor_before,
                "no fallback under a task"
            );
        }

        // Off-task polling still has an explicit source of attribution.
        assert_eq!(block_on(cell.wait(&constructor)), Ok(()));
        assert_eq!(
            published.causal_order(&constructor.logical_now()),
            CausalOrder::Before
        );

        let host_source = causal_context(97, "host-source");
        let host_published = host_source.logical_tick();
        let host_cell = OnceCell::new();
        assert_eq!(
            block_on(host_cell.get_or_init_cx(&host_source, || async { 7 })),
            Ok(&7)
        );
        let host_observer = causal_context(97, "host-observer");
        assert_eq!(block_on(host_cell.wait(&host_observer)), Ok(()));
        assert_eq!(
            host_published.causal_order(&host_observer.logical_now()),
            CausalOrder::Before
        );

        let untracked = OnceCell::new();
        {
            let _current = Cx::set_current(Some(Cx::for_testing()));
            assert_eq!(
                block_on(untracked.get_or_init_cx(&host_source, || async { 11 })),
                Ok(&11)
            );
        }
        assert!(
            untracked.publication.get().is_none(),
            "untracked actual initializer"
        );
        let before = host_observer.logical_now();
        assert_eq!(block_on(untracked.wait(&host_observer)), Ok(()));
        assert_eq!(host_observer.logical_now(), before);
    }
}

#[test]
fn unsuccessful_initialization_and_cancelled_waits_do_not_publish_value_edges() {
    let _host = Cx::set_current(None);
    let source = causal_context(97, "failed-source");
    let observer = causal_context(97, "retrying-observer");
    let failed = source.logical_tick();
    let cell = OnceCell::<u32>::new();
    assert_eq!(
        block_on(cell.get_or_try_init_cx(&source, || async { Err::<u32, _>("failed") })),
        Ok(Err("failed"))
    );
    assert!(cell.publication.get().is_none());
    assert!(!cell.is_initialized());

    let mut initializer = Box::pin(cell.get_or_init_cx(&source, pending::<u32>));
    assert!(poll_once(initializer.as_mut()).is_pending());
    let mut waiter = Box::pin(cell.get_or_init_cx(&observer, || async { 41 }));
    let before_wait = observer.logical_now();
    assert!(poll_once(waiter.as_mut()).is_pending());
    assert_eq!(observer.logical_now(), before_wait);
    drop(initializer);
    assert!(cell.publication.get().is_none());
    assert_eq!(poll_once(waiter.as_mut()), Poll::Ready(Ok(&41)));
    drop(waiter);
    let retried = observer.logical_tick();
    assert_eq!(failed.causal_order(&retried), CausalOrder::Concurrent);

    let waiting = causal_context(97, "cancelled-waiter");
    let fresh = OnceCell::new();
    let mut wait = Box::pin(fresh.wait(&waiting));
    assert!(poll_once(wait.as_mut()).is_pending());
    let before_cancel = waiting.logical_now();
    waiting.cancel_fast(CancelKind::User);
    assert_eq!(
        poll_once(wait.as_mut()),
        Poll::Ready(Err(OnceCellError::Cancelled))
    );
    drop(wait);
    assert_eq!(waiting.logical_now(), before_cancel);
    assert!(fresh.waiters.lock().unwrap().waiters.is_empty());
    assert_eq!(
        block_on(fresh.get_or_init_cx(&waiting, || async { panic!("cancelled") })),
        Err(OnceCellError::Cancelled)
    );
    assert!(fresh.publication.get().is_none());
    assert_eq!(
        block_on(fresh.get_or_init_cx(&source, || async { 7 })),
        Ok(&7)
    );
    assert_eq!(
        waiting.logical_now(),
        before_cancel,
        "retired waiter received no publication"
    );
}

#[test]
fn probes_failed_sets_and_take_reset_cannot_republish_stale_evidence() {
    let _host = Cx::set_current(None);
    let source = causal_context(97, "source");
    let contender = causal_context(97, "contender");
    let published = source.logical_tick();
    let mut cell = {
        let _current = Cx::set_current(Some(source));
        OnceCell::with_value(41)
    };
    let before = contender.logical_tick();
    {
        let _current = Cx::set_current(Some(contender.clone()));
        assert!(cell.is_initialized());
        assert!(cell.telemetry_snapshot(97).closed);
        assert_eq!(format!("{cell:?}"), "OnceCell { value: 41 }");
        assert_eq!(
            contender.logical_now(),
            before,
            "diagnostics imported publication"
        );
        assert_eq!(cell.set(99), Err(99));
        assert_eq!(OnceCell::<u32>::new().get(), None);
    }
    assert_eq!(contender.logical_now(), before, "no successful observation");
    let reader = causal_context(97, "reader");
    {
        let _current = Cx::set_current(Some(reader.clone()));
        assert_eq!(cell.get(), Some(&41));
    }
    let observed = reader.logical_now();
    assert_eq!(published.causal_order(&observed), CausalOrder::Before);
    assert_eq!(
        before.causal_order(&observed),
        CausalOrder::Concurrent,
        "failed set replaced the source"
    );

    // Exclusive reset by an unattributed host cannot make the old task the
    // source of a later, unrelated host initialization.
    assert_eq!(cell.take(), Some(41));
    assert!(cell.publication.get().is_none());
    assert_eq!(cell.set(7), Ok(()));
    assert!(cell.publication.get().is_none());
    {
        let _current = Cx::set_current(Some(contender.clone()));
        assert_eq!(cell.get(), Some(&7));
    }
    assert_eq!(contender.logical_now(), before);
    let after = contender.logical_tick();
    assert_eq!(published.causal_order(&after), CausalOrder::Concurrent);

    let legacy = Cx::for_testing();
    let before = legacy.logical_now();
    {
        let _current = Cx::set_current(Some(legacy.clone()));
        let legacy_cell = OnceCell::with_value(());
        assert_eq!(legacy_cell.get(), Some(&()));
        assert_eq!(block_on(legacy_cell.wait(&legacy)), Ok(()));
        assert!(legacy_cell.publication.get().is_none());
    }
    assert_eq!(legacy.logical_now(), before);
}

#[test]
fn publication_survives_clock_overflow_and_failed_observation() {
    let _host = Cx::set_current(None);
    let source = causal_context(97, "source");
    let exhausted = causal_context(97, "exhausted");
    for (cx, node) in [(&source, "source"), (&exhausted, "exhausted")] {
        let mut time = VectorClock::new();
        time.set(&NodeId::new(node), u64::MAX - 1);
        let _ = cx.logical_receive(&LogicalTime::Vector(time));
    }
    let cell = OnceCell::new();
    let mut wait = Box::pin(cell.wait(&exhausted));
    assert!(poll_once(wait.as_mut()).is_pending());
    {
        let _current = Cx::set_current(Some(source.clone()));
        assert_eq!(cell.set(41), Ok(()), "publication does not tick the source");
    }
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = poll_once(wait.as_mut());
        }))
        .is_err()
    );
    drop(wait);
    assert!(cell.is_initialized());
    assert!(cell.waiters.lock().unwrap().waiters.is_empty());
    let observer = causal_context(97, "observer");
    assert_eq!(block_on(cell.wait(&observer)), Ok(()));
    assert_eq!(
        source.logical_now().causal_order(&observer.logical_now()),
        CausalOrder::Before
    );
    assert_eq!(cell.into_inner(), Some(41));
}

fn message_time(events: &[TraceEvent], message: &str) -> LogicalTime {
    events
        .iter()
        .find(|event| matches!(&event.data, TraceData::Message(text) if text == message))
        .and_then(|event| event.logical_time.clone())
        .unwrap_or_else(|| panic!("missing logical timestamp for {message}"))
}

fn initialization_trace(waiters_parked: bool) -> Vec<TraceEvent> {
    let _host = Cx::set_current(None);
    let mut lab = LabRuntime::new_with_task_causality(LabConfig::new(97).max_steps(128));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let cell = Arc::new(OnceCell::new());
    let (release, mut gate) = crate::channel::oneshot::channel::<()>();
    let source_cell = Arc::clone(&cell);
    let (initializer, _join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().unwrap();
            assert_eq!(
                source_cell
                    .get_or_init_cx(&cx, || async {
                        if waiters_parked {
                            gate.recv(&cx).await.unwrap();
                        }
                        cx.trace("once-published");
                        41
                    })
                    .await,
                Ok(&41)
            );
            cx.trace("once-source-after");
        })
        .unwrap();
    lab.scheduler.lock().schedule(initializer, 0);
    lab.step_for_test();

    for name in ["once-read", "once-waited"] {
        let reader_cell = Arc::clone(&cell);
        let (reader, _join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                if name == "once-read" {
                    assert_eq!(
                        reader_cell
                            .get_or_init(|| async { panic!("already initializing") })
                            .await,
                        &41
                    );
                } else {
                    reader_cell.wait(&cx).await.unwrap();
                }
                cx.trace(name);
            })
            .unwrap();
        lab.scheduler.lock().schedule(reader, 0);
        lab.step_for_test();
        if waiters_parked {
            assert!(lab.state.task(reader).is_some(), "reader must be parked");
        }
    }
    if waiters_parked {
        release.send_blocking(()).unwrap();
    }
    lab.run_until_idle();
    assert!(lab.is_quiescent());
    lab.trace().snapshot()
}

#[test]
fn lab_initialization_orders_value_readers_without_ordering_them_to_each_other() {
    for waiters_parked in [false, true] {
        let events = initialization_trace(waiters_parked);
        let published = message_time(&events, "once-published");
        let late = message_time(&events, "once-source-after");
        let read = message_time(&events, "once-read");
        let waited = message_time(&events, "once-waited");
        for observed in [&read, &waited] {
            assert_eq!(published.causal_order(observed), CausalOrder::Before);
            assert_eq!(late.causal_order(observed), CausalOrder::Concurrent);
        }
        assert_eq!(read.causal_order(&waited), CausalOrder::Concurrent);
        let repeated = initialization_trace(waiters_parked);
        assert_eq!(read, message_time(&repeated, "once-read"));
        assert_eq!(waited, message_time(&repeated, "once-waited"));
    }
}

#[test]
fn publication_preserves_once_cell_auto_traits() {
    fn assert_traits<
        T: Send + Sync + Unpin + std::panic::UnwindSafe + std::panic::RefUnwindSafe,
    >() {
    }
    fn assert_unwind_safe<T: std::panic::UnwindSafe>() {}
    assert_traits::<OnceCell<()>>();
    assert_traits::<&OnceCell<()>>();
    assert_traits::<WaitInit<'static, ()>>();
    assert_unwind_safe::<OnceCell<std::cell::Cell<()>>>();
}
