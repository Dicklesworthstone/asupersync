    #![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

    use super::*;
    use crate::lab::run_async_under_lab;
    use crate::runtime::yield_now;
    #[cfg(not(target_arch = "wasm32"))]
    use crate::runtime::RuntimeBuilder;
    use crate::stream::iter;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn ordered(cx: Cx) {
        let completed = Arc::new(AtomicUsize::new(0));
        let child_completed = Arc::clone(&completed);
        let outcome = map_collect_concurrent(&cx, iter(0..4), 4, move |_child, index| {
            let completed = Arc::clone(&child_completed);
            async move {
                if index == 0 {
                    while completed.load(Ordering::SeqCst) < 3 {
                        yield_now().await;
                    }
                } else {
                    completed.fetch_add(1, Ordering::SeqCst);
                }
                Box::new(index * 10)
            }
        }).await;
        let Outcome::Ok(values) = outcome else { panic!("maps must succeed") };
        assert_eq!(completed.load(Ordering::SeqCst), 3, "later inputs finished first");
        assert_eq!(values.into_iter().map(|value| *value).collect::<Vec<_>>(), [0, 10, 20, 30]);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn collection_restores_order_after_out_of_order_native_completions() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            ordered(Cx::current().expect("native parent context")).await;
        }));
    }

    #[test]
    fn collection_restores_order_under_lab_schedules() {
        for seed in [0xC011, 0xC012, 0xC013] {
            let ((), report) = run_async_under_lab(seed, ordered);
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    fn collection_bounds_overlapping_work_and_visits_each_input_once() {
        let ((), report) = run_async_under_lab(0xC014, |cx| async move {
            let running = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let seen: Arc<Vec<AtomicUsize>> = Arc::new((0..24).map(|_| AtomicUsize::new(0)).collect());
            let factory_running = Arc::clone(&running);
            let factory_peak = Arc::clone(&peak);
            let factory_seen = Arc::clone(&seen);
            let outcome = map_collect_concurrent(&cx, iter(0..24), 3, move |_child, index| {
                let running = Arc::clone(&factory_running);
                let peak = Arc::clone(&factory_peak);
                let seen = Arc::clone(&factory_seen);
                async move {
                    let live = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(live, Ordering::SeqCst);
                    seen[index].fetch_add(1, Ordering::SeqCst);
                    yield_now().await;
                    yield_now().await;
                    running.fetch_sub(1, Ordering::SeqCst);
                    index
                }
            }).await;
            assert!(matches!(outcome, Outcome::Ok(values) if values == (0..24).collect::<Vec<_>>()));
            assert_eq!(running.load(Ordering::SeqCst), 0);
            assert!((2..=3).contains(&peak.load(Ordering::SeqCst)), "real bounded overlap");
            assert!(seen.iter().all(|count| count.load(Ordering::SeqCst) == 1));
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    fn collection_accepts_non_clone_values() {
        struct NotClone(usize);
        let ((), report) = run_async_under_lab(0xC015, |cx| async move {
            let source = iter([NotClone(7), NotClone(9)]);
            let outcome = map_collect_concurrent(&cx, source, 2, |_child, value| async move { value }).await;
            let Outcome::Ok(values) = outcome else { panic!("maps must succeed") };
            assert_eq!(values.iter().map(|value| value.0).collect::<Vec<_>>(), [7, 9]);
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    fn collection_accepts_borrowed_non_send_source_and_reports_missing_runtime() {
        let cx = Cx::for_testing();
        let local = std::rc::Rc::new(std::cell::Cell::new(0));
        let source = iter([7]).inspect(|_| local.set(local.get() + 1));
        let mut work = Box::pin(map_collect_concurrent(&cx, source, 1,
            |_child, value| async move { value }));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(work.as_mut().poll(&mut task), std::task::Poll::Ready(Outcome::Panicked(_))));
        drop(work);
        assert_eq!(local.get(), 1, "source was polled without adding Send or static bounds");
    }

    #[test]
    fn collection_empty_input_has_no_factory_calls_and_zero_limit_is_rejected() {
        async fn unexpected(_child: Cx, _item: u8) -> u8 {
            panic!("empty source must not spawn")
        }
        let cx = Cx::for_testing();
        let mut empty = Box::pin(map_collect_concurrent(&cx, iter([] as [u8; 0]), 1, unexpected));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(empty.as_mut().poll(&mut task), std::task::Poll::Ready(Outcome::Ok(values)) if values.is_empty()));
        let mut zero = Box::pin(map_collect_concurrent(&cx, iter([1]), 0, |_child, item| async move { item }));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| zero.as_mut().poll(&mut task))).is_err());
    }

    #[test]
    fn collection_failure_drains_parked_members_and_drops_completed_values() {
        struct Value(Arc<AtomicUsize>);
        impl Drop for Value {
            fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        let ((), report) = run_async_under_lab(0xC016, |cx| async move {
            let started = Arc::new(AtomicUsize::new(0));
            let cleaned = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let outer_cleaned = Arc::clone(&cleaned);
            let outer_drops = Arc::clone(&drops);
            let outcome = try_map_collect_concurrent(&cx, iter(0..4), 4, move |child, index| {
                let started = Arc::clone(&started);
                let cleaned = Arc::clone(&cleaned);
                let drops = Arc::clone(&drops);
                async move {
                    if index == 0 {
                        while started.load(Ordering::SeqCst) < 3 { yield_now().await; }
                        // Let the successful item leave its value in the collector.
                        yield_now().await;
                        return Err("map failed");
                    }
                    started.fetch_add(1, Ordering::SeqCst);
                    if index == 1 { return Ok(Value(drops)); }
                    child.cancelled().await;
                    yield_now().await;
                    cleaned.fetch_add(1, Ordering::SeqCst);
                    Err("drained")
                }
            }).await;
            assert!(matches!(outcome, Outcome::Err("map failed")));
            assert_eq!(outer_cleaned.load(Ordering::SeqCst), 2, "observed before parent region close");
            assert_eq!(outer_drops.load(Ordering::SeqCst), 1, "completed output was retired");
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }
