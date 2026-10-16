    #![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

    use super::*;
    use crate::channel::mpsc;
    use crate::combinator::try_map_collect_concurrent;
    use crate::lab::run_async_under_lab;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    #[derive(Clone, Copy)]
    enum Fault {
        Source,
        FactoryClone,
        PayloadDrop,
    }

    #[derive(Default)]
    struct Signal {
        holding: AtomicBool,
        waker: Mutex<Option<Waker>>,
        source_failures: AtomicUsize,
        payload_drops: AtomicUsize,
    }

    struct HostilePayload(Arc<Signal>);

    impl Drop for HostilePayload {
        fn drop(&mut self) {
            self.0.payload_drops.fetch_add(1, Ordering::SeqCst);
            panic!("secondary panic while retiring source payload");
        }
    }

    struct Source {
        phase: u8,
        signal: Arc<Signal>,
        fault: Fault,
    }

    impl Stream for Source {
        type Item = u8;

        fn poll_next(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<u8>> {
            if self.phase == 0 {
                self.phase = 1;
                return Poll::Ready(Some(0));
            }
            if self.phase == 2 {
                return Poll::Ready(None);
            }
            // The failure is armed only AFTER the first child owns its checked
            // send permit. No source event or spin rescues the child later.
            let incoming = task.waker().clone();
            let mut registered = self.signal.waker.lock();
            if !self.signal.holding.load(Ordering::SeqCst) {
                let retired = registered.replace(incoming);
                drop(registered);
                drop(retired);
                return Poll::Pending;
            }
            drop(registered);
            drop(incoming);
            match self.fault {
                Fault::Source => {
                    self.signal.source_failures.fetch_add(1, Ordering::SeqCst);
                    panic!("source poll panic");
                }
                Fault::PayloadDrop => {
                    self.signal.source_failures.fetch_add(1, Ordering::SeqCst);
                    std::panic::panic_any(HostilePayload(Arc::clone(&self.signal)));
                }
                Fault::FactoryClone => {
                    self.phase = 2;
                    Poll::Ready(Some(1))
                }
            }
        }
    }

    struct CloneBomb {
        calls: Arc<AtomicUsize>,
        armed: bool,
    }

    impl Clone for CloneBomb {
        fn clone(&self) -> Self {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.armed && index == 1 {
                panic!("factory clone panic");
            }
            Self { calls: Arc::clone(&self.calls), armed: self.armed }
        }
    }

    impl CloneBomb {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    fn panic_message<T, E>(outcome: Outcome<T, E>) -> String {
        match outcome {
            Outcome::Panicked(payload) => format!("{payload:?}"),
            _ => panic!("admission failure must be reported as Panicked"),
        }
    }

    async fn journey(cx: Cx, fault: Fault, collect: bool, cleanup_panics: bool) {
        let signal = Arc::new(Signal::default());
        let cleaned = Arc::new(AtomicUsize::new(0));
        let clones = Arc::new(AtomicUsize::new(0));
        let source = Source { phase: 0, signal: Arc::clone(&signal), fault };
        let (sender, mut receiver) = mpsc::channel::<u8>(1);
        let child_sender = sender.clone();
        let child_signal = Arc::clone(&signal);
        let child_cleaned = Arc::clone(&cleaned);
        let bomb = CloneBomb { calls: Arc::clone(&clones), armed: matches!(fault, Fault::FactoryClone) };
        let factory = move |child: Cx, item| {
            // Capture the complete CloneBomb, not just one of its fields.
            assert!(bomb.calls() > 0);
            assert_eq!(item, 0, "no item may be admitted after the armed failure");
            let sender = child_sender.clone();
            let signal = Arc::clone(&child_signal);
            let cleaned = Arc::clone(&child_cleaned);
            async move {
                let permit = sender.reserve_checked(&child).await.unwrap();
                signal.holding.store(true, Ordering::SeqCst);
                let wake = signal.waker.lock().take();
                if let Some(wake) = wake { wake.wake(); }
                child.cancelled().await;
                assert!(child.checkpoint().is_err());
                // Cleanup is asynchronous: abort-and-return without joining
                // cannot satisfy the counter and capacity assertions below.
                yield_now().await;
                yield_now().await;
                drop(permit);
                cleaned.fetch_add(1, Ordering::SeqCst);
                if cleanup_panics { panic!("cleanup panic wins"); }
                Err::<(), _>("child drained")
            }
        };
        let message = if collect {
            panic_message(try_map_collect_concurrent(&cx, source, 2, factory).await)
        } else {
            panic_message(try_for_each_concurrent(&cx, source, 2, factory).await)
        };
        assert!(signal.holding.load(Ordering::SeqCst));
        assert_eq!(cleaned.load(Ordering::SeqCst), 1, "checked before parent region teardown");
        assert!(matches!(receiver.try_recv(), Err(mpsc::RecvError::Empty)));
        assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        sender.try_reserve().expect("the child's capacity was returned").abort();
        let expected = if cleanup_panics {
            "cleanup panic wins"
        } else {
            match fault {
                Fault::Source => "source poll panic",
                Fault::FactoryClone => "factory clone panic",
                Fault::PayloadDrop => "non-string payload",
            }
        };
        assert!(message.contains(expected), "{message}");
        assert_eq!(clones.load(Ordering::SeqCst), if matches!(fault, Fault::FactoryClone) { 2 } else { 1 });
        assert_eq!(signal.source_failures.load(Ordering::SeqCst), usize::from(!matches!(fault, Fault::FactoryClone)));
        assert_eq!(signal.payload_drops.load(Ordering::SeqCst), usize::from(matches!(fault, Fault::PayloadDrop)));
    }

    #[test]
    fn source_and_factory_panics_drain_checked_members_in_lab() {
        for fault in [Fault::Source, Fault::FactoryClone, Fault::PayloadDrop] {
            for collect in [false, true] {
                let ((), report) = run_async_under_lab(0xC020, move |cx| journey(cx, fault, collect, false));
                assert!(report.quiescent && report.invariant_violations.is_empty());
            }
        }
    }

    #[test]
    fn cleanup_panic_takes_precedence_after_admission_panic() {
        for collect in [false, true] {
            let ((), report) = run_async_under_lab(0xC021, move |cx| journey(cx, Fault::Source, collect, true));
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn source_and_factory_panics_drain_checked_members_on_native_runtime() {
        for fault in [Fault::Source, Fault::FactoryClone, Fault::PayloadDrop] {
            for collect in [false, true] {
                let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
                runtime.block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("native parent context");
                    journey(cx, fault, collect, false).await;
                }));
            }
        }
    }
