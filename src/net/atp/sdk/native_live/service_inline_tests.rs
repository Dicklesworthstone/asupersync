    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    #[test]
    fn stop_can_escalate_but_never_downgrade_or_replace_the_first_reason() {
        let control = LiveStreamServiceControl::default();
        assert!(!control.is_stopping());
        control.stop();
        let first = CancelReason::user("first");
        control.cancel(first.clone());
        control.stop();
        control.cancel(CancelReason::user("second"));
        assert!(matches!(control.snapshot(), StopRequest::Abort(reason) if reason == first));
    }

    #[test]
    fn idle_stop_wakes_outside_the_control_lock() {
        struct Probe(LiveStreamServiceControl, AtomicUsize);
        impl Wake for Probe {
            fn wake(self: Arc<Self>) {
                assert!(self.0.is_stopping());
                self.1.fetch_add(1, Ordering::SeqCst);
            }
        }
        let control = LiveStreamServiceControl::default();
        let probe = Arc::new(Probe(control.clone(), AtomicUsize::new(0)));
        control.register(&Waker::from(Arc::clone(&probe)));
        control.stop();
        assert_eq!(probe.1.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn capacity_remains_held_by_a_worker_after_the_manager_owner_drops() {
        let admission = Arc::new(super::super::Admission {
            active: AtomicUsize::new(0),
            capacity: 2,
        });
        let capacity = Arc::new(Capacity {
            _permits: vec![admission.reserve().unwrap(), admission.reserve().unwrap()],
        });
        let worker = Arc::clone(&capacity);
        drop(capacity);
        assert!(matches!(
            admission.reserve(),
            Err(LiveStreamError::Capacity)
        ));
        drop(worker);
        assert_eq!(admission.active.load(Ordering::Relaxed), 0);
    }
