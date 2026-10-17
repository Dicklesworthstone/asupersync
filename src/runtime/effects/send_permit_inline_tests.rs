    use super::*;
    use std::panic::AssertUnwindSafe;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_permit_commit() {
        let committed = Arc::new(Mutex::new(Vec::new()));
        let committed_clone = Arc::clone(&committed);
        let aborted = Arc::new(Mutex::new(false));
        let aborted_clone = Arc::clone(&aborted);

        let permit = SendPermit::new(
            move |data: &[u8]| {
                committed_clone.lock().unwrap().extend_from_slice(data);
                Ok::<(), ()>(())
            },
            move || {
                *aborted_clone.lock().unwrap() = true;
            },
        );

        assert!(permit.commit(b"test data").is_ok());
        assert_eq!(*committed.lock().unwrap(), b"test data");
        assert!(!*aborted.lock().unwrap());
    }

    #[test]
    fn test_permit_abort() {
        let committed = Arc::new(Mutex::new(Vec::new()));
        let committed_clone = Arc::clone(&committed);
        let aborted = Arc::new(Mutex::new(false));
        let aborted_clone = Arc::clone(&aborted);

        let permit = SendPermit::new(
            move |data: &[u8]| {
                committed_clone.lock().unwrap().extend_from_slice(data);
                Ok::<(), ()>(())
            },
            move || {
                *aborted_clone.lock().unwrap() = true;
            },
        );

        permit.abort();
        assert!(committed.lock().unwrap().is_empty());
        assert!(*aborted.lock().unwrap());
    }

    #[test]
    fn test_permit_commit_error_aborts_reservation() {
        let abort_count = Arc::new(Mutex::new(0usize));
        let abort_count_clone = Arc::clone(&abort_count);

        let permit = SendPermit::new(
            move |data: &[u8]| {
                assert_eq!(data, b"too large");
                Err::<(), &'static str>("send queue rejected commit")
            },
            move || {
                *abort_count_clone.lock().unwrap() += 1;
            },
        );

        assert_eq!(
            permit.commit(b"too large"),
            Err("send queue rejected commit")
        );
        assert_eq!(*abort_count.lock().unwrap(), 1);
    }

    #[test]
    fn test_permit_drop_aborts() {
        let committed = Arc::new(Mutex::new(Vec::new()));
        let committed_clone = Arc::clone(&committed);
        let aborted = Arc::new(Mutex::new(false));
        let aborted_clone = Arc::clone(&aborted);

        {
            let _permit = SendPermit::new(
                move |data: &[u8]| {
                    committed_clone.lock().unwrap().extend_from_slice(data);
                    Ok::<(), ()>(())
                },
                move || {
                    *aborted_clone.lock().unwrap() = true;
                },
            );
            // permit dropped here
        }

        assert!(committed.lock().unwrap().is_empty());
        assert!(*aborted.lock().unwrap());
    }

    #[derive(Default)]
    struct ProbeState {
        abort_calls: AtomicUsize,
        commit_calls: AtomicUsize,
        capture_drops: AtomicUsize,
        aborts_seen_on_drop: AtomicUsize,
    }

    struct CommitCapture {
        state: Arc<ProbeState>,
        panic_on_drop: bool,
    }

    impl Drop for CommitCapture {
        fn drop(&mut self) {
            self.state.aborts_seen_on_drop.store(
                self.state.abort_calls.load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
            self.state.capture_drops.fetch_add(1, Ordering::SeqCst);
            assert!(!self.panic_on_drop, "unused commit capture panic");
        }
    }

    fn probe_permit(
        state: &Arc<ProbeState>,
        capture_panics: bool,
        abort_panics: bool,
    ) -> SendPermit<()> {
        let capture = CommitCapture {
            state: Arc::clone(state),
            panic_on_drop: capture_panics,
        };
        let commit_state = Arc::clone(state);
        let abort_state = Arc::clone(state);
        SendPermit::new(
            move |_| {
                commit_state.commit_calls.fetch_add(1, Ordering::SeqCst);
                drop(capture);
                Ok(())
            },
            move || {
                abort_state.abort_calls.fetch_add(1, Ordering::SeqCst);
                assert!(!abort_panics, "abort callback panic");
            },
        )
    }

    fn assert_rollback_before_retirement(state: &ProbeState) {
        assert_eq!(state.abort_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.commit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.capture_drops.load(Ordering::SeqCst), 1);
        assert_eq!(state.aborts_seen_on_drop.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn explicit_abort_releases_reservation_before_unused_capture_drop() {
        let state = Arc::new(ProbeState::default());
        probe_permit(&state, false, false).abort();
        assert_rollback_before_retirement(&state);
    }

    #[test]
    fn explicit_abort_releases_reservation_when_unused_capture_drop_panics() {
        let state = Arc::new(ProbeState::default());
        let failed = std::panic::catch_unwind(AssertUnwindSafe(|| {
            probe_permit(&state, true, false).abort();
        }));
        assert!(failed.is_err(), "capture panic must still propagate");
        assert_rollback_before_retirement(&state);
    }

    #[test]
    fn implicit_drop_releases_reservation_when_unused_capture_drop_panics() {
        let state = Arc::new(ProbeState::default());
        let failed = std::panic::catch_unwind(AssertUnwindSafe(|| {
            drop(probe_permit(&state, true, false));
        }));
        assert!(failed.is_err());
        assert_rollback_before_retirement(&state);
    }

    #[test]
    fn abort_callback_panic_is_not_retried_and_retires_commit_capture() {
        let state = Arc::new(ProbeState::default());
        let failed = std::panic::catch_unwind(AssertUnwindSafe(|| {
            probe_permit(&state, false, true).abort();
        }));
        assert!(failed.is_err(), "rollback callback panic must propagate");
        assert_rollback_before_retirement(&state);
    }

    #[test]
    fn commit_panic_rolls_back_reservation_once() {
        let aborts = Arc::new(AtomicUsize::new(0));
        let abort_calls = Arc::clone(&aborts);
        let permit = SendPermit::new(
            |_| -> Result<(), ()> { panic!("commit callback panic") },
            move || {
                abort_calls.fetch_add(1, Ordering::SeqCst);
            },
        );
        let failed = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = permit.commit(b"payload");
        }));
        assert!(failed.is_err());
        assert_eq!(aborts.load(Ordering::SeqCst), 1);
    }
