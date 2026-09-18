use super::*;
use crate::time::{TimerDriver, TimerDriverHandle};
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Wake, Waker};

// Deliberately not Debug: capture diagnostics must never inspect the provider.
struct ScriptedClock {
    samples: Mutex<VecDeque<u64>>,
    calls: AtomicUsize,
    callback: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl ScriptedClock {
    fn new(samples: &[u64]) -> Self {
        Self {
            samples: Mutex::new(samples.iter().copied().collect()),
            calls: AtomicUsize::new(0),
            callback: Mutex::new(None),
        }
    }
}

impl TimeSource for ScriptedClock {
    fn now(&self) -> Time {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let callback = self.callback.lock().take();
        if let Some(callback) = callback {
            callback();
        }
        Time::from_nanos(self.samples.lock().pop_front().expect("scripted sample"))
    }
}

fn tape(samples: &[u64]) -> TimeTape {
    let source = Arc::new(ScriptedClock::new(samples));
    let recorder = RecordingTimeSource::new(source, samples.len());
    for sample in samples {
        assert_eq!(recorder.now(), Time::from_nanos(*sample));
    }
    recorder.finish().expect("complete capture")
}

#[test]
fn exact_observations_include_repeats_zero_and_maximum() {
    let values = [0, 0, 1, 1, u64::MAX];
    let tape = tape(&values);
    assert_eq!(tape.observations(), values.len());
    let replay = tape.replay();
    for (index, value) in values.into_iter().enumerate() {
        assert_eq!(replay.observations_consumed(), index);
        assert_eq!(replay.try_now(), Ok(Time::from_nanos(value)));
    }
    assert_eq!(replay.verify_complete(), Ok(()));
    assert_eq!(replay.replay_error(), None);
}

#[test]
fn early_completeness_check_does_not_poison_replay() {
    let replay = tape(&[10, 20]).replay();
    assert_eq!(
        replay.verify_complete(),
        Err(TimeReplayError::Unconsumed {
            consumed: 0,
            total: 2,
        })
    );
    assert_eq!(replay.try_now(), Ok(Time::from_nanos(10)));
    assert_eq!(
        replay.verify_complete(),
        Err(TimeReplayError::Unconsumed {
            consumed: 1,
            total: 2,
        })
    );
    assert_eq!(replay.replay_error(), None);
    assert_eq!(replay.try_now(), Ok(Time::from_nanos(20)));
    assert_eq!(replay.verify_complete(), Ok(()));
}

#[test]
fn exhaustion_is_sticky_and_never_invents_a_timestamp() {
    let replay = tape(&[7]).replay();
    assert_eq!(replay.try_now(), Ok(Time::from_nanos(7)));
    let expected = TimeReplayError::Exhausted { index: 1 };
    for _ in 0..3 {
        assert_eq!(replay.try_now(), Err(expected));
        assert_eq!(replay.verify_complete(), Err(expected));
        assert_eq!(replay.replay_error(), Some(expected));
        assert_eq!(replay.observations_consumed(), 1);
    }
}

#[test]
fn infallible_interface_panics_with_typed_sticky_failure() {
    let replay = tape(&[]).replay();
    let panic = catch_unwind(AssertUnwindSafe(|| replay.now())).expect_err("must refuse");
    let expected = TimeReplayError::Exhausted { index: 0 };
    assert_eq!(panic.downcast_ref::<TimeReplayError>(), Some(&expected));
    // These reacquire the replay lock after the panic, rather than deadlocking.
    assert_eq!(replay.try_now(), Err(expected));
    assert_eq!(replay.verify_complete(), Err(expected));
}

#[test]
fn empty_window_is_complete_but_has_no_observation() {
    let replay = tape(&[]).replay();
    assert_eq!(replay.verify_complete(), Ok(()));
    assert_eq!(replay.observations_consumed(), 0);
    assert_eq!(
        replay.try_now(),
        Err(TimeReplayError::Exhausted { index: 0 })
    );
}

#[test]
fn setup_diagnostics_and_finish_never_sample_the_source() {
    let source = Arc::new(ScriptedClock::new(&[]));
    let recorder = RecordingTimeSource::new(Arc::clone(&source), 0);
    assert!(!recorder.is_finished());
    assert_eq!(recorder.capture_error(), None);
    assert!(format!("{recorder:?}").contains("RecordingTimeSource"));
    assert_eq!(recorder.finish().unwrap().observations(), 0);
    assert!(recorder.is_finished());
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(recorder.finish().unwrap_err(), TimeCaptureError::Finished);
}

#[test]
fn zero_limit_refuses_capture_without_changing_live_time() {
    let source = Arc::new(ScriptedClock::new(&[17, 19]));
    let recorder = RecordingTimeSource::new(Arc::clone(&source), 0);
    assert_eq!(recorder.now(), Time::from_nanos(17));
    assert_eq!(recorder.now(), Time::from_nanos(19));
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        recorder.capture_error(),
        Some(TimeCaptureError::ObservationLimit)
    );
    assert_eq!(
        recorder.finish().unwrap_err(),
        TimeCaptureError::ObservationLimit
    );
}

#[test]
fn exact_limit_succeeds_but_one_more_read_invalidates_the_whole_window() {
    assert_eq!(tape(&[11]).observations(), 1);
    let source = Arc::new(ScriptedClock::new(&[11, 12, 13]));
    let recorder = RecordingTimeSource::new(source, 1);
    assert_eq!(recorder.now(), Time::from_nanos(11));
    assert_eq!(recorder.now(), Time::from_nanos(12));
    assert_eq!(recorder.now(), Time::from_nanos(13));
    assert_eq!(
        recorder.finish().unwrap_err(),
        TimeCaptureError::ObservationLimit
    );
}

#[test]
fn bounded_growth_and_large_logical_limit_preserve_samples() {
    for count in [1, 7, 8, 9, 16, 17, 65] {
        let samples: Vec<u64> = (0..count).collect();
        assert_eq!(tape(&samples).observations(), samples.len());
    }
    let recorder = RecordingTimeSource::new(Arc::new(ScriptedClock::new(&[1])), usize::MAX);
    assert_eq!(recorder.now(), Time::from_nanos(1));
    assert_eq!(recorder.finish().unwrap().observations(), 1);
}

#[test]
fn backwards_source_time_is_forwarded_but_not_admitted_to_replay() {
    let recorder = RecordingTimeSource::new(Arc::new(ScriptedClock::new(&[10, 9, 30])), 3);
    for value in [10, 9, 30] {
        assert_eq!(recorder.now(), Time::from_nanos(value));
    }
    assert_eq!(recorder.capture_error(), Some(TimeCaptureError::NonMonotonic));
    assert_eq!(recorder.finish().unwrap_err(), TimeCaptureError::NonMonotonic);
}

#[test]
fn source_reads_after_finish_are_outside_the_captured_window() {
    let recorder = RecordingTimeSource::new(Arc::new(ScriptedClock::new(&[10, 99])), 1);
    assert_eq!(recorder.now(), Time::from_nanos(10));
    let replay = recorder.finish().unwrap().replay();
    assert_eq!(recorder.now(), Time::from_nanos(99));
    assert_eq!(recorder.capture_error(), None);
    assert_eq!(replay.try_now(), Ok(Time::from_nanos(10)));
    assert_eq!(replay.verify_complete(), Ok(()));
}

#[test]
fn unwinding_source_invalidates_capture_but_future_reads_still_forward() {
    struct PanickingClock(AtomicBool);
    impl TimeSource for PanickingClock {
        fn now(&self) -> Time {
            assert!(!self.0.swap(false, Ordering::SeqCst), "source panic sentinel");
            Time::from_nanos(42)
        }
    }
    let recorder = RecordingTimeSource::new(Arc::new(PanickingClock(AtomicBool::new(true))), 2);
    assert!(catch_unwind(AssertUnwindSafe(|| recorder.now())).is_err());
    assert_eq!(recorder.now(), Time::from_nanos(42));
    assert_eq!(
        recorder.capture_error(),
        Some(TimeCaptureError::InterruptedObservation)
    );
    assert_eq!(
        recorder.finish().unwrap_err(),
        TimeCaptureError::InterruptedObservation
    );
}

#[test]
fn source_can_reenter_diagnostics_without_a_capture_lock() {
    let source = Arc::new(ScriptedClock::new(&[3]));
    let recorder = Arc::new(RecordingTimeSource::new(Arc::clone(&source), 1));
    let weak = Arc::downgrade(&recorder);
    *source.callback.lock() = Some(Box::new(move || {
        let recorder = weak.upgrade().unwrap();
        assert_eq!(recorder.capture_error(), None);
        assert!(!recorder.is_finished());
        assert!(format!("{recorder:?}").contains("observations"));
    }));
    assert_eq!(recorder.now(), Time::from_nanos(3));
    assert_eq!(recorder.finish().unwrap().observations(), 1);
}

#[test]
fn reentrant_source_reads_are_forwarded_but_capture_is_refused() {
    let source = Arc::new(ScriptedClock::new(&[10, 20]));
    let recorder = Arc::new(RecordingTimeSource::new(Arc::clone(&source), 2));
    let weak = Arc::downgrade(&recorder);
    *source.callback.lock() = Some(Box::new(move || {
        assert_eq!(weak.upgrade().unwrap().now(), Time::from_nanos(10));
    }));
    assert_eq!(recorder.now(), Time::from_nanos(20));
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        recorder.finish().unwrap_err(),
        TimeCaptureError::ConcurrentObservation
    );
}

#[test]
fn finish_during_source_callback_never_exports_an_incomplete_prefix() {
    let source = Arc::new(ScriptedClock::new(&[10]));
    let recorder = Arc::new(RecordingTimeSource::new(Arc::clone(&source), 1));
    let weak = Arc::downgrade(&recorder);
    *source.callback.lock() = Some(Box::new(move || {
        assert_eq!(
            weak.upgrade().unwrap().finish().unwrap_err(),
            TimeCaptureError::ObservationInFlight
        );
    }));
    assert_eq!(recorder.now(), Time::from_nanos(10));
    assert!(recorder.is_finished());
    assert_eq!(
        recorder.capture_error(),
        Some(TimeCaptureError::ObservationInFlight)
    );
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn concurrent_source_calls_refuse_ambiguous_attribution() {
    use std::sync::mpsc;
    use std::time::Duration;

    struct GatedClock {
        first: AtomicBool,
        entered: mpsc::SyncSender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
    }
    impl TimeSource for GatedClock {
        fn now(&self) -> Time {
            if self.first.swap(false, Ordering::SeqCst) {
                self.entered.send(()).unwrap();
                self.resume
                    .lock()
                    .recv_timeout(Duration::from_secs(5))
                    .expect("release first source call");
                Time::from_nanos(10)
            } else {
                Time::from_nanos(20)
            }
        }
    }
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let recorder = Arc::new(RecordingTimeSource::new(
        Arc::new(GatedClock {
            first: AtomicBool::new(true),
            entered: entered_tx,
            resume: Mutex::new(resume_rx),
        }),
        2,
    ));
    let worker_clock = Arc::clone(&recorder);
    let worker = std::thread::spawn(move || worker_clock.now());
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = recorder.now();
    resume_tx.send(()).unwrap();
    let first = worker.join().unwrap();
    assert_eq!(first, Time::from_nanos(10));
    assert_eq!(second, Time::from_nanos(20));
    assert_eq!(
        recorder.finish().unwrap_err(),
        TimeCaptureError::ConcurrentObservation
    );
}

#[test]
fn trait_object_sources_and_redacted_debug_are_supported() {
    let source: Arc<dyn TimeSource> = Arc::new(ScriptedClock::new(&[987_654_321]));
    let recorder = RecordingTimeSource::new(source, 1);
    assert_eq!(recorder.now(), Time::from_nanos(987_654_321));
    assert!(!format!("{recorder:?}").contains("987654321"));
    let tape = recorder.finish().unwrap();
    assert!(!format!("{tape:?}").contains("987654321"));
    assert!(!format!("{:?}", tape.replay()).contains("987654321"));
}

#[test]
fn captured_clock_replays_real_timer_driver_expiration() {
    struct AdjustableClock(AtomicU64);
    impl TimeSource for AdjustableClock {
        fn now(&self) -> Time {
            Time::from_nanos(self.0.load(Ordering::SeqCst))
        }
    }
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let source = Arc::new(AdjustableClock(AtomicU64::new(0)));
    let recorder = Arc::new(RecordingTimeSource::new(Arc::clone(&source), 64));
    let driver = TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::clone(&recorder))));
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let _timer = driver.register(Time::from_secs(1), Waker::from(Arc::clone(&wakes)));
    assert_eq!(driver.process_timers(), 0);
    source.0.store(2_000_000_000, Ordering::SeqCst);
    assert_eq!(driver.process_timers(), 1);
    assert_eq!(driver.pending_count(), 0);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    drop(driver);

    // Replay the same public driver journey without any underlying clock.
    let replay = Arc::new(recorder.finish().unwrap().replay());
    let driver = TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::clone(&replay))));
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let _timer = driver.register(Time::from_secs(1), Waker::from(Arc::clone(&wakes)));
    assert_eq!(driver.process_timers(), 0);
    assert_eq!(driver.process_timers(), 1);
    assert_eq!(driver.pending_count(), 0);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(replay.verify_complete(), Ok(()));
}
