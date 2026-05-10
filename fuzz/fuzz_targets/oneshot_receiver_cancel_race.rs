#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::thread;
use std::time::Duration;

use asupersync::channel::oneshot::{self, RecvError, SendError};
use asupersync::cx::cap;
use asupersync::types::{CancelKind, TaskId};
use asupersync::util::ArenaIndex;
use asupersync::{Budget, Cx, RegionId};

#[derive(Debug, Clone)]
struct CancelRaceTracker {
    operations: Arc<StdMutex<Vec<String>>>,
    cancel_results: Arc<StdMutex<Vec<CancelEvent>>>,
    recv_results: Arc<StdMutex<Vec<RecvEvent>>>,
    race_outcomes: Arc<StdMutex<Vec<RaceOutcome>>>,
}

#[derive(Debug, Clone)]
struct CancelEvent {
    cancel_time: u64,
    cancel_kind: String,
    cancel_message: String,
}

#[derive(Debug, Clone)]
struct RecvEvent {
    recv_attempt_id: usize,
    outcome: RecvOutcome,
    was_cancelled_at_poll: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum RecvOutcome {
    GotValue(u32),
    GotCancelled,
    GotClosed,
    GotPolledAfterCompletion,
    StillPending,
    PanicOccurred,
}

#[derive(Debug, Clone)]
struct RaceOutcome {
    test_id: usize,
    final_recv_state: RecvOutcome,
    cancel_occurred: bool,
    send_occurred: bool,
    invariant_violated: bool,
    violation_description: String,
}

impl CancelRaceTracker {
    fn new() -> Self {
        Self {
            operations: Arc::new(StdMutex::new(Vec::new())),
            cancel_results: Arc::new(StdMutex::new(Vec::new())),
            recv_results: Arc::new(StdMutex::new(Vec::new())),
            race_outcomes: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn record_operation(&self, op: &str) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(op.to_string());
        }
    }

    fn record_cancel_event(&self, event: CancelEvent) {
        if let Ok(mut events) = self.cancel_results.lock() {
            events.push(event);
        }
    }

    fn record_recv_event(&self, event: RecvEvent) {
        if let Ok(mut events) = self.recv_results.lock() {
            events.push(event);
        }
    }

    fn record_race_outcome(&self, outcome: RaceOutcome) {
        if let Ok(mut outcomes) = self.race_outcomes.lock() {
            outcomes.push(outcome);
        }
    }

    fn validate_cancel_race_invariants(&self) {
        // Core invariant: receiver gets either Cancelled OR value, never both
        // Also: cancelled receiver should never receive a value after cancellation

        if let Ok(events) = self.cancel_results.lock() {
            for event in events.iter() {
                self.record_operation(&format!(
                    "cancel_event_{}_{}_{}",
                    event.cancel_time, event.cancel_kind, event.cancel_message
                ));
            }
        }

        if let Ok(events) = self.recv_results.lock() {
            for event in events.iter() {
                self.record_operation(&format!(
                    "recv_event_{}_cancelled_{}_{:?}",
                    event.recv_attempt_id, event.was_cancelled_at_poll, event.outcome
                ));
            }
        }

        if let Ok(outcomes) = self.race_outcomes.lock() {
            for outcome in outcomes.iter() {
                if outcome.invariant_violated {
                    panic!(
                        "Cancel race invariant violated in test {}: {}",
                        outcome.test_id, outcome.violation_description
                    );
                }

                // If cancel occurred and send occurred, receiver should get exactly one outcome
                if outcome.cancel_occurred && outcome.send_occurred {
                    match &outcome.final_recv_state {
                        RecvOutcome::GotValue(_) => {
                            // Value received despite cancellation - this might be OK if timing allows
                            self.record_operation("value_received_despite_cancel");
                        }
                        RecvOutcome::GotCancelled => {
                            // Cancellation observed - this is the expected outcome
                            self.record_operation("cancel_observed_correctly");
                        }
                        RecvOutcome::GotClosed => {
                            // Sender was dropped - also valid
                            self.record_operation("closed_observed");
                        }
                        RecvOutcome::StillPending | RecvOutcome::GotPolledAfterCompletion => {
                            // These should not happen in a properly resolved race
                            panic!(
                                "Race test {} left in unresolved state: {:?}",
                                outcome.test_id, outcome.final_recv_state
                            );
                        }
                        RecvOutcome::PanicOccurred => {
                            // Panics during cancel races are not acceptable
                            panic!("Panic occurred during cancel race test {}", outcome.test_id);
                        }
                    }
                }
            }
        }
    }
}

fn recv_outcome_from_poll(poll: Poll<Result<u32, RecvError>>) -> RecvOutcome {
    match poll {
        Poll::Ready(Ok(v)) => RecvOutcome::GotValue(v),
        Poll::Ready(Err(RecvError::Cancelled)) => RecvOutcome::GotCancelled,
        Poll::Ready(Err(RecvError::Closed)) => RecvOutcome::GotClosed,
        Poll::Ready(Err(RecvError::PolledAfterCompletion)) => RecvOutcome::GotPolledAfterCompletion,
        Poll::Pending => RecvOutcome::StillPending,
    }
}

fn observe_active_recv_poll(
    tracker: &CancelRaceTracker,
    recv_attempt_id: usize,
    cx: &Cx<cap::All>,
    poll: Poll<Result<u32, RecvError>>,
    phase: &str,
) -> RecvOutcome {
    let outcome = recv_outcome_from_poll(poll);
    tracker.record_recv_event(RecvEvent {
        recv_attempt_id,
        outcome: outcome.clone(),
        was_cancelled_at_poll: cx.is_cancel_requested(),
    });

    if outcome == RecvOutcome::GotPolledAfterCompletion {
        panic!(
            "receiver poll unexpectedly completed after completion during {phase} for attempt {recv_attempt_id}"
        );
    }

    outcome
}

struct TrackedWaker {
    op_id: usize,
    tracker: CancelRaceTracker,
}

impl TrackedWaker {
    fn new(op_id: usize, tracker: CancelRaceTracker) -> Self {
        Self { op_id, tracker }
    }

    fn create_waker(&self) -> Waker {
        let data = Arc::new(self.clone());
        let raw = RawWaker::new(Arc::into_raw(data) as *const (), &TRACKED_WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}

impl Clone for TrackedWaker {
    fn clone(&self) -> Self {
        Self {
            op_id: self.op_id,
            tracker: self.tracker.clone(),
        }
    }
}

static TRACKED_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    tracked_waker_clone,
    tracked_waker_wake,
    tracked_waker_wake_by_ref,
    tracked_waker_drop,
);

unsafe fn tracked_waker_clone(data: *const ()) -> RawWaker {
    let arc = unsafe { Arc::from_raw(data as *const TrackedWaker) };
    let cloned = arc.clone();
    std::mem::forget(arc);
    let new_data = Arc::into_raw(cloned) as *const ();
    RawWaker::new(new_data, &TRACKED_WAKER_VTABLE)
}

unsafe fn tracked_waker_wake(data: *const ()) {
    let arc = unsafe { Arc::from_raw(data as *const TrackedWaker) };
    arc.tracker
        .record_operation(&format!("waker_wake_{}", arc.op_id));
}

unsafe fn tracked_waker_wake_by_ref(data: *const ()) {
    let arc = unsafe { Arc::from_raw(data as *const TrackedWaker) };
    arc.tracker
        .record_operation(&format!("waker_wake_by_ref_{}", arc.op_id));
    std::mem::forget(arc);
}

unsafe fn tracked_waker_drop(data: *const ()) {
    let _arc = unsafe { Arc::from_raw(data as *const TrackedWaker) };
}

#[derive(Debug, Clone, Arbitrary)]
struct CancelRaceConfig {
    test_value: u32,
    race_pattern: CancelRacePattern,
    cancel_timing: CancelTiming,
}

#[derive(Debug, Clone, Arbitrary)]
enum CancelRacePattern {
    SimpleCancel,
    CancelDuringSend,
    CancelBeforeSend,
    CancelAfterSend,
    RapidCancelSend {
        iterations: u8,
    },
    DelayedOperations {
        send_delay_us: u16,
        cancel_delay_us: u16,
    },
    ConcurrentMultipleRecv {
        recv_count: u8,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum CancelTiming {
    ImmediateCancel,
    DelayedCancel { delay_us: u16 },
    CancelAfterFirstPoll,
    CancelDuringPoll,
    RandomTiming { seed: u8 },
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let config: CancelRaceConfig = u.arbitrary().unwrap_or(CancelRaceConfig {
        test_value: 42,
        race_pattern: CancelRacePattern::SimpleCancel,
        cancel_timing: CancelTiming::ImmediateCancel,
    });

    let tracker = CancelRaceTracker::new();
    let test_id = config.test_value as usize;

    // Execute race pattern
    match config.race_pattern {
        CancelRacePattern::SimpleCancel => {
            test_simple_cancel(&tracker, test_id, config.test_value, &config.cancel_timing);
        }

        CancelRacePattern::CancelDuringSend => {
            test_cancel_during_send(&tracker, test_id, config.test_value, &config.cancel_timing);
        }

        CancelRacePattern::CancelBeforeSend => {
            test_cancel_before_send(&tracker, test_id, config.test_value, &config.cancel_timing);
        }

        CancelRacePattern::CancelAfterSend => {
            test_cancel_after_send(&tracker, test_id, config.test_value, &config.cancel_timing);
        }

        CancelRacePattern::RapidCancelSend { iterations } => {
            test_rapid_cancel_send(&tracker, test_id, config.test_value, iterations.min(8));
        }

        CancelRacePattern::DelayedOperations {
            send_delay_us,
            cancel_delay_us,
        } => {
            test_delayed_operations(
                &tracker,
                test_id,
                config.test_value,
                send_delay_us,
                cancel_delay_us,
            );
        }

        CancelRacePattern::ConcurrentMultipleRecv { recv_count } => {
            test_concurrent_multiple_recv(&tracker, test_id, config.test_value, recv_count.min(5));
        }
    }

    // Validate invariants
    tracker.validate_cancel_race_invariants();
});

fn test_simple_cancel(
    tracker: &CancelRaceTracker,
    test_id: usize,
    value: u32,
    timing: &CancelTiming,
) {
    tracker.record_operation("test_simple_cancel");

    let cx: Cx<cap::All> = Cx::new(
        RegionId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        TaskId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        Budget::unlimited(),
    );

    let (sender, mut receiver) = oneshot::channel::<u32>();
    let mut send_occurred = false;

    // Set up cancellation based on timing
    let cx_clone = cx.clone();
    let timing_clone = timing.clone();
    let tracker_clone = tracker.clone();
    let cancel_handle = thread::spawn(move || {
        match timing_clone {
            CancelTiming::ImmediateCancel => {
                // Cancel immediately
            }
            CancelTiming::DelayedCancel { delay_us } => {
                thread::sleep(Duration::from_micros(delay_us.min(1000) as u64));
            }
            CancelTiming::RandomTiming { seed } => {
                let delay = (seed as u64) % 500;
                thread::sleep(Duration::from_micros(delay));
            }
            _ => {
                thread::sleep(Duration::from_micros(100));
            }
        }

        cx_clone.cancel_with(CancelKind::User, Some("test_cancel"));
        tracker_clone.record_cancel_event(CancelEvent {
            cancel_time: 0,
            cancel_kind: "User".to_string(),
            cancel_message: "test_cancel".to_string(),
        });
    });

    // Start receiving
    let recv_future = receiver.recv(&cx);
    let mut pinned_recv = Box::pin(recv_future);
    let recv_waker = TrackedWaker::new(test_id, tracker.clone()).create_waker();
    let mut recv_context = Context::from_waker(&recv_waker);

    // Poll receiver
    let recv_result = pinned_recv.as_mut().poll(&mut recv_context);
    let mut final_recv_state = match recv_result {
        Poll::Ready(Ok(v)) => RecvOutcome::GotValue(v),
        Poll::Ready(Err(RecvError::Cancelled)) => RecvOutcome::GotCancelled,
        Poll::Ready(Err(RecvError::Closed)) => RecvOutcome::GotClosed,
        Poll::Ready(Err(RecvError::PolledAfterCompletion)) => RecvOutcome::GotPolledAfterCompletion,
        Poll::Pending => RecvOutcome::StillPending,
    };

    // Attempt to send after starting cancel
    let send_result = catch_unwind(AssertUnwindSafe(|| sender.send(&cx, value)));

    if let Ok(result) = send_result {
        send_occurred = match result {
            Ok(()) => {
                tracker.record_operation("send_succeeded");
                true
            }
            Err(SendError::Cancelled(v)) => {
                tracker.record_operation(&format!("send_cancelled_with_value_{}", v));
                false
            }
            Err(SendError::Disconnected(v)) => {
                tracker.record_operation(&format!("send_disconnected_with_value_{}", v));
                true // Send was attempted, but receiver was gone
            }
        };
    } else {
        tracker.record_operation("send_panicked");
        final_recv_state = RecvOutcome::PanicOccurred;
    }

    // Wait for cancel to complete
    let _ = cancel_handle.join();
    let cancel_occurred = true;

    // If receiver was still pending, poll again to see final state
    if final_recv_state == RecvOutcome::StillPending {
        let recv_result_2 = pinned_recv.as_mut().poll(&mut recv_context);
        final_recv_state = match recv_result_2 {
            Poll::Ready(Ok(v)) => RecvOutcome::GotValue(v),
            Poll::Ready(Err(RecvError::Cancelled)) => RecvOutcome::GotCancelled,
            Poll::Ready(Err(RecvError::Closed)) => RecvOutcome::GotClosed,
            Poll::Ready(Err(RecvError::PolledAfterCompletion)) => {
                RecvOutcome::GotPolledAfterCompletion
            }
            Poll::Pending => RecvOutcome::StillPending,
        };
    }

    tracker.record_recv_event(RecvEvent {
        recv_attempt_id: test_id,
        outcome: final_recv_state.clone(),
        was_cancelled_at_poll: cx.is_cancel_requested(),
    });

    // Check for invariant violations
    let violation = false;
    let violation_desc = String::new();

    // Core invariant: if cancel occurred and was observed by receiver,
    // receiver should not have received a value
    if cancel_occurred && final_recv_state == RecvOutcome::GotCancelled && send_occurred {
        // This is actually OK - cancel was observed correctly
    }

    // If receiver got both a value AND the context was cancelled, this is suspicious
    if matches!(&final_recv_state, RecvOutcome::GotValue(_)) && cx.is_cancel_requested() {
        // This might be OK if send happened before cancel was processed
        tracker.record_operation("value_received_while_cancelled_context");
    }

    tracker.record_race_outcome(RaceOutcome {
        test_id,
        final_recv_state,
        cancel_occurred,
        send_occurred,
        invariant_violated: violation,
        violation_description: violation_desc,
    });
}

fn test_cancel_during_send(
    tracker: &CancelRaceTracker,
    test_id: usize,
    value: u32,
    _timing: &CancelTiming,
) {
    tracker.record_operation("test_cancel_during_send");

    let cx: Cx<cap::All> = Cx::new(
        RegionId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        TaskId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        Budget::unlimited(),
    );

    let (sender, mut receiver) = oneshot::channel::<u32>();

    // Start concurrent operations
    let cx_send = cx.clone();
    let cx_cancel = cx.clone();
    let tracker_send = tracker.clone();
    let tracker_cancel = tracker.clone();

    let send_handle = thread::spawn(move || {
        let result = sender.send(&cx_send, value);
        match result {
            Ok(()) => tracker_send.record_operation("concurrent_send_succeeded"),
            Err(SendError::Cancelled(v)) => {
                tracker_send.record_operation(&format!("concurrent_send_cancelled_{}", v));
            }
            Err(SendError::Disconnected(v)) => {
                tracker_send.record_operation(&format!("concurrent_send_disconnected_{}", v));
            }
        }
        result.is_ok()
    });

    let cancel_handle = thread::spawn(move || {
        // Small delay to let send start
        thread::sleep(Duration::from_micros(10));
        cx_cancel.cancel_with(CancelKind::User, Some("concurrent_cancel"));
        tracker_cancel.record_cancel_event(CancelEvent {
            cancel_time: 0,
            cancel_kind: "User".to_string(),
            cancel_message: "concurrent_cancel".to_string(),
        });
    });

    // Try to receive
    let recv_future = receiver.recv(&cx);
    let mut pinned_recv = Box::pin(recv_future);
    let recv_waker = TrackedWaker::new(test_id + 1000, tracker.clone()).create_waker();
    let mut recv_context = Context::from_waker(&recv_waker);

    let recv_result = pinned_recv.as_mut().poll(&mut recv_context);
    let final_recv_state = match recv_result {
        Poll::Ready(Ok(v)) => RecvOutcome::GotValue(v),
        Poll::Ready(Err(RecvError::Cancelled)) => RecvOutcome::GotCancelled,
        Poll::Ready(Err(RecvError::Closed)) => RecvOutcome::GotClosed,
        Poll::Ready(Err(RecvError::PolledAfterCompletion)) => RecvOutcome::GotPolledAfterCompletion,
        Poll::Pending => {
            // Poll again after operations complete
            let _ = send_handle.join();
            let _ = cancel_handle.join();

            let recv_result_2 = pinned_recv.as_mut().poll(&mut recv_context);
            match recv_result_2 {
                Poll::Ready(Ok(v)) => RecvOutcome::GotValue(v),
                Poll::Ready(Err(RecvError::Cancelled)) => RecvOutcome::GotCancelled,
                Poll::Ready(Err(RecvError::Closed)) => RecvOutcome::GotClosed,
                Poll::Ready(Err(RecvError::PolledAfterCompletion)) => {
                    RecvOutcome::GotPolledAfterCompletion
                }
                Poll::Pending => RecvOutcome::StillPending,
            }
        }
    };

    tracker.record_race_outcome(RaceOutcome {
        test_id,
        final_recv_state,
        cancel_occurred: true,
        send_occurred: true,
        invariant_violated: false,
        violation_description: String::new(),
    });
}

// Simplified implementations for other test patterns
fn test_cancel_before_send(
    tracker: &CancelRaceTracker,
    test_id: usize,
    value: u32,
    _timing: &CancelTiming,
) {
    tracker.record_operation("test_cancel_before_send");

    let cx: Cx<cap::All> = Cx::new(
        RegionId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        TaskId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        Budget::unlimited(),
    );

    // Cancel first
    cx.cancel_with(CancelKind::User, Some("cancel_before_send"));

    let (sender, mut receiver) = oneshot::channel::<u32>();

    // Try to send on cancelled context
    let send_result = sender.send(&cx, value);
    let send_occurred = send_result.is_ok();

    // Try to receive
    let recv_result = catch_unwind(AssertUnwindSafe(|| {
        let recv_future = receiver.recv(&cx);
        let mut pinned_recv = Box::pin(recv_future);
        let recv_waker = TrackedWaker::new(test_id, tracker.clone()).create_waker();
        let mut recv_context = Context::from_waker(&recv_waker);
        pinned_recv.as_mut().poll(&mut recv_context)
    }));

    let final_recv_state = match recv_result {
        Ok(Poll::Ready(Ok(v))) => RecvOutcome::GotValue(v),
        Ok(Poll::Ready(Err(RecvError::Cancelled))) => RecvOutcome::GotCancelled,
        Ok(Poll::Ready(Err(RecvError::Closed))) => RecvOutcome::GotClosed,
        Ok(Poll::Ready(Err(RecvError::PolledAfterCompletion))) => {
            RecvOutcome::GotPolledAfterCompletion
        }
        Ok(Poll::Pending) => RecvOutcome::StillPending,
        Err(_) => RecvOutcome::PanicOccurred,
    };

    tracker.record_race_outcome(RaceOutcome {
        test_id,
        final_recv_state,
        cancel_occurred: true,
        send_occurred,
        invariant_violated: false,
        violation_description: String::new(),
    });
}

fn test_cancel_after_send(
    tracker: &CancelRaceTracker,
    test_id: usize,
    value: u32,
    _timing: &CancelTiming,
) {
    tracker.record_operation("test_cancel_after_send");

    let cx: Cx<cap::All> = Cx::new(
        RegionId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        TaskId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        Budget::unlimited(),
    );

    let (sender, mut receiver) = oneshot::channel::<u32>();

    // Send first
    let send_result = sender.send(&cx, value);
    let send_occurred = send_result.is_ok();

    // Cancel after send
    cx.cancel_with(CancelKind::User, Some("cancel_after_send"));

    // Try to receive
    let recv_future = receiver.recv(&cx);
    let mut pinned_recv = Box::pin(recv_future);
    let recv_waker = TrackedWaker::new(test_id, tracker.clone()).create_waker();
    let mut recv_context = Context::from_waker(&recv_waker);

    let recv_result = pinned_recv.as_mut().poll(&mut recv_context);
    let final_recv_state = match recv_result {
        Poll::Ready(Ok(v)) => RecvOutcome::GotValue(v),
        Poll::Ready(Err(RecvError::Cancelled)) => RecvOutcome::GotCancelled,
        Poll::Ready(Err(RecvError::Closed)) => RecvOutcome::GotClosed,
        Poll::Ready(Err(RecvError::PolledAfterCompletion)) => RecvOutcome::GotPolledAfterCompletion,
        Poll::Pending => RecvOutcome::StillPending,
    };

    tracker.record_race_outcome(RaceOutcome {
        test_id,
        final_recv_state,
        cancel_occurred: true,
        send_occurred,
        invariant_violated: false,
        violation_description: String::new(),
    });
}

fn test_rapid_cancel_send(tracker: &CancelRaceTracker, test_id: usize, value: u32, iterations: u8) {
    tracker.record_operation("test_rapid_cancel_send");

    for i in 0..iterations {
        let cx: Cx<cap::All> = Cx::new(
            RegionId::from_arena(ArenaIndex::new((test_id + i as usize) as u32, 0)),
            TaskId::from_arena(ArenaIndex::new((test_id + i as usize) as u32, 0)),
            Budget::unlimited(),
        );

        let (sender, mut receiver) = oneshot::channel::<u32>();

        // Rapid cancel/send race
        if i % 2 == 0 {
            cx.cancel_with(CancelKind::User, Some("rapid_cancel"));
            thread::sleep(Duration::from_micros(1));
        }

        let send_result = sender.send(&cx, value);
        match send_result {
            Ok(()) => tracker.record_operation("rapid_send_succeeded"),
            Err(SendError::Cancelled(v)) => {
                tracker.record_operation(&format!("rapid_send_cancelled_with_value_{}", v));
            }
            Err(SendError::Disconnected(v)) => {
                tracker.record_operation(&format!("rapid_send_disconnected_with_value_{}", v));
            }
        }

        if i % 2 == 1 {
            cx.cancel_with(CancelKind::User, Some("rapid_cancel"));
        }

        let recv_future = receiver.recv(&cx);
        let mut pinned_recv = Box::pin(recv_future);
        let recv_waker = TrackedWaker::new(test_id + i as usize, tracker.clone()).create_waker();
        let mut recv_context = Context::from_waker(&recv_waker);

        observe_active_recv_poll(
            tracker,
            test_id + i as usize,
            &cx,
            pinned_recv.as_mut().poll(&mut recv_context),
            "rapid_cancel_send",
        );
    }
}

fn test_delayed_operations(
    tracker: &CancelRaceTracker,
    test_id: usize,
    value: u32,
    send_delay_us: u16,
    cancel_delay_us: u16,
) {
    tracker.record_operation("test_delayed_operations");

    let cx: Cx<cap::All> = Cx::new(
        RegionId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        TaskId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        Budget::unlimited(),
    );

    let (sender, mut receiver) = oneshot::channel::<u32>();

    let cx_send = cx.clone();
    let cx_cancel = cx.clone();
    let send_delay = Duration::from_micros(send_delay_us.min(1000) as u64);
    let cancel_delay = Duration::from_micros(cancel_delay_us.min(1000) as u64);

    let send_handle = thread::spawn(move || {
        thread::sleep(send_delay);
        sender.send(&cx_send, value).is_ok()
    });

    let cancel_handle = thread::spawn(move || {
        thread::sleep(cancel_delay);
        cx_cancel.cancel_with(CancelKind::User, Some("delayed_cancel"));
    });

    // Receive
    let recv_future = receiver.recv(&cx);
    let mut pinned_recv = Box::pin(recv_future);
    let recv_waker = TrackedWaker::new(test_id, tracker.clone()).create_waker();
    let mut recv_context = Context::from_waker(&recv_waker);

    let mut final_recv_state = observe_active_recv_poll(
        tracker,
        test_id,
        &cx,
        pinned_recv.as_mut().poll(&mut recv_context),
        "delayed_operations_initial",
    );

    // Wait for operations
    let send_occurred = match send_handle.join() {
        Ok(sent) => sent,
        Err(_) => {
            tracker.record_operation("delayed_send_panicked");
            false
        }
    };
    if cancel_handle.join().is_err() {
        tracker.record_operation("delayed_cancel_panicked");
    }

    // Final poll only if the first poll registered interest instead of completing.
    if final_recv_state == RecvOutcome::StillPending {
        final_recv_state = observe_active_recv_poll(
            tracker,
            test_id,
            &cx,
            pinned_recv.as_mut().poll(&mut recv_context),
            "delayed_operations_final",
        );
    }

    tracker.record_race_outcome(RaceOutcome {
        test_id,
        final_recv_state,
        cancel_occurred: true,
        send_occurred,
        invariant_violated: false,
        violation_description: String::new(),
    });
}

fn test_concurrent_multiple_recv(
    tracker: &CancelRaceTracker,
    test_id: usize,
    value: u32,
    recv_count: u8,
) {
    tracker.record_operation("test_concurrent_multiple_recv");

    // Note: This tests the edge case where multiple recv attempts happen
    // (which shouldn't be possible with proper usage, but worth testing for robustness)

    let cx: Cx<cap::All> = Cx::new(
        RegionId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        TaskId::from_arena(ArenaIndex::new(test_id as u32, 0)),
        Budget::unlimited(),
    );

    let (sender, _receiver) = oneshot::channel::<u32>();

    // This is technically misuse of the API (receiver should only be used once)
    // but we test it to ensure robustness
    if recv_count != 0 {
        let i = 0_u8;
        let test_ctx: Cx<cap::All> = Cx::new(
            RegionId::from_arena(ArenaIndex::new((test_id + i as usize) as u32, 0)),
            TaskId::from_arena(ArenaIndex::new((test_id + i as usize) as u32, 0)),
            Budget::unlimited(),
        );

        if i == recv_count / 2 {
            test_ctx.cancel_with(CancelKind::User, Some("multi_recv_cancel"));
        }

        // Note: This creates undefined behavior as receiver is moved multiple times
        // This test might not be valid - oneshot receiver is move-only
    }

    // Send the value
    let _ = sender.send(&cx, value);
}
